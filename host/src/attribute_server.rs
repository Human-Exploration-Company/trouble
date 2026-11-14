use core::marker::PhantomData;

use embassy_sync::blocking_mutex::raw::RawMutex;

use self::client_att_table::ClientAttTables;
pub use self::client_att_table::{ClientAttTable, ClientAttTableBuilder, ClientAttTableView};
use crate::att::{self, AttClient, AttCmd, AttErrorCode, AttReq};
use crate::attribute::{Attribute, AttributeData, AttributeTable, CCCD};
use crate::connection::Connection;
use crate::cursor::WriteCursor;
#[cfg(feature = "gatt")]
use crate::types::gatt_traits::AsGatt;
use crate::types::uuid::Uuid;
use crate::{codec, Error, Identity, PacketPool};

mod client_att_table;

#[derive(Default)]
struct Client {
    identity: Identity,
    is_connected: bool,
    #[cfg(feature = "gatt-caching")]
    caching: CachingState,
}

impl Client {
    fn set_identity(&mut self, identity: Identity) {
        self.identity = identity;
    }
}

/// Whether a client knows the current database (Core Spec Vol 3, Part G,
/// Section 2.5.2), and where its state comes from.
#[cfg(feature = "gatt-caching")]
#[derive(Clone, Copy)]
struct CachingState {
    /// The client knows the current database: it is new to it, or confirmed
    /// a Service Changed indication since it changed.
    change_aware: bool,
    /// The server has held this state since an earlier connection: it is
    /// newer than any copy the application kept.
    held: bool,
    /// The state comes from a bond made before this connection: held by the
    /// server or restored by the application.
    from_bond: bool,
    /// The client wrote its Service Changed CCCD on this connection.
    service_changed_written: bool,
}

#[cfg(feature = "gatt-caching")]
impl Default for CachingState {
    /// A client without a trusted relationship knows the database it meets.
    fn default() -> Self {
        Self {
            change_aware: true,
            held: false,
            from_bond: false,
            service_changed_written: false,
        }
    }
}

/// The GATT service's Service Changed characteristic, found when the server
/// is created.
#[cfg(feature = "gatt-caching")]
#[derive(Clone, Copy)]
struct CachingHandles {
    service_changed: u16,
    service_changed_cccd: u16,
}

#[cfg(feature = "gatt-caching")]
impl CachingHandles {
    /// `build_gatt_service` lays them out in order: Service Changed's
    /// declaration, value and CCCD.
    fn find<M: RawMutex, const MAX: usize>(table: &AttributeTable<'_, M, MAX>) -> Option<Self> {
        use bt_hci::uuid::characteristic::SERVICE_CHANGED;
        use bt_hci::uuid::descriptors::CLIENT_CHARACTERISTIC_CONFIGURATION;
        table.iterate(|mut it| {
            let (service_changed, _) = it.find(|(_, att)| att.uuid == Uuid::from(SERVICE_CHANGED))?;
            if it.next()?.1.uuid != Uuid::from(CLIENT_CHARACTERISTIC_CONFIGURATION) {
                return None;
            }
            Some(Self {
                service_changed,
                service_changed_cccd: service_changed + 1,
            })
        })
    }
}

/// A client's GATT caching state (Core Spec Vol 3, Part G, Sections 2.5.2 and
/// 7.1): for the application to keep across connections and resets for a
/// bonded client, as the specification requires, and to restore on its
/// next connection ([`AttributeServer::restore_client_caching`]).
#[cfg(feature = "gatt-caching")]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClientCaching {
    /// The client's Service Changed CCCD enables indications.
    pub service_changed: bool,
    /// The client knows the current database: it is owed no Service Changed
    /// indication. Restore `false` for a client whose cache predates a
    /// change to the database.
    pub change_aware: bool,
}

/// A GATT server capable of processing the GATT protocol using the provided table of attributes.
pub struct AttributeServer<'values, M: RawMutex, P: PacketPool, const ATT_MAX: usize, const CONN_MAX: usize> {
    att_table: AttributeTable<'values, M, ATT_MAX>,
    client_att_tables: ClientAttTables<M, CONN_MAX>,
    #[cfg(feature = "gatt-caching")]
    caching: Option<CachingHandles>,
    #[cfg(feature = "gatt-caching")]
    database_hash: u128,
    _p: PhantomData<P>,
}

pub(crate) mod sealed {
    use super::*;

    pub trait DynamicAttributeServer<P: PacketPool> {
        fn connect(&self, connection: &Connection<'_, P>) -> Result<(), Error>;
        fn disconnect(&self, connection: &Connection<'_, P>);
        fn process(
            &self,
            connection: &Connection<'_, P>,
            packet: &AttClient,
            rx: &mut [u8],
        ) -> Result<Option<usize>, Error>;
        fn should_notify(&self, connection: &Connection<'_, P>, cccd_handle: u16) -> bool;
        fn should_indicate(&self, connection: &Connection<'_, P>, cccd_handle: u16) -> bool;
        fn set(&self, connection: &Connection<'_, P>, att_handle: u16, input: &[u8]) -> Result<(), Error>;
        fn get(&self, connection: &Connection<'_, P>, att_handle: u16, buf: &mut [u8]) -> Result<usize, Error>;
        fn update_identity(&self, identity: Identity) -> Result<(), Error>;

        fn can_read(&self, connection: &Connection<'_, P>, handle: u16) -> Result<(), AttErrorCode>;
        fn can_write(&self, connection: &Connection<'_, P>, handle: u16) -> Result<(), AttErrorCode>;

        /// The client of `identity` has paired and bonded again.
        #[cfg(feature = "gatt-caching")]
        fn bond_added(&self, identity: &Identity);
    }
}

/// Type erased attribute server
pub trait DynamicAttributeServer<P: PacketPool>: sealed::DynamicAttributeServer<P> {}

impl<M: RawMutex, P: PacketPool, const ATT_MAX: usize, const CONN_MAX: usize> DynamicAttributeServer<P>
    for AttributeServer<'_, M, P, ATT_MAX, CONN_MAX>
{
}
impl<M: RawMutex, P: PacketPool, const ATT_MAX: usize, const CONN_MAX: usize> sealed::DynamicAttributeServer<P>
    for AttributeServer<'_, M, P, ATT_MAX, CONN_MAX>
{
    fn connect(&self, connection: &Connection<'_, P>) -> Result<(), Error> {
        AttributeServer::connect(self, connection)
    }

    fn disconnect(&self, connection: &Connection<'_, P>) {
        #[cfg(feature = "security")]
        let bonded = connection.is_bonded_peer();
        #[cfg(not(feature = "security"))]
        let bonded = false;

        self.client_att_tables.disconnect(&connection.peer_identity(), bonded);
    }

    fn process(
        &self,
        connection: &Connection<'_, P>,
        packet: &AttClient,
        rx: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        let res = AttributeServer::process(self, connection, packet, rx)?;
        Ok(res)
    }

    fn should_notify(&self, connection: &Connection<'_, P>, cccd_handle: u16) -> bool {
        AttributeServer::should_notify(self, connection, cccd_handle)
    }
    fn should_indicate(&self, connection: &Connection<'_, P>, cccd_handle: u16) -> bool {
        AttributeServer::should_indicate(self, connection, cccd_handle)
    }

    fn get(&self, connection: &Connection<'_, P>, att_handle: u16, buf: &mut [u8]) -> Result<usize, Error> {
        self.att_table
            .with_attribute(att_handle, |att| {
                if matches!(att.data, AttributeData::ClientSpecific { .. }) {
                    self.client_att_tables
                        .read(&connection.peer_identity(), att_handle, 0, buf)
                } else {
                    att.read(0, buf)
                }
                .map_err(Into::into)
            })
            .unwrap_or(Err(Error::NotFound))
    }

    fn set(&self, connection: &Connection<'_, P>, att_handle: u16, input: &[u8]) -> Result<(), Error> {
        self.att_table
            .with_attribute_mut(att_handle, |att| {
                if !att.data.is_variable_len() && att.data.capacity() != input.len() {
                    Err(Error::UnexpectedDataLength {
                        expected: att.data.capacity(),
                        actual: input.len(),
                    })
                } else if matches!(att.data, AttributeData::ClientSpecific { .. }) {
                    self.client_att_tables
                        .write(&connection.peer_identity(), att_handle, 0, input)
                        .map_err(Into::into)
                } else {
                    att.write(0, input).map_err(Into::into)
                }
            })
            .unwrap_or(Err(Error::NotFound))
    }

    fn update_identity(&self, identity: Identity) -> Result<(), Error> {
        self.client_att_tables.update_identity(identity)
    }

    #[cfg(feature = "gatt-caching")]
    fn bond_added(&self, identity: &Identity) {
        AttributeServer::bond_added(self, identity)
    }

    fn can_read(&self, connection: &Connection<'_, P>, handle: u16) -> Result<(), AttErrorCode> {
        self.att_table
            .with_attribute(handle, |att| self.can_read(connection, att))
            .unwrap_or(Err(AttErrorCode::INVALID_HANDLE))
    }

    fn can_write(&self, connection: &Connection<'_, P>, handle: u16) -> Result<(), AttErrorCode> {
        self.att_table
            .with_attribute(handle, |att| self.can_write(connection, att))
            .unwrap_or(Err(AttErrorCode::INVALID_HANDLE))
    }
}

impl<'values, M: RawMutex, P: PacketPool, const ATT_MAX: usize, const CONN_MAX: usize>
    AttributeServer<'values, M, P, ATT_MAX, CONN_MAX>
{
    /// Create a new instance of the AttributeServer
    ///
    /// With `gatt-caching`, the table is complete: its Database Hash is
    /// computed now.
    pub fn new(att_table: AttributeTable<'values, M, ATT_MAX>) -> AttributeServer<'values, M, P, ATT_MAX, CONN_MAX> {
        let cccd_tables = ClientAttTables::new(&att_table);
        #[cfg(feature = "gatt-caching")]
        let (caching, database_hash) = (CachingHandles::find(&att_table), att_table.hash());
        AttributeServer {
            att_table,
            client_att_tables: cccd_tables,
            #[cfg(feature = "gatt-caching")]
            caching,
            #[cfg(feature = "gatt-caching")]
            database_hash,
            _p: PhantomData,
        }
    }

    /// The table's Database Hash, computed as Core Spec Vol 3, Part G,
    /// Section 7.3.1 has it, but not exposed: the GATT service has no
    /// Database Hash characteristic, which beside Service Changed would
    /// oblige the server to Robust Caching (Section 2.5.2.1). An application
    /// keeps it with each bonded client's [`ClientCaching`]: a different
    /// hash after a reset means that the database changed.
    #[cfg(feature = "gatt-caching")]
    pub fn database_hash(&self) -> u128 {
        self.database_hash
    }

    /// The client's caching state, for the application to keep if the client
    /// is bonded; `None` without Service Changed or the client.
    #[cfg(feature = "gatt-caching")]
    pub fn client_caching(&self, connection: &Connection<'_, P>) -> Option<ClientCaching> {
        let handles = self.caching?;
        self.client_att_tables
            .with_client_mut(&connection.peer_identity(), |client, table| ClientCaching {
                service_changed: table
                    .get(handles.service_changed_cccd)
                    .and_then(|value| value.try_into().ok())
                    .is_some_and(|value| CCCD(u16::from_le_bytes(value)).should_indicate()),
                change_aware: client.caching.change_aware,
            })
    }

    /// Restore a bonded client's caching state, as kept from its last
    /// connection. Call it when the client connects, before its requests are
    /// processed. Returns whether the state was restored: the server keeps a
    /// bonded client's state across its connections while the bond lasts and
    /// the slot is not needed for another client, and state it holds from an
    /// earlier connection is newer than any copy, so it keeps that and
    /// returns `false`.
    #[cfg(feature = "gatt-caching")]
    pub fn restore_client_caching(&self, connection: &Connection<'_, P>, caching: ClientCaching) -> bool {
        let Some(handles) = self.caching else {
            return false;
        };
        let cccd: u16 = if caching.service_changed { 0x0002 } else { 0 };
        self.client_att_tables
            .with_client_mut(&connection.peer_identity(), |client, table| {
                if client.caching.held {
                    return false;
                }
                let _ = table.write(handles.service_changed_cccd, 0, &cccd.to_le_bytes());
                client.caching = CachingState {
                    change_aware: caching.change_aware,
                    from_bond: true,
                    ..CachingState::default()
                };
                true
            })
            .unwrap_or(false)
    }

    /// A new bond replaces the one the client's caching state came from: a
    /// new trusted relationship, so a Service Changed CCCD the client set
    /// under the old bond and has not set again on this connection is
    /// dropped, and the client knows the database (Core Spec Vol 3, Part G,
    /// Section 2.5.2). What it wrote on this connection before pairing again
    /// stands.
    #[cfg(feature = "gatt-caching")]
    fn bond_added(&self, identity: &Identity) {
        let Some(handles) = self.caching else {
            return;
        };
        self.client_att_tables.with_client_mut(identity, |client, table| {
            let state = &mut client.caching;
            if !state.from_bond {
                return;
            }
            if !state.service_changed_written {
                let _ = table.write(handles.service_changed_cccd, 0, &[0, 0]);
            }
            // Any copy the application kept is of the old bond.
            *state = CachingState {
                held: true,
                service_changed_written: state.service_changed_written,
                ..CachingState::default()
            };
        });
    }

    /// Indicate Service Changed for the whole database to the client, if it
    /// does not know the current database and enabled the indication:
    /// `Ok(true)` once it confirmed, from when it knows it. For a bonded
    /// client whose cache predates a change to the database, once its link
    /// is encrypted (Core Spec Vol 3, Part G, Sections 2.5.2 and 7.1).
    #[cfg(feature = "gatt-caching")]
    pub async fn indicate_service_changed(
        &self,
        connection: &crate::gatt::GattConnection<'_, '_, P>,
    ) -> Result<bool, Error> {
        let handles = self.caching.ok_or(Error::NotFound)?;
        let conn = connection.raw();
        let owed = |caching: ClientCaching| caching.service_changed && !caching.change_aware;
        if !self.client_caching(conn).is_some_and(owed) {
            return Ok(false);
        }
        // Any client may enable it: there is no security to raise first.
        // Affected handles 0x0001 to 0xFFFF: the client rediscovers all.
        crate::attribute::send_indication(conn, handles.service_changed, &[0x01, 0x00, 0xff, 0xff]).await?;
        // "Once the server has received the ATT_HANDLE_VALUE_CFM PDU, the
        // server can consider the client to be aware" (Section 2.5.2).
        self.client_att_tables
            .with_client_mut(&conn.peer_identity(), |client, _| {
                client.caching.change_aware = true;
            });
        Ok(true)
    }

    /// Read an attribute value with permission checks for the given connection.
    pub fn read(
        &self,
        connection: &Connection<'_, P>,
        handle: u16,
        offset: usize,
        data: &mut [u8],
    ) -> Result<usize, AttErrorCode> {
        self.att_table
            .with_attribute(handle, |att| {
                self.read_attribute_data(connection, handle, offset, att, data)
            })
            .unwrap_or(Err(AttErrorCode::ATTRIBUTE_NOT_FOUND))
    }

    pub(crate) fn connect(&self, connection: &Connection<'_, P>) -> Result<(), Error> {
        self.client_att_tables.connect(&connection.peer_identity(), |identity| {
            connection.is_bonded_identity(identity)
        })
    }

    pub(crate) fn should_notify(&self, connection: &Connection<'_, P>, cccd_handle: u16) -> bool {
        self.client_att_tables
            .with_value(&connection.peer_identity(), cccd_handle, |value| {
                if let Ok(value) = value.try_into() {
                    CCCD(u16::from_le_bytes(value)).should_notify()
                } else {
                    false
                }
            })
            .unwrap_or(false)
    }

    pub(crate) fn should_indicate(&self, connection: &Connection<'_, P>, cccd_handle: u16) -> bool {
        self.client_att_tables
            .with_value(&connection.peer_identity(), cccd_handle, |value| {
                if let Ok(value) = value.try_into() {
                    CCCD(u16::from_le_bytes(value)).should_indicate()
                } else {
                    false
                }
            })
            .unwrap_or(false)
    }

    fn can_read(&self, connection: &Connection<'_, P>, att: &Attribute<'_>) -> Result<(), AttErrorCode> {
        match connection.security_level() {
            Ok(level) => att.permissions().can_read(
                level,
                #[cfg(feature = "legacy-pairing")]
                connection.encryption_key_len().unwrap_or(0),
            ),
            Err(_) => Err(AttErrorCode::INVALID_HANDLE),
        }
    }

    fn can_write(&self, connection: &Connection<'_, P>, att: &Attribute<'_>) -> Result<(), AttErrorCode> {
        match connection.security_level() {
            Ok(level) => att.permissions().can_write(
                level,
                #[cfg(feature = "legacy-pairing")]
                connection.encryption_key_len().unwrap_or(0),
            ),
            Err(_) => Err(AttErrorCode::INVALID_HANDLE),
        }
    }

    fn read_attribute_data(
        &self,
        connection: &Connection<'_, P>,
        handle: u16,
        offset: usize,
        att: &Attribute<'values>,
        data: &mut [u8],
    ) -> Result<usize, AttErrorCode> {
        self.can_read(connection, att)?;
        if matches!(att.data, AttributeData::ClientSpecific { .. }) {
            return self
                .client_att_tables
                .read(&connection.peer_identity(), handle, offset, data);
        }
        att.read(offset, data)
    }

    fn write_attribute_data(
        &self,
        connection: &Connection<'_, P>,
        handle: u16,
        offset: usize,
        att: &mut Attribute<'values>,
        data: &[u8],
    ) -> Result<(), AttErrorCode> {
        self.can_write(connection, att)?;
        if matches!(att.data, AttributeData::ClientSpecific { .. }) {
            self.client_att_tables
                .write(&connection.peer_identity(), handle, offset, data)?;
            #[cfg(feature = "gatt-caching")]
            if self
                .caching
                .is_some_and(|handles| handles.service_changed_cccd == handle)
            {
                self.client_att_tables
                    .with_client_mut(&connection.peer_identity(), |client, _| {
                        client.caching.service_changed_written = true;
                    });
            }
            return Ok(());
        }
        att.write(offset, data)
    }

    fn handle_read_by_type_req(
        &self,
        connection: &Connection<'_, P>,
        buf: &mut [u8],
        start: u16,
        end: u16,
        attribute_type: &Uuid,
    ) -> Result<usize, codec::Error> {
        let mut handle = start;
        let mut data = WriteCursor::new(buf);

        if start > end || start == 0 {
            return Self::error_response(data, att::ATT_READ_BY_TYPE_REQ, start, AttErrorCode::INVALID_HANDLE);
        }

        let (mut header, mut body) = data.split(2)?;
        let err = self.att_table.iterate_from(start, |it| {
            let mut ret = Err(AttErrorCode::ATTRIBUTE_NOT_FOUND);
            for (att_handle, att) in it {
                // trace!("[read_by_type] Check attribute {:?} {}", att.uuid, att.handle);
                if &att.uuid == attribute_type && att_handle <= end {
                    body.write(att_handle)?;
                    handle = att_handle;

                    let new_ret = self.read_attribute_data(connection, att_handle, 0, att, body.write_buf());
                    match (new_ret, ret) {
                        (Ok(first_length), Err(_)) => {
                            // First successful read, store this length, all subsequent ones must match it.
                            // debug!("[read_by_type] found first entry {:x?}, handle {}", att.uuid, handle);
                            ret = new_ret;
                            body.commit(first_length)?;
                        }
                        (Ok(new_length), Ok(old_length)) => {
                            // Any matching attribute after the first, verify the lengths are identical, if not break.
                            if new_length == old_length {
                                // debug!("[read_by_type] found equal length {}, handle {}", new_length, handle);
                                body.commit(new_length)?;
                            } else {
                                // We encountered a different length,  unwind the handle.
                                // debug!("[read_by_type] different length: {}, old: {}", new_length, old_length);
                                body.truncate(body.len() - 2);
                                // And then break to ensure we respond with the previously found entries.
                                break;
                            }
                        }
                        (Err(error_code), Ok(_old_length)) => {
                            // New read failed, but we had a previous value, return what we had thus far, truncate to
                            // remove the previously written handle.
                            body.truncate(body.len() - 2);
                            // We do silently drop the error here.
                            // debug!("[read_by_group] new error: {:?}, returning result thus far", error_code);
                            break;
                        }
                        (Err(_), Err(_)) => {
                            // Error on the first possible read, return this error.
                            ret = new_ret;
                            break;
                        }
                    }
                    // If we get here, we always have had a successful read, and we can check that we still have space
                    // left in the buffer to write the next entry if it exists.
                    if let Ok(expected_length) = ret {
                        if body.available() < expected_length + 2 {
                            break;
                        }
                    }
                }
            }
            ret
        });

        match err {
            Ok(len) => {
                header.write(att::ATT_READ_BY_TYPE_RSP)?;
                header.write(2 + len as u8)?;
                Ok(header.len() + body.len())
            }
            Err(e) => Ok(Self::error_response(data, att::ATT_READ_BY_TYPE_REQ, handle, e)?),
        }
    }

    fn handle_read_by_group_type_req(
        &self,
        connection: &Connection<'_, P>,
        buf: &mut [u8],
        start: u16,
        end: u16,
        group_type: &Uuid,
    ) -> Result<usize, codec::Error> {
        let mut handle = start;
        let mut data = WriteCursor::new(buf);

        if start > end || start == 0 {
            return Self::error_response(data, att::ATT_READ_BY_TYPE_REQ, start, AttErrorCode::INVALID_HANDLE);
        }

        let (mut header, mut body) = data.split(2)?;
        // Multiple entries can be returned in the response as long as they are of equal length.
        let err = self.att_table.iterate_from(start, |mut it| {
            // ret either holds the length of the attribute, or the error code encountered.
            let mut ret: Result<usize, AttErrorCode> = Err(AttErrorCode::ATTRIBUTE_NOT_FOUND);
            while let Some((att_handle, att)) = it.next() {
                // trace!("[read_by_group] Check attribute {:x?} {}", att.uuid, att.handle);
                if &att.uuid == group_type && att_handle <= end {
                    // debug!("[read_by_group] found! {:x?} handle: {}", att.uuid, att.handle);
                    handle = att_handle;
                    let last_handle_in_group = it.service_group_end();

                    body.write(att_handle)?;
                    body.write(last_handle_in_group)?;
                    let new_ret = self.read_attribute_data(connection, att_handle, 0, att, body.write_buf());
                    match (new_ret, ret) {
                        (Ok(first_length), Err(_)) => {
                            // First successful read, store this length, all subsequent ones must match it.
                            // debug!("[read_by_group] found first entry {:x?}, handle {}", att.uuid, handle);
                            ret = new_ret;
                            body.commit(first_length)?;
                        }
                        (Ok(new_length), Ok(old_length)) => {
                            // Any matching attribute after the first, verify the lengths are identical, if not break.
                            if new_length == old_length {
                                // debug!("[read_by_group] found equal length {}, handle {}", new_length, handle);
                                body.commit(new_length)?;
                            } else {
                                // We encountered a different length,  unwind the handle and last_handle written.
                                // debug!("[read_by_group] different length: {}, old: {}", new_length, old_length);
                                body.truncate(body.len() - 4);
                                // And then break to ensure we respond with the previously found entries.
                                break;
                            }
                        }
                        (Err(error_code), Ok(_old_length)) => {
                            // New read failed, but we had a previous value, return what we had thus far, truncate to
                            // remove the previously written handle and last handle.
                            body.truncate(body.len() - 4);
                            // We do silently drop the error here.
                            // debug!("[read_by_group] new error: {:?}, returning result thus far", error_code);
                            break;
                        }
                        (Err(_), Err(_)) => {
                            // Error on the first possible read, return this error.
                            ret = new_ret;
                            break;
                        }
                    }
                    // If we get here, we always have had a successful read, and we can check that we still have space
                    // left in the buffer to write the next entry if it exists.
                    if let Ok(expected_length) = ret {
                        if body.available() < expected_length + 4 {
                            break;
                        }
                    }
                }
            }
            ret
        });

        match err {
            Ok(len) => {
                header.write(att::ATT_READ_BY_GROUP_TYPE_RSP)?;
                header.write(4 + len as u8)?;
                Ok(header.len() + body.len())
            }
            Err(e) => Ok(Self::error_response(data, att::ATT_READ_BY_GROUP_TYPE_REQ, handle, e)?),
        }
    }

    fn handle_read_req(
        &self,
        connection: &Connection<'_, P>,
        buf: &mut [u8],
        handle: u16,
    ) -> Result<usize, codec::Error> {
        let mut data = WriteCursor::new(buf);

        data.write(att::ATT_READ_RSP)?;

        let err = self
            .att_table
            .with_attribute(handle, |att| {
                let len = self.read_attribute_data(connection, handle, 0, att, data.write_buf())?;
                data.commit(len)?;
                Ok(len)
            })
            .unwrap_or(Err(AttErrorCode::ATTRIBUTE_NOT_FOUND));

        match err {
            Ok(_) => Ok(data.len()),
            Err(e) => Ok(Self::error_response(data, att::ATT_READ_REQ, handle, e)?),
        }
    }

    fn handle_write_cmd(
        &self,
        connection: &Connection<'_, P>,
        buf: &mut [u8],
        handle: u16,
        data: &[u8],
    ) -> Result<usize, codec::Error> {
        self.att_table.with_attribute_mut(handle, |att| {
            // Write commands can't respond with an error.
            let _ = self.write_attribute_data(connection, handle, 0, att, data);
        });
        Ok(0)
    }

    fn handle_write_req(
        &self,
        connection: &Connection<'_, P>,
        buf: &mut [u8],
        handle: u16,
        data: &[u8],
    ) -> Result<usize, codec::Error> {
        let err = self
            .att_table
            .with_attribute_mut(handle, |att| {
                self.write_attribute_data(connection, handle, 0, att, data)
            })
            .unwrap_or(Err(AttErrorCode::ATTRIBUTE_NOT_FOUND));

        let mut w = WriteCursor::new(buf);
        match err {
            Ok(()) => {
                w.write(att::ATT_WRITE_RSP)?;
                Ok(w.len())
            }
            Err(e) => Ok(Self::error_response(w, att::ATT_WRITE_REQ, handle, e)?),
        }
    }

    fn handle_find_type_value(
        &self,
        connection: &Connection<'_, P>,
        buf: &mut [u8],
        start: u16,
        end: u16,
        attr_type: u16,
        attr_value: &[u8],
    ) -> Result<usize, codec::Error> {
        let mut w = WriteCursor::new(buf);
        let attr_type = Uuid::new_short(attr_type);

        if start > end || start == 0 {
            return Self::error_response(w, att::ATT_READ_BY_TYPE_REQ, start, AttErrorCode::INVALID_HANDLE);
        }

        w.write(att::ATT_FIND_BY_TYPE_VALUE_RSP)?;
        self.att_table.iterate_from(start, |mut it| {
            while let Some((handle, att)) = it.next() {
                // Only attributes that the link may read are compared.
                if handle <= end && att.uuid == attr_type && self.can_read(connection, att).is_ok() {
                    let value = att.data.value();
                    if value == Some(attr_value) {
                        if w.available() < 4 {
                            break;
                        }
                        w.write(handle)?;
                        w.write(it.service_group_end())?;
                    }
                }
            }
            Ok::<(), codec::Error>(())
        })?;
        if w.len() > 1 {
            Ok(w.len())
        } else {
            Ok(Self::error_response(
                w,
                att::ATT_FIND_BY_TYPE_VALUE_REQ,
                start,
                AttErrorCode::ATTRIBUTE_NOT_FOUND,
            )?)
        }
    }

    fn handle_find_information(&self, buf: &mut [u8], start: u16, end: u16) -> Result<usize, codec::Error> {
        let mut w = WriteCursor::new(buf);

        if start > end || start == 0 {
            return Self::error_response(w, att::ATT_READ_BY_TYPE_REQ, start, AttErrorCode::INVALID_HANDLE);
        }

        let (mut header, mut body) = w.split(2)?;

        header.write(att::ATT_FIND_INFORMATION_RSP)?;
        let mut t = 0;

        self.att_table.iterate_from(start, |it| {
            for (handle, att) in it {
                if handle <= end {
                    // FIND_INFORMATION_RSP "Format" byte (Core spec, Vol 3 Part F, 3.4.3.2):
                    // 0x01 = handle(s) + 16-bit UUID(s), 0x02 = handle(s) + 128-bit UUID(s).
                    // `get_att_type()` returns the real format code (32-bit reports 0x02 and is
                    // widened to 128-bit by `att_bytes()`), so the header byte, this same-type
                    // batching check, and the body written below all agree.
                    let format = att.uuid.get_att_type();
                    if t == 0 {
                        t = format;
                    } else if t != format {
                        break;
                    }
                    let (uuid, len) = att.uuid.att_bytes();
                    let uuid = &uuid[..len];
                    if body.available() < 2 + uuid.len() {
                        break;
                    }
                    body.write(handle)?;
                    body.append(uuid)?;
                }
            }
            Ok::<(), codec::Error>(())
        })?;
        header.write(t)?;

        if body.len() > 2 {
            Ok(header.len() + body.len())
        } else {
            Ok(Self::error_response(
                w,
                att::ATT_FIND_INFORMATION_REQ,
                start,
                AttErrorCode::ATTRIBUTE_NOT_FOUND,
            )?)
        }
    }

    fn error_response(
        mut w: WriteCursor<'_>,
        opcode: u8,
        handle: u16,
        code: AttErrorCode,
    ) -> Result<usize, codec::Error> {
        w.reset();
        w.write(att::ATT_ERROR_RSP)?;
        w.write(opcode)?;
        w.write(handle)?;
        w.write(code)?;
        Ok(w.len())
    }

    #[cfg(feature = "att-queued-writes")]
    fn handle_prepare_write(
        &self,
        connection: &Connection<'_, P>,
        buf: &mut [u8],
        handle: u16,
        offset: u16,
        value: &[u8],
    ) -> Result<usize, codec::Error> {
        let mut w = WriteCursor::new(buf);

        let err = connection.prepare_write(handle, offset, value);
        match err {
            Ok(()) => {
                w.write(att::ATT_PREPARE_WRITE_RSP)?;
                w.write(handle)?;
                w.write(offset)?;
                w.append(value)?;
                Ok(w.len())
            }
            Err(e) => Ok(Self::error_response(w, att::ATT_PREPARE_WRITE_REQ, handle, e)?),
        }
    }

    #[cfg(not(feature = "att-queued-writes"))]
    fn handle_prepare_write(
        &self,
        _connection: &Connection<'_, P>,
        buf: &mut [u8],
        handle: u16,
        _offset: u16,
        _value: &[u8],
    ) -> Result<usize, codec::Error> {
        let w = WriteCursor::new(buf);
        Self::error_response(w, att::ATT_PREPARE_WRITE_REQ, 0, AttErrorCode::REQUEST_NOT_SUPPORTED)
    }

    #[cfg(feature = "att-queued-writes")]
    fn handle_execute_write(
        &self,
        connection: &Connection<'_, P>,
        buf: &mut [u8],
        flags: u8,
    ) -> Result<usize, codec::Error> {
        let mut w = WriteCursor::new(buf);
        if flags == 0x01 {
            let err = connection.with_prepare_write(|pw| {
                if pw.handle == 0 {
                    return Ok(());
                }
                let data = &pw.buf[..pw.len as usize];
                self.att_table
                    .with_attribute_mut(pw.handle, |att| {
                        self.write_attribute_data(connection, pw.handle, pw.offset as usize, att, data)
                    })
                    .unwrap_or(Err(AttErrorCode::ATTRIBUTE_NOT_FOUND))
            });
            connection.clear_prepare_write();
            match err {
                Ok(()) => {
                    w.write(att::ATT_EXECUTE_WRITE_RSP)?;
                    Ok(w.len())
                }
                Err(e) => Ok(Self::error_response(w, att::ATT_EXECUTE_WRITE_REQ, 0, e)?),
            }
        } else {
            connection.clear_prepare_write();
            w.write(att::ATT_EXECUTE_WRITE_RSP)?;
            Ok(w.len())
        }
    }

    #[cfg(not(feature = "att-queued-writes"))]
    fn handle_execute_write(
        &self,
        _connection: &Connection<'_, P>,
        buf: &mut [u8],
        _flags: u8,
    ) -> Result<usize, codec::Error> {
        let w = WriteCursor::new(buf);
        Self::error_response(w, att::ATT_EXECUTE_WRITE_REQ, 0, AttErrorCode::REQUEST_NOT_SUPPORTED)
    }

    fn handle_read_blob(
        &self,
        connection: &Connection<'_, P>,
        buf: &mut [u8],
        handle: u16,
        offset: u16,
    ) -> Result<usize, codec::Error> {
        let mut w = WriteCursor::new(buf);
        w.write(att::ATT_READ_BLOB_RSP)?;

        let err = self
            .att_table
            .with_attribute(handle, |att| {
                let n = self.read_attribute_data(connection, handle, offset as usize, att, w.write_buf())?;
                w.commit(n)?;
                Ok(n)
            })
            .unwrap_or(Err(AttErrorCode::ATTRIBUTE_NOT_FOUND));

        match err {
            Ok(_) => Ok(w.len()),
            Err(e) => Ok(Self::error_response(w, att::ATT_READ_BLOB_REQ, handle, e)?),
        }
    }

    fn handle_read_multiple(&self, buf: &mut [u8]) -> Result<usize, codec::Error> {
        // Read Multiple Variable is not supported.
        let w = WriteCursor::new(buf);
        Self::error_response(w, att::ATT_READ_MULTIPLE_REQ, 0, AttErrorCode::REQUEST_NOT_SUPPORTED)
    }

    /// Process an event and produce a response if necessary
    pub fn process(
        &self,
        connection: &Connection<'_, P>,
        packet: &AttClient,
        rx: &mut [u8],
    ) -> Result<Option<usize>, codec::Error> {
        let len = match packet {
            AttClient::Request(AttReq::ReadByType {
                start,
                end,
                attribute_type,
            }) => self.handle_read_by_type_req(connection, rx, *start, *end, attribute_type)?,

            AttClient::Request(AttReq::ReadByGroupType { start, end, group_type }) => {
                self.handle_read_by_group_type_req(connection, rx, *start, *end, group_type)?
            }
            AttClient::Request(AttReq::FindInformation {
                start_handle,
                end_handle,
            }) => self.handle_find_information(rx, *start_handle, *end_handle)?,

            AttClient::Request(AttReq::Read { handle }) => self.handle_read_req(connection, rx, *handle)?,

            AttClient::Command(AttCmd::Write { handle, data }) => {
                self.handle_write_cmd(connection, rx, *handle, data)?;
                0
            }

            AttClient::Request(AttReq::Write { handle, data }) => {
                self.handle_write_req(connection, rx, *handle, data)?
            }

            AttClient::Request(AttReq::ExchangeMtu { mtu }) => 0, // Done outside,

            AttClient::Request(AttReq::FindByTypeValue {
                start_handle,
                end_handle,
                att_type,
                att_value,
            }) => self.handle_find_type_value(connection, rx, *start_handle, *end_handle, *att_type, att_value)?,

            AttClient::Request(AttReq::PrepareWrite { handle, offset, value }) => {
                self.handle_prepare_write(connection, rx, *handle, *offset, value)?
            }

            AttClient::Request(AttReq::ExecuteWrite { flags }) => self.handle_execute_write(connection, rx, *flags)?,

            AttClient::Request(AttReq::ReadBlob { handle, offset }) => {
                self.handle_read_blob(connection, rx, *handle, *offset)?
            }

            AttClient::Request(AttReq::ReadMultiple { .. }) => self.handle_read_multiple(rx)?,

            AttClient::Confirmation(_) => 0,
        };
        if len > 0 {
            Ok(Some(len))
        } else {
            Ok(None)
        }
    }

    /// Get a reference to the attribute table
    pub fn table(&self) -> &AttributeTable<'values, M, ATT_MAX> {
        &self.att_table
    }

    /// Write a value to the attribute table and send notifications/indications
    /// to all connected peers that have subscribed via the CCCD.
    ///
    /// If the attribute at `value_handle + 1` is a CCCD (UUID 0x2902), each
    /// connection is checked for notification/indication subscriptions and
    /// sent the appropriate PDU.
    #[cfg(feature = "gatt")]
    pub async fn write_and_notify<C: crate::Controller, T: AsGatt + ?Sized>(
        &self,
        stack: &crate::Stack<'_, C, P>,
        value_handle: u16,
        data: &T,
    ) -> Result<(), Error> {
        self.att_table.write(value_handle, 0, data.as_gatt())?;

        // Check if the next handle is a CCCD
        let cccd_handle = value_handle + 1;
        if self.att_table.uuid(cccd_handle)
            != Some(bt_hci::uuid::descriptors::CLIENT_CHARACTERISTIC_CONFIGURATION.into())
        {
            return Ok(());
        }

        self.notify(stack, value_handle, data).await
    }

    /// Send notifications/indications to all connected peers that have subscribed
    /// via the CCCD without updating the value stored in the attribute table.
    ///
    /// If the attribute at `value_handle + 1` is not a CCCD (UUID 0x2902), an error
    /// is returned. Each connection is checked for notification/indication
    /// subscriptions and sent the appropriate PDU.
    #[cfg(feature = "gatt")]
    pub async fn notify<C: crate::Controller, T: AsGatt + ?Sized>(
        &self,
        stack: &crate::Stack<'_, C, P>,
        value_handle: u16,
        data: &T,
    ) -> Result<(), Error> {
        // Check if the next handle is a CCCD
        let cccd_handle = value_handle + 1;
        if self.att_table.uuid(cccd_handle)
            != Some(bt_hci::uuid::descriptors::CLIENT_CHARACTERISTIC_CONFIGURATION.into())
        {
            return Err(Error::InvalidValue);
        }

        let data = data.as_gatt();
        for conn in stack.connections() {
            if self.should_indicate(&conn, cccd_handle) {
                let uns = att::AttUns::Indicate {
                    handle: value_handle,
                    data,
                };
                if let Ok(pdu) = crate::gatt::assemble(&conn, att::AttServer::Unsolicited(uns)) {
                    conn.send(pdu).await;
                }
            } else if self.should_notify(&conn, cccd_handle) {
                let uns = att::AttUns::Notify {
                    handle: value_handle,
                    data,
                };
                if let Ok(pdu) = crate::gatt::assemble(&conn, att::AttServer::Unsolicited(uns)) {
                    conn.send(pdu).await;
                }
            }
        }
        Ok(())
    }

    /// Get the client-specific attribute table for a connection
    pub fn get_client_att_table(&self, connection: &Connection<'_, P>) -> Option<ClientAttTable> {
        self.client_att_tables.get_client_att_table(&connection.peer_identity())
    }

    /// Set the client-specific attribute table for a connection
    pub fn set_client_att_table(&self, connection: &Connection<'_, P>, table: &ClientAttTableView<'_>) {
        self.client_att_tables
            .set_client_att_table(&connection.peer_identity(), table);
    }
}

#[cfg(test)]
mod tests {

    use core::task::Poll;

    use bt_hci::param::{AddrKind, BdAddr, ConnHandle, LeConnRole};
    use bt_hci::uuid::declarations::{PRIMARY_SERVICE, SECONDARY_SERVICE};
    use embassy_sync::blocking_mutex::raw::NoopRawMutex;

    use super::*;
    use crate::connection_manager::tests::{setup, ADDR_1};
    use crate::prelude::*;
    use crate::Address;

    // Find By Type Value does not compare a value that the link cannot read.
    #[test]
    fn find_type_value_obeys_read_permission() {
        const SECRET: &[u8] = b"secret";
        const PUBLIC: &[u8] = b"public";
        let mut table: AttributeTable<'_, NoopRawMutex, 16> = AttributeTable::new();
        {
            let mut svc = table.add_service(Service {
                uuid: Uuid::new_short(0x1800),
            });
            let _ = svc
                .add_characteristic_small(Uuid::new_short(0x2A00), [CharacteristicProp::Read], *b"secret")
                .read_permission(PermissionLevel::EncryptionRequired)
                .build();
            let _ = svc
                .add_characteristic_small(Uuid::new_short(0x2A01), [CharacteristicProp::Read], *b"public")
                .build();
        }
        let server = AttributeServer::<_, DefaultPacketPool, 16, 1>::new(table);

        let mgr = setup();
        assert!(mgr.poll_accept(LeConnRole::Peripheral, &[], None).is_pending());
        unwrap!(mgr.connect(
            ConnHandle::new(0),
            Address::new(AddrKind::RANDOM, BdAddr::new(ADDR_1)),
            LeConnRole::Peripheral,
            ConnParams::new(),
        ));
        let Poll::Ready(conn) = mgr.poll_accept(LeConnRole::Peripheral, &[], None) else {
            panic!("expected connection to be accepted");
        };

        let mut buf = [0u8; 32];
        // The link has no encryption: a guess of the protected value is not found.
        let len = server
            .handle_find_type_value(&conn, &mut buf, 1, u16::MAX, 0x2A00, SECRET)
            .unwrap();
        // Error response: opcode, request opcode, handle 1, "Attribute Not Found".
        assert_eq!(
            &buf[..len],
            &[att::ATT_ERROR_RSP, att::ATT_FIND_BY_TYPE_VALUE_REQ, 1, 0, 0x0A]
        );
        // A public value is still found.
        let len = server
            .handle_find_type_value(&conn, &mut buf, 1, u16::MAX, 0x2A01, PUBLIC)
            .unwrap();
        assert_eq!(buf[0], att::ATT_FIND_BY_TYPE_VALUE_RSP);
        assert_eq!(len, 5);
        // Primary service discovery by UUID still works. The last service ends
        // at 0xFFFF.
        let len = server
            .handle_find_type_value(&conn, &mut buf, 1, u16::MAX, 0x2800, &0x1800u16.to_le_bytes())
            .unwrap();
        assert_eq!(buf[0], att::ATT_FIND_BY_TYPE_VALUE_RSP);
        assert_eq!(&buf[1..len], &[1, 0, 0xFF, 0xFF]);
    }

    #[test]
    fn read_multiple_variable_is_not_supported() {
        let mut table: AttributeTable<'_, NoopRawMutex, 4> = AttributeTable::new();
        table.add_service(Service {
            uuid: Uuid::new_short(0x1800),
        });
        let server = AttributeServer::<_, DefaultPacketPool, 4, 1>::new(table);
        let mut buf = [0u8; 16];
        let len = server.handle_read_multiple(&mut buf).unwrap();
        // The handle in error is 0x0000 and the code is "Request Not Supported".
        assert_eq!(
            &buf[..len],
            &[att::ATT_ERROR_RSP, att::ATT_READ_MULTIPLE_REQ, 0, 0, 0x06]
        );
    }

    #[test]
    fn test_attribute_server_last_handle_of_group() {
        // This test comes from a situation where a service had exactly 16 handles, this resulted in the
        // last_handle_in_group field of the ReadByGroupType response was 16 aligned (96 to be exact), in this situation
        // the next request will start at 96 + 1, which was one handle beyond the start of the next service.
        //
        // Snippet from the original failure mode:
        // WARN  trouble_host::attribute_server] Looking for group: Uuid16([0, 28]) between 75 and 65535
        // DEBUG trouble_host::attribute_server] [read_by_group] found! Uuid16([0, 28]) 80
        // DEBUG trouble_host::attribute_server] last_handle_in_group: 96
        // DEBUG trouble_host::attribute_server] read_attribute_data: Ok(16)
        // TRACE trouble_host::host] [host] granted send packets = 1, len = 30
        // TRACE trouble_host::host] [host] sent acl packet len = 26
        // TRACE trouble_host::host] [host] inbound l2cap header channel = 4, fragment len = 7, total = 7
        // INFO  main_ble::ble_bas_peripheral] [gatt-attclient]: ReadByGroupType { start: 97, end: 65535, group_type: Uuid16([0, 40]) }
        // INFO  main_ble::ble_bas_peripheral] [gatt] other event
        // WARN  trouble_host::attribute_server] Looking for group: Uuid16([0, 28]) between 97 and 65535
        // WARN  trouble_host::attribute_server] [read_by_group] Dit not find attribute Uuid16([0, 28]) between 97  65535

        // The request:
        // INFO  main_ble::ble_bas_peripheral] [gatt-attclient]: ReadByGroupType { start: 97, end: 65535, group_type: Uuid16([0, 40]) }
        // In trace, the "group_type: Uuid16([0, 40]) }" is decimal, so this becomes group type 0x2800, which is the
        // primary service group.
        let primary_service_group_type = Uuid::new_short(0x2800);

        let _ = env_logger::try_init();
        const MAX_ATTRIBUTES: usize = 1024;
        const CONNECTIONS_MAX: usize = 3;
        const L2CAP_CHANNELS_MAX: usize = 5;
        type FacadeDummyType = [u8; 0];

        // Instead of only checking the failure mode, we fuzz the length of the interior service to cross over several
        // multiples of 16.
        for interior_handle_count in 0..=64u8 {
            debug!("Testing with interior handle count of {}", interior_handle_count);

            // Create a new table.
            let mut table: AttributeTable<'_, NoopRawMutex, { MAX_ATTRIBUTES }> = AttributeTable::new();

            // Add a first service, contents don't really matter, but the issue doesn't manifest without this.
            {
                let svc = table.add_service(Service {
                    uuid: Uuid::new_long([10; 16]),
                });
            }

            // Add an interior service that has a varying length.
            {
                let mut svc = table.add_service(Service {
                    uuid: Uuid::new_long([0; 16]),
                });

                for c in 0..interior_handle_count {
                    let _service_instance = svc
                        .add_characteristic_ro::<[u8; 2], _>(Uuid::new_long([c; 16]), &[0, 0])
                        .build();
                }
            }
            // Now add the service at the end, contents don't really matter.
            {
                table.add_service(Service {
                    uuid: Uuid::new_long([8; 16]),
                });
            }

            // Print the table for debugging.
            table.iterate(|it| {
                for (handle, att) in it {
                    let uuid = &att.uuid;
                    if *uuid == PRIMARY_SERVICE.into() || *uuid == SECONDARY_SERVICE.into() {
                        trace!("service 0x{:0>4x?}, 0x{:0>2x?}", handle, uuid,);
                    } else {
                        trace!("  0x{:0>4x?}, 0x{:0>2x?}", handle, uuid,);
                    }
                }
            });

            // Create a server.
            let server = AttributeServer::<_, DefaultPacketPool, MAX_ATTRIBUTES, CONNECTIONS_MAX>::new(table);

            // Create the connection manager.
            let mgr = setup();

            // Try to connect.
            assert!(mgr.poll_accept(LeConnRole::Peripheral, &[], None).is_pending());
            unwrap!(mgr.connect(
                ConnHandle::new(0),
                Address::new(AddrKind::RANDOM, BdAddr::new(ADDR_1)),
                LeConnRole::Peripheral,
                ConnParams::new(),
            ));

            if let Poll::Ready(conn_handle) = mgr.poll_accept(LeConnRole::Peripheral, &[], None) {
                // We now have a connection, we can send the mocked requests to our attribute server.
                let mut buffer = [0u8; 64];

                let mut start = 1;
                let end = u16::MAX;
                // There are always three services that we should be able to discover.
                for _ in 0..3 {
                    let length = server
                        .handle_read_by_group_type_req(
                            &conn_handle,
                            &mut buffer,
                            start,
                            end,
                            &primary_service_group_type,
                        )
                        .unwrap();
                    let response = &buffer[0..length];
                    trace!("  0x{:0>2x?}", response);
                    // It should be a successful response, because the service should be found, this will assert if
                    // we failed to retrieve the third service.
                    assert_eq!(response[0], att::ATT_READ_BY_GROUP_TYPE_RSP);
                    // The last handle of this group is at byte 4 & 5, so retrieve that and update the start for the
                    // next cycle. We only check the first response here, and ignore any others that may be in the
                    // response.
                    let last_handle = u16::from_le_bytes([response[4], response[5]]);
                    start = last_handle.saturating_add(1);
                }
            } else {
                panic!("expected connection to be accepted");
            };
        }
    }

    #[test]
    fn find_information_reports_128bit_format_and_widens_32bit() {
        // Regression: FIND_INFORMATION_RSP must report Format 0x02 (Core spec Vol 3 Part F,
        // 3.4.3.2) and a full 16-byte UUID body for both 128-bit and 32-bit characteristic
        // UUIDs. Before the fix the format byte was the uuid-kind tag (0x03 for 128-bit, which
        // is reserved), and a 32-bit UUID emitted a 4-byte body under a 0x02 header — both
        // malformed. A 32-bit UUID has no ATT format of its own, so it is widened against the
        // Bluetooth base UUID.
        let _ = env_logger::try_init();
        const MAX_ATTRIBUTES: usize = 64;
        const CONNECTIONS_MAX: usize = 3;

        let uuid128 = [
            0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01, 0x34, 0x12, 0x78, 0x56, 0xF0, 0xDE, 0xBC, 0x9A,
        ];
        let uuid32 = Uuid::Uuid32([0x11, 0x22, 0x33, 0x44]);

        let mut table: AttributeTable<'_, NoopRawMutex, { MAX_ATTRIBUTES }> = AttributeTable::new();
        let (h128, h32) = {
            let mut svc = table.add_service(Service {
                uuid: Uuid::new_long([0; 16]),
            });
            let c128 = svc
                .add_characteristic_ro::<[u8; 2], _>(Uuid::new_long(uuid128), &[0, 0])
                .build();
            let c32 = svc.add_characteristic_ro::<[u8; 2], _>(uuid32, &[0, 0]).build();
            (c128.handle, c32.handle)
        };

        let server = AttributeServer::<_, DefaultPacketPool, MAX_ATTRIBUTES, CONNECTIONS_MAX>::new(table);
        let mut buf = [0u8; 64];

        // 128-bit characteristic value: Format 0x02, the 16-byte UUID echoed back verbatim.
        let len = server.handle_find_information(&mut buf, h128, h128).unwrap();
        let rsp = &buf[..len];
        assert_eq!(rsp[0], att::ATT_FIND_INFORMATION_RSP);
        assert_eq!(
            rsp[1], 0x02,
            "128-bit UUID must report Format 0x02, not the 0x03 kind tag"
        );
        assert_eq!(len, 2 + 2 + 16, "one 18-byte entry: 2-byte handle + 16-byte UUID");
        assert_eq!(u16::from_le_bytes([rsp[2], rsp[3]]), h128);
        assert_eq!(&rsp[4..20], &uuid128);

        // 32-bit characteristic value: Format 0x02, widened to the 128-bit base UUID.
        let len = server.handle_find_information(&mut buf, h32, h32).unwrap();
        let rsp = &buf[..len];
        assert_eq!(rsp[0], att::ATT_FIND_INFORMATION_RSP);
        assert_eq!(
            rsp[1], 0x02,
            "32-bit UUID has no ATT format of its own; must report 0x02"
        );
        assert_eq!(len, 2 + 2 + 16, "32-bit UUID must be widened to a 16-byte body");
        assert_eq!(u16::from_le_bytes([rsp[2], rsp[3]]), h32);
        let expected = bt_hci::uuid::BluetoothUuid128::base()
            .set_initial_group(0x4433_2211)
            .to_le_bytes();
        assert_eq!(&rsp[4..20], &expected);
    }

    #[test]
    fn characteristic_subscription_predicates_read_their_own_cccd_bit() {
        let mut table: AttributeTable<'_, NoopRawMutex, 8> = AttributeTable::new();
        let characteristic = {
            let mut svc = table.add_service(Service {
                uuid: Uuid::new_short(0x1800),
            });
            svc.add_characteristic_small(
                Uuid::new_short(0x2A00),
                [CharacteristicProp::Notify, CharacteristicProp::Indicate],
                [0u8; 2],
            )
            .build()
        };
        let cccd_handle = characteristic.cccd_handle.expect("notify/indicate adds a CCCD");
        let server = AttributeServer::<_, DefaultPacketPool, 8, 1>::new(table);

        let mgr = setup();
        assert!(mgr.poll_accept(LeConnRole::Peripheral, &[], None).is_pending());
        unwrap!(mgr.connect(
            ConnHandle::new(0),
            Address::new(AddrKind::RANDOM, BdAddr::new(ADDR_1)),
            LeConnRole::Peripheral,
            ConnParams::new(),
        ));
        let Poll::Ready(conn) = mgr.poll_accept(LeConnRole::Peripheral, &[], None) else {
            panic!("expected connection to be accepted");
        };
        let conn = unwrap!(GattConnection::try_new(conn, &server));

        for (cccd, notify, indicate) in [
            ([0x00, 0x00], false, false),
            ([0x01, 0x00], true, false),
            ([0x02, 0x00], false, true),
            ([0x03, 0x00], true, true),
        ] {
            unwrap!(sealed::DynamicAttributeServer::set(
                &server,
                conn.raw(),
                cccd_handle,
                &cccd
            ));
            assert_eq!(characteristic.should_notify(&conn), notify, "CCCD {cccd:02x?}");
            assert_eq!(characteristic.should_indicate(&conn), indicate, "CCCD {cccd:02x?}");
        }
    }

    #[cfg(feature = "gatt-caching")]
    mod caching {
        extern crate std;

        use std::boxed::Box;

        use bt_hci::uuid::characteristic::{CLIENT_SUPPORTED_FEATURES, DATABASE_HASH, SERVICE_CHANGED};
        use bt_hci::uuid::descriptors::CLIENT_CHARACTERISTIC_CONFIGURATION;
        use embassy_futures::block_on;
        use embassy_futures::join::join;

        use super::*;
        use crate::connection_manager::tests::ADDR_2;
        use crate::connection_manager::ConnectionManager;
        use crate::gatt::GattConnection;

        const SIZE: usize = GAP_SERVICE_ATTRIBUTE_COUNT + 4;
        // GAP 1..=5 (with security and central 1..=7), GATT from 6: Service
        // Changed, then a service of one characteristic that is read,
        // written and notifies.
        const GATT: u16 = if cfg!(feature = "central") { 8 } else { 6 };
        const SERVICE_CHANGED_VALUE: u16 = GATT + 2;
        const SERVICE_CHANGED_CCCD: u16 = GATT + 3;
        const SUBSCRIBED: ClientCaching = ClientCaching {
            service_changed: true,
            change_aware: false,
        };
        const NEW: ClientCaching = ClientCaching {
            service_changed: false,
            change_aware: true,
        };

        type Server<const CONN: usize> = AttributeServer<'static, NoopRawMutex, DefaultPacketPool, SIZE, CONN>;

        struct Setup<const CONN: usize = 1> {
            mgr: &'static ConnectionManager<'static, DefaultPacketPool>,
            server: &'static Server<CONN>,
            characteristic: Characteristic<[u8; 2]>,
            conn: Connection<'static, DefaultPacketPool>,
        }

        fn setup_caching() -> Setup {
            setup_slots()
        }

        /// A server with `CONN` client slots, and one client connected.
        fn setup_slots<const CONN: usize>() -> Setup<CONN> {
            let mut table: AttributeTable<'static, NoopRawMutex, SIZE> = AttributeTable::new();
            unwrap!(GapConfig::default("trouble").build(&mut table));
            let characteristic = table
                .add_service(Service::new(Uuid::new_short(0x180d)))
                .add_characteristic_small(
                    Uuid::new_short(0x2a37),
                    [
                        CharacteristicProp::Read,
                        CharacteristicProp::WriteWithoutResponse,
                        CharacteristicProp::Notify,
                    ],
                    [0u8; 2],
                )
                .build();
            let server: &'static Server<CONN> = Box::leak(Box::new(AttributeServer::new(table)));
            let mgr = setup();
            assert!(mgr.poll_accept(LeConnRole::Peripheral, &[], None).is_pending());
            let conn = connect_peer(mgr, 0, ADDR_1);
            unwrap!(server.connect(&conn));
            Setup {
                mgr,
                server,
                characteristic,
                conn,
            }
        }

        fn connect_peer(
            mgr: &'static ConnectionManager<'static, DefaultPacketPool>,
            handle: u16,
            addr: [u8; 6],
        ) -> Connection<'static, DefaultPacketPool> {
            unwrap!(mgr.connect(
                ConnHandle::new(handle),
                Address::new(AddrKind::RANDOM, BdAddr::new(addr)),
                LeConnRole::Peripheral,
                ConnParams::new(),
            ));
            let Poll::Ready(conn) = mgr.poll_accept(LeConnRole::Peripheral, &[], None) else {
                panic!("expected connection to be accepted");
            };
            conn
        }

        /// The stack keeps a bond with the client of `conn`.
        fn bond<const CONN: usize>(s: &Setup<CONN>, conn: &Connection<'static, DefaultPacketPool>) {
            let bond = BondInformation::new(
                conn.peer_identity(),
                crate::security_manager::LongTermKey::new(1),
                SecurityLevel::EncryptedAuthenticated,
                true,
            );
            unwrap!(s.mgr.security_manager.add_bond_information(bond));
        }

        fn disconnect<const CONN: usize>(s: &Setup<CONN>, conn: &Connection<'static, DefaultPacketPool>) {
            sealed::DynamicAttributeServer::disconnect(s.server, conn);
        }

        /// The client enables Service Changed indications over the air.
        fn subscribe<const CONN: usize>(s: &Setup<CONN>, conn: &Connection<'static, DefaultPacketPool>) {
            let mut buf = [0u8; 8];
            unwrap!(s.server.handle_write_req(conn, &mut buf, SERVICE_CHANGED_CCCD, &[2, 0]));
        }

        fn change_aware(setup: &Setup) -> bool {
            unwrap!(setup.server.client_caching(&setup.conn)).change_aware
        }

        /// A bonded client's next connection: the server keeps its state.
        fn reconnect(setup: &Setup) {
            unwrap!(setup.server.connect(&setup.conn));
        }

        /// A PDU from the client.
        fn pdu(bytes: &[u8]) -> crate::pdu::Pdu<<DefaultPacketPool as PacketPool>::Packet> {
            let mut packet = unwrap!(DefaultPacketPool::allocate());
            packet.as_mut()[..bytes.len()].copy_from_slice(bytes);
            crate::pdu::Pdu::new(packet, bytes.len())
        }

        /// What the server answers `bytes` through `GattEvent`, as an
        /// application that accepts every event does.
        fn answer(s: &Setup, bytes: &[u8]) -> Option<std::vec::Vec<u8>> {
            let data = crate::gatt::GattData::new(pdu(bytes), s.conn.clone());
            let reply = unwrap!(crate::gatt::GattEvent::new(data, s.server).accept());
            reply.consume_att_payload(|payload| payload.map(|payload| payload.to_vec()))
        }

        #[test]
        fn the_gatt_service_carries_service_changed_alone() {
            let s = setup_caching();
            let table = s.server.table();
            assert_eq!(table.uuid(GATT), Some(PRIMARY_SERVICE.into()));
            assert_eq!(table.uuid(SERVICE_CHANGED_VALUE), Some(SERVICE_CHANGED.into()));
            assert_eq!(
                table.uuid(SERVICE_CHANGED_CCCD),
                Some(CLIENT_CHARACTERISTIC_CONFIGURATION.into())
            );
            assert_eq!(table.uuid(SERVICE_CHANGED_CCCD + 1), Some(PRIMARY_SERVICE.into()));
            // Neither Database Hash, which beside Service Changed obliges the
            // server to Robust Caching, nor Client Supported Features, which
            // shall not exist without them.
            for handle in 1..=SIZE as u16 {
                let uuid = table.uuid(handle);
                assert_ne!(uuid, Some(DATABASE_HASH.into()));
                assert_ne!(uuid, Some(CLIENT_SUPPORTED_FEATURES.into()));
            }
        }

        // A GAP service of Device Name and Appearance, then the GATT service
        // as `build_gatt_service` makes it. The expected hash is not from the
        // specification: it is the AES-CMAC, with a zero key, of this
        // message (Core Spec Vol 3, Part G, Section 7.3.1), each line a
        // handle, a type and, for declarations, the value:
        //
        // 0100 0028 0018
        // 0200 0328 02 0300 002a
        // 0400 0328 02 0500 012a
        // 0600 0028 0118
        // 0700 0328 20 0800 052a
        // 0900 0229
        //
        // > xxd -plain -revert message.txt message.bin
        // > openssl mac -cipher AES-128-CBC -macopt hexkey:00000000000000000000000000000000 -in message.bin CMAC
        // 7C3F23502BD8432AC1F1246426949C50
        #[test]
        fn the_database_hash_of_the_gap_and_gatt_services() {
            use bt_hci::uuid::characteristic::{APPEARANCE, DEVICE_NAME};
            let mut table: AttributeTable<'static, NoopRawMutex, 9> = AttributeTable::new();
            let mut gap = table.add_service(Service::new(bt_hci::uuid::service::GAP));
            gap.add_characteristic_ro(DEVICE_NAME, "trouble");
            gap.add_characteristic_ro(APPEARANCE, &appearance::UNKNOWN);
            gap.build();
            crate::gap::build_gatt_service(&mut table);
            let server = AttributeServer::<_, DefaultPacketPool, 9, 1>::new(table);
            assert_eq!(server.database_hash(), 0x7c3f23502bd8432ac1f1246426949c50);
        }

        #[test]
        fn another_table_has_another_hash() {
            let s = setup_caching();
            let mut table: AttributeTable<'static, NoopRawMutex, SIZE> = AttributeTable::new();
            unwrap!(GapConfig::default("trouble").build(&mut table));
            table
                .add_service(Service::new(Uuid::new_short(0x180d)))
                .add_characteristic_small(Uuid::new_short(0x2a38), [CharacteristicProp::Notify], [0u8; 2])
                .build();
            let other = AttributeServer::<_, DefaultPacketPool, SIZE, 1>::new(table);
            assert_ne!(other.database_hash(), s.server.database_hash());
            assert_eq!(s.server.database_hash(), s.server.table().hash());
        }

        #[test]
        fn a_new_client_knows_the_database_and_is_not_subscribed() {
            let s = setup_caching();
            assert_eq!(s.server.client_caching(&s.conn), Some(NEW));
        }

        #[test]
        fn a_client_subscribes_over_the_air() {
            let s = setup_caching();
            subscribe(&s, &s.conn);
            assert_eq!(
                s.server.client_caching(&s.conn),
                Some(ClientCaching {
                    change_aware: true,
                    ..SUBSCRIBED
                })
            );
        }

        #[test]
        fn a_kept_state_is_restored() {
            let s = setup_caching();
            assert!(s.server.restore_client_caching(&s.conn, SUBSCRIBED));
            assert_eq!(s.server.client_caching(&s.conn), Some(SUBSCRIBED));
        }

        #[test]
        fn a_state_held_from_an_earlier_connection_is_kept() {
            let s = setup_caching();
            subscribe(&s, &s.conn);
            reconnect(&s);
            assert!(!s.server.restore_client_caching(&s.conn, ClientCaching::default()));
            assert!(unwrap!(s.server.client_caching(&s.conn)).service_changed);
        }

        // Without Robust Caching, a client that does not know the database
        // is served as any other, through `GattEvent` as an application
        // meets its PDUs: its requests, its commands and its notifications.
        #[test]
        fn a_client_that_does_not_know_the_database_is_served() {
            use embassy_futures::poll_once;
            let s = setup_caching();
            let cccd = unwrap!(s.characteristic.cccd_handle);
            unwrap!(sealed::DynamicAttributeServer::set(s.server, &s.conn, cccd, &[1, 0]));
            s.server.restore_client_caching(&s.conn, SUBSCRIBED);
            let gatt = unwrap!(GattConnection::try_new(s.conn.clone(), s.server));

            let value = s.characteristic.handle.to_le_bytes();
            assert_eq!(answer(&s, &[att::ATT_WRITE_CMD, value[0], value[1], 7, 7]), None);
            assert_eq!(unwrap!(s.server.table().get(&s.characteristic)), [7, 7]);
            assert_eq!(
                answer(&s, &[att::ATT_READ_REQ, value[0], value[1]]).as_deref(),
                Some(&[att::ATT_READ_RSP, 7, 7][..])
            );
            let notified = poll_once(s.characteristic.notify(&gatt, &[1, 2], false));
            assert!(matches!(notified, Poll::Ready(Ok(()))));
            let Poll::Ready((_, pdu)) = poll_once(s.mgr.outbound()) else {
                panic!("expected a notification");
            };
            assert_eq!(
                &pdu.as_ref()[4..],
                &[att::ATT_HANDLE_VALUE_NTF, value[0], value[1], 1, 2]
            );
            assert!(!change_aware(&s));
        }

        /// The client pairs and bonds again.
        fn bond_again(s: &Setup) {
            sealed::DynamicAttributeServer::bond_added(s.server, &s.conn.peer_identity());
        }

        #[test]
        fn a_new_bond_drops_what_the_client_set_under_the_old_one() {
            let s = setup_caching();
            subscribe(&s, &s.conn);
            reconnect(&s);
            bond_again(&s);
            assert_eq!(s.server.client_caching(&s.conn), Some(NEW));
            // The application's copy is of the old bond.
            assert!(!s.server.restore_client_caching(&s.conn, SUBSCRIBED));
        }

        #[test]
        fn a_new_bond_drops_a_restored_state() {
            let s = setup_caching();
            assert!(s.server.restore_client_caching(&s.conn, SUBSCRIBED));
            bond_again(&s);
            assert_eq!(s.server.client_caching(&s.conn), Some(NEW));
        }

        #[test]
        fn a_new_bond_keeps_what_the_client_wrote_on_this_connection() {
            let s = setup_caching();
            subscribe(&s, &s.conn);
            reconnect(&s);
            subscribe(&s, &s.conn);
            bond_again(&s);
            assert_eq!(
                s.server.client_caching(&s.conn),
                Some(ClientCaching {
                    service_changed: true,
                    ..NEW
                })
            );
        }

        #[test]
        fn a_first_bond_keeps_what_the_client_set_before_pairing() {
            let s = setup_caching();
            subscribe(&s, &s.conn);
            bond_again(&s);
            assert_eq!(
                s.server.client_caching(&s.conn),
                Some(ClientCaching {
                    change_aware: true,
                    ..SUBSCRIBED
                })
            );
        }

        #[test]
        fn service_changed_is_at_its_fixed_handle() {
            assert_eq!(SERVICE_CHANGED_VALUE, crate::gap::SERVICE_CHANGED_VALUE_HANDLE);
            let s = setup_caching();
            assert_eq!(unwrap!(s.server.caching).service_changed, SERVICE_CHANGED_VALUE);
        }

        #[test]
        fn an_unbonded_client_leaves_nothing_behind() {
            let s = setup_caching();
            subscribe(&s, &s.conn);
            s.server.restore_client_caching(&s.conn, SUBSCRIBED);
            disconnect(&s, &s.conn);
            unwrap!(s.server.connect(&s.conn));
            assert_eq!(s.server.client_caching(&s.conn), Some(NEW));
        }

        #[test]
        fn a_bonded_client_finds_its_state_on_its_next_connection() {
            let s = setup_caching();
            bond(&s, &s.conn);
            subscribe(&s, &s.conn);
            disconnect(&s, &s.conn);
            unwrap!(s.server.connect(&s.conn));
            assert!(!s.server.restore_client_caching(&s.conn, NEW));
            assert_eq!(
                s.server.client_caching(&s.conn),
                Some(ClientCaching {
                    change_aware: true,
                    ..SUBSCRIBED
                })
            );
        }

        #[test]
        fn a_booted_slot_leaves_nothing_behind() {
            let s = setup_caching();
            bond(&s, &s.conn);
            subscribe(&s, &s.conn);
            disconnect(&s, &s.conn);
            // The only slot goes to another client.
            let other = connect_peer(s.mgr, 1, ADDR_2);
            unwrap!(s.server.connect(&other));
            assert_eq!(s.server.client_caching(&other), Some(NEW));
            assert_eq!(s.server.client_caching(&s.conn), None);
            disconnect(&s, &other);
            unwrap!(s.server.connect(&s.conn));
            assert_eq!(s.server.client_caching(&s.conn), Some(NEW));
            // Nothing held: what the application kept is restored.
            assert!(s.server.restore_client_caching(&s.conn, SUBSCRIBED));
        }

        #[test]
        fn a_removed_bond_leaves_nothing_behind() {
            let s = setup_caching();
            bond(&s, &s.conn);
            subscribe(&s, &s.conn);
            disconnect(&s, &s.conn);
            unwrap!(s.mgr.security_manager.remove_bond_information(s.conn.peer_identity()));
            unwrap!(s.server.connect(&s.conn));
            assert_eq!(s.server.client_caching(&s.conn), Some(NEW));
            assert!(s.server.restore_client_caching(&s.conn, SUBSCRIBED));
        }

        #[test]
        fn a_removed_bond_frees_its_slot_for_another_client() {
            let s = setup_slots::<2>();
            bond(&s, &s.conn);
            subscribe(&s, &s.conn);
            disconnect(&s, &s.conn);
            unwrap!(s.mgr.security_manager.remove_bond_information(s.conn.peer_identity()));
            let other = connect_peer(s.mgr, 1, ADDR_2);
            unwrap!(s.server.connect(&other));
            assert_eq!(s.server.client_caching(&s.conn), None);
        }

        #[test]
        fn a_bonded_client_finds_its_slot_behind_an_empty_one() {
            let s = setup_slots::<2>();
            // Slot 0 for an unbonded client, slot 1 for the bonded one.
            let other = s.conn.clone();
            let bonded = connect_peer(s.mgr, 1, ADDR_2);
            unwrap!(s.server.connect(&bonded));
            bond(&s, &bonded);
            subscribe(&s, &bonded);
            disconnect(&s, &bonded);
            disconnect(&s, &other);
            unwrap!(s.server.connect(&bonded));
            assert!(!s.server.restore_client_caching(&bonded, NEW));
            assert!(unwrap!(s.server.client_caching(&bonded)).service_changed);
        }

        #[test]
        fn service_changed_is_indicated_for_the_whole_database() {
            let s = setup_caching();
            s.server.restore_client_caching(&s.conn, SUBSCRIBED);
            let gatt = unwrap!(GattConnection::try_new(s.conn.clone(), s.server));
            let peer = async {
                let (handle, pdu) = s.mgr.outbound().await;
                // L2CAP header, then Handle Value Indication of Service Changed:
                // affected handles 0x0001 to 0xFFFF.
                assert_eq!(
                    &pdu.as_ref()[4..],
                    &[
                        att::ATT_HANDLE_VALUE_IND,
                        SERVICE_CHANGED_VALUE as u8,
                        0,
                        0x01,
                        0x00,
                        0xff,
                        0xff
                    ]
                );
                s.mgr.signal_indication_confirmation(handle);
            };
            let (indicated, ()) = block_on(join(s.server.indicate_service_changed(&gatt), peer));
            assert_eq!(indicated, Ok(true));
            // Confirmed: the client knows the database, and is owed nothing.
            assert!(change_aware(&s));
            assert_eq!(block_on(s.server.indicate_service_changed(&gatt)), Ok(false));
        }

        #[test]
        fn service_changed_is_not_indicated_to_a_client_that_knows_the_database() {
            let s = setup_caching();
            s.server.restore_client_caching(
                &s.conn,
                ClientCaching {
                    change_aware: true,
                    ..SUBSCRIBED
                },
            );
            let gatt = unwrap!(GattConnection::try_new(s.conn.clone(), s.server));
            assert_eq!(block_on(s.server.indicate_service_changed(&gatt)), Ok(false));
            assert!(change_aware(&s));
        }

        #[test]
        fn service_changed_is_not_indicated_unasked() {
            let s = setup_caching();
            s.server.restore_client_caching(
                &s.conn,
                ClientCaching {
                    service_changed: false,
                    ..SUBSCRIBED
                },
            );
            let gatt = unwrap!(GattConnection::try_new(s.conn.clone(), s.server));
            assert_eq!(block_on(s.server.indicate_service_changed(&gatt)), Ok(false));
            assert!(!change_aware(&s));
        }

        #[test]
        fn caching_needs_service_changed_as_the_gatt_service_lays_it_out() {
            // Service Changed without its CCCD.
            let mut table: AttributeTable<'static, NoopRawMutex, SIZE> = AttributeTable::new();
            let mut gatt = table.add_service(Service::new(Uuid::new_short(0x1801)));
            gatt.add_characteristic_small(SERVICE_CHANGED, [CharacteristicProp::Read], [0u8; 4]);
            gatt.build();
            assert!(CachingHandles::find(&table).is_none());
            // As `build_gatt_service` lays it out.
            let s = setup_caching();
            let handles = unwrap!(CachingHandles::find(s.server.table()));
            assert_eq!(
                (handles.service_changed, handles.service_changed_cccd),
                (SERVICE_CHANGED_VALUE, SERVICE_CHANGED_CCCD)
            );
        }
    }
}
