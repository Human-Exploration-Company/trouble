//! ## Generic Access Profile
//!
//! This profile defines the generic procedures related to discovery of
//! Bluetooth devices (idle mode procedures) and link management aspects
//! of connecting to Bluetooth devices (connecting mode procedures).
//! It also defines procedures related to use of different security levels.
//! In addition, this profile includes common format requirements for
//! parameters accessible on the user interface level.

use embassy_sync::blocking_mutex::raw::RawMutex;

use crate::prelude::*;

/// Advertising packet is limited to 31 bytes. 9 of these are used by other GAP data, leaving 22 bytes for the Device Name characteristic
const DEVICE_NAME_MAX_LENGTH: usize = 22;

/// The number of attributes added by the GAP and GATT services
/// GAP_SERVICE:                      1
/// ├── DEVICE_NAME:                  2
/// ├── APPEARANCE:                   2
/// └── CENTRAL_ADDRESS_RESOLUTION:   2 (security+central only)
/// GATT_SERVICE:                   + 1
/// └── SERVICE_CHANGED:              3 (gatt-caching only)
///                                 ---
///                                 = 6 (or 8 with security+central), 3 more with gatt-caching
pub const GAP_SERVICE_ATTRIBUTE_COUNT: usize =
    6 + if cfg!(all(feature = "security", feature = "central")) {
        2
    } else {
        0
    } + GATT_CACHING_ATTRIBUTE_COUNT;

#[cfg(feature = "gatt-caching")]
const GATT_CACHING_ATTRIBUTE_COUNT: usize = 3;
#[cfg(not(feature = "gatt-caching"))]
const GATT_CACHING_ATTRIBUTE_COUNT: usize = 0;

/// The handle of the Service Changed characteristic value when the table
/// starts with the GAP and GATT services, as `#[gatt_server]` builds it: 8,
/// or 10 with `security` and `central`. It shall not change while the
/// server has a trusted relationship with any client (Core Spec Vol 3,
/// Part G, Section 7.1), so neither may the features that size the GAP
/// service.
#[cfg(feature = "gatt-caching")]
pub const SERVICE_CHANGED_VALUE_HANDLE: u16 = (GAP_SERVICE_ATTRIBUTE_COUNT - GATT_CACHING_ATTRIBUTE_COUNT) as u16 + 2;

/// Configuration for the GAP Service.
pub enum GapConfig<'a> {
    /// Peripheral device configuration.
    Peripheral(PeripheralConfig<'a>),
    /// Central device configuration.
    Central(CentralConfig<'a>),
}

/// Configuration for a peripheral device GAP Service.
pub struct PeripheralConfig<'a> {
    /// The name of the peripheral device.
    pub name: &'a str,
    /// The representation of the external appearance of the device.
    ///
    /// Example: `&appearance::sensor::GENERIC_SENSOR.`
    pub appearance: &'a BluetoothUuid16,
    // TODO: Add more GAP parameters
    // pub preferred_connection_parameters: Option<ConnectionParameters>,
}

/// Configuration for a central device GAP Service.
pub struct CentralConfig<'a> {
    /// The name of the central device.
    pub name: &'a str,
    /// The representation of the external appearance of the device.
    ///
    /// Example: `&appearance::sensor::GENERIC_SENSOR`
    pub appearance: &'a BluetoothUuid16,
    // TODO: Add more GAP parameters
}

impl<'a> GapConfig<'a> {
    /// Create a default peripheral configuration.
    ///
    /// This configuration will use the `UNKNOWN` appearance.
    pub fn default(name: &'a str) -> Self {
        GapConfig::Peripheral(PeripheralConfig {
            name,
            appearance: &appearance::UNKNOWN,
        })
    }

    /// Add the GAP config to the attribute table
    pub fn build<M: RawMutex, const MAX: usize>(
        self,
        table: &mut AttributeTable<'a, M, MAX>,
    ) -> Result<(), &'static str> {
        match self {
            GapConfig::Peripheral(config) => config.build(table),
            GapConfig::Central(config) => config.build(table),
        }
    }
}

impl<'a> PeripheralConfig<'a> {
    /// Add the peripheral GAP config to the attribute table
    fn build<M: RawMutex, const MAX: usize>(self, table: &mut AttributeTable<'a, M, MAX>) -> Result<(), &'static str> {
        // Store the name by reference (lives for `'a`); a one-shot StaticCell
        // would panic if the server is ever built twice.
        if self.name.len() > DEVICE_NAME_MAX_LENGTH {
            return Err("Device name is too long. Max length is 22 bytes");
        }

        let mut gap_builder = table.add_service(Service::new(service::GAP));
        gap_builder.add_characteristic_ro(characteristic::DEVICE_NAME, self.name);
        gap_builder.add_characteristic_ro(characteristic::APPEARANCE, self.appearance);
        #[cfg(all(feature = "security", feature = "central"))]
        gap_builder.add_characteristic_ro(characteristic::CENTRAL_ADDRESS_RESOLUTION, &1u8);
        gap_builder.build();

        build_gatt_service(table);

        Ok(())
    }
}

impl<'a> CentralConfig<'a> {
    /// Add the peripheral GAP config to the attribute table
    fn build<M: RawMutex, const MAX: usize>(self, table: &mut AttributeTable<'a, M, MAX>) -> Result<(), &'static str> {
        // Store the name by reference (lives for `'a`); a one-shot StaticCell
        // would panic if the server is ever built twice.
        if self.name.len() > DEVICE_NAME_MAX_LENGTH {
            return Err("Device name is too long. Max length is 22 bytes");
        }

        let mut gap_builder = table.add_service(Service::new(service::GAP));
        gap_builder.add_characteristic_ro(characteristic::DEVICE_NAME, self.name);
        gap_builder.add_characteristic_ro(characteristic::APPEARANCE, self.appearance);
        #[cfg(all(feature = "security", feature = "central"))]
        gap_builder.add_characteristic_ro(characteristic::CENTRAL_ADDRESS_RESOLUTION, &1u8);
        gap_builder.build();

        build_gatt_service(table);

        Ok(())
    }
}

/// The GATT service. With `gatt-caching` it carries Service Changed (Core
/// Spec Vol 3, Part G, Section 7.1), so that a client that kept the table
/// hears when it changes. Neither Database Hash nor Client Supported
/// Features: with Service Changed, the Database Hash obliges the server to
/// Robust Caching (Section 2.5.2.1), and without the hash, Enhanced ATT and
/// multiple handle value notifications, Client Supported Features shall not
/// exist (Section 7, Table 7.1, C.2).
pub(crate) fn build_gatt_service<M: RawMutex, const MAX: usize>(table: &mut AttributeTable<'_, M, MAX>) {
    #[allow(unused_mut)]
    let mut gatt_builder = table.add_service(Service::new(service::GATT));
    #[cfg(feature = "gatt-caching")]
    {
        use crate::attribute::{AttributeData, CharacteristicProps, MAX_SMALL_DATA_SIZE};
        // The value is only ever indicated, never read. Written out rather
        // than through `add_characteristic_small`, whose every value type
        // carries its own copy of the code.
        let data = AttributeData::SmallData {
            variable_len: false,
            capacity: 4,
            len: 4,
            value: [0; MAX_SMALL_DATA_SIZE],
        };
        let props = CharacteristicProps::from(CharacteristicProp::Indicate as u8);
        gatt_builder.push_characteristic(
            characteristic::SERVICE_CHANGED.into(),
            props,
            props.default_permissions(),
            data,
        );
    }
    gatt_builder.build();
}

#[cfg(test)]
mod tests {
    extern crate std;

    use embassy_sync::blocking_mutex::raw::NoopRawMutex;

    use super::*;

    // Building the GAP config twice must not panic. With the one-shot StaticCell
    // the second build panicked ("StaticCell already full").
    #[test]
    fn gap_config_can_be_built_twice() {
        for _ in 0..2 {
            let mut table: AttributeTable<'_, NoopRawMutex, 16> = AttributeTable::new();
            GapConfig::Peripheral(PeripheralConfig {
                name: "trouble",
                appearance: &appearance::UNKNOWN,
            })
            .build(&mut table)
            .unwrap();
        }
    }
}
