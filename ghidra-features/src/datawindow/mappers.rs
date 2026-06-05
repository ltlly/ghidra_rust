//! Data window table mappers -- convert data row objects to addresses/locations.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.datawindow`:
//!
//! - [`DataRowToAddressMapper`] -- maps data rows to addresses
//! - [`DataRowToLocationMapper`] -- maps data rows to program locations

use super::DataRowObject;

/// Mapper that converts a `DataRowObject` to an address for navigation.
///
/// Ported from `ghidra.app.plugin.core.datawindow.DataRowObjectToAddressTableRowMapper`.
#[derive(Debug)]
pub struct DataRowToAddressMapper;

impl DataRowToAddressMapper {
    /// Map a row object to its address.
    pub fn get_address(row: &DataRowObject) -> u64 {
        row.address_key
    }
}

/// Mapper that converts a `DataRowObject` to a program location.
///
/// Ported from `ghidra.app.plugin.core.datawindow.DataRowObjectToProgramLocationTableRowMapper`.
#[derive(Debug)]
pub struct DataRowToLocationMapper;

impl DataRowToLocationMapper {
    /// Map a row object to a program location (address, type name, offset).
    pub fn get_location(row: &DataRowObject) -> (u64, &str, u32) {
        (row.address_key, &row.type_name, row.length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_mapper() {
        let row = DataRowObject::new(0x400000, "0x400000", "dword", "0x12345678", 4);
        assert_eq!(DataRowToAddressMapper::get_address(&row), 0x400000);
    }

    #[test]
    fn test_location_mapper() {
        let row = DataRowObject::new(0x400000, "0x400000", "string", "hello", 6);
        let (addr, type_name, len) = DataRowToLocationMapper::get_location(&row);
        assert_eq!(addr, 0x400000);
        assert_eq!(type_name, "string");
        assert_eq!(len, 6);
    }
}
