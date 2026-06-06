//! Address, label, and namespace table columns.
//!
//! Ported from `ghidra.util.table.field`:
//! - `AddressTableColumn` -- displays the address for a row.
//! - `AddressTableDataTableColumn` -- displays the address for data rows.
//! - `AddressTableLengthTableColumn` -- displays address range length.
//! - `LabelTableColumn` -- displays the symbol label at an address.
//! - `NamespaceTableColumn` -- displays the namespace of a symbol.
//! - `EOLCommentTableColumn` -- displays end-of-line comments.

use ghidra_core::addr::Address;

use super::traits::{ProgramBasedDynamicTableColumn, ProgramInfo, ProgramLocationTableColumn,
                    ProgramLocationTableColumnExt, ServiceProvider, Settings};
use super::core::AddressBasedLocation;
use super::super::mapper::ProgramLocation;

// ---------------------------------------------------------------------------
// AddressTableColumn
// ---------------------------------------------------------------------------

/// Displays the address for a table row.
///
/// Ported from `ghidra.util.table.field.AddressTableColumn`.
#[derive(Debug)]
pub struct AddressTableColumn;

impl ProgramBasedDynamicTableColumn<Address> for AddressTableColumn {
    fn column_name(&self) -> &str { "Location" }

    fn column_display_name(&self, _settings: &Settings) -> String {
        self.column_name().to_string()
    }

    fn get_value(&self, row: &Address, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        Some(format!("0x{:x}", row.offset))
    }

    fn preferred_width(&self) -> usize { 200 }
}

impl ProgramLocationTableColumn<Address> for AddressTableColumn {
    fn get_program_location(&self, row: &Address, _settings: &Settings,
                            _program: &ProgramInfo, _sp: &ServiceProvider)
        -> Option<ProgramLocation> {
        Some(ProgramLocation::new(*row))
    }
}

impl ProgramLocationTableColumnExt<Address> for AddressTableColumn {}

// ---------------------------------------------------------------------------
// AddressTableDataTableColumn
// ---------------------------------------------------------------------------

/// Displays the address for data table rows (address-based location rendering).
///
/// Ported from `ghidra.util.table.field.AddressTableDataTableColumn`.
#[derive(Debug)]
pub struct AddressTableDataTableColumn;

impl ProgramBasedDynamicTableColumn<Address> for AddressTableDataTableColumn {
    fn column_name(&self) -> &str { "Address" }

    fn get_value(&self, row: &Address, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        let loc = AddressBasedLocation::from_address(*row);
        Some(loc.to_string())
    }

    fn preferred_width(&self) -> usize { 150 }
}

impl ProgramLocationTableColumn<Address> for AddressTableDataTableColumn {
    fn get_program_location(&self, row: &Address, _settings: &Settings,
                            _program: &ProgramInfo, _sp: &ServiceProvider)
        -> Option<ProgramLocation> {
        Some(ProgramLocation::new(*row))
    }
}

impl ProgramLocationTableColumnExt<Address> for AddressTableDataTableColumn {}

// ---------------------------------------------------------------------------
// AddressTableLengthTableColumn
// ---------------------------------------------------------------------------

/// Displays the length of an address range.
///
/// Ported from `ghidra.util.table.field.AddressTableLengthTableColumn`.
#[derive(Debug)]
pub struct AddressTableLengthTableColumn;

impl ProgramBasedDynamicTableColumn<(Address, Address)> for AddressTableLengthTableColumn {
    fn column_name(&self) -> &str { "Length" }

    fn get_value(&self, row: &(Address, Address), _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        let len = row.1.offset.saturating_sub(row.0.offset);
        Some(format!("0x{:x}", len))
    }

    fn preferred_width(&self) -> usize { 80 }
}

// ---------------------------------------------------------------------------
// LabelTableColumn
// ---------------------------------------------------------------------------

/// Displays the symbol label at a program location.
///
/// Ported from `ghidra.util.table.field.LabelTableColumn`.
#[derive(Debug)]
pub struct LabelTableColumn;

impl ProgramBasedDynamicTableColumn<ProgramLocation> for LabelTableColumn {
    fn column_name(&self) -> &str { "Label" }

    fn get_value(&self, row: &ProgramLocation, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        // In a real implementation, this would look up the symbol table.
        // Here we format the address as a fallback.
        Some(format!("0x{:x}", row.address.offset))
    }

    fn preferred_width(&self) -> usize { 200 }
}

impl ProgramLocationTableColumn<ProgramLocation> for LabelTableColumn {
    fn get_program_location(&self, row: &ProgramLocation, _settings: &Settings,
                            _program: &ProgramInfo, _sp: &ServiceProvider)
        -> Option<ProgramLocation> {
        Some(row.clone())
    }
}

impl ProgramLocationTableColumnExt<ProgramLocation> for LabelTableColumn {}

// ---------------------------------------------------------------------------
// NamespaceTableColumn
// ---------------------------------------------------------------------------

/// Displays the namespace of a symbol.
///
/// Ported from `ghidra.util.table.field.NamespaceTableColumn`.
#[derive(Debug)]
pub struct NamespaceTableColumn;

impl ProgramBasedDynamicTableColumn<ProgramLocation> for NamespaceTableColumn {
    fn column_name(&self) -> &str { "Namespace" }

    fn get_value(&self, _row: &ProgramLocation, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        // In a real implementation, this would look up the symbol's namespace.
        Some("Global".to_string())
    }

    fn preferred_width(&self) -> usize { 120 }
}

// ---------------------------------------------------------------------------
// EOLCommentTableColumn
// ---------------------------------------------------------------------------

/// Displays end-of-line comments at a program location.
///
/// Ported from `ghidra.util.table.field.EOLCommentTableColumn`.
#[derive(Debug)]
pub struct EOLCommentTableColumn;

impl ProgramBasedDynamicTableColumn<ProgramLocation> for EOLCommentTableColumn {
    fn column_name(&self) -> &str { "EOL Comment" }

    fn get_value(&self, _row: &ProgramLocation, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        // In a real implementation, this would look up comments in the listing.
        None
    }

    fn preferred_width(&self) -> usize { 200 }
}

impl ProgramLocationTableColumn<ProgramLocation> for EOLCommentTableColumn {
    fn get_program_location(&self, row: &ProgramLocation, _settings: &Settings,
                            _program: &ProgramInfo, _sp: &ServiceProvider)
        -> Option<ProgramLocation> {
        Some(row.clone())
    }
}

impl ProgramLocationTableColumnExt<ProgramLocation> for EOLCommentTableColumn {}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_program() -> ProgramInfo {
        ProgramInfo::new("test", "x86:LE:64:default")
    }

    fn test_sp() -> ServiceProvider {
        ServiceProvider::new("TestTool")
    }

    #[test]
    fn test_address_table_column() {
        let col = AddressTableColumn;
        assert_eq!(col.column_name(), "Location");
        assert_eq!(col.preferred_width(), 200);
        let addr = Address::new(0x401000);
        let val = col.get_value(&addr, &Settings::new(), &test_program(), &test_sp());
        assert_eq!(val.unwrap(), "0x401000");
    }

    #[test]
    fn test_address_table_column_location() {
        let col = AddressTableColumn;
        let addr = Address::new(0x401000);
        let loc = col.get_program_location(&addr, &Settings::new(), &test_program(), &test_sp());
        assert!(loc.is_some());
        assert_eq!(loc.unwrap().address.offset, 0x401000);
    }

    #[test]
    fn test_address_table_data_column() {
        let col = AddressTableDataTableColumn;
        assert_eq!(col.column_name(), "Address");
        let addr = Address::new(0x1000);
        let val = col.get_value(&addr, &Settings::new(), &test_program(), &test_sp());
        assert_eq!(val.unwrap(), "0x1000");
    }

    #[test]
    fn test_address_table_length_column() {
        let col = AddressTableLengthTableColumn;
        assert_eq!(col.column_name(), "Length");
        let range = (Address::new(0x1000), Address::new(0x1040));
        let val = col.get_value(&range, &Settings::new(), &test_program(), &test_sp());
        assert_eq!(val.unwrap(), "0x40");
    }

    #[test]
    fn test_label_table_column() {
        let col = LabelTableColumn;
        assert_eq!(col.column_name(), "Label");
        let loc = ProgramLocation::new(Address::new(0x100));
        let val = col.get_value(&loc, &Settings::new(), &test_program(), &test_sp());
        assert!(val.is_some());
    }

    #[test]
    fn test_namespace_table_column() {
        let col = NamespaceTableColumn;
        assert_eq!(col.column_name(), "Namespace");
        let loc = ProgramLocation::new(Address::new(0x100));
        let val = col.get_value(&loc, &Settings::new(), &test_program(), &test_sp());
        assert_eq!(val.unwrap(), "Global");
    }

    #[test]
    fn test_eol_comment_table_column() {
        let col = EOLCommentTableColumn;
        assert_eq!(col.column_name(), "EOL Comment");
        let loc = ProgramLocation::new(Address::new(0x100));
        let val = col.get_value(&loc, &Settings::new(), &test_program(), &test_sp());
        // No comment in test
        assert!(val.is_none());
    }
}
