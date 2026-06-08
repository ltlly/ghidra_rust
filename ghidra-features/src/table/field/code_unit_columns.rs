//! Code unit and bytes table columns.
//!
//! Ported from `ghidra.util.table.field`:
//! - `CodeUnitTableColumn` -- displays the code unit at a program location.
//! - `BytesTableColumn` -- displays raw bytes at an address.
//! - `ByteCountProgramLocationBasedTableColumn` -- displays byte count.

use ghidra_core::addr::Address;

use super::traits::{ProgramBasedDynamicTableColumn, ProgramInfo, ProgramLocationTableColumn,
                    ProgramLocationTableColumnExt, ServiceProvider, Settings};
use super::settings_defs::{CODE_UNIT_COUNT_DEF, CODE_UNIT_OFFSET_DEF};
use super::super::mapper::ProgramLocation;

// ---------------------------------------------------------------------------
// CodeUnitTableColumn
// ---------------------------------------------------------------------------

/// Displays the code unit (instruction or data) at a program location.
///
/// Ported from `ghidra.util.table.field.CodeUnitTableColumn`.
#[derive(Debug)]
pub struct CodeUnitTableColumn;

impl ProgramBasedDynamicTableColumn<ProgramLocation> for CodeUnitTableColumn {
    fn column_name(&self) -> &str { "Code Unit" }

    fn column_display_name(&self, settings: &Settings) -> String {
        let count = CODE_UNIT_COUNT_DEF.get_count(settings);
        let offset = CODE_UNIT_OFFSET_DEF.get_display_value(settings);
        let mut name = self.column_name().to_string();
        if count != 1 {
            name.push_str(&format!("[{}]", count));
        }
        if offset != "0" {
            name.push_str(&offset);
        }
        name
    }

    fn get_value(&self, row: &ProgramLocation, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        // In a real implementation, this would format the code unit listing.
        Some(format!("0x{:x}", row.address.offset))
    }

    fn preferred_width(&self) -> usize { 200 }
}

impl ProgramLocationTableColumn<ProgramLocation> for CodeUnitTableColumn {
    fn get_program_location(&self, row: &ProgramLocation, _settings: &Settings,
                            _program: &ProgramInfo, _sp: &ServiceProvider)
        -> Option<ProgramLocation> {
        Some(row.clone())
    }
}

impl ProgramLocationTableColumnExt<ProgramLocation> for CodeUnitTableColumn {}

// ---------------------------------------------------------------------------
// BytesTableColumn
// ---------------------------------------------------------------------------

/// Displays raw bytes at an address.
///
/// Ported from `ghidra.util.table.field.BytesTableColumn`.
#[derive(Debug)]
pub struct BytesTableColumn;

impl ProgramBasedDynamicTableColumn<Address> for BytesTableColumn {
    fn column_name(&self) -> &str { "Bytes" }

    fn get_value(&self, _row: &Address, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        // In a real implementation, read bytes from program memory.
        None
    }

    fn preferred_width(&self) -> usize { 120 }
}

// ---------------------------------------------------------------------------
// ByteCountProgramLocationBasedTableColumn
// ---------------------------------------------------------------------------

/// Displays the byte count associated with a program location.
///
/// Ported from `ghidra.util.table.field.ByteCountProgramLocationBasedTableColumn`.
#[derive(Debug)]
pub struct ByteCountProgramLocationBasedTableColumn;

impl ProgramBasedDynamicTableColumn<Address> for ByteCountProgramLocationBasedTableColumn {
    fn column_name(&self) -> &str { "Byte Count" }

    fn get_value(&self, _row: &Address, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        // In a real implementation, count bytes at the address.
        None
    }
}

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
    fn test_code_unit_column_name() {
        let col = CodeUnitTableColumn;
        assert_eq!(col.column_name(), "Code Unit");
    }

    #[test]
    fn test_code_unit_column_display_name_default() {
        let col = CodeUnitTableColumn;
        let settings = Settings::new();
        assert_eq!(col.column_display_name(&settings), "Code Unit");
    }

    #[test]
    fn test_code_unit_column_display_name_multi() {
        let col = CodeUnitTableColumn;
        let mut settings = Settings::new();
        settings.set_long("Code Unit Count", 3);
        let name = col.column_display_name(&settings);
        assert!(name.contains("[3]"), "Expected [3] in '{}'", name);
    }

    #[test]
    fn test_code_unit_column_value() {
        let col = CodeUnitTableColumn;
        let loc = ProgramLocation::new(Address::new(0x1000));
        let val = col.get_value(&loc, &Settings::new(), &test_program(), &test_sp());
        assert!(val.is_some());
    }

    #[test]
    fn test_code_unit_column_location() {
        let col = CodeUnitTableColumn;
        let loc = ProgramLocation::new(Address::new(0x1000));
        let result = col.get_program_location(&loc, &Settings::new(), &test_program(), &test_sp());
        assert!(result.is_some());
        assert_eq!(result.unwrap().address.offset, 0x1000);
    }

    #[test]
    fn test_bytes_column() {
        let col = BytesTableColumn;
        assert_eq!(col.column_name(), "Bytes");
        assert_eq!(col.preferred_width(), 120);
    }

    #[test]
    fn test_byte_count_column() {
        let col = ByteCountProgramLocationBasedTableColumn;
        assert_eq!(col.column_name(), "Byte Count");
    }
}
