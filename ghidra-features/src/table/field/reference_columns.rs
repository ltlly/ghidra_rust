//! Reference-related table columns.
//!
//! Ported from `ghidra.util.table.field`:
//! - `ReferenceFromAddressTableColumn` / `ReferenceToAddressTableColumn`
//! - `ReferenceFromBytesTableColumn` / `ReferenceToBytesTableColumn`
//! - `ReferenceFromLabelTableColumn`
//! - `ReferenceFromFunctionTableColumn`
//! - `ReferenceFromPreviewTableColumn` / `ReferenceToPreviewTableColumn`
//! - `ReferenceTypeTableColumn`
//! - `ReferenceCountToAddressTableColumn`
//! - `OffcutReferenceCountToAddressTableColumn`
//! - `PreviewTableColumn`

use ghidra_core::addr::Address;

use super::traits::{ProgramBasedDynamicTableColumn, ProgramInfo, ProgramLocationTableColumn,
                    ProgramLocationTableColumnExt, RefType, ServiceProvider, Settings};
use super::core::{IncomingReferenceEndpoint, OutgoingReferenceEndpoint, ReferenceAddressPair};
use super::super::mapper::ProgramLocation;

// ---------------------------------------------------------------------------
// ReferenceFromAddressTableColumn
// ---------------------------------------------------------------------------

/// Displays the source address for a reference pair.
///
/// Ported from `ghidra.util.table.field.ReferenceFromAddressTableColumn`.
#[derive(Debug)]
pub struct ReferenceFromAddressTableColumn;

impl ProgramBasedDynamicTableColumn<ReferenceAddressPair> for ReferenceFromAddressTableColumn {
    fn column_name(&self) -> &str { "From Location" }

    fn get_value(&self, row: &ReferenceAddressPair, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        Some(format!("0x{:x}", row.source().offset))
    }
}

impl ProgramLocationTableColumn<ReferenceAddressPair> for ReferenceFromAddressTableColumn {
    fn get_program_location(&self, row: &ReferenceAddressPair, _settings: &Settings,
                            _program: &ProgramInfo, _sp: &ServiceProvider)
        -> Option<ProgramLocation> {
        Some(ProgramLocation::new(row.source()))
    }
}

impl ProgramLocationTableColumnExt<ReferenceAddressPair> for ReferenceFromAddressTableColumn {}

// ---------------------------------------------------------------------------
// ReferenceToAddressTableColumn
// ---------------------------------------------------------------------------

/// Displays the destination address for a reference pair.
///
/// Ported from `ghidra.util.table.field.ReferenceToAddressTableColumn`.
#[derive(Debug)]
pub struct ReferenceToAddressTableColumn;

impl ProgramBasedDynamicTableColumn<ReferenceAddressPair> for ReferenceToAddressTableColumn {
    fn column_name(&self) -> &str { "To Location" }

    fn get_value(&self, row: &ReferenceAddressPair, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        Some(format!("0x{:x}", row.destination().offset))
    }
}

impl ProgramLocationTableColumn<ReferenceAddressPair> for ReferenceToAddressTableColumn {
    fn get_program_location(&self, row: &ReferenceAddressPair, _settings: &Settings,
                            _program: &ProgramInfo, _sp: &ServiceProvider)
        -> Option<ProgramLocation> {
        Some(ProgramLocation::new(row.destination()))
    }
}

impl ProgramLocationTableColumnExt<ReferenceAddressPair> for ReferenceToAddressTableColumn {}

// ---------------------------------------------------------------------------
// ReferenceFromBytesTableColumn
// ---------------------------------------------------------------------------

/// Displays bytes at the source of a reference.
///
/// Ported from `ghidra.util.table.field.ReferenceFromBytesTableColumn`.
#[derive(Debug)]
pub struct ReferenceFromBytesTableColumn;

impl ProgramBasedDynamicTableColumn<ReferenceAddressPair> for ReferenceFromBytesTableColumn {
    fn column_name(&self) -> &str { "From Bytes" }

    fn get_value(&self, _row: &ReferenceAddressPair, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        // In a real implementation, read bytes from memory at the source address.
        None
    }
}

// ---------------------------------------------------------------------------
// ReferenceToBytesTableColumn
// ---------------------------------------------------------------------------

/// Displays bytes at the destination of a reference.
///
/// Ported from `ghidra.util.table.field.ReferenceToBytesTableColumn`.
#[derive(Debug)]
pub struct ReferenceToBytesTableColumn;

impl ProgramBasedDynamicTableColumn<ReferenceAddressPair> for ReferenceToBytesTableColumn {
    fn column_name(&self) -> &str { "To Bytes" }

    fn get_value(&self, _row: &ReferenceAddressPair, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        None
    }
}

// ---------------------------------------------------------------------------
// ReferenceFromLabelTableColumn
// ---------------------------------------------------------------------------

/// Displays the label at the source of a reference.
///
/// Ported from `ghidra.util.table.field.ReferenceFromLabelTableColumn`.
#[derive(Debug)]
pub struct ReferenceFromLabelTableColumn;

impl ProgramBasedDynamicTableColumn<ReferenceAddressPair> for ReferenceFromLabelTableColumn {
    fn column_name(&self) -> &str { "From Label" }

    fn get_value(&self, row: &ReferenceAddressPair, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        Some(format!("0x{:x}", row.source().offset))
    }
}

impl ProgramLocationTableColumn<ReferenceAddressPair> for ReferenceFromLabelTableColumn {
    fn get_program_location(&self, row: &ReferenceAddressPair, _settings: &Settings,
                            _program: &ProgramInfo, _sp: &ServiceProvider)
        -> Option<ProgramLocation> {
        Some(ProgramLocation::new(row.source()))
    }
}

impl ProgramLocationTableColumnExt<ReferenceAddressPair> for ReferenceFromLabelTableColumn {}

// ---------------------------------------------------------------------------
// ReferenceFromFunctionTableColumn
// ---------------------------------------------------------------------------

/// Displays the function name at the source of a reference.
///
/// Ported from `ghidra.util.table.field.ReferenceFromFunctionTableColumn`.
#[derive(Debug)]
pub struct ReferenceFromFunctionTableColumn;

impl ProgramBasedDynamicTableColumn<ReferenceAddressPair> for ReferenceFromFunctionTableColumn {
    fn column_name(&self) -> &str { "From Function" }

    fn get_value(&self, _row: &ReferenceAddressPair, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        None // needs function lookup
    }
}

// ---------------------------------------------------------------------------
// ReferenceFromPreviewTableColumn / ReferenceToPreviewTableColumn
// ---------------------------------------------------------------------------

/// Displays a preview of the code unit at the source of a reference.
///
/// Ported from `ghidra.util.table.field.ReferenceFromPreviewTableColumn`.
#[derive(Debug)]
pub struct ReferenceFromPreviewTableColumn;

impl ProgramBasedDynamicTableColumn<ReferenceAddressPair> for ReferenceFromPreviewTableColumn {
    fn column_name(&self) -> &str { "From Preview" }

    fn get_value(&self, _row: &ReferenceAddressPair, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        None
    }
}

/// Displays a preview of the code unit at the destination of a reference.
///
/// Ported from `ghidra.util.table.field.ReferenceToPreviewTableColumn`.
#[derive(Debug)]
pub struct ReferenceToPreviewTableColumn;

impl ProgramBasedDynamicTableColumn<ReferenceAddressPair> for ReferenceToPreviewTableColumn {
    fn column_name(&self) -> &str { "To Preview" }

    fn get_value(&self, _row: &ReferenceAddressPair, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        None
    }
}

// ---------------------------------------------------------------------------
// ReferenceTypeTableColumn
// ---------------------------------------------------------------------------

/// Displays the reference type for a reference object.
///
/// Ported from `ghidra.util.table.field.ReferenceTypeTableColumn`.
#[derive(Debug)]
pub struct ReferenceTypeTableColumn;

impl ProgramBasedDynamicTableColumn<IncomingReferenceEndpoint> for ReferenceTypeTableColumn {
    fn column_name(&self) -> &str { "Ref Type" }

    fn get_value(&self, row: &IncomingReferenceEndpoint, _settings: &Settings,
                 _program: &ProgramInfo, _sp: &ServiceProvider) -> Option<String> {
        Some(row.reference_type().display_string().to_string())
    }
}

impl ProgramLocationTableColumn<IncomingReferenceEndpoint> for ReferenceTypeTableColumn {
    fn get_program_location(&self, _row: &IncomingReferenceEndpoint, _settings: &Settings,
                            _program: &ProgramInfo, _sp: &ServiceProvider)
        -> Option<ProgramLocation> {
        None
    }
}

impl ProgramLocationTableColumnExt<IncomingReferenceEndpoint> for ReferenceTypeTableColumn {}

// ---------------------------------------------------------------------------
// ReferenceCountToAddressTableColumn
// ---------------------------------------------------------------------------

/// Displays the number of references to an address.
///
/// Ported from `ghidra.util.table.field.ReferenceCountToAddressTableColumn`.
#[derive(Debug)]
pub struct ReferenceCountToAddressTableColumn;

impl ProgramBasedDynamicTableColumn<Address> for ReferenceCountToAddressTableColumn {
    fn column_name(&self) -> &str { "Ref To Count" }

    fn get_value(&self, _row: &Address, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        None // needs xref lookup
    }
}

// ---------------------------------------------------------------------------
// OffcutReferenceCountToAddressTableColumn
// ---------------------------------------------------------------------------

/// Displays the number of offcut (partial) references to an address.
///
/// Ported from `ghidra.util.table.field.OffcutReferenceCountToAddressTableColumn`.
#[derive(Debug)]
pub struct OffcutReferenceCountToAddressTableColumn;

impl ProgramBasedDynamicTableColumn<Address> for OffcutReferenceCountToAddressTableColumn {
    fn column_name(&self) -> &str { "Offcut Ref Count" }

    fn get_value(&self, _row: &Address, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        None
    }
}

// ---------------------------------------------------------------------------
// PreviewTableColumn
// ---------------------------------------------------------------------------

/// Displays a preview of the listing at a program location.
///
/// Ported from `ghidra.util.table.field.PreviewTableColumn`.
#[derive(Debug)]
pub struct PreviewTableColumn;

impl ProgramBasedDynamicTableColumn<ProgramLocation> for PreviewTableColumn {
    fn column_name(&self) -> &str { "Preview" }

    fn get_value(&self, _row: &ProgramLocation, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        None
    }

    fn preferred_width(&self) -> usize { 300 }
}

impl ProgramLocationTableColumn<ProgramLocation> for PreviewTableColumn {
    fn get_program_location(&self, row: &ProgramLocation, _settings: &Settings,
                            _program: &ProgramInfo, _sp: &ServiceProvider)
        -> Option<ProgramLocation> {
        Some(row.clone())
    }
}

impl ProgramLocationTableColumnExt<ProgramLocation> for PreviewTableColumn {}

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
    fn test_ref_from_address() {
        let col = ReferenceFromAddressTableColumn;
        assert_eq!(col.column_name(), "From Location");
        let pair = ReferenceAddressPair::new(Address::new(0x100), Address::new(0x200));
        let val = col.get_value(&pair, &Settings::new(), &test_program(), &test_sp()).unwrap();
        assert_eq!(val, "0x100");
    }

    #[test]
    fn test_ref_to_address() {
        let col = ReferenceToAddressTableColumn;
        assert_eq!(col.column_name(), "To Location");
        let pair = ReferenceAddressPair::new(Address::new(0x100), Address::new(0x200));
        let val = col.get_value(&pair, &Settings::new(), &test_program(), &test_sp()).unwrap();
        assert_eq!(val, "0x200");
    }

    #[test]
    fn test_ref_from_label() {
        let col = ReferenceFromLabelTableColumn;
        assert_eq!(col.column_name(), "From Label");
        let pair = ReferenceAddressPair::new(Address::new(0x100), Address::new(0x200));
        let val = col.get_value(&pair, &Settings::new(), &test_program(), &test_sp()).unwrap();
        assert_eq!(val, "0x100");
    }

    #[test]
    fn test_ref_type_column() {
        let col = ReferenceTypeTableColumn;
        assert_eq!(col.column_name(), "Ref Type");
        let ep = IncomingReferenceEndpoint::new(
            Address::new(0x100), RefType::Call, false, super::super::traits::SourceType::Analysis);
        let val = col.get_value(&ep, &Settings::new(), &test_program(), &test_sp()).unwrap();
        assert_eq!(val, "Call");
    }

    #[test]
    fn test_ref_from_location() {
        let col = ReferenceFromAddressTableColumn;
        let pair = ReferenceAddressPair::new(Address::new(0x100), Address::new(0x200));
        let loc = col.get_program_location(&pair, &Settings::new(), &test_program(), &test_sp());
        assert!(loc.is_some());
        assert_eq!(loc.unwrap().address.offset, 0x100);
    }

    #[test]
    fn test_ref_to_location() {
        let col = ReferenceToAddressTableColumn;
        let pair = ReferenceAddressPair::new(Address::new(0x100), Address::new(0x200));
        let loc = col.get_program_location(&pair, &Settings::new(), &test_program(), &test_sp());
        assert!(loc.is_some());
        assert_eq!(loc.unwrap().address.offset, 0x200);
    }

    #[test]
    fn test_preview_table_column() {
        let col = PreviewTableColumn;
        assert_eq!(col.column_name(), "Preview");
        assert_eq!(col.preferred_width(), 300);
    }

    #[test]
    fn test_ref_count_column() {
        let col = ReferenceCountToAddressTableColumn;
        assert_eq!(col.column_name(), "Ref To Count");
    }

    #[test]
    fn test_offcut_ref_count_column() {
        let col = OffcutReferenceCountToAddressTableColumn;
        assert_eq!(col.column_name(), "Offcut Ref Count");
    }
}
