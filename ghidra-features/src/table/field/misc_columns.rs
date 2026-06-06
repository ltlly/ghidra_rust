//! Miscellaneous table columns.
//!
//! Ported from `ghidra.util.table.field`:
//! - `SourceTypeTableColumn` -- displays the symbol source type.
//! - `SymbolTypeTableColumn` -- displays the symbol type.
//! - `MonospacedByteRenderer` -- marker for monospaced byte rendering.

use ghidra_core::addr::Address;

use super::traits::{ProgramBasedDynamicTableColumn, ProgramInfo, ProgramLocationTableColumn,
                    ProgramLocationTableColumnExt, ServiceProvider, Settings, SymbolType,
                    SourceType};
use super::super::mapper::ProgramLocation;

// ---------------------------------------------------------------------------
// SourceTypeTableColumn
// ---------------------------------------------------------------------------

/// Displays the symbol source type (User Defined, Analysis, etc.).
///
/// Ported from `ghidra.util.table.field.SourceTypeTableColumn`.
#[derive(Debug)]
pub struct SourceTypeTableColumn;

impl ProgramBasedDynamicTableColumn<ProgramLocation> for SourceTypeTableColumn {
    fn column_name(&self) -> &str { "Symbol Source" }

    fn get_value(&self, _row: &ProgramLocation, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        // In a real implementation, look up the primary symbol and return its source.
        None
    }
}

// ---------------------------------------------------------------------------
// SymbolTypeTableColumn
// ---------------------------------------------------------------------------

/// Displays the symbol type (Function, Label, Parameter, etc.).
///
/// Ported from `ghidra.util.table.field.SymbolTypeTableColumn`.
#[derive(Debug)]
pub struct SymbolTypeTableColumn;

impl ProgramBasedDynamicTableColumn<ProgramLocation> for SymbolTypeTableColumn {
    fn column_name(&self) -> &str { "Symbol Type" }

    fn get_value(&self, _row: &ProgramLocation, _settings: &Settings, _program: &ProgramInfo,
                 _sp: &ServiceProvider) -> Option<String> {
        // In a real implementation, look up the symbol and return its type display name.
        None
    }
}

// ---------------------------------------------------------------------------
// MonospacedByteRenderer
// ---------------------------------------------------------------------------

/// Marker struct indicating a column should use monospaced rendering for bytes.
///
/// Ported from `ghidra.util.table.field.MonospacedByteRenderer`.
#[derive(Debug, Clone, Copy)]
pub struct MonospacedByteRenderer;

impl MonospacedByteRenderer {
    /// Returns the fixed-width font name to use for byte display.
    pub fn font_name(&self) -> &str {
        "Monospaced"
    }

    /// Format bytes as a hex string with spaces.
    pub fn format_bytes(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
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
    fn test_source_type_column() {
        let col = SourceTypeTableColumn;
        assert_eq!(col.column_name(), "Symbol Source");
    }

    #[test]
    fn test_symbol_type_column() {
        let col = SymbolTypeTableColumn;
        assert_eq!(col.column_name(), "Symbol Type");
    }

    #[test]
    fn test_monospaced_byte_renderer_format() {
        let bytes = [0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(MonospacedByteRenderer::format_bytes(&bytes), "de ad be ef");
    }

    #[test]
    fn test_monospaced_byte_renderer_empty() {
        let bytes: Vec<u8> = vec![];
        assert_eq!(MonospacedByteRenderer::format_bytes(&bytes), "");
    }

    #[test]
    fn test_monospaced_byte_renderer_font() {
        assert_eq!(MonospacedByteRenderer.font_name(), "Monospaced");
    }

    #[test]
    fn test_symbol_type_column_value_none() {
        let col = SymbolTypeTableColumn;
        let loc = ProgramLocation::new(Address::new(0x100));
        let val = col.get_value(&loc, &Settings::new(), &test_program(), &test_sp());
        assert!(val.is_none());
    }
}
