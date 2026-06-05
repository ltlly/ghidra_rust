//! Utility functions for the decompiler component.
//!
//! Ports `ghidra.app.decompiler.component.DecompilerUtils`.

use crate::decompiler::decompile_options::DecompileOptions;

/// Gather decompiler options from the program (simplified).
///
/// In Ghidra Java this reads from both the tool's options service and
/// the program's stored options. In Rust we provide a direct configuration
/// path.
pub fn get_decompile_options() -> DecompileOptions {
    DecompileOptions::default()
}

/// Address range within a decompiled function.
#[derive(Debug, Clone)]
pub struct DecompilerAddressRange {
    /// Start address.
    pub start: u64,
    /// End address (exclusive).
    pub end: u64,
}

impl DecompilerAddressRange {
    /// Create a new address range.
    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    /// Check if an address is in this range.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    /// The size of the range.
    pub fn size(&self) -> u64 {
        self.end - self.start
    }
}

/// Get the data type name for a varnode from its Pcode representation.
///
/// In Ghidra Java this traverses CAST ops and pcode to determine the
/// most specific data type. Here we provide the simplified interface.
pub fn get_data_type_for_varnode(
    varnode_size: usize,
    has_cast_op: bool,
) -> String {
    if has_cast_op {
        match varnode_size {
            1 => "byte".to_string(),
            2 => "short".to_string(),
            4 => "int".to_string(),
            8 => "longlong".to_string(),
            _ => format!("uint{}", varnode_size * 8),
        }
    } else {
        format!("undefined{}", varnode_size)
    }
}

/// Check if a function has an explicit return type.
pub fn has_explicit_return_type(signature_xml: &str) -> bool {
    !signature_xml.is_empty() && signature_xml.contains("return")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_range() {
        let range = DecompilerAddressRange::new(0x1000, 0x1100);
        assert!(range.contains(0x1050));
        assert!(!range.contains(0x2000));
        assert_eq!(range.size(), 0x100);
    }

    #[test]
    fn test_data_type_name() {
        assert_eq!(get_data_type_for_varnode(4, true), "int");
        assert_eq!(get_data_type_for_varnode(1, true), "byte");
        assert_eq!(get_data_type_for_varnode(4, false), "undefined4");
    }

    #[test]
    fn test_explicit_return_type() {
        assert!(has_explicit_return_type(r#"<return type="int"/>"#));
        assert!(!has_explicit_return_type(""));
    }
}
