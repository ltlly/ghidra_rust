//! Address table analysis for indirect jump resolution.
//!
//! Ported from Ghidra's `AddressTable`, `AddressTableAnalyzer`,
//! and `AddressTableDialog`.

use serde::{Deserialize, Serialize};

/// Represents an address table found in a binary (e.g., jump tables, vtables).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressTable {
    /// Base address of the table.
    pub base_address: String,
    /// List of addresses in the table.
    pub entries: Vec<String>,
    /// The element size in bytes (typically 4 or 8).
    pub element_size: usize,
    /// Whether entries are relative offsets rather than absolute addresses.
    pub is_relative: bool,
    /// Whether the table is in read-only memory.
    pub is_read_only: bool,
}

impl AddressTable {
    /// Create a new address table.
    pub fn new(base_address: &str, element_size: usize) -> Self {
        Self {
            base_address: base_address.to_string(),
            entries: Vec::new(),
            element_size,
            is_relative: false,
            is_read_only: true,
        }
    }

    /// Add an entry to the table.
    pub fn add_entry(&mut self, address: &str) {
        self.entries.push(address.to_string());
    }

    /// Return the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return the total byte size of the table.
    pub fn byte_size(&self) -> usize {
        self.entries.len() * self.element_size
    }

    /// Set whether entries are relative offsets.
    pub fn set_relative(&mut self, relative: bool) {
        self.is_relative = relative;
    }
}

/// Analyzer that detects address tables in binaries.
#[derive(Debug, Clone)]
pub struct AddressTableAnalyzer {
    /// Minimum number of entries to consider a valid table.
    pub min_entries: usize,
    /// Maximum entry size to consider.
    pub max_element_size: usize,
    /// Whether the analyzer is enabled.
    pub enabled: bool,
}

impl Default for AddressTableAnalyzer {
    fn default() -> Self {
        Self {
            min_entries: 3,
            max_element_size: 8,
            enabled: true,
        }
    }
}

impl AddressTableAnalyzer {
    /// Check if a sequence of bytes could be an address table.
    pub fn could_be_table(&self, byte_count: usize, element_size: usize) -> bool {
        element_size > 0
            && element_size <= self.max_element_size
            && byte_count / element_size >= self.min_entries
    }

    /// Calculate the number of entries given byte count and element size.
    pub fn entry_count(&self, byte_count: usize, element_size: usize) -> usize {
        if element_size == 0 {
            0
        } else {
            byte_count / element_size
        }
    }
}

/// Dialog configuration for address table display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressTableDialogConfig {
    /// Title of the dialog.
    pub title: String,
    /// Whether to show entry addresses.
    pub show_addresses: bool,
    /// Whether to show resolved symbols.
    pub show_symbols: bool,
    /// Whether to allow editing.
    pub allow_edit: bool,
}

impl Default for AddressTableDialogConfig {
    fn default() -> Self {
        Self {
            title: "Address Table".to_string(),
            show_addresses: true,
            show_symbols: true,
            allow_edit: false,
        }
    }
}

/// Flow override types for disassembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowOverride {
    /// No override.
    None,
    /// Force a call flow.
    Call,
    /// Force a jump flow.
    Jump,
    /// Force a call-return flow (call that returns).
    CallReturn,
    /// Force a return flow.
    Return,
}

impl Default for FlowOverride {
    fn default() -> Self {
        Self::None
    }
}

impl FlowOverride {
    /// Return the display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::None => "No Override",
            Self::Call => "Call",
            Self::Jump => "Jump",
            Self::CallReturn => "Call/Return",
            Self::Return => "Return",
        }
    }

    /// Return all possible values.
    pub fn all_values() -> &'static [FlowOverride] {
        &[
            Self::None,
            Self::Call,
            Self::Jump,
            Self::CallReturn,
            Self::Return,
        ]
    }
}

/// Length override for disassembly instructions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LengthOverride {
    /// The instruction address.
    pub address: String,
    /// The overridden length in bytes.
    pub length: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_table_new() {
        let table = AddressTable::new("0x401000", 4);
        assert_eq!(table.base_address, "0x401000");
        assert_eq!(table.element_size, 4);
        assert!(table.is_empty());
    }

    #[test]
    fn test_address_table_add_entries() {
        let mut table = AddressTable::new("0x401000", 4);
        table.add_entry("0x402000");
        table.add_entry("0x402004");
        table.add_entry("0x402008");
        assert_eq!(table.len(), 3);
        assert_eq!(table.byte_size(), 12);
    }

    #[test]
    fn test_address_table_relative() {
        let mut table = AddressTable::new("0x401000", 4);
        table.set_relative(true);
        assert!(table.is_relative);
    }

    #[test]
    fn test_analyzer_could_be_table() {
        let analyzer = AddressTableAnalyzer::default();
        assert!(analyzer.could_be_table(16, 4));
        assert!(!analyzer.could_be_table(4, 4)); // only 1 entry
        assert!(!analyzer.could_be_table(16, 0));
    }

    #[test]
    fn test_analyzer_entry_count() {
        let analyzer = AddressTableAnalyzer::default();
        assert_eq!(analyzer.entry_count(16, 4), 4);
        assert_eq!(analyzer.entry_count(16, 8), 2);
        assert_eq!(analyzer.entry_count(16, 0), 0);
    }

    #[test]
    fn test_flow_override_display() {
        assert_eq!(FlowOverride::None.display_name(), "No Override");
        assert_eq!(FlowOverride::Call.display_name(), "Call");
        assert_eq!(FlowOverride::Jump.display_name(), "Jump");
        assert_eq!(FlowOverride::Return.display_name(), "Return");
    }

    #[test]
    fn test_flow_override_all_values() {
        assert_eq!(FlowOverride::all_values().len(), 5);
    }

    #[test]
    fn test_dialog_config_default() {
        let config = AddressTableDialogConfig::default();
        assert_eq!(config.title, "Address Table");
        assert!(config.show_addresses);
        assert!(!config.allow_edit);
    }
}
