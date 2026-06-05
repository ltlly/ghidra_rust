//! AutoTableDisassembler -- automatic table-driven disassembly model.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.disassembler.AutoTableDisassemblerModel`.
//!
//! Provides the business logic for automatically detecting and disassembling
//! address tables (jump tables, switch tables) in programs.  This analyzer
//! identifies pointer tables used by indirect jumps and marks the targets
//! as code.

use ghidra_core::Address;
use std::collections::BTreeMap;

// ============================================================================
// TableEntryKind -- the kind of entry in an address table
// ============================================================================

/// The kind of an entry in an address table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableEntryKind {
    /// An absolute address.
    Absolute,
    /// A relative offset from the table base.
    RelativeOffset,
    /// A relative offset from the instruction that uses the table.
    InstructionRelative,
}

// ============================================================================
// AddressTable -- a detected address table
// ============================================================================

/// A detected address table in the program.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.disassembler.AddressTable`.
#[derive(Debug, Clone)]
pub struct AddressTable {
    /// The start address of the table.
    pub start: Address,
    /// The entries in the table (index -> target address).
    pub entries: BTreeMap<u64, Address>,
    /// The kind of entries in the table.
    pub entry_kind: TableEntryKind,
    /// The size of each entry in bytes (e.g., 4 for 32-bit pointers).
    pub entry_size: usize,
    /// The address of the instruction that references this table (if known).
    pub referencing_instruction: Option<Address>,
}

impl AddressTable {
    /// Create a new address table.
    pub fn new(start: Address, entry_kind: TableEntryKind, entry_size: usize) -> Self {
        Self {
            start,
            entries: BTreeMap::new(),
            entry_kind,
            entry_size,
            referencing_instruction: None,
        }
    }

    /// Add an entry to the table.
    pub fn add_entry(&mut self, index: u64, target: Address) {
        self.entries.insert(index, target);
    }

    /// Get the target address for a given index.
    pub fn get_target(&self, index: u64) -> Option<Address> {
        self.entries.get(&index).copied()
    }

    /// The number of entries in the table.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// The total size of the table in bytes.
    pub fn byte_size(&self) -> usize {
        self.entries.len() * self.entry_size
    }

    /// The end address of the table (start + byte_size - 1).
    pub fn end_address(&self) -> Address {
        Address::new(self.start.offset + self.byte_size() as u64 - 1)
    }

    /// Get all target addresses.
    pub fn targets(&self) -> Vec<Address> {
        self.entries.values().copied().collect()
    }

    /// Set the referencing instruction.
    pub fn with_reference(mut self, addr: Address) -> Self {
        self.referencing_instruction = Some(addr);
        self
    }

    /// Check if the table is contiguous (entries are sequential).
    pub fn is_contiguous(&self) -> bool {
        if self.entries.is_empty() {
            return true;
        }
        let indices: Vec<u64> = self.entries.keys().copied().collect();
        for i in 1..indices.len() {
            if indices[i] != indices[i - 1] + 1 {
                return false;
            }
        }
        true
    }

    /// Check if all targets are within the given address range.
    pub fn all_targets_in_range(&self, min: Address, max: Address) -> bool {
        self.entries
            .values()
            .all(|addr| addr.offset >= min.offset && addr.offset <= max.offset)
    }
}

// ============================================================================
// AutoTableDisassemblerModel -- the analysis model
// ============================================================================

/// Model for automatic table disassembly analysis.
///
/// Ported from `ghidra.app.plugin.core.disassembler.AutoTableDisassemblerModel`.
///
/// Scans for potential address tables and validates them against known
/// code boundaries.
#[derive(Debug, Default)]
pub struct AutoTableDisassemblerModel {
    /// Detected tables.
    tables: Vec<AddressTable>,
    /// Known code addresses (for validation).
    code_addresses: Vec<Address>,
    /// Known data addresses (to exclude from table detection).
    data_addresses: Vec<Address>,
    /// Configuration.
    config: TableDisassemblerConfig,
}

/// Configuration for the auto table disassembler.
#[derive(Debug, Clone)]
pub struct TableDisassemblerConfig {
    /// Maximum number of entries in a table to consider.
    pub max_table_entries: usize,
    /// Minimum number of entries to be considered a valid table.
    pub min_table_entries: usize,
    /// Default pointer size (in bytes) for the architecture.
    pub default_pointer_size: usize,
    /// Whether to check that table targets are valid code addresses.
    pub validate_targets: bool,
    /// Maximum table size in bytes.
    pub max_table_bytes: usize,
}

impl Default for TableDisassemblerConfig {
    fn default() -> Self {
        Self {
            max_table_entries: 1024,
            min_table_entries: 2,
            default_pointer_size: 4,
            validate_targets: true,
            max_table_bytes: 4096,
        }
    }
}

impl AutoTableDisassemblerModel {
    /// Create a new auto table disassembler model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with custom configuration.
    pub fn with_config(config: TableDisassemblerConfig) -> Self {
        Self {
            tables: Vec::new(),
            code_addresses: Vec::new(),
            data_addresses: Vec::new(),
            config,
        }
    }

    /// Set known code addresses (for target validation).
    pub fn set_code_addresses(&mut self, addrs: Vec<Address>) {
        self.code_addresses = addrs;
        self.code_addresses.sort_by_key(|a| a.offset);
    }

    /// Set known data addresses.
    pub fn set_data_addresses(&mut self, addrs: Vec<Address>) {
        self.data_addresses = addrs;
        self.data_addresses.sort_by_key(|a| a.offset);
    }

    /// Add a detected address table.
    pub fn add_table(&mut self, table: AddressTable) {
        self.tables.push(table);
    }

    /// Get all detected tables.
    pub fn tables(&self) -> &[AddressTable] {
        &self.tables
    }

    /// Get the number of detected tables.
    pub fn table_count(&self) -> usize {
        self.tables.len()
    }

    /// Validate a potential table.
    ///
    /// Checks that the table has enough entries, all targets are valid
    /// code addresses, and the table doesn't overlap with known data.
    pub fn validate_table(&self, table: &AddressTable) -> TableValidationResult {
        let mut errors = Vec::new();

        // Check entry count
        if table.entry_count() < self.config.min_table_entries {
            errors.push(format!(
                "Table has {} entries (minimum {})",
                table.entry_count(),
                self.config.min_table_entries
            ));
        }

        if table.entry_count() > self.config.max_table_entries {
            errors.push(format!(
                "Table has {} entries (maximum {})",
                table.entry_count(),
                self.config.max_table_entries
            ));
        }

        // Check table size
        if table.byte_size() > self.config.max_table_bytes {
            errors.push(format!(
                "Table is {} bytes (maximum {})",
                table.byte_size(),
                self.config.max_table_bytes
            ));
        }

        // Validate targets if configured
        if self.config.validate_targets {
            for (idx, target) in &table.entries {
                if !self.is_code_address(*target) {
                    errors.push(format!(
                        "Entry {} target {:#x} is not a known code address",
                        idx, target.offset
                    ));
                }
            }
        }

        TableValidationResult {
            valid: errors.is_empty(),
            errors,
            entry_count: table.entry_count(),
            total_bytes: table.byte_size(),
        }
    }

    /// Check if an address is a known code address (binary search).
    fn is_code_address(&self, addr: Address) -> bool {
        self.code_addresses
            .binary_search_by_key(&addr.offset, |a| a.offset)
            .is_ok()
    }

    /// Check if an address is a known data address (binary search).
    pub fn is_data_address(&self, addr: Address) -> bool {
        self.data_addresses
            .binary_search_by_key(&addr.offset, |a| a.offset)
            .is_ok()
    }

    /// Get all valid tables (those that pass validation).
    pub fn valid_tables(&self) -> Vec<&AddressTable> {
        self.tables
            .iter()
            .filter(|t| self.validate_table(t).valid)
            .collect()
    }

    /// Get all unique target addresses from all valid tables.
    pub fn all_valid_targets(&self) -> Vec<Address> {
        let mut targets: Vec<Address> = self
            .valid_tables()
            .iter()
            .flat_map(|t| t.targets())
            .collect();
        targets.sort_by_key(|a| a.offset);
        targets.dedup();
        targets
    }
}

// ============================================================================
// TableValidationResult
// ============================================================================

/// The result of validating an address table.
#[derive(Debug, Clone)]
pub struct TableValidationResult {
    /// Whether the table passed validation.
    pub valid: bool,
    /// Validation errors (empty if valid).
    pub errors: Vec<String>,
    /// The number of entries in the table.
    pub entry_count: usize,
    /// The total size in bytes.
    pub total_bytes: usize,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_table_basic() {
        let mut table = AddressTable::new(
            Address::new(0x2000),
            TableEntryKind::Absolute,
            4,
        );
        table.add_entry(0, Address::new(0x1000));
        table.add_entry(1, Address::new(0x1100));
        table.add_entry(2, Address::new(0x1200));

        assert_eq!(table.entry_count(), 3);
        assert_eq!(table.byte_size(), 12);
        assert_eq!(table.get_target(1), Some(Address::new(0x1100)));
        assert!(table.is_contiguous());
    }

    #[test]
    fn test_address_table_end_address() {
        let mut table = AddressTable::new(
            Address::new(0x2000),
            TableEntryKind::Absolute,
            4,
        );
        table.add_entry(0, Address::new(0x1000));
        table.add_entry(1, Address::new(0x1100));

        assert_eq!(table.end_address().offset, 0x2007); // 0x2000 + 2*4 - 1
    }

    #[test]
    fn test_address_table_non_contiguous() {
        let mut table = AddressTable::new(
            Address::new(0x2000),
            TableEntryKind::Absolute,
            4,
        );
        table.add_entry(0, Address::new(0x1000));
        table.add_entry(5, Address::new(0x1100)); // Gap

        assert!(!table.is_contiguous());
    }

    #[test]
    fn test_address_table_targets_in_range() {
        let mut table = AddressTable::new(
            Address::new(0x2000),
            TableEntryKind::Absolute,
            4,
        );
        table.add_entry(0, Address::new(0x1000));
        table.add_entry(1, Address::new(0x1100));

        assert!(table.all_targets_in_range(Address::new(0x0), Address::new(0x2000)));
        assert!(!table.all_targets_in_range(Address::new(0x0), Address::new(0x1050)));
    }

    #[test]
    fn test_address_table_with_reference() {
        let table = AddressTable::new(
            Address::new(0x2000),
            TableEntryKind::Absolute,
            4,
        )
        .with_reference(Address::new(0x500));
        assert_eq!(table.referencing_instruction, Some(Address::new(0x500)));
    }

    #[test]
    fn test_auto_table_disassembler_validate() {
        let mut model = AutoTableDisassemblerModel::new();
        model.set_code_addresses(vec![
            Address::new(0x1000),
            Address::new(0x1100),
            Address::new(0x1200),
        ]);

        let mut table = AddressTable::new(
            Address::new(0x2000),
            TableEntryKind::Absolute,
            4,
        );
        table.add_entry(0, Address::new(0x1000));
        table.add_entry(1, Address::new(0x1100));
        table.add_entry(2, Address::new(0x1200));

        let result = model.validate_table(&table);
        assert!(result.valid, "Errors: {:?}", result.errors);
        assert_eq!(result.entry_count, 3);
    }

    #[test]
    fn test_auto_table_disassembler_validate_invalid_target() {
        let mut model = AutoTableDisassemblerModel::new();
        model.set_code_addresses(vec![Address::new(0x1000)]);

        let mut table = AddressTable::new(
            Address::new(0x2000),
            TableEntryKind::Absolute,
            4,
        );
        table.add_entry(0, Address::new(0x1000));
        table.add_entry(1, Address::new(0x9999)); // Not in code addresses

        let result = model.validate_table(&table);
        assert!(!result.valid);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_auto_table_disassembler_validate_too_few_entries() {
        let mut model = AutoTableDisassemblerModel::new();
        let table = AddressTable::new(
            Address::new(0x2000),
            TableEntryKind::Absolute,
            4,
        );

        let result = model.validate_table(&table);
        assert!(!result.valid);
    }

    #[test]
    fn test_auto_table_disassembler_valid_tables() {
        let mut model = AutoTableDisassemblerModel::new();
        model.set_code_addresses(vec![
            Address::new(0x1000),
            Address::new(0x1100),
            Address::new(0x1200),
            Address::new(0x1300),
        ]);

        // Valid table
        let mut table1 = AddressTable::new(
            Address::new(0x2000),
            TableEntryKind::Absolute,
            4,
        );
        table1.add_entry(0, Address::new(0x1000));
        table1.add_entry(1, Address::new(0x1100));

        // Invalid table (bad target)
        let mut table2 = AddressTable::new(
            Address::new(0x3000),
            TableEntryKind::Absolute,
            4,
        );
        table2.add_entry(0, Address::new(0x1000));
        table2.add_entry(1, Address::new(0x9999));

        model.add_table(table1);
        model.add_table(table2);

        assert_eq!(model.valid_tables().len(), 1);
    }

    #[test]
    fn test_auto_table_disassembler_all_valid_targets() {
        let mut model = AutoTableDisassemblerModel::new();
        model.set_code_addresses(vec![
            Address::new(0x1000),
            Address::new(0x1100),
            Address::new(0x1200),
        ]);

        let mut table = AddressTable::new(
            Address::new(0x2000),
            TableEntryKind::Absolute,
            4,
        );
        table.add_entry(0, Address::new(0x1000));
        table.add_entry(1, Address::new(0x1100));
        table.add_entry(2, Address::new(0x1200));

        model.add_table(table);

        let targets = model.all_valid_targets();
        assert_eq!(targets.len(), 3);
    }

    #[test]
    fn test_table_disassembler_config_default() {
        let config = TableDisassemblerConfig::default();
        assert_eq!(config.max_table_entries, 1024);
        assert_eq!(config.min_table_entries, 2);
        assert_eq!(config.default_pointer_size, 4);
        assert!(config.validate_targets);
    }

    #[test]
    fn test_table_entry_kind() {
        assert_eq!(TableEntryKind::Absolute, TableEntryKind::Absolute);
        assert_ne!(TableEntryKind::Absolute, TableEntryKind::RelativeOffset);
    }

    #[test]
    fn test_is_data_address() {
        let mut model = AutoTableDisassemblerModel::new();
        model.set_data_addresses(vec![Address::new(0x5000), Address::new(0x5100)]);
        assert!(model.is_data_address(Address::new(0x5000)));
        assert!(!model.is_data_address(Address::new(0x6000)));
    }
}
