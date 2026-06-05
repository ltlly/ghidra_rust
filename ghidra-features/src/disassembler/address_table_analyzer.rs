//! Address Table Analyzer -- ported from
//! `ghidra.app.plugin.core.disassembler.AddressTableAnalyzer` and
//! `ghidra.app.plugin.core.disassembler.AutoTableDisassemblerPlugin`.
//!
//! Scans for address tables in memory and disassembles targets.

use ghidra_core::Address;
use std::collections::BTreeMap;

/// An address table found in memory.
///
/// Ported from `ghidra.app.plugin.core.disassembler.AddressTable`.
#[derive(Debug, Clone)]
pub struct AddressTable {
    /// The start address of the table.
    pub start_address: Address,
    /// Table entries: ordinal -> target address.
    pub entries: BTreeMap<u64, Address>,
    /// Pointer size in bytes.
    pub pointer_size: u8,
    /// Whether entries are relative offsets (vs. absolute addresses).
    pub is_relative: bool,
    /// The label/name of the table (if known).
    pub label: Option<String>,
    /// Whether all entries point to valid code.
    pub all_valid: bool,
}

impl AddressTable {
    /// Create a new address table at the given start address.
    pub fn new(start_address: Address, pointer_size: u8) -> Self {
        Self {
            start_address,
            entries: BTreeMap::new(),
            pointer_size,
            is_relative: false,
            label: None,
            all_valid: false,
        }
    }

    /// Add an entry at the given ordinal.
    pub fn add_entry(&mut self, ordinal: u64, target: Address) {
        self.entries.insert(ordinal, target);
    }

    /// Number of entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// The end address of the table (exclusive).
    pub fn end_address(&self) -> u64 {
        self.start_address.offset
            + (self.entries.len() as u64) * (self.pointer_size as u64)
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Resolve a table entry to an absolute address.
    ///
    /// For relative tables, adds the offset to the table base.
    pub fn resolve_entry(&self, ordinal: u64) -> Option<Address> {
        self.entries.get(&ordinal).map(|entry| {
            if self.is_relative {
                Address::new(self.start_address.offset.wrapping_add(entry.offset))
            } else {
                *entry
            }
        })
    }

    /// Get all resolved target addresses.
    pub fn all_targets(&self) -> Vec<Address> {
        (0..self.entries.len() as u64)
            .filter_map(|i| self.resolve_entry(i))
            .collect()
    }
}

/// Options for the address table analyzer.
#[derive(Debug, Clone)]
pub struct AddressTableAnalyzerOptions {
    /// Minimum number of entries to consider as a table.
    pub min_entries: usize,
    /// Whether to look for relative (offset-based) tables.
    pub detect_relative: bool,
    /// Whether to look for absolute pointer tables.
    pub detect_absolute: bool,
    /// Minimum table alignment (in bytes).
    pub min_alignment: u8,
    /// Maximum table size (in entries).
    pub max_entries: usize,
}

impl Default for AddressTableAnalyzerOptions {
    fn default() -> Self {
        Self {
            min_entries: 2,
            detect_relative: true,
            detect_absolute: true,
            min_alignment: 4,
            max_entries: 10000,
        }
    }
}

/// Analyzer for finding address tables in memory and scheduling their targets
/// for disassembly.
///
/// Ported from `ghidra.app.plugin.core.disassembler.AddressTableAnalyzer` and
/// `ghidra.app.plugin.core.disassembler.AutoTableDisassemblerPlugin`.
#[derive(Debug)]
pub struct AddressTableAnalyzer {
    /// Analysis options.
    pub options: AddressTableAnalyzerOptions,
    /// Tables found during analysis.
    tables: Vec<AddressTable>,
    /// Addresses that have been analyzed.
    analyzed_regions: Vec<(u64, u64)>,
}

impl AddressTableAnalyzer {
    /// Create a new address table analyzer with default options.
    pub fn new() -> Self {
        Self {
            options: AddressTableAnalyzerOptions::default(),
            tables: Vec::new(),
            analyzed_regions: Vec::new(),
        }
    }

    /// Create with custom options.
    pub fn with_options(options: AddressTableAnalyzerOptions) -> Self {
        Self {
            options,
            tables: Vec::new(),
            analyzed_regions: Vec::new(),
        }
    }

    /// Report a found table.
    pub fn add_table(&mut self, table: AddressTable) {
        self.tables.push(table);
    }

    /// Get all found tables.
    pub fn tables(&self) -> &[AddressTable] {
        &self.tables
    }

    /// Get mutable reference to tables.
    pub fn tables_mut(&mut self) -> &mut Vec<AddressTable> {
        &mut self.tables
    }

    /// Mark a region as analyzed.
    pub fn mark_analyzed(&mut self, start: u64, end: u64) {
        self.analyzed_regions.push((start, end));
    }

    /// Check if an address falls within an already-analyzed region.
    pub fn is_analyzed(&self, address: u64) -> bool {
        self.analyzed_regions
            .iter()
            .any(|&(start, end)| address >= start && address <= end)
    }

    /// Validate that a potential table entry is a valid code pointer.
    ///
    /// Returns `true` if the target address points to a valid code location.
    pub fn validate_table_entry(
        target: u64,
        code_regions: &[(u64, u64)],
        min_alignment: u8,
    ) -> bool {
        // Check alignment
        if target % min_alignment as u64 != 0 {
            return false;
        }
        // Check if target is within a code region
        code_regions
            .iter()
            .any(|&(start, end)| target >= start && target <= end)
    }

    /// Scan a memory region for potential address tables.
    ///
    /// Given raw pointer values read from memory, checks if they form
    /// a valid table (sequential pointers to code regions).
    pub fn scan_for_tables(
        &self,
        base_address: u64,
        pointers: &[u64],
        code_regions: &[(u64, u64)],
        pointer_size: u8,
    ) -> Vec<AddressTable> {
        let mut tables = Vec::new();
        let mut current_table: Option<AddressTable> = None;
        let mut consecutive_valid = 0usize;

        for (i, &ptr) in pointers.iter().enumerate() {
            if Self::validate_table_entry(ptr, code_regions, self.options.min_alignment) {
                consecutive_valid += 1;
                let table = current_table.get_or_insert_with(|| {
                    AddressTable::new(
                        Address::new(base_address + (i as u64) * pointer_size as u64),
                        pointer_size,
                    )
                });
                table.add_entry(consecutive_valid as u64 - 1, Address::new(ptr));
            } else {
                // End of potential table
                if let Some(table) = current_table.take() {
                    if table.entry_count() >= self.options.min_entries {
                        tables.push(table);
                    }
                }
                consecutive_valid = 0;
            }
        }

        // Check final table
        if let Some(table) = current_table {
            if table.entry_count() >= self.options.min_entries {
                tables.push(table);
            }
        }

        tables
    }

    /// Get all target addresses from all found tables.
    pub fn all_disassembly_targets(&self) -> Vec<Address> {
        self.tables
            .iter()
            .flat_map(|t| t.all_targets())
            .collect()
    }

    /// Clear all found tables and analyzed regions.
    pub fn clear(&mut self) {
        self.tables.clear();
        self.analyzed_regions.clear();
    }

    /// The number of tables found.
    pub fn table_count(&self) -> usize {
        self.tables.len()
    }
}

impl Default for AddressTableAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_table_new() {
        let table = AddressTable::new(Address::new(0x4000), 4);
        assert_eq!(table.start_address, Address::new(0x4000));
        assert_eq!(table.pointer_size, 4);
        assert!(!table.is_relative);
        assert!(table.is_empty());
    }

    #[test]
    fn test_address_table_add_entry() {
        let mut table = AddressTable::new(Address::new(0x4000), 4);
        table.add_entry(0, Address::new(0x1000));
        table.add_entry(1, Address::new(0x2000));
        assert_eq!(table.entry_count(), 2);
        assert_eq!(table.end_address(), 0x4008);
    }

    #[test]
    fn test_address_table_resolve_absolute() {
        let mut table = AddressTable::new(Address::new(0x4000), 4);
        table.add_entry(0, Address::new(0x8000));
        assert_eq!(table.resolve_entry(0), Some(Address::new(0x8000)));
    }

    #[test]
    fn test_address_table_resolve_relative() {
        let mut table = AddressTable::new(Address::new(0x4000), 4);
        table.is_relative = true;
        table.add_entry(0, Address::new(0x100));
        assert_eq!(table.resolve_entry(0), Some(Address::new(0x4100)));
    }

    #[test]
    fn test_address_table_all_targets() {
        let mut table = AddressTable::new(Address::new(0x4000), 4);
        table.add_entry(0, Address::new(0x1000));
        table.add_entry(1, Address::new(0x2000));
        let targets = table.all_targets();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0], Address::new(0x1000));
        assert_eq!(targets[1], Address::new(0x2000));
    }

    #[test]
    fn test_analyzer_options_default() {
        let opts = AddressTableAnalyzerOptions::default();
        assert_eq!(opts.min_entries, 2);
        assert!(opts.detect_relative);
        assert!(opts.detect_absolute);
        assert_eq!(opts.min_alignment, 4);
    }

    #[test]
    fn test_validate_table_entry() {
        let code_regions = vec![(0x1000, 0x2000), (0x4000, 0x5000)];
        assert!(AddressTableAnalyzer::validate_table_entry(
            0x1000, &code_regions, 4
        ));
        assert!(AddressTableAnalyzer::validate_table_entry(
            0x4000, &code_regions, 4
        ));
        // Not aligned
        assert!(!AddressTableAnalyzer::validate_table_entry(
            0x1001, &code_regions, 4
        ));
        // Not in code region
        assert!(!AddressTableAnalyzer::validate_table_entry(
            0x3000, &code_regions, 4
        ));
    }

    #[test]
    fn test_scan_for_tables() {
        let analyzer = AddressTableAnalyzer::new();
        let code_regions = vec![(0x1000, 0x2000), (0x4000, 0x5000)];
        let pointers = vec![0x1000, 0x1004, 0x9999, 0x4000, 0x4004, 0x4008];

        let tables = analyzer.scan_for_tables(0x8000, &pointers, &code_regions, 4);
        assert_eq!(tables.len(), 2);
        assert_eq!(tables[0].entry_count(), 2);
        assert_eq!(tables[1].entry_count(), 3);
    }

    #[test]
    fn test_scan_too_small_table() {
        let analyzer = AddressTableAnalyzer::new();
        let code_regions = vec![(0x1000, 0x2000)];
        // Only 1 valid pointer -> below min_entries (2)
        let pointers = vec![0x1000, 0x9999];

        let tables = analyzer.scan_for_tables(0x8000, &pointers, &code_regions, 4);
        assert_eq!(tables.len(), 0);
    }

    #[test]
    fn test_mark_analyzed_and_check() {
        let mut analyzer = AddressTableAnalyzer::new();
        analyzer.mark_analyzed(0x1000, 0x2000);
        assert!(analyzer.is_analyzed(0x1500));
        assert!(!analyzer.is_analyzed(0x3000));
    }

    #[test]
    fn test_all_disassembly_targets() {
        let mut analyzer = AddressTableAnalyzer::new();
        let mut t1 = AddressTable::new(Address::new(0x4000), 4);
        t1.add_entry(0, Address::new(0x1000));
        let mut t2 = AddressTable::new(Address::new(0x5000), 4);
        t2.add_entry(0, Address::new(0x2000));
        analyzer.add_table(t1);
        analyzer.add_table(t2);
        let targets = analyzer.all_disassembly_targets();
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn test_clear() {
        let mut analyzer = AddressTableAnalyzer::new();
        let mut table = AddressTable::new(Address::new(0x4000), 4);
        table.add_entry(0, Address::new(0x1000));
        analyzer.add_table(table);
        analyzer.mark_analyzed(0x1000, 0x2000);
        assert_eq!(analyzer.table_count(), 1);
        analyzer.clear();
        assert_eq!(analyzer.table_count(), 0);
        assert!(!analyzer.is_analyzed(0x1500));
    }
}
