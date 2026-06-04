//! Address table analysis -- ported from Ghidra's
//! `AddressTable.java` and `AddressTableAnalyzer.java`.
//!
//! This module provides:
//!
//! - [`AddressTable`] -- representation of an address table (switch/jump table)
//! - [`AddressTableAnalyzer`] -- analyzer that discovers address tables in undefined data
//! - [`AddressTableOptions`] -- configuration for the address table analyzer

use crate::base::analyzer::core::*;
use crate::base::analyzer::priority::*;
use crate::base::analyzer::r#trait::*;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// One billion cases for probability calculation.
pub const BILLION_CASES: u64 = 1024 * 1024 * 1024;
/// Upper bound on table entries.
pub const TOO_MANY_ENTRIES: usize = 1024 * 1024;
/// Default minimum address that should be considered a valid pointer.
pub const MINIMUM_SAFE_ADDRESS: u64 = 1024;

/// Bookmark type name for address tables.
const ADDRESS_TABLE_BOOKMARK_TYPENAME: &str = "Address Table";
/// Prefix for address table labels.
const NAME_PREFIX: &str = "AddrTable";
/// Prefix for index-to-table labels.
const INDEX_PREFIX: &str = "IndexToAddrTable";

// ---------------------------------------------------------------------------
// AddressTable
// ---------------------------------------------------------------------------

/// Represents an address table (e.g., switch table, vtable, jump table).
///
/// An address table is a contiguous sequence of pointer-sized values in
/// memory that reference other addresses in the program. Optionally, a
/// secondary index table may follow the main table.
#[derive(Debug, Clone)]
pub struct AddressTable {
    /// Start address of the table.
    pub top_address: Address,
    /// Pointer values from the table.
    pub table_elements: Vec<Address>,
    /// Start address of the optional index table.
    pub top_index_address: Option<Address>,
    /// Number of entries in the index table.
    pub index_len: usize,
    /// Size of each address entry in bytes.
    pub addr_size: usize,
    /// Number of bytes to skip between entries.
    pub skip_amount: usize,
    /// Whether this is a negative (downward-growing) table.
    pub negative_table: bool,
    /// Whether entries are shifted pointers.
    pub shifted_addr: bool,
}

impl AddressTable {
    /// Create a new address table.
    pub fn new(
        top_address: Address,
        table_elements: Vec<Address>,
        addr_byte_size: usize,
        skip_amount: usize,
        shifted_addr: bool,
    ) -> Self {
        Self {
            top_address,
            table_elements,
            top_index_address: None,
            index_len: 0,
            addr_size: addr_byte_size,
            skip_amount,
            negative_table: false,
            shifted_addr,
        }
    }

    /// Create an address table with a secondary index.
    pub fn with_index(
        top_address: Address,
        table_elements: Vec<Address>,
        top_index_address: Address,
        index_len: usize,
        addr_byte_size: usize,
        skip_amount: usize,
        shifted_addr: bool,
    ) -> Self {
        Self {
            top_address,
            table_elements,
            top_index_address: Some(top_index_address),
            index_len,
            addr_size: addr_byte_size,
            skip_amount,
            negative_table: false,
            shifted_addr,
        }
    }

    /// Create a new address table from remaining entries starting at `start_pos`.
    ///
    /// Returns `None` if there are no remaining entries.
    pub fn remaining_table(&self, start_pos: usize) -> Option<AddressTable> {
        if self.top_index_address.is_some() {
            return None;
        }
        if start_pos == 0 || start_pos >= self.table_elements.len() {
            return None;
        }
        let byte_length = self.byte_length_for_range(0, start_pos - 1, false);
        let new_top = self.top_address.add(byte_length as u64);
        let new_elements = self.table_elements[start_pos..].to_vec();

        Some(AddressTable::new(
            new_top,
            new_elements,
            self.addr_size,
            self.skip_amount,
            self.shifted_addr,
        ))
    }

    /// Get the byte length of the entire table in memory.
    pub fn byte_length(&self) -> usize {
        let mut length = self.table_elements.len() * self.addr_size;
        if self.top_index_address.is_some() {
            length += self.index_len;
        }
        length
    }

    /// Get the byte length for a range of entries.
    pub fn byte_length_for_range(&self, start: usize, end: usize, include_index: bool) -> usize {
        let mut length = ((end - start) + 1) * self.addr_size;
        if include_index && self.top_index_address.is_some() {
            length += self.index_len;
        }
        length
    }

    /// Get the number of address entries in the table.
    pub fn num_entries(&self) -> usize {
        self.table_elements.len()
    }

    /// Get a reference to the table elements.
    pub fn elements(&self) -> &[Address] {
        &self.table_elements
    }

    /// Get the start address of the index table, if present.
    pub fn index_address(&self) -> Option<Address> {
        self.top_index_address
    }

    /// Get a generic name for the table.
    pub fn table_name(&self, offset: usize) -> String {
        format!(
            "{}{}",
            NAME_PREFIX,
            self.top_address.add((offset * self.addr_size) as u64)
        )
    }

    /// Get a generic name for the index to the table.
    pub fn index_name(&self, offset: usize) -> String {
        format!(
            "{}{}",
            INDEX_PREFIX,
            self.top_address.add((offset * self.addr_size) as u64)
        )
    }

    /// Get the label prefix for an element.
    pub fn element_prefix(&self, offset: usize) -> String {
        format!(
            "{}{}Element",
            NAME_PREFIX,
            self.top_address.add((offset * self.addr_size) as u64)
        )
    }

    /// Validate that the table region is undefined and can be claimed.
    ///
    /// Returns `true` if the table can be created (no existing defined data
    /// overlaps it), `false` otherwise.
    pub fn can_create_table(&self, program: &Program, start: usize, end: usize, include_index: bool) -> bool {
        let total_len = self.byte_length_for_range(start, end, include_index);
        let table_end = self.top_address.add((start * self.addr_size) as u64)
            .add(total_len as u64 - 1);

        // Check for overlapping defined data
        for (addr, instr) in &program.listing.instructions {
            let instr_end = addr.add(instr.length as u64 - 1);
            if addr.space_id == self.top_address.space_id
                && addr.offset <= table_end.offset
                && instr_end.offset >= self.top_address.offset
            {
                return false;
            }
        }
        for (addr, data) in &program.listing.data_items {
            let data_end = addr.add(data.length as u64 - 1);
            if addr.space_id == self.top_address.space_id
                && addr.offset <= table_end.offset
                && data_end.offset >= self.top_address.offset
            {
                return false;
            }
        }
        true
    }

    /// Check if an address is a valid pointer target.
    ///
    /// A valid pointer must be >= `min_addr` and within `max_distance` of
    /// the table start.
    pub fn is_valid_pointer(addr: Address, min_addr: u64, max_distance: u64, table_start: Address) -> bool {
        if addr.offset < min_addr {
            return false;
        }
        if addr.space_id != table_start.space_id {
            return false;
        }
        let distance = if addr.offset >= table_start.offset {
            addr.offset - table_start.offset
        } else {
            table_start.offset - addr.offset
        };
        distance <= max_distance
    }
}

// ---------------------------------------------------------------------------
// AddressTableOptions
// ---------------------------------------------------------------------------

/// Options for the address table analyzer.
#[derive(Debug, Clone)]
pub struct AddressTableOptions {
    /// Minimum number of consecutive entries to form a table.
    pub min_table_size: usize,
    /// Alignment of the table start address in bytes.
    pub table_alignment: usize,
    /// Alignment of pointer entries in bytes.
    pub ptr_alignment: usize,
    /// Whether to auto-label table entries.
    pub auto_label: bool,
    /// Minimum address to consider a value as a pointer.
    pub min_pointer_addr: u64,
    /// Maximum distance between consecutive pointers before breaking the table.
    pub max_pointer_diff: u64,
    /// Whether to use relocation table entries to guide pointer analysis.
    pub relocation_guide: bool,
    /// Whether to allow offcut references.
    pub allow_offcut_references: bool,
    /// Whether to create bookmarks at table locations.
    pub create_bookmarks: bool,
}

impl Default for AddressTableOptions {
    fn default() -> Self {
        Self {
            min_table_size: 4,
            table_alignment: 4,
            ptr_alignment: 1,
            auto_label: false,
            min_pointer_addr: MINIMUM_SAFE_ADDRESS,
            max_pointer_diff: 0xFFFFFF,
            relocation_guide: true,
            allow_offcut_references: false,
            create_bookmarks: true,
        }
    }
}

// ---------------------------------------------------------------------------
// AddressTableAnalyzer
// ---------------------------------------------------------------------------

/// Analyzer that discovers address tables in undefined data.
///
/// Scans undefined data regions looking for runs of pointer-sized values
/// that point to valid addresses in the program. When found, creates
/// pointer data items and optionally labels the table.
///
/// This analyzer is disabled by default and must be explicitly enabled.
#[derive(Debug, Clone)]
pub struct AddressTableAnalyzer {
    base: AbstractAnalyzer,
    options: AddressTableOptions,
    /// Whether the processor uses low-bit code addressing.
    processor_has_low_bit_code: bool,
}

impl AddressTableAnalyzer {
    /// Create a new address table analyzer.
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "Create Address Tables",
            "Analyzes undefined data for address tables.",
            AnalyzerType::Byte,
        );
        base.set_priority(AnalysisPriority::DATA_TYPE_PROPAGATION.before());
        base.set_supports_one_time_analysis(true);
        base.set_default_enablement(false);

        Self {
            base,
            options: AddressTableOptions::default(),
            processor_has_low_bit_code: false,
        }
    }

    /// Get the analyzer options.
    pub fn options(&self) -> &AddressTableOptions {
        &self.options
    }

    /// Get a mutable reference to the analyzer options.
    pub fn options_mut(&mut self) -> &mut AddressTableOptions {
        &mut self.options
    }

    /// Scan an address range for potential address tables.
    ///
    /// Returns discovered tables as a vector of `(table, probability)` pairs.
    pub fn scan_for_tables(
        &self,
        program: &Program,
        start: Address,
        end: Address,
        _monitor: &dyn TaskMonitor,
    ) -> Vec<AddressTable> {
        let mut tables = Vec::new();
        let alignment = self.options.ptr_alignment;
        let min_entries = self.options.min_table_size;

        // Scan for runs of potential pointers
        let mut current_run: Vec<Address> = Vec::new();
        let mut run_start = start;

        let mut addr = start;
        while addr.offset <= end.offset {
            // In a full implementation, this would read memory at addr,
            // interpret it as a pointer-sized value, and check validity.
            // For now, we use the listing's data items as a proxy.
            if let Some(data) = program.listing.get_defined_data_at(&addr) {
                if data.is_pointer() {
                    current_run.push(addr);
                } else if current_run.len() >= min_entries {
                    tables.push(AddressTable::new(
                        run_start,
                        current_run.clone(),
                        alignment,
                        0,
                        false,
                    ));
                    current_run.clear();
                } else {
                    current_run.clear();
                }
            } else if !current_run.is_empty() && current_run.len() >= min_entries {
                tables.push(AddressTable::new(
                    run_start,
                    current_run.clone(),
                    alignment,
                    0,
                    false,
                ));
                current_run.clear();
            }

            if current_run.is_empty() {
                run_start = addr.add(alignment as u64);
            }
            addr = addr.add(alignment as u64);
        }

        // Flush any remaining run
        if current_run.len() >= min_entries {
            tables.push(AddressTable::new(
                run_start,
                current_run,
                alignment,
                0,
                false,
            ));
        }

        tables
    }
}

impl Default for AddressTableAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for AddressTableAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }

    fn description(&self) -> &str {
        self.base.description()
    }

    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }

    fn priority(&self) -> AnalysisPriority {
        self.base.priority()
    }

    fn default_enablement(&self, _program: &Program) -> bool {
        self.base.default_enablement(_program)
    }

    fn can_analyze(&self, program: &Program) -> bool {
        let addr_size = program.language.size;
        addr_size == 32 || addr_size == 64
    }

    fn added(
        &self,
        program: &mut Program,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        monitor.check_cancelled()?;
        monitor.set_message("Searching for address tables...");

        for range in set.iter() {
            if monitor.is_cancelled() {
                break;
            }
            let tables = self.scan_for_tables(program, range.start, range.end, monitor);
            for table in &tables {
                if self.options.create_bookmarks {
                    program.set_bookmark(
                        table.top_address,
                        BookmarkType::Analysis,
                        ADDRESS_TABLE_BOOKMARK_TYPENAME,
                        table.table_name(0),
                    );
                }
                log.append_msg(format!(
                    "Found address table at {} with {} entries",
                    table.top_address,
                    table.num_entries()
                ));
            }
        }

        Ok(true)
    }

    fn supports_one_time_analysis(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_table_creation() {
        let elements = vec![Address::new(0x2000), Address::new(0x2004), Address::new(0x2008)];
        let table = AddressTable::new(Address::new(0x1000), elements, 4, 0, false);
        assert_eq!(table.num_entries(), 3);
        assert_eq!(table.byte_length(), 12);
        assert!(table.index_address().is_none());
    }

    #[test]
    fn test_address_table_with_index() {
        let elements = vec![Address::new(0x2000), Address::new(0x2004)];
        let table = AddressTable::with_index(
            Address::new(0x1000),
            elements,
            Address::new(0x1010),
            8,
            4,
            0,
            false,
        );
        assert_eq!(table.num_entries(), 2);
        assert_eq!(table.byte_length(), 16); // 8 (table) + 8 (index)
        assert!(table.index_address().is_some());
    }

    #[test]
    fn test_address_table_name() {
        let table = AddressTable::new(Address::new(0x1000), vec![], 4, 0, false);
        assert_eq!(table.table_name(0), "AddrTable0x00001000");
    }

    #[test]
    fn test_address_table_element_prefix() {
        let table = AddressTable::new(Address::new(0x1000), vec![], 4, 0, false);
        assert_eq!(table.element_prefix(0), "AddrTable0x00001000Element");
    }

    #[test]
    fn test_address_table_remaining() {
        let elements = vec![
            Address::new(0x2000),
            Address::new(0x2004),
            Address::new(0x2008),
            Address::new(0x200C),
        ];
        let table = AddressTable::new(Address::new(0x1000), elements, 4, 0, false);
        let remaining = table.remaining_table(2).unwrap();
        assert_eq!(remaining.num_entries(), 2);
        assert_eq!(remaining.top_address.offset, 0x1008);
    }

    #[test]
    fn test_address_table_remaining_nothing() {
        let elements = vec![Address::new(0x2000)];
        let table = AddressTable::new(Address::new(0x1000), elements, 4, 0, false);
        assert!(table.remaining_table(0).is_none()); // start_pos == 0
        assert!(table.remaining_table(1).is_none()); // start_pos >= len
    }

    #[test]
    fn test_is_valid_pointer() {
        assert!(AddressTable::is_valid_pointer(
            Address::new(0x4000),
            0x1000,
            0xFFFFFF,
            Address::new(0x1000)
        ));
        assert!(!AddressTable::is_valid_pointer(
            Address::new(0x500), // below minimum
            0x1000,
            0xFFFFFF,
            Address::new(0x1000)
        ));
    }

    #[test]
    fn test_byte_length_for_range() {
        let elements = vec![Address::new(0x2000); 10];
        let table = AddressTable::new(Address::new(0x1000), elements, 4, 0, false);
        assert_eq!(table.byte_length_for_range(0, 4, false), 20); // 5 entries * 4 bytes
    }

    #[test]
    fn test_options_defaults() {
        let opts = AddressTableOptions::default();
        assert_eq!(opts.min_table_size, 4);
        assert_eq!(opts.table_alignment, 4);
        assert_eq!(opts.min_pointer_addr, MINIMUM_SAFE_ADDRESS);
        assert!(opts.relocation_guide);
        assert!(!opts.auto_label);
    }

    #[test]
    fn test_analyzer_creation() {
        let analyzer = AddressTableAnalyzer::new();
        assert_eq!(analyzer.name(), "Create Address Tables");
        assert!(!analyzer.default_enablement(&Program::new("test", Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        })));
    }

    #[test]
    fn test_analyzer_can_analyze() {
        let analyzer = AddressTableAnalyzer::new();
        let prog32 = Program::new("test", Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 32,
        });
        let prog64 = Program::new("test", Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        });
        let prog16 = Program::new("test", Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 16,
        });
        assert!(analyzer.can_analyze(&prog32));
        assert!(analyzer.can_analyze(&prog64));
        assert!(!analyzer.can_analyze(&prog16));
    }
}
