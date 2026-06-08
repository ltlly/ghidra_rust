//! Program utilities ported from Ghidra's `ghidra.program.util` package.
//!
//! Provides utility types and functions for working with programs:
//! - [`ProgramDiff`] -- compare two programs for differences
//! - [`MemoryDiff`] -- compare memory contents between programs
//! - [`MemoryRangeDiff`] -- compare a single memory range
//! - [`ProgramMergeFilter`] -- filter what gets merged
//! - [`ProgramMemoryUtil`] -- memory utility functions
//! - [`FunctionUtility`] -- function-related utilities
//! - [`FunctionMerge`] -- merge function data
//! - [`SymbolicPropagator`] -- propagate symbolic values through instructions
//! - [`ExternalSymbolResolver`] -- resolve external symbols
//! - [`AddressIteratorConverter`] -- convert addresses between address spaces
//! - [`MultiAddressRangeIterator`] -- iterate over multi-address ranges
//! - [`DataTypeCleaner`] -- clean up data types
//! - [`InteriorSelection`] -- represents a selection within a composite
//! - [`FoundString`] / [`StringSearcher`] -- find strings in programs

use std::collections::HashMap;
use std::fmt;

use crate::base::analyzer::{Address, AddressRange, AddressSet, Program};

// ---------------------------------------------------------------------------
// ProgramDiff
// ---------------------------------------------------------------------------

/// Categories of differences between two programs.
///
/// Ported from `ghidra.program.util.ProgramDiff`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiffCategory {
    /// Differences in memory byte contents.
    MemoryBytes,
    /// Differences in memory block properties (name, permissions).
    MemoryBlocks,
    /// Differences in code units (instructions, data).
    CodeUnits,
    /// Differences in labels/symbols.
    Labels,
    /// Differences in comments.
    Comments,
    /// Differences in equates.
    Equates,
    /// Differences in functions.
    Functions,
    /// Differences in references.
    References,
    /// Differences in data types.
    DataTypes,
    /// Differences in bookmarks.
    Bookmarks,
    /// Differences in properties.
    Properties,
    /// All categories.
    All,
}

/// A program difference report.
#[derive(Debug, Clone)]
pub struct ProgramDiffReport {
    /// The address set where differences were found.
    pub differences: AddressSet,
    /// Per-category difference addresses.
    pub by_category: HashMap<DiffCategory, AddressSet>,
}

impl ProgramDiffReport {
    pub fn new() -> Self {
        Self {
            differences: AddressSet::new(),
            by_category: HashMap::new(),
        }
    }

    /// Add a difference at the given address for the specified category.
    pub fn add_difference(&mut self, addr: Address, category: DiffCategory) {
        self.differences.add(addr);
        self.by_category
            .entry(category)
            .or_insert_with(AddressSet::new)
            .add(addr);
    }

    /// Add a range of differences for the specified category.
    pub fn add_range(&mut self, start: Address, end: Address, category: DiffCategory) {
        self.differences.add_range(AddressRange::new(start, end));
        self.by_category
            .entry(category)
            .or_insert_with(AddressSet::new)
            .add_range(AddressRange::new(start, end));
    }

    /// Get the address set for a specific category.
    pub fn get_category_set(&self, category: DiffCategory) -> Option<&AddressSet> {
        self.by_category.get(&category)
    }

    /// Check if there are any differences.
    pub fn is_empty(&self) -> bool {
        self.differences.is_empty()
    }

    /// Get the total number of difference addresses.
    pub fn num_differences(&self) -> usize {
        self.differences.num_addresses() as usize
    }
}

impl Default for ProgramDiffReport {
    fn default() -> Self {
        Self::new()
    }
}

/// Utility for comparing two programs.
///
/// Ported from `ghidra.program.util.ProgramDiff`.
pub struct ProgramDiff;

impl ProgramDiff {
    /// Compare labels/symbols of two programs over the given address set.
    pub fn diff_labels(
        program_a: &Program,
        program_b: &Program,
        addr_set: &AddressSet,
    ) -> ProgramDiffReport {
        let mut report = ProgramDiffReport::new();

        for range in addr_set.iter() {
            let mut addr = range.start;
            while addr.offset <= range.end.offset {
                let sym_a = program_a.symbols.get(&addr);
                let sym_b = program_b.symbols.get(&addr);
                if sym_a != sym_b {
                    report.add_difference(addr, DiffCategory::Labels);
                }
                addr = Address::new(addr.offset + 1);
            }
        }

        report
    }

    /// Compare functions of two programs.
    pub fn diff_functions(
        program_a: &Program,
        program_b: &Program,
    ) -> ProgramDiffReport {
        let mut report = ProgramDiffReport::new();

        let funcs_a = &program_a.function_manager.functions;
        let funcs_b = &program_b.function_manager.functions;

        // Find functions in A but not B
        for (addr, func_a) in funcs_a {
            match funcs_b.get(addr) {
                Some(func_b) => {
                    let name_a = func_a.name.as_deref().unwrap_or("");
                    let name_b = func_b.name.as_deref().unwrap_or("");
                    if name_a != name_b || func_a.body.num_addresses() != func_b.body.num_addresses() {
                        report.add_difference(*addr, DiffCategory::Functions);
                    }
                }
                None => {
                    report.add_difference(*addr, DiffCategory::Functions);
                }
            }
        }

        // Find functions in B but not A
        for addr in funcs_b.keys() {
            if !funcs_a.contains_key(addr) {
                report.add_difference(*addr, DiffCategory::Functions);
            }
        }

        report
    }

    /// Full diff of two programs across all categories.
    pub fn full_diff(
        program_a: &Program,
        program_b: &Program,
        addr_set: &AddressSet,
    ) -> ProgramDiffReport {
        let mut report = Self::diff_labels(program_a, program_b, addr_set);
        let func_report = Self::diff_functions(program_a, program_b);
        for (cat, addrs) in func_report.by_category {
            for range in addrs.iter() {
                report.add_range(range.start, range.end, cat);
            }
        }
        report
    }
}

// ---------------------------------------------------------------------------
// MemoryDiff
// ---------------------------------------------------------------------------

/// Compares memory address sets of two programs.
///
/// Note: The current Program model tracks initialized addresses (AddressSet)
/// but not byte values, so this compares address coverage rather than byte content.
///
/// Ported from `ghidra.program.util.MemoryDiff`.
#[derive(Debug)]
pub struct MemoryDiff {
    /// Address ranges in program_a but not program_b.
    only_in_a: AddressSet,
    /// Address ranges in program_b but not program_a.
    only_in_b: AddressSet,
    /// Address ranges in both programs.
    in_both: AddressSet,
}

impl MemoryDiff {
    /// Create a new memory diff comparing two programs over the given address set.
    pub fn new(program_a: &Program, program_b: &Program, addr_set: &AddressSet) -> Self {
        let mem_a = program_a.memory.intersect(addr_set);
        let mem_b = program_b.memory.intersect(addr_set);

        let in_both = mem_a.intersect(&mem_b);
        let _only_in_a = mem_a.clone();
        // Compute only_in_a = mem_a - in_both
        let mut only_in_a_set = mem_a;
        only_in_a_set.delete(&in_both);

        let mut only_in_b_set = mem_b;
        only_in_b_set.delete(&in_both);

        Self {
            only_in_a: only_in_a_set,
            only_in_b: only_in_b_set,
            in_both,
        }
    }

    /// Get addresses only in program A.
    pub fn only_in_a(&self) -> &AddressSet {
        &self.only_in_a
    }

    /// Get addresses only in program B.
    pub fn only_in_b(&self) -> &AddressSet {
        &self.only_in_b
    }

    /// Get addresses present in both programs.
    pub fn in_both(&self) -> &AddressSet {
        &self.in_both
    }

    /// Check if the two programs have identical memory coverage.
    pub fn is_identical(&self) -> bool {
        self.only_in_a.is_empty() && self.only_in_b.is_empty()
    }
}

// ---------------------------------------------------------------------------
// MemoryRangeDiff
// ---------------------------------------------------------------------------

/// Compares a single memory range between two programs.
///
/// Ported from `ghidra.program.util.MemoryRangeDiff`.
#[derive(Debug, Clone)]
pub struct MemoryRangeDiff {
    /// The address range being compared.
    pub range: AddressRange,
    /// Whether this range exists in program A.
    pub in_program_a: bool,
    /// Whether this range exists in program B.
    pub in_program_b: bool,
}

impl MemoryRangeDiff {
    /// Create a new range diff.
    pub fn new(program_a: &Program, program_b: &Program, range: AddressRange) -> Self {
        let in_program_a = program_a.memory.contains(&range.start);
        let in_program_b = program_b.memory.contains(&range.start);
        Self {
            range,
            in_program_a,
            in_program_b,
        }
    }

    /// Check if the range exists in both programs.
    pub fn is_identical(&self) -> bool {
        self.in_program_a == self.in_program_b
    }
}

// ---------------------------------------------------------------------------
// ProgramMergeFilter
// ---------------------------------------------------------------------------

/// Controls what categories of data are included in a merge operation.
///
/// Ported from `ghidra.program.util.ProgramMergeFilter`.
#[derive(Debug, Clone)]
pub struct ProgramMergeFilter {
    /// Which categories to merge.
    categories: HashMap<DiffCategory, MergeAction>,
}

/// Action to take when merging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeAction {
    /// Replace the target with the source.
    Replace,
    /// Add the source only if the target is empty/missing.
    Add,
    /// Remove the target data.
    Remove,
    /// Skip this category entirely.
    Skip,
}

impl ProgramMergeFilter {
    pub fn new() -> Self {
        Self {
            categories: HashMap::new(),
        }
    }

    /// Set the merge action for a category.
    pub fn set_action(&mut self, category: DiffCategory, action: MergeAction) {
        self.categories.insert(category, action);
    }

    /// Get the merge action for a category.
    pub fn get_action(&self, category: DiffCategory) -> MergeAction {
        self.categories.get(&category).copied().unwrap_or(MergeAction::Skip)
    }

    /// Check if the category should be merged (replace or add).
    pub fn should_merge(&self, category: DiffCategory) -> bool {
        matches!(
            self.get_action(category),
            MergeAction::Replace | MergeAction::Add
        )
    }

    /// Create a filter that merges everything (replace).
    pub fn merge_all() -> Self {
        let mut filter = Self::new();
        for cat in [
            DiffCategory::MemoryBytes,
            DiffCategory::MemoryBlocks,
            DiffCategory::CodeUnits,
            DiffCategory::Labels,
            DiffCategory::Comments,
            DiffCategory::Equates,
            DiffCategory::Functions,
            DiffCategory::References,
            DiffCategory::DataTypes,
            DiffCategory::Bookmarks,
            DiffCategory::Properties,
        ] {
            filter.set_action(cat, MergeAction::Replace);
        }
        filter
    }

    /// Create a filter that merges nothing.
    pub fn skip_all() -> Self {
        Self::new()
    }
}

impl Default for ProgramMergeFilter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ProgramDiffFilter
// ---------------------------------------------------------------------------

/// Controls what categories of data are included in a diff operation.
///
/// Ported from `ghidra.program.util.ProgramDiffFilter`.
#[derive(Debug, Clone)]
pub struct ProgramDiffFilter {
    /// Which categories to include (true = include).
    categories: HashMap<DiffCategory, bool>,
}

impl ProgramDiffFilter {
    /// Create a new filter that diffs everything.
    pub fn all() -> Self {
        let mut categories = HashMap::new();
        for cat in [
            DiffCategory::MemoryBytes,
            DiffCategory::MemoryBlocks,
            DiffCategory::CodeUnits,
            DiffCategory::Labels,
            DiffCategory::Comments,
            DiffCategory::Equates,
            DiffCategory::Functions,
            DiffCategory::References,
            DiffCategory::DataTypes,
            DiffCategory::Bookmarks,
            DiffCategory::Properties,
        ] {
            categories.insert(cat, true);
        }
        Self { categories }
    }

    /// Create a filter that diffs nothing.
    pub fn none() -> Self {
        Self { categories: HashMap::new() }
    }

    /// Set whether a category should be diffed.
    pub fn set_diff(&mut self, category: DiffCategory, enabled: bool) {
        self.categories.insert(category, enabled);
    }

    /// Check if a category should be diffed.
    pub fn should_diff(&self, category: DiffCategory) -> bool {
        self.categories.get(&category).copied().unwrap_or(false)
    }
}

impl Default for ProgramDiffFilter {
    fn default() -> Self { Self::all() }
}

// ---------------------------------------------------------------------------
// ProgramMemoryUtil
// ---------------------------------------------------------------------------

/// Memory utility functions.
///
/// Ported from `ghidra.program.util.ProgramMemoryUtil`.
pub struct ProgramMemoryUtil;

impl ProgramMemoryUtil {
    /// Get the set of initialized memory addresses in a program.
    pub fn get_initialized_memory(program: &Program) -> &AddressSet {
        &program.memory
    }

    /// Check whether a program has any initialized memory.
    pub fn has_memory(program: &Program) -> bool {
        !program.memory.is_empty()
    }

    /// Get the total number of initialized bytes.
    pub fn total_initialized_bytes(program: &Program) -> u64 {
        program.memory.num_addresses()
    }

    /// Get the common address set between two programs' initialized memory.
    pub fn common_address_set(program_a: &Program, program_b: &Program) -> AddressSet {
        program_a.memory.intersect(&program_b.memory)
    }

    /// Get the union of two programs' initialized memory.
    pub fn union_address_set(program_a: &Program, program_b: &Program) -> AddressSet {
        program_a.memory.union(&program_b.memory)
    }

    /// Get the minimum address of a program's initialized memory.
    pub fn min_address(program: &Program) -> Option<Address> {
        if program.memory.is_empty() {
            None
        } else {
            Some(program.memory.min_address())
        }
    }

    /// Get the maximum address of a program's initialized memory.
    pub fn max_address(program: &Program) -> Option<Address> {
        if program.memory.is_empty() {
            None
        } else {
            Some(program.memory.max_address())
        }
    }
}

// ---------------------------------------------------------------------------
// FunctionUtility
// ---------------------------------------------------------------------------

/// Function-related utilities.
///
/// Ported from `ghidra.program.util.FunctionUtility`.
pub struct FunctionUtility;

impl FunctionUtility {
    /// Check if an address is at the start of a function.
    pub fn is_function_start(program: &Program, addr: Address) -> bool {
        program.function_manager.functions.contains_key(&addr)
    }

    /// Find the function containing the given address.
    pub fn get_function_containing(program: &Program, addr: Address) -> Option<String> {
        program
            .function_manager
            .get_function_containing(&addr)
            .and_then(|f| f.name.clone())
    }

    /// Get the number of functions in the program.
    pub fn function_count(program: &Program) -> usize {
        program.function_manager.functions.len()
    }

    /// Get all function entry points.
    pub fn function_entry_points(program: &Program) -> Vec<Address> {
        program
            .function_manager
            .functions
            .keys()
            .copied()
            .collect()
    }
}

// ---------------------------------------------------------------------------
// FunctionMerge
// ---------------------------------------------------------------------------

/// Merge data from one function into another.
///
/// Ported from `ghidra.program.util.FunctionMerge`.
#[derive(Debug)]
pub struct FunctionMerge;

impl FunctionMerge {
    /// Merge body ranges from source function into target function.
    pub fn merge_bodies(target_body: &AddressSet, source_body: &AddressSet) -> AddressSet {
        target_body.union(source_body)
    }

    /// Intersect function bodies to find common addresses.
    pub fn intersect_bodies(body_a: &AddressSet, body_b: &AddressSet) -> AddressSet {
        body_a.intersect(body_b)
    }
}

// ---------------------------------------------------------------------------
// SymbolicPropagator
// ---------------------------------------------------------------------------

/// Propagates symbolic values through program instructions.
///
/// Used for constant propagation and value tracking analysis.
///
/// Ported from `ghidra.program.util.SymbolicPropogator`.
#[derive(Debug, Clone)]
pub struct SymbolicPropagator {
    /// Known register values at specific addresses.
    register_values: HashMap<(Address, String), i64>,
    /// Tracked value assignments.
    assignments: HashMap<Address, ValueAssignment>,
}

/// A value assignment at an address.
#[derive(Debug, Clone)]
pub struct ValueAssignment {
    /// The address of the assignment.
    pub address: Address,
    /// The register or variable being assigned.
    pub target: String,
    /// The assigned value (None if unknown).
    pub value: Option<i64>,
}

impl SymbolicPropagator {
    pub fn new() -> Self {
        Self {
            register_values: HashMap::new(),
            assignments: HashMap::new(),
        }
    }

    /// Set a known register value at an address.
    pub fn set_register_value(&mut self, addr: Address, register: &str, value: i64) {
        self.register_values.insert((addr, register.to_string()), value);
    }

    /// Get a register value at an address.
    pub fn get_register_value(&self, addr: Address, register: &str) -> Option<i64> {
        self.register_values
            .get(&(addr, register.to_string()))
            .copied()
    }

    /// Record a value assignment.
    pub fn add_assignment(&mut self, assignment: ValueAssignment) {
        self.assignments.insert(assignment.address, assignment);
    }

    /// Get the assignment at an address.
    pub fn get_assignment(&self, addr: Address) -> Option<&ValueAssignment> {
        self.assignments.get(&addr)
    }

    /// Get all known register values for an address.
    pub fn values_at(&self, addr: Address) -> Vec<(&str, i64)> {
        self.register_values
            .iter()
            .filter(|((a, _), _)| *a == addr)
            .map(|((_, reg), val)| (reg.as_str(), *val))
            .collect()
    }

    /// Propagate a constant value through a range.
    pub fn propagate_constant(
        &mut self,
        start: Address,
        end: Address,
        register: &str,
        value: i64,
    ) {
        let mut addr = start;
        while addr.offset <= end.offset {
            self.set_register_value(addr, register, value);
            addr = Address::new(addr.offset + 1);
        }
    }
}

impl Default for SymbolicPropagator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ExternalSymbolResolver
// ---------------------------------------------------------------------------

/// Resolves external symbols from a library program.
///
/// Ported from `ghidra.program.util.ExternalSymbolResolver`.
pub struct ExternalSymbolResolver;

impl ExternalSymbolResolver {
    /// Find a symbol by name in the program's symbols.
    pub fn find_symbol(program: &Program, symbol_name: &str) -> Option<Address> {
        program
            .symbols
            .iter()
            .find(|(_, name)| name.as_str() == symbol_name)
            .map(|(addr, _)| *addr)
    }

    /// Get all external references (symbols pointing to external libraries).
    pub fn get_external_references(program: &Program) -> Vec<(Address, &str)> {
        program
            .external_references
            .iter()
            .map(|(addr, name)| (*addr, name.as_str()))
            .collect()
    }

    /// Get all defined symbols as name-address pairs.
    pub fn get_all_symbols(program: &Program) -> Vec<(&str, Address)> {
        program
            .symbols
            .iter()
            .map(|(addr, name)| (name.as_str(), *addr))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// AddressIteratorConverter
// ---------------------------------------------------------------------------

/// Converts addresses by applying an offset.
///
/// Ported from `ghidra.program.util.AddressIteratorConverter`.
#[derive(Debug, Clone)]
pub struct AddressIteratorConverter {
    /// Offset to add when converting.
    offset: i64,
}

impl AddressIteratorConverter {
    pub fn new(offset: i64) -> Self {
        Self { offset }
    }

    /// Convert an address by applying the offset.
    pub fn convert(&self, addr: Address) -> Address {
        let new_offset = (addr.offset as i64 + self.offset) as u64;
        Address::new(new_offset)
    }

    /// Convert a set of addresses.
    pub fn convert_set(&self, set: &AddressSet) -> AddressSet {
        let mut result = AddressSet::new();
        for range in set.iter() {
            let new_start = self.convert(range.start);
            let new_end = self.convert(range.end);
            result.add_range(AddressRange::new(new_start, new_end));
        }
        result
    }
}

// ---------------------------------------------------------------------------
// MultiAddressRangeIterator
// ---------------------------------------------------------------------------

/// Iterates over address ranges from multiple address sets.
///
/// Ported from `ghidra.program.util.MultiAddressRangeIterator`.
#[derive(Debug)]
pub struct MultiAddressRangeIterator {
    ranges: Vec<AddressRange>,
    index: usize,
}

impl MultiAddressRangeIterator {
    pub fn new(sets: &[&AddressSet]) -> Self {
        let mut ranges: Vec<AddressRange> = Vec::new();
        for set in sets {
            for range in set.iter() {
                ranges.push(*range);
            }
        }
        ranges.sort_by_key(|r| r.start.offset);
        Self { ranges, index: 0 }
    }
}

impl Iterator for MultiAddressRangeIterator {
    type Item = AddressRange;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.ranges.len() {
            let range = self.ranges[self.index];
            self.index += 1;
            Some(range)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// DataTypeCleaner
// ---------------------------------------------------------------------------

/// Removes data types from a program that are no longer used.
///
/// Ported from `ghidra.program.util.DataTypeCleaner`.
pub struct DataTypeCleaner;

impl DataTypeCleaner {
    /// Placeholder for finding unused data types.
    pub fn find_unused_types(_program: &Program) -> Vec<String> {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// InteriorSelection
// ---------------------------------------------------------------------------

/// Represents a selection within a composite data type.
///
/// Ported from `ghidra.program.util.InteriorSelection`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteriorSelection {
    /// The start of the selection within the composite.
    pub from: Address,
    /// The end of the selection within the composite.
    pub to: Address,
}

impl InteriorSelection {
    pub fn new(from: Address, to: Address) -> Self {
        Self { from, to }
    }

    /// Check if the selection is empty (from == to).
    pub fn is_empty(&self) -> bool {
        self.from == self.to
    }
}

// ---------------------------------------------------------------------------
// FoundString
// ---------------------------------------------------------------------------

/// A string found during string searching in a program.
///
/// Ported from `ghidra.program.util.string.FoundString`.
#[derive(Debug, Clone)]
pub struct FoundString {
    /// The address where the string starts.
    pub address: Address,
    /// The length of the string in bytes (including any terminator).
    pub length: usize,
    /// The string value (decoded).
    pub value: String,
    /// Whether this is a null-terminated string.
    pub is_null_terminated: bool,
    /// The character size (1 for ASCII, 2 for UTF-16).
    pub char_size: u8,
}

impl FoundString {
    pub fn new(
        address: Address,
        length: usize,
        value: String,
        is_null_terminated: bool,
        char_size: u8,
    ) -> Self {
        Self {
            address,
            length,
            value,
            is_null_terminated,
            char_size,
        }
    }
}

// ---------------------------------------------------------------------------
// StringSearcher
// ---------------------------------------------------------------------------

/// Searches for strings in program memory.
///
/// Ported from `ghidra.program.util.string.StringSearcher`.
#[derive(Debug, Clone)]
pub struct StringSearcher {
    /// Minimum string length to report.
    min_length: usize,
    /// Whether to search for null-terminated strings.
    search_null_terminated: bool,
    /// Character alignment (1 for byte-aligned, 2 for word-aligned).
    alignment: usize,
}

impl StringSearcher {
    pub fn new(min_length: usize) -> Self {
        Self {
            min_length,
            search_null_terminated: true,
            alignment: 1,
        }
    }

    /// Set the minimum string length.
    pub fn set_min_length(&mut self, min_length: usize) {
        self.min_length = min_length;
    }

    /// Set the character alignment.
    pub fn set_alignment(&mut self, alignment: usize) {
        self.alignment = alignment.max(1);
    }

    /// Search for null-terminated ASCII strings in the given byte data.
    pub fn search(&self, data: &[u8], base_addr: Address) -> Vec<FoundString> {
        let mut results = Vec::new();

        if self.search_null_terminated {
            results.extend(self.find_null_terminated(data, base_addr));
        }

        results
    }

    /// Find null-terminated ASCII strings.
    fn find_null_terminated(&self, data: &[u8], base_addr: Address) -> Vec<FoundString> {
        let mut results = Vec::new();
        let mut start: Option<usize> = None;

        for i in (0..data.len()).step_by(self.alignment) {
            let b = data[i];
            if b >= 0x20 && b < 0x7F {
                // Printable ASCII
                if start.is_none() {
                    start = Some(i);
                }
            } else if b == 0 {
                // Null terminator
                if let Some(s) = start {
                    let len = i - s;
                    if len >= self.min_length {
                        let value = String::from_utf8_lossy(&data[s..i]).into_owned();
                        results.push(FoundString::new(
                            Address::new(base_addr.offset + s as u64),
                            len + 1,
                            value,
                            true,
                            1,
                        ));
                    }
                }
                start = None;
            } else {
                start = None;
            }
        }

        results
    }
}

impl Default for StringSearcher {
    fn default() -> Self {
        Self::new(5)
    }
}

// ---------------------------------------------------------------------------
// DefaultAddressTranslator
// ---------------------------------------------------------------------------

/// Translates addresses between different address spaces.
///
/// Ported from `ghidra.program.util.DefaultAddressTranslator`.
#[derive(Debug, Clone)]
pub struct DefaultAddressTranslator {
    source_offset: u64,
    target_offset: u64,
}

impl DefaultAddressTranslator {
    pub fn new(source_offset: u64, target_offset: u64) -> Self {
        Self {
            source_offset,
            target_offset,
        }
    }

    /// Translate an address from source to target space.
    pub fn translate(&self, addr: Address) -> Address {
        let relative = addr.offset.wrapping_sub(self.source_offset);
        Address::new(self.target_offset.wrapping_add(relative))
    }

    /// Reverse-translate from target back to source.
    pub fn reverse_translate(&self, addr: Address) -> Address {
        let relative = addr.offset.wrapping_sub(self.target_offset);
        Address::new(self.source_offset.wrapping_add(relative))
    }
}

// ---------------------------------------------------------------------------
// ProgramSelection
// ---------------------------------------------------------------------------

/// A selection of addresses in a program.
///
/// Ported from `ghidra.program.util.ProgramSelection`.
///
/// Wraps an [`AddressSet`] with optional interior (sub-field) selection
/// for use in the listing display.
#[derive(Debug, Clone, Default)]
pub struct ProgramSelection {
    /// The selected address set.
    pub address_set: AddressSet,
    /// Optional interior selection within a composite.
    pub interior: Option<InteriorSelection>,
}

impl ProgramSelection {
    /// Create an empty selection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a selection from an address range.
    pub fn from_range(from: Address, to: Address) -> Self {
        let (lo, hi) = if from <= to { (from, to) } else { (to, from) };
        let mut address_set = AddressSet::new();
        address_set.add_range(AddressRange::new(lo, hi));
        Self { address_set, interior: None }
    }

    /// Create a selection from an address set.
    pub fn from_address_set(set: AddressSet) -> Self {
        Self { address_set: set, interior: None }
    }

    /// Whether the selection is empty.
    pub fn is_empty(&self) -> bool {
        self.address_set.is_empty()
    }

    /// Number of addresses in the selection.
    pub fn num_addresses(&self) -> u64 {
        self.address_set.num_addresses()
    }

    /// Check if an address is in the selection.
    pub fn contains(&self, addr: &Address) -> bool {
        self.address_set.contains(addr)
    }

    /// Clear the selection.
    pub fn clear(&mut self) {
        self.address_set = AddressSet::new();
        self.interior = None;
    }

    /// Add an address to the selection.
    pub fn add(&mut self, addr: Address) {
        self.address_set.add(addr);
    }

    /// Add a range to the selection.
    pub fn add_range(&mut self, from: Address, to: Address) {
        self.address_set.add_range(AddressRange::new(from, to));
    }
}

// ---------------------------------------------------------------------------
// ContextEvaluator
// ---------------------------------------------------------------------------

/// Evaluation action for symbolic propagation.
///
/// Ported from `ghidra.program.util.ContextEvaluator`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalAction {
    /// Continue evaluation.
    Continue,
    /// Stop evaluation.
    Stop,
    /// Skip this instruction.
    Skip,
}

/// Callback trait for symbolic propagation.
///
/// Ported from `ghidra.program.util.ContextEvaluator`.
pub trait ContextEvaluator: Send + Sync + std::fmt::Debug {
    /// Called before an instruction is evaluated.
    fn evaluate_context_before(
        &self,
        address: Address,
        _register_state: &HashMap<String, u64>,
    ) -> EvalAction;

    /// Called after an instruction has been evaluated.
    fn evaluate_context(
        &self,
        address: Address,
        _register_state: &HashMap<String, u64>,
    ) -> EvalAction;

    /// Called when a reference is detected.
    fn evaluate_reference(&self, _addr: Address, _target: Address, _ref_type: &str) -> bool {
        true
    }

    /// Called when a potential constant address is detected.
    fn evaluate_constant(&self, _addr: Address, _constant: u64, _size: usize) -> bool {
        false
    }
}

/// A default evaluator that always continues.
#[derive(Debug, Clone, Copy)]
pub struct DefaultContextEvaluator;

impl ContextEvaluator for DefaultContextEvaluator {
    fn evaluate_context_before(&self, _address: Address, _state: &HashMap<String, u64>) -> EvalAction {
        EvalAction::Continue
    }
    fn evaluate_context(&self, _address: Address, _state: &HashMap<String, u64>) -> EvalAction {
        EvalAction::Continue
    }
}

// ---------------------------------------------------------------------------
// VarnodeContext
// ---------------------------------------------------------------------------

/// A context for tracking register and memory values during symbolic
/// propagation.
///
/// Ported from `ghidra.program.util.VarnodeContext`.
#[derive(Debug)]
pub struct VarnodeContext {
    /// Current register values.
    reg_vals: HashMap<String, u64>,
    /// Current memory values.
    mem_vals: HashMap<u64, u64>,
    /// Unique (temporary) values.
    unique_vals: HashMap<u64, u64>,
    /// Stack of saved states for flow forking.
    saved_states: Vec<(HashMap<String, u64>, HashMap<u64, u64>, HashMap<u64, u64>)>,
    /// Flow tracking.
    flow_map: HashMap<u64, Vec<u64>>,
}

impl VarnodeContext {
    /// Create a new empty context.
    pub fn new() -> Self {
        Self {
            reg_vals: HashMap::new(),
            mem_vals: HashMap::new(),
            unique_vals: HashMap::new(),
            saved_states: Vec::new(),
            flow_map: HashMap::new(),
        }
    }

    /// Set a register value.
    pub fn set_register(&mut self, name: &str, value: u64) {
        self.reg_vals.insert(name.to_string(), value);
    }

    /// Get a register value.
    pub fn get_register(&self, name: &str) -> Option<u64> {
        self.reg_vals.get(name).copied()
    }

    /// Remove a register value.
    pub fn remove_register(&mut self, name: &str) -> Option<u64> {
        self.reg_vals.remove(name)
    }

    /// Set a memory value.
    pub fn set_memory(&mut self, addr: u64, value: u64) {
        self.mem_vals.insert(addr, value);
    }

    /// Get a memory value.
    pub fn get_memory(&self, addr: u64) -> Option<u64> {
        self.mem_vals.get(&addr).copied()
    }

    /// Set a unique value.
    pub fn set_unique(&mut self, id: u64, value: u64) {
        self.unique_vals.insert(id, value);
    }

    /// Get a unique value.
    pub fn get_unique(&self, id: u64) -> Option<u64> {
        self.unique_vals.get(&id).copied()
    }

    /// Record a flow edge.
    pub fn add_flow(&mut self, from: u64, to: u64) {
        self.flow_map.entry(from).or_default().push(to);
    }

    /// Get flow targets from an address.
    pub fn flow_targets(&self, from: u64) -> &[u64] {
        self.flow_map.get(&from).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Save (fork) the current state.
    pub fn save_state(&mut self) {
        self.saved_states.push((
            self.reg_vals.clone(),
            self.mem_vals.clone(),
            self.unique_vals.clone(),
        ));
    }

    /// Restore the most recently saved state. Returns false if empty.
    pub fn restore_state(&mut self) -> bool {
        if let Some((regs, mems, uniqs)) = self.saved_states.pop() {
            self.reg_vals = regs;
            self.mem_vals = mems;
            self.unique_vals = uniqs;
            true
        } else {
            false
        }
    }

    /// Number of saved states.
    pub fn saved_state_depth(&self) -> usize {
        self.saved_states.len()
    }

    /// Clear all values.
    pub fn clear(&mut self) {
        self.reg_vals.clear();
        self.mem_vals.clear();
        self.unique_vals.clear();
        self.flow_map.clear();
    }
}

impl Default for VarnodeContext {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// GhidraProgramUtilities
// ---------------------------------------------------------------------------

/// Utility functions for working with programs.
///
/// Ported from `ghidra.program.util.GhidraProgramUtilities`.
pub struct GhidraProgramUtilities;

impl GhidraProgramUtilities {
    /// Check if a program should be prompted for analysis.
    pub fn should_ask_to_analyze(program: &Program) -> bool {
        program.function_manager.functions.is_empty()
    }
}

// ---------------------------------------------------------------------------
// ListingDiff
// ---------------------------------------------------------------------------

/// Compares two program listings.
///
/// Ported from `ghidra.program.util.ListingDiff`.
#[derive(Debug)]
pub struct ListingDiff {
    /// Categories of differences to compare.
    pub diff_filter: ProgramDiffFilter,
}

impl ListingDiff {
    /// Create a new ListingDiff.
    pub fn new() -> Self {
        Self { diff_filter: ProgramDiffFilter::all() }
    }

    /// Compare two programs.
    pub fn diff(
        &self,
        program_a: &Program,
        program_b: &Program,
        addr_set: &AddressSet,
    ) -> ProgramDiffReport {
        let mut report = ProgramDiffReport::new();
        if self.diff_filter.should_diff(DiffCategory::Labels) {
            let label_report = ProgramDiff::diff_labels(program_a, program_b, addr_set);
            for range in label_report.differences.iter() {
                report.add_range(range.start, range.end, DiffCategory::Labels);
            }
        }
        if self.diff_filter.should_diff(DiffCategory::Functions) {
            let func_report = ProgramDiff::diff_functions(program_a, program_b);
            for (cat, addrs) in func_report.by_category {
                for range in addrs.iter() {
                    report.add_range(range.start, range.end, cat);
                }
            }
        }
        report
    }
}

impl Default for ListingDiff {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// MarkerLocation
// ---------------------------------------------------------------------------

/// A location for a marker in the program.
///
/// Ported from `ghidra.program.util.MarkerLocation`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MarkerLocation {
    /// Address of the marker.
    pub address: Address,
    /// Marker type.
    pub marker_type: String,
    /// Description.
    pub description: String,
    /// Source plugin.
    pub source: String,
}

impl MarkerLocation {
    pub fn new(address: Address, marker_type: impl Into<String>, description: impl Into<String>, source: impl Into<String>) -> Self {
        Self { address, marker_type: marker_type.into(), description: description.into(), source: source.into() }
    }
}

impl fmt::Display for MarkerLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] 0x{:X}: {} ({})", self.marker_type, self.address.offset, self.description, self.source)
    }
}

// ---------------------------------------------------------------------------
// ProgramMerge
// ---------------------------------------------------------------------------

/// Merge utility for combining two programs.
///
/// Ported from `ghidra.program.util.ProgramMerge`.
pub struct ProgramMerge;

impl ProgramMerge {
    /// Merge functions from `source` into `dest` within the given address set.
    pub fn merge_functions(dest: &mut Program, source: &Program, addr_set: &AddressSet) -> AddressSet {
        let mut merged = AddressSet::new();
        for (addr, func) in &source.function_manager.functions {
            if addr_set.contains(addr) && !dest.function_manager.functions.contains_key(addr) {
                dest.function_manager.functions.insert(*addr, func.clone());
                merged.add(*addr);
            }
        }
        merged
    }

    /// Merge symbols from `source` into `dest` within the given address set.
    pub fn merge_symbols(dest: &mut Program, source: &Program, addr_set: &AddressSet) -> AddressSet {
        let mut merged = AddressSet::new();
        for (addr, name) in &source.symbols {
            if addr_set.contains(addr) && !dest.symbols.contains_key(addr) {
                dest.symbols.insert(*addr, name.clone());
                merged.add(*addr);
            }
        }
        merged
    }
}

// ---------------------------------------------------------------------------
// ProgramConflictException
// ---------------------------------------------------------------------------

/// Exception indicating a conflict between two programs.
///
/// Ported from `ghidra.program.util.ProgramConflictException`.
#[derive(Debug, Clone)]
pub struct ProgramConflictException {
    /// Address of the conflict.
    pub address: Address,
    /// Description.
    pub message: String,
}

impl fmt::Display for ProgramConflictException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Program conflict at 0x{:X}: {}", self.address.offset, self.message)
    }
}

impl std::error::Error for ProgramConflictException {}

// ---------------------------------------------------------------------------
// GroupView
// ---------------------------------------------------------------------------

/// A view that groups addresses.
///
/// Ported from `ghidra.program.util.GroupView`.
#[derive(Debug, Clone, Default)]
pub struct GroupView {
    /// The groups.
    pub groups: Vec<AddressGroup>,
}

/// A named group of addresses.
#[derive(Debug, Clone)]
pub struct AddressGroup {
    /// Group name.
    pub name: String,
    /// Addresses in this group.
    pub addresses: AddressSet,
}

impl AddressGroup {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), addresses: AddressSet::new() }
    }
}

impl GroupView {
    pub fn new() -> Self { Self::default() }
    pub fn add_group(&mut self, group: AddressGroup) { self.groups.push(group); }
    pub fn group_for_address(&self, addr: &Address) -> Option<&AddressGroup> {
        self.groups.iter().find(|g| g.addresses.contains(addr))
    }
    pub fn group_count(&self) -> usize { self.groups.len() }
}

// ---------------------------------------------------------------------------
// AddressTranslationException
// ---------------------------------------------------------------------------

/// Exception thrown when an attempt is made to translate an address
/// from one program into an equivalent address in another program.
///
/// Ported from `ghidra.program.util.AddressTranslationException`.
#[derive(Debug, Clone)]
pub struct AddressTranslationException {
    /// The address that could not be translated.
    pub address: Option<Address>,
    /// Description of the translation failure.
    pub message: String,
}

impl AddressTranslationException {
    /// Create a new exception with no specific address.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            address: None,
            message: message.into(),
        }
    }

    /// Create a new exception for a specific address with source/dest program names.
    pub fn with_address(
        address: Address,
        source_program: &str,
        dest_program: &str,
    ) -> Self {
        Self {
            address: Some(address),
            message: format!(
                "Cannot translate address \"0x{:X}\" in program \"{}\" to address in program \"{}\".",
                address.offset, source_program, dest_program
            ),
        }
    }
}

impl fmt::Display for AddressTranslationException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AddressTranslationException {}

// ---------------------------------------------------------------------------
// AddressTranslator (trait)
// ---------------------------------------------------------------------------

/// Translates addresses between two programs.
///
/// Ported from `ghidra.program.util.AddressTranslator`.
pub trait AddressTranslator: Send + Sync + std::fmt::Debug {
    /// Get the destination program for translated addresses.
    fn destination_program(&self) -> &str;

    /// Get the source program for addresses being translated.
    fn source_program(&self) -> &str;

    /// Translate a single address from the source program to the destination program.
    fn get_address(&self, source_address: Address) -> Result<Address, AddressTranslationException>;

    /// Returns true if this translator provides a one-to-one mapping
    /// (preserving relative offsets within ranges).
    fn is_one_for_one(&self) -> bool;

    /// Translate an address range. Only meaningful if `is_one_for_one()` returns true.
    fn get_address_range(
        &self,
        source_range: &AddressRange,
    ) -> Result<AddressRange, AddressTranslationException> {
        let start = self.get_address(source_range.start)?;
        let end = self.get_address(source_range.end)?;
        Ok(AddressRange::new(start, end))
    }

    /// Translate an address set. Only meaningful if `is_one_for_one()` returns true.
    fn get_address_set(
        &self,
        source_set: &AddressSet,
    ) -> Result<AddressSet, AddressTranslationException> {
        let mut result = AddressSet::new();
        for range in source_set.iter() {
            let translated = self.get_address_range(range)?;
            result.add_range(translated);
        }
        Ok(result)
    }
}

/// A simple offset-based address translator.
///
/// Translates addresses by applying a fixed offset.
/// Ported from `ghidra.program.util.DefaultAddressTranslator` (the Java interface version).
#[derive(Debug, Clone)]
pub struct OffsetAddressTranslator {
    source_name: String,
    dest_name: String,
    offset: i64,
}

impl OffsetAddressTranslator {
    pub fn new(
        source_name: impl Into<String>,
        dest_name: impl Into<String>,
        offset: i64,
    ) -> Self {
        Self {
            source_name: source_name.into(),
            dest_name: dest_name.into(),
            offset,
        }
    }
}

impl AddressTranslator for OffsetAddressTranslator {
    fn destination_program(&self) -> &str {
        &self.dest_name
    }

    fn source_program(&self) -> &str {
        &self.source_name
    }

    fn get_address(&self, source_address: Address) -> Result<Address, AddressTranslationException> {
        let new_offset = (source_address.offset as i64 + self.offset) as u64;
        Ok(Address::new(new_offset))
    }

    fn is_one_for_one(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// MemoryBlockDiff
// ---------------------------------------------------------------------------

/// Determines the types of differences between two memory blocks.
///
/// Ported from `ghidra.program.util.MemoryBlockDiff`.
#[derive(Debug, Clone)]
pub struct MemoryBlockDiff {
    /// The first block's name.
    pub block1_name: Option<String>,
    /// The second block's name.
    pub block2_name: Option<String>,
    /// Bitflags indicating which properties differ.
    diff_flags: u32,
}

/// Memory block property difference flags.
pub mod memory_block_flags {
    /// Block names differ.
    pub const NAME: u32          = 0x001;
    /// Start addresses differ.
    pub const START_ADDRESS: u32 = 0x002;
    /// End addresses differ.
    pub const END_ADDRESS: u32   = 0x004;
    /// Sizes differ.
    pub const SIZE: u32          = 0x008;
    /// Read permissions differ.
    pub const READ: u32          = 0x010;
    /// Write permissions differ.
    pub const WRITE: u32         = 0x020;
    /// Execute permissions differ.
    pub const EXECUTE: u32       = 0x040;
    /// Volatile flags differ.
    pub const VOLATILE: u32      = 0x080;
    /// Artificial flags differ.
    pub const ARTIFICIAL: u32    = 0x100;
    /// Block types differ.
    pub const TYPE: u32          = 0x200;
    /// Initialization states differ.
    pub const INIT: u32          = 0x400;
    /// Source names differ.
    pub const SOURCE: u32        = 0x800;
    /// Comments differ.
    pub const COMMENT: u32       = 0x1000;
    /// All difference flags combined.
    pub const ALL: u32           = 0x1FFF;
}

/// Describes a memory block for use with `MemoryBlockDiff`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryBlockDesc {
    pub name: String,
    pub start: u64,
    pub end: u64,
    pub size: u64,
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub volatile: bool,
    pub artificial: bool,
    pub block_type: String,
    pub initialized: bool,
    pub source_name: Option<String>,
    pub comment: Option<String>,
}

impl MemoryBlockDesc {
    pub fn new(name: impl Into<String>, start: u64, end: u64) -> Self {
        let s = start;
        let e = end;
        Self {
            name: name.into(),
            start: s,
            end: e,
            size: e - s + 1,
            read: true,
            write: false,
            execute: false,
            volatile: false,
            artificial: false,
            block_type: "DEFAULT".into(),
            initialized: true,
            source_name: None,
            comment: None,
        }
    }
}

impl MemoryBlockDiff {
    /// Compare two optional memory block descriptions.
    ///
    /// If both are `None`, no differences are reported.
    /// If only one is `None`, all flags are set.
    pub fn new(block1: Option<&MemoryBlockDesc>, block2: Option<&MemoryBlockDesc>) -> Self {
        let (b1_name, b2_name) = match (&block1, &block2) {
            (Some(b1), Some(b2)) => (Some(b1.name.clone()), Some(b2.name.clone())),
            (Some(b1), None) => (Some(b1.name.clone()), None),
            (None, Some(b2)) => (None, Some(b2.name.clone())),
            (None, None) => (None, None),
        };

        Self {
            block1_name: b1_name,
            block2_name: b2_name,
            diff_flags: Self::compute_flags(block1, block2),
        }
    }

    fn compute_flags(
        block1: Option<&MemoryBlockDesc>,
        block2: Option<&MemoryBlockDesc>,
    ) -> u32 {
        match (block1, block2) {
            (None, None) => 0,
            (None, Some(_)) | (Some(_), None) => memory_block_flags::ALL,
            (Some(b1), Some(b2)) => {
                let mut flags = 0u32;
                if b1.name != b2.name {
                    flags |= memory_block_flags::NAME;
                }
                if b1.start != b2.start {
                    flags |= memory_block_flags::START_ADDRESS;
                }
                if b1.end != b2.end {
                    flags |= memory_block_flags::END_ADDRESS;
                }
                if b1.size != b2.size {
                    flags |= memory_block_flags::SIZE;
                }
                if b1.read != b2.read {
                    flags |= memory_block_flags::READ;
                }
                if b1.write != b2.write {
                    flags |= memory_block_flags::WRITE;
                }
                if b1.execute != b2.execute {
                    flags |= memory_block_flags::EXECUTE;
                }
                if b1.volatile != b2.volatile {
                    flags |= memory_block_flags::VOLATILE;
                }
                if b1.artificial != b2.artificial {
                    flags |= memory_block_flags::ARTIFICIAL;
                }
                if b1.block_type != b2.block_type {
                    flags |= memory_block_flags::TYPE;
                }
                if b1.initialized != b2.initialized {
                    flags |= memory_block_flags::INIT;
                }
                if b1.source_name != b2.source_name {
                    flags |= memory_block_flags::SOURCE;
                }
                if b1.comment != b2.comment {
                    flags |= memory_block_flags::COMMENT;
                }
                flags
            }
        }
    }

    /// Returns true if the block names differ.
    pub fn is_name_different(&self) -> bool {
        (self.diff_flags & memory_block_flags::NAME) != 0
    }

    /// Returns true if the start addresses differ.
    pub fn is_start_address_different(&self) -> bool {
        (self.diff_flags & memory_block_flags::START_ADDRESS) != 0
    }

    /// Returns true if the end addresses differ.
    pub fn is_end_address_different(&self) -> bool {
        (self.diff_flags & memory_block_flags::END_ADDRESS) != 0
    }

    /// Returns true if the sizes differ.
    pub fn is_size_different(&self) -> bool {
        (self.diff_flags & memory_block_flags::SIZE) != 0
    }

    /// Returns true if the read permissions differ.
    pub fn is_read_different(&self) -> bool {
        (self.diff_flags & memory_block_flags::READ) != 0
    }

    /// Returns true if the write permissions differ.
    pub fn is_write_different(&self) -> bool {
        (self.diff_flags & memory_block_flags::WRITE) != 0
    }

    /// Returns true if the execute permissions differ.
    pub fn is_exec_different(&self) -> bool {
        (self.diff_flags & memory_block_flags::EXECUTE) != 0
    }

    /// Returns true if the volatile flags differ.
    pub fn is_volatile_different(&self) -> bool {
        (self.diff_flags & memory_block_flags::VOLATILE) != 0
    }

    /// Returns true if the artificial flags differ.
    pub fn is_artificial_different(&self) -> bool {
        (self.diff_flags & memory_block_flags::ARTIFICIAL) != 0
    }

    /// Returns true if the block types differ.
    pub fn is_type_different(&self) -> bool {
        (self.diff_flags & memory_block_flags::TYPE) != 0
    }

    /// Returns true if the initialization states differ.
    pub fn is_init_different(&self) -> bool {
        (self.diff_flags & memory_block_flags::INIT) != 0
    }

    /// Returns true if the source names differ.
    pub fn is_source_different(&self) -> bool {
        (self.diff_flags & memory_block_flags::SOURCE) != 0
    }

    /// Returns true if the comments differ.
    pub fn is_comment_different(&self) -> bool {
        (self.diff_flags & memory_block_flags::COMMENT) != 0
    }

    /// Returns true if there are any differences at all.
    pub fn has_differences(&self) -> bool {
        self.diff_flags != 0
    }

    /// Returns the raw difference flags.
    pub fn flags(&self) -> u32 {
        self.diff_flags
    }

    /// Gets a string representation of the types of differences.
    pub fn differences_as_string(&self) -> String {
        let mut parts = Vec::new();
        if self.is_name_different() { parts.push("Name"); }
        if self.is_start_address_different() { parts.push("StartAddress"); }
        if self.is_end_address_different() { parts.push("EndAddress"); }
        if self.is_size_different() { parts.push("Size"); }
        if self.is_read_different() { parts.push("R"); }
        if self.is_write_different() { parts.push("W"); }
        if self.is_exec_different() { parts.push("X"); }
        if self.is_volatile_different() { parts.push("Volatile"); }
        if self.is_artificial_different() { parts.push("Artificial"); }
        if self.is_type_different() { parts.push("Type"); }
        if self.is_init_different() { parts.push("Initialized"); }
        if self.is_source_different() { parts.push("Source"); }
        if self.is_comment_different() { parts.push("Comment"); }
        parts.join(" ")
    }
}

// ---------------------------------------------------------------------------
// MultiAddressIterator
// ---------------------------------------------------------------------------

/// Iterates through multiple address iterators simultaneously.
///
/// The `next()` method returns the next address as determined from all the iterators,
/// respecting sort order (forward or backward).
///
/// Ported from `ghidra.program.util.MultiAddressIterator`.
#[derive(Debug)]
pub struct MultiAddressIterator {
    /// Buffered addresses from each iterator, one per source.
    addrs: Vec<Option<Address>>,
    /// The underlying address sources (collected into sorted Vecs).
    sources: Vec<Vec<Address>>,
    /// Current index into each source.
    indices: Vec<usize>,
    /// Whether to iterate forward (ascending) or backward (descending).
    forward: bool,
}

impl MultiAddressIterator {
    /// Create a new multi-address iterator from multiple address sets.
    ///
    /// All iterators will proceed in the direction indicated by `forward`.
    pub fn new(sets: &[&AddressSet], forward: bool) -> Self {
        let mut sources = Vec::with_capacity(sets.len());
        for set in sets {
            let mut addrs: Vec<Address> = set.iter().flat_map(|r| {
                let mut v = Vec::new();
                let mut a = r.start;
                while a.offset <= r.end.offset {
                    v.push(a);
                    a = Address::new(a.offset + 1);
                }
                v
            }).collect();
            if !forward {
                addrs.reverse();
            }
            sources.push(addrs);
        }
        let n = sources.len();
        Self {
            addrs: vec![None; n],
            sources,
            indices: vec![0; n],
            forward,
        }
    }

    /// Create from pre-built sorted address vectors.
    pub fn from_sorted_vecs(vectors: Vec<Vec<Address>>, forward: bool) -> Self {
        let n = vectors.len();
        Self {
            addrs: vec![None; n],
            sources: vectors,
            indices: vec![0; n],
            forward,
        }
    }

    /// Fill empty slots from their respective sources.
    fn fill_empty(&mut self) {
        for i in 0..self.addrs.len() {
            if self.addrs[i].is_none() && self.indices[i] < self.sources[i].len() {
                self.addrs[i] = Some(self.sources[i][self.indices[i]]);
                self.indices[i] += 1;
            }
        }
    }

    /// Check whether any iterator still has addresses.
    pub fn has_next(&mut self) -> bool {
        self.fill_empty();
        self.addrs.iter().any(|a| a.is_some())
    }

    /// Returns the next address (the minimum or maximum depending on direction).
    pub fn next(&mut self) -> Option<Address> {
        self.fill_empty();

        let mut best: Option<Address> = None;
        let mut best_indices = Vec::new();

        for (i, addr_opt) in self.addrs.iter().enumerate() {
            if let Some(addr) = addr_opt {
                match best {
                    None => {
                        best = Some(*addr);
                        best_indices.clear();
                        best_indices.push(i);
                    }
                    Some(current_best) => {
                        let cmp = addr.offset.cmp(&current_best.offset);
                        let is_better = if self.forward {
                            cmp == std::cmp::Ordering::Less
                        } else {
                            cmp == std::cmp::Ordering::Greater
                        };

                        if addr.offset == current_best.offset {
                            best_indices.push(i);
                        } else if is_better {
                            best = Some(*addr);
                            best_indices.clear();
                            best_indices.push(i);
                        }
                    }
                }
            }
        }

        // Consume all slots that matched the best address.
        for &i in &best_indices {
            self.addrs[i] = None;
        }

        best
    }

    /// Returns the next addresses from all iterators that share the
    /// same minimum/maximum address. Each element in the result corresponds
    /// to the source at that index; `None` if that source did not contribute.
    pub fn next_addresses(&mut self) -> Vec<Option<Address>> {
        self.fill_empty();

        let mut best: Option<Address> = None;
        let mut best_indices = Vec::new();

        for (i, addr_opt) in self.addrs.iter().enumerate() {
            if let Some(addr) = addr_opt {
                match best {
                    None => {
                        best = Some(*addr);
                        best_indices.clear();
                        best_indices.push(i);
                    }
                    Some(current_best) => {
                        let cmp = addr.offset.cmp(&current_best.offset);
                        let is_better = if self.forward {
                            cmp == std::cmp::Ordering::Less
                        } else {
                            cmp == std::cmp::Ordering::Greater
                        };

                        if addr.offset == current_best.offset {
                            best_indices.push(i);
                        } else if is_better {
                            best = Some(*addr);
                            best_indices.clear();
                            best_indices.push(i);
                        }
                    }
                }
            }
        }

        let n = self.addrs.len();
        let mut result = vec![None; n];
        for &i in &best_indices {
            result[i] = self.addrs[i];
            self.addrs[i] = None;
        }

        result
    }
}

// ---------------------------------------------------------------------------
// MultiCodeUnitIterator
// ---------------------------------------------------------------------------

/// Represents a code unit at an address (simplified for the Rust model).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeUnitInfo {
    /// Address of the code unit.
    pub address: Address,
    /// Mnemonic or data type name.
    pub mnemonic: String,
    /// Size in bytes.
    pub size: usize,
}

/// Iterates through multiple code-unit iterators simultaneously.
///
/// Returns the next code unit(s) as determined from all the iterators.
///
/// Ported from `ghidra.program.util.MultiCodeUnitIterator`.
#[derive(Debug)]
pub struct MultiCodeUnitIterator {
    /// Buffered code units from each source, one per source.
    cus: Vec<Option<CodeUnitInfo>>,
    /// The underlying code-unit sources.
    sources: Vec<Vec<CodeUnitInfo>>,
    /// Current index into each source.
    indices: Vec<usize>,
    /// Iteration direction.
    forward: bool,
}

impl MultiCodeUnitIterator {
    /// Create a new multi-code-unit iterator from multiple sorted code-unit lists.
    pub fn new(sources: Vec<Vec<CodeUnitInfo>>, forward: bool) -> Self {
        let n = sources.len();
        Self {
            cus: vec![None; n],
            sources,
            indices: vec![0; n],
            forward,
        }
    }

    fn fill_empty(&mut self) {
        for i in 0..self.cus.len() {
            if self.cus[i].is_none() && self.indices[i] < self.sources[i].len() {
                self.cus[i] = Some(self.sources[i][self.indices[i]].clone());
                self.indices[i] += 1;
            }
        }
    }

    /// Check whether any source still has code units.
    pub fn has_next(&mut self) -> bool {
        self.fill_empty();
        self.cus.iter().any(|c| c.is_some())
    }

    /// Returns the next code-unit array. Each element corresponds to the source
    /// at that index; `None` if that source does not have a code unit at this address.
    pub fn next_code_units(&mut self) -> Vec<Option<CodeUnitInfo>> {
        self.fill_empty();

        let mut best_addr: Option<Address> = None;
        let mut best_indices = Vec::new();

        for (i, cu_opt) in self.cus.iter().enumerate() {
            if let Some(cu) = cu_opt {
                match best_addr {
                    None => {
                        best_addr = Some(cu.address);
                        best_indices.clear();
                        best_indices.push(i);
                    }
                    Some(current_best) => {
                        let cmp = cu.address.offset.cmp(&current_best.offset);
                        let is_better = if self.forward {
                            cmp == std::cmp::Ordering::Less
                        } else {
                            cmp == std::cmp::Ordering::Greater
                        };

                        if cu.address.offset == current_best.offset {
                            best_indices.push(i);
                        } else if is_better {
                            best_addr = Some(cu.address);
                            best_indices.clear();
                            best_indices.push(i);
                        }
                    }
                }
            }
        }

        let n = self.cus.len();
        let mut result = vec![None; n];
        for &i in &best_indices {
            result[i] = self.cus[i].clone();
            self.cus[i] = None;
        }

        result
    }
}

// ---------------------------------------------------------------------------
// CombinedAddressRangeIterator
// ---------------------------------------------------------------------------

/// Combines two address range iterators into a single iterator that produces
/// non-overlapping ranges covering the union of both inputs.
///
/// When two ranges overlap, the output is split so that overlapping sub-ranges
/// appear once and non-overlapping parts from each source also appear.
///
/// Ported from `ghidra.program.util.CombinedAddressRangeIterator`.
#[derive(Debug)]
pub struct CombinedAddressRangeIterator {
    ranges_a: Vec<AddressRange>,
    ranges_b: Vec<AddressRange>,
    index_a: usize,
    index_b: usize,
    /// Partially consumed range from A.
    current_a: Option<AddressRange>,
    /// Partially consumed range from B.
    current_b: Option<AddressRange>,
}

impl CombinedAddressRangeIterator {
    /// Create a new combined iterator from two address sets.
    pub fn new(set_a: &AddressSet, set_b: &AddressSet) -> Self {
        let ranges_a: Vec<AddressRange> = set_a.iter().copied().collect();
        let ranges_b: Vec<AddressRange> = set_b.iter().copied().collect();
        Self {
            ranges_a,
            ranges_b,
            index_a: 0,
            index_b: 0,
            current_a: None,
            current_b: None,
        }
    }

    fn advance_a(&mut self) {
        if self.index_a < self.ranges_a.len() {
            self.current_a = Some(self.ranges_a[self.index_a]);
            self.index_a += 1;
        } else {
            self.current_a = None;
        }
    }

    fn advance_b(&mut self) {
        if self.index_b < self.ranges_b.len() {
            self.current_b = Some(self.ranges_b[self.index_b]);
            self.index_b += 1;
        } else {
            self.current_b = None;
        }
    }

    /// Get the next non-overlapping range from the union of both inputs.
    pub fn next_range(&mut self) -> Option<AddressRange> {
        // Lazily advance if we have nothing current.
        if self.current_a.is_none() && self.index_a < self.ranges_a.len() {
            self.advance_a();
        }
        if self.current_b.is_none() && self.index_b < self.ranges_b.len() {
            self.advance_b();
        }

        match (self.current_a, self.current_b) {
            (None, None) => None,
            (Some(a), None) => {
                self.current_a = None;
                Some(a)
            }
            (None, Some(b)) => {
                self.current_b = None;
                Some(b)
            }
            (Some(a), Some(b)) => {
                // If they don't overlap, emit the one that starts first.
                if a.end.offset < b.start.offset {
                    self.current_a = None;
                    Some(a)
                } else if b.end.offset < a.start.offset {
                    self.current_b = None;
                    Some(b)
                } else {
                    // They overlap. Emit the non-overlapping prefix of whichever starts first,
                    // then adjust the other.
                    if a.start.offset < b.start.offset {
                        // Emit [a.start, b.start-1], advance a to [b.start, a.end]
                        let result = AddressRange::new(a.start, Address::new(b.start.offset - 1));
                        self.current_a = Some(AddressRange::new(b.start, a.end));
                        Some(result)
                    } else if b.start.offset < a.start.offset {
                        let result = AddressRange::new(b.start, Address::new(a.start.offset - 1));
                        self.current_b = Some(AddressRange::new(a.start, b.end));
                        Some(result)
                    } else {
                        // Same start. Emit the shorter one, advance the longer.
                        if a.end.offset <= b.end.offset {
                            self.current_a = None;
                            if a.end.offset < b.end.offset {
                                self.current_b = Some(AddressRange::new(
                                    Address::new(a.end.offset + 1),
                                    b.end,
                                ));
                            } else {
                                self.current_b = None;
                            }
                            Some(a)
                        } else {
                            self.current_b = None;
                            self.current_a = Some(AddressRange::new(
                                Address::new(b.end.offset + 1),
                                a.end,
                            ));
                            Some(b)
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ProgramMemoryComparator
// ---------------------------------------------------------------------------

/// Compares the memory address sets of two programs and determines
/// which addresses are shared, which are exclusive to each program,
/// and which initialized memory overlaps.
///
/// Ported from `ghidra.program.util.ProgramMemoryComparator`.
#[derive(Debug)]
pub struct ProgramMemoryComparator {
    /// Addresses of initialized memory in both programs.
    init_in_both: AddressSet,
    /// Addresses with the same memory type in both programs.
    same_type_in_both: AddressSet,
    /// Addresses present in both programs (any type).
    in_both: AddressSet,
    /// Addresses only in program one.
    only_in_one: AddressSet,
    /// Addresses only in program two.
    only_in_two: AddressSet,
}

impl ProgramMemoryComparator {
    /// Compare two programs' memory layouts.
    ///
    /// Returns `Err` if the programs cannot be compared (null or conflicting address spaces).
    pub fn new(program_a: &Program, program_b: &Program) -> Result<Self, ProgramConflictException> {
        if program_a.language.processor != program_b.language.processor
            || program_a.language.variant != program_b.language.variant
            || program_a.language.size != program_b.language.size
        {
            return Err(ProgramConflictException {
                address: Address::new(0),
                message: format!(
                    "Address spaces conflict between {} and {}.",
                    program_a.name, program_b.name
                ),
            });
        }

        Ok(Self::compute(program_a, program_b))
    }

    fn compute(program_a: &Program, program_b: &Program) -> Self {
        let mem_a = &program_a.memory;
        let mem_b = &program_b.memory;

        let in_both = mem_a.intersect(mem_b);
        let only_in_a = {
            let mut s = mem_a.clone();
            s.delete(&in_both);
            s
        };
        let only_in_b = {
            let mut s = mem_b.clone();
            s.delete(&in_both);
            s
        };

        // For initialized memory, use the full memory sets (the Program model
        // only tracks initialized addresses).
        let init_in_both = in_both.clone();
        let same_type_in_both = init_in_both.clone();

        Self {
            init_in_both,
            same_type_in_both,
            in_both,
            only_in_one: only_in_a,
            only_in_two: only_in_b,
        }
    }

    /// Check whether two programs are similar (same language or address spaces).
    pub fn similar_programs(program_a: &Program, program_b: &Program) -> bool {
        program_a.language.processor == program_b.language.processor
            && program_a.language.variant == program_b.language.variant
            && program_a.language.size == program_b.language.size
    }

    /// Get the combined address set from both programs.
    pub fn combined_addresses(program_a: &Program, program_b: &Program) -> AddressSet {
        program_a.memory.union(&program_b.memory)
    }

    /// Addresses in common between both programs.
    pub fn addresses_in_common(&self) -> &AddressSet {
        &self.in_both
    }

    /// Initialized addresses in common.
    pub fn initialized_in_common(&self) -> &AddressSet {
        &self.init_in_both
    }

    /// Addresses with the same memory type in common.
    pub fn same_type_in_common(&self) -> &AddressSet {
        &self.same_type_in_both
    }

    /// Addresses only in program one.
    pub fn addresses_only_in_one(&self) -> &AddressSet {
        &self.only_in_one
    }

    /// Addresses only in program two.
    pub fn addresses_only_in_two(&self) -> &AddressSet {
        &self.only_in_two
    }

    /// Whether the two programs have any memory differences.
    pub fn has_memory_differences(&self) -> bool {
        !self.only_in_one.is_empty() || !self.only_in_two.is_empty()
    }
}

// ---------------------------------------------------------------------------
// ProgramMergeManager
// ---------------------------------------------------------------------------

/// Manages merging of differences between two programs.
///
/// Program1 is the program being modified by the merge. Program2 is the source
/// for obtaining differences to apply to program1.
///
/// Ported from `ghidra.program.util.ProgramMergeManager`.
#[derive(Debug)]
pub struct ProgramMergeManager {
    /// The first program (modified by merge).
    program1: Program,
    /// The second program (source of differences).
    program2: Program,
    /// The diff filter controlling which categories are compared.
    diff_filter: ProgramDiffFilter,
    /// The merge filter controlling which categories are merged.
    merge_filter: ProgramMergeFilter,
    /// Error messages accumulated during merge.
    error_messages: Vec<String>,
    /// Informational messages accumulated during merge.
    info_messages: Vec<String>,
}

impl ProgramMergeManager {
    /// Create a new merge manager for two programs.
    pub fn new(program1: Program, program2: Program) -> Self {
        Self {
            program1,
            program2,
            diff_filter: ProgramDiffFilter::all(),
            merge_filter: ProgramMergeFilter::new(),
            error_messages: Vec::new(),
            info_messages: Vec::new(),
        }
    }

    /// Get the first program (the one being modified).
    pub fn program_one(&self) -> &Program {
        &self.program1
    }

    /// Get the second program (the source of differences).
    pub fn program_two(&self) -> &Program {
        &self.program2
    }

    /// Get a reference to the current diff filter.
    pub fn diff_filter(&self) -> &ProgramDiffFilter {
        &self.diff_filter
    }

    /// Set the diff filter.
    pub fn set_diff_filter(&mut self, filter: ProgramDiffFilter) {
        self.diff_filter = filter;
    }

    /// Get a reference to the current merge filter.
    pub fn merge_filter(&self) -> &ProgramMergeFilter {
        &self.merge_filter
    }

    /// Set the merge filter.
    pub fn set_merge_filter(&mut self, filter: ProgramMergeFilter) {
        self.merge_filter = filter;
    }

    /// Whether the memory layouts of the two programs match.
    pub fn memory_matches(&self) -> bool {
        ProgramMemoryComparator::similar_programs(&self.program1, &self.program2)
    }

    /// Get the combined addresses from both programs.
    pub fn combined_addresses(&self) -> AddressSet {
        ProgramMemoryComparator::combined_addresses(&self.program1, &self.program2)
    }

    /// Get the addresses in common between both programs.
    pub fn addresses_in_common(&self) -> AddressSet {
        self.program1.memory.intersect(&self.program2.memory)
    }

    /// Get addresses only in program one.
    pub fn addresses_only_in_one(&self) -> AddressSet {
        let in_both = self.program1.memory.intersect(&self.program2.memory);
        let mut only = self.program1.memory.clone();
        only.delete(&in_both);
        only
    }

    /// Get addresses only in program two.
    pub fn addresses_only_in_two(&self) -> AddressSet {
        let in_both = self.program1.memory.intersect(&self.program2.memory);
        let mut only = self.program2.memory.clone();
        only.delete(&in_both);
        only
    }

    /// Get filtered differences between the two programs.
    pub fn get_filtered_differences(&self) -> ProgramDiffReport {
        let addr_set = self.combined_addresses();
        ProgramDiff::full_diff(&self.program1, &self.program2, &addr_set)
    }

    /// Merge functions from program2 into program1 at the specified addresses.
    pub fn merge_functions(&mut self, addr_set: &AddressSet) -> AddressSet {
        ProgramMerge::merge_functions(&mut self.program1, &self.program2, addr_set)
    }

    /// Merge symbols from program2 into program1 at the specified addresses.
    pub fn merge_symbols(&mut self, addr_set: &AddressSet) -> AddressSet {
        ProgramMerge::merge_symbols(&mut self.program1, &self.program2, addr_set)
    }

    /// Perform a full merge based on the current merge filter.
    pub fn merge_all(&mut self) -> AddressSet {
        let mut merged = AddressSet::new();
        let addr_set = self.addresses_in_common();

        if self.merge_filter.should_merge(DiffCategory::Functions) {
            let result = self.merge_functions(&addr_set);
            for range in result.iter() {
                merged.add_range(*range);
            }
        }

        if self.merge_filter.should_merge(DiffCategory::Labels) {
            let result = self.merge_symbols(&addr_set);
            for range in result.iter() {
                merged.add_range(*range);
            }
        }

        merged
    }

    /// Get accumulated error messages.
    pub fn error_messages(&self) -> &[String] {
        &self.error_messages
    }

    /// Get accumulated informational messages.
    pub fn info_messages(&self) -> &[String] {
        &self.info_messages
    }

    /// Clear all accumulated messages.
    pub fn clear_messages(&mut self) {
        self.error_messages.clear();
        self.info_messages.clear();
    }
}

// ---------------------------------------------------------------------------
// DiffUtility
// ---------------------------------------------------------------------------

/// Utility functions for getting and creating objects in one program based on
/// objects from another program.
///
/// Ported from `ghidra.program.util.DiffUtility`.
pub struct DiffUtility;

impl DiffUtility {
    /// Convert an address set from one program to a compatible address set in
    /// the other program. For the simplified model this returns the same set
    /// since both programs share the same address space.
    pub fn get_compatible_address_set(addr_set: &AddressSet, _other_program: &Program) -> AddressSet {
        addr_set.clone()
    }

    /// Get a compatible memory address in another program.
    pub fn get_compatible_memory_address(
        addr: Address,
        _other_program: &Program,
    ) -> Option<Address> {
        Some(addr)
    }

    /// Get the code-unit-aligned address set for the given address set.
    /// In this simplified model, returns the same set.
    pub fn get_code_unit_set(addr_set: &AddressSet, _program: &Program) -> AddressSet {
        addr_set.clone()
    }

    /// Compare addresses from two different programs.
    pub fn compare(
        _program1: &Program,
        addr1: Address,
        _program2: &Program,
        addr2: Address,
    ) -> std::cmp::Ordering {
        addr1.offset.cmp(&addr2.offset)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::analyzer::{Function, Language};

    fn make_program(name: &str) -> Program {
        Program::new(name, Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        })
    }

    #[test]
    fn test_program_diff_report() {
        let mut report = ProgramDiffReport::new();
        assert!(report.is_empty());
        assert_eq!(report.num_differences(), 0);

        report.add_difference(Address::new(0x1000), DiffCategory::MemoryBytes);
        report.add_difference(Address::new(0x1001), DiffCategory::MemoryBytes);
        report.add_difference(Address::new(0x2000), DiffCategory::Labels);

        assert!(!report.is_empty());
        assert_eq!(report.num_differences(), 3);

        let mem_set = report.get_category_set(DiffCategory::MemoryBytes).unwrap();
        assert!(mem_set.contains(&Address::new(0x1000)));
        assert!(mem_set.contains(&Address::new(0x1001)));
        assert!(!mem_set.contains(&Address::new(0x2000)));

        let label_set = report.get_category_set(DiffCategory::Labels).unwrap();
        assert!(label_set.contains(&Address::new(0x2000)));
    }

    #[test]
    fn test_program_diff_report_range() {
        let mut report = ProgramDiffReport::new();
        report.add_range(Address::new(0x1000), Address::new(0x100F), DiffCategory::CodeUnits);

        assert_eq!(report.num_differences(), 16);
        let code_set = report.get_category_set(DiffCategory::CodeUnits).unwrap();
        assert!(code_set.contains(&Address::new(0x1005)));
    }

    #[test]
    fn test_program_diff_functions_identical() {
        let mut prog_a = make_program("a");
        let mut prog_b = make_program("b");

        prog_a.function_manager.functions.insert(
            Address::new(0x1000),
            Function { name: Some("main".into()), entry_point: Address::new(0x1000), body: AddressSet::from_range(AddressRange::new(Address::new(0x1000), Address::new(0x10FF))), is_external: false, is_thunk: false, is_inline: false, has_noreturn: false, call_fixup: None },
        );
        prog_b.function_manager.functions.insert(
            Address::new(0x1000),
            Function { name: Some("main".into()), entry_point: Address::new(0x1000), body: AddressSet::from_range(AddressRange::new(Address::new(0x1000), Address::new(0x10FF))), is_external: false, is_thunk: false, is_inline: false, has_noreturn: false, call_fixup: None },
        );

        let report = ProgramDiff::diff_functions(&prog_a, &prog_b);
        assert!(report.is_empty());
    }

    #[test]
    fn test_program_diff_functions_different() {
        let mut prog_a = make_program("a");
        let mut prog_b = make_program("b");

        prog_a.function_manager.functions.insert(
            Address::new(0x1000),
            Function { name: Some("main".into()), entry_point: Address::new(0x1000), body: AddressSet::new(), is_external: false, is_thunk: false, is_inline: false, has_noreturn: false, call_fixup: None },
        );
        prog_b.function_manager.functions.insert(
            Address::new(0x1000),
            Function { name: Some("main2".into()), entry_point: Address::new(0x1000), body: AddressSet::new(), is_external: false, is_thunk: false, is_inline: false, has_noreturn: false, call_fixup: None },
        );

        let report = ProgramDiff::diff_functions(&prog_a, &prog_b);
        assert!(!report.is_empty());
        assert!(report.differences.contains(&Address::new(0x1000)));
    }

    #[test]
    fn test_program_diff_functions_only_in_one() {
        let mut prog_a = make_program("a");
        let prog_b = make_program("b");

        prog_a.function_manager.functions.insert(
            Address::new(0x1000),
            Function { name: Some("main".into()), entry_point: Address::new(0x1000), body: AddressSet::new(), is_external: false, is_thunk: false, is_inline: false, has_noreturn: false, call_fixup: None },
        );

        let report = ProgramDiff::diff_functions(&prog_a, &prog_b);
        assert!(!report.is_empty());
    }

    #[test]
    fn test_memory_diff_identical() {
        let mut prog_a = make_program("a");
        let mut prog_b = make_program("b");

        prog_a.memory.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x1FFF)));
        prog_b.memory.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x1FFF)));

        let mut addr_set = AddressSet::new();
        addr_set.add_range(AddressRange::new(Address::new(0), Address::new(0xFFFF)));

        let diff = MemoryDiff::new(&prog_a, &prog_b, &addr_set);
        assert!(diff.is_identical());
        assert!(!diff.in_both().is_empty());
    }

    #[test]
    fn test_memory_diff_different() {
        let mut prog_a = make_program("a");
        let mut prog_b = make_program("b");

        prog_a.memory.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x1FFF)));
        prog_b.memory.add_range(AddressRange::new(Address::new(0x2000), Address::new(0x2FFF)));

        let mut addr_set = AddressSet::new();
        addr_set.add_range(AddressRange::new(Address::new(0), Address::new(0xFFFF)));

        let diff = MemoryDiff::new(&prog_a, &prog_b, &addr_set);
        assert!(!diff.is_identical());
        assert!(diff.only_in_a().contains(&Address::new(0x1000)));
        assert!(diff.only_in_b().contains(&Address::new(0x2000)));
        assert!(diff.in_both().is_empty());
    }

    #[test]
    fn test_program_merge_filter() {
        let mut filter = ProgramMergeFilter::new();
        assert_eq!(filter.get_action(DiffCategory::MemoryBytes), MergeAction::Skip);
        assert!(!filter.should_merge(DiffCategory::MemoryBytes));

        filter.set_action(DiffCategory::MemoryBytes, MergeAction::Replace);
        assert!(filter.should_merge(DiffCategory::MemoryBytes));
    }

    #[test]
    fn test_program_merge_filter_merge_all() {
        let filter = ProgramMergeFilter::merge_all();
        assert!(filter.should_merge(DiffCategory::MemoryBytes));
        assert!(filter.should_merge(DiffCategory::Labels));
        assert!(filter.should_merge(DiffCategory::Functions));
    }

    #[test]
    fn test_program_merge_filter_skip_all() {
        let filter = ProgramMergeFilter::skip_all();
        assert!(!filter.should_merge(DiffCategory::MemoryBytes));
        assert!(!filter.should_merge(DiffCategory::Labels));
    }

    #[test]
    fn test_symbolic_propagator() {
        let mut prop = SymbolicPropagator::new();

        prop.set_register_value(Address::new(0x1000), "EAX", 42);
        assert_eq!(prop.get_register_value(Address::new(0x1000), "EAX"), Some(42));
        assert_eq!(prop.get_register_value(Address::new(0x1000), "EBX"), None);
        assert_eq!(prop.get_register_value(Address::new(0x1001), "EAX"), None);

        let values = prop.values_at(Address::new(0x1000));
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], ("EAX", 42));
    }

    #[test]
    fn test_symbolic_propagator_propagate() {
        let mut prop = SymbolicPropagator::new();
        prop.propagate_constant(Address::new(0x1000), Address::new(0x100F), "EAX", 100);

        assert_eq!(prop.get_register_value(Address::new(0x1000), "EAX"), Some(100));
        assert_eq!(prop.get_register_value(Address::new(0x100F), "EAX"), Some(100));
        assert_eq!(prop.get_register_value(Address::new(0x1010), "EAX"), None);
    }

    #[test]
    fn test_symbolic_propagator_assignment() {
        let mut prop = SymbolicPropagator::new();
        prop.add_assignment(ValueAssignment {
            address: Address::new(0x2000),
            target: "ESP".into(),
            value: Some(0x7FFF0000),
        });

        let assignment = prop.get_assignment(Address::new(0x2000)).unwrap();
        assert_eq!(assignment.target, "ESP");
        assert_eq!(assignment.value, Some(0x7FFF0000));
    }

    #[test]
    fn test_address_iterator_converter() {
        let converter = AddressIteratorConverter::new(0x1000);
        assert_eq!(converter.convert(Address::new(0)), Address::new(0x1000));
        assert_eq!(converter.convert(Address::new(0x500)), Address::new(0x1500));
    }

    #[test]
    fn test_address_iterator_converter_set() {
        let converter = AddressIteratorConverter::new(0x10000);
        let mut set = AddressSet::new();
        set.add_range(AddressRange::new(Address::new(0), Address::new(0xFF)));

        let converted = converter.convert_set(&set);
        assert!(converted.contains(&Address::new(0x10000)));
        assert!(converted.contains(&Address::new(0x100FF)));
        assert!(!converted.contains(&Address::new(0x1000)));
    }

    #[test]
    fn test_multi_address_range_iterator() {
        let mut set_a = AddressSet::new();
        set_a.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x1FFF)));
        let mut set_b = AddressSet::new();
        set_b.add_range(AddressRange::new(Address::new(0x5000), Address::new(0x5FFF)));

        let iter = MultiAddressRangeIterator::new(&[&set_a, &set_b]);
        let ranges: Vec<AddressRange> = iter.collect();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start.offset, 0x1000);
        assert_eq!(ranges[1].start.offset, 0x5000);
    }

    #[test]
    fn test_function_utility() {
        let mut program = make_program("test");
        program.function_manager.functions.insert(
            Address::new(0x1000),
            Function { name: Some("main".into()), entry_point: Address::new(0x1000), body: AddressSet::new(), is_external: false, is_thunk: false, is_inline: false, has_noreturn: false, call_fixup: None },
        );
        program.function_manager.functions.insert(
            Address::new(0x2000),
            Function { name: Some("helper".into()), entry_point: Address::new(0x2000), body: AddressSet::new(), is_external: false, is_thunk: false, is_inline: false, has_noreturn: false, call_fixup: None },
        );

        assert_eq!(FunctionUtility::function_count(&program), 2);
        assert!(FunctionUtility::is_function_start(&program, Address::new(0x1000)));
        assert!(!FunctionUtility::is_function_start(&program, Address::new(0x1500)));

        let entries = FunctionUtility::function_entry_points(&program);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_function_merge() {
        let mut body_a = AddressSet::new();
        body_a.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x1FFF)));
        let mut body_b = AddressSet::new();
        body_b.add_range(AddressRange::new(Address::new(0x2000), Address::new(0x2FFF)));

        let merged = FunctionMerge::merge_bodies(&body_a, &body_b);
        assert!(merged.contains(&Address::new(0x1000)));
        assert!(merged.contains(&Address::new(0x2000)));

        let intersected = FunctionMerge::intersect_bodies(&body_a, &body_a);
        assert_eq!(intersected.num_addresses(), body_a.num_addresses());
    }

    #[test]
    fn test_string_searcher() {
        let searcher = StringSearcher::new(3);
        let data = b"hello\x00world\x00ab\x00";
        let results = searcher.search(data, Address::new(0));

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].value, "hello");
        assert_eq!(results[0].address.offset, 0);
        assert_eq!(results[0].length, 6);
        assert!(results[0].is_null_terminated);

        assert_eq!(results[1].value, "world");
        assert_eq!(results[1].address.offset, 6);
    }

    #[test]
    fn test_string_searcher_min_length() {
        let data = b"hi\x00toolong\x00";
        let searcher = StringSearcher::new(5);
        let results = searcher.search(data, Address::new(0));

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "toolong");
    }

    #[test]
    fn test_interior_selection() {
        let sel = InteriorSelection::new(Address::new(0x100), Address::new(0x100));
        assert!(sel.is_empty());

        let sel = InteriorSelection::new(Address::new(0x100), Address::new(0x200));
        assert!(!sel.is_empty());
    }

    #[test]
    fn test_default_address_translator() {
        let translator = DefaultAddressTranslator::new(0, 0x10000);

        assert_eq!(translator.translate(Address::new(0)), Address::new(0x10000));
        assert_eq!(translator.translate(Address::new(0x100)), Address::new(0x10100));
        assert_eq!(
            translator.reverse_translate(Address::new(0x10000)),
            Address::new(0)
        );
        assert_eq!(
            translator.reverse_translate(Address::new(0x10100)),
            Address::new(0x100)
        );
    }

    #[test]
    fn test_program_memory_util() {
        let mut program = make_program("test");
        assert!(!ProgramMemoryUtil::has_memory(&program));

        program.memory.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x1FFF)));
        assert!(ProgramMemoryUtil::has_memory(&program));
        assert_eq!(ProgramMemoryUtil::total_initialized_bytes(&program), 0x1000);
    }

    #[test]
    fn test_external_symbol_resolver() {
        let mut program = make_program("test");
        program.symbols.insert(Address::new(0x100), "printf".into());
        program.symbols.insert(Address::new(0x200), "malloc".into());

        assert_eq!(
            ExternalSymbolResolver::find_symbol(&program, "printf"),
            Some(Address::new(0x100))
        );
        assert_eq!(
            ExternalSymbolResolver::find_symbol(&program, "missing"),
            None
        );

        let all = ExternalSymbolResolver::get_all_symbols(&program);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_found_string() {
        let fs = FoundString::new(Address::new(0x1000), 6, "hello".into(), true, 1);
        assert_eq!(fs.address.offset, 0x1000);
        assert_eq!(fs.length, 6);
        assert!(fs.is_null_terminated);
        assert_eq!(fs.char_size, 1);
    }

    #[test]
    fn test_program_diff_labels() {
        let mut prog_a = make_program("a");
        let mut prog_b = make_program("b");

        prog_a.symbols.insert(Address::new(0x1000), "main".into());
        prog_b.symbols.insert(Address::new(0x1000), "main_renamed".into());

        let mut addr_set = AddressSet::new();
        addr_set.add(Address::new(0x1000));

        let report = ProgramDiff::diff_labels(&prog_a, &prog_b, &addr_set);
        assert!(!report.is_empty());
        assert!(report.differences.contains(&Address::new(0x1000)));
    }

    #[test]
    fn test_memory_range_diff() {
        let mut prog_a = make_program("a");
        prog_a.memory.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x1FFF)));

        let prog_b = make_program("b");

        let range = AddressRange::new(Address::new(0x1000), Address::new(0x100F));
        let diff = MemoryRangeDiff::new(&prog_a, &prog_b, range);
        assert!(diff.in_program_a);
        assert!(!diff.in_program_b);
        assert!(!diff.is_identical());
    }

    #[test]
    fn test_program_memory_util_common() {
        let mut prog_a = make_program("a");
        let mut prog_b = make_program("b");

        prog_a.memory.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x1FFF)));
        prog_b.memory.add_range(AddressRange::new(Address::new(0x1500), Address::new(0x2500)));

        let common = ProgramMemoryUtil::common_address_set(&prog_a, &prog_b);
        assert!(common.contains(&Address::new(0x1500)));
        assert!(common.contains(&Address::new(0x1FFF)));
        assert!(!common.contains(&Address::new(0x1000)));
    }

    #[test]
    fn test_program_selection() {
        let sel = ProgramSelection::new();
        assert!(sel.is_empty());

        let sel = ProgramSelection::from_range(Address::new(0x1000), Address::new(0x2000));
        assert!(!sel.is_empty());
        assert!(sel.contains(&Address::new(0x1500)));
        assert!(!sel.contains(&Address::new(0x3000)));
        assert_eq!(sel.num_addresses(), 0x1001);

        // Reversed range should work
        let sel = ProgramSelection::from_range(Address::new(0x2000), Address::new(0x1000));
        assert!(sel.contains(&Address::new(0x1500)));
    }

    #[test]
    fn test_program_selection_from_address_set() {
        let mut set = AddressSet::new();
        set.add_range(AddressRange::new(Address::new(0x100), Address::new(0x200)));
        let sel = ProgramSelection::from_address_set(set);
        assert!(sel.contains(&Address::new(0x150)));
    }

    #[test]
    fn test_program_selection_clear() {
        let mut sel = ProgramSelection::from_range(Address::new(0x1000), Address::new(0x2000));
        assert!(!sel.is_empty());
        sel.clear();
        assert!(sel.is_empty());
    }

    #[test]
    fn test_varnode_context() {
        let mut ctx = VarnodeContext::new();
        assert_eq!(ctx.get_register("EAX"), None);

        ctx.set_register("EAX", 0x1234);
        assert_eq!(ctx.get_register("EAX"), Some(0x1234));

        ctx.set_memory(0x401000, 0x42);
        assert_eq!(ctx.get_memory(0x401000), Some(0x42));

        ctx.set_unique(1, 99);
        assert_eq!(ctx.get_unique(1), Some(99));

        // Flow tracking
        ctx.add_flow(0x401000, 0x401005);
        ctx.add_flow(0x401000, 0x402000);
        assert_eq!(ctx.flow_targets(0x401000).len(), 2);
        assert_eq!(ctx.flow_targets(0x402000).len(), 0);
    }

    #[test]
    fn test_varnode_context_save_restore() {
        let mut ctx = VarnodeContext::new();
        ctx.set_register("EAX", 100);
        assert_eq!(ctx.saved_state_depth(), 0);

        ctx.save_state();
        assert_eq!(ctx.saved_state_depth(), 1);

        ctx.set_register("EAX", 200);
        assert_eq!(ctx.get_register("EAX"), Some(200));

        assert!(ctx.restore_state());
        assert_eq!(ctx.get_register("EAX"), Some(100));
        assert_eq!(ctx.saved_state_depth(), 0);

        // Restore on empty stack returns false
        assert!(!ctx.restore_state());
    }

    #[test]
    fn test_varnode_context_remove_register() {
        let mut ctx = VarnodeContext::new();
        ctx.set_register("EAX", 42);
        assert_eq!(ctx.remove_register("EAX"), Some(42));
        assert_eq!(ctx.get_register("EAX"), None);
    }

    #[test]
    fn test_default_context_evaluator() {
        let evaluator = DefaultContextEvaluator;
        let state = HashMap::new();
        assert_eq!(
            evaluator.evaluate_context_before(Address::new(0x1000), &state),
            EvalAction::Continue
        );
        assert_eq!(
            evaluator.evaluate_context(Address::new(0x1000), &state),
            EvalAction::Continue
        );
    }

    #[test]
    fn test_eval_action_variants() {
        assert_ne!(EvalAction::Continue, EvalAction::Stop);
        assert_ne!(EvalAction::Continue, EvalAction::Skip);
        assert_ne!(EvalAction::Stop, EvalAction::Skip);
    }

    #[test]
    fn test_ghidra_program_utilities() {
        let mut prog = make_program("test");
        // No functions -> should ask to analyze
        assert!(GhidraProgramUtilities::should_ask_to_analyze(&prog));

        prog.function_manager.functions.insert(
            Address::new(0x1000),
            Function {
                name: Some("main".into()),
                entry_point: Address::new(0x1000),
                body: AddressSet::new(),
                is_external: false,
                is_thunk: false,
                is_inline: false,
                has_noreturn: false,
                call_fixup: None,
            },
        );
        assert!(!GhidraProgramUtilities::should_ask_to_analyze(&prog));
    }

    #[test]
    fn test_listing_diff() {
        let prog_a = make_program("a");
        let prog_b = make_program("b");

        let mut addr_set = AddressSet::new();
        addr_set.add(Address::new(0x1000));

        let diff = ListingDiff::new();
        let report = diff.diff(&prog_a, &prog_b, &addr_set);
        // Both have no symbols, so diff should be empty
        assert!(report.is_empty());
    }

    #[test]
    fn test_marker_location() {
        let marker = MarkerLocation::new(
            Address::new(0x401000),
            "Bookmark",
            "Important location",
            "TestPlugin",
        );
        assert_eq!(marker.address.offset, 0x401000);
        assert_eq!(marker.marker_type, "Bookmark");
        let display = format!("{}", marker);
        assert!(display.contains("Bookmark"));
        assert!(display.contains("401000"));
    }

    #[test]
    fn test_group_view() {
        let mut gv = GroupView::new();
        assert_eq!(gv.group_count(), 0);

        let mut group = AddressGroup::new("text");
        group.addresses.add_range(AddressRange::new(Address::new(0x401000), Address::new(0x401FFF)));
        gv.add_group(group);

        assert_eq!(gv.group_count(), 1);
        assert!(gv.group_for_address(&Address::new(0x401500)).is_some());
        assert!(gv.group_for_address(&Address::new(0x500000)).is_none());
    }

    #[test]
    fn test_program_conflict_exception() {
        let err = ProgramConflictException {
            address: Address::new(0x401000),
            message: "Overlapping block".to_string(),
        };
        let display = format!("{}", err);
        assert!(display.contains("401000"));
        assert!(display.contains("Overlapping block"));
    }

    #[test]
    fn test_program_diff_filter() {
        let filter = ProgramDiffFilter::all();
        assert!(filter.should_diff(DiffCategory::Labels));
        assert!(filter.should_diff(DiffCategory::Functions));

        let mut filter = ProgramDiffFilter::none();
        assert!(!filter.should_diff(DiffCategory::Labels));
        filter.set_diff(DiffCategory::Labels, true);
        assert!(filter.should_diff(DiffCategory::Labels));
    }

    #[test]
    fn test_program_merge_functions() {
        let mut dest = make_program("dest");
        let mut source = make_program("source");
        source.function_manager.functions.insert(
            Address::new(0x1000),
            Function {
                name: Some("main".into()),
                entry_point: Address::new(0x1000),
                body: AddressSet::new(),
                is_external: false,
                is_thunk: false,
                is_inline: false,
                has_noreturn: false,
                call_fixup: None,
            },
        );

        let mut addr_set = AddressSet::new();
        addr_set.add(Address::new(0x1000));

        let merged = ProgramMerge::merge_functions(&mut dest, &source, &addr_set);
        assert!(!merged.is_empty());
        assert!(dest.function_manager.functions.contains_key(&Address::new(0x1000)));
    }

    // --- Tests for newly added types ---

    #[test]
    fn test_memory_block_diff_identical() {
        let block = MemoryBlockDesc::new(".text", 0x401000, 0x401FFF);
        let diff = MemoryBlockDiff::new(Some(&block), Some(&block));
        assert!(!diff.has_differences());
        assert!(!diff.is_name_different());
        assert!(!diff.is_start_address_different());
        assert!(!diff.is_end_address_different());
        assert!(!diff.is_size_different());
        assert!(!diff.is_read_different());
        assert!(!diff.is_write_different());
        assert!(!diff.is_exec_different());
        assert_eq!(diff.flags(), 0);
    }

    #[test]
    fn test_memory_block_diff_all_different() {
        let mut block1 = MemoryBlockDesc::new(".text", 0x401000, 0x401FFF);
        block1.write = false;
        block1.execute = true;
        block1.block_type = "DEFAULT".into();

        let mut block2 = MemoryBlockDesc::new(".code", 0x402000, 0x402FFF);
        block2.write = true;
        block2.execute = false;
        block2.block_type = "OVERLAY".into();

        let diff = MemoryBlockDiff::new(Some(&block1), Some(&block2));
        assert!(diff.has_differences());
        assert!(diff.is_name_different());
        assert!(diff.is_start_address_different());
        assert!(diff.is_end_address_different());
        assert!(!diff.is_size_different()); // both blocks are the same size (0x1000)
        assert!(diff.is_write_different());
        assert!(diff.is_exec_different());
        assert!(diff.is_type_different());
    }

    #[test]
    fn test_memory_block_diff_none_blocks() {
        let diff = MemoryBlockDiff::new(None, None);
        assert!(!diff.has_differences());
    }

    #[test]
    fn test_memory_block_diff_one_none() {
        let block = MemoryBlockDesc::new(".text", 0x401000, 0x401FFF);
        let diff = MemoryBlockDiff::new(Some(&block), None);
        assert!(diff.has_differences());
        assert_eq!(diff.flags(), memory_block_flags::ALL);
    }

    #[test]
    fn test_memory_block_diff_permissions() {
        let mut block1 = MemoryBlockDesc::new(".text", 0x401000, 0x401FFF);
        block1.read = true;
        block1.write = false;
        block1.volatile = false;

        let mut block2 = MemoryBlockDesc::new(".text", 0x401000, 0x401FFF);
        block2.read = true;
        block2.write = true;
        block2.volatile = true;

        let diff = MemoryBlockDiff::new(Some(&block1), Some(&block2));
        assert!(!diff.is_read_different());
        assert!(diff.is_write_different());
        assert!(diff.is_volatile_different());
        assert!(!diff.is_name_different());
    }

    #[test]
    fn test_memory_block_diff_differences_string() {
        let mut block1 = MemoryBlockDesc::new(".text", 0x401000, 0x401FFF);
        block1.write = false;

        let mut block2 = MemoryBlockDesc::new(".data", 0x401000, 0x401FFF);
        block2.write = true;

        let diff = MemoryBlockDiff::new(Some(&block1), Some(&block2));
        let s = diff.differences_as_string();
        assert!(s.contains("Name"));
        assert!(s.contains("W"));
    }

    #[test]
    fn test_multi_address_iterator_forward() {
        let mut set_a = AddressSet::new();
        set_a.add(Address::new(0x1000));
        set_a.add(Address::new(0x1002));

        let mut set_b = AddressSet::new();
        set_b.add(Address::new(0x1001));
        set_b.add(Address::new(0x1003));

        let mut iter = MultiAddressIterator::new(&[&set_a, &set_b], true);
        assert!(iter.has_next());
        assert_eq!(iter.next(), Some(Address::new(0x1000)));
        assert_eq!(iter.next(), Some(Address::new(0x1001)));
        assert_eq!(iter.next(), Some(Address::new(0x1002)));
        assert_eq!(iter.next(), Some(Address::new(0x1003)));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_multi_address_iterator_backward() {
        let mut set_a = AddressSet::new();
        set_a.add(Address::new(0x1000));
        set_a.add(Address::new(0x1002));

        let mut set_b = AddressSet::new();
        set_b.add(Address::new(0x1001));
        set_b.add(Address::new(0x1003));

        let mut iter = MultiAddressIterator::new(&[&set_a, &set_b], false);
        assert_eq!(iter.next(), Some(Address::new(0x1003)));
        assert_eq!(iter.next(), Some(Address::new(0x1002)));
        assert_eq!(iter.next(), Some(Address::new(0x1001)));
        assert_eq!(iter.next(), Some(Address::new(0x1000)));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_multi_address_iterator_duplicate_addresses() {
        let mut set_a = AddressSet::new();
        set_a.add(Address::new(0x1000));

        let mut set_b = AddressSet::new();
        set_b.add(Address::new(0x1000));

        let mut iter = MultiAddressIterator::new(&[&set_a, &set_b], true);
        // Both sources have 0x1000, next() should return it once
        assert_eq!(iter.next(), Some(Address::new(0x1000)));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_multi_address_iterator_next_addresses() {
        let mut set_a = AddressSet::new();
        set_a.add(Address::new(0x1000));

        let mut set_b = AddressSet::new();
        set_b.add(Address::new(0x1000));

        let mut iter = MultiAddressIterator::new(&[&set_a, &set_b], true);
        let addrs = iter.next_addresses();
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], Some(Address::new(0x1000)));
        assert_eq!(addrs[1], Some(Address::new(0x1000)));
    }

    #[test]
    fn test_multi_address_iterator_empty() {
        let set_a = AddressSet::new();
        let set_b = AddressSet::new();

        let mut iter = MultiAddressIterator::new(&[&set_a, &set_b], true);
        assert!(!iter.has_next());
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_address_translation_exception() {
        let err = AddressTranslationException::new("cannot translate");
        assert_eq!(err.message, "cannot translate");
        assert!(err.address.is_none());
        let display = format!("{}", err);
        assert!(display.contains("cannot translate"));
    }

    #[test]
    fn test_address_translation_exception_with_address() {
        let err = AddressTranslationException::with_address(
            Address::new(0x401000),
            "program1",
            "program2",
        );
        assert!(err.address.is_some());
        assert_eq!(err.address.unwrap().offset, 0x401000);
        assert!(err.message.contains("401000"));
        assert!(err.message.contains("program1"));
        assert!(err.message.contains("program2"));
    }

    #[test]
    fn test_offset_address_translator() {
        let translator = OffsetAddressTranslator::new("src", "dst", 0x10000);
        assert_eq!(translator.source_program(), "src");
        assert_eq!(translator.destination_program(), "dst");
        assert!(translator.is_one_for_one());

        let addr = translator.get_address(Address::new(0x100)).unwrap();
        assert_eq!(addr.offset, 0x10100);

        let addr2 = translator.get_address(Address::new(0)).unwrap();
        assert_eq!(addr2.offset, 0x10000);
    }

    #[test]
    fn test_offset_address_translator_range() {
        let translator = OffsetAddressTranslator::new("src", "dst", 0x10000);
        let range = AddressRange::new(Address::new(0x100), Address::new(0x200));
        let translated = translator.get_address_range(&range).unwrap();
        assert_eq!(translated.start.offset, 0x10100);
        assert_eq!(translated.end.offset, 0x10200);
    }

    #[test]
    fn test_offset_address_translator_set() {
        let translator = OffsetAddressTranslator::new("src", "dst", 0x10000);
        let mut set = AddressSet::new();
        set.add_range(AddressRange::new(Address::new(0x100), Address::new(0x1FF)));

        let translated = translator.get_address_set(&set).unwrap();
        assert!(translated.contains(&Address::new(0x10100)));
        assert!(translated.contains(&Address::new(0x101FF)));
        assert!(!translated.contains(&Address::new(0x100)));
    }

    #[test]
    fn test_multi_code_unit_iterator() {
        let cu1 = vec![
            CodeUnitInfo { address: Address::new(0x1000), mnemonic: "MOV".into(), size: 2 },
            CodeUnitInfo { address: Address::new(0x1002), mnemonic: "ADD".into(), size: 3 },
        ];
        let cu2 = vec![
            CodeUnitInfo { address: Address::new(0x1001), mnemonic: "NOP".into(), size: 1 },
            CodeUnitInfo { address: Address::new(0x1002), mnemonic: "SUB".into(), size: 3 },
        ];

        let mut iter = MultiCodeUnitIterator::new(vec![cu1, cu2], true);
        assert!(iter.has_next());

        // First: address 0x1000 from source 0 only
        let batch = iter.next_code_units();
        assert!(batch[0].is_some());
        assert!(batch[1].is_none());
        assert_eq!(batch[0].as_ref().unwrap().address.offset, 0x1000);

        // Second: address 0x1001 from source 1 only
        let batch = iter.next_code_units();
        assert!(batch[0].is_none());
        assert!(batch[1].is_some());
        assert_eq!(batch[1].as_ref().unwrap().address.offset, 0x1001);

        // Third: address 0x1002 from both sources
        let batch = iter.next_code_units();
        assert!(batch[0].is_some());
        assert!(batch[1].is_some());
        assert_eq!(batch[0].as_ref().unwrap().mnemonic, "ADD");
        assert_eq!(batch[1].as_ref().unwrap().mnemonic, "SUB");

        assert!(!iter.has_next());
    }

    #[test]
    fn test_combined_address_range_iterator_no_overlap() {
        let mut set_a = AddressSet::new();
        set_a.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x1FFF)));
        let mut set_b = AddressSet::new();
        set_b.add_range(AddressRange::new(Address::new(0x3000), Address::new(0x3FFF)));

        let mut iter = CombinedAddressRangeIterator::new(&set_a, &set_b);
        let r1 = iter.next_range().unwrap();
        assert_eq!(r1.start.offset, 0x1000);
        assert_eq!(r1.end.offset, 0x1FFF);
        let r2 = iter.next_range().unwrap();
        assert_eq!(r2.start.offset, 0x3000);
        assert_eq!(r2.end.offset, 0x3FFF);
        assert!(iter.next_range().is_none());
    }

    #[test]
    fn test_combined_address_range_iterator_full_overlap() {
        let mut set_a = AddressSet::new();
        set_a.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x2000)));
        let mut set_b = AddressSet::new();
        set_b.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x2000)));

        let mut iter = CombinedAddressRangeIterator::new(&set_a, &set_b);
        let r1 = iter.next_range().unwrap();
        assert_eq!(r1.start.offset, 0x1000);
        assert_eq!(r1.end.offset, 0x2000);
        assert!(iter.next_range().is_none());
    }

    #[test]
    fn test_combined_address_range_iterator_partial_overlap() {
        let mut set_a = AddressSet::new();
        set_a.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x2000)));
        let mut set_b = AddressSet::new();
        set_b.add_range(AddressRange::new(Address::new(0x1800), Address::new(0x2800)));

        let mut iter = CombinedAddressRangeIterator::new(&set_a, &set_b);
        let ranges: Vec<AddressRange> = std::iter::from_fn(|| iter.next_range()).collect();
        // Should have: [0x1000,0x17FF], [0x1800,0x2000], [0x2001,0x2800]
        assert_eq!(ranges.len(), 3);
        assert_eq!(ranges[0].start.offset, 0x1000);
        assert_eq!(ranges[0].end.offset, 0x17FF);
    }

    #[test]
    fn test_program_memory_comparator() {
        let mut prog_a = make_program("a");
        let mut prog_b = make_program("b");

        prog_a.language = Language { processor: "x86".into(), variant: "LE".into(), size: 64 };
        prog_b.language = Language { processor: "x86".into(), variant: "LE".into(), size: 64 };

        prog_a.memory.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x1FFF)));
        prog_b.memory.add_range(AddressRange::new(Address::new(0x1800), Address::new(0x2FFF)));

        let comparator = ProgramMemoryComparator::new(&prog_a, &prog_b).unwrap();

        assert!(comparator.has_memory_differences());
        assert!(comparator.addresses_in_common().contains(&Address::new(0x1800)));
        assert!(!comparator.addresses_only_in_one().is_empty());
        assert!(!comparator.addresses_only_in_two().is_empty());
    }

    #[test]
    fn test_program_memory_comparator_identical() {
        let mut prog_a = make_program("a");
        let mut prog_b = make_program("b");

        prog_a.memory.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x1FFF)));
        prog_b.memory.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x1FFF)));

        let comparator = ProgramMemoryComparator::new(&prog_a, &prog_b).unwrap();
        assert!(!comparator.has_memory_differences());
        assert!(comparator.addresses_only_in_one().is_empty());
        assert!(comparator.addresses_only_in_two().is_empty());
    }

    #[test]
    fn test_program_memory_comparator_similar() {
        let prog_a = make_program("a");
        let prog_b = make_program("b");
        assert!(ProgramMemoryComparator::similar_programs(&prog_a, &prog_b));
    }

    #[test]
    fn test_program_merge_manager() {
        let mut prog_a = make_program("a");
        let mut prog_b = make_program("b");

        prog_a.memory.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x1FFF)));
        prog_b.memory.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x1FFF)));

        prog_b.function_manager.functions.insert(
            Address::new(0x1000),
            Function {
                name: Some("main".into()),
                entry_point: Address::new(0x1000),
                body: AddressSet::new(),
                is_external: false,
                is_thunk: false,
                is_inline: false,
                has_noreturn: false,
                call_fixup: None,
            },
        );

        let mut manager = ProgramMergeManager::new(prog_a, prog_b);
        assert!(manager.memory_matches());
        assert!(manager.program_one().function_manager.functions.is_empty());
        assert!(!manager.program_two().function_manager.functions.is_empty());

        // Merge with functions enabled
        manager.set_merge_filter(ProgramMergeFilter::merge_all());
        let merged = manager.merge_all();
        assert!(!merged.is_empty());
        assert!(manager.program_one().function_manager.functions.contains_key(&Address::new(0x1000)));
    }

    #[test]
    fn test_program_merge_manager_address_sets() {
        let mut prog_a = make_program("a");
        let mut prog_b = make_program("b");

        prog_a.memory.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x1FFF)));
        prog_b.memory.add_range(AddressRange::new(Address::new(0x1800), Address::new(0x2FFF)));

        let manager = ProgramMergeManager::new(prog_a, prog_b);

        assert!(manager.memory_matches());
        let combined = manager.combined_addresses();
        assert!(combined.contains(&Address::new(0x1000)));
        assert!(combined.contains(&Address::new(0x2FFF)));

        let common = manager.addresses_in_common();
        assert!(common.contains(&Address::new(0x1800)));
        assert!(common.contains(&Address::new(0x1FFF)));

        let only_one = manager.addresses_only_in_one();
        assert!(only_one.contains(&Address::new(0x1000)));
        assert!(!only_one.contains(&Address::new(0x1800)));

        let only_two = manager.addresses_only_in_two();
        assert!(only_two.contains(&Address::new(0x2000)));
        assert!(!only_two.contains(&Address::new(0x1FFF)));
    }

    #[test]
    fn test_diff_utility() {
        let prog_a = make_program("a");
        let prog_b = make_program("b");

        let mut set = AddressSet::new();
        set.add(Address::new(0x1000));
        set.add(Address::new(0x2000));

        let compatible = DiffUtility::get_compatible_address_set(&set, &prog_b);
        assert!(compatible.contains(&Address::new(0x1000)));
        assert!(compatible.contains(&Address::new(0x2000)));

        let addr = DiffUtility::get_compatible_memory_address(Address::new(0x3000), &prog_b);
        assert_eq!(addr, Some(Address::new(0x3000)));

        let ord = DiffUtility::compare(&prog_a, Address::new(0x1000), &prog_b, Address::new(0x2000));
        assert_eq!(ord, std::cmp::Ordering::Less);
    }
}
