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
        let only_in_a = mem_a.clone();
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
}
