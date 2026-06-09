//! Program difference (diff) framework.
//!
//! Ported from Ghidra's `ghidra.program.diff` and
//! `ghidra.app.plugin.core.diff` Java packages.
//!
//! This module provides the ability to compare two programs at various
//! levels of granularity (bytes, code units, symbols, functions, etc.)
//! and produce a set of differences that can be displayed or applied.
//!
//! # Key types
//!
//! - [`ProgramDiffFilter`] -- controls which program aspects to compare
//! - [`DiffResult`] -- a single difference between two programs
//! - [`DiffController`] -- manages diff state, navigation, and apply/ignore
//! - [`ProgramMergeFilter`] -- controls how differences are applied
//! - [`ProgramMemoryComparator`] -- compares memory layouts of two programs
//! - [`DiffService`] -- service interface for launching diffs
//!
//! # Submodules
//!
//! - [`diff_controller`] -- diff controller and address set types
//! - [`diff_service`] -- diff service interface
//! - [`merge_filter`] -- merge filter and merge action types
//! - [`apply_settings`] -- diff apply settings and option management
//! - [`diff_actions`] -- bulk diff actions (ignore all, merge all, replace all)
//! - [`memory_comparator`] -- program memory layout comparison
//! - [`program_diff_plugin`] -- main diff plugin managing providers and events
//! - [`program_diff_filter`] -- advanced filter categories, groups, presets, and builder
//! - [`diff_apply_panel`] -- UI logic for configuring and applying differences

pub mod diff_controller;
pub mod diff_service;
pub mod merge_filter;
pub mod apply_settings;
pub mod diff_actions;
pub mod memory_comparator;
pub mod program_diff_plugin;
pub mod program_diff_filter;
pub mod diff_apply_panel;

use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// ProgramDiffFilter
// ---------------------------------------------------------------------------

/// Flags controlling which aspects of a program are compared.
///
/// Ported from Ghidra's `ProgramDiffFilter` Java class.
///
/// Each flag corresponds to a category of program data that may be
/// included or excluded from the diff comparison. Multiple flags can
/// be combined with bitwise OR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProgramDiffFilter(u32);

impl ProgramDiffFilter {
    /// No filter flags set.
    pub const NONE: Self = Self(0);
    /// Compare program bytes (memory content).
    pub const BYTES: Self = Self(1 << 0);
    /// Compare code units (instructions and data).
    pub const CODE_UNITS: Self = Self(1 << 1);
    /// Compare defined data types.
    pub const DATA_TYPES: Self = Self(1 << 2);
    /// Compare symbols (labels, functions, etc.).
    pub const SYMBOLS: Self = Self(1 << 3);
    /// Compare equates (named constants).
    pub const EQUATES: Self = Self(1 << 4);
    /// Compare bookmarks.
    pub const BOOKMARKS: Self = Self(1 << 5);
    /// Compare comments (plate, pre, end-of-line, repeatable).
    pub const COMMENTS: Self = Self(1 << 6);
    /// Compare function signatures and properties.
    pub const FUNCTIONS: Self = Self(1 << 7);
    /// Compare register variable references.
    pub const REGISTERS: Self = Self(1 << 8);
    /// Compare user-defined properties / settings.
    pub const PROPERTIES: Self = Self(1 << 9);
    /// Compare reference relationships.
    pub const REFERENCES: Self = Self(1 << 10);
    /// Compare memory blocks.
    pub const MEMORY_BLOCKS: Self = Self(1 << 11);
    /// Compare imported/exported external symbols.
    pub const EXTERNALS: Self = Self(1 << 12);
    /// Compare analysis options.
    pub const OPTIONS: Self = Self(1 << 13);
    /// Compare relocation records.
    pub const RELOCATIONS: Self = Self(1 << 14);

    /// All diff filter flags combined.
    pub const ALL: Self = Self(0x7FFF);

    /// Create a filter with no flags set.
    pub const fn empty() -> Self {
        Self::NONE
    }

    /// Create a filter with all flags set.
    pub const fn all() -> Self {
        Self::ALL
    }

    /// Create a filter from a raw bitmask.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Get the raw bitmask.
    pub const fn bits(&self) -> u32 {
        self.0
    }

    /// Check if a flag is set.
    pub const fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Set a flag.
    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    /// Clear a flag.
    pub fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }

    /// Toggle a flag.
    pub fn toggle(&mut self, other: Self) {
        self.0 ^= other.0;
    }

    /// Set or clear a flag based on a boolean.
    pub fn set(&mut self, other: Self, enabled: bool) {
        if enabled {
            self.insert(other);
        } else {
            self.remove(other);
        }
    }

    /// Check if no flags are set.
    pub const fn is_empty(&self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for ProgramDiffFilter {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitAnd for ProgramDiffFilter {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl std::ops::BitOrAssign for ProgramDiffFilter {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl Default for ProgramDiffFilter {
    fn default() -> Self {
        Self::all()
    }
}

// ---------------------------------------------------------------------------
// DiffResult
// ---------------------------------------------------------------------------

/// The type of a program difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiffType {
    /// A byte value changed at an address.
    ByteChanged,
    /// A code unit was added in the second program.
    CodeUnitAdded,
    /// A code unit was removed from the first program.
    CodeUnitRemoved,
    /// A code unit was modified between programs.
    CodeUnitChanged,
    /// A symbol was added.
    SymbolAdded,
    /// A symbol was removed.
    SymbolRemoved,
    /// A symbol was renamed.
    SymbolRenamed,
    /// A data type changed.
    DataTypeChanged,
    /// A comment changed.
    CommentChanged,
    /// A function property changed.
    FunctionChanged,
    /// A reference changed.
    ReferenceChanged,
    /// A bookmark changed.
    BookmarkChanged,
    /// A memory block changed.
    MemoryBlockChanged,
    /// An equate changed.
    EquateChanged,
    /// A property/setting changed.
    PropertyChanged,
}

impl DiffType {
    /// A human-readable label for this diff type.
    pub fn label(&self) -> &'static str {
        match self {
            Self::ByteChanged => "Byte Changed",
            Self::CodeUnitAdded => "Code Unit Added",
            Self::CodeUnitRemoved => "Code Unit Removed",
            Self::CodeUnitChanged => "Code Unit Changed",
            Self::SymbolAdded => "Symbol Added",
            Self::SymbolRemoved => "Symbol Removed",
            Self::SymbolRenamed => "Symbol Renamed",
            Self::DataTypeChanged => "Data Type Changed",
            Self::CommentChanged => "Comment Changed",
            Self::FunctionChanged => "Function Changed",
            Self::ReferenceChanged => "Reference Changed",
            Self::BookmarkChanged => "Bookmark Changed",
            Self::MemoryBlockChanged => "Memory Block Changed",
            Self::EquateChanged => "Equate Changed",
            Self::PropertyChanged => "Property Changed",
        }
    }
}

/// A single difference found between two programs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffResult {
    /// The address where the difference was found.
    pub address: u64,
    /// The type of difference.
    pub diff_type: DiffType,
    /// Optional description of the difference.
    pub description: String,
    /// Value from program 1 (if applicable).
    pub value1: Option<String>,
    /// Value from program 2 (if applicable).
    pub value2: Option<String>,
}

impl DiffResult {
    /// Create a new diff result.
    pub fn new(address: u64, diff_type: DiffType, description: impl Into<String>) -> Self {
        Self {
            address,
            diff_type,
            description: description.into(),
            value1: None,
            value2: None,
        }
    }

    /// Create a diff result with before/after values.
    pub fn with_values(
        address: u64,
        diff_type: DiffType,
        description: impl Into<String>,
        value1: impl Into<String>,
        value2: impl Into<String>,
    ) -> Self {
        Self {
            address,
            diff_type,
            description: description.into(),
            value1: Some(value1.into()),
            value2: Some(value2.into()),
        }
    }
}

impl PartialOrd for DiffResult {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DiffResult {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.address
            .cmp(&other.address)
            .then_with(|| self.diff_type.label().cmp(other.diff_type.label()))
    }
}

// ---------------------------------------------------------------------------
// ProgramDiffer
// ---------------------------------------------------------------------------

/// A simple program representation for diffing.
///
/// In Ghidra proper this would be a full `Program` object; here we use
/// a simplified version that holds addresses, bytes, and basic metadata.
#[derive(Debug, Clone)]
pub struct ProgramSnapshot {
    /// The program name.
    pub name: String,
    /// Memory blocks: name -> (start_address, bytes).
    pub blocks: BTreeMap<String, (u64, Vec<u8>)>,
    /// Symbols: address -> name.
    pub symbols: BTreeMap<u64, String>,
    /// Comments: address -> comment text.
    pub comments: BTreeMap<u64, String>,
}

impl ProgramSnapshot {
    /// Create an empty program snapshot.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            blocks: BTreeMap::new(),
            symbols: BTreeMap::new(),
            comments: BTreeMap::new(),
        }
    }

    /// Add a memory block.
    pub fn add_block(&mut self, name: impl Into<String>, start: u64, data: Vec<u8>) {
        self.blocks.insert(name.into(), (start, data));
    }

    /// Add a symbol.
    pub fn add_symbol(&mut self, address: u64, name: impl Into<String>) {
        self.symbols.insert(address, name.into());
    }

    /// Add a comment.
    pub fn add_comment(&mut self, address: u64, text: impl Into<String>) {
        self.comments.insert(address, text.into());
    }

    /// Get the byte at a given address, searching all blocks.
    pub fn byte_at(&self, address: u64) -> Option<u8> {
        for (_, (start, data)) in &self.blocks {
            let offset = address.wrapping_sub(*start);
            if offset < data.len() as u64 {
                return Some(data[offset as usize]);
            }
        }
        None
    }
}

/// Compare two program snapshots according to the given filter.
pub fn diff_programs(
    prog1: &ProgramSnapshot,
    prog2: &ProgramSnapshot,
    filter: ProgramDiffFilter,
) -> Vec<DiffResult> {
    let mut results = Vec::new();

    if filter.contains(ProgramDiffFilter::BYTES) {
        diff_bytes(prog1, prog2, &mut results);
    }
    if filter.contains(ProgramDiffFilter::SYMBOLS) {
        diff_symbols(prog1, prog2, &mut results);
    }
    if filter.contains(ProgramDiffFilter::COMMENTS) {
        diff_comments(prog1, prog2, &mut results);
    }
    if filter.contains(ProgramDiffFilter::MEMORY_BLOCKS) {
        diff_blocks(prog1, prog2, &mut results);
    }

    results.sort();
    results
}

fn diff_bytes(prog1: &ProgramSnapshot, prog2: &ProgramSnapshot, results: &mut Vec<DiffResult>) {
    for (_, (start, data)) in &prog1.blocks {
        for (i, &byte) in data.iter().enumerate() {
            let addr = start + i as u64;
            if let Some(other_byte) = prog2.byte_at(addr) {
                if byte != other_byte {
                    results.push(DiffResult::with_values(
                        addr,
                        DiffType::ByteChanged,
                        format!("byte changed at 0x{:x}", addr),
                        format!("0x{:02x}", byte),
                        format!("0x{:02x}", other_byte),
                    ));
                }
            }
        }
    }
}

fn diff_symbols(prog1: &ProgramSnapshot, prog2: &ProgramSnapshot, results: &mut Vec<DiffResult>) {
    for (addr, name) in &prog1.symbols {
        match prog2.symbols.get(addr) {
            Some(other_name) => {
                if name != other_name {
                    results.push(DiffResult::with_values(
                        *addr,
                        DiffType::SymbolRenamed,
                        format!("symbol renamed at 0x{:x}", addr),
                        name.clone(),
                        other_name.clone(),
                    ));
                }
            }
            None => {
                results.push(DiffResult::new(
                    *addr,
                    DiffType::SymbolRemoved,
                    format!("symbol '{}' removed at 0x{:x}", name, addr),
                ));
            }
        }
    }
    for (addr, name) in &prog2.symbols {
        if !prog1.symbols.contains_key(addr) {
            results.push(DiffResult::new(
                *addr,
                DiffType::SymbolAdded,
                format!("symbol '{}' added at 0x{:x}", name, addr),
            ));
        }
    }
}

fn diff_comments(
    prog1: &ProgramSnapshot,
    prog2: &ProgramSnapshot,
    results: &mut Vec<DiffResult>,
) {
    for (addr, comment) in &prog1.comments {
        match prog2.comments.get(addr) {
            Some(other) => {
                if comment != other {
                    results.push(DiffResult::with_values(
                        *addr,
                        DiffType::CommentChanged,
                        format!("comment changed at 0x{:x}", addr),
                        comment.clone(),
                        other.clone(),
                    ));
                }
            }
            None => {
                results.push(DiffResult::new(
                    *addr,
                    DiffType::CommentChanged,
                    format!("comment removed at 0x{:x}", addr),
                ));
            }
        }
    }
    for addr in prog2.comments.keys() {
        if !prog1.comments.contains_key(addr) {
            results.push(DiffResult::new(
                *addr,
                DiffType::CommentChanged,
                format!("comment added at 0x{:x}", addr),
            ));
        }
    }
}

fn diff_blocks(prog1: &ProgramSnapshot, prog2: &ProgramSnapshot, results: &mut Vec<DiffResult>) {
    for name in prog1.blocks.keys() {
        if !prog2.blocks.contains_key(name) {
            results.push(DiffResult::new(
                0,
                DiffType::MemoryBlockChanged,
                format!("memory block '{}' removed", name),
            ));
        }
    }
    for name in prog2.blocks.keys() {
        if !prog1.blocks.contains_key(name) {
            results.push(DiffResult::new(
                0,
                DiffType::MemoryBlockChanged,
                format!("memory block '{}' added", name),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_filter_basic() {
        let mut f = ProgramDiffFilter::empty();
        assert!(f.is_empty());
        f.insert(ProgramDiffFilter::BYTES);
        assert!(f.contains(ProgramDiffFilter::BYTES));
        assert!(!f.contains(ProgramDiffFilter::SYMBOLS));
        f.insert(ProgramDiffFilter::SYMBOLS);
        assert!(f.contains(ProgramDiffFilter::BYTES | ProgramDiffFilter::SYMBOLS));
    }

    #[test]
    fn test_diff_filter_combine() {
        let f = ProgramDiffFilter::BYTES | ProgramDiffFilter::SYMBOLS;
        assert!(f.contains(ProgramDiffFilter::BYTES));
        assert!(f.contains(ProgramDiffFilter::SYMBOLS));
        assert!(!f.contains(ProgramDiffFilter::COMMENTS));
    }

    #[test]
    fn test_diff_filter_set_toggle() {
        let mut f = ProgramDiffFilter::empty();
        f.set(ProgramDiffFilter::BYTES, true);
        assert!(f.contains(ProgramDiffFilter::BYTES));
        f.set(ProgramDiffFilter::BYTES, false);
        assert!(!f.contains(ProgramDiffFilter::BYTES));
    }

    #[test]
    fn test_diff_filter_all() {
        let f = ProgramDiffFilter::all();
        assert!(f.contains(ProgramDiffFilter::BYTES));
        assert!(f.contains(ProgramDiffFilter::SYMBOLS));
        assert!(f.contains(ProgramDiffFilter::COMMENTS));
        assert!(f.contains(ProgramDiffFilter::REFERENCES));
    }

    #[test]
    fn test_diff_bytes_changed() {
        let mut prog1 = ProgramSnapshot::new("p1");
        prog1.add_block(".text", 0x1000, vec![0x90, 0xC3, 0xCC]);
        let mut prog2 = ProgramSnapshot::new("p2");
        prog2.add_block(".text", 0x1000, vec![0x90, 0xCB, 0xCC]);

        let results = diff_programs(&prog1, &prog2, ProgramDiffFilter::BYTES);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].address, 0x1001);
        assert_eq!(results[0].diff_type, DiffType::ByteChanged);
    }

    #[test]
    fn test_diff_symbols_renamed() {
        let mut prog1 = ProgramSnapshot::new("p1");
        prog1.add_symbol(0x1000, "main");
        let mut prog2 = ProgramSnapshot::new("p2");
        prog2.add_symbol(0x1000, "main_entry");

        let results = diff_programs(&prog1, &prog2, ProgramDiffFilter::SYMBOLS);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].diff_type, DiffType::SymbolRenamed);
    }

    #[test]
    fn test_diff_symbols_added() {
        let prog1 = ProgramSnapshot::new("p1");
        let mut prog2 = ProgramSnapshot::new("p2");
        prog2.add_symbol(0x2000, "new_func");

        let results = diff_programs(&prog1, &prog2, ProgramDiffFilter::SYMBOLS);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].diff_type, DiffType::SymbolAdded);
    }

    #[test]
    fn test_diff_symbols_removed() {
        let mut prog1 = ProgramSnapshot::new("p1");
        prog1.add_symbol(0x1000, "old_func");
        let prog2 = ProgramSnapshot::new("p2");

        let results = diff_programs(&prog1, &prog2, ProgramDiffFilter::SYMBOLS);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].diff_type, DiffType::SymbolRemoved);
    }

    #[test]
    fn test_diff_comments() {
        let mut prog1 = ProgramSnapshot::new("p1");
        prog1.add_comment(0x1000, "old comment");
        let mut prog2 = ProgramSnapshot::new("p2");
        prog2.add_comment(0x1000, "new comment");

        let results = diff_programs(&prog1, &prog2, ProgramDiffFilter::COMMENTS);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].diff_type, DiffType::CommentChanged);
    }

    #[test]
    fn test_diff_memory_blocks() {
        let mut prog1 = ProgramSnapshot::new("p1");
        prog1.add_block(".text", 0x1000, vec![0x90]);
        let mut prog2 = ProgramSnapshot::new("p2");
        prog2.add_block(".data", 0x2000, vec![0x00]);

        let results = diff_programs(&prog1, &prog2, ProgramDiffFilter::MEMORY_BLOCKS);
        assert_eq!(results.len(), 2); // one removed, one added
    }

    #[test]
    fn test_diff_no_differences() {
        let mut prog1 = ProgramSnapshot::new("p1");
        prog1.add_block(".text", 0x1000, vec![0x90, 0xC3]);
        prog1.add_symbol(0x1000, "main");
        let mut prog2 = ProgramSnapshot::new("p2");
        prog2.add_block(".text", 0x1000, vec![0x90, 0xC3]);
        prog2.add_symbol(0x1000, "main");

        let results = diff_programs(&prog1, &prog2, ProgramDiffFilter::all());
        assert!(results.is_empty());
    }

    #[test]
    fn test_diff_type_label() {
        assert_eq!(DiffType::ByteChanged.label(), "Byte Changed");
        assert_eq!(DiffType::SymbolAdded.label(), "Symbol Added");
    }

    #[test]
    fn test_diff_results_sorted() {
        let mut prog1 = ProgramSnapshot::new("p1");
        prog1.add_block(".text", 0x1000, vec![0x00, 0x00, 0x00]);
        let mut prog2 = ProgramSnapshot::new("p2");
        prog2.add_block(".text", 0x1000, vec![0xFF, 0xFF, 0xFF]);

        let results = diff_programs(&prog1, &prog2, ProgramDiffFilter::BYTES);
        assert_eq!(results.len(), 3);
        for window in results.windows(2) {
            assert!(window[0].address <= window[1].address);
        }
    }

    #[test]
    fn test_program_snapshot_byte_at() {
        let mut prog = ProgramSnapshot::new("test");
        prog.add_block(".text", 0x1000, vec![0xCA, 0xFE]);
        assert_eq!(prog.byte_at(0x1000), Some(0xCA));
        assert_eq!(prog.byte_at(0x1001), Some(0xFE));
        assert_eq!(prog.byte_at(0x1002), None);
        assert_eq!(prog.byte_at(0x0000), None);
    }
}
