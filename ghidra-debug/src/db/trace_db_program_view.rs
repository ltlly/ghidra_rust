//! Database-backed program view extensions for traces.
//!
//! Ported from Ghidra's `ghidra.trace.database.program` package:
//! - DBTraceProgramViewFunctionManager
//! - DBTraceProgramViewSymbolTable
//! - DBTraceProgramViewBookmarkManager
//! - DBTraceProgramViewEquateTable
//! - DBTraceProgramViewPropertyMapManager
//! - DBTraceProgramViewFragment
//! - DBTraceProgramViewRootModule
//! - DBTraceVariableSnapProgramView
//!
//! These provide Ghidra Program API compatibility layers over the trace database.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A function entry in a program view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewFunction {
    /// The function entry address.
    pub entry_address: u64,
    /// The function name.
    pub name: String,
    /// The function body minimum address.
    pub body_min: u64,
    /// The function body maximum address.
    pub body_max: u64,
    /// Whether this is a thunk function.
    pub is_thunk: bool,
    /// The calling convention name.
    pub calling_convention: String,
    /// The lifespan during which this function exists.
    pub lifespan: Lifespan,
}

impl ProgramViewFunction {
    /// Create a new function entry.
    pub fn new(
        entry_address: u64,
        name: impl Into<String>,
        body_min: u64,
        body_max: u64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            entry_address,
            name: name.into(),
            body_min,
            body_max,
            is_thunk: false,
            calling_convention: "default".to_string(),
            lifespan,
        }
    }

    /// Whether this function contains the given address.
    pub fn contains_address(&self, address: u64) -> bool {
        address >= self.body_min && address <= self.body_max
    }

    /// The size of the function body.
    pub fn body_size(&self) -> u64 {
        self.body_max - self.body_min + 1
    }
}

/// A function manager for a program view over a trace.
///
/// Ported from Ghidra's `DBTraceProgramViewFunctionManager`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProgramViewFunctionManager {
    /// The functions in this view.
    pub functions: Vec<ProgramViewFunction>,
}

impl ProgramViewFunctionManager {
    /// Create a new function manager.
    pub fn new() -> Self {
        Self {
            functions: Vec::new(),
        }
    }

    /// Add a function.
    pub fn add_function(&mut self, function: ProgramViewFunction) {
        self.functions.push(function);
    }

    /// Get a function at the given address and snap.
    pub fn get_function_at(&self, snap: i64, address: u64) -> Option<&ProgramViewFunction> {
        self.functions.iter().find(|f| {
            f.entry_address == address && f.lifespan.contains(snap)
        })
    }

    /// Get the function containing the given address and snap.
    pub fn get_function_containing(
        &self,
        snap: i64,
        address: u64,
    ) -> Option<&ProgramViewFunction> {
        self.functions
            .iter()
            .find(|f| f.contains_address(address) && f.lifespan.contains(snap))
    }

    /// Get all functions at the given snap.
    pub fn get_functions_at_snap(&self, snap: i64) -> Vec<&ProgramViewFunction> {
        self.functions
            .iter()
            .filter(|f| f.lifespan.contains(snap))
            .collect()
    }

    /// Get function count at the given snap.
    pub fn function_count(&self, snap: i64) -> usize {
        self.functions
            .iter()
            .filter(|f| f.lifespan.contains(snap))
            .count()
    }
}

/// A bookmark entry in a program view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewBookmark {
    /// The address.
    pub address: u64,
    /// The bookmark type.
    pub bookmark_type: String,
    /// The category.
    pub category: String,
    /// The comment.
    pub comment: String,
    /// The lifespan.
    pub lifespan: Lifespan,
}

/// A bookmark manager for a program view over a trace.
///
/// Ported from Ghidra's `DBTraceProgramViewBookmarkManager`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProgramViewBookmarkManager {
    /// The bookmarks in this view.
    pub bookmarks: Vec<ProgramViewBookmark>,
}

impl ProgramViewBookmarkManager {
    /// Create a new bookmark manager.
    pub fn new() -> Self {
        Self {
            bookmarks: Vec::new(),
        }
    }

    /// Add a bookmark.
    pub fn add_bookmark(&mut self, bookmark: ProgramViewBookmark) {
        self.bookmarks.push(bookmark);
    }

    /// Get bookmarks at an address and snap.
    pub fn get_bookmarks_at(&self, snap: i64, address: u64) -> Vec<&ProgramViewBookmark> {
        self.bookmarks
            .iter()
            .filter(|b| b.address == address && b.lifespan.contains(snap))
            .collect()
    }

    /// Get all bookmarks at a snap.
    pub fn get_all_bookmarks_at_snap(&self, snap: i64) -> Vec<&ProgramViewBookmark> {
        self.bookmarks
            .iter()
            .filter(|b| b.lifespan.contains(snap))
            .collect()
    }
}

/// An equate entry in a program view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewEquate {
    /// The equate name.
    pub name: String,
    /// The equate value.
    pub value: i64,
    /// The address where this equate is applied.
    pub address: u64,
    /// The operand index.
    pub operand_index: i32,
    /// The lifespan.
    pub lifespan: Lifespan,
}

/// An equate table for a program view over a trace.
///
/// Ported from Ghidra's `DBTraceProgramViewEquateTable`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProgramViewEquateTable {
    /// The equates in this view.
    pub equates: Vec<ProgramViewEquate>,
}

impl ProgramViewEquateTable {
    /// Create a new equate table.
    pub fn new() -> Self {
        Self {
            equates: Vec::new(),
        }
    }

    /// Add an equate.
    pub fn add_equate(&mut self, equate: ProgramViewEquate) {
        self.equates.push(equate);
    }

    /// Get equates at an address and snap.
    pub fn get_equates_at(&self, snap: i64, address: u64) -> Vec<&ProgramViewEquate> {
        self.equates
            .iter()
            .filter(|e| e.address == address && e.lifespan.contains(snap))
            .collect()
    }

    /// Get an equate by value at an address and operand.
    pub fn get_equate_by_value(
        &self,
        snap: i64,
        address: u64,
        operand_index: i32,
        value: i64,
    ) -> Option<&ProgramViewEquate> {
        self.equates.iter().find(|e| {
            e.address == address
                && e.operand_index == operand_index
                && e.value == value
                && e.lifespan.contains(snap)
        })
    }
}

/// A fragment in a program view.
///
/// Ported from Ghidra's `DBTraceProgramViewFragment`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewFragment {
    /// The fragment name.
    pub name: String,
    /// The minimum address in this fragment.
    pub min_address: u64,
    /// The maximum address in this fragment.
    pub max_address: u64,
    /// The lifespan.
    pub lifespan: Lifespan,
}

impl ProgramViewFragment {
    /// Create a new fragment.
    pub fn new(
        name: impl Into<String>,
        min_address: u64,
        max_address: u64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            name: name.into(),
            min_address,
            max_address,
            lifespan,
        }
    }

    /// Whether this fragment contains the given address.
    pub fn contains_address(&self, address: u64) -> bool {
        address >= self.min_address && address <= self.max_address
    }
}

/// A variable-snap program view that can be positioned at different snaps.
///
/// Ported from Ghidra's `DBTraceVariableSnapProgramView`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewSnapshot {
    /// The current snap of this view.
    pub current_snap: i64,
    /// The function manager.
    pub functions: ProgramViewFunctionManager,
    /// The bookmark manager.
    pub bookmarks: ProgramViewBookmarkManager,
    /// The equate table.
    pub equates: ProgramViewEquateTable,
    /// The fragments.
    pub fragments: Vec<ProgramViewFragment>,
}

impl ProgramViewSnapshot {
    /// Create a new program view snapshot at the given snap.
    pub fn new(snap: i64) -> Self {
        Self {
            current_snap: snap,
            functions: ProgramViewFunctionManager::new(),
            bookmarks: ProgramViewBookmarkManager::new(),
            equates: ProgramViewEquateTable::new(),
            fragments: Vec::new(),
        }
    }

    /// Set the current snap.
    pub fn set_snap(&mut self, snap: i64) {
        self.current_snap = snap;
    }

    /// Get the current snap.
    pub fn snap(&self) -> i64 {
        self.current_snap
    }
}

/// A change set for a program view.
///
/// Ported from Ghidra's `DBTraceProgramViewChangeSet`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProgramViewChangeSet {
    /// The address ranges that have changed.
    pub changed_addresses: Vec<(u64, u64)>,
}

impl ProgramViewChangeSet {
    /// Create a new change set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a changed address range.
    pub fn add_range(&mut self, min_address: u64, max_address: u64) {
        self.changed_addresses.push((min_address, max_address));
    }

    /// Whether the change set is empty.
    pub fn is_empty(&self) -> bool {
        self.changed_addresses.is_empty()
    }

    /// Get the number of changed ranges.
    pub fn range_count(&self) -> usize {
        self.changed_addresses.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_manager() {
        let mut mgr = ProgramViewFunctionManager::new();
        mgr.add_function(ProgramViewFunction::new(
            0x1000,
            "main",
            0x1000,
            0x1100,
            Lifespan::span(0, 100),
        ));

        assert_eq!(mgr.function_count(50), 1);
        assert!(mgr.get_function_at(50, 0x1000).is_some());
        assert!(mgr.get_function_containing(50, 0x1050).is_some());
        assert!(mgr.get_function_containing(50, 0x2000).is_none());
        assert_eq!(mgr.function_count(150), 0);
    }

    #[test]
    fn test_function_body() {
        let f = ProgramViewFunction::new(0x1000, "main", 0x1000, 0x1100, Lifespan::span(0, 100));
        assert!(f.contains_address(0x1050));
        assert!(!f.contains_address(0x2000));
        assert_eq!(f.body_size(), 0x101);
    }

    #[test]
    fn test_bookmark_manager() {
        let mut mgr = ProgramViewBookmarkManager::new();
        mgr.add_bookmark(ProgramViewBookmark {
            address: 0x1000,
            bookmark_type: "Note".to_string(),
            category: "test".to_string(),
            comment: "A test bookmark".to_string(),
            lifespan: Lifespan::span(0, 100),
        });

        assert_eq!(mgr.get_bookmarks_at(50, 0x1000).len(), 1);
        assert!(mgr.get_bookmarks_at(50, 0x2000).is_empty());
        assert_eq!(mgr.get_all_bookmarks_at_snap(50).len(), 1);
    }

    #[test]
    fn test_equate_table() {
        let mut table = ProgramViewEquateTable::new();
        table.add_equate(ProgramViewEquate {
            name: "MY_CONST".to_string(),
            value: 42,
            address: 0x1000,
            operand_index: 0,
            lifespan: Lifespan::span(0, 100),
        });

        assert_eq!(table.get_equates_at(50, 0x1000).len(), 1);
        assert!(table
            .get_equate_by_value(50, 0x1000, 0, 42)
            .is_some());
        assert!(table
            .get_equate_by_value(50, 0x1000, 0, 99)
            .is_none());
    }

    #[test]
    fn test_fragment() {
        let frag = ProgramViewFragment::new(".text", 0x1000, 0x2000, Lifespan::span(0, 100));
        assert!(frag.contains_address(0x1500));
        assert!(!frag.contains_address(0x3000));
    }

    #[test]
    fn test_program_view_snapshot() {
        let mut view = ProgramViewSnapshot::new(10);
        assert_eq!(view.snap(), 10);
        view.set_snap(20);
        assert_eq!(view.snap(), 20);
    }

    #[test]
    fn test_change_set() {
        let mut cs = ProgramViewChangeSet::new();
        assert!(cs.is_empty());
        cs.add_range(0x1000, 0x2000);
        cs.add_range(0x3000, 0x4000);
        assert_eq!(cs.range_count(), 2);
    }
}
