//! TraceChangeSet - tracking changes made to a trace within transactions.
//!
//! Ported from Ghidra's `ghidra.trace.model.TraceChangeSet`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Types of changes that can occur in a trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TraceChangeKind {
    /// Memory bytes were modified.
    MemoryChanged,
    /// A code unit was added or removed.
    CodeUnitChanged,
    /// A symbol was added, removed, or modified.
    SymbolChanged,
    /// A bookmark was added or removed.
    BookmarkChanged,
    /// A breakpoint was added or removed.
    BreakpointChanged,
    /// A thread was created or destroyed.
    ThreadChanged,
    /// A module was loaded or unloaded.
    ModuleChanged,
    /// A memory region was added or removed.
    RegionChanged,
    /// A property was changed.
    PropertyChanged,
    /// A reference was added or removed.
    ReferenceChanged,
    /// The register context was changed.
    RegisterContextChanged,
    /// The target object tree was changed.
    TargetObjectChanged,
    /// The data type manager was changed.
    DataTypeChanged,
}

/// A change set that tracks which addresses and components have been modified.
///
/// This is used to implement Ghidra's undo/redo and to track which parts of
/// a trace need to be refreshed in the UI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceChangeSet {
    /// Memory address ranges that have been modified.
    pub memory_changes: BTreeSet<(u64, u64)>,
    /// Symbol IDs that have been changed.
    pub symbol_changes: BTreeSet<i64>,
    /// Thread keys that have been changed.
    pub thread_changes: BTreeSet<i64>,
    /// Module keys that have been changed.
    pub module_changes: BTreeSet<i64>,
    /// Bookmark keys that have been changed.
    pub bookmark_changes: BTreeSet<i64>,
    /// Breakpoint keys that have been changed.
    pub breakpoint_changes: BTreeSet<i64>,
    /// Property keys that have been changed.
    pub property_changes: BTreeSet<String>,
    /// Kinds of changes present in this set.
    pub change_kinds: BTreeSet<TraceChangeKind>,
    /// Whether the entire trace should be considered dirty.
    pub dirty_all: bool,
}

impl TraceChangeSet {
    /// Create a new empty change set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear all tracked changes.
    pub fn clear(&mut self) {
        self.memory_changes.clear();
        self.symbol_changes.clear();
        self.thread_changes.clear();
        self.module_changes.clear();
        self.bookmark_changes.clear();
        self.breakpoint_changes.clear();
        self.property_changes.clear();
        self.change_kinds.clear();
        self.dirty_all = false;
    }

    /// Check if the change set is empty.
    pub fn is_empty(&self) -> bool {
        !self.dirty_all
            && self.memory_changes.is_empty()
            && self.symbol_changes.is_empty()
            && self.thread_changes.is_empty()
            && self.module_changes.is_empty()
            && self.bookmark_changes.is_empty()
            && self.breakpoint_changes.is_empty()
            && self.property_changes.is_empty()
    }

    /// Record a memory change in an address range.
    pub fn add_memory_change(&mut self, min_addr: u64, max_addr: u64) {
        self.memory_changes.insert((min_addr, max_addr));
        self.change_kinds.insert(TraceChangeKind::MemoryChanged);
    }

    /// Record a symbol change.
    pub fn add_symbol_change(&mut self, symbol_id: i64) {
        self.symbol_changes.insert(symbol_id);
        self.change_kinds.insert(TraceChangeKind::SymbolChanged);
    }

    /// Record a thread change.
    pub fn add_thread_change(&mut self, thread_key: i64) {
        self.thread_changes.insert(thread_key);
        self.change_kinds.insert(TraceChangeKind::ThreadChanged);
    }

    /// Record a module change.
    pub fn add_module_change(&mut self, module_key: i64) {
        self.module_changes.insert(module_key);
        self.change_kinds.insert(TraceChangeKind::ModuleChanged);
    }

    /// Record a bookmark change.
    pub fn add_bookmark_change(&mut self, bookmark_key: i64) {
        self.bookmark_changes.insert(bookmark_key);
        self.change_kinds.insert(TraceChangeKind::BookmarkChanged);
    }

    /// Record a breakpoint change.
    pub fn add_breakpoint_change(&mut self, breakpoint_key: i64) {
        self.breakpoint_changes.insert(breakpoint_key);
        self.change_kinds
            .insert(TraceChangeKind::BreakpointChanged);
    }

    /// Record a property change.
    pub fn add_property_change(&mut self, key: impl Into<String>) {
        self.property_changes.insert(key.into());
        self.change_kinds
            .insert(TraceChangeKind::PropertyChanged);
    }

    /// Check if a specific kind of change is present.
    pub fn has_change(&self, kind: TraceChangeKind) -> bool {
        self.change_kinds.contains(&kind)
    }

    /// Mark the entire trace as dirty.
    pub fn mark_dirty_all(&mut self) {
        self.dirty_all = true;
    }

    /// Merge another change set into this one.
    pub fn merge(&mut self, other: &TraceChangeSet) {
        self.memory_changes.extend(&other.memory_changes);
        self.symbol_changes.extend(&other.symbol_changes);
        self.thread_changes.extend(&other.thread_changes);
        self.module_changes.extend(&other.module_changes);
        self.bookmark_changes.extend(&other.bookmark_changes);
        self.breakpoint_changes.extend(&other.breakpoint_changes);
        self.property_changes.extend(other.property_changes.iter().cloned());
        self.change_kinds.extend(&other.change_kinds);
        if other.dirty_all {
            self.dirty_all = true;
        }
    }
}

/// Change record for individual changes in a trace domain object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceChangeRecord {
    /// The kind of change.
    pub kind: TraceChangeKind,
    /// The affected key (object ID, address, etc.).
    pub key: String,
    /// Whether this was an add, remove, or modify.
    pub operation: ChangeOperation,
}

/// The type of change operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeOperation {
    /// An object was added.
    Added,
    /// An object was removed.
    Removed,
    /// An object was modified.
    Modified,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_change_set_basics() {
        let mut cs = TraceChangeSet::new();
        assert!(cs.is_empty());

        cs.add_memory_change(0x1000, 0x1FFF);
        assert!(!cs.is_empty());
        assert!(cs.has_change(TraceChangeKind::MemoryChanged));
    }

    #[test]
    fn test_change_set_merge() {
        let mut cs1 = TraceChangeSet::new();
        cs1.add_symbol_change(1);
        cs1.add_thread_change(5);

        let mut cs2 = TraceChangeSet::new();
        cs2.add_symbol_change(2);
        cs2.add_module_change(10);

        cs1.merge(&cs2);
        assert_eq!(cs1.symbol_changes.len(), 2);
        assert_eq!(cs1.thread_changes.len(), 1);
        assert_eq!(cs1.module_changes.len(), 1);
    }

    #[test]
    fn test_clear() {
        let mut cs = TraceChangeSet::new();
        cs.add_memory_change(0x1000, 0x1FFF);
        cs.add_symbol_change(1);
        assert!(!cs.is_empty());

        cs.clear();
        assert!(cs.is_empty());
    }

    #[test]
    fn test_dirty_all() {
        let mut cs = TraceChangeSet::new();
        cs.mark_dirty_all();
        assert!(!cs.is_empty());
        assert!(cs.dirty_all);
    }

    #[test]
    fn test_change_record() {
        let record = TraceChangeRecord {
            kind: TraceChangeKind::SymbolChanged,
            key: "sym_42".into(),
            operation: ChangeOperation::Added,
        };
        assert_eq!(record.operation, ChangeOperation::Added);
    }
}
