//! TraceChangeSet - tracks changes to a trace.
//!
//! Ported from Ghidra's `DBTraceChangeSet`. Records which parts of a trace
//! have been modified since the last save or since a given baseline.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The type of change that occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChangeType {
    /// A new object was added.
    Added,
    /// An existing object was modified.
    Modified,
    /// An object was removed.
    Removed,
}

/// A record of a single change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceChangeRecord {
    /// The type of change.
    pub change_type: ChangeType,
    /// The category of object changed (e.g., "thread", "memory", "bookmark").
    pub category: String,
    /// The key of the changed object.
    pub key: String,
}

impl TraceChangeRecord {
    /// Create a new change record.
    pub fn new(change_type: ChangeType, category: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            change_type,
            category: category.into(),
            key: key.into(),
        }
    }
}

/// Tracks changes made to a trace since the last save.
///
/// Groups changes by category for efficient querying.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceChangeSet {
    records: Vec<TraceChangeRecord>,
    /// Snap keys that have been modified.
    dirty_snaps: BTreeSet<i64>,
    /// Whether the trace info has been modified.
    info_changed: bool,
    /// Whether any objects have changed.
    objects_changed: bool,
    /// Whether any memory state has changed.
    memory_changed: bool,
    /// Whether any register context has changed.
    register_context_changed: bool,
}

impl TraceChangeSet {
    /// Create a new empty change set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a change.
    pub fn record(&mut self, record: TraceChangeRecord) {
        match record.category.as_str() {
            "memory" => self.memory_changed = true,
            "register_context" => self.register_context_changed = true,
            "objects" => self.objects_changed = true,
            "info" => self.info_changed = true,
            _ => {}
        }
        self.records.push(record);
    }

    /// Mark a snap as dirty.
    pub fn mark_snap_dirty(&mut self, snap: i64) {
        self.dirty_snaps.insert(snap);
    }

    /// Whether the change set has any changes.
    pub fn has_changes(&self) -> bool {
        !self.records.is_empty()
            || !self.dirty_snaps.is_empty()
            || self.info_changed
            || self.memory_changed
            || self.register_context_changed
            || self.objects_changed
    }

    /// Whether the info has changed.
    pub fn is_info_changed(&self) -> bool {
        self.info_changed
    }

    /// Whether memory has changed.
    pub fn is_memory_changed(&self) -> bool {
        self.memory_changed
    }

    /// Whether register context has changed.
    pub fn is_register_context_changed(&self) -> bool {
        self.register_context_changed
    }

    /// Whether objects have changed.
    pub fn is_objects_changed(&self) -> bool {
        self.objects_changed
    }

    /// Get dirty snap keys.
    pub fn dirty_snaps(&self) -> &BTreeSet<i64> {
        &self.dirty_snaps
    }

    /// Get all change records.
    pub fn records(&self) -> &[TraceChangeRecord] {
        &self.records
    }

    /// Clear the change set.
    pub fn clear(&mut self) {
        self.records.clear();
        self.dirty_snaps.clear();
        self.info_changed = false;
        self.objects_changed = false;
        self.memory_changed = false;
        self.register_context_changed = false;
    }

    /// Number of change records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether there are no change records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_change_set_record() {
        let mut cs = TraceChangeSet::new();
        cs.record(TraceChangeRecord::new(ChangeType::Added, "thread", "Threads[1]"));
        cs.record(TraceChangeRecord::new(ChangeType::Modified, "memory", "0x400000"));

        assert!(cs.has_changes());
        assert!(cs.is_memory_changed());
        assert!(!cs.is_info_changed());
        assert_eq!(cs.len(), 2);
    }

    #[test]
    fn test_change_set_dirty_snaps() {
        let mut cs = TraceChangeSet::new();
        cs.mark_snap_dirty(0);
        cs.mark_snap_dirty(5);
        cs.mark_snap_dirty(0); // duplicate

        assert_eq!(cs.dirty_snaps().len(), 2);
        assert!(cs.dirty_snaps().contains(&0));
        assert!(cs.dirty_snaps().contains(&5));
    }

    #[test]
    fn test_change_set_categories() {
        let mut cs = TraceChangeSet::new();
        cs.record(TraceChangeRecord::new(ChangeType::Added, "info", "key"));
        assert!(cs.is_info_changed());

        cs.record(TraceChangeRecord::new(ChangeType::Modified, "register_context", "rax"));
        assert!(cs.is_register_context_changed());
    }

    #[test]
    fn test_change_set_clear() {
        let mut cs = TraceChangeSet::new();
        cs.record(TraceChangeRecord::new(ChangeType::Added, "thread", "1"));
        cs.mark_snap_dirty(0);
        cs.clear();

        assert!(!cs.has_changes());
        assert!(cs.is_empty());
        assert!(cs.dirty_snaps().is_empty());
    }

    #[test]
    fn test_change_set_serde() {
        let mut cs = TraceChangeSet::new();
        cs.record(TraceChangeRecord::new(ChangeType::Added, "thread", "1"));
        let json = serde_json::to_string(&cs).unwrap();
        let back: TraceChangeSet = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
    }
}
