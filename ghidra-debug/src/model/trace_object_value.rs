//! Supplementary types for target object value changes and snapshots.
//!
//! Ported from Ghidra's `ghidra.trace.model.target` package. These types
//! complement the core `TraceObjectValue` and `TraceObjectValPath` types
//! in `target_value.rs` with change notifications and tree snapshots.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A change event for target object values.
///
/// Ported from Ghidra's value change notification system. When values in
/// the target object tree change, these events are emitted to listeners.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueChangeEvent {
    /// The kind of change.
    pub kind: ValueChangeKind,
    /// The parent object key.
    pub parent_key: i64,
    /// The entry key that changed.
    pub entry_key: String,
    /// The child object key (if object reference).
    pub child_object_key: Option<i64>,
    /// The snap range affected.
    pub snap_min: i64,
    pub snap_max: i64,
}

impl ValueChangeEvent {
    /// Create a new value change event.
    pub fn new(
        kind: ValueChangeKind,
        parent_key: i64,
        entry_key: impl Into<String>,
        snap_min: i64,
        snap_max: i64,
    ) -> Self {
        Self {
            kind,
            parent_key,
            entry_key: entry_key.into(),
            child_object_key: None,
            snap_min,
            snap_max,
        }
    }

    /// Set the child object key.
    pub fn with_child_key(mut self, key: i64) -> Self {
        self.child_object_key = Some(key);
        self
    }

    /// The lifespan affected by this change.
    pub fn lifespan(&self) -> Lifespan {
        Lifespan::span(self.snap_min, self.snap_max)
    }
}

/// The kind of change to a value entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ValueChangeKind {
    /// A value was inserted.
    Inserted,
    /// A value was mutated (lifespan changed).
    Mutated,
    /// A value was deleted.
    Deleted,
}

impl std::fmt::Display for ValueChangeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inserted => write!(f, "inserted"),
            Self::Mutated => write!(f, "mutated"),
            Self::Deleted => write!(f, "deleted"),
        }
    }
}

/// Snapshot of the target object tree state at a given snap.
///
/// Captures the full state of the target tree at a specific point in time,
/// allowing queries against a consistent view without snap parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetTreeSnapshot {
    /// The snap at which this snapshot was taken.
    pub snap: i64,
    /// All alive parent->child entries at this snap.
    /// Each entry is (parent_key, entry_key, child_object_key).
    pub entries: Vec<(i64, String, Option<i64>)>,
}

impl TargetTreeSnapshot {
    /// Create a new empty snapshot.
    pub fn new(snap: i64) -> Self {
        Self {
            snap,
            entries: Vec::new(),
        }
    }

    /// Add an entry to the snapshot.
    pub fn add_entry(
        &mut self,
        parent_key: i64,
        entry_key: impl Into<String>,
        child_key: Option<i64>,
    ) {
        self.entries.push((parent_key, entry_key.into(), child_key));
    }

    /// Find all child entries of a given parent.
    pub fn children_of(&self, parent_key: i64) -> Vec<(&str, Option<i64>)> {
        self.entries
            .iter()
            .filter(|(pk, _, _)| *pk == parent_key)
            .map(|(_, ek, ck)| (ek.as_str(), *ck))
            .collect()
    }

    /// Whether a specific entry exists.
    pub fn has_entry(&self, parent_key: i64, entry_key: &str) -> bool {
        self.entries
            .iter()
            .any(|(pk, ek, _)| *pk == parent_key && ek == entry_key)
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the snapshot is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A listener interface for target object changes.
///
/// Ported from Ghidra's `TraceObjectListener`. Objects implementing this
/// trait can register to receive notifications when the target tree changes.
pub trait TraceObjectChangeListener {
    /// Called when a value is inserted.
    fn value_inserted(&mut self, event: &ValueChangeEvent);

    /// Called when a value is mutated.
    fn value_mutated(&mut self, event: &ValueChangeEvent);

    /// Called when a value is deleted.
    fn value_deleted(&mut self, event: &ValueChangeEvent);

    /// Called when an object is created.
    fn object_created(&mut self, _object_key: i64) {
        // Default: no-op
    }

    /// Called when an object is deleted.
    fn object_deleted(&mut self, _object_key: i64) {
        // Default: no-op
    }
}

/// A simple collector for change events.
#[derive(Debug, Clone, Default)]
pub struct ChangeCollector {
    /// Collected events.
    pub events: Vec<ValueChangeEvent>,
}

impl ChangeCollector {
    /// Create a new collector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear all collected events.
    pub fn clear(&mut self) {
        self.events.clear();
    }
}

impl TraceObjectChangeListener for ChangeCollector {
    fn value_inserted(&mut self, event: &ValueChangeEvent) {
        self.events.push(event.clone());
    }

    fn value_mutated(&mut self, event: &ValueChangeEvent) {
        self.events.push(event.clone());
    }

    fn value_deleted(&mut self, event: &ValueChangeEvent) {
        self.events.push(event.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_change_event() {
        let event =
            ValueChangeEvent::new(ValueChangeKind::Inserted, 1, "Threads[0]", 0, 10)
                .with_child_key(50);
        assert_eq!(event.kind, ValueChangeKind::Inserted);
        assert_eq!(event.parent_key, 1);
        assert_eq!(event.entry_key, "Threads[0]");
        assert_eq!(event.child_object_key, Some(50));
        assert_eq!(event.lifespan(), Lifespan::span(0, 10));
    }

    #[test]
    fn test_value_change_kind_display() {
        assert_eq!(ValueChangeKind::Inserted.to_string(), "inserted");
        assert_eq!(ValueChangeKind::Mutated.to_string(), "mutated");
        assert_eq!(ValueChangeKind::Deleted.to_string(), "deleted");
    }

    #[test]
    fn test_value_change_kind_equality() {
        assert_ne!(ValueChangeKind::Inserted, ValueChangeKind::Deleted);
    }

    #[test]
    fn test_target_tree_snapshot() {
        let mut snap = TargetTreeSnapshot::new(5);
        snap.add_entry(1, "Threads[0]", Some(10));
        snap.add_entry(1, "Threads[1]", Some(11));
        snap.add_entry(1, "_display", None);

        assert_eq!(snap.len(), 3);
        assert!(!snap.is_empty());
        assert!(snap.has_entry(1, "Threads[0]"));
        assert!(!snap.has_entry(1, "Threads[2]"));

        let children = snap.children_of(1);
        assert_eq!(children.len(), 3);
    }

    #[test]
    fn test_target_tree_snapshot_empty() {
        let snap = TargetTreeSnapshot::new(0);
        assert!(snap.is_empty());
        assert_eq!(snap.children_of(0).len(), 0);
    }

    #[test]
    fn test_change_collector() {
        let mut collector = ChangeCollector::new();
        let event = ValueChangeEvent::new(ValueChangeKind::Inserted, 1, "test", 0, 0);
        collector.value_inserted(&event);
        collector.value_deleted(&event);
        assert_eq!(collector.events.len(), 2);

        collector.clear();
        assert!(collector.events.is_empty());
    }

    #[test]
    fn test_change_listener_default_methods() {
        struct MinimalListener;
        impl TraceObjectChangeListener for MinimalListener {
            fn value_inserted(&mut self, _: &ValueChangeEvent) {}
            fn value_mutated(&mut self, _: &ValueChangeEvent) {}
            fn value_deleted(&mut self, _: &ValueChangeEvent) {}
        }

        let mut listener = MinimalListener;
        listener.object_created(42);
        listener.object_deleted(42);
    }

    #[test]
    fn test_change_event_serde() {
        let event = ValueChangeEvent::new(ValueChangeKind::Mutated, 1, "attr", 0, 5);
        let json = serde_json::to_string(&event).unwrap();
        let back: ValueChangeEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, ValueChangeKind::Mutated);
    }

    #[test]
    fn test_snapshot_serde() {
        let mut snap = TargetTreeSnapshot::new(0);
        snap.add_entry(1, "test", Some(10));
        let json = serde_json::to_string(&snap).unwrap();
        let back: TargetTreeSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
    }
}
