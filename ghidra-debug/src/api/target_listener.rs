//! Target publication and object change listeners.
//!
//! Ported from Ghidra's `TargetPublicationListener`, `TraceObjectChangeListener`.

use serde::{Deserialize, Serialize};

/// The kind of change that occurred on a target object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetChangeKind {
    /// A new object was created.
    Created,
    /// An existing object was modified.
    Modified,
    /// An object was deleted.
    Deleted,
    /// An attribute was added.
    AttributeAdded,
    /// An attribute was removed.
    AttributeRemoved,
    /// An attribute's value changed.
    AttributeChanged,
    /// An object was activated (focused).
    Activated,
    /// An object was deactivated.
    Deactivated,
}

/// A record of a change on a target object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetChangeRecord {
    /// The object path that changed.
    pub path: String,
    /// The kind of change.
    pub kind: TargetChangeKind,
    /// The snap at which the change occurred.
    pub snap: i64,
    /// The attribute name (for attribute changes).
    pub attribute: Option<String>,
    /// Optional old value (JSON-encoded).
    pub old_value: Option<String>,
    /// Optional new value (JSON-encoded).
    pub new_value: Option<String>,
}

impl TargetChangeRecord {
    /// Create a new change record.
    pub fn new(path: impl Into<String>, kind: TargetChangeKind, snap: i64) -> Self {
        Self {
            path: path.into(),
            kind,
            snap,
            attribute: None,
            old_value: None,
            new_value: None,
        }
    }

    /// Set attribute information.
    pub fn with_attribute(mut self, attr: impl Into<String>) -> Self {
        self.attribute = Some(attr.into());
        self
    }

    /// Set old/new values.
    pub fn with_values(mut self, old: Option<String>, new: Option<String>) -> Self {
        self.old_value = old;
        self.new_value = new;
        self
    }
}

/// A listener for target publication events.
///
/// In Java this is `TargetPublicationListener<T>`, generic over the target object type.
/// In Rust we use a trait-based approach.
pub trait TargetPublicationListener: Send + Sync {
    /// Called when a target is published (made available).
    fn on_published(&self, path: &str);
    /// Called when a target is unpublished (removed).
    fn on_unpublished(&self, path: &str);
}

/// A listener for changes to trace objects.
pub trait TraceObjectChangeListener: Send + Sync {
    /// Called when objects change in a trace.
    fn on_change(&self, record: &TargetChangeRecord);
}

/// A simple in-memory event dispatcher for target change events.
#[derive(Default)]
pub struct TargetChangeDispatcher {
    /// Collected change records.
    records: Vec<TargetChangeRecord>,
}

impl TargetChangeDispatcher {
    /// Create a new dispatcher.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a change.
    pub fn record(&mut self, change: TargetChangeRecord) {
        self.records.push(change);
    }

    /// Get all recorded changes.
    pub fn records(&self) -> &[TargetChangeRecord] {
        &self.records
    }

    /// Clear all recorded changes.
    pub fn clear(&mut self) {
        self.records.clear();
    }

    /// Number of recorded changes.
    pub fn count(&self) -> usize {
        self.records.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_change_record() {
        let r = TargetChangeRecord::new("Threads[1]", TargetChangeKind::Created, 0)
            .with_attribute("_name");
        assert_eq!(r.path, "Threads[1]");
        assert_eq!(r.kind, TargetChangeKind::Created);
        assert_eq!(r.attribute.as_deref(), Some("_name"));
    }

    #[test]
    fn test_dispatcher() {
        let mut d = TargetChangeDispatcher::new();
        d.record(TargetChangeRecord::new("a", TargetChangeKind::Created, 0));
        d.record(TargetChangeRecord::new("b", TargetChangeKind::Modified, 1));
        assert_eq!(d.count(), 2);
        d.clear();
        assert_eq!(d.count(), 0);
    }
}
