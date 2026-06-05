//! Domain object change tracking and event queue types.
//!
//! Ported from Ghidra's `DomainObjectEventQueues` and related types
//! in Framework-TraceModeling.
//!
//! Provides change tracking for domain objects, event queuing with
//! enable/disable controls, and change record types.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

/// The type of domain object change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainObjectChangeType {
    /// The domain object was saved.
    Saved,
    /// The domain object was closed.
    Closed,
    /// A property was changed.
    PropertyChanged,
    /// The domain object state changed.
    StateChanged,
    /// Content was added.
    ContentAdded,
    /// Content was removed.
    ContentRemoved,
    /// Content was modified.
    ContentModified,
    /// Undo was performed.
    Undo,
    /// Redo was performed.
    Redo,
}

/// A record of a domain object change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainObjectChangeRecord {
    /// The type of change.
    pub change_type: DomainObjectChangeType,
    /// The affected property name (if applicable).
    pub property_name: Option<String>,
    /// The old value (if applicable).
    pub old_value: Option<String>,
    /// The new value (if applicable).
    pub new_value: Option<String>,
    /// Timestamp of the change.
    pub timestamp: i64,
}

impl DomainObjectChangeRecord {
    /// Create a new change record.
    pub fn new(change_type: DomainObjectChangeType) -> Self {
        Self {
            change_type,
            property_name: None,
            old_value: None,
            new_value: None,
            timestamp: 0,
        }
    }

    /// Set the property name.
    pub fn with_property(mut self, name: impl Into<String>) -> Self {
        self.property_name = Some(name.into());
        self
    }

    /// Set the old and new values.
    pub fn with_values(mut self, old: impl Into<String>, new: impl Into<String>) -> Self {
        self.old_value = Some(old.into());
        self.new_value = Some(new.into());
        self
    }

    /// Set the timestamp.
    pub fn with_timestamp(mut self, ts: i64) -> Self {
        self.timestamp = ts;
        self
    }
}

/// An event queue for domain object events.
///
/// Events can be queued and then flushed when the domain object
/// commits a transaction.
///
/// Ported from Ghidra's `DomainObjectEventQueues`.
#[derive(Debug, Default)]
pub struct DomainObjectEventQueue {
    /// Pending events.
    queue: VecDeque<DomainObjectChangeRecord>,
    /// Whether the queue is enabled (events are accumulated).
    enabled: bool,
    /// The maximum queue size.
    max_size: usize,
}

impl DomainObjectEventQueue {
    /// Create a new event queue.
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            enabled: true,
            max_size: 10000,
        }
    }

    /// Create with a specific max size.
    pub fn with_max_size(mut self, max: usize) -> Self {
        self.max_size = max;
        self
    }

    /// Enable event accumulation.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable event accumulation.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Whether the queue is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Add an event to the queue.
    pub fn enqueue(&mut self, record: DomainObjectChangeRecord) {
        if !self.enabled {
            return;
        }
        if self.queue.len() >= self.max_size {
            self.queue.pop_front();
        }
        self.queue.push_back(record);
    }

    /// Drain and return all pending events.
    pub fn flush(&mut self) -> Vec<DomainObjectChangeRecord> {
        std::mem::take(&mut self.queue).into_iter().collect()
    }

    /// Get the number of pending events.
    pub fn pending_count(&self) -> usize {
        self.queue.len()
    }

    /// Whether there are pending events.
    pub fn has_pending(&self) -> bool {
        !self.queue.is_empty()
    }

    /// Clear all pending events.
    pub fn clear(&mut self) {
        self.queue.clear();
    }
}

/// Trait for domain objects that can track changes.
pub trait ChangeTrackable {
    /// Get the pending changes.
    fn pending_changes(&self) -> &[DomainObjectChangeRecord];

    /// Whether there are unsaved changes.
    fn has_unsaved_changes(&self) -> bool;

    /// Mark changes as saved.
    fn mark_saved(&mut self);
}

/// A simple change tracker implementation.
#[derive(Debug, Default)]
pub struct SimpleChangeTracker {
    changes: Vec<DomainObjectChangeRecord>,
    saved_count: usize,
}

impl SimpleChangeTracker {
    /// Create a new tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a change.
    pub fn record(&mut self, change: DomainObjectChangeRecord) {
        self.changes.push(change);
    }

    /// Get all changes.
    pub fn all_changes(&self) -> &[DomainObjectChangeRecord] {
        &self.changes
    }

    /// Get changes since the last save.
    pub fn changes_since_save(&self) -> &[DomainObjectChangeRecord] {
        &self.changes[self.saved_count..]
    }

    /// Get the total number of changes.
    pub fn total_changes(&self) -> usize {
        self.changes.len()
    }
}

impl ChangeTrackable for SimpleChangeTracker {
    fn pending_changes(&self) -> &[DomainObjectChangeRecord] {
        self.changes_since_save()
    }

    fn has_unsaved_changes(&self) -> bool {
        self.changes.len() > self.saved_count
    }

    fn mark_saved(&mut self) {
        self.saved_count = self.changes.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_object_change_record() {
        let record = DomainObjectChangeRecord::new(DomainObjectChangeType::PropertyChanged)
            .with_property("name")
            .with_values("old", "new")
            .with_timestamp(100);

        assert_eq!(record.change_type, DomainObjectChangeType::PropertyChanged);
        assert_eq!(record.property_name, Some("name".into()));
        assert_eq!(record.old_value, Some("old".into()));
        assert_eq!(record.new_value, Some("new".into()));
        assert_eq!(record.timestamp, 100);
    }

    #[test]
    fn test_event_queue_basic() {
        let mut queue = DomainObjectEventQueue::new();
        assert!(queue.is_enabled());

        queue.enqueue(DomainObjectChangeRecord::new(DomainObjectChangeType::Saved));
        queue.enqueue(DomainObjectChangeRecord::new(
            DomainObjectChangeType::ContentModified,
        ));

        assert_eq!(queue.pending_count(), 2);
        assert!(queue.has_pending());

        let events = queue.flush();
        assert_eq!(events.len(), 2);
        assert!(!queue.has_pending());
    }

    #[test]
    fn test_event_queue_disabled() {
        let mut queue = DomainObjectEventQueue::new();
        queue.disable();

        queue.enqueue(DomainObjectChangeRecord::new(DomainObjectChangeType::Saved));
        assert_eq!(queue.pending_count(), 0);
    }

    #[test]
    fn test_event_queue_max_size() {
        let mut queue = DomainObjectEventQueue::new().with_max_size(3);

        for _ in 0..5 {
            queue.enqueue(DomainObjectChangeRecord::new(
                DomainObjectChangeType::ContentModified,
            ));
        }

        // Only last 3 should remain
        assert_eq!(queue.pending_count(), 3);
    }

    #[test]
    fn test_simple_change_tracker() {
        let mut tracker = SimpleChangeTracker::new();

        tracker.record(DomainObjectChangeRecord::new(
            DomainObjectChangeType::ContentAdded,
        ));
        tracker.record(DomainObjectChangeRecord::new(
            DomainObjectChangeType::ContentModified,
        ));

        assert!(tracker.has_unsaved_changes());
        assert_eq!(tracker.pending_changes().len(), 2);

        tracker.mark_saved();
        assert!(!tracker.has_unsaved_changes());
        assert_eq!(tracker.pending_changes().len(), 0);

        tracker.record(DomainObjectChangeRecord::new(
            DomainObjectChangeType::ContentRemoved,
        ));
        assert!(tracker.has_unsaved_changes());
        assert_eq!(tracker.pending_changes().len(), 1);
    }

    #[test]
    fn test_change_type_variants() {
        let types = [
            DomainObjectChangeType::Saved,
            DomainObjectChangeType::Closed,
            DomainObjectChangeType::PropertyChanged,
            DomainObjectChangeType::StateChanged,
            DomainObjectChangeType::ContentAdded,
            DomainObjectChangeType::ContentRemoved,
            DomainObjectChangeType::ContentModified,
            DomainObjectChangeType::Undo,
            DomainObjectChangeType::Redo,
        ];

        // Ensure all variants are distinct
        for (i, a) in types.iter().enumerate() {
            for (j, b) in types.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn test_event_queue_clear() {
        let mut queue = DomainObjectEventQueue::new();
        queue.enqueue(DomainObjectChangeRecord::new(DomainObjectChangeType::Saved));
        queue.clear();
        assert!(!queue.has_pending());
    }
}
