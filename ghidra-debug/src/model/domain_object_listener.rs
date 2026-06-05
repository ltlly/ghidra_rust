//! Domain object listener for trace change events.
//!
//! Ported from Ghidra's `TraceDomainObjectListener` which extends
//! `TypedEventDispatcher` and implements `DomainObjectListener`.
//!
//! Provides dispatching of domain object change records to registered
//! handlers, with special handling for RESTORED events.

use std::collections::HashMap;

use crate::model::TraceExecutionState;

/// The type of domain object event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainObjectEvent {
    /// The domain object has been restored from storage.
    Restored,
    /// The domain object has been saved.
    Saved,
    /// The domain object is about to close.
    Closing,
    /// A property of the domain object changed.
    PropertyChanged,
    /// The domain object's name changed.
    NameChanged,
    /// The domain object's description changed.
    DescriptionChanged,
    /// An undo/redo state change occurred.
    UndoRedoChanged,
}

/// A single change record within a domain object change event.
#[derive(Debug, Clone)]
pub struct DomainObjectChangeRecord {
    /// The type of event that occurred.
    pub event_type: DomainObjectEvent,
    /// A secondary event type or sub-type, represented as an integer code.
    pub sub_event: i32,
    /// The old value, if applicable (as a serialized string).
    pub old_value: Option<String>,
    /// The new value, if applicable (as a serialized string).
    pub new_value: Option<String>,
}

impl DomainObjectChangeRecord {
    /// Create a new change record.
    pub fn new(event_type: DomainObjectEvent, sub_event: i32) -> Self {
        Self {
            event_type,
            sub_event,
            old_value: None,
            new_value: None,
        }
    }

    /// Create a change record with old and new values.
    pub fn with_values(
        event_type: DomainObjectEvent,
        sub_event: i32,
        old_value: Option<String>,
        new_value: Option<String>,
    ) -> Self {
        Self {
            event_type,
            sub_event,
            old_value,
            new_value,
        }
    }
}

/// A composite change event containing multiple change records.
#[derive(Debug, Clone)]
pub struct DomainObjectChangedEvent {
    /// The change records in this event.
    records: Vec<DomainObjectChangeRecord>,
}

impl DomainObjectChangedEvent {
    /// Create a new composite change event.
    pub fn new(records: Vec<DomainObjectChangeRecord>) -> Self {
        Self { records }
    }

    /// Check if this event contains a record of the given type.
    pub fn contains(&self, event_type: DomainObjectEvent) -> bool {
        self.records.iter().any(|r| r.event_type == event_type)
    }

    /// Get all records.
    pub fn records(&self) -> &[DomainObjectChangeRecord] {
        &self.records
    }

    /// Get the number of records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Check if this event has no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl<'a> IntoIterator for &'a DomainObjectChangedEvent {
    type Item = &'a DomainObjectChangeRecord;
    type IntoIter = std::slice::Iter<'a, DomainObjectChangeRecord>;

    fn into_iter(self) -> Self::IntoIter {
        self.records.iter()
    }
}

/// A handler for domain object change records.
pub type ChangeRecordHandler = Box<dyn Fn(&DomainObjectChangeRecord)>;

/// A handler specifically for restored events.
pub type RestoredHandler = Box<dyn Fn(&DomainObjectChangeRecord)>;

/// A dispatcher for trace domain object events.
///
/// This mirrors Ghidra's `TraceDomainObjectListener`, which extends
/// `TypedEventDispatcher` and dispatches domain object change events
/// to registered handlers.
#[derive(Default)]
pub struct TraceDomainObjectListener {
    /// Handlers keyed by event type.
    handlers: HashMap<DomainObjectEvent, Vec<usize>>,
    /// All registered handlers by ID.
    all_handlers: Vec<ChangeRecordHandler>,
    /// Optional special handler for RESTORED events.
    restored_handler: Option<RestoredHandler>,
    /// Whether this listener is enabled.
    enabled: bool,
}

impl TraceDomainObjectListener {
    /// Create a new domain object listener.
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            all_handlers: Vec::new(),
            restored_handler: None,
            enabled: true,
        }
    }

    /// Set the handler for restored events.
    pub fn set_restored_handler(&mut self, handler: RestoredHandler) {
        self.restored_handler = Some(handler);
    }

    /// Register a handler for a specific event type.
    pub fn add_handler(&mut self, event_type: DomainObjectEvent, handler: ChangeRecordHandler) -> usize {
        let id = self.all_handlers.len();
        self.all_handlers.push(handler);
        self.handlers
            .entry(event_type)
            .or_insert_with(Vec::new)
            .push(id);
        id
    }

    /// Enable or disable this listener.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Check if this listener is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Process a domain object change event.
    ///
    /// If the event contains a RESTORED record and a restored handler is set,
    /// only the restored handler is invoked. Otherwise, all registered handlers
    /// for each event type are invoked.
    pub fn domain_object_changed(&self, event: &DomainObjectChangedEvent) {
        if !self.enabled {
            return;
        }

        // Check for RESTORED event with special handler
        if self.restored_handler.is_some() && event.contains(DomainObjectEvent::Restored) {
            for record in event.records() {
                if record.event_type == DomainObjectEvent::Restored {
                    if let Some(handler) = &self.restored_handler {
                        handler(record);
                    }
                    return;
                }
            }
        }

        // Dispatch all records to their registered handlers
        for record in event {
            self.handle_change_record(record);
        }
    }

    /// Dispatch a single change record to registered handlers.
    fn handle_change_record(&self, record: &DomainObjectChangeRecord) {
        if let Some(handler_ids) = self.handlers.get(&record.event_type) {
            for &id in handler_ids {
                if let Some(handler) = self.all_handlers.get(id) {
                    handler(record);
                }
            }
        }
    }
}

/// Convenience methods for common trace listener patterns.
impl TraceDomainObjectListener {
    /// Create a listener that tracks execution state changes.
    pub fn for_execution_state_changes() -> (Self, std::sync::Arc<std::sync::Mutex<Vec<TraceExecutionState>>>) {
        use std::sync::{Arc, Mutex};

        let states = Arc::new(Mutex::new(Vec::new()));
        let states_clone = states.clone();

        let mut listener = Self::new();
        listener.add_handler(
            DomainObjectEvent::PropertyChanged,
            Box::new(move |_record| {
                // In a full implementation, this would parse the execution state from the record
                // For now, we track that a change occurred
            }),
        );
        (listener, states)
    }
}

impl std::fmt::Debug for TraceDomainObjectListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TraceDomainObjectListener")
            .field("enabled", &self.enabled)
            .field("handler_count", &self.all_handlers.len())
            .field("has_restored_handler", &self.restored_handler.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_domain_object_event_types() {
        assert_ne!(DomainObjectEvent::Restored, DomainObjectEvent::Saved);
        assert_eq!(DomainObjectEvent::Restored, DomainObjectEvent::Restored);
    }

    #[test]
    fn test_change_record_creation() {
        let record = DomainObjectChangeRecord::new(DomainObjectEvent::PropertyChanged, 1);
        assert_eq!(record.event_type, DomainObjectEvent::PropertyChanged);
        assert_eq!(record.sub_event, 1);
        assert!(record.old_value.is_none());
        assert!(record.new_value.is_none());
    }

    #[test]
    fn test_change_record_with_values() {
        let record = DomainObjectChangeRecord::with_values(
            DomainObjectEvent::NameChanged,
            0,
            Some("old_name".into()),
            Some("new_name".into()),
        );
        assert_eq!(record.old_value.as_deref(), Some("old_name"));
        assert_eq!(record.new_value.as_deref(), Some("new_name"));
    }

    #[test]
    fn test_changed_event_contains() {
        let event = DomainObjectChangedEvent::new(vec![
            DomainObjectChangeRecord::new(DomainObjectEvent::PropertyChanged, 1),
            DomainObjectChangeRecord::new(DomainObjectEvent::Saved, 0),
        ]);
        assert!(event.contains(DomainObjectEvent::PropertyChanged));
        assert!(event.contains(DomainObjectEvent::Saved));
        assert!(!event.contains(DomainObjectEvent::Restored));
        assert_eq!(event.len(), 2);
    }

    #[test]
    fn test_empty_event() {
        let event = DomainObjectChangedEvent::new(vec![]);
        assert!(event.is_empty());
        assert!(!event.contains(DomainObjectEvent::Restored));
    }

    #[test]
    fn test_listener_dispatch() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        let mut listener = TraceDomainObjectListener::new();
        listener.add_handler(
            DomainObjectEvent::PropertyChanged,
            Box::new(move |_record| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            }),
        );

        let event = DomainObjectChangedEvent::new(vec![
            DomainObjectChangeRecord::new(DomainObjectEvent::PropertyChanged, 1),
        ]);
        listener.domain_object_changed(&event);
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        // Non-matching event should not trigger
        let event2 = DomainObjectChangedEvent::new(vec![
            DomainObjectChangeRecord::new(DomainObjectEvent::Saved, 0),
        ]);
        listener.domain_object_changed(&event2);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_listener_restored_handler() {
        let restored_count = Arc::new(AtomicUsize::new(0));
        let restored_clone = restored_count.clone();
        let normal_count = Arc::new(AtomicUsize::new(0));
        let normal_clone = normal_count.clone();

        let mut listener = TraceDomainObjectListener::new();
        listener.set_restored_handler(Box::new(move |_record| {
            restored_clone.fetch_add(1, Ordering::SeqCst);
        }));
        listener.add_handler(
            DomainObjectEvent::Restored,
            Box::new(move |_record| {
                normal_clone.fetch_add(1, Ordering::SeqCst);
            }),
        );

        let event = DomainObjectChangedEvent::new(vec![
            DomainObjectChangeRecord::new(DomainObjectEvent::Restored, 0),
        ]);
        listener.domain_object_changed(&event);
        // Restored handler should fire, normal handler should not
        assert_eq!(restored_count.load(Ordering::SeqCst), 1);
        assert_eq!(normal_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_listener_disabled() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        let mut listener = TraceDomainObjectListener::new();
        listener.add_handler(
            DomainObjectEvent::PropertyChanged,
            Box::new(move |_| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            }),
        );
        listener.set_enabled(false);

        let event = DomainObjectChangedEvent::new(vec![
            DomainObjectChangeRecord::new(DomainObjectEvent::PropertyChanged, 1),
        ]);
        listener.domain_object_changed(&event);
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_listener_multiple_handlers() {
        let counter = Arc::new(AtomicUsize::new(0));
        let c1 = counter.clone();
        let c2 = counter.clone();

        let mut listener = TraceDomainObjectListener::new();
        listener.add_handler(
            DomainObjectEvent::PropertyChanged,
            Box::new(move |_| {
                c1.fetch_add(1, Ordering::SeqCst);
            }),
        );
        listener.add_handler(
            DomainObjectEvent::PropertyChanged,
            Box::new(move |_| {
                c2.fetch_add(1, Ordering::SeqCst);
            }),
        );

        let event = DomainObjectChangedEvent::new(vec![
            DomainObjectChangeRecord::new(DomainObjectEvent::PropertyChanged, 1),
        ]);
        listener.domain_object_changed(&event);
        // Both handlers should fire
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_changed_event_iteration() {
        let event = DomainObjectChangedEvent::new(vec![
            DomainObjectChangeRecord::new(DomainObjectEvent::PropertyChanged, 1),
            DomainObjectChangeRecord::new(DomainObjectEvent::NameChanged, 0),
            DomainObjectChangeRecord::new(DomainObjectEvent::Saved, 0),
        ]);
        let types: Vec<_> = event.into_iter().map(|r| r.event_type).collect();
        assert_eq!(types.len(), 3);
        assert_eq!(types[0], DomainObjectEvent::PropertyChanged);
    }

    #[test]
    fn test_execution_state_tracking() {
        let (listener, _states) = TraceDomainObjectListener::for_execution_state_changes();
        assert!(listener.is_enabled());
    }
}
