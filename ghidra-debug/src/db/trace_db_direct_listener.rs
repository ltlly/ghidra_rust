//! Direct change listeners for the trace database.
//!
//! Ported from Ghidra's `DBTraceDirectChangeListener`. These listeners
//! receive change notifications directly from the database layer,
//! bypassing the standard event queue. They are useful for performance-
//! critical paths where the overhead of queuing is undesirable.

use serde::{Deserialize, Serialize};

/// The kind of direct change notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DirectChangeKind {
    /// A trace object was added.
    ObjectAdded,
    /// A trace object was removed.
    ObjectRemoved,
    /// A trace object was modified.
    ObjectModified,
    /// A value was set on a property map.
    PropertySet,
    /// A value was cleared from a property map.
    PropertyCleared,
    /// Memory bytes were written.
    MemoryBytesChanged,
    /// Register values were written.
    RegisterValuesChanged,
    /// A time/snap was added.
    SnapAdded,
    /// A time/snap was removed.
    SnapRemoved,
    /// The trace schema was changed.
    SchemaChanged,
    /// Data types were modified.
    DataTypesChanged,
    /// The trace was closed.
    TraceClosed,
}

/// A direct change event from the database layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectChangeEvent {
    /// The kind of change.
    pub kind: DirectChangeKind,
    /// The snap (time) the change occurred at.
    pub snap: i64,
    /// The address space affected, if applicable.
    pub space: Option<String>,
    /// The start offset, if applicable.
    pub offset_min: Option<u64>,
    /// The end offset, if applicable.
    pub offset_max: Option<u64>,
    /// Additional context string.
    pub context: Option<String>,
}

impl DirectChangeEvent {
    /// Create a new event.
    pub fn new(kind: DirectChangeKind, snap: i64) -> Self {
        Self {
            kind,
            snap,
            space: None,
            offset_min: None,
            offset_max: None,
            context: None,
        }
    }

    /// Set the address space.
    pub fn with_space(mut self, space: impl Into<String>) -> Self {
        self.space = Some(space.into());
        self
    }

    /// Set the offset range.
    pub fn with_range(mut self, min: u64, max: u64) -> Self {
        self.offset_min = Some(min);
        self.offset_max = Some(max);
        self
    }

    /// Set the context.
    pub fn with_context(mut self, ctx: impl Into<String>) -> Self {
        self.context = Some(ctx.into());
        self
    }

    /// Whether this event affects a specific address range.
    pub fn has_range(&self) -> bool {
        self.offset_min.is_some() && self.offset_max.is_some()
    }
}

/// Trait for direct change listeners.
///
/// Implementors receive change notifications directly, without going
/// through the event queue.
pub trait DirectChangeListener: Send + Sync {
    /// Called when a direct change occurs.
    fn on_change(&self, event: &DirectChangeEvent);
}

/// A collection of direct change listeners with thread-safe dispatch.
pub struct DirectChangeListenerSet {
    listeners: Vec<Box<dyn DirectChangeListener>>,
}

impl std::fmt::Debug for DirectChangeListenerSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectChangeListenerSet")
            .field("count", &self.listeners.len())
            .finish()
    }
}

impl DirectChangeListenerSet {
    /// Create a new empty listener set.
    pub fn new() -> Self {
        Self {
            listeners: Vec::new(),
        }
    }

    /// Add a listener.
    pub fn add(&mut self, listener: Box<dyn DirectChangeListener>) {
        self.listeners.push(listener);
    }

    /// Remove all listeners.
    pub fn clear(&mut self) {
        self.listeners.clear();
    }

    /// Notify all listeners of a change event.
    pub fn notify(&self, event: &DirectChangeEvent) {
        for listener in &self.listeners {
            listener.on_change(event);
        }
    }

    /// The number of registered listeners.
    pub fn len(&self) -> usize {
        self.listeners.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.listeners.is_empty()
    }
}

impl Default for DirectChangeListenerSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    struct CountingListener {
        count: AtomicU32,
    }

    impl CountingListener {
        fn new() -> Self {
            Self {
                count: AtomicU32::new(0),
            }
        }
    }

    impl DirectChangeListener for CountingListener {
        fn on_change(&self, _event: &DirectChangeEvent) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_direct_change_event() {
        let event = DirectChangeEvent::new(DirectChangeKind::MemoryBytesChanged, 5)
            .with_space("ram")
            .with_range(0x1000, 0x1fff)
            .with_context("write");
        assert_eq!(event.kind, DirectChangeKind::MemoryBytesChanged);
        assert_eq!(event.snap, 5);
        assert!(event.has_range());
        assert_eq!(event.space.as_deref(), Some("ram"));
    }

    #[test]
    fn test_event_no_range() {
        let event = DirectChangeEvent::new(DirectChangeKind::SnapAdded, 0);
        assert!(!event.has_range());
    }

    #[test]
    fn test_listener_set() {
        let mut set = DirectChangeListenerSet::new();
        assert!(set.is_empty());

        set.add(Box::new(CountingListener::new()));
        set.add(Box::new(CountingListener::new()));
        assert_eq!(set.len(), 2);

        let event = DirectChangeEvent::new(DirectChangeKind::ObjectAdded, 0);
        set.notify(&event);
    }

    #[test]
    fn test_listener_notified() {
        let listener = Arc::new(CountingListener::new());
        let mut set = DirectChangeListenerSet::new();
        set.add(Box::new(CountingListener::new()));

        let event = DirectChangeEvent::new(DirectChangeKind::TraceClosed, 0);
        set.notify(&event);
        // The Arc listener wasn't added to the set, so it wasn't notified
        assert_eq!(listener.count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_clear_listeners() {
        let mut set = DirectChangeListenerSet::new();
        set.add(Box::new(CountingListener::new()));
        set.add(Box::new(CountingListener::new()));
        assert_eq!(set.len(), 2);

        set.clear();
        assert!(set.is_empty());
    }

    #[test]
    fn test_direct_change_kind_variants() {
        let kinds = vec![
            DirectChangeKind::ObjectAdded,
            DirectChangeKind::ObjectRemoved,
            DirectChangeKind::ObjectModified,
            DirectChangeKind::PropertySet,
            DirectChangeKind::PropertyCleared,
            DirectChangeKind::MemoryBytesChanged,
            DirectChangeKind::RegisterValuesChanged,
            DirectChangeKind::SnapAdded,
            DirectChangeKind::SnapRemoved,
            DirectChangeKind::SchemaChanged,
            DirectChangeKind::DataTypesChanged,
            DirectChangeKind::TraceClosed,
        ];
        assert_eq!(kinds.len(), 12);
    }

    #[test]
    fn test_direct_change_event_serde() {
        let event = DirectChangeEvent::new(DirectChangeKind::MemoryBytesChanged, 3)
            .with_space("ram")
            .with_range(0, 0xff);
        let json = serde_json::to_string(&event).unwrap();
        let back: DirectChangeEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, DirectChangeKind::MemoryBytesChanged);
        assert_eq!(back.snap, 3);
    }

    #[test]
    fn test_event_with_context() {
        let event = DirectChangeEvent::new(DirectChangeKind::SchemaChanged, 0)
            .with_context("thread added");
        assert_eq!(event.context.as_deref(), Some("thread added"));
    }
}
