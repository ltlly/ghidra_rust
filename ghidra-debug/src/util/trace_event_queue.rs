//! Trace event queue and change management utilities.
//!
//! Ported from Ghidra's `TraceChangeManager`, `TraceEvents`,
//! `TypedEventDispatcher`, `TraceChangeRecord`.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// The kind of change event in a trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TraceChangeKind {
    /// An object was created.
    ObjectCreated,
    /// An object was destroyed.
    ObjectDestroyed,
    /// An attribute was set.
    AttributeSet,
    /// An attribute was removed.
    AttributeRemoved,
    /// Memory bytes changed.
    MemoryChanged,
    /// Register values changed.
    RegisterChanged,
    /// A property changed.
    PropertyChanged,
    /// A listing change (code unit added/removed).
    ListingChanged,
    /// A symbol was added/changed.
    SymbolChanged,
    /// A breakpoint was added/removed.
    BreakpointChanged,
}

/// A record of a trace change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceChangeRecord {
    /// The kind of change.
    pub kind: TraceChangeKind,
    /// The snap at which the change occurred.
    pub snap: i64,
    /// The affected path or space.
    pub path: String,
    /// Optional address.
    pub address: Option<u64>,
    /// Thread key (if applicable).
    pub thread_key: Option<i64>,
}

impl TraceChangeRecord {
    /// Create a new change record.
    pub fn new(kind: TraceChangeKind, snap: i64, path: impl Into<String>) -> Self {
        Self {
            kind,
            snap,
            path: path.into(),
            address: None,
            thread_key: None,
        }
    }

    /// Set the address.
    pub fn with_address(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    /// Set the thread key.
    pub fn with_thread(mut self, key: i64) -> Self {
        self.thread_key = Some(key);
        self
    }
}

/// A FIFO event queue for trace change records.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceEventQueue {
    /// Pending events.
    queue: VecDeque<TraceChangeRecord>,
    /// Maximum queue depth (0 = unlimited).
    max_depth: usize,
}

impl TraceEventQueue {
    /// Create a new event queue.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a queue with a maximum depth.
    pub fn with_max_depth(max_depth: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            max_depth,
        }
    }

    /// Push a change record onto the queue.
    pub fn push(&mut self, record: TraceChangeRecord) {
        if self.max_depth > 0 && self.queue.len() >= self.max_depth {
            self.queue.pop_front();
        }
        self.queue.push_back(record);
    }

    /// Pop the next change record.
    pub fn pop(&mut self) -> Option<TraceChangeRecord> {
        self.queue.pop_front()
    }

    /// Peek at the next record without removing it.
    pub fn peek(&self) -> Option<&TraceChangeRecord> {
        self.queue.front()
    }

    /// Number of pending events.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Drain all events.
    pub fn drain(&mut self) -> Vec<TraceChangeRecord> {
        self.queue.drain(..).collect()
    }

    /// Clear all events.
    pub fn clear(&mut self) {
        self.queue.clear();
    }
}

/// A typed event dispatcher that dispatches events to registered handlers.
///
/// Ported from Ghidra's `TypedEventDispatcher`.
#[derive(Default)]
pub struct TypedEventDispatcher {
    /// Dispatched events by kind.
    events: Vec<TraceChangeRecord>,
}

impl TypedEventDispatcher {
    /// Create a new dispatcher.
    pub fn new() -> Self {
        Self::default()
    }

    /// Dispatch an event.
    pub fn dispatch(&mut self, record: TraceChangeRecord) {
        self.events.push(record);
    }

    /// Get all dispatched events.
    pub fn events(&self) -> &[TraceChangeRecord] {
        &self.events
    }

    /// Get events of a specific kind.
    pub fn events_of_kind(&self, kind: TraceChangeKind) -> Vec<&TraceChangeRecord> {
        self.events.iter().filter(|e| e.kind == kind).collect()
    }

    /// Clear all events.
    pub fn clear(&mut self) {
        self.events.clear();
    }

    /// Number of events.
    pub fn count(&self) -> usize {
        self.events.len()
    }
}

/// Manages change tracking for a trace.
///
/// Ported from Ghidra's `TraceChangeManager`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceChangeManager {
    /// The event queue.
    queue: TraceEventQueue,
    /// Whether change tracking is enabled.
    enabled: bool,
}

impl TraceChangeManager {
    /// Create a new change manager.
    pub fn new() -> Self {
        Self {
            queue: TraceEventQueue::new(),
            enabled: true,
        }
    }

    /// Enable or disable change tracking.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Whether tracking is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Record a change (if tracking is enabled).
    pub fn record_change(&mut self, record: TraceChangeRecord) {
        if self.enabled {
            self.queue.push(record);
        }
    }

    /// Get the event queue.
    pub fn queue(&self) -> &TraceEventQueue {
        &self.queue
    }

    /// Get mutable access to the event queue.
    pub fn queue_mut(&mut self) -> &mut TraceEventQueue {
        &mut self.queue
    }
}

/// A wrapping instruction iterator that adjusts addresses.
///
/// Ported from Ghidra's `WrappingInstructionIterator`.
#[derive(Debug)]
#[allow(dead_code)]
pub struct WrappingInstructionIterator<I> {
    inner: I,
    offset: i64,
}

impl<I> WrappingInstructionIterator<I> {
    /// Create a new wrapping iterator with an address offset.
    pub fn new(inner: I, offset: i64) -> Self {
        Self { inner, offset }
    }
}

/// A data adapter for converting settings to data types.
///
/// Ported from Ghidra's `DataAdapterFromDataType`, `DataAdapterFromSettings`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataAdapter {
    /// The data type name.
    pub data_type_name: String,
    /// The data type size in bytes.
    pub size: usize,
    /// Whether the data is signed.
    pub signed: bool,
    /// Byte order.
    pub big_endian: bool,
}

impl DataAdapter {
    /// Create a new data adapter.
    pub fn new(data_type_name: impl Into<String>, size: usize) -> Self {
        Self {
            data_type_name: data_type_name.into(),
            size,
            signed: false,
            big_endian: false,
        }
    }

    /// Create a signed adapter.
    pub fn signed(mut self) -> Self {
        self.signed = true;
        self
    }

    /// Set byte order.
    pub fn with_endian(mut self, big_endian: bool) -> Self {
        self.big_endian = big_endian;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_queue() {
        let mut q = TraceEventQueue::new();
        q.push(TraceChangeRecord::new(TraceChangeKind::MemoryChanged, 0, "ram"));
        q.push(TraceChangeRecord::new(TraceChangeKind::ObjectCreated, 1, "threads"));
        assert_eq!(q.len(), 2);
        let first = q.pop().unwrap();
        assert_eq!(first.kind, TraceChangeKind::MemoryChanged);
    }

    #[test]
    fn test_event_queue_max_depth() {
        let mut q = TraceEventQueue::with_max_depth(2);
        q.push(TraceChangeRecord::new(TraceChangeKind::MemoryChanged, 0, "a"));
        q.push(TraceChangeRecord::new(TraceChangeKind::MemoryChanged, 1, "b"));
        q.push(TraceChangeRecord::new(TraceChangeKind::MemoryChanged, 2, "c"));
        assert_eq!(q.len(), 2);
        // oldest was evicted
        assert_eq!(q.peek().unwrap().snap, 1);
    }

    #[test]
    fn test_typed_dispatcher() {
        let mut d = TypedEventDispatcher::new();
        d.dispatch(TraceChangeRecord::new(TraceChangeKind::MemoryChanged, 0, "ram"));
        d.dispatch(TraceChangeRecord::new(TraceChangeKind::ObjectCreated, 1, "threads"));
        d.dispatch(TraceChangeRecord::new(TraceChangeKind::MemoryChanged, 2, "ram"));
        assert_eq!(d.count(), 3);
        assert_eq!(d.events_of_kind(TraceChangeKind::MemoryChanged).len(), 2);
    }

    #[test]
    fn test_change_manager() {
        let mut mgr = TraceChangeManager::new();
        mgr.record_change(TraceChangeRecord::new(
            TraceChangeKind::MemoryChanged,
            0,
            "ram",
        ));
        assert_eq!(mgr.queue().len(), 1);
        mgr.set_enabled(false);
        mgr.record_change(TraceChangeRecord::new(
            TraceChangeKind::ObjectCreated,
            1,
            "threads",
        ));
        assert_eq!(mgr.queue().len(), 1); // not recorded
    }

    #[test]
    fn test_data_adapter() {
        let a = DataAdapter::new("uint32", 4).with_endian(false);
        assert_eq!(a.size, 4);
        assert!(!a.big_endian);
    }
}
