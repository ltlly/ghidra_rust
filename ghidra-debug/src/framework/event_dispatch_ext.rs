//! Extended event dispatch types for the trace framework.
//!
//! Ported from Ghidra's `ghidra.framework.data.DomainObjectEventQueues`
//! and related event dispatch utilities in Framework-TraceModeling.
//!
//! Provides:
//! - `EventPriority`: Event dispatch priority levels.
//! - `EventSubscription`: A subscription to an event type.
//! - `DispatchQueue`: An ordered queue for event dispatch.
//! - `BatchDispatcher`: Groups events for batch delivery.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

/// Priority levels for event dispatch.
///
/// Higher-priority events are dispatched before lower-priority ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EventPriority {
    /// Background events, dispatched when idle.
    Low = 0,
    /// Normal priority (default).
    Normal = 1,
    /// High priority, dispatched immediately.
    High = 2,
    /// Critical events, always dispatched first.
    Critical = 3,
}

impl Default for EventPriority {
    fn default() -> Self {
        EventPriority::Normal
    }
}

/// A subscription to an event type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSubscription {
    /// Unique subscription ID.
    pub id: u64,
    /// The event type name.
    pub event_type: String,
    /// The dispatch priority.
    pub priority: EventPriority,
    /// Whether this subscription is currently active.
    pub active: bool,
}

impl EventSubscription {
    /// Create a new event subscription.
    pub fn new(id: u64, event_type: impl Into<String>, priority: EventPriority) -> Self {
        Self {
            id,
            event_type: event_type.into(),
            priority,
            active: true,
        }
    }

    /// Deactivate this subscription.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Activate this subscription.
    pub fn activate(&mut self) {
        self.active = true;
    }
}

/// A pending event in the dispatch queue.
#[derive(Debug, Clone)]
pub struct PendingEvent {
    /// The event type name.
    pub event_type: String,
    /// The event priority.
    pub priority: EventPriority,
    /// The event payload (serialized as opaque bytes).
    pub payload: Vec<u8>,
    /// Monotonic sequence number for ordering.
    pub sequence: u64,
}

/// An ordered queue for event dispatch.
///
/// Events are dispatched in priority order (highest first), with
/// FIFO ordering within the same priority level.
#[derive(Debug)]
pub struct DispatchQueue {
    /// Queues per priority level.
    queues: BTreeMap<EventPriority, VecDeque<PendingEvent>>,
    /// Monotonic sequence counter.
    next_sequence: AtomicU64,
    /// Whether dispatching is currently paused.
    paused: bool,
}

impl DispatchQueue {
    /// Create a new empty dispatch queue.
    pub fn new() -> Self {
        Self {
            queues: BTreeMap::new(),
            next_sequence: AtomicU64::new(1),
            paused: false,
        }
    }

    /// Enqueue an event.
    pub fn enqueue(&mut self, event_type: impl Into<String>, priority: EventPriority, payload: Vec<u8>) {
        let seq = self.next_sequence.fetch_add(1, Ordering::Relaxed);
        let event = PendingEvent {
            event_type: event_type.into(),
            priority,
            payload,
            sequence: seq,
        };
        self.queues
            .entry(priority)
            .or_insert_with(VecDeque::new)
            .push_back(event);
    }

    /// Dequeue the highest-priority event.
    pub fn dequeue(&mut self) -> Option<PendingEvent> {
        if self.paused {
            return None;
        }
        // Iterate from highest to lowest priority
        for (_prio, queue) in self.queues.iter_mut().rev() {
            if let Some(event) = queue.pop_front() {
                return Some(event);
            }
        }
        None
    }

    /// Get the total number of pending events.
    pub fn pending_count(&self) -> usize {
        self.queues.values().map(|q| q.len()).sum()
    }

    /// Check if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queues.values().all(|q| q.is_empty())
    }

    /// Pause event dispatch.
    pub fn pause(&mut self) {
        self.paused = true;
    }

    /// Resume event dispatch.
    pub fn resume(&mut self) {
        self.paused = false;
    }

    /// Whether dispatching is paused.
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Drain all events, respecting priority order.
    pub fn drain(&mut self) -> Vec<PendingEvent> {
        let mut result = Vec::new();
        for (_prio, queue) in self.queues.iter_mut().rev() {
            result.extend(queue.drain(..));
        }
        result
    }
}

impl Default for DispatchQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Groups events for batch delivery.
///
/// Events accumulated in a batch are delivered together when the batch
/// is flushed, reducing the overhead of individual event dispatches.
#[derive(Debug)]
pub struct BatchDispatcher {
    /// The batch of accumulated events.
    batch: Vec<PendingEvent>,
    /// The maximum batch size before auto-flush.
    max_batch_size: usize,
    /// Monotonic sequence counter.
    next_sequence: AtomicU64,
}

impl BatchDispatcher {
    /// Create a new batch dispatcher.
    pub fn new(max_batch_size: usize) -> Self {
        Self {
            batch: Vec::new(),
            max_batch_size,
            next_sequence: AtomicU64::new(1),
        }
    }

    /// Add an event to the current batch.
    ///
    /// Returns true if the batch was auto-flushed due to reaching max size.
    pub fn add(&mut self, event_type: impl Into<String>, priority: EventPriority, payload: Vec<u8>) -> bool {
        let seq = self.next_sequence.fetch_add(1, Ordering::Relaxed);
        self.batch.push(PendingEvent {
            event_type: event_type.into(),
            priority,
            payload,
            sequence: seq,
        });
        self.batch.len() >= self.max_batch_size
    }

    /// Flush the current batch, returning all accumulated events.
    pub fn flush(&mut self) -> Vec<PendingEvent> {
        std::mem::take(&mut self.batch)
    }

    /// Get the number of events in the current batch.
    pub fn batch_size(&self) -> usize {
        self.batch.len()
    }

    /// Check if the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.batch.is_empty()
    }
}

impl Default for BatchDispatcher {
    fn default() -> Self {
        Self::new(100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_priority_ordering() {
        assert!(EventPriority::Critical > EventPriority::High);
        assert!(EventPriority::High > EventPriority::Normal);
        assert!(EventPriority::Normal > EventPriority::Low);
    }

    #[test]
    fn test_event_subscription() {
        let mut sub = EventSubscription::new(1, "TraceActivated", EventPriority::High);
        assert!(sub.active);
        assert_eq!(sub.event_type, "TraceActivated");

        sub.deactivate();
        assert!(!sub.active);

        sub.activate();
        assert!(sub.active);
    }

    #[test]
    fn test_dispatch_queue_enqueue_dequeue() {
        let mut queue = DispatchQueue::new();
        assert!(queue.is_empty());

        queue.enqueue("low_event", EventPriority::Low, vec![1]);
        queue.enqueue("high_event", EventPriority::High, vec![2]);
        queue.enqueue("critical_event", EventPriority::Critical, vec![3]);
        queue.enqueue("normal_event", EventPriority::Normal, vec![4]);

        assert_eq!(queue.pending_count(), 4);

        // Critical first
        let event = queue.dequeue().unwrap();
        assert_eq!(event.event_type, "critical_event");

        // Then high
        let event = queue.dequeue().unwrap();
        assert_eq!(event.event_type, "high_event");

        // Then normal
        let event = queue.dequeue().unwrap();
        assert_eq!(event.event_type, "normal_event");

        // Then low
        let event = queue.dequeue().unwrap();
        assert_eq!(event.event_type, "low_event");

        assert!(queue.dequeue().is_none());
    }

    #[test]
    fn test_dispatch_queue_fifo_within_priority() {
        let mut queue = DispatchQueue::new();
        queue.enqueue("first", EventPriority::Normal, vec![]);
        queue.enqueue("second", EventPriority::Normal, vec![]);
        queue.enqueue("third", EventPriority::Normal, vec![]);

        assert_eq!(queue.dequeue().unwrap().event_type, "first");
        assert_eq!(queue.dequeue().unwrap().event_type, "second");
        assert_eq!(queue.dequeue().unwrap().event_type, "third");
    }

    #[test]
    fn test_dispatch_queue_pause_resume() {
        let mut queue = DispatchQueue::new();
        queue.enqueue("event", EventPriority::Normal, vec![]);

        queue.pause();
        assert!(queue.dequeue().is_none());

        queue.resume();
        assert!(queue.dequeue().is_some());
    }

    #[test]
    fn test_dispatch_queue_drain() {
        let mut queue = DispatchQueue::new();
        queue.enqueue("a", EventPriority::Low, vec![]);
        queue.enqueue("b", EventPriority::High, vec![]);
        queue.enqueue("c", EventPriority::Normal, vec![]);

        let events = queue.drain();
        assert_eq!(events.len(), 3);
        assert!(queue.is_empty());
    }

    #[test]
    fn test_batch_dispatcher() {
        let mut batch = BatchDispatcher::new(3);
        assert!(batch.is_empty());

        batch.add("a", EventPriority::Normal, vec![]);
        batch.add("b", EventPriority::Normal, vec![]);
        assert_eq!(batch.batch_size(), 2);

        // Third triggers auto-flush indication
        let should_flush = batch.add("c", EventPriority::Normal, vec![]);
        assert!(should_flush);

        // The batch still holds the events; caller should flush
        let events = batch.flush();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].event_type, "a");
        assert_eq!(events[2].event_type, "c");

        // Test manual flush with new events
        batch.add("d", EventPriority::High, vec![]);
        let events = batch.flush();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "d");
    }
}
