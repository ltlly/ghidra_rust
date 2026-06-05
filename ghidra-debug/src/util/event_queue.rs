//! Domain object event queues.
//!
//! Ported from Ghidra's `DomainObjectEventQueues` class. Provides an
//! event queue management system for domain objects, supporting both
//! public and private event queues with configurable delivery delays.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use super::events::TraceChangeRecord;

/// A unique identifier for a private event queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventQueueId(u64);

impl EventQueueId {
    /// Create a new event queue ID with the given value.
    pub fn new(id: u64) -> Self {
        Self(id)
    }
}

/// The next event queue ID counter.
static NEXT_QUEUE_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl EventQueueId {
    /// Generate a new unique event queue ID.
    pub fn generate() -> Self {
        Self(NEXT_QUEUE_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
}

/// A pending event in the queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingEvent {
    /// The change record.
    pub record: TraceChangeRecord,
    /// The timestamp when the event was queued (milliseconds since epoch).
    pub timestamp: u64,
}

impl PendingEvent {
    /// Create a new pending event.
    pub fn new(record: TraceChangeRecord, timestamp: u64) -> Self {
        Self { record, timestamp }
    }
}

/// A single event queue with a listener ID and pending events.
#[derive(Debug)]
pub struct EventQueue {
    /// Unique identifier for this queue.
    pub id: EventQueueId,
    /// Maximum delay before flushing (milliseconds).
    pub max_delay_ms: u64,
    /// Pending events.
    pending: Vec<PendingEvent>,
    /// Whether this queue is active.
    active: bool,
    /// The listener name (for debugging).
    pub listener_name: String,
}

impl EventQueue {
    /// Create a new event queue.
    pub fn new(id: EventQueueId, max_delay_ms: u64) -> Self {
        Self {
            id,
            max_delay_ms,
            pending: Vec::new(),
            active: true,
            listener_name: String::new(),
        }
    }

    /// Create a new event queue with a listener name.
    pub fn with_listener_name(mut self, name: impl Into<String>) -> Self {
        self.listener_name = name.into();
        self
    }

    /// Enqueue an event.
    pub fn enqueue(&mut self, record: TraceChangeRecord, timestamp: u64) {
        if self.active {
            self.pending.push(PendingEvent::new(record, timestamp));
        }
    }

    /// Get all pending events and clear the queue.
    pub fn flush(&mut self) -> Vec<PendingEvent> {
        std::mem::take(&mut self.pending)
    }

    /// Whether there are pending events.
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// The number of pending events.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Whether this queue is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Deactivate this queue (no more events will be enqueued).
    pub fn deactivate(&mut self) {
        self.active = false;
        self.pending.clear();
    }
}

/// Manages event queues for a domain object.
///
/// Ported from Ghidra's `DomainObjectEventQueues`. Supports a public
/// event queue and multiple private event queues, each with their own
/// listener and flush behavior.
#[derive(Debug)]
pub struct DomainObjectEventQueues {
    /// The public event queue.
    public_queue: EventQueue,
    /// Private event queues, keyed by their ID.
    private_queues: HashMap<EventQueueId, EventQueue>,
    /// Whether events are enabled.
    events_enabled: bool,
    /// The source domain object name (for debugging).
    pub source_name: String,
}

impl DomainObjectEventQueues {
    /// Create a new event queue manager.
    pub fn new(source_name: impl Into<String>, flush_interval_ms: u64) -> Self {
        let id = EventQueueId::generate();
        Self {
            public_queue: EventQueue::new(id, flush_interval_ms),
            private_queues: HashMap::new(),
            events_enabled: true,
            source_name: source_name.into(),
        }
    }

    /// Fire an event into the public queue.
    pub fn fire_event(&mut self, record: TraceChangeRecord) {
        if self.events_enabled {
            let now = chrono::Utc::now().timestamp_millis() as u64;
            self.public_queue.enqueue(record, now);
        }
    }

    /// Fire an event into a specific private queue.
    pub fn fire_private_event(
        &mut self,
        queue_id: EventQueueId,
        record: TraceChangeRecord,
    ) -> Result<(), EventQueueError> {
        if !self.events_enabled {
            return Ok(());
        }
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let queue = self
            .private_queues
            .get_mut(&queue_id)
            .ok_or(EventQueueError::QueueNotFound(queue_id))?;
        queue.enqueue(record, now);
        Ok(())
    }

    /// Create a private event queue.
    pub fn create_private_queue(&mut self, max_delay_ms: u64) -> EventQueueId {
        let id = EventQueueId::generate();
        let queue = EventQueue::new(id, max_delay_ms);
        self.private_queues.insert(id, queue);
        id
    }

    /// Create a private event queue with a listener name.
    pub fn create_private_queue_named(
        &mut self,
        max_delay_ms: u64,
        listener_name: impl Into<String>,
    ) -> EventQueueId {
        let id = EventQueueId::generate();
        let queue = EventQueue::new(id, max_delay_ms).with_listener_name(listener_name);
        self.private_queues.insert(id, queue);
        id
    }

    /// Remove a private event queue.
    pub fn remove_private_queue(&mut self, id: EventQueueId) -> bool {
        self.private_queues.remove(&id).is_some()
    }

    /// Flush all queues (public and private), returning all events.
    pub fn flush_all(&mut self) -> Vec<(EventQueueId, Vec<PendingEvent>)> {
        let mut result = Vec::new();

        let public_events = self.public_queue.flush();
        if !public_events.is_empty() {
            result.push((self.public_queue.id, public_events));
        }

        for (id, queue) in &mut self.private_queues {
            let events = queue.flush();
            if !events.is_empty() {
                result.push((*id, events));
            }
        }

        result
    }

    /// Flush only the public queue.
    pub fn flush_public(&mut self) -> Vec<PendingEvent> {
        self.public_queue.flush()
    }

    /// Flush a specific private queue.
    pub fn flush_private(&mut self, id: EventQueueId) -> Result<Vec<PendingEvent>, EventQueueError> {
        let queue = self
            .private_queues
            .get_mut(&id)
            .ok_or(EventQueueError::QueueNotFound(id))?;
        Ok(queue.flush())
    }

    /// Enable or disable all events.
    pub fn set_events_enabled(&mut self, enabled: bool) {
        self.events_enabled = enabled;
    }

    /// Whether events are enabled.
    pub fn events_enabled(&self) -> bool {
        self.events_enabled
    }

    /// The number of private queues.
    pub fn private_queue_count(&self) -> usize {
        self.private_queues.len()
    }

    /// Whether any queue has pending events.
    pub fn has_pending_events(&self) -> bool {
        self.public_queue.has_pending()
            || self.private_queues.values().any(|q| q.has_pending())
    }

    /// Total pending event count across all queues.
    pub fn total_pending_count(&self) -> usize {
        self.public_queue.pending_count()
            + self
                .private_queues
                .values()
                .map(|q| q.pending_count())
                .sum::<usize>()
    }
}

/// Error type for event queue operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum EventQueueError {
    /// The specified queue was not found.
    #[error("event queue {0:?} not found")]
    QueueNotFound(EventQueueId),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_queue_id() {
        let id1 = EventQueueId::generate();
        let id2 = EventQueueId::generate();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_event_queue_basic() {
        let id = EventQueueId::generate();
        let mut queue = EventQueue::new(id, 100);
        assert!(!queue.has_pending());
        assert_eq!(queue.pending_count(), 0);

        queue.enqueue(TraceChangeRecord::new("test", "key", "value"), 1000);
        assert!(queue.has_pending());
        assert_eq!(queue.pending_count(), 1);

        let events = queue.flush();
        assert_eq!(events.len(), 1);
        assert!(!queue.has_pending());
    }

    #[test]
    fn test_event_queue_deactivate() {
        let id = EventQueueId::generate();
        let mut queue = EventQueue::new(id, 100);
        queue.enqueue(TraceChangeRecord::new("test", "key", "value"), 1000);
        assert!(queue.has_pending());

        queue.deactivate();
        assert!(!queue.is_active());
        assert!(!queue.has_pending());

        // Can't enqueue to inactive queue
        queue.enqueue(TraceChangeRecord::new("test2", "key2", "value2"), 2000);
        assert!(!queue.has_pending());
    }

    #[test]
    fn test_domain_object_event_queues() {
        let mut queues = DomainObjectEventQueues::new("TestTrace", 50);
        assert!(queues.events_enabled());
        assert!(!queues.has_pending_events());

        queues.fire_event(TraceChangeRecord::new("thread_added", "Thread.1", "new"));
        assert!(queues.has_pending_events());
        assert_eq!(queues.total_pending_count(), 1);
    }

    #[test]
    fn test_private_queues() {
        let mut queues = DomainObjectEventQueues::new("TestTrace", 50);
        let id = queues.create_private_queue_named(100, "test_listener");
        assert_eq!(queues.private_queue_count(), 1);

        queues
            .fire_private_event(id, TraceChangeRecord::new("event", "key", "val"))
            .unwrap();
        assert!(queues.has_pending_events());
        assert_eq!(queues.total_pending_count(), 1);

        let events = queues.flush_private(id).unwrap();
        assert_eq!(events.len(), 1);
        assert!(!queues.has_pending_events());

        assert!(queues.remove_private_queue(id));
        assert_eq!(queues.private_queue_count(), 0);
    }

    #[test]
    fn test_fire_private_to_missing_queue() {
        let mut queues = DomainObjectEventQueues::new("TestTrace", 50);
        let fake_id = EventQueueId::new(999);
        let result = queues.fire_private_event(fake_id, TraceChangeRecord::new("e", "k", "v"));
        assert!(result.is_err());
    }

    #[test]
    fn test_flush_all() {
        let mut queues = DomainObjectEventQueues::new("TestTrace", 50);
        let id = queues.create_private_queue(100);

        queues.fire_event(TraceChangeRecord::new("e1", "k1", "v1"));
        queues.fire_private_event(id, TraceChangeRecord::new("e2", "k2", "v2")).unwrap();

        let all = queues.flush_all();
        assert_eq!(all.len(), 2); // public + private
    }

    #[test]
    fn test_events_disabled() {
        let mut queues = DomainObjectEventQueues::new("TestTrace", 50);
        queues.set_events_enabled(false);
        assert!(!queues.events_enabled());

        queues.fire_event(TraceChangeRecord::new("e", "k", "v"));
        assert!(!queues.has_pending_events());
    }

    #[test]
    fn test_queue_with_listener_name() {
        let id = EventQueueId::generate();
        let queue = EventQueue::new(id, 100).with_listener_name("my_listener");
        assert_eq!(queue.listener_name, "my_listener");
    }

    #[test]
    fn test_event_queue_id_serde() {
        let id = EventQueueId::new(42);
        let json = serde_json::to_string(&id).unwrap();
        let back: EventQueueId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }
}
