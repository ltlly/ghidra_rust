//! DomainObjectEventQueues ported from Ghidra's `ghidra.framework.data`.
//!
//! Manages event dispatch queues for domain objects (traces), supporting
//! listener registration, event flushing, and change notification delivery.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, RwLock};

/// Unique identifier for a registered event listener.
pub type ListenerId = u64;

/// Represents a domain object event to be delivered.
#[derive(Debug, Clone)]
pub struct DomainObjectEvent {
    /// The event type identifier.
    pub event_type: String,
    /// The primary source object key.
    pub source_key: i64,
    /// Optional old value before the change.
    pub old_value: Option<String>,
    /// Optional new value after the change.
    pub new_value: Option<String>,
}

/// Priority levels for event queue processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventPriority {
    /// Highest priority - delivered immediately.
    Immediate,
    /// High priority - delivered before normal events.
    High,
    /// Normal priority.
    Normal,
    /// Low priority - delivered after normal events.
    Low,
}

impl PartialOrd for EventPriority {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EventPriority {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Higher priority = higher value (Immediate is highest)
        let self_val: u8 = match self {
            EventPriority::Low => 0,
            EventPriority::Normal => 1,
            EventPriority::High => 2,
            EventPriority::Immediate => 3,
        };
        let other_val: u8 = match other {
            EventPriority::Low => 0,
            EventPriority::Normal => 1,
            EventPriority::High => 2,
            EventPriority::Immediate => 3,
        };
        self_val.cmp(&other_val)
    }
}

struct QueuedEvent {
    event: DomainObjectEvent,
    priority: EventPriority,
}

/// Manages event queues for domain objects, supporting prioritized delivery.
///
/// Ported from Ghidra's `DomainObjectEventQueues`.
pub struct DomainObjectEventQueues {
    queue: Mutex<VecDeque<QueuedEvent>>,
    listeners: RwLock<HashMap<ListenerId, Box<dyn Fn(&DomainObjectEvent) + Send + Sync>>>,
    next_listener_id: Mutex<ListenerId>,
    flush_lock: Mutex<()>,
    max_queue_size: usize,
}

impl DomainObjectEventQueues {
    /// Create a new event queue manager with a default max queue size.
    pub fn new() -> Self {
        Self::with_max_queue_size(10_000)
    }

    /// Create a new event queue manager with a specified max queue size.
    pub fn with_max_queue_size(max_queue_size: usize) -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            listeners: RwLock::new(HashMap::new()),
            next_listener_id: Mutex::new(0),
            flush_lock: Mutex::new(()),
            max_queue_size,
        }
    }

    /// Register a listener for domain object events. Returns a listener ID
    /// that can be used to unregister.
    pub fn add_listener<F>(&self, listener: F) -> ListenerId
    where
        F: Fn(&DomainObjectEvent) + Send + Sync + 'static,
    {
        let mut id = self.next_listener_id.lock().unwrap();
        let listener_id = *id;
        *id += 1;

        let mut listeners = self.listeners.write().unwrap();
        listeners.insert(listener_id, Box::new(listener));
        listener_id
    }

    /// Unregister a listener by its ID.
    pub fn remove_listener(&self, listener_id: ListenerId) -> bool {
        let mut listeners = self.listeners.write().unwrap();
        listeners.remove(&listener_id).is_some()
    }

    /// Queue an event for delivery at normal priority.
    pub fn queue_event(&self, event: DomainObjectEvent) {
        self.queue_event_with_priority(event, EventPriority::Normal);
    }

    /// Queue an event with a specified priority.
    pub fn queue_event_with_priority(&self, event: DomainObjectEvent, priority: EventPriority) {
        let mut queue = self.queue.lock().unwrap();
        if queue.len() >= self.max_queue_size {
            // Drop the lowest-priority event to make room
            if let Some(pos) = queue
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.priority)
                .map(|(i, _)| i)
            {
                queue.remove(pos);
            }
        }
        queue.push_back(QueuedEvent { event, priority });
    }

    /// Flush all queued events, delivering them to registered listeners.
    /// Events are delivered in priority order (highest first).
    ///
    /// Returns the number of events delivered.
    pub fn flush(&self) -> usize {
        let _guard = self.flush_lock.lock().unwrap();

        let events: Vec<DomainObjectEvent> = {
            let mut queue = self.queue.lock().unwrap();
            // Sort by priority (highest first)
            let mut sorted: Vec<QueuedEvent> = queue.drain(..).collect();
            sorted.sort_by(|a, b| b.priority.cmp(&a.priority));
            sorted.into_iter().map(|qe| qe.event).collect()
        };

        if events.is_empty() {
            return 0;
        }

        let listeners = self.listeners.read().unwrap();
        for event in &events {
            for listener in listeners.values() {
                listener(event);
            }
        }

        events.len()
    }

    /// Drain all queued events without delivering them.
    pub fn drain(&self) -> Vec<DomainObjectEvent> {
        let mut queue = self.queue.lock().unwrap();
        queue.drain(..).map(|qe| qe.event).collect()
    }

    /// Check if there are any pending events.
    pub fn has_pending(&self) -> bool {
        let queue = self.queue.lock().unwrap();
        !queue.is_empty()
    }

    /// Get the current number of queued events.
    pub fn pending_count(&self) -> usize {
        let queue = self.queue.lock().unwrap();
        queue.len()
    }

    /// Get the number of registered listeners.
    pub fn listener_count(&self) -> usize {
        let listeners = self.listeners.read().unwrap();
        listeners.len()
    }
}

impl Default for DomainObjectEventQueues {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_queue_and_flush() {
        let queues = DomainObjectEventQueues::new();
        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = count.clone();

        queues.add_listener(move |_evt| {
            count_clone.fetch_add(1, Ordering::Relaxed);
        });

        queues.queue_event(DomainObjectEvent {
            event_type: "test".into(),
            source_key: 1,
            old_value: None,
            new_value: None,
        });
        queues.queue_event(DomainObjectEvent {
            event_type: "test2".into(),
            source_key: 2,
            old_value: None,
            new_value: None,
        });

        assert_eq!(queues.pending_count(), 2);
        let delivered = queues.flush();
        assert_eq!(delivered, 2);
        assert_eq!(count.load(Ordering::Relaxed), 2);
        assert!(!queues.has_pending());
    }

    #[test]
    fn test_priority_ordering() {
        let queues = DomainObjectEventQueues::new();
        let order = Arc::new(Mutex::new(Vec::new()));
        let order_clone = order.clone();

        queues.add_listener(move |evt| {
            order_clone.lock().unwrap().push(evt.event_type.clone());
        });

        queues.queue_event_with_priority(
            DomainObjectEvent {
                event_type: "low".into(),
                source_key: 1,
                old_value: None,
                new_value: None,
            },
            EventPriority::Low,
        );
        queues.queue_event_with_priority(
            DomainObjectEvent {
                event_type: "immediate".into(),
                source_key: 2,
                old_value: None,
                new_value: None,
            },
            EventPriority::Immediate,
        );
        queues.queue_event_with_priority(
            DomainObjectEvent {
                event_type: "normal".into(),
                source_key: 3,
                old_value: None,
                new_value: None,
            },
            EventPriority::Normal,
        );

        queues.flush();
        let result = order.lock().unwrap();
        assert_eq!(result[0], "immediate");
        assert_eq!(result[1], "normal");
        assert_eq!(result[2], "low");
    }

    #[test]
    fn test_remove_listener() {
        let queues = DomainObjectEventQueues::new();
        let id = queues.add_listener(|_| {});
        assert_eq!(queues.listener_count(), 1);
        assert!(queues.remove_listener(id));
        assert_eq!(queues.listener_count(), 0);
        assert!(!queues.remove_listener(id));
    }

    #[test]
    fn test_drain() {
        let queues = DomainObjectEventQueues::new();
        queues.queue_event(DomainObjectEvent {
            event_type: "test".into(),
            source_key: 1,
            old_value: None,
            new_value: None,
        });
        let drained = queues.drain();
        assert_eq!(drained.len(), 1);
        assert!(!queues.has_pending());
    }

    #[test]
    fn test_max_queue_size() {
        let queues = DomainObjectEventQueues::with_max_queue_size(2);
        queues.queue_event(DomainObjectEvent {
            event_type: "a".into(),
            source_key: 1,
            old_value: None,
            new_value: None,
        });
        queues.queue_event(DomainObjectEvent {
            event_type: "b".into(),
            source_key: 2,
            old_value: None,
            new_value: None,
        });
        queues.queue_event_with_priority(
            DomainObjectEvent {
                event_type: "c_low".into(),
                source_key: 3,
                old_value: None,
                new_value: None,
            },
            EventPriority::Low,
        );
        // The low-priority event was added but should be dropped if queue is full
        // Actually, we drop the existing Low priority to make room
        assert!(queues.pending_count() <= 2);
    }
}
