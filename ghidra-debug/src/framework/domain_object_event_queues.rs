//! Domain object event queues for change notification dispatching.
//!
//! Ported from Ghidra's `ghidra.framework.data.DomainObjectEventQueues`.
//! Manages event dispatching for domain objects, including a main event
//! queue and optional private event queues for isolated listeners.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

/// A unique identifier for a private event queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EventQueueId(u64);

impl EventQueueId {
    /// Create a new event queue ID with the given value.
    pub fn new(id: u64) -> Self {
        Self(id)
    }
}

impl fmt::Display for EventQueueId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EventQueue({})", self.0)
    }
}

/// A type-erased event record that can be dispatched through event queues.
#[derive(Debug, Clone)]
pub struct DomainChangeEvent {
    /// The event type identifier.
    pub event_type: String,
    /// A human-readable description of the change.
    pub description: String,
    /// Optional serialized payload.
    pub payload: Option<Vec<u8>>,
}

impl DomainChangeEvent {
    /// Create a new domain change event.
    pub fn new(event_type: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            event_type: event_type.into(),
            description: description.into(),
            payload: None,
        }
    }

    /// Create a "restored" event (sent when events are re-enabled).
    pub fn restored() -> Self {
        Self::new("RESTORED", "Domain object restored")
    }

    /// Attach a binary payload.
    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = Some(payload);
        self
    }
}

/// A listener for domain object change events.
pub trait DomainObjectListener: Send + Sync {
    /// Called when a change event is fired.
    fn event_received(&self, event: &DomainChangeEvent);
}

/// A simple function-based listener.
pub struct FnListener {
    handler: Box<dyn Fn(&DomainChangeEvent) + Send + Sync>,
}

impl FnListener {
    /// Create a new function-based listener.
    pub fn new<F: Fn(&DomainChangeEvent) + Send + Sync + 'static>(handler: F) -> Self {
        Self {
            handler: Box::new(handler),
        }
    }
}

impl DomainObjectListener for FnListener {
    fn event_received(&self, event: &DomainChangeEvent) {
        (self.handler)(event);
    }
}

/// An individual event queue that buffers and dispatches events.
struct EventQueue {
    listeners: Vec<Arc<dyn DomainObjectListener>>,
    buffer: Vec<DomainChangeEvent>,
    max_delay: Duration,
}

impl fmt::Debug for EventQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventQueue")
            .field("listener_count", &self.listeners.len())
            .field("buffer_len", &self.buffer.len())
            .field("max_delay", &self.max_delay)
            .finish()
    }
}

impl EventQueue {
    fn new(max_delay: Duration) -> Self {
        Self {
            listeners: Vec::new(),
            buffer: Vec::new(),
            max_delay,
        }
    }

    fn add_listener(&mut self, listener: Arc<dyn DomainObjectListener>) {
        self.listeners.push(listener);
    }

    fn remove_listener(&mut self, listener_id: usize) -> bool {
        if listener_id < self.listeners.len() {
            self.listeners.remove(listener_id);
            true
        } else {
            false
        }
    }

    fn fire_event(&mut self, event: DomainChangeEvent) {
        // Dispatch immediately to all listeners
        for listener in &self.listeners {
            listener.event_received(&event);
        }
        self.buffer.push(event);
    }

    fn flush(&mut self) {
        // In this simplified implementation, events are already dispatched immediately.
        // Clear the buffer after flushing.
        self.buffer.clear();
    }

    fn listener_count(&self) -> usize {
        self.listeners.len()
    }
}

/// Manages event queues for a domain object.
///
/// Provides a main event queue and supports creating private event queues
/// for isolated listener groups. Events are dispatched immediately when
/// `fire_event()` is called, and buffered until `flush_events()`.
///
/// Corresponds to Ghidra's `DomainObjectEventQueues`.
pub struct DomainObjectEventQueues {
    main_queue: Mutex<EventQueue>,
    private_queues: RwLock<HashMap<EventQueueId, Mutex<EventQueue>>>,
    events_enabled: RwLock<bool>,
    next_queue_id: Mutex<u64>,
}

impl DomainObjectEventQueues {
    /// Create a new event queue manager.
    ///
    /// `max_delay` controls the maximum delay before events are flushed.
    pub fn new(max_delay: Duration) -> Self {
        Self {
            main_queue: Mutex::new(EventQueue::new(max_delay)),
            private_queues: RwLock::new(HashMap::new()),
            events_enabled: RwLock::new(true),
            next_queue_id: Mutex::new(1),
        }
    }

    /// Add a listener to the main event queue.
    pub fn add_listener(&self, listener: Arc<dyn DomainObjectListener>) {
        let mut queue = self.main_queue.lock().unwrap();
        queue.add_listener(listener);
    }

    /// Remove a listener from the main event queue by index.
    pub fn remove_listener(&self, index: usize) -> bool {
        let mut queue = self.main_queue.lock().unwrap();
        queue.remove_listener(index)
    }

    /// Fire an event to all queues (main and private).
    ///
    /// If events are disabled, the event is silently dropped.
    pub fn fire_event(&self, event: DomainChangeEvent) {
        let enabled = *self.events_enabled.read().unwrap();
        if !enabled {
            return;
        }

        // Fire to main queue
        {
            let mut queue = self.main_queue.lock().unwrap();
            queue.fire_event(event.clone());
        }

        // Fire to all private queues
        let private = self.private_queues.read().unwrap();
        for queue in private.values() {
            let mut q = queue.lock().unwrap();
            q.fire_event(event.clone());
        }
    }

    /// Create a private event queue with its own listener.
    ///
    /// Returns a unique ID that can be used to remove or flush the queue.
    pub fn create_private_queue(&self, listener: Arc<dyn DomainObjectListener>) -> EventQueueId {
        let max_delay = {
            let main = self.main_queue.lock().unwrap();
            main.max_delay
        };
        let id = {
            let mut counter = self.next_queue_id.lock().unwrap();
            let id = *counter;
            *counter += 1;
            EventQueueId::new(id)
        };
        let mut queue = EventQueue::new(max_delay);
        queue.add_listener(listener);

        let mut private = self.private_queues.write().unwrap();
        private.insert(id, Mutex::new(queue));
        id
    }

    /// Remove a private event queue.
    ///
    /// Returns `true` if the queue existed and was removed.
    pub fn remove_private_queue(&self, id: EventQueueId) -> bool {
        let mut private = self.private_queues.write().unwrap();
        private.remove(&id).is_some()
    }

    /// Flush all events in the main queue and all private queues.
    pub fn flush_events(&self) {
        {
            let mut queue = self.main_queue.lock().unwrap();
            queue.flush();
        }
        let private = self.private_queues.read().unwrap();
        for queue in private.values() {
            let mut q = queue.lock().unwrap();
            q.flush();
        }
    }

    /// Flush events for a specific private queue.
    pub fn flush_private_queue(&self, id: EventQueueId) -> Result<(), String> {
        let private = self.private_queues.read().unwrap();
        if let Some(queue) = private.get(&id) {
            let mut q = queue.lock().unwrap();
            q.flush();
            Ok(())
        } else {
            Err(format!("Private queue {} no longer exists", id))
        }
    }

    /// Enable or disable event sending.
    ///
    /// When re-enabling, a `RESTORED` event is sent to all queues.
    pub fn set_events_enabled(&self, enabled: bool) {
        let mut current = self.events_enabled.write().unwrap();
        if *current == enabled {
            return;
        }
        *current = enabled;

        if enabled {
            // Fire a restored event
            let restored = DomainChangeEvent::restored();
            drop(current);

            {
                let mut queue = self.main_queue.lock().unwrap();
                queue.fire_event(restored.clone());
            }
            let private = self.private_queues.read().unwrap();
            for queue in private.values() {
                let mut q = queue.lock().unwrap();
                q.fire_event(restored.clone());
            }
        }
    }

    /// Check if events are currently being sent.
    pub fn is_sending_events(&self) -> bool {
        *self.events_enabled.read().unwrap()
    }

    /// Get the number of listeners on the main queue.
    pub fn listener_count(&self) -> usize {
        let queue = self.main_queue.lock().unwrap();
        queue.listener_count()
    }

    /// Get the number of private queues.
    pub fn private_queue_count(&self) -> usize {
        let private = self.private_queues.read().unwrap();
        private.len()
    }
}

impl fmt::Debug for DomainObjectEventQueues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let enabled = *self.events_enabled.read().unwrap();
        let private_count = self.private_queues.read().unwrap().len();
        f.debug_struct("DomainObjectEventQueues")
            .field("events_enabled", &enabled)
            .field("private_queues", &private_count)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingListener {
        count: AtomicUsize,
        events: Mutex<Vec<String>>,
    }

    impl CountingListener {
        fn new() -> Self {
            Self {
                count: AtomicUsize::new(0),
                events: Mutex::new(Vec::new()),
            }
        }

        fn count(&self) -> usize {
            self.count.load(Ordering::SeqCst)
        }

        fn event_types(&self) -> Vec<String> {
            self.events.lock().unwrap().clone()
        }
    }

    impl DomainObjectListener for CountingListener {
        fn event_received(&self, event: &DomainChangeEvent) {
            self.count.fetch_add(1, Ordering::SeqCst);
            self.events.lock().unwrap().push(event.event_type.clone());
        }
    }

    #[test]
    fn test_basic_event_firing() {
        let queues = DomainObjectEventQueues::new(Duration::from_millis(100));
        let listener = Arc::new(CountingListener::new());

        queues.add_listener(listener.clone());
        queues.fire_event(DomainChangeEvent::new("TEST", "test event"));

        assert_eq!(listener.count(), 1);
    }

    #[test]
    fn test_multiple_listeners() {
        let queues = DomainObjectEventQueues::new(Duration::from_millis(100));
        let l1 = Arc::new(CountingListener::new());
        let l2 = Arc::new(CountingListener::new());

        queues.add_listener(l1.clone());
        queues.add_listener(l2.clone());

        queues.fire_event(DomainChangeEvent::new("TEST", "test"));

        assert_eq!(l1.count(), 1);
        assert_eq!(l2.count(), 1);
    }

    #[test]
    fn test_private_queue() {
        let queues = DomainObjectEventQueues::new(Duration::from_millis(100));
        let main_listener = Arc::new(CountingListener::new());
        let private_listener = Arc::new(CountingListener::new());

        queues.add_listener(main_listener.clone());
        let qid = queues.create_private_queue(private_listener.clone());

        queues.fire_event(DomainChangeEvent::new("TEST", "test"));

        // Both main and private listeners receive the event
        assert_eq!(main_listener.count(), 1);
        assert_eq!(private_listener.count(), 1);

        // Remove private queue
        assert!(queues.remove_private_queue(qid));
        queues.fire_event(DomainChangeEvent::new("TEST2", "test2"));

        // Main still receives, private does not
        assert_eq!(main_listener.count(), 2);
        assert_eq!(private_listener.count(), 1);
    }

    #[test]
    fn test_events_disabled() {
        let queues = DomainObjectEventQueues::new(Duration::from_millis(100));
        let listener = Arc::new(CountingListener::new());
        queues.add_listener(listener.clone());

        queues.set_events_enabled(false);
        assert!(!queues.is_sending_events());

        queues.fire_event(DomainChangeEvent::new("TEST", "should be dropped"));
        assert_eq!(listener.count(), 0);

        // Re-enable sends a RESTORED event
        queues.set_events_enabled(true);
        assert!(queues.is_sending_events());
        assert_eq!(listener.count(), 1);
        assert_eq!(listener.event_types()[0], "RESTORED");
    }

    #[test]
    fn test_flush_events() {
        let queues = DomainObjectEventQueues::new(Duration::from_millis(100));
        let listener = Arc::new(CountingListener::new());
        queues.add_listener(listener.clone());

        queues.fire_event(DomainChangeEvent::new("A", "a"));
        queues.fire_event(DomainChangeEvent::new("B", "b"));
        queues.flush_events();

        // Events are already dispatched, but flush should not error
        assert_eq!(listener.count(), 2);
    }

    #[test]
    fn test_flush_nonexistent_private_queue() {
        let queues = DomainObjectEventQueues::new(Duration::from_millis(100));
        let result = queues.flush_private_queue(EventQueueId::new(999));
        assert!(result.is_err());
    }

    #[test]
    fn test_private_queue_flush() {
        let queues = DomainObjectEventQueues::new(Duration::from_millis(100));
        let listener = Arc::new(CountingListener::new());
        let qid = queues.create_private_queue(listener.clone());

        queues.fire_event(DomainChangeEvent::new("TEST", "test"));
        let result = queues.flush_private_queue(qid);
        assert!(result.is_ok());
        assert_eq!(listener.count(), 1);
    }

    #[test]
    fn test_domain_change_event_restored() {
        let evt = DomainChangeEvent::restored();
        assert_eq!(evt.event_type, "RESTORED");
    }

    #[test]
    fn test_domain_change_event_with_payload() {
        let evt = DomainChangeEvent::new("DATA", "data change").with_payload(vec![1, 2, 3]);
        assert!(evt.payload.is_some());
        assert_eq!(evt.payload.unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn test_listener_count() {
        let queues = DomainObjectEventQueues::new(Duration::from_millis(100));
        assert_eq!(queues.listener_count(), 0);

        let l1 = Arc::new(CountingListener::new());
        queues.add_listener(l1);
        assert_eq!(queues.listener_count(), 1);

        let l2 = Arc::new(CountingListener::new());
        queues.add_listener(l2);
        assert_eq!(queues.listener_count(), 2);
    }

    #[test]
    fn test_fn_listener() {
        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = count.clone();
        let listener = Arc::new(FnListener::new(move |_event| {
            count_clone.fetch_add(1, Ordering::SeqCst);
        }));

        let queues = DomainObjectEventQueues::new(Duration::from_millis(100));
        queues.add_listener(listener);
        queues.fire_event(DomainChangeEvent::new("TEST", "test"));

        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_event_queue_id_display() {
        let id = EventQueueId::new(42);
        assert_eq!(format!("{}", id), "EventQueue(42)");
    }
}
