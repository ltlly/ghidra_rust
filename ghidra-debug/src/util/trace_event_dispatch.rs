//! Event dispatch utilities ported from ghidra.trace.util.
//!
//! Provides a typed event dispatcher for trace change events.

use std::collections::HashMap;

/// Type alias for event listener ID.
pub type ListenerId = u64;

/// A simple event dispatcher that manages typed listeners.
pub struct TraceEventDispatcher<T: Clone + std::fmt::Debug> {
    listeners: HashMap<ListenerId, Box<dyn Fn(&T) + Send + Sync>>,
    next_id: ListenerId,
}

impl<T: Clone + std::fmt::Debug> std::fmt::Debug for TraceEventDispatcher<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TraceEventDispatcher")
            .field("listener_count", &self.listeners.len())
            .field("next_id", &self.next_id)
            .finish()
    }
}

impl<T: Clone + std::fmt::Debug> Default for TraceEventDispatcher<T> {
    fn default() -> Self {
        Self {
            listeners: HashMap::new(),
            next_id: 0,
        }
    }
}

impl<T: Clone + std::fmt::Debug> TraceEventDispatcher<T> {
    /// Create a new dispatcher.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a listener, returning its ID.
    pub fn register(&mut self, listener: impl Fn(&T) + Send + Sync + 'static) -> ListenerId {
        let id = self.next_id;
        self.next_id += 1;
        self.listeners.insert(id, Box::new(listener));
        id
    }

    /// Remove a listener by ID.
    pub fn unregister(&mut self, id: ListenerId) -> bool {
        self.listeners.remove(&id).is_some()
    }

    /// Dispatch an event to all listeners.
    pub fn dispatch(&self, event: &T) {
        for listener in self.listeners.values() {
            listener(event);
        }
    }

    /// Number of registered listeners.
    pub fn listener_count(&self) -> usize {
        self.listeners.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_dispatch() {
        let mut dispatcher = TraceEventDispatcher::<String>::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        let id = dispatcher.register(move |_event| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });

        dispatcher.dispatch(&"test".to_string());
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        dispatcher.unregister(id);
        dispatcher.dispatch(&"test2".to_string());
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }
}
