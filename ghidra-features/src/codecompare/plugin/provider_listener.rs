//! Function comparison provider listener.
//!
//! Ported from Ghidra's `FunctionComparisonProviderListener` Java interface in
//! `ghidra.features.codecompare.plugin`.
//!
//! Allows subscribers to register for function comparison provider changes,
//! such as when a provider is opened or closed. This is distinct from the
//! lower-level [`ProviderEventListener`] trait in `provider.rs`, which handles
//! more granular provider lifecycle events (activated, tab text changed, view
//! changed). This higher-level interface is used by components that need to
//! know when comparison windows are created or destroyed.
//!
//! In the original Java, this is a simple interface with two methods:
//! - `providerOpened(FunctionComparisonProvider provider)`
//! - `providerClosed(FunctionComparisonProvider provider)`
//!
//! In this Rust port, we define the trait and provide integration with the
//! plugin's provider management.
//!
//! # Key types
//!
//! - [`ProviderLifecycleEvent`] -- events about provider lifecycle
//! - [`FunctionComparisonProviderListener`] -- trait for receiving provider events
//! - [`ProviderListenerRegistry`] -- manages registered listeners

use std::sync::{Arc, Mutex};

/// Events about comparison provider lifecycle.
///
/// These are higher-level events than the per-provider events in
/// `ProviderEventListener`. They represent the creation and destruction
/// of comparison windows from the perspective of the plugin.
#[derive(Debug, Clone)]
pub enum ProviderLifecycleEvent {
    /// A new comparison provider was opened.
    ProviderOpened {
        /// The unique provider ID.
        provider_id: u64,
        /// A description of the comparison (e.g., "main() vs init()").
        description: String,
    },
    /// A comparison provider was closed.
    ProviderClosed {
        /// The unique provider ID.
        provider_id: u64,
    },
    /// The last comparison provider was closed.
    ///
    /// This is a convenience event that fires when the provider count
    /// drops to zero.
    AllProvidersClosed,
    /// A provider was activated (gained focus).
    ProviderActivated {
        /// The unique provider ID.
        provider_id: u64,
    },
}

/// Trait for receiving function comparison provider lifecycle events.
///
/// Implement this trait to be notified when comparison providers are
/// opened, closed, or activated.
///
/// Ported from Ghidra's `FunctionComparisonProviderListener` Java interface.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::plugin::provider_listener::*;
///
/// struct MyListener {
///     open_count: std::sync::Mutex<usize>,
/// }
///
/// impl MyListener {
///     fn new() -> Self {
///         Self { open_count: std::sync::Mutex::new(0) }
///     }
/// }
///
/// impl FunctionComparisonProviderListener for MyListener {
///     fn provider_opened(&self, provider_id: u64, description: &str) {
///         *self.open_count.lock().unwrap() += 1;
///     }
///
///     fn provider_closed(&self, provider_id: u64) {}
/// }
/// ```
pub trait FunctionComparisonProviderListener: Send + Sync {
    /// Called when a new comparison provider is opened.
    ///
    /// # Parameters
    /// - `provider_id`: The unique ID of the new provider.
    /// - `description`: A human-readable description of the comparison.
    fn provider_opened(&self, provider_id: u64, description: &str);

    /// Called when a comparison provider is closed.
    ///
    /// # Parameters
    /// - `provider_id`: The unique ID of the closed provider.
    fn provider_closed(&self, provider_id: u64);

    /// Called when all comparison providers have been closed.
    ///
    /// Default implementation does nothing.
    fn all_providers_closed(&self) {}

    /// Called when a comparison provider is activated (gains focus).
    ///
    /// Default implementation does nothing.
    fn provider_activated(&self, _provider_id: u64) {}
}

/// A simple listener that records provider lifecycle events.
///
/// Useful for testing and for components that need to track the
/// history of provider events.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::plugin::provider_listener::*;
/// use std::sync::Arc;
///
/// let listener = Arc::new(RecordingProviderListener::new());
/// listener.provider_opened(1, "main() vs init()");
/// listener.provider_closed(1);
///
/// assert_eq!(listener.open_count(), 1);
/// assert_eq!(listener.close_count(), 1);
/// ```
#[derive(Debug, Default)]
pub struct RecordingProviderListener {
    /// All recorded events in order.
    events: Mutex<Vec<ProviderLifecycleEvent>>,
    /// Count of open events.
    open_count: Mutex<usize>,
    /// Count of close events.
    close_count: Mutex<usize>,
    /// Count of activate events.
    activate_count: Mutex<usize>,
    /// Count of all-closed events.
    all_closed_count: Mutex<usize>,
}

impl RecordingProviderListener {
    /// Create a new recording listener.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the total number of events recorded.
    pub fn event_count(&self) -> usize {
        self.events.lock().unwrap().len()
    }

    /// Get the number of open events.
    pub fn open_count(&self) -> usize {
        *self.open_count.lock().unwrap()
    }

    /// Get the number of close events.
    pub fn close_count(&self) -> usize {
        *self.close_count.lock().unwrap()
    }

    /// Get the number of activate events.
    pub fn activate_count(&self) -> usize {
        *self.activate_count.lock().unwrap()
    }

    /// Get the number of all-closed events.
    pub fn all_closed_count(&self) -> usize {
        *self.all_closed_count.lock().unwrap()
    }

    /// Get all recorded events.
    pub fn events(&self) -> Vec<ProviderLifecycleEvent> {
        self.events.lock().unwrap().clone()
    }

    /// Check if any provider was opened.
    pub fn has_opened(&self) -> bool {
        *self.open_count.lock().unwrap() > 0
    }

    /// Check if any provider was closed.
    pub fn has_closed(&self) -> bool {
        *self.close_count.lock().unwrap() > 0
    }

    /// Clear all recorded events.
    pub fn clear(&self) {
        self.events.lock().unwrap().clear();
        *self.open_count.lock().unwrap() = 0;
        *self.close_count.lock().unwrap() = 0;
        *self.activate_count.lock().unwrap() = 0;
        *self.all_closed_count.lock().unwrap() = 0;
    }
}

impl FunctionComparisonProviderListener for RecordingProviderListener {
    fn provider_opened(&self, provider_id: u64, description: &str) {
        self.events.lock().unwrap().push(ProviderLifecycleEvent::ProviderOpened {
            provider_id,
            description: description.to_string(),
        });
        *self.open_count.lock().unwrap() += 1;
    }

    fn provider_closed(&self, provider_id: u64) {
        self.events.lock().unwrap().push(ProviderLifecycleEvent::ProviderClosed {
            provider_id,
        });
        *self.close_count.lock().unwrap() += 1;
    }

    fn all_providers_closed(&self) {
        self.events.lock().unwrap().push(ProviderLifecycleEvent::AllProvidersClosed);
        *self.all_closed_count.lock().unwrap() += 1;
    }

    fn provider_activated(&self, provider_id: u64) {
        self.events.lock().unwrap().push(ProviderLifecycleEvent::ProviderActivated {
            provider_id,
        });
        *self.activate_count.lock().unwrap() += 1;
    }
}

/// Registry for managing function comparison provider listeners.
///
/// Provides a centralized way to register, remove, and notify listeners
/// about provider lifecycle events. The plugin uses this to manage its
/// set of provider listeners.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::plugin::provider_listener::*;
/// use std::sync::Arc;
///
/// let mut registry = ProviderListenerRegistry::new();
/// let listener = Arc::new(RecordingProviderListener::new());
/// registry.add_listener(listener.clone());
///
/// registry.notify_opened(1, "main() vs init()");
/// assert_eq!(listener.open_count(), 1);
///
/// registry.notify_closed(1);
/// assert_eq!(listener.close_count(), 1);
/// ```
#[derive(Debug, Default)]
pub struct ProviderListenerRegistry {
    /// Registered listeners.
    listeners: Vec<Arc<dyn FunctionComparisonProviderListener>>,
}

impl ProviderListenerRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a listener to the registry.
    pub fn add_listener(&mut self, listener: Arc<dyn FunctionComparisonProviderListener>) {
        self.listeners.push(listener);
    }

    /// Remove all listeners.
    pub fn clear(&mut self) {
        self.listeners.clear();
    }

    /// Get the number of registered listeners.
    pub fn listener_count(&self) -> usize {
        self.listeners.len()
    }

    /// Check if there are any registered listeners.
    pub fn has_listeners(&self) -> bool {
        !self.listeners.is_empty()
    }

    /// Notify all listeners that a provider was opened.
    pub fn notify_opened(&self, provider_id: u64, description: &str) {
        for listener in &self.listeners {
            listener.provider_opened(provider_id, description);
        }
    }

    /// Notify all listeners that a provider was closed.
    pub fn notify_closed(&self, provider_id: u64) {
        for listener in &self.listeners {
            listener.provider_closed(provider_id);
        }
    }

    /// Notify all listeners that all providers have been closed.
    pub fn notify_all_closed(&self) {
        for listener in &self.listeners {
            listener.all_providers_closed();
        }
    }

    /// Notify all listeners that a provider was activated.
    pub fn notify_activated(&self, provider_id: u64) {
        for listener in &self.listeners {
            listener.provider_activated(provider_id);
        }
    }

    /// Notify listeners based on a lifecycle event.
    pub fn notify_event(&self, event: &ProviderLifecycleEvent) {
        match event {
            ProviderLifecycleEvent::ProviderOpened { provider_id, description } => {
                self.notify_opened(*provider_id, description);
            }
            ProviderLifecycleEvent::ProviderClosed { provider_id } => {
                self.notify_closed(*provider_id);
            }
            ProviderLifecycleEvent::AllProvidersClosed => {
                self.notify_all_closed();
            }
            ProviderLifecycleEvent::ProviderActivated { provider_id } => {
                self.notify_activated(*provider_id);
            }
        }
    }
}

/// A no-op listener that does nothing.
///
/// Useful as a default or placeholder.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpProviderListener;

impl FunctionComparisonProviderListener for NoOpProviderListener {
    fn provider_opened(&self, _provider_id: u64, _description: &str) {}
    fn provider_closed(&self, _provider_id: u64) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // --- RecordingProviderListener tests ---

    #[test]
    fn test_recording_listener_new() {
        let listener = RecordingProviderListener::new();
        assert_eq!(listener.event_count(), 0);
        assert_eq!(listener.open_count(), 0);
        assert_eq!(listener.close_count(), 0);
        assert!(!listener.has_opened());
        assert!(!listener.has_closed());
    }

    #[test]
    fn test_recording_listener_opened() {
        let listener = RecordingProviderListener::new();
        listener.provider_opened(1, "main() vs init()");

        assert_eq!(listener.open_count(), 1);
        assert!(listener.has_opened());
        assert_eq!(listener.event_count(), 1);

        let events = listener.events();
        assert!(matches!(
            &events[0],
            ProviderLifecycleEvent::ProviderOpened {
                provider_id: 1,
                description,
            } if description == "main() vs init()"
        ));
    }

    #[test]
    fn test_recording_listener_closed() {
        let listener = RecordingProviderListener::new();
        listener.provider_closed(1);

        assert_eq!(listener.close_count(), 1);
        assert!(listener.has_closed());
        assert_eq!(listener.event_count(), 1);

        let events = listener.events();
        assert!(matches!(
            &events[0],
            ProviderLifecycleEvent::ProviderClosed { provider_id: 1 }
        ));
    }

    #[test]
    fn test_recording_listener_all_closed() {
        let listener = RecordingProviderListener::new();
        listener.all_providers_closed();

        assert_eq!(listener.all_closed_count(), 1);
        assert_eq!(listener.event_count(), 1);

        let events = listener.events();
        assert!(matches!(
            &events[0],
            ProviderLifecycleEvent::AllProvidersClosed
        ));
    }

    #[test]
    fn test_recording_listener_activated() {
        let listener = RecordingProviderListener::new();
        listener.provider_activated(1);

        assert_eq!(listener.activate_count(), 1);
        assert_eq!(listener.event_count(), 1);

        let events = listener.events();
        assert!(matches!(
            &events[0],
            ProviderLifecycleEvent::ProviderActivated { provider_id: 1 }
        ));
    }

    #[test]
    fn test_recording_listener_multiple_events() {
        let listener = RecordingProviderListener::new();
        listener.provider_opened(1, "comparison 1");
        listener.provider_opened(2, "comparison 2");
        listener.provider_activated(2);
        listener.provider_closed(1);
        listener.provider_closed(2);
        listener.all_providers_closed();

        assert_eq!(listener.event_count(), 6);
        assert_eq!(listener.open_count(), 2);
        assert_eq!(listener.close_count(), 2);
        assert_eq!(listener.activate_count(), 1);
        assert_eq!(listener.all_closed_count(), 1);
    }

    #[test]
    fn test_recording_listener_clear() {
        let listener = RecordingProviderListener::new();
        listener.provider_opened(1, "test");
        listener.provider_closed(1);

        assert_eq!(listener.event_count(), 2);

        listener.clear();
        assert_eq!(listener.event_count(), 0);
        assert_eq!(listener.open_count(), 0);
        assert_eq!(listener.close_count(), 0);
    }

    // --- ProviderListenerRegistry tests ---

    #[test]
    fn test_registry_new() {
        let registry = ProviderListenerRegistry::new();
        assert_eq!(registry.listener_count(), 0);
        assert!(!registry.has_listeners());
    }

    #[test]
    fn test_registry_add_listener() {
        let mut registry = ProviderListenerRegistry::new();
        let listener = Arc::new(RecordingProviderListener::new());
        registry.add_listener(listener);

        assert_eq!(registry.listener_count(), 1);
        assert!(registry.has_listeners());
    }

    #[test]
    fn test_registry_clear() {
        let mut registry = ProviderListenerRegistry::new();
        registry.add_listener(Arc::new(RecordingProviderListener::new()));
        registry.add_listener(Arc::new(RecordingProviderListener::new()));

        assert_eq!(registry.listener_count(), 2);

        registry.clear();
        assert_eq!(registry.listener_count(), 0);
        assert!(!registry.has_listeners());
    }

    #[test]
    fn test_registry_notify_opened() {
        let mut registry = ProviderListenerRegistry::new();
        let listener = Arc::new(RecordingProviderListener::new());
        registry.add_listener(listener.clone());

        registry.notify_opened(1, "main() vs init()");

        assert_eq!(listener.open_count(), 1);
        let events = listener.events();
        assert!(matches!(
            &events[0],
            ProviderLifecycleEvent::ProviderOpened {
                provider_id: 1,
                description,
            } if description == "main() vs init()"
        ));
    }

    #[test]
    fn test_registry_notify_closed() {
        let mut registry = ProviderListenerRegistry::new();
        let listener = Arc::new(RecordingProviderListener::new());
        registry.add_listener(listener.clone());

        registry.notify_closed(1);

        assert_eq!(listener.close_count(), 1);
    }

    #[test]
    fn test_registry_notify_all_closed() {
        let mut registry = ProviderListenerRegistry::new();
        let listener = Arc::new(RecordingProviderListener::new());
        registry.add_listener(listener.clone());

        registry.notify_all_closed();

        assert_eq!(listener.all_closed_count(), 1);
    }

    #[test]
    fn test_registry_notify_activated() {
        let mut registry = ProviderListenerRegistry::new();
        let listener = Arc::new(RecordingProviderListener::new());
        registry.add_listener(listener.clone());

        registry.notify_activated(1);

        assert_eq!(listener.activate_count(), 1);
    }

    #[test]
    fn test_registry_notify_event() {
        let mut registry = ProviderListenerRegistry::new();
        let listener = Arc::new(RecordingProviderListener::new());
        registry.add_listener(listener.clone());

        registry.notify_event(&ProviderLifecycleEvent::ProviderOpened {
            provider_id: 1,
            description: "test".to_string(),
        });
        registry.notify_event(&ProviderLifecycleEvent::ProviderClosed {
            provider_id: 1,
        });

        assert_eq!(listener.open_count(), 1);
        assert_eq!(listener.close_count(), 1);
    }

    #[test]
    fn test_registry_multiple_listeners() {
        let mut registry = ProviderListenerRegistry::new();
        let listener1 = Arc::new(RecordingProviderListener::new());
        let listener2 = Arc::new(RecordingProviderListener::new());
        registry.add_listener(listener1.clone());
        registry.add_listener(listener2.clone());

        registry.notify_opened(1, "test");

        assert_eq!(listener1.open_count(), 1);
        assert_eq!(listener2.open_count(), 1);
    }

    #[test]
    fn test_registry_no_listeners() {
        let registry = ProviderListenerRegistry::new();
        // Should not panic
        registry.notify_opened(1, "test");
        registry.notify_closed(1);
        registry.notify_all_closed();
        registry.notify_activated(1);
    }

    // --- NoOpProviderListener tests ---

    #[test]
    fn test_noop_listener() {
        let listener = NoOpProviderListener;
        // Should not panic
        listener.provider_opened(1, "test");
        listener.provider_closed(1);
        listener.all_providers_closed();
        listener.provider_activated(1);
    }

    // --- ProviderLifecycleEvent tests ---

    #[test]
    fn test_lifecycle_event_clone() {
        let event = ProviderLifecycleEvent::ProviderOpened {
            provider_id: 1,
            description: "test".to_string(),
        };
        let cloned = event.clone();
        assert!(matches!(
            cloned,
            ProviderLifecycleEvent::ProviderOpened {
                provider_id: 1,
                ..
            }
        ));
    }

    #[test]
    fn test_lifecycle_event_debug() {
        let event = ProviderLifecycleEvent::ProviderClosed { provider_id: 1 };
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("ProviderClosed"));
        assert!(debug_str.contains("1"));
    }
}
