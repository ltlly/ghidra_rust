//! Property change event management.
//!
//! Ports Ghidra's `PropertyChangeManager` pattern used throughout
//! `ghidra.framework.model.DomainObject` and `ghidra.program.model.listing.CodeUnit`
//! to coalesce, dispatch, and manage property change listeners.
//!
//! # Overview
//!
//! In Ghidra, Java's `PropertyChangeListener` / `PropertyChangeSupport` pair is
//! used to notify UI components and analysis listeners whenever a property on a
//! domain object (program, function, data unit, etc.) changes.  This module
//! provides the Rust equivalent:
//!
//! - [`PropertyChangeManager`] -- registers listeners, fires events, manages
//!   enable/disable state, and supports scoped event groups.
//! - [`ScopedPropertyChanges`] -- RAII guard that collects property changes
//!   during a scope and fires a consolidated event on drop.
//!
//! # Architecture
//!
//! The manager is parameterised by a *source identifier* (typically an address
//! or object id) and uses the `PropertyChangeEvent` from `ghidra_gui` as the
//! event payload.  Listeners receive events via the [`PropertyChangeListener`]
//! trait.
//!
//! Unlike Java's `PropertyChangeSupport` which is bound to a single source
//! object, this manager supports multiple named sources -- matching how Ghidra's
//! program change sets track changes across addresses and property names.

use ghidra_core::addr::Address;
use std::collections::HashMap;
use std::fmt;

// Re-use the event/listener types from the GUI crate when available,
// but define our own so this module can compile independently.

/// A property change event delivered to listeners.
#[derive(Debug, Clone)]
pub struct PropertyChangeEvent {
    /// The source identifier (e.g. address offset, object id).
    pub source_id: u64,
    /// The name of the property that changed.
    pub property_name: String,
    /// The old value, if known.
    pub old_value: Option<PropertyValue>,
    /// The new value, if known.
    pub new_value: Option<PropertyValue>,
}

impl PropertyChangeEvent {
    /// Create a new property change event.
    pub fn new(
        source_id: u64,
        property_name: impl Into<String>,
        old_value: Option<PropertyValue>,
        new_value: Option<PropertyValue>,
    ) -> Self {
        Self {
            source_id,
            property_name: property_name.into(),
            old_value,
            new_value,
        }
    }

    /// Convenience: build from an `Address` rather than a raw `u64`.
    pub fn for_address(
        address: &Address,
        property_name: impl Into<String>,
        old_value: Option<PropertyValue>,
        new_value: Option<PropertyValue>,
    ) -> Self {
        Self::new(address.offset, property_name, old_value, new_value)
    }
}

impl fmt::Display for PropertyChangeEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PropertyChangeEvent {{ source=0x{:X}, property=\"{}\" }}",
            self.source_id, self.property_name
        )
    }
}

/// A type-erased property value used in change events.
///
/// This is deliberately kept small and cloneable.  It mirrors the subset of
/// value types that Ghidra's `PropertyMap` supports (see the `property` module).
#[derive(Debug, Clone, PartialEq)]
pub enum PropertyValue {
    /// A string value.
    String(String),
    /// A boolean value.
    Bool(bool),
    /// A 64-bit integer value (covers both `int` and `long`).
    Int(i64),
    /// A 64-bit floating-point value.
    Float(f64),
    /// A void/existence marker (no value).
    Void,
}

impl fmt::Display for PropertyValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PropertyValue::String(s) => write!(f, "{}", s),
            PropertyValue::Bool(b) => write!(f, "{}", b),
            PropertyValue::Int(i) => write!(f, "{}", i),
            PropertyValue::Float(fl) => write!(f, "{}", fl),
            PropertyValue::Void => write!(f, "<void>"),
        }
    }
}

/// Trait for objects that want to receive property change notifications.
///
/// Corresponds to `java.beans.PropertyChangeListener` as used by Ghidra's
/// domain objects, code units, and analysis plugins.
pub trait PropertyChangeListener: Send + Sync {
    /// Called when a property changes.
    fn property_changed(&mut self, event: &PropertyChangeEvent);
}

/// An opaque handle returned when registering a listener.  Pass it to
/// [`PropertyChangeManager::remove_listener`] to unregister.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ListenerId(u64);

/// Manages property change listeners and dispatches events.
///
/// Corresponds to `java.beans.PropertyChangeSupport` as used throughout
/// Ghidra's domain object hierarchy.  Supports:
///
/// - Registration / removal of multiple listeners
/// - Bulk enable / disable (for suppressing events during batch updates)
/// - Scoped event groups via [`ScopedPropertyChanges`]
/// - Per-property filtering (listeners can opt into specific property names)
pub struct PropertyChangeManager {
    /// Next listener id.
    next_id: u64,
    /// Registered listeners, keyed by handle.
    listeners: HashMap<ListenerId, ListenerEntry>,
    /// Whether event delivery is currently enabled.
    enabled: bool,
    /// Pending events collected while delivery was disabled.
    pending: Vec<PropertyChangeEvent>,
}

/// Internal entry for a registered listener.
struct ListenerEntry {
    /// The listener trait object.
    listener: Box<dyn PropertyChangeListener>,
    /// Optional filter: if non-empty, only events whose property_name
    /// is in this set will be delivered.
    filter: Vec<String>,
}

impl PropertyChangeManager {
    /// Create a new, empty property change manager.
    pub fn new() -> Self {
        Self {
            next_id: 1,
            listeners: HashMap::new(),
            enabled: true,
            pending: Vec::new(),
        }
    }

    /// Register a listener that receives all property change events.
    ///
    /// Returns a handle that can be used to remove the listener later.
    pub fn add_listener(&mut self, listener: Box<dyn PropertyChangeListener>) -> ListenerId {
        let id = ListenerId(self.next_id);
        self.next_id += 1;
        self.listeners.insert(
            id,
            ListenerEntry {
                listener,
                filter: Vec::new(),
            },
        );
        id
    }

    /// Register a listener that only receives events for the specified
    /// property names.
    ///
    /// Returns a handle that can be used to remove the listener later.
    pub fn add_filtered_listener(
        &mut self,
        listener: Box<dyn PropertyChangeListener>,
        property_names: Vec<String>,
    ) -> ListenerId {
        let id = ListenerId(self.next_id);
        self.next_id += 1;
        self.listeners.insert(
            id,
            ListenerEntry {
                listener,
                filter: property_names,
            },
        );
        id
    }

    /// Remove a previously registered listener.
    ///
    /// Returns `true` if the listener was found and removed.
    pub fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.listeners.remove(&id).is_some()
    }

    /// The number of registered listeners.
    pub fn listener_count(&self) -> usize {
        self.listeners.len()
    }

    /// Fire a property change event to all matching listeners.
    ///
    /// If the manager is disabled, the event is queued for later delivery
    /// via [`flush_pending`](Self::flush_pending).
    pub fn fire_property_changed(&mut self, event: PropertyChangeEvent) {
        if !self.enabled {
            self.pending.push(event);
            return;
        }
        self.deliver_event(&event);
    }

    /// Convenience: fire a property change for a specific address.
    pub fn fire_address_property_changed(
        &mut self,
        address: &Address,
        property_name: impl Into<String>,
        old_value: Option<PropertyValue>,
        new_value: Option<PropertyValue>,
    ) {
        let event = PropertyChangeEvent::for_address(address, property_name, old_value, new_value);
        self.fire_property_changed(event);
    }

    /// Disable event delivery.  Events fired while disabled are queued.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Re-enable event delivery and flush any queued events.
    pub fn enable(&mut self) {
        self.enabled = true;
        self.flush_pending();
    }

    /// Whether the manager is currently delivering events.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Deliver all queued events and clear the pending queue.
    pub fn flush_pending(&mut self) {
        let events: Vec<PropertyChangeEvent> = self.pending.drain(..).collect();
        for event in events {
            self.deliver_event(&event);
        }
    }

    /// Discard all queued events without delivering them.
    pub fn clear_pending(&mut self) {
        self.pending.clear();
    }

    /// The number of events waiting to be delivered.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Remove all registered listeners and pending events.
    pub fn clear(&mut self) {
        self.listeners.clear();
        self.pending.clear();
    }

    // -- internal --

    fn deliver_event(&mut self, event: &PropertyChangeEvent) {
        for entry in self.listeners.values_mut() {
            if entry.filter.is_empty() || entry.filter.iter().any(|f| f == &event.property_name) {
                entry.listener.property_changed(event);
            }
        }
    }
}

impl Default for PropertyChangeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PropertyChangeManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PropertyChangeManager")
            .field("listener_count", &self.listeners.len())
            .field("enabled", &self.enabled)
            .field("pending_count", &self.pending.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// ScopedPropertyChanges -- RAII guard for grouped changes
// ---------------------------------------------------------------------------

/// An RAII guard that collects property changes within a scope and fires
/// a consolidated notification on drop.
///
/// This mirrors Ghidra's pattern of wrapping batch edits in a transaction
/// and only notifying listeners once the batch completes.
///
/// # Example
///
/// ```ignore
/// use ghidra_features::base::properties::property_change_manager::*;
///
/// let mut mgr = PropertyChangeManager::new();
/// // ... register listeners ...
///
/// {
///     let _scope = ScopedPropertyChanges::new(&mut mgr);
///     // Multiple property changes happen here; events are collected.
/// }
/// // On drop, all collected events are flushed.
/// ```
pub struct ScopedPropertyChanges<'a> {
    manager: &'a mut PropertyChangeManager,
    collected: Vec<PropertyChangeEvent>,
}

impl<'a> ScopedPropertyChanges<'a> {
    /// Begin a scoped property change session.
    ///
    /// Disables immediate event delivery on the manager and starts
    /// collecting events.
    pub fn new(manager: &'a mut PropertyChangeManager) -> Self {
        manager.disable();
        Self {
            manager,
            collected: Vec::new(),
        }
    }

    /// Record a property change within this scope.
    pub fn record(&mut self, event: PropertyChangeEvent) {
        self.collected.push(event);
    }

    /// Record a property change for an address within this scope.
    pub fn record_address(
        &mut self,
        address: &Address,
        property_name: impl Into<String>,
        old_value: Option<PropertyValue>,
        new_value: Option<PropertyValue>,
    ) {
        self.collected
            .push(PropertyChangeEvent::for_address(address, property_name, old_value, new_value));
    }

    /// The number of events collected so far.
    pub fn count(&self) -> usize {
        self.collected.len()
    }

    /// Whether any events have been collected.
    pub fn has_changes(&self) -> bool {
        !self.collected.is_empty()
    }

    /// The collected events (read-only).
    pub fn events(&self) -> &[PropertyChangeEvent] {
        &self.collected
    }

    /// Drop the scope, flushing all collected events.
    fn finish(mut self) {
        // Take the collected events and deliver them.
        let events: Vec<PropertyChangeEvent> = self.collected.drain(..).collect();
        // Re-enable the manager first so delivery works.
        self.manager.enabled = true;
        for event in events {
            self.manager.deliver_event(&event);
        }
    }
}

impl<'a> Drop for ScopedPropertyChanges<'a> {
    fn drop(&mut self) {
        // Deliver any remaining events.
        let events: Vec<PropertyChangeEvent> = self.collected.drain(..).collect();
        self.manager.enabled = true;
        for event in events {
            self.manager.deliver_event(&event);
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// A test listener that records all events it receives.
    #[derive(Debug, Clone)]
    struct RecordingListener {
        events: Arc<Mutex<Vec<PropertyChangeEvent>>>,
    }

    impl RecordingListener {
        fn new() -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn events(&self) -> Vec<PropertyChangeEvent> {
            self.events.lock().unwrap().clone()
        }

        fn event_count(&self) -> usize {
            self.events.lock().unwrap().len()
        }
    }

    impl PropertyChangeListener for RecordingListener {
        fn property_changed(&mut self, event: &PropertyChangeEvent) {
            self.events.lock().unwrap().push(event.clone());
        }
    }

    // -----------------------------------------------------------------------
    // PropertyValue
    // -----------------------------------------------------------------------

    #[test]
    fn test_property_value_display() {
        assert_eq!(PropertyValue::String("hello".into()).to_string(), "hello");
        assert_eq!(PropertyValue::Bool(true).to_string(), "true");
        assert_eq!(PropertyValue::Int(42).to_string(), "42");
        assert_eq!(PropertyValue::Void.to_string(), "<void>");
    }

    // -----------------------------------------------------------------------
    // PropertyChangeEvent
    // -----------------------------------------------------------------------

    #[test]
    fn test_event_construction() {
        let evt = PropertyChangeEvent::new(
            0x1000,
            "COMMENT",
            None,
            Some(PropertyValue::String("new comment".into())),
        );
        assert_eq!(evt.source_id, 0x1000);
        assert_eq!(evt.property_name, "COMMENT");
        assert!(evt.old_value.is_none());
        assert!(evt.new_value.is_some());
    }

    #[test]
    fn test_event_for_address() {
        let addr = Address::new(0xDEAD);
        let evt = PropertyChangeEvent::for_address(&addr, "EQUATE", None, None);
        assert_eq!(evt.source_id, 0xDEAD);
    }

    #[test]
    fn test_event_display() {
        let evt = PropertyChangeEvent::new(0x100, "TEST", None, None);
        let s = format!("{}", evt);
        assert!(s.contains("0x100"));
        assert!(s.contains("TEST"));
    }

    // -----------------------------------------------------------------------
    // PropertyChangeManager -- basic
    // -----------------------------------------------------------------------

    #[test]
    fn test_manager_default() {
        let mgr = PropertyChangeManager::new();
        assert_eq!(mgr.listener_count(), 0);
        assert!(mgr.is_enabled());
        assert_eq!(mgr.pending_count(), 0);
    }

    #[test]
    fn test_add_remove_listener() {
        let mut mgr = PropertyChangeManager::new();
        let id = mgr.add_listener(Box::new(RecordingListener::new()));
        assert_eq!(mgr.listener_count(), 1);

        assert!(mgr.remove_listener(id));
        assert_eq!(mgr.listener_count(), 0);
        assert!(!mgr.remove_listener(id)); // already removed
    }

    #[test]
    fn test_fire_event() {
        let mut mgr = PropertyChangeManager::new();
        let listener = RecordingListener::new();
        let events_ref = listener.events.clone();
        mgr.add_listener(Box::new(listener));

        mgr.fire_property_changed(PropertyChangeEvent::new(
            0x100,
            "COMMENT",
            None,
            Some(PropertyValue::String("hello".into())),
        ));

        let events = events_ref.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].property_name, "COMMENT");
    }

    #[test]
    fn test_fire_address_property_changed() {
        let mut mgr = PropertyChangeManager::new();
        let listener = RecordingListener::new();
        let events_ref = listener.events.clone();
        mgr.add_listener(Box::new(listener));

        mgr.fire_address_property_changed(
            &Address::new(0x200),
            "EQUATE",
            None,
            Some(PropertyValue::Int(42)),
        );

        let events = events_ref.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source_id, 0x200);
    }

    // -----------------------------------------------------------------------
    // PropertyChangeManager -- filtered listeners
    // -----------------------------------------------------------------------

    #[test]
    fn test_filtered_listener() {
        let mut mgr = PropertyChangeManager::new();
        let listener = RecordingListener::new();
        let events_ref = listener.events.clone();
        mgr.add_filtered_listener(
            Box::new(listener),
            vec!["COMMENT".to_string()],
        );

        // This should be received.
        mgr.fire_property_changed(PropertyChangeEvent::new(1, "COMMENT", None, None));
        // This should be filtered out.
        mgr.fire_property_changed(PropertyChangeEvent::new(2, "EQUATE", None, None));

        let events = events_ref.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source_id, 1);
    }

    // -----------------------------------------------------------------------
    // PropertyChangeManager -- enable/disable
    // -----------------------------------------------------------------------

    #[test]
    fn test_disable_enable() {
        let mut mgr = PropertyChangeManager::new();
        let listener = RecordingListener::new();
        let events_ref = listener.events.clone();
        mgr.add_listener(Box::new(listener));

        mgr.disable();
        assert!(!mgr.is_enabled());

        mgr.fire_property_changed(PropertyChangeEvent::new(1, "A", None, None));
        mgr.fire_property_changed(PropertyChangeEvent::new(2, "B", None, None));
        assert_eq!(mgr.pending_count(), 2);

        // Events not yet delivered.
        assert_eq!(events_ref.lock().unwrap().len(), 0);

        mgr.enable();
        assert!(mgr.is_enabled());
        assert_eq!(mgr.pending_count(), 0);

        // Now delivered.
        assert_eq!(events_ref.lock().unwrap().len(), 2);
    }

    #[test]
    fn test_flush_pending() {
        let mut mgr = PropertyChangeManager::new();
        let listener = RecordingListener::new();
        let events_ref = listener.events.clone();
        mgr.add_listener(Box::new(listener));

        mgr.disable();
        mgr.fire_property_changed(PropertyChangeEvent::new(1, "X", None, None));
        mgr.flush_pending();

        assert_eq!(events_ref.lock().unwrap().len(), 1);
        assert_eq!(mgr.pending_count(), 0);
    }

    #[test]
    fn test_clear_pending() {
        let mut mgr = PropertyChangeManager::new();
        mgr.disable();
        mgr.fire_property_changed(PropertyChangeEvent::new(1, "X", None, None));
        assert_eq!(mgr.pending_count(), 1);

        mgr.clear_pending();
        assert_eq!(mgr.pending_count(), 0);
    }

    // -----------------------------------------------------------------------
    // PropertyChangeManager -- clear
    // -----------------------------------------------------------------------

    #[test]
    fn test_clear() {
        let mut mgr = PropertyChangeManager::new();
        mgr.add_listener(Box::new(RecordingListener::new()));
        mgr.disable();
        mgr.fire_property_changed(PropertyChangeEvent::new(1, "X", None, None));

        mgr.clear();
        assert_eq!(mgr.listener_count(), 0);
        assert_eq!(mgr.pending_count(), 0);
    }

    // -----------------------------------------------------------------------
    // ScopedPropertyChanges
    // -----------------------------------------------------------------------

    #[test]
    fn test_scoped_property_changes() {
        let mut mgr = PropertyChangeManager::new();
        let listener = RecordingListener::new();
        let events_ref = listener.events.clone();
        mgr.add_listener(Box::new(listener));

        {
            let mut scope = ScopedPropertyChanges::new(&mut mgr);
            assert!(!mgr_is_enabled_hack(&scope.manager));
            scope.record(PropertyChangeEvent::new(1, "A", None, None));
            scope.record(PropertyChangeEvent::new(2, "B", None, None));
            assert_eq!(scope.count(), 2);
            assert!(scope.has_changes());
        }
        // After drop, events are delivered and manager is re-enabled.

        // Note: we can't access `mgr` after the scope because of borrowing,
        // but the events should have been delivered.
        // We verify via the listener's events reference.
        assert_eq!(events_ref.lock().unwrap().len(), 2);
    }

    #[test]
    fn test_scoped_record_address() {
        let mut mgr = PropertyChangeManager::new();
        let listener = RecordingListener::new();
        let events_ref = listener.events.clone();
        mgr.add_listener(Box::new(listener));

        {
            let mut scope = ScopedPropertyChanges::new(&mut mgr);
            scope.record_address(
                &Address::new(0x300),
                "COMMENT",
                None,
                Some(PropertyValue::String("test".into())),
            );
        }

        let events = events_ref.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source_id, 0x300);
    }

    #[test]
    fn test_scoped_empty() {
        let mut mgr = PropertyChangeManager::new();
        let listener = RecordingListener::new();
        let events_ref = listener.events.clone();
        mgr.add_listener(Box::new(listener));

        {
            let scope = ScopedPropertyChanges::new(&mut mgr);
            assert!(!scope.has_changes());
            assert_eq!(scope.count(), 0);
        }

        assert_eq!(events_ref.lock().unwrap().len(), 0);
    }

    // Helper to peek at the manager's enabled state inside a scope.
    fn mgr_is_enabled_hack(mgr: &PropertyChangeManager) -> bool {
        mgr.enabled
    }
}
