//! Composite editor listener interfaces.
//!
//! Ported from `ghidra.app.plugin.core.compositeeditor.CompositeChangeListener`
//! and `CompositeEditorModelListener`.

/// Events emitted by the composite editor model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompositeChangeEvent {
    /// A component was added.
    ComponentAdded { row: usize },
    /// A component was removed.
    ComponentRemoved { row: usize },
    /// A component's type was changed.
    ComponentTypeChanged { row: usize },
    /// A component's name was changed.
    ComponentNameChanged { row: usize },
    /// Components were reordered.
    ComponentsReordered,
    /// All components were cleared.
    ComponentsCleared,
    /// The editor lock state changed.
    LockStateChanged { locked: bool },
    /// The alignment changed.
    AlignmentChanged { alignment: usize },
}

/// Trait for listening to composite editor changes.
pub trait CompositeChangeListener: std::fmt::Debug {
    /// Called when a change occurs in the composite editor.
    fn on_change(&self, event: &CompositeChangeEvent);

    /// Called when the editor model is about to be disposed.
    fn on_dispose(&self) {}
}

/// Lock state change listener interface.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.CompositeEditorLockListener`.
pub trait CompositeEditorLockListener: std::fmt::Debug {
    /// Called when the editor lock/unlock state changes.
    ///
    /// # Parameters
    /// * `locked` - true if the editor is now locked, false if unlocked.
    fn lock_state_changed(&self, locked: bool);
}

/// Model listener adapter providing no-op default implementations.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.CompositeEditorModelAdapter`.
#[derive(Debug, Default)]
pub struct CompositeEditorModelAdapter;

impl CompositeChangeListener for CompositeEditorModelAdapter {
    fn on_change(&self, _event: &CompositeChangeEvent) {}
    fn on_dispose(&self) {}
}

impl CompositeEditorLockListener for CompositeEditorModelAdapter {
    fn lock_state_changed(&self, _locked: bool) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestListener {
        events: std::sync::Mutex<Vec<CompositeChangeEvent>>,
    }

    impl TestListener {
        fn new() -> Self {
            Self {
                events: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl CompositeChangeListener for TestListener {
        fn on_change(&self, event: &CompositeChangeEvent) {
            self.events.lock().unwrap().push(event.clone());
        }
    }

    #[test]
    fn test_listener_receives_events() {
        let listener = TestListener::new();
        let event = CompositeChangeEvent::ComponentAdded { row: 0 };
        listener.on_change(&event);
        let events = listener.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], CompositeChangeEvent::ComponentAdded { row: 0 });
    }

    #[test]
    fn test_adapter_noop() {
        let adapter = CompositeEditorModelAdapter;
        adapter.on_change(&CompositeChangeEvent::ComponentsCleared);
        adapter.on_dispose();
        adapter.lock_state_changed(true);
        // Should not panic
    }

    #[test]
    fn test_event_variants() {
        let events = vec![
            CompositeChangeEvent::ComponentAdded { row: 0 },
            CompositeChangeEvent::ComponentRemoved { row: 1 },
            CompositeChangeEvent::ComponentTypeChanged { row: 2 },
            CompositeChangeEvent::ComponentNameChanged { row: 3 },
            CompositeChangeEvent::ComponentsReordered,
            CompositeChangeEvent::ComponentsCleared,
            CompositeChangeEvent::LockStateChanged { locked: true },
            CompositeChangeEvent::AlignmentChanged { alignment: 8 },
        ];
        assert_eq!(events.len(), 8);
    }
}
