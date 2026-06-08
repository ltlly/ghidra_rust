//! Domain object listener abstraction for the Ghidra framework.
//!
//! Ports Ghidra's `framework.model.DomainObjectListener` interface. Listeners
//! are notified when a domain object changes, is about to close, or has closed.

use std::fmt;

// ============================================================================
// DomainObjectListener trait
// ============================================================================

/// A listener that receives notifications about changes to a domain object.
///
/// Register listeners via [`DomainObject::add_listener`](super::domain_object::DomainObject::add_listener).
/// Implementations should be thread-safe.
pub trait DomainObjectListener: fmt::Debug + Send + Sync {
    /// Called when the domain object has changed.
    ///
    /// The `event` describes what changed.
    fn domain_object_changed(&self, event: &DomainObjectChangeEvent);

    /// Called just before the domain object is closed.
    fn domain_object_about_to_close(&self);

    /// Called after the domain object has been closed.
    fn domain_object_closed(&self);
}

// ============================================================================
// DomainObjectChangeEvent
// ============================================================================

/// Describes a change that occurred in a domain object.
#[derive(Debug, Clone)]
pub struct DomainObjectChangeEvent {
    /// The type of change that occurred.
    pub event_type: DomainObjectChangeType,
    /// Human-readable description of the change.
    pub description: String,
}

impl DomainObjectChangeEvent {
    /// Create a new change event.
    pub fn new(event_type: DomainObjectChangeType, description: impl Into<String>) -> Self {
        Self {
            event_type,
            description: description.into(),
        }
    }
}

impl fmt::Display for DomainObjectChangeEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:?}] {}", self.event_type, self.description)
    }
}

// ============================================================================
// DomainObjectChangeType
// ============================================================================

/// Enumeration of domain object change types.
///
/// Each variant represents a category of change that can occur within
/// a domain object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainObjectChangeType {
    /// Memory content changed.
    MemoryChanged,
    /// A memory block was added.
    MemoryBlockAdded,
    /// A memory block was removed.
    MemoryBlockRemoved,
    /// A memory block was moved.
    MemoryBlockMoved,
    /// Code (instructions) changed.
    CodeChanged,
    /// Code was added.
    CodeAdded,
    /// Code was removed.
    CodeRemoved,
    /// Code was replaced.
    CodeReplaced,
    /// A data type was changed.
    DataTypeChanged,
    /// A data type was added.
    DataTypeAdded,
    /// A data type was removed.
    DataTypeRemoved,
    /// A symbol was added.
    SymbolAdded,
    /// A symbol was removed.
    SymbolRemoved,
    /// A symbol was renamed.
    SymbolRenamed,
    /// A symbol was moved.
    SymbolMoved,
    /// A symbol's source changed.
    SymbolSourceChanged,
    /// A symbol's primary status changed.
    SymbolPrimaryChanged,
    /// A function was added.
    FunctionAdded,
    /// A function was removed.
    FunctionRemoved,
    /// A function was changed.
    FunctionChanged,
    /// A reference was added.
    ReferenceAdded,
    /// A reference was removed.
    ReferenceRemoved,
    /// A bookmark was added.
    BookmarkAdded,
    /// A bookmark was removed.
    BookmarkRemoved,
    /// A bookmark was changed.
    BookmarkChanged,
    /// An external program was added.
    ExternalProgramAdded,
    /// An external program was removed.
    ExternalProgramRemoved,
    /// A relocation was added.
    RelocationAdded,
    /// A property changed.
    PropertyChanged,
    /// The language changed.
    LanguageChanged,
    /// The object was restored from a save/undo.
    Restored,
    /// A generic, unclassified change.
    Other,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Arc;

    #[derive(Debug)]
    struct TestListener {
        changed_count: Arc<AtomicU32>,
        about_to_close_called: Arc<AtomicBool>,
        closed_called: Arc<AtomicBool>,
    }

    impl TestListener {
        fn new() -> (Self, Arc<AtomicU32>, Arc<AtomicBool>, Arc<AtomicBool>) {
            let changed = Arc::new(AtomicU32::new(0));
            let about_to_close = Arc::new(AtomicBool::new(false));
            let closed = Arc::new(AtomicBool::new(false));
            let listener = Self {
                changed_count: changed.clone(),
                about_to_close_called: about_to_close.clone(),
                closed_called: closed.clone(),
            };
            (listener, changed, about_to_close, closed)
        }
    }

    impl DomainObjectListener for TestListener {
        fn domain_object_changed(&self, _event: &DomainObjectChangeEvent) {
            self.changed_count.fetch_add(1, Ordering::Relaxed);
        }
        fn domain_object_about_to_close(&self) {
            self.about_to_close_called.store(true, Ordering::Relaxed);
        }
        fn domain_object_closed(&self) {
            self.closed_called.store(true, Ordering::Relaxed);
        }
    }

    #[test]
    fn test_listener_change_notification() {
        let (listener, changed, _, _) = TestListener::new();
        let event = DomainObjectChangeEvent::new(
            DomainObjectChangeType::MemoryChanged,
            "memory block modified",
        );
        listener.domain_object_changed(&event);
        listener.domain_object_changed(&event);
        assert_eq!(changed.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_listener_close_notification() {
        let (listener, _, about_to_close, closed) = TestListener::new();
        listener.domain_object_about_to_close();
        assert!(about_to_close.load(Ordering::Relaxed));
        listener.domain_object_closed();
        assert!(closed.load(Ordering::Relaxed));
    }

    #[test]
    fn test_change_event_display() {
        let event = DomainObjectChangeEvent::new(
            DomainObjectChangeType::SymbolAdded,
            "added symbol main",
        );
        let s = format!("{}", event);
        assert!(s.contains("SymbolAdded"));
        assert!(s.contains("added symbol main"));
    }

    #[test]
    fn test_change_type_equality() {
        assert_eq!(
            DomainObjectChangeType::MemoryChanged,
            DomainObjectChangeType::MemoryChanged
        );
        assert_ne!(
            DomainObjectChangeType::MemoryChanged,
            DomainObjectChangeType::CodeChanged
        );
    }
}
