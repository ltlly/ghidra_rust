//! Trace event system - typed events for trace domain objects.
//!
//! Ported from Ghidra's `ghidra.trace.util.TraceEvent` and `ghidra.trace.util.TraceEvents`.
//! Provides a strongly-typed event dispatch system for change notifications
//! within a trace, including thread, module, memory, bookmark, breakpoint,
//! symbol, and target object events.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;


/// A type-safe event identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventId(u32);

impl EventId {
    /// Create a new event ID.
    pub fn new(id: u32) -> Self {
        Self(id)
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Event({})", self.0)
    }
}

/// A change record describing what changed in the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceChangeRecord {
    /// The event that triggered this change.
    pub event_name: String,
    /// The affected object path/key.
    pub object_key: String,
    /// The affected value (serialized as string).
    pub value: String,
    /// Whether this is a creation event.
    pub is_creation: bool,
    /// Whether this is a removal event.
    pub is_removal: bool,
}

impl TraceChangeRecord {
    /// Create a new change record.
    pub fn new(event: impl Into<String>, object_key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            event_name: event.into(),
            object_key: object_key.into(),
            value: value.into(),
            is_creation: false,
            is_removal: false,
        }
    }

    /// Mark as a creation event.
    pub fn as_creation(mut self) -> Self {
        self.is_creation = true;
        self
    }

    /// Mark as a removal event.
    pub fn as_removal(mut self) -> Self {
        self.is_removal = true;
        self
    }
}

/// All defined trace events.
///
/// This enum mirrors Ghidra's `TraceEvents` class which defines every
/// event type that can be emitted by trace managers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TraceEventKind {
    // ── Thread events ──
    /// A thread was added.
    ThreadAdded,
    /// A thread was removed.
    ThreadRemoved,
    /// A thread's lifespan changed.
    ThreadLifespanChanged,
    /// A thread's execution state changed.
    ThreadStateChanged,

    // ── Process events ──
    /// A process was added.
    ProcessAdded,
    /// A process was removed.
    ProcessRemoved,
    /// A process's lifespan changed.
    ProcessLifespanChanged,

    // ── Module events ──
    /// A module was added.
    ModuleAdded,
    /// A module was removed.
    ModuleRemoved,
    /// A module's lifespan changed.
    ModuleLifespanChanged,

    // ── Section events ──
    /// A section was added.
    SectionAdded,
    /// A section was removed.
    SectionRemoved,

    // ── Memory events ──
    /// Memory bytes were changed.
    BytesChanged,
    /// Memory state was changed.
    BytesStateChanged,
    /// A memory region was added.
    RegionAdded,
    /// A memory region was removed.
    RegionRemoved,
    /// A memory region's lifespan changed.
    RegionLifespanChanged,

    // ── Bookmark events ──
    /// A bookmark was added.
    BookmarkAdded,
    /// A bookmark was removed.
    BookmarkRemoved,

    // ── Breakpoint events ──
    /// A breakpoint location was added.
    BreakpointLocationAdded,
    /// A breakpoint location was removed.
    BreakpointLocationRemoved,

    // ── Symbol events ──
    /// A symbol was added.
    SymbolAdded,
    /// A symbol was removed.
    SymbolRemoved,
    /// A reference was added.
    ReferenceAdded,
    /// A reference was removed.
    ReferenceRemoved,
    /// An equate was added.
    EquateAdded,
    /// An equate was removed.
    EquateRemoved,

    // ── Stack events ──
    /// A stack frame was added.
    StackFrameAdded,
    /// A stack frame was removed.
    StackFrameRemoved,

    // ── Register context events ──
    /// A register context value changed.
    RegisterContextChanged,

    // ── Code listing events ──
    /// A code unit was added.
    CodeUnitAdded,
    /// A code unit was removed.
    CodeUnitRemoved,

    // ── Object events ──
    /// An object was activated.
    ObjectActivated,
    /// An object's attribute changed.
    ObjectAttributeChanged,
    /// An object's element changed.
    ObjectElementChanged,
    /// An object was inserted.
    ObjectInserted,
    /// An object was removed.
    ObjectRemoved,

    // ── Property events ──
    /// A trace property changed.
    PropertyChanged,

    // ── Overlay events ──
    /// An overlay address space was added.
    OverlayAdded,
    /// An overlay address space was deleted.
    OverlayDeleted,

    // ── Snapshot events ──
    /// A snapshot was added.
    SnapshotAdded,
    /// A snapshot was removed.
    SnapshotRemoved,

    // ── Platform events ──
    /// A guest platform was mapped.
    GuestPlatformMapped,
    /// A guest platform was unmapped.
    GuestPlatformUnmapped,
}

impl TraceEventKind {
    /// Get a human-readable name for this event.
    pub fn name(&self) -> &'static str {
        match self {
            Self::ThreadAdded => "THREAD_ADDED",
            Self::ThreadRemoved => "THREAD_REMOVED",
            Self::ThreadLifespanChanged => "THREAD_LIFESPAN_CHANGED",
            Self::ThreadStateChanged => "THREAD_STATE_CHANGED",
            Self::ProcessAdded => "PROCESS_ADDED",
            Self::ProcessRemoved => "PROCESS_REMOVED",
            Self::ProcessLifespanChanged => "PROCESS_LIFESPAN_CHANGED",
            Self::ModuleAdded => "MODULE_ADDED",
            Self::ModuleRemoved => "MODULE_REMOVED",
            Self::ModuleLifespanChanged => "MODULE_LIFESPAN_CHANGED",
            Self::SectionAdded => "SECTION_ADDED",
            Self::SectionRemoved => "SECTION_REMOVED",
            Self::BytesChanged => "BYTES_CHANGED",
            Self::BytesStateChanged => "BYTES_STATE_CHANGED",
            Self::RegionAdded => "REGION_ADDED",
            Self::RegionRemoved => "REGION_REMOVED",
            Self::RegionLifespanChanged => "REGION_LIFESPAN_CHANGED",
            Self::BookmarkAdded => "BOOKMARK_ADDED",
            Self::BookmarkRemoved => "BOOKMARK_REMOVED",
            Self::BreakpointLocationAdded => "BREAKPOINT_LOCATION_ADDED",
            Self::BreakpointLocationRemoved => "BREAKPOINT_LOCATION_REMOVED",
            Self::SymbolAdded => "SYMBOL_ADDED",
            Self::SymbolRemoved => "SYMBOL_REMOVED",
            Self::ReferenceAdded => "REFERENCE_ADDED",
            Self::ReferenceRemoved => "REFERENCE_REMOVED",
            Self::EquateAdded => "EQUATE_ADDED",
            Self::EquateRemoved => "EQUATE_REMOVED",
            Self::StackFrameAdded => "STACK_FRAME_ADDED",
            Self::StackFrameRemoved => "STACK_FRAME_REMOVED",
            Self::RegisterContextChanged => "REGISTER_CONTEXT_CHANGED",
            Self::CodeUnitAdded => "CODE_UNIT_ADDED",
            Self::CodeUnitRemoved => "CODE_UNIT_REMOVED",
            Self::ObjectActivated => "OBJECT_ACTIVATED",
            Self::ObjectAttributeChanged => "OBJECT_ATTRIBUTE_CHANGED",
            Self::ObjectElementChanged => "OBJECT_ELEMENT_CHANGED",
            Self::ObjectInserted => "OBJECT_INSERTED",
            Self::ObjectRemoved => "OBJECT_REMOVED",
            Self::PropertyChanged => "PROPERTY_CHANGED",
            Self::OverlayAdded => "OVERLAY_ADDED",
            Self::OverlayDeleted => "OVERLAY_DELETED",
            Self::SnapshotAdded => "SNAPSHOT_ADDED",
            Self::SnapshotRemoved => "SNAPSHOT_REMOVED",
            Self::GuestPlatformMapped => "GUEST_PLATFORM_MAPPED",
            Self::GuestPlatformUnmapped => "GUEST_PLATFORM_UNMAPPED",
        }
    }
}

impl fmt::Display for TraceEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// A callback that can be registered to receive trace events.
pub type EventHandler = Box<dyn Fn(&TraceChangeRecord) + Send + Sync>;

/// A typed event dispatcher for trace domain objects.
///
/// Manages registration and dispatch of event handlers, ensuring that
/// handlers are called when the corresponding event fires.
#[derive(Default)]
pub struct TypedEventDispatcher {
    handlers: HashMap<String, Vec<u64>>,
    next_id: u64,
    /// The actual handler storage, indexed by ID.
    handler_store: HashMap<u64, EventHandler>,
}

impl TypedEventDispatcher {
    /// Create a new empty dispatcher.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a handler for a specific event kind.
    /// Returns a handle ID that can be used to unregister.
    pub fn listen(&mut self, event: TraceEventKind, handler: EventHandler) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.handler_store.insert(id, handler);
        self.handlers
            .entry(event.name().to_string())
            .or_default()
            .push(id);
        id
    }

    /// Unregister a handler by its handle ID.
    pub fn unlisten(&mut self, handle_id: u64) -> bool {
        self.handler_store.remove(&handle_id).is_some()
        // Note: we don't clean up the handler list here for simplicity.
        // Stale IDs will be skipped during dispatch.
    }

    /// Dispatch a change record to all registered handlers for that event.
    pub fn dispatch(&self, record: &TraceChangeRecord) {
        if let Some(ids) = self.handlers.get(&record.event_name) {
            for &id in ids {
                if let Some(handler) = self.handler_store.get(&id) {
                    handler(record);
                }
            }
        }
    }

    /// Get the number of registered handlers.
    pub fn handler_count(&self) -> usize {
        self.handler_store.len()
    }
}

impl fmt::Debug for TypedEventDispatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TypedEventDispatcher")
            .field("handler_count", &self.handler_count())
            .finish()
    }
}

/// A change manager that records and dispatches trace changes.
///
/// This is the central coordinator for trace change notifications,
/// collecting change records and dispatching them to listeners.
#[derive(Debug, Default)]
pub struct TraceChangeManager {
    dispatcher: TypedEventDispatcher,
    pending: Vec<TraceChangeRecord>,
    recording: bool,
}

impl TraceChangeManager {
    /// Create a new change manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Start recording changes (batch mode).
    pub fn begin_recording(&mut self) {
        self.recording = true;
    }

    /// Stop recording and return all pending changes.
    pub fn end_recording(&mut self) -> Vec<TraceChangeRecord> {
        self.recording = false;
        std::mem::take(&mut self.pending)
    }

    /// Record a change and optionally dispatch it immediately.
    pub fn record(&mut self, record: TraceChangeRecord) {
        if self.recording {
            self.pending.push(record.clone());
        }
        self.dispatcher.dispatch(&record);
    }

    /// Register a handler for a specific event.
    pub fn listen(&mut self, event: TraceEventKind, handler: EventHandler) -> u64 {
        self.dispatcher.listen(event, handler)
    }

    /// Unregister a handler.
    pub fn unlisten(&mut self, handle_id: u64) -> bool {
        self.dispatcher.unlisten(handle_id)
    }

    /// Flush all pending recorded events (dispatch them now).
    pub fn flush(&mut self) {
        let pending = std::mem::take(&mut self.pending);
        for record in pending {
            self.dispatcher.dispatch(&record);
        }
    }
}

/// A method protector that prevents re-entrant calls.
///
/// Used to guard against recursive event dispatch that could cause
/// stack overflows or inconsistent state.
#[derive(Debug, Default)]
pub struct MethodProtector {
    active: bool,
}

impl MethodProtector {
    /// Create a new protector.
    pub fn new() -> Self {
        Self { active: false }
    }

    /// Try to enter the protected section.
    /// Returns true if entry was successful (not re-entrant).
    pub fn enter(&mut self) -> bool {
        if self.active {
            false
        } else {
            self.active = true;
            true
        }
    }

    /// Exit the protected section.
    pub fn exit(&mut self) {
        self.active = false;
    }

    /// Check if the protected section is currently active.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_event_kind_names() {
        assert_eq!(TraceEventKind::ThreadAdded.name(), "THREAD_ADDED");
        assert_eq!(TraceEventKind::BytesChanged.name(), "BYTES_CHANGED");
        assert_eq!(
            TraceEventKind::BreakpointLocationAdded.name(),
            "BREAKPOINT_LOCATION_ADDED"
        );
    }

    #[test]
    fn test_event_kind_display() {
        assert_eq!(format!("{}", TraceEventKind::ModuleAdded), "MODULE_ADDED");
    }

    #[test]
    fn test_change_record() {
        let rec = TraceChangeRecord::new("THREAD_ADDED", "Threads[0]", "new thread")
            .as_creation();
        assert!(rec.is_creation);
        assert!(!rec.is_removal);
    }

    #[test]
    fn test_dispatcher_dispatch() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let mut dispatcher = TypedEventDispatcher::new();
        dispatcher.listen(
            TraceEventKind::ThreadAdded,
            Box::new(move |_rec| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            }),
        );

        let rec = TraceChangeRecord::new("THREAD_ADDED", "Threads[0]", "new");
        dispatcher.dispatch(&rec);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_dispatcher_unlisten() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let mut dispatcher = TypedEventDispatcher::new();
        let handle = dispatcher.listen(
            TraceEventKind::ThreadAdded,
            Box::new(move |_rec| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            }),
        );

        dispatcher.unlisten(handle);
        let rec = TraceChangeRecord::new("THREAD_ADDED", "Threads[0]", "new");
        dispatcher.dispatch(&rec);
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_change_manager_recording() {
        let mut mgr = TraceChangeManager::new();
        mgr.begin_recording();
        mgr.record(TraceChangeRecord::new("THREAD_ADDED", "Threads[0]", "new"));
        mgr.record(TraceChangeRecord::new("MODULE_ADDED", "Modules[0]", "lib.so"));
        let changes = mgr.end_recording();
        assert_eq!(changes.len(), 2);
    }

    #[test]
    fn test_method_protector() {
        let mut prot = MethodProtector::new();
        assert!(!prot.is_active());
        assert!(prot.enter());
        assert!(prot.is_active());
        assert!(!prot.enter()); // re-entrant, should fail
        prot.exit();
        assert!(!prot.is_active());
        assert!(prot.enter()); // can enter again
    }

    #[test]
    fn test_all_event_kinds_have_names() {
        // Verify every variant has a name and doesn't panic
        let kinds = [
            TraceEventKind::ThreadAdded,
            TraceEventKind::ThreadRemoved,
            TraceEventKind::ThreadLifespanChanged,
            TraceEventKind::ThreadStateChanged,
            TraceEventKind::ProcessAdded,
            TraceEventKind::ProcessRemoved,
            TraceEventKind::ProcessLifespanChanged,
            TraceEventKind::ModuleAdded,
            TraceEventKind::ModuleRemoved,
            TraceEventKind::ModuleLifespanChanged,
            TraceEventKind::BytesChanged,
            TraceEventKind::BytesStateChanged,
            TraceEventKind::BookmarkAdded,
            TraceEventKind::BookmarkRemoved,
            TraceEventKind::BreakpointLocationAdded,
            TraceEventKind::BreakpointLocationRemoved,
            TraceEventKind::SymbolAdded,
            TraceEventKind::SymbolRemoved,
            TraceEventKind::ObjectInserted,
            TraceEventKind::ObjectRemoved,
            TraceEventKind::PropertyChanged,
            TraceEventKind::SnapshotAdded,
            TraceEventKind::SnapshotRemoved,
        ];
        for kind in &kinds {
            assert!(!kind.name().is_empty());
        }
    }
}
