//! Trace domain object event listener infrastructure.
//!
//! Ported from Ghidra's `TraceDomainObjectListener` in
//! `ghidra.trace.model`. Provides a type-safe event dispatch system
//! for trace changes including threads, modules, regions, breakpoints,
//! bookmarks, and other trace entities.

use serde::{Deserialize, Serialize};

/// The kind of trace event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TraceEventKind {
    /// A thread was added.
    ThreadAdded,
    /// A thread was changed.
    ThreadChanged,
    /// A thread's lifespan changed.
    ThreadLifespanChanged,
    /// A thread was deleted.
    ThreadDeleted,
    /// A module was added.
    ModuleAdded,
    /// A module was changed.
    ModuleChanged,
    /// A module's lifespan changed.
    ModuleLifespanChanged,
    /// A module was deleted.
    ModuleDeleted,
    /// A memory region was added.
    RegionAdded,
    /// A memory region was changed.
    RegionChanged,
    /// A region's lifespan changed.
    RegionLifespanChanged,
    /// A memory region was deleted.
    RegionDeleted,
    /// A breakpoint was added.
    BreakpointAdded,
    /// A breakpoint was changed.
    BreakpointChanged,
    /// A breakpoint's lifespan changed.
    BreakpointLifespanChanged,
    /// A breakpoint was deleted.
    BreakpointDeleted,
    /// A bookmark was added.
    BookmarkAdded,
    /// A bookmark was changed.
    BookmarkChanged,
    /// A bookmark's lifespan changed.
    BookmarkLifespanChanged,
    /// A bookmark was deleted.
    BookmarkDeleted,
    /// A process was added.
    ProcessAdded,
    /// A process was deleted.
    ProcessDeleted,
    /// Memory bytes were written.
    MemoryBytesChanged,
    /// Register values were written.
    RegistersChanged,
    /// A snapshot was created.
    SnapshotCreated,
    /// The trace was restored (full refresh).
    TraceRestored,
}

impl TraceEventKind {
    /// Whether this is an "added" event.
    pub fn is_added(&self) -> bool {
        matches!(
            self,
            Self::ThreadAdded
                | Self::ModuleAdded
                | Self::RegionAdded
                | Self::BreakpointAdded
                | Self::BookmarkAdded
                | Self::ProcessAdded
                | Self::SnapshotCreated
        )
    }

    /// Whether this is a "deleted" event.
    pub fn is_deleted(&self) -> bool {
        matches!(
            self,
            Self::ThreadDeleted
                | Self::ModuleDeleted
                | Self::RegionDeleted
                | Self::BreakpointDeleted
                | Self::BookmarkDeleted
                | Self::ProcessDeleted
        )
    }

    /// Whether this is a "changed" event.
    pub fn is_changed(&self) -> bool {
        matches!(
            self,
            Self::ThreadChanged
                | Self::ThreadLifespanChanged
                | Self::ModuleChanged
                | Self::ModuleLifespanChanged
                | Self::RegionChanged
                | Self::RegionLifespanChanged
                | Self::BreakpointChanged
                | Self::BreakpointLifespanChanged
                | Self::BookmarkChanged
                | Self::BookmarkLifespanChanged
                | Self::MemoryBytesChanged
                | Self::RegistersChanged
        )
    }

    /// Whether this event relates to threads.
    pub fn is_thread_event(&self) -> bool {
        matches!(
            self,
            Self::ThreadAdded | Self::ThreadChanged | Self::ThreadLifespanChanged | Self::ThreadDeleted
        )
    }

    /// Whether this event relates to modules.
    pub fn is_module_event(&self) -> bool {
        matches!(
            self,
            Self::ModuleAdded | Self::ModuleChanged | Self::ModuleLifespanChanged | Self::ModuleDeleted
        )
    }

    /// Whether this event relates to memory regions.
    pub fn is_region_event(&self) -> bool {
        matches!(
            self,
            Self::RegionAdded | Self::RegionChanged | Self::RegionLifespanChanged | Self::RegionDeleted
        )
    }

    /// Whether this event relates to breakpoints.
    pub fn is_breakpoint_event(&self) -> bool {
        matches!(
            self,
            Self::BreakpointAdded
                | Self::BreakpointChanged
                | Self::BreakpointLifespanChanged
                | Self::BreakpointDeleted
        )
    }

    /// Whether this event relates to bookmarks.
    pub fn is_bookmark_event(&self) -> bool {
        matches!(
            self,
            Self::BookmarkAdded
                | Self::BookmarkChanged
                | Self::BookmarkLifespanChanged
                | Self::BookmarkDeleted
        )
    }
}

/// A trace domain object change record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDomainChangeRecord {
    /// The kind of event.
    pub event_kind: TraceEventKind,
    /// The object path (for target object events).
    pub object_path: Option<String>,
    /// The snap (for snap-related events).
    pub snap: Option<i64>,
    /// An associated name or identifier.
    pub name: Option<String>,
}

/// A trait for listening to trace domain object events.
///
/// Ported from Ghidra's `TraceDomainObjectListener`.
pub trait TraceDomainObjectEventListener: Send + Sync {
    /// Called when any event occurs.
    fn on_event(&self, record: &TraceDomainChangeRecord);

    /// Called when the trace is restored.
    fn on_trace_restored(&self) {
        // Default: do nothing
    }
}

/// A composite event listener that dispatches to multiple listeners.
#[derive(Default)]
pub struct CompositeTraceListener {
    listeners: Vec<Box<dyn TraceDomainObjectEventListener>>,
}

impl std::fmt::Debug for CompositeTraceListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositeTraceListener")
            .field("listener_count", &self.listeners.len())
            .finish()
    }
}

impl CompositeTraceListener {
    /// Create a new composite listener.
    pub fn new() -> Self {
        Self {
            listeners: Vec::new(),
        }
    }

    /// Add a listener.
    pub fn add_listener(&mut self, listener: Box<dyn TraceDomainObjectEventListener>) {
        self.listeners.push(listener);
    }

    /// Dispatch an event to all listeners.
    pub fn dispatch(&self, record: &TraceDomainChangeRecord) {
        for listener in &self.listeners {
            listener.on_event(record);
        }
        if record.event_kind == TraceEventKind::TraceRestored {
            for listener in &self.listeners {
                listener.on_trace_restored();
            }
        }
    }

    /// Get the number of registered listeners.
    pub fn listener_count(&self) -> usize {
        self.listeners.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct CountingListener {
        count: Arc<AtomicUsize>,
    }

    impl TraceDomainObjectEventListener for CountingListener {
        fn on_event(&self, _record: &TraceDomainChangeRecord) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_event_kind_classification() {
        assert!(TraceEventKind::ThreadAdded.is_added());
        assert!(!TraceEventKind::ThreadAdded.is_deleted());
        assert!(TraceEventKind::ThreadDeleted.is_deleted());
        assert!(TraceEventKind::ThreadChanged.is_changed());
        assert!(TraceEventKind::TraceRestored.is_changed() == false);
    }

    #[test]
    fn test_event_kind_entity_type() {
        assert!(TraceEventKind::ThreadAdded.is_thread_event());
        assert!(!TraceEventKind::ThreadAdded.is_module_event());
        assert!(TraceEventKind::ModuleAdded.is_module_event());
        assert!(TraceEventKind::RegionAdded.is_region_event());
        assert!(TraceEventKind::BreakpointAdded.is_breakpoint_event());
        assert!(TraceEventKind::BookmarkAdded.is_bookmark_event());
    }

    #[test]
    fn test_composite_listener_dispatch() {
        let count = Arc::new(AtomicUsize::new(0));
        let mut composite = CompositeTraceListener::new();
        composite.add_listener(Box::new(CountingListener {
            count: count.clone(),
        }));
        composite.add_listener(Box::new(CountingListener {
            count: count.clone(),
        }));

        let record = TraceDomainChangeRecord {
            event_kind: TraceEventKind::ThreadAdded,
            object_path: None,
            snap: Some(0),
            name: Some("main".into()),
        };
        composite.dispatch(&record);
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_composite_listener_restored() {
        let count = Arc::new(AtomicUsize::new(0));
        let mut composite = CompositeTraceListener::new();
        composite.add_listener(Box::new(CountingListener {
            count: count.clone(),
        }));

        let record = TraceDomainChangeRecord {
            event_kind: TraceEventKind::TraceRestored,
            object_path: None,
            snap: None,
            name: None,
        };
        composite.dispatch(&record);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_composite_listener_count() {
        let mut composite = CompositeTraceListener::new();
        assert_eq!(composite.listener_count(), 0);
        composite.add_listener(Box::new(CountingListener {
            count: Arc::new(AtomicUsize::new(0)),
        }));
        assert_eq!(composite.listener_count(), 1);
    }

    #[test]
    fn test_change_record_serde() {
        let record = TraceDomainChangeRecord {
            event_kind: TraceEventKind::ModuleAdded,
            object_path: Some("/Processes/1/Modules".into()),
            snap: Some(5),
            name: Some("libc.so".into()),
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: TraceDomainChangeRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.event_kind, TraceEventKind::ModuleAdded);
        assert_eq!(back.snap, Some(5));
    }

    #[test]
    fn test_all_event_kinds() {
        let all = [
            TraceEventKind::ThreadAdded,
            TraceEventKind::ThreadChanged,
            TraceEventKind::ThreadLifespanChanged,
            TraceEventKind::ThreadDeleted,
            TraceEventKind::ModuleAdded,
            TraceEventKind::ModuleChanged,
            TraceEventKind::ModuleLifespanChanged,
            TraceEventKind::ModuleDeleted,
            TraceEventKind::RegionAdded,
            TraceEventKind::RegionChanged,
            TraceEventKind::RegionLifespanChanged,
            TraceEventKind::RegionDeleted,
            TraceEventKind::BreakpointAdded,
            TraceEventKind::BreakpointChanged,
            TraceEventKind::BreakpointLifespanChanged,
            TraceEventKind::BreakpointDeleted,
            TraceEventKind::BookmarkAdded,
            TraceEventKind::BookmarkChanged,
            TraceEventKind::BookmarkLifespanChanged,
            TraceEventKind::BookmarkDeleted,
            TraceEventKind::ProcessAdded,
            TraceEventKind::ProcessDeleted,
            TraceEventKind::MemoryBytesChanged,
            TraceEventKind::RegistersChanged,
            TraceEventKind::SnapshotCreated,
            TraceEventKind::TraceRestored,
        ];
        assert_eq!(all.len(), 26);
    }
}
