//! TraceRecorder -- records trace events for later replay or analysis.
//!
//! Ported from Ghidra's `TraceRecorder` concept in the
//! `Framework-TraceModeling` package.
//!
//! A `TraceRecorder` captures a sequence of trace events (memory writes,
//! register changes, thread creation, breakpoints, etc.) in order. It can
//! be used to build a trace from scratch, to record a live debugging session,
//! or to log events for later replay.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::target::key_path::KeyPath;

// ---------------------------------------------------------------------------
// RecordedEvent -- a single captured event
// ---------------------------------------------------------------------------

/// A recorded trace event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecordedEvent {
    /// A memory region was mapped.
    MemoryRegionCreated {
        /// The object path of the region.
        path: KeyPath,
        /// The region name.
        name: String,
        /// Start address.
        start: u64,
        /// End address (inclusive).
        end: u64,
        /// The snap at which this was recorded.
        snap: i64,
    },
    /// Memory bytes were written.
    MemoryBytesWritten {
        /// The address space name.
        space: String,
        /// The start offset.
        offset: u64,
        /// The bytes written.
        bytes: Vec<u8>,
        /// The snap.
        snap: i64,
    },
    /// A register value was set.
    RegisterSet {
        /// The register name.
        name: String,
        /// The value bytes.
        value: Vec<u8>,
        /// The snap.
        snap: i64,
    },
    /// A thread was created.
    ThreadCreated {
        /// The thread's object path.
        path: KeyPath,
        /// The thread ID.
        tid: i64,
        /// The thread name.
        name: String,
        /// The snap.
        snap: i64,
    },
    /// A thread was removed.
    ThreadRemoved {
        /// The thread's object path.
        path: KeyPath,
        /// The snap.
        snap: i64,
    },
    /// A process was created.
    ProcessCreated {
        /// The process's object path.
        path: KeyPath,
        /// The process ID.
        pid: i64,
        /// The process name.
        name: String,
        /// The snap.
        snap: i64,
    },
    /// A breakpoint was set.
    BreakpointSet {
        /// The breakpoint object path.
        path: KeyPath,
        /// The breakpoint address.
        address: u64,
        /// The snap.
        snap: i64,
    },
    /// A breakpoint was removed.
    BreakpointRemoved {
        /// The breakpoint object path.
        path: KeyPath,
        /// The snap.
        snap: i64,
    },
    /// Execution state changed.
    ExecutionStateChanged {
        /// The path of the stateful object.
        path: KeyPath,
        /// The new state name.
        state: String,
        /// The snap.
        snap: i64,
    },
    /// A snapshot was created.
    SnapshotCreated {
        /// The snap value.
        snap: i64,
        /// An optional label.
        label: Option<String>,
    },
    /// A user comment or annotation.
    Annotation {
        /// The path of the annotated object.
        path: Option<KeyPath>,
        /// The annotation text.
        text: String,
        /// The snap.
        snap: i64,
    },
}

impl RecordedEvent {
    /// The snap at which this event occurred.
    pub fn snap(&self) -> i64 {
        match self {
            Self::MemoryRegionCreated { snap, .. }
            | Self::MemoryBytesWritten { snap, .. }
            | Self::RegisterSet { snap, .. }
            | Self::ThreadCreated { snap, .. }
            | Self::ThreadRemoved { snap, .. }
            | Self::ProcessCreated { snap, .. }
            | Self::BreakpointSet { snap, .. }
            | Self::BreakpointRemoved { snap, .. }
            | Self::ExecutionStateChanged { snap, .. }
            | Self::SnapshotCreated { snap, .. }
            | Self::Annotation { snap, .. } => *snap,
        }
    }

    /// A short label for the event kind (for display / filtering).
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::MemoryRegionCreated { .. } => "memory-region-created",
            Self::MemoryBytesWritten { .. } => "memory-bytes-written",
            Self::RegisterSet { .. } => "register-set",
            Self::ThreadCreated { .. } => "thread-created",
            Self::ThreadRemoved { .. } => "thread-removed",
            Self::ProcessCreated { .. } => "process-created",
            Self::BreakpointSet { .. } => "breakpoint-set",
            Self::BreakpointRemoved { .. } => "breakpoint-removed",
            Self::ExecutionStateChanged { .. } => "execution-state-changed",
            Self::SnapshotCreated { .. } => "snapshot-created",
            Self::Annotation { .. } => "annotation",
        }
    }

    /// The object path associated with this event, if any.
    pub fn object_path(&self) -> Option<&KeyPath> {
        match self {
            Self::MemoryRegionCreated { path, .. }
            | Self::ThreadCreated { path, .. }
            | Self::ThreadRemoved { path, .. }
            | Self::ProcessCreated { path, .. }
            | Self::BreakpointSet { path, .. }
            | Self::BreakpointRemoved { path, .. }
            | Self::ExecutionStateChanged { path, .. } => Some(path),
            Self::Annotation { path, .. } => path.as_ref(),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// TraceRecorder
// ---------------------------------------------------------------------------

/// Records trace events in chronological order.
///
/// Use `record_*` methods to capture events. Events are stored sorted by snap
/// and then by insertion order. Query methods allow filtering and replaying.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRecorder {
    /// All recorded events, in insertion order.
    events: Vec<RecordedEvent>,
    /// The name or description of this recording session.
    pub label: String,
    /// Whether the recorder is currently recording.
    recording: bool,
    /// Global metadata attached to this recording.
    pub metadata: BTreeMap<String, String>,
}

impl TraceRecorder {
    /// Create a new recorder.
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            events: Vec::new(),
            label: label.into(),
            recording: true,
            metadata: BTreeMap::new(),
        }
    }

    /// Whether the recorder is active.
    pub fn is_recording(&self) -> bool {
        self.recording
    }

    /// Start or resume recording.
    pub fn start(&mut self) {
        self.recording = true;
    }

    /// Pause recording (events will be discarded while paused).
    pub fn pause(&mut self) {
        self.recording = false;
    }

    /// Record a single event.
    pub fn record(&mut self, event: RecordedEvent) {
        if self.recording {
            self.events.push(event);
        }
    }

    /// Record a memory-bytes-written event.
    pub fn record_memory_write(
        &mut self,
        space: impl Into<String>,
        offset: u64,
        bytes: Vec<u8>,
        snap: i64,
    ) {
        self.record(RecordedEvent::MemoryBytesWritten {
            space: space.into(),
            offset,
            bytes,
            snap,
        });
    }

    /// Record a register-set event.
    pub fn record_register_set(
        &mut self,
        name: impl Into<String>,
        value: Vec<u8>,
        snap: i64,
    ) {
        self.record(RecordedEvent::RegisterSet {
            name: name.into(),
            value,
            snap,
        });
    }

    /// Record a thread-created event.
    pub fn record_thread_created(
        &mut self,
        path: KeyPath,
        tid: i64,
        name: impl Into<String>,
        snap: i64,
    ) {
        self.record(RecordedEvent::ThreadCreated {
            path,
            tid,
            name: name.into(),
            snap,
        });
    }

    /// Record a snapshot-created event.
    pub fn record_snapshot(&mut self, snap: i64, label: Option<String>) {
        self.record(RecordedEvent::SnapshotCreated { snap, label });
    }

    /// Record an annotation.
    pub fn record_annotation(
        &mut self,
        path: Option<KeyPath>,
        text: impl Into<String>,
        snap: i64,
    ) {
        self.record(RecordedEvent::Annotation {
            path,
            text: text.into(),
            snap,
        });
    }

    /// All recorded events.
    pub fn events(&self) -> &[RecordedEvent] {
        &self.events
    }

    /// The number of recorded events.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether no events have been recorded.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Filter events by kind label.
    pub fn events_of_kind(&self, kind: &str) -> Vec<&RecordedEvent> {
        self.events.iter().filter(|e| e.kind_label() == kind).collect()
    }

    /// All events at a given snap.
    pub fn events_at_snap(&self, snap: i64) -> Vec<&RecordedEvent> {
        self.events.iter().filter(|e| e.snap() == snap).collect()
    }

    /// All events within a snap range.
    pub fn events_in_range(&self, min_snap: i64, max_snap: i64) -> Vec<&RecordedEvent> {
        self.events
            .iter()
            .filter(|e| e.snap() >= min_snap && e.snap() <= max_snap)
            .collect()
    }

    /// The minimum snap across all recorded events, if any.
    pub fn min_snap(&self) -> Option<i64> {
        self.events.iter().map(|e| e.snap()).min()
    }

    /// The maximum snap across all recorded events, if any.
    pub fn max_snap(&self) -> Option<i64> {
        self.events.iter().map(|e| e.snap()).max()
    }

    /// All events associated with a given object path.
    pub fn events_for_path(&self, path: &KeyPath) -> Vec<&RecordedEvent> {
        self.events
            .iter()
            .filter(|e| e.object_path() == Some(path))
            .collect()
    }

    /// Clear all recorded events.
    pub fn clear(&mut self) {
        self.events.clear();
    }

    /// Sort events by snap (stable, preserves insertion order within a snap).
    pub fn sort_by_snap(&mut self) {
        self.events.sort_by_key(|e| e.snap());
    }
}

impl Default for TraceRecorder {
    fn default() -> Self {
        Self::new("default")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recorder_basic() {
        let mut rec = TraceRecorder::new("test-session");
        assert!(rec.is_recording());
        assert!(rec.is_empty());

        rec.record_memory_write("ram", 0x1000, vec![0x90, 0x90], 0);
        rec.record_register_set("RIP", vec![0x00, 0x10, 0x40, 0, 0, 0, 0, 0], 0);
        rec.record_snapshot(1, Some("after-step".into()));

        assert_eq!(rec.len(), 3);
        assert!(!rec.is_empty());
    }

    #[test]
    fn test_recorder_pause() {
        let mut rec = TraceRecorder::new("test");
        rec.record_snapshot(0, None);
        rec.pause();
        assert!(!rec.is_recording());

        rec.record_snapshot(1, None); // should be discarded
        assert_eq!(rec.len(), 1);

        rec.start();
        rec.record_snapshot(2, None);
        assert_eq!(rec.len(), 2);
    }

    #[test]
    fn test_event_snap() {
        let e = RecordedEvent::MemoryBytesWritten {
            space: "ram".into(),
            offset: 0,
            bytes: vec![],
            snap: 42,
        };
        assert_eq!(e.snap(), 42);
        assert_eq!(e.kind_label(), "memory-bytes-written");
    }

    #[test]
    fn test_event_object_path() {
        let path = KeyPath::parse("Session.Processes[0].Threads[1]");
        let e = RecordedEvent::ThreadCreated {
            path: path.clone(),
            tid: 100,
            name: "main".into(),
            snap: 0,
        };
        assert_eq!(e.object_path(), Some(&path));

        let e2 = RecordedEvent::SnapshotCreated {
            snap: 5,
            label: None,
        };
        assert!(e2.object_path().is_none());
    }

    #[test]
    fn test_event_kind_labels() {
        assert_eq!(
            RecordedEvent::MemoryRegionCreated {
                path: KeyPath::ROOT,
                name: "".into(),
                start: 0,
                end: 0,
                snap: 0,
            }
            .kind_label(),
            "memory-region-created"
        );
        assert_eq!(
            RecordedEvent::BreakpointSet {
                path: KeyPath::ROOT,
                address: 0,
                snap: 0,
            }
            .kind_label(),
            "breakpoint-set"
        );
    }

    #[test]
    fn test_filter_by_kind() {
        let mut rec = TraceRecorder::new("t");
        rec.record_memory_write("ram", 0, vec![1], 0);
        rec.record_register_set("RAX", vec![0; 8], 0);
        rec.record_memory_write("ram", 1, vec![2], 1);

        let writes = rec.events_of_kind("memory-bytes-written");
        assert_eq!(writes.len(), 2);
        let regs = rec.events_of_kind("register-set");
        assert_eq!(regs.len(), 1);
    }

    #[test]
    fn test_filter_by_snap() {
        let mut rec = TraceRecorder::new("t");
        rec.record_memory_write("ram", 0, vec![1], 0);
        rec.record_memory_write("ram", 1, vec![2], 1);
        rec.record_memory_write("ram", 2, vec![3], 1);

        assert_eq!(rec.events_at_snap(0).len(), 1);
        assert_eq!(rec.events_at_snap(1).len(), 2);
        assert_eq!(rec.events_at_snap(2).len(), 0);
    }

    #[test]
    fn test_filter_by_range() {
        let mut rec = TraceRecorder::new("t");
        for i in 0..10 {
            rec.record_memory_write("ram", i, vec![i as u8], i as i64);
        }
        assert_eq!(rec.events_in_range(3, 6).len(), 4);
    }

    #[test]
    fn test_snap_range() {
        let mut rec = TraceRecorder::new("t");
        assert!(rec.min_snap().is_none());
        assert!(rec.max_snap().is_none());

        rec.record_snapshot(5, None);
        rec.record_snapshot(2, None);
        rec.record_snapshot(8, None);

        assert_eq!(rec.min_snap(), Some(2));
        assert_eq!(rec.max_snap(), Some(8));
    }

    #[test]
    fn test_events_for_path() {
        let path = KeyPath::parse("Session.Threads[0]");
        let other = KeyPath::parse("Session.Threads[1]");

        let mut rec = TraceRecorder::new("t");
        rec.record_thread_created(path.clone(), 1, "main", 0);
        rec.record_thread_created(other, 2, "other", 0);
        rec.record_register_set("RIP", vec![0; 8], 1);

        let events = rec.events_for_path(&path);
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_sort_by_snap() {
        let mut rec = TraceRecorder::new("t");
        rec.record_snapshot(5, None);
        rec.record_snapshot(2, None);
        rec.record_snapshot(8, None);

        rec.sort_by_snap();
        let snaps: Vec<i64> = rec.events().iter().map(|e| e.snap()).collect();
        assert_eq!(snaps, vec![2, 5, 8]);
    }

    #[test]
    fn test_clear() {
        let mut rec = TraceRecorder::new("t");
        rec.record_snapshot(0, None);
        rec.record_snapshot(1, None);
        assert_eq!(rec.len(), 2);
        rec.clear();
        assert_eq!(rec.len(), 0);
    }

    #[test]
    fn test_recorder_serde() {
        let mut rec = TraceRecorder::new("serde-test");
        rec.record_snapshot(0, Some("start".into()));
        rec.metadata.insert("version".into(), "1.0".into());

        let json = serde_json::to_string(&rec).unwrap();
        let back: TraceRecorder = serde_json::from_str(&json).unwrap();
        assert_eq!(back.label, "serde-test");
        assert_eq!(back.len(), 1);
        assert_eq!(back.metadata.get("version").map(|s| s.as_str()), Some("1.0"));
    }

    #[test]
    fn test_event_serde() {
        let e = RecordedEvent::ThreadCreated {
            path: KeyPath::parse("T"),
            tid: 42,
            name: "main".into(),
            snap: 0,
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: RecordedEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.snap(), 0);
        assert_eq!(back.kind_label(), "thread-created");
    }

    #[test]
    fn test_annotation_event() {
        let mut rec = TraceRecorder::new("t");
        rec.record_annotation(
            Some(KeyPath::parse("P")),
            "reached breakpoint",
            5,
        );
        assert_eq!(rec.len(), 1);
        let e = &rec.events()[0];
        assert_eq!(e.kind_label(), "annotation");
    }

    #[test]
    fn test_record_methods() {
        let mut rec = TraceRecorder::new("t");

        let path = KeyPath::parse("P.T");
        rec.record_thread_created(path.clone(), 1, "main", 0);
        rec.record_memory_write("ram", 0x1000, vec![0xCC], 0);
        rec.record_register_set("RSP", vec![0; 8], 1);
        rec.record_snapshot(2, None);
        rec.record_annotation(None, "note", 2);

        assert_eq!(rec.len(), 5);
    }
}
