//! Trace -- enhanced trace data model for the debug framework.
//!
//! Ported from Ghidra's `ghidra.trace.model.Trace` and
//! `ghidra.trace.database.DBTraceImpl`.
//!
//! This module provides a richer trace container than the basic `model::trace::Trace`,
//! adding direct management of processes, threads, snapshots, and memory regions
//! with full lifecycle support.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::TraceMemoryState;

use super::trace_process::TraceProcess;
use super::trace_thread::TraceThread;

// ---------------------------------------------------------------------------
// TraceStatistics
// ---------------------------------------------------------------------------

/// Aggregate statistics for a trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceStatistics {
    /// Total number of snapshots recorded.
    pub snapshot_count: usize,
    /// Total number of processes (including dead).
    pub process_count: usize,
    /// Total number of threads (including dead).
    pub thread_count: usize,
    /// Number of currently alive processes.
    pub alive_process_count: usize,
    /// Number of currently alive threads.
    pub alive_thread_count: usize,
}

// ---------------------------------------------------------------------------
// TraceEvent
// ---------------------------------------------------------------------------

/// An event recorded in a trace's event log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    /// The snap at which this event occurred.
    pub snap: i64,
    /// A human-readable description of the event.
    pub description: String,
    /// The kind of event.
    pub kind: TraceEventKind,
}

/// The kind of a trace event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceEventKind {
    /// A process was created.
    ProcessCreated,
    /// A process was destroyed.
    ProcessDestroyed,
    /// A thread was created.
    ThreadCreated,
    /// A thread was destroyed.
    ThreadDestroyed,
    /// A breakpoint was hit.
    BreakpointHit,
    /// A signal or exception occurred.
    Signal,
    /// A module was loaded.
    ModuleLoaded,
    /// A module was unloaded.
    ModuleUnloaded,
    /// A memory region changed.
    MemoryChanged,
    /// A generic event.
    Other(String),
}

// ---------------------------------------------------------------------------
// Trace
// ---------------------------------------------------------------------------

/// An enhanced trace container that manages processes, threads, snapshots,
/// memory state, and an event log.
///
/// This builds on the basic `model::trace::Trace` by adding:
/// - Process and thread lifecycle management
/// - Memory state tracking per snap
/// - Event log with structured entries
/// - Snapshot descriptions and metadata
///
/// Ported from Ghidra's `DBTraceImpl` and `Trace` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceData {
    /// A unique identifier for this trace.
    pub id: String,
    /// Whether the trace has been closed.
    pub closed: bool,
    /// User-visible name.
    pub name: String,
    /// User comment.
    pub comment: String,
    /// Whether the trace is writable.
    writable: bool,
    /// Processes indexed by key.
    processes: BTreeMap<i64, TraceProcess>,
    /// Threads indexed by key.
    threads: BTreeMap<i64, TraceThread>,
    /// Snapshot metadata indexed by snap key.
    snapshots: BTreeMap<i64, TraceSnapshotEntry>,
    /// Memory state cache: (space, offset) -> state at a given snap.
    /// Only tracks explicitly observed or errored regions.
    memory_state: BTreeMap<MemoryKey, TraceMemoryState>,
    /// Event log.
    events: Vec<TraceEvent>,
    /// Next available process key.
    next_process_key: i64,
    /// Next available thread key.
    next_thread_key: i64,
    /// Next available snapshot key.
    next_snap_key: i64,
    /// Custom properties.
    properties: BTreeMap<String, String>,
}

/// A composite key for memory state lookups.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MemoryKey {
    /// The address space name.
    pub space: String,
    /// The byte offset within the space.
    pub offset: u64,
    /// The snap at which this state applies.
    pub snap: i64,
}

/// Metadata for a single snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSnapshotEntry {
    /// The snapshot key (snap value).
    pub key: i64,
    /// An optional description.
    pub description: Option<String>,
    /// The timestamp (epoch millis) when the snapshot was created, if known.
    pub timestamp: Option<i64>,
    /// Which threads were alive at this snapshot.
    pub alive_threads: Vec<i64>,
    /// Which processes were alive at this snapshot.
    pub alive_processes: Vec<i64>,
}

impl TraceSnapshotEntry {
    /// Create a new snapshot entry.
    pub fn new(key: i64) -> Self {
        Self {
            key,
            description: None,
            timestamp: None,
            alive_threads: Vec::new(),
            alive_processes: Vec::new(),
        }
    }

    /// Set a description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Set a timestamp.
    pub fn with_timestamp(mut self, ts: i64) -> Self {
        self.timestamp = Some(ts);
        self
    }
}

impl TraceData {
    /// Create a new empty trace.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            closed: false,
            name: String::new(),
            comment: String::new(),
            writable: true,
            processes: BTreeMap::new(),
            threads: BTreeMap::new(),
            snapshots: BTreeMap::new(),
            memory_state: BTreeMap::new(),
            events: Vec::new(),
            next_process_key: 1,
            next_thread_key: 1,
            next_snap_key: 0,
            properties: BTreeMap::new(),
        }
    }

    /// Set the trace name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    // -- Lifecycle --

    /// Whether this trace has been closed.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Close this trace.
    pub fn close(&mut self) {
        self.closed = true;
    }

    /// Whether this trace is writable.
    pub fn is_writable(&self) -> bool {
        self.writable && !self.closed
    }

    /// Set whether this trace is writable.
    pub fn set_writable(&mut self, writable: bool) {
        self.writable = writable;
    }

    // -- Properties --

    /// Get a property value.
    pub fn property(&self, key: &str) -> Option<&str> {
        self.properties.get(key).map(|s| s.as_str())
    }

    /// Set a property value.
    pub fn set_property(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.properties.insert(key.into(), value.into());
    }

    /// Remove a property.
    pub fn remove_property(&mut self, key: &str) -> Option<String> {
        self.properties.remove(key)
    }

    // -- Snapshots --

    /// Create a new snapshot and return its key.
    pub fn create_snapshot(&mut self) -> i64 {
        let key = self.next_snap_key;
        self.next_snap_key += 1;
        self.snapshots.insert(key, TraceSnapshotEntry::new(key));
        key
    }

    /// Create a snapshot with a description.
    pub fn create_snapshot_with_desc(&mut self, desc: impl Into<String>) -> i64 {
        let key = self.create_snapshot();
        if let Some(entry) = self.snapshots.get_mut(&key) {
            entry.description = Some(desc.into());
        }
        key
    }

    /// Get snapshot metadata by key.
    pub fn snapshot(&self, key: i64) -> Option<&TraceSnapshotEntry> {
        self.snapshots.get(&key)
    }

    /// Get mutable snapshot metadata by key.
    pub fn snapshot_mut(&mut self, key: i64) -> Option<&mut TraceSnapshotEntry> {
        self.snapshots.get_mut(&key)
    }

    /// The number of snapshots.
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    /// All snapshot keys in order.
    pub fn snapshot_keys(&self) -> Vec<i64> {
        self.snapshots.keys().copied().collect()
    }

    /// The latest snapshot key, if any.
    pub fn latest_snapshot(&self) -> Option<i64> {
        self.snapshots.keys().next_back().copied()
    }

    // -- Processes --

    /// Add a new process and return its key.
    pub fn add_process(&mut self, name: impl Into<String>, snap: i64) -> i64 {
        let key = self.next_process_key;
        self.next_process_key += 1;
        let path = format!("Processes[{key}]");
        let process = TraceProcess::new(key, path, name, snap);
        self.processes.insert(key, process);
        self.events.push(TraceEvent {
            snap,
            description: format!("Process {key} created"),
            kind: TraceEventKind::ProcessCreated,
        });
        key
    }

    /// Get a process by key.
    pub fn process(&self, key: i64) -> Option<&TraceProcess> {
        self.processes.get(&key)
    }

    /// Get a mutable process by key.
    pub fn process_mut(&mut self, key: i64) -> Option<&mut TraceProcess> {
        self.processes.get_mut(&key)
    }

    /// Remove (kill) a process at the given snap.
    pub fn remove_process(&mut self, key: i64, snap: i64) -> bool {
        if let Some(p) = self.processes.get_mut(&key) {
            p.remove(snap);
            self.events.push(TraceEvent {
                snap,
                description: format!("Process {key} destroyed"),
                kind: TraceEventKind::ProcessDestroyed,
            });
            true
        } else {
            false
        }
    }

    /// All process keys.
    pub fn process_keys(&self) -> Vec<i64> {
        self.processes.keys().copied().collect()
    }

    /// All processes alive at the given snap.
    pub fn processes_at(&self, snap: i64) -> Vec<&TraceProcess> {
        self.processes
            .values()
            .filter(|p| p.is_valid(snap))
            .collect()
    }

    /// The number of processes (including dead ones).
    pub fn process_count(&self) -> usize {
        self.processes.len()
    }

    // -- Threads --

    /// Add a new thread to a process and return its key.
    pub fn add_thread(
        &mut self,
        process_key: i64,
        name: impl Into<String>,
        snap: i64,
    ) -> Option<i64> {
        if !self.processes.contains_key(&process_key) {
            return None;
        }
        let key = self.next_thread_key;
        self.next_thread_key += 1;
        let path = format!("Processes[{process_key}].Threads[{key}]");
        let mut thread = TraceThread::new(key, path, name, snap);
        thread.process_key = process_key;
        self.threads.insert(key, thread);
        self.events.push(TraceEvent {
            snap,
            description: format!("Thread {key} created in process {process_key}"),
            kind: TraceEventKind::ThreadCreated,
        });
        Some(key)
    }

    /// Get a thread by key.
    pub fn thread(&self, key: i64) -> Option<&TraceThread> {
        self.threads.get(&key)
    }

    /// Get a mutable thread by key.
    pub fn thread_mut(&mut self, key: i64) -> Option<&mut TraceThread> {
        self.threads.get_mut(&key)
    }

    /// Remove (kill) a thread at the given snap.
    pub fn remove_thread(&mut self, key: i64, snap: i64) -> bool {
        if let Some(t) = self.threads.get_mut(&key) {
            t.remove(snap);
            self.events.push(TraceEvent {
                snap,
                description: format!("Thread {key} destroyed"),
                kind: TraceEventKind::ThreadDestroyed,
            });
            true
        } else {
            false
        }
    }

    /// All thread keys.
    pub fn thread_keys(&self) -> Vec<i64> {
        self.threads.keys().copied().collect()
    }

    /// All threads alive at the given snap.
    pub fn threads_at(&self, snap: i64) -> Vec<&TraceThread> {
        self.threads
            .values()
            .filter(|t| t.is_valid(snap))
            .collect()
    }

    /// All threads belonging to a given process, alive at `snap`.
    pub fn threads_for_process_at(&self, process_key: i64, snap: i64) -> Vec<&TraceThread> {
        self.threads
            .values()
            .filter(|t| t.process_key == process_key && t.is_valid(snap))
            .collect()
    }

    /// The number of threads (including dead ones).
    pub fn thread_count(&self) -> usize {
        self.threads.len()
    }

    // -- Memory state --

    /// Set the memory state for a given address at a snap.
    pub fn set_memory_state(
        &mut self,
        space: impl Into<String>,
        offset: u64,
        snap: i64,
        state: TraceMemoryState,
    ) {
        let key = MemoryKey {
            space: space.into(),
            offset,
            snap,
        };
        self.memory_state.insert(key, state);
    }

    /// Get the memory state for a given address at a snap.
    pub fn memory_state_at(
        &self,
        space: &str,
        offset: u64,
        snap: i64,
    ) -> Option<TraceMemoryState> {
        // Find the latest state at or before the given snap for this (space, offset).
        let search = MemoryKey {
            space: space.to_string(),
            offset,
            snap,
        };
        self.memory_state
            .range(..=search)
            .rev()
            .find(|(k, _)| k.space == space && k.offset == offset)
            .map(|(_, &s)| s)
    }

    // -- Event log --

    /// Add a custom event to the log.
    pub fn log_event(
        &mut self,
        snap: i64,
        description: impl Into<String>,
        kind: TraceEventKind,
    ) {
        self.events.push(TraceEvent {
            snap,
            description: description.into(),
            kind,
        });
    }

    /// All recorded events.
    pub fn events(&self) -> &[TraceEvent] {
        &self.events
    }

    /// Events at a specific snap.
    pub fn events_at(&self, snap: i64) -> Vec<&TraceEvent> {
        self.events.iter().filter(|e| e.snap == snap).collect()
    }

    /// The number of events.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Clear the event log.
    pub fn clear_events(&mut self) {
        self.events.clear();
    }

    // -- Statistics --

    /// Compute aggregate statistics.
    pub fn statistics(&self) -> TraceStatistics {
        TraceStatistics {
            snapshot_count: self.snapshots.len(),
            process_count: self.processes.len(),
            thread_count: self.threads.len(),
            alive_process_count: self.processes.values().filter(|p| p.is_alive_now()).count(),
            alive_thread_count: self.threads.values().filter(|t| t.is_alive_now()).count(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_creation() {
        let t = TraceData::new("trace-001");
        assert_eq!(t.id, "trace-001");
        assert!(!t.is_closed());
        assert!(t.is_writable());
        assert_eq!(t.snapshot_count(), 0);
        assert_eq!(t.process_count(), 0);
        assert_eq!(t.thread_count(), 0);
    }

    #[test]
    fn test_trace_lifecycle() {
        let mut t = TraceData::new("t1");
        assert!(t.is_writable());
        t.close();
        assert!(t.is_closed());
        assert!(!t.is_writable());
    }

    #[test]
    fn test_trace_properties() {
        let mut t = TraceData::new("t1");
        t.set_property("arch", "x86_64");
        assert_eq!(t.property("arch"), Some("x86_64"));
        t.remove_property("arch");
        assert!(t.property("arch").is_none());
    }

    #[test]
    fn test_snapshots() {
        let mut t = TraceData::new("t1");
        let s0 = t.create_snapshot();
        assert_eq!(s0, 0);
        let s1 = t.create_snapshot_with_desc("initial load");
        assert_eq!(s1, 1);
        assert_eq!(t.snapshot_count(), 2);
        assert_eq!(t.latest_snapshot(), Some(1));

        let entry = t.snapshot(s1).unwrap();
        assert_eq!(entry.description.as_deref(), Some("initial load"));
    }

    #[test]
    fn test_process_lifecycle() {
        let mut t = TraceData::new("t1");
        let p1 = t.add_process("myapp", 0);
        assert_eq!(p1, 1);
        assert_eq!(t.process_count(), 1);

        let p = t.process(p1).unwrap();
        assert_eq!(p.name, "myapp");
        assert!(p.is_valid(0));

        t.remove_process(p1, 10);
        let p = t.process(p1).unwrap();
        assert!(p.is_valid(10));
        assert!(!p.is_valid(11));
    }

    #[test]
    fn test_thread_lifecycle() {
        let mut t = TraceData::new("t1");
        let p = t.add_process("myapp", 0);
        let th = t.add_thread(p, "main", 0).unwrap();
        assert_eq!(t.thread_count(), 1);

        let thread = t.thread(th).unwrap();
        assert_eq!(thread.name, "main");
        assert!(thread.is_valid(0));

        t.remove_thread(th, 5);
        let thread = t.thread(th).unwrap();
        assert!(thread.is_valid(5));
        assert!(!thread.is_valid(6));
    }

    #[test]
    fn test_add_thread_invalid_process() {
        let mut t = TraceData::new("t1");
        assert!(t.add_thread(999, "main", 0).is_none());
    }

    #[test]
    fn test_threads_for_process() {
        let mut t = TraceData::new("t1");
        let p1 = t.add_process("app1", 0);
        let p2 = t.add_process("app2", 0);
        t.add_thread(p1, "main", 0);
        t.add_thread(p1, "worker", 1);
        t.add_thread(p2, "main", 0);

        assert_eq!(t.threads_for_process_at(p1, 5).len(), 2);
        assert_eq!(t.threads_for_process_at(p2, 5).len(), 1);
    }

    #[test]
    fn test_processes_at() {
        let mut t = TraceData::new("t1");
        let p1 = t.add_process("app1", 0);
        t.add_process("app2", 5);
        t.remove_process(p1, 10);

        assert_eq!(t.processes_at(0).len(), 1);
        assert_eq!(t.processes_at(5).len(), 2);
        assert_eq!(t.processes_at(10).len(), 2);
        assert_eq!(t.processes_at(11).len(), 1);
    }

    #[test]
    fn test_memory_state() {
        let mut t = TraceData::new("t1");
        t.set_memory_state("ram", 0x1000, 0, TraceMemoryState::Known);
        t.set_memory_state("ram", 0x1000, 5, TraceMemoryState::Error);

        assert_eq!(
            t.memory_state_at("ram", 0x1000, 0),
            Some(TraceMemoryState::Known)
        );
        assert_eq!(
            t.memory_state_at("ram", 0x1000, 3),
            Some(TraceMemoryState::Known)
        );
        assert_eq!(
            t.memory_state_at("ram", 0x1000, 5),
            Some(TraceMemoryState::Error)
        );
        assert!(t.memory_state_at("ram", 0x2000, 0).is_none());
    }

    #[test]
    fn test_event_log() {
        let mut t = TraceData::new("t1");
        t.add_process("app", 0);
        t.add_thread(1, "main", 0);
        assert_eq!(t.event_count(), 2);

        t.log_event(5, "custom event", TraceEventKind::Other("test".into()));
        assert_eq!(t.event_count(), 3);
        assert_eq!(t.events_at(5).len(), 1);

        t.clear_events();
        assert_eq!(t.event_count(), 0);
    }

    #[test]
    fn test_statistics() {
        let mut t = TraceData::new("t1");
        t.create_snapshot();
        t.create_snapshot();
        let p = t.add_process("app", 0);
        t.add_thread(p, "main", 0);

        let stats = t.statistics();
        assert_eq!(stats.snapshot_count, 2);
        assert_eq!(stats.process_count, 1);
        assert_eq!(stats.thread_count, 1);
        assert_eq!(stats.alive_process_count, 1);
        assert_eq!(stats.alive_thread_count, 1);
    }

    #[test]
    fn test_trace_name() {
        let t = TraceData::new("t1").with_name("My Trace");
        assert_eq!(t.name, "My Trace");
    }

    #[test]
    fn test_snapshot_entry_builder() {
        let entry = TraceSnapshotEntry::new(42)
            .with_description("after load")
            .with_timestamp(1000);
        assert_eq!(entry.key, 42);
        assert_eq!(entry.description.as_deref(), Some("after load"));
        assert_eq!(entry.timestamp, Some(1000));
    }

    #[test]
    fn test_trace_data_serde() {
        let mut t = TraceData::new("t1");
        let p = t.add_process("app", 0);
        t.add_thread(p, "main", 0);
        t.create_snapshot_with_desc("snap 0");

        let json = serde_json::to_string(&t).unwrap();
        let back: TraceData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "t1");
        assert_eq!(back.process_count(), 1);
        assert_eq!(back.thread_count(), 1);
        assert_eq!(back.snapshot_count(), 1);
    }
}
