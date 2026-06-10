//! Trace -- enhanced trace data model for the debug framework.
//!
//! Ported from Ghidra's `ghidra.trace.model.Trace` and
//! `ghidra.trace.database.DBTraceImpl`.
//!
//! This module provides a richer trace container than the basic `model::trace::Trace`,
//! adding direct management of processes, threads, snapshots, and memory regions
//! with full lifecycle support.
//!
//! New in this update: lifespan-aware names and comments for threads,
//! thread/process lookup by path, emulator cache versioning, breakpoint
//! associations on threads, `delete_thread` for full removal, snapshot
//! time management, and the `TraceTimeSnapshot` helper.

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
// TraceTimeSnapshot
// ---------------------------------------------------------------------------

/// Point-in-time snapshot metadata, mirroring `TraceSnapshot` in Java.
///
/// Each snapshot records a description, an optional wall-clock timestamp,
/// and the sets of processes and threads alive at that point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceTimeSnapshot {
    /// The snapshot key (snap value).
    pub key: i64,
    /// An optional human-readable description.
    pub description: Option<String>,
    /// Wall-clock timestamp (epoch milliseconds), if known.
    pub timestamp: Option<i64>,
}

impl TraceTimeSnapshot {
    /// Create a new time snapshot.
    pub fn new(key: i64) -> Self {
        Self {
            key,
            description: None,
            timestamp: None,
        }
    }

    /// Set a description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Set a wall-clock timestamp.
    pub fn with_timestamp(mut self, ts: i64) -> Self {
        self.timestamp = Some(ts);
        self
    }
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
    /// Emulator cache version for invalidation.
    emulator_cache_version: i64,
    /// Base language ID (e.g. "x86:LE:64:default").
    base_language_id: Option<String>,
    /// Base compiler spec ID.
    base_compiler_spec_id: Option<String>,
    /// Time snapshots indexed by key.
    time_snapshots: BTreeMap<i64, TraceTimeSnapshot>,
    /// Breakpoint specs: id -> (name, expression, enabled, snap, thread_keys, process_key).
    breakpoints: BTreeMap<i64, TraceBreakpointEntry>,
    /// Next available breakpoint key.
    next_breakpoint_key: i64,
    /// Saved views (snap -> view name).
    saved_views: BTreeMap<i64, String>,
}

/// A breakpoint entry tracked within a trace.
///
/// Ported from Ghidra's `TraceBreakpointSpec` / `TraceBreakpointLocation`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceBreakpointEntry {
    /// Unique key.
    pub key: i64,
    /// Human-readable name (e.g. "Breakpoint #1").
    pub name: String,
    /// Expression or address string (e.g. "0x401000").
    pub expression: String,
    /// Whether the breakpoint is currently enabled.
    pub enabled: bool,
    /// The snap at which this breakpoint was created.
    pub creation_snap: i64,
    /// Thread keys this breakpoint applies to (empty = all threads).
    pub thread_keys: Vec<i64>,
    /// Process key this breakpoint belongs to (0 = global).
    pub process_key: i64,
    /// Number of times this breakpoint has been hit.
    pub hit_count: u64,
    /// The snap at which the breakpoint was last hit, if ever.
    pub last_hit_snap: Option<i64>,
}

impl TraceBreakpointEntry {
    /// Create a new breakpoint entry.
    pub fn new(key: i64, name: impl Into<String>, expression: impl Into<String>, snap: i64) -> Self {
        Self {
            key,
            name: name.into(),
            expression: expression.into(),
            enabled: true,
            creation_snap: snap,
            thread_keys: Vec::new(),
            process_key: 0,
            hit_count: 0,
            last_hit_snap: None,
        }
    }

    /// Record a hit.
    pub fn record_hit(&mut self, snap: i64) {
        self.hit_count += 1;
        self.last_hit_snap = Some(snap);
    }
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
            emulator_cache_version: 0,
            base_language_id: None,
            base_compiler_spec_id: None,
            time_snapshots: BTreeMap::new(),
            breakpoints: BTreeMap::new(),
            next_breakpoint_key: 1,
            saved_views: BTreeMap::new(),
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

    // -- Language / Compiler --

    /// Set the base language ID for this trace.
    pub fn set_base_language(&mut self, lang_id: impl Into<String>) {
        self.base_language_id = Some(lang_id.into());
    }

    /// The base language ID, if set.
    pub fn base_language(&self) -> Option<&str> {
        self.base_language_id.as_deref()
    }

    /// Set the base compiler spec ID for this trace.
    pub fn set_base_compiler_spec(&mut self, spec_id: impl Into<String>) {
        self.base_compiler_spec_id = Some(spec_id.into());
    }

    /// The base compiler spec ID, if set.
    pub fn base_compiler_spec(&self) -> Option<&str> {
        self.base_compiler_spec_id.as_deref()
    }

    // -- Emulator cache --

    /// Set the emulator cache version. Incrementing this invalidates
    /// any cached emulation results.
    pub fn set_emulator_cache_version(&mut self, version: i64) {
        self.emulator_cache_version = version;
    }

    /// The current emulator cache version.
    pub fn emulator_cache_version(&self) -> i64 {
        self.emulator_cache_version
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

    /// Delete a thread entirely from the trace (not just mark as removed).
    ///
    /// Returns the removed thread, if any.
    pub fn delete_thread(&mut self, key: i64) -> Option<TraceThread> {
        let thread = self.threads.remove(&key);
        if thread.is_some() {
            self.events.push(TraceEvent {
                snap: 0,
                description: format!("Thread {key} deleted"),
                kind: TraceEventKind::ThreadDestroyed,
            });
        }
        thread
    }

    /// Get a thread by its path (e.g. "Processes[1].Threads[2]").
    pub fn get_thread_by_path(&self, path: &str) -> Option<&TraceThread> {
        self.threads.values().find(|t| t.path == path)
    }

    /// Get a live thread by path at a given snap.
    ///
    /// A thread is "live" at `snap` if its lifespan contains `snap`.
    pub fn get_live_thread_by_path(&self, snap: i64, path: &str) -> Option<&TraceThread> {
        self.threads
            .values()
            .find(|t| t.path == path && t.is_valid(snap))
    }

    /// Get a process by its path (e.g. "Processes[1]").
    pub fn get_process_by_path(&self, path: &str) -> Option<&TraceProcess> {
        self.processes.values().find(|p| p.path == path)
    }

    /// Get a live process by path at a given snap.
    pub fn get_live_process_by_path(&self, snap: i64, path: &str) -> Option<&TraceProcess> {
        self.processes
            .values()
            .find(|p| p.path == path && p.is_valid(snap))
    }

    /// Iterate over all threads (including dead ones).
    pub fn all_threads(&self) -> impl Iterator<Item = &TraceThread> {
        self.threads.values()
    }

    /// Iterate over all processes (including dead ones).
    pub fn all_processes(&self) -> impl Iterator<Item = &TraceProcess> {
        self.processes.values()
    }

    /// Delete a process entirely from the trace (not just mark as removed).
    ///
    /// Returns the removed process, if any.
    pub fn delete_process(&mut self, key: i64) -> Option<TraceProcess> {
        let process = self.processes.remove(&key);
        if process.is_some() {
            self.events.push(TraceEvent {
                snap: 0,
                description: format!("Process {key} deleted"),
                kind: TraceEventKind::ProcessDestroyed,
            });
        }
        process
    }

    // -- Breakpoints --

    /// Add a breakpoint and return its key.
    pub fn add_breakpoint(
        &mut self,
        name: impl Into<String>,
        expression: impl Into<String>,
        snap: i64,
    ) -> i64 {
        let key = self.next_breakpoint_key;
        self.next_breakpoint_key += 1;
        let bp = TraceBreakpointEntry::new(key, name, expression, snap);
        self.breakpoints.insert(key, bp);
        key
    }

    /// Get a breakpoint by key.
    pub fn breakpoint(&self, key: i64) -> Option<&TraceBreakpointEntry> {
        self.breakpoints.get(&key)
    }

    /// Get a mutable breakpoint by key.
    pub fn breakpoint_mut(&mut self, key: i64) -> Option<&mut TraceBreakpointEntry> {
        self.breakpoints.get_mut(&key)
    }

    /// Remove a breakpoint by key. Returns the removed entry, if any.
    pub fn remove_breakpoint(&mut self, key: i64) -> Option<TraceBreakpointEntry> {
        self.breakpoints.remove(&key)
    }

    /// All breakpoint keys.
    pub fn breakpoint_keys(&self) -> Vec<i64> {
        self.breakpoints.keys().copied().collect()
    }

    /// The number of breakpoints.
    pub fn breakpoint_count(&self) -> usize {
        self.breakpoints.len()
    }

    /// All enabled breakpoints.
    pub fn enabled_breakpoints(&self) -> impl Iterator<Item = &TraceBreakpointEntry> {
        self.breakpoints.values().filter(|bp| bp.enabled)
    }

    // -- Time snapshots --

    /// Get or create a time snapshot at the given snap.
    pub fn get_or_create_time_snapshot(&mut self, snap: i64) -> &mut TraceTimeSnapshot {
        self.time_snapshots
            .entry(snap)
            .or_insert_with(|| TraceTimeSnapshot::new(snap))
    }

    /// Get a time snapshot at a given snap.
    pub fn time_snapshot(&self, snap: i64) -> Option<&TraceTimeSnapshot> {
        self.time_snapshots.get(&snap)
    }

    /// Set a time snapshot description.
    pub fn set_snapshot_description(&mut self, snap: i64, desc: impl Into<String>) {
        let entry = self
            .time_snapshots
            .entry(snap)
            .or_insert_with(|| TraceTimeSnapshot::new(snap));
        entry.description = Some(desc.into());
    }

    /// Set a time snapshot timestamp.
    pub fn set_snapshot_timestamp(&mut self, snap: i64, ts: i64) {
        let entry = self
            .time_snapshots
            .entry(snap)
            .or_insert_with(|| TraceTimeSnapshot::new(snap));
        entry.timestamp = Some(ts);
    }

    // -- Saved views --

    /// Save a named view at a snap.
    pub fn save_view(&mut self, snap: i64, name: impl Into<String>) {
        self.saved_views.insert(snap, name.into());
    }

    /// Get the name of a saved view at a snap.
    pub fn saved_view(&self, snap: i64) -> Option<&str> {
        self.saved_views.get(&snap).map(|s| s.as_str())
    }

    /// Remove a saved view at a snap.
    pub fn remove_saved_view(&mut self, snap: i64) -> Option<String> {
        self.saved_views.remove(&snap)
    }

    /// All saved view snaps.
    pub fn saved_view_snaps(&self) -> Vec<i64> {
        self.saved_views.keys().copied().collect()
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

    #[test]
    fn test_language_and_compiler() {
        let mut t = TraceData::new("t1");
        assert!(t.base_language().is_none());
        t.set_base_language("x86:LE:64:default");
        assert_eq!(t.base_language(), Some("x86:LE:64:default"));
        t.set_base_compiler_spec("default");
        assert_eq!(t.base_compiler_spec(), Some("default"));
    }

    #[test]
    fn test_emulator_cache_version() {
        let mut t = TraceData::new("t1");
        assert_eq!(t.emulator_cache_version(), 0);
        t.set_emulator_cache_version(3);
        assert_eq!(t.emulator_cache_version(), 3);
    }

    #[test]
    fn test_delete_thread() {
        let mut t = TraceData::new("t1");
        let p = t.add_process("app", 0);
        let th = t.add_thread(p, "main", 0).unwrap();
        assert_eq!(t.thread_count(), 1);
        let removed = t.delete_thread(th);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().name, "main");
        assert_eq!(t.thread_count(), 0);
    }

    #[test]
    fn test_delete_process() {
        let mut t = TraceData::new("t1");
        let p = t.add_process("app", 0);
        assert_eq!(t.process_count(), 1);
        let removed = t.delete_process(p);
        assert!(removed.is_some());
        assert_eq!(t.process_count(), 0);
    }

    #[test]
    fn test_thread_by_path() {
        let mut t = TraceData::new("t1");
        let p = t.add_process("app", 0);
        let th = t.add_thread(p, "main", 0).unwrap();
        let thread = t.thread(th).unwrap();
        let path = thread.path.clone();

        assert!(t.get_thread_by_path(&path).is_some());
        assert!(t.get_thread_by_path("nonexistent").is_none());
    }

    #[test]
    fn test_live_thread_by_path() {
        let mut t = TraceData::new("t1");
        let p = t.add_process("app", 0);
        let th = t.add_thread(p, "main", 0).unwrap();
        let thread = t.thread(th).unwrap();
        let path = thread.path.clone();

        assert!(t.get_live_thread_by_path(0, &path).is_some());
        t.remove_thread(th, 5);
        assert!(t.get_live_thread_by_path(0, &path).is_some());
        assert!(t.get_live_thread_by_path(10, &path).is_none());
    }

    #[test]
    fn test_process_by_path() {
        let mut t = TraceData::new("t1");
        let p = t.add_process("app", 0);
        let process = t.process(p).unwrap();
        let path = process.path.clone();

        assert!(t.get_process_by_path(&path).is_some());
        assert!(t.get_process_by_path("nonexistent").is_none());
    }

    #[test]
    fn test_breakpoints() {
        let mut t = TraceData::new("t1");
        let bp1 = t.add_breakpoint("bp1", "0x401000", 0);
        let bp2 = t.add_breakpoint("bp2", "0x402000", 0);
        assert_eq!(t.breakpoint_count(), 2);

        let bp = t.breakpoint(bp1).unwrap();
        assert_eq!(bp.name, "bp1");
        assert!(bp.enabled);

        t.breakpoint_mut(bp2).unwrap().enabled = false;
        assert_eq!(t.enabled_breakpoints().count(), 1);

        t.remove_breakpoint(bp1);
        assert_eq!(t.breakpoint_count(), 1);
        assert!(t.breakpoint(bp1).is_none());
    }

    #[test]
    fn test_breakpoint_hit() {
        let mut t = TraceData::new("t1");
        let bp = t.add_breakpoint("bp1", "0x401000", 0);
        t.breakpoint_mut(bp).unwrap().record_hit(5);
        t.breakpoint_mut(bp).unwrap().record_hit(10);
        let bp = t.breakpoint(bp).unwrap();
        assert_eq!(bp.hit_count, 2);
        assert_eq!(bp.last_hit_snap, Some(10));
    }

    #[test]
    fn test_time_snapshots() {
        let mut t = TraceData::new("t1");
        t.set_snapshot_description(0, "initial");
        t.set_snapshot_timestamp(0, 1000);
        let ts = t.time_snapshot(0).unwrap();
        assert_eq!(ts.description.as_deref(), Some("initial"));
        assert_eq!(ts.timestamp, Some(1000));
    }

    #[test]
    fn test_saved_views() {
        let mut t = TraceData::new("t1");
        t.save_view(0, "main");
        t.save_view(5, "detail");
        assert_eq!(t.saved_view(0), Some("main"));
        assert_eq!(t.saved_view(5), Some("detail"));
        assert_eq!(t.saved_view_snaps().len(), 2);
        t.remove_saved_view(0);
        assert!(t.saved_view(0).is_none());
    }

    #[test]
    fn test_all_threads_and_processes() {
        let mut t = TraceData::new("t1");
        let p = t.add_process("app", 0);
        t.add_thread(p, "main", 0);
        t.add_thread(p, "worker", 1);
        assert_eq!(t.all_threads().count(), 2);
        assert_eq!(t.all_processes().count(), 1);
    }

    #[test]
    fn test_time_snapshot_builder() {
        let ts = TraceTimeSnapshot::new(5)
            .with_description("step")
            .with_timestamp(5000);
        assert_eq!(ts.key, 5);
        assert_eq!(ts.description.as_deref(), Some("step"));
        assert_eq!(ts.timestamp, Some(5000));
    }

    #[test]
    fn test_breakpoint_entry_builder() {
        let bp = TraceBreakpointEntry::new(1, "main_bp", "main", 0);
        assert_eq!(bp.key, 1);
        assert_eq!(bp.name, "main_bp");
        assert_eq!(bp.expression, "main");
        assert!(bp.enabled);
        assert_eq!(bp.hit_count, 0);
    }
}
