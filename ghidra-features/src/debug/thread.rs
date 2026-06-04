//! Thread and process model for the Debug framework.
//!
//! Ported from `ghidra.trace.model.thread` — includes [`TraceThread`]
//! and [`TraceProcess`].

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use super::core_types::{Lifespan, TraceExecutionState};

// ---------------------------------------------------------------------------
// TraceProcess
// ---------------------------------------------------------------------------

/// A process in a trace.
///
/// Ported from `ghidra.trace.model.thread.TraceProcess`. If the process does
/// not carry an explicit [`TraceExecutionState`], its existence implies `Alive`.
#[derive(Debug, Clone)]
pub struct TraceProcess {
    /// Process ID as assigned by the target platform.
    pub pid: u64,
    /// Display name for this process.
    pub name: String,
    /// The execution state of the process (if tracked).
    pub execution_state: Option<TraceExecutionState>,
}

impl TraceProcess {
    /// Create a new process.
    pub fn new(pid: u64, name: impl Into<String>) -> Self {
        Self {
            pid,
            name: name.into(),
            execution_state: None,
        }
    }

    /// Create a new process with an explicit execution state.
    pub fn with_state(pid: u64, name: impl Into<String>, state: TraceExecutionState) -> Self {
        Self {
            pid,
            name: name.into(),
            execution_state: Some(state),
        }
    }

    /// Returns the effective execution state, defaulting to `Alive` if not set.
    pub fn state(&self) -> TraceExecutionState {
        self.execution_state.unwrap_or(TraceExecutionState::Alive)
    }
}

// ---------------------------------------------------------------------------
// TraceThread
// ---------------------------------------------------------------------------

/// A thread in a trace.
///
/// Ported from `ghidra.trace.model.thread.TraceThread`. Each thread is
/// identified by a unique key and belongs to a process. Threads have
/// time-varying names and execution states tracked via [`Lifespan`].
#[derive(Debug, Clone)]
pub struct TraceThread {
    /// Unique key identifying this thread (all time, within a trace).
    key: u64,
    /// The owning process key (if any).
    pub process_key: Option<u64>,
    /// The TID as assigned by the target platform.
    pub tid: u64,
    /// Time-varying thread names: (snap_from, name).
    names: BTreeMap<i64, String>,
    /// Time-varying execution states: (snap_from, state).
    states: BTreeMap<i64, TraceExecutionState>,
    /// Time-varying comments: (snap_from, comment).
    comments: BTreeMap<i64, Option<String>>,
    /// The lifespan of this thread (creation to deletion).
    pub lifespan: Lifespan,
    /// Whether this thread has been deleted.
    deleted: bool,
}

impl TraceThread {
    /// Create a new thread.
    pub fn new(key: u64, tid: u64, snap: i64, name: impl Into<String>) -> Self {
        let mut names = BTreeMap::new();
        names.insert(snap, name.into());
        Self {
            key,
            process_key: None,
            tid,
            names,
            states: BTreeMap::new(),
            comments: BTreeMap::new(),
            lifespan: Lifespan::now_on(snap),
            deleted: false,
        }
    }

    /// Set the owning process.
    pub fn set_process(&mut self, process_key: u64) {
        self.process_key = Some(process_key);
    }

    /// Returns the unique key for this thread.
    pub fn key(&self) -> u64 {
        self.key
    }

    /// Get the thread name at the given snapshot.
    ///
    /// Returns the most recent name set at or before the given snap.
    pub fn get_name(&self, snap: i64) -> Option<&str> {
        self.names
            .range(..=snap)
            .next_back()
            .map(|(_, n)| n.as_str())
    }

    /// Set the thread name effective from the given snapshot.
    pub fn set_name(&mut self, snap: i64, name: impl Into<String>) {
        self.names.insert(snap, name.into());
    }

    /// Set the thread name for a lifespan.
    pub fn set_name_span(&mut self, lifespan: &Lifespan, name: impl Into<String>) {
        self.names.insert(lifespan.min(), name.into());
    }

    /// Get the execution state at the given snapshot.
    pub fn get_execution_state(&self, snap: i64) -> Option<TraceExecutionState> {
        self.states
            .range(..=snap)
            .next_back()
            .map(|(_, s)| *s)
    }

    /// Set the execution state effective from the given snapshot.
    pub fn set_execution_state(&mut self, snap: i64, state: TraceExecutionState) {
        self.states.insert(snap, state);
    }

    /// Get the comment at the given snapshot.
    pub fn get_comment(&self, snap: i64) -> Option<&str> {
        self.comments
            .range(..=snap)
            .next_back()
            .and_then(|(_, c)| c.as_deref())
    }

    /// Set the comment effective from the given snapshot.
    pub fn set_comment(&mut self, snap: i64, comment: Option<String>) {
        self.comments.insert(snap, comment);
    }

    /// Remove this thread from the given snap onward (mark as removed at snap).
    pub fn remove(&mut self, snap: i64) {
        self.lifespan = self.lifespan.with_max(snap - 1);
    }

    /// Delete this thread entirely.
    pub fn delete(&mut self) {
        self.deleted = true;
    }

    /// Check if the thread is valid at the given snapshot.
    pub fn is_valid(&self, snap: i64) -> bool {
        !self.deleted && self.lifespan.contains(snap)
    }

    /// Check if the thread is alive for any of the given span.
    pub fn is_alive(&self, span: &Lifespan) -> bool {
        !self.deleted && self.lifespan.intersects(span)
    }
}

// ---------------------------------------------------------------------------
// ThreadManager
// ---------------------------------------------------------------------------

/// Manages threads within a trace.
#[derive(Debug)]
pub struct TraceThreadManager {
    next_key: AtomicU64,
    threads: BTreeMap<u64, TraceThread>,
}

impl TraceThreadManager {
    /// Create a new empty thread manager.
    pub fn new() -> Self {
        Self {
            next_key: AtomicU64::new(1),
            threads: BTreeMap::new(),
        }
    }

    /// Add a new thread to the trace.
    pub fn add_thread(
        &mut self,
        tid: u64,
        snap: i64,
        name: impl Into<String>,
    ) -> u64 {
        let key = self.next_key.fetch_add(1, Ordering::Relaxed);
        let thread = TraceThread::new(key, tid, snap, name);
        self.threads.insert(key, thread);
        key
    }

    /// Get a thread by its key.
    pub fn get_thread(&self, key: u64) -> Option<&TraceThread> {
        self.threads.get(&key)
    }

    /// Get a mutable reference to a thread by its key.
    pub fn get_thread_mut(&mut self, key: u64) -> Option<&mut TraceThread> {
        self.threads.get_mut(&key)
    }

    /// Remove a thread by its key.
    pub fn remove_thread(&mut self, key: u64) -> Option<TraceThread> {
        self.threads.remove(&key)
    }

    /// Get all threads that are valid at the given snapshot.
    pub fn get_threads_at_snap(&self, snap: i64) -> Vec<&TraceThread> {
        self.threads
            .values()
            .filter(|t| t.is_valid(snap))
            .collect()
    }

    /// Iterate over all threads.
    pub fn threads(&self) -> impl Iterator<Item = &TraceThread> {
        self.threads.values()
    }

    /// Returns the number of threads.
    pub fn len(&self) -> usize {
        self.threads.len()
    }

    /// Returns `true` if there are no threads.
    pub fn is_empty(&self) -> bool {
        self.threads.is_empty()
    }
}

impl Default for TraceThreadManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_basic() {
        let proc = TraceProcess::new(1234, "test_process");
        assert_eq!(proc.pid, 1234);
        assert_eq!(proc.name, "test_process");
        assert_eq!(proc.state(), TraceExecutionState::Alive);
    }

    #[test]
    fn test_process_with_state() {
        let proc = TraceProcess::with_state(42, "my_proc", TraceExecutionState::Stopped);
        assert_eq!(proc.state(), TraceExecutionState::Stopped);
    }

    #[test]
    fn test_thread_creation() {
        let thread = TraceThread::new(1, 100, 0, "main");
        assert_eq!(thread.key(), 1);
        assert_eq!(thread.tid, 100);
        assert_eq!(thread.get_name(0), Some("main"));
        assert!(thread.is_valid(0));
        assert!(thread.is_valid(100));
        assert!(!thread.is_valid(-1));
    }

    #[test]
    fn test_thread_name_history() {
        let mut thread = TraceThread::new(1, 100, 0, "main");
        thread.set_name(10, "renamed_thread");

        assert_eq!(thread.get_name(0), Some("main"));
        assert_eq!(thread.get_name(5), Some("main"));
        assert_eq!(thread.get_name(10), Some("renamed_thread"));
        assert_eq!(thread.get_name(100), Some("renamed_thread"));
    }

    #[test]
    fn test_thread_state_history() {
        let mut thread = TraceThread::new(1, 100, 0, "main");
        thread.set_execution_state(0, TraceExecutionState::Stopped);
        thread.set_execution_state(5, TraceExecutionState::Running);
        thread.set_execution_state(10, TraceExecutionState::Stopped);

        assert_eq!(
            thread.get_execution_state(0),
            Some(TraceExecutionState::Stopped)
        );
        assert_eq!(
            thread.get_execution_state(3),
            Some(TraceExecutionState::Stopped)
        );
        assert_eq!(
            thread.get_execution_state(5),
            Some(TraceExecutionState::Running)
        );
        assert_eq!(
            thread.get_execution_state(10),
            Some(TraceExecutionState::Stopped)
        );
        assert_eq!(
            thread.get_execution_state(100),
            Some(TraceExecutionState::Stopped)
        );
    }

    #[test]
    fn test_thread_comment() {
        let mut thread = TraceThread::new(1, 100, 0, "main");
        thread.set_comment(0, Some("initial comment".to_string()));
        thread.set_comment(5, None);

        assert_eq!(thread.get_comment(0), Some("initial comment"));
        assert_eq!(thread.get_comment(3), Some("initial comment"));
        assert_eq!(thread.get_comment(5), None);
    }

    #[test]
    fn test_thread_remove_and_delete() {
        let mut thread = TraceThread::new(1, 100, 0, "main");
        assert!(thread.is_valid(100));

        thread.remove(50);
        assert!(thread.is_valid(49));
        assert!(!thread.is_valid(50));

        let mut thread2 = TraceThread::new(2, 200, 0, "other");
        thread2.delete();
        assert!(!thread2.is_valid(0));
        assert!(!thread2.is_alive(&Lifespan::at(0)));
    }

    #[test]
    fn test_thread_manager() {
        let mut mgr = TraceThreadManager::new();
        let k1 = mgr.add_thread(100, 0, "main");
        let _k2 = mgr.add_thread(200, 5, "worker");

        assert_eq!(mgr.len(), 2);
        assert!(!mgr.is_empty());

        let t1 = mgr.get_thread(k1).unwrap();
        assert_eq!(t1.tid, 100);
        assert_eq!(t1.get_name(0), Some("main"));

        let at_snap_3: Vec<u64> = mgr
            .get_threads_at_snap(3)
            .iter()
            .map(|t| t.key())
            .collect();
        assert_eq!(at_snap_3, vec![k1]);

        let at_snap_10: Vec<u64> = mgr
            .get_threads_at_snap(10)
            .iter()
            .map(|t| t.key())
            .collect();
        assert_eq!(at_snap_10.len(), 2);
    }

    #[test]
    fn test_thread_manager_remove() {
        let mut mgr = TraceThreadManager::new();
        let k = mgr.add_thread(100, 0, "temp");
        assert_eq!(mgr.len(), 1);
        mgr.remove_thread(k);
        assert_eq!(mgr.len(), 0);
        assert!(mgr.get_thread(k).is_none());
    }
}
