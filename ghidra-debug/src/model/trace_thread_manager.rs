//! Trace thread manager - manages threads and processes.
//!
//! Ported from Ghidra's `TraceThreadManager` and `DBTraceThreadManager`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::thread::{TraceProcess, TraceThread};
use super::Lifespan;

/// Manages threads and processes within a trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceThreadManager {
    /// Threads by key.
    threads: BTreeMap<i64, TraceThread>,
    /// Processes by key.
    processes: BTreeMap<i64, TraceProcess>,
    /// Next available key.
    next_key: i64,
}

impl TraceThreadManager {
    /// Create a new empty thread manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a thread, returning its assigned key.
    pub fn add_thread(&mut self, mut thread: TraceThread) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        thread.key = key;
        self.threads.insert(key, thread);
        key
    }

    /// Get a thread by key.
    pub fn get_thread(&self, key: i64) -> Option<&TraceThread> {
        self.threads.get(&key)
    }

    /// Get a mutable thread by key.
    pub fn get_thread_mut(&mut self, key: i64) -> Option<&mut TraceThread> {
        self.threads.get_mut(&key)
    }

    /// Add a process, returning its assigned key.
    pub fn add_process(&mut self, mut process: TraceProcess) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        process.key = key;
        self.processes.insert(key, process);
        key
    }

    /// Get a process by key.
    pub fn get_process(&self, key: i64) -> Option<&TraceProcess> {
        self.processes.get(&key)
    }

    /// Remove a thread by key.
    pub fn remove_thread(&mut self, key: i64) -> Option<TraceThread> {
        self.threads.remove(&key)
    }

    /// Remove a process by key.
    pub fn remove_process(&mut self, key: i64) -> Option<TraceProcess> {
        self.processes.remove(&key)
    }

    /// Get all threads valid at the given snap.
    pub fn threads_at_snap(&self, snap: i64) -> Vec<&TraceThread> {
        self.threads.values().filter(|t| t.is_valid(snap)).collect()
    }

    /// Get all processes valid at the given snap.
    pub fn processes_at_snap(&self, snap: i64) -> Vec<&TraceProcess> {
        self.processes
            .values()
            .filter(|p| p.lifespan.contains(snap))
            .collect()
    }

    /// Count of threads.
    pub fn thread_count(&self) -> usize {
        self.threads.len()
    }

    /// Count of processes.
    pub fn process_count(&self) -> usize {
        self.processes.len()
    }

    /// Iterate over all threads.
    pub fn all_threads(&self) -> impl Iterator<Item = &TraceThread> {
        self.threads.values()
    }

    /// Iterate over all processes.
    pub fn all_processes(&self) -> impl Iterator<Item = &TraceProcess> {
        self.processes.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_thread() {
        let mut mgr = TraceThreadManager::new();
        let key = mgr.add_thread(TraceThread::new(0, "Threads[1]", "main", 0));
        assert!(mgr.get_thread(key).is_some());
        assert_eq!(mgr.thread_count(), 1);
    }

    #[test]
    fn test_add_process() {
        let mut mgr = TraceThreadManager::new();
        let key = mgr.add_process(TraceProcess::new(0, "Processes[1]", "bash", 0));
        assert!(mgr.get_process(key).is_some());
        assert_eq!(mgr.process_count(), 1);
    }

    #[test]
    fn test_threads_at_snap() {
        let mut mgr = TraceThreadManager::new();
        let mut t = TraceThread::new(0, "Threads[1]", "main", 0);
        t.lifespan = Lifespan::span(0, 10);
        mgr.add_thread(t);
        let mut t2 = TraceThread::new(0, "Threads[2]", "worker", 5);
        t2.lifespan = Lifespan::span(5, 20);
        mgr.add_thread(t2);

        assert_eq!(mgr.threads_at_snap(0).len(), 1);
        assert_eq!(mgr.threads_at_snap(7).len(), 2);
        assert_eq!(mgr.threads_at_snap(15).len(), 1);
    }
}
