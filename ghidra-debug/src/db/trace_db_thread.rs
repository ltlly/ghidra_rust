//! Database-backed trace thread and process management.
//!
//! Ported from Ghidra's thread/process database managers in
//! Framework-TraceModeling.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// The execution state of a thread in the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DBThreadState {
    /// Thread is running.
    Running,
    /// Thread is stopped.
    Stopped,
    /// Thread has terminated.
    Terminated,
    /// Thread state is unknown.
    Unknown,
}

/// A database-backed process record.
///
/// Ported from Ghidra's `DBTraceProcess` / process manager entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DBTraceProcessRecord {
    /// The process key (database row ID).
    pub key: i64,
    /// The process ID (OS PID).
    pub pid: Option<i64>,
    /// The lifespan of this process.
    pub lifespan: Lifespan,
    /// The process name.
    pub name: String,
    /// The executable path.
    pub executable_path: Option<String>,
}

impl DBTraceProcessRecord {
    /// Create a new process record.
    pub fn new(key: i64, name: impl Into<String>, lifespan: Lifespan) -> Self {
        Self {
            key,
            pid: None,
            lifespan,
            name: name.into(),
            executable_path: None,
        }
    }

    /// Set the PID.
    pub fn with_pid(mut self, pid: i64) -> Self {
        self.pid = Some(pid);
        self
    }

    /// Set the executable path.
    pub fn with_executable(mut self, path: impl Into<String>) -> Self {
        self.executable_path = Some(path.into());
        self
    }
}

/// A database-backed thread record.
///
/// Ported from Ghidra's `DBTraceThread` / thread manager entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DBTraceThreadRecord {
    /// The thread key (database row ID).
    pub key: i64,
    /// The process key this thread belongs to.
    pub process_key: i64,
    /// The OS thread ID.
    pub tid: Option<i64>,
    /// The thread name.
    pub name: String,
    /// The lifespan of this thread.
    pub lifespan: Lifespan,
    /// The execution state.
    pub state: DBThreadState,
    /// The program counter offset, if known.
    pub pc_offset: Option<u64>,
    /// The address space for the PC.
    pub pc_space: Option<String>,
}

impl DBTraceThreadRecord {
    /// Create a new thread record.
    pub fn new(
        key: i64,
        process_key: i64,
        name: impl Into<String>,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            key,
            process_key,
            tid: None,
            name: name.into(),
            lifespan,
            state: DBThreadState::Unknown,
            pc_offset: None,
            pc_space: None,
        }
    }

    /// Set the TID.
    pub fn with_tid(mut self, tid: i64) -> Self {
        self.tid = Some(tid);
        self
    }

    /// Set the execution state.
    pub fn with_state(mut self, state: DBThreadState) -> Self {
        self.state = state;
        self
    }

    /// Set the program counter.
    pub fn with_pc(mut self, space: impl Into<String>, offset: u64) -> Self {
        self.pc_space = Some(space.into());
        self.pc_offset = Some(offset);
        self
    }
}

/// A database-backed stack frame record.
///
/// Ported from Ghidra's stack frame manager entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DBStackFrameRecord {
    /// The frame key.
    pub key: i64,
    /// The thread key this frame belongs to.
    pub thread_key: i64,
    /// The frame level (0 = innermost).
    pub level: i32,
    /// The return address offset, if known.
    pub return_offset: Option<u64>,
    /// The address space for the return address.
    pub return_space: Option<String>,
}

impl DBStackFrameRecord {
    /// Create a new stack frame record.
    pub fn new(key: i64, thread_key: i64, level: i32) -> Self {
        Self {
            key,
            thread_key,
            level,
            return_offset: None,
            return_space: None,
        }
    }

    /// Set the return address.
    pub fn with_return_address(mut self, space: impl Into<String>, offset: u64) -> Self {
        self.return_space = Some(space.into());
        self.return_offset = Some(offset);
        self
    }
}

/// Manager for database-backed processes and threads.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DBThreadManager {
    processes: IndexMap<i64, DBTraceProcessRecord>,
    threads: IndexMap<i64, DBTraceThreadRecord>,
    stack_frames: IndexMap<i64, Vec<DBStackFrameRecord>>,
    next_key: i64,
}

impl DBThreadManager {
    /// Create a new thread manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a new unique key.
    fn alloc_key(&mut self) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        key
    }

    /// Add a process.
    pub fn add_process(&mut self, name: impl Into<String>, lifespan: Lifespan) -> i64 {
        let key = self.alloc_key();
        let record = DBTraceProcessRecord::new(key, name, lifespan);
        self.processes.insert(key, record);
        key
    }

    /// Add a thread to a process.
    pub fn add_thread(
        &mut self,
        process_key: i64,
        name: impl Into<String>,
        lifespan: Lifespan,
    ) -> Option<i64> {
        if !self.processes.contains_key(&process_key) {
            return None;
        }
        let key = self.alloc_key();
        let record = DBTraceThreadRecord::new(key, process_key, name, lifespan);
        self.threads.insert(key, record);
        Some(key)
    }

    /// Get a process by key.
    pub fn get_process(&self, key: i64) -> Option<&DBTraceProcessRecord> {
        self.processes.get(&key)
    }

    /// Get a thread by key.
    pub fn get_thread(&self, key: i64) -> Option<&DBTraceThreadRecord> {
        self.threads.get(&key)
    }

    /// Get a mutable reference to a thread by key.
    pub fn get_thread_mut(&mut self, key: i64) -> Option<&mut DBTraceThreadRecord> {
        self.threads.get_mut(&key)
    }

    /// Get all threads for a process.
    pub fn threads_for_process(&self, process_key: i64) -> Vec<&DBTraceThreadRecord> {
        self.threads
            .values()
            .filter(|t| t.process_key == process_key)
            .collect()
    }

    /// Remove a process and all its threads.
    pub fn remove_process(&mut self, key: i64) -> Option<DBTraceProcessRecord> {
        // Remove all threads for this process
        let thread_keys: Vec<i64> = self
            .threads
            .values()
            .filter(|t| t.process_key == key)
            .map(|t| t.key)
            .collect();
        for tk in thread_keys {
            self.threads.shift_remove(&tk);
            self.stack_frames.shift_remove(&tk);
        }
        self.processes.shift_remove(&key)
    }

    /// Remove a thread.
    pub fn remove_thread(&mut self, key: i64) -> Option<DBTraceThreadRecord> {
        self.stack_frames.shift_remove(&key);
        self.threads.shift_remove(&key)
    }

    /// Add a stack frame to a thread.
    pub fn add_stack_frame(
        &mut self,
        thread_key: i64,
        level: i32,
    ) -> Option<i64> {
        if !self.threads.contains_key(&thread_key) {
            return None;
        }
        let key = self.alloc_key();
        let frame = DBStackFrameRecord::new(key, thread_key, level);
        self.stack_frames
            .entry(thread_key)
            .or_default()
            .push(frame);
        Some(key)
    }

    /// Get stack frames for a thread.
    pub fn stack_frames(&self, thread_key: i64) -> &[DBStackFrameRecord] {
        self.stack_frames
            .get(&thread_key)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// The number of processes.
    pub fn process_count(&self) -> usize {
        self.processes.len()
    }

    /// The number of threads.
    pub fn thread_count(&self) -> usize {
        self.threads.len()
    }

    /// Get all processes.
    pub fn processes(&self) -> &IndexMap<i64, DBTraceProcessRecord> {
        &self.processes
    }

    /// Get all threads.
    pub fn threads(&self) -> &IndexMap<i64, DBTraceThreadRecord> {
        &self.threads
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_record() {
        let proc = DBTraceProcessRecord::new(1, "myapp", Lifespan::now_on(0))
            .with_pid(1234)
            .with_executable("/usr/bin/myapp");
        assert_eq!(proc.key, 1);
        assert_eq!(proc.pid, Some(1234));
        assert_eq!(proc.executable_path.as_deref(), Some("/usr/bin/myapp"));
    }

    #[test]
    fn test_thread_record() {
        let thread = DBTraceThreadRecord::new(1, 1, "main", Lifespan::now_on(0))
            .with_tid(100)
            .with_state(DBThreadState::Running)
            .with_pc("ram", 0x400000);
        assert_eq!(thread.key, 1);
        assert_eq!(thread.state, DBThreadState::Running);
        assert_eq!(thread.pc_offset, Some(0x400000));
    }

    #[test]
    fn test_stack_frame_record() {
        let frame = DBStackFrameRecord::new(1, 1, 0)
            .with_return_address("ram", 0x401000);
        assert_eq!(frame.level, 0);
        assert_eq!(frame.return_offset, Some(0x401000));
    }

    #[test]
    fn test_thread_manager_basics() {
        let mut mgr = DBThreadManager::new();
        assert_eq!(mgr.process_count(), 0);

        let proc_key = mgr.add_process("myapp", Lifespan::now_on(0));
        assert_eq!(mgr.process_count(), 1);

        let thread_key = mgr.add_thread(proc_key, "main", Lifespan::now_on(0)).unwrap();
        assert_eq!(mgr.thread_count(), 1);

        let proc = mgr.get_process(proc_key).unwrap();
        assert_eq!(proc.name, "myapp");

        let thread = mgr.get_thread(thread_key).unwrap();
        assert_eq!(thread.name, "main");
        assert_eq!(thread.process_key, proc_key);
    }

    #[test]
    fn test_thread_manager_threads_for_process() {
        let mut mgr = DBThreadManager::new();
        let p1 = mgr.add_process("p1", Lifespan::now_on(0));
        let p2 = mgr.add_process("p2", Lifespan::now_on(0));

        mgr.add_thread(p1, "t1", Lifespan::now_on(0));
        mgr.add_thread(p1, "t2", Lifespan::now_on(0));
        mgr.add_thread(p2, "t3", Lifespan::now_on(0));

        let p1_threads = mgr.threads_for_process(p1);
        assert_eq!(p1_threads.len(), 2);
        let p2_threads = mgr.threads_for_process(p2);
        assert_eq!(p2_threads.len(), 1);
    }

    #[test]
    fn test_thread_manager_remove_process() {
        let mut mgr = DBThreadManager::new();
        let p = mgr.add_process("p", Lifespan::now_on(0));
        mgr.add_thread(p, "t1", Lifespan::now_on(0));
        mgr.add_thread(p, "t2", Lifespan::now_on(0));

        mgr.remove_process(p);
        assert_eq!(mgr.process_count(), 0);
        assert_eq!(mgr.thread_count(), 0);
    }

    #[test]
    fn test_thread_manager_stack_frames() {
        let mut mgr = DBThreadManager::new();
        let p = mgr.add_process("p", Lifespan::now_on(0));
        let t = mgr.add_thread(p, "main", Lifespan::now_on(0)).unwrap();

        mgr.add_stack_frame(t, 0);
        mgr.add_stack_frame(t, 1);
        mgr.add_stack_frame(t, 2);

        let frames = mgr.stack_frames(t);
        assert_eq!(frames.len(), 3);
    }

    #[test]
    fn test_thread_manager_nonexistent() {
        let mut mgr = DBThreadManager::new();
        assert!(mgr.add_thread(999, "none", Lifespan::now_on(0)).is_none());
        assert!(mgr.get_process(999).is_none());
        assert!(mgr.get_thread(999).is_none());
    }

    #[test]
    fn test_thread_manager_serde() {
        let mut mgr = DBThreadManager::new();
        let p = mgr.add_process("p", Lifespan::now_on(0));
        mgr.add_thread(p, "t", Lifespan::now_on(0));

        let json = serde_json::to_string(&mgr).unwrap();
        let back: DBThreadManager = serde_json::from_str(&json).unwrap();
        assert_eq!(back.process_count(), 1);
        assert_eq!(back.thread_count(), 1);
    }

    #[test]
    fn test_db_thread_state() {
        assert_ne!(DBThreadState::Running, DBThreadState::Stopped);
        assert_eq!(DBThreadState::Unknown, DBThreadState::Unknown);
    }
}
