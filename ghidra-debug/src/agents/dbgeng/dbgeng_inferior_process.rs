//! Dbgeng process representation.
//!
//! Models a dbgeng debuggee process. In dbgeng, each debugged program is
//! identified by a process number (0-based in the dbgeng internals, but
//! exposed as 1-based in the trace hierarchy). A process has its own address
//! space, loaded modules, threads, and memory.
//!
//! This corresponds to the Processes[N] node in the Ghidra trace object tree
//! and maps to `TraceProcess` on the model side.
//!
//! Ported from Ghidra's `Debugger-agent-dbgeng` Python commands
//! (`put_processes`, `put_process_state`, etc.) and the Ghidra process
//! concept. Unlike GDB's "inferior" abstraction, dbgeng uses "processes"
//! directly, with WoW64 support for 32-bit processes on 64-bit Windows.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::dbgeng_thread::DbgEngThread;
use crate::agents::{
    ExecutionState, MemoryRegion, ModuleInfo, ProcessInfo,
};

/// A dbgeng debuggee process.
///
/// Each process in dbgeng represents a separate target being debugged.
/// Processes are numbered in the `Processes[N]` hierarchy. The dbgeng
/// agent supports WoW64 mode where a 32-bit process runs on 64-bit Windows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbgEngInferiorProcess {
    /// Process number in the trace hierarchy (0-based).
    pub num: u32,
    /// Process ID assigned by the OS, if known.
    pub pid: Option<u64>,
    /// Current execution state.
    pub state: ExecutionState,
    /// Display name (typically the target image path).
    pub display: String,
    /// Threads within this process, keyed by thread number.
    pub threads: BTreeMap<u32, DbgEngThread>,
    /// Loaded modules (DLLs / executables).
    pub modules: Vec<ModuleInfo>,
    /// Memory regions (virtual memory mappings).
    pub memory_regions: Vec<MemoryRegion>,
    /// Whether this process has been synchronized to the trace.
    pub synced: bool,
    /// Exit code, if the process has terminated.
    pub exit_code: Option<i32>,
    /// Whether the target is 64-bit.
    pub is_64bit: bool,
    /// Whether WoW64 mode is active (32-bit on 64-bit Windows).
    pub is_wow64: bool,
}

impl DbgEngInferiorProcess {
    /// Create a new process.
    pub fn new(num: u32) -> Self {
        Self {
            num,
            pid: None,
            state: ExecutionState::NotStarted,
            display: format!("Process {}", num),
            threads: BTreeMap::new(),
            modules: Vec::new(),
            memory_regions: Vec::new(),
            synced: false,
            exit_code: None,
            is_64bit: true,
            is_wow64: false,
        }
    }

    /// Create a process with a known PID.
    pub fn with_pid(mut self, pid: u64) -> Self {
        self.pid = Some(pid);
        self
    }

    /// Set the display name.
    pub fn with_display(mut self, display: impl Into<String>) -> Self {
        self.display = display.into();
        self
    }

    /// Set the 64-bit flag.
    pub fn with_64bit(mut self, is_64bit: bool) -> Self {
        self.is_64bit = is_64bit;
        self
    }

    /// Set the WoW64 flag.
    pub fn with_wow64(mut self, is_wow64: bool) -> Self {
        self.is_wow64 = is_wow64;
        self
    }

    /// Get the trace object path for this process.
    pub fn trace_path(&self) -> String {
        format!("Processes[{}]", self.num)
    }

    /// Get the trace path for this process's memory space.
    pub fn memory_path(&self) -> String {
        format!("Processes[{}].Memory", self.num)
    }

    /// Get the trace path for this process's modules container.
    pub fn modules_path(&self) -> String {
        format!("Processes[{}].Modules", self.num)
    }

    /// Get the trace path for this process's environment.
    pub fn environment_path(&self) -> String {
        format!("Processes[{}].Environment", self.num)
    }

    /// Get the trace path for this process's breakpoints container.
    pub fn breakpoints_path(&self) -> String {
        format!("Processes[{}].Breakpoints", self.num)
    }

    /// Compute the overall process state from its threads.
    ///
    /// If any thread is running, the process is running. If all threads
    /// are stopped, the process is stopped. If no threads exist or all
    /// are exited, the process is inactive/terminated.
    pub fn compute_state(&self) -> ExecutionState {
        if self.threads.is_empty() {
            return self.state;
        }
        let mut any_running = false;
        let mut all_exited = true;
        for t in self.threads.values() {
            if t.state == ExecutionState::Running {
                any_running = true;
                all_exited = false;
            } else if t.state != ExecutionState::Exited {
                all_exited = false;
            }
        }
        if any_running {
            ExecutionState::Running
        } else if all_exited {
            ExecutionState::Exited
        } else {
            ExecutionState::Stopped
        }
    }

    /// Add a thread to this process.
    pub fn add_thread(&mut self, thread: DbgEngThread) {
        self.threads.insert(thread.num, thread);
    }

    /// Remove a thread by number.
    pub fn remove_thread(&mut self, thread_num: u32) -> Option<DbgEngThread> {
        self.threads.remove(&thread_num)
    }

    /// Get a thread by number.
    pub fn get_thread(&self, thread_num: u32) -> Option<&DbgEngThread> {
        self.threads.get(&thread_num)
    }

    /// Get a mutable reference to a thread by number.
    pub fn get_thread_mut(&mut self, thread_num: u32) -> Option<&mut DbgEngThread> {
        self.threads.get_mut(&thread_num)
    }

    /// Add a module to this process.
    ///
    /// Replaces any existing module with the same name.
    pub fn add_module(&mut self, module: ModuleInfo) {
        self.modules.retain(|m| m.name != module.name);
        self.modules.push(module);
    }

    /// Remove a module by name.
    pub fn remove_module(&mut self, name: &str) -> Option<ModuleInfo> {
        if let Some(pos) = self.modules.iter().position(|m| m.name == name) {
            Some(self.modules.remove(pos))
        } else {
            None
        }
    }

    /// Clear all modules.
    pub fn clear_modules(&mut self) {
        self.modules.clear();
    }

    /// Add a memory region.
    ///
    /// Replaces any existing region with the same base address.
    pub fn add_memory_region(&mut self, region: MemoryRegion) {
        self.memory_regions.retain(|r| r.base != region.base);
        self.memory_regions.push(region);
    }

    /// Clear all memory regions.
    pub fn clear_memory_regions(&mut self) {
        self.memory_regions.clear();
    }

    /// Convert to a `ProcessInfo` for the common agent interface.
    pub fn to_process_info(&self) -> ProcessInfo {
        ProcessInfo {
            id: self.num as u64,
            state: self.compute_state(),
        }
    }

    /// Build trace object key-value pairs for this process.
    ///
    /// These are used to populate the `Processes[N]` node in the trace.
    pub fn build_trace_values(&self) -> Vec<(String, String)> {
        let state = self.compute_state();
        vec![
            ("_state".to_string(), state.as_trace_str().to_string()),
            ("_display".to_string(), self.display.clone()),
        ]
    }

    /// Build trace object key-value pairs for this process's environment.
    pub fn build_environment_values(
        &self,
        os: &str,
        arch: &str,
        endian: &str,
    ) -> Vec<(String, String)> {
        let mut values = vec![
            ("Debugger".to_string(), "dbgeng".to_string()),
            ("Arch".to_string(), arch.to_string()),
            ("OS".to_string(), os.to_string()),
            ("Endian".to_string(), endian.to_string()),
        ];
        if self.is_wow64 {
            values.push(("WoW64".to_string(), "true".to_string()));
        }
        values
    }

    /// Mark this process as synchronized.
    pub fn mark_synced(&mut self) {
        self.synced = true;
    }

    /// Set the exit code and mark as exited.
    pub fn set_exit(&mut self, code: i32) {
        self.exit_code = Some(code);
        self.state = ExecutionState::Exited;
    }

    /// Check if the process is alive (not exited/disconnected).
    pub fn is_alive(&self) -> bool {
        !matches!(self.state, ExecutionState::Exited | ExecutionState::NotStarted)
    }

    /// Get the number of threads.
    pub fn thread_count(&self) -> usize {
        self.threads.len()
    }

    /// Get all thread numbers.
    pub fn thread_numbers(&self) -> Vec<u32> {
        self.threads.keys().copied().collect()
    }

    /// Get the selected thread (first running, then first stopped).
    pub fn selected_thread(&self) -> Option<&DbgEngThread> {
        self.threads
            .values()
            .find(|t| t.state == ExecutionState::Running)
            .or_else(|| self.threads.values().find(|t| t.state == ExecutionState::Stopped))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::dbgeng::dbgeng_thread::DbgEngThread;

    #[test]
    fn test_process_new() {
        let p = DbgEngInferiorProcess::new(0);
        assert_eq!(p.num, 0);
        assert_eq!(p.pid, None);
        assert_eq!(p.state, ExecutionState::NotStarted);
        assert_eq!(p.display, "Process 0");
        assert!(p.threads.is_empty());
        assert!(p.modules.is_empty());
        assert!(!p.synced);
        assert!(p.is_64bit);
        assert!(!p.is_wow64);
    }

    #[test]
    fn test_process_with_pid() {
        let p = DbgEngInferiorProcess::new(1).with_pid(1234);
        assert_eq!(p.pid, Some(1234));
    }

    #[test]
    fn test_process_builder() {
        let p = DbgEngInferiorProcess::new(1)
            .with_display("notepad.exe")
            .with_64bit(false)
            .with_wow64(true);
        assert_eq!(p.display, "notepad.exe");
        assert!(!p.is_64bit);
        assert!(p.is_wow64);
    }

    #[test]
    fn test_process_trace_paths() {
        let p = DbgEngInferiorProcess::new(2);
        assert_eq!(p.trace_path(), "Processes[2]");
        assert_eq!(p.memory_path(), "Processes[2].Memory");
        assert_eq!(p.modules_path(), "Processes[2].Modules");
        assert_eq!(p.environment_path(), "Processes[2].Environment");
        assert_eq!(p.breakpoints_path(), "Processes[2].Breakpoints");
    }

    #[test]
    fn test_process_compute_state_empty() {
        let p = DbgEngInferiorProcess::new(1);
        assert_eq!(p.compute_state(), ExecutionState::NotStarted);
    }

    #[test]
    fn test_process_compute_state_running() {
        let mut p = DbgEngInferiorProcess::new(1);
        p.add_thread(DbgEngThread::new(1).with_state(ExecutionState::Stopped));
        p.add_thread(DbgEngThread::new(2).with_state(ExecutionState::Running));
        assert_eq!(p.compute_state(), ExecutionState::Running);
    }

    #[test]
    fn test_process_compute_state_stopped() {
        let mut p = DbgEngInferiorProcess::new(1);
        p.add_thread(DbgEngThread::new(1).with_state(ExecutionState::Stopped));
        p.add_thread(DbgEngThread::new(2).with_state(ExecutionState::Stopped));
        assert_eq!(p.compute_state(), ExecutionState::Stopped);
    }

    #[test]
    fn test_process_compute_state_all_exited() {
        let mut p = DbgEngInferiorProcess::new(1);
        p.add_thread(DbgEngThread::new(1).with_state(ExecutionState::Exited));
        p.add_thread(DbgEngThread::new(2).with_state(ExecutionState::Exited));
        assert_eq!(p.compute_state(), ExecutionState::Exited);
    }

    #[test]
    fn test_process_thread_management() {
        let mut p = DbgEngInferiorProcess::new(1);
        p.add_thread(DbgEngThread::new(1));
        p.add_thread(DbgEngThread::new(3));
        assert_eq!(p.thread_count(), 2);
        assert!(p.get_thread(1).is_some());
        assert!(p.get_thread(2).is_none());
        assert!(p.get_thread(3).is_some());

        let removed = p.remove_thread(1);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().num, 1);
        assert_eq!(p.thread_count(), 1);
    }

    #[test]
    fn test_process_module_management() {
        let mut p = DbgEngInferiorProcess::new(1);
        p.add_module(ModuleInfo {
            name: "ntdll.dll".to_string(),
            base: 0x7ff800000000,
            size: 0x1e6000,
            build_id: None,
            debug_path: None,
            load_path: Some("C:\\Windows\\System32\\ntdll.dll".to_string()),
        });
        assert_eq!(p.modules.len(), 1);

        // Replace same name
        p.add_module(ModuleInfo {
            name: "ntdll.dll".to_string(),
            base: 0x7ff800020000,
            size: 0x1e6000,
            build_id: None,
            debug_path: None,
            load_path: Some("C:\\Windows\\System32\\ntdll.dll".to_string()),
        });
        assert_eq!(p.modules.len(), 1);
        assert_eq!(p.modules[0].base, 0x7ff800020000);

        p.clear_modules();
        assert!(p.modules.is_empty());
    }

    #[test]
    fn test_process_exit() {
        let mut p = DbgEngInferiorProcess::new(1);
        p.state = ExecutionState::Stopped;
        assert!(p.is_alive());
        p.set_exit(0);
        assert!(!p.is_alive());
        assert_eq!(p.exit_code, Some(0));
        assert_eq!(p.state, ExecutionState::Exited);
    }

    #[test]
    fn test_process_build_trace_values() {
        let p = DbgEngInferiorProcess::new(1);
        let values = p.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "_state" && v == "NOT_STARTED"));
        assert!(values.iter().any(|(k, v)| k == "_display" && v == "Process 1"));
    }

    #[test]
    fn test_process_build_environment_values() {
        let p = DbgEngInferiorProcess::new(1).with_wow64(true);
        let values = p.build_environment_values("Windows", "x86", "little");
        assert!(values.iter().any(|(k, v)| k == "Debugger" && v == "dbgeng"));
        assert!(values.iter().any(|(k, v)| k == "WoW64" && v == "true"));
    }

    #[test]
    fn test_process_to_process_info() {
        let p = DbgEngInferiorProcess::new(3);
        let info = p.to_process_info();
        assert_eq!(info.id, 3);
    }

    #[test]
    fn test_process_selected_thread() {
        let mut p = DbgEngInferiorProcess::new(1);
        assert!(p.selected_thread().is_none());

        p.add_thread(DbgEngThread::new(1).with_state(ExecutionState::Stopped));
        let sel = p.selected_thread();
        assert!(sel.is_some());
        assert_eq!(sel.unwrap().num, 1);

        p.add_thread(DbgEngThread::new(2).with_state(ExecutionState::Running));
        let sel = p.selected_thread();
        assert!(sel.is_some());
        assert_eq!(sel.unwrap().num, 2); // Running thread preferred
    }

    #[test]
    fn test_process_mark_synced() {
        let mut p = DbgEngInferiorProcess::new(1);
        assert!(!p.synced);
        p.mark_synced();
        assert!(p.synced);
    }

    #[test]
    fn test_process_memory_regions() {
        let mut p = DbgEngInferiorProcess::new(1);
        p.add_memory_region(MemoryRegion {
            base: 0x10000,
            size: 0x1000,
            offset: 0,
            permissions: "rwx".to_string(),
            object_file: "test.exe".to_string(),
        });
        assert_eq!(p.memory_regions.len(), 1);

        // Replace same base
        p.add_memory_region(MemoryRegion {
            base: 0x10000,
            size: 0x2000,
            offset: 0,
            permissions: "rw-".to_string(),
            object_file: "test.exe".to_string(),
        });
        assert_eq!(p.memory_regions.len(), 1);
        assert_eq!(p.memory_regions[0].size, 0x2000);

        p.clear_memory_regions();
        assert!(p.memory_regions.is_empty());
    }
}
