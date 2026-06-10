//! LLDB process representation.
//!
//! Models an LLDB "process" (SBProcess) as a debuggee process. In LLDB,
//! the debugged program is represented by a process object identified by
//! a process ID. A process has its own address space, loaded modules
//! (targets/images), threads, and memory.
//!
//! This corresponds to the Processes[N] node in the Ghidra trace object
//! tree and maps to `TraceProcess` on the model side.
//!
//! Ported from Ghidra's `Debugger-agent-lldb` Python commands (`put_processes`,
//! `put_process_state`, etc.) and the LLDB `SBProcess` API.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::lldb_thread::LldbThread;
use crate::agents::{
    ExecutionState, MemoryRegion, ModuleInfo, ProcessInfo,
};

/// An LLDB process (debuggee).
///
/// Each process in LLDB represents a target being debugged. The process
/// is accessed through the LLDB Python API via `SBProcess`. Unlike GDB,
/// LLDB does not use the "inferior" concept; it uses "process" directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LldbInferiorProcess {
    /// LLDB process ID (assigned by the OS).
    pub pid: u64,
    /// LLDB-internal process index (0-based in the target list).
    pub index: u32,
    /// Current execution state.
    pub state: ExecutionState,
    /// Display name (typically the target image path).
    pub display: String,
    /// Threads within this process, keyed by LLDB thread index.
    pub threads: BTreeMap<u32, LldbThread>,
    /// Loaded modules (shared libraries / images).
    pub modules: Vec<ModuleInfo>,
    /// Memory regions (mapped address ranges).
    pub memory_regions: Vec<MemoryRegion>,
    /// Whether this process has been synchronized to the trace.
    pub synced: bool,
    /// Exit code, if the process has terminated.
    pub exit_code: Option<i32>,
    /// The triple string for the process's target (e.g. "x86_64-apple-macosx").
    pub triple: Option<String>,
    /// Pointer size in bytes for the target architecture.
    pub pointer_size: usize,
}

impl LldbInferiorProcess {
    /// Create a new process with the given PID and index.
    pub fn new(pid: u64, index: u32) -> Self {
        Self {
            pid,
            index,
            state: ExecutionState::NotStarted,
            display: format!("Process {}", pid),
            threads: BTreeMap::new(),
            modules: Vec::new(),
            memory_regions: Vec::new(),
            synced: false,
            exit_code: None,
            triple: None,
            pointer_size: 8,
        }
    }

    /// Set the display name.
    pub fn with_display(mut self, display: impl Into<String>) -> Self {
        self.display = display.into();
        self
    }

    /// Set the target triple.
    pub fn with_triple(mut self, triple: impl Into<String>) -> Self {
        self.triple = Some(triple.into());
        self
    }

    /// Set the pointer size.
    pub fn with_pointer_size(mut self, size: usize) -> Self {
        self.pointer_size = size;
        self
    }

    /// Get the trace object path for this process.
    ///
    /// LLDB uses `Processes[N]` where N is the process index.
    pub fn trace_path(&self) -> String {
        format!("Processes[{}]", self.index)
    }

    /// Get the trace path for this process's memory space.
    pub fn memory_path(&self) -> String {
        format!("Processes[{}].Memory", self.index)
    }

    /// Get the trace path for this process's modules container.
    pub fn modules_path(&self) -> String {
        format!("Processes[{}].Modules", self.index)
    }

    /// Get the trace path for this process's environment.
    pub fn environment_path(&self) -> String {
        format!("Processes[{}].Environment", self.index)
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
    pub fn add_thread(&mut self, thread: LldbThread) {
        self.threads.insert(thread.index, thread);
    }

    /// Remove a thread by index.
    pub fn remove_thread(&mut self, thread_index: u32) -> Option<LldbThread> {
        self.threads.remove(&thread_index)
    }

    /// Get a thread by index.
    pub fn get_thread(&self, thread_index: u32) -> Option<&LldbThread> {
        self.threads.get(&thread_index)
    }

    /// Get a mutable reference to a thread by index.
    pub fn get_thread_mut(&mut self, thread_index: u32) -> Option<&mut LldbThread> {
        self.threads.get_mut(&thread_index)
    }

    /// Add a module to this process.
    pub fn add_module(&mut self, module: ModuleInfo) {
        // Replace if same name exists
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
    pub fn add_memory_region(&mut self, region: MemoryRegion) {
        // Replace if same base exists
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
            id: self.pid,
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
        vec![
            ("Debugger".to_string(), "lldb".to_string()),
            ("Arch".to_string(), arch.to_string()),
            ("OS".to_string(), os.to_string()),
            ("Endian".to_string(), endian.to_string()),
        ]
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

    /// Get all thread indices.
    pub fn thread_indices(&self) -> Vec<u32> {
        self.threads.keys().copied().collect()
    }

    /// Get the selected thread (first running, then first stopped).
    pub fn selected_thread(&self) -> Option<&LldbThread> {
        self.threads
            .values()
            .find(|t| t.state == ExecutionState::Running)
            .or_else(|| self.threads.values().find(|t| t.state == ExecutionState::Stopped))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::lldb::lldb_thread::LldbThread;

    #[test]
    fn test_process_new() {
        let p = LldbInferiorProcess::new(1234, 0);
        assert_eq!(p.pid, 1234);
        assert_eq!(p.index, 0);
        assert_eq!(p.state, ExecutionState::NotStarted);
        assert!(p.display.contains("1234"));
        assert!(p.threads.is_empty());
        assert!(p.modules.is_empty());
        assert!(!p.synced);
        assert_eq!(p.pointer_size, 8);
    }

    #[test]
    fn test_process_with_triple() {
        let p = LldbInferiorProcess::new(1, 0)
            .with_triple("x86_64-apple-macosx");
        assert_eq!(p.triple.as_deref(), Some("x86_64-apple-macosx"));
    }

    #[test]
    fn test_process_trace_paths() {
        let p = LldbInferiorProcess::new(100, 2);
        assert_eq!(p.trace_path(), "Processes[2]");
        assert_eq!(p.memory_path(), "Processes[2].Memory");
        assert_eq!(p.modules_path(), "Processes[2].Modules");
        assert_eq!(p.environment_path(), "Processes[2].Environment");
    }

    #[test]
    fn test_process_compute_state_empty() {
        let p = LldbInferiorProcess::new(1, 0);
        assert_eq!(p.compute_state(), ExecutionState::NotStarted);
    }

    #[test]
    fn test_process_compute_state_running() {
        let mut p = LldbInferiorProcess::new(1, 0);
        p.add_thread(LldbThread::new(1, 0).with_state(ExecutionState::Stopped));
        p.add_thread(LldbThread::new(2, 0).with_state(ExecutionState::Running));
        assert_eq!(p.compute_state(), ExecutionState::Running);
    }

    #[test]
    fn test_process_compute_state_stopped() {
        let mut p = LldbInferiorProcess::new(1, 0);
        p.add_thread(LldbThread::new(1, 0).with_state(ExecutionState::Stopped));
        p.add_thread(LldbThread::new(2, 0).with_state(ExecutionState::Stopped));
        assert_eq!(p.compute_state(), ExecutionState::Stopped);
    }

    #[test]
    fn test_process_compute_state_all_exited() {
        let mut p = LldbInferiorProcess::new(1, 0);
        p.add_thread(LldbThread::new(1, 0).with_state(ExecutionState::Exited));
        p.add_thread(LldbThread::new(2, 0).with_state(ExecutionState::Exited));
        assert_eq!(p.compute_state(), ExecutionState::Exited);
    }

    #[test]
    fn test_process_thread_management() {
        let mut p = LldbInferiorProcess::new(1, 0);
        p.add_thread(LldbThread::new(1, 0));
        p.add_thread(LldbThread::new(3, 0));
        assert_eq!(p.thread_count(), 2);
        assert!(p.get_thread(1).is_some());
        assert!(p.get_thread(2).is_none());
        assert!(p.get_thread(3).is_some());

        let removed = p.remove_thread(1);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().index, 1);
        assert_eq!(p.thread_count(), 1);
    }

    #[test]
    fn test_process_module_management() {
        let mut p = LldbInferiorProcess::new(1, 0);
        p.add_module(ModuleInfo {
            name: "libc.so.6".to_string(),
            base: 0x7ffff7a00000,
            size: 0x1e6000,
            build_id: None,
            debug_path: None,
            load_path: None,
        });
        assert_eq!(p.modules.len(), 1);

        // Replace same name
        p.add_module(ModuleInfo {
            name: "libc.so.6".to_string(),
            base: 0x7ffff7c00000,
            size: 0x1e6000,
            build_id: None,
            debug_path: None,
            load_path: None,
        });
        assert_eq!(p.modules.len(), 1);
        assert_eq!(p.modules[0].base, 0x7ffff7c00000);

        p.clear_modules();
        assert!(p.modules.is_empty());
    }

    #[test]
    fn test_process_exit() {
        let mut p = LldbInferiorProcess::new(1, 0);
        p.state = ExecutionState::Stopped;
        assert!(p.is_alive());
        p.set_exit(0);
        assert!(!p.is_alive());
        assert_eq!(p.exit_code, Some(0));
        assert_eq!(p.state, ExecutionState::Exited);
    }

    #[test]
    fn test_process_build_trace_values() {
        let p = LldbInferiorProcess::new(1, 0);
        let values = p.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "_state" && v == "NOT_STARTED"));
        assert!(values.iter().any(|(k, v)| k == "_display"));
    }

    #[test]
    fn test_process_to_process_info() {
        let p = LldbInferiorProcess::new(42, 0);
        let info = p.to_process_info();
        assert_eq!(info.id, 42);
    }

    #[test]
    fn test_process_selected_thread() {
        let mut p = LldbInferiorProcess::new(1, 0);
        assert!(p.selected_thread().is_none());

        p.add_thread(LldbThread::new(1, 0).with_state(ExecutionState::Stopped));
        let sel = p.selected_thread();
        assert!(sel.is_some());
        assert_eq!(sel.unwrap().index, 1);

        p.add_thread(LldbThread::new(2, 0).with_state(ExecutionState::Running));
        let sel = p.selected_thread();
        assert!(sel.is_some());
        assert_eq!(sel.unwrap().index, 2); // Running thread preferred
    }

    #[test]
    fn test_process_mark_synced() {
        let mut p = LldbInferiorProcess::new(1, 0);
        assert!(!p.synced);
        p.mark_synced();
        assert!(p.synced);
    }

    #[test]
    fn test_process_build_environment_values() {
        let p = LldbInferiorProcess::new(1, 0);
        let values = p.build_environment_values("Darwin", "x86_64", "little");
        assert!(values.iter().any(|(k, v)| k == "Debugger" && v == "lldb"));
        assert!(values.iter().any(|(k, v)| k == "OS" && v == "Darwin"));
    }

    #[test]
    fn test_process_pointer_size() {
        let p = LldbInferiorProcess::new(1, 0).with_pointer_size(4);
        assert_eq!(p.pointer_size, 4);
    }
}
