//! GDB inferior process representation.
//!
//! Models a GDB "inferior" as a debuggee process. In GDB, each debugged
//! program is an "inferior" identified by a number (1-based). An inferior
//! has its own address space, loaded modules, threads, and memory.
//!
//! This corresponds to the Inferiors[N] node in the Ghidra trace object
//! tree and maps to `TraceProcess` on the model side.
//!
//! Ported from Ghidra's `Debugger-agent-gdb` Python commands (`put_inferiors`,
//! `put_inferior_state`, etc.) and the Ghidra `Inferior` concept.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::gdb_thread::GdbThread;
use crate::agents::{
    ExecutionState, MemoryRegion, ModuleInfo, ProcessInfo,
};

/// A GDB inferior (debuggee process).
///
/// Each inferior in GDB represents a separate process being debugged.
/// Inferiors are numbered starting at 1. The first inferior is created
/// automatically when GDB starts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GdbInferiorProcess {
    /// GDB inferior number (1-based).
    pub num: u32,
    /// Process ID assigned by the OS, if known.
    pub pid: Option<u64>,
    /// Current execution state.
    pub state: ExecutionState,
    /// Display name (typically the target image path).
    pub display: String,
    /// Threads within this inferior, keyed by thread number.
    pub threads: BTreeMap<u32, GdbThread>,
    /// Loaded modules (shared libraries / objfiles).
    pub modules: Vec<ModuleInfo>,
    /// Memory regions (mapped address ranges).
    pub memory_regions: Vec<MemoryRegion>,
    /// Whether this inferior has been synchronized to the trace.
    pub synced: bool,
    /// Exit code, if the inferior has terminated.
    pub exit_code: Option<i32>,
}

impl GdbInferiorProcess {
    /// Create a new inferior process.
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
        }
    }

    /// Create an inferior with a known PID.
    pub fn with_pid(mut self, pid: u64) -> Self {
        self.pid = Some(pid);
        self
    }

    /// Set the display name.
    pub fn with_display(mut self, display: impl Into<String>) -> Self {
        self.display = display.into();
        self
    }

    /// Get the trace object path for this inferior.
    pub fn trace_path(&self) -> String {
        format!("Inferiors[{}]", self.num)
    }

    /// Get the trace path for this inferior's memory space.
    pub fn memory_path(&self) -> String {
        format!("Inferiors[{}].Memory", self.num)
    }

    /// Get the trace path for this inferior's modules container.
    pub fn modules_path(&self) -> String {
        format!("Inferiors[{}].Modules", self.num)
    }

    /// Get the trace path for this inferior's environment.
    pub fn environment_path(&self) -> String {
        format!("Inferiors[{}].Environment", self.num)
    }

    /// Get the trace path for this inferior's breakpoints container.
    pub fn breakpoints_path(&self) -> String {
        format!("Inferiors[{}].Breakpoints", self.num)
    }

    /// Compute the overall inferior state from its threads.
    ///
    /// If any thread is running, the inferior is running. If all threads
    /// are stopped, the inferior is stopped. If no threads exist or all
    /// are exited, the inferior is inactive/terminated.
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

    /// Add a thread to this inferior.
    pub fn add_thread(&mut self, thread: GdbThread) {
        self.threads.insert(thread.num, thread);
    }

    /// Remove a thread by number.
    pub fn remove_thread(&mut self, thread_num: u32) -> Option<GdbThread> {
        self.threads.remove(&thread_num)
    }

    /// Get a thread by number.
    pub fn get_thread(&self, thread_num: u32) -> Option<&GdbThread> {
        self.threads.get(&thread_num)
    }

    /// Get a mutable reference to a thread by number.
    pub fn get_thread_mut(&mut self, thread_num: u32) -> Option<&mut GdbThread> {
        self.threads.get_mut(&thread_num)
    }

    /// Add a module to this inferior.
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
            id: self.num as u64,
            state: self.compute_state(),
        }
    }

    /// Build trace object key-value pairs for this inferior.
    ///
    /// These are used to populate the `Inferiors[N]` node in the trace.
    pub fn build_trace_values(&self) -> Vec<(String, String)> {
        let state = self.compute_state();
        vec![
            ("_state".to_string(), state.as_trace_str().to_string()),
            ("_display".to_string(), self.display.clone()),
        ]
    }

    /// Build trace object key-value pairs for this inferior's environment.
    pub fn build_environment_values(
        &self,
        os: &str,
        arch: &str,
        endian: &str,
    ) -> Vec<(String, String)> {
        vec![
            ("Debugger".to_string(), "gdb".to_string()),
            ("Arch".to_string(), arch.to_string()),
            ("OS".to_string(), os.to_string()),
            ("Endian".to_string(), endian.to_string()),
        ]
    }

    /// Mark this inferior as synchronized.
    pub fn mark_synced(&mut self) {
        self.synced = true;
    }

    /// Set the exit code and mark as exited.
    pub fn set_exit(&mut self, code: i32) {
        self.exit_code = Some(code);
        self.state = ExecutionState::Exited;
    }

    /// Check if the inferior is alive (not exited/disconnected).
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
    pub fn selected_thread(&self) -> Option<&GdbThread> {
        self.threads
            .values()
            .find(|t| t.state == ExecutionState::Running)
            .or_else(|| self.threads.values().find(|t| t.state == ExecutionState::Stopped))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::gdb::gdb_thread::GdbThread;

    #[test]
    fn test_inferior_new() {
        let inf = GdbInferiorProcess::new(1);
        assert_eq!(inf.num, 1);
        assert_eq!(inf.pid, None);
        assert_eq!(inf.state, ExecutionState::NotStarted);
        assert_eq!(inf.display, "Process 1");
        assert!(inf.threads.is_empty());
        assert!(inf.modules.is_empty());
        assert!(!inf.synced);
    }

    #[test]
    fn test_inferior_with_pid() {
        let inf = GdbInferiorProcess::new(1).with_pid(1234);
        assert_eq!(inf.pid, Some(1234));
    }

    #[test]
    fn test_inferior_trace_paths() {
        let inf = GdbInferiorProcess::new(2);
        assert_eq!(inf.trace_path(), "Inferiors[2]");
        assert_eq!(inf.memory_path(), "Inferiors[2].Memory");
        assert_eq!(inf.modules_path(), "Inferiors[2].Modules");
        assert_eq!(inf.environment_path(), "Inferiors[2].Environment");
        assert_eq!(inf.breakpoints_path(), "Inferiors[2].Breakpoints");
    }

    #[test]
    fn test_inferior_compute_state_empty() {
        let inf = GdbInferiorProcess::new(1);
        // No threads: state is whatever is set
        assert_eq!(inf.compute_state(), ExecutionState::NotStarted);
    }

    #[test]
    fn test_inferior_compute_state_running() {
        let mut inf = GdbInferiorProcess::new(1);
        inf.add_thread(GdbThread::new(1).with_state(ExecutionState::Stopped));
        inf.add_thread(GdbThread::new(2).with_state(ExecutionState::Running));
        assert_eq!(inf.compute_state(), ExecutionState::Running);
    }

    #[test]
    fn test_inferior_compute_state_stopped() {
        let mut inf = GdbInferiorProcess::new(1);
        inf.add_thread(GdbThread::new(1).with_state(ExecutionState::Stopped));
        inf.add_thread(GdbThread::new(2).with_state(ExecutionState::Stopped));
        assert_eq!(inf.compute_state(), ExecutionState::Stopped);
    }

    #[test]
    fn test_inferior_compute_state_all_exited() {
        let mut inf = GdbInferiorProcess::new(1);
        inf.add_thread(GdbThread::new(1).with_state(ExecutionState::Exited));
        inf.add_thread(GdbThread::new(2).with_state(ExecutionState::Exited));
        assert_eq!(inf.compute_state(), ExecutionState::Exited);
    }

    #[test]
    fn test_inferior_thread_management() {
        let mut inf = GdbInferiorProcess::new(1);
        inf.add_thread(GdbThread::new(1));
        inf.add_thread(GdbThread::new(3));
        assert_eq!(inf.thread_count(), 2);
        assert!(inf.get_thread(1).is_some());
        assert!(inf.get_thread(2).is_none());
        assert!(inf.get_thread(3).is_some());

        let removed = inf.remove_thread(1);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().num, 1);
        assert_eq!(inf.thread_count(), 1);
    }

    #[test]
    fn test_inferior_module_management() {
        let mut inf = GdbInferiorProcess::new(1);
        inf.add_module(ModuleInfo {
            name: "libc.so.6".to_string(),
            base: 0x7ffff7a00000,
            size: 0x1e6000,
            build_id: None,
            debug_path: None,
            load_path: None,
        });
        assert_eq!(inf.modules.len(), 1);

        // Replace same name
        inf.add_module(ModuleInfo {
            name: "libc.so.6".to_string(),
            base: 0x7ffff7c00000,
            size: 0x1e6000,
            build_id: None,
            debug_path: None,
            load_path: None,
        });
        assert_eq!(inf.modules.len(), 1);
        assert_eq!(inf.modules[0].base, 0x7ffff7c00000);

        inf.clear_modules();
        assert!(inf.modules.is_empty());
    }

    #[test]
    fn test_inferior_exit() {
        let mut inf = GdbInferiorProcess::new(1);
        inf.state = ExecutionState::Stopped;
        assert!(inf.is_alive());
        inf.set_exit(0);
        assert!(!inf.is_alive());
        assert_eq!(inf.exit_code, Some(0));
        assert_eq!(inf.state, ExecutionState::Exited);
    }

    #[test]
    fn test_inferior_build_trace_values() {
        let inf = GdbInferiorProcess::new(1);
        let values = inf.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "_state" && v == "NOT_STARTED"));
        assert!(values.iter().any(|(k, v)| k == "_display" && v == "Process 1"));
    }

    #[test]
    fn test_inferior_to_process_info() {
        let inf = GdbInferiorProcess::new(3);
        let info = inf.to_process_info();
        assert_eq!(info.id, 3);
    }

    #[test]
    fn test_inferior_selected_thread() {
        let mut inf = GdbInferiorProcess::new(1);
        assert!(inf.selected_thread().is_none());

        inf.add_thread(GdbThread::new(1).with_state(ExecutionState::Stopped));
        let sel = inf.selected_thread();
        assert!(sel.is_some());
        assert_eq!(sel.unwrap().num, 1);

        inf.add_thread(GdbThread::new(2).with_state(ExecutionState::Running));
        let sel = inf.selected_thread();
        assert!(sel.is_some());
        assert_eq!(sel.unwrap().num, 2); // Running thread preferred
    }

    #[test]
    fn test_inferior_mark_synced() {
        let mut inf = GdbInferiorProcess::new(1);
        assert!(!inf.synced);
        inf.mark_synced();
        assert!(inf.synced);
    }
}
