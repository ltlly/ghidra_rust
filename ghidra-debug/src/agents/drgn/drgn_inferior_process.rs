//! drgn process representation.
//!
//! Models a drgn "process" as a debuggee. In drgn, the debugged target
//! (kernel or userspace) is represented as a process with threads,
//! modules, and memory regions.
//!
//! This corresponds to the `Processes[N]` node in the Ghidra trace
//! object tree and maps to `TraceProcess` on the model side.
//!
//! Ported from Ghidra's `Debugger-agent-drgn` Python commands (`put_processes`,
//! `put_threads`, `put_modules`, etc.).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::drgn_thread::DrgnThread;
use super::{DrgnModuleInfo, DrgnSymbolInfo};
use crate::agents::{
    ExecutionState, MemoryRegion, ProcessInfo,
};

/// A drgn debuggee process.
///
/// For kernel debugging, this represents the kernel itself (PID 0).
/// For userspace debugging, this represents the target process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrgnInferiorProcess {
    /// Process number (0-based for drgn).
    pub num: u32,
    /// Process ID assigned by the OS, if known.
    pub pid: Option<u64>,
    /// Current execution state.
    pub state: ExecutionState,
    /// Display name.
    pub display: String,
    /// Threads within this process, keyed by thread number.
    pub threads: BTreeMap<u32, DrgnThread>,
    /// Loaded modules (kernel modules or shared libraries).
    pub modules: Vec<DrgnModuleInfo>,
    /// Memory regions (mapped address ranges).
    pub memory_regions: Vec<MemoryRegion>,
    /// Symbols loaded from the target.
    pub symbols: Vec<DrgnSymbolInfo>,
    /// Whether this is a kernel debug session.
    pub is_kernel: bool,
    /// Whether this process has been synchronized to the trace.
    pub synced: bool,
    /// Kernel version string (for kernel debugging).
    pub kernel_version: Option<String>,
}

impl DrgnInferiorProcess {
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
            symbols: Vec::new(),
            is_kernel: false,
            synced: false,
            kernel_version: None,
        }
    }

    /// Create a kernel process.
    pub fn kernel(num: u32) -> Self {
        Self {
            num,
            pid: Some(0),
            state: ExecutionState::Running,
            display: "Kernel".to_string(),
            is_kernel: true,
            ..Self::new(num)
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

    /// Set the kernel version.
    pub fn with_kernel_version(mut self, version: impl Into<String>) -> Self {
        self.kernel_version = Some(version.into());
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

    /// Get the trace path for this process's symbols container.
    pub fn symbols_path(&self) -> String {
        format!("Processes[{}].Symbols", self.num)
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
    pub fn add_thread(&mut self, thread: DrgnThread) {
        self.threads.insert(thread.num, thread);
    }

    /// Remove a thread by number.
    pub fn remove_thread(&mut self, thread_num: u32) -> Option<DrgnThread> {
        self.threads.remove(&thread_num)
    }

    /// Get a thread by number.
    pub fn get_thread(&self, thread_num: u32) -> Option<&DrgnThread> {
        self.threads.get(&thread_num)
    }

    /// Get a mutable reference to a thread by number.
    pub fn get_thread_mut(&mut self, thread_num: u32) -> Option<&mut DrgnThread> {
        self.threads.get_mut(&thread_num)
    }

    /// Add a module to this process.
    ///
    /// If a module with the same name already exists, it is replaced.
    pub fn add_module(&mut self, module: DrgnModuleInfo) {
        self.modules.retain(|m| m.name != module.name);
        self.modules.push(module);
    }

    /// Remove a module by name.
    pub fn remove_module(&mut self, name: &str) -> Option<DrgnModuleInfo> {
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
    /// If a region with the same base address already exists, it is replaced.
    pub fn add_memory_region(&mut self, region: MemoryRegion) {
        self.memory_regions.retain(|r| r.base != region.base);
        self.memory_regions.push(region);
    }

    /// Clear all memory regions.
    pub fn clear_memory_regions(&mut self) {
        self.memory_regions.clear();
    }

    /// Add a symbol.
    ///
    /// If a symbol with the same name already exists, it is replaced.
    pub fn add_symbol(&mut self, symbol: DrgnSymbolInfo) {
        self.symbols.retain(|s| s.name != symbol.name);
        self.symbols.push(symbol);
    }

    /// Clear all symbols.
    pub fn clear_symbols(&mut self) {
        self.symbols.clear();
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
            ("Debugger".to_string(), "drgn".to_string()),
            ("Arch".to_string(), arch.to_string()),
            ("OS".to_string(), os.to_string()),
            ("Endian".to_string(), endian.to_string()),
        ];
        if let Some(ref kv) = self.kernel_version {
            values.push(("KernelVersion".to_string(), kv.clone()));
        }
        values
    }

    /// Mark this process as synchronized.
    pub fn mark_synced(&mut self) {
        self.synced = true;
    }

    /// Check if the process is alive (not exited/not started).
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
    pub fn selected_thread(&self) -> Option<&DrgnThread> {
        self.threads
            .values()
            .find(|t| t.state == ExecutionState::Running)
            .or_else(|| self.threads.values().find(|t| t.state == ExecutionState::Stopped))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::DrgnModuleInfo;

    #[test]
    fn test_process_new() {
        let p = DrgnInferiorProcess::new(0);
        assert_eq!(p.num, 0);
        assert_eq!(p.pid, None);
        assert_eq!(p.state, ExecutionState::NotStarted);
        assert_eq!(p.display, "Process 0");
        assert!(p.threads.is_empty());
        assert!(p.modules.is_empty());
        assert!(!p.is_kernel);
        assert!(!p.synced);
    }

    #[test]
    fn test_process_kernel() {
        let p = DrgnInferiorProcess::kernel(0);
        assert_eq!(p.num, 0);
        assert_eq!(p.pid, Some(0));
        assert!(p.is_kernel);
        assert_eq!(p.display, "Kernel");
    }

    #[test]
    fn test_process_with_pid() {
        let p = DrgnInferiorProcess::new(1).with_pid(1234);
        assert_eq!(p.pid, Some(1234));
    }

    #[test]
    fn test_process_trace_paths() {
        let p = DrgnInferiorProcess::new(0);
        assert_eq!(p.trace_path(), "Processes[0]");
        assert_eq!(p.memory_path(), "Processes[0].Memory");
        assert_eq!(p.modules_path(), "Processes[0].Modules");
        assert_eq!(p.environment_path(), "Processes[0].Environment");
        assert_eq!(p.symbols_path(), "Processes[0].Symbols");
    }

    #[test]
    fn test_process_compute_state_empty() {
        let p = DrgnInferiorProcess::new(0);
        assert_eq!(p.compute_state(), ExecutionState::NotStarted);
    }

    #[test]
    fn test_process_compute_state_running() {
        let mut p = DrgnInferiorProcess::new(0);
        p.add_thread(DrgnThread::new(0).with_state(ExecutionState::Stopped));
        p.add_thread(DrgnThread::new(1).with_state(ExecutionState::Running));
        assert_eq!(p.compute_state(), ExecutionState::Running);
    }

    #[test]
    fn test_process_compute_state_stopped() {
        let mut p = DrgnInferiorProcess::new(0);
        p.add_thread(DrgnThread::new(0).with_state(ExecutionState::Stopped));
        p.add_thread(DrgnThread::new(1).with_state(ExecutionState::Stopped));
        assert_eq!(p.compute_state(), ExecutionState::Stopped);
    }

    #[test]
    fn test_process_compute_state_all_exited() {
        let mut p = DrgnInferiorProcess::new(0);
        p.add_thread(DrgnThread::new(0).with_state(ExecutionState::Exited));
        p.add_thread(DrgnThread::new(1).with_state(ExecutionState::Exited));
        assert_eq!(p.compute_state(), ExecutionState::Exited);
    }

    #[test]
    fn test_process_thread_management() {
        let mut p = DrgnInferiorProcess::new(0);
        p.add_thread(DrgnThread::new(0));
        p.add_thread(DrgnThread::new(2));
        assert_eq!(p.thread_count(), 2);
        assert!(p.get_thread(0).is_some());
        assert!(p.get_thread(1).is_none());
        assert!(p.get_thread(2).is_some());

        let removed = p.remove_thread(0);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().num, 0);
        assert_eq!(p.thread_count(), 1);
    }

    #[test]
    fn test_process_module_management() {
        let mut p = DrgnInferiorProcess::new(0);
        let m = DrgnModuleInfo {
            name: "virtio_net".to_string(),
            address_range: (0xffffffffa0000000, 0xffffffffa0010000),
            build_id: Some("abc123".to_string()),
            debug_file_bias: None,
            debug_file_path: None,
            debug_file_status: None,
            loaded_file_bias: None,
            loaded_file_path: Some("/lib/modules/5.15.0/kernel/drivers/net/virtio_net.ko".to_string()),
            loaded_file_status: None,
            is_relocatable: true,
        };
        p.add_module(m);
        assert_eq!(p.modules.len(), 1);

        // Replace same name
        let m2 = DrgnModuleInfo {
            name: "virtio_net".to_string(),
            address_range: (0xffffffffa0020000, 0xffffffffa0030000),
            build_id: None,
            debug_file_bias: None,
            debug_file_path: None,
            debug_file_status: None,
            loaded_file_bias: None,
            loaded_file_path: None,
            loaded_file_status: None,
            is_relocatable: true,
        };
        p.add_module(m2);
        assert_eq!(p.modules.len(), 1);
        assert_eq!(p.modules[0].base(), 0xffffffffa0020000);

        p.clear_modules();
        assert!(p.modules.is_empty());
    }

    #[test]
    fn test_process_symbol_management() {
        let mut p = DrgnInferiorProcess::new(0);
        let s = super::super::DrgnSymbolInfo {
            name: "do_sys_open".to_string(),
            address: 0xffffffff81234567,
            size: 0x100,
        };
        p.add_symbol(s);
        assert_eq!(p.symbols.len(), 1);

        // Replace same name
        let s2 = super::super::DrgnSymbolInfo {
            name: "do_sys_open".to_string(),
            address: 0xffffffff81234600,
            size: 0x200,
        };
        p.add_symbol(s2);
        assert_eq!(p.symbols.len(), 1);
        assert_eq!(p.symbols[0].address, 0xffffffff81234600);

        p.clear_symbols();
        assert!(p.symbols.is_empty());
    }

    #[test]
    fn test_process_build_trace_values() {
        let p = DrgnInferiorProcess::new(0);
        let values = p.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "_state" && v == "NOT_STARTED"));
        assert!(values.iter().any(|(k, v)| k == "_display" && v == "Process 0"));
    }

    #[test]
    fn test_process_build_environment_values() {
        let p = DrgnInferiorProcess::kernel(0)
            .with_kernel_version("5.15.0");
        let values = p.build_environment_values("Linux", "Language.C", "little");
        assert!(values.iter().any(|(k, v)| k == "Debugger" && v == "drgn"));
        assert!(values.iter().any(|(k, v)| k == "KernelVersion" && v == "5.15.0"));
    }

    #[test]
    fn test_process_to_process_info() {
        let p = DrgnInferiorProcess::new(0);
        let info = p.to_process_info();
        assert_eq!(info.id, 0);
    }

    #[test]
    fn test_process_selected_thread() {
        let mut p = DrgnInferiorProcess::new(0);
        assert!(p.selected_thread().is_none());

        p.add_thread(DrgnThread::new(0).with_state(ExecutionState::Stopped));
        let sel = p.selected_thread();
        assert!(sel.is_some());
        assert_eq!(sel.unwrap().num, 0);

        p.add_thread(DrgnThread::new(1).with_state(ExecutionState::Running));
        let sel = p.selected_thread();
        assert!(sel.is_some());
        assert_eq!(sel.unwrap().num, 1); // Running thread preferred
    }

    #[test]
    fn test_process_mark_synced() {
        let mut p = DrgnInferiorProcess::new(0);
        assert!(!p.synced);
        p.mark_synced();
        assert!(p.synced);
    }

    #[test]
    fn test_process_is_alive() {
        let mut p = DrgnInferiorProcess::new(0);
        p.state = ExecutionState::Stopped;
        assert!(p.is_alive());
        p.state = ExecutionState::Running;
        assert!(p.is_alive());
        p.state = ExecutionState::Exited;
        assert!(!p.is_alive());
        p.state = ExecutionState::NotStarted;
        assert!(!p.is_alive());
    }
}
