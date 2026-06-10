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
//! `put_threads`, `put_modules`, `put_regions`, `put_sections`, etc.).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::drgn_thread::DrgnThread;
use super::{DrgnModuleInfo, DrgnSectionInfo, DrgnSymbolInfo};
use crate::agents::{
    ExecutionState, MemoryRegion, ProcessInfo,
};

/// Memory page size used for quantization (matches Python `PAGE_SIZE`).
pub const PAGE_SIZE: u64 = 4096;

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
    /// Sections for relocatable modules, keyed by module base address.
    pub sections: BTreeMap<u64, Vec<DrgnSectionInfo>>,
    /// Whether this is a kernel debug session.
    pub is_kernel: bool,
    /// Whether this process has been synchronized to the trace.
    pub synced: bool,
    /// Kernel version string (for kernel debugging).
    pub kernel_version: Option<String>,
    /// Exit code, if the process has terminated.
    pub exit_code: Option<i32>,
    /// Whether this is the first record (controls initial environment/processes sync).
    pub first_record: bool,
    /// Set of visited (thread, frame) pairs since last stop, for dedup.
    pub visited_frames: Vec<(u32, u32)>,
    /// Whether modules have changed since last sync.
    pub modules_changed: bool,
    /// Whether memory regions have changed since last sync.
    pub regions_changed: bool,
    /// Whether threads have changed since last sync.
    pub threads_changed: bool,
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
            sections: BTreeMap::new(),
            is_kernel: false,
            synced: false,
            kernel_version: None,
            exit_code: None,
            first_record: true,
            visited_frames: Vec::new(),
            modules_changed: false,
            regions_changed: false,
            threads_changed: false,
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

    /// Get the trace path for a specific memory region.
    pub fn region_path(&self, start: u64) -> String {
        format!("Processes[{}].Memory[0x{:x}]", self.num, start)
    }

    /// Get the trace path for a specific module.
    pub fn module_path(&self, base: u64) -> String {
        format!("Processes[{}].Modules[0x{:x}]", self.num, base)
    }

    /// Get the trace path for a module's attributes.
    pub fn module_attributes_path(&self, base: u64) -> String {
        format!("Processes[{}].Modules[0x{:x}].Attributes", self.num, base)
    }

    /// Get the trace path for a module's sections container.
    pub fn module_sections_path(&self, base: u64) -> String {
        format!("Processes[{}].Modules[0x{:x}].Sections", self.num, base)
    }

    /// Get the trace path for a specific section within a module.
    pub fn section_path(&self, module_base: u64, section_name: &str) -> String {
        format!(
            "Processes[{}].Modules[0x{:x}].Sections[{}]",
            self.num, module_base, section_name
        )
    }

    /// Quantize an address range to page boundaries.
    pub fn quantize_pages(start: u64, end: u64) -> (u64, u64) {
        (
            start / PAGE_SIZE * PAGE_SIZE,
            (end + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE,
        )
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

    /// Find a module by its base address string (hex).
    pub fn find_module_by_base_str(&self, base_str: &str) -> Option<&DrgnModuleInfo> {
        self.modules.iter().find(|m| {
            format!("0x{:x}", m.base()) == base_str
        })
    }

    /// Clear all modules.
    pub fn clear_modules(&mut self) {
        self.modules.clear();
        self.sections.clear();
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

    /// Set sections for a relocatable module.
    pub fn set_module_sections(&mut self, module_base: u64, sections: Vec<DrgnSectionInfo>) {
        self.sections.insert(module_base, sections);
    }

    /// Get sections for a module by base address.
    pub fn get_module_sections(&self, module_base: u64) -> Option<&Vec<DrgnSectionInfo>> {
        self.sections.get(&module_base)
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
        let mut values = vec![
            ("_state".to_string(), state.as_trace_str().to_string()),
            ("_display".to_string(), self.display.clone()),
        ];
        if let Some(pid) = self.pid {
            values.push(("PID".to_string(), pid.to_string()));
        }
        values
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

    /// Build trace object key-value pairs for a memory region.
    pub fn build_region_values(region: &MemoryRegion) -> Vec<(String, String)> {
        vec![
            (
                "Range".to_string(),
                format!("0x{:x}:0x{:x}", region.base, region.base + region.size),
            ),
            ("Name".to_string(), region.object_file.clone()),
            (
                "_readable".to_string(),
                region.permissions.contains('r').to_string(),
            ),
            (
                "_writable".to_string(),
                region.permissions.contains('w').to_string(),
            ),
            (
                "_executable".to_string(),
                region.permissions.contains('x').to_string(),
            ),
            (
                "_display".to_string(),
                format!("0x{:x} {}", region.base, region.object_file),
            ),
        ]
    }

    /// Build trace object key-value pairs for a module.
    pub fn build_module_values(module: &DrgnModuleInfo) -> Vec<(String, String)> {
        let mut values = vec![
            (
                "Range".to_string(),
                format!("0x{:x}:0x{:x}", module.base(), module.base() + module.size()),
            ),
            ("Name".to_string(), module.name.clone()),
            (
                "_display".to_string(),
                format!("{:x} {}", module.base(), module.name),
            ),
        ];
        if let Some(ref bid) = module.build_id {
            values.push(("BuildId".to_string(), bid.clone()));
        }
        if let Some(ref dp) = module.debug_file_path {
            values.push(("DebugPath".to_string(), dp.clone()));
        }
        if let Some(ref lp) = module.loaded_file_path {
            values.push(("LoadPath".to_string(), lp.clone()));
        }
        values
    }

    /// Build trace object key-value pairs for a module's attributes.
    pub fn build_module_attribute_values(module: &DrgnModuleInfo) -> Vec<(String, String)> {
        let mut values = Vec::new();
        if let Some(ref bid) = module.build_id {
            values.push(("BuildId".to_string(), bid.clone()));
        }
        if let Some(bias) = module.debug_file_bias {
            values.push(("DebugBias".to_string(), format!("0x{:x}", bias)));
        }
        if let Some(ref dp) = module.debug_file_path {
            values.push(("DebugPath".to_string(), dp.clone()));
        }
        if let Some(ref ds) = module.debug_file_status {
            values.push(("DebugStatus".to_string(), ds.clone()));
        }
        if let Some(bias) = module.loaded_file_bias {
            values.push(("LoadBias".to_string(), format!("0x{:x}", bias)));
        }
        if let Some(ref lp) = module.loaded_file_path {
            values.push(("LoadPath".to_string(), lp.clone()));
        }
        if let Some(ref ls) = module.loaded_file_status {
            values.push(("LoadStatus".to_string(), ls.clone()));
        }
        values
    }

    /// Build trace object key-value pairs for a section within a relocatable module.
    pub fn build_section_values(section: &DrgnSectionInfo) -> Vec<(String, String)> {
        vec![
            ("Address".to_string(), format!("0x{:x}", section.address)),
            ("Size".to_string(), format!("0x{:x}", section.size)),
            (
                "_display".to_string(),
                format!("{} 0x{:x}", section.name, section.address),
            ),
        ]
    }

    /// Build trace object key-value pairs for a symbol.
    pub fn build_symbol_values(symbol: &DrgnSymbolInfo) -> Vec<(String, String)> {
        vec![
            ("Address".to_string(), format!("0x{:x}", symbol.address)),
            ("Size".to_string(), format!("0x{:x}", symbol.size)),
            (
                "_display".to_string(),
                format!("{} 0x{:x}", symbol.name, symbol.address),
            ),
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

    /// Clear the visited frames set (called at start of each stop).
    pub fn clear_visited(&mut self) {
        self.visited_frames.clear();
    }

    /// Record a (thread, frame) pair as visited.
    pub fn record_visited(&mut self, thread_num: u32, frame_level: u32) {
        let pair = (thread_num, frame_level);
        if !self.visited_frames.contains(&pair) {
            self.visited_frames.push(pair);
        }
    }

    /// Check if a (thread, frame) pair has been visited.
    pub fn is_visited(&self, thread_num: u32, frame_level: u32) -> bool {
        self.visited_frames.contains(&(thread_num, frame_level))
    }

    /// Reset the first_record flag.
    pub fn mark_recorded(&mut self) {
        self.first_record = false;
    }

    /// Check if modules need re-syncing.
    pub fn needs_module_sync(&self) -> bool {
        self.first_record || self.modules_changed
    }

    /// Check if regions need re-syncing.
    pub fn needs_region_sync(&self) -> bool {
        self.first_record || self.regions_changed || self.modules_changed
    }

    /// Mark modules as changed.
    pub fn mark_modules_changed(&mut self) {
        self.modules_changed = true;
    }

    /// Mark regions as changed.
    pub fn mark_regions_changed(&mut self) {
        self.regions_changed = true;
    }

    /// Mark threads as changed.
    pub fn mark_threads_changed(&mut self) {
        self.threads_changed = true;
    }

    /// Clear the changed flags after a sync.
    pub fn clear_changed_flags(&mut self) {
        self.modules_changed = false;
        self.regions_changed = false;
        self.threads_changed = false;
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
        assert_eq!(p.exit_code, None);
        assert!(p.first_record);
        assert!(p.visited_frames.is_empty());
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
    fn test_process_module_paths() {
        let p = DrgnInferiorProcess::new(0);
        assert_eq!(p.module_path(0xffffffffa0000000), "Processes[0].Modules[0xffffffffa0000000]");
        assert_eq!(
            p.module_attributes_path(0xffffffffa0000000),
            "Processes[0].Modules[0xffffffffa0000000].Attributes"
        );
        assert_eq!(
            p.module_sections_path(0xffffffffa0000000),
            "Processes[0].Modules[0xffffffffa0000000].Sections"
        );
        assert_eq!(
            p.section_path(0xffffffffa0000000, ".text"),
            "Processes[0].Modules[0xffffffffa0000000].Sections[.text]"
        );
    }

    #[test]
    fn test_process_region_path() {
        let p = DrgnInferiorProcess::new(0);
        assert_eq!(p.region_path(0x7f0000), "Processes[0].Memory[0x7f0000]");
    }

    #[test]
    fn test_quantize_pages() {
        let (start, end) = DrgnInferiorProcess::quantize_pages(0x1234, 0x5678);
        assert_eq!(start, 0x1000);
        assert_eq!(end, 0x6000);

        let (start, end) = DrgnInferiorProcess::quantize_pages(0x1000, 0x2000);
        assert_eq!(start, 0x1000);
        assert_eq!(end, 0x2000);
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
    fn test_process_find_module_by_base_str() {
        let mut p = DrgnInferiorProcess::new(0);
        let m = DrgnModuleInfo {
            name: "virtio_net".to_string(),
            address_range: (0xffffffffa0000000, 0xffffffffa0010000),
            build_id: None,
            debug_file_bias: None,
            debug_file_path: None,
            debug_file_status: None,
            loaded_file_bias: None,
            loaded_file_path: None,
            loaded_file_status: None,
            is_relocatable: true,
        };
        p.add_module(m);
        assert!(p.find_module_by_base_str("0xffffffffa0000000").is_some());
        assert!(p.find_module_by_base_str("0xffffffffb0000000").is_none());
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
    fn test_process_sections() {
        let mut p = DrgnInferiorProcess::new(0);
        let sections = vec![
            DrgnSectionInfo { name: ".text".to_string(), address: 0xffffffffa0000000, size: 0x5000 },
            DrgnSectionInfo { name: ".data".to_string(), address: 0xffffffffa0005000, size: 0x1000 },
        ];
        p.set_module_sections(0xffffffffa0000000, sections);
        assert!(p.get_module_sections(0xffffffffa0000000).is_some());
        assert_eq!(p.get_module_sections(0xffffffffa0000000).unwrap().len(), 2);
        assert!(p.get_module_sections(0xffffffffb0000000).is_none());
    }

    #[test]
    fn test_process_build_trace_values() {
        let p = DrgnInferiorProcess::new(0);
        let values = p.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "_state" && v == "NOT_STARTED"));
        assert!(values.iter().any(|(k, v)| k == "_display" && v == "Process 0"));
    }

    #[test]
    fn test_process_build_trace_values_with_pid() {
        let p = DrgnInferiorProcess::new(0).with_pid(1234);
        let values = p.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "PID" && v == "1234"));
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
    fn test_process_build_region_values() {
        let region = MemoryRegion {
            base: 0x7f0000,
            size: 0x1000,
            offset: 0,
            permissions: "rwxp".to_string(),
            object_file: "[stack]".to_string(),
        };
        let values = DrgnInferiorProcess::build_region_values(&region);
        assert!(values.iter().any(|(k, v)| k == "_readable" && v == "true"));
        assert!(values.iter().any(|(k, v)| k == "_writable" && v == "true"));
        assert!(values.iter().any(|(k, v)| k == "_executable" && v == "true"));
    }

    #[test]
    fn test_process_build_module_values() {
        let m = DrgnModuleInfo {
            name: "virtio_net".to_string(),
            address_range: (0xffffffffa0000000, 0xffffffffa0010000),
            build_id: Some("abc123".to_string()),
            debug_file_bias: None,
            debug_file_path: Some("/usr/lib/debug/...".to_string()),
            debug_file_status: None,
            loaded_file_bias: None,
            loaded_file_path: Some("/lib/modules/5.15.0/...".to_string()),
            loaded_file_status: None,
            is_relocatable: true,
        };
        let values = DrgnInferiorProcess::build_module_values(&m);
        assert!(values.iter().any(|(k, v)| k == "BuildId" && v == "abc123"));
        assert!(values.iter().any(|(k, _v)| k == "DebugPath"));
        assert!(values.iter().any(|(k, _v)| k == "LoadPath"));
    }

    #[test]
    fn test_process_build_module_attribute_values() {
        let m = DrgnModuleInfo {
            name: "virtio_net".to_string(),
            address_range: (0xffffffffa0000000, 0xffffffffa0010000),
            build_id: Some("abc123".to_string()),
            debug_file_bias: Some(0x1000),
            debug_file_path: Some("/usr/lib/debug/...".to_string()),
            debug_file_status: Some("found".to_string()),
            loaded_file_bias: Some(0x2000),
            loaded_file_path: Some("/lib/modules/5.15.0/...".to_string()),
            loaded_file_status: Some("loaded".to_string()),
            is_relocatable: true,
        };
        let values = DrgnInferiorProcess::build_module_attribute_values(&m);
        assert!(values.iter().any(|(k, _)| k == "BuildId"));
        assert!(values.iter().any(|(k, _)| k == "DebugBias"));
        assert!(values.iter().any(|(k, _)| k == "DebugStatus"));
        assert!(values.iter().any(|(k, _)| k == "LoadBias"));
        assert!(values.iter().any(|(k, _)| k == "LoadStatus"));
    }

    #[test]
    fn test_process_build_section_values() {
        let s = DrgnSectionInfo {
            name: ".text".to_string(),
            address: 0xffffffffa0000000,
            size: 0x5000,
        };
        let values = DrgnInferiorProcess::build_section_values(&s);
        assert!(values.iter().any(|(k, v)| k == "Address" && v == "0xffffffffa0000000"));
        assert!(values.iter().any(|(k, v)| k == "Size" && v == "0x5000"));
    }

    #[test]
    fn test_process_build_symbol_values() {
        let s = super::super::DrgnSymbolInfo {
            name: "do_sys_open".to_string(),
            address: 0xffffffff81234567,
            size: 0x100,
        };
        let values = DrgnInferiorProcess::build_symbol_values(&s);
        assert!(values.iter().any(|(k, _)| k == "Address"));
        assert!(values.iter().any(|(k, _)| k == "Size"));
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
    fn test_process_exit() {
        let mut p = DrgnInferiorProcess::new(0);
        p.state = ExecutionState::Stopped;
        assert!(p.is_alive());
        p.set_exit(0);
        assert!(!p.is_alive());
        assert_eq!(p.exit_code, Some(0));
        assert_eq!(p.state, ExecutionState::Exited);
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

    #[test]
    fn test_process_visited_tracking() {
        let mut p = DrgnInferiorProcess::new(0);
        assert!(!p.is_visited(0, 0));
        p.record_visited(0, 0);
        assert!(p.is_visited(0, 0));
        assert!(!p.is_visited(0, 1));
        p.record_visited(0, 1);
        assert!(p.is_visited(0, 1));
        p.clear_visited();
        assert!(!p.is_visited(0, 0));
    }

    #[test]
    fn test_process_changed_flags() {
        let mut p = DrgnInferiorProcess::new(0);
        // first_record is true by default, so needs_module_sync returns true
        assert!(p.needs_module_sync());
        assert!(p.needs_region_sync());
        p.mark_recorded();
        assert!(!p.needs_module_sync());
        assert!(!p.needs_region_sync());

        p.mark_modules_changed();
        assert!(p.needs_module_sync());
        assert!(p.needs_region_sync());

        p.clear_changed_flags();
        assert!(!p.needs_module_sync());
        assert!(!p.needs_region_sync());
    }
}
