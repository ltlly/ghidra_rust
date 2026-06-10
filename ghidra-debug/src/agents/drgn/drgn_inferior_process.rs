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
use std::collections::{BTreeMap, BTreeSet};

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
    /// Whether breakpoints have changed since last sync.
    pub breakpoints_changed: bool,
    /// Whether watches have changed since last sync.
    pub watches_changed: bool,
    /// Relocated sections for relocatable modules.
    pub relocated_sections: Vec<DrgnRelocatedSection>,
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
            breakpoints_changed: false,
            watches_changed: false,
            relocated_sections: Vec::new(),
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

    /// Find a module by name.
    pub fn find_module(&self, name: &str) -> Option<&DrgnModuleInfo> {
        self.modules.iter().find(|m| m.name == name)
    }

    /// Find a module by base address.
    pub fn find_module_by_base(&self, base: u64) -> Option<&DrgnModuleInfo> {
        self.modules.iter().find(|m| m.base() == base)
    }

    /// Find the module that contains the given address.
    pub fn find_module_containing(&self, address: u64) -> Option<&DrgnModuleInfo> {
        self.modules
            .iter()
            .find(|m| address >= m.base() && address < m.base() + m.size())
    }

    /// Get a mutable reference to a module by name.
    pub fn get_module_mut(&mut self, name: &str) -> Option<&mut DrgnModuleInfo> {
        self.modules.iter_mut().find(|m| m.name == name)
    }

    /// Get the number of modules.
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    /// Find a memory region by base address.
    pub fn find_region(&self, base: u64) -> Option<&MemoryRegion> {
        self.memory_regions.iter().find(|r| r.base == base)
    }

    /// Find the memory region that contains the given address.
    pub fn find_region_containing(&self, address: u64) -> Option<&MemoryRegion> {
        self.memory_regions
            .iter()
            .find(|r| address >= r.base && address < r.base + r.size)
    }

    /// Check if a given address falls within any mapped region.
    pub fn is_address_mapped(&self, addr: u64) -> bool {
        self.memory_regions
            .iter()
            .any(|r| addr >= r.base && addr < r.base + r.size)
    }

    /// Get the number of memory regions.
    pub fn memory_region_count(&self) -> usize {
        self.memory_regions.len()
    }

    /// Get a sorted list of all thread numbers.
    pub fn sorted_thread_numbers(&self) -> Vec<u32> {
        let mut nums: Vec<u32> = self.threads.keys().copied().collect();
        nums.sort();
        nums
    }

    /// Get a sorted list of all module base addresses.
    pub fn sorted_module_bases(&self) -> Vec<u64> {
        let mut bases: Vec<u64> = self.modules.iter().map(|m| m.base()).collect();
        bases.sort();
        bases
    }

    /// Update this process's state from its threads.
    pub fn refresh_state(&mut self) {
        self.state = self.compute_state();
    }

    /// Get all running thread numbers.
    pub fn running_thread_numbers(&self) -> Vec<u32> {
        self.threads
            .iter()
            .filter(|(_, t)| t.state == ExecutionState::Running)
            .map(|(&num, _)| num)
            .collect()
    }

    /// Get all stopped thread numbers.
    pub fn stopped_thread_numbers(&self) -> Vec<u32> {
        self.threads
            .iter()
            .filter(|(_, t)| t.state == ExecutionState::Stopped)
            .map(|(&num, _)| num)
            .collect()
    }

    /// Count the total number of stack frames across all threads.
    pub fn total_frame_count(&self) -> usize {
        self.threads.values().map(|t| t.frame_count()).sum()
    }

    /// Check if the breakpoints dirty flag is set.
    pub fn needs_breakpoint_sync(&self) -> bool {
        self.breakpoints_changed
    }

    /// Mark breakpoints as changed.
    pub fn mark_breakpoints_changed(&mut self) {
        self.breakpoints_changed = true;
    }

    /// Check if watches dirty flag is set.
    pub fn needs_watch_sync(&self) -> bool {
        self.watches_changed
    }

    /// Mark watches as changed.
    pub fn mark_watches_changed(&mut self) {
        self.watches_changed = true;
    }

    /// Whether any child has changed since last sync.
    pub fn has_any_changes(&self) -> bool {
        self.modules_changed
            || self.regions_changed
            || self.threads_changed
            || self.breakpoints_changed
            || self.watches_changed
    }
}

/// Snapshot descriptor for trace recording.
///
/// Ported from the Python `snapshot()` calls in `commands.py` and `hooks.py`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrgnSnapshot {
    /// Snapshot ID (sequential).
    pub id: u64,
    /// Description (e.g., "Stopped", "Continued").
    pub description: String,
    /// Timestamp (unix epoch millis, if available).
    pub timestamp: Option<u64>,
}

impl DrgnSnapshot {
    /// Create a new snapshot.
    pub fn new(id: u64, description: impl Into<String>) -> Self {
        Self {
            id,
            description: description.into(),
            timestamp: None,
        }
    }

    /// Set the timestamp.
    pub fn with_timestamp(mut self, ts: u64) -> Self {
        self.timestamp = Some(ts);
        self
    }
}

/// Per-process synchronization state, ported from Python `ProcessState` in hooks.py.
///
/// Tracks what has changed since the last stop, what has already been synced
/// (visited), and the snapshot history for this process.
#[derive(Debug, Clone)]
pub struct DrgnProcessSyncState {
    /// Whether this is the first recording for this process.
    pub first: bool,
    /// Whether threads need re-sync.
    pub threads_dirty: bool,
    /// Whether modules need re-sync.
    pub modules_dirty: bool,
    /// Whether regions need re-sync.
    pub regions_dirty: bool,
    /// Whether breakpoints need re-sync.
    pub breaks_dirty: bool,
    /// Whether watches need re-sync.
    pub watches_dirty: bool,
    /// Visited (thread_num, frame_level) pairs since last stop.
    pub visited: BTreeSet<(u32, u32)>,
    /// Snapshots recorded for this process.
    pub snapshots: Vec<DrgnSnapshot>,
    /// Next snapshot ID.
    next_snap_id: u64,
}

impl Default for DrgnProcessSyncState {
    fn default() -> Self {
        Self {
            first: true,
            threads_dirty: false,
            modules_dirty: false,
            regions_dirty: false,
            breaks_dirty: false,
            watches_dirty: false,
            visited: BTreeSet::new(),
            snapshots: Vec::new(),
            next_snap_id: 0,
        }
    }
}

impl DrgnProcessSyncState {
    /// Create a new sync state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark as no longer first recording.
    pub fn mark_recorded(&mut self) {
        self.first = false;
    }

    /// Clear visited state (called when a new stop occurs).
    pub fn clear_visited(&mut self) {
        self.visited.clear();
    }

    /// Record a visit to a thread/frame combination.
    pub fn record_visit(&mut self, thread_num: u32, frame_level: u32) {
        self.visited.insert((thread_num, frame_level));
    }

    /// Check if a thread/frame has been visited.
    pub fn is_visited(&self, thread_num: u32, frame_level: u32) -> bool {
        self.visited.contains(&(thread_num, frame_level))
    }

    /// Check if a thread has any visited frames.
    pub fn thread_visited(&self, thread_num: u32) -> bool {
        self.visited.iter().any(|(t, _)| *t == thread_num)
    }

    /// Create a new snapshot.
    pub fn create_snapshot(&mut self, description: impl Into<String>) -> &DrgnSnapshot {
        let snap = DrgnSnapshot::new(self.next_snap_id, description);
        self.next_snap_id += 1;
        self.snapshots.push(snap);
        self.snapshots.last().unwrap()
    }

    /// Mark threads as dirty (need re-sync).
    pub fn mark_threads_dirty(&mut self) {
        self.threads_dirty = true;
    }

    /// Mark modules as dirty.
    pub fn mark_modules_dirty(&mut self) {
        self.modules_dirty = true;
    }

    /// Mark regions as dirty.
    pub fn mark_regions_dirty(&mut self) {
        self.regions_dirty = true;
    }

    /// Mark breakpoints as dirty.
    pub fn mark_breaks_dirty(&mut self) {
        self.breaks_dirty = true;
    }

    /// Mark watches as dirty.
    pub fn mark_watches_dirty(&mut self) {
        self.watches_dirty = true;
    }

    /// Consume the threads dirty flag (returns true if was dirty).
    pub fn take_threads_dirty(&mut self) -> bool {
        let dirty = self.threads_dirty;
        self.threads_dirty = false;
        dirty
    }

    /// Consume the modules dirty flag.
    pub fn take_modules_dirty(&mut self) -> bool {
        let dirty = self.modules_dirty;
        self.modules_dirty = false;
        dirty
    }

    /// Consume the regions dirty flag.
    pub fn take_regions_dirty(&mut self) -> bool {
        let dirty = self.regions_dirty;
        self.regions_dirty = false;
        dirty
    }

    /// Consume the breakpoints dirty flag.
    pub fn take_breaks_dirty(&mut self) -> bool {
        let dirty = self.breaks_dirty;
        self.breaks_dirty = false;
        dirty
    }

    /// Whether anything has changed since the last sync.
    pub fn has_dirty(&self) -> bool {
        self.first
            || self.threads_dirty
            || self.modules_dirty
            || self.regions_dirty
            || self.breaks_dirty
            || self.watches_dirty
    }
}

/// Tracks the global convenience variables for the drgn agent session.
///
/// Ported from Python `util.py` convenience variable map. These variables
/// control agent behavior such as the Ghidra language/compiler selection
/// and the selected process/thread/frame.
#[derive(Debug, Clone)]
pub struct DrgnConvenienceState {
    /// Currently selected process ID.
    pub selected_pid: i64,
    /// Currently selected thread ID.
    pub selected_tid: i64,
    /// Currently selected frame level.
    pub selected_level: i64,
    /// Variable map for other convenience variables.
    pub variables: BTreeMap<String, String>,
}

impl Default for DrgnConvenienceState {
    fn default() -> Self {
        Self {
            selected_pid: -1,
            selected_tid: -1,
            selected_level: -1,
            variables: BTreeMap::new(),
        }
    }
}

impl DrgnConvenienceState {
    /// Create a new convenience state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Select a process.
    pub fn select_process(&mut self, pid: i64) {
        self.selected_pid = pid;
    }

    /// Select a thread.
    pub fn select_thread(&mut self, tid: i64) {
        self.selected_tid = tid;
    }

    /// Select a frame.
    pub fn select_frame(&mut self, level: i64) {
        self.selected_level = level;
    }

    /// Get the selected process, or None if none selected.
    pub fn selected_process(&self) -> Option<u32> {
        if self.selected_pid >= 0 {
            Some(self.selected_pid as u32)
        } else {
            None
        }
    }

    /// Get the selected thread, or None if none selected.
    pub fn selected_thread(&self) -> Option<u32> {
        if self.selected_tid >= 0 {
            Some(self.selected_tid as u32)
        } else {
            None
        }
    }

    /// Get the selected frame, or None if none selected.
    pub fn selected_frame(&self) -> Option<u32> {
        if self.selected_level >= 0 {
            Some(self.selected_level as u32)
        } else {
            None
        }
    }

    /// Get a convenience variable.
    pub fn get_variable(&self, key: &str) -> Option<&str> {
        self.variables.get(key).map(|s| s.as_str())
    }

    /// Set a convenience variable.
    pub fn set_variable(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.variables.insert(key.into(), value.into());
    }

    /// Reset all state to defaults.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// An available process entry for the `Sessions[0].Available` tree.
///
/// This represents a process visible on the system, not necessarily being debugged.
/// Ported from the `put_processes` pattern in `commands.py`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailableProcess {
    /// Process ID.
    pub pid: u64,
    /// Process name.
    pub name: String,
}

impl AvailableProcess {
    /// Create a new available process entry.
    pub fn new(pid: u64, name: impl Into<String>) -> Self {
        Self {
            pid,
            name: name.into(),
        }
    }

    /// Build the trace path for this available process.
    pub fn trace_path(&self) -> String {
        format!("Sessions[0].Available[{}]", self.pid)
    }

    /// Build trace object key-value pairs.
    pub fn build_trace_values(&self) -> Vec<(String, String)> {
        vec![
            ("PID".to_string(), format!("{}", self.pid)),
            ("Name".to_string(), self.name.clone()),
            (
                "_display".to_string(),
                format!("{} {}", self.pid, self.name),
            ),
        ]
    }
}

/// A local variable within a stack frame.
///
/// Ported from Python `put_locals()` in `commands.py` which reads
/// `StackFrame.locals()` and `StackFrame[key]` to populate the
/// `Processes[N].Threads[M].Stack[L].Locals` container.
///
/// Each local variable has a name, a drgn type, a kind (parameter,
/// local, global, etc.), and an optional address and display value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrgnLocalVariable {
    /// Variable name.
    pub name: String,
    /// Type name as a string (e.g., "struct task_struct *").
    pub type_name: String,
    /// Kind of variable.
    pub kind: DrgnVariableKind,
    /// Address of the variable in memory, if addressable.
    pub address: Option<u64>,
    /// Display value (stringified value).
    pub display_value: String,
    /// Whether the value is absent (optimized out).
    pub is_absent: bool,
}

impl DrgnLocalVariable {
    /// Create a new local variable.
    pub fn new(
        name: impl Into<String>,
        type_name: impl Into<String>,
        kind: DrgnVariableKind,
        display_value: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            type_name: type_name.into(),
            kind,
            address: None,
            display_value: display_value.into(),
            is_absent: false,
        }
    }

    /// Set the address.
    pub fn with_address(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    /// Mark as absent (optimized out).
    pub fn with_absent(mut self, absent: bool) -> Self {
        self.is_absent = absent;
        self
    }

    /// Get the trace path for this local variable.
    pub fn trace_path(&self, process_num: u32, thread_num: u32, frame_level: u32) -> String {
        format!(
            "Processes[{}].Threads[{}].Stack[{}].Locals.{}",
            process_num, thread_num, frame_level, self.name
        )
    }

    /// Build trace object key-value pairs.
    ///
    /// Matches the Python `put_object()` output in `commands.py`.
    pub fn build_trace_values(&self) -> Vec<(String, String)> {
        let mut values = vec![
            (
                "_display".to_string(),
                format!("{} [{}:{}]", self.name, self.type_name, self.display_value),
            ),
            ("Kind".to_string(), self.kind.as_str().to_string()),
            ("Type".to_string(), self.type_name.clone()),
        ];
        if self.is_absent {
            values.push(("Value".to_string(), "<absent>".to_string()));
        } else {
            values.push(("Value".to_string(), self.display_value.clone()));
        }
        if let Some(addr) = self.address {
            values.push(("Address".to_string(), format!("0x{:x}", addr)));
        }
        values
    }
}

/// Kind of variable in a stack frame.
///
/// Ported from drgn's `TypeKind` and variable classification in
/// `commands.py` `put_object()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DrgnVariableKind {
    /// Function parameter.
    Parameter,
    /// Local variable.
    Local,
    /// Global variable.
    Global,
    /// Struct/union/class member.
    Member,
    /// Pointer type.
    Pointer,
    /// Typedef.
    Typedef,
    /// Primitive type (int, char, etc.).
    Primitive,
    /// Unknown or other.
    Other,
}

impl DrgnVariableKind {
    /// Get the string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Parameter => "parameter",
            Self::Local => "local",
            Self::Global => "global",
            Self::Member => "member",
            Self::Pointer => "pointer",
            Self::Typedef => "typedef",
            Self::Primitive => "primitive",
            Self::Other => "other",
        }
    }
}

/// Symbol binding attribute.
///
/// Ported from Python `put_symbols()` which reads `s.binding`
/// (e.g., `STB_GLOBAL`, `STB_LOCAL`, `STB_WEAK`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DrgnSymbolBinding {
    /// Local binding.
    Local,
    /// Global binding.
    Global,
    /// Weak binding.
    Weak,
    /// Other/unknown binding.
    Other,
}

impl DrgnSymbolBinding {
    /// Parse from drgn binding string.
    pub fn from_str(s: &str) -> Self {
        match s {
            "STB_LOCAL" | "LOCAL" => Self::Local,
            "STB_GLOBAL" | "GLOBAL" => Self::Global,
            "STB_WEAK" | "WEAK" => Self::Weak,
            _ => Self::Other,
        }
    }

    /// Get string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "LOCAL",
            Self::Global => "GLOBAL",
            Self::Weak => "WEAK",
            Self::Other => "OTHER",
        }
    }
}

/// Symbol kind/type.
///
/// Ported from Python `put_symbols()` which reads `s.kind`
/// (e.g., `STT_FUNC`, `STT_OBJECT`, `STT_NOTYPE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DrgnSymbolKind {
    /// Function symbol.
    Function,
    /// Data/object symbol.
    Object,
    /// Section symbol.
    Section,
    /// File symbol.
    File,
    /// No type.
    NoType,
    /// Other/unknown.
    Other,
}

impl DrgnSymbolKind {
    /// Parse from drgn kind string.
    pub fn from_str(s: &str) -> Self {
        match s {
            "STT_FUNC" | "FUNC" => Self::Function,
            "STT_OBJECT" | "OBJECT" => Self::Object,
            "STT_SECTION" | "SECTION" => Self::Section,
            "STT_FILE" | "FILE" => Self::File,
            "STT_NOTYPE" | "NOTYPE" => Self::NoType,
            _ => Self::Other,
        }
    }

    /// Get string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Function => "FUNC",
            Self::Object => "OBJECT",
            Self::Section => "SECTION",
            Self::File => "FILE",
            Self::NoType => "NOTYPE",
            Self::Other => "OTHER",
        }
    }
}

/// Enriched symbol information with binding and kind metadata.
///
/// Extends `DrgnSymbolInfo` with the binding and kind fields that
/// the Python `put_symbols()` reads from `s.binding` and `s.kind`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrgnEnrichedSymbol {
    /// Symbol name.
    pub name: String,
    /// Symbol address.
    pub address: u64,
    /// Symbol size.
    pub size: u64,
    /// Symbol binding (local, global, weak).
    pub binding: DrgnSymbolBinding,
    /// Symbol kind (function, object, etc.).
    pub kind: DrgnSymbolKind,
}

impl DrgnEnrichedSymbol {
    /// Create a new enriched symbol.
    pub fn new(
        name: impl Into<String>,
        address: u64,
        size: u64,
        binding: DrgnSymbolBinding,
        kind: DrgnSymbolKind,
    ) -> Self {
        Self {
            name: name.into(),
            address,
            size,
            binding,
            kind,
        }
    }

    /// Build trace object key-value pairs.
    ///
    /// Matches the Python `put_symbols()` output which includes
    /// Address, Size, Name, Binding, and Kind.
    pub fn build_trace_values(&self) -> Vec<(String, String)> {
        vec![
            ("Address".to_string(), format!("0x{:x}", self.address)),
            ("Size".to_string(), format!("0x{:x}", self.size)),
            ("Name".to_string(), self.name.clone()),
            ("Binding".to_string(), self.binding.as_str().to_string()),
            ("Kind".to_string(), self.kind.as_str().to_string()),
            (
                "_display".to_string(),
                format!("{} 0x{:x}", self.name, self.address),
            ),
            (
                "_short_display".to_string(),
                format!("0x{:x}", self.address),
            ),
        ]
    }
}

/// A memory and register mapper for translating drgn addresses to
/// Ghidra trace addresses.
///
/// Ported from Python `DefaultMemoryMapper` and `DefaultRegisterMapper`
/// in `arch.py`. The mapper translates process-local offsets into
/// Ghidra's address space model.
#[derive(Debug, Clone)]
pub struct DrgnMemoryMapper {
    /// Default address space name (typically "ram").
    pub default_space: String,
}

impl DrgnMemoryMapper {
    /// Create a new memory mapper with default space "ram".
    pub fn new() -> Self {
        Self {
            default_space: "ram".to_string(),
        }
    }

    /// Create a mapper with a specific default space.
    pub fn with_space(space: impl Into<String>) -> Self {
        Self {
            default_space: space.into(),
        }
    }

    /// Map a process offset to (base_space, address_space, offset).
    ///
    /// In drgn's simple model, the base space is always the default space.
    pub fn map(&self, _process_num: u32, offset: u64) -> (&str, u64) {
        (&self.default_space, offset)
    }

    /// Reverse map a Ghidra address back to a process offset.
    pub fn map_back(&self, _process_num: u32, space: &str, offset: u64) -> Option<u64> {
        if space == self.default_space {
            Some(offset)
        } else {
            None
        }
    }
}

impl Default for DrgnMemoryMapper {
    fn default() -> Self {
        Self::new()
    }
}

/// A register mapper for translating register names and values.
///
/// Ported from Python `DefaultRegisterMapper` in `arch.py`.
/// Handles byte order conversion for register values.
#[derive(Debug, Clone)]
pub struct DrgnRegisterMapper {
    /// Byte order for register values.
    pub byte_order: DrgnByteOrder,
}

/// Byte order for register values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DrgnByteOrder {
    /// Little-endian.
    Little,
    /// Big-endian.
    Big,
}

impl DrgnByteOrder {
    /// Convert to trace string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Little => "little",
            Self::Big => "big",
        }
    }
}

impl DrgnRegisterMapper {
    /// Create a register mapper.
    pub fn new(byte_order: DrgnByteOrder) -> Self {
        Self { byte_order }
    }

    /// Create a little-endian mapper.
    pub fn little_endian() -> Self {
        Self::new(DrgnByteOrder::Little)
    }

    /// Create a big-endian mapper.
    pub fn big_endian() -> Self {
        Self::new(DrgnByteOrder::Big)
    }

    /// Map a register name (identity in the default mapper).
    pub fn map_name(&self, _process_num: u32, name: &str) -> String {
        name.to_string()
    }

    /// Map a register name back (identity in the default mapper).
    pub fn map_name_back(&self, _process_num: u32, name: &str) -> String {
        name.to_string()
    }
}

impl Default for DrgnRegisterMapper {
    fn default() -> Self {
        Self::little_endian()
    }
}

/// Manages multiple drgn processes (the `PROGRAMS` dict from Python).
///
/// Ported from the Python `commands.py` `PROGRAMS` dictionary that maps
/// process IDs to `drgn.Program` instances. In the Rust port, this
/// manages `DrgnInferiorProcess` instances.
#[derive(Debug, Default)]
pub struct DrgnProcessManager {
    /// Active processes keyed by process number.
    pub processes: BTreeMap<u32, DrgnInferiorProcess>,
    /// Convenience state for selected process/thread/frame.
    pub convenience: DrgnConvenienceState,
    /// Memory mapper.
    pub memory_mapper: DrgnMemoryMapper,
    /// Register mapper.
    pub register_mapper: DrgnRegisterMapper,
}

impl DrgnProcessManager {
    /// Create a new process manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a process.
    pub fn add_process(&mut self, process: DrgnInferiorProcess) {
        let num = process.num;
        self.processes.insert(num, process);
    }

    /// Remove a process by number.
    pub fn remove_process(&mut self, num: u32) -> Option<DrgnInferiorProcess> {
        self.processes.remove(&num)
    }

    /// Get a process by number.
    pub fn get_process(&self, num: u32) -> Option<&DrgnInferiorProcess> {
        self.processes.get(&num)
    }

    /// Get a mutable reference to a process by number.
    pub fn get_process_mut(&mut self, num: u32) -> Option<&mut DrgnInferiorProcess> {
        self.processes.get_mut(&num)
    }

    /// Get the currently selected process.
    pub fn selected_process(&self) -> Option<&DrgnInferiorProcess> {
        self.convenience
            .selected_process()
            .and_then(|pid| self.processes.get(&pid))
    }

    /// Get a mutable reference to the currently selected process.
    pub fn selected_process_mut(&mut self) -> Option<&mut DrgnInferiorProcess> {
        let pid = self.convenience.selected_process()?;
        self.processes.get_mut(&pid)
    }

    /// Select a process and return it.
    pub fn select_process(&mut self, pid: i64) -> Option<&DrgnInferiorProcess> {
        self.convenience.select_process(pid);
        self.processes.get(&(pid as u32))
    }

    /// Select a thread within the current process.
    pub fn select_thread(&mut self, tid: i64) {
        self.convenience.select_thread(tid);
    }

    /// Select a frame level.
    pub fn select_frame(&mut self, level: i64) {
        self.convenience.select_frame(level);
    }

    /// Get all process numbers.
    pub fn process_numbers(&self) -> Vec<u32> {
        self.processes.keys().copied().collect()
    }

    /// Get the number of processes.
    pub fn process_count(&self) -> usize {
        self.processes.len()
    }

    /// Check if a process exists.
    pub fn has_process(&self, num: u32) -> bool {
        self.processes.contains_key(&num)
    }

    /// Mark all processes for module sync.
    pub fn mark_all_modules_changed(&mut self) {
        for p in self.processes.values_mut() {
            p.mark_modules_changed();
        }
    }

    /// Mark all processes for thread sync.
    pub fn mark_all_threads_changed(&mut self) {
        for p in self.processes.values_mut() {
            p.mark_threads_changed();
        }
    }

    /// Reset all state.
    pub fn reset(&mut self) {
        self.processes.clear();
        self.convenience.reset();
    }
}

/// drgn-specific module section with address information for relocatable modules.
///
/// For kernel modules (RelocatableModule in drgn), sections have relocated
/// addresses. This extends `DrgnSectionInfo` with the module base address
/// for proper trace path construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrgnRelocatedSection {
    /// Section name (e.g., ".text", ".data").
    pub name: String,
    /// Relocated section address.
    pub address: u64,
    /// Section size.
    pub size: u64,
    /// Parent module base address.
    pub module_base: u64,
}

impl DrgnRelocatedSection {
    /// Create a new relocated section.
    pub fn new(
        name: impl Into<String>,
        address: u64,
        size: u64,
        module_base: u64,
    ) -> Self {
        Self {
            name: name.into(),
            address,
            size,
            module_base,
        }
    }

    /// Get the module base formatted as hex.
    pub fn module_base_hex(&self) -> String {
        format!("0x{:x}", self.module_base)
    }

    /// Build the trace path for this section.
    pub fn trace_path(&self, process_num: u32) -> String {
        format!(
            "Processes[{}].Modules[0x{:x}].Sections[{}]",
            process_num, self.module_base, self.name
        )
    }

    /// Build trace object key-value pairs for this section.
    ///
    /// Matches the Python `put_sections` output.
    pub fn build_trace_values(&self) -> Vec<(String, String)> {
        vec![
            ("Address".to_string(), format!("0x{:x}", self.address)),
            ("Size".to_string(), format!("0x{:x}", self.size)),
            ("Name".to_string(), self.name.clone()),
            (
                "_display".to_string(),
                format!("{} 0x{:x}", self.name, self.address),
            ),
        ]
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

    #[test]
    fn test_process_find_module() {
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
        assert!(p.find_module("virtio_net").is_some());
        assert!(p.find_module("e1000").is_none());
        assert!(p.find_module_by_base(0xffffffffa0000000).is_some());
        assert!(p.find_module_containing(0xffffffffa0005000).is_some());
        assert!(p.find_module_containing(0x100000).is_none());
    }

    #[test]
    fn test_process_find_region() {
        let mut p = DrgnInferiorProcess::new(0);
        p.add_memory_region(MemoryRegion {
            base: 0x10000,
            size: 0x5000,
            offset: 0,
            permissions: "rw-".to_string(),
            object_file: "stack".to_string(),
        });
        assert!(p.find_region(0x10000).is_some());
        assert!(p.find_region_containing(0x12000).is_some());
        assert!(p.find_region_containing(0x20000).is_none());
        assert!(p.is_address_mapped(0x10000));
        assert!(p.is_address_mapped(0x14fff));
        assert!(!p.is_address_mapped(0x15000));
    }

    #[test]
    fn test_process_sorted_lists() {
        let mut p = DrgnInferiorProcess::new(0);
        p.add_thread(DrgnThread::new(3));
        p.add_thread(DrgnThread::new(1));
        p.add_thread(DrgnThread::new(2));
        assert_eq!(p.sorted_thread_numbers(), vec![1, 2, 3]);
    }

    #[test]
    fn test_process_thread_queries() {
        let mut p = DrgnInferiorProcess::new(0);
        p.add_thread(DrgnThread::new(0).with_state(ExecutionState::Running));
        p.add_thread(DrgnThread::new(1).with_state(ExecutionState::Stopped));
        p.add_thread(DrgnThread::new(2).with_state(ExecutionState::Running));
        assert_eq!(p.running_thread_numbers(), vec![0, 2]);
        assert_eq!(p.stopped_thread_numbers(), vec![1]);
        assert_eq!(p.total_frame_count(), 0);
    }

    #[test]
    fn test_process_refresh_state() {
        let mut p = DrgnInferiorProcess::new(0);
        p.add_thread(DrgnThread::new(0).with_state(ExecutionState::Running));
        p.add_thread(DrgnThread::new(1).with_state(ExecutionState::Stopped));
        p.refresh_state();
        assert_eq!(p.state, ExecutionState::Running);
    }

    #[test]
    fn test_process_breakpoint_watches_flags() {
        let mut p = DrgnInferiorProcess::new(0);
        assert!(!p.needs_breakpoint_sync());
        p.mark_breakpoints_changed();
        assert!(p.needs_breakpoint_sync());
        assert!(!p.needs_watch_sync());
        p.mark_watches_changed();
        assert!(p.needs_watch_sync());
        assert!(p.has_any_changes());
    }

    #[test]
    fn test_snapshot() {
        let snap = DrgnSnapshot::new(0, "Stopped").with_timestamp(1234567890);
        assert_eq!(snap.id, 0);
        assert_eq!(snap.description, "Stopped");
        assert_eq!(snap.timestamp, Some(1234567890));
    }

    #[test]
    fn test_process_sync_state() {
        let mut state = DrgnProcessSyncState::new();
        assert!(state.first);

        state.mark_recorded();
        assert!(!state.first);

        state.record_visit(1, 0);
        state.record_visit(1, 1);
        state.record_visit(2, 0);
        assert!(state.is_visited(1, 0));
        assert!(state.is_visited(1, 1));
        assert!(!state.is_visited(1, 2));
        assert!(state.thread_visited(2));

        state.clear_visited();
        assert!(!state.is_visited(1, 0));
    }

    #[test]
    fn test_process_sync_state_dirty_flags() {
        let mut state = DrgnProcessSyncState::new();
        assert!(!state.take_modules_dirty());

        state.mark_modules_dirty();
        assert!(state.take_modules_dirty());
        assert!(!state.take_modules_dirty()); // consumed

        state.mark_threads_dirty();
        state.mark_breaks_dirty();
        state.mark_watches_dirty();
        assert!(state.take_threads_dirty());
        assert!(state.take_breaks_dirty());
        assert!(state.take_regions_dirty() == false);

        assert!(state.has_dirty()); // watches_dirty is still true
    }

    #[test]
    fn test_process_sync_state_snapshots() {
        let mut state = DrgnProcessSyncState::new();
        state.create_snapshot("Stopped");
        state.create_snapshot("Continued");
        state.create_snapshot("Stopped");
        assert_eq!(state.snapshots.len(), 3);
        assert_eq!(state.snapshots[0].id, 0);
        assert_eq!(state.snapshots[1].id, 1);
        assert_eq!(state.snapshots[2].id, 2);
    }

    #[test]
    fn test_convenience_state() {
        let mut state = DrgnConvenienceState::new();
        assert_eq!(state.selected_pid, -1);
        assert!(state.selected_process().is_none());

        state.select_process(0);
        assert_eq!(state.selected_process(), Some(0));

        state.select_thread(42);
        assert_eq!(state.selected_thread(), Some(42));

        state.select_frame(2);
        assert_eq!(state.selected_frame(), Some(2));

        state.set_variable("_ghidra_tracing", "true");
        assert_eq!(state.get_variable("_ghidra_tracing"), Some("true"));
        assert_eq!(state.get_variable("nonexistent"), None);

        state.reset();
        assert_eq!(state.selected_pid, -1);
    }

    #[test]
    fn test_available_process() {
        let ap = AvailableProcess::new(1234, "bash");
        assert_eq!(ap.trace_path(), "Sessions[0].Available[1234]");
        let values = ap.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "PID" && v == "1234"));
        assert!(values.iter().any(|(k, v)| k == "Name" && v == "bash"));
    }

    #[test]
    fn test_relocated_section() {
        let sec = DrgnRelocatedSection::new(".text", 0xffffffffa0000000, 0x5000, 0xffffffffa0000000);
        assert_eq!(sec.module_base_hex(), "0xffffffffa0000000");
        assert_eq!(
            sec.trace_path(0),
            "Processes[0].Modules[0xffffffffa0000000].Sections[.text]"
        );
        let values = sec.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "Address" && v == "0xffffffffa0000000"));
        assert!(values.iter().any(|(k, v)| k == "Size" && v == "0x5000"));
        assert!(values.iter().any(|(k, v)| k == "Name" && v == ".text"));
    }

    #[test]
    fn test_process_module_count() {
        let mut p = DrgnInferiorProcess::new(0);
        assert_eq!(p.module_count(), 0);
        assert_eq!(p.memory_region_count(), 0);
        p.add_module(DrgnModuleInfo {
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
        });
        assert_eq!(p.module_count(), 1);
    }

    #[test]
    fn test_local_variable() {
        let local = DrgnLocalVariable::new(
            "fd",
            "int",
            DrgnVariableKind::Parameter,
            "3",
        )
        .with_address(0x7fff0000);
        assert_eq!(local.name, "fd");
        assert_eq!(local.type_name, "int");
        assert_eq!(local.kind, DrgnVariableKind::Parameter);
        assert_eq!(local.address, Some(0x7fff0000));
        assert!(!local.is_absent);
        assert_eq!(
            local.trace_path(0, 1, 2),
            "Processes[0].Threads[1].Stack[2].Locals.fd"
        );
        let values = local.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "Kind" && v == "parameter"));
        assert!(values.iter().any(|(k, v)| k == "Type" && v == "int"));
        assert!(values.iter().any(|(k, v)| k == "Value" && v == "3"));
        assert!(values.iter().any(|(k, v)| k == "Address" && v == "0x7fff0000"));
    }

    #[test]
    fn test_local_variable_absent() {
        let local = DrgnLocalVariable::new(
            "reg",
            "unsigned long",
            DrgnVariableKind::Local,
            "<optimized out>",
        )
        .with_absent(true);
        assert!(local.is_absent);
        let values = local.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "Value" && v == "<absent>"));
    }

    #[test]
    fn test_variable_kind() {
        assert_eq!(DrgnVariableKind::Parameter.as_str(), "parameter");
        assert_eq!(DrgnVariableKind::Local.as_str(), "local");
        assert_eq!(DrgnVariableKind::Global.as_str(), "global");
        assert_eq!(DrgnVariableKind::Pointer.as_str(), "pointer");
    }

    #[test]
    fn test_symbol_binding() {
        assert_eq!(DrgnSymbolBinding::from_str("STB_GLOBAL"), DrgnSymbolBinding::Global);
        assert_eq!(DrgnSymbolBinding::from_str("LOCAL"), DrgnSymbolBinding::Local);
        assert_eq!(DrgnSymbolBinding::from_str("STB_WEAK"), DrgnSymbolBinding::Weak);
        assert_eq!(DrgnSymbolBinding::from_str("unknown"), DrgnSymbolBinding::Other);
        assert_eq!(DrgnSymbolBinding::Global.as_str(), "GLOBAL");
    }

    #[test]
    fn test_symbol_kind() {
        assert_eq!(DrgnSymbolKind::from_str("STT_FUNC"), DrgnSymbolKind::Function);
        assert_eq!(DrgnSymbolKind::from_str("OBJECT"), DrgnSymbolKind::Object);
        assert_eq!(DrgnSymbolKind::from_str("STT_NOTYPE"), DrgnSymbolKind::NoType);
        assert_eq!(DrgnSymbolKind::Function.as_str(), "FUNC");
    }

    #[test]
    fn test_enriched_symbol() {
        let sym = DrgnEnrichedSymbol::new(
            "do_sys_open",
            0xffffffff81234567,
            0x100,
            DrgnSymbolBinding::Global,
            DrgnSymbolKind::Function,
        );
        let values = sym.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "Binding" && v == "GLOBAL"));
        assert!(values.iter().any(|(k, v)| k == "Kind" && v == "FUNC"));
        assert!(values.iter().any(|(k, v)| k == "Name" && v == "do_sys_open"));
        assert!(values.iter().any(|(k, v)| k == "_short_display" && v == "0xffffffff81234567"));
    }

    #[test]
    fn test_memory_mapper() {
        let mapper = DrgnMemoryMapper::new();
        assert_eq!(mapper.default_space, "ram");
        let (space, offset) = mapper.map(0, 0x12345678);
        assert_eq!(space, "ram");
        assert_eq!(offset, 0x12345678);
        assert_eq!(mapper.map_back(0, "ram", 0x12345678), Some(0x12345678));
        assert_eq!(mapper.map_back(0, "other", 0x12345678), None);

        let mapper2 = DrgnMemoryMapper::with_space("kernel");
        assert_eq!(mapper2.default_space, "kernel");
    }

    #[test]
    fn test_register_mapper() {
        let mapper = DrgnRegisterMapper::little_endian();
        assert_eq!(mapper.byte_order, DrgnByteOrder::Little);
        assert_eq!(mapper.map_name(0, "rax"), "rax");
        assert_eq!(mapper.map_name_back(0, "rax"), "rax");

        let be_mapper = DrgnRegisterMapper::big_endian();
        assert_eq!(be_mapper.byte_order, DrgnByteOrder::Big);
    }

    #[test]
    fn test_byte_order() {
        assert_eq!(DrgnByteOrder::Little.as_str(), "little");
        assert_eq!(DrgnByteOrder::Big.as_str(), "big");
    }

    #[test]
    fn test_process_manager() {
        let mut mgr = DrgnProcessManager::new();
        assert_eq!(mgr.process_count(), 0);

        mgr.add_process(DrgnInferiorProcess::kernel(0));
        mgr.add_process(DrgnInferiorProcess::new(1).with_pid(1234));
        assert_eq!(mgr.process_count(), 2);
        assert!(mgr.has_process(0));
        assert!(mgr.has_process(1));
        assert!(!mgr.has_process(2));

        mgr.select_process(0);
        assert!(mgr.selected_process().is_some());
        assert_eq!(mgr.selected_process().unwrap().num, 0);

        mgr.select_thread(42);
        assert_eq!(mgr.convenience.selected_thread(), Some(42));

        let removed = mgr.remove_process(1);
        assert!(removed.is_some());
        assert_eq!(mgr.process_count(), 1);
        assert_eq!(mgr.process_numbers(), vec![0]);
    }

    #[test]
    fn test_process_manager_reset() {
        let mut mgr = DrgnProcessManager::new();
        mgr.add_process(DrgnInferiorProcess::new(0));
        mgr.select_process(0);
        mgr.reset();
        assert_eq!(mgr.process_count(), 0);
        assert_eq!(mgr.convenience.selected_pid, -1);
    }

    #[test]
    fn test_process_manager_mark_all() {
        let mut mgr = DrgnProcessManager::new();
        mgr.add_process(DrgnInferiorProcess::new(0));
        mgr.add_process(DrgnInferiorProcess::new(1));
        mgr.mark_all_modules_changed();
        assert!(mgr.get_process(0).unwrap().modules_changed);
        assert!(mgr.get_process(1).unwrap().modules_changed);
    }
}
