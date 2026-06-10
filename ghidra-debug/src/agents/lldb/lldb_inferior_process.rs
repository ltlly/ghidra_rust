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
use std::collections::{BTreeMap, BTreeSet, HashMap};

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
    /// Loaded modules (shared libraries / images) with sections.
    pub modules: Vec<LldbModuleWithSections>,
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
    /// Breakpoint IDs associated with this process.
    pub breakpoint_ids: Vec<u32>,
    /// Watchpoint configurations for this process.
    pub watchpoints: BTreeMap<u32, LldbWatchpointConfig>,
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
            breakpoint_ids: Vec::new(),
            watchpoints: BTreeMap::new(),
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
    ///
    /// Wraps the `ModuleInfo` in `LldbModuleWithSections` and replaces
    /// any existing module with the same name.
    pub fn add_module(&mut self, module: ModuleInfo) {
        self.modules.retain(|m| m.info.name != module.name);
        self.modules.push(LldbModuleWithSections::from_info(module));
    }

    /// Add a module with sections.
    pub fn add_module_with_sections(&mut self, module: LldbModuleWithSections) {
        self.modules.retain(|m| m.info.name != module.info.name);
        self.modules.push(module);
    }

    /// Remove a module by name.
    pub fn remove_module(&mut self, name: &str) -> Option<LldbModuleWithSections> {
        if let Some(pos) = self.modules.iter().position(|m| m.info.name == name) {
            Some(self.modules.remove(pos))
        } else {
            None
        }
    }

    /// Get a module by name.
    pub fn get_module(&self, name: &str) -> Option<&LldbModuleWithSections> {
        self.modules.iter().find(|m| m.info.name == name)
    }

    /// Get a mutable reference to a module by name.
    pub fn get_module_mut(&mut self, name: &str) -> Option<&mut LldbModuleWithSections> {
        self.modules.iter_mut().find(|m| m.info.name == name)
    }

    /// Clear all modules.
    pub fn clear_modules(&mut self) {
        self.modules.clear();
    }

    /// Get the number of modules.
    pub fn module_count(&self) -> usize {
        self.modules.len()
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

    /// Get threads sorted by index.
    pub fn threads_sorted(&self) -> Vec<&LldbThread> {
        let mut threads: Vec<_> = self.threads.values().collect();
        threads.sort_by_key(|t| t.index);
        threads
    }

    /// Get all running threads.
    pub fn running_threads(&self) -> Vec<&LldbThread> {
        self.threads
            .values()
            .filter(|t| t.state == ExecutionState::Running)
            .collect()
    }

    /// Get all stopped threads.
    pub fn stopped_threads(&self) -> Vec<&LldbThread> {
        self.threads
            .values()
            .filter(|t| t.state == ExecutionState::Stopped)
            .collect()
    }

    /// Count threads by execution state.
    pub fn thread_state_counts(&self) -> BTreeMap<ExecutionState, usize> {
        let mut counts = BTreeMap::new();
        for t in self.threads.values() {
            *counts.entry(t.state).or_insert(0) += 1;
        }
        counts
    }

    /// Build trace object key-value pairs for the threads container.
    pub fn build_threads_container_values(&self) -> Vec<(String, String)> {
        vec![("_count".to_string(), self.threads.len().to_string())]
    }

    /// Find a module that contains the given address.
    pub fn module_at_address(&self, addr: u64) -> Option<&LldbModuleWithSections> {
        self.modules
            .iter()
            .find(|m| addr >= m.info.base && addr < m.info.base + m.info.size)
    }

    /// Get sorted modules by base address.
    pub fn modules_sorted(&self) -> Vec<&LldbModuleWithSections> {
        let mut mods: Vec<_> = self.modules.iter().collect();
        mods.sort_by_key(|m| m.info.base);
        mods
    }

    /// Build trace object key-value pairs for the modules container.
    pub fn build_modules_container_values(&self) -> Vec<(String, String)> {
        vec![("_count".to_string(), self.modules.len().to_string())]
    }

    /// Find a memory region that contains the given address.
    pub fn memory_region_at(&self, addr: u64) -> Option<&MemoryRegion> {
        self.memory_regions
            .iter()
            .find(|r| addr >= r.base && addr < r.base + r.size)
    }

    /// Get total memory footprint (sum of all region sizes).
    pub fn memory_footprint(&self) -> u64 {
        self.memory_regions.iter().map(|r| r.size).sum()
    }

    /// Get a memory region by base address.
    pub fn get_memory_region(&self, base: u64) -> Option<&MemoryRegion> {
        self.memory_regions.iter().find(|r| r.base == base)
    }

    /// Check if a given address falls within any mapped region.
    pub fn is_address_mapped(&self, addr: u64) -> bool {
        self.memory_regions
            .iter()
            .any(|r| addr >= r.base && addr < r.base + r.size)
    }

    /// Update this process's state from its threads.
    ///
    /// Sets `self.state` to the computed state from threads.
    pub fn refresh_state(&mut self) {
        self.state = self.compute_state();
    }

    /// Add a breakpoint ID association.
    pub fn add_breakpoint_id(&mut self, bp_id: u32) {
        if !self.breakpoint_ids.contains(&bp_id) {
            self.breakpoint_ids.push(bp_id);
        }
    }

    /// Remove a breakpoint ID association.
    pub fn remove_breakpoint_id(&mut self, bp_id: u32) {
        self.breakpoint_ids.retain(|id| *id != bp_id);
    }

    /// Add a watchpoint to this process.
    pub fn add_watchpoint(&mut self, watchpoint: LldbWatchpointConfig) {
        self.watchpoints.insert(watchpoint.id, watchpoint);
    }

    /// Remove a watchpoint by ID.
    pub fn remove_watchpoint(&mut self, wp_id: u32) -> Option<LldbWatchpointConfig> {
        self.watchpoints.remove(&wp_id)
    }

    /// Get a watchpoint by ID.
    pub fn get_watchpoint(&self, wp_id: u32) -> Option<&LldbWatchpointConfig> {
        self.watchpoints.get(&wp_id)
    }

    /// Get a mutable watchpoint by ID.
    pub fn get_watchpoint_mut(&mut self, wp_id: u32) -> Option<&mut LldbWatchpointConfig> {
        self.watchpoints.get_mut(&wp_id)
    }

    /// Get the number of watchpoints.
    pub fn watchpoint_count(&self) -> usize {
        self.watchpoints.len()
    }

    /// Check if a watchpoint covers the given address.
    pub fn watchpoint_at_address(&self, addr: u64) -> Option<&LldbWatchpointConfig> {
        self.watchpoints.values().find(|wp| {
            let (start, end) = wp.address_range();
            addr >= start && addr < end
        })
    }

    /// Build trace object key-value pairs for the watchpoints container.
    pub fn build_watchpoints_container_values(&self) -> Vec<(String, String)> {
        vec![("_count".to_string(), self.watchpoints.len().to_string())]
    }

    /// Build the retain keys for watchpoint children.
    pub fn build_watchpoint_retain_keys(&self) -> Vec<String> {
        self.watchpoints
            .keys()
            .map(|id| format!("[{}]", id))
            .collect()
    }

    /// Build the retain keys for process-level object children.
    ///
    /// This is used with `retain_values` to clean up stale children.
    pub fn build_retain_keys(&self) -> Vec<String> {
        vec![format!("[{}]", self.index)]
    }

    /// Build the retain keys for thread children.
    pub fn build_thread_retain_keys(&self) -> Vec<String> {
        self.threads
            .keys()
            .map(|idx| format!("[{}]", idx))
            .collect()
    }

    /// Build the retain keys for module children.
    pub fn build_module_retain_keys(&self) -> Vec<String> {
        self.modules
            .iter()
            .map(|m| format!("[{}]", m.info.name))
            .collect()
    }

    /// Build the retain keys for memory region children.
    pub fn build_region_retain_keys(&self) -> Vec<String> {
        self.memory_regions
            .iter()
            .map(|r| format!("[{:08x}]", r.base))
            .collect()
    }

    /// Get the number of memory regions.
    pub fn memory_region_count(&self) -> usize {
        self.memory_regions.len()
    }
}

/// A module section within a loaded module/image.
///
/// Sections correspond to Mach-O segments (__TEXT, __DATA), ELF sections
/// (.text, .data, .bss), or PE sections. Ported from the Python `Section`
/// class in `util.py`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LldbModuleSection {
    /// Section name (e.g., "__TEXT.__text", ".text").
    pub name: String,
    /// Start address of the section.
    pub start: u64,
    /// End address (exclusive) of the section.
    pub end: u64,
    /// File offset of the section.
    pub offset: u64,
    /// Section attributes (e.g., flags like "code", "data").
    pub attrs: Vec<String>,
}

impl LldbModuleSection {
    /// Create a new module section.
    pub fn new(name: impl Into<String>, start: u64, end: u64) -> Self {
        Self {
            name: name.into(),
            start,
            end,
            offset: 0,
            attrs: Vec::new(),
        }
    }

    /// Set the file offset.
    pub fn with_offset(mut self, offset: u64) -> Self {
        self.offset = offset;
        self
    }

    /// Set section attributes.
    pub fn with_attrs(mut self, attrs: Vec<String>) -> Self {
        self.attrs = attrs;
        self
    }

    /// Get the size of the section in bytes.
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Build the trace path for this section within a module.
    pub fn trace_path(&self, process_index: u32, module_name: &str) -> String {
        format!(
            "Processes[{}].Modules[{}].Sections[{}]",
            process_index, module_name, self.name
        )
    }

    /// Build trace key-value pairs for this section.
    pub fn build_trace_values(&self) -> Vec<(String, String)> {
        let mut values = Vec::new();
        if self.end == self.start {
            values.push(("Address".to_string(), format!("0x{:x}", self.start)));
        } else {
            values.push((
                "Range".to_string(),
                format!("0x{:x}:0x{:x}", self.start, self.end),
            ));
        }
        values.push(("Offset".to_string(), format!("0x{:x}", self.offset)));
        if !self.attrs.is_empty() {
            values.push(("Attrs".to_string(), self.attrs.join(",")));
        }
        values
    }
}

/// Extended module info with sections support.
///
/// This wraps `ModuleInfo` with additional section data ported from
/// the Python agent's `put_modules` function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LldbModuleWithSections {
    /// Base module info.
    pub info: ModuleInfo,
    /// Sections within this module, keyed by section name.
    pub sections: BTreeMap<String, LldbModuleSection>,
}

impl LldbModuleWithSections {
    /// Create from a `ModuleInfo`.
    pub fn from_info(info: ModuleInfo) -> Self {
        Self {
            info,
            sections: BTreeMap::new(),
        }
    }

    /// Add a section. Replaces if same name exists.
    pub fn add_section(&mut self, section: LldbModuleSection) {
        self.sections.insert(section.name.clone(), section);
    }

    /// Remove a section by name.
    pub fn remove_section(&mut self, name: &str) -> Option<LldbModuleSection> {
        self.sections.remove(name)
    }

    /// Clear all sections.
    pub fn clear_sections(&mut self) {
        self.sections.clear();
    }

    /// Get section count.
    pub fn section_count(&self) -> usize {
        self.sections.len()
    }

    /// Build the trace path for this module's sections container.
    pub fn sections_path(&self, process_index: u32) -> String {
        format!(
            "Processes[{}].Modules[{}].Sections",
            process_index, self.info.name
        )
    }
}

/// Snapshot descriptor for trace recording.
///
/// Ported from the Python `snapshot` calls in `commands.py` and `hooks.py`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LldbSnapshot {
    /// Snapshot ID (sequential).
    pub id: u64,
    /// Description (e.g., "Stopped", "Exited with code 0").
    pub description: String,
    /// Timestamp (unix epoch millis, if available).
    pub timestamp: Option<u64>,
}

impl LldbSnapshot {
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

/// Tracks the synchronization state for a process between stops.
///
/// Ported from the Python `InferiorState` class in `hooks.py`. Tracks
/// which aspects of the process have changed and need re-sync.
#[derive(Debug, Clone)]
pub struct LldbProcessSyncState {
    /// Whether this is the first recording for this process.
    pub first: bool,
    /// Last known memory regions (for change detection).
    pub regions: Vec<MemoryRegion>,
    /// Whether modules have changed since last stop.
    pub modules_dirty: bool,
    /// Whether threads have changed since last stop.
    pub threads_dirty: bool,
    /// Whether breakpoints have changed since last stop.
    pub breaks_dirty: bool,
    /// Visited (thread_index, frame_level) pairs since last stop.
    pub visited: BTreeSet<(u32, u32)>,
    /// Snapshots recorded for this process.
    pub snapshots: Vec<LldbSnapshot>,
    /// Next snapshot ID.
    next_snap_id: u64,
}

impl Default for LldbProcessSyncState {
    fn default() -> Self {
        Self {
            first: true,
            regions: Vec::new(),
            modules_dirty: false,
            threads_dirty: false,
            breaks_dirty: false,
            visited: BTreeSet::new(),
            snapshots: Vec::new(),
            next_snap_id: 0,
        }
    }
}

impl LldbProcessSyncState {
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
    pub fn record_visit(&mut self, thread_index: u32, frame_level: u32) {
        self.visited.insert((thread_index, frame_level));
    }

    /// Check if a thread/frame has been visited.
    pub fn is_visited(&self, thread_index: u32, frame_level: u32) -> bool {
        self.visited.contains(&(thread_index, frame_level))
    }

    /// Check if a thread has any visited frames.
    pub fn thread_visited(&self, thread_index: u32) -> bool {
        self.visited.iter().any(|(t, _)| *t == thread_index)
    }

    /// Create a new snapshot.
    pub fn create_snapshot(&mut self, description: impl Into<String>) -> &LldbSnapshot {
        let snap = LldbSnapshot::new(self.next_snap_id, description);
        self.next_snap_id += 1;
        self.snapshots.push(snap);
        self.snapshots.last().unwrap()
    }

    /// Mark modules as dirty (need re-sync).
    pub fn mark_modules_dirty(&mut self) {
        self.modules_dirty = true;
    }

    /// Mark threads as dirty.
    pub fn mark_threads_dirty(&mut self) {
        self.threads_dirty = true;
    }

    /// Mark breakpoints as dirty.
    pub fn mark_breaks_dirty(&mut self) {
        self.breaks_dirty = true;
    }

    /// Consume the modules dirty flag (returns true if was dirty).
    pub fn take_modules_dirty(&mut self) -> bool {
        let dirty = self.modules_dirty;
        self.modules_dirty = false;
        dirty
    }

    /// Consume the threads dirty flag.
    pub fn take_threads_dirty(&mut self) -> bool {
        let dirty = self.threads_dirty;
        self.threads_dirty = false;
        dirty
    }

    /// Consume the breaks dirty flag.
    pub fn take_breaks_dirty(&mut self) -> bool {
        let dirty = self.breaks_dirty;
        self.breaks_dirty = false;
        dirty
    }

    /// Check if regions have changed compared to the provided new regions.
    ///
    /// Returns true if the regions differ from the last known set.
    pub fn regions_changed(&self, new_regions: &[MemoryRegion]) -> bool {
        if self.regions.len() != new_regions.len() {
            return true;
        }
        for (old, new) in self.regions.iter().zip(new_regions.iter()) {
            if old.base != new.base || old.size != new.size {
                return true;
            }
        }
        false
    }

    /// Update the stored regions.
    pub fn update_regions(&mut self, regions: Vec<MemoryRegion>) {
        self.regions = regions;
    }
}

/// Signal configuration for an LLDB process.
///
/// LLDB can intercept and handle Unix signals. This tracks which signals
/// are configured to stop, notify, or pass through.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LldbSignalConfig {
    /// Signal number.
    pub number: i32,
    /// Signal name (e.g. "SIGSEGV").
    pub name: String,
    /// Whether this signal stops the process.
    pub stop: bool,
    /// Whether this signal notifies the debugger.
    pub notify: bool,
    /// Whether this signal is passed to the process.
    pub pass: bool,
    /// Optional description.
    pub description: Option<String>,
}

impl LldbSignalConfig {
    /// Create a new signal config.
    pub fn new(number: i32, name: impl Into<String>) -> Self {
        Self {
            number,
            name: name.into(),
            stop: true,
            notify: true,
            pass: true,
            description: None,
        }
    }

    /// Set stop behavior.
    pub fn with_stop(mut self, stop: bool) -> Self {
        self.stop = stop;
        self
    }

    /// Set notify behavior.
    pub fn with_notify(mut self, notify: bool) -> Self {
        self.notify = notify;
        self
    }

    /// Set pass behavior.
    pub fn with_pass(mut self, pass: bool) -> Self {
        self.pass = pass;
        self
    }

    /// Set description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
}

/// Process launch configuration.
///
/// Mirrors LLDB's `SBLaunchInfo` -- specifies how to launch a target process,
/// including arguments, environment, working directory, and launch flags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LldbLaunchConfig {
    /// Target executable path.
    pub executable: String,
    /// Command-line arguments (argv[1..]).
    pub arguments: Vec<String>,
    /// Environment variables to set.
    pub environment: HashMap<String, String>,
    /// Working directory for the launched process.
    pub working_dir: Option<String>,
    /// Whether to launch in a new terminal window.
    pub launch_in_terminal: bool,
    /// Whether to disable ASLR.
    pub disable_aslr: bool,
    /// Whether to stop at entry point.
    pub stop_at_entry: bool,
    /// Standard I/O file actions.
    pub stdin_path: Option<String>,
    pub stdout_path: Option<String>,
    pub stderr_path: Option<String>,
}

impl LldbLaunchConfig {
    /// Create a launch config for the given executable.
    pub fn new(executable: impl Into<String>) -> Self {
        Self {
            executable: executable.into(),
            arguments: Vec::new(),
            environment: HashMap::new(),
            working_dir: None,
            launch_in_terminal: false,
            disable_aslr: false,
            stop_at_entry: false,
            stdin_path: None,
            stdout_path: None,
            stderr_path: None,
        }
    }

    /// Add an argument.
    pub fn with_arg(mut self, arg: impl Into<String>) -> Self {
        self.arguments.push(arg.into());
        self
    }

    /// Add multiple arguments.
    pub fn with_args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.arguments.extend(args.into_iter().map(|a| a.into()));
        self
    }

    /// Set an environment variable.
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.environment.insert(key.into(), value.into());
        self
    }

    /// Set the working directory.
    pub fn with_working_dir(mut self, dir: impl Into<String>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    /// Disable ASLR for the launched process.
    pub fn with_disable_aslr(mut self, disable: bool) -> Self {
        self.disable_aslr = disable;
        self
    }

    /// Stop at the program entry point.
    pub fn with_stop_at_entry(mut self, stop: bool) -> Self {
        self.stop_at_entry = stop;
        self
    }

    /// Build the LLDB launch command string.
    pub fn build_command(&self) -> String {
        let mut cmd = format!("file {}", self.executable);
        if !self.arguments.is_empty() {
            let args_str: Vec<&str> = self.arguments.iter().map(|s| s.as_str()).collect();
            cmd += &format!(" -- {}", args_str.join(" "));
        }
        cmd
    }
}

/// Process attach configuration.
///
/// Mirrors LLDB's `SBAttachInfo` -- specifies how to attach to an
/// already-running process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LldbAttachConfig {
    /// PID to attach to (mutually exclusive with `name`).
    pub pid: Option<u64>,
    /// Process name to attach to (mutually exclusive with `pid`).
    pub name: Option<String>,
    /// Whether to wait for the process to launch.
    pub wait_for: bool,
    /// Whether to attach in stopped state.
    pub stop_at_entry: bool,
}

impl LldbAttachConfig {
    /// Attach to a process by PID.
    pub fn by_pid(pid: u64) -> Self {
        Self {
            pid: Some(pid),
            name: None,
            wait_for: false,
            stop_at_entry: true,
        }
    }

    /// Attach to a process by name.
    pub fn by_name(name: impl Into<String>) -> Self {
        Self {
            pid: None,
            name: Some(name.into()),
            wait_for: false,
            stop_at_entry: true,
        }
    }

    /// Set whether to wait for the process.
    pub fn with_wait_for(mut self, wait: bool) -> Self {
        self.wait_for = wait;
        self
    }

    /// Build the LLDB attach command string.
    pub fn build_command(&self) -> String {
        if let Some(pid) = self.pid {
            format!("process attach --pid {}", pid)
        } else if let Some(ref name) = self.name {
            format!("process attach --name {}", name)
        } else {
            "process attach".to_string()
        }
    }
}

/// Target information for an LLDB debug session.
///
/// Represents the SBTarget-level metadata: the executable being debugged,
/// the platform, and architecture details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LldbTargetInfo {
    /// Path to the target executable.
    pub executable_path: Option<String>,
    /// Target triple (e.g. "x86_64-apple-macosx").
    pub triple: String,
    /// Platform name (e.g. "host", "remote-linux").
    pub platform: String,
    /// Pointer size in bytes.
    pub pointer_size: usize,
    /// Whether the target is big-endian.
    pub big_endian: bool,
    /// Address size in bits.
    pub address_size: usize,
}

impl LldbTargetInfo {
    /// Create new target info.
    pub fn new(triple: impl Into<String>) -> Self {
        Self {
            executable_path: None,
            triple: triple.into(),
            platform: "host".to_string(),
            pointer_size: 8,
            big_endian: false,
            address_size: 64,
        }
    }

    /// Set the executable path.
    pub fn with_executable(mut self, path: impl Into<String>) -> Self {
        self.executable_path = Some(path.into());
        self
    }

    /// Set the platform.
    pub fn with_platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = platform.into();
        self
    }

    /// Set the pointer size.
    pub fn with_pointer_size(mut self, size: usize) -> Self {
        self.pointer_size = size;
        self
    }

    /// Set endianness.
    pub fn with_big_endian(mut self, big: bool) -> Self {
        self.big_endian = big;
        self
    }

    /// Get the architecture component from the triple.
    pub fn arch(&self) -> &str {
        self.triple.split('-').next().unwrap_or(&self.triple)
    }

    /// Get the OS component from the triple.
    pub fn os(&self) -> &str {
        self.triple.split('-').nth(1).unwrap_or("unknown")
    }

    /// Get the endianness as a trace string.
    pub fn endian_str(&self) -> &'static str {
        if self.big_endian { "big" } else { "little" }
    }
}

/// Tracks signal configurations for a process.
#[derive(Debug, Clone, Default)]
pub struct LldbSignalTable {
    signals: BTreeMap<i32, LldbSignalConfig>,
}

impl LldbSignalTable {
    /// Create an empty signal table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a signal configuration.
    pub fn set(&mut self, config: LldbSignalConfig) {
        self.signals.insert(config.number, config);
    }

    /// Get a signal configuration by number.
    pub fn get(&self, number: i32) -> Option<&LldbSignalConfig> {
        self.signals.get(&number)
    }

    /// Get all signal configurations.
    pub fn all(&self) -> &BTreeMap<i32, LldbSignalConfig> {
        &self.signals
    }

    /// Get signals configured to stop the process.
    pub fn stopping_signals(&self) -> Vec<&LldbSignalConfig> {
        self.signals.values().filter(|s| s.stop).collect()
    }

    /// Populate with default Unix signal configurations.
    pub fn populate_defaults(&mut self) {
        let defaults: &[(i32, &str, &str)] = &[
            (1, "SIGHUP", "Hangup"),
            (2, "SIGINT", "Interrupt"),
            (3, "SIGQUIT", "Quit"),
            (4, "SIGILL", "Illegal instruction"),
            (5, "SIGTRAP", "Trace/breakpoint trap"),
            (6, "SIGABRT", "Abort"),
            (7, "SIGBUS", "Bus error"),
            (8, "SIGFPE", "Floating point exception"),
            (9, "SIGKILL", "Kill"),
            (11, "SIGSEGV", "Segmentation fault"),
            (13, "SIGPIPE", "Broken pipe"),
            (14, "SIGALRM", "Alarm clock"),
            (15, "SIGTERM", "Terminated"),
            (17, "SIGCHLD", "Child status changed"),
            (18, "SIGCONT", "Continue"),
            (19, "SIGSTOP", "Stop"),
            (20, "SIGTSTP", "Terminal stop"),
            (21, "SIGTTIN", "Background read"),
            (22, "SIGTTOU", "Background write"),
            (29, "SIGIO", "I/O possible"),
            (31, "SIGSYS", "Bad system call"),
        ];
        for &(num, name, desc) in defaults {
            let stop = matches!(num, 4 | 5 | 6 | 7 | 8 | 11 | 31);
            self.set(
                LldbSignalConfig::new(num, name)
                    .with_stop(stop)
                    .with_description(desc),
            );
        }
    }

    /// Count of configured signals.
    pub fn len(&self) -> usize {
        self.signals.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.signals.is_empty()
    }
}

/// Process-level breakpoint state.
///
/// LLDB tracks breakpoints at the target level (shared across processes)
/// but they resolve per-process. This struct tracks resolved breakpoints
/// for a single process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LldbProcessBreakpoint {
    /// Breakpoint ID (target-level).
    pub id: u32,
    /// Resolved address in this process.
    pub resolved_address: Option<u64>,
    /// Whether the breakpoint is enabled.
    pub enabled: bool,
    /// Number of times hit.
    pub hit_count: u32,
    /// Condition expression (if conditional).
    pub condition: Option<String>,
    /// Whether this is a hardware breakpoint.
    pub hardware: bool,
    /// Optional ignore count (skip first N hits).
    pub ignore_count: u32,
    /// Breakpoint type (software, hardware, watchpoint).
    pub bp_type: LldbBreakpointType,
    /// LLDB-specific: auto-continue after hitting.
    pub auto_continue: bool,
    /// LLDB-specific: command list to execute on hit.
    pub commands: Vec<String>,
}

/// Type of breakpoint within an LLDB target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LldbBreakpointType {
    /// Regular software breakpoint.
    Breakpoint,
    /// Hardware breakpoint (instruction breakpoint).
    HardwareBreakpoint,
    /// Write watchpoint (data breakpoint on write).
    WriteWatchpoint,
    /// Read watchpoint (data breakpoint on read).
    ReadWatchpoint,
    /// Access watchpoint (data breakpoint on read/write).
    AccessWatchpoint,
    /// Exception breakpoint (e.g. C++ throw, Objective-C exception).
    ExceptionBreakpoint,
}

impl LldbBreakpointType {
    /// Whether this is a watchpoint type.
    pub fn is_watchpoint(&self) -> bool {
        matches!(
            self,
            Self::WriteWatchpoint | Self::ReadWatchpoint | Self::AccessWatchpoint
        )
    }

    /// Whether this is a breakpoint type (not watchpoint).
    pub fn is_breakpoint(&self) -> bool {
        !self.is_watchpoint()
    }

    /// Convert to the Ghidra breakpoint kinds string.
    ///
    /// 'x' = software, 'X' = hardware, 'w' = write watch, 'r' = read watch,
    /// 'a' = access watch.
    pub fn to_kinds_str(&self) -> &'static str {
        match self {
            Self::Breakpoint => "x",
            Self::HardwareBreakpoint | Self::ExceptionBreakpoint => "X",
            Self::WriteWatchpoint => "w",
            Self::ReadWatchpoint => "r",
            Self::AccessWatchpoint => "a",
        }
    }
}

impl LldbProcessBreakpoint {
    /// Create a new breakpoint entry.
    pub fn new(id: u32) -> Self {
        Self {
            id,
            resolved_address: None,
            enabled: true,
            hit_count: 0,
            condition: None,
            hardware: false,
            ignore_count: 0,
            bp_type: LldbBreakpointType::Breakpoint,
            auto_continue: false,
            commands: Vec::new(),
        }
    }

    /// Set the resolved address.
    pub fn with_address(mut self, addr: u64) -> Self {
        self.resolved_address = Some(addr);
        self
    }

    /// Set as hardware breakpoint.
    pub fn with_hardware(mut self, hw: bool) -> Self {
        self.hardware = hw;
        if hw {
            self.bp_type = LldbBreakpointType::HardwareBreakpoint;
        }
        self
    }

    /// Set the breakpoint type.
    pub fn with_type(mut self, bp_type: LldbBreakpointType) -> Self {
        self.bp_type = bp_type;
        self
    }

    /// Set a condition expression.
    pub fn with_condition(mut self, cond: impl Into<String>) -> Self {
        self.condition = Some(cond.into());
        self
    }

    /// Set auto-continue behavior.
    pub fn with_auto_continue(mut self, auto_continue: bool) -> Self {
        self.auto_continue = auto_continue;
        self
    }

    /// Add a command to execute on hit.
    pub fn with_command(mut self, cmd: impl Into<String>) -> Self {
        self.commands.push(cmd.into());
        self
    }

    /// Record a hit.
    pub fn record_hit(&mut self) {
        self.hit_count += 1;
    }

    /// Check if this breakpoint should stop execution.
    pub fn should_stop(&self) -> bool {
        if !self.enabled {
            return false;
        }
        if self.auto_continue {
            return false;
        }
        self.hit_count == 0 || self.hit_count > self.ignore_count
    }

    /// Build the trace object key-value pairs for this breakpoint.
    ///
    /// Ported from `put_single_breakpoint` in the Python agent.
    pub fn build_trace_values(&self) -> Vec<(String, String)> {
        let mut values = Vec::new();
        values.push(("Enabled".to_string(), self.enabled.to_string()));
        values.push(("Hit Count".to_string(), self.hit_count.to_string()));
        values.push(("Kinds".to_string(), self.bp_type.to_kinds_str().to_string()));
        if self.hardware {
            values.push(("Temporary".to_string(), "false".to_string()));
        }
        if let Some(ref cond) = self.condition {
            values.push(("Condition".to_string(), cond.clone()));
        }
        if !self.commands.is_empty() {
            values.push(("Commands".to_string(), self.commands.join("\n")));
        }
        if self.ignore_count > 0 {
            values.push(("Ignore Count".to_string(), self.ignore_count.to_string()));
        }
        values
    }
}

/// LLDB watchpoint configuration.
///
/// Mirrors LLDB's `SBWatchpoint` API. In LLDB, watchpoints are data
/// breakpoints that trigger when a memory location is read, written,
/// or accessed.
///
/// Ported from `put_single_watchpoint` in the Python agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LldbWatchpointConfig {
    /// Watchpoint ID (target-level).
    pub id: u32,
    /// Watch address.
    pub address: u64,
    /// Size of the watched region in bytes.
    pub size: u32,
    /// Type of watchpoint.
    pub watch_type: LldbWatchpointType,
    /// Whether this watchpoint is enabled.
    pub enabled: bool,
    /// Number of times hit.
    pub hit_count: u32,
    /// Condition expression (if conditional).
    pub condition: Option<String>,
    /// LLDB-specific: command list to execute on hit.
    pub commands: Vec<String>,
    /// LLDB-specific: ignore count (skip first N hits).
    pub ignore_count: u32,
}

/// Type of LLDB watchpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LldbWatchpointType {
    /// Write only.
    Write,
    /// Read only.
    Read,
    /// Read and write (access).
    Access,
}

impl LldbWatchpointType {
    /// Convert to the Ghidra kinds string.
    pub fn to_kinds_str(&self) -> &'static str {
        match self {
            Self::Write => "w",
            Self::Read => "r",
            Self::Access => "a",
        }
    }

    /// Convert from LLDB watch type integer.
    ///
    /// LLDB uses: 1 = read, 2 = write, 4 = modify (but commonly
    /// reported as read/write combinations).
    pub fn from_lldb_watch_type(read: bool, write: bool) -> Self {
        match (read, write) {
            (true, true) => Self::Access,
            (true, false) => Self::Read,
            (false, true) => Self::Write,
            (false, false) => Self::Access, // default
        }
    }
}

impl LldbWatchpointConfig {
    /// Create a new watchpoint.
    pub fn new(id: u32, address: u64, size: u32) -> Self {
        Self {
            id,
            address,
            size,
            watch_type: LldbWatchpointType::Access,
            enabled: true,
            hit_count: 0,
            condition: None,
            commands: Vec::new(),
            ignore_count: 0,
        }
    }

    /// Set the watchpoint type.
    pub fn with_type(mut self, watch_type: LldbWatchpointType) -> Self {
        self.watch_type = watch_type;
        self
    }

    /// Set enabled state.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Set a condition expression.
    pub fn with_condition(mut self, cond: impl Into<String>) -> Self {
        self.condition = Some(cond.into());
        self
    }

    /// Add a command to execute on hit.
    pub fn with_command(mut self, cmd: impl Into<String>) -> Self {
        self.commands.push(cmd.into());
        self
    }

    /// Record a hit.
    pub fn record_hit(&mut self) {
        self.hit_count += 1;
    }

    /// Get the watched address range (start, end exclusive).
    pub fn address_range(&self) -> (u64, u64) {
        (self.address, self.address + self.size as u64)
    }

    /// Build the trace object key-value pairs for this watchpoint.
    pub fn build_trace_values(&self) -> Vec<(String, String)> {
        let mut values = Vec::new();
        values.push(("Enabled".to_string(), self.enabled.to_string()));
        values.push(("Hit Count".to_string(), self.hit_count.to_string()));
        values.push(("Kinds".to_string(), self.watch_type.to_kinds_str().to_string()));
        values.push((
            "Range".to_string(),
            format!("0x{:x}:0x{:x}", self.address, self.address + self.size as u64),
        ));
        if let Some(ref cond) = self.condition {
            values.push(("Condition".to_string(), cond.clone()));
        }
        if !self.commands.is_empty() {
            values.push(("Commands".to_string(), self.commands.join("\n")));
        }
        if self.ignore_count > 0 {
            values.push(("Ignore Count".to_string(), self.ignore_count.to_string()));
        }
        values
    }
}

/// A process available for attachment on the LLDB platform.
///
/// Ported from the `put_available` command in the Python agent.
/// Represents processes visible on the debugging platform that can
/// be attached to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LldbAvailableProcess {
    /// OS process ID.
    pub pid: u64,
    /// Process name.
    pub name: String,
    /// Full executable path / command line.
    pub executable: String,
}

impl LldbAvailableProcess {
    /// Create a new available process entry.
    pub fn new(pid: u64, name: impl Into<String>, executable: impl Into<String>) -> Self {
        Self {
            pid,
            name: name.into(),
            executable: executable.into(),
        }
    }

    /// Build the display string for the Available list.
    pub fn display(&self) -> String {
        format!("{} {}", self.pid, self.executable)
    }

    /// Build the trace object key-value pairs.
    pub fn build_trace_values(&self) -> Vec<(String, String)> {
        vec![
            ("PID".to_string(), self.pid.to_string()),
            ("Name".to_string(), self.name.clone()),
            ("_display".to_string(), self.display()),
        ]
    }
}

/// LLDB register bank (group).
///
/// In LLDB, registers are organized into banks/groups (e.g.,
/// "General Purpose Registers", "Floating Point Registers", etc.).
/// The Python agent's `putreg` function iterates over register banks
/// from `SBFrame.GetRegisters()`.
///
/// Ported from the register bank iteration in `commands.py`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LldbRegisterBank {
    /// Bank name (e.g., "General Purpose Registers").
    pub name: String,
    /// Register names in this bank.
    pub register_names: Vec<String>,
    /// Number of registers in this bank.
    pub count: usize,
}

impl LldbRegisterBank {
    /// Create a new register bank.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            register_names: Vec::new(),
            count: 0,
        }
    }

    /// Set the register names for this bank.
    pub fn with_registers(mut self, names: Vec<String>) -> Self {
        self.count = names.len();
        self.register_names = names;
        self
    }

    /// Whether this is the primary (general purpose) register bank.
    pub fn is_primary(&self) -> bool {
        self.name == "General Purpose Registers"
    }
}

/// Memory access permission flags.
///
/// Ported from the Python `Region` class's permissions handling
/// and the `IsReadable`/`IsWritable`/`IsExecutable` checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LldbMemoryAccess {
    /// Region is readable.
    pub readable: bool,
    /// Region is writable.
    pub writable: bool,
    /// Region is executable.
    pub executable: bool,
}

impl LldbMemoryAccess {
    /// Create a new memory access descriptor.
    pub fn new(readable: bool, writable: bool, executable: bool) -> Self {
        Self {
            readable,
            writable,
            executable,
        }
    }

    /// Parse from a permission string (e.g., "rwx", "r-xp").
    pub fn from_perms(perms: &str) -> Self {
        Self {
            readable: perms.contains('r'),
            writable: perms.contains('w'),
            executable: perms.contains('x'),
        }
    }

    /// Convert to a permission string.
    pub fn to_perms(&self) -> String {
        let mut s = String::with_capacity(4);
        s.push(if self.readable { 'r' } else { '-' });
        s.push(if self.writable { 'w' } else { '-' });
        s.push(if self.executable { 'x' } else { '-' });
        s.push('p');
        s
    }

    /// Convert to the Ghidra trace key-value pairs.
    pub fn build_trace_values(&self) -> Vec<(String, String)> {
        vec![
            ("Permissions".to_string(), self.to_perms()),
            ("_readable".to_string(), self.readable.to_string()),
            ("_writable".to_string(), self.writable.to_string()),
            ("_executable".to_string(), self.executable.to_string()),
        ]
    }
}

impl Default for LldbMemoryAccess {
    fn default() -> Self {
        Self {
            readable: true,
            writable: false,
            executable: false,
        }
    }
}

/// LLDB process manager -- manages multiple processes within a single
/// LLDB target/debug session.
///
/// LLDB can debug multiple processes (e.g. when following forks). This
/// manager tracks all known processes and provides convenient access.
///
/// Ported from the process management in `commands.py` and `hooks.py`.
#[derive(Debug, Default)]
pub struct LldbProcessManager {
    processes: BTreeMap<u32, LldbInferiorProcess>,
    active_index: Option<u32>,
    /// Available processes on the platform (for attachment).
    available: Vec<LldbAvailableProcess>,
}

impl LldbProcessManager {
    /// Create a new empty process manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a process.
    pub fn add(&mut self, process: LldbInferiorProcess) {
        let idx = process.index;
        if self.active_index.is_none() {
            self.active_index = Some(idx);
        }
        self.processes.insert(idx, process);
    }

    /// Remove a process by index.
    pub fn remove(&mut self, index: u32) -> Option<LldbInferiorProcess> {
        let removed = self.processes.remove(&index);
        if self.active_index == Some(index) {
            self.active_index = self.processes.keys().next().copied();
        }
        removed
    }

    /// Get a process by index.
    pub fn get(&self, index: u32) -> Option<&LldbInferiorProcess> {
        self.processes.get(&index)
    }

    /// Get a mutable process by index.
    pub fn get_mut(&mut self, index: u32) -> Option<&mut LldbInferiorProcess> {
        self.processes.get_mut(&index)
    }

    /// Get the currently active process.
    pub fn active(&self) -> Option<&LldbInferiorProcess> {
        self.active_index.and_then(|i| self.processes.get(&i))
    }

    /// Get a mutable reference to the active process.
    pub fn active_mut(&mut self) -> Option<&mut LldbInferiorProcess> {
        self.active_index.and_then(move |i| self.processes.get_mut(&i))
    }

    /// Set the active process by index.
    pub fn set_active(&mut self, index: u32) {
        if self.processes.contains_key(&index) {
            self.active_index = Some(index);
        }
    }

    /// Get the active process index.
    pub fn active_index(&self) -> Option<u32> {
        self.active_index
    }

    /// Get all process indices.
    pub fn indices(&self) -> Vec<u32> {
        self.processes.keys().copied().collect()
    }

    /// Count of managed processes.
    pub fn len(&self) -> usize {
        self.processes.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.processes.is_empty()
    }

    /// Get all processes.
    pub fn all(&self) -> &BTreeMap<u32, LldbInferiorProcess> {
        &self.processes
    }

    /// Get all alive (non-exited) processes.
    pub fn alive(&self) -> Vec<&LldbInferiorProcess> {
        self.processes.values().filter(|p| p.is_alive()).collect()
    }

    /// Get total thread count across all processes.
    pub fn total_thread_count(&self) -> usize {
        self.processes.values().map(|p| p.threads.len()).sum()
    }

    /// Build process info list for the common agent interface.
    pub fn build_process_info_list(&self) -> Vec<ProcessInfo> {
        self.processes
            .values()
            .map(|p| p.to_process_info())
            .collect()
    }

    /// Set the list of available processes (from platform query).
    ///
    /// Ported from `put_available` in the Python agent.
    pub fn set_available(&mut self, available: Vec<LldbAvailableProcess>) {
        self.available = available;
    }

    /// Add an available process.
    pub fn add_available(&mut self, proc: LldbAvailableProcess) {
        self.available.push(proc);
    }

    /// Clear the available processes list.
    pub fn clear_available(&mut self) {
        self.available.clear();
    }

    /// Get the available processes.
    pub fn available(&self) -> &[LldbAvailableProcess] {
        &self.available
    }

    /// Get the number of available processes.
    pub fn available_count(&self) -> usize {
        self.available.len()
    }

    /// Find an available process by PID.
    pub fn find_available(&self, pid: u64) -> Option<&LldbAvailableProcess> {
        self.available.iter().find(|a| a.pid == pid)
    }

    /// Build the retain keys for available process children.
    pub fn build_available_retain_keys(&self) -> Vec<String> {
        self.available
            .iter()
            .map(|a| format!("[{}]", a.pid))
            .collect()
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
        assert!(p.breakpoint_ids.is_empty());
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
        assert_eq!(p.modules[0].info.name, "libc.so.6");

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
        assert_eq!(p.modules[0].info.base, 0x7ffff7c00000);

        p.clear_modules();
        assert!(p.modules.is_empty());
    }

    #[test]
    fn test_process_module_with_sections() {
        let mut p = LldbInferiorProcess::new(1, 0);
        let mut mod_ws = LldbModuleWithSections::from_info(ModuleInfo {
            name: "libSystem.B.dylib".to_string(),
            base: 0x7fff20000000,
            size: 0x100000,
            build_id: None,
            debug_path: None,
            load_path: None,
        });
        mod_ws.add_section(LldbModuleSection::new("__TEXT.__text", 0x7fff20001000, 0x7fff20080000));
        mod_ws.add_section(LldbModuleSection::new("__DATA.__data", 0x7fff20080000, 0x7fff20100000));
        p.add_module_with_sections(mod_ws);

        let m = p.get_module("libSystem.B.dylib").unwrap();
        assert_eq!(m.section_count(), 2);
        assert!(m.sections.contains_key("__TEXT.__text"));
        assert!(m.sections.contains_key("__DATA.__data"));

        let text = m.sections.get("__TEXT.__text").unwrap();
        assert_eq!(text.size(), 0x7fff20080000 - 0x7fff20001000);
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
        assert!(values.iter().any(|(k, _v)| k == "_state"));
        assert!(values.iter().any(|(k, _v)| k == "_display"));
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

    #[test]
    fn test_threads_sorted() {
        let mut p = LldbInferiorProcess::new(1, 0);
        p.add_thread(LldbThread::new(3, 0));
        p.add_thread(LldbThread::new(1, 0));
        p.add_thread(LldbThread::new(2, 0));
        let sorted = p.threads_sorted();
        assert_eq!(sorted[0].index, 1);
        assert_eq!(sorted[1].index, 2);
        assert_eq!(sorted[2].index, 3);
    }

    #[test]
    fn test_running_stopped_threads() {
        let mut p = LldbInferiorProcess::new(1, 0);
        p.add_thread(LldbThread::new(1, 0).with_state(ExecutionState::Running));
        p.add_thread(LldbThread::new(2, 0).with_state(ExecutionState::Stopped));
        p.add_thread(LldbThread::new(3, 0).with_state(ExecutionState::Running));
        assert_eq!(p.running_threads().len(), 2);
        assert_eq!(p.stopped_threads().len(), 1);
    }

    #[test]
    fn test_thread_state_counts() {
        let mut p = LldbInferiorProcess::new(1, 0);
        p.add_thread(LldbThread::new(1, 0).with_state(ExecutionState::Running));
        p.add_thread(LldbThread::new(2, 0).with_state(ExecutionState::Running));
        p.add_thread(LldbThread::new(3, 0).with_state(ExecutionState::Stopped));
        let counts = p.thread_state_counts();
        assert_eq!(counts.get(&ExecutionState::Running), Some(&2));
        assert_eq!(counts.get(&ExecutionState::Stopped), Some(&1));
    }

    #[test]
    fn test_module_at_address() {
        let mut p = LldbInferiorProcess::new(1, 0);
        p.add_module(ModuleInfo {
            name: "libc.so.6".to_string(),
            base: 0x7ffff7a00000,
            size: 0x1e6000,
            build_id: None,
            debug_path: None,
            load_path: None,
        });
        assert!(p.module_at_address(0x7ffff7a00000).is_some());
        assert!(p.module_at_address(0x7ffff7be5fff).is_some());
        assert!(p.module_at_address(0x7ffff7be6000).is_none());
        assert!(p.module_at_address(0x100000).is_none());
    }

    #[test]
    fn test_modules_sorted() {
        let mut p = LldbInferiorProcess::new(1, 0);
        p.add_module(ModuleInfo {
            name: "b.so".to_string(),
            base: 0x2000,
            size: 0x1000,
            build_id: None,
            debug_path: None,
            load_path: None,
        });
        p.add_module(ModuleInfo {
            name: "a.so".to_string(),
            base: 0x1000,
            size: 0x1000,
            build_id: None,
            debug_path: None,
            load_path: None,
        });
        let sorted = p.modules_sorted();
        assert_eq!(sorted[0].info.name, "a.so");
        assert_eq!(sorted[1].info.name, "b.so");
    }

    #[test]
    fn test_memory_region_at() {
        let mut p = LldbInferiorProcess::new(1, 0);
        p.add_memory_region(MemoryRegion {
            base: 0x1000,
            size: 0x2000,
            offset: 0,
            permissions: "r-xp".to_string(),
            object_file: "a.out".to_string(),
        });
        assert!(p.memory_region_at(0x1000).is_some());
        assert!(p.memory_region_at(0x2fff).is_some());
        assert!(p.memory_region_at(0x3000).is_none());
    }

    #[test]
    fn test_memory_footprint() {
        let mut p = LldbInferiorProcess::new(1, 0);
        p.add_memory_region(MemoryRegion {
            base: 0x1000,
            size: 0x2000,
            offset: 0,
            permissions: "r-xp".to_string(),
            object_file: "a.out".to_string(),
        });
        p.add_memory_region(MemoryRegion {
            base: 0x5000,
            size: 0x1000,
            offset: 0,
            permissions: "rw-p".to_string(),
            object_file: "libc.so".to_string(),
        });
        assert_eq!(p.memory_footprint(), 0x3000);
    }

    #[test]
    fn test_build_threads_container_values() {
        let mut p = LldbInferiorProcess::new(1, 0);
        p.add_thread(LldbThread::new(1, 0));
        p.add_thread(LldbThread::new(2, 0));
        let values = p.build_threads_container_values();
        assert!(values.iter().any(|(k, v)| k == "_count" && v == "2"));
    }

    #[test]
    fn test_build_modules_container_values() {
        let mut p = LldbInferiorProcess::new(1, 0);
        p.add_module(ModuleInfo {
            name: "test.so".to_string(),
            base: 0x1000,
            size: 0x1000,
            build_id: None,
            debug_path: None,
            load_path: None,
        });
        let values = p.build_modules_container_values();
        assert!(values.iter().any(|(k, v)| k == "_count" && v == "1"));
    }

    #[test]
    fn test_process_is_address_mapped() {
        let mut p = LldbInferiorProcess::new(1, 0);
        p.add_memory_region(MemoryRegion {
            base: 0x400000,
            size: 0x1000,
            offset: 0,
            permissions: "r-xp".to_string(),
            object_file: "test".to_string(),
        });
        assert!(p.is_address_mapped(0x400000));
        assert!(p.is_address_mapped(0x400500));
        assert!(!p.is_address_mapped(0x500000));
        assert!(!p.is_address_mapped(0x300000));
    }

    #[test]
    fn test_process_refresh_state() {
        let mut p = LldbInferiorProcess::new(1, 0);
        p.add_thread(LldbThread::new(1, 0).with_state(ExecutionState::Running));
        p.add_thread(LldbThread::new(2, 0).with_state(ExecutionState::Stopped));
        p.refresh_state();
        assert_eq!(p.state, ExecutionState::Running);
    }

    #[test]
    fn test_process_breakpoint_ids() {
        let mut p = LldbInferiorProcess::new(1, 0);
        p.add_breakpoint_id(1);
        p.add_breakpoint_id(2);
        p.add_breakpoint_id(1); // duplicate
        assert_eq!(p.breakpoint_ids.len(), 2);
        p.remove_breakpoint_id(1);
        assert_eq!(p.breakpoint_ids.len(), 1);
        assert_eq!(p.breakpoint_ids[0], 2);
    }

    #[test]
    fn test_process_retain_keys() {
        let mut p = LldbInferiorProcess::new(1, 0);
        p.add_thread(LldbThread::new(1, 0));
        p.add_thread(LldbThread::new(3, 0));
        let keys = p.build_thread_retain_keys();
        assert!(keys.contains(&"[1]".to_string()));
        assert!(keys.contains(&"[3]".to_string()));
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_module_section() {
        let sec = LldbModuleSection::new("__TEXT.__text", 0x1000, 0x5000)
            .with_offset(0x1000)
            .with_attrs(vec!["code".to_string(), "instructions".to_string()]);
        assert_eq!(sec.name, "__TEXT.__text");
        assert_eq!(sec.size(), 0x4000);
        assert_eq!(
            sec.trace_path(1, "libSystem.B.dylib"),
            "Processes[1].Modules[libSystem.B.dylib].Sections[__TEXT.__text]"
        );
        let vals = sec.build_trace_values();
        assert!(vals.iter().any(|(k, _)| k == "Range"));
        assert!(vals.iter().any(|(k, _)| k == "Offset"));
        assert!(vals.iter().any(|(k, _)| k == "Attrs"));
    }

    #[test]
    fn test_module_section_zero_size() {
        let sec = LldbModuleSection::new("__DATA.__bss", 0x5000, 0x5000);
        let vals = sec.build_trace_values();
        assert!(vals.iter().any(|(k, _)| k == "Address"));
    }

    #[test]
    fn test_snapshot() {
        let snap = LldbSnapshot::new(0, "Stopped").with_timestamp(1234567890);
        assert_eq!(snap.id, 0);
        assert_eq!(snap.description, "Stopped");
        assert_eq!(snap.timestamp, Some(1234567890));
    }

    #[test]
    fn test_process_sync_state() {
        let mut state = LldbProcessSyncState::new();
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
        let mut state = LldbProcessSyncState::new();
        assert!(!state.take_modules_dirty());

        state.mark_modules_dirty();
        assert!(state.take_modules_dirty());
        assert!(!state.take_modules_dirty()); // consumed

        state.mark_threads_dirty();
        state.mark_breaks_dirty();
        assert!(state.take_threads_dirty());
        assert!(state.take_breaks_dirty());
    }

    #[test]
    fn test_process_sync_state_regions() {
        let mut state = LldbProcessSyncState::new();
        let regions = vec![MemoryRegion {
            base: 0x400000,
            size: 0x1000,
            offset: 0,
            permissions: "r-xp".to_string(),
            object_file: "test".to_string(),
        }];
        assert!(state.regions_changed(&regions));
        state.update_regions(regions.clone());
        assert!(!state.regions_changed(&regions));

        let different = vec![MemoryRegion {
            base: 0x500000,
            size: 0x1000,
            offset: 0,
            permissions: "r-xp".to_string(),
            object_file: "test".to_string(),
        }];
        assert!(state.regions_changed(&different));
    }

    #[test]
    fn test_process_sync_state_snapshots() {
        let mut state = LldbProcessSyncState::new();
        state.create_snapshot("Stopped");
        state.create_snapshot("Continued");
        state.create_snapshot("Stopped");
        assert_eq!(state.snapshots.len(), 3);
        assert_eq!(state.snapshots[0].id, 0);
        assert_eq!(state.snapshots[1].id, 1);
        assert_eq!(state.snapshots[2].id, 2);
    }
}

#[cfg(test)]
mod signal_tests {
    use super::*;

    #[test]
    fn test_signal_config() {
        let sig = LldbSignalConfig::new(11, "SIGSEGV")
            .with_stop(true)
            .with_description("Segmentation fault");
        assert_eq!(sig.number, 11);
        assert_eq!(sig.name, "SIGSEGV");
        assert!(sig.stop);
        assert!(sig.description.is_some());
    }

    #[test]
    fn test_signal_table() {
        let mut table = LldbSignalTable::new();
        assert!(table.is_empty());
        table.populate_defaults();
        assert!(!table.is_empty());
        assert!(table.len() > 10);
        assert!(table.get(11).is_some());
        assert_eq!(table.get(11).unwrap().name, "SIGSEGV");
        assert!(!table.stopping_signals().is_empty());
    }
}

#[cfg(test)]
mod launch_tests {
    use super::*;

    #[test]
    fn test_launch_config() {
        let cfg = LldbLaunchConfig::new("/usr/bin/ls")
            .with_arg("-la")
            .with_working_dir("/tmp")
            .with_disable_aslr(true)
            .with_stop_at_entry(true);
        assert_eq!(cfg.executable, "/usr/bin/ls");
        assert_eq!(cfg.arguments, vec!["-la"]);
        assert!(cfg.disable_aslr);
        assert!(cfg.stop_at_entry);
    }

    #[test]
    fn test_launch_config_command() {
        let cfg = LldbLaunchConfig::new("/usr/bin/ls").with_arg("-la");
        let cmd = cfg.build_command();
        assert!(cmd.contains("file /usr/bin/ls"));
        assert!(cmd.contains("-la"));
    }

    #[test]
    fn test_attach_config_pid() {
        let cfg = LldbAttachConfig::by_pid(1234);
        assert_eq!(cfg.pid, Some(1234));
        assert!(cfg.stop_at_entry);
        assert_eq!(cfg.build_command(), "process attach --pid 1234");
    }

    #[test]
    fn test_attach_config_name() {
        let cfg = LldbAttachConfig::by_name("myapp");
        assert_eq!(cfg.name.as_deref(), Some("myapp"));
        assert_eq!(cfg.build_command(), "process attach --name myapp");
    }
}

#[cfg(test)]
mod target_tests {
    use super::*;

    #[test]
    fn test_target_info() {
        let info = LldbTargetInfo::new("x86_64-apple-macosx")
            .with_platform("remote-macosx")
            .with_pointer_size(8);
        assert_eq!(info.arch(), "x86_64");
        assert_eq!(info.platform, "remote-macosx");
        assert_eq!(info.endian_str(), "little");
    }
}

#[cfg(test)]
mod breakpoint_tests {
    use super::*;

    #[test]
    fn test_process_breakpoint() {
        let bp = LldbProcessBreakpoint::new(1)
            .with_address(0x401000)
            .with_hardware(true);
        assert_eq!(bp.id, 1);
        assert_eq!(bp.resolved_address, Some(0x401000));
        assert!(bp.hardware);
        assert_eq!(bp.hit_count, 0);
        assert!(bp.should_stop());
    }

    #[test]
    fn test_breakpoint_ignore_count() {
        let mut bp = LldbProcessBreakpoint::new(1).with_address(0x401000);
        bp.ignore_count = 2;
        // Before any hits, should stop (hit_count == 0 always stops)
        assert!(bp.should_stop());
        // First two hits should not stop (still within ignore count)
        bp.record_hit();
        assert!(!bp.should_stop());
        bp.record_hit();
        assert!(!bp.should_stop());
        // Third hit should stop (hit_count 3 > ignore_count 2)
        bp.record_hit();
        assert!(bp.should_stop());
    }

    #[test]
    fn test_breakpoint_disabled() {
        let mut bp = LldbProcessBreakpoint::new(1).with_address(0x401000);
        bp.enabled = false;
        assert!(!bp.should_stop());
    }
}

#[cfg(test)]
mod manager_tests {
    use super::*;

    #[test]
    fn test_process_manager() {
        let mut mgr = LldbProcessManager::new();
        assert!(mgr.is_empty());

        mgr.add(LldbInferiorProcess::new(100, 0));
        mgr.add(LldbInferiorProcess::new(200, 1));
        assert_eq!(mgr.len(), 2);
        assert_eq!(mgr.active_index(), Some(0));

        mgr.set_active(1);
        assert_eq!(mgr.active_index(), Some(1));
        assert!(mgr.active().is_some());
        assert_eq!(mgr.active().unwrap().pid, 200);
    }

    #[test]
    fn test_process_manager_remove() {
        let mut mgr = LldbProcessManager::new();
        mgr.add(LldbInferiorProcess::new(100, 0));
        mgr.add(LldbInferiorProcess::new(200, 1));

        let removed = mgr.remove(0);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().pid, 100);
        assert_eq!(mgr.len(), 1);
        // Active should have shifted since we removed the active one
        assert_eq!(mgr.active_index(), Some(1));
    }

    #[test]
    fn test_process_manager_alive() {
        let mut mgr = LldbProcessManager::new();
        let mut p1 = LldbInferiorProcess::new(100, 0);
        p1.state = ExecutionState::Stopped;
        let mut p2 = LldbInferiorProcess::new(200, 1);
        p2.state = ExecutionState::Exited;
        mgr.add(p1);
        mgr.add(p2);
        assert_eq!(mgr.alive().len(), 1);
    }

    #[test]
    fn test_process_manager_total_threads() {
        let mut mgr = LldbProcessManager::new();
        let mut p1 = LldbInferiorProcess::new(100, 0);
        p1.add_thread(LldbThread::new(1, 0));
        p1.add_thread(LldbThread::new(2, 0));
        let mut p2 = LldbInferiorProcess::new(200, 1);
        p2.add_thread(LldbThread::new(1, 1));
        mgr.add(p1);
        mgr.add(p2);
        assert_eq!(mgr.total_thread_count(), 3);
    }

    #[test]
    fn test_process_manager_build_info_list() {
        let mut mgr = LldbProcessManager::new();
        let mut p1 = LldbInferiorProcess::new(100, 0);
        p1.state = ExecutionState::Stopped;
        mgr.add(p1);
        let list = mgr.build_process_info_list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, 100);
    }

    #[test]
    fn test_process_manager_available() {
        let mut mgr = LldbProcessManager::new();
        assert_eq!(mgr.available_count(), 0);

        mgr.add_available(LldbAvailableProcess::new(1234, "bash", "/bin/bash"));
        mgr.add_available(LldbAvailableProcess::new(5678, "python3", "/usr/bin/python3"));
        assert_eq!(mgr.available_count(), 2);

        let found = mgr.find_available(1234);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "bash");

        assert!(mgr.find_available(9999).is_none());

        let keys = mgr.build_available_retain_keys();
        assert!(keys.contains(&"[1234]".to_string()));
        assert!(keys.contains(&"[5678]".to_string()));

        mgr.clear_available();
        assert_eq!(mgr.available_count(), 0);
    }
}

#[cfg(test)]
mod breakpoint_type_tests {
    use super::*;

    #[test]
    fn test_breakpoint_type_is_watchpoint() {
        assert!(!LldbBreakpointType::Breakpoint.is_watchpoint());
        assert!(!LldbBreakpointType::HardwareBreakpoint.is_watchpoint());
        assert!(LldbBreakpointType::WriteWatchpoint.is_watchpoint());
        assert!(LldbBreakpointType::ReadWatchpoint.is_watchpoint());
        assert!(LldbBreakpointType::AccessWatchpoint.is_watchpoint());
    }

    #[test]
    fn test_breakpoint_type_kinds_str() {
        assert_eq!(LldbBreakpointType::Breakpoint.to_kinds_str(), "x");
        assert_eq!(LldbBreakpointType::HardwareBreakpoint.to_kinds_str(), "X");
        assert_eq!(LldbBreakpointType::WriteWatchpoint.to_kinds_str(), "w");
        assert_eq!(LldbBreakpointType::ReadWatchpoint.to_kinds_str(), "r");
        assert_eq!(LldbBreakpointType::AccessWatchpoint.to_kinds_str(), "a");
    }

    #[test]
    fn test_breakpoint_auto_continue() {
        let bp = LldbProcessBreakpoint::new(1)
            .with_address(0x401000)
            .with_auto_continue(true);
        assert!(!bp.should_stop()); // auto-continue prevents stop

        let bp = LldbProcessBreakpoint::new(2)
            .with_address(0x401000)
            .with_auto_continue(false);
        assert!(bp.should_stop());
    }

    #[test]
    fn test_breakpoint_with_type() {
        let bp = LldbProcessBreakpoint::new(1)
            .with_type(LldbBreakpointType::HardwareBreakpoint);
        assert_eq!(bp.bp_type, LldbBreakpointType::HardwareBreakpoint);
    }

    #[test]
    fn test_breakpoint_with_command() {
        let bp = LldbProcessBreakpoint::new(1)
            .with_command("print $rax")
            .with_command("bt");
        assert_eq!(bp.commands.len(), 2);
        assert_eq!(bp.commands[0], "print $rax");
    }

    #[test]
    fn test_breakpoint_build_trace_values() {
        let bp = LldbProcessBreakpoint::new(1)
            .with_address(0x401000)
            .with_condition("rax == 0")
            .with_command("bt");
        let vals = bp.build_trace_values();
        assert!(vals.iter().any(|(k, v)| k == "Enabled" && v == "true"));
        assert!(vals.iter().any(|(k, v)| k == "Kinds" && v == "x"));
        assert!(vals.iter().any(|(k, v)| k == "Condition" && v == "rax == 0"));
        assert!(vals.iter().any(|(k, v)| k == "Commands" && v == "bt"));
    }
}

#[cfg(test)]
mod watchpoint_tests {
    use super::*;

    #[test]
    fn test_watchpoint_config() {
        let wp = LldbWatchpointConfig::new(1, 0x7fff0000, 8)
            .with_type(LldbWatchpointType::Write)
            .with_enabled(true);
        assert_eq!(wp.id, 1);
        assert_eq!(wp.address, 0x7fff0000);
        assert_eq!(wp.size, 8);
        assert_eq!(wp.watch_type, LldbWatchpointType::Write);
        assert!(wp.enabled);
    }

    #[test]
    fn test_watchpoint_address_range() {
        let wp = LldbWatchpointConfig::new(1, 0x1000, 4);
        let (start, end) = wp.address_range();
        assert_eq!(start, 0x1000);
        assert_eq!(end, 0x1004);
    }

    #[test]
    fn test_watchpoint_hit() {
        let mut wp = LldbWatchpointConfig::new(1, 0x1000, 8);
        assert_eq!(wp.hit_count, 0);
        wp.record_hit();
        assert_eq!(wp.hit_count, 1);
        wp.record_hit();
        assert_eq!(wp.hit_count, 2);
    }

    #[test]
    fn test_watchpoint_type_from_lldb() {
        assert_eq!(
            LldbWatchpointType::from_lldb_watch_type(true, true),
            LldbWatchpointType::Access
        );
        assert_eq!(
            LldbWatchpointType::from_lldb_watch_type(true, false),
            LldbWatchpointType::Read
        );
        assert_eq!(
            LldbWatchpointType::from_lldb_watch_type(false, true),
            LldbWatchpointType::Write
        );
    }

    #[test]
    fn test_watchpoint_type_kinds_str() {
        assert_eq!(LldbWatchpointType::Write.to_kinds_str(), "w");
        assert_eq!(LldbWatchpointType::Read.to_kinds_str(), "r");
        assert_eq!(LldbWatchpointType::Access.to_kinds_str(), "a");
    }

    #[test]
    fn test_watchpoint_build_trace_values() {
        let wp = LldbWatchpointConfig::new(1, 0x1000, 4)
            .with_type(LldbWatchpointType::Write)
            .with_condition("x == 5");
        let vals = wp.build_trace_values();
        assert!(vals.iter().any(|(k, v)| k == "Enabled" && v == "true"));
        assert!(vals.iter().any(|(k, v)| k == "Kinds" && v == "w"));
        assert!(vals.iter().any(|(k, _)| k == "Range"));
        assert!(vals.iter().any(|(k, v)| k == "Condition" && v == "x == 5"));
    }

    #[test]
    fn test_watchpoint_with_command() {
        let wp = LldbWatchpointConfig::new(1, 0x1000, 8)
            .with_command("bt")
            .with_command("register read");
        assert_eq!(wp.commands.len(), 2);
    }
}

#[cfg(test)]
mod available_process_tests {
    use super::*;

    #[test]
    fn test_available_process() {
        let ap = LldbAvailableProcess::new(1234, "bash", "/bin/bash");
        assert_eq!(ap.pid, 1234);
        assert_eq!(ap.name, "bash");
        assert_eq!(ap.executable, "/bin/bash");
        assert!(ap.display().contains("1234"));
        assert!(ap.display().contains("/bin/bash"));
    }

    #[test]
    fn test_available_process_trace_values() {
        let ap = LldbAvailableProcess::new(42, "test", "/usr/bin/test");
        let vals = ap.build_trace_values();
        assert!(vals.iter().any(|(k, v)| k == "PID" && v == "42"));
        assert!(vals.iter().any(|(k, v)| k == "Name" && v == "test"));
        assert!(vals.iter().any(|(k, _)| k == "_display"));
    }
}

#[cfg(test)]
mod register_bank_tests {
    use super::*;

    #[test]
    fn test_register_bank() {
        let bank = LldbRegisterBank::new("General Purpose Registers")
            .with_registers(vec![
                "rax".to_string(),
                "rbx".to_string(),
                "rcx".to_string(),
            ]);
        assert_eq!(bank.name, "General Purpose Registers");
        assert_eq!(bank.count, 3);
        assert!(bank.is_primary());
        assert_eq!(bank.register_names.len(), 3);
    }

    #[test]
    fn test_register_bank_not_primary() {
        let bank = LldbRegisterBank::new("Floating Point Registers");
        assert!(!bank.is_primary());
    }
}

#[cfg(test)]
mod memory_access_tests {
    use super::*;

    #[test]
    fn test_memory_access_from_perms() {
        let acc = LldbMemoryAccess::from_perms("rwx");
        assert!(acc.readable);
        assert!(acc.writable);
        assert!(acc.executable);

        let acc = LldbMemoryAccess::from_perms("r-xp");
        assert!(acc.readable);
        assert!(!acc.writable);
        assert!(acc.executable);

        let acc = LldbMemoryAccess::from_perms("---p");
        assert!(!acc.readable);
        assert!(!acc.writable);
        assert!(!acc.executable);
    }

    #[test]
    fn test_memory_access_to_perms() {
        let acc = LldbMemoryAccess::new(true, true, true);
        assert_eq!(acc.to_perms(), "rwxp");

        let acc = LldbMemoryAccess::new(true, false, true);
        assert_eq!(acc.to_perms(), "r-xp");
    }

    #[test]
    fn test_memory_access_build_trace_values() {
        let acc = LldbMemoryAccess::new(true, false, true);
        let vals = acc.build_trace_values();
        assert!(vals.iter().any(|(k, v)| k == "Permissions" && v == "r-xp"));
        assert!(vals.iter().any(|(k, v)| k == "_readable" && v == "true"));
        assert!(vals.iter().any(|(k, v)| k == "_writable" && v == "false"));
        assert!(vals.iter().any(|(k, v)| k == "_executable" && v == "true"));
    }

    #[test]
    fn test_memory_access_default() {
        let acc = LldbMemoryAccess::default();
        assert!(acc.readable);
        assert!(!acc.writable);
        assert!(!acc.executable);
    }
}

#[cfg(test)]
mod process_watchpoint_tests {
    use super::*;

    #[test]
    fn test_process_watchpoint_management() {
        let mut p = LldbInferiorProcess::new(1, 0);
        assert_eq!(p.watchpoint_count(), 0);

        p.add_watchpoint(LldbWatchpointConfig::new(1, 0x1000, 8));
        p.add_watchpoint(LldbWatchpointConfig::new(2, 0x2000, 4));
        assert_eq!(p.watchpoint_count(), 2);

        let wp = p.get_watchpoint(1);
        assert!(wp.is_some());
        assert_eq!(wp.unwrap().address, 0x1000);

        let removed = p.remove_watchpoint(1);
        assert!(removed.is_some());
        assert_eq!(p.watchpoint_count(), 1);
        assert!(p.get_watchpoint(1).is_none());
    }

    #[test]
    fn test_process_watchpoint_at_address() {
        let mut p = LldbInferiorProcess::new(1, 0);
        p.add_watchpoint(LldbWatchpointConfig::new(1, 0x1000, 8));

        assert!(p.watchpoint_at_address(0x1000).is_some());
        assert!(p.watchpoint_at_address(0x1007).is_some());
        assert!(p.watchpoint_at_address(0x1008).is_none());
        assert!(p.watchpoint_at_address(0x0fff).is_none());
    }

    #[test]
    fn test_process_build_watchpoints_container_values() {
        let mut p = LldbInferiorProcess::new(1, 0);
        p.add_watchpoint(LldbWatchpointConfig::new(1, 0x1000, 8));
        p.add_watchpoint(LldbWatchpointConfig::new(2, 0x2000, 4));
        let vals = p.build_watchpoints_container_values();
        assert!(vals.iter().any(|(k, v)| k == "_count" && v == "2"));
    }

    #[test]
    fn test_process_build_watchpoint_retain_keys() {
        let mut p = LldbInferiorProcess::new(1, 0);
        p.add_watchpoint(LldbWatchpointConfig::new(1, 0x1000, 8));
        p.add_watchpoint(LldbWatchpointConfig::new(3, 0x3000, 4));
        let keys = p.build_watchpoint_retain_keys();
        assert!(keys.contains(&"[1]".to_string()));
        assert!(keys.contains(&"[3]".to_string()));
        assert_eq!(keys.len(), 2);
    }
}
