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
//! `put_inferior_state`, `put_regions`, `put_modules`, etc.) and the Ghidra
//! `Inferior` concept.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use super::gdb_thread::GdbThread;
use crate::agents::{
    ExecutionState, MemoryRegion, ModuleInfo, ProcessInfo, RegisterValue,
};

/// A process available on the system (from `info os processes`).
///
/// Ported from the Python `Available` dataclass in `util.py`.
/// These are processes visible on the OS that can potentially be
/// attached to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailableProcess {
    /// OS process ID.
    pub pid: u32,
    /// User running the process.
    pub user: String,
    /// Command line / process name.
    pub command: String,
}

impl AvailableProcess {
    /// Create a new available process entry.
    pub fn new(pid: u32, user: impl Into<String>, command: impl Into<String>) -> Self {
        Self {
            pid,
            user: user.into(),
            command: command.into(),
        }
    }

    /// Parse from `info os processes` output line.
    ///
    /// Expected format: `PID USER COMMAND`
    pub fn from_info_line(line: &str) -> Option<Self> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let pid = parts[0].parse::<u32>().ok()?;
            let user = parts[1].to_string();
            let command = parts[2..].join(" ");
            Some(Self { pid, user, command })
        } else {
            None
        }
    }
}

/// A breakpoint location within a breakpoint.
///
/// Ported from the Python `BreakpointLocation` dataclass in `util.py`.
/// GDB breakpoints can have multiple locations (e.g., inlined functions
/// or template instantiations).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreakpointLocationInfo {
    /// Resolved address of this location.
    pub address: u64,
    /// Whether this location is enabled.
    pub enabled: bool,
    /// Thread group (inferior) IDs this location applies to.
    pub thread_groups: Vec<u32>,
}

impl BreakpointLocationInfo {
    /// Create a new breakpoint location.
    pub fn new(address: u64, enabled: bool) -> Self {
        Self {
            address,
            enabled,
            thread_groups: Vec::new(),
        }
    }

    /// Add a thread group (inferior) this location applies to.
    pub fn with_thread_group(mut self, inf_num: u32) -> Self {
        self.thread_groups.push(inf_num);
        self
    }

    /// Set thread groups.
    pub fn with_thread_groups(mut self, groups: Vec<u32>) -> Self {
        self.thread_groups = groups;
        self
    }
}

/// A module section within a loaded module.
///
/// Sections correspond to ELF sections (e.g., `.text`, `.data`, `.bss`)
/// or PE sections. Ported from the Python `Section` class in `util.py`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleSection {
    /// Section name (e.g., ".text", ".data").
    pub name: String,
    /// Start address of the section.
    pub start: u64,
    /// End address (exclusive) of the section.
    pub end: u64,
    /// File offset of the section.
    pub offset: u64,
    /// Section attributes (e.g., flags like "alloc", "load").
    pub attrs: Vec<String>,
}

impl ModuleSection {
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
    pub fn trace_path(&self, inferior_num: u32, module_name: &str) -> String {
        format!(
            "Inferiors[{}].Modules[{}].Sections[{}]",
            inferior_num, module_name, self.name
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
pub struct ModuleWithSections {
    /// Base module info.
    pub info: ModuleInfo,
    /// Sections within this module, keyed by section name.
    pub sections: BTreeMap<String, ModuleSection>,
}

impl ModuleWithSections {
    /// Create from a `ModuleInfo`.
    pub fn from_info(info: ModuleInfo) -> Self {
        Self {
            info,
            sections: BTreeMap::new(),
        }
    }

    /// Add a section. Replaces if same name exists.
    pub fn add_section(&mut self, section: ModuleSection) {
        self.sections.insert(section.name.clone(), section);
    }

    /// Remove a section by name.
    pub fn remove_section(&mut self, name: &str) -> Option<ModuleSection> {
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
    pub fn sections_path(&self, inferior_num: u32) -> String {
        format!(
            "Inferiors[{}].Modules[{}].Sections",
            inferior_num, self.info.name
        )
    }
}

/// Snapshot descriptor for trace recording.
///
/// Ported from the Python `snapshot` calls in `commands.py` and `hooks.py`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// Snapshot ID (sequential).
    pub id: u64,
    /// Description (e.g., "Stopped", "Exited with code 0").
    pub description: String,
    /// Timestamp (unix epoch millis, if available).
    pub timestamp: Option<u64>,
}

impl Snapshot {
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

/// Tracks the synchronization state for an inferior between stops.
///
/// Ported from the Python `InferiorState` class in `hooks.py`. Tracks
/// which aspects of the inferior have changed and need re-sync.
#[derive(Debug, Clone)]
pub struct InferiorSyncState {
    /// Whether this is the first recording for this inferior.
    pub first: bool,
    /// Last known memory regions (for change detection).
    pub regions: Vec<MemoryRegion>,
    /// Whether modules have changed since last stop.
    pub modules_dirty: bool,
    /// Whether threads have changed since last stop.
    pub threads_dirty: bool,
    /// Whether breakpoints have changed since last stop.
    pub breaks_dirty: bool,
    /// Visited (thread, frame_level) pairs since last stop.
    pub visited: BTreeSet<(u32, u32)>,
    /// Snapshots recorded for this inferior.
    pub snapshots: Vec<Snapshot>,
    /// Next snapshot ID.
    next_snap_id: u64,
}

impl Default for InferiorSyncState {
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

impl InferiorSyncState {
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
    pub fn create_snapshot(&mut self, description: impl Into<String>) -> &Snapshot {
        let snap = Snapshot::new(self.next_snap_id, description);
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
        // Compare by base address and size for efficiency
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
    pub modules: Vec<ModuleWithSections>,
    /// Memory regions (mapped address ranges).
    pub memory_regions: Vec<MemoryRegion>,
    /// Whether this inferior has been synchronized to the trace.
    pub synced: bool,
    /// Exit code, if the inferior has terminated.
    pub exit_code: Option<i32>,
    /// Breakpoint IDs associated with this inferior.
    pub breakpoint_ids: Vec<u32>,
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
            breakpoint_ids: Vec::new(),
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

    /// Get the trace path for a specific breakpoint location in this inferior.
    pub fn breakpoint_loc_path(&self, break_num: u32, loc_num: u32) -> String {
        format!("Inferiors[{}].Breakpoints[{}.{}]", self.num, break_num, loc_num)
    }

    /// Compute the overall inferior state from its threads.
    ///
    /// Ported from `compute_inf_state` in `commands.py`.
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

    /// Update this inferior's state from its threads.
    ///
    /// This sets `self.state` to the computed state from threads.
    pub fn refresh_state(&mut self) {
        self.state = self.compute_state();
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
    ///
    /// Replaces if same name exists.
    pub fn add_module(&mut self, module: ModuleInfo) {
        self.modules.retain(|m| m.info.name != module.name);
        self.modules.push(ModuleWithSections::from_info(module));
    }

    /// Add a module with sections.
    pub fn add_module_with_sections(&mut self, module: ModuleWithSections) {
        self.modules.retain(|m| m.info.name != module.info.name);
        self.modules.push(module);
    }

    /// Remove a module by name.
    pub fn remove_module(&mut self, name: &str) -> Option<ModuleWithSections> {
        if let Some(pos) = self.modules.iter().position(|m| m.info.name == name) {
            Some(self.modules.remove(pos))
        } else {
            None
        }
    }

    /// Get a module by name.
    pub fn get_module(&self, name: &str) -> Option<&ModuleWithSections> {
        self.modules.iter().find(|m| m.info.name == name)
    }

    /// Get a mutable reference to a module by name.
    pub fn get_module_mut(&mut self, name: &str) -> Option<&mut ModuleWithSections> {
        self.modules.iter_mut().find(|m| m.info.name == name)
    }

    /// Clear all modules.
    pub fn clear_modules(&mut self) {
        self.modules.clear();
    }

    /// Add a memory region.
    ///
    /// Replaces if same base exists.
    pub fn add_memory_region(&mut self, region: MemoryRegion) {
        self.memory_regions.retain(|r| r.base != region.base);
        self.memory_regions.push(region);
    }

    /// Clear all memory regions.
    pub fn clear_memory_regions(&mut self) {
        self.memory_regions.clear();
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

    /// Convert to a `ProcessInfo` for the common agent interface.
    pub fn to_process_info(&self) -> ProcessInfo {
        ProcessInfo {
            id: self.num as u64,
            state: self.compute_state(),
        }
    }

    /// Build trace object key-value pairs for this inferior.
    ///
    /// Ported from `put_inferior_state` in `commands.py`.
    pub fn build_trace_values(&self) -> Vec<(String, String)> {
        let state = self.compute_state();
        let mut values = vec![
            ("State".to_string(), state.as_trace_str().to_string()),
            ("_display".to_string(), self.display.clone()),
        ];
        if let Some(code) = self.exit_code {
            values.push(("Exit Code".to_string(), code.to_string()));
        }
        values
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
    ///
    /// Ported from `record_exited` in `hooks.py`.
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
    ///
    /// Ported from the Python thread selection logic.
    pub fn selected_thread(&self) -> Option<&GdbThread> {
        self.threads
            .values()
            .find(|t| t.state == ExecutionState::Running)
            .or_else(|| self.threads.values().find(|t| t.state == ExecutionState::Stopped))
    }

    /// Get the number of modules.
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    /// Get the number of memory regions.
    pub fn memory_region_count(&self) -> usize {
        self.memory_regions.len()
    }

    /// Build the retain keys for inferior-level object children.
    ///
    /// This is used with `retain_values` to clean up stale children.
    pub fn build_retain_keys(&self) -> Vec<String> {
        vec![format!("[{}]", self.num)]
    }

    /// Build the retain keys for thread children.
    pub fn build_thread_retain_keys(&self) -> Vec<String> {
        self.threads
            .keys()
            .map(|num| format!("[{}]", num))
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

    /// Get threads sorted by number.
    pub fn threads_sorted(&self) -> Vec<&GdbThread> {
        let mut threads: Vec<_> = self.threads.values().collect();
        threads.sort_by_key(|t| t.num);
        threads
    }

    /// Get all running threads.
    pub fn running_threads(&self) -> Vec<&GdbThread> {
        self.threads
            .values()
            .filter(|t| t.state == ExecutionState::Running)
            .collect()
    }

    /// Get all stopped threads.
    pub fn stopped_threads(&self) -> Vec<&GdbThread> {
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
    pub fn module_at_address(&self, addr: u64) -> Option<&ModuleWithSections> {
        self.modules
            .iter()
            .find(|m| addr >= m.info.base && addr < m.info.base + m.info.size)
    }

    /// Get sorted modules by base address.
    pub fn modules_sorted(&self) -> Vec<&ModuleWithSections> {
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

    /// Find a module by base address.
    ///
    /// Ported from `put_modules` which iterates modules by base.
    pub fn find_module_by_base(&self, base: u64) -> Option<&ModuleWithSections> {
        self.modules.iter().find(|m| m.info.base == base)
    }

    /// Get a sorted list of all thread numbers.
    ///
    /// Ported from the thread iteration in `put_threads`.
    pub fn sorted_thread_numbers(&self) -> Vec<u32> {
        let mut nums: Vec<u32> = self.threads.keys().copied().collect();
        nums.sort();
        nums
    }

    /// Get a sorted list of all module base addresses.
    pub fn sorted_module_bases(&self) -> Vec<u64> {
        let mut bases: Vec<u64> = self.modules.iter().map(|m| m.info.base).collect();
        bases.sort();
        bases
    }

    /// Build the display string for this inferior.
    ///
    /// Ported from `compute_name` in `commands.py`. The GDB format is
    /// `'{pid} [{infnum}]'` when a PID is known, or `'{display}'` otherwise.
    pub fn build_display_string(&self) -> String {
        match self.pid {
            Some(pid) => format!("{} [{}]", pid, self.num),
            None => self.display.clone(),
        }
    }

    /// Build extended trace values including PID and display string.
    ///
    /// Ported from `put_inferior_state` in `commands.py`.
    pub fn build_trace_values_extended(&self) -> Vec<(String, String)> {
        let state = self.compute_state();
        let mut values = vec![
            ("State".to_string(), state.as_trace_str().to_string()),
            ("_display".to_string(), self.build_display_string()),
        ];
        if let Some(pid) = self.pid {
            values.push(("PID".to_string(), format!("{}", pid)));
        }
        if let Some(code) = self.exit_code {
            values.push(("Exit Code".to_string(), code.to_string()));
        }
        values
    }

    /// Count the total number of stack frames across all threads.
    pub fn total_frame_count(&self) -> usize {
        self.threads.values().map(|t| t.frame_count()).sum()
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
}

/// Signal configuration for a GDB inferior.
///
/// GDB can intercept and handle Unix signals via the `handle` command.
/// This tracks which signals are configured to stop, print, or pass
/// through to the inferior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GdbSignalConfig {
    /// Signal number.
    pub number: i32,
    /// Signal name (e.g. "SIGSEGV").
    pub name: String,
    /// Whether this signal stops the process.
    pub stop: bool,
    /// Whether this signal prints a message.
    pub print: bool,
    /// Whether this signal is passed to the process.
    pub pass: bool,
    /// Optional description.
    pub description: Option<String>,
}

impl GdbSignalConfig {
    /// Create a new signal config.
    pub fn new(number: i32, name: impl Into<String>) -> Self {
        Self {
            number,
            name: name.into(),
            stop: true,
            print: true,
            pass: true,
            description: None,
        }
    }

    /// Set stop behavior.
    pub fn with_stop(mut self, stop: bool) -> Self {
        self.stop = stop;
        self
    }

    /// Set print behavior.
    pub fn with_print(mut self, print: bool) -> Self {
        self.print = print;
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

/// Tracks signal configurations for a GDB inferior.
///
/// Ported from GDB's `info signals` / `handle` command output.
/// Maintains the table of how each signal is handled.
#[derive(Debug, Clone, Default)]
pub struct GdbSignalTable {
    signals: BTreeMap<i32, GdbSignalConfig>,
}

impl GdbSignalTable {
    /// Create an empty signal table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a signal configuration.
    pub fn set(&mut self, config: GdbSignalConfig) {
        self.signals.insert(config.number, config);
    }

    /// Get a signal configuration by number.
    pub fn get(&self, number: i32) -> Option<&GdbSignalConfig> {
        self.signals.get(&number)
    }

    /// Get all signal configurations.
    pub fn all(&self) -> &BTreeMap<i32, GdbSignalConfig> {
        &self.signals
    }

    /// Get signals configured to stop the process.
    pub fn stopping_signals(&self) -> Vec<&GdbSignalConfig> {
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
                GdbSignalConfig::new(num, name)
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

/// Inferior-level breakpoint state.
///
/// GDB tracks breakpoints globally but they resolve per-inferior when
/// debugging multiple processes. This struct tracks resolved breakpoints
/// for a single inferior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GdbProcessBreakpoint {
    /// Breakpoint number (GDB-internal).
    pub number: u32,
    /// Resolved address in this inferior.
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
    /// Breakpoint type (breakpoint, watchpoint, etc.).
    pub bp_type: GdbProcessBreakpointType,
}

/// Type of breakpoint within a GDB inferior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GdbProcessBreakpointType {
    /// Regular software breakpoint.
    Breakpoint,
    /// Hardware breakpoint.
    HardwareBreakpoint,
    /// Write watchpoint.
    WriteWatchpoint,
    /// Read watchpoint.
    ReadWatchpoint,
    /// Access watchpoint (read/write).
    AccessWatchpoint,
}

impl GdbProcessBreakpoint {
    /// Create a new breakpoint entry.
    pub fn new(number: u32) -> Self {
        Self {
            number,
            resolved_address: None,
            enabled: true,
            hit_count: 0,
            condition: None,
            hardware: false,
            ignore_count: 0,
            bp_type: GdbProcessBreakpointType::Breakpoint,
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
            self.bp_type = GdbProcessBreakpointType::HardwareBreakpoint;
        }
        self
    }

    /// Set a condition expression.
    pub fn with_condition(mut self, cond: impl Into<String>) -> Self {
        self.condition = Some(cond.into());
        self
    }

    /// Set the breakpoint type.
    pub fn with_type(mut self, bp_type: GdbProcessBreakpointType) -> Self {
        self.bp_type = bp_type;
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
        self.hit_count == 0 || self.hit_count > self.ignore_count
    }
}

/// GDB inferior manager -- manages multiple inferiors within a single
/// GDB debug session.
///
/// GDB can debug multiple inferiors (e.g. when following forks, or via
/// `add-inferior`). This manager tracks all known inferiors and provides
/// convenient access.
#[derive(Debug, Default)]
pub struct GdbInferiorManager {
    inferiors: BTreeMap<u32, GdbInferiorProcess>,
    active_num: Option<u32>,
}

impl GdbInferiorManager {
    /// Create a new empty inferior manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an inferior.
    pub fn add(&mut self, inferior: GdbInferiorProcess) {
        let num = inferior.num;
        if self.active_num.is_none() {
            self.active_num = Some(num);
        }
        self.inferiors.insert(num, inferior);
    }

    /// Remove an inferior by number.
    pub fn remove(&mut self, num: u32) -> Option<GdbInferiorProcess> {
        let removed = self.inferiors.remove(&num);
        if self.active_num == Some(num) {
            self.active_num = self.inferiors.keys().next().copied();
        }
        removed
    }

    /// Get an inferior by number.
    pub fn get(&self, num: u32) -> Option<&GdbInferiorProcess> {
        self.inferiors.get(&num)
    }

    /// Get a mutable inferior by number.
    pub fn get_mut(&mut self, num: u32) -> Option<&mut GdbInferiorProcess> {
        self.inferiors.get_mut(&num)
    }

    /// Get the currently active inferior.
    pub fn active(&self) -> Option<&GdbInferiorProcess> {
        self.active_num.and_then(|n| self.inferiors.get(&n))
    }

    /// Get a mutable reference to the active inferior.
    pub fn active_mut(&mut self) -> Option<&mut GdbInferiorProcess> {
        self.active_num.and_then(move |n| self.inferiors.get_mut(&n))
    }

    /// Set the active inferior by number.
    pub fn set_active(&mut self, num: u32) {
        if self.inferiors.contains_key(&num) {
            self.active_num = Some(num);
        }
    }

    /// Get the active inferior number.
    pub fn active_num(&self) -> Option<u32> {
        self.active_num
    }

    /// Get all inferior numbers.
    pub fn numbers(&self) -> Vec<u32> {
        self.inferiors.keys().copied().collect()
    }

    /// Count of managed inferiors.
    pub fn len(&self) -> usize {
        self.inferiors.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.inferiors.is_empty()
    }

    /// Get all inferiors.
    pub fn all(&self) -> &BTreeMap<u32, GdbInferiorProcess> {
        &self.inferiors
    }

    /// Get all alive (non-exited) inferiors.
    pub fn alive(&self) -> Vec<&GdbInferiorProcess> {
        self.inferiors.values().filter(|p| p.is_alive()).collect()
    }

    /// Get total thread count across all inferiors.
    pub fn total_thread_count(&self) -> usize {
        self.inferiors.values().map(|p| p.threads.len()).sum()
    }

    /// Build process info list for the common agent interface.
    pub fn build_process_info_list(&self) -> Vec<ProcessInfo> {
        self.inferiors
            .values()
            .map(|p| p.to_process_info())
            .collect()
    }
}

/// Address index for fast base-address lookup from memory regions.
///
/// Ported from the Python `Index` class in `util.py`. Uses sorted
/// base addresses with binary search for efficient lookup of which
/// region a given address falls within.
#[derive(Debug, Clone)]
pub struct RegionIndex {
    /// Regions keyed by base address.
    regions: BTreeMap<u64, MemoryRegion>,
    /// Sorted base addresses for binary search.
    bases: Vec<u64>,
}

impl RegionIndex {
    /// Build an index from a list of memory regions.
    pub fn from_regions(regions: &[MemoryRegion]) -> Self {
        let mut map = BTreeMap::new();
        let mut bases = Vec::new();
        for r in regions {
            map.insert(r.base, r.clone());
            bases.push(r.base);
        }
        bases.sort();
        Self { regions: map, bases }
    }

    /// Compute the base address for a given address.
    ///
    /// Returns the base address of the region containing `address`,
    /// or `address` itself if no region contains it.
    ///
    /// Ported from `Index.compute_base` in `util.py`.
    pub fn compute_base(&self, address: u64) -> u64 {
        // Binary search: find the last base <= address
        match self.bases.binary_search(&address) {
            Ok(idx) => self.bases[idx],
            Err(0) => address,
            Err(idx) => {
                let floor = self.bases[idx - 1];
                if let Some(region) = self.regions.get(&floor) {
                    if region.base + region.size > address {
                        floor
                    } else {
                        address
                    }
                } else {
                    address
                }
            }
        }
    }

    /// Find the region containing the given address.
    pub fn find_region(&self, address: u64) -> Option<&MemoryRegion> {
        let base = self.compute_base(address);
        if base == address {
            return None;
        }
        self.regions.get(&base)
    }

    /// Check if regions have changed compared to a reference list.
    ///
    /// Ported from `RegionInfoReader.have_changed` in `util.py`.
    pub fn have_changed(&self, new_regions: &[MemoryRegion]) -> bool {
        if self.regions.len() != new_regions.len() {
            return true;
        }
        for r in new_regions {
            if self.regions.get(&r.base) != Some(r) {
                return true;
            }
        }
        false
    }

    /// Get the number of indexed regions.
    pub fn len(&self) -> usize {
        self.regions.len()
    }

    /// Check if the index is empty.
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }
}

impl Default for RegionIndex {
    fn default() -> Self {
        Self {
            regions: BTreeMap::new(),
            bases: Vec::new(),
        }
    }
}

/// GDB version-aware module info reader configuration.
///
/// Ported from the Python `ModuleInfoReader` hierarchy in `util.py`.
/// GDB's `maintenance info sections` command output format varies
/// across versions (v8, v9, v11+).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModuleInfoFormat {
    /// GDB 8.x format (`maintenance info sections ALLOBJ`).
    V8,
    /// GDB 9-10 format (v8 command, v9 section pattern).
    V9,
    /// GDB 11+ format (`maintenance info sections -all-objects`).
    V11,
}

impl ModuleInfoFormat {
    /// Choose the appropriate format for a GDB major version.
    pub fn for_gdb_version(major: u32) -> Self {
        match major {
            8 => Self::V8,
            9 | 10 => Self::V9,
            _ => Self::V11, // 11, 12, 13+
        }
    }

    /// The GDB command to list modules.
    pub fn command(&self) -> &'static str {
        match self {
            Self::V8 | Self::V9 => "maintenance info sections ALLOBJ",
            Self::V11 => "maintenance info sections -all-objects",
        }
    }

    /// Whether the format uses "Exec file" in addition to "Object file".
    pub fn has_exec_file(&self) -> bool {
        matches!(self, Self::V11)
    }
}

/// Parse region output from `info proc mappings`.
///
/// Expected format per line:
/// `START END SIZE OFFSET [PERMS] OBJFILE`
///
/// Ported from `RegionInfoReader.region_from_line` in `util.py`.
pub fn parse_proc_mapping_line(line: &str, max_addr: u64) -> Option<MemoryRegion> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }
    let start = u64::from_str_radix(parts[0].trim_start_matches("0x"), 16).ok()? & max_addr;
    let end = u64::from_str_radix(parts[1].trim_start_matches("0x"), 16).ok()? & max_addr;
    let _size = u64::from_str_radix(parts[2].trim_start_matches("0x"), 16).ok()?;
    let offset = u64::from_str_radix(parts[3].trim_start_matches("0x"), 16).ok()?;

    let (perms, objfile_start) = if parts.len() >= 5 {
        let fourth = parts[4];
        if fourth.starts_with('r') || fourth.starts_with('-') {
            (fourth.to_string(), 5)
        } else {
            ("---p".to_string(), 4)
        }
    } else {
        ("---p".to_string(), 4)
    };

    let objfile = if objfile_start < parts.len() {
        parts[objfile_start..].join(" ")
    } else {
        String::new()
    };

    Some(MemoryRegion {
        base: start,
        size: end.saturating_sub(start),
        offset,
        permissions: perms,
        object_file: objfile,
    })
}

/// Compute the maximum address for the current pointer size.
///
/// Ported from `compute_max_addr` in `util.py`.
pub fn compute_max_addr(pointer_size: usize) -> u64 {
    let bits = pointer_size * 8;
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

/// Module section info as parsed from `maintenance info sections`.
///
/// Ported from the Python `Section` dataclass in `util.py`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedSection {
    /// Section name.
    pub name: String,
    /// Virtual memory start address.
    pub vma_start: u64,
    /// Virtual memory end address.
    pub vma_end: u64,
    /// File offset.
    pub file_offset: u64,
    /// Section attributes (e.g., "CONTENTS", "ALLOC", "LOAD", "READONLY", "CODE").
    pub attrs: Vec<String>,
}

impl ParsedSection {
    /// Create a new parsed section.
    pub fn new(
        name: impl Into<String>,
        vma_start: u64,
        vma_end: u64,
        file_offset: u64,
        attrs: Vec<String>,
    ) -> Self {
        Self {
            name: name.into(),
            vma_start,
            vma_end,
            file_offset,
            attrs,
        }
    }

    /// Check if the section has the ALLOC attribute.
    pub fn is_alloc(&self) -> bool {
        self.attrs.iter().any(|a| a.to_uppercase() == "ALLOC")
    }

    /// Check if the section has the LOAD attribute.
    pub fn is_load(&self) -> bool {
        self.attrs.iter().any(|a| a.to_uppercase() == "LOAD")
    }

    /// Check if the section has the CODE attribute.
    pub fn is_code(&self) -> bool {
        self.attrs.iter().any(|a| a.to_uppercase() == "CODE")
    }

    /// Check if the section has the READONLY attribute.
    pub fn is_readonly(&self) -> bool {
        self.attrs.iter().any(|a| a.to_uppercase() == "READONLY")
    }

    /// Merge with another section's info (takes non-zero values, merges attrs).
    ///
    /// Ported from `Section.better` in `util.py`.
    pub fn merge(&self, other: &ParsedSection) -> ParsedSection {
        let start = if self.vma_start != 0 {
            self.vma_start
        } else {
            other.vma_start
        };
        let end = if self.vma_end != 0 {
            self.vma_end
        } else {
            other.vma_end
        };
        let offset = if self.file_offset != 0 {
            self.file_offset
        } else {
            other.file_offset
        };
        let mut attrs: BTreeSet<String> = self.attrs.iter().cloned().collect();
        for a in &other.attrs {
            attrs.insert(a.clone());
        }
        ParsedSection {
            name: self.name.clone(),
            vma_start: start,
            vma_end: end,
            file_offset: offset,
            attrs: attrs.into_iter().collect(),
        }
    }

    /// Get the size of the section.
    pub fn size(&self) -> u64 {
        self.vma_end.saturating_sub(self.vma_start)
    }
}

/// Parsed module info from `maintenance info sections`.
///
/// Groups sections by module (objfile) name.
#[derive(Debug, Clone)]
pub struct ParsedModule {
    /// Module (objfile) name.
    pub name: String,
    /// Sections within this module, keyed by section name.
    pub sections: BTreeMap<String, ParsedSection>,
}

impl ParsedModule {
    /// Create a new parsed module.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            sections: BTreeMap::new(),
        }
    }

    /// Add a section. Merges if same name exists.
    pub fn add_section(&mut self, section: ParsedSection) {
        if let Some(existing) = self.sections.get(&section.name) {
            let merged = existing.merge(&section);
            self.sections.insert(section.name.clone(), merged);
        } else {
            self.sections.insert(section.name.clone(), section);
        }
    }

    /// Get only the ALLOC sections.
    pub fn alloc_sections(&self) -> Vec<&ParsedSection> {
        self.sections.values().filter(|s| s.is_alloc()).collect()
    }

    /// Compute the base address from ALLOC sections.
    ///
    /// Uses the minimum VMA start of all ALLOC sections, adjusted
    /// through the region index.
    pub fn compute_base(&self, index: &RegionIndex) -> u64 {
        let alloc: Vec<&ParsedSection> = self.alloc_sections();
        if alloc.is_empty() {
            return 0;
        }
        alloc
            .iter()
            .map(|s| index.compute_base(s.vma_start))
            .min()
            .unwrap_or(0)
    }

    /// Compute the maximum address from ALLOC sections.
    pub fn compute_max_addr(&self) -> u64 {
        let alloc: Vec<&ParsedSection> = self.alloc_sections();
        if alloc.is_empty() {
            return 0;
        }
        alloc.iter().map(|s| s.vma_end).max().unwrap_or(0)
    }

    /// Convert to a `ModuleInfo` using the region index for base address computation.
    pub fn to_module_info(&self, index: &RegionIndex) -> ModuleInfo {
        let base = self.compute_base(index);
        let max_addr = self.compute_max_addr();
        ModuleInfo {
            name: self.name.clone(),
            base,
            size: max_addr.saturating_sub(base),
            build_id: None,
            debug_path: None,
            load_path: None,
        }
    }

    /// Convert to a `ModuleWithSections`.
    pub fn to_module_with_sections(&self, index: &RegionIndex) -> ModuleWithSections {
        let info = self.to_module_info(index);
        let mut mod_ws = ModuleWithSections::from_info(info);
        for sec in self.sections.values() {
            if sec.is_alloc() {
                mod_ws.add_section(ModuleSection::new(
                    &sec.name,
                    sec.vma_start,
                    sec.vma_end,
                ));
            }
        }
        mod_ws
    }
}

/// Parse a section line from `maintenance info sections`.
///
/// Handles both v8 (plain hex) and v9+ (bracket index) formats.
///
/// V8 format:
/// `0xVMA_START -> 0xVMA_END at 0xOFFSET: NAME ATTRS`
///
/// V9+ format:
/// `[IDX] 0xVMA_START -> 0xVMA_END at 0xOFFSET: NAME ATTRS`
pub fn parse_section_line(line: &str, max_addr: u64) -> Option<ParsedSection> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Try to find the pattern: 0xSTART -> 0xEND at 0xOFFSET: NAME ATTRS
    let arrow_pos = trimmed.find(" -> ")?;
    let at_pos = trimmed.find(" at ")?;
    let colon_pos = trimmed.find(':')?;

    if arrow_pos >= at_pos || at_pos >= colon_pos {
        return None;
    }

    // Extract VMA start (before " -> ")
    let vma_start_str = trimmed[..arrow_pos].trim();
    // Handle optional [IDX] prefix
    let vma_start_str = if let Some(bracket_end) = vma_start_str.rfind(']') {
        vma_start_str[bracket_end + 1..].trim()
    } else {
        vma_start_str
    };
    let vma_start = u64::from_str_radix(vma_start_str.trim_start_matches("0x"), 16).ok()? & max_addr;

    // Extract VMA end (between " -> " and " at ")
    let vma_end_str = trimmed[arrow_pos + 4..at_pos].trim();
    let vma_end = u64::from_str_radix(vma_end_str.trim_start_matches("0x"), 16).ok()? & max_addr;

    // Extract offset (between " at " and ":")
    let offset_str = trimmed[at_pos + 4..colon_pos].trim();
    let file_offset = u64::from_str_radix(offset_str.trim_start_matches("0x"), 16).ok()?;

    // Extract name and attrs (after ":")
    let rest = trimmed[colon_pos + 1..].trim();
    let rest_parts: Vec<&str> = rest.split_whitespace().collect();
    if rest_parts.is_empty() {
        return None;
    }
    let name = rest_parts[0].to_string();
    let attrs: Vec<String> = rest_parts[1..].iter().map(|s| s.to_string()).collect();

    Some(ParsedSection::new(name, vma_start, vma_end, file_offset, attrs))
}

/// Parse a module name line from `maintenance info sections`.
///
/// V8 format: `Object file: NAME`
/// V11 format: `Exec file: \`NAME', file type TYPE`
pub fn parse_module_name_line(line: &str, has_exec_file: bool) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.starts_with("Object file:") {
        let name = trimmed.strip_prefix("Object file:")?.trim();
        if name.is_empty() {
            return None;
        }
        Some(name.to_string())
    } else if has_exec_file && trimmed.starts_with("Exec file:") {
        // Format: `Exec file: \`NAME', file type TYPE`
        let rest = trimmed.strip_prefix("Exec file:")?.trim();
        if rest.starts_with('`') {
            let end = rest[1..].find('\'')?;
            Some(rest[1..1 + end].to_string())
        } else {
            Some(rest.to_string())
        }
    } else {
        None
    }
}

/// GDB convenience variable state.
///
/// GDB has "convenience variables" ($var) that can be used to track
/// state. The agent uses `_ghidra_tracing` to indicate whether a trace
/// session is active, and `_ghidra_tracing_snap` for the current snapshot.
///
/// Ported from the Python `commands.py` state management and
/// `gdb.set_convenience_variable` / `gdb.convenience_variable` calls.
#[derive(Debug, Clone, Default)]
pub struct GdbConvenienceState {
    /// Whether Ghidra tracing is active.
    pub tracing_active: bool,
    /// Current snapshot ID.
    pub current_snapshot: Option<u64>,
    /// Whether pagination is currently enabled.
    pub pagination: bool,
    /// Whether confirmation prompts are enabled.
    pub confirm: bool,
}

impl GdbConvenienceState {
    /// Create a new convenience state with defaults.
    pub fn new() -> Self {
        Self {
            tracing_active: false,
            current_snapshot: None,
            pagination: true,
            confirm: true,
        }
    }

    /// Enable tracing mode.
    pub fn enable_tracing(&mut self) {
        self.tracing_active = true;
    }

    /// Disable tracing mode.
    pub fn disable_tracing(&mut self) {
        self.tracing_active = false;
        self.current_snapshot = None;
    }

    /// Set the current snapshot.
    pub fn set_snapshot(&mut self, snap: u64) {
        self.current_snapshot = Some(snap);
    }

    /// Get the GDB command strings to configure pagination off.
    ///
    /// Returns the commands to save pagination state and disable it.
    /// Ported from the `no_pagination` context manager in `methods.py`.
    pub fn disable_pagination_commands(&self) -> Vec<String> {
        vec![
            "set pagination off".to_string(),
        ]
    }

    /// Get the GDB command strings to restore pagination.
    pub fn restore_pagination_commands(&self) -> Vec<String> {
        let val = if self.pagination { "on" } else { "off" };
        vec![format!("set pagination {}", val)]
    }

    /// Get the GDB command strings to disable confirmation.
    ///
    /// Ported from the `no_confirm` context manager in `methods.py`.
    pub fn disable_confirm_commands(&self) -> Vec<String> {
        vec![
            "set confirm off".to_string(),
        ]
    }

    /// Get the GDB command strings to restore confirmation.
    pub fn restore_confirm_commands(&self) -> Vec<String> {
        let val = if self.confirm { "on" } else { "off" };
        vec![format!("set confirm {}", val)]
    }
}

/// Address mapper for GDB traces.
///
/// Maps between Ghidra trace addresses and GDB addresses.
/// In GDB, addresses may need adjustment based on the target's
/// memory layout (e.g., PIE executables, ASLR).
///
/// Ported from `arch.DefaultMemoryMapper` in the Python agent.
#[derive(Debug, Clone, Default)]
pub struct GdbMemoryMapper {
    /// Address offsets per inferior, keyed by inferior number.
    /// Maps inferior_num -> offset to add to convert Ghidra address to GDB address.
    offsets: BTreeMap<u32, i64>,
    /// The default pointer size in bytes.
    pub pointer_size: usize,
}

impl GdbMemoryMapper {
    /// Create a new memory mapper.
    pub fn new(pointer_size: usize) -> Self {
        Self {
            offsets: BTreeMap::new(),
            pointer_size,
        }
    }

    /// Set the address offset for an inferior.
    pub fn set_offset(&mut self, inferior_num: u32, offset: i64) {
        self.offsets.insert(inferior_num, offset);
    }

    /// Get the address offset for an inferior.
    pub fn get_offset(&self, inferior_num: u32) -> i64 {
        self.offsets.get(&inferior_num).copied().unwrap_or(0)
    }

    /// Map a Ghidra trace address to a GDB address.
    ///
    /// Applies the inferior's address offset.
    pub fn map_to_gdb(&self, inferior_num: u32, ghidra_addr: u64) -> u64 {
        let offset = self.get_offset(inferior_num);
        (ghidra_addr as i64 + offset) as u64
    }

    /// Map a GDB address to a Ghidra trace address.
    ///
    /// Reverse of `map_to_gdb`.
    pub fn map_from_gdb(&self, inferior_num: u32, gdb_addr: u64) -> u64 {
        let offset = self.get_offset(inferior_num);
        (gdb_addr as i64 - offset) as u64
    }

    /// Clear the offset for an inferior.
    pub fn clear_offset(&mut self, inferior_num: u32) {
        self.offsets.remove(&inferior_num);
    }

    /// Clear all offsets.
    pub fn clear_all(&mut self) {
        self.offsets.clear();
    }

    /// Get the maximum address for the current pointer size.
    pub fn max_address(&self) -> u64 {
        compute_max_addr(self.pointer_size)
    }
}

/// Register mapper for GDB traces.
///
/// Maps between Ghidra register names/indices and GDB register names.
/// GDB uses names like "rax", "rip", while Ghidra uses indices or
/// different naming conventions.
///
/// Ported from `arch.DefaultRegisterMapper` in the Python agent.
#[derive(Debug, Clone, Default)]
pub struct GdbRegisterMapper {
    /// Maps GDB register name -> Ghidra register name.
    name_map: BTreeMap<String, String>,
    /// Maps GDB register name -> register size in bytes.
    size_map: BTreeMap<String, usize>,
    /// Maps GDB register name -> register group.
    group_map: BTreeMap<String, String>,
}

impl GdbRegisterMapper {
    /// Create a new register mapper.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a register name mapping.
    pub fn map_name(&mut self, gdb_name: impl Into<String>, ghidra_name: impl Into<String>) {
        self.name_map.insert(gdb_name.into(), ghidra_name.into());
    }

    /// Set the size for a register.
    pub fn set_size(&mut self, name: impl Into<String>, size: usize) {
        self.size_map.insert(name.into(), size);
    }

    /// Set the group for a register.
    pub fn set_group(&mut self, name: impl Into<String>, group: impl Into<String>) {
        self.group_map.insert(name.into(), group.into());
    }

    /// Map a GDB register name to its Ghidra name.
    ///
    /// Returns the Ghidra name if mapped, or the original name.
    pub fn map_register_name(&self, gdb_name: &str) -> String {
        self.name_map
            .get(gdb_name)
            .cloned()
            .unwrap_or_else(|| gdb_name.to_string())
    }

    /// Get the register size by GDB name.
    pub fn get_size(&self, name: &str) -> Option<usize> {
        self.size_map.get(name).copied()
    }

    /// Get the register group by GDB name.
    pub fn get_group(&self, name: &str) -> Option<&str> {
        self.group_map.get(name).map(|s| s.as_str())
    }

    /// Get the number of mapped registers.
    pub fn len(&self) -> usize {
        self.name_map.len()
    }

    /// Check if the mapper is empty.
    pub fn is_empty(&self) -> bool {
        self.name_map.is_empty()
    }
}

/// Unified GDB process manager that ties together inferior management,
/// memory mapping, register mapping, and sync state.
///
/// This is the top-level manager for a GDB debugging session.
/// It corresponds to the Python agent's `commands.State` and the
/// various `put_*` commands.
///
/// Ported from the overall agent architecture in `commands.py` and `hooks.py`.
#[derive(Debug)]
pub struct GdbProcessManager {
    /// Managed inferiors.
    pub inferiors: GdbInferiorManager,
    /// Memory address mapper.
    pub memory_mapper: GdbMemoryMapper,
    /// Register name mapper.
    pub register_mapper: GdbRegisterMapper,
    /// Convenience variable state.
    pub convenience: GdbConvenienceState,
    /// Per-inferior sync states.
    sync_states: BTreeMap<u32, InferiorSyncState>,
    /// Signal table.
    pub signal_table: GdbSignalTable,
    /// Whether the manager is initialized (trace started).
    pub initialized: bool,
}

impl GdbProcessManager {
    /// Create a new process manager.
    pub fn new() -> Self {
        Self {
            inferiors: GdbInferiorManager::new(),
            memory_mapper: GdbMemoryMapper::new(8),
            register_mapper: GdbRegisterMapper::new(),
            convenience: GdbConvenienceState::new(),
            sync_states: BTreeMap::new(),
            signal_table: GdbSignalTable::new(),
            initialized: false,
        }
    }

    /// Create a process manager with a specific pointer size.
    pub fn with_pointer_size(mut self, size: usize) -> Self {
        self.memory_mapper = GdbMemoryMapper::new(size);
        self
    }

    /// Initialize the manager (called when trace starts).
    pub fn initialize(&mut self) {
        self.signal_table.populate_defaults();
        self.convenience.enable_tracing();
        self.initialized = true;
    }

    /// Shut down the manager (called when trace stops).
    pub fn shutdown(&mut self) {
        self.convenience.disable_tracing();
        self.initialized = false;
    }

    /// Get or create the sync state for an inferior.
    pub fn get_or_create_sync_state(&mut self, inferior_num: u32) -> &mut InferiorSyncState {
        self.sync_states
            .entry(inferior_num)
            .or_insert_with(InferiorSyncState::new)
    }

    /// Get the sync state for an inferior, if it exists.
    pub fn get_sync_state(&self, inferior_num: u32) -> Option<&InferiorSyncState> {
        self.sync_states.get(&inferior_num)
    }

    /// Add an inferior to the manager.
    pub fn add_inferior(&mut self, inferior: GdbInferiorProcess) {
        let num = inferior.num;
        self.sync_states.entry(num).or_insert_with(InferiorSyncState::new);
        self.inferiors.add(inferior);
    }

    /// Remove an inferior from the manager.
    pub fn remove_inferior(&mut self, num: u32) -> Option<GdbInferiorProcess> {
        self.sync_states.remove(&num);
        self.inferiors.remove(num)
    }

    /// Get the active inferior's sync state.
    pub fn active_sync_state(&mut self) -> Option<&mut InferiorSyncState> {
        let num = self.inferiors.active_num()?;
        Some(self.get_or_create_sync_state(num))
    }

    /// Compute environment values for the current session.
    ///
    /// Ported from `put_environment` in `commands.py`.
    pub fn build_environment(
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

    /// Map a Ghidra address to GDB for the active inferior.
    pub fn map_address_to_gdb(&self, address: u64) -> u64 {
        if let Some(num) = self.inferiors.active_num() {
            self.memory_mapper.map_to_gdb(num, address)
        } else {
            address
        }
    }

    /// Map a GDB address to Ghidra for the active inferior.
    pub fn map_address_from_gdb(&self, address: u64) -> u64 {
        if let Some(num) = self.inferiors.active_num() {
            self.memory_mapper.map_from_gdb(num, address)
        } else {
            address
        }
    }

    /// Map a register value from GDB to Ghidra.
    pub fn map_register_value(
        &self,
        name: &str,
        bytes: &[u8],
    ) -> RegisterValue {
        let mapped_name = self.register_mapper.map_register_name(name);
        RegisterValue::new(mapped_name, bytes.to_vec())
    }

    /// Build the full trace snapshot description for a stop event.
    ///
    /// Ported from `InferiorState.record()` in `hooks.py`.
    pub fn build_stop_snapshot_description(&self, stop_reason: &str) -> String {
        match stop_reason {
            "breakpoint-hit" => "Stopped at breakpoint".to_string(),
            "signal-received" => "Stopped on signal".to_string(),
            "end-stepping-range" => "Stepped".to_string(),
            "function-finished" => "Function finished".to_string(),
            "exited-normally" => "Exited normally".to_string(),
            "exited-signalled" => "Exited with signal".to_string(),
            other => format!("Stopped: {}", other),
        }
    }

    /// Get the total number of threads across all inferiors.
    pub fn total_threads(&self) -> usize {
        self.inferiors.total_thread_count()
    }

    /// Get the total number of modules across all inferiors.
    pub fn total_modules(&self) -> usize {
        self.inferiors
            .all()
            .values()
            .map(|p| p.modules.len())
            .sum()
    }

    /// Get the total number of memory regions across all inferiors.
    pub fn total_memory_regions(&self) -> usize {
        self.inferiors
            .all()
            .values()
            .map(|p| p.memory_regions.len())
            .sum()
    }

    /// Check if the manager has any active (non-exited) inferiors.
    pub fn has_active_inferiors(&self) -> bool {
        !self.inferiors.alive().is_empty()
    }

    /// Build a summary of the current debugging session.
    pub fn build_session_summary(&self) -> Vec<(String, String)> {
        let mut summary = Vec::new();
        summary.push(("Inferiors".to_string(), self.inferiors.len().to_string()));
        summary.push(("Threads".to_string(), self.total_threads().to_string()));
        summary.push(("Modules".to_string(), self.total_modules().to_string()));
        summary.push((
            "MemoryRegions".to_string(),
            self.total_memory_regions().to_string(),
        ));
        summary.push((
            "Signals".to_string(),
            self.signal_table.len().to_string(),
        ));
        summary
    }
}

impl Default for GdbProcessManager {
    fn default() -> Self {
        Self::new()
    }
}

/// GNU Debugdata prefix used to filter out `.gnu_debugdata` modules.
///
/// GDB's `maintenance info sections` can include sections from
/// `.gnu_debugdata` (mini debuginfo) which we skip.
pub const GNU_DEBUGDATA_PREFIX: &str = ".gnu_debugdata for ";

/// Check if a module name should be skipped (gnu_debugdata).
pub fn should_skip_module(name: &str) -> bool {
    name.starts_with(GNU_DEBUGDATA_PREFIX)
}

/// Quantize an address range to page boundaries.
///
/// Ported from `quantize_pages` in `commands.py`.
pub fn quantize_pages(start: u64, end: u64, page_size: u64) -> (u64, u64) {
    let page_start = start / page_size * page_size;
    let page_end = (end + page_size - 1) / page_size * page_size;
    (page_start, page_end)
}

/// Default page size (4096 bytes).
pub const PAGE_SIZE: u64 = 4096;

/// Quantize an address range to default page boundaries.
pub fn quantize_to_pages(start: u64, end: u64) -> (u64, u64) {
    quantize_pages(start, end, PAGE_SIZE)
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
        assert!(inf.breakpoint_ids.is_empty());
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
        assert_eq!(inf.breakpoint_loc_path(1, 2), "Inferiors[2].Breakpoints[1.2]");
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
        assert_eq!(inf.modules[0].info.name, "libc.so.6");

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
        assert_eq!(inf.modules[0].info.base, 0x7ffff7c00000);

        inf.clear_modules();
        assert!(inf.modules.is_empty());
    }

    #[test]
    fn test_inferior_module_with_sections() {
        let mut inf = GdbInferiorProcess::new(1);
        let mut mod_ws = ModuleWithSections::from_info(ModuleInfo {
            name: "libc.so.6".to_string(),
            base: 0x7ffff7a00000,
            size: 0x1e6000,
            build_id: None,
            debug_path: None,
            load_path: None,
        });
        mod_ws.add_section(ModuleSection::new(".text", 0x7ffff7a01000, 0x7ffff7b00000));
        mod_ws.add_section(ModuleSection::new(".data", 0x7ffff7b00000, 0x7ffff7b80000));
        inf.add_module_with_sections(mod_ws);

        let m = inf.get_module("libc.so.6").unwrap();
        assert_eq!(m.section_count(), 2);
        assert!(m.sections.contains_key(".text"));
        assert!(m.sections.contains_key(".data"));

        let text = m.sections.get(".text").unwrap();
        assert_eq!(text.size(), 0x7ffff7b00000 - 0x7ffff7a01000);
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
        assert!(values.iter().any(|(k, v)| k == "State" && v == "NOT_STARTED"));
        assert!(values.iter().any(|(k, v)| k == "_display" && v == "Process 1"));
    }

    #[test]
    fn test_inferior_build_trace_values_with_exit() {
        let mut inf = GdbInferiorProcess::new(1);
        inf.set_exit(42);
        let values = inf.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "Exit Code" && v == "42"));
        assert!(values.iter().any(|(k, v)| k == "State" && v == "TERMINATED"));
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

    #[test]
    fn test_inferior_breakpoint_ids() {
        let mut inf = GdbInferiorProcess::new(1);
        inf.add_breakpoint_id(1);
        inf.add_breakpoint_id(2);
        inf.add_breakpoint_id(1); // duplicate
        assert_eq!(inf.breakpoint_ids.len(), 2);
        inf.remove_breakpoint_id(1);
        assert_eq!(inf.breakpoint_ids.len(), 1);
        assert_eq!(inf.breakpoint_ids[0], 2);
    }

    #[test]
    fn test_inferior_memory_query() {
        let mut inf = GdbInferiorProcess::new(1);
        inf.add_memory_region(MemoryRegion {
            base: 0x400000,
            size: 0x1000,
            offset: 0,
            permissions: "r-xp".to_string(),
            object_file: "test".to_string(),
        });
        assert!(inf.is_address_mapped(0x400000));
        assert!(inf.is_address_mapped(0x400500));
        assert!(!inf.is_address_mapped(0x500000));
        assert!(!inf.is_address_mapped(0x300000));
    }

    #[test]
    fn test_inferior_retain_keys() {
        let mut inf = GdbInferiorProcess::new(1);
        inf.add_thread(GdbThread::new(1));
        inf.add_thread(GdbThread::new(3));
        let keys = inf.build_thread_retain_keys();
        assert!(keys.contains(&"[1]".to_string()));
        assert!(keys.contains(&"[3]".to_string()));
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_module_section() {
        let sec = ModuleSection::new(".text", 0x1000, 0x5000)
            .with_offset(0x1000)
            .with_attrs(vec!["alloc".to_string(), "load".to_string()]);
        assert_eq!(sec.name, ".text");
        assert_eq!(sec.size(), 0x4000);
        assert_eq!(sec.trace_path(1, "libc.so.6"), "Inferiors[1].Modules[libc.so.6].Sections[.text]");
        let vals = sec.build_trace_values();
        assert!(vals.iter().any(|(k, _)| k == "Range"));
        assert!(vals.iter().any(|(k, _)| k == "Offset"));
        assert!(vals.iter().any(|(k, _)| k == "Attrs"));
    }

    #[test]
    fn test_module_section_zero_size() {
        let sec = ModuleSection::new(".bss", 0x5000, 0x5000);
        let vals = sec.build_trace_values();
        assert!(vals.iter().any(|(k, _)| k == "Address"));
    }

    #[test]
    fn test_snapshot() {
        let snap = Snapshot::new(0, "Stopped").with_timestamp(1234567890);
        assert_eq!(snap.id, 0);
        assert_eq!(snap.description, "Stopped");
        assert_eq!(snap.timestamp, Some(1234567890));
    }

    #[test]
    fn test_inferior_sync_state() {
        let mut state = InferiorSyncState::new();
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
    fn test_inferior_sync_state_dirty_flags() {
        let mut state = InferiorSyncState::new();
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
    fn test_inferior_sync_state_regions() {
        let mut state = InferiorSyncState::new();
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
    fn test_inferior_sync_state_snapshots() {
        let mut state = InferiorSyncState::new();
        state.create_snapshot("Stopped");
        state.create_snapshot("Continued");
        state.create_snapshot("Stopped");
        assert_eq!(state.snapshots.len(), 3);
        assert_eq!(state.snapshots[0].id, 0);
        assert_eq!(state.snapshots[1].id, 1);
        assert_eq!(state.snapshots[2].id, 2);
    }

    #[test]
    fn test_inferior_refresh_state() {
        let mut inf = GdbInferiorProcess::new(1);
        inf.add_thread(GdbThread::new(1).with_state(ExecutionState::Running));
        inf.add_thread(GdbThread::new(2).with_state(ExecutionState::Stopped));
        inf.refresh_state();
        assert_eq!(inf.state, ExecutionState::Running);
    }

    #[test]
    fn test_inferior_threads_sorted() {
        let mut inf = GdbInferiorProcess::new(1);
        inf.add_thread(GdbThread::new(3));
        inf.add_thread(GdbThread::new(1));
        inf.add_thread(GdbThread::new(2));
        let sorted = inf.threads_sorted();
        assert_eq!(sorted[0].num, 1);
        assert_eq!(sorted[1].num, 2);
        assert_eq!(sorted[2].num, 3);
    }

    #[test]
    fn test_inferior_running_stopped_threads() {
        let mut inf = GdbInferiorProcess::new(1);
        inf.add_thread(GdbThread::new(1).with_state(ExecutionState::Running));
        inf.add_thread(GdbThread::new(2).with_state(ExecutionState::Stopped));
        inf.add_thread(GdbThread::new(3).with_state(ExecutionState::Running));
        assert_eq!(inf.running_threads().len(), 2);
        assert_eq!(inf.stopped_threads().len(), 1);
    }

    #[test]
    fn test_inferior_thread_state_counts() {
        let mut inf = GdbInferiorProcess::new(1);
        inf.add_thread(GdbThread::new(1).with_state(ExecutionState::Running));
        inf.add_thread(GdbThread::new(2).with_state(ExecutionState::Running));
        inf.add_thread(GdbThread::new(3).with_state(ExecutionState::Stopped));
        let counts = inf.thread_state_counts();
        assert_eq!(counts.get(&ExecutionState::Running), Some(&2));
        assert_eq!(counts.get(&ExecutionState::Stopped), Some(&1));
    }

    #[test]
    fn test_inferior_build_threads_container_values() {
        let mut inf = GdbInferiorProcess::new(1);
        inf.add_thread(GdbThread::new(1));
        inf.add_thread(GdbThread::new(2));
        let values = inf.build_threads_container_values();
        assert!(values.iter().any(|(k, v)| k == "_count" && v == "2"));
    }

    #[test]
    fn test_inferior_module_at_address() {
        let mut inf = GdbInferiorProcess::new(1);
        inf.add_module(ModuleInfo {
            name: "libc.so.6".to_string(),
            base: 0x7ffff7a00000,
            size: 0x1e6000,
            build_id: None,
            debug_path: None,
            load_path: None,
        });
        assert!(inf.module_at_address(0x7ffff7a00000).is_some());
        assert!(inf.module_at_address(0x7ffff7be5fff).is_some());
        assert!(inf.module_at_address(0x7ffff7be6000).is_none());
        assert!(inf.module_at_address(0x100000).is_none());
    }

    #[test]
    fn test_inferior_modules_sorted() {
        let mut inf = GdbInferiorProcess::new(1);
        inf.add_module(ModuleInfo {
            name: "b.so".to_string(),
            base: 0x2000,
            size: 0x1000,
            build_id: None,
            debug_path: None,
            load_path: None,
        });
        inf.add_module(ModuleInfo {
            name: "a.so".to_string(),
            base: 0x1000,
            size: 0x1000,
            build_id: None,
            debug_path: None,
            load_path: None,
        });
        let sorted = inf.modules_sorted();
        assert_eq!(sorted[0].info.name, "a.so");
        assert_eq!(sorted[1].info.name, "b.so");
    }

    #[test]
    fn test_inferior_build_modules_container_values() {
        let mut inf = GdbInferiorProcess::new(1);
        inf.add_module(ModuleInfo {
            name: "test.so".to_string(),
            base: 0x1000,
            size: 0x1000,
            build_id: None,
            debug_path: None,
            load_path: None,
        });
        let values = inf.build_modules_container_values();
        assert!(values.iter().any(|(k, v)| k == "_count" && v == "1"));
    }

    #[test]
    fn test_inferior_memory_region_at() {
        let mut inf = GdbInferiorProcess::new(1);
        inf.add_memory_region(MemoryRegion {
            base: 0x1000,
            size: 0x2000,
            offset: 0,
            permissions: "r-xp".to_string(),
            object_file: "a.out".to_string(),
        });
        assert!(inf.memory_region_at(0x1000).is_some());
        assert!(inf.memory_region_at(0x2fff).is_some());
        assert!(inf.memory_region_at(0x3000).is_none());
    }

    #[test]
    fn test_inferior_memory_footprint() {
        let mut inf = GdbInferiorProcess::new(1);
        inf.add_memory_region(MemoryRegion {
            base: 0x1000,
            size: 0x2000,
            offset: 0,
            permissions: "r-xp".to_string(),
            object_file: "a.out".to_string(),
        });
        inf.add_memory_region(MemoryRegion {
            base: 0x5000,
            size: 0x1000,
            offset: 0,
            permissions: "rw-p".to_string(),
            object_file: "libc.so".to_string(),
        });
        assert_eq!(inf.memory_footprint(), 0x3000);
    }

    #[test]
    fn test_inferior_find_module_by_base() {
        let mut inf = GdbInferiorProcess::new(1);
        inf.add_module(ModuleInfo {
            name: "libc.so.6".to_string(),
            base: 0x7ffff7a00000,
            size: 0x1e6000,
            build_id: None,
            debug_path: None,
            load_path: None,
        });
        assert!(inf.find_module_by_base(0x7ffff7a00000).is_some());
        assert!(inf.find_module_by_base(0x100000).is_none());
    }

    #[test]
    fn test_inferior_sorted_thread_numbers() {
        let mut inf = GdbInferiorProcess::new(1);
        inf.add_thread(GdbThread::new(3));
        inf.add_thread(GdbThread::new(1));
        inf.add_thread(GdbThread::new(2));
        assert_eq!(inf.sorted_thread_numbers(), vec![1, 2, 3]);
    }

    #[test]
    fn test_inferior_sorted_module_bases() {
        let mut inf = GdbInferiorProcess::new(1);
        inf.add_module(ModuleInfo {
            name: "b.so".to_string(),
            base: 0x3000,
            size: 0x1000,
            build_id: None,
            debug_path: None,
            load_path: None,
        });
        inf.add_module(ModuleInfo {
            name: "a.so".to_string(),
            base: 0x1000,
            size: 0x1000,
            build_id: None,
            debug_path: None,
            load_path: None,
        });
        assert_eq!(inf.sorted_module_bases(), vec![0x1000, 0x3000]);
    }

    #[test]
    fn test_inferior_build_display_string() {
        let inf = GdbInferiorProcess::new(2);
        assert_eq!(inf.build_display_string(), "Process 2");

        let inf_pid = GdbInferiorProcess::new(2).with_pid(1234);
        assert_eq!(inf_pid.build_display_string(), "1234 [2]");
    }

    #[test]
    fn test_inferior_build_trace_values_extended() {
        let mut inf = GdbInferiorProcess::new(1).with_pid(42);
        inf.state = ExecutionState::Stopped;
        let values = inf.build_trace_values_extended();
        assert!(values.iter().any(|(k, v)| k == "State" && v == "STOPPED"));
        assert!(values.iter().any(|(k, v)| k == "PID" && v == "42"));
        assert!(values.iter().any(|(k, v)| k == "_display" && v == "42 [1]"));
    }

    #[test]
    fn test_inferior_total_frame_count() {
        let mut inf = GdbInferiorProcess::new(1);
        let mut t1 = GdbThread::new(1);
        t1.add_frame(GdbStackFrame::new(0, 0x401000));
        t1.add_frame(GdbStackFrame::new(1, 0x402000));
        let mut t2 = GdbThread::new(2);
        t2.add_frame(GdbStackFrame::new(0, 0x501000));
        inf.add_thread(t1);
        inf.add_thread(t2);
        assert_eq!(inf.total_frame_count(), 3);
    }

    #[test]
    fn test_inferior_running_stopped_thread_numbers() {
        let mut inf = GdbInferiorProcess::new(1);
        inf.add_thread(GdbThread::new(1).with_state(ExecutionState::Running));
        inf.add_thread(GdbThread::new(2).with_state(ExecutionState::Stopped));
        inf.add_thread(GdbThread::new(3).with_state(ExecutionState::Running));
        inf.add_thread(GdbThread::new(4).with_state(ExecutionState::Exited));
        assert_eq!(inf.running_thread_numbers(), vec![1, 3]);
        assert_eq!(inf.stopped_thread_numbers(), vec![2]);
    }
}

#[cfg(test)]
mod signal_tests {
    use super::*;

    #[test]
    fn test_signal_config() {
        let sig = GdbSignalConfig::new(11, "SIGSEGV")
            .with_stop(true)
            .with_description("Segmentation fault");
        assert_eq!(sig.number, 11);
        assert_eq!(sig.name, "SIGSEGV");
        assert!(sig.stop);
        assert!(sig.description.is_some());
    }

    #[test]
    fn test_signal_table() {
        let mut table = GdbSignalTable::new();
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
mod breakpoint_tests {
    use super::*;

    #[test]
    fn test_process_breakpoint() {
        let bp = GdbProcessBreakpoint::new(1)
            .with_address(0x401000)
            .with_hardware(true);
        assert_eq!(bp.number, 1);
        assert_eq!(bp.resolved_address, Some(0x401000));
        assert!(bp.hardware);
        assert_eq!(bp.hit_count, 0);
        assert!(bp.should_stop());
        assert_eq!(bp.bp_type, GdbProcessBreakpointType::HardwareBreakpoint);
    }

    #[test]
    fn test_breakpoint_ignore_count() {
        let mut bp = GdbProcessBreakpoint::new(1).with_address(0x401000);
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
        let mut bp = GdbProcessBreakpoint::new(1).with_address(0x401000);
        bp.enabled = false;
        assert!(!bp.should_stop());
    }

    #[test]
    fn test_breakpoint_type() {
        let bp = GdbProcessBreakpoint::new(1).with_type(GdbProcessBreakpointType::WriteWatchpoint);
        assert_eq!(bp.bp_type, GdbProcessBreakpointType::WriteWatchpoint);
    }
}

#[cfg(test)]
mod available_process_tests {
    use super::*;

    #[test]
    fn test_available_process_new() {
        let ap = AvailableProcess::new(1234, "root", "/usr/bin/test");
        assert_eq!(ap.pid, 1234);
        assert_eq!(ap.user, "root");
        assert_eq!(ap.command, "/usr/bin/test");
    }

    #[test]
    fn test_available_process_parse() {
        let ap = AvailableProcess::from_info_line("1234 root /usr/bin/gdb --interpreter=mi2");
        assert!(ap.is_some());
        let ap = ap.unwrap();
        assert_eq!(ap.pid, 1234);
        assert_eq!(ap.user, "root");
        assert!(ap.command.contains("gdb"));
    }

    #[test]
    fn test_available_process_parse_short() {
        let ap = AvailableProcess::from_info_line("1234");
        assert!(ap.is_none());
    }
}

#[cfg(test)]
mod breakpoint_location_tests {
    use super::*;

    #[test]
    fn test_breakpoint_location_info() {
        let loc = BreakpointLocationInfo::new(0x401000, true)
            .with_thread_group(1)
            .with_thread_group(2);
        assert_eq!(loc.address, 0x401000);
        assert!(loc.enabled);
        assert_eq!(loc.thread_groups, vec![1, 2]);
    }

    #[test]
    fn test_breakpoint_location_disabled() {
        let loc = BreakpointLocationInfo::new(0x401000, false);
        assert!(!loc.enabled);
        assert!(loc.thread_groups.is_empty());
    }
}

#[cfg(test)]
mod region_index_tests {
    use super::*;

    #[test]
    fn test_region_index_basic() {
        let regions = vec![
            MemoryRegion {
                base: 0x1000,
                size: 0x2000,
                offset: 0,
                permissions: "r-xp".to_string(),
                object_file: "a.out".to_string(),
            },
            MemoryRegion {
                base: 0x5000,
                size: 0x1000,
                offset: 0,
                permissions: "rw-p".to_string(),
                object_file: "libc.so".to_string(),
            },
        ];
        let idx = RegionIndex::from_regions(&regions);
        assert_eq!(idx.len(), 2);
        assert_eq!(idx.compute_base(0x1500), 0x1000);
        assert_eq!(idx.compute_base(0x5500), 0x5000);
        // Address before all regions returns itself
        assert_eq!(idx.compute_base(0x0500), 0x0500);
        // Address between regions returns itself
        assert_eq!(idx.compute_base(0x3000), 0x3000);
    }

    #[test]
    fn test_region_index_find_region() {
        let regions = vec![MemoryRegion {
            base: 0x400000,
            size: 0x1000,
            offset: 0,
            permissions: "r-xp".to_string(),
            object_file: "test".to_string(),
        }];
        let idx = RegionIndex::from_regions(&regions);
        assert!(idx.find_region(0x400500).is_some());
        assert!(idx.find_region(0x500000).is_none());
    }

    #[test]
    fn test_region_index_empty() {
        let idx = RegionIndex::default();
        assert!(idx.is_empty());
        assert_eq!(idx.compute_base(0x1000), 0x1000);
    }

    #[test]
    fn test_region_index_have_changed() {
        let regions = vec![MemoryRegion {
            base: 0x400000,
            size: 0x1000,
            offset: 0,
            permissions: "r-xp".to_string(),
            object_file: "test".to_string(),
        }];
        let idx = RegionIndex::from_regions(&regions);
        assert!(!idx.have_changed(&regions));

        let different = vec![MemoryRegion {
            base: 0x500000,
            size: 0x1000,
            offset: 0,
            permissions: "r-xp".to_string(),
            object_file: "test".to_string(),
        }];
        assert!(idx.have_changed(&different));
    }
}

#[cfg(test)]
mod module_info_format_tests {
    use super::*;

    #[test]
    fn test_module_info_format_for_version() {
        assert_eq!(ModuleInfoFormat::for_gdb_version(8), ModuleInfoFormat::V8);
        assert_eq!(ModuleInfoFormat::for_gdb_version(9), ModuleInfoFormat::V9);
        assert_eq!(ModuleInfoFormat::for_gdb_version(10), ModuleInfoFormat::V9);
        assert_eq!(ModuleInfoFormat::for_gdb_version(11), ModuleInfoFormat::V11);
        assert_eq!(ModuleInfoFormat::for_gdb_version(13), ModuleInfoFormat::V11);
    }

    #[test]
    fn test_module_info_format_command() {
        assert_eq!(ModuleInfoFormat::V8.command(), "maintenance info sections ALLOBJ");
        assert_eq!(ModuleInfoFormat::V11.command(), "maintenance info sections -all-objects");
    }

    #[test]
    fn test_module_info_format_has_exec_file() {
        assert!(!ModuleInfoFormat::V8.has_exec_file());
        assert!(!ModuleInfoFormat::V9.has_exec_file());
        assert!(ModuleInfoFormat::V11.has_exec_file());
    }
}

#[cfg(test)]
mod parsed_section_tests {
    use super::*;

    #[test]
    fn test_parsed_section_basic() {
        let sec = ParsedSection::new(".text", 0x1000, 0x5000, 0x1000, vec!["ALLOC".to_string()]);
        assert_eq!(sec.name, ".text");
        assert_eq!(sec.size(), 0x4000);
        assert!(sec.is_alloc());
        assert!(!sec.is_readonly());
    }

    #[test]
    fn test_parsed_section_attrs() {
        let sec = ParsedSection::new(
            ".rodata",
            0x5000,
            0x6000,
            0x5000,
            vec!["ALLOC".to_string(), "LOAD".to_string(), "READONLY".to_string()],
        );
        assert!(sec.is_alloc());
        assert!(sec.is_load());
        assert!(sec.is_readonly());
        assert!(!sec.is_code());
    }

    #[test]
    fn test_parsed_section_merge() {
        let sec1 = ParsedSection::new(".text", 0x1000, 0, 0, vec!["ALLOC".to_string()]);
        let sec2 = ParsedSection::new(".text", 0, 0x5000, 0x1000, vec!["LOAD".to_string()]);
        let merged = sec1.merge(&sec2);
        assert_eq!(merged.vma_start, 0x1000);
        assert_eq!(merged.vma_end, 0x5000);
        assert_eq!(merged.file_offset, 0x1000);
        assert!(merged.attrs.contains(&"ALLOC".to_string()));
        assert!(merged.attrs.contains(&"LOAD".to_string()));
    }
}

#[cfg(test)]
mod parsed_module_tests {
    use super::*;

    #[test]
    fn test_parsed_module_basic() {
        let mut module = ParsedModule::new("libc.so.6");
        module.add_section(ParsedSection::new(
            ".text",
            0x7ffff7a01000,
            0x7ffff7b00000,
            0x1000,
            vec!["ALLOC".to_string(), "LOAD".to_string()],
        ));
        module.add_section(ParsedSection::new(
            ".data",
            0x7ffff7b00000,
            0x7ffff7b80000,
            0x100000,
            vec!["ALLOC".to_string(), "LOAD".to_string()],
        ));
        assert_eq!(module.sections.len(), 2);
        assert_eq!(module.alloc_sections().len(), 2);
    }

    #[test]
    fn test_parsed_module_add_section_merge() {
        let mut module = ParsedModule::new("test");
        module.add_section(ParsedSection::new(".text", 0x1000, 0, 0, vec!["ALLOC".to_string()]));
        module.add_section(ParsedSection::new(".text", 0, 0x5000, 0x1000, vec!["LOAD".to_string()]));
        assert_eq!(module.sections.len(), 1);
        let sec = module.sections.get(".text").unwrap();
        assert_eq!(sec.vma_start, 0x1000);
        assert_eq!(sec.vma_end, 0x5000);
    }

    #[test]
    fn test_parsed_module_to_module_info() {
        let mut module = ParsedModule::new("test.so");
        module.add_section(ParsedSection::new(
            ".text",
            0x1000,
            0x3000,
            0x1000,
            vec!["ALLOC".to_string()],
        ));
        let idx = RegionIndex::default();
        let info = module.to_module_info(&idx);
        assert_eq!(info.name, "test.so");
        assert_eq!(info.base, 0x1000);
        assert_eq!(info.size, 0x2000);
    }

    #[test]
    fn test_parsed_module_empty() {
        let module = ParsedModule::new("empty");
        assert!(module.alloc_sections().is_empty());
        assert_eq!(module.compute_max_addr(), 0);
    }
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    #[test]
    fn test_parse_section_line_v8() {
        let line = "  0x0000000000401000 -> 0x0000000000402000 at 0x00001000: .text ALLOC LOAD READONLY CODE";
        let max_addr = 0xFFFFFFFFFFFFFFFF;
        let sec = parse_section_line(line, max_addr);
        assert!(sec.is_some());
        let sec = sec.unwrap();
        assert_eq!(sec.name, ".text");
        assert_eq!(sec.vma_start, 0x401000);
        assert_eq!(sec.vma_end, 0x402000);
        assert_eq!(sec.file_offset, 0x1000);
        assert!(sec.is_alloc());
        assert!(sec.is_code());
    }

    #[test]
    fn test_parse_section_line_v9() {
        let line = "  [ 1] 0x0000000000401000 -> 0x0000000000402000 at 0x00001000: .text ALLOC LOAD";
        let max_addr = 0xFFFFFFFFFFFFFFFF;
        let sec = parse_section_line(line, max_addr);
        assert!(sec.is_some());
        let sec = sec.unwrap();
        assert_eq!(sec.name, ".text");
        assert_eq!(sec.vma_start, 0x401000);
    }

    #[test]
    fn test_parse_section_line_invalid() {
        let max_addr = 0xFFFFFFFFFFFFFFFF;
        assert!(parse_section_line("", max_addr).is_none());
        assert!(parse_section_line("garbage", max_addr).is_none());
    }

    #[test]
    fn test_parse_module_name_line_object() {
        let line = "Object file: /usr/lib/x86_64-linux-gnu/libc.so.6";
        let name = parse_module_name_line(line, false);
        assert_eq!(name, Some("/usr/lib/x86_64-linux-gnu/libc.so.6".to_string()));
    }

    #[test]
    fn test_parse_module_name_line_exec() {
        let line = "Exec file: `/usr/bin/test', file type elf64-x86-64.";
        let name = parse_module_name_line(line, true);
        assert_eq!(name, Some("/usr/bin/test".to_string()));
    }

    #[test]
    fn test_parse_module_name_line_exec_v8() {
        // V8 does not recognize Exec file
        let line = "Exec file: `/usr/bin/test', file type elf64-x86-64.";
        let name = parse_module_name_line(line, false);
        assert!(name.is_none());
    }

    #[test]
    fn test_parse_module_name_line_invalid() {
        assert!(parse_module_name_line("some random line", false).is_none());
        assert!(parse_module_name_line("", false).is_none());
    }

    #[test]
    fn test_parse_proc_mapping_line() {
        let line = "0x00400000 0x00401000 0x00001000 0x00000000 r-xp /usr/bin/test";
        let max_addr = 0xFFFFFFFFFFFFFFFF;
        let region = parse_proc_mapping_line(line, max_addr);
        assert!(region.is_some());
        let r = region.unwrap();
        assert_eq!(r.base, 0x400000);
        assert_eq!(r.size, 0x1000);
        assert_eq!(r.permissions, "r-xp");
        assert_eq!(r.object_file, "/usr/bin/test");
    }

    #[test]
    fn test_parse_proc_mapping_line_no_perms() {
        let line = "0x00400000 0x00401000 0x00001000 0x00000000 /usr/bin/test";
        let max_addr = 0xFFFFFFFFFFFFFFFF;
        let region = parse_proc_mapping_line(line, max_addr);
        assert!(region.is_some());
    }

    #[test]
    fn test_parse_proc_mapping_line_short() {
        let max_addr = 0xFFFFFFFFFFFFFFFF;
        assert!(parse_proc_mapping_line("0x1000 0x2000", max_addr).is_none());
        assert!(parse_proc_mapping_line("", max_addr).is_none());
    }

    #[test]
    fn test_compute_max_addr() {
        assert_eq!(compute_max_addr(4), 0xFFFFFFFF);
        assert_eq!(compute_max_addr(8), 0xFFFFFFFFFFFFFFFF);
    }
}

#[cfg(test)]
mod manager_tests {
    use super::*;

    #[test]
    fn test_inferior_manager() {
        let mut mgr = GdbInferiorManager::new();
        assert!(mgr.is_empty());

        mgr.add(GdbInferiorProcess::new(1));
        mgr.add(GdbInferiorProcess::new(2));
        assert_eq!(mgr.len(), 2);
        assert_eq!(mgr.active_num(), Some(1));

        mgr.set_active(2);
        assert_eq!(mgr.active_num(), Some(2));
        assert!(mgr.active().is_some());
        assert_eq!(mgr.active().unwrap().num, 2);
    }

    #[test]
    fn test_inferior_manager_remove() {
        let mut mgr = GdbInferiorManager::new();
        mgr.add(GdbInferiorProcess::new(1));
        mgr.add(GdbInferiorProcess::new(2));

        let removed = mgr.remove(1);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().num, 1);
        assert_eq!(mgr.len(), 1);
        // Active should have shifted since we removed the active one
        assert_eq!(mgr.active_num(), Some(2));
    }

    #[test]
    fn test_inferior_manager_alive() {
        let mut mgr = GdbInferiorManager::new();
        let mut inf1 = GdbInferiorProcess::new(1);
        inf1.state = ExecutionState::Stopped;
        let mut inf2 = GdbInferiorProcess::new(2);
        inf2.state = ExecutionState::Exited;
        mgr.add(inf1);
        mgr.add(inf2);
        assert_eq!(mgr.alive().len(), 1);
    }

    #[test]
    fn test_inferior_manager_total_threads() {
        let mut mgr = GdbInferiorManager::new();
        let mut inf1 = GdbInferiorProcess::new(1);
        inf1.add_thread(GdbThread::new(1));
        inf1.add_thread(GdbThread::new(2));
        let mut inf2 = GdbInferiorProcess::new(2);
        inf2.add_thread(GdbThread::new(1));
        mgr.add(inf1);
        mgr.add(inf2);
        assert_eq!(mgr.total_thread_count(), 3);
    }

    #[test]
    fn test_inferior_manager_build_info_list() {
        let mut mgr = GdbInferiorManager::new();
        let mut inf1 = GdbInferiorProcess::new(1);
        inf1.state = ExecutionState::Stopped;
        mgr.add(inf1);
        let list = mgr.build_process_info_list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, 1);
    }
}

#[cfg(test)]
mod convenience_state_tests {
    use super::*;

    #[test]
    fn test_convenience_state_new() {
        let state = GdbConvenienceState::new();
        assert!(!state.tracing_active);
        assert!(state.current_snapshot.is_none());
        assert!(state.pagination);
        assert!(state.confirm);
    }

    #[test]
    fn test_convenience_state_tracing() {
        let mut state = GdbConvenienceState::new();
        state.enable_tracing();
        assert!(state.tracing_active);
        state.disable_tracing();
        assert!(!state.tracing_active);
        assert!(state.current_snapshot.is_none());
    }

    #[test]
    fn test_convenience_state_snapshot() {
        let mut state = GdbConvenienceState::new();
        state.enable_tracing();
        state.set_snapshot(5);
        assert_eq!(state.current_snapshot, Some(5));
    }

    #[test]
    fn test_convenience_state_commands() {
        let state = GdbConvenienceState::new();
        let cmds = state.disable_pagination_commands();
        assert!(cmds.iter().any(|c| c.contains("pagination")));
        let restore = state.restore_pagination_commands();
        assert!(restore.iter().any(|c| c.contains("on")));
    }
}

#[cfg(test)]
mod memory_mapper_tests {
    use super::*;

    #[test]
    fn test_memory_mapper_new() {
        let mapper = GdbMemoryMapper::new(8);
        assert_eq!(mapper.pointer_size, 8);
        assert_eq!(mapper.get_offset(1), 0);
    }

    #[test]
    fn test_memory_mapper_offset() {
        let mut mapper = GdbMemoryMapper::new(8);
        mapper.set_offset(1, 0x1000);
        assert_eq!(mapper.get_offset(1), 0x1000);
        assert_eq!(mapper.get_offset(2), 0);
    }

    #[test]
    fn test_memory_mapper_map() {
        let mut mapper = GdbMemoryMapper::new(8);
        mapper.set_offset(1, 0x1000);
        assert_eq!(mapper.map_to_gdb(1, 0x5000), 0x6000);
        assert_eq!(mapper.map_from_gdb(1, 0x6000), 0x5000);
    }

    #[test]
    fn test_memory_mapper_no_offset() {
        let mapper = GdbMemoryMapper::new(8);
        assert_eq!(mapper.map_to_gdb(1, 0x5000), 0x5000);
        assert_eq!(mapper.map_from_gdb(1, 0x5000), 0x5000);
    }

    #[test]
    fn test_memory_mapper_max_address() {
        let mapper_64 = GdbMemoryMapper::new(8);
        assert_eq!(mapper_64.max_address(), u64::MAX);
        let mapper_32 = GdbMemoryMapper::new(4);
        assert_eq!(mapper_32.max_address(), 0xFFFFFFFF);
    }

    #[test]
    fn test_memory_mapper_clear() {
        let mut mapper = GdbMemoryMapper::new(8);
        mapper.set_offset(1, 0x1000);
        mapper.set_offset(2, 0x2000);
        mapper.clear_offset(1);
        assert_eq!(mapper.get_offset(1), 0);
        assert_eq!(mapper.get_offset(2), 0x2000);
        mapper.clear_all();
        assert_eq!(mapper.get_offset(2), 0);
    }
}

#[cfg(test)]
mod register_mapper_tests {
    use super::*;

    #[test]
    fn test_register_mapper_new() {
        let mapper = GdbRegisterMapper::new();
        assert!(mapper.is_empty());
    }

    #[test]
    fn test_register_mapper_name_mapping() {
        let mut mapper = GdbRegisterMapper::new();
        mapper.map_name("rax", "RAX");
        mapper.map_name("rip", "RIP");
        assert_eq!(mapper.map_register_name("rax"), "RAX");
        assert_eq!(mapper.map_register_name("rip"), "RIP");
        assert_eq!(mapper.map_register_name("unknown"), "unknown");
    }

    #[test]
    fn test_register_mapper_size() {
        let mut mapper = GdbRegisterMapper::new();
        mapper.set_size("rax", 8);
        mapper.set_size("xmm0", 16);
        assert_eq!(mapper.get_size("rax"), Some(8));
        assert_eq!(mapper.get_size("xmm0"), Some(16));
        assert_eq!(mapper.get_size("unknown"), None);
    }

    #[test]
    fn test_register_mapper_group() {
        let mut mapper = GdbRegisterMapper::new();
        mapper.set_group("rax", "general");
        mapper.set_group("xmm0", "vector");
        assert_eq!(mapper.get_group("rax"), Some("general"));
        assert_eq!(mapper.get_group("xmm0"), Some("vector"));
        assert_eq!(mapper.get_group("unknown"), None);
    }

    #[test]
    fn test_register_mapper_len() {
        let mut mapper = GdbRegisterMapper::new();
        assert_eq!(mapper.len(), 0);
        mapper.map_name("rax", "RAX");
        mapper.map_name("rbx", "RBX");
        assert_eq!(mapper.len(), 2);
    }
}

#[cfg(test)]
mod process_manager_tests {
    use super::*;

    #[test]
    fn test_process_manager_new() {
        let mgr = GdbProcessManager::new();
        assert!(!mgr.initialized);
        assert!(mgr.inferiors.is_empty());
    }

    #[test]
    fn test_process_manager_initialize() {
        let mut mgr = GdbProcessManager::new();
        mgr.initialize();
        assert!(mgr.initialized);
        assert!(mgr.convenience.tracing_active);
        assert!(!mgr.signal_table.is_empty());
    }

    #[test]
    fn test_process_manager_shutdown() {
        let mut mgr = GdbProcessManager::new();
        mgr.initialize();
        mgr.shutdown();
        assert!(!mgr.initialized);
        assert!(!mgr.convenience.tracing_active);
    }

    #[test]
    fn test_process_manager_add_inferior() {
        let mut mgr = GdbProcessManager::new();
        mgr.add_inferior(GdbInferiorProcess::new(1));
        assert_eq!(mgr.inferiors.len(), 1);
        assert!(mgr.get_sync_state(1).is_some());
    }

    #[test]
    fn test_process_manager_remove_inferior() {
        let mut mgr = GdbProcessManager::new();
        mgr.add_inferior(GdbInferiorProcess::new(1));
        mgr.remove_inferior(1);
        assert!(mgr.inferiors.is_empty());
        assert!(mgr.get_sync_state(1).is_none());
    }

    #[test]
    fn test_process_manager_pointer_size() {
        let mgr = GdbProcessManager::new().with_pointer_size(4);
        assert_eq!(mgr.memory_mapper.pointer_size, 4);
    }

    #[test]
    fn test_process_manager_map_address() {
        let mut mgr = GdbProcessManager::new();
        let mut inf = GdbInferiorProcess::new(1);
        inf.state = ExecutionState::Stopped;
        mgr.add_inferior(inf);
        mgr.memory_mapper.set_offset(1, 0x1000);
        assert_eq!(mgr.map_address_to_gdb(0x5000), 0x6000);
        assert_eq!(mgr.map_address_from_gdb(0x6000), 0x5000);
    }

    #[test]
    fn test_process_manager_map_register() {
        let mut mgr = GdbProcessManager::new();
        mgr.register_mapper.map_name("rax", "RAX");
        let rv = mgr.map_register_value("rax", &0x1234u64.to_le_bytes());
        assert_eq!(rv.name, "RAX");
        assert_eq!(rv.as_u64(), Some(0x1234));
    }

    #[test]
    fn test_process_manager_stop_snapshot() {
        let mgr = GdbProcessManager::new();
        assert_eq!(
            mgr.build_stop_snapshot_description("breakpoint-hit"),
            "Stopped at breakpoint"
        );
        assert_eq!(
            mgr.build_stop_snapshot_description("end-stepping-range"),
            "Stepped"
        );
    }

    #[test]
    fn test_process_manager_summary() {
        let mut mgr = GdbProcessManager::new();
        mgr.initialize();
        mgr.add_inferior(GdbInferiorProcess::new(1));
        let summary = mgr.build_session_summary();
        assert!(summary.iter().any(|(k, v)| k == "Inferiors" && v == "1"));
        assert!(summary.iter().any(|(k, v)| k == "Threads" && v == "0"));
    }

    #[test]
    fn test_process_manager_has_active() {
        let mut mgr = GdbProcessManager::new();
        assert!(!mgr.has_active_inferiors());
        let mut inf = GdbInferiorProcess::new(1);
        inf.state = ExecutionState::Stopped;
        mgr.add_inferior(inf);
        assert!(mgr.has_active_inferiors());
    }
}

#[cfg(test)]
mod utility_tests {
    use super::*;

    #[test]
    fn test_should_skip_module() {
        assert!(should_skip_module(".gnu_debugdata for /usr/lib/libc.so.6"));
        assert!(!should_skip_module("/usr/lib/libc.so.6"));
        assert!(!should_skip_module("test.so"));
    }

    #[test]
    fn test_quantize_pages() {
        let (start, end) = quantize_pages(0x1500, 0x3500, 0x1000);
        assert_eq!(start, 0x1000);
        assert_eq!(end, 0x4000);
    }

    #[test]
    fn test_quantize_pages_aligned() {
        let (start, end) = quantize_pages(0x1000, 0x3000, 0x1000);
        assert_eq!(start, 0x1000);
        assert_eq!(end, 0x3000);
    }

    #[test]
    fn test_quantize_to_pages() {
        let (start, end) = quantize_to_pages(0x401234, 0x402500);
        assert_eq!(start, 0x401000);
        assert_eq!(end, 0x403000);
    }

    #[test]
    fn test_gnu_debugdata_prefix() {
        assert_eq!(GNU_DEBUGDATA_PREFIX, ".gnu_debugdata for ");
    }

    #[test]
    fn test_page_size() {
        assert_eq!(PAGE_SIZE, 4096);
    }
}
