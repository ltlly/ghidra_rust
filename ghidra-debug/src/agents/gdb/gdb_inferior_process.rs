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
    ExecutionState, MemoryRegion, ModuleInfo, ProcessInfo,
};

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
}
