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
//!
//! ## Additional features ported from Python agent
//! - PEB (Process Environment Block) address tracking
//! - Available process listing (`.tlist` output)
//! - Detailed memory region properties (Protect, Type, AllocationBase)
//! - Event filter management (specific + arbitrary exception filters)
//! - TTD (Time Travel Debugging) timeline support

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use super::dbgeng_thread::DbgEngThread;
use crate::agents::{
    BreakpointType, ExecutionState, MemoryRegion, ModuleInfo, ProcessInfo,
};

/// Still-active exit code sentinel from the Windows API.
pub const STILL_ACTIVE: i32 = 259;

/// Default page size on Windows (x86/x64).
pub const PAGE_SIZE: u64 = 4096;

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
    /// Process Environment Block address, if known.
    pub peb: Option<u64>,
    /// Human-readable process name (from `.tlist` or module).
    pub name: Option<String>,
    /// Breakpoint IDs associated with this process.
    pub breakpoint_ids: Vec<u32>,
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
            peb: None,
            name: None,
            breakpoint_ids: Vec::new(),
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

    /// Set the PEB address.
    pub fn with_peb(mut self, peb: u64) -> Self {
        self.peb = Some(peb);
        self
    }

    /// Set the process name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
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
        let mut values = vec![
            ("_state".to_string(), state.as_trace_str().to_string()),
            ("_display".to_string(), self.display.clone()),
        ];
        if let Some(code) = self.exit_code {
            values.push(("Exit Code".to_string(), code.to_string()));
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

    /// Compute the display string matching the Python agent format.
    ///
    /// Format: `'{procnum:x} {pid:x}'` for kernel mode, or
    /// `'{pid:x} [{procnum:x}]'` for user mode.
    pub fn build_display_string(&self, is_kernel: bool) -> String {
        match self.pid {
            Some(pid) => {
                if is_kernel {
                    format!("{:x} {:x}", self.num, pid)
                } else {
                    let name_part = self
                        .name
                        .as_deref()
                        .unwrap_or("");
                    if name_part.is_empty() {
                        format!("{:x} [{:x}]", pid, self.num)
                    } else {
                        format!("{:x} [{:x}] {}", pid, self.num, name_part)
                    }
                }
            }
            None => format!("{:x}", self.num),
        }
    }

    /// Quantize an address range to page boundaries.
    pub fn quantize_pages(start: u64, end: u64) -> (u64, u64) {
        (
            start / PAGE_SIZE * PAGE_SIZE,
            (end + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE,
        )
    }

    /// Find a module by name.
    pub fn find_module(&self, name: &str) -> Option<&ModuleInfo> {
        self.modules.iter().find(|m| m.name == name)
    }

    /// Find a module by base address.
    pub fn find_module_by_base(&self, base: u64) -> Option<&ModuleInfo> {
        self.modules.iter().find(|m| m.base == base)
    }

    /// Find the module that contains the given address.
    pub fn find_module_containing(&self, address: u64) -> Option<&ModuleInfo> {
        self.modules
            .iter()
            .find(|m| address >= m.base && address < m.base + m.size)
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

    /// Get a sorted list of all thread numbers.
    pub fn sorted_thread_numbers(&self) -> Vec<u32> {
        let mut nums: Vec<u32> = self.threads.keys().copied().collect();
        nums.sort();
        nums
    }

    /// Get a sorted list of all module base addresses.
    pub fn sorted_module_bases(&self) -> Vec<u64> {
        let mut bases: Vec<u64> = self.modules.iter().map(|m| m.base).collect();
        bases.sort();
        bases
    }

    /// Update this process's state from its threads.
    ///
    /// This sets `self.state` to the computed state from threads.
    pub fn refresh_state(&mut self) {
        self.state = self.compute_state();
    }

    /// Get a module by name.
    pub fn get_module(&self, name: &str) -> Option<&ModuleInfo> {
        self.modules.iter().find(|m| m.name == name)
    }

    /// Get a mutable reference to a module by name.
    pub fn get_module_mut(&mut self, name: &str) -> Option<&mut ModuleInfo> {
        self.modules.iter_mut().find(|m| m.name == name)
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

    /// Get the number of modules.
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    /// Get the number of memory regions.
    pub fn memory_region_count(&self) -> usize {
        self.memory_regions.len()
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

    /// Build the retain keys for process-level object children.
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
            .map(|m| format!("[{}]", m.name))
            .collect()
    }

    /// Build the retain keys for memory region children.
    pub fn build_region_retain_keys(&self) -> Vec<String> {
        self.memory_regions
            .iter()
            .map(|r| format!("[{:08x}]", r.base))
            .collect()
    }

    /// Build the trace object key-value pairs for this process, including PEB.
    ///
    /// Extended version of `build_trace_values` that includes PEB and name.
    pub fn build_trace_values_extended(&self, is_kernel: bool) -> Vec<(String, String)> {
        let state = self.compute_state();
        let mut values = vec![
            ("State".to_string(), state.as_trace_str().to_string()),
            (
                "_display".to_string(),
                self.build_display_string(is_kernel),
            ),
        ];
        if let Some(pid) = self.pid {
            values.push(("PID".to_string(), format!("{}", pid)));
        }
        if let Some(peb) = self.peb {
            values.push(("PEB".to_string(), format!("0x{:x}", peb)));
        }
        if let Some(ref name) = self.name {
            values.push(("Name".to_string(), name.clone()));
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

/// An available process entry, as reported by `.tlist`.
///
/// This represents a process visible on the system, not necessarily
/// being debugged. Used for the `Sessions[0].Available` tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailableProcess {
    /// Process ID.
    pub pid: u64,
    /// Process name (image file name).
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
    pub fn build_trace_values(&self, radix: u32) -> Vec<(String, String)> {
        let pid_str = match radix {
            16 => format!("0x{:x}", self.pid),
            8 => format!("0{:o}", self.pid),
            _ => format!("{}", self.pid),
        };
        vec![
            ("PID".to_string(), format!("{}", self.pid)),
            ("Name".to_string(), self.name.clone()),
            ("_display".to_string(), format!("{} {}", pid_str, self.name)),
        ]
    }
}

/// Extended memory region with Windows-specific protection and type fields.
///
/// This corresponds to the `MEMORY_BASIC_INFORMATION64` structure from
/// the Windows API, used by `put_regions` in the Python agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetailedMemoryRegion {
    /// Base address of the region.
    pub base: u64,
    /// Size of the region in bytes.
    pub size: u64,
    /// Allocation base address.
    pub allocation_base: u64,
    /// Memory protection attributes (e.g. `PAGE_EXECUTE_READWRITE`).
    pub protect: u32,
    /// Memory type (`MEM_IMAGE`, `MEM_MAPPED`, `MEM_PRIVATE`).
    pub mem_type: u32,
    /// Display name (e.g. mapped file name).
    pub display: Option<String>,
}

impl DetailedMemoryRegion {
    /// Create a new detailed memory region.
    pub fn new(base: u64, size: u64) -> Self {
        Self {
            base,
            size,
            allocation_base: base,
            protect: 0,
            mem_type: 0,
            display: None,
        }
    }

    /// Set the allocation base.
    pub fn with_allocation_base(mut self, base: u64) -> Self {
        self.allocation_base = base;
        self
    }

    /// Set the protection flags.
    pub fn with_protect(mut self, protect: u32) -> Self {
        self.protect = protect;
        self
    }

    /// Set the memory type.
    pub fn with_mem_type(mut self, mem_type: u32) -> Self {
        self.mem_type = mem_type;
        self
    }

    /// Set the display name.
    pub fn with_display(mut self, display: impl Into<String>) -> Self {
        self.display = Some(display.into());
        self
    }

    /// Whether the region is readable.
    pub fn is_readable(&self) -> bool {
        // PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ, PAGE_READONLY,
        // PAGE_WRITECOPY, PAGE_EXECUTE_WRITECOPY, PAGE_READWRITE
        self.protect == 0 || (self.protect & 0x66) != 0
    }

    /// Whether the region is writable.
    pub fn is_writable(&self) -> bool {
        self.protect == 0 || (self.protect & 0xCC) != 0
    }

    /// Whether the region is executable.
    pub fn is_executable(&self) -> bool {
        self.protect == 0 || (self.protect & 0xF0) != 0
    }

    /// Convert to the common `MemoryRegion`.
    pub fn to_memory_region(&self) -> MemoryRegion {
        let mut perms = String::new();
        perms.push(if self.is_readable() { 'r' } else { '-' });
        perms.push(if self.is_writable() { 'w' } else { '-' });
        perms.push(if self.is_executable() { 'x' } else { '-' });
        MemoryRegion {
            base: self.base,
            size: self.size,
            offset: 0,
            permissions: perms,
            object_file: self.display.clone().unwrap_or_default(),
        }
    }

    /// Build trace object key-value pairs.
    pub fn build_trace_values(&self) -> Vec<(String, String)> {
        let mut values = vec![
            (
                "Range".to_string(),
                format!("0x{:x}:0x{:x}", self.base, self.base + self.size),
            ),
            ("AllocationBase".to_string(), format!("0x{:x}", self.allocation_base)),
            ("Protect".to_string(), format!("0x{:x}", self.protect)),
            ("Type".to_string(), format!("0x{:x}", self.mem_type)),
            (
                "_readable".to_string(),
                self.is_readable().to_string(),
            ),
            (
                "_writable".to_string(),
                self.is_writable().to_string(),
            ),
            (
                "_executable".to_string(),
                self.is_executable().to_string(),
            ),
        ];
        if let Some(ref name) = self.display {
            values.push(("_display".to_string(), name.clone()));
        }
        values
    }
}

/// A PE section within a loaded module.
///
/// Sections correspond to PE sections (e.g., `.text`, `.rdata`, `.data`)
/// within a loaded DLL or executable. Ported from the Python agent's
/// `SECTIONS_ADD_PATTERN` / `SECTION_KEY_PATTERN` path structure.
///
/// In dbgeng, sections are listed under `Processes[N].Modules[base].Sections`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleSection {
    /// Section name (e.g., ".text", ".rdata", ".data", ".pdata").
    pub name: String,
    /// Start address (virtual address) of the section.
    pub start: u64,
    /// End address (exclusive) of the section.
    pub end: u64,
    /// Section size in bytes.
    pub size: u32,
    /// Section characteristics flags (PE `IMAGE_SECTION_HEADER.Characteristics`).
    pub characteristics: u32,
}

impl ModuleSection {
    /// Create a new module section.
    pub fn new(name: impl Into<String>, start: u64, size: u32) -> Self {
        Self {
            name: name.into(),
            start,
            end: start + size as u64,
            size,
            characteristics: 0,
        }
    }

    /// Set the characteristics flags.
    pub fn with_characteristics(mut self, chars: u32) -> Self {
        self.characteristics = chars;
        self
    }

    /// Whether the section contains executable code.
    ///
    /// Checks `IMAGE_SCN_MEM_EXECUTE` (0x20000000).
    pub fn is_executable(&self) -> bool {
        self.characteristics & 0x20000000 != 0
    }

    /// Whether the section contains initialized data.
    ///
    /// Checks `IMAGE_SCN_CNT_INITIALIZED_DATA` (0x00000040).
    pub fn is_initialized_data(&self) -> bool {
        self.characteristics & 0x00000040 != 0
    }

    /// Whether the section contains uninitialized data.
    ///
    /// Checks `IMAGE_SCN_CNT_UNINITIALIZED_DATA` (0x00000080).
    pub fn is_uninitialized_data(&self) -> bool {
        self.characteristics & 0x00000080 != 0
    }

    /// Whether the section is readable.
    ///
    /// Checks `IMAGE_SCN_MEM_READ` (0x40000000).
    pub fn is_readable(&self) -> bool {
        self.characteristics & 0x40000000 != 0
    }

    /// Whether the section is writable.
    ///
    /// Checks `IMAGE_SCN_MEM_WRITE` (0x80000000).
    pub fn is_writable(&self) -> bool {
        self.characteristics & 0x80000000 != 0
    }

    /// Build the trace path for this section within a module.
    pub fn trace_path(&self, proc_num: u32, module_base: u64) -> String {
        format!(
            "Processes[{}].Modules[0x{:x}].Sections[{}]",
            proc_num, module_base, self.name
        )
    }

    /// Build trace object key-value pairs.
    pub fn build_trace_values(&self) -> Vec<(String, String)> {
        vec![
            (
                "Range".to_string(),
                format!("0x{:x}:0x{:x}", self.start, self.end),
            ),
            ("Size".to_string(), format!("0x{:x}", self.size)),
            (
                "Characteristics".to_string(),
                format!("0x{:x}", self.characteristics),
            ),
            (
                "_display".to_string(),
                format!("{} 0x{:x}", self.name, self.size),
            ),
        ]
    }
}

/// Extended module info with PE sections support.
///
/// This wraps `ModuleInfo` with additional section data ported from
/// the Python agent's `SECTIONS_ADD_PATTERN` path structure and the
/// GDB agent's `ModuleWithSections` pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleWithSections {
    /// Base module info.
    pub info: ModuleInfo,
    /// Sections within this module, keyed by section name.
    pub sections: BTreeMap<String, ModuleSection>,
    /// Module flags from `_DEBUG_MODULE_PARAMETERS.Flags`.
    pub flags: u32,
    /// Symbol type from `_DEBUG_MODULE_PARAMETERS.SymbolType`.
    pub symbol_type: u32,
    /// Whether debug info is loaded for this module.
    pub debug_info_loaded: bool,
}

impl ModuleWithSections {
    /// Create from a `ModuleInfo`.
    pub fn from_info(info: ModuleInfo) -> Self {
        Self {
            info,
            sections: BTreeMap::new(),
            flags: 0,
            symbol_type: 0,
            debug_info_loaded: false,
        }
    }

    /// Set module flags.
    pub fn with_flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Set symbol type.
    pub fn with_symbol_type(mut self, sym_type: u32) -> Self {
        self.symbol_type = sym_type;
        self
    }

    /// Mark debug info as loaded.
    pub fn with_debug_info_loaded(mut self, loaded: bool) -> Self {
        self.debug_info_loaded = loaded;
        self
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

    /// Get a section by name.
    pub fn get_section(&self, name: &str) -> Option<&ModuleSection> {
        self.sections.get(name)
    }

    /// Check if a section exists by name.
    pub fn has_section(&self, name: &str) -> bool {
        self.sections.contains_key(name)
    }

    /// Build the trace path for this module's sections container.
    pub fn sections_path(&self, proc_num: u32) -> String {
        format!(
            "Processes[{}].Modules[0x{:x}].Sections",
            proc_num, self.info.base
        )
    }

    /// Build the trace path for this module.
    pub fn trace_path(&self, proc_num: u32) -> String {
        format!(
            "Processes[{}].Modules[0x{:x}]",
            proc_num, self.info.base
        )
    }

    /// Build trace object key-value pairs for the module.
    pub fn build_trace_values(&self) -> Vec<(String, String)> {
        let mut values = vec![
            (
                "Range".to_string(),
                format!("0x{:x}:0x{:x}", self.info.base, self.info.base + self.info.size),
            ),
            ("Name".to_string(), self.info.name.clone()),
            (
                "_display".to_string(),
                format!("{:x} {}", self.info.base, self.info.name),
            ),
            ("Flags".to_string(), format!("0x{:x}", self.flags)),
        ];
        if let Some(ref path) = self.info.load_path {
            values.push(("Load Path".to_string(), path.clone()));
        }
        if self.debug_info_loaded {
            values.push(("Debug Info".to_string(), "loaded".to_string()));
        }
        values
    }
}

/// Process-level breakpoint state for dbgeng.
///
/// Ported from the Python agent's `put_single_breakpoint`. Dbgeng
/// tracks breakpoints globally but resolves them per-process. This
/// struct captures all the fields that the Python agent writes to
/// the trace object tree under `Processes[N].Debug.Breakpoints[id]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbgEngProcessBreakpoint {
    /// Breakpoint ID (dbgeng-internal).
    pub id: u32,
    /// Breakpoint type.
    pub bp_type: BreakpointType,
    /// Resolved address, if not deferred.
    pub address: Option<u64>,
    /// Whether the breakpoint is enabled.
    pub enabled: bool,
    /// Hit count.
    pub hit_count: u32,
    /// Current pass count.
    pub current_pass_count: u32,
    /// Pass count (skip first N hits).
    pub pass_count: u32,
    /// Offset expression (for deferred or watchpoint breakpoints).
    pub expression: Option<String>,
    /// Match thread ID restriction (if any).
    pub match_tid: Option<u32>,
    /// Handler name.
    pub handler: Option<String>,
    /// Command to execute on hit.
    pub command: Option<String>,
    /// Breakpoint flags (from `GetFlags()`).
    pub flags: u32,
    /// Data breakpoint width (for watchpoints).
    pub data_width: Option<u32>,
    /// Data breakpoint access type (1=W, 2=R, 4=X).
    pub data_access_type: Option<u32>,
}

impl DbgEngProcessBreakpoint {
    /// Create a new breakpoint entry.
    pub fn new(id: u32) -> Self {
        Self {
            id,
            bp_type: BreakpointType::Software,
            address: None,
            enabled: true,
            hit_count: 0,
            current_pass_count: 0,
            pass_count: 0,
            expression: None,
            match_tid: None,
            handler: None,
            command: None,
            flags: 0,
            data_width: None,
            data_access_type: None,
        }
    }

    /// Set the breakpoint type to hardware.
    pub fn with_hardware(mut self) -> Self {
        self.bp_type = BreakpointType::Hardware;
        self
    }

    /// Set the breakpoint type to data (watchpoint).
    pub fn with_data(mut self, width: u32, access_type: u32) -> Self {
        self.bp_type = BreakpointType::Memory;
        self.data_width = Some(width);
        self.data_access_type = Some(access_type);
        self
    }

    /// Set the resolved address.
    pub fn with_address(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    /// Set the offset expression (for deferred breakpoints).
    pub fn with_expression(mut self, expr: impl Into<String>) -> Self {
        self.expression = Some(expr.into());
        self
    }

    /// Set the match thread ID.
    pub fn with_match_tid(mut self, tid: u32) -> Self {
        self.match_tid = Some(tid);
        self
    }

    /// Set the handler name.
    pub fn with_handler(mut self, handler: impl Into<String>) -> Self {
        self.handler = Some(handler.into());
        self
    }

    /// Set the command.
    pub fn with_command(mut self, cmd: impl Into<String>) -> Self {
        self.command = Some(cmd.into());
        self
    }

    /// Set the flags.
    pub fn with_flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Whether this breakpoint is deferred (no resolved address).
    pub fn is_deferred(&self) -> bool {
        self.address.is_none()
    }

    /// Whether the breakpoint is enabled.
    pub fn is_enabled(&self) -> bool {
        self.flags & 0x1 != 0 // DEBUG_BREAKPOINT_ENABLED
    }

    /// Whether the breakpoint is deferred.
    pub fn is_deferred_flag(&self) -> bool {
        self.flags & 0x2 != 0 // DEBUG_BREAKPOINT_DEFERRED
    }

    /// Record a hit.
    pub fn record_hit(&mut self) {
        self.hit_count += 1;
    }

    /// Build the trace path for this breakpoint within a process.
    pub fn trace_path(&self, proc_num: u32) -> String {
        format!(
            "Processes[{}].Debug.Breakpoints[{}]",
            proc_num, self.id
        )
    }

    /// Get the access type label for data breakpoints.
    pub fn access_type_label(&self) -> &'static str {
        match self.data_access_type {
            Some(4) => "X", // DEBUG_BREAKPOINT_EXECUTE
            Some(2) => "R", // DEBUG_BREAKPOINT_READ
            Some(1) => "W", // DEBUG_BREAKPOINT_WRITE
            _ => "x",
        }
    }

    /// Build trace object key-value pairs.
    pub fn build_trace_values(&self) -> Vec<(String, String)> {
        let mut values = Vec::new();
        if let Some(addr) = self.address {
            values.push(("Address".to_string(), format!("0x{:x}", addr)));
        } else if let Some(ref expr) = self.expression {
            values.push(("Address".to_string(), "[Deferred]".to_string()));
            values.push(("Expression".to_string(), expr.clone()));
        }
        values.push(("Enabled".to_string(), self.enabled.to_string()));
        values.push(("HitCount".to_string(), self.hit_count.to_string()));
        values.push(("Pass Count".to_string(), self.pass_count.to_string()));
        values.push(("Current Pass Count".to_string(), self.current_pass_count.to_string()));
        values.push(("Flags".to_string(), format!("0x{:x}", self.flags)));
        let kind = match self.bp_type {
            BreakpointType::Software => "x",
            BreakpointType::Hardware => "x",
            BreakpointType::Memory => self.access_type_label(),
        };
        values.push(("Kinds".to_string(), kind.to_string()));
        if let Some(tid) = self.match_tid {
            values.push(("Match TID".to_string(), format!("{:04x}", tid)));
        }
        if let Some(ref handler) = self.handler {
            values.push(("Handler".to_string(), handler.clone()));
        }
        if let Some(ref cmd) = self.command {
            values.push(("Command".to_string(), cmd.clone()));
        }
        values
    }
}

/// Dbgeng process manager -- manages multiple processes within a single
/// dbgeng debug session.
///
/// Dbgeng can debug multiple processes (e.g., following child processes,
/// or attaching to multiple targets). This manager tracks all known
/// processes and provides convenient access, mirroring the GDB agent's
/// `GdbInferiorManager`.
#[derive(Debug, Default)]
pub struct DbgEngProcessManager {
    processes: BTreeMap<u32, DbgEngInferiorProcess>,
    active_num: Option<u32>,
}

impl DbgEngProcessManager {
    /// Create a new empty process manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a process.
    pub fn add(&mut self, process: DbgEngInferiorProcess) {
        let num = process.num;
        if self.active_num.is_none() {
            self.active_num = Some(num);
        }
        self.processes.insert(num, process);
    }

    /// Remove a process by number.
    pub fn remove(&mut self, num: u32) -> Option<DbgEngInferiorProcess> {
        let removed = self.processes.remove(&num);
        if self.active_num == Some(num) {
            self.active_num = self.processes.keys().next().copied();
        }
        removed
    }

    /// Get a process by number.
    pub fn get(&self, num: u32) -> Option<&DbgEngInferiorProcess> {
        self.processes.get(&num)
    }

    /// Get a mutable process by number.
    pub fn get_mut(&mut self, num: u32) -> Option<&mut DbgEngInferiorProcess> {
        self.processes.get_mut(&num)
    }

    /// Get the currently active process.
    pub fn active(&self) -> Option<&DbgEngInferiorProcess> {
        self.active_num.and_then(|n| self.processes.get(&n))
    }

    /// Get a mutable reference to the active process.
    pub fn active_mut(&mut self) -> Option<&mut DbgEngInferiorProcess> {
        self.active_num.and_then(move |n| self.processes.get_mut(&n))
    }

    /// Set the active process by number.
    pub fn set_active(&mut self, num: u32) {
        if self.processes.contains_key(&num) {
            self.active_num = Some(num);
        }
    }

    /// Get the active process number.
    pub fn active_num(&self) -> Option<u32> {
        self.active_num
    }

    /// Get all process numbers.
    pub fn numbers(&self) -> Vec<u32> {
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
    pub fn all(&self) -> &BTreeMap<u32, DbgEngInferiorProcess> {
        &self.processes
    }

    /// Get all alive (non-exited) processes.
    pub fn alive(&self) -> Vec<&DbgEngInferiorProcess> {
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

    /// Get all process numbers sorted.
    pub fn sorted_numbers(&self) -> Vec<u32> {
        let mut nums: Vec<u32> = self.processes.keys().copied().collect();
        nums.sort();
        nums
    }

    /// Refresh the state of all processes from their threads.
    pub fn refresh_all_states(&mut self) {
        for p in self.processes.values_mut() {
            p.refresh_state();
        }
    }
}

/// Continue option for event/exception filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ContinueOption {
    /// Continue execution (not handled).
    ContinueNotHandled,
    /// Continue execution (handled).
    ContinueHandled,
}

impl ContinueOption {
    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::ContinueNotHandled => "Continue not handled",
            Self::ContinueHandled => "Continue handled",
        }
    }

    /// Convert from integer value (0 or 1).
    pub fn from_value(v: u32) -> Self {
        match v {
            1 => Self::ContinueHandled,
            _ => Self::ContinueNotHandled,
        }
    }
}

/// Execution option for event/exception filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExecutionOption {
    /// Break.
    Break,
    /// Continue.
    Continue,
    /// Ignore.
    Ignore,
    /// Second-chance break.
    SecondChanceBreak,
}

impl ExecutionOption {
    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Break => "Break",
            Self::Continue => "Continue",
            Self::Ignore => "Ignore",
            Self::SecondChanceBreak => "Second-chance break",
        }
    }

    /// Convert from integer value (0-3).
    pub fn from_value(v: u32) -> Self {
        match v {
            0 => Self::Break,
            1 => Self::Continue,
            2 => Self::Ignore,
            3 => Self::SecondChanceBreak,
            _ => Self::Break,
        }
    }
}

/// An event filter entry (specific or exception).
///
/// Corresponds to the event filter objects under
/// `Processes[N].Debug.Events` and `Processes[N].Debug.Exceptions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventFilter {
    /// Filter index.
    pub index: u32,
    /// Event/exception name.
    pub name: String,
    /// Exception code (hex string), for exception filters.
    pub exception_code: Option<String>,
    /// Command to execute when event fires.
    pub command: Option<String>,
    /// Second-chance command (for exceptions).
    pub command2: Option<String>,
    /// Argument for the specific filter.
    pub argument: Option<String>,
    /// Handler name.
    pub handler: Option<String>,
    /// Continue option.
    pub continue_option: ContinueOption,
    /// Execution option.
    pub execution_option: ExecutionOption,
    /// Whether this is a specific event filter (vs. arbitrary exception).
    pub is_specific: bool,
}

impl EventFilter {
    /// Create a new event filter.
    pub fn new(index: u32, name: impl Into<String>) -> Self {
        Self {
            index,
            name: name.into(),
            exception_code: None,
            command: None,
            command2: None,
            argument: None,
            handler: None,
            continue_option: ContinueOption::ContinueNotHandled,
            execution_option: ExecutionOption::Break,
            is_specific: true,
        }
    }

    /// Set the exception code.
    pub fn with_exception_code(mut self, code: impl Into<String>) -> Self {
        self.exception_code = Some(code.into());
        self
    }

    /// Set the command.
    pub fn with_command(mut self, cmd: impl Into<String>) -> Self {
        self.command = Some(cmd.into());
        self
    }

    /// Set the second-chance command.
    pub fn with_command2(mut self, cmd: impl Into<String>) -> Self {
        self.command2 = Some(cmd.into());
        self
    }

    /// Set the argument.
    pub fn with_argument(mut self, arg: impl Into<String>) -> Self {
        self.argument = Some(arg.into());
        self
    }

    /// Set the handler.
    pub fn with_handler(mut self, handler: impl Into<String>) -> Self {
        self.handler = Some(handler.into());
        self
    }

    /// Set the continue option.
    pub fn with_continue_option(mut self, opt: ContinueOption) -> Self {
        self.continue_option = opt;
        self
    }

    /// Set the execution option.
    pub fn with_execution_option(mut self, opt: ExecutionOption) -> Self {
        self.execution_option = opt;
        self
    }

    /// Mark as specific or arbitrary.
    pub fn with_specific(mut self, specific: bool) -> Self {
        self.is_specific = specific;
        self
    }

    /// Build trace path under the process.
    pub fn trace_path_events(&self, proc_num: u32) -> String {
        format!(
            "Processes[{}].Debug.Events[{}]",
            proc_num, self.index
        )
    }

    /// Build trace path under the process exceptions container.
    pub fn trace_path_exceptions(&self, proc_num: u32) -> String {
        format!(
            "Processes[{}].Debug.Exceptions[{}]",
            proc_num, self.index
        )
    }

    /// Build trace object key-value pairs.
    pub fn build_trace_values(&self) -> Vec<(String, String)> {
        let mut values = vec![
            ("Name".to_string(), self.name.clone()),
            (
                "_display".to_string(),
                format!("{} {}", self.index, self.name),
            ),
        ];
        if let Some(ref code) = self.exception_code {
            values.push(("Code".to_string(), code.clone()));
        }
        if let Some(ref cmd) = self.command {
            values.push(("Cmd".to_string(), cmd.clone()));
        }
        if let Some(ref cmd2) = self.command2 {
            values.push(("Cmd2".to_string(), cmd2.clone()));
        }
        if let Some(ref arg) = self.argument {
            values.push(("Arg".to_string(), arg.clone()));
        }
        if let Some(ref handler) = self.handler {
            values.push(("Handler".to_string(), handler.clone()));
        }
        values
    }
}

/// TTD (Time Travel Debugging) position.
///
/// Represents a point in the time-travel trace, consisting of a
/// major (sequence) and minor (step) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TtdPosition {
    /// Major position (sequence number).
    pub major: u64,
    /// Minor position (step within sequence).
    pub minor: u64,
}

impl TtdPosition {
    /// Create a new TTD position.
    pub fn new(major: u64, minor: u64) -> Self {
        Self { major, minor }
    }

    /// Format as a schedule string for the trace.
    pub fn to_schedule_string(&self) -> String {
        format!("{}.{}", self.major, self.minor)
    }
}

impl PartialOrd for TtdPosition {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TtdPosition {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
    }
}

/// TTD event type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TtdEventType {
    /// Module was loaded.
    ModuleLoaded,
    /// Module was unloaded.
    ModuleUnloaded,
    /// Thread was created.
    ThreadCreated,
    /// Thread was terminated.
    ThreadTerminated,
    /// Custom event.
    Custom(String),
}

impl TtdEventType {
    /// Parse from the string reported by dbgeng.
    pub fn from_str(s: &str) -> Self {
        match s {
            "ModuleLoaded" => Self::ModuleLoaded,
            "ModuleUnloaded" => Self::ModuleUnloaded,
            "ThreadCreated" => Self::ThreadCreated,
            "ThreadTerminated" => Self::ThreadTerminated,
            other => Self::Custom(other.to_string()),
        }
    }
}

/// A TTD trace event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TtdEvent {
    /// Position in the trace.
    pub position: TtdPosition,
    /// Type of event.
    pub event_type: TtdEventType,
    /// Snapshot ID in the trace, once assigned.
    pub snap: Option<u64>,
}

impl TtdEvent {
    /// Create a new TTD event.
    pub fn new(position: TtdPosition, event_type: TtdEventType) -> Self {
        Self {
            position,
            event_type,
            snap: None,
        }
    }

    /// Build the description string for snapshot creation.
    pub fn description(&self) -> String {
        let type_str = match &self.event_type {
            TtdEventType::ModuleLoaded => "ModuleLoaded",
            TtdEventType::ModuleUnloaded => "ModuleUnloaded",
            TtdEventType::ThreadCreated => "ThreadCreated",
            TtdEventType::ThreadTerminated => "ThreadTerminated",
            TtdEventType::Custom(s) => s.as_str(),
        };
        format!(
            "[{:x}:{:x}] {}",
            self.position.major, self.position.minor, type_str
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

/// Tracks the synchronization state for a process between stops.
///
/// Ported from the Python `InferiorState` class in `hooks.py`. Tracks
/// which aspects of the process have changed and need re-sync.
#[derive(Debug, Clone)]
pub struct ProcessSyncState {
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
    /// Visited (thread, frame_level) pairs since last stop.
    pub visited: BTreeSet<(u32, u32)>,
    /// Snapshots recorded for this process.
    pub snapshots: Vec<Snapshot>,
    /// Next snapshot ID.
    next_snap_id: u64,
}

impl Default for ProcessSyncState {
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

impl ProcessSyncState {
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
        assert!(p.peb.is_none());
        assert!(p.name.is_none());
        assert!(p.breakpoint_ids.is_empty());
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

    #[test]
    fn test_process_peb_and_name() {
        let p = DbgEngInferiorProcess::new(1)
            .with_peb(0x7ffde000)
            .with_name("notepad.exe");
        assert_eq!(p.peb, Some(0x7ffde000));
        assert_eq!(p.name.as_deref(), Some("notepad.exe"));
    }

    #[test]
    fn test_process_build_display_string_user() {
        let p = DbgEngInferiorProcess::new(0)
            .with_pid(0x1234)
            .with_name("test.exe");
        let disp = p.build_display_string(false);
        assert!(disp.contains("1234"));
        assert!(disp.contains("test.exe"));
    }

    #[test]
    fn test_process_build_display_string_kernel() {
        let p = DbgEngInferiorProcess::new(1).with_pid(0x4);
        let disp = p.build_display_string(true);
        assert_eq!(disp, "1 4");
    }

    #[test]
    fn test_process_quantize_pages() {
        let (start, end) = DbgEngInferiorProcess::quantize_pages(0x1234, 0x5678);
        assert_eq!(start, 0x1000);
        assert_eq!(end, 0x6000);
    }

    #[test]
    fn test_process_find_module() {
        let mut p = DbgEngInferiorProcess::new(1);
        p.add_module(ModuleInfo {
            name: "kernel32.dll".to_string(),
            base: 0x7ff800000000,
            size: 0x1e6000,
            build_id: None,
            debug_path: None,
            load_path: None,
        });
        assert!(p.find_module("kernel32.dll").is_some());
        assert!(p.find_module("ntdll.dll").is_none());
        assert!(p.find_module_by_base(0x7ff800000000).is_some());
        assert!(p.find_module_containing(0x7ff800100000).is_some());
        assert!(p.find_module_containing(0x100000).is_none());
    }

    #[test]
    fn test_process_find_region() {
        let mut p = DbgEngInferiorProcess::new(1);
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
    }

    #[test]
    fn test_process_sorted_lists() {
        let mut p = DbgEngInferiorProcess::new(1);
        p.add_thread(DbgEngThread::new(3));
        p.add_thread(DbgEngThread::new(1));
        p.add_thread(DbgEngThread::new(2));
        assert_eq!(p.sorted_thread_numbers(), vec![1, 2, 3]);
    }

    #[test]
    fn test_process_build_trace_values_extended() {
        let p = DbgEngInferiorProcess::new(0)
            .with_pid(0x1234)
            .with_peb(0x7ffde000)
            .with_name("test.exe");
        let values = p.build_trace_values_extended(false);
        assert!(values.iter().any(|(k, v)| k == "PID" && v == "4660"));
        assert!(values.iter().any(|(k, v)| k == "PEB" && v == "0x7ffde000"));
        assert!(values.iter().any(|(k, v)| k == "Name" && v == "test.exe"));
    }

    #[test]
    fn test_process_thread_queries() {
        let mut p = DbgEngInferiorProcess::new(1);
        p.add_thread(DbgEngThread::new(1).with_state(ExecutionState::Running));
        p.add_thread(DbgEngThread::new(2).with_state(ExecutionState::Stopped));
        p.add_thread(DbgEngThread::new(3).with_state(ExecutionState::Running));
        assert_eq!(p.running_thread_numbers(), vec![1, 3]);
        assert_eq!(p.stopped_thread_numbers(), vec![2]);
        assert_eq!(p.total_frame_count(), 0);
    }

    #[test]
    fn test_available_process() {
        let ap = AvailableProcess::new(1234, "notepad.exe");
        assert_eq!(ap.trace_path(), "Sessions[0].Available[1234]");
        let values = ap.build_trace_values(16);
        assert!(values.iter().any(|(k, v)| k == "PID" && v == "1234"));
        assert!(values.iter().any(|(k, v)| k == "Name" && v == "notepad.exe"));
    }

    #[test]
    fn test_detailed_memory_region() {
        let r = DetailedMemoryRegion::new(0x10000, 0x5000)
            .with_protect(0x20) // PAGE_EXECUTE_READ
            .with_mem_type(0x1000000) // MEM_IMAGE
            .with_display("test.exe");
        assert!(r.is_readable());
        assert!(!r.is_writable());
        assert!(r.is_executable());
        let mr = r.to_memory_region();
        assert_eq!(mr.permissions, "r-x");
        let values = r.build_trace_values();
        assert!(values.iter().any(|(k, _)| k == "Protect"));
    }

    #[test]
    fn test_detailed_memory_region_rw() {
        let r = DetailedMemoryRegion::new(0x20000, 0x1000)
            .with_protect(0x04); // PAGE_READWRITE
        assert!(r.is_readable());
        assert!(r.is_writable());
        assert!(!r.is_executable());
        let mr = r.to_memory_region();
        assert_eq!(mr.permissions, "rw-");
    }

    #[test]
    fn test_continue_option() {
        assert_eq!(
            ContinueOption::from_value(0),
            ContinueOption::ContinueNotHandled
        );
        assert_eq!(
            ContinueOption::from_value(1),
            ContinueOption::ContinueHandled
        );
        assert_eq!(ContinueOption::ContinueNotHandled.label(), "Continue not handled");
    }

    #[test]
    fn test_execution_option() {
        assert_eq!(ExecutionOption::from_value(0), ExecutionOption::Break);
        assert_eq!(ExecutionOption::from_value(1), ExecutionOption::Continue);
        assert_eq!(ExecutionOption::from_value(2), ExecutionOption::Ignore);
        assert_eq!(
            ExecutionOption::from_value(3),
            ExecutionOption::SecondChanceBreak
        );
    }

    #[test]
    fn test_event_filter() {
        let f = EventFilter::new(0, "Create Thread")
            .with_command("gn")
            .with_handler("my_handler")
            .with_continue_option(ContinueOption::ContinueHandled)
            .with_execution_option(ExecutionOption::Break);
        assert_eq!(f.trace_path_events(1), "Processes[1].Debug.Events[0]");
        assert_eq!(
            f.trace_path_exceptions(1),
            "Processes[1].Debug.Exceptions[0]"
        );
        let values = f.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "Name" && v == "Create Thread"));
        assert!(values.iter().any(|(k, v)| k == "Cmd" && v == "gn"));
        assert!(values.iter().any(|(k, v)| k == "Handler" && v == "my_handler"));
    }

    #[test]
    fn test_event_filter_exception() {
        let f = EventFilter::new(2, "Access Violation")
            .with_exception_code("0xc0000005")
            .with_specific(false)
            .with_command2("gn");
        assert!(!f.is_specific);
        assert_eq!(f.exception_code.as_deref(), Some("0xc0000005"));
    }

    #[test]
    fn test_ttd_position() {
        let p1 = TtdPosition::new(1, 0);
        let p2 = TtdPosition::new(1, 5);
        let p3 = TtdPosition::new(2, 0);
        assert!(p1 < p2);
        assert!(p2 < p3);
        assert_eq!(p1.to_schedule_string(), "1.0");
    }

    #[test]
    fn test_ttd_event_type() {
        assert_eq!(
            TtdEventType::from_str("ModuleLoaded"),
            TtdEventType::ModuleLoaded
        );
        assert_eq!(
            TtdEventType::from_str("CustomThing"),
            TtdEventType::Custom("CustomThing".to_string())
        );
    }

    #[test]
    fn test_ttd_event() {
        let e = TtdEvent::new(
            TtdPosition::new(5, 10),
            TtdEventType::ModuleLoaded,
        );
        assert_eq!(e.description(), "[5:a] ModuleLoaded");
        assert!(e.snap.is_none());
    }

    #[test]
    fn test_process_breakpoint_ids() {
        let mut p = DbgEngInferiorProcess::new(1);
        p.add_breakpoint_id(1);
        p.add_breakpoint_id(2);
        p.add_breakpoint_id(1); // duplicate
        assert_eq!(p.breakpoint_ids.len(), 2);
        p.remove_breakpoint_id(1);
        assert_eq!(p.breakpoint_ids.len(), 1);
        assert_eq!(p.breakpoint_ids[0], 2);
    }

    #[test]
    fn test_process_memory_query() {
        let mut p = DbgEngInferiorProcess::new(1);
        p.add_memory_region(MemoryRegion {
            base: 0x400000,
            size: 0x1000,
            offset: 0,
            permissions: "rwx".to_string(),
            object_file: "test".to_string(),
        });
        assert!(p.is_address_mapped(0x400000));
        assert!(p.is_address_mapped(0x400500));
        assert!(!p.is_address_mapped(0x500000));
        assert!(!p.is_address_mapped(0x300000));
    }

    #[test]
    fn test_process_get_memory_region() {
        let mut p = DbgEngInferiorProcess::new(1);
        p.add_memory_region(MemoryRegion {
            base: 0x10000,
            size: 0x5000,
            offset: 0,
            permissions: "rw-".to_string(),
            object_file: "stack".to_string(),
        });
        assert!(p.get_memory_region(0x10000).is_some());
        assert!(p.get_memory_region(0x20000).is_none());
    }

    #[test]
    fn test_process_module_queries() {
        let mut p = DbgEngInferiorProcess::new(1);
        p.add_module(ModuleInfo {
            name: "kernel32.dll".to_string(),
            base: 0x7ff800000000,
            size: 0x1e6000,
            build_id: None,
            debug_path: None,
            load_path: None,
        });
        assert_eq!(p.module_count(), 1);
        assert!(p.get_module("kernel32.dll").is_some());
        assert!(p.get_module("ntdll.dll").is_none());

        // Mutable access
        let m = p.get_module_mut("kernel32.dll").unwrap();
        m.size = 0x200000;
        assert_eq!(p.get_module("kernel32.dll").unwrap().size, 0x200000);
    }

    #[test]
    fn test_process_refresh_state() {
        let mut p = DbgEngInferiorProcess::new(1);
        p.add_thread(DbgEngThread::new(1).with_state(ExecutionState::Running));
        p.add_thread(DbgEngThread::new(2).with_state(ExecutionState::Stopped));
        p.refresh_state();
        assert_eq!(p.state, ExecutionState::Running);
    }

    #[test]
    fn test_process_retain_keys() {
        let mut p = DbgEngInferiorProcess::new(1);
        p.add_thread(DbgEngThread::new(1));
        p.add_thread(DbgEngThread::new(3));
        let keys = p.build_thread_retain_keys();
        assert!(keys.contains(&"[1]".to_string()));
        assert!(keys.contains(&"[3]".to_string()));
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_process_build_trace_values_with_exit() {
        let mut p = DbgEngInferiorProcess::new(1);
        p.state = ExecutionState::Stopped;
        p.set_exit(42);
        let values = p.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "Exit Code" && v == "42"));
        assert!(values.iter().any(|(k, v)| k == "_state" && v == "TERMINATED"));
    }

    #[test]
    fn test_snapshot() {
        let snap = Snapshot::new(0, "Stopped").with_timestamp(1234567890);
        assert_eq!(snap.id, 0);
        assert_eq!(snap.description, "Stopped");
        assert_eq!(snap.timestamp, Some(1234567890));
    }

    #[test]
    fn test_process_sync_state() {
        let mut state = ProcessSyncState::new();
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
        let mut state = ProcessSyncState::new();
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
        let mut state = ProcessSyncState::new();
        let regions = vec![MemoryRegion {
            base: 0x400000,
            size: 0x1000,
            offset: 0,
            permissions: "rwx".to_string(),
            object_file: "test".to_string(),
        }];
        assert!(state.regions_changed(&regions));
        state.update_regions(regions.clone());
        assert!(!state.regions_changed(&regions));

        let different = vec![MemoryRegion {
            base: 0x500000,
            size: 0x1000,
            offset: 0,
            permissions: "rwx".to_string(),
            object_file: "test".to_string(),
        }];
        assert!(state.regions_changed(&different));
    }

    #[test]
    fn test_process_sync_state_snapshots() {
        let mut state = ProcessSyncState::new();
        state.create_snapshot("Stopped");
        state.create_snapshot("Continued");
        state.create_snapshot("Stopped");
        assert_eq!(state.snapshots.len(), 3);
        assert_eq!(state.snapshots[0].id, 0);
        assert_eq!(state.snapshots[1].id, 1);
        assert_eq!(state.snapshots[2].id, 2);
    }

    #[test]
    fn test_process_retain_keys_modules() {
        let mut p = DbgEngInferiorProcess::new(1);
        p.add_module(ModuleInfo {
            name: "ntdll.dll".to_string(),
            base: 0x7ff800000000,
            size: 0x1e6000,
            build_id: None,
            debug_path: None,
            load_path: None,
        });
        let keys = p.build_module_retain_keys();
        assert!(keys.contains(&"[ntdll.dll]".to_string()));
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn test_process_retain_keys_regions() {
        let mut p = DbgEngInferiorProcess::new(1);
        p.add_memory_region(MemoryRegion {
            base: 0x400000,
            size: 0x1000,
            offset: 0,
            permissions: "rwx".to_string(),
            object_file: "test".to_string(),
        });
        let keys = p.build_region_retain_keys();
        assert!(keys.contains(&"[00400000]".to_string()));
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn test_module_section_new() {
        let s = ModuleSection::new(".text", 0x1000, 0x5000);
        assert_eq!(s.name, ".text");
        assert_eq!(s.start, 0x1000);
        assert_eq!(s.end, 0x6000);
        assert_eq!(s.size, 0x5000);
        assert_eq!(s.characteristics, 0);
    }

    #[test]
    fn test_module_section_characteristics() {
        let s = ModuleSection::new(".text", 0x1000, 0x5000)
            .with_characteristics(0x60000020); // MEM_EXECUTE | MEM_READ | CNT_CODE
        assert!(s.is_executable());
        assert!(s.is_readable());
        assert!(!s.is_writable());

        let data = ModuleSection::new(".data", 0x6000, 0x1000)
            .with_characteristics(0xC0000040); // MEM_READ | MEM_WRITE | CNT_INITIALIZED_DATA
        assert!(!data.is_executable());
        assert!(data.is_readable());
        assert!(data.is_writable());
        assert!(data.is_initialized_data());
    }

    #[test]
    fn test_module_section_trace_path() {
        let s = ModuleSection::new(".text", 0x1000, 0x5000);
        assert_eq!(
            s.trace_path(1, 0x7ff800000000),
            "Processes[1].Modules[0x7ff800000000].Sections[.text]"
        );
    }

    #[test]
    fn test_module_section_trace_values() {
        let s = ModuleSection::new(".rdata", 0x7000, 0x2000);
        let values = s.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "Range" && v == "0x7000:0x9000"));
        assert!(values.iter().any(|(k, v)| k == "Size" && v == "0x2000"));
    }

    #[test]
    fn test_module_with_sections() {
        let info = ModuleInfo {
            name: "kernel32.dll".to_string(),
            base: 0x7ff800000000,
            size: 0x1e6000,
            build_id: None,
            debug_path: None,
            load_path: Some("C:\\Windows\\System32\\kernel32.dll".to_string()),
        };
        let mut mod_ws = ModuleWithSections::from_info(info)
            .with_flags(0x1000)
            .with_debug_info_loaded(true);
        assert_eq!(mod_ws.section_count(), 0);
        assert!(!mod_ws.has_section(".text"));

        mod_ws.add_section(ModuleSection::new(".text", 0x1000, 0x80000));
        mod_ws.add_section(ModuleSection::new(".rdata", 0x81000, 0x40000));
        assert_eq!(mod_ws.section_count(), 2);
        assert!(mod_ws.has_section(".text"));
        assert!(mod_ws.has_section(".rdata"));
        assert!(!mod_ws.has_section(".data"));

        let text = mod_ws.get_section(".text").unwrap();
        assert_eq!(text.start, 0x1000);
        assert_eq!(text.size, 0x80000);

        let removed = mod_ws.remove_section(".rdata");
        assert!(removed.is_some());
        assert_eq!(mod_ws.section_count(), 1);

        mod_ws.clear_sections();
        assert_eq!(mod_ws.section_count(), 0);
    }

    #[test]
    fn test_module_with_sections_paths() {
        let info = ModuleInfo {
            name: "ntdll.dll".to_string(),
            base: 0x7ff800100000,
            size: 0x1e6000,
            build_id: None,
            debug_path: None,
            load_path: None,
        };
        let mod_ws = ModuleWithSections::from_info(info);
        assert_eq!(
            mod_ws.trace_path(1),
            "Processes[1].Modules[0x7ff800100000]"
        );
        assert_eq!(
            mod_ws.sections_path(1),
            "Processes[1].Modules[0x7ff800100000].Sections"
        );
    }

    #[test]
    fn test_module_with_sections_trace_values() {
        let info = ModuleInfo {
            name: "test.exe".to_string(),
            base: 0x400000,
            size: 0x10000,
            build_id: None,
            debug_path: None,
            load_path: Some("C:\\test.exe".to_string()),
        };
        let mod_ws = ModuleWithSections::from_info(info).with_debug_info_loaded(true);
        let values = mod_ws.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "Name" && v == "test.exe"));
        assert!(values.iter().any(|(k, v)| k == "Debug Info" && v == "loaded"));
        assert!(values.iter().any(|(k, _v)| k == "Load Path"));
    }

    #[test]
    fn test_process_breakpoint_new() {
        let bp = DbgEngProcessBreakpoint::new(1);
        assert_eq!(bp.id, 1);
        assert_eq!(bp.bp_type, BreakpointType::Software);
        assert!(bp.address.is_none());
        assert!(bp.enabled);
        assert_eq!(bp.hit_count, 0);
        assert!(bp.expression.is_none());
        assert!(bp.match_tid.is_none());
        assert!(bp.handler.is_none());
    }

    #[test]
    fn test_process_breakpoint_builder() {
        let bp = DbgEngProcessBreakpoint::new(5)
            .with_address(0x401000)
            .with_handler("my_handler")
            .with_command("gc")
            .with_match_tid(0x1234)
            .with_flags(0x1); // DEBUG_BREAKPOINT_ENABLED
        assert_eq!(bp.address, Some(0x401000));
        assert_eq!(bp.handler.as_deref(), Some("my_handler"));
        assert_eq!(bp.command.as_deref(), Some("gc"));
        assert_eq!(bp.match_tid, Some(0x1234));
        assert!(!bp.is_deferred());
        assert!(bp.is_enabled());
    }

    #[test]
    fn test_process_breakpoint_deferred() {
        let bp = DbgEngProcessBreakpoint::new(1)
            .with_expression("kernel32!CreateFileW")
            .with_flags(0x3); // ENABLED | DEFERRED
        assert!(bp.is_deferred());
        assert!(bp.is_deferred_flag());
        assert_eq!(bp.expression.as_deref(), Some("kernel32!CreateFileW"));
    }

    #[test]
    fn test_process_breakpoint_data() {
        let bp = DbgEngProcessBreakpoint::new(2)
            .with_data(8, 1) // 8 bytes, write
            .with_address(0x7ffde000);
        assert_eq!(bp.bp_type, BreakpointType::Memory);
        assert_eq!(bp.data_width, Some(8));
        assert_eq!(bp.data_access_type, Some(1));
        assert_eq!(bp.access_type_label(), "W");
    }

    #[test]
    fn test_process_breakpoint_trace_path() {
        let bp = DbgEngProcessBreakpoint::new(3);
        assert_eq!(
            bp.trace_path(1),
            "Processes[1].Debug.Breakpoints[3]"
        );
    }

    #[test]
    fn test_process_breakpoint_build_trace_values() {
        let bp = DbgEngProcessBreakpoint::new(1)
            .with_address(0x401000)
            .with_flags(0x1)
            .with_command("gc");
        let values = bp.build_trace_values();
        assert!(values.iter().any(|(k, v)| k == "Address" && v == "0x401000"));
        assert!(values.iter().any(|(k, v)| k == "Enabled" && v == "true"));
        assert!(values.iter().any(|(k, v)| k == "Command" && v == "gc"));
        assert!(values.iter().any(|(k, v)| k == "Kinds" && v == "x"));
    }

    #[test]
    fn test_process_breakpoint_hit() {
        let mut bp = DbgEngProcessBreakpoint::new(1);
        assert_eq!(bp.hit_count, 0);
        bp.record_hit();
        bp.record_hit();
        assert_eq!(bp.hit_count, 2);
    }

    #[test]
    fn test_process_breakpoint_access_type_labels() {
        let bp_w = DbgEngProcessBreakpoint::new(1).with_data(4, 1);
        assert_eq!(bp_w.access_type_label(), "W");

        let bp_r = DbgEngProcessBreakpoint::new(2).with_data(4, 2);
        assert_eq!(bp_r.access_type_label(), "R");

        let bp_x = DbgEngProcessBreakpoint::new(3).with_data(4, 4);
        assert_eq!(bp_x.access_type_label(), "X");

        let bp_default = DbgEngProcessBreakpoint::new(4);
        assert_eq!(bp_default.access_type_label(), "x");
    }

    #[test]
    fn test_process_manager() {
        let mut mgr = DbgEngProcessManager::new();
        assert!(mgr.is_empty());
        assert_eq!(mgr.len(), 0);
        assert!(mgr.active().is_none());

        mgr.add(DbgEngInferiorProcess::new(0).with_pid(100));
        mgr.add(DbgEngInferiorProcess::new(1).with_pid(200));
        assert_eq!(mgr.len(), 2);
        assert_eq!(mgr.active_num(), Some(0));

        let p0 = mgr.get(0).unwrap();
        assert_eq!(p0.pid, Some(100));

        let p1 = mgr.get(1).unwrap();
        assert_eq!(p1.pid, Some(200));

        mgr.set_active(1);
        assert_eq!(mgr.active_num(), Some(1));
        assert_eq!(mgr.active().unwrap().pid, Some(200));
    }

    #[test]
    fn test_process_manager_remove() {
        let mut mgr = DbgEngProcessManager::new();
        mgr.add(DbgEngInferiorProcess::new(0));
        mgr.add(DbgEngInferiorProcess::new(1));
        mgr.add(DbgEngInferiorProcess::new(2));

        mgr.set_active(1);
        let removed = mgr.remove(1);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().num, 1);

        // Active should fall back to first available
        assert_eq!(mgr.active_num(), Some(0));
        assert_eq!(mgr.len(), 2);
    }

    #[test]
    fn test_process_manager_alive() {
        let mut mgr = DbgEngProcessManager::new();
        let mut p0 = DbgEngInferiorProcess::new(0);
        p0.state = ExecutionState::Stopped;
        mgr.add(p0);
        let mut p1 = DbgEngInferiorProcess::new(1);
        p1.state = ExecutionState::Exited;
        mgr.add(p1);
        let mut p2 = DbgEngInferiorProcess::new(2);
        p2.state = ExecutionState::Running;
        mgr.add(p2);

        let alive = mgr.alive();
        assert_eq!(alive.len(), 2);
        assert!(alive.iter().all(|p| p.is_alive()));
    }

    #[test]
    fn test_process_manager_sorted_numbers() {
        let mut mgr = DbgEngProcessManager::new();
        mgr.add(DbgEngInferiorProcess::new(3));
        mgr.add(DbgEngInferiorProcess::new(1));
        mgr.add(DbgEngInferiorProcess::new(2));
        assert_eq!(mgr.sorted_numbers(), vec![1, 2, 3]);
    }

    #[test]
    fn test_process_manager_process_info_list() {
        let mut mgr = DbgEngProcessManager::new();
        mgr.add(DbgEngInferiorProcess::new(0));
        mgr.add(DbgEngInferiorProcess::new(1));
        let list = mgr.build_process_info_list();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_process_manager_total_threads() {
        let mut mgr = DbgEngProcessManager::new();
        let mut p0 = DbgEngInferiorProcess::new(0);
        p0.add_thread(DbgEngThread::new(0));
        p0.add_thread(DbgEngThread::new(1));
        mgr.add(p0);

        let mut p1 = DbgEngInferiorProcess::new(1);
        p1.add_thread(DbgEngThread::new(0));
        mgr.add(p1);

        assert_eq!(mgr.total_thread_count(), 3);
    }

    #[test]
    fn test_process_manager_mutable() {
        let mut mgr = DbgEngProcessManager::new();
        mgr.add(DbgEngInferiorProcess::new(0));

        let p = mgr.get_mut(0).unwrap();
        p.mark_synced();
        assert!(mgr.get(0).unwrap().synced);

        let active = mgr.active_mut().unwrap();
        active.set_exit(0);
        assert_eq!(mgr.get(0).unwrap().state, ExecutionState::Exited);
    }
}
