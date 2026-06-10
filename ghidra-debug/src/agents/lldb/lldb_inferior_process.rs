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
use std::collections::{BTreeMap, HashMap};

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

    /// Find a module by name.
    pub fn get_module(&self, name: &str) -> Option<&ModuleInfo> {
        self.modules.iter().find(|m| m.name == name)
    }

    /// Find a module that contains the given address.
    pub fn module_at_address(&self, addr: u64) -> Option<&ModuleInfo> {
        self.modules
            .iter()
            .find(|m| addr >= m.base && addr < m.base + m.size)
    }

    /// Get sorted modules by base address.
    pub fn modules_sorted(&self) -> Vec<&ModuleInfo> {
        let mut mods: Vec<_> = self.modules.iter().collect();
        mods.sort_by_key(|m| m.base);
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
        self
    }

    /// Set a condition expression.
    pub fn with_condition(mut self, cond: impl Into<String>) -> Self {
        self.condition = Some(cond.into());
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

/// LLDB process manager -- manages multiple processes within a single
/// LLDB target/debug session.
///
/// LLDB can debug multiple processes (e.g. when following forks). This
/// manager tracks all known processes and provides convenient access.
#[derive(Debug, Default)]
pub struct LldbProcessManager {
    processes: BTreeMap<u32, LldbInferiorProcess>,
    active_index: Option<u32>,
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
        assert_eq!(sorted[0].name, "a.so");
        assert_eq!(sorted[1].name, "b.so");
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
}
