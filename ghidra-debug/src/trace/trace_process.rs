//! TraceProcess -- enhanced process representation for the debug trace.
//!
//! Ported from Ghidra's `ghidra.trace.model.process.TraceProcess` and
//! `ghidra.trace.database.process.DBTraceProcess`.
//!
//! This module provides a richer process type than the basic `model::thread::TraceProcess`,
//! with support for environment variables, command-line arguments, and process-level
//! execution state management.
//!
//! New in this update: `ProcessExitInfo` for exit code/signal tracking,
//! `ProcessIO` for stdin/stdout/stderr paths, `LoadedModule` for tracking
//! loaded modules, `ProcessMemoryMapping` for address space mappings,
//! parent/child process relationships, `ProcessBuilder` for ergonomic
//! construction, `attach`/`detach`/`kill` lifecycle, and `ProcessSnapshot`
//! for point-in-time summaries.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;
use crate::model::TraceExecutionState;

use super::trace_execution_state::TraceExecutionStateManager;

// ---------------------------------------------------------------------------
// ProcessChangeEvent
// ---------------------------------------------------------------------------

/// The kind of change event that occurred on a process.
///
/// Ported from Ghidra's `TraceEvents.PROCESS_ADDED`, `PROCESS_CHANGED`, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessChangeEvent {
    /// A new process was added.
    Added,
    /// The process's lifespan changed (creation or destruction snap moved).
    LifespanChanged,
    /// The process's properties changed (name, env, etc.).
    Changed,
    /// The process was deleted.
    Deleted,
    /// A module was loaded in the process.
    ModuleLoaded,
    /// A module was unloaded from the process.
    ModuleUnloaded,
    /// A memory mapping was created.
    MemoryMappingAdded,
    /// A memory mapping was removed.
    MemoryMappingRemoved,
    /// The process's execution state changed.
    ExecutionStateChanged,
}

impl ProcessChangeEvent {
    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Added => "PROCESS_ADDED",
            Self::LifespanChanged => "PROCESS_LIFESPAN_CHANGED",
            Self::Changed => "PROCESS_CHANGED",
            Self::Deleted => "PROCESS_DELETED",
            Self::ModuleLoaded => "PROCESS_MODULE_LOADED",
            Self::ModuleUnloaded => "PROCESS_MODULE_UNLOADED",
            Self::MemoryMappingAdded => "PROCESS_MEMORY_MAPPING_ADDED",
            Self::MemoryMappingRemoved => "PROCESS_MEMORY_MAPPING_REMOVED",
            Self::ExecutionStateChanged => "PROCESS_EXECUTION_STATE_CHANGED",
        }
    }
}

impl std::fmt::Display for ProcessChangeEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// ProcessChangeRecord
// ---------------------------------------------------------------------------

/// A typed change record carrying the process key and event kind.
///
/// Ported from Ghidra's `TraceChangeRecord<TraceProcess, ?>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessChangeRecord {
    /// The kind of change event.
    pub event: ProcessChangeEvent,
    /// The key of the process that changed.
    pub process_key: i64,
    /// The snap at which the change occurred, if applicable.
    pub snap: Option<i64>,
    /// An optional key name that was affected (e.g. "Name", "Environment").
    pub affected_key: Option<String>,
    /// An optional sub-object key (e.g. module name, mapping name).
    pub sub_key: Option<String>,
}

impl ProcessChangeRecord {
    /// Create a new change record.
    pub fn new(event: ProcessChangeEvent, process_key: i64) -> Self {
        Self {
            event,
            process_key,
            snap: None,
            affected_key: None,
            sub_key: None,
        }
    }

    /// Attach a snap.
    pub fn with_snap(mut self, snap: i64) -> Self {
        self.snap = Some(snap);
        self
    }

    /// Attach an affected key name.
    pub fn with_affected_key(mut self, key: impl Into<String>) -> Self {
        self.affected_key = Some(key.into());
        self
    }

    /// Attach a sub-object key.
    pub fn with_sub_key(mut self, key: impl Into<String>) -> Self {
        self.sub_key = Some(key.into());
        self
    }
}

// ---------------------------------------------------------------------------
// ProcessGroup -- grouping related processes
// ---------------------------------------------------------------------------

/// A logical grouping of related processes.
///
/// Ported from Ghidra's process grouping concepts. Useful for organizing
/// processes by debugger session, target, or user-defined criteria.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessGroup {
    /// Unique identifier for this group.
    pub id: i64,
    /// Human-readable name.
    pub name: String,
    /// Keys of processes in this group.
    process_keys: Vec<i64>,
    /// Optional parent group id.
    pub parent_id: Option<i64>,
    /// Child group ids.
    child_ids: Vec<i64>,
}

impl ProcessGroup {
    /// Create a new process group.
    pub fn new(id: i64, name: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            process_keys: Vec::new(),
            parent_id: None,
            child_ids: Vec::new(),
        }
    }

    /// Add a process key to this group.
    pub fn add_process(&mut self, key: i64) {
        if !self.process_keys.contains(&key) {
            self.process_keys.push(key);
        }
    }

    /// Remove a process key from this group.
    pub fn remove_process(&mut self, key: i64) {
        self.process_keys.retain(|&k| k != key);
    }

    /// The process keys in this group.
    pub fn process_keys(&self) -> &[i64] {
        &self.process_keys
    }

    /// The number of processes in this group.
    pub fn process_count(&self) -> usize {
        self.process_keys.len()
    }

    /// Whether this group contains a given process key.
    pub fn contains_process(&self, key: i64) -> bool {
        self.process_keys.contains(&key)
    }

    /// Set the parent group.
    pub fn set_parent(&mut self, parent_id: i64) {
        self.parent_id = Some(parent_id);
    }

    /// Add a child group.
    pub fn add_child(&mut self, child_id: i64) {
        if !self.child_ids.contains(&child_id) {
            self.child_ids.push(child_id);
        }
    }

    /// Remove a child group.
    pub fn remove_child(&mut self, child_id: i64) {
        self.child_ids.retain(|&k| k != child_id);
    }

    /// The child group ids.
    pub fn child_ids(&self) -> &[i64] {
        &self.child_ids
    }
}

// ---------------------------------------------------------------------------
// DebugConnectionInfo -- connection/target metadata
// ---------------------------------------------------------------------------

/// Information about the debugger connection that produced a process.
///
/// Ported from Ghidra's debugger target/connection metadata tracking.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DebugConnectionInfo {
    /// The debugger type (e.g., "gdb", "lldb", "dbgeng").
    pub debugger_type: Option<String>,
    /// The target hostname or address.
    pub target_host: Option<String>,
    /// The target port.
    pub target_port: Option<u16>,
    /// The connection URI (e.g., "tcp://localhost:1234").
    pub uri: Option<String>,
    /// The command used to launch the debugger.
    pub launch_command: Option<String>,
    /// Additional connection parameters.
    pub parameters: BTreeMap<String, String>,
}

impl DebugConnectionInfo {
    /// Create empty connection info.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the debugger type.
    pub fn with_debugger_type(mut self, dt: impl Into<String>) -> Self {
        self.debugger_type = Some(dt.into());
        self
    }

    /// Set the target host.
    pub fn with_target_host(mut self, host: impl Into<String>) -> Self {
        self.target_host = Some(host.into());
        self
    }

    /// Set the target port.
    pub fn with_target_port(mut self, port: u16) -> Self {
        self.target_port = Some(port);
        self
    }

    /// Set the URI.
    pub fn with_uri(mut self, uri: impl Into<String>) -> Self {
        self.uri = Some(uri.into());
        self
    }

    /// Set the launch command.
    pub fn with_launch_command(mut self, cmd: impl Into<String>) -> Self {
        self.launch_command = Some(cmd.into());
        self
    }

    /// Add a parameter.
    pub fn with_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.parameters.insert(key.into(), value.into());
        self
    }

    /// Whether any connection info is set.
    pub fn has_info(&self) -> bool {
        self.debugger_type.is_some()
            || self.target_host.is_some()
            || self.uri.is_some()
            || self.launch_command.is_some()
            || !self.parameters.is_empty()
    }

    /// A display-friendly connection string.
    pub fn display_string(&self) -> String {
        if let Some(ref uri) = self.uri {
            return uri.clone();
        }
        let mut parts = Vec::new();
        if let Some(ref dt) = self.debugger_type {
            parts.push(dt.clone());
        }
        if let Some(ref host) = self.target_host {
            let s = if let Some(port) = self.target_port {
                format!("{}:{}", host, port)
            } else {
                host.clone()
            };
            parts.push(s);
        }
        if parts.is_empty() {
            "<no connection>".into()
        } else {
            parts.join(" @ ")
        }
    }
}

// ---------------------------------------------------------------------------
// ProcessEnvironment
// ---------------------------------------------------------------------------

/// The environment of a process (env vars, args, working directory).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessEnvironment {
    /// Environment variables.
    pub env: BTreeMap<String, String>,
    /// Command-line arguments (argv[0] is typically the program path).
    pub args: Vec<String>,
    /// The working directory, if known.
    pub working_dir: Option<String>,
}

impl ProcessEnvironment {
    /// Create an empty environment.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set an environment variable.
    pub fn set_env(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.env.insert(key.into(), value.into());
    }

    /// Get an environment variable.
    pub fn get_env(&self, key: &str) -> Option<&str> {
        self.env.get(key).map(|s| s.as_str())
    }

    /// Remove an environment variable.
    pub fn remove_env(&mut self, key: &str) -> Option<String> {
        self.env.remove(key)
    }

    /// Set command-line arguments.
    pub fn set_args(&mut self, args: Vec<String>) {
        self.args = args;
    }

    /// Set the working directory.
    pub fn set_working_dir(&mut self, dir: impl Into<String>) {
        self.working_dir = Some(dir.into());
    }

    /// All environment variable names.
    pub fn env_keys(&self) -> Vec<&str> {
        self.env.keys().map(|s| s.as_str()).collect()
    }

    /// The number of environment variables.
    pub fn env_count(&self) -> usize {
        self.env.len()
    }

    /// Merge another environment into this one.
    ///
    /// Variables from `other` overwrite on conflict.
    pub fn merge(&mut self, other: &ProcessEnvironment) {
        for (k, v) in &other.env {
            self.env.insert(k.clone(), v.clone());
        }
        if !other.args.is_empty() {
            self.args = other.args.clone();
        }
        if other.working_dir.is_some() {
            self.working_dir = other.working_dir.clone();
        }
    }

    /// Check if a specific environment variable exists.
    pub fn has_env(&self, key: &str) -> bool {
        self.env.contains_key(key)
    }

    /// Get all environment variables as a vector of (key, value) pairs.
    pub fn env_pairs(&self) -> Vec<(&str, &str)> {
        self.env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
    }
}

// ---------------------------------------------------------------------------
// ProcessExitInfo
// ---------------------------------------------------------------------------

/// Information about how a process exited.
///
/// Ported from Ghidra's exit code tracking in `DBTraceProcess`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessExitInfo {
    /// Process exited normally with the given exit code.
    ExitCode(i64),
    /// Process was killed by a signal with the given signal number.
    Signal(i32),
    /// Process was killed by a signal with detailed information.
    SignalDetail(ProcessSignalInfo),
    /// Process was killed by the debugger.
    Killed,
    /// Process detached.
    Detached,
    /// Unknown exit reason.
    Unknown,
}

impl ProcessExitInfo {
    /// Whether this represents a normal exit.
    pub fn is_normal_exit(&self) -> bool {
        matches!(self, Self::ExitCode(_))
    }

    /// Whether this represents a signal death.
    pub fn is_signal(&self) -> bool {
        matches!(self, Self::Signal(_) | Self::SignalDetail(_))
    }

    /// Get the exit code, if this was a normal exit.
    pub fn exit_code(&self) -> Option<i64> {
        match self {
            Self::ExitCode(code) => Some(*code),
            _ => None,
        }
    }

    /// Get the signal number, if this was a signal death.
    pub fn signal_number(&self) -> Option<i32> {
        match self {
            Self::Signal(sig) => Some(*sig),
            Self::SignalDetail(info) => Some(info.signal),
            _ => None,
        }
    }

    /// Get the signal info, if this was a detailed signal death.
    pub fn signal_info(&self) -> Option<&ProcessSignalInfo> {
        match self {
            Self::SignalDetail(info) => Some(info),
            _ => None,
        }
    }

    /// Whether the exit was fatal (signal kills, killed by debugger).
    pub fn is_fatal(&self) -> bool {
        match self {
            Self::ExitCode(_) => false,
            Self::Signal(_) => true,
            Self::SignalDetail(info) => info.fatal,
            Self::Killed => true,
            Self::Detached => false,
            Self::Unknown => false,
        }
    }
}

// ---------------------------------------------------------------------------
// ProcessIO
// ---------------------------------------------------------------------------

/// I/O path information for a process.
///
/// Ported from Ghidra's process I/O tracking.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessIO {
    /// Path to stdin (if redirected), or None for terminal.
    pub stdin: Option<String>,
    /// Path to stdout (if redirected), or None for terminal.
    pub stdout: Option<String>,
    /// Path to stderr (if redirected), or None for terminal.
    pub stderr: Option<String>,
}

impl ProcessIO {
    /// Create empty I/O info.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set stdin path.
    pub fn with_stdin(mut self, path: impl Into<String>) -> Self {
        self.stdin = Some(path.into());
        self
    }

    /// Set stdout path.
    pub fn with_stdout(mut self, path: impl Into<String>) -> Self {
        self.stdout = Some(path.into());
        self
    }

    /// Set stderr path.
    pub fn with_stderr(mut self, path: impl Into<String>) -> Self {
        self.stderr = Some(path.into());
        self
    }

    /// Whether any I/O paths are set.
    pub fn has_redirects(&self) -> bool {
        self.stdin.is_some() || self.stdout.is_some() || self.stderr.is_some()
    }
}

// ---------------------------------------------------------------------------
// LoadedModule
// ---------------------------------------------------------------------------

/// A module (shared library / executable) loaded in a process.
///
/// Ported from Ghidra's `TraceModule` and module tracking in `DBTraceProcess`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadedModule {
    /// Module name (e.g., "libc.so.6").
    pub name: String,
    /// Module path on the filesystem.
    pub path: String,
    /// Base address where the module is loaded.
    pub base_address: u64,
    /// Size of the module in bytes.
    pub size: u64,
    /// The snap at which this module was loaded.
    pub loaded_snap: i64,
    /// The snap at which this module was unloaded, if applicable.
    pub unloaded_snap: Option<i64>,
}

impl LoadedModule {
    /// Create a new loaded module.
    pub fn new(
        name: impl Into<String>,
        path: impl Into<String>,
        base_address: u64,
        size: u64,
        snap: i64,
    ) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
            base_address,
            size,
            loaded_snap: snap,
            unloaded_snap: None,
        }
    }

    /// The end address of this module.
    pub fn end_address(&self) -> u64 {
        self.base_address.wrapping_add(self.size)
    }

    /// Whether an address falls within this module.
    pub fn contains_address(&self, addr: u64) -> bool {
        addr >= self.base_address && addr < self.end_address()
    }

    /// Whether this module is still loaded.
    pub fn is_loaded(&self) -> bool {
        self.unloaded_snap.is_none()
    }

    /// Mark the module as unloaded at the given snap.
    pub fn unload(&mut self, snap: i64) {
        self.unloaded_snap = Some(snap);
    }

    /// Whether this module is valid at the given snap.
    pub fn is_valid_at(&self, snap: i64) -> bool {
        snap >= self.loaded_snap
            && self
                .unloaded_snap
                .map_or(true, |unloaded| snap < unloaded)
    }
}

// ---------------------------------------------------------------------------
// ProcessMemoryMapping
// ---------------------------------------------------------------------------

/// A memory mapping in a process's address space.
///
/// Ported from Ghidra's memory region tracking in `DBTraceMemoryManager`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMemoryMapping {
    /// The virtual address start.
    pub vaddr: u64,
    /// The length of the mapping.
    pub length: u64,
    /// The name of this mapping (e.g., "[stack]", "libc.so.6").
    pub name: String,
    /// Whether this mapping is readable.
    pub readable: bool,
    /// Whether this mapping is writable.
    pub writable: bool,
    /// Whether this mapping is executable.
    pub executable: bool,
    /// The snap at which this mapping was created.
    pub created_snap: i64,
    /// The snap at which this mapping was removed, if applicable.
    pub removed_snap: Option<i64>,
}

impl ProcessMemoryMapping {
    /// Create a new mapping.
    pub fn new(
        vaddr: u64,
        length: u64,
        name: impl Into<String>,
        snap: i64,
    ) -> Self {
        Self {
            vaddr,
            length,
            name: name.into(),
            readable: true,
            writable: false,
            executable: false,
            created_snap: snap,
            removed_snap: None,
        }
    }

    /// Set permissions.
    pub fn with_permissions(mut self, read: bool, write: bool, exec: bool) -> Self {
        self.readable = read;
        self.writable = write;
        self.executable = exec;
        self
    }

    /// The end address of this mapping.
    pub fn end_address(&self) -> u64 {
        self.vaddr.wrapping_add(self.length)
    }

    /// Whether an address falls within this mapping.
    pub fn contains_address(&self, addr: u64) -> bool {
        addr >= self.vaddr && addr < self.end_address()
    }

    /// Whether this mapping overlaps with another.
    pub fn overlaps(&self, other: &ProcessMemoryMapping) -> bool {
        self.vaddr < other.end_address() && other.vaddr < self.end_address()
    }

    /// Whether this mapping is still active.
    pub fn is_active(&self) -> bool {
        self.removed_snap.is_none()
    }

    /// Remove this mapping at the given snap.
    pub fn remove(&mut self, snap: i64) {
        self.removed_snap = Some(snap);
    }

    /// Permissions as a string like "rwx" or "r--".
    pub fn permissions_string(&self) -> String {
        let mut s = String::with_capacity(3);
        s.push(if self.readable { 'r' } else { '-' });
        s.push(if self.writable { 'w' } else { '-' });
        s.push(if self.executable { 'x' } else { '-' });
        s
    }
}

// ---------------------------------------------------------------------------
// ProcessSignalInfo
// ---------------------------------------------------------------------------

/// Detailed information about a signal that terminated or stopped a process.
///
/// Ported from Ghidra's signal tracking in `DBTraceProcess`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessSignalInfo {
    /// The signal number (e.g., 11 for SIGSEGV).
    pub signal: i32,
    /// The signal name (e.g., "SIGSEGV").
    pub name: String,
    /// Whether this signal is fatal (terminates the process).
    pub fatal: bool,
    /// An optional description of the signal.
    pub description: Option<String>,
}

impl ProcessSignalInfo {
    /// Create a new signal info.
    pub fn new(signal: i32, name: impl Into<String>) -> Self {
        Self {
            signal,
            name: name.into(),
            fatal: false,
            description: None,
        }
    }

    /// Mark as fatal.
    pub fn with_fatal(mut self, fatal: bool) -> Self {
        self.fatal = fatal;
        self
    }

    /// Set a description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Well-known signal info for common POSIX signals.
    pub fn well_known(signal: i32) -> Self {
        match signal {
            1 => Self::new(1, "SIGHUP").with_fatal(true)
                .with_description("Hangup detected on controlling terminal"),
            2 => Self::new(2, "SIGINT").with_fatal(true)
                .with_description("Interrupt from keyboard"),
            3 => Self::new(3, "SIGQUIT").with_fatal(true)
                .with_description("Quit from keyboard"),
            4 => Self::new(4, "SIGILL").with_fatal(true)
                .with_description("Illegal instruction"),
            6 => Self::new(6, "SIGABRT").with_fatal(true)
                .with_description("Abort signal"),
            8 => Self::new(8, "SIGFPE").with_fatal(true)
                .with_description("Floating-point exception"),
            9 => Self::new(9, "SIGKILL").with_fatal(true)
                .with_description("Kill signal (cannot be caught)"),
            11 => Self::new(11, "SIGSEGV").with_fatal(true)
                .with_description("Invalid memory reference"),
            13 => Self::new(13, "SIGPIPE").with_fatal(true)
                .with_description("Broken pipe"),
            15 => Self::new(15, "SIGTERM").with_fatal(true)
                .with_description("Termination signal"),
            19 => Self::new(19, "SIGSTOP").with_fatal(false)
                .with_description("Stop process (cannot be caught)"),
            17 => Self::new(17, "SIGCHLD").with_fatal(false)
                .with_description("Child stopped or terminated"),
            _ => Self::new(signal, format!("SIGNAL_{signal}")),
        }
    }
}

// ---------------------------------------------------------------------------
// ProcessResourceUsage
// ---------------------------------------------------------------------------

/// Resource usage tracking for a process.
///
/// Ported from Ghidra's process resource monitoring.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessResourceUsage {
    /// Total CPU time consumed (in milliseconds).
    pub cpu_time_ms: u64,
    /// Peak resident set size (in bytes).
    pub peak_rss_bytes: u64,
    /// Current resident set size (in bytes).
    pub current_rss_bytes: u64,
    /// Number of minor page faults.
    pub minor_faults: u64,
    /// Number of major page faults.
    pub major_faults: u64,
    /// The snap at which this usage was recorded.
    pub snap: i64,
}

impl ProcessResourceUsage {
    /// Create a new resource usage record.
    pub fn new(snap: i64) -> Self {
        Self {
            snap,
            ..Default::default()
        }
    }

    /// Set CPU time.
    pub fn with_cpu_time_ms(mut self, ms: u64) -> Self {
        self.cpu_time_ms = ms;
        self
    }

    /// Set peak RSS.
    pub fn with_peak_rss(mut self, bytes: u64) -> Self {
        self.peak_rss_bytes = bytes;
        self
    }

    /// Set current RSS.
    pub fn with_current_rss(mut self, bytes: u64) -> Self {
        self.current_rss_bytes = bytes;
        self
    }

    /// The peak RSS in megabytes (rounded).
    pub fn peak_rss_mb(&self) -> u64 {
        self.peak_rss_bytes / (1024 * 1024)
    }

    /// The current RSS in megabytes (rounded).
    pub fn current_rss_mb(&self) -> u64 {
        self.current_rss_bytes / (1024 * 1024)
    }
}

// ---------------------------------------------------------------------------
// ProcessSnapshot
// ---------------------------------------------------------------------------

/// A point-in-time summary of a process's state.
///
/// Useful for serializing or comparing process state at different snaps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSnapshot {
    /// The process key.
    pub key: i64,
    /// The process name.
    pub name: String,
    /// The PID, if known.
    pub pid: Option<i64>,
    /// The execution state at this snap.
    pub execution_state: TraceExecutionState,
    /// The number of threads alive at this snap.
    pub thread_count: usize,
    /// The number of loaded modules.
    pub module_count: usize,
    /// The snap this snapshot was taken at.
    pub snap: i64,
}

// ---------------------------------------------------------------------------
// TraceProcess
// ---------------------------------------------------------------------------

/// An enhanced process entry for the debug trace.
///
/// This extends the basic `model::thread::TraceProcess` with environment
/// information, execution state management, thread tracking, module tracking,
/// memory mappings, I/O redirection, exit info, and parent/child relationships.
///
/// Ported from Ghidra's `DBTraceProcess` and `TraceProcess` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceProcess {
    /// Unique key identifying this process.
    pub key: i64,
    /// The object path (e.g., "Processes[0]").
    pub path: String,
    /// The OS-assigned PID.
    pub pid: Option<i64>,
    /// The process name (typically the executable name).
    pub name: String,
    /// The lifespan during which this process exists.
    pub lifespan: Lifespan,
    /// Process environment (args, env vars, cwd).
    pub environment: ProcessEnvironment,
    /// Execution state manager for this process.
    pub execution_state: TraceExecutionStateManager,
    /// Keys of threads belonging to this process.
    thread_keys: Vec<i64>,
    /// Exit information, if the process has exited.
    exit_info: Option<ProcessExitInfo>,
    /// I/O redirection paths.
    pub io: ProcessIO,
    /// Loaded modules.
    modules: Vec<LoadedModule>,
    /// Memory mappings.
    memory_mappings: Vec<ProcessMemoryMapping>,
    /// Key of the parent process, if any.
    pub parent_key: Option<i64>,
    /// Keys of child processes.
    child_keys: Vec<i64>,
    /// The snap at which this process was attached (if via attach, not launch).
    pub attached_snap: Option<i64>,
    /// Resource usage tracking.
    resource_usage: Option<ProcessResourceUsage>,
    /// Lifespan-aware name history: (snap, name).
    name_history: Vec<(i64, String)>,
    /// Lifespan-aware comment history: (snap, comment).
    comment_history: Vec<(i64, String)>,
    /// Debug connection info, if available.
    connection_info: Option<DebugConnectionInfo>,
}

impl TraceProcess {
    /// Create a new process.
    pub fn new(
        key: i64,
        path: impl Into<String>,
        name: impl Into<String>,
        snap: i64,
    ) -> Self {
        let path_str = path.into();
        let name_str = name.into();
        let mut name_history = Vec::new();
        name_history.push((snap, name_str.clone()));
        Self {
            key,
            path: path_str.clone(),
            pid: None,
            name: name_str,
            lifespan: Lifespan::now_on(snap),
            environment: ProcessEnvironment::new(),
            execution_state: TraceExecutionStateManager::new(path_str),
            thread_keys: Vec::new(),
            exit_info: None,
            io: ProcessIO::new(),
            modules: Vec::new(),
            memory_mappings: Vec::new(),
            parent_key: None,
            child_keys: Vec::new(),
            attached_snap: None,
            resource_usage: None,
            name_history,
            comment_history: Vec::new(),
            connection_info: None,
        }
    }

    /// Create a builder for constructing a process.
    pub fn builder(key: i64, name: impl Into<String>, snap: i64) -> ProcessBuilder {
        ProcessBuilder::new(key, name, snap)
    }

    /// Set the PID.
    pub fn with_pid(mut self, pid: i64) -> Self {
        self.pid = Some(pid);
        self
    }

    /// Whether this process is valid at `snap`.
    pub fn is_valid(&self, snap: i64) -> bool {
        self.lifespan.contains(snap)
    }

    /// Whether the process is alive for any part of the given span.
    pub fn is_alive(&self, span: &Lifespan) -> bool {
        self.lifespan.intersects(span)
    }

    /// Whether the process is currently alive (has not been removed).
    pub fn is_alive_now(&self) -> bool {
        self.lifespan.lmax() == Lifespan::MAX
    }

    /// End the process's life at the given snap.
    pub fn remove(&mut self, snap: i64) {
        self.lifespan = self.lifespan.with_max(snap);
    }

    // -- Environment --

    /// Set an environment variable.
    pub fn set_env(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.environment.set_env(key, value);
    }

    /// Get an environment variable.
    pub fn get_env(&self, key: &str) -> Option<&str> {
        self.environment.get_env(key)
    }

    /// Set command-line arguments.
    pub fn set_args(&mut self, args: Vec<String>) {
        self.environment.set_args(args);
    }

    /// Set the working directory.
    pub fn set_working_dir(&mut self, dir: impl Into<String>) {
        self.environment.set_working_dir(dir);
    }

    // -- Execution state --

    /// The current execution state of the process.
    pub fn execution_state(&self) -> TraceExecutionState {
        self.execution_state.state()
    }

    /// Transition the process to a new execution state.
    pub fn set_execution_state(
        &mut self,
        state: TraceExecutionState,
        snap: i64,
    ) {
        self.execution_state.transition(state, snap);
    }

    /// Transition with a reason.
    pub fn set_execution_state_with_reason(
        &mut self,
        state: TraceExecutionState,
        snap: i64,
        reason: impl Into<String>,
    ) {
        self.execution_state.transition_with_reason(state, snap, reason);
    }

    /// Query execution state at a given snap.
    pub fn execution_state_at(
        &self,
        snap: i64,
    ) -> Option<super::trace_execution_state::StateQuery> {
        self.execution_state.state_at(snap)
    }

    // -- Thread management --

    /// Register a thread key with this process.
    pub fn add_thread_key(&mut self, thread_key: i64) {
        if !self.thread_keys.contains(&thread_key) {
            self.thread_keys.push(thread_key);
        }
    }

    /// Unregister a thread key from this process.
    pub fn remove_thread_key(&mut self, thread_key: i64) {
        self.thread_keys.retain(|&k| k != thread_key);
    }

    /// The keys of threads belonging to this process.
    pub fn thread_keys(&self) -> &[i64] {
        &self.thread_keys
    }

    /// The number of threads belonging to this process.
    pub fn thread_count(&self) -> usize {
        self.thread_keys.len()
    }

    /// Whether this process has any threads.
    pub fn has_threads(&self) -> bool {
        !self.thread_keys.is_empty()
    }

    // -- Exit info --

    /// The exit information, if the process has exited.
    pub fn exit_info(&self) -> Option<&ProcessExitInfo> {
        self.exit_info.as_ref()
    }

    /// Whether this process has exited.
    pub fn has_exited(&self) -> bool {
        self.exit_info.is_some()
    }

    /// Set exit information.
    pub fn set_exit_info(&mut self, info: ProcessExitInfo) {
        self.exit_info = Some(info);
    }

    /// Record a normal exit with the given code.
    pub fn exit_with_code(&mut self, code: i64) {
        self.exit_info = Some(ProcessExitInfo::ExitCode(code));
    }

    /// Record a signal death.
    pub fn exit_with_signal(&mut self, signal: i32) {
        self.exit_info = Some(ProcessExitInfo::Signal(signal));
    }

    /// Record that the process was killed by the debugger.
    pub fn kill(&mut self, snap: i64) {
        self.exit_info = Some(ProcessExitInfo::Killed);
        self.remove(snap);
    }

    // -- Attach/Detach --

    /// Record that this process was attached to (as opposed to launched).
    pub fn attach(&mut self, snap: i64) {
        self.attached_snap = Some(snap);
        self.set_execution_state(TraceExecutionState::Alive, snap);
    }

    /// Record that this process was detached from.
    pub fn detach(&mut self, snap: i64) {
        self.exit_info = Some(ProcessExitInfo::Detached);
        self.set_execution_state(TraceExecutionState::Detached, snap);
    }

    /// Whether this process was attached (rather than launched).
    pub fn is_attached(&self) -> bool {
        self.attached_snap.is_some()
    }

    // -- Module management --

    /// Add a loaded module.
    pub fn add_module(&mut self, module: LoadedModule) {
        self.modules.push(module);
    }

    /// Remove (unload) a module by name at the given snap.
    pub fn unload_module(&mut self, name: &str, snap: i64) -> bool {
        for m in &mut self.modules {
            if m.name == name && m.is_loaded() {
                m.unload(snap);
                return true;
            }
        }
        false
    }

    /// Get a module by name.
    pub fn module(&self, name: &str) -> Option<&LoadedModule> {
        self.modules.iter().find(|m| m.name == name)
    }

    /// All loaded (non-unloaded) modules.
    pub fn loaded_modules(&self) -> Vec<&LoadedModule> {
        self.modules.iter().filter(|m| m.is_loaded()).collect()
    }

    /// All modules (including unloaded).
    pub fn all_modules(&self) -> &[LoadedModule] {
        &self.modules
    }

    /// Find the module containing the given address.
    pub fn module_at_address(&self, addr: u64) -> Option<&LoadedModule> {
        self.modules.iter().find(|m| m.is_loaded() && m.contains_address(addr))
    }

    /// The number of currently loaded modules.
    pub fn module_count(&self) -> usize {
        self.modules.iter().filter(|m| m.is_loaded()).count()
    }

    // -- Memory mappings --

    /// Add a memory mapping.
    pub fn add_memory_mapping(&mut self, mapping: ProcessMemoryMapping) {
        self.memory_mappings.push(mapping);
    }

    /// Remove a memory mapping by name at the given snap.
    pub fn remove_memory_mapping(&mut self, name: &str, snap: i64) -> bool {
        for m in &mut self.memory_mappings {
            if m.name == name && m.is_active() {
                m.remove(snap);
                return true;
            }
        }
        false
    }

    /// All active memory mappings.
    pub fn active_memory_mappings(&self) -> Vec<&ProcessMemoryMapping> {
        self.memory_mappings.iter().filter(|m| m.is_active()).collect()
    }

    /// All memory mappings (including removed).
    pub fn all_memory_mappings(&self) -> &[ProcessMemoryMapping] {
        &self.memory_mappings
    }

    /// Find the memory mapping containing the given address.
    pub fn memory_mapping_at(&self, addr: u64) -> Option<&ProcessMemoryMapping> {
        self.memory_mappings
            .iter()
            .find(|m| m.is_active() && m.contains_address(addr))
    }

    /// The number of active memory mappings.
    pub fn memory_mapping_count(&self) -> usize {
        self.memory_mappings.iter().filter(|m| m.is_active()).count()
    }

    // -- Parent/child relationships --

    /// Set the parent process key.
    pub fn set_parent(&mut self, parent_key: i64) {
        self.parent_key = Some(parent_key);
    }

    /// Add a child process key.
    pub fn add_child(&mut self, child_key: i64) {
        if !self.child_keys.contains(&child_key) {
            self.child_keys.push(child_key);
        }
    }

    /// Remove a child process key.
    pub fn remove_child(&mut self, child_key: i64) {
        self.child_keys.retain(|&k| k != child_key);
    }

    /// The keys of child processes.
    pub fn child_keys(&self) -> &[i64] {
        &self.child_keys
    }

    /// The number of child processes.
    pub fn child_count(&self) -> usize {
        self.child_keys.len()
    }

    /// Whether this process has a parent.
    pub fn has_parent(&self) -> bool {
        self.parent_key.is_some()
    }

    // -- Resource usage --

    /// Get the current resource usage, if recorded.
    pub fn resource_usage(&self) -> Option<&ProcessResourceUsage> {
        self.resource_usage.as_ref()
    }

    /// Set the resource usage for this process.
    pub fn set_resource_usage(&mut self, usage: ProcessResourceUsage) {
        self.resource_usage = Some(usage);
    }

    // -- Lifespan-aware name --

    /// Set the process name at a given snap (records history).
    pub fn set_name(&mut self, snap: i64, name: impl Into<String>) {
        let n = name.into();
        self.name = n.clone();
        self.name_history.push((snap, n));
    }

    /// Get the process name at a given snap (temporal lookup).
    pub fn name_at(&self, snap: i64) -> &str {
        self.name_history
            .iter()
            .rev()
            .find(|(s, _)| *s <= snap)
            .map(|(_, n)| n.as_str())
            .unwrap_or(&self.name)
    }

    /// The full name history as (snap, name) pairs.
    pub fn name_history(&self) -> &[(i64, String)] {
        &self.name_history
    }

    // -- Lifespan-aware comment --

    /// Set a comment on this process at a given snap.
    pub fn set_comment(&mut self, snap: i64, comment: impl Into<String>) {
        self.comment_history.push((snap, comment.into()));
    }

    /// Get the comment at a given snap.
    pub fn comment_at(&self, snap: i64) -> Option<&str> {
        self.comment_history
            .iter()
            .rev()
            .find(|(s, _)| *s <= snap)
            .map(|(_, c)| c.as_str())
    }

    /// The full comment history as (snap, comment) pairs.
    pub fn comment_history(&self) -> &[(i64, String)] {
        &self.comment_history
    }

    // -- Module queries at specific snaps --

    /// Find the module containing the given address at a specific snap.
    pub fn find_module_by_address_at(&self, addr: u64, snap: i64) -> Option<&LoadedModule> {
        self.modules
            .iter()
            .find(|m| m.is_valid_at(snap) && m.contains_address(addr))
    }

    /// All modules that are active at the given snap.
    pub fn active_modules_at(&self, snap: i64) -> Vec<&LoadedModule> {
        self.modules
            .iter()
            .filter(|m| m.is_valid_at(snap))
            .collect()
    }

    /// The number of modules active at the given snap.
    pub fn module_count_at(&self, snap: i64) -> usize {
        self.modules.iter().filter(|m| m.is_valid_at(snap)).count()
    }

    // -- Memory mapping queries at specific snaps --

    /// Find the memory mapping containing the given address at a specific snap.
    pub fn memory_mapping_at_snap(&self, addr: u64, snap: i64) -> Option<&ProcessMemoryMapping> {
        self.memory_mappings
            .iter()
            .find(|m| {
                m.created_snap <= snap
                    && m.removed_snap.map_or(true, |r| snap < r)
                    && m.contains_address(addr)
            })
    }

    /// All memory mappings active at the given snap.
    pub fn active_memory_mappings_at(&self, snap: i64) -> Vec<&ProcessMemoryMapping> {
        self.memory_mappings
            .iter()
            .filter(|m| {
                m.created_snap <= snap && m.removed_snap.map_or(true, |r| snap < r)
            })
            .collect()
    }

    // -- Snapshot --

    /// Create a point-in-time snapshot of this process's state.
    pub fn snapshot(&self, snap: i64) -> ProcessSnapshot {
        ProcessSnapshot {
            key: self.key,
            name: self.name.clone(),
            pid: self.pid,
            execution_state: self.execution_state.state(),
            thread_count: self.thread_keys.len(),
            module_count: self.module_count(),
            snap,
        }
    }

    // -- Connection info --

    /// Get the debug connection info, if available.
    pub fn connection_info(&self) -> Option<&DebugConnectionInfo> {
        self.connection_info.as_ref()
    }

    /// Set the debug connection info.
    pub fn set_connection_info(&mut self, info: DebugConnectionInfo) {
        self.connection_info = Some(info);
    }

    /// Get the debugger type (e.g., "gdb", "lldb").
    pub fn debugger_type(&self) -> Option<&str> {
        self.connection_info
            .as_ref()
            .and_then(|c| c.debugger_type.as_deref())
    }

    // -- Memory region helpers --

    /// Find all memory mappings that overlap with the given range at a snap.
    pub fn memory_mappings_overlapping(
        &self,
        start: u64,
        length: u64,
        snap: i64,
    ) -> Vec<&ProcessMemoryMapping> {
        let end = start.wrapping_add(length);
        self.memory_mappings
            .iter()
            .filter(|m| {
                m.created_snap <= snap
                    && m.removed_snap.map_or(true, |r| snap < r)
                    && m.vaddr < end
                    && start < m.vaddr.wrapping_add(m.length)
            })
            .collect()
    }

    /// Get total mapped memory size at a given snap.
    pub fn total_mapped_memory_at(&self, snap: i64) -> u64 {
        self.memory_mappings
            .iter()
            .filter(|m| m.created_snap <= snap && m.removed_snap.map_or(true, |r| snap < r))
            .map(|m| m.length)
            .sum()
    }

    /// Get all thread keys that were active at the given snap.
    ///
    /// Note: this returns all registered thread keys; actual thread lifespan
    /// checking requires the thread objects themselves.
    pub fn thread_keys_at(&self, _snap: i64) -> &[i64] {
        // Thread keys are managed externally; this returns all known keys.
        // For temporal filtering, the caller should cross-reference with
        // the thread manager.
        &self.thread_keys
    }

    /// Whether this process has any child processes.
    pub fn has_children(&self) -> bool {
        !self.child_keys.is_empty()
    }

    /// Whether this process is a root process (no parent).
    pub fn is_root(&self) -> bool {
        self.parent_key.is_none()
    }
}

// ---------------------------------------------------------------------------
// ProcessBuilder
// ---------------------------------------------------------------------------

/// Builder for constructing a [`TraceProcess`] with a fluent API.
///
/// # Example
/// ```ignore
/// let process = TraceProcess::builder(1, "myapp", 0)
///     .path("Processes[0]")
///     .pid(1234)
///     .env("HOME", "/home/user")
///     .args(vec!["myapp".into(), "--flag".into()])
///     .working_dir("/tmp")
///     .io(ProcessIO::new().with_stdout("/tmp/out.log"))
///     .build();
/// ```
pub struct ProcessBuilder {
    key: i64,
    name: String,
    snap: i64,
    path: String,
    pid: Option<i64>,
    env: BTreeMap<String, String>,
    args: Vec<String>,
    working_dir: Option<String>,
    io: ProcessIO,
    parent_key: Option<i64>,
    attached: bool,
}

impl ProcessBuilder {
    /// Create a new builder.
    pub fn new(key: i64, name: impl Into<String>, snap: i64) -> Self {
        Self {
            key,
            name: name.into(),
            snap,
            path: String::new(),
            pid: None,
            env: BTreeMap::new(),
            args: Vec::new(),
            working_dir: None,
            io: ProcessIO::new(),
            parent_key: None,
            attached: false,
        }
    }

    /// Set the path.
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }

    /// Set the PID.
    pub fn pid(mut self, pid: i64) -> Self {
        self.pid = Some(pid);
        self
    }

    /// Add an environment variable.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Set command-line arguments.
    pub fn args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    /// Set the working directory.
    pub fn working_dir(mut self, dir: impl Into<String>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    /// Set I/O configuration.
    pub fn io(mut self, io: ProcessIO) -> Self {
        self.io = io;
        self
    }

    /// Set the parent process key.
    pub fn parent(mut self, parent_key: i64) -> Self {
        self.parent_key = Some(parent_key);
        self
    }

    /// Mark this process as attached (rather than launched).
    pub fn attached(mut self) -> Self {
        self.attached = true;
        self
    }

    /// Add multiple environment variables from an iterator of (key, value) pairs.
    pub fn env_pairs<I, K, V>(mut self, pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        for (k, v) in pairs {
            self.env.insert(k.into(), v.into());
        }
        self
    }

    /// Build the [`TraceProcess`].
    pub fn build(self) -> TraceProcess {
        let path = if self.path.is_empty() {
            format!("Processes[{}]", self.key)
        } else {
            self.path
        };
        let mut env = ProcessEnvironment::new();
        for (k, v) in self.env {
            env.set_env(k, v);
        }
        if !self.args.is_empty() {
            env.set_args(self.args);
        }
        if let Some(dir) = self.working_dir {
            env.set_working_dir(dir);
        }
        let mut proc = TraceProcess::new(self.key, path, self.name, self.snap);
        proc.pid = self.pid;
        proc.environment = env;
        proc.io = self.io;
        proc.parent_key = self.parent_key;
        if self.attached {
            proc.attach(self.snap);
        }
        proc
    }
}

// ---------------------------------------------------------------------------
// ProcessManager -- CRUD operations on processes within a trace
// ---------------------------------------------------------------------------

/// Manages processes within a trace, providing CRUD operations,
/// change tracking, and grouping.
///
/// Ported from Ghidra's `DBTraceProcessManager`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessManager {
    /// Processes indexed by key.
    processes: BTreeMap<i64, TraceProcess>,
    /// Process groups indexed by group id.
    groups: BTreeMap<i64, ProcessGroup>,
    /// Next available process key.
    next_key: i64,
    /// Next available group id.
    next_group_id: i64,
    /// Change history (most recent last).
    change_history: Vec<ProcessChangeRecord>,
    /// Maximum change history entries to retain.
    max_history: usize,
}

impl ProcessManager {
    /// Create a new process manager.
    pub fn new() -> Self {
        Self {
            processes: BTreeMap::new(),
            groups: BTreeMap::new(),
            next_key: 1,
            next_group_id: 1,
            change_history: Vec::new(),
            max_history: 1000,
        }
    }

    /// Set the maximum change history size.
    pub fn with_max_history(mut self, max: usize) -> Self {
        self.max_history = max;
        self
    }

    // -- CRUD --

    /// Add a process and return its key.
    pub fn add_process(&mut self, process: TraceProcess) -> i64 {
        let key = process.key;
        if key >= self.next_key {
            self.next_key = key + 1;
        }
        self.push_change(ProcessChangeRecord::new(ProcessChangeEvent::Added, key));
        self.processes.insert(key, process);
        key
    }

    /// Create and add a new process with the given name at the given snap.
    pub fn create_process(
        &mut self,
        name: impl Into<String>,
        snap: i64,
    ) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        let path = format!("Processes[{}]", key);
        let process = TraceProcess::new(key, path, name, snap);
        self.push_change(ProcessChangeRecord::new(ProcessChangeEvent::Added, key));
        self.processes.insert(key, process);
        key
    }

    /// Get a process by key.
    pub fn get_process(&self, key: i64) -> Option<&TraceProcess> {
        self.processes.get(&key)
    }

    /// Get a mutable process by key.
    pub fn get_process_mut(&mut self, key: i64) -> Option<&mut TraceProcess> {
        self.processes.get_mut(&key)
    }

    /// Remove a process by key.
    pub fn remove_process(&mut self, key: i64) -> Option<TraceProcess> {
        let proc = self.processes.remove(&key);
        if proc.is_some() {
            // Remove from all groups
            for group in self.groups.values_mut() {
                group.remove_process(key);
            }
            self.push_change(ProcessChangeRecord::new(ProcessChangeEvent::Deleted, key));
        }
        proc
    }

    /// The number of processes.
    pub fn process_count(&self) -> usize {
        self.processes.len()
    }

    /// All process keys.
    pub fn process_keys(&self) -> Vec<i64> {
        self.processes.keys().copied().collect()
    }

    /// All processes.
    pub fn processes(&self) -> &BTreeMap<i64, TraceProcess> {
        &self.processes
    }

    /// Iterate over all processes.
    pub fn iter(&self) -> impl Iterator<Item = (&i64, &TraceProcess)> {
        self.processes.iter()
    }

    /// Iterate over all processes mutably.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&i64, &mut TraceProcess)> {
        self.processes.iter_mut()
    }

    // -- Temporal queries --

    /// All processes alive at the given snap.
    pub fn alive_at(&self, snap: i64) -> Vec<&TraceProcess> {
        self.processes
            .values()
            .filter(|p| p.is_valid(snap))
            .collect()
    }

    /// The number of processes alive at the given snap.
    pub fn alive_count_at(&self, snap: i64) -> usize {
        self.processes.values().filter(|p| p.is_valid(snap)).count()
    }

    /// Find a process by name at the given snap.
    pub fn find_by_name(&self, name: &str, snap: i64) -> Option<&TraceProcess> {
        self.processes
            .values()
            .find(|p| p.is_valid(snap) && p.name_at(snap) == name)
    }

    /// Find a process by PID at the given snap.
    pub fn find_by_pid(&self, pid: i64, snap: i64) -> Option<&TraceProcess> {
        self.processes
            .values()
            .find(|p| p.is_valid(snap) && p.pid == Some(pid))
    }

    /// Find a process by path.
    pub fn find_by_path(&self, path: &str) -> Option<&TraceProcess> {
        self.processes.values().find(|p| p.path == path)
    }

    /// All root processes (no parent).
    pub fn root_processes(&self) -> Vec<&TraceProcess> {
        self.processes
            .values()
            .filter(|p| p.is_root())
            .collect()
    }

    /// All child processes of a given parent.
    pub fn children_of(&self, parent_key: i64) -> Vec<&TraceProcess> {
        self.processes
            .values()
            .filter(|p| p.parent_key == Some(parent_key))
            .collect()
    }

    // -- Grouping --

    /// Create a new process group.
    pub fn create_group(&mut self, name: impl Into<String>) -> i64 {
        let id = self.next_group_id;
        self.next_group_id += 1;
        self.groups.insert(id, ProcessGroup::new(id, name));
        id
    }

    /// Get a group by id.
    pub fn group(&self, id: i64) -> Option<&ProcessGroup> {
        self.groups.get(&id)
    }

    /// Get a mutable group by id.
    pub fn group_mut(&mut self, id: i64) -> Option<&mut ProcessGroup> {
        self.groups.get_mut(&id)
    }

    /// Remove a group.
    pub fn remove_group(&mut self, id: i64) -> Option<ProcessGroup> {
        self.groups.remove(&id)
    }

    /// Add a process to a group.
    pub fn add_to_group(&mut self, group_id: i64, process_key: i64) -> bool {
        if let Some(group) = self.groups.get_mut(&group_id) {
            group.add_process(process_key);
            true
        } else {
            false
        }
    }

    /// Remove a process from a group.
    pub fn remove_from_group(&mut self, group_id: i64, process_key: i64) -> bool {
        if let Some(group) = self.groups.get_mut(&group_id) {
            group.remove_process(process_key);
            true
        } else {
            false
        }
    }

    /// All groups a process belongs to.
    pub fn groups_for_process(&self, process_key: i64) -> Vec<&ProcessGroup> {
        self.groups
            .values()
            .filter(|g| g.contains_process(process_key))
            .collect()
    }

    /// The number of groups.
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    // -- Change tracking --

    /// Push a change record to the history.
    fn push_change(&mut self, record: ProcessChangeRecord) {
        if self.change_history.len() >= self.max_history {
            self.change_history.remove(0);
        }
        self.change_history.push(record);
    }

    /// Push a change record (public for external callers).
    pub fn record_change(&mut self, record: ProcessChangeRecord) {
        self.push_change(record);
    }

    /// Get the change history.
    pub fn change_history(&self) -> &[ProcessChangeRecord] {
        &self.change_history
    }

    /// Clear the change history.
    pub fn clear_change_history(&mut self) {
        self.change_history.clear();
    }

    /// The number of change records.
    pub fn change_count(&self) -> usize {
        self.change_history.len()
    }

    // -- Bulk operations --

    /// Remove all processes whose lifespan ends at or before the given snap.
    pub fn prune_dead_before(&mut self, snap: i64) -> Vec<TraceProcess> {
        let dead_keys: Vec<i64> = self
            .processes
            .values()
            .filter(|p| !p.is_alive_now() && p.lifespan.lmax() < snap)
            .map(|p| p.key)
            .collect();
        let mut removed = Vec::new();
        for key in dead_keys {
            if let Some(proc) = self.processes.remove(&key) {
                removed.push(proc);
            }
        }
        removed
    }

    /// Get all processes as a vector sorted by key.
    pub fn processes_vec(&self) -> Vec<&TraceProcess> {
        self.processes.values().collect()
    }

    /// Whether any processes exist.
    pub fn is_empty(&self) -> bool {
        self.processes.is_empty()
    }

    /// Clear all processes and groups.
    pub fn clear(&mut self) {
        self.processes.clear();
        self.groups.clear();
    }

    /// Get aggregate statistics.
    pub fn statistics(&self, snap: i64) -> ProcessManagerStatistics {
        ProcessManagerStatistics {
            total_processes: self.processes.len(),
            alive_at_snap: self.alive_count_at(snap),
            total_groups: self.groups.len(),
            root_processes: self.root_processes().len(),
            change_records: self.change_history.len(),
        }
    }
}

/// Aggregate statistics for the process manager.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessManagerStatistics {
    /// Total number of processes (including dead).
    pub total_processes: usize,
    /// Number of processes alive at a given snap.
    pub alive_at_snap: usize,
    /// Number of process groups.
    pub total_groups: usize,
    /// Number of root processes (no parent).
    pub root_processes: usize,
    /// Number of change records in history.
    pub change_records: usize,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_creation() {
        let p = TraceProcess::new(1, "Processes[0]", "myapp", 0);
        assert_eq!(p.key, 1);
        assert_eq!(p.name, "myapp");
        assert!(p.is_valid(0));
        assert!(p.is_valid(100));
        assert!(!p.is_valid(-1));
        assert!(p.is_alive_now());
    }

    #[test]
    fn test_process_with_pid() {
        let p = TraceProcess::new(1, "P[0]", "myapp", 0).with_pid(1234);
        assert_eq!(p.pid, Some(1234));
    }

    #[test]
    fn test_process_remove() {
        let mut p = TraceProcess::new(1, "P[0]", "myapp", 0);
        assert!(p.is_alive_now());
        p.remove(10);
        assert!(p.is_valid(10));
        assert!(!p.is_valid(11));
        assert!(!p.is_alive_now());
    }

    #[test]
    fn test_process_is_alive() {
        let mut p = TraceProcess::new(1, "P[0]", "myapp", 0);
        assert!(p.is_alive(&Lifespan::span(0, 10)));
        p.remove(50);
        assert!(!p.is_alive(&Lifespan::span(100, 200)));
    }

    #[test]
    fn test_process_environment() {
        let mut p = TraceProcess::new(1, "P[0]", "myapp", 0);
        p.set_env("HOME", "/home/user");
        p.set_env("PATH", "/usr/bin");
        assert_eq!(p.get_env("HOME"), Some("/home/user"));
        assert_eq!(p.get_env("PATH"), Some("/usr/bin"));
        assert!(p.get_env("MISSING").is_none());

        p.set_args(vec!["myapp".into(), "--flag".into(), "value".into()]);
        p.set_working_dir("/tmp");

        assert_eq!(p.environment.args.len(), 3);
        assert_eq!(p.environment.working_dir.as_deref(), Some("/tmp"));
    }

    #[test]
    fn test_process_execution_state() {
        let mut p = TraceProcess::new(1, "P[0]", "myapp", 0);
        assert_eq!(p.execution_state(), TraceExecutionState::Unknown);

        p.set_execution_state(TraceExecutionState::Running, 1);
        assert_eq!(p.execution_state(), TraceExecutionState::Running);

        p.set_execution_state_with_reason(
            TraceExecutionState::Stopped,
            5,
            "all-threads-stopped",
        );
        assert_eq!(p.execution_state(), TraceExecutionState::Stopped);
    }

    #[test]
    fn test_process_execution_state_at() {
        let mut p = TraceProcess::new(1, "P[0]", "myapp", 0);
        p.set_execution_state(TraceExecutionState::Running, 1);
        p.set_execution_state(TraceExecutionState::Stopped, 5);

        let q1 = p.execution_state_at(1).unwrap();
        assert_eq!(q1.state, TraceExecutionState::Running);

        let q3 = p.execution_state_at(3).unwrap();
        assert_eq!(q3.state, TraceExecutionState::Running);
        assert_eq!(q3.entered_snap, 1);

        let q5 = p.execution_state_at(5).unwrap();
        assert_eq!(q5.state, TraceExecutionState::Stopped);
    }

    #[test]
    fn test_process_thread_management() {
        let mut p = TraceProcess::new(1, "P[0]", "myapp", 0);
        assert!(!p.has_threads());
        assert_eq!(p.thread_count(), 0);

        p.add_thread_key(10);
        p.add_thread_key(20);
        assert_eq!(p.thread_count(), 2);
        assert!(p.has_threads());
        assert_eq!(p.thread_keys(), &[10, 20]);

        // Adding duplicate is a no-op
        p.add_thread_key(10);
        assert_eq!(p.thread_count(), 2);

        p.remove_thread_key(10);
        assert_eq!(p.thread_count(), 1);
        assert_eq!(p.thread_keys(), &[20]);
    }

    #[test]
    fn test_process_serde() {
        let mut p = TraceProcess::new(1, "P[0]", "myapp", 0);
        p.set_env("HOME", "/root");
        p.set_execution_state(TraceExecutionState::Running, 1);
        p.add_thread_key(5);

        let json = serde_json::to_string(&p).unwrap();
        let back: TraceProcess = serde_json::from_str(&json).unwrap();
        assert_eq!(back.key, 1);
        assert_eq!(back.name, "myapp");
        assert_eq!(back.get_env("HOME"), Some("/root"));
        assert_eq!(back.execution_state(), TraceExecutionState::Running);
        assert_eq!(back.thread_keys(), &[5]);
    }

    #[test]
    fn test_process_environment_builder() {
        let mut env = ProcessEnvironment::new();
        env.set_env("SHELL", "/bin/zsh");
        env.set_args(vec!["prog".into(), "-v".into()]);
        env.set_working_dir("/home/user");

        assert_eq!(env.get_env("SHELL"), Some("/bin/zsh"));
        assert_eq!(env.args.len(), 2);
        assert_eq!(env.working_dir.as_deref(), Some("/home/user"));

        env.remove_env("SHELL");
        assert!(env.get_env("SHELL").is_none());
    }

    // -- New tests for added features --

    #[test]
    fn test_process_exit_info() {
        let exit = ProcessExitInfo::ExitCode(0);
        assert!(exit.is_normal_exit());
        assert!(!exit.is_signal());
        assert_eq!(exit.exit_code(), Some(0));
        assert!(exit.signal_number().is_none());

        let sig = ProcessExitInfo::Signal(11);
        assert!(!sig.is_normal_exit());
        assert!(sig.is_signal());
        assert_eq!(sig.signal_number(), Some(11));
        assert!(sig.exit_code().is_none());

        assert!(!ProcessExitInfo::Killed.is_normal_exit());
        assert!(!ProcessExitInfo::Detached.is_signal());
        assert!(!ProcessExitInfo::Unknown.is_normal_exit());
    }

    #[test]
    fn test_process_exit_lifecycle() {
        let mut p = TraceProcess::new(1, "P[0]", "myapp", 0);
        assert!(!p.has_exited());
        assert!(p.exit_info().is_none());

        p.exit_with_code(0);
        assert!(p.has_exited());
        assert_eq!(p.exit_info().unwrap().exit_code(), Some(0));
    }

    #[test]
    fn test_process_exit_with_signal() {
        let mut p = TraceProcess::new(1, "P[0]", "myapp", 0);
        p.exit_with_signal(11);
        assert!(p.has_exited());
        assert_eq!(p.exit_info().unwrap().signal_number(), Some(11));
    }

    #[test]
    fn test_process_kill() {
        let mut p = TraceProcess::new(1, "P[0]", "myapp", 0);
        assert!(p.is_alive_now());
        p.kill(10);
        assert!(p.has_exited());
        assert!(!p.is_alive_now());
    }

    #[test]
    fn test_process_attach_detach() {
        let mut p = TraceProcess::new(1, "P[0]", "myapp", 0);
        assert!(!p.is_attached());

        p.attach(5);
        assert!(p.is_attached());
        assert_eq!(p.execution_state(), TraceExecutionState::Alive);

        p.detach(10);
        assert!(p.has_exited());
        assert_eq!(p.execution_state(), TraceExecutionState::Detached);
    }

    #[test]
    fn test_process_io() {
        let io = ProcessIO::new()
            .with_stdin("/dev/null")
            .with_stdout("/tmp/out.log")
            .with_stderr("/tmp/err.log");
        assert!(io.has_redirects());
        assert_eq!(io.stdin.as_deref(), Some("/dev/null"));
        assert_eq!(io.stdout.as_deref(), Some("/tmp/out.log"));
        assert_eq!(io.stderr.as_deref(), Some("/tmp/err.log"));

        let empty_io = ProcessIO::new();
        assert!(!empty_io.has_redirects());
    }

    #[test]
    fn test_process_io_field() {
        let mut p = TraceProcess::new(1, "P[0]", "myapp", 0);
        p.io = ProcessIO::new().with_stdout("/tmp/out.log");
        assert!(p.io.has_redirects());
    }

    #[test]
    fn test_loaded_module() {
        let m = LoadedModule::new("libc.so.6", "/usr/lib/libc.so.6", 0x7F000000, 0x200000, 0);
        assert_eq!(m.name, "libc.so.6");
        assert_eq!(m.end_address(), 0x7F200000);
        assert!(m.contains_address(0x7F010000));
        assert!(!m.contains_address(0x7F210000));
        assert!(m.is_loaded());
        assert!(m.is_valid_at(0));
        assert!(m.is_valid_at(100));

        let mut m2 = m.clone();
        m2.unload(50);
        assert!(!m2.is_loaded());
        assert!(m2.is_valid_at(49));
        assert!(!m2.is_valid_at(50));
    }

    #[test]
    fn test_process_modules() {
        let mut p = TraceProcess::new(1, "P[0]", "myapp", 0);
        assert_eq!(p.module_count(), 0);

        p.add_module(LoadedModule::new("myapp", "/usr/bin/myapp", 0x400000, 0x10000, 0));
        p.add_module(LoadedModule::new("libc.so.6", "/usr/lib/libc.so.6", 0x7F000000, 0x200000, 0));
        assert_eq!(p.module_count(), 2);
        assert!(p.module("libc.so.6").is_some());
        assert!(p.module("missing").is_none());

        assert!(p.module_at_address(0x400000).is_some());
        assert_eq!(p.module_at_address(0x400000).unwrap().name, "myapp");
        assert!(p.module_at_address(0x999999).is_none());

        assert!(p.unload_module("libc.so.6", 10));
        assert_eq!(p.module_count(), 1);
        assert_eq!(p.all_modules().len(), 2); // including unloaded
    }

    #[test]
    fn test_process_memory_mappings() {
        let mut p = TraceProcess::new(1, "P[0]", "myapp", 0);
        assert_eq!(p.memory_mapping_count(), 0);

        p.add_memory_mapping(
            ProcessMemoryMapping::new(0x400000, 0x10000, "[heap]", 0)
                .with_permissions(true, true, false),
        );
        p.add_memory_mapping(
            ProcessMemoryMapping::new(0x7FFF0000, 0x80000, "[stack]", 0)
                .with_permissions(true, true, false),
        );
        assert_eq!(p.memory_mapping_count(), 2);

        let heap = p.memory_mapping_at(0x405000).unwrap();
        assert_eq!(heap.name, "[heap]");
        assert_eq!(heap.permissions_string(), "rw-");

        assert!(p.remove_memory_mapping("[heap]", 5));
        assert_eq!(p.memory_mapping_count(), 1);
        assert_eq!(p.all_memory_mappings().len(), 2);
    }

    #[test]
    fn test_memory_mapping_overlap() {
        let m1 = ProcessMemoryMapping::new(0x1000, 0x1000, "a", 0);
        let m2 = ProcessMemoryMapping::new(0x1800, 0x1000, "b", 0);
        let m3 = ProcessMemoryMapping::new(0x3000, 0x1000, "c", 0);

        assert!(m1.overlaps(&m2));
        assert!(!m1.overlaps(&m3));
    }

    #[test]
    fn test_process_parent_child() {
        let mut parent = TraceProcess::new(1, "P[0]", "parent", 0);
        let mut child = TraceProcess::new(2, "P[1]", "child", 1);

        child.set_parent(1);
        parent.add_child(2);

        assert!(child.has_parent());
        assert_eq!(child.parent_key, Some(1));
        assert_eq!(parent.child_count(), 1);
        assert_eq!(parent.child_keys(), &[2]);

        parent.remove_child(2);
        assert_eq!(parent.child_count(), 0);
    }

    #[test]
    fn test_process_snapshot() {
        let mut p = TraceProcess::new(1, "P[0]", "myapp", 0);
        p.pid = Some(1234);
        p.set_execution_state(TraceExecutionState::Running, 1);
        p.add_thread_key(10);
        p.add_module(LoadedModule::new("myapp", "/usr/bin/myapp", 0x400000, 0x10000, 0));

        let snap = p.snapshot(5);
        assert_eq!(snap.key, 1);
        assert_eq!(snap.name, "myapp");
        assert_eq!(snap.pid, Some(1234));
        assert_eq!(snap.execution_state, TraceExecutionState::Running);
        assert_eq!(snap.thread_count, 1);
        assert_eq!(snap.module_count, 1);
        assert_eq!(snap.snap, 5);
    }

    #[test]
    fn test_process_builder() {
        let p = TraceProcess::builder(1, "myapp", 0)
            .path("Processes[0]")
            .pid(1234)
            .env("HOME", "/home/user")
            .args(vec!["myapp".into(), "--flag".into()])
            .working_dir("/tmp")
            .io(ProcessIO::new().with_stdout("/tmp/out.log"))
            .build();

        assert_eq!(p.key, 1);
        assert_eq!(p.name, "myapp");
        assert_eq!(p.pid, Some(1234));
        assert_eq!(p.get_env("HOME"), Some("/home/user"));
        assert_eq!(p.environment.args.len(), 2);
        assert_eq!(p.environment.working_dir.as_deref(), Some("/tmp"));
        assert!(p.io.has_redirects());
        assert!(!p.is_attached());
    }

    #[test]
    fn test_process_builder_attached() {
        let p = TraceProcess::builder(1, "myapp", 5)
            .pid(1234)
            .attached()
            .build();

        assert!(p.is_attached());
        assert_eq!(p.attached_snap, Some(5));
        assert_eq!(p.execution_state(), TraceExecutionState::Alive);
    }

    #[test]
    fn test_process_builder_with_parent() {
        let p = TraceProcess::builder(2, "child", 1)
            .parent(1)
            .build();

        assert!(p.has_parent());
        assert_eq!(p.parent_key, Some(1));
    }

    #[test]
    fn test_process_builder_default_path() {
        let p = TraceProcess::builder(42, "app", 0).build();
        assert_eq!(p.path, "Processes[42]");
    }

    #[test]
    fn test_process_builder_serde() {
        let p = TraceProcess::builder(1, "myapp", 0)
            .pid(100)
            .env("KEY", "VALUE")
            .build();

        let json = serde_json::to_string(&p).unwrap();
        let back: TraceProcess = serde_json::from_str(&json).unwrap();
        assert_eq!(back.key, 1);
        assert_eq!(back.pid, Some(100));
        assert_eq!(back.get_env("KEY"), Some("VALUE"));
    }

    #[test]
    fn test_process_exit_info_serde() {
        let info = ProcessExitInfo::ExitCode(42);
        let json = serde_json::to_string(&info).unwrap();
        let back: ProcessExitInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.exit_code(), Some(42));

        let sig = ProcessExitInfo::Signal(9);
        let json = serde_json::to_string(&sig).unwrap();
        let back: ProcessExitInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.signal_number(), Some(9));
    }

    #[test]
    fn test_loaded_module_serde() {
        let m = LoadedModule::new("libc.so.6", "/usr/lib/libc.so.6", 0x7F000000, 0x200000, 0);
        let json = serde_json::to_string(&m).unwrap();
        let back: LoadedModule = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "libc.so.6");
        assert_eq!(back.base_address, 0x7F000000);
    }

    #[test]
    fn test_process_snapshot_serde() {
        let mut p = TraceProcess::new(1, "P[0]", "myapp", 0);
        p.set_execution_state(TraceExecutionState::Stopped, 0);
        let snap = p.snapshot(0);
        let json = serde_json::to_string(&snap).unwrap();
        let back: ProcessSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.key, 1);
        assert_eq!(back.execution_state, TraceExecutionState::Stopped);
    }

    #[test]
    fn test_process_io_serde() {
        let io = ProcessIO::new()
            .with_stdin("/dev/null")
            .with_stdout("/tmp/out");
        let json = serde_json::to_string(&io).unwrap();
        let back: ProcessIO = serde_json::from_str(&json).unwrap();
        assert_eq!(back.stdin.as_deref(), Some("/dev/null"));
        assert_eq!(back.stdout.as_deref(), Some("/tmp/out"));
    }

    #[test]
    fn test_environment_keys_and_count() {
        let mut env = ProcessEnvironment::new();
        env.set_env("A", "1");
        env.set_env("B", "2");
        env.set_env("C", "3");
        assert_eq!(env.env_count(), 3);
        let keys = env.env_keys();
        assert_eq!(keys, vec!["A", "B", "C"]);
    }

    #[test]
    fn test_process_memory_mapping_permissions_string() {
        let m = ProcessMemoryMapping::new(0, 0x1000, "test", 0)
            .with_permissions(true, false, true);
        assert_eq!(m.permissions_string(), "r-x");

        let m2 = ProcessMemoryMapping::new(0, 0x1000, "test", 0)
            .with_permissions(false, false, false);
        assert_eq!(m2.permissions_string(), "---");

        let m3 = ProcessMemoryMapping::new(0, 0x1000, "test", 0)
            .with_permissions(true, true, true);
        assert_eq!(m3.permissions_string(), "rwx");
    }

    // -- New tests for added features --

    #[test]
    fn test_process_signal_info() {
        let info = ProcessSignalInfo::new(11, "SIGSEGV").with_fatal(true);
        assert_eq!(info.signal, 11);
        assert_eq!(info.name, "SIGSEGV");
        assert!(info.fatal);
        assert!(info.description.is_none());
    }

    #[test]
    fn test_process_signal_info_well_known() {
        let sigsegv = ProcessSignalInfo::well_known(11);
        assert_eq!(sigsegv.signal, 11);
        assert_eq!(sigsegv.name, "SIGSEGV");
        assert!(sigsegv.fatal);
        assert!(sigsegv.description.is_some());

        let sigkill = ProcessSignalInfo::well_known(9);
        assert_eq!(sigkill.name, "SIGKILL");
        assert!(sigkill.fatal);

        let sigstop = ProcessSignalInfo::well_known(19);
        assert_eq!(sigstop.name, "SIGSTOP");
        assert!(!sigstop.fatal);

        // Unknown signal
        let unknown = ProcessSignalInfo::well_known(42);
        assert_eq!(unknown.signal, 42);
        assert_eq!(unknown.name, "SIGNAL_42");
    }

    #[test]
    fn test_process_exit_info_signal_detail() {
        let info = ProcessSignalInfo::well_known(11);
        let exit = ProcessExitInfo::SignalDetail(info);
        assert!(exit.is_signal());
        assert_eq!(exit.signal_number(), Some(11));
        assert!(exit.signal_info().is_some());
        assert!(exit.is_fatal());

        let nonfatal = ProcessExitInfo::SignalDetail(
            ProcessSignalInfo::new(19, "SIGSTOP"),
        );
        assert!(nonfatal.is_signal());
        assert!(!nonfatal.is_fatal());
    }

    #[test]
    fn test_process_exit_info_is_fatal() {
        assert!(!ProcessExitInfo::ExitCode(0).is_fatal());
        assert!(ProcessExitInfo::Signal(11).is_fatal());
        assert!(ProcessExitInfo::Killed.is_fatal());
        assert!(!ProcessExitInfo::Detached.is_fatal());
        assert!(!ProcessExitInfo::Unknown.is_fatal());
    }

    #[test]
    fn test_process_resource_usage() {
        let usage = ProcessResourceUsage::new(5)
            .with_cpu_time_ms(1500)
            .with_peak_rss(1024 * 1024 * 100)
            .with_current_rss(1024 * 1024 * 50);

        assert_eq!(usage.snap, 5);
        assert_eq!(usage.cpu_time_ms, 1500);
        assert_eq!(usage.peak_rss_mb(), 100);
        assert_eq!(usage.current_rss_mb(), 50);
    }

    #[test]
    fn test_process_resource_usage_serde() {
        let usage = ProcessResourceUsage::new(1)
            .with_cpu_time_ms(500)
            .with_peak_rss(1024 * 1024 * 200);

        let json = serde_json::to_string(&usage).unwrap();
        let back: ProcessResourceUsage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.cpu_time_ms, 500);
        assert_eq!(back.peak_rss_mb(), 200);
    }

    #[test]
    fn test_process_set_resource_usage() {
        let mut p = TraceProcess::new(1, "P[0]", "myapp", 0);
        assert!(p.resource_usage().is_none());

        let usage = ProcessResourceUsage::new(5).with_cpu_time_ms(1000);
        p.set_resource_usage(usage);
        assert!(p.resource_usage().is_some());
        assert_eq!(p.resource_usage().unwrap().cpu_time_ms, 1000);
    }

    #[test]
    fn test_process_lifespan_aware_name() {
        let mut p = TraceProcess::new(1, "P[0]", "myapp", 0);
        assert_eq!(p.name_at(0), "myapp");
        assert_eq!(p.name_at(100), "myapp");

        p.set_name(10, "renamed_app");
        assert_eq!(p.name_at(5), "myapp");
        assert_eq!(p.name_at(10), "renamed_app");
        assert_eq!(p.name_at(100), "renamed_app");

        assert_eq!(p.name_history().len(), 2);
    }

    #[test]
    fn test_process_lifespan_aware_comment() {
        let mut p = TraceProcess::new(1, "P[0]", "myapp", 0);
        assert!(p.comment_at(0).is_none());

        p.set_comment(5, "first comment");
        assert_eq!(p.comment_at(5), Some("first comment"));
        assert_eq!(p.comment_at(3), None);

        p.set_comment(10, "second comment");
        assert_eq!(p.comment_at(7), Some("first comment"));
        assert_eq!(p.comment_at(10), Some("second comment"));

        assert_eq!(p.comment_history().len(), 2);
    }

    #[test]
    fn test_process_find_module_by_address_at() {
        let mut p = TraceProcess::new(1, "P[0]", "myapp", 0);
        p.add_module(LoadedModule::new("myapp", "/usr/bin/myapp", 0x400000, 0x10000, 0));
        p.add_module(LoadedModule::new("libc.so.6", "/usr/lib/libc.so.6", 0x7F000000, 0x200000, 5));

        assert!(p.find_module_by_address_at(0x400000, 0).is_some());
        assert_eq!(p.find_module_by_address_at(0x400000, 0).unwrap().name, "myapp");

        // libc not yet loaded at snap 0
        assert!(p.find_module_by_address_at(0x7F000000, 0).is_none());
        // libc loaded at snap 5
        assert!(p.find_module_by_address_at(0x7F000000, 5).is_some());
    }

    #[test]
    fn test_process_active_modules_at() {
        let mut p = TraceProcess::new(1, "P[0]", "myapp", 0);
        p.add_module(LoadedModule::new("myapp", "/usr/bin/myapp", 0x400000, 0x10000, 0));
        p.add_module(LoadedModule::new("libc.so.6", "/usr/lib/libc.so.6", 0x7F000000, 0x200000, 5));

        assert_eq!(p.active_modules_at(0).len(), 1);
        assert_eq!(p.active_modules_at(5).len(), 2);
        assert_eq!(p.module_count_at(0), 1);
        assert_eq!(p.module_count_at(5), 2);
    }

    #[test]
    fn test_process_memory_mapping_at_snap() {
        let mut p = TraceProcess::new(1, "P[0]", "myapp", 0);
        p.add_memory_mapping(
            ProcessMemoryMapping::new(0x400000, 0x10000, "[heap]", 0)
                .with_permissions(true, true, false),
        );
        p.add_memory_mapping(
            ProcessMemoryMapping::new(0x7FFF0000, 0x80000, "[stack]", 5)
                .with_permissions(true, true, false),
        );

        assert!(p.memory_mapping_at_snap(0x405000, 0).is_some());
        assert_eq!(p.memory_mapping_at_snap(0x405000, 0).unwrap().name, "[heap]");

        // Stack not yet at snap 0
        assert!(p.memory_mapping_at_snap(0x7FFF0000, 0).is_none());
        assert!(p.memory_mapping_at_snap(0x7FFF0000, 5).is_some());

        assert_eq!(p.active_memory_mappings_at(0).len(), 1);
        assert_eq!(p.active_memory_mappings_at(5).len(), 2);
    }

    #[test]
    fn test_process_environment_merge() {
        let mut env1 = ProcessEnvironment::new();
        env1.set_env("A", "1");
        env1.set_env("B", "2");

        let mut env2 = ProcessEnvironment::new();
        env2.set_env("B", "overwritten");
        env2.set_env("C", "3");
        env2.set_args(vec!["prog".into()]);

        env1.merge(&env2);
        assert_eq!(env1.get_env("A"), Some("1"));
        assert_eq!(env1.get_env("B"), Some("overwritten"));
        assert_eq!(env1.get_env("C"), Some("3"));
        assert_eq!(env1.args.len(), 1);
    }

    #[test]
    fn test_process_environment_has_env() {
        let mut env = ProcessEnvironment::new();
        env.set_env("PATH", "/usr/bin");
        assert!(env.has_env("PATH"));
        assert!(!env.has_env("MISSING"));
    }

    #[test]
    fn test_process_environment_env_pairs() {
        let mut env = ProcessEnvironment::new();
        env.set_env("A", "1");
        env.set_env("B", "2");

        let pairs = env.env_pairs();
        assert_eq!(pairs.len(), 2);
        assert!(pairs.iter().any(|(k, v)| *k == "A" && *v == "1"));
        assert!(pairs.iter().any(|(k, v)| *k == "B" && *v == "2"));
    }

    #[test]
    fn test_process_builder_env_pairs() {
        let p = TraceProcess::builder(1, "myapp", 0)
            .env_pairs(vec![("HOME", "/home/user"), ("PATH", "/usr/bin")])
            .build();

        assert_eq!(p.get_env("HOME"), Some("/home/user"));
        assert_eq!(p.get_env("PATH"), Some("/usr/bin"));
    }

    #[test]
    fn test_process_signal_detail_serde() {
        let info = ProcessSignalInfo::well_known(11);
        let exit = ProcessExitInfo::SignalDetail(info);

        let json = serde_json::to_string(&exit).unwrap();
        let back: ProcessExitInfo = serde_json::from_str(&json).unwrap();
        assert!(back.is_signal());
        assert_eq!(back.signal_number(), Some(11));
        assert!(back.signal_info().is_some());
        assert_eq!(back.signal_info().unwrap().name, "SIGSEGV");
    }

    #[test]
    fn test_process_signal_info_serde() {
        let info = ProcessSignalInfo::new(6, "SIGABRT")
            .with_fatal(true)
            .with_description("Abort signal");

        let json = serde_json::to_string(&info).unwrap();
        let back: ProcessSignalInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.signal, 6);
        assert_eq!(back.name, "SIGABRT");
        assert!(back.fatal);
        assert_eq!(back.description.as_deref(), Some("Abort signal"));
    }

    // -- New tests for ProcessChangeEvent --

    #[test]
    fn test_process_change_event_display() {
        assert_eq!(ProcessChangeEvent::Added.to_string(), "PROCESS_ADDED");
        assert_eq!(
            ProcessChangeEvent::ExecutionStateChanged.to_string(),
            "PROCESS_EXECUTION_STATE_CHANGED"
        );
        assert_eq!(
            ProcessChangeEvent::ModuleLoaded.to_string(),
            "PROCESS_MODULE_LOADED"
        );
    }

    #[test]
    fn test_process_change_event_serde() {
        let event = ProcessChangeEvent::ModuleLoaded;
        let json = serde_json::to_string(&event).unwrap();
        let back: ProcessChangeEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ProcessChangeEvent::ModuleLoaded);
    }

    // -- New tests for ProcessChangeRecord --

    #[test]
    fn test_process_change_record() {
        let record = ProcessChangeRecord::new(ProcessChangeEvent::Changed, 1)
            .with_snap(5)
            .with_affected_key("Name")
            .with_sub_key("myapp");

        assert_eq!(record.event, ProcessChangeEvent::Changed);
        assert_eq!(record.process_key, 1);
        assert_eq!(record.snap, Some(5));
        assert_eq!(record.affected_key.as_deref(), Some("Name"));
        assert_eq!(record.sub_key.as_deref(), Some("myapp"));
    }

    #[test]
    fn test_process_change_record_serde() {
        let record = ProcessChangeRecord::new(ProcessChangeEvent::Added, 42)
            .with_snap(0);
        let json = serde_json::to_string(&record).unwrap();
        let back: ProcessChangeRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.process_key, 42);
        assert_eq!(back.snap, Some(0));
    }

    // -- New tests for ProcessGroup --

    #[test]
    fn test_process_group() {
        let mut group = ProcessGroup::new(1, "Session A");
        assert_eq!(group.id, 1);
        assert_eq!(group.name, "Session A");
        assert_eq!(group.process_count(), 0);

        group.add_process(10);
        group.add_process(20);
        group.add_process(10); // duplicate
        assert_eq!(group.process_count(), 2);
        assert!(group.contains_process(10));
        assert!(!group.contains_process(30));

        group.remove_process(10);
        assert_eq!(group.process_count(), 1);
        assert!(!group.contains_process(10));
    }

    #[test]
    fn test_process_group_parent_child() {
        let mut group = ProcessGroup::new(1, "parent");
        group.set_parent(0);
        group.add_child(2);
        group.add_child(3);
        assert_eq!(group.parent_id, Some(0));
        assert_eq!(group.child_ids(), &[2, 3]);

        group.remove_child(2);
        assert_eq!(group.child_ids(), &[3]);
    }

    #[test]
    fn test_process_group_serde() {
        let mut group = ProcessGroup::new(1, "test");
        group.add_process(5);
        let json = serde_json::to_string(&group).unwrap();
        let back: ProcessGroup = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, 1);
        assert_eq!(back.process_count(), 1);
    }

    // -- New tests for DebugConnectionInfo --

    #[test]
    fn test_debug_connection_info() {
        let info = DebugConnectionInfo::new()
            .with_debugger_type("gdb")
            .with_target_host("localhost")
            .with_target_port(1234)
            .with_uri("tcp://localhost:1234")
            .with_launch_command("gdb --interpreter=mi")
            .with_param("arch", "x86_64");

        assert!(info.has_info());
        assert_eq!(info.debugger_type.as_deref(), Some("gdb"));
        assert_eq!(info.target_port, Some(1234));
        assert_eq!(info.display_string(), "tcp://localhost:1234");
    }

    #[test]
    fn test_debug_connection_info_empty() {
        let info = DebugConnectionInfo::new();
        assert!(!info.has_info());
        assert_eq!(info.display_string(), "<no connection>");
    }

    #[test]
    fn test_debug_connection_info_display_no_uri() {
        let info = DebugConnectionInfo::new()
            .with_debugger_type("lldb")
            .with_target_host("192.168.1.1")
            .with_target_port(5555);
        assert_eq!(info.display_string(), "lldb @ 192.168.1.1:5555");
    }

    #[test]
    fn test_debug_connection_info_serde() {
        let info = DebugConnectionInfo::new()
            .with_debugger_type("gdb")
            .with_uri("tcp://host:1234");
        let json = serde_json::to_string(&info).unwrap();
        let back: DebugConnectionInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.debugger_type.as_deref(), Some("gdb"));
    }

    // -- New tests for TraceProcess connection info and helpers --

    #[test]
    fn test_process_connection_info() {
        let mut p = TraceProcess::new(1, "P[0]", "myapp", 0);
        assert!(p.connection_info().is_none());
        assert!(p.debugger_type().is_none());

        let info = DebugConnectionInfo::new().with_debugger_type("gdb");
        p.set_connection_info(info);
        assert!(p.connection_info().is_some());
        assert_eq!(p.debugger_type(), Some("gdb"));
    }

    #[test]
    fn test_process_memory_mappings_overlapping() {
        let mut p = TraceProcess::new(1, "P[0]", "myapp", 0);
        p.add_memory_mapping(
            ProcessMemoryMapping::new(0x400000, 0x10000, "[heap]", 0),
        );
        p.add_memory_mapping(
            ProcessMemoryMapping::new(0x7FFF0000, 0x80000, "[stack]", 0),
        );

        // Query overlapping with heap
        let overlapping = p.memory_mappings_overlapping(0x405000, 0x1000, 0);
        assert_eq!(overlapping.len(), 1);
        assert_eq!(overlapping[0].name, "[heap]");

        // Query that doesn't overlap
        let none = p.memory_mappings_overlapping(0x100000, 0x1000, 0);
        assert_eq!(none.len(), 0);
    }

    #[test]
    fn test_process_total_mapped_memory() {
        let mut p = TraceProcess::new(1, "P[0]", "myapp", 0);
        p.add_memory_mapping(
            ProcessMemoryMapping::new(0x400000, 0x10000, "[heap]", 0),
        );
        p.add_memory_mapping(
            ProcessMemoryMapping::new(0x7FFF0000, 0x80000, "[stack]", 0),
        );

        assert_eq!(p.total_mapped_memory_at(0), 0x10000 + 0x80000);
    }

    #[test]
    fn test_process_root_and_children() {
        let mut parent = TraceProcess::new(1, "P[0]", "parent", 0);
        assert!(parent.is_root());
        assert!(!parent.has_children());

        parent.add_child(2);
        parent.add_child(3);
        assert!(parent.has_children());
        assert!(!parent.is_root() || parent.parent_key.is_none()); // still root

        let mut child = TraceProcess::new(2, "P[1]", "child", 1);
        child.set_parent(1);
        assert!(!child.is_root());
    }

    // -- New tests for ProcessManager --

    #[test]
    fn test_process_manager_create() {
        let mut mgr = ProcessManager::new();
        assert!(mgr.is_empty());
        assert_eq!(mgr.process_count(), 0);

        let key = mgr.create_process("myapp", 0);
        assert_eq!(key, 1);
        assert_eq!(mgr.process_count(), 1);
        assert!(mgr.get_process(key).is_some());
        assert_eq!(mgr.get_process(key).unwrap().name, "myapp");
    }

    #[test]
    fn test_process_manager_add_remove() {
        let mut mgr = ProcessManager::new();
        let p = TraceProcess::new(5, "P[5]", "app", 0);
        mgr.add_process(p);
        assert_eq!(mgr.process_count(), 1);

        let removed = mgr.remove_process(5);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().name, "app");
        assert_eq!(mgr.process_count(), 0);

        // Remove nonexistent
        assert!(mgr.remove_process(99).is_none());
    }

    #[test]
    fn test_process_manager_alive_at() {
        let mut mgr = ProcessManager::new();
        mgr.create_process("app1", 0);
        let key2 = mgr.create_process("app2", 5);
        mgr.get_process_mut(key2).unwrap().remove(10);

        assert_eq!(mgr.alive_count_at(0), 1);
        assert_eq!(mgr.alive_count_at(5), 2);
        assert_eq!(mgr.alive_count_at(10), 1); // app2 still valid at snap 10
        assert_eq!(mgr.alive_count_at(11), 1);
    }

    #[test]
    fn test_process_manager_find_by_name() {
        let mut mgr = ProcessManager::new();
        mgr.create_process("myapp", 0);
        mgr.create_process("other", 0);

        let found = mgr.find_by_name("myapp", 0);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "myapp");

        assert!(mgr.find_by_name("missing", 0).is_none());
    }

    #[test]
    fn test_process_manager_find_by_pid() {
        let mut mgr = ProcessManager::new();
        let key = mgr.create_process("myapp", 0);
        mgr.get_process_mut(key).unwrap().pid = Some(1234);

        let found = mgr.find_by_pid(1234, 0);
        assert!(found.is_some());
        assert!(mgr.find_by_pid(9999, 0).is_none());
    }

    #[test]
    fn test_process_manager_find_by_path() {
        let mut mgr = ProcessManager::new();
        mgr.create_process("myapp", 0);

        let found = mgr.find_by_path("Processes[1]");
        assert!(found.is_some());
        assert!(mgr.find_by_path("nonexistent").is_none());
    }

    #[test]
    fn test_process_manager_parent_child() {
        let mut mgr = ProcessManager::new();
        let parent_key = mgr.create_process("parent", 0);
        let child_key = mgr.create_process("child", 1);
        mgr.get_process_mut(child_key).unwrap().set_parent(parent_key);
        mgr.get_process_mut(parent_key).unwrap().add_child(child_key);

        let roots = mgr.root_processes();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].key, parent_key);

        let children = mgr.children_of(parent_key);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].key, child_key);
    }

    #[test]
    fn test_process_manager_groups() {
        let mut mgr = ProcessManager::new();
        let key1 = mgr.create_process("app1", 0);
        let key2 = mgr.create_process("app2", 0);

        let group_id = mgr.create_group("Session A");
        assert_eq!(mgr.group_count(), 1);

        assert!(mgr.add_to_group(group_id, key1));
        assert!(mgr.add_to_group(group_id, key2));
        assert_eq!(mgr.group(group_id).unwrap().process_count(), 2);

        let groups = mgr.groups_for_process(key1);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].name, "Session A");

        assert!(mgr.remove_from_group(group_id, key1));
        assert_eq!(mgr.group(group_id).unwrap().process_count(), 1);

        mgr.remove_group(group_id);
        assert_eq!(mgr.group_count(), 0);
    }

    #[test]
    fn test_process_manager_change_tracking() {
        let mut mgr = ProcessManager::new();
        mgr.create_process("app1", 0);
        mgr.create_process("app2", 5);

        assert_eq!(mgr.change_count(), 2);
        assert_eq!(mgr.change_history()[0].event, ProcessChangeEvent::Added);
        assert_eq!(mgr.change_history()[1].event, ProcessChangeEvent::Added);

        mgr.remove_process(1);
        assert_eq!(mgr.change_count(), 3);
        assert_eq!(mgr.change_history()[2].event, ProcessChangeEvent::Deleted);

        mgr.clear_change_history();
        assert_eq!(mgr.change_count(), 0);
    }

    #[test]
    fn test_process_manager_change_on_remove_from_group() {
        let mut mgr = ProcessManager::new();
        let key = mgr.create_process("app", 0);
        let group_id = mgr.create_group("test");
        mgr.add_to_group(group_id, key);

        // Removing process should also remove from groups
        mgr.remove_process(key);
        assert_eq!(mgr.group(group_id).unwrap().process_count(), 0);
    }

    #[test]
    fn test_process_manager_statistics() {
        let mut mgr = ProcessManager::new();
        mgr.create_process("app1", 0);
        mgr.create_process("app2", 0);
        mgr.create_group("group1");

        let stats = mgr.statistics(0);
        assert_eq!(stats.total_processes, 2);
        assert_eq!(stats.alive_at_snap, 2);
        assert_eq!(stats.total_groups, 1);
        assert_eq!(stats.root_processes, 2);
        assert_eq!(stats.change_records, 2);
    }

    #[test]
    fn test_process_manager_prune_dead() {
        let mut mgr = ProcessManager::new();
        let key = mgr.create_process("app", 0);
        mgr.get_process_mut(key).unwrap().remove(5);

        let pruned = mgr.prune_dead_before(10);
        assert_eq!(pruned.len(), 1);
        assert_eq!(mgr.process_count(), 0);
    }

    #[test]
    fn test_process_manager_iter() {
        let mut mgr = ProcessManager::new();
        mgr.create_process("a", 0);
        mgr.create_process("b", 0);
        mgr.create_process("c", 0);

        let names: Vec<_> = mgr.iter().map(|(_, p)| p.name.clone()).collect();
        assert_eq!(names.len(), 3);
    }

    #[test]
    fn test_process_manager_serde() {
        let mut mgr = ProcessManager::new();
        mgr.create_process("myapp", 0);
        mgr.create_group("test");

        let json = serde_json::to_string(&mgr).unwrap();
        let back: ProcessManager = serde_json::from_str(&json).unwrap();
        assert_eq!(back.process_count(), 1);
        assert_eq!(back.group_count(), 1);
    }

    #[test]
    fn test_process_manager_statistics_serde() {
        let stats = ProcessManagerStatistics {
            total_processes: 5,
            alive_at_snap: 3,
            total_groups: 2,
            root_processes: 2,
            change_records: 10,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let back: ProcessManagerStatistics = serde_json::from_str(&json).unwrap();
        assert_eq!(back.total_processes, 5);
        assert_eq!(back.alive_at_snap, 3);
    }

    #[test]
    fn test_process_manager_clear() {
        let mut mgr = ProcessManager::new();
        mgr.create_process("app", 0);
        mgr.create_group("test");
        assert!(!mgr.is_empty());

        mgr.clear();
        assert!(mgr.is_empty());
        assert_eq!(mgr.group_count(), 0);
    }

    #[test]
    fn test_process_manager_process_keys() {
        let mut mgr = ProcessManager::new();
        mgr.create_process("a", 0);
        mgr.create_process("b", 0);
        let keys = mgr.process_keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&1));
        assert!(keys.contains(&2));
    }

    #[test]
    fn test_process_manager_find_by_name_at_snap() {
        let mut mgr = ProcessManager::new();
        let key = mgr.create_process("myapp", 0);
        mgr.get_process_mut(key).unwrap().set_name(10, "renamed");

        assert_eq!(mgr.find_by_name("myapp", 0).unwrap().key, key);
        assert_eq!(mgr.find_by_name("renamed", 10).unwrap().key, key);
        assert!(mgr.find_by_name("myapp", 10).is_none());
    }

    #[test]
    fn test_process_manager_max_history() {
        let mut mgr = ProcessManager::new().with_max_history(2);
        mgr.create_process("a", 0);
        mgr.create_process("b", 0);
        mgr.create_process("c", 0);

        // Only last 2 records retained
        assert_eq!(mgr.change_count(), 2);
    }

    #[test]
    fn test_process_manager_add_to_nonexistent_group() {
        let mut mgr = ProcessManager::new();
        assert!(!mgr.add_to_group(999, 1));
    }
}
