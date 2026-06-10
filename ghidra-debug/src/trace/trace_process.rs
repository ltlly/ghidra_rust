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
        matches!(self, Self::Signal(_))
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
            _ => None,
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
        Self {
            key,
            path: path_str.clone(),
            pid: None,
            name: name.into(),
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
        assert_eq!(m.end_address(), 0x7F020000);
        assert!(m.contains_address(0x7F010000));
        assert!(!m.contains_address(0x7F030000));
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
}
