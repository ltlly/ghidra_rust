//! TraceProcess -- enhanced process representation for the debug trace.
//!
//! Ported from Ghidra's `ghidra.trace.model.process.TraceProcess` and
//! `ghidra.trace.database.process.DBTraceProcess`.
//!
//! This module provides a richer process type than the basic `model::thread::TraceProcess`,
//! with support for environment variables, command-line arguments, and process-level
//! execution state management.

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
}

// ---------------------------------------------------------------------------
// TraceProcess
// ---------------------------------------------------------------------------

/// An enhanced process entry for the debug trace.
///
/// This extends the basic `model::thread::TraceProcess` with environment
/// information, execution state management, and thread tracking.
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
        }
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
}
