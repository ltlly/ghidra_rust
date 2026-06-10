//! LLDB debugger agent.
//!
//! Rust port of Ghidra's `Debugger-agent-lldb`. This module provides
//! the LLDB agent backend that communicates with LLDB via its Python API
//! (lldb module).
//!
//! LLDB uses "processes[N]" (lowercase) as its process path prefix,
//! but the Ghidra agent normalizes to the standard `Processes[N]` hierarchy.

pub mod arch;
pub mod commands;
pub mod connection;
pub mod hooks;
pub mod lldb_inferior_process;
pub mod lldb_thread;

use serde::{Deserialize, Serialize};

/// LLDB-specific object path patterns.
pub mod paths {
    pub const PROCESSES: &str = "Processes";
    pub const PROCESS: &str = "Processes[{procnum}]";
    pub const THREADS: &str = "Processes[{procnum}].Threads";
    pub const THREAD: &str = "Processes[{procnum}].Threads[{tnum}]";
    pub const STACK: &str = "Processes[{procnum}].Threads[{tnum}].Stack";
    pub const FRAME: &str = "Processes[{procnum}].Threads[{tnum}].Stack[{level}]";
    pub const REGS: &str = "Processes[{procnum}].Threads[{tnum}].Stack[{level}].Registers";
    pub const MEMORY: &str = "Processes[{procnum}].Memory";
    pub const MODULES: &str = "Processes[{procnum}].Modules";
    pub const MODULE: &str = "Processes[{procnum}].Modules[{modpath}]";
    pub const ENVIRONMENT: &str = "Processes[{procnum}].Environment";
    pub const BREAKPOINTS: &str = "Breakpoints";
    pub const BREAKPOINT: &str = "Breakpoints[{id}]";
    pub const SIGNALS: &str = "Signals";
}

/// LLDB version information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LldbVersion {
    /// Full version string.
    pub full: String,
    /// LLDB version number.
    pub version: String,
    /// Target triple.
    pub target_triple: Option<String>,
}

impl LldbVersion {
    /// Parse an LLDB version string.
    pub fn parse(version_str: &str) -> Self {
        Self {
            full: version_str.to_string(),
            version: version_str.to_string(),
            target_triple: None,
        }
    }
}

/// State tracking for the LLDB agent.
#[derive(Debug, Default)]
pub struct LldbState {
    /// Whether a trace is active.
    pub trace_active: bool,
    /// Whether hooks are installed.
    pub hooks_installed: bool,
    /// Currently synchronized process IDs.
    pub synced_processes: Vec<u32>,
    /// Selected process index.
    pub selected_process: Option<u32>,
    /// Selected thread index.
    pub selected_thread: Option<u32>,
    /// Selected frame index.
    pub selected_frame: Option<u32>,
}

impl LldbState {
    /// Create a new empty state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset all tracking state.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Mark a process as synchronized.
    pub fn sync_process(&mut self, proc_id: u32) {
        if !self.synced_processes.contains(&proc_id) {
            self.synced_processes.push(proc_id);
        }
    }

    /// Check if a process is synchronized.
    pub fn is_process_synced(&self, proc_id: u32) -> bool {
        self.synced_processes.contains(&proc_id)
    }
}

/// LLDB stop reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LldbStopReason {
    /// Breakpoint hit.
    Breakpoint,
    /// Watchpoint hit.
    Watchpoint,
    /// Signal received.
    Signal,
    /// Exception.
    Exception,
    /// Exec (execve).
    Exec,
    /// Plan complete (step finished).
    PlanComplete,
    /// Thread exiting.
    ThreadExiting,
    /// Instrumentation.
    Instrumentation,
    /// Processor trace.
    ProcessorTrace,
    /// Fork.
    Fork,
    /// VFork.
    VFork,
    /// Unknown.
    Unknown,
}

impl LldbStopReason {
    /// Convert from LLDB stop reason string.
    pub fn from_lldb(reason: &str) -> Self {
        match reason.to_lowercase().as_str() {
            "breakpoint" => Self::Breakpoint,
            "watchpoint" => Self::Watchpoint,
            "signal" => Self::Signal,
            "exception" => Self::Exception,
            "exec" => Self::Exec,
            "plancomplete" | "plan complete" => Self::PlanComplete,
            "threadexiting" | "thread exiting" => Self::ThreadExiting,
            "instrumentation" => Self::Instrumentation,
            "processortrace" | "processor trace" => Self::ProcessorTrace,
            "fork" => Self::Fork,
            "vfork" => Self::VFork,
            _ => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lldb_state() {
        let mut state = LldbState::new();
        assert!(!state.trace_active);
        state.trace_active = true;
        state.sync_process(1);
        assert!(state.is_process_synced(1));
        state.reset();
        assert!(!state.trace_active);
    }

    #[test]
    fn test_stop_reason() {
        assert_eq!(LldbStopReason::from_lldb("breakpoint"), LldbStopReason::Breakpoint);
        assert_eq!(LldbStopReason::from_lldb("Signal"), LldbStopReason::Signal);
        assert_eq!(LldbStopReason::from_lldb("unknown_reason"), LldbStopReason::Unknown);
    }

    #[test]
    fn test_lldb_version() {
        let ver = LldbVersion::parse("lldb-1400.0.38.14");
        assert!(ver.full.contains("1400"));
    }
}
