//! x64dbg debugger agent.
//!
//! Rust port of Ghidra's `Debugger-agent-x64dbg`. This module provides
//! the x64dbg agent backend that communicates with x64dbg via the
//! x64dbg_automate Python library.
//!
//! x64dbg uses "Processes[N]" as its process path prefix, with
//! support for 32-bit and 64-bit Windows targets.

pub mod arch;
pub mod commands;
pub mod connection;
pub mod hooks;

use serde::{Deserialize, Serialize};

/// x64dbg-specific object path patterns.
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
    pub const MODULE: &str = "Processes[{procnum}].Modules[{modbase}]";
    pub const ENVIRONMENT: &str = "Processes[{procnum}].Environment";
    pub const BREAKPOINTS: &str = "Breakpoints";
    pub const BREAKPOINT: &str = "Breakpoints[{id}]";
    pub const AVAILABLE: &str = "Available";
}

/// x64dbg version information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X64DbgVersion {
    /// Full version string.
    pub full: String,
    /// Name.
    pub name: String,
    /// Dotted version.
    pub dotted: String,
    /// Architecture string (e.g. "x64", "x86").
    pub arch: String,
}

impl X64DbgVersion {
    /// Create from components.
    pub fn new(full: impl Into<String>, name: impl Into<String>, dotted: impl Into<String>, arch: impl Into<String>) -> Self {
        Self {
            full: full.into(),
            name: name.into(),
            dotted: dotted.into(),
            arch: arch.into(),
        }
    }
}

/// State tracking for the x64dbg agent.
#[derive(Debug, Default)]
pub struct X64DbgState {
    /// Whether a trace is active.
    pub trace_active: bool,
    /// Whether hooks are installed.
    pub hooks_installed: bool,
    /// Currently synchronized process IDs.
    pub synced_processes: Vec<u32>,
    /// Selected process ID.
    pub selected_process: Option<u32>,
    /// Selected thread ID.
    pub selected_thread: Option<u32>,
    /// Selected frame level.
    pub selected_frame: Option<u32>,
    /// Whether the target is 64-bit.
    pub is_64bit: bool,
}

impl X64DbgState {
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

/// x64dbg breakpoint type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum X64DbgBreakpointType {
    /// Normal breakpoint (software).
    Normal,
    /// Hardware breakpoint.
    Hardware,
    /// Memory breakpoint.
    Memory,
}

impl X64DbgBreakpointType {
    /// Convert to the Ghidra breakpoint type.
    pub fn to_breakpoint_type(&self) -> crate::agents::BreakpointType {
        match self {
            Self::Normal => crate::agents::BreakpointType::Software,
            Self::Hardware => crate::agents::BreakpointType::Hardware,
            Self::Memory => crate::agents::BreakpointType::Memory,
        }
    }
}

/// x64dbg execution status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum X64DbgExecStatus {
    /// Idle (no process).
    Idle,
    /// Running.
    Running,
    /// Paused.
    Paused,
    /// Stopped at breakpoint.
    Breakpoint,
    /// Single step.
    Step,
    /// Exception.
    Exception,
}

impl X64DbgExecStatus {
    /// Convert to the common execution state.
    pub fn to_execution_state(&self) -> crate::agents::ExecutionState {
        match self {
            Self::Idle => crate::agents::ExecutionState::NotStarted,
            Self::Running => crate::agents::ExecutionState::Running,
            Self::Paused | Self::Breakpoint | Self::Step | Self::Exception => {
                crate::agents::ExecutionState::Stopped
            }
        }
    }
}

/// A CreateThreadEventData equivalent from x64dbg_automate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateThreadEventData {
    /// Thread ID.
    pub thread_id: u64,
    /// Thread handle.
    pub handle: u64,
    /// Start address.
    pub start_address: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x64dbg_state() {
        let mut state = X64DbgState::new();
        state.is_64bit = true;
        state.sync_process(1);
        assert!(state.is_process_synced(1));
        state.reset();
        assert!(!state.is_64bit);
    }

    #[test]
    fn test_x64dbg_version() {
        let ver = X64DbgVersion::new("Snapshot_2023-11-07_01-01", "x64dbg", "Snapshot_2023-11-07_01-01", "x64");
        assert_eq!(ver.arch, "x64");
    }

    #[test]
    fn test_breakpoint_type_conversion() {
        assert_eq!(
            X64DbgBreakpointType::Normal.to_breakpoint_type(),
            crate::agents::BreakpointType::Software
        );
    }

    #[test]
    fn test_exec_status_conversion() {
        assert_eq!(
            X64DbgExecStatus::Running.to_execution_state(),
            crate::agents::ExecutionState::Running
        );
        assert_eq!(
            X64DbgExecStatus::Paused.to_execution_state(),
            crate::agents::ExecutionState::Stopped
        );
    }
}
