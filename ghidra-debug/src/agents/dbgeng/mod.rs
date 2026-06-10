//! Windows Debugging Engine (dbgeng/WinDbg) agent.
//!
//! Rust port of Ghidra's `Debugger-agent-dbgeng`. This module provides
//! the dbgeng agent backend that communicates with the Windows Debugging
//! Engine via pydbgwin/pykd.
//!
//! Dbgeng uses "Processes[N]" as its process path prefix, with
//! WoW64 support for 32-bit processes on 64-bit Windows.

pub mod arch;
pub mod commands;
pub mod connection;
pub mod dbgeng_inferior_process;
pub mod dbgeng_thread;
pub mod hooks;

use serde::{Deserialize, Serialize};

/// Dbgeng-specific object path patterns.
///
/// Dbgeng uses the standard `Processes[N]` hierarchy.
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
}

/// Debugging engine version information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbgEngVersion {
    /// Full version string.
    pub full: String,
    /// Engine name.
    pub name: String,
    /// Dotted version.
    pub dotted: String,
    /// Architecture (e.g. "x64").
    pub arch: String,
}

impl DbgEngVersion {
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

/// State tracking for the dbgeng agent.
#[derive(Debug, Default)]
pub struct DbgEngState {
    /// Whether a trace is active.
    pub trace_active: bool,
    /// Whether hooks are installed.
    pub hooks_installed: bool,
    /// Currently synchronized process IDs.
    pub synced_processes: Vec<u32>,
    /// Selected process number.
    pub selected_process: Option<u32>,
    /// Selected thread number.
    pub selected_thread: Option<u32>,
    /// Selected frame level.
    pub selected_frame: Option<u32>,
    /// Whether the target is 64-bit.
    pub is_64bit: bool,
    /// Whether WoW64 mode is active (32-bit on 64-bit Windows).
    pub is_wow64: bool,
}

impl DbgEngState {
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

/// The _DEBUG_STACK_FRAME structure from dbgeng.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugStackFrame {
    /// Frame number (0 = innermost).
    pub frame_number: u32,
    /// Instruction pointer offset.
    pub instruction_offset: u64,
    /// Stack pointer offset.
    pub stack_offset: u64,
    /// Frame pointer offset.
    pub frame_offset: u64,
    /// Return address offset.
    pub return_offset: u64,
}

/// The _DEBUG_MODULE_PARAMETERS structure from dbgeng.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugModuleParameters {
    /// Module base address.
    pub base: u64,
    /// Module size.
    pub size: u32,
    /// Module name.
    pub name: String,
    /// Image file name.
    pub image_name: String,
    /// Whether debug info is loaded.
    pub debug_info_loaded: bool,
}

/// Breakpoint type from dbgeng.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DbgEngBreakpointType {
    /// Code breakpoint.
    Code,
    /// Data breakpoint (watchpoint).
    Data,
    /// Kernel breakpoint.
    Kernel,
}

/// Interrupt flags for dbgeng.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DebugInterrupt {
    /// Active interrupt.
    Active,
    /// Passive interrupt.
    Passive,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dbgeng_version() {
        let ver = DbgEngVersion::new("10.0.19041.1", "Windows Debugger", "10.0.19041.1", "x64");
        assert_eq!(ver.arch, "x64");
        assert!(ver.full.contains("10.0"));
    }

    #[test]
    fn test_dbgeng_state() {
        let mut state = DbgEngState::new();
        assert!(!state.trace_active);
        state.trace_active = true;
        state.is_64bit = true;
        state.sync_process(1);
        assert!(state.is_process_synced(1));
        assert!(!state.is_process_synced(2));
        state.reset();
        assert!(!state.trace_active);
    }

    #[test]
    fn test_debug_stack_frame() {
        let frame = DebugStackFrame {
            frame_number: 0,
            instruction_offset: 0x7ff612345678,
            stack_offset: 0x000000abcdef,
            frame_offset: 0x000000abcdef00,
            return_offset: 0x7ff61234abcd,
        };
        assert_eq!(frame.frame_number, 0);
        assert!(frame.instruction_offset > 0x7ff600000000);
    }
}
