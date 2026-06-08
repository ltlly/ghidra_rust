//! Debugger agent implementations.
//!
//! This module provides Rust ports of Ghidra's debugger agent backends:
//!
//! - **`gdb`**: GDB agent using GDB/MI protocol and Python extensions.
//!   Ported from `Debugger-agent-gdb`.
//!
//! - **`dbgeng`**: Windows Debugging Engine (WinDbg) agent using pydbgwin/pykd.
//!   Ported from `Debugger-agent-dbgeng`.
//!
//! - **`lldb`**: LLDB agent using the LLDB Python API.
//!   Ported from `Debugger-agent-lldb`.
//!
//! - **`drgn`**: drgn agent for Linux kernel debugging.
//!   Ported from `Debugger-agent-drgn`.
//!
//! - **`x64dbg`**: x64dbg agent using x64dbg_automate.
//!   Ported from `Debugger-agent-x64dbg`.
//!
//! Each agent follows a common pattern:
//! - **connection**: Agent connection lifecycle and process management.
//! - **commands**: Trace put commands (memory, registers, threads, modules, etc.).
//! - **hooks**: Event hooks for automatic trace synchronization.
//! - **arch**: Architecture and language mapping.

pub mod gdb;
pub mod dbgeng;
pub mod lldb;
pub mod drgn;
pub mod x64dbg;

use serde::{Deserialize, Serialize};

/// Common object path patterns used by all agents.
///
/// Each agent uses a tree of trace objects rooted at the trace.
/// The path hierarchy is:
/// - `Processes[N]` - process container
///   - `.Threads[N]` - thread within a process
///     - `.Stack[N]` - stack frame
///       - `.Registers` - register values for that frame
///   - `.Memory` - memory space for the process
///   - `.Modules` - loaded modules
///   - `.Environment` - environment variables
pub mod paths {
    /// Pattern for process container: `Processes`
    pub const PROCESSES: &str = "Processes";
    /// Pattern for a process: `Processes[{procnum}]`
    pub const PROCESS: &str = "Processes[{procnum}]";
    /// Pattern for threads container: `Processes[{procnum}].Threads`
    pub const THREADS: &str = "Processes[{procnum}].Threads";
    /// Pattern for a thread: `Processes[{procnum}].Threads[{tnum}]`
    pub const THREAD: &str = "Processes[{procnum}].Threads[{tnum}]";
    /// Pattern for stack: `Processes[{procnum}].Threads[{tnum}].Stack`
    pub const STACK: &str = "Processes[{procnum}].Threads[{tnum}].Stack";
    /// Pattern for a stack frame: `Processes[{procnum}].Threads[{tnum}].Stack[{level}]`
    pub const FRAME: &str = "Processes[{procnum}].Threads[{tnum}].Stack[{level}]";
    /// Pattern for registers: `Processes[{procnum}].Threads[{tnum}].Stack[{level}].Registers`
    pub const REGS: &str = "Processes[{procnum}].Threads[{tnum}].Stack[{level}].Registers";
    /// Pattern for memory: `Processes[{procnum}].Memory`
    pub const MEMORY: &str = "Processes[{procnum}].Memory";
    /// Pattern for modules: `Processes[{procnum}].Modules`
    pub const MODULES: &str = "Processes[{procnum}].Modules";
    /// Pattern for a module: `Processes[{procnum}].Modules[{modbase}]`
    pub const MODULE: &str = "Processes[{procnum}].Modules[{modbase}]";
    /// Pattern for environment: `Processes[{procnum}].Environment`
    pub const ENVIRONMENT: &str = "Processes[{procnum}].Environment";
    /// Pattern for breakpoints: `Breakpoints`
    pub const BREAKPOINTS: &str = "Breakpoints";
    /// Pattern for a breakpoint: `Breakpoints[{id}]`
    pub const BREAKPOINT: &str = "Breakpoints[{id}]";
}

/// The execution state of a debugged process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExecutionState {
    /// Process is running.
    Running,
    /// Process is stopped (breakpoint, signal, etc.).
    Stopped,
    /// Process has exited.
    Exited,
    /// Process is not yet started.
    NotStarted,
}

impl ExecutionState {
    /// Convert to the string stored in trace objects.
    pub fn as_trace_str(&self) -> &'static str {
        match self {
            Self::Running => "RUNNING",
            Self::Stopped => "STOPPED",
            Self::Exited => "TERMINATED",
            Self::NotStarted => "NOT_STARTED",
        }
    }
}

/// A register value with its name and byte data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterValue {
    /// Register name (e.g. "rax", "rip").
    pub name: String,
    /// The raw bytes of the register value.
    pub bytes: Vec<u8>,
}

impl RegisterValue {
    /// Create a new register value.
    pub fn new(name: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            bytes,
        }
    }

    /// Create a register value from a u64 (little-endian).
    pub fn from_u64(name: impl Into<String>, value: u64) -> Self {
        Self {
            name: name.into(),
            bytes: value.to_le_bytes().to_vec(),
        }
    }

    /// Interpret the value as a u64 (little-endian).
    pub fn as_u64(&self) -> Option<u64> {
        if self.bytes.len() >= 8 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&self.bytes[..8]);
            Some(u64::from_le_bytes(buf))
        } else {
            None
        }
    }
}

/// A memory region descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRegion {
    /// Start address.
    pub base: u64,
    /// Size in bytes.
    pub size: u64,
    /// File offset.
    pub offset: u64,
    /// Permissions string (e.g. "rwxp").
    pub permissions: String,
    /// Object file name.
    pub object_file: String,
}

/// A loaded module descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleInfo {
    /// Module name.
    pub name: String,
    /// Base address.
    pub base: u64,
    /// Size in bytes.
    pub size: u64,
    /// Build ID (if available).
    pub build_id: Option<String>,
    /// Debug file path.
    pub debug_path: Option<String>,
    /// Loaded file path.
    pub load_path: Option<String>,
}

/// A stack frame descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackFrameInfo {
    /// Frame level (0 = innermost).
    pub level: u32,
    /// Instruction pointer.
    pub pc: u64,
    /// Stack pointer.
    pub sp: u64,
    /// Frame pointer.
    pub fp: u64,
    /// Return address.
    pub return_address: u64,
    /// Function name (if known).
    pub function_name: Option<String>,
}

/// A breakpoint descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreakpointInfo {
    /// Breakpoint ID.
    pub id: u32,
    /// Breakpoint type.
    pub bp_type: BreakpointType,
    /// Address.
    pub address: u64,
    /// Whether the breakpoint is enabled.
    pub enabled: bool,
    /// Hit count.
    pub hit_count: u32,
    /// Condition expression (if conditional).
    pub condition: Option<String>,
}

/// Type of breakpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BreakpointType {
    /// Software breakpoint.
    Software,
    /// Hardware breakpoint.
    Hardware,
    /// Memory breakpoint (watchpoint).
    Memory,
}

/// A thread descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadInfo {
    /// Thread ID.
    pub id: u64,
    /// Thread name (if known).
    pub name: Option<String>,
    /// Current execution state.
    pub state: ExecutionState,
}

/// A process descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Process ID.
    pub id: u64,
    /// Current execution state.
    pub state: ExecutionState,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_state_str() {
        assert_eq!(ExecutionState::Running.as_trace_str(), "RUNNING");
        assert_eq!(ExecutionState::Stopped.as_trace_str(), "STOPPED");
        assert_eq!(ExecutionState::Exited.as_trace_str(), "TERMINATED");
    }

    #[test]
    fn test_register_value_u64() {
        let rv = RegisterValue::from_u64("rax", 0x1234567890abcdef);
        assert_eq!(rv.as_u64(), Some(0x1234567890abcdef));
        assert_eq!(rv.name, "rax");
        assert_eq!(rv.bytes.len(), 8);
    }

    #[test]
    fn test_register_value_small() {
        let rv = RegisterValue::new("al", vec![0x42]);
        assert_eq!(rv.as_u64(), None);
    }

    #[test]
    fn test_path_patterns() {
        assert_eq!(paths::PROCESSES, "Processes");
        assert!(paths::FRAME.contains("{level}"));
        assert!(paths::REGS.contains("{procnum}"));
    }

    #[test]
    fn test_breakpoint_type() {
        assert_eq!(BreakpointType::Software, BreakpointType::Software);
        assert_ne!(BreakpointType::Software, BreakpointType::Hardware);
    }
}
