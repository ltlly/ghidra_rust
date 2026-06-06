//! FlatDebuggerAPI - a flattened, script-friendly API for debugger operations.
//!
//! Ported from Ghidra's `ghidra.debug.flatapi.FlatDebuggerAPI`.
//! This provides a high-level, convenient interface for scripting debugger
//! operations: stepping, breakpoint management, memory reading/writing,
//! register access, and trace navigation.

use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::action_name::ActionName;
use super::breakpoint::LogicalBreakpoint;
use crate::model::breakpoint::TraceBreakpointKind;
use crate::model::time::TraceSchedule;

/// The default timeout for waiting on async operations.
pub const DEFAULT_WAIT_TIMEOUT: Duration = Duration::from_secs(60);

/// A result type for flat API operations.
pub type FlatApiResult<T> = Result<T, FlatApiError>;

/// Errors that can occur in flat API operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum FlatApiError {
    /// There is no active trace.
    #[error("No active trace")]
    NoActiveTrace,
    /// There is no active thread.
    #[error("No active thread")]
    NoActiveThread,
    /// The operation timed out.
    #[error("Operation timed out after {0:?}")]
    Timeout(Duration),
    /// The operation was interrupted.
    #[error("Operation interrupted: {0}")]
    Interrupted(String),
    /// An error from the underlying debugger service.
    #[error("Service error: {0}")]
    ServiceError(String),
    /// Invalid argument.
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
}

/// A location in a program (static or dynamic).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramLocation {
    /// The program URL (or trace key for dynamic).
    pub program_url: Option<String>,
    /// The address.
    pub address: u64,
    /// Whether this is a dynamic (trace) location.
    pub is_dynamic: bool,
}

impl ProgramLocation {
    /// Create a static program location.
    pub fn static_loc(url: impl Into<String>, address: u64) -> Self {
        Self {
            program_url: Some(url.into()),
            address,
            is_dynamic: false,
        }
    }

    /// Create a dynamic (trace) location.
    pub fn dynamic_loc(address: u64) -> Self {
        Self {
            program_url: None,
            address,
            is_dynamic: true,
        }
    }
}

/// A set of breakpoint kinds commonly used together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommonBreakpointSet {
    /// The kinds included in this set.
    pub kinds: Vec<TraceBreakpointKind>,
    /// A display label.
    pub label: String,
}

impl CommonBreakpointSet {
    /// Software execute breakpoint set.
    pub fn swx() -> Self {
        Self {
            kinds: vec![TraceBreakpointKind::SwExecute],
            label: "SWX".into(),
        }
    }

    /// Hardware execute breakpoint set.
    pub fn hwx() -> Self {
        Self {
            kinds: vec![TraceBreakpointKind::HwExecute],
            label: "HWX".into(),
        }
    }

    /// Read access breakpoint set.
    pub fn read() -> Self {
        Self {
            kinds: vec![TraceBreakpointKind::Read],
            label: "READ".into(),
        }
    }

    /// Write access breakpoint set.
    pub fn write() -> Self {
        Self {
            kinds: vec![TraceBreakpointKind::Write],
            label: "WRITE".into(),
        }
    }

    /// Read+Write access breakpoint set.
    pub fn access() -> Self {
        Self {
            kinds: vec![TraceBreakpointKind::Read, TraceBreakpointKind::Write],
            label: "ACCESS".into(),
        }
    }
}

/// The FlatDebuggerAPI trait provides a script-friendly interface
/// for performing debugger operations.
///
/// Implement this trait to get convenient methods for stepping,
/// breakpoint management, memory/register access, and more.
pub trait FlatDebuggerApi {
    /// Get the current snap key.
    fn current_snap(&self) -> i64;

    /// Get the current thread key.
    fn current_thread(&self) -> Option<i64>;

    /// Get the current frame (0 = innermost).
    fn current_frame(&self) -> u32 {
        0
    }

    /// Get the current emulation schedule, if in emulated state.
    fn current_emulation_schedule(&self) -> Option<TraceSchedule> {
        None
    }

    // ── Execution control ──────────────────────────────────────

    /// Step the current thread into (step one instruction, entering calls).
    fn step_into(&mut self) -> FlatApiResult<bool>;

    /// Step the current thread over (step one instruction, skipping calls).
    fn step_over(&mut self) -> FlatApiResult<bool>;

    /// Step out of the current function.
    fn step_out(&mut self) -> FlatApiResult<bool>;

    /// Resume execution.
    fn go(&mut self) -> FlatApiResult<bool>;

    /// Interrupt execution.
    fn interrupt(&mut self) -> FlatApiResult<bool>;

    // ── Breakpoint management ──────────────────────────────────

    /// Set a software execute breakpoint at an address.
    fn breakpoint_set_sw_execute(
        &mut self,
        address: u64,
        name: Option<&str>,
    ) -> FlatApiResult<Vec<LogicalBreakpoint>>;

    /// Set a hardware execute breakpoint at an address.
    fn breakpoint_set_hw_execute(
        &mut self,
        address: u64,
        name: Option<&str>,
    ) -> FlatApiResult<Vec<LogicalBreakpoint>>;

    /// Set a read watchpoint at an address.
    fn breakpoint_set_read(
        &mut self,
        address: u64,
        length: u32,
        name: Option<&str>,
    ) -> FlatApiResult<Vec<LogicalBreakpoint>>;

    /// Set a write watchpoint at an address.
    fn breakpoint_set_write(
        &mut self,
        address: u64,
        length: u32,
        name: Option<&str>,
    ) -> FlatApiResult<Vec<LogicalBreakpoint>>;

    /// Delete breakpoints at an address.
    fn breakpoints_clear(&mut self, address: u64) -> FlatApiResult<bool>;

    /// Enable breakpoints at an address.
    fn breakpoints_enable(&mut self, address: u64) -> FlatApiResult<bool>;

    /// Disable breakpoints at an address.
    fn breakpoints_disable(&mut self, address: u64) -> FlatApiResult<bool>;

    // ── Memory access ──────────────────────────────────────────

    /// Read bytes from memory at the current snap.
    fn read_memory(&self, address: u64, length: u32) -> FlatApiResult<Vec<u8>>;

    /// Write bytes to memory.
    fn write_memory(&mut self, address: u64, data: &[u8]) -> FlatApiResult<bool>;

    // ── Register access ────────────────────────────────────────

    /// Read a register value (returned as bytes).
    fn read_register(&self, register: &str) -> FlatApiResult<Vec<u8>>;

    /// Write a register value.
    fn write_register(&mut self, register: &str, value: &[u8]) -> FlatApiResult<bool>;

    // ── Action dispatch ────────────────────────────────────────

    /// Execute an action on the current thread.
    fn do_thread_action(&mut self, action: ActionName) -> FlatApiResult<bool>;

    /// Execute an action on the current trace.
    fn do_trace_action(&mut self, action: ActionName) -> FlatApiResult<bool>;

    /// Flush all asynchronous processing pipelines.
    fn flush_async_pipelines(&mut self) -> FlatApiResult<bool>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_location_static() {
        let loc = ProgramLocation::static_loc("/path/to/prog", 0x401000);
        assert_eq!(loc.address, 0x401000);
        assert!(!loc.is_dynamic);
        assert!(loc.program_url.is_some());
    }

    #[test]
    fn test_program_location_dynamic() {
        let loc = ProgramLocation::dynamic_loc(0x401000);
        assert_eq!(loc.address, 0x401000);
        assert!(loc.is_dynamic);
        assert!(loc.program_url.is_none());
    }

    #[test]
    fn test_common_breakpoint_sets() {
        let swx = CommonBreakpointSet::swx();
        assert_eq!(swx.kinds.len(), 1);
        assert_eq!(swx.kinds[0], TraceBreakpointKind::SwExecute);

        let access = CommonBreakpointSet::access();
        assert_eq!(access.kinds.len(), 2);
    }

    #[test]
    fn test_flat_api_error_display() {
        let err = FlatApiError::NoActiveTrace;
        assert_eq!(err.to_string(), "No active trace");

        let err = FlatApiError::Timeout(Duration::from_secs(30));
        assert!(err.to_string().contains("30s"));
    }
}
