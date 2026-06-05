//! Additional debugger service implementations.
//!
//! Ported from Ghidra's `DebuggerConsoleService`, `DebuggerControlService`,
//! `DebuggerTargetService`, `DebuggerWatchesService`, `DebuggerListingService`.

use serde::{Deserialize, Serialize};

/// Console output level for the debugger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ConsoleOutputLevel {
    /// Informational message.
    Info,
    /// Warning message.
    Warning,
    /// Error message.
    Error,
    /// Debug/verbose message.
    Debug,
}

/// A console message from the debugger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleMessage {
    /// The output level.
    pub level: ConsoleOutputLevel,
    /// The message text.
    pub message: String,
    /// The source (plugin or service name).
    pub source: String,
    /// Timestamp (millis since epoch).
    pub timestamp: u64,
}

impl ConsoleMessage {
    /// Create a new console message.
    pub fn new(
        level: ConsoleOutputLevel,
        message: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            level,
            message: message.into(),
            source: source.into(),
            timestamp: 0,
        }
    }

    /// Create an info message.
    pub fn info(message: impl Into<String>, source: impl Into<String>) -> Self {
        Self::new(ConsoleOutputLevel::Info, message, source)
    }

    /// Create an error message.
    pub fn error(message: impl Into<String>, source: impl Into<String>) -> Self {
        Self::new(ConsoleOutputLevel::Error, message, source)
    }
}

/// The current state of debugger execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DebuggerExecutionState {
    /// The debugger is not connected.
    Disconnected,
    /// The debugger is connected but not running.
    Stopped,
    /// The target is running.
    Running,
    /// The target is stepping.
    Stepping,
    /// The target has terminated.
    Terminated,
    /// An error occurred.
    Error,
}

/// A watch entry for monitoring memory/variable values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchEntry {
    /// Unique ID for this watch.
    pub id: u64,
    /// The expression being watched (e.g. variable name, address).
    pub expression: String,
    /// The last known value (hex string or display string).
    pub value: Option<String>,
    /// The data type of the watched value.
    pub data_type: Option<String>,
    /// Whether this watch is currently enabled.
    pub enabled: bool,
}

impl WatchEntry {
    /// Create a new watch entry.
    pub fn new(id: u64, expression: impl Into<String>) -> Self {
        Self {
            id,
            expression: expression.into(),
            value: None,
            data_type: None,
            enabled: true,
        }
    }

    /// Update the value.
    pub fn set_value(&mut self, value: impl Into<String>) {
        self.value = Some(value.into());
    }
}

/// A breakpoint specification used by the breakpoint service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointSpecEntry {
    /// Unique ID.
    pub id: u64,
    /// The expression (address or symbol).
    pub expression: String,
    /// Whether the breakpoint is enabled.
    pub enabled: bool,
    /// The kinds (Read, Write, Execute).
    pub kinds: Vec<String>,
    /// Number of times to hit before breaking (0 = always).
    pub hit_count: u64,
}

impl BreakpointSpecEntry {
    /// Create a new breakpoint spec.
    pub fn new(id: u64, expression: impl Into<String>) -> Self {
        Self {
            id,
            expression: expression.into(),
            enabled: true,
            kinds: vec!["Execute".to_string()],
            hit_count: 0,
        }
    }
}

/// A managed emulator configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedEmulatorConfig {
    /// The trace ID to emulate.
    pub trace_id: String,
    /// The snap to start emulating from.
    pub start_snap: i64,
    /// Maximum number of steps.
    pub max_steps: u64,
    /// Timeout in milliseconds.
    pub timeout_ms: u64,
    /// Whether to use hardware breakpoints.
    pub use_hw_breakpoints: bool,
}

impl ManagedEmulatorConfig {
    /// Create a new emulator config.
    pub fn new(trace_id: impl Into<String>, start_snap: i64) -> Self {
        Self {
            trace_id: trace_id.into(),
            start_snap,
            max_steps: 10000,
            timeout_ms: 30000,
            use_hw_breakpoints: false,
        }
    }
}

/// The result of an emulation run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulationRunResult {
    /// The schedule that was emulated.
    pub schedule: String,
    /// The snap where the emulated state is stored.
    pub snapshot: i64,
    /// The final execution state.
    pub final_state: DebuggerExecutionState,
    /// Number of steps executed.
    pub steps_executed: u64,
    /// Error message, if any.
    pub error: Option<String>,
}

impl EmulationRunResult {
    /// Create a successful result.
    pub fn success(schedule: impl Into<String>, snapshot: i64, steps: u64) -> Self {
        Self {
            schedule: schedule.into(),
            snapshot,
            final_state: DebuggerExecutionState::Stopped,
            steps_executed: steps,
            error: None,
        }
    }

    /// Create an error result.
    pub fn error(
        schedule: impl Into<String>,
        snapshot: i64,
        error: impl Into<String>,
    ) -> Self {
        Self {
            schedule: schedule.into(),
            snapshot,
            final_state: DebuggerExecutionState::Error,
            steps_executed: 0,
            error: Some(error.into()),
        }
    }
}

/// An auto-mapping specification for static-to-trace mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoMappingSpec {
    /// The program URL to map from.
    pub program_url: String,
    /// The trace ID to map to.
    pub trace_id: String,
    /// The snap at which to apply the mapping.
    pub snap: i64,
    /// The trace address range start.
    pub trace_min_addr: u64,
    /// The trace address range end.
    pub trace_max_addr: u64,
    /// The program address range start.
    pub program_min_addr: u64,
}

impl AutoMappingSpec {
    /// Create a new auto-mapping spec.
    pub fn new(
        program_url: impl Into<String>,
        trace_id: impl Into<String>,
        snap: i64,
    ) -> Self {
        Self {
            program_url: program_url.into(),
            trace_id: trace_id.into(),
            snap,
            trace_min_addr: 0,
            trace_max_addr: 0,
            program_min_addr: 0,
        }
    }
}

/// Progress callback interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressInfo {
    /// The current progress message.
    pub message: String,
    /// The current progress value.
    pub current: u64,
    /// The maximum progress value (0 = indeterminate).
    pub maximum: u64,
    /// Whether cancellation was requested.
    pub cancelled: bool,
}

impl ProgressInfo {
    /// Create a new progress info.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            current: 0,
            maximum: 0,
            cancelled: false,
        }
    }

    /// Create a determinate progress info.
    pub fn determinate(message: impl Into<String>, current: u64, maximum: u64) -> Self {
        Self {
            message: message.into(),
            current,
            maximum,
            cancelled: false,
        }
    }

    /// Progress percentage (if determinate).
    pub fn percentage(&self) -> Option<f64> {
        if self.maximum > 0 {
            Some((self.current as f64 / self.maximum as f64) * 100.0)
        } else {
            None
        }
    }
}

/// A listing integration action context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListingActionContext {
    /// The trace ID.
    pub trace_id: String,
    /// The address of the action.
    pub address: u64,
    /// The address space.
    pub space: String,
    /// The snap.
    pub snap: i64,
    /// Whether the selection is a range.
    pub is_range: bool,
    /// The selection start (if range).
    pub range_start: Option<u64>,
    /// The selection end (if range).
    pub range_end: Option<u64>,
}

impl ListingActionContext {
    /// Create a point context.
    pub fn point(trace_id: impl Into<String>, space: impl Into<String>, addr: u64, snap: i64) -> Self {
        Self {
            trace_id: trace_id.into(),
            address: addr,
            space: space.into(),
            snap,
            is_range: false,
            range_start: None,
            range_end: None,
        }
    }

    /// Create a range context.
    pub fn range(
        trace_id: impl Into<String>,
        space: impl Into<String>,
        start: u64,
        end: u64,
        snap: i64,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            address: start,
            space: space.into(),
            snap,
            is_range: true,
            range_start: Some(start),
            range_end: Some(end),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_console_message() {
        let msg = ConsoleMessage::info("Hello", "TestPlugin");
        assert_eq!(msg.level, ConsoleOutputLevel::Info);
    }

    #[test]
    fn test_watch_entry() {
        let mut w = WatchEntry::new(1, "RAX");
        w.set_value("0x0000000000401000");
        assert_eq!(w.value.as_deref(), Some("0x0000000000401000"));
    }

    #[test]
    fn test_emulation_result() {
        let r = EmulationRunResult::success("step(5)", 10, 5);
        assert_eq!(r.steps_executed, 5);
        assert_eq!(r.final_state, DebuggerExecutionState::Stopped);
    }

    #[test]
    fn test_progress_info() {
        let p = ProgressInfo::determinate("Loading", 50, 100);
        assert_eq!(p.percentage(), Some(50.0));
    }

    #[test]
    fn test_breakpoint_spec() {
        let bp = BreakpointSpecEntry::new(1, "0x400000");
        assert!(bp.enabled);
        assert_eq!(bp.kinds, vec!["Execute".to_string()]);
    }

    #[test]
    fn test_listing_action_context() {
        let ctx = ListingActionContext::point("trace1", "ram", 0x400000, 0);
        assert!(!ctx.is_range);
        let ctx = ListingActionContext::range("trace1", "ram", 0x400000, 0x400fff, 0);
        assert!(ctx.is_range);
    }
}
