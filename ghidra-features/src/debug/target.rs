//! Target API for the Debug framework.
//!
//! Ported from `ghidra.debug.api.target.Target` — the interface between the
//! front-end UI and the back-end debugger connector. Anything the UI might
//! command a target to do is defined here.

use std::collections::HashMap;
use std::fmt;

use super::action_name::ActionName;
use super::breakpoint::TraceBreakpointKind;
use super::core_types::TraceExecutionState;

// ---------------------------------------------------------------------------
// TargetError
// ---------------------------------------------------------------------------

/// Errors that can occur when interacting with a debug target.
#[derive(Debug, Clone)]
pub enum TargetError {
    /// The target is no longer valid.
    InvalidTarget,
    /// The operation timed out.
    Timeout,
    /// The operation was cancelled.
    Cancelled,
    /// A memory access error occurred.
    MemoryError(String),
    /// The requested action is not supported.
    UnsupportedAction(String),
    /// A generic error with a message.
    Other(String),
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetError::InvalidTarget => write!(f, "Invalid target"),
            TargetError::Timeout => write!(f, "Operation timed out"),
            TargetError::Cancelled => write!(f, "Operation cancelled"),
            TargetError::MemoryError(msg) => write!(f, "Memory error: {msg}"),
            TargetError::UnsupportedAction(name) => {
                write!(f, "Unsupported action: {name}")
            }
            TargetError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for TargetError {}

// ---------------------------------------------------------------------------
// ActionResult
// ---------------------------------------------------------------------------

/// The result of invoking a target action.
#[derive(Debug, Clone)]
pub struct ActionResult {
    /// Whether the action succeeded.
    pub success: bool,
    /// An optional message (e.g., error message or output).
    pub message: Option<String>,
    /// An optional result value (e.g., command output).
    pub output: Option<String>,
}

impl ActionResult {
    /// A successful action with no message.
    pub fn ok() -> Self {
        Self {
            success: true,
            message: None,
            output: None,
        }
    }

    /// A successful action with output.
    pub fn with_output(output: impl Into<String>) -> Self {
        Self {
            success: true,
            message: None,
            output: Some(output.into()),
        }
    }

    /// A failed action with an error message.
    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            message: Some(msg.into()),
            output: None,
        }
    }
}

// ---------------------------------------------------------------------------
// ActionEntry
// ---------------------------------------------------------------------------

/// A description of a UI action provided by a target.
///
/// Ported from `Target.ActionEntry`.
#[derive(Debug, Clone)]
pub struct ActionEntry {
    /// The display text for this action.
    display: String,
    /// The common debugger action name.
    pub action_name: ActionName,
    /// More detailed description (tooltip).
    details: String,
    /// Whether invoking the action requires further user interaction.
    pub requires_prompt: bool,
    /// A relative score of specificity.
    pub specificity: u64,
    /// Whether this action is currently enabled.
    pub enabled: bool,
}

impl ActionEntry {
    /// Create a new action entry.
    pub fn new(display: impl Into<String>, action_name: ActionName) -> Self {
        Self {
            display: display.into(),
            action_name,
            details: String::new(),
            requires_prompt: false,
            specificity: 0,
            enabled: true,
        }
    }

    /// Set the details text.
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = details.into();
        self
    }

    /// Set whether this action requires prompting.
    pub fn with_prompt(mut self, requires_prompt: bool) -> Self {
        self.requires_prompt = requires_prompt;
        self
    }

    /// Set the specificity score.
    pub fn with_specificity(mut self, specificity: u64) -> Self {
        self.specificity = specificity;
        self
    }

    /// Set whether this action is enabled.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Get the display text.
    pub fn display(&self) -> &str {
        &self.display
    }

    /// Get the details text.
    pub fn details(&self) -> &str {
        &self.details
    }
}

// ---------------------------------------------------------------------------
// Target trait
// ---------------------------------------------------------------------------

/// The interface between the front-end UI and the back-end connector.
///
/// Ported from `ghidra.debug.api.target.Target`. Anything the UI might
/// command a target to do must be defined as a method here. Each
/// implementation can then sort out, using context from the UI, how to
/// effect the command using the protocol and resources available on the
/// back-end.
pub trait Target: Send + Sync {
    /// Describe the target for display in the UI.
    fn describe(&self) -> String;

    /// Check if the target is still valid.
    fn is_valid(&self) -> bool;

    /// Get the current snapshot key for the target.
    fn get_snap(&self) -> i64;

    /// Execute a CLI command on the target.
    ///
    /// Returns the captured output, or `None` if `capture` is false.
    fn execute(&self, command: &str, capture: bool) -> Result<Option<String>, TargetError>;

    /// Get the execution state of the target's main thread.
    fn get_execution_state(&self) -> TraceExecutionState;

    /// Check if the target is busy updating the trace.
    fn is_busy(&self) -> bool;

    /// Check if the target supports focus synchronization.
    fn supports_focus(&self) -> bool {
        false
    }

    /// Get the kinds of breakpoints supported by the target.
    fn supported_breakpoint_kinds(&self) -> Vec<TraceBreakpointKind> {
        vec![
            TraceBreakpointKind::SwExecute,
            TraceBreakpointKind::HwExecute,
        ]
    }

    /// Read memory from the target at the given address.
    fn read_memory(&self, address: u64, len: usize) -> Result<Vec<u8>, TargetError>;

    /// Write memory to the target at the given address.
    fn write_memory(&self, address: u64, data: &[u8]) -> Result<(), TargetError>;

    /// Read a register value by name.
    fn read_register(&self, name: &str) -> Result<Vec<u8>, TargetError>;

    /// Write a register value by name.
    fn write_register(&self, name: &str, data: &[u8]) -> Result<(), TargetError>;

    /// Place a breakpoint at the given address range.
    fn place_breakpoint(
        &self,
        address: u64,
        length: u64,
        kinds: &[TraceBreakpointKind],
    ) -> Result<u64, TargetError>;

    /// Delete a breakpoint by its ID.
    fn delete_breakpoint(&self, bp_id: u64) -> Result<(), TargetError>;

    /// Toggle a breakpoint (enable/disable).
    fn toggle_breakpoint(&self, bp_id: u64, enabled: bool) -> Result<(), TargetError>;

    /// Forcefully terminate the target.
    fn force_terminate(&self) -> Result<(), TargetError>;

    /// Disconnect from the target.
    fn disconnect(&self) -> Result<(), TargetError>;

    /// Collect all actions that implement the given action name.
    fn collect_actions(&self, name: &ActionName) -> HashMap<String, ActionEntry> {
        HashMap::new()
    }

    /// Forcibly close all transactions on the target's trace.
    fn forcibly_close_transactions(&self) {}
}

// ---------------------------------------------------------------------------
// ObjectArgumentPolicy
// ---------------------------------------------------------------------------

/// Specifies how object arguments are derived when collecting actions.
///
/// Ported from `Target.ObjectArgumentPolicy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectArgumentPolicy {
    /// The object should be taken exactly from the action context.
    ContextOnly,
    /// The object should be taken from the current (active) object in the tool,
    /// or a suitable relative having the correct schema.
    CurrentAndRelated,
    /// The object can be taken from the context or the current object.
    EitherAndRelated,
}

impl ObjectArgumentPolicy {
    /// Returns `true` if the context object is allowed.
    pub fn allow_context_object(&self) -> bool {
        matches!(
            self,
            ObjectArgumentPolicy::ContextOnly | ObjectArgumentPolicy::EitherAndRelated
        )
    }

    /// Returns `true` if the current coordinates object is allowed.
    pub fn allow_coords_object(&self) -> bool {
        matches!(
            self,
            ObjectArgumentPolicy::CurrentAndRelated | ObjectArgumentPolicy::EitherAndRelated
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct MockTarget {
        valid: bool,
        snap: i64,
        state: TraceExecutionState,
    }

    impl MockTarget {
        fn new() -> Self {
            Self {
                valid: true,
                snap: 0,
                state: TraceExecutionState::Stopped,
            }
        }
    }

    impl Target for MockTarget {
        fn describe(&self) -> String {
            "Mock Target".to_string()
        }
        fn is_valid(&self) -> bool {
            self.valid
        }
        fn get_snap(&self) -> i64 {
            self.snap
        }
        fn execute(&self, command: &str, capture: bool) -> Result<Option<String>, TargetError> {
            if capture {
                Ok(Some(format!("echo: {command}")))
            } else {
                Ok(None)
            }
        }
        fn get_execution_state(&self) -> TraceExecutionState {
            self.state
        }
        fn is_busy(&self) -> bool {
            false
        }
        fn read_memory(&self, _address: u64, len: usize) -> Result<Vec<u8>, TargetError> {
            Ok(vec![0u8; len])
        }
        fn write_memory(&self, _address: u64, _data: &[u8]) -> Result<(), TargetError> {
            Ok(())
        }
        fn read_register(&self, _name: &str) -> Result<Vec<u8>, TargetError> {
            Ok(vec![0u8; 8])
        }
        fn write_register(&self, _name: &str, _data: &[u8]) -> Result<(), TargetError> {
            Ok(())
        }
        fn place_breakpoint(
            &self,
            _address: u64,
            _length: u64,
            _kinds: &[TraceBreakpointKind],
        ) -> Result<u64, TargetError> {
            Ok(1)
        }
        fn delete_breakpoint(&self, _bp_id: u64) -> Result<(), TargetError> {
            Ok(())
        }
        fn toggle_breakpoint(&self, _bp_id: u64, _enabled: bool) -> Result<(), TargetError> {
            Ok(())
        }
        fn force_terminate(&self) -> Result<(), TargetError> {
            Ok(())
        }
        fn disconnect(&self) -> Result<(), TargetError> {
            Ok(())
        }
    }

    #[test]
    fn test_mock_target_basic() {
        let target = MockTarget::new();
        assert_eq!(target.describe(), "Mock Target");
        assert!(target.is_valid());
        assert_eq!(target.get_snap(), 0);
        assert_eq!(target.get_execution_state(), TraceExecutionState::Stopped);
        assert!(!target.is_busy());
    }

    #[test]
    fn test_mock_target_execute() {
        let target = MockTarget::new();
        let result = target.execute("help", true).unwrap();
        assert_eq!(result, Some("echo: help".to_string()));

        let result2 = target.execute("run", false).unwrap();
        assert_eq!(result2, None);
    }

    #[test]
    fn test_mock_target_memory() {
        let target = MockTarget::new();
        target.write_memory(0x1000, &[0xAA, 0xBB]).unwrap();
        let data = target.read_memory(0x1000, 2).unwrap();
        assert_eq!(data, vec![0, 0]); // Mock returns zeros
    }

    #[test]
    fn test_mock_target_breakpoint() {
        let target = MockTarget::new();
        let bp_id = target
            .place_breakpoint(0x400000, 1, &[TraceBreakpointKind::SwExecute])
            .unwrap();
        assert_eq!(bp_id, 1);
        target.toggle_breakpoint(bp_id, false).unwrap();
        target.delete_breakpoint(bp_id).unwrap();
    }

    #[test]
    fn test_action_result() {
        let ok = ActionResult::ok();
        assert!(ok.success);
        assert!(ok.message.is_none());

        let err = ActionResult::error("something went wrong");
        assert!(!err.success);
        assert_eq!(err.message.as_deref(), Some("something went wrong"));

        let out = ActionResult::with_output("result");
        assert!(out.success);
        assert_eq!(out.output.as_deref(), Some("result"));
    }

    #[test]
    fn test_object_argument_policy() {
        assert!(ObjectArgumentPolicy::ContextOnly.allow_context_object());
        assert!(!ObjectArgumentPolicy::ContextOnly.allow_coords_object());
        assert!(ObjectArgumentPolicy::CurrentAndRelated.allow_coords_object());
        assert!(!ObjectArgumentPolicy::CurrentAndRelated.allow_context_object());
        assert!(ObjectArgumentPolicy::EitherAndRelated.allow_context_object());
        assert!(ObjectArgumentPolicy::EitherAndRelated.allow_coords_object());
    }

    #[test]
    fn test_target_error_display() {
        assert_eq!(
            format!("{}", TargetError::InvalidTarget),
            "Invalid target"
        );
        assert_eq!(format!("{}", TargetError::Timeout), "Operation timed out");
        assert_eq!(
            format!("{}", TargetError::MemoryError("page fault".into())),
            "Memory error: page fault"
        );
    }

    #[test]
    fn test_supported_breakpoint_kinds() {
        let target = MockTarget::new();
        let kinds = target.supported_breakpoint_kinds();
        assert!(kinds.contains(&TraceBreakpointKind::SwExecute));
        assert!(kinds.contains(&TraceBreakpointKind::HwExecute));
    }
}
