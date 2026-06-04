//! Target - the interface between UI and the back-end connector.
//!
//! Ported from Ghidra's `Target` interface. Anything the UI might command a
//! target to do must be defined here.

use super::action_name::ActionName;
use crate::model::{BreakpointKindSet, TraceExecutionState, TraceMemoryState};
use crate::target::KeyPath;

/// A description of a UI action provided by this target.
#[derive(Debug, Clone)]
pub struct ActionEntry {
    /// The text to display on UI actions.
    pub display: String,
    /// The name of the common debugger command.
    pub name: ActionName,
    /// Whether this action is currently enabled.
    pub enabled: bool,
}

/// An argument policy for object arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectArgumentPolicy {
    /// No arguments.
    None,
    /// A single object argument.
    Single,
    /// Multiple object arguments.
    Multiple,
}

/// The result of collecting actions.
#[derive(Debug, Clone)]
pub struct ActionResult {
    /// The action entry.
    pub entry: ActionEntry,
    /// Optional path argument.
    pub path_arg: Option<KeyPath>,
}

/// The interface between the front-end UI and the back-end connector.
///
/// Anything the UI might command a target to do must be defined as a method
/// on this trait. Each implementation sorts out how to effect the command
/// using the protocol and resources available on the back-end.
pub trait Target {
    /// The timeout for operations, in milliseconds.
    const TIMEOUT_MILLIS: u64 = 10_000;

    // ── Connection lifecycle ──────────────────────────────────────

    /// Terminate the target and its connection.
    fn disconnect(&mut self) -> Result<(), String>;

    /// Forcefully terminate the target.
    fn force_terminate(&mut self) -> Result<(), String>;

    /// Check if the target is busy updating the trace.
    fn is_busy(&self) -> bool;

    /// Forcibly commit all of the back-end's transactions.
    fn forcibly_close_transactions(&mut self);

    // ── Execution control ─────────────────────────────────────────

    /// Resume / continue execution.
    fn resume(&mut self) -> Result<(), String>;

    /// Single-step execution.
    fn step(&mut self, thread_key: Option<i64>) -> Result<(), String>;

    /// Step into a call.
    fn step_into(&mut self, thread_key: Option<i64>) -> Result<(), String>;

    /// Step over a call.
    fn step_over(&mut self, thread_key: Option<i64>) -> Result<(), String>;

    /// Step out of the current function.
    fn step_out(&mut self, thread_key: Option<i64>) -> Result<(), String>;

    // ── Memory access ─────────────────────────────────────────────

    /// Read memory from the target and record it into the trace.
    fn read_memory(
        &mut self,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, String>;

    /// Write data to the target's memory.
    fn write_memory(&mut self, offset: u64, data: &[u8]) -> Result<(), String>;

    // ── Register access ───────────────────────────────────────────

    /// Read registers for the given thread and frame.
    fn read_registers(
        &mut self,
        thread_key: i64,
        frame: i32,
        register_names: &[String],
    ) -> Result<Vec<(String, Vec<u8>)>, String>;

    /// Write a register value.
    fn write_register(
        &mut self,
        thread_key: i64,
        register_name: &str,
        value: &[u8],
    ) -> Result<(), String>;

    // ── Breakpoints ───────────────────────────────────────────────

    /// Add a breakpoint at the given address.
    fn add_breakpoint(
        &mut self,
        offset: u64,
        kinds: &BreakpointKindSet,
    ) -> Result<(), String>;

    /// Toggle a breakpoint's enabled state.
    fn toggle_breakpoint(
        &mut self,
        path: &str,
        enabled: bool,
    ) -> Result<(), String>;

    /// Delete a breakpoint.
    fn delete_breakpoint(&mut self, path: &str) -> Result<(), String>;

    // ── State query ───────────────────────────────────────────────

    /// Get the execution state of a thread.
    fn execution_state(&self, thread_key: i64) -> TraceExecutionState;

    /// Get the memory state at the given offset.
    fn memory_state(&self, offset: u64) -> TraceMemoryState;

    /// Get available actions for the current context.
    fn collect_actions(&self) -> Vec<ActionEntry>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::TraceBreakpointKind;

    struct MockTarget {
        connected: bool,
    }

    impl MockTarget {
        fn new() -> Self {
            Self { connected: true }
        }
    }

    impl Target for MockTarget {
        fn disconnect(&mut self) -> Result<(), String> {
            self.connected = false;
            Ok(())
        }

        fn force_terminate(&mut self) -> Result<(), String> {
            self.connected = false;
            Ok(())
        }

        fn is_busy(&self) -> bool {
            false
        }

        fn forcibly_close_transactions(&mut self) {}

        fn resume(&mut self) -> Result<(), String> {
            Ok(())
        }

        fn step(&mut self, _: Option<i64>) -> Result<(), String> {
            Ok(())
        }

        fn step_into(&mut self, _: Option<i64>) -> Result<(), String> {
            Ok(())
        }

        fn step_over(&mut self, _: Option<i64>) -> Result<(), String> {
            Ok(())
        }

        fn step_out(&mut self, _: Option<i64>) -> Result<(), String> {
            Ok(())
        }

        fn read_memory(&mut self, _offset: u64, _length: u64) -> Result<Vec<u8>, String> {
            Ok(vec![0u8; 16])
        }

        fn write_memory(&mut self, _offset: u64, _data: &[u8]) -> Result<(), String> {
            Ok(())
        }

        fn read_registers(
            &mut self,
            _thread_key: i64,
            _frame: i32,
            _register_names: &[String],
        ) -> Result<Vec<(String, Vec<u8>)>, String> {
            Ok(vec![])
        }

        fn write_register(
            &mut self,
            _thread_key: i64,
            _register_name: &str,
            _value: &[u8],
        ) -> Result<(), String> {
            Ok(())
        }

        fn add_breakpoint(
            &mut self,
            _offset: u64,
            _kinds: &BreakpointKindSet,
        ) -> Result<(), String> {
            Ok(())
        }

        fn toggle_breakpoint(&mut self, _path: &str, _enabled: bool) -> Result<(), String> {
            Ok(())
        }

        fn delete_breakpoint(&mut self, _path: &str) -> Result<(), String> {
            Ok(())
        }

        fn execution_state(&self, _thread_key: i64) -> TraceExecutionState {
            TraceExecutionState::Running
        }

        fn memory_state(&self, _offset: u64) -> TraceMemoryState {
            TraceMemoryState::Known
        }

        fn collect_actions(&self) -> Vec<ActionEntry> {
            vec![ActionEntry {
                display: "Resume".into(),
                name: ActionName::Continue,
                enabled: self.connected,
            }]
        }
    }

    #[test]
    fn test_mock_target_lifecycle() {
        let mut target = MockTarget::new();
        assert!(!target.is_busy());
        assert!(target.disconnect().is_ok());
        assert!(target.collect_actions().iter().all(|a| !a.enabled));
    }

    #[test]
    fn test_mock_target_memory() {
        let mut target = MockTarget::new();
        let data = target.read_memory(0x100, 16).unwrap();
        assert_eq!(data.len(), 16);
        assert!(target.write_memory(0x100, &[1, 2, 3]).is_ok());
    }

    #[test]
    fn test_mock_target_breakpoint() {
        let mut target = MockTarget::new();
        let kinds: BreakpointKindSet = [TraceBreakpointKind::HwExecute].into_iter().collect();
        assert!(target.add_breakpoint(0x400000, &kinds).is_ok());
        assert!(target.toggle_breakpoint("bp1", false).is_ok());
    }

    #[test]
    fn test_mock_target_state() {
        let target = MockTarget::new();
        assert_eq!(target.execution_state(1), TraceExecutionState::Running);
        assert_eq!(target.memory_state(0), TraceMemoryState::Known);
    }
}
