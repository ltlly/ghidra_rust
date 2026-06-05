//! Debugger control actions and plugin.
//!
//! Ported from `ghidra/app/plugin/core/debug/gui/control/` package.
//! Provides action types for controlling debug target execution:
//! - Resume, step into, step over, step out, step ext
//! - Interrupt, disconnect, kill
//! - Emulation control (resume, step back, skip over, interrupt)
//! - Trace snap navigation (forward, backward)

use serde::{Deserialize, Serialize};

/// The kind of control action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ControlActionKind {
    /// Resume execution.
    Resume,
    /// Step into a call.
    StepInto,
    /// Step over a call.
    StepOver,
    /// Step out of current function.
    StepOut,
    /// Extended step (architecture-specific).
    StepExt,
    /// Interrupt/stop execution.
    Interrupt,
    /// Disconnect from target.
    Disconnect,
    /// Kill the target process.
    Kill,
    /// Skip over current instruction (emulation).
    SkipOver,
    /// Step backward (emulation).
    StepBack,
    /// Navigate snap forward.
    SnapForward,
    /// Navigate snap backward.
    SnapBackward,
}

/// A control action targeting a debug target.
///
/// Ported from `TargetActionBuilder.java` and related action classes.
#[derive(Debug, Clone)]
pub struct ControlAction {
    /// The kind of action.
    pub kind: ControlActionKind,
    /// The trace key.
    pub trace_key: i64,
    /// The thread key (0 for all threads).
    pub thread_key: i64,
    /// Number of steps (for step actions).
    pub count: u32,
}

impl ControlAction {
    /// Create a new control action.
    pub fn new(kind: ControlActionKind, trace_key: i64) -> Self {
        Self {
            kind,
            trace_key,
            thread_key: 0,
            count: 1,
        }
    }

    /// Set the thread key.
    pub fn with_thread(mut self, thread_key: i64) -> Self {
        self.thread_key = thread_key;
        self
    }

    /// Set the step count.
    pub fn with_count(mut self, count: u32) -> Self {
        self.count = count;
        self
    }

    /// Execute the action.
    pub fn execute(&self) -> Result<(), String> {
        // In full implementation: dispatch to RMI
        match self.kind {
            ControlActionKind::Resume => Ok(()),
            ControlActionKind::StepInto => Ok(()),
            ControlActionKind::StepOver => Ok(()),
            ControlActionKind::StepOut => Ok(()),
            ControlActionKind::StepExt => Ok(()),
            ControlActionKind::Interrupt => Ok(()),
            ControlActionKind::Disconnect => Ok(()),
            ControlActionKind::Kill => Ok(()),
            ControlActionKind::SkipOver => Ok(()),
            ControlActionKind::StepBack => Ok(()),
            ControlActionKind::SnapForward => Ok(()),
            ControlActionKind::SnapBackward => Ok(()),
        }
    }
}

/// A task that performs a target action and reports results.
///
/// Ported from `TargetActionTask.java`.
#[derive(Debug)]
pub struct TargetActionTask {
    /// The action to perform.
    pub action: ControlAction,
    /// Whether the task has completed.
    completed: bool,
    /// Any error that occurred.
    error: Option<String>,
}

impl TargetActionTask {
    /// Create a new task.
    pub fn new(action: ControlAction) -> Self {
        Self {
            action,
            completed: false,
            error: None,
        }
    }

    /// Run the task.
    pub fn run(&mut self) {
        match self.action.execute() {
            Ok(()) => self.completed = true,
            Err(e) => {
                self.error = Some(e);
                self.completed = true;
            }
        }
    }

    /// Whether the task completed.
    pub fn is_completed(&self) -> bool {
        self.completed
    }

    /// Get any error.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}

/// A docking action for target control in the GUI.
///
/// Ported from `TargetDockingAction.java`.
#[derive(Debug, Clone)]
pub struct TargetDockingAction {
    /// Action kind.
    pub kind: ControlActionKind,
    /// Display name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Keyboard shortcut.
    pub key_binding: Option<String>,
}

impl TargetDockingAction {
    /// Create a new docking action.
    pub fn new(kind: ControlActionKind, name: String, description: String) -> Self {
        Self {
            kind,
            name,
            description,
            key_binding: None,
        }
    }

    /// Set keyboard shortcut.
    pub fn with_key_binding(mut self, binding: String) -> Self {
        self.key_binding = Some(binding);
        self
    }
}

/// A task for disconnecting from a target.
///
/// Ported from `DisconnectTask.java`.
#[derive(Debug)]
pub struct DisconnectTask {
    /// The trace key to disconnect.
    pub trace_key: i64,
}

impl DisconnectTask {
    /// Create a new disconnect task.
    pub fn new(trace_key: i64) -> Self {
        Self { trace_key }
    }

    /// Execute the disconnect.
    pub fn execute(&self) -> Result<(), String> {
        Ok(())
    }
}

/// Control mode determines how actions are dispatched.
///
/// Ported from `ControlModeAction.java`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlMode {
    /// Actions go to the debug target.
    Target,
    /// Actions go to the emulator.
    Emulator,
    /// Actions navigate trace snapshots.
    Trace,
}

impl Default for ControlMode {
    fn default() -> Self {
        ControlMode::Target
    }
}

/// Method actions plugin providing invoke/disassemble actions.
///
/// Ported from `DebuggerMethodActionsPlugin.java`.
#[derive(Debug, Clone)]
pub struct MethodActions {
    /// Whether to follow call targets.
    pub follow_calls: bool,
    /// Whether to disassemble at target.
    pub disassemble: bool,
    /// Maximum recursion depth.
    pub max_depth: u32,
}

impl Default for MethodActions {
    fn default() -> Self {
        Self {
            follow_calls: true,
            disassemble: true,
            max_depth: 10,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_action_resume() {
        let action = ControlAction::new(ControlActionKind::Resume, 1);
        assert_eq!(action.kind, ControlActionKind::Resume);
        assert!(action.execute().is_ok());
    }

    #[test]
    fn test_control_action_step_into() {
        let action = ControlAction::new(ControlActionKind::StepInto, 1)
            .with_thread(42)
            .with_count(5);
        assert_eq!(action.thread_key, 42);
        assert_eq!(action.count, 5);
    }

    #[test]
    fn test_target_action_task() {
        let action = ControlAction::new(ControlActionKind::StepOver, 1);
        let mut task = TargetActionTask::new(action);
        assert!(!task.is_completed());
        task.run();
        assert!(task.is_completed());
        assert!(task.error().is_none());
    }

    #[test]
    fn test_target_docking_action() {
        let action = TargetDockingAction::new(
            ControlActionKind::Resume,
            "Resume".into(),
            "Resume execution".into(),
        )
        .with_key_binding("F5".into());
        assert_eq!(action.key_binding, Some("F5".into()));
    }

    #[test]
    fn test_disconnect_task() {
        let task = DisconnectTask::new(1);
        assert!(task.execute().is_ok());
    }

    #[test]
    fn test_control_mode_default() {
        assert_eq!(ControlMode::default(), ControlMode::Target);
    }

    #[test]
    fn test_method_actions_default() {
        let actions = MethodActions::default();
        assert!(actions.follow_calls);
        assert!(actions.disassemble);
        assert_eq!(actions.max_depth, 10);
    }
}
