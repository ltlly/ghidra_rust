//! Target action task framework and concrete control action implementations.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.control` package.
//! Provides the task infrastructure for executing target actions (resume, step,
//! interrupt, kill, disconnect) and the control mode action for selecting what
//! to control in dynamic views.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::api::tracemgr::DebuggerCoordinates;
use crate::api::control_mode::ControlMode;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default timeout for target action execution (30 seconds).
pub const DEFAULT_ACTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Long timeout for target action execution (5 minutes).
pub const LONG_ACTION_TIMEOUT: Duration = Duration::from_secs(300);

// ---------------------------------------------------------------------------
// TargetActionKind -- the kind of control action to execute
// ---------------------------------------------------------------------------

/// The kind of target control action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetActionKind {
    /// Resume execution.
    Resume,
    /// Step into a function call.
    StepInto,
    /// Step over a function call.
    StepOver,
    /// Step out of the current function.
    StepOut,
    /// Step one instruction.
    StepExt,
    /// Interrupt the running target.
    Interrupt,
    /// Kill the target process.
    Kill,
    /// Disconnect from the target.
    Disconnect,
    /// Navigate to previous snapshot.
    SnapBackward,
    /// Navigate to next snapshot.
    SnapForward,
    /// Send an interrupt signal to the target.
    SignalInterrupt,
    /// Step back (reverse execution).
    StepBack,
    /// Skip over the current instruction.
    SkipOver,
}

impl TargetActionKind {
    /// Returns a human-readable display name for this action kind.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Resume => "Resume",
            Self::StepInto => "Step Into",
            Self::StepOver => "Step Over",
            Self::StepOut => "Step Out",
            Self::StepExt => "Step Instruction",
            Self::Interrupt => "Interrupt",
            Self::Kill => "Kill",
            Self::Disconnect => "Disconnect",
            Self::SnapBackward => "Snap Backward",
            Self::SnapForward => "Snap Forward",
            Self::SignalInterrupt => "Signal Interrupt",
            Self::StepBack => "Step Back",
            Self::SkipOver => "Skip Over",
        }
    }

    /// Whether this action causes the target to execute (resume, step variants).
    pub fn is_execution_action(&self) -> bool {
        matches!(
            self,
            Self::Resume
                | Self::StepInto
                | Self::StepOver
                | Self::StepOut
                | Self::StepExt
                | Self::StepBack
                | Self::SkipOver
        )
    }

    /// Whether this action stops execution.
    pub fn is_stopping_action(&self) -> bool {
        matches!(self, Self::Interrupt | Self::Kill)
    }

    /// Whether this action navigates time.
    pub fn is_navigation_action(&self) -> bool {
        matches!(self, Self::SnapBackward | Self::SnapForward)
    }

    /// Returns the sub-group ordering string for toolbar placement.
    pub fn sub_group(&self) -> &'static str {
        match self {
            Self::Resume => "01",
            Self::Interrupt => "01",
            Self::Kill => "02",
            Self::Disconnect => "03",
            Self::StepInto => "10",
            Self::StepOver => "11",
            Self::StepOut => "12",
            Self::StepExt => "13",
            Self::StepBack => "14",
            Self::SkipOver => "15",
            Self::SnapBackward => "20",
            Self::SnapForward => "21",
            Self::SignalInterrupt => "01",
        }
    }
}

impl fmt::Display for TargetActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ---------------------------------------------------------------------------
// ActionEntry -- a target action to execute
// ---------------------------------------------------------------------------

/// An entry representing a target action to execute on a debug target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionEntry {
    /// The kind of action.
    pub kind: TargetActionKind,
    /// Display text for the action.
    pub display_text: String,
    /// Optional tooltip description.
    pub description: Option<String>,
    /// The target key this action applies to.
    pub target_key: Option<i64>,
    /// Additional parameters for the action.
    pub parameters: HashMap<String, String>,
    /// Whether the action is currently enabled.
    pub enabled: bool,
}

impl ActionEntry {
    /// Create a new action entry.
    pub fn new(kind: TargetActionKind, display_text: impl Into<String>) -> Self {
        Self {
            kind,
            display_text: display_text.into(),
            description: None,
            target_key: None,
            parameters: HashMap::new(),
            enabled: true,
        }
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Set the target key.
    pub fn with_target_key(mut self, key: i64) -> Self {
        self.target_key = Some(key);
        self
    }

    /// Add a parameter.
    pub fn with_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.parameters.insert(key.into(), value.into());
        self
    }

    /// Display string for UI.
    pub fn display(&self) -> &str {
        &self.display_text
    }
}

// ---------------------------------------------------------------------------
// TargetActionTask -- task for executing a target action
// ---------------------------------------------------------------------------

/// A task for executing a target `ActionEntry`.
///
/// This provides the task infrastructure for scheduling target actions,
/// including timeout handling and future-based completion tracking.
#[derive(Debug)]
pub struct TargetActionTask {
    /// The title of this task.
    pub title: String,
    /// The action entry to execute.
    pub entry: ActionEntry,
    /// Whether to enforce a timeout.
    pub timeout: bool,
    /// The timeout duration.
    pub timeout_duration: Duration,
    /// Whether the task can be cancelled.
    pub can_cancel: bool,
    /// Current execution state.
    pub state: ActionTaskState,
    /// Progress (0.0 to 1.0).
    pub progress: f64,
    /// Error message if the task failed.
    pub error: Option<String>,
}

/// The state of a target action task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionTaskState {
    /// Task is pending execution.
    Pending,
    /// Task is currently running.
    Running,
    /// Task completed successfully.
    Completed,
    /// Task was cancelled.
    Cancelled,
    /// Task failed with an error.
    Failed,
    /// Task timed out.
    TimedOut,
}

impl TargetActionTask {
    /// Create a new target action task.
    pub fn new(title: impl Into<String>, entry: ActionEntry) -> Self {
        Self {
            title: title.into(),
            entry,
            timeout: true,
            timeout_duration: DEFAULT_ACTION_TIMEOUT,
            can_cancel: false,
            state: ActionTaskState::Pending,
            progress: 0.0,
            error: None,
        }
    }

    /// Create a task with a custom timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout_duration = timeout;
        self
    }

    /// Create a task that can be cancelled.
    pub fn cancellable(mut self) -> Self {
        self.can_cancel = true;
        self
    }

    /// Mark the task as running.
    pub fn start(&mut self) {
        self.state = ActionTaskState::Running;
        self.progress = 0.0;
    }

    /// Update the progress.
    pub fn set_progress(&mut self, progress: f64) {
        self.progress = progress.clamp(0.0, 1.0);
    }

    /// Mark the task as completed.
    pub fn complete(&mut self) {
        self.state = ActionTaskState::Completed;
        self.progress = 1.0;
    }

    /// Mark the task as cancelled.
    pub fn cancel(&mut self) {
        self.state = ActionTaskState::Cancelled;
    }

    /// Mark the task as failed.
    pub fn fail(&mut self, error: impl Into<String>) {
        self.state = ActionTaskState::Failed;
        self.error = Some(error.into());
    }

    /// Mark the task as timed out.
    pub fn timeout_occurred(&mut self) {
        self.state = ActionTaskState::TimedOut;
    }

    /// Whether the task has reached a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            ActionTaskState::Completed
                | ActionTaskState::Cancelled
                | ActionTaskState::Failed
                | ActionTaskState::TimedOut
        )
    }

    /// Whether the task completed successfully.
    pub fn is_success(&self) -> bool {
        self.state == ActionTaskState::Completed
    }

    /// Get the task title.
    pub fn task_title(&self) -> &str {
        &self.title
    }

    /// Whether the task can be cancelled.
    pub fn can_cancel(&self) -> bool {
        self.can_cancel
    }
}

/// Create a resume action entry.
pub fn resume_action_entry() -> ActionEntry {
    ActionEntry::new(TargetActionKind::Resume, "Resume")
        .with_description("Resume execution of the target")
}

/// Create a step-into action entry.
pub fn step_into_action_entry() -> ActionEntry {
    ActionEntry::new(TargetActionKind::StepInto, "Step Into")
        .with_description("Step into a function call")
}

/// Create a step-over action entry.
pub fn step_over_action_entry() -> ActionEntry {
    ActionEntry::new(TargetActionKind::StepOver, "Step Over")
        .with_description("Step over a function call")
}

/// Create a step-out action entry.
pub fn step_out_action_entry() -> ActionEntry {
    ActionEntry::new(TargetActionKind::StepOut, "Step Out")
        .with_description("Step out of the current function")
}

/// Create an interrupt action entry.
pub fn interrupt_action_entry() -> ActionEntry {
    ActionEntry::new(TargetActionKind::Interrupt, "Interrupt")
        .with_description("Interrupt the running target")
}

/// Create a disconnect action entry.
pub fn disconnect_action_entry() -> ActionEntry {
    ActionEntry::new(TargetActionKind::Disconnect, "Disconnect")
        .with_description("Disconnect from the target")
}

/// Create a kill action entry.
pub fn kill_action_entry() -> ActionEntry {
    ActionEntry::new(TargetActionKind::Kill, "Kill")
        .with_description("Kill the target process")
}

/// Create a snap-backward action entry.
pub fn snap_backward_action_entry() -> ActionEntry {
    ActionEntry::new(TargetActionKind::SnapBackward, "Snap Backward")
        .with_description("Navigate to the previous snapshot")
}

/// Create a snap-forward action entry.
pub fn snap_forward_action_entry() -> ActionEntry {
    ActionEntry::new(TargetActionKind::SnapForward, "Snap Forward")
        .with_description("Navigate to the next snapshot")
}

// ---------------------------------------------------------------------------
// ControlModeAction -- multi-state action for choosing control mode
// ---------------------------------------------------------------------------

/// The state of a control mode action in the toolbar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlModeActionState {
    /// The control mode this state represents.
    pub mode: ControlMode,
    /// Display name for this state (from the mode's label).
    pub name: String,
    /// Whether this state is currently enabled/selectable.
    pub enabled: bool,
}

impl ControlModeActionState {
    /// Create a new control mode action state.
    pub fn new(mode: ControlMode) -> Self {
        Self {
            name: mode.label().to_string(),
            mode,
            enabled: true,
        }
    }
}

/// Multi-state action for choosing what to control and edit in dynamic views.
///
/// This is a toolbar action that cycles through `ControlMode` variants,
/// allowing the user to switch between controlling threads, processes,
/// or the entire target.
#[derive(Debug)]
pub struct ControlModeAction {
    /// The display name.
    pub name: String,
    /// Description.
    pub description: String,
    /// The action group for toolbar placement.
    pub group: String,
    /// All available action states (one per control mode).
    pub states: Vec<ControlModeActionState>,
    /// The index of the currently active state.
    pub current_index: usize,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// Help anchor for documentation.
    pub help_anchor: String,
}

impl ControlModeAction {
    /// Create a new control mode action.
    pub fn new(_plugin_name: impl Into<String>) -> Self {
        let modes = [
            ControlMode::RoTarget,
            ControlMode::RwTarget,
            ControlMode::RoTrace,
            ControlMode::RwTrace,
            ControlMode::RoEmulator,
            ControlMode::RwEmulator,
        ];
        let states = modes
            .into_iter()
            .map(ControlModeActionState::new)
            .collect();

        Self {
            name: "Control Mode".to_string(),
            description: "Choose what to control and edit in dynamic views".to_string(),
            group: "CONTROL".to_string(),
            states,
            current_index: 0,
            enabled: false,
            help_anchor: "control_mode".to_string(),
        }
    }

    /// Get the current control mode.
    pub fn current_mode(&self) -> Option<&ControlMode> {
        self.states.get(self.current_index).map(|s| &s.mode)
    }

    /// Set the current mode index.
    pub fn set_current_index(&mut self, index: usize) {
        if index < self.states.len() {
            self.current_index = index;
        }
    }

    /// Activate the next state in the cycle.
    pub fn cycle_state(&mut self) {
        if !self.states.is_empty() {
            self.current_index = (self.current_index + 1) % self.states.len();
        }
    }

    /// Check if the action should be enabled for the given coordinates.
    pub fn is_enabled_for(&self, current: &DebuggerCoordinates) -> bool {
        current.trace_key.is_some()
    }

    /// Check if a particular state is selectable given whether a target is alive.
    pub fn is_state_selectable(&self, index: usize, is_alive: bool) -> bool {
        self.states
            .get(index)
            .map(|s| s.mode.is_selectable(is_alive))
            .unwrap_or(false)
    }

    /// Enable or disable the action.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

// ---------------------------------------------------------------------------
// SnapshotNavigation -- snap forward/backward navigation
// ---------------------------------------------------------------------------

/// Snapshot navigation state for stepping through trace snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotNavState {
    /// The current snapshot index.
    pub current_index: i64,
    /// The maximum snapshot index.
    pub max_index: i64,
    /// Whether there is a previous snapshot.
    pub has_previous: bool,
    /// Whether there is a next snapshot.
    pub has_next: bool,
}

impl SnapshotNavState {
    /// Create a new snapshot navigation state.
    pub fn new(current_index: i64, max_index: i64) -> Self {
        Self {
            current_index,
            max_index,
            has_previous: current_index > 0,
            has_next: current_index < max_index,
        }
    }

    /// Navigate to the previous snapshot.
    pub fn go_backward(&mut self) -> Option<i64> {
        if self.has_previous {
            self.current_index -= 1;
            self.has_previous = self.current_index > 0;
            self.has_next = self.current_index < self.max_index;
            Some(self.current_index)
        } else {
            None
        }
    }

    /// Navigate to the next snapshot.
    pub fn go_forward(&mut self) -> Option<i64> {
        if self.has_next {
            self.current_index += 1;
            self.has_previous = self.current_index > 0;
            self.has_next = self.current_index < self.max_index;
            Some(self.current_index)
        } else {
            None
        }
    }

    /// Navigate to a specific snapshot.
    pub fn go_to(&mut self, index: i64) -> Option<i64> {
        if index >= 0 && index <= self.max_index {
            self.current_index = index;
            self.has_previous = self.current_index > 0;
            self.has_next = self.current_index < self.max_index;
            Some(self.current_index)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// ControlExecutionState -- tracks the execution state of a debug target
// ---------------------------------------------------------------------------

/// Execution state of a debug target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlExecutionState {
    /// Target is not connected.
    Disconnected,
    /// Target is connected but not running.
    Stopped,
    /// Target is running.
    Running,
    /// Target is in the process of stopping.
    Stopping,
    /// Target has terminated.
    Terminated,
}

impl ControlExecutionState {
    /// Whether the target is in an active state (running or stopping).
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Running | Self::Stopping)
    }

    /// Whether actions that resume execution can be performed.
    pub fn can_resume(&self) -> bool {
        self == &Self::Stopped
    }

    /// Whether an interrupt can be sent.
    pub fn can_interrupt(&self) -> bool {
        self == &Self::Running
    }

    /// Whether a disconnect can be performed.
    pub fn can_disconnect(&self) -> bool {
        matches!(self, Self::Stopped | Self::Running | Self::Stopping)
    }

    /// Display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Disconnected => "Disconnected",
            Self::Stopped => "Stopped",
            Self::Running => "Running",
            Self::Stopping => "Stopping",
            Self::Terminated => "Terminated",
        }
    }
}

impl fmt::Display for ControlExecutionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_action_kind_display() {
        assert_eq!(TargetActionKind::Resume.display_name(), "Resume");
        assert_eq!(TargetActionKind::StepInto.display_name(), "Step Into");
        assert_eq!(TargetActionKind::Interrupt.display_name(), "Interrupt");
        assert_eq!(TargetActionKind::Disconnect.display_name(), "Disconnect");
    }

    #[test]
    fn test_target_action_kind_categories() {
        assert!(TargetActionKind::Resume.is_execution_action());
        assert!(TargetActionKind::StepInto.is_execution_action());
        assert!(TargetActionKind::StepOver.is_execution_action());
        assert!(TargetActionKind::StepOut.is_execution_action());
        assert!(!TargetActionKind::Interrupt.is_execution_action());
        assert!(!TargetActionKind::Disconnect.is_execution_action());

        assert!(TargetActionKind::Interrupt.is_stopping_action());
        assert!(TargetActionKind::Kill.is_stopping_action());
        assert!(!TargetActionKind::Resume.is_stopping_action());

        assert!(TargetActionKind::SnapBackward.is_navigation_action());
        assert!(TargetActionKind::SnapForward.is_navigation_action());
        assert!(!TargetActionKind::Resume.is_navigation_action());
    }

    #[test]
    fn test_action_entry_creation() {
        let entry = resume_action_entry();
        assert_eq!(entry.kind, TargetActionKind::Resume);
        assert_eq!(entry.display(), "Resume");
        assert!(entry.enabled);
        assert!(entry.description.is_some());
    }

    #[test]
    fn test_action_entry_with_params() {
        let entry = ActionEntry::new(TargetActionKind::StepInto, "Step Into")
            .with_target_key(42)
            .with_param("mode", "instruction");
        assert_eq!(entry.target_key, Some(42));
        assert_eq!(entry.parameters.get("mode").unwrap(), "instruction");
    }

    #[test]
    fn test_target_action_task_lifecycle() {
        let entry = resume_action_entry();
        let mut task = TargetActionTask::new("Resume target", entry);

        assert_eq!(task.state, ActionTaskState::Pending);
        assert!(!task.is_terminal());

        task.start();
        assert_eq!(task.state, ActionTaskState::Running);

        task.set_progress(0.5);
        assert!((task.progress - 0.5).abs() < f64::EPSILON);

        task.complete();
        assert_eq!(task.state, ActionTaskState::Completed);
        assert!(task.is_terminal());
        assert!(task.is_success());
    }

    #[test]
    fn test_target_action_task_cancel() {
        let entry = interrupt_action_entry();
        let mut task = TargetActionTask::new("Interrupt target", entry).cancellable();

        assert!(task.can_cancel());

        task.start();
        task.cancel();
        assert_eq!(task.state, ActionTaskState::Cancelled);
        assert!(task.is_terminal());
        assert!(!task.is_success());
    }

    #[test]
    fn test_target_action_task_fail() {
        let entry = disconnect_action_entry();
        let mut task = TargetActionTask::new("Disconnect", entry);

        task.start();
        task.fail("Connection lost");
        assert_eq!(task.state, ActionTaskState::Failed);
        assert_eq!(task.error.as_deref(), Some("Connection lost"));
    }

    #[test]
    fn test_target_action_task_timeout() {
        let entry = resume_action_entry();
        let mut task = TargetActionTask::new("Resume", entry);

        task.start();
        task.timeout_occurred();
        assert_eq!(task.state, ActionTaskState::TimedOut);
        assert!(task.is_terminal());
    }

    #[test]
    fn test_target_action_task_progress_clamped() {
        let entry = resume_action_entry();
        let mut task = TargetActionTask::new("Resume", entry);

        task.set_progress(1.5);
        assert!((task.progress - 1.0).abs() < f64::EPSILON);

        task.set_progress(-0.5);
        assert!((task.progress - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_all_action_entries() {
        let entries = vec![
            resume_action_entry(),
            step_into_action_entry(),
            step_over_action_entry(),
            step_out_action_entry(),
            interrupt_action_entry(),
            disconnect_action_entry(),
            kill_action_entry(),
            snap_backward_action_entry(),
            snap_forward_action_entry(),
        ];
        assert_eq!(entries.len(), 9);
        for entry in &entries {
            assert!(!entry.display().is_empty());
            assert!(entry.description.is_some());
        }
    }

    #[test]
    fn test_snapshot_navigation() {
        let mut nav = SnapshotNavState::new(0, 5);
        assert!(!nav.has_previous);
        assert!(nav.has_next);

        assert_eq!(nav.go_forward(), Some(1));
        assert!(nav.has_previous);
        assert!(nav.has_next);

        assert_eq!(nav.go_backward(), Some(0));
        assert!(!nav.has_previous);

        // Navigate to end
        nav.go_to(5).unwrap();
        assert!(nav.has_previous);
        assert!(!nav.has_next);
        assert!(nav.go_forward().is_none());
    }

    #[test]
    fn test_snapshot_navigation_out_of_bounds() {
        let mut nav = SnapshotNavState::new(0, 5);
        assert!(nav.go_to(-1).is_none());
        assert!(nav.go_to(6).is_none());
        assert_eq!(nav.go_to(3), Some(3));
    }

    #[test]
    fn test_control_mode_action() {
        let action = ControlModeAction::new("TestPlugin");
        assert_eq!(action.name, "Control Mode");
        assert!(!action.states.is_empty());
        assert!(!action.enabled); // starts disabled
    }

    #[test]
    fn test_control_mode_action_cycle() {
        let mut action = ControlModeAction::new("TestPlugin");
        assert_eq!(action.states.len(), 6); // All 6 ControlMode variants
        let initial_index = action.current_index;

        action.cycle_state();
        assert_ne!(action.current_index, initial_index);
        assert_eq!(action.current_index, 1);
    }

    #[test]
    fn test_control_mode_action_selectable() {
        let action = ControlModeAction::new("TestPlugin");
        // RoTarget and RwTarget are selectable when alive
        assert!(action.is_state_selectable(0, true)); // RoTarget
        assert!(action.is_state_selectable(1, true)); // RwTarget
        assert!(!action.is_state_selectable(0, false)); // RoTarget, not alive
    }

    #[test]
    fn test_control_execution_state() {
        assert!(ControlExecutionState::Running.is_active());
        assert!(ControlExecutionState::Stopping.is_active());
        assert!(!ControlExecutionState::Stopped.is_active());
        assert!(!ControlExecutionState::Disconnected.is_active());

        assert!(ControlExecutionState::Stopped.can_resume());
        assert!(!ControlExecutionState::Running.can_resume());

        assert!(ControlExecutionState::Running.can_interrupt());
        assert!(!ControlExecutionState::Stopped.can_interrupt());

        assert!(ControlExecutionState::Stopped.can_disconnect());
        assert!(ControlExecutionState::Running.can_disconnect());
        assert!(!ControlExecutionState::Disconnected.can_disconnect());
        assert!(!ControlExecutionState::Terminated.can_disconnect());
    }

    #[test]
    fn test_control_execution_state_display() {
        assert_eq!(
            ControlExecutionState::Disconnected.display_name(),
            "Disconnected"
        );
        assert_eq!(ControlExecutionState::Running.display_name(), "Running");
        assert_eq!(format!("{}", ControlExecutionState::Stopped), "Stopped");
    }

    #[test]
    fn test_control_mode_action_state() {
        let state = ControlModeActionState::new(ControlMode::RwTarget);
        assert_eq!(state.name, "Control Target");
        assert!(state.enabled);
    }

    #[test]
    fn test_sub_group_ordering() {
        // Verify sub-group strings maintain proper ordering
        assert!(TargetActionKind::Resume.sub_group() < TargetActionKind::StepInto.sub_group());
        assert!(
            TargetActionKind::SnapBackward.sub_group() > TargetActionKind::StepInto.sub_group()
        );
    }
}
