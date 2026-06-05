//! Debugger control plugin and action types.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.control` package (19 files).
//! Provides the control action types for target execution, emulation stepping,
//! trace navigation, and interrupt management.

use serde::{Deserialize, Serialize};

/// The kind of control action available in the debugger.
///
/// Ported from Ghidra's various action classes in `gui.control`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ControlActionKind {
    /// Resume target execution (TargetResumeAction).
    Resume,
    /// Step into the next instruction (TargetStepIntoAction).
    StepInto,
    /// Step over the next instruction (TargetStepOverAction).
    StepOver,
    /// Step out of the current function (TargetStepOutAction).
    StepOut,
    /// Extended step (TargetStepExtAction).
    StepExt,
    /// Interrupt/stop target execution (InterruptAction / TargetInterruptAction).
    Interrupt,
    /// Kill the target process (TargetKillAction).
    Kill,
    /// Disconnect from the target (DisconnectAction).
    Disconnect,
    /// Emulate: resume emulation (EmulateResumeAction).
    EmulateResume,
    /// Emulate: step into (EmulateStepIntoAction).
    EmulateStepInto,
    /// Emulate: skip over (EmulateSkipOverAction).
    EmulateSkipOver,
    /// Emulate: step back (EmulateStepBackAction).
    EmulateStepBack,
    /// Emulate: interrupt (EmulateInterruptAction).
    EmulateInterrupt,
    /// Navigate trace snap backward (TraceSnapBackwardAction).
    SnapBackward,
    /// Navigate trace snap forward (TraceSnapForwardAction).
    SnapForward,
}

impl ControlActionKind {
    /// Whether this is an emulation-only action.
    pub fn is_emulate(&self) -> bool {
        matches!(
            self,
            Self::EmulateResume
                | Self::EmulateStepInto
                | Self::EmulateSkipOver
                | Self::EmulateStepBack
                | Self::EmulateInterrupt
        )
    }

    /// Whether this is a target execution action.
    pub fn is_target(&self) -> bool {
        matches!(
            self,
            Self::Resume
                | Self::StepInto
                | Self::StepOver
                | Self::StepOut
                | Self::StepExt
                | Self::Interrupt
                | Self::Kill
        )
    }

    /// Whether this is a trace navigation action.
    pub fn is_trace(&self) -> bool {
        matches!(self, Self::SnapBackward | Self::SnapForward)
    }

    /// Human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Resume => "Resume target execution",
            Self::StepInto => "Step into instruction",
            Self::StepOver => "Step over instruction",
            Self::StepOut => "Step out of function",
            Self::StepExt => "Extended step",
            Self::Interrupt => "Interrupt target",
            Self::Kill => "Kill target process",
            Self::Disconnect => "Disconnect from target",
            Self::EmulateResume => "Resume emulation",
            Self::EmulateStepInto => "Emulate step into",
            Self::EmulateSkipOver => "Emulate skip over",
            Self::EmulateStepBack => "Emulate step back",
            Self::EmulateInterrupt => "Interrupt emulation",
            Self::SnapBackward => "Navigate snap backward",
            Self::SnapForward => "Navigate snap forward",
        }
    }
}

/// State of the control panel, tracking what kind of execution is active.
///
/// Ported from Ghidra's `DebuggerControlPlugin` state management.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlExecutionState {
    /// No active execution.
    Idle,
    /// Target is running.
    TargetRunning,
    /// Target is stopped.
    TargetStopped,
    /// Emulation is running.
    Emulating,
    /// Emulation is paused.
    EmulationPaused,
}

/// The control mode for the debugger (target vs emulator).
///
/// Ported from Ghidra's `ControlMode` enum in `ghidra.debug.api.control`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DebuggerControlMode {
    /// Control the live target.
    Target,
    /// Control the emulator.
    Emulator,
    /// Control both target and emulator.
    Both,
}

impl Default for DebuggerControlMode {
    fn default() -> Self {
        Self::Target
    }
}

/// A snapshot navigation entry for trace timeline navigation.
///
/// Ported from Ghidra's TraceSnapForwardAction / TraceSnapBackwardAction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapNavigationEntry {
    /// The snap to navigate to.
    pub snap: i64,
    /// The reason for navigation.
    pub reason: String,
    /// Whether this was a forward or backward navigation.
    pub forward: bool,
}

impl SnapNavigationEntry {
    /// Create a new snap navigation entry.
    pub fn new(snap: i64, forward: bool) -> Self {
        Self {
            snap,
            reason: String::new(),
            forward,
        }
    }

    /// Set the reason.
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_action_kind_properties() {
        assert!(ControlActionKind::Resume.is_target());
        assert!(!ControlActionKind::Resume.is_emulate());
        assert!(!ControlActionKind::Resume.is_trace());

        assert!(ControlActionKind::EmulateStepInto.is_emulate());
        assert!(!ControlActionKind::EmulateStepInto.is_target());

        assert!(ControlActionKind::SnapForward.is_trace());
        assert!(!ControlActionKind::SnapForward.is_target());
    }

    #[test]
    fn test_control_action_kind_descriptions() {
        assert!(!ControlActionKind::Resume.description().is_empty());
        assert!(!ControlActionKind::Kill.description().is_empty());
        assert!(!ControlActionKind::Disconnect.description().is_empty());
        assert!(!ControlActionKind::SnapBackward.description().is_empty());
    }

    #[test]
    fn test_control_execution_state() {
        let state = ControlExecutionState::Idle;
        assert_eq!(state, ControlExecutionState::Idle);

        let running = ControlExecutionState::TargetRunning;
        assert_ne!(running, ControlExecutionState::Idle);
    }

    #[test]
    fn test_debugger_control_mode() {
        let mode = DebuggerControlMode::default();
        assert_eq!(mode, DebuggerControlMode::Target);
        assert_ne!(mode, DebuggerControlMode::Emulator);
    }

    #[test]
    fn test_snap_navigation_entry() {
        let entry = SnapNavigationEntry::new(42, true).with_reason("step");
        assert_eq!(entry.snap, 42);
        assert!(entry.forward);
        assert_eq!(entry.reason, "step");
    }

    #[test]
    fn test_control_action_kind_serde() {
        let action = ControlActionKind::Resume;
        let json = serde_json::to_string(&action).unwrap();
        let back: ControlActionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ControlActionKind::Resume);
    }

    #[test]
    fn test_all_action_kinds() {
        let all = [
            ControlActionKind::Resume,
            ControlActionKind::StepInto,
            ControlActionKind::StepOver,
            ControlActionKind::StepOut,
            ControlActionKind::StepExt,
            ControlActionKind::Interrupt,
            ControlActionKind::Kill,
            ControlActionKind::Disconnect,
            ControlActionKind::EmulateResume,
            ControlActionKind::EmulateStepInto,
            ControlActionKind::EmulateSkipOver,
            ControlActionKind::EmulateStepBack,
            ControlActionKind::EmulateInterrupt,
            ControlActionKind::SnapBackward,
            ControlActionKind::SnapForward,
        ];
        // Every variant should have a non-empty description
        for kind in &all {
            assert!(!kind.description().is_empty());
        }
        // Verify count
        assert_eq!(all.len(), 15);
    }
}
