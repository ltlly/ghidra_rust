//! Debugger control panel and provider.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.control` package.
//!
//! Provides the `DebuggerControlProvider` and `ControlAction` interface,
//! as well as the action-creation helpers for building the control toolbar.

use serde::{Deserialize, Serialize};

/// The control action group constant.
///
/// Ported from the `ControlAction` interface's `GROUP` constant.
pub const CONTROL_GROUP: &str = "control";

/// Format a sub-group number for toolbar ordering.
///
/// Ported from `ControlAction.intSubGroup`.
pub fn int_sub_group(sub_group: u32) -> String {
    format!("{:02}", sub_group)
}

/// The kind of control action to perform.
///
/// Ported from `ControlAction` implementations:
/// `ResAction`, `StepIntoAction`, `StepOverAction`, `StepOutAction`,
/// `StepExtendAction`, `InterruptAction`, `KillAction`,
/// `DisconnectAction`, `SkipOverAction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DebuggerControlActionKind {
    /// Resume (continue) execution.
    Resume,
    /// Step into (single step, entering calls).
    StepInto,
    /// Step over (single step, skipping calls).
    StepOver,
    /// Step out (run until current function returns).
    StepOut,
    /// Step to an extended location.
    StepExtend,
    /// Interrupt/pause execution.
    Interrupt,
    /// Kill the target process.
    Kill,
    /// Disconnect from the target.
    Disconnect,
    /// Skip over the current instruction.
    SkipOver,
}

impl DebuggerControlActionKind {
    /// Return the display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Resume => "Resume",
            Self::StepInto => "Step Into",
            Self::StepOver => "Step Over",
            Self::StepOut => "Step Out",
            Self::StepExtend => "Step Extended",
            Self::Interrupt => "Interrupt",
            Self::Kill => "Kill",
            Self::Disconnect => "Disconnect",
            Self::SkipOver => "Skip Over",
        }
    }

    /// Return the icon name.
    pub fn icon_name(&self) -> &'static str {
        match self {
            Self::Resume => "icon.debugger.control.resume",
            Self::StepInto => "icon.debugger.control.step.into",
            Self::StepOver => "icon.debugger.control.step.over",
            Self::StepOut => "icon.debugger.control.step.out",
            Self::StepExtend => "icon.debugger.control.step.extend",
            Self::Interrupt => "icon.debugger.control.interrupt",
            Self::Kill => "icon.debugger.control.kill",
            Self::Disconnect => "icon.debugger.control.disconnect",
            Self::SkipOver => "icon.debugger.control.skip.over",
        }
    }

    /// Return the keyboard shortcut.
    pub fn key_binding(&self) -> Option<&'static str> {
        match self {
            Self::Resume => Some("F5"),
            Self::StepInto => Some("F7"),
            Self::StepOver => Some("F8"),
            Self::StepOut => Some("Shift+F8"),
            Self::StepExtend => Some("F9"),
            Self::Interrupt => Some("F12"),
            _ => None,
        }
    }

    /// Whether this action is destructive (kills or disconnects).
    pub fn is_destructive(&self) -> bool {
        matches!(self, Self::Kill | Self::Disconnect)
    }

    /// All known control action kinds.
    pub fn all() -> &'static [DebuggerControlActionKind] {
        &[
            Self::Resume,
            Self::StepInto,
            Self::StepOver,
            Self::StepOut,
            Self::StepExtend,
            Self::Interrupt,
            Self::Kill,
            Self::Disconnect,
            Self::SkipOver,
        ]
    }
}

impl std::fmt::Display for DebuggerControlActionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.display_name())
    }
}

/// Whether this control action targets the live debugger, the emulator, or
/// trace time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ControlTarget {
    /// Action targets the live debugger.
    Live,
    /// Action targets the p-code emulator.
    Emulator,
    /// Action targets trace time (snapshot navigation).
    TraceTime,
}

/// A constructed control action ready to be dispatched.
///
/// Ported from `DebuggerControlProvider`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerControlAction {
    /// The kind of action.
    pub kind: DebuggerControlActionKind,
    /// The target.
    pub target: ControlTarget,
    /// The action group.
    pub group: String,
    /// The sub-group for ordering.
    pub sub_group: String,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl DebuggerControlAction {
    /// Create a new control action.
    pub fn new(kind: DebuggerControlActionKind, target: ControlTarget) -> Self {
        let sub = match kind {
            DebuggerControlActionKind::Resume => 0,
            DebuggerControlActionKind::StepInto => 1,
            DebuggerControlActionKind::StepOver => 2,
            DebuggerControlActionKind::StepOut => 3,
            DebuggerControlActionKind::StepExtend => 4,
            DebuggerControlActionKind::SkipOver => 5,
            DebuggerControlActionKind::Interrupt => 10,
            DebuggerControlActionKind::Kill => 11,
            DebuggerControlActionKind::Disconnect => 12,
        };
        Self {
            kind,
            target,
            group: CONTROL_GROUP.into(),
            sub_group: int_sub_group(sub),
            enabled: true,
        }
    }
}

/// Configuration for the control provider panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerControlProviderConfig {
    /// Whether to show live target actions.
    pub show_live_actions: bool,
    /// Whether to show emulator actions.
    pub show_emulator_actions: bool,
    /// Whether to show trace-time navigation actions.
    pub show_trace_time_actions: bool,
    /// The default target when connecting.
    pub default_target: ControlTarget,
}

impl Default for DebuggerControlProviderConfig {
    fn default() -> Self {
        Self {
            show_live_actions: true,
            show_emulator_actions: true,
            show_trace_time_actions: true,
            default_target: ControlTarget::Live,
        }
    }
}

/// Build the complete set of live-target control actions.
pub fn live_control_actions() -> Vec<DebuggerControlAction> {
    DebuggerControlActionKind::all()
        .iter()
        .map(|&kind| DebuggerControlAction::new(kind, ControlTarget::Live))
        .collect()
}

/// Build the complete set of emulator control actions.
pub fn emulator_control_actions() -> Vec<DebuggerControlAction> {
    [
        DebuggerControlActionKind::Resume,
        DebuggerControlActionKind::StepInto,
        DebuggerControlActionKind::StepOver,
        DebuggerControlActionKind::StepOut,
        DebuggerControlActionKind::StepExtend,
        DebuggerControlActionKind::SkipOver,
    ]
    .iter()
    .map(|&kind| DebuggerControlAction::new(kind, ControlTarget::Emulator))
    .collect()
}

/// Snapshot navigation action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SnapshotNavAction {
    /// Go to the previous snap.
    SnapBackward,
    /// Go to the next snap.
    SnapForward,
    /// Go to a specific snap.
    GoToSnap,
}

impl SnapshotNavAction {
    /// Return the display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::SnapBackward => "Previous Snap",
            Self::SnapForward => "Next Snap",
            Self::GoToSnap => "Go To Snap",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_int_sub_group() {
        assert_eq!(int_sub_group(0), "00");
        assert_eq!(int_sub_group(5), "05");
        assert_eq!(int_sub_group(12), "12");
    }

    #[test]
    fn test_action_kind_display() {
        assert_eq!(format!("{}", DebuggerControlActionKind::Resume), "Resume");
        assert_eq!(
            format!("{}", DebuggerControlActionKind::StepInto),
            "Step Into"
        );
    }

    #[test]
    fn test_action_kind_names() {
        assert_eq!(
            DebuggerControlActionKind::Kill.display_name(),
            "Kill"
        );
        assert!(DebuggerControlActionKind::Kill
            .icon_name()
            .contains("kill"));
    }

    #[test]
    fn test_action_kind_key_bindings() {
        assert_eq!(
            DebuggerControlActionKind::Resume.key_binding(),
            Some("F5")
        );
        assert_eq!(
            DebuggerControlActionKind::StepInto.key_binding(),
            Some("F7")
        );
        assert_eq!(
            DebuggerControlActionKind::Kill.key_binding(),
            None
        );
    }

    #[test]
    fn test_action_kind_destructive() {
        assert!(DebuggerControlActionKind::Kill.is_destructive());
        assert!(DebuggerControlActionKind::Disconnect.is_destructive());
        assert!(!DebuggerControlActionKind::Resume.is_destructive());
        assert!(!DebuggerControlActionKind::StepInto.is_destructive());
    }

    #[test]
    fn test_action_kind_all() {
        assert_eq!(DebuggerControlActionKind::all().len(), 9);
    }

    #[test]
    fn test_control_action_new() {
        let action = DebuggerControlAction::new(
            DebuggerControlActionKind::Resume,
            ControlTarget::Live,
        );
        assert_eq!(action.kind, DebuggerControlActionKind::Resume);
        assert_eq!(action.target, ControlTarget::Live);
        assert_eq!(action.group, CONTROL_GROUP);
        assert!(action.enabled);
    }

    #[test]
    fn test_control_action_ordering() {
        let resume = DebuggerControlAction::new(
            DebuggerControlActionKind::Resume,
            ControlTarget::Live,
        );
        let step = DebuggerControlAction::new(
            DebuggerControlActionKind::StepInto,
            ControlTarget::Live,
        );
        let interrupt = DebuggerControlAction::new(
            DebuggerControlActionKind::Interrupt,
            ControlTarget::Live,
        );
        assert!(resume.sub_group < step.sub_group);
        assert!(step.sub_group < interrupt.sub_group);
    }

    #[test]
    fn test_provider_config_default() {
        let cfg = DebuggerControlProviderConfig::default();
        assert!(cfg.show_live_actions);
        assert!(cfg.show_emulator_actions);
        assert_eq!(cfg.default_target, ControlTarget::Live);
    }

    #[test]
    fn test_live_control_actions() {
        let actions = live_control_actions();
        assert_eq!(actions.len(), 9);
        assert!(actions.iter().all(|a| a.target == ControlTarget::Live));
    }

    #[test]
    fn test_emulator_control_actions() {
        let actions = emulator_control_actions();
        assert_eq!(actions.len(), 6);
        assert!(actions.iter().all(|a| a.target == ControlTarget::Emulator));
    }

    #[test]
    fn test_snapshot_nav_action() {
        assert_eq!(
            SnapshotNavAction::SnapBackward.display_name(),
            "Previous Snap"
        );
        assert_eq!(
            SnapshotNavAction::SnapForward.display_name(),
            "Next Snap"
        );
    }
}
