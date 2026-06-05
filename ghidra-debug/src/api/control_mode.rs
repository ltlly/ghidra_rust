//! ControlMode - how the debugger controls the target.
//!
//! Ported from Ghidra's `ghidra.debug.api.control.ControlMode` (514 lines).
//! The control mode determines how control actions, breakpoint commands, and
//! state edits are directed -- to the live target, to a trace snapshot, or to
//! an emulated state.

use serde::{Deserialize, Serialize};

/// The mode of control a debugger session has over a target.
///
/// Each variant encodes: (1) whether control goes to the live target or a trace,
/// (2) whether the view follows the present snapshot, and (3) whether state edits
/// are permitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ControlMode {
    /// Control actions and breakpoint commands are directed to the live target,
    /// but state edits are rejected. The view follows the target's present state.
    RoTarget,
    /// Control actions, breakpoint commands, and state edits are all directed to
    /// the live target. The view follows the target's present state.
    RwTarget,
    /// Control actions activate trace snapshots, breakpoint commands are directed
    /// to the emulator, and state edits are rejected.
    RoTrace,
    /// Control actions activate trace snapshots, breakpoint commands are directed
    /// to the emulator, and state edits modify the current trace snapshot.
    RwTrace,
    /// Control actions and breakpoint commands are directed to the emulator, and
    /// state edits are rejected. Used for replaying a recorded trace.
    RoEmulator,
    /// Control actions and breakpoint commands are directed to the emulator, and
    /// state edits modify the emulator's state.
    RwEmulator,
}

impl ControlMode {
    /// A human-readable display label for this mode.
    pub fn label(&self) -> &'static str {
        match self {
            Self::RoTarget => "Control Target w/ Edits Disabled",
            Self::RwTarget => "Control Target",
            Self::RoTrace => "Control Trace w/ Edits Disabled",
            Self::RwTrace => "Control Trace",
            Self::RoEmulator => "Control Emulator w/ Edits Disabled",
            Self::RwEmulator => "Control Emulator",
        }
    }

    /// Whether control actions and breakpoints are directed to the live target
    /// (as opposed to a trace or emulator).
    pub fn is_target(&self) -> bool {
        matches!(self, Self::RoTarget | Self::RwTarget)
    }

    /// Whether the view automatically follows the target's present snapshot.
    ///
    /// Returns `false` for trace modes (RoTrace, RwTrace), which let the user
    /// navigate independently of the present.
    pub fn follows_present(&self) -> bool {
        matches!(
            self,
            Self::RoTarget | Self::RwTarget | Self::RoEmulator | Self::RwEmulator
        )
    }

    /// Whether the target can be stepped in this mode.
    pub fn can_step(&self) -> bool {
        !matches!(self, Self::RoTrace)
    }

    /// Whether the target is being live-controlled.
    pub fn is_live(&self) -> bool {
        matches!(self, Self::RoTarget | Self::RwTarget)
    }

    /// Whether this mode allows editing state (memory, registers, etc.).
    pub fn can_edit(&self) -> bool {
        matches!(self, Self::RwTarget | Self::RwTrace | Self::RwEmulator)
    }

    /// Whether a specific variable at the given address and length is editable.
    ///
    /// In read-only modes, this always returns `false`. In read-write target
    /// mode, this returns `true` only when the view is at the present snapshot.
    pub fn is_variable_editable(&self, is_alive_and_present: bool) -> bool {
        match self {
            Self::RwTarget => is_alive_and_present,
            Self::RwTrace | Self::RwEmulator => true,
            _ => false,
        }
    }

    /// Whether emulated breakpoints should be used.
    ///
    /// Returns `true` for trace and emulator modes, `false` for target modes.
    pub fn use_emulated_breakpoints(&self) -> bool {
        matches!(
            self,
            Self::RoTrace | Self::RwTrace | Self::RoEmulator | Self::RwEmulator
        )
    }

    /// Whether this mode is selectable given the current coordinates.
    ///
    /// Target modes require the trace to have a live target. Trace modes are
    /// always selectable. Emulator modes require the trace to not be alive.
    pub fn is_selectable(&self, is_alive: bool) -> bool {
        match self {
            Self::RoTarget | Self::RwTarget => is_alive,
            Self::RoTrace | Self::RwTrace => true,
            Self::RoEmulator | Self::RwEmulator => !is_alive,
        }
    }

    /// Get the alternative mode for the given coordinates.
    ///
    /// Typically toggles between target/emulator modes. For trace modes,
    /// returns the corresponding read-write or read-only trace mode.
    pub fn alternative(&self) -> Self {
        match self {
            Self::RoTarget => Self::RoEmulator,
            Self::RwTarget => Self::RwEmulator,
            Self::RoTrace => Self::RwTrace,
            Self::RwTrace => Self::RoTrace,
            Self::RoEmulator => Self::RoTarget,
            Self::RwEmulator => Self::RwTarget,
        }
    }

    /// Get the read-write variant of this mode.
    pub fn read_write(&self) -> Self {
        match self {
            Self::RoTarget => Self::RwTarget,
            Self::RwTarget => Self::RwTarget,
            Self::RoTrace => Self::RwTrace,
            Self::RwTrace => Self::RwTrace,
            Self::RoEmulator => Self::RwEmulator,
            Self::RwEmulator => Self::RwEmulator,
        }
    }

    /// Get the read-only variant of this mode.
    pub fn read_only(&self) -> Self {
        match self {
            Self::RoTarget | Self::RwTarget => Self::RoTarget,
            Self::RoTrace | Self::RwTrace => Self::RoTrace,
            Self::RoEmulator | Self::RwEmulator => Self::RoEmulator,
        }
    }

    /// Whether this mode is for emulator control.
    pub fn is_emulator(&self) -> bool {
        matches!(self, Self::RoEmulator | Self::RwEmulator)
    }

    /// Whether this mode is for trace control.
    pub fn is_trace(&self) -> bool {
        matches!(self, Self::RoTrace | Self::RwTrace)
    }

    /// All available control modes.
    pub fn all() -> &'static [ControlMode] {
        &[
            Self::RoTarget,
            Self::RwTarget,
            Self::RoTrace,
            Self::RwTrace,
            Self::RoEmulator,
            Self::RwEmulator,
        ]
    }

    /// Get the default mode for when a live target is available.
    pub fn default_for_live() -> Self {
        Self::RwTarget
    }

    /// Get the default mode for when no live target is available.
    pub fn default_for_dead() -> Self {
        Self::RwEmulator
    }
}

impl std::fmt::Display for ControlMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

impl Default for ControlMode {
    fn default() -> Self {
        Self::RwTarget
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_target() {
        assert!(ControlMode::RoTarget.is_target());
        assert!(ControlMode::RwTarget.is_target());
        assert!(!ControlMode::RoTrace.is_target());
        assert!(!ControlMode::RwTrace.is_target());
        assert!(!ControlMode::RoEmulator.is_target());
        assert!(!ControlMode::RwEmulator.is_target());
    }

    #[test]
    fn test_follows_present() {
        assert!(ControlMode::RoTarget.follows_present());
        assert!(ControlMode::RwTarget.follows_present());
        assert!(!ControlMode::RoTrace.follows_present());
        assert!(!ControlMode::RwTrace.follows_present());
        assert!(ControlMode::RoEmulator.follows_present());
        assert!(ControlMode::RwEmulator.follows_present());
    }

    #[test]
    fn test_can_step() {
        assert!(ControlMode::RoTarget.can_step());
        assert!(ControlMode::RwTarget.can_step());
        assert!(!ControlMode::RoTrace.can_step());
        assert!(ControlMode::RwTrace.can_step());
        assert!(ControlMode::RoEmulator.can_step());
        assert!(ControlMode::RwEmulator.can_step());
    }

    #[test]
    fn test_can_edit() {
        assert!(!ControlMode::RoTarget.can_edit());
        assert!(ControlMode::RwTarget.can_edit());
        assert!(!ControlMode::RoTrace.can_edit());
        assert!(ControlMode::RwTrace.can_edit());
        assert!(!ControlMode::RoEmulator.can_edit());
        assert!(ControlMode::RwEmulator.can_edit());
    }

    #[test]
    fn test_is_variable_editable() {
        // RO modes always false
        assert!(!ControlMode::RoTarget.is_variable_editable(true));
        assert!(!ControlMode::RoTrace.is_variable_editable(true));
        assert!(!ControlMode::RoEmulator.is_variable_editable(true));

        // RW target only when alive and present
        assert!(ControlMode::RwTarget.is_variable_editable(true));
        assert!(!ControlMode::RwTarget.is_variable_editable(false));

        // RW trace/emulator always true
        assert!(ControlMode::RwTrace.is_variable_editable(false));
        assert!(ControlMode::RwEmulator.is_variable_editable(false));
    }

    #[test]
    fn test_use_emulated_breakpoints() {
        assert!(!ControlMode::RoTarget.use_emulated_breakpoints());
        assert!(!ControlMode::RwTarget.use_emulated_breakpoints());
        assert!(ControlMode::RoTrace.use_emulated_breakpoints());
        assert!(ControlMode::RwTrace.use_emulated_breakpoints());
        assert!(ControlMode::RoEmulator.use_emulated_breakpoints());
        assert!(ControlMode::RwEmulator.use_emulated_breakpoints());
    }

    #[test]
    fn test_is_selectable() {
        // Target modes need alive
        assert!(ControlMode::RoTarget.is_selectable(true));
        assert!(!ControlMode::RoTarget.is_selectable(false));
        assert!(ControlMode::RwTarget.is_selectable(true));
        assert!(!ControlMode::RwTarget.is_selectable(false));

        // Trace modes always selectable
        assert!(ControlMode::RoTrace.is_selectable(true));
        assert!(ControlMode::RoTrace.is_selectable(false));

        // Emulator modes need NOT alive
        assert!(!ControlMode::RoEmulator.is_selectable(true));
        assert!(ControlMode::RoEmulator.is_selectable(false));
    }

    #[test]
    fn test_alternative() {
        assert_eq!(ControlMode::RoTarget.alternative(), ControlMode::RoEmulator);
        assert_eq!(ControlMode::RwTarget.alternative(), ControlMode::RwEmulator);
        assert_eq!(ControlMode::RoTrace.alternative(), ControlMode::RwTrace);
        assert_eq!(ControlMode::RwTrace.alternative(), ControlMode::RoTrace);
        assert_eq!(ControlMode::RoEmulator.alternative(), ControlMode::RoTarget);
        assert_eq!(ControlMode::RwEmulator.alternative(), ControlMode::RwTarget);
    }

    #[test]
    fn test_read_write_and_read_only() {
        assert_eq!(ControlMode::RoTarget.read_write(), ControlMode::RwTarget);
        assert_eq!(ControlMode::RwTarget.read_only(), ControlMode::RoTarget);
        assert_eq!(ControlMode::RoTrace.read_write(), ControlMode::RwTrace);
        assert_eq!(ControlMode::RwTrace.read_only(), ControlMode::RoTrace);
    }

    #[test]
    fn test_is_live() {
        assert!(ControlMode::RoTarget.is_live());
        assert!(ControlMode::RwTarget.is_live());
        assert!(!ControlMode::RoTrace.is_live());
        assert!(!ControlMode::RwEmulator.is_live());
    }

    #[test]
    fn test_is_emulator_and_is_trace() {
        assert!(ControlMode::RoEmulator.is_emulator());
        assert!(ControlMode::RwEmulator.is_emulator());
        assert!(!ControlMode::RoTarget.is_emulator());
        assert!(ControlMode::RoTrace.is_trace());
        assert!(ControlMode::RwTrace.is_trace());
        assert!(!ControlMode::RoTarget.is_trace());
    }

    #[test]
    fn test_all_count() {
        assert_eq!(ControlMode::all().len(), 6);
    }

    #[test]
    fn test_default() {
        assert_eq!(ControlMode::default(), ControlMode::RwTarget);
        assert_eq!(ControlMode::default_for_live(), ControlMode::RwTarget);
        assert_eq!(ControlMode::default_for_dead(), ControlMode::RwEmulator);
    }

    #[test]
    fn test_display() {
        assert_eq!(
            ControlMode::RoTarget.to_string(),
            "Control Target w/ Edits Disabled"
        );
        assert_eq!(ControlMode::RwTarget.to_string(), "Control Target");
    }

    #[test]
    fn test_serde() {
        for mode in ControlMode::all() {
            let json = serde_json::to_string(mode).unwrap();
            let back: ControlMode = serde_json::from_str(&json).unwrap();
            assert_eq!(*mode, back);
        }
    }
}
