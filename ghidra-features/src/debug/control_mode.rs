//! Control modes for the Debug framework.
//!
//! Ported from `ghidra.debug.api.control.ControlMode` — the modes that
//! determine where control actions, breakpoint commands, and state edits
//! are directed.

use std::fmt;

// ---------------------------------------------------------------------------
// ControlMode
// ---------------------------------------------------------------------------

/// The control / state editing modes for the debugger.
///
/// Ported from `ghidra.debug.api.control.ControlMode`. Each mode determines
/// how UI commands (resume, step, breakpoint, state edit) are directed:
/// to the live target, the trace, or the emulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControlMode {
    /// Control actions and breakpoint commands are directed to the target,
    /// but state edits are rejected.
    RoTarget,
    /// Control actions, breakpoint commands, and state edits are all
    /// directed to the target.
    RwTarget,
    /// Control actions activate trace snapshots, breakpoint commands are
    /// directed to the emulator, and state edits are rejected.
    RoTrace,
    /// Control actions activate trace snapshots, breakpoint commands are
    /// directed to the emulator, and state edits modify the current
    /// trace snapshot.
    RwTrace,
    /// Control actions, breakpoint commands, and state edits are directed
    /// to the emulator. Edits are accomplished by appending patch steps
    /// to the current schedule and activating that schedule.
    RwEmulator,
}

impl ControlMode {
    /// Returns `true` if this mode controls the live target (not emulator/trace).
    pub fn is_target(&self) -> bool {
        matches!(self, ControlMode::RoTarget | ControlMode::RwTarget)
    }

    /// Returns `true` if this mode allows editing the state.
    pub fn can_edit(&self) -> bool {
        matches!(
            self,
            ControlMode::RwTarget | ControlMode::RwTrace | ControlMode::RwEmulator
        )
    }

    /// Returns `true` if this mode uses emulated breakpoints (vs. target breakpoints).
    pub fn use_emulated_breakpoints(&self) -> bool {
        matches!(
            self,
            ControlMode::RoTrace | ControlMode::RwTrace | ControlMode::RwEmulator
        )
    }

    /// Returns `true` if the UI should keep its active snapshot in sync with
    /// the recorder's latest.
    pub fn follows_present(&self) -> bool {
        matches!(self, ControlMode::RoTarget | ControlMode::RwTarget)
    }

    /// Returns the display name of this mode.
    pub fn display_name(&self) -> &'static str {
        match self {
            ControlMode::RoTarget => "Control Target w/ Edits Disabled",
            ControlMode::RwTarget => "Control Target",
            ControlMode::RoTrace => "Control Trace w/ Edits Disabled",
            ControlMode::RwTrace => "Control Trace",
            ControlMode::RwEmulator => "Control Emulator",
        }
    }

    /// Returns the read-write counterpart of this mode, or itself if already RW.
    ///
    /// `RoTarget` -> `RwEmulator`
    /// `RwTarget` -> `RwEmulator`
    /// `RoTrace`  -> `RwEmulator`
    /// `RwTrace`  -> `RwTrace`
    /// `RwEmulator` -> `RwEmulator`
    pub fn rw_alternative(&self) -> ControlMode {
        match self {
            ControlMode::RoTarget | ControlMode::RwTarget | ControlMode::RoTrace => {
                ControlMode::RwEmulator
            }
            ControlMode::RwTrace | ControlMode::RwEmulator => *self,
        }
    }

    /// All control modes in declaration order.
    pub const ALL: [ControlMode; 5] = [
        ControlMode::RoTarget,
        ControlMode::RwTarget,
        ControlMode::RoTrace,
        ControlMode::RwTrace,
        ControlMode::RwEmulator,
    ];

    /// The default control mode.
    pub const DEFAULT: ControlMode = ControlMode::RoTarget;
}

impl fmt::Display for ControlMode {
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
    fn test_is_target() {
        assert!(ControlMode::RoTarget.is_target());
        assert!(ControlMode::RwTarget.is_target());
        assert!(!ControlMode::RoTrace.is_target());
        assert!(!ControlMode::RwTrace.is_target());
        assert!(!ControlMode::RwEmulator.is_target());
    }

    #[test]
    fn test_can_edit() {
        assert!(!ControlMode::RoTarget.can_edit());
        assert!(!ControlMode::RoTrace.can_edit());
        assert!(ControlMode::RwTarget.can_edit());
        assert!(ControlMode::RwTrace.can_edit());
        assert!(ControlMode::RwEmulator.can_edit());
    }

    #[test]
    fn test_use_emulated_breakpoints() {
        assert!(!ControlMode::RoTarget.use_emulated_breakpoints());
        assert!(!ControlMode::RwTarget.use_emulated_breakpoints());
        assert!(ControlMode::RoTrace.use_emulated_breakpoints());
        assert!(ControlMode::RwTrace.use_emulated_breakpoints());
        assert!(ControlMode::RwEmulator.use_emulated_breakpoints());
    }

    #[test]
    fn test_follows_present() {
        assert!(ControlMode::RoTarget.follows_present());
        assert!(ControlMode::RwTarget.follows_present());
        assert!(!ControlMode::RoTrace.follows_present());
        assert!(!ControlMode::RwTrace.follows_present());
        assert!(!ControlMode::RwEmulator.follows_present());
    }

    #[test]
    fn test_rw_alternative() {
        assert_eq!(ControlMode::RoTarget.rw_alternative(), ControlMode::RwEmulator);
        assert_eq!(ControlMode::RwTarget.rw_alternative(), ControlMode::RwEmulator);
        assert_eq!(ControlMode::RoTrace.rw_alternative(), ControlMode::RwEmulator);
        assert_eq!(ControlMode::RwTrace.rw_alternative(), ControlMode::RwTrace);
        assert_eq!(ControlMode::RwEmulator.rw_alternative(), ControlMode::RwEmulator);
    }

    #[test]
    fn test_display() {
        assert_eq!(
            format!("{}", ControlMode::RwTarget),
            "Control Target"
        );
        assert_eq!(
            format!("{}", ControlMode::RwEmulator),
            "Control Emulator"
        );
    }

    #[test]
    fn test_all_contains_default() {
        assert!(ControlMode::ALL.contains(&ControlMode::DEFAULT));
    }
}
