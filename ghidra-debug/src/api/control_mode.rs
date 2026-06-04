//! ControlMode - how the debugger controls the target.

use serde::{Deserialize, Serialize};

/// The mode of control a debugger session has over a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ControlMode {
    /// The debugger controls the target directly (e.g., live debugging).
    Live,
    /// The debugger is replaying a recorded trace.
    Replay,
    /// The debugger is emulating the target.
    Emulation,
}

impl ControlMode {
    /// Whether the target can be stepped in this mode.
    pub fn can_step(&self) -> bool {
        matches!(self, Self::Live | Self::Emulation)
    }

    /// Whether the target is live.
    pub fn is_live(&self) -> bool {
        *self == Self::Live
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_can_step() {
        assert!(ControlMode::Live.can_step());
        assert!(ControlMode::Emulation.can_step());
        assert!(!ControlMode::Replay.can_step());
    }

    #[test]
    fn test_serde() {
        let m = ControlMode::Emulation;
        let json = serde_json::to_string(&m).unwrap();
        let back: ControlMode = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }
}
