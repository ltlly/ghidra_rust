//! DebuggerControlService - service for debugger control operations.
//!
//! Ported from Ghidra's `ghidra.app.services.DebuggerControlService`.

use serde::{Deserialize, Serialize};

/// Control mode for the debugger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMode {
    /// Not connected.
    Disconnected,
    /// Connected to a target, stopped.
    Stopped,
    /// Connected and running.
    Running,
    /// Connected and stepping.
    Stepping,
}

/// Service interface for debugger control operations.
pub trait DebuggerControlServiceExt {
    /// Get the current control mode.
    fn control_mode(&self) -> ControlMode;

    /// Get the currently active target key.
    fn active_target(&self) -> Option<i64>;

    /// Connect to a target.
    fn connect(&mut self, target_key: i64) -> Result<(), String>;

    /// Disconnect from the current target.
    fn disconnect(&mut self) -> Result<(), String>;

    /// Resume execution.
    fn resume(&mut self) -> Result<(), String>;

    /// Interrupt execution.
    fn interrupt(&mut self) -> Result<(), String>;

    /// Step into.
    fn step_into(&mut self) -> Result<(), String>;

    /// Step over.
    fn step_over(&mut self) -> Result<(), String>;

    /// Step out.
    fn step_out(&mut self) -> Result<(), String>;

    /// Step to a specific address.
    fn step_to_address(&mut self, address: u64) -> Result<(), String>;

    /// Whether connected to a target.
    fn is_connected(&self) -> bool {
        self.control_mode() != ControlMode::Disconnected
    }

    /// Whether the target is running.
    fn is_running(&self) -> bool {
        self.control_mode() == ControlMode::Running
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_modes() {
        assert_ne!(ControlMode::Disconnected, ControlMode::Stopped);
        assert_ne!(ControlMode::Running, ControlMode::Stepping);
    }

    #[test]
    fn test_control_mode_checks() {
        // Test that the derived checks work correctly
        assert!(ControlMode::Disconnected != ControlMode::Running);
        assert!(ControlMode::Running == ControlMode::Running);
    }
}
