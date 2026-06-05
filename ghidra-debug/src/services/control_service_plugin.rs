//! Control service plugin implementation.
//!
//! Ported from Ghidra's `DebuggerControlServicePlugin` in
//! `ghidra.app.plugin.core.debug.service.control`.

use serde::{Deserialize, Serialize};

/// The control service plugin manages the connection to debug targets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlServicePlugin {
    /// The currently active target key.
    pub active_target: Option<i64>,
    /// Whether connected.
    pub connected: bool,
    /// Control mode.
    pub mode: ControlMode,
}

/// Control mode for the debugger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMode {
    /// Normal debugging.
    Normal,
    /// Emulation mode.
    Emulate,
    /// Mixed mode.
    Mixed,
}

impl Default for ControlMode {
    fn default() -> Self {
        Self::Normal
    }
}

impl ControlServicePlugin {
    /// Create a new control service plugin.
    pub fn new() -> Self {
        Self {
            active_target: None,
            connected: false,
            mode: ControlMode::default(),
        }
    }

    /// Connect to a target.
    pub fn connect(&mut self, target_key: i64) {
        self.active_target = Some(target_key);
        self.connected = true;
    }

    /// Disconnect.
    pub fn disconnect(&mut self) {
        self.active_target = None;
        self.connected = false;
    }

    /// Check if connected.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Get the active target.
    pub fn active_target(&self) -> Option<i64> {
        self.active_target
    }

    /// Set the control mode.
    pub fn set_mode(&mut self, mode: ControlMode) {
        self.mode = mode;
    }
}

impl Default for ControlServicePlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_plugin_new() {
        let c = ControlServicePlugin::new();
        assert!(!c.is_connected());
        assert!(c.active_target().is_none());
    }

    #[test]
    fn test_control_plugin_connect() {
        let mut c = ControlServicePlugin::new();
        c.connect(42);
        assert!(c.is_connected());
        assert_eq!(c.active_target(), Some(42));
    }

    #[test]
    fn test_control_plugin_disconnect() {
        let mut c = ControlServicePlugin::new();
        c.connect(1);
        c.disconnect();
        assert!(!c.is_connected());
    }

    #[test]
    fn test_control_mode_default() {
        assert_eq!(ControlMode::default(), ControlMode::Normal);
    }
}
