//! Extended debugger control service implementation types.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.service.control` package.
//! Provides the control service plugin data model.

use std::collections::BTreeMap;

/// State of a debugger control connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlConnectionState {
    /// Not connected to any target.
    Disconnected,
    /// Connection is being established.
    Connecting,
    /// Connected to a target.
    Connected,
    /// Connection is being terminated.
    Disconnecting,
}

/// A registered control target with connection state.
#[derive(Debug, Clone)]
pub struct ControlTarget {
    /// Target identifier.
    pub target_id: i64,
    /// Target display name.
    pub name: String,
    /// Target type (e.g., "gdb", "lldb", "dbgeng").
    pub target_type: String,
    /// Current connection state.
    pub state: ControlConnectionState,
    /// Process ID if attached.
    pub pid: Option<i64>,
}

impl ControlTarget {
    /// Create a new control target.
    pub fn new(target_id: i64, name: impl Into<String>, target_type: impl Into<String>) -> Self {
        Self {
            target_id,
            name: name.into(),
            target_type: target_type.into(),
            state: ControlConnectionState::Disconnected,
            pid: None,
        }
    }

    /// Check if this target is connected.
    pub fn is_connected(&self) -> bool {
        self.state == ControlConnectionState::Connected
    }

    /// Set the connection state.
    pub fn set_state(&mut self, state: ControlConnectionState) {
        self.state = state;
    }
}

/// Implementation data for the debugger control service.
///
/// Corresponds to Java's `DebuggerControlServicePlugin`.
#[derive(Debug)]
pub struct ControlServiceData {
    /// Registered targets by ID.
    targets: BTreeMap<i64, ControlTarget>,
    /// Currently active target ID.
    active_target: Option<i64>,
    /// Control mode.
    pub control_mode: ControlMode,
}

/// Control mode for the debugger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlMode {
    /// Normal control mode.
    Normal,
    /// Automatic control mode (auto-step, etc.).
    Automatic,
}

impl ControlServiceData {
    /// Create new control service data.
    pub fn new() -> Self {
        Self {
            targets: BTreeMap::new(),
            active_target: None,
            control_mode: ControlMode::Normal,
        }
    }

    /// Register a target.
    pub fn register_target(&mut self, target: ControlTarget) {
        self.targets.insert(target.target_id, target);
    }

    /// Unregister a target.
    pub fn unregister_target(&mut self, target_id: i64) -> Option<ControlTarget> {
        if self.active_target == Some(target_id) {
            self.active_target = None;
        }
        self.targets.remove(&target_id)
    }

    /// Get a target by ID.
    pub fn get_target(&self, target_id: i64) -> Option<&ControlTarget> {
        self.targets.get(&target_id)
    }

    /// Get a mutable target by ID.
    pub fn get_target_mut(&mut self, target_id: i64) -> Option<&mut ControlTarget> {
        self.targets.get_mut(&target_id)
    }

    /// Get the active target.
    pub fn active_target(&self) -> Option<&ControlTarget> {
        self.active_target.and_then(|id| self.targets.get(&id))
    }

    /// Set the active target.
    pub fn set_active_target(&mut self, target_id: Option<i64>) {
        self.active_target = target_id;
    }

    /// Get the active target ID.
    pub fn active_target_id(&self) -> Option<i64> {
        self.active_target
    }

    /// Get all registered targets.
    pub fn all_targets(&self) -> Vec<&ControlTarget> {
        self.targets.values().collect()
    }

    /// Get connected targets.
    pub fn connected_targets(&self) -> Vec<&ControlTarget> {
        self.targets.values().filter(|t| t.is_connected()).collect()
    }

    /// Connect to a target.
    pub fn connect(&mut self, target_id: i64) -> Result<(), String> {
        let target = self
            .targets
            .get_mut(&target_id)
            .ok_or_else(|| format!("Target {} not found", target_id))?;
        target.set_state(ControlConnectionState::Connected);
        self.active_target = Some(target_id);
        Ok(())
    }

    /// Disconnect from a target.
    pub fn disconnect(&mut self, target_id: i64) -> Result<(), String> {
        let target = self
            .targets
            .get_mut(&target_id)
            .ok_or_else(|| format!("Target {} not found", target_id))?;
        target.set_state(ControlConnectionState::Disconnected);
        if self.active_target == Some(target_id) {
            self.active_target = None;
        }
        Ok(())
    }

    /// Check if connected to any target.
    pub fn is_connected(&self) -> bool {
        self.targets.values().any(|t| t.is_connected())
    }
}

impl Default for ControlServiceData {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_target() {
        let mut target = ControlTarget::new(1, "GDB Target", "gdb");
        assert!(!target.is_connected());
        target.set_state(ControlConnectionState::Connected);
        assert!(target.is_connected());
    }

    #[test]
    fn test_control_service_data_register() {
        let mut data = ControlServiceData::new();
        data.register_target(ControlTarget::new(1, "GDB", "gdb"));
        data.register_target(ControlTarget::new(2, "LLDB", "lldb"));

        assert_eq!(data.all_targets().len(), 2);
        assert!(data.get_target(1).is_some());
        assert!(data.get_target(3).is_none());
    }

    #[test]
    fn test_control_service_data_connect_disconnect() {
        let mut data = ControlServiceData::new();
        data.register_target(ControlTarget::new(1, "GDB", "gdb"));

        assert!(!data.is_connected());
        data.connect(1).unwrap();
        assert!(data.is_connected());
        assert_eq!(data.active_target_id(), Some(1));
        assert!(data.active_target().unwrap().is_connected());

        data.disconnect(1).unwrap();
        assert!(!data.is_connected());
        assert!(data.active_target_id().is_none());
    }

    #[test]
    fn test_control_service_data_connect_nonexistent() {
        let mut data = ControlServiceData::new();
        assert!(data.connect(999).is_err());
    }

    #[test]
    fn test_control_service_data_unregister() {
        let mut data = ControlServiceData::new();
        data.register_target(ControlTarget::new(1, "GDB", "gdb"));
        data.connect(1).unwrap();

        data.unregister_target(1);
        assert!(data.active_target_id().is_none());
        assert!(data.all_targets().is_empty());
    }

    #[test]
    fn test_control_service_data_connected_targets() {
        let mut data = ControlServiceData::new();
        data.register_target(ControlTarget::new(1, "GDB", "gdb"));
        data.register_target(ControlTarget::new(2, "LLDB", "lldb"));
        data.connect(1).unwrap();

        assert_eq!(data.connected_targets().len(), 1);
    }

    #[test]
    fn test_control_mode() {
        let mut data = ControlServiceData::new();
        assert_eq!(data.control_mode, ControlMode::Normal);
        data.control_mode = ControlMode::Automatic;
        assert_eq!(data.control_mode, ControlMode::Automatic);
    }
}
