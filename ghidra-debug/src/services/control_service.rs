//! Debugger control service - state management and execution control.
//!
//! Ported from Ghidra's `DebuggerControlServicePlugin` (613 lines)
//! and `DebuggerControlService` interface. This module manages the
//! control state of debugger sessions, including mode switching,
//! state editing, and coordination of control actions.

use serde::{Deserialize, Serialize};

use crate::api::control_mode::ControlMode;

/// State editor permission levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StateEditPermission {
    /// No editing allowed.
    ReadOnly,
    /// Direct editing of live target state.
    LiveEdit,
    /// Editing of emulator state only.
    EmulatorEdit,
    /// Editing of trace snapshot state.
    TraceEdit,
}

impl StateEditPermission {
    /// Whether editing is allowed at all.
    pub fn can_edit(&self) -> bool {
        !matches!(self, Self::ReadOnly)
    }
}

/// A pending control action waiting to be executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingControlAction {
    /// The action name.
    pub action: String,
    /// The target thread key (None for all threads).
    pub thread_key: Option<i64>,
    /// Arguments for the action.
    pub args: Vec<String>,
    /// Timestamp when the action was queued.
    pub queued_at: Option<i64>,
}

/// The control service manages debugger execution state and actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlService {
    /// The current control mode.
    mode: ControlMode,
    /// The current state edit permission.
    edit_permission: StateEditPermission,
    /// Pending control actions.
    pending_actions: Vec<PendingControlAction>,
    /// Whether the service is currently processing an action.
    processing: bool,
    /// Whether the connected target supports certain capabilities.
    capabilities: ControlCapabilities,
}

/// Capabilities of the controlled target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlCapabilities {
    /// Whether the target supports interrupting.
    pub can_interrupt: bool,
    /// Whether the target supports killing.
    pub can_kill: bool,
    /// Whether the target supports disconnecting.
    pub can_disconnect: bool,
    /// Whether the target supports state editing.
    pub can_edit_state: bool,
    /// Whether the target supports multiple threads.
    pub supports_threads: bool,
}

impl Default for ControlCapabilities {
    fn default() -> Self {
        Self {
            can_interrupt: true,
            can_kill: true,
            can_disconnect: true,
            can_edit_state: true,
            supports_threads: true,
        }
    }
}

impl ControlService {
    /// Create a new control service with the given mode.
    pub fn new(mode: ControlMode) -> Self {
        let edit_permission = match mode {
            ControlMode::RoTarget | ControlMode::RoTrace | ControlMode::RoEmulator => {
                StateEditPermission::ReadOnly
            }
            ControlMode::RwTarget => StateEditPermission::LiveEdit,
            ControlMode::RwTrace => StateEditPermission::TraceEdit,
            ControlMode::RwEmulator => StateEditPermission::EmulatorEdit,
        };
        Self {
            mode,
            edit_permission,
            pending_actions: Vec::new(),
            processing: false,
            capabilities: ControlCapabilities::default(),
        }
    }

    /// Set the control mode.
    pub fn set_mode(&mut self, mode: ControlMode) {
        self.mode = mode;
        self.edit_permission = match mode {
            ControlMode::RoTarget | ControlMode::RoTrace | ControlMode::RoEmulator => {
                StateEditPermission::ReadOnly
            }
            ControlMode::RwTarget => StateEditPermission::LiveEdit,
            ControlMode::RwTrace => StateEditPermission::TraceEdit,
            ControlMode::RwEmulator => StateEditPermission::EmulatorEdit,
        };
    }

    /// Get the current control mode.
    pub fn mode(&self) -> ControlMode {
        self.mode
    }

    /// Get the current state edit permission.
    pub fn edit_permission(&self) -> StateEditPermission {
        self.edit_permission
    }

    /// Whether state editing is currently allowed.
    pub fn can_edit_state(&self) -> bool {
        self.edit_permission.can_edit() && self.capabilities.can_edit_state
    }

    /// Whether the target can be stepped.
    pub fn can_step(&self) -> bool {
        self.mode.can_step()
    }

    /// Whether control is directed at a live target.
    pub fn is_live(&self) -> bool {
        self.mode.is_live()
    }

    /// Enqueue a control action.
    pub fn enqueue_action(&mut self, action: PendingControlAction) {
        self.pending_actions.push(action);
    }

    /// Dequeue the next pending action.
    pub fn dequeue_action(&mut self) -> Option<PendingControlAction> {
        if self.pending_actions.is_empty() {
            None
        } else {
            Some(self.pending_actions.remove(0))
        }
    }

    /// The number of pending actions.
    pub fn pending_action_count(&self) -> usize {
        self.pending_actions.len()
    }

    /// Clear all pending actions.
    pub fn clear_pending_actions(&mut self) {
        self.pending_actions.clear();
    }

    /// Whether the service is currently processing an action.
    pub fn is_processing(&self) -> bool {
        self.processing
    }

    /// Set the processing state.
    pub fn set_processing(&mut self, processing: bool) {
        self.processing = processing;
    }

    /// Get the capabilities.
    pub fn capabilities(&self) -> &ControlCapabilities {
        &self.capabilities
    }

    /// Set the capabilities.
    pub fn set_capabilities(&mut self, caps: ControlCapabilities) {
        self.capabilities = caps;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_service_modes() {
        let svc = ControlService::new(ControlMode::RwTarget);
        assert_eq!(svc.mode(), ControlMode::RwTarget);
        assert!(svc.can_edit_state());
        assert!(svc.can_step());
        assert!(svc.is_live());

        let mut svc = ControlService::new(ControlMode::RoTrace);
        assert!(!svc.can_edit_state());
        assert!(!svc.is_live());
        svc.set_mode(ControlMode::RwEmulator);
        assert!(svc.can_edit_state());
        assert!(!svc.is_live());
    }

    #[test]
    fn test_state_edit_permission() {
        assert!(!StateEditPermission::ReadOnly.can_edit());
        assert!(StateEditPermission::LiveEdit.can_edit());
        assert!(StateEditPermission::EmulatorEdit.can_edit());
        assert!(StateEditPermission::TraceEdit.can_edit());
    }

    #[test]
    fn test_control_service_enqueue_dequeue() {
        let mut svc = ControlService::new(ControlMode::RwTarget);
        assert_eq!(svc.pending_action_count(), 0);

        svc.enqueue_action(PendingControlAction {
            action: "step".into(),
            thread_key: Some(1),
            args: vec![],
            queued_at: None,
        });
        svc.enqueue_action(PendingControlAction {
            action: "resume".into(),
            thread_key: None,
            args: vec![],
            queued_at: None,
        });
        assert_eq!(svc.pending_action_count(), 2);

        let action = svc.dequeue_action().unwrap();
        assert_eq!(action.action, "step");
        assert_eq!(action.thread_key, Some(1));
        assert_eq!(svc.pending_action_count(), 1);
    }

    #[test]
    fn test_control_service_dequeue_empty() {
        let mut svc = ControlService::new(ControlMode::RwTarget);
        assert!(svc.dequeue_action().is_none());
    }

    #[test]
    fn test_control_service_clear_pending() {
        let mut svc = ControlService::new(ControlMode::RwTarget);
        svc.enqueue_action(PendingControlAction {
            action: "step".into(),
            thread_key: None,
            args: vec![],
            queued_at: None,
        });
        svc.clear_pending_actions();
        assert_eq!(svc.pending_action_count(), 0);
    }

    #[test]
    fn test_control_service_processing() {
        let mut svc = ControlService::new(ControlMode::RwTarget);
        assert!(!svc.is_processing());
        svc.set_processing(true);
        assert!(svc.is_processing());
        svc.set_processing(false);
        assert!(!svc.is_processing());
    }

    #[test]
    fn test_control_service_capabilities() {
        let mut svc = ControlService::new(ControlMode::RwTarget);
        assert!(svc.capabilities().can_interrupt);
        assert!(svc.capabilities().can_kill);

        svc.set_capabilities(ControlCapabilities {
            can_interrupt: false,
            ..Default::default()
        });
        assert!(!svc.capabilities().can_interrupt);
    }

    #[test]
    fn test_control_service_edit_permission_readonly_modes() {
        for mode in &[ControlMode::RoTarget, ControlMode::RoTrace, ControlMode::RoEmulator] {
            let svc = ControlService::new(*mode);
            assert_eq!(svc.edit_permission(), StateEditPermission::ReadOnly);
        }
    }

    #[test]
    fn test_control_service_edit_permission_rw_modes() {
        let svc = ControlService::new(ControlMode::RwTarget);
        assert_eq!(svc.edit_permission(), StateEditPermission::LiveEdit);

        let svc = ControlService::new(ControlMode::RwTrace);
        assert_eq!(svc.edit_permission(), StateEditPermission::TraceEdit);

        let svc = ControlService::new(ControlMode::RwEmulator);
        assert_eq!(svc.edit_permission(), StateEditPermission::EmulatorEdit);
    }

    #[test]
    fn test_control_service_serialization() {
        let svc = ControlService::new(ControlMode::RwTarget);
        let json = serde_json::to_string(&svc).unwrap();
        let back: ControlService = serde_json::from_str(&json).unwrap();
        assert_eq!(back.mode(), ControlMode::RwTarget);
    }

    #[test]
    fn test_pending_control_action_serialization() {
        let action = PendingControlAction {
            action: "step".into(),
            thread_key: Some(1),
            args: vec!["--into".into()],
            queued_at: Some(12345),
        };
        let json = serde_json::to_string(&action).unwrap();
        let back: PendingControlAction = serde_json::from_str(&json).unwrap();
        assert_eq!(back.action, "step");
    }

    #[test]
    fn test_control_service_step_capability() {
        let svc = ControlService::new(ControlMode::RoTrace);
        assert!(!svc.can_step());

        let svc = ControlService::new(ControlMode::RwTrace);
        assert!(svc.can_step());
    }
}
