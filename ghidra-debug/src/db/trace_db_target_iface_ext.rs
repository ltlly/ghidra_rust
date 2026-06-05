//! Extended target interface implementations for database-backed traces.
//!
//! Ported from Ghidra's `ghidra.trace.database.target.iface` package.
//! Provides database-backed implementations for execution stateful, focus scope,
//! and togglable object interfaces.

use crate::model::target_iface::ExecutionState;

/// Database-backed implementation of the execution stateful interface.
///
/// Corresponds to Java's `DBTraceObjectExecutionStateful`. Wraps a trace
/// object and provides access to its execution state (running, stopped, etc.).
#[derive(Debug, Clone)]
pub struct DbObjectExecutionStateful {
    /// The object identifier this is bound to.
    pub object_id: u64,
    /// Current execution state.
    pub state: ExecutionState,
}

impl DbObjectExecutionStateful {
    /// Create a new execution stateful wrapper.
    pub fn new(object_id: u64) -> Self {
        Self {
            object_id,
            state: ExecutionState::Unknown,
        }
    }

    /// Get the current execution state.
    pub fn get_execution_state(&self) -> ExecutionState {
        self.state
    }

    /// Set the execution state.
    pub fn set_execution_state(&mut self, state: ExecutionState) {
        self.state = state;
    }

    /// Check if the object is currently running.
    pub fn is_running(&self) -> bool {
        self.state == ExecutionState::Running
    }

    /// Check if the object is stopped.
    pub fn is_stopped(&self) -> bool {
        self.state == ExecutionState::Stopped
    }
}

/// Database-backed implementation of the focus scope interface.
///
/// Corresponds to Java's `DBTraceObjectFocusScope`. Tracks which
/// object is currently "focused" (selected as the active context).
#[derive(Debug, Clone)]
pub struct DbObjectFocusScope {
    /// The object identifier this is bound to.
    pub object_id: u64,
    /// The currently focused object ID, if any.
    pub focused_object_id: Option<u64>,
}

impl DbObjectFocusScope {
    /// Create a new focus scope wrapper.
    pub fn new(object_id: u64) -> Self {
        Self {
            object_id,
            focused_object_id: None,
        }
    }

    /// Get the currently focused object ID.
    pub fn get_focused(&self) -> Option<u64> {
        self.focused_object_id
    }

    /// Set the focused object.
    pub fn set_focused(&mut self, object_id: Option<u64>) {
        self.focused_object_id = object_id;
    }

    /// Check if anything is focused.
    pub fn has_focus(&self) -> bool {
        self.focused_object_id.is_some()
    }

    /// Clear the focus.
    pub fn clear_focus(&mut self) {
        self.focused_object_id = None;
    }
}

/// Database-backed implementation of the togglable interface.
///
/// Corresponds to Java's `DBTraceObjectTogglable`. Tracks whether
/// a togglable object (like a breakpoint) is enabled or disabled.
#[derive(Debug, Clone)]
pub struct DbObjectTogglable {
    /// The object identifier this is bound to.
    pub object_id: u64,
    /// Whether the object is currently enabled.
    pub enabled: bool,
}

impl DbObjectTogglable {
    /// Create a new togglable wrapper.
    pub fn new(object_id: u64) -> Self {
        Self {
            object_id,
            enabled: false,
        }
    }

    /// Create with a specific initial state.
    pub fn with_state(object_id: u64, enabled: bool) -> Self {
        Self { object_id, enabled }
    }

    /// Check if the object is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Toggle the enabled state.
    pub fn toggle(&mut self) {
        self.enabled = !self.enabled;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_stateful_default() {
        let es = DbObjectExecutionStateful::new(42);
        assert_eq!(es.object_id, 42);
        assert_eq!(es.get_execution_state(), ExecutionState::Unknown);
        assert!(!es.is_running());
        assert!(!es.is_stopped());
    }

    #[test]
    fn test_execution_stateful_set_state() {
        let mut es = DbObjectExecutionStateful::new(1);
        es.set_execution_state(ExecutionState::Running);
        assert!(es.is_running());
        assert!(!es.is_stopped());

        es.set_execution_state(ExecutionState::Stopped);
        assert!(!es.is_running());
        assert!(es.is_stopped());
    }

    #[test]
    fn test_focus_scope_default() {
        let fs = DbObjectFocusScope::new(10);
        assert!(!fs.has_focus());
        assert!(fs.get_focused().is_none());
    }

    #[test]
    fn test_focus_scope_set_and_clear() {
        let mut fs = DbObjectFocusScope::new(10);
        fs.set_focused(Some(5));
        assert!(fs.has_focus());
        assert_eq!(fs.get_focused(), Some(5));

        fs.clear_focus();
        assert!(!fs.has_focus());
    }

    #[test]
    fn test_togglable_default() {
        let tog = DbObjectTogglable::new(7);
        assert!(!tog.is_enabled());
    }

    #[test]
    fn test_togglable_with_state() {
        let tog = DbObjectTogglable::with_state(7, true);
        assert!(tog.is_enabled());
    }

    #[test]
    fn test_togglable_toggle() {
        let mut tog = DbObjectTogglable::new(7);
        assert!(!tog.is_enabled());

        tog.toggle();
        assert!(tog.is_enabled());

        tog.toggle();
        assert!(!tog.is_enabled());
    }

    #[test]
    fn test_togglable_set_enabled() {
        let mut tog = DbObjectTogglable::new(7);
        tog.set_enabled(true);
        assert!(tog.is_enabled());
        tog.set_enabled(false);
        assert!(!tog.is_enabled());
    }
}
