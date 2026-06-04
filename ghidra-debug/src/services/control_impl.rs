//! Debugger control service implementation.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.service.control` package.
//! Provides the control service that manages target connections, process
//! lifecycle, and debugger sessions.

use serde::{Deserialize, Serialize};

/// The state of a debug session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SessionState {
    /// No active session.
    Idle,
    /// Connecting to a target.
    Connecting,
    /// Connected and running.
    Running,
    /// Connected and paused (breakpoint hit, step completed).
    Paused,
    /// Disconnecting.
    Disconnecting,
    /// The session encountered an error.
    Error,
}

impl SessionState {
    /// Whether the session is connected (running or paused).
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Running | Self::Paused)
    }

    /// Whether the session is active (any state except Idle).
    pub fn is_active(&self) -> bool {
        *self != Self::Idle
    }
}

/// A debug session representing a connection to a target.
///
/// Ported from Ghidra's debugger control service session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugSession {
    /// The session ID.
    pub id: String,
    /// The target type (e.g., "gdb", "lldb", "dbgeng").
    pub target_type: String,
    /// The current state.
    pub state: SessionState,
    /// The PID of the target process, if attached.
    pub pid: Option<i64>,
    /// The connection parameters.
    pub parameters: std::collections::BTreeMap<String, String>,
    /// Error message if in error state.
    pub error: Option<String>,
}

impl DebugSession {
    /// Create a new session.
    pub fn new(id: impl Into<String>, target_type: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            target_type: target_type.into(),
            state: SessionState::Idle,
            pid: None,
            parameters: std::collections::BTreeMap::new(),
            error: None,
        }
    }

    /// Set the session state.
    pub fn set_state(&mut self, state: SessionState) {
        self.state = state;
    }

    /// Set the PID.
    pub fn set_pid(&mut self, pid: i64) {
        self.pid = Some(pid);
    }

    /// Set an error message and transition to Error state.
    pub fn set_error(&mut self, msg: impl Into<String>) {
        self.error = Some(msg.into());
        self.state = SessionState::Error;
    }

    /// Clear the error and return to Idle.
    pub fn clear_error(&mut self) {
        self.error = None;
        self.state = SessionState::Idle;
    }

    /// Whether the session is currently connected.
    pub fn is_connected(&self) -> bool {
        self.state.is_connected()
    }
}

/// The debugger control service implementation.
///
/// Ported from Ghidra's debugger control plugin.
#[derive(Debug, Default)]
pub struct ControlServiceImpl {
    /// Active sessions.
    sessions: Vec<DebugSession>,
    /// The active session index.
    active_session_idx: Option<usize>,
}

impl ControlServiceImpl {
    /// Create a new control service.
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a new debug session.
    pub fn start_session(
        &mut self,
        id: impl Into<String>,
        target_type: impl Into<String>,
    ) -> usize {
        let session = DebugSession::new(id, target_type);
        self.sessions.push(session);
        let idx = self.sessions.len() - 1;
        if self.active_session_idx.is_none() {
            self.active_session_idx = Some(idx);
        }
        idx
    }

    /// Get the active session.
    pub fn active_session(&self) -> Option<&DebugSession> {
        self.active_session_idx
            .and_then(|idx| self.sessions.get(idx))
    }

    /// Get a mutable reference to the active session.
    pub fn active_session_mut(&mut self) -> Option<&mut DebugSession> {
        self.active_session_idx
            .and_then(|idx| self.sessions.get_mut(idx))
    }

    /// Set the active session.
    pub fn set_active_session(&mut self, idx: usize) -> Result<(), String> {
        if idx >= self.sessions.len() {
            return Err(format!("Session index {} out of range", idx));
        }
        self.active_session_idx = Some(idx);
        Ok(())
    }

    /// Get all sessions.
    pub fn sessions(&self) -> &[DebugSession] {
        &self.sessions
    }

    /// Close a session by index.
    pub fn close_session(&mut self, idx: usize) -> Option<DebugSession> {
        if idx >= self.sessions.len() {
            return None;
        }
        let session = self.sessions.remove(idx);
        // Fix active session index
        match self.active_session_idx {
            Some(active) if active == idx => self.active_session_idx = None,
            Some(active) if active > idx => self.active_session_idx = Some(active - 1),
            _ => {}
        }
        Some(session)
    }

    /// Number of sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_state() {
        assert!(SessionState::Running.is_connected());
        assert!(SessionState::Paused.is_connected());
        assert!(!SessionState::Idle.is_connected());
        assert!(!SessionState::Error.is_connected());

        assert!(SessionState::Running.is_active());
        assert!(!SessionState::Idle.is_active());
    }

    #[test]
    fn test_debug_session() {
        let mut session = DebugSession::new("s1", "gdb");
        assert_eq!(session.state, SessionState::Idle);
        assert!(!session.is_connected());

        session.set_state(SessionState::Running);
        assert!(session.is_connected());

        session.set_pid(1234);
        assert_eq!(session.pid, Some(1234));

        session.set_error("connection lost");
        assert_eq!(session.state, SessionState::Error);
        assert!(session.error.is_some());

        session.clear_error();
        assert_eq!(session.state, SessionState::Idle);
    }

    #[test]
    fn test_control_service() {
        let mut svc = ControlServiceImpl::new();
        assert_eq!(svc.session_count(), 0);

        svc.start_session("s1", "gdb");
        svc.start_session("s2", "lldb");
        assert_eq!(svc.session_count(), 2);

        assert!(svc.active_session().is_some());
        assert_eq!(svc.active_session().unwrap().id, "s1");

        svc.set_active_session(1).unwrap();
        assert_eq!(svc.active_session().unwrap().id, "s2");
    }

    #[test]
    fn test_close_session() {
        let mut svc = ControlServiceImpl::new();
        svc.start_session("s1", "gdb");
        svc.start_session("s2", "lldb");

        let closed = svc.close_session(0);
        assert!(closed.is_some());
        assert_eq!(svc.session_count(), 1);
    }

    #[test]
    fn test_set_active_out_of_range() {
        let mut svc = ControlServiceImpl::new();
        assert!(svc.set_active_session(5).is_err());
    }

    #[test]
    fn test_session_serde() {
        let session = DebugSession::new("s1", "gdb");
        let json = serde_json::to_string(&session).unwrap();
        let back: DebugSession = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "s1");
    }

    #[test]
    fn test_active_session_mut() {
        let mut svc = ControlServiceImpl::new();
        svc.start_session("s1", "gdb");
        if let Some(session) = svc.active_session_mut() {
            session.set_state(SessionState::Running);
        }
        assert_eq!(
            svc.active_session().unwrap().state,
            SessionState::Running
        );
    }
}
