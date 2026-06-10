//! Trace debugger client - bridges debugger backends with trace storage.
//!
//! Ported from Ghidra's `TraceDebuggerClient` in
//! `ghidra.debug.client.TraceDebuggerClient` and the TraceRmi-based
//! connection management in `ghidra.app.plugin.core.debug.client.tracermi`.
//!
//! This module provides the layer that connects a `DebuggerClientBackend`
//! (any supported agent) to Ghidra's trace database, translating debugger
//! events and state into trace object mutations.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::client::{MemoryMapper, RmiClient, RmiClientConfig, RegisterMapper};
use super::debugger_client::{DebuggerClient, DebuggerClientConfig, DebuggerClientEvent, DebuggerClientKind};

// ---------------------------------------------------------------------------
// TraceDebuggerSession / TraceDebuggerSessionState
// ---------------------------------------------------------------------------

/// State of a trace debugger session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TraceDebuggerSessionState {
    /// Session has not been started.
    Idle,
    /// Session is launching the backend.
    Launching,
    /// Session is connecting to the backend.
    Connecting,
    /// Session is actively debugging.
    Active,
    /// Session is closing.
    Closing,
    /// Session is terminated.
    Terminated,
}

impl TraceDebuggerSessionState {
    /// Whether the session is usable for debugging.
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Whether the session is alive (not terminated or idle).
    pub fn is_alive(&self) -> bool {
        !matches!(self, Self::Terminated | Self::Idle)
    }
}

/// A trace debugger session binding a backend to a trace.
#[derive(Debug)]
pub struct TraceDebuggerSession {
    /// Unique session ID.
    pub session_id: String,
    /// Current session state.
    pub state: TraceDebuggerSessionState,
    /// The backend kind used for this session.
    pub backend_kind: DebuggerClientKind,
    /// Description.
    pub description: String,
    /// The trace key in the trace database.
    pub trace_key: Option<i64>,
    /// The RMI client used to communicate with the backend.
    pub rmi_client: RmiClient,
    /// The debugger client wrapping the backend.
    pub debugger_client: DebuggerClient,
    /// Memory mapper for address translation.
    pub memory_mapper: MemoryMapper,
    /// Register mapper for register name translation.
    pub register_mapper: RegisterMapper,
    /// Target ID -> trace target object key mapping.
    pub target_map: BTreeMap<String, String>,
    /// Session creation timestamp (millis since epoch).
    pub created_at: i64,
}

impl TraceDebuggerSession {
    /// Create a new session.
    pub fn new(
        session_id: impl Into<String>,
        backend_kind: DebuggerClientKind,
        description: impl Into<String>,
    ) -> Self {
        let session_id = session_id.into();
        let description = description.into();
        let rmi_config = RmiClientConfig {
            description: description.clone(),
            ..Default::default()
        };
        let dbg_config = DebuggerClientConfig::new(backend_kind)
            .with_description(&description);
        Self {
            session_id,
            state: TraceDebuggerSessionState::Idle,
            backend_kind,
            description,
            trace_key: None,
            rmi_client: RmiClient::new(rmi_config),
            debugger_client: DebuggerClient::new(dbg_config),
            memory_mapper: MemoryMapper::new(),
            register_mapper: RegisterMapper::new(),
            target_map: BTreeMap::new(),
            created_at: 0,
        }
    }

    /// Transition to a new session state.
    pub fn set_state(&mut self, state: TraceDebuggerSessionState) {
        self.state = state;
    }

    /// Set the trace key after the trace has been opened.
    pub fn set_trace_key(&mut self, key: i64) {
        self.trace_key = Some(key);
    }

    /// Map a backend target ID to a trace object key path.
    pub fn map_target(&mut self, target_id: impl Into<String>, trace_key: impl Into<String>) {
        self.target_map.insert(target_id.into(), trace_key.into());
    }

    /// Get the trace key path for a backend target ID.
    pub fn trace_key_for_target(&self, target_id: &str) -> Option<&str> {
        self.target_map.get(target_id).map(|s| s.as_str())
    }

    /// Whether the session is active.
    pub fn is_active(&self) -> bool {
        self.state.is_active()
    }

    /// Whether the session is alive.
    pub fn is_alive(&self) -> bool {
        self.state.is_alive()
    }

    /// Close the session.
    pub fn close(&mut self) {
        self.state = TraceDebuggerSessionState::Terminated;
        self.rmi_client.close();
    }
}

// ---------------------------------------------------------------------------
// TraceDebuggerClient
// ---------------------------------------------------------------------------

/// Configuration for the trace debugger client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDebuggerClientConfig {
    /// Path to the Ghidra installation root.
    pub ghidra_root: Option<String>,
    /// Path to the user's debug scripts directory.
    pub scripts_dir: Option<String>,
    /// Whether to auto-save traces.
    pub auto_save: bool,
    /// Maximum number of concurrent sessions.
    pub max_sessions: u32,
}

impl Default for TraceDebuggerClientConfig {
    fn default() -> Self {
        Self {
            ghidra_root: None,
            scripts_dir: None,
            auto_save: false,
            max_sessions: 8,
        }
    }
}

/// The trace debugger client, managing sessions between debug backends and
/// trace storage.
///
/// Ported from Ghidra's `TraceDebuggerClient`. This is the top-level
/// coordinator that manages the lifecycle of `TraceDebuggerSession` instances,
/// routing commands from the RMI layer to the appropriate backend, and
/// translating backend events into trace database mutations.
#[derive(Debug)]
pub struct TraceDebuggerClient {
    /// Client configuration.
    pub config: TraceDebuggerClientConfig,
    /// Active sessions, keyed by session ID.
    sessions: BTreeMap<String, TraceDebuggerSession>,
    /// Next session counter for ID generation.
    next_session_id: u64,
}

impl TraceDebuggerClient {
    /// Create a new trace debugger client.
    pub fn new(config: TraceDebuggerClientConfig) -> Self {
        Self {
            config,
            sessions: BTreeMap::new(),
            next_session_id: 1,
        }
    }

    /// Generate a new session ID.
    fn next_session_id(&mut self) -> String {
        let id = format!("session-{}", self.next_session_id);
        self.next_session_id += 1;
        id
    }

    /// Start a new debugging session with the given backend.
    pub fn start_session(
        &mut self,
        kind: DebuggerClientKind,
        description: impl Into<String>,
    ) -> String {
        let session_id = self.next_session_id();
        let session = TraceDebuggerSession::new(&session_id, kind, description);
        self.sessions.insert(session_id.clone(), session);
        session_id
    }

    /// Get a session by ID.
    pub fn get_session(&self, session_id: &str) -> Option<&TraceDebuggerSession> {
        self.sessions.get(session_id)
    }

    /// Get a mutable session by ID.
    pub fn get_session_mut(&mut self, session_id: &str) -> Option<&mut TraceDebuggerSession> {
        self.sessions.get_mut(session_id)
    }

    /// Close and remove a session.
    pub fn close_session(&mut self, session_id: &str) -> bool {
        if let Some(mut session) = self.sessions.remove(session_id) {
            session.close();
            true
        } else {
            false
        }
    }

    /// Get all session IDs.
    pub fn session_ids(&self) -> Vec<String> {
        self.sessions.keys().cloned().collect()
    }

    /// Get the number of active sessions.
    pub fn active_session_count(&self) -> usize {
        self.sessions.values().filter(|s| s.is_active()).count()
    }

    /// Get the total number of sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Close all sessions.
    pub fn close_all(&mut self) {
        for session in self.sessions.values_mut() {
            session.close();
        }
        self.sessions.clear();
    }

    /// Process pending events from a specific session.
    ///
    /// Returns events that should be propagated to the trace database.
    pub fn process_session_events(&mut self, session_id: &str) -> Vec<DebuggerClientEvent> {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.debugger_client.drain_events()
        } else {
            Vec::new()
        }
    }

    /// Get all session summaries.
    pub fn session_summaries(&self) -> Vec<TraceDebuggerSessionSummary> {
        self.sessions
            .values()
            .map(|s| TraceDebuggerSessionSummary {
                session_id: s.session_id.clone(),
                backend_kind: s.backend_kind,
                description: s.description.clone(),
                state: s.state,
                target_count: s.target_map.len(),
                has_trace: s.trace_key.is_some(),
            })
            .collect()
    }
}

/// A summary of a trace debugger session for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDebuggerSessionSummary {
    /// Session ID.
    pub session_id: String,
    /// Backend kind.
    pub backend_kind: DebuggerClientKind,
    /// Description.
    pub description: String,
    /// Current state.
    pub state: TraceDebuggerSessionState,
    /// Number of targets in the session.
    pub target_count: usize,
    /// Whether a trace has been opened.
    pub has_trace: bool,
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_state() {
        assert!(!TraceDebuggerSessionState::Idle.is_alive());
        assert!(!TraceDebuggerSessionState::Idle.is_active());
        assert!(TraceDebuggerSessionState::Active.is_alive());
        assert!(TraceDebuggerSessionState::Active.is_active());
        assert!(!TraceDebuggerSessionState::Terminated.is_alive());
    }

    #[test]
    fn test_session_new() {
        let session = TraceDebuggerSession::new("s1", DebuggerClientKind::Gdb, "GDB debug");
        assert_eq!(session.session_id, "s1");
        assert_eq!(session.backend_kind, DebuggerClientKind::Gdb);
        assert_eq!(session.state, TraceDebuggerSessionState::Idle);
        assert!(session.trace_key.is_none());
        assert!(session.target_map.is_empty());
    }

    #[test]
    fn test_session_state_transitions() {
        let mut session = TraceDebuggerSession::new("s1", DebuggerClientKind::Gdb, "test");
        assert!(!session.is_active());
        session.set_state(TraceDebuggerSessionState::Launching);
        assert!(session.is_alive());
        assert!(!session.is_active());
        session.set_state(TraceDebuggerSessionState::Active);
        assert!(session.is_active());
        session.close();
        assert!(!session.is_alive());
    }

    #[test]
    fn test_session_target_mapping() {
        let mut session = TraceDebuggerSession::new("s1", DebuggerClientKind::Lldb, "test");
        session.map_target("gdb-1", "Processes[0]");
        session.map_target("gdb-2", "Processes[1]");
        assert_eq!(session.trace_key_for_target("gdb-1"), Some("Processes[0]"));
        assert_eq!(session.trace_key_for_target("gdb-2"), Some("Processes[1]"));
        assert!(session.trace_key_for_target("gdb-3").is_none());
    }

    #[test]
    fn test_session_trace_key() {
        let mut session = TraceDebuggerSession::new("s1", DebuggerClientKind::Gdb, "test");
        assert!(session.trace_key.is_none());
        session.set_trace_key(42);
        assert_eq!(session.trace_key, Some(42));
    }

    #[test]
    fn test_trace_debugger_client_sessions() {
        let config = TraceDebuggerClientConfig::default();
        let mut client = TraceDebuggerClient::new(config);
        assert_eq!(client.session_count(), 0);

        let s1 = client.start_session(DebuggerClientKind::Gdb, "GDB session");
        let s2 = client.start_session(DebuggerClientKind::Lldb, "LLDB session");
        assert_eq!(client.session_count(), 2);
        assert!(client.get_session(&s1).is_some());
        assert!(client.get_session(&s2).is_some());
    }

    #[test]
    fn test_trace_debugger_client_close_session() {
        let config = TraceDebuggerClientConfig::default();
        let mut client = TraceDebuggerClient::new(config);
        let s1 = client.start_session(DebuggerClientKind::Gdb, "test");
        assert_eq!(client.session_count(), 1);

        client.close_session(&s1);
        assert_eq!(client.session_count(), 0);
        assert!(client.get_session(&s1).is_none());
    }

    #[test]
    fn test_trace_debugger_client_close_nonexistent() {
        let config = TraceDebuggerClientConfig::default();
        let mut client = TraceDebuggerClient::new(config);
        assert!(!client.close_session("nope"));
    }

    #[test]
    fn test_trace_debugger_client_session_ids() {
        let config = TraceDebuggerClientConfig::default();
        let mut client = TraceDebuggerClient::new(config);
        client.start_session(DebuggerClientKind::Gdb, "a");
        client.start_session(DebuggerClientKind::Lldb, "b");
        let ids = client.session_ids();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn test_trace_debugger_client_active_count() {
        let config = TraceDebuggerClientConfig::default();
        let mut client = TraceDebuggerClient::new(config);
        let s1 = client.start_session(DebuggerClientKind::Gdb, "a");
        assert_eq!(client.active_session_count(), 0); // sessions start as Idle

        client.get_session_mut(&s1).unwrap().set_state(TraceDebuggerSessionState::Active);
        assert_eq!(client.active_session_count(), 1);
    }

    #[test]
    fn test_trace_debugger_client_close_all() {
        let config = TraceDebuggerClientConfig::default();
        let mut client = TraceDebuggerClient::new(config);
        client.start_session(DebuggerClientKind::Gdb, "a");
        client.start_session(DebuggerClientKind::Lldb, "b");
        client.start_session(DebuggerClientKind::Drgn, "c");
        assert_eq!(client.session_count(), 3);

        client.close_all();
        assert_eq!(client.session_count(), 0);
    }

    #[test]
    fn test_trace_debugger_client_session_summaries() {
        let config = TraceDebuggerClientConfig::default();
        let mut client = TraceDebuggerClient::new(config);
        let s1 = client.start_session(DebuggerClientKind::Gdb, "GDB");
        client.get_session_mut(&s1).unwrap().set_state(TraceDebuggerSessionState::Active);
        client.get_session_mut(&s1).unwrap().map_target("t1", "Processes[0]");

        let summaries = client.session_summaries();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].backend_kind, DebuggerClientKind::Gdb);
        assert!(summaries[0].state.is_active());
        assert_eq!(summaries[0].target_count, 1);
        assert!(!summaries[0].has_trace);
    }

    #[test]
    fn test_process_session_events() {
        let config = TraceDebuggerClientConfig::default();
        let mut client = TraceDebuggerClient::new(config);
        let s1 = client.start_session(DebuggerClientKind::Gdb, "test");

        // Push events to the session's debugger client
        client.get_session_mut(&s1).unwrap().debugger_client.push_event(
            DebuggerClientEvent::ConsoleOutput {
                line: "test output".into(),
                is_error: false,
            },
        );

        let events = client.process_session_events(&s1);
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_process_session_events_nonexistent() {
        let config = TraceDebuggerClientConfig::default();
        let mut client = TraceDebuggerClient::new(config);
        let events = client.process_session_events("nope");
        assert!(events.is_empty());
    }

    #[test]
    fn test_trace_debugger_config_default() {
        let config = TraceDebuggerClientConfig::default();
        assert!(!config.auto_save);
        assert_eq!(config.max_sessions, 8);
        assert!(config.ghidra_root.is_none());
    }

    #[test]
    fn test_session_mappers() {
        let mut session = TraceDebuggerSession::new("s1", DebuggerClientKind::Gdb, "test");
        session.memory_mapper.map_space("ram", "memory");
        session.register_mapper.map_register("rax", "RAX");
        assert_eq!(session.memory_mapper.get_mapped_space("ram"), Some("memory"));
        assert_eq!(session.register_mapper.get_local_name("rax"), Some("RAX"));
    }

    #[test]
    fn test_session_summary_has_trace() {
        let mut session = TraceDebuggerSession::new("s1", DebuggerClientKind::Gdb, "test");
        session.set_trace_key(1);
        assert!(session.trace_key.is_some());

        let summaries = vec![TraceDebuggerSessionSummary {
            session_id: session.session_id.clone(),
            backend_kind: session.backend_kind,
            description: session.description.clone(),
            state: session.state,
            target_count: session.target_map.len(),
            has_trace: session.trace_key.is_some(),
        }];
        assert!(summaries[0].has_trace);
    }

    #[test]
    fn test_session_state_all_variants() {
        let states = [
            TraceDebuggerSessionState::Idle,
            TraceDebuggerSessionState::Launching,
            TraceDebuggerSessionState::Connecting,
            TraceDebuggerSessionState::Active,
            TraceDebuggerSessionState::Closing,
            TraceDebuggerSessionState::Terminated,
        ];
        // Only Active should be is_active
        for s in &states {
            if *s == TraceDebuggerSessionState::Active {
                assert!(s.is_active());
            } else {
                assert!(!s.is_active());
            }
        }
    }
}
