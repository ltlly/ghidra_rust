//! Trace debugger client - bridges debugger backends with trace storage.
//!
//! Ported from Ghidra's `TraceDebuggerClient` in
//! `ghidra.debug.client.TraceDebuggerClient`, the TraceRmi-based
//! connection management in `ghidra.app.plugin.core.debug.client.tracermi`,
//! and the `TraceRmiConnection` / `TraceRmiTarget` abstractions from
//! `ghidra.debug.api.tracermi`.
//!
//! This module provides the layer that connects a `DebuggerClientBackend`
//! (any supported agent) to Ghidra's trace database, translating debugger
//! events and state into trace object mutations. The RMI transport layer
//! handles the bidirectional request-reply channel between the front-end
//! (Ghidra) and the back-end debugger agent.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::client::{MemoryMapper, RmiClient, RmiClientConfig, RegisterMapper};
use super::debugger_client::{DebuggerClient, DebuggerClientConfig, DebuggerClientEvent, DebuggerClientKind};
use super::service::RemoteMethodRegistry;

// ---------------------------------------------------------------------------
// TraceRmiConnection / TraceRmiTransport
// ---------------------------------------------------------------------------

/// The lifecycle state of a Trace RMI connection.
///
/// Ported from Ghidra's connection state tracking in
/// `AbstractTraceRmiConnection` and `TraceRmiHandler`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TraceRmiConnectionState {
    /// Connection is being negotiated.
    Negotiating,
    /// Connection is established and active.
    Active,
    /// Connection has a transaction open on one or more targets.
    Busy,
    /// Connection is closing.
    Closing,
    /// Connection has been closed.
    Closed,
    /// Connection encountered an error.
    Error,
}

impl TraceRmiConnectionState {
    /// Whether the connection can accept requests.
    pub fn can_accept_requests(&self) -> bool {
        matches!(self, Self::Active | Self::Busy)
    }

    /// Whether the connection is alive (not closed or errored).
    pub fn is_alive(&self) -> bool {
        !matches!(self, Self::Closed | Self::Error)
    }
}

/// How the RMI connection was established.
///
/// Ported from `TraceRmiServiceListener.ConnectMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RmiConnectMode {
    /// Connection established by connecting to a back-end.
    Connect,
    /// Connection established by accepting a single inbound connection.
    AcceptOne,
    /// Connection established by the server accepting inbound.
    Server,
}

/// A target within a Trace RMI connection.
///
/// Ported from Ghidra's `TraceRmiTarget`. Represents a single debuggee
/// process managed through this connection. Typically a connection handles
/// only one target, but a back-end may create several (e.g., child processes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRmiConnectionTarget {
    /// Unique target identifier within this connection.
    pub target_id: String,
    /// Display name for UI.
    pub display_name: String,
    /// Process ID (if attached).
    pub pid: Option<u64>,
    /// Architecture string (e.g. "x86:LE:64:default").
    pub architecture: Option<String>,
    /// Whether the target is currently running.
    pub running: bool,
    /// Whether a transaction is currently open on this target.
    pub transaction_open: bool,
    /// The trace key assigned to this target.
    pub trace_key: Option<i64>,
    /// Last snapshot number created by the back-end.
    pub last_snapshot: i64,
}

impl TraceRmiConnectionTarget {
    /// Create a new connection target.
    pub fn new(target_id: impl Into<String>, display_name: impl Into<String>) -> Self {
        Self {
            target_id: target_id.into(),
            display_name: display_name.into(),
            pid: None,
            architecture: None,
            running: false,
            transaction_open: false,
            trace_key: None,
            last_snapshot: 0,
        }
    }

    /// Mark this target as having an open transaction.
    pub fn begin_transaction(&mut self) -> Result<(), String> {
        if self.transaction_open {
            return Err("Transaction already open".into());
        }
        self.transaction_open = true;
        Ok(())
    }

    /// Mark this target's transaction as closed.
    pub fn end_transaction(&mut self, _aborted: bool) -> Result<(), String> {
        if !self.transaction_open {
            return Err("No transaction open".into());
        }
        self.transaction_open = false;
        Ok(())
    }

    /// Update the last snapshot number.
    pub fn update_snapshot(&mut self, snap: i64) {
        if snap > self.last_snapshot {
            self.last_snapshot = snap;
        }
    }
}

/// A pending async request on the connection.
///
/// Ported from `RemoteAsyncResult`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRmiRequest {
    /// Request ID.
    pub request_id: u64,
    /// Method name that was invoked.
    pub method: String,
    /// When the request was issued.
    pub issued_at: Duration,
    /// Current state.
    pub state: PendingRequestState,
    /// Result value (JSON) if completed.
    pub result: Option<serde_json::Value>,
    /// Error message if failed.
    pub error: Option<String>,
}

/// State of a pending RMI request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingRequestState {
    /// Still waiting for response.
    Pending,
    /// Completed successfully.
    Completed,
    /// Failed with error.
    Failed,
    /// Was cancelled.
    Cancelled,
    /// Timed out waiting for response.
    TimedOut,
}

impl PendingRmiRequest {
    /// Create a new pending request.
    pub fn new(request_id: u64, method: impl Into<String>) -> Self {
        Self {
            request_id,
            method: method.into(),
            issued_at: Duration::ZERO,
            state: PendingRequestState::Pending,
            result: None,
            error: None,
        }
    }

    /// Mark as completed with a result.
    pub fn complete(&mut self, result: serde_json::Value) {
        self.state = PendingRequestState::Completed;
        self.result = Some(result);
    }

    /// Mark as failed with an error.
    pub fn fail(&mut self, error: impl Into<String>) {
        self.state = PendingRequestState::Failed;
        self.error = Some(error.into());
    }

    /// Mark as timed out.
    pub fn mark_timed_out(&mut self) {
        self.state = PendingRequestState::TimedOut;
    }

    /// Whether the request is still pending.
    pub fn is_pending(&self) -> bool {
        self.state == PendingRequestState::Pending
    }
}

/// A Trace RMI connection representing the transport channel to a back-end.
///
/// Ported from Ghidra's `TraceRmiConnection` interface and
/// `AbstractTraceRmiConnection`. This is the core transport abstraction
/// that manages the bidirectional request-reply channel, tracks targets,
/// and handles the connection lifecycle.
///
/// Each connection typically handles a single target (debuggee process),
/// but may handle multiple when the back-end creates child processes.
#[derive(Debug, Clone)]
pub struct TraceRmiConnection {
    /// Unique connection identifier.
    pub connection_id: String,
    /// Description of this connection.
    pub description: String,
    /// Remote address of the back-end.
    pub remote_address: Option<SocketAddr>,
    /// How this connection was established.
    pub connect_mode: RmiConnectMode,
    /// Current connection state.
    pub state: TraceRmiConnectionState,
    /// Targets managed by this connection.
    pub targets: BTreeMap<String, TraceRmiConnectionTarget>,
    /// Methods provided by the back-end.
    pub method_registry: RemoteMethodRegistry,
    /// Pending async requests.
    pub pending_requests: BTreeMap<u64, PendingRmiRequest>,
    /// Next request ID.
    pub next_request_id: u64,
    /// Whether any target has a transaction open.
    pub busy: bool,
    /// Connection creation time.
    pub created_at: Instant,
    /// Back-end kind.
    pub backend_kind: DebuggerClientKind,
}

impl TraceRmiConnection {
    /// Create a new connection.
    pub fn new(
        connection_id: impl Into<String>,
        backend_kind: DebuggerClientKind,
        connect_mode: RmiConnectMode,
    ) -> Self {
        Self {
            connection_id: connection_id.into(),
            description: String::new(),
            remote_address: None,
            connect_mode,
            state: TraceRmiConnectionState::Negotiating,
            targets: BTreeMap::new(),
            method_registry: RemoteMethodRegistry::new(),
            pending_requests: BTreeMap::new(),
            next_request_id: 1,
            busy: false,
            created_at: Instant::now(),
            backend_kind,
        }
    }

    /// Set the connection description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Set the remote address.
    pub fn set_remote_address(&mut self, addr: SocketAddr) {
        self.remote_address = Some(addr);
    }

    /// Transition to active state.
    pub fn set_active(&mut self) {
        self.state = TraceRmiConnectionState::Active;
    }

    /// Get the description including remote address.
    pub fn full_description(&self) -> String {
        match self.remote_address {
            Some(addr) => format!("{} at {}", self.description, addr),
            None => self.description.clone(),
        }
    }

    /// Add a target to this connection.
    pub fn add_target(&mut self, target: TraceRmiConnectionTarget) {
        self.targets.insert(target.target_id.clone(), target);
    }

    /// Get a target by ID.
    pub fn get_target(&self, target_id: &str) -> Option<&TraceRmiConnectionTarget> {
        self.targets.get(target_id)
    }

    /// Get a mutable target by ID.
    pub fn get_target_mut(&mut self, target_id: &str) -> Option<&mut TraceRmiConnectionTarget> {
        self.targets.get_mut(target_id)
    }

    /// Remove a target from this connection.
    pub fn remove_target(&mut self, target_id: &str) -> Option<TraceRmiConnectionTarget> {
        let target = self.targets.remove(target_id);
        self.recalculate_busy();
        target
    }

    /// Get all target IDs.
    pub fn target_ids(&self) -> Vec<String> {
        self.targets.keys().cloned().collect()
    }

    /// Check if a trace is a target of this connection.
    pub fn is_target(&self, trace_key: i64) -> bool {
        self.targets.values().any(|t| t.trace_key == Some(trace_key))
    }

    /// Whether the connection is busy (has open transactions).
    pub fn is_busy(&self) -> bool {
        self.busy
    }

    /// Whether a specific target has an open transaction.
    pub fn is_target_busy(&self, target_id: &str) -> bool {
        self.targets
            .get(target_id)
            .map(|t| t.transaction_open)
            .unwrap_or(false)
    }

    /// Recalculate the busy flag from target states.
    fn recalculate_busy(&mut self) {
        self.busy = self.targets.values().any(|t| t.transaction_open);
    }

    /// Begin a transaction on a target.
    pub fn begin_transaction(&mut self, target_id: &str) -> Result<(), String> {
        let target = self.targets.get_mut(target_id).ok_or("Target not found")?;
        target.begin_transaction()?;
        self.busy = true;
        Ok(())
    }

    /// End a transaction on a target.
    pub fn end_transaction(&mut self, target_id: &str, aborted: bool) -> Result<(), String> {
        let target = self.targets.get_mut(target_id).ok_or("Target not found")?;
        target.end_transaction(aborted)?;
        self.recalculate_busy();
        Ok(())
    }

    /// Issue a new async request and return its ID.
    pub fn issue_request(&mut self, method: impl Into<String>) -> u64 {
        let id = self.next_request_id;
        self.next_request_id += 1;
        let req = PendingRmiRequest::new(id, method);
        self.pending_requests.insert(id, req);
        id
    }

    /// Complete a pending request.
    pub fn complete_request(&mut self, request_id: u64, result: serde_json::Value) -> bool {
        if let Some(req) = self.pending_requests.get_mut(&request_id) {
            req.complete(result);
            return true;
        }
        false
    }

    /// Fail a pending request.
    pub fn fail_request(&mut self, request_id: u64, error: impl Into<String>) -> bool {
        if let Some(req) = self.pending_requests.get_mut(&request_id) {
            req.fail(error);
            return true;
        }
        false
    }

    /// Get the number of pending requests.
    pub fn pending_count(&self) -> usize {
        self.pending_requests.values().filter(|r| r.is_pending()).count()
    }

    /// Drain completed/failed requests (removes non-pending requests).
    pub fn drain_finished_requests(&mut self) -> Vec<PendingRmiRequest> {
        let mut finished = Vec::new();
        self.pending_requests.retain(|_, req| {
            if !req.is_pending() {
                finished.push(req.clone());
                false
            } else {
                true
            }
        });
        finished
    }

    /// Forcibly close all transactions on all targets.
    pub fn forcibly_close_transactions(&mut self) {
        for target in self.targets.values_mut() {
            target.transaction_open = false;
        }
        self.busy = false;
    }

    /// Forcefully remove a target (without notifying the back-end).
    pub fn force_close_target(&mut self, target_id: &str) -> Option<TraceRmiConnectionTarget> {
        let target = self.targets.remove(target_id);
        self.recalculate_busy();
        target
    }

    /// Close this connection.
    pub fn close(&mut self) {
        self.state = TraceRmiConnectionState::Closed;
        self.targets.clear();
        self.pending_requests.clear();
        self.busy = false;
    }

    /// Whether the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.state == TraceRmiConnectionState::Closed
    }
}

// ---------------------------------------------------------------------------
// TraceRmiTransport - orchestrates connections and backends
// ---------------------------------------------------------------------------

/// Transport configuration for the Trace RMI layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRmiTransportConfig {
    /// Address to bind the listener on.
    pub bind_address: String,
    /// Port for the listener.
    pub port: u16,
    /// Connection timeout.
    pub connect_timeout: Duration,
    /// Request timeout for individual method invocations.
    pub request_timeout: Duration,
    /// Whether to accept multiple clients.
    pub multi_client: bool,
    /// Maximum number of concurrent connections.
    pub max_connections: u32,
}

impl Default for TraceRmiTransportConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1".into(),
            port: 0,
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
            multi_client: false,
            max_connections: 8,
        }
    }
}

/// The Trace RMI transport layer managing all active connections.
///
/// Ported from Ghidra's `TraceRmiServer` / `TraceRmiHandler` orchestration.
/// This is the top-level coordinator for RMI transport, managing the
/// lifecycle of `TraceRmiConnection` instances and routing requests
/// between the front-end and back-end debuggers.
#[derive(Debug)]
pub struct TraceRmiTransport {
    /// Transport configuration.
    pub config: TraceRmiTransportConfig,
    /// Active connections, keyed by connection ID.
    connections: BTreeMap<String, TraceRmiConnection>,
    /// Whether the transport listener is running.
    pub listening: bool,
    /// Next connection ID counter.
    next_connection_id: u64,
}

impl TraceRmiTransport {
    /// Create a new transport with the given configuration.
    pub fn new(config: TraceRmiTransportConfig) -> Self {
        Self {
            config,
            connections: BTreeMap::new(),
            listening: false,
            next_connection_id: 1,
        }
    }

    /// Generate a new connection ID.
    fn next_connection_id(&mut self) -> String {
        let id = format!("conn-{}", self.next_connection_id);
        self.next_connection_id += 1;
        id
    }

    /// Start listening for connections.
    pub fn start_listening(&mut self) {
        self.listening = true;
    }

    /// Stop listening and close all connections.
    pub fn stop(&mut self) {
        self.listening = false;
        for conn in self.connections.values_mut() {
            conn.close();
        }
        self.connections.clear();
    }

    /// Accept a new inbound connection from a back-end.
    pub fn accept_connection(
        &mut self,
        backend_kind: DebuggerClientKind,
        remote_addr: Option<SocketAddr>,
    ) -> String {
        let conn_id = self.next_connection_id();
        let mut conn = TraceRmiConnection::new(&conn_id, backend_kind, RmiConnectMode::Server);
        if let Some(addr) = remote_addr {
            conn.set_remote_address(addr);
        }
        self.connections.insert(conn_id.clone(), conn);
        conn_id
    }

    /// Create an outbound connection to a back-end.
    pub fn connect(
        &mut self,
        backend_kind: DebuggerClientKind,
        remote_addr: SocketAddr,
    ) -> String {
        let conn_id = self.next_connection_id();
        let mut conn = TraceRmiConnection::new(&conn_id, backend_kind, RmiConnectMode::Connect);
        conn.set_remote_address(remote_addr);
        self.connections.insert(conn_id.clone(), conn);
        conn_id
    }

    /// Get a connection by ID.
    pub fn get_connection(&self, conn_id: &str) -> Option<&TraceRmiConnection> {
        self.connections.get(conn_id)
    }

    /// Get a mutable connection by ID.
    pub fn get_connection_mut(&mut self, conn_id: &str) -> Option<&mut TraceRmiConnection> {
        self.connections.get_mut(conn_id)
    }

    /// Close and remove a connection.
    pub fn close_connection(&mut self, conn_id: &str) -> bool {
        if let Some(mut conn) = self.connections.remove(conn_id) {
            conn.close();
            true
        } else {
            false
        }
    }

    /// Get all connection IDs.
    pub fn connection_ids(&self) -> Vec<String> {
        self.connections.keys().cloned().collect()
    }

    /// Get the number of active connections.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Get all active (non-closed) connections.
    pub fn active_connections(&self) -> Vec<&TraceRmiConnection> {
        self.connections.values().filter(|c| c.state.is_alive()).collect()
    }

    /// Get the connection that owns a given trace key.
    pub fn connection_for_trace(&self, trace_key: i64) -> Option<&TraceRmiConnection> {
        self.connections.values().find(|c| c.is_target(trace_key))
    }

    /// Close all connections.
    pub fn close_all(&mut self) {
        for conn in self.connections.values_mut() {
            conn.close();
        }
        self.connections.clear();
    }

    /// Get all targets across all connections.
    pub fn all_targets(&self) -> Vec<(&str, &TraceRmiConnectionTarget)> {
        self.connections
            .iter()
            .flat_map(|(cid, conn)| {
                conn.targets.values().map(move |t| (cid.as_str(), t))
            })
            .collect()
    }
}

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
///
/// This is the top-level coordinator that ties together:
/// - The RMI connection (`TraceRmiConnection`) for transport
/// - The debugger client (`DebuggerClient`) for backend abstraction
/// - The RMI client (`RmiClient`) for protobuf communication
/// - Memory/register mappers for address translation
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
    /// The RMI connection managing transport to the back-end.
    pub connection: Option<TraceRmiConnection>,
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
            connection: None,
            rmi_client: RmiClient::new(rmi_config),
            debugger_client: DebuggerClient::new(dbg_config),
            memory_mapper: MemoryMapper::new(),
            register_mapper: RegisterMapper::new(),
            target_map: BTreeMap::new(),
            created_at: 0,
        }
    }

    /// Attach an RMI connection to this session.
    pub fn set_connection(&mut self, connection: TraceRmiConnection) {
        self.connection = Some(connection);
    }

    /// Get the RMI connection, if any.
    pub fn connection(&self) -> Option<&TraceRmiConnection> {
        self.connection.as_ref()
    }

    /// Get the mutable RMI connection, if any.
    pub fn connection_mut(&mut self) -> Option<&mut TraceRmiConnection> {
        self.connection.as_mut()
    }

    /// Whether this session has an active connection.
    pub fn has_connection(&self) -> bool {
        self.connection.as_ref().map_or(false, |c| c.state.is_alive())
    }

    /// Whether the connection has any open transactions.
    pub fn is_busy(&self) -> bool {
        self.connection.as_ref().map_or(false, |c| c.is_busy())
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

    /// Close the session and its connection.
    pub fn close(&mut self) {
        self.state = TraceDebuggerSessionState::Terminated;
        if let Some(conn) = &mut self.connection {
            conn.close();
        }
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

    // -----------------------------------------------------------------------
    // TraceRmiConnectionState tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_connection_state_can_accept() {
        assert!(TraceRmiConnectionState::Active.can_accept_requests());
        assert!(TraceRmiConnectionState::Busy.can_accept_requests());
        assert!(!TraceRmiConnectionState::Negotiating.can_accept_requests());
        assert!(!TraceRmiConnectionState::Closed.can_accept_requests());
        assert!(!TraceRmiConnectionState::Error.can_accept_requests());
    }

    #[test]
    fn test_connection_state_alive() {
        assert!(TraceRmiConnectionState::Negotiating.is_alive());
        assert!(TraceRmiConnectionState::Active.is_alive());
        assert!(TraceRmiConnectionState::Busy.is_alive());
        assert!(TraceRmiConnectionState::Closing.is_alive());
        assert!(!TraceRmiConnectionState::Closed.is_alive());
        assert!(!TraceRmiConnectionState::Error.is_alive());
    }

    // -----------------------------------------------------------------------
    // TraceRmiConnectionTarget tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_connection_target_new() {
        let t = TraceRmiConnectionTarget::new("gdb-1", "GDB Process");
        assert_eq!(t.target_id, "gdb-1");
        assert_eq!(t.display_name, "GDB Process");
        assert!(t.pid.is_none());
        assert!(!t.running);
        assert!(!t.transaction_open);
        assert!(t.trace_key.is_none());
        assert_eq!(t.last_snapshot, 0);
    }

    #[test]
    fn test_connection_target_transaction() {
        let mut t = TraceRmiConnectionTarget::new("t1", "Target");
        assert!(!t.transaction_open);

        t.begin_transaction().unwrap();
        assert!(t.transaction_open);

        // Cannot begin twice
        assert!(t.begin_transaction().is_err());

        t.end_transaction(false).unwrap();
        assert!(!t.transaction_open);
    }

    #[test]
    fn test_connection_target_transaction_abort() {
        let mut t = TraceRmiConnectionTarget::new("t1", "Target");
        t.begin_transaction().unwrap();
        t.end_transaction(true).unwrap();
        assert!(!t.transaction_open);
    }

    #[test]
    fn test_connection_target_end_without_begin() {
        let mut t = TraceRmiConnectionTarget::new("t1", "Target");
        assert!(t.end_transaction(false).is_err());
    }

    #[test]
    fn test_connection_target_snapshot() {
        let mut t = TraceRmiConnectionTarget::new("t1", "Target");
        assert_eq!(t.last_snapshot, 0);
        t.update_snapshot(5);
        assert_eq!(t.last_snapshot, 5);
        t.update_snapshot(3); // Should not decrease
        assert_eq!(t.last_snapshot, 5);
        t.update_snapshot(10);
        assert_eq!(t.last_snapshot, 10);
    }

    // -----------------------------------------------------------------------
    // PendingRmiRequest tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_pending_request_new() {
        let req = PendingRmiRequest::new(1, "resume");
        assert_eq!(req.request_id, 1);
        assert_eq!(req.method, "resume");
        assert!(req.is_pending());
        assert!(req.result.is_none());
        assert!(req.error.is_none());
    }

    #[test]
    fn test_pending_request_complete() {
        let mut req = PendingRmiRequest::new(1, "readMemory");
        req.complete(serde_json::json!({"data": "deadbeef"}));
        assert!(!req.is_pending());
        assert_eq!(req.state, PendingRequestState::Completed);
        assert!(req.result.is_some());
    }

    #[test]
    fn test_pending_request_fail() {
        let mut req = PendingRmiRequest::new(2, "resume");
        req.fail("timeout");
        assert!(!req.is_pending());
        assert_eq!(req.state, PendingRequestState::Failed);
        assert_eq!(req.error.as_deref(), Some("timeout"));
    }

    #[test]
    fn test_pending_request_timeout() {
        let mut req = PendingRmiRequest::new(3, "step");
        req.mark_timed_out();
        assert!(!req.is_pending());
        assert_eq!(req.state, PendingRequestState::TimedOut);
    }

    // -----------------------------------------------------------------------
    // TraceRmiConnection tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_connection_new() {
        let conn = TraceRmiConnection::new("c1", DebuggerClientKind::Gdb, RmiConnectMode::Server);
        assert_eq!(conn.connection_id, "c1");
        assert_eq!(conn.backend_kind, DebuggerClientKind::Gdb);
        assert_eq!(conn.connect_mode, RmiConnectMode::Server);
        assert_eq!(conn.state, TraceRmiConnectionState::Negotiating);
        assert!(conn.targets.is_empty());
        assert!(!conn.is_busy());
        assert!(!conn.is_closed());
    }

    #[test]
    fn test_connection_description() {
        let conn = TraceRmiConnection::new("c1", DebuggerClientKind::Gdb, RmiConnectMode::Connect)
            .with_description("GDB remote");
        assert_eq!(conn.description, "GDB remote");
    }

    #[test]
    fn test_connection_remote_address() {
        let mut conn = TraceRmiConnection::new("c1", DebuggerClientKind::Gdb, RmiConnectMode::Connect);
        assert!(conn.remote_address.is_none());
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        conn.set_remote_address(addr);
        assert_eq!(conn.remote_address, Some(addr));
        assert!(conn.full_description().contains("127.0.0.1:1234"));
    }

    #[test]
    fn test_connection_state_transition() {
        let mut conn = TraceRmiConnection::new("c1", DebuggerClientKind::Gdb, RmiConnectMode::Connect);
        assert_eq!(conn.state, TraceRmiConnectionState::Negotiating);
        conn.set_active();
        assert_eq!(conn.state, TraceRmiConnectionState::Active);
        assert!(conn.state.can_accept_requests());
    }

    #[test]
    fn test_connection_targets() {
        let mut conn = TraceRmiConnection::new("c1", DebuggerClientKind::Gdb, RmiConnectMode::Connect);
        conn.add_target(TraceRmiConnectionTarget::new("t1", "Target 1"));
        conn.add_target(TraceRmiConnectionTarget::new("t2", "Target 2"));

        assert_eq!(conn.targets.len(), 2);
        assert!(conn.get_target("t1").is_some());
        assert!(conn.get_target("t2").is_some());
        assert!(conn.get_target("t3").is_none());
        assert_eq!(conn.target_ids().len(), 2);
    }

    #[test]
    fn test_connection_target_removal() {
        let mut conn = TraceRmiConnection::new("c1", DebuggerClientKind::Gdb, RmiConnectMode::Connect);
        conn.add_target(TraceRmiConnectionTarget::new("t1", "Target 1"));
        assert_eq!(conn.targets.len(), 1);

        let removed = conn.remove_target("t1");
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().target_id, "t1");
        assert!(conn.targets.is_empty());
    }

    #[test]
    fn test_connection_is_target() {
        let mut conn = TraceRmiConnection::new("c1", DebuggerClientKind::Gdb, RmiConnectMode::Connect);
        let mut target = TraceRmiConnectionTarget::new("t1", "Target");
        target.trace_key = Some(42);
        conn.add_target(target);

        assert!(conn.is_target(42));
        assert!(!conn.is_target(99));
    }

    #[test]
    fn test_connection_busy() {
        let mut conn = TraceRmiConnection::new("c1", DebuggerClientKind::Gdb, RmiConnectMode::Connect);
        conn.add_target(TraceRmiConnectionTarget::new("t1", "Target"));
        assert!(!conn.is_busy());

        conn.begin_transaction("t1").unwrap();
        assert!(conn.is_busy());
        assert!(conn.is_target_busy("t1"));

        conn.end_transaction("t1", false).unwrap();
        assert!(!conn.is_busy());
    }

    #[test]
    fn test_connection_busy_nonexistent_target() {
        let mut conn = TraceRmiConnection::new("c1", DebuggerClientKind::Gdb, RmiConnectMode::Connect);
        assert!(conn.begin_transaction("nope").is_err());
        assert!(conn.end_transaction("nope", false).is_err());
    }

    #[test]
    fn test_connection_force_close_transactions() {
        let mut conn = TraceRmiConnection::new("c1", DebuggerClientKind::Gdb, RmiConnectMode::Connect);
        conn.add_target(TraceRmiConnectionTarget::new("t1", "Target"));
        conn.begin_transaction("t1").unwrap();
        assert!(conn.is_busy());

        conn.forcibly_close_transactions();
        assert!(!conn.is_busy());
    }

    #[test]
    fn test_connection_requests() {
        let mut conn = TraceRmiConnection::new("c1", DebuggerClientKind::Gdb, RmiConnectMode::Connect);
        let rid = conn.issue_request("resume");
        assert_eq!(rid, 1);
        assert_eq!(conn.pending_count(), 1);

        conn.complete_request(rid, serde_json::json!("ok"));
        assert_eq!(conn.pending_count(), 0);

        let rid2 = conn.issue_request("step");
        conn.fail_request(rid2, "error");
        assert_eq!(conn.pending_count(), 0);
    }

    #[test]
    fn test_connection_drain_finished() {
        let mut conn = TraceRmiConnection::new("c1", DebuggerClientKind::Gdb, RmiConnectMode::Connect);
        let r1 = conn.issue_request("resume");
        let r2 = conn.issue_request("step");
        let _r3 = conn.issue_request("readMemory");

        conn.complete_request(r1, serde_json::json!("ok"));
        conn.fail_request(r2, "err");

        let finished = conn.drain_finished_requests();
        assert_eq!(finished.len(), 2);
        assert_eq!(conn.pending_count(), 1); // r3 still pending
    }

    #[test]
    fn test_connection_close() {
        let mut conn = TraceRmiConnection::new("c1", DebuggerClientKind::Gdb, RmiConnectMode::Connect);
        conn.add_target(TraceRmiConnectionTarget::new("t1", "Target"));
        conn.set_active();
        assert!(!conn.is_closed());

        conn.close();
        assert!(conn.is_closed());
        assert!(conn.targets.is_empty());
        assert!(conn.pending_requests.is_empty());
    }

    #[test]
    fn test_connection_force_close_target() {
        let mut conn = TraceRmiConnection::new("c1", DebuggerClientKind::Gdb, RmiConnectMode::Connect);
        conn.add_target(TraceRmiConnectionTarget::new("t1", "Target"));
        let removed = conn.force_close_target("t1");
        assert!(removed.is_some());
        assert!(conn.targets.is_empty());
    }

    #[test]
    fn test_connection_request_nonexistent() {
        let mut conn = TraceRmiConnection::new("c1", DebuggerClientKind::Gdb, RmiConnectMode::Connect);
        assert!(!conn.complete_request(999, serde_json::json!(null)));
        assert!(!conn.fail_request(999, "nope"));
    }

    // -----------------------------------------------------------------------
    // TraceRmiTransport tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_transport_new() {
        let config = TraceRmiTransportConfig::default();
        let transport = TraceRmiTransport::new(config);
        assert!(!transport.listening);
        assert_eq!(transport.connection_count(), 0);
    }

    #[test]
    fn test_transport_listen() {
        let config = TraceRmiTransportConfig::default();
        let mut transport = TraceRmiTransport::new(config);
        assert!(!transport.listening);

        transport.start_listening();
        assert!(transport.listening);
    }

    #[test]
    fn test_transport_accept_connection() {
        let config = TraceRmiTransportConfig::default();
        let mut transport = TraceRmiTransport::new(config);
        transport.start_listening();

        let conn_id = transport.accept_connection(DebuggerClientKind::Gdb, None);
        assert_eq!(transport.connection_count(), 1);
        assert!(transport.get_connection(&conn_id).is_some());
    }

    #[test]
    fn test_transport_connect() {
        let config = TraceRmiTransportConfig::default();
        let mut transport = TraceRmiTransport::new(config);
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        let conn_id = transport.connect(DebuggerClientKind::Lldb, addr);
        let conn = transport.get_connection(&conn_id).unwrap();
        assert_eq!(conn.connect_mode, RmiConnectMode::Connect);
        assert_eq!(conn.remote_address, Some(addr));
    }

    #[test]
    fn test_transport_close_connection() {
        let config = TraceRmiTransportConfig::default();
        let mut transport = TraceRmiTransport::new(config);
        let conn_id = transport.accept_connection(DebuggerClientKind::Gdb, None);
        assert_eq!(transport.connection_count(), 1);

        assert!(transport.close_connection(&conn_id));
        assert_eq!(transport.connection_count(), 0);
        assert!(!transport.close_connection("nope"));
    }

    #[test]
    fn test_transport_stop() {
        let config = TraceRmiTransportConfig::default();
        let mut transport = TraceRmiTransport::new(config);
        transport.start_listening();
        transport.accept_connection(DebuggerClientKind::Gdb, None);
        transport.accept_connection(DebuggerClientKind::Lldb, None);

        transport.stop();
        assert!(!transport.listening);
        assert_eq!(transport.connection_count(), 0);
    }

    #[test]
    fn test_transport_active_connections() {
        let config = TraceRmiTransportConfig::default();
        let mut transport = TraceRmiTransport::new(config);
        let c1 = transport.accept_connection(DebuggerClientKind::Gdb, None);
        let c2 = transport.accept_connection(DebuggerClientKind::Lldb, None);

        // Set one active, close the other
        transport.get_connection_mut(&c1).unwrap().set_active();
        transport.close_connection(&c2);

        let active = transport.active_connections();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].connection_id, c1);
    }

    #[test]
    fn test_transport_connection_for_trace() {
        let config = TraceRmiTransportConfig::default();
        let mut transport = TraceRmiTransport::new(config);
        let c1 = transport.accept_connection(DebuggerClientKind::Gdb, None);

        let mut target = TraceRmiConnectionTarget::new("t1", "Target");
        target.trace_key = Some(42);
        transport.get_connection_mut(&c1).unwrap().add_target(target);

        assert!(transport.connection_for_trace(42).is_some());
        assert!(transport.connection_for_trace(99).is_none());
    }

    #[test]
    fn test_transport_all_targets() {
        let config = TraceRmiTransportConfig::default();
        let mut transport = TraceRmiTransport::new(config);
        let c1 = transport.accept_connection(DebuggerClientKind::Gdb, None);
        let c2 = transport.accept_connection(DebuggerClientKind::Lldb, None);

        transport.get_connection_mut(&c1).unwrap()
            .add_target(TraceRmiConnectionTarget::new("t1", "GDB"));
        transport.get_connection_mut(&c2).unwrap()
            .add_target(TraceRmiConnectionTarget::new("t2", "LLDB"));

        let targets = transport.all_targets();
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn test_transport_close_all() {
        let config = TraceRmiTransportConfig::default();
        let mut transport = TraceRmiTransport::new(config);
        transport.accept_connection(DebuggerClientKind::Gdb, None);
        transport.accept_connection(DebuggerClientKind::Lldb, None);
        assert_eq!(transport.connection_count(), 2);

        transport.close_all();
        assert_eq!(transport.connection_count(), 0);
    }

    #[test]
    fn test_transport_config_default() {
        let config = TraceRmiTransportConfig::default();
        assert_eq!(config.bind_address, "127.0.0.1");
        assert_eq!(config.max_connections, 8);
        assert!(!config.multi_client);
    }

    #[test]
    fn test_transport_multiple_backends() {
        let config = TraceRmiTransportConfig::default();
        let mut transport = TraceRmiTransport::new(config);

        let c1 = transport.accept_connection(DebuggerClientKind::Gdb, None);
        let _c2 = transport.accept_connection(DebuggerClientKind::Lldb, None);
        let _c3 = transport.accept_connection(DebuggerClientKind::Drgn, None);
        let c4 = transport.accept_connection(DebuggerClientKind::X64dbg, None);

        assert_eq!(transport.connection_count(), 4);
        assert_eq!(
            transport.get_connection(&c1).unwrap().backend_kind,
            DebuggerClientKind::Gdb
        );
        assert_eq!(
            transport.get_connection(&c4).unwrap().backend_kind,
            DebuggerClientKind::X64dbg
        );
    }

    // -----------------------------------------------------------------------
    // Session integration tests
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Session-Connection integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_session_connection_attach() {
        let mut session = TraceDebuggerSession::new("s1", DebuggerClientKind::Gdb, "test");
        assert!(!session.has_connection());

        let conn = TraceRmiConnection::new("c1", DebuggerClientKind::Gdb, RmiConnectMode::Connect);
        session.set_connection(conn);
        assert!(session.connection().is_some());
        assert_eq!(session.connection().unwrap().connection_id, "c1");
    }

    #[test]
    fn test_session_connection_alive() {
        let mut session = TraceDebuggerSession::new("s1", DebuggerClientKind::Gdb, "test");
        let mut conn = TraceRmiConnection::new("c1", DebuggerClientKind::Gdb, RmiConnectMode::Connect);
        conn.set_active();
        session.set_connection(conn);

        assert!(session.has_connection());
        assert!(!session.is_busy());
    }

    #[test]
    fn test_session_connection_busy() {
        let mut session = TraceDebuggerSession::new("s1", DebuggerClientKind::Gdb, "test");
        let mut conn = TraceRmiConnection::new("c1", DebuggerClientKind::Gdb, RmiConnectMode::Connect);
        conn.add_target(TraceRmiConnectionTarget::new("t1", "Target"));
        conn.begin_transaction("t1").unwrap();
        session.set_connection(conn);

        assert!(session.is_busy());
    }

    #[test]
    fn test_session_close_closes_connection() {
        let mut session = TraceDebuggerSession::new("s1", DebuggerClientKind::Gdb, "test");
        let mut conn = TraceRmiConnection::new("c1", DebuggerClientKind::Gdb, RmiConnectMode::Connect);
        conn.set_active();
        session.set_connection(conn);

        assert!(session.has_connection());
        session.close();

        assert_eq!(session.state, TraceDebuggerSessionState::Terminated);
        // Connection should also be closed
        assert!(session.connection().unwrap().is_closed());
    }

    #[test]
    fn test_session_no_connection_defaults() {
        let mut session = TraceDebuggerSession::new("s1", DebuggerClientKind::Gdb, "test");
        assert!(!session.has_connection());
        assert!(!session.is_busy());
        assert!(session.connection().is_none());
        assert!(session.connection_mut().is_none());
    }

    #[test]
    fn test_rmi_connect_mode_variants() {
        assert_ne!(RmiConnectMode::Connect, RmiConnectMode::AcceptOne);
        assert_ne!(RmiConnectMode::AcceptOne, RmiConnectMode::Server);
        assert_eq!(RmiConnectMode::Connect, RmiConnectMode::Connect);
    }

    #[test]
    fn test_pending_request_state_variants() {
        assert_ne!(PendingRequestState::Pending, PendingRequestState::Completed);
        assert_ne!(PendingRequestState::Failed, PendingRequestState::TimedOut);
        assert_ne!(PendingRequestState::Cancelled, PendingRequestState::Failed);
    }

    #[test]
    fn test_connection_state_all_variants() {
        let states = [
            TraceRmiConnectionState::Negotiating,
            TraceRmiConnectionState::Active,
            TraceRmiConnectionState::Busy,
            TraceRmiConnectionState::Closing,
            TraceRmiConnectionState::Closed,
            TraceRmiConnectionState::Error,
        ];
        for s in &states {
            match s {
                TraceRmiConnectionState::Active | TraceRmiConnectionState::Busy => {
                    assert!(s.can_accept_requests());
                    assert!(s.is_alive());
                }
                TraceRmiConnectionState::Closed | TraceRmiConnectionState::Error => {
                    assert!(!s.can_accept_requests());
                    assert!(!s.is_alive());
                }
                _ => {
                    assert!(!s.can_accept_requests());
                    assert!(s.is_alive());
                }
            }
        }
    }
}
