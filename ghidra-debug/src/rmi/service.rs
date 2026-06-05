//! Server-side Trace RMI handler and connection management.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.service.tracermi` package.
//!
//! Provides `TraceRmiHandler`, `TraceRmiServer`, `TraceRmiTarget`, and
//! supporting types for managing connections from debug backends.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Connect mode
// ---------------------------------------------------------------------------

/// How the RMI connection was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectMode {
    /// The connection was initiated by a server listening for clients.
    Server,
    /// The connection was initiated by a client connecting to a back-end.
    Client,
}

// ---------------------------------------------------------------------------
// RemoteMethod / RemoteParameter
// ---------------------------------------------------------------------------

/// A remote method available through the RMI interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteMethod {
    /// The method name.
    pub name: String,
    /// Display name for UI.
    pub display_name: String,
    /// Parameter definitions.
    pub parameters: Vec<RemoteParameter>,
    /// Whether this method is enabled.
    pub enabled: bool,
}

/// A parameter of a remote method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteParameter {
    /// Parameter name.
    pub name: String,
    /// Parameter type name.
    pub type_name: String,
    /// Whether this parameter is required.
    pub required: bool,
    /// Default value (JSON).
    pub default_value: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// RemoteMethodRegistry
// ---------------------------------------------------------------------------

/// A registry of remote methods.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemoteMethodRegistry {
    methods: BTreeMap<String, RemoteMethod>,
}

impl RemoteMethodRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a method.
    pub fn register(&mut self, method: RemoteMethod) {
        self.methods.insert(method.name.clone(), method);
    }

    /// Get a method by name.
    pub fn get(&self, name: &str) -> Option<&RemoteMethod> {
        self.methods.get(name)
    }

    /// Get all method names.
    pub fn method_names(&self) -> Vec<&str> {
        self.methods.keys().map(|s| s.as_str()).collect()
    }

    /// Get all methods.
    pub fn methods(&self) -> impl Iterator<Item = &RemoteMethod> {
        self.methods.values()
    }

    /// Number of registered methods.
    pub fn len(&self) -> usize {
        self.methods.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.methods.is_empty()
    }
}

// ---------------------------------------------------------------------------
// RemoteAsyncResult
// ---------------------------------------------------------------------------

/// The state of a pending remote method invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AsyncResultState {
    /// Still pending.
    Pending,
    /// Completed successfully.
    Completed,
    /// Failed with an error.
    Failed,
    /// Was cancelled.
    Cancelled,
    /// Timed out.
    TimedOut,
}

/// An async result for a remote method invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteAsyncResult {
    /// The request ID.
    pub request_id: u64,
    /// Current state.
    pub state: AsyncResultState,
    /// Result value (JSON) if completed.
    pub result: Option<serde_json::Value>,
    /// Error message if failed.
    pub error: Option<String>,
}

impl RemoteAsyncResult {
    /// Create a pending result.
    pub fn pending(request_id: u64) -> Self {
        Self {
            request_id,
            state: AsyncResultState::Pending,
            result: None,
            error: None,
        }
    }

    /// Mark as completed.
    pub fn complete(&mut self, result: serde_json::Value) {
        self.state = AsyncResultState::Completed;
        self.result = Some(result);
    }

    /// Mark as failed.
    pub fn fail(&mut self, error: impl Into<String>) {
        self.state = AsyncResultState::Failed;
        self.error = Some(error.into());
    }

    /// Whether the result is still pending.
    pub fn is_pending(&self) -> bool {
        self.state == AsyncResultState::Pending
    }
}

// ---------------------------------------------------------------------------
// TraceRmiTarget
// ---------------------------------------------------------------------------

/// A target process accessible through the RMI connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRmiTarget {
    /// Target identifier.
    pub target_id: String,
    /// Display name.
    pub display_name: String,
    /// Process ID (if attached).
    pub pid: Option<u64>,
    /// Architecture.
    pub architecture: Option<String>,
    /// Whether the target is currently running.
    pub running: bool,
    /// Whether we have an active session.
    pub has_session: bool,
}

impl TraceRmiTarget {
    /// Create a new target.
    pub fn new(target_id: impl Into<String>, display_name: impl Into<String>) -> Self {
        Self {
            target_id: target_id.into(),
            display_name: display_name.into(),
            pid: None,
            architecture: None,
            running: false,
            has_session: false,
        }
    }
}

// ---------------------------------------------------------------------------
// OpenTrace
// ---------------------------------------------------------------------------

/// An open trace on the server side, tracking its RMI connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenTrace {
    /// The trace key.
    pub trace_key: i64,
    /// The trace file path.
    pub path: String,
    /// Language ID.
    pub language_id: String,
    /// Compiler spec ID.
    pub compiler_spec_id: String,
    /// Pending async results.
    pub pending_results: BTreeMap<u64, RemoteAsyncResult>,
    /// Next request ID.
    pub next_request_id: u64,
}

impl OpenTrace {
    /// Create a new open trace.
    pub fn new(
        trace_key: i64,
        path: impl Into<String>,
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
    ) -> Self {
        Self {
            trace_key,
            path: path.into(),
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
            pending_results: BTreeMap::new(),
            next_request_id: 1,
        }
    }

    /// Issue a new async request.
    pub fn issue_request(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id += 1;
        self.pending_results
            .insert(id, RemoteAsyncResult::pending(id));
        id
    }

    /// Complete a request.
    pub fn complete_request(&mut self, id: u64, result: serde_json::Value) -> bool {
        if let Some(r) = self.pending_results.get_mut(&id) {
            r.complete(result);
            return true;
        }
        false
    }

    /// Fail a request.
    pub fn fail_request(&mut self, id: u64, error: impl Into<String>) -> bool {
        if let Some(r) = self.pending_results.get_mut(&id) {
            r.fail(error);
            return true;
        }
        false
    }

    /// Number of pending requests.
    pub fn pending_count(&self) -> usize {
        self.pending_results
            .values()
            .filter(|r| r.is_pending())
            .count()
    }
}

// ---------------------------------------------------------------------------
// TraceRmiHandler
// ---------------------------------------------------------------------------

/// The server-side handler managing an RMI connection from a back-end.
///
/// Ported from Ghidra's `TraceRmiHandler`. Manages the lifecycle of
/// traces, targets, and method invocations for a single connected client.
#[derive(Debug, Clone)]
pub struct TraceRmiHandler {
    /// Connection mode.
    pub connect_mode: ConnectMode,
    /// Remote address description.
    pub address: String,
    /// Open traces.
    pub traces: BTreeMap<i64, OpenTrace>,
    /// Available targets.
    pub targets: BTreeMap<String, TraceRmiTarget>,
    /// Registered methods.
    pub method_registry: RemoteMethodRegistry,
    /// Whether the handler is connected.
    pub connected: bool,
    /// Next trace key.
    pub next_trace_key: i64,
}

impl TraceRmiHandler {
    /// Create a new handler.
    pub fn new(connect_mode: ConnectMode, address: impl Into<String>) -> Self {
        Self {
            connect_mode,
            address: address.into(),
            traces: BTreeMap::new(),
            targets: BTreeMap::new(),
            method_registry: RemoteMethodRegistry::new(),
            connected: true,
            next_trace_key: 1,
        }
    }

    /// Open a new trace.
    pub fn open_trace(
        &mut self,
        path: impl Into<String>,
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
    ) -> i64 {
        let key = self.next_trace_key;
        self.next_trace_key += 1;
        let trace = OpenTrace::new(key, path, language_id, compiler_spec_id);
        self.traces.insert(key, trace);
        key
    }

    /// Close a trace.
    pub fn close_trace(&mut self, key: i64) -> bool {
        self.traces.remove(&key).is_some()
    }

    /// Get a trace by key.
    pub fn get_trace(&self, key: i64) -> Option<&OpenTrace> {
        self.traces.get(&key)
    }

    /// Get a mutable trace by key.
    pub fn get_trace_mut(&mut self, key: i64) -> Option<&mut OpenTrace> {
        self.traces.get_mut(&key)
    }

    /// Add a target.
    pub fn add_target(&mut self, target: TraceRmiTarget) {
        self.targets.insert(target.target_id.clone(), target);
    }

    /// Get a target.
    pub fn get_target(&self, target_id: &str) -> Option<&TraceRmiTarget> {
        self.targets.get(target_id)
    }

    /// Register a remote method.
    pub fn register_method(&mut self, method: RemoteMethod) {
        self.method_registry.register(method);
    }

    /// Disconnect the handler.
    pub fn disconnect(&mut self) {
        self.connected = false;
        self.traces.clear();
        self.targets.clear();
    }

    /// Get all open trace keys.
    pub fn open_trace_keys(&self) -> Vec<i64> {
        self.traces.keys().copied().collect()
    }
}

// ---------------------------------------------------------------------------
// TraceRmiServer
// ---------------------------------------------------------------------------

/// Configuration for the RMI server listener.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRmiServerConfig {
    /// The address to bind to.
    pub bind_address: String,
    /// The port to listen on.
    pub port: u16,
    /// Whether to accept multiple clients.
    pub multi_client: bool,
}

impl Default for TraceRmiServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1".into(),
            port: 0,
            multi_client: false,
        }
    }
}

/// The RMI server, listening for connections from debug backends.
///
/// Ported from Ghidra's `TraceRmiServer`.
#[derive(Debug, Clone)]
pub struct TraceRmiServer {
    /// Server configuration.
    pub config: TraceRmiServerConfig,
    /// Active handlers (one per connected client).
    pub handlers: BTreeMap<String, TraceRmiHandler>,
    /// Whether the server is running.
    pub running: bool,
}

impl TraceRmiServer {
    /// Create a new server.
    pub fn new(config: TraceRmiServerConfig) -> Self {
        Self {
            config,
            handlers: BTreeMap::new(),
            running: false,
        }
    }

    /// Start the server (mark as running).
    pub fn start(&mut self) {
        self.running = true;
    }

    /// Stop the server.
    pub fn stop(&mut self) {
        self.running = false;
        for handler in self.handlers.values_mut() {
            handler.disconnect();
        }
        self.handlers.clear();
    }

    /// Accept a new client connection.
    pub fn accept_connection(&mut self, client_address: impl Into<String>) -> &mut TraceRmiHandler {
        let addr = client_address.into();
        let handler = TraceRmiHandler::new(ConnectMode::Server, &addr);
        self.handlers.insert(addr.clone(), handler);
        self.handlers.get_mut(&addr).unwrap()
    }

    /// Get the number of active connections.
    pub fn connection_count(&self) -> usize {
        self.handlers.len()
    }

    /// The local address as a string.
    pub fn local_address(&self) -> String {
        format!("{}:{}", self.config.bind_address, self.config.port)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remote_method_registry() {
        let mut registry = RemoteMethodRegistry::new();
        assert!(registry.is_empty());

        registry.register(RemoteMethod {
            name: "resume".into(),
            display_name: "Resume".into(),
            parameters: vec![],
            enabled: true,
        });

        assert_eq!(registry.len(), 1);
        assert!(registry.get("resume").is_some());
        assert!(registry.get("step").is_none());
    }

    #[test]
    fn test_remote_method_with_params() {
        let method = RemoteMethod {
            name: "setBreakpoint".into(),
            display_name: "Set Breakpoint".into(),
            parameters: vec![
                RemoteParameter {
                    name: "address".into(),
                    type_name: "u64".into(),
                    required: true,
                    default_value: None,
                },
                RemoteParameter {
                    name: "kind".into(),
                    type_name: "string".into(),
                    required: false,
                    default_value: Some(serde_json::json!("software")),
                },
            ],
            enabled: true,
        };
        assert_eq!(method.parameters.len(), 2);
        assert!(method.parameters[0].required);
        assert!(!method.parameters[1].required);
    }

    #[test]
    fn test_remote_async_result() {
        let mut result = RemoteAsyncResult::pending(1);
        assert!(result.is_pending());

        result.complete(serde_json::json!("ok"));
        assert!(!result.is_pending());
        assert!(result.result.is_some());
    }

    #[test]
    fn test_remote_async_result_fail() {
        let mut result = RemoteAsyncResult::pending(2);
        result.fail("timeout");
        assert_eq!(result.state, AsyncResultState::Failed);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_trace_rmi_target() {
        let mut target = TraceRmiTarget::new("gdb-1", "GDB Target");
        assert_eq!(target.target_id, "gdb-1");
        assert!(!target.running);

        target.running = true;
        target.pid = Some(1234);
        assert!(target.running);
        assert_eq!(target.pid, Some(1234));
    }

    #[test]
    fn test_open_trace() {
        let mut trace = OpenTrace::new(1, "/tmp/test.trace", "x86:LE:64:default", "default");
        assert_eq!(trace.pending_count(), 0);

        let req_id = trace.issue_request();
        assert_eq!(trace.pending_count(), 1);

        trace.complete_request(req_id, serde_json::json!("done"));
        assert_eq!(trace.pending_count(), 0);
    }

    #[test]
    fn test_open_trace_fail_request() {
        let mut trace = OpenTrace::new(1, "/tmp/test", "l", "c");
        let id = trace.issue_request();
        trace.fail_request(id, "error");
        assert_eq!(trace.pending_count(), 0);
    }

    #[test]
    fn test_trace_rmi_handler() {
        let mut handler = TraceRmiHandler::new(ConnectMode::Client, "10.0.0.1:5000");
        assert!(handler.connected);

        let key = handler.open_trace("/tmp/t", "lang", "cs");
        assert_eq!(key, 1);
        assert!(handler.get_trace(key).is_some());

        handler.register_method(RemoteMethod {
            name: "resume".into(),
            display_name: "Resume".into(),
            parameters: vec![],
            enabled: true,
        });
        assert_eq!(handler.method_registry.len(), 1);

        handler.close_trace(key);
        assert!(handler.get_trace(key).is_none());

        handler.disconnect();
        assert!(!handler.connected);
    }

    #[test]
    fn test_trace_rmi_handler_targets() {
        let mut handler = TraceRmiHandler::new(ConnectMode::Server, "127.0.0.1:5000");
        handler.add_target(TraceRmiTarget::new("t1", "Target 1"));
        assert!(handler.get_target("t1").is_some());
        assert!(handler.get_target("t2").is_none());
    }

    #[test]
    fn test_trace_rmi_handler_multiple_traces() {
        let mut handler = TraceRmiHandler::new(ConnectMode::Client, "addr");
        handler.open_trace("/a", "l", "c");
        handler.open_trace("/b", "l", "c");
        assert_eq!(handler.open_trace_keys().len(), 2);
    }

    #[test]
    fn test_trace_rmi_server() {
        let config = TraceRmiServerConfig {
            bind_address: "0.0.0.0".into(),
            port: 12345,
            multi_client: true,
        };
        let mut server = TraceRmiServer::new(config);
        assert!(!server.running);

        server.start();
        assert!(server.running);
        assert_eq!(server.connection_count(), 0);

        server.accept_connection("10.0.0.2:5000");
        assert_eq!(server.connection_count(), 1);

        server.stop();
        assert!(!server.running);
        assert_eq!(server.connection_count(), 0);
    }

    #[test]
    fn test_trace_rmi_server_local_address() {
        let config = TraceRmiServerConfig {
            bind_address: "127.0.0.1".into(),
            port: 54321,
            ..Default::default()
        };
        let server = TraceRmiServer::new(config);
        assert_eq!(server.local_address(), "127.0.0.1:54321");
    }

    #[test]
    fn test_connect_mode() {
        assert_ne!(ConnectMode::Server, ConnectMode::Client);
    }

    #[test]
    fn test_async_result_state() {
        assert_ne!(AsyncResultState::Pending, AsyncResultState::Completed);
        assert_ne!(AsyncResultState::Failed, AsyncResultState::Cancelled);
    }
}
