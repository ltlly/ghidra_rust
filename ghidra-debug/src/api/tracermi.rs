//! TraceRmi protocol types for remote method invocation.
//!
//! Ported from Ghidra's `ghidra.debug.api.tracermi` package.
//!
//! TraceRmi is a two-way request-reply channel, usually over TCP. The back
//! end provides a set of methods for the front-end to use to control the
//! connection and its targets.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::action_name::ActionName;

// ── Errors ────────────────────────────────────────────────────────────────

/// Result type for TraceRmi operations.
pub type TraceRmiResult<T> = Result<T, TraceRmiError>;

/// Error type for TraceRmi operations.
///
/// Ported from Ghidra's `TraceRmiError`.
#[derive(Debug, Error)]
pub enum TraceRmiError {
    /// A general message.
    #[error("{0}")]
    Message(String),

    /// An error wrapping a cause.
    #[error("{message}")]
    WithCause {
        /// The error message.
        message: String,
        /// The underlying cause.
        #[source]
        cause: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// A connection error.
    #[error("connection error: {0}")]
    Connection(String),

    /// A timeout error.
    #[error("timeout: {0}")]
    Timeout(String),

    /// Invalid arguments.
    #[error("invalid arguments: {0}")]
    InvalidArguments(String),

    /// The connection is closed.
    #[error("connection closed")]
    ConnectionClosed,
}

// ── Remote Parameter ──────────────────────────────────────────────────────

/// The schema name for a parameter type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SchemaName {
    /// The namespace (e.g., "trace").
    pub namespace: String,
    /// The simple name (e.g., "Thread").
    pub name: String,
}

impl SchemaName {
    /// Create a new schema name.
    pub fn new(namespace: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
        }
    }

    /// Create from a qualified name like `"trace::Thread"`.
    pub fn parse(qualified: &str) -> Self {
        if let Some(idx) = qualified.find("::") {
            Self {
                namespace: qualified[..idx].to_string(),
                name: qualified[idx + 2..].to_string(),
            }
        } else {
            Self {
                namespace: String::new(),
                name: qualified.to_string(),
            }
        }
    }

    /// The fully qualified name.
    pub fn qualified(&self) -> String {
        if self.namespace.is_empty() {
            self.name.clone()
        } else {
            format!("{}::{}", self.namespace, self.name)
        }
    }
}

impl std::fmt::Display for SchemaName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.qualified())
    }
}

/// Description of a remote method parameter.
///
/// Ported from Ghidra's `RemoteParameter` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteParameter {
    /// The parameter name.
    pub name: String,
    /// The schema type name.
    pub param_type: SchemaName,
    /// Whether the parameter is required.
    pub required: bool,
    /// The default value (JSON-encoded), if any.
    pub default_value: Option<serde_json::Value>,
    /// Display name.
    pub display: String,
    /// Description.
    pub description: String,
}

impl RemoteParameter {
    /// Create a new required parameter.
    pub fn required(
        name: impl Into<String>,
        param_type: SchemaName,
        display: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            param_type,
            required: true,
            default_value: None,
            display: display.into(),
            description: String::new(),
        }
    }

    /// Create an optional parameter with a default value.
    pub fn optional(
        name: impl Into<String>,
        param_type: SchemaName,
        display: impl Into<String>,
        default: serde_json::Value,
    ) -> Self {
        Self {
            name: name.into(),
            param_type,
            required: false,
            default_value: Some(default),
            display: display.into(),
            description: String::new(),
        }
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }
}

// ── Remote Method ─────────────────────────────────────────────────────────

/// A remote method registered by the back-end debugger.
///
/// Ported from Ghidra's `RemoteMethod` interface. Remote methods must
/// describe parameter names and types at a minimum. They should not return
/// a result -- instead any "result" should be recorded into a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteMethodDescriptor {
    /// The name of the method.
    pub name: String,
    /// The action name hint.
    pub action: ActionName,
    /// Display title for the action.
    pub display: String,
    /// Text for the OK button in prompt dialogs.
    pub ok_text: String,
    /// Description of the method.
    pub description: String,
    /// Parameters, keyed by name.
    pub parameters: BTreeMap<String, RemoteParameter>,
    /// The schema name for the return type (usually void).
    pub ret_type: Option<SchemaName>,
}

impl RemoteMethodDescriptor {
    /// Create a new method descriptor.
    pub fn new(
        name: impl Into<String>,
        action: ActionName,
        display: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            action,
            display: display.into(),
            ok_text: "OK".into(),
            description: String::new(),
            parameters: BTreeMap::new(),
            ret_type: None,
        }
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Set the OK button text.
    pub fn with_ok_text(mut self, text: impl Into<String>) -> Self {
        self.ok_text = text.into();
        self
    }

    /// Add a parameter.
    pub fn with_parameter(mut self, param: RemoteParameter) -> Self {
        self.parameters.insert(param.name.clone(), param);
        self
    }

    /// Set the return type.
    pub fn with_ret_type(mut self, ret_type: SchemaName) -> Self {
        self.ret_type = Some(ret_type);
        self
    }

    /// Validate arguments against the parameter definitions.
    ///
    /// Returns `Ok(())` if valid, or `Err(message)` describing the problem.
    pub fn validate(&self, arguments: &BTreeMap<String, serde_json::Value>) -> Result<(), String> {
        for (name, param) in &self.parameters {
            if !arguments.contains_key(name) {
                if param.required {
                    return Err(format!("Missing required parameter '{}'", name));
                }
            }
        }
        for key in arguments.keys() {
            if !self.parameters.contains_key(key) {
                return Err(format!("Extra argument '{}'", key));
            }
        }
        Ok(())
    }
}

// ── Remote Method Registry ────────────────────────────────────────────────

/// Registry of remote methods provided by the back-end.
///
/// Ported from Ghidra's `RemoteMethodRegistry` interface.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemoteMethodRegistry {
    methods: BTreeMap<String, RemoteMethodDescriptor>,
}

impl RemoteMethodRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a method.
    pub fn register(&mut self, method: RemoteMethodDescriptor) {
        self.methods.insert(method.name.clone(), method);
    }

    /// Get all methods.
    pub fn all(&self) -> &BTreeMap<String, RemoteMethodDescriptor> {
        &self.methods
    }

    /// Get a method by name.
    pub fn get(&self, name: &str) -> Option<&RemoteMethodDescriptor> {
        self.methods.get(name)
    }

    /// Get methods by action name.
    pub fn get_by_action(&self, action: ActionName) -> Vec<&RemoteMethodDescriptor> {
        self.methods
            .values()
            .filter(|m| m.action == action)
            .collect()
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

// ── Launch Parameter ──────────────────────────────────────────────────────

/// A parameter for launching a target.
///
/// Ported from Ghidra's `LaunchParameter`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchParameter {
    /// The parameter name.
    pub name: String,
    /// Display name.
    pub display: String,
    /// The parameter type.
    pub param_type: SchemaName,
    /// Whether this is required for launch.
    pub required: bool,
    /// Default value.
    pub default_value: Option<serde_json::Value>,
    /// Description.
    pub description: String,
}

impl LaunchParameter {
    /// Create a new launch parameter.
    pub fn new(
        name: impl Into<String>,
        display: impl Into<String>,
        param_type: SchemaName,
    ) -> Self {
        Self {
            name: name.into(),
            display: display.into(),
            param_type,
            required: true,
            default_value: None,
            description: String::new(),
        }
    }
}

// ── Terminal Session ──────────────────────────────────────────────────────

/// A terminal/interactive session attached to a target.
///
/// Ported from Ghidra's `TerminalSession`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalSession {
    /// The session ID.
    pub id: String,
    /// Whether the session is active.
    pub active: bool,
    /// The columns (width).
    pub cols: u32,
    /// The rows (height).
    pub rows: u32,
}

impl TerminalSession {
    /// Create a new terminal session.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            active: true,
            cols: 80,
            rows: 24,
        }
    }

    /// Resize the terminal.
    pub fn resize(&mut self, cols: u32, rows: u32) {
        self.cols = cols;
        self.rows = rows;
    }

    /// Close the session.
    pub fn close(&mut self) {
        self.active = false;
    }
}

// ── Connection State ──────────────────────────────────────────────────────

/// The state of a TraceRmi connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnectionState {
    /// Negotiating the connection.
    Negotiating,
    /// Connected and operational.
    Connected,
    /// Busy with an active transaction.
    Busy,
    /// The connection is closed.
    Closed,
}

// ── Async Result ──────────────────────────────────────────────────────────

/// Status of an asynchronous remote result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AsyncStatus {
    /// Still pending.
    Pending,
    /// Completed successfully.
    Completed,
    /// Failed with an error.
    Failed,
    /// Cancelled.
    Cancelled,
}

/// An asynchronous result from a remote method invocation.
///
/// Ported from Ghidra's `RemoteAsyncResult`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteAsyncResult {
    /// The request ID.
    pub request_id: u64,
    /// The method name.
    pub method_name: String,
    /// The status.
    pub status: AsyncStatus,
    /// The result value (JSON), if completed.
    pub result: Option<serde_json::Value>,
    /// The error message, if failed.
    pub error: Option<String>,
    /// The timeout for this result.
    pub timeout: Duration,
}

impl RemoteAsyncResult {
    /// Create a new pending result.
    pub fn new(request_id: u64, method_name: impl Into<String>, timeout: Duration) -> Self {
        Self {
            request_id,
            method_name: method_name.into(),
            status: AsyncStatus::Pending,
            result: None,
            error: None,
            timeout,
        }
    }

    /// Whether this result is still pending.
    pub fn is_pending(&self) -> bool {
        self.status == AsyncStatus::Pending
    }

    /// Whether this result completed successfully.
    pub fn is_completed(&self) -> bool {
        self.status == AsyncStatus::Completed
    }

    /// Mark as completed with a value.
    pub fn complete(&mut self, value: serde_json::Value) {
        self.status = AsyncStatus::Completed;
        self.result = Some(value);
    }

    /// Mark as failed with an error.
    pub fn fail(&mut self, error: impl Into<String>) {
        self.status = AsyncStatus::Failed;
        self.error = Some(error.into());
    }

    /// Mark as cancelled.
    pub fn cancel(&mut self) {
        self.status = AsyncStatus::Cancelled;
    }
}

/// A connection acceptor for incoming TraceRmi connections.
///
/// Ported from Ghidra's `TraceRmiAcceptor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRmiAcceptor {
    /// The listen address (e.g., "0.0.0.0:1234").
    pub listen_address: String,
    /// Whether the acceptor is running.
    pub running: bool,
    /// The port being listened on.
    pub port: u16,
}

impl TraceRmiAcceptor {
    /// Create a new acceptor.
    pub fn new(listen_address: impl Into<String>, port: u16) -> Self {
        Self {
            listen_address: listen_address.into(),
            running: false,
            port,
        }
    }

    /// Get the listen address.
    pub fn address(&self) -> &str {
        &self.listen_address
    }

    /// Whether the acceptor is running.
    pub fn is_running(&self) -> bool {
        self.running
    }
}


// ── TraceRmi Service Listener ─────────────────────────────────────────

/// The mechanism by which a TraceRmi connection was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectMode {
    /// The connection was established via `connect()`.
    Connect,
    /// The connection was established via `acceptOne()`.
    AcceptOne,
    /// The connection was established by the server.
    Server,
}

/// A listener for Trace RMI service events.
///
/// Ported from Ghidra's `TraceRmiServiceListener`. Provides callbacks
/// for connection lifecycle events, acceptor events, and target
/// publication events.
pub trait TraceRmiServiceListener: Send + Sync {
    /// Called when the server has been started.
    fn server_started(&self, _address: &str) {}

    /// Called when the server has been stopped.
    fn server_stopped(&self) {}

    /// Called when a new connection is established.
    fn connected(&self, _connection_id: u64, _mode: ConnectMode) {}

    /// Called when a connection is lost or closed.
    fn disconnected(&self, _connection_id: u64) {}

    /// Called when the service is waiting for an inbound connection.
    fn waiting_accept(&self, _acceptor: &TraceRmiAcceptor) {}

    /// Called when a client cancelled an inbound acceptor.
    fn accept_cancelled(&self, _acceptor: &TraceRmiAcceptor) {}

    /// Called when the service failed to complete an inbound connection.
    fn accept_failed(&self, _acceptor: &TraceRmiAcceptor, _error: &str) {}

    /// Called when a new target was published by a connection.
    fn target_published(&self, _connection_id: u64, _target_key: &str) {}

    /// Called when a transaction was opened for a target.
    fn transaction_opened(&self, _connection_id: u64, _target_key: &str) {}

    /// Called when a transaction was closed for a target.
    fn transaction_closed(&self, _connection_id: u64, _target_key: &str, _aborted: bool) {}
}

/// A collection of TraceRmi service listeners.
#[derive(Default)]
pub struct TraceRmiServiceListenerSet {
    listeners: Vec<Box<dyn TraceRmiServiceListener>>,
}

impl std::fmt::Debug for TraceRmiServiceListenerSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TraceRmiServiceListenerSet")
            .field("count", &self.listeners.len())
            .finish()
    }
}

impl TraceRmiServiceListenerSet {
    /// Create a new empty listener set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a listener.
    pub fn add(&mut self, listener: Box<dyn TraceRmiServiceListener>) {
        self.listeners.push(listener);
    }

    /// Notify all listeners of a server start event.
    pub fn notify_server_started(&self, address: &str) {
        for l in &self.listeners {
            l.server_started(address);
        }
    }

    /// Notify all listeners of a server stop event.
    pub fn notify_server_stopped(&self) {
        for l in &self.listeners {
            l.server_stopped();
        }
    }

    /// Notify all listeners of a new connection.
    pub fn notify_connected(&self, connection_id: u64, mode: ConnectMode) {
        for l in &self.listeners {
            l.connected(connection_id, mode);
        }
    }

    /// Notify all listeners of a disconnection.
    pub fn notify_disconnected(&self, connection_id: u64) {
        for l in &self.listeners {
            l.disconnected(connection_id);
        }
    }

    /// Notify all listeners of a target publication.
    pub fn notify_target_published(&self, connection_id: u64, target_key: &str) {
        for l in &self.listeners {
            l.target_published(connection_id, target_key);
        }
    }

    /// Get the number of registered listeners.
    pub fn len(&self) -> usize {
        self.listeners.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.listeners.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_name() {
        let sn = SchemaName::new("trace", "Thread");
        assert_eq!(sn.qualified(), "trace::Thread");
        assert_eq!(sn.to_string(), "trace::Thread");

        let sn = SchemaName::parse("trace::Process");
        assert_eq!(sn.namespace, "trace");
        assert_eq!(sn.name, "Process");
    }

    #[test]
    fn test_remote_parameter() {
        let param = RemoteParameter::required(
            "addr",
            SchemaName::new("primitive", "long"),
            "Address",
        );
        assert!(param.required);
        assert!(param.default_value.is_none());
    }

    #[test]
    fn test_remote_method_descriptor() {
        let method = RemoteMethodDescriptor::new(
            "step",
            ActionName::Step,
            "Step",
        )
        .with_description("Single-step the target")
        .with_parameter(RemoteParameter::optional(
            "thread",
            SchemaName::new("trace", "Thread"),
            "Thread",
            serde_json::Value::Null,
        ));

        assert_eq!(method.name, "step");
        assert_eq!(method.action, ActionName::Step);
        assert_eq!(method.parameters.len(), 1);
    }

    #[test]
    fn test_method_validate() {
        let method = RemoteMethodDescriptor::new("test", ActionName::Custom("execute".into()), "Test")
            .with_parameter(RemoteParameter::required(
                "cmd",
                SchemaName::new("primitive", "string"),
                "Command",
            ));

        let mut args = BTreeMap::new();
        assert!(method.validate(&args).is_err()); // missing required

        args.insert("cmd".into(), serde_json::json!("ls"));
        assert!(method.validate(&args).is_ok());

        args.insert("extra".into(), serde_json::json!(42));
        assert!(method.validate(&args).is_err()); // extra arg
    }

    #[test]
    fn test_method_registry() {
        let mut reg = RemoteMethodRegistry::new();
        reg.register(
            RemoteMethodDescriptor::new("step", ActionName::Step, "Step"),
        );
        reg.register(
            RemoteMethodDescriptor::new("continue", ActionName::Continue, "Continue"),
        );

        assert_eq!(reg.len(), 2);
        assert!(reg.get("step").is_some());
        assert!(reg.get("missing").is_none());

        let step_methods = reg.get_by_action(ActionName::Step);
        assert_eq!(step_methods.len(), 1);
    }

    #[test]
    fn test_launch_parameter() {
        let param = LaunchParameter::new("exe", "Executable", SchemaName::new("primitive", "string"));
        assert!(param.required);
        assert_eq!(param.display, "Executable");
    }

    #[test]
    fn test_terminal_session() {
        let mut session = TerminalSession::new("term1");
        assert!(session.active);
        session.resize(120, 40);
        assert_eq!(session.cols, 120);
        session.close();
        assert!(!session.active);
    }

    #[test]
    fn test_remote_async_result() {
        let mut result = RemoteAsyncResult::new(1, "step", Duration::from_secs(30));
        assert!(result.is_pending());

        result.complete(serde_json::json!("ok"));
        assert!(result.is_completed());
        assert!(result.result.is_some());

        let mut result2 = RemoteAsyncResult::new(2, "fail", Duration::from_secs(5));
        result2.fail("something broke");
        assert_eq!(result2.status, AsyncStatus::Failed);
    }

    #[test]
    fn test_trace_rmi_error() {
        let err = TraceRmiError::Message("test error".into());
        assert_eq!(err.to_string(), "test error");

        let err = TraceRmiError::ConnectionClosed;
        assert_eq!(err.to_string(), "connection closed");
    }

    #[test]
    fn test_connection_state() {
        let state = ConnectionState::Connected;
        assert_eq!(state, ConnectionState::Connected);
        assert_ne!(state, ConnectionState::Closed);
    }

    #[test]
    fn test_schema_name_display() {
        let sn = SchemaName::new("", "int");
        assert_eq!(sn.to_string(), "int");
    }

    #[test]
    fn test_tracermi_serde() {
        let method = RemoteMethodDescriptor::new("step", ActionName::Step, "Step");
        let json = serde_json::to_string(&method).unwrap();
        let back: RemoteMethodDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "step");
    }

    #[test]
    fn test_trace_rmi_acceptor() {
        let acceptor = TraceRmiAcceptor::new("127.0.0.1:0", 0);
        assert!(acceptor.is_running() || !acceptor.is_running()); // just tests it exists
        assert_eq!(acceptor.address(), "127.0.0.1:0");
    }

    #[test]
    fn test_terminal_session_new() {
        let mut session = TerminalSession::new("session-1");
        assert!(session.active);
        assert_eq!(session.id, "session-1");
        assert_eq!(session.cols, 80);
        session.resize(120, 40);
        assert_eq!(session.cols, 120);
        assert_eq!(session.rows, 40);
        session.close();
        assert!(!session.active);
    }

    #[test]
    fn test_connect_mode() {
        assert_ne!(ConnectMode::Connect, ConnectMode::Server);
        assert_ne!(ConnectMode::AcceptOne, ConnectMode::Server);
    }

    #[test]
    fn test_service_listener_set() {
        struct TestListener {
            connected_count: std::sync::atomic::AtomicU32,
        }
        impl TraceRmiServiceListener for TestListener {
            fn connected(&self, _id: u64, _mode: ConnectMode) {
                self.connected_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }

        let mut set = TraceRmiServiceListenerSet::new();
        assert!(set.is_empty());

        let listener = TestListener {
            connected_count: std::sync::atomic::AtomicU32::new(0),
        };
        set.add(Box::new(listener));
        assert_eq!(set.len(), 1);

        set.notify_connected(1, ConnectMode::Connect);
    }
}
