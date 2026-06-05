//! Trace RMI connection types.
//!
//! Ported from Ghidra's `ghidra.debug.api.tracermi` package:
//! - TraceRmiConnection
//! - TraceRmiError
//! - TraceRmiLaunchOffer
//! - TraceRmiServiceListener
//! - RemoteMethod / RemoteParameter
//! - RemoteMethodRegistry
//! - TerminalSession
//!
//! These provide the RMI (Remote Method Invocation) infrastructure for
//! communicating with debug backends.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An error from a Trace RMI operation.
///
/// Ported from Ghidra's `TraceRmiError`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRmiError {
    /// The error type name.
    pub error_type: String,
    /// The error message.
    pub message: String,
    /// Optional stack trace.
    pub stack_trace: Option<String>,
}

impl TraceRmiError {
    /// Create a new RMI error.
    pub fn new(error_type: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error_type: error_type.into(),
            message: message.into(),
            stack_trace: None,
        }
    }

    /// Create with a stack trace.
    pub fn with_stack_trace(mut self, trace: impl Into<String>) -> Self {
        self.stack_trace = Some(trace.into());
        self
    }
}

impl std::fmt::Display for TraceRmiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.error_type, self.message)
    }
}

impl std::error::Error for TraceRmiError {}

/// A parameter for a remote method.
///
/// Ported from Ghidra's `RemoteParameter`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteParameter {
    /// The parameter name.
    pub name: String,
    /// The parameter type (as a string).
    pub param_type: String,
    /// Whether this parameter is required.
    pub required: bool,
    /// A description of the parameter.
    pub description: String,
    /// Default value if not required.
    pub default_value: Option<serde_json::Value>,
}

impl RemoteParameter {
    /// Create a new remote parameter.
    pub fn new(
        name: impl Into<String>,
        param_type: impl Into<String>,
        required: bool,
    ) -> Self {
        Self {
            name: name.into(),
            param_type: param_type.into(),
            required,
            description: String::new(),
            default_value: None,
        }
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Set the default value.
    pub fn with_default(mut self, default: serde_json::Value) -> Self {
        self.default_value = Some(default);
        self.required = false;
        self
    }
}

/// A method available on a remote debug target.
///
/// Ported from Ghidra's `RemoteMethod`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteMethod {
    /// The method name.
    pub name: String,
    /// The method parameters.
    pub parameters: Vec<RemoteParameter>,
    /// A description of the method.
    pub description: String,
    /// Whether this method requires a connected target.
    pub requires_target: bool,
}

impl RemoteMethod {
    /// Create a new remote method.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            parameters: Vec::new(),
            description: String::new(),
            requires_target: true,
        }
    }

    /// Add a parameter.
    pub fn with_parameter(mut self, param: RemoteParameter) -> Self {
        self.parameters.push(param);
        self
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Get the number of required parameters.
    pub fn required_param_count(&self) -> usize {
        self.parameters.iter().filter(|p| p.required).count()
    }

    /// Find a parameter by name.
    pub fn get_parameter(&self, name: &str) -> Option<&RemoteParameter> {
        self.parameters.iter().find(|p| p.name == name)
    }
}

/// A registry of available remote methods.
///
/// Ported from Ghidra's `RemoteMethodRegistry`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemoteMethodRegistry {
    /// The registered methods by name.
    pub methods: HashMap<String, RemoteMethod>,
}

impl RemoteMethodRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            methods: HashMap::new(),
        }
    }

    /// Register a method.
    pub fn register(&mut self, method: RemoteMethod) {
        self.methods.insert(method.name.clone(), method);
    }

    /// Get a method by name.
    pub fn get_method(&self, name: &str) -> Option<&RemoteMethod> {
        self.methods.get(name)
    }

    /// Get all method names.
    pub fn method_names(&self) -> Vec<&str> {
        self.methods.keys().map(|s| s.as_str()).collect()
    }

    /// Get the number of registered methods.
    pub fn len(&self) -> usize {
        self.methods.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.methods.is_empty()
    }
}

/// A connection to a remote debug target via RMI.
///
/// Ported from Ghidra's `TraceRmiConnection`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRmiConnection {
    /// The connection URL or address.
    pub url: String,
    /// Whether the connection is active.
    pub connected: bool,
    /// The available methods on this connection.
    pub method_registry: RemoteMethodRegistry,
    /// The connection ID.
    pub connection_id: String,
    /// The protocol version.
    pub protocol_version: String,
}

impl TraceRmiConnection {
    /// Create a new RMI connection.
    pub fn new(url: impl Into<String>, connection_id: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            connected: false,
            method_registry: RemoteMethodRegistry::new(),
            connection_id: connection_id.into(),
            protocol_version: "1.0".to_string(),
        }
    }

    /// Whether the connection is active.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Set the connection state.
    pub fn set_connected(&mut self, connected: bool) {
        self.connected = connected;
    }

    /// Register a method on this connection.
    pub fn register_method(&mut self, method: RemoteMethod) {
        self.method_registry.register(method);
    }

    /// Get a method by name.
    pub fn get_method(&self, name: &str) -> Option<&RemoteMethod> {
        self.method_registry.get_method(name)
    }
}

/// An offer to launch a debug session.
///
/// Ported from Ghidra's `TraceRmiLaunchOffer`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRmiLaunchOffer {
    /// The display name for this launch offer.
    pub display_name: String,
    /// The launch scheme (e.g., "gdb", "lldb", "dbgeng").
    pub scheme: String,
    /// The description.
    pub description: String,
    /// The parameters for launching.
    pub parameters: Vec<RemoteParameter>,
}

impl TraceRmiLaunchOffer {
    /// Create a new launch offer.
    pub fn new(
        display_name: impl Into<String>,
        scheme: impl Into<String>,
    ) -> Self {
        Self {
            display_name: display_name.into(),
            scheme: scheme.into(),
            description: String::new(),
            parameters: Vec::new(),
        }
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Add a parameter.
    pub fn with_parameter(mut self, param: RemoteParameter) -> Self {
        self.parameters.push(param);
        self
    }
}

/// A listener for Trace RMI service events.
///
/// Ported from Ghidra's `TraceRmiServiceListener`.
pub trait TraceRmiServiceListener: std::fmt::Debug {
    /// Called when a new connection is established.
    fn connection_opened(&self, connection: &TraceRmiConnection);

    /// Called when a connection is closed.
    fn connection_closed(&self, connection: &TraceRmiConnection);

    /// Called when a connection error occurs.
    fn connection_error(&self, connection: &TraceRmiConnection, error: &TraceRmiError);
}

/// A terminal session for interacting with a debug backend.
///
/// Ported from Ghidra's `TerminalSession`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalSession {
    /// The session ID.
    pub session_id: String,
    /// Whether the session is active.
    pub active: bool,
    /// The command history.
    pub history: Vec<String>,
    /// The current prompt.
    pub prompt: String,
}

impl TerminalSession {
    /// Create a new terminal session.
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            active: false,
            history: Vec::new(),
            prompt: "(dbg) ".to_string(),
        }
    }

    /// Add a command to the history.
    pub fn add_to_history(&mut self, command: impl Into<String>) {
        self.history.push(command.into());
    }

    /// Get the last command.
    pub fn last_command(&self) -> Option<&str> {
        self.history.last().map(|s| s.as_str())
    }

    /// Set the session as active.
    pub fn set_active(&mut self, active: bool) {
        self.active = active;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_rmi_error() {
        let err = TraceRmiError::new("ConnectionError", "Connection refused");
        assert_eq!(err.error_type, "ConnectionError");
        assert_eq!(err.message, "Connection refused");
        assert!(format!("{}", err).contains("Connection refused"));
    }

    #[test]
    fn test_remote_parameter() {
        let param = RemoteParameter::new("target", "string", true)
            .with_description("The target to connect to");
        assert_eq!(param.name, "target");
        assert!(param.required);
        assert_eq!(param.description, "The target to connect to");
    }

    #[test]
    fn test_remote_parameter_with_default() {
        let param = RemoteParameter::new("timeout", "number", true)
            .with_default(serde_json::json!(30));
        assert!(!param.required);
        assert!(param.default_value.is_some());
    }

    #[test]
    fn test_remote_method() {
        let method = RemoteMethod::new("launch")
            .with_parameter(RemoteParameter::new("cmd", "string", true))
            .with_parameter(RemoteParameter::new("args", "array", false))
            .with_description("Launch a debug session");

        assert_eq!(method.required_param_count(), 1);
        assert!(method.get_parameter("cmd").is_some());
        assert!(method.get_parameter("args").is_some());
        assert!(method.get_parameter("missing").is_none());
    }

    #[test]
    fn test_remote_method_registry() {
        let mut registry = RemoteMethodRegistry::new();
        assert!(registry.is_empty());

        registry.register(RemoteMethod::new("launch"));
        registry.register(RemoteMethod::new("resume"));

        assert_eq!(registry.len(), 2);
        assert!(registry.get_method("launch").is_some());

        let mut names = registry.method_names();
        names.sort();
        assert_eq!(names, vec!["launch", "resume"]);
    }

    #[test]
    fn test_trace_rmi_connection() {
        let mut conn = TraceRmiConnection::new("localhost:1234", "conn-1");
        assert!(!conn.is_connected());

        conn.set_connected(true);
        assert!(conn.is_connected());

        conn.register_method(RemoteMethod::new("launch"));
        assert!(conn.get_method("launch").is_some());
    }

    #[test]
    fn test_trace_rmi_launch_offer() {
        let offer = TraceRmiLaunchOffer::new("GDB", "gdb")
            .with_description("Launch via GDB")
            .with_parameter(RemoteParameter::new("cmd", "string", true));

        assert_eq!(offer.display_name, "GDB");
        assert_eq!(offer.scheme, "gdb");
        assert_eq!(offer.parameters.len(), 1);
    }

    #[test]
    fn test_terminal_session() {
        let mut session = TerminalSession::new("session-1");
        assert!(!session.active);
        assert!(session.last_command().is_none());

        session.set_active(true);
        session.add_to_history("help");
        session.add_to_history("registers");

        assert_eq!(session.last_command(), Some("registers"));
        assert_eq!(session.history.len(), 2);
    }

    #[test]
    fn test_trace_rmi_error_display() {
        let err = TraceRmiError::new("Timeout", "Operation timed out")
            .with_stack_trace("at line 42");
        assert!(err.stack_trace.is_some());
        assert!(format!("{}", err).contains("Timeout"));
    }
}
