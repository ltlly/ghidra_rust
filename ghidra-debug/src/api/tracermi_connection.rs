//! Trace RMI connection, method, and parameter types.
//!
//! Ported from Ghidra's `ghidra.debug.api.tracermi` package:
//! - `TraceRmiConnection`: The connection interface to a TraceRmi back end.
//! - `RemoteMethod`: A remote method registered by the back-end debugger.
//! - `RemoteMethodRegistry`: Registry of remote methods for a connection.
//! - `RemoteParameter`: A parameter of a remote method.
//! - `TerminalSession`: A terminal session for interacting with the back end.
//! - `TraceRmiLaunchOffer`: An offer to launch a debug session.
//! - `TraceRmiError`: Error types for RMI operations.
//!
//! TraceRmi is a two-way request-reply channel for debug targets. The back end
//! provides methods for creating and populating a Trace. The front end can invoke
//! these methods to control the debug session.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;

/// A connection to a TraceRmi back end.
///
/// Ported from `TraceRmiConnection`. Represents a two-way request-reply
/// channel, usually over TCP, to a debug back end.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRmiConnectionInfo {
    /// Unique connection identifier.
    pub connection_id: String,
    /// Human-readable description of this connection.
    pub description: String,
    /// Remote address (host:port).
    pub remote_address: Option<String>,
    /// Whether the connection is active.
    pub is_active: bool,
    /// Connection creation timestamp.
    pub created_at: u64,
    /// The method registry for this connection.
    pub methods: RemoteMethodRegistry,
    /// The set of traces (targets) associated with this connection.
    pub targets: Vec<TraceRmiTarget>,
    /// Last snapshot numbers per trace.
    pub last_snapshots: BTreeMap<String, i64>,
}

impl TraceRmiConnectionInfo {
    /// Create a new connection info with the given ID and description.
    pub fn new(connection_id: &str, description: &str) -> Self {
        Self {
            connection_id: connection_id.to_string(),
            description: description.to_string(),
            remote_address: None,
            is_active: true,
            created_at: 0,
            methods: RemoteMethodRegistry::new(),
            targets: Vec::new(),
            last_snapshots: BTreeMap::new(),
        }
    }

    /// Get the method registry.
    pub fn methods(&self) -> &RemoteMethodRegistry {
        &self.methods
    }

    /// Get a mutable reference to the method registry.
    pub fn methods_mut(&mut self) -> &mut RemoteMethodRegistry {
        &mut self.methods
    }

    /// Get the last snapshot for a given trace ID.
    pub fn last_snapshot(&self, trace_id: &str) -> i64 {
        self.last_snapshots.get(trace_id).copied().unwrap_or(0)
    }

    /// Add a target trace to this connection.
    pub fn add_target(&mut self, target: TraceRmiTarget) {
        self.targets.push(target);
    }

    /// Remove a target trace from this connection.
    pub fn remove_target(&mut self, trace_id: &str) -> Option<TraceRmiTarget> {
        if let Some(pos) = self.targets.iter().position(|t| t.trace_id == trace_id) {
            Some(self.targets.remove(pos))
        } else {
            None
        }
    }
}

/// A target trace associated with a TraceRmi connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRmiTarget {
    /// The trace identifier.
    pub trace_id: String,
    /// The trace name.
    pub name: String,
    /// Whether this target is currently active.
    pub is_active: bool,
}

/// A remote method registered by the back-end debugger.
///
/// Ported from `RemoteMethod`. Methods must describe their parameters
/// at minimum. They should also provide display information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteMethod {
    /// The name of the method.
    pub name: String,
    /// A string hinting at the UI action this method achieves.
    pub action: Option<String>,
    /// A title to display in the UI for this action.
    pub display: String,
    /// Text to display in the OK button of any prompt dialog.
    pub ok_text: Option<String>,
    /// The method's parameters.
    pub parameters: Vec<RemoteParameter>,
    /// Whether this method should display the prompt dialog.
    pub hidden: bool,
    /// Whether this method requires a connected back end.
    pub requires_connection: bool,
    /// The method's return type description, if any.
    pub return_type: Option<String>,
    /// A longer description of the method.
    pub description: Option<String>,
}

impl RemoteMethod {
    /// Create a new remote method with the given name and display name.
    pub fn new(name: &str, display: &str) -> Self {
        Self {
            name: name.to_string(),
            action: None,
            display: display.to_string(),
            ok_text: None,
            parameters: Vec::new(),
            hidden: false,
            requires_connection: true,
            return_type: None,
            description: None,
        }
    }

    /// Add a parameter to this method.
    pub fn with_parameter(mut self, param: RemoteParameter) -> Self {
        self.parameters.push(param);
        self
    }

    /// Set the action hint.
    pub fn with_action(mut self, action: &str) -> Self {
        self.action = Some(action.to_string());
        self
    }

    /// Set the OK button text.
    pub fn with_ok_text(mut self, text: &str) -> Self {
        self.ok_text = Some(text.to_string());
        self
    }

    /// Set whether this method is hidden.
    pub fn with_hidden(mut self, hidden: bool) -> Self {
        self.hidden = hidden;
        self
    }

    /// Set the return type.
    pub fn with_return_type(mut self, ret_type: &str) -> Self {
        self.return_type = Some(ret_type.to_string());
        self
    }

    /// Set the description.
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = Some(desc.to_string());
        self
    }

    /// Get a parameter by name.
    pub fn parameter(&self, name: &str) -> Option<&RemoteParameter> {
        self.parameters.iter().find(|p| p.name == name)
    }
}

/// A parameter of a remote method.
///
/// Ported from `RemoteParameter`. Describes a single input parameter
/// to a remote method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteParameter {
    /// The parameter name.
    pub name: String,
    /// A display name for the parameter.
    pub display: String,
    /// The schema name for this parameter's value type.
    pub schema_name: Option<String>,
    /// Whether this parameter is required.
    pub required: bool,
    /// The default value, if any.
    pub default_value: Option<String>,
    /// A longer description of the parameter.
    pub description: Option<String>,
    /// The fixed value, if this parameter is always a specific value.
    pub fixed_value: Option<String>,
}

impl RemoteParameter {
    /// Create a new required parameter.
    pub fn required(name: &str, display: &str) -> Self {
        Self {
            name: name.to_string(),
            display: display.to_string(),
            schema_name: None,
            required: true,
            default_value: None,
            description: None,
            fixed_value: None,
        }
    }

    /// Create an optional parameter with a default value.
    pub fn optional(name: &str, display: &str, default: &str) -> Self {
        Self {
            name: name.to_string(),
            display: display.to_string(),
            schema_name: None,
            required: false,
            default_value: Some(default.to_string()),
            description: None,
            fixed_value: None,
        }
    }

    /// Create a fixed (hidden) parameter.
    pub fn fixed(name: &str, value: &str) -> Self {
        Self {
            name: name.to_string(),
            display: name.to_string(),
            schema_name: None,
            required: false,
            default_value: None,
            description: None,
            fixed_value: Some(value.to_string()),
        }
    }

    /// Set the schema name.
    pub fn with_schema(mut self, schema: &str) -> Self {
        self.schema_name = Some(schema.to_string());
        self
    }

    /// Set the description.
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = Some(desc.to_string());
        self
    }
}

/// Registry of remote methods for a connection.
///
/// Ported from `RemoteMethodRegistry`. Contains the set of methods
/// available on a particular back-end connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteMethodRegistry {
    methods: BTreeMap<String, RemoteMethod>,
}

impl RemoteMethodRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            methods: BTreeMap::new(),
        }
    }

    /// Register a method.
    pub fn register(&mut self, method: RemoteMethod) {
        self.methods.insert(method.name.clone(), method);
    }

    /// Get a method by name.
    pub fn get(&self, name: &str) -> Option<&RemoteMethod> {
        self.methods.get(name)
    }

    /// Get a mutable reference to a method by name.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut RemoteMethod> {
        self.methods.get_mut(name)
    }

    /// Get all method names.
    pub fn method_names(&self) -> Vec<&str> {
        self.methods.keys().map(|s| s.as_str()).collect()
    }

    /// Get all methods.
    pub fn methods(&self) -> impl Iterator<Item = &RemoteMethod> {
        self.methods.values()
    }

    /// Get the number of registered methods.
    pub fn len(&self) -> usize {
        self.methods.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.methods.is_empty()
    }

    /// Get all non-hidden methods.
    pub fn visible_methods(&self) -> impl Iterator<Item = &RemoteMethod> {
        self.methods.values().filter(|m| !m.hidden)
    }

    /// Check if a method exists.
    pub fn contains(&self, name: &str) -> bool {
        self.methods.contains_key(name)
    }
}

impl Default for RemoteMethodRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// A terminal session for interacting with the back end.
///
/// Ported from `TerminalSession`. Represents an interactive shell or
/// terminal session to the debug back end.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalSession {
    /// Session identifier.
    pub session_id: String,
    /// The connection ID this session is associated with.
    pub connection_id: String,
    /// Whether the session is active.
    pub is_active: bool,
    /// The prompt string.
    pub prompt: Option<String>,
    /// Whether the session supports history.
    pub supports_history: bool,
    /// Command history.
    pub history: Vec<String>,
}

impl TerminalSession {
    /// Create a new terminal session.
    pub fn new(session_id: &str, connection_id: &str) -> Self {
        Self {
            session_id: session_id.to_string(),
            connection_id: connection_id.to_string(),
            is_active: true,
            prompt: None,
            supports_history: true,
            history: Vec::new(),
        }
    }

    /// Add a command to the history.
    pub fn add_to_history(&mut self, command: &str) {
        if self.supports_history {
            self.history.push(command.to_string());
        }
    }
}

/// An offer to launch a debug session.
///
/// Ported from `TraceRmiLaunchOffer`. Describes a possible way to
/// start a debug session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRmiLaunchOffer {
    /// The offer identifier.
    pub offer_id: String,
    /// The display name of this launch offer.
    pub display: String,
    /// A description of this launch offer.
    pub description: Option<String>,
    /// The method to invoke to execute this launch.
    pub method_name: String,
    /// Parameters for the launch method.
    pub parameters: BTreeMap<String, String>,
    /// Whether this is the default launch offer.
    pub is_default: bool,
}

impl TraceRmiLaunchOffer {
    /// Create a new launch offer.
    pub fn new(offer_id: &str, display: &str, method_name: &str) -> Self {
        Self {
            offer_id: offer_id.to_string(),
            display: display.to_string(),
            description: None,
            method_name: method_name.to_string(),
            parameters: BTreeMap::new(),
            is_default: false,
        }
    }

    /// Add a parameter.
    pub fn with_parameter(mut self, key: &str, value: &str) -> Self {
        self.parameters.insert(key.to_string(), value.to_string());
        self
    }

    /// Set as default.
    pub fn as_default(mut self) -> Self {
        self.is_default = true;
        self
    }
}

/// Errors that can occur during Trace RMI operations.
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
pub enum TraceRmiError {
    /// The connection was lost.
    #[error("connection lost: {0}")]
    ConnectionLost(String),

    /// The method was not found.
    #[error("method not found: {0}")]
    MethodNotFound(String),

    /// A parameter was invalid.
    #[error("invalid parameter {name}: {reason}")]
    InvalidParameter { name: String, reason: String },

    /// The back end returned an error.
    #[error("remote error: {0}")]
    RemoteError(String),

    /// A timeout occurred.
    #[error("timeout after {0:?}")]
    Timeout(Duration),

    /// The operation was cancelled.
    #[error("cancelled")]
    Cancelled,

    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    IoError(String),

    /// A serialization/deserialization error.
    #[error("encoding error: {0}")]
    EncodingError(String),

    /// The trace target was not found.
    #[error("trace not found: {0}")]
    TraceNotFound(String),

    /// An internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

/// A result of a remote method invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteMethodResult {
    /// Whether the invocation succeeded.
    pub success: bool,
    /// The return value, if any.
    pub return_value: Option<String>,
    /// Error message, if the invocation failed.
    pub error_message: Option<String>,
    /// Output text captured from the invocation.
    pub output: Option<String>,
    /// Duration of the invocation.
    pub duration: Option<Duration>,
}

impl RemoteMethodResult {
    /// Create a successful result.
    pub fn success() -> Self {
        Self {
            success: true,
            return_value: None,
            error_message: None,
            output: None,
            duration: None,
        }
    }

    /// Create a successful result with a return value.
    pub fn success_with(value: &str) -> Self {
        Self {
            success: true,
            return_value: Some(value.to_string()),
            error_message: None,
            output: None,
            duration: None,
        }
    }

    /// Create an error result.
    pub fn error(message: &str) -> Self {
        Self {
            success: false,
            return_value: None,
            error_message: Some(message.to_string()),
            output: None,
            duration: None,
        }
    }
}

/// A launch parameter for starting a debug session.
///
/// Ported from `ghidra.debug.api.tracermi.LaunchParameter`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchParameter {
    /// The parameter name.
    pub name: String,
    /// The display name.
    pub display: String,
    /// The parameter type.
    pub param_type: LaunchParameterType,
    /// Whether this parameter is required.
    pub required: bool,
    /// The default value.
    pub default_value: Option<String>,
    /// A description of the parameter.
    pub description: Option<String>,
    /// For choice types, the available options.
    pub options: Vec<String>,
}

/// The type of a launch parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LaunchParameterType {
    /// A text string parameter.
    String,
    /// A file path parameter.
    FilePath,
    /// A directory path parameter.
    DirectoryPath,
    /// A numeric parameter.
    Number,
    /// A boolean flag.
    Boolean,
    /// A choice from a set of options.
    Choice,
    /// An IP address or hostname.
    HostAddress,
    /// A port number.
    Port,
}

/// Connection status for a Trace RMI connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionStatus {
    /// Not yet connected.
    Disconnected,
    /// Connecting.
    Connecting,
    /// Connected and ready.
    Connected,
    /// Connection is being closed.
    Closing,
    /// Connection has been closed.
    Closed,
    /// An error occurred.
    Error,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remote_method_creation() {
        let method = RemoteMethod::new("launch", "Launch Program")
            .with_action("launch")
            .with_ok_text("Launch")
            .with_parameter(RemoteParameter::required("path", "Executable Path"))
            .with_parameter(RemoteParameter::optional("args", "Arguments", ""));

        assert_eq!(method.name, "launch");
        assert_eq!(method.display, "Launch Program");
        assert_eq!(method.parameters.len(), 2);
        assert!(method.parameter("path").is_some());
        assert!(method.parameter("args").is_some());
        assert!(method.parameter("missing").is_none());
    }

    #[test]
    fn test_remote_parameter_types() {
        let req = RemoteParameter::required("path", "Path");
        assert!(req.required);
        assert!(req.default_value.is_none());

        let opt = RemoteParameter::optional("args", "Args", "default");
        assert!(!opt.required);
        assert_eq!(opt.default_value.as_deref(), Some("default"));

        let fixed = RemoteParameter::fixed("mode", "auto");
        assert_eq!(fixed.fixed_value.as_deref(), Some("auto"));
    }

    #[test]
    fn test_method_registry() {
        let mut registry = RemoteMethodRegistry::new();
        assert!(registry.is_empty());

        registry.register(RemoteMethod::new("launch", "Launch"));
        registry.register(RemoteMethod::new("resume", "Resume").with_hidden(true));
        registry.register(RemoteMethod::new("kill", "Kill"));

        assert_eq!(registry.len(), 3);
        assert!(registry.contains("launch"));
        assert!(!registry.contains("missing"));

        let visible: Vec<_> = registry.visible_methods().collect();
        assert_eq!(visible.len(), 2); // resume is hidden
    }

    #[test]
    fn test_connection_info() {
        let mut conn = TraceRmiConnectionInfo::new("conn-1", "GDB on localhost");
        conn.remote_address = Some("127.0.0.1:12345".to_string());

        conn.add_target(TraceRmiTarget {
            trace_id: "trace-1".to_string(),
            name: "target.exe".to_string(),
            is_active: true,
        });

        assert_eq!(conn.targets.len(), 1);
        assert_eq!(conn.last_snapshot("trace-1"), 0);

        let removed = conn.remove_target("trace-1");
        assert!(removed.is_some());
        assert!(conn.targets.is_empty());
    }

    #[test]
    fn test_terminal_session() {
        let mut session = TerminalSession::new("sess-1", "conn-1");
        assert!(session.is_active);
        assert!(session.history.is_empty());

        session.add_to_history("help");
        session.add_to_history("status");
        assert_eq!(session.history.len(), 2);
    }

    #[test]
    fn test_launch_offer() {
        let offer = TraceRmiLaunchOffer::new("offer-1", "GDB Local", "launch")
            .with_parameter("path", "/usr/bin/ls")
            .as_default();

        assert!(offer.is_default);
        assert_eq!(offer.parameters.get("path").map(|s| s.as_str()), Some("/usr/bin/ls"));
    }

    #[test]
    fn test_trace_rmi_error() {
        let err = TraceRmiError::MethodNotFound("unknown".to_string());
        assert!(err.to_string().contains("unknown"));

        let err = TraceRmiError::Timeout(Duration::from_secs(5));
        assert!(err.to_string().contains("5s"));
    }

    #[test]
    fn test_remote_method_result() {
        let ok = RemoteMethodResult::success();
        assert!(ok.success);
        assert!(ok.error_message.is_none());

        let ok_with = RemoteMethodResult::success_with("output text");
        assert!(ok_with.success);
        assert_eq!(ok_with.return_value.as_deref(), Some("output text"));

        let err = RemoteMethodResult::error("something failed");
        assert!(!err.success);
        assert_eq!(err.error_message.as_deref(), Some("something failed"));
    }

    #[test]
    fn test_launch_parameter() {
        let param = LaunchParameter {
            name: "exe".to_string(),
            display: "Executable".to_string(),
            param_type: LaunchParameterType::FilePath,
            required: true,
            default_value: None,
            description: Some("Path to the executable".to_string()),
            options: vec![],
        };

        assert_eq!(param.param_type, LaunchParameterType::FilePath);
        assert!(param.required);
    }

    #[test]
    fn test_connection_status() {
        assert_ne!(ConnectionStatus::Connected, ConnectionStatus::Disconnected);
        assert_ne!(ConnectionStatus::Error, ConnectionStatus::Closed);
    }

    #[test]
    fn test_remote_method_builder_chain() {
        let method = RemoteMethod::new("execute", "Execute Command")
            .with_action("execute")
            .with_ok_text("Run")
            .with_return_type("string")
            .with_description("Execute a command in the debugger")
            .with_parameter(RemoteParameter::required("command", "Command").with_schema("string"))
            .with_parameter(
                RemoteParameter::optional("timeout", "Timeout", "30")
                    .with_description("Timeout in seconds"),
            );

        assert_eq!(method.parameters.len(), 2);
        assert!(method.description.is_some());
        assert!(method.return_type.is_some());
    }

    #[test]
    fn test_registry_method_names() {
        let mut registry = RemoteMethodRegistry::new();
        registry.register(RemoteMethod::new("a", "A"));
        registry.register(RemoteMethod::new("b", "B"));
        registry.register(RemoteMethod::new("c", "C"));

        let names = registry.method_names();
        assert_eq!(names.len(), 3);
        // BTreeMap sorts keys
        assert_eq!(names, vec!["a", "b", "c"]);
    }
}
