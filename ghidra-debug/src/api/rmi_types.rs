//! Trace RMI (Remote Method Invocation) types.
//!
//! Ported from Ghidra's `ghidra.debug.api.tracermi` package:
//! - `TraceRmiLaunchOffer`: A provider of RMI launch configurations.
//! - `TraceRmiConnection`: An active RMI connection to a debugger.

use serde::{Deserialize, Serialize};

/// The state of an RMI connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnectionState {
    /// Not connected.
    Disconnected,
    /// Connecting.
    Connecting,
    /// Connected and ready.
    Connected,
    /// Connection lost.
    Lost,
    /// Disconnecting.
    Disconnecting,
}

/// An offer to launch a debugger via Trace RMI.
///
/// Each launch offer describes a way to start a debugger backend
/// and connect it to the Ghidra trace framework.
///
/// Ported from Ghidra's `TraceRmiLaunchOffer`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRmiLaunchOffer {
    /// The display name for this offer.
    pub display_name: String,
    /// The debugger type (e.g., "gdb", "lldb").
    pub debugger_type: String,
    /// The command to launch the debugger.
    pub command: String,
    /// Arguments for the launch command.
    pub arguments: Vec<String>,
    /// Environment variables.
    pub environment: Vec<(String, String)>,
    /// Whether this offer is currently available.
    pub available: bool,
    /// A description of the offer.
    pub description: Option<String>,
    /// The working directory.
    pub working_dir: Option<String>,
}

impl TraceRmiLaunchOffer {
    /// Create a new launch offer.
    pub fn new(
        display_name: impl Into<String>,
        debugger_type: impl Into<String>,
        command: impl Into<String>,
    ) -> Self {
        Self {
            display_name: display_name.into(),
            debugger_type: debugger_type.into(),
            command: command.into(),
            arguments: Vec::new(),
            environment: Vec::new(),
            available: true,
            description: None,
            working_dir: None,
        }
    }

    /// Add an argument to the launch command.
    pub fn with_arg(mut self, arg: impl Into<String>) -> Self {
        self.arguments.push(arg.into());
        self
    }

    /// Add multiple arguments.
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.arguments.extend(args);
        self
    }

    /// Set an environment variable.
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.environment.push((key.into(), value.into()));
        self
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Set the working directory.
    pub fn with_working_dir(mut self, dir: impl Into<String>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    /// Check if this offer is available.
    pub fn is_available(&self) -> bool {
        self.available
    }
}

/// A connection to a debugger via Trace RMI.
///
/// Manages the lifecycle and communication channel with a debugger
/// backend process.
///
/// Ported from Ghidra's `TraceRmiConnection`.
#[derive(Debug)]
pub struct TraceRmiConnection {
    /// A unique identifier for this connection.
    pub id: String,
    /// The current connection state.
    state: ConnectionState,
    /// The launch offer used for this connection.
    pub offer: Option<TraceRmiLaunchOffer>,
    /// Process ID of the connected debugger, if applicable.
    pub pid: Option<i64>,
    /// The error message if the connection was lost.
    pub last_error: Option<String>,
    /// Messages received from the debugger.
    received_messages: Vec<String>,
}

impl TraceRmiConnection {
    /// Create a new disconnected connection.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            state: ConnectionState::Disconnected,
            offer: None,
            pid: None,
            last_error: None,
            received_messages: Vec::new(),
        }
    }

    /// Get the current connection state.
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Set the connection state.
    pub fn set_state(&mut self, state: ConnectionState) {
        self.state = state;
    }

    /// Check if the connection is active.
    pub fn is_connected(&self) -> bool {
        self.state == ConnectionState::Connected
    }

    /// Record a received message.
    pub fn push_message(&mut self, msg: impl Into<String>) {
        self.received_messages.push(msg.into());
    }

    /// Get all received messages.
    pub fn messages(&self) -> &[String] {
        &self.received_messages
    }

    /// Clear received messages.
    pub fn clear_messages(&mut self) {
        self.received_messages.clear();
    }

    /// Set the error message.
    pub fn set_error(&mut self, err: impl Into<String>) {
        self.last_error = Some(err.into());
        self.state = ConnectionState::Lost;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_launch_offer() {
        let offer = TraceRmiLaunchOffer::new("GDB", "gdb", "/usr/bin/gdb")
            .with_arg("--interpreter=mi2")
            .with_env("PATH", "/usr/bin")
            .with_description("GDB via MI2")
            .with_working_dir("/tmp");

        assert_eq!(offer.display_name, "GDB");
        assert_eq!(offer.arguments, vec!["--interpreter=mi2"]);
        assert!(offer.is_available());
    }

    #[test]
    fn test_connection_lifecycle() {
        let mut conn = TraceRmiConnection::new("test-conn");
        assert_eq!(conn.state(), ConnectionState::Disconnected);
        assert!(!conn.is_connected());

        conn.set_state(ConnectionState::Connecting);
        assert_eq!(conn.state(), ConnectionState::Connecting);

        conn.set_state(ConnectionState::Connected);
        assert!(conn.is_connected());

        conn.push_message("hello from debugger");
        assert_eq!(conn.messages().len(), 1);

        conn.set_error("connection lost");
        assert_eq!(conn.state(), ConnectionState::Lost);
        assert!(!conn.is_connected());
    }
}
