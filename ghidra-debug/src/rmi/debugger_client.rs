//! Debugger client abstraction for agent backends.
//!
//! Ported from Ghidra's `Debugger-client-protocol` / `DebuggerClientBackend`
//! interface in `ghidra.debug.client.DebuggerClientBackend`.
//!
//! Provides a trait-based abstraction over debug agent backends (GDB, LLDB,
//! dbgeng, drgn, x64dbg, etc.) so the RMI infrastructure can communicate
//! with any supported debugger uniformly. Each backend implements the
//! `DebuggerClientBackend` trait to handle connection lifecycle, command
//! dispatch, and event propagation.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// DebuggerClientState / DebuggerClientKind
// ---------------------------------------------------------------------------

/// The kind of debugger client backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DebuggerClientKind {
    /// GDB via GDB/MI protocol.
    Gdb,
    /// LLDB via the LLDB Python API.
    Lldb,
    /// Windows Debugging Engine (WinDbg/dbgeng).
    Dbgeng,
    /// drgn kernel debugger.
    Drgn,
    /// x64dbg via x64dbg_automate.
    X64dbg,
}

impl DebuggerClientKind {
    /// Human-readable label for display.
    pub fn display_label(&self) -> &'static str {
        match self {
            Self::Gdb => "GDB",
            Self::Lldb => "LLDB",
            Self::Dbgeng => "dbgeng",
            Self::Drgn => "drgn",
            Self::X64dbg => "x64dbg",
        }
    }

    /// Default launcher script for this backend kind.
    pub fn default_launcher(&self) -> &'static str {
        match self {
            Self::Gdb => "local-gdb.sh",
            Self::Lldb => "local-lldb.sh",
            Self::Dbgeng => "local-dbgeng.cmd",
            Self::Drgn => "local-drgn.py",
            Self::X64dbg => "local-x64dbg.cmd",
        }
    }
}

/// The lifecycle state of a debugger client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DebuggerClientState {
    /// Client has been created but not yet started.
    Created,
    /// Client is connecting to the debugger.
    Connecting,
    /// Client is connected and ready for commands.
    Ready,
    /// Client is actively debugging (target running or stopped).
    Active,
    /// Client has been disconnected.
    Disconnected,
    /// Client encountered an error.
    Error,
    /// Client has been shut down.
    Shutdown,
}

impl DebuggerClientState {
    /// Whether the client can accept commands in this state.
    pub fn is_accepting_commands(&self) -> bool {
        matches!(self, Self::Ready | Self::Active)
    }

    /// Whether the client is alive (not shut down or errored).
    pub fn is_alive(&self) -> bool {
        !matches!(self, Self::Shutdown | Self::Error | Self::Disconnected)
    }
}

// ---------------------------------------------------------------------------
// DebuggerClientCommand / DebuggerClientResponse
// ---------------------------------------------------------------------------

/// A command sent from the RMI layer to a debug backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerClientCommand {
    /// The command ID for correlating responses.
    pub command_id: u64,
    /// The method name (e.g. "resume", "readMemory", "listTargets").
    pub method: String,
    /// Named parameters for the command.
    pub parameters: BTreeMap<String, serde_json::Value>,
    /// The trace key this command operates on (if applicable).
    pub trace_key: Option<i64>,
}

impl DebuggerClientCommand {
    /// Create a new command.
    pub fn new(command_id: u64, method: impl Into<String>) -> Self {
        Self {
            command_id,
            method: method.into(),
            parameters: BTreeMap::new(),
            trace_key: None,
        }
    }

    /// Add a parameter.
    pub fn with_param(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.parameters.insert(key.into(), value);
        self
    }

    /// Set the trace key.
    pub fn with_trace_key(mut self, key: i64) -> Self {
        self.trace_key = Some(key);
        self
    }
}

/// A response from a debug backend to a command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerClientResponse {
    /// The command ID this response corresponds to.
    pub command_id: u64,
    /// Whether the command succeeded.
    pub success: bool,
    /// The result value (JSON), if successful.
    pub result: Option<serde_json::Value>,
    /// Error message, if the command failed.
    pub error: Option<String>,
}

impl DebuggerClientResponse {
    /// Create a success response.
    pub fn success(command_id: u64, result: serde_json::Value) -> Self {
        Self {
            command_id,
            success: true,
            result: Some(result),
            error: None,
        }
    }

    /// Create an error response.
    pub fn error(command_id: u64, error: impl Into<String>) -> Self {
        Self {
            command_id,
            success: false,
            result: None,
            error: Some(error.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// DebuggerClientEvent
// ---------------------------------------------------------------------------

/// An event emitted asynchronously by a debug backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DebuggerClientEvent {
    /// The process state changed.
    StateChanged {
        /// The target ID.
        target_id: String,
        /// The new execution state label (e.g. "RUNNING", "STOPPED").
        state: String,
    },
    /// A breakpoint was hit.
    BreakpointHit {
        /// The target ID.
        target_id: String,
        /// The breakpoint ID.
        breakpoint_id: u32,
        /// The thread that hit the breakpoint.
        thread_id: Option<u64>,
    },
    /// Memory was modified by the target.
    MemoryChanged {
        /// The target ID.
        target_id: String,
        /// The address that changed.
        address: u64,
        /// Number of bytes changed.
        length: u64,
    },
    /// A register value changed.
    RegisterChanged {
        /// The target ID.
        target_id: String,
        /// The register name.
        register: String,
    },
    /// A new thread was created.
    ThreadCreated {
        /// The target ID.
        target_id: String,
        /// The thread ID.
        thread_id: u64,
    },
    /// A thread exited.
    ThreadExited {
        /// The target ID.
        target_id: String,
        /// The thread ID.
        thread_id: u64,
    },
    /// Output from the debugger's console.
    ConsoleOutput {
        /// The text line.
        line: String,
        /// Whether this is an error output.
        is_error: bool,
    },
}

// ---------------------------------------------------------------------------
// DebuggerClientTarget
// ---------------------------------------------------------------------------

/// A target reported by the backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerClientTarget {
    /// Unique target identifier.
    pub target_id: String,
    /// Display name.
    pub display_name: String,
    /// Process ID, if attached.
    pub pid: Option<u64>,
    /// Architecture string (e.g. "x86:LE:64:default").
    pub architecture: Option<String>,
    /// Whether the target is currently running.
    pub running: bool,
}

// ---------------------------------------------------------------------------
// DebuggerClientBackend trait
// ---------------------------------------------------------------------------

/// Trait implemented by each debug agent backend.
///
/// This is the core abstraction that allows the RMI layer to drive any
/// supported debugger uniformly. Backend implementations include GDB,
/// LLDB, dbgeng, drgn, and x64dbg.
pub trait DebuggerClientBackend: Send + Sync {
    /// The kind of backend.
    fn kind(&self) -> DebuggerClientKind;

    /// The current state of the client.
    fn state(&self) -> DebuggerClientState;

    /// Human-readable description of this client instance.
    fn description(&self) -> String;

    /// Connect to the debugger.
    fn connect(&mut self) -> Result<(), String>;

    /// Disconnect from the debugger.
    fn disconnect(&mut self) -> Result<(), String>;

    /// Send a command to the backend and return a response.
    ///
    /// For batch operations, multiple commands can be sent before polling
    /// for responses. The `command_id` in the response must match the one
    /// in the request.
    fn execute_command(&mut self, command: DebuggerClientCommand) -> Result<DebuggerClientResponse, String>;

    /// List all targets currently managed by this backend.
    fn list_targets(&self) -> Vec<DebuggerClientTarget>;

    /// Poll for asynchronous events from the backend.
    ///
    /// Returns all events that have been emitted since the last poll.
    fn poll_events(&mut self) -> Vec<DebuggerClientEvent>;
}

// ---------------------------------------------------------------------------
// DebuggerClient
// ---------------------------------------------------------------------------

/// Configuration for a debugger client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerClientConfig {
    /// The backend kind.
    pub kind: DebuggerClientKind,
    /// Human-readable description.
    pub description: String,
    /// Path to the backend launcher script.
    pub launcher_path: Option<String>,
    /// The remote address (if connecting to an existing session).
    pub remote_address: Option<String>,
    /// Additional backend-specific parameters.
    pub parameters: BTreeMap<String, String>,
}

impl DebuggerClientConfig {
    /// Create a new config for a given backend kind.
    pub fn new(kind: DebuggerClientKind) -> Self {
        Self {
            kind,
            description: kind.display_label().to_string(),
            launcher_path: Some(kind.default_launcher().to_string()),
            remote_address: None,
            parameters: BTreeMap::new(),
        }
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Set the remote address.
    pub fn with_remote_address(mut self, addr: impl Into<String>) -> Self {
        self.remote_address = Some(addr.into());
        self
    }

    /// Set the launcher path.
    pub fn with_launcher(mut self, path: impl Into<String>) -> Self {
        self.launcher_path = Some(path.into());
        self
    }

    /// Add a backend-specific parameter.
    pub fn with_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.parameters.insert(key.into(), value.into());
        self
    }
}

/// The debugger client, wrapping a backend implementation.
///
/// This is the high-level entry point for driving a debug session.
/// It manages the backend lifecycle and tracks pending commands.
pub struct DebuggerClient {
    /// Client configuration.
    pub config: DebuggerClientConfig,
    /// Next command ID.
    next_command_id: u64,
    /// Pending command IDs that have been sent but not yet responded to.
    pending_commands: Vec<u64>,
    /// Collected events since last poll.
    events: Vec<DebuggerClientEvent>,
}

impl DebuggerClient {
    /// Create a new debugger client.
    pub fn new(config: DebuggerClientConfig) -> Self {
        Self {
            config,
            next_command_id: 1,
            pending_commands: Vec::new(),
            events: Vec::new(),
        }
    }

    /// Get the next command ID and increment.
    pub fn next_command_id(&mut self) -> u64 {
        let id = self.next_command_id;
        self.next_command_id += 1;
        id
    }

    /// Create a new command with an auto-assigned ID.
    pub fn create_command(&mut self, method: impl Into<String>) -> DebuggerClientCommand {
        let id = self.next_command_id();
        DebuggerClientCommand::new(id, method)
    }

    /// Record that a command was sent (add to pending).
    pub fn record_sent(&mut self, command_id: u64) {
        self.pending_commands.push(command_id);
    }

    /// Record that a response was received (remove from pending).
    pub fn record_received(&mut self, command_id: u64) {
        self.pending_commands.retain(|&id| id != command_id);
    }

    /// Number of pending (outstanding) commands.
    pub fn pending_count(&self) -> usize {
        self.pending_commands.len()
    }

    /// Add an event to the collected events buffer.
    pub fn push_event(&mut self, event: DebuggerClientEvent) {
        self.events.push(event);
    }

    /// Drain all collected events.
    pub fn drain_events(&mut self) -> Vec<DebuggerClientEvent> {
        std::mem::take(&mut self.events)
    }

    /// Number of collected events.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

impl std::fmt::Debug for DebuggerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DebuggerClient")
            .field("config", &self.config)
            .field("pending_count", &self.pending_commands.len())
            .field("event_count", &self.events.len())
            .finish()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debugger_client_kind_display() {
        assert_eq!(DebuggerClientKind::Gdb.display_label(), "GDB");
        assert_eq!(DebuggerClientKind::Lldb.display_label(), "LLDB");
        assert_eq!(DebuggerClientKind::Dbgeng.display_label(), "dbgeng");
        assert_eq!(DebuggerClientKind::Drgn.display_label(), "drgn");
        assert_eq!(DebuggerClientKind::X64dbg.display_label(), "x64dbg");
    }

    #[test]
    fn test_debugger_client_kind_launcher() {
        assert_eq!(DebuggerClientKind::Gdb.default_launcher(), "local-gdb.sh");
        assert_eq!(DebuggerClientKind::Lldb.default_launcher(), "local-lldb.sh");
        assert_eq!(DebuggerClientKind::Dbgeng.default_launcher(), "local-dbgeng.cmd");
    }

    #[test]
    fn test_debugger_client_state_accepting() {
        assert!(DebuggerClientState::Ready.is_accepting_commands());
        assert!(DebuggerClientState::Active.is_accepting_commands());
        assert!(!DebuggerClientState::Created.is_accepting_commands());
        assert!(!DebuggerClientState::Shutdown.is_accepting_commands());
    }

    #[test]
    fn test_debugger_client_state_alive() {
        assert!(DebuggerClientState::Created.is_alive());
        assert!(DebuggerClientState::Ready.is_alive());
        assert!(!DebuggerClientState::Shutdown.is_alive());
        assert!(!DebuggerClientState::Error.is_alive());
    }

    #[test]
    fn test_command_builder() {
        let cmd = DebuggerClientCommand::new(1, "readMemory")
            .with_param("address", serde_json::json!(0x400000))
            .with_param("length", serde_json::json!(256))
            .with_trace_key(1);
        assert_eq!(cmd.command_id, 1);
        assert_eq!(cmd.method, "readMemory");
        assert_eq!(cmd.parameters.len(), 2);
        assert_eq!(cmd.trace_key, Some(1));
    }

    #[test]
    fn test_response_success() {
        let resp = DebuggerClientResponse::success(1, serde_json::json!("ok"));
        assert!(resp.success);
        assert!(resp.error.is_none());
        assert_eq!(resp.command_id, 1);
    }

    #[test]
    fn test_response_error() {
        let resp = DebuggerClientResponse::error(2, "timeout");
        assert!(!resp.success);
        assert_eq!(resp.error.as_deref(), Some("timeout"));
    }

    #[test]
    fn test_debugger_client_config_builder() {
        let config = DebuggerClientConfig::new(DebuggerClientKind::Gdb)
            .with_description("GDB for x86")
            .with_remote_address("localhost:1234")
            .with_param("arch", "x86");
        assert_eq!(config.kind, DebuggerClientKind::Gdb);
        assert_eq!(config.description, "GDB for x86");
        assert_eq!(config.remote_address.as_deref(), Some("localhost:1234"));
        assert_eq!(config.parameters.get("arch").map(|s| s.as_str()), Some("x86"));
    }

    #[test]
    fn test_debugger_client_command_ids() {
        let config = DebuggerClientConfig::new(DebuggerClientKind::Gdb);
        let mut client = DebuggerClient::new(config);
        let c1 = client.create_command("listTargets");
        let c2 = client.create_command("resume");
        assert_eq!(c1.command_id, 1);
        assert_eq!(c2.command_id, 2);
    }

    #[test]
    fn test_debugger_client_pending() {
        let config = DebuggerClientConfig::new(DebuggerClientKind::Gdb);
        let mut client = DebuggerClient::new(config);
        client.record_sent(1);
        client.record_sent(2);
        assert_eq!(client.pending_count(), 2);
        client.record_received(1);
        assert_eq!(client.pending_count(), 1);
    }

    #[test]
    fn test_debugger_client_events() {
        let config = DebuggerClientConfig::new(DebuggerClientKind::Lldb);
        let mut client = DebuggerClient::new(config);
        client.push_event(DebuggerClientEvent::StateChanged {
            target_id: "t1".into(),
            state: "STOPPED".into(),
        });
        client.push_event(DebuggerClientEvent::ConsoleOutput {
            line: "hit breakpoint".into(),
            is_error: false,
        });
        assert_eq!(client.event_count(), 2);
        let events = client.drain_events();
        assert_eq!(events.len(), 2);
        assert_eq!(client.event_count(), 0);
    }

    #[test]
    fn test_debugger_client_event_variants() {
        let events = vec![
            DebuggerClientEvent::StateChanged {
                target_id: "t1".into(),
                state: "RUNNING".into(),
            },
            DebuggerClientEvent::BreakpointHit {
                target_id: "t1".into(),
                breakpoint_id: 3,
                thread_id: Some(42),
            },
            DebuggerClientEvent::MemoryChanged {
                target_id: "t1".into(),
                address: 0x400000,
                length: 4,
            },
            DebuggerClientEvent::RegisterChanged {
                target_id: "t1".into(),
                register: "rax".into(),
            },
            DebuggerClientEvent::ThreadCreated {
                target_id: "t1".into(),
                thread_id: 7,
            },
            DebuggerClientEvent::ThreadExited {
                target_id: "t1".into(),
                thread_id: 7,
            },
            DebuggerClientEvent::ConsoleOutput {
                line: "info".into(),
                is_error: false,
            },
        ];
        assert_eq!(events.len(), 7);
    }

    #[test]
    fn test_debugger_client_target() {
        let target = DebuggerClientTarget {
            target_id: "gdb-1".into(),
            display_name: "GDB Process".into(),
            pid: Some(1234),
            architecture: Some("x86:LE:64:default".into()),
            running: false,
        };
        assert_eq!(target.target_id, "gdb-1");
        assert!(!target.running);
    }

    #[test]
    fn test_debugger_client_config_default_launcher() {
        let config = DebuggerClientConfig::new(DebuggerClientKind::X64dbg);
        assert_eq!(config.launcher_path.as_deref(), Some("local-x64dbg.cmd"));
    }

    #[test]
    fn test_debugger_client_config_override_launcher() {
        let config = DebuggerClientConfig::new(DebuggerClientKind::Gdb)
            .with_launcher("/custom/path/launch.sh");
        assert_eq!(config.launcher_path.as_deref(), Some("/custom/path/launch.sh"));
    }

    #[test]
    fn test_state_transitions() {
        assert!(DebuggerClientState::Created.is_alive());
        assert!(!DebuggerClientState::Created.is_accepting_commands());
        assert!(DebuggerClientState::Connecting.is_alive());
        assert!(!DebuggerClientState::Connecting.is_accepting_commands());
        assert!(DebuggerClientState::Ready.is_alive());
        assert!(DebuggerClientState::Ready.is_accepting_commands());
    }

    #[test]
    fn test_command_trace_key_none_by_default() {
        let cmd = DebuggerClientCommand::new(1, "resume");
        assert!(cmd.trace_key.is_none());
    }
}
