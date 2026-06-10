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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
    /// A process was created or attached.
    ProcessCreated {
        /// The target ID.
        target_id: String,
        /// The process ID.
        pid: u64,
        /// Path to the executable.
        executable: Option<String>,
    },
    /// A process exited.
    ProcessExited {
        /// The target ID.
        target_id: String,
        /// The process ID.
        pid: u64,
        /// The exit code (if available).
        exit_code: Option<i32>,
    },
    /// A shared library/module was loaded.
    LibraryLoaded {
        /// The target ID.
        target_id: String,
        /// Library name or path.
        name: String,
        /// Base address where the library was loaded.
        base_address: u64,
    },
    /// A shared library/module was unloaded.
    LibraryUnloaded {
        /// The target ID.
        target_id: String,
        /// Library name or path.
        name: String,
    },
    /// A signal was received by the target.
    SignalReceived {
        /// The target ID.
        target_id: String,
        /// Signal name (e.g. "SIGSEGV", "SIGINT").
        signal_name: String,
        /// Signal number.
        signal_number: Option<i32>,
    },
    /// Execution stopped at an address.
    Stopped {
        /// The target ID.
        target_id: String,
        /// The reason for stopping.
        reason: String,
        /// The address at which execution stopped.
        pc: Option<u64>,
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
// DebuggerCommandType
// ---------------------------------------------------------------------------

/// Standard debug command types that backends are expected to support.
///
/// Ported from the command methods on Ghidra's `DebuggerClientBackend`
/// interface and the RMI handler's request dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DebuggerCommandType {
    /// Resume execution of the target.
    Resume,
    /// Single-step the target.
    Step,
    /// Step over a function call.
    StepOver,
    /// Step out of the current function.
    StepOut,
    /// Pause/interrupt the target.
    Interrupt,
    /// Kill the target process.
    Kill,
    /// Detach from the target.
    Detach,
    /// Read memory from the target.
    ReadMemory,
    /// Write memory to the target.
    WriteMemory,
    /// Read a register value.
    ReadRegister,
    /// Write a register value.
    WriteRegister,
    /// List threads in the target.
    ListThreads,
    /// Set a breakpoint.
    SetBreakpoint,
    /// Remove a breakpoint.
    RemoveBreakpoint,
    /// List breakpoints.
    ListBreakpoints,
    /// List memory regions.
    ListMemoryRegions,
    /// List loaded modules/libraries.
    ListModules,
    /// Evaluate an expression.
    EvaluateExpression,
    /// Disassemble bytes at an address.
    Disassemble,
}

impl DebuggerCommandType {
    /// Human-readable name for this command.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Resume => "Resume",
            Self::Step => "Step",
            Self::StepOver => "Step Over",
            Self::StepOut => "Step Out",
            Self::Interrupt => "Interrupt",
            Self::Kill => "Kill",
            Self::Detach => "Detach",
            Self::ReadMemory => "Read Memory",
            Self::WriteMemory => "Write Memory",
            Self::ReadRegister => "Read Register",
            Self::WriteRegister => "Write Register",
            Self::ListThreads => "List Threads",
            Self::SetBreakpoint => "Set Breakpoint",
            Self::RemoveBreakpoint => "Remove Breakpoint",
            Self::ListBreakpoints => "List Breakpoints",
            Self::ListMemoryRegions => "List Memory Regions",
            Self::ListModules => "List Modules",
            Self::EvaluateExpression => "Evaluate Expression",
            Self::Disassemble => "Disassemble",
        }
    }

    /// The RMI method name corresponding to this command type.
    pub fn method_name(&self) -> &'static str {
        match self {
            Self::Resume => "resume",
            Self::Step => "step",
            Self::StepOver => "stepOver",
            Self::StepOut => "stepOut",
            Self::Interrupt => "interrupt",
            Self::Kill => "kill",
            Self::Detach => "detach",
            Self::ReadMemory => "readMemory",
            Self::WriteMemory => "writeMemory",
            Self::ReadRegister => "readRegister",
            Self::WriteRegister => "writeRegister",
            Self::ListThreads => "listThreads",
            Self::SetBreakpoint => "setBreakpoint",
            Self::RemoveBreakpoint => "removeBreakpoint",
            Self::ListBreakpoints => "listBreakpoints",
            Self::ListMemoryRegions => "listMemoryRegions",
            Self::ListModules => "listModules",
            Self::EvaluateExpression => "evaluateExpression",
            Self::Disassemble => "disassemble",
        }
    }
}

// ---------------------------------------------------------------------------
// DebuggerClientBackendRegistry
// ---------------------------------------------------------------------------

/// Registration entry for a debugger backend factory.
///
/// Ported from Ghidra's `DebuggerClientProvider` and related extension points.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendRegistration {
    /// The kind of backend.
    pub kind: DebuggerClientKind,
    /// Display name for the backend.
    pub display_name: String,
    /// Path to the launcher script.
    pub launcher_path: String,
    /// Default parameters to use.
    pub default_parameters: BTreeMap<String, String>,
    /// Whether this backend is currently available on the system.
    pub available: bool,
}

/// A registry of available debugger backends.
///
/// Ported from the extension-point-based registration in Ghidra's
/// `DebuggerClientProvider` service. The registry allows the UI and
/// orchestration layer to enumerate which debug backends are installed
/// and available on the current system.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DebuggerClientBackendRegistry {
    backends: BTreeMap<DebuggerClientKind, BackendRegistration>,
}

impl DebuggerClientBackendRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a backend.
    pub fn register(&mut self, registration: BackendRegistration) {
        self.backends.insert(registration.kind, registration);
    }

    /// Unregister a backend.
    pub fn unregister(&mut self, kind: DebuggerClientKind) -> Option<BackendRegistration> {
        self.backends.remove(&kind)
    }

    /// Get a registration by kind.
    pub fn get(&self, kind: DebuggerClientKind) -> Option<&BackendRegistration> {
        self.backends.get(&kind)
    }

    /// Get all registered backend kinds.
    pub fn registered_kinds(&self) -> Vec<DebuggerClientKind> {
        self.backends.keys().copied().collect()
    }

    /// Get all available (installed) backend kinds.
    pub fn available_kinds(&self) -> Vec<DebuggerClientKind> {
        self.backends
            .values()
            .filter(|r| r.available)
            .map(|r| r.kind)
            .collect()
    }

    /// Number of registered backends.
    pub fn len(&self) -> usize {
        self.backends.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }

    /// Mark a backend as available or unavailable.
    pub fn set_available(&mut self, kind: DebuggerClientKind, available: bool) {
        if let Some(reg) = self.backends.get_mut(&kind) {
            reg.available = available;
        }
    }

    /// Register all default Ghidra backends (GDB, LLDB, dbgeng, drgn, x64dbg).
    pub fn register_defaults(&mut self) {
        let kinds = [
            DebuggerClientKind::Gdb,
            DebuggerClientKind::Lldb,
            DebuggerClientKind::Dbgeng,
            DebuggerClientKind::Drgn,
            DebuggerClientKind::X64dbg,
        ];
        for kind in &kinds {
            self.register(BackendRegistration {
                kind: *kind,
                display_name: kind.display_label().to_string(),
                launcher_path: kind.default_launcher().to_string(),
                default_parameters: BTreeMap::new(),
                available: true, // assume available; real impl would probe
            });
        }
    }
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

// ---------------------------------------------------------------------------
// DebuggerClientSession
// ---------------------------------------------------------------------------

/// A debugger client session wrapping a backend with lifecycle management.
///
/// Ported from the session management in Ghidra's `DebuggerClientModel`
/// and `TraceDebuggerLauncher`. Provides a high-level facade over a
/// `DebuggerClientBackend` implementation, tracking the lifecycle state,
/// accumulating events, and providing convenience dispatch methods for
/// standard debug commands.
pub struct DebuggerClientSession {
    /// The backend kind.
    pub kind: DebuggerClientKind,
    /// Description of this session.
    pub description: String,
    /// Current lifecycle state.
    pub state: DebuggerClientState,
    /// Next command ID counter.
    next_command_id: u64,
    /// Pending command IDs.
    pending_commands: Vec<u64>,
    /// Event buffer.
    events: Vec<DebuggerClientEvent>,
    /// Known targets discovered during this session.
    targets: Vec<DebuggerClientTarget>,
    /// The launcher path used for this session.
    pub launcher_path: Option<String>,
    /// The remote address (if applicable).
    pub remote_address: Option<String>,
}

impl DebuggerClientSession {
    /// Create a new session.
    pub fn new(kind: DebuggerClientKind, description: impl Into<String>) -> Self {
        Self {
            kind,
            description: description.into(),
            state: DebuggerClientState::Created,
            next_command_id: 1,
            pending_commands: Vec::new(),
            events: Vec::new(),
            targets: Vec::new(),
            launcher_path: Some(kind.default_launcher().to_string()),
            remote_address: None,
        }
    }

    /// Create a session with a specific launcher path.
    pub fn with_launcher(mut self, path: impl Into<String>) -> Self {
        self.launcher_path = Some(path.into());
        self
    }

    /// Set the remote address for this session.
    pub fn with_remote_address(mut self, addr: impl Into<String>) -> Self {
        self.remote_address = Some(addr.into());
        self
    }

    /// Transition to a new state.
    pub fn set_state(&mut self, state: DebuggerClientState) {
        self.state = state;
    }

    /// Whether this session can accept commands.
    pub fn can_accept_commands(&self) -> bool {
        self.state.is_accepting_commands()
    }

    /// Whether this session is alive.
    pub fn is_alive(&self) -> bool {
        self.state.is_alive()
    }

    /// Allocate a new command ID.
    pub fn next_command_id(&mut self) -> u64 {
        let id = self.next_command_id;
        self.next_command_id += 1;
        id
    }

    /// Create a command with an auto-assigned ID.
    pub fn create_command(&mut self, method: impl Into<String>) -> DebuggerClientCommand {
        let id = self.next_command_id();
        DebuggerClientCommand::new(id, method)
    }

    /// Create a command of a specific standard type.
    pub fn create_standard_command(&mut self, cmd_type: DebuggerCommandType) -> DebuggerClientCommand {
        self.create_command(cmd_type.method_name())
    }

    /// Record a command as sent (add to pending).
    pub fn record_sent(&mut self, command_id: u64) {
        self.pending_commands.push(command_id);
    }

    /// Record a response received (remove from pending).
    pub fn record_received(&mut self, command_id: u64) {
        self.pending_commands.retain(|&id| id != command_id);
    }

    /// Number of pending commands.
    pub fn pending_count(&self) -> usize {
        self.pending_commands.len()
    }

    /// Push an event into the buffer.
    pub fn push_event(&mut self, event: DebuggerClientEvent) {
        self.events.push(event);
    }

    /// Drain all events from the buffer.
    pub fn drain_events(&mut self) -> Vec<DebuggerClientEvent> {
        std::mem::take(&mut self.events)
    }

    /// Number of buffered events.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Update the list of known targets.
    pub fn set_targets(&mut self, targets: Vec<DebuggerClientTarget>) {
        self.targets = targets;
    }

    /// Get the known targets.
    pub fn targets(&self) -> &[DebuggerClientTarget] {
        &self.targets
    }

    /// Get the number of targets.
    pub fn target_count(&self) -> usize {
        self.targets.len()
    }

    /// Close the session.
    pub fn close(&mut self) {
        self.state = DebuggerClientState::Shutdown;
        self.pending_commands.clear();
        self.events.clear();
        self.targets.clear();
    }
}

impl std::fmt::Debug for DebuggerClientSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DebuggerClientSession")
            .field("kind", &self.kind)
            .field("description", &self.description)
            .field("state", &self.state)
            .field("pending_count", &self.pending_commands.len())
            .field("event_count", &self.events.len())
            .field("target_count", &self.targets.len())
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

    // -----------------------------------------------------------------------
    // DebuggerCommandType tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_command_type_display_name() {
        assert_eq!(DebuggerCommandType::Resume.display_name(), "Resume");
        assert_eq!(DebuggerCommandType::StepOver.display_name(), "Step Over");
        assert_eq!(DebuggerCommandType::ReadMemory.display_name(), "Read Memory");
        assert_eq!(DebuggerCommandType::SetBreakpoint.display_name(), "Set Breakpoint");
    }

    #[test]
    fn test_command_type_method_name() {
        assert_eq!(DebuggerCommandType::Resume.method_name(), "resume");
        assert_eq!(DebuggerCommandType::StepOver.method_name(), "stepOver");
        assert_eq!(DebuggerCommandType::ReadMemory.method_name(), "readMemory");
        assert_eq!(DebuggerCommandType::Disassemble.method_name(), "disassemble");
    }

    #[test]
    fn test_command_type_equality() {
        assert_eq!(DebuggerCommandType::Resume, DebuggerCommandType::Resume);
        assert_ne!(DebuggerCommandType::Resume, DebuggerCommandType::Step);
    }

    #[test]
    fn test_command_type_all_variants_have_names() {
        let all = [
            DebuggerCommandType::Resume,
            DebuggerCommandType::Step,
            DebuggerCommandType::StepOver,
            DebuggerCommandType::StepOut,
            DebuggerCommandType::Interrupt,
            DebuggerCommandType::Kill,
            DebuggerCommandType::Detach,
            DebuggerCommandType::ReadMemory,
            DebuggerCommandType::WriteMemory,
            DebuggerCommandType::ReadRegister,
            DebuggerCommandType::WriteRegister,
            DebuggerCommandType::ListThreads,
            DebuggerCommandType::SetBreakpoint,
            DebuggerCommandType::RemoveBreakpoint,
            DebuggerCommandType::ListBreakpoints,
            DebuggerCommandType::ListMemoryRegions,
            DebuggerCommandType::ListModules,
            DebuggerCommandType::EvaluateExpression,
            DebuggerCommandType::Disassemble,
        ];
        for cmd in &all {
            // Both display_name and method_name must be non-empty
            assert!(!cmd.display_name().is_empty());
            assert!(!cmd.method_name().is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // DebuggerClientBackendRegistry tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_backend_registry_new() {
        let registry = DebuggerClientBackendRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_backend_registry_register() {
        let mut registry = DebuggerClientBackendRegistry::new();
        registry.register(BackendRegistration {
            kind: DebuggerClientKind::Gdb,
            display_name: "GDB".into(),
            launcher_path: "local-gdb.sh".into(),
            default_parameters: BTreeMap::new(),
            available: true,
        });
        assert_eq!(registry.len(), 1);
        assert!(registry.get(DebuggerClientKind::Gdb).is_some());
    }

    #[test]
    fn test_backend_registry_available_kinds() {
        let mut registry = DebuggerClientBackendRegistry::new();
        registry.register(BackendRegistration {
            kind: DebuggerClientKind::Gdb,
            display_name: "GDB".into(),
            launcher_path: "local-gdb.sh".into(),
            default_parameters: BTreeMap::new(),
            available: true,
        });
        registry.register(BackendRegistration {
            kind: DebuggerClientKind::Lldb,
            display_name: "LLDB".into(),
            launcher_path: "local-lldb.sh".into(),
            default_parameters: BTreeMap::new(),
            available: false,
        });

        let available = registry.available_kinds();
        assert_eq!(available.len(), 1);
        assert_eq!(available[0], DebuggerClientKind::Gdb);

        let all = registry.registered_kinds();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_backend_registry_set_available() {
        let mut registry = DebuggerClientBackendRegistry::new();
        registry.register(BackendRegistration {
            kind: DebuggerClientKind::Lldb,
            display_name: "LLDB".into(),
            launcher_path: "local-lldb.sh".into(),
            default_parameters: BTreeMap::new(),
            available: false,
        });
        assert!(registry.available_kinds().is_empty());

        registry.set_available(DebuggerClientKind::Lldb, true);
        assert_eq!(registry.available_kinds().len(), 1);
    }

    #[test]
    fn test_backend_registry_unregister() {
        let mut registry = DebuggerClientBackendRegistry::new();
        registry.register(BackendRegistration {
            kind: DebuggerClientKind::Gdb,
            display_name: "GDB".into(),
            launcher_path: "local-gdb.sh".into(),
            default_parameters: BTreeMap::new(),
            available: true,
        });
        let removed = registry.unregister(DebuggerClientKind::Gdb);
        assert!(removed.is_some());
        assert!(registry.is_empty());
    }

    #[test]
    fn test_backend_registry_register_defaults() {
        let mut registry = DebuggerClientBackendRegistry::new();
        registry.register_defaults();
        assert_eq!(registry.len(), 5);
        assert!(registry.get(DebuggerClientKind::Gdb).is_some());
        assert!(registry.get(DebuggerClientKind::Lldb).is_some());
        assert!(registry.get(DebuggerClientKind::Dbgeng).is_some());
        assert!(registry.get(DebuggerClientKind::Drgn).is_some());
        assert!(registry.get(DebuggerClientKind::X64dbg).is_some());
    }

    // -----------------------------------------------------------------------
    // DebuggerClientSession tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_session_new() {
        let session = DebuggerClientSession::new(DebuggerClientKind::Gdb, "test session");
        assert_eq!(session.kind, DebuggerClientKind::Gdb);
        assert_eq!(session.description, "test session");
        assert_eq!(session.state, DebuggerClientState::Created);
        assert!(!session.can_accept_commands());
        assert!(session.is_alive());
    }

    #[test]
    fn test_session_state_transitions() {
        let mut session = DebuggerClientSession::new(DebuggerClientKind::Gdb, "test");
        assert_eq!(session.state, DebuggerClientState::Created);

        session.set_state(DebuggerClientState::Connecting);
        assert!(!session.can_accept_commands());
        assert!(session.is_alive());

        session.set_state(DebuggerClientState::Ready);
        assert!(session.can_accept_commands());
        assert!(session.is_alive());

        session.set_state(DebuggerClientState::Active);
        assert!(session.can_accept_commands());
        assert!(session.is_alive());

        session.close();
        assert!(!session.is_alive());
        assert!(!session.can_accept_commands());
    }

    #[test]
    fn test_session_commands() {
        let mut session = DebuggerClientSession::new(DebuggerClientKind::Gdb, "test");
        let c1 = session.create_command("resume");
        let c2 = session.create_command("step");
        assert_eq!(c1.command_id, 1);
        assert_eq!(c2.command_id, 2);

        session.record_sent(c1.command_id);
        session.record_sent(c2.command_id);
        assert_eq!(session.pending_count(), 2);

        session.record_received(c1.command_id);
        assert_eq!(session.pending_count(), 1);
    }

    #[test]
    fn test_session_standard_command() {
        let mut session = DebuggerClientSession::new(DebuggerClientKind::Gdb, "test");
        let cmd = session.create_standard_command(DebuggerCommandType::ReadMemory);
        assert_eq!(cmd.method, "readMemory");
    }

    #[test]
    fn test_session_events() {
        let mut session = DebuggerClientSession::new(DebuggerClientKind::Gdb, "test");
        session.push_event(DebuggerClientEvent::StateChanged {
            target_id: "t1".into(),
            state: "STOPPED".into(),
        });
        session.push_event(DebuggerClientEvent::ConsoleOutput {
            line: "hello".into(),
            is_error: false,
        });
        assert_eq!(session.event_count(), 2);

        let events = session.drain_events();
        assert_eq!(events.len(), 2);
        assert_eq!(session.event_count(), 0);
    }

    #[test]
    fn test_session_targets() {
        let mut session = DebuggerClientSession::new(DebuggerClientKind::Gdb, "test");
        assert_eq!(session.target_count(), 0);

        session.set_targets(vec![
            DebuggerClientTarget {
                target_id: "gdb-1".into(),
                display_name: "Process".into(),
                pid: Some(1234),
                architecture: Some("x86:LE:64:default".into()),
                running: false,
            },
        ]);
        assert_eq!(session.target_count(), 1);
        assert_eq!(session.targets()[0].target_id, "gdb-1");
    }

    #[test]
    fn test_session_with_launcher() {
        let session = DebuggerClientSession::new(DebuggerClientKind::Gdb, "test")
            .with_launcher("/custom/launch.sh");
        assert_eq!(session.launcher_path.as_deref(), Some("/custom/launch.sh"));
    }

    #[test]
    fn test_session_with_remote_address() {
        let session = DebuggerClientSession::new(DebuggerClientKind::Gdb, "test")
            .with_remote_address("localhost:1234");
        assert_eq!(session.remote_address.as_deref(), Some("localhost:1234"));
    }

    #[test]
    fn test_session_close_clears_state() {
        let mut session = DebuggerClientSession::new(DebuggerClientKind::Gdb, "test");
        session.push_event(DebuggerClientEvent::ConsoleOutput {
            line: "test".into(),
            is_error: false,
        });
        session.record_sent(1);
        session.set_targets(vec![]);
        session.close();
        assert_eq!(session.pending_count(), 0);
        assert_eq!(session.event_count(), 0);
        assert_eq!(session.target_count(), 0);
    }

    // -----------------------------------------------------------------------
    // New event variant tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_event_process_created() {
        let event = DebuggerClientEvent::ProcessCreated {
            target_id: "t1".into(),
            pid: 1234,
            executable: Some("/bin/ls".into()),
        };
        match event {
            DebuggerClientEvent::ProcessCreated { target_id, pid, executable } => {
                assert_eq!(target_id, "t1");
                assert_eq!(pid, 1234);
                assert_eq!(executable.as_deref(), Some("/bin/ls"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_event_process_exited() {
        let event = DebuggerClientEvent::ProcessExited {
            target_id: "t1".into(),
            pid: 1234,
            exit_code: Some(0),
        };
        match event {
            DebuggerClientEvent::ProcessExited { exit_code, .. } => {
                assert_eq!(exit_code, Some(0));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_event_library_loaded() {
        let event = DebuggerClientEvent::LibraryLoaded {
            target_id: "t1".into(),
            name: "libc.so.6".into(),
            base_address: 0x7fff_0000_0000,
        };
        match event {
            DebuggerClientEvent::LibraryLoaded { name, base_address, .. } => {
                assert_eq!(name, "libc.so.6");
                assert_eq!(base_address, 0x7fff_0000_0000);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_event_signal_received() {
        let event = DebuggerClientEvent::SignalReceived {
            target_id: "t1".into(),
            signal_name: "SIGSEGV".into(),
            signal_number: Some(11),
        };
        match event {
            DebuggerClientEvent::SignalReceived { signal_name, signal_number, .. } => {
                assert_eq!(signal_name, "SIGSEGV");
                assert_eq!(signal_number, Some(11));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_event_stopped() {
        let event = DebuggerClientEvent::Stopped {
            target_id: "t1".into(),
            reason: "breakpoint-hit".into(),
            pc: Some(0x401000),
        };
        match event {
            DebuggerClientEvent::Stopped { reason, pc, .. } => {
                assert_eq!(reason, "breakpoint-hit");
                assert_eq!(pc, Some(0x401000));
            }
            _ => panic!("wrong variant"),
        }
    }
}
