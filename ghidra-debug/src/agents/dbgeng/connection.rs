//! Dbgeng agent connection management.
//!
//! Manages the lifecycle of a Windows Debugging Engine connection.
//! Supports local debugging, kernel debugging, remote debugging,
//! and attaching to existing processes.
//!
//! Ported from `Debugger-agent-dbgeng` launcher scripts.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Connection mode for the dbgeng agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DbgEngConnectionMode {
    /// Local debugging (launch process).
    Local,
    /// Attach to existing process.
    Attach,
    /// Kernel debugging.
    Kernel,
    /// Remote debugging via debugging server.
    Remote,
    /// SSH tunnel to remote debugging server.
    Ssh,
    /// Server mode (wait for connections).
    Server,
    /// Use existing debugging extension DLL.
    Extension,
}

impl DbgEngConnectionMode {
    /// Human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Local => "Local DbgEng",
            Self::Attach => "Attach to Process",
            Self::Kernel => "Kernel Debugging",
            Self::Remote => "Remote DbgEng",
            Self::Ssh => "SSH DbgEng",
            Self::Server => "Server Mode",
            Self::Extension => "Extension DLL",
        }
    }

    /// Default launcher script for this mode.
    pub fn launcher_script(&self) -> &'static str {
        match self {
            Self::Local => "local-dbgeng.py",
            Self::Attach => "local-dbgeng-attach.py",
            Self::Kernel => "kernel-dbgeng.py",
            Self::Remote => "remote-dbgeng.py",
            Self::Ssh => "ssh-dbgeng.py",
            Self::Server => "standalone_listener.py",
            Self::Extension => "local-dbgeng-ext.py",
        }
    }
}

/// Configuration for a dbgeng connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbgEngConnectionConfig {
    /// Connection mode.
    pub mode: DbgEngConnectionMode,
    /// Target image to debug.
    pub target_image: Option<String>,
    /// Arguments for the target.
    pub target_args: Vec<String>,
    /// Working directory.
    pub working_dir: Option<String>,
    /// Process ID to attach to (for attach mode).
    pub attach_pid: Option<u32>,
    /// Remote server address.
    pub server_address: Option<String>,
    /// SSH host.
    pub ssh_host: Option<String>,
    /// SSH user.
    pub ssh_user: Option<String>,
    /// Path to debugging extension DLL.
    pub extension_dll: Option<String>,
    /// Initial debugger commands.
    pub init_commands: Vec<String>,
    /// Environment variables.
    pub environment: HashMap<String, String>,
    /// Whether to start a trace automatically.
    pub start_trace: bool,
}

impl DbgEngConnectionConfig {
    /// Create a new local connection config.
    pub fn local() -> Self {
        Self {
            mode: DbgEngConnectionMode::Local,
            target_image: None,
            target_args: Vec::new(),
            working_dir: None,
            attach_pid: None,
            server_address: None,
            ssh_host: None,
            ssh_user: None,
            extension_dll: None,
            init_commands: Vec::new(),
            environment: HashMap::new(),
            start_trace: true,
        }
    }

    /// Create a new attach connection config.
    pub fn attach(pid: u32) -> Self {
        Self {
            mode: DbgEngConnectionMode::Attach,
            target_image: None,
            target_args: Vec::new(),
            working_dir: None,
            attach_pid: Some(pid),
            server_address: None,
            ssh_host: None,
            ssh_user: None,
            extension_dll: None,
            init_commands: Vec::new(),
            environment: HashMap::new(),
            start_trace: true,
        }
    }

    /// Create a new kernel debugging config.
    pub fn kernel() -> Self {
        Self {
            mode: DbgEngConnectionMode::Kernel,
            target_image: None,
            target_args: Vec::new(),
            working_dir: None,
            attach_pid: None,
            server_address: None,
            ssh_host: None,
            ssh_user: None,
            extension_dll: None,
            init_commands: Vec::new(),
            environment: HashMap::new(),
            start_trace: true,
        }
    }

    /// Set the target image.
    pub fn with_target(mut self, image: impl Into<String>) -> Self {
        self.target_image = Some(image.into());
        self
    }

    /// Add a target argument.
    pub fn with_arg(mut self, arg: impl Into<String>) -> Self {
        self.target_args.push(arg.into());
        self
    }

    /// Set the working directory.
    pub fn with_working_dir(mut self, dir: impl Into<String>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    /// Add an initialization command.
    pub fn with_init_command(mut self, cmd: impl Into<String>) -> Self {
        self.init_commands.push(cmd.into());
        self
    }

    /// Set an environment variable.
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.environment.insert(key.into(), value.into());
        self
    }
}

/// State of a dbgeng connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DbgEngConnectionState {
    /// Not connected.
    Disconnected,
    /// Engine is starting.
    Starting,
    /// Waiting for target.
    WaitingForTarget,
    /// Target loaded.
    TargetLoaded,
    /// Debuggee is running.
    Running,
    /// Debuggee is stopped.
    Stopped,
    /// Debuggee has exited.
    Terminated,
    /// Kernel waiting for connection.
    WaitingForKernel,
}

impl DbgEngConnectionState {
    /// Whether the debuggee can be controlled in this state.
    pub fn is_controllable(&self) -> bool {
        matches!(self, Self::Stopped)
    }

    /// Whether the debuggee is alive.
    pub fn is_alive(&self) -> bool {
        !matches!(self, Self::Disconnected | Self::Terminated)
    }
}

/// A dbgeng agent connection.
#[derive(Debug)]
pub struct DbgEngConnection {
    /// Configuration.
    pub config: DbgEngConnectionConfig,
    /// Current state.
    state: DbgEngConnectionState,
    /// Process ID of the debuggee.
    pub pid: Option<u64>,
    /// Connection ID for RMI.
    pub connection_id: Option<String>,
    /// Engine version info.
    pub version: Option<super::DbgEngVersion>,
    /// Whether target is 64-bit.
    pub is_64bit: bool,
}

impl DbgEngConnection {
    /// Create a new connection.
    pub fn new(config: DbgEngConnectionConfig) -> Self {
        Self {
            config,
            state: DbgEngConnectionState::Disconnected,
            pid: None,
            connection_id: None,
            version: None,
            is_64bit: true,
        }
    }

    /// Get current state.
    pub fn state(&self) -> DbgEngConnectionState {
        self.state
    }

    /// Transition to a new state.
    pub fn set_state(&mut self, new_state: DbgEngConnectionState) {
        self.state = new_state;
    }

    /// Check if the debuggee can be controlled.
    pub fn is_controllable(&self) -> bool {
        self.state.is_controllable()
    }

    /// Check if the debuggee is alive.
    pub fn is_alive(&self) -> bool {
        self.state.is_alive()
    }

    /// Build environment variables for the launcher.
    pub fn build_env(&self) -> HashMap<String, String> {
        let mut env = self.config.environment.clone();
        if let Some(ref addr) = self.config.server_address {
            env.insert("GHIDRA_TRACE_RMI_ADDR".to_string(), addr.clone());
        }
        if let Some(ref target) = self.config.target_image {
            env.insert("OPT_TARGET_IMG".to_string(), target.clone());
        }
        env
    }

    /// Build the command to interrupt the debuggee.
    pub fn build_interrupt_command() -> &'static str {
        "SetInterrupt(DEBUG_INTERRUPT_ACTIVE)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_mode_description() {
        assert_eq!(DbgEngConnectionMode::Local.description(), "Local DbgEng");
        assert_eq!(DbgEngConnectionMode::Kernel.description(), "Kernel Debugging");
    }

    #[test]
    fn test_connection_config_local() {
        let cfg = DbgEngConnectionConfig::local()
            .with_target("C:\\test.exe")
            .with_arg("--help");
        assert_eq!(cfg.mode, DbgEngConnectionMode::Local);
        assert_eq!(cfg.target_image, Some("C:\\test.exe".to_string()));
    }

    #[test]
    fn test_connection_config_attach() {
        let cfg = DbgEngConnectionConfig::attach(1234);
        assert_eq!(cfg.mode, DbgEngConnectionMode::Attach);
        assert_eq!(cfg.attach_pid, Some(1234));
    }

    #[test]
    fn test_connection_state() {
        assert!(DbgEngConnectionState::Stopped.is_controllable());
        assert!(!DbgEngConnectionState::Running.is_controllable());
        assert!(!DbgEngConnectionState::Terminated.is_alive());
        assert!(DbgEngConnectionState::Starting.is_alive());
    }

    #[test]
    fn test_connection_lifecycle() {
        let cfg = DbgEngConnectionConfig::local();
        let mut conn = DbgEngConnection::new(cfg);
        assert_eq!(conn.state(), DbgEngConnectionState::Disconnected);
        conn.set_state(DbgEngConnectionState::Starting);
        assert!(conn.is_alive());
        conn.set_state(DbgEngConnectionState::Stopped);
        assert!(conn.is_controllable());
    }
}
