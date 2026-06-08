//! x64dbg agent connection management.
//!
//! Manages the lifecycle of an x64dbg connection. The agent connects
//! to x64dbg via the x64dbg_automate Python library which provides
//! scriptable access to the debugger.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Connection mode for the x64dbg agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum X64DbgConnectionMode {
    /// Local debugging (launch x64dbg).
    Local,
    /// Attach to an existing process.
    Attach,
    /// SSH tunnel to remote x64dbg.
    Ssh,
}

impl X64DbgConnectionMode {
    /// Human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Local => "Local x64dbg",
            Self::Attach => "Attach to Process",
            Self::Ssh => "SSH x64dbg",
        }
    }

    /// Default launcher script name.
    pub fn launcher_script(&self) -> &'static str {
        match self {
            Self::Local => "local-x64dbg.py",
            Self::Attach => "local-x64dbg-attach.py",
            Self::Ssh => "ssh-x64dbg.py",
        }
    }
}

/// Configuration for an x64dbg connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X64DbgConnectionConfig {
    /// Connection mode.
    pub mode: X64DbgConnectionMode,
    /// Path to the x64dbg executable.
    pub x64dbg_path: String,
    /// Target image to debug.
    pub target_image: Option<String>,
    /// Target arguments.
    pub target_args: Vec<String>,
    /// Working directory.
    pub working_dir: Option<String>,
    /// Process ID to attach to.
    pub attach_pid: Option<u32>,
    /// SSH host.
    pub ssh_host: Option<String>,
    /// SSH user.
    pub ssh_user: Option<String>,
    /// Initial commands.
    pub init_commands: Vec<String>,
    /// Environment variables.
    pub environment: HashMap<String, String>,
    /// Whether to start a trace.
    pub start_trace: bool,
}

impl X64DbgConnectionConfig {
    /// Create a new local connection config.
    pub fn local(x64dbg_path: impl Into<String>) -> Self {
        Self {
            mode: X64DbgConnectionMode::Local,
            x64dbg_path: x64dbg_path.into(),
            target_image: None,
            target_args: Vec::new(),
            working_dir: None,
            attach_pid: None,
            ssh_host: None,
            ssh_user: None,
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

    /// Set an environment variable.
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.environment.insert(key.into(), value.into());
        self
    }

    /// Build environment variables for the launcher.
    pub fn build_env(&self) -> HashMap<String, String> {
        let mut env = self.environment.clone();
        env.insert("OPT_X64DBG_EXE".to_string(), self.x64dbg_path.clone());
        if let Some(ref target) = self.target_image {
            env.insert("OPT_TARGET_IMG".to_string(), target.clone());
        }
        env
    }
}

/// State of an x64dbg connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum X64DbgConnectionState {
    /// Not connected.
    Disconnected,
    /// x64dbg is starting.
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
}

impl X64DbgConnectionState {
    /// Whether the debuggee can be controlled.
    pub fn is_controllable(&self) -> bool {
        matches!(self, Self::Stopped)
    }

    /// Whether the debuggee is alive.
    pub fn is_alive(&self) -> bool {
        !matches!(self, Self::Disconnected | Self::Terminated)
    }
}

/// An x64dbg agent connection.
#[derive(Debug)]
pub struct X64DbgConnection {
    /// Configuration.
    pub config: X64DbgConnectionConfig,
    /// Current state.
    state: X64DbgConnectionState,
    /// Process ID of the debuggee.
    pub pid: Option<u64>,
    /// Connection ID for RMI.
    pub connection_id: Option<String>,
    /// Engine version.
    pub version: Option<super::X64DbgVersion>,
    /// Whether the target is 64-bit.
    pub is_64bit: bool,
}

impl X64DbgConnection {
    /// Create a new connection.
    pub fn new(config: X64DbgConnectionConfig) -> Self {
        Self {
            config,
            state: X64DbgConnectionState::Disconnected,
            pid: None,
            connection_id: None,
            version: None,
            is_64bit: true,
        }
    }

    /// Get current state.
    pub fn state(&self) -> X64DbgConnectionState {
        self.state
    }

    /// Transition to a new state.
    pub fn set_state(&mut self, new_state: X64DbgConnectionState) {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_mode() {
        assert_eq!(X64DbgConnectionMode::Local.description(), "Local x64dbg");
        assert_eq!(X64DbgConnectionMode::Attach.description(), "Attach to Process");
    }

    #[test]
    fn test_connection_config() {
        let cfg = X64DbgConnectionConfig::local("C:\\x64dbg\\x64dbg.exe")
            .with_target("C:\\test.exe")
            .with_arg("--help");
        assert_eq!(cfg.mode, X64DbgConnectionMode::Local);
        assert_eq!(cfg.target_image, Some("C:\\test.exe".to_string()));
    }

    #[test]
    fn test_connection_state() {
        assert!(X64DbgConnectionState::Stopped.is_controllable());
        assert!(!X64DbgConnectionState::Running.is_controllable());
        assert!(!X64DbgConnectionState::Terminated.is_alive());
    }

    #[test]
    fn test_build_env() {
        let cfg = X64DbgConnectionConfig::local("C:\\x64dbg\\x64dbg.exe")
            .with_target("C:\\test.exe");
        let env = cfg.build_env();
        assert_eq!(env.get("OPT_X64DBG_EXE").unwrap(), "C:\\x64dbg\\x64dbg.exe");
        assert_eq!(env.get("OPT_TARGET_IMG").unwrap(), "C:\\test.exe");
    }

    #[test]
    fn test_connection_lifecycle() {
        let cfg = X64DbgConnectionConfig::local("C:\\x64dbg\\x64dbg.exe");
        let mut conn = X64DbgConnection::new(cfg);
        assert_eq!(conn.state(), X64DbgConnectionState::Disconnected);
        conn.set_state(X64DbgConnectionState::Starting);
        assert!(conn.is_alive());
        conn.set_state(X64DbgConnectionState::Stopped);
        assert!(conn.is_controllable());
    }
}
