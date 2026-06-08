//! LLDB agent connection management.
//!
//! Manages the lifecycle of an LLDB connection, including launching LLDB
//! locally, via SSH, for Android debugging, or kernel debugging.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Connection mode for the LLDB agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LldbConnectionMode {
    /// Local debugging.
    Local,
    /// Remote debugging via LLDB server.
    Remote,
    /// SSH tunnel to remote LLDB.
    Ssh,
    /// Android debugging (adb forward).
    Android,
    /// Attach to existing process.
    Attach,
    /// Kernel debugging.
    Kernel,
}

impl LldbConnectionMode {
    /// Human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Local => "Local LLDB",
            Self::Remote => "Remote LLDB Server",
            Self::Ssh => "SSH LLDB",
            Self::Android => "Android LLDB",
            Self::Attach => "Attach to Process",
            Self::Kernel => "Kernel LLDB",
        }
    }

    /// Default launcher script name.
    pub fn launcher_script(&self) -> &'static str {
        match self {
            Self::Local => "local-lldb.sh",
            Self::Remote => "remote-lldb.sh",
            Self::Ssh => "ssh-lldb.sh",
            Self::Android => "android-lldb.sh",
            Self::Attach => "local-lldb.sh",
            Self::Kernel => "kernel-lldb.sh",
        }
    }
}

/// Configuration for an LLDB connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LldbConnectionConfig {
    /// Connection mode.
    pub mode: LldbConnectionMode,
    /// Path to the LLDB executable.
    pub lldb_path: String,
    /// Target image to debug.
    pub target_image: Option<String>,
    /// Target arguments.
    pub target_args: Vec<String>,
    /// Working directory.
    pub working_dir: Option<String>,
    /// Remote server address.
    pub server_address: Option<String>,
    /// SSH host.
    pub ssh_host: Option<String>,
    /// SSH user.
    pub ssh_user: Option<String>,
    /// Android device serial.
    pub android_serial: Option<String>,
    /// Initial LLDB commands.
    pub init_commands: Vec<String>,
    /// Environment variables.
    pub environment: HashMap<String, String>,
}

impl LldbConnectionConfig {
    /// Create a new local connection config.
    pub fn local(lldb_path: impl Into<String>) -> Self {
        Self {
            mode: LldbConnectionMode::Local,
            lldb_path: lldb_path.into(),
            target_image: None,
            target_args: Vec::new(),
            working_dir: None,
            server_address: None,
            ssh_host: None,
            ssh_user: None,
            android_serial: None,
            init_commands: Vec::new(),
            environment: HashMap::new(),
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
}

/// State of an LLDB connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LldbConnectionState {
    /// Not connected.
    Disconnected,
    /// LLDB is starting.
    Starting,
    /// Target loaded.
    TargetLoaded,
    /// Debuggee is running.
    Running,
    /// Debuggee is stopped.
    Stopped,
    /// Debuggee has exited.
    Terminated,
}

impl LldbConnectionState {
    /// Whether the debuggee can be controlled.
    pub fn is_controllable(&self) -> bool {
        matches!(self, Self::Stopped)
    }

    /// Whether the debuggee is alive.
    pub fn is_alive(&self) -> bool {
        !matches!(self, Self::Disconnected | Self::Terminated)
    }
}

/// An LLDB agent connection.
#[derive(Debug)]
pub struct LldbConnection {
    /// Configuration.
    pub config: LldbConnectionConfig,
    /// Current state.
    state: LldbConnectionState,
    /// Process ID of the debuggee.
    pub pid: Option<u64>,
    /// Connection ID for RMI.
    pub connection_id: Option<String>,
    /// LLDB version.
    pub version: Option<super::LldbVersion>,
}

impl LldbConnection {
    /// Create a new connection.
    pub fn new(config: LldbConnectionConfig) -> Self {
        Self {
            config,
            state: LldbConnectionState::Disconnected,
            pid: None,
            connection_id: None,
            version: None,
        }
    }

    /// Get current state.
    pub fn state(&self) -> LldbConnectionState {
        self.state
    }

    /// Transition to a new state.
    pub fn set_state(&mut self, new_state: LldbConnectionState) {
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

    /// Build the LLDB launch command.
    pub fn build_launch_command(&self) -> Vec<String> {
        let mut cmd = vec![self.config.lldb_path.clone()];
        if let Some(ref target) = self.config.target_image {
            cmd.push("--".to_string());
            cmd.push(target.clone());
            cmd.extend(self.config.target_args.iter().cloned());
        }
        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_mode() {
        assert_eq!(LldbConnectionMode::Local.description(), "Local LLDB");
        assert_eq!(LldbConnectionMode::Android.description(), "Android LLDB");
    }

    #[test]
    fn test_connection_config() {
        let cfg = LldbConnectionConfig::local("/usr/bin/lldb")
            .with_target("/usr/bin/ls")
            .with_arg("-la");
        assert_eq!(cfg.mode, LldbConnectionMode::Local);
        assert_eq!(cfg.target_image, Some("/usr/bin/ls".to_string()));
    }

    #[test]
    fn test_connection_state() {
        assert!(LldbConnectionState::Stopped.is_controllable());
        assert!(!LldbConnectionState::Terminated.is_alive());
    }

    #[test]
    fn test_build_launch_command() {
        let cfg = LldbConnectionConfig::local("/usr/bin/lldb")
            .with_target("/usr/bin/ls");
        let conn = LldbConnection::new(cfg);
        let cmd = conn.build_launch_command();
        assert_eq!(cmd[0], "/usr/bin/lldb");
        assert!(cmd.contains(&"--".to_string()));
    }
}
