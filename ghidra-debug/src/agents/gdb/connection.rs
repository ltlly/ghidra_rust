//! GDB agent connection management.
//!
//! Manages the lifecycle of a GDB connection, including launching GDB,
//! connecting to GDBserver, and handling connection state transitions.
//!
//! Ported from the GDB launcher scripts and `GdbConnectorsTest`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Connection mode for the GDB agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GdbConnectionMode {
    /// Local debugging (launch GDB directly).
    Local,
    /// Remote debugging via GDBserver.
    Remote,
    /// Attach to an existing process.
    Attach,
    /// Record and replay (rr).
    RecordReplay,
    /// QEMU system emulation.
    QemuSystem,
    /// SSH tunnel to remote GDB.
    Ssh,
    /// Wine-based debugging.
    Wine,
}

impl GdbConnectionMode {
    /// Human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Local => "Local GDB",
            Self::Remote => "Remote GDBserver",
            Self::Attach => "Attach to Process",
            Self::RecordReplay => "Record and Replay (rr)",
            Self::QemuSystem => "QEMU System Emulation",
            Self::Ssh => "SSH GDB",
            Self::Wine => "Wine GDB",
        }
    }

    /// Default launcher script name for this mode.
    pub fn launcher_script(&self) -> &'static str {
        match self {
            Self::Local => "local-gdb.sh",
            Self::Remote => "remote-gdb.sh",
            Self::Attach => "local-gdb.sh",
            Self::RecordReplay => "local-rr.sh",
            Self::QemuSystem => "qemu-sys-gdb.sh",
            Self::Ssh => "ssh-gdb.sh",
            Self::Wine => "wine-gdb.sh",
        }
    }
}

/// Configuration for a GDB connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GdbConnectionConfig {
    /// The connection mode.
    pub mode: GdbConnectionMode,
    /// Path to the GDB executable.
    pub gdb_path: String,
    /// Target image to debug.
    pub target_image: Option<String>,
    /// Arguments for the target.
    pub target_args: Vec<String>,
    /// Working directory.
    pub working_dir: Option<String>,
    /// GDBserver address (for remote mode).
    pub server_address: Option<String>,
    /// SSH host (for SSH mode).
    pub ssh_host: Option<String>,
    /// SSH user (for SSH mode).
    pub ssh_user: Option<String>,
    /// Additional GDB commands to execute on startup.
    pub init_commands: Vec<String>,
    /// Environment variables.
    pub environment: HashMap<String, String>,
}

impl GdbConnectionConfig {
    /// Create a new local connection config.
    pub fn local(gdb_path: impl Into<String>) -> Self {
        Self {
            mode: GdbConnectionMode::Local,
            gdb_path: gdb_path.into(),
            target_image: None,
            target_args: Vec::new(),
            working_dir: None,
            server_address: None,
            ssh_host: None,
            ssh_user: None,
            init_commands: Vec::new(),
            environment: HashMap::new(),
        }
    }

    /// Create a new remote connection config.
    pub fn remote(gdb_path: impl Into<String>, server_address: impl Into<String>) -> Self {
        Self {
            mode: GdbConnectionMode::Remote,
            gdb_path: gdb_path.into(),
            target_image: None,
            target_args: Vec::new(),
            working_dir: None,
            server_address: Some(server_address.into()),
            ssh_host: None,
            ssh_user: None,
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

    /// Set an environment variable.
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.environment.insert(key.into(), value.into());
        self
    }

    /// Build the GDB launch command line.
    pub fn build_command(&self) -> Vec<String> {
        let mut cmd = vec![self.gdb_path.clone()];
        cmd.push("--interpreter=mi2".to_string());

        if let Some(ref target) = self.target_image {
            cmd.push("-ex".to_string());
            cmd.push(format!("file {}", target));
        }

        for init_cmd in &self.init_commands {
            cmd.push("-ex".to_string());
            cmd.push(init_cmd.clone());
        }

        cmd
    }
}

/// State of a GDB connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GdbConnectionState {
    /// Not connected.
    Disconnected,
    /// GDB is starting.
    Starting,
    /// Waiting for target to be specified.
    WaitingForTarget,
    /// Target is loaded, waiting for run.
    TargetLoaded,
    /// Running (debuggee is executing).
    Running,
    /// Stopped (at breakpoint, signal, etc.).
    Stopped,
    /// Terminated (debuggee exited).
    Terminated,
}

impl GdbConnectionState {
    /// Whether the debuggee can be controlled in this state.
    pub fn is_controllable(&self) -> bool {
        matches!(self, Self::Stopped)
    }

    /// Whether the debuggee is alive (not terminated/disconnected).
    pub fn is_alive(&self) -> bool {
        !matches!(self, Self::Disconnected | Self::Terminated)
    }
}

/// A GDB agent connection.
#[derive(Debug)]
pub struct GdbConnection {
    /// Connection configuration.
    pub config: GdbConnectionConfig,
    /// Current state.
    state: GdbConnectionState,
    /// Process ID of the debuggee, if known.
    pub pid: Option<u64>,
    /// Connection ID for RMI.
    pub connection_id: Option<String>,
    /// GDB version.
    pub version: Option<super::GdbVersion>,
}

impl GdbConnection {
    /// Create a new connection from config.
    pub fn new(config: GdbConnectionConfig) -> Self {
        Self {
            config,
            state: GdbConnectionState::Disconnected,
            pid: None,
            connection_id: None,
            version: None,
        }
    }

    /// Get the current connection state.
    pub fn state(&self) -> GdbConnectionState {
        self.state
    }

    /// Transition to a new state.
    pub fn set_state(&mut self, new_state: GdbConnectionState) {
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

    /// Build the full launch command.
    pub fn build_launch_command(&self) -> Vec<String> {
        self.config.build_command()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_mode_description() {
        assert_eq!(GdbConnectionMode::Local.description(), "Local GDB");
        assert_eq!(GdbConnectionMode::Remote.description(), "Remote GDBserver");
    }

    #[test]
    fn test_connection_config_local() {
        let cfg = GdbConnectionConfig::local("/usr/bin/gdb")
            .with_target("/usr/bin/ls")
            .with_arg("-la");
        assert_eq!(cfg.mode, GdbConnectionMode::Local);
        assert_eq!(cfg.target_image, Some("/usr/bin/ls".to_string()));
        assert_eq!(cfg.target_args, vec!["-la"]);
    }

    #[test]
    fn test_connection_config_remote() {
        let cfg = GdbConnectionConfig::remote("/usr/bin/gdb", "localhost:1234")
            .with_init_command("set pagination off");
        assert_eq!(cfg.mode, GdbConnectionMode::Remote);
        assert_eq!(cfg.server_address, Some("localhost:1234".to_string()));
    }

    #[test]
    fn test_build_command() {
        let cfg = GdbConnectionConfig::local("/usr/bin/gdb")
            .with_target("/usr/bin/ls");
        let cmd = cfg.build_command();
        assert_eq!(cmd[0], "/usr/bin/gdb");
        assert!(cmd.contains(&"--interpreter=mi2".to_string()));
    }

    #[test]
    fn test_connection_state() {
        assert!(!GdbConnectionState::Disconnected.is_alive());
        assert!(GdbConnectionState::Stopped.is_controllable());
        assert!(!GdbConnectionState::Running.is_controllable());
    }

    #[test]
    fn test_connection_lifecycle() {
        let cfg = GdbConnectionConfig::local("/usr/bin/gdb");
        let mut conn = GdbConnection::new(cfg);
        assert_eq!(conn.state(), GdbConnectionState::Disconnected);
        conn.set_state(GdbConnectionState::Starting);
        assert!(conn.is_alive());
        conn.set_state(GdbConnectionState::Stopped);
        assert!(conn.is_controllable());
    }
}
