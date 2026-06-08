//! drgn agent connection management.
//!
//! Manages the lifecycle of a drgn connection for Linux kernel
//! and userspace debugging.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Connection mode for the drgn agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DrgnConnectionMode {
    /// Local kernel debugging (/proc/kcore).
    Local,
    /// Core dump analysis.
    Core,
    /// Kernel crash dump analysis.
    Kernel,
}

impl DrgnConnectionMode {
    /// Human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Local => "Local Kernel",
            Self::Core => "Core Dump",
            Self::Kernel => "Kernel Crash Dump",
        }
    }

    /// Default launcher script name.
    pub fn launcher_script(&self) -> &'static str {
        match self {
            Self::Local => "local-drgn.sh",
            Self::Core => "core-drgn.sh",
            Self::Kernel => "kernel-drgn.sh",
        }
    }
}

/// Configuration for a drgn connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrgnConnectionConfig {
    /// Connection mode.
    pub mode: DrgnConnectionMode,
    /// Core dump file path (for core/kernel modes).
    pub core_path: Option<String>,
    /// vmlinux path (for kernel debugging).
    pub vmlinux_path: Option<String>,
    /// Initial commands.
    pub init_commands: Vec<String>,
    /// Environment variables.
    pub environment: HashMap<String, String>,
}

impl DrgnConnectionConfig {
    /// Create a local kernel debugging config.
    pub fn local() -> Self {
        Self {
            mode: DrgnConnectionMode::Local,
            core_path: None,
            vmlinux_path: None,
            init_commands: Vec::new(),
            environment: HashMap::new(),
        }
    }

    /// Create a core dump analysis config.
    pub fn core(core_path: impl Into<String>) -> Self {
        Self {
            mode: DrgnConnectionMode::Core,
            core_path: Some(core_path.into()),
            vmlinux_path: None,
            init_commands: Vec::new(),
            environment: HashMap::new(),
        }
    }

    /// Set the vmlinux path.
    pub fn with_vmlinux(mut self, path: impl Into<String>) -> Self {
        self.vmlinux_path = Some(path.into());
        self
    }

    /// Add an initialization command.
    pub fn with_init_command(mut self, cmd: impl Into<String>) -> Self {
        self.init_commands.push(cmd.into());
        self
    }
}

/// State of a drgn connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DrgnConnectionState {
    /// Not connected.
    Disconnected,
    /// drgn is starting.
    Starting,
    /// Program loaded (kernel or core dump).
    ProgramLoaded,
    /// Debugging active.
    Active,
    /// Error state.
    Error,
}

impl DrgnConnectionState {
    /// Whether debugging is active.
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Whether the connection is alive.
    pub fn is_alive(&self) -> bool {
        !matches!(self, Self::Disconnected | Self::Error)
    }
}

/// A drgn agent connection.
#[derive(Debug)]
pub struct DrgnConnection {
    /// Configuration.
    pub config: DrgnConnectionConfig,
    /// Current state.
    state: DrgnConnectionState,
    /// Connection ID for RMI.
    pub connection_id: Option<String>,
    /// drgn version.
    pub version: Option<super::DrgnVersion>,
    /// Whether this is a kernel debug session.
    pub is_kernel: bool,
}

impl DrgnConnection {
    /// Create a new connection.
    pub fn new(config: DrgnConnectionConfig) -> Self {
        let is_kernel = matches!(
            config.mode,
            DrgnConnectionMode::Local | DrgnConnectionMode::Kernel
        );
        Self {
            config,
            state: DrgnConnectionState::Disconnected,
            connection_id: None,
            version: None,
            is_kernel,
        }
    }

    /// Get current state.
    pub fn state(&self) -> DrgnConnectionState {
        self.state
    }

    /// Transition to a new state.
    pub fn set_state(&mut self, new_state: DrgnConnectionState) {
        self.state = new_state;
    }

    /// Check if debugging is active.
    pub fn is_active(&self) -> bool {
        self.state.is_active()
    }

    /// Check if the connection is alive.
    pub fn is_alive(&self) -> bool {
        self.state.is_alive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_mode() {
        assert_eq!(DrgnConnectionMode::Local.description(), "Local Kernel");
        assert_eq!(DrgnConnectionMode::Core.description(), "Core Dump");
    }

    #[test]
    fn test_connection_config_local() {
        let cfg = DrgnConnectionConfig::local();
        assert_eq!(cfg.mode, DrgnConnectionMode::Local);
        assert!(cfg.core_path.is_none());
    }

    #[test]
    fn test_connection_config_core() {
        let cfg = DrgnConnectionConfig::core("/var/crash/vmcore")
            .with_vmlinux("/boot/vmlinux-5.15.0");
        assert_eq!(cfg.mode, DrgnConnectionMode::Core);
        assert!(cfg.vmlinux_path.is_some());
    }

    #[test]
    fn test_connection_state() {
        assert!(DrgnConnectionState::Active.is_active());
        assert!(!DrgnConnectionState::Disconnected.is_alive());
    }

    #[test]
    fn test_connection_lifecycle() {
        let cfg = DrgnConnectionConfig::local();
        let mut conn = DrgnConnection::new(cfg);
        assert!(conn.is_kernel);
        conn.set_state(DrgnConnectionState::ProgramLoaded);
        assert!(conn.is_alive());
    }
}
