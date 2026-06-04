//! Platform-related API types for the debugger.
//!
//! Ported from Ghidra's `ghidra.debug.api.platform` and
//! `ghidra.app.services.DebuggerPlatformService`.
//! Provides types for describing debugger platforms (GDB, LLDB, etc.)
//! and their capabilities.

use serde::{Deserialize, Serialize};

/// Describes a debugger platform and its capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformDescription {
    /// The unique platform identifier (e.g., "gdb", "lldb", "dbgeng").
    pub id: String,
    /// Human-readable display name (e.g., "GNU Debugger (GDB)").
    pub display_name: String,
    /// The architecture(s) supported.
    pub architectures: Vec<String>,
    /// The operating system(s) supported.
    pub operating_systems: Vec<String>,
    /// Whether this platform supports launching new processes.
    pub supports_launch: bool,
    /// Whether this platform supports attaching to running processes.
    pub supports_attach: bool,
    /// Whether this platform supports kernel debugging.
    pub supports_kernel_debug: bool,
    /// Whether this platform supports remote debugging.
    pub supports_remote: bool,
}

impl PlatformDescription {
    /// Create a new platform description.
    pub fn new(id: impl Into<String>, display_name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            display_name: display_name.into(),
            architectures: Vec::new(),
            operating_systems: Vec::new(),
            supports_launch: true,
            supports_attach: true,
            supports_kernel_debug: false,
            supports_remote: false,
        }
    }

    /// Add a supported architecture.
    pub fn with_arch(mut self, arch: impl Into<String>) -> Self {
        self.architectures.push(arch.into());
        self
    }

    /// Add a supported operating system.
    pub fn with_os(mut self, os: impl Into<String>) -> Self {
        self.operating_systems.push(os.into());
        self
    }

    /// Enable kernel debugging support.
    pub fn with_kernel_debug(mut self) -> Self {
        self.supports_kernel_debug = true;
        self
    }

    /// Enable remote debugging support.
    pub fn with_remote(mut self) -> Self {
        self.supports_remote = true;
        self
    }
}

/// Describes a connection to a debugger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerConnection {
    /// The platform being used.
    pub platform: String,
    /// The connection string (e.g., "localhost:1234" for remote).
    pub connection_string: String,
    /// Whether this is a remote connection.
    pub is_remote: bool,
    /// Optional additional parameters.
    pub parameters: std::collections::BTreeMap<String, String>,
}

impl DebuggerConnection {
    /// Create a new local connection.
    pub fn local(platform: impl Into<String>) -> Self {
        Self {
            platform: platform.into(),
            connection_string: "local".into(),
            is_remote: false,
            parameters: std::collections::BTreeMap::new(),
        }
    }

    /// Create a new remote connection.
    pub fn remote(platform: impl Into<String>, connection: impl Into<String>) -> Self {
        Self {
            platform: platform.into(),
            connection_string: connection.into(),
            is_remote: true,
            parameters: std::collections::BTreeMap::new(),
        }
    }

    /// Add a connection parameter.
    pub fn with_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.parameters.insert(key.into(), value.into());
        self
    }
}

/// A descriptor for a process available for attaching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessDescriptor {
    /// The process ID.
    pub pid: u64,
    /// The process name.
    pub name: String,
    /// The user running the process.
    pub user: Option<String>,
    /// The architecture of the process.
    pub arch: Option<String>,
}

impl ProcessDescriptor {
    /// Create a new process descriptor.
    pub fn new(pid: u64, name: impl Into<String>) -> Self {
        Self {
            pid,
            name: name.into(),
            user: None,
            arch: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_description() {
        let gdb = PlatformDescription::new("gdb", "GNU Debugger")
            .with_arch("x86_64")
            .with_arch("arm")
            .with_os("linux")
            .with_remote();
        assert_eq!(gdb.id, "gdb");
        assert_eq!(gdb.architectures.len(), 2);
        assert!(gdb.supports_remote);
        assert!(!gdb.supports_kernel_debug);
    }

    #[test]
    fn test_debugger_connection_local() {
        let conn = DebuggerConnection::local("gdb");
        assert!(!conn.is_remote);
        assert_eq!(conn.connection_string, "local");
    }

    #[test]
    fn test_debugger_connection_remote() {
        let conn = DebuggerConnection::remote("gdb", "localhost:1234")
            .with_param("arch", "x86_64");
        assert!(conn.is_remote);
        assert_eq!(conn.parameters.get("arch").unwrap(), "x86_64");
    }

    #[test]
    fn test_process_descriptor() {
        let proc = ProcessDescriptor::new(1234, "target_app");
        assert_eq!(proc.pid, 1234);
        assert_eq!(proc.name, "target_app");
        assert!(proc.user.is_none());
    }
}
