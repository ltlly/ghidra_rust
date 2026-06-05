//! DebuggerTargetService - service for managing debug targets.
//!
//! Ported from Ghidra's `ghidra.app.services.DebuggerTargetService`.

use serde::{Deserialize, Serialize};

/// Information about an available debug target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetInfo {
    /// The target type identifier.
    pub target_type: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Whether this target supports launch.
    pub supports_launch: bool,
    /// Whether this target supports attach.
    pub supports_attach: bool,
}

/// Service interface for managing debug targets.
pub trait DebuggerTargetServiceExt {
    /// Get all available targets.
    fn targets(&self) -> Vec<TargetInfo>;

    /// Launch a target.
    fn launch(&mut self, target_type: &str, params: &[String]) -> Result<i64, String>;

    /// Attach to an existing process.
    fn attach(&mut self, target_type: &str, pid: i64) -> Result<i64, String>;

    /// Detach from a target.
    fn detach(&mut self, target_key: i64) -> Result<(), String>;

    /// Kill a target.
    fn kill(&mut self, target_key: i64) -> Result<(), String>;

    /// Get the currently active target key.
    fn active_target(&self) -> Option<i64>;

    /// Connect to a remote target.
    fn connect_remote(
        &mut self,
        connector_type: &str,
        address: &str,
    ) -> Result<i64, String>;

    /// Get running processes on a target.
    fn get_processes(&self, target_key: i64) -> Result<Vec<ProcessInfo>, String>;
}

/// Information about a running process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Process ID.
    pub pid: i64,
    /// Process name.
    pub name: String,
    /// Whether this process is already attached.
    pub attached: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_info() {
        let info = TargetInfo {
            target_type: "gdb".into(),
            display_name: "GDB".into(),
            supports_launch: true,
            supports_attach: true,
        };
        assert!(info.supports_launch);
    }

    #[test]
    fn test_process_info() {
        let proc = ProcessInfo {
            pid: 1234,
            name: "test.exe".into(),
            attached: false,
        };
        assert_eq!(proc.pid, 1234);
        assert!(!proc.attached);
    }
}
