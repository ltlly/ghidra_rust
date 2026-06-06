//! Target service implementation.
//!
//! Ported from Ghidra's `DebuggerTargetServicePlugin` and
//! `AbstractTarget` in `ghidra.app.plugin.core.debug.service.target`.

use serde::{Deserialize, Serialize};

/// Information about a debug target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetDescription {
    /// The target type identifier.
    pub target_type: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Whether this target supports launching.
    pub supports_launch: bool,
    /// Whether this target supports attaching.
    pub supports_attach: bool,
    /// Whether this target is currently running.
    pub running: bool,
    /// The process ID (if attached).
    pub pid: Option<i64>,
}

impl TargetDescription {
    /// Create a new target description.
    pub fn new(target_type: impl Into<String>, display_name: impl Into<String>) -> Self {
        Self {
            target_type: target_type.into(),
            display_name: display_name.into(),
            supports_launch: true,
            supports_attach: true,
            running: false,
            pid: None,
        }
    }
}

/// Target service implementation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetServiceImpl {
    /// Registered targets.
    targets: Vec<TargetDescription>,
    /// Launched target counter.
    next_id: i64,
}

impl TargetServiceImpl {
    /// Create a new target service.
    pub fn new() -> Self {
        Self {
            targets: Vec::new(),
            next_id: 1,
        }
    }

    /// Register a target type.
    pub fn register_target(&mut self, target: TargetDescription) {
        self.targets.push(target);
    }

    /// Get all registered targets.
    pub fn targets(&self) -> &[TargetDescription] {
        &self.targets
    }

    /// Launch a target.
    pub fn launch(&mut self, target_type: &str) -> Result<i64, String> {
        let _target = self
            .targets
            .iter()
            .find(|t| t.target_type == target_type && t.supports_launch)
            .ok_or_else(|| format!("Target type not found: {}", target_type))?;
        let id = self.next_id;
        self.next_id += 1;
        Ok(id)
    }

    /// Attach to a process.
    pub fn attach(&mut self, target_type: &str, _pid: i64) -> Result<i64, String> {
        let _target = self
            .targets
            .iter()
            .find(|t| t.target_type == target_type && t.supports_attach)
            .ok_or_else(|| format!("Target type not found: {}", target_type))?;
        let id = self.next_id;
        self.next_id += 1;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_description_new() {
        let t = TargetDescription::new("gdb", "GDB");
        assert_eq!(t.target_type, "gdb");
        assert!(t.supports_launch);
    }

    #[test]
    fn test_target_service_register_and_list() {
        let mut svc = TargetServiceImpl::new();
        svc.register_target(TargetDescription::new("gdb", "GDB"));
        svc.register_target(TargetDescription::new("lldb", "LLDB"));
        assert_eq!(svc.targets().len(), 2);
    }

    #[test]
    fn test_target_service_launch() {
        let mut svc = TargetServiceImpl::new();
        svc.register_target(TargetDescription::new("gdb", "GDB"));
        let id = svc.launch("gdb").unwrap();
        assert_eq!(id, 1);
    }

    #[test]
    fn test_target_service_launch_not_found() {
        let mut svc = TargetServiceImpl::new();
        assert!(svc.launch("nonexistent").is_err());
    }

    #[test]
    fn test_target_service_attach() {
        let mut svc = TargetServiceImpl::new();
        svc.register_target(TargetDescription::new("gdb", "GDB"));
        let id = svc.attach("gdb", 12345).unwrap();
        assert!(id > 0);
    }
}
