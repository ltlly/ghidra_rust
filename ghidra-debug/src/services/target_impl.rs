//! Target service implementation.
//!
//! Ported from Ghidra's `AbstractTarget` and `DebuggerTargetServicePlugin`.
//! Manages debug target lifecycle (launch, attach, connect, disconnect).

use std::collections::HashMap;

use crate::services::{TargetInfo, TargetService};

/// An active debug target.
#[derive(Debug, Clone)]
pub struct ActiveTarget {
    /// Unique key for this target.
    pub key: i64,
    /// The target type identifier.
    pub target_type: String,
    /// The display name.
    pub display_name: String,
    /// Whether this target is connected.
    pub connected: bool,
    /// The process ID attached to (if any).
    pub pid: Option<i64>,
    /// Additional parameters.
    pub parameters: HashMap<String, String>,
}

impl ActiveTarget {
    /// Create a new active target.
    pub fn new(key: i64, target_type: impl Into<String>, display_name: impl Into<String>) -> Self {
        Self {
            key,
            target_type: target_type.into(),
            display_name: display_name.into(),
            connected: false,
            pid: None,
            parameters: HashMap::new(),
        }
    }
}

/// Default target service implementation.
#[derive(Debug)]
pub struct DefaultTargetService {
    next_key: i64,
    targets: Vec<TargetInfo>,
    active_targets: HashMap<i64, ActiveTarget>,
}

impl DefaultTargetService {
    /// Create a new default target service.
    pub fn new() -> Self {
        let mut svc = Self {
            next_key: 1,
            targets: Vec::new(),
            active_targets: HashMap::new(),
        };
        svc.register_builtins();
        svc
    }

    fn register_builtins(&mut self) {
        self.targets.push(TargetInfo {
            target_type: "gdb".into(),
            display_name: "GDB".into(),
            supports_launch: true,
            supports_attach: true,
        });
        self.targets.push(TargetInfo {
            target_type: "lldb".into(),
            display_name: "LLDB".into(),
            supports_launch: true,
            supports_attach: true,
        });
        self.targets.push(TargetInfo {
            target_type: "dbgeng".into(),
            display_name: "Windows Debugger".into(),
            supports_launch: true,
            supports_attach: true,
        });
        self.targets.push(TargetInfo {
            target_type: "frida".into(),
            display_name: "Frida".into(),
            supports_launch: true,
            supports_attach: true,
        });
        self.targets.push(TargetInfo {
            target_type: "jdi".into(),
            display_name: "Java Debug Interface".into(),
            supports_launch: true,
            supports_attach: true,
        });
    }

    /// Get an active target by key.
    pub fn active_target_info(&self, key: i64) -> Option<&ActiveTarget> {
        self.active_targets.get(&key)
    }

    /// Disconnect a target.
    pub fn disconnect_target(&mut self, key: i64) -> Result<(), String> {
        if let Some(target) = self.active_targets.get_mut(&key) {
            target.connected = false;
            Ok(())
        } else {
            Err(format!("No target with key {}", key))
        }
    }
}

impl Default for DefaultTargetService {
    fn default() -> Self {
        Self::new()
    }
}

impl TargetService for DefaultTargetService {
    fn targets(&self) -> Vec<TargetInfo> {
        self.targets.clone()
    }

    fn launch(&mut self, target_type: &str, params: &[String]) -> Result<i64, String> {
        if !self.targets.iter().any(|t| t.target_type == target_type) {
            return Err(format!("Unknown target type: {}", target_type));
        }
        let key = self.next_key;
        self.next_key += 1;
        let display = format!("{}-{}", target_type, key);
        let mut target = ActiveTarget::new(key, target_type, display);
        target.connected = true;
        for (i, param) in params.iter().enumerate() {
            target
                .parameters
                .insert(format!("param_{}", i), param.clone());
        }
        self.active_targets.insert(key, target);
        Ok(key)
    }

    fn attach(&mut self, target_type: &str, pid: i64) -> Result<i64, String> {
        if !self.targets.iter().any(|t| t.target_type == target_type) {
            return Err(format!("Unknown target type: {}", target_type));
        }
        let key = self.next_key;
        self.next_key += 1;
        let display = format!("{}-pid{}", target_type, pid);
        let mut target = ActiveTarget::new(key, target_type, display);
        target.connected = true;
        target.pid = Some(pid);
        self.active_targets.insert(key, target);
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_builtins() {
        let svc = DefaultTargetService::new();
        assert!(svc.targets.iter().any(|t| t.target_type == "gdb"));
        assert!(svc.targets.iter().any(|t| t.target_type == "lldb"));
        assert!(svc.targets.iter().any(|t| t.target_type == "frida"));
    }

    #[test]
    fn test_launch() {
        let mut svc = DefaultTargetService::new();
        let key = svc.launch("gdb", &["--args".into(), "prog".into()]).unwrap();
        assert_eq!(key, 1);
        let info = svc.active_target_info(key).unwrap();
        assert!(info.connected);
        assert_eq!(info.parameters.len(), 2);
    }

    #[test]
    fn test_attach() {
        let mut svc = DefaultTargetService::new();
        let key = svc.attach("gdb", 1234).unwrap();
        let info = svc.active_target_info(key).unwrap();
        assert!(info.connected);
        assert_eq!(info.pid, Some(1234));
    }

    #[test]
    fn test_launch_unknown_type() {
        let mut svc = DefaultTargetService::new();
        assert!(svc.launch("unknown", &[]).is_err());
    }

    #[test]
    fn test_disconnect() {
        let mut svc = DefaultTargetService::new();
        let key = svc.launch("gdb", &[]).unwrap();
        svc.disconnect_target(key).unwrap();
        let info = svc.active_target_info(key).unwrap();
        assert!(!info.connected);
    }
}
