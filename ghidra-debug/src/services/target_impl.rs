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

/// Abstract base for debug targets.
///
/// Ported from Ghidra's `AbstractTarget`. Provides a common framework
/// for implementing debug target types (GDB, LLDB, etc.) with a
/// standardized lifecycle model.
#[derive(Debug, Clone)]
pub struct AbstractTarget {
    /// The target key (unique identifier).
    pub key: i64,
    /// The target type (e.g., "gdb", "lldb").
    pub target_type: String,
    /// The display name.
    pub display_name: String,
    /// The current execution state.
    pub state: TargetExecutionState,
    /// The process ID (if attached).
    pub pid: Option<i64>,
    /// The thread IDs.
    pub threads: Vec<i64>,
    /// The current thread ID.
    pub current_thread: Option<i64>,
    /// Environment variables.
    pub env: HashMap<String, String>,
    /// Command-line arguments.
    pub args: Vec<String>,
    /// The working directory.
    pub working_dir: Option<String>,
}

/// The execution state of a debug target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetExecutionState {
    /// The target is not started.
    NotStarted,
    /// The target is running.
    Running,
    /// The target is paused (breakpoint hit, step complete, etc.).
    Paused,
    /// The target has terminated.
    Terminated,
    /// The target is in an error state.
    Error,
}

impl AbstractTarget {
    /// Create a new abstract target.
    pub fn new(key: i64, target_type: impl Into<String>, display_name: impl Into<String>) -> Self {
        Self {
            key,
            target_type: target_type.into(),
            display_name: display_name.into(),
            state: TargetExecutionState::NotStarted,
            pid: None,
            threads: Vec::new(),
            current_thread: None,
            env: HashMap::new(),
            args: Vec::new(),
            working_dir: None,
        }
    }

    /// Whether the target is currently alive (not terminated or errored).
    pub fn is_alive(&self) -> bool {
        matches!(
            self.state,
            TargetExecutionState::Running
                | TargetExecutionState::Paused
                | TargetExecutionState::NotStarted
        )
    }

    /// Whether the target is currently running.
    pub fn is_running(&self) -> bool {
        self.state == TargetExecutionState::Running
    }

    /// Whether the target is paused.
    pub fn is_paused(&self) -> bool {
        self.state == TargetExecutionState::Paused
    }

    /// Set the execution state.
    pub fn set_state(&mut self, state: TargetExecutionState) {
        self.state = state;
    }

    /// Add a thread ID.
    pub fn add_thread(&mut self, thread_id: i64) {
        self.threads.push(thread_id);
        if self.current_thread.is_none() {
            self.current_thread = Some(thread_id);
        }
    }

    /// Remove a thread ID.
    pub fn remove_thread(&mut self, thread_id: i64) {
        self.threads.retain(|&t| t != thread_id);
        if self.current_thread == Some(thread_id) {
            self.current_thread = self.threads.first().copied();
        }
    }

    /// Set the current thread.
    pub fn set_current_thread(&mut self, thread_id: Option<i64>) {
        self.current_thread = thread_id;
    }

    /// Set an environment variable.
    pub fn set_env(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.env.insert(key.into(), value.into());
    }

    /// Set command-line arguments.
    pub fn set_args(&mut self, args: Vec<String>) {
        self.args = args;
    }

    /// Set the working directory.
    pub fn set_working_dir(&mut self, dir: impl Into<String>) {
        self.working_dir = Some(dir.into());
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

    #[test]
    fn test_abstract_target() {
        let mut target = AbstractTarget::new(1, "gdb", "GDB Session");
        assert_eq!(target.key, 1);
        assert_eq!(target.target_type, "gdb");
        assert_eq!(target.state, TargetExecutionState::NotStarted);
        assert!(target.is_alive());
        assert!(!target.is_running());
        assert!(!target.is_paused());
    }

    #[test]
    fn test_abstract_target_state_transitions() {
        let mut target = AbstractTarget::new(1, "gdb", "GDB Session");
        target.set_state(TargetExecutionState::Running);
        assert!(target.is_running());
        assert!(target.is_alive());

        target.set_state(TargetExecutionState::Paused);
        assert!(target.is_paused());
        assert!(target.is_alive());

        target.set_state(TargetExecutionState::Terminated);
        assert!(!target.is_alive());
    }

    #[test]
    fn test_abstract_target_threads() {
        let mut target = AbstractTarget::new(1, "gdb", "GDB");
        target.add_thread(100);
        target.add_thread(200);
        assert_eq!(target.threads.len(), 2);
        assert_eq!(target.current_thread, Some(100));

        target.set_current_thread(Some(200));
        assert_eq!(target.current_thread, Some(200));

        target.remove_thread(200);
        assert_eq!(target.threads.len(), 1);
        assert_eq!(target.current_thread, Some(100));

        target.remove_thread(100);
        assert!(target.current_thread.is_none());
    }

    #[test]
    fn test_abstract_target_env() {
        let mut target = AbstractTarget::new(1, "gdb", "GDB");
        target.set_env("PATH", "/usr/bin");
        target.set_args(vec!["--args".into(), "prog".into()]);
        target.set_working_dir("/home/user");
        assert_eq!(target.env.get("PATH"), Some(&"/usr/bin".to_string()));
        assert_eq!(target.args.len(), 2);
        assert_eq!(target.working_dir, Some("/home/user".to_string()));
    }
}
