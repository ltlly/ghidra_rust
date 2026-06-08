//! x64dbg agent event hooks.
//!
//! Implements the x64dbg event hooks that automatically synchronize
//! state changes into the Ghidra trace. These correspond to the
//! `hooks.py` functions in the original Python agent.
//!
//! x64dbg events include:
//! - State changes (running, stopped, breakpoint hit)
//! - Thread events
//! - Module events
//! - Memory events

use serde::{Deserialize, Serialize};

/// x64dbg event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum X64DbgEvent {
    /// Execution state changed.
    StateChanged,
    /// Breakpoint hit.
    BreakpointHit,
    /// Exception occurred.
    Exception,
    /// Module loaded.
    ModuleLoaded,
    /// Module unloaded.
    ModuleUnloaded,
    /// Thread created.
    ThreadCreated,
    /// Thread exited.
    ThreadExited,
    /// Memory page changed.
    MemoryChanged,
    /// Debuggee loaded (process start).
    ProcessCreated,
    /// Debuggee exited.
    ProcessExited,
}

impl X64DbgEvent {
    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::StateChanged => "StateChanged",
            Self::BreakpointHit => "BreakpointHit",
            Self::Exception => "Exception",
            Self::ModuleLoaded => "ModuleLoaded",
            Self::ModuleUnloaded => "ModuleUnloaded",
            Self::ThreadCreated => "ThreadCreated",
            Self::ThreadExited => "ThreadExited",
            Self::MemoryChanged => "MemoryChanged",
            Self::ProcessCreated => "ProcessCreated",
            Self::ProcessExited => "ProcessExited",
        }
    }

    /// Transaction name.
    pub fn transaction_name(&self) -> &'static str {
        match self {
            Self::StateChanged => "State Changed",
            Self::BreakpointHit => "Breakpoint Hit",
            Self::Exception => "Exception",
            Self::ModuleLoaded => "Module Loaded",
            Self::ModuleUnloaded => "Module Unloaded",
            Self::ThreadCreated => "Thread Created",
            Self::ThreadExited => "Thread Exited",
            Self::MemoryChanged => "Memory Changed",
            Self::ProcessCreated => "Process Created",
            Self::ProcessExited => "Process Exited",
        }
    }

    /// Required trace updates.
    pub fn required_updates(&self) -> Vec<&'static str> {
        match self {
            Self::StateChanged => vec!["processes", "threads"],
            Self::BreakpointHit | Self::Exception => vec!["frames", "registers"],
            Self::ModuleLoaded | Self::ModuleUnloaded => vec!["modules"],
            Self::ThreadCreated | Self::ThreadExited => vec!["threads"],
            Self::MemoryChanged => vec!["memory"],
            Self::ProcessCreated | Self::ProcessExited => vec!["processes"],
        }
    }
}

/// Result of processing an x64dbg hook event.
#[derive(Debug, Clone)]
pub struct X64DbgHookResult {
    /// The event.
    pub event: X64DbgEvent,
    /// Transaction name.
    pub tx_name: String,
    /// Operations performed.
    pub operations: Vec<String>,
    /// Whether successful.
    pub success: bool,
    /// Error message if failed.
    pub error: Option<String>,
}

impl X64DbgHookResult {
    /// Create a successful result.
    pub fn success(event: X64DbgEvent, operations: Vec<String>) -> Self {
        Self {
            tx_name: event.transaction_name().to_string(),
            event,
            operations,
            success: true,
            error: None,
        }
    }

    /// Create a failed result.
    pub fn failed(event: X64DbgEvent, error: impl Into<String>) -> Self {
        Self {
            tx_name: event.transaction_name().to_string(),
            event,
            operations: Vec::new(),
            success: false,
            error: Some(error.into()),
        }
    }
}

/// Configuration for x64dbg hook behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X64DbgHookConfig {
    /// Whether hooks are enabled.
    pub enabled: bool,
    /// Sync on state changes.
    pub sync_state_changes: bool,
    /// Sync on breakpoint hits.
    pub sync_breakpoint_hits: bool,
    /// Sync module events.
    pub sync_modules: bool,
    /// Sync thread events.
    pub sync_threads: bool,
    /// Sync memory changes.
    pub sync_memory: bool,
    /// Sync process events.
    pub sync_processes: bool,
}

impl Default for X64DbgHookConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sync_state_changes: true,
            sync_breakpoint_hits: true,
            sync_modules: true,
            sync_threads: true,
            sync_memory: true,
            sync_processes: true,
        }
    }
}

impl X64DbgHookConfig {
    /// Check if an event should be processed.
    pub fn should_process(&self, event: X64DbgEvent) -> bool {
        if !self.enabled {
            return false;
        }
        match event {
            X64DbgEvent::StateChanged => self.sync_state_changes,
            X64DbgEvent::BreakpointHit | X64DbgEvent::Exception => self.sync_breakpoint_hits,
            X64DbgEvent::ModuleLoaded | X64DbgEvent::ModuleUnloaded => self.sync_modules,
            X64DbgEvent::ThreadCreated | X64DbgEvent::ThreadExited => self.sync_threads,
            X64DbgEvent::MemoryChanged => self.sync_memory,
            X64DbgEvent::ProcessCreated | X64DbgEvent::ProcessExited => self.sync_processes,
        }
    }
}

/// x64dbg hook manager.
pub struct X64DbgHookManager {
    config: X64DbgHookConfig,
    installed: bool,
}

impl X64DbgHookManager {
    /// Create a new hook manager.
    pub fn new(config: X64DbgHookConfig) -> Self {
        Self {
            config,
            installed: false,
        }
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(X64DbgHookConfig::default())
    }

    /// Check if hooks are installed.
    pub fn is_installed(&self) -> bool {
        self.installed
    }

    /// Install hooks.
    pub fn install(&mut self) {
        self.installed = true;
    }

    /// Remove hooks.
    pub fn remove(&mut self) {
        self.installed = false;
    }

    /// Get the hook configuration.
    pub fn config(&self) -> &X64DbgHookConfig {
        &self.config
    }

    /// Handle an event.
    pub fn handle_event(&self, event: X64DbgEvent) -> Option<Vec<&'static str>> {
        if self.config.should_process(event) {
            Some(event.required_updates())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_names() {
        assert_eq!(X64DbgEvent::StateChanged.name(), "StateChanged");
        assert_eq!(X64DbgEvent::ModuleLoaded.transaction_name(), "Module Loaded");
    }

    #[test]
    fn test_event_updates() {
        let updates = X64DbgEvent::BreakpointHit.required_updates();
        assert!(updates.contains(&"registers"));
        assert!(updates.contains(&"frames"));
    }

    #[test]
    fn test_hook_config_default() {
        let cfg = X64DbgHookConfig::default();
        assert!(cfg.enabled);
        assert!(cfg.should_process(X64DbgEvent::StateChanged));
    }

    #[test]
    fn test_hook_config_disabled() {
        let mut cfg = X64DbgHookConfig::default();
        cfg.enabled = false;
        assert!(!cfg.should_process(X64DbgEvent::StateChanged));
    }

    #[test]
    fn test_hook_manager() {
        let mut mgr = X64DbgHookManager::with_defaults();
        assert!(!mgr.is_installed());
        mgr.install();
        assert!(mgr.is_installed());
        mgr.remove();
        assert!(!mgr.is_installed());
    }

    #[test]
    fn test_handle_event() {
        let mgr = X64DbgHookManager::with_defaults();
        let result = mgr.handle_event(X64DbgEvent::StateChanged);
        assert!(result.is_some());
    }

    #[test]
    fn test_handle_event_disabled() {
        let mut mgr = X64DbgHookManager::with_defaults();
        mgr.config.sync_state_changes = false;
        let result = mgr.handle_event(X64DbgEvent::StateChanged);
        assert!(result.is_none());
    }
}
