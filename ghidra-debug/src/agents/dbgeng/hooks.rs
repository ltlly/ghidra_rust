//! Dbgeng agent event hooks.
//!
//! Implements the dbgeng event hooks that automatically synchronize
//! state changes into the Ghidra trace. These correspond to the
//! `hooks.py` functions in the original Python agent.
//!
//! Dbgeng events include:
//! - State changes (running, stopped, exited)
//! - Breakpoint events
//! - Module load/unload
//! - Thread create/exit

use serde::{Deserialize, Serialize};

/// Dbgeng event types that trigger trace synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DbgEngEvent {
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
    /// Process created.
    ProcessCreated,
    /// Process exited.
    ProcessExited,
    /// Session status changed.
    SessionStatusChanged,
    /// Engine output available.
    EngineOutput,
}

impl DbgEngEvent {
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
            Self::ProcessCreated => "ProcessCreated",
            Self::ProcessExited => "ProcessExited",
            Self::SessionStatusChanged => "SessionStatusChanged",
            Self::EngineOutput => "EngineOutput",
        }
    }

    /// Transaction name for this event.
    pub fn transaction_name(&self) -> &'static str {
        match self {
            Self::StateChanged => "State Changed",
            Self::BreakpointHit => "Breakpoint Hit",
            Self::Exception => "Exception",
            Self::ModuleLoaded => "Module Loaded",
            Self::ModuleUnloaded => "Module Unloaded",
            Self::ThreadCreated => "Thread Created",
            Self::ThreadExited => "Thread Exited",
            Self::ProcessCreated => "Process Created",
            Self::ProcessExited => "Process Exited",
            Self::SessionStatusChanged => "Session Changed",
            Self::EngineOutput => "Engine Output",
        }
    }

    /// Required trace updates for this event.
    pub fn required_updates(&self) -> Vec<&'static str> {
        match self {
            Self::StateChanged => vec!["processes", "threads"],
            Self::BreakpointHit => vec!["frames", "registers"],
            Self::Exception => vec!["processes", "threads", "frames", "registers"],
            Self::ModuleLoaded | Self::ModuleUnloaded => vec!["modules"],
            Self::ThreadCreated | Self::ThreadExited => vec!["threads"],
            Self::ProcessCreated | Self::ProcessExited => vec!["processes"],
            Self::SessionStatusChanged => vec![],
            Self::EngineOutput => vec![],
        }
    }
}

/// Result of processing a dbgeng hook event.
#[derive(Debug, Clone)]
pub struct DbgEngHookResult {
    /// The event that was processed.
    pub event: DbgEngEvent,
    /// Transaction name.
    pub tx_name: String,
    /// Operations performed.
    pub operations: Vec<String>,
    /// Whether successful.
    pub success: bool,
    /// Error message if failed.
    pub error: Option<String>,
}

impl DbgEngHookResult {
    /// Create a successful result.
    pub fn success(event: DbgEngEvent, operations: Vec<String>) -> Self {
        Self {
            tx_name: event.transaction_name().to_string(),
            event,
            operations,
            success: true,
            error: None,
        }
    }

    /// Create a failed result.
    pub fn failed(event: DbgEngEvent, error: impl Into<String>) -> Self {
        Self {
            tx_name: event.transaction_name().to_string(),
            event,
            operations: Vec::new(),
            success: false,
            error: Some(error.into()),
        }
    }
}

/// Configuration for dbgeng hook behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbgEngHookConfig {
    /// Whether hooks are enabled.
    pub enabled: bool,
    /// Whether to sync on state changes.
    pub sync_state_changes: bool,
    /// Whether to sync on breakpoint hits.
    pub sync_breakpoint_hits: bool,
    /// Whether to sync module load/unload.
    pub sync_modules: bool,
    /// Whether to sync thread events.
    pub sync_threads: bool,
    /// Whether to sync process events.
    pub sync_processes: bool,
}

impl Default for DbgEngHookConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sync_state_changes: true,
            sync_breakpoint_hits: true,
            sync_modules: true,
            sync_threads: true,
            sync_processes: true,
        }
    }
}

impl DbgEngHookConfig {
    /// Check if an event should be processed.
    pub fn should_process(&self, event: DbgEngEvent) -> bool {
        if !self.enabled {
            return false;
        }
        match event {
            DbgEngEvent::StateChanged => self.sync_state_changes,
            DbgEngEvent::BreakpointHit | DbgEngEvent::Exception => self.sync_breakpoint_hits,
            DbgEngEvent::ModuleLoaded | DbgEngEvent::ModuleUnloaded => self.sync_modules,
            DbgEngEvent::ThreadCreated | DbgEngEvent::ThreadExited => self.sync_threads,
            DbgEngEvent::ProcessCreated | DbgEngEvent::ProcessExited => self.sync_processes,
            _ => true,
        }
    }
}

/// Dbgeng hook manager.
pub struct DbgEngHookManager {
    config: DbgEngHookConfig,
    installed: bool,
}

impl DbgEngHookManager {
    /// Create a new hook manager.
    pub fn new(config: DbgEngHookConfig) -> Self {
        Self {
            config,
            installed: false,
        }
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(DbgEngHookConfig::default())
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
    pub fn config(&self) -> &DbgEngHookConfig {
        &self.config
    }

    /// Determine what to do when an event fires.
    pub fn handle_event(&self, event: DbgEngEvent) -> Option<Vec<&'static str>> {
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
        assert_eq!(DbgEngEvent::StateChanged.name(), "StateChanged");
        assert_eq!(DbgEngEvent::ModuleLoaded.transaction_name(), "Module Loaded");
    }

    #[test]
    fn test_event_updates() {
        let updates = DbgEngEvent::BreakpointHit.required_updates();
        assert!(updates.contains(&"registers"));
        assert!(updates.contains(&"frames"));
    }

    #[test]
    fn test_hook_config_default() {
        let cfg = DbgEngHookConfig::default();
        assert!(cfg.enabled);
        assert!(cfg.should_process(DbgEngEvent::StateChanged));
    }

    #[test]
    fn test_hook_config_disabled() {
        let mut cfg = DbgEngHookConfig::default();
        cfg.enabled = false;
        assert!(!cfg.should_process(DbgEngEvent::StateChanged));
    }

    #[test]
    fn test_hook_manager() {
        let mut mgr = DbgEngHookManager::with_defaults();
        assert!(!mgr.is_installed());
        mgr.install();
        assert!(mgr.is_installed());
        mgr.remove();
        assert!(!mgr.is_installed());
    }

    #[test]
    fn test_handle_event() {
        let mgr = DbgEngHookManager::with_defaults();
        let result = mgr.handle_event(DbgEngEvent::StateChanged);
        assert!(result.is_some());
    }

    #[test]
    fn test_handle_event_disabled() {
        let mut mgr = DbgEngHookManager::with_defaults();
        mgr.config.sync_state_changes = false;
        let result = mgr.handle_event(DbgEngEvent::StateChanged);
        assert!(result.is_none());
    }
}
