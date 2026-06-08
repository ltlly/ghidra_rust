//! GDB agent event hooks.
//!
//! Implements the GDB event hooks that automatically synchronize
//! state changes into the Ghidra trace. These correspond to the
//! `hooks.py` functions in the original Python agent.
//!
//! GDB events include:
//! - `on_stop` / `on_cont` / `on_exit`: Execution state changes
//! - `on_new_thread` / `on_thread_exited`: Thread lifecycle
//! - `on_memory_changed`: Memory writes
//! - `on_register_changed`: Register modifications
//! - `on_breakpoint_created` / `on_breakpoint_modified` / `on_breakpoint_deleted`
//! - `on_new_objfile` / `on_clear_objfiles` / `on_free_objfile`: Module changes
//! - `on_inferior_added` / `on_inferior_deleted`: Process lifecycle

use serde::{Deserialize, Serialize};

/// GDB event types that trigger trace synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GdbEvent {
    /// Execution stopped (breakpoint, signal, step completed).
    Stop,
    /// Execution continued.
    Continue,
    /// Process exited.
    Exited,
    /// New inferior (process) was created.
    InferiorAdded,
    /// Inferior was removed.
    InferiorDeleted,
    /// New thread was created.
    NewThread,
    /// Thread exited.
    ThreadExited,
    /// Memory was modified.
    MemoryChanged,
    /// Register value changed.
    RegisterChanged,
    /// Breakpoint was created.
    BreakpointCreated,
    /// Breakpoint was modified.
    BreakpointModified,
    /// Breakpoint was deleted.
    BreakpointDeleted,
    /// New object file (shared library) loaded.
    NewObjfile,
    /// Object files were cleared.
    ClearObjfiles,
    /// Object file was freed.
    FreeObjfile,
}

impl GdbEvent {
    /// Human-readable name for this event.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Stop => "Stop",
            Self::Continue => "Continue",
            Self::Exited => "Exited",
            Self::InferiorAdded => "InferiorAdded",
            Self::InferiorDeleted => "InferiorDeleted",
            Self::NewThread => "NewThread",
            Self::ThreadExited => "ThreadExited",
            Self::MemoryChanged => "MemoryChanged",
            Self::RegisterChanged => "RegisterChanged",
            Self::BreakpointCreated => "BreakpointCreated",
            Self::BreakpointModified => "BreakpointModified",
            Self::BreakpointDeleted => "BreakpointDeleted",
            Self::NewObjfile => "NewObjfile",
            Self::ClearObjfiles => "ClearObjfiles",
            Self::FreeObjfile => "FreeObjfile",
        }
    }

    /// The transaction name to use when processing this event.
    pub fn transaction_name(&self) -> &'static str {
        match self {
            Self::Stop => "Stopped",
            Self::Continue => "Continued",
            Self::Exited => "Exited",
            Self::InferiorAdded => "Inferior Added",
            Self::InferiorDeleted => "Inferior Deleted",
            Self::NewThread => "Thread Created",
            Self::ThreadExited => "Thread Exited",
            Self::MemoryChanged => "Memory Changed",
            Self::RegisterChanged => "Register Changed",
            Self::BreakpointCreated => "Breakpoint Created",
            Self::BreakpointModified => "Breakpoint Modified",
            Self::BreakpointDeleted => "Breakpoint Deleted",
            Self::NewObjfile => "Module Loaded",
            Self::ClearObjfiles => "Modules Cleared",
            Self::FreeObjfile => "Module Freed",
        }
    }

    /// Which trace commands should be executed for this event.
    pub fn required_updates(&self) -> Vec<&'static str> {
        match self {
            Self::Stop => vec!["processes", "threads", "frames", "registers"],
            Self::Continue => vec!["processes", "threads"],
            Self::Exited => vec!["processes", "snapshots"],
            Self::InferiorAdded => vec!["processes"],
            Self::InferiorDeleted => vec!["processes"],
            Self::NewThread => vec!["threads"],
            Self::ThreadExited => vec!["threads"],
            Self::MemoryChanged => vec!["memory"],
            Self::RegisterChanged => vec!["registers"],
            Self::BreakpointCreated | Self::BreakpointModified | Self::BreakpointDeleted => {
                vec!["breakpoints"]
            }
            Self::NewObjfile | Self::ClearObjfiles | Self::FreeObjfile => vec!["modules"],
        }
    }
}

/// Result of processing a hook event.
#[derive(Debug, Clone)]
pub struct HookResult {
    /// The event that was processed.
    pub event: GdbEvent,
    /// Transaction name.
    pub tx_name: String,
    /// Operations performed.
    pub operations: Vec<String>,
    /// Whether the event was handled successfully.
    pub success: bool,
    /// Error message if failed.
    pub error: Option<String>,
}

impl HookResult {
    /// Create a successful result.
    pub fn success(event: GdbEvent, operations: Vec<String>) -> Self {
        Self {
            tx_name: event.transaction_name().to_string(),
            event,
            operations,
            success: true,
            error: None,
        }
    }

    /// Create a failed result.
    pub fn failed(event: GdbEvent, error: impl Into<String>) -> Self {
        Self {
            tx_name: event.transaction_name().to_string(),
            event,
            operations: Vec::new(),
            success: false,
            error: Some(error.into()),
        }
    }
}

/// Configuration for GDB hook behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookConfig {
    /// Whether hooks are enabled.
    pub enabled: bool,
    /// Whether to synchronize on stop events.
    pub sync_on_stop: bool,
    /// Whether to synchronize on continue events.
    pub sync_on_continue: bool,
    /// Whether to synchronize memory changes.
    pub sync_memory_changes: bool,
    /// Whether to synchronize register changes.
    pub sync_register_changes: bool,
    /// Whether to auto-put modules when objfiles change.
    pub sync_objfile_changes: bool,
    /// Whether to auto-put breakpoints.
    pub sync_breakpoints: bool,
}

impl Default for HookConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sync_on_stop: true,
            sync_on_continue: true,
            sync_memory_changes: true,
            sync_register_changes: true,
            sync_objfile_changes: true,
            sync_breakpoints: true,
        }
    }
}

impl HookConfig {
    /// Check if an event should be processed given this config.
    pub fn should_process(&self, event: GdbEvent) -> bool {
        if !self.enabled {
            return false;
        }
        match event {
            GdbEvent::Stop => self.sync_on_stop,
            GdbEvent::Continue => self.sync_on_continue,
            GdbEvent::MemoryChanged => self.sync_memory_changes,
            GdbEvent::RegisterChanged => self.sync_register_changes,
            GdbEvent::NewObjfile | GdbEvent::ClearObjfiles | GdbEvent::FreeObjfile => {
                self.sync_objfile_changes
            }
            GdbEvent::BreakpointCreated
            | GdbEvent::BreakpointModified
            | GdbEvent::BreakpointDeleted => self.sync_breakpoints,
            _ => true,
        }
    }
}

/// GDB hook manager.
///
/// Manages the installation and removal of GDB event hooks.
pub struct GdbHookManager {
    config: HookConfig,
    installed: bool,
}

impl GdbHookManager {
    /// Create a new hook manager.
    pub fn new(config: HookConfig) -> Self {
        Self {
            config,
            installed: false,
        }
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(HookConfig::default())
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
    pub fn config(&self) -> &HookConfig {
        &self.config
    }

    /// Get a mutable reference to the hook configuration.
    pub fn config_mut(&mut self) -> &mut HookConfig {
        &mut self.config
    }

    /// Determine what to do when an event fires.
    pub fn handle_event(&self, event: GdbEvent) -> Option<Vec<&'static str>> {
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
    fn test_gdb_event_names() {
        assert_eq!(GdbEvent::Stop.name(), "Stop");
        assert_eq!(GdbEvent::NewObjfile.transaction_name(), "Module Loaded");
    }

    #[test]
    fn test_gdb_event_updates() {
        let updates = GdbEvent::Stop.required_updates();
        assert!(updates.contains(&"registers"));
        assert!(updates.contains(&"frames"));
    }

    #[test]
    fn test_hook_config_default() {
        let cfg = HookConfig::default();
        assert!(cfg.enabled);
        assert!(cfg.should_process(GdbEvent::Stop));
        assert!(cfg.should_process(GdbEvent::MemoryChanged));
    }

    #[test]
    fn test_hook_config_disabled() {
        let mut cfg = HookConfig::default();
        cfg.enabled = false;
        assert!(!cfg.should_process(GdbEvent::Stop));
    }

    #[test]
    fn test_hook_config_selective() {
        let mut cfg = HookConfig::default();
        cfg.sync_memory_changes = false;
        cfg.sync_register_changes = false;
        assert!(!cfg.should_process(GdbEvent::MemoryChanged));
        assert!(!cfg.should_process(GdbEvent::RegisterChanged));
        assert!(cfg.should_process(GdbEvent::Stop));
    }

    #[test]
    fn test_hook_manager() {
        let mut mgr = GdbHookManager::with_defaults();
        assert!(!mgr.is_installed());
        mgr.install();
        assert!(mgr.is_installed());
        mgr.remove();
        assert!(!mgr.is_installed());
    }

    #[test]
    fn test_handle_event() {
        let mgr = GdbHookManager::with_defaults();
        let result = mgr.handle_event(GdbEvent::Stop);
        assert!(result.is_some());
        assert!(result.unwrap().contains(&"registers"));
    }

    #[test]
    fn test_handle_event_disabled() {
        let mut mgr = GdbHookManager::with_defaults();
        mgr.config_mut().sync_on_stop = false;
        let result = mgr.handle_event(GdbEvent::Stop);
        assert!(result.is_none());
    }
}
