//! drgn agent event hooks.
//!
//! Implements the drgn event hooks for trace synchronization.
//! drgn hooks are typically installed via the `drgn` Python API
//! to capture state changes.

use serde::{Deserialize, Serialize};

/// drgn event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DrgnEvent {
    /// Program state changed.
    ProgramStateChanged,
    /// Thread created or exited.
    ThreadChanged,
    /// Memory changed.
    MemoryChanged,
    /// Breakpoint hit.
    BreakpointHit,
    /// Module loaded or unloaded.
    ModuleChanged,
}

impl DrgnEvent {
    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::ProgramStateChanged => "ProgramStateChanged",
            Self::ThreadChanged => "ThreadChanged",
            Self::MemoryChanged => "MemoryChanged",
            Self::BreakpointHit => "BreakpointHit",
            Self::ModuleChanged => "ModuleChanged",
        }
    }

    /// Transaction name.
    pub fn transaction_name(&self) -> &'static str {
        match self {
            Self::ProgramStateChanged => "State Changed",
            Self::ThreadChanged => "Thread Changed",
            Self::MemoryChanged => "Memory Changed",
            Self::BreakpointHit => "Breakpoint Hit",
            Self::ModuleChanged => "Module Changed",
        }
    }

    /// Required trace updates.
    pub fn required_updates(&self) -> Vec<&'static str> {
        match self {
            Self::ProgramStateChanged => vec!["processes", "threads", "frames", "registers"],
            Self::ThreadChanged => vec!["threads"],
            Self::MemoryChanged => vec!["memory"],
            Self::BreakpointHit => vec!["frames", "registers"],
            Self::ModuleChanged => vec!["modules"],
        }
    }
}

/// Configuration for drgn hook behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrgnHookConfig {
    /// Whether hooks are enabled.
    pub enabled: bool,
    /// Sync on program state changes.
    pub sync_state: bool,
    /// Sync on thread changes.
    pub sync_threads: bool,
    /// Sync on memory changes.
    pub sync_memory: bool,
    /// Sync on module changes.
    pub sync_modules: bool,
}

impl Default for DrgnHookConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sync_state: true,
            sync_threads: true,
            sync_memory: true,
            sync_modules: true,
        }
    }
}

impl DrgnHookConfig {
    /// Check if an event should be processed.
    pub fn should_process(&self, event: DrgnEvent) -> bool {
        if !self.enabled {
            return false;
        }
        match event {
            DrgnEvent::ProgramStateChanged => self.sync_state,
            DrgnEvent::ThreadChanged => self.sync_threads,
            DrgnEvent::MemoryChanged => self.sync_memory,
            DrgnEvent::ModuleChanged => self.sync_modules,
            DrgnEvent::BreakpointHit => true,
        }
    }
}

/// drgn hook manager.
pub struct DrgnHookManager {
    config: DrgnHookConfig,
    installed: bool,
}

impl DrgnHookManager {
    /// Create a new hook manager.
    pub fn new(config: DrgnHookConfig) -> Self {
        Self {
            config,
            installed: false,
        }
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(DrgnHookConfig::default())
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

    /// Handle an event.
    pub fn handle_event(&self, event: DrgnEvent) -> Option<Vec<&'static str>> {
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
        assert_eq!(DrgnEvent::ProgramStateChanged.name(), "ProgramStateChanged");
        assert_eq!(DrgnEvent::ModuleChanged.transaction_name(), "Module Changed");
    }

    #[test]
    fn test_hook_config_default() {
        let cfg = DrgnHookConfig::default();
        assert!(cfg.should_process(DrgnEvent::ProgramStateChanged));
    }

    #[test]
    fn test_hook_manager() {
        let mut mgr = DrgnHookManager::with_defaults();
        assert!(!mgr.is_installed());
        mgr.install();
        assert!(mgr.is_installed());
    }

    #[test]
    fn test_handle_event() {
        let mgr = DrgnHookManager::with_defaults();
        let result = mgr.handle_event(DrgnEvent::ModuleChanged);
        assert!(result.is_some());
        assert!(result.unwrap().contains(&"modules"));
    }
}
