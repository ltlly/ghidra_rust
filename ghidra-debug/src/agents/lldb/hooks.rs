//! LLDB agent event hooks.
//!
//! Implements the LLDB event hooks that automatically synchronize
//! state changes into the Ghidra trace. LLDB provides callback
//! mechanisms through its Python API for process, thread, and
//! breakpoint events.

use serde::{Deserialize, Serialize};

/// LLDB event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LldbEvent {
    /// Process state changed.
    ProcessStateChanged,
    /// Thread created.
    ThreadCreated,
    /// Thread exited.
    ThreadExited,
    /// Breakpoint hit.
    BreakpointHit,
    /// Watchpoint hit.
    WatchpointHit,
    /// Module loaded.
    ModuleLoaded,
    /// Module unloaded.
    ModuleUnloaded,
    /// Signal received.
    SignalReceived,
}

impl LldbEvent {
    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::ProcessStateChanged => "ProcessStateChanged",
            Self::ThreadCreated => "ThreadCreated",
            Self::ThreadExited => "ThreadExited",
            Self::BreakpointHit => "BreakpointHit",
            Self::WatchpointHit => "WatchpointHit",
            Self::ModuleLoaded => "ModuleLoaded",
            Self::ModuleUnloaded => "ModuleUnloaded",
            Self::SignalReceived => "SignalReceived",
        }
    }

    /// Transaction name for this event.
    pub fn transaction_name(&self) -> &'static str {
        match self {
            Self::ProcessStateChanged => "State Changed",
            Self::ThreadCreated => "Thread Created",
            Self::ThreadExited => "Thread Exited",
            Self::BreakpointHit => "Breakpoint Hit",
            Self::WatchpointHit => "Watchpoint Hit",
            Self::ModuleLoaded => "Module Loaded",
            Self::ModuleUnloaded => "Module Unloaded",
            Self::SignalReceived => "Signal Received",
        }
    }

    /// Required trace updates.
    pub fn required_updates(&self) -> Vec<&'static str> {
        match self {
            Self::ProcessStateChanged => vec!["processes", "threads", "frames", "registers"],
            Self::ThreadCreated | Self::ThreadExited => vec!["threads"],
            Self::BreakpointHit | Self::WatchpointHit => vec!["frames", "registers"],
            Self::ModuleLoaded | Self::ModuleUnloaded => vec!["modules"],
            Self::SignalReceived => vec!["processes", "threads"],
        }
    }
}

/// Result of processing an LLDB hook event.
#[derive(Debug, Clone)]
pub struct LldbHookResult {
    /// The event.
    pub event: LldbEvent,
    /// Transaction name.
    pub tx_name: String,
    /// Operations performed.
    pub operations: Vec<String>,
    /// Whether successful.
    pub success: bool,
    /// Error message if failed.
    pub error: Option<String>,
}

impl LldbHookResult {
    /// Create a successful result.
    pub fn success(event: LldbEvent, operations: Vec<String>) -> Self {
        Self {
            tx_name: event.transaction_name().to_string(),
            event,
            operations,
            success: true,
            error: None,
        }
    }

    /// Create a failed result.
    pub fn failed(event: LldbEvent, error: impl Into<String>) -> Self {
        Self {
            tx_name: event.transaction_name().to_string(),
            event,
            operations: Vec::new(),
            success: false,
            error: Some(error.into()),
        }
    }
}

/// Configuration for LLDB hook behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LldbHookConfig {
    /// Whether hooks are enabled.
    pub enabled: bool,
    /// Sync on process state changes.
    pub sync_process_state: bool,
    /// Sync on thread events.
    pub sync_threads: bool,
    /// Sync on breakpoint events.
    pub sync_breakpoints: bool,
    /// Sync on module events.
    pub sync_modules: bool,
    /// Sync on signals.
    pub sync_signals: bool,
}

impl Default for LldbHookConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sync_process_state: true,
            sync_threads: true,
            sync_breakpoints: true,
            sync_modules: true,
            sync_signals: true,
        }
    }
}

impl LldbHookConfig {
    /// Check if an event should be processed.
    pub fn should_process(&self, event: LldbEvent) -> bool {
        if !self.enabled {
            return false;
        }
        match event {
            LldbEvent::ProcessStateChanged => self.sync_process_state,
            LldbEvent::ThreadCreated | LldbEvent::ThreadExited => self.sync_threads,
            LldbEvent::BreakpointHit | LldbEvent::WatchpointHit => self.sync_breakpoints,
            LldbEvent::ModuleLoaded | LldbEvent::ModuleUnloaded => self.sync_modules,
            LldbEvent::SignalReceived => self.sync_signals,
        }
    }
}

/// LLDB hook manager.
pub struct LldbHookManager {
    config: LldbHookConfig,
    installed: bool,
}

impl LldbHookManager {
    /// Create a new hook manager.
    pub fn new(config: LldbHookConfig) -> Self {
        Self {
            config,
            installed: false,
        }
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(LldbHookConfig::default())
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
    pub fn handle_event(&self, event: LldbEvent) -> Option<Vec<&'static str>> {
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
        assert_eq!(LldbEvent::ProcessStateChanged.name(), "ProcessStateChanged");
        assert_eq!(LldbEvent::BreakpointHit.transaction_name(), "Breakpoint Hit");
    }

    #[test]
    fn test_event_updates() {
        let updates = LldbEvent::ProcessStateChanged.required_updates();
        assert!(updates.contains(&"registers"));
        assert!(updates.contains(&"frames"));
    }

    #[test]
    fn test_hook_config_default() {
        let cfg = LldbHookConfig::default();
        assert!(cfg.should_process(LldbEvent::ProcessStateChanged));
    }

    #[test]
    fn test_hook_manager() {
        let mut mgr = LldbHookManager::with_defaults();
        assert!(!mgr.is_installed());
        mgr.install();
        assert!(mgr.is_installed());
    }

    #[test]
    fn test_handle_event() {
        let mgr = LldbHookManager::with_defaults();
        let result = mgr.handle_event(LldbEvent::BreakpointHit);
        assert!(result.is_some());
        assert!(result.unwrap().contains(&"registers"));
    }
}
