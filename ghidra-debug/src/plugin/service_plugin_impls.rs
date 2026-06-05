//! Service plugin implementations.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.service.*` packages.
//! Provides concrete implementations for the debugger service plugins:
//! - `DebuggerBreakpointServicePlugin`: Breakpoint service implementation.
//! - `DebuggerControlServicePlugin`: Control service implementation.
//! - `DebuggerEmulationServicePlugin`: Emulation service implementation.
//! - `DebuggerPlatformServicePlugin`: Platform service implementation.
//! - `DebuggerTargetServicePlugin`: Target service implementation.
//! - `DebuggerTraceManagerServicePlugin`: Trace manager service implementation.
//! - `DebuggerStaticMappingServicePlugin`: Static mapping service implementation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Plugin phase for the debugger service plugin lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServicePluginPhase {
    /// Plugin is being initialized.
    Init,
    /// Plugin is ready to serve.
    Ready,
    /// Plugin is disposing.
    Disposing,
    /// Plugin has been disposed.
    Disposed,
}

impl Default for ServicePluginPhase {
    fn default() -> Self {
        Self::Init
    }
}

/// Configuration for a debugger service plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServicePluginConfig {
    /// The plugin name.
    pub name: String,
    /// The default provider class name.
    pub default_provider: String,
    /// Whether the plugin is enabled.
    pub enabled: bool,
    /// Plugin-specific options.
    pub options: HashMap<String, String>,
}

impl ServicePluginConfig {
    /// Create a new service plugin config.
    pub fn new(name: impl Into<String>, provider: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            default_provider: provider.into(),
            enabled: true,
            options: HashMap::new(),
        }
    }

    /// Set an option.
    pub fn set_option(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.options.insert(key.into(), value.into());
    }

    /// Get an option.
    pub fn get_option(&self, key: &str) -> Option<&str> {
        self.options.get(key).map(|s| s.as_str())
    }
}

/// Breakpoint service plugin data.
///
/// Ported from `DebuggerLogicalBreakpointServicePlugin` internals.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BreakpointServicePluginData {
    /// The plugin phase.
    pub phase: ServicePluginPhase,
    /// Whether to auto-map breakpoints when a new trace is activated.
    pub auto_map: bool,
    /// Whether to place breakpoints in emulators.
    pub emulate_breakpoints: bool,
    /// The maximum number of breakpoint history entries.
    pub max_history: usize,
}

impl BreakpointServicePluginData {
    /// Create new breakpoint service plugin data.
    pub fn new() -> Self {
        Self {
            phase: ServicePluginPhase::Init,
            auto_map: true,
            emulate_breakpoints: true,
            max_history: 100,
        }
    }
}

/// Control service plugin data.
///
/// Ported from `DebuggerControlServicePlugin` internals.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ControlServicePluginData {
    /// The plugin phase.
    pub phase: ServicePluginPhase,
    /// The default control mode.
    pub default_mode: ControlServiceMode,
    /// Whether to follow the current thread.
    pub follow_thread: bool,
    /// Whether to follow the current frame.
    pub follow_frame: bool,
}

/// Control mode for the debugger service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlServiceMode {
    /// The user controls the target directly.
    UserControl,
    /// The tool controls the target (e.g., stepping in the UI).
    ToolControl,
    /// Read-only observation.
    Observe,
}

impl Default for ControlServiceMode {
    fn default() -> Self {
        Self::UserControl
    }
}

impl ControlServicePluginData {
    /// Create new control service plugin data.
    pub fn new() -> Self {
        Self {
            phase: ServicePluginPhase::Init,
            default_mode: ControlServiceMode::default(),
            follow_thread: true,
            follow_frame: true,
        }
    }
}

/// Emulation service plugin data.
///
/// Ported from `DebuggerEmulationServicePlugin` internals.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmulationServicePluginData {
    /// The plugin phase.
    pub phase: ServicePluginPhase,
    /// Whether to cache emulators.
    pub cache_emulators: bool,
    /// The maximum number of cached emulators.
    pub max_cached_emulators: usize,
    /// The emulation step limit (0 = unlimited).
    pub step_limit: u64,
}

impl EmulationServicePluginData {
    /// Create new emulation service plugin data.
    pub fn new() -> Self {
        Self {
            phase: ServicePluginPhase::Init,
            cache_emulators: true,
            max_cached_emulators: 5,
            step_limit: 0,
        }
    }
}

/// Platform service plugin data.
///
/// Ported from `DebuggerPlatformServicePlugin` internals.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlatformServicePluginData {
    /// The plugin phase.
    pub phase: ServicePluginPhase,
    /// Override language ID (if any).
    pub override_language: Option<String>,
    /// Override compiler spec ID (if any).
    pub override_compiler_spec: Option<String>,
}

impl PlatformServicePluginData {
    /// Create new platform service plugin data.
    pub fn new() -> Self {
        Self {
            phase: ServicePluginPhase::Init,
            override_language: None,
            override_compiler_spec: None,
        }
    }
}

/// Target service plugin data.
///
/// Ported from `DebuggerTargetServicePlugin` internals.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetServicePluginData {
    /// The plugin phase.
    pub phase: ServicePluginPhase,
    /// Known target types.
    pub target_types: Vec<String>,
    /// Default target type.
    pub default_target_type: Option<String>,
}

impl TargetServicePluginData {
    /// Create new target service plugin data.
    pub fn new() -> Self {
        Self {
            phase: ServicePluginPhase::Init,
            target_types: Vec::new(),
            default_target_type: None,
        }
    }

    /// Register a target type.
    pub fn register_target_type(&mut self, target_type: impl Into<String>) {
        let tt = target_type.into();
        if !self.target_types.contains(&tt) {
            self.target_types.push(tt);
        }
    }
}

/// Trace manager service plugin data.
///
/// Ported from `DebuggerTraceManagerServicePlugin` internals.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceManagerServicePluginData {
    /// The plugin phase.
    pub phase: ServicePluginPhase,
    /// The maximum number of recently closed traces to remember.
    pub max_recent_traces: usize,
    /// Whether to auto-activate new traces.
    pub auto_activate_new: bool,
}

impl TraceManagerServicePluginData {
    /// Create new trace manager service plugin data.
    pub fn new() -> Self {
        Self {
            phase: ServicePluginPhase::Init,
            max_recent_traces: 10,
            auto_activate_new: true,
        }
    }
}

/// Static mapping service plugin data.
///
/// Ported from `DebuggerStaticMappingServicePlugin` internals.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StaticMappingServicePluginData {
    /// The plugin phase.
    pub phase: ServicePluginPhase,
    /// Whether to auto-map on trace open.
    pub auto_map_on_open: bool,
    /// Whether to auto-map on module change.
    pub auto_map_on_module_change: bool,
    /// Whether to truncate existing mappings on conflict.
    pub truncate_on_conflict: bool,
}

impl StaticMappingServicePluginData {
    /// Create new static mapping service plugin data.
    pub fn new() -> Self {
        Self {
            phase: ServicePluginPhase::Init,
            auto_map_on_open: true,
            auto_map_on_module_change: true,
            truncate_on_conflict: false,
        }
    }
}

/// Container for all service plugin data.
///
/// Aggregates all service plugin data into a single manageable structure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DebuggerServicePluginDataContainer {
    /// Breakpoint service data.
    pub breakpoint: BreakpointServicePluginData,
    /// Control service data.
    pub control: ControlServicePluginData,
    /// Emulation service data.
    pub emulation: EmulationServicePluginData,
    /// Platform service data.
    pub platform: PlatformServicePluginData,
    /// Target service data.
    pub target: TargetServicePluginData,
    /// Trace manager service data.
    pub trace_manager: TraceManagerServicePluginData,
    /// Static mapping service data.
    pub static_mapping: StaticMappingServicePluginData,
}

impl DebuggerServicePluginDataContainer {
    /// Create a new container with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialize all service plugins.
    pub fn initialize_all(&mut self) {
        self.breakpoint.phase = ServicePluginPhase::Ready;
        self.control.phase = ServicePluginPhase::Ready;
        self.emulation.phase = ServicePluginPhase::Ready;
        self.platform.phase = ServicePluginPhase::Ready;
        self.target.phase = ServicePluginPhase::Ready;
        self.trace_manager.phase = ServicePluginPhase::Ready;
        self.static_mapping.phase = ServicePluginPhase::Ready;
    }

    /// Dispose all service plugins.
    pub fn dispose_all(&mut self) {
        self.breakpoint.phase = ServicePluginPhase::Disposed;
        self.control.phase = ServicePluginPhase::Disposed;
        self.emulation.phase = ServicePluginPhase::Disposed;
        self.platform.phase = ServicePluginPhase::Disposed;
        self.target.phase = ServicePluginPhase::Disposed;
        self.trace_manager.phase = ServicePluginPhase::Disposed;
        self.static_mapping.phase = ServicePluginPhase::Disposed;
    }

    /// Whether all plugins are ready.
    pub fn all_ready(&self) -> bool {
        [
            self.breakpoint.phase,
            self.control.phase,
            self.emulation.phase,
            self.platform.phase,
            self.target.phase,
            self.trace_manager.phase,
            self.static_mapping.phase,
        ]
        .iter()
        .all(|&p| p == ServicePluginPhase::Ready)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_plugin_config() {
        let mut config = ServicePluginConfig::new("TestPlugin", "com.test.Provider");
        assert_eq!(config.name, "TestPlugin");
        assert!(config.enabled);

        config.set_option("key1", "value1");
        assert_eq!(config.get_option("key1"), Some("value1"));
        assert_eq!(config.get_option("missing"), None);
    }

    #[test]
    fn test_service_plugin_phase() {
        assert_eq!(ServicePluginPhase::default(), ServicePluginPhase::Init);
        assert_ne!(ServicePluginPhase::Init, ServicePluginPhase::Ready);
    }

    #[test]
    fn test_breakpoint_service_plugin_data() {
        let data = BreakpointServicePluginData::new();
        assert!(data.auto_map);
        assert!(data.emulate_breakpoints);
        assert_eq!(data.max_history, 100);
    }

    #[test]
    fn test_control_service_plugin_data() {
        let data = ControlServicePluginData::new();
        assert!(data.follow_thread);
        assert!(data.follow_frame);
        assert_eq!(data.default_mode, ControlServiceMode::UserControl);
    }

    #[test]
    fn test_emulation_service_plugin_data() {
        let data = EmulationServicePluginData::new();
        assert!(data.cache_emulators);
        assert_eq!(data.max_cached_emulators, 5);
        assert_eq!(data.step_limit, 0);
    }

    #[test]
    fn test_target_service_plugin_data() {
        let mut data = TargetServicePluginData::new();
        assert!(data.target_types.is_empty());

        data.register_target_type("gdb");
        data.register_target_type("lldb");
        data.register_target_type("gdb"); // duplicate
        assert_eq!(data.target_types.len(), 2);
    }

    #[test]
    fn test_trace_manager_service_plugin_data() {
        let data = TraceManagerServicePluginData::new();
        assert!(data.auto_activate_new);
        assert_eq!(data.max_recent_traces, 10);
    }

    #[test]
    fn test_static_mapping_service_plugin_data() {
        let data = StaticMappingServicePluginData::new();
        assert!(data.auto_map_on_open);
        assert!(!data.truncate_on_conflict);
    }

    #[test]
    fn test_service_plugin_container() {
        let mut container = DebuggerServicePluginDataContainer::new();
        assert!(!container.all_ready());

        container.initialize_all();
        assert!(container.all_ready());

        container.dispose_all();
        assert!(!container.all_ready());
        assert_eq!(
            container.breakpoint.phase,
            ServicePluginPhase::Disposed
        );
    }

    #[test]
    fn test_platform_service_plugin_data() {
        let mut data = PlatformServicePluginData::new();
        assert!(data.override_language.is_none());

        data.override_language = Some("x86:LE:64:default".into());
        assert!(data.override_language.is_some());
    }
}
