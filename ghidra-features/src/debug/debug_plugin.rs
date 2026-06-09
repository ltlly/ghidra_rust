//! Debug Plugin -- Ghidra Features Debug Plugin Infrastructure.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug` Java package and
//! `ghidra.app.plugin.debug` (Features/Base).
//!
//! Provides:
//! - [`DebugPluginPackage`]: The debug plugin package definition.
//! - [`DebugPluginConfig`]: Configuration for debug plugins.
//! - [`DebugPluginEvent`]: Events emitted by debug plugins.
//! - [`DebugPluginState`]: Lifecycle state for debug plugins.
//! - [`DebugPluginRegistry`]: Registry of debug plugins.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

// ---------------------------------------------------------------------------
// Debug Plugin Package
// ---------------------------------------------------------------------------

/// The debug plugin package definition.
///
/// Ported from Ghidra's `DebuggerPluginPackage.java` in
/// `ghidra.app.plugin.core.debug`.
///
/// Groups all debugger plugins under a single named package for
/// UI registration and lifecycle management.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugPluginPackage {
    /// The package name.
    pub name: String,
    /// The set of plugin class names in this package.
    pub plugins: BTreeSet<String>,
    /// The description of the package.
    pub description: String,
    /// The priority (lower = loaded earlier).
    pub priority: u32,
    /// The icon resource path.
    pub icon_path: Option<String>,
}

impl DebugPluginPackage {
    /// Create a new debug plugin package.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            plugins: BTreeSet::new(),
            description: String::new(),
            priority: 100,
            icon_path: None,
        }
    }

    /// Add a plugin to this package.
    pub fn add_plugin(&mut self, class_name: impl Into<String>) {
        self.plugins.insert(class_name.into());
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Set the priority.
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    /// Set the icon path.
    pub fn with_icon(mut self, icon_path: impl Into<String>) -> Self {
        self.icon_path = Some(icon_path.into());
        self
    }

    /// Whether this package contains the given plugin.
    pub fn contains(&self, class_name: &str) -> bool {
        self.plugins.contains(class_name)
    }

    /// The main debugger plugin package.
    pub fn debugger() -> Self {
        Self::new("Debugger")
            .with_description("Plugins for debugging and tracing")
            .with_priority(10)
            .with_icon("icon.debugger.package")
    }
}

// ---------------------------------------------------------------------------
// Debug Plugin State
// ---------------------------------------------------------------------------

/// The lifecycle state of a debug plugin.
///
/// Ported from Ghidra's `AbstractDebuggerPlugin` lifecycle phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DebugPluginState {
    /// Plugin is being created.
    Creating,
    /// Plugin is being initialized.
    Initializing,
    /// Plugin is active and ready.
    Active,
    /// Plugin is being disposed.
    Disposing,
    /// Plugin has been disposed.
    Disposed,
}

impl Default for DebugPluginState {
    fn default() -> Self {
        Self::Creating
    }
}

// ---------------------------------------------------------------------------
// Debug Plugin Event
// ---------------------------------------------------------------------------

/// Events emitted by debug plugins.
///
/// Ported from Ghidra's various `PluginEvent` subclasses in the debug package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DebugPluginEvent {
    /// A trace was activated.
    TraceActivated {
        /// The trace key.
        trace_key: String,
    },
    /// A trace was deactivated.
    TraceDeactivated {
        /// The trace key.
        trace_key: String,
    },
    /// A trace was opened.
    TraceOpened {
        /// The trace key.
        trace_key: String,
    },
    /// A trace was closed.
    TraceClosed {
        /// The trace key.
        trace_key: String,
    },
    /// The current coordinates changed.
    CoordinatesChanged {
        /// The trace key.
        trace_key: String,
        /// The snap.
        snap: i64,
    },
    /// A breakpoint was added.
    BreakpointAdded {
        /// The breakpoint address.
        address: u64,
    },
    /// A breakpoint was removed.
    BreakpointRemoved {
        /// The breakpoint address.
        address: u64,
    },
    /// A breakpoint was toggled.
    BreakpointToggled {
        /// The breakpoint address.
        address: u64,
        /// Whether enabled.
        enabled: bool,
    },
    /// The target execution state changed.
    ExecutionStateChanged {
        /// The trace key.
        trace_key: String,
        /// The new state.
        state: String,
    },
    /// A memory region was mapped.
    MemoryMapped {
        /// The trace key.
        trace_key: String,
        /// The region name.
        region: String,
    },
}

// ---------------------------------------------------------------------------
// Debug Plugin Configuration
// ---------------------------------------------------------------------------

/// Configuration for a debug plugin.
///
/// Ported from Ghidra's `@PluginInfo` annotation data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugPluginConfig {
    /// The plugin class name.
    pub class_name: String,
    /// The plugin package name.
    pub package_name: String,
    /// The plugin category.
    pub category: String,
    /// Short description.
    pub short_description: String,
    /// Full description.
    pub description: String,
    /// Plugin status.
    pub status: DebugPluginStatus,
    /// Consumed event types.
    pub events_consumed: Vec<String>,
    /// Produced event types.
    pub events_produced: Vec<String>,
}

/// Plugin release status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DebugPluginStatus {
    /// Plugin is released and stable.
    Released,
    /// Plugin is in beta.
    Beta,
    /// Plugin is experimental.
    Experimental,
    /// Plugin is unstable.
    Unstable,
}

impl Default for DebugPluginStatus {
    fn default() -> Self {
        Self::Released
    }
}

impl DebugPluginConfig {
    /// Create a new debug plugin config.
    pub fn new(class_name: impl Into<String>) -> Self {
        Self {
            class_name: class_name.into(),
            package_name: "Debugger".into(),
            category: "Debugger".into(),
            short_description: String::new(),
            description: String::new(),
            status: DebugPluginStatus::Released,
            events_consumed: Vec::new(),
            events_produced: Vec::new(),
        }
    }

    /// Set the package name.
    pub fn with_package(mut self, package: impl Into<String>) -> Self {
        self.package_name = package.into();
        self
    }

    /// Set the category.
    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.category = category.into();
        self
    }

    /// Set the short description.
    pub fn with_short_description(mut self, desc: impl Into<String>) -> Self {
        self.short_description = desc.into();
        self
    }

    /// Set the full description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Set the status.
    pub fn with_status(mut self, status: DebugPluginStatus) -> Self {
        self.status = status;
        self
    }

    /// Add a consumed event type.
    pub fn consume_event(mut self, event: impl Into<String>) -> Self {
        self.events_consumed.push(event.into());
        self
    }

    /// Add a produced event type.
    pub fn produce_event(mut self, event: impl Into<String>) -> Self {
        self.events_produced.push(event.into());
        self
    }
}

// ---------------------------------------------------------------------------
// Debug Plugin Registration
// ---------------------------------------------------------------------------

/// Registration entry for a debug plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugPluginRegistration {
    /// The plugin configuration.
    pub config: DebugPluginConfig,
    /// The current state.
    pub state: DebugPluginState,
    /// The plugin's service interfaces.
    pub services_provided: BTreeSet<String>,
    /// The plugin's consumed services.
    pub services_consumed: BTreeSet<String>,
}

impl DebugPluginRegistration {
    /// Create a new registration.
    pub fn new(config: DebugPluginConfig) -> Self {
        Self {
            config,
            state: DebugPluginState::Creating,
            services_provided: BTreeSet::new(),
            services_consumed: BTreeSet::new(),
        }
    }

    /// Register a service provided by this plugin.
    pub fn provide_service(&mut self, service_name: impl Into<String>) {
        self.services_provided.insert(service_name.into());
    }

    /// Register a service consumed by this plugin.
    pub fn consume_service(&mut self, service_name: impl Into<String>) {
        self.services_consumed.insert(service_name.into());
    }
}

// ---------------------------------------------------------------------------
// Debug Plugin Registry
// ---------------------------------------------------------------------------

/// Registry of all debug plugins.
///
/// Manages the lifecycle and service wiring for debug plugins.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DebugPluginRegistry {
    /// Registered plugins by class name.
    plugins: BTreeMap<String, DebugPluginRegistration>,
    /// Plugin event listeners.
    listeners: Vec<DebugPluginEventListener>,
    /// Next listener ID.
    next_listener_id: usize,
}

/// A listener for debug plugin events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugPluginEventListener {
    /// The listener ID.
    pub id: usize,
    /// The event types this listener is interested in.
    pub event_types: BTreeSet<String>,
}

impl DebugPluginRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a plugin.
    pub fn register_plugin(&mut self, registration: DebugPluginRegistration) {
        let class_name = registration.config.class_name.clone();
        self.plugins.insert(class_name, registration);
    }

    /// Unregister a plugin.
    pub fn unregister_plugin(&mut self, class_name: &str) -> Option<DebugPluginRegistration> {
        self.plugins.remove(class_name)
    }

    /// Get a plugin registration.
    pub fn get_plugin(&self, class_name: &str) -> Option<&DebugPluginRegistration> {
        self.plugins.get(class_name)
    }

    /// Get a mutable reference to a plugin registration.
    pub fn get_plugin_mut(&mut self, class_name: &str) -> Option<&mut DebugPluginRegistration> {
        self.plugins.get_mut(class_name)
    }

    /// Set a plugin's state.
    pub fn set_plugin_state(&mut self, class_name: &str, state: DebugPluginState) {
        if let Some(reg) = self.plugins.get_mut(class_name) {
            reg.state = state;
        }
    }

    /// Get all registered plugin class names.
    pub fn plugin_names(&self) -> Vec<&str> {
        self.plugins.keys().map(|s| s.as_str()).collect()
    }

    /// Get all plugins in a given package.
    pub fn plugins_in_package(&self, package_name: &str) -> Vec<&DebugPluginRegistration> {
        self.plugins
            .values()
            .filter(|r| r.config.package_name == package_name)
            .collect()
    }

    /// Add a listener for plugin events.
    pub fn add_listener(&mut self, event_types: BTreeSet<String>) -> usize {
        let id = self.next_listener_id;
        self.next_listener_id += 1;
        self.listeners.push(DebugPluginEventListener { id, event_types });
        id
    }

    /// Remove a listener.
    pub fn remove_listener(&mut self, listener_id: usize) {
        self.listeners.retain(|l| l.id != listener_id);
    }

    /// Emit a plugin event.
    pub fn emit_event(&self, event: &DebugPluginEvent) -> Vec<usize> {
        let event_type = match event {
            DebugPluginEvent::TraceActivated { .. } => "TraceActivated",
            DebugPluginEvent::TraceDeactivated { .. } => "TraceDeactivated",
            DebugPluginEvent::TraceOpened { .. } => "TraceOpened",
            DebugPluginEvent::TraceClosed { .. } => "TraceClosed",
            DebugPluginEvent::CoordinatesChanged { .. } => "CoordinatesChanged",
            DebugPluginEvent::BreakpointAdded { .. } => "BreakpointAdded",
            DebugPluginEvent::BreakpointRemoved { .. } => "BreakpointRemoved",
            DebugPluginEvent::BreakpointToggled { .. } => "BreakpointToggled",
            DebugPluginEvent::ExecutionStateChanged { .. } => "ExecutionStateChanged",
            DebugPluginEvent::MemoryMapped { .. } => "MemoryMapped",
        };

        self.listeners
            .iter()
            .filter(|l| l.event_types.contains(event_type))
            .map(|l| l.id)
            .collect()
    }

    /// Get the number of registered plugins.
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Standard Debug Plugin Configurations
// ---------------------------------------------------------------------------

/// Standard debug plugin configurations ported from Ghidra.
pub mod standard_plugins {
    use super::*;

    /// DbViewerPlugin -- database table browser.
    pub fn db_viewer() -> DebugPluginConfig {
        DebugPluginConfig::new("DbViewerPlugin")
            .with_package("Developer")
            .with_category("Diagnostic")
            .with_short_description("Show database tables")
            .with_description(
                "This plugin is a debug aid that allows the user to browse database tables.",
            )
            .consume_event("ProgramActivatedPluginEvent")
    }

    /// EventDisplayPlugin -- plugin event viewer.
    pub fn event_display() -> DebugPluginConfig {
        DebugPluginConfig::new("EventDisplayPlugin")
            .with_package("Developer")
            .with_category("Diagnostic")
            .with_short_description("Show plugin events")
            .with_description(
                "This plugin is a debug aid that prints plugin event information. \
                 It can also be used as a sample of how to handle plugin events \
                 and how to write a component provider.",
            )
    }

    /// DomainEventDisplayPlugin -- domain event viewer.
    pub fn domain_event_display() -> DebugPluginConfig {
        DebugPluginConfig::new("DomainEventDisplayPlugin")
            .with_package("Developer")
            .with_category("Diagnostic")
            .with_short_description("Show domain object events")
            .with_description(
                "Displays domain object change events for debugging purposes.",
            )
    }

    /// DomainFolderChangesDisplayPlugin -- folder change viewer.
    pub fn domain_folder_changes_display() -> DebugPluginConfig {
        DebugPluginConfig::new("DomainFolderChangesDisplayPlugin")
            .with_package("Developer")
            .with_category("Diagnostic")
            .with_short_description("Show domain folder changes")
            .with_description(
                "Displays domain folder change events for debugging purposes.",
            )
    }

    /// ComponentInfoPlugin -- component information viewer.
    pub fn component_info() -> DebugPluginConfig {
        DebugPluginConfig::new("ComponentInfoPlugin")
            .with_package("Developer")
            .with_category("Diagnostic")
            .with_short_description("Show component information")
            .with_description(
                "Displays information about plugin components for debugging purposes.",
            )
    }

    /// GenerateOldLanguagePlugin -- old language generator.
    pub fn generate_old_language() -> DebugPluginConfig {
        DebugPluginConfig::new("GenerateOldLanguagePlugin")
            .with_package("Developer")
            .with_category("Diagnostic")
            .with_short_description("Generate old language definitions")
            .with_description(
                "Generates old language definition files for debugging and migration.",
            )
    }

    /// PropertyManagerPlugin -- property map manager.
    pub fn property_manager() -> DebugPluginConfig {
        DebugPluginConfig::new("PropertyManagerPlugin")
            .with_package("Developer")
            .with_category("Diagnostic")
            .with_short_description("Manage property maps")
            .with_description(
                "Provides a UI for managing program property maps.",
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_plugin_package() {
        let pkg = DebugPluginPackage::debugger();
        assert_eq!(pkg.name, "Debugger");
        assert_eq!(pkg.priority, 10);
        assert!(pkg.description.contains("debugging"));
    }

    #[test]
    fn test_debug_plugin_package_custom() {
        let mut pkg = DebugPluginPackage::new("Custom")
            .with_description("Custom package")
            .with_priority(50);
        pkg.add_plugin("PluginA");
        pkg.add_plugin("PluginB");

        assert!(pkg.contains("PluginA"));
        assert!(pkg.contains("PluginB"));
        assert!(!pkg.contains("PluginC"));
        assert_eq!(pkg.priority, 50);
    }

    #[test]
    fn test_debug_plugin_state() {
        let state = DebugPluginState::default();
        assert_eq!(state, DebugPluginState::Creating);

        assert_ne!(DebugPluginState::Active, DebugPluginState::Disposed);
    }

    #[test]
    fn test_debug_plugin_event() {
        let event = DebugPluginEvent::TraceActivated {
            trace_key: "trace1".into(),
        };
        match event {
            DebugPluginEvent::TraceActivated { trace_key } => {
                assert_eq!(trace_key, "trace1");
            }
            _ => panic!("Wrong event variant"),
        }
    }

    #[test]
    fn test_debug_plugin_config() {
        let config = DebugPluginConfig::new("TestPlugin")
            .with_package("Debugger")
            .with_short_description("Test")
            .with_status(DebugPluginStatus::Beta)
            .consume_event("TraceActivated")
            .produce_event("TraceClosed");

        assert_eq!(config.class_name, "TestPlugin");
        assert_eq!(config.package_name, "Debugger");
        assert_eq!(config.status, DebugPluginStatus::Beta);
        assert_eq!(config.events_consumed.len(), 1);
        assert_eq!(config.events_produced.len(), 1);
    }

    #[test]
    fn test_debug_plugin_registration() {
        let config = DebugPluginConfig::new("TestPlugin");
        let mut reg = DebugPluginRegistration::new(config);
        reg.provide_service("DebuggerControlService");
        reg.consume_service("DebuggerTraceManagerService");

        assert!(reg.services_provided.contains("DebuggerControlService"));
        assert!(reg.services_consumed.contains("DebuggerTraceManagerService"));
    }

    #[test]
    fn test_debug_plugin_registry() {
        let mut registry = DebugPluginRegistry::new();
        assert!(registry.is_empty());

        let config = DebugPluginConfig::new("Plugin1");
        let reg = DebugPluginRegistration::new(config);
        registry.register_plugin(reg);

        assert_eq!(registry.len(), 1);
        assert!(registry.get_plugin("Plugin1").is_some());
        assert!(registry.get_plugin("Missing").is_none());
    }

    #[test]
    fn test_debug_plugin_registry_state() {
        let mut registry = DebugPluginRegistry::new();
        let config = DebugPluginConfig::new("Plugin1");
        let reg = DebugPluginRegistration::new(config);
        registry.register_plugin(reg);

        registry.set_plugin_state("Plugin1", DebugPluginState::Active);
        let reg = registry.get_plugin("Plugin1").unwrap();
        assert_eq!(reg.state, DebugPluginState::Active);
    }

    #[test]
    fn test_debug_plugin_registry_listeners() {
        let mut registry = DebugPluginRegistry::new();
        let mut event_types = BTreeSet::new();
        event_types.insert("TraceActivated".into());
        event_types.insert("TraceClosed".into());
        let listener_id = registry.add_listener(event_types);

        let event = DebugPluginEvent::TraceActivated {
            trace_key: "trace1".into(),
        };
        let listeners = registry.emit_event(&event);
        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0], listener_id);

        let other_event = DebugPluginEvent::BreakpointAdded { address: 0x1000 };
        let listeners = registry.emit_event(&other_event);
        assert!(listeners.is_empty());

        registry.remove_listener(listener_id);
        let listeners = registry.emit_event(&event);
        assert!(listeners.is_empty());
    }

    #[test]
    fn test_debug_plugin_registry_packages() {
        let mut registry = DebugPluginRegistry::new();

        let config1 = DebugPluginConfig::new("Plugin1").with_package("Debugger");
        registry.register_plugin(DebugPluginRegistration::new(config1));

        let config2 = DebugPluginConfig::new("Plugin2").with_package("Developer");
        registry.register_plugin(DebugPluginRegistration::new(config2));

        let config3 = DebugPluginConfig::new("Plugin3").with_package("Debugger");
        registry.register_plugin(DebugPluginRegistration::new(config3));

        let debugger_plugins = registry.plugins_in_package("Debugger");
        assert_eq!(debugger_plugins.len(), 2);

        let developer_plugins = registry.plugins_in_package("Developer");
        assert_eq!(developer_plugins.len(), 1);
    }

    #[test]
    fn test_standard_plugins() {
        let db_viewer = standard_plugins::db_viewer();
        assert_eq!(db_viewer.class_name, "DbViewerPlugin");
        assert_eq!(db_viewer.package_name, "Developer");
        assert_eq!(db_viewer.status, DebugPluginStatus::Released);

        let event_display = standard_plugins::event_display();
        assert_eq!(event_display.class_name, "EventDisplayPlugin");

        let prop_mgr = standard_plugins::property_manager();
        assert_eq!(prop_mgr.class_name, "PropertyManagerPlugin");
    }

    #[test]
    fn test_debug_plugin_package_serde() {
        let pkg = DebugPluginPackage::debugger();
        let json = serde_json::to_string(&pkg).unwrap();
        let back: DebugPluginPackage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "Debugger");
    }

    #[test]
    fn test_debug_plugin_event_serde() {
        let event = DebugPluginEvent::CoordinatesChanged {
            trace_key: "trace1".into(),
            snap: 42,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: DebugPluginEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }
}
