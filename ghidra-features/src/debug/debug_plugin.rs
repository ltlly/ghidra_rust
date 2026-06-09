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
// Debug Plugin Priority
// ---------------------------------------------------------------------------

/// Loading priority for debug plugins.
///
/// Ported from Ghidra's plugin loading order in
/// `ghidra.app.plugin.core.debug`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DebugPluginPriority {
    /// Must be loaded before all others (e.g., trace manager).
    Highest,
    /// Loaded early (e.g., target service, control service).
    High,
    /// Normal loading priority.
    Normal,
    /// Loaded after most plugins (e.g., UI panels).
    Low,
    /// Loaded last (e.g., optional enhancements).
    Lowest,
}

impl Default for DebugPluginPriority {
    fn default() -> Self {
        Self::Normal
    }
}

impl DebugPluginPriority {
    /// Numeric value for ordering (lower = loaded earlier).
    pub fn as_u32(&self) -> u32 {
        match self {
            Self::Highest => 0,
            Self::High => 25,
            Self::Normal => 50,
            Self::Low => 75,
            Self::Lowest => 100,
        }
    }
}

// ---------------------------------------------------------------------------
// Debug Plugin Dependency
// ---------------------------------------------------------------------------

/// A dependency between two debug plugins.
///
/// Ported from Ghidra's `@PluginDependency` annotation data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugPluginDependency {
    /// The class name of the depended-upon plugin.
    pub plugin_class: String,
    /// Whether this dependency is required or optional.
    pub required: bool,
    /// Human-readable reason for the dependency.
    pub reason: String,
}

impl DebugPluginDependency {
    /// Create a required dependency.
    pub fn required(plugin_class: impl Into<String>) -> Self {
        Self {
            plugin_class: plugin_class.into(),
            required: true,
            reason: String::new(),
        }
    }

    /// Create an optional dependency.
    pub fn optional(plugin_class: impl Into<String>) -> Self {
        Self {
            plugin_class: plugin_class.into(),
            required: false,
            reason: String::new(),
        }
    }

    /// Add a reason for the dependency.
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }
}

// ---------------------------------------------------------------------------
// Debug Plugin Loader
// ---------------------------------------------------------------------------

/// The result of loading a single plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugPluginLoadResult {
    /// The plugin class name.
    pub class_name: String,
    /// Whether loading succeeded.
    pub success: bool,
    /// Error message if loading failed.
    pub error: Option<String>,
    /// Time taken to load in milliseconds.
    pub load_time_ms: u64,
}

/// Orchestrates the loading of debug plugins in dependency order.
///
/// Ported from Ghidra's `PluginManager` plugin loading lifecycle.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DebugPluginLoader {
    /// Plugins waiting to be loaded, by class name.
    pending: BTreeMap<String, DebugPluginRegistration>,
    /// Dependencies for each plugin.
    dependencies: BTreeMap<String, Vec<DebugPluginDependency>>,
    /// Load results.
    results: Vec<DebugPluginLoadResult>,
    /// Whether loading is in progress.
    loading: bool,
}

impl DebugPluginLoader {
    /// Create a new plugin loader.
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a plugin for loading with its dependencies.
    pub fn queue_plugin(
        &mut self,
        registration: DebugPluginRegistration,
        deps: Vec<DebugPluginDependency>,
    ) {
        let class_name = registration.config.class_name.clone();
        self.dependencies.insert(class_name.clone(), deps);
        self.pending.insert(class_name, registration);
    }

    /// Get the plugins in dependency-sorted order.
    ///
    /// Plugins with no unmet dependencies come first.
    pub fn loading_order(&self) -> Vec<String> {
        let mut resolved: BTreeSet<String> = BTreeSet::new();
        let mut order = Vec::new();
        let mut remaining: BTreeMap<String, Vec<String>> = self
            .dependencies
            .iter()
            .map(|(k, deps)| {
                (
                    k.clone(),
                    deps.iter()
                        .filter(|d| d.required && self.pending.contains_key(&d.plugin_class))
                        .map(|d| d.plugin_class.clone())
                        .collect(),
                )
            })
            .collect();

        // Topological sort with iterative resolution.
        loop {
            let before = resolved.len();
            for (class, deps) in remaining.iter_mut() {
                if resolved.contains(class) {
                    continue;
                }
                if deps.iter().all(|d| resolved.contains(d.as_str())) {
                    resolved.insert(class.clone());
                    order.push(class.clone());
                }
            }
            if resolved.len() == before {
                break;
            }
        }

        // Append any remaining plugins with circular deps at the end.
        for class in self.pending.keys() {
            if !resolved.contains(class.as_str()) {
                order.push(class.clone());
            }
        }

        order
    }

    /// Mark a plugin load result.
    pub fn record_result(&mut self, result: DebugPluginLoadResult) {
        self.results.push(result);
    }

    /// Get all load results.
    pub fn results(&self) -> &[DebugPluginLoadResult] {
        &self.results
    }

    /// Check if all required dependencies for a plugin are satisfied.
    pub fn dependencies_satisfied(&self, class_name: &str) -> bool {
        if let Some(deps) = self.dependencies.get(class_name) {
            deps.iter().all(|d| !d.required || self.pending.contains_key(&d.plugin_class))
        } else {
            true
        }
    }

    /// Get the number of pending plugins.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Pop a plugin from the pending queue.
    pub fn pop_pending(&mut self, class_name: &str) -> Option<DebugPluginRegistration> {
        self.pending.remove(class_name)
    }

    /// Check if loading is in progress.
    pub fn is_loading(&self) -> bool {
        self.loading
    }

    /// Set the loading flag.
    pub fn set_loading(&mut self, loading: bool) {
        self.loading = loading;
    }
}

// ---------------------------------------------------------------------------
// Debug Plugin Action
// ---------------------------------------------------------------------------

/// An action registered by a debug plugin.
///
/// Ported from Ghidra's `DockingAction` / `AbstractDebuggerPlugin.registerAction`.
/// Debug plugins register named actions (menu items, toolbar buttons, key
/// bindings) that operate on the current debug context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugPluginAction {
    /// The action name (unique identifier).
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// The menu popup group this action belongs to.
    pub menu_group: Option<String>,
    /// Keyboard shortcut (e.g., "Ctrl+Shift+F5").
    pub key_binding: Option<String>,
    /// Toolbar icon resource path.
    pub icon_path: Option<String>,
    /// Whether this action is enabled.
    pub enabled: bool,
    /// Whether this action is currently visible.
    pub visible: bool,
    /// The action context type it operates on.
    pub context_type: Option<String>,
}

impl DebugPluginAction {
    /// Create a new debug plugin action.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            menu_group: None,
            key_binding: None,
            icon_path: None,
            enabled: true,
            visible: true,
            context_type: None,
        }
    }

    /// Set the menu group.
    pub fn with_menu_group(mut self, group: impl Into<String>) -> Self {
        self.menu_group = Some(group.into());
        self
    }

    /// Set the keyboard shortcut.
    pub fn with_key_binding(mut self, binding: impl Into<String>) -> Self {
        self.key_binding = Some(binding.into());
        self
    }

    /// Set the icon path.
    pub fn with_icon(mut self, path: impl Into<String>) -> Self {
        self.icon_path = Some(path.into());
        self
    }

    /// Set the context type.
    pub fn with_context_type(mut self, ctx: impl Into<String>) -> Self {
        self.context_type = Some(ctx.into());
        self
    }
}

/// Registry of actions for a debug plugin.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DebugPluginActionRegistry {
    /// Registered actions, keyed by name.
    actions: BTreeMap<String, DebugPluginAction>,
}

impl DebugPluginActionRegistry {
    /// Create a new empty action registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an action.
    pub fn register(&mut self, action: DebugPluginAction) {
        self.actions.insert(action.name.clone(), action);
    }

    /// Unregister an action by name.
    pub fn unregister(&mut self, name: &str) -> Option<DebugPluginAction> {
        self.actions.remove(name)
    }

    /// Get an action by name.
    pub fn get(&self, name: &str) -> Option<&DebugPluginAction> {
        self.actions.get(name)
    }

    /// Get a mutable reference to an action by name.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut DebugPluginAction> {
        self.actions.get_mut(name)
    }

    /// Set enabled state for an action.
    pub fn set_enabled(&mut self, name: &str, enabled: bool) {
        if let Some(action) = self.actions.get_mut(name) {
            action.enabled = enabled;
        }
    }

    /// Set visibility for an action.
    pub fn set_visible(&mut self, name: &str, visible: bool) {
        if let Some(action) = self.actions.get_mut(name) {
            action.visible = visible;
        }
    }

    /// Get all action names.
    pub fn action_names(&self) -> Vec<&str> {
        self.actions.keys().map(|s| s.as_str()).collect()
    }

    /// Get all enabled actions.
    pub fn enabled_actions(&self) -> Vec<&DebugPluginAction> {
        self.actions.values().filter(|a| a.enabled).collect()
    }

    /// Get the number of registered actions.
    pub fn len(&self) -> usize {
        self.actions.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Debug Plugin Session
// ---------------------------------------------------------------------------

/// Tracks a debug plugin's session state.
///
/// Ported from Ghidra's `AbstractDebuggerPlugin` session management.
/// Each session represents an active debugging connection with its
/// associated state, history, and lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugPluginSession {
    /// Unique session identifier.
    pub session_id: String,
    /// The trace key associated with this session.
    pub trace_key: String,
    /// The connector type (e.g., "gdb", "lldb", "dbgeng").
    pub connector_type: String,
    /// The target being debugged (process name, PID, core file path).
    pub target: String,
    /// Session state.
    pub state: DebugPluginSessionState,
    /// When the session was created (millis since epoch).
    pub created_at: i64,
    /// When the session was last active (millis since epoch).
    pub last_active_at: i64,
    /// User-supplied notes.
    pub notes: String,
    /// Session-specific configuration overrides.
    pub config_overrides: BTreeMap<String, String>,
}

/// The state of a debug plugin session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DebugPluginSessionState {
    /// The session is connecting.
    Connecting,
    /// The session is active.
    Active,
    /// The session is paused.
    Paused,
    /// The session has terminated.
    Terminated,
    /// The session encountered an error.
    Error,
}

impl Default for DebugPluginSessionState {
    fn default() -> Self {
        Self::Connecting
    }
}

impl DebugPluginSession {
    /// Create a new debug plugin session.
    pub fn new(
        session_id: impl Into<String>,
        trace_key: impl Into<String>,
        connector_type: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            trace_key: trace_key.into(),
            connector_type: connector_type.into(),
            target: target.into(),
            state: DebugPluginSessionState::Connecting,
            created_at: 0,
            last_active_at: 0,
            notes: String::new(),
            config_overrides: BTreeMap::new(),
        }
    }

    /// Set a config override.
    pub fn set_config_override(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.config_overrides.insert(key.into(), value.into());
    }

    /// Get a config override.
    pub fn get_config_override(&self, key: &str) -> Option<&str> {
        self.config_overrides.get(key).map(|s| s.as_str())
    }

    /// Check if the session is still active.
    pub fn is_active(&self) -> bool {
        self.state == DebugPluginSessionState::Active
            || self.state == DebugPluginSessionState::Paused
    }
}

// ---------------------------------------------------------------------------
// Debug Plugin Metrics
// ---------------------------------------------------------------------------

/// Performance and usage metrics for a debug plugin.
///
/// Ported from Ghidra's internal plugin diagnostics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DebugPluginMetrics {
    /// Number of events processed.
    pub events_processed: u64,
    /// Number of actions executed.
    pub actions_executed: u64,
    /// Total time spent processing events (microseconds).
    pub event_processing_time_us: u64,
    /// Total time spent on actions (microseconds).
    pub action_execution_time_us: u64,
    /// Number of errors encountered.
    pub error_count: u64,
    /// Number of traces managed.
    pub traces_managed: u64,
    /// Peak memory usage in bytes.
    pub peak_memory_bytes: u64,
    /// Number of service calls made.
    pub service_calls: u64,
}

impl DebugPluginMetrics {
    /// Create new zeroed metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an event processed.
    pub fn record_event(&mut self, processing_time_us: u64) {
        self.events_processed += 1;
        self.event_processing_time_us += processing_time_us;
    }

    /// Record an action executed.
    pub fn record_action(&mut self, execution_time_us: u64) {
        self.actions_executed += 1;
        self.action_execution_time_us += execution_time_us;
    }

    /// Record an error.
    pub fn record_error(&mut self) {
        self.error_count += 1;
    }

    /// Average event processing time in microseconds.
    pub fn avg_event_time_us(&self) -> u64 {
        if self.events_processed == 0 {
            0
        } else {
            self.event_processing_time_us / self.events_processed
        }
    }

    /// Average action execution time in microseconds.
    pub fn avg_action_time_us(&self) -> u64 {
        if self.actions_executed == 0 {
            0
        } else {
            self.action_execution_time_us / self.actions_executed
        }
    }

    /// Reset all metrics to zero.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// ---------------------------------------------------------------------------
// Debug Plugin Tool Adapter
// ---------------------------------------------------------------------------

/// Adapts a debug plugin to the host tool environment.
///
/// Ported from Ghidra's `AbstractDebuggerPlugin` tool integration.
/// Provides the bridge between the plugin and the docking framework,
/// managing providers, menus, and service registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugPluginToolAdapter {
    /// The tool name (e.g., "CodeBrowser", "Debugger").
    pub tool_name: String,
    /// Registered component provider names.
    pub providers: BTreeSet<String>,
    /// Registered service names.
    pub services_registered: BTreeSet<String>,
    /// Consumed service names.
    pub services_consumed: BTreeSet<String>,
    /// Menu path entries.
    pub menu_entries: Vec<MenuEntry>,
    /// Toolbar entries.
    pub toolbar_entries: Vec<ToolbarEntry>,
}

/// A menu entry registered by a debug plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MenuEntry {
    /// The menu path (e.g., "Debugger/Open Target").
    pub path: String,
    /// The action name this menu entry invokes.
    pub action_name: String,
    /// The menu group for ordering.
    pub group: String,
}

/// A toolbar entry registered by a debug plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolbarEntry {
    /// The toolbar group name.
    pub group: String,
    /// The action name this toolbar entry invokes.
    pub action_name: String,
    /// Icon resource path.
    pub icon_path: Option<String>,
    /// Tooltip text.
    pub tooltip: Option<String>,
}

impl DebugPluginToolAdapter {
    /// Create a new tool adapter.
    pub fn new(tool_name: impl Into<String>) -> Self {
        Self {
            tool_name: tool_name.into(),
            providers: BTreeSet::new(),
            services_registered: BTreeSet::new(),
            services_consumed: BTreeSet::new(),
            menu_entries: Vec::new(),
            toolbar_entries: Vec::new(),
        }
    }

    /// Register a component provider.
    pub fn add_provider(&mut self, name: impl Into<String>) {
        self.providers.insert(name.into());
    }

    /// Register a provided service.
    pub fn register_service(&mut self, service_name: impl Into<String>) {
        self.services_registered.insert(service_name.into());
    }

    /// Register a consumed service.
    pub fn consume_service(&mut self, service_name: impl Into<String>) {
        self.services_consumed.insert(service_name.into());
    }

    /// Add a menu entry.
    pub fn add_menu_entry(&mut self, entry: MenuEntry) {
        self.menu_entries.push(entry);
    }

    /// Add a toolbar entry.
    pub fn add_toolbar_entry(&mut self, entry: ToolbarEntry) {
        self.toolbar_entries.push(entry);
    }
}

// ---------------------------------------------------------------------------
// Debug Plugin UI State
// ---------------------------------------------------------------------------

/// The UI state of the debug plugin panels.
///
/// Ported from Ghidra's debugger panel/viewport state management.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugPluginUiState {
    /// The currently selected trace key.
    pub selected_trace: Option<String>,
    /// The currently selected thread key.
    pub selected_thread: Option<i64>,
    /// The currently selected frame level.
    pub selected_frame: Option<u32>,
    /// The snap the UI is viewing.
    pub view_snap: i64,
    /// Whether the listing is synchronized with the trace.
    pub listing_synced: bool,
    /// Whether the registers view is visible.
    pub registers_visible: bool,
    /// Whether the memory view is visible.
    pub memory_visible: bool,
    /// Whether the console view is visible.
    pub console_visible: bool,
    /// Whether the breakpoints view is visible.
    pub breakpoints_visible: bool,
    /// Whether the threads view is visible.
    pub threads_visible: bool,
    /// Whether the modules view is visible.
    pub modules_visible: bool,
    /// Whether the watches view is visible.
    pub watches_visible: bool,
    /// The memory view address.
    pub memory_address: Option<u64>,
    /// The listing view address.
    pub listing_address: Option<u64>,
}

impl Default for DebugPluginUiState {
    fn default() -> Self {
        Self {
            selected_trace: None,
            selected_thread: None,
            selected_frame: None,
            view_snap: 0,
            listing_synced: true,
            registers_visible: true,
            memory_visible: true,
            console_visible: true,
            breakpoints_visible: true,
            threads_visible: true,
            modules_visible: false,
            watches_visible: false,
            memory_address: None,
            listing_address: None,
        }
    }
}

impl DebugPluginUiState {
    /// Create a new UI state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the selected trace.
    pub fn select_trace(&mut self, trace_key: impl Into<String>) {
        self.selected_trace = Some(trace_key.into());
    }

    /// Clear the selected trace.
    pub fn clear_trace(&mut self) {
        self.selected_trace = None;
        self.selected_thread = None;
        self.selected_frame = None;
    }

    /// Set the selected thread.
    pub fn select_thread(&mut self, thread_key: i64) {
        self.selected_thread = Some(thread_key);
    }

    /// Set the selected frame.
    pub fn select_frame(&mut self, frame: u32) {
        self.selected_frame = Some(frame);
    }

    /// Check if a trace is selected.
    pub fn has_trace(&self) -> bool {
        self.selected_trace.is_some()
    }

    /// Check if a thread is selected.
    pub fn has_thread(&self) -> bool {
        self.selected_thread.is_some()
    }
}

// ---------------------------------------------------------------------------
// Logical Breakpoint State Machine
// ---------------------------------------------------------------------------

/// The mode of a logical breakpoint's program bookmark.
///
/// Ported from Ghidra's `LogicalBreakpoint.ProgramMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BreakpointProgramMode {
    /// A placeholder when the program bookmark state is not applicable.
    None,
    /// The breakpoint is mapped but not bookmarked.
    Missing,
    /// The breakpoint's program bookmark is enabled.
    Enabled,
    /// The breakpoint's program bookmark is disabled.
    Disabled,
}

/// The mode of a logical breakpoint's trace/target locations.
///
/// Ported from Ghidra's `LogicalBreakpoint.TraceMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BreakpointTraceMode {
    /// No traces involved.
    None,
    /// The breakpoint is missing from one or more mapped locations.
    Missing,
    /// All mapped locations are placed and enabled.
    Enabled,
    /// All mapped locations are placed and disabled.
    Disabled,
    /// Has both enabled and disabled locations.
    Mixed,
}

impl BreakpointTraceMode {
    /// Convert a boolean to trace breakpoint mode.
    pub fn from_bool(enabled: bool) -> Self {
        if enabled {
            Self::Enabled
        } else {
            Self::Disabled
        }
    }

    /// Compose two trace modes (for locations of the same logical breakpoint).
    pub fn combine(self, that: Self) -> Self {
        match (self, that) {
            (Self::None, other) | (other, Self::None) => match other {
                Self::None => Self::None,
                Self::Enabled | Self::Disabled => other,
                Self::Mixed => Self::Mixed,
                Self::Missing => Self::Missing,
            },
            (Self::Missing, _) | (_, Self::Missing) => Self::Missing,
            (Self::Enabled, Self::Enabled) => Self::Enabled,
            (Self::Disabled, Self::Disabled) => Self::Disabled,
            _ => Self::Mixed,
        }
    }
}

/// The perspective from which to view a logical breakpoint state.
///
/// Ported from Ghidra's `LogicalBreakpoint.Perspective`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BreakpointPerspective {
    /// View from the logical (program bookmark) perspective.
    Logical,
    /// View from the trace (target) perspective.
    Trace,
}

/// The mode of a logical breakpoint.
///
/// Ported from Ghidra's `LogicalBreakpoint.Mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BreakpointMode {
    /// All locations are enabled.
    Enabled,
    /// All locations are disabled.
    Disabled,
    /// Has both enabled and disabled trace locations.
    Mixed,
}

impl BreakpointMode {
    /// Compose modes at the same address.
    pub fn same_address(self, that: Self) -> Self {
        if self == that {
            self
        } else {
            Self::Mixed
        }
    }
}

/// The consistency of a logical breakpoint.
///
/// Ported from Ghidra's `LogicalBreakpoint.Consistency`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BreakpointConsistency {
    /// The bookmark and locations all agree.
    Normal,
    /// Has a bookmark but one or more trace locations is missing.
    Ineffective,
    /// Has a trace location but is not bookmarked, or the bookmark disagrees.
    Inconsistent,
}

impl BreakpointConsistency {
    /// Compose consistencies at the same address.
    pub fn same_address(self, that: Self) -> Self {
        std::cmp::max(self, that)
    }
}

/// The state of a logical breakpoint.
///
/// Ported from Ghidra's `LogicalBreakpoint.State`.
/// This is the cross product of [`BreakpointMode`] and [`BreakpointConsistency`]
/// with an additional `None` option.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BreakpointState {
    /// Placeholder state, usually indicating the breakpoint should not exist.
    None,
    /// The breakpoint is enabled, and all locations and its bookmark agree.
    Enabled,
    /// The breakpoint is disabled, and all locations and its bookmark agree.
    Disabled,
    /// Multiple logical breakpoints at this address, all saved and effective, mixed mode.
    Mixed,
    /// Saved as enabled, but one or more trace locations are absent.
    IneffectiveEnabled,
    /// Saved as disabled, and one or more trace locations are absent.
    IneffectiveDisabled,
    /// Multiple breakpoints, all saved, at least one ineffective, mixed mode.
    IneffectiveMixed,
    /// Enabled, all locations agree, but bookmark is absent or disagrees.
    InconsistentEnabled,
    /// Disabled, all locations agree, but bookmark is absent or disagrees.
    InconsistentDisabled,
    /// Terribly inconsistent: locations disagree, bookmark may be absent.
    InconsistentMixed,
}

impl BreakpointState {
    /// Construct a state from mode and consistency fields.
    pub fn from_fields(mode: Option<BreakpointMode>, consistency: Option<BreakpointConsistency>) -> Self {
        match (mode, consistency) {
            (None, None) | (None, _) | (_, None) => Self::None,
            (Some(BreakpointMode::Enabled), Some(BreakpointConsistency::Normal)) => Self::Enabled,
            (Some(BreakpointMode::Enabled), Some(BreakpointConsistency::Ineffective)) => Self::IneffectiveEnabled,
            (Some(BreakpointMode::Enabled), Some(BreakpointConsistency::Inconsistent)) => Self::InconsistentEnabled,
            (Some(BreakpointMode::Disabled), Some(BreakpointConsistency::Normal)) => Self::Disabled,
            (Some(BreakpointMode::Disabled), Some(BreakpointConsistency::Ineffective)) => Self::IneffectiveDisabled,
            (Some(BreakpointMode::Disabled), Some(BreakpointConsistency::Inconsistent)) => Self::InconsistentDisabled,
            (Some(BreakpointMode::Mixed), Some(BreakpointConsistency::Normal)) => Self::Mixed,
            (Some(BreakpointMode::Mixed), Some(BreakpointConsistency::Ineffective)) => Self::IneffectiveMixed,
            (Some(BreakpointMode::Mixed), Some(BreakpointConsistency::Inconsistent)) => Self::InconsistentMixed,
        }
    }

    /// Get the mode component.
    pub fn mode(&self) -> Option<BreakpointMode> {
        match self {
            Self::None => None,
            Self::Enabled | Self::IneffectiveEnabled | Self::InconsistentEnabled => Some(BreakpointMode::Enabled),
            Self::Disabled | Self::IneffectiveDisabled | Self::InconsistentDisabled => Some(BreakpointMode::Disabled),
            Self::Mixed | Self::IneffectiveMixed | Self::InconsistentMixed => Some(BreakpointMode::Mixed),
        }
    }

    /// Get the consistency component.
    pub fn consistency(&self) -> Option<BreakpointConsistency> {
        match self {
            Self::None => None,
            Self::Enabled | Self::Disabled | Self::Mixed => Some(BreakpointConsistency::Normal),
            Self::IneffectiveEnabled | Self::IneffectiveDisabled | Self::IneffectiveMixed => Some(BreakpointConsistency::Ineffective),
            Self::InconsistentEnabled | Self::InconsistentDisabled | Self::InconsistentMixed => Some(BreakpointConsistency::Inconsistent),
        }
    }

    /// Check if the breakpoint is in the normal consistency state.
    pub fn is_normal(&self) -> bool {
        self.consistency() == Some(BreakpointConsistency::Normal)
    }

    /// Check if the breakpoint is enabled (mixed counts as partially enabled).
    pub fn is_enabled(&self) -> bool {
        self.mode() != Some(BreakpointMode::Disabled)
    }

    /// Check if the breakpoint is disabled (mixed counts as partially disabled).
    pub fn is_disabled(&self) -> bool {
        self.mode() != Some(BreakpointMode::Enabled)
    }

    /// Check if the breakpoint is effective (present on target).
    pub fn is_effective(&self) -> bool {
        self.consistency() != Some(BreakpointConsistency::Ineffective)
    }

    /// Check if the breakpoint is ineffective.
    pub fn is_ineffective(&self) -> bool {
        self.consistency() == Some(BreakpointConsistency::Ineffective)
    }

    /// Compose states at the same address.
    pub fn same_address(self, that: Self) -> Self {
        if matches!(self, Self::None) {
            return that;
        }
        if matches!(that, Self::None) {
            return self;
        }
        let mode = self.mode().unwrap().same_address(that.mode().unwrap());
        let consistency = self.consistency().unwrap().same_address(that.consistency().unwrap());
        Self::from_fields(Some(mode), Some(consistency))
    }

    /// Get the toggled state (what should happen when toggling the breakpoint).
    pub fn get_toggled(self, mapped: bool) -> Self {
        if mapped && self.is_ineffective() {
            Self::Enabled
        } else if self.is_disabled() {
            Self::Enabled
        } else {
            Self::Disabled
        }
    }

    /// Compose states from multiple breakpoints at the same address.
    pub fn same_address_of(states: &[Self]) -> Self {
        states.iter().copied().fold(Self::None, |acc, s| acc.same_address(s))
    }
}

// ---------------------------------------------------------------------------
// Trace RMI Types
// ---------------------------------------------------------------------------

/// The status of a TraceRmi connection.
///
/// Ported from Ghidra's `TraceRmiConnection` lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TraceRmiConnectionState {
    /// The connection is being established.
    Connecting,
    /// The connection is active and ready.
    Active,
    /// The connection is busy (transaction open).
    Busy,
    /// The connection has been closed.
    Closed,
    /// The connection encountered an error.
    Error,
}

impl Default for TraceRmiConnectionState {
    fn default() -> Self {
        Self::Connecting
    }
}

/// A remote parameter descriptor for a TraceRmi method.
///
/// Ported from Ghidra's `RemoteParameter`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteParameter {
    /// The parameter name.
    pub name: String,
    /// The schema type name.
    pub type_name: String,
    /// Whether this parameter is required.
    pub required: bool,
    /// Default value (as a string).
    pub default_value: Option<String>,
    /// Human-readable display name.
    pub display: String,
    /// Description of the parameter.
    pub description: String,
}

impl RemoteParameter {
    /// Create a new required remote parameter.
    pub fn required(name: impl Into<String>, type_name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            type_name: type_name.into(),
            required: true,
            default_value: None,
            display: String::new(),
            description: String::new(),
        }
    }

    /// Create a new optional remote parameter with a default.
    pub fn optional(name: impl Into<String>, type_name: impl Into<String>, default: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            type_name: type_name.into(),
            required: false,
            default_value: Some(default.into()),
            display: String::new(),
            description: String::new(),
        }
    }

    /// Set the display name.
    pub fn with_display(mut self, display: impl Into<String>) -> Self {
        self.display = display.into();
        self
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }
}

/// A remote method registered by a back-end debugger.
///
/// Ported from Ghidra's `RemoteMethod`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteMethodDescriptor {
    /// The method name (e.g., "resume", "step_into").
    pub name: String,
    /// The associated action name.
    pub action_name: Option<String>,
    /// A title to display in the UI.
    pub display: String,
    /// A description of the method.
    pub description: String,
    /// The method's parameters.
    pub parameters: BTreeMap<String, RemoteParameter>,
    /// The return type schema name, if any.
    pub ret_type: Option<String>,
}

impl RemoteMethodDescriptor {
    /// Create a new remote method descriptor.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            action_name: None,
            display: String::new(),
            description: String::new(),
            parameters: BTreeMap::new(),
            ret_type: None,
        }
    }

    /// Set the action name.
    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.action_name = Some(action.into());
        self
    }

    /// Set the display name.
    pub fn with_display(mut self, display: impl Into<String>) -> Self {
        self.display = display.into();
        self
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Add a parameter.
    pub fn with_parameter(mut self, param: RemoteParameter) -> Self {
        self.parameters.insert(param.name.clone(), param);
        self
    }

    /// Set the return type.
    pub fn with_ret_type(mut self, ret_type: impl Into<String>) -> Self {
        self.ret_type = Some(ret_type.into());
        self
    }
}

/// A registry of remote methods provided by a back-end debugger.
///
/// Ported from Ghidra's `RemoteMethodRegistry`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemoteMethodRegistry {
    methods: BTreeMap<String, RemoteMethodDescriptor>,
}

impl RemoteMethodRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a method.
    pub fn register(&mut self, method: RemoteMethodDescriptor) {
        self.methods.insert(method.name.clone(), method);
    }

    /// Get a method by name.
    pub fn get(&self, name: &str) -> Option<&RemoteMethodDescriptor> {
        self.methods.get(name)
    }

    /// Get all methods.
    pub fn all(&self) -> &BTreeMap<String, RemoteMethodDescriptor> {
        &self.methods
    }

    /// Get methods by action name.
    pub fn get_by_action(&self, action: &str) -> Vec<&RemoteMethodDescriptor> {
        self.methods
            .values()
            .filter(|m| m.action_name.as_deref() == Some(action))
            .collect()
    }

    /// Get the number of registered methods.
    pub fn len(&self) -> usize {
        self.methods.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.methods.is_empty()
    }
}

/// A launch parameter for a TraceRmi connection.
///
/// Ported from Ghidra's `LaunchParameter`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchParameter {
    /// The parameter name.
    pub name: String,
    /// The display name.
    pub display: String,
    /// Description of the parameter.
    pub description: String,
    /// Whether this parameter is required.
    pub required: bool,
    /// The parameter type name (e.g., "string", "int", "boolean").
    pub type_name: String,
    /// Available choices, if constrained.
    pub choices: Vec<String>,
    /// Default value as a string.
    pub default_value: Option<String>,
}

impl LaunchParameter {
    /// Create a new launch parameter.
    pub fn new(
        name: impl Into<String>,
        type_name: impl Into<String>,
        display: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            display: display.into(),
            description: String::new(),
            required: false,
            type_name: type_name.into(),
            choices: Vec::new(),
            default_value: None,
        }
    }

    /// Mark this parameter as required.
    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Set constrained choices.
    pub fn with_choices(mut self, choices: Vec<String>) -> Self {
        self.choices = choices;
        self
    }

    /// Set the default value.
    pub fn with_default(mut self, default: impl Into<String>) -> Self {
        self.default_value = Some(default.into());
        self
    }
}

/// A launch offer for a TraceRmi connection.
///
/// Ported from Ghidra's `TraceRmiLaunchOffer`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRmiLaunchOffer {
    /// The connector type (e.g., "gdb", "lldb").
    pub connector_type: String,
    /// Human-readable description.
    pub description: String,
    /// The parameters for this launch offer.
    pub parameters: BTreeMap<String, LaunchParameter>,
    /// The environment name (e.g., "local", "remote").
    pub environment: String,
}

impl TraceRmiLaunchOffer {
    /// Create a new launch offer.
    pub fn new(connector_type: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            connector_type: connector_type.into(),
            description: description.into(),
            parameters: BTreeMap::new(),
            environment: "local".into(),
        }
    }

    /// Add a launch parameter.
    pub fn with_parameter(mut self, param: LaunchParameter) -> Self {
        self.parameters.insert(param.name.clone(), param);
        self
    }

    /// Set the environment.
    pub fn with_environment(mut self, env: impl Into<String>) -> Self {
        self.environment = env.into();
        self
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

    #[test]
    fn test_debug_plugin_priority() {
        assert!(DebugPluginPriority::Highest < DebugPluginPriority::Normal);
        assert!(DebugPluginPriority::Normal < DebugPluginPriority::Lowest);
        assert_eq!(DebugPluginPriority::Highest.as_u32(), 0);
        assert_eq!(DebugPluginPriority::Normal.as_u32(), 50);
        assert_eq!(DebugPluginPriority::default(), DebugPluginPriority::Normal);
    }

    #[test]
    fn test_debug_plugin_dependency() {
        let dep = DebugPluginDependency::required("TraceManagerPlugin")
            .with_reason("Needs trace manager for data access");
        assert!(dep.required);
        assert_eq!(dep.plugin_class, "TraceManagerPlugin");
        assert!(dep.reason.contains("trace manager"));

        let opt = DebugPluginDependency::optional("ConsolePlugin");
        assert!(!opt.required);
    }

    #[test]
    fn test_debug_plugin_dependency_serde() {
        let dep = DebugPluginDependency::required("ControlPlugin");
        let json = serde_json::to_string(&dep).unwrap();
        let back: DebugPluginDependency = serde_json::from_str(&json).unwrap();
        assert_eq!(dep, back);
    }

    #[test]
    fn test_debug_plugin_loader() {
        let mut loader = DebugPluginLoader::new();
        assert!(!loader.is_loading());
        assert_eq!(loader.pending_count(), 0);

        let config_a = DebugPluginConfig::new("PluginA");
        let reg_a = DebugPluginRegistration::new(config_a);
        loader.queue_plugin(reg_a, vec![]);

        let config_b = DebugPluginConfig::new("PluginB");
        let reg_b = DebugPluginRegistration::new(config_b);
        loader.queue_plugin(
            reg_b,
            vec![DebugPluginDependency::required("PluginA")],
        );

        assert_eq!(loader.pending_count(), 2);

        let order = loader.loading_order();
        assert_eq!(order.len(), 2);
        // PluginA has no deps, should come first.
        assert_eq!(order[0], "PluginA");
        assert_eq!(order[1], "PluginB");
    }

    #[test]
    fn test_debug_plugin_loader_dependencies_satisfied() {
        let mut loader = DebugPluginLoader::new();

        let config_a = DebugPluginConfig::new("PluginA");
        let reg_a = DebugPluginRegistration::new(config_a);
        loader.queue_plugin(reg_a, vec![]);

        let config_b = DebugPluginConfig::new("PluginB");
        let reg_b = DebugPluginRegistration::new(config_b);
        loader.queue_plugin(
            reg_b,
            vec![DebugPluginDependency::required("PluginA")],
        );

        assert!(loader.dependencies_satisfied("PluginB"));

        let config_c = DebugPluginConfig::new("PluginC");
        let reg_c = DebugPluginRegistration::new(config_c);
        loader.queue_plugin(
            reg_c,
            vec![DebugPluginDependency::required("MissingPlugin")],
        );

        assert!(!loader.dependencies_satisfied("PluginC"));
    }

    #[test]
    fn test_debug_plugin_loader_record_result() {
        let mut loader = DebugPluginLoader::new();
        loader.record_result(DebugPluginLoadResult {
            class_name: "PluginA".into(),
            success: true,
            error: None,
            load_time_ms: 15,
        });
        assert_eq!(loader.results().len(), 1);
        assert!(loader.results()[0].success);
    }

    #[test]
    fn test_debug_plugin_loader_pop_pending() {
        let mut loader = DebugPluginLoader::new();
        let config = DebugPluginConfig::new("PluginA");
        let reg = DebugPluginRegistration::new(config);
        loader.queue_plugin(reg, vec![]);
        assert_eq!(loader.pending_count(), 1);

        let popped = loader.pop_pending("PluginA");
        assert!(popped.is_some());
        assert_eq!(popped.unwrap().config.class_name, "PluginA");
        assert_eq!(loader.pending_count(), 0);

        assert!(loader.pop_pending("Missing").is_none());
    }

    #[test]
    fn test_debug_plugin_action() {
        let action = DebugPluginAction::new("Resume", "Resume execution")
            .with_menu_group("Execution")
            .with_key_binding("F5")
            .with_icon("icon.resume")
            .with_context_type("TraceContext");

        assert_eq!(action.name, "Resume");
        assert_eq!(action.description, "Resume execution");
        assert_eq!(action.menu_group.as_deref(), Some("Execution"));
        assert_eq!(action.key_binding.as_deref(), Some("F5"));
        assert!(action.enabled);
        assert!(action.visible);
    }

    #[test]
    fn test_debug_plugin_action_registry() {
        let mut registry = DebugPluginActionRegistry::new();
        assert!(registry.is_empty());

        let action = DebugPluginAction::new("Step", "Step into");
        registry.register(action);
        assert_eq!(registry.len(), 1);
        assert!(registry.get("Step").is_some());
        assert!(registry.get("Missing").is_none());

        registry.set_enabled("Step", false);
        assert!(!registry.get("Step").unwrap().enabled);

        registry.set_visible("Step", false);
        assert!(!registry.get("Step").unwrap().visible);

        let removed = registry.unregister("Step");
        assert!(removed.is_some());
        assert!(registry.is_empty());
    }

    #[test]
    fn test_debug_plugin_action_registry_serde() {
        let mut registry = DebugPluginActionRegistry::new();
        registry.register(DebugPluginAction::new("Test", "Test action"));
        let json = serde_json::to_string(&registry).unwrap();
        let back: DebugPluginActionRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
        assert!(back.get("Test").is_some());
    }

    #[test]
    fn test_debug_plugin_session() {
        let mut session = DebugPluginSession::new(
            "session-1",
            "trace-1",
            "gdb",
            "/usr/bin/target",
        );
        assert_eq!(session.session_id, "session-1");
        assert_eq!(session.connector_type, "gdb");
        assert_eq!(session.state, DebugPluginSessionState::Connecting);
        assert!(!session.is_active());

        session.state = DebugPluginSessionState::Active;
        assert!(session.is_active());

        session.state = DebugPluginSessionState::Paused;
        assert!(session.is_active());

        session.state = DebugPluginSessionState::Terminated;
        assert!(!session.is_active());
    }

    #[test]
    fn test_debug_plugin_session_config() {
        let mut session = DebugPluginSession::new("s1", "t1", "gdb", "target");
        session.set_config_override("remote-host", "localhost");
        session.set_config_override("remote-port", "2345");

        assert_eq!(session.get_config_override("remote-host"), Some("localhost"));
        assert_eq!(session.get_config_override("remote-port"), Some("2345"));
        assert_eq!(session.get_config_override("missing"), None);
    }

    #[test]
    fn test_debug_plugin_session_serde() {
        let session = DebugPluginSession::new("s1", "t1", "lldb", "target");
        let json = serde_json::to_string(&session).unwrap();
        let back: DebugPluginSession = serde_json::from_str(&json).unwrap();
        assert_eq!(back.session_id, "s1");
        assert_eq!(back.connector_type, "lldb");
    }

    #[test]
    fn test_debug_plugin_session_state_default() {
        let state = DebugPluginSessionState::default();
        assert_eq!(state, DebugPluginSessionState::Connecting);
    }

    #[test]
    fn test_debug_plugin_metrics() {
        let mut metrics = DebugPluginMetrics::new();
        assert_eq!(metrics.events_processed, 0);

        metrics.record_event(100);
        metrics.record_event(200);
        metrics.record_action(500);
        metrics.record_error();

        assert_eq!(metrics.events_processed, 2);
        assert_eq!(metrics.actions_executed, 1);
        assert_eq!(metrics.error_count, 1);
        assert_eq!(metrics.avg_event_time_us(), 150);
        assert_eq!(metrics.avg_action_time_us(), 500);

        metrics.reset();
        assert_eq!(metrics.events_processed, 0);
        assert_eq!(metrics.error_count, 0);
    }

    #[test]
    fn test_debug_plugin_metrics_serde() {
        let mut metrics = DebugPluginMetrics::new();
        metrics.record_event(100);
        let json = serde_json::to_string(&metrics).unwrap();
        let back: DebugPluginMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(back.events_processed, 1);
    }

    #[test]
    fn test_debug_plugin_tool_adapter() {
        let mut adapter = DebugPluginToolAdapter::new("Debugger");
        assert_eq!(adapter.tool_name, "Debugger");

        adapter.add_provider("TargetProvider");
        adapter.add_provider("ControlProvider");
        adapter.register_service("DebugControlService");
        adapter.consume_service("DebugTraceManagerService");

        assert!(adapter.providers.contains("TargetProvider"));
        assert!(adapter.services_registered.contains("DebugControlService"));

        adapter.add_menu_entry(MenuEntry {
            path: "Debugger/Resume".into(),
            action_name: "Resume".into(),
            group: "Execution".into(),
        });
        assert_eq!(adapter.menu_entries.len(), 1);

        adapter.add_toolbar_entry(ToolbarEntry {
            group: "Debug".into(),
            action_name: "Resume".into(),
            icon_path: Some("icon.resume".into()),
            tooltip: Some("Resume execution".into()),
        });
        assert_eq!(adapter.toolbar_entries.len(), 1);
    }

    #[test]
    fn test_debug_plugin_tool_adapter_serde() {
        let adapter = DebugPluginToolAdapter::new("Debugger");
        let json = serde_json::to_string(&adapter).unwrap();
        let back: DebugPluginToolAdapter = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tool_name, "Debugger");
    }

    #[test]
    fn test_debug_plugin_ui_state() {
        let mut state = DebugPluginUiState::new();
        assert!(!state.has_trace());
        assert!(!state.has_thread());
        assert!(state.listing_synced);

        state.select_trace("trace1");
        assert!(state.has_trace());
        assert_eq!(state.selected_trace.as_deref(), Some("trace1"));

        state.select_thread(42);
        assert!(state.has_thread());
        assert_eq!(state.selected_thread, Some(42));

        state.select_frame(0);
        assert_eq!(state.selected_frame, Some(0));

        state.clear_trace();
        assert!(!state.has_trace());
        assert!(!state.has_thread());
        assert!(state.selected_frame.is_none());
    }

    #[test]
    fn test_debug_plugin_ui_state_serde() {
        let mut state = DebugPluginUiState::new();
        state.select_trace("trace1");
        state.view_snap = 10;
        let json = serde_json::to_string(&state).unwrap();
        let back: DebugPluginUiState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.selected_trace.as_deref(), Some("trace1"));
        assert_eq!(back.view_snap, 10);
    }

    #[test]
    fn test_menu_entry_serde() {
        let entry = MenuEntry {
            path: "Debugger/Step Into".into(),
            action_name: "StepInto".into(),
            group: "Execution".into(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: MenuEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.path, "Debugger/Step Into");
    }

    #[test]
    fn test_toolbar_entry_serde() {
        let entry = ToolbarEntry {
            group: "Debug".into(),
            action_name: "Stop".into(),
            icon_path: Some("icon.stop".into()),
            tooltip: Some("Stop debugging".into()),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: ToolbarEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.action_name, "Stop");
    }

    #[test]
    fn test_breakpoint_trace_mode_combine() {
        assert_eq!(BreakpointTraceMode::None.combine(BreakpointTraceMode::Enabled), BreakpointTraceMode::Enabled);
        assert_eq!(BreakpointTraceMode::Enabled.combine(BreakpointTraceMode::Enabled), BreakpointTraceMode::Enabled);
        assert_eq!(BreakpointTraceMode::Enabled.combine(BreakpointTraceMode::Disabled), BreakpointTraceMode::Mixed);
        assert_eq!(BreakpointTraceMode::Mixed.combine(BreakpointTraceMode::Enabled), BreakpointTraceMode::Mixed);
        assert_eq!(BreakpointTraceMode::Missing.combine(BreakpointTraceMode::Enabled), BreakpointTraceMode::Missing);
    }

    #[test]
    fn test_breakpoint_trace_mode_from_bool() {
        assert_eq!(BreakpointTraceMode::from_bool(true), BreakpointTraceMode::Enabled);
        assert_eq!(BreakpointTraceMode::from_bool(false), BreakpointTraceMode::Disabled);
    }

    #[test]
    fn test_breakpoint_state_from_fields() {
        let state = BreakpointState::from_fields(
            Some(BreakpointMode::Enabled),
            Some(BreakpointConsistency::Normal),
        );
        assert_eq!(state, BreakpointState::Enabled);
        assert!(state.is_enabled());
        assert!(!state.is_disabled());
        assert!(state.is_normal());
        assert!(state.is_effective());

        let state = BreakpointState::from_fields(
            Some(BreakpointMode::Disabled),
            Some(BreakpointConsistency::Ineffective),
        );
        assert_eq!(state, BreakpointState::IneffectiveDisabled);
        assert!(!state.is_enabled());
        assert!(state.is_ineffective());
    }

    #[test]
    fn test_breakpoint_state_same_address() {
        let a = BreakpointState::Enabled;
        let b = BreakpointState::None;
        assert_eq!(a.same_address(b), BreakpointState::Enabled);
        assert_eq!(b.same_address(a), BreakpointState::Enabled);

        let c = BreakpointState::Disabled;
        assert_eq!(a.same_address(c), BreakpointState::Mixed);
    }

    #[test]
    fn test_breakpoint_state_same_address_of() {
        let states = vec![
            BreakpointState::Enabled,
            BreakpointState::None,
            BreakpointState::None,
        ];
        assert_eq!(BreakpointState::same_address_of(&states), BreakpointState::Enabled);
    }

    #[test]
    fn test_breakpoint_state_toggled() {
        assert_eq!(BreakpointState::Enabled.get_toggled(true), BreakpointState::Disabled);
        assert_eq!(BreakpointState::Disabled.get_toggled(true), BreakpointState::Enabled);
        assert_eq!(BreakpointState::IneffectiveEnabled.get_toggled(true), BreakpointState::Enabled);
        assert_eq!(BreakpointState::IneffectiveEnabled.get_toggled(false), BreakpointState::Disabled);
    }

    #[test]
    fn test_breakpoint_state_serde() {
        let state = BreakpointState::InconsistentMixed;
        let json = serde_json::to_string(&state).unwrap();
        let back: BreakpointState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }

    #[test]
    fn test_breakpoint_consistency_ordering() {
        assert!(BreakpointConsistency::Normal < BreakpointConsistency::Ineffective);
        assert!(BreakpointConsistency::Ineffective < BreakpointConsistency::Inconsistent);
        assert_eq!(
            BreakpointConsistency::Normal.same_address(BreakpointConsistency::Inconsistent),
            BreakpointConsistency::Inconsistent
        );
    }

    #[test]
    fn test_remote_parameter() {
        let param = RemoteParameter::required("address", "string")
            .with_display("Target Address")
            .with_description("The IP address to connect to");
        assert!(param.required);
        assert_eq!(param.name, "address");
        assert_eq!(param.type_name, "string");

        let opt = RemoteParameter::optional("port", "int", "2345");
        assert!(!opt.required);
        assert_eq!(opt.default_value.as_deref(), Some("2345"));
    }

    #[test]
    fn test_remote_method_descriptor() {
        let method = RemoteMethodDescriptor::new("resume")
            .with_action("Resume")
            .with_display("Resume Execution")
            .with_description("Resume the target")
            .with_parameter(RemoteParameter::required("thread", "Thread"));
        assert_eq!(method.name, "resume");
        assert_eq!(method.parameters.len(), 1);
        assert!(method.parameters.contains_key("thread"));
    }

    #[test]
    fn test_remote_method_descriptor_serde() {
        let method = RemoteMethodDescriptor::new("step_into")
            .with_display("Step Into");
        let json = serde_json::to_string(&method).unwrap();
        let back: RemoteMethodDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "step_into");
    }

    #[test]
    fn test_remote_method_registry() {
        let mut registry = RemoteMethodRegistry::new();
        assert!(registry.is_empty());

        registry.register(
            RemoteMethodDescriptor::new("resume")
                .with_action("Resume")
                .with_display("Resume"),
        );
        registry.register(
            RemoteMethodDescriptor::new("step_into")
                .with_action("Step")
                .with_display("Step Into"),
        );
        registry.register(
            RemoteMethodDescriptor::new("step_over")
                .with_action("Step")
                .with_display("Step Over"),
        );

        assert_eq!(registry.len(), 3);
        assert!(registry.get("resume").is_some());

        let step_methods = registry.get_by_action("Step");
        assert_eq!(step_methods.len(), 2);
    }

    #[test]
    fn test_remote_method_registry_serde() {
        let mut registry = RemoteMethodRegistry::new();
        registry.register(RemoteMethodDescriptor::new("test"));
        let json = serde_json::to_string(&registry).unwrap();
        let back: RemoteMethodRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
    }

    #[test]
    fn test_launch_parameter() {
        let param = LaunchParameter::new("host", "string", "Host")
            .required()
            .with_description("Remote host address")
            .with_default("localhost");
        assert!(param.required);
        assert_eq!(param.default_value.as_deref(), Some("localhost"));

        let choice_param = LaunchParameter::new("arch", "string", "Architecture")
            .with_choices(vec!["x86".into(), "x86_64".into(), "arm".into()]);
        assert_eq!(choice_param.choices.len(), 3);
    }

    #[test]
    fn test_launch_parameter_serde() {
        let param = LaunchParameter::new("test", "string", "Test");
        let json = serde_json::to_string(&param).unwrap();
        let back: LaunchParameter = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "test");
    }

    #[test]
    fn test_trace_rmi_launch_offer() {
        let offer = TraceRmiLaunchOffer::new("gdb", "GNU Debugger")
            .with_environment("remote")
            .with_parameter(
                LaunchParameter::new("host", "string", "Host").required(),
            )
            .with_parameter(
                LaunchParameter::new("port", "int", "Port").with_default("2345"),
            );
        assert_eq!(offer.connector_type, "gdb");
        assert_eq!(offer.environment, "remote");
        assert_eq!(offer.parameters.len(), 2);
    }

    #[test]
    fn test_trace_rmi_connection_state() {
        let state = TraceRmiConnectionState::default();
        assert_eq!(state, TraceRmiConnectionState::Connecting);
        assert_ne!(TraceRmiConnectionState::Active, TraceRmiConnectionState::Closed);
    }

    #[test]
    fn test_trace_rmi_connection_state_serde() {
        let state = TraceRmiConnectionState::Active;
        let json = serde_json::to_string(&state).unwrap();
        let back: TraceRmiConnectionState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }
}
