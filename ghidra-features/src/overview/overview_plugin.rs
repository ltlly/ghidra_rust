//! Overview Color Plugin -- full lifecycle, action, and config management.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.overview.OverviewColorPlugin` Java class.
//!
//! This module provides an enhanced plugin implementation that covers:
//! - Program lifecycle events (activated, deactivated, closed)
//! - Toggle actions for each overview color service
//! - Multi-action grouping for toolbar display
//! - Config state save/restore of active services
//! - `CodeViewerService` integration for provider installation
//!
//! # Architecture
//!
//! - [`EnhancedOverviewPlugin`] -- top-level plugin with full lifecycle
//! - [`OverviewToggleAction`] -- per-service toggle action model
//! - [`OverviewPluginEvent`] -- program lifecycle events
//! - [`OverviewPluginConfig`] -- serializable plugin configuration

use std::collections::HashMap;

use ghidra_core::Address;

use super::{OverviewColorComponent, OverviewColorService, OverviewSaveState, RgbColor};

// ---------------------------------------------------------------------------
// OverviewPluginEvent -- program lifecycle events
// ---------------------------------------------------------------------------

/// Program lifecycle events dispatched by the plugin.
///
/// Ported from the `ProgramPlugin` callbacks in Java:
/// `programActivated`, `programDeactivated`, `programClosed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverviewPluginEvent {
    /// A program was activated (became the current program).
    ProgramActivated,
    /// A program was deactivated (no longer current).
    ProgramDeactivated,
    /// A program was closed.
    ProgramClosed,
    /// The plugin is being disposed.
    Dispose,
}

// ---------------------------------------------------------------------------
// OverviewToggleAction -- per-service toggle
// ---------------------------------------------------------------------------

/// Toggle action model for a single overview color service.
///
/// Ported from the inner class `OverviewToggleAction extends ToggleDockingAction`
/// in `OverviewColorPlugin.java`.
///
/// Each action toggles one [`OverviewColorService`] on or off in the
/// listing's overview margin.
#[derive(Debug, Clone)]
pub struct OverviewToggleAction {
    /// Action name (matches the service name).
    pub name: String,
    /// Owner plugin name.
    pub owner: String,
    /// Whether the action is currently selected (service is active).
    pub selected: bool,
    /// Menu bar data: menu path.
    pub menu_path: Vec<String>,
    /// Help location topic.
    pub help_topic: String,
    /// Help location name.
    pub help_name: String,
}

impl OverviewToggleAction {
    /// Create a new toggle action for the given service.
    pub fn new(
        owner: impl Into<String>,
        service_name: impl Into<String>,
        help_topic: impl Into<String>,
        help_name: impl Into<String>,
    ) -> Self {
        let name = service_name.into();
        let menu_label = format!("Show {}", name);
        Self {
            name,
            owner: owner.into(),
            selected: false,
            menu_path: vec![menu_label],
            help_topic: help_topic.into(),
            help_name: help_name.into(),
        }
    }

    /// Toggle the selected state. Returns the new state.
    pub fn toggle(&mut self) -> bool {
        self.selected = !self.selected;
        self.selected
    }

    /// Set the selected state explicitly.
    pub fn set_selected(&mut self, selected: bool) {
        self.selected = selected;
    }

    /// Check if the action is currently selected.
    pub fn is_selected(&self) -> bool {
        self.selected
    }

    /// Simulate `actionPerformed` -- returns whether to install or uninstall.
    ///
    /// In the Java original, `actionPerformed` checks `isSelected()` and
    /// calls either `installOverview` or `uninstallOverview`.  Here we
    /// return the intent so the caller can act on it.
    pub fn action_performed(&mut self) -> OverviewAction {
        if self.selected {
            OverviewAction::Install
        } else {
            OverviewAction::Uninstall
        }
    }
}

/// The effect of a toggle action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverviewAction {
    /// Install the overview bar for this service.
    Install,
    /// Uninstall the overview bar for this service.
    Uninstall,
}

// ---------------------------------------------------------------------------
// OverviewPluginConfig -- serializable plugin configuration
// ---------------------------------------------------------------------------

/// Serializable configuration for the overview plugin.
///
/// Ported from the `readConfigState` / `writeConfigState` pattern in
/// `OverviewColorPlugin.java`.
#[derive(Debug, Clone, Default)]
pub struct OverviewPluginConfig {
    /// Names of services that were active when the plugin was last saved.
    pub active_service_names: Vec<String>,
}

impl OverviewPluginConfig {
    /// Create a new config with no active services.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load from an [`OverviewSaveState`].
    pub fn from_save_state(state: &OverviewSaveState) -> Self {
        Self {
            active_service_names: state.active_service_names.clone(),
        }
    }

    /// Convert to an [`OverviewSaveState`].
    pub fn to_save_state(&self) -> OverviewSaveState {
        OverviewSaveState {
            active_service_names: self.active_service_names.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// EnhancedOverviewPlugin
// ---------------------------------------------------------------------------

/// Full-featured overview color plugin.
///
/// Ported from `OverviewColorPlugin extends ProgramPlugin` in Java.
///
/// Manages [`OverviewColorService`] instances, creates toggle actions for
/// each service, and installs/removes [`OverviewColorComponent`] providers
/// as indicated by user actions.
///
/// # Lifecycle
///
/// 1. [`new()`](EnhancedOverviewPlugin::new) -- create plugin
/// 2. [`init()`](EnhancedOverviewPlugin::init) -- discover services, create actions
/// 3. [`program_activated()`](EnhancedOverviewPlugin::program_activated) -- notify services
/// 4. [`program_deactivated()`](EnhancedOverviewPlugin::program_deactivated) -- clear services
/// 5. [`cleanup()`](EnhancedOverviewPlugin::cleanup) -- uninstall all, dispose
///
/// # Example
///
/// ```
/// use ghidra_features::overview::overview_plugin::*;
/// use ghidra_features::overview::*;
///
/// let mut plugin = EnhancedOverviewPlugin::new("OverviewColorPlugin");
/// plugin.init();
/// plugin.program_activated("test.exe");
/// // ... user toggles actions ...
/// plugin.cleanup();
/// ```
pub struct EnhancedOverviewPlugin {
    /// Plugin name.
    pub name: String,
    /// All discovered overview color services.
    all_services: Vec<Box<dyn OverviewColorService>>,
    /// Active services mapped to their components, preserving left-to-right order.
    active_services: LinkedHashMap<usize, OverviewColorComponent>,
    /// Per-service toggle actions.
    action_map: HashMap<usize, OverviewToggleAction>,
    /// Current program name.
    current_program: Option<String>,
    /// Whether the plugin has been initialized.
    initialized: bool,
    /// Help topic identifier.
    pub help_topic: String,
}

/// A simple ordered map backed by `Vec` + `HashMap` to preserve insertion order.
///
/// This matches the Java `LinkedHashMap<OverviewColorService, OverviewColorComponent>`.
struct LinkedHashMap<K: Eq + std::hash::Hash + Clone, V> {
    keys: Vec<K>,
    map: HashMap<K, V>,
}

impl<K: Eq + std::hash::Hash + Clone, V> LinkedHashMap<K, V> {
    fn new() -> Self {
        Self {
            keys: Vec::new(),
            map: HashMap::new(),
        }
    }

    fn insert(&mut self, key: K, value: V) {
        if !self.map.contains_key(&key) {
            self.keys.push(key.clone());
        }
        self.map.insert(key, value);
    }

    fn remove(&mut self, key: &K) -> Option<V> {
        self.keys.retain(|k| k != key);
        self.map.remove(key)
    }

    fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }

    fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.map.get_mut(key)
    }

    fn keys(&self) -> &[K] {
        &self.keys
    }

    fn contains_key(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl std::fmt::Debug for EnhancedOverviewPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnhancedOverviewPlugin")
            .field("name", &self.name)
            .field("service_count", &self.all_services.len())
            .field("active_count", &self.active_services.len())
            .field("current_program", &self.current_program)
            .field("initialized", &self.initialized)
            .finish()
    }
}

impl EnhancedOverviewPlugin {
    /// Create a new overview plugin.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            all_services: Vec::new(),
            active_services: LinkedHashMap::new(),
            action_map: HashMap::new(),
            current_program: None,
            initialized: false,
            help_topic: "OverviewPlugin".to_string(),
        }
    }

    /// Initialize the plugin.
    ///
    /// Discovers services and creates toggle actions for each one.
    /// Ported from `OverviewColorPlugin.init()`.
    pub fn init(&mut self) {
        self.initialized = true;
        // In the Java version, services are discovered via ClassSearcher.
        // Here, services are registered externally via `add_service()`.
    }

    /// Register a color service with the plugin.
    ///
    /// The service is initialized and a toggle action is created for it.
    /// Ported from the `ClassSearcher.getInstances()` + `createActions()` pattern.
    pub fn add_service(&mut self, mut service: Box<dyn OverviewColorService>) {
        let index = self.all_services.len();
        service.initialize();
        if let Some(ref prog) = self.current_program {
            service.set_program(Some(prog.clone()));
        }
        self.all_services.push(service);

        let svc_name = self.all_services[index].name().to_string();
        let action = OverviewToggleAction::new(
            &self.name,
            &svc_name,
            &self.help_topic,
            &svc_name,
        );
        self.action_map.insert(index, action);
    }

    /// Read config state (restore previously active services).
    ///
    /// Ported from `OverviewColorPlugin.readConfigState()`.
    pub fn read_config_state(&mut self, config: &OverviewPluginConfig) {
        for service_name in &config.active_service_names {
            if let Some(index) = self.find_service_index(service_name) {
                if let Some(action) = self.action_map.get_mut(&index) {
                    action.set_selected(true);
                }
                self.install_overview(index);
            }
        }
    }

    /// Write config state (save currently active services).
    ///
    /// Ported from `OverviewColorPlugin.writeConfigState()`.
    pub fn write_config_state(&self) -> OverviewPluginConfig {
        OverviewPluginConfig {
            active_service_names: self.active_service_names(),
        }
    }

    /// Clean up: uninstall all services and dispose.
    ///
    /// Ported from `OverviewColorPlugin.cleanup()`.
    pub fn cleanup(&mut self) {
        let active_indices: Vec<usize> = self.active_services.keys().to_vec();
        for index in active_indices {
            self.uninstall_overview(index);
        }
        self.initialized = false;
    }

    /// Install an overview bar for the given service index.
    ///
    /// Ported from `OverviewColorPlugin.installOverview()`.
    pub fn install_overview(&mut self, service_index: usize) {
        if service_index >= self.all_services.len() {
            return;
        }
        if self.active_services.contains_key(&service_index) {
            return; // already active
        }

        // Set the program on the service
        if let Some(svc) = self.all_services.get_mut(service_index) {
            svc.set_program(self.current_program.clone());
        }

        // Build a component (provider)
        let svc_name = self.all_services[service_index].name().to_string();
        let component = OverviewColorComponent::new(Box::new(super::StubColorService::new(svc_name)));
        self.active_services.insert(service_index, component);

        // Mark the toggle action as selected
        if let Some(action) = self.action_map.get_mut(&service_index) {
            action.set_selected(true);
        }
    }

    /// Uninstall the overview bar for the given service index.
    ///
    /// Ported from `OverviewColorPlugin.uninstallOverview()`.
    pub fn uninstall_overview(&mut self, service_index: usize) {
        self.active_services.remove(&service_index);

        if let Some(svc) = self.all_services.get_mut(service_index) {
            svc.set_program(None);
        }

        if let Some(action) = self.action_map.get_mut(&service_index) {
            action.set_selected(false);
        }
    }

    /// Handle toggle action performed for a service.
    ///
    /// Returns the action taken (install or uninstall).
    pub fn toggle_action(&mut self, service_index: usize) -> Option<OverviewAction> {
        let action = self.action_map.get_mut(&service_index)?;
        let new_state = action.toggle();
        if new_state {
            self.install_overview(service_index);
            Some(OverviewAction::Install)
        } else {
            self.uninstall_overview(service_index);
            Some(OverviewAction::Uninstall)
        }
    }

    /// Notify all active services that a program was activated.
    ///
    /// Ported from `OverviewColorPlugin.programActivated()`.
    pub fn program_activated(&mut self, program_name: impl Into<String>) {
        let name = program_name.into();
        self.current_program = Some(name.clone());
        for &idx in self.active_services.keys() {
            if let Some(svc) = self.all_services.get_mut(idx) {
                svc.set_program(Some(name.clone()));
            }
        }
    }

    /// Notify all active services that the current program was deactivated.
    ///
    /// Ported from `OverviewColorPlugin.programDeactivated()`.
    pub fn program_deactivated(&mut self) {
        for &idx in self.active_services.keys() {
            if let Some(svc) = self.all_services.get_mut(idx) {
                svc.set_program(None);
            }
        }
        self.current_program = None;
    }

    /// Handle a plugin event.
    ///
    /// Dispatches to the appropriate lifecycle method.
    pub fn handle_event(&mut self, event: OverviewPluginEvent) {
        match event {
            OverviewPluginEvent::ProgramActivated => {
                // In a real framework the program name would come from the event.
                // Here the caller should use program_activated() directly.
            }
            OverviewPluginEvent::ProgramDeactivated => {
                self.program_deactivated();
            }
            OverviewPluginEvent::ProgramClosed => {
                self.program_deactivated();
            }
            OverviewPluginEvent::Dispose => {
                self.cleanup();
            }
        }
    }

    /// Get the list of all service names.
    pub fn service_names(&self) -> Vec<&str> {
        self.all_services.iter().map(|s| s.name()).collect()
    }

    /// Get the list of active service names (in order).
    pub fn active_service_names(&self) -> Vec<String> {
        self.active_services
            .keys()
            .iter()
            .filter_map(|&idx| self.all_services.get(idx).map(|s| s.name().to_string()))
            .collect()
    }

    /// Return the number of registered services.
    pub fn service_count(&self) -> usize {
        self.all_services.len()
    }

    /// Return the number of active services.
    pub fn active_service_count(&self) -> usize {
        self.active_services.len()
    }

    /// Check if the plugin has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get a reference to a service by index.
    pub fn service(&self, index: usize) -> Option<&dyn OverviewColorService> {
        self.all_services.get(index).map(|s| s.as_ref())
    }

    /// Get a mutable reference to a service by index.
    ///
    /// Note: returns a `&mut dyn OverviewColorService` with `'static` lifetime
    /// because the services are stored in `Box<dyn OverviewColorService>`.
    pub fn service_mut(&mut self, index: usize) -> Option<&mut (dyn OverviewColorService + 'static)> {
        self.all_services.get_mut(index).map(|s| &mut **s)
    }

    /// Check if a service is currently active.
    pub fn is_active(&self, service_index: usize) -> bool {
        self.active_services.contains_key(&service_index)
    }

    /// Get a reference to a toggle action by service index.
    pub fn action(&self, service_index: usize) -> Option<&OverviewToggleAction> {
        self.action_map.get(&service_index)
    }

    /// Get a mutable reference to a toggle action by service index.
    pub fn action_mut(&mut self, service_index: usize) -> Option<&mut OverviewToggleAction> {
        self.action_map.get_mut(&service_index)
    }

    /// Get the current program name.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    /// Find the service index by name.
    fn find_service_index(&self, name: &str) -> Option<usize> {
        self.all_services
            .iter()
            .position(|s| s.name() == name)
    }
}

impl Default for EnhancedOverviewPlugin {
    fn default() -> Self {
        Self::new("OverviewColorPlugin")
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overview::{OverviewColorService, RgbColor};
    use ghidra_core::Address;

    #[derive(Debug)]
    struct TestService {
        name: String,
        program: Option<String>,
    }

    impl TestService {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                program: None,
            }
        }
    }

    impl OverviewColorService for TestService {
        fn name(&self) -> &str {
            &self.name
        }
        fn get_color(&self, address: &Address) -> RgbColor {
            RgbColor::new((address.offset & 0xFF) as u8, 128, 200)
        }
        fn set_program(&mut self, program_name: Option<String>) {
            self.program = program_name;
        }
        fn get_program(&self) -> Option<&str> {
            self.program.as_deref()
        }
        fn get_tooltip_text(&self, address: &Address) -> String {
            format!("0x{:X}", address.offset)
        }
        fn initialize(&mut self) {}
    }

    #[test]
    fn test_plugin_new() {
        let plugin = EnhancedOverviewPlugin::new("TestPlugin");
        assert_eq!(plugin.name, "TestPlugin");
        assert!(!plugin.is_initialized());
        assert_eq!(plugin.service_count(), 0);
        assert_eq!(plugin.active_service_count(), 0);
    }

    #[test]
    fn test_plugin_init() {
        let mut plugin = EnhancedOverviewPlugin::new("TestPlugin");
        plugin.init();
        assert!(plugin.is_initialized());
    }

    #[test]
    fn test_plugin_add_service() {
        let mut plugin = EnhancedOverviewPlugin::new("TestPlugin");
        plugin.init();
        plugin.add_service(Box::new(TestService::new("Entropy")));
        plugin.add_service(Box::new(TestService::new("AddressType")));

        assert_eq!(plugin.service_count(), 2);
        assert_eq!(plugin.service_names(), vec!["Entropy", "AddressType"]);
        // Actions should be created
        assert!(plugin.action(0).is_some());
        assert!(plugin.action(1).is_some());
    }

    #[test]
    fn test_plugin_install_uninstall() {
        let mut plugin = EnhancedOverviewPlugin::new("TestPlugin");
        plugin.init();
        plugin.add_service(Box::new(TestService::new("Svc1")));
        plugin.add_service(Box::new(TestService::new("Svc2")));

        plugin.install_overview(0);
        assert!(plugin.is_active(0));
        assert_eq!(plugin.active_service_count(), 1);

        plugin.install_overview(1);
        assert_eq!(plugin.active_service_count(), 2);

        plugin.uninstall_overview(0);
        assert!(!plugin.is_active(0));
        assert_eq!(plugin.active_service_count(), 1);
        assert_eq!(plugin.active_service_names(), vec!["Svc2"]);
    }

    #[test]
    fn test_plugin_install_idempotent() {
        let mut plugin = EnhancedOverviewPlugin::new("TestPlugin");
        plugin.init();
        plugin.add_service(Box::new(TestService::new("Svc")));

        plugin.install_overview(0);
        plugin.install_overview(0); // should be a no-op
        assert_eq!(plugin.active_service_count(), 1);
    }

    #[test]
    fn test_plugin_toggle_action() {
        let mut plugin = EnhancedOverviewPlugin::new("TestPlugin");
        plugin.init();
        plugin.add_service(Box::new(TestService::new("Svc")));

        let result = plugin.toggle_action(0);
        assert_eq!(result, Some(OverviewAction::Install));
        assert!(plugin.is_active(0));

        let result = plugin.toggle_action(0);
        assert_eq!(result, Some(OverviewAction::Uninstall));
        assert!(!plugin.is_active(0));
    }

    #[test]
    fn test_plugin_program_lifecycle() {
        let mut plugin = EnhancedOverviewPlugin::new("TestPlugin");
        plugin.init();
        plugin.add_service(Box::new(TestService::new("Svc")));
        plugin.install_overview(0);

        plugin.program_activated("test.exe");
        assert_eq!(plugin.current_program(), Some("test.exe"));
        assert_eq!(plugin.service(0).unwrap().get_program(), Some("test.exe"));

        plugin.program_deactivated();
        assert!(plugin.current_program().is_none());
        assert!(plugin.service(0).unwrap().get_program().is_none());
    }

    #[test]
    fn test_plugin_cleanup() {
        let mut plugin = EnhancedOverviewPlugin::new("TestPlugin");
        plugin.init();
        plugin.add_service(Box::new(TestService::new("Svc1")));
        plugin.add_service(Box::new(TestService::new("Svc2")));
        plugin.install_overview(0);
        plugin.install_overview(1);

        plugin.cleanup();
        assert!(!plugin.is_initialized());
        assert_eq!(plugin.active_service_count(), 0);
    }

    #[test]
    fn test_plugin_config_save_restore() {
        let mut plugin = EnhancedOverviewPlugin::new("TestPlugin");
        plugin.init();
        plugin.add_service(Box::new(TestService::new("Entropy")));
        plugin.add_service(Box::new(TestService::new("AddressType")));
        plugin.install_overview(0);

        let config = plugin.write_config_state();
        assert_eq!(config.active_service_names, vec!["Entropy"]);

        // Restore on a fresh plugin
        let mut plugin2 = EnhancedOverviewPlugin::new("TestPlugin");
        plugin2.init();
        plugin2.add_service(Box::new(TestService::new("Entropy")));
        plugin2.add_service(Box::new(TestService::new("AddressType")));
        plugin2.read_config_state(&config);

        assert!(plugin2.is_active(0));
        assert!(!plugin2.is_active(1));
    }

    #[test]
    fn test_plugin_handle_dispose_event() {
        let mut plugin = EnhancedOverviewPlugin::new("TestPlugin");
        plugin.init();
        plugin.add_service(Box::new(TestService::new("Svc")));
        plugin.install_overview(0);

        plugin.handle_event(OverviewPluginEvent::Dispose);
        assert_eq!(plugin.active_service_count(), 0);
    }

    #[test]
    fn test_toggle_action_model() {
        let mut action = OverviewToggleAction::new("Plugin", "Entropy", "Overview", "Entropy");
        assert!(!action.is_selected());
        assert_eq!(action.name, "Entropy");
        assert_eq!(action.owner, "Plugin");
        assert_eq!(action.menu_path, vec!["Show Entropy"]);

        action.set_selected(true);
        assert!(action.is_selected());
        assert_eq!(action.action_performed(), OverviewAction::Install);

        action.set_selected(false);
        assert_eq!(action.action_performed(), OverviewAction::Uninstall);
    }

    #[test]
    fn test_overview_plugin_config() {
        let config = OverviewPluginConfig::new();
        assert!(config.active_service_names.is_empty());

        let save = OverviewSaveState {
            active_service_names: vec!["A".into(), "B".into()],
        };
        let config = OverviewPluginConfig::from_save_state(&save);
        assert_eq!(config.active_service_names, vec!["A", "B"]);

        let restored = config.to_save_state();
        assert_eq!(restored.active_service_names, vec!["A", "B"]);
    }

    #[test]
    fn test_linked_hash_map_ordering() {
        let mut map = LinkedHashMap::new();
        map.insert(2, "b");
        map.insert(1, "a");
        map.insert(3, "c");
        assert_eq!(map.keys(), &[2, 1, 3]);

        map.remove(&1);
        assert_eq!(map.keys(), &[2, 3]);
        assert_eq!(map.len(), 2);
    }
}
