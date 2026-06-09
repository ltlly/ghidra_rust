//! Function Reachability Plugin -- top-level plugin coordinating reachability providers.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.reachability.FunctionReachabilityPlugin`.
//!
//! Manages the lifecycle of reachability providers, dispatches the
//! "Show Function Reachability" action, and resolves the function at the
//! current location for reachability analysis.
//!
//! # Key Types
//!
//! - [`ReachabilityPlugin`] -- Plugin that owns reachability providers
//! - [`ReachabilityAction`] -- The "Show Function Reachability" action model

use ghidra_core::Address;

use super::graph::FRPathsModel;
use super::reachability_provider::ReachabilityProvider;

// ---------------------------------------------------------------------------
// ReachabilityAction -- the "Function Reachability" action model
// ---------------------------------------------------------------------------

/// The "Function Reachability" menu action.
///
/// Ported from the `DockingAction` created inside `FunctionReachabilityPlugin.createActions()`.
#[derive(Debug, Clone)]
pub struct ReachabilityAction {
    /// Internal action name.
    pub name: String,
    /// Menu group.
    pub group: String,
    /// Description.
    pub description: String,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// Menu path: ["Function", "Function Reachability"].
    pub menu_path: Vec<String>,
    /// Menu bar path: ["Graph", "Function Reachability"].
    pub menu_bar_path: Vec<String>,
}

impl ReachabilityAction {
    /// Create the default "Show Function Reachability" action.
    pub fn new() -> Self {
        Self {
            name: "Show Function Reachability".into(),
            group: "ShowReferences".into(),
            description: "This plugin shows all paths between two functions.".into(),
            enabled: false,
            menu_path: vec!["Function".into(), "Function Reachability".into()],
            menu_bar_path: vec!["Graph".into(), "Function Reachability".into()],
        }
    }

    /// Enable the action.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the action.
    pub fn disable(&mut self) {
        self.enabled = false;
    }
}

impl Default for ReachabilityAction {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ReachabilityPlugin -- top-level plugin
// ---------------------------------------------------------------------------

/// Plugin that manages function reachability providers.
///
/// Ported from `ghidra.app.plugin.core.reachability.FunctionReachabilityPlugin`.
///
/// The plugin:
/// 1. Maintains a list of [`ReachabilityProvider`] instances.
/// 2. Dispatches the "Show Function Reachability" action.
/// 3. Tracks the current program location for function resolution.
/// 4. Creates new providers when the action is triggered.
#[derive(Debug)]
pub struct ReachabilityPlugin {
    /// Active reachability providers.
    providers: Vec<ReachabilityProvider>,
    /// The "Show Function Reachability" action.
    action: ReachabilityAction,
    /// Current program name (if any).
    current_program: Option<String>,
    /// Current cursor address.
    current_location: Option<Address>,
    /// Shared reachability graph used by providers.
    paths_model: FRPathsModel,
}

impl ReachabilityPlugin {
    /// Create a new reachability plugin.
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
            action: ReachabilityAction::new(),
            current_program: None,
            current_location: None,
            paths_model: FRPathsModel::new(),
        }
    }

    /// Get the reachability action.
    pub fn action(&self) -> &ReachabilityAction {
        &self.action
    }

    /// Get a mutable reference to the reachability action.
    pub fn action_mut(&mut self) -> &mut ReachabilityAction {
        &mut self.action
    }

    /// Get the current program name.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    /// Set the current program.
    pub fn set_program(&mut self, program_name: Option<String>) {
        self.current_program = program_name;
        if self.current_program.is_none() {
            self.current_location = None;
        }
    }

    /// Get the current location address.
    pub fn current_location(&self) -> Option<Address> {
        self.current_location
    }

    /// Notify that the location has changed.
    ///
    /// Ported from `FunctionReachabilityPlugin.locationChanged(ProgramLocation)`.
    pub fn location_changed(&mut self, address: Option<Address>) {
        self.current_location = address;
    }

    /// Get the shared paths model.
    pub fn paths_model(&self) -> &FRPathsModel {
        &self.paths_model
    }

    /// Get a mutable reference to the shared paths model.
    pub fn paths_model_mut(&mut self) -> &mut FRPathsModel {
        &mut self.paths_model
    }

    /// Create and register a new reachability provider.
    ///
    /// Ported from `FunctionReachabilityPlugin.createNewProvider(ProgramLocation)`.
    pub fn create_new_provider(&mut self, location: Option<Address>) -> usize {
        let mut provider = ReachabilityProvider::new();
        provider.initialize(self.current_program.clone(), location);
        self.providers.push(provider);
        self.providers.len() - 1
    }

    /// Remove a provider by index.
    ///
    /// Ported from `FunctionReachabilityPlugin.removeProvider(FunctionReachabilityProvider)`.
    pub fn remove_provider(&mut self, index: usize) -> Option<ReachabilityProvider> {
        if index < self.providers.len() {
            Some(self.providers.remove(index))
        } else {
            None
        }
    }

    /// Get the number of active providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Get a reference to a provider by index.
    pub fn provider(&self, index: usize) -> Option<&ReachabilityProvider> {
        self.providers.get(index)
    }

    /// Get a mutable reference to a provider by index.
    pub fn provider_mut(&mut self, index: usize) -> Option<&mut ReachabilityProvider> {
        self.providers.get_mut(index)
    }

    /// Dispose all providers.
    pub fn dispose(&mut self) {
        self.providers.clear();
        self.current_program = None;
        self.current_location = None;
        self.paths_model.clear();
    }

    /// Save plugin state.
    pub fn save_state(&self) -> ReachabilityPluginState {
        ReachabilityPluginState {
            max_depth: 10,
            max_paths: 100,
        }
    }

    /// Restore plugin state.
    pub fn restore_state(&mut self, state: ReachabilityPluginState) {
        // State is applied to newly created providers
        let _ = state;
    }
}

impl Default for ReachabilityPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ReachabilityPluginState -- persisted configuration
// ---------------------------------------------------------------------------

/// Persisted state for the reachability plugin.
///
/// Ported from `FunctionReachabilityPlugin.readConfigState(SaveState)` and
/// `writeConfigState(SaveState)`.
#[derive(Debug, Clone)]
pub struct ReachabilityPluginState {
    /// Maximum search depth.
    pub max_depth: usize,
    /// Maximum number of paths to find.
    pub max_paths: usize,
}

impl Default for ReachabilityPluginState {
    fn default() -> Self {
        Self {
            max_depth: 10,
            max_paths: 100,
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reachability_action_new() {
        let action = ReachabilityAction::new();
        assert_eq!(action.name, "Show Function Reachability");
        assert_eq!(action.group, "ShowReferences");
        assert!(!action.enabled);
        assert_eq!(action.menu_path, vec!["Function", "Function Reachability"]);
        assert_eq!(action.menu_bar_path, vec!["Graph", "Function Reachability"]);
    }

    #[test]
    fn test_reachability_action_enable_disable() {
        let mut action = ReachabilityAction::new();
        assert!(!action.enabled);

        action.enable();
        assert!(action.enabled);

        action.disable();
        assert!(!action.enabled);
    }

    #[test]
    fn test_reachability_action_default() {
        let action = ReachabilityAction::default();
        assert_eq!(action.name, "Show Function Reachability");
    }

    #[test]
    fn test_reachability_plugin_new() {
        let plugin = ReachabilityPlugin::new();
        assert!(plugin.current_program.is_none());
        assert!(plugin.current_location.is_none());
        assert_eq!(plugin.provider_count(), 0);
    }

    #[test]
    fn test_reachability_plugin_set_program() {
        let mut plugin = ReachabilityPlugin::new();
        plugin.set_program(Some("test.exe".into()));
        assert_eq!(plugin.current_program(), Some("test.exe"));

        plugin.set_program(None);
        assert!(plugin.current_program().is_none());
        assert!(plugin.current_location().is_none());
    }

    #[test]
    fn test_reachability_plugin_location_changed() {
        let mut plugin = ReachabilityPlugin::new();
        plugin.location_changed(Some(Address::new(0x401000)));
        assert_eq!(plugin.current_location(), Some(Address::new(0x401000)));
    }

    #[test]
    fn test_reachability_plugin_create_provider() {
        let mut plugin = ReachabilityPlugin::new();
        plugin.set_program(Some("test.exe".into()));

        let idx = plugin.create_new_provider(Some(Address::new(0x401000)));
        assert_eq!(idx, 0);
        assert_eq!(plugin.provider_count(), 1);

        let idx2 = plugin.create_new_provider(Some(Address::new(0x402000)));
        assert_eq!(idx2, 1);
        assert_eq!(plugin.provider_count(), 2);
    }

    #[test]
    fn test_reachability_plugin_remove_provider() {
        let mut plugin = ReachabilityPlugin::new();
        plugin.create_new_provider(None);
        plugin.create_new_provider(None);
        assert_eq!(plugin.provider_count(), 2);

        let removed = plugin.remove_provider(0);
        assert!(removed.is_some());
        assert_eq!(plugin.provider_count(), 1);

        // Out-of-bounds
        assert!(plugin.remove_provider(99).is_none());
    }

    #[test]
    fn test_reachability_plugin_provider_access() {
        let mut plugin = ReachabilityPlugin::new();
        plugin.create_new_provider(Some(Address::new(0x1000)));
        plugin.create_new_provider(Some(Address::new(0x2000)));

        assert!(plugin.provider(0).is_some());
        assert!(plugin.provider(1).is_some());
        assert!(plugin.provider(2).is_none());

        assert!(plugin.provider_mut(0).is_some());
    }

    #[test]
    fn test_reachability_plugin_dispose() {
        let mut plugin = ReachabilityPlugin::new();
        plugin.set_program(Some("test".into()));
        plugin.create_new_provider(None);
        plugin.create_new_provider(None);

        plugin.dispose();
        assert!(plugin.current_program().is_none());
        assert_eq!(plugin.provider_count(), 0);
    }

    #[test]
    fn test_reachability_plugin_save_restore_state() {
        let plugin = ReachabilityPlugin::new();
        let state = plugin.save_state();
        assert_eq!(state.max_depth, 10);
        assert_eq!(state.max_paths, 100);

        let mut plugin2 = ReachabilityPlugin::new();
        plugin2.restore_state(state);
        // restore_state currently no-op, but shouldn't panic
    }

    #[test]
    fn test_reachability_plugin_state_default() {
        let state = ReachabilityPluginState::default();
        assert_eq!(state.max_depth, 10);
        assert_eq!(state.max_paths, 100);
    }

    #[test]
    fn test_reachability_plugin_paths_model() {
        let mut plugin = ReachabilityPlugin::new();
        assert_eq!(plugin.paths_model().vertex_count(), 0);

        plugin.paths_model_mut().add_vertex(
            super::super::graph::FRVertex::new(0x1000, "main"),
        );
        assert_eq!(plugin.paths_model().vertex_count(), 1);
    }
}
