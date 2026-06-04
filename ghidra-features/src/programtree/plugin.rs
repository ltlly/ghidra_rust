//! ProgramTreePlugin -- top-level coordination of multiple tree views.
//!
//! Ported from `ghidra.app.plugin.core.programtree.ProgramTreePlugin`.
//!
//! Manages multiple [`TreeViewProvider`]s, handles events (program
//! activated/deactivated, tree selection changes), and exposes the
//! public API for program tree services.

use std::collections::HashMap;

use ghidra_core::addr::AddressSet;
use ghidra_core::Address;

use super::action_manager::ProgramTreeActionManager;
use super::node::ProgramNode;
use super::tree::ProgramTree;
use super::view_provider::{TreeViewProvider, ViewState};
use super::GroupPath;

/// The default tree name used when no trees are present in a program.
pub const DEFAULT_TREE_NAME: &str = "Program Tree";

/// Event types the program tree plugin produces or consumes.
#[derive(Debug, Clone)]
pub enum ProgramTreeEvent {
    /// A tree was activated (view changed).
    TreeActivated(String),
    /// A tree view was closed.
    TreeClosed(String),
    /// A tree was renamed.
    TreeRenamed { old_name: String, new_name: String },
    /// A tree was created.
    TreeCreated(String),
    /// A tree was deleted.
    TreeDeleted(String),
    /// The selection changed in a tree.
    SelectionChanged {
        tree_name: String,
        paths: Vec<GroupPath>,
    },
}

/// The program tree plugin.
///
/// Coordinates multiple tree views and provides the API for:
/// - adding/removing tree views
/// - switching the current view
/// - handling program activation/deactivation
/// - managing actions (cut/copy/paste/etc.)
/// - persisting/restoring view state
#[derive(Debug)]
pub struct ProgramTreePlugin {
    /// Map from tree name to its view provider.
    provider_map: HashMap<String, TreeViewProvider>,
    /// The currently active tree view.
    current_tree_name: Option<String>,
    /// The default provider (used when no trees exist in the program).
    default_provider: Option<TreeViewProvider>,
    /// The action manager for tree operations.
    action_manager: ProgramTreeActionManager,
    /// Pending events to be processed.
    events: Vec<ProgramTreeEvent>,
    /// Whether replace-view mode is active (double-click replaces view).
    is_replace_view_mode: bool,
    /// Whether the plugin has been initialized.
    initialized: bool,
}

impl ProgramTreePlugin {
    /// Create a new ProgramTreePlugin.
    pub fn new() -> Self {
        let default = TreeViewProvider::new(DEFAULT_TREE_NAME);
        let mut provider_map = HashMap::new();
        provider_map.insert(DEFAULT_TREE_NAME.to_string(), default);

        Self {
            provider_map,
            current_tree_name: Some(DEFAULT_TREE_NAME.to_string()),
            default_provider: None,
            action_manager: ProgramTreeActionManager::new(),
            events: Vec::new(),
            is_replace_view_mode: false,
            initialized: false,
        }
    }

    // ------------------------------------------------------------------
    // Initialization
    // ------------------------------------------------------------------

    /// Initialize the plugin.
    pub fn init(&mut self) {
        self.initialized = true;
    }

    /// Returns `true` if the plugin has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Dispose of the plugin.
    pub fn dispose(&mut self) {
        self.provider_map.clear();
        self.current_tree_name = None;
        self.default_provider = None;
        self.events.clear();
        self.initialized = false;
    }

    // ------------------------------------------------------------------
    // View management
    // ------------------------------------------------------------------

    /// Returns the name of the currently viewed tree.
    pub fn viewed_tree_name(&self) -> Option<&str> {
        self.current_tree_name.as_deref()
    }

    /// Set the current view to the tree with the given name.
    pub fn set_viewed_tree(&mut self, tree_name: &str) {
        if self.provider_map.contains_key(tree_name) {
            self.current_tree_name = Some(tree_name.to_string());
            self.events
                .push(ProgramTreeEvent::TreeActivated(tree_name.to_string()));
        }
    }

    /// Returns a reference to the current view provider.
    pub fn current_provider(&self) -> Option<&TreeViewProvider> {
        self.current_tree_name
            .as_ref()
            .and_then(|name| self.provider_map.get(name))
    }

    /// Returns a mutable reference to the current view provider.
    pub fn current_provider_mut(&mut self) -> Option<&mut TreeViewProvider> {
        self.current_tree_name
            .as_ref()
            .cloned()
            .and_then(move |name| self.provider_map.get_mut(&name))
    }

    /// Returns a reference to the view provider with the given name.
    pub fn get_provider(&self, name: &str) -> Option<&TreeViewProvider> {
        self.provider_map.get(name)
    }

    /// Returns a mutable reference to the view provider with the given name.
    pub fn get_provider_mut(&mut self, name: &str) -> Option<&mut TreeViewProvider> {
        self.provider_map.get_mut(name)
    }

    /// Returns the number of open views.
    pub fn view_count(&self) -> usize {
        self.provider_map.len()
    }

    /// Returns all view names.
    pub fn view_names(&self) -> Vec<&String> {
        self.provider_map.keys().collect()
    }

    /// Add a new tree view with the given name.
    ///
    /// Returns `true` if the view was added, `false` if a view with that
    /// name already exists.
    pub fn add_tree_view(&mut self, tree_name: impl Into<String>) -> bool {
        let name = tree_name.into();
        if self.provider_map.contains_key(&name) {
            return false;
        }
        let provider = TreeViewProvider::new(&name);
        self.provider_map.insert(name.clone(), provider);
        self.events.push(ProgramTreeEvent::TreeCreated(name));
        true
    }

    /// Add a tree view with an existing tree structure.
    pub fn add_tree_view_with_tree(&mut self, tree: ProgramTree) {
        let name = tree.tree_name().to_string();
        let provider = TreeViewProvider::with_tree(tree);
        self.provider_map.insert(name.clone(), provider);
        self.events.push(ProgramTreeEvent::TreeCreated(name));
    }

    /// Close the tree view with the given name.
    ///
    /// Returns `false` if this is the last view (cannot close last view).
    pub fn close_view(&mut self, tree_name: &str) -> bool {
        if self.provider_map.len() <= 1 {
            return false;
        }
        if let Some(mut provider) = self.provider_map.remove(tree_name) {
            provider.dispose();
            self.events
                .push(ProgramTreeEvent::TreeClosed(tree_name.to_string()));
            // If we closed the current view, switch to another one
            if self.current_tree_name.as_deref() == Some(tree_name) {
                self.current_tree_name = self.provider_map.keys().next().cloned();
            }
            true
        } else {
            false
        }
    }

    /// Rename a tree view.
    pub fn rename_view(&mut self, old_name: &str, new_name: &str) -> Result<(), String> {
        if self.provider_map.contains_key(new_name) {
            return Err(format!("'{}' already exists", new_name));
        }
        if let Some(mut provider) = self.provider_map.remove(old_name) {
            provider.set_view_name(new_name);
            self.provider_map.insert(new_name.to_string(), provider);
            if self.current_tree_name.as_deref() == Some(old_name) {
                self.current_tree_name = Some(new_name.to_string());
            }
            self.events.push(ProgramTreeEvent::TreeRenamed {
                old_name: old_name.to_string(),
                new_name: new_name.to_string(),
            });
            Ok(())
        } else {
            Err(format!("'{}' not found", old_name))
        }
    }

    // ------------------------------------------------------------------
    // Program lifecycle
    // ------------------------------------------------------------------

    /// Called when a program is activated.
    ///
    /// Populates the provider map with the program's tree names.
    pub fn program_activated(&mut self, tree_names: &[String]) {
        // Clear existing providers
        for (_, mut provider) in self.provider_map.drain() {
            provider.dispose();
        }

        if tree_names.is_empty() {
            // Add default provider
            let provider = TreeViewProvider::new(DEFAULT_TREE_NAME);
            self.provider_map
                .insert(DEFAULT_TREE_NAME.to_string(), provider);
            self.current_tree_name = Some(DEFAULT_TREE_NAME.to_string());
        } else {
            for name in tree_names {
                let provider = TreeViewProvider::new(name);
                self.provider_map.insert(name.clone(), provider);
            }
            self.current_tree_name = Some(tree_names[0].clone());
        }
    }

    /// Called when the active program is deactivated.
    pub fn program_deactivated(&mut self) {
        // Nothing to do in the model layer; the view layer would
        // clean up Swing components.
    }

    // ------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------

    /// Drain and return all pending events.
    pub fn drain_events(&mut self) -> Vec<ProgramTreeEvent> {
        std::mem::take(&mut self.events)
    }

    /// Process a tree selection event.
    pub fn process_selection_event(&mut self, tree_name: &str, paths: Vec<GroupPath>) {
        if let Some(provider) = self.provider_map.get_mut(tree_name) {
            provider.set_group_selection(&paths);
            self.events.push(ProgramTreeEvent::SelectionChanged {
                tree_name: tree_name.to_string(),
                paths,
            });
        }
    }

    // ------------------------------------------------------------------
    // Settings
    // ------------------------------------------------------------------

    /// Returns whether replace-view mode is active.
    pub fn is_replace_view_mode(&self) -> bool {
        self.is_replace_view_mode
    }

    /// Set replace-view mode.
    pub fn set_replace_view_mode(&mut self, replace: bool) {
        self.is_replace_view_mode = replace;
    }

    // ------------------------------------------------------------------
    // Action manager
    // ------------------------------------------------------------------

    /// Returns a reference to the action manager.
    pub fn action_manager(&self) -> &ProgramTreeActionManager {
        &self.action_manager
    }

    /// Returns a mutable reference to the action manager.
    pub fn action_manager_mut(&mut self) -> &mut ProgramTreeActionManager {
        &mut self.action_manager
    }

    // ------------------------------------------------------------------
    // Tree queries
    // ------------------------------------------------------------------

    /// Returns the effective view address set for the current tree.
    pub fn get_view_address_set(&self) -> AddressSet {
        self.current_provider()
            .map(|p| p.view_address_set().clone())
            .unwrap_or_default()
    }

    /// Returns the tree with the given name.
    pub fn get_tree(&self, tree_name: &str) -> Option<&ProgramTree> {
        self.provider_map
            .get(tree_name)
            .map(|p| p.tree())
    }

    // ------------------------------------------------------------------
    // Persistence
    // ------------------------------------------------------------------

    /// Serialize the plugin state.
    pub fn save_state(&self) -> PluginState {
        let views: Vec<(String, ViewState)> = self
            .provider_map
            .iter()
            .map(|(name, provider)| (name.clone(), provider.save_state()))
            .collect();

        PluginState {
            views,
            current_tree_name: self.current_tree_name.clone(),
            is_replace_view_mode: self.is_replace_view_mode,
        }
    }

    /// Restore the plugin state.
    pub fn restore_state(&mut self, state: &PluginState) {
        self.provider_map.clear();
        for (name, view_state) in &state.views {
            let mut provider = TreeViewProvider::new(name);
            provider.restore_state(view_state);
            self.provider_map.insert(name.clone(), provider);
        }
        self.current_tree_name = state.current_tree_name.clone();
        self.is_replace_view_mode = state.is_replace_view_mode;
    }
}

impl Default for ProgramTreePlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Serializable plugin state for persistence.
#[derive(Debug, Clone, Default)]
pub struct PluginState {
    /// View states indexed by tree name.
    pub views: Vec<(String, ViewState)>,
    /// The currently active tree name.
    pub current_tree_name: Option<String>,
    /// Whether replace-view mode is active.
    pub is_replace_view_mode: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = ProgramTreePlugin::new();
        assert_eq!(plugin.view_count(), 1);
        assert_eq!(plugin.viewed_tree_name(), Some(DEFAULT_TREE_NAME));
        assert!(!plugin.is_replace_view_mode());
    }

    #[test]
    fn test_add_tree_view() {
        let mut plugin = ProgramTreePlugin::new();
        assert!(plugin.add_tree_view("Functions"));
        assert_eq!(plugin.view_count(), 2);
        assert!(!plugin.add_tree_view("Functions")); // duplicate
    }

    #[test]
    fn test_close_view() {
        let mut plugin = ProgramTreePlugin::new();
        plugin.add_tree_view("Functions");

        assert!(plugin.close_view("Functions"));
        assert_eq!(plugin.view_count(), 1);
        assert_eq!(plugin.viewed_tree_name(), Some(DEFAULT_TREE_NAME));
    }

    #[test]
    fn test_cannot_close_last_view() {
        let mut plugin = ProgramTreePlugin::new();
        assert!(!plugin.close_view(DEFAULT_TREE_NAME));
        assert_eq!(plugin.view_count(), 1);
    }

    #[test]
    fn test_rename_view() {
        let mut plugin = ProgramTreePlugin::new();
        plugin.rename_view(DEFAULT_TREE_NAME, "My Tree").unwrap();
        assert_eq!(plugin.viewed_tree_name(), Some("My Tree"));
    }

    #[test]
    fn test_rename_to_existing() {
        let mut plugin = ProgramTreePlugin::new();
        plugin.add_tree_view("Functions");
        assert!(plugin.rename_view(DEFAULT_TREE_NAME, "Functions").is_err());
    }

    #[test]
    fn test_set_viewed_tree() {
        let mut plugin = ProgramTreePlugin::new();
        plugin.add_tree_view("Functions");
        plugin.set_viewed_tree("Functions");
        assert_eq!(plugin.viewed_tree_name(), Some("Functions"));

        let events = plugin.drain_events();
        assert!(events.iter().any(|e| matches!(e, ProgramTreeEvent::TreeActivated(n) if n == "Functions")));
    }

    #[test]
    fn test_program_lifecycle() {
        let mut plugin = ProgramTreePlugin::new();
        let tree_names = vec!["Tree1".into(), "Tree2".into()];
        plugin.program_activated(&tree_names);

        assert_eq!(plugin.view_count(), 2);
        assert_eq!(plugin.viewed_tree_name(), Some("Tree1"));

        plugin.program_deactivated();
        // Plugin still has the tree views
        assert_eq!(plugin.view_count(), 2);
    }

    #[test]
    fn test_program_activated_empty() {
        let mut plugin = ProgramTreePlugin::new();
        plugin.program_activated(&[]);

        assert_eq!(plugin.view_count(), 1);
        assert_eq!(plugin.viewed_tree_name(), Some(DEFAULT_TREE_NAME));
    }

    #[test]
    fn test_save_restore_state() {
        let mut plugin = ProgramTreePlugin::new();
        plugin.add_tree_view("Functions");
        plugin.set_replace_view_mode(true);

        let state = plugin.save_state();
        assert!(state.is_replace_view_mode);
        assert_eq!(state.views.len(), 2);

        let mut plugin2 = ProgramTreePlugin::new();
        plugin2.restore_state(&state);
        assert_eq!(plugin2.view_count(), 2);
        assert!(plugin2.is_replace_view_mode());
    }

    #[test]
    fn test_events() {
        let mut plugin = ProgramTreePlugin::new();
        plugin.add_tree_view("Functions");
        let events = plugin.drain_events();
        assert!(events
            .iter()
            .any(|e| matches!(e, ProgramTreeEvent::TreeCreated(n) if n == "Functions")));
        assert!(plugin.drain_events().is_empty());
    }

    #[test]
    fn test_selection_event() {
        let mut plugin = ProgramTreePlugin::new();
        plugin.add_tree_view("Functions");

        let path = GroupPath::new(vec!["Functions".into(), "my_func".into()]);
        plugin.process_selection_event("Functions", vec![path.clone()]);

        let provider = plugin.get_provider("Functions").unwrap();
        assert_eq!(provider.tree().selected_paths(), &[path]);
    }
}
