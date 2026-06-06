//! Composite editor action manager.
//!
//! Ported from `ghidra.app.plugin.core.compositeeditor.CompositeEditorActionManager`.
//!
//! Manages the actions for a single composite editor. Provides default
//! favorites and cycle group actions, and allows other actions to be added.

use super::actions_impl::CompositeActionType;

/// A composite editor table action with name, type, and enabled state.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.CompositeEditorTableAction`.
#[derive(Debug, Clone)]
pub struct CompositeEditorTableAction {
    /// The action name (unique identifier).
    pub name: String,
    /// The action type.
    pub action_type: CompositeActionType,
    /// Whether the action is currently enabled.
    pub enabled: bool,
    /// The menu group for the action.
    pub menu_group: String,
    /// Key binding (if any).
    pub key_binding: Option<String>,
    /// Description text.
    pub description: String,
}

impl CompositeEditorTableAction {
    /// Create a new composite editor action.
    pub fn new(name: impl Into<String>, action_type: CompositeActionType) -> Self {
        let name_str = name.into();
        let description = action_type.display_name().to_string();
        Self {
            name: name_str,
            action_type,
            enabled: true,
            menu_group: String::new(),
            key_binding: None,
            description,
        }
    }

    /// Get the action name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Whether the action is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the action.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

/// A favorite data type action for the composite editor.
#[derive(Debug, Clone)]
pub struct FavoritesAction {
    /// The data type name.
    pub data_type_name: String,
    /// Whether enabled.
    pub enabled: bool,
}

impl FavoritesAction {
    /// Create a new favorites action.
    pub fn new(data_type_name: impl Into<String>) -> Self {
        Self {
            data_type_name: data_type_name.into(),
            enabled: true,
        }
    }
}

/// A cycle group action for the composite editor.
#[derive(Debug, Clone)]
pub struct CycleGroupAction {
    /// The cycle group name.
    pub group_name: String,
    /// Data type names in the cycle group.
    pub types: Vec<String>,
    /// Whether enabled.
    pub enabled: bool,
    /// Current index in the cycle.
    pub current_index: usize,
}

impl CycleGroupAction {
    /// Create a new cycle group action.
    pub fn new(group_name: impl Into<String>, types: Vec<String>) -> Self {
        Self {
            group_name: group_name.into(),
            types,
            enabled: true,
            current_index: 0,
        }
    }

    /// Get the current data type name in the cycle.
    pub fn current_type(&self) -> Option<&str> {
        self.types.get(self.current_index).map(|s| s.as_str())
    }

    /// Advance to the next type in the cycle.
    pub fn advance(&mut self) {
        if !self.types.is_empty() {
            self.current_index = (self.current_index + 1) % self.types.len();
        }
    }
}

/// Listener for editor action add/remove events.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.EditorActionListener`.
pub trait EditorActionListener: std::fmt::Debug {
    /// Called when actions are added to the manager.
    fn actions_added(&self, actions: &[CompositeEditorTableAction]);
    /// Called when actions are removed from the manager.
    fn actions_removed(&self, actions: &[CompositeEditorTableAction]);
}

/// A no-op editor action listener.
#[derive(Debug, Default)]
pub struct NoOpEditorActionListener;

impl EditorActionListener for NoOpEditorActionListener {
    fn actions_added(&self, _actions: &[CompositeEditorTableAction]) {}
    fn actions_removed(&self, _actions: &[CompositeEditorTableAction]) {}
}

/// Manages the actions for a single composite editor.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.CompositeEditorActionManager`.
///
/// By default provides actions for favorites and cycle groups. Other
/// `CompositeEditorTableAction`s can be added for it to manage.
#[derive(Debug)]
pub struct CompositeEditorActionManager {
    /// Custom editor actions.
    editor_actions: Vec<CompositeEditorTableAction>,
    /// Favorites actions.
    favorites_actions: Vec<CompositeEditorTableAction>,
    /// Cycle group actions.
    cycle_group_actions: Vec<CompositeEditorTableAction>,
    /// Listeners.
    listeners: Vec<Box<dyn EditorActionListener>>,
}

impl CompositeEditorActionManager {
    /// Create a new action manager.
    pub fn new() -> Self {
        Self {
            editor_actions: Vec::new(),
            favorites_actions: Vec::new(),
            cycle_group_actions: Vec::new(),
            listeners: Vec::new(),
        }
    }

    /// Add a listener for action add/remove events.
    pub fn add_listener(&mut self, listener: Box<dyn EditorActionListener>) {
        self.listeners.push(listener);
    }

    /// Remove all listeners.
    pub fn clear_listeners(&mut self) {
        self.listeners.clear();
    }

    /// Set the editor actions (replaces any existing editor actions).
    pub fn set_editor_actions(&mut self, actions: Vec<CompositeEditorTableAction>) {
        self.editor_actions = actions;
    }

    /// Add a single editor action.
    pub fn add_editor_action(&mut self, action: CompositeEditorTableAction) {
        self.editor_actions.push(action);
    }

    /// Get the editor actions.
    pub fn editor_actions(&self) -> &[CompositeEditorTableAction] {
        &self.editor_actions
    }

    /// Get the favorites actions.
    pub fn favorites_actions(&self) -> &[CompositeEditorTableAction] {
        &self.favorites_actions
    }

    /// Get the cycle group actions.
    pub fn cycle_group_actions(&self) -> &[CompositeEditorTableAction] {
        &self.cycle_group_actions
    }

    /// Get all actions (editor + favorites + cycle groups).
    pub fn all_actions(&self) -> Vec<&CompositeEditorTableAction> {
        self.editor_actions
            .iter()
            .chain(self.favorites_actions.iter())
            .chain(self.cycle_group_actions.iter())
            .collect()
    }

    /// Get total action count.
    pub fn action_count(&self) -> usize {
        self.editor_actions.len() + self.favorites_actions.len() + self.cycle_group_actions.len()
    }

    /// Find an action by name.
    pub fn find_action(&self, name: &str) -> Option<&CompositeEditorTableAction> {
        self.editor_actions
            .iter()
            .chain(self.favorites_actions.iter())
            .chain(self.cycle_group_actions.iter())
            .find(|a| a.name == name)
    }

    /// Set the favorites actions.
    pub fn set_favorites_actions(&mut self, actions: Vec<CompositeEditorTableAction>) {
        self.favorites_actions = actions;
    }

    /// Set the cycle group actions.
    pub fn set_cycle_group_actions(&mut self, actions: Vec<CompositeEditorTableAction>) {
        self.cycle_group_actions = actions;
    }

    /// Dispose of the action manager (clear all actions and listeners).
    pub fn dispose(&mut self) {
        self.editor_actions.clear();
        self.favorites_actions.clear();
        self.cycle_group_actions.clear();
        self.listeners.clear();
    }
}

impl Default for CompositeEditorActionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_manager_creation() {
        let mgr = CompositeEditorActionManager::new();
        assert_eq!(mgr.action_count(), 0);
        assert!(mgr.all_actions().is_empty());
    }

    #[test]
    fn test_action_manager_set_editor_actions() {
        let mut mgr = CompositeEditorActionManager::new();
        let actions = vec![
            CompositeEditorTableAction::new("Apply", CompositeActionType::Apply),
            CompositeEditorTableAction::new("Delete", CompositeActionType::Delete),
        ];
        mgr.set_editor_actions(actions);
        assert_eq!(mgr.action_count(), 2);
        assert_eq!(mgr.editor_actions().len(), 2);
    }

    #[test]
    fn test_action_manager_find_action() {
        let mut mgr = CompositeEditorActionManager::new();
        mgr.add_editor_action(CompositeEditorTableAction::new("Apply", CompositeActionType::Apply));
        mgr.add_editor_action(CompositeEditorTableAction::new("Delete", CompositeActionType::Delete));

        let action = mgr.find_action("Apply");
        assert!(action.is_some());
        assert_eq!(action.unwrap().action_type, CompositeActionType::Apply);

        assert!(mgr.find_action("Missing").is_none());
    }

    #[test]
    fn test_action_manager_all_actions() {
        let mut mgr = CompositeEditorActionManager::new();
        mgr.add_editor_action(CompositeEditorTableAction::new("E1", CompositeActionType::Apply));

        let fav = CompositeEditorTableAction::new("F1", CompositeActionType::Favorite);
        mgr.set_favorites_actions(vec![fav]);

        let cycle = CompositeEditorTableAction::new("C1", CompositeActionType::ReplaceDataType);
        mgr.set_cycle_group_actions(vec![cycle]);

        assert_eq!(mgr.action_count(), 3);
        assert_eq!(mgr.all_actions().len(), 3);
    }

    #[test]
    fn test_action_manager_dispose() {
        let mut mgr = CompositeEditorActionManager::new();
        mgr.add_editor_action(CompositeEditorTableAction::new("Test", CompositeActionType::Apply));
        assert_eq!(mgr.action_count(), 1);

        mgr.dispose();
        assert_eq!(mgr.action_count(), 0);
    }

    #[test]
    fn test_composite_editor_table_action() {
        let action = CompositeEditorTableAction::new("Apply", CompositeActionType::Apply);
        assert_eq!(action.get_name(), "Apply");
        assert!(action.is_enabled());

        let mut action = action;
        action.set_enabled(false);
        assert!(!action.is_enabled());
    }

    #[test]
    fn test_favorites_action() {
        let action = FavoritesAction::new("int");
        assert_eq!(action.data_type_name, "int");
        assert!(action.enabled);
    }

    #[test]
    fn test_cycle_group_action() {
        let mut cycle = CycleGroupAction::new("Integer", vec![
            "byte".into(), "short".into(), "int".into(), "long".into(),
        ]);
        assert_eq!(cycle.current_type(), Some("byte"));
        cycle.advance();
        assert_eq!(cycle.current_type(), Some("short"));
        cycle.advance();
        cycle.advance();
        cycle.advance();
        assert_eq!(cycle.current_type(), Some("byte")); // wraps around
    }

    #[test]
    fn test_cycle_group_empty() {
        let mut cycle = CycleGroupAction::new("Empty", vec![]);
        assert!(cycle.current_type().is_none());
        cycle.advance(); // should not panic
    }
}
