//! The top-level docking tool abstraction.
//!
//! A [`DockingTool`] represents a Ghidra-style tool window.  It owns the
//! layout, the action registry, and the plugin manager, and ties them all
//! together.

use super::action::{find_action, find_action_mut, DockingAction, Key, Modifiers};
use super::component::{ComponentMap, ComponentProvider};
use super::layout::DockingLayout;
use super::plugin::{Plugin, PluginError, PluginManager};

// ---------------------------------------------------------------------------
// DockingTool
// ---------------------------------------------------------------------------

/// The top-level tool state.
///
/// A tool is the container for a project, a program under analysis, the
/// current docking layout, registered actions, and loaded plugins.
pub struct DockingTool {
    /// The currently-open project name, if any.
    pub active_project: Option<String>,
    /// The currently-open program name / path, if any.
    pub active_program: Option<String>,
    /// The persisted (or default) docking layout.
    pub layout: DockingLayout,
    /// All registered actions (global + contextual + toggles + menus).
    pub actions: Vec<DockingAction>,
    /// The plugin manager handles plugin lifecycle.
    pub plugin_manager: PluginManager,
    /// Active dockable components, keyed by (provider, name).
    pub components: ComponentMap,
}

impl DockingTool {
    /// Create a new tool with a default layout and an empty plugin manager.
    pub fn new() -> Self {
        Self {
            active_project: None,
            active_program: None,
            layout: DockingLayout::default_layout(),
            actions: Vec::new(),
            plugin_manager: PluginManager::default(),
            components: ComponentMap::new(),
        }
    }

    /// Create a tool with a specific layout.
    pub fn with_layout(layout: DockingLayout) -> Self {
        Self {
            layout,
            ..Self::new()
        }
    }

    // ---------------------------------------------------------------
    // Project / program
    // ---------------------------------------------------------------

    /// Set the active project.
    pub fn set_project(&mut self, project: impl Into<String>) {
        self.active_project = Some(project.into());
    }

    /// Clear the active project.
    pub fn clear_project(&mut self) {
        self.active_project = None;
        self.active_program = None;
    }

    /// Set the active program (will also set the project to `Some` if it
    /// is currently `None`).
    pub fn set_program(&mut self, program: impl Into<String>) {
        self.active_program = Some(program.into());
        if self.active_project.is_none() {
            self.active_project = Some("<unknown>".to_owned());
        }
    }

    /// Clear the active program (leaves the project set).
    pub fn clear_program(&mut self) {
        self.active_program = None;
    }

    // ---------------------------------------------------------------
    // Action management
    // ---------------------------------------------------------------

    /// Register a top-level action.
    pub fn add_action(&mut self, action: DockingAction) {
        self.actions.push(action);
    }

    /// Register multiple actions at once.
    pub fn add_actions(&mut self, actions: Vec<DockingAction>) {
        self.actions.extend(actions);
    }

    /// Remove an action by name (searches recursively through menus).
    pub fn remove_action(&mut self, name: &str) -> Option<DockingAction> {
        let pos = self.actions.iter().position(|a| a.name == name);
        if let Some(idx) = pos {
            Some(self.actions.remove(idx))
        } else {
            // Try sub-menus.
            for action in self.actions.iter_mut() {
                if let Some(items) = action.children_mut() {
                    if let Some(pos) = items.iter().position(|a| a.name == name) {
                        return Some(items.remove(pos));
                    }
                }
            }
            None
        }
    }

    /// Find an action by name (recursively).
    pub fn find_action(&self, name: &str) -> Option<&DockingAction> {
        find_action(&self.actions, name)
    }

    /// Find a mutable action by name (recursively).
    pub fn find_action_mut(&mut self, name: &str) -> Option<&mut DockingAction> {
        find_action_mut(&mut self.actions, name)
    }

    /// Collect all actions — built-in plus those from loaded plugins.
    pub fn all_actions(&self) -> Vec<DockingAction> {
        let mut all: Vec<DockingAction> = self.actions.clone();
        all.extend(self.plugin_manager.collect_actions());
        all
    }

    /// Find the first action that matches the given key chord.
    pub fn action_for_key(&self, modifiers: &Modifiers, key: &Key) -> Option<&DockingAction> {
        // Search built-in actions first.
        for action in super::action::flatten_actions(&self.actions) {
            if action.matches_key(modifiers, key) && action.enabled {
                return Some(action);
            }
        }
        None
    }

    /// Enable or disable an action by name.
    pub fn set_action_enabled(&mut self, name: &str, enabled: bool) -> bool {
        if let Some(action) = self.find_action_mut(name) {
            action.enabled = enabled;
            true
        } else {
            false
        }
    }

    // ---------------------------------------------------------------
    // Plugin management (convenience wrappers)
    // ---------------------------------------------------------------

    /// Load a plugin.  The plugin will be initialised with this tool.
    pub fn add_plugin(&mut self, plugin: Box<dyn Plugin>) -> Result<(), PluginError> {
        let plugin_actions = plugin.get_actions();
        let providers = plugin.get_components();

        // Temporarily swap out the plugin_manager so we can pass `self`
        // to `load` without a double-mutable-borrow conflict.
        let mut pm = std::mem::take(&mut self.plugin_manager);
        let result = pm.load(plugin, self);
        self.plugin_manager = pm;
        result?;

        // Register the plugin's actions and provider windows.
        self.actions.extend(plugin_actions);
        for provider in providers {
            if !self.layout.windows.contains_key(&provider) {
                self.layout.add_window(
                    provider,
                    super::layout::DockingWindowPlacement::docked(
                        super::component::WindowPosition::Center,
                    ),
                );
            }
        }

        Ok(())
    }

    /// Remove a loaded plugin by name.
    pub fn remove_plugin(&mut self, name: &str) -> Result<(), PluginError> {
        self.plugin_manager.unload(name)?;

        // Remove actions contributed by this plugin.
        // (A real implementation would tag actions with their source
        // plugin; here we do a best-effort cleanup.)
        self.actions.retain(|a| {
            // Keep actions that don't look like they came from the plugin.
            !a.name.starts_with(&format!("{}.", name))
        });

        Ok(())
    }

    // ---------------------------------------------------------------
    // Component management
    // ---------------------------------------------------------------

    /// Register a docking component.
    pub fn add_component(&mut self, component: Box<dyn super::component::DockingComponent>) {
        let key = component.instance_key();
        // Register actions from the component.
        self.actions.extend(component.get_actions());
        // Make sure the layout entry exists.
        let provider = component.get_component_provider();
        if !self.layout.windows.contains_key(&provider) {
            self.layout.add_window(
                provider,
                super::layout::DockingWindowPlacement::docked(
                    super::component::WindowPosition::Center,
                ),
            );
        }
        self.components.insert(key, component);
    }

    /// Remove a docking component by its provider and name.
    pub fn remove_component(
        &mut self,
        provider: ComponentProvider,
        name: &str,
    ) -> Option<Box<dyn super::component::DockingComponent>> {
        self.components.remove(&(provider, name.to_owned()))
    }

    /// Get a reference to a docking component.
    pub fn get_component(
        &self,
        provider: ComponentProvider,
        name: &str,
    ) -> Option<&dyn super::component::DockingComponent> {
        self.components
            .get(&(provider, name.to_owned()))
            .map(|c| c.as_ref())
    }

    /// Get a mutable reference to a docking component.
    pub fn get_component_mut(
        &mut self,
        provider: ComponentProvider,
        name: &str,
    ) -> Option<&mut (dyn super::component::DockingComponent + '_)> {
        match self.components.get_mut(&(provider, name.to_owned())) {
            Some(b) => Some(b.as_mut()),
            None => None,
        }
    }

    /// Toggle visibility of a provider window.
    pub fn toggle_provider(&mut self, provider: ComponentProvider) {
        self.layout.toggle(provider);
    }

    /// Return all visible components (respecting layout visibility).
    pub fn visible_components(&self) -> Vec<&dyn super::component::DockingComponent> {
        self.components
            .iter()
            .filter(|((provider, _name), comp)| {
                comp.is_visible()
                    && self
                        .layout
                        .get_window(provider)
                        .map(|p| p.visible)
                        .unwrap_or(true)
            })
            .map(|(_, comp)| comp.as_ref())
            .collect()
    }

    // ---------------------------------------------------------------
    // Layout
    // ---------------------------------------------------------------

    /// Serialize the current tool state (layout).
    pub fn save_layout(&self) -> String {
        self.layout.save()
    }

    /// Restore the layout from a serialized string.
    pub fn load_layout(&mut self, data: &str) -> Result<(), anyhow::Error> {
        self.layout = DockingLayout::load(data)?;
        Ok(())
    }

    /// Reset to the default Ghidra-style layout.
    pub fn reset_layout(&mut self) {
        self.layout.reset_to_default();
    }
}

impl Default for DockingTool {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::action::KeyBinding;
    use super::super::component::SimpleComponent;
    use super::*;

    #[test]
    fn test_new_tool() {
        let tool = DockingTool::new();
        assert!(tool.active_project.is_none());
        assert!(tool.active_program.is_none());
        assert!(tool.actions.is_empty());
        assert!(tool.plugin_manager.is_empty());
    }

    #[test]
    fn test_project_program() {
        let mut tool = DockingTool::new();

        tool.set_project("my-project");
        assert_eq!(tool.active_project.as_deref(), Some("my-project"));

        tool.set_program("hello.elf");
        assert_eq!(tool.active_program.as_deref(), Some("hello.elf"));

        tool.clear_program();
        assert!(tool.active_program.is_none());
        assert_eq!(tool.active_project.as_deref(), Some("my-project"));

        tool.clear_project();
        assert!(tool.active_project.is_none());
    }

    #[test]
    fn test_set_program_sets_default_project() {
        let mut tool = DockingTool::new();
        tool.set_program("a.out");
        assert_eq!(tool.active_project.as_deref(), Some("<unknown>"));
        assert_eq!(tool.active_program.as_deref(), Some("a.out"));
    }

    #[test]
    fn test_add_and_find_action() {
        let mut tool = DockingTool::new();
        let action = DockingAction::new("my-action", "My Action")
            .with_key_binding(KeyBinding::ctrl(super::super::action::Key::S));
        tool.add_action(action);

        assert!(tool.find_action("my-action").is_some());
        assert!(tool.find_action("nonexistent").is_none());
    }

    #[test]
    fn test_action_for_key() {
        let mut tool = DockingTool::new();
        let action = DockingAction::new("save", "Save")
            .with_key_binding(KeyBinding::ctrl(super::super::action::Key::S));
        tool.add_action(action);

        let modifiers = super::super::action::Modifiers::CTRL;
        let found = tool.action_for_key(&modifiers, &super::super::action::Key::S);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "save");

        // Wrong modifier should not match.
        let alt = super::super::action::Modifiers::ALT;
        assert!(tool
            .action_for_key(&alt, &super::super::action::Key::S)
            .is_none());
    }

    #[test]
    fn test_set_action_enabled() {
        let mut tool = DockingTool::new();
        tool.add_action(DockingAction::new("toggle-me", "Toggle Me"));
        assert!(tool.find_action("toggle-me").unwrap().enabled);

        assert!(tool.set_action_enabled("toggle-me", false));
        assert!(!tool.find_action("toggle-me").unwrap().enabled);

        assert!(!tool.set_action_enabled("ghost", true));
    }

    #[test]
    fn test_remove_action() {
        let mut tool = DockingTool::new();
        tool.add_action(DockingAction::new("keep", "Keep"));
        tool.add_action(DockingAction::new("remove", "Remove"));

        assert_eq!(tool.actions.len(), 2);
        let removed = tool.remove_action("remove");
        assert!(removed.is_some());
        assert_eq!(tool.actions.len(), 1);
        assert!(tool.find_action("remove").is_none());
        assert!(tool.find_action("keep").is_some());
    }

    #[test]
    fn test_add_remove_component() {
        let mut tool = DockingTool::new();
        let comp = SimpleComponent::new(ComponentProvider::Console, "Python", "python");

        tool.add_component(Box::new(comp));

        assert!(tool
            .get_component(ComponentProvider::Console, "python")
            .is_some());

        let removed = tool.remove_component(ComponentProvider::Console, "python");
        assert!(removed.is_some());
        assert!(tool
            .get_component(ComponentProvider::Console, "python")
            .is_none());
    }

    #[test]
    fn test_toggle_provider() {
        let mut tool = DockingTool::new();
        // Console is in the default layout.
        let before = tool
            .layout
            .get_window(&ComponentProvider::Console)
            .unwrap()
            .visible;
        tool.toggle_provider(ComponentProvider::Console);
        let after = tool
            .layout
            .get_window(&ComponentProvider::Console)
            .unwrap()
            .visible;
        assert_ne!(before, after);
    }

    #[test]
    fn test_layout_roundtrip() {
        let mut tool = DockingTool::new();
        tool.layout.set_position(
            ComponentProvider::ListingView,
            super::super::component::WindowPosition::Left,
        );

        let saved = tool.save_layout();
        assert!(!saved.is_empty());

        let mut tool2 = DockingTool::new();
        tool2.load_layout(&saved).unwrap();
        assert_eq!(
            tool2
                .layout
                .get_window(&ComponentProvider::ListingView)
                .unwrap()
                .position,
            super::super::component::WindowPosition::Left,
        );
    }

    #[test]
    fn test_reset_layout() {
        let mut tool = DockingTool::new();
        // Remove a window so it differs from default.
        tool.layout.remove_window(&ComponentProvider::Console);
        assert!(tool
            .layout
            .get_window(&ComponentProvider::Console)
            .is_none());

        tool.reset_layout();
        assert!(tool
            .layout
            .get_window(&ComponentProvider::Console)
            .is_some());
    }
}
