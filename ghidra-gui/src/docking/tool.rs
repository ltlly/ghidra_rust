//! The top-level docking tool abstraction.
//!
//! A [`DockingTool`] represents a Ghidra-style tool window.  It owns the
//! layout, the action registry, the plugin manager, and the event system,
//! and ties them all together.

use std::collections::HashMap;
use std::sync::Arc;

use super::action::{
    find_action, find_action_mut, ActionContextInfo, DockingAction, GuiActionManager, Key,
    Modifiers,
};
use super::component::{ComponentMap, ComponentProvider};
use super::layout::DockingLayout;
use super::plugin::{Plugin, PluginError, PluginManager};

// ---------------------------------------------------------------------------
// ToolEvent — events emitted by the tool
// ---------------------------------------------------------------------------

/// Events that a tool can emit to notify interested observers.
///
/// In Ghidra, the tool fires `ToolEvent` instances through a `Service`
/// when significant state changes occur.  This enum models the most
/// common events.
#[derive(Debug, Clone)]
pub enum ToolEvent {
    /// The active program changed.
    ProgramActivated {
        program_name: String,
    },
    /// The active program was closed.
    ProgramClosed {
        program_name: String,
    },
    /// The active project changed.
    ProjectChanged {
        project_name: Option<String>,
    },
    /// A component was added to the tool.
    ComponentAdded {
        provider: ComponentProvider,
        name: String,
    },
    /// A component was removed from the tool.
    ComponentRemoved {
        provider: ComponentProvider,
        name: String,
    },
    /// A component gained focus.
    ComponentFocused {
        provider: ComponentProvider,
        name: String,
    },
    /// The layout was changed (e.g. window moved, split ratio changed).
    LayoutChanged,
    /// The layout was loaded from a saved state.
    LayoutLoaded,
    /// A plugin was loaded.
    PluginLoaded {
        plugin_name: String,
    },
    /// A plugin was unloaded.
    PluginUnloaded {
        plugin_name: String,
    },
    /// An action was triggered.
    ActionTriggered {
        action_name: String,
        context: ActionContextInfo,
    },
    /// A custom tool event (for extensibility).
    Custom {
        event_type: String,
        data: HashMap<String, String>,
    },
}

/// A callback that receives tool events.
pub type ToolEventCallback = Arc<dyn Fn(&ToolEvent) + Send + Sync>;

// ---------------------------------------------------------------------------
// ToolService — service interface for inter-component communication
// ---------------------------------------------------------------------------

/// A named service provided by the tool.
///
/// In Ghidra, plugins communicate through services (interfaces) that
/// the tool brokers.  A plugin can `addService(MyTrait)`, and another
/// can `getService(MyTrait)` without a direct dependency.
#[derive(Debug)]
pub struct ToolService {
    /// Service name (typically the trait or interface name).
    pub name: String,
    /// Opaque service data (type-erased).
    pub data: String,
}

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
    /// The action manager provides undo/redo and centralized dispatch.
    pub action_manager: GuiActionManager,
    /// The plugin manager handles plugin lifecycle.
    pub plugin_manager: PluginManager,
    /// Active dockable components, keyed by (provider, name).
    pub components: ComponentMap,
    /// Registered event listeners.
    event_listeners: Vec<ToolEventCallback>,
    /// Named services provided by the tool.
    services: HashMap<String, ToolService>,
    /// The component that currently has focus, if any.
    focused_component: Option<(ComponentProvider, String)>,
    /// Tool-wide properties (arbitrary key-value settings).
    properties: HashMap<String, String>,
}

impl DockingTool {
    /// Create a new tool with a default layout and an empty plugin manager.
    pub fn new() -> Self {
        Self {
            active_project: None,
            active_program: None,
            layout: DockingLayout::default_layout(),
            actions: Vec::new(),
            action_manager: GuiActionManager::new(),
            plugin_manager: PluginManager::default(),
            components: ComponentMap::new(),
            event_listeners: Vec::new(),
            services: HashMap::new(),
            focused_component: None,
            properties: HashMap::new(),
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
        let name = project.into();
        self.active_project = Some(name.clone());
        self.emit_event(&ToolEvent::ProjectChanged {
            project_name: Some(name),
        });
    }

    /// Clear the active project.
    pub fn clear_project(&mut self) {
        self.active_project = None;
        let old = self.active_program.take();
        if let Some(prog) = old {
            self.emit_event(&ToolEvent::ProgramClosed {
                program_name: prog,
            });
        }
        self.emit_event(&ToolEvent::ProjectChanged {
            project_name: None,
        });
    }

    /// Set the active program (will also set the project to `Some` if it
    /// is currently `None`).
    pub fn set_program(&mut self, program: impl Into<String>) {
        let name = program.into();
        self.active_program = Some(name.clone());
        if self.active_project.is_none() {
            self.active_project = Some("<unknown>".to_owned());
        }
        self.emit_event(&ToolEvent::ProgramActivated {
            program_name: name,
        });
    }

    /// Clear the active program (leaves the project set).
    pub fn clear_program(&mut self) {
        if let Some(prog) = self.active_program.take() {
            self.emit_event(&ToolEvent::ProgramClosed {
                program_name: prog,
            });
        }
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
        let name = key.1.clone();
        self.components.insert(key, component);
        self.emit_event(&ToolEvent::ComponentAdded {
            provider,
            name,
        });
    }

    /// Remove a docking component by its provider and name.
    pub fn remove_component(
        &mut self,
        provider: ComponentProvider,
        name: &str,
    ) -> Option<Box<dyn super::component::DockingComponent>> {
        let result = self.components.remove(&(provider, name.to_owned()));
        if result.is_some() {
            self.emit_event(&ToolEvent::ComponentRemoved {
                provider,
                name: name.to_owned(),
            });
        }
        result
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
        self.emit_event(&ToolEvent::LayoutChanged);
    }

    // ---------------------------------------------------------------
    // Event system
    // ---------------------------------------------------------------

    /// Register an event listener.
    pub fn add_event_listener(&mut self, callback: ToolEventCallback) {
        self.event_listeners.push(callback);
    }

    /// Emit an event to all registered listeners.
    fn emit_event(&self, event: &ToolEvent) {
        for listener in &self.event_listeners {
            listener(event);
        }
    }

    /// Number of registered event listeners.
    pub fn event_listener_count(&self) -> usize {
        self.event_listeners.len()
    }

    /// Clear all event listeners.
    pub fn clear_event_listeners(&mut self) {
        self.event_listeners.clear();
    }

    // ---------------------------------------------------------------
    // Action manager integration
    // ---------------------------------------------------------------

    /// Register an action in both the tool's action list and the action
    /// manager (for undo/redo support).
    pub fn register_action(&mut self, action: DockingAction) {
        self.action_manager.register(action.clone());
        self.actions.push(action);
    }

    /// Trigger an action with context through the action manager.
    pub fn trigger_action(&self, name: &str, ctx: &ActionContextInfo) -> bool {
        let triggered = self.action_manager.trigger_with_context(name, ctx);
        if triggered {
            self.emit_event(&ToolEvent::ActionTriggered {
                action_name: name.to_owned(),
                context: ctx.clone(),
            });
        }
        triggered
    }

    /// Perform undo via the action manager.
    pub fn undo(&mut self) -> Option<String> {
        self.action_manager.undo()
    }

    /// Perform redo via the action manager.
    pub fn redo(&mut self) -> Option<String> {
        self.action_manager.redo()
    }

    /// Whether undo is available.
    pub fn can_undo(&self) -> bool {
        self.action_manager.can_undo()
    }

    /// Whether redo is available.
    pub fn can_redo(&self) -> bool {
        self.action_manager.can_redo()
    }

    // ---------------------------------------------------------------
    // Focus management
    // ---------------------------------------------------------------

    /// Set focus to a specific component.
    pub fn set_focus(&mut self, provider: ComponentProvider, name: impl Into<String>) {
        let name = name.into();
        self.focused_component = Some((provider, name.clone()));
        self.emit_event(&ToolEvent::ComponentFocused {
            provider,
            name,
        });
    }

    /// Get the currently focused component, if any.
    pub fn get_focused(&self) -> Option<&(ComponentProvider, String)> {
        self.focused_component.as_ref()
    }

    /// Clear focus (no component focused).
    pub fn clear_focus(&mut self) {
        self.focused_component = None;
    }

    // ---------------------------------------------------------------
    // Service registry
    // ---------------------------------------------------------------

    /// Register a service with the tool.
    pub fn add_service(&mut self, name: impl Into<String>, data: impl Into<String>) {
        let name = name.into();
        self.services.insert(
            name.clone(),
            ToolService {
                name,
                data: data.into(),
            },
        );
    }

    /// Get a service by name.
    pub fn get_service(&self, name: &str) -> Option<&ToolService> {
        self.services.get(name)
    }

    /// Remove a service by name.
    pub fn remove_service(&mut self, name: &str) -> Option<ToolService> {
        self.services.remove(name)
    }

    /// All registered service names.
    pub fn service_names(&self) -> Vec<&str> {
        self.services.keys().map(|k| k.as_str()).collect()
    }

    // ---------------------------------------------------------------
    // Tool properties
    // ---------------------------------------------------------------

    /// Set a tool-wide property.
    pub fn set_property(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.properties.insert(key.into(), value.into());
    }

    /// Get a tool-wide property.
    pub fn get_property(&self, key: &str) -> Option<&str> {
        self.properties.get(key).map(|v| v.as_str())
    }

    /// Remove a tool-wide property.
    pub fn remove_property(&mut self, key: &str) -> Option<String> {
        self.properties.remove(key)
    }

    /// Get all properties.
    pub fn properties(&self) -> &HashMap<String, String> {
        &self.properties
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

    // --- New: event system tests ---

    #[test]
    fn test_event_listener() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let count = Arc::new(AtomicU32::new(0));
        let count2 = count.clone();

        let mut tool = DockingTool::new();
        tool.add_event_listener(Arc::new(move |_event| {
            count2.fetch_add(1, Ordering::SeqCst);
        }));

        assert_eq!(tool.event_listener_count(), 1);

        tool.set_project("test-project");
        assert_eq!(count.load(Ordering::SeqCst), 1);

        tool.set_program("test.exe");
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_event_program_lifecycle() {
        use std::sync::Mutex;

        let events = Arc::new(Mutex::new(Vec::<String>::new()));
        let events2 = events.clone();

        let mut tool = DockingTool::new();
        tool.add_event_listener(Arc::new(move |event| {
            let name = match event {
                ToolEvent::ProgramActivated { program_name } => {
                    format!("activated:{}", program_name)
                }
                ToolEvent::ProgramClosed { program_name } => {
                    format!("closed:{}", program_name)
                }
                _ => format!("other:{:?}", event),
            };
            events2.lock().unwrap().push(name);
        }));

        tool.set_program("test.exe");
        tool.clear_program();

        let captured = events.lock().unwrap();
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0], "activated:test.exe");
        assert_eq!(captured[1], "closed:test.exe");
    }

    #[test]
    fn test_event_project_changed() {
        use std::sync::Mutex;

        let events = Arc::new(Mutex::new(Vec::<String>::new()));
        let events2 = events.clone();

        let mut tool = DockingTool::new();
        tool.add_event_listener(Arc::new(move |event| {
            if let ToolEvent::ProjectChanged { project_name } = event {
                events2
                    .lock()
                    .unwrap()
                    .push(project_name.clone().unwrap_or_default());
            }
        }));

        tool.set_project("my-project");
        assert_eq!(events.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_event_component_added_removed() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let count = Arc::new(AtomicU32::new(0));
        let count2 = count.clone();

        let mut tool = DockingTool::new();
        tool.add_event_listener(Arc::new(move |_event| {
            count2.fetch_add(1, Ordering::SeqCst);
        }));

        let comp = SimpleComponent::new(ComponentProvider::Console, "Console", "console");
        tool.add_component(Box::new(comp));
        assert_eq!(count.load(Ordering::SeqCst), 1); // ComponentAdded

        tool.remove_component(ComponentProvider::Console, "console");
        assert_eq!(count.load(Ordering::SeqCst), 2); // ComponentRemoved
    }

    #[test]
    fn test_clear_event_listeners() {
        let mut tool = DockingTool::new();
        tool.add_event_listener(Arc::new(|_| {}));
        assert_eq!(tool.event_listener_count(), 1);
        tool.clear_event_listeners();
        assert_eq!(tool.event_listener_count(), 0);
    }

    // --- Focus management ---

    #[test]
    fn test_focus_management() {
        let mut tool = DockingTool::new();

        assert!(tool.get_focused().is_none());

        tool.set_focus(ComponentProvider::ListingView, "listing");
        let focused = tool.get_focused().unwrap();
        assert_eq!(focused.0, ComponentProvider::ListingView);
        assert_eq!(focused.1, "listing");

        tool.clear_focus();
        assert!(tool.get_focused().is_none());
    }

    // --- Service registry ---

    #[test]
    fn test_service_registry() {
        let mut tool = DockingTool::new();

        tool.add_service("GoToService", "goto-handler");
        tool.add_service("SearchService", "search-handler");

        assert_eq!(tool.service_names().len(), 2);
        assert!(tool.get_service("GoToService").is_some());
        assert_eq!(
            tool.get_service("GoToService").unwrap().data,
            "goto-handler"
        );
        assert!(tool.get_service("NonExistent").is_none());

        tool.remove_service("GoToService");
        assert!(tool.get_service("GoToService").is_none());
        assert_eq!(tool.service_names().len(), 1);
    }

    // --- Tool properties ---

    #[test]
    fn test_tool_properties() {
        let mut tool = DockingTool::new();

        tool.set_property("theme", "dark");
        tool.set_property("font-size", "14");

        assert_eq!(tool.get_property("theme"), Some("dark"));
        assert_eq!(tool.get_property("font-size"), Some("14"));
        assert_eq!(tool.get_property("missing"), None);
        assert_eq!(tool.properties().len(), 2);

        tool.remove_property("theme");
        assert_eq!(tool.get_property("theme"), None);
        assert_eq!(tool.properties().len(), 1);
    }

    // --- Action manager integration ---

    #[test]
    fn test_register_action_and_trigger() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let called = Arc::new(AtomicBool::new(false));
        let called2 = called.clone();

        let mut tool = DockingTool::new();
        let action = DockingAction::new("test-action", "Test Action")
            .with_callback(super::super::action::ActionCallback::new(move || {
                called2.store(true, Ordering::SeqCst);
            }));
        tool.register_action(action);

        assert!(tool.find_action("test-action").is_some());

        let ctx = ActionContextInfo::empty();
        assert!(tool.trigger_action("test-action", &ctx));
        assert!(called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_undo_redo_integration() {
        let mut tool = DockingTool::new();

        assert!(!tool.can_undo());
        assert!(!tool.can_redo());
        assert!(tool.undo().is_none());

        use super::super::action::{ActionCallback, UndoEntry};
        let noop = || {};
        tool.action_manager.push_undo(UndoEntry {
            description: "test-undo".to_owned(),
            undo: ActionCallback::new(noop),
            redo: ActionCallback::new(noop),
        });

        assert!(tool.can_undo());
        assert_eq!(tool.undo().as_deref(), Some("test-undo"));
        assert!(tool.can_redo());
        assert_eq!(tool.redo().as_deref(), Some("test-undo"));
        assert!(!tool.can_redo());
    }
}
