//! The `DockingTool` trait for the docking framework.
//!
//! Port of Ghidra's `docking.DockingTool` interface.  In Java this is
//! the interface that tool implementations satisfy.  It exposes the
//! programmatic API that plugins and components use to interact with
//! the tool without depending on a concrete implementation.
//!
//! The existing [`super::tool::DockingTool`] struct provides a concrete
//! implementation; this trait defines the abstract contract.

use std::fmt;

use super::action::DockingAction;
use super::action_context::DockingActionContext;
use super::component::{ComponentProvider as ProviderType, WindowPosition};

// ---------------------------------------------------------------------------
// DockingToolService — a service registered with the tool (trait-level)
// ---------------------------------------------------------------------------

/// A service registered with the tool's service registry.
///
/// Port of Ghidra's `ServiceProvider` concept.  Plugins can register
/// services and other components can look them up by name.
#[derive(Debug, Clone)]
pub struct DockingToolService {
    /// The service name / identifier.
    pub name: String,
    /// The service data (typically a JSON or serialized representation).
    pub data: String,
    /// The owner (plugin) that registered the service.
    pub owner: String,
}

impl DockingToolService {
    /// Create a new tool service.
    pub fn new(
        name: impl Into<String>,
        data: impl Into<String>,
        owner: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            data: data.into(),
            owner: owner.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// DockingToolEvent — events emitted by the tool (trait-level)
// ---------------------------------------------------------------------------

/// Events that a tool can emit to registered listeners.
///
/// Port of the various event types in Ghidra's tool system.
#[derive(Debug, Clone)]
pub enum DockingToolEvent {
    /// A component provider was added.
    ProviderAdded {
        provider: ProviderType,
        name: String,
    },
    /// A component provider was removed.
    ProviderRemoved {
        provider: ProviderType,
        name: String,
    },
    /// A component provider's visibility changed.
    ProviderVisibilityChanged {
        provider: ProviderType,
        name: String,
        visible: bool,
    },
    /// The active (focused) component provider changed.
    ActiveProviderChanged {
        provider: Option<(ProviderType, String)>,
    },
    /// The tool's action context changed.
    ContextChanged {
        provider: Option<(ProviderType, String)>,
    },
    /// An action was added to the tool.
    ActionAdded {
        name: String,
        owner: String,
    },
    /// An action was removed from the tool.
    ActionRemoved {
        name: String,
        owner: String,
    },
    /// The tool's configuration changed.
    ConfigChanged,
    /// The tool was closed.
    Closed,
    /// The tool's status info changed.
    StatusChanged {
        text: String,
    },
}

/// A callback that receives tool events.
pub struct DockingToolEventCallback(Box<dyn Fn(&DockingToolEvent) + Send + Sync>);

impl DockingToolEventCallback {
    /// Create a new event callback.
    pub fn new<F: Fn(&DockingToolEvent) + Send + Sync + 'static>(f: F) -> Self {
        Self(Box::new(f))
    }

    /// Invoke the callback with the given event.
    pub fn invoke(&self, event: &DockingToolEvent) {
        (self.0)(event)
    }
}

impl fmt::Debug for DockingToolEventCallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DockingToolEventCallback").finish()
    }
}

// ---------------------------------------------------------------------------
// PopupActionProvider — callback for contributing popup actions
// ---------------------------------------------------------------------------

/// A provider that contributes actions to popup (context) menus.
///
/// Port of Ghidra's `PopupActionProvider` interface.  Registered with the
/// tool, it is called each time a popup menu is about to be shown so that
/// it can add context-sensitive actions.
pub trait PopupActionProvider: std::fmt::Debug + Send + Sync {
    /// Contribute popup actions for the given context.
    fn contribute_popup_actions(&self, context: &DockingActionContext) -> Vec<DockingAction>;
}

// ---------------------------------------------------------------------------
// DockingContextListener — listener for context changes
// ---------------------------------------------------------------------------

/// A listener notified when the tool's action context changes.
///
/// Port of Ghidra's `DockingContextListener` interface.
pub trait DockingContextListener: std::fmt::Debug + Send + Sync {
    /// Called when the tool's context has changed.
    fn context_changed(&self, context: &DockingActionContext);
}

// ---------------------------------------------------------------------------
// DockingTool trait
// ---------------------------------------------------------------------------

/// The abstract tool interface for the docking framework.
///
/// This trait exposes the API that plugins, component providers, and
/// actions use to interact with the tool.  It covers:
/// - Project and program management
/// - Action registration and dispatch
/// - Component provider management
/// - Layout persistence
/// - Event notification
/// - Service registry
/// - Focus management
pub trait DockingTool: fmt::Debug + Send + Sync {
    /// The name of the tool (e.g. "CodeBrowser").
    fn tool_name(&self) -> &str;

    /// Set the tool name.
    fn set_tool_name(&mut self, name: &str);

    // -- Project / program --

    /// The currently active project name, if any.
    fn active_project(&self) -> Option<&str>;

    /// Set the active project.
    fn set_project(&mut self, project: &str);

    /// Clear the active project.
    fn clear_project(&mut self);

    /// The currently active program name, if any.
    fn active_program(&self) -> Option<&str>;

    /// Set the active program.
    fn set_program(&mut self, program: &str);

    /// Clear the active program.
    fn clear_program(&mut self);

    // -- Actions --

    /// Register a top-level action with the tool.
    fn add_action(&mut self, action: DockingAction);

    /// Remove an action by name.
    fn remove_action(&mut self, name: &str) -> Option<DockingAction>;

    /// Find an action by name.
    fn find_action(&self, name: &str) -> Option<&DockingAction>;

    /// Enable or disable an action by name.
    fn set_action_enabled(&mut self, name: &str, enabled: bool) -> bool;

    /// Trigger an action by name with context.
    fn trigger_action(&self, name: &str, context: &DockingActionContext) -> bool;

    // -- Component providers (Port of Ghidra's Tool.addComponentProvider/removeComponentProvider) --

    /// Add a component provider to the tool, optionally making it visible.
    ///
    /// Port of Ghidra's `Tool.addComponentProvider`.
    fn add_component_provider(&mut self, provider: ProviderType, name: &str, show: bool);

    /// Remove a component provider from the tool.
    ///
    /// Port of Ghidra's `Tool.removeComponentProvider`.
    fn remove_component_provider(&mut self, provider: ProviderType, name: &str);

    /// Get a component provider by name.
    ///
    /// Port of Ghidra's `Tool.getComponentProvider`.
    fn get_component_provider(&self, name: &str) -> Option<(ProviderType, String)>;

    /// Update the title of a component provider.
    ///
    /// Port of Ghidra's `Tool.updateTitle`.
    fn update_title(&mut self, _provider: ProviderType, _name: &str) {}

    /// Get the parent window for a component provider.
    ///
    /// Port of Ghidra's `Tool.getProviderWindow`.
    fn get_provider_window(&self, _provider: &ProviderType, _name: &str) -> Option<String> {
        None
    }

    // -- Components --

    /// Show a component provider.
    fn show_component(&mut self, provider: ProviderType, name: &str);

    /// Hide a component provider.
    fn hide_component(&mut self, provider: ProviderType, name: &str);

    /// Toggle visibility of a component provider.
    fn toggle_component(&mut self, provider: ProviderType, name: &str);

    /// Whether a component is visible.
    fn is_component_visible(&self, provider: &ProviderType, name: &str) -> bool;

    /// Show or hide a component provider.
    ///
    /// Port of Ghidra's `Tool.showComponentProvider`.
    fn show_component_provider(&mut self, provider: ProviderType, name: &str, visible: bool) {
        if visible {
            self.show_component(provider, name);
        } else {
            self.hide_component(provider, name);
        }
    }

    /// Bring a component provider to the front (e.g. within a tab group).
    ///
    /// Port of Ghidra's `Tool.toFront(ComponentProvider)`.
    fn to_front(&mut self, _provider: ProviderType, _name: &str) {}

    /// Whether the tool itself is visible.
    ///
    /// Port of Ghidra's `Tool.isVisible()`.
    fn is_tool_visible(&self) -> bool {
        true
    }

    /// Set the tool's visibility.
    ///
    /// Port of Ghidra's `Tool.setVisible`.
    fn set_tool_visible(&mut self, _visible: bool) {}

    /// Bring the tool window to the front.
    ///
    /// Port of Ghidra's `Tool.toFront()`.
    fn tool_to_front(&mut self) {}

    /// Get the active component provider (the one with focus).
    ///
    /// Port of Ghidra's `Tool.getActiveComponentProvider`.
    fn get_active_component_provider(&self) -> Option<(ProviderType, String)> {
        self.get_focused()
    }

    /// Whether the given component provider is currently active (has focus).
    ///
    /// Port of Ghidra's `Tool.isActive(ComponentProvider)`.
    fn is_active(&self, provider: &ProviderType, name: &str) -> bool {
        self.get_focused()
            .as_ref()
            .map(|(p, n)| p == provider && n == name)
            .unwrap_or(false)
    }

    // -- Layout --

    /// Serialize the current layout to a string.
    fn save_layout(&self) -> String;

    /// Restore the layout from a serialized string.
    fn load_layout(&mut self, data: &str) -> Result<(), String>;

    /// Reset to the default layout.
    fn reset_layout(&mut self);

    // -- Focus --

    /// Set focus to a specific component.
    fn set_focus(&mut self, provider: ProviderType, name: &str);

    /// Get the currently focused component.
    fn get_focused(&self) -> Option<(ProviderType, String)>;

    /// Clear focus.
    fn clear_focus(&mut self);

    // -- Context --

    /// Get the current action context.
    fn current_context(&self) -> DockingActionContext;

    /// Set the current action context.
    fn set_context(&mut self, context: DockingActionContext);

    /// Notify the tool that a provider's context has changed.
    ///
    /// Port of Ghidra's `Tool.contextChanged(ComponentProvider)`.
    fn context_changed(&mut self, _provider: Option<(ProviderType, String)>) {}

    /// Add a context listener.
    ///
    /// Port of Ghidra's `Tool.addContextListener`.
    fn add_context_listener(&mut self, _listener: Box<dyn DockingContextListener>) {}

    /// Remove a context listener.
    ///
    /// Port of Ghidra's `Tool.removeContextListener`.
    fn remove_context_listener(&mut self, _listener_id: &str) {}

    // -- Popup action providers --

    /// Add a popup action provider.
    ///
    /// Port of Ghidra's `Tool.addPopupActionProvider`.
    fn add_popup_action_provider(&mut self, _provider: Box<dyn PopupActionProvider>) {}

    /// Remove a popup action provider.
    ///
    /// Port of Ghidra's `Tool.removePopupActionProvider`.
    fn remove_popup_action_provider(&mut self, _provider_id: &str) {}

    // -- Window manager --

    /// Get the window manager identifier.
    ///
    /// Port of Ghidra's `Tool.getWindowManager()`.
    fn window_manager_id(&self) -> Option<&str> {
        None
    }

    // -- Tool actions manager --

    /// Get the tool actions manager identifier.
    ///
    /// Port of Ghidra's `Tool.getToolActions()`.
    fn tool_actions_id(&self) -> Option<&str> {
        None
    }

    // -- Status bar --

    /// Set the status information text.
    ///
    /// Port of Ghidra's `Tool.setStatusInfo`.
    fn set_status_info(&mut self, _text: &str) {}

    /// Set the status information with an optional beep.
    ///
    /// Port of Ghidra's `Tool.setStatusInfo(text, beep)`.
    fn set_status_info_with_beep(&mut self, text: &str, _beep: bool) {
        self.set_status_info(text);
    }

    /// Get the current status info text.
    ///
    /// Port of Ghidra's `Tool.getStatusInfo`.
    fn get_status_info(&self) -> &str {
        ""
    }

    /// Clear the status info text.
    ///
    /// Port of Ghidra's `Tool.clearStatusInfo`.
    fn clear_status_info(&mut self) {}

    // -- Services --

    /// Register a service with the tool.
    fn add_service(&mut self, name: &str, data: &str);

    /// Get a service by name.
    fn get_service(&self, name: &str) -> Option<&str>;

    /// Remove a service by name.
    fn remove_service(&mut self, name: &str) -> Option<String>;

    // -- Properties --

    /// Set a tool-wide property.
    fn set_property(&mut self, key: &str, value: &str);

    /// Get a tool-wide property.
    fn get_property(&self, key: &str) -> Option<&str>;

    /// Remove a tool-wide property.
    fn remove_property(&mut self, key: &str) -> Option<String>;

    // -- Config state --

    /// Mark the tool's configuration as changed.
    ///
    /// Port of Ghidra's `Tool.setConfigChanged`.
    fn set_config_changed(&mut self, _changed: bool) {}

    /// Whether the tool's configuration has unsaved changes.
    ///
    /// Port of Ghidra's `Tool.hasConfigChanged`.
    fn has_config_changed(&self) -> bool {
        false
    }

    // -- Local actions --

    /// Add a local action associated with a component provider.
    ///
    /// Port of Ghidra's `Tool.addLocalAction`.
    fn add_local_action(&mut self, provider: ProviderType, name: &str, action: DockingAction);

    /// Remove a local action from a component provider.
    ///
    /// Port of Ghidra's `Tool.removeLocalAction`.
    fn remove_local_action(&mut self, provider: ProviderType, name: &str, action_name: &str);

    /// Get all local actions for a component provider.
    ///
    /// Port of Ghidra's `Tool.getLocalActions`.
    fn get_local_actions(&self, provider: &ProviderType, name: &str) -> Vec<&DockingAction>;

    /// Get all global actions registered with the tool.
    ///
    /// Port of Ghidra's `Tool.getGlobalActions`.
    fn get_global_actions(&self) -> Vec<&DockingAction>;

    /// Get all actions (global + local) in the tool.
    ///
    /// Port of Ghidra's `Tool.getAllActions`.
    fn get_all_actions(&self) -> Vec<&DockingAction>;

    /// Get all actions owned by the given owner name.
    ///
    /// Port of Ghidra's `Tool.getDockingActionsByOwnerName`.
    fn get_actions_by_owner(&self, owner: &str) -> Vec<&DockingAction>;

    // -- Dialog --

    /// Show a dialog component provider.
    ///
    /// Port of Ghidra's `Tool.showDialog`.
    fn show_dialog(&mut self, _title: &str) {}

    // -- Window position --

    /// Get the default window position for a component provider.
    fn default_position_for(&self, _provider: &ProviderType) -> WindowPosition {
        WindowPosition::Center
    }

    // -- Menu groups --

    /// Set the menu group for a cascaded sub-menu.
    ///
    /// Port of Ghidra's `Tool.setMenuGroup`.
    fn set_menu_group(&mut self, _menu_path: &[&str], _group: &str, _sub_group: &str) {}

    // -- Icon --

    /// Get the tool's icon identifier.
    ///
    /// Port of Ghidra's `Tool.getIcon`.
    fn icon(&self) -> Option<&str> {
        None
    }

    /// Set the tool's icon.
    fn set_icon(&mut self, _icon: &str) {}

    // -- Options --

    /// Get an option value for the given category and key.
    ///
    /// Port of Ghidra's `Tool.getOptions`.
    fn get_option(&self, _category: &str, _key: &str) -> Option<&str> {
        None
    }

    /// Set an option value for the given category and key.
    fn set_option(&mut self, _category: &str, _key: &str, _value: &str) {}

    /// Remove an option value for the given category and key.
    fn remove_option(&mut self, _category: &str, _key: &str) {}

    // -- Service providers --

    /// Get all registered service names.
    fn service_names(&self) -> Vec<&str> {
        Vec::new()
    }

    /// Check if a service is registered.
    fn has_service(&self, name: &str) -> bool {
        self.get_service(name).is_some()
    }

    // -- Event system --

    /// Register a tool event listener.
    ///
    /// Port of Ghidra's event listener pattern.  Listeners are notified
    /// when providers are added/removed, context changes, etc.
    fn add_event_listener(&mut self, _listener: DockingToolEventCallback) {}

    /// Remove a tool event listener by index.
    fn remove_event_listener(&mut self, _index: usize) {}

    // -- Lifecycle --

    /// Close the tool.
    fn close(&mut self);

    /// Whether the tool has been closed.
    fn is_closed(&self) -> bool {
        false
    }

    /// Dispose of the tool and all its resources.
    fn dispose(&mut self);
}

// ---------------------------------------------------------------------------
// DockingToolConfig — tool configuration state
// ---------------------------------------------------------------------------

/// Configuration and option state for a docking tool.
///
/// Port of Ghidra's `ToolOptions` and related configuration concepts.
/// This struct provides a simple key-value store for tool options organized
/// by category.
#[derive(Debug, Clone, Default)]
pub struct DockingToolConfig {
    /// Tool-wide options organized as (category, key) -> value.
    options: std::collections::BTreeMap<(String, String), String>,
    /// Tool-wide properties.
    properties: std::collections::BTreeMap<String, String>,
    /// Whether the configuration has been modified since last save.
    config_changed: bool,
    /// The tool's icon identifier.
    icon: Option<String>,
}

impl DockingToolConfig {
    /// Create a new empty configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set an option value for the given category and key.
    pub fn set_option(&mut self, category: &str, key: &str, value: &str) {
        self.options
            .insert((category.to_owned(), key.to_owned()), value.to_owned());
        self.config_changed = true;
    }

    /// Get an option value for the given category and key.
    pub fn get_option(&self, category: &str, key: &str) -> Option<&str> {
        self.options
            .get(&(category.to_owned(), key.to_owned()))
            .map(|s| s.as_str())
    }

    /// Remove an option value for the given category and key.
    pub fn remove_option(&mut self, category: &str, key: &str) -> Option<String> {
        let removed = self
            .options
            .remove(&(category.to_owned(), key.to_owned()));
        if removed.is_some() {
            self.config_changed = true;
        }
        removed
    }

    /// Get all option keys for a given category.
    pub fn option_keys_in_category(&self, category: &str) -> Vec<&str> {
        self.options
            .keys()
            .filter(|(cat, _)| cat == category)
            .map(|(_, key)| key.as_str())
            .collect()
    }

    /// Get all categories that have options.
    pub fn categories(&self) -> Vec<&str> {
        let mut cats: Vec<&str> = self
            .options
            .keys()
            .map(|(cat, _)| cat.as_str())
            .collect();
        cats.sort();
        cats.dedup();
        cats
    }

    /// Set a tool-wide property.
    pub fn set_property(&mut self, key: &str, value: &str) {
        self.properties.insert(key.to_owned(), value.to_owned());
    }

    /// Get a tool-wide property.
    pub fn get_property(&self, key: &str) -> Option<&str> {
        self.properties.get(key).map(|s| s.as_str())
    }

    /// Remove a tool-wide property.
    pub fn remove_property(&mut self, key: &str) -> Option<String> {
        self.properties.remove(key)
    }

    /// Get the tool's icon identifier.
    pub fn icon(&self) -> Option<&str> {
        self.icon.as_deref()
    }

    /// Set the tool's icon.
    pub fn set_icon(&mut self, icon: impl Into<String>) {
        self.icon = Some(icon.into());
    }

    /// Whether the configuration has unsaved changes.
    pub fn has_config_changed(&self) -> bool {
        self.config_changed
    }

    /// Set the config changed flag.
    pub fn set_config_changed(&mut self, changed: bool) {
        self.config_changed = changed;
    }

    /// Mark the configuration as saved.
    pub fn mark_saved(&mut self) {
        self.config_changed = false;
    }
}

// ---------------------------------------------------------------------------
// DockingToolInfo — tool metadata
// ---------------------------------------------------------------------------

/// Metadata about a docking tool, returned by queries.
///
/// Port of Ghidra's tool metadata concepts.  This is useful for tool
/// management and serialization.
#[derive(Debug, Clone)]
pub struct DockingToolInfo {
    /// The tool name.
    pub name: String,
    /// The active project, if any.
    pub project: Option<String>,
    /// The active program, if any.
    pub program: Option<String>,
    /// The icon identifier, if any.
    pub icon: Option<String>,
    /// Number of registered global actions.
    pub global_action_count: usize,
    /// Number of registered component providers.
    pub provider_count: usize,
    /// Whether the tool has unsaved configuration changes.
    pub config_changed: bool,
}

impl fmt::Display for DockingToolInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Tool[name={}, project={}, program={}, actions={}, providers={}]",
            self.name,
            self.project.as_deref().unwrap_or("(none)"),
            self.program.as_deref().unwrap_or("(none)"),
            self.global_action_count,
            self.provider_count,
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct MockTool {
        name: String,
        project: Option<String>,
        program: Option<String>,
        closed: bool,
    }

    impl MockTool {
        fn new() -> Self {
            Self {
                name: "CodeBrowser".into(),
                project: None,
                program: None,
                closed: false,
            }
        }
    }

    impl DockingTool for MockTool {
        fn tool_name(&self) -> &str { &self.name }
        fn set_tool_name(&mut self, name: &str) { self.name = name.to_owned(); }
        fn active_project(&self) -> Option<&str> { self.project.as_deref() }
        fn set_project(&mut self, project: &str) { self.project = Some(project.to_owned()); }
        fn clear_project(&mut self) { self.project = None; }
        fn active_program(&self) -> Option<&str> { self.program.as_deref() }
        fn set_program(&mut self, program: &str) { self.program = Some(program.to_owned()); }
        fn clear_program(&mut self) { self.program = None; }
        fn add_action(&mut self, _action: DockingAction) {}
        fn remove_action(&mut self, _name: &str) -> Option<DockingAction> { None }
        fn find_action(&self, _name: &str) -> Option<&DockingAction> { None }
        fn set_action_enabled(&mut self, _name: &str, _enabled: bool) -> bool { false }
        fn trigger_action(&self, _name: &str, _ctx: &DockingActionContext) -> bool { false }
        fn add_component_provider(&mut self, _p: ProviderType, _n: &str, _show: bool) {}
        fn remove_component_provider(&mut self, _p: ProviderType, _n: &str) {}
        fn get_component_provider(&self, _name: &str) -> Option<(ProviderType, String)> { None }
        fn show_component(&mut self, _p: ProviderType, _n: &str) {}
        fn hide_component(&mut self, _p: ProviderType, _n: &str) {}
        fn toggle_component(&mut self, _p: ProviderType, _n: &str) {}
        fn is_component_visible(&self, _p: &ProviderType, _n: &str) -> bool { false }
        fn save_layout(&self) -> String { String::new() }
        fn load_layout(&mut self, _data: &str) -> Result<(), String> { Ok(()) }
        fn reset_layout(&mut self) {}
        fn set_focus(&mut self, _p: ProviderType, _n: &str) {}
        fn get_focused(&self) -> Option<(ProviderType, String)> { None }
        fn clear_focus(&mut self) {}
        fn current_context(&self) -> DockingActionContext { DockingActionContext::new() }
        fn set_context(&mut self, _ctx: DockingActionContext) {}
        fn add_service(&mut self, _name: &str, _data: &str) {}
        fn get_service(&self, _name: &str) -> Option<&str> { None }
        fn remove_service(&mut self, _name: &str) -> Option<String> { None }
        fn set_property(&mut self, _key: &str, _value: &str) {}
        fn get_property(&self, _key: &str) -> Option<&str> { None }
        fn remove_property(&mut self, _key: &str) -> Option<String> { None }
        fn add_local_action(&mut self, _p: ProviderType, _n: &str, _a: DockingAction) {}
        fn remove_local_action(&mut self, _p: ProviderType, _n: &str, _action_name: &str) {}
        fn get_local_actions(&self, _p: &ProviderType, _n: &str) -> Vec<&DockingAction> { Vec::new() }
        fn get_global_actions(&self) -> Vec<&DockingAction> { Vec::new() }
        fn get_all_actions(&self) -> Vec<&DockingAction> { Vec::new() }
        fn get_actions_by_owner(&self, _owner: &str) -> Vec<&DockingAction> { Vec::new() }
        fn close(&mut self) { self.closed = true; }
        fn is_closed(&self) -> bool { self.closed }
        fn dispose(&mut self) { self.closed = true; }
    }

    #[test]
    fn test_tool_trait_basic() {
        let mut tool = MockTool::new();
        assert_eq!(tool.tool_name(), "CodeBrowser");
        assert!(tool.active_project().is_none());
        assert!(tool.active_program().is_none());
        assert!(!tool.is_closed());
    }

    #[test]
    fn test_tool_trait_project_program() {
        let mut tool = MockTool::new();
        tool.set_project("my-project");
        assert_eq!(tool.active_project(), Some("my-project"));

        tool.set_program("test.exe");
        assert_eq!(tool.active_program(), Some("test.exe"));

        tool.clear_program();
        assert!(tool.active_program().is_none());
        assert_eq!(tool.active_project(), Some("my-project"));

        tool.clear_project();
        assert!(tool.active_project().is_none());
    }

    #[test]
    fn test_tool_trait_name() {
        let mut tool = MockTool::new();
        assert_eq!(tool.tool_name(), "CodeBrowser");
        tool.set_tool_name("NewTool");
        assert_eq!(tool.tool_name(), "NewTool");
    }

    #[test]
    fn test_tool_trait_lifecycle() {
        let mut tool = MockTool::new();
        assert!(!tool.is_closed());
        tool.close();
        assert!(tool.is_closed());
    }

    #[test]
    fn test_tool_trait_defaults() {
        let tool = MockTool::new();
        assert_eq!(
            tool.default_position_for(&ProviderType::Console),
            WindowPosition::Center
        );
    }

    #[test]
    fn test_tool_trait_as_trait_object() {
        let tool: Box<dyn DockingTool> = Box::new(MockTool::new());
        assert_eq!(tool.tool_name(), "CodeBrowser");
    }

    // -- DockingToolService tests --

    #[test]
    fn test_docking_tool_service_new() {
        let svc = DockingToolService::new("GhidraScript", "{}", "ScriptPlugin");
        assert_eq!(svc.name, "GhidraScript");
        assert_eq!(svc.data, "{}");
        assert_eq!(svc.owner, "ScriptPlugin");
    }

    #[test]
    fn test_docking_tool_service_clone() {
        let svc = DockingToolService::new("svc", "data", "owner");
        let svc2 = svc.clone();
        assert_eq!(svc.name, svc2.name);
    }

    // -- DockingToolEvent tests --

    #[test]
    fn test_docking_tool_event_variants() {
        let evt = DockingToolEvent::ProviderAdded {
            provider: ProviderType::Console,
            name: "console".to_owned(),
        };
        assert!(format!("{:?}", evt).contains("Console"));

        let evt = DockingToolEvent::ActiveProviderChanged {
            provider: Some((ProviderType::ListingView, "listing".to_owned())),
        };
        assert!(format!("{:?}", evt).contains("ListingView"));

        let evt = DockingToolEvent::ContextChanged { provider: None };
        assert!(format!("{:?}", evt).contains("ContextChanged"));

        let evt = DockingToolEvent::Closed;
        assert!(format!("{:?}", evt).contains("Closed"));
    }

    #[test]
    fn test_docking_tool_event_callback() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let called = Arc::new(AtomicBool::new(false));
        let called2 = called.clone();

        let cb = DockingToolEventCallback::new(move |_evt| {
            called2.store(true, Ordering::SeqCst);
        });

        cb.invoke(&DockingToolEvent::Closed);
        assert!(called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_docking_tool_event_callback_debug() {
        let cb = DockingToolEventCallback::new(|_| {});
        let dbg = format!("{:?}", cb);
        assert!(dbg.contains("DockingToolEventCallback"));
    }

    // -- DockingToolConfig tests --

    #[test]
    fn test_tool_config_new() {
        let config = DockingToolConfig::new();
        assert!(!config.has_config_changed());
        assert!(config.icon().is_none());
        assert!(config.categories().is_empty());
    }

    #[test]
    fn test_tool_config_options() {
        let mut config = DockingToolConfig::new();
        config.set_option("Browser", "font-size", "14");
        config.set_option("Browser", "theme", "dark");
        config.set_option("Editor", "tab-size", "4");

        assert_eq!(config.get_option("Browser", "font-size"), Some("14"));
        assert_eq!(config.get_option("Browser", "theme"), Some("dark"));
        assert_eq!(config.get_option("Editor", "tab-size"), Some("4"));
        assert_eq!(config.get_option("Browser", "missing"), None);
        assert!(config.has_config_changed());
    }

    #[test]
    fn test_tool_config_remove_option() {
        let mut config = DockingToolConfig::new();
        config.set_option("Cat", "key", "value");
        assert_eq!(config.remove_option("Cat", "key"), Some("value".to_owned()));
        assert_eq!(config.get_option("Cat", "key"), None);
        assert_eq!(config.remove_option("Cat", "key"), None);
    }

    #[test]
    fn test_tool_config_categories() {
        let mut config = DockingToolConfig::new();
        config.set_option("Browser", "font-size", "14");
        config.set_option("Editor", "tab-size", "4");
        config.set_option("Browser", "theme", "dark");

        let cats = config.categories();
        assert_eq!(cats.len(), 2);
        assert!(cats.contains(&"Browser"));
        assert!(cats.contains(&"Editor"));
    }

    #[test]
    fn test_tool_config_option_keys_in_category() {
        let mut config = DockingToolConfig::new();
        config.set_option("Browser", "font-size", "14");
        config.set_option("Browser", "theme", "dark");

        let keys = config.option_keys_in_category("Browser");
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"font-size"));
        assert!(keys.contains(&"theme"));

        assert!(config.option_keys_in_category("Missing").is_empty());
    }

    #[test]
    fn test_tool_config_properties() {
        let mut config = DockingToolConfig::new();
        config.set_property("workspace", "default");
        assert_eq!(config.get_property("workspace"), Some("default"));
        assert_eq!(config.get_property("missing"), None);

        let removed = config.remove_property("workspace");
        assert_eq!(removed, Some("default".to_owned()));
        assert!(config.get_property("workspace").is_none());
    }

    #[test]
    fn test_tool_config_icon() {
        let mut config = DockingToolConfig::new();
        assert!(config.icon().is_none());

        config.set_icon("ghidra-icon");
        assert_eq!(config.icon(), Some("ghidra-icon"));
    }

    #[test]
    fn test_tool_config_changed() {
        let mut config = DockingToolConfig::new();
        assert!(!config.has_config_changed());

        config.set_config_changed(true);
        assert!(config.has_config_changed());

        config.mark_saved();
        assert!(!config.has_config_changed());
    }

    // -- DockingToolInfo tests --

    #[test]
    fn test_tool_info_display() {
        let info = DockingToolInfo {
            name: "CodeBrowser".into(),
            project: Some("my-project".into()),
            program: Some("test.exe".into()),
            icon: Some("ghidra".into()),
            global_action_count: 42,
            provider_count: 5,
            config_changed: false,
        };
        let display = info.to_string();
        assert!(display.contains("CodeBrowser"));
        assert!(display.contains("my-project"));
        assert!(display.contains("test.exe"));
        assert!(display.contains("42"));
        assert!(display.contains("5"));
    }

    #[test]
    fn test_tool_info_none_fields() {
        let info = DockingToolInfo {
            name: "EmptyTool".into(),
            project: None,
            program: None,
            icon: None,
            global_action_count: 0,
            provider_count: 0,
            config_changed: true,
        };
        let display = info.to_string();
        assert!(display.contains("(none)"));
        assert!(display.contains("EmptyTool"));
    }

    // -- MockTool extended tests for new default methods --

    #[test]
    fn test_tool_trait_options() {
        let tool = MockTool::new();
        // Default implementations return None/empty.
        assert_eq!(tool.get_option("cat", "key"), None);
        assert!(tool.service_names().is_empty());
        assert!(!tool.has_service("svc"));
        assert_eq!(tool.get_status_info(), "");
        assert!(tool.icon().is_none());
    }

    #[test]
    fn test_tool_trait_visibility() {
        let mut tool = MockTool::new();
        assert!(tool.is_tool_visible());
        tool.set_tool_visible(false); // no-op by default
        assert!(tool.is_tool_visible());
    }

    #[test]
    fn test_tool_trait_active_provider() {
        let tool = MockTool::new();
        // Default get_active_component_provider delegates to get_focused.
        assert!(tool.get_active_component_provider().is_none());
        assert!(!tool.is_active(&ProviderType::Console, "console"));
    }

    #[test]
    fn test_tool_trait_window_manager_actions() {
        let tool = MockTool::new();
        assert!(tool.window_manager_id().is_none());
        assert!(tool.tool_actions_id().is_none());
    }

    #[test]
    fn test_tool_trait_config() {
        let tool = MockTool::new();
        assert!(!tool.has_config_changed());
    }

    // -- PopupActionProvider test --

    #[derive(Debug)]
    struct MockPopupProvider;

    impl PopupActionProvider for MockPopupProvider {
        fn contribute_popup_actions(&self, _ctx: &DockingActionContext) -> Vec<DockingAction> {
            vec![DockingAction::new("popup-action", "Popup Action")]
        }
    }

    #[test]
    fn test_popup_action_provider() {
        let provider = MockPopupProvider;
        let ctx = DockingActionContext::new();
        let actions = provider.contribute_popup_actions(&ctx);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].name, "popup-action");
    }

    // -- DockingContextListener test --

    #[derive(Debug)]
    struct MockContextListener {
        called: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl DockingContextListener for MockContextListener {
        fn context_changed(&self, _ctx: &DockingActionContext) {
            self.called.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn test_docking_context_listener() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let flag = Arc::new(AtomicBool::new(false));
        let listener = MockContextListener { called: flag.clone() };
        let ctx = DockingActionContext::new();
        listener.context_changed(&ctx);
        assert!(flag.load(Ordering::SeqCst));
    }
}
