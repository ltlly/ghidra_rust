//! Action management subsystem for the docking framework.
//!
//! Port of Ghidra's `DockingToolActions`, `PopupActionManager`,
//! `PopupActionProvider`, `GlobalMenuAndToolBarManager`,
//! `WindowActionManager`, `ActionToGuiMapper`, and
//! `DockingActionProxy`.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use super::action::{ActionCallback, DockingAction};
use super::component::ComponentProvider;

// ---------------------------------------------------------------------------
// DockingToolActions — the central action registry interface
// ---------------------------------------------------------------------------

/// Manages the collection of all actions registered with the tool.
///
/// Actions can be:
/// - **Global**: always active regardless of focus.
/// - **Local**: only active when a specific component provider has focus.
/// - **Popup**: contributed dynamically to context menus.
pub struct DockingToolActions {
    /// Global actions (always available).
    global_actions: HashMap<String, DockingAction>,
    /// Local actions keyed by provider, then by action name.
    local_actions: HashMap<ComponentProvider, HashMap<String, DockingAction>>,
    /// Shared action placeholders (for transient providers).
    placeholders: HashMap<String, DockingAction>,
}

impl DockingToolActions {
    /// Create a new, empty action registry.
    pub fn new() -> Self {
        Self {
            global_actions: HashMap::new(),
            local_actions: HashMap::new(),
            placeholders: HashMap::new(),
        }
    }

    // ---------------------------------------------------------------
    // Global actions
    // ---------------------------------------------------------------

    /// Add a global action.
    pub fn add_global_action(&mut self, action: DockingAction) {
        self.global_actions.insert(action.name.clone(), action);
    }

    /// Remove a global action by name.
    pub fn remove_global_action(&mut self, name: &str) -> Option<DockingAction> {
        self.global_actions.remove(name)
    }

    /// Get a global action by name.
    pub fn get_global_action(&self, name: &str) -> Option<&DockingAction> {
        self.global_actions.get(name)
    }

    /// Get all global actions.
    pub fn global_actions(&self) -> &HashMap<String, DockingAction> {
        &self.global_actions
    }

    /// Get all global action names.
    pub fn global_action_names(&self) -> HashSet<&str> {
        self.global_actions.keys().map(|k| k.as_str()).collect()
    }

    // ---------------------------------------------------------------
    // Local actions
    // ---------------------------------------------------------------

    /// Add a local action (only active when the given provider has focus).
    pub fn add_local_action(
        &mut self,
        provider: ComponentProvider,
        action: DockingAction,
    ) {
        self.local_actions
            .entry(provider)
            .or_default()
            .insert(action.name.clone(), action);
    }

    /// Remove a local action.
    pub fn remove_local_action(
        &mut self,
        provider: ComponentProvider,
        action_name: &str,
    ) -> Option<DockingAction> {
        self.local_actions
            .get_mut(&provider)
            .and_then(|actions| actions.remove(action_name))
    }

    /// Get all local actions for a provider.
    pub fn local_actions(
        &self,
        provider: &ComponentProvider,
    ) -> Option<&HashMap<String, DockingAction>> {
        self.local_actions.get(provider)
    }

    /// Get all actions (global + local) that are active for the given
    /// focused provider.
    pub fn active_actions(
        &self,
        focused_provider: Option<&ComponentProvider>,
    ) -> Vec<&DockingAction> {
        let mut actions: Vec<&DockingAction> = self.global_actions.values().collect();

        if let Some(provider) = focused_provider {
            if let Some(local) = self.local_actions.get(provider) {
                actions.extend(local.values());
            }
        }

        actions
    }

    /// Remove all local actions for a provider (e.g. when the provider
    /// is disposed).
    pub fn remove_provider_actions(
        &mut self,
        provider: &ComponentProvider,
    ) -> Option<HashMap<String, DockingAction>> {
        self.local_actions.remove(provider)
    }

    // ---------------------------------------------------------------
    // Placeholders
    // ---------------------------------------------------------------

    /// Register an action placeholder for a transient provider.
    pub fn register_placeholder(&mut self, action: DockingAction) {
        self.placeholders.insert(action.name.clone(), action);
    }

    /// Get a placeholder by name.
    pub fn get_placeholder(&self, name: &str) -> Option<&DockingAction> {
        self.placeholders.get(name)
    }

    /// Remove a placeholder.
    pub fn remove_placeholder(&mut self, name: &str) -> Option<DockingAction> {
        self.placeholders.remove(name)
    }

    /// All registered placeholders.
    pub fn placeholders(&self) -> &HashMap<String, DockingAction> {
        &self.placeholders
    }

    // ---------------------------------------------------------------
    // Queries
    // ---------------------------------------------------------------

    /// Total number of registered actions (global + local + placeholders).
    pub fn total_count(&self) -> usize {
        let local_count: usize = self
            .local_actions
            .values()
            .map(|m| m.len())
            .sum();
        self.global_actions.len() + local_count + self.placeholders.len()
    }

    /// Find any action (global first, then local) by name.
    pub fn find_action(&self, name: &str) -> Option<&DockingAction> {
        self.global_actions
            .get(name)
            .or_else(|| {
                self.local_actions
                    .values()
                    .find_map(|actions| actions.get(name))
            })
    }
}

impl Default for DockingToolActions {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for DockingToolActions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DockingToolActions")
            .field("global_count", &self.global_actions.len())
            .field("local_providers", &self.local_actions.len())
            .field("placeholders", &self.placeholders.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// PopupActionProvider
// ---------------------------------------------------------------------------

/// A trait for objects that contribute actions to popup (context) menus.
///
/// In Ghidra, plugins can register `PopupActionProvider`s with the tool
/// to dynamically add items to context menus.
pub trait PopupActionProvider: fmt::Debug + Send + Sync {
    /// Return the actions to add to the popup menu for the given context.
    fn get_popup_actions(
        &self,
        context_provider: Option<ComponentProvider>,
    ) -> Vec<DockingAction>;
}

/// A closure-based popup action provider.
#[derive(Clone)]
pub struct ClosurePopupProvider {
    name: String,
    callback: Arc<dyn Fn(Option<ComponentProvider>) -> Vec<DockingAction> + Send + Sync>,
}

impl ClosurePopupProvider {
    /// Create a new closure-based popup provider.
    pub fn new(
        name: impl Into<String>,
        callback: Arc<dyn Fn(Option<ComponentProvider>) -> Vec<DockingAction> + Send + Sync>,
    ) -> Self {
        Self {
            name: name.into(),
            callback,
        }
    }
}

impl PopupActionProvider for ClosurePopupProvider {
    fn get_popup_actions(
        &self,
        context_provider: Option<ComponentProvider>,
    ) -> Vec<DockingAction> {
        (self.callback)(context_provider)
    }
}

impl fmt::Debug for ClosurePopupProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClosurePopupProvider")
            .field("name", &self.name)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// PopupActionManager
// ---------------------------------------------------------------------------

/// Manages popup action providers and assembles popup menus.
pub struct PopupActionManager {
    /// Registered popup action providers.
    providers: Vec<Box<dyn PopupActionProvider>>,
}

impl PopupActionManager {
    /// Create a new popup action manager.
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    /// Register a popup action provider.
    pub fn add_provider(&mut self, provider: Box<dyn PopupActionProvider>) {
        self.providers.push(provider);
    }

    /// Remove all providers.
    pub fn clear_providers(&mut self) {
        self.providers.clear();
    }

    /// Number of registered providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Collect all popup actions from all providers for the given context.
    pub fn get_popup_actions(
        &self,
        context_provider: Option<ComponentProvider>,
    ) -> Vec<DockingAction> {
        let mut actions = Vec::new();
        for provider in &self.providers {
            actions.extend(provider.get_popup_actions(context_provider));
        }
        actions
    }
}

impl Default for PopupActionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PopupActionManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PopupActionManager")
            .field("providers", &self.providers.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// MenuBarManager
// ---------------------------------------------------------------------------

/// Manages the global menu bar for the tool.
///
/// In Ghidra, `GlobalMenuAndToolBarManager` holds the set of menu groups
/// and assembles the menu bar from registered actions.  This Rust
/// equivalent provides the same core functionality.
#[derive(Debug, Default)]
pub struct MenuBarManager {
    /// Menu group name -> ordered list of action names.
    groups: HashMap<String, Vec<String>>,
    /// Whether the menu bar is visible.
    visible: bool,
}

impl MenuBarManager {
    /// Create a new menu bar manager.
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
            visible: true,
        }
    }

    /// Add an action to a menu group.
    pub fn add_to_group(
        &mut self,
        group: impl Into<String>,
        action_name: impl Into<String>,
    ) {
        self.groups
            .entry(group.into())
            .or_default()
            .push(action_name.into());
    }

    /// Remove an action from a menu group.
    pub fn remove_from_group(
        &mut self,
        group: &str,
        action_name: &str,
    ) -> bool {
        if let Some(actions) = self.groups.get_mut(group) {
            if let Some(pos) = actions.iter().position(|a| a == action_name) {
                actions.remove(pos);
                return true;
            }
        }
        false
    }

    /// Get all actions in a group.
    pub fn group_actions(&self, group: &str) -> Option<&Vec<String>> {
        self.groups.get(group)
    }

    /// Get all group names.
    pub fn group_names(&self) -> Vec<&str> {
        self.groups.keys().map(|k| k.as_str()).collect()
    }

    /// Whether the menu bar is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set the menu bar visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Remove an entire group.
    pub fn remove_group(&mut self, group: &str) -> Option<Vec<String>> {
        self.groups.remove(group)
    }

    /// Clear all groups.
    pub fn clear(&mut self) {
        self.groups.clear();
    }
}

// ---------------------------------------------------------------------------
// ToolBarManager
// ---------------------------------------------------------------------------

/// Manages a single toolbar.
#[derive(Debug)]
pub struct ToolBarManager {
    /// Toolbar name.
    pub name: String,
    /// Ordered action names.
    actions: Vec<String>,
    /// Whether the toolbar is visible.
    visible: bool,
}

impl ToolBarManager {
    /// Create a new toolbar manager.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            actions: Vec::new(),
            visible: true,
        }
    }

    /// Add an action to the toolbar.
    pub fn add_action(&mut self, action_name: impl Into<String>) {
        self.actions.push(action_name.into());
    }

    /// Remove an action from the toolbar.
    pub fn remove_action(&mut self, action_name: &str) -> bool {
        if let Some(pos) = self.actions.iter().position(|a| a == action_name) {
            self.actions.remove(pos);
            true
        } else {
            false
        }
    }

    /// Get the action names.
    pub fn actions(&self) -> &[String] {
        &self.actions
    }

    /// Whether the toolbar is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }
}

// ---------------------------------------------------------------------------
// WindowActionManager
// ---------------------------------------------------------------------------

/// Manages the "Window" menu actions that show/hide dockable components.
///
/// In Ghidra, each component provider gets a "Show/Hide" toggle action
/// in the Window menu.  This manager tracks those actions.
pub struct WindowActionManager {
    /// Map of provider -> action name.
    show_actions: HashMap<ComponentProvider, String>,
}

impl WindowActionManager {
    /// Create a new window action manager.
    pub fn new() -> Self {
        Self {
            show_actions: HashMap::new(),
        }
    }

    /// Register a show/hide action for a provider.
    pub fn register_action(
        &mut self,
        provider: ComponentProvider,
        action_name: impl Into<String>,
    ) {
        self.show_actions.insert(provider, action_name.into());
    }

    /// Unregister a show/hide action for a provider.
    pub fn unregister_action(&mut self, provider: &ComponentProvider) -> Option<String> {
        self.show_actions.remove(provider)
    }

    /// Get the action name for a provider.
    pub fn get_action_name(&self, provider: &ComponentProvider) -> Option<&str> {
        self.show_actions.get(provider).map(|s| s.as_str())
    }

    /// All registered providers.
    pub fn providers(&self) -> Vec<ComponentProvider> {
        self.show_actions.keys().copied().collect()
    }

    /// Number of registered actions.
    pub fn len(&self) -> usize {
        self.show_actions.len()
    }

    /// Whether no actions are registered.
    pub fn is_empty(&self) -> bool {
        self.show_actions.is_empty()
    }
}

impl Default for WindowActionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for WindowActionManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WindowActionManager")
            .field("count", &self.show_actions.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// DockingActionProxy — a proxy that delegates to another action
// ---------------------------------------------------------------------------

/// A proxy action that delegates to an underlying action.
///
/// In Ghidra, `DockingActionProxy` is used when the same conceptual
/// action needs to be registered in multiple locations (e.g. global
/// menu and local popup menu) but should share state.
#[derive(Debug, Clone)]
pub struct DockingActionProxy {
    /// The name of the action this proxy delegates to.
    pub delegate_name: String,
    /// The proxy's own name (may differ from delegate).
    pub proxy_name: String,
    /// Whether the proxy is currently enabled.
    pub enabled: bool,
}

impl DockingActionProxy {
    /// Create a new action proxy.
    pub fn new(
        proxy_name: impl Into<String>,
        delegate_name: impl Into<String>,
    ) -> Self {
        Self {
            delegate_name: delegate_name.into(),
            proxy_name: proxy_name.into(),
            enabled: true,
        }
    }

    /// Whether the proxy is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set enabled.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_actions_global() {
        let mut actions = DockingToolActions::new();
        actions.add_global_action(DockingAction::new("save", "Save"));
        actions.add_global_action(DockingAction::new("open", "Open"));

        assert_eq!(actions.global_actions().len(), 2);
        assert!(actions.get_global_action("save").is_some());
        assert!(actions.get_global_action("nonexistent").is_none());

        let removed = actions.remove_global_action("save");
        assert!(removed.is_some());
        assert!(actions.get_global_action("save").is_none());
    }

    #[test]
    fn test_tool_actions_local() {
        let mut actions = DockingToolActions::new();
        actions.add_local_action(
            ComponentProvider::ListingView,
            DockingAction::new("goto-addr", "Go To Address"),
        );
        actions.add_local_action(
            ComponentProvider::Console,
            DockingAction::new("run-script", "Run Script"),
        );

        let listing_actions = actions.local_actions(&ComponentProvider::ListingView);
        assert!(listing_actions.is_some());
        assert_eq!(listing_actions.unwrap().len(), 1);

        assert!(actions.local_actions(&ComponentProvider::References).is_none());
    }

    #[test]
    fn test_tool_actions_active() {
        let mut actions = DockingToolActions::new();
        actions.add_global_action(DockingAction::new("global1", "Global 1"));
        actions.add_local_action(
            ComponentProvider::Console,
            DockingAction::new("console1", "Console 1"),
        );

        // With Console focused: global + Console local = 2.
        let active = actions.active_actions(Some(&ComponentProvider::Console));
        assert_eq!(active.len(), 2);

        // With Listing focused: global only = 1.
        let active = actions.active_actions(Some(&ComponentProvider::ListingView));
        assert_eq!(active.len(), 1);

        // No focus: global only.
        let active = actions.active_actions(None);
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn test_tool_actions_remove_provider() {
        let mut actions = DockingToolActions::new();
        actions.add_local_action(
            ComponentProvider::Console,
            DockingAction::new("a1", "A1"),
        );
        let removed = actions.remove_provider_actions(&ComponentProvider::Console);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().len(), 1);
        assert!(actions
            .local_actions(&ComponentProvider::Console)
            .is_none());
    }

    #[test]
    fn test_tool_actions_placeholders() {
        let mut actions = DockingToolActions::new();
        actions.register_placeholder(DockingAction::new("future-action", "Future"));
        assert!(actions.get_placeholder("future-action").is_some());
        let removed = actions.remove_placeholder("future-action");
        assert!(removed.is_some());
        assert!(actions.get_placeholder("future-action").is_none());
    }

    #[test]
    fn test_tool_actions_total_count() {
        let mut actions = DockingToolActions::new();
        actions.add_global_action(DockingAction::new("g1", "G1"));
        actions.add_global_action(DockingAction::new("g2", "G2"));
        actions.add_local_action(
            ComponentProvider::Console,
            DockingAction::new("l1", "L1"),
        );
        actions.register_placeholder(DockingAction::new("p1", "P1"));
        assert_eq!(actions.total_count(), 4);
    }

    #[test]
    fn test_tool_actions_find() {
        let mut actions = DockingToolActions::new();
        actions.add_global_action(DockingAction::new("global", "Global"));
        actions.add_local_action(
            ComponentProvider::Console,
            DockingAction::new("local", "Local"),
        );

        assert!(actions.find_action("global").is_some());
        assert!(actions.find_action("local").is_some());
        assert!(actions.find_action("nonexistent").is_none());
    }

    #[test]
    fn test_popup_action_manager() {
        let mut mgr = PopupActionManager::new();
        assert_eq!(mgr.provider_count(), 0);

        mgr.add_provider(Box::new(ClosurePopupProvider::new(
            "test",
            Arc::new(|_ctx| {
                vec![DockingAction::new("popup-action", "Popup Action")]
            }),
        )));
        assert_eq!(mgr.provider_count(), 1);

        let actions = mgr.get_popup_actions(Some(ComponentProvider::Console));
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].name, "popup-action");
    }

    #[test]
    fn test_popup_action_manager_clear() {
        let mut mgr = PopupActionManager::new();
        mgr.add_provider(Box::new(ClosurePopupProvider::new(
            "p1",
            Arc::new(|_| vec![]),
        )));
        mgr.clear_providers();
        assert_eq!(mgr.provider_count(), 0);
    }

    #[test]
    fn test_menu_bar_manager() {
        let mut mgr = MenuBarManager::new();
        mgr.add_to_group("File", "New");
        mgr.add_to_group("File", "Open");
        mgr.add_to_group("File", "Save");
        mgr.add_to_group("Edit", "Undo");

        assert_eq!(mgr.group_actions("File").unwrap().len(), 3);
        assert_eq!(mgr.group_actions("Edit").unwrap().len(), 1);

        let names = mgr.group_names();
        assert_eq!(names.len(), 2);

        assert!(mgr.remove_from_group("File", "Open"));
        assert_eq!(mgr.group_actions("File").unwrap().len(), 2);
    }

    #[test]
    fn test_menu_bar_visibility() {
        let mut mgr = MenuBarManager::new();
        assert!(mgr.is_visible());
        mgr.set_visible(false);
        assert!(!mgr.is_visible());
    }

    #[test]
    fn test_toolbar_manager() {
        let mut tb = ToolBarManager::new("Main");
        tb.add_action("New");
        tb.add_action("Open");
        tb.add_action("Save");
        assert_eq!(tb.actions().len(), 3);

        assert!(tb.remove_action("Open"));
        assert_eq!(tb.actions().len(), 2);
        assert!(!tb.remove_action("nonexistent"));
    }

    #[test]
    fn test_window_action_manager() {
        let mut mgr = WindowActionManager::new();
        assert!(mgr.is_empty());

        mgr.register_action(ComponentProvider::Console, "ShowConsole");
        mgr.register_action(ComponentProvider::ListingView, "ShowListing");

        assert_eq!(mgr.len(), 2);
        assert_eq!(
            mgr.get_action_name(&ComponentProvider::Console),
            Some("ShowConsole")
        );
        assert!(mgr
            .providers()
            .contains(&ComponentProvider::Console));

        let removed = mgr.unregister_action(&ComponentProvider::Console);
        assert_eq!(removed, Some("ShowConsole".to_owned()));
        assert_eq!(mgr.len(), 1); // ListingView still registered
        mgr.unregister_action(&ComponentProvider::ListingView);
        assert!(mgr.is_empty());
    }

    #[test]
    fn test_docking_action_proxy() {
        let mut proxy = DockingActionProxy::new("proxy-1", "original-action");
        assert_eq!(proxy.proxy_name, "proxy-1");
        assert_eq!(proxy.delegate_name, "original-action");
        assert!(proxy.is_enabled());

        proxy.set_enabled(false);
        assert!(!proxy.is_enabled());
    }
}
