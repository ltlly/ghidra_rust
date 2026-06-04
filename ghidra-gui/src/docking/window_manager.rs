//! Window manager for the docking framework.
//!
//! Port of Ghidra's `DockingWindowManager`.  Manages the top-level
//! window hierarchy, component placeholders, and the mapping between
//! components and their window containers.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use super::action::DockingAction;
use super::component::{ComponentProvider, DockingComponent, WindowPosition};
use super::context::{ActionContext, ContextManager, DefaultActionContext};
use super::drop::{DropCode, DropState};
use super::layout::{DockArea, DockingLayout, SplitDirection, SplitNode};

// ---------------------------------------------------------------------------
// ComponentPlaceholder — tracks a component in the window hierarchy
// ---------------------------------------------------------------------------

/// Tracks a component's state within the window manager.
///
/// In Ghidra, a `ComponentPlaceholder` represents a component that
/// may or may not be currently instantiated.  The placeholder remembers
/// the provider, visibility, and position so it can be restored later.
#[derive(Debug, Clone)]
pub struct ComponentPlaceholder {
    /// The provider this placeholder represents.
    pub provider: ComponentProvider,
    /// Instance name (for multi-instance providers).
    pub instance_name: String,
    /// Whether the component is currently visible.
    pub visible: bool,
    /// The dock area this component is in.
    pub dock_area: Option<DockArea>,
    /// The tab group index (if tabbed).
    pub tab_group: Option<usize>,
    /// The tab index within the group (if tabbed).
    pub tab_index: Option<usize>,
    /// Whether the component is floating (in a detached window).
    pub floating: bool,
    /// Window position for floating components.
    pub float_position: Option<(f32, f32)>,
    /// Window size for floating components.
    pub float_size: Option<(f32, f32)>,
}

impl ComponentPlaceholder {
    /// Create a new component placeholder.
    pub fn new(
        provider: ComponentProvider,
        instance_name: impl Into<String>,
    ) -> Self {
        Self {
            provider,
            instance_name: instance_name.into(),
            visible: false,
            dock_area: None,
            tab_group: None,
            tab_index: None,
            floating: false,
            float_position: None,
            float_size: None,
        }
    }

    /// Create a placeholder for a visible component in a dock area.
    pub fn docked(
        provider: ComponentProvider,
        instance_name: impl Into<String>,
        area: DockArea,
    ) -> Self {
        Self {
            dock_area: Some(area),
            visible: true,
            ..Self::new(provider, instance_name)
        }
    }

    /// Create a placeholder for a floating component.
    pub fn floating(
        provider: ComponentProvider,
        instance_name: impl Into<String>,
        x: f32,
        y: f32,
        width: f32,
        height: f32,
    ) -> Self {
        Self {
            floating: true,
            float_position: Some((x, y)),
            float_size: Some((width, height)),
            visible: true,
            ..Self::new(provider, instance_name)
        }
    }

    /// Get the instance key (provider + name).
    pub fn instance_key(&self) -> (ComponentProvider, String) {
        (self.provider, self.instance_name.clone())
    }
}

// ---------------------------------------------------------------------------
// WindowContainer — a logical window that holds components
// ---------------------------------------------------------------------------

/// Represents a top-level or detached window in the docking framework.
#[derive(Debug, Clone)]
pub struct WindowContainer {
    /// Window identifier.
    pub id: String,
    /// Whether this is the main (primary) window.
    pub is_main: bool,
    /// Components in this window (ordered).
    pub components: Vec<(ComponentProvider, String)>,
    /// Window position (x, y, width, height).
    pub bounds: (f32, f32, f32, f32),
    /// Whether the window is visible.
    pub visible: bool,
}

impl WindowContainer {
    /// Create a new window container.
    pub fn new(id: impl Into<String>, is_main: bool) -> Self {
        Self {
            id: id.into(),
            is_main,
            components: Vec::new(),
            bounds: (0.0, 0.0, 800.0, 600.0),
            visible: true,
        }
    }

    /// Add a component to this window.
    pub fn add_component(
        &mut self,
        provider: ComponentProvider,
        instance_name: impl Into<String>,
    ) {
        self.components
            .push((provider, instance_name.into()));
    }

    /// Remove a component from this window.
    pub fn remove_component(
        &mut self,
        provider: &ComponentProvider,
        instance_name: &str,
    ) -> bool {
        if let Some(pos) = self
            .components
            .iter()
            .position(|(p, n)| p == provider && n == instance_name)
        {
            self.components.remove(pos);
            true
        } else {
            false
        }
    }

    /// Whether this window is empty (no components).
    pub fn is_empty(&self) -> bool {
        self.components.is_empty()
    }

    /// Number of components in this window.
    pub fn component_count(&self) -> usize {
        self.components.len()
    }
}

// ---------------------------------------------------------------------------
// DockingWindowManager
// ---------------------------------------------------------------------------

/// The window manager for the docking framework.
///
/// Manages the hierarchy of windows and the mapping between
/// component providers and their window containers.
pub struct DockingWindowManager {
    /// All registered component placeholders.
    placeholders: HashMap<(ComponentProvider, String), ComponentPlaceholder>,
    /// Window containers.
    windows: Vec<WindowContainer>,
    /// The currently focused component (provider, instance name).
    focused: Option<(ComponentProvider, String)>,
    /// The layout being used.
    layout: DockingLayout,
    /// Context manager for dispatching context changes.
    context_manager: ContextManager,
    /// The current action context.
    current_context: DefaultActionContext,
    /// Drag-and-drop state.
    drop_state: DropState,
    /// Registered docking actions.
    actions: Vec<DockingAction>,
}

impl DockingWindowManager {
    /// Create a new window manager with the given layout.
    pub fn new(layout: DockingLayout) -> Self {
        Self {
            placeholders: HashMap::new(),
            windows: Vec::new(),
            focused: None,
            layout,
            context_manager: ContextManager::new(),
            current_context: DefaultActionContext::new(),
            drop_state: DropState::new(),
            actions: Vec::new(),
        }
    }

    // ---------------------------------------------------------------
    // Component placeholder management
    // ---------------------------------------------------------------

    /// Register a component placeholder.
    pub fn add_placeholder(&mut self, placeholder: ComponentPlaceholder) {
        let key = placeholder.instance_key();
        self.placeholders.insert(key, placeholder);
    }

    /// Remove a component placeholder.
    pub fn remove_placeholder(
        &mut self,
        provider: &ComponentProvider,
        instance_name: &str,
    ) -> Option<ComponentPlaceholder> {
        self.placeholders
            .remove(&(*provider, instance_name.to_owned()))
    }

    /// Get a placeholder.
    pub fn get_placeholder(
        &self,
        provider: &ComponentProvider,
        instance_name: &str,
    ) -> Option<&ComponentPlaceholder> {
        self.placeholders
            .get(&(*provider, instance_name.to_owned()))
    }

    /// Get a mutable placeholder.
    pub fn get_placeholder_mut(
        &mut self,
        provider: &ComponentProvider,
        instance_name: &str,
    ) -> Option<&mut ComponentPlaceholder> {
        self.placeholders
            .get_mut(&(*provider, instance_name.to_owned()))
    }

    /// All registered placeholders.
    pub fn placeholders(&self) -> &HashMap<(ComponentProvider, String), ComponentPlaceholder> {
        &self.placeholders
    }

    /// All visible placeholders.
    pub fn visible_placeholders(&self) -> Vec<&ComponentPlaceholder> {
        self.placeholders.values().filter(|p| p.visible).collect()
    }

    // ---------------------------------------------------------------
    // Window container management
    // ---------------------------------------------------------------

    /// Add a window container.
    pub fn add_window(&mut self, window: WindowContainer) {
        self.windows.push(window);
    }

    /// Remove a window container by ID.
    pub fn remove_window(&mut self, id: &str) -> Option<WindowContainer> {
        if let Some(pos) = self.windows.iter().position(|w| w.id == id) {
            Some(self.windows.remove(pos))
        } else {
            None
        }
    }

    /// Get a window container by ID.
    pub fn get_window(&self, id: &str) -> Option<&WindowContainer> {
        self.windows.iter().find(|w| w.id == id)
    }

    /// Get a mutable window container by ID.
    pub fn get_window_mut(&mut self, id: &str) -> Option<&mut WindowContainer> {
        self.windows.iter_mut().find(|w| w.id == id)
    }

    /// Get the main window.
    pub fn main_window(&self) -> Option<&WindowContainer> {
        self.windows.iter().find(|w| w.is_main)
    }

    /// All window containers.
    pub fn windows(&self) -> &[WindowContainer] {
        &self.windows
    }

    /// Number of window containers.
    pub fn window_count(&self) -> usize {
        self.windows.len()
    }

    // ---------------------------------------------------------------
    // Focus
    // ---------------------------------------------------------------

    /// Set focus to a component.
    pub fn set_focus(&mut self, provider: ComponentProvider, instance_name: impl Into<String>) {
        let name = instance_name.into();
        self.focused = Some((provider, name));

        // Update context.
        self.current_context = DefaultActionContext::with_provider(provider);
        self.context_manager
            .context_changed(&self.current_context);
    }

    /// Get the currently focused component.
    pub fn get_focused(&self) -> Option<&(ComponentProvider, String)> {
        self.focused.as_ref()
    }

    /// Clear focus.
    pub fn clear_focus(&mut self) {
        self.focused = None;
    }

    // ---------------------------------------------------------------
    // Show / hide components
    // ---------------------------------------------------------------

    /// Show a component.
    pub fn show_component(
        &mut self,
        provider: ComponentProvider,
        instance_name: &str,
    ) {
        if let Some(placeholder) = self
            .placeholders
            .get_mut(&(provider, instance_name.to_owned()))
        {
            placeholder.visible = true;
        }
        // Update layout.
        self.layout.show(provider);
    }

    /// Hide a component.
    pub fn hide_component(
        &mut self,
        provider: ComponentProvider,
        instance_name: &str,
    ) {
        if let Some(placeholder) = self
            .placeholders
            .get_mut(&(provider, instance_name.to_owned()))
        {
            placeholder.visible = false;
        }
        self.layout.hide(provider);
    }

    /// Toggle component visibility.
    pub fn toggle_component(
        &mut self,
        provider: ComponentProvider,
        instance_name: &str,
    ) {
        let currently_visible = self
            .placeholders
            .get(&(provider, instance_name.to_owned()))
            .map(|p| p.visible)
            .unwrap_or(false);

        if currently_visible {
            self.hide_component(provider, instance_name);
        } else {
            self.show_component(provider, instance_name);
        }
    }

    /// Whether a component is currently visible.
    pub fn is_component_visible(
        &self,
        provider: &ComponentProvider,
        instance_name: &str,
    ) -> bool {
        self.placeholders
            .get(&(*provider, instance_name.to_owned()))
            .map(|p| p.visible)
            .unwrap_or(false)
    }

    /// Whether this is the last component in a given window.
    pub fn is_last_component_in_window(
        &self,
        provider: &ComponentProvider,
        instance_name: &str,
    ) -> bool {
        for window in &self.windows {
            if window
                .components
                .iter()
                .any(|(p, n)| p == provider && n == instance_name)
            {
                // Count visible components in this window.
                let visible_count = window
                    .components
                    .iter()
                    .filter(|(p, n)| self.is_component_visible(p, n))
                    .count();
                return visible_count <= 1;
            }
        }
        false
    }

    // ---------------------------------------------------------------
    // Context
    // ---------------------------------------------------------------

    /// Get the current action context.
    pub fn current_context(&self) -> &DefaultActionContext {
        &self.current_context
    }

    /// Set the current action context.
    pub fn set_context(&mut self, context: DefaultActionContext) {
        self.current_context = context;
        self.context_manager
            .context_changed(&self.current_context);
    }

    /// Add a context listener.
    pub fn add_context_listener(
        &mut self,
        listener: Box<dyn super::context::DockingContextListener>,
    ) {
        self.context_manager.add_listener(listener);
    }

    /// Clear all context listeners.
    pub fn clear_context_listeners(&mut self) {
        self.context_manager.clear_listeners();
    }

    // ---------------------------------------------------------------
    // Drag-and-drop
    // ---------------------------------------------------------------

    /// Get the current drop state.
    pub fn drop_state(&self) -> &DropState {
        &self.drop_state
    }

    /// Get a mutable reference to the drop state.
    pub fn drop_state_mut(&mut self) -> &mut DropState {
        &mut self.drop_state
    }

    // ---------------------------------------------------------------
    // Actions
    // ---------------------------------------------------------------

    /// Register an action.
    pub fn add_action(&mut self, action: DockingAction) {
        self.actions.push(action);
    }

    /// Remove an action by name.
    pub fn remove_action(&mut self, name: &str) -> Option<DockingAction> {
        if let Some(pos) = self.actions.iter().position(|a| a.name == name) {
            Some(self.actions.remove(pos))
        } else {
            None
        }
    }

    /// All registered actions.
    pub fn actions(&self) -> &[DockingAction] {
        &self.actions
    }

    // ---------------------------------------------------------------
    // Layout
    // ---------------------------------------------------------------

    /// Get the layout.
    pub fn layout(&self) -> &DockingLayout {
        &self.layout
    }

    /// Get a mutable reference to the layout.
    pub fn layout_mut(&mut self) -> &mut DockingLayout {
        &mut self.layout
    }

    /// Set the layout.
    pub fn set_layout(&mut self, layout: DockingLayout) {
        self.layout = layout;
    }
}

impl Default for DockingWindowManager {
    fn default() -> Self {
        Self::new(DockingLayout::default())
    }
}

impl fmt::Debug for DockingWindowManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DockingWindowManager")
            .field("placeholders", &self.placeholders.len())
            .field("windows", &self.windows.len())
            .field("focused", &self.focused)
            .field("actions", &self.actions.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_placeholder_new() {
        let p = ComponentPlaceholder::new(ComponentProvider::Console, "python");
        assert_eq!(p.provider, ComponentProvider::Console);
        assert_eq!(p.instance_name, "python");
        assert!(!p.visible);
        assert!(p.dock_area.is_none());
        assert!(!p.floating);
    }

    #[test]
    fn test_placeholder_docked() {
        let p = ComponentPlaceholder::docked(
            ComponentProvider::ListingView,
            "listing",
            DockArea::Center,
        );
        assert!(p.visible);
        assert_eq!(p.dock_area, Some(DockArea::Center));
    }

    #[test]
    fn test_placeholder_floating() {
        let p = ComponentPlaceholder::floating(
            ComponentProvider::Console,
            "console",
            100.0,
            200.0,
            400.0,
            300.0,
        );
        assert!(p.floating);
        assert!(p.visible);
        assert_eq!(p.float_position, Some((100.0, 200.0)));
        assert_eq!(p.float_size, Some((400.0, 300.0)));
    }

    #[test]
    fn test_window_container() {
        let mut w = WindowContainer::new("main", true);
        assert!(w.is_main);
        assert!(w.is_empty());

        w.add_component(ComponentProvider::ListingView, "listing");
        w.add_component(ComponentProvider::Console, "console");
        assert_eq!(w.component_count(), 2);

        assert!(w.remove_component(&ComponentProvider::Console, "console"));
        assert_eq!(w.component_count(), 1);
        assert!(!w.remove_component(&ComponentProvider::Console, "console"));
    }

    #[test]
    fn test_window_manager_components() {
        let mut wm = DockingWindowManager::default();

        wm.add_placeholder(ComponentPlaceholder::new(
            ComponentProvider::Console,
            "python",
        ));
        assert!(wm
            .get_placeholder(&ComponentProvider::Console, "python")
            .is_some());
        assert!(wm
            .get_placeholder(&ComponentProvider::Console, "other")
            .is_none());

        assert!(wm
            .get_placeholder_mut(&ComponentProvider::Console, "python")
            .is_some());

        let removed = wm.remove_placeholder(&ComponentProvider::Console, "python");
        assert!(removed.is_some());
        assert!(wm
            .get_placeholder(&ComponentProvider::Console, "python")
            .is_none());
    }

    #[test]
    fn test_window_manager_visible_placeholders() {
        let mut wm = DockingWindowManager::default();
        wm.add_placeholder(ComponentPlaceholder::docked(
            ComponentProvider::Console,
            "c",
            DockArea::Bottom,
        ));
        wm.add_placeholder(ComponentPlaceholder::new(
            ComponentProvider::ListingView,
            "l",
        ));

        assert_eq!(wm.visible_placeholders().len(), 1);
    }

    #[test]
    fn test_window_manager_windows() {
        let mut wm = DockingWindowManager::default();
        wm.add_window(WindowContainer::new("main", true));
        wm.add_window(WindowContainer::new("floating-1", false));

        assert_eq!(wm.window_count(), 2);
        assert!(wm.main_window().is_some());
        assert_eq!(wm.main_window().unwrap().id, "main");

        wm.remove_window("floating-1");
        assert_eq!(wm.window_count(), 1);
    }

    #[test]
    fn test_window_manager_focus() {
        let mut wm = DockingWindowManager::default();
        assert!(wm.get_focused().is_none());

        wm.set_focus(ComponentProvider::ListingView, "listing");
        let focused = wm.get_focused().unwrap();
        assert_eq!(focused.0, ComponentProvider::ListingView);
        assert_eq!(focused.1, "listing");

        wm.clear_focus();
        assert!(wm.get_focused().is_none());
    }

    #[test]
    fn test_window_manager_show_hide() {
        let mut wm = DockingWindowManager::default();
        wm.add_placeholder(ComponentPlaceholder::new(
            ComponentProvider::Console,
            "console",
        ));

        assert!(!wm.is_component_visible(&ComponentProvider::Console, "console"));

        wm.show_component(ComponentProvider::Console, "console");
        assert!(wm.is_component_visible(&ComponentProvider::Console, "console"));

        wm.hide_component(ComponentProvider::Console, "console");
        assert!(!wm.is_component_visible(&ComponentProvider::Console, "console"));
    }

    #[test]
    fn test_window_manager_toggle() {
        let mut wm = DockingWindowManager::default();
        wm.add_placeholder(ComponentPlaceholder::new(
            ComponentProvider::Console,
            "console",
        ));

        wm.toggle_component(ComponentProvider::Console, "console");
        assert!(wm.is_component_visible(&ComponentProvider::Console, "console"));

        wm.toggle_component(ComponentProvider::Console, "console");
        assert!(!wm.is_component_visible(&ComponentProvider::Console, "console"));
    }

    #[test]
    fn test_window_manager_last_component() {
        let mut wm = DockingWindowManager::default();
        let mut win = WindowContainer::new("main", true);
        win.add_component(ComponentProvider::ListingView, "listing");
        win.add_component(ComponentProvider::Console, "console");
        wm.add_window(win);

        // Both placeholders exist but only one is visible.
        wm.add_placeholder(ComponentPlaceholder::docked(
            ComponentProvider::ListingView,
            "listing",
            DockArea::Center,
        ));
        wm.add_placeholder(ComponentPlaceholder::new(
            ComponentProvider::Console,
            "console",
        ));

        // Console is not visible, so Listing is the last visible.
        assert!(wm.is_last_component_in_window(
            &ComponentProvider::ListingView,
            "listing"
        ));
        // Console is not visible, so it's also the "last" (being 0).
        assert!(wm.is_last_component_in_window(
            &ComponentProvider::Console,
            "console"
        ));
    }

    #[test]
    fn test_window_manager_actions() {
        let mut wm = DockingWindowManager::default();
        wm.add_action(DockingAction::new("test", "Test"));
        assert_eq!(wm.actions().len(), 1);

        let removed = wm.remove_action("test");
        assert!(removed.is_some());
        assert!(wm.actions().is_empty());
    }

    #[test]
    fn test_window_manager_context() {
        let mut wm = DockingWindowManager::default();
        assert!(wm.current_context().is_default_context());

        wm.set_focus(ComponentProvider::Console, "console");
        assert_eq!(
            wm.current_context().get_component_provider(),
            Some(ComponentProvider::Console)
        );
    }
}
