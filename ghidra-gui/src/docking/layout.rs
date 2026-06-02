//! Docking layout management.
//!
//! The [`DockingLayout`] is the persisted representation of window positions,
//! tab groups, toolbars, and visibility state.  It can be serialized to JSON
//! (or, in the future, an XML-compatible format) and restored across sessions.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::component::{ComponentProvider, WindowPosition};

// ---------------------------------------------------------------------------
// DockingWindowPlacement
// ---------------------------------------------------------------------------

/// Persisted state for a single dockable window.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DockingWindowPlacement {
    /// Where the window sits in the layout.
    pub position: WindowPosition,
    /// Preferred (width, height) in pixels.
    pub size: (f32, f32),
    /// Whether the window is shown.
    pub visible: bool,
    /// Whether the window is floating (detached).
    pub floating: bool,
    /// Whether the window is iconified / minimized.
    pub minimized: bool,
    /// Whether the window is maximized in its dock region.
    pub maximized: bool,
    /// Split ratio (0.0 – 1.0) when sharing a split region with another
    /// window.
    pub split_ratio: f32,
}

impl Default for DockingWindowPlacement {
    fn default() -> Self {
        Self {
            position: WindowPosition::default(),
            size: (300.0, 200.0),
            visible: true,
            floating: false,
            minimized: false,
            maximized: false,
            split_ratio: 0.5,
        }
    }
}

impl DockingWindowPlacement {
    /// Create a placement docked at the given position.
    pub fn docked(position: WindowPosition) -> Self {
        Self {
            position,
            ..Default::default()
        }
    }

    /// Create a floating placement at the given coordinates.
    pub fn floating(x: f32, y: f32, width: f32, height: f32) -> Self {
        Self {
            position: WindowPosition::Custom {
                x,
                y,
                width,
                height,
            },
            floating: true,
            size: (width, height),
            ..Default::default()
        }
    }

    /// Convenience — set the size.
    pub fn with_size(mut self, width: f32, height: f32) -> Self {
        self.size = (width, height);
        self
    }

    /// Convenience — hide the window.
    pub fn hidden(mut self) -> Self {
        self.visible = false;
        self
    }
}

// ---------------------------------------------------------------------------
// TabGroup
// ---------------------------------------------------------------------------

/// A collection of providers stacked in a tabbed group at a given position.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TabGroup {
    /// Providers in this tab group (ordered).
    pub tabs: Vec<ComponentProvider>,
    /// Index of the currently-selected tab.
    pub active_tab: usize,
    /// Where the tab group is docked.
    pub position: WindowPosition,
}

impl TabGroup {
    /// Create a new tab group.
    pub fn new(tabs: Vec<ComponentProvider>, position: WindowPosition) -> Self {
        Self {
            tabs,
            active_tab: 0,
            position,
        }
    }

    /// Select a tab by index.  Returns `false` if the index is out of
    /// bounds.
    pub fn select_tab(&mut self, index: usize) -> bool {
        if index < self.tabs.len() {
            self.active_tab = index;
            true
        } else {
            false
        }
    }

    /// Add a provider to this tab group.
    pub fn add_tab(&mut self, provider: ComponentProvider) {
        self.tabs.push(provider);
    }

    /// Remove a provider from this tab group, returning `true` if it was
    /// found and removed.
    pub fn remove_tab(&mut self, provider: &ComponentProvider) -> bool {
        if let Some(pos) = self.tabs.iter().position(|p| p == provider) {
            self.tabs.remove(pos);
            // Adjust active_tab so it stays valid.
            if self.active_tab >= self.tabs.len() && !self.tabs.is_empty() {
                self.active_tab = self.tabs.len() - 1;
            }
            true
        } else {
            false
        }
    }

    /// Returns `true` when this group has no tabs.
    pub fn is_empty(&self) -> bool {
        self.tabs.is_empty()
    }
}

// ---------------------------------------------------------------------------
// ToolbarConfig
// ---------------------------------------------------------------------------

/// Persisted toolbar configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolbarConfig {
    /// Display name for the toolbar.
    pub name: String,
    /// Ordered list of action names shown on this toolbar.
    pub actions: Vec<String>,
    /// Where the toolbar is docked.
    pub position: WindowPosition,
}

impl ToolbarConfig {
    /// Create a new toolbar config.
    pub fn new(name: impl Into<String>, actions: Vec<String>, position: WindowPosition) -> Self {
        Self {
            name: name.into(),
            actions,
            position,
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
}

// ---------------------------------------------------------------------------
// DockingLayout
// ---------------------------------------------------------------------------

/// The persisted, serializable docking layout for a tool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DockingLayout {
    /// Placement for every known provider window.
    #[serde(default)]
    pub windows: HashMap<ComponentProvider, DockingWindowPlacement>,
    /// Tab groups.
    #[serde(default)]
    pub tabs: Vec<TabGroup>,
    /// Toolbar configurations.
    #[serde(default)]
    pub toolbars: Vec<ToolbarConfig>,
}

impl DockingLayout {
    // ---------------------------------------------------------------
    // Construction
    // ---------------------------------------------------------------

    /// Create an empty layout.
    pub fn new() -> Self {
        Self {
            windows: HashMap::new(),
            tabs: Vec::new(),
            toolbars: Vec::new(),
        }
    }

    /// Create a Ghidra-inspired default layout with commonly-used windows
    /// pre-placed.
    pub fn default_layout() -> Self {
        let mut layout = Self::new();

        // --- Center area (main tab group) ---
        layout.add_window(
            ComponentProvider::ListingView,
            DockingWindowPlacement::docked(WindowPosition::Center).with_size(600.0, 400.0),
        );

        // --- Right side ---
        layout.add_window(
            ComponentProvider::DecompilerView,
            DockingWindowPlacement::docked(WindowPosition::Right).with_size(500.0, 400.0),
        );
        layout.add_window(
            ComponentProvider::DataTypeManager,
            DockingWindowPlacement::docked(WindowPosition::Right).with_size(350.0, 300.0),
        );

        // --- Left side ---
        layout.add_window(
            ComponentProvider::SymbolTree,
            DockingWindowPlacement::docked(WindowPosition::Left).with_size(300.0, 400.0),
        );
        layout.add_window(
            ComponentProvider::ProgramTree,
            DockingWindowPlacement::docked(WindowPosition::Left).with_size(300.0, 300.0),
        );

        // --- Bottom ---
        layout.add_window(
            ComponentProvider::Console,
            DockingWindowPlacement::docked(WindowPosition::Bottom).with_size(600.0, 150.0),
        );
        layout.add_window(
            ComponentProvider::BytesView,
            DockingWindowPlacement::docked(WindowPosition::Bottom).with_size(400.0, 150.0),
        );

        // --- Tab groups ---
        layout.tabs.push(TabGroup::new(
            vec![ComponentProvider::ListingView, ComponentProvider::Console],
            WindowPosition::Center,
        ));

        layout.tabs.push(TabGroup::new(
            vec![
                ComponentProvider::DecompilerView,
                ComponentProvider::DataTypeManager,
                ComponentProvider::FunctionGraph,
            ],
            WindowPosition::Right,
        ));

        layout.tabs.push(TabGroup::new(
            vec![
                ComponentProvider::SymbolTree,
                ComponentProvider::ProgramTree,
                ComponentProvider::Bookmarks,
                ComponentProvider::SearchResults,
            ],
            WindowPosition::Left,
        ));

        layout.tabs.push(TabGroup::new(
            vec![ComponentProvider::BytesView, ComponentProvider::MemoryMap],
            WindowPosition::Bottom,
        ));

        // --- Default toolbars ---
        layout.toolbars.push(ToolbarConfig::new(
            "Main",
            vec![
                "NewProject".into(),
                "OpenProject".into(),
                "Save".into(),
                "Undo".into(),
                "Redo".into(),
                "Analyze".into(),
            ],
            WindowPosition::Top,
        ));

        layout.toolbars.push(ToolbarConfig::new(
            "Navigation",
            vec![
                "GoTo".into(),
                "Back".into(),
                "Forward".into(),
                "Refresh".into(),
            ],
            WindowPosition::Top,
        ));

        layout
    }

    // ---------------------------------------------------------------
    // Window management
    // ---------------------------------------------------------------

    /// Insert or update a window placement.
    pub fn add_window(&mut self, provider: ComponentProvider, placement: DockingWindowPlacement) {
        self.windows.insert(provider, placement);
    }

    /// Remove a window from the layout.
    pub fn remove_window(
        &mut self,
        provider: &ComponentProvider,
    ) -> Option<DockingWindowPlacement> {
        self.windows.remove(provider)
    }

    /// Look up the placement for a provider.
    pub fn get_window(&self, provider: &ComponentProvider) -> Option<&DockingWindowPlacement> {
        self.windows.get(provider)
    }

    /// Look up a mutable placement reference.
    pub fn get_window_mut(
        &mut self,
        provider: &ComponentProvider,
    ) -> Option<&mut DockingWindowPlacement> {
        self.windows.get_mut(provider)
    }

    /// Set the dock position for a provider window.
    pub fn set_position(&mut self, provider: ComponentProvider, pos: WindowPosition) {
        if let Some(placement) = self.windows.get_mut(&provider) {
            placement.position = pos;
        }
    }

    /// Toggle visibility of a provider window.
    pub fn toggle(&mut self, provider: ComponentProvider) {
        if let Some(placement) = self.windows.get_mut(&provider) {
            placement.visible = !placement.visible;
        }
    }

    /// Show a provider window.
    pub fn show(&mut self, provider: ComponentProvider) {
        if let Some(placement) = self.windows.get_mut(&provider) {
            placement.visible = true;
            placement.minimized = false;
        }
    }

    /// Hide a provider window.
    pub fn hide(&mut self, provider: ComponentProvider) {
        if let Some(placement) = self.windows.get_mut(&provider) {
            placement.visible = false;
        }
    }

    /// Minimize a provider window.
    pub fn minimize(&mut self, provider: ComponentProvider) {
        if let Some(placement) = self.windows.get_mut(&provider) {
            placement.minimized = true;
        }
    }

    /// Maximize / restore a provider window.
    pub fn maximize(&mut self, provider: ComponentProvider) {
        if let Some(placement) = self.windows.get_mut(&provider) {
            placement.maximized = !placement.maximized;
        }
    }

    /// Set the split ratio for a provider window.
    pub fn set_split_ratio(&mut self, provider: ComponentProvider, ratio: f32) {
        if let Some(placement) = self.windows.get_mut(&provider) {
            placement.split_ratio = ratio.clamp(0.0, 1.0);
        }
    }

    /// Return all visible windows ordered by position (top → bottom →
    /// left → right → center).
    pub fn visible_windows(&self) -> Vec<(&ComponentProvider, &DockingWindowPlacement)> {
        let mut windows: Vec<_> = self
            .windows
            .iter()
            .filter(|(_, p)| p.visible && !p.minimized)
            .collect();
        windows.sort_by_key(|(_, p)| position_order(&p.position));
        windows
    }

    // ---------------------------------------------------------------
    // Tab group management
    // ---------------------------------------------------------------

    /// Add a tab group.
    pub fn add_tab_group(&mut self, group: TabGroup) {
        self.tabs.push(group);
    }

    /// Remove a tab group by index.
    pub fn remove_tab_group(&mut self, index: usize) -> Option<TabGroup> {
        if index < self.tabs.len() {
            Some(self.tabs.remove(index))
        } else {
            None
        }
    }

    /// Set the active tab in a tab group.
    pub fn set_active_tab(&mut self, tab_group_index: usize, tab_index: usize) -> bool {
        self.tabs
            .get_mut(tab_group_index)
            .map(|group| group.select_tab(tab_index))
            .unwrap_or(false)
    }

    // ---------------------------------------------------------------
    // Toolbar management
    // ---------------------------------------------------------------

    /// Add a toolbar configuration.
    pub fn add_toolbar(&mut self, toolbar: ToolbarConfig) {
        self.toolbars.push(toolbar);
    }

    /// Remove a toolbar by name.
    pub fn remove_toolbar(&mut self, name: &str) -> bool {
        if let Some(pos) = self.toolbars.iter().position(|t| t.name == name) {
            self.toolbars.remove(pos);
            true
        } else {
            false
        }
    }

    // ---------------------------------------------------------------
    // Persistence
    // ---------------------------------------------------------------

    /// Serialize the layout to a JSON string.
    pub fn save(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| {
            log::error!("Failed to serialize docking layout: {}", e);
            "{}".to_string()
        })
    }

    /// Deserialize a layout from a JSON string (the parameter is named
    /// `xml` for Ghidra compatibility but the actual format is JSON).
    pub fn load(xml: &str) -> Result<Self, anyhow::Error> {
        // Try to parse as JSON first; fall back to empty layout on failure.
        serde_json::from_str(xml).map_err(|e| {
            anyhow::anyhow!(
                "Failed to deserialize docking layout: {}. Input length: {}",
                e,
                xml.len()
            )
        })
    }

    /// Reset the entire layout to the default.
    pub fn reset_to_default(&mut self) {
        *self = Self::default_layout();
    }
}

impl Default for DockingLayout {
    fn default() -> Self {
        Self::default_layout()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Assign a sort key for window position so panels render in a consistent
/// order.
fn position_order(pos: &WindowPosition) -> u8 {
    match pos {
        WindowPosition::Top => 0,
        WindowPosition::Bottom => 1,
        WindowPosition::Left => 2,
        WindowPosition::Right => 3,
        WindowPosition::Center => 4,
        WindowPosition::Custom { .. } => 5,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_placement(pos: WindowPosition) -> DockingWindowPlacement {
        DockingWindowPlacement {
            position: pos,
            size: (200.0, 100.0),
            visible: true,
            floating: false,
            minimized: false,
            maximized: false,
            split_ratio: 0.5,
        }
    }

    #[test]
    fn test_add_get_remove_window() {
        let mut layout = DockingLayout::new();
        assert!(layout.get_window(&ComponentProvider::Console).is_none());

        layout.add_window(
            ComponentProvider::Console,
            make_placement(WindowPosition::Bottom),
        );
        let p = layout.get_window(&ComponentProvider::Console).unwrap();
        assert_eq!(p.position, WindowPosition::Bottom);
        assert!(p.visible);

        let removed = layout.remove_window(&ComponentProvider::Console);
        assert!(removed.is_some());
        assert!(layout.get_window(&ComponentProvider::Console).is_none());
    }

    #[test]
    fn test_toggle_visibility() {
        let mut layout = DockingLayout::new();
        layout.add_window(
            ComponentProvider::SymbolTree,
            make_placement(WindowPosition::Left),
        );

        assert!(
            layout
                .get_window(&ComponentProvider::SymbolTree)
                .unwrap()
                .visible
        );
        layout.toggle(ComponentProvider::SymbolTree);
        assert!(
            !layout
                .get_window(&ComponentProvider::SymbolTree)
                .unwrap()
                .visible
        );
        layout.toggle(ComponentProvider::SymbolTree);
        assert!(
            layout
                .get_window(&ComponentProvider::SymbolTree)
                .unwrap()
                .visible
        );
    }

    #[test]
    fn test_show_hide_minimize() {
        let mut layout = DockingLayout::new();
        layout.add_window(
            ComponentProvider::Console,
            make_placement(WindowPosition::Bottom),
        );

        layout.hide(ComponentProvider::Console);
        assert!(
            !layout
                .get_window(&ComponentProvider::Console)
                .unwrap()
                .visible
        );

        layout.show(ComponentProvider::Console);
        assert!(
            layout
                .get_window(&ComponentProvider::Console)
                .unwrap()
                .visible
        );

        layout.minimize(ComponentProvider::Console);
        assert!(
            layout
                .get_window(&ComponentProvider::Console)
                .unwrap()
                .minimized
        );

        layout.show(ComponentProvider::Console);
        assert!(
            !layout
                .get_window(&ComponentProvider::Console)
                .unwrap()
                .minimized
        );
    }

    #[test]
    fn test_maximize_toggle() {
        let mut layout = DockingLayout::new();
        layout.add_window(
            ComponentProvider::ListingView,
            make_placement(WindowPosition::Center),
        );

        assert!(
            !layout
                .get_window(&ComponentProvider::ListingView)
                .unwrap()
                .maximized
        );
        layout.maximize(ComponentProvider::ListingView);
        assert!(
            layout
                .get_window(&ComponentProvider::ListingView)
                .unwrap()
                .maximized
        );
        layout.maximize(ComponentProvider::ListingView);
        assert!(
            !layout
                .get_window(&ComponentProvider::ListingView)
                .unwrap()
                .maximized
        );
    }

    #[test]
    fn test_set_position() {
        let mut layout = DockingLayout::new();
        layout.add_window(
            ComponentProvider::DecompilerView,
            make_placement(WindowPosition::Right),
        );
        layout.set_position(ComponentProvider::DecompilerView, WindowPosition::Left);
        assert_eq!(
            layout
                .get_window(&ComponentProvider::DecompilerView)
                .unwrap()
                .position,
            WindowPosition::Left
        );
    }

    #[test]
    fn test_set_split_ratio() {
        let mut layout = DockingLayout::new();
        layout.add_window(
            ComponentProvider::ListingView,
            make_placement(WindowPosition::Center),
        );
        layout.set_split_ratio(ComponentProvider::ListingView, 0.75);
        let ratio = layout
            .get_window(&ComponentProvider::ListingView)
            .unwrap()
            .split_ratio;
        assert!((ratio - 0.75).abs() < f32::EPSILON);

        // Out-of-range values should be clamped.
        layout.set_split_ratio(ComponentProvider::ListingView, 1.5);
        assert!(
            (layout
                .get_window(&ComponentProvider::ListingView)
                .unwrap()
                .split_ratio
                - 1.0)
                .abs()
                < f32::EPSILON
        );
        layout.set_split_ratio(ComponentProvider::ListingView, -0.2);
        assert!(
            (layout
                .get_window(&ComponentProvider::ListingView)
                .unwrap()
                .split_ratio
                - 0.0)
                .abs()
                < f32::EPSILON
        );
    }

    #[test]
    fn test_tab_group_management() {
        let mut group = TabGroup::new(
            vec![
                ComponentProvider::ListingView,
                ComponentProvider::Console,
                ComponentProvider::SymbolTree,
            ],
            WindowPosition::Center,
        );
        assert_eq!(group.active_tab, 0);

        assert!(group.select_tab(2));
        assert_eq!(group.active_tab, 2);

        assert!(!group.select_tab(5)); // out of bounds

        assert!(group.remove_tab(&ComponentProvider::Console));
        assert_eq!(group.tabs.len(), 2);
        // active_tab was 2, now squashed to 1
        assert_eq!(group.active_tab, 1);

        assert!(group.remove_tab(&ComponentProvider::ListingView));
        assert_eq!(group.tabs.len(), 1);
        assert_eq!(group.active_tab, 0);
    }

    #[test]
    fn test_toolbar_config() {
        let mut tb = ToolbarConfig::new(
            "Test",
            vec!["undo".into(), "redo".into()],
            WindowPosition::Top,
        );
        assert_eq!(tb.name, "Test");
        assert_eq!(tb.actions.len(), 2);

        tb.add_action("save");
        assert_eq!(tb.actions.len(), 3);

        assert!(tb.remove_action("redo"));
        assert!(!tb.remove_action("nonexistent"));
    }

    #[test]
    fn test_default_layout_has_windows() {
        let layout = DockingLayout::default_layout();
        // Should have at least the commonly-used providers.
        assert!(layout.windows.contains_key(&ComponentProvider::ListingView));
        assert!(layout
            .windows
            .contains_key(&ComponentProvider::DecompilerView));
        assert!(layout.windows.contains_key(&ComponentProvider::SymbolTree));
        assert!(layout.windows.contains_key(&ComponentProvider::Console));
        assert!(!layout.tabs.is_empty());
        assert!(layout.toolbars.len() >= 2);
    }

    #[test]
    fn test_roundtrip_save_load() {
        let original = DockingLayout::default_layout();
        let json = original.save();
        assert!(!json.is_empty());

        let restored = DockingLayout::load(&json).expect("deserialization should succeed");
        assert_eq!(original, restored);
    }

    #[test]
    fn test_load_invalid_string() {
        let result = DockingLayout::load("not valid json");
        assert!(result.is_err());
    }

    #[test]
    fn test_visible_windows_ordering() {
        let mut layout = DockingLayout::new();
        layout.add_window(
            ComponentProvider::ListingView,
            make_placement(WindowPosition::Center),
        );
        layout.add_window(
            ComponentProvider::SymbolTree,
            make_placement(WindowPosition::Left),
        );
        layout.add_window(
            ComponentProvider::Console,
            make_placement(WindowPosition::Bottom),
        );

        // Hide one, minimize one
        layout.add_window(
            ComponentProvider::Bookmarks,
            make_placement(WindowPosition::Left).hidden(),
        );
        layout.add_window(
            ComponentProvider::BytesView,
            make_placement(WindowPosition::Bottom),
        );
        layout.minimize(ComponentProvider::BytesView);

        let visible = layout.visible_windows();
        // Should be: Bottom (Console), Left (SymbolTree), Center (ListingView)
        // Bookmarks is hidden, BytesView is minimized
        assert_eq!(visible.len(), 3);
    }

    #[test]
    fn test_reset_to_default() {
        let mut layout = DockingLayout::new();
        layout.add_window(
            ComponentProvider::Console,
            make_placement(WindowPosition::Right),
        );
        assert!(layout.windows.contains_key(&ComponentProvider::Console));

        layout.reset_to_default();
        assert!(layout.windows.contains_key(&ComponentProvider::ListingView));
        assert!(layout.windows.contains_key(&ComponentProvider::Console));
    }
}
