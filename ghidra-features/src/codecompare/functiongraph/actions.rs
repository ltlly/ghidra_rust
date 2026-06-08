//! User actions for the Function Graph comparison view.
//!
//! Ported from Ghidra's `ghidra.features.codecompare.functiongraph.actions` Java package.
//!
//! These actions are available in the dual function graph comparison view and
//! allow the user to manipulate the graph display. Each action operates on
//! one or both sides of the comparison.
//!
//! # Actions
//!
//! - [`FgResetGraphAction`] -- reset vertex positions and grouping
//! - [`FgTogglePopupsAction`] -- toggle popup window visibility
//! - [`FgToggleSatelliteAction`] -- toggle satellite view visibility
//! - [`FgRelayoutAction`] -- change the graph layout algorithm
//! - [`FgChooseFormatAction`] -- edit the code block field format
//!
//! # Base types
//!
//! - [`FgAction`] -- base struct for display-scoped actions
//! - [`FgToggleAction`] -- base struct for toggle actions that affect both displays

use super::fg_display::{DisplayState, FgDisplay, FgDisplayOptions};
use super::FgComparisonContext;
use super::super::graphanalysis::Side;

/// Menu location constants.
const MENU_GRAPH: &str = "Graph";
const MENU_FUNCTION_GRAPH: &str = "Function Graph";

/// Help topic for function graph actions.
const HELP_TOPIC: &str = "FunctionGraphPlugin";

/// Base struct for actions scoped to a single FgDisplay.
///
/// Ported from Ghidra's `AbstractFgAction` Java class.
/// Provides common enablement logic: the action is only enabled when
/// the context belongs to the display this action was created for.
#[derive(Debug, Clone)]
pub struct FgAction {
    /// The action name.
    pub name: String,
    /// The owner (typically the comparison view name).
    pub owner: String,
    /// The side this action is scoped to.
    pub side: Side,
    /// Menu path for popup menus.
    pub menu_path: Vec<String>,
    /// Description text.
    pub description: String,
    /// Help location topic.
    pub help_topic: String,
}

impl FgAction {
    /// Create a new display-scoped action.
    pub fn new(
        name: impl Into<String>,
        owner: impl Into<String>,
        side: Side,
    ) -> Self {
        Self {
            name: name.into(),
            owner: owner.into(),
            side,
            menu_path: Vec::new(),
            description: String::new(),
            help_topic: HELP_TOPIC.to_string(),
        }
    }

    /// Set the menu path.
    pub fn with_menu_path(mut self, path: Vec<String>) -> Self {
        self.menu_path = path;
        self
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Check if this action is enabled for the given context.
    ///
    /// Returns true only if the context's side matches this action's side.
    pub fn is_enabled_for_context(&self, context: &FgComparisonContext) -> bool {
        context.side == self.side
    }
}

/// Base struct for toggle actions that affect both displays.
///
/// These actions (like toggling popups or satellite) apply to both
/// the left and right displays simultaneously.
#[derive(Debug, Clone)]
pub struct FgToggleAction {
    /// The action name.
    pub name: String,
    /// The owner.
    pub owner: String,
    /// Whether the toggle is currently selected.
    pub selected: bool,
    /// Menu path.
    pub menu_path: Vec<String>,
    /// Description.
    pub description: String,
}

impl FgToggleAction {
    /// Create a new toggle action.
    pub fn new(name: impl Into<String>, owner: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            owner: owner.into(),
            selected: false,
            menu_path: Vec::new(),
            description: String::new(),
        }
    }

    /// Whether the toggle is selected.
    pub fn is_selected(&self) -> bool {
        self.selected
    }

    /// Set the selected state.
    pub fn set_selected(&mut self, selected: bool) {
        self.selected = selected;
    }
}

// ---- FgResetGraphAction ----

/// An action to reset a function graph (clear all vertex positions and grouping).
///
/// Ported from Ghidra's `FgResetGraphAction` Java class.
#[derive(Debug, Clone)]
pub struct FgResetGraphAction {
    /// The base action properties.
    pub action: FgAction,
    /// Confirmation message.
    pub confirm_message: String,
}

impl FgResetGraphAction {
    /// Create a new reset graph action for the given side.
    pub fn new(owner: impl Into<String>, side: Side) -> Self {
        let owner_str = owner.into();
        Self {
            action: FgAction::new("Reset Graph", &owner_str, side)
                .with_menu_path(vec![MENU_FUNCTION_GRAPH.to_string(), "Reset Graph".to_string()])
                .with_description("Erase all vertex position and grouping information"),
            confirm_message: "Erase all vertex position and grouping information?".to_string(),
        }
    }

    /// Execute the reset action on the given display.
    ///
    /// Returns true if the graph was reset, false if the display had no results.
    pub fn execute(&self, display: &mut FgDisplay) -> bool {
        if !display.has_results() {
            return false;
        }
        display.reset_graph();
        true
    }

    /// Check if this action is enabled for the given context and display state.
    pub fn is_enabled(&self, context: &FgComparisonContext, display: &FgDisplay) -> bool {
        self.action.is_enabled_for_context(context) && display.has_results()
    }
}

// ---- FgTogglePopupsAction ----

/// An action to toggle popup enablement for the Function Graph comparison views.
///
/// Ported from Ghidra's `FgTogglePopupsAction` Java class.
/// When toggled, popups are shown or hidden on both left and right displays.
#[derive(Debug, Clone)]
pub struct FgTogglePopupsAction {
    /// The base toggle action.
    pub action: FgToggleAction,
}

impl FgTogglePopupsAction {
    /// Create a new toggle popups action.
    pub fn new(owner: impl Into<String>) -> Self {
        let mut action = FgToggleAction::new("Display Popup Windows", owner);
        action.menu_path = vec![
            MENU_FUNCTION_GRAPH.to_string(),
            "Display Popup Windows".to_string(),
        ];
        Self { action }
    }

    /// Toggle popup visibility on both displays.
    pub fn execute(&self, left_display: &mut FgDisplay, right_display: &mut FgDisplay) {
        let visible = self.action.selected;
        left_display.set_popups_visible(visible);
        right_display.set_popups_visible(visible);
    }

    /// Check if this action is enabled (both displays must have results).
    pub fn is_enabled(&self, context: &FgComparisonContext, left_display: &FgDisplay) -> bool {
        if !matches!(context, ctx if ctx.side == Side::Left) {
            // Any context is fine for a global toggle action
        }
        left_display.has_results()
    }

    /// Toggle the selected state and return the new value.
    pub fn toggle(&mut self) -> bool {
        self.action.selected = !self.action.selected;
        self.action.selected
    }
}

// ---- FgToggleSatelliteAction ----

/// An action to toggle satellite enablement for the Function Graph comparison views.
///
/// Ported from Ghidra's `FgToggleSatelliteAction` Java class.
/// The satellite is a minimap view that shows the entire graph with a viewport indicator.
#[derive(Debug, Clone)]
pub struct FgToggleSatelliteAction {
    /// The base toggle action.
    pub action: FgToggleAction,
}

impl FgToggleSatelliteAction {
    /// Create a new toggle satellite action.
    pub fn new(owner: impl Into<String>) -> Self {
        let mut action = FgToggleAction::new("Display Satellite View", owner);
        action.menu_path = vec![
            MENU_FUNCTION_GRAPH.to_string(),
            "Display Satellite".to_string(),
        ];
        Self { action }
    }

    /// Toggle satellite visibility on both displays.
    pub fn execute(&self, left_display: &mut FgDisplay, right_display: &mut FgDisplay) {
        let visible = self.action.selected;
        left_display.set_satellite_visible(visible);
        right_display.set_satellite_visible(visible);
    }

    /// Check if this action is enabled.
    pub fn is_enabled(&self, _context: &FgComparisonContext, left_display: &FgDisplay) -> bool {
        left_display.has_results()
    }

    /// Toggle the selected state and return the new value.
    pub fn toggle(&mut self) -> bool {
        self.action.selected = !self.action.selected;
        self.action.selected
    }
}

// ---- FgRelayoutAction ----

/// Available layout algorithms for the function graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutProvider {
    /// Display name of the layout.
    pub name: String,
    /// Class name (for serialization).
    pub class_name: String,
    /// Priority level (higher = preferred).
    pub priority: i32,
}

impl LayoutProvider {
    /// Create a new layout provider.
    pub fn new(name: impl Into<String>, class_name: impl Into<String>, priority: i32) -> Self {
        Self {
            name: name.into(),
            class_name: class_name.into(),
            priority,
        }
    }
}

/// An action to relayout the function graph using a different layout algorithm.
///
/// Ported from Ghidra's `FgRelayoutAction` Java class.
/// Opens a dialog for the user to choose a layout provider, then applies
/// it to both displays.
#[derive(Debug, Clone)]
pub struct FgRelayoutAction {
    /// The base action properties.
    pub action: FgAction,
    /// Available layout providers.
    pub layout_providers: Vec<LayoutProvider>,
}

impl FgRelayoutAction {
    /// Create a new relayout action.
    pub fn new(owner: impl Into<String>) -> Self {
        let owner_str = owner.into();
        Self {
            action: FgAction::new("Relayout Graph", &owner_str, Side::Left)
                .with_menu_path(vec![
                    MENU_FUNCTION_GRAPH.to_string(),
                    "Relayout Graph".to_string(),
                ])
                .with_description("Choose a layout algorithm for the function graph"),
            layout_providers: Self::default_layout_providers(),
        }
    }

    /// Get the default set of layout providers.
    fn default_layout_providers() -> Vec<LayoutProvider> {
        vec![
            LayoutProvider::new("Flow Chart", "FlowChartLayoutProvider", 100),
            LayoutProvider::new("Block Model", "BlockModelLayoutProvider", 50),
            LayoutProvider::new("Hierarchical", "HierarchicalLayoutProvider", 75),
            LayoutProvider::new("Jung Hierarchical", "JungHierarchicalLayoutProvider", 60),
        ]
    }

    /// Get the available layout provider names.
    pub fn available_layouts(&self) -> Vec<&str> {
        self.layout_providers.iter().map(|p| p.name.as_str()).collect()
    }

    /// Execute the relayout action.
    ///
    /// Returns the name of the selected layout, or None if cancelled.
    pub fn execute(
        &self,
        layout_name: &str,
        left_display: &mut FgDisplay,
        right_display: &mut FgDisplay,
    ) -> bool {
        if !self.layout_providers.iter().any(|p| p.name == layout_name) {
            return false;
        }
        left_display.change_layout(layout_name);
        right_display.change_layout(layout_name);
        true
    }

    /// Check if this action is enabled.
    pub fn is_enabled(&self, context: &FgComparisonContext) -> bool {
        // The relayout action is available for any comparison context
        context.side == Side::Left || context.side == Side::Right
    }
}

// ---- FgChooseFormatAction ----

/// An action to edit the code block field format.
///
/// Ported from Ghidra's `FgChooseFormatAction` Java class.
/// Opens a format editor that lets the user choose which fields to display
/// in the code blocks (address, bytes, mnemonics, etc.).
#[derive(Debug, Clone)]
pub struct FgChooseFormatAction {
    /// The base action properties.
    pub action: FgAction,
}

impl FgChooseFormatAction {
    /// Create a new choose format action.
    pub fn new(owner: impl Into<String>) -> Self {
        let owner_str = owner.into();
        Self {
            action: FgAction::new("Edit Code Block Fields", &owner_str, Side::Left)
                .with_menu_path(vec![
                    MENU_FUNCTION_GRAPH.to_string(),
                    "Edit Fields".to_string(),
                ])
                .with_description("Choose which fields to display in code blocks"),
        }
    }

    /// Check if this action is enabled.
    pub fn is_enabled(&self, _context: &FgComparisonContext, left_display: &FgDisplay) -> bool {
        left_display.has_results()
    }
}

/// Aggregate of all function graph actions, used by the comparison view.
///
/// This struct owns all the actions and provides methods to access them
/// by index or name.
#[derive(Debug)]
pub struct FgActionSet {
    /// Reset graph action for the left display.
    pub reset_left: FgResetGraphAction,
    /// Reset graph action for the right display.
    pub reset_right: FgResetGraphAction,
    /// Toggle popups action.
    pub toggle_popups: FgTogglePopupsAction,
    /// Toggle satellite action.
    pub toggle_satellite: FgToggleSatelliteAction,
    /// Relayout action.
    pub relayout: FgRelayoutAction,
    /// Choose format action.
    pub choose_format: FgChooseFormatAction,
}

impl FgActionSet {
    /// Create a new action set for the given owner.
    pub fn new(owner: impl Into<String> + Clone) -> Self {
        Self {
            reset_left: FgResetGraphAction::new(owner.clone(), Side::Left),
            reset_right: FgResetGraphAction::new(owner.clone(), Side::Right),
            toggle_popups: FgTogglePopupsAction::new(owner.clone()),
            toggle_satellite: FgToggleSatelliteAction::new(owner.clone()),
            relayout: FgRelayoutAction::new(owner.clone()),
            choose_format: FgChooseFormatAction::new(owner),
        }
    }

    /// Initialize toggle states from the current display state.
    pub fn init_from_display(&mut self, display: &FgDisplay) {
        self.toggle_popups.action.selected = display.are_popups_visible();
        self.toggle_satellite.action.selected = display.is_satellite_visible();
    }

    /// Get all action names.
    pub fn action_names(&self) -> Vec<&str> {
        vec![
            &self.reset_left.action.name,
            &self.reset_right.action.name,
            &self.toggle_popups.action.name,
            &self.toggle_satellite.action.name,
            &self.relayout.action.name,
            &self.choose_format.action.name,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::fg_display::FgDisplay;

    fn make_context(side: Side) -> FgComparisonContext {
        FgComparisonContext::new("test", side, "panel")
    }

    // --- FgResetGraphAction tests ---

    #[test]
    fn test_reset_action_enabled() {
        let action = FgResetGraphAction::new("test", Side::Left);
        let mut display = FgDisplay::new("test", Side::Left);
        display.show_function(Some(0x1000), false, "main");
        display.load_graph(
            vec![super::super::fg_display::FgVertex {
                id: 0,
                start_address: 0x1000,
                end_address: 0x1020,
                instruction_count: 5,
                label: "BLOCK 0".to_string(),
            }],
            vec![],
        );

        let ctx = make_context(Side::Left);
        assert!(action.is_enabled(&ctx, &display));
    }

    #[test]
    fn test_reset_action_wrong_side() {
        let action = FgResetGraphAction::new("test", Side::Left);
        let display = FgDisplay::new("test", Side::Left);
        let ctx = make_context(Side::Right);
        assert!(!action.is_enabled(&ctx, &display));
    }

    #[test]
    fn test_reset_action_no_results() {
        let action = FgResetGraphAction::new("test", Side::Left);
        let display = FgDisplay::new("test", Side::Left);
        let ctx = make_context(Side::Left);
        assert!(!action.is_enabled(&ctx, &display));
    }

    #[test]
    fn test_reset_action_execute() {
        let action = FgResetGraphAction::new("test", Side::Left);
        let mut display = FgDisplay::new("test", Side::Left);
        display.show_function(Some(0x1000), false, "main");
        display.load_graph(
            vec![super::super::fg_display::FgVertex {
                id: 0,
                start_address: 0x1000,
                end_address: 0x1020,
                instruction_count: 5,
                label: "BLOCK 0".to_string(),
            }],
            vec![],
        );

        assert!(action.execute(&mut display));
        assert!(display.vertices().is_empty());
    }

    // --- FgTogglePopupsAction tests ---

    #[test]
    fn test_toggle_popups() {
        let mut action = FgTogglePopupsAction::new("test");
        assert!(!action.action.is_selected());

        let new_state = action.toggle();
        assert!(new_state);
        assert!(action.action.is_selected());
    }

    #[test]
    fn test_toggle_popups_execute() {
        let mut action = FgTogglePopupsAction::new("test");
        action.action.set_selected(false);

        let mut left = FgDisplay::new("test", Side::Left);
        let mut right = FgDisplay::new("test", Side::Right);

        action.execute(&mut left, &mut right);
        assert!(!left.are_popups_visible());
        assert!(!right.are_popups_visible());
    }

    // --- FgToggleSatelliteAction tests ---

    #[test]
    fn test_toggle_satellite() {
        let mut action = FgToggleSatelliteAction::new("test");
        assert!(!action.action.is_selected());

        action.toggle();
        assert!(action.action.is_selected());
    }

    #[test]
    fn test_toggle_satellite_execute() {
        let mut action = FgToggleSatelliteAction::new("test");
        action.action.set_selected(false);

        let mut left = FgDisplay::new("test", Side::Left);
        let mut right = FgDisplay::new("test", Side::Right);

        action.execute(&mut left, &mut right);
        assert!(!left.is_satellite_visible());
        assert!(!right.is_satellite_visible());
    }

    // --- FgRelayoutAction tests ---

    #[test]
    fn test_relayout_action_layouts() {
        let action = FgRelayoutAction::new("test");
        let layouts = action.available_layouts();
        assert!(layouts.contains(&"Flow Chart"));
        assert!(layouts.contains(&"Block Model"));
    }

    #[test]
    fn test_relayout_action_execute() {
        let action = FgRelayoutAction::new("test");
        let mut left = FgDisplay::new("test", Side::Left);
        let mut right = FgDisplay::new("test", Side::Right);

        assert!(action.execute("Block Model", &mut left, &mut right));
        assert_eq!(left.layout_name(), "Block Model");
        assert_eq!(right.layout_name(), "Block Model");
    }

    #[test]
    fn test_relayout_action_invalid_layout() {
        let action = FgRelayoutAction::new("test");
        let mut left = FgDisplay::new("test", Side::Left);
        let mut right = FgDisplay::new("test", Side::Right);

        assert!(!action.execute("Nonexistent", &mut left, &mut right));
    }

    #[test]
    fn test_relayout_action_enabled() {
        let action = FgRelayoutAction::new("test");
        let ctx = make_context(Side::Left);
        assert!(action.is_enabled(&ctx));
    }

    // --- FgChooseFormatAction tests ---

    #[test]
    fn test_choose_format_enabled() {
        let action = FgChooseFormatAction::new("test");
        let mut display = FgDisplay::new("test", Side::Left);
        display.show_function(Some(0x1000), false, "main");
        display.load_graph(
            vec![super::super::fg_display::FgVertex {
                id: 0,
                start_address: 0x1000,
                end_address: 0x1020,
                instruction_count: 5,
                label: "BLOCK 0".to_string(),
            }],
            vec![],
        );

        let ctx = make_context(Side::Left);
        assert!(action.is_enabled(&ctx, &display));
    }

    // --- FgActionSet tests ---

    #[test]
    fn test_action_set_names() {
        let set = FgActionSet::new("test");
        let names = set.action_names();
        assert_eq!(names.len(), 6);
        assert!(names.contains(&"Reset Graph"));
        assert!(names.contains(&"Display Popup Windows"));
        assert!(names.contains(&"Display Satellite View"));
        assert!(names.contains(&"Relayout Graph"));
        assert!(names.contains(&"Edit Code Block Fields"));
    }

    #[test]
    fn test_action_set_init_from_display() {
        let mut set = FgActionSet::new("test");
        let mut display = FgDisplay::new("test", Side::Left);
        display.set_popups_visible(false);
        display.set_satellite_visible(false);

        set.init_from_display(&display);
        assert!(!set.toggle_popups.action.is_selected());
        assert!(!set.toggle_satellite.action.is_selected());
    }
}
