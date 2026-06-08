//! Action context and toggle actions for listing code comparison.
//!
//! Ported from Ghidra's `ListingComparisonActionContext` and
//! `ListingDisplayToggleAction` Java classes in
//! `ghidra.features.base.codecompare.listing`.
//!
//! In the original Java, `ListingComparisonActionContext` extends
//! `CodeComparisonActionContext` and provides the specific context for a
//! listing-based code comparison view. `ListingDisplayToggleAction` is an
//! abstract base for toggle actions that only appear when the user right-clicks
//! on a `FieldPanel` inside a `ListingCodeComparisonView`.
//!
//! In this Rust port, we capture the logical state and behavior without
//! the Swing/docking framework dependency.
//!
//! # Key types
//!
//! - [`ActionSource`] -- where the action was triggered from
//! - [`ListingComparisonActionContext`] -- action context for a listing comparison
//! - [`ToggleActionState`] -- state of a toggle action
//! - [`ListingToggleAction`] -- abstract toggle action for listing comparison

use super::ListingSide;
use crate::codecompare::model::ComparisonSide;
use crate::codecompare::panel::ProgramInfo;

/// Where an action was triggered from in the comparison view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionSource {
    /// The left listing panel.
    LeftListing,
    /// The right listing panel.
    RightListing,
    /// The left field panel.
    LeftFieldPanel,
    /// The right field panel.
    RightFieldPanel,
    /// A margin panel (marker or overview).
    MarginPanel(ListingSide),
    /// The field header.
    FieldHeader,
    /// Unknown or unspecified source.
    Unknown,
}

impl ActionSource {
    /// Get the side associated with this action source, if any.
    pub fn side(&self) -> Option<ListingSide> {
        match self {
            Self::LeftListing | Self::LeftFieldPanel | Self::MarginPanel(ListingSide::Left) => {
                Some(ListingSide::Left)
            }
            Self::RightListing | Self::RightFieldPanel | Self::MarginPanel(ListingSide::Right) => {
                Some(ListingSide::Right)
            }
            Self::FieldHeader | Self::Unknown => None,
        }
    }

    /// Check if this source is a field panel (left or right).
    pub fn is_field_panel(&self) -> bool {
        matches!(self, Self::LeftFieldPanel | Self::RightFieldPanel)
    }

    /// Check if this source is a margin panel.
    pub fn is_margin_panel(&self) -> bool {
        matches!(self, Self::MarginPanel(_))
    }
}

/// Action context for a listing code comparison view.
///
/// This is the Rust equivalent of Ghidra's `ListingComparisonActionContext`
/// Java class. It captures which side is active, what the source of the
/// action was, and references to the relevant programs and functions.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::listing::action_context::*;
/// use ghidra_features::codecompare::listing::ListingSide;
/// use ghidra_features::codecompare::panel::ProgramInfo;
///
/// let left_prog = ProgramInfo::new(1, "/old", "old_binary");
/// let right_prog = ProgramInfo::new(2, "/new", "new_binary");
///
/// let ctx = ListingComparisonActionContext::new(
///     ListingSide::Left,
///     ActionSource::LeftFieldPanel,
///     Some(left_prog),
///     Some(right_prog),
/// );
///
/// assert_eq!(ctx.active_side(), ListingSide::Left);
/// assert_eq!(ctx.source(), ActionSource::LeftFieldPanel);
/// assert!(ctx.source_program().is_some());
/// assert!(ctx.target_program().is_some());
/// ```
#[derive(Debug, Clone)]
pub struct ListingComparisonActionContext {
    /// Which side is currently active (focused).
    active_side: ListingSide,
    /// Where the action was triggered from.
    source: ActionSource,
    /// The program on the source side (the side that is NOT active).
    source_program: Option<ProgramInfo>,
    /// The program on the target side (the side that IS active).
    target_program: Option<ProgramInfo>,
    /// The source function name, if applicable.
    source_function: Option<String>,
    /// The target function name, if applicable.
    target_function: Option<String>,
}

impl ListingComparisonActionContext {
    /// Create a new listing comparison action context.
    pub fn new(
        active_side: ListingSide,
        source: ActionSource,
        source_program: Option<ProgramInfo>,
        target_program: Option<ProgramInfo>,
    ) -> Self {
        Self {
            active_side,
            source,
            source_program,
            target_program,
            source_function: None,
            target_function: None,
        }
    }

    /// Create a new context with function information.
    pub fn with_functions(
        active_side: ListingSide,
        source: ActionSource,
        source_program: Option<ProgramInfo>,
        target_program: Option<ProgramInfo>,
        source_function: impl Into<String>,
        target_function: impl Into<String>,
    ) -> Self {
        Self {
            active_side,
            source,
            source_program,
            target_program,
            source_function: Some(source_function.into()),
            target_function: Some(target_function.into()),
        }
    }

    /// Get the active side (the side that has focus).
    pub fn active_side(&self) -> ListingSide {
        self.active_side
    }

    /// Get the source of the action.
    pub fn source(&self) -> ActionSource {
        self.source
    }

    /// Get the program on the source (inactive) side.
    ///
    /// In the Java original, this is `getSourceFunction().getProgram()`.
    pub fn source_program(&self) -> Option<&ProgramInfo> {
        self.source_program.as_ref()
    }

    /// Get the program on the target (active) side.
    ///
    /// In the Java original, this is `getTargetFunction().getProgram()`.
    pub fn target_program(&self) -> Option<&ProgramInfo> {
        self.target_program.as_ref()
    }

    /// Get the source function name.
    pub fn source_function(&self) -> Option<&str> {
        self.source_function.as_deref()
    }

    /// Get the target function name.
    pub fn target_function(&self) -> Option<&str> {
        self.target_function.as_deref()
    }

    /// Check if the context is valid (has a field panel source).
    pub fn is_valid_panel_context(&self) -> bool {
        self.source.is_field_panel()
    }
}

/// State of a toggle action in the listing comparison view.
///
/// This represents the state of a single toggle action in the UI,
/// corresponding to a `ListingDisplayToggleAction` in the Java code.
#[derive(Debug, Clone)]
pub struct ToggleActionState {
    /// The name of this action.
    pub name: String,
    /// The owner of this action.
    pub owner: String,
    /// Whether the action is currently selected (toggled on).
    pub selected: bool,
    /// Whether the action is currently enabled.
    pub enabled: bool,
    /// The description of this action.
    pub description: String,
    /// The help topic for this action.
    pub help_topic: String,
}

impl ToggleActionState {
    /// Create a new toggle action state.
    pub fn new(
        name: impl Into<String>,
        owner: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        let name = name.into();
        let help_topic = format!("Dual Listing {}", name);
        Self {
            name,
            owner: owner.into(),
            selected: false,
            enabled: true,
            description: description.into(),
            help_topic,
        }
    }

    /// Toggle the selected state.
    pub fn toggle(&mut self) {
        self.selected = !self.selected;
    }

    /// Set the selected state.
    pub fn set_selected(&mut self, selected: bool) {
        self.selected = selected;
    }

    /// Set the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

/// Abstract toggle action for listing comparison views.
///
/// This is the Rust equivalent of Ghidra's `ListingDisplayToggleAction` Java
/// class. In the Java version, this is a `ToggleDockingAction` subclass that
/// overrides `isAddToPopup` to only appear when the context object is a
/// `ListingCodeComparisonView` and the source is a `FieldPanel`.
///
/// In this Rust port, we capture the action configuration and state.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::listing::action_context::*;
/// use ghidra_features::codecompare::listing::ListingSide;
///
/// let mut action = ListingToggleAction::new(
///     "Toggle Ignore Byte Diffs",
///     "DualListing",
///     "If selected, difference highlights should ignore Byte differences.",
/// );
///
/// assert!(!action.state().selected);
/// assert!(action.state().enabled);
///
/// action.toggle();
/// assert!(action.state().selected);
/// ```
#[derive(Debug, Clone)]
pub struct ListingToggleAction {
    /// The state of this toggle action.
    state: ToggleActionState,
    /// The popup menu path components.
    popup_menu_path: Vec<String>,
    /// The popup menu group.
    popup_menu_group: String,
    /// The toolbar group.
    toolbar_group: String,
}

impl ListingToggleAction {
    /// Create a new listing toggle action.
    pub fn new(
        name: impl Into<String>,
        owner: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            state: ToggleActionState::new(name, owner, description),
            popup_menu_path: Vec::new(),
            popup_menu_group: String::new(),
            toolbar_group: String::new(),
        }
    }

    /// Get the action state.
    pub fn state(&self) -> &ToggleActionState {
        &self.state
    }

    /// Get a mutable reference to the action state.
    pub fn state_mut(&mut self) -> &mut ToggleActionState {
        &mut self.state
    }

    /// Toggle the action.
    pub fn toggle(&mut self) {
        self.state.toggle();
    }

    /// Set the popup menu path.
    pub fn set_popup_menu_path(&mut self, path: Vec<impl Into<String>>) {
        self.popup_menu_path = path.into_iter().map(|s| s.into()).collect();
    }

    /// Get the popup menu path.
    pub fn popup_menu_path(&self) -> &[String] {
        &self.popup_menu_path
    }

    /// Set the popup menu group.
    pub fn set_popup_menu_group(&mut self, group: impl Into<String>) {
        self.popup_menu_group = group.into();
    }

    /// Get the popup menu group.
    pub fn popup_menu_group(&self) -> &str {
        &self.popup_menu_group
    }

    /// Set the toolbar group.
    pub fn set_toolbar_group(&mut self, group: impl Into<String>) {
        self.toolbar_group = group.into();
    }

    /// Get the toolbar group.
    pub fn toolbar_group(&self) -> &str {
        &self.toolbar_group
    }

    /// Check if this action should appear in the popup menu for the given context.
    ///
    /// In the Java original, this checks that the context is a
    /// `ListingCodeComparisonView` and the source is a `FieldPanel`.
    pub fn is_add_to_popup(&self, source: ActionSource) -> bool {
        source.is_field_panel()
    }
}

/// A collection of toggle actions for listing comparison.
///
/// Manages the toggle actions that control diff filtering (byte diffs,
/// constants, register names) in a listing comparison view.
///
/// This is the Rust equivalent of the action management portion of
/// Ghidra's `ListingDiffActionManager` Java class.
#[derive(Debug)]
pub struct ListingToggleActionSet {
    /// Toggle action for ignoring byte diffs.
    pub ignore_byte_diffs: ListingToggleAction,
    /// Toggle action for ignoring constants.
    pub ignore_constants: ListingToggleAction,
    /// Toggle action for ignoring register names.
    pub ignore_register_names: ListingToggleAction,
}

impl ListingToggleActionSet {
    /// Create a new action set with default configurations.
    pub fn new() -> Self {
        Self {
            ignore_byte_diffs: ListingToggleAction::new(
                "Toggle Ignore Byte Diffs",
                "DualListing",
                "If selected, difference highlights should ignore Byte differences.",
            ),
            ignore_constants: ListingToggleAction::new(
                "Toggle Ignore Constants",
                "DualListing",
                "If selected, difference highlights should ignore operand Constants.",
            ),
            ignore_register_names: ListingToggleAction::new(
                "Toggle Ignore Register Names",
                "DualListing",
                "If selected, difference highlights should ignore operand Registers.",
            ),
        }
    }

    /// Update the enablement of all actions.
    pub fn update_enablement(&mut self, enabled: bool) {
        self.ignore_byte_diffs.state_mut().set_enabled(enabled);
        self.ignore_constants.state_mut().set_enabled(enabled);
        self.ignore_register_names.state_mut().set_enabled(enabled);
    }

    /// Get all actions as a slice.
    pub fn all_actions(&self) -> [&ListingToggleAction; 3] {
        [
            &self.ignore_byte_diffs,
            &self.ignore_constants,
            &self.ignore_register_names,
        ]
    }
}

impl Default for ListingToggleActionSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codecompare::panel::ProgramInfo;

    fn make_program(id: u64, path: &str, name: &str) -> ProgramInfo {
        ProgramInfo::new(id, path, name)
    }

    // --- ActionSource tests ---

    #[test]
    fn test_action_source_side() {
        assert_eq!(
            ActionSource::LeftListing.side(),
            Some(ListingSide::Left)
        );
        assert_eq!(
            ActionSource::RightFieldPanel.side(),
            Some(ListingSide::Right)
        );
        assert_eq!(
            ActionSource::MarginPanel(ListingSide::Left).side(),
            Some(ListingSide::Left)
        );
        assert_eq!(ActionSource::FieldHeader.side(), None);
        assert_eq!(ActionSource::Unknown.side(), None);
    }

    #[test]
    fn test_action_source_is_field_panel() {
        assert!(ActionSource::LeftFieldPanel.is_field_panel());
        assert!(ActionSource::RightFieldPanel.is_field_panel());
        assert!(!ActionSource::LeftListing.is_field_panel());
        assert!(!ActionSource::MarginPanel(ListingSide::Left).is_field_panel());
    }

    #[test]
    fn test_action_source_is_margin_panel() {
        assert!(ActionSource::MarginPanel(ListingSide::Left).is_margin_panel());
        assert!(ActionSource::MarginPanel(ListingSide::Right).is_margin_panel());
        assert!(!ActionSource::LeftFieldPanel.is_margin_panel());
        assert!(!ActionSource::FieldHeader.is_margin_panel());
    }

    // --- ListingComparisonActionContext tests ---

    #[test]
    fn test_action_context_new() {
        let left_prog = make_program(1, "/old", "old");
        let right_prog = make_program(2, "/new", "new");

        let ctx = ListingComparisonActionContext::new(
            ListingSide::Left,
            ActionSource::LeftFieldPanel,
            Some(left_prog),
            Some(right_prog),
        );

        assert_eq!(ctx.active_side(), ListingSide::Left);
        assert_eq!(ctx.source(), ActionSource::LeftFieldPanel);
        assert!(ctx.source_program().is_some());
        assert!(ctx.target_program().is_some());
        assert!(ctx.source_function().is_none());
        assert!(ctx.target_function().is_none());
    }

    #[test]
    fn test_action_context_with_functions() {
        let left_prog = make_program(1, "/old", "old");
        let right_prog = make_program(2, "/new", "new");

        let ctx = ListingComparisonActionContext::with_functions(
            ListingSide::Right,
            ActionSource::RightFieldPanel,
            Some(left_prog),
            Some(right_prog),
            "main_old",
            "main_new",
        );

        assert_eq!(ctx.active_side(), ListingSide::Right);
        assert_eq!(ctx.source_function(), Some("main_old"));
        assert_eq!(ctx.target_function(), Some("main_new"));
    }

    #[test]
    fn test_action_context_valid_panel_context() {
        let ctx = ListingComparisonActionContext::new(
            ListingSide::Left,
            ActionSource::LeftFieldPanel,
            None,
            None,
        );
        assert!(ctx.is_valid_panel_context());

        let ctx = ListingComparisonActionContext::new(
            ListingSide::Left,
            ActionSource::FieldHeader,
            None,
            None,
        );
        assert!(!ctx.is_valid_panel_context());
    }

    #[test]
    fn test_action_context_source_target_programs() {
        let left_prog = make_program(1, "/old", "old_binary");
        let right_prog = make_program(2, "/new", "new_binary");

        let ctx = ListingComparisonActionContext::new(
            ListingSide::Left,
            ActionSource::LeftFieldPanel,
            Some(left_prog.clone()),
            Some(right_prog.clone()),
        );

        // source_program is the inactive side's program
        let src = ctx.source_program().unwrap();
        assert_eq!(src.path, "/old");

        // target_program is the active side's program
        let tgt = ctx.target_program().unwrap();
        assert_eq!(tgt.path, "/new");
    }

    #[test]
    fn test_action_context_no_programs() {
        let ctx = ListingComparisonActionContext::new(
            ListingSide::Left,
            ActionSource::Unknown,
            None,
            None,
        );
        assert!(ctx.source_program().is_none());
        assert!(ctx.target_program().is_none());
    }

    // --- ToggleActionState tests ---

    #[test]
    fn test_toggle_action_state_new() {
        let state = ToggleActionState::new("Test Action", "owner", "A test action.");
        assert_eq!(state.name, "Test Action");
        assert_eq!(state.owner, "owner");
        assert!(!state.selected);
        assert!(state.enabled);
        assert_eq!(state.description, "A test action.");
        assert!(state.help_topic.contains("Test Action"));
    }

    #[test]
    fn test_toggle_action_state_toggle() {
        let mut state = ToggleActionState::new("Test", "owner", "desc");
        assert!(!state.selected);

        state.toggle();
        assert!(state.selected);

        state.toggle();
        assert!(!state.selected);
    }

    #[test]
    fn test_toggle_action_state_set_selected() {
        let mut state = ToggleActionState::new("Test", "owner", "desc");
        state.set_selected(true);
        assert!(state.selected);
        state.set_selected(false);
        assert!(!state.selected);
    }

    #[test]
    fn test_toggle_action_state_set_enabled() {
        let mut state = ToggleActionState::new("Test", "owner", "desc");
        assert!(state.enabled);
        state.set_enabled(false);
        assert!(!state.enabled);
    }

    // --- ListingToggleAction tests ---

    #[test]
    fn test_listing_toggle_action_new() {
        let action = ListingToggleAction::new("Test Action", "owner", "Description.");
        assert_eq!(action.state().name, "Test Action");
        assert!(!action.state().selected);
        assert!(action.state().enabled);
    }

    #[test]
    fn test_listing_toggle_action_toggle() {
        let mut action = ListingToggleAction::new("Test", "owner", "desc");
        assert!(!action.state().selected);

        action.toggle();
        assert!(action.state().selected);
    }

    #[test]
    fn test_listing_toggle_action_popup_menu() {
        let mut action = ListingToggleAction::new("Test", "owner", "desc");
        action.set_popup_menu_path(vec!["Menu", "Submenu", "Action"]);
        assert_eq!(action.popup_menu_path().len(), 3);
        assert_eq!(action.popup_menu_path()[0], "Menu");
    }

    #[test]
    fn test_listing_toggle_action_groups() {
        let mut action = ListingToggleAction::new("Test", "owner", "desc");
        action.set_popup_menu_group("A4_Diff");
        action.set_toolbar_group("A4_Diff");

        assert_eq!(action.popup_menu_group(), "A4_Diff");
        assert_eq!(action.toolbar_group(), "A4_Diff");
    }

    #[test]
    fn test_listing_toggle_action_is_add_to_popup() {
        let action = ListingToggleAction::new("Test", "owner", "desc");

        assert!(action.is_add_to_popup(ActionSource::LeftFieldPanel));
        assert!(action.is_add_to_popup(ActionSource::RightFieldPanel));
        assert!(!action.is_add_to_popup(ActionSource::LeftListing));
        assert!(!action.is_add_to_popup(ActionSource::FieldHeader));
        assert!(!action.is_add_to_popup(ActionSource::Unknown));
    }

    // --- ListingToggleActionSet tests ---

    #[test]
    fn test_action_set_new() {
        let set = ListingToggleActionSet::new();
        assert!(!set.ignore_byte_diffs.state().selected);
        assert!(!set.ignore_constants.state().selected);
        assert!(!set.ignore_register_names.state().selected);
    }

    #[test]
    fn test_action_set_update_enablement() {
        let mut set = ListingToggleActionSet::new();
        assert!(set.ignore_byte_diffs.state().enabled);

        set.update_enablement(false);
        assert!(!set.ignore_byte_diffs.state().enabled);
        assert!(!set.ignore_constants.state().enabled);
        assert!(!set.ignore_register_names.state().enabled);

        set.update_enablement(true);
        assert!(set.ignore_byte_diffs.state().enabled);
        assert!(set.ignore_constants.state().enabled);
        assert!(set.ignore_register_names.state().enabled);
    }

    #[test]
    fn test_action_set_all_actions() {
        let set = ListingToggleActionSet::new();
        let actions = set.all_actions();
        assert_eq!(actions.len(), 3);
        assert_eq!(actions[0].state().name, "Toggle Ignore Byte Diffs");
        assert_eq!(actions[1].state().name, "Toggle Ignore Constants");
        assert_eq!(actions[2].state().name, "Toggle Ignore Register Names");
    }

    #[test]
    fn test_action_set_toggle_individual() {
        let mut set = ListingToggleActionSet::new();
        set.ignore_byte_diffs.toggle();
        assert!(set.ignore_byte_diffs.state().selected);
        assert!(!set.ignore_constants.state().selected);
    }

    #[test]
    fn test_action_set_default() {
        let set = ListingToggleActionSet::default();
        assert_eq!(set.all_actions().len(), 3);
    }
}
