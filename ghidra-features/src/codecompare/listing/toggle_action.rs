//! Toggle actions for listing code comparison displays.
//!
//! Ported from Ghidra's `ListingDisplayToggleAction` Java class in
//! `ghidra.features.base.codecompare.listing`.
//!
//! This module provides toggle action state management for listing comparison
//! views. In Ghidra, toggle actions control visibility of headers, hover
//! popups, and other UI elements in the dual listing comparison window.
//!
//! In the original Java, `ListingDisplayToggleAction` extends
//! `ToggleDockingAction` and overrides `isAddToPopup` to only show
//! the action in the context menu when the source is a `FieldPanel`
//! inside a `ListingCodeComparisonView`. In this Rust port, we capture
//! the logical state and action filtering behavior.
//!
//! # Key types
//!
//! - [`ToggleActionKind`] -- the kind of toggle action
//! - [`ToggleActionState`] -- the state of a toggle action
//! - [`ListingToggleActionManager`] -- manages toggle actions for a listing display

use std::fmt;

use crate::codecompare::panel::action_context::{ActionTrigger, ListingComparisonActionContext};

/// The kind of toggle action available in a listing comparison view.
///
/// Each variant corresponds to a specific toggle action in Ghidra's
/// `ListingCodeComparisonView` Java class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ToggleActionKind {
    /// Toggle the format header visibility.
    Header,
    /// Toggle mouse hover popups.
    Hover,
    /// Toggle synchronized scrolling.
    ScrollSync,
}

impl ToggleActionKind {
    /// A human-readable label for this action kind.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Header => "Toggle Format Header",
            Self::Hover => "Toggle Mouse Hover Popups",
            Self::ScrollSync => "Synchronize Scrolling",
        }
    }

    /// A description of what this action does.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Header => "Toggle the format header display in the listing comparison view.",
            Self::Hover => "Toggle mouse hover popups in the listing comparison view.",
            Self::ScrollSync => "Lock/unlock synchronized scrolling of the dual listing view.",
        }
    }

    /// The help topic for this action.
    pub fn help_topic(&self) -> &'static str {
        match self {
            Self::Header => "Dual Listing Toggle Format Header",
            Self::Hover => "Dual Listing Toggle Mouse Hover Popups",
            Self::ScrollSync => "Synchronize Scrolling of Dual View",
        }
    }

    /// The key binding for this action, if any.
    pub fn key_binding(&self) -> Option<&'static str> {
        match self {
            Self::Header => None,
            Self::Hover => None,
            Self::ScrollSync => None,
        }
    }

    /// The menu path for this action.
    pub fn menu_path(&self) -> &[&str] {
        match self {
            Self::Header => &["Show Listing Format Header"],
            Self::Hover => &["Toggle Mouse Hover Popups"],
            Self::ScrollSync => &["Synchronize Scrolling"],
        }
    }

    /// The menu group for this action.
    pub fn menu_group(&self) -> &'static str {
        match self {
            Self::Header => "Listing Group",
            Self::Hover => "Listing Group",
            Self::ScrollSync => "DualScrolling",
        }
    }
}

impl fmt::Display for ToggleActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// The state of a toggle action.
///
/// In Ghidra, this corresponds to the state of a `ToggleDockingAction`.
/// Here we capture the logical state without the Swing/docking framework.
#[derive(Debug, Clone)]
pub struct ToggleActionState {
    /// The kind of toggle action.
    pub kind: ToggleActionKind,
    /// Whether the action is currently selected (toggled on).
    pub selected: bool,
    /// Whether the action is currently enabled.
    pub enabled: bool,
    /// Whether this action should appear in the popup menu.
    pub show_in_popup: bool,
    /// The icon identifier (for toolbar display).
    pub icon_id: Option<String>,
    /// The toolbar group.
    pub toolbar_group: Option<String>,
}

impl ToggleActionState {
    /// Create a new toggle action state with default values.
    pub fn new(kind: ToggleActionKind) -> Self {
        Self {
            kind,
            selected: false,
            enabled: true,
            show_in_popup: true,
            icon_id: None,
            toolbar_group: None,
        }
    }

    /// Create a toggle action state that is initially selected.
    pub fn new_selected(kind: ToggleActionKind) -> Self {
        Self {
            kind,
            selected: true,
            enabled: true,
            show_in_popup: true,
            icon_id: None,
            toolbar_group: None,
        }
    }

    /// Toggle the selected state.
    ///
    /// Returns the new selected state.
    pub fn toggle(&mut self) -> bool {
        self.selected = !self.selected;
        self.selected
    }

    /// Set the selected state explicitly.
    pub fn set_selected(&mut self, selected: bool) {
        self.selected = selected;
    }

    /// Check if the action is selected.
    pub fn is_selected(&self) -> bool {
        self.selected
    }

    /// Set the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Check if the action is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set the icon identifier.
    pub fn set_icon(&mut self, icon_id: impl Into<String>) {
        self.icon_id = Some(icon_id.into());
    }

    /// Get the icon identifier.
    pub fn icon_id(&self) -> Option<&str> {
        self.icon_id.as_deref()
    }

    /// Set the toolbar group.
    pub fn set_toolbar_group(&mut self, group: impl Into<String>) {
        self.toolbar_group = Some(group.into());
    }

    /// Get the toolbar group.
    pub fn toolbar_group(&self) -> Option<&str> {
        self.toolbar_group.as_deref()
    }

    /// Determine if this action should be shown in the popup menu.
    ///
    /// In Ghidra, `ListingDisplayToggleAction.isAddToPopup()` checks that
    /// the context object is a `ListingCodeComparisonView` and the source
    /// object is a `FieldPanel`. Here we perform the logical equivalent.
    pub fn should_show_in_popup(&self, context: &ListingComparisonActionContext) -> bool {
        // In the full implementation, this would check:
        //   context.context_object_type() == Some("ListingCodeComparisonView")
        //   && context.source_object_type() == Some("FieldPanel")
        // For now, we always show if the context is a listing context.
        self.show_in_popup
            && context.base().context_object_type() != Some("FieldHeader")
    }
}

/// Manages toggle actions for a listing comparison view.
///
/// Ported from the toggle action management in Ghidra's
/// `ListingCodeComparisonView` Java class.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::listing::toggle_action::*;
///
/// let mut manager = ListingToggleActionManager::new();
/// assert_eq!(manager.actions().len(), 3);
///
/// // Toggle hover
/// manager.toggle(ToggleActionKind::Hover);
/// assert!(!manager.is_selected(ToggleActionKind::Hover));
///
/// // Enable/disable all actions
/// manager.set_all_enabled(false);
/// assert!(!manager.is_enabled(ToggleActionKind::Header));
/// ```
pub struct ListingToggleActionManager {
    actions: Vec<ToggleActionState>,
}

impl ListingToggleActionManager {
    /// Create a new toggle action manager with default states.
    pub fn new() -> Self {
        let actions = vec![
            ToggleActionState::new_selected(ToggleActionKind::Header),
            ToggleActionState::new_selected(ToggleActionKind::Hover),
            ToggleActionState::new(ToggleActionKind::ScrollSync),
        ];
        Self { actions }
    }

    /// Get the list of all toggle action states.
    pub fn actions(&self) -> &[ToggleActionState] {
        &self.actions
    }

    /// Get a reference to a specific action by kind.
    pub fn get(&self, kind: ToggleActionKind) -> Option<&ToggleActionState> {
        self.actions.iter().find(|a| a.kind == kind)
    }

    /// Get a mutable reference to a specific action by kind.
    pub fn get_mut(&mut self, kind: ToggleActionKind) -> Option<&mut ToggleActionState> {
        self.actions.iter_mut().find(|a| a.kind == kind)
    }

    /// Toggle a specific action.
    ///
    /// Returns the new selected state.
    pub fn toggle(&mut self, kind: ToggleActionKind) -> bool {
        match self.actions.iter_mut().find(|a| a.kind == kind) {
            Some(action) => {
                action.toggle();
                action.selected
            }
            None => false,
        }
    }

    /// Check if a specific action is selected.
    pub fn is_selected(&self, kind: ToggleActionKind) -> bool {
        self.actions
            .iter()
            .find(|a| a.kind == kind)
            .map_or(false, |a| a.selected)
    }

    /// Check if a specific action is enabled.
    pub fn is_enabled(&self, kind: ToggleActionKind) -> bool {
        self.actions
            .iter()
            .find(|a| a.kind == kind)
            .map_or(false, |a| a.enabled)
    }

    /// Set the selected state of a specific action.
    pub fn set_selected(&mut self, kind: ToggleActionKind, selected: bool) {
        if let Some(action) = self.actions.iter_mut().find(|a| a.kind == kind) {
            action.set_selected(selected);
        }
    }

    /// Set the enabled state of all actions.
    pub fn set_all_enabled(&mut self, enabled: bool) {
        for action in &mut self.actions {
            action.set_enabled(enabled);
        }
    }

    /// Set the enabled state of a specific action.
    pub fn set_enabled(&mut self, kind: ToggleActionKind, enabled: bool) {
        if let Some(action) = self.actions.iter_mut().find(|a| a.kind == kind) {
            action.set_enabled(enabled);
        }
    }

    /// Set icon IDs for all actions from predefined constants.
    pub fn set_default_icons(&mut self) {
        if let Some(action) = self.get_mut(ToggleActionKind::Header) {
            action.set_icon("icon.base.util.listingcompare.header");
        }
        if let Some(action) = self.get_mut(ToggleActionKind::Hover) {
            action.set_icon("icon.base.util.listingcompare.hover.on");
        }
        if let Some(action) = self.get_mut(ToggleActionKind::ScrollSync) {
            action.set_icon("icon.plugin.functioncompare.scroll.lock");
        }
    }

    /// Set toolbar groups for all actions.
    pub fn set_default_toolbar_groups(&mut self) {
        if let Some(action) = self.get_mut(ToggleActionKind::ScrollSync) {
            action.set_toolbar_group("A9_SCROLLING");
        }
    }

    /// Get the number of selected actions.
    pub fn selected_count(&self) -> usize {
        self.actions.iter().filter(|a| a.selected).count()
    }

    /// Get the number of enabled actions.
    pub fn enabled_count(&self) -> usize {
        self.actions.iter().filter(|a| a.enabled).count()
    }
}

impl Default for ListingToggleActionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codecompare::model::ComparisonSide;

    fn make_listing_context() -> ListingComparisonActionContext {
        ListingComparisonActionContext::new(ComparisonSide::Left, ActionTrigger::Mouse)
    }

    // --- ToggleActionKind tests ---

    #[test]
    fn test_toggle_action_kind_label() {
        assert_eq!(ToggleActionKind::Header.label(), "Toggle Format Header");
        assert_eq!(ToggleActionKind::Hover.label(), "Toggle Mouse Hover Popups");
        assert_eq!(ToggleActionKind::ScrollSync.label(), "Synchronize Scrolling");
    }

    #[test]
    fn test_toggle_action_kind_description() {
        assert!(!ToggleActionKind::Header.description().is_empty());
        assert!(!ToggleActionKind::Hover.description().is_empty());
        assert!(!ToggleActionKind::ScrollSync.description().is_empty());
    }

    #[test]
    fn test_toggle_action_kind_help_topic() {
        assert!(!ToggleActionKind::Header.help_topic().is_empty());
        assert!(!ToggleActionKind::Hover.help_topic().is_empty());
        assert!(!ToggleActionKind::ScrollSync.help_topic().is_empty());
    }

    #[test]
    fn test_toggle_action_kind_menu_path() {
        assert_eq!(ToggleActionKind::Header.menu_path(), &["Show Listing Format Header"]);
        assert_eq!(ToggleActionKind::ScrollSync.menu_path(), &["Synchronize Scrolling"]);
    }

    #[test]
    fn test_toggle_action_kind_display() {
        assert_eq!(format!("{}", ToggleActionKind::Header), "Toggle Format Header");
    }

    // --- ToggleActionState tests ---

    #[test]
    fn test_toggle_action_state_new() {
        let state = ToggleActionState::new(ToggleActionKind::Header);
        assert_eq!(state.kind, ToggleActionKind::Header);
        assert!(!state.is_selected());
        assert!(state.is_enabled());
        assert!(state.show_in_popup);
    }

    #[test]
    fn test_toggle_action_state_new_selected() {
        let state = ToggleActionState::new_selected(ToggleActionKind::Hover);
        assert!(state.is_selected());
    }

    #[test]
    fn test_toggle_action_state_toggle() {
        let mut state = ToggleActionState::new(ToggleActionKind::Header);
        assert!(!state.is_selected());

        let new_state = state.toggle();
        assert!(new_state);
        assert!(state.is_selected());

        let new_state = state.toggle();
        assert!(!new_state);
        assert!(!state.is_selected());
    }

    #[test]
    fn test_toggle_action_state_set_selected() {
        let mut state = ToggleActionState::new(ToggleActionKind::Header);
        state.set_selected(true);
        assert!(state.is_selected());
        state.set_selected(false);
        assert!(!state.is_selected());
    }

    #[test]
    fn test_toggle_action_state_enabled() {
        let mut state = ToggleActionState::new(ToggleActionKind::Header);
        assert!(state.is_enabled());

        state.set_enabled(false);
        assert!(!state.is_enabled());
    }

    #[test]
    fn test_toggle_action_state_icon() {
        let mut state = ToggleActionState::new(ToggleActionKind::Header);
        assert!(state.icon_id().is_none());

        state.set_icon("icon.test");
        assert_eq!(state.icon_id(), Some("icon.test"));
    }

    #[test]
    fn test_toggle_action_state_toolbar_group() {
        let mut state = ToggleActionState::new(ToggleActionKind::ScrollSync);
        assert!(state.toolbar_group().is_none());

        state.set_toolbar_group("A9_SCROLLING");
        assert_eq!(state.toolbar_group(), Some("A9_SCROLLING"));
    }

    #[test]
    fn test_toggle_action_state_should_show_in_popup() {
        let state = ToggleActionState::new(ToggleActionKind::Header);
        let ctx = make_listing_context();
        assert!(state.should_show_in_popup(&ctx));
    }

    // --- ListingToggleActionManager tests ---

    #[test]
    fn test_manager_new() {
        let manager = ListingToggleActionManager::new();
        assert_eq!(manager.actions().len(), 3);
    }

    #[test]
    fn test_manager_default() {
        let manager = ListingToggleActionManager::default();
        assert_eq!(manager.actions().len(), 3);
    }

    #[test]
    fn test_manager_default_states() {
        let manager = ListingToggleActionManager::new();
        assert!(manager.is_selected(ToggleActionKind::Header));
        assert!(manager.is_selected(ToggleActionKind::Hover));
        assert!(!manager.is_selected(ToggleActionKind::ScrollSync));
    }

    #[test]
    fn test_manager_toggle() {
        let mut manager = ListingToggleActionManager::new();
        assert!(!manager.is_selected(ToggleActionKind::ScrollSync));

        let new_state = manager.toggle(ToggleActionKind::ScrollSync);
        assert!(new_state);
        assert!(manager.is_selected(ToggleActionKind::ScrollSync));

        let new_state = manager.toggle(ToggleActionKind::ScrollSync);
        assert!(!new_state);
        assert!(!manager.is_selected(ToggleActionKind::ScrollSync));
    }

    #[test]
    fn test_manager_set_selected() {
        let mut manager = ListingToggleActionManager::new();
        manager.set_selected(ToggleActionKind::ScrollSync, true);
        assert!(manager.is_selected(ToggleActionKind::ScrollSync));
    }

    #[test]
    fn test_manager_get() {
        let manager = ListingToggleActionManager::new();
        assert!(manager.get(ToggleActionKind::Header).is_some());
        assert!(manager.get(ToggleActionKind::Hover).is_some());
        assert!(manager.get(ToggleActionKind::ScrollSync).is_some());
    }

    #[test]
    fn test_manager_get_mut() {
        let mut manager = ListingToggleActionManager::new();
        if let Some(action) = manager.get_mut(ToggleActionKind::Header) {
            action.set_selected(false);
        }
        assert!(!manager.is_selected(ToggleActionKind::Header));
    }

    #[test]
    fn test_manager_set_all_enabled() {
        let mut manager = ListingToggleActionManager::new();
        manager.set_all_enabled(false);
        assert!(!manager.is_enabled(ToggleActionKind::Header));
        assert!(!manager.is_enabled(ToggleActionKind::Hover));
        assert!(!manager.is_enabled(ToggleActionKind::ScrollSync));

        manager.set_all_enabled(true);
        assert!(manager.is_enabled(ToggleActionKind::Header));
        assert!(manager.is_enabled(ToggleActionKind::Hover));
        assert!(manager.is_enabled(ToggleActionKind::ScrollSync));
    }

    #[test]
    fn test_manager_set_enabled() {
        let mut manager = ListingToggleActionManager::new();
        manager.set_enabled(ToggleActionKind::Header, false);
        assert!(!manager.is_enabled(ToggleActionKind::Header));
        assert!(manager.is_enabled(ToggleActionKind::Hover));
    }

    #[test]
    fn test_manager_set_default_icons() {
        let mut manager = ListingToggleActionManager::new();
        manager.set_default_icons();
        assert!(manager.get(ToggleActionKind::Header).unwrap().icon_id().is_some());
        assert!(manager.get(ToggleActionKind::Hover).unwrap().icon_id().is_some());
        assert!(manager.get(ToggleActionKind::ScrollSync).unwrap().icon_id().is_some());
    }

    #[test]
    fn test_manager_set_default_toolbar_groups() {
        let mut manager = ListingToggleActionManager::new();
        manager.set_default_toolbar_groups();
        assert_eq!(
            manager.get(ToggleActionKind::ScrollSync).unwrap().toolbar_group(),
            Some("A9_SCROLLING")
        );
    }

    #[test]
    fn test_manager_selected_count() {
        let mut manager = ListingToggleActionManager::new();
        assert_eq!(manager.selected_count(), 2); // Header and Hover are selected by default

        manager.toggle(ToggleActionKind::ScrollSync);
        assert_eq!(manager.selected_count(), 3);
    }

    #[test]
    fn test_manager_enabled_count() {
        let manager = ListingToggleActionManager::new();
        assert_eq!(manager.enabled_count(), 3);
    }
}
