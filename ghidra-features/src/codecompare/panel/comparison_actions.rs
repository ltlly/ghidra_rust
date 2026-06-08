//! Action management for code comparison panels.
//!
//! Ported from Ghidra's action management in `FunctionComparisonPanel` and
//! `CodeComparisonView` Java classes in `ghidra.features.base.codecompare.panel`.
//!
//! This module provides action management for code comparison views,
//! including scroll lock toggling, orientation toggling, and view-specific
//! actions. In Ghidra, these are `DockingAction` objects that are registered
//! with the tool's action manager. Here we capture the action state and
//! behavior without the Swing/docking framework.
//!
//! # Key types
//!
//! - [`ComparisonActionKind`] -- the kind of comparison action
//! - [`ComparisonAction`] -- a single action with state
//! - [`ComparisonActionManager`] -- manages all actions for a comparison panel
//! - [`ActionEvent`] -- events emitted when actions are triggered

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::super::model::ComparisonSide;
use super::code_comparison_view::ViewOrientation;

/// The kind of action available in a code comparison panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ComparisonActionKind {
    /// Toggle synchronized scrolling between the two sides.
    ToggleScrollSync,
    /// Toggle the orientation (side-by-side vs. stacked).
    ToggleOrientation,
    /// Toggle the format header visibility.
    ToggleHeader,
    /// Toggle mouse hover popups.
    ToggleHover,
    /// Navigate to the next difference.
    NextDiff,
    /// Navigate to the previous difference.
    PreviousDiff,
    /// Navigate to the next unmatched code area.
    NextUnmatched,
    /// Navigate to the previous unmatched code area.
    PreviousUnmatched,
    /// Toggle ignore byte diffs filter.
    ToggleIgnoreBytes,
    /// Toggle ignore constants filter.
    ToggleIgnoreConstants,
    /// Toggle ignore register names filter.
    ToggleIgnoreRegisters,
}

impl ComparisonActionKind {
    /// A human-readable label for this action.
    pub fn label(&self) -> &'static str {
        match self {
            Self::ToggleScrollSync => "Synchronize Scrolling",
            Self::ToggleOrientation => "Toggle Orientation",
            Self::ToggleHeader => "Show Format Header",
            Self::ToggleHover => "Toggle Mouse Hover Popups",
            Self::NextDiff => "Go To Next Difference",
            Self::PreviousDiff => "Go To Previous Difference",
            Self::NextUnmatched => "Go To Next Unmatched",
            Self::PreviousUnmatched => "Go To Previous Unmatched",
            Self::ToggleIgnoreBytes => "Ignore Byte Diffs",
            Self::ToggleIgnoreConstants => "Ignore Operand Constants",
            Self::ToggleIgnoreRegisters => "Ignore Operand Registers",
        }
    }

    /// A description of what this action does.
    pub fn description(&self) -> &'static str {
        match self {
            Self::ToggleScrollSync => {
                "Lock/unlock synchronized scrolling of the dual listing view."
            }
            Self::ToggleOrientation => {
                "Toggle between side-by-side and stacked orientation."
            }
            Self::ToggleHeader => "Toggle the format header display.",
            Self::ToggleHover => "Toggle mouse hover popups.",
            Self::NextDiff => "Navigate to the next difference.",
            Self::PreviousDiff => "Navigate to the previous difference.",
            Self::NextUnmatched => "Navigate to the next unmatched code area.",
            Self::PreviousUnmatched => "Navigate to the previous unmatched code area.",
            Self::ToggleIgnoreBytes => {
                "If selected, difference highlights should ignore byte differences."
            }
            Self::ToggleIgnoreConstants => {
                "If selected, difference highlights should ignore operand constant differences."
            }
            Self::ToggleIgnoreRegisters => {
                "If selected, difference highlights should ignore operand register differences."
            }
        }
    }

    /// The help topic for this action.
    pub fn help_topic(&self) -> &'static str {
        match self {
            Self::ToggleScrollSync => "FunctionComparison",
            Self::ToggleOrientation => "FunctionComparison",
            Self::ToggleHeader => "Dual Listing Toggle Format Header",
            Self::ToggleHover => "Dual Listing Toggle Mouse Hover Popups",
            Self::NextDiff => "FunctionComparison",
            Self::PreviousDiff => "FunctionComparison",
            Self::NextUnmatched => "FunctionComparison",
            Self::PreviousUnmatched => "FunctionComparison",
            Self::ToggleIgnoreBytes => "Dual Listing Ignore Bytes",
            Self::ToggleIgnoreConstants => "Dual Listing Ignore Operand Constants",
            Self::ToggleIgnoreRegisters => "Dual Listing Ignore Operand Registers",
        }
    }

    /// Whether this action is a toggle (has a selected state).
    pub fn is_toggle(&self) -> bool {
        matches!(
            self,
            Self::ToggleScrollSync
                | Self::ToggleOrientation
                | Self::ToggleHeader
                | Self::ToggleHover
                | Self::ToggleIgnoreBytes
                | Self::ToggleIgnoreConstants
                | Self::ToggleIgnoreRegisters
        )
    }

    /// Whether this action is a navigation action.
    pub fn is_navigation(&self) -> bool {
        matches!(
            self,
            Self::NextDiff | Self::PreviousDiff | Self::NextUnmatched | Self::PreviousUnmatched
        )
    }

    /// The menu path for this action.
    pub fn menu_path(&self) -> &[&str] {
        match self {
            Self::ToggleScrollSync => &["Synchronize Scrolling"],
            Self::ToggleOrientation => &["Toggle Side by Side"],
            Self::ToggleHeader => &["Show Listing Format Header"],
            Self::ToggleHover => &["Toggle Mouse Hover Popups"],
            Self::NextDiff => &["Go To", "Next Difference"],
            Self::PreviousDiff => &["Go To", "Previous Difference"],
            Self::NextUnmatched => &["Go To", "Next Unmatched"],
            Self::PreviousUnmatched => &["Go To", "Previous Unmatched"],
            Self::ToggleIgnoreBytes => &["Ignore Bytes As Differences"],
            Self::ToggleIgnoreConstants => &["Ignore Operand Constants As Differences"],
            Self::ToggleIgnoreRegisters => &["Ignore Operand Registers As Differences"],
        }
    }
}

/// The state of a comparison action.
#[derive(Debug, Clone)]
pub struct ComparisonAction {
    /// The kind of action.
    pub kind: ComparisonActionKind,
    /// Whether the action is currently enabled.
    pub enabled: bool,
    /// Whether the action is currently selected (for toggle actions).
    pub selected: bool,
    /// The icon identifier.
    pub icon: Option<String>,
    /// The keyboard shortcut.
    pub key_binding: Option<String>,
    /// The action group for menu ordering.
    pub group: String,
}

impl ComparisonAction {
    /// Create a new action.
    pub fn new(kind: ComparisonActionKind) -> Self {
        Self {
            kind,
            enabled: true,
            selected: false,
            icon: None,
            key_binding: None,
            group: "ComparisonActions".to_string(),
        }
    }

    /// Create a new toggle action that is initially selected.
    pub fn new_selected(kind: ComparisonActionKind) -> Self {
        Self {
            kind,
            enabled: true,
            selected: true,
            icon: None,
            key_binding: None,
            group: "ComparisonActions".to_string(),
        }
    }

    /// Toggle the selected state (for toggle actions).
    ///
    /// Returns the new selected state.
    pub fn toggle(&mut self) -> bool {
        self.selected = !self.selected;
        self.selected
    }

    /// Check if this action is a toggle action.
    pub fn is_toggle(&self) -> bool {
        self.kind.is_toggle()
    }

    /// Check if this action is a navigation action.
    pub fn is_navigation(&self) -> bool {
        self.kind.is_navigation()
    }
}

/// Events emitted when comparison actions are triggered.
#[derive(Debug, Clone)]
pub enum ActionEvent {
    /// A toggle action was toggled.
    Toggled {
        kind: ComparisonActionKind,
        new_state: bool,
    },
    /// A navigation action was performed.
    Navigation {
        kind: ComparisonActionKind,
        success: bool,
    },
    /// An action was enabled/disabled.
    EnablementChanged {
        kind: ComparisonActionKind,
        enabled: bool,
    },
}

/// Trait for receiving action events.
pub trait ActionListener: Send + Sync {
    /// Called when an action event occurs.
    fn on_action_event(&self, event: &ActionEvent);
}

/// Manages all actions for a code comparison panel.
///
/// This is the Rust equivalent of the action management in Ghidra's
/// `FunctionComparisonPanel` and `CodeComparisonView` Java classes.
/// It creates, manages, and dispatches events for all comparison actions.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::panel::comparison_actions::*;
///
/// let mut manager = ComparisonActionManager::new();
/// assert!(manager.is_selected(ComparisonActionKind::ToggleHeader));
/// assert!(!manager.is_selected(ComparisonActionKind::ToggleScrollSync));
///
/// manager.toggle(ComparisonActionKind::ToggleScrollSync);
/// assert!(manager.is_selected(ComparisonActionKind::ToggleScrollSync));
/// ```
pub struct ComparisonActionManager {
    actions: HashMap<ComparisonActionKind, ComparisonAction>,
    listeners: Vec<Arc<dyn ActionListener>>,
    invocations: Arc<Mutex<Vec<ActionEvent>>>,
}

impl ComparisonActionManager {
    /// Create a new action manager with default actions.
    pub fn new() -> Self {
        let mut actions = HashMap::new();

        // Toggle actions (initially selected)
        actions.insert(
            ComparisonActionKind::ToggleHeader,
            ComparisonAction::new_selected(ComparisonActionKind::ToggleHeader),
        );
        actions.insert(
            ComparisonActionKind::ToggleHover,
            ComparisonAction::new_selected(ComparisonActionKind::ToggleHover),
        );

        // Toggle actions (initially not selected)
        actions.insert(
            ComparisonActionKind::ToggleScrollSync,
            ComparisonAction::new(ComparisonActionKind::ToggleScrollSync),
        );
        actions.insert(
            ComparisonActionKind::ToggleOrientation,
            ComparisonAction::new(ComparisonActionKind::ToggleOrientation),
        );

        // Filter toggle actions (initially not selected)
        actions.insert(
            ComparisonActionKind::ToggleIgnoreBytes,
            ComparisonAction::new(ComparisonActionKind::ToggleIgnoreBytes),
        );
        actions.insert(
            ComparisonActionKind::ToggleIgnoreConstants,
            ComparisonAction::new(ComparisonActionKind::ToggleIgnoreConstants),
        );
        actions.insert(
            ComparisonActionKind::ToggleIgnoreRegisters,
            ComparisonAction::new(ComparisonActionKind::ToggleIgnoreRegisters),
        );

        // Navigation actions
        actions.insert(
            ComparisonActionKind::NextDiff,
            ComparisonAction::new(ComparisonActionKind::NextDiff),
        );
        actions.insert(
            ComparisonActionKind::PreviousDiff,
            ComparisonAction::new(ComparisonActionKind::PreviousDiff),
        );
        actions.insert(
            ComparisonActionKind::NextUnmatched,
            ComparisonAction::new(ComparisonActionKind::NextUnmatched),
        );
        actions.insert(
            ComparisonActionKind::PreviousUnmatched,
            ComparisonAction::new(ComparisonActionKind::PreviousUnmatched),
        );

        Self {
            actions,
            listeners: Vec::new(),
            invocations: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Add a listener for action events.
    pub fn add_listener(&mut self, listener: Arc<dyn ActionListener>) {
        self.listeners.push(listener);
    }

    /// Remove all listeners.
    pub fn clear_listeners(&mut self) {
        self.listeners.clear();
    }

    /// Fire an action event to all listeners.
    fn fire_event(&self, event: &ActionEvent) {
        for listener in &self.listeners {
            listener.on_action_event(event);
        }
        self.invocations.lock().unwrap().push(event.clone());
    }

    /// Get a reference to an action.
    pub fn get(&self, kind: ComparisonActionKind) -> Option<&ComparisonAction> {
        self.actions.get(&kind)
    }

    /// Get a mutable reference to an action.
    pub fn get_mut(&mut self, kind: ComparisonActionKind) -> Option<&mut ComparisonAction> {
        self.actions.get_mut(&kind)
    }

    /// Check if a toggle action is currently selected.
    pub fn is_selected(&self, kind: ComparisonActionKind) -> bool {
        self.actions.get(&kind).map_or(false, |a| a.selected)
    }

    /// Check if an action is currently enabled.
    pub fn is_enabled(&self, kind: ComparisonActionKind) -> bool {
        self.actions.get(&kind).map_or(false, |a| a.enabled)
    }

    /// Toggle a toggle action.
    ///
    /// Returns the new selected state, or None if the action doesn't exist
    /// or is not a toggle action.
    pub fn toggle(&mut self, kind: ComparisonActionKind) -> Option<bool> {
        let action = self.actions.get_mut(&kind)?;
        if !action.is_toggle() {
            return None;
        }
        let new_state = action.toggle();
        self.fire_event(&ActionEvent::Toggled {
            kind,
            new_state,
        });
        Some(new_state)
    }

    /// Set the selected state of a toggle action.
    pub fn set_selected(&mut self, kind: ComparisonActionKind, selected: bool) {
        if let Some(action) = self.actions.get_mut(&kind) {
            action.selected = selected;
        }
    }

    /// Set the enabled state of an action.
    pub fn set_enabled(&mut self, kind: ComparisonActionKind, enabled: bool) {
        if let Some(action) = self.actions.get_mut(&kind) {
            action.enabled = enabled;
            self.fire_event(&ActionEvent::EnablementChanged { kind, enabled });
        }
    }

    /// Enable or disable all actions.
    pub fn set_all_enabled(&mut self, enabled: bool) {
        let kinds: Vec<ComparisonActionKind> = self.actions.keys().copied().collect();
        for kind in kinds {
            self.set_enabled(kind, enabled);
        }
    }

    /// Enable or disable navigation actions.
    pub fn set_navigation_enabled(&mut self, enabled: bool) {
        let nav_kinds = [
            ComparisonActionKind::NextDiff,
            ComparisonActionKind::PreviousDiff,
            ComparisonActionKind::NextUnmatched,
            ComparisonActionKind::PreviousUnmatched,
        ];
        for kind in &nav_kinds {
            self.set_enabled(*kind, enabled);
        }
    }

    /// Enable or disable filter toggle actions.
    pub fn set_filter_enabled(&mut self, enabled: bool) {
        let filter_kinds = [
            ComparisonActionKind::ToggleIgnoreBytes,
            ComparisonActionKind::ToggleIgnoreConstants,
            ComparisonActionKind::ToggleIgnoreRegisters,
        ];
        for kind in &filter_kinds {
            self.set_enabled(*kind, enabled);
        }
    }

    /// Perform a navigation action.
    ///
    /// Returns true if the navigation was performed (action was enabled).
    pub fn navigate(&mut self, kind: ComparisonActionKind) -> bool {
        if !kind.is_navigation() {
            return false;
        }
        let enabled = self.actions.get(&kind).map_or(false, |a| a.enabled);
        self.fire_event(&ActionEvent::Navigation {
            kind,
            success: enabled,
        });
        enabled
    }

    /// Get the selected orientation based on the toggle state.
    pub fn orientation(&self) -> ViewOrientation {
        if self.is_selected(ComparisonActionKind::ToggleOrientation) {
            ViewOrientation::Stacked
        } else {
            ViewOrientation::SideBySide
        }
    }

    /// Set the orientation and update the toggle state.
    pub fn set_orientation(&mut self, orientation: ViewOrientation) {
        let selected = orientation == ViewOrientation::Stacked;
        self.set_selected(ComparisonActionKind::ToggleOrientation, selected);
    }

    /// Get all toggle actions that are currently selected.
    pub fn selected_actions(&self) -> Vec<ComparisonActionKind> {
        self.actions
            .iter()
            .filter(|(_, a)| a.selected)
            .map(|(k, _)| *k)
            .collect()
    }

    /// Get all toggle actions that are currently enabled.
    pub fn enabled_actions(&self) -> Vec<ComparisonActionKind> {
        self.actions
            .iter()
            .filter(|(_, a)| a.enabled)
            .map(|(k, _)| *k)
            .collect()
    }

    /// Get the number of actions.
    pub fn action_count(&self) -> usize {
        self.actions.len()
    }

    /// Get the recorded invocations (useful for testing).
    pub fn invocations(&self) -> Vec<ActionEvent> {
        self.invocations.lock().unwrap().clone()
    }

    /// Clear the recorded invocations.
    pub fn clear_invocations(&self) {
        self.invocations.lock().unwrap().clear();
    }
}

impl Default for ComparisonActionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// A simple listener that records action events.
#[derive(Debug, Default)]
pub struct TrackingActionListener {
    /// Recorded events.
    pub events: Mutex<Vec<ActionEvent>>,
}

impl TrackingActionListener {
    /// Create a new tracking listener.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the number of events received.
    pub fn event_count(&self) -> usize {
        self.events.lock().unwrap().len()
    }
}

impl ActionListener for TrackingActionListener {
    fn on_action_event(&self, event: &ActionEvent) {
        self.events.lock().unwrap().push(event.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // --- ComparisonActionKind tests ---

    #[test]
    fn test_action_kind_label() {
        assert_eq!(
            ComparisonActionKind::ToggleScrollSync.label(),
            "Synchronize Scrolling"
        );
        assert_eq!(
            ComparisonActionKind::NextDiff.label(),
            "Go To Next Difference"
        );
    }

    #[test]
    fn test_action_kind_description() {
        assert!(!ComparisonActionKind::ToggleScrollSync.description().is_empty());
        assert!(!ComparisonActionKind::NextDiff.description().is_empty());
    }

    #[test]
    fn test_action_kind_help_topic() {
        assert!(!ComparisonActionKind::ToggleScrollSync.help_topic().is_empty());
    }

    #[test]
    fn test_action_kind_is_toggle() {
        assert!(ComparisonActionKind::ToggleScrollSync.is_toggle());
        assert!(ComparisonActionKind::ToggleHeader.is_toggle());
        assert!(ComparisonActionKind::ToggleIgnoreBytes.is_toggle());
        assert!(!ComparisonActionKind::NextDiff.is_toggle());
    }

    #[test]
    fn test_action_kind_is_navigation() {
        assert!(ComparisonActionKind::NextDiff.is_navigation());
        assert!(ComparisonActionKind::PreviousDiff.is_navigation());
        assert!(ComparisonActionKind::NextUnmatched.is_navigation());
        assert!(!ComparisonActionKind::ToggleScrollSync.is_navigation());
    }

    #[test]
    fn test_action_kind_menu_path() {
        assert_eq!(
            ComparisonActionKind::ToggleScrollSync.menu_path(),
            &["Synchronize Scrolling"]
        );
        assert_eq!(
            ComparisonActionKind::NextDiff.menu_path(),
            &["Go To", "Next Difference"]
        );
    }

    // --- ComparisonAction tests ---

    #[test]
    fn test_action_new() {
        let action = ComparisonAction::new(ComparisonActionKind::ToggleHeader);
        assert_eq!(action.kind, ComparisonActionKind::ToggleHeader);
        assert!(action.enabled);
        assert!(!action.selected);
    }

    #[test]
    fn test_action_new_selected() {
        let action = ComparisonAction::new_selected(ComparisonActionKind::ToggleHeader);
        assert!(action.selected);
    }

    #[test]
    fn test_action_toggle() {
        let mut action = ComparisonAction::new(ComparisonActionKind::ToggleHeader);
        assert!(!action.selected);

        let new_state = action.toggle();
        assert!(new_state);
        assert!(action.selected);

        let new_state = action.toggle();
        assert!(!new_state);
        assert!(!action.selected);
    }

    // --- ComparisonActionManager tests ---

    #[test]
    fn test_manager_new() {
        let manager = ComparisonActionManager::new();
        assert_eq!(manager.action_count(), 11);
    }

    #[test]
    fn test_manager_default() {
        let manager = ComparisonActionManager::default();
        assert_eq!(manager.action_count(), 11);
    }

    #[test]
    fn test_manager_default_states() {
        let manager = ComparisonActionManager::new();

        // Initially selected
        assert!(manager.is_selected(ComparisonActionKind::ToggleHeader));
        assert!(manager.is_selected(ComparisonActionKind::ToggleHover));

        // Initially not selected
        assert!(!manager.is_selected(ComparisonActionKind::ToggleScrollSync));
        assert!(!manager.is_selected(ComparisonActionKind::ToggleOrientation));
        assert!(!manager.is_selected(ComparisonActionKind::ToggleIgnoreBytes));
    }

    #[test]
    fn test_manager_toggle() {
        let mut manager = ComparisonActionManager::new();
        assert!(!manager.is_selected(ComparisonActionKind::ToggleScrollSync));

        let result = manager.toggle(ComparisonActionKind::ToggleScrollSync);
        assert_eq!(result, Some(true));
        assert!(manager.is_selected(ComparisonActionKind::ToggleScrollSync));

        let result = manager.toggle(ComparisonActionKind::ToggleScrollSync);
        assert_eq!(result, Some(false));
        assert!(!manager.is_selected(ComparisonActionKind::ToggleScrollSync));
    }

    #[test]
    fn test_manager_toggle_navigation_returns_none() {
        let mut manager = ComparisonActionManager::new();
        let result = manager.toggle(ComparisonActionKind::NextDiff);
        assert_eq!(result, None);
    }

    #[test]
    fn test_manager_set_selected() {
        let mut manager = ComparisonActionManager::new();
        manager.set_selected(ComparisonActionKind::ToggleScrollSync, true);
        assert!(manager.is_selected(ComparisonActionKind::ToggleScrollSync));
    }

    #[test]
    fn test_manager_set_enabled() {
        let mut manager = ComparisonActionManager::new();
        assert!(manager.is_enabled(ComparisonActionKind::NextDiff));

        manager.set_enabled(ComparisonActionKind::NextDiff, false);
        assert!(!manager.is_enabled(ComparisonActionKind::NextDiff));
    }

    #[test]
    fn test_manager_set_all_enabled() {
        let mut manager = ComparisonActionManager::new();
        manager.set_all_enabled(false);

        for kind in &[
            ComparisonActionKind::ToggleHeader,
            ComparisonActionKind::NextDiff,
            ComparisonActionKind::ToggleIgnoreBytes,
        ] {
            assert!(!manager.is_enabled(*kind));
        }

        manager.set_all_enabled(true);
        for kind in &[
            ComparisonActionKind::ToggleHeader,
            ComparisonActionKind::NextDiff,
            ComparisonActionKind::ToggleIgnoreBytes,
        ] {
            assert!(manager.is_enabled(*kind));
        }
    }

    #[test]
    fn test_manager_set_navigation_enabled() {
        let mut manager = ComparisonActionManager::new();
        manager.set_navigation_enabled(false);

        assert!(!manager.is_enabled(ComparisonActionKind::NextDiff));
        assert!(!manager.is_enabled(ComparisonActionKind::PreviousDiff));
        assert!(!manager.is_enabled(ComparisonActionKind::NextUnmatched));
        assert!(!manager.is_enabled(ComparisonActionKind::PreviousUnmatched));

        // Toggle actions should still be enabled
        assert!(manager.is_enabled(ComparisonActionKind::ToggleHeader));
    }

    #[test]
    fn test_manager_set_filter_enabled() {
        let mut manager = ComparisonActionManager::new();
        manager.set_filter_enabled(false);

        assert!(!manager.is_enabled(ComparisonActionKind::ToggleIgnoreBytes));
        assert!(!manager.is_enabled(ComparisonActionKind::ToggleIgnoreConstants));
        assert!(!manager.is_enabled(ComparisonActionKind::ToggleIgnoreRegisters));

        // Other actions should still be enabled
        assert!(manager.is_enabled(ComparisonActionKind::ToggleHeader));
    }

    #[test]
    fn test_manager_navigate() {
        let mut manager = ComparisonActionManager::new();
        assert!(manager.navigate(ComparisonActionKind::NextDiff));

        manager.set_enabled(ComparisonActionKind::NextDiff, false);
        assert!(!manager.navigate(ComparisonActionKind::NextDiff));
    }

    #[test]
    fn test_manager_navigate_non_navigation() {
        let mut manager = ComparisonActionManager::new();
        assert!(!manager.navigate(ComparisonActionKind::ToggleHeader));
    }

    #[test]
    fn test_manager_orientation() {
        let mut manager = ComparisonActionManager::new();
        assert_eq!(manager.orientation(), ViewOrientation::SideBySide);

        manager.toggle(ComparisonActionKind::ToggleOrientation);
        assert_eq!(manager.orientation(), ViewOrientation::Stacked);
    }

    #[test]
    fn test_manager_set_orientation() {
        let mut manager = ComparisonActionManager::new();
        manager.set_orientation(ViewOrientation::Stacked);
        assert!(manager.is_selected(ComparisonActionKind::ToggleOrientation));
        assert_eq!(manager.orientation(), ViewOrientation::Stacked);

        manager.set_orientation(ViewOrientation::SideBySide);
        assert!(!manager.is_selected(ComparisonActionKind::ToggleOrientation));
    }

    #[test]
    fn test_manager_selected_actions() {
        let mut manager = ComparisonActionManager::new();
        let selected = manager.selected_actions();
        assert!(selected.contains(&ComparisonActionKind::ToggleHeader));
        assert!(selected.contains(&ComparisonActionKind::ToggleHover));
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn test_manager_enabled_actions() {
        let manager = ComparisonActionManager::new();
        let enabled = manager.enabled_actions();
        assert_eq!(enabled.len(), 11); // All actions are enabled by default
    }

    #[test]
    fn test_manager_listener() {
        let mut manager = ComparisonActionManager::new();
        let listener = Arc::new(TrackingActionListener::new());
        manager.add_listener(listener.clone());

        manager.toggle(ComparisonActionKind::ToggleScrollSync);
        assert_eq!(listener.event_count(), 1);
    }

    #[test]
    fn test_manager_listener_enablement() {
        let mut manager = ComparisonActionManager::new();
        let listener = Arc::new(TrackingActionListener::new());
        manager.add_listener(listener.clone());

        manager.set_enabled(ComparisonActionKind::NextDiff, false);
        assert_eq!(listener.event_count(), 1);
    }

    #[test]
    fn test_manager_clear_listeners() {
        let mut manager = ComparisonActionManager::new();
        let listener = Arc::new(TrackingActionListener::new());
        manager.add_listener(listener.clone());

        manager.toggle(ComparisonActionKind::ToggleScrollSync);
        assert_eq!(listener.event_count(), 1);

        manager.clear_listeners();
        manager.toggle(ComparisonActionKind::ToggleHeader);
        assert_eq!(listener.event_count(), 1); // Should not increase
    }

    #[test]
    fn test_manager_invocations() {
        let mut manager = ComparisonActionManager::new();

        manager.toggle(ComparisonActionKind::ToggleScrollSync);
        manager.toggle(ComparisonActionKind::ToggleHeader);
        manager.set_enabled(ComparisonActionKind::NextDiff, false);

        let invocations = manager.invocations();
        assert_eq!(invocations.len(), 3);
    }

    #[test]
    fn test_manager_clear_invocations() {
        let mut manager = ComparisonActionManager::new();

        manager.toggle(ComparisonActionKind::ToggleScrollSync);
        assert_eq!(manager.invocations().len(), 1);

        manager.clear_invocations();
        assert_eq!(manager.invocations().len(), 0);
    }

    // --- TrackingActionListener tests ---

    #[test]
    fn test_tracking_listener() {
        let listener = TrackingActionListener::new();
        assert_eq!(listener.event_count(), 0);

        listener.on_action_event(&ActionEvent::Toggled {
            kind: ComparisonActionKind::ToggleHeader,
            new_state: true,
        });
        assert_eq!(listener.event_count(), 1);
    }
}
