//! Actions that control listing diff filtering.
//!
//! Ported from Ghidra's `ListingDiffActionManager` Java class in
//! `ghidra.features.base.codecompare.listing`.
//!
//! This module manages toggle actions for controlling which kinds of
//! differences are highlighted in the listing comparison view. Users
//! can toggle whether byte differences, operand constant differences,
//! and register name differences should be considered when computing
//! the diff.
//!
//! # Key types
//!
//! - [`DiffToggleAction`] -- a toggle action for a specific diff filter
//! - [`DiffFilterKind`] -- the kind of difference to filter
//! - [`ListingDiffActionManager`] -- manages the set of diff toggle actions

use std::sync::{Arc, Mutex};

/// The kind of difference that can be toggled on or off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiffFilterKind {
    /// Whether to ignore byte-level differences.
    IgnoreByteDiffs,
    /// Whether to ignore constant operand differences.
    IgnoreConstants,
    /// Whether to ignore register name differences.
    IgnoreRegisterNames,
}

impl DiffFilterKind {
    /// A human-readable label for this filter.
    pub fn label(&self) -> &'static str {
        match self {
            Self::IgnoreByteDiffs => "Toggle Ignore Byte Diffs",
            Self::IgnoreConstants => "Toggle Ignore Constants",
            Self::IgnoreRegisterNames => "Toggle Ignore Register Names",
        }
    }

    /// A description of this filter.
    pub fn description(&self) -> &'static str {
        match self {
            Self::IgnoreByteDiffs => {
                "If selected, difference highlights should ignore Byte differences."
            }
            Self::IgnoreConstants => {
                "If selected, difference highlights should ignore operand Constants."
            }
            Self::IgnoreRegisterNames => {
                "If selected, difference highlights should ignore operand Registers."
            }
        }
    }

    /// The popup menu label for this action.
    pub fn menu_label(&self) -> &'static str {
        match self {
            Self::IgnoreByteDiffs => "Ignore Bytes As Differences",
            Self::IgnoreConstants => "Ignore Operand Constants As Differences",
            Self::IgnoreRegisterNames => "Ignore Operand Registers As Differences",
        }
    }

    /// The help topic key for this action.
    pub fn help_topic(&self) -> &'static str {
        match self {
            Self::IgnoreByteDiffs => "Dual Listing Ignore Bytes",
            Self::IgnoreConstants => "Dual Listing Ignore Operand Constants",
            Self::IgnoreRegisterNames => "Dual Listing Ignore Operand Registers",
        }
    }

    /// The action group for ordering in popup menus.
    pub fn action_group(&self) -> &'static str {
        "A4_Diff"
    }

    /// The icon name for this action (when active).
    pub fn icon_name(&self) -> &'static str {
        match self {
            Self::IgnoreByteDiffs => "icon.base.util.listingdiff.diffs.byte",
            Self::IgnoreConstants => "icon.base.util.listingdiff.diffs.constants",
            Self::IgnoreRegisterNames => "icon.base.util.listingdiff.diffs.registers",
        }
    }

    /// The icon name for this action (when inactive / negated).
    pub fn negated_icon_name(&self) -> &'static str {
        match self {
            Self::IgnoreByteDiffs => "icon.base.util.listingdiff.diffs.byte.not",
            Self::IgnoreConstants => "icon.base.util.listingdiff.diffs.constants.not",
            Self::IgnoreRegisterNames => "icon.base.util.listingdiff.diffs.registers.not",
        }
    }
}

/// A toggle action that controls a specific diff filter.
///
/// Each action has an enabled state (whether the action itself can be
/// invoked) and a selected state (whether the filter is currently active).
///
/// Ported from the inner classes of Ghidra's `ListingDiffActionManager`.
#[derive(Debug, Clone)]
pub struct DiffToggleAction {
    /// The kind of filter this action controls.
    pub kind: DiffFilterKind,
    /// Whether this action is enabled (can be invoked).
    enabled: bool,
    /// Whether this filter is currently active (selected).
    selected: bool,
}

impl DiffToggleAction {
    /// Create a new toggle action.
    pub fn new(kind: DiffFilterKind) -> Self {
        Self {
            kind,
            enabled: true,
            selected: false,
        }
    }

    /// Get the display name of this action.
    pub fn name(&self) -> &'static str {
        self.kind.label()
    }

    /// Get the description of this action.
    pub fn description(&self) -> &'static str {
        self.kind.description()
    }

    /// Get the menu label.
    pub fn menu_label(&self) -> &'static str {
        self.kind.menu_label()
    }

    /// Check if this action is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Check if this filter is currently selected (active).
    pub fn is_selected(&self) -> bool {
        self.selected
    }

    /// Set the selected state.
    pub fn set_selected(&mut self, selected: bool) {
        self.selected = selected;
    }

    /// Toggle the selected state and return the new value.
    pub fn toggle(&mut self) -> bool {
        self.selected = !self.selected;
        self.selected
    }

    /// Get the icon name based on current state.
    ///
    /// Returns the negated icon when selected (filter is active, showing
    /// that differences of this kind are being suppressed), and the
    /// normal icon when not selected.
    pub fn current_icon_name(&self) -> &'static str {
        if self.selected {
            self.kind.negated_icon_name()
        } else {
            self.kind.icon_name()
        }
    }
}

/// State tracked by a diff action when it is invoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffActionInvocation {
    /// The filter that was toggled.
    pub filter: DiffFilterKind,
    /// The new state of the filter after toggling.
    pub new_state: bool,
}

/// Trait for receiving notifications when a diff filter action is toggled.
pub trait DiffActionListener: Send + Sync {
    /// Called when a diff filter toggle action is performed.
    fn on_action_toggled(&self, invocation: &DiffActionInvocation);
}

/// Manages the set of toggle actions that control listing diff filtering.
///
/// The manager creates and owns three toggle actions for byte diffs,
/// constant diffs, and register name diffs. It coordinates their
/// enabled/selected states and dispatches action events to listeners.
///
/// Ported from Ghidra's `ListingDiffActionManager` Java class.
pub struct ListingDiffActionManager {
    /// The toggle action for ignoring byte differences.
    pub toggle_byte_diffs: DiffToggleAction,
    /// The toggle action for ignoring operand constant differences.
    pub toggle_constants: DiffToggleAction,
    /// The toggle action for ignoring register name differences.
    pub toggle_registers: DiffToggleAction,
    /// Listeners for action events.
    listeners: Vec<Arc<dyn DiffActionListener>>,
    /// Recorded invocations (for testing).
    invocations: Arc<Mutex<Vec<DiffActionInvocation>>>,
}

impl ListingDiffActionManager {
    /// Create a new action manager with default (non-selected) actions.
    pub fn new() -> Self {
        Self {
            toggle_byte_diffs: DiffToggleAction::new(DiffFilterKind::IgnoreByteDiffs),
            toggle_constants: DiffToggleAction::new(DiffFilterKind::IgnoreConstants),
            toggle_registers: DiffToggleAction::new(DiffFilterKind::IgnoreRegisterNames),
            listeners: Vec::new(),
            invocations: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Get all actions as a slice.
    pub fn actions(&self) -> [&DiffToggleAction; 3] {
        [
            &self.toggle_byte_diffs,
            &self.toggle_constants,
            &self.toggle_registers,
        ]
    }

    /// Get all actions as mutable references (for bulk operations).
    pub fn actions_mut(&mut self) -> [&mut DiffToggleAction; 3] {
        [
            &mut self.toggle_byte_diffs,
            &mut self.toggle_constants,
            &mut self.toggle_registers,
        ]
    }

    /// Add a listener for action events.
    pub fn add_listener(&mut self, listener: Arc<dyn DiffActionListener>) {
        self.listeners.push(listener);
    }

    /// Remove all listeners.
    pub fn clear_listeners(&mut self) {
        self.listeners.clear();
    }

    /// Update the enablement of all actions.
    ///
    /// When the comparison view is not showing, all actions should be disabled.
    pub fn update_action_enablement(&mut self, is_showing: bool) {
        self.toggle_byte_diffs.set_enabled(is_showing);
        self.toggle_constants.set_enabled(is_showing);
        self.toggle_registers.set_enabled(is_showing);
    }

    /// Toggle the ignore byte diffs action.
    ///
    /// Returns the new selected state.
    pub fn toggle_ignore_byte_diffs(&mut self) -> bool {
        let new_state = self.toggle_byte_diffs.toggle();
        let invocation = DiffActionInvocation {
            filter: DiffFilterKind::IgnoreByteDiffs,
            new_state,
        };
        self.invocations.lock().unwrap().push(invocation.clone());
        self.fire_action_toggled(&invocation);
        new_state
    }

    /// Toggle the ignore constants action.
    ///
    /// Returns the new selected state.
    pub fn toggle_ignore_constants(&mut self) -> bool {
        let new_state = self.toggle_constants.toggle();
        let invocation = DiffActionInvocation {
            filter: DiffFilterKind::IgnoreConstants,
            new_state,
        };
        self.invocations.lock().unwrap().push(invocation.clone());
        self.fire_action_toggled(&invocation);
        new_state
    }

    /// Toggle the ignore register names action.
    ///
    /// Returns the new selected state.
    pub fn toggle_ignore_registers(&mut self) -> bool {
        let new_state = self.toggle_registers.toggle();
        let invocation = DiffActionInvocation {
            filter: DiffFilterKind::IgnoreRegisterNames,
            new_state,
        };
        self.invocations.lock().unwrap().push(invocation.clone());
        self.fire_action_toggled(&invocation);
        new_state
    }

    /// Fire the action toggled event to all listeners.
    fn fire_action_toggled(&self, invocation: &DiffActionInvocation) {
        for listener in &self.listeners {
            listener.on_action_toggled(invocation);
        }
    }

    /// Get the recorded invocations (useful for testing).
    pub fn invocations(&self) -> Vec<DiffActionInvocation> {
        self.invocations.lock().unwrap().clone()
    }

    /// Clear the recorded invocations.
    pub fn clear_invocations(&self) {
        self.invocations.lock().unwrap().clear();
    }

    /// Get the current diff filter state as a set of active filters.
    pub fn active_filters(&self) -> Vec<DiffFilterKind> {
        let mut filters = Vec::new();
        if self.toggle_byte_diffs.is_selected() {
            filters.push(DiffFilterKind::IgnoreByteDiffs);
        }
        if self.toggle_constants.is_selected() {
            filters.push(DiffFilterKind::IgnoreConstants);
        }
        if self.toggle_registers.is_selected() {
            filters.push(DiffFilterKind::IgnoreRegisterNames);
        }
        filters
    }

    /// Set the filter state from a set of active filters.
    pub fn set_active_filters(&mut self, filters: &[DiffFilterKind]) {
        self.toggle_byte_diffs
            .set_selected(filters.contains(&DiffFilterKind::IgnoreByteDiffs));
        self.toggle_constants
            .set_selected(filters.contains(&DiffFilterKind::IgnoreConstants));
        self.toggle_registers
            .set_selected(filters.contains(&DiffFilterKind::IgnoreRegisterNames));
    }
}

impl Default for ListingDiffActionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// A simple listener that records action toggles.
#[derive(Debug, Default)]
pub struct TrackingDiffActionListener {
    /// Recorded invocations.
    pub invocations: Mutex<Vec<DiffActionInvocation>>,
}

impl TrackingDiffActionListener {
    /// Create a new tracking listener.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the number of invocations.
    pub fn invocation_count(&self) -> usize {
        self.invocations.lock().unwrap().len()
    }
}

impl DiffActionListener for TrackingDiffActionListener {
    fn on_action_toggled(&self, invocation: &DiffActionInvocation) {
        self.invocations.lock().unwrap().push(invocation.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // --- DiffFilterKind tests ---

    #[test]
    fn test_diff_filter_kind_label() {
        assert_eq!(
            DiffFilterKind::IgnoreByteDiffs.label(),
            "Toggle Ignore Byte Diffs"
        );
        assert_eq!(
            DiffFilterKind::IgnoreConstants.label(),
            "Toggle Ignore Constants"
        );
        assert_eq!(
            DiffFilterKind::IgnoreRegisterNames.label(),
            "Toggle Ignore Register Names"
        );
    }

    #[test]
    fn test_diff_filter_kind_description() {
        assert!(!DiffFilterKind::IgnoreByteDiffs.description().is_empty());
        assert!(!DiffFilterKind::IgnoreConstants.description().is_empty());
        assert!(!DiffFilterKind::IgnoreRegisterNames
            .description()
            .is_empty());
    }

    #[test]
    fn test_diff_filter_kind_menu_label() {
        assert_eq!(
            DiffFilterKind::IgnoreByteDiffs.menu_label(),
            "Ignore Bytes As Differences"
        );
        assert_eq!(
            DiffFilterKind::IgnoreConstants.menu_label(),
            "Ignore Operand Constants As Differences"
        );
        assert_eq!(
            DiffFilterKind::IgnoreRegisterNames.menu_label(),
            "Ignore Operand Registers As Differences"
        );
    }

    #[test]
    fn test_diff_filter_kind_help_topic() {
        assert!(!DiffFilterKind::IgnoreByteDiffs.help_topic().is_empty());
    }

    #[test]
    fn test_diff_filter_kind_icon_names() {
        assert_ne!(
            DiffFilterKind::IgnoreByteDiffs.icon_name(),
            DiffFilterKind::IgnoreByteDiffs.negated_icon_name()
        );
    }

    #[test]
    fn test_diff_filter_kind_action_group() {
        for kind in &[
            DiffFilterKind::IgnoreByteDiffs,
            DiffFilterKind::IgnoreConstants,
            DiffFilterKind::IgnoreRegisterNames,
        ] {
            assert_eq!(kind.action_group(), "A4_Diff");
        }
    }

    // --- DiffToggleAction tests ---

    #[test]
    fn test_toggle_action_new() {
        let action = DiffToggleAction::new(DiffFilterKind::IgnoreByteDiffs);
        assert_eq!(action.kind, DiffFilterKind::IgnoreByteDiffs);
        assert!(action.is_enabled());
        assert!(!action.is_selected());
    }

    #[test]
    fn test_toggle_action_name() {
        let action = DiffToggleAction::new(DiffFilterKind::IgnoreConstants);
        assert_eq!(action.name(), "Toggle Ignore Constants");
    }

    #[test]
    fn test_toggle_action_description() {
        let action = DiffToggleAction::new(DiffFilterKind::IgnoreRegisterNames);
        assert!(!action.description().is_empty());
    }

    #[test]
    fn test_toggle_action_menu_label() {
        let action = DiffToggleAction::new(DiffFilterKind::IgnoreByteDiffs);
        assert_eq!(action.menu_label(), "Ignore Bytes As Differences");
    }

    #[test]
    fn test_toggle_action_enable_disable() {
        let mut action = DiffToggleAction::new(DiffFilterKind::IgnoreByteDiffs);
        assert!(action.is_enabled());

        action.set_enabled(false);
        assert!(!action.is_enabled());

        action.set_enabled(true);
        assert!(action.is_enabled());
    }

    #[test]
    fn test_toggle_action_select() {
        let mut action = DiffToggleAction::new(DiffFilterKind::IgnoreByteDiffs);
        assert!(!action.is_selected());

        action.set_selected(true);
        assert!(action.is_selected());

        action.set_selected(false);
        assert!(!action.is_selected());
    }

    #[test]
    fn test_toggle_action_toggle() {
        let mut action = DiffToggleAction::new(DiffFilterKind::IgnoreConstants);
        assert!(!action.is_selected());

        let new_state = action.toggle();
        assert!(new_state);
        assert!(action.is_selected());

        let new_state = action.toggle();
        assert!(!new_state);
        assert!(!action.is_selected());
    }

    #[test]
    fn test_toggle_action_icon_name() {
        let mut action = DiffToggleAction::new(DiffFilterKind::IgnoreByteDiffs);

        // When not selected, show the normal icon
        let normal_icon = action.current_icon_name();
        assert_eq!(normal_icon, DiffFilterKind::IgnoreByteDiffs.icon_name());

        // When selected, show the negated icon
        action.set_selected(true);
        let negated_icon = action.current_icon_name();
        assert_eq!(
            negated_icon,
            DiffFilterKind::IgnoreByteDiffs.negated_icon_name()
        );
    }

    // --- ListingDiffActionManager tests ---

    #[test]
    fn test_action_manager_new() {
        let manager = ListingDiffActionManager::new();
        assert!(manager.toggle_byte_diffs.is_enabled());
        assert!(!manager.toggle_byte_diffs.is_selected());
        assert!(manager.toggle_constants.is_enabled());
        assert!(!manager.toggle_constants.is_selected());
        assert!(manager.toggle_registers.is_enabled());
        assert!(!manager.toggle_registers.is_selected());
    }

    #[test]
    fn test_action_manager_default() {
        let manager = ListingDiffActionManager::default();
        assert_eq!(manager.actions().len(), 3);
    }

    #[test]
    fn test_action_manager_actions() {
        let manager = ListingDiffActionManager::new();
        let actions = manager.actions();
        assert_eq!(actions.len(), 3);
        assert_eq!(actions[0].kind, DiffFilterKind::IgnoreByteDiffs);
        assert_eq!(actions[1].kind, DiffFilterKind::IgnoreConstants);
        assert_eq!(actions[2].kind, DiffFilterKind::IgnoreRegisterNames);
    }

    #[test]
    fn test_action_manager_update_enablement() {
        let mut manager = ListingDiffActionManager::new();

        manager.update_action_enablement(false);
        assert!(!manager.toggle_byte_diffs.is_enabled());
        assert!(!manager.toggle_constants.is_enabled());
        assert!(!manager.toggle_registers.is_enabled());

        manager.update_action_enablement(true);
        assert!(manager.toggle_byte_diffs.is_enabled());
        assert!(manager.toggle_constants.is_enabled());
        assert!(manager.toggle_registers.is_enabled());
    }

    #[test]
    fn test_action_manager_toggle_byte_diffs() {
        let mut manager = ListingDiffActionManager::new();

        let result = manager.toggle_ignore_byte_diffs();
        assert!(result);
        assert!(manager.toggle_byte_diffs.is_selected());

        let result = manager.toggle_ignore_byte_diffs();
        assert!(!result);
        assert!(!manager.toggle_byte_diffs.is_selected());
    }

    #[test]
    fn test_action_manager_toggle_constants() {
        let mut manager = ListingDiffActionManager::new();

        let result = manager.toggle_ignore_constants();
        assert!(result);
        assert!(manager.toggle_constants.is_selected());

        let result = manager.toggle_ignore_constants();
        assert!(!result);
        assert!(!manager.toggle_constants.is_selected());
    }

    #[test]
    fn test_action_manager_toggle_registers() {
        let mut manager = ListingDiffActionManager::new();

        let result = manager.toggle_ignore_registers();
        assert!(result);
        assert!(manager.toggle_registers.is_selected());

        let result = manager.toggle_ignore_registers();
        assert!(!result);
        assert!(!manager.toggle_registers.is_selected());
    }

    #[test]
    fn test_action_manager_invocations() {
        let mut manager = ListingDiffActionManager::new();

        manager.toggle_ignore_byte_diffs();
        manager.toggle_ignore_constants();
        manager.toggle_ignore_registers();

        let invocations = manager.invocations();
        assert_eq!(invocations.len(), 3);
        assert_eq!(invocations[0].filter, DiffFilterKind::IgnoreByteDiffs);
        assert_eq!(invocations[1].filter, DiffFilterKind::IgnoreConstants);
        assert_eq!(invocations[2].filter, DiffFilterKind::IgnoreRegisterNames);
    }

    #[test]
    fn test_action_manager_clear_invocations() {
        let mut manager = ListingDiffActionManager::new();

        manager.toggle_ignore_byte_diffs();
        assert_eq!(manager.invocations().len(), 1);

        manager.clear_invocations();
        assert_eq!(manager.invocations().len(), 0);
    }

    #[test]
    fn test_action_manager_active_filters() {
        let mut manager = ListingDiffActionManager::new();

        // Initially no filters active
        assert!(manager.active_filters().is_empty());

        // Toggle some filters
        manager.toggle_ignore_byte_diffs();
        manager.toggle_ignore_registers();

        let filters = manager.active_filters();
        assert_eq!(filters.len(), 2);
        assert!(filters.contains(&DiffFilterKind::IgnoreByteDiffs));
        assert!(filters.contains(&DiffFilterKind::IgnoreRegisterNames));
        assert!(!filters.contains(&DiffFilterKind::IgnoreConstants));
    }

    #[test]
    fn test_action_manager_set_active_filters() {
        let mut manager = ListingDiffActionManager::new();

        manager.set_active_filters(&[
            DiffFilterKind::IgnoreConstants,
            DiffFilterKind::IgnoreRegisterNames,
        ]);

        assert!(!manager.toggle_byte_diffs.is_selected());
        assert!(manager.toggle_constants.is_selected());
        assert!(manager.toggle_registers.is_selected());

        let filters = manager.active_filters();
        assert_eq!(filters.len(), 2);
    }

    #[test]
    fn test_action_manager_listener() {
        let mut manager = ListingDiffActionManager::new();
        let listener = Arc::new(TrackingDiffActionListener::new());
        manager.add_listener(listener.clone());

        manager.toggle_ignore_byte_diffs();
        manager.toggle_ignore_constants();

        assert_eq!(listener.invocation_count(), 2);
    }

    #[test]
    fn test_action_manager_clear_listeners() {
        let mut manager = ListingDiffActionManager::new();
        let listener = Arc::new(TrackingDiffActionListener::new());
        manager.add_listener(listener.clone());

        manager.toggle_ignore_byte_diffs();
        assert_eq!(listener.invocation_count(), 1);

        manager.clear_listeners();
        manager.toggle_ignore_constants();
        // Listener should not receive the second event
        assert_eq!(listener.invocation_count(), 1);
    }

    // --- DiffActionInvocation tests ---

    #[test]
    fn test_diff_action_invocation_clone() {
        let inv = DiffActionInvocation {
            filter: DiffFilterKind::IgnoreByteDiffs,
            new_state: true,
        };
        let inv2 = inv.clone();
        assert_eq!(inv, inv2);
    }

    // --- TrackingDiffActionListener tests ---

    #[test]
    fn test_tracking_diff_action_listener() {
        let listener = TrackingDiffActionListener::new();
        assert_eq!(listener.invocation_count(), 0);

        listener.on_action_toggled(&DiffActionInvocation {
            filter: DiffFilterKind::IgnoreByteDiffs,
            new_state: true,
        });
        assert_eq!(listener.invocation_count(), 1);

        listener.on_action_toggled(&DiffActionInvocation {
            filter: DiffFilterKind::IgnoreConstants,
            new_state: false,
        });
        assert_eq!(listener.invocation_count(), 2);
    }
}
