//! Selection Plugin -- the Features/Selection plugin for Ghidra.
//!
//! Ported from Ghidra's `ghidra.plugin.core.selection.SelectionPlugin`.
//!
//! This plugin registers the `SelectionService` and provides the actions
//! that let users perform selection operations in the code browser:
//!
//! - Select by address range
//! - Select all
//! - Select function
//! - Select by equate
//! - Invert selection
//! - Clear selection
//!
//! The plugin listens for `ProgramSelectionPluginEvent` and forwards
//! selection changes to any registered [`SelectionServiceListener`]s.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, RwLock};

use super::selection_service::{
    ProgramSelection, SelectionService, SelectionServiceListener,
};

// ---------------------------------------------------------------------------
// SelectionPlugin
// ---------------------------------------------------------------------------

/// The Features/Selection plugin.
///
/// Ported from `ghidra.plugin.core.selection.SelectionPlugin`.
///
/// When installed in a tool this plugin:
///
/// 1. Registers a [`SelectionService`] implementation so other plugins can
///    query or modify the current selection.
/// 2. Listens for program-selection events and notifies all
///    [`SelectionServiceListener`]s when the selection changes.
/// 3. Provides the actions listed above to the tool's menu.
#[derive(Debug)]
pub struct SelectionPlugin {
    /// Plugin name.
    name: String,
    /// Whether this plugin has been disposed.
    disposed: bool,
    /// The current program selection.
    selection: ProgramSelection,
    /// The most recent previous selection (for undo).
    previous_selection: Option<ProgramSelection>,
    /// Registered listeners for selection change notifications.
    listeners: Vec<Arc<dyn SelectionServiceListener>>,
}

impl SelectionPlugin {
    /// Plugin name constant used for registration.
    pub const PLUGIN_NAME: &'static str = "SelectionPlugin";

    /// Create a new selection plugin.
    pub fn new() -> Self {
        Self {
            name: Self::PLUGIN_NAME.to_string(),
            disposed: false,
            selection: ProgramSelection::default(),
            previous_selection: None,
            listeners: Vec::new(),
        }
    }

    /// Create a selection plugin with a custom name.
    pub fn with_name(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Self::new()
        }
    }

    /// Get the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    // -- Selection operations ------------------------------------------------

    /// Get the current selection.
    pub fn get_selection(&self) -> &ProgramSelection {
        &self.selection
    }

    /// Set the current selection, notifying listeners.
    pub fn set_selection(&mut self, selection: ProgramSelection) {
        self.previous_selection = Some(std::mem::replace(
            &mut self.selection,
            selection.clone(),
        ));
        self.notify_selection_changed(&selection);
    }

    /// Clear the current selection, notifying listeners.
    pub fn clear_selection(&mut self) {
        self.set_selection(ProgramSelection::default());
    }

    /// Whether there is a non-empty selection active.
    pub fn has_selection(&self) -> bool {
        !self.selection.is_empty()
    }

    /// Select a single address.
    pub fn select_address(&mut self, address: u64) {
        let mut sel = ProgramSelection::default();
        sel.add_address(address);
        self.set_selection(sel);
    }

    /// Select a contiguous range of addresses.
    pub fn select_range(&mut self, start: u64, end: u64) {
        let mut sel = ProgramSelection::default();
        sel.add_range(start, end);
        self.set_selection(sel);
    }

    /// Select all addresses in the given set.
    pub fn select_addresses(&mut self, addresses: BTreeSet<u64>) {
        let mut sel = ProgramSelection::default();
        for addr in addresses {
            sel.add_address(addr);
        }
        self.set_selection(sel);
    }

    /// Invert the current selection within the given bounds.
    pub fn invert_selection(&mut self, min: u64, max: u64) {
        let mut new_sel = ProgramSelection::default();
        for addr in min..=max {
            if !self.selection.contains(addr) {
                new_sel.add_address(addr);
            }
        }
        self.set_selection(new_sel);
    }

    /// Union the current selection with the given set.
    pub fn union_selection(&mut self, other: &ProgramSelection) {
        let mut result = self.selection.clone();
        result.union_with(other);
        self.set_selection(result);
    }

    /// Intersect the current selection with the given set.
    pub fn intersect_selection(&mut self, other: &ProgramSelection) {
        let mut result = self.selection.clone();
        result.intersect_with(other);
        self.set_selection(result);
    }

    /// Subtract the given set from the current selection.
    pub fn subtract_selection(&mut self, other: &ProgramSelection) {
        let mut result = self.selection.clone();
        result.subtract_with(other);
        self.set_selection(result);
    }

    /// Undo the last selection change.
    pub fn undo(&mut self) -> bool {
        if let Some(prev) = self.previous_selection.take() {
            let current = std::mem::replace(&mut self.selection, prev);
            self.previous_selection = Some(current);
            self.notify_selection_changed(&self.selection);
            true
        } else {
            false
        }
    }

    /// Whether undo is available.
    pub fn can_undo(&self) -> bool {
        self.previous_selection.is_some()
    }

    // -- Listener management -------------------------------------------------

    /// Add a listener that will be notified when the selection changes.
    pub fn add_listener(&mut self, listener: Arc<dyn SelectionServiceListener>) {
        self.listeners.push(listener);
    }

    /// Remove all registered listeners.
    pub fn clear_listeners(&mut self) {
        self.listeners.clear();
    }

    /// Get the number of registered listeners.
    pub fn listener_count(&self) -> usize {
        self.listeners.len()
    }

    // -- Disposal ------------------------------------------------------------

    /// Dispose the plugin, clearing state and listeners.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.selection = ProgramSelection::default();
        self.previous_selection = None;
        self.listeners.clear();
    }

    // -- Internal ------------------------------------------------------------

    /// Notify all registered listeners that the selection has changed.
    fn notify_selection_changed(&self, new_selection: &ProgramSelection) {
        for listener in &self.listeners {
            listener.selection_changed(new_selection);
        }
    }
}

impl Default for SelectionPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SelectionPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SelectionPlugin(name={}, disposed={}, selection_size={})",
            self.name,
            self.disposed,
            self.selection.num_addresses()
        )
    }
}

// ---------------------------------------------------------------------------
// SelectionAction -- enum of available selection actions
// ---------------------------------------------------------------------------

/// Actions that the selection plugin can perform.
///
/// Ported from the various `Select*Action` classes in
/// `ghidra.plugin.core.selection`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SelectionAction {
    /// Select a single address.
    SelectAddress,
    /// Select a contiguous address range.
    SelectRange,
    /// Select all addresses in the program.
    SelectAll,
    /// Select the current function.
    SelectFunction,
    /// Select by equate (named constant).
    SelectByEquate,
    /// Select by code flow from the current address.
    SelectByFlow,
    /// Select by references to the current address.
    SelectByReferences,
    /// Invert the current selection.
    InvertSelection,
    /// Clear the current selection.
    ClearSelection,
    /// Restore a previously saved selection.
    RestoreSelection,
}

impl SelectionAction {
    /// Human-readable display name for this action.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::SelectAddress => "Select Address",
            Self::SelectRange => "Select Range",
            Self::SelectAll => "Select All",
            Self::SelectFunction => "Select Function",
            Self::SelectByEquate => "Select by Equate",
            Self::SelectByFlow => "Select by Flow",
            Self::SelectByReferences => "Select by References",
            Self::InvertSelection => "Invert Selection",
            Self::ClearSelection => "Clear Selection",
            Self::RestoreSelection => "Restore Selection",
        }
    }

    /// Whether this action can be performed when no selection exists.
    pub fn available_without_selection(&self) -> bool {
        matches!(
            self,
            Self::SelectAddress
                | Self::SelectRange
                | Self::SelectAll
                | Self::SelectFunction
                | Self::SelectByEquate
                | Self::SelectByFlow
                | Self::SelectByReferences
                | Self::RestoreSelection
        )
    }

    /// Whether this action requires an existing selection.
    pub fn requires_selection(&self) -> bool {
        !self.available_without_selection()
    }

    /// All available actions in display order.
    pub fn all_actions() -> &'static [SelectionAction] {
        &[
            Self::SelectAddress,
            Self::SelectRange,
            Self::SelectAll,
            Self::SelectFunction,
            Self::SelectByEquate,
            Self::SelectByFlow,
            Self::SelectByReferences,
            Self::InvertSelection,
            Self::ClearSelection,
            Self::RestoreSelection,
        ]
    }
}

impl fmt::Display for SelectionAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = SelectionPlugin::new();
        assert_eq!(plugin.name(), "SelectionPlugin");
        assert!(!plugin.is_disposed());
        assert!(!plugin.has_selection());
    }

    #[test]
    fn test_plugin_with_name() {
        let plugin = SelectionPlugin::with_name("CustomSelection");
        assert_eq!(plugin.name(), "CustomSelection");
    }

    #[test]
    fn test_plugin_select_address() {
        let mut plugin = SelectionPlugin::new();
        plugin.select_address(0x1000);
        assert!(plugin.has_selection());
        assert_eq!(plugin.get_selection().num_addresses(), 1);
        assert!(plugin.get_selection().contains(0x1000));
    }

    #[test]
    fn test_plugin_select_range() {
        let mut plugin = SelectionPlugin::new();
        plugin.select_range(0x1000, 0x100F);
        assert!(plugin.has_selection());
        assert_eq!(plugin.get_selection().num_addresses(), 16);
    }

    #[test]
    fn test_plugin_select_addresses() {
        let mut plugin = SelectionPlugin::new();
        let mut addrs = BTreeSet::new();
        addrs.insert(0x1000);
        addrs.insert(0x2000);
        addrs.insert(0x3000);
        plugin.select_addresses(addrs);
        assert_eq!(plugin.get_selection().num_addresses(), 3);
    }

    #[test]
    fn test_plugin_clear_selection() {
        let mut plugin = SelectionPlugin::new();
        plugin.select_range(0x1000, 0x100F);
        assert!(plugin.has_selection());
        plugin.clear_selection();
        assert!(!plugin.has_selection());
    }

    #[test]
    fn test_plugin_invert() {
        let mut plugin = SelectionPlugin::new();
        plugin.select_address(0x1005);
        plugin.invert_selection(0x1000, 0x1009);
        assert!(!plugin.get_selection().contains(0x1005));
        assert!(plugin.get_selection().contains(0x1000));
        assert!(plugin.get_selection().contains(0x1009));
        assert_eq!(plugin.get_selection().num_addresses(), 9);
    }

    #[test]
    fn test_plugin_undo() {
        let mut plugin = SelectionPlugin::new();
        plugin.select_address(0x1000);
        plugin.select_address(0x2000);
        assert!(plugin.has_selection());
        assert!(plugin.get_selection().contains(0x2000));

        assert!(plugin.undo());
        assert!(plugin.get_selection().contains(0x1000));
        assert!(!plugin.get_selection().contains(0x2000));
    }

    #[test]
    fn test_plugin_undo_empty() {
        let mut plugin = SelectionPlugin::new();
        assert!(!plugin.undo());
    }

    #[test]
    fn test_plugin_undo_toggle() {
        let mut plugin = SelectionPlugin::new();
        plugin.select_address(0x1000);
        plugin.select_address(0x2000);
        // Undo back to 0x1000
        assert!(plugin.undo());
        assert!(plugin.get_selection().contains(0x1000));
        // Redo back to 0x2000
        assert!(plugin.undo());
        assert!(plugin.get_selection().contains(0x2000));
    }

    #[test]
    fn test_plugin_union_selection() {
        let mut plugin = SelectionPlugin::new();
        plugin.select_address(0x1000);

        let mut other = ProgramSelection::default();
        other.add_address(0x2000);
        plugin.union_selection(&other);

        assert!(plugin.get_selection().contains(0x1000));
        assert!(plugin.get_selection().contains(0x2000));
        assert_eq!(plugin.get_selection().num_addresses(), 2);
    }

    #[test]
    fn test_plugin_intersect_selection() {
        let mut plugin = SelectionPlugin::new();
        plugin.select_range(0x1000, 0x100F);

        let mut other = ProgramSelection::default();
        other.add_range(0x1005, 0x1014);
        plugin.intersect_selection(&other);

        assert_eq!(plugin.get_selection().num_addresses(), 11); // 0x1005..=0x100F
        assert!(plugin.get_selection().contains(0x1005));
        assert!(plugin.get_selection().contains(0x100F));
        assert!(!plugin.get_selection().contains(0x1010));
    }

    #[test]
    fn test_plugin_subtract_selection() {
        let mut plugin = SelectionPlugin::new();
        plugin.select_range(0x1000, 0x100F);

        let mut other = ProgramSelection::default();
        other.add_range(0x1005, 0x100A);
        plugin.subtract_selection(&other);

        assert_eq!(plugin.get_selection().num_addresses(), 10); // 0x1000..0x1005 + 0x100B..0x100F
        assert!(plugin.get_selection().contains(0x1004));
        assert!(!plugin.get_selection().contains(0x1005));
        assert!(!plugin.get_selection().contains(0x100A));
        assert!(plugin.get_selection().contains(0x100B));
    }

    #[test]
    fn test_plugin_listeners() {
        let mut plugin = SelectionPlugin::new();
        assert_eq!(plugin.listener_count(), 0);

        let listener = Arc::new(TestListener::new());
        plugin.add_listener(listener.clone());
        assert_eq!(plugin.listener_count(), 1);

        plugin.select_address(0x1000);
        assert_eq!(listener.call_count(), 1);

        plugin.clear_listeners();
        assert_eq!(plugin.listener_count(), 0);
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = SelectionPlugin::new();
        plugin.select_address(0x1000);
        assert!(plugin.has_selection());
        plugin.dispose();
        assert!(plugin.is_disposed());
        assert!(!plugin.has_selection());
        assert_eq!(plugin.listener_count(), 0);
    }

    #[test]
    fn test_plugin_display() {
        let plugin = SelectionPlugin::new();
        let display = format!("{}", plugin);
        assert!(display.contains("SelectionPlugin"));
        assert!(display.contains("selection_size=0"));
    }

    // -- SelectionAction tests -----------------------------------------------

    #[test]
    fn test_action_display_name() {
        assert_eq!(SelectionAction::SelectAddress.display_name(), "Select Address");
        assert_eq!(
            SelectionAction::InvertSelection.display_name(),
            "Invert Selection"
        );
    }

    #[test]
    fn test_action_available_without_selection() {
        assert!(SelectionAction::SelectAddress.available_without_selection());
        assert!(SelectionAction::SelectAll.available_without_selection());
        assert!(!SelectionAction::InvertSelection.available_without_selection());
        assert!(!SelectionAction::ClearSelection.available_without_selection());
    }

    #[test]
    fn test_action_requires_selection() {
        assert!(SelectionAction::ClearSelection.requires_selection());
        assert!(SelectionAction::InvertSelection.requires_selection());
        assert!(!SelectionAction::SelectAddress.requires_selection());
    }

    #[test]
    fn test_action_all_actions() {
        let all = SelectionAction::all_actions();
        assert_eq!(all.len(), 10);
        assert!(all.contains(&SelectionAction::SelectAddress));
        assert!(all.contains(&SelectionAction::ClearSelection));
    }

    #[test]
    fn test_action_display_trait() {
        assert_eq!(format!("{}", SelectionAction::SelectRange), "Select Range");
    }

    // -- Test helper ----------------------------------------------------------

    /// A test listener that counts how many times `selection_changed` was called.
    #[derive(Debug)]
    struct TestListener {
        count: std::sync::atomic::AtomicUsize,
    }

    impl TestListener {
        fn new() -> Self {
            Self {
                count: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn call_count(&self) -> usize {
            self.count.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl SelectionServiceListener for TestListener {
        fn selection_changed(&self, _selection: &ProgramSelection) {
            self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}
