//! Top-level selection plugin.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.select.SelectPlugin`.
//!
//! Coordinates all selection sub-plugins (bytes, flow, references, etc.)
//! and provides the unified interface for programmatic selection management.

use crate::select::{
    AddressSet, ByteSelectionMethod, FlowSelectionType, SelectionModel, SelectionType,
};

// ============================================================================
// SelectPlugin -- top-level selection plugin
// ============================================================================

/// Top-level plugin that orchestrates all selection operations.
///
/// Ported from `ghidra.app.plugin.core.select.SelectPlugin`.
///
/// This plugin acts as the central coordinator for address selection
/// within a program. It delegates to specialised sub-engines for
/// flow-based, reference-based, byte-based, and other selection modes.
#[derive(Debug)]
pub struct SelectPlugin {
    /// Plugin name.
    pub name: String,
    /// The active selection model.
    model: SelectionModel,
    /// Whether the plugin is disposed.
    disposed: bool,
    /// Plugin priority (lower values = higher priority).
    priority: i32,
}

impl SelectPlugin {
    /// Create a new select plugin.
    pub fn new() -> Self {
        Self {
            name: "SelectPlugin".to_string(),
            model: SelectionModel::new(),
            disposed: false,
            priority: 0,
        }
    }

    /// Create a new select plugin with a custom name.
    pub fn with_name(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Self::new()
        }
    }

    /// Get the current selection as an `AddressSet`.
    pub fn get_selection(&self) -> &AddressSet {
        self.model.get_selection()
    }

    /// Set the current selection.
    pub fn set_selection(&mut self, selection: AddressSet) {
        self.model.set_selection(selection);
    }

    /// Clear the current selection.
    pub fn clear_selection(&mut self) {
        self.model.clear();
    }

    /// Whether there is an active (non-empty) selection.
    pub fn has_selection(&self) -> bool {
        self.model.has_selection()
    }

    /// Undo the last selection change.
    pub fn undo(&mut self) -> bool {
        self.model.undo()
    }

    /// Whether undo is available.
    pub fn can_undo(&self) -> bool {
        self.model.can_undo()
    }

    /// Select a single address.
    pub fn select_address(&mut self, address: u64) {
        let mut set = AddressSet::new();
        set.add(ghidra_core::Address::new(address));
        self.model.set_selection(set);
    }

    /// Select a contiguous range of addresses.
    pub fn select_range(&mut self, start: u64, end: u64) {
        let mut set = AddressSet::new();
        set.add_range(
            ghidra_core::Address::new(start),
            ghidra_core::Address::new(end),
        );
        self.model.set_selection(set);
    }

    /// Invert the current selection within the given bounds.
    pub fn invert_selection(&mut self, min: u64, max: u64) {
        let mut set = self.model.get_selection().clone();
        set.invert(
            ghidra_core::Address::new(min),
            ghidra_core::Address::new(max),
        );
        self.model.set_selection(set);
    }

    /// Get the type of the current selection context.
    pub fn selection_type(&self) -> SelectionType {
        if self.model.has_selection() {
            SelectionType::Range
        } else {
            SelectionType::Address
        }
    }

    /// Set the plugin priority.
    pub fn set_priority(&mut self, priority: i32) {
        self.priority = priority;
    }

    /// Get the plugin priority.
    pub fn get_priority(&self) -> i32 {
        self.priority
    }

    /// Whether the plugin is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Dispose the plugin, releasing resources.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.model.clear();
    }
}

impl Default for SelectPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SelectAction -- an action that triggers a selection
// ============================================================================

/// An action that can be performed on the current selection.
///
/// Ported from the various `Select*Action` classes in the selection package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectAction {
    /// Select the current address.
    SelectAddress,
    /// Select the current function.
    SelectFunction,
    /// Select the current instruction.
    SelectInstruction,
    /// Select an address range.
    SelectRange,
    /// Select all addresses.
    SelectAll,
    /// Select by code flow.
    SelectByFlow(FlowSelectionType),
    /// Select by references.
    SelectByReferences,
    /// Invert the selection.
    InvertSelection,
    /// Select by equate.
    SelectByEquate,
    /// Select by bytes.
    SelectByBytes,
    /// Restore a previously saved selection.
    RestoreSelection,
    /// Clear the selection.
    ClearSelection,
}

impl SelectAction {
    /// Human-readable name for this action.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::SelectAddress => "Select Address",
            Self::SelectFunction => "Select Function",
            Self::SelectInstruction => "Select Instruction",
            Self::SelectRange => "Select Range",
            Self::SelectAll => "Select All",
            Self::SelectByFlow(fst) => match fst {
                FlowSelectionType::AllFlowsFrom => "Select All Flows From",
                FlowSelectionType::LimitedFlowsFrom => "Select Limited Flows From",
                FlowSelectionType::Subroutines => "Select Subroutines",
                FlowSelectionType::AllFlowsTo => "Select All Flows To",
                FlowSelectionType::LimitedFlowsTo => "Select Limited Flows To",
            },
            Self::SelectByReferences => "Select References",
            Self::InvertSelection => "Invert Selection",
            Self::SelectByEquate => "Select by Equate",
            Self::SelectByBytes => "Select Bytes",
            Self::RestoreSelection => "Restore Selection",
            Self::ClearSelection => "Clear Selection",
        }
    }

    /// Whether this action is available when there is no active selection.
    pub fn available_without_selection(&self) -> bool {
        matches!(
            self,
            Self::SelectAddress
                | Self::SelectFunction
                | Self::SelectInstruction
                | Self::SelectRange
                | Self::SelectAll
                | Self::SelectByBytes
                | Self::RestoreSelection
        )
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_plugin_new() {
        let plugin = SelectPlugin::new();
        assert_eq!(plugin.name, "SelectPlugin");
        assert!(!plugin.has_selection());
        assert!(!plugin.is_disposed());
        assert_eq!(plugin.get_priority(), 0);
    }

    #[test]
    fn test_select_plugin_with_name() {
        let plugin = SelectPlugin::with_name("CustomSelect");
        assert_eq!(plugin.name, "CustomSelect");
    }

    #[test]
    fn test_select_plugin_select_address() {
        let mut plugin = SelectPlugin::new();
        plugin.select_address(0x1000);
        assert!(plugin.has_selection());
        assert_eq!(plugin.get_selection().num_addresses(), 1);
        assert!(plugin
            .get_selection()
            .contains(ghidra_core::Address::new(0x1000)));
    }

    #[test]
    fn test_select_plugin_select_range() {
        let mut plugin = SelectPlugin::new();
        plugin.select_range(0x1000, 0x100F);
        assert!(plugin.has_selection());
        assert_eq!(plugin.get_selection().num_addresses(), 16);
    }

    #[test]
    fn test_select_plugin_clear() {
        let mut plugin = SelectPlugin::new();
        plugin.select_range(0x1000, 0x100F);
        assert!(plugin.has_selection());
        plugin.clear_selection();
        assert!(!plugin.has_selection());
    }

    #[test]
    fn test_select_plugin_undo() {
        let mut plugin = SelectPlugin::new();
        plugin.select_address(0x1000);
        plugin.select_address(0x2000);
        assert!(plugin.has_selection());
        assert!(plugin.get_selection().contains(ghidra_core::Address::new(0x2000)));

        assert!(plugin.undo());
        assert!(plugin.get_selection().contains(ghidra_core::Address::new(0x1000)));
        assert!(!plugin.get_selection().contains(ghidra_core::Address::new(0x2000)));
    }

    #[test]
    fn test_select_plugin_invert() {
        let mut plugin = SelectPlugin::new();
        plugin.select_address(0x1005);
        plugin.invert_selection(0x1000, 0x1009);
        assert!(!plugin.get_selection().contains(ghidra_core::Address::new(0x1005)));
        assert!(plugin.get_selection().contains(ghidra_core::Address::new(0x1000)));
        assert!(plugin.get_selection().contains(ghidra_core::Address::new(0x1009)));
    }

    #[test]
    fn test_select_plugin_selection_type() {
        let mut plugin = SelectPlugin::new();
        assert_eq!(plugin.selection_type(), SelectionType::Address);
        plugin.select_range(0x1000, 0x100F);
        assert_eq!(plugin.selection_type(), SelectionType::Range);
    }

    #[test]
    fn test_select_plugin_priority() {
        let mut plugin = SelectPlugin::new();
        plugin.set_priority(10);
        assert_eq!(plugin.get_priority(), 10);
    }

    #[test]
    fn test_select_plugin_dispose() {
        let mut plugin = SelectPlugin::new();
        plugin.select_address(0x1000);
        assert!(plugin.has_selection());
        plugin.dispose();
        assert!(plugin.is_disposed());
        assert!(!plugin.has_selection());
    }

    #[test]
    fn test_select_action_display_name() {
        assert_eq!(SelectAction::SelectAddress.display_name(), "Select Address");
        assert_eq!(
            SelectAction::SelectByFlow(FlowSelectionType::AllFlowsFrom).display_name(),
            "Select All Flows From"
        );
        assert_eq!(
            SelectAction::ClearSelection.display_name(),
            "Clear Selection"
        );
    }

    #[test]
    fn test_select_action_available_without_selection() {
        assert!(SelectAction::SelectAddress.available_without_selection());
        assert!(SelectAction::SelectAll.available_without_selection());
        assert!(!SelectAction::InvertSelection.available_without_selection());
        assert!(!SelectAction::ClearSelection.available_without_selection());
    }
}
