//! Equate table provider -- dockable table view for managing equates.
//!
//! Ported from `EquateTableProvider.java` and `EquateTablePlugin.java` in
//! Ghidra's `ghidra.app.plugin.core.equate`.
//!
//! This module provides the domain model for the equate table UI:
//! - [`EquateTableProviderModel`] -- manages the equate table display,
//!   sorting, selection, and reference sub-table
//! - [`EquateTablePlugin`] -- top-level plugin that registers the equate
//!   table provider, actions, and responds to location changes

use super::manager::EquateTable;
use super::plugin::EquatePlugin;
use super::table::{EquateReferenceTableModel, EquateTableModel};
use ghidra_core::Address;

// ============================================================================
// EquateTableProviderModel -- manages the equate table provider display
// ============================================================================

/// Domain model for the equate table provider.
///
/// Corresponds to Ghidra's `EquateTableProvider`. Manages the equate
/// table and its sub-table of references for a selected equate.
#[derive(Debug)]
pub struct EquateTableProviderModel {
    /// The main equate table model.
    equate_model: EquateTableModel,
    /// The reference sub-table model (shows references for a selected equate).
    reference_model: EquateReferenceTableModel,
    /// The currently selected equate name, if any.
    selected_equate: Option<String>,
    /// Whether the provider is currently visible.
    visible: bool,
    /// The current program address for location-based updates.
    current_address: Option<Address>,
}

impl EquateTableProviderModel {
    /// Creates a new equate table provider model.
    pub fn new() -> Self {
        Self {
            equate_model: EquateTableModel::new(),
            reference_model: EquateReferenceTableModel::new(),
            selected_equate: None,
            visible: false,
            current_address: None,
        }
    }

    /// Returns whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Sets the provider visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Toggles the provider visibility.
    pub fn toggle_visible(&mut self) {
        self.visible = !self.visible;
    }

    /// Returns the currently selected equate name.
    pub fn selected_equate(&self) -> Option<&str> {
        self.selected_equate.as_deref()
    }

    /// Selects an equate by name and updates the reference sub-table.
    pub fn select_equate(&mut self, table: &EquateTable, name: Option<&str>) {
        self.selected_equate = name.map(|s| s.to_string());
        self.reference_model.set_equate(table, name);
    }

    /// Returns the number of equates in the table.
    pub fn equate_count(&self) -> usize {
        self.equate_model.row_count()
    }

    /// Returns the number of references for the currently selected equate.
    pub fn reference_count(&self) -> usize {
        self.reference_model.row_count()
    }

    /// Updates the equate model from the equate table.
    pub fn update(&mut self, table: &EquateTable) {
        self.equate_model.update(table);
        // Refresh reference table if an equate is selected.
        if let Some(name) = self.selected_equate.clone() {
            self.reference_model.set_equate(table, Some(&name));
        }
    }

    /// Returns the cell value at (row, col) in the equate model.
    pub fn equate_cell_value(&self, row: usize, col: usize) -> Option<String> {
        self.equate_model.cell_value(row, col)
    }

    /// Returns the cell value at (row, col) in the reference model.
    pub fn reference_cell_value(&self, row: usize, col: usize) -> Option<String> {
        self.reference_model.cell_value(row, col)
    }

    /// Gets the program location for a reference row.
    pub fn get_reference_location(&self, row: usize) -> Option<(Address, i32)> {
        self.reference_model.get_program_location(row)
    }

    /// Gets the program selection for a set of reference rows.
    ///
    /// Returns a list of addresses that were selected.
    pub fn get_reference_selection(&self, rows: &[usize]) -> Vec<Address> {
        self.reference_model.get_program_selection(rows)
    }

    /// Returns the address that is currently focused in the listing.
    pub fn current_address(&self) -> Option<Address> {
        self.current_address
    }

    /// Sets the current address (called when the listing location changes).
    pub fn set_current_address(&mut self, address: Option<Address>) {
        self.current_address = address;
    }

    /// Deletes the currently selected equates.
    ///
    /// Returns the names of the deleted equates.
    pub fn delete_selected(
        &mut self,
        names: &[&str],
        table: &mut EquateTable,
    ) -> Vec<String> {
        let removed = self.equate_model.delete_equates(names, table);
        if self.selected_equate.as_deref().map_or(false, |s| names.contains(&s)) {
            self.selected_equate = None;
            self.reference_model.set_equate(table, None);
        }
        removed
    }

    /// Returns a reference to the equate table model.
    pub fn equate_model(&self) -> &EquateTableModel {
        &self.equate_model
    }

    /// Returns a reference to the reference sub-table model.
    pub fn reference_model(&self) -> &EquateReferenceTableModel {
        &self.reference_model
    }
}

impl Default for EquateTableProviderModel {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// EquateTableWindowPluginState -- full state for the equate table plugin
// ============================================================================

/// Full state for the equate table plugin.
///
/// Combines the equate table plugin (EquatePlugin) with the table
/// provider model to provide a complete plugin state.
#[derive(Debug)]
pub struct EquateTableWindowPluginState {
    /// The underlying equate plugin.
    pub equate_plugin: EquatePlugin,
    /// The table provider model.
    pub provider: EquateTableProviderModel,
    /// Whether the plugin has been initialized.
    initialized: bool,
}

impl EquateTableWindowPluginState {
    /// Creates a new equate table plugin state.
    pub fn new() -> Self {
        Self {
            equate_plugin: EquatePlugin::new(),
            provider: EquateTableProviderModel::new(),
            initialized: false,
        }
    }

    /// Initializes the plugin (called once during startup).
    pub fn init(&mut self) {
        self.initialized = true;
    }

    /// Returns whether the plugin has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns a reference to the equate plugin.
    pub fn plugin(&self) -> &EquatePlugin {
        &self.equate_plugin
    }

    /// Returns a mutable reference to the equate plugin.
    pub fn plugin_mut(&mut self) -> &mut EquatePlugin {
        &mut self.equate_plugin
    }

    /// Returns a reference to the table provider.
    pub fn provider(&self) -> &EquateTableProviderModel {
        &self.provider
    }

    /// Returns a mutable reference to the table provider.
    pub fn provider_mut(&mut self) -> &mut EquateTableProviderModel {
        &mut self.provider
    }

    /// Responds to a location change in the listing.
    pub fn location_changed(&mut self, address: Option<Address>) {
        self.provider.set_current_address(address);
    }
}

impl Default for EquateTableWindowPluginState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_model_new() {
        let model = EquateTableProviderModel::new();
        assert!(!model.is_visible());
        assert!(model.selected_equate().is_none());
        assert_eq!(model.equate_count(), 0);
        assert_eq!(model.reference_count(), 0);
    }

    #[test]
    fn test_provider_model_toggle_visible() {
        let mut model = EquateTableProviderModel::new();
        assert!(!model.is_visible());
        model.toggle_visible();
        assert!(model.is_visible());
        model.toggle_visible();
        assert!(!model.is_visible());
    }

    #[test]
    fn test_provider_model_select_equate() {
        let mut table = EquateTable::new();
        table.create_equate("FLAG_A", 1).unwrap();
        table.add_reference("FLAG_A", Address::new(0x1000), 0);
        table.add_reference("FLAG_A", Address::new(0x2000), 1);

        let mut model = EquateTableProviderModel::new();
        model.update(&table);

        assert_eq!(model.equate_count(), 1);

        model.select_equate(&table, Some("FLAG_A"));
        assert_eq!(model.selected_equate(), Some("FLAG_A"));
        assert_eq!(model.reference_count(), 2);
    }

    #[test]
    fn test_provider_model_delete_selected() {
        let mut table = EquateTable::new();
        table.create_equate("A", 1).unwrap();
        table.create_equate("B", 2).unwrap();

        let mut model = EquateTableProviderModel::new();
        model.update(&table);
        assert_eq!(model.equate_count(), 2);

        let removed = model.delete_selected(&["A"], &mut table);
        assert_eq!(removed, vec!["A"]);
        assert_eq!(table.num_equates(), 1);
    }

    #[test]
    fn test_provider_model_cell_values() {
        let mut table = EquateTable::new();
        table.create_equate("MY_FLAG", 42).unwrap();
        table.add_reference("MY_FLAG", Address::new(0x1000), 0);

        let mut model = EquateTableProviderModel::new();
        model.update(&table);

        let name = model.equate_cell_value(0, 0);
        assert!(name.is_some());
    }

    #[test]
    fn test_provider_model_reference_location() {
        let mut table = EquateTable::new();
        table.create_equate("X", 10).unwrap();
        table.add_reference("X", Address::new(0x5000), 0);

        let mut model = EquateTableProviderModel::new();
        model.select_equate(&table, Some("X"));

        let loc = model.get_reference_location(0);
        assert!(loc.is_some());
        let (addr, op) = loc.unwrap();
        assert_eq!(addr, Address::new(0x5000));
        assert_eq!(op, 0);
    }

    #[test]
    fn test_plugin_state_lifecycle() {
        let mut state = EquateTableWindowPluginState::new();
        assert!(!state.is_initialized());

        state.init();
        assert!(state.is_initialized());

        // Location change
        state.location_changed(Some(Address::new(0x401000)));
        assert_eq!(
            state.provider().current_address(),
            Some(Address::new(0x401000))
        );
    }

    #[test]
    fn test_plugin_state_default() {
        let state = EquateTableWindowPluginState::default();
        assert!(!state.is_initialized());
        assert!(!state.provider().is_visible());
    }

    #[test]
    fn test_provider_model_set_current_address() {
        let mut model = EquateTableProviderModel::new();
        assert!(model.current_address().is_none());

        model.set_current_address(Some(Address::new(0x1000)));
        assert_eq!(model.current_address(), Some(Address::new(0x1000)));
    }

    #[test]
    fn test_provider_model_update_with_selected() {
        let mut table = EquateTable::new();
        table.create_equate("A", 1).unwrap();
        table.add_reference("A", Address::new(0x1000), 0);

        let mut model = EquateTableProviderModel::new();
        model.update(&table);
        model.select_equate(&table, Some("A"));

        // Add more data to table and update
        table.create_equate("B", 2).unwrap();
        table.add_reference("A", Address::new(0x2000), 1);
        model.update(&table);

        // Reference model should auto-refresh for selected equate
        assert_eq!(model.reference_count(), 2);
    }

    #[test]
    fn test_provider_model_deselect_equate() {
        let mut table = EquateTable::new();
        table.create_equate("A", 1).unwrap();
        table.add_reference("A", Address::new(0x1000), 0);

        let mut model = EquateTableProviderModel::new();
        model.select_equate(&table, Some("A"));
        assert!(model.selected_equate().is_some());

        model.select_equate(&table, None);
        assert!(model.selected_equate().is_none());
        assert_eq!(model.reference_count(), 0);
    }

    #[test]
    fn test_plugin_state_plugin_access() {
        let mut state = EquateTableWindowPluginState::new();
        let plugin = state.plugin();
        let all = plugin.get_all_equates(&EquateTable::new());
        assert!(all.is_empty());

        let plugin_mut = state.plugin_mut();
        assert_eq!(plugin_mut.get_all_equates(&EquateTable::new()).len(), 0);
    }
}
