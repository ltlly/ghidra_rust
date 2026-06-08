//! ExternalDebugInfoProviderTableModel -- table model for provider configuration.
//!
//! Ported from `ghidra.app.util.bin.format.dwarf.external.gui.ExternalDebugInfoProviderTableModel`.
//!
//! This module provides a table model that manages a list of
//! [`ExternalDebugInfoProviderTableRow`] instances.  It supports adding,
//! removing, and reordering providers, as well as tracking whether the
//! configuration has changed.

use std::sync::Arc;

use super::super::debug_info_provider::DebugInfoProvider;
use super::super::debug_info_provider_status::DebugInfoProviderStatus;
use super::external_debug_info_provider_table_row::ExternalDebugInfoProviderTableRow;

/// Column indices for the table model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnIndex {
    /// The enabled/disabled checkbox column.
    Enabled = 0,
    /// The status icon column.
    Status = 1,
    /// The location/description column.
    Location = 2,
}

impl ColumnIndex {
    /// Returns the column name for display.
    pub fn display_name(&self) -> &str {
        match self {
            ColumnIndex::Enabled => "Enabled",
            ColumnIndex::Status => "Status",
            ColumnIndex::Location => "Location",
        }
    }

    /// Returns the total number of columns.
    pub const fn count() -> usize {
        3
    }

    /// Returns all column indices.
    pub fn all() -> &'static [ColumnIndex] {
        &[ColumnIndex::Enabled, ColumnIndex::Status, ColumnIndex::Location]
    }
}

/// Table model for the external debug info provider configuration.
///
/// Manages a list of [`ExternalDebugInfoProviderTableRow`] instances and
/// tracks changes to the configuration.
#[derive(Debug)]
pub struct ExternalDebugInfoProviderTableModel {
    /// The rows in the table.
    rows: Vec<ExternalDebugInfoProviderTableRow>,
    /// Whether the data has changed since the last save.
    data_changed: bool,
}

impl ExternalDebugInfoProviderTableModel {
    /// Creates a new empty table model.
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            data_changed: false,
        }
    }

    /// Returns `true` if the table has no rows.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Returns the number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Returns the number of columns.
    pub fn column_count(&self) -> usize {
        ColumnIndex::count()
    }

    /// Returns the column name for the given index.
    pub fn column_name(&self, col: usize) -> &str {
        match col {
            0 => ColumnIndex::Enabled.display_name(),
            1 => ColumnIndex::Status.display_name(),
            2 => ColumnIndex::Location.display_name(),
            _ => "Unknown",
        }
    }

    /// Returns a reference to the rows.
    pub fn rows(&self) -> &[ExternalDebugInfoProviderTableRow] {
        &self.rows
    }

    /// Returns a mutable reference to the rows.
    pub fn rows_mut(&mut self) -> &mut Vec<ExternalDebugInfoProviderTableRow> {
        &mut self.rows
    }

    /// Returns a reference to the row at the given index.
    pub fn row(&self, index: usize) -> Option<&ExternalDebugInfoProviderTableRow> {
        self.rows.get(index)
    }

    /// Returns a mutable reference to the row at the given index.
    pub fn row_mut(&mut self, index: usize) -> Option<&mut ExternalDebugInfoProviderTableRow> {
        self.rows.get_mut(index)
    }

    /// Replaces all items in the table with the given providers.
    pub fn set_items(&mut self, items: Vec<Arc<dyn DebugInfoProvider>>) {
        self.rows.clear();
        for item in items {
            self.rows.push(ExternalDebugInfoProviderTableRow::new(item));
        }
        self.data_changed = false;
    }

    /// Returns the list of providers from all rows.
    pub fn get_items(&self) -> Vec<Arc<dyn DebugInfoProvider>> {
        self.rows.iter().map(|row| Arc::clone(row.item())).collect()
    }

    /// Adds a single provider to the table.
    pub fn add_item(&mut self, item: Arc<dyn DebugInfoProvider>) {
        self.rows.push(ExternalDebugInfoProviderTableRow::new(item));
        self.data_changed = true;
    }

    /// Adds multiple providers to the table.
    pub fn add_items(&mut self, items: Vec<Arc<dyn DebugInfoProvider>>) {
        for item in items {
            self.rows.push(ExternalDebugInfoProviderTableRow::new(item));
        }
        self.data_changed = true;
    }

    /// Deletes rows at the given indices.
    ///
    /// Indices should be sorted in descending order to avoid index shifting.
    pub fn delete_rows(&mut self, indices: &[usize]) {
        // Sort indices in descending order to avoid shifting issues.
        let mut sorted_indices = indices.to_vec();
        sorted_indices.sort_unstable_by(|a, b| b.cmp(a));

        for &idx in &sorted_indices {
            if idx < self.rows.len() {
                self.rows.remove(idx);
            }
        }
        self.data_changed = true;
    }

    /// Moves a row by the given delta.
    ///
    /// A positive delta moves the row down; a negative delta moves it up.
    pub fn move_row(&mut self, row_index: usize, delta: isize) {
        let dest_index = row_index as isize + delta;
        if row_index >= self.rows.len() || dest_index < 0 || dest_index as usize >= self.rows.len()
        {
            return;
        }

        let dest_index = dest_index as usize;
        self.rows.swap(row_index, dest_index);
        self.data_changed = true;
    }

    /// Returns `true` if the data has changed since the last save.
    pub fn is_data_changed(&self) -> bool {
        self.data_changed
    }

    /// Sets the data changed flag.
    pub fn set_data_changed(&mut self, changed: bool) {
        self.data_changed = changed;
    }

    /// Sets the enabled state of a row.
    pub fn set_row_enabled(&mut self, row_index: usize, enabled: bool) {
        if let Some(row) = self.rows.get_mut(row_index) {
            row.set_enabled(enabled);
            self.data_changed = true;
        }
    }

    /// Sets the status of a row.
    pub fn set_row_status(&mut self, row_index: usize, status: DebugInfoProviderStatus) {
        if let Some(row) = self.rows.get_mut(row_index) {
            row.set_status(status);
        }
    }

    /// Returns the cell value as a string for the given row and column.
    pub fn get_cell_value(&self, row: usize, col: usize) -> Option<String> {
        let row_data = self.rows.get(row)?;
        match col {
            0 => Some(if row_data.is_enabled() {
                "true".to_string()
            } else {
                "false".to_string()
            }),
            1 => Some(format!("{:?}", row_data.status())),
            2 => Some(row_data.item().descriptive_name().to_string()),
            _ => None,
        }
    }

    /// Returns `true` if the cell at the given position is editable.
    ///
    /// Only the "Enabled" column is editable.
    pub fn is_cell_editable(&self, _row: usize, col: usize) -> bool {
        col == ColumnIndex::Enabled as usize
    }

    /// Clears all rows.
    pub fn clear(&mut self) {
        self.rows.clear();
        self.data_changed = true;
    }
}

impl Default for ExternalDebugInfoProviderTableModel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::debug_info_provider::DebugInfoProvider;
    use super::super::super::debug_info_provider_status::DebugInfoProviderStatus;

    #[derive(Debug)]
    struct MockProvider {
        name: String,
        descriptive_name: String,
    }

    impl MockProvider {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                descriptive_name: format!("Test: {}", name),
            }
        }
    }

    impl DebugInfoProvider for MockProvider {
        fn name(&self) -> &str {
            &self.name
        }

        fn descriptive_name(&self) -> &str {
            &self.descriptive_name
        }

        fn status(&self) -> DebugInfoProviderStatus {
            DebugInfoProviderStatus::Unknown
        }
    }

    fn make_provider(name: &str) -> Arc<dyn DebugInfoProvider> {
        Arc::new(MockProvider::new(name))
    }

    #[test]
    fn test_new_model() {
        let model = ExternalDebugInfoProviderTableModel::new();
        assert!(model.is_empty());
        assert_eq!(model.row_count(), 0);
        assert_eq!(model.column_count(), 3);
        assert!(!model.is_data_changed());
    }

    #[test]
    fn test_set_items() {
        let mut model = ExternalDebugInfoProviderTableModel::new();
        let items = vec![make_provider("a"), make_provider("b")];
        model.set_items(items);
        assert_eq!(model.row_count(), 2);
        assert!(!model.is_data_changed());
    }

    #[test]
    fn test_add_item() {
        let mut model = ExternalDebugInfoProviderTableModel::new();
        model.add_item(make_provider("test"));
        assert_eq!(model.row_count(), 1);
        assert!(model.is_data_changed());
    }

    #[test]
    fn test_add_items() {
        let mut model = ExternalDebugInfoProviderTableModel::new();
        model.add_items(vec![make_provider("a"), make_provider("b")]);
        assert_eq!(model.row_count(), 2);
        assert!(model.is_data_changed());
    }

    #[test]
    fn test_delete_rows() {
        let mut model = ExternalDebugInfoProviderTableModel::new();
        model.set_items(vec![
            make_provider("a"),
            make_provider("b"),
            make_provider("c"),
        ]);

        // Delete middle row
        model.delete_rows(&[1]);
        assert_eq!(model.row_count(), 2);
        assert_eq!(model.row(0).unwrap().item().name(), "a");
        assert_eq!(model.row(1).unwrap().item().name(), "c");
        assert!(model.is_data_changed());
    }

    #[test]
    fn test_delete_multiple_rows() {
        let mut model = ExternalDebugInfoProviderTableModel::new();
        model.set_items(vec![
            make_provider("a"),
            make_provider("b"),
            make_provider("c"),
        ]);

        // Delete first and last rows (indices sorted descending)
        model.delete_rows(&[2, 0]);
        assert_eq!(model.row_count(), 1);
        assert_eq!(model.row(0).unwrap().item().name(), "b");
    }

    #[test]
    fn test_move_row_down() {
        let mut model = ExternalDebugInfoProviderTableModel::new();
        model.set_items(vec![
            make_provider("a"),
            make_provider("b"),
            make_provider("c"),
        ]);

        model.move_row(0, 1);
        assert_eq!(model.row(0).unwrap().item().name(), "b");
        assert_eq!(model.row(1).unwrap().item().name(), "a");
        assert!(model.is_data_changed());
    }

    #[test]
    fn test_move_row_up() {
        let mut model = ExternalDebugInfoProviderTableModel::new();
        model.set_items(vec![
            make_provider("a"),
            make_provider("b"),
            make_provider("c"),
        ]);

        model.move_row(2, -1);
        assert_eq!(model.row(1).unwrap().item().name(), "c");
        assert_eq!(model.row(2).unwrap().item().name(), "b");
    }

    #[test]
    fn test_move_row_out_of_bounds() {
        let mut model = ExternalDebugInfoProviderTableModel::new();
        model.set_items(vec![make_provider("a"), make_provider("b")]);

        // Should be a no-op
        model.move_row(0, -1);
        assert_eq!(model.row(0).unwrap().item().name(), "a");
        assert_eq!(model.row(1).unwrap().item().name(), "b");
    }

    #[test]
    fn test_get_items() {
        let mut model = ExternalDebugInfoProviderTableModel::new();
        model.set_items(vec![make_provider("a"), make_provider("b")]);

        let items = model.get_items();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].name(), "a");
        assert_eq!(items[1].name(), "b");
    }

    #[test]
    fn test_get_cell_value() {
        let mut model = ExternalDebugInfoProviderTableModel::new();
        model.set_items(vec![make_provider("test")]);

        assert_eq!(model.get_cell_value(0, 0), Some("true".to_string()));
        assert_eq!(model.get_cell_value(0, 1), Some("Unknown".to_string()));
        assert_eq!(
            model.get_cell_value(0, 2),
            Some("Test: test".to_string())
        );
        assert_eq!(model.get_cell_value(0, 3), None);
        assert_eq!(model.get_cell_value(1, 0), None);
    }

    #[test]
    fn test_is_cell_editable() {
        let model = ExternalDebugInfoProviderTableModel::new();
        assert!(model.is_cell_editable(0, 0)); // Enabled column
        assert!(!model.is_cell_editable(0, 1)); // Status column
        assert!(!model.is_cell_editable(0, 2)); // Location column
    }

    #[test]
    fn test_column_names() {
        let model = ExternalDebugInfoProviderTableModel::new();
        assert_eq!(model.column_name(0), "Enabled");
        assert_eq!(model.column_name(1), "Status");
        assert_eq!(model.column_name(2), "Location");
        assert_eq!(model.column_name(3), "Unknown");
    }

    #[test]
    fn test_set_row_enabled() {
        let mut model = ExternalDebugInfoProviderTableModel::new();
        model.set_items(vec![make_provider("test")]);

        model.set_row_enabled(0, false);
        assert!(!model.row(0).unwrap().is_enabled());
        assert!(model.is_data_changed());
    }

    #[test]
    fn test_set_row_status() {
        let mut model = ExternalDebugInfoProviderTableModel::new();
        model.set_items(vec![make_provider("test")]);

        model.set_row_status(0, DebugInfoProviderStatus::Valid);
        assert_eq!(
            model.row(0).unwrap().status(),
            DebugInfoProviderStatus::Valid
        );
    }

    #[test]
    fn test_clear() {
        let mut model = ExternalDebugInfoProviderTableModel::new();
        model.set_items(vec![make_provider("a"), make_provider("b")]);
        model.set_data_changed(false);

        model.clear();
        assert!(model.is_empty());
        assert!(model.is_data_changed());
    }

    #[test]
    fn test_data_changed_flag() {
        let mut model = ExternalDebugInfoProviderTableModel::new();
        assert!(!model.is_data_changed());

        model.set_data_changed(true);
        assert!(model.is_data_changed());

        model.set_data_changed(false);
        assert!(!model.is_data_changed());
    }

    #[test]
    fn test_column_index() {
        assert_eq!(ColumnIndex::Enabled as usize, 0);
        assert_eq!(ColumnIndex::Status as usize, 1);
        assert_eq!(ColumnIndex::Location as usize, 2);
        assert_eq!(ColumnIndex::count(), 3);
    }

    #[test]
    fn test_column_index_display_name() {
        assert_eq!(ColumnIndex::Enabled.display_name(), "Enabled");
        assert_eq!(ColumnIndex::Status.display_name(), "Status");
        assert_eq!(ColumnIndex::Location.display_name(), "Location");
    }

    #[test]
    fn test_default_model() {
        let model = ExternalDebugInfoProviderTableModel::default();
        assert!(model.is_empty());
    }
}
