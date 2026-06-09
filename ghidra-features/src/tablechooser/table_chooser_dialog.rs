//! Table Chooser Dialog -- the component-level dialog model that
//! presents a table of addressable rows and lets the user select rows
//! and execute an action via a [`TableChooserExecutor`].
//!
//! Ported from `TableChooserDialog.java` and
//! `AbstractTableChooserDialog.java` in
//! `ghidra.app.plugin.core.tablechooser`.
//!
//! This module builds on the base [`TableChooserDialog`] (model-only)
//! and adds:
//! - Column configuration and visibility management.
//! - Executor binding and lifecycle.
//! - Filtering / text-search over the table.
//! - Status text summarising the current view.

use std::cmp::Ordering;
use std::fmt;

use crate::base::tablechooser::{
    Address, AddressableRowObject, ColumnDisplay, TableChooserDialog as BaseDialog,
    TableChooserExecutor, TableChooserTableModel,
};

// ---------------------------------------------------------------------------
// ColumnConfig
// ---------------------------------------------------------------------------

/// Configuration for a single column in the dialog.
#[derive(Debug, Clone)]
pub struct ColumnConfig {
    /// Column name (header text).
    pub name: String,
    /// Whether the column is currently visible.
    pub visible: bool,
    /// Preferred width in pixels.
    pub width: usize,
    /// Whether the column is currently the sort column.
    pub sort_column: bool,
    /// Sort direction (true = ascending).
    pub sort_ascending: bool,
}

impl ColumnConfig {
    /// Create a new visible column config with default width.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            visible: true,
            width: 100,
            sort_column: false,
            sort_ascending: true,
        }
    }

    /// Create a column config with a specific width.
    pub fn with_width(name: impl Into<String>, width: usize) -> Self {
        Self {
            width,
            ..Self::new(name)
        }
    }
}

// ---------------------------------------------------------------------------
// TableChooserDialogState
// ---------------------------------------------------------------------------

/// The dialog-level state that wraps a [`BaseDialog`] with UI
/// configuration: column visibility, filtering, executor, and status text.
///
/// This corresponds to the Java `TableChooserDialogComponentProvider`.
#[derive(Debug)]
pub struct TableChooserDialogState<T: AddressableRowObject> {
    /// The underlying base dialog model.
    inner: BaseDialog<T>,
    /// Per-column configuration (one entry per column, including address).
    column_configs: Vec<ColumnConfig>,
    /// The executor bound to this dialog (runs on selected rows).
    executor: Option<Box<dyn TableChooserExecutor<T>>>,
    /// Current filter text (empty = show all rows).
    filter_text: String,
    /// Indices of rows that pass the current filter.
    filtered_indices: Vec<usize>,
    /// Whether the dialog is currently visible.
    visible: bool,
    /// Whether to confirm before executing the action.
    confirm_execute: bool,
}

impl<T: AddressableRowObject + Clone> TableChooserDialogState<T> {
    /// Create a new dialog state with the given title.
    pub fn new(title: impl Into<String>) -> Self {
        let inner = BaseDialog::new(title);
        let column_configs = vec![ColumnConfig::new("Address")];
        // Pre-populate column configs from the inner model.
        // The inner model starts with 0 custom columns; they are added via add_column.
        let mut s = Self {
            inner,
            column_configs,
            executor: None,
            filter_text: String::new(),
            filtered_indices: Vec::new(),
            visible: true,
            confirm_execute: true,
        };
        s.rebuild_filtered_indices();
        s
    }

    // -- Title ---------------------------------------------------------------

    /// The dialog title.
    pub fn title(&self) -> &str {
        self.inner.title()
    }

    // -- Rows ----------------------------------------------------------------

    /// Add a row to the dialog.
    pub fn add_row(&mut self, row: T) {
        self.inner.add_row(row);
        self.rebuild_filtered_indices();
    }

    /// The total number of rows (unfiltered).
    pub fn total_row_count(&self) -> usize {
        self.inner.model().row_count()
    }

    /// The number of visible (filtered) rows.
    pub fn visible_row_count(&self) -> usize {
        self.filtered_indices.len()
    }

    /// Get a reference to a row by its index in the *unfiltered* model.
    pub fn get_row(&self, index: usize) -> Option<&T> {
        self.inner.model().get_row(index)
    }

    /// Get the model index for a given visible-row position.
    ///
    /// Returns `None` if the position is out of range.
    pub fn visible_row_index(&self, visible_pos: usize) -> Option<usize> {
        self.filtered_indices.get(visible_pos).copied()
    }

    // -- Columns -------------------------------------------------------------

    /// Add a column to the dialog.
    pub fn add_column(&mut self, column: Box<dyn ColumnDisplay<T>>) {
        let config = ColumnConfig::new(column.get_column_name());
        self.column_configs.push(config);
        self.inner.add_column(column);
    }

    /// The total number of columns (including address).
    pub fn column_count(&self) -> usize {
        self.inner.model().column_count()
    }

    /// Get the column config by index.
    pub fn column_config(&self, index: usize) -> Option<&ColumnConfig> {
        self.column_configs.get(index)
    }

    /// Get a mutable reference to the column config by index.
    pub fn column_config_mut(&mut self, index: usize) -> Option<&mut ColumnConfig> {
        self.column_configs.get_mut(index)
    }

    /// Get all column configs.
    pub fn column_configs(&self) -> &[ColumnConfig] {
        &self.column_configs
    }

    /// Set the sort column and direction.
    pub fn set_sort_column(&mut self, col: usize, ascending: bool) {
        for (i, cfg) in self.column_configs.iter_mut().enumerate() {
            cfg.sort_column = i == col;
            if i == col {
                cfg.sort_ascending = ascending;
            }
        }
        self.inner.model_mut().sort_by_column(col, ascending);
        self.rebuild_filtered_indices();
    }

    /// Get the display value for a cell in the visible table.
    ///
    /// `visible_row` is the position in the filtered view.
    pub fn get_visible_cell_value(&self, visible_row: usize, col: usize) -> Option<String> {
        let model_index = self.filtered_indices.get(visible_row)?;
        self.inner.model().get_cell_value(*model_index, col)
    }

    // -- Executor ------------------------------------------------------------

    /// Bind an executor to this dialog.
    pub fn set_executor(&mut self, executor: Box<dyn TableChooserExecutor<T>>) {
        self.executor = Some(executor);
    }

    /// Get the executor's button name, if an executor is bound.
    pub fn executor_button_name(&self) -> Option<&str> {
        self.executor.as_ref().map(|e| e.get_button_name())
    }

    /// Execute the bound action on the row at the given visible position.
    ///
    /// Returns `true` if the row was consumed (should be removed), `false`
    /// otherwise. Returns `None` if no executor is bound or the position
    /// is invalid.
    pub fn execute_on_visible_row(&mut self, visible_pos: usize) -> Option<bool> {
        let executor = self.executor.as_ref()?;
        let model_index = *self.filtered_indices.get(visible_pos)?;
        let row = self.inner.model().get_row(model_index)?;
        let remove = executor.execute(row);
        if remove {
            self.inner.model_mut().remove_row(model_index);
            self.rebuild_filtered_indices();
        }
        Some(remove)
    }

    // -- Filter / Search -----------------------------------------------------

    /// Set the filter text and recompute visible rows.
    ///
    /// A row is visible if *any* of its cell values (as strings) contain
    /// the filter text (case-insensitive).
    pub fn set_filter_text(&mut self, text: impl Into<String>) {
        self.filter_text = text.into();
        self.rebuild_filtered_indices();
    }

    /// The current filter text.
    pub fn filter_text(&self) -> &str {
        &self.filter_text
    }

    fn rebuild_filtered_indices(&mut self) {
        let model = self.inner.model();
        let total = model.row_count();
        if self.filter_text.is_empty() {
            self.filtered_indices = (0..total).collect();
        } else {
            let lower_filter = self.filter_text.to_lowercase();
            self.filtered_indices = (0..total)
                .filter(|&row_idx| {
                    let col_count = model.column_count();
                    (0..col_count).any(|col| {
                        model
                            .get_cell_value(row_idx, col)
                            .map_or(false, |v| v.to_lowercase().contains(&lower_filter))
                    })
                })
                .collect();
        }
    }

    // -- Status text ---------------------------------------------------------

    /// Generate a status summary string.
    ///
    /// Example: `"42 of 100 rows shown"`.
    pub fn status_text(&self) -> String {
        let visible = self.visible_row_count();
        let total = self.total_row_count();
        if self.filter_text.is_empty() {
            format!("{} row(s)", total)
        } else {
            format!("{} of {} row(s) shown", visible, total)
        }
    }

    // -- Visibility ----------------------------------------------------------

    /// Whether the dialog is currently visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Show or hide the dialog.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Close the dialog.
    pub fn close(&mut self) {
        self.visible = false;
    }

    // -- Confirmation --------------------------------------------------------

    /// Whether to confirm before executing.
    pub fn confirm_execute(&self) -> bool {
        self.confirm_execute
    }

    /// Set whether to confirm before executing.
    pub fn set_confirm_execute(&mut self, value: bool) {
        self.confirm_execute = value;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;
    use std::fmt;

    #[derive(Debug, Clone)]
    struct TestRow {
        addr: u64,
        name: String,
        size: u64,
    }

    impl AddressableRowObject for TestRow {
        fn get_address(&self) -> Address {
            Address(self.addr)
        }
    }

    fn make_rows() -> Vec<TestRow> {
        vec![
            TestRow {
                addr: 0x3000,
                name: "func_c".into(),
                size: 100,
            },
            TestRow {
                addr: 0x1000,
                name: "func_a".into(),
                size: 200,
            },
            TestRow {
                addr: 0x2000,
                name: "func_b".into(),
                size: 50,
            },
        ]
    }

    #[test]
    fn test_dialog_state_new() {
        let dialog = TableChooserDialogState::<TestRow>::new("Choose");
        assert_eq!(dialog.title(), "Choose");
        assert_eq!(dialog.total_row_count(), 0);
        assert_eq!(dialog.visible_row_count(), 0);
        assert!(dialog.is_visible());
        assert!(dialog.confirm_execute());
        assert_eq!(dialog.filter_text(), "");
    }

    #[test]
    fn test_dialog_add_rows() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        for row in make_rows() {
            dialog.add_row(row);
        }
        assert_eq!(dialog.total_row_count(), 3);
        assert_eq!(dialog.visible_row_count(), 3);
    }

    #[test]
    fn test_dialog_column_configs() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        // Starts with the Address column.
        assert_eq!(dialog.column_configs().len(), 1);
        assert_eq!(dialog.column_configs()[0].name, "Address");

        dialog.add_column(Box::new(
            crate::base::tablechooser::StringColumnDisplay::new(
                "Name",
                Box::new(|r: &TestRow| r.name.clone()),
            ),
        ));
        assert_eq!(dialog.column_configs().len(), 2);
        assert_eq!(dialog.column_configs()[1].name, "Name");
    }

    #[test]
    fn test_dialog_filter() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        // Add Name column so filtering on function names works.
        dialog.add_column(Box::new(
            crate::base::tablechooser::StringColumnDisplay::new(
                "Name",
                Box::new(|r: &TestRow| r.name.clone()),
            ),
        ));
        for row in make_rows() {
            dialog.add_row(row);
        }

        // Filter for "func_a" -- only one row matches.
        dialog.set_filter_text("func_a");
        assert_eq!(dialog.visible_row_count(), 1);
        assert_eq!(dialog.visible_row_index(0), Some(1)); // model index 1

        // Filter for "func" -- all rows match.
        dialog.set_filter_text("func");
        assert_eq!(dialog.visible_row_count(), 3);

        // Clear filter.
        dialog.set_filter_text("");
        assert_eq!(dialog.visible_row_count(), 3);
    }

    #[test]
    fn test_dialog_filter_case_insensitive() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        dialog.add_column(Box::new(
            crate::base::tablechooser::StringColumnDisplay::new(
                "Name",
                Box::new(|r: &TestRow| r.name.clone()),
            ),
        ));
        dialog.add_row(TestRow {
            addr: 0x1000,
            name: "MyFunc".into(),
            size: 10,
        });

        dialog.set_filter_text("myfunc");
        assert_eq!(dialog.visible_row_count(), 1);

        dialog.set_filter_text("MYFUNC");
        assert_eq!(dialog.visible_row_count(), 1);
    }

    #[test]
    fn test_dialog_visible_cell_value() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        for row in make_rows() {
            dialog.add_row(row);
        }
        dialog.add_column(Box::new(
            crate::base::tablechooser::StringColumnDisplay::new(
                "Name",
                Box::new(|r: &TestRow| r.name.clone()),
            ),
        ));

        // Visible row 0 = model row 0 (func_c at 0x3000).
        let addr_cell = dialog.get_visible_cell_value(0, 0);
        assert_eq!(addr_cell, Some("0x3000".to_string()));

        let name_cell = dialog.get_visible_cell_value(0, 1);
        assert_eq!(name_cell, Some("func_c".to_string()));
    }

    #[test]
    fn test_dialog_sort_column() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        for row in make_rows() {
            dialog.add_row(row);
        }
        dialog.add_column(Box::new(
            crate::base::tablechooser::StringColumnDisplay::new(
                "Name",
                Box::new(|r: &TestRow| r.name.clone()),
            ),
        ));

        // Sort by Name ascending.
        dialog.set_sort_column(1, true);
        let first = dialog.get_visible_cell_value(0, 1);
        assert_eq!(first, Some("func_a".to_string()));

        // Sort by Name descending.
        dialog.set_sort_column(1, false);
        let first = dialog.get_visible_cell_value(0, 1);
        assert_eq!(first, Some("func_c".to_string()));
    }

    #[test]
    fn test_dialog_status_text() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        dialog.add_column(Box::new(
            crate::base::tablechooser::StringColumnDisplay::new(
                "Name",
                Box::new(|r: &TestRow| r.name.clone()),
            ),
        ));
        for row in make_rows() {
            dialog.add_row(row);
        }

        assert_eq!(dialog.status_text(), "3 row(s)");

        dialog.set_filter_text("func_a");
        assert_eq!(dialog.status_text(), "1 of 3 row(s) shown");
    }

    #[test]
    fn test_dialog_visibility() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        assert!(dialog.is_visible());
        dialog.close();
        assert!(!dialog.is_visible());
        dialog.set_visible(true);
        assert!(dialog.is_visible());
    }

    #[test]
    fn test_dialog_confirm_execute() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        assert!(dialog.confirm_execute());
        dialog.set_confirm_execute(false);
        assert!(!dialog.confirm_execute());
    }

    // -- Executor tests ------------------------------------------------------

    #[derive(Debug)]
    struct RemoveExecutor {
        button_name: String,
    }

    impl RemoveExecutor {
        fn new() -> Self {
            Self {
                button_name: "Remove".into(),
            }
        }
    }

    impl TableChooserExecutor<TestRow> for RemoveExecutor {
        fn get_button_name(&self) -> &str {
            &self.button_name
        }

        fn execute(&self, _row: &TestRow) -> bool {
            true // always remove
        }
    }

    #[test]
    fn test_dialog_executor_binding() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        assert!(dialog.executor_button_name().is_none());

        dialog.set_executor(Box::new(RemoveExecutor::new()));
        assert_eq!(dialog.executor_button_name(), Some("Remove"));
    }

    #[test]
    fn test_dialog_execute_on_visible_row() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        for row in make_rows() {
            dialog.add_row(row);
        }
        dialog.set_executor(Box::new(RemoveExecutor::new()));

        // Execute on visible row 0 (model row 0 = func_c).
        let result = dialog.execute_on_visible_row(0);
        assert_eq!(result, Some(true));
        // Row should be removed.
        assert_eq!(dialog.total_row_count(), 2);
        assert_eq!(dialog.visible_row_count(), 2);
    }

    #[test]
    fn test_dialog_execute_no_executor() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        dialog.add_row(TestRow {
            addr: 0x1000,
            name: "a".into(),
            size: 0,
        });

        let result = dialog.execute_on_visible_row(0);
        assert!(result.is_none());
    }

    #[test]
    fn test_dialog_execute_invalid_index() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        dialog.add_row(TestRow {
            addr: 0x1000,
            name: "a".into(),
            size: 0,
        });
        dialog.set_executor(Box::new(RemoveExecutor::new()));

        let result = dialog.execute_on_visible_row(99);
        assert!(result.is_none());
    }

    #[test]
    fn test_dialog_execute_with_filter() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        dialog.add_column(Box::new(
            crate::base::tablechooser::StringColumnDisplay::new(
                "Name",
                Box::new(|r: &TestRow| r.name.clone()),
            ),
        ));
        for row in make_rows() {
            dialog.add_row(row);
        }
        dialog.set_executor(Box::new(RemoveExecutor::new()));

        // Filter to only "func_b".
        dialog.set_filter_text("func_b");
        assert_eq!(dialog.visible_row_count(), 1);

        // Execute on the only visible row.
        let result = dialog.execute_on_visible_row(0);
        assert_eq!(result, Some(true));
        assert_eq!(dialog.total_row_count(), 2);
    }

    #[test]
    fn test_column_config() {
        let mut cfg = ColumnConfig::new("Test");
        assert_eq!(cfg.name, "Test");
        assert!(cfg.visible);
        assert_eq!(cfg.width, 100);
        assert!(!cfg.sort_column);
        assert!(cfg.sort_ascending);

        cfg.visible = false;
        cfg.width = 200;
        assert!(!cfg.visible);
        assert_eq!(cfg.width, 200);
    }

    #[test]
    fn test_column_config_with_width() {
        let cfg = ColumnConfig::with_width("Wide", 300);
        assert_eq!(cfg.name, "Wide");
        assert_eq!(cfg.width, 300);
    }

    #[test]
    fn test_dialog_get_row() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        for row in make_rows() {
            dialog.add_row(row);
        }
        assert_eq!(dialog.get_row(0).unwrap().name, "func_c");
        assert_eq!(dialog.get_row(1).unwrap().name, "func_a");
        assert!(dialog.get_row(99).is_none());
    }

    #[test]
    fn test_dialog_visible_row_index_out_of_range() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        dialog.add_row(TestRow {
            addr: 0x1000,
            name: "a".into(),
            size: 0,
        });
        assert!(dialog.visible_row_index(99).is_none());
    }
}
