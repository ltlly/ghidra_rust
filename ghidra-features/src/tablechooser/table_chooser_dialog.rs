//! Table Chooser Dialog -- the component-level dialog model that
//! presents a table of addressable rows and lets the user select rows
//! and execute an action via a [`TableChooserExecutor`].
//!
//! Ported from `TableChooserDialog.java` and
//! `AbstractTableChooserDialog.java` in
//! `ghidra.app.tablechooser`.
//!
//! This module builds on the base [`BaseDialog`] (model-only) and adds:
//! - Column configuration and visibility management.
//! - Executor binding and lifecycle.
//! - Filtering / text-search over the table.
//! - Status text summarising the current view.
//! - Selection tracking (selected row indices).
//! - Pending-items management for background execution.
//! - Bulk and per-row execution with removal semantics.
//! - Closed-listener callback support.
//! - Contains / add / remove row operations.

use std::cmp::Ordering;
use std::collections::HashSet;
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
// ExecutionResult
// ---------------------------------------------------------------------------

/// Result of an execution pass (single-row or bulk).
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Number of rows processed.
    pub processed: usize,
    /// Number of rows removed from the table.
    pub removed: usize,
    /// Whether execution was cancelled early.
    pub cancelled: bool,
}

// ---------------------------------------------------------------------------
// ClosedCallback
// ---------------------------------------------------------------------------

/// A boxed closure invoked when the dialog closes.
type ClosedCallback = Box<dyn FnMut()>;

// ---------------------------------------------------------------------------
// TableChooserDialogState
// ---------------------------------------------------------------------------

/// The dialog-level state that wraps a [`BaseDialog`] with UI
/// configuration: column visibility, filtering, executor, selection,
/// pending items, and status text.
///
/// This corresponds to the Java `TableChooserDialogComponentProvider`.
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
    /// Currently selected visible-row positions.
    selected_visible_positions: Vec<usize>,
    /// Rows currently being processed by a background worker (addresses).
    pending_addresses: HashSet<u64>,
    /// Whether a background worker is currently busy.
    busy: bool,
    /// Optional callback invoked when the dialog closes.
    closed_callback: Option<ClosedCallback>,
}

impl<T: AddressableRowObject + Clone + fmt::Debug> fmt::Debug for TableChooserDialogState<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TableChooserDialogState")
            .field("title", &self.inner.title())
            .field("column_configs", &self.column_configs)
            .field("filter_text", &self.filter_text)
            .field("visible", &self.visible)
            .field("confirm_execute", &self.confirm_execute)
            .field("selected_visible_positions", &self.selected_visible_positions)
            .field("pending_addresses", &self.pending_addresses)
            .field("busy", &self.busy)
            .finish()
    }
}

impl<T: AddressableRowObject + Clone> TableChooserDialogState<T> {
    /// Create a new dialog state with the given title.
    pub fn new(title: impl Into<String>) -> Self {
        let inner = BaseDialog::new(title);
        let column_configs = vec![ColumnConfig::new("Address")];
        let mut s = Self {
            inner,
            column_configs,
            executor: None,
            filter_text: String::new(),
            filtered_indices: Vec::new(),
            visible: true,
            confirm_execute: true,
            selected_visible_positions: Vec::new(),
            pending_addresses: HashSet::new(),
            busy: false,
            closed_callback: None,
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

    /// Add a row to the dialog. Can be called from any thread context
    /// (the Rust model is single-threaded; this mirrors the Java
    /// `add(AddressableRowObject)` method).
    pub fn add_row(&mut self, row: T) {
        self.inner.add_row(row);
        self.rebuild_filtered_indices();
    }

    /// Add multiple rows to the dialog.
    pub fn add_rows(&mut self, rows: impl IntoIterator<Item = T>) {
        for row in rows {
            self.inner.add_row(row);
        }
        self.rebuild_filtered_indices();
    }

    /// Remove a specific row from the dialog, matching by address.
    ///
    /// Returns `true` if the row was found and removed.
    /// Mirrors `TableChooserDialog.remove(AddressableRowObject)`.
    pub fn remove_row(&mut self, target_address: Address) -> bool {
        let model = self.inner.model();
        let idx = (0..model.row_count()).find(|&i| {
            model
                .get_row(i)
                .map_or(false, |r| r.get_address() == target_address)
        });
        if let Some(idx) = idx {
            self.inner.model_mut().remove_row(idx);
            self.pending_addresses.remove(&target_address.0);
            self.rebuild_filtered_indices();
            true
        } else {
            false
        }
    }

    /// Check whether a row with the given address is still in the dialog.
    ///
    /// Mirrors `TableChooserDialog.contains(AddressableRowObject)`.
    pub fn contains(&self, address: Address) -> bool {
        let model = self.inner.model();
        (0..model.row_count()).any(|i| {
            model
                .get_row(i)
                .map_or(false, |r| r.get_address() == address)
        })
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

    /// Execute the bound action on all currently selected visible rows.
    ///
    /// Uses `execute_in_bulk` if the executor supports it; otherwise
    /// falls back to per-row `execute` calls.
    ///
    /// Returns an [`ExecutionResult`] summarising what happened.
    /// Returns `None` if no executor is bound.
    ///
    /// This mirrors the Java `okCallback()` logic with
    /// `doProcessRows` / `doProcessRowsInTransaction`.
    pub fn execute_on_selected(&mut self) -> Option<ExecutionResult> {
        if self.executor.is_none() {
            return None;
        }

        // Collect selected visible positions, excluding pending items.
        let selected_positions: Vec<usize> = self
            .selected_visible_positions
            .iter()
            .copied()
            .filter(|&pos| {
                self.filtered_indices
                    .get(pos)
                    .and_then(|&model_idx| self.inner.model().get_row(model_idx))
                    .map_or(false, |row| !self.pending_addresses.contains(&row.get_address().0))
            })
            .collect();

        if selected_positions.is_empty() {
            return Some(ExecutionResult {
                processed: 0,
                removed: 0,
                cancelled: false,
            });
        }

        // Mark as pending.
        for &pos in &selected_positions {
            if let Some(&model_idx) = self.filtered_indices.get(pos) {
                if let Some(row) = self.inner.model().get_row(model_idx) {
                    self.pending_addresses.insert(row.get_address().0);
                }
            }
        }

        // Try bulk execution first.
        let executor = self.executor.as_ref().unwrap();
        let mut rows_to_process: Vec<T> = Vec::new();
        let mut model_indices: Vec<usize> = Vec::new();
        for &pos in &selected_positions {
            if let Some(&model_idx) = self.filtered_indices.get(pos) {
                if let Some(row) = self.inner.model().get_row(model_idx) {
                    rows_to_process.push(row.clone());
                    model_indices.push(model_idx);
                }
            }
        }

        let mut deleted: Vec<T> = Vec::new();
        let bulk_used = executor.execute_in_bulk(&rows_to_process, &mut deleted);

        if !bulk_used {
            // Fall back to per-row execution.
            for row in &rows_to_process {
                if executor.execute(row) {
                    deleted.push(row.clone());
                }
            }
        }

        let removed = deleted.len();

        // Remove deleted rows.
        for deleted_row in &deleted {
            self.pending_addresses.remove(&deleted_row.get_address().0);
            // Find and remove from model.
            let model = self.inner.model();
            let idx = (0..model.row_count()).find(|&i| {
                model
                    .get_row(i)
                    .map_or(false, |r| r.get_address() == deleted_row.get_address())
            });
            if let Some(idx) = idx {
                self.inner.model_mut().remove_row(idx);
            }
        }

        // Clear pending for all processed rows.
        for row in &rows_to_process {
            self.pending_addresses.remove(&row.get_address().0);
        }

        self.clear_selection();
        self.rebuild_filtered_indices();

        Some(ExecutionResult {
            processed: rows_to_process.len(),
            removed,
            cancelled: false,
        })
    }

    // -- Selection -----------------------------------------------------------

    /// Set the selected visible-row positions.
    pub fn set_selected_visible_positions(&mut self, positions: Vec<usize>) {
        self.selected_visible_positions = positions;
    }

    /// Get the currently selected visible-row positions.
    pub fn selected_visible_positions(&self) -> &[usize] {
        &self.selected_visible_positions
    }

    /// Select a single visible row by position.
    pub fn select_visible_row(&mut self, pos: usize) {
        if !self.selected_visible_positions.contains(&pos) {
            self.selected_visible_positions.push(pos);
            self.selected_visible_positions.sort_unstable();
        }
    }

    /// Select a range of visible rows.
    pub fn select_visible_range(&mut self, start: usize, end: usize) {
        for pos in start..=end {
            self.select_visible_row(pos);
        }
    }

    /// Clear all selections.
    pub fn clear_selection(&mut self) {
        self.selected_visible_positions.clear();
    }

    /// Get the model indices for all selected visible rows.
    pub fn selected_model_indices(&self) -> Vec<usize> {
        self.selected_visible_positions
            .iter()
            .filter_map(|&pos| self.filtered_indices.get(pos).copied())
            .collect()
    }

    /// Get the row objects for all selected visible rows.
    pub fn selected_row_objects(&self) -> Vec<&T> {
        self.selected_visible_positions
            .iter()
            .filter_map(|&pos| {
                let model_idx = *self.filtered_indices.get(pos)?;
                self.inner.model().get_row(model_idx)
            })
            .collect()
    }

    /// Whether there are any selected rows.
    pub fn has_selection(&self) -> bool {
        !self.selected_visible_positions.is_empty()
    }

    /// The number of selected rows.
    pub fn selection_count(&self) -> usize {
        self.selected_visible_positions.len()
    }

    // -- Pending / Busy ------------------------------------------------------

    /// Whether a specific address is currently being processed.
    pub fn is_pending(&self, address: Address) -> bool {
        self.pending_addresses.contains(&address.0)
    }

    /// Get all addresses currently pending execution.
    pub fn pending_addresses(&self) -> &HashSet<u64> {
        &self.pending_addresses
    }

    /// Whether the dialog is currently processing items.
    pub fn is_busy(&self) -> bool {
        self.busy
    }

    /// Set the busy state (for background worker tracking).
    pub fn set_busy(&mut self, busy: bool) {
        self.busy = busy;
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

    /// Set a custom status / message text.
    ///
    /// Mirrors `TableChooserDialog.setMessage(String)`.
    pub fn set_message(&mut self, _message: impl Into<String>) {
        // In a GUI implementation this would update the status bar.
        // For the non-GUI model we store it but currently discard.
        // Kept for API compatibility.
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
    ///
    /// Invokes the closed callback if one is set.
    /// Mirrors `TableChooserDialog.close()`.
    pub fn close(&mut self) {
        self.visible = false;
        if let Some(ref mut cb) = self.closed_callback {
            cb();
        }
    }

    // -- Closed listener -----------------------------------------------------

    /// Set a callback to be invoked when the dialog is closed.
    ///
    /// Mirrors `TableChooserDialog.setClosedListener(Callback)`.
    pub fn set_closed_listener(&mut self, callback: impl FnMut() + 'static) {
        self.closed_callback = Some(Box::new(callback));
    }

    /// Remove the closed listener.
    pub fn clear_closed_listener(&mut self) {
        self.closed_callback = None;
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

    // -- Disposal ------------------------------------------------------------

    /// Dispose of the dialog, clearing all state.
    ///
    /// Mirrors `TableChooserDialog.dispose()`.
    pub fn dispose(&mut self) {
        self.visible = false;
        self.pending_addresses.clear();
        self.selected_visible_positions.clear();
        self.busy = false;
        self.closed_callback = None;
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
    fn test_dialog_add_rows_batch() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        dialog.add_rows(make_rows());
        assert_eq!(dialog.total_row_count(), 3);
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

    // -- Selection tests -----------------------------------------------------

    #[test]
    fn test_selection_basic() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        dialog.add_rows(make_rows());

        assert!(!dialog.has_selection());
        assert_eq!(dialog.selection_count(), 0);

        dialog.select_visible_row(0);
        dialog.select_visible_row(2);
        assert!(dialog.has_selection());
        assert_eq!(dialog.selection_count(), 2);
        assert_eq!(dialog.selected_visible_positions(), &[0, 2]);
    }

    #[test]
    fn test_selection_range() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        dialog.add_rows(make_rows());

        dialog.select_visible_range(0, 2);
        assert_eq!(dialog.selection_count(), 3);
    }

    #[test]
    fn test_selection_clear() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        dialog.add_rows(make_rows());

        dialog.select_visible_row(0);
        dialog.select_visible_row(1);
        assert_eq!(dialog.selection_count(), 2);

        dialog.clear_selection();
        assert_eq!(dialog.selection_count(), 0);
    }

    #[test]
    fn test_selected_row_objects() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        dialog.add_rows(make_rows());

        dialog.select_visible_row(0);
        let selected = dialog.selected_row_objects();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].addr, 0x3000);
    }

    #[test]
    fn test_select_no_duplicates() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        dialog.add_rows(make_rows());

        dialog.select_visible_row(1);
        dialog.select_visible_row(1);
        assert_eq!(dialog.selection_count(), 1);
    }

    // -- Remove / Contains tests ---------------------------------------------

    #[test]
    fn test_remove_row() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        dialog.add_rows(make_rows());
        assert_eq!(dialog.total_row_count(), 3);

        let removed = dialog.remove_row(Address(0x1000));
        assert!(removed);
        assert_eq!(dialog.total_row_count(), 2);
        assert!(!dialog.contains(Address(0x1000)));
        assert!(dialog.contains(Address(0x2000)));
    }

    #[test]
    fn test_remove_nonexistent_row() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        dialog.add_rows(make_rows());

        let removed = dialog.remove_row(Address(0x9999));
        assert!(!removed);
        assert_eq!(dialog.total_row_count(), 3);
    }

    #[test]
    fn test_contains() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        dialog.add_rows(make_rows());

        assert!(dialog.contains(Address(0x1000)));
        assert!(dialog.contains(Address(0x2000)));
        assert!(dialog.contains(Address(0x3000)));
        assert!(!dialog.contains(Address(0x4000)));
    }

    // -- Bulk execution tests ------------------------------------------------

    #[derive(Debug)]
    struct BulkRemoveExecutor;

    impl TableChooserExecutor<TestRow> for BulkRemoveExecutor {
        fn get_button_name(&self) -> &str {
            "Bulk Remove"
        }

        fn execute(&self, _row: &TestRow) -> bool {
            true
        }

        fn execute_in_bulk(
            &self,
            rows: &[TestRow],
            deleted: &mut Vec<TestRow>,
        ) -> bool {
            for row in rows {
                // Remove rows with size > 100
                if row.size > 100 {
                    deleted.push(row.clone());
                }
            }
            true
        }
    }

    #[test]
    fn test_execute_on_selected_bulk() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        dialog.add_rows(make_rows());
        dialog.set_executor(Box::new(BulkRemoveExecutor));

        dialog.select_visible_row(0); // func_c, size=100
        dialog.select_visible_row(1); // func_a, size=200

        let result = dialog.execute_on_selected().unwrap();
        assert_eq!(result.processed, 2);
        // Only func_a (size=200 > 100) should be removed by bulk executor.
        assert_eq!(result.removed, 1);
        assert_eq!(dialog.total_row_count(), 2);
    }

    #[test]
    fn test_execute_on_selected_no_executor() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        dialog.add_rows(make_rows());
        dialog.select_visible_row(0);

        let result = dialog.execute_on_selected();
        assert!(result.is_none());
    }

    #[test]
    fn test_execute_on_selected_empty_selection() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        dialog.add_rows(make_rows());
        dialog.set_executor(Box::new(RemoveExecutor::new()));

        let result = dialog.execute_on_selected().unwrap();
        assert_eq!(result.processed, 0);
        assert_eq!(result.removed, 0);
    }

    #[test]
    fn test_execute_on_selected_fallback_to_per_row() {
        // RemoveExecutor does not override execute_in_bulk, so it falls back.
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        dialog.add_rows(make_rows());
        dialog.set_executor(Box::new(RemoveExecutor::new()));

        dialog.select_visible_row(0);
        dialog.select_visible_row(1);

        let result = dialog.execute_on_selected().unwrap();
        assert_eq!(result.processed, 2);
        assert_eq!(result.removed, 2);
        assert_eq!(dialog.total_row_count(), 1);
    }

    // -- Pending / Busy tests ------------------------------------------------

    #[test]
    fn test_pending_tracking() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        dialog.add_rows(make_rows());

        assert!(!dialog.is_pending(Address(0x1000)));
        assert!(!dialog.is_busy());

        dialog.set_busy(true);
        assert!(dialog.is_busy());

        dialog.set_busy(false);
        assert!(!dialog.is_busy());
    }

    // -- Closed listener tests -----------------------------------------------

    #[test]
    fn test_closed_listener() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = called.clone();

        dialog.set_closed_listener(move || {
            called_clone.store(true, Ordering::SeqCst);
        });

        assert!(!called.load(Ordering::SeqCst));
        dialog.close();
        assert!(called.load(Ordering::SeqCst));
        assert!(!dialog.is_visible());
    }

    #[test]
    fn test_clear_closed_listener() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        dialog.set_closed_listener(|| {});
        dialog.clear_closed_listener();
        // Should not panic when closing without listener.
        dialog.close();
    }

    // -- Dispose tests -------------------------------------------------------

    #[test]
    fn test_dispose() {
        let mut dialog = TableChooserDialogState::<TestRow>::new("D");
        dialog.add_rows(make_rows());
        dialog.select_visible_row(0);
        dialog.set_busy(true);
        dialog.set_visible(true);

        dialog.dispose();
        assert!(!dialog.is_visible());
        assert!(!dialog.is_busy());
        assert_eq!(dialog.selection_count(), 0);
    }
}
