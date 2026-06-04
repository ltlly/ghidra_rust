//! Table-chooser dialog.
//!
//! This module provides the Rust analogues of Ghidra's
//! `TableChooserDialog` and `TableServiceTableChooserDialog`, which
//! display a table of [`AddressableRowObject`]s and allow users to
//! select rows and execute an action via a [`TableChooserExecutor`].

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use ghidra_core::addr::Address;

use super::model::{SimpleRowObject, TableChooserTableModel, TableSortState};
use super::traits::{AddressableRowObject, TableChooserExecutor};

// ---------------------------------------------------------------------------
// DialogState
// ---------------------------------------------------------------------------

/// Lifecycle state of a table-chooser dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogState {
    /// The dialog is being constructed.
    Initializing,
    /// The dialog is visible and accepting input.
    Open,
    /// The dialog is currently processing selected rows.
    Busy,
    /// The dialog has been closed.
    Closed,
}

// ---------------------------------------------------------------------------
// TableChooserDialog
// ---------------------------------------------------------------------------

/// Dialog to show a table of items with an executable action.
///
/// This is the Rust equivalent of
/// `ghidra.app.tablechooser.TableChooserDialog`.  If constructed with
/// a non-null executor, a button will be placed in the dialog, allowing
/// the user to perform the action defined by the executor.
///
/// # Pending Items
///
/// Items that are currently being processed are tracked as "pending"
/// and painted differently.  Attempting to reschedule pending items
/// has no effect.
pub struct TableChooserDialog {
    /// Dialog title.
    title: String,
    /// Whether the dialog is modal.
    is_modal: bool,
    /// Current lifecycle state.
    state: DialogState,
    /// The underlying table model.
    model: TableChooserTableModel<SimpleRowObject>,
    /// The executor for processing selected rows.
    executor: Option<Arc<dyn TableChooserExecutor>>,
    /// Set of addresses currently being processed.
    pending: HashSet<Address>,
    /// Indices of currently selected rows.
    selected_rows: Vec<usize>,
    /// Whether the OK button is enabled.
    ok_enabled: bool,
    /// Status text displayed in the dialog.
    status_text: String,
    /// Callback invoked when the dialog is closed.
    closed_callback: Option<Box<dyn Fn() + Send + Sync>>,
    /// Program name for display.
    program_name: Option<String>,
    /// Whether the executor is busy processing rows.
    busy: bool,
}

impl TableChooserDialog {
    /// Creates a new table-chooser dialog.
    ///
    /// # Parameters
    ///
    /// * `title` -- the dialog title.
    /// * `executor` -- optional executor for processing selected rows.
    /// * `program_name` -- optional program name for display.
    /// * `is_modal` -- whether the dialog is modal.
    pub fn new(
        title: impl Into<String>,
        executor: Option<Arc<dyn TableChooserExecutor>>,
        program_name: Option<String>,
        is_modal: bool,
    ) -> Self {
        let title = title.into();
        let mut model = TableChooserTableModel::new(&title);
        model.set_sort_column(0);

        Self {
            title,
            is_modal,
            state: DialogState::Initializing,
            model,
            executor,
            pending: HashSet::new(),
            selected_rows: Vec::new(),
            ok_enabled: false,
            status_text: String::new(),
            closed_callback: None,
            program_name,
            busy: false,
        }
    }

    /// Returns the dialog title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns whether the dialog is modal.
    pub fn is_modal(&self) -> bool {
        self.is_modal
    }

    /// Returns the current dialog state.
    pub fn state(&self) -> DialogState {
        self.state
    }

    /// Shows the dialog (transitions to `Open` state).
    pub fn show(&mut self) {
        self.state = DialogState::Open;
    }

    /// Closes the dialog and invokes the closed callback.
    pub fn close(&mut self) {
        self.state = DialogState::Closed;
        if let Some(cb) = &self.closed_callback {
            cb();
        }
    }

    /// Sets the callback to be invoked when the dialog is closed.
    pub fn set_closed_listener(&mut self, callback: impl Fn() + Send + Sync + 'static) {
        self.closed_callback = Some(Box::new(callback));
    }

    /// Adds a row object to the dialog's table.
    pub fn add(&mut self, row: SimpleRowObject) {
        self.model.add_object(row);
    }

    /// Removes a row object from the dialog's table by address.
    pub fn remove(&mut self, addr: &Address) -> bool {
        self.model.remove_object(addr)
    }

    /// Returns `true` if the dialog contains a row at the given address.
    pub fn contains(&self, addr: &Address) -> bool {
        self.model.contains_address(addr)
    }

    /// Sets the selected rows by index.
    pub fn set_selected_rows(&mut self, rows: Vec<usize>) {
        self.selected_rows = rows;
        self.ok_enabled = !self.selected_rows.is_empty();
    }

    /// Returns the indices of the currently selected rows.
    pub fn selected_rows(&self) -> &[usize] {
        &self.selected_rows
    }

    /// Returns references to the currently selected row objects.
    pub fn get_selected_row_objects(&self) -> Vec<&SimpleRowObject> {
        self.model.get_row_objects_at(&self.selected_rows)
    }

    /// Clears the current selection.
    pub fn clear_selection(&mut self) {
        self.selected_rows.clear();
        self.ok_enabled = false;
    }

    /// Returns `true` if the OK button is enabled.
    pub fn is_ok_enabled(&self) -> bool {
        self.ok_enabled
    }

    /// Sets the OK button enabled state.
    pub fn set_ok_enabled(&mut self, enabled: bool) {
        self.ok_enabled = enabled;
    }

    /// Returns the executor button name, if an executor is set.
    pub fn button_name(&self) -> Option<&str> {
        self.executor.as_ref().map(|e| e.button_name())
    }

    /// Invoked when the user presses the OK button.
    ///
    /// Processes selected rows through the executor.
    pub fn ok_callback(&mut self) {
        let executor = match &self.executor {
            Some(e) => Arc::clone(e),
            None => return,
        };

        let selected_addrs: Vec<Address> = self
            .selected_rows
            .iter()
            .filter_map(|&i| self.model.get_address(i))
            .filter(|a| !self.pending.contains(a))
            .collect();

        if selected_addrs.is_empty() {
            return;
        }

        // Mark as pending.
        for addr in &selected_addrs {
            self.pending.insert(*addr);
        }

        self.clear_selection();
        self.busy = true;
        self.state = DialogState::Busy;

        // Process each row.
        let mut to_remove = Vec::new();
        for (i, addr) in selected_addrs.iter().enumerate() {
            if let Some(row) = self.model.get_row_object(i) {
                if executor.execute(row) {
                    to_remove.push(*addr);
                }
            }
        }

        // Remove completed rows.
        for addr in &to_remove {
            self.model.remove_object(addr);
        }

        // Clear pending.
        for addr in &selected_addrs {
            self.pending.remove(addr);
        }

        self.busy = false;
        self.state = DialogState::Open;
        self.status_text.clear();
    }

    /// Returns the number of rows in the table.
    pub fn row_count(&self) -> usize {
        self.model.row_count()
    }

    /// Sets the status message displayed in the dialog.
    pub fn set_message(&mut self, message: impl Into<String>) {
        self.status_text = message.into();
    }

    /// Returns the current status text.
    pub fn status_text(&self) -> &str {
        &self.status_text
    }

    /// Returns `true` if the dialog is currently busy processing rows.
    pub fn is_busy(&self) -> bool {
        self.busy
    }

    /// Adds a custom column to the table.
    pub fn add_custom_column(
        &mut self,
        column: std::sync::Arc<dyn super::adapter::DynamicTableColumn<String>>,
    ) {
        self.model.add_custom_column(column);
    }

    /// Sets the sort column by index.
    pub fn set_sort_column(&mut self, index: usize) {
        self.model.set_sort_column(index);
        self.model.sort();
    }

    /// Sets the sort state.
    pub fn set_sort_state(&mut self, state: &TableSortState) {
        self.model.set_sort_column(state.primary_column());
        self.model.set_sort_descending(state.is_primary_descending());
        self.model.sort();
    }

    /// Returns a reference to the underlying table model.
    pub fn model(&self) -> &TableChooserTableModel<SimpleRowObject> {
        &self.model
    }

    /// Returns a mutable reference to the underlying table model.
    pub fn model_mut(&mut self) -> &mut TableChooserTableModel<SimpleRowObject> {
        &mut self.model
    }

    /// Returns the set of addresses currently being processed.
    pub fn pending(&self) -> &HashSet<Address> {
        &self.pending
    }

    /// Disposes the dialog and releases resources.
    pub fn dispose(&mut self) {
        self.state = DialogState::Closed;
        self.model.clear();
        self.pending.clear();
        self.selected_rows.clear();
    }
}

// ---------------------------------------------------------------------------
// TableServiceTableChooserDialog
// ---------------------------------------------------------------------------

/// A [`TableChooserDialog`] that is managed by a `TableServicePlugin`.
///
/// This is the Rust equivalent of
/// `ghidra.app.plugin.core.table.TableServiceTableChooserDialog`.
/// When this dialog is closed, it notifies the owning plugin so
/// the plugin can remove the dialog from its managed set.
pub struct TableServiceTableChooserDialog {
    /// The inner dialog.
    inner: TableChooserDialog,
    /// Identifier of the owning plugin.
    plugin_id: String,
    /// Callback to notify the plugin that this dialog was closed.
    plugin_removal_callback: Option<Box<dyn Fn() + Send + Sync>>,
}

impl TableServiceTableChooserDialog {
    /// Creates a new `TableServiceTableChooserDialog`.
    ///
    /// # Parameters
    ///
    /// * `plugin_id` -- identifier of the owning plugin.
    /// * `title` -- the dialog title.
    /// * `executor` -- optional executor for processing selected rows.
    /// * `program_name` -- optional program name for display.
    /// * `is_modal` -- whether the dialog is modal.
    pub fn new(
        plugin_id: impl Into<String>,
        title: impl Into<String>,
        executor: Option<Arc<dyn TableChooserExecutor>>,
        program_name: Option<String>,
        is_modal: bool,
    ) -> Self {
        Self {
            inner: TableChooserDialog::new(title, executor, program_name, is_modal),
            plugin_id: plugin_id.into(),
            plugin_removal_callback: None,
        }
    }

    /// Sets the callback that notifies the plugin when this dialog closes.
    pub fn set_plugin_removal_callback(&mut self, cb: impl Fn() + Send + Sync + 'static) {
        self.plugin_removal_callback = Some(Box::new(cb));
    }

    /// Returns the owning plugin ID.
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    /// Closes the dialog and notifies the owning plugin.
    pub fn close(&mut self) {
        self.inner.close();
        if let Some(cb) = &self.plugin_removal_callback {
            cb();
        }
    }

    /// Returns a reference to the inner dialog.
    pub fn inner(&self) -> &TableChooserDialog {
        &self.inner
    }

    /// Returns a mutable reference to the inner dialog.
    pub fn inner_mut(&mut self) -> &mut TableChooserDialog {
        &mut self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;

    #[test]
    fn test_dialog_lifecycle() {
        let mut dialog = TableChooserDialog::new("Test Dialog", None, None, false);
        assert_eq!(dialog.state(), DialogState::Initializing);

        dialog.show();
        assert_eq!(dialog.state(), DialogState::Open);

        dialog.close();
        assert_eq!(dialog.state(), DialogState::Closed);
    }

    #[test]
    fn test_dialog_add_remove() {
        let mut dialog = TableChooserDialog::new("Test", None, None, false);
        dialog.show();

        dialog.add(SimpleRowObject::new(Address::new(0x1000)));
        dialog.add(SimpleRowObject::new(Address::new(0x2000)));
        assert_eq!(dialog.row_count(), 2);

        assert!(dialog.contains(&Address::new(0x1000)));
        dialog.remove(&Address::new(0x1000));
        assert_eq!(dialog.row_count(), 1);
        assert!(!dialog.contains(&Address::new(0x1000)));
    }

    #[test]
    fn test_dialog_selection() {
        let mut dialog = TableChooserDialog::new("Test", None, None, false);
        dialog.show();

        dialog.add(SimpleRowObject::new(Address::new(0x1000)));
        dialog.add(SimpleRowObject::new(Address::new(0x2000)));
        dialog.add(SimpleRowObject::new(Address::new(0x3000)));

        dialog.set_selected_rows(vec![0, 2]);
        assert_eq!(dialog.selected_rows().len(), 2);
        assert!(dialog.is_ok_enabled());

        dialog.clear_selection();
        assert!(dialog.selected_rows().is_empty());
        assert!(!dialog.is_ok_enabled());
    }

    #[test]
    fn test_dialog_with_executor() {
        struct TestExecutor;
        impl TableChooserExecutor for TestExecutor {
            fn button_name(&self) -> &str {
                "Execute"
            }
            fn execute(&self, _row: &dyn AddressableRowObject) -> bool {
                true // remove all
            }
        }

        let mut dialog = TableChooserDialog::new(
            "Test",
            Some(Arc::new(TestExecutor)),
            Some("test.exe".into()),
            false,
        );
        dialog.show();

        dialog.add(SimpleRowObject::new(Address::new(0x1000)));
        dialog.add(SimpleRowObject::new(Address::new(0x2000)));
        dialog.set_selected_rows(vec![0, 1]);

        assert_eq!(dialog.button_name(), Some("Execute"));

        dialog.ok_callback();
        assert_eq!(dialog.row_count(), 0); // All removed by executor
    }

    #[test]
    fn test_dialog_closed_callback() {
        let closed = Arc::new(RwLock::new(false));
        let closed_clone = Arc::clone(&closed);

        let mut dialog = TableChooserDialog::new("Test", None, None, false);
        dialog.set_closed_listener(move || {
            *closed_clone.write().unwrap() = true;
        });

        dialog.show();
        dialog.close();

        assert!(*closed.read().unwrap());
    }

    #[test]
    fn test_service_table_chooser_dialog() {
        let mut dialog = TableServiceTableChooserDialog::new(
            "TableServicePlugin",
            "Test",
            None,
            None,
            false,
        );
        assert_eq!(dialog.plugin_id(), "TableServicePlugin");

        dialog.inner_mut().show();
        assert_eq!(dialog.inner().state(), DialogState::Open);

        dialog.close();
        assert_eq!(dialog.inner().state(), DialogState::Closed);
    }

    #[test]
    fn test_dialog_sort() {
        let mut dialog = TableChooserDialog::new("Test", None, None, false);
        dialog.show();

        dialog.add(SimpleRowObject::new(Address::new(0x3000)));
        dialog.add(SimpleRowObject::new(Address::new(0x1000)));
        dialog.add(SimpleRowObject::new(Address::new(0x2000)));

        dialog.set_sort_column(0);
        assert_eq!(dialog.model().get_address(0), Some(Address::new(0x1000)));
        assert_eq!(dialog.model().get_address(2), Some(Address::new(0x3000)));
    }

    #[test]
    fn test_dialog_status_message() {
        let mut dialog = TableChooserDialog::new("Test", None, None, false);
        dialog.set_message("Processing...");
        assert_eq!(dialog.status_text(), "Processing...");
    }
}
