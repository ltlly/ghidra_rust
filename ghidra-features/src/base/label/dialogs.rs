//! Label dialogs and additional action types.
//!
//! Ported from Ghidra's label plugin dialogs and actions:
//! - [`EditExternalLabelAction`] -- edit labels on external symbols
//! - [`LabelHistoryInputDialog`] -- dialog for adding history comments
//! - [`LabelHistoryPanel`] -- panel that displays label history
//! - [`LabelHistoryTask`] -- background task that queries label history
//! - [`SymbolChooserDialog`] -- dialog for selecting symbols/labels

use std::collections::HashMap;

use ghidra_core::addr::Address;

use super::history::{LabelHistoryAction, LabelHistoryEntry, LabelHistoryTableModel};

// ---------------------------------------------------------------------------
// EditExternalLabelAction
// ---------------------------------------------------------------------------

/// Action for editing labels on external symbols.
///
/// Ported from Ghidra's `EditExternalLabelAction`. This action is enabled
/// when the user right-clicks on an external symbol in the listing or
/// symbol tree, and allows editing the label's name and source type.
///
/// # Example
///
/// ```
/// use ghidra_features::base::label::EditExternalLabelAction;
///
/// let action = EditExternalLabelAction::new("my_external_func");
/// assert_eq!(action.current_name(), "my_external_func");
/// assert!(!action.is_enabled_for(None));
/// ```
#[derive(Debug, Clone)]
pub struct EditExternalLabelAction {
    /// The current external label name.
    current_name: String,
    /// The source address.
    address: Option<Address>,
    /// Whether the action is currently enabled.
    enabled: bool,
}

impl EditExternalLabelAction {
    /// Creates a new action with the given external label name.
    pub fn new(current_name: impl Into<String>) -> Self {
        Self {
            current_name: current_name.into(),
            address: None,
            enabled: false,
        }
    }

    /// Creates the action configured for a specific address.
    pub fn with_address(mut self, address: Address) -> Self {
        self.address = Some(address);
        self.enabled = true;
        self
    }

    /// Returns the current label name.
    pub fn current_name(&self) -> &str {
        &self.current_name
    }

    /// Returns the address, if set.
    pub fn address(&self) -> Option<Address> {
        self.address
    }

    /// Returns whether the action is enabled for the given context.
    pub fn is_enabled_for(&self, address: Option<Address>) -> bool {
        address.is_some()
    }

    /// Performs the rename action.
    ///
    /// Returns the new name if the action succeeded.
    pub fn execute(&mut self, new_name: impl Into<String>) -> String {
        let name = new_name.into();
        let old = self.current_name.clone();
        self.current_name = name;
        old
    }
}

// ---------------------------------------------------------------------------
// LabelHistoryInputDialog
// ---------------------------------------------------------------------------

/// Dialog for entering a comment to accompany a label history entry.
///
/// Ported from Ghidra's `LabelHistoryInputDialog`. Shown when a user
/// wants to add a descriptive comment to a label change.
///
/// # Example
///
/// ```
/// use ghidra_features::base::label::LabelHistoryInputDialog;
///
/// let dialog = LabelHistoryInputDialog::new("Add Label", "my_label");
/// assert_eq!(dialog.title(), "Add Label");
/// assert_eq!(dialog.label_name(), "my_label");
/// ```
#[derive(Debug, Clone)]
pub struct LabelHistoryInputDialog {
    /// The dialog title.
    title: String,
    /// The label being modified.
    label_name: String,
    /// The user-entered comment.
    comment: String,
    /// Whether the dialog was confirmed.
    confirmed: bool,
}

impl LabelHistoryInputDialog {
    /// Creates a new history input dialog.
    pub fn new(title: impl Into<String>, label_name: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            label_name: label_name.into(),
            comment: String::new(),
            confirmed: false,
        }
    }

    /// Returns the dialog title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the label name being modified.
    pub fn label_name(&self) -> &str {
        &self.label_name
    }

    /// Sets the comment text.
    pub fn set_comment(&mut self, comment: impl Into<String>) {
        self.comment = comment.into();
    }

    /// Returns the entered comment.
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Confirms the dialog (simulates pressing OK).
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }

    /// Cancels the dialog.
    pub fn cancel(&mut self) {
        self.confirmed = false;
        self.comment.clear();
    }

    /// Returns whether the dialog was confirmed.
    pub fn is_confirmed(&self) -> bool {
        self.confirmed
    }
}

// ---------------------------------------------------------------------------
// LabelHistoryPanel
// ---------------------------------------------------------------------------

/// Panel that displays label history for an address or all addresses.
///
/// Ported from Ghidra's `LabelHistoryPanel`. This panel shows a table
/// of all label changes at the selected address, or across the entire
/// program.
///
/// # Example
///
/// ```
/// use ghidra_features::base::label::{LabelHistoryPanel, LabelHistoryEntry, LabelHistoryAction};
/// use ghidra_features::base::analyzer::core::Address;
///
/// let mut panel = LabelHistoryPanel::new();
/// panel.set_entries(vec![
///     LabelHistoryEntry {
///         address: Address::new(0x1000),
///         action: LabelHistoryAction::Add,
///         label: "main".to_string(),
///         user: "user".to_string(),
///         date: "2024-01-01".to_string(),
///     },
/// ]);
/// assert_eq!(panel.entry_count(), 1);
/// ```
pub struct LabelHistoryPanel {
    /// The history entries being displayed.
    entries: Vec<LabelHistoryEntry>,
    /// Whether to show the address column (false = single address mode).
    show_address_column: bool,
    /// Whether showing all addresses or a specific one.
    show_all: bool,
    /// The currently focused address, if any.
    focused_address: Option<Address>,
}

impl LabelHistoryPanel {
    /// Creates a new empty history panel.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            show_address_column: true,
            show_all: false,
            focused_address: None,
        }
    }

    /// Creates a panel showing history for a specific address.
    pub fn for_address(address: Address) -> Self {
        Self {
            entries: Vec::new(),
            show_address_column: false,
            show_all: false,
            focused_address: Some(address),
        }
    }

    /// Creates a panel showing all history.
    pub fn show_all() -> Self {
        Self {
            entries: Vec::new(),
            show_address_column: true,
            show_all: true,
            focused_address: None,
        }
    }

    /// Sets the entries to display.
    pub fn set_entries(&mut self, entries: Vec<LabelHistoryEntry>) {
        self.entries = entries;
    }

    /// Returns the number of entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns a reference to the entries.
    pub fn entries(&self) -> &[LabelHistoryEntry] {
        &self.entries
    }

    /// Creates a LabelHistoryTableModel from the current entries.
    pub fn table_model(&self) -> LabelHistoryTableModel {
        LabelHistoryTableModel::new(self.entries.clone(), self.show_address_column)
    }

    /// Returns whether the panel is showing all addresses.
    pub fn is_show_all(&self) -> bool {
        self.show_all
    }

    /// Returns the focused address, if any.
    pub fn focused_address(&self) -> Option<Address> {
        self.focused_address
    }

    /// Sets the focused address.
    pub fn set_focused_address(&mut self, address: Option<Address>) {
        self.focused_address = address;
    }
}

impl Default for LabelHistoryPanel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// LabelHistoryTask
// ---------------------------------------------------------------------------

/// Background task that queries label history for a program.
///
/// Ported from Ghidra's `LabelHistoryTask`. This task runs in the
/// background to gather label history entries, which can be displayed
/// in the [`LabelHistoryPanel`].
///
/// # Example
///
/// ```
/// use ghidra_features::base::label::LabelHistoryTask;
/// use ghidra_features::base::analyzer::core::Address;
///
/// let task = LabelHistoryTask::for_address(Address::new(0x1000));
/// assert_eq!(task.task_name(), "Label History");
/// assert_eq!(task.address(), Some(Address::new(0x1000)));
/// ```
#[derive(Debug, Clone)]
pub struct LabelHistoryTask {
    /// The task name.
    task_name: String,
    /// The address to query history for, if any.
    address: Option<Address>,
    /// Whether this is a "show all" task.
    show_all: bool,
    /// Accumulated results.
    results: Vec<LabelHistoryEntry>,
    /// Whether the task completed.
    completed: bool,
}

impl LabelHistoryTask {
    /// Creates a task to show history for a specific address.
    pub fn for_address(address: Address) -> Self {
        Self {
            task_name: "Label History".to_string(),
            address: Some(address),
            show_all: false,
            results: Vec::new(),
            completed: false,
        }
    }

    /// Creates a task to show all label history.
    pub fn for_all() -> Self {
        Self {
            task_name: "All Label History".to_string(),
            address: None,
            show_all: true,
            results: Vec::new(),
            completed: false,
        }
    }

    /// Returns the task name.
    pub fn task_name(&self) -> &str {
        &self.task_name
    }

    /// Returns the address to query, if any.
    pub fn address(&self) -> Option<Address> {
        self.address
    }

    /// Returns whether this is a "show all" task.
    pub fn is_show_all(&self) -> bool {
        self.show_all
    }

    /// Returns the results.
    pub fn results(&self) -> &[LabelHistoryEntry] {
        &self.results
    }

    /// Sets the results (simulates task completion).
    pub fn set_results(&mut self, results: Vec<LabelHistoryEntry>) {
        self.results = results;
        self.completed = true;
    }

    /// Returns whether the task completed.
    pub fn is_completed(&self) -> bool {
        self.completed
    }
}

// ---------------------------------------------------------------------------
// SymbolChooserDialog
// ---------------------------------------------------------------------------

/// Dialog for selecting a symbol/label from the program's symbol table.
///
/// Ported from Ghidra's `SymbolChooserDialog`. Allows the user to browse
/// and select symbols, with filtering by type, namespace, and name.
///
/// # Example
///
/// ```
/// use ghidra_features::base::label::SymbolChooserDialog;
///
/// let dialog = SymbolChooserDialog::new("Select Label");
/// assert_eq!(dialog.title(), "Select Label");
/// assert!(dialog.selected_symbol().is_none());
/// ```
#[derive(Debug, Clone)]
pub struct SymbolChooserDialog {
    /// The dialog title.
    title: String,
    /// The selected symbol name, if any.
    selected: Option<String>,
    /// Filter text for symbol name.
    filter_text: String,
    /// Whether to show external symbols.
    show_externals: bool,
    /// Whether to show only functions.
    functions_only: bool,
    /// Whether the dialog was confirmed.
    confirmed: bool,
}

impl SymbolChooserDialog {
    /// Creates a new symbol chooser dialog.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            selected: None,
            filter_text: String::new(),
            show_externals: true,
            functions_only: false,
            confirmed: false,
        }
    }

    /// Returns the dialog title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Sets the filter text.
    pub fn set_filter_text(&mut self, text: impl Into<String>) {
        self.filter_text = text.into();
    }

    /// Returns the filter text.
    pub fn filter_text(&self) -> &str {
        &self.filter_text
    }

    /// Sets whether to show external symbols.
    pub fn set_show_externals(&mut self, show: bool) {
        self.show_externals = show;
    }

    /// Returns whether external symbols are shown.
    pub fn show_externals(&self) -> bool {
        self.show_externals
    }

    /// Sets whether to show only functions.
    pub fn set_functions_only(&mut self, only: bool) {
        self.functions_only = only;
    }

    /// Returns whether only functions are shown.
    pub fn functions_only(&self) -> bool {
        self.functions_only
    }

    /// Selects a symbol by name.
    pub fn select(&mut self, name: impl Into<String>) {
        self.selected = Some(name.into());
    }

    /// Returns the selected symbol name, if any.
    pub fn selected_symbol(&self) -> Option<&str> {
        self.selected.as_deref()
    }

    /// Confirms the dialog.
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }

    /// Cancels the dialog.
    pub fn cancel(&mut self) {
        self.confirmed = false;
        self.selected = None;
    }

    /// Returns whether the dialog was confirmed.
    pub fn is_confirmed(&self) -> bool {
        self.confirmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::history::LabelHistoryTableModel;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    #[test]
    fn test_edit_external_label_action() {
        let mut action = EditExternalLabelAction::new("old_name");
        assert_eq!(action.current_name(), "old_name");
        assert!(action.address().is_none());
        assert!(!action.is_enabled_for(None));
        assert!(action.is_enabled_for(Some(addr(0x1000))));

        let old = action.execute("new_name");
        assert_eq!(old, "old_name");
        assert_eq!(action.current_name(), "new_name");
    }

    #[test]
    fn test_edit_external_label_with_address() {
        let action = EditExternalLabelAction::new("func").with_address(addr(0x2000));
        assert_eq!(action.address(), Some(addr(0x2000)));
        assert!(action.enabled);
    }

    #[test]
    fn test_label_history_input_dialog() {
        let mut dialog = LabelHistoryInputDialog::new("Add Label", "my_label");
        assert_eq!(dialog.title(), "Add Label");
        assert_eq!(dialog.label_name(), "my_label");
        assert!(!dialog.is_confirmed());
        assert!(dialog.comment().is_empty());

        dialog.set_comment("This is a test");
        dialog.confirm();
        assert!(dialog.is_confirmed());
        assert_eq!(dialog.comment(), "This is a test");

        dialog.cancel();
        assert!(!dialog.is_confirmed());
        assert!(dialog.comment().is_empty());
    }

    #[test]
    fn test_label_history_panel() {
        let mut panel = LabelHistoryPanel::new();
        assert_eq!(panel.entry_count(), 0);
        assert!(!panel.is_show_all());
        assert!(panel.focused_address().is_none());

        let entry = LabelHistoryEntry {
            address: addr(0x1000),
            action: LabelHistoryAction::Add,
            label: "main".to_string(),
            user: "user".to_string(),
            date: "2024-01-01".to_string(),
        };
        panel.set_entries(vec![entry]);
        assert_eq!(panel.entry_count(), 1);
    }

    #[test]
    fn test_label_history_panel_for_address() {
        let panel = LabelHistoryPanel::for_address(addr(0x4000));
        assert_eq!(panel.focused_address(), Some(addr(0x4000)));
        assert!(!panel.is_show_all());
    }

    #[test]
    fn test_label_history_panel_show_all() {
        let panel = LabelHistoryPanel::show_all();
        assert!(panel.is_show_all());
        assert!(panel.focused_address().is_none());
    }

    #[test]
    fn test_label_history_panel_set_focused() {
        let mut panel = LabelHistoryPanel::new();
        assert!(panel.focused_address().is_none());
        panel.set_focused_address(Some(addr(0x1000)));
        assert_eq!(panel.focused_address(), Some(addr(0x1000)));
    }

    #[test]
    fn test_label_history_task_for_address() {
        let task = LabelHistoryTask::for_address(addr(0x1000));
        assert_eq!(task.task_name(), "Label History");
        assert_eq!(task.address(), Some(addr(0x1000)));
        assert!(!task.is_show_all());
        assert!(!task.is_completed());
        assert!(task.results().is_empty());
    }

    #[test]
    fn test_label_history_task_for_all() {
        let task = LabelHistoryTask::for_all();
        assert_eq!(task.task_name(), "All Label History");
        assert!(task.address().is_none());
        assert!(task.is_show_all());
    }

    #[test]
    fn test_label_history_task_set_results() {
        let mut task = LabelHistoryTask::for_address(addr(0x1000));
        let entries = vec![
            LabelHistoryEntry {
                address: addr(0x1000),
                action: LabelHistoryAction::Add,
                label: "main".to_string(),
                user: "user1".to_string(),
                date: "2024-01-01".to_string(),
            },
            LabelHistoryEntry {
                address: addr(0x1000),
                action: LabelHistoryAction::Rename,
                label: "main_entry".to_string(),
                user: "user2".to_string(),
                date: "2024-01-02".to_string(),
            },
        ];
        task.set_results(entries);
        assert!(task.is_completed());
        assert_eq!(task.results().len(), 2);
    }

    #[test]
    fn test_symbol_chooser_dialog() {
        let mut dialog = SymbolChooserDialog::new("Select Label");
        assert_eq!(dialog.title(), "Select Label");
        assert!(dialog.selected_symbol().is_none());
        assert!(dialog.show_externals());
        assert!(!dialog.functions_only());
        assert!(!dialog.is_confirmed());

        dialog.set_filter_text("main*");
        assert_eq!(dialog.filter_text(), "main*");

        dialog.set_functions_only(true);
        assert!(dialog.functions_only());

        dialog.set_show_externals(false);
        assert!(!dialog.show_externals());

        dialog.select("my_function");
        assert_eq!(dialog.selected_symbol(), Some("my_function"));

        dialog.confirm();
        assert!(dialog.is_confirmed());
        assert_eq!(dialog.selected_symbol(), Some("my_function"));

        dialog.cancel();
        assert!(!dialog.is_confirmed());
        assert!(dialog.selected_symbol().is_none());
    }

    #[test]
    fn test_symbol_chooser_select_and_confirm() {
        let mut dialog = SymbolChooserDialog::new("Pick");
        dialog.select("target_func");
        dialog.confirm();
        assert_eq!(dialog.selected_symbol(), Some("target_func"));
    }
}
