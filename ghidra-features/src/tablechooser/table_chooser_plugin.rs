//! Table Chooser Plugin -- manages the lifecycle and configuration of
//! a table chooser component within the Ghidra plugin framework.
//!
//! Ported from `TableChooserPlugin.java` in
//! `ghidra.app.plugin.core.tablechooser` and
//! `ghidra.app.plugin`.
//!
//! The plugin is responsible for:
//! - Registering the table chooser component provider on program activation.
//! - Managing plugin-level options (e.g. whether to show addresses as
//!   hex or decimal, confirmation before execute).
//! - Coordinating with the [`TableChooserDialogState`] to display
//!   results to the user.
//! - Creating configured dialog instances with columns and executors.

use crate::base::tablechooser::{
    Address, AddressableRowObject, ColumnDisplay, TableChooserExecutor, TableChooserTableModel,
};
use crate::tablechooser::table_chooser_dialog::{ColumnConfig, TableChooserDialogState};

// ---------------------------------------------------------------------------
// TableChooserPlugin
// ---------------------------------------------------------------------------

/// The main plugin that hosts a table chooser dialog.
///
/// Ported from `TableChooserPlugin.java`. In the Java original this
/// extends `ProgramPlugin` and manages a `TableChooserDialogComponentProvider`.
/// In Rust we model the lifecycle and configuration without a GUI toolkit.
#[derive(Debug)]
pub struct TableChooserPlugin {
    /// Plugin name.
    name: String,
    /// Whether addresses are displayed in hexadecimal (true) or decimal (false).
    hex_address_display: bool,
    /// Whether to prompt the user for confirmation before executing an action.
    confirm_before_execute: bool,
    /// The currently active table chooser dialog, if any.
    dialog: Option<TableChooserDialogStateWrapper>,
    /// The currently loaded program name (if any).
    program_name: Option<String>,
    /// Aggregated plugin options.
    options: TableChooserPluginOptions,
}

/// Internal wrapper for the dialog state (type-erased for storage in the plugin).
#[derive(Debug, Clone)]
pub struct TableChooserDialogStateWrapper {
    /// Title of the dialog.
    pub title: String,
    /// Number of rows currently in the table.
    pub row_count: usize,
    /// Number of columns currently in the table.
    pub column_count: usize,
    /// Whether the dialog is currently visible.
    pub visible: bool,
    /// Whether the dialog is currently busy processing.
    pub busy: bool,
}

impl TableChooserPlugin {
    /// Create a new plugin with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            hex_address_display: true,
            confirm_before_execute: true,
            dialog: None,
            program_name: None,
            options: TableChooserPluginOptions::default(),
        }
    }

    /// Create a new plugin with custom options.
    pub fn with_options(name: impl Into<String>, options: TableChooserPluginOptions) -> Self {
        let hex = options.hex_display;
        let confirm = options.confirm_execute;
        Self {
            name: name.into(),
            hex_address_display: hex,
            confirm_before_execute: confirm,
            dialog: None,
            program_name: None,
            options,
        }
    }

    /// Plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    // -- Options ---------------------------------------------------------------

    /// Whether addresses are displayed in hexadecimal.
    pub fn hex_address_display(&self) -> bool {
        self.hex_address_display
    }

    /// Set whether addresses should be displayed in hexadecimal.
    pub fn set_hex_address_display(&mut self, value: bool) {
        self.hex_address_display = value;
    }

    /// Whether the user is prompted for confirmation before executing.
    pub fn confirm_before_execute(&self) -> bool {
        self.confirm_before_execute
    }

    /// Set whether to prompt for confirmation before executing.
    pub fn set_confirm_before_execute(&mut self, value: bool) {
        self.confirm_before_execute = value;
    }

    /// Get a reference to the plugin options.
    pub fn options(&self) -> &TableChooserPluginOptions {
        &self.options
    }

    /// Get a mutable reference to the plugin options.
    pub fn options_mut(&mut self) -> &mut TableChooserPluginOptions {
        &mut self.options
    }

    /// Update plugin options from an options struct.
    pub fn apply_options(&mut self, options: TableChooserPluginOptions) {
        self.hex_address_display = options.hex_display;
        self.confirm_before_execute = options.confirm_execute;
        self.options = options;
    }

    // -- Program lifecycle -----------------------------------------------------

    /// Called when a program is opened/activated.
    ///
    /// In the Java original this is handled by `programActivated()`.
    pub fn program_opened(&mut self, program_name: impl Into<String>) {
        self.program_name = Some(program_name.into());
    }

    /// Called when the current program is closed.
    ///
    /// In the Java original this is handled by `programClosed()`.
    pub fn program_closed(&mut self) {
        self.program_name = None;
        // Close any open dialog when the program goes away.
        self.dialog = None;
    }

    /// The name of the currently loaded program, if any.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    /// Whether a program is currently loaded.
    pub fn is_program_loaded(&self) -> bool {
        self.program_name.is_some()
    }

    // -- Dialog management -----------------------------------------------------

    /// Open a new table chooser dialog with the given title.
    ///
    /// Returns a mutable reference to a [`TableChooserDialogStateWrapper`]
    /// tracking the dialog state.
    pub fn open_dialog(&mut self, title: impl Into<String>) -> &mut TableChooserDialogStateWrapper {
        let title_str = title.into();
        let state = TableChooserDialogStateWrapper {
            title: title_str,
            row_count: 0,
            column_count: 0,
            visible: true,
            busy: false,
        };
        self.dialog = Some(state);
        self.dialog.as_mut().unwrap()
    }

    /// Create a fully configured `TableChooserDialogState` for the given
    /// row type, applying the plugin's current options.
    ///
    /// This is the factory method that mirrors the Java plugin's
    /// `createDialog` / dialog construction pattern.
    pub fn create_dialog<T: AddressableRowObject + Clone>(
        &self,
        title: impl Into<String>,
    ) -> TableChooserDialogState<T> {
        let mut dialog = TableChooserDialogState::new(title);
        dialog.set_confirm_execute(self.confirm_before_execute);
        dialog
    }

    /// Create a configured dialog with an executor.
    pub fn create_dialog_with_executor<T: AddressableRowObject + Clone>(
        &self,
        title: impl Into<String>,
        executor: Box<dyn TableChooserExecutor<T>>,
    ) -> TableChooserDialogState<T> {
        let mut dialog = self.create_dialog(title);
        dialog.set_executor(executor);
        dialog
    }

    /// Close the current dialog, if any.
    pub fn close_dialog(&mut self) {
        if let Some(ref mut dlg) = self.dialog {
            dlg.visible = false;
        }
        self.dialog = None;
    }

    /// Get the current dialog state, if open.
    pub fn dialog_state(&self) -> Option<&TableChooserDialogStateWrapper> {
        self.dialog.as_ref()
    }

    /// Whether a dialog is currently open and visible.
    pub fn is_dialog_open(&self) -> bool {
        self.dialog.as_ref().map_or(false, |d| d.visible)
    }

    /// Update the row count on the current dialog state.
    pub fn update_dialog_row_count(&mut self, count: usize) {
        if let Some(ref mut dlg) = self.dialog {
            dlg.row_count = count;
        }
    }

    /// Update the column count on the current dialog state.
    pub fn update_dialog_column_count(&mut self, count: usize) {
        if let Some(ref mut dlg) = self.dialog {
            dlg.column_count = count;
        }
    }

    /// Set the busy state on the current dialog.
    pub fn set_dialog_busy(&mut self, busy: bool) {
        if let Some(ref mut dlg) = self.dialog {
            dlg.busy = busy;
        }
    }

    /// Whether the current dialog is busy.
    pub fn is_dialog_busy(&self) -> bool {
        self.dialog.as_ref().map_or(false, |d| d.busy)
    }

    // -- Plugin lifecycle (dispose) --------------------------------------------

    /// Dispose of the plugin, closing any open dialog.
    ///
    /// Mirrors `Plugin.dispose()`.
    pub fn dispose(&mut self) {
        self.dialog = None;
        self.program_name = None;
    }
}

// ---------------------------------------------------------------------------
// TableChooserPluginOptions
// ---------------------------------------------------------------------------

/// Aggregated options for the table chooser plugin.
///
/// Mirrors the Ghidra `Options` service entries that the Java plugin
/// registers under the "Table Chooser" category.
#[derive(Debug, Clone)]
pub struct TableChooserPluginOptions {
    /// Display addresses in hex.
    pub hex_display: bool,
    /// Prompt before executing action.
    pub confirm_execute: bool,
    /// Default column width in pixels.
    pub default_column_width: usize,
    /// Maximum number of rows before showing a warning.
    pub max_row_warning_threshold: usize,
    /// Whether to show a confirmation dialog for large selections.
    pub confirm_large_selection: bool,
    /// Threshold for large selection warning.
    pub large_selection_threshold: usize,
}

impl Default for TableChooserPluginOptions {
    fn default() -> Self {
        Self {
            hex_display: true,
            confirm_execute: true,
            default_column_width: 100,
            max_row_warning_threshold: 10_000,
            confirm_large_selection: true,
            large_selection_threshold: 100,
        }
    }
}

impl TableChooserPluginOptions {
    /// Create options with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create options for a headless/non-interactive context.
    pub fn headless() -> Self {
        Self {
            hex_display: true,
            confirm_execute: false,
            default_column_width: 100,
            max_row_warning_threshold: usize::MAX,
            confirm_large_selection: false,
            large_selection_threshold: usize::MAX,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_new() {
        let plugin = TableChooserPlugin::new("TableChooserPlugin");
        assert_eq!(plugin.name(), "TableChooserPlugin");
        assert!(plugin.hex_address_display());
        assert!(plugin.confirm_before_execute());
        assert!(plugin.program_name().is_none());
        assert!(!plugin.is_dialog_open());
        assert!(!plugin.is_program_loaded());
    }

    #[test]
    fn test_plugin_with_options() {
        let opts = TableChooserPluginOptions::headless();
        let plugin = TableChooserPlugin::with_options("P", opts);
        assert!(!plugin.confirm_before_execute());
        assert_eq!(plugin.options().max_row_warning_threshold, usize::MAX);
    }

    #[test]
    fn test_plugin_options() {
        let mut plugin = TableChooserPlugin::new("P");
        plugin.set_hex_address_display(false);
        assert!(!plugin.hex_address_display());
        plugin.set_confirm_before_execute(false);
        assert!(!plugin.confirm_before_execute());
    }

    #[test]
    fn test_plugin_apply_options() {
        let mut plugin = TableChooserPlugin::new("P");
        let opts = TableChooserPluginOptions {
            hex_display: false,
            confirm_execute: false,
            default_column_width: 200,
            max_row_warning_threshold: 5000,
            confirm_large_selection: false,
            large_selection_threshold: 50,
        };
        plugin.apply_options(opts);
        assert!(!plugin.hex_address_display());
        assert!(!plugin.confirm_before_execute());
        assert_eq!(plugin.options().default_column_width, 200);
    }

    #[test]
    fn test_plugin_program_lifecycle() {
        let mut plugin = TableChooserPlugin::new("P");
        assert!(plugin.program_name().is_none());
        assert!(!plugin.is_program_loaded());

        plugin.program_opened("test.exe");
        assert_eq!(plugin.program_name(), Some("test.exe"));
        assert!(plugin.is_program_loaded());

        plugin.program_closed();
        assert!(plugin.program_name().is_none());
        assert!(!plugin.is_program_loaded());
    }

    #[test]
    fn test_plugin_open_close_dialog() {
        let mut plugin = TableChooserPlugin::new("P");
        assert!(!plugin.is_dialog_open());

        {
            let state = plugin.open_dialog("Choose Items");
            assert_eq!(state.title, "Choose Items");
            assert!(state.visible);
        }
        assert!(plugin.is_dialog_open());

        plugin.close_dialog();
        assert!(!plugin.is_dialog_open());
        assert!(plugin.dialog_state().is_none());
    }

    #[test]
    fn test_plugin_dialog_update_counts() {
        let mut plugin = TableChooserPlugin::new("P");
        plugin.open_dialog("Test");

        plugin.update_dialog_row_count(42);
        plugin.update_dialog_column_count(5);
        let state = plugin.dialog_state().unwrap();
        assert_eq!(state.row_count, 42);
        assert_eq!(state.column_count, 5);
    }

    #[test]
    fn test_plugin_dialog_busy() {
        let mut plugin = TableChooserPlugin::new("P");
        plugin.open_dialog("Test");

        assert!(!plugin.is_dialog_busy());
        plugin.set_dialog_busy(true);
        assert!(plugin.is_dialog_busy());
        plugin.set_dialog_busy(false);
        assert!(!plugin.is_dialog_busy());
    }

    #[test]
    fn test_plugin_program_closed_closes_dialog() {
        let mut plugin = TableChooserPlugin::new("P");
        plugin.program_opened("prog");
        plugin.open_dialog("Test");
        assert!(plugin.is_dialog_open());

        plugin.program_closed();
        assert!(!plugin.is_dialog_open());
    }

    #[test]
    fn test_plugin_options_default() {
        let opts = TableChooserPluginOptions::default();
        assert!(opts.hex_display);
        assert!(opts.confirm_execute);
        assert_eq!(opts.default_column_width, 100);
        assert_eq!(opts.max_row_warning_threshold, 10_000);
        assert!(opts.confirm_large_selection);
        assert_eq!(opts.large_selection_threshold, 100);
    }

    #[test]
    fn test_plugin_options_headless() {
        let opts = TableChooserPluginOptions::headless();
        assert!(!opts.confirm_execute);
        assert!(!opts.confirm_large_selection);
        assert_eq!(opts.max_row_warning_threshold, usize::MAX);
    }

    #[test]
    fn test_dialog_state_clone() {
        let state = TableChooserDialogStateWrapper {
            title: "Test".into(),
            row_count: 10,
            column_count: 3,
            visible: true,
            busy: false,
        };
        let cloned = state.clone();
        assert_eq!(cloned.title, "Test");
        assert_eq!(cloned.row_count, 10);
        assert_eq!(cloned.column_count, 3);
        assert!(cloned.visible);
        assert!(!cloned.busy);
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = TableChooserPlugin::new("P");
        plugin.program_opened("prog");
        plugin.open_dialog("Test");
        assert!(plugin.is_dialog_open());
        assert!(plugin.is_program_loaded());

        plugin.dispose();
        assert!(!plugin.is_dialog_open());
        assert!(!plugin.is_program_loaded());
    }

    #[test]
    fn test_plugin_create_dialog() {
        #[derive(Debug, Clone)]
        struct Row {
            addr: u64,
        }
        impl AddressableRowObject for Row {
            fn get_address(&self) -> Address {
                Address(self.addr)
            }
        }

        let plugin = TableChooserPlugin::new("P");
        let dialog = plugin.create_dialog::<Row>("Test Dialog");
        assert_eq!(dialog.title(), "Test Dialog");
        assert!(dialog.confirm_execute());
    }

    #[test]
    fn test_plugin_create_dialog_with_executor() {
        #[derive(Debug, Clone)]
        struct Row {
            addr: u64,
        }
        impl AddressableRowObject for Row {
            fn get_address(&self) -> Address {
                Address(self.addr)
            }
        }

        #[derive(Debug)]
        struct NoopExecutor;
        impl TableChooserExecutor<Row> for NoopExecutor {
            fn get_button_name(&self) -> &str {
                "Run"
            }
            fn execute(&self, _row: &Row) -> bool {
                false
            }
        }

        let mut plugin = TableChooserPlugin::new("P");
        plugin.set_confirm_before_execute(false);

        let dialog = plugin.create_dialog_with_executor("E", Box::new(NoopExecutor));
        assert_eq!(dialog.executor_button_name(), Some("Run"));
        assert!(!dialog.confirm_execute());
    }
}
