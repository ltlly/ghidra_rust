//! Table Chooser Plugin -- manages the lifecycle and configuration of
//! a table chooser component within the Ghidra plugin framework.
//!
//! Ported from `TableChooserPlugin.java` in
//! `ghidra.app.plugin.core.tablechooser`.
//!
//! The plugin is responsible for:
//! - Registering the table chooser component provider on program activation.
//! - Managing plugin-level options (e.g. whether to show addresses as
//!   hex or decimal, confirmation before execute).
//! - Coordinating with the [`TableChooserDialog`] to display results
//!   to the user.

use crate::base::tablechooser::{
    Address, AddressableRowObject, ColumnDisplay, TableChooserExecutor, TableChooserTableModel,
};

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
    dialog: Option<TableChooserDialogState>,
    /// The currently loaded program name (if any).
    program_name: Option<String>,
}

/// Internal state tracking for an open dialog.
#[derive(Debug, Clone)]
pub struct TableChooserDialogState {
    /// Title of the dialog.
    pub title: String,
    /// Number of rows currently in the table.
    pub row_count: usize,
    /// Number of columns currently in the table.
    pub column_count: usize,
    /// Whether the dialog is currently visible.
    pub visible: bool,
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

    // -- Dialog management -----------------------------------------------------

    /// Open a new table chooser dialog with the given title.
    ///
    /// Returns a mutable reference to a [`TableChooserDialog`] that the
    /// caller can populate with rows and columns.
    pub fn open_dialog(&mut self, title: impl Into<String>) -> &mut TableChooserDialogState {
        let title_str = title.into();
        let state = TableChooserDialogState {
            title: title_str,
            row_count: 0,
            column_count: 0,
            visible: true,
        };
        self.dialog = Some(state);
        self.dialog.as_mut().unwrap()
    }

    /// Close the current dialog, if any.
    pub fn close_dialog(&mut self) {
        if let Some(ref mut dlg) = self.dialog {
            dlg.visible = false;
        }
        self.dialog = None;
    }

    /// Get the current dialog state, if open.
    pub fn dialog_state(&self) -> Option<&TableChooserDialogState> {
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
}

impl Default for TableChooserPluginOptions {
    fn default() -> Self {
        Self {
            hex_display: true,
            confirm_execute: true,
            default_column_width: 100,
            max_row_warning_threshold: 10_000,
        }
    }
}

impl TableChooserPluginOptions {
    /// Create options with default values.
    pub fn new() -> Self {
        Self::default()
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
    fn test_plugin_program_lifecycle() {
        let mut plugin = TableChooserPlugin::new("P");
        assert!(plugin.program_name().is_none());

        plugin.program_opened("test.exe");
        assert_eq!(plugin.program_name(), Some("test.exe"));

        plugin.program_closed();
        assert!(plugin.program_name().is_none());
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
    }

    #[test]
    fn test_dialog_state_clone() {
        let state = TableChooserDialogState {
            title: "Test".into(),
            row_count: 10,
            column_count: 3,
            visible: true,
        };
        let cloned = state.clone();
        assert_eq!(cloned.title, "Test");
        assert_eq!(cloned.row_count, 10);
        assert_eq!(cloned.column_count, 3);
        assert!(cloned.visible);
    }
}
