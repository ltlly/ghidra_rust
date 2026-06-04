//! Core traits for the Ghidra table management framework.
//!
//! This module provides the Rust analogues of Ghidra's Java interfaces:
//!
//! - [`AddressableRowObject`] -- a table row that is located at a program address.
//! - [`ColumnDisplay`] -- defines a custom column in a table-chooser dialog.
//! - [`TableChooserExecutor`] -- processes selected rows in a table dialog.
//! - [`TableService`] -- creates table views and table-chooser dialogs.

use ghidra_core::addr::Address;

// ---------------------------------------------------------------------------
// AddressableRowObject
// ---------------------------------------------------------------------------

/// A row object in a table that is associated with a program address.
///
/// This is the Rust equivalent of
/// `ghidra.app.tablechooser.AddressableRowObject`.  Any type that
/// implements this trait can appear in a [`TableChooserDialog`].
pub trait AddressableRowObject {
    /// Returns the address associated with this row.
    fn address(&self) -> Address;
}

// ---------------------------------------------------------------------------
// ColumnDisplay
// ---------------------------------------------------------------------------

/// Defines a custom column in a table-chooser dialog.
///
/// This is the Rust equivalent of
/// `ghidra.app.tablechooser.ColumnDisplay<T>`.  Each column display
/// knows its name, how to extract a value from a row, and how to
/// compare two rows for sorting.
///
/// # Type Parameters
///
/// * `T` -- the column value type (e.g., `String`, `u64`, `bool`).
pub trait ColumnDisplay<T: Clone + PartialOrd>: Send + Sync {
    /// Returns the column header name.
    fn column_name(&self) -> &str;

    /// Extracts the column value from a row object.
    fn column_value(&self, row: &dyn AddressableRowObject) -> T;

    /// Compares two row objects by this column's values.
    ///
    /// The default implementation compares by address if the column
    /// values are equal.
    fn compare(&self, a: &dyn AddressableRowObject, b: &dyn AddressableRowObject) -> std::cmp::Ordering {
        let va = self.column_value(a);
        let vb = self.column_value(b);
        va.partial_cmp(&vb).unwrap_or_else(|| a.address().offset.cmp(&b.address().offset))
    }
}

// ---------------------------------------------------------------------------
// TableChooserExecutor
// ---------------------------------------------------------------------------

/// Callback for processing selected rows in a table-chooser dialog.
///
/// This is the Rust equivalent of
/// `ghidra.app.tablechooser.TableChooserExecutor`.  Users implement
/// this trait to define an action that is applied to selected table rows
/// when the "apply" button is pressed.
pub trait TableChooserExecutor: Send + Sync {
    /// Returns the label for the "apply" button (e.g., "Rename", "Delete").
    fn button_name(&self) -> &str;

    /// Executes the action on a single row.
    ///
    /// Returns `true` if the row should be removed from the table after
    /// execution.
    fn execute(&self, row: &dyn AddressableRowObject) -> bool;

    /// Executes the action on all selected rows in bulk.
    ///
    /// Returns `true` if bulk processing was used.  The default
    /// implementation processes each row individually via
    /// [`execute`](TableChooserExecutor::execute).
    fn execute_in_bulk(
        &self,
        rows: &[&dyn AddressableRowObject],
        _deleted: &mut Vec<usize>,
        cancelled: &dyn Fn() -> bool,
    ) -> bool {
        for (i, row) in rows.iter().enumerate() {
            if cancelled() {
                break;
            }
            if self.execute(*row) {
                _deleted.push(i);
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// TableService
// ---------------------------------------------------------------------------

/// Service interface for creating table views and table-chooser dialogs.
///
/// This is the Rust equivalent of
/// `ghidra.app.util.query.TableService`.  Plugins that provide table
/// display functionality implement this trait.
pub trait TableService: Send + Sync {
    /// Creates a table view for the given model.
    ///
    /// # Parameters
    ///
    /// * `title` -- the window title.
    /// * `table_type_name` -- the table type name used for grouping.
    /// * `window_sub_menu` -- optional sub-menu name in the window menu.
    ///
    /// Returns a provider ID that can be used to manage the view.
    fn show_table(
        &self,
        title: &str,
        table_type_name: &str,
        window_sub_menu: Option<&str>,
    ) -> String;

    /// Creates a table view with associated markers.
    ///
    /// # Parameters
    ///
    /// * `title` -- the window title.
    /// * `table_type_name` -- the table type name used for grouping.
    /// * `marker_color` -- RGBA color for markers.
    /// * `window_sub_menu` -- optional sub-menu name in the window menu.
    ///
    /// Returns a provider ID that can be used to manage the view.
    fn show_table_with_markers(
        &self,
        title: &str,
        table_type_name: &str,
        marker_color: (u8, u8, u8, u8),
        window_sub_menu: Option<&str>,
    ) -> String;

    /// Creates a table-chooser dialog.
    ///
    /// # Parameters
    ///
    /// * `title` -- the dialog title.
    /// * `is_modal` -- whether the dialog is modal.
    ///
    /// Returns a dialog ID that can be used to manage the dialog.
    fn create_table_chooser_dialog(
        &self,
        title: &str,
        is_modal: bool,
    ) -> String;
}
