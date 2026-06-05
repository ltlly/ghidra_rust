//! Table chooser dialog framework.
//!
//! Ported from Ghidra's `ghidra.app.tablechooser` Java package. Provides a
//! table-based dialog that lets users browse a set of addressable row
//! objects, optionally apply column-specific sorting, and execute an
//! action on the selected row(s).
//!
//! # Key types
//!
//! - [`AddressableRowObject`] -- trait for rows that have an address
//! - [`ColumnDisplay`] -- trait for defining custom table columns
//! - [`TableChooserDialog`] -- the dialog model
//! - [`TableChooserExecutor`] -- trait for executing actions on selected rows
//! - [`TableChooserTableModel`] -- the backing data model

use std::cmp::Ordering;
use std::fmt;

// ---------------------------------------------------------------------------
// Placeholder types
// ---------------------------------------------------------------------------

/// Placeholder for a Ghidra Program.
#[derive(Debug, Clone)]
pub struct Program {
    pub name: String,
}

/// Placeholder for a program address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Address(pub u64);

impl PartialOrd for Address {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Address {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

// ---------------------------------------------------------------------------
// AddressableRowObject
// ---------------------------------------------------------------------------

/// Trait for row objects that have a program address.
///
/// This is the minimum interface for any row displayed in a
/// `TableChooserDialog`.
pub trait AddressableRowObject: fmt::Debug {
    /// Return the address associated with this row.
    fn get_address(&self) -> Address;
}

// ---------------------------------------------------------------------------
// ColumnDisplay
// ---------------------------------------------------------------------------

/// Trait for defining a custom column in a table chooser dialog.
pub trait ColumnDisplay<T: AddressableRowObject>: fmt::Debug {
    /// The column name / header.
    fn get_column_name(&self) -> &str;

    /// The preferred width of this column in pixels.
    fn get_column_width(&self) -> usize {
        100
    }

    /// Get the display value for a given row.
    fn get_value(&self, row: &T) -> String;

    /// Compare two rows by this column (for sorting).
    fn compare(&self, a: &T, b: &T) -> Ordering {
        self.get_value(a).cmp(&self.get_value(b))
    }
}

// ---------------------------------------------------------------------------
// StringColumnDisplay
// ---------------------------------------------------------------------------

/// A simple string-valued column display.
pub struct StringColumnDisplay<T: AddressableRowObject> {
    name: String,
    extractor: Box<dyn Fn(&T) -> String>,
}

impl<T: AddressableRowObject> fmt::Debug for StringColumnDisplay<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StringColumnDisplay")
            .field("name", &self.name)
            .finish()
    }
}

impl<T: AddressableRowObject> StringColumnDisplay<T> {
    pub fn new(name: impl Into<String>, extractor: Box<dyn Fn(&T) -> String>) -> Self {
        Self {
            name: name.into(),
            extractor,
        }
    }
}

impl<T: AddressableRowObject> ColumnDisplay<T> for StringColumnDisplay<T> {
    fn get_column_name(&self) -> &str {
        &self.name
    }

    fn get_value(&self, row: &T) -> String {
        (self.extractor)(row)
    }
}

// ---------------------------------------------------------------------------
// TableChooserExecutor
// ---------------------------------------------------------------------------

/// Trait for executing an action on selected rows in a table chooser.
pub trait TableChooserExecutor<T: AddressableRowObject>: fmt::Debug {
    /// The button text for the execute action.
    fn get_button_name(&self) -> &str;

    /// Execute the action on a single selected row.
    ///
    /// Returns `true` if the row should be removed from the table after
    /// execution, `false` to keep it.
    fn execute(&self, row: &T) -> bool;
}

// ---------------------------------------------------------------------------
// TableChooserTableModel
// ---------------------------------------------------------------------------

/// The data model for a table chooser dialog.
#[derive(Debug)]
pub struct TableChooserTableModel<T: AddressableRowObject> {
    rows: Vec<T>,
    columns: Vec<Box<dyn ColumnDisplay<T>>>,
}

impl<T: AddressableRowObject + Clone> TableChooserTableModel<T> {
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            columns: Vec::new(),
        }
    }

    /// Add a row to the model.
    pub fn add_row(&mut self, row: T) {
        self.rows.push(row);
    }

    /// Add multiple rows.
    pub fn add_rows(&mut self, rows: impl IntoIterator<Item = T>) {
        self.rows.extend(rows);
    }

    /// Remove a row at the given index.
    pub fn remove_row(&mut self, index: usize) -> Option<T> {
        if index < self.rows.len() {
            Some(self.rows.remove(index))
        } else {
            None
        }
    }

    /// Get the number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Get a reference to a row by index.
    pub fn get_row(&self, index: usize) -> Option<&T> {
        self.rows.get(index)
    }

    /// Get all rows.
    pub fn get_rows(&self) -> &[T] {
        &self.rows
    }

    /// Add a custom column display.
    pub fn add_column(&mut self, column: Box<dyn ColumnDisplay<T>>) {
        self.columns.push(column);
    }

    /// Get the number of columns (address + custom columns).
    pub fn column_count(&self) -> usize {
        1 + self.columns.len() // address column + custom columns
    }

    /// Get the column name at the given index (0 = address).
    pub fn column_name(&self, index: usize) -> &str {
        if index == 0 {
            "Address"
        } else {
            self.columns
                .get(index - 1)
                .map(|c| c.get_column_name())
                .unwrap_or("")
        }
    }

    /// Get the display value for a cell (row, column).
    pub fn get_cell_value(&self, row: usize, col: usize) -> Option<String> {
        let r = self.rows.get(row)?;
        if col == 0 {
            Some(format!("0x{:x}", r.get_address().0))
        } else {
            self.columns.get(col - 1).map(|c| c.get_value(r))
        }
    }

    /// Sort rows by the given column index.
    pub fn sort_by_column(&mut self, col: usize, ascending: bool) {
        if col == 0 {
            if ascending {
                self.rows.sort_by_key(|r| r.get_address());
            } else {
                self.rows.sort_by(|a, b| b.get_address().cmp(&a.get_address()));
            }
        } else if let Some(column) = self.columns.get(col - 1) {
            // We need to borrow column immutably while sorting rows mutably.
            // Work around by collecting values first.
            let col_ref: &dyn ColumnDisplay<T> = column.as_ref();
            let order = |a: &T, b: &T| -> Ordering {
                let ord = col_ref.compare(a, b);
                if ascending {
                    ord
                } else {
                    ord.reverse()
                }
            };
            self.rows.sort_by(order);
        }
    }
}

impl<T: AddressableRowObject + Clone> Default for TableChooserTableModel<T> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TableChooserDialog (model -- no GUI)
// ---------------------------------------------------------------------------

/// A table chooser dialog model that combines a table model with an
/// executor for operating on selected rows.
#[derive(Debug)]
pub struct TableChooserDialog<T: AddressableRowObject> {
    title: String,
    model: TableChooserTableModel<T>,
}

impl<T: AddressableRowObject + Clone> TableChooserDialog<T> {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            model: TableChooserTableModel::new(),
        }
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn model(&self) -> &TableChooserTableModel<T> {
        &self.model
    }

    pub fn model_mut(&mut self) -> &mut TableChooserTableModel<T> {
        &mut self.model
    }

    /// Add a row to the dialog.
    pub fn add_row(&mut self, row: T) {
        self.model.add_row(row);
    }

    /// Add a column to the dialog.
    pub fn add_column(&mut self, column: Box<dyn ColumnDisplay<T>>) {
        self.model.add_column(column);
    }
}

// ---------------------------------------------------------------------------
// Mappers (for integrating with Ghidra's table row framework)
// ---------------------------------------------------------------------------

/// Maps an `AddressableRowObject` to an address-based table row.
#[derive(Debug)]
pub struct AddressableRowObjectToAddressTableRowMapper;

impl AddressableRowObjectToAddressTableRowMapper {
    pub fn get_address<T: AddressableRowObject>(row: &T) -> Address {
        row.get_address()
    }
}

/// Maps an `AddressableRowObject` to a program location table row.
#[derive(Debug)]
pub struct AddressableRowObjectToProgramLocationTableRowMapper;

impl AddressableRowObjectToProgramLocationTableRowMapper {
    pub fn get_address<T: AddressableRowObject>(row: &T) -> Address {
        row.get_address()
    }
}

/// Maps an `AddressableRowObject` to a function table row.
#[derive(Debug)]
pub struct AddressableRowObjectToFunctionTableRowMapper;

impl AddressableRowObjectToFunctionTableRowMapper {
    pub fn get_address<T: AddressableRowObject>(row: &T) -> Address {
        row.get_address()
    }
}

/// Adapter for dynamic table column integration.
#[derive(Debug)]
pub struct ColumnDisplayDynamicTableColumnAdapter<T: AddressableRowObject> {
    inner: Box<dyn ColumnDisplay<T>>,
}

impl<T: AddressableRowObject> ColumnDisplayDynamicTableColumnAdapter<T> {
    pub fn new(inner: Box<dyn ColumnDisplay<T>>) -> Self {
        Self { inner }
    }

    pub fn column_name(&self) -> &str {
        self.inner.get_column_name()
    }

    pub fn column_width(&self) -> usize {
        self.inner.get_column_width()
    }

    pub fn get_value(&self, row: &T) -> String {
        self.inner.get_value(row)
    }
}

/// A comparable column display that provides custom comparison logic.
pub trait AbstractComparableColumnDisplay<T: AddressableRowObject>: ColumnDisplay<T> {
    /// Compare two values (the values returned by `get_value`).
    fn compare_values(&self, val_a: &str, val_b: &str) -> Ordering {
        val_a.cmp(val_b)
    }
}

/// Column display abstract base providing default implementations.
pub trait AbstractColumnDisplay<T: AddressableRowObject>: ColumnDisplay<T> {
    /// The maximum width of this column (pixels).
    fn max_column_width(&self) -> usize {
        300
    }

    /// The minimum width of this column (pixels).
    fn min_column_width(&self) -> usize {
        50
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_addressable_row_object() {
        let row = TestRow {
            addr: 0x401000,
            name: "main".into(),
            size: 256,
        };
        assert_eq!(row.get_address(), Address(0x401000));
    }

    #[test]
    fn test_table_model_add_rows() {
        let mut model = TableChooserTableModel::new();
        let rows = make_rows();
        model.add_rows(rows);
        assert_eq!(model.row_count(), 3);
    }

    #[test]
    fn test_table_model_remove_row() {
        let mut model = TableChooserTableModel::new();
        model.add_rows(make_rows());
        let removed = model.remove_row(1);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().name, "func_a");
        assert_eq!(model.row_count(), 2);
    }

    #[test]
    fn test_table_model_cell_value_address() {
        let mut model = TableChooserTableModel::new();
        model.add_row(TestRow {
            addr: 0x400000,
            name: "test".into(),
            size: 0,
        });
        assert_eq!(
            model.get_cell_value(0, 0),
            Some("0x400000".to_string())
        );
    }

    #[test]
    fn test_table_model_sort_by_address() {
        let mut model = TableChooserTableModel::new();
        model.add_rows(make_rows());
        model.sort_by_column(0, true);
        assert_eq!(model.get_row(0).unwrap().addr, 0x1000);
        assert_eq!(model.get_row(2).unwrap().addr, 0x3000);
    }

    #[test]
    fn test_table_model_sort_descending() {
        let mut model = TableChooserTableModel::new();
        model.add_rows(make_rows());
        model.sort_by_column(0, false);
        assert_eq!(model.get_row(0).unwrap().addr, 0x3000);
        assert_eq!(model.get_row(2).unwrap().addr, 0x1000);
    }

    #[test]
    fn test_string_column_display() {
        let col = StringColumnDisplay::<TestRow>::new("Name", Box::new(|r| r.name.clone()));
        assert_eq!(col.get_column_name(), "Name");
        let row = TestRow {
            addr: 0,
            name: "test".into(),
            size: 0,
        };
        assert_eq!(col.get_value(&row), "test");
    }

    #[test]
    fn test_table_model_custom_column() {
        let mut model = TableChooserTableModel::new();
        model.add_rows(make_rows());
        model.add_column(Box::new(StringColumnDisplay::new(
            "Name",
            Box::new(|r: &TestRow| r.name.clone()),
        )));

        assert_eq!(model.column_count(), 2); // address + Name
        assert_eq!(model.column_name(0), "Address");
        assert_eq!(model.column_name(1), "Name");
        assert_eq!(
            model.get_cell_value(0, 1),
            Some("func_c".to_string())
        );
    }

    #[test]
    fn test_table_chooser_dialog() {
        let mut dialog = TableChooserDialog::new("Choose Function");
        assert_eq!(dialog.title(), "Choose Function");
        dialog.add_row(TestRow {
            addr: 0x400000,
            name: "main".into(),
            size: 100,
        });
        assert_eq!(dialog.model().row_count(), 1);
    }

    #[test]
    fn test_sort_by_custom_column() {
        let mut model = TableChooserTableModel::new();
        model.add_rows(make_rows());
        model.add_column(Box::new(StringColumnDisplay::new(
            "Name",
            Box::new(|r: &TestRow| r.name.clone()),
        )));

        model.sort_by_column(1, true); // sort by Name ascending
        assert_eq!(model.get_row(0).unwrap().name, "func_a");
        assert_eq!(model.get_row(1).unwrap().name, "func_b");
        assert_eq!(model.get_row(2).unwrap().name, "func_c");
    }

    #[test]
    fn test_mappers() {
        let row = TestRow {
            addr: 0x400000,
            name: "main".into(),
            size: 0,
        };
        assert_eq!(
            AddressableRowObjectToAddressTableRowMapper::get_address(&row),
            Address(0x400000)
        );
        assert_eq!(
            AddressableRowObjectToProgramLocationTableRowMapper::get_address(&row),
            Address(0x400000)
        );
    }

    #[test]
    fn test_column_display_adapter() {
        let col = StringColumnDisplay::<TestRow>::new("Size", Box::new(|r| r.size.to_string()));
        let adapter = ColumnDisplayDynamicTableColumnAdapter::new(Box::new(col));
        assert_eq!(adapter.column_name(), "Size");
        let row = TestRow {
            addr: 0,
            name: "".into(),
            size: 42,
        };
        assert_eq!(adapter.get_value(&row), "42");
    }
}
