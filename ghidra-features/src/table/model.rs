//! Table model for the table-chooser dialog.
//!
//! This module provides the Rust analogue of
//! `ghidra.app.tablechooser.TableChooserTableModel`, which manages
//! a sorted, filterable collection of [`AddressableRowObject`]s.

use std::collections::HashSet;
use std::sync::Arc;

use ghidra_core::addr::Address;

use super::adapter::{ColumnDisplayDynamicTableColumnAdapter, DynamicTableColumn};
use super::traits::{AddressableRowObject, ColumnDisplay};

// ---------------------------------------------------------------------------
// SimpleRowObject
// ---------------------------------------------------------------------------

/// A simple [`AddressableRowObject`] backed by an address and label.
///
/// This is a convenience implementation for testing and simple use cases.
#[derive(Debug, Clone)]
pub struct SimpleRowObject {
    /// The address associated with this row.
    pub addr: Address,
    /// An optional label for display purposes.
    pub label: String,
}

impl SimpleRowObject {
    /// Creates a new `SimpleRowObject` with the given address.
    pub fn new(addr: Address) -> Self {
        Self {
            addr,
            label: String::new(),
        }
    }

    /// Creates a new `SimpleRowObject` with address and label.
    pub fn with_label(addr: Address, label: impl Into<String>) -> Self {
        Self {
            addr,
            label: label.into(),
        }
    }
}

impl AddressableRowObject for SimpleRowObject {
    fn address(&self) -> Address {
        self.addr
    }
}

// ---------------------------------------------------------------------------
// TableChooserTableModel
// ---------------------------------------------------------------------------

/// Table model for the table-chooser dialog.
///
/// This is the Rust equivalent of
/// `ghidra.app.tablechooser.TableChooserTableModel`.  It manages a
/// collection of [`AddressableRowObject`] instances, supports sorting,
/// filtering, and custom columns.
///
/// # Type Parameters
///
/// * `T` -- the concrete row object type.
pub struct TableChooserTableModel<T: AddressableRowObject + Clone + Send + Sync> {
    /// Internal storage of rows.
    rows: Vec<T>,
    /// Set of row keys for fast membership testing.
    row_set: HashSet<u64>,
    /// Custom columns added by the user.
    custom_columns: Vec<Arc<dyn DynamicTableColumn<String>>>,
    /// The column index currently used for sorting (default: by address).
    sort_column: Option<usize>,
    /// Whether sort is descending.
    sort_descending: bool,
    /// Title of this table model.
    title: String,
    /// Next auto-increment key.
    next_key: u64,
}

impl<T: AddressableRowObject + Clone + Send + Sync> TableChooserTableModel<T> {
    /// Creates a new table model with the given title.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            rows: Vec::new(),
            row_set: HashSet::new(),
            custom_columns: Vec::new(),
            sort_column: None,
            sort_descending: false,
            title: title.into(),
            next_key: 1,
        }
    }

    /// Returns the title of this model.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Adds a row object to the model.
    ///
    /// Returns the assigned key for the row.
    pub fn add_object(&mut self, row: T) -> u64 {
        let key = self.next_key;
        self.next_key += 1;
        self.row_set.insert(key);
        self.rows.push(row);
        key
    }

    /// Removes a row object by address.
    ///
    /// Returns `true` if an object was removed.
    pub fn remove_object(&mut self, addr: &Address) -> bool {
        if let Some(idx) = self.rows.iter().position(|r| r.address() == *addr) {
            self.rows.remove(idx);
            return true;
        }
        false
    }

    /// Returns `true` if the model contains a row at the given address.
    pub fn contains_address(&self, addr: &Address) -> bool {
        self.rows.iter().any(|r| r.address() == *addr)
    }

    /// Returns the number of rows in the model.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Returns a reference to the row at the given index.
    pub fn get_row_object(&self, row: usize) -> Option<&T> {
        self.rows.get(row)
    }

    /// Returns a reference to all rows.
    pub fn get_row_objects(&self) -> &[T] {
        &self.rows
    }

    /// Returns the row objects at the given indices.
    pub fn get_row_objects_at(&self, indices: &[usize]) -> Vec<&T> {
        indices.iter().filter_map(|&i| self.rows.get(i)).collect()
    }

    /// Returns the address of the row at the given index.
    pub fn get_address(&self, row: usize) -> Option<Address> {
        self.rows.get(row).map(|r| r.address())
    }

    /// Adds a custom column to the model.
    pub fn add_custom_column(&mut self, column: Arc<dyn DynamicTableColumn<String>>) {
        self.custom_columns.push(column);
    }

    /// Returns the number of columns (1 base + custom columns).
    pub fn column_count(&self) -> usize {
        1 + self.custom_columns.len()
    }

    /// Returns the name of the column at the given index.
    pub fn column_name(&self, col: usize) -> &str {
        if col == 0 {
            "Address"
        } else if let Some(c) = self.custom_columns.get(col - 1) {
            c.column_name()
        } else {
            ""
        }
    }

    /// Gets the cell value at the given row and column.
    pub fn get_cell_value(&self, row: usize, col: usize) -> Option<String> {
        let r = self.rows.get(row)?;
        if col == 0 {
            Some(format!("0x{:X}", r.address().offset))
        } else if let Some(c) = self.custom_columns.get(col - 1) {
            Some(c.get_value(r))
        } else {
            None
        }
    }

    /// Sets the sort column index.
    pub fn set_sort_column(&mut self, col: usize) {
        self.sort_column = Some(col);
    }

    /// Sets the sort direction.
    pub fn set_sort_descending(&mut self, descending: bool) {
        self.sort_descending = descending;
    }

    /// Sorts the rows by the current sort column.
    pub fn sort(&mut self) {
        let col = self.sort_column;
        let desc = self.sort_descending;

        self.rows.sort_by(|a, b| {
            let ord = match col {
                Some(c) if c > 0 => {
                    if let Some(column) = self.custom_columns.get(c - 1) {
                        column.compare(a, b)
                    } else {
                        a.address().offset.cmp(&b.address().offset)
                    }
                }
                _ => a.address().offset.cmp(&b.address().offset),
            };
            if desc { ord.reverse() } else { ord }
        });
    }

    /// Filters rows to only those whose addresses are in the given set.
    pub fn filter_by_addresses(&mut self, addrs: &HashSet<Address>) {
        self.rows.retain(|r| addrs.contains(&r.address()));
    }

    /// Clears all rows.
    pub fn clear(&mut self) {
        self.rows.clear();
        self.row_set.clear();
    }

    /// Returns the index of the row at the given address, if any.
    pub fn index_of_address(&self, addr: &Address) -> Option<usize> {
        self.rows.iter().position(|r| r.address() == *addr)
    }
}

impl<T: AddressableRowObject + Clone + Send + Sync> Default for TableChooserTableModel<T> {
    fn default() -> Self {
        Self::new("Untitled")
    }
}

// ---------------------------------------------------------------------------
// TableSortState
// ---------------------------------------------------------------------------

/// Represents the sort state of a table (column index + direction).
///
/// This is the Rust equivalent of Ghidra's `TableSortState`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableSortState {
    /// Column indices in priority order.
    columns: Vec<SortColumn>,
}

/// A single sort column entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SortColumn {
    /// The 0-based column index.
    pub column: usize,
    /// Whether the sort is descending.
    pub descending: bool,
}

impl TableSortState {
    /// Creates a default sort state with a single ascending column.
    pub fn create_default(column: usize) -> Self {
        Self {
            columns: vec![SortColumn {
                column,
                descending: false,
            }],
        }
    }

    /// Creates a sort state with the given column and direction.
    pub fn new(column: usize, descending: bool) -> Self {
        Self {
            columns: vec![SortColumn { column, descending }],
        }
    }

    /// Adds a secondary sort column.
    pub fn then(mut self, column: usize, descending: bool) -> Self {
        self.columns.push(SortColumn { column, descending });
        self
    }

    /// Returns the sort columns in priority order.
    pub fn columns(&self) -> &[SortColumn] {
        &self.columns
    }

    /// Returns the primary sort column index.
    pub fn primary_column(&self) -> usize {
        self.columns.first().map(|c| c.column).unwrap_or(0)
    }

    /// Returns `true` if the primary sort is descending.
    pub fn is_primary_descending(&self) -> bool {
        self.columns.first().map(|c| c.descending).unwrap_or(false)
    }
}
