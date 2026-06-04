//! Adapter that bridges [`ColumnDisplay`] to a dynamic table column.
//!
//! This module provides the Rust analogue of
//! `ghidra.app.tablechooser.ColumnDisplayDynamicTableColumnAdapter`,
//! which wraps a `ColumnDisplay` so it can be used as a generic
//! dynamic table column in the table model.

use std::cmp::Ordering;

use super::traits::{AddressableRowObject, ColumnDisplay};

// ---------------------------------------------------------------------------
// DynamicTableColumn
// ---------------------------------------------------------------------------

/// Trait for a dynamically-dispatched table column.
///
/// This is the Rust equivalent of Ghidra's `DynamicTableColumn`.
pub trait DynamicTableColumn<T>: Send + Sync {
    /// Returns the column header name.
    fn column_name(&self) -> &str;

    /// Extracts the column value from a row object.
    fn get_value(&self, row: &dyn AddressableRowObject) -> T;

    /// Compares two row objects by this column's values.
    fn compare(&self, a: &dyn AddressableRowObject, b: &dyn AddressableRowObject) -> Ordering;
}

// ---------------------------------------------------------------------------
// ColumnDisplayDynamicTableColumnAdapter
// ---------------------------------------------------------------------------

/// Adapter that wraps a [`ColumnDisplay`] as a [`DynamicTableColumn`].
///
/// This is the Rust equivalent of
/// `ghidra.app.tablechooser.ColumnDisplayDynamicTableColumnAdapter<T>`.
///
/// The adapter delegates all operations to the wrapped `ColumnDisplay`.
pub struct ColumnDisplayDynamicTableColumnAdapter<T: Clone + PartialOrd + Send + Sync> {
    display: Box<dyn ColumnDisplay<T>>,
}

impl<T: Clone + PartialOrd + Send + Sync> ColumnDisplayDynamicTableColumnAdapter<T> {
    /// Creates a new adapter wrapping the given column display.
    pub fn new(display: Box<dyn ColumnDisplay<T>>) -> Self {
        Self { display }
    }

    /// Returns the inner column display.
    pub fn inner(&self) -> &dyn ColumnDisplay<T> {
        self.display.as_ref()
    }
}

impl<T: Clone + PartialOrd + Send + Sync + 'static> DynamicTableColumn<T>
    for ColumnDisplayDynamicTableColumnAdapter<T>
{
    fn column_name(&self) -> &str {
        self.display.column_name()
    }

    fn get_value(&self, row: &dyn AddressableRowObject) -> T {
        self.display.column_value(row)
    }

    fn compare(&self, a: &dyn AddressableRowObject, b: &dyn AddressableRowObject) -> Ordering {
        self.display.compare(a, b)
    }
}
