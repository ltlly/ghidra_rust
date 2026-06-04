//! Column display implementations.
//!
//! This module provides the Rust analogues of Ghidra's column display
//! hierarchy:
//!
//! - [`AbstractColumnDisplay`] -- base implementation of [`ColumnDisplay`].
//! - [`AbstractComparableColumnDisplay`] -- column display for comparable values.
//! - [`StringColumnDisplay`] -- concrete column display for `String` values.
//!
//! These are useful as base types for user-defined table columns in
//! the table-chooser dialog.

use std::cmp::Ordering;

use super::traits::{AddressableRowObject, ColumnDisplay};

// ---------------------------------------------------------------------------
// AbstractColumnDisplay
// ---------------------------------------------------------------------------

/// Base implementation of [`ColumnDisplay`] that provides a stored name.
///
/// Subclasses only need to implement [`column_value`](ColumnDisplay::column_value)
/// and optionally override [`compare`](ColumnDisplay::compare).
pub struct AbstractColumnDisplay {
    name: String,
}

impl AbstractColumnDisplay {
    /// Creates a new `AbstractColumnDisplay` with the given column name.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

// ---------------------------------------------------------------------------
// AbstractComparableColumnDisplay
// ---------------------------------------------------------------------------

/// A column display for values that implement `PartialOrd`.
///
/// This is the Rust equivalent of
/// `ghidra.app.tablechooser.AbstractComparableColumnDisplay<T>`.
/// The [`compare`](ColumnDisplay::compare) implementation compares
/// the extracted column values directly.
pub struct AbstractComparableColumnDisplay<T: Clone + PartialOrd> {
    name: String,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: Clone + PartialOrd> AbstractComparableColumnDisplay<T> {
    /// Creates a new `AbstractComparableColumnDisplay` with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T: Clone + PartialOrd + Send + Sync + 'static> ColumnDisplay<T>
    for AbstractComparableColumnDisplay<T>
{
    fn column_name(&self) -> &str {
        &self.name
    }

    fn column_value(&self, _row: &dyn AddressableRowObject) -> T {
        unimplemented!("subclasses must override column_value")
    }

    fn compare(&self, a: &dyn AddressableRowObject, b: &dyn AddressableRowObject) -> Ordering {
        let va = self.column_value(a);
        let vb = self.column_value(b);
        va.partial_cmp(&vb)
            .unwrap_or_else(|| a.address().offset.cmp(&b.address().offset))
    }
}

// ---------------------------------------------------------------------------
// StringColumnDisplay
// ---------------------------------------------------------------------------

/// A concrete column display for `String` values.
///
/// This is the Rust equivalent of
/// `ghidra.app.tablechooser.StringColumnDisplay`.
pub struct StringColumnDisplay {
    name: String,
}

impl StringColumnDisplay {
    /// Creates a new `StringColumnDisplay` with the given column name.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

impl ColumnDisplay<String> for StringColumnDisplay {
    fn column_name(&self) -> &str {
        &self.name
    }

    fn column_value(&self, row: &dyn AddressableRowObject) -> String {
        // Default implementation formats the address.
        format!("0x{:X}", row.address().offset)
    }

    fn compare(&self, a: &dyn AddressableRowObject, b: &dyn AddressableRowObject) -> Ordering {
        let va = self.column_value(a);
        let vb = self.column_value(b);
        va.cmp(&vb)
    }
}
