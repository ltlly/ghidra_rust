//! Table model utilities ported from Ghidra's `ghidra.util.table` package.
//!
//! Provides table model types for displaying program data:
//! - [`GhidraTableModel`] -- base trait for table models
//! - [`AddressBasedTableModel`] -- table model keyed by addresses
//! - [`GhidraFilterTable`] -- filtered table with address navigation
//! - [`TableRowObject`] -- a row in a table model
//! - [`TableColumn`] -- column descriptor for table models
//!
//! # Example
//!
//! ```rust
//! use ghidra_features::table_util::*;
//! use ghidra_features::base::analyzer::Address;
//!
//! let mut model = SimpleTableModel::new(vec!["Name", "Address", "Size"]);
//! model.add_row(vec![".text".into(), "0x1000".into(), "4096".into()]);
//! model.add_row(vec![".data".into(), "0x5000".into(), "2048".into()]);
//!
//! assert_eq!(model.row_count(), 2);
//! assert_eq!(model.column_count(), 3);
//! assert_eq!(model.get_value(0, 0), Some(".text"));
//! ```

use std::collections::HashMap;
use std::fmt;

use crate::base::analyzer::{Address, AddressSet};

// ---------------------------------------------------------------------------
// TableColumn
// ---------------------------------------------------------------------------

/// Describes a column in a table model.
///
/// Ported from `ghidra.util.table.GhidraTableColumn`.
#[derive(Debug, Clone)]
pub struct TableColumn {
    /// The column name/header.
    pub name: String,
    /// The column index.
    pub index: usize,
    /// The preferred width in pixels (for UI).
    pub preferred_width: usize,
    /// Whether the column is sortable.
    pub sortable: bool,
    /// Whether the column is visible.
    pub visible: bool,
    /// The column type description.
    pub column_type: ColumnType,
}

/// The type of data in a column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColumnType {
    /// String data.
    String,
    /// Numeric data.
    Number,
    /// Address data.
    Address,
    /// Boolean data.
    Boolean,
    /// Custom type.
    Custom(String),
}

impl TableColumn {
    pub fn new(name: impl Into<String>, index: usize) -> Self {
        Self {
            name: name.into(),
            index,
            preferred_width: 100,
            sortable: true,
            visible: true,
            column_type: ColumnType::String,
        }
    }

    pub fn with_width(mut self, width: usize) -> Self {
        self.preferred_width = width;
        self
    }

    pub fn with_type(mut self, column_type: ColumnType) -> Self {
        self.column_type = column_type;
        self
    }

    pub fn sortable(mut self, sortable: bool) -> Self {
        self.sortable = sortable;
        self
    }

    pub fn visible(mut self, visible: bool) -> Self {
        self.visible = visible;
        self
    }
}

// ---------------------------------------------------------------------------
// GhidraTableModel trait
// ---------------------------------------------------------------------------

/// Trait for table models that display program data.
///
/// Ported from `ghidra.util.table.GhidraTableModel`.
pub trait GhidraTableModel {
    /// Get the number of rows.
    fn row_count(&self) -> usize;

    /// Get the number of columns.
    fn column_count(&self) -> usize;

    /// Get the column name at the given index.
    fn column_name(&self, col: usize) -> &str;

    /// Get the value at the given row and column.
    fn get_value(&self, row: usize, col: usize) -> Option<&str>;

    /// Get the address associated with a row (if any).
    fn get_address(&self, row: usize) -> Option<Address> {
        None
    }

    /// Get the column descriptors.
    fn columns(&self) -> &[TableColumn];

    /// Check if the model is empty.
    fn is_empty(&self) -> bool {
        self.row_count() == 0
    }
}

// ---------------------------------------------------------------------------
// AddressBasedTableModel
// ---------------------------------------------------------------------------

/// A table model where each row is associated with an address.
///
/// This is the most common table model in Ghidra for displaying
/// program data like symbols, functions, bookmarks, etc.
///
/// Ported from `ghidra.util.table.AddressBasedTableModel`.
#[derive(Debug, Clone)]
pub struct AddressBasedTableModel {
    columns: Vec<TableColumn>,
    rows: Vec<AddressTableRow>,
}

/// A row in an address-based table.
#[derive(Debug, Clone)]
pub struct AddressTableRow {
    /// The address associated with this row.
    pub address: Address,
    /// Column values as strings.
    pub values: Vec<String>,
}

impl AddressBasedTableModel {
    pub fn new(column_names: Vec<&str>) -> Self {
        let columns = column_names
            .iter()
            .enumerate()
            .map(|(i, name)| TableColumn::new(*name, i))
            .collect();
        Self {
            columns,
            rows: Vec::new(),
        }
    }

    /// Add a row with the given address and values.
    pub fn add_row(&mut self, address: Address, values: Vec<String>) {
        assert_eq!(
            values.len(),
            self.columns.len(),
            "Number of values must match number of columns"
        );
        self.rows.push(AddressTableRow { address, values });
    }

    /// Sort rows by address.
    pub fn sort_by_address(&mut self) {
        self.rows.sort_by_key(|r| r.address.offset);
    }

    /// Sort rows by a specific column.
    pub fn sort_by_column(&mut self, col: usize) {
        self.rows.sort_by(|a, b| {
            a.values
                .get(col)
                .unwrap_or(&String::new())
                .cmp(b.values.get(col).unwrap_or(&String::new()))
        });
    }

    /// Get the address set of all rows.
    pub fn address_set(&self) -> AddressSet {
        let mut set = AddressSet::new();
        for row in &self.rows {
            set.add(row.address);
        }
        set
    }

    /// Find rows at a specific address.
    pub fn find_rows_at(&self, addr: Address) -> Vec<usize> {
        self.rows
            .iter()
            .enumerate()
            .filter(|(_, r)| r.address == addr)
            .map(|(i, _)| i)
            .collect()
    }

    /// Remove all rows.
    pub fn clear(&mut self) {
        self.rows.clear();
    }

    /// Get a row by index.
    pub fn get_row(&self, row: usize) -> Option<&AddressTableRow> {
        self.rows.get(row)
    }
}

impl GhidraTableModel for AddressBasedTableModel {
    fn row_count(&self) -> usize {
        self.rows.len()
    }

    fn column_count(&self) -> usize {
        self.columns.len()
    }

    fn column_name(&self, col: usize) -> &str {
        self.columns
            .get(col)
            .map(|c| c.name.as_str())
            .unwrap_or("")
    }

    fn get_value(&self, row: usize, col: usize) -> Option<&str> {
        self.rows
            .get(row)
            .and_then(|r| r.values.get(col))
            .map(|s| s.as_str())
    }

    fn get_address(&self, row: usize) -> Option<Address> {
        self.rows.get(row).map(|r| r.address)
    }

    fn columns(&self) -> &[TableColumn] {
        &self.columns
    }
}

// ---------------------------------------------------------------------------
// SimpleTableModel
// ---------------------------------------------------------------------------

/// A simple table model without address association.
#[derive(Debug, Clone)]
pub struct SimpleTableModel {
    columns: Vec<TableColumn>,
    rows: Vec<Vec<String>>,
}

impl SimpleTableModel {
    pub fn new(column_names: Vec<&str>) -> Self {
        let columns = column_names
            .iter()
            .enumerate()
            .map(|(i, name)| TableColumn::new(*name, i))
            .collect();
        Self {
            columns,
            rows: Vec::new(),
        }
    }

    /// Add a row of values.
    pub fn add_row(&mut self, values: Vec<String>) {
        assert_eq!(
            values.len(),
            self.columns.len(),
            "Number of values must match number of columns"
        );
        self.rows.push(values);
    }

    /// Remove all rows.
    pub fn clear(&mut self) {
        self.rows.clear();
    }

    /// Sort by a column.
    pub fn sort_by_column(&mut self, col: usize) {
        self.rows.sort_by(|a, b| {
            a.get(col)
                .unwrap_or(&String::new())
                .cmp(b.get(col).unwrap_or(&String::new()))
        });
    }
}

impl GhidraTableModel for SimpleTableModel {
    fn row_count(&self) -> usize {
        self.rows.len()
    }

    fn column_count(&self) -> usize {
        self.columns.len()
    }

    fn column_name(&self, col: usize) -> &str {
        self.columns
            .get(col)
            .map(|c| c.name.as_str())
            .unwrap_or("")
    }

    fn get_value(&self, row: usize, col: usize) -> Option<&str> {
        self.rows
            .get(row)
            .and_then(|r| r.get(col))
            .map(|s| s.as_str())
    }

    fn columns(&self) -> &[TableColumn] {
        &self.columns
    }
}

// ---------------------------------------------------------------------------
// GhidraFilterTable
// ---------------------------------------------------------------------------

/// A filtered table that supports address-based navigation.
///
/// Wraps a table model with filtering and row selection by address.
///
/// Ported from `ghidra.util.table.GhidraFilterTable`.
#[derive(Debug)]
pub struct GhidraFilterTable<M: GhidraTableModel> {
    model: M,
    /// Row indices that pass the current filter.
    filtered_rows: Vec<usize>,
    /// Current filter text.
    filter_text: String,
}

impl<M: GhidraTableModel> GhidraFilterTable<M> {
    pub fn new(model: M) -> Self {
        let row_count = model.row_count();
        let filtered_rows = (0..row_count).collect();
        Self {
            model,
            filtered_rows,
            filter_text: String::new(),
        }
    }

    /// Apply a text filter to the table.
    pub fn set_filter(&mut self, filter: &str) {
        self.filter_text = filter.to_string();
        let filter_lower = filter.to_lowercase();

        if filter_lower.is_empty() {
            self.filtered_rows = (0..self.model.row_count()).collect();
        } else {
            self.filtered_rows = (0..self.model.row_count())
                .filter(|&row| {
                    (0..self.model.column_count()).any(|col| {
                        self.model
                            .get_value(row, col)
                            .map(|v| v.to_lowercase().contains(&filter_lower))
                            .unwrap_or(false)
                    })
                })
                .collect();
        }
    }

    /// Get the number of filtered rows.
    pub fn filtered_row_count(&self) -> usize {
        self.filtered_rows.len()
    }

    /// Get the model row index for a filtered row index.
    pub fn model_row(&self, filtered_row: usize) -> Option<usize> {
        self.filtered_rows.get(filtered_row).copied()
    }

    /// Get a value by filtered row index.
    pub fn get_filtered_value(&self, filtered_row: usize, col: usize) -> Option<&str> {
        self.model_row(filtered_row)
            .and_then(|row| self.model.get_value(row, col))
    }

    /// Get the address for a filtered row.
    pub fn get_filtered_address(&self, filtered_row: usize) -> Option<Address> {
        self.model_row(filtered_row)
            .and_then(|row| self.model.get_address(row))
    }

    /// Find the first filtered row at the given address.
    pub fn find_row_by_address(&self, addr: Address) -> Option<usize> {
        self.filtered_rows.iter().position(|&row| {
            self.model
                .get_address(row)
                .map(|a| a == addr)
                .unwrap_or(false)
        })
    }

    /// Get the underlying model.
    pub fn model(&self) -> &M {
        &self.model
    }

    /// Get the current filter text.
    pub fn filter_text(&self) -> &str {
        &self.filter_text
    }

    /// Clear the filter.
    pub fn clear_filter(&mut self) {
        self.set_filter("");
    }

    /// Check if a filter is active.
    pub fn is_filtered(&self) -> bool {
        !self.filter_text.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table_column() {
        let col = TableColumn::new("Name", 0)
            .with_width(200)
            .with_type(ColumnType::String);
        assert_eq!(col.name, "Name");
        assert_eq!(col.index, 0);
        assert_eq!(col.preferred_width, 200);
        assert!(col.sortable);
        assert!(col.visible);
    }

    #[test]
    fn test_simple_table_model() {
        let mut model = SimpleTableModel::new(vec!["A", "B", "C"]);
        assert_eq!(model.row_count(), 0);
        assert_eq!(model.column_count(), 3);
        assert!(model.is_empty());

        model.add_row(vec!["1".into(), "2".into(), "3".into()]);
        model.add_row(vec!["4".into(), "5".into(), "6".into()]);

        assert_eq!(model.row_count(), 2);
        assert!(!model.is_empty());
        assert_eq!(model.get_value(0, 0), Some("1"));
        assert_eq!(model.get_value(0, 1), Some("2"));
        assert_eq!(model.get_value(1, 2), Some("6"));
        assert_eq!(model.get_value(2, 0), None);
        assert_eq!(model.column_name(0), "A");
        assert_eq!(model.column_name(2), "C");
    }

    #[test]
    fn test_simple_table_model_sort() {
        let mut model = SimpleTableModel::new(vec!["Name", "Value"]);
        model.add_row(vec!["Charlie".into(), "3".into()]);
        model.add_row(vec!["Alpha".into(), "1".into()]);
        model.add_row(vec!["Bravo".into(), "2".into()]);

        model.sort_by_column(0);
        assert_eq!(model.get_value(0, 0), Some("Alpha"));
        assert_eq!(model.get_value(1, 0), Some("Bravo"));
        assert_eq!(model.get_value(2, 0), Some("Charlie"));
    }

    #[test]
    fn test_address_based_table_model() {
        let mut model = AddressBasedTableModel::new(vec!["Symbol", "Address", "Type"]);
        model.add_row(Address::new(0x1000), vec!["main".into(), "0x1000".into(), "Function".into()]);
        model.add_row(Address::new(0x2000), vec!["data".into(), "0x2000".into(), "Label".into()]);

        assert_eq!(model.row_count(), 2);
        assert_eq!(model.get_address(0), Some(Address::new(0x1000)));
        assert_eq!(model.get_value(1, 0), Some("data"));
    }

    #[test]
    fn test_address_based_table_model_address_set() {
        let mut model = AddressBasedTableModel::new(vec!["Name"]);
        model.add_row(Address::new(0x1000), vec!["a".into()]);
        model.add_row(Address::new(0x2000), vec!["b".into()]);
        model.add_row(Address::new(0x1000), vec!["c".into()]);

        let set = model.address_set();
        assert!(set.contains(&Address::new(0x1000)));
        assert!(set.contains(&Address::new(0x2000)));

        let rows_at_1000 = model.find_rows_at(Address::new(0x1000));
        assert_eq!(rows_at_1000.len(), 2);
    }

    #[test]
    fn test_address_based_table_model_sort_by_address() {
        let mut model = AddressBasedTableModel::new(vec!["Name"]);
        model.add_row(Address::new(0x3000), vec!["c".into()]);
        model.add_row(Address::new(0x1000), vec!["a".into()]);
        model.add_row(Address::new(0x2000), vec!["b".into()]);

        model.sort_by_address();
        assert_eq!(model.get_value(0, 0), Some("a"));
        assert_eq!(model.get_value(1, 0), Some("b"));
        assert_eq!(model.get_value(2, 0), Some("c"));
    }

    #[test]
    fn test_ghidra_filter_table() {
        let mut model = SimpleTableModel::new(vec!["Name", "Category"]);
        model.add_row(vec!["func_a".into(), "text".into()]);
        model.add_row(vec!["func_b".into(), "data".into()]);
        model.add_row(vec!["var_c".into(), "text".into()]);

        let mut table = GhidraFilterTable::new(model);
        assert_eq!(table.filtered_row_count(), 3);
        assert!(!table.is_filtered());

        table.set_filter("func");
        assert_eq!(table.filtered_row_count(), 2);
        assert!(table.is_filtered());
        assert_eq!(table.get_filtered_value(0, 0), Some("func_a"));
        assert_eq!(table.get_filtered_value(1, 0), Some("func_b"));

        table.set_filter("data");
        assert_eq!(table.filtered_row_count(), 1);
        assert_eq!(table.get_filtered_value(0, 0), Some("func_b"));

        table.clear_filter();
        assert_eq!(table.filtered_row_count(), 3);
        assert!(!table.is_filtered());
    }

    #[test]
    fn test_ghidra_filter_table_by_address() {
        let mut model = AddressBasedTableModel::new(vec!["Name", "Addr"]);
        model.add_row(Address::new(0x1000), vec!["main".into(), "0x1000".into()]);
        model.add_row(Address::new(0x2000), vec!["helper".into(), "0x2000".into()]);
        model.add_row(Address::new(0x3000), vec!["data".into(), "0x3000".into()]);

        let table = GhidraFilterTable::new(model);

        assert_eq!(table.find_row_by_address(Address::new(0x2000)), Some(1));
        assert_eq!(table.find_row_by_address(Address::new(0x5000)), None);

        assert_eq!(table.get_filtered_address(0), Some(Address::new(0x1000)));
        assert_eq!(table.get_filtered_address(2), Some(Address::new(0x3000)));
    }

    #[test]
    fn test_ghidra_filter_table_model_row_mapping() {
        let mut model = SimpleTableModel::new(vec!["Name"]);
        model.add_row(vec!["alpha".into()]);
        model.add_row(vec!["beta".into()]);
        model.add_row(vec!["gamma".into()]);

        let mut table = GhidraFilterTable::new(model);
        table.set_filter("b");

        // Only "beta" (1) matches
        assert_eq!(table.filtered_row_count(), 1);
        assert_eq!(table.model_row(0), Some(1));
    }

    #[test]
    fn test_column_type() {
        assert_eq!(ColumnType::String, ColumnType::String);
        assert_ne!(ColumnType::String, ColumnType::Number);
        assert_eq!(ColumnType::Custom("foo".into()), ColumnType::Custom("foo".into()));
    }

    #[test]
    fn test_table_model_clear() {
        let mut model = SimpleTableModel::new(vec!["X"]);
        model.add_row(vec!["1".into()]);
        model.add_row(vec!["2".into()]);
        assert_eq!(model.row_count(), 2);

        model.clear();
        assert_eq!(model.row_count(), 0);
        assert!(model.is_empty());
    }

    #[test]
    fn test_address_based_model_clear() {
        let mut model = AddressBasedTableModel::new(vec!["Name"]);
        model.add_row(Address::new(0x1000), vec!["a".into()]);
        model.clear();
        assert_eq!(model.row_count(), 0);
        assert!(model.address_set().is_empty());
    }
}
