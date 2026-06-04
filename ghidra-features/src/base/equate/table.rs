//! Equate table models -- data models for the Equates Table UI.
//!
//! Ported from `ghidra.app.plugin.core.equate.EquateTableModel` and
//! `ghidra.app.plugin.core.equate.EquateReferenceTableModel` in Ghidra's
//! Features/Base.
//!
//! This module provides:
//! - [`EquateTableModel`] -- model for the main equates table (name, value,
//!   reference count, enum-based flag)
//! - [`EquateReferenceTableModel`] -- model for the references sub-table
//!   (address, operand index)
//! - Column definitions: [`EquateNameColumn`], [`EquateValueColumn`],
//!   [`EquateRefCountColumn`], [`IsEnumBasedColumn`],
//!   [`ReferenceAddressColumn`], [`ReferenceOpIndexColumn`]

use super::manager::EquateTable;
use super::{EquateReference, EquateValue};
use ghidra_core::Address;
use std::cmp::Ordering;

// ============================================================================
// Column trait
// ============================================================================

/// A column in a table model.
///
/// Each column knows its name, how to extract a value from a row, and
/// optionally how to sort and produce a filter string.
pub trait TableColumn<R>: std::fmt::Debug {
    /// The column name (header text).
    fn name(&self) -> &str;

    /// Extract a display string from a row.
    fn display_value(&self, row: &R) -> String;

    /// Whether this column is visible by default.
    fn is_visible(&self) -> bool {
        true
    }

    /// Produce a filter string for searching.
    fn filter_string(&self, row: &R) -> String {
        self.display_value(row)
    }
}

// ============================================================================
// Equate table columns
// ============================================================================

/// Column: equate display name.
#[derive(Debug, Clone)]
pub struct EquateNameColumn;

impl TableColumn<EquateValue> for EquateNameColumn {
    fn name(&self) -> &str {
        "Name"
    }

    fn display_value(&self, row: &EquateValue) -> String {
        row.display_name().to_string()
    }

    fn filter_string(&self, row: &EquateValue) -> String {
        row.display_name().to_string()
    }
}

/// Column: equate value (hex).
#[derive(Debug, Clone)]
pub struct EquateValueColumn;

impl TableColumn<EquateValue> for EquateValueColumn {
    fn name(&self) -> &str {
        "Value"
    }

    fn display_value(&self, row: &EquateValue) -> String {
        format!("0x{:x}", row.value)
    }

    fn filter_string(&self, row: &EquateValue) -> String {
        format!("{} {}", format!("{:x}", row.value), row.value)
    }
}

/// Column: reference count.
#[derive(Debug, Clone)]
pub struct EquateRefCountColumn;

impl TableColumn<EquateValue> for EquateRefCountColumn {
    fn name(&self) -> &str {
        "# Refs"
    }

    fn display_value(&self, row: &EquateValue) -> String {
        row.reference_count().to_string()
    }
}

/// Column: is the equate based on an enum.
#[derive(Debug, Clone)]
pub struct IsEnumBasedColumn;

impl TableColumn<EquateValue> for IsEnumBasedColumn {
    fn name(&self) -> &str {
        "Is Enum-Based"
    }

    fn display_value(&self, row: &EquateValue) -> String {
        row.is_enum_based.to_string()
    }

    fn is_visible(&self) -> bool {
        false // hidden by default, matching Java
    }
}

// ============================================================================
// Reference table columns
// ============================================================================

/// Column: reference address.
#[derive(Debug, Clone)]
pub struct ReferenceAddressColumn;

impl TableColumn<EquateReference> for ReferenceAddressColumn {
    fn name(&self) -> &str {
        "Ref Addr"
    }

    fn display_value(&self, row: &EquateReference) -> String {
        format!("0x{:x}", row.address.offset)
    }
}

/// Column: operand index.
#[derive(Debug, Clone)]
pub struct ReferenceOpIndexColumn;

impl TableColumn<EquateReference> for ReferenceOpIndexColumn {
    fn name(&self) -> &str {
        "Op Index"
    }

    fn display_value(&self, row: &EquateReference) -> String {
        row.op_index.to_string()
    }
}

// ============================================================================
// SortOrder
// ============================================================================

/// Sort direction for table columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SortOrder {
    /// Ascending.
    Ascending,
    /// Descending.
    Descending,
}

impl Default for SortOrder {
    fn default() -> Self {
        SortOrder::Ascending
    }
}

// ============================================================================
// EquateTableModel
// ============================================================================

/// Data model for the main equates table.
///
/// Corresponds to `EquateTableModel` in Java. Provides column definitions,
/// data access, sorting, filtering, and editing support for the equate
/// table display.
#[derive(Debug, Clone)]
pub struct EquateTableModel {
    /// The equate list (sorted/filtered view).
    equates: Vec<EquateValue>,
    /// The column definitions.
    columns: Vec<EquateColumnDef>,
    /// Current sort column index.
    sort_column: usize,
    /// Current sort order.
    sort_order: SortOrder,
    /// Current filter text.
    filter_text: Option<String>,
    /// Editable name column index.
    name_column_index: usize,
}

/// Column definition for the equate table.
#[derive(Debug, Clone)]
pub struct EquateColumnDef {
    /// Column name.
    pub name: String,
    /// Whether visible.
    pub visible: bool,
    /// Column index.
    pub index: usize,
}

/// Column indices in the equate table.
pub mod equate_columns {
    /// Name column.
    pub const NAME: usize = 0;
    /// Value column.
    pub const VALUE: usize = 1;
    /// Reference count column.
    pub const REFS: usize = 2;
    /// Is enum-based column.
    pub const IS_ENUM_BASED: usize = 3;
}

impl EquateTableModel {
    /// Create a new model.
    pub fn new() -> Self {
        Self {
            equates: Vec::new(),
            columns: vec![
                EquateColumnDef {
                    name: "Name".to_string(),
                    visible: true,
                    index: equate_columns::NAME,
                },
                EquateColumnDef {
                    name: "Value".to_string(),
                    visible: true,
                    index: equate_columns::VALUE,
                },
                EquateColumnDef {
                    name: "# Refs".to_string(),
                    visible: true,
                    index: equate_columns::REFS,
                },
                EquateColumnDef {
                    name: "Is Enum-Based".to_string(),
                    visible: false,
                    index: equate_columns::IS_ENUM_BASED,
                },
            ],
            sort_column: 0,
            sort_order: SortOrder::Ascending,
            filter_text: None,
            name_column_index: equate_columns::NAME,
        }
    }

    /// Refresh the model from an equate table.
    pub fn update(&mut self, table: &EquateTable) {
        self.equates = table.get_all_equates().into_iter().cloned().collect();
        self.apply_sort();
    }

    /// Get the number of rows.
    pub fn row_count(&self) -> usize {
        self.equates.len()
    }

    /// Get the number of visible columns.
    pub fn visible_column_count(&self) -> usize {
        self.columns.iter().filter(|c| c.visible).count()
    }

    /// Get all column definitions.
    pub fn columns(&self) -> &[EquateColumnDef] {
        &self.columns
    }

    /// Get a cell value by row and column index.
    pub fn cell_value(&self, row: usize, col: usize) -> Option<String> {
        let eq = self.equates.get(row)?;
        match col {
            equate_columns::NAME => Some(eq.display_name().to_string()),
            equate_columns::VALUE => Some(format!("0x{:x}", eq.value)),
            equate_columns::REFS => Some(eq.reference_count().to_string()),
            equate_columns::IS_ENUM_BASED => Some(eq.is_enum_based.to_string()),
            _ => None,
        }
    }

    /// Get the equate at a row.
    pub fn get_equate(&self, row: usize) -> Option<&EquateValue> {
        self.equates.get(row)
    }

    /// Check if a cell is editable.
    ///
    /// Only the name column is editable, and only for user-defined equates
    /// (not enum-based).
    pub fn is_cell_editable(&self, _row: usize, col: usize) -> bool {
        if col != self.name_column_index {
            return false;
        }
        // Enum-based equates have names that start with the DATATYPE_TAG.
        if let Some(eq) = self.equates.get(_row) {
            !super::manager::EquateManager::is_enum_equate_name(&eq.name)
        } else {
            false
        }
    }

    /// Set the value at a cell (rename equate).
    ///
    /// Returns `Some((old_name, new_name))` if a rename is needed, or `None`
    /// if the edit is invalid.
    pub fn set_cell_value(&mut self, row: usize, col: usize, value: &str) -> Option<(String, String)> {
        if col != self.name_column_index {
            return None;
        }
        if !(value.is_ascii() && !value.is_empty()) {
            return None;
        }
        let eq = self.equates.get(row)?;
        if eq.name == value {
            return None; // no change
        }
        let old_name = eq.name.clone();
        Some((old_name, value.to_string()))
    }

    // -------------------------------------------------------------------
    // Sorting
    // -------------------------------------------------------------------

    /// Set the sort column and order.
    pub fn set_sort(&mut self, column: usize, order: SortOrder) {
        self.sort_column = column;
        self.sort_order = order;
        self.apply_sort();
    }

    /// Get the current sort column.
    pub fn sort_column(&self) -> usize {
        self.sort_column
    }

    /// Get the current sort order.
    pub fn sort_order(&self) -> SortOrder {
        self.sort_order
    }

    fn apply_sort(&mut self) {
        let col = self.sort_column;
        let ascending = self.sort_order == SortOrder::Ascending;

        self.equates.sort_by(|a, b| {
            let ord = match col {
                equate_columns::NAME => a.name.cmp(&b.name),
                equate_columns::VALUE => a.value.cmp(&b.value),
                equate_columns::REFS => a.reference_count().cmp(&b.reference_count()),
                equate_columns::IS_ENUM_BASED => a.is_enum_based.cmp(&b.is_enum_based),
                _ => Ordering::Equal,
            };
            if ascending {
                ord
            } else {
                ord.reverse()
            }
        });
    }

    // -------------------------------------------------------------------
    // Filtering
    // -------------------------------------------------------------------

    /// Set the filter text.
    pub fn set_filter(&mut self, filter: Option<String>) {
        self.filter_text = filter;
    }

    /// Get the current filter text.
    pub fn filter_text(&self) -> Option<&str> {
        self.filter_text.as_deref()
    }

    /// Get the display name of the table.
    pub fn name(&self) -> &str {
        "Equates"
    }
}

impl Default for EquateTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// EquateReferenceTableModel
// ============================================================================

/// Data model for the equate references sub-table.
///
/// Corresponds to `EquateReferenceTableModel` in Java. Displays the
/// address and operand index of all references to a selected equate.
#[derive(Debug, Clone)]
pub struct EquateReferenceTableModel {
    /// The references being displayed.
    references: Vec<EquateReference>,
    /// The column definitions.
    columns: Vec<ReferenceColumnDef>,
}

/// Column definition for the reference table.
#[derive(Debug, Clone)]
pub struct ReferenceColumnDef {
    /// Column name.
    pub name: String,
    /// Column index.
    pub index: usize,
}

/// Column indices in the reference table.
pub mod reference_columns {
    /// Address column.
    pub const ADDRESS: usize = 0;
    /// Operand index column.
    pub const OP_INDEX: usize = 1;
}

impl EquateReferenceTableModel {
    /// Create a new model.
    pub fn new() -> Self {
        Self {
            references: Vec::new(),
            columns: vec![
                ReferenceColumnDef {
                    name: "Ref Addr".to_string(),
                    index: reference_columns::ADDRESS,
                },
                ReferenceColumnDef {
                    name: "Op Index".to_string(),
                    index: reference_columns::OP_INDEX,
                },
            ],
        }
    }

    /// Set the equate whose references are displayed.
    pub fn set_equate(&mut self, table: &EquateTable, equate_name: Option<&str>) {
        self.references.clear();
        if let Some(name) = equate_name {
            if let Some(eq) = table.get_equate(name) {
                self.references = eq.references.clone();
            }
        }
    }

    /// Get the number of rows.
    pub fn row_count(&self) -> usize {
        self.references.len()
    }

    /// Get the number of columns.
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    /// Get a cell value by row and column index.
    pub fn cell_value(&self, row: usize, col: usize) -> Option<String> {
        let ref_entry = self.references.get(row)?;
        match col {
            reference_columns::ADDRESS => Some(format!("0x{:x}", ref_entry.address.offset)),
            reference_columns::OP_INDEX => Some(ref_entry.op_index.to_string()),
            _ => None,
        }
    }

    /// Get the reference at a row.
    pub fn get_reference(&self, row: usize) -> Option<&EquateReference> {
        self.references.get(row)
    }

    /// Get the display name.
    pub fn name(&self) -> &str {
        "Equate References"
    }

    /// Get the program location for navigation (address + operand index).
    pub fn get_program_location(&self, row: usize) -> Option<(Address, i32)> {
        self.references
            .get(row)
            .map(|r| (r.address, r.op_index))
    }

    /// Get the program selection for a set of rows.
    pub fn get_program_selection(&self, rows: &[usize]) -> Vec<Address> {
        rows.iter()
            .filter_map(|&row| self.references.get(row))
            .map(|r| r.address)
            .collect()
    }
}

impl Default for EquateReferenceTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::manager::EquateTable;

    fn make_table_with_equates() -> EquateTable {
        let mut table = EquateTable::new();
        table.create_equate("ALPHA", 10).unwrap();
        table.create_equate("BETA", 20).unwrap();
        table.create_equate("GAMMA", 30).unwrap();
        table.add_reference("ALPHA", Address::new(0x1000), 0);
        table.add_reference("ALPHA", Address::new(0x2000), 1);
        table.add_reference("BETA", Address::new(0x3000), 0);
        table
    }

    // ---------------------------------------------------------------
    // EquateTableModel tests
    // ---------------------------------------------------------------

    #[test]
    fn test_model_creation() {
        let model = EquateTableModel::new();
        assert_eq!(model.row_count(), 0);
        assert_eq!(model.visible_column_count(), 3); // NAME, VALUE, REFS
        assert_eq!(model.name(), "Equates");
    }

    #[test]
    fn test_model_update() {
        let table = make_table_with_equates();
        let mut model = EquateTableModel::new();
        model.update(&table);
        assert_eq!(model.row_count(), 3);
    }

    #[test]
    fn test_model_cell_values() {
        let table = make_table_with_equates();
        let mut model = EquateTableModel::new();
        model.update(&table);

        // Sorted by name (default): ALPHA, BETA, GAMMA
        assert_eq!(model.cell_value(0, 0).unwrap(), "ALPHA");
        assert_eq!(model.cell_value(1, 0).unwrap(), "BETA");
        assert_eq!(model.cell_value(2, 0).unwrap(), "GAMMA");

        // Value column
        assert_eq!(model.cell_value(0, 1).unwrap(), "0xa");
        assert_eq!(model.cell_value(1, 1).unwrap(), "0x14");

        // Ref count column
        assert_eq!(model.cell_value(0, 2).unwrap(), "2"); // ALPHA has 2 refs
        assert_eq!(model.cell_value(1, 2).unwrap(), "1"); // BETA has 1 ref
    }

    #[test]
    fn test_model_get_equate() {
        let table = make_table_with_equates();
        let mut model = EquateTableModel::new();
        model.update(&table);

        let eq = model.get_equate(0).unwrap();
        assert_eq!(eq.name, "ALPHA");
    }

    #[test]
    fn test_model_sort_by_value() {
        let table = make_table_with_equates();
        let mut model = EquateTableModel::new();
        model.update(&table);

        // Sort by value descending
        model.set_sort(equate_columns::VALUE, SortOrder::Descending);
        assert_eq!(model.cell_value(0, 0).unwrap(), "GAMMA"); // 30
        assert_eq!(model.cell_value(1, 0).unwrap(), "BETA"); // 20
        assert_eq!(model.cell_value(2, 0).unwrap(), "ALPHA"); // 10
    }

    #[test]
    fn test_model_sort_by_ref_count() {
        let table = make_table_with_equates();
        let mut model = EquateTableModel::new();
        model.update(&table);

        // Sort by ref count ascending
        model.set_sort(equate_columns::REFS, SortOrder::Ascending);
        // GAMMA (0 refs), BETA (1 ref), ALPHA (2 refs)
        assert_eq!(model.cell_value(0, 0).unwrap(), "GAMMA");
        assert_eq!(model.cell_value(1, 0).unwrap(), "BETA");
        assert_eq!(model.cell_value(2, 0).unwrap(), "ALPHA");
    }

    #[test]
    fn test_model_sort_order() {
        let table = make_table_with_equates();
        let mut model = EquateTableModel::new();
        model.update(&table);

        model.set_sort(equate_columns::NAME, SortOrder::Ascending);
        assert_eq!(model.sort_order(), SortOrder::Ascending);
        assert_eq!(model.sort_column(), equate_columns::NAME);
        assert_eq!(model.cell_value(0, 0).unwrap(), "ALPHA");
        assert_eq!(model.cell_value(2, 0).unwrap(), "GAMMA");

        model.set_sort(equate_columns::NAME, SortOrder::Descending);
        assert_eq!(model.cell_value(0, 0).unwrap(), "GAMMA");
        assert_eq!(model.cell_value(2, 0).unwrap(), "ALPHA");
    }

    #[test]
    fn test_model_editable_name_user_defined() {
        let table = make_table_with_equates();
        let mut model = EquateTableModel::new();
        model.update(&table);

        // User-defined equates should be editable.
        assert!(model.is_cell_editable(0, equate_columns::NAME));
        // Non-name columns should not be editable.
        assert!(!model.is_cell_editable(0, equate_columns::VALUE));
    }

    #[test]
    fn test_model_editable_name_enum_based() {
        let mut table = EquateTable::new();
        table
            .create_equate(
                &super::super::manager::EquateManager::format_name_for_equate("uuid", 1),
                1,
            )
            .unwrap();

        let mut model = EquateTableModel::new();
        model.update(&table);

        // Enum-based equates should NOT be editable.
        assert!(!model.is_cell_editable(0, equate_columns::NAME));
    }

    #[test]
    fn test_model_set_cell_value() {
        let table = make_table_with_equates();
        let mut model = EquateTableModel::new();
        model.update(&table);

        // Valid rename
        let result = model.set_cell_value(0, equate_columns::NAME, "NEW_NAME");
        assert!(result.is_some());
        let (old, new) = result.unwrap();
        assert_eq!(old, "ALPHA");
        assert_eq!(new, "NEW_NAME");

        // Same name -> no change
        let result = model.set_cell_value(0, equate_columns::VALUE, "0xa");
        assert!(result.is_none());
    }

    #[test]
    fn test_model_filter() {
        let mut model = EquateTableModel::new();
        assert!(model.filter_text().is_none());
        model.set_filter(Some("test".to_string()));
        assert_eq!(model.filter_text(), Some("test"));
    }

    #[test]
    fn test_model_columns() {
        let model = EquateTableModel::new();
        let cols = model.columns();
        assert_eq!(cols.len(), 4);
        assert_eq!(cols[0].name, "Name");
        assert!(cols[0].visible);
        assert!(!cols[3].visible); // IsEnumBased is hidden
    }

    #[test]
    fn test_model_empty_update() {
        let table = EquateTable::new();
        let mut model = EquateTableModel::new();
        model.update(&table);
        assert_eq!(model.row_count(), 0);
    }

    // ---------------------------------------------------------------
    // EquateReferenceTableModel tests
    // ---------------------------------------------------------------

    #[test]
    fn test_ref_model_creation() {
        let model = EquateReferenceTableModel::new();
        assert_eq!(model.row_count(), 0);
        assert_eq!(model.column_count(), 2);
        assert_eq!(model.name(), "Equate References");
    }

    #[test]
    fn test_ref_model_set_equate() {
        let table = make_table_with_equates();
        let mut model = EquateReferenceTableModel::new();
        model.set_equate(&table, Some("ALPHA"));
        assert_eq!(model.row_count(), 2);
    }

    #[test]
    fn test_ref_model_set_equate_none() {
        let table = make_table_with_equates();
        let mut model = EquateReferenceTableModel::new();
        model.set_equate(&table, Some("ALPHA"));
        model.set_equate(&table, None);
        assert_eq!(model.row_count(), 0);
    }

    #[test]
    fn test_ref_model_cell_values() {
        let table = make_table_with_equates();
        let mut model = EquateReferenceTableModel::new();
        model.set_equate(&table, Some("ALPHA"));

        // References are stored in insertion order.
        assert_eq!(model.cell_value(0, 0).unwrap(), "0x1000");
        assert_eq!(model.cell_value(0, 1).unwrap(), "0");
        assert_eq!(model.cell_value(1, 0).unwrap(), "0x2000");
        assert_eq!(model.cell_value(1, 1).unwrap(), "1");
    }

    #[test]
    fn test_ref_model_get_reference() {
        let table = make_table_with_equates();
        let mut model = EquateReferenceTableModel::new();
        model.set_equate(&table, Some("ALPHA"));

        let ref_entry = model.get_reference(0).unwrap();
        assert_eq!(ref_entry.address, Address::new(0x1000));
        assert_eq!(ref_entry.op_index, 0);
    }

    #[test]
    fn test_ref_model_get_program_location() {
        let table = make_table_with_equates();
        let mut model = EquateReferenceTableModel::new();
        model.set_equate(&table, Some("ALPHA"));

        let (addr, op_idx) = model.get_program_location(1).unwrap();
        assert_eq!(addr, Address::new(0x2000));
        assert_eq!(op_idx, 1);
    }

    #[test]
    fn test_ref_model_get_program_selection() {
        let table = make_table_with_equates();
        let mut model = EquateReferenceTableModel::new();
        model.set_equate(&table, Some("ALPHA"));

        let addrs = model.get_program_selection(&[0, 1]);
        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains(&Address::new(0x1000)));
        assert!(addrs.contains(&Address::new(0x2000)));
    }

    #[test]
    fn test_ref_model_nonexistent_equate() {
        let table = EquateTable::new();
        let mut model = EquateReferenceTableModel::new();
        model.set_equate(&table, Some("NONEXISTENT"));
        assert_eq!(model.row_count(), 0);
    }

    // ---------------------------------------------------------------
    // Column trait tests
    // ---------------------------------------------------------------

    #[test]
    fn test_equate_name_column() {
        let col = EquateNameColumn;
        assert_eq!(col.name(), "Name");
        let eq = super::super::EquateValue::new("TEST", 42);
        assert_eq!(col.display_value(&eq), "TEST");
        assert!(col.is_visible());
    }

    #[test]
    fn test_equate_value_column() {
        let col = EquateValueColumn;
        assert_eq!(col.name(), "Value");
        let eq = super::super::EquateValue::new("TEST", 0xFF);
        assert_eq!(col.display_value(&eq), "0xff");
        // Filter string includes both hex and decimal
        assert_eq!(col.filter_string(&eq), "ff 255");
    }

    #[test]
    fn test_equate_ref_count_column() {
        let col = EquateRefCountColumn;
        assert_eq!(col.name(), "# Refs");
        let mut eq = super::super::EquateValue::new("TEST", 42);
        eq.add_reference(Address::new(0x1000), 0);
        assert_eq!(col.display_value(&eq), "1");
    }

    #[test]
    fn test_is_enum_based_column() {
        let col = IsEnumBasedColumn;
        assert_eq!(col.name(), "Is Enum-Based");
        assert!(!col.is_visible());
        let eq = super::super::EquateValue::new("TEST", 42);
        assert_eq!(col.display_value(&eq), "false");
    }

    #[test]
    fn test_reference_address_column() {
        let col = ReferenceAddressColumn;
        assert_eq!(col.name(), "Ref Addr");
        let ref_entry = EquateReference::new(Address::new(0x4000), 0);
        assert_eq!(col.display_value(&ref_entry), "0x4000");
    }

    #[test]
    fn test_reference_op_index_column() {
        let col = ReferenceOpIndexColumn;
        assert_eq!(col.name(), "Op Index");
        let ref_entry = EquateReference::new(Address::new(0x4000), 3);
        assert_eq!(col.display_value(&ref_entry), "3");
    }

    // ---------------------------------------------------------------
    // SortOrder tests
    // ---------------------------------------------------------------

    #[test]
    fn test_sort_order_default() {
        assert_eq!(SortOrder::default(), SortOrder::Ascending);
    }

    #[test]
    fn test_sort_order_equality() {
        assert_eq!(SortOrder::Ascending, SortOrder::Ascending);
        assert_ne!(SortOrder::Ascending, SortOrder::Descending);
    }
}
