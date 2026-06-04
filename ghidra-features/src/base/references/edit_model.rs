//! Table model for displaying and editing references from a code unit.
//!
//! Ported from `EditReferencesModel`. Provides column definitions, row
//! access, and editable-cell logic for the references table.

use ghidra_core::addr::Address;
use ghidra_core::symbol::{RefType, Reference, SourceType, MNEMONIC};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Column indices for the references table model.
pub mod column {
    /// Operand index column.
    pub const OPERAND: usize = 0;
    /// Destination address column.
    pub const LOCATION: usize = 1;
    /// Label/display name column.
    pub const LABEL: usize = 2;
    /// Reference type column.
    pub const REF_TYPE: usize = 3;
    /// Is-primary flag column.
    pub const IS_PRIMARY: usize = 4;
    /// Source type column.
    pub const REF_SOURCE: usize = 5;
}

/// Column names for the references table model.
pub const REFERENCE_COLUMNS: &[&str] = &[
    "Operand", "Destination", "Label", "Ref-Type", "Primary?", "Source",
];

/// The default sort column index.
pub const DEFAULT_SORT_COL: usize = column::OPERAND;

/// A single row in the references table, wrapping a [`Reference`] with
/// display-oriented helpers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceRow {
    /// The underlying reference.
    pub reference: Reference,
    /// A human-readable label for the destination (resolved symbol name or
    /// formatted address).
    pub label: String,
}

impl ReferenceRow {
    /// Create a row from a reference and a pre-formatted label.
    pub fn new(reference: Reference, label: String) -> Self {
        Self { reference, label }
    }

    /// Returns the operand display string ("MNEMONIC" or "OP-N").
    pub fn operand_display(&self) -> String {
        let op = self.reference.get_operand_index();
        if op == MNEMONIC {
            "MNEMONIC".to_string()
        } else {
            format!("OP-{}", op)
        }
    }

    /// Returns the destination address.
    pub fn to_address(&self) -> &Address {
        self.reference.get_to_address()
    }

    /// Returns the reference type.
    pub fn ref_type(&self) -> RefType {
        self.reference.get_reference_type()
    }

    /// Returns whether this is the primary reference.
    pub fn is_primary(&self) -> bool {
        self.reference.is_primary()
    }

    /// Returns the source type.
    pub fn source(&self) -> SourceType {
        self.reference.get_source()
    }
}

impl fmt::Display for ReferenceRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} -> {} [{}]",
            self.operand_display(),
            self.to_address(),
            self.ref_type()
        )
    }
}

/// The references table model.
///
/// Manages the list of references from a single code unit and supports
/// querying, sorting, and modification of rows.
#[derive(Debug, Clone)]
pub struct EditReferencesModel {
    /// Column names.
    columns: Vec<String>,
    /// The current rows.
    rows: Vec<ReferenceRow>,
    /// The default sort column.
    sort_column: usize,
}

impl Default for EditReferencesModel {
    fn default() -> Self {
        Self::new()
    }
}

impl EditReferencesModel {
    /// Create a new empty references model.
    pub fn new() -> Self {
        Self {
            columns: REFERENCE_COLUMNS.iter().map(|s| s.to_string()).collect(),
            rows: Vec::new(),
            sort_column: DEFAULT_SORT_COL,
        }
    }

    /// Replace the model data with references from a code unit.
    ///
    /// In the Java version this calls `cu.getReferencesFrom()`. Here we
    /// accept pre-built references and labels.
    pub fn set_references(&mut self, refs: Vec<ReferenceRow>) {
        self.rows = refs;
        self.sort_rows();
    }

    /// Clear all references.
    pub fn clear(&mut self) {
        self.rows.clear();
    }

    /// Returns the number of columns.
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    /// Returns the number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Returns the column name at the given index.
    pub fn column_name(&self, col: usize) -> &str {
        &self.columns[col]
    }

    /// Returns a reference to the row at the given index.
    pub fn get_row(&self, row: usize) -> Option<&ReferenceRow> {
        self.rows.get(row)
    }

    /// Returns a mutable reference to the row at the given index.
    pub fn get_row_mut(&mut self, row: usize) -> Option<&mut ReferenceRow> {
        self.rows.get_mut(row)
    }

    /// Returns the cell value for display purposes.
    pub fn get_cell_value(&self, row: usize, col: usize) -> Option<String> {
        let r = self.rows.get(row)?;
        Some(match col {
            column::OPERAND => r.operand_display(),
            column::LOCATION => r.to_address().to_string(),
            column::LABEL => r.label.clone(),
            column::REF_TYPE => r.ref_type().name().to_string(),
            column::IS_PRIMARY => r.is_primary().to_string(),
            column::REF_SOURCE => r.source().display_string().to_string(),
            _ => return None,
        })
    }

    /// Returns `true` if the cell at the given position is editable.
    ///
    /// Only the REF_TYPE and IS_PRIMARY columns are editable, and only for
    /// memory or external addresses.
    pub fn is_cell_editable(&self, row: usize, col: usize) -> bool {
        let r = match self.rows.get(row) {
            Some(r) => r,
            None => return false,
        };
        if col == column::IS_PRIMARY || col == column::REF_TYPE {
            let to_addr = r.to_address();
            if to_addr.is_memory_address() {
                return true;
            }
            if col == column::REF_TYPE {
                return true;
            }
        }
        false
    }

    /// Returns the row index containing the specified reference, or -1 if
    /// not found.
    pub fn find_row(&self, ref_data: &Reference) -> Option<usize> {
        self.rows
            .iter()
            .position(|r| r.reference == *ref_data)
    }

    /// Returns a clone of the reference at the given row, or None.
    pub fn get_reference(&self, row: usize) -> Option<Reference> {
        self.rows.get(row).map(|r| r.reference.clone())
    }

    /// Sort rows by the current sort column.
    fn sort_rows(&mut self) {
        self.rows.sort_by(|a, b| match self.sort_column {
            column::OPERAND => a
                .reference
                .get_operand_index()
                .cmp(&b.reference.get_operand_index()),
            column::LOCATION => a.to_address().cmp(b.to_address()),
            column::LABEL => a.label.cmp(&b.label),
            column::REF_TYPE => a
                .ref_type()
                .name()
                .cmp(b.ref_type().name()),
            column::IS_PRIMARY => a.is_primary().cmp(&b.is_primary()),
            column::REF_SOURCE => a
                .source()
                .display_string()
                .cmp(b.source().display_string()),
            _ => std::cmp::Ordering::Equal,
        });
    }

    /// Set the sort column and re-sort.
    pub fn set_sort_column(&mut self, col: usize) {
        if col < self.columns.len() {
            self.sort_column = col;
            self.sort_rows();
        }
    }

    /// Returns the allowed reference types for a given reference, based on
    /// destination address properties.
    pub fn get_allowed_ref_types(&self, row: usize) -> Option<&'static [RefType]> {
        let r = self.rows.get(row)?;
        let to_addr = r.to_address();
        Some(
            crate::base::references::ref_type_factory::RefTypeFactory::get_allowed_ref_types(
                to_addr.is_memory_address(),
                to_addr.is_stack_address(),
                to_addr.is_register_address(),
                to_addr.is_external_address(),
                false,
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::symbol::DataRefType;

    fn make_ref(from: u64, to: u64, op: i32) -> Reference {
        Reference::new(
            Address::new(from),
            Address::new(to),
            RefType::Data(DataRefType::Data),
            op,
        )
    }

    #[test]
    fn test_model_column_count() {
        let model = EditReferencesModel::new();
        assert_eq!(model.column_count(), 6);
    }

    #[test]
    fn test_model_column_names() {
        let model = EditReferencesModel::new();
        assert_eq!(model.column_name(0), "Operand");
        assert_eq!(model.column_name(5), "Source");
    }

    #[test]
    fn test_model_set_references() {
        let mut model = EditReferencesModel::new();
        let refs = vec![
            ReferenceRow::new(make_ref(0x1000, 0x2000, 0), "target".to_string()),
            ReferenceRow::new(make_ref(0x1000, 0x3000, 1), "other".to_string()),
        ];
        model.set_references(refs);
        assert_eq!(model.row_count(), 2);
    }

    #[test]
    fn test_model_get_cell_value() {
        let mut model = EditReferencesModel::new();
        let refs = vec![ReferenceRow::new(
            make_ref(0x1000, 0x2000, 0),
            "my_label".to_string(),
        )];
        model.set_references(refs);
        assert_eq!(model.get_cell_value(0, column::OPERAND).unwrap(), "OP-0");
        assert_eq!(model.get_cell_value(0, column::LABEL).unwrap(), "my_label");
    }

    #[test]
    fn test_model_mnemonic_operand() {
        let mut model = EditReferencesModel::new();
        let refs = vec![ReferenceRow::new(
            make_ref(0x1000, 0x2000, MNEMONIC),
            "label".to_string(),
        )];
        model.set_references(refs);
        assert_eq!(
            model.get_cell_value(0, column::OPERAND).unwrap(),
            "MNEMONIC"
        );
    }

    #[test]
    fn test_model_is_cell_editable_primary() {
        let mut model = EditReferencesModel::new();
        let refs = vec![ReferenceRow::new(
            make_ref(0x1000, 0x2000, 0),
            "label".to_string(),
        )];
        model.set_references(refs);
        // Memory addresses allow editing IS_PRIMARY
        assert!(model.is_cell_editable(0, column::IS_PRIMARY));
        // Non-existent row
        assert!(!model.is_cell_editable(99, column::IS_PRIMARY));
    }

    #[test]
    fn test_model_find_row() {
        let mut model = EditReferencesModel::new();
        let r = make_ref(0x1000, 0x2000, 0);
        let refs = vec![ReferenceRow::new(r.clone(), "label".to_string())];
        model.set_references(refs);
        assert_eq!(model.find_row(&r), Some(0));
        assert_eq!(model.find_row(&make_ref(0x5000, 0x6000, 0)), None);
    }

    #[test]
    fn test_model_sort() {
        let mut model = EditReferencesModel::new();
        let refs = vec![
            ReferenceRow::new(make_ref(0x1000, 0x3000, 1), "b".to_string()),
            ReferenceRow::new(make_ref(0x1000, 0x2000, 0), "a".to_string()),
        ];
        model.set_references(refs);
        // Default sort is by operand index
        assert_eq!(
            model.get_cell_value(0, column::OPERAND).unwrap(),
            "OP-0"
        );
        assert_eq!(
            model.get_cell_value(1, column::OPERAND).unwrap(),
            "OP-1"
        );
    }

    #[test]
    fn test_model_clear() {
        let mut model = EditReferencesModel::new();
        let refs = vec![ReferenceRow::new(
            make_ref(0x1000, 0x2000, 0),
            "label".to_string(),
        )];
        model.set_references(refs);
        assert_eq!(model.row_count(), 1);
        model.clear();
        assert_eq!(model.row_count(), 0);
    }

    #[test]
    fn test_reference_row_display() {
        let row = ReferenceRow::new(
            make_ref(0x1000, 0x2000, 0),
            "target".to_string(),
        );
        let display = format!("{}", row);
        assert!(display.contains("OP-0"));
    }
}
