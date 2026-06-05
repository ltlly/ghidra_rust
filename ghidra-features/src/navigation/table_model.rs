//! Table model for the location references display.
//!
//! Ported from `ghidra.app.plugin.core.navigation.locationreferences.LocationReferencesTableModel`
//! and related table row mapper types.

use std::collections::BTreeMap;

use ghidra_core::Address;

use super::locationreferences::{LocationReference, DescriptorKind};

// ---------------------------------------------------------------------------
// LocationReferencesTableModel
// ---------------------------------------------------------------------------

/// Table model for displaying location references in a table view.
///
/// Ported from `ghidra.app.plugin.core.navigation.locationreferences.LocationReferencesTableModel`.
#[derive(Debug)]
pub struct LocationReferencesTableModel {
    /// The references being displayed.
    references: Vec<LocationReference>,
    /// Column definitions.
    columns: Vec<ColumnDef>,
    /// Sort column index.
    sort_column: usize,
    /// Sort ascending.
    sort_ascending: bool,
    /// Filter text.
    filter_text: String,
    /// Whether the model is disposed.
    disposed: bool,
}

/// A column definition in the references table.
#[derive(Debug, Clone)]
pub struct ColumnDef {
    /// Column name.
    pub name: String,
    /// Column width hint.
    pub width: usize,
    /// Whether the column is sortable.
    pub sortable: bool,
}

impl ColumnDef {
    /// Create a new column definition.
    pub fn new(name: impl Into<String>, width: usize, sortable: bool) -> Self {
        Self {
            name: name.into(),
            width,
            sortable,
        }
    }
}

impl LocationReferencesTableModel {
    /// Column index for the address column.
    pub const ADDRESS_COL: usize = 0;
    /// Column index for the reference type column.
    pub const REF_TYPE_COL: usize = 1;
    /// Column index for the label column.
    pub const LABEL_COL: usize = 2;
    /// Column index for the offcut column.
    pub const OFFCUT_COL: usize = 3;

    /// Default column definitions.
    pub fn default_columns() -> Vec<ColumnDef> {
        vec![
            ColumnDef::new("Address", 120, true),
            ColumnDef::new("Ref Type", 80, true),
            ColumnDef::new("Label", 200, true),
            ColumnDef::new("Offcut", 60, true),
        ]
    }

    /// Create a new table model.
    pub fn new() -> Self {
        Self {
            references: Vec::new(),
            columns: Self::default_columns(),
            sort_column: Self::ADDRESS_COL,
            sort_ascending: true,
            filter_text: String::new(),
            disposed: false,
        }
    }

    /// Create a table model with specific column definitions.
    pub fn with_columns(columns: Vec<ColumnDef>) -> Self {
        Self {
            references: Vec::new(),
            columns,
            sort_column: 0,
            sort_ascending: true,
            filter_text: String::new(),
            disposed: false,
        }
    }

    /// Set the references.
    pub fn set_references(&mut self, refs: Vec<LocationReference>) {
        self.references = refs;
        self.apply_sort();
    }

    /// Get the references.
    pub fn references(&self) -> &[LocationReference] {
        &self.references
    }

    /// Number of rows.
    pub fn row_count(&self) -> usize {
        self.references.len()
    }

    /// Number of columns.
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    /// Get a column definition.
    pub fn column(&self, index: usize) -> Option<&ColumnDef> {
        self.columns.get(index)
    }

    /// Get all column definitions.
    pub fn columns(&self) -> &[ColumnDef] {
        &self.columns
    }

    /// Get the cell value as a string.
    pub fn get_cell_value(&self, row: usize, col: usize) -> Option<String> {
        let reference = self.references.get(row)?;
        match col {
            Self::ADDRESS_COL => Some(format!("{}", reference.location_of_use())),
            Self::REF_TYPE_COL => Some(reference.ref_type_string().to_string()),
            Self::LABEL_COL => Some(reference.field_name().unwrap_or("").to_string()),
            Self::OFFCUT_COL => Some(if reference.is_offcut_reference() {
                "Yes".into()
            } else {
                "No".into()
            }),
            _ => None,
        }
    }

    /// Get the address at a given row.
    pub fn get_address(&self, row: usize) -> Option<Address> {
        self.references.get(row).map(|r| r.location_of_use())
    }

    /// Get the reference at a given row.
    pub fn get_reference(&self, row: usize) -> Option<&LocationReference> {
        self.references.get(row)
    }

    /// Sort by a column.
    pub fn sort_by_column(&mut self, column: usize) {
        if column == self.sort_column {
            self.sort_ascending = !self.sort_ascending;
        } else {
            self.sort_column = column;
            self.sort_ascending = true;
        }
        self.apply_sort();
    }

    fn apply_sort(&mut self) {
        let ascending = self.sort_ascending;
        let col = self.sort_column;
        self.references.sort_by(|a, b| {
            let cmp = match col {
                Self::ADDRESS_COL => a.location_of_use().cmp(&b.location_of_use()),
                Self::REF_TYPE_COL => a.ref_type_string().cmp(b.ref_type_string()),
                Self::LABEL_COL => {
                    let la = a.field_name().unwrap_or("");
                    let lb = b.field_name().unwrap_or("");
                    la.cmp(lb)
                }
                Self::OFFCUT_COL => a.is_offcut_reference().cmp(&b.is_offcut_reference()),
                _ => std::cmp::Ordering::Equal,
            };
            if ascending {
                cmp
            } else {
                cmp.reverse()
            }
        });
    }

    /// Set a filter text that restricts visible rows.
    pub fn set_filter(&mut self, filter: impl Into<String>) {
        self.filter_text = filter.into();
    }

    /// Get the filter text.
    pub fn filter_text(&self) -> &str {
        &self.filter_text
    }

    /// Whether the model is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Dispose of the model.
    pub fn dispose(&mut self) {
        self.references.clear();
        self.disposed = true;
    }

    /// Get a summary of the references.
    pub fn summary(&self) -> ReferenceSummary {
        let total = self.references.len();
        let offcuts = self.references.iter().filter(|r| r.is_offcut_reference()).count();
        let mut by_type: BTreeMap<String, usize> = BTreeMap::new();
        for r in &self.references {
            *by_type.entry(r.ref_type_string().to_string()).or_insert(0) += 1;
        }
        ReferenceSummary {
            total,
            offcuts,
            by_type,
        }
    }
}

impl Default for LocationReferencesTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ReferenceSummary
// ---------------------------------------------------------------------------

/// Summary statistics for a set of references.
#[derive(Debug, Clone)]
pub struct ReferenceSummary {
    /// Total number of references.
    pub total: usize,
    /// Number of offcut references.
    pub offcuts: usize,
    /// Count of references by type.
    pub by_type: BTreeMap<String, usize>,
}

// ---------------------------------------------------------------------------
// Table row mappers
// ---------------------------------------------------------------------------

/// Maps a `LocationReference` to a table row address.
///
/// Ported from `LocationReferenceToAddressTableRowMapper`.
#[derive(Debug)]
pub struct LocationReferenceToAddressTableRowMapper;

impl LocationReferenceToAddressTableRowMapper {
    /// Get the address from a reference for table display.
    pub fn get_row_address(reference: &LocationReference) -> Address {
        reference.location_of_use()
    }
}

/// Maps a `LocationReference` to the function containing it.
///
/// Ported from `LocationReferenceToFunctionContainingTableRowMapper`.
#[derive(Debug)]
pub struct LocationReferenceToFunctionContainingTableRowMapper {
    /// Maps addresses to their containing function names.
    address_to_function: BTreeMap<Address, String>,
}

impl LocationReferenceToFunctionContainingTableRowMapper {
    /// Create a new mapper.
    pub fn new() -> Self {
        Self {
            address_to_function: BTreeMap::new(),
        }
    }

    /// Register an address-to-function mapping.
    pub fn register(&mut self, address: Address, function_name: impl Into<String>) {
        self.address_to_function.insert(address, function_name.into());
    }

    /// Get the containing function name for a reference.
    pub fn get_containing_function(&self, reference: &LocationReference) -> Option<&str> {
        self.address_to_function
            .get(&reference.location_of_use())
            .map(|s| s.as_str())
    }
}

impl Default for LocationReferenceToFunctionContainingTableRowMapper {
    fn default() -> Self {
        Self::new()
    }
}

/// Maps a `LocationReference` to a program location for table display.
///
/// Ported from `LocationReferenceToProgramLocationTableRowMapper`.
#[derive(Debug)]
pub struct LocationReferenceToProgramLocationTableRowMapper;

impl LocationReferenceToProgramLocationTableRowMapper {
    /// Get the display string for a reference in the program location context.
    pub fn get_display_string(reference: &LocationReference) -> String {
        format!(
            "{} {}",
            reference.location_of_use(),
            reference.ref_type_string()
        )
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    fn sample_refs() -> Vec<LocationReference> {
        vec![
            LocationReference::with_ref_type(addr(0x3000), "READ", false),
            LocationReference::with_ref_type(addr(0x1000), "WRITE", false),
            LocationReference::with_ref_type(addr(0x2000), "CALL", true),
        ]
    }

    #[test]
    fn test_table_model_creation() {
        let model = LocationReferencesTableModel::new();
        assert_eq!(model.row_count(), 0);
        assert_eq!(model.column_count(), 4);
        assert!(!model.is_disposed());
    }

    #[test]
    fn test_table_model_set_references() {
        let mut model = LocationReferencesTableModel::new();
        model.set_references(sample_refs());
        assert_eq!(model.row_count(), 3);
    }

    #[test]
    fn test_table_model_get_cell_value() {
        let mut model = LocationReferencesTableModel::new();
        model.set_references(vec![
            LocationReference::with_ref_type(addr(0x1000), "READ", false),
        ]);

        let addr_val = model.get_cell_value(0, LocationReferencesTableModel::ADDRESS_COL);
        assert!(addr_val.is_some());

        let ref_type = model.get_cell_value(0, LocationReferencesTableModel::REF_TYPE_COL).unwrap();
        assert_eq!(ref_type, "READ");
    }

    #[test]
    fn test_table_model_sort_by_address() {
        let mut model = LocationReferencesTableModel::new();
        model.set_references(sample_refs());

        // Default sort is by address, ascending
        assert_eq!(model.get_address(0), Some(addr(0x1000)));
        assert_eq!(model.get_address(1), Some(addr(0x2000)));
        assert_eq!(model.get_address(2), Some(addr(0x3000)));

        // Toggle to descending
        model.sort_by_column(LocationReferencesTableModel::ADDRESS_COL);
        assert_eq!(model.get_address(0), Some(addr(0x3000)));
    }

    #[test]
    fn test_table_model_sort_by_ref_type() {
        let mut model = LocationReferencesTableModel::new();
        model.set_references(sample_refs());

        model.sort_by_column(LocationReferencesTableModel::REF_TYPE_COL);
        let first = model.get_cell_value(0, LocationReferencesTableModel::REF_TYPE_COL).unwrap();
        assert_eq!(first, "CALL");
    }

    #[test]
    fn test_table_model_get_address() {
        let mut model = LocationReferencesTableModel::new();
        model.set_references(sample_refs());
        assert!(model.get_address(0).is_some());
        assert!(model.get_address(99).is_none());
    }

    #[test]
    fn test_table_model_dispose() {
        let mut model = LocationReferencesTableModel::new();
        model.set_references(sample_refs());
        model.dispose();
        assert!(model.is_disposed());
        assert_eq!(model.row_count(), 0);
    }

    #[test]
    fn test_table_model_summary() {
        let mut model = LocationReferencesTableModel::new();
        model.set_references(sample_refs());
        let summary = model.summary();
        assert_eq!(summary.total, 3);
        assert_eq!(summary.offcuts, 1);
        assert_eq!(summary.by_type["READ"], 1);
        assert_eq!(summary.by_type["WRITE"], 1);
        assert_eq!(summary.by_type["CALL"], 1);
    }

    #[test]
    fn test_column_def() {
        let col = ColumnDef::new("Address", 120, true);
        assert_eq!(col.name, "Address");
        assert_eq!(col.width, 120);
        assert!(col.sortable);
    }

    #[test]
    fn test_address_mapper() {
        let reference = LocationReference::new(addr(0x1000));
        let address = LocationReferenceToAddressTableRowMapper::get_row_address(&reference);
        assert_eq!(address, addr(0x1000));
    }

    #[test]
    fn test_function_containing_mapper() {
        let mut mapper = LocationReferenceToFunctionContainingTableRowMapper::new();
        mapper.register(addr(0x1000), "main");
        mapper.register(addr(0x2000), "init");

        let reference = LocationReference::new(addr(0x1000));
        assert_eq!(mapper.get_containing_function(&reference), Some("main"));

        let unknown = LocationReference::new(addr(0x3000));
        assert_eq!(mapper.get_containing_function(&unknown), None);
    }

    #[test]
    fn test_program_location_mapper() {
        let reference = LocationReference::with_ref_type(addr(0x1000), "READ", false);
        let display = LocationReferenceToProgramLocationTableRowMapper::get_display_string(&reference);
        assert!(display.contains("READ"));
    }

    #[test]
    fn test_table_model_with_columns() {
        let cols = vec![
            ColumnDef::new("Addr", 100, true),
            ColumnDef::new("Type", 80, false),
        ];
        let model = LocationReferencesTableModel::with_columns(cols);
        assert_eq!(model.column_count(), 2);
    }
}
