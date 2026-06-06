//! Data window plugin for browsing defined data in a program.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.datawindow` package.
//!
//! Provides a table view of all defined data items in the current program,
//! with filtering by data type, address range, and coverage.
//!
//! # Key Types
//!
//! - [`DataWindowPlugin`] -- Plugin providing the data window
//! - [`DataTableModel`] -- Table model for data items
//! - [`DataRowObject`] -- A single data item row
//! - [`DataWindowFilter`] -- Filtering configuration
//! - [`DataColumn`] -- Column definitions for the table

/// Data window provider for displaying data items.
///
/// Ported from `ghidra.app.plugin.core.datawindow.DataWindowProvider`.
pub mod provider;

/// Action context and filter actions for the data window.
///
/// Ported from `ghidra.app.plugin.core.datawindow.DataWindowContext`
/// and `ghidra.app.plugin.core.datawindow.FilterAction`.
pub mod context;

/// Table mappers for data row objects.
///
/// Ported from `ghidra.app.plugin.core.datawindow.DataRowObjectToAddressTableRowMapper`
/// and `DataRowObjectToProgramLocationTableRowMapper`.
pub mod mappers;

/// Filter dialog for filtering data items by type, address range, and text.
///
/// Ported from `ghidra.app.plugin.core.datawindow.DataWindowFilterDialog`.
pub mod filter_dialog;

use std::collections::{BTreeMap, HashMap};

/// Display name for the data value column.
pub const DATA_VALUE_COLUMN: &str = "Data";

/// Display name for the data type column.
pub const DATA_TYPE_COLUMN: &str = "Type";

/// Display name for the address column.
pub const ADDRESS_COLUMN: &str = "Address";

/// Display name for the length column.
pub const LENGTH_COLUMN: &str = "Length";

// ---------------------------------------------------------------------------
// Data column
// ---------------------------------------------------------------------------

/// Column definitions for the data window table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataColumn {
    /// The address of the data item.
    Address,
    /// The data value representation.
    DataValue,
    /// The data type name.
    DataType,
    /// The byte length of the data item.
    Length,
}

impl DataColumn {
    /// Display name for this column.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Address => ADDRESS_COLUMN,
            Self::DataValue => DATA_VALUE_COLUMN,
            Self::DataType => DATA_TYPE_COLUMN,
            Self::Length => LENGTH_COLUMN,
        }
    }

    /// All columns in display order.
    pub fn all() -> &'static [DataColumn] {
        &[
            Self::Address,
            Self::DataType,
            Self::DataValue,
            Self::Length,
        ]
    }
}

// ---------------------------------------------------------------------------
// Data row object
// ---------------------------------------------------------------------------

/// A row in the data window table, representing a single defined data item.
///
/// Ported from `ghidra.app.plugin.core.datawindow.DataRowObject`.
#[derive(Debug, Clone)]
pub struct DataRowObject {
    /// The address key for this data item.
    pub address_key: u64,
    /// The display address string.
    pub address: String,
    /// The data type display name.
    pub type_name: String,
    /// The data value representation.
    pub value: String,
    /// The byte length.
    pub length: u32,
}

impl DataRowObject {
    /// Create a new data row object.
    pub fn new(
        address_key: u64,
        address: impl Into<String>,
        type_name: impl Into<String>,
        value: impl Into<String>,
        length: u32,
    ) -> Self {
        Self {
            address_key,
            address: address.into(),
            type_name: type_name.into(),
            value: value.into(),
            length,
        }
    }
}

impl PartialEq for DataRowObject {
    fn eq(&self, other: &Self) -> bool {
        self.address_key == other.address_key
    }
}

impl Eq for DataRowObject {}

impl PartialOrd for DataRowObject {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DataRowObject {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.address_key.cmp(&other.address_key)
    }
}

// ---------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------

/// An address range for filtering data items.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRange {
    /// Start address (inclusive).
    pub start: u64,
    /// End address (inclusive).
    pub end: u64,
}

impl AddressRange {
    /// Create a new address range.
    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    /// Whether this range contains the given address.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr <= self.end
    }
}

/// Address coverage used for filtering.
#[derive(Debug, Clone, Default)]
pub struct Coverage {
    /// Address ranges that are covered.
    ranges: Vec<AddressRange>,
}

impl Coverage {
    /// Create a new empty coverage.
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Add a range to the coverage.
    pub fn add_range(&mut self, start: u64, end: u64) {
        self.ranges.push(AddressRange::new(start, end));
    }

    /// Whether the coverage contains the given address.
    pub fn contains(&self, addr: u64) -> bool {
        self.ranges.is_empty() || self.ranges.iter().any(|r| r.contains(addr))
    }

    /// Number of ranges in this coverage.
    pub fn range_count(&self) -> usize {
        self.ranges.len()
    }
}

// ---------------------------------------------------------------------------
// Data window filter
// ---------------------------------------------------------------------------

/// Filter configuration for the data window.
#[derive(Debug, Clone)]
pub struct DataWindowFilter {
    /// Map of data type display name to enabled state.
    type_enabled_map: BTreeMap<String, bool>,
    /// Whether filtering is active.
    pub enabled: bool,
    /// Optional coverage filter.
    pub coverage: Option<Coverage>,
}

impl DataWindowFilter {
    /// Create a new empty filter.
    pub fn new() -> Self {
        Self {
            type_enabled_map: BTreeMap::new(),
            enabled: false,
            coverage: None,
        }
    }

    /// Register a data type name as available for filtering.
    pub fn register_type(&mut self, type_name: impl Into<String>) {
        self.type_enabled_map.insert(type_name.into(), true);
    }

    /// Enable or disable a specific type.
    pub fn set_type_enabled(&mut self, type_name: &str, enabled: bool) {
        if let Some(v) = self.type_enabled_map.get_mut(type_name) {
            *v = enabled;
        }
    }

    /// Whether a given type is currently enabled.
    pub fn is_type_enabled(&self, type_name: &str) -> bool {
        if !self.enabled {
            return true;
        }
        self.type_enabled_map
            .get(type_name)
            .copied()
            .unwrap_or(false)
    }

    /// Whether a row object passes the filter.
    pub fn accepts(&self, row: &DataRowObject) -> bool {
        if !self.enabled {
            return true;
        }
        if !self.is_type_enabled(&row.type_name) {
            return false;
        }
        if let Some(ref cov) = self.coverage {
            if !cov.contains(row.address_key) {
                return false;
            }
        }
        true
    }

    /// Get all registered type names.
    pub fn type_names(&self) -> Vec<&str> {
        self.type_enabled_map.keys().map(|s| s.as_str()).collect()
    }

    /// Get the enabled state map.
    pub fn type_enabled_map(&self) -> &BTreeMap<String, bool> {
        &self.type_enabled_map
    }
}

impl Default for DataWindowFilter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Data table model
// ---------------------------------------------------------------------------

/// Table model for the data window.
///
/// Ported from `ghidra.app.plugin.core.datawindow.DataTableModel`.
#[derive(Debug)]
pub struct DataTableModel {
    /// All data rows.
    rows: Vec<DataRowObject>,
    /// Filter configuration.
    filter: DataWindowFilter,
}

impl DataTableModel {
    /// Create a new data table model.
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            filter: DataWindowFilter::new(),
        }
    }

    /// Add a row to the model.
    pub fn add_row(&mut self, row: DataRowObject) {
        self.rows.push(row);
        self.rows.sort();
    }

    /// Remove the row at the given address key.
    pub fn remove_row(&mut self, address_key: u64) {
        self.rows.retain(|r| r.address_key != address_key);
    }

    /// Get the total number of rows (before filtering).
    pub fn total_rows(&self) -> usize {
        self.rows.len()
    }

    /// Get the number of filtered rows.
    pub fn filtered_row_count(&self) -> usize {
        self.rows.iter().filter(|r| self.filter.accepts(r)).count()
    }

    /// Get a row by index from the filtered view.
    pub fn get_filtered_row(&self, index: usize) -> Option<&DataRowObject> {
        self.rows
            .iter()
            .filter(|r| self.filter.accepts(r))
            .nth(index)
    }

    /// Get the filter.
    pub fn filter(&self) -> &DataWindowFilter {
        &self.filter
    }

    /// Get a mutable reference to the filter.
    pub fn filter_mut(&mut self) -> &mut DataWindowFilter {
        &mut self.filter
    }

    /// Get all unique type names from the data.
    pub fn unique_type_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.rows.iter().map(|r| r.type_name.as_str()).collect();
        names.sort();
        names.dedup();
        names
    }

    /// Clear all rows.
    pub fn clear(&mut self) {
        self.rows.clear();
    }
}

impl Default for DataTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Data window plugin
// ---------------------------------------------------------------------------

/// Plugin providing a window that displays all defined data items.
///
/// Ported from `ghidra.app.plugin.core.datawindow.DataWindowPlugin`.
#[derive(Debug)]
pub struct DataWindowPlugin {
    /// The table model.
    model: DataTableModel,
    /// Whether the window is visible.
    visible: bool,
    /// Whether the types need to be refreshed.
    reset_needed: bool,
}

impl DataWindowPlugin {
    /// Create a new data window plugin.
    pub fn new() -> Self {
        Self {
            model: DataTableModel::new(),
            visible: false,
            reset_needed: true,
        }
    }

    /// Get the table model.
    pub fn model(&self) -> &DataTableModel {
        &self.model
    }

    /// Get a mutable reference to the table model.
    pub fn model_mut(&mut self) -> &mut DataTableModel {
        &mut self.model
    }

    /// Mark the window as visible.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
        if visible && self.reset_needed {
            self.reset_needed = false;
        }
    }

    /// Whether the window is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Notify that data was added at the given address.
    pub fn data_added(&mut self, row: DataRowObject) {
        self.model.add_row(row);
    }

    /// Notify that data was removed at the given address key.
    pub fn data_removed(&mut self, address_key: u64) {
        self.model.remove_row(address_key);
    }

    /// Reload the data.
    pub fn reload(&mut self) {
        // In a full implementation, this re-scans the program listing.
        self.reset_needed = false;
    }
}

impl Default for DataWindowPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Data-to-Address table row mappers
// ---------------------------------------------------------------------------

/// Maps data window rows to address table rows.
///
/// Ported from `ghidra.app.plugin.core.datawindow
/// .DataToAddressTableRowMapper`.
#[derive(Debug, Clone)]
pub struct DataToAddressTableRowMapper {
    /// The mapper name.
    pub name: String,
}

impl DataToAddressTableRowMapper {
    /// Create a new mapper.
    pub fn new() -> Self {
        Self {
            name: "DataToAddress".into(),
        }
    }

    /// Map a data row to an address.
    pub fn map(&self, row: &DataRowObject) -> u64 {
        row.address_key
    }
}

impl Default for DataToAddressTableRowMapper {
    fn default() -> Self {
        Self::new()
    }
}

/// Maps data window rows to program location table rows.
///
/// Ported from `ghidra.app.plugin.core.datawindow
/// .DataToProgramLocationTableRowMapper`.
#[derive(Debug, Clone)]
pub struct DataToProgramLocationTableRowMapper {
    /// The mapper name.
    pub name: String,
}

impl DataToProgramLocationTableRowMapper {
    /// Create a new mapper.
    pub fn new() -> Self {
        Self {
            name: "DataToProgramLocation".into(),
        }
    }

    /// Map a data row to a program location (address + component path).
    pub fn map(&self, row: &DataRowObject) -> (u64, Vec<u64>) {
        (row.address_key, Vec::new())
    }
}

impl Default for DataToProgramLocationTableRowMapper {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_column_display_names() {
        assert_eq!(DataColumn::Address.display_name(), "Address");
        assert_eq!(DataColumn::DataType.display_name(), "Type");
        assert_eq!(DataColumn::all().len(), 4);
    }

    #[test]
    fn test_data_row_object_ordering() {
        let r1 = DataRowObject::new(100, "0x64", "int", "42", 4);
        let r2 = DataRowObject::new(200, "0xC8", "byte", "0xFF", 1);
        assert!(r1 < r2);
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_address_range() {
        let range = AddressRange::new(0x100, 0x200);
        assert!(range.contains(0x100));
        assert!(range.contains(0x180));
        assert!(range.contains(0x200));
        assert!(!range.contains(0x099));
        assert!(!range.contains(0x201));
    }

    #[test]
    fn test_coverage_empty_contains_all() {
        let cov = Coverage::new();
        assert!(cov.contains(0x400000));
        assert!(cov.range_count() == 0);
    }

    #[test]
    fn test_coverage_with_ranges() {
        let mut cov = Coverage::new();
        cov.add_range(0x100, 0x200);
        cov.add_range(0x500, 0x600);
        assert!(cov.contains(0x150));
        assert!(cov.contains(0x550));
        assert!(!cov.contains(0x300));
    }

    #[test]
    fn test_data_window_filter_no_filter() {
        let filter = DataWindowFilter::new();
        let row = DataRowObject::new(0, "0x0", "int", "0", 4);
        assert!(filter.accepts(&row));
    }

    #[test]
    fn test_data_window_filter_type_filter() {
        let mut filter = DataWindowFilter::new();
        filter.register_type("int");
        filter.register_type("byte");
        filter.enabled = true;
        filter.set_type_enabled("byte", false);

        let int_row = DataRowObject::new(0, "0x0", "int", "0", 4);
        let byte_row = DataRowObject::new(1, "0x1", "byte", "0", 1);

        assert!(filter.accepts(&int_row));
        assert!(!filter.accepts(&byte_row));
    }

    #[test]
    fn test_data_table_model_lifecycle() {
        let mut model = DataTableModel::new();
        assert_eq!(model.total_rows(), 0);

        model.add_row(DataRowObject::new(300, "0x12C", "int", "42", 4));
        model.add_row(DataRowObject::new(100, "0x64", "byte", "0xFF", 1));
        assert_eq!(model.total_rows(), 2);

        // Should be sorted by address key
        let first = model.get_filtered_row(0).unwrap();
        assert_eq!(first.address_key, 100);

        model.remove_row(100);
        assert_eq!(model.total_rows(), 1);
    }

    #[test]
    fn test_data_table_model_unique_types() {
        let mut model = DataTableModel::new();
        model.add_row(DataRowObject::new(0, "0x0", "int", "0", 4));
        model.add_row(DataRowObject::new(4, "0x4", "byte", "0", 1));
        model.add_row(DataRowObject::new(8, "0x8", "int", "0", 4));

        let types = model.unique_type_names();
        assert_eq!(types, vec!["byte", "int"]);
    }

    #[test]
    fn test_data_window_plugin_lifecycle() {
        let mut plugin = DataWindowPlugin::new();
        assert!(!plugin.is_visible());
        assert_eq!(plugin.model().total_rows(), 0);

        plugin.set_visible(true);
        assert!(plugin.is_visible());

        plugin.data_added(DataRowObject::new(0, "0x0", "int", "5", 4));
        assert_eq!(plugin.model().total_rows(), 1);

        plugin.data_removed(0);
        assert_eq!(plugin.model().total_rows(), 0);
    }
}
