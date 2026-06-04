//! Selection plugin and address range table model.
//!
//! Ports `ghidra.app.plugin.core.codebrowser.CodeBrowserSelectionPlugin` and
//! `ghidra.app.plugin.core.codebrowser.AddressRangeTableModel`.

use std::fmt;

use super::address_range_info::AddressRangeInfo;

/// Options category for the selection plugin.
pub const OPTION_CATEGORY_NAME: &str = "Selection Tables";

/// Minimum range size option name.
pub const MIN_RANGE_SIZE_OPTION_NAME: &str = "Minimum Range Size";
/// Default minimum range size.
pub const MIN_RANGE_SIZE_DEFAULT: u64 = 1;
/// Ranges limit option name.
pub const RANGES_LIMIT_OPTION_NAME: &str = "Ranges Limit";
/// Default ranges limit.
pub const RANGES_LIMIT_DEFAULT: usize = 5000;

/// Action name for creating the address range table.
pub const CREATE_ADDRESS_RANGE_TABLE_ACTION_NAME: &str = "Create Address Range Table";

// ---------------------------------------------------------------------------
// AddressRangeTableModel
// ---------------------------------------------------------------------------

/// A table model for displaying address range information.
///
/// Each row corresponds to an [`AddressRangeInfo`] entry, providing columns
/// for min address, max address, length, identical bytes, block name,
/// reference counts, and raw bytes / code unit display.
///
/// Ported from Ghidra's `AddressRangeTableModel`.
#[derive(Debug)]
pub struct AddressRangeTableModel {
    /// The table title.
    title: String,
    /// Program name.
    program_name: String,
    /// The rows of the table.
    rows: Vec<AddressRangeInfo>,
    /// Column definitions.
    columns: Vec<TableColumn>,
}

/// A column definition for the address range table.
#[derive(Debug, Clone)]
pub struct TableColumn {
    /// Column header name.
    pub name: String,
    /// Whether this column is visible by default.
    pub visible: bool,
    /// Column type hint.
    pub column_type: ColumnType,
}

/// Column type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnType {
    /// Address column (min or max).
    Address,
    /// Integer column (length, ref count).
    Integer,
    /// Boolean column (identical bytes).
    Boolean,
    /// String column (block name).
    String,
    /// Bytes column (raw data).
    Bytes,
    /// Code unit column.
    CodeUnit,
}

impl AddressRangeTableModel {
    /// Column index for the min address.
    pub const MIN_ADDRESS_COLUMN_INDEX: usize = 0;
    /// Column index for the max address.
    pub const MAX_ADDRESS_COLUMN_INDEX: usize = 1;

    /// Create a new address range table model.
    pub fn new(program_name: impl Into<String>) -> Self {
        let program_name_str = program_name.into();
        Self {
            title: format!("Selected Ranges in {}", program_name_str),
            program_name: program_name_str,
            rows: Vec::new(),
            columns: Self::default_columns(),
        }
    }

    /// Get the default column definitions.
    fn default_columns() -> Vec<TableColumn> {
        vec![
            TableColumn {
                name: "Min Address".to_string(),
                visible: true,
                column_type: ColumnType::Address,
            },
            TableColumn {
                name: "Max Address".to_string(),
                visible: true,
                column_type: ColumnType::Address,
            },
            TableColumn {
                name: "Length".to_string(),
                visible: true,
                column_type: ColumnType::Integer,
            },
            TableColumn {
                name: "Identical Bytes".to_string(),
                visible: true,
                column_type: ColumnType::Boolean,
            },
            TableColumn {
                name: "Block Name".to_string(),
                visible: true,
                column_type: ColumnType::String,
            },
            TableColumn {
                name: "To References".to_string(),
                visible: true,
                column_type: ColumnType::Integer,
            },
            TableColumn {
                name: "From References".to_string(),
                visible: true,
                column_type: ColumnType::Integer,
            },
            TableColumn {
                name: "Bytes".to_string(),
                visible: false,
                column_type: ColumnType::Bytes,
            },
            TableColumn {
                name: "Code Unit".to_string(),
                visible: false,
                column_type: ColumnType::CodeUnit,
            },
        ]
    }

    /// Get the table title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Get the program name.
    pub fn program_name(&self) -> &str {
        &self.program_name
    }

    /// Get the column definitions.
    pub fn columns(&self) -> &[TableColumn] {
        &self.columns
    }

    /// Load data into the model.
    ///
    /// Ports `AddressRangeTableModel.doLoad(Accumulator, TaskMonitor)`.
    pub fn load(&mut self, data: Vec<AddressRangeInfo>) {
        self.rows = data;
    }

    /// Get a reference to all rows.
    pub fn rows(&self) -> &[AddressRangeInfo] {
        &self.rows
    }

    /// Get a mutable reference to all rows.
    pub fn rows_mut(&mut self) -> &mut Vec<AddressRangeInfo> {
        &mut self.rows
    }

    /// Get the number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Get the number of columns.
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    /// Get a row by index.
    pub fn get_row(&self, index: usize) -> Option<&AddressRangeInfo> {
        self.rows.get(index)
    }

    /// Get the min address for a given row.
    pub fn get_min_address(&self, row: usize) -> Option<u64> {
        self.rows.get(row).map(|r| r.min())
    }

    /// Get the max address for a given row.
    pub fn get_max_address(&self, row: usize) -> Option<u64> {
        self.rows.get(row).map(|r| r.max())
    }

    /// Get the address for a given row and column.
    ///
    /// Returns the min address for column 0, the max address for column 1.
    pub fn get_address(&self, row: usize, column: usize) -> Option<u64> {
        match column {
            Self::MIN_ADDRESS_COLUMN_INDEX => self.get_min_address(row),
            Self::MAX_ADDRESS_COLUMN_INDEX => self.get_max_address(row),
            _ => None,
        }
    }

    /// Get the cell value as a string for a given row and column.
    pub fn get_cell_value(&self, row: usize, column: usize) -> Option<String> {
        let info = self.rows.get(row)?;
        let col = self.columns.get(column)?;
        match col.column_type {
            ColumnType::Address => {
                if column == Self::MIN_ADDRESS_COLUMN_INDEX {
                    Some(format!("0x{:X}", info.min()))
                } else {
                    Some(format!("0x{:X}", info.max()))
                }
            }
            ColumnType::Integer => match col.name.as_str() {
                "Length" => Some(info.size().to_string()),
                "To References" => Some(info.num_refs_to().to_string()),
                "From References" => Some(info.num_refs_from().to_string()),
                _ => None,
            },
            ColumnType::Boolean => Some(if info.is_same_byte() { "Yes" } else { "No" }.to_string()),
            ColumnType::String => Some("".to_string()), // Block name requires memory model
            ColumnType::Bytes => Some("".to_string()),
            ColumnType::CodeUnit => Some("".to_string()),
        }
    }

    /// Get the program selection (address set) for the given row indices.
    ///
    /// Ports `AddressRangeTableModel.getProgramSelection(int[])`.
    pub fn get_program_selection(&self, row_indices: &[usize]) -> Vec<(u64, u64)> {
        row_indices
            .iter()
            .filter_map(|&idx| self.rows.get(idx))
            .map(|info| (info.min(), info.max()))
            .collect()
    }
}

impl fmt::Display for AddressRangeTableModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AddressRangeTableModel(title={}, rows={})",
            self.title,
            self.rows.len()
        )
    }
}

// ---------------------------------------------------------------------------
// CodeBrowserSelectionPlugin
// ---------------------------------------------------------------------------

/// The selection analysis plugin for the code browser.
///
/// When the user makes a selection in the listing, this plugin provides
/// analysis tools such as "Create Address Range Table" that display
/// properties of the selected ranges.
///
/// Ported from Ghidra's `CodeBrowserSelectionPlugin`.
#[derive(Debug)]
pub struct CodeBrowserSelectionPlugin {
    /// Plugin name.
    name: String,
    /// Whether the plugin is disposed.
    disposed: bool,
    /// Options.
    min_range_size: u64,
    /// Maximum number of ranges to display.
    ranges_limit: usize,
}

impl CodeBrowserSelectionPlugin {
    /// Create a new selection plugin.
    pub fn new() -> Self {
        Self {
            name: "CodeBrowserSelectionPlugin".to_string(),
            disposed: false,
            min_range_size: MIN_RANGE_SIZE_DEFAULT,
            ranges_limit: RANGES_LIMIT_DEFAULT,
        }
    }

    /// Get the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the plugin is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Get the minimum range size filter.
    pub fn min_range_size(&self) -> u64 {
        self.min_range_size
    }

    /// Set the minimum range size filter.
    pub fn set_min_range_size(&mut self, size: u64) {
        self.min_range_size = size;
    }

    /// Get the ranges limit.
    pub fn ranges_limit(&self) -> usize {
        self.ranges_limit
    }

    /// Set the ranges limit.
    pub fn set_ranges_limit(&mut self, limit: usize) {
        self.ranges_limit = limit;
    }

    /// Create an address range table model from a selection.
    pub fn create_table_model(
        &self,
        program_name: &str,
        ranges: &[AddressRangeInfo],
    ) -> AddressRangeTableModel {
        let mut model = AddressRangeTableModel::new(program_name);
        let filtered: Vec<AddressRangeInfo> = ranges
            .iter()
            .filter(|r| r.size() >= self.min_range_size)
            .take(self.ranges_limit)
            .cloned()
            .collect();
        model.load(filtered);
        model
    }

    /// Dispose of this plugin.
    pub fn dispose(&mut self) {
        self.disposed = true;
    }
}

impl Default for CodeBrowserSelectionPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CodeBrowserSelectionPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CodeBrowserSelectionPlugin(name={})", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_ranges() -> Vec<AddressRangeInfo> {
        vec![
            AddressRangeInfo::new(0x1000, 0x10FF, 256, true, 10, 5),
            AddressRangeInfo::new(0x2000, 0x200F, 16, false, 3, 1),
            AddressRangeInfo::new(0x3000, 0x3FFF, 4096, true, 20, 10),
        ]
    }

    #[test]
    fn test_table_model_creation() {
        let model = AddressRangeTableModel::new("test.exe");
        assert_eq!(model.title(), "Selected Ranges in test.exe");
        assert_eq!(model.program_name(), "test.exe");
        assert_eq!(model.row_count(), 0);
    }

    #[test]
    fn test_table_model_columns() {
        let model = AddressRangeTableModel::new("test.exe");
        assert_eq!(model.column_count(), 9);

        // Check that first two columns are Address type.
        assert_eq!(model.columns()[0].column_type, ColumnType::Address);
        assert_eq!(model.columns()[1].column_type, ColumnType::Address);
        assert_eq!(model.columns()[0].name, "Min Address");
        assert_eq!(model.columns()[1].name, "Max Address");
    }

    #[test]
    fn test_table_model_load_and_access() {
        let mut model = AddressRangeTableModel::new("test.exe");
        let ranges = make_test_ranges();
        model.load(ranges);

        assert_eq!(model.row_count(), 3);
        assert_eq!(model.get_min_address(0), Some(0x1000));
        assert_eq!(model.get_max_address(0), Some(0x10FF));
    }

    #[test]
    fn test_table_model_get_address_by_column() {
        let mut model = AddressRangeTableModel::new("test.exe");
        model.load(make_test_ranges());

        assert_eq!(
            model.get_address(0, AddressRangeTableModel::MIN_ADDRESS_COLUMN_INDEX),
            Some(0x1000)
        );
        assert_eq!(
            model.get_address(0, AddressRangeTableModel::MAX_ADDRESS_COLUMN_INDEX),
            Some(0x10FF)
        );
        assert_eq!(model.get_address(0, 5), None); // Unknown column
    }

    #[test]
    fn test_table_model_get_cell_value() {
        let mut model = AddressRangeTableModel::new("test.exe");
        model.load(make_test_ranges());

        assert_eq!(model.get_cell_value(0, 0), Some("0x1000".to_string()));
        assert_eq!(model.get_cell_value(0, 1), Some("0x10FF".to_string()));
        assert_eq!(model.get_cell_value(0, 2), Some("256".to_string()));
        assert_eq!(model.get_cell_value(0, 3), Some("Yes".to_string()));
        assert_eq!(model.get_cell_value(1, 3), Some("No".to_string()));
        assert_eq!(model.get_cell_value(0, 5), Some("10".to_string()));
        assert_eq!(model.get_cell_value(0, 6), Some("5".to_string()));
    }

    #[test]
    fn test_table_model_out_of_bounds() {
        let mut model = AddressRangeTableModel::new("test.exe");
        model.load(make_test_ranges());

        assert!(model.get_row(10).is_none());
        assert!(model.get_min_address(10).is_none());
        assert!(model.get_cell_value(10, 0).is_none());
    }

    #[test]
    fn test_table_model_program_selection() {
        let mut model = AddressRangeTableModel::new("test.exe");
        model.load(make_test_ranges());

        let sel = model.get_program_selection(&[0, 2]);
        assert_eq!(sel.len(), 2);
        assert_eq!(sel[0], (0x1000, 0x10FF));
        assert_eq!(sel[1], (0x3000, 0x3FFF));
    }

    #[test]
    fn test_selection_plugin_creation() {
        let plugin = CodeBrowserSelectionPlugin::new();
        assert_eq!(plugin.name(), "CodeBrowserSelectionPlugin");
        assert!(!plugin.is_disposed());
        assert_eq!(plugin.min_range_size(), MIN_RANGE_SIZE_DEFAULT);
        assert_eq!(plugin.ranges_limit(), RANGES_LIMIT_DEFAULT);
    }

    #[test]
    fn test_selection_plugin_filtering() {
        let mut plugin = CodeBrowserSelectionPlugin::new();
        plugin.set_min_range_size(100); // Filter out ranges < 100

        let ranges = make_test_ranges();
        let model = plugin.create_table_model("test.exe", &ranges);

        // 0x2000..0x200F has size 16, which is < 100, so filtered out.
        assert_eq!(model.row_count(), 2);
    }

    #[test]
    fn test_selection_plugin_ranges_limit() {
        let mut plugin = CodeBrowserSelectionPlugin::new();
        plugin.set_ranges_limit(1);

        let ranges = make_test_ranges();
        let model = plugin.create_table_model("test.exe", &ranges);
        assert_eq!(model.row_count(), 1);
    }

    #[test]
    fn test_selection_plugin_dispose() {
        let mut plugin = CodeBrowserSelectionPlugin::new();
        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_table_model_display() {
        let model = AddressRangeTableModel::new("test.exe");
        let display = format!("{}", model);
        assert!(display.contains("test.exe"));
        assert!(display.contains("rows=0"));
    }

    #[test]
    fn test_constants() {
        assert!(!OPTION_CATEGORY_NAME.is_empty());
        assert!(!MIN_RANGE_SIZE_OPTION_NAME.is_empty());
        assert_eq!(MIN_RANGE_SIZE_DEFAULT, 1);
        assert_eq!(RANGES_LIMIT_DEFAULT, 5000);
    }
}
