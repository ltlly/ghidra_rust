//! BSim overview model and provider.
//!
//! Ports Ghidra's BSim overview classes:
//! - `ghidra.features.bsim.gui.overview.BSimOverviewModel`
//! - `ghidra.features.bsim.gui.overview.BSimOverviewProvider`
//! - `ghidra.features.bsim.gui.overview.BSimOverviewRowObject`
//! - `ghidra.features.bsim.gui.overview.BSimOverviewRowObjectToAddressTableRowMapper`
//!
//! These types provide a table-model view of BSim database executables,
//! their metadata, and associated function counts.


use ghidra_core::addr::Address;

/// A row in the BSim overview table.
///
/// Ports `ghidra.features.bsim.gui.overview.BSimOverviewRowObject`.
/// Each row represents one executable in the BSim database.
#[derive(Debug, Clone)]
pub struct BSimOverviewRowObject {
    /// The executable name.
    pub executable_name: String,
    /// The MD5 hash of the executable.
    pub md5: String,
    /// The architecture string (e.g., "x86:LE:32:default").
    pub architecture: String,
    /// The compiler (e.g., "gcc", "msvc").
    pub compiler: String,
    /// File path of the executable.
    pub path: String,
    /// Date the executable was ingested (ISO 8601).
    pub ingest_date: String,
    /// Whether this is a true executable (vs. library).
    pub is_executable: bool,
    /// Number of functions in this executable.
    pub function_count: usize,
    /// Number of matched functions (when comparing).
    pub matched_count: usize,
    /// Similarity score (when comparing).
    pub similarity_score: f64,
    /// The unique database row key.
    pub row_key: String,
}

impl BSimOverviewRowObject {
    /// Create a new overview row object.
    pub fn new(
        executable_name: impl Into<String>,
        md5: impl Into<String>,
        architecture: impl Into<String>,
    ) -> Self {
        Self {
            executable_name: executable_name.into(),
            md5: md5.into(),
            architecture: architecture.into(),
            compiler: String::new(),
            path: String::new(),
            ingest_date: String::new(),
            is_executable: true,
            function_count: 0,
            matched_count: 0,
            similarity_score: 0.0,
            row_key: String::new(),
        }
    }

    /// Get the match percentage (matched / total functions * 100).
    pub fn match_percentage(&self) -> f64 {
        if self.function_count == 0 {
            return 0.0;
        }
        (self.matched_count as f64 / self.function_count as f64) * 100.0
    }

    /// Whether this row has any matched functions.
    pub fn has_matches(&self) -> bool {
        self.matched_count > 0
    }
}

/// A mapper that converts overview row objects to addresses.
///
/// Ports `ghidra.features.bsim.gui.overview.BSimOverviewRowObjectToAddressTableRowMapper`.
/// This is used to link BSim results to addresses in the listing view.
pub struct BSimOverviewRowObjectToAddressTableRowMapper;

impl BSimOverviewRowObjectToAddressTableRowMapper {
    /// Map an overview row to an address (returns the entry point if available).
    pub fn map_to_address(row: &BSimOverviewRowObject) -> Option<Address> {
        // In a full implementation, this would look up the function entry point
        // from the row key.
        if !row.row_key.is_empty() {
            // Parse the row key as an address if possible.
            if let Ok(offset) = u64::from_str_radix(&row.row_key, 16) {
                return Some(Address::new(offset));
            }
        }
        None
    }
}

/// The table model for the BSim overview.
///
/// Ports `ghidra.features.bsim.gui.overview.BSimOverviewModel`.
/// This model provides the data for a table showing all executables
/// in the BSim database with their metadata and match statistics.
#[derive(Debug, Clone, Default)]
pub struct BSimOverviewModel {
    /// The rows in the model.
    rows: Vec<BSimOverviewRowObject>,
    /// Column names.
    columns: Vec<String>,
    /// Sort column index.
    sort_column: Option<usize>,
    /// Whether sort is ascending.
    sort_ascending: bool,
}

impl BSimOverviewModel {
    /// Column index for executable name.
    pub const COL_NAME: usize = 0;
    /// Column index for MD5.
    pub const COL_MD5: usize = 1;
    /// Column index for architecture.
    pub const COL_ARCH: usize = 2;
    /// Column index for compiler.
    pub const COL_COMPILER: usize = 3;
    /// Column index for function count.
    pub const COL_FUNCTION_COUNT: usize = 4;
    /// Column index for match count.
    pub const COL_MATCH_COUNT: usize = 5;
    /// Column index for similarity score.
    pub const COL_SIMILARITY: usize = 6;
    /// Column index for ingest date.
    pub const COL_DATE: usize = 7;

    /// Create a new overview model with default columns.
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            columns: vec![
                "Name".into(),
                "MD5".into(),
                "Architecture".into(),
                "Compiler".into(),
                "Functions".into(),
                "Matches".into(),
                "Similarity".into(),
                "Date".into(),
            ],
            sort_column: None,
            sort_ascending: true,
        }
    }

    /// Add a row to the model.
    pub fn add_row(&mut self, row: BSimOverviewRowObject) {
        self.rows.push(row);
    }

    /// Get a row by index.
    pub fn get_row(&self, index: usize) -> Option<&BSimOverviewRowObject> {
        self.rows.get(index)
    }

    /// Get the number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Get the number of columns.
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    /// Get the column name at the given index.
    pub fn column_name(&self, index: usize) -> Option<&str> {
        self.columns.get(index).map(|s| s.as_str())
    }

    /// Get the value at a specific cell.
    pub fn get_value_at(&self, row: usize, col: usize) -> Option<String> {
        let r = self.rows.get(row)?;
        match col {
            Self::COL_NAME => Some(r.executable_name.clone()),
            Self::COL_MD5 => Some(r.md5.clone()),
            Self::COL_ARCH => Some(r.architecture.clone()),
            Self::COL_COMPILER => Some(r.compiler.clone()),
            Self::COL_FUNCTION_COUNT => Some(r.function_count.to_string()),
            Self::COL_MATCH_COUNT => Some(r.matched_count.to_string()),
            Self::COL_SIMILARITY => Some(format!("{:.4}", r.similarity_score)),
            Self::COL_DATE => Some(r.ingest_date.clone()),
            _ => None,
        }
    }

    /// Sort the model by the given column.
    pub fn sort_by_column(&mut self, col: usize, ascending: bool) {
        self.sort_column = Some(col);
        self.sort_ascending = ascending;

        self.rows.sort_by(|a, b| {
            let cmp = match col {
                Self::COL_NAME => a.executable_name.cmp(&b.executable_name),
                Self::COL_MD5 => a.md5.cmp(&b.md5),
                Self::COL_ARCH => a.architecture.cmp(&b.architecture),
                Self::COL_COMPILER => a.compiler.cmp(&b.compiler),
                Self::COL_FUNCTION_COUNT => a.function_count.cmp(&b.function_count),
                Self::COL_MATCH_COUNT => a.matched_count.cmp(&b.matched_count),
                Self::COL_SIMILARITY => a
                    .similarity_score
                    .partial_cmp(&b.similarity_score)
                    .unwrap_or(std::cmp::Ordering::Equal),
                Self::COL_DATE => a.ingest_date.cmp(&b.ingest_date),
                _ => std::cmp::Ordering::Equal,
            };
            if ascending {
                cmp
            } else {
                cmp.reverse()
            }
        });
    }

    /// Clear all rows.
    pub fn clear(&mut self) {
        self.rows.clear();
    }

    /// Get all rows as a slice.
    pub fn rows(&self) -> &[BSimOverviewRowObject] {
        &self.rows
    }

    /// Filter rows by a predicate.
    pub fn filtered_rows<F: Fn(&BSimOverviewRowObject) -> bool>(
        &self,
        predicate: F,
    ) -> Vec<&BSimOverviewRowObject> {
        self.rows.iter().filter(|r| predicate(r)).collect()
    }
}

/// The BSim overview provider manages the connection between the overview
/// model and the BSim database.
///
/// Ports `ghidra.features.bsim.gui.overview.BSimOverviewProvider`.
#[derive(Debug)]
pub struct BSimOverviewProvider {
    /// The overview model.
    model: BSimOverviewModel,
    /// The database name this provider is connected to.
    database_name: String,
    /// Whether the provider has been initialized.
    initialized: bool,
}

impl BSimOverviewProvider {
    /// Create a new overview provider.
    pub fn new(database_name: impl Into<String>) -> Self {
        Self {
            model: BSimOverviewModel::new(),
            database_name: database_name.into(),
            initialized: false,
        }
    }

    /// Initialize the provider by loading data from the database.
    pub fn initialize(&mut self) {
        self.initialized = true;
    }

    /// Whether the provider is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get the database name.
    pub fn database_name(&self) -> &str {
        &self.database_name
    }

    /// Get a reference to the overview model.
    pub fn model(&self) -> &BSimOverviewModel {
        &self.model
    }

    /// Get a mutable reference to the overview model.
    pub fn model_mut(&mut self) -> &mut BSimOverviewModel {
        &mut self.model
    }

    /// Refresh the model from the database.
    pub fn refresh(&mut self) {
        // In a full implementation, this would re-query the database.
        self.model.clear();
        self.initialized = true;
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn row_object_new() {
        let row = BSimOverviewRowObject::new("test.exe", "abc123", "x86:LE:32:default");
        assert_eq!(row.executable_name, "test.exe");
        assert_eq!(row.md5, "abc123");
        assert_eq!(row.architecture, "x86:LE:32:default");
        assert!(row.is_executable);
        assert_eq!(row.function_count, 0);
    }

    #[test]
    fn row_object_match_percentage() {
        let mut row = BSimOverviewRowObject::new("test.exe", "abc", "x86");
        row.function_count = 100;
        row.matched_count = 75;
        assert!((row.match_percentage() - 75.0).abs() < 1e-6);
    }

    #[test]
    fn row_object_match_percentage_zero() {
        let row = BSimOverviewRowObject::new("test.exe", "abc", "x86");
        assert!((row.match_percentage() - 0.0).abs() < 1e-6);
    }

    #[test]
    fn row_object_has_matches() {
        let mut row = BSimOverviewRowObject::new("test.exe", "abc", "x86");
        assert!(!row.has_matches());
        row.matched_count = 5;
        assert!(row.has_matches());
    }

    #[test]
    fn mapper_map_to_address_none() {
        let row = BSimOverviewRowObject::new("test.exe", "abc", "x86");
        assert!(BSimOverviewRowObjectToAddressTableRowMapper::map_to_address(&row).is_none());
    }

    #[test]
    fn mapper_map_to_address_hex() {
        let mut row = BSimOverviewRowObject::new("test.exe", "abc", "x86");
        row.row_key = "1000".into();
        let addr = BSimOverviewRowObjectToAddressTableRowMapper::map_to_address(&row);
        assert_eq!(addr, Some(Address::new(0x1000)));
    }

    #[test]
    fn overview_model_new() {
        let model = BSimOverviewModel::new();
        assert_eq!(model.row_count(), 0);
        assert_eq!(model.column_count(), 8);
        assert_eq!(model.column_name(0), Some("Name"));
    }

    #[test]
    fn overview_model_add_row() {
        let mut model = BSimOverviewModel::new();
        let row = BSimOverviewRowObject::new("test.exe", "abc", "x86");
        model.add_row(row);
        assert_eq!(model.row_count(), 1);
    }

    #[test]
    fn overview_model_get_value_at() {
        let mut model = BSimOverviewModel::new();
        let mut row = BSimOverviewRowObject::new("test.exe", "abc", "x86");
        row.function_count = 42;
        model.add_row(row);

        assert_eq!(model.get_value_at(0, 0), Some("test.exe".into()));
        assert_eq!(model.get_value_at(0, 4), Some("42".into()));
        assert_eq!(model.get_value_at(0, 99), None);
        assert_eq!(model.get_value_at(1, 0), None); // out of range
    }

    #[test]
    fn overview_model_sort() {
        let mut model = BSimOverviewModel::new();
        model.add_row(BSimOverviewRowObject::new("z.exe", "abc", "x86"));
        model.add_row(BSimOverviewRowObject::new("a.exe", "def", "ARM"));
        model.add_row(BSimOverviewRowObject::new("m.exe", "ghi", "MIPS"));

        model.sort_by_column(BSimOverviewModel::COL_NAME, true);
        assert_eq!(model.get_row(0).unwrap().executable_name, "a.exe");
        assert_eq!(model.get_row(2).unwrap().executable_name, "z.exe");

        model.sort_by_column(BSimOverviewModel::COL_NAME, false);
        assert_eq!(model.get_row(0).unwrap().executable_name, "z.exe");
    }

    #[test]
    fn overview_model_clear() {
        let mut model = BSimOverviewModel::new();
        model.add_row(BSimOverviewRowObject::new("test.exe", "abc", "x86"));
        model.clear();
        assert_eq!(model.row_count(), 0);
    }

    #[test]
    fn overview_model_filtered_rows() {
        let mut model = BSimOverviewModel::new();
        model.add_row(BSimOverviewRowObject::new("exe1.exe", "abc", "x86"));
        model.add_row(BSimOverviewRowObject::new("exe2.exe", "def", "ARM"));
        model.add_row(BSimOverviewRowObject::new("exe3.exe", "ghi", "x86"));

        let x86 = model.filtered_rows(|r| r.architecture == "x86");
        assert_eq!(x86.len(), 2);
    }

    #[test]
    fn overview_provider_new() {
        let provider = BSimOverviewProvider::new("test_db");
        assert_eq!(provider.database_name(), "test_db");
        assert!(!provider.is_initialized());
    }

    #[test]
    fn overview_provider_initialize() {
        let mut provider = BSimOverviewProvider::new("test_db");
        provider.initialize();
        assert!(provider.is_initialized());
    }

    #[test]
    fn overview_provider_refresh() {
        let mut provider = BSimOverviewProvider::new("test_db");
        provider.model_mut().add_row(BSimOverviewRowObject::new("test", "abc", "x86"));
        provider.refresh();
        assert!(provider.model().rows().is_empty());
    }
}
