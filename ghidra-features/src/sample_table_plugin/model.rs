//! Table models for the Sample Table Plugin extension.
//!
//! Ported from `FunctionStatsRowObject.java`, `SampleTableModel.java`, and
//! `SampleSearchTableModel.java` in the SampleTablePlugin extension.
//!
//! These models provide the data layer for the filterable table views
//! displayed by the plugin providers.

use std::fmt;

use super::algorithm::FunctionAlgorithm;
use super::search::SearchResults;

// ---------------------------------------------------------------------------
// FunctionStatsRowObject
// ---------------------------------------------------------------------------

/// Row data object for the function statistics table.
///
/// Ported from `FunctionStatsRowObject.java`. Holds a function reference,
/// algorithm name, and computed score for display in the table.
#[derive(Debug, Clone)]
pub struct FunctionStatsRowObject {
    /// Name of the function.
    function_name: String,
    /// Entry point address of the function.
    address: u64,
    /// Name of the algorithm that produced the score.
    algorithm_name: String,
    /// Computed score value.
    score: i32,
}

impl FunctionStatsRowObject {
    /// Create a new row object.
    pub fn new(
        function_name: impl Into<String>,
        address: u64,
        algorithm_name: impl Into<String>,
        score: i32,
    ) -> Self {
        Self {
            function_name: function_name.into(),
            address,
            algorithm_name: algorithm_name.into(),
            score,
        }
    }

    /// Entry point address of the function.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Name of the function.
    pub fn function_name(&self) -> &str {
        &self.function_name
    }

    /// Name of the scoring algorithm.
    pub fn algorithm_name(&self) -> &str {
        &self.algorithm_name
    }

    /// Computed score value.
    pub fn score(&self) -> i32 {
        self.score
    }
}

impl fmt::Display for FunctionStatsRowObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FunctionStats[func={}, algo={}, score={}]",
            self.function_name, self.algorithm_name, self.score
        )
    }
}

// ---------------------------------------------------------------------------
// SampleTableModel
// ---------------------------------------------------------------------------

/// Column descriptor for a table model.
#[derive(Debug, Clone)]
pub struct TableColumn {
    /// Column header name.
    pub name: String,
    /// Whether the column is hidden by default.
    pub hidden: bool,
    /// Column index for default sort (-1 for none).
    pub default_sort_index: Option<usize>,
}

impl TableColumn {
    /// Create a visible column.
    pub fn visible(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            hidden: false,
            default_sort_index: None,
        }
    }

    /// Create a hidden column.
    pub fn hidden(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            hidden: true,
            default_sort_index: None,
        }
    }
}

/// Threaded table model for function algorithm results.
///
/// Ported from `SampleTableModel.java`. In the Java original this extends
/// `ThreadedTableModelStub` for background loading. In Rust we provide a
/// synchronous load interface that mirrors the same data flow.
///
/// The model has four columns: Function Name, Algorithm, Score (default sorted),
/// and Address (hidden by default).
#[derive(Debug)]
pub struct SampleTableModel {
    /// Model name for identification.
    name: String,
    /// Table rows.
    rows: Vec<FunctionStatsRowObject>,
    /// Column descriptors.
    columns: Vec<TableColumn>,
}

impl SampleTableModel {
    /// Create a new table model with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        let columns = vec![
            TableColumn::visible("Function Name"),
            TableColumn::visible("Algorithm"),
            TableColumn {
                name: "Score".to_string(),
                hidden: false,
                default_sort_index: Some(0),
            },
            TableColumn::hidden("Address"),
        ];
        Self {
            name: name.into(),
            rows: Vec::new(),
            columns,
        }
    }

    /// Get the model name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the column names.
    pub fn column_names(&self) -> Vec<&str> {
        self.columns.iter().map(|c| c.name.as_str()).collect()
    }

    /// Get the number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Get a row by index.
    pub fn row(&self, index: usize) -> Option<&FunctionStatsRowObject> {
        self.rows.get(index)
    }

    /// Get all rows as a slice.
    pub fn rows(&self) -> &[FunctionStatsRowObject] {
        &self.rows
    }

    /// Reset (clear) all data.
    pub fn reset(&mut self) {
        self.rows.clear();
    }

    /// Load data by running all algorithms against a simulated function.
    ///
    /// In the Java original, `doLoad()` calls `plugin.getFunction()` and
    /// iterates over the plugin's algorithms. Here we provide a direct
    /// interface that accepts the function parameters and algorithm list.
    pub fn load_with_function(
        &mut self,
        function_name: &str,
        address: u64,
        body_size: usize,
        basic_block_count: usize,
        reference_count: usize,
        algorithms: &[Box<dyn FunctionAlgorithm>],
    ) {
        for algorithm in algorithms {
            let score = algorithm.score(body_size, basic_block_count, reference_count);
            self.rows.push(FunctionStatsRowObject::new(
                function_name,
                address,
                algorithm.name(),
                score,
            ));
        }
    }

    /// Add a row directly.
    pub fn add_row(&mut self, row: FunctionStatsRowObject) {
        self.rows.push(row);
    }
}

// ---------------------------------------------------------------------------
// SampleSearchTableModel
// ---------------------------------------------------------------------------

/// Table model for search results.
///
/// Ported from `SampleSearchTableModel.java`. Provides two columns:
/// Address and Value.
#[derive(Debug)]
pub struct SampleSearchTableModel {
    /// Table rows.
    rows: Vec<SearchResults>,
    /// Column descriptors.
    columns: Vec<TableColumn>,
}

impl SampleSearchTableModel {
    /// Create a new empty search table model.
    pub fn new() -> Self {
        let columns = vec![
            TableColumn::visible("Address"),
            TableColumn::visible("Value"),
        ];
        Self {
            rows: Vec::new(),
            columns,
        }
    }

    /// Get the column names.
    pub fn column_names(&self) -> Vec<&str> {
        self.columns.iter().map(|c| c.name.as_str()).collect()
    }

    /// Get the number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Get a row by index.
    pub fn row(&self, index: usize) -> Option<&SearchResults> {
        self.rows.get(index)
    }

    /// Get all rows as a slice.
    pub fn rows(&self) -> &[SearchResults] {
        &self.rows
    }

    /// Load search results into the model.
    pub fn load(&mut self, results: Vec<SearchResults>) {
        self.rows = results;
    }

    /// Get the address for a given row (mirrors `getAddress(int row)`).
    pub fn get_address(&self, row: usize) -> Option<u64> {
        self.rows.get(row).map(|r| r.address())
    }
}

impl Default for SampleSearchTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample_table_plugin::algorithm::{
        BasicBlockCounterFunctionAlgorithm, ReferenceFunctionAlgorithm, SizeFunctionAlgorithm,
    };

    #[test]
    fn test_row_object_fields() {
        let row = FunctionStatsRowObject::new("main", 0x400000, "Size", 512);
        assert_eq!(row.function_name(), "main");
        assert_eq!(row.address(), 0x400000);
        assert_eq!(row.algorithm_name(), "Size");
        assert_eq!(row.score(), 512);
    }

    #[test]
    fn test_row_object_display() {
        let row = FunctionStatsRowObject::new("main", 0x400000, "Size", 512);
        let s = format!("{}", row);
        assert!(s.contains("main"));
        assert!(s.contains("Size"));
        assert!(s.contains("512"));
    }

    #[test]
    fn test_row_object_clone() {
        let row = FunctionStatsRowObject::new("f", 0x1000, "Alg", 1);
        let cloned = row.clone();
        assert_eq!(cloned.function_name(), row.function_name());
        assert_eq!(cloned.score(), row.score());
    }

    #[test]
    fn test_table_model_basic() {
        let model = SampleTableModel::new("test");
        assert_eq!(model.name(), "test");
        assert_eq!(model.row_count(), 0);
    }

    #[test]
    fn test_table_model_columns() {
        let model = SampleTableModel::new("test");
        let names = model.column_names();
        assert_eq!(names, vec!["Function Name", "Algorithm", "Score", "Address"]);
    }

    #[test]
    fn test_table_model_load() {
        let mut model = SampleTableModel::new("test");
        let algs: Vec<Box<dyn FunctionAlgorithm>> = vec![
            Box::new(SizeFunctionAlgorithm::new()),
            Box::new(BasicBlockCounterFunctionAlgorithm::new()),
            Box::new(ReferenceFunctionAlgorithm::new()),
        ];
        model.load_with_function("foo", 0x2000, 100, 5, 10, &algs);
        assert_eq!(model.row_count(), 3);
        assert_eq!(model.row(0).unwrap().score(), 100);
        assert_eq!(model.row(1).unwrap().score(), 5);
        assert_eq!(model.row(2).unwrap().score(), 10);
    }

    #[test]
    fn test_table_model_reset() {
        let mut model = SampleTableModel::new("test");
        let algs: Vec<Box<dyn FunctionAlgorithm>> =
            vec![Box::new(SizeFunctionAlgorithm::new())];
        model.load_with_function("f", 0x1000, 10, 1, 0, &algs);
        assert_eq!(model.row_count(), 1);
        model.reset();
        assert_eq!(model.row_count(), 0);
    }

    #[test]
    fn test_table_model_add_row() {
        let mut model = SampleTableModel::new("test");
        model.add_row(FunctionStatsRowObject::new("f", 0x1000, "A", 42));
        assert_eq!(model.row_count(), 1);
        assert_eq!(model.row(0).unwrap().score(), 42);
    }

    #[test]
    fn test_table_model_out_of_bounds() {
        let model = SampleTableModel::new("test");
        assert!(model.row(0).is_none());
    }

    #[test]
    fn test_search_table_model_basic() {
        let model = SampleSearchTableModel::new();
        assert_eq!(model.row_count(), 0);
        let names = model.column_names();
        assert_eq!(names, vec!["Address", "Value"]);
    }

    #[test]
    fn test_search_table_model_load() {
        let mut model = SampleSearchTableModel::new();
        let results = vec![
            SearchResults::new(0x1000, "alpha".to_string()),
            SearchResults::new(0x2000, "beta".to_string()),
            SearchResults::new(0x3000, "gamma".to_string()),
        ];
        model.load(results);
        assert_eq!(model.row_count(), 3);
        assert_eq!(model.row(1).unwrap().display_value(), "beta");
    }

    #[test]
    fn test_search_table_model_get_address() {
        let mut model = SampleSearchTableModel::new();
        model.load(vec![SearchResults::new(0xABCD, "x".to_string())]);
        assert_eq!(model.get_address(0), Some(0xABCD));
        assert_eq!(model.get_address(1), None);
    }

    #[test]
    fn test_search_table_model_default() {
        let model = SampleSearchTableModel::default();
        assert_eq!(model.row_count(), 0);
    }

    #[test]
    fn test_table_column_visible() {
        let col = TableColumn::visible("Name");
        assert_eq!(col.name, "Name");
        assert!(!col.hidden);
    }

    #[test]
    fn test_table_column_hidden() {
        let col = TableColumn::hidden("Addr");
        assert_eq!(col.name, "Addr");
        assert!(col.hidden);
    }
}
