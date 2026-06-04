//! Sample Table Plugin -- example Ghidra extension demonstrating table-based
//! analysis views.
//!
//! This module ports the SampleTablePlugin extension from Ghidra's Java source.
//! It provides two example plugins:
//!
//! 1. **SampleTablePlugin** -- Runs pluggable `FunctionAlgorithm` implementations
//!    on the currently selected function and displays results in a filterable
//!    table. Includes three built-in algorithms:
//!    - [`SizeFunctionAlgorithm`] -- Scores by function body byte count.
//!    - [`BasicBlockCounterFunctionAlgorithm`] -- Scores by number of basic blocks.
//!    - [`ReferenceFunctionAlgorithm`] -- Scores by incoming reference count.
//!
//! 2. **SampleSearchTablePlugin** -- Searches for zero-parameter functions and
//!    displays matches in a table with address and name columns.
//!
//! # Architecture
//!
//! - [`FunctionAlgorithm`] -- Trait for pluggable scoring algorithms.
//! - [`FunctionStatsRowObject`] -- Row data for the algorithm results table.
//! - [`SampleTablePlugin`] / [`SampleTableProvider`] -- Plugin + UI provider
//!   for the algorithm-based table.
//! - [`SampleTableModel`] -- Threaded table model that loads algorithm results.
//! - [`SearchResults`] -- Row data for the search results table.
//! - [`SampleSearcher`] -- Performs the function search.
//! - [`SampleSearchTablePlugin`] / [`SampleSearchTableProvider`] -- Plugin + UI
//!   provider for the search-based table.
//! - [`SampleSearchTableModel`] -- Table model for search results.

pub mod algorithm;
pub mod model;
pub mod plugin;
pub mod provider;
pub mod search;

pub use algorithm::{
    BasicBlockCounterFunctionAlgorithm, FunctionAlgorithm, ReferenceFunctionAlgorithm,
    SizeFunctionAlgorithm,
};
pub use model::{FunctionStatsRowObject, SampleSearchTableModel, SampleTableModel};
pub use plugin::{SampleSearchTablePlugin, SampleTablePlugin};
pub use provider::{SampleSearchTableProvider, SampleTableProvider};
pub use search::{SampleSearcher, SearchResults};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- FunctionStatsRowObject ---

    #[test]
    fn test_function_stats_row_object() {
        let row = FunctionStatsRowObject::new("main", 0x400000, "Size", 1024);
        assert_eq!(row.function_name(), "main");
        assert_eq!(row.address(), 0x400000);
        assert_eq!(row.algorithm_name(), "Size");
        assert_eq!(row.score(), 1024);
    }

    #[test]
    fn test_function_stats_display() {
        let row = FunctionStatsRowObject::new("main", 0x400000, "Size", 1024);
        let s = format!("{}", row);
        assert!(s.contains("main"));
        assert!(s.contains("Size"));
        assert!(s.contains("1024"));
    }

    // --- FunctionAlgorithm trait ---

    #[test]
    fn test_size_algorithm() {
        let alg = SizeFunctionAlgorithm::new();
        assert_eq!(alg.name(), "Size");
        // A function with body_size=512 should score 512
        let score = alg.score(512, 10, 5);
        assert_eq!(score, 512);
    }

    #[test]
    fn test_size_algorithm_zero() {
        let alg = SizeFunctionAlgorithm::new();
        let score = alg.score(0, 0, 0);
        assert_eq!(score, 0);
    }

    #[test]
    fn test_basic_block_counter_algorithm() {
        let alg = BasicBlockCounterFunctionAlgorithm::new();
        assert_eq!(alg.name(), "Basic Block Count");
        // Score is the basic block count
        let score = alg.score(100, 42, 3);
        assert_eq!(score, 42);
    }

    #[test]
    fn test_basic_block_counter_zero() {
        let alg = BasicBlockCounterFunctionAlgorithm::new();
        let score = alg.score(0, 0, 0);
        assert_eq!(score, 0);
    }

    #[test]
    fn test_reference_function_algorithm() {
        let alg = ReferenceFunctionAlgorithm::new();
        assert_eq!(alg.name(), "References To");
        // Score is the incoming reference count
        let score = alg.score(200, 8, 99);
        assert_eq!(score, 99);
    }

    #[test]
    fn test_reference_function_algorithm_zero() {
        let alg = ReferenceFunctionAlgorithm::new();
        let score = alg.score(0, 0, 0);
        assert_eq!(score, 0);
    }

    // --- SampleTableModel ---

    #[test]
    fn test_sample_table_model_columns() {
        let model = SampleTableModel::new("TestModel");
        let cols = model.column_names();
        assert_eq!(cols.len(), 4);
        assert_eq!(cols[0], "Function Name");
        assert_eq!(cols[1], "Algorithm");
        assert_eq!(cols[2], "Score");
        assert_eq!(cols[3], "Address");
    }

    #[test]
    fn test_sample_table_model_load() {
        let mut model = SampleTableModel::new("TestModel");
        let algorithms: Vec<Box<dyn FunctionAlgorithm>> = vec![
            Box::new(SizeFunctionAlgorithm::new()),
            Box::new(BasicBlockCounterFunctionAlgorithm::new()),
        ];

        // Simulate loading with a "function" having body_size=100, bb_count=5,
        // ref_count=0
        model.load_with_function("testFunc", 0x401000, 100, 5, 0, &algorithms);
        assert_eq!(model.row_count(), 2);

        let row0 = model.row(0).unwrap();
        assert_eq!(row0.function_name(), "testFunc");
        assert_eq!(row0.score(), 100); // Size

        let row1 = model.row(1).unwrap();
        assert_eq!(row1.score(), 5); // Basic Block Count
    }

    #[test]
    fn test_sample_table_model_reset() {
        let mut model = SampleTableModel::new("TestModel");
        let algorithms: Vec<Box<dyn FunctionAlgorithm>> =
            vec![Box::new(SizeFunctionAlgorithm::new())];
        model.load_with_function("f1", 0x1000, 10, 1, 0, &algorithms);
        assert_eq!(model.row_count(), 1);

        model.reset();
        assert_eq!(model.row_count(), 0);
    }

    #[test]
    fn test_sample_table_model_no_algorithms() {
        let mut model = SampleTableModel::new("TestModel");
        let algorithms: Vec<Box<dyn FunctionAlgorithm>> = vec![];
        model.load_with_function("f1", 0x1000, 10, 1, 0, &algorithms);
        assert_eq!(model.row_count(), 0);
    }

    // --- SearchResults ---

    #[test]
    fn test_search_results() {
        let sr = SearchResults::new(0x400000, "main".to_string());
        assert_eq!(sr.address(), 0x400000);
        assert_eq!(sr.display_value(), "main");
    }

    #[test]
    fn test_search_results_display() {
        let sr = SearchResults::new(0x400000, "main".to_string());
        let s = format!("{}", sr);
        assert!(s.contains("main"));
    }

    // --- SampleSearcher ---

    #[test]
    fn test_sample_searcher() {
        let functions = vec![
            (0x1000, "main".to_string(), 2),   // 2 params -> not included
            (0x2000, "helper".to_string(), 0),  // 0 params -> included
            (0x3000, "init".to_string(), 0),    // 0 params -> included
            (0x4000, "process".to_string(), 3), // 3 params -> not included
        ];
        let searcher = SampleSearcher::new(functions);
        let results = searcher.search();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].address(), 0x2000);
        assert_eq!(results[0].display_value(), "helper");
        assert_eq!(results[1].address(), 0x3000);
        assert_eq!(results[1].display_value(), "init");
    }

    #[test]
    fn test_sample_searcher_empty() {
        let searcher = SampleSearcher::new(vec![]);
        let results = searcher.search();
        assert!(results.is_empty());
    }

    #[test]
    fn test_sample_searcher_all_have_params() {
        let functions = vec![
            (0x1000, "a".to_string(), 1),
            (0x2000, "b".to_string(), 2),
        ];
        let searcher = SampleSearcher::new(functions);
        let results = searcher.search();
        assert!(results.is_empty());
    }

    // --- SampleSearchTableModel ---

    #[test]
    fn test_search_table_model_columns() {
        let model = SampleSearchTableModel::new();
        let cols = model.column_names();
        assert_eq!(cols.len(), 2);
        assert_eq!(cols[0], "Address");
        assert_eq!(cols[1], "Value");
    }

    #[test]
    fn test_search_table_model_load() {
        let mut model = SampleSearchTableModel::new();
        let results = vec![
            SearchResults::new(0x1000, "alpha".to_string()),
            SearchResults::new(0x2000, "beta".to_string()),
        ];
        model.load(results);
        assert_eq!(model.row_count(), 2);
        assert_eq!(model.row(0).unwrap().display_value(), "alpha");
        assert_eq!(model.row(1).unwrap().display_value(), "beta");
    }

    // --- Plugin-level ---

    #[test]
    fn test_sample_table_plugin_new() {
        let plugin = SampleTablePlugin::new("SampleTablePlugin");
        assert_eq!(plugin.name(), "SampleTablePlugin");
        assert!(plugin.reset_table_data());
        assert!(plugin.algorithms().is_empty());
    }

    #[test]
    fn test_sample_table_plugin_set_reset() {
        let mut plugin = SampleTablePlugin::new("SampleTablePlugin");
        plugin.set_reset_table_data(false);
        assert!(!plugin.reset_table_data());
    }

    #[test]
    fn test_sample_table_plugin_add_algorithm() {
        let mut plugin = SampleTablePlugin::new("SampleTablePlugin");
        plugin.add_algorithm(Box::new(SizeFunctionAlgorithm::new()));
        plugin.add_algorithm(Box::new(ReferenceFunctionAlgorithm::new()));
        assert_eq!(plugin.algorithms().len(), 2);
        assert_eq!(plugin.algorithms()[0].name(), "Size");
        assert_eq!(plugin.algorithms()[1].name(), "References To");
    }

    #[test]
    fn test_sample_search_table_plugin_new() {
        let functions = vec![
            (0x1000, "main".to_string(), 0),
            (0x2000, "helper".to_string(), 2),
        ];
        let plugin = SampleSearchTablePlugin::new("SampleSearchPlugin", functions);
        assert_eq!(plugin.name(), "SampleSearchPlugin");
    }

    // --- Provider ---

    #[test]
    fn test_sample_table_provider_new() {
        let provider = SampleTableProvider::new("SampleTable");
        assert_eq!(provider.name(), "SampleTable");
        assert!(provider.is_visible());
    }

    #[test]
    fn test_sample_table_provider_dispose() {
        let mut provider = SampleTableProvider::new("SampleTable");
        provider.dispose();
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_sample_search_table_provider_new() {
        let provider = SampleSearchTableProvider::new("SearchProvider");
        assert_eq!(provider.name(), "SearchProvider");
        assert!(provider.is_visible());
    }

    #[test]
    fn test_sample_search_table_provider_dispose() {
        let mut provider = SampleSearchTableProvider::new("SearchProvider");
        provider.dispose();
        assert!(!provider.is_visible());
    }
}
