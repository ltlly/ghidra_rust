//! Plugin implementations for the Sample Table Plugin extension.
//!
//! Ported from `SampleTablePlugin.java` and `SampleSearchTablePlugin.java`
//! in the SampleTablePlugin extension.
//!
//! Each plugin manages its lifecycle, algorithm registration, and
//! option handling.

use super::algorithm::FunctionAlgorithm;

// ---------------------------------------------------------------------------
// SampleTablePlugin
// ---------------------------------------------------------------------------

/// The main sample table plugin.
///
/// Ported from `SampleTablePlugin.java`. Manages a list of
/// [`FunctionAlgorithm`]s and the "reset table data" option. In the
/// Java original this extends `ProgramPlugin` and creates a
/// `SampleTableProvider` on `init()`.
#[derive(Debug)]
pub struct SampleTablePlugin {
    /// Plugin name.
    name: String,
    /// Registered algorithms.
    algorithms: Vec<Box<dyn FunctionAlgorithm>>,
    /// Whether to reset (clear) existing table data before loading.
    reset_table_data: bool,
}

impl SampleTablePlugin {
    /// Create a new plugin with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            algorithms: Vec::new(),
            reset_table_data: true,
        }
    }

    /// Plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether to reset table data before reload.
    pub fn reset_table_data(&self) -> bool {
        self.reset_table_data
    }

    /// Set the reset-table-data option.
    pub fn set_reset_table_data(&mut self, value: bool) {
        self.reset_table_data = value;
    }

    /// Add a scoring algorithm.
    pub fn add_algorithm(&mut self, algorithm: Box<dyn FunctionAlgorithm>) {
        self.algorithms.push(algorithm);
    }

    /// Get the registered algorithms.
    pub fn algorithms(&self) -> &[Box<dyn FunctionAlgorithm>] {
        &self.algorithms
    }

    /// Discover default algorithms.
    ///
    /// In the Java original, algorithms are discovered at runtime via
    /// `ClassSearcher.getInstances(FunctionAlgorithm.class)`. Here we
    /// return the three built-in algorithms.
    pub fn discover_default_algorithms() -> Vec<Box<dyn FunctionAlgorithm>> {
        vec![
            Box::new(super::algorithm::SizeFunctionAlgorithm::new()),
            Box::new(super::algorithm::BasicBlockCounterFunctionAlgorithm::new()),
            Box::new(super::algorithm::ReferenceFunctionAlgorithm::new()),
        ]
    }
}

// ---------------------------------------------------------------------------
// SampleSearchTablePlugin
// ---------------------------------------------------------------------------

/// The search-based table plugin.
///
/// Ported from `SampleSearchTablePlugin.java`. Provides a component
/// provider for displaying zero-parameter function search results.
#[derive(Debug)]
pub struct SampleSearchTablePlugin {
    /// Plugin name.
    name: String,
    /// Functions to search through.
    functions: Vec<(u64, String, usize)>,
}

impl SampleSearchTablePlugin {
    /// Create a new search table plugin.
    ///
    /// Each function entry is `(address, name, param_count)`.
    pub fn new(name: impl Into<String>, functions: Vec<(u64, String, usize)>) -> Self {
        Self {
            name: name.into(),
            functions,
        }
    }

    /// Plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the function entries.
    pub fn functions(&self) -> &[(u64, String, usize)] {
        &self.functions
    }

    /// Perform the search using the plugin's function list.
    pub fn search(&self) -> Vec<super::search::SearchResults> {
        let searcher = super::search::SampleSearcher::new(self.functions.clone());
        searcher.search()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample_table_plugin::algorithm::{
        BasicBlockCounterFunctionAlgorithm, SizeFunctionAlgorithm,
    };

    #[test]
    fn test_plugin_new() {
        let plugin = SampleTablePlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert!(plugin.reset_table_data());
        assert!(plugin.algorithms().is_empty());
    }

    #[test]
    fn test_plugin_set_reset() {
        let mut plugin = SampleTablePlugin::new("P");
        plugin.set_reset_table_data(false);
        assert!(!plugin.reset_table_data());
        plugin.set_reset_table_data(true);
        assert!(plugin.reset_table_data());
    }

    #[test]
    fn test_plugin_add_algorithms() {
        let mut plugin = SampleTablePlugin::new("P");
        plugin.add_algorithm(Box::new(SizeFunctionAlgorithm::new()));
        plugin.add_algorithm(Box::new(BasicBlockCounterFunctionAlgorithm::new()));
        assert_eq!(plugin.algorithms().len(), 2);
    }

    #[test]
    fn test_plugin_discover_defaults() {
        let algs = SampleTablePlugin::discover_default_algorithms();
        assert_eq!(algs.len(), 3);
        assert_eq!(algs[0].name(), "Size");
        assert_eq!(algs[1].name(), "Basic Block Count");
        assert_eq!(algs[2].name(), "References To");
    }

    #[test]
    fn test_search_plugin_new() {
        let funcs = vec![
            (0x1000, "a".to_string(), 0),
            (0x2000, "b".to_string(), 2),
        ];
        let plugin = SampleSearchTablePlugin::new("SP", funcs);
        assert_eq!(plugin.name(), "SP");
        assert_eq!(plugin.functions().len(), 2);
    }

    #[test]
    fn test_search_plugin_search() {
        let funcs = vec![
            (0x1000, "main".to_string(), 0),
            (0x2000, "helper".to_string(), 2),
            (0x3000, "init".to_string(), 0),
        ];
        let plugin = SampleSearchTablePlugin::new("SP", funcs);
        let results = plugin.search();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].display_value(), "main");
        assert_eq!(results[1].display_value(), "init");
    }

    #[test]
    fn test_search_plugin_no_matches() {
        let funcs = vec![(0x1000, "a".to_string(), 5)];
        let plugin = SampleSearchTablePlugin::new("SP", funcs);
        assert!(plugin.search().is_empty());
    }
}
