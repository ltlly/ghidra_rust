//! Search infrastructure for the Sample Table Plugin extension.
//!
//! Ported from `SampleSearcher.java` and `SearchResults.java` in the
//! SampleTablePlugin extension.
//!
//! The searcher iterates over functions in a program and collects
//! zero-parameter functions as search results.

use std::fmt;

// ---------------------------------------------------------------------------
// SearchResults
// ---------------------------------------------------------------------------

/// A single search result row.
///
/// Ported from `SearchResults.java`. Holds the entry-point address and
/// display name for a function that matched the search criteria.
#[derive(Debug, Clone)]
pub struct SearchResults {
    /// Entry-point address of the matching function.
    address: u64,
    /// Display value (typically the function name).
    display_value: String,
}

impl SearchResults {
    /// Create a new search result.
    pub fn new(address: u64, display_value: String) -> Self {
        Self {
            address,
            display_value,
        }
    }

    /// Entry-point address.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Display value (function name).
    pub fn display_value(&self) -> &str {
        &self.display_value
    }
}

impl fmt::Display for SearchResults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SearchResult[0x{:x}: {}]", self.address, self.display_value)
    }
}

// ---------------------------------------------------------------------------
// SampleSearcher
// ---------------------------------------------------------------------------

/// Represents a function in the search space.
#[derive(Debug, Clone)]
pub struct FunctionEntry {
    /// Entry-point address.
    pub address: u64,
    /// Function name.
    pub name: String,
    /// Number of parameters.
    pub param_count: usize,
}

/// Searches for zero-parameter functions in a program.
///
/// Ported from `SampleSearcher.java`. In the Java original this operates
/// on a `Program` object and its `FunctionManager`. In Rust we provide a
/// standalone searcher that takes a list of [`FunctionEntry`] items.
///
/// The search collects all functions with `param_count == 0`.
#[derive(Debug)]
pub struct SampleSearcher {
    /// The functions to search through.
    functions: Vec<FunctionEntry>,
}

impl SampleSearcher {
    /// Create a new searcher with the given function entries.
    ///
    /// Each entry is `(address, name, param_count)`.
    pub fn new(functions: Vec<(u64, String, usize)>) -> Self {
        Self {
            functions: functions
                .into_iter()
                .map(|(addr, name, pc)| FunctionEntry {
                    address: addr,
                    name,
                    param_count: pc,
                })
                .collect(),
        }
    }

    /// Create a new searcher from pre-built entries.
    pub fn from_entries(functions: Vec<FunctionEntry>) -> Self {
        Self { functions }
    }

    /// Perform the search and return matching results.
    ///
    /// Returns all functions with zero parameters, in iteration order.
    pub fn search(&self) -> Vec<SearchResults> {
        self.functions
            .iter()
            .filter(|f| f.param_count == 0)
            .map(|f| SearchResults::new(f.address, f.name.clone()))
            .collect()
    }

    /// The number of functions in the search space.
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_results_new() {
        let sr = SearchResults::new(0x400000, "main".to_string());
        assert_eq!(sr.address(), 0x400000);
        assert_eq!(sr.display_value(), "main");
    }

    #[test]
    fn test_search_results_clone() {
        let sr = SearchResults::new(0x1000, "f".to_string());
        let cloned = sr.clone();
        assert_eq!(cloned.address(), sr.address());
        assert_eq!(cloned.display_value(), sr.display_value());
    }

    #[test]
    fn test_search_results_display() {
        let sr = SearchResults::new(0xDEAD, "beef".to_string());
        let s = format!("{}", sr);
        assert!(s.contains("dead"));
        assert!(s.contains("beef"));
    }

    #[test]
    fn test_searcher_basic() {
        let searcher = SampleSearcher::new(vec![
            (0x1000, "main".to_string(), 2),
            (0x2000, "helper".to_string(), 0),
            (0x3000, "init".to_string(), 0),
        ]);
        let results = searcher.search();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].address(), 0x2000);
        assert_eq!(results[0].display_value(), "helper");
        assert_eq!(results[1].address(), 0x3000);
    }

    #[test]
    fn test_searcher_no_matches() {
        let searcher = SampleSearcher::new(vec![
            (0x1000, "a".to_string(), 1),
            (0x2000, "b".to_string(), 5),
        ]);
        assert!(searcher.search().is_empty());
    }

    #[test]
    fn test_searcher_empty() {
        let searcher = SampleSearcher::new(vec![]);
        assert!(searcher.search().is_empty());
        assert_eq!(searcher.function_count(), 0);
    }

    #[test]
    fn test_searcher_all_match() {
        let searcher = SampleSearcher::new(vec![
            (0x1000, "a".to_string(), 0),
            (0x2000, "b".to_string(), 0),
        ]);
        assert_eq!(searcher.search().len(), 2);
    }

    #[test]
    fn test_searcher_function_count() {
        let searcher = SampleSearcher::new(vec![
            (0x1000, "a".to_string(), 0),
            (0x2000, "b".to_string(), 1),
            (0x3000, "c".to_string(), 2),
        ]);
        assert_eq!(searcher.function_count(), 3);
    }

    #[test]
    fn test_searcher_from_entries() {
        let entries = vec![
            FunctionEntry {
                address: 0x100,
                name: "zero_param".to_string(),
                param_count: 0,
            },
            FunctionEntry {
                address: 0x200,
                name: "one_param".to_string(),
                param_count: 1,
            },
        ];
        let searcher = SampleSearcher::from_entries(entries);
        let results = searcher.search();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].address(), 0x100);
    }
}
