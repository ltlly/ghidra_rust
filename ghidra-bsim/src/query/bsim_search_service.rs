//! BSim search service interface.
//!
//! Ports Ghidra's `ghidra.features.bsim.gui.search.BSimSearchService`.
//! Defines the high-level interface for searching BSim databases.

use super::description::{BSimFunctionDescription, BSimResultSet};
use super::server_config::ServerConfig;

/// Settings for a BSim search operation.
#[derive(Debug, Clone)]
pub struct BSimSearchSettings {
    /// Maximum number of results to return.
    pub max_results: usize,
    /// Minimum similarity threshold (0.0 to 1.0).
    pub min_similarity: f64,
    /// Minimum significance threshold.
    pub min_significance: f64,
    /// Whether to include child function analysis.
    pub include_children: bool,
    /// Specific executable name to restrict search.
    pub executable_filter: Option<String>,
    /// Architecture filter.
    pub architecture_filter: Option<String>,
    /// Compiler filter.
    pub compiler_filter: Option<String>,
}

impl Default for BSimSearchSettings {
    fn default() -> Self {
        Self {
            max_results: 100,
            min_similarity: 0.5,
            min_significance: 0.01,
            include_children: false,
            executable_filter: None,
            architecture_filter: None,
            compiler_filter: None,
        }
    }
}

/// A single BSim search result.
#[derive(Debug, Clone)]
pub struct BSimSearchResultEntry {
    /// The function description.
    pub function: BSimFunctionDescription,
    /// Similarity score.
    pub similarity: f64,
    /// Significance score.
    pub significance: f64,
    /// The executable name containing the matched function.
    pub executable_name: String,
    /// The architecture.
    pub architecture: String,
    /// Whether this result includes child analysis.
    pub has_child_analysis: bool,
}

/// Status of a BSim search operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BSimSearchStatus {
    /// Not started.
    Idle,
    /// Currently searching.
    Searching,
    /// Completed successfully.
    Complete,
    /// Encountered an error.
    Error,
    /// Cancelled by user.
    Cancelled,
}

/// Trait defining the BSim search service interface.
///
/// Ports Ghidra's `BSimSearchService`. Provides a high-level API for
/// searching BSim databases for similar functions.
pub trait BSimSearchService: Send + Sync {
    /// Search for functions similar to the given description.
    fn search(
        &self,
        query: &BSimFunctionDescription,
        settings: &BSimSearchSettings,
    ) -> BSimResultSet;

    /// Get the current search status.
    fn status(&self) -> BSimSearchStatus;

    /// Cancel an in-progress search.
    fn cancel(&self);

    /// Get the server configuration for this service.
    fn server_config(&self) -> &ServerConfig;
}

/// In-memory mock implementation of the search service for testing.
#[derive(Debug)]
pub struct MockBSimSearchService {
    config: ServerConfig,
    results: Vec<BSimSearchResultEntry>,
    status: BSimSearchStatus,
}

impl MockBSimSearchService {
    /// Create a new mock search service.
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            results: Vec::new(),
            status: BSimSearchStatus::Idle,
        }
    }

    /// Add a mock result.
    pub fn add_result(&mut self, result: BSimSearchResultEntry) {
        self.results.push(result);
    }

    /// Get the mock results.
    pub fn results(&self) -> &[BSimSearchResultEntry] {
        &self.results
    }
}

impl BSimSearchService for MockBSimSearchService {
    fn search(
        &self,
        _query: &BSimFunctionDescription,
        settings: &BSimSearchSettings,
    ) -> BSimResultSet {
        // Return mock results filtered by settings
        let filtered: Vec<_> = self
            .results
            .iter()
            .filter(|r| r.similarity >= settings.min_similarity)
            .filter(|r| r.significance >= settings.min_significance)
            .take(settings.max_results)
            .cloned()
            .collect();

        BSimResultSet {
            results: filtered.iter().map(|r| r.function.clone()).collect(),
            total_matches: filtered.len(),
            query_time_ms: 0,
        }
    }

    fn status(&self) -> BSimSearchStatus {
        self.status
    }

    fn cancel(&self) {
        // No-op in mock
    }

    fn server_config(&self) -> &ServerConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_settings_default() {
        let s = BSimSearchSettings::default();
        assert_eq!(s.max_results, 100);
        assert!((s.min_similarity - 0.5).abs() < 1e-6);
        assert!(s.min_significance > 0.0);
        assert!(!s.include_children);
        assert!(s.executable_filter.is_none());
    }

    #[test]
    fn search_status_variants() {
        assert_ne!(BSimSearchStatus::Idle, BSimSearchStatus::Searching);
        assert_ne!(BSimSearchStatus::Complete, BSimSearchStatus::Error);
    }

    #[test]
    fn mock_search_service() {
        let config = ServerConfig::postgresql("localhost", "test");
        let mut service = MockBSimSearchService::new(config);
        assert_eq!(service.status(), BSimSearchStatus::Idle);

        let entry = BSimSearchResultEntry {
            function: BSimFunctionDescription::new("exe1", "func1", 0x1000),
            similarity: 0.95,
            significance: 0.01,
            executable_name: "test.exe".to_string(),
            architecture: "x86".to_string(),
            has_child_analysis: false,
        };
        service.add_result(entry);
        assert_eq!(service.results().len(), 1);
    }

    #[test]
    fn mock_search_filters() {
        let config = ServerConfig::postgresql("localhost", "test");
        let mut service = MockBSimSearchService::new(config);

        service.add_result(BSimSearchResultEntry {
            function: BSimFunctionDescription::new("exe1", "f1", 0x1000),
            similarity: 0.9,
            significance: 0.1,
            executable_name: "test.exe".to_string(),
            architecture: "x86".to_string(),
            has_child_analysis: false,
        });
        service.add_result(BSimSearchResultEntry {
            function: BSimFunctionDescription::new("exe1", "f2", 0x2000),
            similarity: 0.3,
            significance: 0.1,
            executable_name: "test.exe".to_string(),
            architecture: "x86".to_string(),
            has_child_analysis: false,
        });

        let query = BSimFunctionDescription::new("exe1", "query", 0x0);
        let settings = BSimSearchSettings {
            min_similarity: 0.5,
            ..Default::default()
        };

        let results = service.search(&query, &settings);
        assert_eq!(results.total_matches, 1); // Only f1 passes threshold
    }

    #[test]
    fn mock_search_server_config() {
        let config = ServerConfig::elasticsearch("eshost", 9200);
        let service = MockBSimSearchService::new(config);
        assert_eq!(service.server_config().backend_type, "elastic");
    }
}
