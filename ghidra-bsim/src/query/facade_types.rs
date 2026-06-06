//! BSim facade types -- high-level convenience API.
//!
//! Port of Ghidra's `ghidra.features.bsim.query.facade` package:
//! - `SimilarFunctionQueryService`: the main query service interface
//! - `SFQueryServiceFactory`: factory for creating query services
//! - `SFQueryInfo`: query info bundle
//! - `SFQueryResult`: query result bundle
//! - `SFOverviewInfo`: overview info for a BSim database
//! - `DatabaseInfo`: database metadata
//! - `FunctionSymbolIterator`: iterator over function symbols
//! - `QueryDatabaseException`: database error type
//! - `SFResultsUpdateListener`: listener for results updates

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Exception for query database operations.
///
/// Port of `ghidra.features.bsim.query.facade.QueryDatabaseException`.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Query database error: {message}")]
pub struct QueryDatabaseException {
    /// Error message.
    pub message: String,
    /// Underlying error cause (if any).
    pub cause: Option<String>,
}

impl QueryDatabaseException {
    /// Create a new query database exception.
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into(), cause: None }
    }

    /// Create with a cause.
    pub fn with_cause(message: impl Into<String>, cause: impl Into<String>) -> Self {
        Self { message: message.into(), cause: Some(cause.into()) }
    }
}

/// Database info metadata.
///
/// Port of `ghidra.features.bsim.query.facade.DatabaseInfo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseInfo {
    /// Database name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Number of executables.
    pub exe_count: u64,
    /// Number of functions.
    pub function_count: u64,
    /// Creation date (ISO-8601).
    pub creation_date: String,
    /// Schema version.
    pub schema_version: u32,
}

impl DatabaseInfo {
    /// Create a new database info.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            exe_count: 0,
            function_count: 0,
            creation_date: String::new(),
            schema_version: 1,
        }
    }
}

/// Overview info for a BSim database.
///
/// Port of `ghidra.features.bsim.query.facade.SFOverviewInfo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SfOverviewInfo {
    /// Database info.
    pub database_info: DatabaseInfo,
    /// Total number of matches found.
    pub total_matches: u64,
    /// Number of unique executables with matches.
    pub matched_exes: u64,
    /// Average similarity score.
    pub average_score: f64,
}

impl SfOverviewInfo {
    /// Create a new overview info.
    pub fn new(database_info: DatabaseInfo) -> Self {
        Self {
            database_info,
            total_matches: 0,
            matched_exes: 0,
            average_score: 0.0,
        }
    }
}

/// Query info bundle.
///
/// Port of `ghidra.features.bsim.query.facade.SFQueryInfo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SfQueryInfo {
    /// The query name.
    pub query_name: String,
    /// The database to query.
    pub database_name: String,
    /// Similarity threshold.
    pub similarity_threshold: f64,
    /// Maximum results.
    pub max_results: usize,
    /// Additional filter parameters.
    pub filters: HashMap<String, String>,
}

impl SfQueryInfo {
    /// Create a new query info.
    pub fn new(query_name: impl Into<String>, database_name: impl Into<String>) -> Self {
        Self {
            query_name: query_name.into(),
            database_name: database_name.into(),
            similarity_threshold: 0.8,
            max_results: 100,
            filters: HashMap::new(),
        }
    }

    /// Set similarity threshold.
    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.similarity_threshold = threshold;
        self
    }
}

/// Query result bundle.
///
/// Port of `ghidra.features.bsim.query.facade.SFQueryResult`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SfQueryResult {
    /// The query info that produced this result.
    pub query_info: SfQueryInfo,
    /// Result rows (function hash -> score).
    pub results: Vec<SfResultRow>,
    /// Total number of results before truncation.
    pub total_count: u64,
    /// Query execution time in milliseconds.
    pub execution_time_ms: u64,
}

impl SfQueryResult {
    /// Create a new empty query result.
    pub fn new(query_info: SfQueryInfo) -> Self {
        Self { query_info, results: Vec::new(), total_count: 0, execution_time_ms: 0 }
    }

    /// Whether the result set is empty.
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    /// Number of result rows.
    pub fn len(&self) -> usize {
        self.results.len()
    }
}

/// A single result row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SfResultRow {
    /// Function name.
    pub function_name: String,
    /// Executable name.
    pub executable_name: String,
    /// Similarity score.
    pub score: f64,
    /// Address of the matched function (if known).
    pub address: Option<u64>,
}

impl SfResultRow {
    /// Create a new result row.
    pub fn new(
        function_name: impl Into<String>,
        executable_name: impl Into<String>,
        score: f64,
    ) -> Self {
        Self {
            function_name: function_name.into(),
            executable_name: executable_name.into(),
            score,
            address: None,
        }
    }
}

/// Iterator over function symbols in a BSim result.
///
/// Port of `ghidra.features.bsim.query.facade.FunctionSymbolIterator`.
#[derive(Debug)]
pub struct FunctionSymbolIterator {
    items: Vec<SfResultRow>,
    index: usize,
}

impl FunctionSymbolIterator {
    /// Create a new iterator from result rows.
    pub fn new(items: Vec<SfResultRow>) -> Self {
        Self { items, index: 0 }
    }

    /// Number of remaining items.
    pub fn remaining(&self) -> usize {
        self.items.len().saturating_sub(self.index)
    }
}

impl Iterator for FunctionSymbolIterator {
    type Item = SfResultRow;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.items.len() {
            let item = self.items[self.index].clone();
            self.index += 1;
            Some(item)
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.remaining();
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for FunctionSymbolIterator {}

/// Listener for query results updates.
///
/// Port of `ghidra.features.bsim.query.facade.SFResultsUpdateListener`.
pub trait SfResultsUpdateListener: std::fmt::Debug {
    /// Called when results are updated.
    fn results_updated(&self, results: &SfQueryResult);

    /// Called when the query encounters an error.
    fn query_error(&self, error: &QueryDatabaseException);
}

/// Factory for creating SimilarFunctionQueryService instances.
///
/// Port of `ghidra.features.bsim.query.facade.SFQueryServiceFactory`.
pub trait SfQueryServiceFactory: std::fmt::Debug {
    /// Create a new query service for the given server.
    fn create_service(&self, server_url: &str) -> Result<Box<dyn SimilarFunctionQueryService>, QueryDatabaseException>;
}

/// The main query service interface for BSim.
///
/// Port of `ghidra.features.bsim.query.facade.SimilarFunctionQueryService`.
pub trait SimilarFunctionQueryService: std::fmt::Debug {
    /// Execute a query.
    fn query(&self, info: &SfQueryInfo) -> Result<SfQueryResult, QueryDatabaseException>;

    /// Get overview information for the database.
    fn overview(&self, database_name: &str) -> Result<SfOverviewInfo, QueryDatabaseException>;

    /// List available databases.
    fn list_databases(&self) -> Result<Vec<DatabaseInfo>, QueryDatabaseException>;

    /// Whether the service is connected.
    fn is_connected(&self) -> bool;
}

/// Default factory implementation (placeholder).
///
/// Port of `ghidra.features.bsim.query.facade.DefaultSFQueryServiceFactory`.
#[derive(Debug, Default)]
pub struct DefaultSfQueryServiceFactory;

impl DefaultSfQueryServiceFactory {
    /// Create a new default factory.
    pub fn new() -> Self {
        Self
    }
}

impl SfQueryServiceFactory for DefaultSfQueryServiceFactory {
    fn create_service(&self, _server_url: &str) -> Result<Box<dyn SimilarFunctionQueryService>, QueryDatabaseException> {
        Err(QueryDatabaseException::new("Default factory does not create real services"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_database_exception() {
        let e = QueryDatabaseException::new("connection failed");
        assert!(e.cause.is_none());
        let e2 = QueryDatabaseException::with_cause("failed", "timeout");
        assert_eq!(e2.cause, Some("timeout".into()));
    }

    #[test]
    fn test_database_info() {
        let info = DatabaseInfo::new("my_bsim_db");
        assert_eq!(info.name, "my_bsim_db");
        assert_eq!(info.schema_version, 1);
    }

    #[test]
    fn test_sf_overview_info() {
        let overview = SfOverviewInfo::new(DatabaseInfo::new("test"));
        assert_eq!(overview.total_matches, 0);
        assert!((overview.average_score).abs() < f64::EPSILON);
    }

    #[test]
    fn test_sf_query_info() {
        let info = SfQueryInfo::new("q1", "db1").with_threshold(0.9);
        assert!((info.similarity_threshold - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn test_sf_query_result() {
        let info = SfQueryInfo::new("q1", "db1");
        let mut result = SfQueryResult::new(info);
        assert!(result.is_empty());
        result.results.push(SfResultRow::new("main", "libc.so", 0.95));
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_function_symbol_iterator() {
        let rows = vec![
            SfResultRow::new("main", "a.out", 0.9),
            SfResultRow::new("init", "a.out", 0.8),
            SfResultRow::new("exit", "a.out", 0.7),
        ];
        let mut iter = FunctionSymbolIterator::new(rows);
        assert_eq!(iter.len(), 3);
        assert_eq!(iter.next().unwrap().function_name, "main");
        assert_eq!(iter.remaining(), 2);
    }

    #[test]
    fn test_sf_result_row() {
        let row = SfResultRow::new("func", "lib.so", 0.85);
        assert_eq!(row.function_name, "func");
        assert_eq!(row.executable_name, "lib.so");
        assert!((row.score - 0.85).abs() < f64::EPSILON);
    }

    #[test]
    fn test_default_factory() {
        let factory = DefaultSfQueryServiceFactory::new();
        let result = factory.create_service("http://localhost");
        assert!(result.is_err());
    }
}
