//! Similar Function Query Service -- high-level query API.
//!
//! Ports `ghidra.features.bsim.query.facade.SimilarFunctionQueryService`,
//! `SFQueryInfo`, `SFQueryResult`, `SFOverviewInfo`, `SFResultsUpdateListener`,
//! `DatabaseInfo`, `SFQueryServiceFactory`, `DefaultSFQueryServiceFactory`,
//! `FunctionSymbolIterator`, `QueryDatabaseException` from Ghidra's Java source.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::description::{BSimExecutableInfo, BSimFunctionDescription, SimilarityMetric};
use super::function_database::FunctionDatabase;
use super::BSimResult;

/// Information about a BSim query that can be sent to the server.
///
/// Port of `ghidra.features.bsim.query.facade.SFQueryInfo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SFQueryInfo {
    /// The function to search for.
    pub function: BSimFunctionDescription,
    /// Maximum number of results.
    pub max_results: usize,
    /// Minimum similarity threshold.
    pub min_similarity: f64,
    /// The similarity metric to use.
    pub metric: SimilarityMetric,
    /// Whether to include signatures in results.
    pub include_signatures: bool,
    /// Whether to include callgraph information.
    pub include_callgraph: bool,
    /// The number of query stages (for staged queries).
    pub num_stages: usize,
}

impl SFQueryInfo {
    /// Create a new SFQueryInfo with a function to search for.
    pub fn new(function: BSimFunctionDescription) -> Self {
        Self {
            function,
            max_results: 100,
            min_similarity: 0.5,
            metric: SimilarityMetric::Combined,
            include_signatures: false,
            include_callgraph: false,
            num_stages: 0,
        }
    }

    /// Set the maximum results.
    pub fn with_max_results(mut self, max: usize) -> Self {
        self.max_results = max;
        self
    }

    /// Set the minimum similarity threshold.
    pub fn with_min_similarity(mut self, threshold: f64) -> Self {
        self.min_similarity = threshold;
        self
    }

    /// Set the similarity metric.
    pub fn with_metric(mut self, metric: SimilarityMetric) -> Self {
        self.metric = metric;
        self
    }

    /// Enable or disable signature inclusion.
    pub fn with_signatures(mut self, include: bool) -> Self {
        self.include_signatures = include;
        self
    }

    /// Enable or disable callgraph inclusion.
    pub fn with_callgraph(mut self, include: bool) -> Self {
        self.include_callgraph = include;
        self
    }

    /// Set the number of query stages.
    pub fn with_stages(mut self, num_stages: usize) -> Self {
        self.num_stages = num_stages;
        self
    }
}

/// Information about the database server.
///
/// Port of `ghidra.features.bsim.query.facade.DatabaseInfo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseInfo {
    /// Server URL.
    pub server_url: String,
    /// Database name.
    pub database_name: String,
    /// Total function count.
    pub total_functions: usize,
    /// Total executable count.
    pub total_executables: usize,
    /// Database creation date (Unix timestamp).
    pub creation_date: Option<i64>,
    /// Database version.
    pub version: String,
}

impl DatabaseInfo {
    /// Create a new DatabaseInfo.
    pub fn new(server_url: impl Into<String>, database_name: impl Into<String>) -> Self {
        Self {
            server_url: server_url.into(),
            database_name: database_name.into(),
            total_functions: 0,
            total_executables: 0,
            creation_date: None,
            version: String::new(),
        }
    }
}

/// Overview information about a BSim database.
///
/// Port of `ghidra.features.bsim.query.facade.SFOverviewInfo`.
#[derive(Debug, Clone, Default)]
pub struct SFOverviewInfo {
    /// The database info.
    pub database_info: Option<DatabaseInfo>,
    /// List of executables in the database.
    pub executables: Vec<BSimExecutableInfo>,
    /// Total number of functions.
    pub total_functions: usize,
    /// Total number of executables.
    pub total_executables: usize,
}

impl SFOverviewInfo {
    /// Create a new overview info.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the executable count.
    pub fn executable_count(&self) -> usize {
        self.executables.len()
    }
}

/// Result of a similar function query.
///
/// Port of `ghidra.features.bsim.query.facade.SFQueryResult`.
#[derive(Debug, Clone)]
pub struct SFQueryResult {
    /// The original query info.
    pub query_info: SFQueryInfo,
    /// The database info.
    pub database_info: Option<DatabaseInfo>,
    /// The list of similarity results.
    pub results: Vec<SimilarityResult>,
}

impl SFQueryResult {
    /// Create a new query result.
    pub fn new(query_info: SFQueryInfo) -> Self {
        Self {
            query_info,
            database_info: None,
            results: Vec::new(),
        }
    }

    /// Get the number of results.
    pub fn result_count(&self) -> usize {
        self.results.len()
    }

    /// Get the top result (highest similarity).
    pub fn top_result(&self) -> Option<&SimilarityResult> {
        self.results
            .iter()
            .max_by(|a, b| a.similarity.partial_cmp(&b.similarity).unwrap_or(std::cmp::Ordering::Equal))
    }
}

/// A single similarity result from a BSim query.
///
/// Ports the similarity result types from the protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarityResult {
    /// The matched function description.
    pub matched_function: BSimFunctionDescription,
    /// The similarity score (0.0 to 1.0).
    pub similarity: f64,
    /// The executable containing the matched function.
    pub executable_name: String,
    /// The score breakdown by metric.
    pub score_breakdown: std::collections::HashMap<String, f64>,
    /// Callgraph match information.
    pub callgraph_match: Option<CallgraphMatchInfo>,
}

impl SimilarityResult {
    /// Create a new similarity result.
    pub fn new(
        matched_function: BSimFunctionDescription,
        similarity: f64,
        executable_name: impl Into<String>,
    ) -> Self {
        Self {
            matched_function,
            similarity,
            executable_name: executable_name.into(),
            score_breakdown: std::collections::HashMap::new(),
            callgraph_match: None,
        }
    }
}

/// Callgraph match information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallgraphMatchInfo {
    /// Number of matched children.
    pub matched_children: usize,
    /// Total children in the original function.
    pub total_children: usize,
    /// The callgraph similarity score.
    pub score: f64,
}

/// Listener for updates during BSim results retrieval.
///
/// Port of `ghidra.features.bsim.query.facade.SFResultsUpdateListener`.
pub trait SFResultsUpdateListener: Send + Sync {
    /// Called when new results arrive.
    fn on_results_update(&self, results: &[SimilarityResult]);

    /// Called when the query is complete.
    fn on_complete(&self, result: &SFQueryResult);

    /// Called when an error occurs.
    fn on_error(&self, error: &str);
}

/// Iterator over function symbols in a BSim database.
///
/// Port of `ghidra.features.bsim.query.facade.FunctionSymbolIterator`.
pub struct FunctionSymbolIterator {
    functions: Vec<BSimFunctionDescription>,
    index: usize,
}

impl FunctionSymbolIterator {
    /// Create a new iterator over the given functions.
    pub fn new(functions: Vec<BSimFunctionDescription>) -> Self {
        Self {
            functions,
            index: 0,
        }
    }

    /// Get the total number of functions.
    pub fn total(&self) -> usize {
        self.functions.len()
    }
}

impl Iterator for FunctionSymbolIterator {
    type Item = BSimFunctionDescription;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.functions.len() {
            let item = self.functions[self.index].clone();
            self.index += 1;
            Some(item)
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.functions.len() - self.index;
        (remaining, Some(remaining))
    }
}

/// Error type for BSim query operations.
///
/// Port of `ghidra.features.bsim.query.facade.QueryDatabaseException`.
#[derive(Debug, Clone)]
pub struct QueryDatabaseException {
    /// Error message.
    pub message: String,
    /// The underlying cause (if any).
    pub cause: Option<String>,
}

impl QueryDatabaseException {
    /// Create a new query database exception.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            cause: None,
        }
    }

    /// Create with a cause.
    pub fn with_cause(message: impl Into<String>, cause: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            cause: Some(cause.into()),
        }
    }
}

impl fmt::Display for QueryDatabaseException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BSim query error: {}", self.message)?;
        if let Some(cause) = &self.cause {
            write!(f, " (caused by: {})", cause)?;
        }
        Ok(())
    }
}

impl std::error::Error for QueryDatabaseException {}

impl From<super::BSimError> for QueryDatabaseException {
    fn from(e: super::BSimError) -> Self {
        QueryDatabaseException::new(e.to_string())
    }
}

/// Factory for creating `SimilarFunctionQueryService` instances.
///
/// Port of `ghidra.features.bsim.query.facade.SFQueryServiceFactory` and
/// `DefaultSFQueryServiceFactory`.
pub trait SFQueryServiceFactory: Send + Sync {
    /// Create a new query service.
    fn create_service(&self) -> BSimResult<Box<dyn FunctionDatabase>>;

    /// Get the factory name.
    fn name(&self) -> &str;
}

/// Default implementation of the query service factory.
#[derive(Debug)]
pub struct DefaultSFQueryServiceFactory {
    /// Server configuration.
    pub server_config: super::server_config::ServerConfig,
}

impl DefaultSFQueryServiceFactory {
    /// Create a new factory with the given server configuration.
    pub fn new(server_config: super::server_config::ServerConfig) -> Self {
        Self { server_config }
    }
}

impl SFQueryServiceFactory for DefaultSFQueryServiceFactory {
    fn create_service(&self) -> BSimResult<Box<dyn FunctionDatabase>> {
        super::client::BSimClientFactory::create_from_config(&self.server_config)
    }

    fn name(&self) -> &str {
        "DefaultSFQueryServiceFactory"
    }
}

/// Main service for querying similar functions.
///
/// Port of `ghidra.features.bsim.query.facade.SimilarFunctionQueryService`.
pub struct SimilarFunctionQueryService {
    database: Box<dyn FunctionDatabase>,
    num_stages: usize,
}

impl SimilarFunctionQueryService {
    /// Create a new query service with the given database.
    pub fn new(database: Box<dyn FunctionDatabase>) -> Self {
        Self {
            database,
            num_stages: 0,
        }
    }

    /// Create a new query service using a factory.
    pub fn from_factory(factory: &dyn SFQueryServiceFactory) -> BSimResult<Self> {
        let database = factory.create_service()?;
        Ok(Self::new(database))
    }

    /// Open the database connection.
    pub fn open(&mut self) -> BSimResult<()> {
        self.database.open()
    }

    /// Close the database connection.
    pub fn close(&mut self) -> BSimResult<()> {
        self.database.close()
    }

    /// Query for similar functions.
    pub fn query_similar(
        &self,
        info: &SFQueryInfo,
    ) -> BSimResult<SFQueryResult> {
        let results = self.database.query_similar(
            &info.function,
            info.metric.clone(),
            info.max_results,
            info.min_similarity,
        )?;

        let similarity_results: Vec<SimilarityResult> = results
            .results
            .iter()
            .map(|m| {
                // BSimFunctionDescription has function_name and executable_id
                // Use a default similarity of 1.0 for direct matches
                SimilarityResult::new(
                    m.clone(),
                    1.0,
                    m.executable_id.clone(),
                )
            })
            .collect();

        let mut result = SFQueryResult::new(info.clone());
        result.results = similarity_results;
        Ok(result)
    }

    /// Get database overview information.
    pub fn get_overview(&self) -> BSimResult<SFOverviewInfo> {
        let mut overview = SFOverviewInfo::new();
        overview.total_functions = self.database.function_count()?;
        overview.total_executables = self.database.executable_count()?;
        Ok(overview)
    }

    /// Set the number of query stages.
    pub fn set_num_stages(&mut self, stages: usize) {
        self.num_stages = stages;
    }

    /// Get the number of query stages.
    pub fn num_stages(&self) -> usize {
        self.num_stages
    }

    /// Access the underlying database.
    pub fn database(&self) -> &dyn FunctionDatabase {
        self.database.as_ref()
    }

    /// Access the underlying database mutably.
    pub fn database_mut(&mut self) -> &mut dyn FunctionDatabase {
        self.database.as_mut()
    }
}

impl Drop for SimilarFunctionQueryService {
    fn drop(&mut self) {
        let _ = self.database.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sf_query_info_new() {
        let func = BSimFunctionDescription::new("exe1", "test_func", 0x1000);
        let info = SFQueryInfo::new(func);
        assert_eq!(info.max_results, 100);
        assert!((info.min_similarity - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_sf_query_info_builder() {
        let func = BSimFunctionDescription::new("exe1", "test_func", 0x1000);
        let info = SFQueryInfo::new(func)
            .with_max_results(50)
            .with_min_similarity(0.8)
            .with_metric(SimilarityMetric::Cosine)
            .with_signatures(true)
            .with_stages(3);
        assert_eq!(info.max_results, 50);
        assert!((info.min_similarity - 0.8).abs() < f64::EPSILON);
        assert!(info.include_signatures);
        assert_eq!(info.num_stages, 3);
    }

    #[test]
    fn test_database_info_new() {
        let info = DatabaseInfo::new("http://localhost", "testdb");
        assert_eq!(info.server_url, "http://localhost");
        assert_eq!(info.database_name, "testdb");
        assert_eq!(info.total_functions, 0);
    }

    #[test]
    fn test_sf_overview_info() {
        let overview = SFOverviewInfo::new();
        assert_eq!(overview.executable_count(), 0);
        assert_eq!(overview.total_functions, 0);
    }

    #[test]
    fn test_sf_query_result_new() {
        let func = BSimFunctionDescription::new("exe1", "test_func", 0x1000);
        let info = SFQueryInfo::new(func);
        let result = SFQueryResult::new(info);
        assert_eq!(result.result_count(), 0);
        assert!(result.top_result().is_none());
    }

    #[test]
    fn test_similarity_result_new() {
        let func = BSimFunctionDescription::new("exe1", "matched", 0x2000);
        let result = SimilarityResult::new(func, 0.95, "exe1");
        assert!((result.similarity - 0.95).abs() < f64::EPSILON);
        assert_eq!(result.executable_name, "exe1");
    }

    #[test]
    fn test_function_symbol_iterator() {
        let funcs = vec![
            BSimFunctionDescription::new("exe1", "a", 0x1000),
            BSimFunctionDescription::new("exe1", "b", 0x2000),
            BSimFunctionDescription::new("exe1", "c", 0x3000),
        ];
        let mut iter = FunctionSymbolIterator::new(funcs);
        assert_eq!(iter.total(), 3);
        assert!(iter.next().is_some());
        assert!(iter.next().is_some());
        assert!(iter.next().is_some());
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_query_database_exception() {
        let e = QueryDatabaseException::new("connection failed");
        assert!(format!("{}", e).contains("connection failed"));

        let e2 = QueryDatabaseException::with_cause("query failed", "timeout");
        assert!(format!("{}", e2).contains("timeout"));
    }

    #[test]
    fn test_query_database_exception_from_bsim_error() {
        let bsim_err = super::super::BSimError::ConnectionError("refused".into());
        let exc: QueryDatabaseException = bsim_err.into();
        assert!(format!("{}", exc).contains("refused"));
    }

    #[test]
    fn test_similarity_result_with_callgraph() {
        let func = BSimFunctionDescription::new("exe1", "matched", 0x2000);
        let mut result = SimilarityResult::new(func, 0.9, "exe1");
        result.callgraph_match = Some(CallgraphMatchInfo {
            matched_children: 5,
            total_children: 8,
            score: 0.625,
        });
        assert!(result.callgraph_match.is_some());
        let cg = result.callgraph_match.as_ref().unwrap();
        assert_eq!(cg.matched_children, 5);
    }
}
