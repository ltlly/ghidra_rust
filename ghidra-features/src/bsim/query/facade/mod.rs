//! High-level facade for BSim operations.
//!
//! Port of `ghidra.features.bsim.query.facade`:
//! - [`DatabaseInfo`]: database metadata wrapper
//! - [`SFQueryInfo`]: query request container
//! - [`SFQueryResult`]: query result container
//! - [`SFOverviewInfo`]: overview query info
//! - [`SimilarFunctionQueryService`]: main service for querying similar functions
//! - [`SFQueryServiceFactory`]: factory trait for creating query services
//! - [`SFResultsUpdateListener`]: listener for result updates
//! - [`QueryDatabaseException`]: database query exception
//! - [`FunctionSymbolIterator`]: iterator over function symbols

use serde::{Deserialize, Serialize};

use super::super::client::{BSimError, BSimResult, ConnectionType, FunctionDatabase};
use super::super::description::{
    DatabaseInformation, DescriptionManager, ExecutableRecord, FunctionDescription,
};
use super::super::protocol::{SimilarityResult, StagingManager};

// ============================================================================
// DatabaseInfo
// ============================================================================

/// Wrapper around database metadata for display purposes.
///
/// Provides convenient access to database name, owner, version,
/// description, and read-only status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseInfo {
    /// Server URL.
    pub server_url: String,
    /// Database metadata.
    pub database_information: DatabaseInformation,
}

impl DatabaseInfo {
    /// Create a new database info.
    pub fn new(server_url: impl Into<String>, info: DatabaseInformation) -> Self {
        Self {
            server_url: server_url.into(),
            database_information: info,
        }
    }

    /// Get the server URL.
    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    /// Get the database name.
    pub fn name(&self) -> &str {
        &self.database_information.database_name
    }

    /// Get the database owner.
    pub fn owner(&self) -> &str {
        &self.database_information.owner
    }

    /// Get the database description.
    pub fn description(&self) -> &str {
        &self.database_information.description
    }

    /// Get the version string (major.minor).
    pub fn version(&self) -> String {
        format!(
            "{}.{}",
            self.database_information.major, self.database_information.minor
        )
    }

    /// Whether the database is read-only.
    pub fn is_read_only(&self) -> bool {
        self.database_information.readonly
    }
}

impl std::fmt::Display for DatabaseInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Database: {}\n\tName: {}\n\tOwner: {}\n\tVersion: {}\n\tDescription: {}",
            self.server_url,
            self.name(),
            self.owner(),
            self.version(),
            self.description()
        )
    }
}

// ============================================================================
// QueryDatabaseException
// ============================================================================

/// Exception for BSim database query operations.
#[derive(Debug, Clone)]
pub struct QueryDatabaseException {
    /// Error message.
    pub message: String,
}

impl QueryDatabaseException {
    /// Create a new query database exception.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for QueryDatabaseException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Query database error: {}", self.message)
    }
}

impl std::error::Error for QueryDatabaseException {}

impl From<BSimError> for QueryDatabaseException {
    fn from(e: BSimError) -> Self {
        Self::new(format!("{}", e))
    }
}

// ============================================================================
// FunctionSymbolIterator
// ============================================================================

/// Iterator over function descriptions (representing function symbols).
///
/// Bridges the gap between function symbol collections and the
/// description-based iteration expected by BSim signature generators.
#[derive(Debug, Clone)]
pub struct FunctionSymbolIterator {
    /// The underlying function descriptions.
    functions: Vec<FunctionDescription>,
    /// Current position in the iteration.
    position: usize,
}

impl FunctionSymbolIterator {
    /// Create a new iterator from a vector of function descriptions.
    pub fn new(functions: Vec<FunctionDescription>) -> Self {
        Self {
            functions,
            position: 0,
        }
    }

    /// Get the number of functions.
    pub fn len(&self) -> usize {
        self.functions.len()
    }

    /// Whether the iterator is empty.
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }
}

impl Iterator for FunctionSymbolIterator {
    type Item = FunctionDescription;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position < self.functions.len() {
            let item = self.functions[self.position].clone();
            self.position += 1;
            Some(item)
        } else {
            None
        }
    }
}

// ============================================================================
// SFResultsUpdateListener
// ============================================================================

/// Listener trait for receiving updates when BSim query results change.
pub trait SFResultsUpdateListener: Send + Sync {
    /// Called when results have been updated.
    fn on_results_updated(&self, count: usize);

    /// Called when an error occurs during query processing.
    fn on_error(&self, error: &str);
}

/// No-op listener that discards all events.
#[derive(Debug, Clone, Default)]
pub struct NullResultsListener;

impl SFResultsUpdateListener for NullResultsListener {
    fn on_results_updated(&self, _count: usize) {}
    fn on_error(&self, _error: &str) {}
}

// ============================================================================
// SFQueryInfo
// ============================================================================

/// Container for BSim query request parameters.
///
/// Holds the set of function names to search for, along with
/// configurable thresholds and filter settings.
#[derive(Debug, Clone)]
pub struct SFQueryInfo {
    /// Function names to query.
    pub function_names: Vec<String>,
    /// Program name the functions belong to.
    pub program_name: String,
    /// Similarity threshold (0.0 - 1.0).
    pub similarity_threshold: f64,
    /// Significance threshold.
    pub significance_threshold: f64,
    /// Maximum results per function.
    pub max_results_per_function: usize,
    /// Number of query stages (for batched queries).
    pub num_stages: usize,
    /// BSim filter expressions.
    pub filters: Vec<String>,
}

impl SFQueryInfo {
    /// Create a new query info with the given function names.
    pub fn new(function_names: Vec<String>, program_name: impl Into<String>) -> Self {
        if function_names.is_empty() {
            panic!("Function list cannot be empty");
        }
        Self {
            function_names,
            program_name: program_name.into(),
            similarity_threshold: 0.7,
            significance_threshold: 4.0,
            max_results_per_function: 20,
            num_stages: 1,
            filters: Vec::new(),
        }
    }

    /// Get the program name.
    pub fn program_name(&self) -> &str {
        &self.program_name
    }

    /// Get the function names.
    pub fn function_names(&self) -> &[String] {
        &self.function_names
    }

    /// Set the similarity threshold.
    pub fn with_similarity_threshold(mut self, threshold: f64) -> Self {
        self.similarity_threshold = threshold;
        self
    }

    /// Set the significance threshold.
    pub fn with_significance_threshold(mut self, threshold: f64) -> Self {
        self.significance_threshold = threshold;
        self
    }

    /// Set the maximum results per function.
    pub fn with_max_results(mut self, max: usize) -> Self {
        self.max_results_per_function = max;
        self
    }

    /// Set the number of query stages.
    pub fn with_stages(mut self, stages: usize) -> Self {
        self.num_stages = stages;
        self
    }

    /// Add a BSim filter.
    pub fn add_filter(&mut self, filter: impl Into<String>) {
        self.filters.push(filter.into());
    }

    /// Default number of queries per stage.
    pub const DEFAULT_QUERIES_PER_STAGE: usize = 10;
}

// ============================================================================
// SFOverviewInfo
// ============================================================================

/// Container for BSim overview query parameters.
///
/// Used when querying the database for an overview of all function
/// similarities, rather than searching for specific functions.
#[derive(Debug, Clone)]
pub struct SFOverviewInfo {
    /// Function names to include in the overview.
    pub function_names: Vec<String>,
    /// Program name.
    pub program_name: String,
    /// Similarity threshold.
    pub similarity_threshold: f64,
    /// Whether to include callgraph information.
    pub include_callgraph: bool,
    /// Maximum total results.
    pub max_results: usize,
}

impl SFOverviewInfo {
    /// Create a new overview info.
    pub fn new(function_names: Vec<String>, program_name: impl Into<String>) -> Self {
        Self {
            function_names,
            program_name: program_name.into(),
            similarity_threshold: 0.7,
            include_callgraph: false,
            max_results: 500,
        }
    }

    /// Set similarity threshold.
    pub fn with_similarity_threshold(mut self, threshold: f64) -> Self {
        self.similarity_threshold = threshold;
        self
    }

    /// Enable callgraph inclusion.
    pub fn with_callgraph(mut self, include: bool) -> Self {
        self.include_callgraph = include;
        self
    }
}

// ============================================================================
// SFQueryResult
// ============================================================================

/// Result of a BSim similarity query.
///
/// Contains the original query info, the list of similarity results,
/// and database metadata.
#[derive(Debug, Clone)]
pub struct SFQueryResult {
    /// The original query info.
    pub query_info: SFQueryInfo,
    /// Similarity results.
    pub results: Vec<SimilarityResult>,
    /// Database info at the time of query.
    pub database_info: Option<DatabaseInfo>,
}

impl SFQueryResult {
    /// Create a new query result.
    pub fn new(
        query_info: SFQueryInfo,
        results: Vec<SimilarityResult>,
        database_info: Option<DatabaseInfo>,
    ) -> Self {
        Self {
            query_info,
            results,
            database_info,
        }
    }

    /// Get the similarity results.
    pub fn similarity_results(&self) -> &[SimilarityResult] {
        &self.results
    }

    /// Get the database info.
    pub fn database_info(&self) -> Option<&DatabaseInfo> {
        self.database_info.as_ref()
    }

    /// Total number of matched functions across all results.
    pub fn total_match_count(&self) -> usize {
        self.results.iter().map(|r| r.notes.len()).sum()
    }

    /// Get the original query.
    pub fn query(&self) -> &SFQueryInfo {
        &self.query_info
    }
}

/// Simplified BSim query result (from the basic facade).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimQueryResult {
    /// The matched function.
    pub function: FunctionDescription,
    /// Similarity score (0.0 - 1.0).
    pub similarity: f64,
    /// Significance score.
    pub significance: f64,
    /// The executable containing the matched function.
    pub executable: Option<ExecutableRecord>,
}

// ============================================================================
// SFQueryServiceFactory
// ============================================================================

/// Factory trait for creating `SimilarFunctionQueryService` instances.
pub trait SFQueryServiceFactory: Send + Sync {
    /// Create a new query service for the given program name.
    fn create_service(&self, program_name: &str) -> BSimResult<Box<dyn FunctionDatabase>>;
}

/// Default factory that creates in-memory databases.
#[derive(Debug, Clone, Default)]
pub struct DefaultSFQueryServiceFactory {
    /// Connection type to create.
    pub connection_type: ConnectionType,
    /// Server URL (for network-backed databases).
    pub server_url: Option<String>,
}

impl DefaultSFQueryServiceFactory {
    /// Create a new default factory.
    pub fn new(connection_type: ConnectionType) -> Self {
        Self {
            connection_type,
            server_url: None,
        }
    }

    /// Set the server URL.
    pub fn with_server_url(mut self, url: impl Into<String>) -> Self {
        self.server_url = Some(url.into());
        self
    }
}

impl SFQueryServiceFactory for DefaultSFQueryServiceFactory {
    fn create_service(&self, _program_name: &str) -> BSimResult<Box<dyn FunctionDatabase>> {
        // In a full implementation, this would create the appropriate database
        // backend based on connection_type. For now, return an error.
        Err(BSimError::NoDatabase(
            "Factory not fully implemented".to_string(),
        ))
    }
}

// ============================================================================
// SimilarFunctionQueryService
// ============================================================================

/// Main service for querying a BSim database for similar functions.
///
/// Wraps a `FunctionDatabase` connection and provides high-level
/// operations like generating queries, executing searches, and
/// applying results.
pub struct SimilarFunctionQueryService {
    /// The underlying database connection.
    database: Option<Box<dyn FunctionDatabase>>,
    /// Program name.
    program_name: String,
    /// Staging manager for batched operations.
    staging: StagingManager,
    /// Number of query stages.
    num_stages: usize,
}

impl SimilarFunctionQueryService {
    /// Create a new query service.
    pub fn new(program_name: impl Into<String>) -> Self {
        Self {
            database: None,
            program_name: program_name.into(),
            staging: StagingManager::default(),
            num_stages: 0,
        }
    }

    /// Set the database connection.
    pub fn set_database(&mut self, db: Box<dyn FunctionDatabase>) {
        self.database = Some(db);
    }

    /// Get the program name.
    pub fn program_name(&self) -> &str {
        &self.program_name
    }

    /// Get the number of stages.
    pub fn num_stages(&self) -> usize {
        self.num_stages
    }

    /// Set the number of stages.
    pub fn set_num_stages(&mut self, stages: usize) {
        self.num_stages = stages;
    }

    /// Whether the service has an active database connection.
    pub fn is_connected(&self) -> bool {
        self.database.is_some()
    }

    /// Get the database info (if connected).
    pub fn database_info(&self) -> Option<&dyn FunctionDatabase> {
        self.database.as_deref()
    }

    /// Change the password on the server.
    pub fn change_password(&mut self, _username: &str, _new_password: &str) -> Option<String> {
        if self.database.is_none() {
            return Some("Connection not established".to_string());
        }
        // In a full implementation, this would send a PasswordChange request.
        None
    }
}

// ============================================================================
// BSimFacade (high-level facade)
// ============================================================================

/// High-level facade for BSim operations.
///
/// Wraps the lower-level query infrastructure with a simplified API
/// for common operations like "find similar functions" or
/// "query by signature."
pub struct BSimFacade {
    /// Database connection URL.
    url: String,
    /// Similarity threshold for queries.
    pub similarity_threshold: f64,
    /// Maximum results to return.
    pub max_results: usize,
}

impl BSimFacade {
    /// Create a new BSim facade.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            similarity_threshold: 0.7,
            max_results: 100,
        }
    }

    /// Get the connection URL.
    pub fn url(&self) -> &str {
        &self.url
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_facade() {
        let facade = BSimFacade::new("jdbc:postgresql://localhost/bsim");
        assert_eq!(facade.url(), "jdbc:postgresql://localhost/bsim");
        assert_eq!(facade.similarity_threshold, 0.7);
        assert_eq!(facade.max_results, 100);
    }

    #[test]
    fn test_query_result() {
        let func = FunctionDescription::new(0, "test_func", Some(0x1000));
        let result = BSimQueryResult {
            function: func,
            similarity: 0.95,
            significance: 0.99,
            executable: None,
        };
        assert!(result.similarity > 0.9);
    }

    #[test]
    fn database_info_display() {
        let info = DatabaseInformation {
            database_name: "testdb".to_string(),
            owner: "admin".to_string(),
            description: "Test database".to_string(),
            major: 1,
            minor: 0,
            readonly: false,
            ..Default::default()
        };
        let db_info = DatabaseInfo::new("localhost:5432", info);
        assert_eq!(db_info.name(), "testdb");
        assert_eq!(db_info.owner(), "admin");
        assert_eq!(db_info.version(), "1.0");
        assert!(!db_info.is_read_only());
        let display = format!("{}", db_info);
        assert!(display.contains("testdb"));
    }

    #[test]
    fn query_database_exception() {
        let e = QueryDatabaseException::new("connection failed");
        assert!(format!("{}", e).contains("connection failed"));
    }

    #[test]
    fn query_database_exception_from_bsim_error() {
        let bsim_err = BSimError::NoDatabase("test".to_string());
        let e: QueryDatabaseException = bsim_err.into();
        assert!(format!("{}", e).contains("test"));
    }

    #[test]
    fn function_symbol_iterator() {
        let funcs = vec![
            FunctionDescription::new(0, "main", Some(0x1000)),
            FunctionDescription::new(0, "foo", Some(0x2000)),
            FunctionDescription::new(0, "bar", Some(0x3000)),
        ];
        let mut iter = FunctionSymbolIterator::new(funcs);
        assert_eq!(iter.len(), 3);
        assert!(!iter.is_empty());

        let first = iter.next().unwrap();
        assert_eq!(first.function_name, "main");

        let second = iter.next().unwrap();
        assert_eq!(second.function_name, "foo");

        let third = iter.next().unwrap();
        assert_eq!(third.function_name, "bar");

        assert!(iter.next().is_none());
    }

    #[test]
    fn function_symbol_iterator_empty() {
        let iter = FunctionSymbolIterator::new(vec![]);
        assert!(iter.is_empty());
        assert_eq!(iter.len(), 0);
    }

    #[test]
    fn sf_query_info_creation() {
        let info = SFQueryInfo::new(
            vec!["main".to_string(), "foo".to_string()],
            "test_program",
        )
        .with_similarity_threshold(0.8)
        .with_significance_threshold(5.0)
        .with_max_results(50)
        .with_stages(3);

        assert_eq!(info.function_names().len(), 2);
        assert_eq!(info.program_name(), "test_program");
        assert!((info.similarity_threshold - 0.8).abs() < 1e-9);
        assert!((info.significance_threshold - 5.0).abs() < 1e-9);
        assert_eq!(info.max_results_per_function, 50);
        assert_eq!(info.num_stages, 3);
    }

    #[test]
    fn sf_query_info_with_filters() {
        let mut info = SFQueryInfo::new(vec!["main".to_string()], "prog");
        info.add_filter("architecture:x86");
        info.add_filter("compiler:gcc");
        assert_eq!(info.filters.len(), 2);
    }

    #[test]
    fn sf_overview_info_creation() {
        let info = SFOverviewInfo::new(
            vec!["main".to_string()],
            "prog",
        )
        .with_similarity_threshold(0.9)
        .with_callgraph(true);

        assert_eq!(info.function_names.len(), 1);
        assert!((info.similarity_threshold - 0.9).abs() < 1e-9);
        assert!(info.include_callgraph);
    }

    #[test]
    fn sf_query_result_methods() {
        let query_info = SFQueryInfo::new(vec!["main".to_string()], "prog");
        let results = vec![];
        let qr = SFQueryResult::new(query_info, results, None);
        assert_eq!(qr.total_match_count(), 0);
        assert!(qr.database_info().is_none());
    }

    #[test]
    fn default_sf_query_service_factory() {
        let factory = DefaultSFQueryServiceFactory::new(ConnectionType::InMemory)
            .with_server_url("localhost:5432");
        assert!(factory.server_url.is_some());
    }

    #[test]
    fn similar_function_query_service() {
        let mut svc = SimilarFunctionQueryService::new("test_program");
        assert_eq!(svc.program_name(), "test_program");
        assert!(!svc.is_connected());
        assert_eq!(svc.num_stages(), 0);

        svc.set_num_stages(5);
        assert_eq!(svc.num_stages(), 5);

        let result = svc.change_password("user", "pass");
        assert!(result.is_some()); // Error because not connected.
    }

    #[test]
    fn null_results_listener() {
        let listener = NullResultsListener;
        listener.on_results_updated(10);
        listener.on_error("test error");
    }

    #[test]
    fn sf_query_info_default_stages() {
        assert_eq!(SFQueryInfo::DEFAULT_QUERIES_PER_STAGE, 10);
    }
}
