//! BSim facade types -- Rust port of Ghidra's `ghidra.features.bsim.query.facade` package.
//!
//! This module provides the high-level service interface for BSim operations:
//! - [`SimilarFunctionQueryService`] -- main user-facing service for querying BSim
//! - [`SFQueryResult`] -- result of a BSim query operation
//! - [`SFQueryInfo`] -- information about a BSim query
//! - [`SFOverviewInfo`] -- overview information for a BSim database
//! - [`DatabaseInfo`] -- database connection information
//! - [`FunctionSymbolIterator`] -- iterates over function symbols from query results

use serde::{Deserialize, Serialize};

use super::client::{BSimError, BSimResult, Configuration, ConnectionType, FunctionDatabase};
use super::description::{DatabaseInformation, ExecutableRecord, FunctionDescription};
use super::protocol::{
    BSimQueryType, BSimResponseType, FunctionEntry, QueryNearest, SimilarityResult,
};

// ============================================================================
// DatabaseInfo
// ============================================================================

/// Connection information for a BSim database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseInfo {
    /// The URL or path to the database.
    pub url: String,
    /// The connection type.
    pub connection_type: ConnectionType,
    /// Optional username for authentication.
    pub username: Option<String>,
    /// Optional password for authentication.
    pub password: Option<String>,
    /// Database name.
    pub database_name: Option<String>,
}

impl DatabaseInfo {
    /// Create a new database info.
    pub fn new(url: impl Into<String>, connection_type: ConnectionType) -> Self {
        Self {
            url: url.into(),
            connection_type,
            username: None,
            password: None,
            database_name: None,
        }
    }

    /// Set the username.
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Set the password.
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Set the database name.
    pub fn with_database_name(mut self, name: impl Into<String>) -> Self {
        self.database_name = Some(name.into());
        self
    }
}

// ============================================================================
// SFQueryInfo
// ============================================================================

/// Information about a BSim query operation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SFQueryInfo {
    /// The number of functions queried.
    pub function_count: usize,
    /// The number of matches found.
    pub match_count: usize,
    /// The query duration in milliseconds.
    pub duration_ms: u64,
    /// Any warnings or messages from the query.
    pub messages: Vec<String>,
    /// Whether the query was successful.
    pub success: bool,
}

impl SFQueryInfo {
    /// Create new query info.
    pub fn new() -> Self {
        Self::default()
    }
}

// ============================================================================
// SFOverviewInfo
// ============================================================================

/// Overview information about a BSim database.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SFOverviewInfo {
    /// Database information/metadata.
    pub database_info: Option<DatabaseInformation>,
    /// Number of executables in the database.
    pub executable_count: usize,
    /// Number of functions in the database.
    pub function_count: usize,
    /// Number of distinct signatures.
    pub signature_count: usize,
    /// List of executable names.
    pub executable_names: Vec<String>,
}

impl SFOverviewInfo {
    /// Create new overview info.
    pub fn new() -> Self {
        Self::default()
    }
}

// ============================================================================
// SFQueryResult
// ============================================================================

/// Result of a BSim query operation.
///
/// Contains the similarity results for each queried function, plus
/// metadata about the query.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SFQueryResult {
    /// Similarity results grouped by queried function.
    pub results: Vec<SimilarityResult>,
    /// Query metadata.
    pub info: SFQueryInfo,
    /// Executable records referenced by the results.
    pub executables: Vec<ExecutableRecord>,
}

impl SFQueryResult {
    /// Create a new empty query result.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a similarity result.
    pub fn add_result(&mut self, result: SimilarityResult) {
        self.results.push(result);
    }

    /// Get the total number of matches across all results.
    pub fn total_matches(&self) -> usize {
        self.results.iter().map(|r| r.note_count()).sum()
    }

    /// Get the number of queried functions that had at least one match.
    pub fn functions_with_matches(&self) -> usize {
        self.results.iter().filter(|r| r.note_count() > 0).count()
    }

    /// Whether the query was successful.
    pub fn is_success(&self) -> bool {
        self.info.success
    }
}

// ============================================================================
// SFResultsUpdateListener
// ============================================================================

/// Trait for receiving updates during a BSim query operation.
///
/// Implementations can track progress and provide UI feedback.
pub trait SFResultsUpdateListener: Send + Sync {
    /// Called when the query starts.
    fn on_query_start(&self, _function_count: usize) {}

    /// Called when a function result is available.
    fn on_function_result(&self, _index: usize, _result: &SimilarityResult) {}

    /// Called when the query completes.
    fn on_query_complete(&self, _result: &SFQueryResult) {}

    /// Called when an error occurs.
    fn on_error(&self, _error: &BSimError) {}

    /// Check if the operation should be cancelled.
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// A no-op listener that does nothing.
#[derive(Debug, Clone, Default)]
pub struct NullSFResultsListener;

impl SFResultsUpdateListener for NullSFResultsListener {}

// ============================================================================
// FunctionSymbolIterator
// ============================================================================

/// Iterates over function symbols from BSim query results.
///
/// Maps BSim FunctionDescription entries to a uniform interface
/// for consumption by other Ghidra components.
#[derive(Debug)]
pub struct FunctionSymbolIterator {
    /// The functions to iterate over.
    functions: Vec<FunctionDescription>,
    /// Current position.
    position: usize,
}

impl FunctionSymbolIterator {
    /// Create a new iterator over the given functions.
    pub fn new(functions: Vec<FunctionDescription>) -> Self {
        Self {
            functions,
            position: 0,
        }
    }

    /// Get the total number of functions.
    pub fn len(&self) -> usize {
        self.functions.len()
    }

    /// Whether the iterator is empty.
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }

    /// Reset the iterator to the beginning.
    pub fn reset(&mut self) {
        self.position = 0;
    }

    /// Get the current function (without advancing).
    pub fn peek(&self) -> Option<&FunctionDescription> {
        self.functions.get(self.position)
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

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.functions.len() - self.position;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for FunctionSymbolIterator {}

// ============================================================================
// SimilarFunctionQueryService
// ============================================================================

/// High-level service for querying a BSim database for similar functions.
///
/// This is the main user-facing entry point for BSim queries. It handles:
/// - Generating function signatures
/// - Building and executing BSim queries
/// - Processing and presenting results
///
/// # Usage
///
/// ```ignore
/// let service = SimilarFunctionQueryService::new();
/// service.connect(&database_info)?;
/// let result = service.query_by_functions(&function_entries)?;
/// ```
pub struct SimilarFunctionQueryService {
    /// The active database connection (if any).
    database: Option<Box<dyn FunctionDatabase>>,
    /// Service configuration.
    config: Configuration,
    /// Number of staging stages (0 = auto-detect from database).
    num_stages: u32,
}

impl SimilarFunctionQueryService {
    /// Create a new service (not connected).
    pub fn new() -> Self {
        Self {
            database: None,
            config: Configuration::default(),
            num_stages: 0,
        }
    }

    /// Create a service with a pre-configured database.
    pub fn with_database(database: Box<dyn FunctionDatabase>) -> Self {
        Self {
            database: Some(database),
            config: Configuration::default(),
            num_stages: 0,
        }
    }

    /// Set the service configuration.
    pub fn set_config(&mut self, config: Configuration) {
        self.config = config;
    }

    /// Get the current configuration.
    pub fn config(&self) -> &Configuration {
        &self.config
    }

    /// Whether the service is connected to a database.
    pub fn is_connected(&self) -> bool {
        self.database.as_ref().map_or(false, |db| db.is_connected())
    }

    /// Connect to a BSim database.
    pub fn connect(&mut self, info: &DatabaseInfo) -> BSimResult<()> {
        // In a full implementation, this would create the appropriate
        // FunctionDatabase implementation based on connection_type.
        Err(BSimError::NoDatabase(format!(
            "Connection to {} not yet implemented",
            info.url
        )))
    }

    /// Disconnect from the database.
    pub fn disconnect(&mut self) -> BSimResult<()> {
        if let Some(ref mut db) = self.database {
            db.close()?;
        }
        self.database = None;
        Ok(())
    }

    /// Get overview information about the connected database.
    pub fn query_overviews(&mut self) -> BSimResult<SFOverviewInfo> {
        let db = self
            .database
            .as_mut()
            .ok_or_else(|| BSimError::NoDatabase("not connected".into()))?;

        let mut overview = SFOverviewInfo::new();
        overview.database_info = db.database_info()?;
        overview.executable_count = db.executable_count()? as usize;
        Ok(overview)
    }

    /// Query by function entries.
    ///
    /// Builds a QueryNearest from the given function entries and executes it.
    pub fn query_by_functions(
        &mut self,
        functions: &[FunctionEntry],
        md5: &str,
    ) -> BSimResult<SFQueryResult> {
        let db = self
            .database
            .as_mut()
            .ok_or_else(|| BSimError::NoDatabase("not connected".into()))?;

        let mut query = QueryNearest::new();
        query.base.similarity_threshold = self.config.similarity_threshold;
        query.base.significance_threshold = self.config.significance_threshold;
        query.base.max_results = self.config.max_results;
        query.query_md5 = md5.to_string();
        query.query_functions = functions.to_vec();

        let mut query_type = BSimQueryType::QueryNearest(query);
        let response = db.query(&mut query_type)?;

        match response {
            BSimResponseType::ResponseNearest(resp) => {
                let mut result = SFQueryResult::new();
                result.info.success = resp.base.success;
                result.results = resp.results;
                Ok(result)
            }
            BSimResponseType::ResponseError(err) => {
                Err(BSimError::QueryError(err.error_message))
            }
            _ => Err(BSimError::QueryError(
                "unexpected response type".to_string(),
            )),
        }
    }

    /// Get the number of staging stages.
    pub fn num_stages(&self) -> u32 {
        self.num_stages
    }

    /// Set the number of staging stages.
    pub fn set_num_stages(&mut self, stages: u32) {
        self.num_stages = stages;
    }
}

impl Default for SimilarFunctionQueryService {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SimilarFunctionQueryService {
    fn drop(&mut self) {
        let _ = self.disconnect();
    }
}

// ============================================================================
// SFQueryServiceFactory
// ============================================================================

/// Trait for creating SimilarFunctionQueryService instances.
///
/// Allows dependency injection for testing.
pub trait SFQueryServiceFactory: Send + Sync {
    /// Create a new service instance.
    fn create_service(&self) -> SimilarFunctionQueryService;

    /// Create a service with a pre-configured database.
    fn create_service_with_database(
        &self,
        database: Box<dyn FunctionDatabase>,
    ) -> SimilarFunctionQueryService;
}

/// Default factory implementation.
#[derive(Debug, Clone, Default)]
pub struct DefaultSFQueryServiceFactory;

impl DefaultSFQueryServiceFactory {
    /// Create a new default factory.
    pub fn new() -> Self {
        Self
    }
}

impl SFQueryServiceFactory for DefaultSFQueryServiceFactory {
    fn create_service(&self) -> SimilarFunctionQueryService {
        SimilarFunctionQueryService::new()
    }

    fn create_service_with_database(
        &self,
        database: Box<dyn FunctionDatabase>,
    ) -> SimilarFunctionQueryService {
        SimilarFunctionQueryService::with_database(database)
    }
}

// ============================================================================
// QueryDatabaseException
// ============================================================================

/// Exception type for BSim query database operations.
///
/// This is the Rust equivalent of the Java `QueryDatabaseException`.
#[derive(Debug, Clone)]
pub struct QueryDatabaseException {
    /// The error message.
    pub message: String,
    /// The underlying error cause (if any).
    pub cause: Option<String>,
}

impl QueryDatabaseException {
    /// Create a new exception.
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

impl std::fmt::Display for QueryDatabaseException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BSim database error: {}", self.message)?;
        if let Some(ref cause) = self.cause {
            write!(f, " (caused by: {})", cause)?;
        }
        Ok(())
    }
}

impl std::error::Error for QueryDatabaseException {}

impl From<BSimError> for QueryDatabaseException {
    fn from(e: BSimError) -> Self {
        Self::new(format!("{}", e))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::client::{DatabaseStatus, TemporaryScoreCaching};

    #[test]
    fn database_info_creation() {
        let info = DatabaseInfo::new("localhost:5432/bsim", ConnectionType::Postgresql)
            .with_username("user")
            .with_password("pass")
            .with_database_name("mydb");

        assert_eq!(info.url, "localhost:5432/bsim");
        assert_eq!(info.connection_type, ConnectionType::Postgresql);
        assert_eq!(info.username.as_deref(), Some("user"));
        assert_eq!(info.database_name.as_deref(), Some("mydb"));
    }

    #[test]
    fn sf_query_info_default() {
        let info = SFQueryInfo::new();
        assert_eq!(info.function_count, 0);
        assert_eq!(info.match_count, 0);
        assert!(info.messages.is_empty());
    }

    #[test]
    fn sf_overview_info_default() {
        let info = SFOverviewInfo::new();
        assert_eq!(info.executable_count, 0);
        assert_eq!(info.function_count, 0);
    }

    #[test]
    fn sf_query_result_total_matches() {
        let mut result = SFQueryResult::new();

        let mut r1 = SimilarityResult::new(FunctionDescription::new(0, "fn1", Some(0x1000)));
        r1.add_note(FunctionDescription::new(0, "match1", Some(0x2000)), 0.9, 5.0);
        r1.add_note(FunctionDescription::new(0, "match2", Some(0x3000)), 0.8, 4.0);
        result.add_result(r1);

        let mut r2 = SimilarityResult::new(FunctionDescription::new(0, "fn2", Some(0x4000)));
        r2.add_note(FunctionDescription::new(0, "match3", Some(0x5000)), 0.95, 6.0);
        result.add_result(r2);

        assert_eq!(result.total_matches(), 3);
        assert_eq!(result.functions_with_matches(), 2);
    }

    #[test]
    fn function_symbol_iterator() {
        let funcs = vec![
            FunctionDescription::new(0, "a", Some(0x1000)),
            FunctionDescription::new(0, "b", Some(0x2000)),
            FunctionDescription::new(0, "c", Some(0x3000)),
        ];
        let mut iter = FunctionSymbolIterator::new(funcs);
        assert_eq!(iter.len(), 3);

        let first = iter.next().unwrap();
        assert_eq!(first.function_name, "a");

        let second = iter.next().unwrap();
        assert_eq!(second.function_name, "b");

        assert_eq!(iter.len(), 3); // len doesn't change with position.

        iter.reset();
        assert_eq!(iter.peek().unwrap().function_name, "a");
    }

    #[test]
    fn function_symbol_iterator_exact_size() {
        let funcs = vec![
            FunctionDescription::new(0, "a", Some(0x1000)),
            FunctionDescription::new(0, "b", Some(0x2000)),
        ];
        let iter = FunctionSymbolIterator::new(funcs);
        assert_eq!(iter.len(), 2);
    }

    #[test]
    fn similar_function_query_service_not_connected() {
        let service = SimilarFunctionQueryService::new();
        assert!(!service.is_connected());
    }

    #[test]
    fn query_database_exception_display() {
        let e = QueryDatabaseException::new("connection failed");
        assert!(format!("{}", e).contains("connection failed"));

        let e2 = QueryDatabaseException::with_cause("query failed", "timeout");
        assert!(format!("{}", e2).contains("timeout"));
    }

    #[test]
    fn query_database_exception_from_bsim_error() {
        let err = BSimError::Cancelled;
        let qde: QueryDatabaseException = err.into();
        assert!(format!("{}", qde).contains("cancelled"));
    }

    #[test]
    fn default_factory_creates_service() {
        let factory = DefaultSFQueryServiceFactory::new();
        let service = factory.create_service();
        assert!(!service.is_connected());
    }

    #[test]
    fn sf_query_result_success() {
        let mut result = SFQueryResult::new();
        assert!(!result.is_success());
        result.info.success = true;
        assert!(result.is_success());
    }

    #[test]
    fn null_listener_default() {
        let listener = NullSFResultsListener;
        assert!(!listener.is_cancelled());
    }
}
