//! BSim Query Service -- wraps a FunctionDatabase with query-level logic.
//!
//! Ports Ghidra's `ghidra.features.bsim.query.BSimQueryService`.  In the
//! Java version this sits between the high-level GUI / API layer and the
//! raw `FunctionDatabase` backend, adding query validation, result
//! formatting, error translation, and optional caching.
//!
//! The [`BSimService`](crate::bsim_service::BSimService) manages
//! *connections*; `BSimQueryService` operates on a *single open connection*
//! and provides the query-level API that callers actually use.

use crate::query::description::{
    BSimExecutableInfo, BSimFunctionDescription, BSimResultSet, SimilarityMetric,
};
use crate::query::function_database::FunctionDatabase;
use super::BSimResult;

/// Maximum number of results returned by a single query unless overridden.
const DEFAULT_MAX_RESULTS: usize = 100;

/// Default minimum similarity threshold.
const DEFAULT_MIN_SIMILARITY: f64 = 0.01;

/// Wraps a [`FunctionDatabase`] and adds query-level conveniences.
///
/// Responsible for:
/// - Validating query parameters before forwarding them to the backend.
/// - Translating low-level database errors into [`BSimError`](super::BSimError).
/// - Providing a builder-style query API.
/// - Optionally caching recent results (not yet implemented; placeholder).
pub struct BSimQueryService {
    /// The underlying database handle.
    database: Box<dyn FunctionDatabase>,
    /// Default maximum results for queries that do not specify one.
    default_max_results: usize,
    /// Default minimum similarity.
    default_min_similarity: f64,
}

impl BSimQueryService {
    /// Create a new query service wrapping the given database.
    ///
    /// The database should already be open; the service does **not** call
    /// `open()` automatically.
    pub fn new(database: Box<dyn FunctionDatabase>) -> Self {
        Self {
            database,
            default_max_results: DEFAULT_MAX_RESULTS,
            default_min_similarity: DEFAULT_MIN_SIMILARITY,
        }
    }

    /// Set the default maximum results.
    pub fn with_default_max_results(mut self, max: usize) -> Self {
        self.default_max_results = max;
        self
    }

    /// Set the default minimum similarity.
    pub fn with_default_min_similarity(mut self, threshold: f64) -> Self {
        self.default_min_similarity = threshold;
        self
    }

    // ------------------------------------------------------------------
    // Lifecycle delegation
    // ------------------------------------------------------------------

    /// Open the underlying database connection.
    pub fn open(&mut self) -> BSimResult<()> {
        self.database.open()
    }

    /// Close the underlying database connection.
    pub fn close(&mut self) -> BSimResult<()> {
        self.database.close()
    }

    /// Whether the underlying connection is open.
    pub fn is_open(&self) -> bool {
        self.database.is_open()
    }

    // ------------------------------------------------------------------
    // Query operations
    // ------------------------------------------------------------------

    /// Search for functions similar to the given description using default
    /// parameters.
    pub fn search(
        &self,
        description: &BSimFunctionDescription,
    ) -> BSimResult<BSimResultSet> {
        self.search_with(
            description,
            SimilarityMetric::Combined,
            self.default_max_results,
            self.default_min_similarity,
        )
    }

    /// Search for similar functions with explicit parameters.
    pub fn search_with(
        &self,
        description: &BSimFunctionDescription,
        metric: SimilarityMetric,
        max_results: usize,
        min_similarity: f64,
    ) -> BSimResult<BSimResultSet> {
        self.ensure_open()?;

        if description.function_name.is_empty() {
            return Err(super::BSimError::SchemaError(
                "Function name must not be empty".to_string(),
            ));
        }

        let effective_max = if max_results == 0 {
            self.default_max_results
        } else {
            max_results
        };

        self.database
            .query_similar(description, metric, effective_max, min_similarity)
    }

    /// Query for a specific function by its hash.
    pub fn lookup_by_hash(
        &self,
        function_hash: &str,
    ) -> BSimResult<Option<BSimFunctionDescription>> {
        self.ensure_open()?;
        if function_hash.is_empty() {
            return Err(super::BSimError::SchemaError(
                "Function hash must not be empty".to_string(),
            ));
        }
        self.database.query_by_hash(function_hash)
    }

    /// Get all functions belonging to an executable.
    pub fn functions_for_executable(
        &self,
        executable_id: &str,
    ) -> BSimResult<Vec<BSimFunctionDescription>> {
        self.ensure_open()?;
        self.database.get_functions_for_executable(executable_id)
    }

    /// Get information about a registered executable.
    pub fn executable_info(
        &self,
        executable_id: &str,
    ) -> BSimResult<Option<BSimExecutableInfo>> {
        self.ensure_open()?;
        self.database.get_executable_info(executable_id)
    }

    // ------------------------------------------------------------------
    // Ingest operations
    // ------------------------------------------------------------------

    /// Ingest function descriptions into the database.
    pub fn ingest(
        &mut self,
        functions: &[BSimFunctionDescription],
    ) -> BSimResult<usize> {
        self.ensure_open()?;
        if functions.is_empty() {
            return Ok(0);
        }
        self.database.ingest_functions(functions)
    }

    /// Register an executable in the database.
    pub fn register_executable(
        &mut self,
        info: &BSimExecutableInfo,
    ) -> BSimResult<()> {
        self.ensure_open()?;
        self.database.register_executable(info)
    }

    /// Remove an executable and all its functions.
    pub fn remove_executable(
        &mut self,
        executable_id: &str,
    ) -> BSimResult<()> {
        self.ensure_open()?;
        self.database.remove_executable(executable_id)
    }

    // ------------------------------------------------------------------
    // Statistics
    // ------------------------------------------------------------------

    /// Get the total number of functions in the database.
    pub fn function_count(&self) -> BSimResult<usize> {
        self.ensure_open()?;
        self.database.function_count()
    }

    /// Get the total number of executables in the database.
    pub fn executable_count(&self) -> BSimResult<usize> {
        self.ensure_open()?;
        self.database.executable_count()
    }

    /// Whether the backend supports a given similarity metric.
    pub fn supports_metric(&self, metric: SimilarityMetric) -> bool {
        self.database.supports_metric(metric)
    }

    // ------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------

    fn ensure_open(&self) -> BSimResult<()> {
        if !self.database.is_open() {
            return Err(super::BSimError::ConnectionError(
                "BSimQueryService: database is not open".to_string(),
            ));
        }
        Ok(())
    }
}

impl Drop for BSimQueryService {
    fn drop(&mut self) {
        let _ = self.database.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::function_database::StubFunctionDatabase;

    fn open_service() -> BSimQueryService {
        let mut svc = BSimQueryService::new(Box::new(StubFunctionDatabase::new()));
        svc.open().unwrap();
        svc
    }

    #[test]
    fn test_new_service() {
        let svc = BSimQueryService::new(Box::new(StubFunctionDatabase::new()));
        assert!(!svc.is_open());
    }

    #[test]
    fn test_open_close() {
        let mut svc = BSimQueryService::new(Box::new(StubFunctionDatabase::new()));
        svc.open().unwrap();
        assert!(svc.is_open());
        svc.close().unwrap();
        assert!(!svc.is_open());
    }

    #[test]
    fn test_builder_defaults() {
        let svc = BSimQueryService::new(Box::new(StubFunctionDatabase::new()))
            .with_default_max_results(50)
            .with_default_min_similarity(0.1);
        assert_eq!(svc.default_max_results, 50);
        assert!((svc.default_min_similarity - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn test_search_default() {
        let svc = open_service();
        let func = BSimFunctionDescription::new("exe1", "func1", 0x1000);
        let results = svc.search(&func).unwrap();
        assert_eq!(results.total_matches, 0);
    }

    #[test]
    fn test_search_with() {
        let svc = open_service();
        let func = BSimFunctionDescription::new("exe1", "func1", 0x1000);
        let results = svc
            .search_with(&func, SimilarityMetric::Cosine, 50, 0.5)
            .unwrap();
        assert_eq!(results.total_matches, 0);
    }

    #[test]
    fn test_search_empty_name_errors() {
        let svc = open_service();
        let func = BSimFunctionDescription::new("exe1", "", 0x1000);
        assert!(svc.search(&func).is_err());
    }

    #[test]
    fn test_search_closed_errors() {
        let svc = BSimQueryService::new(Box::new(StubFunctionDatabase::new()));
        let func = BSimFunctionDescription::new("exe1", "func1", 0x1000);
        assert!(svc.search(&func).is_err());
    }

    #[test]
    fn test_ingest_and_count() {
        let mut svc = open_service();
        let funcs = vec![
            BSimFunctionDescription::new("exe1", "f1", 0x1000),
            BSimFunctionDescription::new("exe1", "f2", 0x2000),
        ];
        let count = svc.ingest(&funcs).unwrap();
        assert_eq!(count, 2);
        assert_eq!(svc.function_count().unwrap(), 2);
    }

    #[test]
    fn test_ingest_empty() {
        let mut svc = open_service();
        let count = svc.ingest(&[]).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_register_and_remove_executable() {
        let mut svc = open_service();
        let info = BSimExecutableInfo::new("exe1", "test.exe");
        svc.register_executable(&info).unwrap();
        assert_eq!(svc.executable_count().unwrap(), 1);

        svc.remove_executable("exe1").unwrap();
        assert_eq!(svc.executable_count().unwrap(), 0);
    }

    #[test]
    fn test_executable_info() {
        let mut svc = open_service();
        let info = BSimExecutableInfo::new("exe1", "test.exe");
        svc.register_executable(&info).unwrap();

        let retrieved = svc.executable_info("exe1").unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().executable_id, "exe1");

        let missing = svc.executable_info("nope").unwrap();
        assert!(missing.is_none());
    }

    #[test]
    fn test_lookup_by_hash() {
        let mut svc = open_service();
        let func = BSimFunctionDescription::new("exe1", "f1", 0x1000)
            .with_hash("abc123");
        svc.ingest(&[func]).unwrap();

        let found = svc.lookup_by_hash("abc123").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().function_name, "f1");

        let missing = svc.lookup_by_hash("no_such_hash").unwrap();
        assert!(missing.is_none());
    }

    #[test]
    fn test_lookup_empty_hash_errors() {
        let svc = open_service();
        assert!(svc.lookup_by_hash("").is_err());
    }

    #[test]
    fn test_functions_for_executable() {
        let mut svc = open_service();
        let funcs = vec![
            BSimFunctionDescription::new("exe1", "f1", 0x1000),
            BSimFunctionDescription::new("exe2", "f2", 0x2000),
        ];
        svc.ingest(&funcs).unwrap();

        let exe1_funcs = svc.functions_for_executable("exe1").unwrap();
        assert_eq!(exe1_funcs.len(), 1);
        assert_eq!(exe1_funcs[0].function_name, "f1");
    }

    #[test]
    fn test_supports_metric() {
        let svc = open_service();
        assert!(svc.supports_metric(SimilarityMetric::Cosine));
    }

    #[test]
    fn test_drop_closes() {
        let mut svc = BSimQueryService::new(Box::new(StubFunctionDatabase::new()));
        svc.open().unwrap();
        assert!(svc.is_open());
        drop(svc);
        // If drop panicked the test harness would catch it.
    }
}
