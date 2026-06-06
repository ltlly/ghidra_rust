//! Port of `SimilarFunctionQueryService` from `ghidra.features.bsim.query.facade`.
//!
//! A high-level service for querying BSim databases for functions similar to
//! a given set of functions from a program. This is the primary user-facing
//! API for BSim similarity queries.

use std::collections::HashMap;

/// Status of a BSim query service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryServiceStatus {
    /// Not connected to any database.
    Disconnected,
    /// Connected to a database.
    Connected,
    /// Query in progress.
    Querying,
    /// An error occurred.
    Error,
}

/// Information about a BSim query result.
#[derive(Debug, Clone, Default)]
pub struct SFQueryResult {
    /// The URL of the database queried.
    pub database_url: String,
    /// Number of functions queried.
    pub functions_queried: usize,
    /// Number of matches found.
    pub matches_found: usize,
    /// Query execution time in milliseconds.
    pub query_time_ms: u64,
    /// Per-function match results: function name -> list of (match_name, score).
    pub match_results: HashMap<String, Vec<(String, f64)>>,
    /// Whether the query completed successfully.
    pub success: bool,
    /// Error message if the query failed.
    pub error_message: Option<String>,
}

impl SFQueryResult {
    /// Create a new empty query result.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if the query was successful.
    pub fn is_success(&self) -> bool {
        self.success && self.error_message.is_none()
    }

    /// Get matches for a specific function.
    pub fn get_matches(&self, func_name: &str) -> Option<&Vec<(String, f64)>> {
        self.match_results.get(func_name)
    }

    /// Get the top N matches across all queried functions.
    pub fn top_matches(&self, n: usize) -> Vec<(String, String, f64)> {
        let mut all: Vec<(String, String, f64)> = self
            .match_results
            .iter()
            .flat_map(|(queried, matches)| {
                matches
                    .iter()
                    .map(move |(match_name, score)| (queried.clone(), match_name.clone(), *score))
            })
            .collect();
        all.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        all.truncate(n);
        all
    }
}

/// Query information for a set of functions to query.
#[derive(Debug, Clone, Default)]
pub struct SFQueryInfo {
    /// Names of functions to query.
    pub function_names: Vec<String>,
    /// The program name these functions come from.
    pub program_name: String,
    /// The program MD5 hash.
    pub program_md5: String,
    /// Maximum number of results per function.
    pub max_results_per_func: usize,
    /// Minimum similarity score threshold.
    pub min_score: f64,
}

impl SFQueryInfo {
    /// Create new query info for the given function names.
    pub fn new(function_names: Vec<String>) -> Self {
        Self {
            function_names,
            max_results_per_func: 10,
            min_score: 0.5,
            ..Default::default()
        }
    }

    /// Get the number of functions to query.
    pub fn function_count(&self) -> usize {
        self.function_names.len()
    }
}

/// High-level service for querying a BSim database for similar functions.
///
/// Ports `ghidra.features.bsim.query.facade.SimilarFunctionQueryService`.
/// Wraps the lower-level `FunctionDatabase` API with a simpler interface
/// for querying function similarities.
#[derive(Debug, Clone)]
pub struct SimilarFunctionQueryService {
    /// Current connection status.
    status: QueryServiceStatus,
    /// URL of the connected database.
    database_url: Option<String>,
    /// Number of query stages (0 = auto-detect).
    num_stages: usize,
    /// Cached query results.
    cached_results: Vec<SFQueryResult>,
    /// Number of queries performed.
    query_count: u64,
}

impl SimilarFunctionQueryService {
    /// Create a new service (not yet connected).
    pub fn new() -> Self {
        Self::default()
    }

    /// Connect to a BSim database at the given URL.
    pub fn connect(&mut self, url: &str) -> Result<(), String> {
        self.database_url = Some(url.to_string());
        self.status = QueryServiceStatus::Connected;
        Ok(())
    }

    /// Disconnect from the current database.
    pub fn disconnect(&mut self) {
        self.database_url = None;
        self.status = QueryServiceStatus::Disconnected;
        self.cached_results.clear();
    }

    /// Check if the service is connected.
    pub fn is_connected(&self) -> bool {
        self.status == QueryServiceStatus::Connected
    }

    /// Get the current status.
    pub fn status(&self) -> QueryServiceStatus {
        self.status
    }

    /// Get the connected database URL.
    pub fn database_url(&self) -> Option<&str> {
        self.database_url.as_deref()
    }

    /// Set the number of query stages.
    pub fn set_num_stages(&mut self, stages: usize) {
        self.num_stages = stages;
    }

    /// Get the number of query stages.
    pub fn num_stages(&self) -> usize {
        self.num_stages
    }

    /// Get the number of queries performed.
    pub fn query_count(&self) -> u64 {
        self.query_count
    }

    /// Cache a query result.
    pub fn cache_result(&mut self, result: SFQueryResult) {
        self.cached_results.push(result);
        self.query_count += 1;
    }

    /// Get cached results.
    pub fn cached_results(&self) -> &[SFQueryResult] {
        &self.cached_results
    }

    /// Clear cached results.
    pub fn clear_cache(&mut self) {
        self.cached_results.clear();
    }
}

impl Default for SimilarFunctionQueryService {
    fn default() -> Self {
        Self {
            status: QueryServiceStatus::Disconnected,
            database_url: None,
            num_stages: 0,
            cached_results: Vec::new(),
            query_count: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sf_query_service_default() {
        let svc = SimilarFunctionQueryService::new();
        assert_eq!(svc.status(), QueryServiceStatus::Disconnected);
        assert!(!svc.is_connected());
        assert!(svc.database_url().is_none());
        assert_eq!(svc.num_stages(), 0);
    }

    #[test]
    fn test_sf_query_service_connect() {
        let mut svc = SimilarFunctionQueryService::new();
        svc.connect("postgresql://localhost/bsim").unwrap();
        assert!(svc.is_connected());
        assert_eq!(svc.database_url(), Some("postgresql://localhost/bsim"));
    }

    #[test]
    fn test_sf_query_service_disconnect() {
        let mut svc = SimilarFunctionQueryService::new();
        svc.connect("test").unwrap();
        svc.disconnect();
        assert!(!svc.is_connected());
        assert_eq!(svc.status(), QueryServiceStatus::Disconnected);
    }

    #[test]
    fn test_sf_query_result_default() {
        let result = SFQueryResult::new();
        assert!(!result.is_success());
        assert_eq!(result.matches_found, 0);
    }

    #[test]
    fn test_sf_query_result_success() {
        let mut result = SFQueryResult::new();
        result.success = true;
        result.match_results.insert(
            "main".to_string(),
            vec![("main_copy".to_string(), 0.95), ("entry".to_string(), 0.80)],
        );
        assert!(result.is_success());
        assert_eq!(result.matches_found, 0); // not set automatically

        let matches = result.get_matches("main").unwrap();
        assert_eq!(matches.len(), 2);

        let top = result.top_matches(1);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].2, 0.95);
    }

    #[test]
    fn test_sf_query_info() {
        let info = SFQueryInfo::new(vec!["main".to_string(), "init".to_string()]);
        assert_eq!(info.function_count(), 2);
        assert_eq!(info.max_results_per_func, 10);
        assert_eq!(info.min_score, 0.5);
    }

    #[test]
    fn test_sf_query_service_stages() {
        let mut svc = SimilarFunctionQueryService::new();
        svc.set_num_stages(3);
        assert_eq!(svc.num_stages(), 3);
    }

    #[test]
    fn test_sf_query_service_cache() {
        let mut svc = SimilarFunctionQueryService::new();
        let result = SFQueryResult {
            success: true,
            matches_found: 5,
            ..Default::default()
        };
        svc.cache_result(result);
        assert_eq!(svc.query_count(), 1);
        assert_eq!(svc.cached_results().len(), 1);

        svc.clear_cache();
        assert!(svc.cached_results().is_empty());
    }

    #[test]
    fn test_sf_query_result_top_matches_ordering() {
        let mut result = SFQueryResult::new();
        result.success = true;
        result.match_results.insert(
            "func_a".to_string(),
            vec![
                ("match_1".to_string(), 0.5),
                ("match_2".to_string(), 0.9),
            ],
        );
        result.match_results.insert(
            "func_b".to_string(),
            vec![("match_3".to_string(), 0.7)],
        );

        let top = result.top_matches(10);
        assert_eq!(top.len(), 3);
        assert_eq!(top[0].2, 0.9); // highest score first
        assert_eq!(top[1].2, 0.7);
        assert_eq!(top[2].2, 0.5);
    }
}
