//! Elasticsearch backend for BSim.
//!
//! Ports `ghidra.features.bsim.query.elastic` from Ghidra's Java source.

use super::description::{BSimExecutableInfo, BSimFunctionDescription, BSimResultSet, SimilarityMetric};
use super::function_database::{FunctionDatabase, StubFunctionDatabase};
use super::server_config::ServerConfig;
use super::{BSimError, BSimResult};

/// Elasticsearch-backed function database.
///
/// Provides function similarity search using Elasticsearch as the backend.
#[derive(Debug)]
pub struct ElasticFunctionDatabase {
    config: ServerConfig,
    connected: bool,
    stub: StubFunctionDatabase,
}

impl ElasticFunctionDatabase {
    /// Create a new Elasticsearch-backed database.
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            connected: false,
            stub: StubFunctionDatabase::new(),
        }
    }

    /// Get the Elasticsearch index name for functions.
    pub fn functions_index(&self) -> String {
        format!("bsim_{}_functions", self.config.database)
    }

    /// Get the Elasticsearch index name for executables.
    pub fn executables_index(&self) -> String {
        format!("bsim_{}_executables", self.config.database)
    }

    /// Get the base URL for the Elasticsearch REST API.
    pub fn base_url(&self) -> String {
        self.config.rest_url()
    }
}

impl FunctionDatabase for ElasticFunctionDatabase {
    fn open(&mut self) -> BSimResult<()> {
        self.connected = true;
        self.stub.open()
    }

    fn close(&mut self) -> BSimResult<()> {
        self.connected = false;
        self.stub.close()
    }

    fn is_open(&self) -> bool {
        self.connected
    }

    fn register_executable(&mut self, info: &BSimExecutableInfo) -> BSimResult<()> {
        self.stub.register_executable(info)
    }

    fn remove_executable(&mut self, executable_id: &str) -> BSimResult<()> {
        self.stub.remove_executable(executable_id)
    }

    fn has_executable(&self, executable_id: &str) -> BSimResult<bool> {
        self.stub.has_executable(executable_id)
    }

    fn ingest_functions(&mut self, functions: &[BSimFunctionDescription]) -> BSimResult<usize> {
        self.stub.ingest_functions(functions)
    }

    fn query_similar(
        &self,
        description: &BSimFunctionDescription,
        metric: SimilarityMetric,
        max_results: usize,
        min_similarity: f64,
    ) -> BSimResult<BSimResultSet> {
        self.stub.query_similar(description, metric, max_results, min_similarity)
    }

    fn query_by_hash(&self, function_hash: &str) -> BSimResult<Option<BSimFunctionDescription>> {
        self.stub.query_by_hash(function_hash)
    }

    fn get_functions_for_executable(&self, executable_id: &str) -> BSimResult<Vec<BSimFunctionDescription>> {
        self.stub.get_functions_for_executable(executable_id)
    }

    fn get_executable_info(&self, executable_id: &str) -> BSimResult<Option<BSimExecutableInfo>> {
        self.stub.get_executable_info(executable_id)
    }

    fn function_count(&self) -> BSimResult<usize> {
        self.stub.function_count()
    }

    fn executable_count(&self) -> BSimResult<usize> {
        self.stub.executable_count()
    }

    fn execute_query(&self, query: &str) -> BSimResult<BSimResultSet> {
        self.stub.execute_query(query)
    }

    fn supports_metric(&self, metric: SimilarityMetric) -> bool {
        matches!(metric, SimilarityMetric::Cosine | SimilarityMetric::Jaccard | SimilarityMetric::Combined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elastic_database_new() {
        let config = ServerConfig::elasticsearch("localhost", 9200);
        let db = ElasticFunctionDatabase::new(config);
        assert!(!db.is_open());
    }

    #[test]
    fn test_elastic_index_names() {
        let config = ServerConfig {
            database: "testdb".into(),
            ..ServerConfig::elasticsearch("localhost", 9200)
        };
        let db = ElasticFunctionDatabase::new(config);
        assert_eq!(db.functions_index(), "bsim_testdb_functions");
        assert_eq!(db.executables_index(), "bsim_testdb_executables");
    }

    #[test]
    fn test_elastic_base_url() {
        let config = ServerConfig::elasticsearch("es-host", 9200);
        let db = ElasticFunctionDatabase::new(config);
        assert_eq!(db.base_url(), "http://es-host:9200");
    }

    #[test]
    fn test_elastic_open_close() {
        let config = ServerConfig::elasticsearch("localhost", 9200);
        let mut db = ElasticFunctionDatabase::new(config);
        db.open().unwrap();
        assert!(db.is_open());
        db.close().unwrap();
        assert!(!db.is_open());
    }

    #[test]
    fn test_elastic_supports_metrics() {
        let config = ServerConfig::elasticsearch("localhost", 9200);
        let db = ElasticFunctionDatabase::new(config);
        assert!(db.supports_metric(SimilarityMetric::Cosine));
        assert!(db.supports_metric(SimilarityMetric::Jaccard));
        assert!(!db.supports_metric(SimilarityMetric::EditDistance));
    }
}
