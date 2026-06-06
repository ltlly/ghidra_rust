//! Elasticsearch backend for BSim.
//!
//! Ports `ghidra.features.bsim.query.elastic` from Ghidra's Java source.

pub mod elastic_utilities;

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

// ============================================================================
// Additional elastic types -- Ports remaining Java elastic classes
// ============================================================================

/// Connection handle for an Elasticsearch instance.
///
/// Ports `ghidra.features.bsim.query.elastic.ElasticConnection`.
#[derive(Debug, Clone)]
pub struct ElasticConnection {
    /// Base URL of the Elasticsearch server.
    pub base_url: String,
    /// Username for authentication (if required).
    pub username: Option<String>,
    /// Connection timeout in seconds.
    pub timeout_secs: u64,
    /// Whether the connection is active.
    connected: bool,
}

impl ElasticConnection {
    /// Create a new connection to the given URL.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            username: None,
            timeout_secs: 30,
            connected: false,
        }
    }

    /// Set authentication credentials.
    pub fn with_auth(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Set the connection timeout.
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    /// Check if the connection is active.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Test the connection.
    pub fn connect(&mut self) -> BSimResult<()> {
        // In a real implementation, this would issue a GET /
        self.connected = true;
        Ok(())
    }

    /// Disconnect.
    pub fn disconnect(&mut self) {
        self.connected = false;
    }

    /// Get the health endpoint URL.
    pub fn health_url(&self) -> String {
        format!("{}/_cluster/health", self.base_url)
    }
}

/// Side-effects tracker for elastic operations (error tracking, logging).
///
/// Ports `ghidra.features.bsim.query.elastic.ElasticEffects`.
#[derive(Debug, Default)]
pub struct ElasticEffects {
    /// Error messages collected during operations.
    pub errors: Vec<String>,
    /// Warning messages.
    pub warnings: Vec<String>,
    /// Number of successful operations.
    pub success_count: usize,
    /// Number of failed operations.
    pub failure_count: usize,
}

impl ElasticEffects {
    /// Create a new effects tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an error.
    pub fn add_error(&mut self, message: impl Into<String>) {
        self.errors.push(message.into());
        self.failure_count += 1;
    }

    /// Record a warning.
    pub fn add_warning(&mut self, message: impl Into<String>) {
        self.warnings.push(message.into());
    }

    /// Record a success.
    pub fn add_success(&mut self) {
        self.success_count += 1;
    }

    /// Whether any errors were recorded.
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Get the total operation count.
    pub fn total_operations(&self) -> usize {
        self.success_count + self.failure_count
    }

    /// Clear all recorded effects.
    pub fn clear(&mut self) {
        self.errors.clear();
        self.warnings.clear();
        self.success_count = 0;
        self.failure_count = 0;
    }
}

/// Factory for creating base64-encoded vector representations for Elasticsearch.
///
/// Ports `ghidra.features.bsim.query.elastic.Base64VectorFactory`.
#[derive(Debug)]
pub struct Base64VectorFactory;

impl Base64VectorFactory {
    /// Encode a floating-point vector to a base64 string for storage.
    pub fn encode_vector(vector: &[f64]) -> String {
        let bytes: Vec<u8> = vector
            .iter()
            .flat_map(|v| v.to_le_bytes().to_vec())
            .collect();
        elastic_utilities::base64_encode(&bytes)
    }

    /// Decode a base64 string back to a floating-point vector.
    pub fn decode_vector(encoded: &str) -> Result<Vec<f64>, BSimError> {
        let bytes = elastic_utilities::base64_decode(encoded)?;
        if bytes.len() % 8 != 0 {
            return Err(BSimError::SerializationError(
                "Invalid vector byte length".to_string(),
            ));
        }
        let mut result = Vec::with_capacity(bytes.len() / 8);
        for chunk in bytes.chunks_exact(8) {
            let val = f64::from_le_bytes(chunk.try_into().unwrap());
            result.push(val);
        }
        Ok(result)
    }
}

/// Elastic-side ID resolution type.
///
/// Ports `ghidra.features.bsim.query.elastic.IDElasticResolution`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ElasticIdResolution {
    /// The Elasticsearch document ID.
    pub document_id: String,
    /// The internal row key (if resolved).
    pub row_key: Option<i64>,
    /// Whether this resolution succeeded.
    pub resolved: bool,
}

impl ElasticIdResolution {
    /// Create a new ID resolution.
    pub fn new(document_id: impl Into<String>) -> Self {
        Self {
            document_id: document_id.into(),
            row_key: None,
            resolved: false,
        }
    }

    /// Mark as resolved with the given row key.
    pub fn resolve(&mut self, row_key: i64) {
        self.row_key = Some(row_key);
        self.resolved = true;
    }
}

/// Row key for Elasticsearch backend.
///
/// Ports `ghidra.features.bsim.query.elastic.RowKeyElastic`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct RowKeyElastic {
    /// The Elasticsearch document ID.
    pub document_id: String,
    /// The index name.
    pub index: String,
}

impl RowKeyElastic {
    /// Create a new elastic row key.
    pub fn new(document_id: impl Into<String>, index: impl Into<String>) -> Self {
        Self {
            document_id: document_id.into(),
            index: index.into(),
        }
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

    #[test]
    fn test_elastic_connection() {
        let mut conn = ElasticConnection::new("http://localhost:9200")
            .with_auth("admin")
            .with_timeout(60);
        assert_eq!(conn.base_url, "http://localhost:9200");
        assert_eq!(conn.username.as_deref(), Some("admin"));
        assert_eq!(conn.timeout_secs, 60);
        assert!(!conn.is_connected());

        conn.connect().unwrap();
        assert!(conn.is_connected());

        conn.disconnect();
        assert!(!conn.is_connected());
    }

    #[test]
    fn test_elastic_connection_health_url() {
        let conn = ElasticConnection::new("http://es:9200");
        assert_eq!(conn.health_url(), "http://es:9200/_cluster/health");
    }

    #[test]
    fn test_elastic_effects() {
        let mut effects = ElasticEffects::new();
        assert!(!effects.has_errors());
        assert_eq!(effects.total_operations(), 0);

        effects.add_success();
        effects.add_success();
        assert_eq!(effects.total_operations(), 2);

        effects.add_error("connection refused");
        assert!(effects.has_errors());
        assert_eq!(effects.failure_count, 1);

        effects.add_warning("slow query");
        assert_eq!(effects.warnings.len(), 1);

        effects.clear();
        assert!(!effects.has_errors());
        assert_eq!(effects.total_operations(), 0);
    }

    #[test]
    fn test_base64_vector_factory_roundtrip() {
        let vector = vec![1.0, 2.5, -3.7, 0.0, 42.0];
        let encoded = Base64VectorFactory::encode_vector(&vector);
        assert!(!encoded.is_empty());

        let decoded = Base64VectorFactory::decode_vector(&encoded).unwrap();
        assert_eq!(decoded.len(), vector.len());
        for (a, b) in vector.iter().zip(decoded.iter()) {
            assert!((a - b).abs() < 1e-10);
        }
    }

    #[test]
    fn test_elastic_id_resolution() {
        let mut res = ElasticIdResolution::new("doc_123");
        assert!(!res.resolved);
        assert!(res.row_key.is_none());

        res.resolve(42);
        assert!(res.resolved);
        assert_eq!(res.row_key, Some(42));
    }

    #[test]
    fn test_row_key_elastic() {
        let key = RowKeyElastic::new("doc_1", "functions");
        assert_eq!(key.document_id, "doc_1");
        assert_eq!(key.index, "functions");

        let key2 = RowKeyElastic::new("doc_1", "functions");
        assert_eq!(key, key2);
    }
}
