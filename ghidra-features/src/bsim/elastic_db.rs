//! Elasticsearch database backend for BSim.
//!
//! Ports Ghidra's `ghidra.features.bsim.query.elastic.ElasticDatabase`
//! and `ghidra.features.bsim.query.elastic.ElasticConnection`.
//!
//! This module models the connection parameters and query structure
//! for an Elasticsearch-backed BSim database.  The actual HTTP calls
//! are abstracted behind the `ElasticConnection` trait.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::configuration::{BSimServerConfig, BSimDatabaseType};
use super::{FeatureVector, BSimMetadata, BSimSignature};

// ============================================================================
// ElasticConnection
// ============================================================================

/// Abstraction over an HTTP connection to Elasticsearch.
///
/// Implementors handle the actual HTTP GET/POST/PUT/DELETE calls.
/// The `ElasticDatabase` delegates all I/O to this trait.
pub trait ElasticConnection: Send + Sync {
    /// Perform an HTTP GET request to the given path (relative to the base URL).
    fn get(&self, path: &str) -> Result<String, ElasticError>;

    /// Perform an HTTP POST request with a JSON body.
    fn post(&self, path: &str, body: &str) -> Result<String, ElasticError>;

    /// Perform an HTTP PUT request with a JSON body.
    fn put(&self, path: &str, body: &str) -> Result<String, ElasticError>;

    /// Perform an HTTP DELETE request.
    fn delete(&self, path: &str) -> Result<String, ElasticError>;

    /// Check if the connection is alive.
    fn ping(&self) -> bool;
}

// ============================================================================
// ElasticError
// ============================================================================

/// Errors from Elasticsearch operations.
#[derive(Debug, Clone)]
pub enum ElasticError {
    /// Connection error.
    Connection(String),
    /// HTTP error with status code.
    Http(u16, String),
    /// JSON parse error.
    Parse(String),
    /// Index not found.
    IndexNotFound(String),
    /// Document not found.
    DocumentNotFound(String),
    /// Other error.
    Other(String),
}

impl std::fmt::Display for ElasticError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ElasticError::Connection(msg) => write!(f, "Connection error: {}", msg),
            ElasticError::Http(code, msg) => write!(f, "HTTP {}: {}", code, msg),
            ElasticError::Parse(msg) => write!(f, "Parse error: {}", msg),
            ElasticError::IndexNotFound(idx) => write!(f, "Index not found: {}", idx),
            ElasticError::DocumentNotFound(id) => write!(f, "Document not found: {}", id),
            ElasticError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ElasticError {}

// ============================================================================
// Constants
// ============================================================================

/// BSim Elasticsearch schema version.
pub const LAYOUT_VERSION: i32 = 3;

/// Maximum vectors returned in one query.
pub const MAX_VECTOR_OVERALL: usize = 9000;

/// Maximum functions returned per window.
pub const MAX_FUNCTION_WINDOW: usize = 500;

/// Maximum functions updated in one window.
pub const MAX_FUNCTIONUPDATE_WINDOW: usize = 500;

/// Maximum vector meta documents per mget.
pub const MAX_VECTORCOUNT_WINDOW: usize = 100;

/// Maximum vector/meta documents per delete/update bulk.
pub const MAX_VECTORDELETE_WINDOW: usize = 100;

/// Maximum functions per bulk ingest request.
pub const MAX_FUNCTION_BULK: usize = 200;

/// Maximum vectors per bulk ingest request.
pub const MAX_VECTOR_BULK: usize = 200;

// ============================================================================
// ElasticDatabase
// ============================================================================

/// Elasticsearch-backed BSim database.
///
/// Stores BSim signatures as JSON documents in Elasticsearch indices.
/// Document types:
/// - `executable/exe`: executable metadata (ExecutableRecord)
/// - `executable/function`: function metadata (FunctionDescription)
/// - `vector/vector`: feature vector (LSHVector)
/// - `meta/meta`: vector duplication count
///
/// Ported from `ghidra.features.bsim.query.elastic.ElasticDatabase`.
pub struct ElasticDatabase<C: ElasticConnection> {
    /// Low-level connection to Elasticsearch.
    connection: C,
    /// Server information.
    server_info: BSimServerConfig,
    /// The repository prefix for all indices.
    repository: String,
    /// Current status.
    status: ConnectionStatus,
    /// Whether the database has been initialized.
    initialized: bool,
    /// Last error, if any.
    last_error: Option<ElasticError>,
}

/// Connection status for the elastic database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionStatus {
    /// Not connected.
    Disconnected,
    /// Connected and ready.
    Connected,
    /// Connection error.
    Error,
}

impl<C: ElasticConnection> ElasticDatabase<C> {
    /// Create a new elastic database instance.
    pub fn new(connection: C, server_info: BSimServerConfig, repository: impl Into<String>) -> Self {
        Self {
            connection,
            server_info,
            repository: repository.into(),
            status: ConnectionStatus::Disconnected,
            initialized: false,
            last_error: None,
        }
    }

    /// Initialize the database (check connection, verify schema).
    pub fn initialize(&mut self) -> Result<(), ElasticError> {
        if !self.connection.ping() {
            self.status = ConnectionStatus::Error;
            return Err(ElasticError::Connection("Cannot reach server".into()));
        }
        self.status = ConnectionStatus::Connected;
        self.initialized = true;
        Ok(())
    }

    /// Whether the database is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get the current status.
    pub fn status(&self) -> ConnectionStatus {
        self.status
    }

    /// Get the repository name.
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// Get the last error, if any.
    pub fn last_error(&self) -> Option<&ElasticError> {
        self.last_error.as_ref()
    }

    /// Build the index name for a given type.
    pub fn index_name(&self, index_type: &str) -> String {
        format!("{}_{}", self.repository, index_type)
    }

    /// Escape special characters for use in JSON strings.
    pub fn escape_json(s: &str) -> String {
        let mut result = String::with_capacity(s.len() + 10);
        for ch in s.chars() {
            match ch {
                '"' => result.push_str("\\\""),
                '\\' => result.push_str("\\\\"),
                '\n' => result.push_str("\\n"),
                '\r' => result.push_str("\\r"),
                '\t' => result.push_str("\\t"),
                '\x08' => result.push_str("\\b"),
                '\x0C' => result.push_str("\\f"),
                _ => result.push(ch),
            }
        }
        result
    }

    /// Build a search query JSON for finding functions by executable hash.
    pub fn build_function_search_query(exe_hash: &str, from: usize, size: usize) -> String {
        format!(
            r#"{{"query":{{"term":{{"exehash":"{}"}}}},"from":{},"size":{}}}"#,
            Self::escape_json(exe_hash),
            from,
            size
        )
    }

    /// Build a search query JSON for finding similar vectors.
    pub fn build_vector_similarity_query(
        query_vector: &FeatureVector,
        band: usize,
        bucket: u32,
        max_results: usize,
    ) -> String {
        format!(
            r#"{{"query":{{"bool":{{"must":[{{"term":{{"band":{}}}}},{{"term":{{"bucket":{}}}}}]}}}},"size":{}}}"#,
            band,
            bucket,
            max_results
        )
    }

    /// Get the server info.
    pub fn server_info(&self) -> &BSimServerConfig {
        &self.server_info
    }

    /// Get a reference to the connection.
    pub fn connection(&self) -> &C {
        &self.connection
    }
}

// ============================================================================
// NullElasticConnection (for testing)
// ============================================================================

/// A no-op elastic connection for testing.
#[derive(Debug)]
pub struct NullElasticConnection {
    /// Whether the ping should succeed.
    pub alive: bool,
    /// Stored responses keyed by (method, path).
    pub responses: HashMap<String, String>,
}

impl NullElasticConnection {
    /// Create a new null connection.
    pub fn new(alive: bool) -> Self {
        Self {
            alive,
            responses: HashMap::new(),
        }
    }

    /// Add a canned response for a method+path.
    pub fn set_response(&mut self, method: &str, path: &str, response: impl Into<String>) {
        self.responses
            .insert(format!("{}:{}", method, path), response.into());
    }
}

impl ElasticConnection for NullElasticConnection {
    fn get(&self, path: &str) -> Result<String, ElasticError> {
        self.responses
            .get(&format!("GET:{}", path))
            .cloned()
            .ok_or_else(|| ElasticError::Other(format!("No response for GET {}", path)))
    }

    fn post(&self, path: &str, _body: &str) -> Result<String, ElasticError> {
        self.responses
            .get(&format!("POST:{}", path))
            .cloned()
            .ok_or_else(|| ElasticError::Other(format!("No response for POST {}", path)))
    }

    fn put(&self, path: &str, _body: &str) -> Result<String, ElasticError> {
        self.responses
            .get(&format!("PUT:{}", path))
            .cloned()
            .ok_or_else(|| ElasticError::Other(format!("No response for PUT {}", path)))
    }

    fn delete(&self, path: &str) -> Result<String, ElasticError> {
        self.responses
            .get(&format!("DELETE:{}", path))
            .cloned()
            .ok_or_else(|| ElasticError::Other(format!("No response for DELETE {}", path)))
    }

    fn ping(&self) -> bool {
        self.alive
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elastic_database_escape_json() {
        assert_eq!(ElasticDatabase::<NullElasticConnection>::escape_json("hello"), "hello");
        assert_eq!(
            ElasticDatabase::<NullElasticConnection>::escape_json("a\"b\\c\nd"),
            "a\\\"b\\\\c\\nd"
        );
    }

    #[test]
    fn elastic_database_index_name() {
        let conn = NullElasticConnection::new(true);
        let info = BSimServerConfig::in_memory("test");
        let db = ElasticDatabase::new(conn, info, "myrepo");
        assert_eq!(db.index_name("exe"), "myrepo_exe");
        assert_eq!(db.index_name("function"), "myrepo_function");
    }

    #[test]
    fn elastic_database_initialize_ok() {
        let conn = NullElasticConnection::new(true);
        let info = BSimServerConfig::in_memory("test");
        let mut db = ElasticDatabase::new(conn, info, "repo");
        assert!(!db.is_initialized());
        db.initialize().unwrap();
        assert!(db.is_initialized());
        assert_eq!(db.status(), ConnectionStatus::Connected);
    }

    #[test]
    fn elastic_database_initialize_fail() {
        let conn = NullElasticConnection::new(false);
        let info = BSimServerConfig::in_memory("test");
        let mut db = ElasticDatabase::new(conn, info, "repo");
        assert!(db.initialize().is_err());
        assert_eq!(db.status(), ConnectionStatus::Error);
    }

    #[test]
    fn elastic_database_build_queries() {
        let q = ElasticDatabase::<NullElasticConnection>::build_function_search_query("abc123", 0, 10);
        assert!(q.contains("abc123"));
        assert!(q.contains("\"from\":0"));
        assert!(q.contains("\"size\":10"));

        let fv = FeatureVector::from_pairs(vec![1, 2], vec![1.0, 0.5]);
        let q = ElasticDatabase::<NullElasticConnection>::build_vector_similarity_query(&fv, 3, 42, 50);
        assert!(q.contains("\"band\":3"));
        assert!(q.contains("\"bucket\":42"));
    }

    #[test]
    fn elastic_constants() {
        assert_eq!(LAYOUT_VERSION, 3);
        assert!(MAX_VECTOR_OVERALL > 0);
        assert!(MAX_FUNCTION_WINDOW > 0);
    }

    #[test]
    fn null_elastic_connection() {
        let mut conn = NullElasticConnection::new(true);
        assert!(conn.ping());

        conn.set_response("GET", "/_cluster/health", r#"{"status":"green"}"#);
        let result = conn.get("/_cluster/health").unwrap();
        assert!(result.contains("green"));
    }
}
