//! Elasticsearch-based BSim backend.
//!
//! Port of `ghidra.features.bsim.query.elastic`:
//! - [`ElasticDatabase`]: Elasticsearch BSim function database
//! - [`ElasticConnection`]: HTTP connection to Elasticsearch
//! - [`ElasticEffects`]: side effects for Elastic operations
//! - [`ElasticException`]: Elasticsearch-specific errors
//! - [`IdelasticResolution`]: ID-based elastic resolution
//! - [`RowKeyElastic`]: Elasticsearch row key type
//! - [`Base64VectorFactory`]: vector factory for base64-encoded vectors

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::super::client::BSimError;

// New modules ported from Ghidra's BSim elastic package
pub mod base64_lite;
pub mod elastic_utilities;

// ============================================================================
// ElasticException
// ============================================================================

/// Exception specific to Elasticsearch BSim operations.
#[derive(Debug, Clone)]
pub struct ElasticException {
    /// Error message.
    pub message: String,
    /// HTTP status code (if applicable).
    pub status_code: Option<u16>,
}

impl ElasticException {
    /// Create a new elastic exception.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status_code: None,
        }
    }

    /// Create with an HTTP status code.
    pub fn with_status(message: impl Into<String>, status_code: u16) -> Self {
        Self {
            message: message.into(),
            status_code: Some(status_code),
        }
    }
}

impl fmt::Display for ElasticException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.status_code {
            Some(code) => write!(f, "Elasticsearch error ({}): {}", code, self.message),
            None => write!(f, "Elasticsearch error: {}", self.message),
        }
    }
}

impl std::error::Error for ElasticException {}

impl From<ElasticException> for BSimError {
    fn from(e: ElasticException) -> Self {
        BSimError::QueryError(format!("{}", e))
    }
}

// ============================================================================
// ElasticConnection
// ============================================================================

/// HTTP connection handler for Elasticsearch.
///
/// Manages the base URL and provides methods for sending
/// HTTP requests (POST, PUT, GET, DELETE) to the Elasticsearch cluster.
#[derive(Debug, Clone)]
pub struct ElasticConnection {
    /// The host URL (e.g., "http://hostname:port").
    pub host_url: String,
    /// The base URL prefix for all requests.
    pub http_url_base: String,
    /// Last HTTP response code.
    last_response_code: u16,
}

/// HTTP methods for Elasticsearch requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    /// POST request.
    Post,
    /// PUT request.
    Put,
    /// GET request.
    Get,
    /// DELETE request.
    Delete,
}

impl ElasticConnection {
    /// Create a new elastic connection.
    pub fn new(url: impl Into<String>, repo: impl Into<String>) -> Self {
        let host_url = url.into();
        let http_url_base = format!("{}/{}_", host_url, repo.into());
        Self {
            host_url,
            http_url_base,
            last_response_code: 0,
        }
    }

    /// Whether the last request was successful (2xx).
    pub fn last_request_successful(&self) -> bool {
        (200..300).contains(&self.last_response_code)
    }

    /// Get the last response code.
    pub fn last_response_code(&self) -> u16 {
        self.last_response_code
    }

    /// Set the last response code (for testing).
    pub fn set_last_response_code(&mut self, code: u16) {
        self.last_response_code = code;
    }

    /// Build a URL for a specific index type.
    pub fn index_url(&self, index_type: &str) -> String {
        format!("{}{}", self.http_url_base, index_type)
    }

    /// Build a URL for searching.
    pub fn search_url(&self) -> String {
        format!("{}{}/_search", self.http_url_base, "function")
    }
}

// ============================================================================
// RowKeyElastic
// ============================================================================

/// Row key for Elasticsearch-backed BSim database.
///
/// Elasticsearch uses string-based document IDs, so this type
/// wraps a numeric key with string conversion support.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RowKeyElastic {
    /// The numeric key value.
    pub key: u64,
    /// The string representation used as the Elasticsearch document ID.
    pub doc_id: String,
}

impl RowKeyElastic {
    /// Create a new elastic row key.
    pub fn new(key: u64) -> Self {
        Self {
            key,
            doc_id: key.to_string(),
        }
    }

    /// Create from a document ID string.
    pub fn from_doc_id(doc_id: impl Into<String>) -> Self {
        let doc_id = doc_id.into();
        let key = doc_id.parse::<u64>().unwrap_or(0);
        Self { key, doc_id }
    }
}

impl From<u64> for RowKeyElastic {
    fn from(key: u64) -> Self {
        Self::new(key)
    }
}

// ============================================================================
// IdelasticResolution
// ============================================================================

/// Resolves vector IDs to their Elasticsearch document representations.
///
/// Maps numeric vector IDs to their corresponding Elasticsearch
/// document IDs and metadata.
#[derive(Debug, Clone, Default)]
pub struct IdelasticResolution {
    /// Map from vector ID to document ID.
    pub resolutions: HashMap<u64, String>,
}

impl IdelasticResolution {
    /// Create a new resolution map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a resolution.
    pub fn add(&mut self, vector_id: u64, doc_id: impl Into<String>) {
        self.resolutions.insert(vector_id, doc_id.into());
    }

    /// Look up a document ID by vector ID.
    pub fn get(&self, vector_id: u64) -> Option<&str> {
        self.resolutions.get(&vector_id).map(|s| s.as_str())
    }

    /// Number of resolutions.
    pub fn len(&self) -> usize {
        self.resolutions.len()
    }

    /// Whether the resolution map is empty.
    pub fn is_empty(&self) -> bool {
        self.resolutions.is_empty()
    }
}

// ============================================================================
// Base64VectorFactory
// ============================================================================

/// Factory for creating and decoding base64-encoded feature vectors.
///
/// Elasticsearch stores vectors as base64-encoded binary blobs.
/// This factory handles the encoding/decoding of vector data.
#[derive(Debug, Clone, Default)]
pub struct Base64VectorFactory {
    /// Cache of decoded vectors by their ID.
    cache: HashMap<u64, Vec<f64>>,
}

impl Base64VectorFactory {
    /// Create a new vector factory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Encode a feature vector to a base64 string.
    pub fn encode_vector(vector: &[f64]) -> String {
        let bytes: Vec<u8> = vector
            .iter()
            .flat_map(|v| v.to_le_bytes().to_vec())
            .collect();
        base64_encode(&bytes)
    }

    /// Decode a base64 string back to a feature vector.
    pub fn decode_vector(encoded: &str) -> Option<Vec<f64>> {
        let bytes = base64_decode(encoded)?;
        if bytes.len() % 8 != 0 {
            return None;
        }
        let mut result = Vec::with_capacity(bytes.len() / 8);
        for chunk in bytes.chunks_exact(8) {
            let arr: [u8; 8] = chunk.try_into().ok()?;
            result.push(f64::from_le_bytes(arr));
        }
        Some(result)
    }

    /// Cache a decoded vector.
    pub fn cache_vector(&mut self, id: u64, vector: Vec<f64>) {
        self.cache.insert(id, vector);
    }

    /// Get a cached vector.
    pub fn get_cached(&self, id: u64) -> Option<&Vec<f64>> {
        self.cache.get(&id)
    }

    /// Clear the cache.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Cache size.
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }
}

/// Simple base64 encoding (using standard alphabet).
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Simple base64 decoding.
fn base64_decode(data: &str) -> Option<Vec<u8>> {
    fn char_to_val(c: char) -> Option<u8> {
        match c {
            'A'..='Z' => Some((c as u8) - b'A'),
            'a'..='z' => Some((c as u8) - b'a' + 26),
            '0'..='9' => Some((c as u8) - b'0' + 52),
            '+' => Some(62),
            '/' => Some(63),
            _ => None,
        }
    }

    // Count padding
    let padding = if data.ends_with("==") {
        2
    } else if data.ends_with('=') {
        1
    } else {
        0
    };

    // Remove padding and decode
    let clean: String = data.trim_end_matches('=').to_string();
    let mut result = Vec::new();

    for chunk in clean.as_bytes().chunks(4) {
        let vals: Vec<u8> = chunk
            .iter()
            .map(|&b| char_to_val(b as char).unwrap_or(0))
            .collect();

        let b0 = vals.get(0).copied().unwrap_or(0) as u32;
        let b1 = vals.get(1).copied().unwrap_or(0) as u32;
        let b2 = vals.get(2).copied().unwrap_or(0) as u32;

        let triple = (b0 << 18) | (b1 << 12) | (b2 << 6);

        result.push(((triple >> 16) & 0xFF) as u8);
        if chunk.len() > 2 {
            result.push(((triple >> 8) & 0xFF) as u8);
        }
        if chunk.len() > 3 {
            result.push((triple & 0xFF) as u8);
        }
    }

    // Remove padding bytes
    for _ in 0..padding {
        result.pop();
    }

    Some(result)
}

// ============================================================================
// ElasticDatabase
// ============================================================================

/// Elasticsearch-backed BSim function database.
#[derive(Debug, Clone)]
pub struct ElasticDatabase {
    /// Elasticsearch host URL.
    pub host: String,
    /// Index name.
    pub index: String,
    /// Whether the index exists.
    index_exists: bool,
    /// Connection handler.
    pub connection: Option<ElasticConnection>,
}

impl ElasticDatabase {
    /// Create a new Elastic database handle.
    pub fn new(host: impl Into<String>, index: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            index: index.into(),
            index_exists: false,
            connection: None,
        }
    }

    /// Whether the index exists.
    pub fn index_exists(&self) -> bool {
        self.index_exists
    }

    /// Set whether the index exists.
    pub fn set_index_exists(&mut self, exists: bool) {
        self.index_exists = exists;
    }

    /// Get the full index URL.
    pub fn index_url(&self) -> String {
        format!("{}/{}", self.host, self.index)
    }

    /// Connect to the Elasticsearch cluster.
    pub fn connect(&mut self) {
        self.connection = Some(ElasticConnection::new(&self.host, &self.index));
    }

    /// Whether connected.
    pub fn is_connected(&self) -> bool {
        self.connection.is_some()
    }
}

// ============================================================================
// ElasticEffects
// ============================================================================

/// Side effects for Elasticsearch BSim operations.
#[derive(Debug, Clone, Default)]
pub struct ElasticEffects {
    /// Number of documents indexed.
    pub indexed_count: usize,
    /// Number of documents deleted.
    pub deleted_count: usize,
    /// Number of query requests made.
    pub query_count: usize,
    /// Number of bulk operations.
    pub bulk_count: usize,
}

impl ElasticEffects {
    /// Create a new empty effects tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge another effects tracker.
    pub fn merge(&mut self, other: &ElasticEffects) {
        self.indexed_count += other.indexed_count;
        self.deleted_count += other.deleted_count;
        self.query_count += other.query_count;
        self.bulk_count += other.bulk_count;
    }

    /// Whether any operations were performed.
    pub fn has_operations(&self) -> bool {
        self.indexed_count > 0 || self.deleted_count > 0 || self.query_count > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elastic_database() {
        let db = ElasticDatabase::new("http://localhost:9200", "bsim");
        assert_eq!(db.index_url(), "http://localhost:9200/bsim");
        assert!(!db.index_exists());
        assert!(!db.is_connected());
    }

    #[test]
    fn test_elastic_database_connect() {
        let mut db = ElasticDatabase::new("http://localhost:9200", "bsim");
        db.connect();
        assert!(db.is_connected());
        assert!(db.connection.is_some());
    }

    #[test]
    fn test_elastic_effects() {
        let mut fx = ElasticEffects::new();
        fx.indexed_count = 100;
        assert_eq!(fx.indexed_count, 100);
        assert!(fx.has_operations());
    }

    #[test]
    fn test_elastic_effects_merge() {
        let mut e1 = ElasticEffects::new();
        e1.indexed_count = 10;
        e1.query_count = 5;

        let mut e2 = ElasticEffects::new();
        e2.indexed_count = 20;
        e2.deleted_count = 3;

        e1.merge(&e2);
        assert_eq!(e1.indexed_count, 30);
        assert_eq!(e1.query_count, 5);
        assert_eq!(e1.deleted_count, 3);
    }

    #[test]
    fn elastic_exception_display() {
        let e = ElasticException::new("connection refused");
        assert!(format!("{}", e).contains("connection refused"));

        let e = ElasticException::with_status("not found", 404);
        assert!(format!("{}", e).contains("404"));
    }

    #[test]
    fn elastic_exception_to_bsim_error() {
        let e = ElasticException::new("test");
        let bsim_err: BSimError = e.into();
        match bsim_err {
            BSimError::QueryError(msg) => assert!(msg.contains("test")),
            _ => panic!("expected QueryError"),
        }
    }

    #[test]
    fn elastic_connection_creation() {
        let conn = ElasticConnection::new("http://localhost:9200", "bsim");
        assert_eq!(conn.host_url, "http://localhost:9200");
        assert_eq!(conn.http_url_base, "http://localhost:9200/bsim_");
        assert_eq!(conn.last_response_code(), 0);
        assert!(!conn.last_request_successful());
    }

    #[test]
    fn elastic_connection_response_code() {
        let mut conn = ElasticConnection::new("http://localhost:9200", "bsim");
        conn.set_last_response_code(200);
        assert!(conn.last_request_successful());

        conn.set_last_response_code(404);
        assert!(!conn.last_request_successful());
    }

    #[test]
    fn elastic_connection_urls() {
        let conn = ElasticConnection::new("http://localhost:9200", "bsim");
        assert_eq!(conn.index_url("function"), "http://localhost:9200/bsim_function");
        assert_eq!(conn.search_url(), "http://localhost:9200/bsim_function/_search");
    }

    #[test]
    fn row_key_elastic_creation() {
        let key = RowKeyElastic::new(42);
        assert_eq!(key.key, 42);
        assert_eq!(key.doc_id, "42");
    }

    #[test]
    fn row_key_elastic_from_doc_id() {
        let key = RowKeyElastic::from_doc_id("123");
        assert_eq!(key.key, 123);
        assert_eq!(key.doc_id, "123");
    }

    #[test]
    fn row_key_elastic_from_u64() {
        let key: RowKeyElastic = 99u64.into();
        assert_eq!(key.key, 99);
    }

    #[test]
    fn idelastic_resolution() {
        let mut res = IdelasticResolution::new();
        assert!(res.is_empty());

        res.add(1, "doc_1");
        res.add(2, "doc_2");
        assert_eq!(res.len(), 2);
        assert_eq!(res.get(1), Some("doc_1"));
        assert_eq!(res.get(2), Some("doc_2"));
        assert_eq!(res.get(3), None);
    }

    #[test]
    fn base64_vector_factory_encode_decode() {
        let vector = vec![1.0f64, 2.0, 3.0];
        let encoded = Base64VectorFactory::encode_vector(&vector);
        assert!(!encoded.is_empty());

        let decoded = Base64VectorFactory::decode_vector(&encoded).unwrap();
        assert_eq!(decoded.len(), 3);
        assert!((decoded[0] - 1.0).abs() < 1e-9);
        assert!((decoded[1] - 2.0).abs() < 1e-9);
        assert!((decoded[2] - 3.0).abs() < 1e-9);
    }

    #[test]
    fn base64_vector_factory_cache() {
        let mut factory = Base64VectorFactory::new();
        assert_eq!(factory.cache_size(), 0);

        factory.cache_vector(1, vec![1.0, 2.0]);
        assert_eq!(factory.cache_size(), 1);
        assert!(factory.get_cached(1).is_some());
        assert!(factory.get_cached(2).is_none());

        factory.clear_cache();
        assert_eq!(factory.cache_size(), 0);
    }
}
