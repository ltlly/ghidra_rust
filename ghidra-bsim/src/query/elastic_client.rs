//! Elasticsearch client for BSim.
//!
//! Port of Ghidra's `ghidra.features.bsim.query.elastic` package:
//! - `ElasticConnection`: HTTP connection to Elasticsearch
//! - `ElasticDatabase`: Elasticsearch-backed function database
//! - `ElasticEffects`: effects tracker for elastic operations
//! - `ElasticException`: elastic-specific errors
//! - `Handler`: request handler
//! - `IDElasticResolution`: id resolution for elastic
//! - `RowKeyElastic`: row key for elastic documents
//! - `Base64Lite`: lightweight base64 encoding

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Base64-lite encoder/decoder for vector data.
///
/// Port of `ghidra.features.bsim.query.elastic.Base64Lite`.
pub struct Base64Lite;

impl Base64Lite {
    /// Standard Base64 alphabet.
    const ALPHABET: &'static [u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// Encode bytes to base64 string.
    pub fn encode(data: &[u8]) -> String {
        let mut result = String::with_capacity((data.len() * 4 / 3) + 4);
        for chunk in data.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
            let triple = (b0 << 16) | (b1 << 8) | b2;
            result.push(Self::ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
            result.push(Self::ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
            if chunk.len() > 1 {
                result.push(Self::ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
            } else {
                result.push('=');
            }
            if chunk.len() > 2 {
                result.push(Self::ALPHABET[(triple & 0x3F) as usize] as char);
            } else {
                result.push('=');
            }
        }
        result
    }
}

/// Base64 vector factory for creating vectors from base64-encoded data.
///
/// Port of `ghidra.features.bsim.query.elastic.Base64VectorFactory`.
#[derive(Debug, Default)]
pub struct Base64VectorFactory;

impl Base64VectorFactory {
    /// Create a float vector from a base64-encoded string.
    pub fn from_base64(encoded: &str, dimension: usize) -> Option<Vec<f32>> {
        let bytes = Self::decode_bytes(encoded)?;
        if bytes.len() < dimension * 4 {
            return None;
        }
        let mut result = Vec::with_capacity(dimension);
        for i in 0..dimension {
            let offset = i * 4;
            let val = f32::from_le_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]);
            result.push(val);
        }
        Some(result)
    }

    /// Encode a float vector to base64.
    pub fn to_base64(vector: &[f32]) -> String {
        let mut bytes = Vec::with_capacity(vector.len() * 4);
        for &val in vector {
            bytes.extend_from_slice(&val.to_le_bytes());
        }
        Base64Lite::encode(&bytes)
    }

    fn decode_bytes(encoded: &str) -> Option<Vec<u8>> {
        let encoded = encoded.trim_end_matches('=');
        let mut result = Vec::new();
        let chars: Vec<u8> = encoded
            .bytes()
            .map(|b| {
                match b {
                    b'A'..=b'Z' => b - b'A',
                    b'a'..=b'z' => b - b'a' + 26,
                    b'0'..=b'9' => b - b'0' + 52,
                    b'+' => 62,
                    b'/' => 63,
                    _ => 0,
                }
            })
            .collect();

        for chunk in chars.chunks(4) {
            if chunk.len() >= 2 {
                let b0 = chunk[0] as u32;
                let b1 = chunk[1] as u32;
                let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
                let triple = (b0 << 18) | (b1 << 12) | (b2 << 6);
                result.push(((triple >> 16) & 0xFF) as u8);
                if chunk.len() > 2 {
                    result.push(((triple >> 8) & 0xFF) as u8);
                }
                if chunk.len() > 3 {
                    result.push((triple & 0xFF) as u8);
                }
            }
        }
        Some(result)
    }
}

/// Row key for Elasticsearch documents.
///
/// Port of `ghidra.features.bsim.query.elastic.RowKeyElastic`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RowKeyElastic {
    /// Document id.
    pub doc_id: String,
    /// Index name.
    pub index: String,
}

impl RowKeyElastic {
    /// Create a new elastic row key.
    pub fn new(doc_id: impl Into<String>, index: impl Into<String>) -> Self {
        Self { doc_id: doc_id.into(), index: index.into() }
    }
}

/// ID resolution for Elasticsearch.
///
/// Port of `ghidra.features.bsim.query.elastic.IDElasticResolution`.
#[derive(Debug, Clone, Default)]
pub struct IdElasticResolution {
    /// Map from name to elastic id.
    pub id_map: HashMap<String, i64>,
    /// Map from elastic id to name.
    pub name_map: HashMap<i64, String>,
}

impl IdElasticResolution {
    /// Create a new resolution.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a mapping.
    pub fn add(&mut self, name: impl Into<String>, id: i64) {
        let name = name.into();
        self.name_map.insert(id, name.clone());
        self.id_map.insert(name, id);
    }

    /// Resolve name to id.
    pub fn resolve_name(&self, name: &str) -> Option<i64> {
        self.id_map.get(name).copied()
    }

    /// Resolve id to name.
    pub fn resolve_id(&self, id: i64) -> Option<&str> {
        self.name_map.get(&id).map(|s| s.as_str())
    }
}

/// Effects tracker for Elasticsearch operations.
///
/// Port of `ghidra.features.bsim.query.elastic.ElasticEffects`.
#[derive(Debug, Clone, Default)]
pub struct ElasticEffects {
    /// Number of index operations.
    pub index_ops: u64,
    /// Number of search operations.
    pub search_ops: u64,
    /// Number of delete operations.
    pub delete_ops: u64,
    /// Number of update operations.
    pub update_ops: u64,
    /// Whether any effects have been recorded.
    pub has_effects: bool,
}

impl ElasticEffects {
    /// Create new effects.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an index operation.
    pub fn record_index(&mut self, count: u64) {
        self.index_ops += count;
        self.has_effects = true;
    }

    /// Record a search operation.
    pub fn record_search(&mut self, count: u64) {
        self.search_ops += count;
        self.has_effects = true;
    }

    /// Record a delete operation.
    pub fn record_delete(&mut self, count: u64) {
        self.delete_ops += count;
        self.has_effects = true;
    }

    /// Record an update operation.
    pub fn record_update(&mut self, count: u64) {
        self.update_ops += count;
        self.has_effects = true;
    }

    /// Total operations.
    pub fn total(&self) -> u64 {
        self.index_ops + self.search_ops + self.delete_ops + self.update_ops
    }
}

/// Elastic-specific exception.
///
/// Port of `ghidra.features.bsim.query.elastic.ElasticException`.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Elasticsearch error: {message}")]
pub struct ElasticException {
    /// Error message.
    pub message: String,
    /// HTTP status code (if applicable).
    pub status_code: Option<u16>,
}

impl ElasticException {
    /// Create a new elastic exception.
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into(), status_code: None }
    }

    /// Create with a status code.
    pub fn with_status(message: impl Into<String>, status_code: u16) -> Self {
        Self { message: message.into(), status_code: Some(status_code) }
    }
}

/// HTTP connection to Elasticsearch.
///
/// Port of `ghidra.features.bsim.query.elastic.ElasticConnection`.
#[derive(Debug)]
pub struct ElasticConnection {
    /// Base URL of the Elasticsearch server.
    pub base_url: String,
    /// Whether connected.
    connected: bool,
    /// Connection timeout in milliseconds.
    pub timeout_ms: u64,
}

impl ElasticConnection {
    /// Create a new elastic connection.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self { base_url: base_url.into(), connected: false, timeout_ms: 30000 }
    }

    /// Connect (placeholder).
    pub fn connect(&mut self) -> Result<(), ElasticException> {
        self.connected = true;
        Ok(())
    }

    /// Disconnect.
    pub fn disconnect(&mut self) {
        self.connected = false;
    }

    /// Whether connected.
    pub fn is_connected(&self) -> bool {
        self.connected
    }
}

/// Request handler for Elasticsearch operations.
///
/// Port of `ghidra.features.bsim.query.elastic.Handler`.
#[derive(Debug)]
pub struct Handler {
    /// The connection to use.
    pub connection: ElasticConnection,
    /// Effects tracker.
    pub effects: ElasticEffects,
}

impl Handler {
    /// Create a new handler.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            connection: ElasticConnection::new(base_url),
            effects: ElasticEffects::new(),
        }
    }

    /// Execute a search query (placeholder).
    pub fn search(&mut self, _index: &str, _query: &str) -> Result<String, ElasticException> {
        self.effects.record_search(1);
        Ok("{}".into())
    }

    /// Index a document (placeholder).
    pub fn index(&mut self, _index: &str, _id: &str, _body: &str) -> Result<(), ElasticException> {
        self.effects.record_index(1);
        Ok(())
    }

    /// Delete a document (placeholder).
    pub fn delete(&mut self, _index: &str, _id: &str) -> Result<(), ElasticException> {
        self.effects.record_delete(1);
        Ok(())
    }
}

/// Elasticsearch-backed function database.
///
/// Port of `ghidra.features.bsim.query.elastic.ElasticDatabase`.
#[derive(Debug)]
pub struct ElasticDatabase {
    /// Handler for HTTP operations.
    pub handler: Handler,
    /// ID resolution.
    pub resolution: IdElasticResolution,
    /// Whether connected.
    connected: bool,
}

impl ElasticDatabase {
    /// Create a new elastic database.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            handler: Handler::new(base_url),
            resolution: IdElasticResolution::new(),
            connected: false,
        }
    }

    /// Connect.
    pub fn connect(&mut self) -> Result<(), ElasticException> {
        self.handler.connection.connect()?;
        self.connected = true;
        Ok(())
    }

    /// Disconnect.
    pub fn disconnect(&mut self) {
        self.handler.connection.disconnect();
        self.connected = false;
    }

    /// Whether connected.
    pub fn is_connected(&self) -> bool {
        self.connected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_lite_encode() {
        let encoded = Base64Lite::encode(b"Hello");
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_base64_vector_factory_roundtrip() {
        let vector = vec![1.0f32, 2.0, 3.0, 4.0];
        let encoded = Base64VectorFactory::to_base64(&vector);
        let decoded = Base64VectorFactory::from_base64(&encoded, 4).unwrap();
        for (a, b) in vector.iter().zip(decoded.iter()) {
            assert!((a - b).abs() < 1e-6);
        }
    }

    #[test]
    fn test_row_key_elastic() {
        let key = RowKeyElastic::new("doc123", "functions");
        assert_eq!(key.doc_id, "doc123");
        assert_eq!(key.index, "functions");
    }

    #[test]
    fn test_id_elastic_resolution() {
        let mut res = IdElasticResolution::new();
        res.add("main", 42);
        assert_eq!(res.resolve_name("main"), Some(42));
        assert_eq!(res.resolve_id(42), Some("main"));
        assert!(res.resolve_name("unknown").is_none());
    }

    #[test]
    fn test_elastic_effects() {
        let mut fx = ElasticEffects::new();
        fx.record_index(10);
        fx.record_search(5);
        assert_eq!(fx.total(), 15);
        assert!(fx.has_effects);
    }

    #[test]
    fn test_elastic_exception() {
        let e = ElasticException::new("connection refused");
        assert_eq!(e.message, "connection refused");
        assert!(e.status_code.is_none());

        let e2 = ElasticException::with_status("not found", 404);
        assert_eq!(e2.status_code, Some(404));
    }

    #[test]
    fn test_elastic_connection() {
        let mut conn = ElasticConnection::new("http://localhost:9200");
        assert!(!conn.is_connected());
        conn.connect().unwrap();
        assert!(conn.is_connected());
        conn.disconnect();
        assert!(!conn.is_connected());
    }

    #[test]
    fn test_elastic_database() {
        let mut db = ElasticDatabase::new("http://localhost:9200");
        assert!(!db.is_connected());
        db.connect().unwrap();
        assert!(db.is_connected());
        db.disconnect();
        assert!(!db.is_connected());
    }

    #[test]
    fn test_handler() {
        let mut h = Handler::new("http://localhost:9200");
        let result = h.search("functions", r#"{"query":{"match_all":{}}}"#);
        assert!(result.is_ok());
        assert_eq!(h.effects.search_ops, 1);
    }
}
