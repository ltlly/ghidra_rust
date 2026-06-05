//! ElasticSearch utility functions for BSim.
//!
//! Ports `ghidra.features.bsim.query.elastic.ElasticUtilities`.

use super::super::BSimError;

/// Encode bytes to a URL-safe Base64 string (no padding).
///
/// Port of `ghidra.features.bsim.query.elastic.Base64Lite`.
pub fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut result = String::new();
    let mut i = 0;
    while i + 2 < data.len() {
        let b0 = data[i] as u32;
        let b1 = data[i + 1] as u32;
        let b2 = data[i + 2] as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        result.push(CHARS[(triple & 0x3F) as usize] as char);
        i += 3;
    }
    let remaining = data.len() - i;
    if remaining == 1 {
        let b0 = data[i] as u32;
        result.push(CHARS[((b0 >> 2) & 0x3F) as usize] as char);
        result.push(CHARS[((b0 << 4) & 0x3F) as usize] as char);
    } else if remaining == 2 {
        let b0 = data[i] as u32;
        let b1 = data[i + 1] as u32;
        let triple = (b0 << 16) | (b1 << 8);
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
    }
    result
}

/// Decode a URL-safe Base64 string to bytes.
pub fn base64_decode(s: &str) -> Result<Vec<u8>, BSimError> {
    fn char_to_val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }

    let bytes = s.as_bytes();
    let mut result = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;
    while i + 3 < bytes.len() {
        let a = char_to_val(bytes[i]).ok_or_else(|| BSimError::QueryError("invalid base64 char".into()))?;
        let b = char_to_val(bytes[i + 1]).ok_or_else(|| BSimError::QueryError("invalid base64 char".into()))?;
        let c = char_to_val(bytes[i + 2]).ok_or_else(|| BSimError::QueryError("invalid base64 char".into()))?;
        let d = char_to_val(bytes[i + 3]).ok_or_else(|| BSimError::QueryError("invalid base64 char".into()))?;
        let triple = (a << 18) | (b << 12) | (c << 6) | d;
        result.push(((triple >> 16) & 0xFF) as u8);
        result.push(((triple >> 8) & 0xFF) as u8);
        result.push((triple & 0xFF) as u8);
        i += 4;
    }
    let remaining = bytes.len() - i;
    if remaining >= 2 {
        let a = char_to_val(bytes[i]).ok_or_else(|| BSimError::QueryError("invalid base64 char".into()))?;
        let b = char_to_val(bytes[i + 1]).ok_or_else(|| BSimError::QueryError("invalid base64 char".into()))?;
        result.push(((a << 2) | (b >> 4)) as u8);
        if remaining >= 3 {
            let c = char_to_val(bytes[i + 2]).ok_or_else(|| BSimError::QueryError("invalid base64 char".into()))?;
            result.push(((b << 4) | (c >> 2)) as u8);
        }
    }
    Ok(result)
}

/// Encode a floating-point vector to base64 for ElasticSearch storage.
///
/// Port of `ghidra.features.bsim.query.elastic.Base64VectorFactory`.
pub fn encode_vector(vector: &[f64]) -> String {
    let mut bytes = Vec::with_capacity(vector.len() * 8);
    for &val in vector {
        bytes.extend_from_slice(&val.to_le_bytes());
    }
    base64_encode(&bytes)
}

/// Decode a base64-encoded vector back to floats.
pub fn decode_vector(encoded: &str) -> Result<Vec<f64>, BSimError> {
    let bytes = base64_decode(encoded)?;
    if bytes.len() % 8 != 0 {
        return Err(BSimError::QueryError("invalid vector encoding length".into()));
    }
    let mut result = Vec::with_capacity(bytes.len() / 8);
    for chunk in bytes.chunks_exact(8) {
        let val = f64::from_le_bytes(chunk.try_into().unwrap());
        result.push(val);
    }
    Ok(result)
}

/// ElasticSearch exception type.
#[derive(Debug, Clone)]
pub struct ElasticException {
    /// HTTP status code.
    pub status: u16,
    /// Error message.
    pub message: String,
    /// Error category.
    pub category: ElasticErrorCategory,
}

/// Error categories for ElasticSearch operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElasticErrorCategory {
    /// Connection error (server unreachable).
    Connection,
    /// Index not found.
    IndexNotFound,
    /// Query parse error.
    QueryParse,
    /// Document not found.
    DocumentNotFound,
    /// Mapping error.
    Mapping,
    /// Other/unclassified error.
    Other,
}

impl std::fmt::Display for ElasticException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ElasticSearch error ({}): {}", self.status, self.message)
    }
}

impl std::error::Error for ElasticException {}

/// Effects tracking for ElasticSearch operations.
#[derive(Debug, Clone, Default)]
pub struct ElasticEffects {
    /// Number of documents indexed.
    pub indexed: usize,
    /// Number of documents updated.
    pub updated: usize,
    /// Number of documents deleted.
    pub deleted: usize,
    /// Number of search queries executed.
    pub queries: usize,
    /// Number of errors encountered.
    pub errors: usize,
}

impl ElasticEffects {
    /// Create new empty effects tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge effects from another tracker.
    pub fn merge(&mut self, other: &ElasticEffects) {
        self.indexed += other.indexed;
        self.updated += other.updated;
        self.deleted += other.deleted;
        self.queries += other.queries;
        self.errors += other.errors;
    }
}

/// Resolution of ID mapping in ElasticSearch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdElasticResolution {
    /// Resolved by internal ID.
    ById,
    /// Resolved by name lookup.
    ByName,
    /// Not resolved.
    Unresolved,
}

/// An ElasticSearch row key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RowKeyElastic {
    /// The index name.
    pub index: String,
    /// The document ID within the index.
    pub doc_id: String,
}

impl RowKeyElastic {
    /// Create a new row key.
    pub fn new(index: impl Into<String>, doc_id: impl Into<String>) -> Self {
        Self {
            index: index.into(),
            doc_id: doc_id.into(),
        }
    }

    /// Get the full qualified key string.
    pub fn qualified_key(&self) -> String {
        format!("{}/{}", self.index, self.doc_id)
    }
}

/// A handler for ElasticSearch REST API operations.
#[derive(Debug, Clone)]
pub struct ElasticHandler {
    /// Base URL for the ElasticSearch instance.
    pub base_url: String,
    /// Index name prefix.
    pub index_prefix: String,
}

impl ElasticHandler {
    /// Create a new handler.
    pub fn new(base_url: impl Into<String>, index_prefix: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            index_prefix: index_prefix.into(),
        }
    }

    /// Build a URL for an index operation.
    pub fn index_url(&self, index_name: &str) -> String {
        format!("{}/{}/{}", self.base_url, self.index_prefix, index_name)
    }

    /// Build a URL for a search operation.
    pub fn search_url(&self, index_name: &str) -> String {
        format!("{}/{}/{}/_search", self.base_url, self.index_prefix, index_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, BSim!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(data.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_base64_empty() {
        let encoded = base64_encode(b"");
        assert!(encoded.is_empty());
        let decoded = base64_decode("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_base64_single_byte() {
        let data = [0xFF_u8];
        let encoded = base64_encode(&data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(data.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_vector_roundtrip() {
        let vector = vec![1.0, 2.5, -3.7, 0.0];
        let encoded = encode_vector(&vector);
        let decoded = decode_vector(&encoded).unwrap();
        assert_eq!(vector.len(), decoded.len());
        for (a, b) in vector.iter().zip(decoded.iter()) {
            assert!((a - b).abs() < 1e-10);
        }
    }

    #[test]
    fn test_elastic_effects_merge() {
        let mut e1 = ElasticEffects::new();
        e1.indexed = 10;
        e1.queries = 3;
        let mut e2 = ElasticEffects::new();
        e2.indexed = 5;
        e2.errors = 1;
        e1.merge(&e2);
        assert_eq!(e1.indexed, 15);
        assert_eq!(e1.queries, 3);
        assert_eq!(e1.errors, 1);
    }

    #[test]
    fn test_row_key_elastic() {
        let key = RowKeyElastic::new("functions", "doc_123");
        assert_eq!(key.qualified_key(), "functions/doc_123");
    }

    #[test]
    fn test_elastic_handler_urls() {
        let handler = ElasticHandler::new("http://localhost:9200", "bsim");
        assert_eq!(handler.index_url("funcs"), "http://localhost:9200/bsim/funcs");
        assert_eq!(handler.search_url("funcs"), "http://localhost:9200/bsim/funcs/_search");
    }

    #[test]
    fn test_elastic_exception_display() {
        let exc = ElasticException {
            status: 404,
            message: "not found".to_string(),
            category: ElasticErrorCategory::IndexNotFound,
        };
        let s = format!("{}", exc);
        assert!(s.contains("404"));
        assert!(s.contains("not found"));
    }
}
