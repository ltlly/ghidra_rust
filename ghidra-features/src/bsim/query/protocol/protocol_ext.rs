//! Extended BSim protocol types.
//!
//! Additional request/response types and helper utilities for the BSim
//! client-server protocol.  Core protocol types are in the parent `mod.rs`.

use serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use std::collections::HashMap;

use super::super::FeatureVector;

/// A helper for formatting BSim protocol XML escape sequences.
///
/// Port of Ghidra's XML escape utilities used in BSim protocol serialization.
pub struct XmlEscapeWriter;

impl XmlEscapeWriter {
    /// Escape special XML characters in a string.
    pub fn escape(input: &str) -> String {
        input
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }

    /// Decode a boolean from a string representation.
    pub fn decode_boolean(value: &str) -> bool {
        matches!(value, "true" | "1" | "yes")
    }

    /// Encode a signed integer as a string.
    pub fn encode_signed_integer(value: i64) -> String {
        value.to_string()
    }

    /// Parse a double from a string.
    pub fn parse_double(value: &str) -> Result<f64, String> {
        value.parse::<f64>().map_err(|e| format!("Invalid double: {}", e))
    }
}

/// Extension trait for vector-related operations in the BSim protocol.
///
/// Provides additional operations on feature vectors used in the
/// BSim protocol exchange.
pub trait VectorProtocolExt {
    /// Serialize a vector to a compact string representation.
    fn to_protocol_string(&self) -> String;

    /// Compute a quick hash for protocol exchange.
    fn protocol_hash(&self) -> u64;
}

impl VectorProtocolExt for FeatureVector {
    fn to_protocol_string(&self) -> String {
        let parts: Vec<String> = self
            .hashes
            .iter()
            .zip(self.weights.iter())
            .map(|(h, w)| format!("{}:{}", h, w))
            .collect();
        parts.join(",")
    }

    fn protocol_hash(&self) -> u64 {
        let mut hash: u64 = 0xcbf29ce484222325;
        for (h, w) in self.hashes.iter().zip(self.weights.iter()) {
            hash ^= (*h as u64).wrapping_mul(1099511628211);
            hash ^= (*w as u32 as u64).wrapping_mul(1099511628211);
        }
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_escape_basic() {
        assert_eq!(XmlEscapeWriter::escape("hello"), "hello");
        assert_eq!(XmlEscapeWriter::escape("a<b"), "a&lt;b");
        assert_eq!(XmlEscapeWriter::escape("a&b"), "a&amp;b");
        assert_eq!(XmlEscapeWriter::escape("\"q\""), "&quot;q&quot;");
    }

    #[test]
    fn decode_boolean_values() {
        assert!(XmlEscapeWriter::decode_boolean("true"));
        assert!(XmlEscapeWriter::decode_boolean("1"));
        assert!(!XmlEscapeWriter::decode_boolean("false"));
        assert!(!XmlEscapeWriter::decode_boolean("0"));
    }

    #[test]
    fn encode_signed_integer_values() {
        assert_eq!(XmlEscapeWriter::encode_signed_integer(42), "42");
        assert_eq!(XmlEscapeWriter::encode_signed_integer(-1), "-1");
    }

    #[test]
    fn parse_double_values() {
        assert!((XmlEscapeWriter::parse_double("3.14").unwrap() - 3.14).abs() < 1e-10);
        assert!(XmlEscapeWriter::parse_double("not_a_number").is_err());
    }

    #[test]
    fn vector_protocol_string() {
        let fv = FeatureVector::from_pairs(vec![1, 2], vec![0.5, 0.3]);
        let s = fv.to_protocol_string();
        assert!(s.contains("1:0.5") || s.contains("2:0.3"));
    }

    #[test]
    fn vector_protocol_hash_deterministic() {
        let fv = FeatureVector::from_pairs(vec![1, 2], vec![1.0, 1.0]);
        let h1 = fv.protocol_hash();
        let h2 = fv.protocol_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_vectors_different_hashes() {
        let a = FeatureVector::from_pairs(vec![1], vec![1.0]);
        let b = FeatureVector::from_pairs(vec![2], vec![1.0]);
        assert_ne!(a.protocol_hash(), b.protocol_hash());
    }
}
