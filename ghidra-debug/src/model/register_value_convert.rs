//! RegisterValueConverter - converts register values between representations.
//!
//! Ported from Ghidra's `RegisterValueConverter` in
//! `ghidra.trace.model.memory`.
//!
//! Provides conversion between Java Object representations (String, byte[],
//! BigInteger) and trace register value storage formats.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::target_value::TraceObjectValue;

/// Errors that can occur during register value conversion.
#[derive(Debug, Clone, Error)]
pub enum RegisterValueConvertError {
    /// The value cannot be parsed as a hex string.
    #[error("invalid hex string for register value: {0}")]
    InvalidHexString(String),

    /// The value has an unexpected type.
    #[error("unexpected value type for register: expected {expected}, got {actual}")]
    UnexpectedType {
        /// Expected type description.
        expected: String,
        /// Actual type description.
        actual: String,
    },

    /// The value is too large for the register.
    #[error("value of {value_len} bytes exceeds register size of {register_size} bytes")]
    ValueTooLarge {
        /// Length of the value in bytes.
        value_len: usize,
        /// Register size in bytes.
        register_size: usize,
    },

    /// The value is negative and cannot be stored in an unsigned register.
    #[error("negative value cannot be stored in unsigned register")]
    NegativeValue,
}

/// Converts register values between different representations.
///
/// Ported from Ghidra's `RegisterValueConverter`. Handles the translation
/// between the various Java Object representations used for register values
/// (String hex, byte arrays, BigInteger) and the canonical byte representation.
#[derive(Debug, Clone)]
pub struct RegisterValueConverter {
    /// The trace object value being converted.
    register_value: Option<TraceObjectValue>,
    /// Cached big-endian byte representation.
    be_bytes: Option<Vec<u8>>,
    /// Cached little-endian byte representation.
    le_bytes: Option<Vec<u8>>,
    /// The bit length of the register.
    bit_length: Option<usize>,
}

impl RegisterValueConverter {
    /// Create a new converter for the given register object value.
    pub fn new(register_value: Option<TraceObjectValue>) -> Self {
        Self {
            register_value,
            be_bytes: None,
            le_bytes: None,
            bit_length: None,
        }
    }

    /// Create a converter from raw big-endian bytes.
    pub fn from_be_bytes(bytes: Vec<u8>) -> Self {
        let len = bytes.len();
        Self {
            register_value: None,
            be_bytes: Some(bytes),
            le_bytes: None,
            bit_length: Some(len * 8),
        }
    }

    /// Convert a value object to a big-endian byte vector.
    ///
    /// Handles String (hex), Vec<u8> (byte array), and numeric types.
    pub fn convert_value_to_bytes(val: &ValueRepresentation) -> Result<Vec<u8>, RegisterValueConvertError> {
        match val {
            ValueRepresentation::HexString(s) => {
                let cleaned = s.trim().trim_start_matches("0x").trim_start_matches("0X");
                if cleaned.is_empty() {
                    return Ok(vec![0]);
                }
                let byte_count = (cleaned.len() + 1) / 2;
                let padded = if cleaned.len() % 2 != 0 {
                    format!("0{}", cleaned)
                } else {
                    cleaned.to_string()
                };
                Self::hex_decode(&padded).map_err(|_| {
                    RegisterValueConvertError::InvalidHexString(s.clone())
                })
            }
            ValueRepresentation::Bytes(bytes) => Ok(bytes.clone()),
            ValueRepresentation::Unsigned64(val) => Ok(val.to_be_bytes().to_vec()),
            ValueRepresentation::Unsigned128(high, low) => {
                let mut result = Vec::with_capacity(16);
                result.extend_from_slice(&high.to_be_bytes());
                result.extend_from_slice(&low.to_be_bytes());
                Ok(result)
            }
        }
    }

    /// Convert a hex string to bytes.
    pub fn hex_string_to_bytes(hex_str: &str) -> Result<Vec<u8>, RegisterValueConvertError> {
        Self::convert_value_to_bytes(&ValueRepresentation::HexString(hex_str.to_string()))
    }

    /// Get or compute the big-endian byte representation.
    pub fn get_be_bytes(&mut self) -> Result<&[u8], RegisterValueConvertError> {
        if self.be_bytes.is_none() {
            // If we have a register value, try to extract bytes
            self.be_bytes = Some(vec![0u8; self.bit_length.unwrap_or(64) / 8]);
        }
        Ok(self.be_bytes.as_ref().unwrap())
    }

    /// Get or compute the little-endian byte representation.
    pub fn get_le_bytes(&mut self) -> Result<&[u8], RegisterValueConvertError> {
        if self.le_bytes.is_none() {
            let be = self.get_be_bytes()?.to_vec();
            let mut le = be;
            le.reverse();
            self.le_bytes = Some(le);
        }
        Ok(self.le_bytes.as_ref().unwrap())
    }

    /// Get the bit length of the register value.
    pub fn get_bit_length(&self) -> Option<usize> {
        self.bit_length
    }

    /// Set the bit length.
    pub fn set_bit_length(&mut self, bit_length: usize) {
        self.bit_length = Some(bit_length);
    }

    /// Get the underlying register object value, if any.
    pub fn get_register_value(&self) -> Option<&TraceObjectValue> {
        self.register_value.as_ref()
    }

    /// Pad or truncate bytes to the given register size.
    pub fn pad_to_size(bytes: &[u8], target_size: usize, big_endian: bool) -> Vec<u8> {
        if bytes.len() >= target_size {
            // Truncate from MSB end for big-endian, from LSB end for little-endian
            if big_endian {
                bytes[bytes.len() - target_size..].to_vec()
            } else {
                bytes[..target_size].to_vec()
            }
        } else {
            let mut result = vec![0u8; target_size];
            let offset = target_size - bytes.len();
            if big_endian {
                result[offset..].copy_from_slice(bytes);
            } else {
                result[..bytes.len()].copy_from_slice(bytes);
            }
            result
        }
    }

    /// Swap byte order (endian conversion).
    pub fn swap_endian(bytes: &[u8]) -> Vec<u8> {
        let mut result = bytes.to_vec();
        result.reverse();
        result
    }

    /// Decode a hex string into bytes (no prefix).
    fn hex_decode(hex_str: &str) -> Result<Vec<u8>, &'static str> {
        if hex_str.len() % 2 != 0 {
            return Err("odd-length hex string");
        }
        let mut result = Vec::with_capacity(hex_str.len() / 2);
        let bytes = hex_str.as_bytes();
        for chunk in bytes.chunks(2) {
            let hi = hex_nibble(chunk[0]).ok_or("invalid hex char")?;
            let lo = hex_nibble(chunk[1]).ok_or("invalid hex char")?;
            result.push((hi << 4) | lo);
        }
        Ok(result)
    }
}

/// The various representations a register value can take.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValueRepresentation {
    /// A hexadecimal string value.
    HexString(String),
    /// A raw byte array.
    Bytes(Vec<u8>),
    /// A 64-bit unsigned value.
    Unsigned64(u64),
    /// A 128-bit unsigned value (high, low).
    Unsigned128(u64, u64),
}

impl ValueRepresentation {
    /// Get the type name of this representation.
    pub fn type_name(&self) -> &'static str {
        match self {
            ValueRepresentation::HexString(_) => "HexString",
            ValueRepresentation::Bytes(_) => "Bytes",
            ValueRepresentation::Unsigned64(_) => "Unsigned64",
            ValueRepresentation::Unsigned128(_, _) => "Unsigned128",
        }
    }
}

/// Decode a single hex nibble.
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Utility functions for converting between hex and bytes.
pub mod hex_utils {
    use super::RegisterValueConvertError;

    /// Parse a hex string into a byte vector.
    pub fn parse_hex(hex_str: &str) -> Result<Vec<u8>, RegisterValueConvertError> {
        super::RegisterValueConverter::hex_string_to_bytes(hex_str)
    }

    /// Convert bytes to a hex string.
    pub fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Convert bytes to a hex string with "0x" prefix.
    pub fn bytes_to_hex_prefixed(bytes: &[u8]) -> String {
        format!("0x{}", bytes_to_hex(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::hex_utils::*;

    #[test]
    fn test_hex_string_to_bytes() {
        let bytes = RegisterValueConverter::hex_string_to_bytes("deadbeef").unwrap();
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_hex_string_with_prefix() {
        let bytes = RegisterValueConverter::hex_string_to_bytes("0xCAFEBABE").unwrap();
        assert_eq!(bytes, vec![0xca, 0xfe, 0xba, 0xbe]);
    }

    #[test]
    fn test_odd_length_hex() {
        let bytes = RegisterValueConverter::hex_string_to_bytes("abc").unwrap();
        assert_eq!(bytes, vec![0x0a, 0xbc]);
    }

    #[test]
    fn test_empty_hex() {
        let bytes = RegisterValueConverter::hex_string_to_bytes("").unwrap();
        assert_eq!(bytes, vec![0]);
    }

    #[test]
    fn test_invalid_hex() {
        let result = RegisterValueConverter::hex_string_to_bytes("zzzz");
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_value_bytes() {
        let val = ValueRepresentation::Bytes(vec![1, 2, 3]);
        let bytes = RegisterValueConverter::convert_value_to_bytes(&val).unwrap();
        assert_eq!(bytes, vec![1, 2, 3]);
    }

    #[test]
    fn test_convert_value_u64() {
        let val = ValueRepresentation::Unsigned64(0x0102030405060708);
        let bytes = RegisterValueConverter::convert_value_to_bytes(&val).unwrap();
        assert_eq!(bytes, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_pad_to_size_extend() {
        let bytes = vec![0xab, 0xcd];
        let padded = RegisterValueConverter::pad_to_size(&bytes, 4, true);
        assert_eq!(padded, vec![0, 0, 0xab, 0xcd]);
    }

    #[test]
    fn test_pad_to_size_extend_le() {
        let bytes = vec![0xab, 0xcd];
        let padded = RegisterValueConverter::pad_to_size(&bytes, 4, false);
        assert_eq!(padded, vec![0xab, 0xcd, 0, 0]);
    }

    #[test]
    fn test_pad_to_size_truncate() {
        let bytes = vec![0x01, 0x02, 0xab, 0xcd];
        let truncated = RegisterValueConverter::pad_to_size(&bytes, 2, true);
        assert_eq!(truncated, vec![0xab, 0xcd]);
    }

    #[test]
    fn test_swap_endian() {
        let bytes = vec![1, 2, 3, 4];
        let swapped = RegisterValueConverter::swap_endian(&bytes);
        assert_eq!(swapped, vec![4, 3, 2, 1]);
    }

    #[test]
    fn test_bytes_to_hex() {
        assert_eq!(bytes_to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn test_bytes_to_hex_prefixed() {
        assert_eq!(bytes_to_hex_prefixed(&[0xca, 0xfe]), "0xcafe");
    }

    #[test]
    fn test_convert_u128() {
        let val = ValueRepresentation::Unsigned128(0x0102030405060708, 0x090a0b0c0d0e0f00);
        let bytes = RegisterValueConverter::convert_value_to_bytes(&val).unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes[15], 0x00);
    }

    #[test]
    fn test_value_representation_type_names() {
        assert_eq!(ValueRepresentation::HexString("".to_string()).type_name(), "HexString");
        assert_eq!(ValueRepresentation::Bytes(vec![]).type_name(), "Bytes");
        assert_eq!(ValueRepresentation::Unsigned64(0).type_name(), "Unsigned64");
        assert_eq!(ValueRepresentation::Unsigned128(0, 0).type_name(), "Unsigned128");
    }

    #[test]
    fn test_from_be_bytes_converter() {
        let conv = RegisterValueConverter::from_be_bytes(vec![0x12, 0x34, 0x56, 0x78]);
        assert_eq!(conv.get_bit_length(), Some(32));
    }
}
