//! RegisterValue types for register context.
//!
//! Ported from Ghidra's `RegisterValueException` and `RegisterSizeConverter`
//! in `ghidra.trace.model.memory`.

use serde::{Deserialize, Serialize};

/// An error that occurs when a register value is invalid.
///
/// Ported from Ghidra's `RegisterValueException`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterValueException {
    /// The register name.
    pub register: String,
    /// The error message.
    pub message: String,
    /// The invalid value bytes, if available.
    pub value_bytes: Option<Vec<u8>>,
}

impl RegisterValueException {
    /// Create a new register value error.
    pub fn new(register: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            register: register.into(),
            message: message.into(),
            value_bytes: None,
        }
    }

    /// Create with the invalid value bytes.
    pub fn with_value(mut self, bytes: Vec<u8>) -> Self {
        self.value_bytes = Some(bytes);
        self
    }
}

impl std::fmt::Display for RegisterValueException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RegisterValue error for '{}': {}", self.register, self.message)
    }
}

impl std::error::Error for RegisterValueException {}

/// Converts register values between different representations.
///
/// Ported from Ghidra's `RegisterSizeConverter`.
#[derive(Debug, Clone)]
pub struct RegisterSizeConverter {
    /// Source register size in bytes.
    pub source_size: usize,
    /// Target register size in bytes.
    pub target_size: usize,
    /// Whether the source is big-endian.
    pub source_big_endian: bool,
    /// Whether the target is big-endian.
    pub target_big_endian: bool,
}

impl RegisterSizeConverter {
    /// Create a new converter.
    pub fn new(source_size: usize, target_size: usize) -> Self {
        Self {
            source_size,
            target_size,
            source_big_endian: false,
            target_big_endian: false,
        }
    }

    /// Set source as big-endian.
    pub fn with_source_big_endian(mut self) -> Self {
        self.source_big_endian = true;
        self
    }

    /// Set target as big-endian.
    pub fn with_target_big_endian(mut self) -> Self {
        self.target_big_endian = true;
        self
    }

    /// Convert a value from source to target size/endianness.
    pub fn convert(&self, value: &[u8]) -> Result<Vec<u8>, RegisterValueException> {
        if value.len() != self.source_size {
            return Err(RegisterValueException::new(
                "source",
                format!(
                    "Expected {} bytes, got {}",
                    self.source_size,
                    value.len()
                ),
            ));
        }

        let mut result = vec![0u8; self.target_size];

        if self.target_size >= self.source_size {
            // Zero-extend or sign-extend
            if self.source_big_endian == self.target_big_endian {
                // Same endianness - copy to the "low" end, zero-fill the rest
                if self.source_big_endian {
                    // BE: MSB at index 0, zeros go at the end
                    result[..self.source_size].copy_from_slice(value);
                } else {
                    // LE: LSB at index 0, zeros go at the end
                    result[..self.source_size].copy_from_slice(value);
                }
            } else {
                // Different endianness - reverse and copy
                let offset = self.target_size - self.source_size;
                for (i, &b) in value.iter().rev().enumerate() {
                    if self.target_big_endian {
                        result[i + offset] = b;
                    } else {
                        result[self.target_size - 1 - i - offset] = b;
                    }
                }
            }
        } else {
            // Truncate - keep the "low" (least significant) bytes
            if self.source_big_endian == self.target_big_endian {
                if self.source_big_endian {
                    // BE: keep high bytes (first N)
                    result.copy_from_slice(&value[..self.target_size]);
                } else {
                    // LE: keep low bytes (first N)
                    result.copy_from_slice(&value[..self.target_size]);
                }
            } else {
                for (i, &b) in value.iter().rev().enumerate().take(self.target_size) {
                    result[self.target_size - 1 - i] = b;
                }
            }
        }

        Ok(result)
    }

    /// Convert a u64 value (always little-endian in Rust).
    pub fn convert_u64(&self, value: u64) -> Result<u64, RegisterValueException> {
        let src_bytes = if self.source_big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        let src_slice = &src_bytes[8 - self.source_size..];
        let result_bytes = self.convert(src_slice)?;

        let mut buf = [0u8; 8];
        let offset = 8 - self.target_size;
        if self.target_big_endian {
            buf[..self.target_size].copy_from_slice(&result_bytes);
            Ok(u64::from_be_bytes(buf))
        } else {
            buf[offset..].copy_from_slice(&result_bytes);
            Ok(u64::from_le_bytes(buf))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_value_error() {
        let err = RegisterValueException::new("RAX", "size mismatch");
        assert_eq!(err.register, "RAX");
        assert!(err.to_string().contains("size mismatch"));
    }

    #[test]
    fn test_register_value_error_with_value() {
        let err = RegisterValueException::new("RAX", "invalid")
            .with_value(vec![0xFF, 0xFF]);
        assert!(err.value_bytes.is_some());
    }

    #[test]
    fn test_converter_same_size() {
        let converter = RegisterSizeConverter::new(4, 4);
        let input = vec![0x78, 0x56, 0x34, 0x12];
        let result = converter.convert(&input).unwrap();
        assert_eq!(result, input);
    }

    #[test]
    fn test_converter_zero_extend() {
        let converter = RegisterSizeConverter::new(4, 8);
        let input = vec![0x78, 0x56, 0x34, 0x12];
        let result = converter.convert(&input).unwrap();
        assert_eq!(result, vec![0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0]);
    }

    #[test]
    fn test_converter_truncate() {
        let converter = RegisterSizeConverter::new(8, 4);
        let input = vec![0x78, 0x56, 0x34, 0x12, 0xAA, 0xBB, 0xCC, 0xDD];
        let result = converter.convert(&input).unwrap();
        assert_eq!(result, vec![0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_converter_wrong_size() {
        let converter = RegisterSizeConverter::new(4, 8);
        let input = vec![1, 2, 3]; // wrong size
        assert!(converter.convert(&input).is_err());
    }

    #[test]
    fn test_converter_u64() {
        let converter = RegisterSizeConverter::new(8, 8);
        let result = converter.convert_u64(0x1234567890ABCDEF).unwrap();
        assert_eq!(result, 0x1234567890ABCDEF);
    }

    #[test]
    fn test_register_value_error_display() {
        let err = RegisterValueException::new("RIP", "out of range");
        let s = err.to_string();
        assert!(s.contains("RIP"));
        assert!(s.contains("out of range"));
    }

    #[test]
    fn test_error_is_std_error() {
        let err = RegisterValueException::new("test", "msg");
        let _: &dyn std::error::Error = &err;
    }
}
