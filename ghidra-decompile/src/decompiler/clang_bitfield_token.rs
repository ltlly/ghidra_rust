//! ClangBitFieldToken -- port of `ghidra.app.decompiler.ClangBitFieldToken`.
//!
//! Represents a bit-field access token in the decompiler's C output.

use serde::{Deserialize, Serialize};

/// A token representing a bit-field access in the decompiler output.
///
/// In C, bit-fields allow packing multiple small values into a single
/// larger integer.  This token type captures the bit-range information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClangBitFieldToken {
    /// The name of the field being accessed.
    pub field_name: String,
    /// The least-significant bit of the bit-field within its containing integer.
    pub lsb: u32,
    /// The most-significant bit of the bit-field within its containing integer.
    pub msb: u32,
    /// The data type name of the bit-field (e.g., "unsigned int").
    pub data_type: String,
    /// The size in bits of the underlying storage.
    pub storage_bits: u32,
    /// The address where the containing variable resides.
    pub address: u64,
    /// Syntax coloring type (matches Ghidra SyntaxType).
    pub syntax_type: SyntaxType,
}

/// Syntax coloring types for tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyntaxType {
    /// Default color.
    Default,
    /// Keyword (if, while, return, etc.).
    Keyword,
    /// Type name.
    Type,
    /// Function name.
    Function,
    /// Variable / field name.
    Variable,
    /// Comment text.
    Comment,
    /// Literal constant.
    Constant,
    /// Parameter name.
    Parameter,
    /// Global variable.
    Global,
    /// Error / unrecognized.
    Error,
    /// Special token.
    Special,
}

impl ClangBitFieldToken {
    /// Create a new bit-field token.
    pub fn new(
        field_name: impl Into<String>,
        lsb: u32,
        msb: u32,
        data_type: impl Into<String>,
        storage_bits: u32,
        address: u64,
    ) -> Self {
        Self {
            field_name: field_name.into(),
            lsb,
            msb,
            data_type: data_type.into(),
            storage_bits,
            address,
            syntax_type: SyntaxType::Variable,
        }
    }

    /// Number of bits in this bit-field.
    pub fn bit_size(&self) -> u32 {
        self.msb - self.lsb + 1
    }

    /// Mask covering the bits of this field within its storage.
    pub fn bit_mask(&self) -> u64 {
        let size = self.bit_size();
        if size >= 64 {
            u64::MAX
        } else {
            ((1u64 << size) - 1) << self.lsb
        }
    }

    /// Extract the field value from a raw storage value.
    pub fn extract_value(&self, storage_value: u64) -> u64 {
        (storage_value & self.bit_mask()) >> self.lsb
    }

    /// Insert a field value into a raw storage value.
    pub fn insert_value(&self, storage_value: u64, field_value: u64) -> u64 {
        let mask = self.bit_mask();
        (storage_value & !mask) | ((field_value << self.lsb) & mask)
    }
}

impl Default for SyntaxType {
    fn default() -> Self {
        Self::Default
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_field_creation() {
        let bf = ClangBitFieldToken::new("flags", 0, 7, "unsigned char", 8, 0x1000);
        assert_eq!(bf.field_name, "flags");
        assert_eq!(bf.lsb, 0);
        assert_eq!(bf.msb, 7);
        assert_eq!(bf.data_type, "unsigned char");
        assert_eq!(bf.storage_bits, 8);
    }

    #[test]
    fn test_bit_size() {
        let bf = ClangBitFieldToken::new("f", 4, 7, "int", 32, 0);
        assert_eq!(bf.bit_size(), 4);
    }

    #[test]
    fn test_bit_mask() {
        let bf = ClangBitFieldToken::new("f", 0, 3, "int", 32, 0);
        assert_eq!(bf.bit_mask(), 0xF);

        let bf2 = ClangBitFieldToken::new("f", 4, 7, "int", 32, 0);
        assert_eq!(bf2.bit_mask(), 0xF0);
    }

    #[test]
    fn test_extract_value() {
        let bf = ClangBitFieldToken::new("f", 4, 7, "int", 32, 0);
        assert_eq!(bf.extract_value(0xAB), 0xA);
        assert_eq!(bf.extract_value(0xCD), 0xC);
    }

    #[test]
    fn test_insert_value() {
        let bf = ClangBitFieldToken::new("f", 4, 7, "int", 32, 0);
        let result = bf.insert_value(0x00, 0xA);
        assert_eq!(result, 0xA0);
    }

    #[test]
    fn test_full_width_field() {
        let bf = ClangBitFieldToken::new("val", 0, 63, "unsigned long", 64, 0);
        assert_eq!(bf.bit_mask(), u64::MAX);
    }
}
