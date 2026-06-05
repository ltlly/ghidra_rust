//! DebuggerPcodeUtils - utility functions for pcode debugger integration.
//!
//! Ported from Ghidra's `DebuggerPcodeUtils` in `ghidra.pcode.exec`.
//!
//! Provides utility functions used during pcode-based debugging,
//! including address translation, register mapping, and context
//! management helpers.

use serde::{Deserialize, Serialize};

/// A utility struct for pcode debugger operations.
///
/// Ported from Ghidra's `DebuggerPcodeUtils`. Provides static utility
/// methods for common debugger-pcode integration tasks.
#[derive(Debug)]
pub struct DebuggerPcodeUtils;

impl DebuggerPcodeUtils {
    /// Compute the effective address for a pcode load/store operation.
    ///
    /// Takes a space ID and offset and produces the canonical address.
    /// For register space, the offset encodes the register's position.
    pub fn compute_effective_address(space_id: u32, offset: u64) -> EffectiveAddress {
        EffectiveAddress { space_id, offset }
    }

    /// Check if a space ID refers to register space.
    pub fn is_register_space(space_id: u32) -> bool {
        space_id == 0xFFFFFFFE || space_id == 0xFFFFFFFF
    }

    /// Check if a space ID refers to memory (RAM) space.
    pub fn is_memory_space(space_id: u32) -> bool {
        space_id < 0xFFFFFF00
    }

    /// Compute the byte offset for a register within its container.
    pub fn register_byte_offset(register_offset: u64, register_size: usize) -> (u64, usize) {
        let byte_offset = register_offset / 8;
        let bit_offset = register_offset % 8;
        let byte_size = ((register_size as u64 + 7) / 8) as usize;
        (byte_offset, byte_size)
    }

    /// Build a context register value from individual context fields.
    pub fn build_context_value(fields: &[ContextField]) -> Vec<u8> {
        let max_bit = fields.iter().map(|f| f.bit_offset + f.bit_length).max().unwrap_or(0);
        let byte_len = ((max_bit + 7) / 8) as usize;
        let mut result = vec![0u8; byte_len];

        for field in fields {
            let mut remaining = field.value;
            for i in 0..field.bit_length {
                let bit_pos = field.bit_offset + i;
                let byte_idx = (bit_pos / 8) as usize;
                let bit_idx = bit_pos % 8;
                if byte_idx < result.len() && (remaining & 1) != 0 {
                    result[byte_idx] |= 1 << bit_idx;
                }
                remaining >>= 1;
            }
        }

        result
    }

    /// Extract a context field value from a context register byte array.
    pub fn extract_context_field(context: &[u8], bit_offset: u32, bit_length: u32) -> u64 {
        let mut result: u64 = 0;
        for i in 0..bit_length {
            let bit_pos = bit_offset + i;
            let byte_idx = (bit_pos / 8) as usize;
            let bit_idx = bit_pos % 8;
            if byte_idx < context.len() {
                let bit = (context[byte_idx] >> bit_idx) & 1;
                result |= (bit as u64) << i;
            }
        }
        result
    }

    /// Validate that a pcode address is well-formed.
    pub fn validate_address(addr: &EffectiveAddress) -> Result<(), PcodeAddressError> {
        if addr.space_id == 0 {
            return Err(PcodeAddressError::InvalidSpaceId);
        }
        Ok(())
    }
}

/// An effective address in the pcode address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EffectiveAddress {
    /// The address space identifier.
    pub space_id: u32,
    /// The offset within the space.
    pub offset: u64,
}

impl EffectiveAddress {
    /// Create a new effective address.
    pub fn new(space_id: u32, offset: u64) -> Self {
        Self { space_id, offset }
    }

    /// Check if this is a register-space address.
    pub fn is_register(&self) -> bool {
        DebuggerPcodeUtils::is_register_space(self.space_id)
    }

    /// Check if this is a memory-space address.
    pub fn is_memory(&self) -> bool {
        DebuggerPcodeUtils::is_memory_space(self.space_id)
    }

    /// Add an offset to this address.
    pub fn offset_by(&self, delta: i64) -> Self {
        Self {
            space_id: self.space_id,
            offset: self.offset.wrapping_add(delta as u64),
        }
    }
}

/// A context field definition for pcode context registers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextField {
    /// The field name.
    pub name: String,
    /// The bit offset within the context register.
    pub bit_offset: u32,
    /// The bit length of the field.
    pub bit_length: u32,
    /// The field value.
    pub value: u64,
}

impl ContextField {
    /// Create a new context field.
    pub fn new(
        name: impl Into<String>,
        bit_offset: u32,
        bit_length: u32,
        value: u64,
    ) -> Self {
        Self {
            name: name.into(),
            bit_offset,
            bit_length,
            value,
        }
    }

    /// Get the mask for this field.
    pub fn mask(&self) -> u64 {
        if self.bit_length >= 64 {
            u64::MAX
        } else {
            (1u64 << self.bit_length) - 1
        }
    }

    /// Check if the value fits within the field's bit length.
    pub fn value_fits(&self) -> bool {
        self.value <= self.mask()
    }
}

/// Errors that can occur during pcode address operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PcodeAddressError {
    /// The space ID is invalid.
    #[error("invalid address space ID")]
    InvalidSpaceId,

    /// The offset is out of range for the space.
    #[error("address offset out of range: {0}")]
    OffsetOutOfRange(u64),

    /// The register size is invalid.
    #[error("invalid register size: {0}")]
    InvalidRegisterSize(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_effective_address() {
        let addr = EffectiveAddress::new(1, 0x1000);
        assert!(addr.is_memory());
        assert!(!addr.is_register());
    }

    #[test]
    fn test_register_space_address() {
        let addr = EffectiveAddress::new(0xFFFFFFFE, 0);
        assert!(addr.is_register());
        assert!(!addr.is_memory());
    }

    #[test]
    fn test_address_offset_by() {
        let addr = EffectiveAddress::new(1, 0x1000);
        let offset = addr.offset_by(0x10);
        assert_eq!(offset.offset, 0x1010);
    }

    #[test]
    fn test_compute_effective_address() {
        let addr = DebuggerPcodeUtils::compute_effective_address(1, 0x400000);
        assert_eq!(addr.space_id, 1);
        assert_eq!(addr.offset, 0x400000);
    }

    #[test]
    fn test_is_register_space() {
        assert!(DebuggerPcodeUtils::is_register_space(0xFFFFFFFE));
        assert!(DebuggerPcodeUtils::is_register_space(0xFFFFFFFF));
        assert!(!DebuggerPcodeUtils::is_register_space(0));
        assert!(!DebuggerPcodeUtils::is_register_space(1));
    }

    #[test]
    fn test_is_memory_space() {
        assert!(DebuggerPcodeUtils::is_memory_space(0));
        assert!(DebuggerPcodeUtils::is_memory_space(1));
        assert!(DebuggerPcodeUtils::is_memory_space(0xFFFFF000));
        assert!(!DebuggerPcodeUtils::is_memory_space(0xFFFFFFFE));
    }

    #[test]
    fn test_register_byte_offset() {
        let (offset, size) = DebuggerPcodeUtils::register_byte_offset(0, 32);
        assert_eq!(offset, 0);
        assert_eq!(size, 4);

        let (offset, size) = DebuggerPcodeUtils::register_byte_offset(8, 8);
        assert_eq!(offset, 1);
        assert_eq!(size, 1);
    }

    #[test]
    fn test_context_field() {
        let field = ContextField::new("TMode", 0, 1, 1);
        assert_eq!(field.mask(), 1);
        assert!(field.value_fits());

        let field2 = ContextField::new("Mode", 1, 2, 3);
        assert_eq!(field2.mask(), 3);
        assert!(field2.value_fits());
    }

    #[test]
    fn test_build_context_value_single_field() {
        let fields = vec![ContextField::new("TMode", 5, 1, 1)];
        let ctx = DebuggerPcodeUtils::build_context_value(&fields);
        assert_eq!(ctx.len(), 1);
        assert_eq!(ctx[0], 0x20); // bit 5 set
    }

    #[test]
    fn test_build_context_value_multiple_fields() {
        let fields = vec![
            ContextField::new("TMode", 5, 1, 1),
            ContextField::new("Mode", 0, 2, 3),
        ];
        let ctx = DebuggerPcodeUtils::build_context_value(&fields);
        assert_eq!(ctx[0], 0x23); // bits 0,1 (value 3) + bit 5
    }

    #[test]
    fn test_extract_context_field() {
        let context = vec![0x23u8]; // 0b00100011
        let tmode = DebuggerPcodeUtils::extract_context_field(&context, 5, 1);
        assert_eq!(tmode, 1);
        let mode = DebuggerPcodeUtils::extract_context_field(&context, 0, 2);
        assert_eq!(mode, 3);
    }

    #[test]
    fn test_extract_context_field_multibyte() {
        let context = vec![0x00, 0x01]; // bit 8 is set
        let val = DebuggerPcodeUtils::extract_context_field(&context, 8, 1);
        assert_eq!(val, 1);
    }

    #[test]
    fn test_validate_address() {
        let valid = EffectiveAddress::new(1, 0x1000);
        assert!(DebuggerPcodeUtils::validate_address(&valid).is_ok());

        let invalid = EffectiveAddress::new(0, 0x1000);
        assert!(DebuggerPcodeUtils::validate_address(&invalid).is_err());
    }

    #[test]
    fn test_context_field_value_too_large() {
        let field = ContextField::new("test", 0, 2, 10);
        assert!(!field.value_fits());
    }
}
