//! SLEIGH context symbol: context variable definitions.
//!
//! A [`ContextSymbol`] represents a context variable defined in a `.slaspec`
//! file. Context variables are special fields that carry state across
//! instruction boundaries during disassembly. They are typically stored
//! in a context register and can affect how subsequent instructions are
//! decoded.
//!
//! For example, on ARM, the `TMode` context bit indicates whether the
//! processor is in Thumb or ARM mode:
//!
//! ```text
//! define context TMode
//!     bit = (0,0)
//!     flow = true;
//! ```
//!
//! # Key Types
//! - [`ContextSymbol`] -- a context variable bound to a bit range in a varnode

use serde::{Deserialize, Serialize};
use std::fmt;

use super::sleigh_symbol::{Location, SymbolType};

// ---------------------------------------------------------------------------
// ContextSymbol
// ---------------------------------------------------------------------------

/// A context variable symbol.
///
/// `ContextSymbol` extends `ValueSymbol` (which extends `FamilySymbol` ->
/// `TripleSymbol` -> `SleighSymbol`). It represents a context variable that
/// is stored in a bit range within a context register varnode.
///
/// Each context symbol has:
/// - A pattern expression that defines how the context variable is extracted
/// - A reference to the varnode that stores the context bits
/// - A low and high bit position within that varnode
/// - A flow flag indicating whether the variable propagates along control flow
///
/// # Example
///
/// For ARM TMode:
/// - `varnode_name = "context_reg"`
/// - `low = 0`, `high = 0` (single bit)
/// - `flow = true` (propagates along control flow)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextSymbol {
    /// Symbol name (e.g., "TMode")
    pub name: String,
    /// Symbol id
    pub id: usize,
    /// Scope id
    pub scope_id: usize,
    /// Source location
    pub location: Location,
    /// Name of the varnode that stores the context bits
    pub varnode_name: String,
    /// Id of the varnode that stores the context bits
    pub varnode_id: usize,
    /// Low bit position within the varnode (inclusive)
    pub low: i32,
    /// High bit position within the varnode (inclusive)
    pub high: i32,
    /// Whether this context variable propagates along control flow
    pub flow: bool,
    /// The pattern expression id for extracting the value
    pub pattern_value_id: Option<usize>,
}

impl ContextSymbol {
    /// Create a new context symbol.
    pub fn new(
        name: impl Into<String>,
        location: Location,
        varnode_name: impl Into<String>,
        varnode_id: usize,
        low: i32,
        high: i32,
        flow: bool,
    ) -> Self {
        Self {
            name: name.into(),
            id: 0,
            scope_id: 0,
            location,
            varnode_name: varnode_name.into(),
            varnode_id,
            low,
            high,
            flow,
            pattern_value_id: None,
        }
    }

    /// Returns the symbol type.
    pub fn symbol_type(&self) -> SymbolType {
        SymbolType::Context
    }

    /// Returns the number of bits this context variable spans.
    pub fn bit_width(&self) -> i32 {
        self.high - self.low + 1
    }

    /// Returns `true` if this is a single-bit context variable.
    pub fn is_single_bit(&self) -> bool {
        self.low == self.high
    }

    /// Returns `true` if this context variable propagates along control flow.
    pub fn is_flow(&self) -> bool {
        self.flow
    }

    /// Extract this context variable's value from a context bit vector.
    ///
    /// Bits are numbered in big-endian order within each byte: bit 0 is the
    /// MSB (bit 7) of the first byte, bit 1 is bit 6, etc.
    pub fn extract_value(&self, context_bits: &[u8]) -> u64 {
        let mut value: u64 = 0;
        let width = self.bit_width() as usize;

        for i in 0..width {
            let bit_pos = self.low as usize + i;
            let byte_idx = bit_pos / 8;
            let bit_off = 7 - (bit_pos % 8);

            if byte_idx < context_bits.len() {
                let bit = (context_bits[byte_idx] >> bit_off) & 1;
                value |= (bit as u64) << (width - 1 - i);
            }
        }

        value
    }

    /// Encode a value into a context bit vector at this variable's position.
    ///
    /// Bits are numbered in big-endian order within each byte: bit 0 is the
    /// MSB (bit 7) of the first byte, bit 1 is bit 6, etc.
    pub fn encode_value(&self, context_bits: &mut Vec<u8>, value: u64) {
        let width = self.bit_width() as usize;
        let required_bytes = (self.high as usize + 8) / 8;

        if context_bits.len() < required_bytes {
            context_bits.resize(required_bytes, 0);
        }

        for i in 0..width {
            let bit_pos = self.low as usize + i;
            let byte_idx = bit_pos / 8;
            let bit_off = 7 - (bit_pos % 8);

            if byte_idx < context_bits.len() {
                if (value >> (width - 1 - i)) & 1 != 0 {
                    context_bits[byte_idx] |= 1 << bit_off;
                } else {
                    context_bits[byte_idx] &= !(1 << bit_off);
                }
            }
        }
    }
}

impl fmt::Display for ContextSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: context[{}:{}] in {} (flow={})",
            self.name, self.low, self.high, self.varnode_name, self.flow
        )
    }
}

impl PartialEq for ContextSymbol {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for ContextSymbol {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_symbol_new() {
        let sym = ContextSymbol::new(
            "TMode",
            Location::unknown(),
            "context_reg",
            0,
            0,
            0,
            true,
        );
        assert_eq!(sym.name, "TMode");
        assert_eq!(sym.varnode_name, "context_reg");
        assert_eq!(sym.low, 0);
        assert_eq!(sym.high, 0);
        assert!(sym.flow);
    }

    #[test]
    fn test_context_symbol_type() {
        let sym = ContextSymbol::new("test", Location::unknown(), "ctx", 0, 0, 7, false);
        assert_eq!(sym.symbol_type(), SymbolType::Context);
    }

    #[test]
    fn test_context_symbol_bit_width() {
        let single = ContextSymbol::new("bit", Location::unknown(), "ctx", 0, 0, 0, false);
        assert_eq!(single.bit_width(), 1);
        assert!(single.is_single_bit());

        let multi = ContextSymbol::new("field", Location::unknown(), "ctx", 0, 0, 7, false);
        assert_eq!(multi.bit_width(), 8);
        assert!(!multi.is_single_bit());
    }

    #[test]
    fn test_context_symbol_extract_single_bit() {
        let sym = ContextSymbol::new("TMode", Location::unknown(), "ctx", 0, 0, 0, true);

        // Bit 0 is the MSB (bit 7) of byte 0
        // 0x80 = 0b1000_0000, bit 7 = 1
        let bits = vec![0x80];
        assert_eq!(sym.extract_value(&bits), 1);

        // 0x00 = 0b0000_0000, bit 7 = 0
        let bits = vec![0x00];
        assert_eq!(sym.extract_value(&bits), 0);
    }

    #[test]
    fn test_context_symbol_extract_multi_bit() {
        // Bits 4-7 in SLEIGH bit numbering
        // Bit 4 = byte 0 bit 3, bit 5 = byte 0 bit 2, bit 6 = byte 0 bit 1, bit 7 = byte 0 bit 0
        // So bits 4-7 correspond to the low nibble (bits 0-3) of byte 0
        let sym = ContextSymbol::new("Mode", Location::unknown(), "ctx", 0, 4, 7, false);

        // Low nibble = 0xA (0b1010): byte = 0x0A
        let bits = vec![0x0A];
        assert_eq!(sym.extract_value(&bits), 0xA);

        // Low nibble = 0xF: byte = 0x0F
        let bits = vec![0x0F];
        assert_eq!(sym.extract_value(&bits), 0xF);
    }

    #[test]
    fn test_context_symbol_encode_value() {
        let sym = ContextSymbol::new("Mode", Location::unknown(), "ctx", 0, 4, 7, false);
        let mut bits = vec![0x00u8; 1];

        sym.encode_value(&mut bits, 0xA);
        // Bits 4-7 should contain 0xA (0b1010)
        // Bit 4 (off=3) = 1, bit 5 (off=2) = 0, bit 6 (off=1) = 1, bit 7 (off=0) = 0
        // Result: 0b0000_1010 = 0x0A
        assert_eq!(bits[0], 0x0A);

        let extracted = sym.extract_value(&bits);
        assert_eq!(extracted, 0xA);
    }

    #[test]
    fn test_context_symbol_encode_roundtrip() {
        let sym = ContextSymbol::new("Field", Location::unknown(), "ctx", 0, 2, 5, false);
        let mut bits = vec![0x00u8; 1];

        for value in 0..16u64 {
            bits[0] = 0x00;
            sym.encode_value(&mut bits, value);
            let extracted = sym.extract_value(&bits);
            assert_eq!(extracted, value, "Roundtrip failed for value {}", value);
        }
    }

    #[test]
    fn test_context_symbol_flow() {
        let flow = ContextSymbol::new("TMode", Location::unknown(), "ctx", 0, 0, 0, true);
        assert!(flow.is_flow());

        let no_flow = ContextSymbol::new("Mode", Location::unknown(), "ctx", 0, 0, 1, false);
        assert!(!no_flow.is_flow());
    }

    #[test]
    fn test_context_symbol_display() {
        let sym = ContextSymbol::new("TMode", Location::unknown(), "ctx_reg", 0, 0, 0, true);
        let s = format!("{}", sym);
        assert!(s.contains("TMode"));
        assert!(s.contains("0:0"));
        assert!(s.contains("ctx_reg"));
        assert!(s.contains("true"));
    }

    #[test]
    fn test_context_symbol_equality() {
        let a = ContextSymbol::new("TMode", Location::unknown(), "ctx", 0, 0, 0, true);
        let b = ContextSymbol::new("TMode", Location::unknown(), "ctx", 0, 1, 1, false);
        let c = ContextSymbol::new("Mode", Location::unknown(), "ctx", 0, 0, 0, true);

        assert_eq!(a, b); // Same name
        assert_ne!(a, c); // Different name
    }
}
