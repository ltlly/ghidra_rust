//! Byte-based constant propagation domain.
//!
//! Ported from `PcodeByteBasedConstantPropagation.java` in the Lisa extension.
//!
//! Tracks individual bytes of values as either known constants or top
//! (unknown). This allows partial constant knowledge: for example,
//! knowing the low byte of a register even when the full value is
//! unknown.

use crate::lisa::lattice::LatticeElement;
use std::fmt;

/// A single byte value in the constant propagation domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ByteValue {
    /// The byte value is known.
    Constant(u8),
    /// The byte value is unknown.
    Top,
    /// The byte is unreachable.
    Bottom,
}

/// Byte-based constant propagation element.
///
/// Tracks each byte of a value independently as either a known constant
/// or unknown. Supports up to 8 bytes (64-bit values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PcodeByteBasedConstantPropagation {
    /// Individual byte values, from least significant to most significant.
    /// Index 0 = least significant byte.
    bytes: [ByteValue; 8],
    /// Number of valid bytes (1-8).
    num_bytes: u8,
}

impl PcodeByteBasedConstantPropagation {
    /// Create a fully known constant value.
    pub fn from_u64(value: u64, num_bytes: u8) -> Self {
        let mut bytes = [ByteValue::Top; 8];
        let n = num_bytes.min(8) as usize;
        for i in 0..n {
            bytes[i] = ByteValue::Constant(((value >> (i * 8)) & 0xFF) as u8);
        }
        Self {
            bytes,
            num_bytes: num_bytes.min(8),
        }
    }

    /// Create a fully unknown (top) value of the given size.
    pub fn top_of_size(num_bytes: u8) -> Self {
        Self {
            bytes: [ByteValue::Top; 8],
            num_bytes: num_bytes.min(8),
        }
    }

    /// Get the byte value at the given index.
    pub fn byte(&self, index: usize) -> &ByteValue {
        &self.bytes[index]
    }

    /// Set the byte value at the given index.
    pub fn set_byte(&mut self, index: usize, value: ByteValue) {
        if index < 8 {
            self.bytes[index] = value;
        }
    }

    /// Get the number of bytes.
    pub fn num_bytes(&self) -> u8 {
        self.num_bytes
    }

    /// Try to reconstruct the full concrete value.
    ///
    /// Returns `Some(value)` if all bytes are known constants,
    /// `None` otherwise.
    pub fn to_u64(&self) -> Option<u64> {
        let mut result = 0u64;
        for i in 0..self.num_bytes as usize {
            match self.bytes[i] {
                ByteValue::Constant(b) => result |= (b as u64) << (i * 8),
                _ => return None,
            }
        }
        Some(result)
    }

    /// Check if all bytes are known constants.
    pub fn is_fully_constant(&self) -> bool {
        (0..self.num_bytes as usize).all(|i| matches!(self.bytes[i], ByteValue::Constant(_)))
    }

    /// Check if all bytes are unknown.
    pub fn is_fully_unknown(&self) -> bool {
        (0..self.num_bytes as usize).all(|i| self.bytes[i] == ByteValue::Top)
    }
}

impl LatticeElement for PcodeByteBasedConstantPropagation {
    fn top() -> Self {
        Self {
            bytes: [ByteValue::Top; 8],
            num_bytes: 8,
        }
    }

    fn bottom() -> Self {
        Self {
            bytes: [ByteValue::Bottom; 8],
            num_bytes: 8,
        }
    }

    fn is_top(&self) -> bool {
        (0..self.num_bytes as usize).all(|i| self.bytes[i] == ByteValue::Top)
    }

    fn is_bottom(&self) -> bool {
        (0..self.num_bytes as usize).all(|i| self.bytes[i] == ByteValue::Bottom)
    }

    fn lub(&self, other: &Self) -> Result<Self, String> {
        let n = self.num_bytes.max(other.num_bytes);
        let mut result = [ByteValue::Top; 8];
        for i in 0..n as usize {
            result[i] = match (&self.bytes[i], &other.bytes[i]) {
                (ByteValue::Bottom, x) | (x, ByteValue::Bottom) => *x,
                (ByteValue::Constant(a), ByteValue::Constant(b)) if a == b => {
                    ByteValue::Constant(*a)
                }
                _ => ByteValue::Top,
            };
        }
        Ok(Self {
            bytes: result,
            num_bytes: n,
        })
    }

    fn widening(&self, other: &Self) -> Result<Self, String> {
        self.lub(other)
    }

    fn less_or_equal(&self, other: &Self) -> bool {
        let n = self.num_bytes.max(other.num_bytes);
        for i in 0..n as usize {
            match (&self.bytes[i], &other.bytes[i]) {
                (_, ByteValue::Top) => {}
                (ByteValue::Bottom, _) => {}
                (ByteValue::Constant(a), ByteValue::Constant(b)) if a == b => {}
                _ => return false,
            }
        }
        true
    }
}

impl fmt::Display for PcodeByteBasedConstantPropagation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(val) = self.to_u64() {
            return write!(f, "0x{val:x}");
        }
        write!(f, "[")?;
        for i in 0..self.num_bytes as usize {
            if i > 0 {
                write!(f, ",")?;
            }
            match self.bytes[i] {
                ByteValue::Constant(b) => write!(f, "{b:02x}")?,
                ByteValue::Top => write!(f, "??")?,
                ByteValue::Bottom => write!(f, "\u{22a5}")?,
            }
        }
        write!(f, "]")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_u64() {
        let cp = PcodeByteBasedConstantPropagation::from_u64(0x04030201, 4);
        assert!(cp.is_fully_constant());
        assert_eq!(cp.to_u64(), Some(0x04030201));
        assert_eq!(*cp.byte(0), ByteValue::Constant(1));
        assert_eq!(*cp.byte(3), ByteValue::Constant(4));
    }

    #[test]
    fn test_top_of_size() {
        let cp = PcodeByteBasedConstantPropagation::top_of_size(4);
        assert!(cp.is_fully_unknown());
        assert!(cp.to_u64().is_none());
    }

    #[test]
    fn test_lub_same() {
        let a = PcodeByteBasedConstantPropagation::from_u64(42, 1);
        let b = PcodeByteBasedConstantPropagation::from_u64(42, 1);
        let lub = a.lub(&b).unwrap();
        assert!(lub.is_fully_constant());
        assert_eq!(lub.to_u64(), Some(42));
    }

    #[test]
    fn test_lub_different() {
        let a = PcodeByteBasedConstantPropagation::from_u64(1, 1);
        let b = PcodeByteBasedConstantPropagation::from_u64(2, 1);
        let lub = a.lub(&b).unwrap();
        assert!(!lub.is_fully_constant());
    }

    #[test]
    fn test_lub_with_top() {
        let a = PcodeByteBasedConstantPropagation::from_u64(42, 1);
        let b = PcodeByteBasedConstantPropagation::top_of_size(1);
        let lub = a.lub(&b).unwrap();
        assert!(lub.is_fully_unknown());
    }

    #[test]
    fn test_display_fully_known() {
        let cp = PcodeByteBasedConstantPropagation::from_u64(255, 1);
        assert_eq!(cp.to_string(), "0xff");
    }

    #[test]
    fn test_display_partial() {
        let mut cp = PcodeByteBasedConstantPropagation::top_of_size(2);
        cp.set_byte(0, ByteValue::Constant(0xAB));
        assert_eq!(cp.to_string(), "[ab,??]");
    }

    #[test]
    fn test_less_or_equal() {
        let a = PcodeByteBasedConstantPropagation::from_u64(5, 1);
        let b = PcodeByteBasedConstantPropagation::from_u64(5, 1);
        let top = PcodeByteBasedConstantPropagation::top_of_size(1);
        assert!(a.less_or_equal(&b));
        assert!(a.less_or_equal(&top));
        assert!(!top.less_or_equal(&a));
    }
}
