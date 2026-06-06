//! TraceMemoryStatePcodeArithmetic ported from
//! TraceMemoryStatePcodeArithmetic.java.
//!
//! Pcode arithmetic that operates on trace memory state (known/unknown bytes).

/// Represents a byte that may be known or unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateByte {
    /// Known byte value.
    Known(u8),
    /// Unknown/uninitialized byte.
    Unknown,
}

/// Arithmetic operations on trace memory state.
#[derive(Debug)]
pub struct TraceMemoryStatePcodeArithmetic {
    /// Size of the state space in bytes.
    pub size: usize,
}

impl TraceMemoryStatePcodeArithmetic {
    /// Create arithmetic for the given size.
    pub fn new(size: usize) -> Self {
        Self { size }
    }

    /// Check if all bytes in a slice are known.
    pub fn all_known(bytes: &[StateByte]) -> bool {
        bytes.iter().all(|b| matches!(b, StateByte::Known(_)))
    }

    /// Check if any byte in a slice is unknown.
    pub fn any_unknown(bytes: &[StateByte]) -> bool {
        bytes.iter().any(|b| matches!(b, StateByte::Unknown))
    }

    /// Convert known bytes to a plain byte vec, returning None if any unknown.
    pub fn to_bytes(bytes: &[StateByte]) -> Option<Vec<u8>> {
        let mut result = Vec::with_capacity(bytes.len());
        for b in bytes {
            match b {
                StateByte::Known(v) => result.push(*v),
                StateByte::Unknown => return None,
            }
        }
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_known() {
        let bytes = vec![StateByte::Known(1), StateByte::Known(2)];
        assert!(TraceMemoryStatePcodeArithmetic::all_known(&bytes));
    }

    #[test]
    fn test_any_unknown() {
        let bytes = vec![StateByte::Known(1), StateByte::Unknown];
        assert!(TraceMemoryStatePcodeArithmetic::any_unknown(&bytes));
    }

    #[test]
    fn test_to_bytes_known() {
        let bytes = vec![StateByte::Known(0xAB), StateByte::Known(0xCD)];
        assert_eq!(TraceMemoryStatePcodeArithmetic::to_bytes(&bytes), Some(vec![0xAB, 0xCD]));
    }

    #[test]
    fn test_to_bytes_unknown() {
        let bytes = vec![StateByte::Known(1), StateByte::Unknown];
        assert_eq!(TraceMemoryStatePcodeArithmetic::to_bytes(&bytes), None);
    }
}
