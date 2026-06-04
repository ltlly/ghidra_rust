//! P-code statement types.
//!
//! Ported from the `ghidra.lisa.pcode.statements` package in the
//! Lisa extension.
//!
//! Statements are the p-code operation types that represent executable
//! units: binary ops, unary ops, ternary ops, and no-ops.

/// A binary p-code operator (e.g., INT_ADD, INT_MULT).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcodeBinaryOperator {
    /// The opcode name.
    pub opcode: String,
    /// The address of this statement.
    pub address: u64,
    /// Left input varnode offset.
    pub left_offset: u64,
    /// Right input varnode offset.
    pub right_offset: u64,
    /// Output varnode offset.
    pub output_offset: u64,
    /// Size in bytes.
    pub size: u32,
}

impl PcodeBinaryOperator {
    pub fn new(
        opcode: impl Into<String>,
        address: u64,
        left_offset: u64,
        right_offset: u64,
        output_offset: u64,
        size: u32,
    ) -> Self {
        Self {
            opcode: opcode.into(),
            address,
            left_offset,
            right_offset,
            output_offset,
            size,
        }
    }
}

/// A unary p-code operator (e.g., INT_NEGATE, INT_ZEXT).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcodeUnaryOperator {
    /// The opcode name.
    pub opcode: String,
    /// The address of this statement.
    pub address: u64,
    /// Input varnode offset.
    pub input_offset: u64,
    /// Output varnode offset.
    pub output_offset: u64,
    /// Size in bytes.
    pub size: u32,
}

impl PcodeUnaryOperator {
    pub fn new(
        opcode: impl Into<String>,
        address: u64,
        input_offset: u64,
        output_offset: u64,
        size: u32,
    ) -> Self {
        Self {
            opcode: opcode.into(),
            address,
            input_offset,
            output_offset,
            size,
        }
    }
}

/// A ternary p-code operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcodeTernaryOperator {
    /// The opcode name.
    pub opcode: String,
    /// The address of this statement.
    pub address: u64,
    /// Input offsets.
    pub input_offsets: [u64; 3],
    /// Output varnode offset.
    pub output_offset: u64,
    /// Size in bytes.
    pub size: u32,
}

impl PcodeTernaryOperator {
    pub fn new(
        opcode: impl Into<String>,
        address: u64,
        input_offsets: [u64; 3],
        output_offset: u64,
        size: u32,
    ) -> Self {
        Self {
            opcode: opcode.into(),
            address,
            input_offsets,
            output_offset,
            size,
        }
    }
}

/// A no-op p-code statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcodeNop {
    /// The address of this statement.
    pub address: u64,
}

impl PcodeNop {
    pub fn new(address: u64) -> Self {
        Self { address }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_operator() {
        let op = PcodeBinaryOperator::new("INT_ADD", 0x1000, 0, 8, 16, 8);
        assert_eq!(op.address, 0x1000);
        assert_eq!(op.size, 8);
    }

    #[test]
    fn test_unary_operator() {
        let op = PcodeUnaryOperator::new("INT_NEGATE", 0x1000, 0, 8, 8);
        assert_eq!(op.opcode, "INT_NEGATE");
    }

    #[test]
    fn test_ternary_operator() {
        let op = PcodeTernaryOperator::new("STORE", 0x1000, [0, 8, 16], 0, 4);
        assert_eq!(op.input_offsets, [0, 8, 16]);
    }

    #[test]
    fn test_nop() {
        let nop = PcodeNop::new(0x1000);
        assert_eq!(nop.address, 0x1000);
    }
}
