//! P-code expression types.
//!
//! Ported from the `ghidra.lisa.pcode.expressions` package in the
//! Lisa extension.
//!
//! These represent the typed expression nodes in the p-code IR as
//! understood by the LISA analysis framework.

/// A p-code binary expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcodeBinaryExpression {
    /// The opcode name (e.g., "INT_ADD", "FLOAT_MULT").
    pub opcode: String,
    /// Index of the left operand in the expression table.
    pub left_idx: usize,
    /// Index of the right operand in the expression table.
    pub right_idx: usize,
    /// Output size in bytes.
    pub size: u32,
}

impl PcodeBinaryExpression {
    pub fn new(opcode: impl Into<String>, left: usize, right: usize, size: u32) -> Self {
        Self {
            opcode: opcode.into(),
            left_idx: left,
            right_idx: right,
            size,
        }
    }
}

/// A p-code unary expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcodeUnaryExpression {
    /// The opcode name (e.g., "INT_NEGATE", "INT_ZEXT").
    pub opcode: String,
    /// Index of the input operand.
    pub input_idx: usize,
    /// Output size in bytes.
    pub size: u32,
}

impl PcodeUnaryExpression {
    pub fn new(opcode: impl Into<String>, input: usize, size: u32) -> Self {
        Self {
            opcode: opcode.into(),
            input_idx: input,
            size,
        }
    }
}

/// A p-code ternary expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcodeTernaryExpression {
    /// The opcode name.
    pub opcode: String,
    /// Index of the first input.
    pub input0_idx: usize,
    /// Index of the second input.
    pub input1_idx: usize,
    /// Index of the third input.
    pub input2_idx: usize,
    /// Output size in bytes.
    pub size: u32,
}

impl PcodeTernaryExpression {
    pub fn new(
        opcode: impl Into<String>,
        i0: usize,
        i1: usize,
        i2: usize,
        size: u32,
    ) -> Self {
        Self {
            opcode: opcode.into(),
            input0_idx: i0,
            input1_idx: i1,
            input2_idx: i2,
            size,
        }
    }
}

/// A p-code call expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcodeCallExpression {
    /// The call target address.
    pub target: u64,
    /// Indices of the argument expressions.
    pub argument_indices: Vec<usize>,
    /// Output size in bytes (0 if void).
    pub output_size: u32,
}

impl PcodeCallExpression {
    pub fn new(target: u64, argument_indices: Vec<usize>, output_size: u32) -> Self {
        Self {
            target,
            argument_indices,
            output_size,
        }
    }
}

/// A p-code varargs expression (used for variadic functions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcodeVarargsExpression {
    /// Indices of the argument expressions.
    pub argument_indices: Vec<usize>,
}

impl PcodeVarargsExpression {
    pub fn new(argument_indices: Vec<usize>) -> Self {
        Self { argument_indices }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_expression() {
        let expr = PcodeBinaryExpression::new("INT_ADD", 0, 1, 8);
        assert_eq!(expr.opcode, "INT_ADD");
        assert_eq!(expr.left_idx, 0);
        assert_eq!(expr.right_idx, 1);
    }

    #[test]
    fn test_unary_expression() {
        let expr = PcodeUnaryExpression::new("INT_ZEXT", 0, 8);
        assert_eq!(expr.input_idx, 0);
    }

    #[test]
    fn test_ternary_expression() {
        let expr = PcodeTernaryExpression::new("PIECE", 0, 1, 2, 16);
        assert_eq!(expr.input0_idx, 0);
        assert_eq!(expr.size, 16);
    }

    #[test]
    fn test_call_expression() {
        let expr = PcodeCallExpression::new(0x4000, vec![0, 1], 8);
        assert_eq!(expr.target, 0x4000);
        assert_eq!(expr.argument_indices.len(), 2);
    }

    #[test]
    fn test_varargs_expression() {
        let expr = PcodeVarargsExpression::new(vec![0, 1, 2]);
        assert_eq!(expr.argument_indices.len(), 3);
    }
}
