//! COPY operation.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorCopy`.

use num_bigint::BigInt;

use super::unary::UnaryOpBehavior;

/// COPY: `out = in1` (identity operation).
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorCopy;

impl UnaryOpBehavior for OpBehaviorCopy {
    fn evaluate_unary_u64(&self, _sizeout: usize, _sizein: usize, in1: u64) -> u64 {
        in1
    }

    fn evaluate_unary_bigint(&self, _sizeout: usize, _sizein: usize, in1: &BigInt) -> BigInt {
        in1.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_copy_basic() {
        let op = OpBehaviorCopy;
        assert_eq!(op.evaluate_unary_u64(8, 8, 42), 42);
    }
}
