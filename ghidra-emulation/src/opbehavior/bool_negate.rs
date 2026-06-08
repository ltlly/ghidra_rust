//! Boolean NOT operation.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorBoolNegate`.

use num_bigint::BigInt;

use super::unary::UnaryOpBehavior;

/// Boolean NOT: `out = in1 ^ 1` (flip the low bit).
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorBoolNegate;

impl UnaryOpBehavior for OpBehaviorBoolNegate {
    fn evaluate_unary_u64(&self, _sizeout: usize, _sizein: usize, in1: u64) -> u64 {
        in1 ^ 1
    }

    fn evaluate_unary_bigint(&self, _sizeout: usize, _sizein: usize, in1: &BigInt) -> BigInt {
        in1 ^ BigInt::from(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bool_negate_true() {
        let op = OpBehaviorBoolNegate;
        assert_eq!(op.evaluate_unary_u64(1, 1, 1), 0);
    }

    #[test]
    fn test_bool_negate_false() {
        let op = OpBehaviorBoolNegate;
        assert_eq!(op.evaluate_unary_u64(1, 1, 0), 1);
    }
}
