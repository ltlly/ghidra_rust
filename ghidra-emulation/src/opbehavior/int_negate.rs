//! Integer bitwise NOT (negate) operation.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorIntNegate`.

use num_bigint::BigInt;

use super::unary::UnaryOpBehavior;
use crate::opbehavior::utils::uintb_negate;

/// Integer bitwise NOT: `out = ~in1`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntNegate;

impl UnaryOpBehavior for OpBehaviorIntNegate {
    fn evaluate_unary_u64(&self, _sizeout: usize, sizein: usize, in1: u64) -> u64 {
        uintb_negate(in1, sizein)
    }

    fn evaluate_unary_bigint(&self, _sizeout: usize, _sizein: usize, in1: &BigInt) -> BigInt {
        !in1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_int_negate_basic() {
        let op = OpBehaviorIntNegate;
        assert_eq!(op.evaluate_unary_u64(1, 1, 0x00), 0xFF);
        assert_eq!(op.evaluate_unary_u64(1, 1, 0xFF), 0x00);
    }

    #[test]
    fn test_int_negate_4byte() {
        let op = OpBehaviorIntNegate;
        assert_eq!(op.evaluate_unary_u64(4, 4, 0x00000000), 0xFFFFFFFF);
    }
}
