//! Integer two's complement (negate) operation.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorInt2Comp`.

use num_bigint::BigInt;

use super::unary::UnaryOpBehavior;
use crate::opbehavior::utils::uintb_negate;

/// Integer two's complement: `out = -in1`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorInt2Comp;

impl UnaryOpBehavior for OpBehaviorInt2Comp {
    fn evaluate_unary_u64(&self, _sizeout: usize, sizein: usize, in1: u64) -> u64 {
        uintb_negate(in1.wrapping_sub(1), sizein)
    }

    fn evaluate_unary_bigint(&self, _sizeout: usize, _sizein: usize, in1: &BigInt) -> BigInt {
        -in1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_int_2comp_basic() {
        let op = OpBehaviorInt2Comp;
        // Two's complement of 5 = -5 = 0xFB (1 byte)
        assert_eq!(op.evaluate_unary_u64(1, 1, 5), 0xFB);
    }

    #[test]
    fn test_int_2comp_zero() {
        let op = OpBehaviorInt2Comp;
        assert_eq!(op.evaluate_unary_u64(1, 1, 0), 0);
    }
}
