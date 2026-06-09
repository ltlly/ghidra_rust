//! Integer subtraction operation implementing the unified OpBehavior trait.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorIntSub`.
//!
//! This provides an implementation of the unified [`OpBehavior`] trait for
//! integer subtraction, complementing the existing [`super::int_sub::OpBehaviorIntSub`]
//! which implements [`super::binary::BinaryOpBehavior`].

use num_bigint::BigInt;

use super::op_behavior::{OpBehavior, OpBehaviorKind};
use crate::opbehavior::utils::calc_mask;

/// Integer subtraction: `out = in1 - in2`.
///
/// Implements the unified [`OpBehavior`] trait.
#[derive(Debug, Clone, Copy)]
pub struct UnifiedOpBehaviorIntSub;

impl OpBehavior for UnifiedOpBehaviorIntSub {
    fn opcode(&self) -> u32 {
        // PcodeOp.INT_SUB = 5 in Ghidra's numbering
        5
    }

    fn kind(&self) -> OpBehaviorKind {
        OpBehaviorKind::Binary
    }

    fn evaluate_binary_u64(&self, sizeout: usize, _sizein: usize, in1: u64, in2: u64) -> Option<u64> {
        let mask = calc_mask(sizeout);
        Some((in1.wrapping_sub(in2)) & mask)
    }

    fn evaluate_binary_bigint(
        &self,
        _sizeout: usize,
        _sizein: usize,
        in1: &BigInt,
        in2: &BigInt,
    ) -> Option<BigInt> {
        Some(in1 - in2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_int_sub_basic() {
        let op = UnifiedOpBehaviorIntSub;
        assert_eq!(op.kind(), OpBehaviorKind::Binary);
        assert_eq!(op.evaluate_binary_u64(8, 8, 30, 10), Some(20));
    }

    #[test]
    fn test_unified_int_sub_underflow() {
        let op = UnifiedOpBehaviorIntSub;
        let result = op.evaluate_binary_u64(4, 4, 0, 1);
        assert_eq!(result, Some(0xFFFFFFFF));
    }

    #[test]
    fn test_unified_int_sub_bigint() {
        let op = UnifiedOpBehaviorIntSub;
        let a = BigInt::from(300);
        let b = BigInt::from(100);
        assert_eq!(op.evaluate_binary_bigint(8, 8, &a, &b), Some(BigInt::from(200)));
    }

    #[test]
    fn test_unified_int_sub_unary_returns_none() {
        let op = UnifiedOpBehaviorIntSub;
        assert_eq!(op.evaluate_unary_u64(8, 8, 42), None);
    }

    #[test]
    fn test_unified_int_sub_opcode() {
        let op = UnifiedOpBehaviorIntSub;
        assert_eq!(op.opcode(), 5);
    }
}
