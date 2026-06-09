//! Integer addition operation implementing the unified OpBehavior trait.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorIntAdd`.
//!
//! This provides an implementation of the unified [`OpBehavior`] trait for
//! integer addition, complementing the existing [`super::int_add::OpBehaviorIntAdd`]
//! which implements [`super::binary::BinaryOpBehavior`].

use num_bigint::BigInt;

use super::op_behavior::{OpBehavior, OpBehaviorKind};
use crate::opbehavior::utils::calc_mask;

/// Integer addition: `out = in1 + in2`.
///
/// Implements the unified [`OpBehavior`] trait.
#[derive(Debug, Clone, Copy)]
pub struct UnifiedOpBehaviorIntAdd;

impl OpBehavior for UnifiedOpBehaviorIntAdd {
    fn opcode(&self) -> u32 {
        // PcodeOp.INT_ADD = 4 in Ghidra's numbering
        4
    }

    fn kind(&self) -> OpBehaviorKind {
        OpBehaviorKind::Binary
    }

    fn evaluate_binary_u64(&self, sizeout: usize, _sizein: usize, in1: u64, in2: u64) -> Option<u64> {
        let mask = calc_mask(sizeout);
        Some((in1.wrapping_add(in2)) & mask)
    }

    fn evaluate_binary_bigint(
        &self,
        _sizeout: usize,
        _sizein: usize,
        in1: &BigInt,
        in2: &BigInt,
    ) -> Option<BigInt> {
        Some(in1 + in2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_int_add_basic() {
        let op = UnifiedOpBehaviorIntAdd;
        assert_eq!(op.kind(), OpBehaviorKind::Binary);
        assert_eq!(op.evaluate_binary_u64(8, 8, 10, 20), Some(30));
    }

    #[test]
    fn test_unified_int_add_overflow() {
        let op = UnifiedOpBehaviorIntAdd;
        let result = op.evaluate_binary_u64(4, 4, 0xFFFFFFFF, 1);
        assert_eq!(result, Some(0));
    }

    #[test]
    fn test_unified_int_add_bigint() {
        let op = UnifiedOpBehaviorIntAdd;
        let a = BigInt::from(100);
        let b = BigInt::from(200);
        assert_eq!(op.evaluate_binary_bigint(8, 8, &a, &b), Some(BigInt::from(300)));
    }

    #[test]
    fn test_unified_int_add_unary_returns_none() {
        let op = UnifiedOpBehaviorIntAdd;
        assert_eq!(op.evaluate_unary_u64(8, 8, 42), None);
    }

    #[test]
    fn test_unified_int_add_opcode() {
        let op = UnifiedOpBehaviorIntAdd;
        assert_eq!(op.opcode(), 4);
    }
}
