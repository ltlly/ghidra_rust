//! Integer addition operation.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorIntAdd`.

use num_bigint::BigInt;

use super::binary::BinaryOpBehavior;
use crate::opbehavior::utils::calc_mask;

/// Integer addition: `out = in1 + in2`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntAdd;

impl BinaryOpBehavior for OpBehaviorIntAdd {
    fn evaluate_binary_u64(&self, sizeout: usize, _sizein: usize, in1: u64, in2: u64) -> u64 {
        let mask = calc_mask(sizeout);
        (in1.wrapping_add(in2)) & mask
    }

    fn evaluate_binary_bigint(
        &self,
        _sizeout: usize,
        _sizein: usize,
        in1: &BigInt,
        in2: &BigInt,
    ) -> BigInt {
        in1 + in2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_int_add_basic() {
        let op = OpBehaviorIntAdd;
        assert_eq!(op.evaluate_binary_u64(8, 8, 10, 20), 30);
    }

    #[test]
    fn test_int_add_overflow() {
        let op = OpBehaviorIntAdd;
        // 4-byte overflow
        let result = op.evaluate_binary_u64(4, 4, 0xFFFFFFFF, 1);
        assert_eq!(result, 0);
    }

    #[test]
    fn test_int_add_bigint() {
        let op = OpBehaviorIntAdd;
        let a = BigInt::from(100);
        let b = BigInt::from(200);
        assert_eq!(op.evaluate_binary_bigint(8, 8, &a, &b), BigInt::from(300));
    }
}
