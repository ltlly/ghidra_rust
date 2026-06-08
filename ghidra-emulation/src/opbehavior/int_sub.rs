//! Integer subtraction operation.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorIntSub`.

use num_bigint::BigInt;

use super::binary::BinaryOpBehavior;
use crate::opbehavior::utils::calc_mask;

/// Integer subtraction: `out = in1 - in2`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntSub;

impl BinaryOpBehavior for OpBehaviorIntSub {
    fn evaluate_binary_u64(&self, sizeout: usize, _sizein: usize, in1: u64, in2: u64) -> u64 {
        let mask = calc_mask(sizeout);
        (in1.wrapping_sub(in2)) & mask
    }

    fn evaluate_binary_bigint(
        &self,
        _sizeout: usize,
        _sizein: usize,
        in1: &BigInt,
        in2: &BigInt,
    ) -> BigInt {
        in1 - in2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_int_sub_basic() {
        let op = OpBehaviorIntSub;
        assert_eq!(op.evaluate_binary_u64(8, 8, 30, 10), 20);
    }

    #[test]
    fn test_int_sub_underflow() {
        let op = OpBehaviorIntSub;
        let result = op.evaluate_binary_u64(4, 4, 0, 1);
        assert_eq!(result, 0xFFFFFFFF);
    }
}
