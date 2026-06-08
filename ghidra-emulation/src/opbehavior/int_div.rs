//! Integer unsigned division operation.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorIntDiv`.

use num_bigint::BigInt;
use num_traits::Zero;

use super::binary::BinaryOpBehavior;
use crate::opbehavior::utils::calc_mask;

/// Integer unsigned division: `out = in1 / in2`.
///
/// Returns 0 if divisor is 0.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntDiv;

impl BinaryOpBehavior for OpBehaviorIntDiv {
    fn evaluate_binary_u64(&self, sizeout: usize, sizein: usize, in1: u64, in2: u64) -> u64 {
        if sizein == 0 || in2 == 0 {
            return 0;
        }
        if in1 == in2 {
            return 1;
        }
        if sizein == 8 {
            // For 64-bit, use unsigned division
            let result = (in1 as u128) / (in2 as u128);
            return (result as u64) & calc_mask(sizeout);
        }
        (in1 / in2) & calc_mask(sizeout)
    }

    fn evaluate_binary_bigint(
        &self,
        _sizeout: usize,
        sizein: usize,
        in1: &BigInt,
        in2: &BigInt,
    ) -> BigInt {
        if sizein == 0 || in2.is_zero() {
            return BigInt::from(0);
        }
        in1 / in2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_int_div_basic() {
        let op = OpBehaviorIntDiv;
        assert_eq!(op.evaluate_binary_u64(8, 8, 100, 10), 10);
    }

    #[test]
    fn test_int_div_by_zero() {
        let op = OpBehaviorIntDiv;
        assert_eq!(op.evaluate_binary_u64(8, 8, 100, 0), 0);
    }

    #[test]
    fn test_int_div_equal() {
        let op = OpBehaviorIntDiv;
        assert_eq!(op.evaluate_binary_u64(8, 8, 42, 42), 1);
    }
}
