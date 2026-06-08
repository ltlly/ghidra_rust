//! Integer left shift operation.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorIntLeft`.

use num_bigint::BigInt;

use super::binary::BinaryOpBehavior;
use crate::opbehavior::utils::calc_mask;

/// Integer left shift: `out = in1 << in2`.
///
/// Returns 0 if shift amount >= sizein*8.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntLeft;

impl BinaryOpBehavior for OpBehaviorIntLeft {
    fn evaluate_binary_u64(&self, sizeout: usize, sizein: usize, in1: u64, in2: u64) -> u64 {
        if (in2 as i64) < 0 || in2 >= (sizein as u64 * 8) {
            return 0;
        }
        (in1 << in2) & calc_mask(sizeout)
    }

    fn evaluate_binary_bigint(
        &self,
        _sizeout: usize,
        sizein: usize,
        in1: &BigInt,
        in2: &BigInt,
    ) -> BigInt {
        let max_shift = BigInt::from(sizein * 8);
        if in2 >= &max_shift {
            return BigInt::from(0);
        }
        let shift = in2.to_u32_digits().1.first().copied().unwrap_or(0) as usize;
        in1 << shift
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_int_left_basic() {
        let op = OpBehaviorIntLeft;
        assert_eq!(op.evaluate_binary_u64(8, 8, 1, 4), 16);
    }

    #[test]
    fn test_int_left_overflow() {
        let op = OpBehaviorIntLeft;
        // Shift amount >= 64 for 8-byte input
        assert_eq!(op.evaluate_binary_u64(8, 8, 1, 64), 0);
    }
}
