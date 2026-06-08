//! Integer multiplication operation.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorIntMult`.

use num_bigint::BigInt;

use super::binary::BinaryOpBehavior;
use crate::opbehavior::utils::calc_mask;

/// Integer multiplication: `out = in1 * in2`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntMult;

impl BinaryOpBehavior for OpBehaviorIntMult {
    fn evaluate_binary_u64(&self, sizeout: usize, _sizein: usize, in1: u64, in2: u64) -> u64 {
        let mask = calc_mask(sizeout);
        (in1.wrapping_mul(in2)) & mask
    }

    fn evaluate_binary_bigint(
        &self,
        _sizeout: usize,
        _sizein: usize,
        in1: &BigInt,
        in2: &BigInt,
    ) -> BigInt {
        in1 * in2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_int_mult_basic() {
        let op = OpBehaviorIntMult;
        assert_eq!(op.evaluate_binary_u64(8, 8, 6, 7), 42);
    }

    #[test]
    fn test_int_mult_overflow() {
        let op = OpBehaviorIntMult;
        let result = op.evaluate_binary_u64(4, 4, 0x10000, 0x10000);
        assert_eq!(result, 0); // Overflows 4 bytes
    }
}
