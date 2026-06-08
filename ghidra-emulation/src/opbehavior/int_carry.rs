//! Integer carry detection.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorIntCarry`.

use num_bigint::BigInt;

use super::binary::BinaryOpBehavior;
use crate::opbehavior::utils::calc_mask;

/// Integer carry: `out = (in1 + in2) carries ? 1 : 0`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntCarry;

impl BinaryOpBehavior for OpBehaviorIntCarry {
    fn evaluate_binary_u64(&self, _sizeout: usize, sizein: usize, in1: u64, in2: u64) -> u64 {
        let mask = calc_mask(sizein);
        let sum = (in1.wrapping_add(in2)) & mask;
        if (in1 as u128) > (sum as u128) { 1 } else { 0 }
    }

    fn evaluate_binary_bigint(
        &self,
        _sizeout: usize,
        sizein: usize,
        in1: &BigInt,
        in2: &BigInt,
    ) -> BigInt {
        use num_bigint::ToBigInt;
        let mask = calc_mask(sizein).to_bigint().unwrap();
        let sum = (in1 + in2) & &mask;
        if in1 > &sum {
            BigInt::from(1)
        } else {
            BigInt::from(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_int_carry_true() {
        let op = OpBehaviorIntCarry;
        // 0xFF + 1 = 0x100, carry for 1-byte
        assert_eq!(op.evaluate_binary_u64(1, 1, 0xFF, 1), 1);
    }

    #[test]
    fn test_int_carry_false() {
        let op = OpBehaviorIntCarry;
        assert_eq!(op.evaluate_binary_u64(8, 8, 10, 20), 0);
    }
}
