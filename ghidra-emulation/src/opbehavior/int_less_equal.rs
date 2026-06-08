//! Integer unsigned less-than-or-equal comparison.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorIntLessEqual`.

use num_bigint::BigInt;

use super::binary::BinaryOpBehavior;
use crate::opbehavior::utils::calc_mask;

/// Integer unsigned less-than-or-equal: `out = (in1 <= in2) ? 1 : 0`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntLessEqual;

impl BinaryOpBehavior for OpBehaviorIntLessEqual {
    fn evaluate_binary_u64(&self, _sizeout: usize, sizein: usize, in1: u64, in2: u64) -> u64 {
        if sizein == 0 {
            return 0;
        }
        let mask = calc_mask(sizein);
        let masked_in1 = in1 & mask;
        let masked_in2 = in2 & mask;
        if masked_in1 == masked_in2 {
            return 1;
        }
        if sizein < 8 {
            return if masked_in1 < masked_in2 { 1 } else { 0 };
        }
        let sign_mask = 0x80u64 << ((sizein - 1) * 8);
        let bit1 = masked_in1 & sign_mask;
        let bit2 = masked_in2 & sign_mask;
        if bit1 != bit2 {
            return if bit1 != 0 { 0 } else { 1 };
        }
        if masked_in1 < masked_in2 { 1 } else { 0 }
    }

    fn evaluate_binary_bigint(
        &self,
        _sizeout: usize,
        _sizein: usize,
        in1: &BigInt,
        in2: &BigInt,
    ) -> BigInt {
        if in1 <= in2 {
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
    fn test_int_less_equal_true() {
        let op = OpBehaviorIntLessEqual;
        assert_eq!(op.evaluate_binary_u64(8, 8, 5, 10), 1);
        assert_eq!(op.evaluate_binary_u64(8, 8, 5, 5), 1);
    }

    #[test]
    fn test_int_less_equal_false() {
        let op = OpBehaviorIntLessEqual;
        assert_eq!(op.evaluate_binary_u64(8, 8, 10, 5), 0);
    }
}
