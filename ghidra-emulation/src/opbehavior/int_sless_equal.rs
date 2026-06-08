//! Integer signed less-than-or-equal comparison.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorIntSlessEqual`.

use num_bigint::BigInt;

use super::binary::BinaryOpBehavior;
use crate::opbehavior::utils::convert_to_signed_value;

/// Integer signed less-than-or-equal: `out = (in1 <=s in2) ? 1 : 0`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntSlessEqual;

impl BinaryOpBehavior for OpBehaviorIntSlessEqual {
    fn evaluate_binary_u64(&self, _sizeout: usize, sizein: usize, in1: u64, in2: u64) -> u64 {
        if sizein == 0 {
            return 0;
        }
        let sign_mask = 0x80u64 << ((sizein - 1) * 8);
        let bit1 = in1 & sign_mask;
        let bit2 = in2 & sign_mask;
        if bit1 != bit2 {
            return if bit1 != 0 { 1 } else { 0 };
        }
        if in1 <= in2 { 1 } else { 0 }
    }

    fn evaluate_binary_bigint(
        &self,
        _sizeout: usize,
        sizein: usize,
        in1: &BigInt,
        in2: &BigInt,
    ) -> BigInt {
        if sizein == 0 {
            return BigInt::from(0);
        }
        let signed_in1 = convert_to_signed_value(in1, sizein);
        let signed_in2 = convert_to_signed_value(in2, sizein);
        if signed_in1 <= signed_in2 {
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
    fn test_int_sless_equal_true() {
        let op = OpBehaviorIntSlessEqual;
        assert_eq!(op.evaluate_binary_u64(8, 8, 5, 10), 1);
        assert_eq!(op.evaluate_binary_u64(8, 8, 5, 5), 1);
    }

    #[test]
    fn test_int_sless_equal_negative() {
        let op = OpBehaviorIntSlessEqual;
        let in1 = 0xFFFFFFFFFFFFFFFFu64; // -1 signed
        assert_eq!(op.evaluate_binary_u64(8, 8, in1, 1), 1);
    }
}
