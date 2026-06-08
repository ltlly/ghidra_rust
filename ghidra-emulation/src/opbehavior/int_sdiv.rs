//! Integer signed division operation.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorIntSdiv`.

use num_bigint::BigInt;
use num_traits::Zero;

use super::binary::BinaryOpBehavior;
use crate::opbehavior::utils::{zzz_sign_extend, zzz_zero_extend, convert_to_signed_value};

/// Integer signed division: `out = in1 / in2` (signed).
///
/// Throws on divide by zero.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntSdiv;

impl BinaryOpBehavior for OpBehaviorIntSdiv {
    fn evaluate_binary_u64(&self, sizeout: usize, sizein: usize, in1: u64, in2: u64) -> u64 {
        if in2 == 0 {
            panic!("Divide by 0");
        }
        let sign_bit = (sizein * 8) - 1;
        let num = zzz_sign_extend(in1, sign_bit);
        let denom = zzz_sign_extend(in2, sign_bit);
        let sres = (num as i64) / (denom as i64);
        let out_sign_bit = (sizeout * 8) - 1;
        zzz_zero_extend(sres as u64, out_sign_bit)
    }

    fn evaluate_binary_bigint(
        &self,
        _sizeout: usize,
        sizein: usize,
        in1: &BigInt,
        in2: &BigInt,
    ) -> BigInt {
        if in2.is_zero() {
            panic!("Divide by 0");
        }
        let signed_in1 = convert_to_signed_value(in1, sizein);
        let signed_in2 = convert_to_signed_value(in2, sizein);
        signed_in1 / signed_in2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_int_sdiv_basic() {
        let op = OpBehaviorIntSdiv;
        // 10 / 2 = 5
        assert_eq!(op.evaluate_binary_u64(8, 8, 10, 2), 5);
    }

    #[test]
    fn test_int_sdiv_negative() {
        let op = OpBehaviorIntSdiv;
        // -10 / 3 = -3 (signed), represented as unsigned
        let in1 = -10i64 as u64;
        let result = op.evaluate_binary_u64(8, 8, in1, 3);
        assert_eq!(result as i64, -3);
    }

    #[test]
    #[should_panic(expected = "Divide by 0")]
    fn test_int_sdiv_by_zero() {
        let op = OpBehaviorIntSdiv;
        op.evaluate_binary_u64(8, 8, 10, 0);
    }
}
