//! Integer signed remainder operation.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorIntSrem`.

use num_bigint::BigInt;
use num_traits::Zero;

use super::binary::BinaryOpBehavior;
use crate::opbehavior::utils::{zzz_sign_extend, zzz_zero_extend, convert_to_signed_value};

/// Integer signed remainder: `out = in1 % in2` (signed).
///
/// Throws on remainder by zero.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntSrem;

impl BinaryOpBehavior for OpBehaviorIntSrem {
    fn evaluate_binary_u64(&self, sizeout: usize, sizein: usize, in1: u64, in2: u64) -> u64 {
        if in2 == 0 {
            panic!("Remainder by 0");
        }
        let sign_bit = (sizein * 8) - 1;
        let val = zzz_sign_extend(in1, sign_bit);
        let mod_val = zzz_sign_extend(in2, sign_bit);
        let sres = (val as i64) % (mod_val as i64);
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
            panic!("Remainder by 0");
        }
        let signed_in1 = convert_to_signed_value(in1, sizein);
        let signed_in2 = convert_to_signed_value(in2, sizein);
        signed_in1 % signed_in2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_int_srem_basic() {
        let op = OpBehaviorIntSrem;
        assert_eq!(op.evaluate_binary_u64(8, 8, 17, 5), 2);
    }

    #[test]
    fn test_int_srem_negative() {
        let op = OpBehaviorIntSrem;
        // -17 % 5 = -2 (signed)
        let in1 = (-17i64 as u64) & 0xFFFFFFFFFFFFFFFF;
        let result = op.evaluate_binary_u64(8, 8, in1, 5);
        assert_eq!(result as i64, -2);
    }
}
