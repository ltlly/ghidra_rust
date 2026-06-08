//! Integer arithmetic right shift operation.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorIntSright`.

use num_bigint::BigInt;

use super::binary::BinaryOpBehavior;
use crate::opbehavior::utils::{calc_mask, signbit_negative, convert_to_signed_value};

/// Integer arithmetic right shift: `out = in1 >> in2` (sign-extending).
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntSright;

impl BinaryOpBehavior for OpBehaviorIntSright {
    fn evaluate_binary_u64(&self, _sizeout: usize, sizein: usize, in1: u64, in2: u64) -> u64 {
        let max_shift = (sizein as u64 * 8) - 1;
        if (in2 as i64) < 0 || in2 > max_shift {
            if signbit_negative(in1, sizein) {
                return calc_mask(sizein);
            }
            return 0;
        }
        if signbit_negative(in1, sizein) {
            let res = ((in1 as i64) >> in2) as u64;
            let mask = calc_mask(sizein);
            let mask = (mask >> in2) ^ mask;
            res | mask
        } else {
            in1 >> in2
        }
    }

    fn evaluate_binary_bigint(
        &self,
        _sizeout: usize,
        sizein: usize,
        in1: &BigInt,
        in2: &BigInt,
    ) -> BigInt {
        let signbit = (sizein * 8) - 1;
        let max_shift = BigInt::from(signbit);
        let shift = if in2 > &max_shift {
            signbit
        } else {
            in2.to_u32_digits().1.first().copied().unwrap_or(0) as usize
        };
        let signed_in = if in1.bit(signbit as u64) {
            convert_to_signed_value(in1, sizein)
        } else {
            in1.clone()
        };
        signed_in >> shift
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_int_sright_positive() {
        let op = OpBehaviorIntSright;
        assert_eq!(op.evaluate_binary_u64(8, 8, 16, 2), 4);
    }

    #[test]
    fn test_int_sright_negative() {
        let op = OpBehaviorIntSright;
        // Negative 4-byte value (bit 31 set)
        let in1: u64 = 0xFFFFFF00;
        let result = op.evaluate_binary_u64(4, 4, in1, 4);
        // 0xFFFFFF00 >> 4 = 0xFFFFFFF0 (sign-extended within 4 bytes)
        assert_eq!(result, 0xFFFFFFF0);
    }
}
