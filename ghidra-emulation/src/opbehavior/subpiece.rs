//! SUBPIECE operation (truncation/extraction).
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorSubpiece`.

use num_bigint::BigInt;
use num_traits::ToPrimitive;

use super::binary::BinaryOpBehavior;
use crate::opbehavior::utils::calc_mask;

/// SUBPIECE: extracts a subpiece from in1 starting at byte offset in2.
///
/// `out = (in1 >> (in2 * 8)) & mask(sizeout)`
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorSubpiece;

impl BinaryOpBehavior for OpBehaviorSubpiece {
    fn evaluate_binary_u64(&self, sizeout: usize, _sizein: usize, in1: u64, in2: u64) -> u64 {
        (in1 >> (in2 * 8)) & calc_mask(sizeout)
    }

    fn evaluate_binary_bigint(
        &self,
        _sizeout: usize,
        sizein: usize,
        in1: &BigInt,
        in2: &BigInt,
    ) -> BigInt {
        use num_bigint::ToBigInt;
        let sign_bit = (sizein * 8) - 1;
        let mut res = in1.clone();
        let negative = res.bit(sign_bit as u64);
        if negative {
            let bigmask = calc_mask(sizein).to_bigint().unwrap();
            res = res & bigmask;
            res.set_bit(sign_bit as u64, false);
        }
        let shift = in2.to_usize().unwrap() * 8;
        res = res >> shift;
        let new_sign = sign_bit as isize - shift as isize;
        if negative && new_sign >= 0 {
            res.set_bit(new_sign as u64, true);
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subpiece_low_byte() {
        let op = OpBehaviorSubpiece;
        // Extract low byte of 0xABCD
        assert_eq!(op.evaluate_binary_u64(1, 2, 0xABCD, 0), 0xCD);
    }

    #[test]
    fn test_subpiece_high_byte() {
        let op = OpBehaviorSubpiece;
        // Extract high byte of 0xABCD
        assert_eq!(op.evaluate_binary_u64(1, 2, 0xABCD, 1), 0xAB);
    }

    #[test]
    fn test_subpiece_4_from_8() {
        let op = OpBehaviorSubpiece;
        // Extract low 4 bytes from 8-byte value
        assert_eq!(
            op.evaluate_binary_u64(4, 8, 0x123456789ABCDEF0, 0),
            0x9ABCDEF0
        );
    }
}
