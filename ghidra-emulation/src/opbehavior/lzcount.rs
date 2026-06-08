//! LZCOUNT operation (leading zero count).
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorLzcount`.

use num_bigint::BigInt;
use num_traits::Zero;

use super::unary::UnaryOpBehavior;

/// LZCOUNT: counts the number of leading zeros in in1.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorLzcount;

impl UnaryOpBehavior for OpBehaviorLzcount {
    fn evaluate_unary_u64(&self, _sizeout: usize, sizein: usize, in1: u64) -> u64 {
        let total_bits = (sizein * 8) as u32;
        if in1 == 0 {
            return total_bits as u64;
        }
        (in1.leading_zeros() - (64 - total_bits)) as u64
    }

    fn evaluate_unary_bigint(&self, _sizeout: usize, sizein: usize, in1: &BigInt) -> BigInt {
        let total_bits = sizein * 8;
        if in1.is_zero() {
            return BigInt::from(total_bits);
        }
        BigInt::from(total_bits - in1.bits() as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lzcount_basic() {
        let op = OpBehaviorLzcount;
        assert_eq!(op.evaluate_unary_u64(8, 8, 0), 64);
        assert_eq!(op.evaluate_unary_u64(1, 1, 0), 8);
        assert_eq!(op.evaluate_unary_u64(1, 1, 0x80), 0);
        assert_eq!(op.evaluate_unary_u64(1, 1, 0x01), 7);
    }

    #[test]
    fn test_lzcount_4byte() {
        let op = OpBehaviorLzcount;
        assert_eq!(op.evaluate_unary_u64(4, 4, 0x80000000), 0);
        assert_eq!(op.evaluate_unary_u64(4, 4, 0x00000001), 31);
    }
}
