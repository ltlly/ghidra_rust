//! POPCOUNT operation (population count / number of set bits).
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorPopcount`.

use num_bigint::BigInt;

use super::unary::UnaryOpBehavior;

/// POPCOUNT: counts the number of set bits in in1.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorPopcount;

impl UnaryOpBehavior for OpBehaviorPopcount {
    fn evaluate_unary_u64(&self, _sizeout: usize, _sizein: usize, in1: u64) -> u64 {
        in1.count_ones() as u64
    }

    fn evaluate_unary_bigint(&self, _sizeout: usize, sizein: usize, in1: &BigInt) -> BigInt {
        let total_bits = sizein * 8;
        let mut count = 0u64;
        for i in 0..total_bits {
            if in1.bit(i as u64) {
                count += 1;
            }
        }
        BigInt::from(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_popcount_basic() {
        let op = OpBehaviorPopcount;
        assert_eq!(op.evaluate_unary_u64(8, 8, 0xFF), 8);
        assert_eq!(op.evaluate_unary_u64(8, 8, 0), 0);
        assert_eq!(op.evaluate_unary_u64(8, 8, 1), 1);
        assert_eq!(op.evaluate_unary_u64(8, 8, 0b10101010), 4);
    }
}
