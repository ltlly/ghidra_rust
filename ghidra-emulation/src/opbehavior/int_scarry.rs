//! Integer signed carry detection.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorIntScarry`.

use num_bigint::BigInt;

use super::binary::BinaryOpBehavior;

/// Integer signed carry: detects if signed addition overflows.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntScarry;

impl BinaryOpBehavior for OpBehaviorIntScarry {
    fn evaluate_binary_u64(&self, _sizeout: usize, sizein: usize, in1: u64, in2: u64) -> u64 {
        let res = in1.wrapping_add(in2);
        let sign_bit = sizein * 8 - 1;
        let a = ((in1 >> sign_bit) & 1) as u32;
        let b = ((in2 >> sign_bit) & 1) as u32;
        let r = ((res >> sign_bit) & 1) as u32;
        let mut result = r ^ a;
        let mut a_mut = a ^ b;
        a_mut ^= 1;
        result &= a_mut;
        result as u64
    }

    fn evaluate_binary_bigint(
        &self,
        _sizeout: usize,
        sizein: usize,
        in1: &BigInt,
        in2: &BigInt,
    ) -> BigInt {
        let res = in1 + in2;
        let sign_bit = sizein * 8 - 1;
        let a = in1.bit(sign_bit as u64);
        let b = in2.bit(sign_bit as u64);
        let r = res.bit(sign_bit as u64);
        let result = (r ^ a) & ((a ^ b) ^ true);
        if result {
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
    fn test_int_scarry_no_overflow() {
        let op = OpBehaviorIntScarry;
        assert_eq!(op.evaluate_binary_u64(8, 8, 10, 20), 0);
    }

    #[test]
    fn test_int_scarry_overflow() {
        let op = OpBehaviorIntScarry;
        // Max positive 1-byte: 127 + 1 = overflow
        assert_eq!(op.evaluate_binary_u64(1, 1, 127, 1), 1);
    }
}
