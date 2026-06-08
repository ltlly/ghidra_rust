//! Integer signed borrow detection.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorIntSborrow`.

use num_bigint::BigInt;

use super::binary::BinaryOpBehavior;

/// Integer signed borrow: detects if signed subtraction overflows.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntSborrow;

impl BinaryOpBehavior for OpBehaviorIntSborrow {
    fn evaluate_binary_u64(&self, _sizeout: usize, sizein: usize, in1: u64, in2: u64) -> u64 {
        let res = in1.wrapping_sub(in2);
        let sign_bit = sizein * 8 - 1;
        let a = ((in1 >> sign_bit) & 1) as u32;
        let b = ((in2 >> sign_bit) & 1) as u32;
        let r = ((res >> sign_bit) & 1) as u32;
        let mut a_mut = a ^ r;
        let mut r_mut = r ^ b;
        r_mut ^= 1;
        a_mut &= r_mut;
        a_mut as u64
    }

    fn evaluate_binary_bigint(
        &self,
        _sizeout: usize,
        sizein: usize,
        in1: &BigInt,
        in2: &BigInt,
    ) -> BigInt {
        let res = in1 - in2;
        let sign_bit = sizein * 8 - 1;
        let a = in1.bit(sign_bit as u64);
        let b = in2.bit(sign_bit as u64);
        let r = res.bit(sign_bit as u64);
        let result = (a ^ r) & ((r ^ b) ^ true);
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
    fn test_int_sborrow_no_overflow() {
        let op = OpBehaviorIntSborrow;
        assert_eq!(op.evaluate_binary_u64(8, 8, 30, 10), 0);
    }

    #[test]
    fn test_int_sborrow_overflow() {
        let op = OpBehaviorIntSborrow;
        // -128 - 1 = overflow for 1-byte signed
        assert_eq!(op.evaluate_binary_u64(1, 1, 128, 1), 1);
    }
}
