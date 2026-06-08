//! Integer inequality comparison.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorNotEqual`.

use num_bigint::BigInt;

use super::binary::BinaryOpBehavior;

/// Integer inequality: `out = (in1 != in2) ? 1 : 0`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorNotEqual;

impl BinaryOpBehavior for OpBehaviorNotEqual {
    fn evaluate_binary_u64(&self, _sizeout: usize, _sizein: usize, in1: u64, in2: u64) -> u64 {
        if in1 != in2 { 1 } else { 0 }
    }

    fn evaluate_binary_bigint(
        &self,
        _sizeout: usize,
        _sizein: usize,
        in1: &BigInt,
        in2: &BigInt,
    ) -> BigInt {
        if in1 != in2 {
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
    fn test_int_not_equal_true() {
        let op = OpBehaviorNotEqual;
        assert_eq!(op.evaluate_binary_u64(8, 8, 42, 43), 1);
    }

    #[test]
    fn test_int_not_equal_false() {
        let op = OpBehaviorNotEqual;
        assert_eq!(op.evaluate_binary_u64(8, 8, 42, 42), 0);
    }
}
