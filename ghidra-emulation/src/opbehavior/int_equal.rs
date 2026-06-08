//! Integer equality comparison.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorEqual`.

use num_bigint::BigInt;

use super::binary::BinaryOpBehavior;

/// Integer equality: `out = (in1 == in2) ? 1 : 0`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorEqual;

impl BinaryOpBehavior for OpBehaviorEqual {
    fn evaluate_binary_u64(&self, _sizeout: usize, _sizein: usize, in1: u64, in2: u64) -> u64 {
        if in1 == in2 { 1 } else { 0 }
    }

    fn evaluate_binary_bigint(
        &self,
        _sizeout: usize,
        _sizein: usize,
        in1: &BigInt,
        in2: &BigInt,
    ) -> BigInt {
        if in1 == in2 {
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
    fn test_int_equal_true() {
        let op = OpBehaviorEqual;
        assert_eq!(op.evaluate_binary_u64(8, 8, 42, 42), 1);
    }

    #[test]
    fn test_int_equal_false() {
        let op = OpBehaviorEqual;
        assert_eq!(op.evaluate_binary_u64(8, 8, 42, 43), 0);
    }
}
