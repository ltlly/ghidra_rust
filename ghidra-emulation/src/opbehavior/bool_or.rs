//! Boolean OR operation.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorBoolOr`.

use num_bigint::BigInt;

use super::binary::BinaryOpBehavior;

/// Boolean OR: `out = in1 | in2` (treating as boolean values).
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorBoolOr;

impl BinaryOpBehavior for OpBehaviorBoolOr {
    fn evaluate_binary_u64(&self, _sizeout: usize, _sizein: usize, in1: u64, in2: u64) -> u64 {
        in1 | in2
    }

    fn evaluate_binary_bigint(
        &self,
        _sizeout: usize,
        _sizein: usize,
        in1: &BigInt,
        in2: &BigInt,
    ) -> BigInt {
        in1 | in2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bool_or_both() {
        let op = OpBehaviorBoolOr;
        assert_eq!(op.evaluate_binary_u64(1, 1, 1, 1), 1);
    }

    #[test]
    fn test_bool_or_one() {
        let op = OpBehaviorBoolOr;
        assert_eq!(op.evaluate_binary_u64(1, 1, 1, 0), 1);
    }

    #[test]
    fn test_bool_or_neither() {
        let op = OpBehaviorBoolOr;
        assert_eq!(op.evaluate_binary_u64(1, 1, 0, 0), 0);
    }
}
