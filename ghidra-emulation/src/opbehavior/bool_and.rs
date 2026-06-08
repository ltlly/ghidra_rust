//! Boolean AND operation.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorBoolAnd`.

use num_bigint::BigInt;

use super::binary::BinaryOpBehavior;

/// Boolean AND: `out = in1 & in2` (treating as boolean values).
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorBoolAnd;

impl BinaryOpBehavior for OpBehaviorBoolAnd {
    fn evaluate_binary_u64(&self, _sizeout: usize, _sizein: usize, in1: u64, in2: u64) -> u64 {
        in1 & in2
    }

    fn evaluate_binary_bigint(
        &self,
        _sizeout: usize,
        _sizein: usize,
        in1: &BigInt,
        in2: &BigInt,
    ) -> BigInt {
        in1 & in2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bool_and_true() {
        let op = OpBehaviorBoolAnd;
        assert_eq!(op.evaluate_binary_u64(1, 1, 1, 1), 1);
    }

    #[test]
    fn test_bool_and_false() {
        let op = OpBehaviorBoolAnd;
        assert_eq!(op.evaluate_binary_u64(1, 1, 1, 0), 0);
    }
}
