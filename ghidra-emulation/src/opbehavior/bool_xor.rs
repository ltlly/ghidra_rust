//! Boolean XOR operation.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorBoolXor`.

use num_bigint::BigInt;

use super::binary::BinaryOpBehavior;

/// Boolean XOR: `out = in1 ^ in2` (treating as boolean values).
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorBoolXor;

impl BinaryOpBehavior for OpBehaviorBoolXor {
    fn evaluate_binary_u64(&self, _sizeout: usize, _sizein: usize, in1: u64, in2: u64) -> u64 {
        in1 ^ in2
    }

    fn evaluate_binary_bigint(
        &self,
        _sizeout: usize,
        _sizein: usize,
        in1: &BigInt,
        in2: &BigInt,
    ) -> BigInt {
        in1 ^ in2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bool_xor_different() {
        let op = OpBehaviorBoolXor;
        assert_eq!(op.evaluate_binary_u64(1, 1, 1, 0), 1);
    }

    #[test]
    fn test_bool_xor_same() {
        let op = OpBehaviorBoolXor;
        assert_eq!(op.evaluate_binary_u64(1, 1, 1, 1), 0);
    }
}
