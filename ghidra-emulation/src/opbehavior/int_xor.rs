//! Integer bitwise XOR operation.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorIntXor`.

use num_bigint::BigInt;

use super::binary::BinaryOpBehavior;

/// Integer bitwise XOR: `out = in1 ^ in2`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntXor;

impl BinaryOpBehavior for OpBehaviorIntXor {
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
    fn test_int_xor_basic() {
        let op = OpBehaviorIntXor;
        assert_eq!(op.evaluate_binary_u64(8, 8, 0xFF00, 0x0FF0), 0xF0F0);
    }

    #[test]
    fn test_int_xor_same() {
        let op = OpBehaviorIntXor;
        assert_eq!(op.evaluate_binary_u64(8, 8, 0xAAAA, 0xAAAA), 0);
    }
}
