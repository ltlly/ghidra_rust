//! Integer bitwise OR operation.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorIntOr`.

use num_bigint::BigInt;

use super::binary::BinaryOpBehavior;

/// Integer bitwise OR: `out = in1 | in2`.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntOr;

impl BinaryOpBehavior for OpBehaviorIntOr {
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
    fn test_int_or_basic() {
        let op = OpBehaviorIntOr;
        assert_eq!(op.evaluate_binary_u64(8, 8, 0xFF00, 0x00FF), 0xFFFF);
    }
}
