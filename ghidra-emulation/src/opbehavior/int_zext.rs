//! Integer zero extension operation.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorIntZext`.

use num_bigint::BigInt;

use super::unary::UnaryOpBehavior;

/// Integer zero extension: zero-extends in1 to fill sizeout.
///
/// This is essentially a no-op for u64 values, as the upper bits are already 0.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntZext;

impl UnaryOpBehavior for OpBehaviorIntZext {
    fn evaluate_unary_u64(&self, _sizeout: usize, _sizein: usize, in1: u64) -> u64 {
        in1
    }

    fn evaluate_unary_bigint(&self, _sizeout: usize, _sizein: usize, in1: &BigInt) -> BigInt {
        in1.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_int_zext_basic() {
        let op = OpBehaviorIntZext;
        assert_eq!(op.evaluate_unary_u64(4, 1, 0xFF), 0xFF);
    }
}
