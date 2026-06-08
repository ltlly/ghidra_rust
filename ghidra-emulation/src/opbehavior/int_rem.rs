//! Integer unsigned remainder operation.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorIntRem`.

use num_bigint::BigInt;
use num_traits::Zero;

use super::binary::BinaryOpBehavior;

/// Integer unsigned remainder: `out = in1 % in2`.
///
/// Throws on remainder by zero.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntRem;

impl BinaryOpBehavior for OpBehaviorIntRem {
    fn evaluate_binary_u64(&self, _sizeout: usize, _sizein: usize, in1: u64, in2: u64) -> u64 {
        if in2 == 0 {
            panic!("Remainder by 0");
        }
        // Unsigned remainder
        in1 % in2
    }

    fn evaluate_binary_bigint(
        &self,
        _sizeout: usize,
        _sizein: usize,
        in1: &BigInt,
        in2: &BigInt,
    ) -> BigInt {
        if in2.is_zero() {
            panic!("Remainder by 0");
        }
        in1 % in2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_int_rem_basic() {
        let op = OpBehaviorIntRem;
        assert_eq!(op.evaluate_binary_u64(8, 8, 17, 5), 2);
    }

    #[test]
    #[should_panic(expected = "Remainder by 0")]
    fn test_int_rem_by_zero() {
        let op = OpBehaviorIntRem;
        op.evaluate_binary_u64(8, 8, 10, 0);
    }
}
