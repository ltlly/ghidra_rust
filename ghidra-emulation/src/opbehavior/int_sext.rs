//! Integer sign extension operation.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorIntSext`.

use num_bigint::BigInt;

use super::unary::UnaryOpBehavior;
use crate::opbehavior::utils::{sign_extend, convert_to_signed_value};

/// Integer sign extension: extends the sign bit of in1 to fill sizeout.
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorIntSext;

impl UnaryOpBehavior for OpBehaviorIntSext {
    fn evaluate_unary_u64(&self, sizeout: usize, sizein: usize, in1: u64) -> u64 {
        sign_extend(in1, sizein, sizeout)
    }

    fn evaluate_unary_bigint(&self, _sizeout: usize, sizein: usize, in1: &BigInt) -> BigInt {
        convert_to_signed_value(in1, sizein)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_int_sext_positive() {
        let op = OpBehaviorIntSext;
        // 0x7F (positive) extended to 2 bytes = 0x007F
        assert_eq!(op.evaluate_unary_u64(2, 1, 0x7F), 0x007F);
    }

    #[test]
    fn test_int_sext_negative() {
        let op = OpBehaviorIntSext;
        // 0x80 (negative in 1 byte) extended to 2 bytes = 0xFF80
        assert_eq!(op.evaluate_unary_u64(2, 1, 0x80), 0xFF80);
    }

    #[test]
    fn test_int_sext_4_to_8() {
        let op = OpBehaviorIntSext;
        // 0x80000000 (negative in 4 bytes) extended to 8 bytes
        assert_eq!(op.evaluate_unary_u64(8, 4, 0x80000000), 0xFFFFFFFF80000000);
    }
}
