//! PIECE operation (concatenation).
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehaviorPiece`.

use num_bigint::BigInt;

use super::binary::BinaryOpBehavior;

/// PIECE: concatenates in1 (high) and in2 (low).
///
/// `out = (in1 << sizein*8) | in2`
#[derive(Debug, Clone, Copy)]
pub struct OpBehaviorPiece;

impl BinaryOpBehavior for OpBehaviorPiece {
    fn evaluate_binary_u64(&self, _sizeout: usize, sizein: usize, in1: u64, in2: u64) -> u64 {
        (in1 << (sizein * 8)) | in2
    }

    fn evaluate_binary_bigint(
        &self,
        _sizeout: usize,
        sizein: usize,
        in1: &BigInt,
        in2: &BigInt,
    ) -> BigInt {
        (in1 << (sizein * 8)) | in2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_piece_basic() {
        let op = OpBehaviorPiece;
        // Concatenate 0xAB (high) and 0xCD (low) = 0xABCD
        assert_eq!(op.evaluate_binary_u64(2, 1, 0xAB, 0xCD), 0xABCD);
    }

    #[test]
    fn test_piece_4byte() {
        let op = OpBehaviorPiece;
        // Concatenate two 4-byte values into 8-byte
        assert_eq!(
            op.evaluate_binary_u64(8, 4, 0x12345678, 0x9ABCDEF0),
            0x123456789ABCDEF0
        );
    }
}
