//! Unified OpBehavior trait for P-code operations.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.OpBehavior`.
//!
//! The Java `OpBehavior` is a base class with just an opcode field.
//! Subclasses include `BinaryOpBehavior`, `UnaryOpBehavior`, and
//! `SpecialOpBehavior`. This module provides a unified Rust trait
//! that all operation behaviors implement.

use num_bigint::BigInt;

/// The category of a P-code operation behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpBehaviorKind {
    /// Binary (2-input) operation.
    Binary,
    /// Unary (1-input) operation.
    Unary,
    /// Special operation (control flow, etc.).
    Special,
}

/// Unified trait for all P-code operation behaviors.
///
/// This mirrors the Java `OpBehavior` base class, extended with
/// evaluation methods from `BinaryOpBehavior` and `UnaryOpBehavior`.
///
/// All P-code operation implementations should implement this trait.
/// The default implementations of `evaluate_binary_u64` and
/// `evaluate_unary_u64` return `None`, so implementors only need to
/// override the methods relevant to their behavior kind.
pub trait OpBehavior: std::fmt::Debug {
    /// Get the P-code opcode for this behavior.
    fn opcode(&self) -> u32;

    /// Get the behavior kind (binary, unary, or special).
    fn kind(&self) -> OpBehaviorKind;

    /// Evaluate a binary operation using u64 data.
    ///
    /// Returns `Some(result)` if this is a binary operation, `None` otherwise.
    fn evaluate_binary_u64(
        &self,
        _sizeout: usize,
        _sizein: usize,
        _in1: u64,
        _in2: u64,
    ) -> Option<u64> {
        None
    }

    /// Evaluate a binary operation using BigInt data.
    ///
    /// Returns `Some(result)` if this is a binary operation, `None` otherwise.
    fn evaluate_binary_bigint(
        &self,
        _sizeout: usize,
        _sizein: usize,
        _in1: &BigInt,
        _in2: &BigInt,
    ) -> Option<BigInt> {
        None
    }

    /// Evaluate a unary operation using u64 data.
    ///
    /// Returns `Some(result)` if this is a unary operation, `None` otherwise.
    fn evaluate_unary_u64(&self, _sizeout: usize, _sizein: usize, _in1: u64) -> Option<u64> {
        None
    }

    /// Evaluate a unary operation using BigInt data.
    ///
    /// Returns `Some(result)` if this is a unary operation, `None` otherwise.
    fn evaluate_unary_bigint(
        &self,
        _sizeout: usize,
        _sizein: usize,
        _in1: &BigInt,
    ) -> Option<BigInt> {
        None
    }
}

/// A wrapper that adapts a [`BinaryOpBehavior`] to the unified [`OpBehavior`] trait.
///
/// This allows existing binary operation implementations to be used with
/// the unified trait without modification.
#[derive(Debug)]
pub struct BinaryOpBehaviorAdapter<B: super::binary::BinaryOpBehavior + std::fmt::Debug> {
    opcode: u32,
    inner: B,
}

impl<B: super::binary::BinaryOpBehavior + std::fmt::Debug> BinaryOpBehaviorAdapter<B> {
    /// Create a new adapter wrapping a binary operation behavior.
    pub fn new(opcode: u32, inner: B) -> Self {
        Self { opcode, inner }
    }
}

impl<B: super::binary::BinaryOpBehavior + std::fmt::Debug> OpBehavior for BinaryOpBehaviorAdapter<B> {
    fn opcode(&self) -> u32 {
        self.opcode
    }

    fn kind(&self) -> OpBehaviorKind {
        OpBehaviorKind::Binary
    }

    fn evaluate_binary_u64(
        &self,
        sizeout: usize,
        sizein: usize,
        in1: u64,
        in2: u64,
    ) -> Option<u64> {
        Some(self.inner.evaluate_binary_u64(sizeout, sizein, in1, in2))
    }

    fn evaluate_binary_bigint(
        &self,
        sizeout: usize,
        sizein: usize,
        in1: &BigInt,
        in2: &BigInt,
    ) -> Option<BigInt> {
        Some(self.inner.evaluate_binary_bigint(sizeout, sizein, in1, in2))
    }
}

/// A wrapper that adapts a [`UnaryOpBehavior`] to the unified [`OpBehavior`] trait.
#[derive(Debug)]
pub struct UnaryOpBehaviorAdapter<B: super::unary::UnaryOpBehavior + std::fmt::Debug> {
    opcode: u32,
    inner: B,
}

impl<B: super::unary::UnaryOpBehavior + std::fmt::Debug> UnaryOpBehaviorAdapter<B> {
    /// Create a new adapter wrapping a unary operation behavior.
    pub fn new(opcode: u32, inner: B) -> Self {
        Self { opcode, inner }
    }
}

impl<B: super::unary::UnaryOpBehavior + std::fmt::Debug> OpBehavior for UnaryOpBehaviorAdapter<B> {
    fn opcode(&self) -> u32 {
        self.opcode
    }

    fn kind(&self) -> OpBehaviorKind {
        OpBehaviorKind::Unary
    }

    fn evaluate_unary_u64(&self, sizeout: usize, sizein: usize, in1: u64) -> Option<u64> {
        Some(self.inner.evaluate_unary_u64(sizeout, sizein, in1))
    }

    fn evaluate_unary_bigint(
        &self,
        sizeout: usize,
        sizein: usize,
        in1: &BigInt,
    ) -> Option<BigInt> {
        Some(self.inner.evaluate_unary_bigint(sizeout, sizein, in1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opbehavior::int_add::OpBehaviorIntAdd;
    use crate::opbehavior::int_sub::OpBehaviorIntSub;
    use crate::opbehavior::copy::OpBehaviorCopy;

    #[test]
    fn test_binary_adapter_int_add() {
        let adapter = BinaryOpBehaviorAdapter::new(1, OpBehaviorIntAdd);
        assert_eq!(adapter.opcode(), 1);
        assert_eq!(adapter.kind(), OpBehaviorKind::Binary);
        assert_eq!(adapter.evaluate_binary_u64(8, 8, 10, 20), Some(30));
        assert_eq!(adapter.evaluate_unary_u64(8, 8, 10), None);
    }

    #[test]
    fn test_binary_adapter_int_sub() {
        let adapter = BinaryOpBehaviorAdapter::new(2, OpBehaviorIntSub);
        assert_eq!(adapter.evaluate_binary_u64(8, 8, 30, 10), Some(20));
    }

    #[test]
    fn test_unary_adapter_copy() {
        let adapter = UnaryOpBehaviorAdapter::new(3, OpBehaviorCopy);
        assert_eq!(adapter.opcode(), 3);
        assert_eq!(adapter.kind(), OpBehaviorKind::Unary);
        assert_eq!(adapter.evaluate_unary_u64(8, 8, 42), Some(42));
        assert_eq!(adapter.evaluate_binary_u64(8, 8, 10, 20), None);
    }

    #[test]
    fn test_binary_adapter_overflow() {
        let adapter = BinaryOpBehaviorAdapter::new(1, OpBehaviorIntAdd);
        let result = adapter.evaluate_binary_u64(4, 4, 0xFFFFFFFF, 1);
        assert_eq!(result, Some(0));
    }

    #[test]
    fn test_binary_adapter_bigint() {
        let adapter = BinaryOpBehaviorAdapter::new(1, OpBehaviorIntAdd);
        let a = BigInt::from(100);
        let b = BigInt::from(200);
        assert_eq!(
            adapter.evaluate_binary_bigint(8, 8, &a, &b),
            Some(BigInt::from(300))
        );
    }
}
