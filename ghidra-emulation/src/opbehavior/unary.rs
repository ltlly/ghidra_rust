//! Unary operation behavior trait.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.UnaryOpBehavior`.

use num_bigint::BigInt;

/// Trait for unary (1-input) P-code operations.
///
/// Each unary operation takes one input and produces one output. The sizes
/// are specified in bytes. Values are treated as unsigned unless otherwise noted.
pub trait UnaryOpBehavior {
    /// Evaluate the unary operation using u64 data.
    ///
    /// # Arguments
    /// * `sizeout` - intended output size (bytes)
    /// * `sizein` - input size (bytes)
    /// * `in1` - unsigned input 1
    ///
    /// # Returns
    /// Operation result. Note: if the operation overflows, bits may be set
    /// beyond the specified `sizeout`. The caller should truncate as needed.
    fn evaluate_unary_u64(&self, sizeout: usize, sizein: usize, in1: u64) -> u64;

    /// Evaluate the unary operation using BigInt data.
    ///
    /// # Arguments
    /// * `sizeout` - intended output size (bytes)
    /// * `sizein` - input size (bytes)
    /// * `in1` - unsigned input 1
    ///
    /// # Returns
    /// Operation result as a BigInt.
    fn evaluate_unary_bigint(&self, sizeout: usize, sizein: usize, in1: &BigInt) -> BigInt;
}
