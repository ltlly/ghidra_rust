//! Binary operation behavior trait.
//!
//! Ported from Java: `ghidra.pcode.opbehavior.BinaryOpBehavior`.

use num_bigint::BigInt;

/// Trait for binary (2-input) P-code operations.
///
/// Each binary operation takes two inputs and produces one output. The sizes
/// are specified in bytes. Values are treated as unsigned unless otherwise noted.
pub trait BinaryOpBehavior {
    /// Evaluate the binary operation using u64 data.
    ///
    /// # Arguments
    /// * `sizeout` - intended output size (bytes)
    /// * `sizein` - input size (bytes)
    /// * `in1` - unsigned input 1
    /// * `in2` - unsigned input 2
    ///
    /// # Returns
    /// Operation result. Note: if the operation overflows, bits may be set
    /// beyond the specified `sizeout`. The caller should truncate as needed.
    fn evaluate_binary_u64(&self, sizeout: usize, sizein: usize, in1: u64, in2: u64) -> u64;

    /// Evaluate the binary operation using BigInt data.
    ///
    /// # Arguments
    /// * `sizeout` - intended output size (bytes)
    /// * `sizein` - input size (bytes)
    /// * `in1` - unsigned input 1
    /// * `in2` - unsigned input 2
    ///
    /// # Returns
    /// Operation result as a BigInt.
    fn evaluate_binary_bigint(
        &self,
        sizeout: usize,
        sizein: usize,
        in1: &BigInt,
        in2: &BigInt,
    ) -> BigInt;
}
