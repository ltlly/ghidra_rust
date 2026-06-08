//! Scalar integer types for Ghidra Rust.
//!
//! Models Ghidra's `ghidra.program.model.scalar` package. Provides
//! [`Scalar`] (an immutable integer stored in an arbitrary number of bits)
//! and [`ScalarOverflowException`].

pub mod scalar;
pub mod overflow;

pub use scalar::Scalar;
pub use overflow::ScalarOverflowException;
