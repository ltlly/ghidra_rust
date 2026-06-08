//! Scalar overflow exception for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.scalar.ScalarOverflowException`.
//!
//! A [`ScalarOverflowException`] indicates that precision would be lost during
//! a scalar operation. For signed operations, the unused bits did not match the
//! sign bit. For unsigned operations, the unused bits were not all zero.

use std::fmt;

/// Indicates that precision would be lost during a scalar operation.
///
/// Corresponds to `ghidra.program.model.scalar.ScalarOverflowException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScalarOverflowException {
    message: String,
}

impl ScalarOverflowException {
    /// Creates a new exception with the default message.
    pub fn new() -> Self {
        Self {
            message: "Scalar overflow".to_string(),
        }
    }

    /// Creates a new exception with a custom message.
    pub fn with_message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Default for ScalarOverflowException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ScalarOverflowException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ScalarOverflowException: {}", self.message)
    }
}

impl std::error::Error for ScalarOverflowException {}
