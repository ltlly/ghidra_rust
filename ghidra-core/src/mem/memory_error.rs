//! Error types for memory operations.
//!
//! This module provides the error types used throughout the memory subsystem.
//! They correspond to the exception classes in Ghidra's
//! `ghidra.program.model.mem` package:
//!
//! | Java class | Rust type |
//! |---|---|
//! | `MemoryAccessException` | [`MemoryAccessError`] |
//! | `MemoryBlockException` | [`MemoryBlockError`] |
//! | `MemoryConflictException` | [`MemoryConflictError`] |
//! | `InvalidAddressException` | [`InvalidAddressError`] |
//! | `InvalidBlockNameException` | [`InvalidBlockNameError`] |
//!
//! All error types implement `std::error::Error`, `Display`, and `Debug`,
//! and can be converted into the crate-level [`GhidraError`](crate::error::GhidraError).

use crate::error::GhidraError;
use std::fmt;

// ============================================================================
// MemoryAccessError
// ============================================================================

/// Error returned when a memory access is not permitted.
///
/// This corresponds to Ghidra's `MemoryAccessException`. It is thrown when:
/// - Reading from uninitialized memory
/// - Reading/writing at an address outside any block
/// - Writing to a read-only block
/// - Any other permission violation
///
/// # Examples
///
/// ```
/// use ghidra_core::mem::memory_error::MemoryAccessError;
///
/// let err = MemoryAccessError::new("address out of range");
/// assert_eq!(format!("{}", err), "MemoryAccessError: address out of range");
/// ```
#[derive(Debug, Clone)]
pub struct MemoryAccessError {
    /// The human-readable error message.
    pub message: String,
}

impl MemoryAccessError {
    /// Creates a new `MemoryAccessError` with the given message.
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }

    /// Creates a `MemoryAccessError` with a default message.
    pub fn default_error() -> Self {
        Self {
            message: "Memory access error".into(),
        }
    }
}

impl fmt::Display for MemoryAccessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MemoryAccessError: {}", self.message)
    }
}

impl std::error::Error for MemoryAccessError {}

impl From<MemoryAccessError> for GhidraError {
    fn from(e: MemoryAccessError) -> Self {
        GhidraError::MemoryError(e.message)
    }
}

impl From<GhidraError> for MemoryAccessError {
    fn from(e: GhidraError) -> Self {
        MemoryAccessError::new(format!("{}", e))
    }
}

// ============================================================================
// MemoryBlockError
// ============================================================================

/// Error thrown for memory block-related problems.
///
/// This corresponds to Ghidra's `MemoryBlockException`. It is thrown when
/// block operations like split, join, or move fail due to block constraints
/// (e.g., non-contiguous blocks, non-default types).
///
/// # Examples
///
/// ```
/// use ghidra_core::mem::memory_error::MemoryBlockError;
///
/// let err = MemoryBlockError::new("blocks not contiguous");
/// assert_eq!(format!("{}", err), "MemoryBlockError: blocks not contiguous");
/// ```
#[derive(Debug, Clone)]
pub struct MemoryBlockError {
    /// The human-readable error message.
    pub message: String,
}

impl MemoryBlockError {
    /// Creates a new `MemoryBlockError` with the given message.
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }

    /// Creates a `MemoryBlockError` with a default message.
    pub fn default_error() -> Self {
        Self {
            message: "Memory block error".into(),
        }
    }
}

impl fmt::Display for MemoryBlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MemoryBlockError: {}", self.message)
    }
}

impl std::error::Error for MemoryBlockError {}

impl From<MemoryBlockError> for GhidraError {
    fn from(e: MemoryBlockError) -> Self {
        GhidraError::MemoryError(e.message)
    }
}

impl From<MemoryBlockError> for MemoryAccessError {
    fn from(e: MemoryBlockError) -> Self {
        MemoryAccessError::new(e.message)
    }
}

// ============================================================================
// MemoryConflictError
// ============================================================================

/// Error thrown when creating or moving a memory block would cause blocks to
/// overlap.
///
/// This corresponds to Ghidra's `MemoryConflictException`. It is thrown when
/// a new block overlaps with an existing block at the same address range.
///
/// # Examples
///
/// ```
/// use ghidra_core::mem::memory_error::MemoryConflictError;
///
/// let err = MemoryConflictError::new("new block overlaps .text");
/// assert_eq!(format!("{}", err), "MemoryConflictError: new block overlaps .text");
/// ```
#[derive(Debug, Clone)]
pub struct MemoryConflictError {
    /// The human-readable error message.
    pub message: String,
}

impl MemoryConflictError {
    /// Creates a new `MemoryConflictError` with the given message.
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }

    /// Creates a `MemoryConflictError` with a default message.
    pub fn default_error() -> Self {
        Self {
            message: "Memory conflict".into(),
        }
    }
}

impl fmt::Display for MemoryConflictError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MemoryConflictError: {}", self.message)
    }
}

impl std::error::Error for MemoryConflictError {}

impl From<MemoryConflictError> for GhidraError {
    fn from(e: MemoryConflictError) -> Self {
        GhidraError::MemoryError(e.message)
    }
}

// ============================================================================
// InvalidBlockNameError
// ============================================================================

/// Error for invalid memory block names.
///
/// Thrown when a block name is empty or contains control characters
/// (ASCII 0..=0x19).
#[derive(Debug, Clone)]
pub struct InvalidBlockNameError {
    /// The invalid name that was provided.
    pub name: String,
}

impl InvalidBlockNameError {
    /// Creates a new `InvalidBlockNameError` for the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

impl fmt::Display for InvalidBlockNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid memory block name: '{}'", self.name)
    }
}

impl std::error::Error for InvalidBlockNameError {}

// ============================================================================
// InvalidAddressError
// ============================================================================

/// Error for invalid addresses.
///
/// Corresponds to Ghidra's `InvalidAddressException`. Thrown when an address
/// is improperly formatted or not defined within the target.
///
/// # Examples
///
/// ```
/// use ghidra_core::mem::memory_error::InvalidAddressError;
///
/// let err = InvalidAddressError::new("address not in memory space");
/// assert_eq!(format!("{}", err), "InvalidAddressError: address not in memory space");
/// ```
#[derive(Debug, Clone)]
pub struct InvalidAddressError {
    /// The human-readable error message.
    pub message: String,
}

impl InvalidAddressError {
    /// Creates a new `InvalidAddressError` with the given message.
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }

    /// Creates an `InvalidAddressError` with a default message.
    pub fn default_error() -> Self {
        Self {
            message: "Invalid address".into(),
        }
    }
}

impl fmt::Display for InvalidAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InvalidAddressError: {}", self.message)
    }
}

impl std::error::Error for InvalidAddressError {}

impl From<InvalidAddressError> for GhidraError {
    fn from(e: InvalidAddressError) -> Self {
        GhidraError::AddressError(e.message)
    }
}

impl From<InvalidAddressError> for MemoryAccessError {
    fn from(e: InvalidAddressError) -> Self {
        MemoryAccessError::new(e.message)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_access_error_new() {
        let err = MemoryAccessError::new("test error");
        assert_eq!(err.message, "test error");
        assert_eq!(format!("{}", err), "MemoryAccessError: test error");
    }

    #[test]
    fn test_memory_access_error_default() {
        let err = MemoryAccessError::default_error();
        assert_eq!(err.message, "Memory access error");
    }

    #[test]
    fn test_memory_access_error_into_ghidra_error() {
        let err: GhidraError = MemoryAccessError::new("test").into();
        assert!(matches!(err, GhidraError::MemoryError(_)));
    }

    #[test]
    fn test_memory_access_error_from_ghidra_error() {
        let ghidra_err = GhidraError::MemoryError("test".into());
        let err: MemoryAccessError = ghidra_err.into();
        // GhidraError::MemoryError formats as "Memory error: test"
        assert!(err.message.contains("test"));
    }

    #[test]
    fn test_memory_block_error_new() {
        let err = MemoryBlockError::new("block issue");
        assert_eq!(format!("{}", err), "MemoryBlockError: block issue");
    }

    #[test]
    fn test_memory_block_error_default() {
        let err = MemoryBlockError::default_error();
        assert_eq!(format!("{}", err), "MemoryBlockError: Memory block error");
    }

    #[test]
    fn test_memory_block_error_into_ghidra_error() {
        let err: GhidraError = MemoryBlockError::new("test").into();
        assert!(matches!(err, GhidraError::MemoryError(_)));
    }

    #[test]
    fn test_memory_block_error_into_memory_access_error() {
        let err: MemoryAccessError = MemoryBlockError::new("block issue").into();
        assert_eq!(err.message, "block issue");
    }

    #[test]
    fn test_memory_conflict_error_new() {
        let err = MemoryConflictError::new("overlap detected");
        assert_eq!(format!("{}", err), "MemoryConflictError: overlap detected");
    }

    #[test]
    fn test_memory_conflict_error_default() {
        let err = MemoryConflictError::default_error();
        assert_eq!(format!("{}", err), "MemoryConflictError: Memory conflict");
    }

    #[test]
    fn test_memory_conflict_error_into_ghidra_error() {
        let err: GhidraError = MemoryConflictError::new("test").into();
        assert!(matches!(err, GhidraError::MemoryError(_)));
    }

    #[test]
    fn test_invalid_block_name_error() {
        let err = InvalidBlockNameError::new("");
        assert_eq!(
            format!("{}", err),
            "Invalid memory block name: ''"
        );
    }

    #[test]
    fn test_invalid_address_error_new() {
        let err = InvalidAddressError::new("bad address");
        assert_eq!(format!("{}", err), "InvalidAddressError: bad address");
    }

    #[test]
    fn test_invalid_address_error_default() {
        let err = InvalidAddressError::default_error();
        assert_eq!(format!("{}", err), "InvalidAddressError: Invalid address");
    }

    #[test]
    fn test_invalid_address_error_into_ghidra_error() {
        let err: GhidraError = InvalidAddressError::new("test").into();
        assert!(matches!(err, GhidraError::AddressError(_)));
    }

    #[test]
    fn test_invalid_address_error_into_memory_access_error() {
        let err: MemoryAccessError = InvalidAddressError::new("test").into();
        assert_eq!(err.message, "test");
    }

    #[test]
    fn test_error_debug() {
        let err = MemoryAccessError::new("debug test");
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("MemoryAccessError"));
        assert!(debug_str.contains("debug test"));
    }

    #[test]
    fn test_error_clone() {
        let err = MemoryAccessError::new("clone test");
        let cloned = err.clone();
        assert_eq!(err.message, cloned.message);
    }
}
