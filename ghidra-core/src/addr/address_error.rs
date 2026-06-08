//! Error types for address operations in Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.address.AddressFormatException`,
//! `AddressOutOfBoundsException`, `AddressOverflowException`, and
//! `SegmentMismatchException`.
//!
//! These errors are used throughout the address subsystem to signal
//! parsing failures, out-of-bounds offsets, arithmetic overflows, and
//! cross-segment violations.

use std::fmt;

// ---------------------------------------------------------------------------
// AddressFormatException
// ---------------------------------------------------------------------------

/// Error when parsing an address string fails.
///
/// Corresponds to `ghidra.program.model.address.AddressFormatException`.
///
/// This is returned when an address string cannot be parsed (invalid hex,
/// missing space name, offset too large for the space, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressFormatException {
    message: String,
}

impl AddressFormatException {
    /// Create a new format exception with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for AddressFormatException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address format error: {}", self.message)
    }
}

impl std::error::Error for AddressFormatException {}

impl From<std::num::ParseIntError> for AddressFormatException {
    fn from(e: std::num::ParseIntError) -> Self {
        Self::new(format!("Invalid address offset: {}", e))
    }
}

// ---------------------------------------------------------------------------
// AddressOutOfBoundsException
// ---------------------------------------------------------------------------

/// Error when an address offset is outside the valid range for its space.
///
/// Corresponds to `ghidra.program.model.address.AddressOutOfBoundsException`.
///
/// This is thrown when an operation would produce an address whose offset is
/// less than the minimum or greater than the maximum allowed by the address
/// space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressOutOfBoundsException {
    message: String,
}

impl AddressOutOfBoundsException {
    /// Create a new out-of-bounds exception with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Create an exception for an offset in a specific space.
    pub fn for_offset(space_name: &str, offset: u64) -> Self {
        Self::new(format!(
            "Offset 0x{:x} is out of bounds for address space '{}'",
            offset, space_name
        ))
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for AddressOutOfBoundsException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address out of bounds: {}", self.message)
    }
}

impl std::error::Error for AddressOutOfBoundsException {}

impl From<AddressFormatException> for AddressOutOfBoundsException {
    fn from(e: AddressFormatException) -> Self {
        Self::new(e.message)
    }
}

// ---------------------------------------------------------------------------
// AddressOverflowException
// ---------------------------------------------------------------------------

/// Error when an address arithmetic operation would overflow.
///
/// Corresponds to `ghidra.program.model.address.AddressOverflowException`.
///
/// This is thrown by `addNoWrap` / `subtractNoWrap` when the result would
/// exceed the address space bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressOverflowException {
    message: String,
}

impl AddressOverflowException {
    /// Create a new overflow exception with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Create an exception for an addition overflow.
    pub fn add_overflow(addr_offset: u64, displacement: u64) -> Self {
        Self::new(format!(
            "Address overflow in add: 0x{:x} + 0x{:x}",
            addr_offset, displacement
        ))
    }

    /// Create an exception for a subtraction overflow.
    pub fn subtract_overflow(addr_offset: u64, displacement: u64) -> Self {
        Self::new(format!(
            "Address overflow in subtract: 0x{:x} - 0x{:x}",
            addr_offset, displacement
        ))
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for AddressOverflowException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address overflow: {}", self.message)
    }
}

impl std::error::Error for AddressOverflowException {}

impl From<AddressOverflowException> for AddressOutOfBoundsException {
    fn from(e: AddressOverflowException) -> Self {
        Self::new(e.message)
    }
}

// ---------------------------------------------------------------------------
// SegmentMismatchException
// ---------------------------------------------------------------------------

/// Error when two addresses are compared or combined across incompatible segments.
///
/// Corresponds to `ghidra.program.model.address.SegmentMismatchException`.
///
/// This is thrown when an operation requires two addresses to be in the same
/// segment but they are not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentMismatchException {
    message: String,
}

impl SegmentMismatchException {
    /// Create a new segment mismatch exception with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Create an exception for two addresses in different segments.
    pub fn different_segments(seg1: u16, seg2: u16) -> Self {
        Self::new(format!(
            "Segment mismatch: 0x{:04x} vs 0x{:04x}",
            seg1, seg2
        ))
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for SegmentMismatchException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Segment mismatch: {}", self.message)
    }
}

impl std::error::Error for SegmentMismatchException {}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_format_exception() {
        let e = AddressFormatException::new("bad hex");
        assert_eq!(e.message(), "bad hex");
        assert!(format!("{}", e).contains("bad hex"));
    }

    #[test]
    fn test_address_format_exception_from_parse_int() {
        let parse_err = "not_a_number".parse::<u64>().unwrap_err();
        let e = AddressFormatException::from(parse_err);
        assert!(format!("{}", e).contains("Invalid address offset"));
    }

    #[test]
    fn test_address_out_of_bounds() {
        let e = AddressOutOfBoundsException::new("too large");
        assert_eq!(e.message(), "too large");
        assert!(format!("{}", e).contains("out of bounds"));
    }

    #[test]
    fn test_address_out_of_bounds_for_offset() {
        let e = AddressOutOfBoundsException::for_offset("ram", 0xDEAD);
        assert!(format!("{}", e).contains("0xdead"));
        assert!(format!("{}", e).contains("ram"));
    }

    #[test]
    fn test_address_overflow() {
        let e = AddressOverflowException::add_overflow(0xFFFFFFFF, 1);
        assert!(format!("{}", e).contains("overflow"));
        assert!(format!("{}", e).contains("0xffffffff"));
    }

    #[test]
    fn test_address_overflow_subtract() {
        let e = AddressOverflowException::subtract_overflow(0, 1);
        assert!(format!("{}", e).contains("overflow"));
    }

    #[test]
    fn test_overflow_to_out_of_bounds_conversion() {
        let overflow = AddressOverflowException::new("test");
        let oob = AddressOutOfBoundsException::from(overflow);
        assert_eq!(oob.message(), "test");
    }

    #[test]
    fn test_segment_mismatch() {
        let e = SegmentMismatchException::different_segments(0x1000, 0x2000);
        assert!(format!("{}", e).contains("0x1000"));
        assert!(format!("{}", e).contains("0x2000"));
    }

    #[test]
    fn test_errors_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AddressFormatException>();
        assert_send_sync::<AddressOutOfBoundsException>();
        assert_send_sync::<AddressOverflowException>();
        assert_send_sync::<SegmentMismatchException>();
    }
}
