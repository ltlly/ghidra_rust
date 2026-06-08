//! Stack frame definition for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.listing.StackFrame`.
//!
//! Defines the [`StackFrame`] trait which describes a function's stack frame
//! layout including local variables, parameters, and saved registers.

use serde::{Deserialize, Serialize};

/// Indicator for a stack that grows negatively.
pub const GROWS_NEGATIVE: i32 = -1;
/// Indicator for a stack that grows positively.
pub const GROWS_POSITIVE: i32 = 1;
/// Indicator for an unknown stack parameter offset.
pub const UNKNOWN_PARAM_OFFSET: i32 = 128 * 1024;

/// Definition of a stack frame.
///
/// Corresponds to `ghidra.program.model.listing.StackFrame`.
///
/// All offsets into a stack are from a zero base. Usually negative offsets
/// are parameters and positive offsets are locals, but this depends on the
/// architecture's stack growth direction.
///
/// Each frame consists of:
/// - A **local section** (variables local to the function)
/// - A **parameter section** (function parameters)
/// - **Saved information** (return address, saved registers, etc.)
///
/// A frame grows negative if parameters are referenced with positive offsets
/// from 0, or positive if parameters are referenced with negative offsets.
pub trait StackFrame {
    /// Returns the size of this stack frame in bytes.
    fn get_frame_size(&self) -> i32;

    /// Returns the local portion of the stack frame in bytes.
    fn get_local_size(&self) -> i32;

    /// Returns the parameter portion of the stack frame in bytes.
    fn get_parameter_size(&self) -> i32;

    /// Returns the offset to the start of the parameters.
    fn get_parameter_offset(&self) -> i32;

    /// Returns `true` if the specified offset could correspond to a parameter.
    fn is_parameter_offset(&self, offset: i32) -> bool;

    /// Returns the return address stack offset.
    fn get_return_address_offset(&self) -> i32;

    /// Returns `true` if the stack grows in a negative direction.
    fn grows_negative(&self) -> bool;
}

/// Concrete stack frame data for serialization and storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackFrameData {
    /// Total frame size in bytes.
    pub frame_size: i32,
    /// Size of the local variable area.
    pub local_size: i32,
    /// Size of the parameter area.
    pub parameter_size: i32,
    /// Offset to the start of parameters.
    pub parameter_offset: i32,
    /// Offset of the return address within the frame.
    pub return_address_offset: i32,
    /// Whether the stack grows negatively.
    pub grows_negative: bool,
}

impl StackFrameData {
    /// Create a new stack frame data with the given configuration.
    pub fn new(
        frame_size: i32,
        local_size: i32,
        parameter_size: i32,
        return_address_offset: i32,
        grows_negative: bool,
    ) -> Self {
        let parameter_offset = if grows_negative {
            return_address_offset + (frame_size - local_size)
        } else {
            return_address_offset - parameter_size
        };
        Self {
            frame_size,
            local_size,
            parameter_size,
            parameter_offset,
            return_address_offset,
            grows_negative,
        }
    }

    /// Create an empty (zero-size) stack frame.
    pub fn empty(grows_negative: bool) -> Self {
        Self {
            frame_size: 0,
            local_size: 0,
            parameter_size: 0,
            parameter_offset: 0,
            return_address_offset: 0,
            grows_negative,
        }
    }
}

impl StackFrame for StackFrameData {
    fn get_frame_size(&self) -> i32 {
        self.frame_size
    }

    fn get_local_size(&self) -> i32 {
        self.local_size
    }

    fn get_parameter_size(&self) -> i32 {
        self.parameter_size
    }

    fn get_parameter_offset(&self) -> i32 {
        self.parameter_offset
    }

    fn is_parameter_offset(&self, offset: i32) -> bool {
        if self.grows_negative {
            offset >= self.parameter_offset
                && offset < self.parameter_offset + self.parameter_size
        } else {
            offset >= self.parameter_offset
                && offset < self.parameter_offset + self.parameter_size
        }
    }

    fn get_return_address_offset(&self) -> i32 {
        self.return_address_offset
    }

    fn grows_negative(&self) -> bool {
        self.grows_negative
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_frame_grows_negative() {
        let frame = StackFrameData::new(16, 8, 4, 12, true);
        assert!(frame.grows_negative());
        assert_eq!(frame.get_frame_size(), 16);
        assert_eq!(frame.get_local_size(), 8);
        assert_eq!(frame.get_parameter_size(), 4);
    }

    #[test]
    fn test_stack_frame_grows_positive() {
        let frame = StackFrameData::new(16, 8, 4, -4, false);
        assert!(!frame.grows_negative());
        assert_eq!(frame.get_frame_size(), 16);
    }

    #[test]
    fn test_stack_frame_empty() {
        let frame = StackFrameData::empty(true);
        assert_eq!(frame.get_frame_size(), 0);
        assert_eq!(frame.get_local_size(), 0);
        assert_eq!(frame.get_parameter_size(), 0);
    }

    #[test]
    fn test_stack_frame_is_parameter_offset() {
        let frame = StackFrameData::new(16, 8, 4, 12, true);
        assert!(frame.is_parameter_offset(20)); // parameter_offset = 12 + (16 - 8) = 20
    }

    #[test]
    fn test_stack_frame_unknown_param_offset() {
        assert_eq!(UNKNOWN_PARAM_OFFSET, 131072);
    }
}
