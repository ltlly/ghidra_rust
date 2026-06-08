//! Memory fault handler interface.
//!
//! Ported from Java: `ghidra.pcode.memstate.MemoryFaultHandler`.

use ghidra_core::addr::Address;

/// Trait for handling memory faults during emulation.
///
/// Implementations can customize how uninitialized reads and unknown address
/// accesses are handled.
pub trait MemoryFaultHandler {
    /// An attempt has been made to read uninitialized memory.
    ///
    /// # Arguments
    /// * `address` - uninitialized storage address (memory, register or unique)
    /// * `size` - number of uninitialized bytes
    /// * `buf` - storage buffer
    /// * `buf_offset` - read offset within buffer
    ///
    /// # Returns
    /// `true` if data should be treated as initialized
    fn uninitialized_read(
        &self,
        address: Address,
        size: usize,
        buf: &mut [u8],
        buf_offset: usize,
    ) -> bool;

    /// Unable to translate the specified address.
    ///
    /// # Arguments
    /// * `address` - address which failed to be translated
    /// * `write` - true if memory operation was a write vs. read
    ///
    /// # Returns
    /// `true` if fault was handled
    fn unknown_address(&self, address: Address, write: bool) -> bool;
}

/// Default fault handler that initializes uninitialized reads to zero.
#[derive(Debug, Clone, Copy)]
pub struct DefaultMemoryFaultHandler;

impl MemoryFaultHandler for DefaultMemoryFaultHandler {
    fn uninitialized_read(
        &self,
        _address: Address,
        size: usize,
        buf: &mut [u8],
        buf_offset: usize,
    ) -> bool {
        // Initialize to zero and treat as initialized
        for i in 0..size {
            if buf_offset + i < buf.len() {
                buf[buf_offset + i] = 0;
            }
        }
        true
    }

    fn unknown_address(&self, _address: Address, _write: bool) -> bool {
        // Don't handle the fault
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_handler_initializes_to_zero() {
        let handler = DefaultMemoryFaultHandler;
        let mut buf = vec![0xFF; 10];
        let result = handler.uninitialized_read(Address::new(0x100), 5, &mut buf, 0);
        assert!(result);
        assert_eq!(&buf[..5], &[0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_default_handler_unknown_address() {
        let handler = DefaultMemoryFaultHandler;
        assert!(!handler.unknown_address(Address::new(0x100), false));
    }
}
