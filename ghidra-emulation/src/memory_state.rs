//! MemoryState interface for the legacy emulation framework.
//!
//! Ported from Java: `ghidra.pcode.memstate.MemoryState`.
//!
//! A [`MemoryState`] provides the main interface for reading and writing
//! values during emulation. It associates [`MemoryBank`]s with specific
//! address spaces and provides convenience methods for register and varnode
//! access.

use num_bigint::BigInt;
use num_traits::ToPrimitive;

use super::memstate::MemoryBank;

/// Errors that can occur during memory state operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum MemoryStateError {
    /// No memory bank is registered for the given address space.
    #[error("no memory bank registered for address space: {0}")]
    NoBankForSpace(String),

    /// A memory fault occurred.
    #[error("memory fault at space={space}, offset=0x{offset:x}: {msg}")]
    MemoryFault {
        /// The address space name.
        space: String,
        /// The offset within the space.
        offset: u64,
        /// Description of the fault.
        msg: String,
    },

    /// An invalid operation was attempted.
    #[error("invalid operation: {0}")]
    InvalidOperation(String),
}

/// Result type for memory state operations.
pub type MemoryStateResult<T> = Result<T, MemoryStateError>;

/// The main interface for reading and writing values during emulation.
///
/// MemoryBanks are registered for specific address spaces. All read/write
/// operations are delegated to the appropriate bank.
///
/// Ported from Java: `ghidra.pcode.memstate.MemoryState` (deprecated since 12.1).
pub trait MemoryState {
    /// Register a [`MemoryBank`] for an address space.
    ///
    /// Each address space used during emulation must be registered separately.
    fn set_memory_bank(&mut self, space_name: &str, bank: MemoryBank);

    /// Get a reference to the [`MemoryBank`] for the given address space.
    fn get_memory_bank(&self, space_name: &str) -> Option<&MemoryBank>;

    /// Get a mutable reference to the [`MemoryBank`] for the given address space.
    fn get_memory_bank_mut(&mut self, space_name: &str) -> Option<&mut MemoryBank>;

    /// Set a value at the given address space and offset.
    fn set_value(
        &mut self,
        space_name: &str,
        offset: u64,
        size: usize,
        value: u64,
    ) -> MemoryStateResult<()>;

    /// Get a value from the given address space and offset.
    fn get_value(
        &mut self,
        space_name: &str,
        offset: u64,
        size: usize,
    ) -> MemoryStateResult<u64>;

    /// Set a BigInt value at the given address space and offset.
    fn set_bigint_value(
        &mut self,
        space_name: &str,
        offset: u64,
        size: usize,
        value: &BigInt,
    ) -> MemoryStateResult<()>;

    /// Get a BigInt value from the given address space and offset.
    fn get_bigint_value(
        &mut self,
        space_name: &str,
        offset: u64,
        size: usize,
        signed: bool,
    ) -> MemoryStateResult<BigInt>;

    /// Read a chunk of bytes from the given address space and offset.
    fn get_chunk(
        &mut self,
        space_name: &str,
        offset: u64,
        size: usize,
        stop_on_uninitialized: bool,
    ) -> MemoryStateResult<usize>;

    /// Write a chunk of bytes to the given address space and offset.
    fn set_chunk(
        &mut self,
        space_name: &str,
        offset: u64,
        data: &[u8],
    ) -> MemoryStateResult<()>;

    /// Set the initialization state of a byte range.
    fn set_initialized(
        &mut self,
        space_name: &str,
        offset: u64,
        size: usize,
        initialized: bool,
    ) -> MemoryStateResult<()>;
}

/// A default implementation of [`MemoryState`] backed by a map of
/// [`MemoryBank`]s keyed by address space name.
#[derive(Debug)]
pub struct DefaultMemoryState {
    /// Memory banks keyed by address space name.
    banks: std::collections::HashMap<String, MemoryBank>,
}

impl DefaultMemoryState {
    /// Create a new empty memory state.
    pub fn new() -> Self {
        Self {
            banks: std::collections::HashMap::new(),
        }
    }

    /// Get the number of registered memory banks.
    pub fn bank_count(&self) -> usize {
        self.banks.len()
    }

    /// Check if a memory bank is registered for the given space.
    pub fn has_bank(&self, space_name: &str) -> bool {
        self.banks.contains_key(space_name)
    }
}

impl Default for DefaultMemoryState {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryState for DefaultMemoryState {
    fn set_memory_bank(&mut self, space_name: &str, bank: MemoryBank) {
        self.banks.insert(space_name.to_string(), bank);
    }

    fn get_memory_bank(&self, space_name: &str) -> Option<&MemoryBank> {
        self.banks.get(space_name)
    }

    fn get_memory_bank_mut(&mut self, space_name: &str) -> Option<&mut MemoryBank> {
        self.banks.get_mut(space_name)
    }

    fn set_value(
        &mut self,
        space_name: &str,
        offset: u64,
        size: usize,
        value: u64,
    ) -> MemoryStateResult<()> {
        let bank = self
            .banks
            .get_mut(space_name)
            .ok_or_else(|| MemoryStateError::NoBankForSpace(space_name.to_string()))?;

        let mut buf = vec![0u8; size];
        MemoryBank::deconstruct_value(&mut buf, 0, value, size, bank.is_big_endian());
        bank.set_chunk(offset, &buf);
        Ok(())
    }

    fn get_value(
        &mut self,
        space_name: &str,
        offset: u64,
        size: usize,
    ) -> MemoryStateResult<u64> {
        let bank = self
            .banks
            .get_mut(space_name)
            .ok_or_else(|| MemoryStateError::NoBankForSpace(space_name.to_string()))?;

        let mut buf = vec![0u8; size];
        bank.get_chunk(offset, size, &mut buf, false);
        Ok(MemoryBank::construct_value(&buf, 0, size, bank.is_big_endian()))
    }

    fn set_bigint_value(
        &mut self,
        space_name: &str,
        offset: u64,
        size: usize,
        value: &BigInt,
    ) -> MemoryStateResult<()> {
        let bank = self
            .banks
            .get_mut(space_name)
            .ok_or_else(|| MemoryStateError::NoBankForSpace(space_name.to_string()))?;

        let mut buf = vec![0u8; size];
        let mut val = value.clone();
        if bank.is_big_endian() {
            for i in (0..size).rev() {
                buf[i] = (&val & BigInt::from(0xFF)).to_u8().unwrap_or(0);
                val >>= 8;
            }
        } else {
            for i in 0..size {
                buf[i] = (&val & BigInt::from(0xFF)).to_u8().unwrap_or(0);
                val >>= 8;
            }
        }
        bank.set_chunk(offset, &buf);
        Ok(())
    }

    fn get_bigint_value(
        &mut self,
        space_name: &str,
        offset: u64,
        size: usize,
        signed: bool,
    ) -> MemoryStateResult<BigInt> {
        let bank = self
            .banks
            .get_mut(space_name)
            .ok_or_else(|| MemoryStateError::NoBankForSpace(space_name.to_string()))?;

        let mut buf = vec![0u8; size];
        bank.get_chunk(offset, size, &mut buf, false);

        let mut result = BigInt::from(0u32);
        if bank.is_big_endian() {
            for i in 0..size {
                result <<= 8;
                result |= BigInt::from(buf[i]);
            }
        } else {
            for i in (0..size).rev() {
                result <<= 8;
                result |= BigInt::from(buf[i]);
            }
        }

        if signed && size > 0 {
            let sign_bit = size * 8 - 1;
            let sign_mask = BigInt::from(1u32) << sign_bit;
            if &result & &sign_mask != BigInt::from(0u32) {
                let full_mask = (BigInt::from(1u32) << (size * 8)) - BigInt::from(1u32);
                result = result - full_mask - BigInt::from(1u32);
            }
        }

        Ok(result)
    }

    fn get_chunk(
        &mut self,
        space_name: &str,
        offset: u64,
        size: usize,
        stop_on_uninitialized: bool,
    ) -> MemoryStateResult<usize> {
        let bank = self
            .banks
            .get_mut(space_name)
            .ok_or_else(|| MemoryStateError::NoBankForSpace(space_name.to_string()))?;

        let mut buf = vec![0u8; size];
        let read = bank.get_chunk(offset, size, &mut buf, stop_on_uninitialized);
        Ok(read)
    }

    fn set_chunk(
        &mut self,
        space_name: &str,
        offset: u64,
        data: &[u8],
    ) -> MemoryStateResult<()> {
        let bank = self
            .banks
            .get_mut(space_name)
            .ok_or_else(|| MemoryStateError::NoBankForSpace(space_name.to_string()))?;

        bank.set_chunk(offset, data);
        Ok(())
    }

    fn set_initialized(
        &mut self,
        space_name: &str,
        offset: u64,
        size: usize,
        initialized: bool,
    ) -> MemoryStateResult<()> {
        let bank = self
            .banks
            .get_mut(space_name)
            .ok_or_else(|| MemoryStateError::NoBankForSpace(space_name.to_string()))?;

        bank.set_initialized(offset, size, initialized);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_memory_state_creation() {
        let state = DefaultMemoryState::new();
        assert_eq!(state.bank_count(), 0);
        assert!(!state.has_bank("RAM"));
    }

    #[test]
    fn test_set_memory_bank() {
        let mut state = DefaultMemoryState::new();
        let bank = MemoryBank::new("RAM", false, 256);
        state.set_memory_bank("RAM", bank);

        assert_eq!(state.bank_count(), 1);
        assert!(state.has_bank("RAM"));
    }

    #[test]
    fn test_set_get_value() {
        let mut state = DefaultMemoryState::new();
        state.set_memory_bank("RAM", MemoryBank::new("RAM", false, 256));

        state.set_value("RAM", 0x100, 4, 0x12345678).unwrap();
        let val = state.get_value("RAM", 0x100, 4).unwrap();
        assert_eq!(val, 0x12345678);
    }

    #[test]
    fn test_set_get_value_big_endian() {
        let mut state = DefaultMemoryState::new();
        state.set_memory_bank("RAM", MemoryBank::new("RAM", true, 256));

        state.set_value("RAM", 0x100, 4, 0x12345678).unwrap();
        let val = state.get_value("RAM", 0x100, 4).unwrap();
        assert_eq!(val, 0x12345678);
    }

    #[test]
    fn test_no_bank_error() {
        let mut state = DefaultMemoryState::new();
        let result = state.set_value("RAM", 0x100, 4, 42);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_get_chunk() {
        let mut state = DefaultMemoryState::new();
        state.set_memory_bank("RAM", MemoryBank::new("RAM", false, 256));

        let data = vec![1, 2, 3, 4, 5];
        state.set_chunk("RAM", 0x200, &data).unwrap();

        let mut buf = vec![0u8; 5];
        let bank = state.get_memory_bank_mut("RAM").unwrap();
        let read = bank.get_chunk(0x200, 5, &mut buf, false);
        assert_eq!(read, 5);
        assert_eq!(buf, data);
    }

    #[test]
    fn test_set_initialized() {
        let mut state = DefaultMemoryState::new();
        state.set_memory_bank("RAM", MemoryBank::new("RAM", false, 256));

        state.set_value("RAM", 0x100, 3, 0x030201).unwrap();
        state.set_initialized("RAM", 0x100, 3, false).unwrap();

        // Reading uninitialized should trigger fault handler (zero-init)
        let val = state.get_value("RAM", 0x100, 3).unwrap();
        assert_eq!(val, 0);
    }
}
