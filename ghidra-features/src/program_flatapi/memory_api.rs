//! Memory operations for the Flat Program API.
//!
//! Ported from `ghidra.program.flatapi.FlatProgramAPI` memory-related methods:
//! - Memory block management (create, get, remove)
//! - Byte-level read/write (`getByte`, `setByte`, `getBytes`, `setBytes`)
//! - Typed read/write (`getShort`, `getInt`, `getLong`, `getFloat`, `getDouble`)
//! - Address utilities (`toAddr`, `createAddressSet`, `getAddressFactory`)

use super::types::*;

/// Memory map that holds all memory blocks for a program.
///
/// Ported from `ghidra.program.model.mem.Memory`.
#[derive(Debug, Clone, Default)]
pub struct Memory {
    blocks: Vec<MemoryBlock>,
}

impl Memory {
    pub fn new() -> Self {
        Self::default()
    }

    // -----------------------------------------------------------------------
    // Block management
    // -----------------------------------------------------------------------

    /// Create an uninitialized memory block.
    pub fn create_uninitialized_block(
        &mut self,
        name: &str,
        start: Address,
        length: u64,
        _overlay: bool,
    ) -> &MemoryBlock {
        let block = MemoryBlock::new_uninitialized(name, start, length);
        self.blocks.push(block);
        self.blocks.last().unwrap()
    }

    /// Create an initialized memory block from a byte slice.
    pub fn create_initialized_block(
        &mut self,
        name: &str,
        start: Address,
        input: &[u8],
        length: u64,
        overlay: bool,
    ) -> &MemoryBlock {
        let block = MemoryBlock::new_initialized_with_length(name, start, input, length, overlay);
        self.blocks.push(block);
        self.blocks.last().unwrap()
    }

    /// Return a reference to the block with the given name.
    pub fn get_block_by_name(&self, name: &str) -> Option<&MemoryBlock> {
        self.blocks.iter().find(|b| b.name == name)
    }

    /// Return a mutable reference to the block with the given name.
    pub fn get_block_by_name_mut(&mut self, name: &str) -> Option<&mut MemoryBlock> {
        self.blocks.iter_mut().find(|b| b.name == name)
    }

    /// Return a reference to the block containing the given address.
    pub fn get_block_at(&self, address: Address) -> Option<&MemoryBlock> {
        self.blocks.iter().find(|b| b.contains(address))
    }

    /// Return all blocks.
    pub fn get_blocks(&self) -> &[MemoryBlock] {
        &self.blocks
    }

    /// Remove a block by name.  Returns true if a block was removed.
    pub fn remove_block(&mut self, name: &str) -> bool {
        let len_before = self.blocks.len();
        self.blocks.retain(|b| b.name != name);
        self.blocks.len() != len_before
    }

    // -----------------------------------------------------------------------
    // Address range helpers
    // -----------------------------------------------------------------------

    /// Return the minimum address across all blocks.
    pub fn get_min_address(&self) -> Option<Address> {
        self.blocks.iter().map(|b| b.start).min()
    }

    /// Return the maximum address across all blocks (last byte of the highest block).
    pub fn get_max_address(&self) -> Option<Address> {
        self.blocks.iter().map(|b| b.end()).max()
    }

    /// Return an `AddressSet` covering all loaded and initialized memory.
    pub fn get_loaded_and_initialized_address_set(&self) -> AddressSet {
        let mut set = AddressSet::new();
        for block in &self.blocks {
            if block.initialized && !block.overlay {
                set.add_range(block.start, block.start.add(block.length - 1));
            }
        }
        set
    }

    /// Check whether the given address falls within any memory block.
    pub fn contains(&self, address: Address) -> bool {
        self.blocks.iter().any(|b| b.contains(address))
    }

    // -----------------------------------------------------------------------
    // Byte-level read/write
    // -----------------------------------------------------------------------

    /// Return the block containing the address, as a mutable reference.
    fn block_mut_for(&mut self, address: Address) -> Result<&mut MemoryBlock, MemoryAccessException> {
        self.blocks
            .iter_mut()
            .find(|b| b.contains(address))
            .ok_or(MemoryAccessException::new("No memory block at address"))
    }

    fn block_for(&self, address: Address) -> Result<&MemoryBlock, MemoryAccessException> {
        self.blocks
            .iter()
            .find(|b| b.contains(address))
            .ok_or(MemoryAccessException::new("No memory block at address"))
    }

    /// Read a single signed byte.
    pub fn get_byte(&self, address: Address) -> Result<i8, MemoryAccessException> {
        let block = self.block_for(address)?;
        let offset = (address.offset - block.start.offset) as usize;
        if offset >= block.data.len() {
            return Err(MemoryAccessException::new("Offset out of range"));
        }
        Ok(block.data[offset] as i8)
    }

    /// Write a single byte.
    pub fn set_byte(&mut self, address: Address, value: i8) -> Result<(), MemoryAccessException> {
        let block = self.block_mut_for(address)?;
        let offset = (address.offset - block.start.offset) as usize;
        if offset >= block.data.len() {
            return Err(MemoryAccessException::new("Offset out of range"));
        }
        block.data[offset] = value as u8;
        Ok(())
    }

    /// Read `length` signed bytes starting at `address`.
    pub fn get_bytes(
        &self,
        address: Address,
        length: usize,
    ) -> Result<Vec<u8>, MemoryAccessException> {
        let block = self.block_for(address)?;
        let offset = (address.offset - block.start.offset) as usize;
        if offset + length > block.data.len() {
            return Err(MemoryAccessException::new("Read exceeds block bounds"));
        }
        Ok(block.data[offset..offset + length].to_vec())
    }

    /// Write bytes starting at `address`.
    pub fn set_bytes(
        &mut self,
        address: Address,
        values: &[u8],
    ) -> Result<(), MemoryAccessException> {
        let block = self.block_mut_for(address)?;
        let offset = (address.offset - block.start.offset) as usize;
        if offset + values.len() > block.data.len() {
            return Err(MemoryAccessException::new("Write exceeds block bounds"));
        }
        block.data[offset..offset + values.len()].copy_from_slice(values);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Typed read/write
    // -----------------------------------------------------------------------

    /// Read a big-endian signed 16-bit short.
    pub fn get_short(&self, address: Address) -> Result<i16, MemoryAccessException> {
        let bytes = self.get_bytes(address, 2)?;
        Ok(i16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// Write a big-endian signed 16-bit short.
    pub fn set_short(&mut self, address: Address, value: i16) -> Result<(), MemoryAccessException> {
        self.set_bytes(address, &value.to_be_bytes())
    }

    /// Read a big-endian signed 32-bit integer.
    pub fn get_int(&self, address: Address) -> Result<i32, MemoryAccessException> {
        let bytes = self.get_bytes(address, 4)?;
        Ok(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Write a big-endian signed 32-bit integer.
    pub fn set_int(&mut self, address: Address, value: i32) -> Result<(), MemoryAccessException> {
        self.set_bytes(address, &value.to_be_bytes())
    }

    /// Read a big-endian signed 64-bit long.
    pub fn get_long(&self, address: Address) -> Result<i64, MemoryAccessException> {
        let bytes = self.get_bytes(address, 8)?;
        Ok(i64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Write a big-endian signed 64-bit long.
    pub fn set_long(&mut self, address: Address, value: i64) -> Result<(), MemoryAccessException> {
        self.set_bytes(address, &value.to_be_bytes())
    }

    /// Read a 32-bit IEEE 754 float (via `get_int` + bit cast).
    pub fn get_float(&self, address: Address) -> Result<f32, MemoryAccessException> {
        let bits = self.get_int(address)?;
        Ok(f32::from_bits(bits as u32))
    }

    /// Write a 32-bit IEEE 754 float.
    pub fn set_float(&mut self, address: Address, value: f32) -> Result<(), MemoryAccessException> {
        self.set_int(address, value.to_bits() as i32)
    }

    /// Read a 64-bit IEEE 754 double (via `get_long` + bit cast).
    pub fn get_double(&self, address: Address) -> Result<f64, MemoryAccessException> {
        let bits = self.get_long(address)?;
        Ok(f64::from_bits(bits as u64))
    }

    /// Write a 64-bit IEEE 754 double.
    pub fn set_double(&mut self, address: Address, value: f64) -> Result<(), MemoryAccessException> {
        self.set_long(address, value.to_bits() as i64)
    }

    // -----------------------------------------------------------------------
    // Byte search
    // -----------------------------------------------------------------------

    /// Find the first occurrence of `pattern` starting from `start`.
    ///
    /// Returns the address of the match, or `None` if not found.
    pub fn find_bytes(
        &self,
        start: Address,
        pattern: &[u8],
    ) -> Option<Address> {
        for block in &self.blocks {
            if !block.initialized || block.overlay {
                continue;
            }
            let search_from = if start.offset >= block.start.offset && start.offset < block.end().offset {
                (start.offset - block.start.offset) as usize
            } else if start.offset < block.start.offset {
                0
            } else {
                continue;
            };
            let data = &block.data[search_from..];
            if let Some(pos) = find_subsequence(data, pattern) {
                return Some(block.start.add((search_from + pos) as u64));
            }
        }
        None
    }
}

// ============================================================================
// MemoryAccessException
// ============================================================================

/// Thrown when a memory access is invalid (e.g. reading uninitialized memory).
///
/// Ported from `ghidra.program.model.mem.MemoryAccessException`.
#[derive(Debug, Clone)]
pub struct MemoryAccessException {
    message: String,
}

impl MemoryAccessException {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for MemoryAccessException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MemoryAccessException: {}", self.message)
    }
}

impl std::error::Error for MemoryAccessException {}

// ============================================================================
// AddressFactory
// ============================================================================

/// Factory for creating addresses.
///
/// Ported from `ghidra.program.model.address.AddressFactory`.
#[derive(Debug, Clone, Default)]
pub struct AddressFactory {
    default_space_name: String,
}

impl AddressFactory {
    pub fn new() -> Self {
        Self {
            default_space_name: "ram".to_string(),
        }
    }

    /// Get an address in the default address space at the given offset.
    pub fn get_default_address(&self, offset: u64) -> Address {
        Address::new(offset)
    }

    /// Get an address in a named address space.
    pub fn get_address(&self, space: &str, offset: u64) -> Address {
        // Leak the space name to get a &'static str -- acceptable for the
        // small number of address spaces in a program.
        let static_space: &'static str = Box::leak(space.to_string().into_boxed_str());
        Address::in_space(static_space, offset)
    }

    /// Return the name of the default address space.
    pub fn get_default_space_name(&self) -> &str {
        &self.default_space_name
    }
}

// ============================================================================
// Utility
// ============================================================================

/// Find the first occurrence of `needle` in `haystack`.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_block_create_and_read() {
        let mut memory = Memory::new();
        let start = Address::new(0x1000);
        let block = memory.create_initialized_block(".text", start, &[0x55, 0x48, 0x89], 3, false);
        assert_eq!(block.name, ".text");
        assert_eq!(block.length, 3);

        let byte = memory.get_byte(Address::new(0x1000)).unwrap();
        assert_eq!(byte, 0x55i8);
    }

    #[test]
    fn test_memory_read_write_byte() {
        let mut memory = Memory::new();
        memory.create_initialized_block(".data", Address::new(0x2000), &[0; 256], 256, false);
        memory.set_byte(Address::new(0x2000), 42).unwrap();
        assert_eq!(memory.get_byte(Address::new(0x2000)).unwrap(), 42);
    }

    #[test]
    fn test_memory_read_write_int() {
        let mut memory = Memory::new();
        memory.create_initialized_block(".data", Address::new(0x3000), &[0; 64], 64, false);
        memory.set_int(Address::new(0x3000), 0x12345678u32 as i32).unwrap();
        let val = memory.get_int(Address::new(0x3000)).unwrap();
        assert_eq!(val as u32, 0x12345678);
    }

    #[test]
    fn test_memory_read_write_long() {
        let mut memory = Memory::new();
        memory.create_initialized_block(".data", Address::new(0x4000), &[0; 64], 64, false);
        memory.set_long(Address::new(0x4000), 0x0102030405060708i64).unwrap();
        assert_eq!(
            memory.get_long(Address::new(0x4000)).unwrap(),
            0x0102030405060708i64
        );
    }

    #[test]
    fn test_memory_read_write_float() {
        let mut memory = Memory::new();
        memory.create_initialized_block(".data", Address::new(0x5000), &[0; 64], 64, false);
        memory.set_float(Address::new(0x5000), 3.14f32).unwrap();
        let val = memory.get_float(Address::new(0x5000)).unwrap();
        assert!((val - 3.14f32).abs() < 1e-6);
    }

    #[test]
    fn test_memory_read_write_double() {
        let mut memory = Memory::new();
        memory.create_initialized_block(".data", Address::new(0x6000), &[0; 64], 64, false);
        memory.set_double(Address::new(0x6000), 2.718281828f64).unwrap();
        let val = memory.get_double(Address::new(0x6000)).unwrap();
        assert!((val - 2.718281828f64).abs() < 1e-9);
    }

    #[test]
    fn test_memory_find_bytes() {
        let mut memory = Memory::new();
        let data = vec![0x00, 0x55, 0x48, 0x89, 0xe5, 0x00];
        memory.create_initialized_block(".text", Address::new(0x1000), &data, data.len() as u64, false);
        let found = memory.find_bytes(Address::new(0x1000), &[0x55, 0x48]);
        assert_eq!(found, Some(Address::new(0x1001)));
    }

    #[test]
    fn test_memory_get_blocks() {
        let mut memory = Memory::new();
        memory.create_initialized_block(".text", Address::new(0x1000), &[0; 256], 256, false);
        memory.create_initialized_block(".data", Address::new(0x2000), &[0; 128], 128, false);
        assert_eq!(memory.get_blocks().len(), 2);
    }

    #[test]
    fn test_memory_remove_block() {
        let mut memory = Memory::new();
        memory.create_initialized_block(".text", Address::new(0x1000), &[0; 256], 256, false);
        assert!(memory.remove_block(".text"));
        assert!(memory.get_blocks().is_empty());
    }

    #[test]
    fn test_memory_access_exception() {
        let memory = Memory::new();
        let result = memory.get_byte(Address::new(0x9999));
        assert!(result.is_err());
    }

    #[test]
    fn test_memory_contains() {
        let mut memory = Memory::new();
        memory.create_initialized_block(".text", Address::new(0x1000), &[0; 256], 256, false);
        assert!(memory.contains(Address::new(0x1000)));
        assert!(memory.contains(Address::new(0x10FF)));
        assert!(!memory.contains(Address::new(0x2000)));
    }

    #[test]
    fn test_address_factory() {
        let factory = AddressFactory::new();
        let addr = factory.get_default_address(0x400000);
        assert_eq!(addr.offset, 0x400000);
        assert_eq!(addr.space_name, "ram");
    }
}
