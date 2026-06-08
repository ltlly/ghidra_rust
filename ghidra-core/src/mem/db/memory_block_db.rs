//! Database-backed memory block.
//!
//! Mirrors `ghidra.program.database.mem.MemoryBlockDB`. Each block is
//! composed of one or more [`SubMemoryBlock`] segments that handle the
//! actual byte storage. The block itself manages address range, name,
//! flags, and delegates byte I/O to the appropriate sub-block.

use crate::addr::Address;
use crate::error::GhidraError;
use crate::mem::db::sub_memory_block::{SubMemoryBlock, SubMemoryBlockType};
use crate::mem::{
    ByteMappingScheme, MemoryBlockType, FLAG_ARTIFICIAL, FLAG_EXECUTE, FLAG_READ, FLAG_VOLATILE,
    FLAG_WRITE,
};

// ============================================================================
// MemoryBlockDB
// ============================================================================

/// A database-backed memory block.
///
/// Mirrors `ghidra.program.database.mem.MemoryBlockDB`. Each block is
/// identified by a unique `id` (record key) and is composed of sub-blocks
/// that handle actual byte storage.
#[derive(Debug)]
pub struct MemoryBlockDB {
    /// Unique block identifier (record key).
    id: u64,
    /// Block name.
    name: String,
    /// Start address.
    start_address: Address,
    /// End address (inclusive).
    end_address: Address,
    /// Block length in bytes.
    length: u64,
    /// Permission and attribute flags.
    flags: u8,
    /// Whether the block has initialized data.
    initialized: bool,
    /// Whether the block is mapped (bit or byte mapped).
    mapped: bool,
    /// Optional mapped source base address.
    mapped_source: Option<Address>,
    /// Optional byte mapping scheme.
    mapping_scheme: Option<ByteMappingScheme>,
    /// Whether the block has been invalidated.
    invalid: bool,
    /// Comment text.
    comment: String,
    /// Source name.
    source_name: String,
    /// Sub-blocks composing this block.
    sub_blocks: Vec<Box<dyn SubMemoryBlock>>,
    /// Cached last-accessed sub-block index.
    last_sub_block_index: Option<usize>,
    /// List of blocks that map onto this block (rebuilt on address set refresh).
    mapped_blocks: Vec<u64>,
}

impl MemoryBlockDB {
    /// Create a new MemoryBlockDB.
    ///
    /// This is typically called by the adapter during database loading.
    pub fn new(
        id: u64,
        name: String,
        start_address: Address,
        end_address: Address,
        length: u64,
        flags: u8,
        initialized: bool,
        mapped: bool,
        mapped_source: Option<Address>,
        mapping_scheme: Option<ByteMappingScheme>,
    ) -> Self {
        Self {
            id,
            name,
            start_address,
            end_address,
            length,
            flags,
            initialized,
            mapped,
            mapped_source,
            mapping_scheme,
            invalid: false,
            comment: String::new(),
            source_name: String::new(),
            sub_blocks: Vec::new(),
            last_sub_block_index: None,
            mapped_blocks: Vec::new(),
        }
    }

    // ---- identity ----

    /// Returns the block's unique identifier (record key).
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Returns the block name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the start address.
    pub fn start(&self) -> Address {
        self.start_address
    }

    /// Returns the end address (inclusive).
    pub fn end(&self) -> Address {
        self.end_address
    }

    /// Returns the block length in bytes.
    pub fn size(&self) -> u64 {
        self.length
    }

    /// Returns the permission and attribute flags.
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Returns the block comment.
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Returns the source name.
    pub fn source_name(&self) -> &str {
        &self.source_name
    }

    // ---- state queries ----

    /// Whether the block is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Whether the block is mapped (bit or byte).
    pub fn is_mapped(&self) -> bool {
        self.mapped
    }

    /// Whether the block resides in an overlay address space.
    pub fn is_overlay(&self) -> bool {
        false // simplified; overlay detection requires address space info
    }

    /// Whether the block is loaded in memory.
    pub fn is_loaded(&self) -> bool {
        true // simplified
    }

    /// Whether the block is the EXTERNAL block.
    pub fn is_external_block(&self) -> bool {
        self.name == "EXTERNAL"
    }

    /// Whether the block has been invalidated.
    pub fn is_invalid(&self) -> bool {
        self.invalid
    }

    // ---- permission checks ----

    /// Whether this block is readable.
    pub fn is_read(&self) -> bool {
        (self.flags & FLAG_READ) != 0
    }

    /// Whether this block is writable.
    pub fn is_write(&self) -> bool {
        (self.flags & FLAG_WRITE) != 0
    }

    /// Whether this block is executable.
    pub fn is_execute(&self) -> bool {
        (self.flags & FLAG_EXECUTE) != 0
    }

    /// Whether this block is volatile.
    pub fn is_volatile(&self) -> bool {
        (self.flags & FLAG_VOLATILE) != 0
    }

    /// Whether this block is artificial.
    pub fn is_artificial(&self) -> bool {
        (self.flags & FLAG_ARTIFICIAL) != 0
    }

    // ---- type queries ----

    /// Returns the memory block type.
    pub fn block_type(&self) -> MemoryBlockType {
        if let Some(first) = self.sub_blocks.first() {
            first.block_type()
        } else if self.mapped {
            MemoryBlockType::Default // fallback
        } else {
            MemoryBlockType::Default
        }
    }

    /// Returns the mapped source base address, if any.
    pub fn mapped_source_base(&self) -> Option<Address> {
        self.mapped_source
    }

    /// Returns the byte mapping scheme, if any.
    pub fn byte_mapping_scheme(&self) -> Option<&ByteMappingScheme> {
        self.mapping_scheme.as_ref()
    }

    // ---- address containment ----

    /// Returns true if `addr` falls within this block.
    pub fn contains(&self, addr: &Address) -> bool {
        addr.offset >= self.start_address.offset && addr.offset <= self.end_address.offset
    }

    /// Returns the block-relative offset for the given address.
    /// Errors if the address is not in this block.
    pub fn block_offset(&self, addr: &Address) -> Result<u64, GhidraError> {
        if !self.contains(addr) {
            return Err(GhidraError::MemoryError(format!(
                "Address {} not contained in block '{}'",
                addr, self.name
            )));
        }
        Ok(addr.offset - self.start_address.offset)
    }

    // ---- byte I/O ----

    /// Read a single byte at the given address.
    pub fn get_byte_at(&self, addr: &Address) -> Result<u8, GhidraError> {
        self.check_valid()?;
        let offset = self.block_offset(addr)?;
        self.get_byte_at_offset(offset)
    }

    /// Read a single byte at the given block-relative offset.
    pub fn get_byte_at_offset(&self, offset: u64) -> Result<u8, GhidraError> {
        let sub = self.find_sub_block(offset)?;
        sub.get_byte(offset)
    }

    /// Read bytes starting at `addr` into `buf[off..off+len]`.
    /// Returns the number of bytes actually read.
    pub fn get_bytes_at(
        &self,
        addr: &Address,
        buf: &mut [u8],
        off: usize,
        len: usize,
    ) -> Result<usize, GhidraError> {
        self.check_valid()?;
        let offset = self.block_offset(addr)?;
        self.get_bytes_at_offset(offset, buf, off, len)
    }

    /// Read bytes starting at block-relative offset into `buf[off..off+len]`.
    pub fn get_bytes_at_offset(
        &self,
        offset: u64,
        buf: &mut [u8],
        off: usize,
        len: usize,
    ) -> Result<usize, GhidraError> {
        if off + len > buf.len() {
            return Err(GhidraError::MemoryError("Buffer bounds exceeded".into()));
        }
        if offset >= self.length {
            return Err(GhidraError::MemoryError("Offset beyond block end".into()));
        }

        let clamped_len = (len as u64).min(self.length - offset) as usize;
        let mut total_copied = 0;

        while total_copied < clamped_len {
            let cur_offset = offset + total_copied as u64;
            let sub = self.find_sub_block(cur_offset)?;
            let remaining = clamped_len - total_copied;
            let n = sub.get_bytes(cur_offset, buf, off + total_copied, remaining)?;
            if n == 0 {
                break;
            }
            total_copied += n;
        }

        Ok(total_copied)
    }

    /// Write a single byte at the given address.
    pub fn put_byte_at(&mut self, addr: &Address, value: u8) -> Result<(), GhidraError> {
        let offset = self.block_offset(addr)?;
        self.put_byte_at_offset(offset, value)
    }

    /// Write a single byte at the given block-relative offset.
    pub fn put_byte_at_offset(&mut self, offset: u64, value: u8) -> Result<(), GhidraError> {
        self.check_valid()?;
        let sub = self.find_sub_block_mut(offset)?;
        sub.put_byte(offset, value)
    }

    /// Write bytes from `buf[off..off+len]` starting at `addr`.
    pub fn put_bytes_at(
        &mut self,
        addr: &Address,
        buf: &[u8],
        off: usize,
        len: usize,
    ) -> Result<usize, GhidraError> {
        let offset = self.block_offset(addr)?;
        self.put_bytes_at_offset(offset, buf, off, len)
    }

    /// Write bytes from `buf[off..off+len]` at block-relative offset.
    pub fn put_bytes_at_offset(
        &mut self,
        offset: u64,
        buf: &[u8],
        off: usize,
        len: usize,
    ) -> Result<usize, GhidraError> {
        self.check_valid()?;
        if off + len > buf.len() {
            return Err(GhidraError::MemoryError("Buffer bounds exceeded".into()));
        }
        if offset >= self.length {
            return Err(GhidraError::MemoryError("Offset beyond block end".into()));
        }

        let clamped_len = (len as u64).min(self.length - offset) as usize;
        let mut total_written = 0;

        while total_written < clamped_len {
            let cur_offset = offset + total_written as u64;
            let sub = self.find_sub_block_mut(cur_offset)?;
            let remaining = clamped_len - total_written;
            let n = sub.put_bytes(cur_offset, buf, off + total_written, remaining)?;
            if n == 0 {
                break;
            }
            total_written += n;
        }

        Ok(total_written)
    }

    // ---- block mutation ----

    /// Set the block name.
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    /// Set the block comment.
    pub fn set_comment(&mut self, comment: String) {
        self.comment = comment;
    }

    /// Set the source name.
    pub fn set_source_name(&mut self, source_name: String) {
        self.source_name = source_name;
    }

    /// Set the block flags.
    pub fn set_flags(&mut self, flags: u8) {
        self.flags = flags;
    }

    /// Update a specific flag bit. Returns true if the flag changed.
    pub fn set_flag_bit(&mut self, flag_mask: u8, enable: bool) -> bool {
        let old = self.flags;
        if enable {
            self.flags |= flag_mask;
        } else {
            self.flags &= !flag_mask;
        }
        self.flags != old
    }

    /// Set the read permission.
    pub fn set_read(&mut self, r: bool) -> bool {
        self.set_flag_bit(FLAG_READ, r)
    }

    /// Set the write permission.
    pub fn set_write(&mut self, w: bool) -> bool {
        self.set_flag_bit(FLAG_WRITE, w)
    }

    /// Set the execute permission.
    pub fn set_execute(&mut self, x: bool) -> bool {
        self.set_flag_bit(FLAG_EXECUTE, x)
    }

    /// Set all permissions at once. Returns true if any changed.
    pub fn set_permissions(&mut self, read: bool, write: bool, execute: bool) -> bool {
        let changed = self.set_flag_bit(FLAG_READ, read);
        let changed2 = self.set_flag_bit(FLAG_WRITE, write);
        let changed3 = self.set_flag_bit(FLAG_EXECUTE, execute);
        changed || changed2 || changed3
    }

    /// Set the volatile flag.
    pub fn set_volatile(&mut self, v: bool) -> bool {
        self.set_flag_bit(FLAG_VOLATILE, v)
    }

    /// Set the artificial flag.
    pub fn set_artificial(&mut self, a: bool) -> bool {
        self.set_flag_bit(FLAG_ARTIFICIAL, a)
    }

    /// Set the start address (used during move operations).
    pub fn set_start_address(&mut self, new_start: Address) {
        let size = self.length;
        self.start_address = new_start;
        self.end_address = new_start.add(size.saturating_sub(1));
    }

    /// Invalidate this block (marks it as stale).
    pub fn invalidate(&mut self) {
        self.invalid = true;
    }

    // ---- sub-block management ----

    /// Add a sub-block to this block.
    pub fn add_sub_block(&mut self, sub: Box<dyn SubMemoryBlock>) {
        self.sub_blocks.push(sub);
        self.sub_blocks
            .sort_by_key(|s| s.starting_offset());
        self.last_sub_block_index = None;
    }

    /// Set the sub-blocks for this block.
    pub fn set_sub_blocks(&mut self, subs: Vec<Box<dyn SubMemoryBlock>>) {
        self.sub_blocks = subs;
        self.sub_blocks
            .sort_by_key(|s| s.starting_offset());
        self.last_sub_block_index = None;
    }

    /// Returns a reference to the sub-blocks.
    pub fn sub_blocks(&self) -> &[Box<dyn SubMemoryBlock>] {
        &self.sub_blocks
    }

    /// Returns the number of sub-blocks.
    pub fn num_sub_blocks(&self) -> usize {
        self.sub_blocks.len()
    }

    // ---- mapped block tracking ----

    /// Add a block that maps onto this block.
    pub fn add_mapped_block(&mut self, mapped_block_id: u64) {
        if !self.mapped_blocks.contains(&mapped_block_id) {
            self.mapped_blocks.push(mapped_block_id);
        }
    }

    /// Clear the mapped block list (rebuilt during address set refresh).
    pub fn clear_mapped_block_list(&mut self) {
        self.mapped_blocks.clear();
    }

    /// Returns the IDs of blocks that map onto this block.
    pub fn get_mapped_block_ids(&self) -> &[u64] {
        &self.mapped_blocks
    }

    // ---- split / join ----

    /// Split this block at `addr`. Returns a new MemoryBlockDB for the back half.
    pub fn split(&mut self, addr: Address) -> Result<MemoryBlockDB, GhidraError> {
        self.last_sub_block_index = None;
        let offset = addr.offset - self.start_address.offset;
        let new_length = self.length - offset;

        // Find the sub-block containing the split point
        let index = self.get_sub_block_index_for_offset(offset)?;
        let sub = &mut self.sub_blocks[index];

        let mut split_blocks: Vec<Box<dyn SubMemoryBlock>> = Vec::new();

        if sub.starting_offset() == offset {
            // The split point is at the boundary; move sub-blocks from index onward
            split_blocks = self.sub_blocks.drain(index..).collect();
        } else {
            // Split the sub-block at the offset
            let new_sub = sub.split(offset)?;
            split_blocks.push(new_sub);
            // Move remaining sub-blocks after the split one
            split_blocks.extend(self.sub_blocks.drain(index + 1..));
        }

        // Shorten this block
        self.length = offset;
        self.end_address = self.start_address.add(offset.saturating_sub(1));

        // Create the new block for the back half
        let new_name = format!("{}.split", self.name);
        let mut new_block = MemoryBlockDB::new(
            0, // assigned by adapter
            new_name,
            addr,
            addr.add(new_length.saturating_sub(1)),
            new_length,
            self.flags,
            self.initialized,
            self.mapped,
            self.mapped_source,
            self.mapping_scheme.clone(),
        );
        new_block.set_sub_blocks(split_blocks);

        Ok(new_block)
    }

    /// Join another block into this block.
    pub fn join(&mut self, other: &mut MemoryBlockDB) -> Result<(), GhidraError> {
        self.last_sub_block_index = None;
        self.length += other.length;
        self.end_address = self.start_address.add(self.length.saturating_sub(1));

        let n = self.sub_blocks.len();
        self.sub_blocks.extend(other.sub_blocks.drain(..));

        // Try to merge the last old sub-block with the first new one
        if n > 0 && n < self.sub_blocks.len() {
            let (left, right) = self.sub_blocks.split_at_mut(n);
            if let (Some(last_old), Some(first_new)) = (left.last_mut(), right.first_mut()) {
                if last_old.join(first_new.as_mut()) {
                    self.sub_blocks.remove(n);
                }
            }
        }

        // Re-sequence sub-blocks
        let mut starting_offset = 0u64;
        for sub in &mut self.sub_blocks {
            sub.set_parent_id_and_starting_offset(self.id, starting_offset);
            starting_offset += sub.length();
        }

        other.invalidate();
        Ok(())
    }

    /// Initialize this block with a fill value (converts uninitialized to initialized).
    pub fn initialize_block(&mut self, initial_value: u8) -> Result<(), GhidraError> {
        self.last_sub_block_index = None;
        // Delete existing sub-blocks
        for sub in &mut self.sub_blocks {
            sub.delete()?;
        }
        self.sub_blocks.clear();

        // Create buffer sub-blocks (chunked at 1 GiB max)
        const GBYTE: u64 = 1 << 30;
        let mut block_offset = 0u64;
        while block_offset < self.length {
            let chunk_size = (self.length - block_offset).min(GBYTE);
            self.sub_blocks.push(Box::new(
                crate::mem::db::sub_memory_block::BufferSubMemoryBlock::new(
                    0, self.id, block_offset, chunk_size, initial_value,
                ),
            ));
            block_offset += chunk_size;
        }

        self.initialized = true;
        self.mapped = false;
        Ok(())
    }

    /// Convert this block to uninitialized.
    pub fn uninitialize_block(&mut self) -> Result<(), GhidraError> {
        self.last_sub_block_index = None;
        for sub in &mut self.sub_blocks {
            sub.delete()?;
        }
        self.sub_blocks.clear();
        self.sub_blocks.push(Box::new(
            crate::mem::db::sub_memory_block::UninitializedSubMemoryBlock::new(
                0, self.id, 0, self.length,
            ),
        ));
        self.initialized = false;
        Ok(())
    }

    /// Delete this block and all its sub-blocks.
    pub fn delete(&mut self) -> Result<(), GhidraError> {
        for sub in &mut self.sub_blocks {
            sub.delete()?;
        }
        self.sub_blocks.clear();
        self.invalidate();
        Ok(())
    }

    // ---- validation ----

    /// Check that this block has not been invalidated.
    pub fn check_valid(&self) -> Result<(), GhidraError> {
        if self.invalid {
            return Err(GhidraError::InvalidState(format!(
                "MemoryBlock '{}' has been invalidated (concurrent modification)",
                self.name
            )));
        }
        Ok(())
    }

    // ---- internal helpers ----

    /// Find the sub-block containing the given offset.
    fn find_sub_block(&self, offset: u64) -> Result<&dyn SubMemoryBlock, GhidraError> {
        // Check cached last sub-block first
        if let Some(idx) = self.last_sub_block_index {
            if let Some(sub) = self.sub_blocks.get(idx) {
                if sub.contains(offset) {
                    return Ok(sub.as_ref());
                }
            }
        }
        // Binary search
        let idx = self.find_sub_block_index(offset)?;
        Ok(self.sub_blocks[idx].as_ref())
    }

    /// Find the sub-block containing the given offset (mutable).
    fn find_sub_block_mut(
        &mut self,
        offset: u64,
    ) -> Result<&mut dyn SubMemoryBlock, GhidraError> {
        // Check cached last sub-block first
        if let Some(idx) = self.last_sub_block_index {
            if idx < self.sub_blocks.len() && self.sub_blocks[idx].contains(offset) {
                return Ok(self.sub_blocks[idx].as_mut());
            }
        }
        let idx = self.find_sub_block_index(offset)?;
        self.last_sub_block_index = Some(idx);
        Ok(self.sub_blocks[idx].as_mut())
    }

    /// Binary search for the sub-block index containing `offset`.
    fn find_sub_block_index(&self, offset: u64) -> Result<usize, GhidraError> {
        if self.sub_blocks.is_empty() {
            return Err(GhidraError::MemoryError(format!(
                "No sub-blocks in block '{}' (offset={})",
                self.name, offset
            )));
        }
        self.find_sub_block_recursive(0, self.sub_blocks.len() - 1, offset)
    }

    fn find_sub_block_recursive(
        &self,
        min: usize,
        max: usize,
        offset: u64,
    ) -> Result<usize, GhidraError> {
        if min > max {
            return Err(GhidraError::MemoryError(format!(
                "Offset {} out of bounds in block '{}'",
                offset, self.name
            )));
        }
        let mid = (min + max) / 2;
        let sub = &self.sub_blocks[mid];
        if sub.contains(offset) {
            return Ok(mid);
        }
        if offset < sub.starting_offset() {
            if mid == 0 {
                return Err(GhidraError::MemoryError(format!(
                    "Offset {} out of bounds in block '{}'",
                    offset, self.name
                )));
            }
            self.find_sub_block_recursive(min, mid - 1, offset)
        } else {
            self.find_sub_block_recursive(mid + 1, max, offset)
        }
    }

    /// Get the index of the sub-block containing `offset` for split operations.
    fn get_sub_block_index_for_offset(&self, offset: u64) -> Result<usize, GhidraError> {
        for (i, sub) in self.sub_blocks.iter().enumerate() {
            if sub.contains(offset) {
                return Ok(i);
            }
        }
        Err(GhidraError::MemoryError(format!(
            "Offset {} not in any sub-block of block '{}'",
            offset, self.name
        )))
    }
}

// ---- Display ----

impl std::fmt::Display for MemoryBlockDB {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}({}-{})",
            self.name, self.start_address, self.end_address
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::db::sub_memory_block::{BufferSubMemoryBlock, UninitializedSubMemoryBlock};

    fn make_initialized_block(name: &str, start: u64, size: u64) -> MemoryBlockDB {
        let start_addr = Address::new(start);
        let end_addr = Address::new(start + size - 1);
        let mut block = MemoryBlockDB::new(
            1,
            name.to_string(),
            start_addr,
            end_addr,
            size,
            FLAG_READ | FLAG_WRITE | FLAG_EXECUTE,
            true,
            false,
            None,
            None,
        );
        block.add_sub_block(Box::new(BufferSubMemoryBlock::new(
            1, 1, 0, size, 0x00,
        )));
        block
    }

    fn make_uninitialized_block(name: &str, start: u64, size: u64) -> MemoryBlockDB {
        let start_addr = Address::new(start);
        let end_addr = Address::new(start + size - 1);
        let mut block = MemoryBlockDB::new(
            1,
            name.to_string(),
            start_addr,
            end_addr,
            size,
            FLAG_READ | FLAG_WRITE,
            false,
            false,
            None,
            None,
        );
        block.add_sub_block(Box::new(UninitializedSubMemoryBlock::new(
            1, 1, 0, size,
        )));
        block
    }

    #[test]
    fn test_basic_properties() {
        let block = make_initialized_block(".text", 0x1000, 256);
        assert_eq!(block.name(), ".text");
        assert_eq!(block.start(), Address::new(0x1000));
        assert_eq!(block.end(), Address::new(0x10FF));
        assert_eq!(block.size(), 256);
        assert!(block.is_initialized());
        assert!(!block.is_mapped());
        assert!(block.is_read());
        assert!(block.is_write());
        assert!(block.is_execute());
    }

    #[test]
    fn test_contains() {
        let block = make_initialized_block(".text", 0x1000, 256);
        assert!(block.contains(&Address::new(0x1000)));
        assert!(block.contains(&Address::new(0x1080)));
        assert!(block.contains(&Address::new(0x10FF)));
        assert!(!block.contains(&Address::new(0x0FFF)));
        assert!(!block.contains(&Address::new(0x1100)));
    }

    #[test]
    fn test_read_write_byte() {
        let mut block = make_initialized_block(".text", 0x1000, 256);
        block.put_byte_at(&Address::new(0x1000), 0x42).unwrap();
        assert_eq!(block.get_byte_at(&Address::new(0x1000)).unwrap(), 0x42);
        block.put_byte_at(&Address::new(0x10FF), 0xFF).unwrap();
        assert_eq!(block.get_byte_at(&Address::new(0x10FF)).unwrap(), 0xFF);
    }

    #[test]
    fn test_read_write_bytes() {
        let mut block = make_initialized_block(".text", 0x1000, 256);
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        block
            .put_bytes_at(&Address::new(0x1000), &data, 0, 4)
            .unwrap();

        let mut buf = [0u8; 4];
        let n = block
            .get_bytes_at(&Address::new(0x1000), &mut buf, 0, 4)
            .unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf, data);
    }

    #[test]
    fn test_uninitialized_read_fails() {
        let block = make_uninitialized_block("heap", 0x5000, 64);
        assert!(block.get_byte_at(&Address::new(0x5000)).is_err());
    }

    #[test]
    fn test_uninitialized_write_fails() {
        let mut block = make_uninitialized_block("heap", 0x5000, 64);
        assert!(block.put_byte_at(&Address::new(0x5000), 0x42).is_err());
    }

    #[test]
    fn test_out_of_bounds() {
        let block = make_initialized_block(".text", 0x1000, 256);
        assert!(block.get_byte_at(&Address::new(0x2000)).is_err());
    }

    #[test]
    fn test_flag_operations() {
        let mut block = make_initialized_block(".text", 0x1000, 256);
        assert!(block.is_read());
        assert!(block.is_write());

        let changed = block.set_write(false);
        assert!(changed);
        assert!(!block.is_write());

        let changed = block.set_write(false);
        assert!(!changed); // no change

        let changed = block.set_execute(false);
        assert!(changed);
        assert!(!block.is_execute());
    }

    #[test]
    fn test_set_name_comment() {
        let mut block = make_initialized_block(".text", 0x1000, 256);
        block.set_name(".rodata".to_string());
        assert_eq!(block.name(), ".rodata");

        block.set_comment("read-only data".to_string());
        assert_eq!(block.comment(), "read-only data");
    }

    #[test]
    fn test_invalidate() {
        let mut block = make_initialized_block(".text", 0x1000, 256);
        assert!(block.check_valid().is_ok());
        block.invalidate();
        assert!(block.check_valid().is_err());
        assert!(block.is_invalid());
    }

    #[test]
    fn test_split_block() {
        let mut block = make_initialized_block(".text", 0x1000, 256);
        // Write some data so we can verify it's split correctly
        block.put_byte_at(&Address::new(0x1000), 0xAA).unwrap();
        block.put_byte_at(&Address::new(0x1080), 0xBB).unwrap();

        let new_block = block.split(Address::new(0x1080)).unwrap();

        assert_eq!(block.size(), 128);
        assert_eq!(block.end(), Address::new(0x107F));
        assert_eq!(block.get_byte_at(&Address::new(0x1000)).unwrap(), 0xAA);

        assert_eq!(new_block.size(), 128);
        assert_eq!(new_block.start(), Address::new(0x1080));
        assert_eq!(new_block.name(), ".text.split");
    }

    #[test]
    fn test_join_blocks() {
        let mut block1 = make_initialized_block("A", 0x1000, 128);
        let mut block2 = make_initialized_block("B", 0x1080, 128);
        block1.put_byte_at(&Address::new(0x1000), 0xAA).unwrap();
        block2.put_byte_at(&Address::new(0x1080), 0xBB).unwrap();

        block1.join(&mut block2).unwrap();

        assert_eq!(block1.size(), 256);
        assert_eq!(block1.end(), Address::new(0x10FF));
        assert_eq!(block1.get_byte_at(&Address::new(0x1000)).unwrap(), 0xAA);
        assert_eq!(block1.get_byte_at(&Address::new(0x1080)).unwrap(), 0xBB);
        assert!(block2.is_invalid());
    }

    #[test]
    fn test_initialize_block() {
        let mut block = make_uninitialized_block("heap", 0x5000, 256);
        assert!(!block.is_initialized());
        block.initialize_block(0xFF).unwrap();
        assert!(block.is_initialized());
        assert_eq!(block.get_byte_at(&Address::new(0x5000)).unwrap(), 0xFF);
        assert_eq!(block.get_byte_at(&Address::new(0x50FF)).unwrap(), 0xFF);
    }

    #[test]
    fn test_uninitialize_block() {
        let mut block = make_initialized_block(".text", 0x1000, 256);
        assert!(block.is_initialized());
        block.uninitialize_block().unwrap();
        assert!(!block.is_initialized());
        assert!(block.get_byte_at(&Address::new(0x1000)).is_err());
    }

    #[test]
    fn test_delete_block() {
        let mut block = make_initialized_block(".text", 0x1000, 256);
        block.delete().unwrap();
        assert!(block.is_invalid());
    }

    #[test]
    fn test_display() {
        let block = make_initialized_block(".text", 0x1000, 256);
        assert_eq!(format!("{}", block), ".text(0x1000-0x10ff)");
    }

    #[test]
    fn test_mapped_block_tracking() {
        let mut block = make_initialized_block(".text", 0x1000, 256);
        block.add_mapped_block(42);
        block.add_mapped_block(43);
        block.add_mapped_block(42); // duplicate
        assert_eq!(block.get_mapped_block_ids().len(), 2);
        assert_eq!(block.get_mapped_block_ids()[0], 42);
        assert_eq!(block.get_mapped_block_ids()[1], 43);

        block.clear_mapped_block_list();
        assert!(block.get_mapped_block_ids().is_empty());
    }

    #[test]
    fn test_block_offset() {
        let block = make_initialized_block(".text", 0x1000, 256);
        assert_eq!(block.block_offset(&Address::new(0x1000)).unwrap(), 0);
        assert_eq!(block.block_offset(&Address::new(0x10FF)).unwrap(), 255);
        assert!(block.block_offset(&Address::new(0x2000)).is_err());
    }

    #[test]
    fn test_multiple_sub_blocks() {
        let start_addr = Address::new(0x1000);
        let mut block = MemoryBlockDB::new(
            1,
            ".text".to_string(),
            start_addr,
            Address::new(0x11FF),
            512,
            FLAG_READ | FLAG_WRITE | FLAG_EXECUTE,
            true,
            false,
            None,
            None,
        );
        // Two sub-blocks: first 256 bytes initialized, next 256 uninitialized
        block.add_sub_block(Box::new(BufferSubMemoryBlock::new(
            1, 1, 0, 256, 0xAA,
        )));
        block.add_sub_block(Box::new(BufferSubMemoryBlock::new(
            2, 1, 256, 256, 0xBB,
        )));

        assert_eq!(block.get_byte_at(&Address::new(0x1000)).unwrap(), 0xAA);
        assert_eq!(block.get_byte_at(&Address::new(0x10FF)).unwrap(), 0xAA);
        assert_eq!(block.get_byte_at(&Address::new(0x1100)).unwrap(), 0xBB);
        assert_eq!(block.get_byte_at(&Address::new(0x11FF)).unwrap(), 0xBB);
    }

    #[test]
    fn test_read_across_sub_blocks() {
        let start_addr = Address::new(0x1000);
        let mut block = MemoryBlockDB::new(
            1,
            ".text".to_string(),
            start_addr,
            Address::new(0x11FF),
            512,
            FLAG_READ | FLAG_WRITE | FLAG_EXECUTE,
            true,
            false,
            None,
            None,
        );
        block.add_sub_block(Box::new(BufferSubMemoryBlock::new(
            1, 1, 0, 256, 0xAA,
        )));
        block.add_sub_block(Box::new(BufferSubMemoryBlock::new(
            2, 1, 256, 256, 0xBB,
        )));

        let mut buf = [0u8; 512];
        let n = block
            .get_bytes_at(&Address::new(0x1000), &mut buf, 0, 512)
            .unwrap();
        assert_eq!(n, 512);
        assert!(buf[..256].iter().all(|&b| b == 0xAA));
        assert!(buf[256..].iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn test_permissions_string() {
        let block = make_initialized_block(".text", 0x1000, 256);
        let mut s = String::new();
        if block.is_read() {
            s.push('r');
        } else {
            s.push('-');
        }
        if block.is_write() {
            s.push('w');
        } else {
            s.push('-');
        }
        if block.is_execute() {
            s.push('x');
        } else {
            s.push('-');
        }
        assert_eq!(s, "rwx");
    }
}
