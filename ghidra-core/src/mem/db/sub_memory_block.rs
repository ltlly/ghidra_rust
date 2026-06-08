//! Sub-memory block implementations.
//!
//! Mirrors `ghidra.program.database.mem.SubMemoryBlock` and its concrete
//! subclasses (`UninitializedSubMemoryBlock`, `BufferSubMemoryBlock`).
//!
//! A [`MemoryBlockDB`] is composed of one or more `SubMemoryBlock` segments
//! that handle the actual storage and retrieval of bytes.

use crate::error::GhidraError;
use crate::mem::{MemoryAccessError, MemoryBlockType};

// ============================================================================
// SubMemoryBlockType — mirrors sub-block type constants
// ============================================================================

/// Identifies the concrete sub-block kind for serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubMemoryBlockType {
    /// Initialized data stored in a database buffer.
    Buffer,
    /// Uninitialized (no backing data).
    Uninitialized,
    /// Data sourced from file bytes on disk.
    FileBytes,
    /// Byte-mapped to another memory region.
    ByteMapped,
    /// Bit-mapped to another memory region.
    BitMapped,
}

// ============================================================================
// SubMemoryBlock — trait (mirrors abstract class SubMemoryBlock)
// ============================================================================

/// Trait for the various types of memory block sub-sections.
///
/// Used by [`MemoryBlockDB`] to do the actual storing and fetching of bytes
/// that make up a memory block. Each sub-block covers a contiguous offset
/// range within the parent block.
pub trait SubMemoryBlock: Send {
    /// Return whether this sub-block has been initialized (has byte values).
    fn is_initialized(&self) -> bool;

    /// Returns the id of the MemoryBlockDB that owns this sub-block.
    fn parent_block_id(&self) -> u64;

    /// Returns the starting offset relative to the containing MemoryBlockDB.
    fn starting_offset(&self) -> u64;

    /// Returns the length of this sub-block in bytes.
    fn length(&self) -> u64;

    /// Returns true if `mem_block_offset` falls within this sub-block.
    fn contains(&self, mem_block_offset: u64) -> bool {
        mem_block_offset >= self.starting_offset()
            && mem_block_offset < self.starting_offset() + self.length()
    }

    /// Read a single byte at the given parent-block offset.
    fn get_byte(&self, mem_block_offset: u64) -> Result<u8, GhidraError>;

    /// Read bytes starting at the given parent-block offset.
    /// Returns the number of bytes actually read.
    fn get_bytes(
        &self,
        mem_block_offset: u64,
        buf: &mut [u8],
        off: usize,
        len: usize,
    ) -> Result<usize, GhidraError>;

    /// Write a single byte at the given parent-block offset.
    fn put_byte(&mut self, mem_block_offset: u64, value: u8) -> Result<(), GhidraError>;

    /// Write bytes starting at the given parent-block offset.
    /// Returns the number of bytes actually written.
    fn put_bytes(
        &mut self,
        mem_block_offset: u64,
        buf: &[u8],
        off: usize,
        len: usize,
    ) -> Result<usize, GhidraError>;

    /// Delete this sub-block (release backing storage).
    fn delete(&mut self) -> Result<(), GhidraError>;

    /// Set the length of this sub-block (used during split).
    fn set_length(&mut self, length: u64);

    /// Attempt to join `other` into `self` if compatible.
    /// Returns `true` if the join succeeded.
    fn join(&mut self, other: &mut dyn SubMemoryBlock) -> bool;

    /// Returns true if this is a mapped sub-block (bit or byte mapped).
    fn is_mapped(&self) -> bool {
        false
    }

    /// Returns the [`MemoryBlockType`] for this sub-block.
    fn block_type(&self) -> MemoryBlockType {
        MemoryBlockType::Default
    }

    /// Split this sub-block at `mem_block_offset` (parent-block offset).
    /// Returns a new sub-block containing the back half.
    fn split(&mut self, mem_block_offset: u64) -> Result<Box<dyn SubMemoryBlock>, GhidraError>;

    /// Update the owning block id and starting offset (used during split/join).
    fn set_parent_id_and_starting_offset(&mut self, key: u64, starting_offset: u64);

    /// A human-readable description of this sub-block.
    fn description(&self) -> String;

    /// Returns the sub-block serialization type.
    fn sub_block_type(&self) -> SubMemoryBlockType;

    /// Returns the record key for this sub-block (used for DB persistence).
    fn record_key(&self) -> u64;
}

impl PartialOrd for dyn SubMemoryBlock {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for dyn SubMemoryBlock {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.starting_offset().cmp(&other.starting_offset())
    }
}

impl PartialEq for dyn SubMemoryBlock {
    fn eq(&self, other: &Self) -> bool {
        self.starting_offset() == other.starting_offset()
            && self.length() == other.length()
            && self.parent_block_id() == other.parent_block_id()
    }
}

impl Eq for dyn SubMemoryBlock {}

// ============================================================================
// UninitializedSubMemoryBlock
// ============================================================================

/// Sub-block that has no backing data -- reading/writing is always an error.
///
/// Mirrors `ghidra.program.database.mem.UninitializedSubMemoryBlock`.
#[derive(Debug, Clone)]
pub struct UninitializedSubMemoryBlock {
    /// Record key in the database.
    record_key: u64,
    /// ID of the owning MemoryBlockDB.
    parent_id: u64,
    /// Starting offset within the parent block.
    offset: u64,
    /// Length in bytes.
    len: u64,
}

impl UninitializedSubMemoryBlock {
    /// Create a new uninitialized sub-block.
    pub fn new(record_key: u64, parent_id: u64, offset: u64, len: u64) -> Self {
        Self {
            record_key,
            parent_id,
            offset,
            len,
        }
    }
}

impl SubMemoryBlock for UninitializedSubMemoryBlock {
    fn is_initialized(&self) -> bool {
        false
    }

    fn parent_block_id(&self) -> u64 {
        self.parent_id
    }

    fn starting_offset(&self) -> u64 {
        self.offset
    }

    fn length(&self) -> u64 {
        self.len
    }

    fn get_byte(&self, _mem_block_offset: u64) -> Result<u8, GhidraError> {
        Err(GhidraError::MemoryError(
            "Attempted to read from uninitialized block".into(),
        ))
    }

    fn get_bytes(
        &self,
        _mem_block_offset: u64,
        _buf: &mut [u8],
        _off: usize,
        _len: usize,
    ) -> Result<usize, GhidraError> {
        Err(GhidraError::MemoryError(
            "Attempted to read from uninitialized block".into(),
        ))
    }

    fn put_byte(&mut self, _mem_block_offset: u64, _value: u8) -> Result<(), GhidraError> {
        Err(GhidraError::MemoryError(
            "Attempted to write to an uninitialized block".into(),
        ))
    }

    fn put_bytes(
        &mut self,
        _mem_block_offset: u64,
        _buf: &[u8],
        _off: usize,
        _len: usize,
    ) -> Result<usize, GhidraError> {
        Err(GhidraError::MemoryError(
            "Attempted to write to an uninitialized block".into(),
        ))
    }

    fn delete(&mut self) -> Result<(), GhidraError> {
        // In the real implementation this calls adapter.deleteSubBlock(record_key).
        // Here we just mark as deleted by setting length to 0.
        self.len = 0;
        Ok(())
    }

    fn set_length(&mut self, length: u64) {
        self.len = length;
    }

    fn join(&mut self, other: &mut dyn SubMemoryBlock) -> bool {
        if other.sub_block_type() != SubMemoryBlockType::Uninitialized {
            return false;
        }
        self.len += other.length();
        other.delete().ok();
        true
    }

    fn split(&mut self, mem_block_offset: u64) -> Result<Box<dyn SubMemoryBlock>, GhidraError> {
        let offset_in_sub = mem_block_offset - self.offset;
        let new_length = self.len - offset_in_sub;
        self.len = offset_in_sub;

        Ok(Box::new(UninitializedSubMemoryBlock::new(
            0, // new record key assigned by adapter
            self.parent_id,
            mem_block_offset,
            new_length,
        )))
    }

    fn set_parent_id_and_starting_offset(&mut self, key: u64, starting_offset: u64) {
        self.parent_id = key;
        self.offset = starting_offset;
    }

    fn description(&self) -> String {
        format!("uninit[0x{:x}]", self.len)
    }

    fn sub_block_type(&self) -> SubMemoryBlockType {
        SubMemoryBlockType::Uninitialized
    }

    fn record_key(&self) -> u64 {
        self.record_key
    }
}

// ============================================================================
// BufferSubMemoryBlock
// ============================================================================

/// Sub-block backed by an in-memory byte buffer.
///
/// Mirrors `ghidra.program.database.mem.BufferSubMemoryBlock`. Each buffer
/// sub-block stores its bytes in a private `Vec<u8>` buffer. In the Java
/// version this uses a `DBBuffer` (chained database buffers); here we use
/// a simple `Vec<u8>` as the in-memory representation.
#[derive(Debug, Clone)]
pub struct BufferSubMemoryBlock {
    /// Record key in the database.
    record_key: u64,
    /// ID of the owning MemoryBlockDB.
    parent_id: u64,
    /// Starting offset within the parent block.
    offset: u64,
    /// Length in bytes.
    len: u64,
    /// The backing byte buffer.
    buf: Vec<u8>,
}

impl BufferSubMemoryBlock {
    /// Maximum buffer capacity (1 GiB, matching Java's Memory.GBYTE).
    pub const MAX_BUFFER_SIZE: u64 = 1 << 30;

    /// Create a new buffer sub-block with all bytes set to `initial_value`.
    pub fn new(
        record_key: u64,
        parent_id: u64,
        offset: u64,
        len: u64,
        initial_value: u8,
    ) -> Self {
        Self {
            record_key,
            parent_id,
            offset,
            len,
            buf: vec![initial_value; len as usize],
        }
    }

    /// Create a new buffer sub-block from existing data.
    pub fn from_data(
        record_key: u64,
        parent_id: u64,
        offset: u64,
        data: Vec<u8>,
    ) -> Self {
        let len = data.len() as u64;
        Self {
            record_key,
            parent_id,
            offset,
            len,
            buf: data,
        }
    }

    /// Returns a reference to the backing buffer.
    pub fn buffer(&self) -> &[u8] {
        &self.buf
    }

    /// Returns a mutable reference to the backing buffer.
    pub fn buffer_mut(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }
}

impl SubMemoryBlock for BufferSubMemoryBlock {
    fn is_initialized(&self) -> bool {
        true
    }

    fn parent_block_id(&self) -> u64 {
        self.parent_id
    }

    fn starting_offset(&self) -> u64 {
        self.offset
    }

    fn length(&self) -> u64 {
        self.len
    }

    fn get_byte(&self, mem_block_offset: u64) -> Result<u8, GhidraError> {
        let offset_in_sub = (mem_block_offset - self.offset) as usize;
        if offset_in_sub >= self.buf.len() {
            return Err(GhidraError::MemoryError(format!(
                "Offset {} is out of bounds for buffer sub-block (len={})",
                offset_in_sub,
                self.buf.len()
            )));
        }
        Ok(self.buf[offset_in_sub])
    }

    fn get_bytes(
        &self,
        mem_block_offset: u64,
        buf: &mut [u8],
        off: usize,
        len: usize,
    ) -> Result<usize, GhidraError> {
        let offset_in_sub = (mem_block_offset - self.offset) as usize;
        let available = self.buf.len().saturating_sub(offset_in_sub);
        let actual = len.min(available);
        if actual == 0 {
            return Ok(0);
        }
        buf[off..off + actual].copy_from_slice(&self.buf[offset_in_sub..offset_in_sub + actual]);
        Ok(actual)
    }

    fn put_byte(&mut self, mem_block_offset: u64, value: u8) -> Result<(), GhidraError> {
        let offset_in_sub = (mem_block_offset - self.offset) as usize;
        if offset_in_sub >= self.buf.len() {
            return Err(GhidraError::MemoryError(format!(
                "Offset {} is out of bounds for buffer sub-block (len={})",
                offset_in_sub,
                self.buf.len()
            )));
        }
        self.buf[offset_in_sub] = value;
        Ok(())
    }

    fn put_bytes(
        &mut self,
        mem_block_offset: u64,
        buf: &[u8],
        off: usize,
        len: usize,
    ) -> Result<usize, GhidraError> {
        let offset_in_sub = (mem_block_offset - self.offset) as usize;
        let available = self.buf.len().saturating_sub(offset_in_sub);
        let actual = len.min(available);
        if actual == 0 {
            return Ok(0);
        }
        self.buf[offset_in_sub..offset_in_sub + actual]
            .copy_from_slice(&buf[off..off + actual]);
        Ok(actual)
    }

    fn delete(&mut self) -> Result<(), GhidraError> {
        self.buf.clear();
        self.buf.shrink_to_fit();
        self.len = 0;
        Ok(())
    }

    fn set_length(&mut self, length: u64) {
        self.len = length;
        self.buf.resize(length as usize, 0);
    }

    fn join(&mut self, other: &mut dyn SubMemoryBlock) -> bool {
        if other.sub_block_type() != SubMemoryBlockType::Buffer {
            return false;
        }
        let combined = self.len + other.length();
        if combined > Self::MAX_BUFFER_SIZE {
            return false;
        }
        // Extract bytes from other and append
        let mut tmp = vec![0u8; other.length() as usize];
        if other.get_bytes(other.starting_offset(), &mut tmp, 0, tmp.len()).is_err() {
            return false;
        }
        self.buf.extend_from_slice(&tmp);
        self.len = combined;
        other.delete().ok();
        true
    }

    fn split(&mut self, mem_block_offset: u64) -> Result<Box<dyn SubMemoryBlock>, GhidraError> {
        let offset_in_sub = (mem_block_offset - self.offset) as usize;
        let new_length = self.len - offset_in_sub as u64;
        let remaining = self.buf.split_off(offset_in_sub);
        self.len = offset_in_sub as u64;

        Ok(Box::new(BufferSubMemoryBlock::from_data(
            0, // new record key assigned by adapter
            self.parent_id,
            mem_block_offset,
            remaining,
        )))
    }

    fn set_parent_id_and_starting_offset(&mut self, key: u64, starting_offset: u64) {
        self.parent_id = key;
        self.offset = starting_offset;
    }

    fn description(&self) -> String {
        format!("init[0x{:x}]", self.len)
    }

    fn sub_block_type(&self) -> SubMemoryBlockType {
        SubMemoryBlockType::Buffer
    }

    fn record_key(&self) -> u64 {
        self.record_key
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uninitialized_contains() {
        let sub = UninitializedSubMemoryBlock::new(1, 100, 0, 256);
        assert!(sub.contains(0));
        assert!(sub.contains(128));
        assert!(sub.contains(255));
        assert!(!sub.contains(256));
        assert!(!sub.contains(u64::MAX));
    }

    #[test]
    fn test_uninitialized_read_fails() {
        let sub = UninitializedSubMemoryBlock::new(1, 100, 0, 256);
        assert!(sub.get_byte(0).is_err());
        assert!(sub.get_bytes(0, &mut [0u8; 4], 0, 4).is_err());
    }

    #[test]
    fn test_uninitialized_write_fails() {
        let mut sub = UninitializedSubMemoryBlock::new(1, 100, 0, 256);
        assert!(sub.put_byte(0, 0x42).is_err());
        assert!(sub.put_bytes(0, &[0x42], 0, 1).is_err());
    }

    #[test]
    fn test_uninitialized_join() {
        let mut sub1 = UninitializedSubMemoryBlock::new(1, 100, 0, 128);
        let mut sub2 = UninitializedSubMemoryBlock::new(2, 100, 128, 128);
        assert!(sub1.join(&mut sub2));
        assert_eq!(sub1.length(), 256);
    }

    #[test]
    fn test_uninitialized_join_rejects_different_type() {
        let mut sub1 = UninitializedSubMemoryBlock::new(1, 100, 0, 128);
        let mut sub2 = BufferSubMemoryBlock::new(2, 100, 128, 128, 0x00);
        assert!(!sub1.join(&mut sub2));
    }

    #[test]
    fn test_uninitialized_split() {
        let mut sub = UninitializedSubMemoryBlock::new(1, 100, 0, 256);
        let new_sub = sub.split(128).unwrap();
        assert_eq!(sub.length(), 128);
        assert_eq!(new_sub.length(), 128);
        assert_eq!(new_sub.starting_offset(), 128);
        assert!(!new_sub.is_initialized());
    }

    #[test]
    fn test_uninitialized_description() {
        let sub = UninitializedSubMemoryBlock::new(1, 100, 0, 256);
        assert_eq!(sub.description(), "uninit[0x100]");
    }

    #[test]
    fn test_buffer_read_write() {
        let mut sub = BufferSubMemoryBlock::new(1, 100, 0, 256, 0x00);
        sub.put_byte(0, 0x42).unwrap();
        sub.put_byte(255, 0xFF).unwrap();
        assert_eq!(sub.get_byte(0).unwrap(), 0x42);
        assert_eq!(sub.get_byte(255).unwrap(), 0xFF);
    }

    #[test]
    fn test_buffer_get_bytes() {
        let sub = BufferSubMemoryBlock::new(1, 100, 0, 256, 0xAA);
        let mut buf = [0u8; 8];
        let n = sub.get_bytes(0, &mut buf, 0, 8).unwrap();
        assert_eq!(n, 8);
        assert!(buf.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn test_buffer_put_bytes() {
        let mut sub = BufferSubMemoryBlock::new(1, 100, 0, 256, 0x00);
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let n = sub.put_bytes(0, &data, 0, 4).unwrap();
        assert_eq!(n, 4);
        assert_eq!(sub.get_byte(0).unwrap(), 0xDE);
        assert_eq!(sub.get_byte(1).unwrap(), 0xAD);
        assert_eq!(sub.get_byte(2).unwrap(), 0xBE);
        assert_eq!(sub.get_byte(3).unwrap(), 0xEF);
    }

    #[test]
    fn test_buffer_join() {
        let mut sub1 = BufferSubMemoryBlock::new(1, 100, 0, 4, 0xAA);
        let mut sub2 = BufferSubMemoryBlock::new(2, 100, 4, 4, 0xBB);
        assert!(sub1.join(&mut sub2));
        assert_eq!(sub1.length(), 8);
        assert_eq!(sub1.get_byte(0).unwrap(), 0xAA);
        assert_eq!(sub1.get_byte(4).unwrap(), 0xBB);
    }

    #[test]
    fn test_buffer_split() {
        let mut sub = BufferSubMemoryBlock::new(1, 100, 0, 8, 0x42);
        let new_sub = sub.split(4).unwrap();
        assert_eq!(sub.length(), 4);
        assert_eq!(new_sub.length(), 4);
        assert_eq!(sub.get_byte(0).unwrap(), 0x42);
        assert_eq!(new_sub.get_byte(4).unwrap(), 0x42);
    }

    #[test]
    fn test_buffer_out_of_bounds() {
        let sub = BufferSubMemoryBlock::new(1, 100, 0, 16, 0x00);
        assert!(sub.get_byte(16).is_err());
        assert!(sub.get_byte(u64::MAX).is_err());
    }

    #[test]
    fn test_buffer_description() {
        let sub = BufferSubMemoryBlock::new(1, 100, 0, 1024, 0x00);
        assert_eq!(sub.description(), "init[0x400]");
    }

    #[test]
    fn test_buffer_from_data() {
        let data = vec![1, 2, 3, 4, 5];
        let sub = BufferSubMemoryBlock::from_data(1, 100, 0, data);
        assert_eq!(sub.length(), 5);
        assert_eq!(sub.get_byte(0).unwrap(), 1);
        assert_eq!(sub.get_byte(4).unwrap(), 5);
    }

    #[test]
    fn test_sub_block_type_equality() {
        assert_eq!(
            SubMemoryBlockType::Buffer,
            SubMemoryBlockType::Buffer
        );
        assert_ne!(
            SubMemoryBlockType::Buffer,
            SubMemoryBlockType::Uninitialized
        );
    }

    #[test]
    fn test_buffer_partial_read_at_end() {
        let sub = BufferSubMemoryBlock::new(1, 100, 0, 4, 0xFF);
        let mut buf = [0u8; 8];
        let n = sub.get_bytes(0, &mut buf, 0, 8).unwrap();
        assert_eq!(n, 4);
        assert!(buf[..4].iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn test_uninitialized_block_type() {
        let sub = UninitializedSubMemoryBlock::new(1, 100, 0, 128);
        assert_eq!(sub.block_type(), MemoryBlockType::Default);
        assert!(!sub.is_mapped());
        assert!(!sub.is_initialized());
    }

    #[test]
    fn test_buffer_block_type() {
        let sub = BufferSubMemoryBlock::new(1, 100, 0, 128, 0x00);
        assert_eq!(sub.block_type(), MemoryBlockType::Default);
        assert!(!sub.is_mapped());
        assert!(sub.is_initialized());
    }

    #[test]
    fn test_set_parent_id_and_starting_offset() {
        let mut sub = BufferSubMemoryBlock::new(1, 100, 0, 128, 0x00);
        sub.set_parent_id_and_starting_offset(200, 64);
        assert_eq!(sub.parent_block_id(), 200);
        assert_eq!(sub.starting_offset(), 64);
    }

    #[test]
    fn test_buffer_set_length() {
        let mut sub = BufferSubMemoryBlock::new(1, 100, 0, 128, 0xAA);
        sub.set_length(256);
        assert_eq!(sub.length(), 256);
        assert_eq!(sub.buffer().len(), 256);
        // Original bytes preserved
        assert_eq!(sub.get_byte(0).unwrap(), 0xAA);
        // New bytes are zero
        assert_eq!(sub.get_byte(200).unwrap(), 0x00);
    }
}
