//! Ghidra memory model.
//!
//! This module implements the complete memory subsystem from `ghidra.program.model.mem`,
//! including the [`Memory`] trait, [`MemoryBlock`] struct, byte/bit-mapped blocks,
//! [`MemoryBlockType`], error types, [`ByteMappingScheme`], [`MemBuffer`] trait,
//! [`WrappedMemBuffer`], and the concrete [`MemoryMap`] implementation.
//!
//! # Block Types
//!
//! * **Initialized** — a memory block with known data (from file bytes, input stream, or zero-filled).
//! * **Uninitialized** — a memory block whose data is unknown.
//! * **Byte-Mapped** — bytes are mapped to another memory region via a [`ByteMappingScheme`].
//! * **Bit-Mapped** — bytes correspond to individual bits in another memory region.
//! * **Overlay** — alternate content for a physical memory region in a different execution context.

use crate::addr::{Address, AddressRange};
use crate::error::GhidraError;
use std::collections::HashMap;
use std::fmt;

// ============================================================================
// Constants (from Memory.java and MemoryBlock.java)
// ============================================================================

/// Name reserved for the EXTERNAL memory block used by loaders (e.g., ELF).
pub const EXTERNAL_BLOCK_NAME: &str = "EXTERNAL";

/// Name reserved for the heap pseudo-block.
pub const HEAP_BLOCK_NAME: &str = "__HEAP__";

/// Shift factor for gigabyte calculations.
pub const GBYTE_SHIFT_FACTOR: u32 = 30;

/// One gigabyte in bytes.
pub const GBYTE: u64 = 1u64 << GBYTE_SHIFT_FACTOR;

/// Maximum total binary size: 16 GiB.
pub const MAX_BINARY_SIZE_GB: u64 = 16;

/// Maximum total binary size in bytes.
pub const MAX_BINARY_SIZE: u64 = MAX_BINARY_SIZE_GB << GBYTE_SHIFT_FACTOR;

/// Maximum size of a single memory block.
pub const MAX_BLOCK_SIZE_GB: u64 = 16;

/// Maximum size of a single memory block in bytes.
pub const MAX_BLOCK_SIZE: u64 = MAX_BLOCK_SIZE_GB << GBYTE_SHIFT_FACTOR;

// Memory block flag bits (mirrors Java MemoryBlock flags)
/// Read permission flag.
pub const FLAG_READ: u8 = 0x4;
/// Write permission flag.
pub const FLAG_WRITE: u8 = 0x2;
/// Execute permission flag.
pub const FLAG_EXECUTE: u8 = 0x1;
/// Volatile memory attribute flag (e.g., I/O regions).
pub const FLAG_VOLATILE: u8 = 0x8;
/// Artificial memory block flag (fabricated for analysis).
pub const FLAG_ARTIFICIAL: u8 = 0x10;

// ============================================================================
// Error types
// ============================================================================

/// Error returned when a memory access is not permitted (uninitialized memory,
/// address out of range, write to read-only block, etc.).
#[derive(Debug, Clone)]
pub struct MemoryAccessError {
    pub message: String,
}

impl MemoryAccessError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }

    pub fn default() -> Self {
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

/// Error thrown for memory block-related problems (split, join, move failures).
#[derive(Debug, Clone)]
pub struct MemoryBlockError {
    pub message: String,
}

impl MemoryBlockError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }

    pub fn default() -> Self {
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

/// Error thrown when creating or moving a memory block would cause blocks to overlap.
#[derive(Debug, Clone)]
pub struct MemoryConflictError {
    pub message: String,
}

impl MemoryConflictError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }

    pub fn default() -> Self {
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

/// Error for invalid memory block names.
#[derive(Debug, Clone)]
pub struct InvalidBlockNameError {
    pub name: String,
}

impl fmt::Display for InvalidBlockNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid memory block name: '{}'", self.name)
    }
}

impl std::error::Error for InvalidBlockNameError {}

// ============================================================================
// MemoryBlockType — mirrors ghidra.program.model.mem.MemoryBlockType
// ============================================================================

/// The type of a memory block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemoryBlockType {
    /// Standard initialized/uninitialized block.
    Default,
    /// Bit-mapped block (each byte maps to a single bit in source).
    BitMapped,
    /// Byte-mapped block (bytes map to another memory region).
    ByteMapped,
}

impl MemoryBlockType {
    /// Human-readable name of this block type.
    pub fn name(&self) -> &'static str {
        match self {
            MemoryBlockType::Default => "Default",
            MemoryBlockType::BitMapped => "Bit Mapped",
            MemoryBlockType::ByteMapped => "Byte Mapped",
        }
    }
}

impl fmt::Display for MemoryBlockType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ============================================================================
// ByteMappingScheme — mirrors ghidra.program.database.mem.ByteMappingScheme
// ============================================================================

/// Describes a byte mapping/decimation scheme for byte-mapped sub-blocks.
///
/// A byte-mapped block maps some of its bytes to an underlying source memory region.
/// The mapping is defined by a ratio: `mapped_byte_count : mapped_source_byte_count`.
///
/// For example, a "2:4" scheme means 2 mapped bytes followed by 2 non-mapped (skipped)
/// bytes in the source region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteMappingScheme {
    /// Number of mapped bytes per pattern cycle (1..127).
    mapped_byte_count: u8,
    /// Total number of source bytes per pattern cycle (1..127).
    mapped_source_byte_count: u8,
    /// Non-mapped (skipped) source bytes per pattern cycle.
    non_mapped_byte_count: u8,
}

impl ByteMappingScheme {
    /// Create a 1:1 mapping scheme.
    pub fn one_to_one() -> Self {
        Self {
            mapped_byte_count: 1,
            mapped_source_byte_count: 1,
            non_mapped_byte_count: 0,
        }
    }

    /// Create a mapping scheme from a ratio of mapped bytes to source bytes.
    ///
    /// # Panics
    /// Panics if the ratio is invalid (values must be 1..=127 and
    /// `mapped_byte_count <= mapped_source_byte_count`).
    pub fn new(mapped_byte_count: u8, mapped_source_byte_count: u8) -> Self {
        Self::validate(mapped_byte_count, mapped_source_byte_count);
        let non_mapped = mapped_source_byte_count - mapped_byte_count;
        Self {
            mapped_byte_count,
            mapped_source_byte_count,
            non_mapped_byte_count: non_mapped,
        }
    }

    /// Create a mapping scheme from an encoded 14-bit value (for DB storage compatibility).
    /// A value of 0 represents the 1:1 default mapping.
    pub fn from_encoded(encoded: u16) -> Self {
        if encoded == 0 {
            return Self::one_to_one();
        }
        let mapped_byte_count = ((encoded >> 7) & 0x7F) as u8;
        let mapped_source_byte_count = (encoded & 0x7F) as u8;
        Self::new(mapped_byte_count, mapped_source_byte_count)
    }

    /// Create a mapping scheme from a string like "2:4".
    pub fn from_str(s: &str) -> Result<Self, String> {
        let colon = s.find(':').ok_or_else(|| {
            format!("invalid mapping scheme: {}", s)
        })?;
        let left: u8 = s[..colon].parse().map_err(|_| {
            format!("invalid mapping scheme: {}", s)
        })?;
        let right: u8 = s[colon + 1..].parse().map_err(|_| {
            format!("invalid mapping scheme: {}", s)
        })?;
        Ok(Self::new(left, right))
    }

    /// Validate a mapping ratio.
    fn validate(mapped_byte_count: u8, mapped_source_byte_count: u8) {
        if mapped_byte_count == 0
            || mapped_byte_count > 127
            || mapped_source_byte_count == 0
            || mapped_source_byte_count > 127
            || mapped_byte_count > mapped_source_byte_count
        {
            panic!(
                "invalid byte mapping ratio: {}:{}",
                mapped_byte_count, mapped_source_byte_count
            );
        }
    }

    /// Check if this is a 1:1 mapping.
    pub fn is_one_to_one_mapping(&self) -> bool {
        self.mapped_source_byte_count <= 1
    }

    /// Number of mapped bytes per source byte count.
    pub fn mapped_byte_count(&self) -> u8 {
        if self.is_one_to_one_mapping() {
            1
        } else {
            self.mapped_byte_count
        }
    }

    /// Number of source bytes per mapping ratio.
    pub fn mapped_source_byte_count(&self) -> u8 {
        if self.is_one_to_one_mapping() {
            1
        } else {
            self.mapped_source_byte_count
        }
    }

    /// Encode this scheme as a single 14-bit value for DB storage.
    /// Returns 0 for 1:1 mapping (legacy compatibility).
    pub fn encode(&self) -> u16 {
        if self.is_one_to_one_mapping() {
            0
        } else {
            ((self.mapped_byte_count as u16) << 7) | (self.mapped_source_byte_count as u16 & 0x7F)
        }
    }

    /// Calculate the mapped source address for a given offset within the sub-block.
    ///
    /// `mapped_source_base` is the source region's base [`Address`].
    /// `offset_in_sub_block` is the byte offset from the start of the mapped sub-block.
    ///
    /// Returns the corresponding address in the source region.
    pub fn get_mapped_source_address(
        &self,
        mapped_source_base: Address,
        offset_in_sub_block: u64,
    ) -> Address {
        if self.is_one_to_one_mapping() {
            return mapped_source_base.add(offset_in_sub_block);
        }
        let mbc = self.mapped_byte_count as u64;
        let msbc = self.mapped_source_byte_count as u64;
        let source_offset =
            msbc * (offset_in_sub_block / mbc) + (offset_in_sub_block % mbc);
        mapped_source_base.add(source_offset)
    }

    /// Calculate the address within the mapped block for a given source offset.
    ///
    /// `mapped_block_start` is the start address of the mapped block.
    /// `mapped_block_size` is the total size of the mapped block.
    /// `mapped_source_offset` is the byte offset into the source region (relative to the
    ///   mapping base).
    /// `skip_back` controls behaviour when the source offset hits a non-mapped byte:
    ///   - `true`: return the closest preceding mapped address.
    ///   - `false`: return the closest following mapped address, or `None` if impossible.
    pub fn get_mapped_address(
        &self,
        mapped_block_start: Address,
        mapped_block_size: u64,
        mapped_source_offset: u64,
        skip_back: bool,
    ) -> Option<Address> {
        if self.is_one_to_one_mapping() {
            if mapped_source_offset >= mapped_block_size {
                return None;
            }
            return Some(mapped_block_start.add(mapped_source_offset));
        }
        let mbc = self.mapped_byte_count as u64;
        let msbc = self.mapped_source_byte_count as u64;
        let mut mapped_offset = mbc * (mapped_source_offset / msbc);
        let offset_limit = mapped_block_size.saturating_sub(1);
        let modulo = mapped_source_offset % msbc;
        if modulo < mbc {
            mapped_offset += modulo;
        } else if !skip_back {
            mapped_offset += mbc;
            if mapped_offset > offset_limit {
                return None;
            }
        }
        Some(mapped_block_start.add(mapped_offset))
    }

    /// Read bytes through the mapping scheme from memory into `buf[off..]`.
    ///
    /// `memory` provides raw byte access for the source addresses.
    /// `mapped_source_base` is the source region base address.
    /// `offset_in_sub_block` is the start offset within the mapped sub-block.
    /// Returns the number of bytes actually read.
    pub fn get_bytes(
        &self,
        memory: &dyn Memory,
        mapped_source_base: Address,
        offset_in_sub_block: u64,
        buf: &mut [u8],
        off: usize,
        len: usize,
    ) -> Result<usize, GhidraError> {
        if self.is_one_to_one_mapping() {
            let addr = mapped_source_base.add(offset_in_sub_block);
            let mut tmp = vec![0u8; len];
            let n = memory.get_bytes(addr, &mut tmp, off, len)?;
            let end = off + n;
            buf[off..end].copy_from_slice(&tmp[..n]);
            return Ok(n);
        }

        let mbc = self.mapped_byte_count as u64;
        let msbc = self.mapped_source_byte_count as u64;
        let pattern_count = offset_in_sub_block / mbc;
        let partial = (offset_in_sub_block % mbc) as usize;
        let mapped_offset = msbc * pattern_count + partial as u64;

        // Read a generous buffer to avoid incremental reads
        let buf_size = (msbc as usize) * ((len / mbc as usize) + 1);
        let mut raw = vec![0u8; buf_size];
        let src_addr = mapped_source_base.add(mapped_offset);
        let raw_cnt = memory.get_bytes(src_addr, &mut raw, 0, buf_size)?;

        let mut cnt = 0;
        let mut idx = off;
        let mut ri = 0usize;
        let mut rem = mbc as usize - partial;
        let mut skipping = false;
        while ri < raw_cnt && cnt < len {
            if !skipping {
                buf[idx] = raw[ri];
                idx += 1;
                cnt += 1;
                rem -= 1;
                if rem == 0 {
                    skipping = true;
                    rem = self.non_mapped_byte_count as usize;
                }
            } else {
                rem -= 1;
                if rem == 0 {
                    skipping = false;
                    rem = mbc as usize;
                }
            }
            ri += 1;
        }
        Ok(cnt)
    }

    /// Write bytes through the mapping scheme to memory.
    ///
    /// `memory` provides raw byte write access.
    /// `mapped_source_base` is the source region base address.
    /// `offset_in_sub_block` is the start offset within the mapped sub-block.
    pub fn set_bytes(
        &self,
        memory: &mut dyn Memory,
        mapped_source_base: Address,
        offset_in_sub_block: u64,
        buf: &[u8],
        off: usize,
        len: usize,
    ) -> Result<(), GhidraError> {
        if self.is_one_to_one_mapping() {
            let addr = mapped_source_base.add(offset_in_sub_block);
            memory.set_bytes(addr, buf, off, len)
        } else {
            let mbc = self.mapped_byte_count as u64;
            let msbc = self.mapped_source_byte_count as u64;
            let pattern_count = offset_in_sub_block / mbc;
            let partial = (offset_in_sub_block % mbc) as usize;
            let mapped_offset = msbc * pattern_count + partial as u64;

            let mut dest_addr = mapped_source_base.add(mapped_offset);
            let mut index = off;
            let mut cnt = 0;
            let mut remaining = mbc as usize - partial;
            while cnt < len {
                let chunk = remaining.min(len - cnt);
                memory.set_bytes(dest_addr, buf, index, chunk)?;
                index += chunk;
                cnt += chunk;
                dest_addr = dest_addr.add(chunk as u64 + self.non_mapped_byte_count as u64);
                remaining = mbc as usize;
            }
            Ok(())
        }
    }
}

impl fmt::Display for ByteMappingScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_one_to_one_mapping() {
            write!(f, "1:1 mapping")
        } else {
            write!(
                f,
                "{}:{} mapping",
                self.mapped_byte_count, self.mapped_source_byte_count
            )
        }
    }
}

impl Default for ByteMappingScheme {
    fn default() -> Self {
        Self::one_to_one()
    }
}

// ============================================================================
// MemoryBlockSourceInfo — mirrors ghidra.program.model.mem.MemoryBlockSourceInfo
// ============================================================================

/// Describes the source of bytes for a portion of a memory block.
///
/// A memory block may be backed by multiple sources (e.g., after joining blocks).
/// Each source is described by a [`MemoryBlockSourceInfo`].
#[derive(Debug, Clone)]
pub struct MemoryBlockSourceInfo {
    /// Length of this byte source in bytes.
    pub length: u64,
    /// Start address where this byte source is mapped.
    pub min_address: Address,
    /// End address where this byte source is mapped.
    pub max_address: Address,
    /// Description of this source.
    pub description: String,
    /// Optional file bytes ID that backs this source.
    pub file_bytes_id: Option<u64>,
    /// Offset into the underlying file bytes where this source starts, or -1 if N/A.
    pub file_bytes_offset: i64,
    /// Optional mapped address range (for bit/byte-mapped blocks).
    pub mapped_range: Option<AddressRange>,
    /// Optional byte mapping scheme (for byte-mapped blocks).
    pub byte_mapping_scheme: Option<ByteMappingScheme>,
}

impl MemoryBlockSourceInfo {
    /// Create a simple source info for an initialized block.
    pub fn new_initialized(
        length: u64,
        min_address: Address,
        file_bytes_id: Option<u64>,
        file_bytes_offset: i64,
    ) -> Self {
        let max_address = min_address.add(length.saturating_sub(1));
        Self {
            length,
            min_address,
            max_address,
            description: String::new(),
            file_bytes_id,
            file_bytes_offset,
            mapped_range: None,
            byte_mapping_scheme: None,
        }
    }

    /// Create a source info for a byte-mapped block.
    pub fn new_byte_mapped(
        length: u64,
        min_address: Address,
        mapped_range: AddressRange,
        scheme: ByteMappingScheme,
    ) -> Self {
        let max_address = min_address.add(length.saturating_sub(1));
        Self {
            length,
            min_address,
            max_address,
            description: format!("Mapped: {}", scheme),
            file_bytes_id: None,
            file_bytes_offset: -1,
            mapped_range: Some(mapped_range),
            byte_mapping_scheme: Some(scheme),
        }
    }

    /// Create a source info for a bit-mapped block.
    pub fn new_bit_mapped(length: u64, min_address: Address, mapped_range: AddressRange) -> Self {
        let max_address = min_address.add(length.saturating_sub(1));
        Self {
            length,
            min_address,
            max_address,
            description: "Bit Mapped".to_string(),
            file_bytes_id: None,
            file_bytes_offset: -1,
            mapped_range: Some(mapped_range),
            byte_mapping_scheme: None,
        }
    }

    /// Check if the given address is within this source.
    pub fn contains(&self, address: &Address) -> bool {
        address.offset >= self.min_address.offset && address.offset <= self.max_address.offset
    }

    /// Check if this source contains the specified file offset.
    pub fn contains_file_offset(&self, file_offset: u64) -> bool {
        let start = self.file_bytes_offset;
        if start < 0 {
            return false;
        }
        let start = start as u64;
        let end = start + self.length.saturating_sub(1);
        file_offset >= start && file_offset <= end
    }

    /// Get the address within this source that corresponds to the given file offset.
    pub fn locate_address_for_file_offset(&self, file_offset: u64) -> Option<Address> {
        if !self.contains_file_offset(file_offset) {
            return None;
        }
        let start = self.file_bytes_offset as u64;
        let offset = file_offset.saturating_sub(start);
        if offset >= self.length {
            return None;
        }
        Some(self.min_address.add(offset))
    }
}

// ============================================================================
// MemoryBlock — mirrors ghidra.program.model.mem.MemoryBlock
// ============================================================================

/// A contiguous block of memory within a program.
///
/// Each block has a type, permissions, optional source info, and may be mapped
/// to another region via byte/bit mapping.
#[derive(Debug, Clone)]
pub struct MemoryBlock {
    /// Block name (must be unique and valid per `is_valid_memory_block_name`).
    pub name: String,
    /// Address range this block occupies.
    pub range: AddressRange,
    /// Type of this memory block.
    pub block_type: MemoryBlockType,
    /// Permission and attribute flags (bitmask of `FLAG_*`).
    pub flags: u8,
    /// Comment associated with this block.
    pub comment: String,
    /// Name of the source file that provided the data.
    pub source_name: String,
    /// Source info objects describing backing byte sources.
    pub source_infos: Vec<MemoryBlockSourceInfo>,
    /// Whether the block is initialized (has known data).
    pub initialized: bool,
    /// Raw data bytes (for initialized blocks).
    pub data: Vec<u8>,
    /// Optional mapped source base address (for byte/bit-mapped blocks).
    pub mapped_source_base: Option<Address>,
    /// Optional byte mapping scheme (for byte-mapped blocks).
    pub mapping_scheme: Option<ByteMappingScheme>,
    /// Whether this block resides in an overlay address space.
    pub is_overlay: bool,
    /// Whether this is a real loaded block (not a special file-header block).
    pub is_loaded: bool,
}

impl MemoryBlock {
    /// Create a simple initialized memory block.
    pub fn new_initialized(
        name: impl Into<String>,
        range: AddressRange,
        flags: u8,
        data: Vec<u8>,
    ) -> Self {
        let len = range.len();
        let min_addr = range.start;
        let source_info = MemoryBlockSourceInfo::new_initialized(len, min_addr, None, -1);
        Self {
            name: name.into(),
            range,
            block_type: MemoryBlockType::Default,
            flags,
            comment: String::new(),
            source_name: String::new(),
            source_infos: vec![source_info],
            initialized: true,
            data,
            mapped_source_base: None,
            mapping_scheme: None,
            is_overlay: false,
            is_loaded: true,
        }
    }

    /// Create an uninitialized memory block.
    pub fn new_uninitialized(
        name: impl Into<String>,
        range: AddressRange,
        flags: u8,
    ) -> Self {
        let len = range.len();
        let min_addr = range.start;
        let source_info = MemoryBlockSourceInfo::new_initialized(len, min_addr, None, -1);
        Self {
            name: name.into(),
            range,
            block_type: MemoryBlockType::Default,
            flags,
            comment: String::new(),
            source_name: String::new(),
            source_infos: vec![source_info],
            initialized: false,
            data: Vec::new(),
            mapped_source_base: None,
            mapping_scheme: None,
            is_overlay: false,
            is_loaded: true,
        }
    }

    /// Create a byte-mapped memory block.
    pub fn new_byte_mapped(
        name: impl Into<String>,
        range: AddressRange,
        flags: u8,
        mapped_source_base: Address,
        scheme: ByteMappingScheme,
    ) -> Self {
        let len = range.len();
        let mapped_range = AddressRange::new(mapped_source_base, mapped_source_base.add(len));
        let source_info = MemoryBlockSourceInfo::new_byte_mapped(
            len,
            range.start,
            mapped_range,
            scheme.clone(),
        );
        Self {
            name: name.into(),
            range,
            block_type: MemoryBlockType::ByteMapped,
            flags,
            comment: String::new(),
            source_name: String::new(),
            source_infos: vec![source_info],
            initialized: false,
            data: Vec::new(),
            mapped_source_base: Some(mapped_source_base),
            mapping_scheme: Some(scheme),
            is_overlay: false,
            is_loaded: true,
        }
    }

    /// Create a bit-mapped memory block.
    pub fn new_bit_mapped(
        name: impl Into<String>,
        range: AddressRange,
        flags: u8,
        mapped_source_base: Address,
    ) -> Self {
        let len = range.len();
        let mapped_range = AddressRange::new(mapped_source_base, mapped_source_base.add(len));
        let source_info =
            MemoryBlockSourceInfo::new_bit_mapped(len, range.start, mapped_range);
        Self {
            name: name.into(),
            range,
            block_type: MemoryBlockType::BitMapped,
            flags,
            comment: String::new(),
            source_name: String::new(),
            source_infos: vec![source_info],
            initialized: false,
            data: Vec::new(),
            mapped_source_base: Some(mapped_source_base),
            mapping_scheme: None,
            is_overlay: false,
            is_loaded: true,
        }
    }

    // ---- property accessors ----

    /// Get the start address of this block.
    pub fn start(&self) -> Address {
        self.range.start
    }

    /// Get the end address (inclusive) of this block.
    pub fn end(&self) -> Address {
        self.range.end
    }

    /// Number of bytes in this block.
    pub fn size(&self) -> u64 {
        self.range.len()
    }

    /// Check whether the given address is within this block.
    pub fn contains(&self, addr: &Address) -> bool {
        self.range.contains(addr)
    }

    /// Get the address range.
    pub fn address_range(&self) -> &AddressRange {
        &self.range
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
    /// Whether this block is volatile (e.g., memory-mapped I/O).
    pub fn is_volatile(&self) -> bool {
        (self.flags & FLAG_VOLATILE) != 0
    }
    /// Whether this block is artificial (fabricated for analysis).
    pub fn is_artificial(&self) -> bool {
        (self.flags & FLAG_ARTIFICIAL) != 0
    }
    /// Whether this is a mapped block (bit-mapped or byte-mapped).
    pub fn is_mapped(&self) -> bool {
        matches!(
            self.block_type,
            MemoryBlockType::BitMapped | MemoryBlockType::ByteMapped
        )
    }
    /// Whether this is the reserved EXTERNAL block.
    pub fn is_external_block(&self) -> bool {
        self.name == EXTERNAL_BLOCK_NAME
    }

    // ---- byte-level access (used by Memory) ----

    /// Read a single byte at the given address within this block.
    pub fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessError> {
        if !self.contains(addr) {
            return Err(MemoryAccessError::new(format!(
                "Address {} is not in block '{}'",
                addr, self.name
            )));
        }
        let offset = (addr.offset - self.range.start.offset) as usize;
        if offset >= self.data.len() {
            return Err(MemoryAccessError::new(format!(
                "Address {} is uninitialized in block '{}'",
                addr, self.name
            )));
        }
        Ok(self.data[offset])
    }

    /// Read bytes from this block into `buf[off..off+len]`.
    /// Returns the number of bytes actually read.
    pub fn get_bytes(
        &self,
        addr: &Address,
        buf: &mut [u8],
        off: usize,
        len: usize,
    ) -> Result<usize, MemoryAccessError> {
        if !self.contains(addr) {
            return Err(MemoryAccessError::new(format!(
                "Address {} is not in block '{}'",
                addr, self.name
            )));
        }
        let start = (addr.offset - self.range.start.offset) as usize;
        let available = self.data.len().saturating_sub(start);
        let actual = len.min(available);
        if actual == 0 {
            return Err(MemoryAccessError::new(format!(
                "No initialized bytes at {} in block '{}'",
                addr, self.name
            )));
        }
        let end = off + actual;
        buf[off..end].copy_from_slice(&self.data[start..start + actual]);
        Ok(actual)
    }

    /// Write a single byte at the given address.
    pub fn put_byte(&self, _addr: &Address, _value: u8) -> Result<(), MemoryAccessError> {
        // This is a read-oriented view; mutation goes through MemoryMap.
        Err(MemoryAccessError::new("Direct block mutation not supported; use MemoryMap"))
    }

    /// Write bytes at the given address.
    /// Returns the number of bytes actually written.
    pub fn put_bytes(
        &self,
        _addr: &Address,
        _buf: &[u8],
        _off: usize,
        _len: usize,
    ) -> Result<usize, MemoryAccessError> {
        Err(MemoryAccessError::new("Direct block mutation not supported; use MemoryMap"))
    }
}

impl PartialEq for MemoryBlock {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.range == other.range
    }
}

impl Eq for MemoryBlock {}

impl PartialOrd for MemoryBlock {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.range.start.offset.cmp(&other.range.start.offset))
    }
}

impl Ord for MemoryBlock {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.range.start.offset.cmp(&other.range.start.offset)
    }
}

// ============================================================================
// MemBuffer trait — mirrors ghidra.program.model.mem.MemBuffer
// ============================================================================

/// Provides an array-like interface into memory at a specific address.
///
/// Bytes are retrieved using a positive offset from the current position.
/// This is used by language parsers to read disassembly operands efficiently.
pub trait MemBuffer: Send + Sync {
    /// Get one byte at `offset` from the current position.
    fn get_byte(&self, offset: i64) -> Result<u8, MemoryAccessError>;

    /// Get one unsigned byte at `offset` from the current position.
    fn get_unsigned_byte(&self, offset: i64) -> Result<u16, MemoryAccessError> {
        self.get_byte(offset).map(|b| b as u16 & 0xFF)
    }

    /// Read bytes into `buf` starting at `offset`.
    /// Returns the number of bytes actually read.
    fn get_bytes(&self, buf: &mut [u8], offset: i64) -> usize;

    /// Get the address corresponding to offset 0.
    fn get_address(&self) -> Address;

    /// Get the [`Memory`] object used by this buffer, if available.
    fn get_memory(&self) -> Option<&dyn Memory>;

    /// Whether the underlying bytes are big-endian.
    fn is_big_endian(&self) -> bool;

    /// Whether the first byte of the buffer is readable (initialized).
    fn is_initialized_memory(&self) -> bool {
        self.get_byte(0).is_ok()
    }

    /// Read a 2-byte short at the given offset, respecting endianness.
    fn get_short(&self, offset: i64) -> Result<i16, MemoryAccessError> {
        let mut buf = [0u8; 2];
        let n = self.get_bytes(&mut buf, offset);
        if n < 2 {
            return Err(MemoryAccessError::new("Cannot read short: not enough bytes"));
        }
        Ok(if self.is_big_endian() {
            i16::from_be_bytes(buf)
        } else {
            i16::from_le_bytes(buf)
        })
    }

    /// Read an unsigned 2-byte short at the given offset.
    fn get_unsigned_short(&self, offset: i64) -> Result<u16, MemoryAccessError> {
        self.get_short(offset).map(|v| v as u16)
    }

    /// Read a 4-byte int at the given offset, respecting endianness.
    fn get_int(&self, offset: i64) -> Result<i32, MemoryAccessError> {
        let mut buf = [0u8; 4];
        let n = self.get_bytes(&mut buf, offset);
        if n < 4 {
            return Err(MemoryAccessError::new("Cannot read int: not enough bytes"));
        }
        Ok(if self.is_big_endian() {
            i32::from_be_bytes(buf)
        } else {
            i32::from_le_bytes(buf)
        })
    }

    /// Read an unsigned 4-byte int at the given offset.
    fn get_unsigned_int(&self, offset: i64) -> Result<u64, MemoryAccessError> {
        self.get_int(offset).map(|v| v as u32 as u64)
    }

    /// Read an 8-byte long at the given offset, respecting endianness.
    fn get_long(&self, offset: i64) -> Result<i64, MemoryAccessError> {
        let mut buf = [0u8; 8];
        let n = self.get_bytes(&mut buf, offset);
        if n < 8 {
            return Err(MemoryAccessError::new("Cannot read long: not enough bytes"));
        }
        Ok(if self.is_big_endian() {
            i64::from_be_bytes(buf)
        } else {
            i64::from_le_bytes(buf)
        })
    }

    /// Read a big-integer of `size` bytes at the given offset.
    fn get_big_integer(
        &self,
        offset: i64,
        size: usize,
        signed: bool,
    ) -> Result<num_bigint::BigInt, MemoryAccessError> {
        use num_bigint::{BigInt, Sign};
        if size == 0 {
            return Ok(BigInt::from(0u8));
        }
        let mut buf = vec![0u8; size];
        let n = self.get_bytes(&mut buf, offset);
        if n < size {
            return Err(MemoryAccessError::new("Cannot read big integer: not enough bytes"));
        }
        if self.is_big_endian() {
            buf.reverse();
        }
        Ok(BigInt::from_bytes_le(
            if signed && (buf.last().copied().unwrap_or(0) & 0x80) != 0 {
                Sign::Minus
            } else {
                Sign::Plus
            },
            &buf,
        ))
    }

    /// Read a variable-length signed integer (len = 1, 2, or 4 bytes).
    fn get_var_length_int(&self, offset: i64, len: usize) -> Result<i64, MemoryAccessError> {
        match len {
            1 => self.get_byte(offset).map(|b| b as i8 as i64),
            2 => self.get_short(offset).map(|v| v as i64),
            4 => self.get_int(offset).map(|v| v as i64),
            _ => Err(MemoryAccessError::new(format!(
                "Invalid length for read: {}",
                len
            ))),
        }
    }

    /// Read a variable-length unsigned integer (len = 1, 2, or 4 bytes).
    fn get_var_length_unsigned_int(
        &self,
        offset: i64,
        len: usize,
    ) -> Result<u64, MemoryAccessError> {
        match len {
            1 => self.get_byte(offset).map(|b| b as u64),
            2 => self.get_unsigned_short(offset).map(|v| v as u64),
            4 => self.get_unsigned_int(offset),
            _ => Err(MemoryAccessError::new(format!(
                "Invalid length for read: {}",
                len
            ))),
        }
    }
}

// ============================================================================
// MutableMemBuffer trait
// ============================================================================

/// A [`MemBuffer`] that also supports writing bytes.
pub trait MutableMemBuffer: MemBuffer {
    /// Write a byte at `offset` from the current position.
    fn set_byte(&mut self, offset: i64, value: u8) -> Result<(), MemoryAccessError>;

    /// Write bytes from `buf` at `offset` from the current position.
    fn set_bytes(&mut self, offset: i64, buf: &[u8]) -> Result<(), MemoryAccessError>;
}

// ============================================================================
// WrappedMemBuffer — mirrors ghidra.program.model.mem.WrappedMemBuffer
// ============================================================================

/// A zero-based index view on top of an underlying [`MemBuffer`] at a given address.
///
/// Optional internal buffering reduces the number of raw memory accesses. The
/// constructor that omits `buffer_size` disables buffering.
///
/// Not thread-safe.
pub struct WrappedMemBuffer<'a> {
    /// The underlying memory buffer.
    inner: Box<dyn MemBuffer + 'a>,
    /// True if the underlying memory is big-endian.
    big_endian: bool,
    /// Base offset from the inner buffer's start address (inner.addr + base_offset = addr(0)).
    base_offset: i64,
    /// The address corresponding to offset 0 in this buffer.
    address: Address,
    /// Internal cache buffer.
    buffer: Vec<u8>,
    /// Minimum offset currently cached.
    min_offset: i64,
    /// Maximum offset currently cached.
    max_offset: i64,
}

impl<'a> WrappedMemBuffer<'a> {
    /// Default buffer size (0 = no buffering).
    const DEFAULT_BUFSIZE: usize = 0;

    /// Construct a wrapped buffer with the default (no) buffer size.
    pub fn new(
        inner: Box<dyn MemBuffer + 'a>,
        base_offset: i64,
    ) -> Result<Self, MemoryAccessError> {
        Self::with_buffer_size(inner, Self::DEFAULT_BUFSIZE, base_offset)
    }

    /// Construct a wrapped buffer with a specific cache buffer size.
    pub fn with_buffer_size(
        inner: Box<dyn MemBuffer + 'a>,
        buffer_size: usize,
        base_offset: i64,
    ) -> Result<Self, MemoryAccessError> {
        let big_endian = inner.is_big_endian();
        let address = inner.get_address().add(base_offset as u64);
        let mut buffer = vec![0u8; buffer_size];

        let mut min_offset = 0i64;
        let mut max_offset = -1i64;

        // Pre-fill the cache if buffering is enabled
        if buffer_size > 0 {
            let mut tmp = vec![0u8; buffer_size];
            let n = inner.get_bytes(&mut tmp, base_offset);
            if n > 0 {
                buffer[..n].copy_from_slice(&tmp[..n]);
            }
            // Cache is indexed by our relative offsets (0..n-1)
            max_offset = (n as i64).saturating_sub(1);
            min_offset = 0;
        }

        Ok(Self {
            inner,
            big_endian,
            base_offset,
            address,
            buffer,
            min_offset,
            max_offset,
        })
    }

    /// Compute the offset into the inner buffer, guarding against wrap-around.
    fn compute_offset(&self, offset: i64) -> Result<i64, MemoryAccessError> {
        let buf_offset = self.base_offset + offset;
        if offset > 0 && buf_offset < self.base_offset {
            return Err(MemoryAccessError::new(
                "Invalid WrappedMemBuffer, offset would wrap underlying memory buffer",
            ));
        }
        if offset < 0 && buf_offset > self.base_offset {
            return Err(MemoryAccessError::new(
                "Invalid WrappedMemBuffer offset, offset would wrap underlying memory buffer",
            ));
        }
        Ok(buf_offset)
    }

    /// Fill the internal cache buffer starting at the given relative offset.
    #[allow(dead_code)]
    fn fill_buffer(&mut self, offset: i64) -> Result<(), MemoryAccessError> {
        let real_offset = self.compute_offset(offset)?;
        let mut tmp = vec![0u8; self.buffer.len()];
        let n = self.inner.get_bytes(&mut tmp, real_offset);
        if n == 0 {
            return Err(MemoryAccessError::new(
                "No bytes available in memory to cache",
            ));
        }
        let copy_len = n.min(self.buffer.len());
        self.buffer[..copy_len].copy_from_slice(&tmp[..copy_len]);
        self.min_offset = offset;
        self.max_offset = offset + (copy_len as i64) - 1;
        Ok(())
    }
}

impl<'a> MemBuffer for WrappedMemBuffer<'a> {
    fn get_byte(&self, offset: i64) -> Result<u8, MemoryAccessError> {
        if self.buffer.is_empty() {
            return self.inner.get_byte(self.compute_offset(offset)?);
        }
        if offset >= self.min_offset && offset <= self.max_offset {
            return Ok(self.buffer[(offset - self.min_offset) as usize]);
        }
        // We need mutable access — but the trait requires &self. Delegate to inner.
        // In Java the buffer cache is mutable behind a non-thread-safe contract;
        // for Rust we simplify: if buffer miss, fall back to inner directly.
        self.inner.get_byte(self.compute_offset(offset)?)
    }

    fn get_bytes(&self, buf: &mut [u8], offset: i64) -> usize {
        // If buffered and the request fits in the cache
        if !self.buffer.is_empty() && buf.len() <= self.buffer.len() {
            if offset >= self.min_offset
                && (buf.len() as i64 + offset - 1) <= self.max_offset
            {
                let start = (offset - self.min_offset) as usize;
                let end = start + buf.len();
                buf.copy_from_slice(&self.buffer[start..end]);
                return buf.len();
            }
        }
        // Fallback
        match self.compute_offset(offset) {
            Ok(real_offset) => self.inner.get_bytes(buf, real_offset),
            Err(_) => 0,
        }
    }

    fn get_address(&self) -> Address {
        self.address
    }

    fn get_memory(&self) -> Option<&dyn Memory> {
        self.inner.get_memory()
    }

    fn is_big_endian(&self) -> bool {
        self.big_endian
    }
}

// ============================================================================
// Memory trait — mirrors ghidra.program.model.mem.Memory
// ============================================================================

/// The central interface for inspecting and managing the memory model of a program.
///
/// Provides block creation, removal, byte-level read/write, and search operations.
/// All block manipulations require exclusive access.
pub trait Memory: Send + Sync {
    // ---- constants ----

    /// The maximum permitted size of all memory blocks (16 GiB).
    fn max_binary_size(&self) -> u64 {
        MAX_BINARY_SIZE
    }

    /// The maximum permitted size of a single memory block.
    fn max_block_size(&self) -> u64 {
        MAX_BLOCK_SIZE
    }

    /// Check if an address is in the reserved EXTERNAL block.
    fn is_external_block_address(&self, addr: &Address) -> bool {
        if let Some(block) = self.get_block(addr) {
            return block.is_external_block();
        }
        false
    }

    /// Validate a block name: non-empty, no control characters (ASCII 0..=0x19).
    fn is_valid_memory_block_name(&self, name: &str) -> bool {
        if name.is_empty() {
            return false;
        }
        name.chars().all(|c| (c as u32) >= 0x20)
    }

    /// Locate addresses in memory that correspond to a file offset.
    fn locate_addresses_for_file_offset(&self, file_offset: u64) -> Vec<Address> {
        let mut result = Vec::new();
        for block in self.get_blocks() {
            for info in &block.source_infos {
                if let Some(addr) = info.locate_address_for_file_offset(file_offset) {
                    result.push(addr);
                }
            }
        }
        result
    }

    /// Get the source info for the byte at the given address.
    fn get_address_source_info(&self, addr: &Address) -> Option<&MemoryBlockSourceInfo> {
        let block = self.get_block(addr)?;
        block.source_infos.iter().find(|info| info.contains(addr))
    }

    // ---- address set queries ----

    /// The set of addresses corresponding to all loaded, initialized memory blocks.
    fn loaded_and_initialized_address_set(&self) -> Vec<AddressRange>;

    /// The set of addresses corresponding to all initialized memory blocks
    /// (including non-loaded blocks like debug sections).
    fn all_initialized_address_set(&self) -> Vec<AddressRange>;

    /// The set of executable addresses.
    fn execute_set(&self) -> Vec<AddressRange>;

    // ---- properties ----

    /// Whether memory defaults to big-endian byte order.
    fn is_big_endian(&self) -> bool;

    /// Total memory size in bytes.
    fn total_size(&self) -> u64;

    // ---- block lookup ----

    /// Find the block containing the given address.
    fn get_block(&self, addr: &Address) -> Option<&MemoryBlock>;

    /// Find the block with the given name.
    fn get_block_by_name(&self, name: &str) -> Option<&MemoryBlock>;

    /// Get all memory blocks.
    fn get_blocks(&self) -> Vec<&MemoryBlock>;

    // ---- block creation ----

    /// Create an initialized block filled with zeroes from an input stream concept.
    /// `data` provides the initial byte content.
    fn create_initialized_block(
        &mut self,
        name: &str,
        start: Address,
        data: Vec<u8>,
        is_overlay: bool,
    ) -> Result<&MemoryBlock, GhidraError>;

    /// Create an initialized block filled with a constant byte value.
    fn create_initialized_block_value(
        &mut self,
        name: &str,
        start: Address,
        size: u64,
        initial_value: u8,
        is_overlay: bool,
    ) -> Result<&MemoryBlock, GhidraError>;

    /// Create an uninitialized block.
    fn create_uninitialized_block(
        &mut self,
        name: &str,
        start: Address,
        size: u64,
        is_overlay: bool,
    ) -> Result<&MemoryBlock, GhidraError>;

    /// Create a bit-mapped block.
    fn create_bit_mapped_block(
        &mut self,
        name: &str,
        start: Address,
        mapped_address: Address,
        length: u64,
        is_overlay: bool,
    ) -> Result<&MemoryBlock, GhidraError>;

    /// Create a byte-mapped block with a specific mapping scheme.
    fn create_byte_mapped_block(
        &mut self,
        name: &str,
        start: Address,
        mapped_address: Address,
        length: u64,
        scheme: Option<ByteMappingScheme>,
        is_overlay: bool,
    ) -> Result<&MemoryBlock, GhidraError>;

    /// Create a block from another block's properties.
    fn create_block_from(
        &mut self,
        block: &MemoryBlock,
        name: &str,
        start: Address,
        length: u64,
    ) -> Result<&MemoryBlock, GhidraError>;

    // ---- block manipulation ----

    /// Remove a memory block.
    fn remove_block(&mut self, block_name: &str) -> Result<(), GhidraError>;

    /// Move a memory block to a new start address.
    fn move_block(
        &mut self,
        block_name: &str,
        new_start: Address,
    ) -> Result<(), GhidraError>;

    /// Split a block at the given address (which becomes the start of a new block).
    fn split_block(&mut self, block_name: &str, at: Address) -> Result<(), GhidraError>;

    /// Join two contiguous blocks into one.
    fn join_blocks(
        &mut self,
        block_one: &str,
        block_two: &str,
    ) -> Result<String, GhidraError>;

    /// Convert an uninitialized block to initialized with a fill value.
    fn convert_to_initialized(
        &mut self,
        block_name: &str,
        initial_value: u8,
    ) -> Result<(), GhidraError>;

    /// Convert an initialized block to uninitialized (discarding data).
    fn convert_to_uninitialized(&mut self, block_name: &str) -> Result<(), GhidraError>;

    // ---- byte read ----

    /// Read a single byte.
    fn get_byte(&self, addr: Address) -> Result<u8, GhidraError>;

    /// Read bytes into `dest`. Returns number of bytes read.
    fn get_bytes(&self, addr: Address, dest: &mut [u8], dest_index: usize, size: usize)
        -> Result<usize, GhidraError>;

    /// Read a 2-byte short.
    fn get_short(&self, addr: Address) -> Result<i16, GhidraError>;

    /// Read a 2-byte short with explicit endianness.
    fn get_short_endian(&self, addr: Address, big_endian: bool) -> Result<i16, GhidraError>;

    /// Read a 4-byte int.
    fn get_int(&self, addr: Address) -> Result<i32, GhidraError>;

    /// Read a 4-byte int with explicit endianness.
    fn get_int_endian(&self, addr: Address, big_endian: bool) -> Result<i32, GhidraError>;

    /// Read an 8-byte long.
    fn get_long(&self, addr: Address) -> Result<i64, GhidraError>;

    /// Read an 8-byte long with explicit endianness.
    fn get_long_endian(&self, addr: Address, big_endian: bool) -> Result<i64, GhidraError>;

    // ---- byte write ----

    /// Write a single byte.
    fn set_byte(&mut self, addr: Address, value: u8) -> Result<(), GhidraError>;

    /// Write bytes.
    fn set_bytes(
        &mut self,
        addr: Address,
        source: &[u8],
        source_index: usize,
        size: usize,
    ) -> Result<(), GhidraError>;

    /// Write a 2-byte short.
    fn set_short(&mut self, addr: Address, value: i16) -> Result<(), GhidraError>;

    /// Write a 4-byte int.
    fn set_int(&mut self, addr: Address, value: i32) -> Result<(), GhidraError>;

    /// Write an 8-byte long.
    fn set_long(&mut self, addr: Address, value: i64) -> Result<(), GhidraError>;

    // ---- search ----

    /// Find a sequence of bytes (with optional mask) in loaded memory.
    /// Returns the address of the first match, or `None`.
    fn find_bytes(
        &self,
        start_addr: Address,
        end_addr: Address,
        bytes: &[u8],
        masks: Option<&[u8]>,
        forward: bool,
    ) -> Option<Address>;

}

// ============================================================================
// MemoryMap — concrete implementation of Memory (analogous to MemoryMapImpl)
// ============================================================================

/// The concrete memory map implementation.
///
/// Manages a collection of [`MemoryBlock`]s and provides read/write access
/// with endianness awareness and error handling.
#[derive(Debug, Clone)]
pub struct MemoryMap {
    /// All memory blocks keyed by name.
    blocks: HashMap<String, MemoryBlock>,
    /// Blocks ordered by start address for efficient lookup.
    blocks_by_addr: Vec<String>,
    /// Whether the memory space is big-endian.
    big_endian: bool,
}

impl MemoryMap {
    /// Create a new, empty memory map.
    pub fn new(big_endian: bool) -> Self {
        Self {
            blocks: HashMap::new(),
            blocks_by_addr: Vec::new(),
            big_endian,
        }
    }

    /// Insert a block, maintaining the address-ordered index.
    fn insert_block(&mut self, block: MemoryBlock) -> Result<(), GhidraError> {
        let name = block.name.clone();
        // Validate name
        if !self.is_valid_memory_block_name(&name) {
            return Err(GhidraError::MemoryError(format!(
                "Invalid block name: '{}'",
                name
            )));
        }
        // Check for overlap with existing blocks
        for existing in self.blocks.values() {
            if !existing.is_overlay
                && !block.is_overlay
                && existing.range.start.offset <= block.range.end.offset
                && block.range.start.offset <= existing.range.end.offset
            {
                return Err(GhidraError::MemoryError(format!(
                    "Memory conflict: new block '{}' overlaps with existing block '{}'",
                    name, existing.name
                )));
            }
        }
        // Check total size limit
        let new_total: u64 = self.blocks.values().map(|b| b.size()).sum::<u64>() + block.size();
        if new_total > MAX_BINARY_SIZE {
            return Err(GhidraError::MemoryError(
                "Total memory size exceeds maximum".into(),
            ));
        }
        self.blocks.insert(name.clone(), block);
        self.blocks_by_addr.push(name);
        self.blocks_by_addr.sort_by(|a, b| {
            let ba = self.blocks.get(a).map(|blk| blk.start().offset).unwrap_or(0);
            let bb = self.blocks.get(b).map(|blk| blk.start().offset).unwrap_or(0);
            ba.cmp(&bb)
        });
        Ok(())
    }

    /// Find the block containing an address (returns name instead of reference for mutability compatibility).
    fn find_block_index(&self, addr: &Address) -> Option<&String> {
        // Binary search over ordered blocks
        let offsets: Vec<u64> = self
            .blocks_by_addr
            .iter()
            .filter_map(|name| self.blocks.get(name))
            .map(|b| b.start().offset)
            .collect();
        match offsets.binary_search(&addr.offset) {
            Ok(i) => {
                // Exact match on block start
                Some(&self.blocks_by_addr[i])
            }
            Err(0) => None,
            Err(i) => {
                // Check the block just before this insertion point
                let candidate_name = &self.blocks_by_addr[i - 1];
                let block = &self.blocks[candidate_name];
                if block.contains(addr) {
                    Some(candidate_name)
                } else {
                    None
                }
            }
        }
    }
}

impl Default for MemoryMap {
    fn default() -> Self {
        Self::new(false)
    }
}

impl Memory for MemoryMap {
    fn loaded_and_initialized_address_set(&self) -> Vec<AddressRange> {
        self.blocks
            .values()
            .filter(|b| b.is_loaded && b.initialized)
            .map(|b| b.range)
            .collect()
    }

    fn all_initialized_address_set(&self) -> Vec<AddressRange> {
        self.blocks
            .values()
            .filter(|b| b.initialized)
            .map(|b| b.range)
            .collect()
    }

    fn execute_set(&self) -> Vec<AddressRange> {
        self.blocks
            .values()
            .filter(|b| b.is_execute())
            .map(|b| b.range)
            .collect()
    }

    fn is_big_endian(&self) -> bool {
        self.big_endian
    }

    fn total_size(&self) -> u64 {
        self.blocks.values().map(|b| b.size()).sum()
    }

    fn get_block(&self, addr: &Address) -> Option<&MemoryBlock> {
        self.find_block_index(addr)
            .and_then(|name| self.blocks.get(name))
    }

    fn get_block_by_name(&self, name: &str) -> Option<&MemoryBlock> {
        self.blocks.get(name)
    }

    fn get_blocks(&self) -> Vec<&MemoryBlock> {
        self.blocks_by_addr
            .iter()
            .filter_map(|name| self.blocks.get(name))
            .collect()
    }

    fn create_initialized_block(
        &mut self,
        name: &str,
        start: Address,
        data: Vec<u8>,
        is_overlay: bool,
    ) -> Result<&MemoryBlock, GhidraError> {
        let size = data.len() as u64;
        let end = start.add(size.saturating_sub(1));
        let mut block = MemoryBlock::new_initialized(
            name,
            AddressRange::new(start, end),
            FLAG_READ | FLAG_WRITE | FLAG_EXECUTE,
            data,
        );
        block.is_overlay = is_overlay;
        self.insert_block(block)?;
        Ok(self.blocks.get(name).unwrap())
    }

    fn create_initialized_block_value(
        &mut self,
        name: &str,
        start: Address,
        size: u64,
        initial_value: u8,
        is_overlay: bool,
    ) -> Result<&MemoryBlock, GhidraError> {
        let data = vec![initial_value; size as usize];
        self.create_initialized_block(name, start, data, is_overlay)
    }

    fn create_uninitialized_block(
        &mut self,
        name: &str,
        start: Address,
        size: u64,
        is_overlay: bool,
    ) -> Result<&MemoryBlock, GhidraError> {
        let end = start.add(size.saturating_sub(1));
        let mut block = MemoryBlock::new_uninitialized(
            name,
            AddressRange::new(start, end),
            FLAG_READ | FLAG_WRITE | FLAG_EXECUTE,
        );
        block.is_overlay = is_overlay;
        self.insert_block(block)?;
        Ok(self.blocks.get(name).unwrap())
    }

    fn create_bit_mapped_block(
        &mut self,
        name: &str,
        start: Address,
        mapped_address: Address,
        length: u64,
        is_overlay: bool,
    ) -> Result<&MemoryBlock, GhidraError> {
        let end = start.add(length.saturating_sub(1));
        let mut block = MemoryBlock::new_bit_mapped(
            name,
            AddressRange::new(start, end),
            FLAG_READ | FLAG_WRITE,
            mapped_address,
        );
        block.is_overlay = is_overlay;
        self.insert_block(block)?;
        Ok(self.blocks.get(name).unwrap())
    }

    fn create_byte_mapped_block(
        &mut self,
        name: &str,
        start: Address,
        mapped_address: Address,
        length: u64,
        scheme: Option<ByteMappingScheme>,
        is_overlay: bool,
    ) -> Result<&MemoryBlock, GhidraError> {
        let end = start.add(length.saturating_sub(1));
        let scheme = scheme.unwrap_or_default();
        let mut block = MemoryBlock::new_byte_mapped(
            name,
            AddressRange::new(start, end),
            FLAG_READ | FLAG_WRITE,
            mapped_address,
            scheme,
        );
        block.is_overlay = is_overlay;
        self.insert_block(block)?;
        Ok(self.blocks.get(name).unwrap())
    }

    fn create_block_from(
        &mut self,
        block: &MemoryBlock,
        name: &str,
        start: Address,
        length: u64,
    ) -> Result<&MemoryBlock, GhidraError> {
        let end = start.add(length.saturating_sub(1));
        let range = AddressRange::new(start, end);
        let new_block = if block.initialized {
            let data = vec![0u8; length as usize];
            MemoryBlock::new_initialized(name, range, block.flags, data)
        } else {
            MemoryBlock::new_uninitialized(name, range, block.flags)
        };
        self.insert_block(new_block)?;
        Ok(self.blocks.get(name).unwrap())
    }

    fn remove_block(&mut self, block_name: &str) -> Result<(), GhidraError> {
        if self.blocks.remove(block_name).is_none() {
            return Err(GhidraError::NotFound(format!(
                "Memory block '{}' not found",
                block_name
            )));
        }
        self.blocks_by_addr.retain(|n| n != block_name);
        Ok(())
    }

    fn move_block(
        &mut self,
        block_name: &str,
        new_start: Address,
    ) -> Result<(), GhidraError> {
        // Validate and get block
        let block = self.blocks.get(block_name).ok_or_else(|| {
            GhidraError::NotFound(format!("Memory block '{}' not found", block_name))
        })?;
        let size = block.size();
        let new_end = new_start.add(size.saturating_sub(1));

        // Check for overlap with other blocks
        let name_to_check = block_name.to_string();
        for (other_name, other) in self.blocks.iter() {
            if *other_name != name_to_check
                && new_start.offset <= other.end().offset
                && other.start().offset <= new_end.offset
            {
                return Err(GhidraError::MemoryError(format!(
                    "Move conflict: '{}' would overlap '{}'",
                    block_name, other_name
                )));
            }
        }

        let block = self.blocks.get_mut(block_name).unwrap();
        block.range = AddressRange::new(new_start, new_end);
        // Update source infos
        for info in &mut block.source_infos {
            info.min_address = new_start;
            info.max_address = new_end;
        }
        self.blocks_by_addr.sort_by(|a, b| {
            let ba = self.blocks.get(a).map(|b| b.start().offset).unwrap_or(0);
            let bb = self.blocks.get(b).map(|b| b.start().offset).unwrap_or(0);
            ba.cmp(&bb)
        });
        Ok(())
    }

    fn split_block(&mut self, block_name: &str, at: Address) -> Result<(), GhidraError> {
        let block = self.blocks.get(block_name).ok_or_else(|| {
            GhidraError::NotFound(format!("Memory block '{}' not found", block_name))
        })?;
        if !block.contains(&at) {
            return Err(GhidraError::MemoryError(format!(
                "Address {} is not within block '{}'",
                at, block_name
            )));
        }
        if at.offset == block.start().offset {
            return Err(GhidraError::MemoryError(
                "Split at block start address is not meaningful".into(),
            ));
        }

        let block = self.blocks.get_mut(block_name).unwrap();
        let old_end = block.end();
        let split_offset = (at.offset - block.start().offset) as usize;

        // Shorten the original block to end at (at - 1)
        block.range.end = at.prev();
        let remaining_data = block.data.split_off(split_offset);
        block.data.shrink_to_fit();

        // Create the second block
        let second_name = format!("{}.split", block_name);
        let _remaining_len = remaining_data.len() as u64;
        let second_block = MemoryBlock::new_initialized(
            &second_name,
            AddressRange::new(at, old_end),
            block.flags,
            remaining_data,
        );
        self.blocks.insert(second_name.clone(), second_block);
        self.blocks_by_addr.push(second_name);
        self.blocks_by_addr.sort_by(|a, b| {
            let ba = self.blocks.get(a).map(|b| b.start().offset).unwrap_or(0);
            let bb = self.blocks.get(b).map(|b| b.start().offset).unwrap_or(0);
            ba.cmp(&bb)
        });
        Ok(())
    }

    fn join_blocks(
        &mut self,
        block_one: &str,
        block_two: &str,
    ) -> Result<String, GhidraError> {
        let (b1_end, b2_start, b1_type, b2_type) = {
            let b1 = self.blocks.get(block_one).ok_or_else(|| {
                GhidraError::NotFound(format!("Block '{}' not found", block_one))
            })?;
            let b2 = self.blocks.get(block_two).ok_or_else(|| {
                GhidraError::NotFound(format!("Block '{}' not found", block_two))
            })?;
            (b1.end(), b2.start(), b1.block_type, b2.block_type)
        };

        if b1_type != MemoryBlockType::Default || b2_type != MemoryBlockType::Default {
            return Err(GhidraError::MemoryError(
                "Join only supported for DEFAULT block types".into(),
            ));
        }
        if b1_end.next() != b2_start && b1_end != b2_start.prev() {
            return Err(GhidraError::MemoryError(
                "Blocks must be contiguous to join".into(),
            ));
        }

        let b2 = self.blocks.remove(block_two).unwrap();
        let b1 = self.blocks.get_mut(block_one).unwrap();
        b1.range.end = b2.end();
        b1.data.extend_from_slice(&b2.data);
        b1.source_infos.extend(b2.source_infos);

        self.blocks_by_addr.retain(|n| n != block_two);
        Ok(block_one.to_string())
    }

    fn convert_to_initialized(
        &mut self,
        block_name: &str,
        initial_value: u8,
    ) -> Result<(), GhidraError> {
        let block = self.blocks.get_mut(block_name).ok_or_else(|| {
            GhidraError::NotFound(format!("Block '{}' not found", block_name))
        })?;
        if block.initialized {
            return Ok(());
        }
        let size = block.size() as usize;
        block.data = vec![initial_value; size];
        block.initialized = true;
        Ok(())
    }

    fn convert_to_uninitialized(&mut self, block_name: &str) -> Result<(), GhidraError> {
        let block = self.blocks.get_mut(block_name).ok_or_else(|| {
            GhidraError::NotFound(format!("Block '{}' not found", block_name))
        })?;
        if !block.initialized {
            return Ok(());
        }
        block.data.clear();
        block.initialized = false;
        Ok(())
    }

    fn get_byte(&self, addr: Address) -> Result<u8, GhidraError> {
        let name = self.find_block_index(&addr).ok_or_else(|| {
            GhidraError::MemoryError(format!(
                "Address {} is not in any memory block",
                addr
            ))
        })?;

        let block = &self.blocks[name];
        match block.block_type {
            MemoryBlockType::Default => {
                block.get_byte(&addr).map_err(|e| e.into())
            }
            MemoryBlockType::ByteMapped => {
                // For byte-mapped blocks, delegate through the mapping scheme
                let base = block.mapped_source_base.ok_or_else(|| {
                    GhidraError::MemoryError("Mapped block without source base".into())
                })?;
                let default_scheme = ByteMappingScheme::one_to_one();
                let scheme = block.mapping_scheme.as_ref().unwrap_or(&default_scheme);
                let offset = addr.offset - block.start().offset;
                let src_addr = scheme.get_mapped_source_address(base, offset);
                // Recurse: this delegates to the source block
                self.get_byte(src_addr)
            }
            MemoryBlockType::BitMapped => {
                let base = block.mapped_source_base.ok_or_else(|| {
                    GhidraError::MemoryError("Bit-mapped block without source base".into())
                })?;
                let offset = addr.offset - block.start().offset;
                let src_addr = base.add(offset);
                let byte_val = self.get_byte(src_addr)?;
                // Each byte in the bit-mapped block corresponds to a single bit.
                // The source byte at that offset is mapped: bit at position 0 indicates value.
                Ok((byte_val & 0x01) as u8)
            }
        }
    }

    fn get_bytes(
        &self,
        addr: Address,
        dest: &mut [u8],
        dest_index: usize,
        size: usize,
    ) -> Result<usize, GhidraError> {
        let name = self.find_block_index(&addr).ok_or_else(|| {
            GhidraError::MemoryError(format!(
                "Address {} is not in any memory block",
                addr
            ))
        })?;

        let block = &self.blocks[name];
        match block.block_type {
            MemoryBlockType::Default => {
                let n = block
                    .get_bytes(&addr, dest, dest_index, size)
                    .map_err(|e| GhidraError::MemoryError(e.message))?;
                Ok(n)
            }
            MemoryBlockType::ByteMapped => {
                let base = block.mapped_source_base.ok_or_else(|| {
                    GhidraError::MemoryError("Mapped block without source base".into())
                })?;
                let default_scheme = ByteMappingScheme::one_to_one();
                let scheme = block.mapping_scheme.as_ref().unwrap_or(&default_scheme);
                let offset = addr.offset - block.start().offset;
                scheme.get_bytes(self, base, offset, dest, dest_index, size)
            }
            MemoryBlockType::BitMapped => {
                let base = block.mapped_source_base.ok_or_else(|| {
                    GhidraError::MemoryError("Bit-mapped block without source base".into())
                })?;
                let offset = addr.offset - block.start().offset;
                let mut count = 0;
                let end = dest_index + size;
                for i in dest_index..end {
                    if offset + count as u64 >= block.size() {
                        break;
                    }
                    let src_addr = base.add(offset + count as u64);
                    match self.get_byte(src_addr) {
                        Ok(b) => {
                            dest[i] = b & 0x01;
                            count += 1;
                        }
                        Err(_) => break,
                    }
                }
                Ok(count)
            }
        }
    }

    fn get_short(&self, addr: Address) -> Result<i16, GhidraError> {
        self.get_short_endian(addr, self.big_endian)
    }

    fn get_short_endian(&self, addr: Address, big_endian: bool) -> Result<i16, GhidraError> {
        let mut buf = [0u8; 2];
        let n = self.get_bytes(addr, &mut buf, 0, 2)?;
        if n < 2 {
            return Err(GhidraError::MemoryError("Not enough bytes for short".into()));
        }
        Ok(if big_endian {
            i16::from_be_bytes(buf)
        } else {
            i16::from_le_bytes(buf)
        })
    }

    fn get_int(&self, addr: Address) -> Result<i32, GhidraError> {
        self.get_int_endian(addr, self.big_endian)
    }

    fn get_int_endian(&self, addr: Address, big_endian: bool) -> Result<i32, GhidraError> {
        let mut buf = [0u8; 4];
        let n = self.get_bytes(addr, &mut buf, 0, 4)?;
        if n < 4 {
            return Err(GhidraError::MemoryError("Not enough bytes for int".into()));
        }
        Ok(if big_endian {
            i32::from_be_bytes(buf)
        } else {
            i32::from_le_bytes(buf)
        })
    }

    fn get_long(&self, addr: Address) -> Result<i64, GhidraError> {
        self.get_long_endian(addr, self.big_endian)
    }

    fn get_long_endian(&self, addr: Address, big_endian: bool) -> Result<i64, GhidraError> {
        let mut buf = [0u8; 8];
        let n = self.get_bytes(addr, &mut buf, 0, 8)?;
        if n < 8 {
            return Err(GhidraError::MemoryError("Not enough bytes for long".into()));
        }
        Ok(if big_endian {
            i64::from_be_bytes(buf)
        } else {
            i64::from_le_bytes(buf)
        })
    }

    fn set_byte(&mut self, addr: Address, value: u8) -> Result<(), GhidraError> {
        // Clone the block name to release the immutable borrow before mutable access
        let block_name = self
            .find_block_index(&addr)
            .cloned()
            .ok_or_else(|| {
                GhidraError::MemoryError(format!(
                    "Address {} is not in any memory block",
                    addr
                ))
            })?;
        // Now we have a copy of the name with no borrow on self
        let block = self.blocks.get_mut(&block_name).unwrap();
        if !block.is_write() {
            return Err(GhidraError::MemoryError(format!(
                "Block '{}' is not writable",
                block_name
            )));
        }
        if !block.initialized {
            return Err(GhidraError::MemoryError(format!(
                "Block '{}' is uninitialized",
                block_name
            )));
        }
        let offset = (addr.offset - block.start().offset) as usize;
        if offset >= block.data.len() {
            // Expand data if needed
            block.data.resize(offset + 1, 0);
        }
        block.data[offset] = value;
        Ok(())
    }

    fn set_bytes(
        &mut self,
        addr: Address,
        source: &[u8],
        source_index: usize,
        size: usize,
    ) -> Result<(), GhidraError> {
        // Clone the block name to release the immutable borrow before mutable access
        let block_name = self
            .find_block_index(&addr)
            .cloned()
            .ok_or_else(|| {
                GhidraError::MemoryError(format!(
                    "Address {} is not in any memory block",
                    addr
                ))
            })?;
        let block = self.blocks.get_mut(&block_name).unwrap();
        if !block.is_write() {
            return Err(GhidraError::MemoryError(format!(
                "Block '{}' is not writable",
                block_name
            )));
        }
        if !block.initialized {
            return Err(GhidraError::MemoryError(format!(
                "Block '{}' is uninitialized",
                block_name
            )));
        }
        let offset = (addr.offset - block.start().offset) as usize;
        let end_needed = offset + size;
        if end_needed > block.data.len() {
            block.data.resize(end_needed, 0);
        }
        let src_end = source_index + size;
        block.data[offset..offset + size].copy_from_slice(&source[source_index..src_end]);
        Ok(())
    }

    fn set_short(&mut self, addr: Address, value: i16) -> Result<(), GhidraError> {
        let buf = if self.big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        self.set_bytes(addr, &buf, 0, 2)
    }

    fn set_int(&mut self, addr: Address, value: i32) -> Result<(), GhidraError> {
        let buf = if self.big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        self.set_bytes(addr, &buf, 0, 4)
    }

    fn set_long(&mut self, addr: Address, value: i64) -> Result<(), GhidraError> {
        let buf = if self.big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        self.set_bytes(addr, &buf, 0, 8)
    }

    fn find_bytes(
        &self,
        start_addr: Address,
        end_addr: Address,
        bytes: &[u8],
        masks: Option<&[u8]>,
        forward: bool,
    ) -> Option<Address> {
        if bytes.is_empty() {
            return None;
        }
        let default_mask = vec![0xFFu8; bytes.len()];
        let mask = masks.unwrap_or(&default_mask);

        // Collect loaded memory data in the search range
        let mut addr = start_addr;
        let mut search_buffer = Vec::with_capacity((end_addr.offset - start_addr.offset + 1) as usize);

        if forward {
            while addr.offset <= end_addr.offset {
                match self.get_byte(addr) {
                    Ok(b) => {
                        search_buffer.push(b);
                        addr = addr.next();
                    }
                    Err(_) => break,
                }
            }
            // Linear search with mask
            if search_buffer.len() < bytes.len() {
                return None;
            }
            for i in 0..=search_buffer.len() - bytes.len() {
                let mut found = true;
                for j in 0..bytes.len() {
                    if search_buffer[i + j] & mask[j] != bytes[j] & mask[j] {
                        found = false;
                        break;
                    }
                }
                if found {
                    return Some(start_addr.add(i as u64));
                }
            }
        } else {
            // Backward search: collect bytes in reverse
            addr = end_addr;
            while addr.offset >= start_addr.offset {
                match self.get_byte(addr) {
                    Ok(b) => {
                        search_buffer.push(b);
                        if addr.offset == 0 {
                            break;
                        }
                        addr = addr.prev();
                    }
                    Err(_) => break,
                }
            }
            search_buffer.reverse();
            if search_buffer.len() < bytes.len() {
                return None;
            }
            for i in (0..=search_buffer.len() - bytes.len()).rev() {
                let mut found = true;
                for j in 0..bytes.len() {
                    if search_buffer[i + j] & mask[j] != bytes[j] & mask[j] {
                        found = false;
                        break;
                    }
                }
                if found {
                    return Some(start_addr.add(i as u64));
                }
            }
        }

        None
    }
}

impl MemoryMap {
    /// Get the set of blocks as an ordered vector.
    pub fn ordered_blocks(&self) -> Vec<&MemoryBlock> {
        self.get_blocks()
    }
}

// ============================================================================
// StubMemory — empty Memory implementation for testing/stubs
// ============================================================================

/// A stub memory implementation that contains no blocks.
/// Useful for testing and placeholder contexts.
#[derive(Debug, Clone, Default)]
pub struct StubMemory {
    big_endian: bool,
}

impl StubMemory {
    pub fn new(big_endian: bool) -> Self {
        Self { big_endian }
    }
}

impl Memory for StubMemory {
    fn loaded_and_initialized_address_set(&self) -> Vec<AddressRange> {
        Vec::new()
    }
    fn all_initialized_address_set(&self) -> Vec<AddressRange> {
        Vec::new()
    }
    fn execute_set(&self) -> Vec<AddressRange> {
        Vec::new()
    }
    fn is_big_endian(&self) -> bool {
        self.big_endian
    }
    fn total_size(&self) -> u64 {
        0
    }
    fn get_block(&self, _addr: &Address) -> Option<&MemoryBlock> {
        None
    }
    fn get_block_by_name(&self, _name: &str) -> Option<&MemoryBlock> {
        None
    }
    fn get_blocks(&self) -> Vec<&MemoryBlock> {
        Vec::new()
    }
    fn create_initialized_block(
        &mut self,
        _name: &str,
        _start: Address,
        _data: Vec<u8>,
        _is_overlay: bool,
    ) -> Result<&MemoryBlock, GhidraError> {
        Err(GhidraError::NotSupported("StubMemory".into()))
    }
    fn create_initialized_block_value(
        &mut self,
        _name: &str,
        _start: Address,
        _size: u64,
        _initial_value: u8,
        _is_overlay: bool,
    ) -> Result<&MemoryBlock, GhidraError> {
        Err(GhidraError::NotSupported("StubMemory".into()))
    }
    fn create_uninitialized_block(
        &mut self,
        _name: &str,
        _start: Address,
        _size: u64,
        _is_overlay: bool,
    ) -> Result<&MemoryBlock, GhidraError> {
        Err(GhidraError::NotSupported("StubMemory".into()))
    }
    fn create_bit_mapped_block(
        &mut self,
        _name: &str,
        _start: Address,
        _mapped_address: Address,
        _length: u64,
        _is_overlay: bool,
    ) -> Result<&MemoryBlock, GhidraError> {
        Err(GhidraError::NotSupported("StubMemory".into()))
    }
    fn create_byte_mapped_block(
        &mut self,
        _name: &str,
        _start: Address,
        _mapped_address: Address,
        _length: u64,
        _scheme: Option<ByteMappingScheme>,
        _is_overlay: bool,
    ) -> Result<&MemoryBlock, GhidraError> {
        Err(GhidraError::NotSupported("StubMemory".into()))
    }
    fn create_block_from(
        &mut self,
        _block: &MemoryBlock,
        _name: &str,
        _start: Address,
        _length: u64,
    ) -> Result<&MemoryBlock, GhidraError> {
        Err(GhidraError::NotSupported("StubMemory".into()))
    }
    fn remove_block(&mut self, _block_name: &str) -> Result<(), GhidraError> {
        Err(GhidraError::NotSupported("StubMemory".into()))
    }
    fn move_block(
        &mut self,
        _block_name: &str,
        _new_start: Address,
    ) -> Result<(), GhidraError> {
        Err(GhidraError::NotSupported("StubMemory".into()))
    }
    fn split_block(&mut self, _block_name: &str, _at: Address) -> Result<(), GhidraError> {
        Err(GhidraError::NotSupported("StubMemory".into()))
    }
    fn join_blocks(
        &mut self,
        _block_one: &str,
        _block_two: &str,
    ) -> Result<String, GhidraError> {
        Err(GhidraError::NotSupported("StubMemory".into()))
    }
    fn convert_to_initialized(
        &mut self,
        _block_name: &str,
        _initial_value: u8,
    ) -> Result<(), GhidraError> {
        Err(GhidraError::NotSupported("StubMemory".into()))
    }
    fn convert_to_uninitialized(&mut self, _block_name: &str) -> Result<(), GhidraError> {
        Err(GhidraError::NotSupported("StubMemory".into()))
    }
    fn get_byte(&self, _addr: Address) -> Result<u8, GhidraError> {
        Err(GhidraError::MemoryError(
            "Address is not in any memory block".into(),
        ))
    }
    fn get_bytes(
        &self,
        _addr: Address,
        _dest: &mut [u8],
        _dest_index: usize,
        _size: usize,
    ) -> Result<usize, GhidraError> {
        Err(GhidraError::MemoryError(
            "Address is not in any memory block".into(),
        ))
    }
    fn get_short(&self, _addr: Address) -> Result<i16, GhidraError> {
        Err(GhidraError::MemoryError("Address is not in memory".into()))
    }
    fn get_short_endian(&self, _addr: Address, _big_endian: bool) -> Result<i16, GhidraError> {
        Err(GhidraError::MemoryError("Address is not in memory".into()))
    }
    fn get_int(&self, _addr: Address) -> Result<i32, GhidraError> {
        Err(GhidraError::MemoryError("Address is not in memory".into()))
    }
    fn get_int_endian(&self, _addr: Address, _big_endian: bool) -> Result<i32, GhidraError> {
        Err(GhidraError::MemoryError("Address is not in memory".into()))
    }
    fn get_long(&self, _addr: Address) -> Result<i64, GhidraError> {
        Err(GhidraError::MemoryError("Address is not in memory".into()))
    }
    fn get_long_endian(&self, _addr: Address, _big_endian: bool) -> Result<i64, GhidraError> {
        Err(GhidraError::MemoryError("Address is not in memory".into()))
    }
    fn set_byte(&mut self, _addr: Address, _value: u8) -> Result<(), GhidraError> {
        Err(GhidraError::MemoryError(
            "Memory write not permitted".into(),
        ))
    }
    fn set_bytes(
        &mut self,
        _addr: Address,
        _source: &[u8],
        _source_index: usize,
        _size: usize,
    ) -> Result<(), GhidraError> {
        Err(GhidraError::MemoryError(
            "Memory write not permitted".into(),
        ))
    }
    fn set_short(&mut self, _addr: Address, _value: i16) -> Result<(), GhidraError> {
        Err(GhidraError::MemoryError(
            "Memory write not permitted".into(),
        ))
    }
    fn set_int(&mut self, _addr: Address, _value: i32) -> Result<(), GhidraError> {
        Err(GhidraError::MemoryError(
            "Memory write not permitted".into(),
        ))
    }
    fn set_long(&mut self, _addr: Address, _value: i64) -> Result<(), GhidraError> {
        Err(GhidraError::MemoryError(
            "Memory write not permitted".into(),
        ))
    }
    fn find_bytes(
        &self,
        _start_addr: Address,
        _end_addr: Address,
        _bytes: &[u8],
        _masks: Option<&[u8]>,
        _forward: bool,
    ) -> Option<Address> {
        None
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_memory() -> MemoryMap {
        MemoryMap::new(false)
    }

    #[test]
    fn test_create_initialized_block() {
        let mut mem = make_memory();
        let data = vec![0x90u8; 256];
        let start = Address::new(0x1000);
        let result = mem.create_initialized_block(".text", start, data.clone(), false);
        assert!(result.is_ok());
        let block = mem.get_block_by_name(".text").unwrap();
        assert_eq!(block.start(), start);
        assert_eq!(block.size(), 256);
        assert!(block.initialized);
        assert_eq!(block.data, data);
    }

    #[test]
    fn test_read_byte() {
        let mut mem = make_memory();
        let data = vec![0xCCu8; 16];
        mem.create_initialized_block(".text", Address::new(0x1000), data, false)
            .unwrap();
        let b = mem.get_byte(Address::new(0x1000)).unwrap();
        assert_eq!(b, 0xCC);
        let b = mem.get_byte(Address::new(0x100F)).unwrap();
        assert_eq!(b, 0xCC);
    }

    #[test]
    fn test_read_out_of_bounds() {
        let mem = make_memory();
        let result = mem.get_byte(Address::new(0xDEAD));
        assert!(result.is_err());
    }

    #[test]
    fn test_read_short() {
        let mut mem = make_memory();
        // 0x1000: 0x34 0x12 (little-endian 0x1234)
        let data = vec![0x34, 0x12, 0x00, 0x00];
        mem.create_initialized_block(".text", Address::new(0x1000), data, false)
            .unwrap();
        let s = mem.get_short(Address::new(0x1000)).unwrap();
        assert_eq!(s, 0x1234);
    }

    #[test]
    fn test_read_int() {
        let mut mem = make_memory();
        // 0x1000: 0x78 0x56 0x34 0x12 (little-endian 0x12345678)
        let data = vec![0x78, 0x56, 0x34, 0x12];
        mem.create_initialized_block(".text", Address::new(0x1000), data, false)
            .unwrap();
        let v = mem.get_int(Address::new(0x1000)).unwrap();
        assert_eq!(v, 0x12345678);
    }

    #[test]
    fn test_read_long() {
        let mut mem = make_memory();
        let data = vec![0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12];
        mem.create_initialized_block(".text", Address::new(0x1000), data, false)
            .unwrap();
        let v = mem.get_long(Address::new(0x1000)).unwrap();
        assert_eq!(v, 0x1234567890ABCDEF);
    }

    #[test]
    fn test_write_byte() {
        let mut mem = make_memory();
        mem.create_initialized_block(".text", Address::new(0x1000), vec![0u8; 16], false)
            .unwrap();
        mem.set_byte(Address::new(0x1004), 0x42).unwrap();
        assert_eq!(mem.get_byte(Address::new(0x1004)).unwrap(), 0x42);
    }

    #[test]
    fn test_set_short() {
        let mut mem = make_memory();
        mem.create_initialized_block(".text", Address::new(0x1000), vec![0u8; 16], false)
            .unwrap();
        mem.set_short(Address::new(0x1000), 0x1234).unwrap();
        assert_eq!(mem.get_byte(Address::new(0x1000)).unwrap(), 0x34);
        assert_eq!(mem.get_byte(Address::new(0x1001)).unwrap(), 0x12);
    }

    #[test]
    fn test_remove_block() {
        let mut mem = make_memory();
        mem.create_initialized_block(".text", Address::new(0x1000), vec![0u8; 16], false)
            .unwrap();
        assert!(mem.get_block_by_name(".text").is_some());
        mem.remove_block(".text").unwrap();
        assert!(mem.get_block_by_name(".text").is_none());
    }

    #[test]
    fn test_move_block() {
        let mut mem = make_memory();
        mem.create_initialized_block(".text", Address::new(0x1000), vec![0x90u8; 256], false)
            .unwrap();
        mem.move_block(".text", Address::new(0x2000)).unwrap();
        let block = mem.get_block_by_name(".text").unwrap();
        assert_eq!(block.start(), Address::new(0x2000));
        // Old address should be empty
        assert!(mem.get_block(&Address::new(0x1000)).is_none());
        // New address should contain the block
        assert!(mem.get_block(&Address::new(0x2000)).is_some());
    }

    #[test]
    fn test_split_block() {
        let mut mem = make_memory();
        mem.create_initialized_block(".text", Address::new(0x1000), vec![0x90u8; 256], false)
            .unwrap();
        mem.split_block(".text", Address::new(0x1080)).unwrap();
        let b1 = mem.get_block_by_name(".text").unwrap();
        let b2 = mem.get_block_by_name(".text.split").unwrap();
        assert_eq!(b1.end(), Address::new(0x107F));
        assert_eq!(b2.start(), Address::new(0x1080));
    }

    #[test]
    fn test_join_blocks() {
        let mut mem = make_memory();
        mem.create_initialized_block("A", Address::new(0x1000), vec![0xAAu8; 128], false)
            .unwrap();
        mem.create_initialized_block("B", Address::new(0x1080), vec![0xBBu8; 128], false)
            .unwrap();
        let joined = mem.join_blocks("A", "B").unwrap();
        assert_eq!(joined, "A");
        let block = mem.get_block_by_name("A").unwrap();
        assert_eq!(block.size(), 256);
        assert!(mem.get_block_by_name("B").is_none());
        // First byte from A
        assert_eq!(block.data[0], 0xAA);
        // First byte from B (at offset 128)
        assert_eq!(block.data[128], 0xBB);
    }

    #[test]
    fn test_convert_to_initialized() {
        let mut mem = make_memory();
        mem.create_uninitialized_block("heap", Address::new(0x5000), 64, false)
            .unwrap();
        mem.convert_to_initialized("heap", 0x00).unwrap();
        let block = mem.get_block_by_name("heap").unwrap();
        assert!(block.initialized);
        assert_eq!(block.data.len(), 64);
        assert_eq!(block.data[0], 0x00);
    }

    #[test]
    fn test_convert_to_uninitialized() {
        let mut mem = make_memory();
        mem.create_initialized_block("tmp", Address::new(0x7000), vec![0xFFu8; 32], false)
            .unwrap();
        mem.convert_to_uninitialized("tmp").unwrap();
        let block = mem.get_block_by_name("tmp").unwrap();
        assert!(!block.initialized);
        assert!(block.data.is_empty());
    }

    #[test]
    fn test_find_bytes_forward() {
        let mut mem = make_memory();
        let mut data = vec![0u8; 256];
        data[64..68].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        mem.create_initialized_block(".text", Address::new(0x1000), data, false)
            .unwrap();
        let result = mem.find_bytes(
            Address::new(0x1000),
            Address::new(0x10FF),
            &[0xDE, 0xAD, 0xBE, 0xEF],
            None,
            true,
        );
        assert_eq!(result, Some(Address::new(0x1040)));
    }

    #[test]
    fn test_find_bytes_with_mask() {
        let mut mem = make_memory();
        let mut data = vec![0u8; 256];
        data[32..36].copy_from_slice(&[0x55, 0xAA, 0x55, 0xAA]);
        mem.create_initialized_block(".text", Address::new(0x1000), data, false)
            .unwrap();
        // Search for 0x55 ignoring upper nibble (mask 0x0F)
        let result = mem.find_bytes(
            Address::new(0x1000),
            Address::new(0x10FF),
            &[0x05, 0x0A, 0x05, 0x0A],
            Some(&[0x0F, 0x0F, 0x0F, 0x0F]),
            true,
        );
        assert_eq!(result, Some(Address::new(0x1020)));
    }

    #[test]
    fn test_find_bytes_not_found() {
        let mut mem = make_memory();
        mem.create_initialized_block(".text", Address::new(0x1000), vec![0u8; 256], false)
            .unwrap();
        let result = mem.find_bytes(
            Address::new(0x1000),
            Address::new(0x10FF),
            &[0xDE, 0xAD, 0xBE, 0xEF],
            None,
            true,
        );
        assert_eq!(result, None);
    }

    #[test]
    fn test_overlap_detection() {
        let mut mem = make_memory();
        mem.create_initialized_block("A", Address::new(0x1000), vec![0u8; 256], false)
            .unwrap();
        let result =
            mem.create_initialized_block("B", Address::new(0x1050), vec![0u8; 256], false);
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_block_name() {
        assert!(MemoryMap::default().is_valid_memory_block_name(".text"));
        assert!(MemoryMap::default().is_valid_memory_block_name("MyBlock"));
        assert!(!MemoryMap::default().is_valid_memory_block_name(""));
        assert!(!MemoryMap::default().is_valid_memory_block_name("\x01block"));
    }

    #[test]
    fn test_byte_mapping_scheme_default() {
        let scheme = ByteMappingScheme::default();
        assert!(scheme.is_one_to_one_mapping());
        assert_eq!(scheme.mapped_byte_count(), 1);
        assert_eq!(scheme.mapped_source_byte_count(), 1);
        assert_eq!(scheme.encode(), 0);
    }

    #[test]
    fn test_byte_mapping_scheme_ratio() {
        let scheme = ByteMappingScheme::new(2, 4);
        assert!(!scheme.is_one_to_one_mapping());
        assert_eq!(scheme.mapped_byte_count(), 2);
        assert_eq!(scheme.mapped_source_byte_count(), 4);
    }

    #[test]
    fn test_byte_mapping_scheme_from_encoded() {
        let scheme = ByteMappingScheme::from_encoded(0);
        assert!(scheme.is_one_to_one_mapping());

        // Encode 2:4 -> (2 << 7) | 4 = 0x104 = 260
        let encoded = ((2u16) << 7) | 4u16;
        let scheme = ByteMappingScheme::from_encoded(encoded);
        assert_eq!(scheme.mapped_byte_count(), 2);
        assert_eq!(scheme.mapped_source_byte_count(), 4);
    }

    #[test]
    fn test_byte_mapping_scheme_from_str() {
        let scheme = ByteMappingScheme::from_str("3:6").unwrap();
        assert_eq!(scheme.mapped_byte_count(), 3);
        assert_eq!(scheme.mapped_source_byte_count(), 6);
    }

    #[test]
    fn test_byte_mapping_scheme_invalid_str() {
        assert!(ByteMappingScheme::from_str("invalid").is_err());
        assert!(ByteMappingScheme::from_str("a:b").is_err());
    }

    #[test]
    fn test_byte_mapping_get_mapped_source_address() {
        // 2:4 mapping: 2 mapped bytes, 2 skipped per cycle of 4
        let scheme = ByteMappingScheme::new(2, 4);
        let base = Address::new(0x1000);

        // Offset 0 in sub-block -> source offset 0
        assert_eq!(
            scheme.get_mapped_source_address(base, 0),
            Address::new(0x1000)
        );
        // Offset 1 -> source offset 1
        assert_eq!(
            scheme.get_mapped_source_address(base, 1),
            Address::new(0x1001)
        );
        // Offset 2 (skips to next pattern after 2 mapped): mappedOffset = 4*1 + 0 = 4
        assert_eq!(
            scheme.get_mapped_source_address(base, 2),
            Address::new(0x1004)
        );
    }

    #[test]
    fn test_memory_block_type_names() {
        assert_eq!(MemoryBlockType::Default.name(), "Default");
        assert_eq!(MemoryBlockType::BitMapped.name(), "Bit Mapped");
        assert_eq!(MemoryBlockType::ByteMapped.name(), "Byte Mapped");
    }

    #[test]
    fn test_memory_block_permissions() {
        let block = MemoryBlock::new_initialized(
            "test",
            AddressRange::new(Address::new(0x1000), Address::new(0x10FF)),
            FLAG_READ | FLAG_EXECUTE,
            vec![0u8; 256],
        );
        assert!(block.is_read());
        assert!(!block.is_write());
        assert!(block.is_execute());
        assert!(!block.is_volatile());
        assert!(!block.is_artificial());
    }

    #[test]
    fn test_memory_block_contains() {
        let block = MemoryBlock::new_initialized(
            "test",
            AddressRange::new(Address::new(0x1000), Address::new(0x10FF)),
            0,
            vec![0u8; 256],
        );
        assert!(block.contains(&Address::new(0x1000)));
        assert!(block.contains(&Address::new(0x1080)));
        assert!(block.contains(&Address::new(0x10FF)));
        assert!(!block.contains(&Address::new(0x0FFF)));
        assert!(!block.contains(&Address::new(0x1100)));
    }

    #[test]
    fn test_stub_memory() {
        let mem = StubMemory::new(false);
        assert_eq!(mem.total_size(), 0);
        assert!(mem.get_blocks().is_empty());
        assert!(mem.get_byte(Address::new(0x1000)).is_err());
    }

    #[test]
    fn test_execute_set() {
        let mut mem = make_memory();
        mem.create_initialized_block(
            ".text",
            Address::new(0x1000),
            vec![0u8; 256],
            false,
        )
        .unwrap();
        // .text was created with RWX flags
        let exec = mem.execute_set();
        assert_eq!(exec.len(), 1);
    }

    #[test]
    fn test_total_size() {
        let mut mem = make_memory();
        mem.create_initialized_block("A", Address::new(0x1000), vec![0u8; 100], false)
            .unwrap();
        mem.create_initialized_block("B", Address::new(0x2000), vec![0u8; 200], false)
            .unwrap();
        assert_eq!(mem.total_size(), 300);
    }

    #[test]
    fn test_source_info() {
        let info = MemoryBlockSourceInfo::new_initialized(
            100,
            Address::new(0x1000),
            Some(42),
            128,
        );
        assert!(info.contains(&Address::new(0x1050)));
        assert!(!info.contains(&Address::new(0x0FFF)));
        assert!(info.contains_file_offset(128));
        assert!(info.contains_file_offset(227));
        assert!(!info.contains_file_offset(100));
        let addr = info.locate_address_for_file_offset(128);
        assert_eq!(addr, Some(Address::new(0x1000)));
        let addr = info.locate_address_for_file_offset(140);
        assert_eq!(addr, Some(Address::new(0x100C)));
    }

    #[test]
    fn test_memory_access_error_display() {
        let err = MemoryAccessError::new("test error");
        assert_eq!(format!("{}", err), "MemoryAccessError: test error");
    }

    #[test]
    fn test_memory_conflict_error() {
        let err = MemoryConflictError::new("overlap detected");
        assert_eq!(format!("{}", err), "MemoryConflictError: overlap detected");
    }

    #[test]
    fn test_memory_block_error() {
        let err = MemoryBlockError::default();
        assert_eq!(format!("{}", err), "MemoryBlockError: Memory block error");
    }
}
