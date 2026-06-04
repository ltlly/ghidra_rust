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

use crate::addr::{Address, AddressRange, AddressRangeIterator};
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

/// Error for invalid addresses -- mirrors `ghidra.program.model.mem.InvalidAddressException`.
///
/// Thrown when an address is improperly formatted or not defined within the target.
#[derive(Debug, Clone)]
pub struct InvalidAddressError {
    pub message: String,
}

impl InvalidAddressError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }

    pub fn default() -> Self {
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

impl From<GhidraError> for MemoryAccessError {
    fn from(e: GhidraError) -> Self {
        MemoryAccessError::new(format!("{}", e))
    }
}

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
        } else if skip_back {
            // Non-mapped byte: snap back to the last mapped byte in this group
            mapped_offset += mbc - 1;
        } else {
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

    /// Returns the minimum mapped address for this source.
    pub fn get_min_address(&self) -> Address {
        self.min_address
    }

    /// Returns the maximum mapped address for this source.
    pub fn get_max_address(&self) -> Address {
        self.max_address
    }

    /// Returns the mapped length in bytes.
    pub fn get_length(&self) -> u64 {
        self.length
    }

    /// Returns the backing file bytes identifier, if present.
    pub fn get_file_bytes_id(&self) -> Option<u64> {
        self.file_bytes_id
    }

    /// Returns the starting offset into the underlying file bytes, if any.
    pub fn get_file_bytes_offset(&self) -> Option<u64> {
        (self.file_bytes_offset >= 0).then_some(self.file_bytes_offset as u64)
    }

    /// Returns the mapped source address range, if this source is mapped.
    pub fn get_mapped_range(&self) -> Option<AddressRange> {
        self.mapped_range
    }

    /// Returns the byte mapping scheme, if this source is byte-mapped.
    pub fn get_byte_mapping_scheme(&self) -> Option<&ByteMappingScheme> {
        self.byte_mapping_scheme.as_ref()
    }

    /// Returns true if this source is byte-mapped.
    pub fn is_byte_mapped(&self) -> bool {
        self.byte_mapping_scheme.is_some()
    }

    /// Returns true if this source is bit-mapped.
    pub fn is_bit_mapped(&self) -> bool {
        self.mapped_range.is_some() && self.byte_mapping_scheme.is_none()
    }

    /// Returns true if this source is any mapped source (bit or byte mapped).
    pub fn is_mapped(&self) -> bool {
        self.mapped_range.is_some()
    }

    /// Returns true if this source has file bytes backing.
    pub fn has_file_bytes(&self) -> bool {
        self.file_bytes_id.is_some() && self.file_bytes_offset >= 0
    }

    /// Returns true if the source describes a single contiguous file-backed range.
    pub fn is_file_bytes_range(&self) -> bool {
        self.has_file_bytes() && !self.is_mapped()
    }

    /// Returns the source description string.
    pub fn get_description(&self) -> &str {
        &self.description
    }

    /// Returns the address range covered by this source.
    pub fn get_address_range(&self) -> AddressRange {
        AddressRange::new(self.min_address, self.max_address)
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

    /// Create an overlay memory block.
    ///
    /// An overlay provides alternate content for a physical memory region in a
    /// different execution context. Any block type can be used as an overlay.
    /// If `source_block` is provided the new block inherits its type and
    /// mapping properties; otherwise it defaults to an initialized block with
    /// the given `data`.
    pub fn new_overlay(
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
            is_overlay: true,
            is_loaded: true,
        }
    }

    /// Create an overlay byte-mapped block.
    pub fn new_overlay_byte_mapped(
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
            is_overlay: true,
            is_loaded: true,
        }
    }

    /// Create an overlay bit-mapped block.
    pub fn new_overlay_bit_mapped(
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
            is_overlay: true,
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

    /// Returns the block name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Returns the block comment.
    pub fn get_comment(&self) -> &str {
        &self.comment
    }

    /// Returns the block source name.
    pub fn get_source_name(&self) -> &str {
        &self.source_name
    }

    /// Returns the underlying block type.
    pub fn get_type(&self) -> MemoryBlockType {
        self.block_type
    }

    /// Returns the minimum address of the block.
    pub fn get_start(&self) -> Address {
        self.start()
    }

    /// Returns the maximum address of the block.
    pub fn get_end(&self) -> Address {
        self.end()
    }

    /// Returns the address range occupied by the block.
    pub fn get_address_range(&self) -> AddressRange {
        self.range
    }

    /// Returns the start offset within the address space.
    pub fn get_start_offset(&self) -> u64 {
        self.start().offset
    }

    /// Returns the end offset within the address space.
    pub fn get_end_offset(&self) -> u64 {
        self.end().offset
    }

    /// Returns the block size in bytes.
    pub fn get_size(&self) -> u64 {
        self.size()
    }

    /// Returns true if this block has initialized contents.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns true if this block belongs to an overlay space.
    pub fn is_overlay(&self) -> bool {
        self.is_overlay
    }

    /// Returns true if this block is loaded into memory.
    pub fn is_loaded(&self) -> bool {
        self.is_loaded
    }

    /// Returns true if this is a default memory block.
    pub fn is_default(&self) -> bool {
        matches!(self.block_type, MemoryBlockType::Default)
    }

    /// Returns true if this is a byte-mapped block.
    pub fn is_byte_mapped(&self) -> bool {
        matches!(self.block_type, MemoryBlockType::ByteMapped)
    }

    /// Returns true if this is a bit-mapped block.
    pub fn is_bit_mapped(&self) -> bool {
        matches!(self.block_type, MemoryBlockType::BitMapped)
    }

    /// Returns the mapped source base address for mapped blocks.
    pub fn get_mapped_source_base(&self) -> Option<Address> {
        self.mapped_source_base
    }

    /// Returns the byte mapping scheme for mapped blocks.
    pub fn get_byte_mapping_scheme(&self) -> Option<&ByteMappingScheme> {
        self.mapping_scheme.as_ref()
    }

    /// Returns all block source descriptors.
    pub fn get_source_infos(&self) -> &[MemoryBlockSourceInfo] {
        &self.source_infos
    }

    /// Returns the first block source descriptor, if any.
    pub fn get_source_info(&self) -> Option<&MemoryBlockSourceInfo> {
        self.source_infos.first()
    }

    /// Returns true if the block has one or more source descriptors.
    pub fn has_source_infos(&self) -> bool {
        !self.source_infos.is_empty()
    }

    /// Returns the permission and attribute flags bitmask.
    pub fn get_flags(&self) -> u8 {
        self.flags
    }

    /// Returns true if the block has any of the given flags set.
    pub fn has_any_flags(&self, flags: u8) -> bool {
        (self.flags & flags) != 0
    }

    /// Returns true if the block has all of the given flags set.
    pub fn has_all_flags(&self, flags: u8) -> bool {
        (self.flags & flags) == flags
    }

    /// Returns the initialized byte slice when available.
    pub fn get_data(&self) -> Option<&[u8]> {
        self.initialized.then_some(self.data.as_slice())
    }

    /// Returns the initialized byte at the given block-relative offset.
    pub fn get_byte_at_offset(&self, offset: u64) -> Option<u8> {
        let index = usize::try_from(offset).ok()?;
        self.data.get(index).copied()
    }

    /// Returns true if the given block-relative offset falls within this block.
    pub fn contains_offset(&self, offset: u64) -> bool {
        offset < self.size()
    }

    /// Returns the block-relative offset for a given address.
    pub fn get_offset(&self, addr: &Address) -> Option<u64> {
        self.contains(addr)
            .then_some(addr.offset.saturating_sub(self.range.start.offset))
    }

    /// Returns the address corresponding to a block-relative offset.
    pub fn get_address(&self, offset: u64) -> Option<Address> {
        self.contains_offset(offset)
            .then_some(self.range.start.add(offset))
    }

    /// Returns true if the given address lies on a block boundary.
    pub fn is_block_start(&self, addr: &Address) -> bool {
        *addr == self.range.start
    }

    /// Returns true if the given address is the last byte in the block.
    pub fn is_block_end(&self, addr: &Address) -> bool {
        *addr == self.range.end
    }

    /// Returns true if this block is contiguous with another block.
    pub fn is_adjacent_to(&self, other: &MemoryBlock) -> bool {
        self.end().next() == other.start() || other.end().next() == self.start()
    }

    /// Returns true if this block overlaps another block.
    pub fn intersects(&self, other: &MemoryBlock) -> bool {
        self.range.intersects(&other.range)
    }

    /// Returns the intersecting address range with another block, if any.
    pub fn intersection(&self, other: &MemoryBlock) -> Option<AddressRange> {
        self.range.intersection(&other.range)
    }

    /// Returns a compact permission string like `rwx`.
    pub fn permissions_string(&self) -> String {
        [
            if self.is_read() { 'r' } else { '-' },
            if self.is_write() { 'w' } else { '-' },
            if self.is_execute() { 'x' } else { '-' },
        ]
        .into_iter()
        .collect()
    }

    /// Returns true if the block is any mapped form.
    pub fn has_mapped_source(&self) -> bool {
        self.mapped_source_base.is_some()
    }

    /// Returns true if the block maps a particular source address.
    pub fn maps_source_address(&self, addr: &Address) -> bool {
        self.source_infos.iter().any(|info| {
            info.get_mapped_range()
                .map(|range| range.contains(addr))
                .unwrap_or(false)
        })
    }

    /// Returns true if the block is backed by file bytes.
    pub fn has_file_bytes(&self) -> bool {
        self.source_infos.iter().any(MemoryBlockSourceInfo::has_file_bytes)
    }

    /// Returns the first source info containing the given file offset, if any.
    pub fn get_source_info_for_file_offset(&self, file_offset: u64) -> Option<&MemoryBlockSourceInfo> {
        self.source_infos
            .iter()
            .find(|info| info.contains_file_offset(file_offset))
    }

    /// Returns the first source info containing the given address, if any.
    pub fn get_source_info_for_address(&self, addr: &Address) -> Option<&MemoryBlockSourceInfo> {
        self.source_infos.iter().find(|info| info.contains(addr))
    }

    /// Returns the address corresponding to a file offset inside this block.
    pub fn locate_address_for_file_offset(&self, file_offset: u64) -> Option<Address> {
        self.get_source_info_for_file_offset(file_offset)
            .and_then(|info| info.locate_address_for_file_offset(file_offset))
    }

    /// Returns true if this block covers the given file offset.
    pub fn contains_file_offset(&self, file_offset: u64) -> bool {
        self.get_source_info_for_file_offset(file_offset).is_some()
    }

    /// Returns the raw source descriptor count.
    pub fn get_source_info_count(&self) -> usize {
        self.source_infos.len()
    }

    /// Returns true if a given address lies within a source info entry.
    pub fn contains_source_address(&self, addr: &Address) -> bool {
        self.get_source_info_for_address(addr).is_some()
    }

    /// Returns a clone of the block with updated comment text.
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = comment.into();
        self
    }

    /// Returns a clone of the block with updated source name text.
    pub fn with_source_name(mut self, source_name: impl Into<String>) -> Self {
        self.source_name = source_name.into();
        self
    }

    /// Returns a clone of the block with updated loaded state.
    pub fn with_loaded(mut self, is_loaded: bool) -> Self {
        self.is_loaded = is_loaded;
        self
    }

    /// Returns a clone of the block with updated overlay state.
    pub fn with_overlay(mut self, is_overlay: bool) -> Self {
        self.is_overlay = is_overlay;
        self
    }

    /// Returns a clone of the block with updated flags.
    pub fn with_flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    /// Returns a clone of the block with appended source info.
    pub fn with_source_info(mut self, info: MemoryBlockSourceInfo) -> Self {
        self.source_infos.push(info);
        self
    }

    /// Returns a clone of the block with replacement bytes, updating initialized state.
    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.initialized = true;
        self.data = data;
        self
    }

    /// Returns the slice of initialized bytes for the requested offset range.
    pub fn get_bytes_at_offset(&self, offset: u64, size: usize) -> Option<&[u8]> {
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(size)?;
        self.data.get(start..end)
    }

    /// Returns the block-relative range for a given source info entry.
    pub fn get_source_info_address_ranges(&self) -> Vec<AddressRange> {
        self.source_infos.iter().map(MemoryBlockSourceInfo::get_address_range).collect()
    }

    /// Returns true if the block has no address span.
    pub fn is_empty(&self) -> bool {
        self.range.is_empty()
    }

    /// Returns the source info descriptions associated with the block.
    pub fn source_descriptions(&self) -> Vec<&str> {
        self.source_infos.iter().map(|info| info.get_description()).collect()
    }

    /// Returns the first file-bytes identifier associated with the block, if any.
    pub fn get_file_bytes_id(&self) -> Option<u64> {
        self.source_infos.iter().find_map(MemoryBlockSourceInfo::get_file_bytes_id)
    }

    /// Returns the first file offset associated with the block, if any.
    pub fn get_file_offset(&self) -> Option<u64> {
        self.source_infos.iter().find_map(MemoryBlockSourceInfo::get_file_bytes_offset)
    }

    /// Returns true if the block has an associated comment.
    pub fn has_comment(&self) -> bool {
        !self.comment.is_empty()
    }

    /// Returns true if the block has an associated source name.
    pub fn has_source_name(&self) -> bool {
        !self.source_name.is_empty()
    }

    /// Returns true if the block contains initialized bytes at the given address.
    pub fn is_initialized_address(&self, addr: &Address) -> bool {
        self.get_offset(addr)
            .and_then(|offset| usize::try_from(offset).ok())
            .map(|offset| offset < self.data.len())
            .unwrap_or(false)
    }

    /// Returns the number of initialized bytes currently materialized in the block.
    pub fn initialized_length(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the block is fully materialized for its declared size.
    pub fn is_fully_initialized(&self) -> bool {
        self.initialized && self.data.len() as u64 >= self.size()
    }

    /// Returns true if the block can satisfy read access.
    pub fn is_readable(&self) -> bool {
        self.is_read()
    }

    /// Returns true if the block can satisfy write access.
    pub fn is_writable(&self) -> bool {
        self.is_write()
    }

    /// Returns true if the block can satisfy execute access.
    pub fn is_executable(&self) -> bool {
        self.is_execute()
    }

    /// Returns true if this block shares any address with a range.
    pub fn intersects_range(&self, range: &AddressRange) -> bool {
        self.range.intersects(range)
    }

    /// Returns true if this block fully contains a range.
    pub fn contains_range(&self, range: &AddressRange) -> bool {
        self.range.contains_range(range)
    }

    /// Returns a subrange of this block starting at the given offset for the given size.
    pub fn sub_range(&self, offset: u64, size: u64) -> Option<AddressRange> {
        if size == 0 || !self.contains_offset(offset) {
            return None;
        }
        let end_offset = offset.checked_add(size - 1)?;
        if !self.contains_offset(end_offset) {
            return None;
        }
        Some(AddressRange::new(self.start().add(offset), self.start().add(end_offset)))
    }

    /// Returns all addresses in the block as an iterator.
    pub fn iter_addresses(&self) -> AddressRangeIterator {
        self.range.iter()
    }

    /// Returns a clone of the source infos vector.
    pub fn source_infos(&self) -> &[MemoryBlockSourceInfo] {
        &self.source_infos
    }

    /// Returns true if the given absolute address falls within the block and is readable.
    pub fn can_read(&self, addr: &Address) -> bool {
        self.is_read() && self.contains(addr)
    }

    /// Returns true if the given absolute address falls within the block and is writable.
    pub fn can_write(&self, addr: &Address) -> bool {
        self.is_write() && self.contains(addr)
    }

    /// Returns true if the given absolute address falls within the block and is executable.
    pub fn can_execute(&self, addr: &Address) -> bool {
        self.is_execute() && self.contains(addr)
    }

    /// Returns the block name and address range as a compact label.
    pub fn display_label(&self) -> String {
        format!("{} [{}-{}]", self.name, self.start(), self.end())
    }

    /// Returns true if the block contains any bytes.
    pub fn has_data(&self) -> bool {
        !self.data.is_empty()
    }

    /// Returns a clone of the block with replacement source infos.
    pub fn with_source_infos(mut self, source_infos: Vec<MemoryBlockSourceInfo>) -> Self {
        self.source_infos = source_infos;
        self
    }

    /// Returns the first mapped address range if available.
    pub fn get_mapped_address_range(&self) -> Option<AddressRange> {
        self.source_infos.iter().find_map(MemoryBlockSourceInfo::get_mapped_range)
    }

    /// Returns true if any source info maps a file offset.
    pub fn has_file_offset_mapping(&self) -> bool {
        self.source_infos.iter().any(MemoryBlockSourceInfo::has_file_bytes)
    }

    /// Returns true if this block is synthetic analysis-only memory.
    pub fn is_analysis_only(&self) -> bool {
        self.is_artificial() && !self.is_loaded
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

/// A [`MemBuffer`] that also supports writing bytes and repositioning.
///
/// Mirrors `ghidra.program.model.mem.MutableMemBuffer`. This interface
/// facilitates repositioning of a MemBuffer object via `advance` and
/// `set_position`.
pub trait MutableMemBuffer: MemBuffer {
    /// Write a byte at `offset` from the current position.
    fn set_byte(&mut self, offset: i64, value: u8) -> Result<(), MemoryAccessError>;

    /// Write bytes from `buf` at `offset` from the current position.
    fn set_bytes(&mut self, offset: i64, buf: &[u8]) -> Result<(), MemoryAccessError>;

    /// Advance the address pointer by `displacement` bytes.
    ///
    /// Analogous to Java's `advance(int)`. The default implementation
    /// panics; override for implementations that support repositioning.
    fn advance(&mut self, _displacement: i64) -> Result<(), MemoryAccessError> {
        Err(MemoryAccessError::new(
            "advance() not supported by this buffer implementation",
        ))
    }

    /// Set the base address so that offset 0 corresponds to `addr`.
    ///
    /// Analogous to Java's `setPosition(Address)`. The default
    /// implementation panics; override for implementations that support
    /// repositioning.
    fn set_position(&mut self, _addr: Address) {
        panic!("set_position() not supported by this buffer implementation")
    }

    /// Create a cloned copy of this buffer.
    ///
    /// Analogous to Java's `clone()`. The default implementation panics;
    /// override for implementations that support cloning.
    fn clone_buffer(&self) -> Box<dyn MutableMemBuffer> {
        panic!("clone_buffer() not supported by this buffer implementation")
    }
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
// ByteMemBufferImpl — mirrors ghidra.program.model.mem.ByteMemBufferImpl
// ============================================================================

/// Simple byte buffer implementation of [`MemBuffer`].
///
/// Even if a [`Memory`] reference is provided, the available bytes are
/// limited to the slice given at construction time. This is commonly
/// used by disassemblers and analyzers to inspect a fixed window of bytes.
pub struct ByteMemBufferImpl<'a> {
    /// The backing byte data.
    bytes: Vec<u8>,
    /// The address corresponding to offset 0 in `bytes`.
    addr: Address,
    /// Optional reference to a [`Memory`] (for address-space queries).
    mem: Option<&'a dyn Memory>,
    /// Whether this buffer is big-endian.
    big_endian: bool,
}

impl<'a> ByteMemBufferImpl<'a> {
    /// Construct a `ByteMemBufferImpl` without an associated Memory.
    ///
    /// `addr` is the address of byte index 0; `bytes` is the data;
    /// `is_big_endian` controls byte-order for multi-byte reads.
    pub fn new(addr: Address, bytes: Vec<u8>, is_big_endian: bool) -> Self {
        Self {
            bytes,
            addr,
            mem: None,
            big_endian: is_big_endian,
        }
    }

    /// Construct a `ByteMemBufferImpl` with an associated Memory.
    pub fn with_memory(
        memory: &'a dyn Memory,
        addr: Address,
        bytes: Vec<u8>,
        is_big_endian: bool,
    ) -> Self {
        Self {
            bytes,
            addr,
            mem: Some(memory),
            big_endian: is_big_endian,
        }
    }

    /// Returns the number of bytes contained in the buffer.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns true if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl<'a> MemBuffer for ByteMemBufferImpl<'a> {
    fn get_byte(&self, offset: i64) -> Result<u8, MemoryAccessError> {
        if offset < 0 || offset as usize >= self.bytes.len() {
            return Err(MemoryAccessError::new(format!(
                "Offset {} is not in range [0, {})",
                offset,
                self.bytes.len()
            )));
        }
        Ok(self.bytes[offset as usize])
    }

    fn get_bytes(&self, buf: &mut [u8], offset: i64) -> usize {
        if offset < 0 || offset as usize >= self.bytes.len() {
            return 0;
        }
        let start = offset as usize;
        let available = self.bytes.len() - start;
        let n = buf.len().min(available);
        buf[..n].copy_from_slice(&self.bytes[start..start + n]);
        n
    }

    fn get_address(&self) -> Address {
        self.addr
    }

    fn get_memory(&self) -> Option<&dyn Memory> {
        self.mem
    }

    fn is_big_endian(&self) -> bool {
        self.big_endian
    }
}

// ============================================================================
// MemoryBufferImpl — mirrors ghidra.program.model.mem.MemoryBufferImpl
// ============================================================================

/// A [`MutableMemBuffer`] backed by a [`Memory`] reference with internal
/// byte caching.
///
/// Mirrors `ghidra.program.model.mem.MemoryBufferImpl`. The internal cache
/// reduces the number of calls to [`Memory`] and avoids per-call error
/// checks. The cache is re-filled when a read falls outside the currently
/// cached range. This implementation will not wrap if the end of the
/// memory space is encountered.
///
/// Stores `&'a mut dyn Memory` for write support. Read methods (`&self`)
/// use unsafe reborrowing for the cache-miss path (safe because `MemoryBufferImpl`
/// is the sole accessor during that scope).
pub struct MemoryBufferImpl<'a> {
    /// Mutable reference to the backing memory (needed for write support).
    mem: &'a mut dyn Memory,
    /// Current base address (offset 0 in this buffer).
    start_addr: Address,
    /// Whether the underlying memory is big-endian.
    big_endian: bool,
    /// Internal byte cache.
    buffer: Vec<u8>,
    /// Index into `buffer` that corresponds to `start_addr`.
    start_addr_index: usize,
    /// Minimum valid cached offset (relative to `start_addr`).
    min_offset: i64,
    /// Maximum valid cached offset (inclusive, relative to `start_addr`).
    max_offset: i64,
    /// Re-cache threshold (fraction of buffer size).
    threshold: usize,
}

impl<'a> MemoryBufferImpl<'a> {
    /// Default internal buffer size.
    const DEFAULT_BUFSIZE: usize = 1024;

    /// Construct a new `MemoryBufferImpl` with default buffer size.
    pub fn new(mem: &'a mut dyn Memory, addr: Address) -> Self {
        Self::with_buffer_size(mem, addr, Self::DEFAULT_BUFSIZE)
    }

    /// Construct a new `MemoryBufferImpl` with a specific buffer size.
    pub fn with_buffer_size(mem: &'a mut dyn Memory, addr: Address, buf_size: usize) -> Self {
        let threshold = buf_size / 100;
        let big_endian = mem.is_big_endian();
        let mut buf = vec![0u8; buf_size];
        let n = mem.get_bytes(addr, &mut buf, 0, buf_size).unwrap_or(0);
        Self {
            mem,
            start_addr: addr,
            big_endian,
            buffer: buf,
            start_addr_index: 0,
            min_offset: 0,
            max_offset: if n > 0 { n as i64 - 1 } else { -1 },
            threshold,
        }
    }

    /// Compute the absolute address for a given relative offset.
    fn address_for_offset(&self, offset: i64) -> Address {
        self.start_addr.add(offset as u64)
    }
}

impl<'a> MemBuffer for MemoryBufferImpl<'a> {
    fn get_byte(&self, offset: i64) -> Result<u8, MemoryAccessError> {
        // Fast path: within cache
        if offset >= self.min_offset && offset <= self.max_offset {
            let idx = (self.start_addr_index as i64 + offset - self.min_offset) as usize;
            return Ok(self.buffer[idx]);
        }
        // Slow path: fall back to direct memory read.
        // SAFETY: we hold &mut self.mem, temporarily reborrowing as &self.mem for a read.
        // This is safe because MutableMemBuffer (which holds &mut self) guarantees exclusive
        // access to the buffer -- no concurrent mutable aliasing occurs.
        let mem_ref: &dyn Memory = self.mem;
        let addr = self.address_for_offset(offset);
        mem_ref.get_byte(addr).map_err(MemoryAccessError::from)
    }

    fn get_bytes(&self, buf: &mut [u8], offset: i64) -> usize {
        if offset >= self.min_offset && (buf.len() as i64 + offset) <= self.max_offset + 1 {
            let src_start = (self.start_addr_index as i64 + offset - self.min_offset) as usize;
            buf.copy_from_slice(&self.buffer[src_start..src_start + buf.len()]);
            return buf.len();
        }
        let mem_ref: &dyn Memory = self.mem;
        let addr = self.address_for_offset(offset);
        mem_ref.get_bytes(addr, buf, 0, buf.len()).unwrap_or(0)
    }

    fn get_address(&self) -> Address {
        self.start_addr
    }

    fn get_memory(&self) -> Option<&dyn Memory> {
        Some(self.mem)
    }

    fn is_big_endian(&self) -> bool {
        self.big_endian
    }
}

impl<'a> MutableMemBuffer for MemoryBufferImpl<'a> {
    fn set_byte(&mut self, offset: i64, value: u8) -> Result<(), MemoryAccessError> {
        let addr = self.address_for_offset(offset);
        self.mem
            .set_byte(addr, value)
            .map_err(MemoryAccessError::from)
    }

    fn set_bytes(&mut self, offset: i64, buf: &[u8]) -> Result<(), MemoryAccessError> {
        let addr = self.address_for_offset(offset);
        self.mem
            .set_bytes(addr, buf, 0, buf.len())
            .map_err(MemoryAccessError::from)
    }

    fn advance(&mut self, displacement: i64) -> Result<(), MemoryAccessError> {
        let new_addr = self.start_addr.add(displacement as u64);
        self.set_position(new_addr);
        Ok(())
    }

    fn set_position(&mut self, addr: Address) {
        // If the new address is within the currently cached range, just slide.
        if self.min_offset <= self.max_offset {
            let diff = addr.offset as i64 - self.start_addr.offset as i64;
            if diff >= self.min_offset && diff < self.max_offset - self.threshold as i64 {
                self.start_addr = addr;
                self.min_offset -= diff;
                self.max_offset -= diff;
                self.start_addr_index = (self.start_addr_index as i64 + diff) as usize;
                return;
            }
        }
        // Otherwise refill cache.
        self.start_addr = addr;
        self.start_addr_index = 0;
        self.min_offset = 0;
        self.max_offset = -1;
        let buf_len = self.buffer.len();
        let n = self
            .mem
            .get_bytes(addr, &mut self.buffer[..], 0, buf_len)
            .unwrap_or(0);
        if n > 0 {
            self.max_offset = n as i64 - 1;
        }
    }

    fn clone_buffer(&self) -> Box<dyn MutableMemBuffer> {
        // Note: Cannot clone a &mut reference. Return a ByteMemBufferImpl snapshot
        // of the current cache contents as a read-only MemBuffer wrapped in a
        // thin MutableMemBuffer adapter.
        // In practice callers should reconstruct a new buffer from the Memory
        // reference directly; this provides a best-effort snapshot.
        panic!("MemoryBufferImpl::clone_buffer is not supported; create a new buffer from Memory directly")
    }
}

// ============================================================================
// DumbMemBufferImpl — mirrors ghidra.program.model.mem.DumbMemBufferImpl
// ============================================================================

/// A [`MemoryBufferImpl`] with a small (16-byte) internal cache.
///
/// Mirrors `ghidra.program.model.mem.DumbMemBufferImpl`. Convenience wrapper
/// for contexts that only need a small lookahead.
pub struct DumbMemBufferImpl<'a> {
    inner: MemoryBufferImpl<'a>,
}

impl<'a> DumbMemBufferImpl<'a> {
    /// Cache size used by `DumbMemBufferImpl`.
    const BUF_SIZE: usize = 16;

    /// Construct a new `DumbMemBufferImpl`.
    pub fn new(mem: &'a mut dyn Memory, addr: Address) -> Self {
        Self {
            inner: MemoryBufferImpl::with_buffer_size(mem, addr, Self::BUF_SIZE),
        }
    }
}

impl<'a> MemBuffer for DumbMemBufferImpl<'a> {
    fn get_byte(&self, offset: i64) -> Result<u8, MemoryAccessError> {
        self.inner.get_byte(offset)
    }

    fn get_bytes(&self, buf: &mut [u8], offset: i64) -> usize {
        self.inner.get_bytes(buf, offset)
    }

    fn get_address(&self) -> Address {
        self.inner.get_address()
    }

    fn get_memory(&self) -> Option<&dyn Memory> {
        self.inner.get_memory()
    }

    fn is_big_endian(&self) -> bool {
        self.inner.is_big_endian()
    }
}

// ============================================================================
// MemBufferInputStream — mirrors ghidra.program.model.mem.MemBufferInputStream
// ============================================================================

/// Adapter that wraps a [`MemBuffer`] as a `std::io::Read`.
///
/// Mirrors `ghidra.program.model.mem.MemBufferInputStream`. Reads bytes
/// sequentially from the buffer, advancing an internal cursor. Returns
/// `Ok(0)` (EOF) when the end of the available range is reached.
pub struct MemBufferInputStream<'a> {
    membuf: &'a dyn MemBuffer,
    current_position: i64,
    /// Exclusive upper bound on position (current_position < max_position).
    max_position: i64,
}

impl<'a> MemBufferInputStream<'a> {
    /// Create a new input stream over the entire MemBuffer (up to `i32::MAX` bytes).
    pub fn new(membuf: &'a dyn MemBuffer) -> Self {
        Self::with_range(membuf, 0, i32::MAX as i64)
    }

    /// Create a new input stream starting at `initial_position`, limited to
    /// `length` bytes.
    ///
    /// # Panics
    /// Panics if `initial_position < 0`, `length < 0`, or the sum overflows.
    pub fn with_range(membuf: &'a dyn MemBuffer, initial_position: i64, length: i64) -> Self {
        let max_position = initial_position + length;
        assert!(
            initial_position >= 0 && length >= 0 && max_position >= 0,
            "Invalid MemBufferInputStream range"
        );
        Self {
            membuf,
            current_position: initial_position,
            max_position,
        }
    }

    /// Returns the number of bytes available for reading.
    pub fn available(&self) -> usize {
        if self.current_position >= 0 && self.current_position < self.max_position {
            (self.max_position - self.current_position) as usize
        } else {
            0
        }
    }
}

impl<'a> std::io::Read for MemBufferInputStream<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.current_position < 0 || self.current_position >= self.max_position {
            return Ok(0); // EOF
        }
        let max_readable =
            ((self.max_position - self.current_position) as usize).min(buf.len());
        let n = self.membuf.get_bytes(&mut buf[..max_readable], self.current_position);
        self.current_position += n as i64;
        Ok(n)
    }
}

// ============================================================================
// MemoryBlockListener — mirrors ghidra.program.model.mem.MemoryBlockListener
// ============================================================================

/// Callback interface for notifications about changes to a [`MemoryBlock`].
///
/// Mirrors `ghidra.program.model.mem.MemoryBlockListener`. Implementations
/// receive notification when properties of a memory block change (name,
/// comment, permissions, source, or data).
pub trait MemoryBlockListener {
    /// Called when the block name changes.
    fn name_changed(&self, block: &MemoryBlock, old_name: &str, new_name: &str);

    /// Called when the block comment changes.
    fn comment_changed(&self, block: &MemoryBlock, old_comment: Option<&str>, new_comment: Option<&str>);

    /// Called when the read permission changes.
    fn read_status_changed(&self, block: &MemoryBlock, is_read: bool);

    /// Called when the write permission changes.
    fn write_status_changed(&self, block: &MemoryBlock, is_write: bool);

    /// Called when the execute permission changes.
    fn execute_status_changed(&self, block: &MemoryBlock, is_execute: bool);

    /// Called when the source name changes.
    fn source_changed(&self, block: &MemoryBlock, old_source: &str, new_source: &str);

    /// Called when the source offset changes.
    fn source_offset_changed(&self, block: &MemoryBlock, old_offset: i64, new_offset: i64);

    /// Called when bytes in the block change.
    fn data_changed(&self, block: &MemoryBlock, addr: Address, old_data: &[u8], new_data: &[u8]);
}

// ============================================================================
// MemoryBlockStub — mirrors ghidra.program.model.mem.MemoryBlockStub
// ============================================================================

/// A stub [`MemoryBlock`] for use in tests.
///
/// Mirrors `ghidra.program.model.mem.MemoryBlockStub`. All methods that are
/// not explicitly overridden will panic with `UnsupportedOperation`. Override
/// individual methods via the builder pattern for test-specific behavior.
#[derive(Debug, Clone)]
pub struct MemoryBlockStub {
    pub start: Address,
    pub end: Address,
}

impl MemoryBlockStub {
    /// Create a new stub with default (null) start/end addresses.
    pub fn new() -> Self {
        Self {
            start: Address::NULL,
            end: Address::NULL,
        }
    }

    /// Create a new stub with the given start and end addresses.
    pub fn with_range(start: Address, end: Address) -> Self {
        Self { start, end }
    }

    /// Create a full [`MemoryBlock`] from this stub's range with given flags.
    pub fn to_memory_block(&self, name: &str, flags: u8) -> MemoryBlock {
        MemoryBlock::new_initialized(
            name,
            AddressRange::new(self.start, self.end),
            flags,
            vec![0u8; (self.end.offset - self.start.offset + 1) as usize],
        )
    }
}

impl Default for MemoryBlockStub {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// FileBytes — simple representation of file-backed byte storage
// ============================================================================

/// Represents a stored sequence of file bytes that can back memory blocks.
///
/// This is a simplified version of Ghidra's `FileBytes` used in
/// [`MemoryBlockSourceInfo`] references. Each `FileBytes` has a unique
/// identifier and a total length.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FileBytes {
    /// Unique identifier for this file bytes object.
    pub id: u64,
    /// Name of the source file.
    pub filename: String,
    /// Total number of bytes stored.
    pub size: u64,
    /// Offset within the source file where these bytes begin.
    pub file_offset: u64,
}

impl FileBytes {
    /// Create a new `FileBytes` descriptor.
    pub fn new(id: u64, filename: impl Into<String>, size: u64, file_offset: u64) -> Self {
        Self {
            id,
            filename: filename.into(),
            size,
            file_offset,
        }
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

    /// Rename a memory block.
    ///
    /// The block identified by `old_name` is renamed to `new_name`.
    /// Returns an error if the old block does not exist or the new name
    /// is already taken.
    fn rename_block(&mut self, old_name: &str, new_name: &str) -> Result<(), GhidraError>;

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

    fn rename_block(&mut self, old_name: &str, new_name: &str) -> Result<(), GhidraError> {
        if old_name == new_name {
            return Ok(());
        }
        if self.blocks.contains_key(new_name) {
            return Err(GhidraError::MemoryError(format!(
                "Block name '{}' already in use",
                new_name
            )));
        }
        let mut block = self.blocks.remove(old_name).ok_or_else(|| {
            GhidraError::NotFound(format!("Block '{}' not found", old_name))
        })?;
        // Update the blocks_by_addr index
        if let Some(pos) = self.blocks_by_addr.iter().position(|n| n == old_name) {
            self.blocks_by_addr[pos] = new_name.to_string();
        }
        block.name = new_name.to_string();
        self.blocks.insert(new_name.to_string(), block);
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

        // Extract mapped block properties into locals to avoid borrow conflicts
        let mapped_info: Option<(MemoryBlockType, Address, ByteMappingScheme, bool, u64)> = {
            let block = self.blocks.get(&block_name).unwrap();
            match block.block_type {
                MemoryBlockType::ByteMapped | MemoryBlockType::BitMapped => {
                    let base = block.mapped_source_base.ok_or_else(|| {
                        GhidraError::MemoryError("Mapped block without source base".into())
                    })?;
                    if !block.is_write() {
                        return Err(GhidraError::MemoryError(format!(
                            "Block '{}' is not writable",
                            block_name
                        )));
                    }
                    let default_scheme = ByteMappingScheme::one_to_one();
                    let scheme = block.mapping_scheme.as_ref().unwrap_or(&default_scheme);
                    Some((block.block_type, base, scheme.clone(), true, block.start().offset))
                }
                MemoryBlockType::Default => None,
            }
        };

        // Handle mapped blocks: write-through to the source (no borrow on self.blocks)
        if let Some((btype, base, scheme, is_write, start_offset)) = mapped_info {
            if !is_write {
                return Err(GhidraError::MemoryError(format!(
                    "Block '{}' is not writable",
                    block_name
                )));
            }
            let offset = addr.offset - start_offset;
            return match btype {
                MemoryBlockType::ByteMapped => {
                    let src_addr = scheme.get_mapped_source_address(base, offset);
                    self.set_byte(src_addr, value)
                }
                MemoryBlockType::BitMapped => {
                    let src_addr = base.add(offset);
                    let existing = self.get_byte(src_addr).unwrap_or(0);
                    let new_val = (existing & 0xFE) | (value & 0x01);
                    self.set_byte(src_addr, new_val)
                }
                _ => unreachable!(),
            };
        }

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

        // Extract mapped block properties into locals to avoid borrow conflicts
        let mapped_info: Option<(MemoryBlockType, Address, ByteMappingScheme, bool, u64)> = {
            let block = self.blocks.get(&block_name).unwrap();
            match block.block_type {
                MemoryBlockType::ByteMapped | MemoryBlockType::BitMapped => {
                    let base = block.mapped_source_base.ok_or_else(|| {
                        GhidraError::MemoryError("Mapped block without source base".into())
                    })?;
                    if !block.is_write() {
                        return Err(GhidraError::MemoryError(format!(
                            "Block '{}' is not writable",
                            block_name
                        )));
                    }
                    let default_scheme = ByteMappingScheme::one_to_one();
                    let scheme = block.mapping_scheme.as_ref().unwrap_or(&default_scheme);
                    Some((block.block_type, base, scheme.clone(), true, block.start().offset))
                }
                MemoryBlockType::Default => None,
            }
        };

        // Handle mapped blocks: write-through to the source (no borrow on self.blocks)
        if let Some((btype, base, scheme, is_write, start_offset)) = mapped_info {
            if !is_write {
                return Err(GhidraError::MemoryError(format!(
                    "Block '{}' is not writable",
                    block_name
                )));
            }
            let offset = addr.offset - start_offset;
            return match btype {
                MemoryBlockType::ByteMapped => {
                    scheme.set_bytes(self, base, offset, source, source_index, size)
                }
                MemoryBlockType::BitMapped => {
                    for i in 0..size {
                        let src_addr = base.add(offset + i as u64);
                        let existing = self.get_byte(src_addr).unwrap_or(0);
                        let new_val = (existing & 0xFE) | (source[source_index + i] & 0x01);
                        self.set_byte(src_addr, new_val)?;
                    }
                    Ok(())
                }
                _ => unreachable!(),
            };
        }

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

    /// Returns the number of memory blocks.
    pub fn num_blocks(&self) -> usize {
        self.blocks.len()
    }

    /// Returns true if memory contains no blocks.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Returns the minimum block start address, if any.
    pub fn min_address(&self) -> Option<Address> {
        self.blocks_by_addr
            .first()
            .and_then(|name| self.blocks.get(name))
            .map(MemoryBlock::start)
    }

    /// Returns the maximum block end address, if any.
    pub fn max_address(&self) -> Option<Address> {
        self.blocks_by_addr
            .last()
            .and_then(|name| self.blocks.get(name))
            .map(MemoryBlock::end)
    }

    /// Returns an iterator over blocks in address order.
    pub fn iter_blocks(&self) -> impl Iterator<Item = &MemoryBlock> {
        self.blocks_by_addr
            .iter()
            .filter_map(|name| self.blocks.get(name))
    }

    /// Returns true if the address falls within any memory block.
    pub fn contains(&self, addr: &Address) -> bool {
        self.get_block(addr).is_some()
    }

    /// Returns only the overlay blocks.
    pub fn get_overlay_blocks(&self) -> Vec<&MemoryBlock> {
        self.blocks
            .values()
            .filter(|b| b.is_overlay)
            .collect()
    }

    /// Returns only the non-overlay (physical) blocks in address order.
    pub fn get_physical_blocks(&self) -> Vec<&MemoryBlock> {
        self.blocks_by_addr
            .iter()
            .filter_map(|name| self.blocks.get(name))
            .filter(|b| !b.is_overlay)
            .collect()
    }

    /// Returns the number of overlay blocks.
    pub fn num_overlay_blocks(&self) -> usize {
        self.blocks.values().filter(|b| b.is_overlay).count()
    }

    /// Returns true if this map contains any overlay blocks.
    pub fn has_overlay_blocks(&self) -> bool {
        self.blocks.values().any(|b| b.is_overlay)
    }

    /// Returns all mapped blocks (byte-mapped and bit-mapped) in address order.
    pub fn get_mapped_blocks(&self) -> Vec<&MemoryBlock> {
        self.blocks_by_addr
            .iter()
            .filter_map(|name| self.blocks.get(name))
            .filter(|b| b.is_mapped())
            .collect()
    }

    /// Create an overlay initialized block with custom data.
    pub fn create_overlay_initialized_block(
        &mut self,
        name: &str,
        start: Address,
        data: Vec<u8>,
    ) -> Result<&MemoryBlock, GhidraError> {
        let size = data.len() as u64;
        let end = start.add(size.saturating_sub(1));
        let block = MemoryBlock::new_overlay(
            name,
            AddressRange::new(start, end),
            FLAG_READ | FLAG_WRITE | FLAG_EXECUTE,
            data,
        );
        self.insert_block(block)?;
        Ok(self.blocks.get(name).unwrap())
    }

    /// Create an overlay byte-mapped block.
    pub fn create_overlay_byte_mapped_block(
        &mut self,
        name: &str,
        start: Address,
        mapped_address: Address,
        length: u64,
        scheme: Option<ByteMappingScheme>,
    ) -> Result<&MemoryBlock, GhidraError> {
        let end = start.add(length.saturating_sub(1));
        let scheme = scheme.unwrap_or_default();
        let block = MemoryBlock::new_overlay_byte_mapped(
            name,
            AddressRange::new(start, end),
            FLAG_READ | FLAG_WRITE,
            mapped_address,
            scheme,
        );
        self.insert_block(block)?;
        Ok(self.blocks.get(name).unwrap())
    }

    /// Create an overlay bit-mapped block.
    pub fn create_overlay_bit_mapped_block(
        &mut self,
        name: &str,
        start: Address,
        mapped_address: Address,
        length: u64,
    ) -> Result<&MemoryBlock, GhidraError> {
        let end = start.add(length.saturating_sub(1));
        let block = MemoryBlock::new_overlay_bit_mapped(
            name,
            AddressRange::new(start, end),
            FLAG_READ | FLAG_WRITE,
            mapped_address,
        );
        self.insert_block(block)?;
        Ok(self.blocks.get(name).unwrap())
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
    fn rename_block(&mut self, _old_name: &str, _new_name: &str) -> Result<(), GhidraError> {
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

    #[test]
    fn test_overlay_block() {
        let block = MemoryBlock::new_overlay(
            "ov",
            AddressRange::new(Address::new(0x1000), Address::new(0x10FF)),
            FLAG_READ | FLAG_WRITE | FLAG_EXECUTE,
            vec![0xAAu8; 256],
        );
        assert!(block.is_overlay());
        assert!(block.is_initialized());
        assert_eq!(block.size(), 256);
        assert_eq!(block.get_byte(&Address::new(0x1000)).unwrap(), 0xAA);
        assert_eq!(block.permissions_string(), "rwx");
    }

    #[test]
    fn test_overlay_byte_mapped_block() {
        let block = MemoryBlock::new_overlay_byte_mapped(
            "ov_map",
            AddressRange::new(Address::new(0x2000), Address::new(0x20FF)),
            FLAG_READ | FLAG_WRITE,
            Address::new(0x1000),
            ByteMappingScheme::default(),
        );
        assert!(block.is_overlay());
        assert!(block.is_byte_mapped());
        assert!(block.is_mapped());
        assert_eq!(block.get_mapped_source_base(), Some(Address::new(0x1000)));
    }

    #[test]
    fn test_overlay_bit_mapped_block() {
        let block = MemoryBlock::new_overlay_bit_mapped(
            "ov_bmap",
            AddressRange::new(Address::new(0x3000), Address::new(0x30FF)),
            FLAG_READ | FLAG_WRITE,
            Address::new(0x1000),
        );
        assert!(block.is_overlay());
        assert!(block.is_bit_mapped());
        assert!(block.is_mapped());
    }

    #[test]
    fn test_memory_map_overlay_blocks() {
        let mut mem = make_memory();
        mem.create_initialized_block(".text", Address::new(0x1000), vec![0x90u8; 256], false)
            .unwrap();
        mem.create_overlay_initialized_block("ov.text", Address::new(0x1000), vec![0xCCu8; 256])
            .unwrap();

        assert!(mem.has_overlay_blocks());
        assert_eq!(num_overlay_blocks(&mem), 1);

        let physical = get_physical_block_count(&mem);
        assert_eq!(physical, 1);

        // The overlay should be returned for address 0x1000 (first match)
        // Both blocks contain that address - the result depends on block ordering
        // but both exist in the map
        let overlays = mem.get_overlay_blocks();
        assert_eq!(overlays.len(), 1);
        assert!(overlays[0].is_overlay());
    }

    #[test]
    fn test_memory_map_overlay_byte_mapped() {
        let mut mem = make_memory();
        // Create source block
        mem.create_initialized_block("src", Address::new(0x5000), vec![0xAAu8; 256], false)
            .unwrap();
        // Create overlay byte-mapped block pointing to source
        mem.create_overlay_byte_mapped_block(
            "ov_map",
            Address::new(0x6000),
            Address::new(0x5000),
            256,
            None,
        )
        .unwrap();

        let mapped = mem.get_mapped_blocks();
        assert_eq!(mapped.len(), 1);
        assert!(mapped[0].is_byte_mapped());
        assert!(mapped[0].is_overlay());
    }

    #[test]
    fn test_byte_mapped_write_through() {
        let mut mem = make_memory();
        // Create source block
        mem.create_initialized_block("src", Address::new(0x5000), vec![0u8; 256], false)
            .unwrap();
        // Create byte-mapped block pointing to source (1:1 mapping)
        mem.create_byte_mapped_block(
            "map",
            Address::new(0x6000),
            Address::new(0x5000),
            64,
            None,
            false,
        )
        .unwrap();

        // Writing to the mapped block should write through to the source
        mem.set_byte(Address::new(0x6000), 0x42).unwrap();
        // Read through the source directly
        assert_eq!(mem.get_byte(Address::new(0x5000)).unwrap(), 0x42);
        // Read through the mapped block
        assert_eq!(mem.get_byte(Address::new(0x6000)).unwrap(), 0x42);
    }

    #[test]
    fn test_bit_mapped_write_through() {
        let mut mem = make_memory();
        // Create source block
        mem.create_initialized_block("src", Address::new(0x5000), vec![0u8; 256], false)
            .unwrap();
        // Create bit-mapped block pointing to source
        mem.create_bit_mapped_block(
            "bmap",
            Address::new(0x6000),
            Address::new(0x5000),
            64,
            false,
        )
        .unwrap();

        // Writing 1 to the bit-mapped block should set bit 0 in the source
        mem.set_byte(Address::new(0x6000), 0x01).unwrap();
        assert_eq!(mem.get_byte(Address::new(0x5000)).unwrap(), 0x01);

        // Writing 0 should clear bit 0
        mem.set_byte(Address::new(0x6000), 0x00).unwrap();
        assert_eq!(mem.get_byte(Address::new(0x5000)).unwrap(), 0x00);
    }

    #[test]
    fn test_byte_mapped_non_one_to_one_write_through() {
        let mut mem = make_memory();
        // Create source block
        mem.create_initialized_block("src", Address::new(0x5000), vec![0u8; 256], false)
            .unwrap();
        // Create 2:4 byte-mapped block: 2 mapped bytes per 4 source bytes
        let scheme = ByteMappingScheme::new(2, 4);
        mem.create_byte_mapped_block(
            "map24",
            Address::new(0x6000),
            Address::new(0x5000),
            64,
            Some(scheme),
            false,
        )
        .unwrap();

        // Write at mapped block offset 0 -> source offset 0
        mem.set_byte(Address::new(0x6000), 0xAA).unwrap();
        assert_eq!(mem.get_byte(Address::new(0x5000)).unwrap(), 0xAA);

        // Write at mapped block offset 1 -> source offset 1
        mem.set_byte(Address::new(0x6001), 0xBB).unwrap();
        assert_eq!(mem.get_byte(Address::new(0x5001)).unwrap(), 0xBB);

        // Write at mapped block offset 2 -> source offset 4 (skips 2)
        mem.set_byte(Address::new(0x6002), 0xCC).unwrap();
        assert_eq!(mem.get_byte(Address::new(0x5004)).unwrap(), 0xCC);
    }

    #[test]
    fn test_memory_block_is_loaded_check() {
        let block = MemoryBlock::new_initialized(
            "test",
            AddressRange::new(Address::new(0x1000), Address::new(0x10FF)),
            FLAG_READ,
            vec![0u8; 256],
        );
        assert!(block.is_loaded());

        let overlay = MemoryBlock::new_overlay(
            "ov",
            AddressRange::new(Address::new(0x1000), Address::new(0x10FF)),
            FLAG_READ,
            vec![0u8; 256],
        );
        assert!(overlay.is_overlay());
        assert!(overlay.is_loaded());
    }

    #[test]
    fn test_memory_block_default_type_check() {
        let init = MemoryBlock::new_initialized(
            "init",
            AddressRange::new(Address::new(0x1000), Address::new(0x10FF)),
            FLAG_READ,
            vec![0u8; 256],
        );
        assert!(init.is_default());

        let uninit = MemoryBlock::new_uninitialized(
            "uninit",
            AddressRange::new(Address::new(0x2000), Address::new(0x20FF)),
            FLAG_READ,
        );
        assert!(uninit.is_default());
    }

    #[test]
    fn test_byte_mapping_scheme_get_mapped_address() {
        let scheme = ByteMappingScheme::new(2, 4);
        let start = Address::new(0x6000);

        // Source offset 0 (mapped byte) -> mapped offset 0
        let addr = scheme.get_mapped_address(start, 64, 0, false).unwrap();
        assert_eq!(addr, Address::new(0x6000));

        // Source offset 1 (mapped byte) -> mapped offset 1
        let addr = scheme.get_mapped_address(start, 64, 1, false).unwrap();
        assert_eq!(addr, Address::new(0x6001));

        // Source offset 2 (non-mapped, skip_back=false) -> mapped offset 2 (next mapped)
        let addr = scheme.get_mapped_address(start, 64, 2, false).unwrap();
        assert_eq!(addr, Address::new(0x6002));

        // Source offset 2 (non-mapped, skip_back=true) -> mapped offset 1 (prev)
        let addr = scheme.get_mapped_address(start, 64, 2, true).unwrap();
        assert_eq!(addr, Address::new(0x6001));
    }

    // =====================================================================
    // Tests for InvalidAddressError
    // =====================================================================

    #[test]
    fn test_invalid_address_error_new() {
        let err = InvalidAddressError::new("bad address 0xGG");
        assert_eq!(format!("{}", err), "InvalidAddressError: bad address 0xGG");
        use std::error::Error;
        assert!(err.source().is_none());
    }

    #[test]
    fn test_invalid_address_error_default() {
        let err = InvalidAddressError::default();
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

    // =====================================================================
    // Tests for ByteMemBufferImpl
    // =====================================================================

    #[test]
    fn test_byte_mem_buffer_impl_basic() {
        let data = vec![0x10, 0x20, 0x30, 0x40];
        let buf = ByteMemBufferImpl::new(Address::new(0x1000), data, false);
        assert_eq!(buf.len(), 4);
        assert!(!buf.is_empty());
        assert_eq!(buf.get_address(), Address::new(0x1000));
        assert!(!buf.is_big_endian());
        assert!(buf.get_memory().is_none());
    }

    #[test]
    fn test_byte_mem_buffer_impl_get_byte() {
        let data = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let buf = ByteMemBufferImpl::new(Address::new(0x2000), data, true);
        assert_eq!(buf.get_byte(0).unwrap(), 0xAA);
        assert_eq!(buf.get_byte(1).unwrap(), 0xBB);
        assert_eq!(buf.get_byte(3).unwrap(), 0xDD);
        assert!(buf.get_byte(4).is_err());
        assert!(buf.get_byte(-1).is_err());
    }

    #[test]
    fn test_byte_mem_buffer_impl_get_bytes() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let buf = ByteMemBufferImpl::new(Address::new(0x1000), data, false);
        let mut dest = [0u8; 3];
        let n = buf.get_bytes(&mut dest, 1);
        assert_eq!(n, 3);
        assert_eq!(dest, [0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_byte_mem_buffer_impl_get_bytes_beyond_end() {
        let data = vec![0x01, 0x02];
        let buf = ByteMemBufferImpl::new(Address::new(0x1000), data, false);
        let mut dest = [0u8; 10];
        let n = buf.get_bytes(&mut dest, 0);
        assert_eq!(n, 2);
        assert_eq!(dest[0], 0x01);
        assert_eq!(dest[1], 0x02);
    }

    #[test]
    fn test_byte_mem_buffer_impl_get_bytes_negative_offset() {
        let data = vec![0x01, 0x02];
        let buf = ByteMemBufferImpl::new(Address::new(0x1000), data, false);
        let mut dest = [0u8; 2];
        let n = buf.get_bytes(&mut dest, -1);
        assert_eq!(n, 0);
    }

    #[test]
    fn test_byte_mem_buffer_impl_empty() {
        let buf = ByteMemBufferImpl::new(Address::new(0x1000), vec![], false);
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        assert!(buf.get_byte(0).is_err());
    }

    #[test]
    fn test_byte_mem_buffer_impl_short() {
        // Little-endian: 0x34 0x12 -> 0x1234
        let data = vec![0x34, 0x12, 0x00, 0x00];
        let buf = ByteMemBufferImpl::new(Address::new(0x1000), data, false);
        assert_eq!(buf.get_short(0).unwrap(), 0x1234);
    }

    #[test]
    fn test_byte_mem_buffer_impl_int() {
        // Little-endian: 0x78 0x56 0x34 0x12 -> 0x12345678
        let data = vec![0x78, 0x56, 0x34, 0x12];
        let buf = ByteMemBufferImpl::new(Address::new(0x1000), data, false);
        assert_eq!(buf.get_int(0).unwrap(), 0x12345678i32);
    }

    #[test]
    fn test_byte_mem_buffer_impl_long() {
        let data = vec![0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12];
        let buf = ByteMemBufferImpl::new(Address::new(0x1000), data, false);
        assert_eq!(buf.get_long(0).unwrap(), 0x1234567890ABCDEFi64);
    }

    #[test]
    fn test_byte_mem_buffer_impl_big_endian() {
        // Big-endian: 0x12 0x34 -> 0x1234
        let data = vec![0x12, 0x34];
        let buf = ByteMemBufferImpl::new(Address::new(0x1000), data, true);
        assert_eq!(buf.get_short(0).unwrap(), 0x1234);
    }

    #[test]
    fn test_byte_mem_buffer_impl_is_initialized_memory() {
        let data = vec![0x42];
        let buf = ByteMemBufferImpl::new(Address::new(0x1000), data, false);
        assert!(buf.is_initialized_memory());
    }

    #[test]
    fn test_byte_mem_buffer_impl_unsigned_byte() {
        let data = vec![0xFF, 0x80, 0x00];
        let buf = ByteMemBufferImpl::new(Address::new(0x1000), data, false);
        assert_eq!(buf.get_unsigned_byte(0).unwrap(), 255);
        assert_eq!(buf.get_unsigned_byte(1).unwrap(), 128);
        assert_eq!(buf.get_unsigned_byte(2).unwrap(), 0);
    }

    #[test]
    fn test_byte_mem_buffer_impl_var_length_int() {
        let data = vec![0xFF, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12];
        let buf = ByteMemBufferImpl::new(Address::new(0x1000), data, false);
        // 1-byte signed: 0xFF = -1
        assert_eq!(buf.get_var_length_int(0, 1).unwrap(), -1);
        // 2-byte signed little-endian: 0x1234
        assert_eq!(buf.get_var_length_int(1, 2).unwrap(), 0x1234);
        // 4-byte signed little-endian: 0x12345678
        assert_eq!(buf.get_var_length_int(3, 4).unwrap(), 0x12345678);
    }

    #[test]
    fn test_byte_mem_buffer_impl_var_length_unsigned_int() {
        let data = vec![0xFF, 0x34, 0x12];
        let buf = ByteMemBufferImpl::new(Address::new(0x1000), data, false);
        assert_eq!(buf.get_var_length_unsigned_int(0, 1).unwrap(), 255);
        assert_eq!(buf.get_var_length_unsigned_int(1, 2).unwrap(), 0x1234);
    }

    // =====================================================================
    // Tests for MemoryBufferImpl
    // =====================================================================

    fn make_memory_for_buffer() -> MemoryMap {
        let mut mem = MemoryMap::new(false);
        let data = vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
                        0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0xFF];
        mem.create_initialized_block(".text", Address::new(0x1000), data, false)
            .unwrap();
        mem
    }

    #[test]
    fn test_memory_buffer_impl_basic() {
        let mut mem = make_memory_for_buffer();
        let buf = MemoryBufferImpl::new(&mut mem, Address::new(0x1000));
        assert_eq!(buf.get_address(), Address::new(0x1000));
        assert!(!buf.is_big_endian());
        assert!(buf.get_memory().is_some());
    }

    #[test]
    fn test_memory_buffer_impl_read_byte() {
        let mut mem = make_memory_for_buffer();
        let buf = MemoryBufferImpl::new(&mut mem, Address::new(0x1000));
        assert_eq!(buf.get_byte(0).unwrap(), 0x10);
        assert_eq!(buf.get_byte(1).unwrap(), 0x20);
        assert_eq!(buf.get_byte(15).unwrap(), 0xFF);
    }

    #[test]
    fn test_memory_buffer_impl_read_bytes() {
        let mut mem = make_memory_for_buffer();
        let buf = MemoryBufferImpl::new(&mut mem, Address::new(0x1000));
        let mut dest = [0u8; 4];
        let n = buf.get_bytes(&mut dest, 2);
        assert_eq!(n, 4);
        assert_eq!(dest, [0x30, 0x40, 0x50, 0x60]);
    }

    #[test]
    fn test_memory_buffer_impl_out_of_range_fallback() {
        let mut mem = make_memory_for_buffer();
        // Use a small buffer size so cache is limited
        let buf = MemoryBufferImpl::with_buffer_size(&mut mem, Address::new(0x1000), 4);
        // Byte at offset 0 should be from cache
        assert_eq!(buf.get_byte(0).unwrap(), 0x10);
        // Byte at offset 10 should fall back to direct memory read
        assert_eq!(buf.get_byte(10).unwrap(), 0xB0);
    }

    #[test]
    fn test_memory_buffer_impl_write_byte() {
        let mut mem = make_memory_for_buffer();
        let mut buf = MemoryBufferImpl::new(&mut mem, Address::new(0x1000));
        buf.set_byte(0, 0x42).unwrap();
        // Read back through the memory directly
        assert_eq!(buf.get_memory().unwrap().get_byte(Address::new(0x1000)).unwrap(), 0x42);
    }

    #[test]
    fn test_memory_buffer_impl_write_bytes() {
        let mut mem = make_memory_for_buffer();
        let mut buf = MemoryBufferImpl::new(&mut mem, Address::new(0x1000));
        buf.set_bytes(4, &[0xAA, 0xBB]).unwrap();
        assert_eq!(buf.get_memory().unwrap().get_byte(Address::new(0x1004)).unwrap(), 0xAA);
        assert_eq!(buf.get_memory().unwrap().get_byte(Address::new(0x1005)).unwrap(), 0xBB);
    }

    #[test]
    fn test_memory_buffer_impl_advance() {
        let mut mem = make_memory_for_buffer();
        let mut buf = MemoryBufferImpl::new(&mut mem, Address::new(0x1000));
        // Before advance: byte at offset 0 is 0x10
        assert_eq!(buf.get_byte(0).unwrap(), 0x10);
        // Advance by 4
        buf.advance(4).unwrap();
        // Now offset 0 points to 0x1004 = 0x50
        assert_eq!(buf.get_address(), Address::new(0x1004));
    }

    #[test]
    fn test_memory_buffer_impl_set_position() {
        let mut mem = make_memory_for_buffer();
        let mut buf = MemoryBufferImpl::new(&mut mem, Address::new(0x1000));
        buf.set_position(Address::new(0x1008));
        assert_eq!(buf.get_address(), Address::new(0x1008));
        assert_eq!(buf.get_byte(0).unwrap(), 0x90);
    }

    // =====================================================================
    // Tests for DumbMemBufferImpl
    // =====================================================================

    #[test]
    fn test_dumb_mem_buffer_impl_basic() {
        let mut mem = make_memory_for_buffer();
        let buf = DumbMemBufferImpl::new(&mut mem, Address::new(0x1000));
        assert_eq!(buf.get_address(), Address::new(0x1000));
        assert_eq!(buf.get_byte(0).unwrap(), 0x10);
        assert_eq!(buf.get_byte(5).unwrap(), 0x60);
    }

    #[test]
    fn test_dumb_mem_buffer_impl_short() {
        let mut mem = make_memory_for_buffer();
        let buf = DumbMemBufferImpl::new(&mut mem, Address::new(0x1000));
        assert_eq!(buf.get_short(0).unwrap(), 0x2010);
    }

    // =====================================================================
    // Tests for MemBufferInputStream
    // =====================================================================

    #[test]
    fn test_mem_buffer_input_stream_basic() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let buf = ByteMemBufferImpl::new(Address::new(0x1000), data, false);
        let mut stream = MemBufferInputStream::new(&buf);
        assert_eq!(stream.available(), i32::MAX as usize);

        let mut out = [0u8; 3];
        let n = std::io::Read::read(&mut stream, &mut out).unwrap();
        assert_eq!(n, 3);
        assert_eq!(out, [0x01, 0x02, 0x03]);

        let n = std::io::Read::read(&mut stream, &mut out).unwrap();
        assert_eq!(n, 2);
        assert_eq!(out[0], 0x04);
        assert_eq!(out[1], 0x05);
    }

    #[test]
    fn test_mem_buffer_input_stream_with_range() {
        let data = vec![0x10, 0x20, 0x30, 0x40, 0x50];
        let buf = ByteMemBufferImpl::new(Address::new(0x1000), data, false);
        let mut stream = MemBufferInputStream::with_range(&buf, 1, 3);
        assert_eq!(stream.available(), 3);

        let mut out = [0u8; 10];
        let n = std::io::Read::read(&mut stream, &mut out).unwrap();
        assert_eq!(n, 3);
        assert_eq!(out[0], 0x20);
        assert_eq!(out[1], 0x30);
        assert_eq!(out[2], 0x40);

        // Should be EOF now
        let n = std::io::Read::read(&mut stream, &mut out).unwrap();
        assert_eq!(n, 0);
        assert_eq!(stream.available(), 0);
    }

    #[test]
    fn test_mem_buffer_input_stream_read_to_end() {
        let data = vec![0xAA, 0xBB, 0xCC];
        let buf = ByteMemBufferImpl::new(Address::new(0x1000), data, false);
        let mut stream = MemBufferInputStream::with_range(&buf, 0, 3);
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut stream, &mut out).unwrap();
        assert_eq!(out, vec![0xAA, 0xBB, 0xCC]);
    }

    // =====================================================================
    // Tests for MemoryBlockListener (trait existence and dispatch)
    // =====================================================================

    struct TestBlockListener {
        name_changed: std::sync::Mutex<Vec<(String, String)>>,
    }

    impl TestBlockListener {
        fn new() -> Self {
            Self {
                name_changed: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl MemoryBlockListener for TestBlockListener {
        fn name_changed(&self, _block: &MemoryBlock, old_name: &str, new_name: &str) {
            self.name_changed
                .lock()
                .unwrap()
                .push((old_name.to_string(), new_name.to_string()));
        }
        fn comment_changed(&self, _block: &MemoryBlock, _old: Option<&str>, _new: Option<&str>) {}
        fn read_status_changed(&self, _block: &MemoryBlock, _is_read: bool) {}
        fn write_status_changed(&self, _block: &MemoryBlock, _is_write: bool) {}
        fn execute_status_changed(&self, _block: &MemoryBlock, _is_execute: bool) {}
        fn source_changed(&self, _block: &MemoryBlock, _old: &str, _new: &str) {}
        fn source_offset_changed(&self, _block: &MemoryBlock, _old: i64, _new: i64) {}
        fn data_changed(&self, _block: &MemoryBlock, _addr: Address, _old: &[u8], _new: &[u8]) {}
    }

    #[test]
    fn test_memory_block_listener_name_changed() {
        let listener = TestBlockListener::new();
        let block = MemoryBlock::new_initialized(
            "old_name",
            AddressRange::new(Address::new(0x1000), Address::new(0x10FF)),
            FLAG_READ,
            vec![0u8; 256],
        );
        listener.name_changed(&block, "old_name", "new_name");
        let changes = listener.name_changed.lock().unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].0, "old_name");
        assert_eq!(changes[0].1, "new_name");
    }

    // =====================================================================
    // Tests for MemoryBlockStub
    // =====================================================================

    #[test]
    fn test_memory_block_stub_new() {
        let stub = MemoryBlockStub::new();
        assert!(stub.start.is_null());
        assert!(stub.end.is_null());
    }

    #[test]
    fn test_memory_block_stub_with_range() {
        let stub = MemoryBlockStub::with_range(Address::new(0x1000), Address::new(0x10FF));
        assert_eq!(stub.start, Address::new(0x1000));
        assert_eq!(stub.end, Address::new(0x10FF));
    }

    #[test]
    fn test_memory_block_stub_to_memory_block() {
        let stub = MemoryBlockStub::with_range(Address::new(0x1000), Address::new(0x100F));
        let block = stub.to_memory_block("test", FLAG_READ | FLAG_WRITE);
        assert_eq!(block.name, "test");
        assert_eq!(block.size(), 16);
        assert!(block.is_read());
        assert!(block.is_write());
        assert!(!block.is_execute());
    }

    // =====================================================================
    // Tests for FileBytes
    // =====================================================================

    #[test]
    fn test_file_bytes_new() {
        let fb = FileBytes::new(42, "test.bin", 1024, 0);
        assert_eq!(fb.id, 42);
        assert_eq!(fb.filename, "test.bin");
        assert_eq!(fb.size, 1024);
        assert_eq!(fb.file_offset, 0);
    }

    #[test]
    fn test_file_bytes_equality() {
        let fb1 = FileBytes::new(1, "a.bin", 100, 0);
        let fb2 = FileBytes::new(1, "a.bin", 100, 0);
        assert_eq!(fb1, fb2);
    }

    // =====================================================================
    // Additional MemoryBlock tests
    // =====================================================================

    #[test]
    fn test_memory_block_permissions_string() {
        let block = MemoryBlock::new_initialized(
            "test",
            AddressRange::new(Address::new(0x1000), Address::new(0x10FF)),
            FLAG_READ | FLAG_WRITE | FLAG_EXECUTE,
            vec![0u8; 256],
        );
        assert_eq!(block.permissions_string(), "rwx");

        let ro = MemoryBlock::new_initialized(
            "ro",
            AddressRange::new(Address::new(0x2000), Address::new(0x20FF)),
            FLAG_READ,
            vec![0u8; 256],
        );
        assert_eq!(ro.permissions_string(), "r--");
    }

    #[test]
    fn test_memory_block_uninitialized() {
        let block = MemoryBlock::new_uninitialized(
            "heap",
            AddressRange::new(Address::new(0x5000), Address::new(0x5FFF)),
            FLAG_READ | FLAG_WRITE,
        );
        assert!(!block.initialized);
        assert!(block.data.is_empty());
        assert!(block.get_byte_at_offset(0).is_none());
    }

    #[test]
    fn test_memory_block_adjacent() {
        let b1 = MemoryBlock::new_initialized(
            "A",
            AddressRange::new(Address::new(0x1000), Address::new(0x10FF)),
            FLAG_READ,
            vec![0u8; 256],
        );
        let b2 = MemoryBlock::new_initialized(
            "B",
            AddressRange::new(Address::new(0x1100), Address::new(0x11FF)),
            FLAG_READ,
            vec![0u8; 256],
        );
        assert!(b1.is_adjacent_to(&b2));
        assert!(b2.is_adjacent_to(&b1));
    }

    #[test]
    fn test_memory_block_not_adjacent() {
        let b1 = MemoryBlock::new_initialized(
            "A",
            AddressRange::new(Address::new(0x1000), Address::new(0x10FF)),
            FLAG_READ,
            vec![0u8; 256],
        );
        let b2 = MemoryBlock::new_initialized(
            "B",
            AddressRange::new(Address::new(0x2000), Address::new(0x20FF)),
            FLAG_READ,
            vec![0u8; 256],
        );
        assert!(!b1.is_adjacent_to(&b2));
    }

    #[test]
    fn test_memory_block_intersects() {
        let b1 = MemoryBlock::new_initialized(
            "A",
            AddressRange::new(Address::new(0x1000), Address::new(0x10FF)),
            FLAG_READ,
            vec![0u8; 256],
        );
        let b2 = MemoryBlock::new_initialized(
            "B",
            AddressRange::new(Address::new(0x1080), Address::new(0x1180)),
            FLAG_READ,
            vec![0u8; 256],
        );
        assert!(b1.intersects(&b2));
        assert!(b2.intersects(&b1));
    }

    #[test]
    fn test_memory_block_intersection() {
        let b1 = MemoryBlock::new_initialized(
            "A",
            AddressRange::new(Address::new(0x1000), Address::new(0x10FF)),
            FLAG_READ,
            vec![0u8; 256],
        );
        let b2 = MemoryBlock::new_initialized(
            "B",
            AddressRange::new(Address::new(0x1080), Address::new(0x1180)),
            FLAG_READ,
            vec![0u8; 256],
        );
        let isect = b1.intersection(&b2).unwrap();
        assert_eq!(isect.start, Address::new(0x1080));
        assert_eq!(isect.end, Address::new(0x10FF));
    }

    #[test]
    fn test_memory_block_with_comment() {
        let block = MemoryBlock::new_initialized(
            "test",
            AddressRange::new(Address::new(0x1000), Address::new(0x10FF)),
            FLAG_READ,
            vec![0u8; 256],
        )
        .with_comment("This is a comment");
        assert!(block.has_comment());
        assert_eq!(block.get_comment(), "This is a comment");
    }

    #[test]
    fn test_memory_block_with_source_name() {
        let block = MemoryBlock::new_initialized(
            "test",
            AddressRange::new(Address::new(0x1000), Address::new(0x10FF)),
            FLAG_READ,
            vec![0u8; 256],
        )
        .with_source_name("a.out");
        assert!(block.has_source_name());
        assert_eq!(block.get_source_name(), "a.out");
    }

    #[test]
    fn test_memory_block_display_label() {
        let block = MemoryBlock::new_initialized(
            ".text",
            AddressRange::new(Address::new(0x1000), Address::new(0x10FF)),
            FLAG_READ | FLAG_EXECUTE,
            vec![0u8; 256],
        );
        // Address::Display uses 8-digit lowercase hex
        assert_eq!(block.display_label(), ".text [00001000-000010ff]");
    }

    #[test]
    fn test_memory_block_sub_range() {
        let block = MemoryBlock::new_initialized(
            "test",
            AddressRange::new(Address::new(0x1000), Address::new(0x10FF)),
            FLAG_READ,
            vec![0u8; 256],
        );
        let sub = block.sub_range(0x10, 0x20).unwrap();
        assert_eq!(sub.start, Address::new(0x1010));
        assert_eq!(sub.end, Address::new(0x102F));
    }

    #[test]
    fn test_memory_block_sub_range_out_of_bounds() {
        let block = MemoryBlock::new_initialized(
            "test",
            AddressRange::new(Address::new(0x1000), Address::new(0x10FF)),
            FLAG_READ,
            vec![0u8; 256],
        );
        // Offset beyond block
        assert!(block.sub_range(0x200, 0x10).is_none());
        // Size extending beyond block
        assert!(block.sub_range(0x100, 0x200).is_none());
    }

    #[test]
    fn test_memory_block_contains_range() {
        let block = MemoryBlock::new_initialized(
            "test",
            AddressRange::new(Address::new(0x1000), Address::new(0x10FF)),
            FLAG_READ,
            vec![0u8; 256],
        );
        let inner = AddressRange::new(Address::new(0x1020), Address::new(0x1040));
        assert!(block.contains_range(&inner));
        let outer = AddressRange::new(Address::new(0x0F00), Address::new(0x1100));
        assert!(!block.contains_range(&outer));
    }

    #[test]
    fn test_memory_block_iter_addresses() {
        let block = MemoryBlock::new_initialized(
            "tiny",
            AddressRange::new(Address::new(0x1000), Address::new(0x1003)),
            FLAG_READ,
            vec![0u8; 4],
        );
        let addrs: Vec<Address> = block.iter_addresses().collect();
        assert_eq!(addrs.len(), 4);
        assert_eq!(addrs[0], Address::new(0x1000));
        assert_eq!(addrs[3], Address::new(0x1003));
    }

    // =====================================================================
    // Additional MemoryMap tests
    // =====================================================================

    #[test]
    fn test_memory_map_min_max_address() {
        let mut mem = make_memory();
        mem.create_initialized_block("A", Address::new(0x1000), vec![0u8; 100], false)
            .unwrap();
        mem.create_initialized_block("B", Address::new(0x5000), vec![0u8; 50], false)
            .unwrap();
        assert_eq!(mem.min_address(), Some(Address::new(0x1000)));
        assert_eq!(mem.max_address(), Some(Address::new(0x5031)));
    }

    #[test]
    fn test_memory_map_contains() {
        let mut mem = make_memory();
        mem.create_initialized_block("A", Address::new(0x1000), vec![0u8; 256], false)
            .unwrap();
        assert!(mem.contains(&Address::new(0x1000)));
        assert!(mem.contains(&Address::new(0x10FF)));
        assert!(!mem.contains(&Address::new(0x0FFF)));
        assert!(!mem.contains(&Address::new(0x1100)));
    }

    #[test]
    fn test_memory_map_blocks_in_order() {
        let mut mem = make_memory();
        mem.create_initialized_block("C", Address::new(0x3000), vec![0u8; 10], false)
            .unwrap();
        mem.create_initialized_block("A", Address::new(0x1000), vec![0u8; 10], false)
            .unwrap();
        mem.create_initialized_block("B", Address::new(0x2000), vec![0u8; 10], false)
            .unwrap();
        let blocks = mem.get_blocks();
        assert_eq!(blocks[0].name, "A");
        assert_eq!(blocks[1].name, "B");
        assert_eq!(blocks[2].name, "C");
    }

    #[test]
    fn test_memory_map_num_blocks() {
        let mut mem = make_memory();
        assert_eq!(mem.num_blocks(), 0);
        assert!(mem.is_empty());
        mem.create_initialized_block("A", Address::new(0x1000), vec![0u8; 10], false)
            .unwrap();
        assert_eq!(mem.num_blocks(), 1);
        assert!(!mem.is_empty());
    }

    #[test]
    fn test_memory_map_iter_blocks() {
        let mut mem = make_memory();
        mem.create_initialized_block("A", Address::new(0x1000), vec![0u8; 10], false)
            .unwrap();
        mem.create_initialized_block("B", Address::new(0x2000), vec![0u8; 10], false)
            .unwrap();
        let names: Vec<&str> = mem.iter_blocks().map(|b| b.name.as_str()).collect();
        assert_eq!(names, vec!["A", "B"]);
    }

    #[test]
    fn test_memory_map_big_endian() {
        let mut mem = MemoryMap::new(true);
        assert!(mem.is_big_endian());
        mem.create_initialized_block(".text", Address::new(0x1000), vec![0x12, 0x34], false)
            .unwrap();
        let s = mem.get_short(Address::new(0x1000)).unwrap();
        assert_eq!(s, 0x1234);
    }

    #[test]
    fn test_memory_map_write_set_int() {
        let mut mem = make_memory();
        mem.create_initialized_block(".text", Address::new(0x1000), vec![0u8; 16], false)
            .unwrap();
        mem.set_int(Address::new(0x1000), 0x12345678i32).unwrap();
        assert_eq!(mem.get_int(Address::new(0x1000)).unwrap(), 0x12345678i32);
    }

    #[test]
    fn test_memory_map_write_set_long() {
        let mut mem = make_memory();
        mem.create_initialized_block(".text", Address::new(0x1000), vec![0u8; 16], false)
            .unwrap();
        mem.set_long(Address::new(0x1000), 0x1234567890ABCDEFi64)
            .unwrap();
        assert_eq!(
            mem.get_long(Address::new(0x1000)).unwrap(),
            0x1234567890ABCDEFi64
        );
    }

    #[test]
    fn test_memory_map_uninitialized_block_read_fails() {
        let mut mem = make_memory();
        mem.create_uninitialized_block("heap", Address::new(0x5000), 64, false)
            .unwrap();
        assert!(mem.get_byte(Address::new(0x5000)).is_err());
    }

    #[test]
    fn test_memory_map_initialized_block_value() {
        let mut mem = make_memory();
        mem.create_initialized_block_value(".bss", Address::new(0x3000), 16, 0xCC, false)
            .unwrap();
        assert_eq!(mem.get_byte(Address::new(0x3000)).unwrap(), 0xCC);
        assert_eq!(mem.get_byte(Address::new(0x300F)).unwrap(), 0xCC);
    }

    #[test]
    fn test_memory_map_find_bytes_backward() {
        let mut mem = make_memory();
        let mut data = vec![0u8; 256];
        data[100..104].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        mem.create_initialized_block(".text", Address::new(0x1000), data, false)
            .unwrap();
        let result = mem.find_bytes(
            Address::new(0x1000),
            Address::new(0x10FF),
            &[0xDE, 0xAD, 0xBE, 0xEF],
            None,
            false,
        );
        assert_eq!(result, Some(Address::new(0x1064)));
    }

    #[test]
    fn test_memory_map_find_bytes_multiple_matches_forward() {
        let mut mem = make_memory();
        let mut data = vec![0u8; 256];
        data[10..12].copy_from_slice(&[0xAB, 0xCD]);
        data[200..202].copy_from_slice(&[0xAB, 0xCD]);
        mem.create_initialized_block(".text", Address::new(0x1000), data, false)
            .unwrap();
        let result = mem.find_bytes(
            Address::new(0x1000),
            Address::new(0x10FF),
            &[0xAB, 0xCD],
            None,
            true,
        );
        // Should find the first match
        assert_eq!(result, Some(Address::new(0x100A)));
    }

    // =====================================================================
    // Tests for ByteMappingScheme additional scenarios
    // =====================================================================

    #[test]
    fn test_byte_mapping_scheme_display() {
        let scheme = ByteMappingScheme::one_to_one();
        assert_eq!(format!("{}", scheme), "1:1 mapping");

        let scheme = ByteMappingScheme::new(2, 4);
        assert_eq!(format!("{}", scheme), "2:4 mapping");
    }

    #[test]
    fn test_byte_mapping_scheme_encode_roundtrip() {
        let scheme = ByteMappingScheme::new(3, 7);
        let encoded = scheme.encode();
        let decoded = ByteMappingScheme::from_encoded(encoded);
        assert_eq!(decoded.mapped_byte_count(), 3);
        assert_eq!(decoded.mapped_source_byte_count(), 7);
    }

    #[test]
    fn test_byte_mapping_scheme_3_to_4() {
        let scheme = ByteMappingScheme::new(3, 4);
        let base = Address::new(0x1000);
        // Offset 0 -> source 0
        assert_eq!(scheme.get_mapped_source_address(base, 0), Address::new(0x1000));
        // Offset 1 -> source 1
        assert_eq!(scheme.get_mapped_source_address(base, 1), Address::new(0x1001));
        // Offset 2 -> source 2
        assert_eq!(scheme.get_mapped_source_address(base, 2), Address::new(0x1002));
        // Offset 3 -> next pattern: source offset 4
        assert_eq!(scheme.get_mapped_source_address(base, 3), Address::new(0x1004));
    }

    #[test]
    #[should_panic(expected = "invalid byte mapping ratio")]
    fn test_byte_mapping_scheme_invalid_zero() {
        ByteMappingScheme::new(0, 4);
    }

    #[test]
    #[should_panic(expected = "invalid byte mapping ratio")]
    fn test_byte_mapping_scheme_invalid_exceeds() {
        ByteMappingScheme::new(5, 4);
    }

    // =====================================================================
    // Tests for MemoryBlockSourceInfo additional scenarios
    // =====================================================================

    #[test]
    fn test_memory_block_source_info_byte_mapped() {
        let info = MemoryBlockSourceInfo::new_byte_mapped(
            100,
            Address::new(0x2000),
            AddressRange::new(Address::new(0x1000), Address::new(0x1063)),
            ByteMappingScheme::default(),
        );
        assert!(info.is_byte_mapped());
        assert!(info.is_mapped());
        assert!(!info.is_bit_mapped());
        assert!(info.get_byte_mapping_scheme().is_some());
        assert_eq!(info.get_length(), 100);
        assert!(info.get_mapped_range().is_some());
    }

    #[test]
    fn test_memory_block_source_info_bit_mapped() {
        let info = MemoryBlockSourceInfo::new_bit_mapped(
            64,
            Address::new(0x3000),
            AddressRange::new(Address::new(0x1000), Address::new(0x103F)),
        );
        assert!(info.is_bit_mapped());
        assert!(info.is_mapped());
        assert!(!info.is_byte_mapped());
        assert!(info.get_byte_mapping_scheme().is_none());
    }

    #[test]
    fn test_memory_block_source_info_no_file_bytes() {
        let info = MemoryBlockSourceInfo::new_initialized(100, Address::new(0x1000), None, -1);
        assert!(!info.has_file_bytes());
        assert!(!info.is_file_bytes_range());
        assert!(info.get_file_bytes_id().is_none());
        assert!(info.get_file_bytes_offset().is_none());
    }

    #[test]
    fn test_memory_block_source_info_address_range() {
        let info = MemoryBlockSourceInfo::new_initialized(100, Address::new(0x1000), Some(1), 0);
        let range = info.get_address_range();
        assert_eq!(range.start, Address::new(0x1000));
        assert_eq!(range.end, Address::new(0x1063));
    }

    // =====================================================================
    // Additional error type tests
    // =====================================================================

    #[test]
    fn test_memory_access_error_is_clone() {
        let err = MemoryAccessError::new("test");
        let err2 = err.clone();
        assert_eq!(err.message, err2.message);
    }

    #[test]
    fn test_memory_access_error_is_std_error() {
        let err: Box<dyn std::error::Error> =
            Box::new(MemoryAccessError::new("test error"));
        assert!(err.to_string().contains("test error"));
    }

    #[test]
    fn test_memory_block_error_into_memory_access_error() {
        let block_err = MemoryBlockError::new("block problem");
        let access_err: MemoryAccessError = block_err.into();
        assert_eq!(access_err.message, "block problem");
    }

    #[test]
    fn test_memory_conflict_error_into_ghidra_error() {
        let err: GhidraError = MemoryConflictError::new("conflict").into();
        assert!(matches!(err, GhidraError::MemoryError(_)));
    }

    // =====================================================================
    // StubMemory additional tests
    // =====================================================================

    #[test]
    fn test_stub_memory_big_endian() {
        let mem = StubMemory::new(true);
        assert!(mem.is_big_endian());
    }

    #[test]
    fn test_stub_memory_all_methods_return_error() {
        let mut mem = StubMemory::new(false);
        assert!(mem.get_byte(Address::new(0)).is_err());
        assert!(mem.get_short(Address::new(0)).is_err());
        assert!(mem.get_int(Address::new(0)).is_err());
        assert!(mem.get_long(Address::new(0)).is_err());
        assert!(mem.set_byte(Address::new(0), 0).is_err());
        assert!(mem.set_short(Address::new(0), 0).is_err());
        assert!(mem.set_int(Address::new(0), 0).is_err());
        assert!(mem.set_long(Address::new(0), 0).is_err());
        assert!(mem.create_initialized_block("x", Address::new(0), vec![], false).is_err());
        assert!(mem.remove_block("x").is_err());
    }

    #[test]
    fn test_stub_memory_find_bytes_returns_none() {
        let mem = StubMemory::new(false);
        assert!(mem
            .find_bytes(Address::new(0), Address::new(10), &[0x00], None, true)
            .is_none());
    }

    #[test]
    fn test_stub_memory_address_sets_empty() {
        let mem = StubMemory::new(false);
        assert!(mem.loaded_and_initialized_address_set().is_empty());
        assert!(mem.all_initialized_address_set().is_empty());
        assert!(mem.execute_set().is_empty());
    }

    // =====================================================================
    // Tests for Memory trait helper methods
    // =====================================================================

    #[test]
    fn test_memory_max_binary_size() {
        let mem = make_memory();
        assert_eq!(mem.max_binary_size(), MAX_BINARY_SIZE);
        assert_eq!(mem.max_block_size(), MAX_BLOCK_SIZE);
    }

    #[test]
    fn test_memory_is_valid_block_name() {
        let mem = make_memory();
        assert!(mem.is_valid_memory_block_name("hello"));
        assert!(mem.is_valid_memory_block_name(".text"));
        assert!(mem.is_valid_memory_block_name("block with spaces"));
        assert!(!mem.is_valid_memory_block_name(""));
        assert!(!mem.is_valid_memory_block_name("\n"));
        assert!(!mem.is_valid_memory_block_name("\t"));
        assert!(!mem.is_valid_memory_block_name("\x00abc"));
    }

    #[test]
    fn test_memory_is_external_block_address() {
        let mut mem = make_memory();
        mem.create_initialized_block(
            EXTERNAL_BLOCK_NAME,
            Address::new(0xF000),
            vec![0u8; 16],
            false,
        )
        .unwrap();
        assert!(mem.is_external_block_address(&Address::new(0xF000)));
        assert!(!mem.is_external_block_address(&Address::new(0x0000)));
    }

    #[test]
    fn test_memory_locate_addresses_for_file_offset() {
        let mut mem = make_memory();
        // Create a block with file-backed source info
        let mut block = MemoryBlock::new_initialized(
            ".text",
            AddressRange::new(Address::new(0x1000), Address::new(0x10FF)),
            FLAG_READ,
            vec![0u8; 256],
        );
        block.source_infos = vec![MemoryBlockSourceInfo::new_initialized(
            256,
            Address::new(0x1000),
            Some(1),
            100, // File bytes start at offset 100
        )];
        mem.insert_block(block).unwrap();

        // File offset 100 should map to address 0x1000
        let addrs = mem.locate_addresses_for_file_offset(100);
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], Address::new(0x1000));

        // File offset 150 should map to address 0x1032
        let addrs = mem.locate_addresses_for_file_offset(150);
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], Address::new(0x1032));

        // File offset 0 should not match (out of range)
        let addrs = mem.locate_addresses_for_file_offset(0);
        assert!(addrs.is_empty());
    }

    #[test]
    fn test_memory_get_address_source_info() {
        let mut mem = make_memory();
        let mut block = MemoryBlock::new_initialized(
            ".text",
            AddressRange::new(Address::new(0x1000), Address::new(0x10FF)),
            FLAG_READ,
            vec![0u8; 256],
        );
        block.source_infos = vec![MemoryBlockSourceInfo::new_initialized(
            256,
            Address::new(0x1000),
            Some(1),
            0,
        )];
        mem.insert_block(block).unwrap();

        let info = mem.get_address_source_info(&Address::new(0x1050));
        assert!(info.is_some());
        assert_eq!(info.unwrap().get_length(), 256);

        let info = mem.get_address_source_info(&Address::new(0x9999));
        assert!(info.is_none());
    }

    // =====================================================================
    // Constants tests
    // =====================================================================

    #[test]
    fn test_constants_values() {
        assert_eq!(EXTERNAL_BLOCK_NAME, "EXTERNAL");
        assert_eq!(HEAP_BLOCK_NAME, "__HEAP__");
        assert_eq!(GBYTE_SHIFT_FACTOR, 30);
        assert_eq!(GBYTE, 1 << 30);
        assert_eq!(MAX_BINARY_SIZE_GB, 16);
        assert_eq!(MAX_BINARY_SIZE, 16u64 << 30);
        assert_eq!(MAX_BLOCK_SIZE_GB, 16);
        assert_eq!(MAX_BLOCK_SIZE, 16u64 << 30);
        assert_eq!(FLAG_READ, 0x4);
        assert_eq!(FLAG_WRITE, 0x2);
        assert_eq!(FLAG_EXECUTE, 0x01);
        assert_eq!(FLAG_VOLATILE, 0x8);
        assert_eq!(FLAG_ARTIFICIAL, 0x10);
    }

    // =====================================================================
    // WrappedMemBuffer additional tests
    // =====================================================================

    #[test]
    fn test_wrapped_mem_buffer_basic() {
        let data = vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
        let inner = ByteMemBufferImpl::new(Address::new(0x1000), data, false);
        let wrapped = WrappedMemBuffer::new(Box::new(inner), 4).unwrap();
        // offset 0 in wrapped = offset 4 in inner = 0x50
        assert_eq!(wrapped.get_address(), Address::new(0x1004));
        assert_eq!(wrapped.get_byte(0).unwrap(), 0x50);
        assert_eq!(wrapped.get_byte(3).unwrap(), 0x80);
    }

    #[test]
    fn test_wrapped_mem_buffer_with_cache() {
        let data = vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
        let inner = ByteMemBufferImpl::new(Address::new(0x1000), data, false);
        let wrapped = WrappedMemBuffer::with_buffer_size(Box::new(inner), 4, 0).unwrap();
        assert_eq!(wrapped.get_address(), Address::new(0x1000));
        assert_eq!(wrapped.get_byte(0).unwrap(), 0x10);
        assert_eq!(wrapped.get_byte(1).unwrap(), 0x20);
    }

    #[test]
    fn test_wrapped_mem_buffer_get_bytes() {
        let data = vec![0x10, 0x20, 0x30, 0x40, 0x50];
        let inner = ByteMemBufferImpl::new(Address::new(0x1000), data, false);
        // base_offset=2 means wrapped offset 0 = inner offset 2
        let wrapped = WrappedMemBuffer::new(Box::new(inner), 2).unwrap();
        let mut dest = [0u8; 3];
        let n = wrapped.get_bytes(&mut dest, 0);
        assert_eq!(n, 3);
        assert_eq!(dest, [0x30, 0x40, 0x50]);
    }

    #[test]
    fn test_wrapped_mem_buffer_endian() {
        let data = vec![0x34, 0x12];
        let inner = ByteMemBufferImpl::new(Address::new(0x1000), data, false);
        let wrapped = WrappedMemBuffer::new(Box::new(inner), 0).unwrap();
        assert!(!wrapped.is_big_endian());
        assert_eq!(wrapped.get_short(0).unwrap(), 0x1234);
    }

    // =====================================================================
    // Edge case tests
    // =====================================================================

    #[test]
    fn test_memory_map_join_non_contiguous_fails() {
        let mut mem = make_memory();
        mem.create_initialized_block("A", Address::new(0x1000), vec![0xAA; 64], false)
            .unwrap();
        mem.create_initialized_block("B", Address::new(0x3000), vec![0xBB; 64], false)
            .unwrap();
        let result = mem.join_blocks("A", "B");
        assert!(result.is_err());
    }

    #[test]
    fn test_memory_map_split_at_start_fails() {
        let mut mem = make_memory();
        mem.create_initialized_block(".text", Address::new(0x1000), vec![0x90; 64], false)
            .unwrap();
        let result = mem.split_block(".text", Address::new(0x1000));
        assert!(result.is_err());
    }

    #[test]
    fn test_memory_map_remove_nonexistent_fails() {
        let mut mem = make_memory();
        let result = mem.remove_block("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_memory_map_move_nonexistent_fails() {
        let mut mem = make_memory();
        let result = mem.move_block("nonexistent", Address::new(0x2000));
        assert!(result.is_err());
    }

    #[test]
    fn test_memory_block_write_to_readonly_fails() {
        let mut mem = make_memory();
        mem.create_initialized_block(
            ".rodata",
            Address::new(0x1000),
            vec![0u8; 16],
            false,
        )
        .unwrap();
        // Remove write permission
        let block = mem.blocks.get_mut(".rodata").unwrap();
        block.flags = FLAG_READ;

        let result = mem.set_byte(Address::new(0x1000), 0x42);
        assert!(result.is_err());
    }

    #[test]
    fn test_memory_block_get_bytes_at_offset() {
        let block = MemoryBlock::new_initialized(
            "test",
            AddressRange::new(Address::new(0x1000), Address::new(0x100F)),
            FLAG_READ,
            vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
                 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0xFF],
        );
        let bytes = block.get_bytes_at_offset(4, 4).unwrap();
        assert_eq!(bytes, &[0x50, 0x60, 0x70, 0x80]);
    }

    #[test]
    fn test_memory_block_get_bytes_at_offset_out_of_range() {
        let block = MemoryBlock::new_initialized(
            "test",
            AddressRange::new(Address::new(0x1000), Address::new(0x1003)),
            FLAG_READ,
            vec![0x10, 0x20, 0x30, 0x40],
        );
        assert!(block.get_bytes_at_offset(2, 10).is_none());
    }

    #[test]
    fn test_memory_block_has_data() {
        let init = MemoryBlock::new_initialized(
            "init",
            AddressRange::new(Address::new(0x1000), Address::new(0x100F)),
            FLAG_READ,
            vec![0u8; 16],
        );
        assert!(init.has_data());

        let uninit = MemoryBlock::new_uninitialized(
            "uninit",
            AddressRange::new(Address::new(0x2000), Address::new(0x200F)),
            FLAG_READ,
        );
        assert!(!uninit.has_data());
    }

    #[test]
    fn test_memory_block_is_fully_initialized() {
        let full = MemoryBlock::new_initialized(
            "full",
            AddressRange::new(Address::new(0x1000), Address::new(0x100F)),
            FLAG_READ,
            vec![0u8; 16],
        );
        assert!(full.is_fully_initialized());

        // A block with size > data.len() is not fully initialized
        let partial = MemoryBlock {
            name: "partial".to_string(),
            range: AddressRange::new(Address::new(0x2000), Address::new(0x20FF)),
            block_type: MemoryBlockType::Default,
            flags: FLAG_READ,
            comment: String::new(),
            source_name: String::new(),
            source_infos: vec![],
            initialized: true,
            data: vec![0u8; 10], // only 10 bytes but size is 256
            mapped_source_base: None,
            mapping_scheme: None,
            is_overlay: false,
            is_loaded: true,
        };
        assert!(!partial.is_fully_initialized());
    }
}

// Helper functions used by tests
#[cfg(test)]
fn num_overlay_blocks(mem: &MemoryMap) -> usize {
    mem.get_overlay_blocks().len()
}

#[cfg(test)]
fn get_physical_block_count(mem: &MemoryMap) -> usize {
    mem.get_physical_blocks().len()
}
