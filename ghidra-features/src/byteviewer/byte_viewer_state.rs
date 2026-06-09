//! Byte viewer state, index mapping, and block-set implementations.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.byteviewer`:
//! - `ByteViewerState` -- snapshot of the current view position
//! - `ByteViewerLocationMemento` -- serialisable view position for undo/redo
//! - `ByteViewerProgramLocation` -- program location within the byte viewer
//! - `IndexMap` -- maps between memory bytes and display-line indexes
//! - `EmptyByteBlockSet` -- sentinel block set with no blocks
//! - `MemoryByteBlock` -- byte block backed by program memory
//! - `ProgramByteBlockSet` -- block set for a program object
//! - `FileByteBlock` -- byte block backed by a raw file buffer
//! - `FileByteBlockSet` -- block set for a file object
//!
//! # Key types
//!
//! - [`ByteViewerState`] -- snapshot of the viewer's current scroll and
//!   cursor position
//! - [`ByteViewerLocationMemento`] -- serialisable location memento
//! - [`ByteViewerProgramLocation`] -- program location for the byte viewer
//! - [`IndexMap`] -- maps line indexes to block/offset pairs
//! - [`EmptyByteBlockSet`] -- a block set that contains no blocks
//! - [`MemoryByteBlock`] -- a byte block backed by a program memory block
//! - [`ProgramByteBlockSet`] -- a block set backed by a program's memory
//! - [`FileByteBlock`] -- a byte block backed by a raw byte buffer
//! - [`FileByteBlockSet`] -- a block set backed by a single file buffer

use num_bigint::BigInt;
use std::collections::BTreeMap;

use super::{
    ByteBlock, ByteBlockInfo, ByteBlockRange, ByteBlockSelection,
    ByteBlockSet, ByteEditInfo, ByteBlockChangeManager,
};

// ---------------------------------------------------------------------------
// ByteViewerState
// ---------------------------------------------------------------------------

/// A snapshot of the byte viewer's current view.
///
/// Ported from Ghidra's `ByteViewerState`.
///
/// Records the current block, offset, column, scroll index, and the
/// corresponding address for the focused position.
#[derive(Debug, Clone)]
pub struct ByteViewerState {
    /// The address at the current view focus (None if no program is loaded).
    address: Option<u64>,
    /// The block index.
    block_index: usize,
    /// The byte offset within the block.
    offset: BigInt,
    /// The column index.
    column: usize,
    /// The scroll position line index.
    scroll_index: BigInt,
    /// The vertical scroll offset within the current line.
    y_offset: i32,
}

impl ByteViewerState {
    /// Create a new viewer state.
    pub fn new(
        address: Option<u64>,
        block_index: usize,
        offset: BigInt,
        column: usize,
        scroll_index: BigInt,
        y_offset: i32,
    ) -> Self {
        Self {
            address,
            block_index,
            offset,
            column,
            scroll_index,
            y_offset,
        }
    }

    /// Create from a `ByteBlockInfo` and viewer position.
    pub fn from_info(
        info: &ByteBlockInfo,
        scroll_index: BigInt,
        y_offset: i32,
        address: Option<u64>,
    ) -> Self {
        Self {
            address,
            block_index: info.block_index(),
            offset: info.offset().clone(),
            column: info.column(),
            scroll_index,
            y_offset,
        }
    }

    /// The address at the current view focus.
    pub fn address(&self) -> Option<u64> {
        self.address
    }

    /// The block index.
    pub fn block_index(&self) -> usize {
        self.block_index
    }

    /// The byte offset within the block.
    pub fn offset(&self) -> &BigInt {
        &self.offset
    }

    /// The column index.
    pub fn column(&self) -> usize {
        self.column
    }

    /// The scroll position line index.
    pub fn scroll_index(&self) -> &BigInt {
        &self.scroll_index
    }

    /// The vertical scroll offset.
    pub fn y_offset(&self) -> i32 {
        self.y_offset
    }
}

impl std::fmt::Display for ByteViewerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ByteViewerState: address={:?}, block={}, offset={}, scroll_index={}, y_offset={}",
            self.address, self.block_index, self.offset, self.scroll_index, self.y_offset
        )
    }
}

// ---------------------------------------------------------------------------
// ByteViewerLocationMemento
// ---------------------------------------------------------------------------

/// Serialisable memento of the byte viewer's location.
///
/// Ported from Ghidra's `ByteViewerLocationMemento`.
///
/// Captures the program, program location, block number, block offset,
/// column, and viewer position so that the location can be restored later
/// (e.g. for undo/redo or tool-state persistence).
#[derive(Debug, Clone)]
pub struct ByteViewerLocationMemento {
    /// The program name (opaque).
    program_name: Option<String>,
    /// The address at the location.
    address: Option<u64>,
    /// The block number.
    block_num: usize,
    /// The block offset.
    block_offset: BigInt,
    /// The column.
    column: usize,
    /// The scroll index.
    scroll_index: BigInt,
    /// The vertical offset within the scroll line.
    y_offset: i32,
}

impl ByteViewerLocationMemento {
    /// Create a new location memento.
    pub fn new(
        program_name: Option<String>,
        address: Option<u64>,
        block_num: usize,
        block_offset: BigInt,
        column: usize,
        scroll_index: BigInt,
        y_offset: i32,
    ) -> Self {
        Self {
            program_name,
            address,
            block_num,
            block_offset,
            column,
            scroll_index,
            y_offset,
        }
    }

    /// Restore from a serialised state map.
    pub fn from_state(state: &BTreeMap<String, String>) -> Option<Self> {
        let block_num: usize = state
            .get("Block Num")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let block_offset = state
            .get("Block Offset")
            .and_then(|s| s.parse::<i64>().ok())
            .map(BigInt::from)
            .unwrap_or_else(|| BigInt::from(0));
        let scroll_index: i64 = state
            .get("INDEX")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let y_offset: i32 = state
            .get("Y_OFFSET")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let program_name = state.get("PROGRAM").cloned();

        Some(Self {
            program_name,
            address: None,
            block_num,
            block_offset,
            column: 0,
            scroll_index: BigInt::from(scroll_index),
            y_offset,
        })
    }

    /// Save to a serialised state map.
    pub fn to_state(&self) -> BTreeMap<String, String> {
        let mut state = BTreeMap::new();
        state.insert("Block Num".to_string(), self.block_num.to_string());
        state.insert("Block Offset".to_string(), self.block_offset.to_string());
        state.insert("INDEX".to_string(), self.scroll_index.to_string());
        state.insert("Y_OFFSET".to_string(), self.y_offset.to_string());
        if let Some(ref prog) = self.program_name {
            state.insert("PROGRAM".to_string(), prog.clone());
        }
        state
    }

    /// The program name.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    /// The address at the location.
    pub fn address(&self) -> Option<u64> {
        self.address
    }

    /// The block number.
    pub fn block_num(&self) -> usize {
        self.block_num
    }

    /// The block offset.
    pub fn block_offset(&self) -> &BigInt {
        &self.block_offset
    }

    /// The column.
    pub fn column(&self) -> usize {
        self.column
    }

    /// The scroll index.
    pub fn scroll_index(&self) -> &BigInt {
        &self.scroll_index
    }

    /// The vertical offset.
    pub fn y_offset(&self) -> i32 {
        self.y_offset
    }
}

// ---------------------------------------------------------------------------
// ByteViewerProgramLocation
// ---------------------------------------------------------------------------

/// A program location specific to the byte viewer.
///
/// Ported from Ghidra's `ByteViewerProgramLocation`.
///
/// Extends a basic address + character-offset location for use in the byte
/// viewer context.
#[derive(Debug, Clone)]
pub struct ByteViewerProgramLocation {
    /// The address.
    address: u64,
    /// The character offset within the displayed field.
    character_offset: usize,
}

impl ByteViewerProgramLocation {
    /// Create a new byte viewer program location.
    pub fn new(address: u64, character_offset: usize) -> Self {
        Self {
            address,
            character_offset,
        }
    }

    /// The address.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// The character offset.
    pub fn character_offset(&self) -> usize {
        self.character_offset
    }
}

// ---------------------------------------------------------------------------
// BlockInfo (internal to IndexMap)
// ---------------------------------------------------------------------------

/// Computed block index information used by [`IndexMap`].
///
/// Ported from Ghidra's `BlockInfo` inner class.
#[derive(Debug, Clone)]
pub struct BlockInfo {
    /// Reference to the byte block.
    block_index: usize,
    /// The starting display-line index for this block.
    start_index: BigInt,
    /// The byte offset of the block's start within the display grid.
    block_start: BigInt,
    /// The byte offset of the block's end (exclusive).
    block_end: BigInt,
    /// The ending display-line index for this block.
    end_index: BigInt,
}

impl BlockInfo {
    /// Create new block info.
    pub fn new(
        block_index: usize,
        start_index: BigInt,
        block_start: BigInt,
        block_end: BigInt,
        end_index: BigInt,
    ) -> Self {
        Self {
            block_index,
            start_index,
            block_start,
            block_end,
            end_index,
        }
    }

    /// The block index.
    pub fn block_index(&self) -> usize {
        self.block_index
    }

    /// The starting display-line index.
    pub fn start_index(&self) -> &BigInt {
        &self.start_index
    }

    /// The byte offset of the block start.
    pub fn block_start(&self) -> &BigInt {
        &self.block_start
    }

    /// The byte offset of the block end.
    pub fn block_end(&self) -> &BigInt {
        &self.block_end
    }

    /// The ending display-line index.
    pub fn end_index(&self) -> &BigInt {
        &self.end_index
    }
}

// ---------------------------------------------------------------------------
// IndexMap
// ---------------------------------------------------------------------------

/// Maps between bytes in memory and display-line indexes.
///
/// Ported from Ghidra's `IndexMap`.
///
/// Extra indexes are inserted to make each block occupy a uniform number
/// of indexes such that the number of indexes per block is a multiple of
/// the bytes-per-line. This ensures that every display line is fully
/// populated within a block.
#[derive(Debug, Clone)]
pub struct IndexMap {
    /// Block information, keyed by end-layout-index.
    block_info: BTreeMap<BigInt, BlockInfo>,
    /// Total number of indexes.
    num_indexes: BigInt,
    /// Bytes per display line.
    bytes_per_line: usize,
}

impl IndexMap {
    /// Create an empty index map with default 16 bytes per line.
    pub fn new() -> Self {
        Self {
            block_info: BTreeMap::new(),
            num_indexes: BigInt::from(0),
            bytes_per_line: 16,
        }
    }

    /// Build an index map from a set of block sizes.
    ///
    /// `block_sizes` is a slice of `(block_index, block_size, alignment)`
    /// tuples. The `block_offset` is the user-configured column offset.
    pub fn from_blocks(
        block_sizes: &[(usize, usize, usize)],
        bytes_per_line: usize,
        block_offset: usize,
    ) -> Self {
        let mut block_info = BTreeMap::new();
        let bytes_in_line = BigInt::from(bytes_per_line);
        let mut next_start = BigInt::from(0);

        for &(block_index, block_size, alignment) in block_sizes {
            let block_padding = (alignment + block_offset) % bytes_per_line;
            let block_start = &next_start + BigInt::from(block_padding);
            let block_end = &block_start + BigInt::from(block_size);
            let remainder = {
                let r = &block_end % &bytes_in_line;
                r.to_string().parse::<usize>().unwrap_or(0)
            };
            let end_index = if remainder == 0 {
                block_end.clone()
            } else {
                &block_end + BigInt::from(bytes_per_line - remainder)
            };
            let end_layout_index = &end_index / &bytes_in_line;
            let info = BlockInfo::new(
                block_index,
                next_start.clone(),
                block_start,
                block_end,
                end_index.clone(),
            );
            block_info.insert(end_layout_index, info);
            next_start = end_index + &bytes_in_line;
        }

        let num_indexes = if next_start == BigInt::from(0) {
            BigInt::from(0)
        } else {
            (&next_start / &bytes_in_line) - BigInt::from(1)
        };

        Self {
            block_info,
            num_indexes,
            bytes_per_line,
        }
    }

    /// Total number of display lines.
    pub fn num_indexes(&self) -> &BigInt {
        &self.num_indexes
    }

    /// Bytes per display line.
    pub fn bytes_per_line(&self) -> usize {
        self.bytes_per_line
    }

    /// Get the block info for the given line index and field offset.
    ///
    /// Returns the block index and byte offset within that block, or `None`
    /// if the index/offset does not map to a valid byte.
    pub fn get_block_info(&self, index: &BigInt, field_offset: usize) -> Option<(usize, BigInt)> {
        let bytes_in_line = BigInt::from(self.bytes_per_line);
        let byte_index = index * &bytes_in_line + BigInt::from(field_offset);

        // Find the first block info whose end-layout-index >= index
        for (_, info) in self.block_info.range(index..) {
            if byte_index >= info.block_start && byte_index < info.block_end {
                let offset = &byte_index - &info.block_start;
                return Some((info.block_index, offset));
            }
        }
        None
    }

    /// Whether the given index is a block-separator line.
    pub fn is_block_separator_index(&self, index: &BigInt) -> bool {
        self.block_info.contains_key(index)
    }
}

impl Default for IndexMap {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// EmptyByteBlockSet
// ---------------------------------------------------------------------------

/// A sentinel block set that contains no blocks.
///
/// Ported from Ghidra's `EmptyByteBlockSet`.
///
/// Used as a placeholder when no program or file is loaded.
#[derive(Debug, Clone, Default)]
pub struct EmptyByteBlockSet {
    blocks: Vec<ByteBlock>,
}

impl EmptyByteBlockSet {
    /// Create a new empty block set.
    pub fn new() -> Self {
        Self { blocks: Vec::new() }
    }
}

impl ByteBlockSet {
    // Note: ByteBlockSet is a struct, not a trait in the existing code,
    // so EmptyByteBlockSet is just a convenience that wraps an empty
    // ByteBlockSet. The actual methods are on ByteBlockSet itself.
}

// ---------------------------------------------------------------------------
// MemoryByteBlock
// ---------------------------------------------------------------------------

/// A byte block backed by a program memory region.
///
/// Ported from Ghidra's `MemoryByteBlock`.
///
/// This stores an address range and a data buffer, with support for
/// endianness-aware multi-byte reads and writes.
#[derive(Debug, Clone)]
pub struct MemoryByteBlock {
    /// Human-readable name of this block.
    name: String,
    /// Start address.
    start_address: u64,
    /// End address (exclusive).
    end_address: u64,
    /// The raw data.
    data: Vec<u8>,
    /// Whether the block is big-endian.
    big_endian: bool,
    /// Whether the block is editable.
    editable: bool,
    /// Whether the block is initialized.
    initialized: bool,
}

impl MemoryByteBlock {
    /// Create a new memory byte block.
    pub fn new(
        name: impl Into<String>,
        start_address: u64,
        data: Vec<u8>,
        big_endian: bool,
        editable: bool,
    ) -> Self {
        let end_address = start_address + data.len() as u64;
        Self {
            name: name.into(),
            start_address,
            end_address,
            data,
            big_endian,
            editable,
            initialized: true,
        }
    }

    /// Create an uninitialized memory byte block.
    pub fn uninitialized(
        name: impl Into<String>,
        start_address: u64,
        size: usize,
        big_endian: bool,
    ) -> Self {
        Self {
            name: name.into(),
            start_address,
            end_address: start_address + size as u64,
            data: vec![0; size],
            big_endian,
            editable: true,
            initialized: false,
        }
    }

    /// The block name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The start address.
    pub fn start_address(&self) -> u64 {
        self.start_address
    }

    /// The end address (exclusive).
    pub fn end_address(&self) -> u64 {
        self.end_address
    }

    /// Block size in bytes.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Whether this block is big-endian.
    pub fn is_big_endian(&self) -> bool {
        self.big_endian
    }

    /// Set endianness.
    pub fn set_big_endian(&mut self, big_endian: bool) {
        self.big_endian = big_endian;
    }

    /// Whether this block is editable.
    pub fn is_editable(&self) -> bool {
        self.editable
    }

    /// Whether this block is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Whether this block contains the given address.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.start_address && address < self.end_address
    }

    /// Get the byte at the given offset within the block.
    pub fn get_byte(&self, offset: usize) -> Option<u8> {
        self.data.get(offset).copied()
    }

    /// Set the byte at the given offset.
    pub fn set_byte(&mut self, offset: usize, value: u8) -> bool {
        if offset < self.data.len() {
            self.data[offset] = value;
            true
        } else {
            false
        }
    }

    /// Get the bytes of this block.
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get a mutable reference to the bytes.
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get the 16-bit value at the given offset, respecting endianness.
    pub fn get_short(&self, offset: usize) -> Option<i16> {
        if offset + 2 > self.data.len() {
            return None;
        }
        let val = if self.big_endian {
            i16::from_be_bytes([self.data[offset], self.data[offset + 1]])
        } else {
            i16::from_le_bytes([self.data[offset], self.data[offset + 1]])
        };
        Some(val)
    }

    /// Get the 32-bit value at the given offset, respecting endianness.
    pub fn get_int(&self, offset: usize) -> Option<i32> {
        if offset + 4 > self.data.len() {
            return None;
        }
        let val = if self.big_endian {
            i32::from_be_bytes(self.data[offset..offset + 4].try_into().unwrap())
        } else {
            i32::from_le_bytes(self.data[offset..offset + 4].try_into().unwrap())
        };
        Some(val)
    }

    /// Get the 64-bit value at the given offset, respecting endianness.
    pub fn get_long(&self, offset: usize) -> Option<i64> {
        if offset + 8 > self.data.len() {
            return None;
        }
        let val = if self.big_endian {
            i64::from_be_bytes(self.data[offset..offset + 8].try_into().unwrap())
        } else {
            i64::from_le_bytes(self.data[offset..offset + 8].try_into().unwrap())
        };
        Some(val)
    }

    /// Set the 16-bit value at the given offset.
    pub fn set_short(&mut self, offset: usize, value: i16) -> bool {
        if offset + 2 > self.data.len() {
            return false;
        }
        let bytes = if self.big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        self.data[offset..offset + 2].copy_from_slice(&bytes);
        true
    }

    /// Set the 32-bit value at the given offset.
    pub fn set_int(&mut self, offset: usize, value: i32) -> bool {
        if offset + 4 > self.data.len() {
            return false;
        }
        let bytes = if self.big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        self.data[offset..offset + 4].copy_from_slice(&bytes);
        true
    }

    /// Set the 64-bit value at the given offset.
    pub fn set_long(&mut self, offset: usize, value: i64) -> bool {
        if offset + 8 > self.data.len() {
            return false;
        }
        let bytes = if self.big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        self.data[offset..offset + 8].copy_from_slice(&bytes);
        true
    }

    /// Natural alignment for the given radix.
    pub fn alignment(&self, radix: usize) -> usize {
        if radix == 0 {
            0
        } else {
            (self.start_address as usize) % radix
        }
    }

    /// Get the address for the given offset.
    pub fn address_at(&self, offset: u64) -> Option<u64> {
        let addr = self.start_address + offset;
        if addr < self.end_address {
            Some(addr)
        } else {
            None
        }
    }

    /// Get the offset for the given address.
    pub fn offset_of(&self, address: u64) -> Option<u64> {
        if self.contains(address) {
            Some(address - self.start_address)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// ProgramByteBlockSet
// ---------------------------------------------------------------------------

/// A block set backed by a program's memory.
///
/// Ported from Ghidra's `ProgramByteBlockSet`.
///
/// Manages a collection of [`MemoryByteBlock`]s, a [`ByteBlockChangeManager`]
/// for tracking edits, and program-aware address translation.
#[derive(Debug, Clone)]
pub struct ProgramByteBlockSet {
    /// The program name.
    program_name: String,
    /// The memory blocks.
    blocks: Vec<MemoryByteBlock>,
    /// The change manager.
    change_manager: ByteBlockChangeManager,
}

impl ProgramByteBlockSet {
    /// Create a new program byte block set.
    pub fn new(
        program_name: impl Into<String>,
        blocks: Vec<MemoryByteBlock>,
        change_manager: ByteBlockChangeManager,
    ) -> Self {
        Self {
            program_name: program_name.into(),
            blocks,
            change_manager,
        }
    }

    /// The program name.
    pub fn program_name(&self) -> &str {
        &self.program_name
    }

    /// Get all blocks.
    pub fn blocks(&self) -> &[MemoryByteBlock] {
        &self.blocks
    }

    /// Get all blocks (mutable).
    pub fn blocks_mut(&mut self) -> &mut Vec<MemoryByteBlock> {
        &mut self.blocks
    }

    /// Get the change manager.
    pub fn change_manager(&self) -> &ByteBlockChangeManager {
        &self.change_manager
    }

    /// Get a mutable reference to the change manager.
    pub fn change_manager_mut(&mut self) -> &mut ByteBlockChangeManager {
        &mut self.change_manager
    }

    /// Find the block containing the given address.
    pub fn block_at(&self, address: u64) -> Option<&MemoryByteBlock> {
        self.blocks.iter().find(|b| b.contains(address))
    }

    /// Find the block containing the given address (mutable).
    pub fn block_at_mut(&mut self, address: u64) -> Option<&mut MemoryByteBlock> {
        self.blocks.iter_mut().find(|b| b.contains(address))
    }

    /// Get the byte at the given address.
    pub fn byte_at(&self, address: u64) -> Option<u8> {
        let block = self.block_at(address)?;
        let offset = (address - block.start_address()) as usize;
        block.get_byte(offset)
    }

    /// Notify the change manager of a byte edit.
    pub fn notify_byte_editing(
        &mut self,
        block_index: usize,
        offset: BigInt,
        old_value: Vec<u8>,
        new_value: Vec<u8>,
    ) {
        if let Some(block) = self.blocks.get(block_index) {
            let edit = ByteEditInfo::new(block.start_address(), offset, old_value, new_value);
            self.change_manager.add(edit);
        }
    }

    /// Get the block number for the block starting at the given address.
    pub fn byte_block_number(&self, block_start_addr: u64) -> i32 {
        self.blocks
            .iter()
            .position(|b| b.start_address() == block_start_addr)
            .map(|i| i as i32)
            .unwrap_or(-1)
    }

    /// Number of blocks.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Convert an address to a (block_index, offset) pair.
    pub fn address_to_info(&self, address: u64) -> Option<(usize, u64)> {
        for (i, block) in self.blocks.iter().enumerate() {
            if block.contains(address) {
                return Some((i, address - block.start_address()));
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// FileByteBlock
// ---------------------------------------------------------------------------

/// A byte block backed by a raw file buffer.
///
/// Ported from Ghidra's `FileByteBlock`.
///
/// The block is not editable in the Ghidra sense (file-backed blocks are
/// read-only from the viewer's perspective).
#[derive(Debug, Clone)]
pub struct FileByteBlock {
    /// The raw bytes.
    data: Vec<u8>,
    /// Whether this block is big-endian.
    big_endian: bool,
}

impl FileByteBlock {
    /// Create a new file byte block from the given buffer.
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            big_endian: false, // default to little-endian for files
        }
    }

    /// Block size in bytes.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Whether this block is big-endian.
    pub fn is_big_endian(&self) -> bool {
        self.big_endian
    }

    /// Set endianness.
    pub fn set_big_endian(&mut self, big_endian: bool) {
        self.big_endian = big_endian;
    }

    /// Whether this block is editable (always false for file blocks).
    pub fn is_editable(&self) -> bool {
        false
    }

    /// Get the byte at the given offset.
    pub fn get_byte(&self, offset: usize) -> Option<u8> {
        self.data.get(offset).copied()
    }

    /// Get the 16-bit value at the given offset.
    pub fn get_short(&self, offset: usize) -> Option<i16> {
        if offset + 2 > self.data.len() {
            return None;
        }
        let val = if self.big_endian {
            i16::from_be_bytes([self.data[offset], self.data[offset + 1]])
        } else {
            i16::from_le_bytes([self.data[offset], self.data[offset + 1]])
        };
        Some(val)
    }

    /// Get the 32-bit value at the given offset.
    pub fn get_int(&self, offset: usize) -> Option<i32> {
        if offset + 4 > self.data.len() {
            return None;
        }
        let val = if self.big_endian {
            i32::from_be_bytes(self.data[offset..offset + 4].try_into().unwrap())
        } else {
            i32::from_le_bytes(self.data[offset..offset + 4].try_into().unwrap())
        };
        Some(val)
    }

    /// Get the 64-bit value at the given offset.
    pub fn get_long(&self, offset: usize) -> Option<i64> {
        if offset + 8 > self.data.len() {
            return None;
        }
        let val = if self.big_endian {
            i64::from_be_bytes(self.data[offset..offset + 8].try_into().unwrap())
        } else {
            i64::from_le_bytes(self.data[offset..offset + 8].try_into().unwrap())
        };
        Some(val)
    }

    /// Get the bytes of this block.
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    /// Natural alignment (always 0 for file blocks).
    pub fn alignment(&self, _radix: usize) -> usize {
        0
    }

    /// Get a location representation string for the given offset.
    pub fn location_representation(&self, offset: usize) -> Option<String> {
        if offset < self.data.len() {
            Some(format!("{:08}", offset))
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// FileByteBlockSet
// ---------------------------------------------------------------------------

/// A block set backed by a single file buffer.
///
/// Ported from Ghidra's `FileByteBlockSet`.
///
/// Manages a single [`FileByteBlock`] and tracks edits as a simple list of
/// changed byte offsets.
#[derive(Debug, Clone)]
pub struct FileByteBlockSet {
    /// The file byte block.
    block: FileByteBlock,
    /// List of edited byte offsets.
    edit_offsets: Vec<usize>,
}

impl FileByteBlockSet {
    /// Create a new file block set from the given data.
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            block: FileByteBlock::new(data),
            edit_offsets: Vec::new(),
        }
    }

    /// Create from a file byte block directly.
    pub fn from_block(block: FileByteBlock) -> Self {
        Self {
            block,
            edit_offsets: Vec::new(),
        }
    }

    /// Get the block.
    pub fn block(&self) -> &FileByteBlock {
        &self.block
    }

    /// Get the block (mutable).
    pub fn block_mut(&mut self) -> &mut FileByteBlock {
        &mut self.block
    }

    /// Whether the given offset range has been changed.
    pub fn is_changed(&self, offset: usize, length: usize) -> bool {
        for i in offset..offset + length {
            if self.edit_offsets.contains(&i) {
                return true;
            }
        }
        false
    }

    /// Notify of a byte edit at the given offsets.
    pub fn notify_byte_editing(&mut self, offset: usize, old_value: &[u8], new_value: &[u8]) {
        for i in 0..old_value.len() {
            if old_value[i] != new_value[i] {
                if !self.edit_offsets.contains(&(offset + i)) {
                    self.edit_offsets.push(offset + i);
                }
            }
        }
    }

    /// Save the block data to a byte vector.
    pub fn save(&mut self) -> Vec<u8> {
        let data = self.block.bytes().to_vec();
        self.edit_offsets.clear();
        data
    }

    /// Number of edited bytes.
    pub fn edit_count(&self) -> usize {
        self.edit_offsets.len()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn big(n: u64) -> BigInt {
        BigInt::from(n)
    }

    // ---- ByteViewerState tests ----

    #[test]
    fn test_viewer_state_create() {
        let info = ByteBlockInfo::new(0, big(42), 3);
        let state = ByteViewerState::from_info(&info, big(10), 5, Some(0x1000));
        assert_eq!(state.address(), Some(0x1000));
        assert_eq!(state.block_index(), 0);
        assert_eq!(*state.offset(), big(42));
        assert_eq!(state.column(), 3);
        assert_eq!(*state.scroll_index(), big(10));
        assert_eq!(state.y_offset(), 5);
    }

    #[test]
    fn test_viewer_state_display() {
        let state = ByteViewerState::new(Some(0x1000), 0, big(0), 0, big(0), 0);
        let s = format!("{}", state);
        assert!(s.contains("ByteViewerState"));
        assert!(s.contains("4096")); // 0x1000 = 4096 decimal
    }

    // ---- ByteViewerLocationMemento tests ----

    #[test]
    fn test_location_memento_create() {
        let memento = ByteViewerLocationMemento::new(
            Some("test.exe".into()),
            Some(0x1000),
            0,
            big(5),
            2,
            big(10),
            3,
        );
        assert_eq!(memento.program_name(), Some("test.exe"));
        assert_eq!(memento.block_num(), 0);
        assert_eq!(*memento.block_offset(), big(5));
        assert_eq!(memento.column(), 2);
    }

    #[test]
    fn test_location_memento_roundtrip() {
        let memento = ByteViewerLocationMemento::new(
            Some("test.exe".into()),
            None,
            3,
            big(100),
            1,
            big(50),
            7,
        );
        let state = memento.to_state();
        let restored = ByteViewerLocationMemento::from_state(&state).unwrap();
        assert_eq!(restored.program_name(), Some("test.exe"));
        assert_eq!(restored.block_num(), 3);
        assert_eq!(*restored.block_offset(), big(100));
        assert_eq!(*restored.scroll_index(), big(50));
        assert_eq!(restored.y_offset(), 7);
    }

    // ---- ByteViewerProgramLocation tests ----

    #[test]
    fn test_program_location_create() {
        let loc = ByteViewerProgramLocation::new(0x1000, 3);
        assert_eq!(loc.address(), 0x1000);
        assert_eq!(loc.character_offset(), 3);
    }

    // ---- IndexMap tests ----

    #[test]
    fn test_index_map_empty() {
        let map = IndexMap::new();
        assert_eq!(*map.num_indexes(), big(0));
        assert_eq!(map.bytes_per_line(), 16);
    }

    #[test]
    fn test_index_map_from_blocks() {
        // One block: 32 bytes, 16 bytes per line, alignment 0, offset 0
        // 32 bytes / 16 bytes per line = 2 lines, num_indexes = 1 (0-based)
        let map = IndexMap::from_blocks(&[(0, 32, 0)], 16, 0);
        assert!(*map.num_indexes() >= big(1));
    }

    #[test]
    fn test_index_map_multi_block() {
        // Two blocks: 16 and 32 bytes
        let map = IndexMap::from_blocks(&[(0, 16, 0), (1, 32, 0)], 16, 0);
        assert!(*map.num_indexes() > big(0));
    }

    #[test]
    fn test_index_map_get_block_info() {
        let map = IndexMap::from_blocks(&[(0, 32, 0)], 16, 0);
        let info = map.get_block_info(&big(0), 0);
        assert!(info.is_some());
        let (block_idx, offset) = info.unwrap();
        assert_eq!(block_idx, 0);
        assert_eq!(offset, big(0));

        let info = map.get_block_info(&big(0), 5);
        assert!(info.is_some());
        let (block_idx, offset) = info.unwrap();
        assert_eq!(block_idx, 0);
        assert_eq!(offset, big(5));
    }

    // ---- MemoryByteBlock tests ----

    #[test]
    fn test_memory_byte_block_create() {
        let block = MemoryByteBlock::new(".text", 0x1000, vec![0x90, 0xC3], true, true);
        assert_eq!(block.name(), ".text");
        assert_eq!(block.start_address(), 0x1000);
        assert_eq!(block.end_address(), 0x1002);
        assert!(block.contains(0x1000));
        assert!(!block.contains(0x1002));
        assert!(block.is_big_endian());
        assert!(block.is_editable());
        assert!(block.is_initialized());
    }

    #[test]
    fn test_memory_byte_block_read_write() {
        let mut block = MemoryByteBlock::new(".data", 0x2000, vec![0x00; 16], true, true);
        assert_eq!(block.get_byte(0), Some(0x00));
        assert!(block.set_byte(0, 0xFF));
        assert_eq!(block.get_byte(0), Some(0xFF));
    }

    #[test]
    fn test_memory_byte_block_short() {
        let block = MemoryByteBlock::new(".data", 0x2000, vec![0xCA, 0xFE], true, true);
        assert_eq!(block.get_short(0), Some(0xCAFE_u16 as i16));

        let block_le = MemoryByteBlock::new(".data", 0x2000, vec![0xFE, 0xCA], false, true);
        assert_eq!(block_le.get_short(0), Some(0xCAFE_u16 as i16));
    }

    #[test]
    fn test_memory_byte_block_alignment() {
        let block = MemoryByteBlock::new(".text", 0x1002, vec![0; 16], true, true);
        assert_eq!(block.alignment(4), 2);
        assert_eq!(block.alignment(2), 0);
    }

    #[test]
    fn test_memory_byte_block_address_conversion() {
        let block = MemoryByteBlock::new(".text", 0x1000, vec![0; 256], true, true);
        assert_eq!(block.address_at(5), Some(0x1005));
        assert_eq!(block.offset_of(0x1005), Some(5));
        assert!(block.address_at(256).is_none());
    }

    // ---- ProgramByteBlockSet tests ----

    #[test]
    fn test_program_block_set_create() {
        let blocks = vec![
            MemoryByteBlock::new(".text", 0x1000, vec![0; 16], true, true),
            MemoryByteBlock::new(".data", 0x2000, vec![0; 8], true, true),
        ];
        let bs = ProgramByteBlockSet::new("test.exe", blocks, ByteBlockChangeManager::new());
        assert_eq!(bs.program_name(), "test.exe");
        assert_eq!(bs.block_count(), 2);
    }

    #[test]
    fn test_program_block_set_byte_at() {
        let blocks = vec![
            MemoryByteBlock::new(".text", 0x1000, vec![0x90, 0xC3], true, true),
        ];
        let bs = ProgramByteBlockSet::new("test", blocks, ByteBlockChangeManager::new());
        assert_eq!(bs.byte_at(0x1000), Some(0x90));
        assert_eq!(bs.byte_at(0x1001), Some(0xC3));
        assert_eq!(bs.byte_at(0x2000), None);
    }

    #[test]
    fn test_program_block_set_address_to_info() {
        let blocks = vec![
            MemoryByteBlock::new(".text", 0x1000, vec![0; 16], true, true),
        ];
        let bs = ProgramByteBlockSet::new("test", blocks, ByteBlockChangeManager::new());
        assert_eq!(bs.address_to_info(0x1005), Some((0, 5)));
        assert!(bs.address_to_info(0x2000).is_none());
    }

    #[test]
    fn test_program_block_set_block_number() {
        let blocks = vec![
            MemoryByteBlock::new(".text", 0x1000, vec![0; 16], true, true),
            MemoryByteBlock::new(".data", 0x2000, vec![0; 8], true, true),
        ];
        let bs = ProgramByteBlockSet::new("test", blocks, ByteBlockChangeManager::new());
        assert_eq!(bs.byte_block_number(0x1000), 0);
        assert_eq!(bs.byte_block_number(0x2000), 1);
        assert_eq!(bs.byte_block_number(0x3000), -1);
    }

    // ---- FileByteBlock tests ----

    #[test]
    fn test_file_byte_block_create() {
        let block = FileByteBlock::new(vec![0xCA, 0xFE, 0xBA, 0xBE]);
        assert_eq!(block.size(), 4);
        assert!(!block.is_editable());
        assert!(!block.is_big_endian());
    }

    #[test]
    fn test_file_byte_block_read() {
        let block = FileByteBlock::new(vec![0xCA, 0xFE, 0xBA, 0xBE]);
        assert_eq!(block.get_byte(0), Some(0xCA));
        assert_eq!(block.get_byte(3), Some(0xBE));
        assert_eq!(block.get_byte(4), None);
    }

    #[test]
    fn test_file_byte_block_short_le() {
        let block = FileByteBlock::new(vec![0xFE, 0xCA]);
        assert_eq!(block.get_short(0), Some(0xCAFE_u16 as i16));
    }

    #[test]
    fn test_file_byte_block_int_le() {
        let block = FileByteBlock::new(vec![0xEF, 0xBE, 0xAD, 0xDE]);
        assert_eq!(block.get_int(0), Some(0xDEADBEEFu32 as i32));
    }

    #[test]
    fn test_file_byte_block_location() {
        let block = FileByteBlock::new(vec![0; 100]);
        assert_eq!(block.location_representation(0), Some("00000000".into()));
        assert_eq!(block.location_representation(99), Some("00000099".into()));
        assert!(block.location_representation(100).is_none());
    }

    // ---- FileByteBlockSet tests ----

    #[test]
    fn test_file_block_set_create() {
        let bs = FileByteBlockSet::new(vec![0x00, 0x01, 0x02]);
        assert_eq!(bs.block().size(), 3);
        assert!(!bs.is_changed(0, 3));
    }

    #[test]
    fn test_file_block_set_edit() {
        let mut bs = FileByteBlockSet::new(vec![0x00, 0x01, 0x02]);
        bs.notify_byte_editing(0, &[0x00], &[0xFF]);
        assert!(bs.is_changed(0, 1));
        assert!(!bs.is_changed(1, 1));
        assert_eq!(bs.edit_count(), 1);
    }

    #[test]
    fn test_file_block_set_save() {
        let mut bs = FileByteBlockSet::new(vec![0x00, 0x01, 0x02]);
        bs.notify_byte_editing(1, &[0x01], &[0xFF]);
        let data = bs.save();
        assert_eq!(data, vec![0x00, 0x01, 0x02]); // save returns original data
        assert_eq!(bs.edit_count(), 0);
    }
}
