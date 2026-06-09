//! Byte viewer module.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.byteviewer` and
//! `ghidra.app.plugin.core.format` Java packages.
//!
//! Provides a model for displaying raw memory bytes in various formats
//! (hex, octal, decimal, binary, character) with support for byte blocks,
//! format selection, field rendering, change tracking, and configuration.
//!
//! # Key types
//!
//! - [`ByteBlock`] -- a contiguous region of bytes with an address range
//! - [`ByteBlockSet`] -- a collection of byte blocks representing a program's memory
//! - [`FormatModel`] -- defines how bytes are formatted for display
//! - [`ByteField`] -- a single field within a byte display row
//! - [`ByteBlockRange`] -- a range within a byte block
//! - [`ByteBlockSelection`] -- a selection of disjoint byte block ranges
//! - [`ByteBlockInfo`] -- block + offset + column tuple
//! - [`IndexedByteBlockInfo`] -- sortable block info with line index
//! - [`ByteEditInfo`] -- records a byte edit (old/new values)
//! - [`ByteBlockChangeManager`] -- tracks changes across byte blocks
//! - [`ByteViewerConfigOptions`] -- user-configurable viewer settings
//! - [`FieldFactory`] -- generates display fields from format models
//!
//! # Sub-modules
//!
//! - [`format`] -- the [`DataFormatModel`](format::DataFormatModel) trait hierarchy
//!   and all concrete format model implementations

pub mod byte_viewer_component;
pub mod byte_viewer_layout_model;
pub mod byte_viewer_plugin;
pub mod format;

use num_bigint::BigInt;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// ByteBlock (high-level, owned-memory block)
// ---------------------------------------------------------------------------

/// A contiguous block of bytes in a program's memory space.
///
/// Ported from Ghidra's `ByteBlock` Java class (the concrete
/// memory-backed implementation rather than the trait).
///
/// Each block has a name, start address, and a byte buffer. It models
/// a single memory region (e.g. `.text`, `.data`, stack, etc.).
#[derive(Debug, Clone)]
pub struct ByteBlock {
    /// The name of this block (e.g. ".text", "EXTERNAL").
    name: String,
    /// The start address of this block.
    start_address: u64,
    /// The raw bytes in this block.
    data: Vec<u8>,
    /// Whether this block is initialized (has actual bytes).
    initialized: bool,
    /// Whether this block is readable.
    readable: bool,
    /// Whether this block is writable.
    writable: bool,
    /// Whether this block is executable.
    executable: bool,
    /// Endianness.
    big_endian: bool,
    /// Edit history (offset -> (old, new)).
    edits: BTreeMap<usize, (u8, u8)>,
}

impl ByteBlock {
    /// Create a new initialized byte block.
    pub fn new(name: impl Into<String>, start_address: u64, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            start_address,
            data,
            initialized: true,
            readable: true,
            writable: false,
            executable: false,
            big_endian: true,
            edits: BTreeMap::new(),
        }
    }

    /// Create a new uninitialized byte block (e.g. for gaps).
    pub fn uninitialized(name: impl Into<String>, start_address: u64, size: usize) -> Self {
        Self {
            name: name.into(),
            start_address,
            data: vec![0; size],
            initialized: false,
            readable: true,
            writable: true,
            executable: false,
            big_endian: true,
            edits: BTreeMap::new(),
        }
    }

    /// Create an executable code block.
    pub fn code_block(name: impl Into<String>, start_address: u64, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            start_address,
            data,
            initialized: true,
            readable: true,
            writable: false,
            executable: true,
            big_endian: true,
            edits: BTreeMap::new(),
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
        self.start_address + self.data.len() as u64
    }

    /// The size of this block in bytes.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Whether this block is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Whether this block is readable.
    pub fn is_readable(&self) -> bool {
        self.readable
    }

    /// Whether this block is writable.
    pub fn is_writable(&self) -> bool {
        self.writable
    }

    /// Whether this block is executable.
    pub fn is_executable(&self) -> bool {
        self.executable
    }

    /// Whether this block is big-endian.
    pub fn is_big_endian(&self) -> bool {
        self.big_endian
    }

    /// Set endianness.
    pub fn set_big_endian(&mut self, big_endian: bool) {
        self.big_endian = big_endian;
    }

    /// Get the byte at a given offset within this block.
    pub fn byte_at(&self, offset: usize) -> Option<u8> {
        self.data.get(offset).copied()
    }

    /// Get the byte at a given absolute address.
    pub fn byte_at_address(&self, address: u64) -> Option<u8> {
        if address >= self.start_address && address < self.end_address() {
            let offset = (address - self.start_address) as usize;
            self.data.get(offset).copied()
        } else {
            None
        }
    }

    /// Get a slice of bytes from the block.
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get a mutable slice of bytes from the block.
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Check if this block contains the given address.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.start_address && address < self.end_address()
    }

    /// Set permissions.
    pub fn set_permissions(&mut self, readable: bool, writable: bool, executable: bool) {
        self.readable = readable;
        self.writable = writable;
        self.executable = executable;
    }

    /// Set the byte at `offset`, recording the change.
    pub fn set_byte_at(&mut self, offset: usize, value: u8) -> bool {
        if offset >= self.data.len() {
            return false;
        }
        let old = self.data[offset];
        if old != value {
            self.edits.entry(offset).or_insert((old, value));
            // Update the "new" value if overwritten again
            if let Some(entry) = self.edits.get_mut(&offset) {
                entry.1 = value;
            }
            self.data[offset] = value;
        }
        true
    }

    /// Whether the byte at `offset` has been changed from its original value.
    pub fn is_changed(&self, offset: usize) -> bool {
        self.edits.contains_key(&offset)
    }

    /// Whether any byte in the range `[offset, offset+count)` has been changed.
    pub fn is_range_changed(&self, offset: usize, count: usize) -> bool {
        for i in offset..offset + count {
            if self.edits.contains_key(&i) {
                return true;
            }
        }
        false
    }

    /// Get all edits recorded on this block.
    pub fn edits(&self) -> &BTreeMap<usize, (u8, u8)> {
        &self.edits
    }

    /// Get the alignment offset for a given radix.
    pub fn alignment(&self, radix: usize) -> usize {
        if radix == 0 {
            0
        } else {
            (self.start_address as usize) % radix
        }
    }
}

// ---------------------------------------------------------------------------
// ByteBlockSet
// ---------------------------------------------------------------------------

/// A collection of byte blocks representing a program's memory layout.
///
/// Ported from Ghidra's `ByteBlockSet` Java interface.
#[derive(Debug, Clone)]
pub struct ByteBlockSet {
    /// The name of this block set (typically the program name).
    name: String,
    blocks: Vec<ByteBlock>,
}

impl ByteBlockSet {
    /// Create a new empty block set.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            blocks: Vec::new(),
        }
    }

    /// Add a byte block.
    pub fn add_block(&mut self, block: ByteBlock) {
        self.blocks.push(block);
    }

    /// Get all blocks.
    pub fn blocks(&self) -> &[ByteBlock] {
        &self.blocks
    }

    /// Get all blocks (mutable).
    pub fn blocks_mut(&mut self) -> &mut Vec<ByteBlock> {
        &mut self.blocks
    }

    /// Find the block containing the given address.
    pub fn block_at(&self, address: u64) -> Option<&ByteBlock> {
        self.blocks.iter().find(|b| b.contains(address))
    }

    /// Find the block containing the given address (mutable).
    pub fn block_at_mut(&mut self, address: u64) -> Option<&mut ByteBlock> {
        self.blocks.iter_mut().find(|b| b.contains(address))
    }

    /// Get the byte at a given address.
    pub fn byte_at(&self, address: u64) -> Option<u8> {
        self.block_at(address)?.byte_at_address(address)
    }

    /// The total size of all blocks combined.
    pub fn total_size(&self) -> usize {
        self.blocks.iter().map(|b| b.size()).sum()
    }

    /// The name of this block set.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Number of blocks.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Get the start address of a block by index.
    pub fn block_start(&self, index: usize) -> Option<u64> {
        self.blocks.get(index).map(|b| b.start_address())
    }

    /// Get the block number that starts at the given address.
    /// Returns -1 if not found.
    pub fn byte_block_number(&self, address: u64) -> i32 {
        self.blocks
            .iter()
            .position(|b| b.start_address() == address)
            .map(|i| i as i32)
            .unwrap_or(-1)
    }
}

// ---------------------------------------------------------------------------
// ByteBlockRange
// ---------------------------------------------------------------------------

/// A range within a byte block (start index and inclusive end index).
///
/// Ported from Ghidra's `ByteBlockRange`.
#[derive(Debug, Clone)]
pub struct ByteBlockRange {
    /// The block index within the block set.
    block_index: usize,
    /// Start byte index within the block.
    start_index: BigInt,
    /// End byte index (inclusive) within the block.
    end_index: BigInt,
}

impl ByteBlockRange {
    /// Create a new byte block range.
    pub fn new(block_index: usize, start_index: BigInt, end_index: BigInt) -> Self {
        Self {
            block_index,
            start_index,
            end_index,
        }
    }

    /// The block index.
    pub fn block_index(&self) -> usize {
        self.block_index
    }

    /// Start index within the block.
    pub fn start_index(&self) -> &BigInt {
        &self.start_index
    }

    /// End index (inclusive) within the block.
    pub fn end_index(&self) -> &BigInt {
        &self.end_index
    }

    /// Number of bytes in this range.
    pub fn length(&self) -> BigInt {
        &self.end_index - &self.start_index + BigInt::from(1)
    }
}

impl PartialEq for ByteBlockRange {
    fn eq(&self, other: &Self) -> bool {
        self.block_index == other.block_index
            && self.start_index == other.start_index
            && self.end_index == other.end_index
    }
}

impl Eq for ByteBlockRange {}

impl std::fmt::Display for ByteBlockRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Block {}, start={}, end={}",
            self.block_index, self.start_index, self.end_index
        )
    }
}

// ---------------------------------------------------------------------------
// ByteBlockSelection
// ---------------------------------------------------------------------------

/// A selection of disjoint byte block ranges.
///
/// Ported from Ghidra's `ByteBlockSelection`.
#[derive(Debug, Clone, Default)]
pub struct ByteBlockSelection {
    ranges: Vec<ByteBlockRange>,
}

impl ByteBlockSelection {
    /// Create an empty selection.
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Create a selection from a list of ranges.
    pub fn from_ranges(ranges: Vec<ByteBlockRange>) -> Self {
        Self { ranges }
    }

    /// Add a range to the selection.
    pub fn add(&mut self, range: ByteBlockRange) {
        self.ranges.push(range);
    }

    /// Get the number of ranges in this selection.
    pub fn number_of_ranges(&self) -> usize {
        self.ranges.len()
    }

    /// Get the range at the given index.
    pub fn range(&self, index: usize) -> Option<&ByteBlockRange> {
        self.ranges.get(index)
    }

    /// Get all ranges.
    pub fn ranges(&self) -> &[ByteBlockRange] {
        &self.ranges
    }

    /// Whether this selection is empty.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}

// ---------------------------------------------------------------------------
// ByteBlockInfo
// ---------------------------------------------------------------------------

/// A tuple of (block_index, offset, column) identifying a position within
/// a byte block set.
///
/// Ported from Ghidra's `ByteBlockInfo`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ByteBlockInfo {
    block_index: usize,
    offset: BigInt,
    column: usize,
}

impl ByteBlockInfo {
    /// Create a new byte block info.
    pub fn new(block_index: usize, offset: BigInt, column: usize) -> Self {
        Self {
            block_index,
            offset,
            column,
        }
    }

    /// Create with column 0.
    pub fn at(block_index: usize, offset: BigInt) -> Self {
        Self::new(block_index, offset, 0)
    }

    /// The block index.
    pub fn block_index(&self) -> usize {
        self.block_index
    }

    /// The offset into the block.
    pub fn offset(&self) -> &BigInt {
        &self.offset
    }

    /// The column within the UI field.
    pub fn column(&self) -> usize {
        self.column
    }
}

impl std::fmt::Display for ByteBlockInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ByteBlockInfo: block={}, offset={}, column={}",
            self.block_index, self.offset, self.column
        )
    }
}

// ---------------------------------------------------------------------------
// IndexedByteBlockInfo
// ---------------------------------------------------------------------------

/// A [`ByteBlockInfo`] extended with a line index so it can be ordered.
///
/// Ported from Ghidra's `IndexedByteBlockInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedByteBlockInfo {
    line_index: BigInt,
    info: ByteBlockInfo,
}

impl IndexedByteBlockInfo {
    /// Create a new indexed byte block info.
    pub fn new(
        line_index: BigInt,
        block_index: usize,
        offset: BigInt,
        column: usize,
    ) -> Self {
        Self {
            line_index,
            info: ByteBlockInfo::new(block_index, offset, column),
        }
    }

    /// The line index.
    pub fn line_index(&self) -> &BigInt {
        &self.line_index
    }

    /// The underlying block info.
    pub fn info(&self) -> &ByteBlockInfo {
        &self.info
    }
}

impl PartialOrd for IndexedByteBlockInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for IndexedByteBlockInfo {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.line_index
            .cmp(&other.line_index)
            .then_with(|| self.info.offset.cmp(&other.info.offset))
            .then_with(|| self.info.column.cmp(&other.info.column))
    }
}

// ---------------------------------------------------------------------------
// ByteEditInfo
// ---------------------------------------------------------------------------

/// Records a byte edit: which block address, what offset, and the
/// old / new byte values.
///
/// Ported from Ghidra's `ByteEditInfo`.
#[derive(Debug, Clone)]
pub struct ByteEditInfo {
    block_start_address: u64,
    offset: BigInt,
    old_value: Vec<u8>,
    new_value: Vec<u8>,
}

impl ByteEditInfo {
    /// Create a new byte edit info.
    pub fn new(
        block_start_address: u64,
        offset: BigInt,
        old_value: Vec<u8>,
        new_value: Vec<u8>,
    ) -> Self {
        Self {
            block_start_address,
            offset,
            old_value,
            new_value,
        }
    }

    /// Block start address.
    pub fn block_address(&self) -> u64 {
        self.block_start_address
    }

    /// Offset into the block.
    pub fn offset(&self) -> &BigInt {
        &self.offset
    }

    /// Old byte values.
    pub fn old_value(&self) -> &[u8] {
        &self.old_value
    }

    /// New byte values.
    pub fn new_value(&self) -> &[u8] {
        &self.new_value
    }
}

// ---------------------------------------------------------------------------
// ByteBlockChangeManager
// ---------------------------------------------------------------------------

/// Tracks byte-level changes across byte blocks for undo/redo and
/// rendering purposes.
///
/// Ported from Ghidra's `ByteBlockChangeManager`.
#[derive(Debug, Clone, Default)]
pub struct ByteBlockChangeManager {
    changes: Vec<ByteEditInfo>,
}

impl ByteBlockChangeManager {
    /// Create a new empty change manager.
    pub fn new() -> Self {
        Self {
            changes: Vec::new(),
        }
    }

    /// Create from an existing change manager (clone its changes).
    pub fn from_existing(other: &ByteBlockChangeManager) -> Self {
        Self {
            changes: other.changes.clone(),
        }
    }

    /// Record an edit.
    pub fn add(&mut self, edit: ByteEditInfo) {
        // Record per-byte changes
        for i in 0..edit.old_value.len() {
            if edit.old_value[i] != edit.new_value[i] {
                let single_edit = ByteEditInfo::new(
                    edit.block_start_address,
                    &edit.offset + i,
                    vec![edit.old_value[i]],
                    vec![edit.new_value[i]],
                );
                self.changes.push(single_edit);
            }
        }
    }

    /// Check whether any byte in the range has been changed.
    pub fn is_changed(&self, block_address: u64, offset: &BigInt, unit_byte_size: usize) -> bool {
        for i in 0..unit_byte_size {
            let test_offset = offset + i;
            if self.contains(block_address, &test_offset) {
                return true;
            }
        }
        false
    }

    /// Get all recorded changes.
    pub fn changes(&self) -> &[ByteEditInfo] {
        &self.changes
    }

    /// Clear all changes.
    pub fn clear(&mut self) {
        self.changes.clear();
    }

    /// Number of tracked changes.
    pub fn len(&self) -> usize {
        self.changes.len()
    }

    /// Whether the change list is empty.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    fn contains(&self, block_address: u64, offset: &BigInt) -> bool {
        self.changes.iter().any(|edit| {
            edit.block_start_address == block_address && edit.offset == *offset
        })
    }
}

// ---------------------------------------------------------------------------
// ByteViewerConfigOptions
// ---------------------------------------------------------------------------

/// Configuration values for the byte viewer.
///
/// Ported from Ghidra's `ByteViewerConfigOptions`.
#[derive(Debug, Clone)]
pub struct ByteViewerConfigOptions {
    bytes_per_line: usize,
    offset: usize,
    compact_chars: bool,
    use_char_alignment: bool,
    hex_group_size: usize,
    charset_name: String,
}

impl ByteViewerConfigOptions {
    /// Default bytes per line.
    pub const DEFAULT_BYTES_PER_LINE: usize = 16;

    /// Create with default values.
    pub fn new() -> Self {
        Self {
            bytes_per_line: Self::DEFAULT_BYTES_PER_LINE,
            offset: 0,
            compact_chars: true,
            use_char_alignment: true,
            hex_group_size: 1,
            charset_name: "US-ASCII".to_string(),
        }
    }

    /// Bytes per display line.
    pub fn bytes_per_line(&self) -> usize {
        self.bytes_per_line
    }

    /// Set bytes per display line, clamping dependent fields.
    pub fn set_bytes_per_line(&mut self, value: usize) {
        self.bytes_per_line = value;
        self.offset = self.offset.min(self.bytes_per_line.saturating_sub(1));
        self.hex_group_size = self.hex_group_size.clamp(1, self.bytes_per_line);
    }

    /// Column offset for display alignment.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Set the display offset, normalizing to `[0, bytes_per_line)`.
    pub fn set_offset(&mut self, new_offset: usize) {
        self.offset = self.calc_normalized_offset(new_offset as isize);
    }

    /// Calculate the normalized offset from a (possibly negative) value.
    pub fn calc_normalized_offset(&self, new_offset: isize) -> usize {
        if new_offset < 0 {
            self.bytes_per_line - 1
        } else if new_offset as usize >= self.bytes_per_line {
            (new_offset as usize) % self.bytes_per_line
        } else {
            new_offset as usize
        }
    }

    /// Hex group size (bytes per hex unit).
    pub fn hex_group_size(&self) -> usize {
        self.hex_group_size
    }

    /// Set hex group size.
    pub fn set_hex_group_size(&mut self, value: usize) {
        self.hex_group_size = value;
    }

    /// Charset name.
    pub fn charset_name(&self) -> &str {
        &self.charset_name
    }

    /// Set charset name.
    pub fn set_charset_name(&mut self, name: impl Into<String>) {
        self.charset_name = name.into();
    }

    /// Whether to use compact character width.
    pub fn is_compact_chars(&self) -> bool {
        self.compact_chars
    }

    /// Set compact chars.
    pub fn set_compact_chars(&mut self, value: bool) {
        self.compact_chars = value;
    }

    /// Whether to use character alignment.
    pub fn is_use_char_alignment(&self) -> bool {
        self.use_char_alignment
    }

    /// Set use char alignment.
    pub fn set_use_char_alignment(&mut self, value: bool) {
        self.use_char_alignment = value;
    }

    /// Check if two configs have equal options.
    pub fn are_options_equal(&self, other: &Self) -> bool {
        self.bytes_per_line == other.bytes_per_line
            && self.compact_chars == other.compact_chars
            && self.charset_name == other.charset_name
            && self.hex_group_size == other.hex_group_size
            && self.offset == other.offset
            && self.use_char_alignment == other.use_char_alignment
    }

    /// Check if layout-affecting params changed.
    pub fn are_layout_params_changed(&self, other: &Self) -> bool {
        self.offset != other.offset
            || self.hex_group_size != other.hex_group_size
            || self.bytes_per_line != other.bytes_per_line
            || self.use_char_alignment != other.use_char_alignment
    }

    /// Check if display-width-affecting params changed.
    pub fn are_display_widths_changed(&self, other: &Self) -> bool {
        self.hex_group_size != other.hex_group_size
            || self.compact_chars != other.compact_chars
    }
}

impl Default for ByteViewerConfigOptions {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FieldFactory
// ---------------------------------------------------------------------------

/// Generates display fields from a format model.
///
/// Ported from Ghidra's `FieldFactory`.  Each instance renders one
/// column of formatted bytes within a byte viewer row.
#[derive(Debug, Clone)]
pub struct FieldFactory {
    /// The format model this factory uses.
    format_name: String,
    /// Character width in display units (e.g. pixels in GUI context).
    char_width: usize,
    /// The unit byte size from the format model.
    unit_byte_size: usize,
    /// The data unit symbol size from the format model.
    symbol_size: usize,
    /// Starting x position for rendering.
    start_x: usize,
    /// Number of bytes per line.
    bytes_per_line: usize,
    /// Field offset.
    field_offset: usize,
}

impl FieldFactory {
    /// Create a new field factory.
    pub fn new(
        format_name: impl Into<String>,
        char_width: usize,
        unit_byte_size: usize,
        symbol_size: usize,
        bytes_per_line: usize,
        field_offset: usize,
    ) -> Self {
        Self {
            format_name: format_name.into(),
            char_width,
            unit_byte_size,
            symbol_size,
            start_x: 0,
            bytes_per_line,
            field_offset,
        }
    }

    /// Set the starting x position.
    pub fn set_start_x(&mut self, x: usize) {
        self.start_x = x;
    }

    /// Get the starting x position.
    pub fn start_x(&self) -> usize {
        self.start_x
    }

    /// Get the field width in display units.
    pub fn field_width(&self) -> usize {
        self.char_width * self.symbol_size
    }

    /// Number of fields per line.
    pub fn fields_per_line(&self) -> usize {
        if self.unit_byte_size == 0 {
            0
        } else {
            self.bytes_per_line / self.unit_byte_size
        }
    }

    /// The format name.
    pub fn format_name(&self) -> &str {
        &self.format_name
    }

    /// The unit byte size.
    pub fn unit_byte_size(&self) -> usize {
        self.unit_byte_size
    }

    /// The data unit symbol size.
    pub fn symbol_size(&self) -> usize {
        self.symbol_size
    }

    /// Render a row of bytes using the given format model and byte data.
    ///
    /// Returns a vector of formatted strings, one per unit in the row.
    pub fn render_row(
        &self,
        model: &format::DataFormat,
        block: &dyn format::ByteBlock,
        start_index: &BigInt,
        num_units: usize,
    ) -> Vec<String> {
        let mut result = Vec::with_capacity(num_units);
        for i in 0..num_units {
            let index = start_index + (i * self.unit_byte_size);
            match model.get_data_representation(block, &index) {
                Ok(s) => result.push(s),
                Err(_) => result.push("??".repeat(self.unit_byte_size.max(1))),
            }
        }
        result
    }
}

// ---------------------------------------------------------------------------
// FormatModel (legacy high-level convenience struct)
// ---------------------------------------------------------------------------

/// The display format for bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ByteFormat {
    /// Hexadecimal (e.g. "FF", "0A").
    Hex,
    /// Octal (e.g. "377", "012").
    Octal,
    /// Decimal (e.g. "255", "10").
    Decimal,
    /// Binary (e.g. "11111111", "00001010").
    Binary,
}

impl ByteFormat {
    /// Format a single byte in this format.
    pub fn format_byte(&self, byte: u8) -> String {
        match self {
            Self::Hex => format!("{:02X}", byte),
            Self::Octal => format!("{:03o}", byte),
            Self::Decimal => format!("{:3}", byte),
            Self::Binary => format!("{:08b}", byte),
        }
    }

    /// The width (in characters) of a single formatted byte.
    pub fn field_width(&self) -> usize {
        match self {
            Self::Hex => 2,
            Self::Octal => 3,
            Self::Decimal => 3,
            Self::Binary => 8,
        }
    }
}

impl Default for ByteFormat {
    fn default() -> Self {
        Self::Hex
    }
}

/// A model that controls how bytes are displayed in the byte viewer.
///
/// Defines the format (hex, octal, etc.), the number of bytes per row,
/// and grouping.
#[derive(Debug, Clone)]
pub struct FormatModel {
    /// The byte display format.
    pub format: ByteFormat,
    /// Number of bytes per row (typically 16).
    pub bytes_per_row: usize,
    /// Number of bytes per group (typically 1 or 2 for hex).
    pub bytes_per_group: usize,
    /// Whether to show an ASCII sidebar.
    pub show_ascii: bool,
    /// Whether to show addresses.
    pub show_address: bool,
}

impl FormatModel {
    /// Create a new format model with typical hex defaults (16 bytes/row, 1 byte/group).
    pub fn hex() -> Self {
        Self {
            format: ByteFormat::Hex,
            bytes_per_row: 16,
            bytes_per_group: 1,
            show_ascii: true,
            show_address: true,
        }
    }

    /// Create a binary format model (8 bytes/row).
    pub fn binary() -> Self {
        Self {
            format: ByteFormat::Binary,
            bytes_per_row: 8,
            bytes_per_group: 1,
            show_ascii: false,
            show_address: true,
        }
    }

    /// Format a row of bytes according to this model.
    pub fn format_row(&self, address: u64, bytes: &[u8]) -> String {
        let mut line = String::new();

        if self.show_address {
            line.push_str(&format!("{:08X}  ", address));
        }

        let width = self.format.field_width();
        for (i, &byte) in bytes.iter().enumerate() {
            if i > 0 && i % self.bytes_per_group == 0 {
                line.push(' ');
            }
            line.push_str(&self.format.format_byte(byte));
        }

        // Pad to fixed width
        let max_fields = self.bytes_per_row;
        let padded_width = max_fields * (width + 1);
        if bytes.len() < max_fields {
            let current = line.len() - if self.show_address { 10 } else { 0 };
            for _ in current..padded_width {
                line.push(' ');
            }
        }

        if self.show_ascii {
            line.push_str("  |");
            for &byte in bytes {
                if byte.is_ascii_graphic() || byte == b' ' {
                    line.push(byte as char);
                } else {
                    line.push('.');
                }
            }
            line.push('|');
        }

        line
    }

    /// Format a full block of bytes into lines.
    pub fn format_block(&self, start_address: u64, data: &[u8]) -> String {
        let mut output = String::new();
        for (i, chunk) in data.chunks(self.bytes_per_row).enumerate() {
            let addr = start_address + (i * self.bytes_per_row) as u64;
            output.push_str(&self.format_row(addr, chunk));
            output.push('\n');
        }
        output
    }
}

impl Default for FormatModel {
    fn default() -> Self {
        Self::hex()
    }
}

// ---------------------------------------------------------------------------
// ByteField
// ---------------------------------------------------------------------------

/// A single field in a byte display row.
///
/// Represents one rendered byte value at a specific position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteField {
    /// The absolute address of this byte.
    pub address: u64,
    /// The byte value.
    pub value: u8,
    /// The formatted string representation.
    pub text: String,
    /// The column index in the row.
    pub column: usize,
    /// Whether this byte is selected.
    pub selected: bool,
}

impl ByteField {
    /// Create a new byte field.
    pub fn new(address: u64, value: u8, format: ByteFormat, column: usize) -> Self {
        Self {
            address,
            value,
            text: format.format_byte(value),
            column,
            selected: false,
        }
    }
}

// ---------------------------------------------------------------------------
// AddressFormat
// ---------------------------------------------------------------------------

/// How addresses are displayed in the byte viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFormat {
    /// 32-bit hex (8 digits).
    Hex32,
    /// 64-bit hex (16 digits).
    Hex64,
    /// Decimal.
    Decimal,
    /// Segmented (segment:offset).
    Segmented,
}

impl AddressFormat {
    /// Format an address.
    pub fn format(&self, address: u64) -> String {
        match self {
            Self::Hex32 => format!("{:08X}", address as u32),
            Self::Hex64 => format!("{:016X}", address),
            Self::Decimal => format!("{}", address),
            Self::Segmented => {
                let seg = (address >> 16) & 0xFFFF;
                let off = address & 0xFFFF;
                format!("{:04X}:{:04X}", seg, off)
            }
        }
    }
}

impl Default for AddressFormat {
    fn default() -> Self {
        Self::Hex64
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;

    fn big(n: u64) -> BigInt {
        BigInt::from(n)
    }

    // ---- ByteBlock tests ----

    #[test]
    fn test_byte_block_basic() {
        let block = ByteBlock::new(".text", 0x1000, vec![0x90, 0xC3, 0xCC]);
        assert_eq!(block.name(), ".text");
        assert_eq!(block.start_address(), 0x1000);
        assert_eq!(block.end_address(), 0x1003);
        assert_eq!(block.size(), 3);
        assert!(block.is_initialized());
        assert!(block.contains(0x1000));
        assert!(block.contains(0x1002));
        assert!(!block.contains(0x1003));
    }

    #[test]
    fn test_byte_block_at_address() {
        let block = ByteBlock::new(".text", 0x1000, vec![0xCA, 0xFE]);
        assert_eq!(block.byte_at_address(0x1000), Some(0xCA));
        assert_eq!(block.byte_at_address(0x1001), Some(0xFE));
        assert_eq!(block.byte_at_address(0x1002), None);
    }

    #[test]
    fn test_byte_block_uninitialized() {
        let block = ByteBlock::uninitialized("stack", 0x7FFF0000, 0x10000);
        assert!(!block.is_initialized());
        assert_eq!(block.size(), 0x10000);
    }

    #[test]
    fn test_byte_block_edit() {
        let mut block = ByteBlock::new(".text", 0x1000, vec![0x90, 0xC3]);
        assert!(block.set_byte_at(0, 0xCC));
        assert_eq!(block.byte_at(0), Some(0xCC));
        assert!(block.is_changed(0));
        assert!(!block.is_changed(1));
        assert!(block.is_range_changed(0, 2));
    }

    #[test]
    fn test_byte_block_endian() {
        let mut block = ByteBlock::new(".text", 0x1000, vec![0x00]);
        assert!(block.is_big_endian()); // default
        block.set_big_endian(false);
        assert!(!block.is_big_endian());
    }

    #[test]
    fn test_byte_block_alignment() {
        let block = ByteBlock::new(".text", 0x1002, vec![0; 16]);
        assert_eq!(block.alignment(4), 2);
        assert_eq!(block.alignment(2), 0);
        assert_eq!(block.alignment(1), 0);
    }

    // ---- ByteBlockSet tests ----

    #[test]
    fn test_byte_block_set() {
        let mut set = ByteBlockSet::new("test.exe");
        set.add_block(ByteBlock::new(".text", 0x1000, vec![0x90, 0xC3]));
        set.add_block(ByteBlock::new(".data", 0x2000, vec![0x01, 0x02]));

        assert_eq!(set.block_count(), 2);
        assert_eq!(set.total_size(), 4);
        assert_eq!(set.byte_at(0x1000), Some(0x90));
        assert_eq!(set.byte_at(0x2000), Some(0x01));
        assert_eq!(set.byte_at(0x3000), None);
    }

    #[test]
    fn test_block_set_block_at() {
        let mut set = ByteBlockSet::new("test");
        set.add_block(ByteBlock::new(".text", 0x1000, vec![0x90; 16]));
        set.add_block(ByteBlock::new(".data", 0x2000, vec![0x00; 8]));

        let block = set.block_at(0x1005).unwrap();
        assert_eq!(block.name(), ".text");

        assert!(set.block_at(0x1500).is_none());
    }

    #[test]
    fn test_byte_block_number() {
        let mut set = ByteBlockSet::new("test");
        set.add_block(ByteBlock::new(".text", 0x1000, vec![0x90]));
        set.add_block(ByteBlock::new(".data", 0x2000, vec![0x00]));
        assert_eq!(set.byte_block_number(0x1000), 0);
        assert_eq!(set.byte_block_number(0x2000), 1);
        assert_eq!(set.byte_block_number(0x3000), -1);
    }

    // ---- ByteBlockRange tests ----

    #[test]
    fn test_byte_block_range() {
        let range = ByteBlockRange::new(0, big(10), big(20));
        assert_eq!(range.block_index(), 0);
        assert_eq!(*range.start_index(), big(10));
        assert_eq!(*range.end_index(), big(20));
        assert_eq!(range.length(), big(11));
    }

    #[test]
    fn test_byte_block_range_eq() {
        let r1 = ByteBlockRange::new(0, big(0), big(10));
        let r2 = ByteBlockRange::new(0, big(0), big(10));
        let r3 = ByteBlockRange::new(1, big(0), big(10));
        assert_eq!(r1, r2);
        assert_ne!(r1, r3);
    }

    // ---- ByteBlockSelection tests ----

    #[test]
    fn test_byte_block_selection() {
        let mut sel = ByteBlockSelection::new();
        assert!(sel.is_empty());
        sel.add(ByteBlockRange::new(0, big(0), big(9)));
        sel.add(ByteBlockRange::new(0, big(20), big(29)));
        assert_eq!(sel.number_of_ranges(), 2);
        assert_eq!(sel.range(0).unwrap().start_index(), &big(0));
        assert_eq!(sel.range(1).unwrap().start_index(), &big(20));
    }

    #[test]
    fn test_byte_block_selection_from_ranges() {
        let ranges = vec![
            ByteBlockRange::new(0, big(0), big(4)),
            ByteBlockRange::new(1, big(0), big(4)),
        ];
        let sel = ByteBlockSelection::from_ranges(ranges);
        assert_eq!(sel.number_of_ranges(), 2);
    }

    // ---- ByteBlockInfo tests ----

    #[test]
    fn test_byte_block_info() {
        let info = ByteBlockInfo::new(0, big(42), 3);
        assert_eq!(info.block_index(), 0);
        assert_eq!(*info.offset(), big(42));
        assert_eq!(info.column(), 3);
    }

    #[test]
    fn test_byte_block_info_at() {
        let info = ByteBlockInfo::at(1, big(100));
        assert_eq!(info.column(), 0);
    }

    // ---- IndexedByteBlockInfo tests ----

    #[test]
    fn test_indexed_byte_block_info_ordering() {
        let a = IndexedByteBlockInfo::new(big(0), 0, big(10), 0);
        let b = IndexedByteBlockInfo::new(big(0), 0, big(20), 0);
        let c = IndexedByteBlockInfo::new(big(1), 0, big(0), 0);
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn test_indexed_byte_block_info_column_ordering() {
        let a = IndexedByteBlockInfo::new(big(0), 0, big(10), 0);
        let b = IndexedByteBlockInfo::new(big(0), 0, big(10), 1);
        assert!(a < b);
    }

    // ---- ByteEditInfo tests ----

    #[test]
    fn test_byte_edit_info() {
        let edit = ByteEditInfo::new(0x1000, big(5), vec![0x90], vec![0xCC]);
        assert_eq!(edit.block_address(), 0x1000);
        assert_eq!(*edit.offset(), big(5));
        assert_eq!(edit.old_value(), &[0x90]);
        assert_eq!(edit.new_value(), &[0xCC]);
    }

    // ---- ByteBlockChangeManager tests ----

    #[test]
    fn test_change_manager_basic() {
        let mut mgr = ByteBlockChangeManager::new();
        assert!(mgr.is_empty());

        let edit = ByteEditInfo::new(0x1000, big(0), vec![0x90, 0xC3], vec![0xCC, 0xC3]);
        mgr.add(edit);
        // Only byte 0 changed (0x90 -> 0xCC), byte 1 was unchanged
        assert_eq!(mgr.len(), 1);
        assert!(mgr.is_changed(0x1000, &big(0), 1));
        assert!(!mgr.is_changed(0x1000, &big(1), 1));
    }

    #[test]
    fn test_change_manager_range_check() {
        let mut mgr = ByteBlockChangeManager::new();
        let edit = ByteEditInfo::new(0x1000, big(5), vec![0x00], vec![0xFF]);
        mgr.add(edit);
        assert!(mgr.is_changed(0x1000, &big(4), 2)); // range [4,6) includes 5
        assert!(!mgr.is_changed(0x1000, &big(4), 1)); // range [4,5) does not include 5
    }

    #[test]
    fn test_change_manager_from_existing() {
        let mut mgr1 = ByteBlockChangeManager::new();
        mgr1.add(ByteEditInfo::new(0x1000, big(0), vec![0x00], vec![0xFF]));
        let mgr2 = ByteBlockChangeManager::from_existing(&mgr1);
        assert_eq!(mgr2.len(), 1);
    }

    #[test]
    fn test_change_manager_clear() {
        let mut mgr = ByteBlockChangeManager::new();
        mgr.add(ByteEditInfo::new(0x1000, big(0), vec![0x00], vec![0xFF]));
        assert!(!mgr.is_empty());
        mgr.clear();
        assert!(mgr.is_empty());
    }

    // ---- ByteViewerConfigOptions tests ----

    #[test]
    fn test_config_options_defaults() {
        let opts = ByteViewerConfigOptions::new();
        assert_eq!(opts.bytes_per_line(), 16);
        assert_eq!(opts.hex_group_size(), 1);
        assert_eq!(opts.offset(), 0);
        assert!(opts.is_compact_chars());
        assert!(opts.is_use_char_alignment());
        assert_eq!(opts.charset_name(), "US-ASCII");
    }

    #[test]
    fn test_config_options_set_bytes_per_line() {
        let mut opts = ByteViewerConfigOptions::new();
        opts.set_offset(15);
        opts.set_bytes_per_line(8);
        assert_eq!(opts.bytes_per_line(), 8);
        assert_eq!(opts.offset(), 7); // clamped
    }

    #[test]
    fn test_config_options_offset_normalization() {
        let opts = ByteViewerConfigOptions::new(); // 16 bytes/line
        assert_eq!(opts.calc_normalized_offset(-1), 15);
        assert_eq!(opts.calc_normalized_offset(16), 0);
        assert_eq!(opts.calc_normalized_offset(17), 1);
        assert_eq!(opts.calc_normalized_offset(5), 5);
    }

    #[test]
    fn test_config_options_equality() {
        let a = ByteViewerConfigOptions::new();
        let b = ByteViewerConfigOptions::new();
        assert!(a.are_options_equal(&b));

        let mut c = ByteViewerConfigOptions::new();
        c.set_hex_group_size(2);
        assert!(!a.are_options_equal(&c));
    }

    #[test]
    fn test_config_options_layout_changed() {
        let a = ByteViewerConfigOptions::new();
        let mut b = ByteViewerConfigOptions::new();
        assert!(!a.are_layout_params_changed(&b));
        b.set_offset(1);
        assert!(a.are_layout_params_changed(&b));
    }

    #[test]
    fn test_config_options_display_width_changed() {
        let a = ByteViewerConfigOptions::new();
        let mut b = ByteViewerConfigOptions::new();
        assert!(!a.are_display_widths_changed(&b));
        b.set_hex_group_size(2);
        assert!(a.are_display_widths_changed(&b));
    }

    // ---- FieldFactory tests ----

    #[test]
    fn test_field_factory() {
        let factory = FieldFactory::new("Hex", 8, 1, 2, 16, 0);
        assert_eq!(factory.field_width(), 16);
        assert_eq!(factory.fields_per_line(), 16);
        assert_eq!(factory.format_name(), "Hex");
    }

    #[test]
    fn test_field_factory_grouped() {
        let factory = FieldFactory::new("Hex", 8, 2, 4, 16, 0);
        assert_eq!(factory.fields_per_line(), 8);
    }

    #[test]
    fn test_field_factory_start_x() {
        let mut factory = FieldFactory::new("Hex", 8, 1, 2, 16, 0);
        factory.set_start_x(100);
        assert_eq!(factory.start_x(), 100);
    }

    // ---- ByteFormat tests ----

    #[test]
    fn test_byte_format_hex() {
        assert_eq!(ByteFormat::Hex.format_byte(0xFF), "FF");
        assert_eq!(ByteFormat::Hex.format_byte(0x0A), "0A");
        assert_eq!(ByteFormat::Hex.field_width(), 2);
    }

    #[test]
    fn test_byte_format_octal() {
        assert_eq!(ByteFormat::Octal.format_byte(255), "377");
        assert_eq!(ByteFormat::Octal.field_width(), 3);
    }

    #[test]
    fn test_byte_format_decimal() {
        assert_eq!(ByteFormat::Decimal.format_byte(255), "255");
    }

    #[test]
    fn test_byte_format_binary() {
        assert_eq!(ByteFormat::Binary.format_byte(0xA5), "10100101");
        assert_eq!(ByteFormat::Binary.field_width(), 8);
    }

    // ---- FormatModel tests ----

    #[test]
    fn test_format_model_hex_row() {
        let model = FormatModel::hex();
        let data = [0x48, 0x65, 0x6C, 0x6C, 0x6F];
        let row = model.format_row(0x1000, &data);
        assert!(row.contains("00001000"));
        assert!(row.contains("48"));
        assert!(row.contains("Hello"));
    }

    #[test]
    fn test_format_model_block() {
        let model = FormatModel::hex();
        let data: Vec<u8> = (0..32).collect();
        let output = model.format_block(0x0, &data);
        let lines: Vec<&str> = output.trim().lines().collect();
        assert_eq!(lines.len(), 2); // 32 bytes / 16 bytes per row
    }

    // ---- ByteField tests ----

    #[test]
    fn test_byte_field() {
        let field = ByteField::new(0x1000, 0xFF, ByteFormat::Hex, 0);
        assert_eq!(field.text, "FF");
        assert_eq!(field.address, 0x1000);
        assert!(!field.selected);
    }

    // ---- AddressFormat tests ----

    #[test]
    fn test_address_format_hex32() {
        assert_eq!(AddressFormat::Hex32.format(0x12345678), "12345678");
    }

    #[test]
    fn test_address_format_hex64() {
        assert_eq!(
            AddressFormat::Hex64.format(0x0000000012345678),
            "0000000012345678"
        );
    }

    #[test]
    fn test_address_format_segmented() {
        assert_eq!(AddressFormat::Segmented.format(0x0040_0100), "0040:0100");
    }

    // ---- Code block test ----

    #[test]
    fn test_code_block() {
        let block = ByteBlock::code_block(".text", 0x1000, vec![0xCC]);
        assert!(block.is_executable());
        assert!(block.is_readable());
        assert!(!block.is_writable());
    }
}
