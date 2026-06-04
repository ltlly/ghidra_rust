//! Built-in format models for the byte viewer.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.format` Java package.
//!
//! This module provides the [`DataFormatModel`] trait hierarchy and all
//! concrete format model implementations that control how raw memory
//! bytes are displayed and edited in the byte viewer.
//!
//! # Trait hierarchy
//!
//! - [`DataFormatModel`] -- the core trait every format must implement
//! - [`MutableDataFormatModel`] -- optional trait for formats that allow editing
//! - [`UniversalDataFormatModel`] -- marker for formats that work on any byte block
//! - [`ProgramDataFormatModel`] -- marker for formats that need a `Program` reference
//!
//! # Concrete models
//!
//! | Model | Unit size | Symbol size | Editable |
//! |-------|-----------|-------------|----------|
//! | [`HexFormatModel`] | 1 (configurable group) | 2 per byte | yes |
//! | [`HexShortFormatModel`] | 2 | 4 | yes |
//! | [`HexIntegerFormatModel`] | 4 | 8 | yes |
//! | [`HexLongFormatModel`] | 8 | 16 | yes |
//! | [`HexLongLongFormatModel`] | 16 | 32 | yes |
//! | [`BinaryFormatModel`] | 1 | 8 | yes |
//! | [`OctalFormatModel`] | 1 | 3 | yes |
//! | [`IntegerFormatModel`] | 4 | 11 | no |
//! | [`CharacterFormatModel`] | 1 | 1 | yes |

use num_bigint::BigInt;
use std::fmt;

// ===========================================================================
// Error type
// ===========================================================================

/// Error indicating that a byte block access was not permitted
/// (e.g., read/write violation).
///
/// Ported from Ghidra's `ByteBlockAccessException`.
#[derive(Debug, Clone)]
pub struct ByteBlockAccessException(pub String);

impl fmt::Display for ByteBlockAccessException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Byte block access error: {}", self.0)
    }
}

impl std::error::Error for ByteBlockAccessException {}

// ===========================================================================
// ByteBlock interface (trait object used by format models)
// ===========================================================================

/// Trait representing a contiguous block of bytes that can be read/written.
///
/// Ported from Ghidra's `ByteBlock` Java interface.  Format models
/// operate on blocks through this trait, making them agnostic to the
/// underlying storage (memory-mapped, file-backed, etc.).
pub trait ByteBlock: Send + Sync {
    /// Get a human-readable location string for the given index
    /// (e.g., an address like `"00401000"`).
    fn location_representation(&self, index: &BigInt) -> String;

    /// Maximum number of characters in any location representation.
    fn max_location_representation_size(&self) -> usize;

    /// Name used for describing the indexes (e.g., `"addr"`, `"offset"`).
    fn index_name(&self) -> &str;

    /// Number of bytes in this block.
    fn length(&self) -> BigInt;

    /// Get the byte at the given index.
    fn get_byte(&self, index: &BigInt) -> Result<u8, ByteBlockAccessException>;

    /// Get multiple bytes starting at `index`.  Returns the number of
    /// bytes actually copied into `dest`.
    fn get_bytes(
        &self,
        dest: &mut [u8],
        index: &BigInt,
        count: usize,
    ) -> Result<usize, ByteBlockAccessException>;

    /// Returns `true` if the block has an initialized value at `index`.
    fn has_value(&self, index: &BigInt) -> bool {
        let _ = index;
        true
    }

    /// Get the 16-bit value at the given index.
    fn get_short(&self, index: &BigInt) -> Result<i16, ByteBlockAccessException>;

    /// Get the 32-bit value at the given index.
    fn get_int(&self, index: &BigInt) -> Result<i32, ByteBlockAccessException>;

    /// Get the 64-bit value at the given index.
    fn get_long(&self, index: &BigInt) -> Result<i64, ByteBlockAccessException>;

    /// Set the byte at the given index.
    fn set_byte(
        &mut self,
        index: &BigInt,
        value: u8,
    ) -> Result<(), ByteBlockAccessException>;

    /// Set the 16-bit value at the given index.
    fn set_short(
        &mut self,
        index: &BigInt,
        value: i16,
    ) -> Result<(), ByteBlockAccessException>;

    /// Set the 32-bit value at the given index.
    fn set_int(
        &mut self,
        index: &BigInt,
        value: i32,
    ) -> Result<(), ByteBlockAccessException>;

    /// Set the 64-bit value at the given index.
    fn set_long(
        &mut self,
        index: &BigInt,
        value: i64,
    ) -> Result<(), ByteBlockAccessException>;

    /// Whether this block can be modified.
    fn is_editable(&self) -> bool;

    /// Set endianness for the block.
    fn set_big_endian(&mut self, big_endian: bool);

    /// Whether this block is big-endian.
    fn is_big_endian(&self) -> bool;

    /// Natural alignment (offset) for the given radix.
    fn get_alignment(&self, radix: usize) -> usize;
}

// ===========================================================================
// DataFormatModel trait
// ===========================================================================

/// Core trait for all data format models.
///
/// A `DataFormatModel` knows how to convert raw bytes into human-readable
/// strings and how to map cursor positions to byte offsets.  Each
/// implementation corresponds to one display format (hex, octal, binary,
/// integer, character, etc.).
///
/// Ported from Ghidra's `DataFormatModel` Java interface.
pub trait DataFormatModel: Send {
    /// Number of bytes that form one display unit (e.g. 1 for hex byte,
    /// 2 for unicode char, 4 for 32-bit integer).
    fn unit_byte_size(&self) -> usize;

    /// Human-readable name of this format (e.g. `"Hex"`, `"Binary"`).
    fn name(&self) -> &str;

    /// Descriptive name used for labels / headers.
    fn descriptive_name(&self) -> String {
        self.name().to_string()
    }

    /// Number of characters required to display one unit
    /// (e.g. 2 for `"ff"` in hex, 8 for `"00000001"` in binary).
    fn data_unit_symbol_size(&self) -> usize;

    /// Given a character position within a unit (0..data_unit_symbol_size-1),
    /// return which byte (0..unit_byte_size-1) it maps to.
    fn get_byte_offset(&self, block: &dyn ByteBlock, position: usize) -> usize;

    /// Given a byte offset into a unit, return the column position.
    fn get_column_position(&self, block: &dyn ByteBlock, byte_offset: usize) -> usize;

    /// Get the string representation at the given index in the block.
    fn get_data_representation(
        &self,
        block: &dyn ByteBlock,
        index: &BigInt,
    ) -> Result<String, ByteBlockAccessException>;

    /// Number of characters between consecutive units (visual delimiter).
    fn unit_delimiter_size(&self) -> usize;

    /// Pad `value` on the left with `pad_char` until it reaches `symbol_size`.
    fn pad(value: &str, symbol_size: usize, pad_char: &str) -> String {
        if value.len() >= symbol_size {
            value.to_string()
        } else {
            let mut s = String::new();
            for _ in 0..(symbol_size - value.len()) {
                s.push_str(pad_char);
            }
            s.push_str(value);
            s
        }
    }

    /// Pad with zeroes (convenience).
    fn pad_zero(value: &str, symbol_size: usize) -> String {
        Self::pad(value, symbol_size, "0")
    }
}

// ===========================================================================
// MutableDataFormatModel trait
// ===========================================================================

/// Extension trait for format models that support in-place byte editing.
///
/// Ported from Ghidra's `MutableDataFormatModel` Java interface.
pub trait MutableDataFormatModel: DataFormatModel {
    /// Replace the character at position `pos` within the unit starting
    /// at `index` with `c`.
    ///
    /// Returns `true` if the replacement was applied, `false` if `c` is
    /// not a legal character for this format.
    fn replace_value(
        &self,
        block: &mut dyn ByteBlock,
        index: &BigInt,
        pos: usize,
        c: char,
    ) -> Result<bool, ByteBlockAccessException>;
}

// ===========================================================================
// Marker / extension traits
// ===========================================================================

/// Marker trait for format models that work universally on any byte block.
///
/// Ported from Ghidra's `UniversalDataFormatModel`.
pub trait UniversalDataFormatModel: DataFormatModel {}

/// Marker trait for format models that need a program reference.
///
/// Ported from Ghidra's `ProgramDataFormatModel`.
pub trait ProgramDataFormatModel: DataFormatModel {
    /// Update the program reference.  Pass `None` to clear.
    fn set_program(&mut self, program: Option<u64> /* opaque program handle */);
}

// ===========================================================================
// HexFormatModel
// ===========================================================================

/// Converts byte values to hexadecimal representation, optionally grouping
/// bytes together (e.g. 2-byte groups: `"4f2a"`).
///
/// Ported from Ghidra's `HexFormatModel`.
#[derive(Debug, Clone)]
pub struct HexFormatModel {
    symbol_size: usize,
    group_size: usize,
    full_symbol_error: String,
}

impl HexFormatModel {
    const GOOD_CHARS: &'static str = "0123456789abcdefABCDEF";

    /// Create a new hex format model with a group size of 1 (individual bytes).
    pub fn new() -> Self {
        let group_size = 1;
        Self {
            symbol_size: 2 * group_size,
            group_size,
            full_symbol_error: "??".repeat(group_size),
        }
    }

    /// Create with a specific group size (number of bytes per unit).
    pub fn with_group_size(group_size: usize) -> Self {
        assert!(group_size > 0, "group_size must be > 0");
        Self {
            symbol_size: 2 * group_size,
            group_size,
            full_symbol_error: "??".repeat(group_size),
        }
    }

    /// Current hex group size.
    pub fn hex_group_size(&self) -> usize {
        self.group_size
    }

    /// Update the group size (e.g. from `ByteViewerConfigOptions`).
    pub fn set_group_size(&mut self, group_size: usize) {
        self.group_size = group_size;
        self.symbol_size = 2 * group_size;
        self.full_symbol_error = "??".repeat(group_size);
    }
}

impl Default for HexFormatModel {
    fn default() -> Self {
        Self::new()
    }
}

impl DataFormatModel for HexFormatModel {
    fn unit_byte_size(&self) -> usize {
        self.group_size
    }

    fn name(&self) -> &str {
        "Hex"
    }

    fn data_unit_symbol_size(&self) -> usize {
        self.symbol_size
    }

    fn get_byte_offset(&self, _block: &dyn ByteBlock, position: usize) -> usize {
        if position < self.symbol_size {
            position / 2
        } else {
            self.group_size - 1
        }
    }

    fn get_column_position(&self, _block: &dyn ByteBlock, byte_offset: usize) -> usize {
        byte_offset * 2
    }

    fn get_data_representation(
        &self,
        block: &dyn ByteBlock,
        index: &BigInt,
    ) -> Result<String, ByteBlockAccessException> {
        let mut bytes = vec![0u8; self.group_size];
        let bytes_read = block.get_bytes(&mut bytes, index, self.group_size)?;
        if bytes_read == 0 {
            return Ok(self.full_symbol_error.clone());
        }
        let mut s = String::with_capacity(bytes_read * 2);
        for &b in &bytes[..bytes_read] {
            s.push_str(&format!("{:02x}", b));
        }
        Ok(s)
    }

    fn unit_delimiter_size(&self) -> usize {
        1
    }
}

impl MutableDataFormatModel for HexFormatModel {
    fn replace_value(
        &self,
        block: &mut dyn ByteBlock,
        index: &BigInt,
        char_position: usize,
        c: char,
    ) -> Result<bool, ByteBlockAccessException> {
        if Self::GOOD_CHARS.find(c).is_none() {
            return Ok(false);
        }
        if char_position >= self.symbol_size {
            return Ok(false);
        }

        let byte_no = self.get_byte_offset(block, char_position);
        let target_index = index + byte_no;
        let b = block.get_byte(&target_index)?;
        let cb = c.to_digit(16).unwrap() as u8;

        let new_b = if char_position % 2 == 0 {
            (b & 0x0f) | (cb << 4)
        } else {
            (b & 0xf0) | cb
        };
        block.set_byte(&target_index, new_b)?;
        Ok(true)
    }
}

impl UniversalDataFormatModel for HexFormatModel {}

// ===========================================================================
// HexValueFormatModel -- abstract base for 2/4/8/16-byte hex numbers
// ===========================================================================

/// Base for multi-byte hex value format models.
///
/// Ported from Ghidra's `HexValueFormatModel`.
#[derive(Debug, Clone)]
pub struct HexValueFormatModel {
    name: String,
    symbol_size: usize,
    nbytes: usize,
    full_symbol_error: String,
}

impl HexValueFormatModel {
    /// Create a new hex value format model.
    pub fn new(name: impl Into<String>, nbytes: usize) -> Self {
        Self {
            name: name.into(),
            nbytes,
            symbol_size: nbytes * 2,
            full_symbol_error: "??".repeat(nbytes),
        }
    }
}

impl DataFormatModel for HexValueFormatModel {
    fn unit_byte_size(&self) -> usize {
        self.nbytes
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn data_unit_symbol_size(&self) -> usize {
        self.symbol_size
    }

    fn get_byte_offset(&self, block: &dyn ByteBlock, position: usize) -> usize {
        let o = position / 2;
        if block.is_big_endian() {
            o
        } else {
            self.nbytes - 1 - o
        }
    }

    fn get_column_position(&self, block: &dyn ByteBlock, byte_offset: usize) -> usize {
        if byte_offset >= self.nbytes {
            panic!("invalid byte_offset: {}", byte_offset);
        }
        if block.is_big_endian() {
            byte_offset * 2
        } else {
            (self.nbytes - 1 - byte_offset) * 2
        }
    }

    fn get_data_representation(
        &self,
        _block: &dyn ByteBlock,
        _index: &BigInt,
    ) -> Result<String, ByteBlockAccessException> {
        // Subclasses override this; base returns error string
        Ok(self.full_symbol_error.clone())
    }

    fn unit_delimiter_size(&self) -> usize {
        1
    }
}

impl MutableDataFormatModel for HexValueFormatModel {
    fn replace_value(
        &self,
        block: &mut dyn ByteBlock,
        index: &BigInt,
        char_position: usize,
        c: char,
    ) -> Result<bool, ByteBlockAccessException> {
        if char_position >= self.symbol_size {
            return Ok(false);
        }
        let cb = match c.to_digit(16) {
            Some(v) => v as u8,
            None => return Ok(false),
        };
        let byte_offset = self.get_byte_offset(block, char_position);
        let target_index = index + byte_offset;
        let b = block.get_byte(&target_index)?;
        let new_b = if char_position % 2 == 0 {
            (b & 0x0f) | (cb << 4)
        } else {
            (b & 0xf0) | cb
        };
        block.set_byte(&target_index, new_b)?;
        Ok(true)
    }
}

impl UniversalDataFormatModel for HexValueFormatModel {}

// ===========================================================================
// HexShortFormatModel (2 bytes / 4 hex digits)
// ===========================================================================

/// Displays a 2-byte value as a 4-digit hex number.
///
/// Ported from Ghidra's `HexShortFormatModel`.
#[derive(Debug, Clone)]
pub struct HexShortFormatModel {
    inner: HexValueFormatModel,
}

impl HexShortFormatModel {
    /// Create a new hex short format model.
    pub fn new() -> Self {
        Self {
            inner: HexValueFormatModel::new("Hex Short", 2),
        }
    }
}

impl Default for HexShortFormatModel {
    fn default() -> Self {
        Self::new()
    }
}

impl DataFormatModel for HexShortFormatModel {
    fn unit_byte_size(&self) -> usize {
        self.inner.unit_byte_size()
    }
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn data_unit_symbol_size(&self) -> usize {
        self.inner.data_unit_symbol_size()
    }
    fn get_byte_offset(&self, block: &dyn ByteBlock, position: usize) -> usize {
        self.inner.get_byte_offset(block, position)
    }
    fn get_column_position(&self, block: &dyn ByteBlock, byte_offset: usize) -> usize {
        self.inner.get_column_position(block, byte_offset)
    }
    fn get_data_representation(
        &self,
        block: &dyn ByteBlock,
        index: &BigInt,
    ) -> Result<String, ByteBlockAccessException> {
        let s = block.get_short(index)?;
        Ok(Self::pad_zero(
            &format!("{:x}", s as u16),
            self.inner.data_unit_symbol_size(),
        ))
    }
    fn unit_delimiter_size(&self) -> usize {
        self.inner.unit_delimiter_size()
    }
}

impl MutableDataFormatModel for HexShortFormatModel {
    fn replace_value(
        &self,
        block: &mut dyn ByteBlock,
        index: &BigInt,
        pos: usize,
        c: char,
    ) -> Result<bool, ByteBlockAccessException> {
        self.inner.replace_value(block, index, pos, c)
    }
}

impl UniversalDataFormatModel for HexShortFormatModel {}

// ===========================================================================
// HexIntegerFormatModel (4 bytes / 8 hex digits)
// ===========================================================================

/// Displays a 4-byte value as an 8-digit hex number.
///
/// Ported from Ghidra's `HexIntegerFormatModel`.
#[derive(Debug, Clone)]
pub struct HexIntegerFormatModel {
    inner: HexValueFormatModel,
}

impl HexIntegerFormatModel {
    /// Create a new hex integer format model.
    pub fn new() -> Self {
        Self {
            inner: HexValueFormatModel::new("Hex Integer", 4),
        }
    }
}

impl Default for HexIntegerFormatModel {
    fn default() -> Self {
        Self::new()
    }
}

impl DataFormatModel for HexIntegerFormatModel {
    fn unit_byte_size(&self) -> usize {
        self.inner.unit_byte_size()
    }
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn data_unit_symbol_size(&self) -> usize {
        self.inner.data_unit_symbol_size()
    }
    fn get_byte_offset(&self, block: &dyn ByteBlock, position: usize) -> usize {
        self.inner.get_byte_offset(block, position)
    }
    fn get_column_position(&self, block: &dyn ByteBlock, byte_offset: usize) -> usize {
        self.inner.get_column_position(block, byte_offset)
    }
    fn get_data_representation(
        &self,
        block: &dyn ByteBlock,
        index: &BigInt,
    ) -> Result<String, ByteBlockAccessException> {
        let i = block.get_int(index)?;
        Ok(Self::pad_zero(
            &format!("{:x}", i as u32),
            self.inner.data_unit_symbol_size(),
        ))
    }
    fn unit_delimiter_size(&self) -> usize {
        self.inner.unit_delimiter_size()
    }
}

impl MutableDataFormatModel for HexIntegerFormatModel {
    fn replace_value(
        &self,
        block: &mut dyn ByteBlock,
        index: &BigInt,
        pos: usize,
        c: char,
    ) -> Result<bool, ByteBlockAccessException> {
        self.inner.replace_value(block, index, pos, c)
    }
}

impl UniversalDataFormatModel for HexIntegerFormatModel {}

// ===========================================================================
// HexLongFormatModel (8 bytes / 16 hex digits)
// ===========================================================================

/// Displays an 8-byte value as a 16-digit hex number.
///
/// Ported from Ghidra's `HexLongFormatModel`.
#[derive(Debug, Clone)]
pub struct HexLongFormatModel {
    inner: HexValueFormatModel,
}

impl HexLongFormatModel {
    /// Create a new hex long format model.
    pub fn new() -> Self {
        Self {
            inner: HexValueFormatModel::new("Hex Long", 8),
        }
    }
}

impl Default for HexLongFormatModel {
    fn default() -> Self {
        Self::new()
    }
}

impl DataFormatModel for HexLongFormatModel {
    fn unit_byte_size(&self) -> usize {
        self.inner.unit_byte_size()
    }
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn data_unit_symbol_size(&self) -> usize {
        self.inner.data_unit_symbol_size()
    }
    fn get_byte_offset(&self, block: &dyn ByteBlock, position: usize) -> usize {
        self.inner.get_byte_offset(block, position)
    }
    fn get_column_position(&self, block: &dyn ByteBlock, byte_offset: usize) -> usize {
        self.inner.get_column_position(block, byte_offset)
    }
    fn get_data_representation(
        &self,
        block: &dyn ByteBlock,
        index: &BigInt,
    ) -> Result<String, ByteBlockAccessException> {
        let l = block.get_long(index)?;
        Ok(Self::pad_zero(
            &format!("{:x}", l as u64),
            self.inner.data_unit_symbol_size(),
        ))
    }
    fn unit_delimiter_size(&self) -> usize {
        self.inner.unit_delimiter_size()
    }
}

impl MutableDataFormatModel for HexLongFormatModel {
    fn replace_value(
        &self,
        block: &mut dyn ByteBlock,
        index: &BigInt,
        pos: usize,
        c: char,
    ) -> Result<bool, ByteBlockAccessException> {
        self.inner.replace_value(block, index, pos, c)
    }
}

impl UniversalDataFormatModel for HexLongFormatModel {}

// ===========================================================================
// HexLongLongFormatModel (16 bytes / 32 hex digits)
// ===========================================================================

/// Displays a 16-byte value as a 32-digit hex number.
///
/// Ported from Ghidra's `HexLongLongFormatModel`.
#[derive(Debug, Clone)]
pub struct HexLongLongFormatModel {
    inner: HexValueFormatModel,
}

impl HexLongLongFormatModel {
    /// Create a new hex long-long format model.
    pub fn new() -> Self {
        Self {
            inner: HexValueFormatModel::new("Hex Long Long", 16),
        }
    }
}

impl Default for HexLongLongFormatModel {
    fn default() -> Self {
        Self::new()
    }
}

impl DataFormatModel for HexLongLongFormatModel {
    fn unit_byte_size(&self) -> usize {
        self.inner.unit_byte_size()
    }
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn data_unit_symbol_size(&self) -> usize {
        self.inner.data_unit_symbol_size()
    }
    fn get_byte_offset(&self, block: &dyn ByteBlock, position: usize) -> usize {
        self.inner.get_byte_offset(block, position)
    }
    fn get_column_position(&self, block: &dyn ByteBlock, byte_offset: usize) -> usize {
        self.inner.get_column_position(block, byte_offset)
    }
    fn get_data_representation(
        &self,
        block: &dyn ByteBlock,
        index: &BigInt,
    ) -> Result<String, ByteBlockAccessException> {
        let nbytes = self.inner.nbytes;
        let mut bytes = vec![0u8; nbytes];
        let read = block.get_bytes(&mut bytes, index, nbytes)?;
        if read != nbytes {
            return Ok(self.inner.full_symbol_error.clone());
        }
        // Convert bytes to a hex string respecting endianness
        let val: u128 = if block.is_big_endian() {
            bytes.iter().fold(0u128, |acc, &b| (acc << 8) | b as u128)
        } else {
            bytes
                .iter()
                .rev()
                .fold(0u128, |acc, &b| (acc << 8) | b as u128)
        };
        Ok(format!("{:032x}", val))
    }
    fn unit_delimiter_size(&self) -> usize {
        self.inner.unit_delimiter_size()
    }
}

impl MutableDataFormatModel for HexLongLongFormatModel {
    fn replace_value(
        &self,
        block: &mut dyn ByteBlock,
        index: &BigInt,
        pos: usize,
        c: char,
    ) -> Result<bool, ByteBlockAccessException> {
        self.inner.replace_value(block, index, pos, c)
    }
}

impl UniversalDataFormatModel for HexLongLongFormatModel {}

// ===========================================================================
// BinaryFormatModel
// ===========================================================================

/// Converts byte values to 8-character binary representation.
///
/// Ported from Ghidra's `BinaryFormatModel`.
#[derive(Debug, Clone)]
pub struct BinaryFormatModel {
    symbol_size: usize,
}

impl BinaryFormatModel {
    const GOOD_CHARS: &'static str = "01";

    /// Create a new binary format model.
    pub fn new() -> Self {
        Self { symbol_size: 8 }
    }
}

impl Default for BinaryFormatModel {
    fn default() -> Self {
        Self::new()
    }
}

impl DataFormatModel for BinaryFormatModel {
    fn unit_byte_size(&self) -> usize {
        1
    }

    fn name(&self) -> &str {
        "Binary"
    }

    fn data_unit_symbol_size(&self) -> usize {
        self.symbol_size
    }

    fn get_byte_offset(&self, _block: &dyn ByteBlock, _position: usize) -> usize {
        0
    }

    fn get_column_position(&self, _block: &dyn ByteBlock, _byte_offset: usize) -> usize {
        0
    }

    fn get_data_representation(
        &self,
        block: &dyn ByteBlock,
        index: &BigInt,
    ) -> Result<String, ByteBlockAccessException> {
        let b = block.get_byte(index)?;
        let val = b as u32;
        let str_repr = format!("{:b}", val);
        Ok(Self::pad_zero(&str_repr, self.symbol_size))
    }

    fn unit_delimiter_size(&self) -> usize {
        1
    }
}

impl MutableDataFormatModel for BinaryFormatModel {
    fn replace_value(
        &self,
        block: &mut dyn ByteBlock,
        index: &BigInt,
        char_position: usize,
        c: char,
    ) -> Result<bool, ByteBlockAccessException> {
        if char_position > 7 {
            return Ok(false);
        }
        if Self::GOOD_CHARS.find(c).is_none() {
            return Ok(false);
        }
        if char_position == 0 && c != '0' && c != '1' {
            return Ok(false);
        }

        let b = block.get_byte(index)?;
        let cb = c.to_digit(2).unwrap() as u8;
        let mask = 1u8 << (7 - char_position);
        let new_b = (b & !mask) | if cb == 1 { mask } else { 0 };
        block.set_byte(index, new_b)?;
        Ok(true)
    }
}

impl UniversalDataFormatModel for BinaryFormatModel {}

// ===========================================================================
// OctalFormatModel
// ===========================================================================

/// Converts byte values to 3-character octal representation.
///
/// Ported from Ghidra's `OctalFormatModel`.
#[derive(Debug, Clone)]
pub struct OctalFormatModel {
    symbol_size: usize,
}

impl OctalFormatModel {
    const GOOD_CHARS: &'static str = "01234567";

    /// Create a new octal format model.
    pub fn new() -> Self {
        Self { symbol_size: 3 }
    }
}

impl Default for OctalFormatModel {
    fn default() -> Self {
        Self::new()
    }
}

impl DataFormatModel for OctalFormatModel {
    fn unit_byte_size(&self) -> usize {
        1
    }

    fn name(&self) -> &str {
        "Octal"
    }

    fn data_unit_symbol_size(&self) -> usize {
        self.symbol_size
    }

    fn get_byte_offset(&self, _block: &dyn ByteBlock, _position: usize) -> usize {
        0
    }

    fn get_column_position(&self, _block: &dyn ByteBlock, _byte_offset: usize) -> usize {
        0
    }

    fn get_data_representation(
        &self,
        block: &dyn ByteBlock,
        index: &BigInt,
    ) -> Result<String, ByteBlockAccessException> {
        let b = block.get_byte(index)?;
        let i = b as u32;
        Ok(Self::pad_zero(&format!("{:o}", i), self.symbol_size))
    }

    fn unit_delimiter_size(&self) -> usize {
        1
    }
}

impl MutableDataFormatModel for OctalFormatModel {
    fn replace_value(
        &self,
        block: &mut dyn ByteBlock,
        index: &BigInt,
        char_position: usize,
        c: char,
    ) -> Result<bool, ByteBlockAccessException> {
        if char_position > 2 {
            return Ok(false);
        }
        if Self::GOOD_CHARS.find(c).is_none() {
            return Ok(false);
        }
        // First digit can only be 0-3 (max byte value is 377 octal)
        if char_position == 0 && c > '3' {
            return Ok(false);
        }

        let b = block.get_byte(index)?;
        let cb = c.to_digit(8).unwrap() as u8;
        let new_b = match char_position {
            0 => (b & 0x3f) | (cb << 6),
            1 => (b & 0xc7) | (cb << 3),
            _ => (b & 0xf8) | cb,
        };
        block.set_byte(index, new_b)?;
        Ok(true)
    }
}

impl UniversalDataFormatModel for OctalFormatModel {}

// ===========================================================================
// IntegerFormatModel (decimal, read-only)
// ===========================================================================

/// Displays a 4-byte value as a signed decimal integer.
///
/// This format does **not** support editing.
///
/// Ported from Ghidra's `IntegerFormatModel`.
#[derive(Debug, Clone)]
pub struct IntegerFormatModel {
    symbol_size: usize,
}

impl IntegerFormatModel {
    /// Create a new integer (decimal) format model.
    pub fn new() -> Self {
        // 11 chars: sign + up to 10 digits for i32
        Self { symbol_size: 11 }
    }
}

impl Default for IntegerFormatModel {
    fn default() -> Self {
        Self::new()
    }
}

impl DataFormatModel for IntegerFormatModel {
    fn unit_byte_size(&self) -> usize {
        4
    }

    fn name(&self) -> &str {
        "Integer"
    }

    fn data_unit_symbol_size(&self) -> usize {
        self.symbol_size
    }

    fn get_byte_offset(&self, _block: &dyn ByteBlock, _position: usize) -> usize {
        0
    }

    fn get_column_position(&self, _block: &dyn ByteBlock, _byte_offset: usize) -> usize {
        0
    }

    fn get_data_representation(
        &self,
        block: &dyn ByteBlock,
        index: &BigInt,
    ) -> Result<String, ByteBlockAccessException> {
        let i = block.get_int(index)?;
        Ok(Self::pad(&format!("{}", i), self.symbol_size, " "))
    }

    fn unit_delimiter_size(&self) -> usize {
        1
    }
}

impl UniversalDataFormatModel for IntegerFormatModel {}

// ===========================================================================
// CharacterFormatModel (ASCII / simple char display)
// ===========================================================================

/// Converts byte values to character representation.
///
/// This is a simplified port of Ghidra's `CharacterFormatModel`.
/// It supports ASCII encoding.  Non-printable characters are shown as
/// `'.'`.
#[derive(Debug, Clone)]
pub struct CharacterFormatModel {
    /// Whether to use compact (single-width) character cells.
    compact: bool,
}

impl CharacterFormatModel {
    /// Create a new character format model.
    pub fn new() -> Self {
        Self { compact: true }
    }

    /// Whether compact mode is active.
    pub fn is_compact(&self) -> bool {
        self.compact
    }

    /// Set compact mode.
    pub fn set_compact(&mut self, compact: bool) {
        self.compact = compact;
    }
}

impl Default for CharacterFormatModel {
    fn default() -> Self {
        Self::new()
    }
}

impl DataFormatModel for CharacterFormatModel {
    fn unit_byte_size(&self) -> usize {
        1
    }

    fn name(&self) -> &str {
        "Chars"
    }

    fn descriptive_name(&self) -> String {
        "Chars (US-ASCII)".to_string()
    }

    fn data_unit_symbol_size(&self) -> usize {
        1
    }

    fn get_byte_offset(&self, _block: &dyn ByteBlock, _position: usize) -> usize {
        0
    }

    fn get_column_position(&self, _block: &dyn ByteBlock, _byte_offset: usize) -> usize {
        0
    }

    fn get_data_representation(
        &self,
        block: &dyn ByteBlock,
        index: &BigInt,
    ) -> Result<String, ByteBlockAccessException> {
        let b = block.get_byte(index)?;
        let ch = b as char;
        if b < 0x20 || b == 0x7f {
            Ok(".".to_string())
        } else {
            Ok(ch.to_string())
        }
    }

    fn unit_delimiter_size(&self) -> usize {
        0
    }
}

impl MutableDataFormatModel for CharacterFormatModel {
    fn replace_value(
        &self,
        block: &mut dyn ByteBlock,
        index: &BigInt,
        char_position: usize,
        c: char,
    ) -> Result<bool, ByteBlockAccessException> {
        if char_position != 0 {
            return Ok(false);
        }
        let cb = c as u8;
        // Only support printable ASCII when replacing
        if cb < 0x20 || cb == 0x7f {
            return Ok(false);
        }
        block.set_byte(index, cb)?;
        Ok(true)
    }
}

impl UniversalDataFormatModel for CharacterFormatModel {}

// ===========================================================================
// FormatModel registry / convenience
// ===========================================================================

/// An enumeration of all built-in data format models.
///
/// This is a convenience wrapper that allows selecting a format model
/// by name or by a known variant, without requiring trait objects.
#[derive(Debug, Clone)]
pub enum DataFormat {
    /// Individual hex bytes.
    Hex(HexFormatModel),
    /// Hex short (2-byte groups).
    HexShort(HexShortFormatModel),
    /// Hex integer (4-byte groups).
    HexInteger(HexIntegerFormatModel),
    /// Hex long (8-byte groups).
    HexLong(HexLongFormatModel),
    /// Hex long-long (16-byte groups).
    HexLongLong(HexLongLongFormatModel),
    /// Binary bits.
    Binary(BinaryFormatModel),
    /// Octal digits.
    Octal(OctalFormatModel),
    /// Signed decimal integer.
    Integer(IntegerFormatModel),
    /// ASCII characters.
    Character(CharacterFormatModel),
}

impl DataFormat {
    /// Get the name of the format.
    pub fn name(&self) -> &str {
        match self {
            Self::Hex(m) => m.name(),
            Self::HexShort(m) => m.name(),
            Self::HexInteger(m) => m.name(),
            Self::HexLong(m) => m.name(),
            Self::HexLongLong(m) => m.name(),
            Self::Binary(m) => m.name(),
            Self::Octal(m) => m.name(),
            Self::Integer(m) => m.name(),
            Self::Character(m) => m.name(),
        }
    }

    /// Get the unit byte size.
    pub fn unit_byte_size(&self) -> usize {
        match self {
            Self::Hex(m) => m.unit_byte_size(),
            Self::HexShort(m) => m.unit_byte_size(),
            Self::HexInteger(m) => m.unit_byte_size(),
            Self::HexLong(m) => m.unit_byte_size(),
            Self::HexLongLong(m) => m.unit_byte_size(),
            Self::Binary(m) => m.unit_byte_size(),
            Self::Octal(m) => m.unit_byte_size(),
            Self::Integer(m) => m.unit_byte_size(),
            Self::Character(m) => m.unit_byte_size(),
        }
    }

    /// Get the data representation at `index` in `block`.
    pub fn get_data_representation(
        &self,
        block: &dyn ByteBlock,
        index: &BigInt,
    ) -> Result<String, ByteBlockAccessException> {
        match self {
            Self::Hex(m) => m.get_data_representation(block, index),
            Self::HexShort(m) => m.get_data_representation(block, index),
            Self::HexInteger(m) => m.get_data_representation(block, index),
            Self::HexLong(m) => m.get_data_representation(block, index),
            Self::HexLongLong(m) => m.get_data_representation(block, index),
            Self::Binary(m) => m.get_data_representation(block, index),
            Self::Octal(m) => m.get_data_representation(block, index),
            Self::Integer(m) => m.get_data_representation(block, index),
            Self::Character(m) => m.get_data_representation(block, index),
        }
    }

    /// Get all available format models.
    pub fn all_formats() -> Vec<DataFormat> {
        vec![
            DataFormat::Hex(HexFormatModel::new()),
            DataFormat::HexShort(HexShortFormatModel::new()),
            DataFormat::HexInteger(HexIntegerFormatModel::new()),
            DataFormat::HexLong(HexLongFormatModel::new()),
            DataFormat::HexLongLong(HexLongLongFormatModel::new()),
            DataFormat::Binary(BinaryFormatModel::new()),
            DataFormat::Octal(OctalFormatModel::new()),
            DataFormat::Integer(IntegerFormatModel::new()),
            DataFormat::Character(CharacterFormatModel::new()),
        ]
    }
}

// ===========================================================================
// Legacy convenience functions (backward compatibility)
// ===========================================================================

/// Standard hex format: 16 bytes per row, 1 byte per group, ASCII sidebar.
pub fn hex_model() -> super::FormatModel {
    super::FormatModel::hex()
}

/// Hex format with 2-byte groups.
pub fn hex_16bit_model() -> super::FormatModel {
    super::FormatModel {
        format: super::ByteFormat::Hex,
        bytes_per_row: 16,
        bytes_per_group: 2,
        show_ascii: true,
        show_address: true,
    }
}

/// Hex format with 4-byte groups.
pub fn hex_32bit_model() -> super::FormatModel {
    super::FormatModel {
        format: super::ByteFormat::Hex,
        bytes_per_row: 16,
        bytes_per_group: 4,
        show_ascii: true,
        show_address: true,
    }
}

/// Octal format: 16 bytes per row.
pub fn octal_model() -> super::FormatModel {
    super::FormatModel {
        format: super::ByteFormat::Octal,
        bytes_per_row: 16,
        bytes_per_group: 1,
        show_ascii: true,
        show_address: true,
    }
}

/// Decimal format: 16 bytes per row.
pub fn decimal_model() -> super::FormatModel {
    super::FormatModel {
        format: super::ByteFormat::Decimal,
        bytes_per_row: 16,
        bytes_per_group: 1,
        show_ascii: true,
        show_address: true,
    }
}

/// Binary format: 8 bytes per row.
pub fn binary_model() -> super::FormatModel {
    super::FormatModel::binary()
}

/// Get all available legacy format models.
pub fn all_models() -> Vec<(&'static str, super::FormatModel)> {
    vec![
        ("Hex (8-bit)", hex_model()),
        ("Hex (16-bit)", hex_16bit_model()),
        ("Hex (32-bit)", hex_32bit_model()),
        ("Octal", octal_model()),
        ("Decimal", decimal_model()),
        ("Binary", binary_model()),
    ]
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;

    // ---- Test helper: a simple in-memory ByteBlock ----

    fn bigint_to_usize(v: &BigInt) -> Option<usize> {
        if v.sign() == num_bigint::Sign::Minus {
            return None;
        }
        let bytes = v.to_bytes_be().1;
        let mut result: usize = 0;
        for &b in &bytes {
            result = result.checked_mul(256)?.checked_add(b as usize)?;
        }
        Some(result)
    }

    struct TestBlock {
        data: Vec<u8>,
        big_endian: bool,
    }

    impl TestBlock {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                big_endian: true,
            }
        }

        fn le(data: Vec<u8>) -> Self {
            Self {
                data,
                big_endian: false,
            }
        }
    }

    impl ByteBlock for TestBlock {
        fn location_representation(&self, index: &BigInt) -> String {
            let val = bigint_to_usize(index).unwrap_or(0);
            format!("{:08x}", val)
        }

        fn max_location_representation_size(&self) -> usize {
            8
        }

        fn index_name(&self) -> &str {
            "addr"
        }

        fn length(&self) -> BigInt {
            BigInt::from(self.data.len())
        }

        fn get_byte(&self, index: &BigInt) -> Result<u8, ByteBlockAccessException> {
            let idx = bigint_to_usize(index)
                .ok_or_else(|| ByteBlockAccessException("index out of range".into()))?;
            self.data
                .get(idx)
                .copied()
                .ok_or_else(|| ByteBlockAccessException("index out of bounds".into()))
        }

        fn get_bytes(
            &self,
            dest: &mut [u8],
            index: &BigInt,
            count: usize,
        ) -> Result<usize, ByteBlockAccessException> {
            let idx = bigint_to_usize(index)
                .ok_or_else(|| ByteBlockAccessException("index out of range".into()))?;
            let available = self.data.len().saturating_sub(idx);
            let to_copy = count.min(available).min(dest.len());
            dest[..to_copy].copy_from_slice(&self.data[idx..idx + to_copy]);
            Ok(to_copy)
        }

        fn get_short(&self, index: &BigInt) -> Result<i16, ByteBlockAccessException> {
            let idx = bigint_to_usize(index)
                .ok_or_else(|| ByteBlockAccessException("index out of range".into()))?;
            if idx + 2 > self.data.len() {
                return Err(ByteBlockAccessException("not enough bytes".into()));
            }
            let val = if self.big_endian {
                i16::from_be_bytes([self.data[idx], self.data[idx + 1]])
            } else {
                i16::from_le_bytes([self.data[idx], self.data[idx + 1]])
            };
            Ok(val)
        }

        fn get_int(&self, index: &BigInt) -> Result<i32, ByteBlockAccessException> {
            let idx = bigint_to_usize(index)
                .ok_or_else(|| ByteBlockAccessException("index out of range".into()))?;
            if idx + 4 > self.data.len() {
                return Err(ByteBlockAccessException("not enough bytes".into()));
            }
            let val = if self.big_endian {
                i32::from_be_bytes(self.data[idx..idx + 4].try_into().unwrap())
            } else {
                i32::from_le_bytes(self.data[idx..idx + 4].try_into().unwrap())
            };
            Ok(val)
        }

        fn get_long(&self, index: &BigInt) -> Result<i64, ByteBlockAccessException> {
            let idx = bigint_to_usize(index)
                .ok_or_else(|| ByteBlockAccessException("index out of range".into()))?;
            if idx + 8 > self.data.len() {
                return Err(ByteBlockAccessException("not enough bytes".into()));
            }
            let val = if self.big_endian {
                i64::from_be_bytes(self.data[idx..idx + 8].try_into().unwrap())
            } else {
                i64::from_le_bytes(self.data[idx..idx + 8].try_into().unwrap())
            };
            Ok(val)
        }

        fn set_byte(
            &mut self,
            index: &BigInt,
            value: u8,
        ) -> Result<(), ByteBlockAccessException> {
            let idx = bigint_to_usize(index)
                .ok_or_else(|| ByteBlockAccessException("index out of range".into()))?;
            if idx >= self.data.len() {
                return Err(ByteBlockAccessException("index out of bounds".into()));
            }
            self.data[idx] = value;
            Ok(())
        }

        fn set_short(
            &mut self,
            _index: &BigInt,
            _value: i16,
        ) -> Result<(), ByteBlockAccessException> {
            Ok(())
        }

        fn set_int(
            &mut self,
            _index: &BigInt,
            _value: i32,
        ) -> Result<(), ByteBlockAccessException> {
            Ok(())
        }

        fn set_long(
            &mut self,
            _index: &BigInt,
            _value: i64,
        ) -> Result<(), ByteBlockAccessException> {
            Ok(())
        }

        fn is_editable(&self) -> bool {
            true
        }

        fn set_big_endian(&mut self, big_endian: bool) {
            self.big_endian = big_endian;
        }

        fn is_big_endian(&self) -> bool {
            self.big_endian
        }

        fn get_alignment(&self, _radix: usize) -> usize {
            0
        }
    }

    fn idx(n: u64) -> BigInt {
        BigInt::from(n)
    }

    // ---- HexFormatModel tests ----

    #[test]
    fn test_hex_format_single_byte() {
        let model = HexFormatModel::new();
        let block = TestBlock::new(vec![0xFF, 0x0A, 0x48]);
        assert_eq!(
            model.get_data_representation(&block, &idx(0)).unwrap(),
            "ff"
        );
        assert_eq!(
            model.get_data_representation(&block, &idx(1)).unwrap(),
            "0a"
        );
        assert_eq!(model.unit_byte_size(), 1);
        assert_eq!(model.data_unit_symbol_size(), 2);
    }

    #[test]
    fn test_hex_format_grouped() {
        let model = HexFormatModel::with_group_size(2);
        let block = TestBlock::new(vec![0xCA, 0xFE, 0xBA, 0xBE]);
        assert_eq!(
            model.get_data_representation(&block, &idx(0)).unwrap(),
            "cafe"
        );
        assert_eq!(
            model.get_data_representation(&block, &idx(2)).unwrap(),
            "babe"
        );
        assert_eq!(model.unit_byte_size(), 2);
        assert_eq!(model.data_unit_symbol_size(), 4);
    }

    #[test]
    fn test_hex_format_set_group_size() {
        let mut model = HexFormatModel::new();
        assert_eq!(model.unit_byte_size(), 1);
        model.set_group_size(4);
        assert_eq!(model.unit_byte_size(), 4);
        assert_eq!(model.data_unit_symbol_size(), 8);
    }

    #[test]
    fn test_hex_format_byte_offset() {
        let model = HexFormatModel::with_group_size(2);
        let block = TestBlock::new(vec![0; 4]);
        assert_eq!(model.get_byte_offset(&block, 0), 0);
        assert_eq!(model.get_byte_offset(&block, 1), 0);
        assert_eq!(model.get_byte_offset(&block, 2), 1);
        assert_eq!(model.get_byte_offset(&block, 3), 1);
    }

    #[test]
    fn test_hex_format_column_position() {
        let model = HexFormatModel::with_group_size(2);
        let block = TestBlock::new(vec![0; 4]);
        assert_eq!(model.get_column_position(&block, 0), 0);
        assert_eq!(model.get_column_position(&block, 1), 2);
    }

    #[test]
    fn test_hex_format_edit() {
        let model = HexFormatModel::new();
        let mut block = TestBlock::new(vec![0x00]);
        // Replace high nibble with 'a'
        assert!(model
            .replace_value(&mut block, &idx(0), 0, 'a')
            .unwrap());
        assert_eq!(block.data[0], 0xa0);
        // Replace low nibble with '5'
        assert!(model
            .replace_value(&mut block, &idx(0), 1, '5')
            .unwrap());
        assert_eq!(block.data[0], 0xa5);
        // Invalid char
        assert!(!model
            .replace_value(&mut block, &idx(0), 0, 'z')
            .unwrap());
    }

    #[test]
    fn test_hex_format_delimiter() {
        let model = HexFormatModel::new();
        assert_eq!(model.unit_delimiter_size(), 1);
    }

    // ---- HexShortFormatModel tests ----

    #[test]
    fn test_hex_short() {
        let model = HexShortFormatModel::new();
        let block = TestBlock::new(vec![0xCA, 0xFE]);
        assert_eq!(
            model.get_data_representation(&block, &idx(0)).unwrap(),
            "cafe"
        );
        assert_eq!(model.unit_byte_size(), 2);
    }

    #[test]
    fn test_hex_short_le() {
        let model = HexShortFormatModel::new();
        let block = TestBlock::le(vec![0xFE, 0xCA]);
        assert_eq!(
            model.get_data_representation(&block, &idx(0)).unwrap(),
            "cafe"
        );
    }

    // ---- HexIntegerFormatModel tests ----

    #[test]
    fn test_hex_integer() {
        let model = HexIntegerFormatModel::new();
        let block = TestBlock::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(
            model.get_data_representation(&block, &idx(0)).unwrap(),
            "deadbeef"
        );
        assert_eq!(model.unit_byte_size(), 4);
    }

    // ---- HexLongFormatModel tests ----

    #[test]
    fn test_hex_long() {
        let model = HexLongFormatModel::new();
        let block = TestBlock::new(vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        assert_eq!(
            model.get_data_representation(&block, &idx(0)).unwrap(),
            "0123456789abcdef"
        );
        assert_eq!(model.unit_byte_size(), 8);
    }

    // ---- HexLongLongFormatModel tests ----

    #[test]
    fn test_hex_long_long() {
        let model = HexLongLongFormatModel::new();
        let mut data = vec![0u8; 16];
        for (i, d) in data.iter_mut().enumerate() {
            *d = i as u8;
        }
        let block = TestBlock::new(data);
        let repr = model.get_data_representation(&block, &idx(0)).unwrap();
        assert_eq!(repr.len(), 32);
        // Big-endian: first bytes are 0x00, 0x01, 0x02, 0x03, ...
        assert!(repr.starts_with("000102030405"));
    }

    // ---- BinaryFormatModel tests ----

    #[test]
    fn test_binary_format() {
        let model = BinaryFormatModel::new();
        let block = TestBlock::new(vec![0xA5]);
        assert_eq!(
            model.get_data_representation(&block, &idx(0)).unwrap(),
            "10100101"
        );
        assert_eq!(model.unit_byte_size(), 1);
        assert_eq!(model.data_unit_symbol_size(), 8);
    }

    #[test]
    fn test_binary_format_zero() {
        let model = BinaryFormatModel::new();
        let block = TestBlock::new(vec![0x00]);
        assert_eq!(
            model.get_data_representation(&block, &idx(0)).unwrap(),
            "00000000"
        );
    }

    #[test]
    fn test_binary_format_edit() {
        let model = BinaryFormatModel::new();
        let mut block = TestBlock::new(vec![0x00]);
        // Set bit 7 (leftmost) to 1
        assert!(model
            .replace_value(&mut block, &idx(0), 0, '1')
            .unwrap());
        assert_eq!(block.data[0], 0x80);
        // Set bit 0 (rightmost) to 1
        assert!(model
            .replace_value(&mut block, &idx(0), 7, '1')
            .unwrap());
        assert_eq!(block.data[0], 0x81);
    }

    // ---- OctalFormatModel tests ----

    #[test]
    fn test_octal_format() {
        let model = OctalFormatModel::new();
        let block = TestBlock::new(vec![0xFF]);
        assert_eq!(
            model.get_data_representation(&block, &idx(0)).unwrap(),
            "377"
        );
        assert_eq!(model.unit_byte_size(), 1);
        assert_eq!(model.data_unit_symbol_size(), 3);
    }

    #[test]
    fn test_octal_format_zero() {
        let model = OctalFormatModel::new();
        let block = TestBlock::new(vec![0x00]);
        assert_eq!(
            model.get_data_representation(&block, &idx(0)).unwrap(),
            "000"
        );
    }

    #[test]
    fn test_octal_format_edit() {
        let model = OctalFormatModel::new();
        let mut block = TestBlock::new(vec![0x00]);
        // Set to 377 octal = 0xFF
        model
            .replace_value(&mut block, &idx(0), 0, '3')
            .unwrap();
        assert_eq!(block.data[0], 0xC0);
        model
            .replace_value(&mut block, &idx(0), 1, '7')
            .unwrap();
        assert_eq!(block.data[0], 0xF8);
        model
            .replace_value(&mut block, &idx(0), 2, '7')
            .unwrap();
        assert_eq!(block.data[0], 0xFF);
    }

    #[test]
    fn test_octal_edit_first_digit_limit() {
        let model = OctalFormatModel::new();
        let mut block = TestBlock::new(vec![0x00]);
        // First digit cannot exceed 3
        assert!(!model
            .replace_value(&mut block, &idx(0), 0, '4')
            .unwrap());
    }

    // ---- IntegerFormatModel tests ----

    #[test]
    fn test_integer_format_positive() {
        let model = IntegerFormatModel::new();
        let block = TestBlock::new(vec![0x00, 0x00, 0x01, 0x00]);
        assert_eq!(
            model.get_data_representation(&block, &idx(0)).unwrap(),
            "        256"
        );
    }

    #[test]
    fn test_integer_format_negative() {
        let model = IntegerFormatModel::new();
        // -1 in big-endian i32
        let block = TestBlock::new(vec![0xFF, 0xFF, 0xFF, 0xFF]);
        let repr = model.get_data_representation(&block, &idx(0)).unwrap();
        assert!(repr.contains("-1"));
    }

    #[test]
    fn test_integer_format_no_edit() {
        // IntegerFormatModel does not implement MutableDataFormatModel
        let model = IntegerFormatModel::new();
        assert_eq!(model.unit_byte_size(), 4);
    }

    // ---- CharacterFormatModel tests ----

    #[test]
    fn test_char_format_printable() {
        let model = CharacterFormatModel::new();
        let block = TestBlock::new(vec![b'A', b'z', b'0']);
        assert_eq!(
            model.get_data_representation(&block, &idx(0)).unwrap(),
            "A"
        );
        assert_eq!(
            model.get_data_representation(&block, &idx(1)).unwrap(),
            "z"
        );
        assert_eq!(
            model.get_data_representation(&block, &idx(2)).unwrap(),
            "0"
        );
    }

    #[test]
    fn test_char_format_control() {
        let model = CharacterFormatModel::new();
        let block = TestBlock::new(vec![0x00, 0x0A, 0x7F]);
        assert_eq!(
            model.get_data_representation(&block, &idx(0)).unwrap(),
            "."
        );
        assert_eq!(
            model.get_data_representation(&block, &idx(1)).unwrap(),
            "."
        );
        assert_eq!(
            model.get_data_representation(&block, &idx(2)).unwrap(),
            "."
        );
    }

    #[test]
    fn test_char_format_edit() {
        let model = CharacterFormatModel::new();
        let mut block = TestBlock::new(vec![0x00]);
        assert!(model
            .replace_value(&mut block, &idx(0), 0, 'X')
            .unwrap());
        assert_eq!(block.data[0], b'X');
        // Control chars not allowed
        assert!(!model
            .replace_value(&mut block, &idx(0), 0, '\x01')
            .unwrap());
    }

    #[test]
    fn test_char_format_delimiter() {
        let model = CharacterFormatModel::new();
        assert_eq!(model.unit_delimiter_size(), 0);
    }

    // ---- DataFormat enum tests ----

    #[test]
    fn test_data_format_all_formats() {
        let formats = DataFormat::all_formats();
        assert_eq!(formats.len(), 9);
        let names: Vec<&str> = formats.iter().map(|f| f.name()).collect();
        assert!(names.contains(&"Hex"));
        assert!(names.contains(&"Hex Short"));
        assert!(names.contains(&"Hex Integer"));
        assert!(names.contains(&"Hex Long"));
        assert!(names.contains(&"Hex Long Long"));
        assert!(names.contains(&"Binary"));
        assert!(names.contains(&"Octal"));
        assert!(names.contains(&"Integer"));
        assert!(names.contains(&"Chars"));
    }

    #[test]
    fn test_data_format_representation() {
        let block = TestBlock::new(vec![0xFF]);
        let hex = DataFormat::Hex(HexFormatModel::new());
        assert_eq!(
            hex.get_data_representation(&block, &idx(0)).unwrap(),
            "ff"
        );
        assert_eq!(hex.unit_byte_size(), 1);
    }

    // ---- Pad utility tests ----

    #[test]
    fn test_pad_zero() {
        assert_eq!(HexFormatModel::pad_zero("a", 2), "0a");
        assert_eq!(HexFormatModel::pad_zero("ff", 2), "ff");
        assert_eq!(HexFormatModel::pad_zero("1", 4), "0001");
    }

    #[test]
    fn test_pad_space() {
        assert_eq!(
            <IntegerFormatModel as DataFormatModel>::pad("-1", 11, " "),
            "         -1"
        );
    }

    // ---- Error tests ----

    #[test]
    fn test_byte_block_access_error_display() {
        let err = ByteBlockAccessException("read failed".into());
        assert_eq!(
            format!("{}", err),
            "Byte block access error: read failed"
        );
    }

    // ---- Legacy model tests ----

    #[test]
    fn test_legacy_hex_model_output() {
        let model = hex_model();
        let data = [0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F];
        let row = model.format_row(0x1000, &data);
        assert!(row.contains("48"));
        assert!(row.contains("Hello Wo"));
    }

    #[test]
    fn test_legacy_hex_16bit_grouping() {
        let model = hex_16bit_model();
        let data = [0x48, 0x65, 0x6C, 0x6C];
        let row = model.format_row(0x1000, &data);
        assert!(row.contains("48"));
        assert!(row.contains("65"));
    }

    #[test]
    fn test_legacy_binary_model() {
        let model = binary_model();
        let data = [0xFF, 0x00, 0xA5];
        let row = model.format_row(0, &data);
        assert!(row.contains("11111111"));
        assert!(row.contains("00000000"));
        assert!(row.contains("10100101"));
    }

    #[test]
    fn test_legacy_all_models_returns_nonempty() {
        let models = all_models();
        assert!(!models.is_empty());
        for (name, model) in &models {
            let data = [0x41, 0x42];
            let _row = model.format_row(0, &data);
            assert!(!name.is_empty());
        }
    }

    #[test]
    fn test_legacy_octal_model() {
        let model = octal_model();
        let data = [0xFF, 0x00];
        let row = model.format_row(0, &data);
        assert!(row.contains("377"));
        assert!(row.contains("000"));
    }

    #[test]
    fn test_legacy_decimal_model() {
        let model = decimal_model();
        let data = [0xFF, 0x0A];
        let row = model.format_row(0, &data);
        assert!(row.contains("255"));
        assert!(row.contains(" 10"));
    }
}
