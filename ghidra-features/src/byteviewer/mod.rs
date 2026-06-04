//! Byte viewer module.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.byteviewer` Java package.
//!
//! Provides a model for displaying raw memory bytes in various formats
//! (hex, octal, decimal, binary) with support for byte blocks, format
//! selection, and field rendering.
//!
//! # Key types
//!
//! - [`ByteBlock`] -- a contiguous region of bytes with an address range
//! - [`ByteBlockSet`] -- a collection of byte blocks representing a program's memory
//! - [`FormatModel`] -- defines how bytes are formatted for display
//! - [`ByteField`] -- a single field within a byte display row

pub mod format;

use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// ByteBlock
// ---------------------------------------------------------------------------

/// A contiguous block of bytes in a program's memory space.
///
/// Ported from Ghidra's `ByteBlock` Java class.
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
}

impl ByteBlock {
    /// Create a new initialized byte block.
    pub fn new(
        name: impl Into<String>,
        start_address: u64,
        data: Vec<u8>,
    ) -> Self {
        Self {
            name: name.into(),
            start_address,
            data,
            initialized: true,
            readable: true,
            writable: false,
            executable: false,
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
        }
    }

    /// Create an executable code block.
    pub fn code_block(
        name: impl Into<String>,
        start_address: u64,
        data: Vec<u8>,
    ) -> Self {
        Self {
            name: name.into(),
            start_address,
            data,
            initialized: true,
            readable: true,
            writable: false,
            executable: true,
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

    /// Find the block containing the given address.
    pub fn block_at(&self, address: u64) -> Option<&ByteBlock> {
        self.blocks.iter().find(|b| b.contains(address))
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
}

// ---------------------------------------------------------------------------
// FormatModel
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
            let current = line.len()
                - if self.show_address { 10 } else { 0 };
            for _ in current..padded_width {
                line.push(' ');
            }
        }

        if self.show_ascii {
            line.push_str("  |");
            for &byte in bytes {
                if byte >= 0x20 && byte <= 0x7E {
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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_byte_field() {
        let field = ByteField::new(0x1000, 0xFF, ByteFormat::Hex, 0);
        assert_eq!(field.text, "FF");
        assert_eq!(field.address, 0x1000);
        assert!(!field.selected);
    }

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
        assert_eq!(
            AddressFormat::Segmented.format(0x0040_0100),
            "0040:0100"
        );
    }

    #[test]
    fn test_code_block() {
        let block = ByteBlock::code_block(".text", 0x1000, vec![0xCC]);
        assert!(block.is_executable());
        assert!(block.is_readable());
        assert!(!block.is_writable());
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
}
