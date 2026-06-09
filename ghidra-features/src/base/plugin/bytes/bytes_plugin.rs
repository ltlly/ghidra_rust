//! Bytes Plugin -- displays raw memory bytes in various formats.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.byteviewer` and
//! `ghidra.app.plugin.core.format` packages.
//!
//! This module provides the bytes plugin that displays raw memory bytes
//! in various formats (hex, octal, decimal, binary, character). Supports
//! byte editing, format selection, and display configuration.
//!
//! # Architecture
//!
//! ```text
//! BytesPlugin
//!   ├── ByteViewerProvider (display component)
//!   ├── FormatModel (display format)
//!   ├── ByteBlockManager (memory block management)
//!   └── ByteEditManager (byte editing)
//! ```
//!
//! # Example
//!
//! ```
//! use ghidra_features::base::plugin::bytes::bytes_plugin::BytesPlugin;
//!
//! let mut plugin = BytesPlugin::new("Bytes");
//! plugin.init();
//! assert_eq!(plugin.name(), "Bytes");
//! ```

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// DisplayFormat -- byte display formats
// ---------------------------------------------------------------------------

/// The format for displaying bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisplayFormat {
    /// Hexadecimal format (e.g., "FF 0A 1B").
    Hex,
    /// Octal format (e.g., "377 012 033").
    Octal,
    /// Decimal format (e.g., "255 10 27").
    Decimal,
    /// Binary format (e.g., "11111111 00001010 00011011").
    Binary,
    /// Character format (e.g., "..").
    Character,
}

impl DisplayFormat {
    /// Returns the display name for this format.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Hex => "Hexadecimal",
            Self::Octal => "Octal",
            Self::Decimal => "Decimal",
            Self::Binary => "Binary",
            Self::Character => "Character",
        }
    }

    /// Returns the default column width for this format.
    pub fn default_column_width(&self) -> usize {
        match self {
            Self::Hex => 2,
            Self::Octal => 3,
            Self::Decimal => 3,
            Self::Binary => 8,
            Self::Character => 1,
        }
    }

    /// Formats a single byte in this format.
    pub fn format_byte(&self, byte: u8) -> String {
        match self {
            Self::Hex => format!("{:02X}", byte),
            Self::Octal => format!("{:03o}", byte),
            Self::Decimal => format!("{:3}", byte),
            Self::Binary => format!("{:08b}", byte),
            Self::Character => {
                if byte.is_ascii_graphic() || byte == b' ' {
                    (byte as char).to_string()
                } else {
                    ".".to_string()
                }
            }
        }
    }

    /// Returns all available formats.
    pub fn all() -> &'static [DisplayFormat] {
        &[
            Self::Hex,
            Self::Octal,
            Self::Decimal,
            Self::Binary,
            Self::Character,
        ]
    }
}

impl fmt::Display for DisplayFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ---------------------------------------------------------------------------
// ByteBlock -- a contiguous block of bytes
// ---------------------------------------------------------------------------

/// A contiguous block of bytes in memory.
///
/// Ported from Ghidra's `ByteBlock` Java class.
#[derive(Debug, Clone)]
pub struct ByteBlock {
    /// The block name.
    name: String,
    /// The start address.
    start_address: u64,
    /// The raw bytes.
    data: Vec<u8>,
    /// Whether this block is initialized.
    initialized: bool,
    /// Whether this block is readable.
    readable: bool,
    /// Whether this block is writable.
    writable: bool,
}

impl ByteBlock {
    /// Creates a new byte block.
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
        }
    }

    /// Creates an uninitialized byte block.
    pub fn uninitialized(name: impl Into<String>, start_address: u64, size: usize) -> Self {
        Self {
            name: name.into(),
            start_address,
            data: vec![0; size],
            initialized: false,
            readable: true,
            writable: false,
        }
    }

    /// Returns the block name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the start address.
    pub fn start_address(&self) -> u64 {
        self.start_address
    }

    /// Returns the end address.
    pub fn end_address(&self) -> u64 {
        self.start_address + self.data.len() as u64
    }

    /// Returns the size of the block.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Returns a reference to the block data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns a mutable reference to the block data.
    pub fn data_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }

    /// Returns whether this block is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns whether this block is readable.
    pub fn is_readable(&self) -> bool {
        self.readable
    }

    /// Returns whether this block is writable.
    pub fn is_writable(&self) -> bool {
        self.writable
    }

    /// Sets the readable flag.
    pub fn set_readable(&mut self, readable: bool) {
        self.readable = readable;
    }

    /// Sets the writable flag.
    pub fn set_writable(&mut self, writable: bool) {
        self.writable = writable;
    }

    /// Reads a byte at the given offset.
    pub fn read_byte(&self, offset: usize) -> Option<u8> {
        self.data.get(offset).copied()
    }

    /// Writes a byte at the given offset.
    pub fn write_byte(&mut self, offset: usize, value: u8) -> bool {
        if offset < self.data.len() {
            self.data[offset] = value;
            true
        } else {
            false
        }
    }

    /// Returns a formatted string of the block data.
    pub fn format(&self, format: DisplayFormat, bytes_per_row: usize) -> Vec<String> {
        let mut lines = Vec::new();
        for (i, chunk) in self.data.chunks(bytes_per_row).enumerate() {
            let addr = self.start_address + (i * bytes_per_row) as u64;
            let hex: Vec<String> = chunk.iter().map(|b| format.format_byte(*b)).collect();
            let separator = match format {
                DisplayFormat::Binary => "  ",
                _ => " ",
            };
            lines.push(format!("{:08X}  {}", addr, hex.join(separator)));
        }
        lines
    }
}

// ---------------------------------------------------------------------------
// BytesPlugin -- the main plugin
// ---------------------------------------------------------------------------

/// The bytes plugin.
///
/// Displays raw memory bytes in various formats. Supports byte editing,
/// format selection, and display configuration.
///
/// Ported from Ghidra's byte viewer and format plugin Java classes.
#[derive(Debug)]
pub struct BytesPlugin {
    /// The plugin name.
    name: String,
    /// Memory blocks by name.
    blocks: HashMap<String, ByteBlock>,
    /// Current display format.
    format: DisplayFormat,
    /// Bytes per row.
    bytes_per_row: usize,
    /// Whether the plugin is initialized.
    initialized: bool,
    /// Whether the plugin is disposed.
    disposed: bool,
    /// Plugin options.
    options: HashMap<String, BytesOption>,
}

/// A bytes plugin option.
#[derive(Debug, Clone)]
pub enum BytesOption {
    /// Boolean option.
    Bool(bool),
    /// Integer option.
    Int(i32),
    /// String option.
    String(String),
}

impl fmt::Display for BytesOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(v) => write!(f, "{}", v),
            Self::Int(v) => write!(f, "{}", v),
            Self::String(v) => write!(f, "{}", v),
        }
    }
}

impl BytesPlugin {
    /// Creates a new bytes plugin.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            blocks: HashMap::new(),
            format: DisplayFormat::Hex,
            bytes_per_row: 16,
            initialized: false,
            disposed: false,
            options: HashMap::new(),
        }
    }

    /// Returns the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Initializes the plugin.
    pub fn init(&mut self) {
        if self.initialized {
            return;
        }
        self.initialized = true;
    }

    /// Disposes the plugin.
    pub fn dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        self.blocks.clear();
    }

    /// Returns whether the plugin is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns whether the plugin is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Adds a byte block.
    pub fn add_block(&mut self, block: ByteBlock) {
        self.blocks.insert(block.name.clone(), block);
    }

    /// Returns a reference to a byte block by name.
    pub fn block(&self, name: &str) -> Option<&ByteBlock> {
        self.blocks.get(name)
    }

    /// Returns a mutable reference to a byte block by name.
    pub fn block_mut(&mut self, name: &str) -> Option<&mut ByteBlock> {
        self.blocks.get_mut(name)
    }

    /// Returns the number of byte blocks.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Returns all block names.
    pub fn block_names(&self) -> Vec<&str> {
        self.blocks.keys().map(|s| s.as_str()).collect()
    }

    /// Removes a byte block by name.
    pub fn remove_block(&mut self, name: &str) -> Option<ByteBlock> {
        self.blocks.remove(name)
    }

    /// Sets the display format.
    pub fn set_format(&mut self, format: DisplayFormat) {
        self.format = format;
    }

    /// Returns the current display format.
    pub fn format(&self) -> DisplayFormat {
        self.format
    }

    /// Sets the bytes per row.
    pub fn set_bytes_per_row(&mut self, bytes_per_row: usize) {
        self.bytes_per_row = bytes_per_row.max(1);
    }

    /// Returns the bytes per row.
    pub fn bytes_per_row(&self) -> usize {
        self.bytes_per_row
    }

    /// Reads a byte at the given address.
    pub fn read_byte(&self, address: u64) -> Option<u8> {
        for block in self.blocks.values() {
            if address >= block.start_address() && address < block.end_address() {
                let offset = (address - block.start_address()) as usize;
                return block.read_byte(offset);
            }
        }
        None
    }

    /// Writes a byte at the given address.
    pub fn write_byte(&mut self, address: u64, value: u8) -> bool {
        for block in self.blocks.values_mut() {
            if address >= block.start_address() && address < block.end_address() {
                let offset = (address - block.start_address()) as usize;
                return block.write_byte(offset, value);
            }
        }
        false
    }

    /// Formats the bytes at the given address range.
    pub fn format_range(&self, start: u64, end: u64) -> Vec<String> {
        let mut lines = Vec::new();
        for block in self.blocks.values() {
            if start >= block.start_address() && start < block.end_address() {
                let offset = (start - block.start_address()) as usize;
                let count = ((end - start) as usize).min(block.size() - offset);
                let data = &block.data()[offset..offset + count];
                for (i, chunk) in data.chunks(self.bytes_per_row).enumerate() {
                    let addr = start + (i * self.bytes_per_row) as u64;
                    let formatted: Vec<String> =
                        chunk.iter().map(|b| self.format.format_byte(*b)).collect();
                    let separator = match self.format {
                        DisplayFormat::Binary => "  ",
                        _ => " ",
                    };
                    lines.push(format!("{:08X}  {}", addr, formatted.join(separator)));
                }
                break;
            }
        }
        lines
    }

    /// Sets a plugin option.
    pub fn set_option(&mut self, key: impl Into<String>, value: BytesOption) {
        self.options.insert(key.into(), value);
    }

    /// Gets a plugin option.
    pub fn get_option(&self, key: &str) -> Option<&BytesOption> {
        self.options.get(key)
    }
}

impl Default for BytesPlugin {
    fn default() -> Self {
        Self::new("BytesPlugin")
    }
}

impl fmt::Display for BytesPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BytesPlugin({}, blocks={})", self.name, self.block_count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = BytesPlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert_eq!(plugin.block_count(), 0);
        assert_eq!(plugin.format(), DisplayFormat::Hex);
        assert_eq!(plugin.bytes_per_row(), 16);
    }

    #[test]
    fn test_byte_block() {
        let block = ByteBlock::new(".text", 0x401000, vec![0x55, 0x89, 0xE5]);
        assert_eq!(block.name(), ".text");
        assert_eq!(block.start_address(), 0x401000);
        assert_eq!(block.end_address(), 0x401003);
        assert_eq!(block.size(), 3);
        assert!(block.is_initialized());
    }

    #[test]
    fn test_display_format() {
        assert_eq!(DisplayFormat::Hex.format_byte(0xFF), "FF");
        assert_eq!(DisplayFormat::Octal.format_byte(255), "377");
        assert_eq!(DisplayFormat::Decimal.format_byte(255), "255");
        assert_eq!(DisplayFormat::Binary.format_byte(0xFF), "11111111");
        assert_eq!(DisplayFormat::Character.format_byte(b'A'), "A");
        assert_eq!(DisplayFormat::Character.format_byte(0x01), ".");
    }

    #[test]
    fn test_plugin_blocks() {
        let mut plugin = BytesPlugin::new("TestPlugin");
        let block = ByteBlock::new(".text", 0x401000, vec![0x55, 0x89, 0xE5]);
        plugin.add_block(block);
        assert_eq!(plugin.block_count(), 1);
        assert!(plugin.block(".text").is_some());
        assert_eq!(plugin.read_byte(0x401000), Some(0x55));
    }

    #[test]
    fn test_write_byte() {
        let mut plugin = BytesPlugin::new("TestPlugin");
        let block = ByteBlock::new(".text", 0x401000, vec![0x55, 0x89, 0xE5]);
        plugin.add_block(block);
        assert!(plugin.write_byte(0x401000, 0x90));
        assert_eq!(plugin.read_byte(0x401000), Some(0x90));
    }

    #[test]
    fn test_format_range() {
        let mut plugin = BytesPlugin::new("TestPlugin");
        let block = ByteBlock::new(".text", 0x401000, vec![0x55, 0x89, 0xE5, 0x83, 0xEC, 0x10]);
        plugin.add_block(block);
        plugin.set_bytes_per_row(3);
        let lines = plugin.format_range(0x401000, 0x401006);
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn test_init_dispose() {
        let mut plugin = BytesPlugin::new("TestPlugin");
        plugin.init();
        assert!(plugin.is_initialized());
        plugin.dispose();
        assert!(plugin.is_disposed());
    }
}
