//! BytesView Provider -- component provider for the byte viewer.
//!
//! Ported from Ghidra's
//! `ghidra.app.plugin.core.byteviewer.ProgramByteViewerComponentProvider`
//! and `ghidra.app.plugin.core.byteviewer.ByteViewerComponentProvider`.
//!
//! This module provides [`BytesViewProvider`], which owns the byte viewer
//! component, manages its connection to a program, tracks location/
//! selection/highlight state, and coordinates clipboard operations.
//!
//! In the Rust port, Swing-specific UI components (panels, decorators,
//! toolbars) are replaced with a pure-data representation of the view state.
//!
//! # Architecture
//!
//! ```text
//! BytesViewProvider
//!   ├── name / visible / disposed
//!   ├── program connection (program_name)
//!   ├── navigation state (location, selection, highlight)
//!   ├── byte viewer state (format, bytes_per_line, blocks)
//!   └── clipboard state
//! ```

use std::fmt;

// ---------------------------------------------------------------------------
// DisplayFormat
// ---------------------------------------------------------------------------

/// The format for displaying bytes in the provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisplayFormat {
    /// Hexadecimal (e.g. "FF 0A 1B").
    Hex,
    /// Octal (e.g. "377 012 033").
    Octal,
    /// Decimal (e.g. "255 10 27").
    Decimal,
    /// Binary (e.g. "11111111 00001010 00011011").
    Binary,
    /// Character (e.g. "..").
    Character,
}

impl DisplayFormat {
    /// Returns the human-readable name for this format.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Hex => "Hexadecimal",
            Self::Octal => "Octal",
            Self::Decimal => "Decimal",
            Self::Binary => "Binary",
            Self::Character => "Character",
        }
    }

    /// Formats a single byte.
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
        &[Self::Hex, Self::Octal, Self::Decimal, Self::Binary, Self::Character]
    }
}

impl Default for DisplayFormat {
    fn default() -> Self {
        Self::Hex
    }
}

impl fmt::Display for DisplayFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ---------------------------------------------------------------------------
// ProviderByteBlock -- a block of bytes managed by the provider
// ---------------------------------------------------------------------------

/// A contiguous region of bytes managed by the provider.
#[derive(Debug, Clone)]
pub struct ProviderByteBlock {
    /// Block name (e.g. ".text", ".data").
    name: String,
    /// Start address.
    start_address: u64,
    /// Raw byte data.
    data: Vec<u8>,
    /// Whether this block is initialized.
    initialized: bool,
    /// Whether this block is readable.
    readable: bool,
    /// Whether this block is writable.
    writable: bool,
    /// Whether this block is executable.
    executable: bool,
}

impl ProviderByteBlock {
    /// Creates a new initialized byte block.
    pub fn new(name: impl Into<String>, start_address: u64, data: Vec<u8>) -> Self {
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

    /// Creates an uninitialized byte block.
    pub fn uninitialized(name: impl Into<String>, start_address: u64, size: usize) -> Self {
        Self {
            name: name.into(),
            start_address,
            data: vec![0; size],
            initialized: false,
            readable: true,
            writable: false,
            executable: false,
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

    /// The block size in bytes.
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

    /// Sets permission flags.
    pub fn set_permissions(&mut self, readable: bool, writable: bool, executable: bool) {
        self.readable = readable;
        self.writable = writable;
        self.executable = executable;
    }

    /// Whether this block contains the given address.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.start_address && address < self.end_address()
    }

    /// Read a byte at the given offset within this block.
    pub fn byte_at(&self, offset: usize) -> Option<u8> {
        self.data.get(offset).copied()
    }

    /// Read a byte at the given absolute address.
    pub fn byte_at_address(&self, address: u64) -> Option<u8> {
        if self.contains(address) {
            let offset = (address - self.start_address) as usize;
            self.data.get(offset).copied()
        } else {
            None
        }
    }

    /// Returns a reference to the raw data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns a mutable reference to the raw data.
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

// ---------------------------------------------------------------------------
// SelectionRange -- a selection range within the byte viewer
// ---------------------------------------------------------------------------

/// A contiguous selection range identified by start/end addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionRange {
    /// Start address (inclusive).
    pub start: u64,
    /// End address (inclusive).
    pub end: u64,
}

impl SelectionRange {
    /// Creates a new selection range.
    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    /// The number of bytes in this range.
    pub fn length(&self) -> u64 {
        self.end - self.start + 1
    }

    /// Whether this range contains the given address.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.start && address <= self.end
    }
}

// ---------------------------------------------------------------------------
// ClipboardEntry -- clipboard data
// ---------------------------------------------------------------------------

/// A clipboard entry holding formatted byte data.
#[derive(Debug, Clone)]
pub struct ClipboardEntry {
    /// The text representation of the copied bytes.
    pub text: String,
    /// The raw bytes (if available).
    pub raw: Option<Vec<u8>>,
    /// The source address range.
    pub source_range: Option<SelectionRange>,
}

impl ClipboardEntry {
    /// Creates a text-only clipboard entry.
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            raw: None,
            source_range: None,
        }
    }

    /// Creates a clipboard entry with raw bytes.
    pub fn with_raw(text: impl Into<String>, raw: Vec<u8>) -> Self {
        Self {
            text: text.into(),
            raw: Some(raw),
            source_range: None,
        }
    }
}

// ---------------------------------------------------------------------------
// BytesViewProvider
// ---------------------------------------------------------------------------

/// The component provider for the byte viewer.
///
/// Manages the byte viewer's connection to a program, its display state
/// (format, blocks, cursor), navigation state (location, selection,
/// highlight), and clipboard operations.
///
/// Ported from `ProgramByteViewerComponentProvider` and
/// `ByteViewerComponentProvider`.
#[derive(Debug)]
pub struct BytesViewProvider {
    /// Provider name.
    name: String,
    /// Whether this is the connected (primary) provider.
    is_connected: bool,
    /// Whether the provider is currently visible.
    visible: bool,
    /// Whether the provider has been disposed.
    disposed: bool,
    /// The connected program name (if any).
    program_name: Option<String>,
    /// Current display format.
    format: DisplayFormat,
    /// Bytes per display line.
    bytes_per_line: usize,
    /// Byte blocks managed by this provider.
    blocks: Vec<ProviderByteBlock>,
    /// Current cursor address.
    cursor_address: Option<u64>,
    /// Current selection.
    selection: Vec<SelectionRange>,
    /// Current highlight.
    highlight: Vec<SelectionRange>,
    /// Whether to follow program location changes.
    follow_location: bool,
    /// Clipboard contents.
    clipboard: Option<ClipboardEntry>,
    /// Title bar text.
    title: String,
}

impl BytesViewProvider {
    /// Creates a new BytesView provider.
    pub fn new(name: impl Into<String>, is_connected: bool) -> Self {
        let name = name.into();
        Self {
            title: name.clone(),
            name,
            is_connected,
            visible: false,
            disposed: false,
            program_name: None,
            format: DisplayFormat::default(),
            bytes_per_line: 16,
            blocks: Vec::new(),
            cursor_address: None,
            selection: Vec::new(),
            highlight: Vec::new(),
            follow_location: true,
            clipboard: None,
        }
    }

    /// Returns the provider name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether this is the connected (primary) provider.
    pub fn is_connected(&self) -> bool {
        self.is_connected
    }

    /// Whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Sets visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Whether the provider has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Disposes the provider.
    pub fn dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        self.blocks.clear();
        self.selection.clear();
        self.highlight.clear();
        self.clipboard = None;
        self.program_name = None;
    }

    // ---- Program connection ----

    /// Connects this provider to a program.
    pub fn program_opened(&mut self, program_name: impl Into<String>) {
        self.program_name = Some(program_name.into());
        self.blocks.clear();
        self.cursor_address = None;
        self.selection.clear();
        self.highlight.clear();
        self.update_title();
    }

    /// Disconnects from the current program.
    pub fn program_closed(&mut self) {
        self.program_name = None;
        self.blocks.clear();
        self.cursor_address = None;
        self.selection.clear();
        self.highlight.clear();
        self.update_title();
    }

    /// The name of the connected program, if any.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    // ---- Display format ----

    /// Returns the current display format.
    pub fn format(&self) -> DisplayFormat {
        self.format
    }

    /// Sets the display format.
    pub fn set_format(&mut self, format: DisplayFormat) {
        self.format = format;
    }

    /// Returns the bytes per display line.
    pub fn bytes_per_line(&self) -> usize {
        self.bytes_per_line
    }

    /// Sets the bytes per display line.
    pub fn set_bytes_per_line(&mut self, n: usize) {
        self.bytes_per_line = n.max(1);
    }

    // ---- Byte blocks ----

    /// Adds a byte block to this provider.
    pub fn add_block(&mut self, block: ProviderByteBlock) {
        self.blocks.push(block);
    }

    /// Returns the number of byte blocks.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Returns a reference to the byte blocks.
    pub fn blocks(&self) -> &[ProviderByteBlock] {
        &self.blocks
    }

    /// Returns a mutable reference to the byte blocks.
    pub fn blocks_mut(&mut self) -> &mut Vec<ProviderByteBlock> {
        &mut self.blocks
    }

    /// Finds the block containing the given address.
    pub fn block_at(&self, address: u64) -> Option<&ProviderByteBlock> {
        self.blocks.iter().find(|b| b.contains(address))
    }

    /// Reads a byte at the given address across all blocks.
    pub fn read_byte(&self, address: u64) -> Option<u8> {
        for block in &self.blocks {
            if let Some(byte) = block.byte_at_address(address) {
                return Some(byte);
            }
        }
        None
    }

    /// Formats a range of bytes for display.
    pub fn format_range(&self, start: u64, end: u64) -> Vec<String> {
        let mut lines = Vec::new();
        for block in &self.blocks {
            if start >= block.start_address() && start < block.end_address() {
                let offset = (start - block.start_address()) as usize;
                let count = ((end - start) as usize).min(block.size() - offset);
                let data = &block.data()[offset..offset + count];
                for (i, chunk) in data.chunks(self.bytes_per_line).enumerate() {
                    let addr = start + (i * self.bytes_per_line) as u64;
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

    // ---- Cursor ----

    /// The current cursor address, if any.
    pub fn cursor_address(&self) -> Option<u64> {
        self.cursor_address
    }

    /// Sets the cursor address.
    pub fn set_cursor_address(&mut self, address: Option<u64>) {
        self.cursor_address = address;
    }

    // ---- Selection ----

    /// Returns a reference to the current selection ranges.
    pub fn selection(&self) -> &[SelectionRange] {
        &self.selection
    }

    /// Sets the selection to a single range.
    pub fn set_selection(&mut self, range: SelectionRange) {
        self.selection.clear();
        self.selection.push(range);
    }

    /// Clears the selection.
    pub fn clear_selection(&mut self) {
        self.selection.clear();
    }

    /// Adds a range to the selection.
    pub fn add_selection(&mut self, range: SelectionRange) {
        self.selection.push(range);
    }

    // ---- Highlight ----

    /// Returns a reference to the current highlight ranges.
    pub fn highlight(&self) -> &[SelectionRange] {
        &self.highlight
    }

    /// Sets the highlight to a single range.
    pub fn set_highlight(&mut self, range: SelectionRange) {
        self.highlight.clear();
        self.highlight.push(range);
    }

    /// Clears the highlight.
    pub fn clear_highlight(&mut self) {
        self.highlight.clear();
    }

    // ---- Follow location ----

    /// Whether the provider follows program location changes.
    pub fn follow_location(&self) -> bool {
        self.follow_location
    }

    /// Sets whether to follow location changes.
    pub fn set_follow_location(&mut self, follow: bool) {
        self.follow_location = follow;
    }

    // ---- Clipboard ----

    /// Copies the current selection to the clipboard.
    pub fn copy_selection(&mut self) -> Option<&ClipboardEntry> {
        if self.selection.is_empty() {
            return None;
        }
        let range = &self.selection[0];
        let mut text = String::new();
        let mut raw = Vec::new();
        for addr in range.start..=range.end {
            if let Some(byte) = self.read_byte(addr) {
                text.push_str(&self.format.format_byte(byte));
                text.push(' ');
                raw.push(byte);
            }
        }
        self.clipboard = Some(ClipboardEntry::with_raw(text.trim(), raw));
        self.clipboard.as_ref()
    }

    /// Returns a reference to the current clipboard contents.
    pub fn clipboard(&self) -> Option<&ClipboardEntry> {
        self.clipboard.as_ref()
    }

    /// Clears the clipboard.
    pub fn clear_clipboard(&mut self) {
        self.clipboard = None;
    }

    // ---- Title ----

    /// Returns the current title text.
    pub fn title(&self) -> &str {
        &self.title
    }

    fn update_title(&mut self) {
        self.title = if let Some(ref prog) = self.program_name {
            format!("Bytes: {}", prog)
        } else {
            "Bytes".to_string()
        };
    }

    // ---- Configuration persistence ----

    /// Writes configuration state.
    pub fn write_config_state(
        &self,
        store: &mut std::collections::HashMap<String, super::bytes_plugin::ConfigValue>,
    ) {
        store.insert(
            "bytes_per_line".into(),
            super::bytes_plugin::ConfigValue::Int(self.bytes_per_line as i32),
        );
        store.insert(
            "format".into(),
            super::bytes_plugin::ConfigValue::String(self.format.display_name().to_string()),
        );
        store.insert(
            "follow_location".into(),
            super::bytes_plugin::ConfigValue::Bool(self.follow_location),
        );
    }

    /// Reads configuration state.
    pub fn read_config_state(
        &mut self,
        store: &std::collections::HashMap<String, super::bytes_plugin::ConfigValue>,
    ) {
        if let Some(super::bytes_plugin::ConfigValue::Int(n)) = store.get("bytes_per_line") {
            self.bytes_per_line = (*n as usize).max(1);
        }
        if let Some(super::bytes_plugin::ConfigValue::Bool(follow)) = store.get("follow_location")
        {
            self.follow_location = *follow;
        }
        if let Some(super::bytes_plugin::ConfigValue::String(fmt_str)) = store.get("format") {
            self.format = match fmt_str.as_str() {
                "Octal" => DisplayFormat::Octal,
                "Decimal" => DisplayFormat::Decimal,
                "Binary" => DisplayFormat::Binary,
                "Character" => DisplayFormat::Character,
                _ => DisplayFormat::Hex,
            };
        }
    }
}

impl Default for BytesViewProvider {
    fn default() -> Self {
        Self::new("Bytes", true)
    }
}

impl fmt::Display for BytesViewProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BytesViewProvider({}, connected={}, blocks={}, program={:?})",
            self.name,
            self.is_connected,
            self.blocks.len(),
            self.program_name
        )
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = BytesViewProvider::new("TestProvider", true);
        assert_eq!(provider.name(), "TestProvider");
        assert!(provider.is_connected());
        assert!(!provider.is_visible());
        assert!(!provider.is_disposed());
        assert!(provider.program_name().is_none());
        assert_eq!(provider.format(), DisplayFormat::Hex);
        assert_eq!(provider.bytes_per_line(), 16);
    }

    #[test]
    fn test_provider_disconnected() {
        let provider = BytesViewProvider::new("Snapshot", false);
        assert!(!provider.is_connected());
    }

    #[test]
    fn test_provider_visibility() {
        let mut provider = BytesViewProvider::new("Test", true);
        provider.set_visible(true);
        assert!(provider.is_visible());
        provider.set_visible(false);
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_provider_dispose() {
        let mut provider = BytesViewProvider::new("Test", true);
        provider.program_opened("test.exe");
        provider.dispose();
        assert!(provider.is_disposed());
        assert!(provider.program_name().is_none());
        assert_eq!(provider.block_count(), 0);
    }

    #[test]
    fn test_program_connection() {
        let mut provider = BytesViewProvider::new("Test", true);
        provider.program_opened("test.exe");
        assert_eq!(provider.program_name(), Some("test.exe"));
        assert_eq!(provider.title(), "Bytes: test.exe");

        provider.program_closed();
        assert!(provider.program_name().is_none());
        assert_eq!(provider.title(), "Bytes");
    }

    #[test]
    fn test_display_format() {
        let mut provider = BytesViewProvider::new("Test", true);
        provider.set_format(DisplayFormat::Octal);
        assert_eq!(provider.format(), DisplayFormat::Octal);
        assert_eq!(provider.format().display_name(), "Octal");
    }

    #[test]
    fn test_format_byte() {
        assert_eq!(DisplayFormat::Hex.format_byte(0xFF), "FF");
        assert_eq!(DisplayFormat::Octal.format_byte(255), "377");
        assert_eq!(DisplayFormat::Decimal.format_byte(255), "255");
        assert_eq!(DisplayFormat::Binary.format_byte(0xFF), "11111111");
        assert_eq!(DisplayFormat::Character.format_byte(b'A'), "A");
        assert_eq!(DisplayFormat::Character.format_byte(0x01), ".");
    }

    #[test]
    fn test_display_format_all() {
        assert_eq!(DisplayFormat::all().len(), 5);
    }

    #[test]
    fn test_provider_blocks() {
        let mut provider = BytesViewProvider::new("Test", true);
        provider.add_block(ProviderByteBlock::new(".text", 0x401000, vec![0x55, 0x89, 0xE5]));
        provider.add_block(ProviderByteBlock::new(".data", 0x402000, vec![0x01, 0x02]));
        assert_eq!(provider.block_count(), 2);
        assert!(provider.block_at(0x401000).is_some());
        assert!(provider.block_at(0x402000).is_some());
        assert!(provider.block_at(0x403000).is_none());
    }

    #[test]
    fn test_read_byte() {
        let mut provider = BytesViewProvider::new("Test", true);
        provider.add_block(ProviderByteBlock::new(".text", 0x401000, vec![0x55, 0x89]));
        assert_eq!(provider.read_byte(0x401000), Some(0x55));
        assert_eq!(provider.read_byte(0x401001), Some(0x89));
        assert_eq!(provider.read_byte(0x401002), None);
    }

    #[test]
    fn test_format_range() {
        let mut provider = BytesViewProvider::new("Test", true);
        provider.add_block(ProviderByteBlock::new(
            ".text",
            0x401000,
            vec![0x55, 0x89, 0xE5, 0x83, 0xEC, 0x10],
        ));
        provider.set_bytes_per_line(3);
        let lines = provider.format_range(0x401000, 0x401006);
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn test_cursor() {
        let mut provider = BytesViewProvider::new("Test", true);
        assert!(provider.cursor_address().is_none());
        provider.set_cursor_address(Some(0x401000));
        assert_eq!(provider.cursor_address(), Some(0x401000));
    }

    #[test]
    fn test_selection() {
        let mut provider = BytesViewProvider::new("Test", true);
        assert!(provider.selection().is_empty());

        provider.set_selection(SelectionRange::new(0x401000, 0x40100F));
        assert_eq!(provider.selection().len(), 1);
        assert!(provider.selection()[0].contains(0x401005));

        provider.add_selection(SelectionRange::new(0x402000, 0x40200F));
        assert_eq!(provider.selection().len(), 2);

        provider.clear_selection();
        assert!(provider.selection().is_empty());
    }

    #[test]
    fn test_highlight() {
        let mut provider = BytesViewProvider::new("Test", true);
        provider.set_highlight(SelectionRange::new(0x401000, 0x40100F));
        assert_eq!(provider.highlight().len(), 1);
        provider.clear_highlight();
        assert!(provider.highlight().is_empty());
    }

    #[test]
    fn test_follow_location() {
        let mut provider = BytesViewProvider::new("Test", true);
        assert!(provider.follow_location());
        provider.set_follow_location(false);
        assert!(!provider.follow_location());
    }

    #[test]
    fn test_clipboard() {
        let mut provider = BytesViewProvider::new("Test", true);
        provider.add_block(ProviderByteBlock::new(".text", 0x401000, vec![0x55, 0x89, 0xE5]));
        provider.set_selection(SelectionRange::new(0x401000, 0x401002));
        let entry = provider.copy_selection().unwrap();
        assert!(!entry.text.is_empty());
        assert!(entry.raw.is_some());
        assert_eq!(entry.raw.as_ref().unwrap().len(), 3);
    }

    #[test]
    fn test_clipboard_empty() {
        let mut provider = BytesViewProvider::new("Test", true);
        assert!(provider.copy_selection().is_none());
    }

    #[test]
    fn test_byte_block() {
        let block = ProviderByteBlock::new(".text", 0x401000, vec![0x55, 0x89, 0xE5]);
        assert_eq!(block.name(), ".text");
        assert_eq!(block.start_address(), 0x401000);
        assert_eq!(block.end_address(), 0x401003);
        assert_eq!(block.size(), 3);
        assert!(block.is_initialized());
        assert!(block.contains(0x401000));
        assert!(!block.contains(0x401003));
    }

    #[test]
    fn test_byte_block_uninitialized() {
        let block = ProviderByteBlock::uninitialized("stack", 0x7FFF0000, 0x10000);
        assert!(!block.is_initialized());
        assert_eq!(block.size(), 0x10000);
    }

    #[test]
    fn test_byte_block_permissions() {
        let mut block = ProviderByteBlock::new(".text", 0x401000, vec![0x55]);
        block.set_permissions(true, false, true);
        assert!(block.is_readable());
        assert!(!block.is_writable());
        assert!(block.is_executable());
    }

    #[test]
    fn test_selection_range() {
        let range = SelectionRange::new(0x1000, 0x100F);
        assert_eq!(range.length(), 16);
        assert!(range.contains(0x1005));
        assert!(!range.contains(0x1010));
    }

    #[test]
    fn test_config_persistence() {
        let mut provider = BytesViewProvider::new("Test", true);
        provider.set_bytes_per_line(32);
        provider.set_format(DisplayFormat::Binary);
        provider.set_follow_location(false);

        let mut store = std::collections::HashMap::new();
        provider.write_config_state(&mut store);

        let mut provider2 = BytesViewProvider::new("Test2", true);
        provider2.read_config_state(&store);
        assert_eq!(provider2.bytes_per_line(), 32);
        assert_eq!(provider2.format(), DisplayFormat::Binary);
        assert!(!provider2.follow_location());
    }

    #[test]
    fn test_default() {
        let provider = BytesViewProvider::default();
        assert_eq!(provider.name(), "Bytes");
        assert!(provider.is_connected());
    }

    #[test]
    fn test_display() {
        let provider = BytesViewProvider::new("Test", true);
        let s = format!("{}", provider);
        assert!(s.contains("Test"));
        assert!(s.contains("connected=true"));
    }
}
