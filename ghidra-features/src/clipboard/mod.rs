//! Clipboard Operations -- copy/paste code units and data.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.clipboard` Java package.
//!
//! Provides logic for copying and pasting code units (instructions and data)
//! between address ranges. Supports multiple clipboard formats, content
//! providers, and a program transferable model for structured clipboard
//! data exchange.
//!
//! # Key Types
//!
//! - [`ClipboardFormat`] -- the format of data on the clipboard
//! - [`ClipboardEntry`] -- a single clipboard entry with format and data
//! - [`ProgramTransferable`] -- structured clipboard data with metadata
//! - [`ClipboardManager`] -- manages clipboard history and content

use ghidra_core::Address;

/// The format of data on the clipboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClipboardFormat {
    /// Raw bytes.
    Bytes,
    /// Text representation (listing format).
    Text,
    /// Hex string.
    Hex,
    /// Assembly source text.
    Assembly,
    /// XML representation.
    Xml,
    /// Address string (address table).
    AddressTable,
}

impl ClipboardFormat {
    /// Display name for this format.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Bytes => "Bytes",
            Self::Text => "Text",
            Self::Hex => "Hex",
            Self::Assembly => "Assembly",
            Self::Xml => "XML",
            Self::AddressTable => "Address Table",
        }
    }
}

/// A single clipboard entry.
#[derive(Debug, Clone)]
pub struct ClipboardEntry {
    /// The source address range start.
    pub source_start: Address,
    /// The source address range end.
    pub source_end: Address,
    /// The data bytes.
    pub data: Vec<u8>,
    /// The text representation.
    pub text: String,
    /// The format of this entry.
    pub format: ClipboardFormat,
}

impl ClipboardEntry {
    /// Create a new clipboard entry from bytes.
    pub fn from_bytes(start: Address, end: Address, data: Vec<u8>) -> Self {
        let hex: String = data.iter().map(|b| format!("{:02x}", b)).collect();
        Self {
            source_start: start,
            source_end: end,
            data,
            text: hex,
            format: ClipboardFormat::Bytes,
        }
    }

    /// Create a new clipboard entry from text.
    pub fn from_text(start: Address, end: Address, text: String) -> Self {
        Self {
            source_start: start,
            source_end: end,
            data: Vec::new(),
            text,
            format: ClipboardFormat::Text,
        }
    }

    /// Create a new clipboard entry from hex string.
    pub fn from_hex(start: Address, end: Address, hex: &str) -> Self {
        let data: Vec<u8> = hex
            .split(|c: char| c.is_whitespace() || c == ',')
            .filter(|s| !s.is_empty())
            .filter_map(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .collect();
        Self {
            source_start: start,
            source_end: end,
            data,
            text: hex.to_string(),
            format: ClipboardFormat::Hex,
        }
    }

    /// Get the hex representation of the bytes.
    pub fn as_hex(&self) -> String {
        self.data
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The number of bytes in this entry.
    pub fn byte_count(&self) -> usize {
        self.data.len()
    }

    /// The address range size.
    pub fn address_range_size(&self) -> u64 {
        self.source_end.offset.saturating_sub(self.source_start.offset) + 1
    }
}

// ---------------------------------------------------------------------------
// ProgramTransferable -- structured clipboard data with metadata
// ---------------------------------------------------------------------------

/// Structured clipboard data representing a program transfer.
///
/// Ported from the `ProgramTransferable` concept in `clipboard` package.
#[derive(Debug, Clone)]
pub struct ProgramTransferable {
    /// The source program name.
    pub source_program: String,
    /// The clipboard entries.
    entries: Vec<ClipboardEntry>,
    /// The preferred format for paste operations.
    pub preferred_format: ClipboardFormat,
}

impl ProgramTransferable {
    /// Create a new program transferable.
    pub fn new(source_program: impl Into<String>, preferred_format: ClipboardFormat) -> Self {
        Self {
            source_program: source_program.into(),
            entries: Vec::new(),
            preferred_format,
        }
    }

    /// Add an entry.
    pub fn add_entry(&mut self, entry: ClipboardEntry) {
        self.entries.push(entry);
    }

    /// Get all entries.
    pub fn entries(&self) -> &[ClipboardEntry] {
        &self.entries
    }

    /// Get total byte count across all entries.
    pub fn total_bytes(&self) -> usize {
        self.entries.iter().map(|e| e.byte_count()).sum()
    }

    /// Whether this transferable has data.
    pub fn has_data(&self) -> bool {
        !self.entries.is_empty()
    }

    /// Get entries matching a specific format.
    pub fn entries_with_format(&self, format: ClipboardFormat) -> Vec<&ClipboardEntry> {
        self.entries.iter().filter(|e| e.format == format).collect()
    }
}

// ---------------------------------------------------------------------------
// ClipboardManager
// ---------------------------------------------------------------------------

/// Clipboard manager for code units with history.
///
/// Ported from the clipboard plugin management logic.
#[derive(Debug, Default)]
pub struct ClipboardManager {
    entries: Vec<ClipboardEntry>,
    /// Maximum history size.
    max_history: usize,
}

impl ClipboardManager {
    /// Create a new clipboard manager.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            max_history: 32,
        }
    }

    /// Create a clipboard manager with a custom history limit.
    pub fn with_max_history(max_history: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_history,
        }
    }

    /// Copy a byte range to the clipboard.
    pub fn copy_bytes(&mut self, start: Address, end: Address, data: Vec<u8>) {
        self.push_entry(ClipboardEntry::from_bytes(start, end, data));
    }

    /// Copy text to the clipboard.
    pub fn copy_text(&mut self, start: Address, end: Address, text: String) {
        self.push_entry(ClipboardEntry::from_text(start, end, text));
    }

    /// Copy from hex string.
    pub fn copy_hex(&mut self, start: Address, end: Address, hex: &str) {
        self.push_entry(ClipboardEntry::from_hex(start, end, hex));
    }

    /// Get the most recent clipboard entry.
    pub fn peek(&self) -> Option<&ClipboardEntry> {
        self.entries.last()
    }

    /// Pop the most recent clipboard entry.
    pub fn pop(&mut self) -> Option<ClipboardEntry> {
        self.entries.pop()
    }

    /// Get the clipboard entry count.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Get entry by index (0 = oldest).
    pub fn get_entry(&self, index: usize) -> Option<&ClipboardEntry> {
        self.entries.get(index)
    }

    /// Clear the clipboard.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Get the maximum history size.
    pub fn max_history(&self) -> usize {
        self.max_history
    }

    fn push_entry(&mut self, entry: ClipboardEntry) {
        if self.entries.len() >= self.max_history {
            self.entries.remove(0);
        }
        self.entries.push(entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_copy_and_peek() {
        let mut mgr = ClipboardManager::new();
        mgr.copy_bytes(Address::new(0x1000), Address::new(0x1003), vec![0x48, 0x89, 0xD8]);
        let entry = mgr.peek().unwrap();
        assert_eq!(entry.data, vec![0x48, 0x89, 0xD8]);
        assert_eq!(entry.as_hex(), "48 89 D8");
    }

    #[test]
    fn test_copy_text() {
        let mut mgr = ClipboardManager::new();
        mgr.copy_text(
            Address::new(0x1000),
            Address::new(0x1003),
            "mov rax, rbx".into(),
        );
        let entry = mgr.peek().unwrap();
        assert_eq!(entry.format, ClipboardFormat::Text);
    }

    #[test]
    fn test_pop() {
        let mut mgr = ClipboardManager::new();
        mgr.copy_bytes(Address::new(0x1000), Address::new(0x1000), vec![0x90]);
        assert_eq!(mgr.entry_count(), 1);
        let entry = mgr.pop().unwrap();
        assert_eq!(entry.data, vec![0x90]);
        assert_eq!(mgr.entry_count(), 0);
    }

    #[test]
    fn test_clear() {
        let mut mgr = ClipboardManager::new();
        mgr.copy_bytes(Address::new(0x1000), Address::new(0x1000), vec![0x90]);
        mgr.clear();
        assert_eq!(mgr.entry_count(), 0);
    }

    #[test]
    fn test_copy_hex() {
        let mut mgr = ClipboardManager::new();
        mgr.copy_hex(Address::new(0x1000), Address::new(0x1003), "48 89 D8");
        let entry = mgr.peek().unwrap();
        assert_eq!(entry.data, vec![0x48, 0x89, 0xD8]);
        assert_eq!(entry.format, ClipboardFormat::Hex);
    }

    #[test]
    fn test_clipboard_format_display() {
        assert_eq!(ClipboardFormat::Bytes.display_name(), "Bytes");
        assert_eq!(ClipboardFormat::Assembly.display_name(), "Assembly");
        assert_eq!(ClipboardFormat::Xml.display_name(), "XML");
    }

    #[test]
    fn test_entry_byte_count() {
        let entry = ClipboardEntry::from_bytes(
            Address::new(0x1000),
            Address::new(0x1003),
            vec![0x48, 0x89, 0xD8, 0xC3],
        );
        assert_eq!(entry.byte_count(), 4);
        assert_eq!(entry.address_range_size(), 4);
    }

    #[test]
    fn test_entry_from_hex_with_prefix() {
        let entry = ClipboardEntry::from_hex(
            Address::new(0x1000),
            Address::new(0x1003),
            "0x48, 0x89, 0xD8, 0xC3",
        );
        assert_eq!(entry.data, vec![0x48, 0x89, 0xD8, 0xC3]);
    }

    #[test]
    fn test_max_history() {
        let mut mgr = ClipboardManager::with_max_history(2);
        mgr.copy_bytes(Address::new(0x1000), Address::new(0x1000), vec![1]);
        mgr.copy_bytes(Address::new(0x2000), Address::new(0x2000), vec![2]);
        mgr.copy_bytes(Address::new(0x3000), Address::new(0x3000), vec![3]);
        assert_eq!(mgr.entry_count(), 2);
        // oldest entry was evicted
        assert_eq!(mgr.get_entry(0).unwrap().data, vec![2]);
        assert_eq!(mgr.get_entry(1).unwrap().data, vec![3]);
    }

    #[test]
    fn test_program_transferable() {
        let mut pt = ProgramTransferable::new("my_program", ClipboardFormat::Bytes);
        pt.add_entry(ClipboardEntry::from_bytes(
            Address::new(0x1000),
            Address::new(0x1003),
            vec![0x48, 0x89, 0xD8, 0xC3],
        ));
        pt.add_entry(ClipboardEntry::from_text(
            Address::new(0x2000),
            Address::new(0x2000),
            "nop".into(),
        ));
        assert!(pt.has_data());
        assert_eq!(pt.total_bytes(), 4);
        assert_eq!(pt.entries_with_format(ClipboardFormat::Bytes).len(), 1);
        assert_eq!(pt.entries_with_format(ClipboardFormat::Text).len(), 1);
    }

    #[test]
    fn test_program_transferable_empty() {
        let pt = ProgramTransferable::new("prog", ClipboardFormat::Text);
        assert!(!pt.has_data());
        assert_eq!(pt.total_bytes(), 0);
    }
}
