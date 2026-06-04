//! Clipboard Operations -- copy/paste code units and data.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.clipboard` Java package.
//!
//! Provides logic for copying and pasting code units (instructions and data)
//! between address ranges.

use ghidra_core::Address;

/// The format of data on the clipboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardFormat {
    /// Raw bytes.
    Bytes,
    /// Text representation (listing format).
    Text,
    /// Hex string.
    Hex,
    /// Assembly source text.
    Assembly,
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

    /// Get the hex representation of the bytes.
    pub fn as_hex(&self) -> String {
        self.data
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Clipboard manager for code units.
#[derive(Debug, Default)]
pub struct ClipboardManager {
    entries: Vec<ClipboardEntry>,
}

impl ClipboardManager {
    /// Create a new clipboard manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Copy a byte range to the clipboard.
    pub fn copy_bytes(&mut self, start: Address, end: Address, data: Vec<u8>) {
        self.entries
            .push(ClipboardEntry::from_bytes(start, end, data));
    }

    /// Copy text to the clipboard.
    pub fn copy_text(&mut self, start: Address, end: Address, text: String) {
        self.entries
            .push(ClipboardEntry::from_text(start, end, text));
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

    /// Clear the clipboard.
    pub fn clear(&mut self) {
        self.entries.clear();
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
}
