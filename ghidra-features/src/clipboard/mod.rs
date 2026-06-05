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

    /// All available clipboard formats.
    pub fn all() -> &'static [ClipboardFormat] {
        &[
            Self::Bytes,
            Self::Text,
            Self::Hex,
            Self::Assembly,
            Self::Xml,
            Self::AddressTable,
        ]
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

impl std::fmt::Display for ClipboardEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{:?}] {} ({} bytes): {}",
            self.format,
            self.as_hex(),
            self.byte_count(),
            self.text
        )
    }
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

    #[test]
    fn test_byte_content_provider() {
        let provider = ByteContentProvider::new();
        let entry = provider.provide_bytes(
            Address::new(0x1000),
            Address::new(0x1003),
            &[0x48, 0x89, 0xD8, 0xC3],
        );
        assert_eq!(entry.data, vec![0x48, 0x89, 0xD8, 0xC3]);
        assert_eq!(entry.format, ClipboardFormat::Bytes);
    }

    #[test]
    fn test_text_content_provider() {
        let provider = TextContentProvider::new();
        let entry = provider.provide_text(
            Address::new(0x1000),
            Address::new(0x1003),
            &["mov rax, rbx".to_string(), "ret".to_string()],
        );
        assert_eq!(entry.format, ClipboardFormat::Text);
        assert!(entry.text.contains("mov rax, rbx"));
        assert!(entry.text.contains("ret"));
    }

    #[test]
    fn test_assembly_content_provider() {
        let provider = AssemblyContentProvider::new();
        let entry = provider.provide_assembly(
            Address::new(0x1000),
            &["mov rax, rbx".to_string(), "ret".to_string()],
            &["0x48 0x89 0xD8".to_string(), "0xC3".to_string()],
        );
        assert_eq!(entry.format, ClipboardFormat::Assembly);
        assert!(entry.text.contains("mov rax, rbx"));
    }

    #[test]
    fn test_html_transferable() {
        let mut ht = HtmlTransferable::new("test_program");
        ht.add_text("mov rax, rbx\n");
        ht.add_text("ret\n");
        assert!(ht.has_content());
        assert_eq!(ht.text_content(), "mov rax, rbx\nret\n");
    }

    #[test]
    fn test_code_unit_transferable() {
        let mut cut = CodeUnitTransferable::new("prog", ClipboardFormat::Text);
        cut.add_code_unit(Address::new(0x1000), "mov rax, rbx", &[0x48, 0x89, 0xD8]);
        cut.add_code_unit(Address::new(0x1003), "ret", &[0xC3]);
        assert_eq!(cut.code_unit_count(), 2);
        assert_eq!(cut.total_bytes(), 4);
    }

    #[test]
    fn test_clipboard_format_all_variants() {
        let formats = ClipboardFormat::all();
        assert_eq!(formats.len(), 6);
        assert!(formats.contains(&ClipboardFormat::Bytes));
        assert!(formats.contains(&ClipboardFormat::Xml));
    }

    #[test]
    fn test_clipboard_entry_display() {
        let entry = ClipboardEntry::from_bytes(
            Address::new(0x1000),
            Address::new(0x1003),
            vec![0x48, 0x89],
        );
        let s = format!("{}", entry);
        assert!(s.contains("48"));
        assert!(s.contains("89"));
    }
}

// ---------------------------------------------------------------------------
// ByteContentProvider -- provides raw bytes to the clipboard
// ---------------------------------------------------------------------------

/// Provider that supplies raw bytes for clipboard operations.
///
/// Ported from the byte-content provider concept in Ghidra's clipboard package.
#[derive(Debug, Default)]
pub struct ByteContentProvider;

impl ByteContentProvider {
    /// Create a new byte content provider.
    pub fn new() -> Self {
        Self
    }

    /// Provide bytes for a clipboard entry.
    pub fn provide_bytes(
        &self,
        start: Address,
        end: Address,
        bytes: &[u8],
    ) -> ClipboardEntry {
        ClipboardEntry::from_bytes(start, end, bytes.to_vec())
    }
}

// ---------------------------------------------------------------------------
// TextContentProvider -- provides text representations to the clipboard
// ---------------------------------------------------------------------------

/// Provider that supplies text for clipboard operations.
///
/// Ported from the text-content provider concept in Ghidra's clipboard package.
#[derive(Debug, Default)]
pub struct TextContentProvider;

impl TextContentProvider {
    /// Create a new text content provider.
    pub fn new() -> Self {
        Self
    }

    /// Provide text for a clipboard entry from code unit lines.
    pub fn provide_text(
        &self,
        start: Address,
        end: Address,
        lines: &[String],
    ) -> ClipboardEntry {
        let text = lines.join("\n");
        ClipboardEntry::from_text(start, end, text)
    }
}

// ---------------------------------------------------------------------------
// AssemblyContentProvider -- provides assembly text to the clipboard
// ---------------------------------------------------------------------------

/// Provider that supplies assembly text for clipboard operations.
///
/// Ported from the assembly-content provider concept in Ghidra's clipboard package.
#[derive(Debug, Default)]
pub struct AssemblyContentProvider;

impl AssemblyContentProvider {
    /// Create a new assembly content provider.
    pub fn new() -> Self {
        Self
    }

    /// Provide assembly text with corresponding byte representations.
    pub fn provide_assembly(
        &self,
        start: Address,
        asm_lines: &[String],
        _byte_lines: &[String],
    ) -> ClipboardEntry {
        let text = asm_lines.join("\n");
        ClipboardEntry {
            source_start: start,
            source_end: Address::new(start.offset + asm_lines.len() as u64),
            data: Vec::new(),
            text,
            format: ClipboardFormat::Assembly,
        }
    }
}

// ---------------------------------------------------------------------------
// HtmlTransferable -- HTML-capable clipboard transferable
// ---------------------------------------------------------------------------

/// A transferable that can produce HTML content for clipboard operations.
///
/// Ported from the HTML transferable concept in Ghidra's clipboard package.
#[derive(Debug, Clone)]
pub struct HtmlTransferable {
    /// Source program name.
    pub source_program: String,
    /// Plain text content.
    text_content: String,
}

impl HtmlTransferable {
    /// Create a new HTML transferable.
    pub fn new(source_program: impl Into<String>) -> Self {
        Self {
            source_program: source_program.into(),
            text_content: String::new(),
        }
    }

    /// Add text content.
    pub fn add_text(&mut self, text: &str) {
        self.text_content.push_str(text);
    }

    /// Whether this transferable has content.
    pub fn has_content(&self) -> bool {
        !self.text_content.is_empty()
    }

    /// Get the plain text content.
    pub fn text_content(&self) -> &str {
        &self.text_content
    }

    /// Generate a basic HTML representation.
    pub fn to_html(&self) -> String {
        format!(
            "<html><body><pre>{}</pre></body></html>",
            self.text_content
        )
    }
}

// ---------------------------------------------------------------------------
// CodeUnitTransferable -- structured code unit clipboard data
// ---------------------------------------------------------------------------

/// A transferable for structured code unit data.
///
/// Ported from the CodeUnitTransferable concept in Ghidra's clipboard package.
#[derive(Debug, Clone)]
pub struct CodeUnitTransferable {
    /// Source program.
    pub source_program: String,
    /// The preferred format.
    pub preferred_format: ClipboardFormat,
    /// Code unit entries.
    entries: Vec<CodeUnitEntry>,
}

/// A single code unit entry for structured clipboard transfer.
#[derive(Debug, Clone)]
pub struct CodeUnitEntry {
    /// The address.
    pub address: Address,
    /// The display text (instruction mnemonic, data label, etc.).
    pub display_text: String,
    /// The raw bytes.
    pub bytes: Vec<u8>,
}

impl CodeUnitTransferable {
    /// Create a new code unit transferable.
    pub fn new(source_program: impl Into<String>, preferred_format: ClipboardFormat) -> Self {
        Self {
            source_program: source_program.into(),
            preferred_format,
            entries: Vec::new(),
        }
    }

    /// Add a code unit entry.
    pub fn add_code_unit(
        &mut self,
        address: Address,
        display_text: &str,
        bytes: &[u8],
    ) {
        self.entries.push(CodeUnitEntry {
            address,
            display_text: display_text.to_string(),
            bytes: bytes.to_vec(),
        });
    }

    /// The number of code units.
    pub fn code_unit_count(&self) -> usize {
        self.entries.len()
    }

    /// Total bytes across all entries.
    pub fn total_bytes(&self) -> usize {
        self.entries.iter().map(|e| e.bytes.len()).sum()
    }

    /// Get all entries.
    pub fn entries(&self) -> &[CodeUnitEntry] {
        &self.entries
    }

    /// Get the text representation of all code units.
    pub fn to_text(&self) -> String {
        self.entries
            .iter()
            .map(|e| format!("{}: {}", e.address, e.display_text))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Get the hex dump of all bytes.
    pub fn to_hex_dump(&self) -> String {
        self.entries
            .iter()
            .flat_map(|e| e.bytes.iter())
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }
}
