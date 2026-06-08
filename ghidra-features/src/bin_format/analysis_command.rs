//! Binary analysis command framework ported from Ghidra's
//! `ghidra.framework.cmd.BinaryAnalysisCommand` and related classes.
//!
//! Provides the core abstractions for format-specific binary analysis:
//! - [`BinaryAnalysisCommand`] trait -- the command interface for binary format annotation
//! - [`AnalysisWorker`] trait -- callback interface for analysis workers
//! - [`MessageLog`] -- a thread-safe log for analysis messages
//! - [`MarkupEntry`] -- description of a data markup operation
//! - [`FragmentEntry`] -- description of a memory fragment to create
//! - [`CommentEntry`] -- description of a comment to set
//! - [`LabelEntry`] -- description of a label/symbol to create
//! - [`ProgramMarkup`] -- collected markup results from an analysis command
//!
//! In Ghidra's Java codebase, each binary format (ELF, PE, Mach-O, COFF, PEF,
//! AppleSingle/Double, COFF Archive) has its own `BinaryAnalysisCommand`
//! implementation that annotates a `Program` with data types, fragments, labels,
//! and comments. The Rust port captures this logic in a format-agnostic way:
//! each command returns a [`ProgramMarkup`] describing what annotations to apply,
//! rather than directly mutating a Program object.

use std::fmt;
use std::sync::{Arc, Mutex};

use super::binary_reader::BinaryReader;
use super::byte_provider::ByteProvider;
use super::types::DataTypeDescription;

// ---------------------------------------------------------------------------
// MessageLog
// ---------------------------------------------------------------------------

/// A thread-safe log for analysis messages.
///
/// Ported from `ghidra.app.util.importer.MessageLog`. Collects informational
/// messages, warnings, and errors produced during binary analysis.
#[derive(Debug, Clone)]
pub struct MessageLog {
    messages: Arc<Mutex<Vec<LogEntry>>>,
}

/// A single log entry with severity level.
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub level: LogLevel,
    pub message: String,
}

/// Severity level for log messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogLevel {
    Info,
    Warning,
    Error,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warning => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
        }
    }
}

impl MessageLog {
    /// Create a new empty message log.
    pub fn new() -> Self {
        Self {
            messages: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Append an informational message.
    pub fn append_msg(&self, msg: impl Into<String>) {
        let mut msgs = self.messages.lock().unwrap();
        msgs.push(LogEntry {
            level: LogLevel::Info,
            message: msg.into(),
        });
    }

    /// Append a warning message.
    pub fn append_warning(&self, msg: impl Into<String>) {
        let mut msgs = self.messages.lock().unwrap();
        msgs.push(LogEntry {
            level: LogLevel::Warning,
            message: msg.into(),
        });
    }

    /// Append an error message.
    pub fn append_error(&self, msg: impl Into<String>) {
        let mut msgs = self.messages.lock().unwrap();
        msgs.push(LogEntry {
            level: LogLevel::Error,
            message: msg.into(),
        });
    }

    /// Append an exception as an error message.
    pub fn append_exception(&self, err: &dyn std::error::Error) {
        self.append_error(format!("{}", err));
    }

    /// Get all messages as a vector of log entries.
    pub fn get_messages(&self) -> Vec<LogEntry> {
        let msgs = self.messages.lock().unwrap();
        msgs.clone()
    }

    /// Get all messages formatted as a single string.
    pub fn to_string_lossy(&self) -> String {
        let msgs = self.messages.lock().unwrap();
        msgs.iter()
            .map(|e| format!("[{}] {}", e.level, e.message))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Check if there are any error-level messages.
    pub fn has_errors(&self) -> bool {
        let msgs = self.messages.lock().unwrap();
        msgs.iter().any(|e| e.level == LogLevel::Error)
    }

    /// Check if the log is empty.
    pub fn is_empty(&self) -> bool {
        let msgs = self.messages.lock().unwrap();
        msgs.is_empty()
    }

    /// Get the number of messages.
    pub fn len(&self) -> usize {
        let msgs = self.messages.lock().unwrap();
        msgs.len()
    }

    /// Clear all messages.
    pub fn clear(&self) {
        let mut msgs = self.messages.lock().unwrap();
        msgs.clear();
    }
}

impl Default for MessageLog {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for MessageLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msgs = self.messages.lock().unwrap();
        for entry in msgs.iter() {
            writeln!(f, "[{}] {}", entry.level, entry.message)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CommentType
// ---------------------------------------------------------------------------

/// Types of comments in a program listing.
///
/// Ported from `ghidra.program.model.listing.CommentType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommentType {
    /// End-of-line comment (appears after the instruction/data on the same line).
    Eol,
    /// Pre-comment (appears above the instruction/data).
    Pre,
    /// Post-comment (appears below the instruction/data).
    Post,
    /// Plate comment (appears above with separator lines).
    Plate,
    /// Repeatable comment (shared at all references to this address).
    Repeatable,
}

impl fmt::Display for CommentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommentType::Eol => write!(f, "EOL"),
            CommentType::Pre => write!(f, "Pre"),
            CommentType::Post => write!(f, "Post"),
            CommentType::Plate => write!(f, "Plate"),
            CommentType::Repeatable => write!(f, "Repeatable"),
        }
    }
}

// ---------------------------------------------------------------------------
// SourceType
// ---------------------------------------------------------------------------

/// Source of a symbol or label.
///
/// Ported from `ghidra.program.model.symbol.SourceType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceType {
    /// User-defined (highest priority).
    UserDefined,
    /// Analysis-defined.
    Analysis,
    /// Imported from debug info or similar.
    Imported,
    /// Default/source unknown.
    Default,
}

// ---------------------------------------------------------------------------
// Markup entries
// ---------------------------------------------------------------------------

/// A data markup operation: create a data item at an address.
///
/// Ported from the `createData()` calls in Ghidra's analysis commands.
#[derive(Debug, Clone)]
pub struct MarkupEntry {
    /// File offset (virtual address) where the data starts.
    pub address: u64,
    /// The data type to create at this address.
    pub data_type: DataTypeDescription,
    /// An optional name/label for this data item.
    pub name: Option<String>,
    /// An optional comment for this data item.
    pub comment: Option<String>,
    /// The type of comment (if any).
    pub comment_type: Option<CommentType>,
}

impl MarkupEntry {
    /// Create a new markup entry.
    pub fn new(address: u64, data_type: DataTypeDescription) -> Self {
        Self {
            address,
            data_type,
            name: None,
            comment: None,
            comment_type: None,
        }
    }

    /// Set the name/label for this entry.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set a comment for this entry.
    pub fn with_comment(mut self, comment: impl Into<String>, comment_type: CommentType) -> Self {
        self.comment = Some(comment.into());
        self.comment_type = Some(comment_type);
        self
    }
}

/// A fragment entry: a named region of the program's address space.
///
/// Ported from `createFragment()` calls in Ghidra's analysis commands.
#[derive(Debug, Clone)]
pub struct FragmentEntry {
    /// Fragment name.
    pub name: String,
    /// Start address of the fragment.
    pub address: u64,
    /// Length of the fragment in bytes.
    pub length: u64,
    /// Optional parent module name.
    pub parent_module: Option<String>,
}

impl FragmentEntry {
    /// Create a new fragment entry.
    pub fn new(name: impl Into<String>, address: u64, length: u64) -> Self {
        Self {
            name: name.into(),
            address,
            length,
            parent_module: None,
        }
    }

    /// Set the parent module for this fragment.
    pub fn with_parent(mut self, module: impl Into<String>) -> Self {
        self.parent_module = Some(module.into());
        self
    }
}

/// A label/symbol entry.
///
/// Ported from `createLabel()` calls in Ghidra's analysis commands.
#[derive(Debug, Clone)]
pub struct LabelEntry {
    /// Address of the label.
    pub address: u64,
    /// Label/symbol name.
    pub name: String,
    /// Source of the label.
    pub source: SourceType,
    /// Whether this is a primary symbol (unique at its address).
    pub is_primary: bool,
}

impl LabelEntry {
    /// Create a new label entry.
    pub fn new(address: u64, name: impl Into<String>) -> Self {
        Self {
            address,
            name: name.into(),
            source: SourceType::Analysis,
            is_primary: true,
        }
    }

    /// Set the source type.
    pub fn with_source(mut self, source: SourceType) -> Self {
        self.source = source;
        self
    }

    /// Set whether this is a primary label.
    pub fn with_primary(mut self, primary: bool) -> Self {
        self.is_primary = primary;
        self
    }
}

/// A comment entry.
///
/// Ported from `setComment()` / `setPlateComment()` / `setEOLComment()` calls.
#[derive(Debug, Clone)]
pub struct CommentEntry {
    /// Address of the comment.
    pub address: u64,
    /// Comment text.
    pub text: String,
    /// Comment type.
    pub comment_type: CommentType,
}

impl CommentEntry {
    /// Create a new comment entry.
    pub fn new(address: u64, text: impl Into<String>, comment_type: CommentType) -> Self {
        Self {
            address,
            text: text.into(),
            comment_type,
        }
    }
}

/// A reference entry: a cross-reference between addresses.
///
/// Ported from `ReferenceManager.addMemoryReference()`.
#[derive(Debug, Clone)]
pub struct ReferenceEntry {
    /// Source address.
    pub from_address: u64,
    /// Target address.
    pub to_address: u64,
    /// Reference type description.
    pub ref_type: String,
    /// Source of the reference.
    pub source: SourceType,
}

impl ReferenceEntry {
    /// Create a new reference entry.
    pub fn new(from_address: u64, to_address: u64, ref_type: impl Into<String>) -> Self {
        Self {
            from_address,
            to_address,
            ref_type: ref_type.into(),
            source: SourceType::Analysis,
        }
    }
}

// ---------------------------------------------------------------------------
// ProgramMarkup
// ---------------------------------------------------------------------------

/// Collected markup results from a binary analysis command.
///
/// This is the output of running a [`BinaryAnalysisCommand`]. It describes all
/// the annotations (data types, fragments, labels, comments, references) that
/// should be applied to a program.
#[derive(Debug, Clone, Default)]
pub struct ProgramMarkup {
    /// Data type markups.
    pub data_markups: Vec<MarkupEntry>,
    /// Fragment definitions.
    pub fragments: Vec<FragmentEntry>,
    /// Label/symbol definitions.
    pub labels: Vec<LabelEntry>,
    /// Comment annotations.
    pub comments: Vec<CommentEntry>,
    /// Cross-references.
    pub references: Vec<ReferenceEntry>,
    /// Analysis messages.
    pub messages: MessageLog,
}

impl ProgramMarkup {
    /// Create a new empty markup.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a data markup entry.
    pub fn add_markup(&mut self, entry: MarkupEntry) {
        self.data_markups.push(entry);
    }

    /// Add a fragment entry.
    pub fn add_fragment(&mut self, entry: FragmentEntry) {
        self.fragments.push(entry);
    }

    /// Add a label entry.
    pub fn add_label(&mut self, entry: LabelEntry) {
        self.labels.push(entry);
    }

    /// Add a comment entry.
    pub fn add_comment(&mut self, entry: CommentEntry) {
        self.comments.push(entry);
    }

    /// Add a reference entry.
    pub fn add_reference(&mut self, entry: ReferenceEntry) {
        self.references.push(entry);
    }

    /// Check if the markup is empty (no entries at all).
    pub fn is_empty(&self) -> bool {
        self.data_markups.is_empty()
            && self.fragments.is_empty()
            && self.labels.is_empty()
            && self.comments.is_empty()
            && self.references.is_empty()
    }

    /// Get the total number of markup entries.
    pub fn entry_count(&self) -> usize {
        self.data_markups.len()
            + self.fragments.len()
            + self.labels.len()
            + self.comments.len()
            + self.references.len()
    }

    /// Remove empty fragments (fragments with length 0).
    ///
    /// Ported from `removeEmptyFragments()` in the Java commands.
    pub fn remove_empty_fragments(&mut self) {
        self.fragments.retain(|f| f.length > 0);
    }
}

// ---------------------------------------------------------------------------
// BinaryAnalysisCommand trait
// ---------------------------------------------------------------------------

/// The main trait for binary format analysis commands.
///
/// Ported from `ghidra.framework.cmd.BinaryAnalysisCommand` and
/// `ghidra.app.plugin.core.analysis.AnalysisWorker`. Each binary format
/// (ELF, PE, Mach-O, COFF, PEF, etc.) implements this trait to provide
/// format-specific analysis that annotates a program with data types,
/// fragments, labels, and comments.
pub trait BinaryAnalysisCommand: Send + Sync {
    /// Returns the name of this analysis command.
    fn name(&self) -> &str;

    /// Check if this command can be applied to the given binary data.
    ///
    /// This typically checks for format magic bytes or signatures.
    fn can_apply(&self, data: &[u8]) -> bool;

    /// Execute the analysis command on the given binary data.
    ///
    /// Returns a `ProgramMarkup` describing all annotations to apply,
    /// or an error string if analysis fails.
    fn apply(&self, data: &[u8], is_little_endian: bool) -> Result<ProgramMarkup, String>;

    /// Get the message log from the last analysis run.
    fn messages(&self) -> &MessageLog;
}

// ---------------------------------------------------------------------------
// Format detection utilities
// ---------------------------------------------------------------------------

/// Detect the binary format of the given data.
///
/// Returns the detected format name, or `None` if the format is not recognized.
/// Ported from the `canApply()` methods across all analysis commands.
pub fn detect_format(data: &[u8]) -> Option<BinaryFormat> {
    if data.len() < 4 {
        return None;
    }

    // ELF magic: 0x7f 'E' 'L' 'F'
    if data.len() >= 16 && data[0] == 0x7f && data[1] == b'E' && data[2] == b'L' && data[3] == b'F' {
        return Some(BinaryFormat::Elf);
    }

    // DOS MZ magic: 'M' 'Z'
    if data[0] == b'M' && data[1] == b'Z' {
        // Check for PE signature at e_lfanew
        if data.len() >= 0x40 {
            let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
            if e_lfanew + 4 <= data.len() {
                let pe_sig = u32::from_le_bytes([
                    data[e_lfanew],
                    data[e_lfanew + 1],
                    data[e_lfanew + 2],
                    data[e_lfanew + 3],
                ]);
                if pe_sig == 0x0000_4550 {
                    // "PE\0\0"
                    return Some(BinaryFormat::Pe);
                }
            }
        }
        return Some(BinaryFormat::DosMz);
    }

    // Mach-O magic (32-bit LE, 64-bit LE, 32-bit BE, 64-bit BE, Fat)
    let magic32 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let magic32_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if magic32 == 0xFEEDFACE || magic32 == 0xFEEDFACF {
        return Some(BinaryFormat::MachO);
    }
    if magic32_be == 0xFEEDFACE || magic32_be == 0xFEEDFACF {
        return Some(BinaryFormat::MachO);
    }
    if magic32 == 0xBEBAFECA || magic32_be == 0xBEBAFECA {
        return Some(BinaryFormat::MachOFat);
    }

    // COFF Archive magic: "!<arch>\n"
    if data.len() >= 8 && &data[..8] == b"!<arch>\n" {
        return Some(BinaryFormat::CoffArchive);
    }

    // PEF (Classic Macintosh Preferred Executable Format)
    // PEF Container Header starts with: join2 (0x4A6F696E), then cfrag (0x63667267)
    if data.len() >= 8 {
        let magic_pef = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic_pef == 0x4A6F_696E {
            return Some(BinaryFormat::Pef);
        }
    }

    // AppleSingle/Double magic numbers
    if data.len() >= 4 {
        let magic_asd = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic_asd == 0x00051600 || magic_asd == 0x00051607 {
            return Some(BinaryFormat::AppleSingleDouble);
        }
    }

    // COFF: check for common machine types
    if data.len() >= 2 {
        let machine = u16::from_le_bytes([data[0], data[1]]);
        if is_coff_machine_type(machine) {
            // Additional heuristic: the section count should be reasonable
            if data.len() >= 20 {
                let num_sections = u16::from_le_bytes([data[2], data[3]]);
                if num_sections > 0 && num_sections <= 100 {
                    return Some(BinaryFormat::Coff);
                }
            }
        }
    }

    None
}

/// Known binary formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryFormat {
    /// ELF (Executable and Linkable Format) - Linux/Unix
    Elf,
    /// PE (Portable Executable) - Windows
    Pe,
    /// Mach-O - macOS/iOS (single architecture)
    MachO,
    /// Mach-O Fat/Universal binary (multiple architectures)
    MachOFat,
    /// COFF (Common Object File Format)
    Coff,
    /// COFF Archive (.a / .lib)
    CoffArchive,
    /// DOS MZ executable
    DosMz,
    /// PEF (Preferred Executable Format) - Classic Mac
    Pef,
    /// AppleSingle/Double
    AppleSingleDouble,
    /// Raw binary (no recognized format)
    Raw,
}

impl fmt::Display for BinaryFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BinaryFormat::Elf => write!(f, "ELF"),
            BinaryFormat::Pe => write!(f, "PE"),
            BinaryFormat::MachO => write!(f, "Mach-O"),
            BinaryFormat::MachOFat => write!(f, "Mach-O Fat"),
            BinaryFormat::Coff => write!(f, "COFF"),
            BinaryFormat::CoffArchive => write!(f, "COFF Archive"),
            BinaryFormat::DosMz => write!(f, "DOS MZ"),
            BinaryFormat::Pef => write!(f, "PEF"),
            BinaryFormat::AppleSingleDouble => write!(f, "AppleSingle/Double"),
            BinaryFormat::Raw => write!(f, "Raw Binary"),
        }
    }
}

/// Check if a u16 machine type is a known COFF machine type.
fn is_coff_machine_type(machine: u16) -> bool {
    matches!(
        machine,
        0x0000     // IMAGE_FILE_MACHINE_UNKNOWN (but present in some COFF files)
        | 0x014c   // IMAGE_FILE_MACHINE_I386
        | 0x0162   // IMAGE_FILE_MACHINE_R3000
        | 0x0166   // IMAGE_FILE_MACHINE_R4000
        | 0x0168   // IMAGE_FILE_MACHINE_R10000
        | 0x0169   // IMAGE_FILE_MACHINE_WCEMIPSV2
        | 0x01a2   // IMAGE_FILE_MACHINE_SH3
        | 0x01a3   // IMAGE_FILE_MACHINE_SH3DSP
        | 0x01a6   // IMAGE_FILE_MACHINE_SH4
        | 0x01a8   // IMAGE_FILE_MACHINE_SH5
        | 0x01c0   // IMAGE_FILE_MACHINE_ARM
        | 0x01c2   // IMAGE_FILE_MACHINE_THUMB
        | 0x01c4   // IMAGE_FILE_MACHINE_ARMNT
        | 0x01d3   // IMAGE_FILE_MACHINE_AM33
        | 0x01f0   // IMAGE_FILE_MACHINE_POWERPC
        | 0x01f1   // IMAGE_FILE_MACHINE_POWERPCFP
        | 0x0200   // IMAGE_FILE_MACHINE_IA64
        | 0x0266   // IMAGE_FILE_MACHINE_MIPS16
        | 0x0366   // IMAGE_FILE_MACHINE_MIPSFPU
        | 0x0466   // IMAGE_FILE_MACHINE_MIPSFPU16
        | 0x0520   // IMAGE_FILE_MACHINE_TRICORE
        | 0x0cef   // IMAGE_FILE_MACHINE_CEF
        | 0x0ebc   // IMAGE_FILE_MACHINE_EBC
        | 0x8664   // IMAGE_FILE_MACHINE_AMD64
        | 0x9041   // IMAGE_FILE_MACHINE_M32R
        | 0xaa64   // IMAGE_FILE_MACHINE_ARM64
        | 0xc0ee   // IMAGE_FILE_MACHINE_CEE
    )
}

// ---------------------------------------------------------------------------
// AnalysisRunner
// ---------------------------------------------------------------------------

/// A runner that applies markup entries to produce a structured description.
///
/// This utility organizes and validates the output of analysis commands.
pub struct AnalysisRunner;

impl AnalysisRunner {
    /// Sort markup entries by address for consistent output.
    pub fn sort_by_address(markup: &mut ProgramMarkup) {
        markup.data_markups.sort_by_key(|m| m.address);
        markup.fragments.sort_by_key(|f| f.address);
        markup.labels.sort_by_key(|l| l.address);
        markup.comments.sort_by_key(|c| c.address);
        markup.references.sort_by_key(|r| r.from_address);
    }

    /// Check for overlapping fragments and log warnings.
    pub fn check_overlaps(markup: &ProgramMarkup) -> Vec<String> {
        let mut warnings = Vec::new();
        let mut fragments = markup.fragments.clone();
        fragments.sort_by_key(|f| f.address);

        for i in 0..fragments.len() {
            for j in (i + 1)..fragments.len() {
                let a = &fragments[i];
                let b = &fragments[j];
                // b starts after a ends, no overlap (since sorted)
                if b.address >= a.address + a.length {
                    break;
                }
                warnings.push(format!(
                    "Fragment '{}' [{:#x}..{:#x}) overlaps with '{}' [{:#x}..{:#x})",
                    a.name,
                    a.address,
                    a.address + a.length,
                    b.name,
                    b.address,
                    b.address + b.length
                ));
            }
        }
        warnings
    }

    /// Validate that all markup entries reference addresses within bounds.
    pub fn validate_bounds(markup: &ProgramMarkup, data_len: u64) -> Vec<String> {
        let mut errors = Vec::new();

        for m in &markup.data_markups {
            let dt_size = m.data_type.size().unwrap_or(0) as u64;
            if m.address + dt_size > data_len {
                errors.push(format!(
                    "Markup at {:#x} (size {}) exceeds data length {:#x}",
                    m.address, dt_size, data_len
                ));
            }
        }

        for f in &markup.fragments {
            if f.address + f.length > data_len {
                errors.push(format!(
                    "Fragment '{}' at {:#x} (len {}) exceeds data length {:#x}",
                    f.name, f.address, f.length, data_len
                ));
            }
        }

        for l in &markup.labels {
            if l.address >= data_len {
                errors.push(format!(
                    "Label '{}' at {:#x} exceeds data length {:#x}",
                    l.name, l.address, data_len
                ));
            }
        }

        errors
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_log_basic() {
        let log = MessageLog::new();
        assert!(log.is_empty());

        log.append_msg("test message");
        assert_eq!(log.len(), 1);
        assert!(!log.has_errors());

        log.append_warning("warning");
        assert_eq!(log.len(), 2);

        log.append_error("error");
        assert_eq!(log.len(), 3);
        assert!(log.has_errors());
    }

    #[test]
    fn test_message_log_display() {
        let log = MessageLog::new();
        log.append_msg("hello");
        log.append_error("bad");
        let s = log.to_string_lossy();
        assert!(s.contains("[INFO] hello"));
        assert!(s.contains("[ERROR] bad"));
    }

    #[test]
    fn test_message_log_exception() {
        let log = MessageLog::new();
        let err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        log.append_exception(&err);
        assert_eq!(log.len(), 1);
        let msgs = log.get_messages();
        assert_eq!(msgs[0].level, LogLevel::Error);
        assert!(msgs[0].message.contains("file missing"));
    }

    #[test]
    fn test_markup_entry_builder() {
        let entry = MarkupEntry::new(0x100, DataTypeDescription::DWord)
            .with_name("header_size")
            .with_comment("Size of the header", CommentType::Eol);
        assert_eq!(entry.address, 0x100);
        assert_eq!(entry.name, Some("header_size".into()));
        assert!(entry.comment.is_some());
    }

    #[test]
    fn test_fragment_entry_builder() {
        let frag = FragmentEntry::new(".text", 0x1000, 0x5000)
            .with_parent("RootModule");
        assert_eq!(frag.name, ".text");
        assert_eq!(frag.address, 0x1000);
        assert_eq!(frag.length, 0x5000);
        assert_eq!(frag.parent_module, Some("RootModule".into()));
    }

    #[test]
    fn test_label_entry_builder() {
        let label = LabelEntry::new(0x2000, "main")
            .with_source(SourceType::UserDefined)
            .with_primary(true);
        assert_eq!(label.address, 0x2000);
        assert_eq!(label.name, "main");
        assert_eq!(label.source, SourceType::UserDefined);
        assert!(label.is_primary);
    }

    #[test]
    fn test_program_markup() {
        let mut markup = ProgramMarkup::new();
        assert!(markup.is_empty());

        markup.add_markup(MarkupEntry::new(0, DataTypeDescription::DWord));
        markup.add_fragment(FragmentEntry::new(".text", 0x100, 0x500));
        markup.add_label(LabelEntry::new(0x100, "start"));
        markup.add_comment(CommentEntry::new(0x100, "Entry point", CommentType::Plate));
        markup.add_reference(ReferenceEntry::new(0x200, 0x100, "DATA"));

        assert_eq!(markup.entry_count(), 5);
        assert!(!markup.is_empty());
    }

    #[test]
    fn test_remove_empty_fragments() {
        let mut markup = ProgramMarkup::new();
        markup.add_fragment(FragmentEntry::new(".text", 0x100, 0x500));
        markup.add_fragment(FragmentEntry::new(".empty", 0x600, 0));
        markup.add_fragment(FragmentEntry::new(".data", 0x700, 0x100));
        markup.remove_empty_fragments();
        assert_eq!(markup.fragments.len(), 2);
        assert_eq!(markup.fragments[0].name, ".text");
        assert_eq!(markup.fragments[1].name, ".data");
    }

    #[test]
    fn test_detect_format_elf() {
        let mut data = vec![0u8; 64];
        data[0] = 0x7f;
        data[1] = b'E';
        data[2] = b'L';
        data[3] = b'F';
        data[4] = 2; // ELFCLASS64
        data[5] = 1; // ELFDATA2LSB
        assert_eq!(detect_format(&data), Some(BinaryFormat::Elf));
    }

    #[test]
    fn test_detect_format_pe() {
        let mut data = vec![0u8; 256];
        data[0] = b'M';
        data[1] = b'Z';
        // e_lfanew at offset 0x3c
        data[0x3c] = 0x80;
        data[0x3d] = 0x00;
        data[0x3e] = 0x00;
        data[0x3f] = 0x00;
        // PE signature at offset 0x80
        data[0x80] = b'P';
        data[0x81] = b'E';
        data[0x82] = 0;
        data[0x83] = 0;
        assert_eq!(detect_format(&data), Some(BinaryFormat::Pe));
    }

    #[test]
    fn test_detect_format_macho() {
        let mut data = vec![0u8; 32];
        // MH_MAGIC_64 = 0xFEEDFACF (little-endian)
        data[0] = 0xCF;
        data[1] = 0xFA;
        data[2] = 0xED;
        data[3] = 0xFE;
        assert_eq!(detect_format(&data), Some(BinaryFormat::MachO));
    }

    #[test]
    fn test_detect_format_macho_be() {
        let mut data = vec![0u8; 32];
        // MH_MAGIC (big-endian) = 0xFEEDFACE stored as BE
        data[0] = 0xFE;
        data[1] = 0xED;
        data[2] = 0xFA;
        data[3] = 0xCE;
        assert_eq!(detect_format(&data), Some(BinaryFormat::MachO));
    }

    #[test]
    fn test_detect_format_coff_archive() {
        let mut data = vec![0u8; 64];
        data[..8].copy_from_slice(b"!<arch>\n");
        assert_eq!(detect_format(&data), Some(BinaryFormat::CoffArchive));
    }

    #[test]
    fn test_detect_format_pef() {
        let mut data = vec![0u8; 32];
        // PEF magic: join = 0x4A6F696E
        data[0] = 0x4A;
        data[1] = 0x6F;
        data[2] = 0x69;
        data[3] = 0x6E;
        assert_eq!(detect_format(&data), Some(BinaryFormat::Pef));
    }

    #[test]
    fn test_detect_format_apple_single() {
        let mut data = vec![0u8; 32];
        // AppleSingle magic = 0x00051600
        data[0] = 0x00;
        data[1] = 0x05;
        data[2] = 0x16;
        data[3] = 0x00;
        assert_eq!(detect_format(&data), Some(BinaryFormat::AppleSingleDouble));
    }

    #[test]
    fn test_detect_format_apple_double() {
        let mut data = vec![0u8; 32];
        // AppleDouble magic = 0x00051607
        data[0] = 0x00;
        data[1] = 0x05;
        data[2] = 0x16;
        data[3] = 0x07;
        assert_eq!(detect_format(&data), Some(BinaryFormat::AppleSingleDouble));
    }

    #[test]
    fn test_detect_format_coff() {
        let mut data = vec![0u8; 32];
        // IMAGE_FILE_MACHINE_AMD64 = 0x8664
        data[0] = 0x64;
        data[1] = 0x86;
        // Number of sections = 3
        data[2] = 0x03;
        data[3] = 0x00;
        assert_eq!(detect_format(&data), Some(BinaryFormat::Coff));
    }

    #[test]
    fn test_detect_format_unknown() {
        let data = vec![0x12, 0x34, 0x56, 0x78];
        assert_eq!(detect_format(&data), None);
    }

    #[test]
    fn test_detect_format_too_short() {
        let data = vec![0x01, 0x02];
        assert_eq!(detect_format(&data), None);
    }

    #[test]
    fn test_binary_format_display() {
        assert_eq!(BinaryFormat::Elf.to_string(), "ELF");
        assert_eq!(BinaryFormat::Pe.to_string(), "PE");
        assert_eq!(BinaryFormat::MachO.to_string(), "Mach-O");
        assert_eq!(BinaryFormat::CoffArchive.to_string(), "COFF Archive");
    }

    #[test]
    fn test_analysis_runner_sort() {
        let mut markup = ProgramMarkup::new();
        markup.add_markup(MarkupEntry::new(0x300, DataTypeDescription::DWord));
        markup.add_markup(MarkupEntry::new(0x100, DataTypeDescription::Word));
        markup.add_markup(MarkupEntry::new(0x200, DataTypeDescription::Byte));
        AnalysisRunner::sort_by_address(&mut markup);
        assert_eq!(markup.data_markups[0].address, 0x100);
        assert_eq!(markup.data_markups[1].address, 0x200);
        assert_eq!(markup.data_markups[2].address, 0x300);
    }

    #[test]
    fn test_analysis_runner_validate_bounds() {
        let mut markup = ProgramMarkup::new();
        markup.add_markup(MarkupEntry::new(0x100, DataTypeDescription::DWord));
        markup.add_fragment(FragmentEntry::new(".big", 0x100, 0x100));
        markup.add_label(LabelEntry::new(0x1FC, "end"));

        // Data length = 0x200: all entries within bounds
        let errors = AnalysisRunner::validate_bounds(&markup, 0x200);
        assert!(errors.is_empty(), "expected no errors, got {:?}", errors);

        // Data length = 0x104: fragment and label exceed bounds
        let errors = AnalysisRunner::validate_bounds(&markup, 0x104);
        assert!(!errors.is_empty());
    }

    #[test]
    fn test_analysis_runner_overlaps() {
        let mut markup = ProgramMarkup::new();
        markup.add_fragment(FragmentEntry::new(".a", 0x100, 0x100));
        markup.add_fragment(FragmentEntry::new(".b", 0x180, 0x100));
        let warnings = AnalysisRunner::check_overlaps(&markup);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("overlaps"));
    }

    #[test]
    fn test_comment_type_display() {
        assert_eq!(CommentType::Eol.to_string(), "EOL");
        assert_eq!(CommentType::Plate.to_string(), "Plate");
    }

    #[test]
    fn test_log_level_display() {
        assert_eq!(LogLevel::Info.to_string(), "INFO");
        assert_eq!(LogLevel::Warning.to_string(), "WARN");
        assert_eq!(LogLevel::Error.to_string(), "ERROR");
    }

    #[test]
    fn test_reference_entry() {
        let r = ReferenceEntry::new(0x100, 0x200, "DATA");
        assert_eq!(r.from_address, 0x100);
        assert_eq!(r.to_address, 0x200);
        assert_eq!(r.ref_type, "DATA");
    }
}
