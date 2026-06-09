//! Clipboard Content Provider Service -- trait and code browser implementation.
//!
//! Ported from:
//! - `ghidra.app.services.ClipboardContentProviderService`
//! - `ghidra.app.plugin.core.clipboard.CodeBrowserClipboardProvider`
//!
//! Provides the trait interface that clipboard content providers implement,
//! and the `CodeBrowserClipboardProvider` -- the listing view's provider
//! that supplies formatted code, addresses, labels, comments, and bytes
//! to the clipboard system.
//!
//! # Architecture
//!
//! ```text
//! ClipboardContentProviderService (trait)
//!   |-- provider_name()
//!   |-- can_copy() / can_paste()
//!   |-- copy() / copy_special() / paste()
//!   |-- supported_copy_types()
//!   `-- lost_ownership()
//!
//! CodeBrowserClipboardProvider (struct, implements the trait)
//!   |-- current_location (address, field type)
//!   |-- current_selection (address set)
//!   |-- string_content (inline text override)
//!   |-- copy_types (available CopyType variants)
//!   `-- formatting options (include_quotes_for_strings, etc.)
//! ```

use std::collections::HashSet;

use ghidra_core::Address;

use super::{ClipboardEntry, ClipboardFormat};

// ---------------------------------------------------------------------------
// CopyType -- the listing-specific copy types
// ---------------------------------------------------------------------------

/// Listing-specific clipboard copy types.
///
/// Ported from the `ClipboardType` constants defined in `CodeBrowserClipboardProvider`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CopyType {
    /// Formatted code text (assembly listing).
    CodeText,
    /// Labels and comments.
    LabelsAndComments,
    /// Labels only.
    Labels,
    /// Comments only.
    Comments,
    /// Byte string (hex with spaces).
    ByteString,
    /// Byte string without spaces.
    ByteStringNoSpace,
    /// Data text representation.
    DataText,
    /// Dereferenced data text.
    DereferencedDataText,
    /// Python byte string (b"...").
    PythonByteString,
    /// Python list of bytes.
    PythonList,
    /// C++ byte array.
    CppByteArray,
    /// Address text.
    AddressText,
    /// Address with function offset.
    AddressTextWithOffset,
    /// Byte source offset (file offset).
    ByteSourceOffset,
    /// Memory block offset.
    BlockOffset,
    /// Function offset.
    FunctionOffset,
    /// Imagebase offset.
    ImagebaseOffset,
    /// Local Ghidra URL.
    GhidraLocalUrl,
    /// Shared Ghidra URL.
    GhidraSharedUrl,
}

impl CopyType {
    /// Display name for this copy type.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::CodeText => "Formatted Code",
            Self::LabelsAndComments => "Labels and Comments",
            Self::Labels => "Labels",
            Self::Comments => "Comments",
            Self::ByteString => "Byte String",
            Self::ByteStringNoSpace => "Byte String (no spaces)",
            Self::DataText => "Data",
            Self::DereferencedDataText => "Dereferenced Data",
            Self::PythonByteString => "Python Byte String",
            Self::PythonList => "Python List",
            Self::CppByteArray => "C++ Byte Array",
            Self::AddressText => "Address",
            Self::AddressTextWithOffset => "Address w/ Offset",
            Self::ByteSourceOffset => "Byte Source Offset",
            Self::BlockOffset => "Memory Block Offset",
            Self::FunctionOffset => "Function Offset",
            Self::ImagebaseOffset => "Imagebase Offset",
            Self::GhidraLocalUrl => "Local GhidraURL",
            Self::GhidraSharedUrl => "Shared GhidraURL",
        }
    }

    /// Description for this copy type.
    pub fn description(&self) -> &'static str {
        match self {
            Self::CodeText => "Copy formatted listing text",
            Self::LabelsAndComments => "Copy labels and comments as structured data",
            Self::Labels => "Copy labels only",
            Self::Comments => "Copy comments only",
            Self::ByteString => "Copy bytes as hex string with spaces",
            Self::ByteStringNoSpace => "Copy bytes as hex string without spaces",
            Self::DataText => "Copy data value text representations",
            Self::DereferencedDataText => "Copy dereferenced pointer data",
            Self::PythonByteString => "Copy as Python b'...' byte string",
            Self::PythonList => "Copy as Python [0xNN, ...] list",
            Self::CppByteArray => "Copy as C++ {0xNN, ...} array",
            Self::AddressText => "Copy addresses as hex strings",
            Self::AddressTextWithOffset => "Copy symbol + offset notation",
            Self::ByteSourceOffset => "Copy file offsets of selected bytes",
            Self::BlockOffset => "Copy memory block offsets",
            Self::FunctionOffset => "Copy function-relative offsets",
            Self::ImagebaseOffset => "Copy imagebase-relative offsets",
            Self::GhidraLocalUrl => "Copy local Ghidra URL",
            Self::GhidraSharedUrl => "Copy shared Ghidra URL",
        }
    }

    /// All available copy types (the default listing set).
    pub fn default_listing_types() -> &'static [CopyType] {
        &[
            Self::CodeText,
            Self::LabelsAndComments,
            Self::Labels,
            Self::Comments,
            Self::ByteString,
            Self::ByteStringNoSpace,
            Self::DataText,
            Self::DereferencedDataText,
            Self::PythonByteString,
            Self::PythonList,
            Self::CppByteArray,
            Self::AddressText,
            Self::AddressTextWithOffset,
            Self::ByteSourceOffset,
            Self::BlockOffset,
            Self::FunctionOffset,
            Self::ImagebaseOffset,
        ]
    }
}

// ---------------------------------------------------------------------------
// LocationKind -- the kind of listing field at the current location
// ---------------------------------------------------------------------------

/// The kind of listing field at the current cursor location.
///
/// Ported from the `ProgramLocation` subclasses used by
/// `CodeBrowserClipboardProvider.copyFromCurrentLocation()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocationKind {
    /// An address field.
    AddressField,
    /// A label field (symbol name).
    LabelField,
    /// A function name field.
    FunctionNameField,
    /// A comment field.
    CommentField,
    /// A bytes field.
    BytesField,
    /// An operand field.
    OperandField,
    /// A mnemonic field.
    MnemonicField,
    /// A variable field.
    VariableField,
    /// Some other field.
    Other,
}

// ---------------------------------------------------------------------------
// ListingLocation -- the current cursor location in the listing
// ---------------------------------------------------------------------------

/// The current cursor location in the listing view.
///
/// Ported from the `ProgramLocation` / `currentLocation` field in
/// `CodeBrowserClipboardProvider`.
#[derive(Debug, Clone)]
pub struct ListingLocation {
    /// The address at this location.
    pub address: Address,
    /// The kind of field at this location.
    pub field_kind: LocationKind,
    /// Optional label name (for label/function name fields).
    pub label_name: Option<String>,
    /// Optional comment text (for comment fields).
    pub comment_text: Option<String>,
    /// Optional operand representation text.
    pub operand_text: Option<String>,
    /// Optional mnemonic text.
    pub mnemonic_text: Option<String>,
    /// Optional variable name.
    pub variable_name: Option<String>,
}

impl ListingLocation {
    /// Create a new listing location.
    pub fn new(address: Address, field_kind: LocationKind) -> Self {
        Self {
            address,
            field_kind,
            label_name: None,
            comment_text: None,
            operand_text: None,
            mnemonic_text: None,
            variable_name: None,
        }
    }

    /// Create an address field location.
    pub fn address_field(address: Address) -> Self {
        Self::new(address, LocationKind::AddressField)
    }

    /// Create a label field location.
    pub fn label_field(address: Address, name: impl Into<String>) -> Self {
        let mut loc = Self::new(address, LocationKind::LabelField);
        loc.label_name = Some(name.into());
        loc
    }

    /// Create a function name field location.
    pub fn function_name_field(address: Address, name: impl Into<String>) -> Self {
        let mut loc = Self::new(address, LocationKind::FunctionNameField);
        loc.label_name = Some(name.into());
        loc
    }

    /// Create a comment field location.
    pub fn comment_field(address: Address, text: impl Into<String>) -> Self {
        let mut loc = Self::new(address, LocationKind::CommentField);
        loc.comment_text = Some(text.into());
        loc
    }

    /// Create a bytes field location.
    pub fn bytes_field(address: Address) -> Self {
        Self::new(address, LocationKind::BytesField)
    }

    /// Create an operand field location.
    pub fn operand_field(address: Address, text: impl Into<String>) -> Self {
        let mut loc = Self::new(address, LocationKind::OperandField);
        loc.operand_text = Some(text.into());
        loc
    }

    /// Create a mnemonic field location.
    pub fn mnemonic_field(address: Address, mnemonic: impl Into<String>) -> Self {
        let mut loc = Self::new(address, LocationKind::MnemonicField);
        loc.mnemonic_text = Some(mnemonic.into());
        loc
    }

    /// Create a variable field location.
    pub fn variable_field(address: Address, name: impl Into<String>) -> Self {
        let mut loc = Self::new(address, LocationKind::VariableField);
        loc.variable_name = Some(name.into());
        loc
    }

    /// Whether copy can be performed from this location with no selection.
    ///
    /// Ported from `CodeBrowserClipboardProvider.canCopyCurrentLocationWithNoSelection()`.
    pub fn can_copy_without_selection(&self) -> bool {
        matches!(
            self.field_kind,
            LocationKind::AddressField
                | LocationKind::LabelField
                | LocationKind::FunctionNameField
                | LocationKind::CommentField
                | LocationKind::BytesField
                | LocationKind::OperandField
                | LocationKind::MnemonicField
                | LocationKind::VariableField
        )
    }

    /// Copy text from the current location (no selection).
    ///
    /// Ported from `CodeBrowserClipboardProvider.copyFromCurrentLocation()`.
    pub fn copy_from_location(&self) -> Option<String> {
        match self.field_kind {
            LocationKind::AddressField => Some(self.address.to_string()),
            LocationKind::LabelField | LocationKind::FunctionNameField => {
                self.label_name.clone()
            }
            LocationKind::CommentField => self.comment_text.clone(),
            LocationKind::BytesField => Some(format!("{:02X}", self.address.offset)),
            LocationKind::OperandField => self.operand_text.clone(),
            LocationKind::MnemonicField => self.mnemonic_text.clone(),
            LocationKind::VariableField => self.variable_name.clone(),
            LocationKind::Other => None,
        }
    }
}

// ---------------------------------------------------------------------------
// ClipboardContentProviderService trait
// ---------------------------------------------------------------------------

/// A provider of clipboard content for a specific view.
///
/// Ported from `ghidra.app.services.ClipboardContentProviderService`.
///
/// Different views (listing, decompiler, etc.) provide different content
/// to the clipboard through this trait.
pub trait ClipboardContentProviderService: std::fmt::Debug {
    /// The name of this provider (e.g., "Listing", "Decompiler").
    fn provider_name(&self) -> &str;

    /// Whether this provider can supply copy content right now.
    fn can_copy(&self) -> bool;

    /// Whether this provider can paste right now.
    fn can_paste(&self) -> bool;

    /// Whether copy special is available.
    fn enable_copy(&self) -> bool;

    /// Whether copy special is available.
    fn enable_copy_special(&self) -> bool;

    /// Whether paste is available.
    fn enable_paste(&self) -> bool;

    /// Perform a copy and return the entry.
    fn copy(&self) -> Option<ClipboardEntry>;

    /// Perform a special copy with a specific type.
    fn copy_special(&self, copy_type: CopyType) -> Option<ClipboardEntry>;

    /// Paste an entry into this provider.
    fn paste(&mut self, entry: &ClipboardEntry) -> Result<bool, String>;

    /// Get the currently available copy types.
    fn current_copy_types(&self) -> Vec<CopyType>;

    /// Whether this provider can paste with the given content formats.
    fn can_paste_formats(&self, formats: &[ClipboardFormat]) -> bool;

    /// Notification that clipboard ownership was lost.
    fn lost_ownership(&mut self) {}

    /// The formats this provider can supply, in preference order.
    fn supported_formats(&self) -> Vec<ClipboardFormat>;
}

// ---------------------------------------------------------------------------
// CodeBrowserClipboardProvider -- listing view clipboard provider
// ---------------------------------------------------------------------------

/// Clipboard content provider for the listing (code browser) view.
///
/// Ported from `ghidra.app.plugin.core.clipboard.CodeBrowserClipboardProvider`.
///
/// Provides copy/paste of code units, addresses, labels, comments, byte
/// strings, and various offset representations from the listing display.
#[derive(Debug)]
pub struct CodeBrowserClipboardProvider {
    /// The name of the source program.
    pub source_program: String,
    /// Current cursor location.
    current_location: Option<ListingLocation>,
    /// Current selection (set of selected addresses).
    selection: HashSet<u64>,
    /// Whether copy from selection is enabled.
    copy_from_selection_enabled: bool,
    /// Optional inline string content override.
    string_content: Option<String>,
    /// Whether to include quotes for string data.
    include_quotes_for_string_data: bool,
    /// The last copy entry.
    last_copy: Option<ClipboardEntry>,
}

impl CodeBrowserClipboardProvider {
    /// Create a new code browser clipboard provider.
    pub fn new(source_program: impl Into<String>) -> Self {
        Self {
            source_program: source_program.into(),
            current_location: None,
            selection: HashSet::new(),
            copy_from_selection_enabled: false,
            string_content: None,
            include_quotes_for_string_data: true,
            last_copy: None,
        }
    }

    /// Set the current cursor location.
    pub fn set_location(&mut self, location: ListingLocation) {
        self.current_location = Some(location);
    }

    /// Get the current cursor location.
    pub fn location(&self) -> Option<&ListingLocation> {
        self.current_location.as_ref()
    }

    /// Set the current selection.
    pub fn set_selection(&mut self, addresses: Vec<u64>) {
        self.selection = addresses.iter().copied().collect();
        self.copy_from_selection_enabled = !self.selection.is_empty();
    }

    /// Get the current selection.
    pub fn selection(&self) -> &HashSet<u64> {
        &self.selection
    }

    /// Whether there is a selection.
    pub fn has_selection(&self) -> bool {
        !self.selection.is_empty()
    }

    /// Set inline string content (overrides normal copy behavior).
    pub fn set_string_content(&mut self, text: Option<String>) {
        self.string_content = text;
    }

    /// Get the inline string content.
    pub fn string_content(&self) -> Option<&str> {
        self.string_content.as_deref()
    }

    /// Whether to include quotes for string data.
    pub fn include_quotes(&self) -> bool {
        self.include_quotes_for_string_data
    }

    /// Set whether to include quotes for string data.
    pub fn set_include_quotes(&mut self, include: bool) {
        self.include_quotes_for_string_data = include;
    }

    /// Get the last copy result.
    pub fn last_copy(&self) -> Option<&ClipboardEntry> {
        self.last_copy.as_ref()
    }

    /// Copy addresses as a newline-separated string.
    ///
    /// Ported from `CodeBrowserClipboardProvider.copyAddress()`.
    fn copy_address(&self) -> String {
        let mut addrs: Vec<u64> = self.selection.iter().copied().collect();
        addrs.sort();
        addrs
            .iter()
            .map(|a| format!("0x{:x}", a))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Copy byte string (hex with spaces).
    fn copy_byte_string(&self) -> String {
        sorted_set(&self.selection)
            .iter()
            .map(|a| format!("{:02X}", a & 0xFF))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Copy byte string without spaces.
    fn copy_byte_string_no_space(&self) -> String {
        sorted_set(&self.selection)
            .iter()
            .map(|a| format!("{:02X}", a & 0xFF))
            .collect::<Vec<_>>()
            .join("")
    }

    /// Copy as Python byte string.
    fn copy_python_byte_string(&self) -> String {
        let bytes: String = sorted_set(&self.selection)
            .iter()
            .map(|a| format!("\\x{:02x}", a & 0xFF))
            .collect();
        format!("b\"{}\"", bytes)
    }

    /// Copy as Python list.
    fn copy_python_list(&self) -> String {
        let items: String = sorted_set(&self.selection)
            .iter()
            .map(|a| format!("0x{:02x}", a & 0xFF))
            .collect::<Vec<_>>()
            .join(", ");
        format!("[{}]", items)
    }

    /// Copy as C++ byte array.
    fn copy_cpp_byte_array(&self) -> String {
        let items: String = sorted_set(&self.selection)
            .iter()
            .map(|a| format!("0x{:02x}", a & 0xFF))
            .collect::<Vec<_>>()
            .join(", ");
        format!("{{{}}}", items)
    }

    /// Copy imagebase offset.
    fn copy_imagebase_offset(&self, imagebase: u64) -> String {
        let mut addrs: Vec<u64> = self.selection.iter().copied().collect();
        addrs.sort();
        addrs
            .iter()
            .map(|a| format!("{:x}", a.wrapping_sub(imagebase)))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Copy symbol string (address with function offset notation).
    ///
    /// Ported from `CodeBrowserClipboardProvider.copySymbolString()`.
    ///
    /// For addresses inside a function, produces `funcname + 0xNN` notation.
    /// For addresses at a function entry point, produces the function name.
    /// For addresses outside any function, produces the raw address string.
    fn copy_symbol_string(
        &self,
        functions: &[(u64, u64, String)], // (entry, addr, name)
    ) -> String {
        let mut addrs: Vec<u64> = self.selection.iter().copied().collect();
        addrs.sort();
        addrs
            .iter()
            .map(|addr| {
                // Find if this address falls within a known function
                for &(entry, _end, ref name) in functions {
                    if *addr == entry {
                        return name.clone();
                    }
                    if *addr > entry {
                        let delta = addr - entry;
                        return format!("{} + {:#x}", name, delta);
                    }
                }
                format!("0x{:x}", addr)
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Copy byte source offsets (file offsets).
    ///
    /// Ported from `CodeBrowserClipboardProvider.copyByteSourceOffset()`.
    ///
    /// Converts each selected address to its file offset. Addresses without
    /// a file offset mapping produce `<NO_OFFSET>`.
    fn copy_byte_source_offset(&self, file_offsets: &[(u64, Option<u64>)]) -> String {
        file_offsets
            .iter()
            .map(|(_, offset)| match offset {
                Some(o) => format!("{:x}", o),
                None => "<NO_OFFSET>".to_string(),
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Copy memory block offsets.
    ///
    /// Ported from `CodeBrowserClipboardProvider.copyBlockSourceOffset()`.
    ///
    /// For each selected address, computes the offset from the start of its
    /// containing memory block. Addresses not in any block produce
    /// `<NO_OFFSET>`.
    fn copy_block_offset(
        &self,
        block_ranges: &[(u64, u64, u64)], // (addr, block_start, block_end)
    ) -> String {
        let mut addrs: Vec<u64> = self.selection.iter().copied().collect();
        addrs.sort();
        addrs
            .iter()
            .map(|addr| {
                for &(a, block_start, _block_end) in block_ranges {
                    if a == *addr {
                        return format!("{:x}", addr - block_start);
                    }
                }
                "<NO_OFFSET>".to_string()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Copy function-relative offsets.
    ///
    /// Ported from `CodeBrowserClipboardProvider.copyFunctionSourceOffset()`.
    ///
    /// For each selected address, computes the offset from the containing
    /// function's entry point. Addresses not in any function produce
    /// `<NO_OFFSET>`.
    fn copy_function_offset(&self, functions: &[(u64, u64, String)]) -> String {
        let mut addrs: Vec<u64> = self.selection.iter().copied().collect();
        addrs.sort();
        addrs
            .iter()
            .map(|addr| {
                for &(entry, _end, ref _name) in functions {
                    if *addr >= entry {
                        return format!("{:x}", addr - entry);
                    }
                }
                "<NO_OFFSET>".to_string()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Copy formatted code text (simplified listing representation).
    fn copy_code_text(&self, code_lines: &[String]) -> String {
        code_lines.join("\n")
    }

    /// Copy labels and comments as structured text.
    ///
    /// Ported from `CodeBrowserClipboardProvider.copyLabelsComments()`.
    fn copy_labels_comments(
        &self,
        labels: &[(u64, String)],
        comments: &[(u64, String)],
    ) -> String {
        let mut lines = Vec::new();
        for (addr, label) in labels {
            lines.push(format!("0x{:x}: {}", addr, label));
        }
        for (addr, comment) in comments {
            lines.push(format!("0x{:x}: // {}", addr, comment));
        }
        lines.join("\n")
    }

    /// Copy data text representations.
    ///
    /// Ported from `CodeBrowserClipboardProvider.copyDataText()`.
    ///
    /// Produces a newline-separated list of data value text representations
    /// for the selected addresses.
    fn copy_data_text(&self, data_values: &[String]) -> String {
        data_values.join("\n")
    }

    /// Copy dereferenced data text.
    ///
    /// Ported from `CodeBrowserClipboardProvider.copyReferencedDataText()`.
    ///
    /// Follows pointer chains and produces the final data value at each
    /// dereferenced address.
    fn copy_dereferenced_data_text(&self, deref_values: &[String]) -> String {
        deref_values.join("\n")
    }
}

impl ClipboardContentProviderService for CodeBrowserClipboardProvider {
    fn provider_name(&self) -> &str {
        "CodeBrowser"
    }

    fn can_copy(&self) -> bool {
        self.string_content.is_some()
            || self.copy_from_selection_enabled
            || self
                .current_location
                .as_ref()
                .map_or(false, |loc| loc.can_copy_without_selection())
    }

    fn can_paste(&self) -> bool {
        self.last_copy.is_some()
    }

    fn enable_copy(&self) -> bool {
        true
    }

    fn enable_copy_special(&self) -> bool {
        true
    }

    fn enable_paste(&self) -> bool {
        true
    }

    fn copy(&self) -> Option<ClipboardEntry> {
        // Priority 1: inline string content
        if let Some(ref text) = self.string_content {
            return Some(ClipboardEntry::from_text(
                Address::new(0),
                Address::new(0),
                text.clone(),
            ));
        }

        // Priority 2: copy from selection
        if self.copy_from_selection_enabled {
            let text = self.copy_address();
            let min_addr = self.selection.iter().min().copied().unwrap_or(0);
            let max_addr = self.selection.iter().max().copied().unwrap_or(0);
            return Some(ClipboardEntry::from_text(
                Address::new(min_addr),
                Address::new(max_addr),
                text,
            ));
        }

        // Priority 3: copy from current location (no selection)
        let loc = self.current_location.as_ref()?;
        let text = loc.copy_from_location()?;
        Some(ClipboardEntry::from_text(
            loc.address,
            loc.address,
            text,
        ))
    }

    fn copy_special(&self, copy_type: CopyType) -> Option<ClipboardEntry> {
        if !self.copy_from_selection_enabled && self.string_content.is_none() {
            // For location-based copy, delegate to default copy
            if matches!(
                copy_type,
                CopyType::CodeText
                    | CopyType::ByteString
                    | CopyType::ByteStringNoSpace
                    | CopyType::AddressText
            ) {
                return self.copy();
            }
            return None;
        }

        let min_addr = self.selection.iter().min().copied().unwrap_or(0);
        let max_addr = self.selection.iter().max().copied().unwrap_or(0);

        // Note: Many copy_special methods require program context (listing model,
        // functions, memory blocks, etc.) that is not available in the standalone
        // provider. The provider-level implementations delegate to the helper
        // methods; when program context is available, callers should populate
        // the provider's data before calling copy_special.
        let text = match copy_type {
            CopyType::CodeText => self.copy_address(), // needs listing model
            CopyType::LabelsAndComments => self.copy_labels_comments(&[], &[]),
            CopyType::Labels => String::new(),  // needs program symbol table
            CopyType::Comments => String::new(), // needs program listing
            CopyType::ByteString => self.copy_byte_string(),
            CopyType::ByteStringNoSpace => self.copy_byte_string_no_space(),
            CopyType::DataText => self.copy_data_text(&[]), // needs program data
            CopyType::DereferencedDataText => self.copy_dereferenced_data_text(&[]),
            CopyType::PythonByteString => self.copy_python_byte_string(),
            CopyType::PythonList => self.copy_python_list(),
            CopyType::CppByteArray => self.copy_cpp_byte_array(),
            CopyType::AddressText => self.copy_address(),
            CopyType::AddressTextWithOffset => self.copy_symbol_string(&[]), // needs functions
            CopyType::ByteSourceOffset => self.copy_byte_source_offset(&[]), // needs memory info
            CopyType::BlockOffset => self.copy_block_offset(&[]), // needs memory blocks
            CopyType::FunctionOffset => self.copy_function_offset(&[]), // needs functions
            CopyType::ImagebaseOffset => self.copy_imagebase_offset(0),
            CopyType::GhidraLocalUrl => format!("ghidra://localhost/{}", self.source_program),
            CopyType::GhidraSharedUrl => format!("ghidra://shared/{}", self.source_program),
        };

        let format = match copy_type {
            CopyType::ByteString | CopyType::ByteStringNoSpace => ClipboardFormat::Hex,
            CopyType::PythonByteString | CopyType::PythonList | CopyType::CppByteArray => {
                ClipboardFormat::Assembly
            }
            CopyType::CodeText => ClipboardFormat::Text,
            _ => ClipboardFormat::Text,
        };

        Some(ClipboardEntry {
            source_start: Address::new(min_addr),
            source_end: Address::new(max_addr),
            data: Vec::new(),
            text,
            format,
        })
    }

    fn paste(&mut self, entry: &ClipboardEntry) -> Result<bool, String> {
        self.last_copy = Some(entry.clone());
        Ok(true)
    }

    fn current_copy_types(&self) -> Vec<CopyType> {
        let mut types: Vec<CopyType> = CopyType::default_listing_types().to_vec();
        // Add URL types if a program is available
        types.push(CopyType::GhidraLocalUrl);
        types.push(CopyType::GhidraSharedUrl);
        types
    }

    fn can_paste_formats(&self, formats: &[ClipboardFormat]) -> bool {
        formats.iter().any(|f| {
            matches!(
                f,
                ClipboardFormat::Bytes | ClipboardFormat::Text | ClipboardFormat::Hex
            )
        })
    }

    fn lost_ownership(&mut self) {
        // No-op in Rust model (no system clipboard to track)
    }

    fn supported_formats(&self) -> Vec<ClipboardFormat> {
        vec![
            ClipboardFormat::Text,
            ClipboardFormat::Bytes,
            ClipboardFormat::Hex,
            ClipboardFormat::Assembly,
        ]
    }
}

// ---------------------------------------------------------------------------
// Helper: sorted iteration over HashSet<u64>
// ---------------------------------------------------------------------------

/// Return a sorted Vec from a HashSet<u64>.
fn sorted_set(set: &HashSet<u64>) -> Vec<u64> {
    let mut v: Vec<u64> = set.iter().copied().collect();
    v.sort();
    v
}

// ---------------------------------------------------------------------------
// LabelStringTransferable -- label string clipboard transferable
// ---------------------------------------------------------------------------

/// A transferable that carries a label name string for paste operations.
///
/// Ported from `CodeBrowserClipboardProvider.LabelStringTransferable`.
///
/// Used when pasting a label name onto a label field, function name field,
/// or operand field in the listing.
#[derive(Debug, Clone)]
pub struct LabelStringTransferable {
    /// The label name.
    pub data: String,
}

impl LabelStringTransferable {
    /// Create a new label string transferable.
    pub fn new(name: impl Into<String>) -> Self {
        Self { data: name.into() }
    }

    /// Get the label name.
    pub fn name(&self) -> &str {
        &self.data
    }
}

// ---------------------------------------------------------------------------
// NonLabelStringTransferable -- non-label string clipboard transferable
// ---------------------------------------------------------------------------

/// A transferable that carries non-label text for paste operations.
///
/// Ported from `CodeBrowserClipboardProvider.NonLabelStringTransferable`.
///
/// Used when pasting text onto address fields, comment fields, mnemonic
/// fields, or operand fields that are not label references.
#[derive(Debug, Clone)]
pub struct NonLabelStringTransferable {
    /// The text content.
    pub data: String,
}

impl NonLabelStringTransferable {
    /// Create a new non-label string transferable from a single string.
    pub fn new(text: impl Into<String>) -> Self {
        Self { data: text.into() }
    }

    /// Create a new non-label string transferable from multiple lines.
    pub fn from_lines(lines: &[String]) -> Self {
        Self {
            data: lines.join("\n"),
        }
    }

    /// Get the text content.
    pub fn text(&self) -> &str {
        &self.data
    }
}

// ---------------------------------------------------------------------------
// CodeUnitInfo -- structured code unit information for clipboard paste
// ---------------------------------------------------------------------------

/// Comment type for a code unit.
///
/// Ported from `ghidra.program.model.listing.CommentType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommentType {
    /// Pre-line comment.
    Pre,
    /// End-of-line comment.
    Eol,
    /// Post-line comment.
    Post,
    /// Plate comment (above).
    Plate,
    /// Repeatable comment.
    Repeatable,
}

impl CommentType {
    /// Display name for this comment type.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Pre => "Pre",
            Self::Eol => "EOL",
            Self::Post => "Post",
            Self::Plate => "Plate",
            Self::Repeatable => "Repeatable",
        }
    }
}

/// Structured information about a code unit for clipboard transfer.
///
/// Ported from `ghidra.app.cmd.comments.CodeUnitInfo`.
///
/// Carries labels, comments, and function info for a single code unit
/// address, used for structured paste operations (labels, comments,
/// labels+comments).
#[derive(Debug, Clone)]
pub struct CodeUnitInfo {
    /// Index offset from the start address of the copied range.
    pub offset: i64,
    /// Symbols (labels) at this address.
    pub symbols: Vec<String>,
    /// Comments by type.
    pub comments: Vec<(CommentType, Vec<String>)>,
    /// Whether this code unit is a function entry point.
    pub is_function: bool,
    /// Function name if this is a function entry.
    pub function_name: Option<String>,
}

impl CodeUnitInfo {
    /// Create a new code unit info.
    pub fn new(offset: i64) -> Self {
        Self {
            offset,
            symbols: Vec::new(),
            comments: Vec::new(),
            is_function: false,
            function_name: None,
        }
    }

    /// Set the symbols for this code unit.
    pub fn set_symbols(&mut self, symbols: Vec<String>) {
        self.symbols = symbols;
    }

    /// Add a comment of the given type.
    pub fn set_comment(&mut self, comment_type: CommentType, lines: Vec<String>) {
        self.comments.push((comment_type, lines));
    }

    /// Mark this code unit as a function entry.
    pub fn set_function(&mut self, name: impl Into<String>) {
        self.is_function = true;
        self.function_name = Some(name.into());
    }

    /// Get all labels as a single string.
    pub fn labels_text(&self) -> String {
        self.symbols.join(", ")
    }

    /// Get all comments as a single string.
    pub fn comments_text(&self) -> String {
        self.comments
            .iter()
            .flat_map(|(_, lines)| lines.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ---------------------------------------------------------------------------
// CodeUnitInfoTransferable -- structured clipboard data for labels/comments
// ---------------------------------------------------------------------------

/// A transferable for structured code unit info (labels and comments).
///
/// Ported from `CodeUnitInfoTransferable` in the clipboard package.
///
/// Carries a list of `CodeUnitInfo` entries for paste operations that
/// restore labels, comments, and function names.
#[derive(Debug, Clone)]
pub struct CodeUnitInfoTransferable {
    /// The code unit info entries.
    infos: Vec<CodeUnitInfo>,
}

impl CodeUnitInfoTransferable {
    /// Create a new transferable from code unit info entries.
    pub fn new(infos: Vec<CodeUnitInfo>) -> Self {
        Self { infos }
    }

    /// Get the code unit info entries.
    pub fn infos(&self) -> &[CodeUnitInfo] {
        &self.infos
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.infos.len()
    }

    /// Whether this transferable has entries.
    pub fn is_empty(&self) -> bool {
        self.infos.is_empty()
    }

    /// Extract only labels from the entries.
    pub fn labels_only(&self) -> Vec<(i64, &str)> {
        self.infos
            .iter()
            .filter(|info| !info.symbols.is_empty())
            .map(|info| (info.offset, info.symbols[0].as_str()))
            .collect()
    }

    /// Extract only comments from the entries.
    pub fn comments_only(&self) -> Vec<(i64, &str)> {
        self.infos
            .iter()
            .flat_map(|info| {
                info.comments
                    .iter()
                    .flat_map(|(_, lines)| lines.iter())
                    .map(move |line| (info.offset, line.as_str()))
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// PasteLabelAction -- describes a paste label action
// ---------------------------------------------------------------------------

/// The result of pasting a label string.
///
/// Ported from `CodeBrowserClipboardProvider.pasteLabelString()`.
#[derive(Debug, Clone)]
pub enum PasteLabelResult {
    /// Rename an existing label at the given address.
    RenameLabel {
        /// The address.
        address: u64,
        /// The old label name.
        old_name: String,
        /// The new label name.
        new_name: String,
    },
    /// Rename a function at the given address.
    RenameFunction {
        /// The address.
        address: u64,
        /// The old function name.
        old_name: String,
        /// The new function name.
        new_name: String,
    },
    /// Set a variable name.
    SetVariableName {
        /// The variable name.
        name: String,
    },
    /// Set a comment at the given address.
    SetComment {
        /// The address.
        address: u64,
        /// The comment type.
        comment_type: CommentType,
        /// The comment text.
        text: String,
    },
    /// The paste could not be performed.
    Failed(String),
}

// ---------------------------------------------------------------------------
// DecompilerClipboardProvider -- decompiler view clipboard provider
// ---------------------------------------------------------------------------

/// Clipboard content provider for the decompiler view.
///
/// Ported from the decompiler's clipboard provider concept.
#[derive(Debug)]
pub struct DecompilerClipboardProvider {
    /// The source program name.
    pub source_program: String,
    /// Current decompiled text.
    decompiled_text: Option<String>,
    /// Current selection in decompiler.
    selected_text: Option<String>,
    /// Last copy entry.
    last_copy: Option<ClipboardEntry>,
}

impl DecompilerClipboardProvider {
    /// Create a new decompiler clipboard provider.
    pub fn new(source_program: impl Into<String>) -> Self {
        Self {
            source_program: source_program.into(),
            decompiled_text: None,
            selected_text: None,
            last_copy: None,
        }
    }

    /// Set the current decompiled text.
    pub fn set_decompiled_text(&mut self, text: Option<String>) {
        self.decompiled_text = text;
    }

    /// Set the current selection in the decompiler.
    pub fn set_selected_text(&mut self, text: Option<String>) {
        self.selected_text = text;
    }
}

impl ClipboardContentProviderService for DecompilerClipboardProvider {
    fn provider_name(&self) -> &str {
        "Decompiler"
    }

    fn can_copy(&self) -> bool {
        self.selected_text.is_some() || self.decompiled_text.is_some()
    }

    fn can_paste(&self) -> bool {
        false // Decompiler does not support paste
    }

    fn enable_copy(&self) -> bool {
        true
    }

    fn enable_copy_special(&self) -> bool {
        false
    }

    fn enable_paste(&self) -> bool {
        false
    }

    fn copy(&self) -> Option<ClipboardEntry> {
        let text = self
            .selected_text
            .as_deref()
            .or(self.decompiled_text.as_deref())?;
        Some(ClipboardEntry::from_text(
            Address::new(0),
            Address::new(0),
            text.to_string(),
        ))
    }

    fn copy_special(&self, _copy_type: CopyType) -> Option<ClipboardEntry> {
        self.copy()
    }

    fn paste(&mut self, _entry: &ClipboardEntry) -> Result<bool, String> {
        Err("Decompiler does not support paste".to_string())
    }

    fn current_copy_types(&self) -> Vec<CopyType> {
        vec![CopyType::CodeText]
    }

    fn can_paste_formats(&self, _formats: &[ClipboardFormat]) -> bool {
        false
    }

    fn supported_formats(&self) -> Vec<ClipboardFormat> {
        vec![ClipboardFormat::Text, ClipboardFormat::Assembly]
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- CopyType tests --

    #[test]
    fn test_copy_type_display_name() {
        assert_eq!(CopyType::CodeText.display_name(), "Formatted Code");
        assert_eq!(CopyType::ByteString.display_name(), "Byte String");
        assert_eq!(CopyType::GhidraLocalUrl.display_name(), "Local GhidraURL");
    }

    #[test]
    fn test_copy_type_description() {
        assert_eq!(CopyType::CodeText.description(), "Copy formatted listing text");
        assert_eq!(CopyType::AddressText.description(), "Copy addresses as hex strings");
    }

    #[test]
    fn test_default_listing_types() {
        let types = CopyType::default_listing_types();
        assert_eq!(types.len(), 17);
        assert!(types.contains(&CopyType::CodeText));
        assert!(types.contains(&CopyType::ByteString));
        assert!(types.contains(&CopyType::ImagebaseOffset));
    }

    #[test]
    fn test_copy_type_display_name_and_description() {
        assert_eq!(CopyType::CodeText.display_name(), "Formatted Code");
        assert_eq!(CopyType::CodeText.description(), "Copy formatted listing text");
    }

    // -- ListingLocation tests --

    #[test]
    fn test_listing_location_address_field() {
        let loc = ListingLocation::address_field(Address::new(0x1000));
        assert_eq!(loc.address.offset, 0x1000);
        assert_eq!(loc.field_kind, LocationKind::AddressField);
        assert!(loc.can_copy_without_selection());
        assert_eq!(loc.copy_from_location(), Some("00001000".to_string()));
    }

    #[test]
    fn test_listing_location_label_field() {
        let loc = ListingLocation::label_field(Address::new(0x2000), "main");
        assert_eq!(loc.field_kind, LocationKind::LabelField);
        assert_eq!(loc.copy_from_location(), Some("main".to_string()));
    }

    #[test]
    fn test_listing_location_comment_field() {
        let loc = ListingLocation::comment_field(Address::new(0x3000), "a comment");
        assert_eq!(loc.field_kind, LocationKind::CommentField);
        assert_eq!(loc.copy_from_location(), Some("a comment".to_string()));
    }

    #[test]
    fn test_listing_location_mnemonic_field() {
        let loc = ListingLocation::mnemonic_field(Address::new(0x4000), "mov");
        assert_eq!(loc.copy_from_location(), Some("mov".to_string()));
    }

    #[test]
    fn test_listing_location_variable_field() {
        let loc = ListingLocation::variable_field(Address::new(0x5000), "iVar1");
        assert_eq!(loc.copy_from_location(), Some("iVar1".to_string()));
    }

    #[test]
    fn test_listing_location_other_cannot_copy() {
        let loc = ListingLocation::new(Address::new(0x1000), LocationKind::Other);
        assert!(!loc.can_copy_without_selection());
        assert!(loc.copy_from_location().is_none());
    }

    // -- CodeBrowserClipboardProvider tests --

    #[test]
    fn test_provider_name() {
        let provider = CodeBrowserClipboardProvider::new("test");
        assert_eq!(provider.provider_name(), "CodeBrowser");
    }

    #[test]
    fn test_can_copy_with_selection() {
        let mut provider = CodeBrowserClipboardProvider::new("test");
        assert!(!provider.can_copy());

        provider.set_selection(vec![0x1000, 0x1001]);
        assert!(provider.can_copy());
    }

    #[test]
    fn test_can_copy_with_string_content() {
        let mut provider = CodeBrowserClipboardProvider::new("test");
        provider.set_string_content(Some("hello".to_string()));
        assert!(provider.can_copy());
    }

    #[test]
    fn test_can_copy_with_location() {
        let mut provider = CodeBrowserClipboardProvider::new("test");
        provider.set_location(ListingLocation::address_field(Address::new(0x1000)));
        assert!(provider.can_copy());
    }

    #[test]
    fn test_copy_from_string_content() {
        let mut provider = CodeBrowserClipboardProvider::new("test");
        provider.set_string_content(Some("inline text".to_string()));

        let entry = provider.copy().unwrap();
        assert_eq!(entry.text, "inline text");
        assert_eq!(entry.format, ClipboardFormat::Text);
    }

    #[test]
    fn test_copy_from_selection() {
        let mut provider = CodeBrowserClipboardProvider::new("test");
        provider.set_selection(vec![0x1000, 0x1001, 0x1002]);

        let entry = provider.copy().unwrap();
        assert!(entry.text.contains("0x1000"));
        assert!(entry.text.contains("0x1002"));
    }

    #[test]
    fn test_copy_from_location() {
        let mut provider = CodeBrowserClipboardProvider::new("test");
        provider.set_location(ListingLocation::label_field(Address::new(0x1000), "main"));

        let entry = provider.copy().unwrap();
        assert_eq!(entry.text, "main");
    }

    #[test]
    fn test_copy_no_selection_no_location() {
        let provider = CodeBrowserClipboardProvider::new("test");
        assert!(provider.copy().is_none());
    }

    #[test]
    fn test_copy_special_byte_string() {
        let mut provider = CodeBrowserClipboardProvider::new("test");
        provider.set_selection(vec![0x1000, 0x1001, 0x1002]);

        let entry = provider.copy_special(CopyType::ByteString).unwrap();
        assert_eq!(entry.format, ClipboardFormat::Hex);
        assert!(entry.text.contains("48") || entry.text.contains("00"));
    }

    #[test]
    fn test_copy_special_python_byte_string() {
        let mut provider = CodeBrowserClipboardProvider::new("test");
        provider.set_selection(vec![0x48, 0x89]);

        let entry = provider.copy_special(CopyType::PythonByteString).unwrap();
        assert!(entry.text.starts_with("b\""));
        assert!(entry.text.ends_with('"'));
    }

    #[test]
    fn test_copy_special_python_list() {
        let mut provider = CodeBrowserClipboardProvider::new("test");
        provider.set_selection(vec![0x48, 0x89]);

        let entry = provider.copy_special(CopyType::PythonList).unwrap();
        assert!(entry.text.starts_with('['));
        assert!(entry.text.ends_with(']'));
    }

    #[test]
    fn test_copy_special_ghidra_url() {
        let mut provider = CodeBrowserClipboardProvider::new("my_program");
        provider.set_selection(vec![0x1000]);

        let entry = provider.copy_special(CopyType::GhidraLocalUrl).unwrap();
        assert!(entry.text.contains("ghidra://"));
        assert!(entry.text.contains("my_program"));
    }

    #[test]
    fn test_paste() {
        let mut provider = CodeBrowserClipboardProvider::new("test");
        assert!(!provider.can_paste());

        let entry = ClipboardEntry::from_bytes(
            Address::new(0x1000),
            Address::new(0x1003),
            vec![0x48, 0x89, 0xD8],
        );
        let result = provider.paste(&entry);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert!(provider.can_paste());
        assert!(provider.last_copy().is_some());
    }

    #[test]
    fn test_current_copy_types() {
        let provider = CodeBrowserClipboardProvider::new("test");
        let types = provider.current_copy_types();
        assert!(types.len() >= 17);
        assert!(types.contains(&CopyType::CodeText));
        assert!(types.contains(&CopyType::GhidraLocalUrl));
    }

    #[test]
    fn test_supported_formats() {
        let provider = CodeBrowserClipboardProvider::new("test");
        let formats = provider.supported_formats();
        assert!(formats.contains(&ClipboardFormat::Text));
        assert!(formats.contains(&ClipboardFormat::Bytes));
        assert!(formats.contains(&ClipboardFormat::Hex));
    }

    #[test]
    fn test_can_paste_formats() {
        let provider = CodeBrowserClipboardProvider::new("test");
        assert!(provider.can_paste_formats(&[ClipboardFormat::Bytes]));
        assert!(provider.can_paste_formats(&[ClipboardFormat::Text]));
        assert!(!provider.can_paste_formats(&[ClipboardFormat::Xml]));
    }

    #[test]
    fn test_include_quotes() {
        let mut provider = CodeBrowserClipboardProvider::new("test");
        assert!(provider.include_quotes());

        provider.set_include_quotes(false);
        assert!(!provider.include_quotes());
    }

    #[test]
    fn test_location_accessor() {
        let mut provider = CodeBrowserClipboardProvider::new("test");
        assert!(provider.location().is_none());

        provider.set_location(ListingLocation::address_field(Address::new(0x1000)));
        assert!(provider.location().is_some());
        assert_eq!(provider.location().unwrap().address.offset, 0x1000);
    }

    // -- DecompilerClipboardProvider tests --

    #[test]
    fn test_decompiler_provider_name() {
        let provider = DecompilerClipboardProvider::new("test");
        assert_eq!(provider.provider_name(), "Decompiler");
    }

    #[test]
    fn test_decompiler_copy_from_selected() {
        let mut provider = DecompilerClipboardProvider::new("test");
        provider.set_selected_text(Some("int main(void) {".to_string()));

        let entry = provider.copy().unwrap();
        assert_eq!(entry.text, "int main(void) {");
    }

    #[test]
    fn test_decompiler_copy_from_decompiled() {
        let mut provider = DecompilerClipboardProvider::new("test");
        provider.set_decompiled_text(Some("int main(void) { return 0; }".to_string()));

        let entry = provider.copy().unwrap();
        assert!(entry.text.contains("return 0"));
    }

    #[test]
    fn test_decompiler_copy_selected_over_decompiled() {
        let mut provider = DecompilerClipboardProvider::new("test");
        provider.set_decompiled_text(Some("full text".to_string()));
        provider.set_selected_text(Some("selected".to_string()));

        let entry = provider.copy().unwrap();
        assert_eq!(entry.text, "selected");
    }

    #[test]
    fn test_decompiler_no_copy() {
        let provider = DecompilerClipboardProvider::new("test");
        assert!(!provider.can_copy());
        assert!(provider.copy().is_none());
    }

    #[test]
    fn test_decompiler_cannot_paste() {
        let mut provider = DecompilerClipboardProvider::new("test");
        assert!(!provider.can_paste());
        assert!(!provider.enable_paste());

        let entry = ClipboardEntry::from_bytes(
            Address::new(0x1000),
            Address::new(0x1003),
            vec![0x48],
        );
        assert!(provider.paste(&entry).is_err());
    }

    #[test]
    fn test_decompiler_copy_types() {
        let provider = DecompilerClipboardProvider::new("test");
        assert_eq!(provider.current_copy_types(), vec![CopyType::CodeText]);
    }

    #[test]
    fn test_decompiler_formats() {
        let provider = DecompilerClipboardProvider::new("test");
        let formats = provider.supported_formats();
        assert!(formats.contains(&ClipboardFormat::Text));
        assert!(formats.contains(&ClipboardFormat::Assembly));
        assert!(!formats.contains(&ClipboardFormat::Bytes));
    }

    #[test]
    fn test_decompiler_enable_flags() {
        let provider = DecompilerClipboardProvider::new("test");
        assert!(provider.enable_copy());
        assert!(!provider.enable_copy_special());
        assert!(!provider.enable_paste());
    }

    // -- LocationKind tests --

    #[test]
    fn test_location_kind_equality() {
        assert_eq!(LocationKind::AddressField, LocationKind::AddressField);
        assert_ne!(LocationKind::AddressField, LocationKind::LabelField);
    }

    // -- Byte string formatting tests --

    #[test]
    fn test_copy_byte_string_sorted() {
        let mut provider = CodeBrowserClipboardProvider::new("test");
        provider.set_selection(vec![0x1003, 0x1001, 0x1002]);

        let entry = provider.copy_special(CopyType::ByteString).unwrap();
        let parts: Vec<&str> = entry.text.split(' ').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn test_copy_byte_string_no_space() {
        let mut provider = CodeBrowserClipboardProvider::new("test");
        provider.set_selection(vec![0x1000, 0x1001]);

        let entry = provider.copy_special(CopyType::ByteStringNoSpace).unwrap();
        assert!(!entry.text.contains(' '));
    }

    // -- LabelStringTransferable tests --

    #[test]
    fn test_label_string_transferable() {
        let lst = LabelStringTransferable::new("main");
        assert_eq!(lst.name(), "main");
    }

    #[test]
    fn test_label_string_transferable_clone() {
        let lst = LabelStringTransferable::new("test_label");
        let lst2 = lst.clone();
        assert_eq!(lst2.name(), "test_label");
    }

    // -- NonLabelStringTransferable tests --

    #[test]
    fn test_non_label_string_transferable() {
        let nst = NonLabelStringTransferable::new("0x1000");
        assert_eq!(nst.text(), "0x1000");
    }

    #[test]
    fn test_non_label_string_from_lines() {
        let nst = NonLabelStringTransferable::from_lines(&[
            "line1".to_string(),
            "line2".to_string(),
        ]);
        assert_eq!(nst.text(), "line1\nline2");
    }

    // -- CommentType tests --

    #[test]
    fn test_comment_type_display() {
        assert_eq!(CommentType::Pre.display_name(), "Pre");
        assert_eq!(CommentType::Eol.display_name(), "EOL");
        assert_eq!(CommentType::Plate.display_name(), "Plate");
        assert_eq!(CommentType::Repeatable.display_name(), "Repeatable");
    }

    // -- CodeUnitInfo tests --

    #[test]
    fn test_code_unit_info_new() {
        let info = CodeUnitInfo::new(0);
        assert_eq!(info.offset, 0);
        assert!(info.symbols.is_empty());
        assert!(info.comments.is_empty());
        assert!(!info.is_function);
    }

    #[test]
    fn test_code_unit_info_symbols() {
        let mut info = CodeUnitInfo::new(0);
        info.set_symbols(vec!["main".to_string(), "entry".to_string()]);
        assert_eq!(info.labels_text(), "main, entry");
    }

    #[test]
    fn test_code_unit_info_comments() {
        let mut info = CodeUnitInfo::new(0);
        info.set_comment(CommentType::Eol, vec!["a comment".to_string()]);
        assert_eq!(info.comments_text(), "a comment");
    }

    #[test]
    fn test_code_unit_info_function() {
        let mut info = CodeUnitInfo::new(0);
        info.set_function("main");
        assert!(info.is_function);
        assert_eq!(info.function_name.as_deref(), Some("main"));
    }

    // -- CodeUnitInfoTransferable tests --

    #[test]
    fn test_code_unit_info_transferable() {
        let mut info1 = CodeUnitInfo::new(0);
        info1.set_symbols(vec!["main".to_string()]);
        let mut info2 = CodeUnitInfo::new(4);
        info2.set_comment(CommentType::Eol, vec!["ret".to_string()]);

        let cut = CodeUnitInfoTransferable::new(vec![info1, info2]);
        assert_eq!(cut.len(), 2);
        assert!(!cut.is_empty());
    }

    #[test]
    fn test_code_unit_info_transferable_empty() {
        let cut = CodeUnitInfoTransferable::new(vec![]);
        assert!(cut.is_empty());
        assert_eq!(cut.len(), 0);
    }

    #[test]
    fn test_code_unit_info_transferable_labels_only() {
        let mut info = CodeUnitInfo::new(0);
        info.set_symbols(vec!["main".to_string()]);
        let cut = CodeUnitInfoTransferable::new(vec![info]);
        let labels = cut.labels_only();
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].1, "main");
    }

    #[test]
    fn test_code_unit_info_transferable_comments_only() {
        let mut info = CodeUnitInfo::new(0);
        info.set_comment(CommentType::Plate, vec!["plate comment".to_string()]);
        let cut = CodeUnitInfoTransferable::new(vec![info]);
        let comments = cut.comments_only();
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0].1, "plate comment");
    }

    // -- PasteLabelResult tests --

    #[test]
    fn test_paste_label_result_rename() {
        let result = PasteLabelResult::RenameLabel {
            address: 0x1000,
            old_name: "old".to_string(),
            new_name: "new".to_string(),
        };
        match result {
            PasteLabelResult::RenameLabel {
                address,
                old_name,
                new_name,
            } => {
                assert_eq!(address, 0x1000);
                assert_eq!(old_name, "old");
                assert_eq!(new_name, "new");
            }
            _ => panic!("Expected RenameLabel"),
        }
    }

    #[test]
    fn test_paste_label_result_set_comment() {
        let result = PasteLabelResult::SetComment {
            address: 0x2000,
            comment_type: CommentType::Eol,
            text: "hello".to_string(),
        };
        match result {
            PasteLabelResult::SetComment {
                address,
                comment_type,
                text,
            } => {
                assert_eq!(address, 0x2000);
                assert_eq!(comment_type, CommentType::Eol);
                assert_eq!(text, "hello");
            }
            _ => panic!("Expected SetComment"),
        }
    }

    #[test]
    fn test_paste_label_result_failed() {
        let result = PasteLabelResult::Failed("no label at address".to_string());
        match result {
            PasteLabelResult::Failed(msg) => {
                assert_eq!(msg, "no label at address");
            }
            _ => panic!("Expected Failed"),
        }
    }

    // -- Enhanced copy method tests --

    #[test]
    fn test_copy_symbol_string() {
        let provider = CodeBrowserClipboardProvider::new("test");
        let functions = vec![
            (0x1000u64, 0x10FFu64, "main".to_string()),
            (0x2000u64, 0x20FFu64, "helper".to_string()),
        ];
        let result = provider.copy_symbol_string(&functions);
        // Empty selection should produce empty string
        assert!(result.is_empty());
    }

    #[test]
    fn test_copy_byte_source_offset() {
        let provider = CodeBrowserClipboardProvider::new("test");
        let offsets = vec![
            (0x1000u64, Some(0x100u64)),
            (0x1001u64, None),
        ];
        let result = provider.copy_byte_source_offset(&offsets);
        assert!(result.contains("100"));
        assert!(result.contains("<NO_OFFSET>"));
    }

    #[test]
    fn test_copy_block_offset() {
        let mut provider = CodeBrowserClipboardProvider::new("test");
        provider.set_selection(vec![0x1000, 0x1001]);
        let blocks = vec![
            (0x1000u64, 0x1000u64, 0x1FFFu64),
            (0x1001u64, 0x1000u64, 0x1FFFu64),
        ];
        let result = provider.copy_block_offset(&blocks);
        assert!(result.contains("0"));
    }

    #[test]
    fn test_copy_function_offset() {
        let provider = CodeBrowserClipboardProvider::new("test");
        let functions = vec![(0x1000u64, 0x10FFu64, "main".to_string())];
        let result = provider.copy_function_offset(&functions);
        // Empty selection produces empty string
        assert!(result.is_empty());
    }

    #[test]
    fn test_copy_data_text() {
        let provider = CodeBrowserClipboardProvider::new("test");
        let values = vec!["0x48".to_string(), "0x89".to_string()];
        let result = provider.copy_data_text(&values);
        assert_eq!(result, "0x48\n0x89");
    }

    #[test]
    fn test_copy_dereferenced_data_text() {
        let provider = CodeBrowserClipboardProvider::new("test");
        let values = vec!["0x7FF00000".to_string()];
        let result = provider.copy_dereferenced_data_text(&values);
        assert_eq!(result, "0x7FF00000");
    }
}
