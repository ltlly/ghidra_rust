//! Clipboard service interfaces -- ported from Ghidra's clipboard package.
//!
//! Provides the clipboard service trait and content provider service trait.
//!
//! Ported from:
//! - `ghidra.app.services.ClipboardService`
//! - `ghidra.app.services.ClipboardContentProviderService`

use ghidra_core::Address;

use super::{ClipboardEntry, ClipboardFormat, ClipboardManager, ProgramTransferable};

// ---------------------------------------------------------------------------
// ClipboardType -- a type of clipboard content
// ---------------------------------------------------------------------------

/// The type of content being copied to the clipboard.
///
/// Ported from `ghidra.app.util.ClipboardType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClipboardType {
    /// Raw bytes.
    Bytes,
    /// Listing text (formatted code).
    ListingText,
    /// Labels and comments.
    LabelsAndComments,
    /// Labels only.
    Labels,
    /// Comments only.
    Comments,
    /// Byte string (hex bytes).
    ByteString,
    /// Address table.
    AddressTable,
    /// Assembly source code.
    AssemblySource,
    /// Ghidra internal URL.
    GhidraUrl,
}

impl ClipboardType {
    /// Display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Bytes => "Bytes",
            Self::ListingText => "Listing Text",
            Self::LabelsAndComments => "Labels and Comments",
            Self::Labels => "Labels",
            Self::Comments => "Comments",
            Self::ByteString => "Byte String",
            Self::AddressTable => "Address Table",
            Self::AssemblySource => "Assembly Source",
            Self::GhidraUrl => "Ghidra URL",
        }
    }

    /// The MIME-like identifier for this clipboard type.
    pub fn mime_id(&self) -> &'static str {
        match self {
            Self::Bytes => "ghidra.bytes",
            Self::ListingText => "ghidra.listing.text",
            Self::LabelsAndComments => "ghidra.labels.comments",
            Self::Labels => "ghidra.labels",
            Self::Comments => "ghidra.comments",
            Self::ByteString => "ghidra.byte.string",
            Self::AddressTable => "ghidra.address.table",
            Self::AssemblySource => "ghidra.assembly",
            Self::GhidraUrl => "ghidra.url",
        }
    }

    /// All clipboard types.
    pub fn all() -> &'static [ClipboardType] {
        &[
            Self::Bytes,
            Self::ListingText,
            Self::LabelsAndComments,
            Self::Labels,
            Self::Comments,
            Self::ByteString,
            Self::AddressTable,
            Self::AssemblySource,
            Self::GhidraUrl,
        ]
    }
}

// ---------------------------------------------------------------------------
// ClipboardService trait
// ---------------------------------------------------------------------------

/// Service for clipboard operations provided by the clipboard plugin.
///
/// Ported from `ghidra.app.services.ClipboardService`.
///
/// Content provider services register with this service to supply
/// and consume clipboard data.
pub trait ClipboardService {
    /// Copy the current selection to the clipboard.
    fn copy(&self) -> Option<ClipboardEntry>;

    /// Copy with a specific type.
    fn copy_special(&self, clipboard_type: ClipboardType) -> Option<ClipboardEntry>;

    /// Paste from the clipboard into the current location.
    fn paste(&self, entry: &ClipboardEntry) -> Result<(), String>;

    /// Whether paste is currently available.
    fn can_paste(&self) -> bool;

    /// Get the current clipboard contents.
    fn get_contents(&self) -> Option<&ClipboardEntry>;
}

// ---------------------------------------------------------------------------
// ClipboardContentProviderService trait
// ---------------------------------------------------------------------------

/// A provider of clipboard content for a specific view.
///
/// Ported from `ghidra.app.services.ClipboardContentProviderService`.
///
/// Different views (listing, decompiler, etc.) provide different
/// content to the clipboard through this trait.
pub trait ClipboardContentProviderService {
    /// The name of this provider.
    fn provider_name(&self) -> &str;

    /// Whether this provider can supply copy content right now.
    fn can_copy(&self) -> bool;

    /// Whether this provider can paste right now.
    fn can_paste(&self) -> bool;

    /// Perform a copy and return the entry.
    fn copy(&self) -> Option<ClipboardEntry>;

    /// Perform a special copy with a specific type.
    fn copy_special(&self, clipboard_type: ClipboardType) -> Option<ClipboardEntry>;

    /// Paste an entry into this provider.
    fn paste(&mut self, entry: &ClipboardEntry) -> Result<(), String>;

    /// The formats this provider can supply, in preference order.
    fn supported_formats(&self) -> Vec<ClipboardFormat>;
}

// ---------------------------------------------------------------------------
// ListingClipboardProvider -- listing view clipboard provider
// ---------------------------------------------------------------------------

/// Clipboard content provider for the listing (code browser) view.
///
/// Provides copy/paste of code units, addresses, labels, and comments
/// from the listing display.
#[derive(Debug)]
pub struct ListingClipboardProvider {
    /// The name of the source program.
    pub source_program: String,
    /// Current selection (address offsets).
    selection: Vec<u64>,
    /// The last copy entry.
    last_copy: Option<ClipboardEntry>,
}

impl ListingClipboardProvider {
    /// Create a new listing clipboard provider.
    pub fn new(source_program: impl Into<String>) -> Self {
        Self {
            source_program: source_program.into(),
            selection: Vec::new(),
            last_copy: None,
        }
    }

    /// Set the current selection.
    pub fn set_selection(&mut self, addresses: Vec<u64>) {
        self.selection = addresses;
    }

    /// Get the current selection.
    pub fn selection(&self) -> &[u64] {
        &self.selection
    }

    /// Whether there is a selection.
    pub fn has_selection(&self) -> bool {
        !self.selection.is_empty()
    }

    /// Get the last copy result.
    pub fn last_copy(&self) -> Option<&ClipboardEntry> {
        self.last_copy.as_ref()
    }
}

impl ClipboardContentProviderService for ListingClipboardProvider {
    fn provider_name(&self) -> &str {
        "Listing"
    }

    fn can_copy(&self) -> bool {
        self.has_selection()
    }

    fn can_paste(&self) -> bool {
        self.last_copy.is_some()
    }

    fn copy(&self) -> Option<ClipboardEntry> {
        if !self.has_selection() {
            return None;
        }
        let start = Address::new(self.selection[0]);
        let end = Address::new(*self.selection.last().unwrap_or(&self.selection[0]));
        let data: Vec<u8> = self
            .selection
            .iter()
            .flat_map(|a| a.to_le_bytes())
            .collect();
        Some(ClipboardEntry::from_bytes(start, end, data))
    }

    fn copy_special(&self, clipboard_type: ClipboardType) -> Option<ClipboardEntry> {
        match clipboard_type {
            ClipboardType::Bytes => self.copy(),
            ClipboardType::ByteString => self.copy().map(|mut e| {
                e.format = ClipboardFormat::Hex;
                e
            }),
            ClipboardType::ListingText => self.copy().map(|mut e| {
                e.format = ClipboardFormat::Text;
                e
            }),
            _ => self.copy(),
        }
    }

    fn paste(&mut self, entry: &ClipboardEntry) -> Result<(), String> {
        self.last_copy = Some(entry.clone());
        Ok(())
    }

    fn supported_formats(&self) -> Vec<ClipboardFormat> {
        vec![
            ClipboardFormat::Bytes,
            ClipboardFormat::Text,
            ClipboardFormat::Hex,
            ClipboardFormat::Assembly,
        ]
    }
}

// ---------------------------------------------------------------------------
// ClipboardPluginModel -- the plugin-level clipboard model
// ---------------------------------------------------------------------------

/// Plugin-level model managing clipboard state and provider registration.
///
/// Ported from `ghidra.app.plugin.core.clipboard.ClipboardPlugin`.
#[derive(Debug)]
pub struct ClipboardPluginModel {
    /// Registered content providers.
    providers: Vec<String>,
    /// The last provider name that supplied content.
    last_provider: Option<String>,
    /// The last clipboard type used for copy-special.
    last_copy_special_type: Option<ClipboardType>,
    /// Whether to remove quotes from string copies.
    pub remove_quotes: bool,
    /// Clipboard manager for history.
    manager: ClipboardManager,
}

impl ClipboardPluginModel {
    /// Create a new clipboard plugin model.
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
            last_provider: None,
            last_copy_special_type: None,
            remove_quotes: false,
            manager: ClipboardManager::new(),
        }
    }

    /// Register a content provider.
    pub fn register_provider(&mut self, name: impl Into<String>) {
        let n = name.into();
        if !self.providers.contains(&n) {
            self.providers.push(n);
        }
    }

    /// Unregister a content provider.
    pub fn unregister_provider(&mut self, name: &str) {
        self.providers.retain(|n| n != name);
    }

    /// Get registered providers.
    pub fn providers(&self) -> &[String] {
        &self.providers
    }

    /// Set the active provider.
    pub fn set_active_provider(&mut self, name: impl Into<String>) {
        self.last_provider = Some(name.into());
    }

    /// Get the active provider.
    pub fn active_provider(&self) -> Option<&str> {
        self.last_provider.as_deref()
    }

    /// Record a copy-special type.
    pub fn set_last_copy_special_type(&mut self, ct: ClipboardType) {
        self.last_copy_special_type = Some(ct);
    }

    /// Get the last copy-special type.
    pub fn last_copy_special_type(&self) -> Option<ClipboardType> {
        self.last_copy_special_type
    }

    /// Copy bytes to the clipboard.
    pub fn copy(&mut self, entry: ClipboardEntry) {
        self.manager.copy_entry(entry);
    }

    /// Get clipboard history.
    pub fn history(&self) -> &[ClipboardEntry] {
        self.manager.entries()
    }

    /// Create a program transferable from entries.
    pub fn create_transferable(
        &self,
        program_name: &str,
        format: ClipboardFormat,
    ) -> ProgramTransferable {
        let mut t = ProgramTransferable::new(program_name, format);
        for entry in self.manager.entries() {
            t.add_entry(entry.clone());
        }
        t
    }
}

impl Default for ClipboardPluginModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clipboard_type_display() {
        assert_eq!(ClipboardType::Bytes.display_name(), "Bytes");
        assert_eq!(ClipboardType::ByteString.display_name(), "Byte String");
    }

    #[test]
    fn test_clipboard_type_mime_id() {
        assert_eq!(ClipboardType::Bytes.mime_id(), "ghidra.bytes");
        assert_eq!(ClipboardType::ListingText.mime_id(), "ghidra.listing.text");
    }

    #[test]
    fn test_clipboard_type_all() {
        assert_eq!(ClipboardType::all().len(), 9);
    }

    #[test]
    fn test_listing_provider_copy() {
        let mut provider = ListingClipboardProvider::new("test_program");
        assert!(!provider.can_copy());

        provider.set_selection(vec![0x1000, 0x1001, 0x1002]);
        assert!(provider.can_copy());

        let entry = provider.copy().unwrap();
        assert_eq!(entry.source_start.offset, 0x1000);
        assert_eq!(entry.source_end.offset, 0x1002);
    }

    #[test]
    fn test_listing_provider_copy_special() {
        let mut provider = ListingClipboardProvider::new("test");
        provider.set_selection(vec![0x1000]);

        let hex_entry = provider
            .copy_special(ClipboardType::ByteString)
            .unwrap();
        assert_eq!(hex_entry.format, ClipboardFormat::Hex);

        let text_entry = provider
            .copy_special(ClipboardType::ListingText)
            .unwrap();
        assert_eq!(text_entry.format, ClipboardFormat::Text);
    }

    #[test]
    fn test_listing_provider_formats() {
        let provider = ListingClipboardProvider::new("test");
        assert_eq!(provider.supported_formats().len(), 4);
    }

    #[test]
    fn test_clipboard_plugin_model() {
        let mut model = ClipboardPluginModel::new();
        model.register_provider("Listing");
        model.register_provider("Decompiler");
        assert_eq!(model.providers().len(), 2);

        model.set_active_provider("Listing");
        assert_eq!(model.active_provider(), Some("Listing"));

        model.set_last_copy_special_type(ClipboardType::ByteString);
        assert_eq!(
            model.last_copy_special_type(),
            Some(ClipboardType::ByteString)
        );
    }

    #[test]
    fn test_clipboard_plugin_model_unregister() {
        let mut model = ClipboardPluginModel::new();
        model.register_provider("A");
        model.register_provider("B");
        model.unregister_provider("A");
        assert_eq!(model.providers().len(), 1);
        assert_eq!(model.providers()[0], "B");
    }

    #[test]
    fn test_create_transferable() {
        let mut model = ClipboardPluginModel::new();
        model.copy(ClipboardEntry::from_bytes(
            Address::new(0x1000),
            Address::new(0x100F),
            vec![0u8; 16],
        ));
        let t = model.create_transferable("prog", ClipboardFormat::Bytes);
        assert_eq!(t.source_program, "prog");
        assert_eq!(t.entries().len(), 1);
    }
}
