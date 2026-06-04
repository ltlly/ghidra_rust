//! Clipboard management for code browser.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.clipboard` package.
//!
//! Provides types for managing cut/copy/paste operations in the listing view:
//!
//! - [`ClipboardType`] -- Describes a format of data that can be copied.
//! - [`ClipboardService`] -- Trait for clipboard service implementations.
//! - [`ClipboardContentProvider`] -- Trait for content providers that supply
//!   data to the clipboard.
//!
//! Note: GUI-specific classes (CopyPasteSpecialDialog, CodeBrowserClipboardProvider)
//! are not ported as they depend on Java Swing/AWT.

use std::collections::HashMap;

/// Represents a type of data that can be copied to or pasted from the clipboard.
///
/// Each clipboard type has a unique name (e.g., "Address", "Bytes", "Code") and
/// an associated description. This corresponds to Ghidra's `ClipboardType`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClipboardType {
    /// Unique name identifying this clipboard type.
    name: String,
    /// Human-readable description of this type.
    description: String,
}

impl ClipboardType {
    /// Create a new clipboard type.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
        }
    }

    /// Get the type name.
    pub fn type_name(&self) -> &str {
        &self.name
    }

    /// Get the type description.
    pub fn description(&self) -> &str {
        &self.description
    }
}

impl std::fmt::Display for ClipboardType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

// ---------------------------------------------------------------------------
// Well-known clipboard types
// ---------------------------------------------------------------------------

/// Clipboard type for address strings.
pub fn clipboard_type_address() -> ClipboardType {
    ClipboardType::new("Address", "Copy address as hex string")
}

/// Clipboard type for raw bytes.
pub fn clipboard_type_bytes() -> ClipboardType {
    ClipboardType::new("Bytes", "Copy raw bytes")
}

/// Clipboard type for assembly code.
pub fn clipboard_type_code() -> ClipboardType {
    ClipboardType::new("Code", "Copy assembly code")
}

/// Clipboard type for labels/names.
pub fn clipboard_type_label() -> ClipboardType {
    ClipboardType::new("Label", "Copy label/name")
}

/// Clipboard type for comments.
pub fn clipboard_type_comment() -> ClipboardType {
    ClipboardType::new("Comment", "Copy comment text")
}

// ---------------------------------------------------------------------------
// Clipboard content data
// ---------------------------------------------------------------------------

/// Data payload for a clipboard operation.
///
/// This is a platform-independent representation of clipboard contents.
#[derive(Debug, Clone)]
pub struct ClipboardContent {
    /// The clipboard type this content was created from.
    pub clipboard_type: ClipboardType,
    /// The string representation of the data.
    pub text: String,
    /// Optional raw bytes (for byte copy operations).
    pub bytes: Option<Vec<u8>>,
    /// Whether outer quotes should be removed from string data.
    pub remove_quotes: bool,
}

impl ClipboardContent {
    /// Create text-only clipboard content.
    pub fn text(clipboard_type: ClipboardType, text: impl Into<String>) -> Self {
        Self {
            clipboard_type,
            text: text.into(),
            bytes: None,
            remove_quotes: false,
        }
    }

    /// Create clipboard content with both text and raw bytes.
    pub fn with_bytes(
        clipboard_type: ClipboardType,
        text: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            clipboard_type,
            text: text.into(),
            bytes: Some(bytes),
            remove_quotes: false,
        }
    }

    /// Remove outer quotes and standard string prefix from the text.
    ///
    /// Ported from `StringTransferable.removeOuterQuotesAndStandardStringPrefix`.
    pub fn remove_outer_quotes(&mut self) {
        let s = self.text.trim();
        // Remove common string prefixes (these consume the opening quote).
        let (s, prefix_removed) = if let Some(rest) = s.strip_prefix("L\"") {
            (rest, true)
        } else if let Some(rest) = s.strip_prefix("u\"") {
            (rest, true)
        } else if let Some(rest) = s.strip_prefix("U\"") {
            (rest, true)
        } else if let Some(rest) = s.strip_prefix("u8\"") {
            (rest, true)
        } else {
            (s, false)
        };

        if prefix_removed {
            // Prefix consumed the opening quote; just strip trailing quote.
            let s = s.strip_suffix('"').unwrap_or(s);
            self.text = s.to_string();
        } else if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
            // Remove surrounding double quotes.
            self.text = s[1..s.len() - 1].to_string();
        } else if s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2 {
            // Remove surrounding single quotes.
            self.text = s[1..s.len() - 1].to_string();
        } else {
            self.text = s.to_string();
        }
    }
}

// ---------------------------------------------------------------------------
// Clipboard service trait
// ---------------------------------------------------------------------------

/// Trait for clipboard service implementations.
///
/// The clipboard service coordinates copy/paste operations between
/// content providers and the system clipboard.
///
/// Ported from Ghidra's `ClipboardService` interface.
pub trait ClipboardService: Send + Sync {
    /// Register a content provider.
    fn register_content_provider(&mut self, provider_id: &str);

    /// De-register a content provider.
    fn deregister_content_provider(&mut self, provider_id: &str);

    /// Copy data to the clipboard using the active content provider.
    fn copy(&self, provider_id: &str) -> Option<ClipboardContent>;

    /// Paste data from the clipboard.
    fn paste(&self, provider_id: &str, content: &ClipboardContent);

    /// Get the list of available clipboard types for copy special.
    fn available_copy_types(&self, provider_id: &str) -> Vec<ClipboardType>;

    /// Whether the clipboard currently has pasteable content.
    fn has_paste_content(&self) -> bool;
}

// ---------------------------------------------------------------------------
// Clipboard manager
// ---------------------------------------------------------------------------

/// Manages clipboard state and content providers.
///
/// This is the Rust equivalent of `ClipboardPlugin`, providing the
/// non-GUI portions of clipboard management.
#[derive(Debug)]
pub struct ClipboardManager {
    /// Registered content providers.
    providers: HashMap<String, ProviderState>,
    /// Whether the manager currently owns the clipboard.
    is_owner: bool,
    /// The last content placed on the clipboard.
    last_content: Option<ClipboardContent>,
    /// The last used copy special type per provider.
    last_copy_special_type: HashMap<String, ClipboardType>,
    /// Whether to remove outer quotes when copying strings.
    remove_quotes: bool,
}

/// Internal state for a registered clipboard content provider.
#[derive(Debug, Clone)]
struct ProviderState {
    /// Whether this provider can currently copy.
    can_copy: bool,
    /// Whether this provider can paste.
    can_paste: bool,
    /// Available copy special types.
    copy_types: Vec<ClipboardType>,
}

impl ClipboardManager {
    /// Create a new clipboard manager.
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            is_owner: false,
            last_content: None,
            last_copy_special_type: HashMap::new(),
            remove_quotes: false,
        }
    }

    /// Set whether to remove outer quotes from string clipboard content.
    pub fn set_remove_quotes(&mut self, remove: bool) {
        self.remove_quotes = remove;
    }

    /// Whether quote removal is enabled.
    pub fn remove_quotes(&self) -> bool {
        self.remove_quotes
    }

    /// Register a content provider with initial capabilities.
    pub fn register_provider(
        &mut self,
        provider_id: impl Into<String>,
        can_copy: bool,
        can_paste: bool,
        copy_types: Vec<ClipboardType>,
    ) {
        let id = provider_id.into();
        self.providers.insert(
            id,
            ProviderState {
                can_copy,
                can_paste,
                copy_types,
            },
        );
    }

    /// De-register a content provider.
    pub fn deregister_provider(&mut self, provider_id: &str) {
        self.providers.remove(provider_id);
        self.last_copy_special_type.remove(provider_id);
    }

    /// Perform a copy operation for the given provider.
    ///
    /// Returns the content that was copied, or None if the provider can't copy.
    pub fn copy(&mut self, provider_id: &str, content: ClipboardContent) -> Option<ClipboardContent> {
        let provider = self.providers.get(provider_id)?;
        if !provider.can_copy {
            return None;
        }

        let mut content = content;
        if self.remove_quotes {
            content.remove_outer_quotes();
        }

        self.last_content = Some(content.clone());
        self.is_owner = true;
        Some(content)
    }

    /// Perform a copy special operation with a specific clipboard type.
    pub fn copy_special(
        &mut self,
        provider_id: &str,
        clipboard_type: ClipboardType,
        content: ClipboardContent,
    ) -> Option<ClipboardContent> {
        let result = self.copy(provider_id, content)?;
        self.last_copy_special_type
            .insert(provider_id.to_string(), clipboard_type);
        Some(result)
    }

    /// Get the last used copy special type for a provider.
    pub fn last_copy_special_type(&self, provider_id: &str) -> Option<&ClipboardType> {
        self.last_copy_special_type.get(provider_id)
    }

    /// Whether the manager currently owns the clipboard.
    pub fn is_owner(&self) -> bool {
        self.is_owner
    }

    /// Called when the manager loses clipboard ownership.
    pub fn lost_ownership(&mut self) {
        self.is_owner = false;
    }

    /// Get the last content placed on the clipboard.
    pub fn last_content(&self) -> Option<&ClipboardContent> {
        self.last_content.as_ref()
    }

    /// Clear the clipboard.
    pub fn clear(&mut self) {
        self.last_content = None;
        self.is_owner = false;
    }

    /// Check if a provider can currently copy.
    pub fn can_copy(&self, provider_id: &str) -> bool {
        self.providers
            .get(provider_id)
            .map(|p| p.can_copy)
            .unwrap_or(false)
    }

    /// Update a provider's can_copy state.
    pub fn set_can_copy(&mut self, provider_id: &str, can_copy: bool) {
        if let Some(provider) = self.providers.get_mut(provider_id) {
            provider.can_copy = can_copy;
        }
    }

    /// Update a provider's can_paste state.
    pub fn set_can_paste(&mut self, provider_id: &str, can_paste: bool) {
        if let Some(provider) = self.providers.get_mut(provider_id) {
            provider.can_paste = can_paste;
        }
    }
}

impl Default for ClipboardManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clipboard_type_display() {
        let ct = ClipboardType::new("Address", "Address as hex");
        assert_eq!(ct.type_name(), "Address");
        assert_eq!(ct.description(), "Address as hex");
        assert_eq!(format!("{}", ct), "Address");
    }

    #[test]
    fn test_clipboard_type_equality() {
        let a = ClipboardType::new("Bytes", "Raw bytes");
        let b = ClipboardType::new("Bytes", "Raw bytes");
        assert_eq!(a, b);
    }

    #[test]
    fn test_well_known_types() {
        assert_eq!(clipboard_type_address().type_name(), "Address");
        assert_eq!(clipboard_type_bytes().type_name(), "Bytes");
        assert_eq!(clipboard_type_code().type_name(), "Code");
        assert_eq!(clipboard_type_label().type_name(), "Label");
        assert_eq!(clipboard_type_comment().type_name(), "Comment");
    }

    #[test]
    fn test_clipboard_content_text() {
        let content = ClipboardContent::text(clipboard_type_address(), "0x400000");
        assert_eq!(content.text, "0x400000");
        assert!(content.bytes.is_none());
        assert!(!content.remove_quotes);
    }

    #[test]
    fn test_clipboard_content_with_bytes() {
        let bytes = vec![0x48, 0x65, 0x6C, 0x6C, 0x6F];
        let content =
            ClipboardContent::with_bytes(clipboard_type_bytes(), "48 65 6C 6C 6F", bytes.clone());
        assert_eq!(content.bytes, Some(bytes));
    }

    #[test]
    fn test_remove_outer_quotes_double() {
        let mut content = ClipboardContent::text(clipboard_type_label(), "\"hello world\"");
        content.remove_outer_quotes();
        assert_eq!(content.text, "hello world");
    }

    #[test]
    fn test_remove_outer_quotes_single() {
        let mut content = ClipboardContent::text(clipboard_type_label(), "'x'");
        content.remove_outer_quotes();
        assert_eq!(content.text, "x");
    }

    #[test]
    fn test_remove_outer_quotes_with_prefix() {
        let mut content = ClipboardContent::text(clipboard_type_label(), "L\"wide string\"");
        content.remove_outer_quotes();
        assert_eq!(content.text, "wide string");
    }

    #[test]
    fn test_remove_outer_quotes_no_quotes() {
        let mut content = ClipboardContent::text(clipboard_type_label(), "no quotes here");
        content.remove_outer_quotes();
        assert_eq!(content.text, "no quotes here");
    }

    #[test]
    fn test_clipboard_manager_new() {
        let mgr = ClipboardManager::new();
        assert!(!mgr.is_owner());
        assert!(mgr.last_content().is_none());
        assert!(!mgr.remove_quotes());
    }

    #[test]
    fn test_clipboard_manager_register_and_copy() {
        let mut mgr = ClipboardManager::new();
        mgr.register_provider("code_browser", true, true, vec![clipboard_type_code()]);

        let content = ClipboardContent::text(clipboard_type_code(), "mov eax, ebx");
        let result = mgr.copy("code_browser", content);
        assert!(result.is_some());
        assert!(mgr.is_owner());
        assert_eq!(mgr.last_content().unwrap().text, "mov eax, ebx");
    }

    #[test]
    fn test_clipboard_manager_copy_disabled() {
        let mut mgr = ClipboardManager::new();
        mgr.register_provider("provider1", false, true, vec![]);

        let content = ClipboardContent::text(clipboard_type_code(), "nop");
        let result = mgr.copy("provider1", content);
        assert!(result.is_none());
        assert!(!mgr.is_owner());
    }

    #[test]
    fn test_clipboard_manager_unknown_provider() {
        let mgr = ClipboardManager::new();
        assert!(!mgr.can_copy("nonexistent"));
    }

    #[test]
    fn test_clipboard_manager_lost_ownership() {
        let mut mgr = ClipboardManager::new();
        mgr.register_provider("p", true, true, vec![]);
        let content = ClipboardContent::text(clipboard_type_code(), "test");
        mgr.copy("p", content);
        assert!(mgr.is_owner());

        mgr.lost_ownership();
        assert!(!mgr.is_owner());
    }

    #[test]
    fn test_clipboard_manager_clear() {
        let mut mgr = ClipboardManager::new();
        mgr.register_provider("p", true, true, vec![]);
        let content = ClipboardContent::text(clipboard_type_code(), "test");
        mgr.copy("p", content);
        mgr.clear();
        assert!(!mgr.is_owner());
        assert!(mgr.last_content().is_none());
    }

    #[test]
    fn test_clipboard_manager_copy_special() {
        let mut mgr = ClipboardManager::new();
        mgr.register_provider(
            "p",
            true,
            true,
            vec![clipboard_type_address(), clipboard_type_bytes()],
        );

        let content = ClipboardContent::text(clipboard_type_address(), "0x400000");
        let result = mgr.copy_special("p", clipboard_type_address(), content);
        assert!(result.is_some());
        assert_eq!(
            mgr.last_copy_special_type("p").unwrap().type_name(),
            "Address"
        );
    }

    #[test]
    fn test_clipboard_manager_remove_quotes() {
        let mut mgr = ClipboardManager::new();
        mgr.set_remove_quotes(true);
        assert!(mgr.remove_quotes());

        mgr.register_provider("p", true, true, vec![]);
        let content = ClipboardContent::text(clipboard_type_label(), "\"quoted\"");
        let result = mgr.copy("p", content).unwrap();
        assert_eq!(result.text, "quoted");
    }

    #[test]
    fn test_clipboard_manager_deregister() {
        let mut mgr = ClipboardManager::new();
        mgr.register_provider("p", true, true, vec![]);
        assert!(mgr.can_copy("p"));

        mgr.deregister_provider("p");
        assert!(!mgr.can_copy("p"));
    }
}
