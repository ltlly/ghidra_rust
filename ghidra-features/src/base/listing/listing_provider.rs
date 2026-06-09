//! Listing Provider -- component provider for the program listing view.
//!
//! Ported from Ghidra's `ListingProvider.java` and related classes.
//!
//! This module provides [`ListingProvider`], which manages a single listing
//! view panel. Each provider represents a window displaying program data
//! (instructions, data, comments, labels) with navigation history, cursor
//! tracking, and display configuration.
//!
//! # Architecture
//!
//! ```text
//! ListingProvider
//!   ├── CursorManager (cursor position tracking)
//!   ├── NavigationHistory (back/forward navigation)
//!   ├── DisplayConfig (view settings)
//!   └── ProgramRef (current program reference)
//! ```
//!
//! # Example
//!
//! ```
//! use ghidra_features::base::listing::listing_provider::ListingProvider;
//!
//! let mut provider = ListingProvider::new("PrimaryListing", true);
//! provider.go_to("0x00401000");
//! assert_eq!(provider.current_address(), Some("0x00401000"));
//! ```

use std::fmt;

// ---------------------------------------------------------------------------
// CursorPosition -- tracks the current cursor location
// ---------------------------------------------------------------------------

/// Represents a cursor position in the listing view.
#[derive(Debug, Clone)]
pub struct CursorPosition {
    /// The address as a hex string.
    pub address: String,
    /// The row offset from the address start.
    pub row: usize,
    /// The column offset within the row.
    pub column: usize,
    /// The field name at the cursor position.
    pub field_name: Option<String>,
}

impl CursorPosition {
    /// Creates a new cursor position.
    pub fn new(address: impl Into<String>, row: usize, column: usize) -> Self {
        Self {
            address: address.into(),
            row,
            column,
            field_name: None,
        }
    }

    /// Creates a cursor position with a field name.
    pub fn with_field(mut self, field_name: impl Into<String>) -> Self {
        self.field_name = Some(field_name.into());
        self
    }
}

impl fmt::Display for CursorPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.address, self.row, self.column)
    }
}

// ---------------------------------------------------------------------------
// DisplayConfig -- listing view configuration
// ---------------------------------------------------------------------------

/// Display configuration for the listing view.
#[derive(Debug, Clone)]
pub struct DisplayConfig {
    /// Whether to show line numbers.
    pub show_line_numbers: bool,
    /// Whether to show addresses.
    pub show_addresses: bool,
    /// Whether to show bytes.
    pub show_bytes: bool,
    /// Whether to show comments.
    pub show_comments: bool,
    /// Whether to show labels.
    pub show_labels: bool,
    /// Whether to wrap long lines.
    pub wrap_lines: bool,
    /// The font size in points.
    pub font_size: u32,
    /// The tab size in spaces.
    pub tab_size: u32,
    /// Whether to highlight the current line.
    pub highlight_current_line: bool,
    /// Whether to show a cursor.
    pub show_cursor: bool,
}

impl Default for DisplayConfig {
    fn default() -> Self {
        Self {
            show_line_numbers: true,
            show_addresses: true,
            show_bytes: true,
            show_comments: true,
            show_labels: true,
            wrap_lines: false,
            font_size: 12,
            tab_size: 4,
            highlight_current_line: true,
            show_cursor: true,
        }
    }
}

impl DisplayConfig {
    /// Serializes the configuration to JSON for state persistence.
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"show_line_numbers":{},"show_addresses":{},"show_bytes":{},"show_comments":{},"show_labels":{},"wrap_lines":{},"font_size":{},"tab_size":{},"highlight_current_line":{},"show_cursor":{}}}"#,
            self.show_line_numbers,
            self.show_addresses,
            self.show_bytes,
            self.show_comments,
            self.show_labels,
            self.wrap_lines,
            self.font_size,
            self.tab_size,
            self.highlight_current_line,
            self.show_cursor,
        )
    }

    /// Deserializes a configuration from a JSON string.
    ///
    /// Returns `None` on parse failure.
    pub fn from_json(json: &str) -> Option<Self> {
        let get_bool = |key: &str| -> Option<bool> {
            let needle = format!("\"{}\":", key);
            let start = json.find(&needle)? + needle.len();
            let rest = &json[start..];
            if rest.starts_with("true") {
                Some(true)
            } else if rest.starts_with("false") {
                Some(false)
            } else {
                None
            }
        };
        let get_u32 = |key: &str| -> Option<u32> {
            let needle = format!("\"{}\":", key);
            let start = json.find(&needle)? + needle.len();
            let rest = &json[start..];
            let end = rest
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest.len());
            rest[..end].parse().ok()
        };

        Some(Self {
            show_line_numbers: get_bool("show_line_numbers")?,
            show_addresses: get_bool("show_addresses")?,
            show_bytes: get_bool("show_bytes")?,
            show_comments: get_bool("show_comments")?,
            show_labels: get_bool("show_labels")?,
            wrap_lines: get_bool("wrap_lines")?,
            font_size: get_u32("font_size")?,
            tab_size: get_u32("tab_size")?,
            highlight_current_line: get_bool("highlight_current_line")?,
            show_cursor: get_bool("show_cursor")?,
        })
    }
}

// ---------------------------------------------------------------------------
// ListingProvider -- a single listing view panel
// ---------------------------------------------------------------------------

/// A provider for the program listing view.
///
/// Each provider represents a single listing window (either connected/primary
/// or disconnected/clone). It manages cursor position, navigation history,
/// display configuration, and program reference.
///
/// Ported from Ghidra's listing provider Java classes.
#[derive(Debug)]
pub struct ListingProvider {
    /// Provider name.
    name: String,
    /// Current cursor position.
    cursor: Option<CursorPosition>,
    /// Whether this is the connected (primary) provider.
    connected: bool,
    /// Current program name.
    program: Option<String>,
    /// Address history for back/forward navigation.
    history: Vec<String>,
    /// Current position in history.
    history_index: usize,
    /// Display configuration.
    display_config: DisplayConfig,
    /// Whether the provider is visible.
    visible: bool,
    /// Whether the provider has focus.
    focused: bool,
}

impl ListingProvider {
    /// Creates a new provider.
    pub fn new(name: impl Into<String>, connected: bool) -> Self {
        Self {
            name: name.into(),
            cursor: None,
            connected,
            program: None,
            history: Vec::new(),
            history_index: 0,
            display_config: DisplayConfig::default(),
            visible: false,
            focused: false,
        }
    }

    /// Returns the provider name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the current cursor position.
    pub fn cursor(&self) -> Option<&CursorPosition> {
        self.cursor.as_ref()
    }

    /// Returns the current address.
    pub fn current_address(&self) -> Option<&str> {
        self.cursor.as_ref().map(|c| c.address.as_str())
    }

    /// Sets the cursor position.
    pub fn set_cursor(&mut self, cursor: CursorPosition) {
        self.cursor = Some(cursor);
    }

    /// Clears the cursor position.
    pub fn clear_cursor(&mut self) {
        self.cursor = None;
    }

    /// Navigates to the given address.
    pub fn go_to(&mut self, address: impl Into<String>) {
        let addr = address.into();
        // Truncate forward history
        self.history.truncate(self.history_index);
        self.history.push(addr.clone());
        self.history_index = self.history.len();
        self.cursor = Some(CursorPosition::new(addr, 0, 0));
    }

    /// Navigates back in history.
    pub fn go_back(&mut self) -> bool {
        if self.history_index > 1 {
            self.history_index -= 1;
            let addr = self.history.get(self.history_index - 1).cloned();
            if let Some(addr) = addr {
                self.cursor = Some(CursorPosition::new(addr, 0, 0));
            }
            true
        } else {
            false
        }
    }

    /// Navigates forward in history.
    pub fn go_forward(&mut self) -> bool {
        if self.history_index < self.history.len() {
            let addr = self.history.get(self.history_index).cloned();
            if let Some(addr) = addr {
                self.cursor = Some(CursorPosition::new(addr, 0, 0));
            }
            self.history_index += 1;
            true
        } else {
            false
        }
    }

    /// Returns whether this is the connected (primary) provider.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Sets the current program.
    pub fn set_program(&mut self, program: Option<String>) {
        self.program = program;
    }

    /// Returns the current program name.
    pub fn program(&self) -> Option<&str> {
        self.program.as_deref()
    }

    /// Returns the display configuration.
    pub fn display_config(&self) -> &DisplayConfig {
        &self.display_config
    }

    /// Returns a mutable reference to the display configuration.
    pub fn display_config_mut(&mut self) -> &mut DisplayConfig {
        &mut self.display_config
    }

    /// Sets the display configuration.
    pub fn set_display_config(&mut self, config: DisplayConfig) {
        self.display_config = config;
    }

    /// Returns whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Sets the visibility of the provider.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Returns whether the provider has focus.
    pub fn is_focused(&self) -> bool {
        self.focused
    }

    /// Sets the focus state of the provider.
    pub fn set_focused(&mut self, focused: bool) {
        self.focused = focused;
    }

    /// Returns the navigation history length.
    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    /// Returns the current history index.
    pub fn history_index(&self) -> usize {
        self.history_index
    }

    /// Clears the provider state.
    pub fn clear(&mut self) {
        self.cursor = None;
        self.history.clear();
        self.history_index = 0;
    }
}

impl Default for ListingProvider {
    fn default() -> Self {
        Self::new("ListingProvider", false)
    }
}

impl fmt::Display for ListingProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ListingProvider({}, connected={}, visible={})",
            self.name, self.connected, self.visible
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = ListingProvider::new("TestProvider", true);
        assert_eq!(provider.name(), "TestProvider");
        assert!(provider.is_connected());
        assert!(!provider.is_visible());
        assert!(!provider.is_focused());
        assert!(provider.cursor().is_none());
        assert!(provider.program().is_none());
    }

    #[test]
    fn test_navigation() {
        let mut provider = ListingProvider::new("TestProvider", true);
        provider.go_to("0x00401000");
        assert_eq!(provider.current_address(), Some("0x00401000"));
        assert_eq!(provider.history_len(), 1);
        assert_eq!(provider.history_index(), 1);

        provider.go_to("0x00402000");
        assert_eq!(provider.current_address(), Some("0x00402000"));
        assert_eq!(provider.history_len(), 2);
        assert_eq!(provider.history_index(), 2);

        assert!(provider.go_back());
        assert_eq!(provider.current_address(), Some("0x00401000"));
        assert_eq!(provider.history_index(), 1);

        assert!(provider.go_forward());
        assert_eq!(provider.current_address(), Some("0x00402000"));
        assert_eq!(provider.history_index(), 2);

        assert!(!provider.go_forward());
    }

    #[test]
    fn test_cursor() {
        let mut provider = ListingProvider::new("TestProvider", true);
        let cursor = CursorPosition::new("0x00401000", 2, 10).with_field("mnemonic");
        provider.set_cursor(cursor);
        assert!(provider.cursor().is_some());
        let cursor = provider.cursor().unwrap();
        assert_eq!(cursor.address, "0x00401000");
        assert_eq!(cursor.row, 2);
        assert_eq!(cursor.column, 10);
        assert_eq!(cursor.field_name.as_deref(), Some("mnemonic"));

        provider.clear_cursor();
        assert!(provider.cursor().is_none());
    }

    #[test]
    fn test_display_config() {
        let mut provider = ListingProvider::new("TestProvider", true);
        let config = provider.display_config();
        assert!(config.show_line_numbers);
        assert!(config.show_addresses);
        assert_eq!(config.font_size, 12);

        let mut new_config = DisplayConfig::default();
        new_config.font_size = 14;
        new_config.show_line_numbers = false;
        provider.set_display_config(new_config);

        let config = provider.display_config();
        assert!(!config.show_line_numbers);
        assert_eq!(config.font_size, 14);
    }

    #[test]
    fn test_visibility_and_focus() {
        let mut provider = ListingProvider::new("TestProvider", true);
        assert!(!provider.is_visible());
        assert!(!provider.is_focused());

        provider.set_visible(true);
        provider.set_focused(true);
        assert!(provider.is_visible());
        assert!(provider.is_focused());
    }

    #[test]
    fn test_program() {
        let mut provider = ListingProvider::new("TestProvider", true);
        assert!(provider.program().is_none());

        provider.set_program(Some("test.exe".to_string()));
        assert_eq!(provider.program(), Some("test.exe"));

        provider.set_program(None);
        assert!(provider.program().is_none());
    }

    #[test]
    fn test_clear() {
        let mut provider = ListingProvider::new("TestProvider", true);
        provider.go_to("0x00401000");
        provider.set_program(Some("test.exe".to_string()));
        provider.set_visible(true);

        provider.clear();
        assert!(provider.cursor().is_none());
        assert_eq!(provider.history_len(), 0);
        assert_eq!(provider.history_index(), 0);
    }

    #[test]
    fn test_display_config_json() {
        let config = DisplayConfig::default();
        let json = config.to_json();
        let restored = DisplayConfig::from_json(&json);
        assert!(restored.is_some());
        let restored = restored.unwrap();
        assert_eq!(restored.show_line_numbers, config.show_line_numbers);
        assert_eq!(restored.font_size, config.font_size);
        assert_eq!(restored.tab_size, config.tab_size);
    }

    #[test]
    fn test_cursor_display() {
        let cursor = CursorPosition::new("0x00401000", 2, 10);
        assert_eq!(format!("{}", cursor), "0x00401000:2:10");
    }

    #[test]
    fn test_provider_display() {
        let provider = ListingProvider::new("TestProvider", true);
        let display = format!("{}", provider);
        assert!(display.contains("TestProvider"));
        assert!(display.contains("connected=true"));
        assert!(display.contains("visible=false"));
    }
}
