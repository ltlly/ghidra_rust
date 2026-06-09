//! Code Browser -- the main listing view component.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.codebrowser.CodeBrowser`.
//!
//! This module provides the core listing view component that displays
//! disassembly, data, and other program information. It handles rendering,
//! cursor management, selection, scrolling, and user interactions.
//!
//! # Architecture
//!
//! ```text
//! CodeBrowser
//!   ├── ListingModel (data model)
//!   ├── CursorManager (cursor position and movement)
//!   ├── SelectionManager (address range selection)
//!   ├── FieldManager (field layout and rendering)
//!   └── ViewManager (viewport and scrolling)
//! ```
//!
//! # Example
//!
//! ```
//! use ghidra_features::base::codebrowser::code_browser::CodeBrowser;
//!
//! let mut browser = CodeBrowser::new("MainBrowser");
//! browser.go_to("0x401000");
//! assert_eq!(browser.current_address(), Some("0x401000"));
//! ```

use std::collections::BTreeSet;
use std::fmt;

// ---------------------------------------------------------------------------
// ListingField -- a field in the listing display
// ---------------------------------------------------------------------------

/// The type of field in a listing row.
///
/// Ported from Ghidra's field types used in the listing panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ListingFieldType {
    /// Address field.
    Address,
    /// Bytes field (hex dump).
    Bytes,
    /// Mnemonic field.
    Mnemonic,
    /// Operand field.
    Operand,
    /// Pre-comment field.
    PreComment,
    /// Post-comment field.
    PostComment,
    /// End-of-line comment field.
    EolComment,
    /// Plate comment field.
    PlateComment,
    /// Repeatable comment field.
    RepeatableComment,
    /// Data type field.
    DataType,
    /// Label/namespace field.
    Label,
    /// Function signature field.
    FunctionSignature,
    /// Separator field (blank line between code units).
    Separator,
}

/// A field in the listing display.
///
/// Represents a single renderable field within a listing row, including
/// its type, text content, and column position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingField {
    /// The field type.
    pub field_type: ListingFieldType,
    /// The field text content.
    pub text: String,
    /// The start column of the field.
    pub start_col: usize,
    /// The end column of the field.
    pub end_col: usize,
    /// The row index.
    pub row: usize,
}

impl ListingField {
    /// Creates a new listing field.
    pub fn new(
        field_type: ListingFieldType,
        text: impl Into<String>,
        start_col: usize,
        end_col: usize,
        row: usize,
    ) -> Self {
        Self {
            field_type,
            text: text.into(),
            start_col,
            end_col,
            row,
        }
    }

    /// Returns the field width in columns.
    pub fn width(&self) -> usize {
        self.end_col - self.start_col
    }
}

// ---------------------------------------------------------------------------
// CursorPosition -- cursor location in the listing
// ---------------------------------------------------------------------------

/// Cursor position in the listing view.
///
/// Tracks the address, row, column, and optional field at the cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorPosition {
    /// The address (as hex string).
    pub address: String,
    /// The row index within the listing.
    pub row: usize,
    /// The column index within the row.
    pub col: usize,
    /// The field at the cursor position.
    pub field: Option<ListingField>,
}

impl CursorPosition {
    /// Creates a new cursor position.
    pub fn new(address: impl Into<String>, row: usize, col: usize) -> Self {
        Self {
            address: address.into(),
            row,
            col,
            field: None,
        }
    }

    /// Creates a cursor position with a field.
    pub fn with_field(
        address: impl Into<String>,
        row: usize,
        col: usize,
        field: ListingField,
    ) -> Self {
        Self {
            address: address.into(),
            row,
            col,
            field: Some(field),
        }
    }
}

// ---------------------------------------------------------------------------
// CodeBrowser -- the main listing view
// ---------------------------------------------------------------------------

/// The code browser component.
///
/// Provides the main listing view that displays disassembly, data, and other
/// program information. Handles rendering, cursor management, selection,
/// scrolling, and user interactions.
///
/// Ported from Ghidra's `CodeBrowser` Java class.
#[derive(Debug)]
pub struct CodeBrowser {
    /// The browser name.
    name: String,
    /// Current cursor position.
    cursor: Option<CursorPosition>,
    /// Selected address ranges as (start, end) pairs.
    selection: BTreeSet<(u64, u64)>,
    /// Current address as hex string.
    current_address: Option<String>,
    /// Address history for back/forward navigation.
    history: Vec<String>,
    /// Current position in history.
    history_index: usize,
    /// Whether the browser is focused.
    focused: bool,
    /// Current program name.
    program: Option<String>,
    /// Visible row count.
    visible_rows: usize,
    /// Starting row offset.
    start_row: usize,
    /// Whether the header is showing.
    header_visible: bool,
    /// Whether hover popups are enabled.
    hover_enabled: bool,
    /// Whether the cursor line highlight is enabled.
    cursor_line_highlight: bool,
    /// Pending address to navigate to on next update.
    pending_goto: Option<String>,
}

impl CodeBrowser {
    /// Creates a new code browser.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            cursor: None,
            selection: BTreeSet::new(),
            current_address: None,
            history: Vec::new(),
            history_index: 0,
            focused: false,
            program: None,
            visible_rows: 50,
            start_row: 0,
            header_visible: true,
            hover_enabled: true,
            cursor_line_highlight: true,
            pending_goto: None,
        }
    }

    /// Returns the browser name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the current address.
    pub fn current_address(&self) -> Option<&str> {
        self.current_address.as_deref()
    }

    /// Navigates to the given address.
    ///
    /// Truncates any forward history and pushes the new address.
    /// Also sets the cursor to row 0, col 0 at the new address.
    pub fn go_to(&mut self, address: impl Into<String>) {
        let addr = address.into();
        // Truncate forward history
        self.history.truncate(self.history_index);
        self.history.push(addr.clone());
        self.history_index = self.history.len();
        self.current_address = Some(addr.clone());
        self.cursor = Some(CursorPosition::new(addr, 0, 0));
        self.pending_goto = None;
    }

    /// Navigates back in history.
    pub fn go_back(&mut self) -> bool {
        if self.history_index > 1 {
            self.history_index -= 1;
            let addr = self.history.get(self.history_index - 1).cloned();
            self.current_address = addr.clone();
            if let Some(a) = addr {
                self.cursor = Some(CursorPosition::new(a, 0, 0));
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
            self.current_address = addr.clone();
            self.history_index += 1;
            if let Some(a) = addr {
                self.cursor = Some(CursorPosition::new(a, 0, 0));
            }
            true
        } else {
            false
        }
    }

    /// Returns a reference to the current cursor position.
    pub fn cursor(&self) -> Option<&CursorPosition> {
        self.cursor.as_ref()
    }

    /// Sets the cursor position.
    pub fn set_cursor(&mut self, cursor: CursorPosition) {
        self.current_address = Some(cursor.address.clone());
        self.cursor = Some(cursor);
    }

    /// Moves the cursor up one row.
    pub fn cursor_up(&mut self) {
        if let Some(ref mut cursor) = self.cursor {
            if cursor.row > 0 {
                cursor.row -= 1;
            }
        }
    }

    /// Moves the cursor down one row.
    pub fn cursor_down(&mut self) {
        if let Some(ref mut cursor) = self.cursor {
            cursor.row += 1;
        }
    }

    /// Returns the current selection as a set of (start, end) address pairs.
    pub fn selection(&self) -> &BTreeSet<(u64, u64)> {
        &self.selection
    }

    /// Adds a range to the selection.
    pub fn select(&mut self, start: u64, end: u64) {
        self.selection.insert((start, end));
    }

    /// Clears the selection.
    pub fn clear_selection(&mut self) {
        self.selection.clear();
    }

    /// Returns whether there is an active selection.
    pub fn has_selection(&self) -> bool {
        !self.selection.is_empty()
    }

    /// Returns the number of selected address ranges.
    pub fn selection_range_count(&self) -> usize {
        self.selection.len()
    }

    /// Sets the focus state.
    pub fn set_focused(&mut self, focused: bool) {
        self.focused = focused;
    }

    /// Returns whether the browser is focused.
    pub fn is_focused(&self) -> bool {
        self.focused
    }

    /// Sets the current program.
    pub fn set_program(&mut self, program: Option<String>) {
        self.program = program;
        self.clear();
    }

    /// Returns the current program name.
    pub fn program(&self) -> Option<&str> {
        self.program.as_deref()
    }

    /// Sets the number of visible rows.
    pub fn set_visible_rows(&mut self, rows: usize) {
        self.visible_rows = rows;
    }

    /// Returns the number of visible rows.
    pub fn visible_rows(&self) -> usize {
        self.visible_rows
    }

    /// Sets the starting row offset.
    pub fn set_start_row(&mut self, row: usize) {
        self.start_row = row;
    }

    /// Returns the starting row offset.
    pub fn start_row(&self) -> usize {
        self.start_row
    }

    /// Scrolls up by one page.
    pub fn page_up(&mut self) {
        self.start_row = self.start_row.saturating_sub(self.visible_rows);
    }

    /// Scrolls down by one page.
    pub fn page_down(&mut self) {
        self.start_row += self.visible_rows;
    }

    /// Scrolls to the top.
    pub fn scroll_to_top(&mut self) {
        self.start_row = 0;
    }

    /// Scrolls to the bottom.
    pub fn scroll_to_bottom(&mut self) {
        // Without a total row count, we just move far down.
        // The listing model would clamp this to the actual end.
        self.start_row = usize::MAX / 2;
    }

    /// Sets whether the header is visible.
    pub fn show_header(&mut self, visible: bool) {
        self.header_visible = visible;
    }

    /// Returns whether the header is visible.
    pub fn is_header_visible(&self) -> bool {
        self.header_visible
    }

    /// Sets whether hover popups are enabled.
    pub fn set_hover_enabled(&mut self, enabled: bool) {
        self.hover_enabled = enabled;
    }

    /// Returns whether hover popups are enabled.
    pub fn is_hover_enabled(&self) -> bool {
        self.hover_enabled
    }

    /// Sets whether the cursor line highlight is enabled.
    pub fn set_cursor_line_highlight(&mut self, enabled: bool) {
        self.cursor_line_highlight = enabled;
    }

    /// Returns whether the cursor line highlight is enabled.
    pub fn is_cursor_line_highlight(&self) -> bool {
        self.cursor_line_highlight
    }

    /// Sets a pending goto address.
    ///
    /// This will be consumed on the next call to [`take_pending_goto`].
    pub fn set_pending_goto(&mut self, address: impl Into<String>) {
        self.pending_goto = Some(address.into());
    }

    /// Takes and returns the pending goto address, if any.
    pub fn take_pending_goto(&mut self) -> Option<String> {
        self.pending_goto.take()
    }

    /// Clears the browser state.
    pub fn clear(&mut self) {
        self.cursor = None;
        self.selection.clear();
        self.current_address = None;
        self.history.clear();
        self.history_index = 0;
        self.start_row = 0;
        self.pending_goto = None;
    }
}

impl Default for CodeBrowser {
    fn default() -> Self {
        Self::new("CodeBrowser")
    }
}

impl fmt::Display for CodeBrowser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CodeBrowser({}, addr={:?})",
            self.name, self.current_address
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_browser_creation() {
        let browser = CodeBrowser::new("TestBrowser");
        assert_eq!(browser.name(), "TestBrowser");
        assert!(browser.current_address().is_none());
        assert!(!browser.has_selection());
        assert!(browser.is_header_visible());
        assert!(browser.is_hover_enabled());
    }

    #[test]
    fn test_navigation() {
        let mut browser = CodeBrowser::new("TestBrowser");
        browser.go_to("0x401000");
        assert_eq!(browser.current_address(), Some("0x401000"));
        browser.go_to("0x402000");
        assert_eq!(browser.current_address(), Some("0x402000"));
        browser.go_back();
        assert_eq!(browser.current_address(), Some("0x401000"));
        browser.go_forward();
        assert_eq!(browser.current_address(), Some("0x402000"));
    }

    #[test]
    fn test_selection() {
        let mut browser = CodeBrowser::new("TestBrowser");
        browser.select(0x401000, 0x401100);
        assert!(browser.has_selection());
        assert_eq!(browser.selection_range_count(), 1);
        browser.clear_selection();
        assert!(!browser.has_selection());
    }

    #[test]
    fn test_cursor() {
        let mut browser = CodeBrowser::new("TestBrowser");
        browser.go_to("0x401000");
        assert!(browser.cursor().is_some());
        browser.cursor_down();
        assert_eq!(browser.cursor().unwrap().row, 1);
        browser.cursor_up();
        assert_eq!(browser.cursor().unwrap().row, 0);
    }

    #[test]
    fn test_cursor_up_at_boundary() {
        let mut browser = CodeBrowser::new("TestBrowser");
        browser.go_to("0x401000");
        browser.cursor_up(); // Should not panic or go negative
        assert_eq!(browser.cursor().unwrap().row, 0);
    }

    #[test]
    fn test_scrolling() {
        let mut browser = CodeBrowser::new("TestBrowser");
        browser.set_visible_rows(25);
        assert_eq!(browser.visible_rows(), 25);
        browser.page_down();
        assert_eq!(browser.start_row(), 25);
        browser.page_up();
        assert_eq!(browser.start_row(), 0);
    }

    #[test]
    fn test_page_up_at_top() {
        let mut browser = CodeBrowser::new("TestBrowser");
        browser.set_visible_rows(50);
        browser.page_up(); // Should not underflow
        assert_eq!(browser.start_row(), 0);
    }

    #[test]
    fn test_scroll_to_top() {
        let mut browser = CodeBrowser::new("TestBrowser");
        browser.page_down();
        browser.page_down();
        assert!(browser.start_row() > 0);
        browser.scroll_to_top();
        assert_eq!(browser.start_row(), 0);
    }

    #[test]
    fn test_header_and_hover() {
        let mut browser = CodeBrowser::new("TestBrowser");
        assert!(browser.is_header_visible());
        browser.show_header(false);
        assert!(!browser.is_header_visible());

        assert!(browser.is_hover_enabled());
        browser.set_hover_enabled(false);
        assert!(!browser.is_hover_enabled());
    }

    #[test]
    fn test_cursor_line_highlight() {
        let mut browser = CodeBrowser::new("TestBrowser");
        assert!(browser.is_cursor_line_highlight());
        browser.set_cursor_line_highlight(false);
        assert!(!browser.is_cursor_line_highlight());
    }

    #[test]
    fn test_pending_goto() {
        let mut browser = CodeBrowser::new("TestBrowser");
        assert!(browser.take_pending_goto().is_none());
        browser.set_pending_goto("0x401000");
        assert_eq!(browser.take_pending_goto(), Some("0x401000".to_string()));
        assert!(browser.take_pending_goto().is_none());
    }

    #[test]
    fn test_clear() {
        let mut browser = CodeBrowser::new("TestBrowser");
        browser.go_to("0x401000");
        browser.select(0x401000, 0x401100);
        browser.page_down();
        browser.set_pending_goto("0x500000");

        browser.clear();
        assert!(browser.current_address().is_none());
        assert!(!browser.has_selection());
        assert_eq!(browser.start_row(), 0);
        assert!(browser.take_pending_goto().is_none());
    }

    #[test]
    fn test_set_program_clears_state() {
        let mut browser = CodeBrowser::new("TestBrowser");
        browser.go_to("0x401000");
        browser.select(0x401000, 0x401100);

        browser.set_program(Some("test.exe".to_string()));
        assert_eq!(browser.program(), Some("test.exe"));
        assert!(browser.current_address().is_none());
        assert!(!browser.has_selection());
    }

    #[test]
    fn test_listing_field() {
        let field = ListingField::new(ListingFieldType::Mnemonic, "MOV", 10, 13, 0);
        assert_eq!(field.width(), 3);
        assert_eq!(field.field_type, ListingFieldType::Mnemonic);
    }

    #[test]
    fn test_cursor_position_with_field() {
        let field = ListingField::new(ListingFieldType::Operand, "EAX", 14, 17, 0);
        let pos = CursorPosition::with_field("0x401000", 0, 14, field);
        assert!(pos.field.is_some());
        assert_eq!(pos.field.unwrap().text, "EAX");
    }

    #[test]
    fn test_display() {
        let browser = CodeBrowser::new("TestBrowser");
        let display = format!("{}", browser);
        assert!(display.contains("TestBrowser"));
    }
}
