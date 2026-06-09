//! Console panel model for UI-oriented console management.
//!
//! Ported from `ghidra.app.plugin.core.console.ConsoleComponentProvider` and
//! `ghidra.framework.main.ConsoleTextPane` (Features/Base).
//!
//! The Java `ConsoleComponentProvider` builds a Swing panel containing a
//! `JScrollPane` wrapping a `ConsoleTextPane`, and wires up actions for
//! clear, scroll-lock, and find. It also tracks the current program/address
//! for double-click navigation via `GoToService`.
//!
//! This module models those UI concerns in pure Rust:
//! - Panel state (scroll lock, visibility, find query)
//! - Action dispatch (clear, toggle scroll lock, find next/previous)
//! - Cursor-based find navigation over the underlying log
//! - Program/address tracking for navigation resolution
//!
//! # Key types
//!
//! - [`ConsolePanel`] -- the panel model wrapping a [`ConsoleLog`]
//! - [`FindState`] -- cursor position for incremental find
//! - [`PanelAction`] -- discrete actions the panel can perform
//!
//! # Example
//!
//! ```
//! use ghidra_features::console::console_panel::*;
//! use ghidra_features::console::console_log::ConsoleLog;
//!
//! let mut panel = ConsolePanel::new("ScriptConsole");
//! panel.add_message("script", "Hello");
//! panel.add_error_message("script", "Error");
//! assert_eq!(panel.log().entry_count(), 2);
//!
//! // Scroll lock
//! panel.set_scroll_lock(true);
//! assert!(panel.is_scroll_locked());
//!
//! // Find
//! let results = panel.find("Hello");
//! assert_eq!(results.len(), 1);
//!
//! // Clear
//! panel.perform_action(PanelAction::Clear);
//! assert!(panel.log().is_empty());
//! ```

use super::console_log::{ConsoleLog, ConsoleStyle};
use super::ConsoleMessage;
use super::ConsoleMessageType;

// ---------------------------------------------------------------------------
// PanelAction -- discrete actions the panel can perform
// ---------------------------------------------------------------------------

/// Discrete actions the console panel can execute.
///
/// Mirrors the toolbar and context-menu actions in
/// `ConsoleComponentProvider.createActions()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PanelAction {
    /// Clear all console messages.
    Clear,
    /// Toggle scroll lock.
    ToggleScrollLock,
    /// Open / activate the find dialog.
    Find,
    /// Find the next occurrence of the current query.
    FindNext,
    /// Find the previous occurrence of the current query.
    FindPrevious,
    /// Close the find dialog and clear highlights.
    CloseFind,
}

// ---------------------------------------------------------------------------
// FindState -- cursor for incremental find
// ---------------------------------------------------------------------------

/// Cursor state for incremental find within the console panel.
///
/// Tracks the current query string and the offset of the most recent match
/// so that `FindNext` / `FindPrevious` can advance without re-scanning from
/// the beginning.
#[derive(Debug, Clone, Default)]
pub struct FindState {
    /// Current search query.
    query: String,
    /// All match offsets `(start, end)` for the current query.
    matches: Vec<(usize, usize)>,
    /// Index into `matches` for the current position, or `None` if no match.
    cursor: Option<usize>,
}

impl FindState {
    /// Create an empty find state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the current query.
    pub fn query(&self) -> &str {
        &self.query
    }

    /// Get all match offsets.
    pub fn matches(&self) -> &[(usize, usize)] {
        &self.matches
    }

    /// Number of matches for the current query.
    pub fn match_count(&self) -> usize {
        self.matches.len()
    }

    /// Current cursor index, if any.
    pub fn cursor(&self) -> Option<usize> {
        self.cursor
    }

    /// The current match range, if any.
    pub fn current_match(&self) -> Option<(usize, usize)> {
        self.cursor.and_then(|i| self.matches.get(i).copied())
    }

    /// Set the query and recompute matches against the given text.
    pub fn set_query(&mut self, query: &str, text: &str) {
        self.query = query.to_string();
        self.matches.clear();
        self.cursor = None;

        if query.is_empty() {
            return;
        }

        let mut start = 0;
        while let Some(pos) = text[start..].find(query) {
            let abs = start + pos;
            self.matches.push((abs, abs + query.len()));
            start = abs + 1;
        }

        if !self.matches.is_empty() {
            self.cursor = Some(0);
        }
    }

    /// Advance to the next match. Wraps around.
    pub fn next(&mut self) -> Option<(usize, usize)> {
        if self.matches.is_empty() {
            return None;
        }
        let idx = match self.cursor {
            Some(i) => (i + 1) % self.matches.len(),
            None => 0,
        };
        self.cursor = Some(idx);
        self.current_match()
    }

    /// Advance to the previous match. Wraps around.
    pub fn previous(&mut self) -> Option<(usize, usize)> {
        if self.matches.is_empty() {
            return None;
        }
        let idx = match self.cursor {
            Some(i) => {
                if i == 0 {
                    self.matches.len() - 1
                } else {
                    i - 1
                }
            }
            None => self.matches.len() - 1,
        };
        self.cursor = Some(idx);
        self.current_match()
    }

    /// Clear all state.
    pub fn clear(&mut self) {
        self.query.clear();
        self.matches.clear();
        self.cursor = None;
    }

    /// Whether the find dialog is active (has a query).
    pub fn is_active(&self) -> bool {
        !self.query.is_empty()
    }
}

// ---------------------------------------------------------------------------
// ConsolePanel -- the panel model
// ---------------------------------------------------------------------------

/// Console panel model.
///
/// Wraps a [`ConsoleLog`] and adds UI-level state: scroll lock, visibility,
/// find navigation, program/address tracking for double-click navigation,
/// and action dispatch.
///
/// Mirrors `ConsoleComponentProvider` in Java which builds a Swing panel
/// around a `ConsoleTextPane` and wires up toolbar actions.
#[derive(Debug)]
pub struct ConsolePanel {
    /// Display name.
    name: String,
    /// Underlying console log.
    log: ConsoleLog,
    /// Scroll lock state.
    scroll_lock: bool,
    /// Whether the panel is visible.
    visible: bool,
    /// Find state for search navigation.
    find_state: FindState,
    /// Name of the currently active program, if any.
    current_program: Option<String>,
    /// Current address for navigation context (hex string).
    current_address: Option<String>,
}

impl ConsolePanel {
    /// Create a new console panel with default log settings.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            log: ConsoleLog::default(),
            scroll_lock: false,
            visible: true,
            find_state: FindState::new(),
            current_program: None,
            current_address: None,
        }
    }

    /// Create a panel with a specific log character limit.
    pub fn with_max_chars(name: impl Into<String>, max_chars: usize) -> Self {
        Self {
            name: name.into(),
            log: ConsoleLog::new(max_chars),
            scroll_lock: false,
            visible: true,
            find_state: FindState::new(),
            current_program: None,
            current_address: None,
        }
    }

    /// Get the panel name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get a reference to the underlying log.
    pub fn log(&self) -> &ConsoleLog {
        &self.log
    }

    /// Get a mutable reference to the underlying log.
    pub fn log_mut(&mut self) -> &mut ConsoleLog {
        &mut self.log
    }

    // -- Message output (mirrors ConsoleComponentProvider / ConsoleService) --

    /// Add an informational message with an originator tag.
    ///
    /// Format: `originator> message\n`
    pub fn add_message(&mut self, originator: &str, message: &str) {
        self.ensure_visible();
        let text = format!("{}> {}\n", originator, message);
        self.log.add_message(&text);
    }

    /// Add an error message with an originator tag.
    pub fn add_error_message(&mut self, originator: &str, message: &str) {
        self.ensure_visible();
        let text = format!("{}> {}\n", originator, message);
        self.log.add_error_message(&text);
    }

    /// Print text without a trailing newline (partial line).
    pub fn print(&mut self, msg: &str) {
        self.ensure_visible();
        self.log.add_message(msg);
    }

    /// Print error text without a trailing newline.
    pub fn print_error(&mut self, errmsg: &str) {
        self.ensure_visible();
        self.log.add_error_message(errmsg);
    }

    /// Print a message followed by a newline.
    pub fn println(&mut self, msg: &str) {
        self.ensure_visible();
        self.log.add_message(&format!("{}\n", msg));
    }

    /// Print an error message followed by a newline.
    pub fn println_error(&mut self, errmsg: &str) {
        self.ensure_visible();
        self.log.add_error_message(&format!("{}\n", errmsg));
    }

    /// Add a structured [`ConsoleMessage`] to the panel.
    pub fn add_console_message(&mut self, msg: &ConsoleMessage) {
        self.ensure_visible();
        let text = format!("{}> {}\n", msg.source, msg.text);
        match msg.msg_type {
            ConsoleMessageType::Info => self.log.add_message(&text),
            ConsoleMessageType::Error => self.log.add_error_message(&text),
            ConsoleMessageType::Warning => {
                // Warnings are rendered as output with a [WARN] prefix.
                let warn_text = format!("{}> [WARN] {}\n", msg.source, msg.text);
                self.log.add_message(&warn_text);
            }
        }
    }

    // -- Scroll lock --

    /// Check if scroll lock is enabled.
    pub fn is_scroll_locked(&self) -> bool {
        self.scroll_lock
    }

    /// Set scroll lock state.
    pub fn set_scroll_lock(&mut self, locked: bool) {
        self.scroll_lock = locked;
    }

    /// Toggle scroll lock.
    pub fn toggle_scroll_lock(&mut self) {
        self.scroll_lock = !self.scroll_lock;
    }

    // -- Visibility --

    /// Check if the panel is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set panel visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Ensure the panel is visible (auto-show on message).
    fn ensure_visible(&mut self) {
        if !self.visible {
            self.visible = true;
        }
    }

    // -- Find --

    /// Get a reference to the find state.
    pub fn find_state(&self) -> &FindState {
        &self.find_state
    }

    /// Execute a find query against the console text.
    ///
    /// Returns the number of matches found.
    pub fn find(&mut self, query: &str) -> usize {
        let text = self.log.to_text();
        self.find_state.set_query(query, &text);
        self.find_state.match_count()
    }

    /// Find the next match. Returns the match range or `None`.
    pub fn find_next(&mut self) -> Option<(usize, usize)> {
        self.find_state.next()
    }

    /// Find the previous match. Returns the match range or `None`.
    pub fn find_previous(&mut self) -> Option<(usize, usize)> {
        self.find_state.previous()
    }

    /// Close the find dialog and clear highlights.
    pub fn close_find(&mut self) {
        self.find_state.clear();
    }

    // -- Program / address tracking --

    /// Set the current program name.
    ///
    /// Mirrors `ConsoleComponentProvider.setCurrentProgram()`.
    pub fn set_current_program(&mut self, program: Option<String>) {
        self.current_program = program;
    }

    /// Get the current program name.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    /// Set the current address.
    ///
    /// Mirrors `ConsoleComponentProvider.setCurrentAddress()`.
    pub fn set_current_address(&mut self, address: Option<String>) {
        self.current_address = address;
    }

    /// Get the current address.
    pub fn current_address(&self) -> Option<&str> {
        self.current_address.as_deref()
    }

    // -- Action dispatch --

    /// Perform a panel action.
    ///
    /// Mirrors the action handlers in `ConsoleComponentProvider.createActions()`.
    pub fn perform_action(&mut self, action: PanelAction) {
        match action {
            PanelAction::Clear => {
                self.log.clear();
                // Also close find if open (mirrors Java behavior).
                self.find_state.clear();
            }
            PanelAction::ToggleScrollLock => {
                self.toggle_scroll_lock();
            }
            PanelAction::Find => {
                // In a real UI this would open the find dialog.
                // Here it is a no-op; use `find()` directly.
            }
            PanelAction::FindNext => {
                self.find_next();
            }
            PanelAction::FindPrevious => {
                self.find_previous();
            }
            PanelAction::CloseFind => {
                self.close_find();
            }
        }
    }

    // -- Text access --

    /// Get all console text as a single string.
    pub fn text(&self) -> String {
        self.log.to_text()
    }

    /// Get the total character count.
    pub fn text_length(&self) -> usize {
        self.log.total_chars()
    }

    /// Extract a text range.
    pub fn get_text(&self, offset: usize, length: usize) -> Option<String> {
        self.log.get_text(offset, length)
    }
}

impl Default for ConsolePanel {
    fn default() -> Self {
        Self::new("Console")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_panel_creation() {
        let panel = ConsolePanel::new("TestConsole");
        assert_eq!(panel.name(), "TestConsole");
        assert!(panel.is_visible());
        assert!(!panel.is_scroll_locked());
        assert_eq!(panel.text_length(), 0);
    }

    #[test]
    fn test_panel_add_message() {
        let mut panel = ConsolePanel::new("Test");
        panel.add_message("script", "hello");
        assert!(panel.text().contains("script> hello\n"));
    }

    #[test]
    fn test_panel_add_error_message() {
        let mut panel = ConsolePanel::new("Test");
        panel.add_error_message("script", "oops");
        assert_eq!(panel.log().error_count(), 1);
        assert!(panel.text().contains("oops"));
    }

    #[test]
    fn test_panel_print() {
        let mut panel = ConsolePanel::new("Test");
        panel.print("hello ");
        panel.println("world");
        assert!(panel.text().contains("hello world"));
    }

    #[test]
    fn test_panel_print_error() {
        let mut panel = ConsolePanel::new("Test");
        panel.print_error("err ");
        panel.println_error("done");
        assert!(panel.text().contains("err "));
        assert!(panel.text().contains("done"));
    }

    #[test]
    fn test_panel_scroll_lock() {
        let mut panel = ConsolePanel::new("Test");
        assert!(!panel.is_scroll_locked());
        panel.set_scroll_lock(true);
        assert!(panel.is_scroll_locked());
        panel.toggle_scroll_lock();
        assert!(!panel.is_scroll_locked());
    }

    #[test]
    fn test_panel_visibility() {
        let mut panel = ConsolePanel::new("Test");
        panel.set_visible(false);
        assert!(!panel.is_visible());
        // Adding a message auto-shows
        panel.add_message("s", "msg");
        assert!(panel.is_visible());
    }

    #[test]
    fn test_panel_find() {
        let mut panel = ConsolePanel::new("Test");
        panel.add_message("s", "hello world hello");
        let count = panel.find("hello");
        assert_eq!(count, 2);
        assert_eq!(panel.find_state().cursor(), Some(0));
    }

    #[test]
    fn test_panel_find_next_previous() {
        let mut panel = ConsolePanel::new("Test");
        panel.add_message("s", "aaa bbb aaa bbb aaa");
        panel.find("aaa");
        assert_eq!(panel.find_state().match_count(), 3);

        let m = panel.find_next();
        assert!(m.is_some());
        assert_eq!(panel.find_state().cursor(), Some(1));

        let m = panel.find_previous();
        assert!(m.is_some());
        assert_eq!(panel.find_state().cursor(), Some(0));
    }

    #[test]
    fn test_panel_find_wraps_around() {
        let mut panel = ConsolePanel::new("Test");
        panel.add_message("s", "aaa bbb");
        panel.find("aaa");
        assert_eq!(panel.find_state().cursor(), Some(0));

        // Going previous from 0 should wrap to last (0 in this case).
        let m = panel.find_previous();
        assert!(m.is_some());
    }

    #[test]
    fn test_panel_close_find() {
        let mut panel = ConsolePanel::new("Test");
        panel.add_message("s", "hello");
        panel.find("hello");
        assert!(panel.find_state().is_active());
        panel.close_find();
        assert!(!panel.find_state().is_active());
    }

    #[test]
    fn test_panel_clear() {
        let mut panel = ConsolePanel::new("Test");
        panel.add_message("s", "hello");
        panel.find("hello");
        panel.perform_action(PanelAction::Clear);
        assert!(panel.log().is_empty());
        assert!(!panel.find_state().is_active());
    }

    #[test]
    fn test_panel_program_tracking() {
        let mut panel = ConsolePanel::new("Test");
        assert!(panel.current_program().is_none());
        panel.set_current_program(Some("test.exe".to_string()));
        assert_eq!(panel.current_program(), Some("test.exe"));
        panel.set_current_program(None);
        assert!(panel.current_program().is_none());
    }

    #[test]
    fn test_panel_address_tracking() {
        let mut panel = ConsolePanel::new("Test");
        assert!(panel.current_address().is_none());
        panel.set_current_address(Some("0x400000".to_string()));
        assert_eq!(panel.current_address(), Some("0x400000"));
    }

    #[test]
    fn test_panel_get_text() {
        let mut panel = ConsolePanel::new("Test");
        panel.add_message("s", "abcdef");
        assert_eq!(panel.get_text(0, 2), Some("s>".to_string()));
        assert!(panel.get_text(0, 1000).is_none());
    }

    #[test]
    fn test_panel_with_console_message() {
        let mut panel = ConsolePanel::new("Test");
        let msg = ConsoleMessage::new("analysis", "Starting", ConsoleMessageType::Info);
        panel.add_console_message(&msg);
        assert!(panel.text().contains("analysis> Starting"));
    }

    #[test]
    fn test_panel_with_warning_message() {
        let mut panel = ConsolePanel::new("Test");
        let msg = ConsoleMessage::new("plugin", "Deprecated API", ConsoleMessageType::Warning);
        panel.add_console_message(&msg);
        assert!(panel.text().contains("[WARN]"));
    }

    #[test]
    fn test_panel_default() {
        let panel = ConsolePanel::default();
        assert_eq!(panel.name(), "Console");
    }

    #[test]
    fn test_panel_with_max_chars() {
        let panel = ConsolePanel::with_max_chars("Test", 5000);
        assert_eq!(panel.log().max_chars(), 5000);
    }

    #[test]
    fn test_panel_toggle_scroll_lock_action() {
        let mut panel = ConsolePanel::new("Test");
        panel.perform_action(PanelAction::ToggleScrollLock);
        assert!(panel.is_scroll_locked());
        panel.perform_action(PanelAction::ToggleScrollLock);
        assert!(!panel.is_scroll_locked());
    }

    #[test]
    fn test_find_state_empty() {
        let fs = FindState::new();
        assert!(!fs.is_active());
        assert_eq!(fs.match_count(), 0);
        assert!(fs.current_match().is_none());
    }

    #[test]
    fn test_find_state_set_query() {
        let mut fs = FindState::new();
        fs.set_query("abc", "abc def abc ghi abc");
        assert_eq!(fs.match_count(), 3);
        assert!(fs.is_active());
        assert_eq!(fs.cursor(), Some(0));
    }

    #[test]
    fn test_find_state_no_matches() {
        let mut fs = FindState::new();
        fs.set_query("xyz", "hello world");
        assert_eq!(fs.match_count(), 0);
        assert!(fs.cursor().is_none());
        assert!(fs.next().is_none());
        assert!(fs.previous().is_none());
    }

    #[test]
    fn test_find_state_clear() {
        let mut fs = FindState::new();
        fs.set_query("abc", "abc");
        fs.clear();
        assert!(!fs.is_active());
        assert_eq!(fs.match_count(), 0);
    }
}
