//! Console provider -- view-state management for the console panel.
//!
//! Ported from Ghidra's `ConsoleComponentProvider` view-state layer in
//! `ghidra.app.plugin.core.console`.
//!
//! This module provides [`ConsoleProvider`], which manages the display
//! configuration, command history, and interactive state of the console
//! panel.  It sits above the raw [`ConsoleComponentProvider`] text buffer
//! and adds:
//!
//! - Display configuration (font size, max lines, wrap mode)
//! - Command history with up/down navigation
//! - Search state (current query, match positions, current match index)
//! - Action coordination (clear, copy, paste, find, font resize)
//!
//! [`ConsoleComponentProvider`]: super::console_component_provider::ConsoleComponentProvider

use serde::{Deserialize, Serialize};

use super::console_component_provider::ConsoleComponentProvider;
use super::console_service::ConsoleService;

// ============================================================================
// ConsoleProviderConfig -- display options
// ============================================================================

/// Display configuration for the console panel.
///
/// Mirrors the `SaveState` fields that Ghidra's `ConsoleComponentProvider`
/// persists between sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleProviderConfig {
    /// Maximum number of lines retained in the console buffer.
    pub max_lines: usize,
    /// Whether long lines wrap at the panel edge.
    pub line_wrap: bool,
    /// Whether the console auto-scrolls to the bottom on new output.
    pub auto_scroll: bool,
    /// Font point size for the console text area.
    pub font_size: u32,
    /// Whether to clear the console when a new script begins.
    pub clear_on_run: bool,
}

impl Default for ConsoleProviderConfig {
    fn default() -> Self {
        Self {
            max_lines: 100_000,
            line_wrap: true,
            auto_scroll: true,
            font_size: 12,
            clear_on_run: false,
        }
    }
}

impl ConsoleProviderConfig {
    /// Serialize configuration to JSON for persistence.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Deserialize configuration from JSON.
    pub fn from_json(json: &str) -> Option<Self> {
        serde_json::from_str(json).ok()
    }
}

// ============================================================================
// SearchState -- interactive find state
// ============================================================================

/// Tracks the state of an interactive search in the console text.
#[derive(Debug, Clone, Default)]
pub struct SearchState {
    /// The current search query.
    query: String,
    /// All match offsets `(start, end)` in the console text.
    matches: Vec<(usize, usize)>,
    /// Index of the currently highlighted match.
    current_index: Option<usize>,
    /// Whether the search is case-sensitive.
    case_sensitive: bool,
}

impl SearchState {
    /// Create a new empty search state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if a search is active.
    pub fn is_active(&self) -> bool {
        !self.query.is_empty()
    }

    /// Returns the current query string.
    pub fn query(&self) -> &str {
        &self.query
    }

    /// Returns the number of matches.
    pub fn match_count(&self) -> usize {
        self.matches.len()
    }

    /// Returns the current match offset, or `None`.
    pub fn current_match(&self) -> Option<(usize, usize)> {
        self.current_index.and_then(|i| self.matches.get(i).copied())
    }

    /// Returns the 1-based index of the current match, or `None`.
    pub fn current_match_number(&self) -> Option<usize> {
        self.current_index.map(|i| i + 1)
    }

    /// Returns whether the search is case-sensitive.
    pub fn is_case_sensitive(&self) -> bool {
        self.case_sensitive
    }

    /// Sets the case-sensitivity flag.
    pub fn set_case_sensitive(&mut self, case_sensitive: bool) {
        self.case_sensitive = case_sensitive;
    }

    /// Update the search with a new query and match list.
    pub fn update(&mut self, query: impl Into<String>, matches: Vec<(usize, usize)>) {
        self.query = query.into();
        self.matches = matches;
        self.current_index = if self.matches.is_empty() {
            None
        } else {
            Some(0)
        };
    }

    /// Advance to the next match (wraps around).
    pub fn next_match(&mut self) -> Option<(usize, usize)> {
        if self.matches.is_empty() {
            return None;
        }
        let idx = self.current_index.map_or(0, |i| (i + 1) % self.matches.len());
        self.current_index = Some(idx);
        self.current_match()
    }

    /// Go to the previous match (wraps around).
    pub fn prev_match(&mut self) -> Option<(usize, usize)> {
        if self.matches.is_empty() {
            return None;
        }
        let idx = self.current_index.map_or(0, |i| {
            if i == 0 {
                self.matches.len() - 1
            } else {
                i - 1
            }
        });
        self.current_index = Some(idx);
        self.current_match()
    }

    /// Clear the search state.
    pub fn clear(&mut self) {
        self.query.clear();
        self.matches.clear();
        self.current_index = None;
    }
}

// ============================================================================
// CommandHistory -- up/down history navigation
// ============================================================================

/// Ring-buffer command history for the console input line.
#[derive(Debug, Clone)]
pub struct CommandHistory {
    /// Stored commands (oldest first).
    commands: Vec<String>,
    /// Current navigation position (`commands.len()` = not browsing).
    position: usize,
    /// Maximum number of history entries.
    max_size: usize,
}

impl CommandHistory {
    /// Create a new command history with the given capacity.
    pub fn new(max_size: usize) -> Self {
        Self {
            commands: Vec::new(),
            position: 0,
            max_size,
        }
    }

    /// Add a command to the history.
    ///
    /// Empty commands and duplicates of the most recent entry are ignored.
    pub fn push(&mut self, command: impl Into<String>) {
        let cmd = command.into();
        if cmd.is_empty() {
            return;
        }
        if self.commands.last().map_or(false, |last| *last == cmd) {
            self.position = self.commands.len();
            return;
        }
        if self.commands.len() >= self.max_size {
            self.commands.remove(0);
        }
        self.commands.push(cmd);
        self.position = self.commands.len();
    }

    /// Move back in history (older). Returns the command, or `None`.
    pub fn previous(&mut self) -> Option<&str> {
        if self.commands.is_empty() {
            return None;
        }
        if self.position > 0 {
            self.position -= 1;
        }
        self.commands.get(self.position).map(|s| s.as_str())
    }

    /// Move forward in history (newer). Returns the command, or `None`.
    pub fn next(&mut self) -> Option<&str> {
        if self.commands.is_empty() || self.position >= self.commands.len() {
            return None;
        }
        self.position += 1;
        if self.position >= self.commands.len() {
            return None;
        }
        self.commands.get(self.position).map(|s| s.as_str())
    }

    /// Reset the navigation position to the end.
    pub fn reset_position(&mut self) {
        self.position = self.commands.len();
    }

    /// Returns the number of stored commands.
    pub fn len(&self) -> usize {
        self.commands.len()
    }

    /// Returns `true` if the history is empty.
    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }

    /// Returns a reference to all stored commands.
    pub fn commands(&self) -> &[String] {
        &self.commands
    }

    /// Clear all history.
    pub fn clear(&mut self) {
        self.commands.clear();
        self.position = 0;
    }
}

impl Default for CommandHistory {
    fn default() -> Self {
        Self::new(500)
    }
}

// ============================================================================
// ConsoleProvider -- high-level view-state manager
// ============================================================================

/// High-level provider for the console panel.
///
/// Manages display configuration, command history, and search state on
/// top of the raw [`ConsoleComponentProvider`].  This is the Rust
/// equivalent of the view-state portion of Ghidra's
/// `ConsoleComponentProvider` that coordinates actions like "Find",
/// "Copy", and font-size changes.
///
/// # Example
///
/// ```
/// use ghidra_features::base::console::{
///     ConsoleProvider, ConsoleProviderConfig, ConsoleService,
/// };
///
/// let mut provider = ConsoleProvider::new("Ghidra Script");
/// provider.console_mut().add_message("script", "Analysis started");
/// provider.history_mut().push("runScript('MyScript.java')");
///
/// // Search
/// provider.update_search("Analysis");
/// assert_eq!(provider.search().match_count(), 1);
/// ```
#[derive(Debug)]
pub struct ConsoleProvider {
    /// The underlying text-buffer console.
    console: ConsoleComponentProvider,
    /// Display configuration.
    config: ConsoleProviderConfig,
    /// Command history.
    history: CommandHistory,
    /// Interactive search state.
    search: SearchState,
    /// Whether the provider is currently showing a script output (vs.
    /// user-typed input).
    script_running: bool,
}

impl ConsoleProvider {
    /// Create a new console provider with default configuration.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            console: ConsoleComponentProvider::new(name),
            config: ConsoleProviderConfig::default(),
            history: CommandHistory::default(),
            search: SearchState::new(),
            script_running: false,
        }
    }

    /// Create a new console provider with the given configuration.
    pub fn with_config(name: impl Into<String>, config: ConsoleProviderConfig) -> Self {
        Self {
            console: ConsoleComponentProvider::new(name),
            config,
            history: CommandHistory::default(),
            search: SearchState::new(),
            script_running: false,
        }
    }

    // -- Accessors -----------------------------------------------------------

    /// Returns a reference to the underlying console component provider.
    pub fn console(&self) -> &ConsoleComponentProvider {
        &self.console
    }

    /// Returns a mutable reference to the underlying console component
    /// provider.
    pub fn console_mut(&mut self) -> &mut ConsoleComponentProvider {
        &mut self.console
    }

    /// Returns a reference to the display configuration.
    pub fn config(&self) -> &ConsoleProviderConfig {
        &self.config
    }

    /// Returns a mutable reference to the display configuration.
    pub fn config_mut(&mut self) -> &mut ConsoleProviderConfig {
        &mut self.config
    }

    /// Returns a reference to the command history.
    pub fn history(&self) -> &CommandHistory {
        &self.history
    }

    /// Returns a mutable reference to the command history.
    pub fn history_mut(&mut self) -> &mut CommandHistory {
        &mut self.history
    }

    /// Returns a reference to the search state.
    pub fn search(&self) -> &SearchState {
        &self.search
    }

    /// Returns `true` if a script is currently running.
    pub fn is_script_running(&self) -> bool {
        self.script_running
    }

    // -- Actions -------------------------------------------------------------

    /// Mark a script as starting -- optionally clears the console if
    /// `config.clear_on_run` is set.
    pub fn script_started(&mut self) {
        if self.config.clear_on_run {
            self.console.clear_messages();
        }
        self.script_running = true;
    }

    /// Mark the current script as finished.
    pub fn script_finished(&mut self) {
        self.script_running = false;
    }

    /// Submit a command: adds it to history and executes a callback-style
    /// return.  The caller is responsible for actually running the command.
    ///
    /// Returns `true` if the command was added to history.
    pub fn submit_command(&mut self, command: &str) -> bool {
        self.history.push(command);
        self.history.reset_position();
        !command.is_empty()
    }

    /// Run a search in the console text, updating the search state.
    pub fn update_search(&mut self, query: &str) {
        let matches = self.console.find_all(query);
        self.search.update(query, matches);
    }

    /// Clear the current search state.
    pub fn clear_search(&mut self) {
        self.search.clear();
    }

    /// Copy the current selection range to a string.
    ///
    /// Returns `None` if the range is out of bounds.
    pub fn copy_range(&self, offset: usize, length: usize) -> Option<String> {
        self.console.get_text(offset, length)
    }

    /// Serialize the configuration to JSON for persistence.
    pub fn save_state(&self) -> String {
        self.config.to_json()
    }

    /// Restore configuration from a JSON string.
    pub fn load_state(&mut self, json: &str) {
        if let Some(cfg) = ConsoleProviderConfig::from_json(json) {
            self.config = cfg;
        }
    }
}

// -- ConsoleService delegation -----------------------------------------------

impl ConsoleService for ConsoleProvider {
    fn add_message(&mut self, originator: &str, message: &str) {
        self.console.add_message(originator, message);
    }

    fn add_error_message(&mut self, originator: &str, message: &str) {
        self.console.add_error_message(originator, message);
    }

    fn add_exception(&mut self, originator: &str, message: &str) {
        self.console.add_exception(originator, message);
    }

    fn clear_messages(&mut self) {
        self.console.clear_messages();
    }

    fn print(&mut self, msg: &str) {
        self.console.print(msg);
    }

    fn print_error(&mut self, errmsg: &str) {
        self.console.print_error(errmsg);
    }

    fn println(&mut self, msg: &str) {
        self.console.println(msg);
    }

    fn println_error(&mut self, errmsg: &str) {
        self.console.println_error(errmsg);
    }

    fn get_stdout(&self) -> Box<dyn std::io::Write> {
        self.console.get_stdout()
    }

    fn get_stderr(&self) -> Box<dyn std::io::Write> {
        self.console.get_stderr()
    }

    fn get_text(&self, offset: usize, length: usize) -> Option<String> {
        self.console.get_text(offset, length)
    }

    fn get_text_length(&self) -> usize {
        self.console.get_text_length()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // ConsoleProviderConfig
    // ------------------------------------------------------------------

    #[test]
    fn test_config_defaults() {
        let cfg = ConsoleProviderConfig::default();
        assert_eq!(cfg.max_lines, 100_000);
        assert!(cfg.line_wrap);
        assert!(cfg.auto_scroll);
        assert_eq!(cfg.font_size, 12);
        assert!(!cfg.clear_on_run);
    }

    #[test]
    fn test_config_json_roundtrip() {
        let cfg = ConsoleProviderConfig {
            max_lines: 50_000,
            line_wrap: false,
            font_size: 14,
            ..Default::default()
        };
        let json = cfg.to_json();
        let restored = ConsoleProviderConfig::from_json(&json).unwrap();
        assert_eq!(restored.max_lines, 50_000);
        assert!(!restored.line_wrap);
        assert_eq!(restored.font_size, 14);
    }

    // ------------------------------------------------------------------
    // SearchState
    // ------------------------------------------------------------------

    #[test]
    fn test_search_new() {
        let s = SearchState::new();
        assert!(!s.is_active());
        assert_eq!(s.match_count(), 0);
        assert!(s.current_match().is_none());
    }

    #[test]
    fn test_search_update() {
        let mut s = SearchState::new();
        s.update("hello", vec![(0, 5), (10, 15)]);
        assert!(s.is_active());
        assert_eq!(s.match_count(), 2);
        assert_eq!(s.current_match_number(), Some(1));
        assert_eq!(s.current_match(), Some((0, 5)));
    }

    #[test]
    fn test_search_next_prev() {
        let mut s = SearchState::new();
        s.update("x", vec![(0, 1), (5, 6), (10, 11)]);

        // Already at 0, next -> 1
        assert_eq!(s.next_match(), Some((5, 6)));
        assert_eq!(s.current_match_number(), Some(2));

        // next -> 2
        assert_eq!(s.next_match(), Some((10, 11)));
        assert_eq!(s.current_match_number(), Some(3));

        // next wraps -> 0
        assert_eq!(s.next_match(), Some((0, 1)));

        // prev wraps -> 2
        assert_eq!(s.prev_match(), Some((10, 11)));
    }

    #[test]
    fn test_search_case_sensitive() {
        let mut s = SearchState::new();
        assert!(!s.is_case_sensitive());
        s.set_case_sensitive(true);
        assert!(s.is_case_sensitive());
    }

    #[test]
    fn test_search_clear() {
        let mut s = SearchState::new();
        s.update("q", vec![(0, 1)]);
        s.clear();
        assert!(!s.is_active());
        assert_eq!(s.match_count(), 0);
    }

    #[test]
    fn test_search_empty_matches() {
        let mut s = SearchState::new();
        s.update("notfound", vec![]);
        assert!(s.is_active()); // query is set
        assert_eq!(s.match_count(), 0);
        assert!(s.current_match().is_none());
        assert!(s.next_match().is_none());
        assert!(s.prev_match().is_none());
    }

    // ------------------------------------------------------------------
    // CommandHistory
    // ------------------------------------------------------------------

    #[test]
    fn test_history_push_and_navigate() {
        let mut h = CommandHistory::new(100);
        h.push("first");
        h.push("second");
        h.push("third");
        h.reset_position();

        assert_eq!(h.previous(), Some("third"));
        assert_eq!(h.previous(), Some("second"));
        assert_eq!(h.previous(), Some("first"));
        // Stays at first
        assert_eq!(h.previous(), Some("first"));

        assert_eq!(h.next(), Some("second"));
        assert_eq!(h.next(), Some("third"));
        assert_eq!(h.next(), None);
    }

    #[test]
    fn test_history_ignores_empty() {
        let mut h = CommandHistory::new(100);
        h.push("");
        assert_eq!(h.len(), 0);
    }

    #[test]
    fn test_history_ignores_duplicate_top() {
        let mut h = CommandHistory::new(100);
        h.push("cmd");
        h.push("cmd");
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn test_history_max_size() {
        let mut h = CommandHistory::new(3);
        h.push("a");
        h.push("b");
        h.push("c");
        h.push("d");
        assert_eq!(h.len(), 3);
        assert_eq!(h.commands()[0], "b");
        assert_eq!(h.commands()[2], "d");
    }

    #[test]
    fn test_history_clear() {
        let mut h = CommandHistory::new(100);
        h.push("a");
        h.push("b");
        h.clear();
        assert!(h.is_empty());
        assert!(h.previous().is_none());
    }

    #[test]
    fn test_history_default_capacity() {
        let h = CommandHistory::default();
        assert_eq!(h.max_size, 500);
    }

    // ------------------------------------------------------------------
    // ConsoleProvider
    // ------------------------------------------------------------------

    #[test]
    fn test_provider_creation() {
        let p = ConsoleProvider::new("Test");
        assert_eq!(p.console().name(), "Test");
        assert!(!p.is_script_running());
        assert!(!p.search().is_active());
    }

    #[test]
    fn test_provider_with_config() {
        let cfg = ConsoleProviderConfig {
            font_size: 16,
            clear_on_run: true,
            ..Default::default()
        };
        let p = ConsoleProvider::with_config("Test", cfg);
        assert_eq!(p.config().font_size, 16);
        assert!(p.config().clear_on_run);
    }

    #[test]
    fn test_provider_script_lifecycle() {
        let mut p = ConsoleProvider::new("Test");
        assert!(!p.is_script_running());

        p.script_started();
        assert!(p.is_script_running());

        p.script_finished();
        assert!(!p.is_script_running());
    }

    #[test]
    fn test_provider_clear_on_run() {
        let cfg = ConsoleProviderConfig {
            clear_on_run: true,
            ..Default::default()
        };
        let mut p = ConsoleProvider::with_config("Test", cfg);
        p.console_mut().add_message("s", "old output");

        p.script_started();
        assert_eq!(p.get_text_length(), 0);
    }

    #[test]
    fn test_provider_submit_command() {
        let mut p = ConsoleProvider::new("Test");
        assert!(p.submit_command("runScript('Foo.java')"));
        assert!(!p.submit_command(""));

        assert_eq!(p.history().len(), 1);
        assert_eq!(p.history().commands()[0], "runScript('Foo.java')");
    }

    #[test]
    fn test_provider_search_integration() {
        let mut p = ConsoleProvider::new("Test");
        p.console_mut().add_message("s", "hello world hello");
        p.update_search("hello");

        assert_eq!(p.search().match_count(), 2);
        assert_eq!(p.search().current_match_number(), Some(1));

        p.clear_search();
        assert!(!p.search().is_active());
    }

    #[test]
    fn test_provider_copy_range() {
        let mut p = ConsoleProvider::new("Test");
        p.console_mut().add_message("s", "hello");
        let copied = p.copy_range(0, 2);
        assert_eq!(copied, Some("s>".to_string()));
    }

    #[test]
    fn test_provider_save_load_state() {
        let mut p = ConsoleProvider::new("Test");
        p.config_mut().font_size = 18;
        let state = p.save_state();

        let mut p2 = ConsoleProvider::new("Test2");
        p2.load_state(&state);
        assert_eq!(p2.config().font_size, 18);
    }

    #[test]
    fn test_provider_console_service_delegation() {
        let mut p = ConsoleProvider::new("Test");
        p.add_message("s", "msg");
        p.add_error_message("s", "err");
        p.println("line");

        assert!(p.get_text_length() > 0);
        let text = p.get_text(0, 2).unwrap();
        assert_eq!(text, "s>");
    }

    #[test]
    fn test_provider_console_mut_access() {
        let mut p = ConsoleProvider::new("Test");
        p.console_mut().set_scroll_lock(true);
        assert!(p.console().is_scroll_locked());
    }
}
