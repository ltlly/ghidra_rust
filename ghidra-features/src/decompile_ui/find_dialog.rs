//! Decompiler Find Dialog -- Rust port of
//! `ghidra.app.decompiler.component.DecompilerFindDialog`.
//!
//! In Ghidra, `DecompilerFindDialog` extends `FindDialog` and wraps a
//! `DecompilerSearcher` to provide find/replace functionality within the
//! decompiler's C code output.  The dialog supports forward/backward
//! searching, case-sensitive/insensitive matching, regular expressions,
//! and scoped searching (current function or all functions).
//!
//! # Architecture
//!
//! ```text
//! DecompilerFindDialog
//!   ├── title: String
//!   ├── searcher: DecompilerSearcher
//!   ├── search_text: String
//!   ├── replace_text: Option<String>
//!   ├── case_sensitive: bool
//!   ├── use_regex: bool
//!   ├── search_direction: SearchDirection
//!   ├── search_scope: SearchScope
//!   ├── match_count: usize
//!   ├── current_match_index: Option<usize>
//!   └── visible: bool
//! ```

use std::fmt;

// ---------------------------------------------------------------------------
// SearchDirection -- direction of search within the decompiler output
// ---------------------------------------------------------------------------

/// The direction to search within the decompiler's C code output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SearchDirection {
    /// Search forward from the current cursor position.
    Forward,
    /// Search backward from the current cursor position.
    Backward,
}

impl Default for SearchDirection {
    fn default() -> Self {
        Self::Forward
    }
}

impl fmt::Display for SearchDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Forward => write!(f, "Forward"),
            Self::Backward => write!(f, "Backward"),
        }
    }
}

// ---------------------------------------------------------------------------
// SearchScope -- scope of the search
// ---------------------------------------------------------------------------

/// The scope of the decompiler text search.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SearchScope {
    /// Search only within the currently decompiled function.
    CurrentFunction,
    /// Search across all decompiled functions in the program.
    AllFunctions,
}

impl Default for SearchScope {
    fn default() -> Self {
        Self::CurrentFunction
    }
}

impl fmt::Display for SearchScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CurrentFunction => write!(f, "Current Function"),
            Self::AllFunctions => write!(f, "All Functions"),
        }
    }
}

// ---------------------------------------------------------------------------
// SearchMatch -- a single search result in the decompiler output
// ---------------------------------------------------------------------------

/// A single text match found in the decompiler output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchMatch {
    /// The 0-based line number where the match was found.
    pub line_index: usize,
    /// The 0-based column offset of the start of the match within the line.
    pub column_start: usize,
    /// The 0-based column offset of the end of the match within the line.
    pub column_end: usize,
    /// The matched text.
    pub matched_text: String,
    /// The address associated with this line (if known).
    pub address: Option<u64>,
}

impl SearchMatch {
    /// Create a new search match.
    pub fn new(
        line_index: usize,
        column_start: usize,
        column_end: usize,
        matched_text: String,
        address: Option<u64>,
    ) -> Self {
        Self {
            line_index,
            column_start,
            column_end,
            matched_text,
            address,
        }
    }

    /// The length of the matched text.
    pub fn length(&self) -> usize {
        self.column_end - self.column_start
    }
}

// ---------------------------------------------------------------------------
// SearchResult -- the full result of a search operation
// ---------------------------------------------------------------------------

/// The result of executing a search in the decompiler.
#[derive(Debug, Clone, Default)]
pub struct SearchResult {
    /// All matches found, in document order.
    pub matches: Vec<SearchMatch>,
    /// The index of the currently selected match (if any).
    pub current_index: Option<usize>,
    /// Whether the search wrapped around from the end to the beginning.
    pub wrapped: bool,
}

impl SearchResult {
    /// Create an empty search result.
    pub fn new() -> Self {
        Self::default()
    }

    /// The total number of matches.
    pub fn match_count(&self) -> usize {
        self.matches.len()
    }

    /// Whether any matches were found.
    pub fn has_matches(&self) -> bool {
        !self.matches.is_empty()
    }

    /// Get the current match.
    pub fn current_match(&self) -> Option<&SearchMatch> {
        self.current_index.and_then(|i| self.matches.get(i))
    }

    /// Advance to the next match and return it.
    pub fn next_match(&mut self) -> Option<&SearchMatch> {
        if self.matches.is_empty() {
            return None;
        }
        let idx = match self.current_index {
            Some(i) => (i + 1) % self.matches.len(),
            None => 0,
        };
        self.current_index = Some(idx);
        if idx == 0 && self.current_index != Some(0) {
            self.wrapped = true;
        }
        self.matches.get(idx)
    }

    /// Move to the previous match and return it.
    pub fn previous_match(&mut self) -> Option<&SearchMatch> {
        if self.matches.is_empty() {
            return None;
        }
        let idx = match self.current_index {
            Some(i) => {
                if i == 0 {
                    self.wrapped = true;
                    self.matches.len() - 1
                } else {
                    i - 1
                }
            }
            None => self.matches.len() - 1,
        };
        self.current_index = Some(idx);
        self.matches.get(idx)
    }
}

// ---------------------------------------------------------------------------
// SearchOptions -- configurable search parameters
// ---------------------------------------------------------------------------

/// Options controlling how the decompiler text search behaves.
#[derive(Debug, Clone)]
pub struct SearchOptions {
    /// The text to search for.
    pub search_text: String,
    /// Optional replacement text.
    pub replace_text: Option<String>,
    /// Whether the search is case-sensitive.
    pub case_sensitive: bool,
    /// Whether to interpret the search text as a regular expression.
    pub use_regex: bool,
    /// The direction to search.
    pub direction: SearchDirection,
    /// The scope of the search.
    pub scope: SearchScope,
    /// Whether to match whole words only.
    pub whole_word: bool,
}

impl Default for SearchOptions {
    fn default() -> Self {
        Self {
            search_text: String::new(),
            replace_text: None,
            case_sensitive: false,
            use_regex: false,
            direction: SearchDirection::Forward,
            scope: SearchScope::CurrentFunction,
            whole_word: false,
        }
    }
}

impl SearchOptions {
    /// Create search options with the given search text.
    pub fn with_text(search_text: impl Into<String>) -> Self {
        Self {
            search_text: search_text.into(),
            ..Default::default()
        }
    }

    /// Set case sensitivity.
    pub fn case_sensitive(mut self, yes: bool) -> Self {
        self.case_sensitive = yes;
        self
    }

    /// Set regex mode.
    pub fn regex(mut self, yes: bool) -> Self {
        self.use_regex = yes;
        self
    }

    /// Set the search direction.
    pub fn direction(mut self, dir: SearchDirection) -> Self {
        self.direction = dir;
        self
    }

    /// Set the search scope.
    pub fn scope(mut self, scope: SearchScope) -> Self {
        self.scope = scope;
        self
    }

    /// Set whole-word matching.
    pub fn whole_word(mut self, yes: bool) -> Self {
        self.whole_word = yes;
        self
    }
}

// ---------------------------------------------------------------------------
// DecompilerFindDialog -- the main find dialog model
// ---------------------------------------------------------------------------

/// The Decompiler Find Dialog.
///
/// This models the `DecompilerFindDialog` from Ghidra, which wraps a
/// `FindDialog` with a `DecompilerSearcher`.  It manages the dialog
/// state, search options, and navigates through matches.
///
/// In Ghidra:
/// ```java
/// public class DecompilerFindDialog extends FindDialog {
///     public DecompilerFindDialog(DecompilerPanel decompilerPanel) {
///         super("Decompiler Find", new DecompilerSearcher(decompilerPanel));
///         setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionFind"));
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct DecompilerFindDialog {
    /// The dialog title.
    title: String,
    /// Current search options.
    options: SearchOptions,
    /// The last search result.
    result: SearchResult,
    /// Whether the dialog is currently visible.
    visible: bool,
    /// Help topic identifier.
    help_topic: String,
    /// Help location path.
    help_location: String,
    /// Whether the replace UI is shown.
    show_replace: bool,
    /// Status message to display.
    status_message: Option<String>,
    /// The function name scope for the current search (if scoped).
    function_scope: Option<String>,
}

impl DecompilerFindDialog {
    /// Create a new find dialog.
    ///
    /// # Arguments
    /// * `title` - The dialog title (typically "Decompiler Find").
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            options: SearchOptions::default(),
            result: SearchResult::new(),
            visible: false,
            help_topic: "DECOMPILER".to_string(),
            help_location: "ActionFind".to_string(),
            show_replace: false,
            status_message: None,
            function_scope: None,
        }
    }

    /// Create a dialog with the standard Ghidra title and help location.
    pub fn for_decompiler() -> Self {
        Self::new("Decompiler Find")
    }

    // -- Visibility --

    /// Show the dialog.
    pub fn show(&mut self) {
        self.visible = true;
        self.status_message = None;
    }

    /// Hide the dialog.
    pub fn hide(&mut self) {
        self.visible = false;
    }

    /// Toggle visibility.
    pub fn toggle(&mut self) {
        self.visible = !self.visible;
        if self.visible {
            self.status_message = None;
        }
    }

    /// Whether the dialog is currently visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    // -- Replace UI --

    /// Show or hide the replace portion of the dialog.
    pub fn set_show_replace(&mut self, show: bool) {
        self.show_replace = show;
    }

    /// Whether the replace UI is shown.
    pub fn is_showing_replace(&self) -> bool {
        self.show_replace
    }

    // -- Search options --

    /// Get the current search text.
    pub fn search_text(&self) -> &str {
        &self.options.search_text
    }

    /// Set the search text.
    pub fn set_search_text(&mut self, text: impl Into<String>) {
        self.options.search_text = text.into();
        self.result = SearchResult::new();
    }

    /// Get the replacement text.
    pub fn replace_text(&self) -> Option<&str> {
        self.options.replace_text.as_deref()
    }

    /// Set the replacement text.
    pub fn set_replace_text(&mut self, text: Option<String>) {
        self.options.replace_text = text;
    }

    /// Whether the search is case-sensitive.
    pub fn is_case_sensitive(&self) -> bool {
        self.options.case_sensitive
    }

    /// Set case sensitivity.
    pub fn set_case_sensitive(&mut self, yes: bool) {
        self.options.case_sensitive = yes;
        self.result = SearchResult::new();
    }

    /// Whether regex mode is enabled.
    pub fn is_regex(&self) -> bool {
        self.options.use_regex
    }

    /// Set regex mode.
    pub fn set_regex(&mut self, yes: bool) {
        self.options.use_regex = yes;
        self.result = SearchResult::new();
    }

    /// Get the search direction.
    pub fn direction(&self) -> SearchDirection {
        self.options.direction
    }

    /// Set the search direction.
    pub fn set_direction(&mut self, dir: SearchDirection) {
        self.options.direction = dir;
    }

    /// Get the search scope.
    pub fn scope(&self) -> SearchScope {
        self.options.scope
    }

    /// Set the search scope.
    pub fn set_scope(&mut self, scope: SearchScope) {
        self.options.scope = scope;
        self.result = SearchResult::new();
    }

    /// Whether whole-word matching is enabled.
    pub fn is_whole_word(&self) -> bool {
        self.options.whole_word
    }

    /// Set whole-word matching.
    pub fn set_whole_word(&mut self, yes: bool) {
        self.options.whole_word = yes;
        self.result = SearchResult::new();
    }

    /// Get the current search options.
    pub fn options(&self) -> &SearchOptions {
        &self.options
    }

    /// Set all search options at once.
    pub fn set_options(&mut self, options: SearchOptions) {
        self.options = options;
        self.result = SearchResult::new();
    }

    // -- Function scope --

    /// Set the function scope for the search.
    pub fn set_function_scope(&mut self, name: Option<String>) {
        self.function_scope = name;
    }

    /// Get the function scope.
    pub fn function_scope(&self) -> Option<&str> {
        self.function_scope.as_deref()
    }

    // -- Search results --

    /// Get the current search result.
    pub fn result(&self) -> &SearchResult {
        &self.result
    }

    /// Set the search result (typically from executing a search).
    pub fn set_result(&mut self, result: SearchResult) {
        let count = result.match_count();
        self.result = result;
        if count == 0 {
            self.status_message = Some("No matches found".to_string());
        } else {
            self.status_message = None;
        }
    }

    /// Navigate to the next match.
    pub fn find_next(&mut self) -> Option<&SearchMatch> {
        self.result.next_match()
    }

    /// Navigate to the previous match.
    pub fn find_previous(&mut self) -> Option<&SearchMatch> {
        self.result.previous_match()
    }

    /// The total number of matches.
    pub fn match_count(&self) -> usize {
        self.result.match_count()
    }

    /// The 1-based index of the current match (for display).
    pub fn current_match_number(&self) -> Option<usize> {
        self.result.current_index.map(|i| i + 1)
    }

    // -- Status --

    /// Get the status message.
    pub fn status_message(&self) -> Option<&str> {
        self.status_message.as_deref()
    }

    /// Set a status message.
    pub fn set_status_message(&mut self, msg: Option<String>) {
        self.status_message = msg;
    }

    // -- Help --

    /// Get the help topic.
    pub fn help_topic(&self) -> &str {
        &self.help_topic
    }

    /// Get the help location.
    pub fn help_location(&self) -> &str {
        &self.help_location
    }

    // -- Title --

    /// Get the dialog title.
    pub fn title(&self) -> &str {
        &self.title
    }
}

impl Default for DecompilerFindDialog {
    fn default() -> Self {
        Self::for_decompiler()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_dialog_creation() {
        let dialog = DecompilerFindDialog::for_decompiler();
        assert_eq!(dialog.title(), "Decompiler Find");
        assert!(!dialog.is_visible());
        assert_eq!(dialog.match_count(), 0);
        assert_eq!(dialog.help_topic(), "DECOMPILER");
        assert_eq!(dialog.help_location(), "ActionFind");
    }

    #[test]
    fn test_find_dialog_visibility() {
        let mut dialog = DecompilerFindDialog::for_decompiler();
        assert!(!dialog.is_visible());

        dialog.show();
        assert!(dialog.is_visible());

        dialog.hide();
        assert!(!dialog.is_visible());

        dialog.toggle();
        assert!(dialog.is_visible());

        dialog.toggle();
        assert!(!dialog.is_visible());
    }

    #[test]
    fn test_find_dialog_search_text() {
        let mut dialog = DecompilerFindDialog::for_decompiler();
        assert_eq!(dialog.search_text(), "");

        dialog.set_search_text("hello");
        assert_eq!(dialog.search_text(), "hello");
    }

    #[test]
    fn test_find_dialog_options() {
        let mut dialog = DecompilerFindDialog::for_decompiler();

        dialog.set_case_sensitive(true);
        assert!(dialog.is_case_sensitive());

        dialog.set_regex(true);
        assert!(dialog.is_regex());

        dialog.set_whole_word(true);
        assert!(dialog.is_whole_word());

        dialog.set_direction(SearchDirection::Backward);
        assert_eq!(dialog.direction(), SearchDirection::Backward);

        dialog.set_scope(SearchScope::AllFunctions);
        assert_eq!(dialog.scope(), SearchScope::AllFunctions);
    }

    #[test]
    fn test_find_dialog_replace() {
        let mut dialog = DecompilerFindDialog::for_decompiler();
        assert!(!dialog.is_showing_replace());
        assert!(dialog.replace_text().is_none());

        dialog.set_show_replace(true);
        assert!(dialog.is_showing_replace());

        dialog.set_replace_text(Some("world".to_string()));
        assert_eq!(dialog.replace_text(), Some("world"));
    }

    #[test]
    fn test_search_result_navigation() {
        let mut result = SearchResult::new();
        result.matches = vec![
            SearchMatch::new(0, 0, 5, "hello".to_string(), Some(0x1000)),
            SearchMatch::new(5, 10, 15, "world".to_string(), Some(0x2000)),
            SearchMatch::new(10, 0, 5, "test".to_string(), Some(0x3000)),
        ];

        assert_eq!(result.match_count(), 3);
        assert!(result.has_matches());

        // Navigate forward.
        let m = result.next_match().unwrap();
        assert_eq!(m.matched_text, "hello");
        assert_eq!(m.line_index, 0);

        let m = result.next_match().unwrap();
        assert_eq!(m.matched_text, "world");
        assert_eq!(m.line_index, 5);

        let m = result.next_match().unwrap();
        assert_eq!(m.matched_text, "test");

        // Wraps around.
        let m = result.next_match().unwrap();
        assert_eq!(m.matched_text, "hello");

        // Navigate backward.
        let m = result.previous_match().unwrap();
        assert_eq!(m.matched_text, "test");
    }

    #[test]
    fn test_search_result_empty() {
        let mut result = SearchResult::new();
        assert!(!result.has_matches());
        assert_eq!(result.match_count(), 0);
        assert!(result.next_match().is_none());
        assert!(result.previous_match().is_none());
        assert!(result.current_match().is_none());
    }

    #[test]
    fn test_search_options_builder() {
        let opts = SearchOptions::with_text("test")
            .case_sensitive(true)
            .regex(false)
            .direction(SearchDirection::Backward)
            .scope(SearchScope::AllFunctions)
            .whole_word(true);

        assert_eq!(opts.search_text, "test");
        assert!(opts.case_sensitive);
        assert!(!opts.use_regex);
        assert_eq!(opts.direction, SearchDirection::Backward);
        assert_eq!(opts.scope, SearchScope::AllFunctions);
        assert!(opts.whole_word);
    }

    #[test]
    fn test_search_match_properties() {
        let m = SearchMatch::new(3, 10, 15, "hello".to_string(), Some(0x4000));
        assert_eq!(m.length(), 5);
        assert_eq!(m.line_index, 3);
        assert_eq!(m.column_start, 10);
        assert_eq!(m.column_end, 15);
        assert_eq!(m.address, Some(0x4000));
    }

    #[test]
    fn test_find_dialog_with_results() {
        let mut dialog = DecompilerFindDialog::for_decompiler();
        dialog.set_search_text("main");

        let mut result = SearchResult::new();
        result.matches = vec![
            SearchMatch::new(0, 0, 4, "main".to_string(), Some(0x1000)),
            SearchMatch::new(15, 5, 9, "main".to_string(), Some(0x1040)),
        ];
        result.current_index = Some(0);
        dialog.set_result(result);

        assert_eq!(dialog.match_count(), 2);
        assert_eq!(dialog.current_match_number(), Some(1));

        dialog.find_next();
        assert_eq!(dialog.current_match_number(), Some(2));

        dialog.find_previous();
        assert_eq!(dialog.current_match_number(), Some(1));
    }

    #[test]
    fn test_find_dialog_no_matches_status() {
        let mut dialog = DecompilerFindDialog::for_decompiler();
        let result = SearchResult::new();
        dialog.set_result(result);
        assert_eq!(dialog.status_message(), Some("No matches found"));
    }

    #[test]
    fn test_find_dialog_function_scope() {
        let mut dialog = DecompilerFindDialog::for_decompiler();
        assert!(dialog.function_scope().is_none());

        dialog.set_function_scope(Some("main".to_string()));
        assert_eq!(dialog.function_scope(), Some("main"));
    }

    #[test]
    fn test_search_direction_display() {
        assert_eq!(SearchDirection::Forward.to_string(), "Forward");
        assert_eq!(SearchDirection::Backward.to_string(), "Backward");
    }

    #[test]
    fn test_search_scope_display() {
        assert_eq!(SearchScope::CurrentFunction.to_string(), "Current Function");
        assert_eq!(SearchScope::AllFunctions.to_string(), "All Functions");
    }
}
