//! Search text plugin model.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.searchtext` Java package.
//!
//! Provides the plugin-level coordination for text search in the
//! program listing.
//!
//! # Key Types
//!
//! - [`SearchTextPlugin`] -- plugin coordinating text search
//! - [`SearchResult`] -- result of a search operation
//! - [`SearchState`] -- state of the search

use ghidra_core::Address;

use super::SearchOptions;

// ---------------------------------------------------------------------------
// SearchResult
// ---------------------------------------------------------------------------

/// Result of a single search match.
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// The address where the match was found.
    pub address: Address,
    /// The matching text.
    pub match_text: String,
    /// The field type where the match was found (e.g., "instruction", "comment").
    pub field_type: String,
    /// The column offset within the matched text.
    pub column: usize,
}

impl SearchResult {
    /// Create a new search result.
    pub fn new(
        address: Address,
        match_text: impl Into<String>,
        field_type: impl Into<String>,
    ) -> Self {
        Self {
            address,
            match_text: match_text.into(),
            field_type: field_type.into(),
            column: 0,
        }
    }

    /// Set the column offset.
    pub fn with_column(mut self, column: usize) -> Self {
        self.column = column;
        self
    }
}

// ---------------------------------------------------------------------------
// SearchState
// ---------------------------------------------------------------------------

/// State of the search operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchState {
    /// No search has been started.
    Idle,
    /// A search is currently running.
    Running,
    /// The search completed successfully.
    Complete,
    /// The search was cancelled by the user.
    Cancelled,
    /// The search encountered an error.
    Error,
}

impl SearchState {
    /// Whether the search is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Complete | Self::Cancelled | Self::Error)
    }
}

// ---------------------------------------------------------------------------
// SearchTextPlugin
// ---------------------------------------------------------------------------

/// Plugin for text search in the program listing.
///
/// Ported from `ghidra.app.plugin.core.searchtext.SearchTextPlugin`.
#[derive(Debug)]
pub struct SearchTextPlugin {
    /// Current search options.
    options: SearchOptions,
    /// Search results collected so far.
    results: Vec<SearchResult>,
    /// Current state.
    state: SearchState,
    /// Index of the current result.
    current_result_index: Option<usize>,
    /// Whether search was started from the beginning.
    from_start: bool,
}

impl SearchTextPlugin {
    /// Create a new search text plugin.
    pub fn new() -> Self {
        Self {
            options: SearchOptions::new(
                "", false, true, true, true, true, true, true, true, true, true, false, true,
            ),
            results: Vec::new(),
            state: SearchState::Idle,
            current_result_index: None,
            from_start: true,
        }
    }

    /// Set search options.
    pub fn set_options(&mut self, options: SearchOptions) {
        self.options = options;
    }

    /// Get the current search options.
    pub fn options(&self) -> &SearchOptions {
        &self.options
    }

    /// Add a search result.
    pub fn add_result(&mut self, result: SearchResult) {
        self.results.push(result);
    }

    /// Get all results.
    pub fn results(&self) -> &[SearchResult] {
        &self.results
    }

    /// Number of results.
    pub fn result_count(&self) -> usize {
        self.results.len()
    }

    /// Get the current search state.
    pub fn state(&self) -> SearchState {
        self.state
    }

    /// Set the search state.
    pub fn set_state(&mut self, state: SearchState) {
        self.state = state;
    }

    /// Navigate to the next result.
    pub fn next_result(&mut self) -> Option<&SearchResult> {
        if self.results.is_empty() {
            return None;
        }
        let idx = match self.current_result_index {
            Some(i) => (i + 1) % self.results.len(),
            None => 0,
        };
        self.current_result_index = Some(idx);
        self.results.get(idx)
    }

    /// Navigate to the previous result.
    pub fn previous_result(&mut self) -> Option<&SearchResult> {
        if self.results.is_empty() {
            return None;
        }
        let idx = match self.current_result_index {
            Some(i) => {
                if i == 0 {
                    self.results.len() - 1
                } else {
                    i - 1
                }
            }
            None => self.results.len() - 1,
        };
        self.current_result_index = Some(idx);
        self.results.get(idx)
    }

    /// Get the current result.
    pub fn current_result(&self) -> Option<&SearchResult> {
        self.current_result_index.and_then(|i| self.results.get(i))
    }

    /// The current result index.
    pub fn current_result_index(&self) -> Option<usize> {
        self.current_result_index
    }

    /// Whether the search started from the beginning.
    pub fn from_start(&self) -> bool {
        self.from_start
    }

    /// Set whether the search starts from the beginning.
    pub fn set_from_start(&mut self, from_start: bool) {
        self.from_start = from_start;
    }

    /// Clear all results and reset state.
    pub fn reset(&mut self) {
        self.results.clear();
        self.state = SearchState::Idle;
        self.current_result_index = None;
    }

    /// Whether there are any results.
    pub fn has_results(&self) -> bool {
        !self.results.is_empty()
    }
}

impl Default for SearchTextPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_result() {
        let result = SearchResult::new(Address::new(0x1000), "hello", "comment")
            .with_column(5);
        assert_eq!(result.address, Address::new(0x1000));
        assert_eq!(result.match_text, "hello");
        assert_eq!(result.field_type, "comment");
        assert_eq!(result.column, 5);
    }

    #[test]
    fn test_search_state() {
        assert!(SearchState::Complete.is_terminal());
        assert!(SearchState::Cancelled.is_terminal());
        assert!(SearchState::Error.is_terminal());
        assert!(!SearchState::Idle.is_terminal());
        assert!(!SearchState::Running.is_terminal());
    }

    #[test]
    fn test_search_text_plugin_new() {
        let plugin = SearchTextPlugin::new();
        assert_eq!(plugin.state(), SearchState::Idle);
        assert!(plugin.results().is_empty());
        assert!(plugin.current_result().is_none());
        assert!(!plugin.has_results());
    }

    #[test]
    fn test_search_text_plugin_add_results() {
        let mut plugin = SearchTextPlugin::new();
        plugin.add_result(SearchResult::new(Address::new(0x1000), "hello", "comment"));
        plugin.add_result(SearchResult::new(Address::new(0x2000), "world", "label"));
        assert_eq!(plugin.result_count(), 2);
        assert!(plugin.has_results());
    }

    #[test]
    fn test_search_text_plugin_navigate_forward() {
        let mut plugin = SearchTextPlugin::new();
        plugin.add_result(SearchResult::new(Address::new(0x1000), "a", "comment"));
        plugin.add_result(SearchResult::new(Address::new(0x2000), "b", "label"));
        plugin.add_result(SearchResult::new(Address::new(0x3000), "c", "code"));

        let r1 = plugin.next_result().unwrap();
        assert_eq!(r1.address, Address::new(0x1000));

        let r2 = plugin.next_result().unwrap();
        assert_eq!(r2.address, Address::new(0x2000));

        let r3 = plugin.next_result().unwrap();
        assert_eq!(r3.address, Address::new(0x3000));

        // Wraps around
        let r4 = plugin.next_result().unwrap();
        assert_eq!(r4.address, Address::new(0x1000));
    }

    #[test]
    fn test_search_text_plugin_navigate_backward() {
        let mut plugin = SearchTextPlugin::new();
        plugin.add_result(SearchResult::new(Address::new(0x1000), "a", "comment"));
        plugin.add_result(SearchResult::new(Address::new(0x2000), "b", "label"));

        // Starts from end
        let r1 = plugin.previous_result().unwrap();
        assert_eq!(r1.address, Address::new(0x2000));

        let r2 = plugin.previous_result().unwrap();
        assert_eq!(r2.address, Address::new(0x1000));

        // Wraps around
        let r3 = plugin.previous_result().unwrap();
        assert_eq!(r3.address, Address::new(0x2000));
    }

    #[test]
    fn test_search_text_plugin_navigate_empty() {
        let mut plugin = SearchTextPlugin::new();
        assert!(plugin.next_result().is_none());
        assert!(plugin.previous_result().is_none());
    }

    #[test]
    fn test_search_text_plugin_current_result() {
        let mut plugin = SearchTextPlugin::new();
        plugin.add_result(SearchResult::new(Address::new(0x1000), "hello", "comment"));

        assert!(plugin.current_result().is_none());
        plugin.next_result();
        assert!(plugin.current_result().is_some());
        assert_eq!(plugin.current_result_index(), Some(0));
    }

    #[test]
    fn test_search_text_plugin_reset() {
        let mut plugin = SearchTextPlugin::new();
        plugin.add_result(SearchResult::new(Address::new(0x1000), "hello", "comment"));
        plugin.set_state(SearchState::Complete);

        plugin.reset();
        assert!(plugin.results().is_empty());
        assert_eq!(plugin.state(), SearchState::Idle);
        assert!(plugin.current_result().is_none());
    }

    #[test]
    fn test_search_text_plugin_state() {
        let mut plugin = SearchTextPlugin::new();
        plugin.set_state(SearchState::Running);
        assert_eq!(plugin.state(), SearchState::Running);
    }

    #[test]
    fn test_search_text_plugin_from_start() {
        let mut plugin = SearchTextPlugin::new();
        assert!(plugin.from_start());
        plugin.set_from_start(false);
        assert!(!plugin.from_start());
    }
}
