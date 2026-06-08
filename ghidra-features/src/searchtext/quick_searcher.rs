//! Quick searcher -- ported from `QuickSearcher.java` in
//! `ghidra.app.plugin.core.searchtext.quicksearcher`.
//!
//! Provides a fast incremental search mode that searches the listing
//! display text as the user types.

use serde::{Deserialize, Serialize};

use super::search_types::SearchDirection;

// ---------------------------------------------------------------------------
// QuickSearchProvider -- trait for quick search data sources
// ---------------------------------------------------------------------------

/// Trait for providing listing display text for quick search.
///
/// Ported from the `QuickSearcher` and related classes.
pub trait QuickSearchProvider: Send + Sync {
    /// Get the text content at the given address.
    fn get_text_at(&self, address: u64) -> Option<String>;

    /// Get the next address after the given address.
    fn next_address(&self, address: u64) -> Option<u64>;

    /// Get the previous address before the given address.
    fn previous_address(&self, address: u64) -> Option<u64>;
}

// ---------------------------------------------------------------------------
// QuickSearchState -- incremental search state
// ---------------------------------------------------------------------------

/// State for an incremental quick search.
///
/// Ported from the state management in `QuickSearcher`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickSearchState {
    /// The current search string.
    pub search_string: String,
    /// The search direction.
    pub direction: SearchDirection,
    /// The starting address for the current search.
    pub start_address: u64,
    /// The current match address.
    pub current_match: Option<u64>,
    /// Whether the search wraps around at address boundaries.
    pub wrap: bool,
    /// Whether the search is case-sensitive.
    pub case_sensitive: bool,
    /// Total matches found so far.
    pub match_count: usize,
}

impl QuickSearchState {
    /// Create a new quick search state.
    pub fn new(start_address: u64) -> Self {
        Self {
            search_string: String::new(),
            direction: SearchDirection::Forward,
            start_address,
            current_match: None,
            wrap: true,
            case_sensitive: true,
            match_count: 0,
        }
    }

    /// Whether the search is active.
    pub fn is_active(&self) -> bool {
        !self.search_string.is_empty()
    }

    /// Reset the search state.
    pub fn reset(&mut self) {
        self.search_string.clear();
        self.current_match = None;
        self.match_count = 0;
    }

    /// Set the search string and reset match state.
    pub fn set_search_string(&mut self, text: String) {
        self.search_string = text;
        self.current_match = None;
        self.match_count = 0;
    }
}

impl Default for QuickSearchState {
    fn default() -> Self {
        Self::new(0)
    }
}

// ---------------------------------------------------------------------------
// QuickSearchEngine -- performs the actual quick search
// ---------------------------------------------------------------------------

/// Engine that performs incremental text search over listing display
/// content.
///
/// Ported from the search logic in `QuickSearcher`.
#[derive(Debug)]
pub struct QuickSearchEngine {
    /// Whether the search is case-sensitive.
    case_sensitive: bool,
    /// Maximum number of matches to find before stopping.
    max_matches: usize,
    /// Whether to search forward or backward.
    direction: SearchDirection,
}

impl QuickSearchEngine {
    /// Create a new quick search engine.
    pub fn new() -> Self {
        Self {
            case_sensitive: true,
            max_matches: 1000,
            direction: SearchDirection::Forward,
        }
    }

    /// Set case sensitivity.
    pub fn set_case_sensitive(&mut self, case_sensitive: bool) {
        self.case_sensitive = case_sensitive;
    }

    /// Set maximum matches.
    pub fn set_max_matches(&mut self, max: usize) {
        self.max_matches = max;
    }

    /// Set search direction.
    pub fn set_direction(&mut self, direction: SearchDirection) {
        self.direction = direction;
    }

    /// Search for text within a string, returning the start index if found.
    pub fn find_in_text(&self, haystack: &str, needle: &str) -> Option<usize> {
        if needle.is_empty() {
            return Some(0);
        }
        let (hay, nee) = if self.case_sensitive {
            (haystack.to_string(), needle.to_string())
        } else {
            (haystack.to_lowercase(), needle.to_lowercase())
        };
        hay.find(&nee)
    }

    /// Search for multiple occurrences within text.
    pub fn find_all_in_text(&self, haystack: &str, needle: &str) -> Vec<usize> {
        if needle.is_empty() {
            return vec![];
        }
        let (hay, nee) = if self.case_sensitive {
            (haystack.to_string(), needle.to_string())
        } else {
            (haystack.to_lowercase(), needle.to_lowercase())
        };

        let mut positions = Vec::new();
        let mut start = 0;
        while let Some(pos) = hay[start..].find(&nee) {
            positions.push(start + pos);
            start += pos + 1;
        }
        positions
    }
}

impl Default for QuickSearchEngine {
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
    fn test_quick_search_state() {
        let mut state = QuickSearchState::new(0x400000);
        assert!(!state.is_active());
        assert_eq!(state.start_address, 0x400000);

        state.set_search_string("main".into());
        assert!(state.is_active());
        assert_eq!(state.search_string, "main");
        assert_eq!(state.match_count, 0);

        state.reset();
        assert!(!state.is_active());
    }

    #[test]
    fn test_quick_search_state_direction() {
        let mut state = QuickSearchState::new(0);
        state.direction = SearchDirection::Backward;
        assert_eq!(state.direction, SearchDirection::Backward);
    }

    #[test]
    fn test_quick_search_engine() {
        let engine = QuickSearchEngine::new();
        assert!(engine.case_sensitive);

        assert_eq!(engine.find_in_text("Hello World", "World"), Some(6));
        assert_eq!(engine.find_in_text("Hello World", "xyz"), None);
    }

    #[test]
    fn test_quick_search_engine_case_insensitive() {
        let mut engine = QuickSearchEngine::new();
        engine.set_case_sensitive(false);

        assert_eq!(engine.find_in_text("Hello World", "hello"), Some(0));
        assert_eq!(engine.find_in_text("Hello World", "WORLD"), Some(6));
    }

    #[test]
    fn test_quick_search_engine_find_all() {
        let engine = QuickSearchEngine::new();
        let positions = engine.find_all_in_text("abcabcabc", "abc");
        assert_eq!(positions, vec![0, 3, 6]);
    }

    #[test]
    fn test_quick_search_engine_find_all_case_insensitive() {
        let mut engine = QuickSearchEngine::new();
        engine.set_case_sensitive(false);
        let positions = engine.find_all_in_text("ABCabcAbc", "abc");
        assert_eq!(positions, vec![0, 3, 6]);
    }

    #[test]
    fn test_quick_search_engine_empty_needle() {
        let engine = QuickSearchEngine::new();
        assert_eq!(engine.find_in_text("anything", ""), Some(0));
        assert!(engine.find_all_in_text("anything", "").is_empty());
    }

    #[test]
    fn test_quick_search_engine_max_matches() {
        let mut engine = QuickSearchEngine::new();
        engine.set_max_matches(5);
        assert_eq!(engine.max_matches, 5);
    }
}
