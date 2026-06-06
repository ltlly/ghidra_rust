//! `SearchHistory` -- manages previously used searches.
//!
//! Ported from `ghidra.features.base.memsearch.gui.SearchHistory`.

use crate::memsearch::matcher::UserInputByteMatcher;

/// Manages memory search history.
///
/// Maintains a list of previously used `ByteMatcher`s for memory searching.
/// Each matcher records the input search text and the settings used.
///
/// Ported from `SearchHistory.java`.
#[derive(Debug, Clone)]
pub struct SearchHistory {
    history: Vec<UserInputByteMatcher>,
    max_history: usize,
}

impl SearchHistory {
    /// Create a new search history with the given max size.
    pub fn new(max_history: usize) -> Self {
        Self {
            history: Vec::new(),
            max_history: max_history.max(1),
        }
    }

    /// Add a search to the history.
    ///
    /// If a similar matcher already exists (same format and input),
    /// it is removed first.
    pub fn add_search(&mut self, matcher: UserInputByteMatcher) {
        // Remove similar matchers
        let input = matcher.input().to_string();
        self.history.retain(|m| m.input() != input);

        // Add to front
        self.history.insert(0, matcher);

        // Truncate if needed
        if self.history.len() > self.max_history {
            self.history.truncate(self.max_history);
        }
    }

    /// Get the list of historical matchers.
    pub fn entries(&self) -> &[UserInputByteMatcher] {
        &self.history
    }

    /// Get the most recent search, if any.
    pub fn most_recent(&self) -> Option<&UserInputByteMatcher> {
        self.history.first()
    }

    /// Get the number of entries in the history.
    pub fn len(&self) -> usize {
        self.history.len()
    }

    /// Returns true if the history is empty.
    pub fn is_empty(&self) -> bool {
        self.history.is_empty()
    }

    /// Clear the history.
    pub fn clear(&mut self) {
        self.history.clear();
    }

    /// Get the maximum number of entries.
    pub fn max_history(&self) -> usize {
        self.max_history
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memsearch::gui::SearchSettings;

    fn make_matcher(input: &str) -> UserInputByteMatcher {
        UserInputByteMatcher::new("test", input, SearchSettings::default())
    }

    #[test]
    fn test_history_add() {
        let mut history = SearchHistory::new(10);
        history.add_search(make_matcher("55 89"));
        assert_eq!(history.len(), 1);
    }

    #[test]
    fn test_history_max() {
        let mut history = SearchHistory::new(2);
        history.add_search(make_matcher("11"));
        history.add_search(make_matcher("22"));
        history.add_search(make_matcher("33"));
        assert_eq!(history.len(), 2);
        assert_eq!(history.most_recent().unwrap().input(), "33");
    }

    #[test]
    fn test_history_dedup() {
        let mut history = SearchHistory::new(10);
        history.add_search(make_matcher("55 89"));
        history.add_search(make_matcher("55 89"));
        assert_eq!(history.len(), 1);
    }

    #[test]
    fn test_history_clear() {
        let mut history = SearchHistory::new(10);
        history.add_search(make_matcher("55"));
        history.clear();
        assert!(history.is_empty());
    }

    #[test]
    fn test_most_recent() {
        let mut history = SearchHistory::new(10);
        assert!(history.most_recent().is_none());
        history.add_search(make_matcher("first"));
        history.add_search(make_matcher("second"));
        assert_eq!(history.most_recent().unwrap().input(), "second");
    }
}
