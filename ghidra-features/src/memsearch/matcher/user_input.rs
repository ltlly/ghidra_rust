//! `UserInputByteMatcher` -- abstract base for matchers created from user input.
//!
//! Ported from `ghidra.features.base.memsearch.matcher.UserInputByteMatcher`.

use crate::memsearch::gui::SearchSettings;
use crate::memsearch::matcher::search_data::SearchData;
use crate::memsearch::matcher::ByteMatcher;

/// Abstract base class for matchers that are created from user input text.
///
/// Stores the [`SearchData`] (name, input text, settings) and provides
/// default implementations for common accessor methods.
#[derive(Debug, Clone)]
pub struct UserInputByteMatcher {
    search_data: SearchData,
    description: String,
    valid_search: bool,
    valid_input: bool,
    pattern_length: usize,
}

impl UserInputByteMatcher {
    /// Create a new user input byte matcher.
    pub fn new(name: &str, input: &str, settings: SearchSettings) -> Self {
        let search_data = SearchData::new(name, input, settings);
        Self {
            search_data,
            description: String::new(),
            valid_search: true,
            valid_input: true,
            pattern_length: 0,
        }
    }

    /// Set the description.
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    /// Set validity.
    pub fn with_validity(mut self, valid_search: bool, valid_input: bool) -> Self {
        self.valid_search = valid_search;
        self.valid_input = valid_input;
        self
    }

    /// Set the pattern length.
    pub fn with_pattern_length(mut self, len: usize) -> Self {
        self.pattern_length = len;
        self
    }

    /// Get the search data.
    pub fn search_data(&self) -> &SearchData {
        &self.search_data
    }

    /// Get the name of this matcher.
    pub fn name(&self) -> &str {
        self.search_data.name()
    }

    /// Get the user input text.
    pub fn input(&self) -> &str {
        self.search_data.input()
    }

    /// Get the search settings.
    pub fn settings(&self) -> &SearchSettings {
        self.search_data.settings()
    }

    /// Returns true if this matcher is valid and can perform a search.
    pub fn is_valid_search(&self) -> bool {
        self.valid_search
    }

    /// Returns true if this matcher has valid (but possibly incomplete) input text.
    pub fn is_valid_input(&self) -> bool {
        self.valid_input
    }

    /// Get the tool tip for this matcher.
    pub fn tooltip(&self) -> Option<&str> {
        None
    }
}

impl ByteMatcher for UserInputByteMatcher {
    fn match_bytes(&self, _bytes: &[u8], _base_offset: u64) -> Vec<crate::memsearch::matcher::Match> {
        Vec::new()
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn pattern_length(&self) -> usize {
        self.pattern_length
    }
}

impl std::fmt::Display for UserInputByteMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.search_data.input())
    }
}

impl PartialEq for UserInputByteMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.search_data == other.search_data
    }
}

impl Eq for UserInputByteMatcher {}

impl std::hash::Hash for UserInputByteMatcher {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.search_data.hash(state);
    }
}
