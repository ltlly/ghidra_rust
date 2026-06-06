//! `SearchData` -- metadata associated with a search match.
//!
//! Ported from `ghidra.features.base.memsearch.matcher.SearchData`.

use std::hash::{Hash, Hasher};

use crate::memsearch::gui::SearchSettings;

/// Metadata attached to each search match, recording the name, user input,
/// and settings that produced the match.
#[derive(Debug, Clone)]
pub struct SearchData {
    name: String,
    input: String,
    settings: SearchSettings,
}

impl SearchData {
    /// Create new search data.
    pub fn new(name: &str, input: &str, settings: SearchSettings) -> Self {
        Self {
            name: name.to_string(),
            input: input.to_string(),
            settings,
        }
    }

    /// Get the matcher name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the user input that produced this search.
    pub fn input(&self) -> &str {
        &self.input
    }

    /// Get the search settings used.
    pub fn settings(&self) -> &SearchSettings {
        &self.settings
    }
}

impl PartialEq for SearchData {
    fn eq(&self, other: &Self) -> bool {
        self.input == other.input && self.settings == other.settings
    }
}

impl Eq for SearchData {}

impl Hash for SearchData {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.input.hash(state);
        self.settings.hash(state);
    }
}

impl std::fmt::Display for SearchData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.input)
    }
}
