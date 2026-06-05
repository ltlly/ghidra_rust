//! Search type definitions and searcher trait -- ported from
//! `Searcher.java`, `SearchOptions.java`, and the
//! `databasesearcher` sub-package in
//! `ghidra.app.plugin.core.searchtext`.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// SearchOptions
// ---------------------------------------------------------------------------

/// Options controlling what and how to search in the program listing.
///
/// Ported from `ghidra.app.plugin.core.searchtext.SearchOptions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchOptions {
    /// Text to search for.
    pub search_text: String,
    /// Whether the search is case-sensitive.
    pub case_sensitive: bool,
    /// Whether to search using regular expressions.
    pub use_regex: bool,
    /// Whether to search instruction mnemonics.
    pub search_mnemonics: bool,
    /// Whether to search instruction operand values.
    pub search_operands: bool,
    /// Whether to search comments.
    pub search_comments: bool,
    /// Whether to search data values (bytes, strings, etc.).
    pub search_data_values: bool,
    /// Whether to search labels/symbol names.
    pub search_labels: bool,
    /// Whether to search in non-loaded (overlay) memory blocks.
    pub search_non_loaded: bool,
    /// Whether to search the program database (fast) or
    /// listing display (slower, matches rendered text).
    pub use_program_database: bool,
}

impl SearchOptions {
    /// Create default search options.
    pub fn new(search_text: impl Into<String>) -> Self {
        Self {
            search_text: search_text.into(),
            case_sensitive: true,
            use_regex: false,
            search_mnemonics: true,
            search_operands: true,
            search_comments: true,
            search_data_values: false,
            search_labels: true,
            search_non_loaded: false,
            use_program_database: true,
        }
    }

    /// Search all fields.
    pub fn search_all(search_text: impl Into<String>) -> Self {
        Self {
            search_text: search_text.into(),
            case_sensitive: false,
            use_regex: false,
            search_mnemonics: true,
            search_operands: true,
            search_comments: true,
            search_data_values: true,
            search_labels: true,
            search_non_loaded: true,
            use_program_database: true,
        }
    }
}

impl Default for SearchOptions {
    fn default() -> Self {
        Self::new("")
    }
}

// ---------------------------------------------------------------------------
// TextSearchResult -- a single search result
// ---------------------------------------------------------------------------

/// A single text search result.
///
/// Ported from `Searcher.TextSearchResult`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextSearchResult {
    /// The address where the match was found.
    pub address: u64,
    /// The matched text.
    pub matched_text: String,
    /// The field name where the match was found.
    pub field_name: String,
    /// The line number (in the listing display).
    pub line_number: Option<usize>,
    /// Character offset within the field.
    pub char_offset: usize,
    /// Length of the match.
    pub match_length: usize,
}

impl TextSearchResult {
    /// Create a new search result.
    pub fn new(
        address: u64,
        matched_text: impl Into<String>,
        field_name: impl Into<String>,
    ) -> Self {
        Self {
            address,
            matched_text: matched_text.into(),
            field_name: field_name.into(),
            line_number: None,
            char_offset: 0,
            match_length: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// SearchField -- which field to search
// ---------------------------------------------------------------------------

/// Fields that can be searched in the program.
///
/// Ported from `ProgramDatabaseFieldSearcher` field types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SearchField {
    /// Instruction mnemonic (e.g., "MOV", "CALL").
    InstructionMnemonic,
    /// Instruction operands (register names, constants).
    InstructionOperands,
    /// Data mnemonic (e.g., "db", "dw", "dd", "dq").
    DataMnemonic,
    /// Data operand values.
    DataOperands,
    /// Comments (pre, post, end-of-line, plate).
    Comments,
    /// Labels / symbol names.
    Labels,
    /// All fields.
    All,
}

impl SearchField {
    /// Display name for this field.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::InstructionMnemonic => "Instruction Mnemonics",
            Self::InstructionOperands => "Instruction Operands",
            Self::DataMnemonic => "Data Mnemonics",
            Self::DataOperands => "Data Values",
            Self::Comments => "Comments",
            Self::Labels => "Labels",
            Self::All => "All Fields",
        }
    }

    /// All searchable fields.
    pub fn all_fields() -> &'static [SearchField] {
        &[
            Self::InstructionMnemonic,
            Self::InstructionOperands,
            Self::DataMnemonic,
            Self::DataOperands,
            Self::Comments,
            Self::Labels,
        ]
    }
}

// ---------------------------------------------------------------------------
// SearchDirection
// ---------------------------------------------------------------------------

/// Direction to search from the current location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SearchDirection {
    /// Search forward (increasing addresses).
    Forward,
    /// Search backward (decreasing addresses).
    Backward,
    /// Search all addresses (both directions from current).
    All,
}

// ---------------------------------------------------------------------------
// SearchAddressIterator -- trait for iterating addresses to search
// ---------------------------------------------------------------------------

/// Trait for providing addresses to search.
///
/// Ported from `SearchAddressIterator` and its subclasses.
pub trait SearchAddressIterator: Send + Sync {
    /// Get the next address to search.
    fn next_address(&mut self) -> Option<u64>;

    /// Reset the iterator to the beginning.
    fn reset(&mut self);
}

// ---------------------------------------------------------------------------
// ListingDisplaySearcher -- search rendered listing text
// ---------------------------------------------------------------------------

/// Result from a listing-display search that matches rendered text.
///
/// Ported from `ListingDisplaySearcher`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListingDisplaySearchResult {
    /// The address of the match.
    pub address: u64,
    /// The rendered text that matched.
    pub rendered_text: String,
    /// Row in the field panel.
    pub row: usize,
    /// Column start in the field.
    pub col_start: usize,
    /// Column end in the field.
    pub col_end: usize,
    /// The field name.
    pub field_name: String,
}

impl ListingDisplaySearchResult {
    /// Create a new listing display search result.
    pub fn new(address: u64, rendered_text: impl Into<String>, field_name: impl Into<String>) -> Self {
        Self {
            address,
            rendered_text: rendered_text.into(),
            row: 0,
            col_start: 0,
            col_end: 0,
            field_name: field_name.into(),
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_options_default() {
        let opts = SearchOptions::default();
        assert!(opts.search_text.is_empty());
        assert!(opts.case_sensitive);
        assert!(!opts.use_regex);
    }

    #[test]
    fn test_search_options_new() {
        let opts = SearchOptions::new("main");
        assert_eq!(opts.search_text, "main");
        assert!(opts.search_mnemonics);
        assert!(opts.search_operands);
        assert!(opts.search_comments);
    }

    #[test]
    fn test_search_options_all() {
        let opts = SearchOptions::search_all("test");
        assert!(!opts.case_sensitive);
        assert!(opts.search_data_values);
        assert!(opts.search_non_loaded);
    }

    #[test]
    fn test_text_search_result() {
        let r = TextSearchResult::new(0x400000, "CALL main", "Mnemonic");
        assert_eq!(r.address, 0x400000);
        assert_eq!(r.matched_text, "CALL main");
        assert_eq!(r.field_name, "Mnemonic");
    }

    #[test]
    fn test_search_field_display() {
        assert_eq!(SearchField::InstructionMnemonic.display_name(), "Instruction Mnemonics");
        assert_eq!(SearchField::Comments.display_name(), "Comments");
        assert_eq!(SearchField::all_fields().len(), 6);
    }

    #[test]
    fn test_search_direction() {
        assert_ne!(SearchDirection::Forward, SearchDirection::Backward);
    }

    #[test]
    fn test_listing_display_search_result() {
        let r = ListingDisplaySearchResult::new(0x100, "MOV RAX", "Mnemonic");
        assert_eq!(r.address, 0x100);
        assert_eq!(r.rendered_text, "MOV RAX");
    }
}
