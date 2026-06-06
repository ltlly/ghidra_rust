//! Search-and-replace framework for Ghidra program elements.
//!
//! Ported from `ghidra.features.base.replace`.
//!
//! Provides [`SearchAndReplaceQuery`] for executing pattern-based search/replace
//! operations across multiple program element types (symbols, comments, data types,
//! memory blocks, program tree groups). Each element type is handled by a
//! [`SearchAndReplaceHandler`], and each match produces a [`QuickFix`] item.

use regex::{Regex, RegexBuilder};
use std::collections::HashSet;
use std::fmt;

use crate::quickfix::{QuickFix, QuickFixItem, QuickFixStatus};

// ---------------------------------------------------------------------------
// SearchType
// ---------------------------------------------------------------------------

/// A program element type that can be included/excluded in a search-and-replace
/// operation. Each type has a name, description, and an associated handler.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SearchType {
    /// Display name of the search type.
    name: String,
    /// Tooltip description of this type.
    description: String,
    /// Name of the handler that processes this type.
    handler_name: String,
}

impl SearchType {
    /// Create a new search type.
    pub fn new(
        handler_name: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            handler_name: handler_name.into(),
            name: name.into(),
            description: description.into(),
        }
    }

    /// Return the name of this search type.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Return the handler name.
    pub fn handler_name(&self) -> &str {
        &self.handler_name
    }
}

impl PartialOrd for SearchType {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SearchType {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.name.cmp(&other.name)
    }
}

impl fmt::Display for SearchType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

// ---------------------------------------------------------------------------
// Standard search types
// ---------------------------------------------------------------------------

impl SearchType {
    /// Symbols (labels, function names, etc.).
    pub fn symbols() -> Self {
        Self::new("symbols", "Symbols", "Search symbol/label names")
    }

    /// Listing comments (pre, post, plate, end-of-line, repeatable).
    pub fn comments() -> Self {
        Self::new("comments", "Listing Comments", "Search listing comments")
    }

    /// Data type names.
    pub fn data_types() -> Self {
        Self::new("datatypes", "Data Types", "Search data type names")
    }

    /// Data type field names.
    pub fn data_type_fields() -> Self {
        Self::new("datatypes", "Data Type Fields", "Search data type field names")
    }

    /// Data type category names.
    pub fn data_type_categories() -> Self {
        Self::new("datatypes", "Data Type Categories", "Search data type category names")
    }

    /// Memory block names.
    pub fn memory_blocks() -> Self {
        Self::new("memory_blocks", "Memory Blocks", "Search memory block names")
    }

    /// Program tree group names.
    pub fn program_tree_groups() -> Self {
        Self::new(
            "program_tree",
            "Program Tree Groups",
            "Search program tree group names",
        )
    }

    /// Enum value names.
    pub fn enum_values() -> Self {
        Self::new("datatypes", "Enum Values", "Search enum value names")
    }

    /// Data type descriptions.
    pub fn data_type_descriptions() -> Self {
        Self::new(
            "datatypes",
            "Data Type Descriptions",
            "Search data type descriptions",
        )
    }

    /// Field comments in data types.
    pub fn field_comments() -> Self {
        Self::new("datatypes", "Field Comments", "Search data type field comments")
    }

    /// Enum comments.
    pub fn enum_comments() -> Self {
        Self::new("datatypes", "Enum Comments", "Search enum comments")
    }

    /// Get the set of all built-in search types.
    pub fn all_builtin_types() -> HashSet<SearchType> {
        let mut types = HashSet::new();
        types.insert(Self::symbols());
        types.insert(Self::comments());
        types.insert(Self::data_types());
        types.insert(Self::data_type_fields());
        types.insert(Self::data_type_categories());
        types.insert(Self::memory_blocks());
        types.insert(Self::program_tree_groups());
        types.insert(Self::enum_values());
        types.insert(Self::data_type_descriptions());
        types.insert(Self::field_comments());
        types.insert(Self::enum_comments());
        types
    }
}

// ---------------------------------------------------------------------------
// SearchAndReplaceHandler
// ---------------------------------------------------------------------------

/// Trait for discoverable search-and-replace handlers.
///
/// Each handler is responsible for searching one or more specific program element
/// types for a given search pattern and generating appropriate fix items.
pub trait SearchAndReplaceHandler: Send + Sync {
    /// Return the set of [`SearchType`]s this handler supports.
    fn search_and_replace_types(&self) -> HashSet<SearchType>;

    /// Search the program for the pattern specified in `query` and produce fix items.
    fn find_all(&self, query: &SearchAndReplaceQuery) -> Result<Vec<QuickFixItem>, String>;
}

// ---------------------------------------------------------------------------
// SearchAndReplaceQuery
// ---------------------------------------------------------------------------

/// Immutable query object holding all parameters for a search-and-replace operation.
#[derive(Debug, Clone)]
pub struct SearchAndReplaceQuery {
    search_text: String,
    replacement_text: String,
    pattern: Regex,
    search_limit: usize,
    selected_types: HashSet<SearchType>,
    is_regex: bool,
    is_case_sensitive: bool,
    is_whole_word: bool,
}

impl SearchAndReplaceQuery {
    /// Create a new query.
    ///
    /// # Arguments
    ///
    /// * `search_text` - The user-entered search pattern text.
    /// * `replacement_text` - The replacement text.
    /// * `search_types` - The types of program elements to search.
    /// * `is_regex` - If true, interpret `search_text` as a regex.
    /// * `is_case_sensitive` - If true, the search is case sensitive.
    /// * `is_whole_word` - If true, match whole words only.
    /// * `search_limit` - Maximum number of results before stopping.
    ///
    /// # Errors
    ///
    /// Returns an error if the regex pattern is invalid.
    pub fn new(
        search_text: &str,
        replacement_text: &str,
        search_types: HashSet<SearchType>,
        is_regex: bool,
        is_case_sensitive: bool,
        is_whole_word: bool,
        search_limit: usize,
    ) -> Result<Self, String> {
        let pattern = Self::create_pattern(search_text, is_regex, is_case_sensitive, is_whole_word)?;
        Ok(Self {
            search_text: search_text.to_string(),
            replacement_text: replacement_text.to_string(),
            pattern,
            search_limit,
            selected_types: search_types,
            is_regex,
            is_case_sensitive,
            is_whole_word,
        })
    }

    /// The compiled search pattern.
    pub fn search_pattern(&self) -> &Regex {
        &self.pattern
    }

    /// The raw search text.
    pub fn search_text(&self) -> &str {
        &self.search_text
    }

    /// The replacement text.
    pub fn replacement_text(&self) -> &str {
        &self.replacement_text
    }

    /// Whether the given search type is included in this query.
    pub fn contains_search_type(&self, search_type: &SearchType) -> bool {
        self.selected_types.contains(search_type)
    }

    /// The set of all selected search types.
    pub fn selected_search_types(&self) -> &HashSet<SearchType> {
        &self.selected_types
    }

    /// Maximum number of results.
    pub fn search_limit(&self) -> usize {
        self.search_limit
    }

    /// Whether this is a regex query.
    pub fn is_regex(&self) -> bool {
        self.is_regex
    }

    /// Whether this is case-sensitive.
    pub fn is_case_sensitive(&self) -> bool {
        self.is_case_sensitive
    }

    /// Whether this is a whole-word query.
    pub fn is_whole_word(&self) -> bool {
        self.is_whole_word
    }

    /// Perform the search, collecting matches from all selected handler types.
    pub fn find_all(&self, handlers: &[Box<dyn SearchAndReplaceHandler>]) -> Vec<QuickFixItem> {
        let mut results = Vec::new();
        for handler in handlers {
            let handler_types = handler.search_and_replace_types();
            if self.selected_types.iter().any(|t| handler_types.contains(t)) {
                match handler.find_all(self) {
                    Ok(items) => results.extend(items),
                    Err(_) => { /* handler error -- skip */ }
                }
            }
        }
        results.truncate(self.search_limit);
        results
    }

    // -- private helpers --

    fn create_pattern(
        text: &str,
        is_regex: bool,
        case_sensitive: bool,
        whole_word: bool,
    ) -> Result<Regex, String> {
        let pattern_str = if is_regex {
            text.to_string()
        } else {
            let escaped = regex::escape(text);
            if whole_word {
                format!(r"\b{}\b", escaped)
            } else {
                escaped
            }
        };

        RegexBuilder::new(&pattern_str)
            .case_insensitive(!case_sensitive)
            .dot_matches_new_line(true)
            .build()
            .map_err(|e| format!("Invalid regex pattern: {e}"))
    }
}

// ---------------------------------------------------------------------------
// ListingCommentsHandler (concrete example handler)
// ---------------------------------------------------------------------------

/// A handler that searches listing comments for the pattern.
#[derive(Debug)]
pub struct ListingCommentsHandler;

impl SearchAndReplaceHandler for ListingCommentsHandler {
    fn search_and_replace_types(&self) -> HashSet<SearchType> {
        let mut types = HashSet::new();
        types.insert(SearchType::comments());
        types
    }

    fn find_all(&self, query: &SearchAndReplaceQuery) -> Result<Vec<QuickFixItem>, String> {
        // In a full implementation, this would iterate through all comments
        // in the program and match against the pattern.
        // This is a stub that returns empty results.
        let _ = query;
        Ok(Vec::new())
    }
}

/// A handler that searches symbol names.
#[derive(Debug)]
pub struct SymbolsHandler;

impl SearchAndReplaceHandler for SymbolsHandler {
    fn search_and_replace_types(&self) -> HashSet<SearchType> {
        let mut types = HashSet::new();
        types.insert(SearchType::symbols());
        types
    }

    fn find_all(&self, query: &SearchAndReplaceQuery) -> Result<Vec<QuickFixItem>, String> {
        let _ = query;
        Ok(Vec::new())
    }
}

/// A handler that searches data type names and fields.
#[derive(Debug)]
pub struct DataTypesHandler;

impl SearchAndReplaceHandler for DataTypesHandler {
    fn search_and_replace_types(&self) -> HashSet<SearchType> {
        let mut types = HashSet::new();
        types.insert(SearchType::data_types());
        types.insert(SearchType::data_type_fields());
        types.insert(SearchType::data_type_categories());
        types.insert(SearchType::enum_values());
        types.insert(SearchType::data_type_descriptions());
        types.insert(SearchType::field_comments());
        types.insert(SearchType::enum_comments());
        types
    }

    fn find_all(&self, query: &SearchAndReplaceQuery) -> Result<Vec<QuickFixItem>, String> {
        let _ = query;
        Ok(Vec::new())
    }
}

/// A handler that searches memory block names.
#[derive(Debug)]
pub struct MemoryBlockHandler;

impl SearchAndReplaceHandler for MemoryBlockHandler {
    fn search_and_replace_types(&self) -> HashSet<SearchType> {
        let mut types = HashSet::new();
        types.insert(SearchType::memory_blocks());
        types
    }

    fn find_all(&self, query: &SearchAndReplaceQuery) -> Result<Vec<QuickFixItem>, String> {
        let _ = query;
        Ok(Vec::new())
    }
}

/// A handler that searches program tree group names.
#[derive(Debug)]
pub struct ProgramTreeHandler;

impl SearchAndReplaceHandler for ProgramTreeHandler {
    fn search_and_replace_types(&self) -> HashSet<SearchType> {
        let mut types = HashSet::new();
        types.insert(SearchType::program_tree_groups());
        types
    }

    fn find_all(&self, query: &SearchAndReplaceQuery) -> Result<Vec<QuickFixItem>, String> {
        let _ = query;
        Ok(Vec::new())
    }
}

/// Create all built-in search-and-replace handlers.
pub fn create_builtin_handlers() -> Vec<Box<dyn SearchAndReplaceHandler>> {
    vec![
        Box::new(ListingCommentsHandler),
        Box::new(SymbolsHandler),
        Box::new(DataTypesHandler),
        Box::new(MemoryBlockHandler),
        Box::new(ProgramTreeHandler),
    ]
}

// ---------------------------------------------------------------------------
// RenameQuickFix
// ---------------------------------------------------------------------------

/// A quick-fix item for renaming a program element.
#[derive(Debug, Clone)]
pub struct RenameQuickFix {
    item: QuickFixItem,
}

impl RenameQuickFix {
    /// Create a new rename quick-fix.
    pub fn new(
        item_type: impl Into<String>,
        address: u64,
        path: impl Into<String>,
        old_name: impl Into<String>,
        new_name: impl Into<String>,
    ) -> Self {
        Self {
            item: QuickFixItem::new("Rename", item_type, old_name, new_name)
                .with_address(address)
                .with_path(path),
        }
    }
}

impl QuickFix for RenameQuickFix {
    fn action_name(&self) -> &str {
        "Rename"
    }
    fn item_type(&self) -> &str {
        self.item.item_type()
    }
    fn address(&self) -> Option<u64> {
        self.item.address()
    }
    fn path(&self) -> Option<&str> {
        self.item.path()
    }
    fn original(&self) -> &str {
        self.item.original()
    }
    fn current(&self) -> &str {
        self.item.current()
    }
    fn preview(&self) -> &str {
        self.item.preview()
    }
    fn status(&self) -> QuickFixStatus {
        self.item.status()
    }
    fn execute(&mut self) {
        self.item.execute();
    }
}

// ---------------------------------------------------------------------------
// UpdateCommentQuickFix
// ---------------------------------------------------------------------------

/// A quick-fix item for updating a listing comment.
#[derive(Debug, Clone)]
pub struct UpdateCommentQuickFix {
    item: QuickFixItem,
}

impl UpdateCommentQuickFix {
    /// Create a new comment-update quick-fix.
    pub fn new(
        address: u64,
        comment_type: impl Into<String>,
        old_comment: impl Into<String>,
        new_comment: impl Into<String>,
    ) -> Self {
        Self {
            item: QuickFixItem::new("Update Comment", comment_type, old_comment, new_comment)
                .with_address(address),
        }
    }
}

impl QuickFix for UpdateCommentQuickFix {
    fn action_name(&self) -> &str {
        "Update Comment"
    }
    fn item_type(&self) -> &str {
        self.item.item_type()
    }
    fn address(&self) -> Option<u64> {
        self.item.address()
    }
    fn original(&self) -> &str {
        self.item.original()
    }
    fn current(&self) -> &str {
        self.item.current()
    }
    fn preview(&self) -> &str {
        self.item.preview()
    }
    fn status(&self) -> QuickFixStatus {
        self.item.status()
    }
    fn execute(&mut self) {
        self.item.execute();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_type_ordering() {
        let a = SearchType::symbols();
        let b = SearchType::comments();
        assert!(b < a); // "Comments" < "Symbols"
    }

    #[test]
    fn test_all_builtin_types() {
        let types = SearchType::all_builtin_types();
        assert!(types.len() >= 11);
        assert!(types.contains(&SearchType::symbols()));
        assert!(types.contains(&SearchType::comments()));
        assert!(types.contains(&SearchType::memory_blocks()));
    }

    #[test]
    fn test_query_creation_simple() {
        let types = HashSet::from([SearchType::symbols()]);
        let query = SearchAndReplaceQuery::new("foo", "bar", types, false, true, false, 1000)
            .unwrap();
        assert_eq!(query.search_text(), "foo");
        assert_eq!(query.replacement_text(), "bar");
        assert!(query.contains_search_type(&SearchType::symbols()));
        assert!(!query.contains_search_type(&SearchType::comments()));
    }

    #[test]
    fn test_query_creation_regex() {
        let types = HashSet::from([SearchType::symbols()]);
        let query =
            SearchAndReplaceQuery::new(r"func_\d+", "func_X", types, true, false, false, 500)
                .unwrap();
        assert!(query.is_regex());
        assert!(query.search_pattern().is_match("func_42"));
    }

    #[test]
    fn test_query_creation_whole_word() {
        let types = HashSet::from([SearchType::symbols()]);
        let query = SearchAndReplaceQuery::new("foo", "bar", types, false, true, true, 1000)
            .unwrap();
        assert!(query.is_whole_word());
        // Whole word: should not match "foobar"
        assert!(!query.search_pattern().is_match("foobar"));
        // Should match "foo" standalone
        assert!(query.search_pattern().is_match("foo"));
    }

    #[test]
    fn test_query_case_insensitive() {
        let types = HashSet::from([SearchType::comments()]);
        let query = SearchAndReplaceQuery::new("hello", "world", types, false, false, false, 1000)
            .unwrap();
        assert!(!query.is_case_sensitive());
        assert!(query.search_pattern().is_match("HELLO"));
    }

    #[test]
    fn test_query_invalid_regex() {
        let types = HashSet::from([SearchType::symbols()]);
        let result = SearchAndReplaceQuery::new("[invalid", "x", types, true, false, false, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_query_limit() {
        let types = HashSet::from([SearchType::symbols()]);
        let query = SearchAndReplaceQuery::new("x", "y", types, false, false, false, 5).unwrap();
        assert_eq!(query.search_limit(), 5);
    }

    #[test]
    fn test_handlers_return_types() {
        let sym_handler = SymbolsHandler;
        let types = sym_handler.search_and_replace_types();
        assert!(types.contains(&SearchType::symbols()));

        let dt_handler = DataTypesHandler;
        let dt_types = dt_handler.search_and_replace_types();
        assert!(dt_types.contains(&SearchType::data_types()));
        assert!(dt_types.contains(&SearchType::data_type_fields()));
        assert!(dt_types.contains(&SearchType::enum_values()));
    }

    #[test]
    fn test_rename_quickfix() {
        let mut fix = RenameQuickFix::new("Symbol", 0x1000, "main/old", "old", "new");
        assert_eq!(fix.action_name(), "Rename");
        assert_eq!(fix.original(), "old");
        assert_eq!(fix.preview(), "new");
        assert_eq!(fix.status(), QuickFixStatus::None);
        fix.execute();
        assert_eq!(fix.status(), QuickFixStatus::Done);
    }

    #[test]
    fn test_update_comment_quickfix() {
        let mut fix = UpdateCommentQuickFix::new(0x2000, "EOL", "old comment", "new comment");
        assert_eq!(fix.action_name(), "Update Comment");
        fix.execute();
        assert_eq!(fix.status(), QuickFixStatus::Done);
    }

    #[test]
    fn test_builtin_handlers() {
        let handlers = create_builtin_handlers();
        assert_eq!(handlers.len(), 5);
    }
}
