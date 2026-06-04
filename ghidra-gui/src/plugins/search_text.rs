//! Search text plugin -- search program database and listing display
//! fields for a pattern.
//!
//! Ports `ghidra.app.plugin.core.searchtext`:
//! - [`SearchOptions`] (the full set of search flags)
//! - [`SearchDirection`] (forward / backward)
//! - [`SearchTask`] (incremental search with cursor)
//! - [`SearchTextPlugin`] (plugin state and actions)

use ghidra_core::addr::Address;
use regex::Regex;

// ---------------------------------------------------------------------------
// SearchDirection
// ---------------------------------------------------------------------------

/// Whether the search proceeds forward or backward through the address
/// space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SearchDirection {
    Forward,
    Backward,
}

// ---------------------------------------------------------------------------
// SearchOptions -- the full set of search parameters
// ---------------------------------------------------------------------------

/// Configuration for a text search across the program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchOptions {
    /// The text pattern to search for.
    text: String,
    /// Search function text (signatures, variables, repeatable comments).
    functions: bool,
    /// Search comment text (pre, post, eol, plate, repeatable).
    comments: bool,
    /// Search symbol labels.
    labels: bool,
    /// Search instruction mnemonics.
    instruction_mnemonics: bool,
    /// Search instruction operands.
    instruction_operands: bool,
    /// Search data mnemonics.
    data_mnemonics: bool,
    /// Search data operand values.
    data_operands: bool,
    /// Case-sensitive matching.
    case_sensitive: bool,
    /// Search direction.
    direction: SearchDirection,
    /// Search all fields (overrides individual field flags).
    search_all: bool,
    /// Include non-loaded memory blocks.
    include_non_loaded: bool,
    /// Use program-database search (fast) vs. listing-display match (slow).
    database_search: bool,
}

impl SearchOptions {
    /// Full constructor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        text: impl Into<String>,
        database_search: bool,
        functions: bool,
        comments: bool,
        labels: bool,
        instruction_mnemonics: bool,
        instruction_operands: bool,
        data_mnemonics: bool,
        data_operands: bool,
        case_sensitive: bool,
        direction: SearchDirection,
        include_non_loaded: bool,
        search_all: bool,
    ) -> Self {
        Self {
            text: text.into(),
            functions,
            comments,
            labels,
            instruction_mnemonics,
            instruction_operands,
            data_mnemonics,
            data_operands,
            case_sensitive,
            direction,
            search_all,
            include_non_loaded,
            database_search,
        }
    }

    /// Options for searching all fields with default settings.
    pub fn search_all(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            functions: false,
            comments: false,
            labels: false,
            instruction_mnemonics: false,
            instruction_operands: false,
            data_mnemonics: false,
            data_operands: false,
            case_sensitive: false,
            direction: SearchDirection::Forward,
            search_all: true,
            include_non_loaded: false,
            database_search: false,
        }
    }

    // -- Getters ----------------------------------------------------------

    /// The search text pattern.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Whether to search functions.
    pub fn search_functions(&self) -> bool {
        self.functions
    }

    /// Whether to search labels.
    pub fn search_labels(&self) -> bool {
        self.labels
    }

    /// Whether to search comments.
    pub fn search_comments(&self) -> bool {
        self.comments
    }

    /// Whether to search instruction mnemonics.
    pub fn search_instruction_mnemonics(&self) -> bool {
        self.instruction_mnemonics
    }

    /// Whether to search instruction operands.
    pub fn search_instruction_operands(&self) -> bool {
        self.instruction_operands
    }

    /// Whether to search instruction mnemonics AND operands.
    pub fn search_both_instruction_mnemonic_and_operands(&self) -> bool {
        self.instruction_mnemonics && self.instruction_operands
    }

    /// Whether to search only instruction mnemonics (not operands).
    pub fn search_only_instruction_mnemonics(&self) -> bool {
        self.instruction_mnemonics && !self.instruction_operands
    }

    /// Whether to search only instruction operands (not mnemonics).
    pub fn search_only_instruction_operands(&self) -> bool {
        self.instruction_operands && !self.instruction_mnemonics
    }

    /// Whether to search data mnemonics.
    pub fn search_data_mnemonics(&self) -> bool {
        self.data_mnemonics
    }

    /// Whether to search data operands.
    pub fn search_data_operands(&self) -> bool {
        self.data_operands
    }

    /// Whether to search data mnemonics AND operands.
    pub fn search_both_data_mnemonics_and_operands(&self) -> bool {
        self.data_mnemonics && self.data_operands
    }

    /// Whether to search only data mnemonics.
    pub fn search_only_data_mnemonics(&self) -> bool {
        self.data_mnemonics && !self.data_operands
    }

    /// Whether to search only data operands.
    pub fn search_only_data_operands(&self) -> bool {
        self.data_operands && !self.data_mnemonics
    }

    /// Whether the search is case-sensitive.
    pub fn is_case_sensitive(&self) -> bool {
        self.case_sensitive
    }

    /// Whether the search direction is forward.
    pub fn is_forward(&self) -> bool {
        self.direction == SearchDirection::Forward
    }

    /// Whether to search all fields (ignoring individual flags).
    pub fn search_all_fields(&self) -> bool {
        self.search_all
    }

    /// Whether to include non-loaded memory blocks.
    pub fn include_non_loaded_memory_blocks(&self) -> bool {
        self.include_non_loaded
    }

    /// Whether to use the fast program-database search.
    pub fn is_program_database_search(&self) -> bool {
        self.database_search
    }
}

// ---------------------------------------------------------------------------
// TextSearchResult -- a single hit
// ---------------------------------------------------------------------------

/// A single search result: an address and the offset within the field
/// text where the match begins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextSearchResult {
    /// Address of the code unit containing the match.
    pub address: Address,
    /// Character offset within the rendered field text.
    pub char_offset: usize,
    /// The field name (e.g. "Mnemonic", "EOL Comment").
    pub field_name: String,
}

// ---------------------------------------------------------------------------
// SearchTask -- incremental search state
// ---------------------------------------------------------------------------

/// Tracks state for an incremental next/previous search.
pub struct SearchTask {
    options: SearchOptions,
    /// The starting address for the current search pass.
    cursor: u64,
    /// Total addressable range end (reserved for future bounded search).
    _range_end: u64,
    /// Whether the search has wrapped around.
    wrapped: bool,
    /// Number of addresses searched so far.
    addresses_searched: u64,
    /// Whether the search is complete (found or exhausted).
    done: bool,
    /// The last result, if any.
    result: Option<TextSearchResult>,
    /// Compiled regex (cached).
    regex: Option<Regex>,
}

impl SearchTask {
    /// Create a new search task.
    ///
    /// `cursor` is the starting address offset and `range_end` is the
    /// upper bound of the search range.
    pub fn new(options: SearchOptions, cursor: u64, range_end: u64) -> Self {
        let regex = compile_regex(&options);
        Self {
            options,
            cursor,
            _range_end: range_end,
            wrapped: false,
            addresses_searched: 0,
            done: false,
            result: None,
            regex,
        }
    }

    /// Run the search against a slice of `(address_offset, field_text)`
    /// entries.
    ///
    /// Returns the first match found (in address order) after the
    /// current cursor, or `None` if nothing matched.
    pub fn search_in_data(&mut self, data: &[(u64, String, String)]) -> Option<TextSearchResult> {
        let re = self.regex.as_ref()?;

        // Sort by address for deterministic iteration
        let mut sorted: Vec<_> = data.iter().collect();
        sorted.sort_by_key(|(addr, _, _)| *addr);

        let start_idx = sorted
            .iter()
            .position(|(addr, _, _)| *addr >= self.cursor)
            .unwrap_or(0);

        // Search forward from cursor
        for (addr, field_name, text) in sorted.iter().skip(start_idx) {
            if let Some(offset) = find_match(re, text, self.options.is_case_sensitive()) {
                self.result = Some(TextSearchResult {
                    address: Address::new(*addr),
                    char_offset: offset,
                    field_name: field_name.clone(),
                });
                self.cursor = *addr + 1;
                self.addresses_searched += 1;
                return self.result.clone();
            }
            self.addresses_searched += 1;
        }

        // Wrap around (search from beginning to cursor)
        if !self.wrapped {
            self.wrapped = true;
            for (addr, field_name, text) in sorted.iter().take(start_idx) {
                if let Some(offset) = find_match(re, text, self.options.is_case_sensitive()) {
                    self.result = Some(TextSearchResult {
                        address: Address::new(*addr),
                        char_offset: offset,
                        field_name: field_name.clone(),
                    });
                    self.cursor = *addr + 1;
                    self.addresses_searched += 1;
                    return self.result.clone();
                }
                self.addresses_searched += 1;
            }
        }

        self.done = true;
        None
    }

    /// Whether the search has finished (no more data to check).
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// The search options used by this task.
    pub fn options(&self) -> &SearchOptions {
        &self.options
    }

    /// The last result found.
    pub fn result(&self) -> Option<&TextSearchResult> {
        self.result.as_ref()
    }

    /// Number of addresses examined so far.
    pub fn addresses_searched(&self) -> u64 {
        self.addresses_searched
    }
}

/// Compile the search text into a regex (respecting case-sensitivity).
fn compile_regex(options: &SearchOptions) -> Option<Regex> {
    let text = options.text();
    if text.is_empty() {
        return None;
    }
    let escaped = regex::escape(text);
    let pattern = if options.is_case_sensitive() {
        format!("(?{})", escaped)
    } else {
        format!("(?i){}", escaped)
    };
    Regex::new(&pattern).ok()
}

/// Find the first match in `text` and return the starting character
/// offset, or `None`.
fn find_match(re: &Regex, text: &str, _case_sensitive: bool) -> Option<usize> {
    re.find(text).map(|m| m.start())
}

// ---------------------------------------------------------------------------
// SearchTextPlugin -- top-level plugin state
// ---------------------------------------------------------------------------

/// The text search plugin, managing dialog state and results.
pub struct SearchTextPlugin {
    /// The last text that was searched for.
    last_searched_text: Option<String>,
    /// Whether the user has performed at least one search.
    searched_once: bool,
    /// Search result limit.
    search_limit: usize,
    /// Whether to highlight results in the listing.
    do_highlight: bool,
}

impl SearchTextPlugin {
    /// Create a new plugin with default settings.
    pub fn new() -> Self {
        Self {
            last_searched_text: None,
            searched_once: false,
            search_limit: 1000,
            do_highlight: true,
        }
    }

    /// Get the last searched text.
    pub fn last_searched_text(&self) -> Option<&str> {
        self.last_searched_text.as_deref()
    }

    /// Whether at least one search has been performed.
    pub fn searched_once(&self) -> bool {
        self.searched_once
    }

    /// Get the search result limit.
    pub fn search_limit(&self) -> usize {
        self.search_limit
    }

    /// Set the search result limit.
    pub fn set_search_limit(&mut self, limit: usize) {
        self.search_limit = limit;
    }

    /// Whether search result highlighting is enabled.
    pub fn do_highlight(&self) -> bool {
        self.do_highlight
    }

    /// Enable or disable search result highlighting.
    pub fn set_do_highlight(&mut self, highlight: bool) {
        self.do_highlight = highlight;
    }

    /// Record that a search was performed.
    pub fn mark_searched(&mut self, text: &str) {
        self.last_searched_text = Some(text.to_owned());
        self.searched_once = true;
    }

    /// Run a "search all" against program data and return all matches
    /// up to the result limit.
    pub fn search_all(
        &self,
        options: &SearchOptions,
        data: &[(u64, String, String)],
    ) -> Vec<TextSearchResult> {
        let re = match compile_regex(options) {
            Some(r) => r,
            None => return Vec::new(),
        };

        let mut results = Vec::new();
        for (addr, field_name, text) in data {
            if results.len() >= self.search_limit {
                break;
            }
            if let Some(offset) = find_match(&re, text, options.is_case_sensitive()) {
                results.push(TextSearchResult {
                    address: Address::new(*addr),
                    char_offset: offset,
                    field_name: field_name.clone(),
                });
            }
        }
        results
    }
}

impl Default for SearchTextPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_opts(text: &str) -> SearchOptions {
        SearchOptions::search_all(text)
    }

    // -- SearchOptions tests ------------------------------------------------

    #[test]
    fn options_search_all() {
        let opts = SearchOptions::search_all("test");
        assert_eq!(opts.text(), "test");
        assert!(opts.search_all_fields());
        assert!(opts.is_forward());
        assert!(!opts.is_case_sensitive());
    }

    #[test]
    fn options_construction() {
        let opts = SearchOptions::new(
            "mov", true, false, false, false, true, true, false, false, true,
            SearchDirection::Backward, false, false,
        );
        assert_eq!(opts.text(), "mov");
        assert!(opts.is_program_database_search());
        assert!(opts.search_both_instruction_mnemonic_and_operands());
        assert!(!opts.search_only_instruction_mnemonics());
        assert!(opts.is_case_sensitive());
        assert!(!opts.is_forward());
    }

    #[test]
    fn options_only_mnemonics() {
        let opts = SearchOptions::new(
            "x", false, false, false, false, true, false, false, false, false,
            SearchDirection::Forward, false, false,
        );
        assert!(opts.search_only_instruction_mnemonics());
        assert!(!opts.search_only_instruction_operands());
    }

    #[test]
    fn options_data_fields() {
        let opts = SearchOptions::new(
            "x", false, false, false, false, false, false, true, true, false,
            SearchDirection::Forward, false, false,
        );
        assert!(opts.search_both_data_mnemonics_and_operands());
    }

    // -- SearchTask tests ---------------------------------------------------

    #[test]
    fn task_finds_match() {
        let opts = default_opts("hello");
        let data = vec![
            (0x100, "Mnemonic".to_string(), "mov eax, ebx".to_string()),
            (0x200, "EOL".to_string(), "say hello world".to_string()),
            (0x300, "Label".to_string(), "main".to_string()),
        ];
        let mut task = SearchTask::new(opts, 0x0, 0x400);
        let result = task.search_in_data(&data);
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.address, Address::new(0x200));
        assert_eq!(r.char_offset, 4);
    }

    #[test]
    fn task_respects_cursor() {
        let opts = default_opts("hello");
        let data = vec![
            (0x100, "EOL".to_string(), "hello there".to_string()),
            (0x200, "EOL".to_string(), "say hello".to_string()),
        ];
        let mut task = SearchTask::new(opts, 0x150, 0x300);
        let result = task.search_in_data(&data);
        assert!(result.is_some());
        assert_eq!(result.unwrap().address, Address::new(0x200));
    }

    #[test]
    fn task_wraps_around() {
        let opts = default_opts("needle");
        let data = vec![
            (0x100, "EOL".to_string(), "the needle is here".to_string()),
            (0x200, "EOL".to_string(), "no match".to_string()),
        ];
        let mut task = SearchTask::new(opts, 0x150, 0x300);
        // First pass misses 0x100 (cursor > 0x100)
        let result = task.search_in_data(&data);
        // Should wrap and find it
        assert!(result.is_some());
        assert_eq!(result.unwrap().address, Address::new(0x100));
    }

    #[test]
    fn task_no_match() {
        let opts = default_opts("nonexistent");
        let data = vec![
            (0x100, "EOL".to_string(), "hello".to_string()),
        ];
        let mut task = SearchTask::new(opts, 0x0, 0x200);
        let result = task.search_in_data(&data);
        assert!(result.is_none());
        assert!(task.is_done());
    }

    #[test]
    fn task_case_insensitive() {
        let opts = SearchOptions::search_all("HeLLo");
        let data = vec![
            (0x100, "EOL".to_string(), "say HELLO world".to_string()),
        ];
        let mut task = SearchTask::new(opts, 0x0, 0x200);
        let result = task.search_in_data(&data);
        assert!(result.is_some());
    }

    #[test]
    fn task_case_sensitive() {
        let opts = SearchOptions::new(
            "HeLLo", false, false, false, false, false, false, false, false, true,
            SearchDirection::Forward, false, true,
        );
        let data = vec![
            (0x100, "EOL".to_string(), "say hello world".to_string()),
        ];
        let mut task = SearchTask::new(opts, 0x0, 0x200);
        let result = task.search_in_data(&data);
        assert!(result.is_none());
    }

    #[test]
    fn task_empty_text_returns_none() {
        let opts = default_opts("");
        let data = vec![(0x100, "EOL".to_string(), "hello".to_string())];
        let mut task = SearchTask::new(opts, 0x0, 0x200);
        let result = task.search_in_data(&data);
        assert!(result.is_none());
    }

    // -- SearchTextPlugin tests ---------------------------------------------

    #[test]
    fn plugin_defaults() {
        let plugin = SearchTextPlugin::new();
        assert!(!plugin.searched_once());
        assert!(plugin.last_searched_text().is_none());
        assert_eq!(plugin.search_limit(), 1000);
        assert!(plugin.do_highlight());
    }

    #[test]
    fn plugin_mark_searched() {
        let mut plugin = SearchTextPlugin::new();
        plugin.mark_searched("mov");
        assert!(plugin.searched_once());
        assert_eq!(plugin.last_searched_text(), Some("mov"));
    }

    #[test]
    fn plugin_set_limit() {
        let mut plugin = SearchTextPlugin::new();
        plugin.set_search_limit(500);
        assert_eq!(plugin.search_limit(), 500);
    }

    #[test]
    fn plugin_toggle_highlight() {
        let mut plugin = SearchTextPlugin::new();
        plugin.set_do_highlight(false);
        assert!(!plugin.do_highlight());
    }

    #[test]
    fn plugin_search_all_returns_matches() {
        let plugin = SearchTextPlugin::new();
        let opts = default_opts("mov");
        let data = vec![
            (0x100, "Mnemonic".to_string(), "mov eax, 1".to_string()),
            (0x200, "Mnemonic".to_string(), "xor eax, eax".to_string()),
            (0x300, "Mnemonic".to_string(), "mov ebx, 2".to_string()),
        ];
        let results = plugin.search_all(&opts, &data);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].address, Address::new(0x100));
        assert_eq!(results[1].address, Address::new(0x300));
    }

    #[test]
    fn plugin_search_all_respects_limit() {
        let mut plugin = SearchTextPlugin::new();
        plugin.set_search_limit(1);
        let opts = default_opts("mov");
        let data = vec![
            (0x100, "M".to_string(), "mov a".to_string()),
            (0x200, "M".to_string(), "mov b".to_string()),
        ];
        let results = plugin.search_all(&opts, &data);
        assert_eq!(results.len(), 1);
    }
}
