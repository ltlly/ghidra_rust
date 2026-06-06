//! Text search plugin -- ported from Ghidra's
//! `ghidra.app.plugin.core.searchtext` Java package.
//!
//! Searches program text as displayed in the listing fields, providing
//! both a "program database" search (fast, searches the DB) and a
//! "listing display" search (slower, searches rendered text).
//!
//! - [`SearchOptions`] -- parameters controlling what/where/how to search
//! - [`Searcher`] -- trait for search implementations
//! - [`SearchTask`] -- a cancellable search task
//! - [`SearchTextPlugin`] -- plugin-level search coordination
//! - [`databasesearcher`] -- program-database-backed search
//! - [`iterators`] -- address iterators for different field types

pub mod databasesearcher;
pub mod dialog;
pub mod iterators;
pub mod plugin;
pub mod search_types;
pub mod quick_searcher;

use ghidra_core::Address;

use crate::gotoquery::ProgramLocation;

// ---------------------------------------------------------------------------
// SearchOptions
// ---------------------------------------------------------------------------

/// Options controlling what and how to search in the program listing.
///
/// Mirrors Ghidra's `SearchOptions` class with the same field semantics.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SearchOptions {
    /// The text pattern to search for.
    text: String,
    /// Search function names/signatures/comments.
    functions: bool,
    /// Search comments (pre, post, plate, EOL).
    comments: bool,
    /// Search labels (symbol names).
    labels: bool,
    /// Search instruction mnemonics.
    instruction_mnemonics: bool,
    /// Search instruction operands.
    instruction_operands: bool,
    /// Search data mnemonics.
    data_mnemonics: bool,
    /// Search data values/operands.
    data_operands: bool,
    /// Whether the search is case-sensitive.
    case_sensitive: bool,
    /// `true` = forward, `false` = backward.
    direction_forward: bool,
    /// `true` = search all fields (overrides individual field flags).
    search_all: bool,
    /// Whether to include non-loaded memory blocks.
    include_non_loaded_blocks: bool,
    /// Whether to use the program-database search (fast) vs.
    /// listing-display match (slow).
    database_search: bool,
}

impl SearchOptions {
    /// Full constructor with all options.
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
        direction_forward: bool,
        include_non_loaded_blocks: bool,
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
            direction_forward,
            search_all,
            include_non_loaded_blocks,
            database_search,
        }
    }

    /// Create a "search all fields" option set.
    pub fn search_all(
        text: impl Into<String>,
        case_sensitive: bool,
        direction_forward: bool,
        include_non_loaded_blocks: bool,
    ) -> Self {
        Self::new(
            text,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            case_sensitive,
            direction_forward,
            include_non_loaded_blocks,
            true,
        )
    }

    // -- Accessors --

    /// The search text pattern.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Whether to search function text.
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

    /// Whether both instruction mnemonics and operands should be searched.
    pub fn search_both_instruction_mnemonic_and_operands(&self) -> bool {
        self.instruction_mnemonics && self.instruction_operands
    }

    /// Whether instruction mnemonics are selected.
    pub fn search_instruction_mnemonics(&self) -> bool {
        self.instruction_mnemonics
    }

    /// Whether instruction operands are selected.
    pub fn search_instruction_operands(&self) -> bool {
        self.instruction_operands
    }

    /// Whether only instruction mnemonics (not operands) are selected.
    pub fn search_only_instruction_mnemonics(&self) -> bool {
        self.instruction_mnemonics && !self.instruction_operands
    }

    /// Whether only instruction operands (not mnemonics) are selected.
    pub fn search_only_instruction_operands(&self) -> bool {
        self.instruction_operands && !self.instruction_mnemonics
    }

    /// Whether both data mnemonics and operands should be searched.
    pub fn search_both_data_mnemonics_and_operands(&self) -> bool {
        self.data_mnemonics && self.data_operands
    }

    /// Whether data mnemonics are selected.
    pub fn search_data_mnemonics(&self) -> bool {
        self.data_mnemonics
    }

    /// Whether data operands are selected.
    pub fn search_data_operands(&self) -> bool {
        self.data_operands
    }

    /// Whether only data mnemonics (not operands) are selected.
    pub fn search_only_data_mnemonics(&self) -> bool {
        self.data_mnemonics && !self.data_operands
    }

    /// Whether only data operands (not mnemonics) are selected.
    pub fn search_only_data_operands(&self) -> bool {
        self.data_operands && !self.data_mnemonics
    }

    /// Whether the search is case-sensitive.
    pub fn is_case_sensitive(&self) -> bool {
        self.case_sensitive
    }

    /// Whether the search direction is forward.
    pub fn is_forward(&self) -> bool {
        self.direction_forward
    }

    /// Whether all fields should be searched.
    pub fn search_all_fields(&self) -> bool {
        self.search_all
    }

    /// Whether to include non-loaded memory blocks.
    pub fn include_non_loaded_memory_blocks(&self) -> bool {
        self.include_non_loaded_blocks
    }

    /// Whether this is a program-database search (fast).
    pub fn is_program_database_search(&self) -> bool {
        self.database_search
    }
}

// ---------------------------------------------------------------------------
// TextSearchResult
// ---------------------------------------------------------------------------

/// A single search result: a program location plus the character offset
/// within the field's rendered text where the match was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextSearchResult {
    /// The program location of the match.
    location: ProgramLocation,
    /// Character offset in the model text.
    offset: usize,
}

impl TextSearchResult {
    /// Create a new search result.
    pub fn new(location: ProgramLocation, offset: usize) -> Self {
        Self { location, offset }
    }

    /// The program location.
    pub fn location(&self) -> &ProgramLocation {
        &self.location
    }

    /// The character offset within the field's text.
    pub fn offset(&self) -> usize {
        self.offset
    }
}

// ---------------------------------------------------------------------------
// Searcher trait
// ---------------------------------------------------------------------------

/// Trait for search implementations.
///
/// Implementors provide an iterator-like interface: call [`search`](Self::search)
/// repeatedly to get the next result until it returns `None`.
pub trait Searcher {
    /// Search for the next match.
    ///
    /// Returns `None` when there are no more matches or the search
    /// has been cancelled.
    fn search(&mut self) -> Option<TextSearchResult>;

    /// Get the search options used by this searcher.
    fn search_options(&self) -> &SearchOptions;
}

// ---------------------------------------------------------------------------
// SearchTask
// ---------------------------------------------------------------------------

/// A search that can be cancelled.
///
/// Wraps a [`Searcher`] and runs it, reporting results back via a channel.
#[derive(Debug)]
pub struct SearchTask {
    /// The navigatable id this search is operating on.
    navigatable_id: u64,
    /// The program name.
    program_name: String,
    /// Whether the task has been cancelled.
    cancelled: bool,
    /// The search options.
    options: SearchOptions,
    /// Accumulated results.
    results: Vec<TextSearchResult>,
}

impl SearchTask {
    /// Create a new search task.
    pub fn new(
        navigatable_id: u64,
        program_name: impl Into<String>,
        options: SearchOptions,
    ) -> Self {
        Self {
            navigatable_id,
            program_name: program_name.into(),
            cancelled: false,
            options,
            results: Vec::new(),
        }
    }

    /// Get the navigatable id.
    pub fn navigatable_id(&self) -> u64 {
        self.navigatable_id
    }

    /// Get the program name.
    pub fn program_name(&self) -> &str {
        &self.program_name
    }

    /// Cancel the search.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Whether the search has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    /// Get the search options.
    pub fn options(&self) -> &SearchOptions {
        &self.options
    }

    /// Add a result.
    pub fn add_result(&mut self, result: TextSearchResult) {
        self.results.push(result);
    }

    /// Get the results.
    pub fn results(&self) -> &[TextSearchResult] {
        &self.results
    }

    /// Get the first result, if any.
    pub fn first_result(&self) -> Option<&TextSearchResult> {
        self.results.first()
    }
}

// ---------------------------------------------------------------------------
// SearchTextPlugin
// ---------------------------------------------------------------------------

/// Plugin that coordinates text searches in the program listing.
///
/// Provides the "Search Text" and "Search All" operations, manages the
/// search dialog state, and dispatches results to the GoTo service.
pub struct SearchTextPlugin {
    /// Plugin name.
    name: String,
    /// Current navigatable id.
    navigatable_id: Option<u64>,
    /// Current program name.
    current_program: Option<String>,
    /// Current active search task.
    current_task: Option<SearchTask>,
    /// Last searched text.
    last_searched_text: Option<String>,
    /// Whether the user has searched at least once.
    searched_once: bool,
    /// Search result limit.
    search_limit: usize,
    /// Whether to highlight matches in the listing.
    do_highlight: bool,
    /// Whether we are waiting for a "Search All" to finish.
    waiting_for_search_all: bool,
    /// Pending events.
    events: Vec<String>,
}

impl SearchTextPlugin {
    /// Create a new search text plugin.
    pub fn new() -> Self {
        Self {
            name: "SearchTextPlugin".to_string(),
            navigatable_id: None,
            current_program: None,
            current_task: None,
            last_searched_text: None,
            searched_once: false,
            search_limit: 500,
            do_highlight: true,
            waiting_for_search_all: false,
            events: Vec::new(),
        }
    }

    /// Plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set the current navigatable.
    pub fn set_navigatable(&mut self, id: Option<u64>) {
        self.navigatable_id = id;
    }

    /// Set the current program.
    pub fn set_program(&mut self, program: Option<String>) {
        self.current_program = program;
    }

    /// Get the search limit.
    pub fn search_limit(&self) -> usize {
        self.search_limit
    }

    /// Set the search limit.
    pub fn set_search_limit(&mut self, limit: usize) {
        self.search_limit = limit;
    }

    /// Whether highlighting is enabled.
    pub fn do_highlight(&self) -> bool {
        self.do_highlight
    }

    /// Set whether to highlight matches.
    pub fn set_highlight(&mut self, highlight: bool) {
        self.do_highlight = highlight;
    }

    /// Get the last searched text.
    pub fn last_searched_text(&self) -> Option<&str> {
        self.last_searched_text.as_deref()
    }

    /// Whether the user has performed at least one search.
    pub fn searched_once(&self) -> bool {
        self.searched_once
    }

    /// Whether a search-all is in progress.
    pub fn is_waiting_for_search_all(&self) -> bool {
        self.waiting_for_search_all
    }

    /// Get the event log.
    pub fn events(&self) -> &[String] {
        &self.events
    }

    /// Start a "search next" operation.
    ///
    /// Creates a [`SearchTask`] from the given options and records it.
    pub fn start_search(&mut self, options: SearchOptions) -> bool {
        let nav_id = match self.navigatable_id {
            Some(id) => id,
            None => return false,
        };
        let prog = match self.current_program.clone() {
            Some(p) => p,
            None => return false,
        };

        let task = SearchTask::new(nav_id, prog, options.clone());
        self.current_task = Some(task);
        self.last_searched_text = Some(options.text().to_string());
        self.searched_once = true;
        self.events.push(format!("Search started: '{}'", options.text()));
        true
    }

    /// Start a "search all" operation.
    pub fn start_search_all(&mut self, options: SearchOptions) -> bool {
        self.waiting_for_search_all = true;
        self.last_searched_text = Some(options.text().to_string());
        self.searched_once = true;
        self.events.push(format!("SearchAll started: '{}'", options.text()));
        true
    }

    /// Notify that the search task completed.
    pub fn task_completed(&mut self, result: Option<TextSearchResult>) {
        if let Some(ref r) = result {
            self.events.push(format!("Search completed: found '{}'", r.location()));
        } else {
            self.events.push("Search completed: not found".to_string());
        }
        self.current_task = None;
    }

    /// Notify that the search task was cancelled.
    pub fn task_cancelled(&mut self) {
        self.events.push("Search cancelled".to_string());
        self.current_task = None;
    }

    /// Notify that search-all finished.
    pub fn search_all_finished(&mut self, match_count: usize) {
        self.waiting_for_search_all = false;
        self.events
            .push(format!("SearchAll finished: {} matches", match_count));
    }

    /// Whether we can close a domain object (not during active search).
    pub fn can_close_domain_object(&self) -> bool {
        self.current_task.is_none() && !self.waiting_for_search_all
    }
}

impl Default for SearchTextPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    fn make_options_all_fields(text: &str) -> SearchOptions {
        SearchOptions::search_all(text, false, true, false)
    }

    #[test]
    fn test_search_options_construction() {
        let opts = SearchOptions::new(
            "hello",
            true,  // database_search
            true,  // functions
            false, // comments
            true,  // labels
            false, // instruction_mnemonics
            false, // instruction_operands
            false, // data_mnemonics
            false, // data_operands
            false, // case_sensitive
            true,  // direction_forward
            false, // include_non_loaded_blocks
            false, // search_all
        );
        assert_eq!(opts.text(), "hello");
        assert!(opts.is_program_database_search());
        assert!(opts.search_functions());
        assert!(opts.search_labels());
        assert!(!opts.search_comments());
        assert!(!opts.is_case_sensitive());
        assert!(opts.is_forward());
    }

    #[test]
    fn test_search_options_search_all() {
        let opts = make_options_all_fields("test");
        assert!(opts.search_all_fields());
        assert_eq!(opts.text(), "test");
    }

    #[test]
    fn test_search_options_instruction_combined() {
        let opts = SearchOptions::new(
            "mov",
            true, true, false, false, true, true, false, false, true, true, false, false,
        );
        assert!(opts.search_both_instruction_mnemonic_and_operands());
        assert!(!opts.search_only_instruction_mnemonics());
        assert!(!opts.search_only_instruction_operands());
    }

    #[test]
    fn test_search_options_instruction_mnemonic_only() {
        let opts = SearchOptions::new(
            "mov",
            true, true, false, false, true, false, false, false, true, true, false, false,
        );
        assert!(!opts.search_both_instruction_mnemonic_and_operands());
        assert!(opts.search_only_instruction_mnemonics());
        assert!(!opts.search_only_instruction_operands());
    }

    #[test]
    fn test_search_options_data_combined() {
        let opts = SearchOptions::new(
            "0xFF",
            true, false, false, false, false, false, true, true, false, true, false, false,
        );
        assert!(opts.search_both_data_mnemonics_and_operands());
        assert!(!opts.search_only_data_mnemonics());
    }

    #[test]
    fn test_search_options_equality() {
        let a = make_options_all_fields("test");
        let b = make_options_all_fields("test");
        assert_eq!(a, b);

        let c = make_options_all_fields("TEST");
        assert_ne!(a, c);
    }

    #[test]
    fn test_text_search_result() {
        let addr = Address::new(0x401000);
        let loc = ProgramLocation::new("test.exe", addr);
        let result = TextSearchResult::new(loc.clone(), 42);
        assert_eq!(result.location(), &loc);
        assert_eq!(result.offset(), 42);
    }

    #[test]
    fn test_search_task_lifecycle() {
        let opts = make_options_all_fields("hello");
        let mut task = SearchTask::new(1, "test.exe", opts);
        assert_eq!(task.navigatable_id(), 1);
        assert_eq!(task.program_name(), "test.exe");
        assert!(!task.is_cancelled());
        assert!(task.results().is_empty());

        let addr = Address::new(0x401000);
        let loc = ProgramLocation::new("test.exe", addr);
        task.add_result(TextSearchResult::new(loc, 0));

        assert_eq!(task.results().len(), 1);
        assert!(task.first_result().is_some());

        task.cancel();
        assert!(task.is_cancelled());
    }

    #[test]
    fn test_search_text_plugin_basic() {
        let mut plugin = SearchTextPlugin::new();
        assert_eq!(plugin.name(), "SearchTextPlugin");
        assert_eq!(plugin.search_limit(), 500);
        assert!(plugin.do_highlight());
        assert!(!plugin.searched_once());
        assert!(plugin.can_close_domain_object());
    }

    #[test]
    fn test_search_text_plugin_start_search() {
        let mut plugin = SearchTextPlugin::new();
        plugin.set_program(Some("test.exe".into()));
        plugin.set_navigatable(Some(1));

        let opts = make_options_all_fields("hello");
        assert!(plugin.start_search(opts));
        assert!(plugin.searched_once());
        assert_eq!(plugin.last_searched_text(), Some("hello"));
        assert_eq!(plugin.events().len(), 1);
    }

    #[test]
    fn test_search_text_plugin_no_program() {
        let mut plugin = SearchTextPlugin::new();
        let opts = make_options_all_fields("hello");
        assert!(!plugin.start_search(opts));
    }

    #[test]
    fn test_search_text_plugin_search_all() {
        let mut plugin = SearchTextPlugin::new();
        plugin.set_program(Some("test.exe".into()));
        plugin.set_navigatable(Some(1));

        let opts = make_options_all_fields("test");
        assert!(plugin.start_search_all(opts));
        assert!(plugin.is_waiting_for_search_all());
        assert!(!plugin.can_close_domain_object());

        plugin.search_all_finished(42);
        assert!(!plugin.is_waiting_for_search_all());
        assert!(plugin.can_close_domain_object());
    }

    #[test]
    fn test_search_text_plugin_cancel() {
        let mut plugin = SearchTextPlugin::new();
        plugin.set_program(Some("test.exe".into()));
        plugin.set_navigatable(Some(1));

        let opts = make_options_all_fields("test");
        plugin.start_search(opts);
        assert!(!plugin.can_close_domain_object());

        plugin.task_cancelled();
        assert!(plugin.can_close_domain_object());
        assert!(plugin.events().last().unwrap().contains("cancelled"));
    }

    #[test]
    fn test_search_text_plugin_task_completed() {
        let mut plugin = SearchTextPlugin::new();
        plugin.set_program(Some("test.exe".into()));
        plugin.set_navigatable(Some(1));

        let opts = make_options_all_fields("test");
        plugin.start_search(opts);

        let addr = Address::new(0x401000);
        let loc = ProgramLocation::new("test.exe", addr);
        plugin.task_completed(Some(TextSearchResult::new(loc, 0)));
        assert!(plugin.can_close_domain_object());
    }

    // -- AbstractSearchTableModel tests --

    #[test]
    fn test_abstract_search_table_model() {
        let mut model = AbstractSearchTableModel::new("Search Results");
        assert_eq!(model.name(), "Search Results");
        assert_eq!(model.row_count(), 0);

        model.add_result(SearchResultRow::new(
            Address::new(0x1000),
            "MOV EAX, 1",
            "Operand",
            0,
        ));
        model.add_result(SearchResultRow::new(
            Address::new(0x2000),
            "CALL printf",
            "Mnemonic",
            1,
        ));
        assert_eq!(model.row_count(), 2);
    }

    #[test]
    fn test_abstract_search_table_model_cell_values() {
        let mut model = AbstractSearchTableModel::new("Test");
        model.add_result(SearchResultRow::new(
            Address::new(0x401000),
            "int x = 42",
            "DataType",
            0,
        ));
        assert_eq!(model.cell_value(0, 0).as_deref(), Some("0x401000"));
        assert_eq!(model.cell_value(0, 1).as_deref(), Some("int x = 42"));
        assert_eq!(model.cell_value(0, 2).as_deref(), Some("DataType"));
        assert!(model.cell_value(1, 0).is_none());
    }

    #[test]
    fn test_abstract_search_table_model_clear() {
        let mut model = AbstractSearchTableModel::new("Test");
        model.add_result(SearchResultRow::new(Address::new(0x1000), "test", "Label", 0));
        model.clear();
        assert_eq!(model.row_count(), 0);
    }

    // -- ListingDisplaySearchTableModel tests --

    #[test]
    fn test_listing_display_search_table_model() {
        let mut model = ListingDisplaySearchTableModel::new();
        assert_eq!(model.name(), "Listing Display Search");
        assert_eq!(model.row_count(), 0);
    }

    #[test]
    fn test_listing_display_search_table_model_with_results() {
        let mut model = ListingDisplaySearchTableModel::new();
        model.add_result(SearchResultRow::new(Address::new(0x1000), "NOP", "Mnemonic", 0));
        model.add_result(SearchResultRow::new(Address::new(0x1001), "RET", "Mnemonic", 1));
        assert_eq!(model.row_count(), 2);

        // Verify ordering
        assert_eq!(model.cell_value(0, 0).as_deref(), Some("0x1000"));
        assert_eq!(model.cell_value(1, 0).as_deref(), Some("0x1001"));
    }

    #[test]
    fn test_listing_display_search_address_iterator() {
        let mut iter = ListingDisplaySearchAddressIterator::new(
            Address::new(0x1000),
            Address::new(0x100F),
        );
        assert_eq!(iter.next(), Some(Address::new(0x1000)));
        assert_eq!(iter.next(), Some(Address::new(0x1001)));
        // Skip to end
        while iter.next().is_some() {}
        assert!(iter.next().is_none());
    }
}

// ---------------------------------------------------------------------------
// AbstractSearchTableModel / ListingDisplaySearchTableModel
//
// Ported from `AbstractSearchTableModel.java` and
// `ListingDisplaySearchTableModel.java` in `ghidra.app.plugin.core.searchtext`.
// ---------------------------------------------------------------------------

/// A single row in a search results table.
#[derive(Debug, Clone)]
pub struct SearchResultRow {
    /// The address of the search result.
    pub address: Address,
    /// The matching text.
    pub text: String,
    /// The field where the match was found.
    pub field_name: String,
    /// The index of this result in the overall result set.
    pub result_index: usize,
}

impl SearchResultRow {
    /// Create a new search result row.
    pub fn new(
        address: Address,
        text: impl Into<String>,
        field_name: impl Into<String>,
        result_index: usize,
    ) -> Self {
        Self {
            address,
            text: text.into(),
            field_name: field_name.into(),
            result_index,
        }
    }
}

/// Abstract base for search table models.
///
/// Provides common functionality for displaying search results in a table.
/// Subclasses customize which columns are available and how results are formatted.
#[derive(Debug, Clone)]
pub struct AbstractSearchTableModel {
    /// Name of the model.
    name: String,
    /// Search result rows.
    results: Vec<SearchResultRow>,
    /// Column headers.
    columns: Vec<String>,
}

impl AbstractSearchTableModel {
    /// Create a new model with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            results: Vec::new(),
            columns: vec![
                "Address".to_string(),
                "Match".to_string(),
                "Field".to_string(),
            ],
        }
    }

    /// Get the model name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the number of result rows.
    pub fn row_count(&self) -> usize {
        self.results.len()
    }

    /// Get the number of columns.
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    /// Get a column header.
    pub fn column_name(&self, col: usize) -> Option<&str> {
        self.columns.get(col).map(|s| s.as_str())
    }

    /// Get a cell value.
    pub fn cell_value(&self, row: usize, col: usize) -> Option<String> {
        let result = self.results.get(row)?;
        match col {
            0 => Some(format!("0x{:X}", result.address.offset)),
            1 => Some(result.text.clone()),
            2 => Some(result.field_name.clone()),
            _ => None,
        }
    }

    /// Add a search result.
    pub fn add_result(&mut self, result: SearchResultRow) {
        self.results.push(result);
    }

    /// Get all results.
    pub fn results(&self) -> &[SearchResultRow] {
        &self.results
    }

    /// Clear all results.
    pub fn clear(&mut self) {
        self.results.clear();
    }

    /// Get the address for a given row (for navigation).
    pub fn get_address(&self, row: usize) -> Option<Address> {
        self.results.get(row).map(|r| r.address)
    }
}

/// Table model for listing display search results.
///
/// This is the primary search table model used when searching text
/// within the code listing display.
#[derive(Debug, Clone)]
pub struct ListingDisplaySearchTableModel {
    base: AbstractSearchTableModel,
}

impl ListingDisplaySearchTableModel {
    /// Create a new listing display search table model.
    pub fn new() -> Self {
        Self {
            base: AbstractSearchTableModel::new("Listing Display Search"),
        }
    }

    /// Get the model name.
    pub fn name(&self) -> &str {
        self.base.name()
    }

    /// Get the row count.
    pub fn row_count(&self) -> usize {
        self.base.row_count()
    }

    /// Get a cell value.
    pub fn cell_value(&self, row: usize, col: usize) -> Option<String> {
        self.base.cell_value(row, col)
    }

    /// Add a result.
    pub fn add_result(&mut self, result: SearchResultRow) {
        self.base.add_result(result);
    }

    /// Clear results.
    pub fn clear(&mut self) {
        self.base.clear();
    }
}

impl Default for ListingDisplaySearchTableModel {
    fn default() -> Self {
        Self::new()
    }
}

/// An iterator over addresses in a listing display search result range.
///
/// Ported from `ListingDisplaySearchAddressIterator.java`.
#[derive(Debug, Clone)]
pub struct ListingDisplaySearchAddressIterator {
    /// Current address.
    current: Address,
    /// End address (exclusive).
    end: Address,
    /// Whether the iterator is exhausted.
    exhausted: bool,
}

impl ListingDisplaySearchAddressIterator {
    /// Create a new iterator over the range [start, end].
    pub fn new(start: Address, end: Address) -> Self {
        Self {
            current: start,
            end,
            exhausted: false,
        }
    }

    /// Get the next address.
    pub fn next(&mut self) -> Option<Address> {
        if self.exhausted || self.current.offset > self.end.offset {
            return None;
        }
        let addr = self.current;
        self.current = Address::new(self.current.offset + 1);
        if self.current.offset > self.end.offset {
            self.exhausted = true;
        }
        Some(addr)
    }
}
