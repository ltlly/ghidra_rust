//! Search-and-Replace service and provider.
//!
//! Ported from `ghidra.features.base.replace.SearchAndReplaceProvider` and
//! `ghidra.features.base.replace.SearchAndReplaceQuckFixTableLoader`.
//!
//! Provides:
//! - [`SearchAndReplaceService`] -- trait for programmatic search-and-replace
//!   operations that can be used by other plugins or scripts.
//! - [`SearchAndReplaceProvider`] -- component provider that displays
//!   search-and-replace results in a table with "Replace All" and "Dismiss"
//!   actions.
//! - [`SearchAndReplaceTableLoader`] -- loads quick-fix items into the
//!   provider's table model.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use super::{SearchAndReplaceHandler, SearchAndReplaceQuery, SearchType};
use crate::quickfix::{QuickFix, QuickFixItem, QuickFixStatus};

// ---------------------------------------------------------------------------
// SearchAndReplaceService trait
// ---------------------------------------------------------------------------

/// Service interface for performing search-and-replace operations.
///
/// This trait provides a programmatic API for searching program elements and
/// applying replacements.  It is the Rust equivalent of the combined
/// `SearchAndReplaceQuery.findAll()` and `SearchAndReplaceProvider` logic
/// from the Java codebase.
///
/// # Example
///
/// ```ignore
/// use ghidra_features::replace::replace_service::SearchAndReplaceService;
/// use ghidra_features::replace::SearchAndReplaceQuery;
///
/// struct MyService;
///
/// impl SearchAndReplaceService for MyService {
///     fn execute_search(
///         &self,
///         query: &SearchAndReplaceQuery,
///     ) -> Vec<Box<dyn QuickFix>> {
///         // ... perform search using handlers ...
///         Vec::new()
///     }
/// }
/// ```
pub trait SearchAndReplaceService: Send + Sync {
    /// Execute a search using the given query and return the matching quick-fix
    /// items.
    ///
    /// The implementation should iterate through the appropriate handlers
    /// for the selected search types, collect matches, and return them as
    /// quick-fix items that can be individually applied or applied in bulk.
    fn execute_search(&self, query: &SearchAndReplaceQuery) -> Vec<Box<dyn QuickFix>>;

    /// Execute a search and apply all replacements.
    ///
    /// Returns the number of items that were successfully replaced.
    fn execute_replace_all(&self, query: &SearchAndReplaceQuery) -> usize {
        let items = self.execute_search(query);
        let mut count = 0;
        for mut item in items {
            item.execute();
            if item.status() == QuickFixStatus::Done {
                count += 1;
            }
        }
        count
    }

    /// Get the names of all available search-and-replace handlers.
    fn available_handler_names(&self) -> Vec<String>;
}

// ---------------------------------------------------------------------------
// SearchAndReplaceTableLoader
// ---------------------------------------------------------------------------

/// Loads search-and-replace quick-fix items into a table model.
///
/// Ported from `ghidra.features.base.replace.SearchAndReplaceQuckFixTableLoader`.
///
/// This struct wraps the search execution and tracks whether results were
/// produced and whether the search limit was exceeded.
pub struct SearchAndReplaceTableLoader {
    /// The search query.
    query: SearchAndReplaceQuery,
    /// The registered handlers (shared via Arc for cheap cloning).
    handlers: Vec<Arc<dyn SearchAndReplaceHandler>>,
    /// Whether the search produced any results.
    has_results: bool,
    /// Whether the search limit was exceeded.
    search_limit_exceeded: bool,
}

impl std::fmt::Debug for SearchAndReplaceTableLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SearchAndReplaceTableLoader")
            .field("query", &self.query)
            .field("handlers", &format!("{} handlers", self.handlers.len()))
            .field("has_results", &self.has_results)
            .field("search_limit_exceeded", &self.search_limit_exceeded)
            .finish()
    }
}

impl SearchAndReplaceTableLoader {
    /// Create a new table loader.
    pub fn new(
        query: SearchAndReplaceQuery,
        handlers: Vec<Arc<dyn SearchAndReplaceHandler>>,
    ) -> Self {
        Self {
            query,
            handlers,
            has_results: false,
            search_limit_exceeded: false,
        }
    }

    /// Load data into the accumulator.
    ///
    /// This executes the search query against all relevant handlers and
    /// collects the results.  If the search limit is exceeded, the
    /// `search_limit_exceeded` flag is set.
    pub fn load_data(&mut self) -> Vec<QuickFixItem> {
        let results = self.query.find_all(&self.handlers);
        self.has_results = !results.is_empty();
        if results.len() >= self.query.search_limit() {
            self.search_limit_exceeded = true;
        }
        results
    }

    /// Whether the search produced any data.
    pub fn did_produce_data(&self) -> bool {
        self.has_results
    }

    /// Whether the maximum data size (search limit) was reached.
    pub fn max_data_size_reached(&self) -> bool {
        self.search_limit_exceeded
    }

    /// Get a reference to the query.
    pub fn query(&self) -> &SearchAndReplaceQuery {
        &self.query
    }
}

// ---------------------------------------------------------------------------
// SearchAndReplaceProvider
// ---------------------------------------------------------------------------

/// Component provider that displays search-and-replace results.
///
/// Ported from `ghidra.features.base.replace.SearchAndReplaceProvider`.
///
/// Manages the result table, the "Replace All" and "Dismiss" button actions,
/// and the lifecycle of the search-and-replace UI component.
#[derive(Debug)]
pub struct SearchAndReplaceProvider {
    /// Unique ID for this provider instance.
    id: usize,
    /// The plugin name that created this provider.
    plugin_name: String,
    /// The program being searched.
    program_name: String,
    /// The search query.
    query: SearchAndReplaceQuery,
    /// The table loader.
    loader: SearchAndReplaceTableLoader,
    /// The accumulated quick-fix items.
    items: Vec<QuickFixItem>,
    /// Whether the provider is visible.
    visible: bool,
    /// Whether the provider has been closed.
    closed: bool,
    /// The tab title text.
    tab_title: String,
    /// The window title.
    title: String,
}

static PROVIDER_ID_COUNTER: AtomicUsize = AtomicUsize::new(1);

impl SearchAndReplaceProvider {
    /// Create a new search-and-replace provider.
    pub fn new(
        plugin_name: &str,
        program_name: &str,
        query: SearchAndReplaceQuery,
        handlers: &[Arc<dyn SearchAndReplaceHandler>],
    ) -> Self {
        let id = PROVIDER_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tab_title = format!(
            "\"{}\" -> \"{}\"",
            query.search_text(),
            query.replacement_text()
        );
        let title = format!("Search & Replace:  {tab_title}");

        let loader = SearchAndReplaceTableLoader::new(query.clone(), handlers.to_vec());

        Self {
            id,
            plugin_name: plugin_name.to_string(),
            program_name: program_name.to_string(),
            query,
            loader,
            items: Vec::new(),
            visible: false,
            closed: false,
            tab_title,
            title,
        }
    }

    /// Get the unique ID of this provider.
    pub fn id(&self) -> usize {
        self.id
    }

    /// Get the program name this provider is searching.
    pub fn program_name(&self) -> &str {
        &self.program_name
    }

    /// Get the plugin name.
    pub fn plugin_name(&self) -> &str {
        &self.plugin_name
    }

    /// Get the tab title.
    pub fn tab_title(&self) -> &str {
        &self.tab_title
    }

    /// Get the window title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Whether the provider has been closed.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Get a reference to the search query.
    pub fn query(&self) -> &SearchAndReplaceQuery {
        &self.query
    }

    /// Load the search results.
    ///
    /// Executes the search and populates the internal items list.
    /// Returns a [`LoadResult`] indicating the outcome.
    pub fn load_results(&mut self) -> LoadResult {
        let items = self.loader.load_data();
        let limit_exceeded = self.loader.max_data_size_reached();
        self.items = items;

        if self.items.is_empty() {
            LoadResult::NoResults
        } else {
            self.visible = true;
            if limit_exceeded {
                LoadResult::LimitExceeded(self.items.len())
            } else {
                LoadResult::Loaded(self.items.len())
            }
        }
    }

    /// Execute all pending quick-fix items.
    ///
    /// Applies each fix and returns the number of successfully applied items.
    pub fn execute_all(&mut self) -> usize {
        let mut count = 0;
        for item in &mut self.items {
            item.execute();
            if item.status() == QuickFixStatus::Done {
                count += 1;
            }
        }
        count
    }

    /// Get the current quick-fix items.
    pub fn items(&self) -> &[QuickFixItem] {
        &self.items
    }

    /// Get the number of items.
    pub fn item_count(&self) -> usize {
        self.items.len()
    }

    /// Set the provider visible.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Bring the provider to front (no-op in headless mode).
    pub fn to_front(&self) {
        // In a full implementation, this would bring the UI component to front.
    }

    /// Close the provider.
    pub fn close(&mut self) {
        self.visible = false;
        self.closed = true;
    }
}

// ---------------------------------------------------------------------------
// LoadResult
// ---------------------------------------------------------------------------

/// The result of loading search-and-replace data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadResult {
    /// No results were found.
    NoResults,
    /// Results were loaded successfully.  Contains the item count.
    Loaded(usize),
    /// The search limit was exceeded.  Contains the number of items found.
    LimitExceeded(usize),
}

impl LoadResult {
    /// Whether results were produced.
    pub fn has_results(&self) -> bool {
        matches!(self, Self::Loaded(_) | Self::LimitExceeded(_))
    }

    /// Whether the search limit was exceeded.
    pub fn is_limit_exceeded(&self) -> bool {
        matches!(self, Self::LimitExceeded(_))
    }

    /// Get the number of items, if any.
    pub fn count(&self) -> usize {
        match self {
            Self::NoResults => 0,
            Self::Loaded(n) | Self::LimitExceeded(n) => *n,
        }
    }
}

// ---------------------------------------------------------------------------
// DefaultSearchAndReplaceService
// ---------------------------------------------------------------------------

/// A default implementation of [`SearchAndReplaceService`] that uses the
/// built-in handlers.
pub struct DefaultSearchAndReplaceService {
    handlers: Vec<Arc<dyn SearchAndReplaceHandler>>,
}

impl std::fmt::Debug for DefaultSearchAndReplaceService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DefaultSearchAndReplaceService")
            .field("handlers", &format!("{} handlers", self.handlers.len()))
            .finish()
    }
}

impl DefaultSearchAndReplaceService {
    /// Create a new service with the built-in handlers.
    pub fn new() -> Self {
        Self {
            handlers: super::create_builtin_handlers()
                .into_iter()
                .map(|h| Arc::from(h) as Arc<dyn SearchAndReplaceHandler>)
                .collect(),
        }
    }

    /// Create a service with custom handlers.
    pub fn with_handlers(handlers: Vec<Arc<dyn SearchAndReplaceHandler>>) -> Self {
        Self { handlers }
    }
}

impl Default for DefaultSearchAndReplaceService {
    fn default() -> Self {
        Self::new()
    }
}

impl SearchAndReplaceService for DefaultSearchAndReplaceService {
    fn execute_search(&self, query: &SearchAndReplaceQuery) -> Vec<Box<dyn QuickFix>> {
        let items = query.find_all(&self.handlers);
        items
            .into_iter()
            .map(|item| Box::new(item) as Box<dyn QuickFix>)
            .collect()
    }

    fn available_handler_names(&self) -> Vec<String> {
        self.handlers
            .iter()
            .flat_map(|h| {
                h.search_and_replace_types()
                    .into_iter()
                    .map(|t| t.handler_name().to_string())
                    .collect::<HashSet<_>>()
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn builtin_handlers_arc() -> Vec<Arc<dyn SearchAndReplaceHandler>> {
        super::super::create_builtin_handlers()
            .into_iter()
            .map(|h| Arc::from(h) as Arc<dyn SearchAndReplaceHandler>)
            .collect()
    }

    #[test]
    fn test_table_loader_no_results() {
        let types = HashSet::from([SearchType::symbols()]);
        let query = SearchAndReplaceQuery::new("nonexistent", "x", types, false, false, false, 1000)
            .unwrap();
        let mut loader = SearchAndReplaceTableLoader::new(query, builtin_handlers_arc());
        let results = loader.load_data();
        assert!(results.is_empty());
        assert!(!loader.did_produce_data());
        assert!(!loader.max_data_size_reached());
    }

    #[test]
    fn test_provider_creation() {
        let types = HashSet::from([SearchType::symbols()]);
        let query = SearchAndReplaceQuery::new("foo", "bar", types, false, true, false, 1000)
            .unwrap();
        let handlers = builtin_handlers_arc();
        let provider = SearchAndReplaceProvider::new("TestPlugin", "test_prog", query, &handlers);

        assert_eq!(provider.plugin_name(), "TestPlugin");
        assert_eq!(provider.program_name(), "test_prog");
        assert!(!provider.is_visible());
        assert!(!provider.is_closed());
        assert!(provider.tab_title().contains("foo"));
        assert!(provider.tab_title().contains("bar"));
        assert!(provider.title().contains("Search & Replace"));
    }

    #[test]
    fn test_provider_unique_ids() {
        let types = HashSet::from([SearchType::symbols()]);
        let query = SearchAndReplaceQuery::new("a", "b", types, false, false, false, 100)
            .unwrap();
        let handlers = builtin_handlers_arc();
        let p1 = SearchAndReplaceProvider::new("P", "prog", query.clone(), &handlers);
        let p2 = SearchAndReplaceProvider::new("P", "prog", query, &handlers);
        assert_ne!(p1.id(), p2.id());
    }

    #[test]
    fn test_provider_load_no_results() {
        let types = HashSet::from([SearchType::symbols()]);
        let query = SearchAndReplaceQuery::new("zzz_no_match", "x", types, false, false, false, 1000)
            .unwrap();
        let handlers = builtin_handlers_arc();
        let mut provider = SearchAndReplaceProvider::new("P", "prog", query, &handlers);
        let result = provider.load_results();
        assert_eq!(result, LoadResult::NoResults);
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_provider_close() {
        let types = HashSet::from([SearchType::symbols()]);
        let query = SearchAndReplaceQuery::new("x", "y", types, false, false, false, 100)
            .unwrap();
        let handlers = builtin_handlers_arc();
        let mut provider = SearchAndReplaceProvider::new("P", "prog", query, &handlers);
        provider.set_visible(true);
        assert!(provider.is_visible());
        provider.close();
        assert!(provider.is_closed());
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_load_result_variants() {
        let no_results = LoadResult::NoResults;
        assert!(!no_results.has_results());
        assert!(!no_results.is_limit_exceeded());
        assert_eq!(no_results.count(), 0);

        let loaded = LoadResult::Loaded(42);
        assert!(loaded.has_results());
        assert!(!loaded.is_limit_exceeded());
        assert_eq!(loaded.count(), 42);

        let limited = LoadResult::LimitExceeded(10000);
        assert!(limited.has_results());
        assert!(limited.is_limit_exceeded());
        assert_eq!(limited.count(), 10000);
    }

    #[test]
    fn test_default_service_creation() {
        let service = DefaultSearchAndReplaceService::new();
        let names = service.available_handler_names();
        assert!(!names.is_empty());
    }

    #[test]
    fn test_default_service_search() {
        let service = DefaultSearchAndReplaceService::new();
        let types = HashSet::from([SearchType::symbols()]);
        let query = SearchAndReplaceQuery::new("no_match_xyz", "r", types, false, false, false, 100)
            .unwrap();
        let results = service.execute_search(&query);
        assert!(results.is_empty());
    }

    #[test]
    fn test_default_service_replace_all() {
        let service = DefaultSearchAndReplaceService::new();
        let types = HashSet::from([SearchType::symbols()]);
        let query = SearchAndReplaceQuery::new("no_match_xyz", "r", types, false, false, false, 100)
            .unwrap();
        let count = service.execute_replace_all(&query);
        assert_eq!(count, 0);
    }
}
