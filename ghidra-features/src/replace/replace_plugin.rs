//! Search-and-Replace plugin.
//!
//! Ported from `ghidra.features.base.replace.SearchAndReplacePlugin`.
//!
//! Provides the [`SearchAndReplacePlugin`] which manages the search-and-replace
//! dialog, registers the menu action, handles search-limit options, and tracks
//! open result providers.  The plugin is the top-level entry point for the
//! search-and-replace feature in a Ghidra tool.

use std::collections::HashSet;
use std::sync::Arc;

use super::replace_service::{SearchAndReplaceProvider, SearchAndReplaceService};
use super::{SearchAndReplaceQuery, SearchAndReplaceHandler, SearchType};
use crate::quickfix::QuickFix;

// ---------------------------------------------------------------------------
// Search constants (port of ghidra.app.util.SearchConstants)
// ---------------------------------------------------------------------------

/// Default maximum number of search results.
pub const DEFAULT_SEARCH_LIMIT: usize = 10_000;

/// Option name for the search limit setting.
pub const SEARCH_LIMIT_NAME: &str = "Search Limit";

/// The option group name for search-related settings.
pub const SEARCH_OPTION_NAME: &str = "Search";

// ---------------------------------------------------------------------------
// PluginStatus
// ---------------------------------------------------------------------------

/// Plugin metadata status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginStatus {
    /// Plugin is released and stable.
    Released,
    /// Plugin is in beta.
    Beta,
    /// Plugin is unstable/experimental.
    Unstable,
}

// ---------------------------------------------------------------------------
// PluginInfo
// ---------------------------------------------------------------------------

/// Plugin metadata configuration.
#[derive(Debug, Clone)]
pub struct PluginInfo {
    /// Plugin status.
    pub status: PluginStatus,
    /// Package name.
    pub package_name: String,
    /// Plugin category.
    pub category: String,
    /// Short description.
    pub short_description: String,
    /// Full description.
    pub description: String,
    /// Names of required services.
    pub services_required: Vec<String>,
}

impl Default for PluginInfo {
    fn default() -> Self {
        Self {
            status: PluginStatus::Released,
            package_name: "Core".to_string(),
            category: "Search".to_string(),
            short_description: "Search and replace text on program element names or comments."
                .to_string(),
            description: "This plugin provides a search and replace capability for a variety of \
                program elements including functions, classes, namespaces, datatypes, field names, \
                and other."
                .to_string(),
            services_required: vec!["ProgramManager".to_string(), "GoToService".to_string()],
        }
    }
}

// ---------------------------------------------------------------------------
// SearchAndReplacePlugin
// ---------------------------------------------------------------------------

/// Plugin to perform search and replace operations for many different program
/// element types such as labels, functions, classes, datatypes, memory blocks,
/// and more.
///
/// Ported from `ghidra.features.base.replace.SearchAndReplacePlugin`.
///
/// # Example
///
/// ```ignore
/// use ghidra_features::replace::replace_plugin::SearchAndReplacePlugin;
///
/// let mut plugin = SearchAndReplacePlugin::new("Search And Replace");
/// plugin.init();
///
/// // Simulate opening a search-and-replace dialog
/// let result = plugin.show_search_and_replace("my_program");
/// plugin.dispose();
/// ```
pub struct SearchAndReplacePlugin {
    /// Plugin name.
    name: String,
    /// Plugin metadata.
    info: PluginInfo,
    /// Cached dialog state (search text history, options, etc.).
    cached_dialog: Option<SearchAndReplaceDialogState>,
    /// Current search limit (from tool options).
    search_limit: usize,
    /// Open result providers.
    providers: Vec<SearchAndReplaceProvider>,
    /// Whether the plugin has been initialized.
    initialized: bool,
    /// The registered search-and-replace handlers (shared via Arc for cheap cloning).
    handlers: Vec<Arc<dyn SearchAndReplaceHandler>>,
}

impl SearchAndReplacePlugin {
    /// Create a new search-and-replace plugin.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            info: PluginInfo::default(),
            cached_dialog: None,
            search_limit: DEFAULT_SEARCH_LIMIT,
            providers: Vec::new(),
            initialized: false,
            handlers: super::create_builtin_handlers()
                .into_iter()
                .map(|h| Arc::from(h) as Arc<dyn SearchAndReplaceHandler>)
                .collect(),
        }
    }

    /// Create a plugin with custom handlers.
    pub fn with_handlers(
        name: impl Into<String>,
        handlers: Vec<Arc<dyn SearchAndReplaceHandler>>,
    ) -> Self {
        Self {
            handlers,
            ..Self::new(name)
        }
    }

    /// Return the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the plugin info.
    pub fn info(&self) -> &PluginInfo {
        &self.info
    }

    /// Initialize the plugin.
    ///
    /// Sets up options listeners and registers the search-and-replace action.
    pub fn init(&mut self) {
        self.initialize_options();
        self.initialized = true;
    }

    /// Dispose of the plugin, closing all open providers.
    pub fn dispose(&mut self) {
        let providers: Vec<_> = self.providers.drain(..).collect();
        for mut provider in providers {
            provider.close();
        }
        self.cached_dialog = None;
        self.initialized = false;
    }

    /// Whether the plugin has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // -- Options --

    /// Get the current search limit.
    pub fn search_limit(&self) -> usize {
        self.search_limit
    }

    /// Set the search limit.  Panics if `limit` is 0.
    pub fn set_search_limit(&mut self, limit: usize) {
        assert!(limit > 0, "Search limit must be greater than 0");
        self.search_limit = limit;
        if let Some(ref mut dialog) = self.cached_dialog {
            dialog.search_limit = limit;
        }
    }

    /// Handle a search-option change from the tool options system.
    ///
    /// Returns `Ok(())` on success, or `Err(message)` if the option value
    /// is invalid (e.g., search limit <= 0).
    pub fn search_options_changed(
        &mut self,
        option_name: &str,
        new_value: SearchOptionValue,
    ) -> Result<(), String> {
        if option_name == SEARCH_LIMIT_NAME {
            match new_value {
                SearchOptionValue::Int(limit) => {
                    if limit <= 0 {
                        return Err("Search limit must be greater than 0".to_string());
                    }
                    self.set_search_limit(limit as usize);
                }
                _ => {
                    return Err("Search limit must be an integer".to_string());
                }
            }
        }
        Ok(())
    }

    // -- Actions --

    /// Execute the search-and-replace action.
    ///
    /// This is the entry point when the user selects "Search And Replace..."
    /// from the menu.  It shows the dialog, and if the user confirms, creates
    /// a new [`SearchAndReplaceProvider`] for the given program.
    ///
    /// Returns `Some(query)` if the user confirmed, or `None` if cancelled.
    pub fn search_and_replace(
        &mut self,
        program_name: &str,
        dialog_params: Option<SearchAndReplaceDialogParams>,
    ) -> Option<SearchAndReplaceQuery> {
        let params = dialog_params.unwrap_or_default();
        let query = SearchAndReplaceQuery::new(
            &params.search_text,
            &params.replacement_text,
            params.selected_types.clone(),
            params.is_regex,
            params.is_case_sensitive,
            params.is_whole_word,
            self.search_limit,
        )
        .ok()?;

        let provider = SearchAndReplaceProvider::new(
            &self.name,
            program_name,
            query.clone(),
            &self.handlers,
        );
        self.providers.push(provider);
        Some(query)
    }

    /// Close a provider (called when the provider's component is closed).
    pub fn provider_closed(&mut self, provider_id: usize) {
        self.providers.retain(|p| p.id() != provider_id);
    }

    /// Notify the plugin that a program was closed.
    pub fn program_closed(&mut self, program_name: &str) {
        let to_close: Vec<usize> = self
            .providers
            .iter()
            .filter(|p| p.program_name() == program_name)
            .map(|p| p.id())
            .collect();
        for id in to_close {
            if let Some(pos) = self.providers.iter().position(|p| p.id() == id) {
                self.providers.remove(pos);
            }
        }
    }

    /// Get the number of open providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    // -- Private helpers --

    fn initialize_options(&mut self) {
        self.cached_dialog = Some(SearchAndReplaceDialogState {
            search_limit: self.search_limit,
            search_history: Vec::new(),
            replace_history: Vec::new(),
        });
    }
}

// ---------------------------------------------------------------------------
// SearchAndReplaceDialogState (in-memory dialog state)
// ---------------------------------------------------------------------------

/// In-memory state for the search-and-replace dialog.
///
/// Mirrors the state that the Java `SearchAndReplaceDialog` holds in its
/// Swing components.  In the Rust port this is a plain data struct since
/// the actual UI is handled separately.
#[derive(Debug, Clone)]
pub struct SearchAndReplaceDialogState {
    /// Current search limit.
    pub search_limit: usize,
    /// Search text history (most recent first).
    pub search_history: Vec<String>,
    /// Replacement text history (most recent first).
    pub replace_history: Vec<String>,
}

impl SearchAndReplaceDialogState {
    /// Maximum number of history entries.
    pub const MAX_HISTORY: usize = 20;

    /// Add a search text entry to the history.
    pub fn add_search_history(&mut self, text: &str) {
        if text.trim().is_empty() {
            return;
        }
        self.search_history.retain(|t| t != text);
        self.search_history.insert(0, text.to_string());
        self.search_history.truncate(Self::MAX_HISTORY);
    }

    /// Add a replacement text entry to the history.
    pub fn add_replace_history(&mut self, text: &str) {
        if text.trim().is_empty() {
            return;
        }
        self.replace_history.retain(|t| t != text);
        self.replace_history.insert(0, text.to_string());
        self.replace_history.truncate(Self::MAX_HISTORY);
    }
}

// ---------------------------------------------------------------------------
// SearchAndReplaceDialogParams
// ---------------------------------------------------------------------------

/// Parameters collected from the search-and-replace dialog.
///
/// These are the user-configurable options that are passed to
/// [`SearchAndReplacePlugin::search_and_replace`].
#[derive(Debug, Clone)]
pub struct SearchAndReplaceDialogParams {
    /// The text to search for.
    pub search_text: String,
    /// The replacement text.
    pub replacement_text: String,
    /// Selected search types.
    pub selected_types: HashSet<SearchType>,
    /// Whether to interpret search text as a regex.
    pub is_regex: bool,
    /// Whether the search is case sensitive.
    pub is_case_sensitive: bool,
    /// Whether to match whole words only.
    pub is_whole_word: bool,
}

impl Default for SearchAndReplaceDialogParams {
    fn default() -> Self {
        Self {
            search_text: String::new(),
            replacement_text: String::new(),
            selected_types: SearchType::all_builtin_types(),
            is_regex: false,
            is_case_sensitive: true,
            is_whole_word: false,
        }
    }
}

// ---------------------------------------------------------------------------
// SearchOptionValue
// ---------------------------------------------------------------------------

/// A value that can be stored in the search options.
#[derive(Debug, Clone)]
pub enum SearchOptionValue {
    /// An integer value.
    Int(i32),
    /// A boolean value.
    Bool(bool),
    /// A string value.
    String(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = SearchAndReplacePlugin::new("Search And Replace");
        assert_eq!(plugin.name(), "Search And Replace");
        assert!(!plugin.is_initialized());
        assert_eq!(plugin.search_limit(), DEFAULT_SEARCH_LIMIT);
        assert_eq!(plugin.provider_count(), 0);
    }

    #[test]
    fn test_plugin_init() {
        let mut plugin = SearchAndReplacePlugin::new("Search And Replace");
        plugin.init();
        assert!(plugin.is_initialized());
        assert!(plugin.cached_dialog.is_some());
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = SearchAndReplacePlugin::new("Search And Replace");
        plugin.init();
        plugin.dispose();
        assert!(!plugin.is_initialized());
        assert!(plugin.cached_dialog.is_none());
    }

    #[test]
    fn test_set_search_limit() {
        let mut plugin = SearchAndReplacePlugin::new("Search And Replace");
        plugin.init();
        plugin.set_search_limit(5000);
        assert_eq!(plugin.search_limit(), 5000);
        assert_eq!(
            plugin.cached_dialog.as_ref().unwrap().search_limit,
            5000
        );
    }

    #[test]
    #[should_panic(expected = "Search limit must be greater than 0")]
    fn test_set_search_limit_zero_panics() {
        let mut plugin = SearchAndReplacePlugin::new("Search And Replace");
        plugin.set_search_limit(0);
    }

    #[test]
    fn test_search_options_changed_valid() {
        let mut plugin = SearchAndReplacePlugin::new("Search And Replace");
        plugin.init();
        let result = plugin.search_options_changed(SEARCH_LIMIT_NAME, SearchOptionValue::Int(2000));
        assert!(result.is_ok());
        assert_eq!(plugin.search_limit(), 2000);
    }

    #[test]
    fn test_search_options_changed_invalid() {
        let mut plugin = SearchAndReplacePlugin::new("Search And Replace");
        plugin.init();
        let result = plugin.search_options_changed(SEARCH_LIMIT_NAME, SearchOptionValue::Int(0));
        assert!(result.is_err());
        assert_eq!(plugin.search_limit(), DEFAULT_SEARCH_LIMIT);
    }

    #[test]
    fn test_search_options_changed_negative() {
        let mut plugin = SearchAndReplacePlugin::new("Search And Replace");
        plugin.init();
        let result = plugin.search_options_changed(SEARCH_LIMIT_NAME, SearchOptionValue::Int(-5));
        assert!(result.is_err());
    }

    #[test]
    fn test_search_and_replace_creates_provider() {
        let mut plugin = SearchAndReplacePlugin::new("Search And Replace");
        plugin.init();

        let params = SearchAndReplaceDialogParams {
            search_text: "foo".to_string(),
            replacement_text: "bar".to_string(),
            selected_types: HashSet::from([SearchType::symbols()]),
            is_regex: false,
            is_case_sensitive: true,
            is_whole_word: false,
        };

        let query = plugin.search_and_replace("test_program", Some(params));
        assert!(query.is_some());
        assert_eq!(plugin.provider_count(), 1);

        let query = query.unwrap();
        assert_eq!(query.search_text(), "foo");
        assert_eq!(query.replacement_text(), "bar");
    }

    #[test]
    fn test_search_and_replace_invalid_regex() {
        let mut plugin = SearchAndReplacePlugin::new("Search And Replace");
        plugin.init();

        let params = SearchAndReplaceDialogParams {
            search_text: "[invalid".to_string(),
            replacement_text: "bar".to_string(),
            selected_types: HashSet::from([SearchType::symbols()]),
            is_regex: true,
            is_case_sensitive: false,
            is_whole_word: false,
        };

        let query = plugin.search_and_replace("test_program", Some(params));
        assert!(query.is_none());
        assert_eq!(plugin.provider_count(), 0);
    }

    #[test]
    fn test_program_closed_removes_providers() {
        let mut plugin = SearchAndReplacePlugin::new("Search And Replace");
        plugin.init();

        let params = SearchAndReplaceDialogParams {
            search_text: "foo".to_string(),
            replacement_text: "bar".to_string(),
            selected_types: HashSet::from([SearchType::symbols()]),
            ..Default::default()
        };

        plugin.search_and_replace("prog_a", Some(params.clone()));
        plugin.search_and_replace("prog_b", Some(params));
        assert_eq!(plugin.provider_count(), 2);

        plugin.program_closed("prog_a");
        assert_eq!(plugin.provider_count(), 1);
    }

    #[test]
    fn test_dialog_state_history() {
        let mut state = SearchAndReplaceDialogState {
            search_limit: 1000,
            search_history: Vec::new(),
            replace_history: Vec::new(),
        };

        state.add_search_history("foo");
        state.add_search_history("bar");
        state.add_search_history("foo"); // dedup
        assert_eq!(state.search_history.len(), 2);
        assert_eq!(state.search_history[0], "foo");
        assert_eq!(state.search_history[1], "bar");

        // Empty strings are ignored
        state.add_search_history("");
        assert_eq!(state.search_history.len(), 2);
    }

    #[test]
    fn test_dialog_state_max_history() {
        let mut state = SearchAndReplaceDialogState {
            search_limit: 1000,
            search_history: Vec::new(),
            replace_history: Vec::new(),
        };

        for i in 0..25 {
            state.add_search_history(&format!("item_{i}"));
        }
        assert_eq!(state.search_history.len(), SearchAndReplaceDialogState::MAX_HISTORY);
        assert_eq!(state.search_history[0], "item_24");
    }

    #[test]
    fn test_default_dialog_params() {
        let params = SearchAndReplaceDialogParams::default();
        assert!(params.search_text.is_empty());
        assert!(params.replacement_text.is_empty());
        assert!(!params.is_regex);
        assert!(params.is_case_sensitive);
        assert!(!params.is_whole_word);
        assert!(params.selected_types.contains(&SearchType::symbols()));
    }

    #[test]
    fn test_plugin_info_defaults() {
        let info = PluginInfo::default();
        assert_eq!(info.status, PluginStatus::Released);
        assert_eq!(info.package_name, "Core");
        assert_eq!(info.category, "Search");
        assert!(info.services_required.contains(&"ProgramManager".to_string()));
    }

    #[test]
    fn test_plugin_with_custom_handlers() {
        use super::super::ListingCommentsHandler;
        let handlers: Vec<Arc<dyn SearchAndReplaceHandler>> =
            vec![Arc::new(ListingCommentsHandler)];
        let plugin = SearchAndReplacePlugin::with_handlers("Custom", handlers);
        assert_eq!(plugin.name(), "Custom");
    }
}
