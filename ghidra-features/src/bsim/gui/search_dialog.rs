//! BSim search dialog types.
//!
//! Port of Ghidra's `ghidra.features.bsim.gui.search.dialog` package.
//!
//! Provides the data types and state for the BSim search dialog,
//! which allows users to configure and execute similarity searches.

use super::{BSimSearchSettings, BSimServerInfo, ConnectionType};
use super::filters::BSimFilterType;

/// The state of the BSim search dialog.
#[derive(Debug, Clone)]
pub struct BSimSearchDialogState {
    /// The current search settings.
    pub settings: BSimSearchSettings,
    /// The server connection info.
    pub server_info: BSimServerInfo,
    /// Active filters.
    pub filters: Vec<BSimFilterType>,
    /// Whether the dialog is open.
    pub is_open: bool,
    /// The current page/tab index.
    pub current_page: SearchDialogPage,
    /// Whether a search is currently in progress.
    pub searching: bool,
    /// Error message (if any).
    pub error_message: Option<String>,
}

/// Pages/tabs in the search dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SearchDialogPage {
    /// Connection settings page.
    Connection,
    /// Filter configuration page.
    Filters,
    /// Search execution page.
    Search,
    /// Results page.
    Results,
}

impl Default for SearchDialogPage {
    fn default() -> Self {
        Self::Connection
    }
}

impl Default for BSimSearchDialogState {
    fn default() -> Self {
        Self {
            settings: BSimSearchSettings::default(),
            server_info: BSimServerInfo {
                url: String::new(),
                database_name: String::new(),
                connection_type: ConnectionType::default(),
                use_ssl: false,
                username: None,
            },
            filters: Vec::new(),
            is_open: false,
            current_page: SearchDialogPage::default(),
            searching: false,
            error_message: None,
        }
    }
}

impl BSimSearchDialogState {
    /// Create a new search dialog state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open the dialog.
    pub fn open(&mut self) {
        self.is_open = true;
        self.error_message = None;
    }

    /// Close the dialog.
    pub fn close(&mut self) {
        self.is_open = false;
    }

    /// Navigate to a page.
    pub fn go_to_page(&mut self, page: SearchDialogPage) {
        self.current_page = page;
    }

    /// Navigate to the next page.
    pub fn next_page(&mut self) {
        self.current_page = match self.current_page {
            SearchDialogPage::Connection => SearchDialogPage::Filters,
            SearchDialogPage::Filters => SearchDialogPage::Search,
            SearchDialogPage::Search => SearchDialogPage::Results,
            SearchDialogPage::Results => SearchDialogPage::Results,
        };
    }

    /// Navigate to the previous page.
    pub fn previous_page(&mut self) {
        self.current_page = match self.current_page {
            SearchDialogPage::Connection => SearchDialogPage::Connection,
            SearchDialogPage::Filters => SearchDialogPage::Connection,
            SearchDialogPage::Search => SearchDialogPage::Filters,
            SearchDialogPage::Results => SearchDialogPage::Search,
        };
    }

    /// Add a filter.
    pub fn add_filter(&mut self, filter: BSimFilterType) {
        self.filters.push(filter);
    }

    /// Remove a filter by index.
    pub fn remove_filter(&mut self, index: usize) -> Option<BSimFilterType> {
        if index < self.filters.len() {
            Some(self.filters.remove(index))
        } else {
            None
        }
    }

    /// Clear all filters.
    pub fn clear_filters(&mut self) {
        self.filters.clear();
    }

    /// Set the search to in-progress.
    pub fn start_search(&mut self) {
        self.searching = true;
        self.error_message = None;
    }

    /// Mark the search as complete.
    pub fn finish_search(&mut self, error: Option<String>) {
        self.searching = false;
        self.error_message = error;
    }

    /// Whether the current configuration is valid for searching.
    pub fn is_valid(&self) -> bool {
        !self.server_info.url.is_empty()
            && !self.server_info.database_name.is_empty()
    }

    /// Get the number of active filters.
    pub fn filter_count(&self) -> usize {
        self.filters.len()
    }
}

/// A saved search configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SavedSearchConfig {
    /// The name of this saved configuration.
    pub name: String,
    /// The server URL.
    pub server_url: String,
    /// The database name.
    pub database_name: String,
    /// The connection type.
    pub connection_type: String,
    /// The minimum similarity threshold.
    pub min_similarity: f64,
    /// Maximum results.
    pub max_results: usize,
    /// Serialized filter configurations.
    pub filters: Vec<String>,
}

impl SavedSearchConfig {
    /// Create a new saved search config.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            server_url: String::new(),
            database_name: String::new(),
            connection_type: "PostgreSQL".to_string(),
            min_similarity: 0.7,
            max_results: 100,
            filters: Vec::new(),
        }
    }

    /// Create from the current dialog state.
    pub fn from_state(name: impl Into<String>, state: &BSimSearchDialogState) -> Self {
        Self {
            name: name.into(),
            server_url: state.server_info.url.clone(),
            database_name: state.server_info.database_name.clone(),
            connection_type: format!("{:?}", state.server_info.connection_type),
            min_similarity: state.settings.min_similarity,
            max_results: state.settings.max_results,
            filters: state.filters.iter().map(|f| f.name.clone()).collect(),
        }
    }
}

/// Manages saved search configurations.
#[derive(Debug, Clone, Default)]
pub struct SavedSearchManager {
    /// All saved configurations.
    pub configs: Vec<SavedSearchConfig>,
}

impl SavedSearchManager {
    /// Create a new manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a configuration.
    pub fn add(&mut self, config: SavedSearchConfig) {
        self.configs.push(config);
    }

    /// Remove a configuration by name.
    pub fn remove(&mut self, name: &str) -> Option<SavedSearchConfig> {
        if let Some(pos) = self.configs.iter().position(|c| c.name == name) {
            Some(self.configs.remove(pos))
        } else {
            None
        }
    }

    /// Get a configuration by name.
    pub fn get(&self, name: &str) -> Option<&SavedSearchConfig> {
        self.configs.iter().find(|c| c.name == name)
    }

    /// Get all configuration names.
    pub fn names(&self) -> Vec<&str> {
        self.configs.iter().map(|c| c.name.as_str()).collect()
    }

    /// Apply a configuration to a dialog state.
    pub fn apply(&self, name: &str, state: &mut BSimSearchDialogState) -> bool {
        if let Some(config) = self.get(name) {
            state.server_info.url = config.server_url.clone();
            state.server_info.database_name = config.database_name.clone();
            state.settings.min_similarity = config.min_similarity;
            state.settings.max_results = config.max_results;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dialog_state_new() {
        let state = BSimSearchDialogState::new();
        assert!(!state.is_open);
        assert_eq!(state.current_page, SearchDialogPage::Connection);
        assert!(!state.searching);
        assert!(state.error_message.is_none());
    }

    #[test]
    fn test_dialog_open_close() {
        let mut state = BSimSearchDialogState::new();
        state.open();
        assert!(state.is_open);
        state.close();
        assert!(!state.is_open);
    }

    #[test]
    fn test_dialog_page_navigation() {
        let mut state = BSimSearchDialogState::new();
        state.next_page();
        assert_eq!(state.current_page, SearchDialogPage::Filters);
        state.next_page();
        assert_eq!(state.current_page, SearchDialogPage::Search);
        state.next_page();
        assert_eq!(state.current_page, SearchDialogPage::Results);
        state.next_page();
        assert_eq!(state.current_page, SearchDialogPage::Results);

        state.previous_page();
        assert_eq!(state.current_page, SearchDialogPage::Search);
        state.previous_page();
        assert_eq!(state.current_page, SearchDialogPage::Filters);
        state.previous_page();
        assert_eq!(state.current_page, SearchDialogPage::Connection);
        state.previous_page();
        assert_eq!(state.current_page, SearchDialogPage::Connection);
    }

    #[test]
    fn test_dialog_search_lifecycle() {
        let mut state = BSimSearchDialogState::new();
        state.start_search();
        assert!(state.searching);
        assert!(state.error_message.is_none());
        state.finish_search(Some("timeout".to_string()));
        assert!(!state.searching);
        assert_eq!(state.error_message, Some("timeout".to_string()));
    }

    #[test]
    fn test_dialog_validity() {
        let mut state = BSimSearchDialogState::new();
        assert!(!state.is_valid()); // no URL or database
        state.server_info.url = "localhost".to_string();
        assert!(!state.is_valid()); // no database
        state.server_info.database_name = "test".to_string();
        assert!(state.is_valid());
    }

    #[test]
    fn test_search_dialog_page_variants() {
        assert_ne!(SearchDialogPage::Connection, SearchDialogPage::Results);
        assert_eq!(SearchDialogPage::default(), SearchDialogPage::Connection);
    }

    #[test]
    fn test_saved_search_config() {
        let config = SavedSearchConfig::new("My Config");
        assert_eq!(config.name, "My Config");
        assert_eq!(config.min_similarity, 0.7);
        assert_eq!(config.max_results, 100);
    }

    #[test]
    fn test_saved_search_manager() {
        let mut manager = SavedSearchManager::new();
        manager.add(SavedSearchConfig::new("config1"));
        manager.add(SavedSearchConfig::new("config2"));
        assert_eq!(manager.names(), vec!["config1", "config2"]);

        let config = manager.get("config1").unwrap();
        assert_eq!(config.name, "config1");

        let removed = manager.remove("config1").unwrap();
        assert_eq!(removed.name, "config1");
        assert!(manager.get("config1").is_none());
    }

    #[test]
    fn test_saved_search_manager_apply() {
        let mut manager = SavedSearchManager::new();
        let mut config = SavedSearchConfig::new("test");
        config.server_url = "localhost:5432".to_string();
        config.database_name = "bsim_db".to_string();
        config.min_similarity = 0.9;
        manager.add(config);

        let mut state = BSimSearchDialogState::new();
        assert!(manager.apply("test", &mut state));
        assert_eq!(state.server_info.url, "localhost:5432");
        assert_eq!(state.server_info.database_name, "bsim_db");
        assert_eq!(state.settings.min_similarity, 0.9);

        assert!(!manager.apply("nonexistent", &mut state));
    }

    #[test]
    fn test_saved_search_from_state() {
        let mut state = BSimSearchDialogState::new();
        state.server_info.url = "localhost".to_string();
        state.server_info.database_name = "test".to_string();
        state.settings.min_similarity = 0.85;

        let config = SavedSearchConfig::from_state("my_config", &state);
        assert_eq!(config.name, "my_config");
        assert_eq!(config.server_url, "localhost");
        assert_eq!(config.min_similarity, 0.85);
    }
}
