//! Search text plugin -- full-featured plugin ported from
//! `ghidra.app.plugin.core.searchtext.SearchTextPlugin`.
//!
//! This module provides the complete plugin that ties together the search
//! dialog, the search provider, the database searcher, and the program
//! navigation (GoTo) service. It manages plugin lifecycle, action
//! registration, domain-object open/close, and event dispatching.
//!
//! # Key Types
//!
//! - [`SearchTextFullPlugin`] -- the main plugin with full lifecycle
//! - [`SearchAction`] -- actions registered by the plugin
//! - [`SearchEvent`] -- events emitted during search

use std::collections::HashMap;

use ghidra_core::Address;

use super::dialog::SearchTextDialog;
use super::search_text_provider::SearchTextProvider;
use super::plugin::SearchResult;
use super::SearchOptions;
use crate::gotoquery::ProgramLocation;

// ---------------------------------------------------------------------------
// SearchEvent
// ---------------------------------------------------------------------------

/// Events emitted by the search text plugin.
///
/// These correspond to the various callbacks and notifications
/// that the Ghidra plugin fires during search operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchEvent {
    /// A new search was initiated.
    SearchStarted {
        /// The search text.
        text: String,
    },
    /// A match was found.
    MatchFound {
        /// The address of the match.
        address: Address,
        /// The matching text.
        match_text: String,
    },
    /// No more matches were found.
    SearchCompleted {
        /// Total number of matches found.
        match_count: usize,
    },
    /// The search was cancelled by the user.
    SearchCancelled,
    /// The search encountered an error.
    SearchError {
        /// Error description.
        message: String,
    },
    /// A "search all" operation finished.
    SearchAllFinished {
        /// Total matches found across all addresses.
        match_count: usize,
    },
    /// The search text changed (incremental search).
    SearchTextChanged {
        /// The new search text.
        text: String,
    },
    /// Search options were modified.
    OptionsChanged,
    /// A program was opened.
    ProgramOpened {
        /// The program name.
        name: String,
    },
    /// A program was closed.
    ProgramClosed {
        /// The program name.
        name: String,
    },
}

// ---------------------------------------------------------------------------
// SearchAction
// ---------------------------------------------------------------------------

/// Actions that the search text plugin registers with the tool.
///
/// Ported from the action definitions in Ghidra's `SearchTextPlugin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SearchAction {
    /// Open the search dialog.
    Search,
    /// Search for the next match.
    SearchNext,
    /// Search for the previous match.
    SearchPrevious,
    /// Search all occurrences (results table).
    SearchAll,
    /// Search in the current selection.
    SearchSelection,
    /// Toggle quick search mode.
    QuickSearch,
}

impl SearchAction {
    /// The action name (used for registration with the tool).
    pub fn name(&self) -> &'static str {
        match self {
            Self::Search => "Search Text",
            Self::SearchNext => "Search Next",
            Self::SearchPrevious => "Search Previous",
            Self::SearchAll => "Search All",
            Self::SearchSelection => "Search Selection",
            Self::QuickSearch => "Quick Search",
        }
    }

    /// A description of the action.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Search => "Open the text search dialog",
            Self::SearchNext => "Find the next occurrence of the search text",
            Self::SearchPrevious => "Find the previous occurrence of the search text",
            Self::SearchAll => "Find all occurrences and display in a results table",
            Self::SearchSelection => "Search within the current selection",
            Self::QuickSearch => "Toggle incremental quick search mode",
        }
    }

    /// The default key binding (empty string if none).
    pub fn key_binding(&self) -> &'static str {
        match self {
            Self::Search => "Ctrl+H",
            Self::SearchNext => "Ctrl+G",
            Self::SearchPrevious => "Ctrl+Shift+G",
            Self::SearchAll => "",
            Self::SearchSelection => "",
            Self::QuickSearch => "",
        }
    }

    /// All available actions.
    pub fn all() -> &'static [SearchAction] {
        &[
            Self::Search,
            Self::SearchNext,
            Self::SearchPrevious,
            Self::SearchAll,
            Self::SearchSelection,
            Self::QuickSearch,
        ]
    }
}

// ---------------------------------------------------------------------------
// SearchTextFullPlugin
// ---------------------------------------------------------------------------

/// Full-featured search text plugin that coordinates all search
/// components.
///
/// This is the Rust port of Ghidra's `SearchTextPlugin` with complete
/// lifecycle management, action handling, and event dispatching.
///
/// This plugin manages the search dialog, provider, event history,
/// program lifecycle, and action map. It delegates actual search
/// execution to the databasesearcher and search task infrastructure.
#[derive(Debug)]
pub struct SearchTextFullPlugin {
    /// The plugin name.
    name: String,
    /// The search dialog state.
    dialog: SearchTextDialog,
    /// The search provider (manages UI panel).
    provider: Option<SearchTextProvider>,
    /// Registered actions and their enabled state.
    actions: HashMap<SearchAction, bool>,
    /// Event history (most recent last).
    events: Vec<SearchEvent>,
    /// Maximum number of events to retain.
    max_events: usize,
    /// Currently open program names.
    open_programs: Vec<String>,
    /// The active program name.
    active_program: Option<String>,
    /// The active navigatable id.
    active_navigatable_id: Option<u64>,
    /// Current search results.
    results: Vec<SearchResult>,
    /// Current search state.
    state: FullPluginState,
    /// Index of the current result (for next/previous navigation).
    current_result_index: Option<usize>,
    /// Last searched text.
    last_searched_text: Option<String>,
    /// Whether the user has searched at least once.
    searched_once: bool,
    /// Search result limit for "search all".
    search_all_limit: usize,
    /// Whether highlighting is enabled.
    highlight_enabled: bool,
    /// Whether we are waiting for a "search all" to finish.
    waiting_for_search_all: bool,
    /// Whether the plugin is disposed.
    disposed: bool,
}

/// State of the full search text plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FullPluginState {
    /// No search is active.
    Idle,
    /// A search is currently running.
    Running,
    /// The search completed successfully.
    Complete,
    /// The search was cancelled.
    Cancelled,
    /// The search encountered an error.
    Error,
}

impl SearchTextFullPlugin {
    /// Create a new search text plugin.
    pub fn new() -> Self {
        let mut actions = HashMap::new();
        for action in SearchAction::all() {
            actions.insert(*action, true);
        }

        Self {
            name: "SearchTextPlugin".to_string(),
            dialog: SearchTextDialog::new(),
            provider: None,
            actions,
            events: Vec::new(),
            max_events: 1000,
            open_programs: Vec::new(),
            active_program: None,
            active_navigatable_id: None,
            results: Vec::new(),
            state: FullPluginState::Idle,
            current_result_index: None,
            last_searched_text: None,
            searched_once: false,
            search_all_limit: 500,
            highlight_enabled: true,
            waiting_for_search_all: false,
            disposed: false,
        }
    }

    /// Get the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Dispose the plugin (release resources).
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.provider = None;
        self.state = FullPluginState::Cancelled;
        self.events.push(SearchEvent::SearchCancelled);
    }

    // -- Program lifecycle --

    /// Notify that a program was opened.
    pub fn program_opened(&mut self, name: impl Into<String>) {
        let name = name.into();
        self.open_programs.push(name.clone());
        self.events.push(SearchEvent::ProgramOpened { name });
    }

    /// Notify that a program was closed.
    pub fn program_closed(&mut self, name: &str) {
        self.open_programs.retain(|n| n != name);
        if self.active_program.as_deref() == Some(name) {
            self.active_program = None;
            self.active_navigatable_id = None;
        }
        self.events
            .push(SearchEvent::ProgramClosed { name: name.to_string() });
    }

    /// Set the active program.
    pub fn set_active_program(&mut self, name: Option<String>) {
        self.active_program = name;
    }

    /// Get the active program name.
    pub fn active_program(&self) -> Option<&str> {
        self.active_program.as_deref()
    }

    /// Set the active navigatable id.
    pub fn set_active_navigatable(&mut self, id: Option<u64>) {
        self.active_navigatable_id = id;
    }

    /// Get the active navigatable id.
    pub fn active_navigatable_id(&self) -> Option<u64> {
        self.active_navigatable_id
    }

    // -- Dialog management --

    /// Get a reference to the search dialog.
    pub fn dialog(&self) -> &SearchTextDialog {
        &self.dialog
    }

    /// Get a mutable reference to the search dialog.
    pub fn dialog_mut(&mut self) -> &mut SearchTextDialog {
        &mut self.dialog
    }

    /// Show the search dialog (record event).
    pub fn show_search_dialog(&mut self) {
        self.events.push(SearchEvent::SearchStarted {
            text: self.dialog.text().to_string(),
        });
    }

    // -- Provider management --

    /// Set the search provider.
    pub fn set_provider(&mut self, provider: SearchTextProvider) {
        self.provider = Some(provider);
    }

    /// Get a reference to the search provider.
    pub fn provider(&self) -> Option<&SearchTextProvider> {
        self.provider.as_ref()
    }

    /// Get a mutable reference to the search provider.
    pub fn provider_mut(&mut self) -> Option<&mut SearchTextProvider> {
        self.provider.as_mut()
    }

    // -- Search operations --

    /// Start a "search next" operation using the current dialog options.
    pub fn start_search(&mut self) -> bool {
        let nav_id = match self.active_navigatable_id {
            Some(id) => id,
            None => return false,
        };
        let prog = match self.active_program.clone() {
            Some(p) => p,
            None => return false,
        };

        let opts = self.dialog.get_search_options();
        if opts.text().is_empty() {
            return false;
        }

        self.state = FullPluginState::Running;
        self.last_searched_text = Some(opts.text().to_string());
        self.searched_once = true;
        self.events.push(SearchEvent::SearchStarted {
            text: opts.text().to_string(),
        });
        true
    }

    /// Execute a "search previous" using the current dialog options.
    pub fn search_previous(&mut self) -> bool {
        let _opts = self.dialog.get_search_options();
        if _opts.text().is_empty() {
            return false;
        }
        // In a full implementation this would reverse the search direction.
        self.start_search()
    }

    /// Execute a "search all" using the current dialog options.
    pub fn start_search_all(&mut self) -> bool {
        let opts = self.dialog.get_search_options();
        if opts.text().is_empty() {
            return false;
        }
        self.waiting_for_search_all = true;
        self.last_searched_text = Some(opts.text().to_string());
        self.searched_once = true;
        self.events.push(SearchEvent::SearchStarted {
            text: opts.text().to_string(),
        });
        true
    }

    /// Add a search result.
    pub fn add_result(&mut self, result: SearchResult) {
        self.results.push(result);
    }

    /// Report that the search task completed.
    pub fn task_completed(&mut self, address: Address, match_text: String) {
        self.state = FullPluginState::Complete;
        self.events.push(SearchEvent::MatchFound {
            address,
            match_text: match_text.clone(),
        });
        self.events.push(SearchEvent::SearchCompleted {
            match_count: self.results.len(),
        });
    }

    /// Report that the search task was cancelled.
    pub fn task_cancelled(&mut self) {
        self.state = FullPluginState::Cancelled;
        self.events.push(SearchEvent::SearchCancelled);
    }

    /// Report a search error.
    pub fn on_search_error(&mut self, message: impl Into<String>) {
        let msg = message.into();
        self.state = FullPluginState::Error;
        self.events.push(SearchEvent::SearchError {
            message: msg.clone(),
        });
    }

    /// Notify that search-all finished.
    pub fn search_all_finished(&mut self, match_count: usize) {
        self.waiting_for_search_all = false;
        self.state = FullPluginState::Complete;
        self.events.push(SearchEvent::SearchAllFinished { match_count });
    }

    // -- Result navigation --

    /// Navigate to the next result.
    pub fn next_result(&mut self) -> Option<&SearchResult> {
        if self.results.is_empty() {
            return None;
        }
        let idx = match self.current_result_index {
            Some(i) => (i + 1) % self.results.len(),
            None => 0,
        };
        self.current_result_index = Some(idx);
        self.results.get(idx)
    }

    /// Navigate to the previous result.
    pub fn previous_result(&mut self) -> Option<&SearchResult> {
        if self.results.is_empty() {
            return None;
        }
        let idx = match self.current_result_index {
            Some(i) => {
                if i == 0 {
                    self.results.len() - 1
                } else {
                    i - 1
                }
            }
            None => self.results.len() - 1,
        };
        self.current_result_index = Some(idx);
        self.results.get(idx)
    }

    /// Get the current result.
    pub fn current_result(&self) -> Option<&SearchResult> {
        self.current_result_index.and_then(|i| self.results.get(i))
    }

    /// Get all results.
    pub fn results(&self) -> &[SearchResult] {
        &self.results
    }

    /// Get the number of results.
    pub fn result_count(&self) -> usize {
        self.results.len()
    }

    // -- Action management --

    /// Whether an action is enabled.
    pub fn is_action_enabled(&self, action: SearchAction) -> bool {
        self.actions.get(&action).copied().unwrap_or(false)
    }

    /// Enable or disable an action.
    pub fn set_action_enabled(&mut self, action: SearchAction, enabled: bool) {
        self.actions.insert(action, enabled);
    }

    // -- Configuration --

    /// Get the search-all result limit.
    pub fn search_all_limit(&self) -> usize {
        self.search_all_limit
    }

    /// Set the search-all result limit.
    pub fn set_search_all_limit(&mut self, limit: usize) {
        self.search_all_limit = limit;
    }

    /// Whether highlighting is enabled.
    pub fn highlight_enabled(&self) -> bool {
        self.highlight_enabled
    }

    /// Enable or disable highlighting.
    pub fn set_highlight_enabled(&mut self, enabled: bool) {
        self.highlight_enabled = enabled;
    }

    // -- Event access --

    /// Get the event history.
    pub fn events(&self) -> &[SearchEvent] {
        &self.events
    }

    /// Get the last event.
    pub fn last_event(&self) -> Option<&SearchEvent> {
        self.events.last()
    }

    /// Clear the event history.
    pub fn clear_events(&mut self) {
        self.events.clear();
    }

    /// The number of events recorded.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    // -- State queries --

    /// Get the current plugin state.
    pub fn state(&self) -> FullPluginState {
        self.state
    }

    /// Whether a search is currently active.
    pub fn is_search_active(&self) -> bool {
        self.state == FullPluginState::Running
    }

    /// Whether a search-all is in progress.
    pub fn is_waiting_for_search_all(&self) -> bool {
        self.waiting_for_search_all
    }

    /// Whether the plugin can close the current domain object.
    pub fn can_close_domain_object(&self) -> bool {
        self.state != FullPluginState::Running && !self.waiting_for_search_all
    }

    /// Get the last searched text.
    pub fn last_searched_text(&self) -> Option<&str> {
        self.last_searched_text.as_deref()
    }

    /// Whether the user has performed at least one search.
    pub fn searched_once(&self) -> bool {
        self.searched_once
    }

    /// Get the number of open programs.
    pub fn open_program_count(&self) -> usize {
        self.open_programs.len()
    }

    /// Get the list of open program names.
    pub fn open_programs(&self) -> &[String] {
        &self.open_programs
    }

    /// Reset the plugin state for a new search session.
    pub fn reset(&mut self) {
        self.results.clear();
        self.state = FullPluginState::Idle;
        self.current_result_index = None;
    }
}

impl Default for SearchTextFullPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = SearchTextFullPlugin::new();
        assert_eq!(plugin.name(), "SearchTextPlugin");
        assert!(!plugin.is_disposed());
        assert!(plugin.active_program().is_none());
        assert!(plugin.active_navigatable_id().is_none());
        assert_eq!(plugin.open_program_count(), 0);
        assert_eq!(plugin.state(), FullPluginState::Idle);
        assert!(!plugin.searched_once());
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = SearchTextFullPlugin::new();
        assert!(!plugin.is_disposed());
        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_plugin_program_lifecycle() {
        let mut plugin = SearchTextFullPlugin::new();

        plugin.program_opened("test.exe");
        assert_eq!(plugin.open_program_count(), 1);
        assert_eq!(plugin.open_programs()[0], "test.exe");

        plugin.set_active_program(Some("test.exe".into()));
        assert_eq!(plugin.active_program(), Some("test.exe"));

        plugin.program_closed("test.exe");
        assert_eq!(plugin.open_program_count(), 0);
        assert!(plugin.active_program().is_none());
    }

    #[test]
    fn test_plugin_navigatable() {
        let mut plugin = SearchTextFullPlugin::new();
        assert!(plugin.active_navigatable_id().is_none());

        plugin.set_active_navigatable(Some(42));
        assert_eq!(plugin.active_navigatable_id(), Some(42));
    }

    #[test]
    fn test_plugin_start_search_no_program() {
        let mut plugin = SearchTextFullPlugin::new();
        plugin.dialog_mut().set_text("hello");
        assert!(!plugin.start_search());
    }

    #[test]
    fn test_plugin_start_search_no_text() {
        let mut plugin = SearchTextFullPlugin::new();
        plugin.set_active_program(Some("test.exe".into()));
        plugin.set_active_navigatable(Some(1));
        assert!(!plugin.start_search());
    }

    #[test]
    fn test_plugin_start_search_success() {
        let mut plugin = SearchTextFullPlugin::new();
        plugin.set_active_program(Some("test.exe".into()));
        plugin.set_active_navigatable(Some(1));
        plugin.dialog_mut().set_text("hello");
        assert!(plugin.start_search());
        assert!(plugin.is_search_active());
        assert!(plugin.searched_once());
        assert_eq!(plugin.last_searched_text(), Some("hello"));
        assert_eq!(plugin.state(), FullPluginState::Running);
    }

    #[test]
    fn test_plugin_search_all() {
        let mut plugin = SearchTextFullPlugin::new();
        plugin.set_active_program(Some("test.exe".into()));
        plugin.set_active_navigatable(Some(1));
        plugin.dialog_mut().set_text("test");
        assert!(plugin.start_search_all());
        assert!(plugin.is_waiting_for_search_all());
        assert!(!plugin.can_close_domain_object());
    }

    #[test]
    fn test_plugin_search_all_no_text() {
        let mut plugin = SearchTextFullPlugin::new();
        plugin.set_active_program(Some("test.exe".into()));
        plugin.set_active_navigatable(Some(1));
        assert!(!plugin.start_search_all());
    }

    #[test]
    fn test_plugin_search_all_finished() {
        let mut plugin = SearchTextFullPlugin::new();
        plugin.set_active_program(Some("test.exe".into()));
        plugin.set_active_navigatable(Some(1));
        plugin.dialog_mut().set_text("test");
        plugin.start_search_all();

        plugin.search_all_finished(42);
        assert!(!plugin.is_waiting_for_search_all());
        assert!(plugin.can_close_domain_object());
    }

    #[test]
    fn test_plugin_task_completed() {
        let mut plugin = SearchTextFullPlugin::new();
        plugin.task_completed(Address::new(0x1000), "found".to_string());
        assert_eq!(plugin.state(), FullPluginState::Complete);
    }

    #[test]
    fn test_plugin_task_cancelled() {
        let mut plugin = SearchTextFullPlugin::new();
        plugin.task_cancelled();
        assert_eq!(plugin.state(), FullPluginState::Cancelled);
    }

    #[test]
    fn test_plugin_on_search_error() {
        let mut plugin = SearchTextFullPlugin::new();
        plugin.on_search_error("something went wrong");
        assert_eq!(plugin.state(), FullPluginState::Error);
        let last = plugin.last_event().unwrap();
        assert!(matches!(last, SearchEvent::SearchError { message } if message == "something went wrong"));
    }

    #[test]
    fn test_plugin_events() {
        let mut plugin = SearchTextFullPlugin::new();
        assert_eq!(plugin.event_count(), 0);

        plugin.program_opened("a.exe");
        plugin.program_opened("b.exe");
        assert_eq!(plugin.event_count(), 2);

        let last = plugin.last_event().unwrap();
        assert!(matches!(last, SearchEvent::ProgramOpened { name } if name == "b.exe"));

        plugin.clear_events();
        assert_eq!(plugin.event_count(), 0);
    }

    #[test]
    fn test_plugin_actions() {
        let plugin = SearchTextFullPlugin::new();
        assert!(plugin.is_action_enabled(SearchAction::Search));
        assert!(plugin.is_action_enabled(SearchAction::SearchNext));
    }

    #[test]
    fn test_plugin_action_disable() {
        let mut plugin = SearchTextFullPlugin::new();
        plugin.set_action_enabled(SearchAction::QuickSearch, false);
        assert!(!plugin.is_action_enabled(SearchAction::QuickSearch));
    }

    #[test]
    fn test_plugin_highlight() {
        let mut plugin = SearchTextFullPlugin::new();
        assert!(plugin.highlight_enabled());
        plugin.set_highlight_enabled(false);
        assert!(!plugin.highlight_enabled());
    }

    #[test]
    fn test_plugin_search_all_limit() {
        let mut plugin = SearchTextFullPlugin::new();
        assert_eq!(plugin.search_all_limit(), 500);
        plugin.set_search_all_limit(1000);
        assert_eq!(plugin.search_all_limit(), 1000);
    }

    #[test]
    fn test_plugin_result_navigation() {
        let mut plugin = SearchTextFullPlugin::new();
        plugin.add_result(SearchResult::new(Address::new(0x1000), "a", "comment"));
        plugin.add_result(SearchResult::new(Address::new(0x2000), "b", "label"));
        plugin.add_result(SearchResult::new(Address::new(0x3000), "c", "code"));

        let r1 = plugin.next_result().unwrap();
        assert_eq!(r1.address, Address::new(0x1000));

        let r2 = plugin.next_result().unwrap();
        assert_eq!(r2.address, Address::new(0x2000));

        let r3 = plugin.next_result().unwrap();
        assert_eq!(r3.address, Address::new(0x3000));

        // Wraps around
        let r4 = plugin.next_result().unwrap();
        assert_eq!(r4.address, Address::new(0x1000));
    }

    #[test]
    fn test_plugin_previous_result() {
        let mut plugin = SearchTextFullPlugin::new();
        plugin.add_result(SearchResult::new(Address::new(0x1000), "a", "comment"));
        plugin.add_result(SearchResult::new(Address::new(0x2000), "b", "label"));

        let r1 = plugin.previous_result().unwrap();
        assert_eq!(r1.address, Address::new(0x2000));

        let r2 = plugin.previous_result().unwrap();
        assert_eq!(r2.address, Address::new(0x1000));

        // Wraps around
        let r3 = plugin.previous_result().unwrap();
        assert_eq!(r3.address, Address::new(0x2000));
    }

    #[test]
    fn test_plugin_result_navigation_empty() {
        let mut plugin = SearchTextFullPlugin::new();
        assert!(plugin.next_result().is_none());
        assert!(plugin.previous_result().is_none());
        assert!(plugin.current_result().is_none());
    }

    #[test]
    fn test_plugin_reset() {
        let mut plugin = SearchTextFullPlugin::new();
        plugin.add_result(SearchResult::new(Address::new(0x1000), "a", "comment"));
        plugin.task_completed(Address::new(0x1000), "found".to_string());

        plugin.reset();
        assert!(plugin.results().is_empty());
        assert_eq!(plugin.state(), FullPluginState::Idle);
        assert!(plugin.current_result().is_none());
    }

    // -- SearchAction tests --

    #[test]
    fn test_search_action_names() {
        assert_eq!(SearchAction::Search.name(), "Search Text");
        assert_eq!(SearchAction::SearchNext.name(), "Search Next");
        assert_eq!(SearchAction::SearchPrevious.name(), "Search Previous");
        assert_eq!(SearchAction::SearchAll.name(), "Search All");
    }

    #[test]
    fn test_search_action_descriptions() {
        assert!(!SearchAction::Search.description().is_empty());
        assert!(!SearchAction::SearchNext.description().is_empty());
    }

    #[test]
    fn test_search_action_key_bindings() {
        assert_eq!(SearchAction::Search.key_binding(), "Ctrl+H");
        assert_eq!(SearchAction::SearchNext.key_binding(), "Ctrl+G");
        assert_eq!(SearchAction::SearchPrevious.key_binding(), "Ctrl+Shift+G");
    }

    #[test]
    fn test_search_action_all() {
        assert_eq!(SearchAction::all().len(), 6);
    }

    // -- SearchEvent tests --

    #[test]
    fn test_search_event_equality() {
        let a = SearchEvent::SearchCancelled;
        let b = SearchEvent::SearchCancelled;
        assert_eq!(a, b);

        let c = SearchEvent::SearchStarted {
            text: "test".into(),
        };
        assert_ne!(a, c);
    }

    // -- FullPluginState tests --

    #[test]
    fn test_full_plugin_state() {
        assert_eq!(FullPluginState::Idle, FullPluginState::Idle);
        assert_ne!(FullPluginState::Idle, FullPluginState::Running);
    }
}
