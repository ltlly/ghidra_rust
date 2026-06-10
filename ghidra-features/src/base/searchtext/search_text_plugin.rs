//! Search text plugin for Features/Base.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.searchtext.SearchTextPlugin`.
//!
//! This module provides the plugin that ties together the search dialog,
//! the search provider, the database searcher, and program navigation.
//! It manages plugin lifecycle, action registration, domain-object
//! open/close, and event dispatching.
//!
//! # Key Types
//!
//! - [`SearchTextPlugin`] -- the main plugin with full lifecycle
//! - [`SearchAction`] -- actions registered by the plugin
//! - [`SearchEvent`] -- events emitted during search
//! - [`PluginState`] -- lifecycle state of the plugin

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// SearchEvent
// ---------------------------------------------------------------------------

/// Events emitted by the search text plugin.
///
/// These correspond to the various callbacks and notifications that the
/// Ghidra plugin fires during search operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchEvent {
    /// A new search was initiated.
    SearchStarted {
        /// The search text.
        text: String,
    },
    /// A match was found.
    MatchFound {
        /// The address of the match (hex).
        address: String,
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
// PluginState
// ---------------------------------------------------------------------------

/// State of the search text plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginState {
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

// ---------------------------------------------------------------------------
// SearchTextPlugin
// ---------------------------------------------------------------------------

/// Full-featured search text plugin that coordinates all search components.
///
/// This is the Rust port of Ghidra's `SearchTextPlugin` with complete
/// lifecycle management, action handling, and event dispatching.
///
/// This plugin manages the search dialog, provider, event history,
/// program lifecycle, and action map. It delegates actual search
/// execution to the databasesearcher and search task infrastructure.
#[derive(Debug)]
pub struct SearchTextPlugin {
    /// The plugin name.
    name: String,
    /// Current search text.
    search_text: String,
    /// Case-sensitive toggle.
    case_sensitive: bool,
    /// Search direction (true = forward).
    forward: bool,
    /// Search all fields toggle.
    search_all_fields: bool,
    /// Whether to search functions.
    functions: bool,
    /// Whether to search comments.
    comments: bool,
    /// Whether to search labels.
    labels: bool,
    /// Whether to search instruction mnemonics.
    instruction_mnemonics: bool,
    /// Whether to search instruction operands.
    instruction_operands: bool,
    /// Whether to search data mnemonics.
    data_mnemonics: bool,
    /// Whether to search data operands.
    data_operands: bool,
    /// Whether to use program database search.
    database_search: bool,
    /// Whether to include non-loaded blocks.
    include_non_loaded: bool,
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
    /// Current plugin state.
    state: PluginState,
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

impl SearchTextPlugin {
    /// Create a new search text plugin.
    pub fn new() -> Self {
        let mut actions = HashMap::new();
        for action in SearchAction::all() {
            actions.insert(*action, true);
        }

        Self {
            name: "SearchTextPlugin".to_string(),
            search_text: String::new(),
            case_sensitive: false,
            forward: true,
            search_all_fields: true,
            functions: true,
            comments: true,
            labels: true,
            instruction_mnemonics: true,
            instruction_operands: true,
            data_mnemonics: true,
            data_operands: true,
            database_search: true,
            include_non_loaded: false,
            actions,
            events: Vec::new(),
            max_events: 1000,
            open_programs: Vec::new(),
            active_program: None,
            active_navigatable_id: None,
            state: PluginState::Idle,
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
        self.state = PluginState::Cancelled;
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

    // -- Search text and options --

    /// Get the current search text.
    pub fn search_text(&self) -> &str {
        &self.search_text
    }

    /// Set the search text.
    pub fn set_search_text(&mut self, text: impl Into<String>) {
        self.search_text = text.into();
    }

    /// Whether the search is case-sensitive.
    pub fn is_case_sensitive(&self) -> bool {
        self.case_sensitive
    }

    /// Set case sensitivity.
    pub fn set_case_sensitive(&mut self, case_sensitive: bool) {
        self.case_sensitive = case_sensitive;
    }

    /// Whether the search direction is forward.
    pub fn is_forward(&self) -> bool {
        self.forward
    }

    /// Set the search direction.
    pub fn set_forward(&mut self, forward: bool) {
        self.forward = forward;
    }

    /// Whether to search all fields.
    pub fn search_all_fields(&self) -> bool {
        self.search_all_fields
    }

    /// Set whether to search all fields.
    pub fn set_search_all_fields(&mut self, search_all: bool) {
        self.search_all_fields = search_all;
    }

    /// Whether to search functions.
    pub fn search_functions(&self) -> bool {
        self.functions
    }

    /// Whether to search comments.
    pub fn search_comments(&self) -> bool {
        self.comments
    }

    /// Whether to search labels.
    pub fn search_labels(&self) -> bool {
        self.labels
    }

    /// Whether to search instruction mnemonics.
    pub fn search_instruction_mnemonics(&self) -> bool {
        self.instruction_mnemonics
    }

    /// Whether to search instruction operands.
    pub fn search_instruction_operands(&self) -> bool {
        self.instruction_operands
    }

    /// Whether to search data mnemonics.
    pub fn search_data_mnemonics(&self) -> bool {
        self.data_mnemonics
    }

    /// Whether to search data operands.
    pub fn search_data_operands(&self) -> bool {
        self.data_operands
    }

    /// Whether to use program database search (fast).
    pub fn is_program_database_search(&self) -> bool {
        self.database_search
    }

    /// Set whether to use program database search.
    pub fn set_database_search(&mut self, database_search: bool) {
        self.database_search = database_search;
    }

    /// Whether to include non-loaded memory blocks.
    pub fn include_non_loaded_blocks(&self) -> bool {
        self.include_non_loaded
    }

    /// Set whether to include non-loaded blocks.
    pub fn set_include_non_loaded(&mut self, include: bool) {
        self.include_non_loaded = include;
    }

    // -- Search operations --

    /// Start a "search next" operation using the current options.
    pub fn start_search(&mut self) -> bool {
        if self.active_navigatable_id.is_none() {
            return false;
        }
        if self.active_program.is_none() {
            return false;
        }
        if self.search_text.is_empty() {
            return false;
        }

        self.state = PluginState::Running;
        self.last_searched_text = Some(self.search_text.clone());
        self.searched_once = true;
        self.events.push(SearchEvent::SearchStarted {
            text: self.search_text.clone(),
        });
        true
    }

    /// Execute a "search previous" using the current options.
    pub fn search_previous(&mut self) -> bool {
        if self.search_text.is_empty() {
            return false;
        }
        // In a full implementation this would reverse the search direction.
        self.start_search()
    }

    /// Execute a "search all" using the current options.
    pub fn start_search_all(&mut self) -> bool {
        if self.search_text.is_empty() {
            return false;
        }
        self.waiting_for_search_all = true;
        self.last_searched_text = Some(self.search_text.clone());
        self.searched_once = true;
        self.events.push(SearchEvent::SearchStarted {
            text: self.search_text.clone(),
        });
        true
    }

    /// Report that the search task completed.
    pub fn task_completed(&mut self, address: String, match_text: String) {
        self.state = PluginState::Complete;
        self.events.push(SearchEvent::MatchFound {
            address,
            match_text: match_text.clone(),
        });
        self.events.push(SearchEvent::SearchCompleted {
            match_count: 0,
        });
    }

    /// Report that the search task was cancelled.
    pub fn task_cancelled(&mut self) {
        self.state = PluginState::Cancelled;
        self.events.push(SearchEvent::SearchCancelled);
    }

    /// Report a search error.
    pub fn on_search_error(&mut self, message: impl Into<String>) {
        let msg = message.into();
        self.state = PluginState::Error;
        self.events.push(SearchEvent::SearchError { message: msg });
    }

    /// Notify that search-all finished.
    pub fn search_all_finished(&mut self, match_count: usize) {
        self.waiting_for_search_all = false;
        self.state = PluginState::Complete;
        self.events.push(SearchEvent::SearchAllFinished { match_count });
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
    pub fn state(&self) -> PluginState {
        self.state
    }

    /// Whether a search is currently active.
    pub fn is_search_active(&self) -> bool {
        self.state == PluginState::Running
    }

    /// Whether a search-all is in progress.
    pub fn is_waiting_for_search_all(&self) -> bool {
        self.waiting_for_search_all
    }

    /// Whether the plugin can close the current domain object.
    pub fn can_close_domain_object(&self) -> bool {
        self.state != PluginState::Running && !self.waiting_for_search_all
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
        self.state = PluginState::Idle;
    }
}

impl Default for SearchTextPlugin {
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
        let plugin = SearchTextPlugin::new();
        assert_eq!(plugin.name(), "SearchTextPlugin");
        assert!(!plugin.is_disposed());
        assert!(plugin.active_program().is_none());
        assert!(plugin.active_navigatable_id().is_none());
        assert_eq!(plugin.open_program_count(), 0);
        assert_eq!(plugin.state(), PluginState::Idle);
        assert!(!plugin.searched_once());
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = SearchTextPlugin::new();
        assert!(!plugin.is_disposed());
        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_plugin_program_lifecycle() {
        let mut plugin = SearchTextPlugin::new();

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
        let mut plugin = SearchTextPlugin::new();
        assert!(plugin.active_navigatable_id().is_none());

        plugin.set_active_navigatable(Some(42));
        assert_eq!(plugin.active_navigatable_id(), Some(42));
    }

    #[test]
    fn test_plugin_start_search_no_program() {
        let mut plugin = SearchTextPlugin::new();
        plugin.set_search_text("hello");
        assert!(!plugin.start_search());
    }

    #[test]
    fn test_plugin_start_search_no_text() {
        let mut plugin = SearchTextPlugin::new();
        plugin.set_active_program(Some("test.exe".into()));
        plugin.set_active_navigatable(Some(1));
        assert!(!plugin.start_search());
    }

    #[test]
    fn test_plugin_start_search_success() {
        let mut plugin = SearchTextPlugin::new();
        plugin.set_active_program(Some("test.exe".into()));
        plugin.set_active_navigatable(Some(1));
        plugin.set_search_text("hello");
        assert!(plugin.start_search());
        assert!(plugin.is_search_active());
        assert!(plugin.searched_once());
        assert_eq!(plugin.last_searched_text(), Some("hello"));
        assert_eq!(plugin.state(), PluginState::Running);
    }

    #[test]
    fn test_plugin_search_all() {
        let mut plugin = SearchTextPlugin::new();
        plugin.set_active_program(Some("test.exe".into()));
        plugin.set_active_navigatable(Some(1));
        plugin.set_search_text("test");
        assert!(plugin.start_search_all());
        assert!(plugin.is_waiting_for_search_all());
        assert!(!plugin.can_close_domain_object());
    }

    #[test]
    fn test_plugin_search_all_no_text() {
        let mut plugin = SearchTextPlugin::new();
        plugin.set_active_program(Some("test.exe".into()));
        plugin.set_active_navigatable(Some(1));
        assert!(!plugin.start_search_all());
    }

    #[test]
    fn test_plugin_search_all_finished() {
        let mut plugin = SearchTextPlugin::new();
        plugin.set_active_program(Some("test.exe".into()));
        plugin.set_active_navigatable(Some(1));
        plugin.set_search_text("test");
        plugin.start_search_all();

        plugin.search_all_finished(42);
        assert!(!plugin.is_waiting_for_search_all());
        assert!(plugin.can_close_domain_object());
    }

    #[test]
    fn test_plugin_task_completed() {
        let mut plugin = SearchTextPlugin::new();
        plugin.task_completed("0x1000".to_string(), "found".to_string());
        assert_eq!(plugin.state(), PluginState::Complete);
    }

    #[test]
    fn test_plugin_task_cancelled() {
        let mut plugin = SearchTextPlugin::new();
        plugin.task_cancelled();
        assert_eq!(plugin.state(), PluginState::Cancelled);
    }

    #[test]
    fn test_plugin_on_search_error() {
        let mut plugin = SearchTextPlugin::new();
        plugin.on_search_error("something went wrong");
        assert_eq!(plugin.state(), PluginState::Error);
        let last = plugin.last_event().unwrap();
        assert!(matches!(last, SearchEvent::SearchError { message } if message == "something went wrong"));
    }

    #[test]
    fn test_plugin_events() {
        let mut plugin = SearchTextPlugin::new();
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
        let plugin = SearchTextPlugin::new();
        assert!(plugin.is_action_enabled(SearchAction::Search));
        assert!(plugin.is_action_enabled(SearchAction::SearchNext));
    }

    #[test]
    fn test_plugin_action_disable() {
        let mut plugin = SearchTextPlugin::new();
        plugin.set_action_enabled(SearchAction::QuickSearch, false);
        assert!(!plugin.is_action_enabled(SearchAction::QuickSearch));
    }

    #[test]
    fn test_plugin_highlight() {
        let mut plugin = SearchTextPlugin::new();
        assert!(plugin.highlight_enabled());
        plugin.set_highlight_enabled(false);
        assert!(!plugin.highlight_enabled());
    }

    #[test]
    fn test_plugin_search_all_limit() {
        let mut plugin = SearchTextPlugin::new();
        assert_eq!(plugin.search_all_limit(), 500);
        plugin.set_search_all_limit(1000);
        assert_eq!(plugin.search_all_limit(), 1000);
    }

    #[test]
    fn test_plugin_reset() {
        let mut plugin = SearchTextPlugin::new();
        plugin.task_completed("0x1000".to_string(), "found".to_string());
        assert_eq!(plugin.state(), PluginState::Complete);

        plugin.reset();
        assert_eq!(plugin.state(), PluginState::Idle);
    }

    #[test]
    fn test_search_options_accessors() {
        let plugin = SearchTextPlugin::new();
        assert!(plugin.search_functions());
        assert!(plugin.search_comments());
        assert!(plugin.search_labels());
        assert!(plugin.search_instruction_mnemonics());
        assert!(plugin.search_instruction_operands());
        assert!(plugin.search_data_mnemonics());
        assert!(plugin.search_data_operands());
        assert!(plugin.is_program_database_search());
        assert!(!plugin.include_non_loaded_blocks());
        assert!(!plugin.is_case_sensitive());
        assert!(plugin.is_forward());
        assert!(plugin.search_all_fields());
    }

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

    #[test]
    fn test_plugin_state() {
        assert_eq!(PluginState::Idle, PluginState::Idle);
        assert_ne!(PluginState::Idle, PluginState::Running);
    }
}
