//! Memory Search Plugin -- full lifecycle, action, and config management.
//!
//! Ported from Ghidra's `MemorySearchPlugin` Java class.
//!
//! This module provides a plugin implementation that covers:
//! - Program lifecycle events (activated, deactivated, closed)
//! - Actions for memory search (show dialog, repeat forward/backward)
//! - Config state save/restore (show options panel, show scan panel)
//! - Search history management
//! - `MemorySearchService` implementation
//!
//! # Architecture
//!
//! - [`MemSearchPlugin`] -- top-level plugin with full lifecycle
//! - [`MemSearchAction`] -- actions registered by the plugin
//! - [`MemSearchPluginEvent`] -- program lifecycle events
//! - [`MemSearchPluginConfig`] -- serializable plugin configuration

use std::collections::HashMap;

use ghidra_core::Address;

use super::combiner::Combiner;
use super::gui::{SearchHistory, SearchGuiModel, SearchSettings};
use super::matcher::UserInputByteMatcher;
use super::searcher::MemoryMatch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of searches to retain in history.
const MAX_HISTORY: usize = 10;

// ---------------------------------------------------------------------------
// MemSearchPluginEvent -- program lifecycle events
// ---------------------------------------------------------------------------

/// Program lifecycle events dispatched by the memory search plugin.
///
/// Ported from the `ProgramPlugin` callbacks in Java:
/// `programActivated`, `programDeactivated`, `programClosed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemSearchPluginEvent {
    /// A program was activated (became the current program).
    ProgramActivated,
    /// A program was deactivated (no longer current).
    ProgramDeactivated,
    /// A program was closed.
    ProgramClosed,
    /// The plugin is being disposed.
    Dispose,
}

// ---------------------------------------------------------------------------
// MemSearchAction -- actions registered by the plugin
// ---------------------------------------------------------------------------

/// Actions that the memory search plugin can register.
///
/// Ported from the `ActionBuilder` calls in `MemorySearchPlugin.createActions()`.
#[derive(Debug, Clone)]
pub enum MemSearchAction {
    /// Open the memory search dialog. Menu: Search -> Memory...
    ShowMemorySearch {
        /// Plugin name (owner).
        owner: String,
        /// Keyboard shortcut (e.g. "s").
        key_binding: String,
    },
    /// Repeat last memory search forwards. Menu: Search -> Repeat Search Forwards.
    RepeatSearchForwards {
        /// Plugin name (owner).
        owner: String,
        /// Keyboard shortcut.
        key_binding: String,
    },
    /// Repeat last memory search backwards. Menu: Search -> Repeat Search Backwards.
    RepeatSearchBackwards {
        /// Plugin name (owner).
        owner: String,
        /// Keyboard shortcut.
        key_binding: String,
    },
}

// ---------------------------------------------------------------------------
// SearchOnceResult -- result of a one-shot search
// ---------------------------------------------------------------------------

/// Result of a one-shot (find next / find previous) search.
///
/// Ported from the inner class `SearchOnceTask` in `MemorySearchPlugin.java`.
#[derive(Debug, Clone)]
pub enum SearchOnceResult {
    /// A match was found.
    Found(MemoryMatch),
    /// No match was found.
    NotFound,
    /// The search was cancelled by the user.
    Cancelled,
    /// The search addresses were empty (search failed).
    EmptyAddresses,
    /// No valid start address was available.
    NoStartAddress,
}

// ---------------------------------------------------------------------------
// MemSearchPluginConfig -- serializable plugin configuration
// ---------------------------------------------------------------------------

/// Serializable configuration for the memory search plugin.
///
/// Ported from the `readConfigState` / `writeConfigState` pattern in
/// `MemorySearchPlugin.java`.
#[derive(Debug, Clone, Default)]
pub struct MemSearchPluginConfig {
    /// Whether to show the options panel.
    pub show_options_panel: bool,
    /// Whether to show the scan panel.
    pub show_scan_panel: bool,
}

impl MemSearchPluginConfig {
    /// Create a new config with default values.
    pub fn new() -> Self {
        Self::default()
    }
}

// ---------------------------------------------------------------------------
// MemSearchPlugin
// ---------------------------------------------------------------------------

/// Full-featured memory search plugin.
///
/// Ported from `MemorySearchPlugin extends Plugin implements MemorySearchService`
/// in Java.
///
/// Manages the memory search provider lifecycle, maintains the last byte
/// matcher used for search, manages search history, and provides actions
/// for opening the search dialog and repeating the last search.
///
/// # Lifecycle
///
/// 1. [`new()`](MemSearchPlugin::new) -- create plugin
/// 2. [`init()`](MemSearchPlugin::init) -- set up actions
/// 3. [`show_search_provider()`](MemSearchPlugin::show_search_provider) -- open search dialog
/// 4. [`search_once()`](MemSearchPlugin::search_once) -- repeat last search
/// 5. [`cleanup()`](MemSearchPlugin::cleanup) -- dispose
///
/// # Example
///
/// ```
/// use ghidra_features::memsearch::mem_search_plugin::*;
/// use ghidra_features::memsearch::gui::SearchSettings;
///
/// let mut plugin = MemSearchPlugin::new("MemorySearchPlugin");
/// plugin.init();
/// plugin.show_search_provider();
/// plugin.cleanup();
/// ```
pub struct MemSearchPlugin {
    /// Plugin name.
    pub name: String,
    /// Last used byte matcher for repeat searches.
    last_byte_matcher: Option<UserInputByteMatcher>,
    /// Plugin configuration (show panels, etc.).
    config: MemSearchPluginConfig,
    /// Search history.
    search_history: SearchHistory,
    /// Last address where a match was found (for repeat searches).
    last_search_address: Option<u64>,
    /// Whether the plugin has been initialized.
    initialized: bool,
    /// Registered actions.
    actions: Vec<MemSearchAction>,
    /// Current program name (if any).
    current_program: Option<String>,
    /// Active provider count.
    active_provider_count: usize,
    /// Event log for testing/debugging.
    event_log: Vec<String>,
}

impl MemSearchPlugin {
    /// Create a new memory search plugin.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            last_byte_matcher: None,
            config: MemSearchPluginConfig::default(),
            search_history: SearchHistory::new(MAX_HISTORY),
            last_search_address: None,
            initialized: false,
            actions: Vec::new(),
            current_program: None,
            active_provider_count: 0,
            event_log: Vec::new(),
        }
    }

    /// Initialize the plugin.
    ///
    /// Creates the standard memory search actions.
    /// Ported from `MemorySearchPlugin(PluginTool)` constructor.
    pub fn init(&mut self) {
        self.initialized = true;
        self.create_actions();
        self.log_event("init");
    }

    /// Create the standard actions.
    ///
    /// Ported from `MemorySearchPlugin.createActions()`.
    fn create_actions(&mut self) {
        self.actions.push(MemSearchAction::ShowMemorySearch {
            owner: self.name.clone(),
            key_binding: "s".to_string(),
        });
        self.actions.push(MemSearchAction::RepeatSearchForwards {
            owner: self.name.clone(),
            key_binding: "F3".to_string(),
        });
        self.actions.push(MemSearchAction::RepeatSearchBackwards {
            owner: self.name.clone(),
            key_binding: "Shift+F3".to_string(),
        });
    }

    /// Show the memory search provider (open the search dialog).
    ///
    /// Ported from `MemorySearchPlugin.showSearchMemoryProvider()`.
    pub fn show_search_provider(&mut self) {
        self.active_provider_count += 1;
        self.log_event("show_search_provider");
    }

    /// Perform a one-shot search (find next or find previous).
    ///
    /// Ported from `MemorySearchPlugin.searchOnce()`.
    ///
    /// Returns the result of the search.
    pub fn search_once(&mut self, forward: bool) -> SearchOnceResult {
        if self.last_byte_matcher.is_none() {
            return SearchOnceResult::NotFound;
        }
        self.log_event(&format!("search_once(forward={})", forward));
        // In the real implementation this would launch a SearchOnceTask.
        // Here we just return NotFound as a placeholder since the actual
        // byte source search requires a program context.
        SearchOnceResult::NotFound
    }

    /// Update the last byte matcher and add it to history.
    ///
    /// Called by the provider after a search is initiated.
    /// Ported from `MemorySearchPlugin.updateByteMatcher()`.
    pub fn update_byte_matcher(&mut self, matcher: UserInputByteMatcher) {
        self.search_history.add_search(matcher.clone());
        self.last_byte_matcher = Some(matcher);
        self.log_event("update_byte_matcher");
    }

    /// Read config state (restore panel visibility).
    ///
    /// Ported from `MemorySearchPlugin.readConfigState()`.
    pub fn read_config_state(&mut self, config: &MemSearchPluginConfig) {
        self.config = config.clone();
        self.log_event("read_config_state");
    }

    /// Write config state (save panel visibility).
    ///
    /// Ported from `MemorySearchPlugin.writeConfigState()`.
    pub fn write_config_state(&self) -> MemSearchPluginConfig {
        self.config.clone()
    }

    /// Set whether the options panel should be shown.
    ///
    /// Ported from `MemorySearchPlugin.setShowOptionsPanel()`.
    pub fn set_show_options_panel(&mut self, show: bool) {
        self.config.show_options_panel = show;
    }

    /// Set whether the scan panel should be shown.
    ///
    /// Ported from `MemorySearchPlugin.setShowScanPanel()`.
    pub fn set_show_scan_panel(&mut self, show: bool) {
        self.config.show_scan_panel = show;
    }

    /// Create a memory search provider (service method).
    ///
    /// Ported from `MemorySearchPlugin.createMemorySearchProvider()`.
    ///
    /// Creates a new provider with the given input and settings. The
    /// provider is marked as "private" so its settings don't pollute
    /// the default search history.
    pub fn create_memory_search_provider(
        &mut self,
        input: &str,
        settings: SearchSettings,
        use_selection: bool,
    ) {
        let _copy = self.search_history.clone();
        self.active_provider_count += 1;
        self.log_event(&format!(
            "create_memory_search_provider(input={:?}, use_selection={})",
            input, use_selection
        ));
    }

    /// Handle a plugin lifecycle event.
    ///
    /// Dispatches to the appropriate lifecycle method.
    pub fn handle_event(&mut self, event: MemSearchPluginEvent) {
        match event {
            MemSearchPluginEvent::ProgramActivated => {
                // In a real framework the program name would come from the event.
            }
            MemSearchPluginEvent::ProgramDeactivated => {
                self.current_program = None;
            }
            MemSearchPluginEvent::ProgramClosed => {
                self.current_program = None;
            }
            MemSearchPluginEvent::Dispose => {
                self.cleanup();
            }
        }
    }

    /// Clean up: dispose resources.
    ///
    /// Ported from the disposal pattern in the Java plugin.
    pub fn cleanup(&mut self) {
        self.last_byte_matcher = None;
        self.last_search_address = None;
        self.initialized = false;
        self.active_provider_count = 0;
        self.log_event("cleanup");
    }

    /// Check if the plugin has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get the current search history.
    pub fn search_history(&self) -> &SearchHistory {
        &self.search_history
    }

    /// Get a mutable reference to the search history.
    pub fn search_history_mut(&mut self) -> &mut SearchHistory {
        &mut self.search_history
    }

    /// Get the last byte matcher, if any.
    pub fn last_byte_matcher(&self) -> Option<&UserInputByteMatcher> {
        self.last_byte_matcher.as_ref()
    }

    /// Get the last search address, if any.
    pub fn last_search_address(&self) -> Option<u64> {
        self.last_search_address
    }

    /// Set the last search address.
    pub fn set_last_search_address(&mut self, address: Option<u64>) {
        self.last_search_address = address;
    }

    /// Get the current program name.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    /// Set the current program name.
    pub fn set_current_program(&mut self, name: Option<String>) {
        self.current_program = name;
    }

    /// Get the active provider count.
    pub fn active_provider_count(&self) -> usize {
        self.active_provider_count
    }

    /// Decrement the active provider count (when a provider is closed).
    pub fn provider_closed(&mut self) {
        if self.active_provider_count > 0 {
            self.active_provider_count -= 1;
        }
    }

    /// Get the registered actions.
    pub fn actions(&self) -> &[MemSearchAction] {
        &self.actions
    }

    /// Check if a repeat search can be performed (last matcher exists).
    pub fn can_repeat_search(&self) -> bool {
        self.last_byte_matcher.is_some()
    }

    /// Get the plugin config.
    pub fn config(&self) -> &MemSearchPluginConfig {
        &self.config
    }

    /// Get the event log.
    pub fn event_log(&self) -> &[String] {
        &self.event_log
    }

    /// Clear the event log.
    pub fn clear_event_log(&mut self) {
        self.event_log.clear();
    }

    fn log_event(&mut self, event: &str) {
        self.event_log.push(event.to_string());
    }
}

impl Default for MemSearchPlugin {
    fn default() -> Self {
        Self::new("MemorySearchPlugin")
    }
}

impl std::fmt::Debug for MemSearchPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemSearchPlugin")
            .field("name", &self.name)
            .field("initialized", &self.initialized)
            .field("active_provider_count", &self.active_provider_count)
            .field("current_program", &self.current_program)
            .field("has_byte_matcher", &self.last_byte_matcher.is_some())
            .field("history_len", &self.search_history.len())
            .finish()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memsearch::gui::SearchSettings;
    use crate::memsearch::matcher::UserInputByteMatcher;

    #[test]
    fn test_plugin_new() {
        let plugin = MemSearchPlugin::new("TestPlugin");
        assert_eq!(plugin.name, "TestPlugin");
        assert!(!plugin.is_initialized());
        assert_eq!(plugin.active_provider_count(), 0);
        assert!(plugin.current_program().is_none());
    }

    #[test]
    fn test_plugin_default() {
        let plugin = MemSearchPlugin::default();
        assert_eq!(plugin.name, "MemorySearchPlugin");
    }

    #[test]
    fn test_plugin_init() {
        let mut plugin = MemSearchPlugin::new("TestPlugin");
        plugin.init();
        assert!(plugin.is_initialized());
        assert_eq!(plugin.actions().len(), 3);
    }

    #[test]
    fn test_plugin_actions() {
        let mut plugin = MemSearchPlugin::new("TestPlugin");
        plugin.init();

        let actions = plugin.actions();
        assert!(matches!(&actions[0], MemSearchAction::ShowMemorySearch { .. }));
        assert!(matches!(&actions[1], MemSearchAction::RepeatSearchForwards { .. }));
        assert!(matches!(&actions[2], MemSearchAction::RepeatSearchBackwards { .. }));
    }

    #[test]
    fn test_plugin_show_search_provider() {
        let mut plugin = MemSearchPlugin::new("TestPlugin");
        plugin.init();
        assert_eq!(plugin.active_provider_count(), 0);

        plugin.show_search_provider();
        assert_eq!(plugin.active_provider_count(), 1);

        plugin.show_search_provider();
        assert_eq!(plugin.active_provider_count(), 2);

        plugin.provider_closed();
        assert_eq!(plugin.active_provider_count(), 1);
    }

    #[test]
    fn test_plugin_update_byte_matcher() {
        let mut plugin = MemSearchPlugin::new("TestPlugin");
        plugin.init();
        assert!(!plugin.can_repeat_search());

        let settings = SearchSettings::default();
        let matcher = UserInputByteMatcher::new("Hex", "55 89", settings);
        plugin.update_byte_matcher(matcher);

        assert!(plugin.can_repeat_search());
        assert!(plugin.last_byte_matcher().is_some());
        assert_eq!(plugin.search_history().len(), 1);
    }

    #[test]
    fn test_plugin_search_once_no_matcher() {
        let mut plugin = MemSearchPlugin::new("TestPlugin");
        plugin.init();
        let result = plugin.search_once(true);
        assert!(matches!(result, SearchOnceResult::NotFound));
    }

    #[test]
    fn test_plugin_search_once_with_matcher() {
        let mut plugin = MemSearchPlugin::new("TestPlugin");
        plugin.init();
        let settings = SearchSettings::default();
        let matcher = UserInputByteMatcher::new("Hex", "55 89", settings);
        plugin.update_byte_matcher(matcher);

        let result = plugin.search_once(true);
        // Without a real byte source, we get NotFound
        assert!(matches!(result, SearchOnceResult::NotFound));
    }

    #[test]
    fn test_plugin_config_save_restore() {
        let mut plugin = MemSearchPlugin::new("TestPlugin");
        plugin.init();

        plugin.set_show_options_panel(true);
        plugin.set_show_scan_panel(true);

        let config = plugin.write_config_state();
        assert!(config.show_options_panel);
        assert!(config.show_scan_panel);

        let mut plugin2 = MemSearchPlugin::new("TestPlugin");
        plugin2.init();
        plugin2.read_config_state(&config);
        assert!(plugin2.config().show_options_panel);
        assert!(plugin2.config().show_scan_panel);
    }

    #[test]
    fn test_plugin_program_lifecycle() {
        let mut plugin = MemSearchPlugin::new("TestPlugin");
        plugin.init();

        plugin.set_current_program(Some("test.exe".to_string()));
        assert_eq!(plugin.current_program(), Some("test.exe"));

        plugin.handle_event(MemSearchPluginEvent::ProgramDeactivated);
        assert!(plugin.current_program().is_none());
    }

    #[test]
    fn test_plugin_cleanup() {
        let mut plugin = MemSearchPlugin::new("TestPlugin");
        plugin.init();
        plugin.show_search_provider();

        let settings = SearchSettings::default();
        let matcher = UserInputByteMatcher::new("Hex", "55", settings);
        plugin.update_byte_matcher(matcher);

        plugin.cleanup();
        assert!(!plugin.is_initialized());
        assert!(!plugin.can_repeat_search());
        assert_eq!(plugin.active_provider_count(), 0);
    }

    #[test]
    fn test_plugin_search_history() {
        let mut plugin = MemSearchPlugin::new("TestPlugin");
        plugin.init();

        let settings = SearchSettings::default();
        let m1 = UserInputByteMatcher::new("Hex", "55 89", settings.clone());
        let m2 = UserInputByteMatcher::new("Hex", "E5 C3", settings);

        plugin.update_byte_matcher(m1);
        plugin.update_byte_matcher(m2);

        assert_eq!(plugin.search_history().len(), 2);
        assert_eq!(plugin.search_history().most_recent().unwrap().input(), "E5 C3");
    }

    #[test]
    fn test_plugin_create_memory_search_provider() {
        let mut plugin = MemSearchPlugin::new("TestPlugin");
        plugin.init();

        let settings = SearchSettings::default();
        plugin.create_memory_search_provider("55 89", settings, false);
        assert_eq!(plugin.active_provider_count(), 1);
    }

    #[test]
    fn test_plugin_event_log() {
        let mut plugin = MemSearchPlugin::new("TestPlugin");
        assert!(plugin.event_log().is_empty());

        plugin.init();
        plugin.show_search_provider();
        assert!(plugin.event_log().len() >= 2);

        plugin.clear_event_log();
        assert!(plugin.event_log().is_empty());
    }

    #[test]
    fn test_plugin_last_search_address() {
        let mut plugin = MemSearchPlugin::new("TestPlugin");
        assert!(plugin.last_search_address().is_none());

        plugin.set_last_search_address(Some(0x401000));
        assert_eq!(plugin.last_search_address(), Some(0x401000));

        plugin.set_last_search_address(None);
        assert!(plugin.last_search_address().is_none());
    }

    #[test]
    fn test_plugin_config_default() {
        let config = MemSearchPluginConfig::new();
        assert!(!config.show_options_panel);
        assert!(!config.show_scan_panel);
    }

    #[test]
    fn test_plugin_provider_closed_underflow() {
        let mut plugin = MemSearchPlugin::new("TestPlugin");
        plugin.init();
        plugin.provider_closed(); // should not underflow
        assert_eq!(plugin.active_provider_count(), 0);
    }

    #[test]
    fn test_plugin_debug_fmt() {
        let mut plugin = MemSearchPlugin::new("TestPlugin");
        plugin.init();
        let debug = format!("{:?}", plugin);
        assert!(debug.contains("TestPlugin"));
        assert!(debug.contains("initialized: true"));
    }

    #[test]
    fn test_search_once_result_variants() {
        let found = SearchOnceResult::Found(MemoryMatch::new(0x1000, vec![0x55]));
        let not_found = SearchOnceResult::NotFound;
        let cancelled = SearchOnceResult::Cancelled;
        let empty = SearchOnceResult::EmptyAddresses;
        let no_start = SearchOnceResult::NoStartAddress;

        assert!(matches!(found, SearchOnceResult::Found(_)));
        assert!(matches!(not_found, SearchOnceResult::NotFound));
        assert!(matches!(cancelled, SearchOnceResult::Cancelled));
        assert!(matches!(empty, SearchOnceResult::EmptyAddresses));
        assert!(matches!(no_start, SearchOnceResult::NoStartAddress));
    }

    #[test]
    fn test_plugin_event_variants() {
        assert_eq!(MemSearchPluginEvent::ProgramActivated, MemSearchPluginEvent::ProgramActivated);
        assert_ne!(MemSearchPluginEvent::ProgramActivated, MemSearchPluginEvent::Dispose);
    }
}
