//! Instruction Search Plugin -- top-level plugin coordinating the
//! instruction search feature.
//!
//! Ported from Ghidra's
//! `ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin` Java class.
//!
//! Manages the full plugin lifecycle: program open/close, action
//! registration, provider management, and search coordination.  This is
//! the enhanced version that builds on the lightweight model in
//! [`super::search_all_task::InstructionSearchPlugin`] by adding:
//!
//! - Program lifecycle event handling
//! - Action context support (is-enabled / is-active for popup menus)
//! - Provider visibility coordination
//! - Search history and cancellation
//! - Configuration persistence hooks

use super::instruction_search_provider::InstructionSearchProvider;
use super::search_all_task::{BytePatternSearchTask, InstructionSearchDialog, SearchTaskStatus};
use super::{
    InstructionSearchData, SearchFormat, SearchOptions, SearchResult, SearchDirection,
};
use ghidra_core::Address;

// ---------------------------------------------------------------------------
// SearchMode -- what kind of search is active
// ---------------------------------------------------------------------------

/// The current search mode of the plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SearchMode {
    /// No search is running.
    Idle,
    /// Building a pattern from selected instructions.
    BuildingPattern,
    /// Searching the program for a byte pattern.
    Searching,
    /// Previewing matches before committing.
    Previewing,
}

impl Default for SearchMode {
    fn default() -> Self {
        SearchMode::Idle
    }
}

// ---------------------------------------------------------------------------
// PluginConfig -- persisted configuration
// ---------------------------------------------------------------------------

/// Configuration options for the instruction search plugin.
///
/// These correspond to the Ghidra tool options that the Java plugin
/// registers via `Options` / `ToolOptions`.
#[derive(Debug, Clone)]
pub struct PluginConfig {
    /// Default search format.
    pub default_format: SearchFormat,
    /// Default search direction.
    pub default_direction: SearchDirection,
    /// Whether to restrict search to the current selection by default.
    pub default_selection_only: bool,
    /// Whether to align matches to instruction boundaries.
    pub align_to_instructions: bool,
    /// Maximum number of results to collect before stopping.
    pub max_results: usize,
    /// Whether to display byte values in big-endian order.
    pub big_endian_display: bool,
    /// Maximum number of recent search patterns to remember.
    pub max_history: usize,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            default_format: SearchFormat::Hex,
            default_direction: SearchDirection::Forward,
            default_selection_only: false,
            align_to_instructions: true,
            max_results: 10_000,
            big_endian_display: false,
            max_history: 20,
        }
    }
}

// ---------------------------------------------------------------------------
// SearchHistoryEntry
// ---------------------------------------------------------------------------

/// A single entry in the search history.
#[derive(Debug, Clone)]
pub struct SearchHistoryEntry {
    /// The search pattern as a hex string.
    pub pattern_hex: String,
    /// The search format used.
    pub format: SearchFormat,
    /// Number of matches found.
    pub match_count: usize,
    /// Whether the search was cancelled.
    pub cancelled: bool,
}

// ---------------------------------------------------------------------------
// PluginState -- aggregated lifecycle state
// ---------------------------------------------------------------------------

/// Aggregated lifecycle state of the plugin.
///
/// Tracks whether a program is open, whether a search is active, and
/// what the provider is currently showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PluginState {
    /// Plugin is initialized but no program is open.
    NoProgram,
    /// A program is open and the plugin is idle.
    Ready,
    /// A search is in progress.
    Searching,
    /// The provider is displaying preview results.
    Previewing,
    /// The plugin has been disposed.
    Disposed,
}

impl Default for PluginState {
    fn default() -> Self {
        PluginState::NoProgram
    }
}

// ---------------------------------------------------------------------------
// InstructionSearchPluginFull
// ---------------------------------------------------------------------------

/// Full-featured instruction search plugin.
///
/// Ported from the complete `InstructionSearchPlugin` Java class including
/// program lifecycle management, action context support, provider
/// coordination, and search history.
///
/// This complements the lightweight [`super::search_all_task::InstructionSearchPlugin`]
/// model by adding the operational lifecycle that the Java plugin manages.
#[derive(Debug)]
pub struct InstructionSearchPluginFull {
    /// Plugin name.
    name: String,
    /// Current lifecycle state.
    state: PluginState,
    /// Whether the plugin is enabled.
    enabled: bool,
    /// Plugin configuration.
    config: PluginConfig,
    /// The provider (if created).
    provider: Option<InstructionSearchProvider>,
    /// Current search mode.
    search_mode: SearchMode,
    /// Current search dialog state.
    dialog: InstructionSearchDialog,
    /// Active search task (if searching).
    active_task: Option<BytePatternSearchTask>,
    /// Search history (most recent first).
    history: Vec<SearchHistoryEntry>,
    /// Current program name (if a program is open).
    current_program: Option<String>,
    /// Current program address range (start, end).
    program_range: Option<(Address, Address)>,
    /// Total number of searches performed.
    search_count: usize,
    /// Total matches found across all searches.
    total_matches: usize,
    /// Whether the provider should be shown on next activation.
    show_provider_on_activate: bool,
}

impl InstructionSearchPluginFull {
    /// Create a new plugin in the initial (no-program) state.
    pub fn new() -> Self {
        Self {
            name: "InstructionSearch".into(),
            state: PluginState::NoProgram,
            enabled: true,
            config: PluginConfig::default(),
            provider: None,
            search_mode: SearchMode::Idle,
            dialog: InstructionSearchDialog::new(),
            active_task: None,
            history: Vec::new(),
            current_program: None,
            program_range: None,
            search_count: 0,
            total_matches: 0,
            show_provider_on_activate: false,
        }
    }

    /// Create a plugin with custom configuration.
    pub fn with_config(config: PluginConfig) -> Self {
        let mut plugin = Self::new();
        plugin.config = config;
        plugin
    }

    // -- Accessors -----------------------------------------------------------

    /// Get the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the current lifecycle state.
    pub fn state(&self) -> PluginState {
        self.state
    }

    /// Whether the plugin is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set whether the plugin is enabled.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get the plugin configuration.
    pub fn config(&self) -> &PluginConfig {
        &self.config
    }

    /// Get a mutable reference to the plugin configuration.
    pub fn config_mut(&mut self) -> &mut PluginConfig {
        &mut self.config
    }

    /// Get the current search mode.
    pub fn search_mode(&self) -> SearchMode {
        self.search_mode
    }

    /// Get the current program name, if any.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    /// Get the current program address range, if known.
    pub fn program_range(&self) -> Option<(Address, Address)> {
        self.program_range
    }

    /// Get the search history.
    pub fn history(&self) -> &[SearchHistoryEntry] {
        &self.history
    }

    /// Get total searches performed.
    pub fn search_count(&self) -> usize {
        self.search_count
    }

    /// Get total matches found.
    pub fn total_matches(&self) -> usize {
        self.total_matches
    }

    /// Get a reference to the provider, if created.
    pub fn provider(&self) -> Option<&InstructionSearchProvider> {
        self.provider.as_ref()
    }

    /// Get a mutable reference to the provider, if created.
    pub fn provider_mut(&mut self) -> Option<&mut InstructionSearchProvider> {
        self.provider.as_mut()
    }

    /// Get a reference to the current dialog state.
    pub fn dialog(&self) -> &InstructionSearchDialog {
        &self.dialog
    }

    /// Get a mutable reference to the current dialog state.
    pub fn dialog_mut(&mut self) -> &mut InstructionSearchDialog {
        &mut self.dialog
    }

    /// Whether a search is currently active.
    pub fn is_searching(&self) -> bool {
        self.search_mode == SearchMode::Searching
    }

    /// Whether the plugin can accept a new search.
    pub fn can_search(&self) -> bool {
        self.state == PluginState::Ready && !self.is_searching()
    }

    // -- Lifecycle -----------------------------------------------------------

    /// Called when a program is opened.
    ///
    /// Ported from `InstructionSearchPlugin.programOpened(Program)`.
    pub fn program_opened(&mut self, program_name: impl Into<String>, start: Address, end: Address) {
        self.current_program = Some(program_name.into());
        self.program_range = Some((start, end));
        self.state = PluginState::Ready;
    }

    /// Called when the current program is closed.
    ///
    /// Ported from `InstructionSearchPlugin.programClosed(Program)`.
    pub fn program_closed(&mut self) {
        self.current_program = None;
        self.program_range = None;
        self.cancel_active_search();
        self.dialog = InstructionSearchDialog::new();
        self.state = PluginState::NoProgram;
        if let Some(provider) = &mut self.provider {
            provider.clear();
        }
    }

    /// Called when the plugin is activated (provider becomes visible).
    ///
    /// Ported from `InstructionSearchPlugin.providerActivated()`.
    pub fn provider_activated(&mut self) {
        if self.provider.is_none() {
            self.provider = Some(InstructionSearchProvider::new());
        }
        if let Some(provider) = &mut self.provider {
            provider.set_visible(true);
        }
    }

    /// Called when the plugin is deactivated (provider hidden).
    ///
    /// Ported from `InstructionSearchPlugin.providerDeactivated()`.
    pub fn provider_deactivated(&mut self) {
        if let Some(provider) = &mut self.provider {
            provider.set_visible(false);
        }
    }

    /// Dispose of the plugin, releasing all resources.
    ///
    /// Ported from `InstructionSearchPlugin.dispose()`.
    pub fn dispose(&mut self) {
        self.cancel_active_search();
        self.provider = None;
        self.dialog = InstructionSearchDialog::new();
        self.history.clear();
        self.state = PluginState::Disposed;
    }

    // -- Search coordination -------------------------------------------------

    /// Open the search dialog with default options from the config.
    ///
    /// Ported from `InstructionSearchPlugin.openSearchDialog()`.
    pub fn open_search_dialog(&mut self) {
        self.dialog = InstructionSearchDialog::new();
        self.dialog.options.format = self.config.default_format;
        self.dialog.options.search_forward =
            self.config.default_direction == SearchDirection::Forward;
        self.dialog.options.selection_only = self.config.default_selection_only;
        self.dialog.options.align_to_instructions = self.config.align_to_instructions;
        self.dialog.open();
        // Snapshot config values before borrowing self.provider.
        let has_provider = self.provider.is_some();
        if has_provider {
            self.provider.as_mut().unwrap().set_dialog_open(true);
        }
    }

    /// Close the search dialog.
    pub fn close_search_dialog(&mut self) {
        self.dialog.close();
        if let Some(provider) = &mut self.provider {
            provider.set_dialog_open(false);
        }
    }

    /// Set the search pattern in the dialog.
    pub fn set_search_pattern(&mut self, bytes: Vec<u8>, mask: Vec<u8>) {
        self.dialog.set_pattern(bytes, mask);
    }

    /// Initiate a search using the current dialog state and program range.
    ///
    /// Returns `true` if the search was started.
    pub fn initiate_search(&mut self) -> bool {
        if !self.can_search() {
            return false;
        }
        if !self.dialog.initiate_search() {
            return false;
        }

        let (start, end) = self.program_range.unwrap_or((Address::new(0), Address::new(0)));
        if let Some(task) = self.dialog.create_task(start, end) {
            self.active_task = Some(task);
            self.search_mode = SearchMode::Searching;
            self.state = PluginState::Searching;
            if let Some(ref mut task) = self.active_task {
                task.start();
            }
            true
        } else {
            false
        }
    }

    /// Execute the active search over the given byte data.
    ///
    /// Returns the number of matches found, or 0 if no search is active.
    pub fn execute_search(&mut self, data: &[u8]) -> usize {
        if self.active_task.is_none() {
            return 0;
        }
        let count = self.active_task.as_mut().unwrap().search_in_bytes(data);
        let cancelled = self.active_task.as_ref().unwrap().status == SearchTaskStatus::Cancelled;
        self.record_search_result(count, cancelled);
        count
    }

    /// Cancel the active search, if any.
    pub fn cancel_active_search(&mut self) {
        let match_count = if let Some(task) = &mut self.active_task {
            task.cancel();
            task.match_count()
        } else {
            0
        };
        if match_count > 0 || self.active_task.is_some() {
            self.record_search_result(match_count, true);
        }
        self.active_task = None;
        self.search_mode = SearchMode::Idle;
        if self.state == PluginState::Searching {
            self.state = PluginState::Ready;
        }
    }

    /// Get the progress of the active search (0.0 to 1.0).
    pub fn search_progress(&self) -> f64 {
        self.active_task
            .as_ref()
            .map(|t| t.progress())
            .unwrap_or(1.0)
    }

    /// Get the results of the most recent search.
    pub fn search_results(&self) -> &[SearchResult] {
        self.active_task
            .as_ref()
            .map(|t| t.results.as_slice())
            .unwrap_or(&[])
    }

    /// Get the number of matches from the active task.
    pub fn active_match_count(&self) -> usize {
        self.active_task
            .as_ref()
            .map(|t| t.match_count())
            .unwrap_or(0)
    }

    // -- History -------------------------------------------------------------

    /// Record a completed search in the history.
    fn record_search_result(&mut self, match_count: usize, cancelled: bool) {
        self.search_count += 1;
        self.total_matches += match_count;

        let pattern_hex = format!("{:02X?}", self.dialog.search_bytes);
        self.history.insert(
            0,
            SearchHistoryEntry {
                pattern_hex,
                format: self.dialog.options.format,
                match_count,
                cancelled,
            },
        );
        if self.history.len() > self.config.max_history {
            self.history.truncate(self.config.max_history);
        }
    }

    /// Clear the search history.
    pub fn clear_history(&mut self) {
        self.history.clear();
    }

    // -- Action context (for UI enablement) ----------------------------------

    /// Whether the "Search" action should be enabled.
    ///
    /// Ported from `InstructionSearchPlugin.isSearchEnabled()`.
    pub fn is_search_action_enabled(&self) -> bool {
        self.can_search() && !self.dialog.search_bytes.is_empty()
    }

    /// Whether the "Cancel" action should be enabled.
    pub fn is_cancel_action_enabled(&self) -> bool {
        self.is_searching()
    }

    /// Whether the "Clear" action should be enabled.
    pub fn is_clear_action_enabled(&self) -> bool {
        !self.dialog.search_bytes.is_empty() || !self.history.is_empty()
    }

    // -- Provider interaction ------------------------------------------------

    /// Update the provider with the latest search state.
    pub fn update_provider(&mut self) {
        let mode = self.search_mode;
        let count = self.active_match_count();
        let searching = self.is_searching();
        if let Some(provider) = &mut self.provider {
            provider.set_search_mode(mode);
            provider.set_match_count(count);
            provider.set_searching(searching);
        }
    }
}

impl Default for InstructionSearchPluginFull {
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

    #[test]
    fn test_plugin_new() {
        let plugin = InstructionSearchPluginFull::new();
        assert_eq!(plugin.name(), "InstructionSearch");
        assert_eq!(plugin.state(), PluginState::NoProgram);
        assert!(plugin.is_enabled());
        assert_eq!(plugin.search_count(), 0);
        assert_eq!(plugin.total_matches(), 0);
        assert!(plugin.current_program().is_none());
        assert!(plugin.provider().is_none());
        assert_eq!(plugin.search_mode(), SearchMode::Idle);
    }

    #[test]
    fn test_plugin_with_config() {
        let config = PluginConfig {
            max_results: 500,
            max_history: 5,
            big_endian_display: true,
            ..PluginConfig::default()
        };
        let plugin = InstructionSearchPluginFull::with_config(config);
        assert_eq!(plugin.config().max_results, 500);
        assert_eq!(plugin.config().max_history, 5);
        assert!(plugin.config().big_endian_display);
    }

    #[test]
    fn test_plugin_program_lifecycle() {
        let mut plugin = InstructionSearchPluginFull::new();
        assert_eq!(plugin.state(), PluginState::NoProgram);

        plugin.program_opened("test.exe", Address::new(0x400000), Address::new(0x500000));
        assert_eq!(plugin.state(), PluginState::Ready);
        assert_eq!(plugin.current_program(), Some("test.exe"));
        assert_eq!(
            plugin.program_range(),
            Some((Address::new(0x400000), Address::new(0x500000)))
        );

        plugin.program_closed();
        assert_eq!(plugin.state(), PluginState::NoProgram);
        assert!(plugin.current_program().is_none());
        assert!(plugin.program_range().is_none());
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = InstructionSearchPluginFull::new();
        plugin.program_opened("test.exe", Address::new(0x0), Address::new(0x100));
        plugin.dispose();
        assert_eq!(plugin.state(), PluginState::Disposed);
        assert!(plugin.provider().is_none());
    }

    #[test]
    fn test_plugin_provider_activation() {
        let mut plugin = InstructionSearchPluginFull::new();
        assert!(plugin.provider().is_none());

        plugin.provider_activated();
        assert!(plugin.provider().is_some());
        assert!(plugin.provider().unwrap().is_visible());

        plugin.provider_deactivated();
        assert!(!plugin.provider().unwrap().is_visible());
    }

    #[test]
    fn test_plugin_open_search_dialog() {
        let mut plugin = InstructionSearchPluginFull::new();
        plugin.program_opened("test.exe", Address::new(0x0), Address::new(0x100));
        plugin.provider_activated();

        plugin.open_search_dialog();
        assert!(plugin.dialog().is_open);
        assert!(plugin.provider().unwrap().is_dialog_open());
    }

    #[test]
    fn test_plugin_close_search_dialog() {
        let mut plugin = InstructionSearchPluginFull::new();
        plugin.program_opened("test.exe", Address::new(0x0), Address::new(0x100));
        plugin.provider_activated();
        plugin.open_search_dialog();
        plugin.close_search_dialog();
        assert!(!plugin.dialog().is_open);
    }

    #[test]
    fn test_plugin_initiate_search() {
        let mut plugin = InstructionSearchPluginFull::new();
        plugin.program_opened("test.exe", Address::new(0x0), Address::new(0x100));

        // Cannot search with empty pattern.
        assert!(!plugin.initiate_search());

        plugin.set_search_pattern(vec![0x90], vec![0xFF]);
        assert!(plugin.initiate_search());
        assert_eq!(plugin.search_mode(), SearchMode::Searching);
        assert!(plugin.is_searching());
    }

    #[test]
    fn test_plugin_execute_search() {
        let mut plugin = InstructionSearchPluginFull::new();
        plugin.program_opened("test.exe", Address::new(0x0), Address::new(0x100));
        plugin.set_search_pattern(vec![0x90, 0xC3], vec![0xFF, 0xFF]);
        plugin.initiate_search();

        let data = vec![0x00, 0x90, 0xC3, 0x00];
        let count = plugin.execute_search(&data);
        assert_eq!(count, 1);
        assert_eq!(plugin.search_count(), 1);
        assert_eq!(plugin.total_matches(), 1);
    }

    #[test]
    fn test_plugin_cancel_search() {
        let mut plugin = InstructionSearchPluginFull::new();
        plugin.program_opened("test.exe", Address::new(0x0), Address::new(0x100));
        plugin.set_search_pattern(vec![0x90], vec![0xFF]);
        plugin.initiate_search();

        plugin.cancel_active_search();
        assert!(!plugin.is_searching());
        assert_eq!(plugin.search_mode(), SearchMode::Idle);
    }

    #[test]
    fn test_plugin_search_history() {
        let mut plugin = InstructionSearchPluginFull::new();
        plugin.program_opened("test.exe", Address::new(0x0), Address::new(0x100));

        plugin.set_search_pattern(vec![0x90], vec![0xFF]);
        plugin.initiate_search();
        plugin.execute_search(&[0x90, 0x00]);

        assert_eq!(plugin.history().len(), 1);
        assert_eq!(plugin.history()[0].match_count, 1);

        plugin.clear_history();
        assert!(plugin.history().is_empty());
    }

    #[test]
    fn test_plugin_history_max() {
        let config = PluginConfig {
            max_history: 2,
            ..PluginConfig::default()
        };
        let mut plugin = InstructionSearchPluginFull::with_config(config);
        plugin.program_opened("test.exe", Address::new(0x0), Address::new(0x100));

        for i in 0..3 {
            plugin.set_search_pattern(vec![i], vec![0xFF]);
            plugin.initiate_search();
            plugin.execute_search(&[i, 0x00]);
            plugin.active_task = None;
            plugin.search_mode = SearchMode::Idle;
            plugin.state = PluginState::Ready;
        }

        assert_eq!(plugin.history().len(), 2);
    }

    #[test]
    fn test_plugin_action_context() {
        let mut plugin = InstructionSearchPluginFull::new();
        plugin.program_opened("test.exe", Address::new(0x0), Address::new(0x100));

        // No pattern set -> search action disabled.
        assert!(!plugin.is_search_action_enabled());
        assert!(!plugin.is_cancel_action_enabled());
        assert!(!plugin.is_clear_action_enabled());

        plugin.set_search_pattern(vec![0x90], vec![0xFF]);
        assert!(plugin.is_search_action_enabled());
        assert!(plugin.is_clear_action_enabled());

        plugin.initiate_search();
        assert!(plugin.is_cancel_action_enabled());
        assert!(!plugin.is_search_action_enabled()); // busy
    }

    #[test]
    fn test_plugin_can_search_requires_ready() {
        let mut plugin = InstructionSearchPluginFull::new();
        // No program -> cannot search.
        assert!(!plugin.can_search());

        plugin.program_opened("test.exe", Address::new(0x0), Address::new(0x100));
        assert!(plugin.can_search());

        plugin.dispose();
        assert!(!plugin.can_search());
    }

    #[test]
    fn test_search_mode_default() {
        assert_eq!(SearchMode::default(), SearchMode::Idle);
    }

    #[test]
    fn test_plugin_state_default() {
        assert_eq!(PluginState::default(), PluginState::NoProgram);
    }

    #[test]
    fn test_plugin_config_default() {
        let config = PluginConfig::default();
        assert_eq!(config.default_format, SearchFormat::Hex);
        assert_eq!(config.default_direction, SearchDirection::Forward);
        assert!(!config.default_selection_only);
        assert!(config.align_to_instructions);
        assert_eq!(config.max_results, 10_000);
        assert!(!config.big_endian_display);
        assert_eq!(config.max_history, 20);
    }

    #[test]
    fn test_plugin_search_progress_default() {
        let plugin = InstructionSearchPluginFull::new();
        assert!((plugin.search_progress() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_plugin_search_results_empty() {
        let plugin = InstructionSearchPluginFull::new();
        assert!(plugin.search_results().is_empty());
    }

    #[test]
    fn test_plugin_update_provider() {
        let mut plugin = InstructionSearchPluginFull::new();
        plugin.program_opened("test.exe", Address::new(0x0), Address::new(0x100));
        plugin.provider_activated();
        plugin.set_search_pattern(vec![0x90], vec![0xFF]);
        plugin.initiate_search();
        plugin.update_provider();

        let provider = plugin.provider().unwrap();
        assert!(provider.is_searching());
        assert_eq!(provider.search_mode(), SearchMode::Searching);
    }
}
