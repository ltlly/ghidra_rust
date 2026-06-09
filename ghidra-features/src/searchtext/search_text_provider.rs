//! Search text provider -- ported from
//! `ghidra.app.plugin.core.searchtext.SearchTextProvider`.
//!
//! The provider manages the search dialog panel within the Ghidra tool.
//! It handles displaying the dialog, managing focus, processing user
//! input, and coordinating with the plugin to execute searches.
//!
//! # Key Types
//!
//! - [`SearchTextProvider`] -- manages the search panel/dialog
//! - [`ProviderState`] -- lifecycle state of the provider
//! - [`SearchPanelConfig`] -- configuration for the search panel

use super::dialog::SearchTextDialog;
use super::search_types::SearchDirection;
use super::SearchOptions;

// ---------------------------------------------------------------------------
// ProviderState
// ---------------------------------------------------------------------------

/// Lifecycle state of the search text provider.
///
/// Tracks whether the provider's UI panel is visible, hidden, or has
/// been disposed (permanently removed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderState {
    /// The provider is initialized but the panel is not yet visible.
    Hidden,
    /// The search panel is visible and active.
    Visible,
    /// The search panel has input focus.
    Focused,
    /// The provider has been disposed and cannot be reused.
    Disposed,
}

impl ProviderState {
    /// Whether the provider is in an active (visible or focused) state.
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Visible | Self::Focused)
    }

    /// Whether the provider has been disposed.
    pub fn is_disposed(&self) -> bool {
        *self == Self::Disposed
    }
}

// ---------------------------------------------------------------------------
// SearchPanelConfig
// ---------------------------------------------------------------------------

/// Configuration for the search panel appearance and behavior.
#[derive(Debug, Clone)]
pub struct SearchPanelConfig {
    /// Whether the panel is initially visible.
    pub initially_visible: bool,
    /// Whether to show the "search all" button.
    pub show_search_all: bool,
    /// Whether to show the direction toggle.
    pub show_direction_toggle: bool,
    /// Whether to show the case-sensitivity toggle.
    pub show_case_sensitive: bool,
    /// Whether to show the search scope selector (database vs listing).
    pub show_scope_selector: bool,
    /// Whether to show the field selection checkboxes.
    pub show_field_selection: bool,
    /// Whether to show the status text area.
    pub show_status: bool,
    /// Whether to close the panel after a successful search.
    pub close_after_search: bool,
    /// Maximum number of items in the search history dropdown.
    pub max_history: usize,
}

impl SearchPanelConfig {
    /// Create a default configuration with all options visible.
    pub fn full() -> Self {
        Self {
            initially_visible: false,
            show_search_all: true,
            show_direction_toggle: true,
            show_case_sensitive: true,
            show_scope_selector: true,
            show_field_selection: true,
            show_status: true,
            close_after_search: false,
            max_history: 50,
        }
    }

    /// Create a minimal configuration (just text input + next/previous).
    pub fn minimal() -> Self {
        Self {
            initially_visible: false,
            show_search_all: false,
            show_direction_toggle: false,
            show_case_sensitive: false,
            show_scope_selector: false,
            show_field_selection: false,
            show_status: false,
            close_after_search: true,
            max_history: 10,
        }
    }
}

impl Default for SearchPanelConfig {
    fn default() -> Self {
        Self::full()
    }
}

// ---------------------------------------------------------------------------
// SearchTextProvider
// ---------------------------------------------------------------------------

/// Provider that manages the search text dialog/panel within the tool.
///
/// Ported from Ghidra's `SearchTextProvider`. This type handles:
/// - Showing/hiding the search panel
/// - Managing search history
/// - Processing user input (text changes, option toggles)
/// - Coordinating with the plugin to start searches
/// - Displaying search status and results
///
/// The provider does not execute searches itself; it delegates to the
/// plugin via callbacks.
#[derive(Debug)]
pub struct SearchTextProvider {
    /// The provider name (used for panel registration).
    name: String,
    /// Current lifecycle state.
    state: ProviderState,
    /// The search dialog (holds user input and options).
    dialog: SearchTextDialog,
    /// Panel configuration.
    config: SearchPanelConfig,
    /// Search text history (most recent first).
    history: Vec<String>,
    /// The owner component name (e.g., "CodeBrowser").
    owner: String,
    /// Whether the panel is docked (vs floating).
    docked: bool,
    /// Status message displayed in the provider.
    status_message: String,
    /// Total matches found in the current search session.
    total_matches: usize,
    /// Current match index (1-based, 0 means no match).
    current_match_index: usize,
}

impl SearchTextProvider {
    /// Create a new search text provider.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Search Text".to_string(),
            state: ProviderState::Hidden,
            dialog: SearchTextDialog::new(),
            config: SearchPanelConfig::default(),
            history: Vec::new(),
            owner: owner.into(),
            docked: true,
            status_message: String::new(),
            total_matches: 0,
            current_match_index: 0,
        }
    }

    /// Create a new provider with a specific configuration.
    pub fn with_config(owner: impl Into<String>, config: SearchPanelConfig) -> Self {
        Self {
            config,
            ..Self::new(owner)
        }
    }

    /// Get the provider name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set the provider name.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    /// Get the owner component name.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Get the current provider state.
    pub fn state(&self) -> ProviderState {
        self.state
    }

    /// Whether the provider panel is currently visible.
    pub fn is_visible(&self) -> bool {
        self.state.is_active()
    }

    /// Whether the provider has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.state.is_disposed()
    }

    // -- Lifecycle --

    /// Show the search panel.
    ///
    /// Transitions from `Hidden` to `Visible` (or `Focused` if the
    /// panel takes focus immediately).
    pub fn show(&mut self) {
        if self.state == ProviderState::Disposed {
            return;
        }
        self.state = ProviderState::Visible;
    }

    /// Show the panel and focus the text input.
    pub fn show_with_focus(&mut self) {
        if self.state == ProviderState::Disposed {
            return;
        }
        self.state = ProviderState::Focused;
    }

    /// Hide the search panel (without disposing).
    pub fn hide(&mut self) {
        if self.state == ProviderState::Disposed {
            return;
        }
        self.state = ProviderState::Hidden;
    }

    /// Toggle panel visibility.
    pub fn toggle(&mut self) {
        if self.state.is_active() {
            self.hide();
        } else {
            self.show();
        }
    }

    /// Dispose the provider (permanent removal).
    ///
    /// After disposal the provider cannot be shown again.
    pub fn dispose(&mut self) {
        self.state = ProviderState::Disposed;
    }

    // -- Dialog delegation --

    /// Get a reference to the search dialog.
    pub fn dialog(&self) -> &SearchTextDialog {
        &self.dialog
    }

    /// Get a mutable reference to the search dialog.
    pub fn dialog_mut(&mut self) -> &mut SearchTextDialog {
        &mut self.dialog
    }

    /// Set the search text in the dialog.
    pub fn set_search_text(&mut self, text: impl Into<String>) {
        self.dialog.set_text(text);
    }

    /// Get the current search text.
    pub fn search_text(&self) -> &str {
        self.dialog.text()
    }

    /// Get the current search options from the dialog.
    pub fn search_options(&self) -> SearchOptions {
        self.dialog.get_search_options()
    }

    // -- History --

    /// Add the current search text to the history.
    ///
    /// Deduplicates: if the text is already in the history, it is moved
    /// to the front.
    pub fn add_to_history(&mut self) {
        let text = self.dialog.text().to_string();
        if text.is_empty() {
            return;
        }
        self.history.retain(|t| t != &text);
        self.history.insert(0, text);
        if self.history.len() > self.config.max_history {
            self.history.truncate(self.config.max_history);
        }
    }

    /// Get the search history.
    pub fn history(&self) -> &[String] {
        &self.history
    }

    /// Clear the search history.
    pub fn clear_history(&mut self) {
        self.history.clear();
    }

    /// Set the search text from a history entry.
    pub fn select_from_history(&mut self, index: usize) -> bool {
        if let Some(text) = self.history.get(index).cloned() {
            self.dialog.set_text(&text);
            true
        } else {
            false
        }
    }

    // -- Status --

    /// Get the status message.
    pub fn status_message(&self) -> &str {
        &self.status_message
    }

    /// Set the status message.
    pub fn set_status_message(&mut self, message: impl Into<String>) {
        let msg = message.into();
        self.status_message = msg.clone();
        self.dialog.set_status_text(&msg);
    }

    /// Update the status to reflect the current search state.
    pub fn update_search_status(&mut self, current: usize, total: usize) {
        self.current_match_index = current;
        self.total_matches = total;
        if total == 0 {
            self.set_status_message("No matches found");
        } else {
            self.set_status_message(format!("Match {} of {}", current, total));
        }
    }

    /// Update the status for a "not found" result.
    pub fn set_not_found_status(&mut self) {
        self.set_status_message("Text not found");
        self.total_matches = 0;
        self.current_match_index = 0;
    }

    /// Update the status for an error.
    pub fn set_error_status(&mut self, message: impl Into<String>) {
        self.set_status_message(format!("Error: {}", message.into()));
    }

    /// Clear the status message.
    pub fn clear_status(&mut self) {
        self.status_message.clear();
    }

    /// Get the total matches found.
    pub fn total_matches(&self) -> usize {
        self.total_matches
    }

    /// Get the current match index (1-based).
    pub fn current_match_index(&self) -> usize {
        self.current_match_index
    }

    // -- Configuration --

    /// Get the panel configuration.
    pub fn config(&self) -> &SearchPanelConfig {
        &self.config
    }

    /// Get a mutable reference to the panel configuration.
    pub fn config_mut(&mut self) -> &mut SearchPanelConfig {
        &mut self.config
    }

    /// Whether the panel is docked.
    pub fn is_docked(&self) -> bool {
        self.docked
    }

    /// Set whether the panel is docked.
    pub fn set_docked(&mut self, docked: bool) {
        self.docked = docked;
    }

    // -- Input processing --

    /// Process a text change from the user (incremental search).
    ///
    /// Returns `true` if the provider should trigger a search.
    pub fn on_text_changed(&mut self, text: &str) -> bool {
        self.dialog.set_text(text);
        // Trigger search if the text is non-empty and we have enough chars.
        !text.is_empty() && text.len() >= 1
    }

    /// Process the user pressing Enter (search next).
    ///
    /// Returns the search options to execute, or `None` if there is no
    /// text to search for.
    pub fn on_search_next(&mut self) -> Option<SearchOptions> {
        let text = self.dialog.text().to_string();
        if text.is_empty() {
            return None;
        }
        self.add_to_history();
        Some(self.dialog.get_search_options())
    }

    /// Process the user requesting search previous.
    ///
    /// Returns the search options with reversed direction, or `None`.
    pub fn on_search_previous(&mut self) -> Option<SearchOptions> {
        let text = self.dialog.text().to_string();
        if text.is_empty() {
            return None;
        }
        self.add_to_history();

        // Build options with reversed direction.
        let base = self.dialog.get_search_options();
        Some(SearchOptions::new(
            base.text(),
            base.is_program_database_search(),
            base.search_functions(),
            base.search_comments(),
            base.search_labels(),
            base.search_instruction_mnemonics(),
            base.search_instruction_operands(),
            base.search_data_mnemonics(),
            base.search_data_operands(),
            base.is_case_sensitive(),
            !base.is_forward(), // reverse direction
            base.include_non_loaded_memory_blocks(),
            base.search_all_fields(),
        ))
    }

    /// Process the user requesting "search all".
    ///
    /// Returns the search options, or `None`.
    pub fn on_search_all(&mut self) -> Option<SearchOptions> {
        let text = self.dialog.text().to_string();
        if text.is_empty() {
            return None;
        }
        self.add_to_history();
        Some(self.dialog.get_search_options())
    }

    /// Process the user toggling case sensitivity.
    pub fn toggle_case_sensitive(&mut self) {
        let current = self.dialog.get_search_options().is_case_sensitive();
        self.dialog.set_case_sensitive(!current);
    }

    /// Process the user toggling search direction.
    pub fn toggle_direction(&mut self) {
        let current = self.dialog.get_search_options().is_forward();
        self.dialog.set_forward(!current);
    }

    /// Process the user toggling database/listing search mode.
    pub fn toggle_search_mode(&mut self) {
        let current = self.dialog.get_search_options().is_program_database_search();
        self.dialog.set_database_search(!current);
    }

    /// Reset the provider state for a new search session.
    pub fn reset(&mut self) {
        self.total_matches = 0;
        self.current_match_index = 0;
        self.status_message.clear();
        self.dialog.set_status_text("");
    }
}

impl Default for SearchTextProvider {
    fn default() -> Self {
        Self::new("default")
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = SearchTextProvider::new("CodeBrowser");
        assert_eq!(provider.name(), "Search Text");
        assert_eq!(provider.owner(), "CodeBrowser");
        assert_eq!(provider.state(), ProviderState::Hidden);
        assert!(!provider.is_visible());
        assert!(!provider.is_disposed());
    }

    #[test]
    fn test_provider_with_config() {
        let config = SearchPanelConfig::minimal();
        let provider = SearchTextProvider::with_config("Test", config);
        assert!(!provider.config().show_search_all);
        assert!(!provider.config().show_field_selection);
        assert!(provider.config().close_after_search);
    }

    #[test]
    fn test_provider_show_hide() {
        let mut provider = SearchTextProvider::new("Test");

        provider.show();
        assert!(provider.is_visible());
        assert_eq!(provider.state(), ProviderState::Visible);

        provider.hide();
        assert!(!provider.is_visible());
        assert_eq!(provider.state(), ProviderState::Hidden);
    }

    #[test]
    fn test_provider_show_with_focus() {
        let mut provider = SearchTextProvider::new("Test");
        provider.show_with_focus();
        assert_eq!(provider.state(), ProviderState::Focused);
        assert!(provider.is_visible());
    }

    #[test]
    fn test_provider_toggle() {
        let mut provider = SearchTextProvider::new("Test");
        assert!(!provider.is_visible());

        provider.toggle();
        assert!(provider.is_visible());

        provider.toggle();
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_provider_dispose() {
        let mut provider = SearchTextProvider::new("Test");
        provider.show();
        assert!(provider.is_visible());

        provider.dispose();
        assert!(provider.is_disposed());

        // Cannot show after dispose.
        provider.show();
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_provider_search_text() {
        let mut provider = SearchTextProvider::new("Test");
        assert_eq!(provider.search_text(), "");

        provider.set_search_text("hello");
        assert_eq!(provider.search_text(), "hello");
    }

    #[test]
    fn test_provider_history() {
        let mut provider = SearchTextProvider::new("Test");

        provider.set_search_text("first");
        provider.add_to_history();
        provider.set_search_text("second");
        provider.add_to_history();
        provider.set_search_text("third");
        provider.add_to_history();

        assert_eq!(provider.history().len(), 3);
        assert_eq!(provider.history()[0], "third");
        assert_eq!(provider.history()[1], "second");
        assert_eq!(provider.history()[2], "first");
    }

    #[test]
    fn test_provider_history_dedup() {
        let mut provider = SearchTextProvider::new("Test");

        provider.set_search_text("hello");
        provider.add_to_history();
        provider.set_search_text("world");
        provider.add_to_history();
        provider.set_search_text("hello");
        provider.add_to_history();

        assert_eq!(provider.history().len(), 2);
        assert_eq!(provider.history()[0], "hello");
        assert_eq!(provider.history()[1], "world");
    }

    #[test]
    fn test_provider_history_max() {
        let config = SearchPanelConfig {
            max_history: 3,
            ..SearchPanelConfig::default()
        };
        let mut provider = SearchTextProvider::with_config("Test", config);

        for i in 0..5 {
            provider.set_search_text(format!("item{}", i));
            provider.add_to_history();
        }

        assert_eq!(provider.history().len(), 3);
        assert_eq!(provider.history()[0], "item4");
    }

    #[test]
    fn test_provider_history_empty_text() {
        let mut provider = SearchTextProvider::new("Test");
        provider.set_search_text("");
        provider.add_to_history();
        assert!(provider.history().is_empty());
    }

    #[test]
    fn test_provider_select_from_history() {
        let mut provider = SearchTextProvider::new("Test");
        provider.set_search_text("hello");
        provider.add_to_history();
        provider.set_search_text("world");
        provider.add_to_history();

        assert!(provider.select_from_history(1));
        assert_eq!(provider.search_text(), "hello");

        assert!(!provider.select_from_history(99));
    }

    #[test]
    fn test_provider_clear_history() {
        let mut provider = SearchTextProvider::new("Test");
        provider.set_search_text("test");
        provider.add_to_history();
        provider.clear_history();
        assert!(provider.history().is_empty());
    }

    #[test]
    fn test_provider_status() {
        let mut provider = SearchTextProvider::new("Test");

        provider.set_status_message("Searching...");
        assert_eq!(provider.status_message(), "Searching...");
        assert_eq!(provider.dialog().status_text(), "Searching...");

        provider.clear_status();
        assert!(provider.status_message().is_empty());
    }

    #[test]
    fn test_provider_update_search_status() {
        let mut provider = SearchTextProvider::new("Test");

        provider.update_search_status(3, 10);
        assert_eq!(provider.total_matches(), 10);
        assert_eq!(provider.current_match_index(), 3);
        assert!(provider.status_message().contains("3"));
        assert!(provider.status_message().contains("10"));

        provider.update_search_status(0, 0);
        assert!(provider.status_message().contains("No matches"));
    }

    #[test]
    fn test_provider_set_not_found_status() {
        let mut provider = SearchTextProvider::new("Test");
        provider.update_search_status(5, 10);
        provider.set_not_found_status();
        assert_eq!(provider.total_matches(), 0);
        assert_eq!(provider.current_match_index(), 0);
        assert!(provider.status_message().contains("not found"));
    }

    #[test]
    fn test_provider_set_error_status() {
        let mut provider = SearchTextProvider::new("Test");
        provider.set_error_status("connection timeout");
        assert!(provider.status_message().contains("Error"));
        assert!(provider.status_message().contains("connection timeout"));
    }

    #[test]
    fn test_provider_on_text_changed() {
        let mut provider = SearchTextProvider::new("Test");
        assert!(!provider.on_text_changed(""));
        assert!(provider.on_text_changed("a"));
        assert!(provider.on_text_changed("abc"));
    }

    #[test]
    fn test_provider_on_search_next() {
        let mut provider = SearchTextProvider::new("Test");
        assert!(provider.on_search_next().is_none());

        provider.set_search_text("hello");
        let opts = provider.on_search_next();
        assert!(opts.is_some());
        assert_eq!(opts.unwrap().text(), "hello");
        assert_eq!(provider.history().len(), 1);
    }

    #[test]
    fn test_provider_on_search_previous() {
        let mut provider = SearchTextProvider::new("Test");
        provider.set_search_text("hello");

        let opts = provider.on_search_previous().unwrap();
        assert_eq!(opts.text(), "hello");
        // Direction should be reversed from the dialog default (forward).
        assert!(!opts.is_forward());
    }

    #[test]
    fn test_provider_on_search_all() {
        let mut provider = SearchTextProvider::new("Test");
        assert!(provider.on_search_all().is_none());

        provider.set_search_text("test");
        let opts = provider.on_search_all();
        assert!(opts.is_some());
    }

    #[test]
    fn test_provider_toggle_case_sensitive() {
        let mut provider = SearchTextProvider::new("Test");
        let initial = provider.search_options().is_case_sensitive();
        provider.toggle_case_sensitive();
        assert_ne!(provider.search_options().is_case_sensitive(), initial);
    }

    #[test]
    fn test_provider_toggle_direction() {
        let mut provider = SearchTextProvider::new("Test");
        let initial = provider.search_options().is_forward();
        provider.toggle_direction();
        assert_ne!(provider.search_options().is_forward(), initial);
    }

    #[test]
    fn test_provider_toggle_search_mode() {
        let mut provider = SearchTextProvider::new("Test");
        let initial = provider.search_options().is_program_database_search();
        provider.toggle_search_mode();
        assert_ne!(
            provider.search_options().is_program_database_search(),
            initial
        );
    }

    #[test]
    fn test_provider_docked() {
        let mut provider = SearchTextProvider::new("Test");
        assert!(provider.is_docked());
        provider.set_docked(false);
        assert!(!provider.is_docked());
    }

    #[test]
    fn test_provider_reset() {
        let mut provider = SearchTextProvider::new("Test");
        provider.update_search_status(5, 10);
        provider.set_status_message("test");

        provider.reset();
        assert_eq!(provider.total_matches(), 0);
        assert_eq!(provider.current_match_index(), 0);
        assert!(provider.status_message().is_empty());
    }

    // -- ProviderState tests --

    #[test]
    fn test_provider_state_active() {
        assert!(ProviderState::Visible.is_active());
        assert!(ProviderState::Focused.is_active());
        assert!(!ProviderState::Hidden.is_active());
        assert!(!ProviderState::Disposed.is_active());
    }

    #[test]
    fn test_provider_state_disposed() {
        assert!(ProviderState::Disposed.is_disposed());
        assert!(!ProviderState::Hidden.is_disposed());
        assert!(!ProviderState::Visible.is_disposed());
    }

    // -- SearchPanelConfig tests --

    #[test]
    fn test_panel_config_full() {
        let config = SearchPanelConfig::full();
        assert!(config.show_search_all);
        assert!(config.show_direction_toggle);
        assert!(config.show_case_sensitive);
        assert!(config.show_scope_selector);
        assert!(config.show_field_selection);
        assert!(config.show_status);
        assert!(!config.close_after_search);
        assert_eq!(config.max_history, 50);
    }

    #[test]
    fn test_panel_config_minimal() {
        let config = SearchPanelConfig::minimal();
        assert!(!config.show_search_all);
        assert!(!config.show_direction_toggle);
        assert!(!config.show_case_sensitive);
        assert!(config.close_after_search);
        assert_eq!(config.max_history, 10);
    }

    #[test]
    fn test_panel_config_default() {
        let config = SearchPanelConfig::default();
        assert!(config.show_search_all);
        assert_eq!(config.max_history, 50);
    }
}
