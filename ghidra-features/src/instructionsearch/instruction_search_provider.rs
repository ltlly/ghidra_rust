//! Instruction Search Provider -- manages the instruction search UI panel.
//!
//! Ported from Ghidra's
//! `ghidra.app.plugin.core.instructionsearch.InstructionSearchProvider`
//! Java class.
//!
//! The provider manages the visibility and state of the instruction
//! search panel within the Ghidra tool.  It handles:
//!
//! - Showing / hiding the search panel
//! - Displaying the current search state (idle, building, searching)
//! - Managing the instruction table display
//! - Displaying match results and progress
//! - Coordinating endianness and format display options

use super::instruction_search_plugin::SearchMode;
use super::panel::{DisplayEndian, InstructionSearchPanelModel, SearchPanelMode, SelectionMode};
use super::SearchFormat;
use ghidra_core::Address;

// ---------------------------------------------------------------------------
// ProviderVisibility -- visibility state
// ---------------------------------------------------------------------------

/// Visibility state of the instruction search provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderVisibility {
    /// The provider panel is hidden.
    Hidden,
    /// The provider panel is visible.
    Visible,
    /// The provider panel has focus.
    Focused,
    /// The provider has been disposed.
    Disposed,
}

impl ProviderVisibility {
    /// Whether the provider is visible (Visible or Focused).
    pub fn is_active(&self) -> bool {
        matches!(self, ProviderVisibility::Visible | ProviderVisibility::Focused)
    }

    /// Whether the provider has been disposed.
    pub fn is_disposed(&self) -> bool {
        *self == ProviderVisibility::Disposed
    }
}

impl Default for ProviderVisibility {
    fn default() -> Self {
        ProviderVisibility::Hidden
    }
}

// ---------------------------------------------------------------------------
// DisplayState -- what the provider is currently showing
// ---------------------------------------------------------------------------

/// The display state of the instruction search provider.
///
/// Tracks what the panel is currently presenting to the user.
#[derive(Debug)]
pub struct DisplayState {
    /// The current panel model.
    pub panel: InstructionSearchPanelModel,
    /// The number of matches currently displayed.
    pub match_count: usize,
    /// Whether a search is in progress.
    pub searching: bool,
    /// Progress of the current search (0.0 to 1.0).
    pub search_progress: f64,
    /// Status message to display.
    pub status_message: String,
    /// Whether the dialog is currently open.
    pub dialog_open: bool,
    /// Current program name (shown in the title bar).
    pub program_name: Option<String>,
    /// Current search address range label.
    pub range_label: String,
}

impl DisplayState {
    /// Create a new display state with defaults.
    pub fn new() -> Self {
        Self {
            panel: InstructionSearchPanelModel::new(),
            match_count: 0,
            searching: false,
            search_progress: 0.0,
            status_message: String::new(),
            dialog_open: false,
            program_name: None,
            range_label: "Full Program".into(),
        }
    }
}

impl Default for DisplayState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// InstructionSearchProvider
// ---------------------------------------------------------------------------

/// Provider for the instruction search panel.
///
/// Ported from Ghidra's `InstructionSearchProvider`.  Manages the
/// lifecycle and display state of the instruction search UI component.
///
/// In the Java original, this extends `ComponentProviderAdapter` and
/// builds a Swing panel with the instruction table, control panel,
/// and preview components.  In Rust we model the lifecycle and state
/// without a GUI framework, following the same pattern used by
/// [`super::search_all_task::InstructionSearchDialog`] and the provider
/// implementations in other modules.
#[derive(Debug)]
pub struct InstructionSearchProvider {
    /// Provider name (used for panel registration).
    name: String,
    /// Current visibility state.
    visibility: ProviderVisibility,
    /// Whether the provider is the primary (default) provider.
    is_primary: bool,
    /// The current display state.
    display: DisplayState,
    /// The active search mode (mirrored from plugin).
    search_mode: SearchMode,
    /// The component ID (for action context).
    component_id: String,
    /// The title displayed in the provider window.
    title: String,
    /// Whether to show the search options panel.
    show_options: bool,
    /// Whether to show the instruction table.
    show_instruction_table: bool,
    /// Whether to show the preview table.
    show_preview: bool,
}

impl InstructionSearchProvider {
    /// Create a new provider with defaults.
    pub fn new() -> Self {
        Self {
            name: "InstructionSearch".into(),
            visibility: ProviderVisibility::Hidden,
            is_primary: true,
            display: DisplayState::new(),
            search_mode: SearchMode::Idle,
            component_id: "InstructionSearchProvider".into(),
            title: "Instruction Search".into(),
            show_options: true,
            show_instruction_table: true,
            show_preview: false,
        }
    }

    /// Create a transient (non-primary) provider.
    pub fn new_transient() -> Self {
        let mut provider = Self::new();
        provider.is_primary = false;
        provider
    }

    /// Create a provider with a specific component ID.
    pub fn with_component_id(id: impl Into<String>) -> Self {
        let mut provider = Self::new();
        provider.component_id = id.into();
        provider
    }

    // -- Accessors -----------------------------------------------------------

    /// Get the provider name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the current visibility state.
    pub fn visibility(&self) -> ProviderVisibility {
        self.visibility
    }

    /// Whether the provider is currently visible.
    pub fn is_visible(&self) -> bool {
        self.visibility.is_active()
    }

    /// Whether the provider has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.visibility.is_disposed()
    }

    /// Whether this is the primary provider.
    pub fn is_primary(&self) -> bool {
        self.is_primary
    }

    /// Get the component ID.
    pub fn component_id(&self) -> &str {
        &self.component_id
    }

    /// Get the title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Get the current search mode.
    pub fn search_mode(&self) -> SearchMode {
        self.search_mode
    }

    /// Get the current display state.
    pub fn display(&self) -> &DisplayState {
        &self.display
    }

    /// Whether the dialog is open.
    pub fn is_dialog_open(&self) -> bool {
        self.display.dialog_open
    }

    /// Whether a search is currently running.
    pub fn is_searching(&self) -> bool {
        self.display.searching
    }

    /// Get the match count.
    pub fn match_count(&self) -> usize {
        self.display.match_count
    }

    // -- Lifecycle -----------------------------------------------------------

    /// Show the provider panel.
    ///
    /// Ported from `ComponentProviderAdapter.setVisible(true)`.
    pub fn show(&mut self) {
        if self.visibility.is_disposed() {
            return;
        }
        self.visibility = ProviderVisibility::Visible;
    }

    /// Show the provider panel and give it focus.
    pub fn show_with_focus(&mut self) {
        if self.visibility.is_disposed() {
            return;
        }
        self.visibility = ProviderVisibility::Focused;
    }

    /// Hide the provider panel.
    pub fn hide(&mut self) {
        if self.visibility.is_disposed() {
            return;
        }
        self.visibility = ProviderVisibility::Hidden;
    }

    /// Toggle visibility.
    pub fn toggle(&mut self) {
        if self.is_visible() {
            self.hide();
        } else {
            self.show();
        }
    }

    /// Set visibility explicitly.
    pub fn set_visible(&mut self, visible: bool) {
        if visible {
            self.show();
        } else {
            self.hide();
        }
    }

    /// Called when the provider component is shown.
    ///
    /// Ported from `ComponentProviderAdapter.componentShown()`.
    pub fn component_shown(&mut self) {
        self.visibility = ProviderVisibility::Visible;
    }

    /// Called when the provider component is hidden.
    pub fn component_hidden(&mut self) {
        if !self.visibility.is_disposed() {
            self.visibility = ProviderVisibility::Hidden;
        }
    }

    /// Dispose of the provider, releasing all resources.
    ///
    /// Ported from `ComponentProviderAdapter.dispose()`.
    pub fn dispose(&mut self) {
        self.visibility = ProviderVisibility::Disposed;
        self.display = DisplayState::new();
    }

    /// Clear the provider display state.
    pub fn clear(&mut self) {
        self.display = DisplayState::new();
        self.search_mode = SearchMode::Idle;
    }

    // -- Display state updates -----------------------------------------------

    /// Set the search mode (mirrored from the plugin).
    pub fn set_search_mode(&mut self, mode: SearchMode) {
        self.search_mode = mode;
        // Map to panel mode.
        self.display.panel.mode = match mode {
            SearchMode::Idle => SearchPanelMode::BuildPattern,
            SearchMode::BuildingPattern => SearchPanelMode::BuildPattern,
            SearchMode::Searching | SearchMode::Previewing => SearchPanelMode::Preview,
        };
    }

    /// Set the match count.
    pub fn set_match_count(&mut self, count: usize) {
        self.display.match_count = count;
    }

    /// Set whether a search is in progress.
    pub fn set_searching(&mut self, searching: bool) {
        self.display.searching = searching;
    }

    /// Set the search progress.
    pub fn set_search_progress(&mut self, progress: f64) {
        self.display.search_progress = progress.clamp(0.0, 1.0);
    }

    /// Set the status message.
    pub fn set_status_message(&mut self, msg: impl Into<String>) {
        self.display.status_message = msg.into();
    }

    /// Clear the status message.
    pub fn clear_status_message(&mut self) {
        self.display.status_message.clear();
    }

    /// Set whether the dialog is open.
    pub fn set_dialog_open(&mut self, open: bool) {
        self.display.dialog_open = open;
    }

    /// Set the current program name.
    pub fn set_program_name(&mut self, name: Option<String>) {
        self.display.program_name = name;
        self.update_title();
    }

    /// Set the address range label.
    pub fn set_range_label(&mut self, label: impl Into<String>) {
        self.display.range_label = label.into();
    }

    /// Set the display format.
    pub fn set_format(&mut self, format: SearchFormat) {
        self.display.panel.format = format;
    }

    /// Set the display endianness.
    pub fn set_endian(&mut self, endian: DisplayEndian) {
        self.display.panel.endian = endian;
    }

    /// Set the selection mode.
    pub fn set_selection_mode(&mut self, mode: SelectionMode) {
        self.display.panel.selection_mode = mode;
    }

    /// Toggle endianness.
    pub fn toggle_endian(&mut self) {
        self.display.panel.endian = match self.display.panel.endian {
            DisplayEndian::Big => DisplayEndian::Little,
            DisplayEndian::Little => DisplayEndian::Big,
        };
    }

    // -- Visibility toggles for sub-panels ----------------------------------

    /// Whether the options panel is shown.
    pub fn show_options(&self) -> bool {
        self.show_options
    }

    /// Set whether the options panel is shown.
    pub fn set_show_options(&mut self, show: bool) {
        self.show_options = show;
    }

    /// Whether the instruction table is shown.
    pub fn show_instruction_table(&self) -> bool {
        self.show_instruction_table
    }

    /// Set whether the instruction table is shown.
    pub fn set_show_instruction_table(&mut self, show: bool) {
        self.show_instruction_table = show;
    }

    /// Whether the preview table is shown.
    pub fn show_preview(&self) -> bool {
        self.show_preview
    }

    /// Set whether the preview table is shown.
    pub fn set_show_preview(&mut self, show: bool) {
        self.show_preview = show;
    }

    // -- Title management ----------------------------------------------------

    /// Update the title based on current state.
    fn update_title(&mut self) {
        if let Some(ref prog) = self.display.program_name {
            self.title = format!("Instruction Search: {}", prog);
        } else {
            self.title = "Instruction Search".into();
        }
    }

    /// Set the title explicitly.
    pub fn set_title(&mut self, title: impl Into<String>) {
        self.title = title.into();
    }

    // -- Provider-local status helpers ---------------------------------------

    /// Set a "searching" status message with progress.
    pub fn set_searching_status(&mut self, progress: f64) {
        let pct = (progress * 100.0) as u32;
        self.display.status_message = format!("Searching... {}%", pct);
        self.display.searching = true;
        self.display.search_progress = progress;
    }

    /// Set a "matches found" status message.
    pub fn set_results_status(&mut self) {
        let count = self.display.match_count;
        self.display.status_message = if count == 0 {
            "No matches found.".into()
        } else if count == 1 {
            "1 match found.".into()
        } else {
            format!("{} matches found.", count)
        };
        self.display.searching = false;
    }

    /// Set a "search cancelled" status message.
    pub fn set_cancelled_status(&mut self) {
        let count = self.display.match_count;
        self.display.status_message = format!(
            "Search cancelled. {} matches found before cancellation.",
            count
        );
        self.display.searching = false;
    }

    /// Set an error status message.
    pub fn set_error_status(&mut self, error: impl Into<String>) {
        self.display.status_message = format!("Error: {}", error.into());
        self.display.searching = false;
    }

    /// Set the "no program" status message.
    pub fn set_no_program_status(&mut self) {
        self.display.status_message = "No program is open.".into();
    }
}

impl Default for InstructionSearchProvider {
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
    fn test_provider_new() {
        let provider = InstructionSearchProvider::new();
        assert_eq!(provider.name(), "InstructionSearch");
        assert_eq!(provider.visibility(), ProviderVisibility::Hidden);
        assert!(!provider.is_visible());
        assert!(!provider.is_disposed());
        assert!(provider.is_primary());
        assert_eq!(provider.component_id(), "InstructionSearchProvider");
        assert_eq!(provider.title(), "Instruction Search");
        assert_eq!(provider.search_mode(), SearchMode::Idle);
        assert_eq!(provider.match_count(), 0);
        assert!(!provider.is_searching());
        assert!(!provider.is_dialog_open());
    }

    #[test]
    fn test_provider_new_transient() {
        let provider = InstructionSearchProvider::new_transient();
        assert!(!provider.is_primary());
    }

    #[test]
    fn test_provider_with_component_id() {
        let provider = InstructionSearchProvider::with_component_id("CustomID");
        assert_eq!(provider.component_id(), "CustomID");
    }

    #[test]
    fn test_provider_visibility_lifecycle() {
        let mut provider = InstructionSearchProvider::new();
        assert!(!provider.is_visible());

        provider.show();
        assert!(provider.is_visible());
        assert_eq!(provider.visibility(), ProviderVisibility::Visible);

        provider.show_with_focus();
        assert_eq!(provider.visibility(), ProviderVisibility::Focused);

        provider.hide();
        assert!(!provider.is_visible());
        assert_eq!(provider.visibility(), ProviderVisibility::Hidden);

        provider.toggle();
        assert!(provider.is_visible());

        provider.toggle();
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_provider_dispose() {
        let mut provider = InstructionSearchProvider::new();
        provider.show();
        assert!(provider.is_visible());

        provider.dispose();
        assert!(provider.is_disposed());
        assert!(!provider.is_visible());

        // Cannot show after dispose.
        provider.show();
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_provider_component_shown_hidden() {
        let mut provider = InstructionSearchProvider::new();

        provider.component_shown();
        assert!(provider.is_visible());

        provider.component_hidden();
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_provider_set_visible() {
        let mut provider = InstructionSearchProvider::new();

        provider.set_visible(true);
        assert!(provider.is_visible());

        provider.set_visible(false);
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_provider_search_mode() {
        let mut provider = InstructionSearchProvider::new();

        provider.set_search_mode(SearchMode::Searching);
        assert_eq!(provider.search_mode(), SearchMode::Searching);
        assert_eq!(provider.display().panel.mode, SearchPanelMode::Preview);

        provider.set_search_mode(SearchMode::Idle);
        assert_eq!(provider.display().panel.mode, SearchPanelMode::BuildPattern);

        provider.set_search_mode(SearchMode::Previewing);
        assert_eq!(provider.display().panel.mode, SearchPanelMode::Preview);
    }

    #[test]
    fn test_provider_match_count() {
        let mut provider = InstructionSearchProvider::new();
        assert_eq!(provider.match_count(), 0);

        provider.set_match_count(42);
        assert_eq!(provider.match_count(), 42);
    }

    #[test]
    fn test_provider_searching() {
        let mut provider = InstructionSearchProvider::new();
        assert!(!provider.is_searching());

        provider.set_searching(true);
        assert!(provider.is_searching());

        provider.set_searching(false);
        assert!(!provider.is_searching());
    }

    #[test]
    fn test_provider_search_progress() {
        let mut provider = InstructionSearchProvider::new();

        provider.set_search_progress(0.75);
        assert!((provider.display().search_progress - 0.75).abs() < f64::EPSILON);

        // Clamped to [0.0, 1.0].
        provider.set_search_progress(1.5);
        assert!((provider.display().search_progress - 1.0).abs() < f64::EPSILON);

        provider.set_search_progress(-0.1);
        assert!((provider.display().search_progress - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_provider_status_message() {
        let mut provider = InstructionSearchProvider::new();
        assert!(provider.display().status_message.is_empty());

        provider.set_status_message("Hello");
        assert_eq!(provider.display().status_message, "Hello");

        provider.clear_status_message();
        assert!(provider.display().status_message.is_empty());
    }

    #[test]
    fn test_provider_dialog_open() {
        let mut provider = InstructionSearchProvider::new();
        assert!(!provider.is_dialog_open());

        provider.set_dialog_open(true);
        assert!(provider.is_dialog_open());

        provider.set_dialog_open(false);
        assert!(!provider.is_dialog_open());
    }

    #[test]
    fn test_provider_program_name() {
        let mut provider = InstructionSearchProvider::new();
        assert!(provider.display().program_name.is_none());
        assert_eq!(provider.title(), "Instruction Search");

        provider.set_program_name(Some("test.exe".into()));
        assert_eq!(provider.display().program_name.as_deref(), Some("test.exe"));
        assert_eq!(provider.title(), "Instruction Search: test.exe");

        provider.set_program_name(None);
        assert_eq!(provider.title(), "Instruction Search");
    }

    #[test]
    fn test_provider_range_label() {
        let mut provider = InstructionSearchProvider::new();
        assert_eq!(provider.display().range_label, "Full Program");

        provider.set_range_label("0x400000..0x500000");
        assert_eq!(provider.display().range_label, "0x400000..0x500000");
    }

    #[test]
    fn test_provider_format() {
        let mut provider = InstructionSearchProvider::new();

        provider.set_format(SearchFormat::Binary);
        assert_eq!(provider.display().panel.format, SearchFormat::Binary);

        provider.set_format(SearchFormat::MaskedHex);
        assert_eq!(provider.display().panel.format, SearchFormat::MaskedHex);
    }

    #[test]
    fn test_provider_endian() {
        let mut provider = InstructionSearchProvider::new();
        assert_eq!(provider.display().panel.endian, DisplayEndian::Little);

        provider.set_endian(DisplayEndian::Big);
        assert_eq!(provider.display().panel.endian, DisplayEndian::Big);

        provider.toggle_endian();
        assert_eq!(provider.display().panel.endian, DisplayEndian::Little);
    }

    #[test]
    fn test_provider_selection_mode() {
        let mut provider = InstructionSearchProvider::new();

        provider.set_selection_mode(SelectionMode::Range);
        assert_eq!(
            provider.display().panel.selection_mode,
            SelectionMode::Range
        );

        provider.set_selection_mode(SelectionMode::All);
        assert_eq!(provider.display().panel.selection_mode, SelectionMode::All);
    }

    #[test]
    fn test_provider_sub_panel_toggles() {
        let mut provider = InstructionSearchProvider::new();

        assert!(provider.show_options());
        provider.set_show_options(false);
        assert!(!provider.show_options());

        assert!(provider.show_instruction_table());
        provider.set_show_instruction_table(false);
        assert!(!provider.show_instruction_table());

        assert!(!provider.show_preview());
        provider.set_show_preview(true);
        assert!(provider.show_preview());
    }

    #[test]
    fn test_provider_set_title() {
        let mut provider = InstructionSearchProvider::new();
        provider.set_title("Custom Title");
        assert_eq!(provider.title(), "Custom Title");
    }

    #[test]
    fn test_provider_status_helpers() {
        let mut provider = InstructionSearchProvider::new();

        provider.set_searching_status(0.5);
        assert!(provider.display().status_message.contains("50%"));
        assert!(provider.is_searching());

        provider.set_match_count(5);
        provider.set_results_status();
        assert!(provider.display().status_message.contains("5 matches"));
        assert!(!provider.is_searching());

        provider.set_match_count(1);
        provider.set_results_status();
        assert!(provider.display().status_message.contains("1 match"));

        provider.set_match_count(0);
        provider.set_results_status();
        assert!(provider.display().status_message.contains("No matches"));

        provider.set_cancelled_status();
        assert!(provider.display().status_message.contains("cancelled"));

        provider.set_error_status("bad input");
        assert!(provider.display().status_message.contains("Error: bad input"));

        provider.set_no_program_status();
        assert!(provider.display().status_message.contains("No program"));
    }

    #[test]
    fn test_provider_clear() {
        let mut provider = InstructionSearchProvider::new();
        provider.set_match_count(42);
        provider.set_searching(true);
        provider.set_status_message("busy");
        provider.set_search_mode(SearchMode::Searching);

        provider.clear();
        assert_eq!(provider.match_count(), 0);
        assert!(!provider.is_searching());
        assert!(provider.display().status_message.is_empty());
        assert_eq!(provider.search_mode(), SearchMode::Idle);
    }

    #[test]
    fn test_provider_visibility_default() {
        assert_eq!(ProviderVisibility::default(), ProviderVisibility::Hidden);
    }

    #[test]
    fn test_provider_visibility_is_active() {
        assert!(!ProviderVisibility::Hidden.is_active());
        assert!(ProviderVisibility::Visible.is_active());
        assert!(ProviderVisibility::Focused.is_active());
        assert!(!ProviderVisibility::Disposed.is_active());
    }

    #[test]
    fn test_provider_visibility_is_disposed() {
        assert!(!ProviderVisibility::Hidden.is_disposed());
        assert!(!ProviderVisibility::Visible.is_disposed());
        assert!(!ProviderVisibility::Focused.is_disposed());
        assert!(ProviderVisibility::Disposed.is_disposed());
    }

    #[test]
    fn test_display_state_default() {
        let state = DisplayState::default();
        assert_eq!(state.match_count, 0);
        assert!(!state.searching);
        assert!((state.search_progress - 0.0).abs() < f64::EPSILON);
        assert!(state.status_message.is_empty());
        assert!(!state.dialog_open);
        assert!(state.program_name.is_none());
        assert_eq!(state.range_label, "Full Program");
    }
}
