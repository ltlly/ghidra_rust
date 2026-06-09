//! References provider -- view-state management for the references panel.
//!
//! Ported from Ghidra's `ReferencesProvider` in
//! `ghidra.app.plugin.core.references`.
//!
//! This module provides [`ReferencesProvider`], which tracks the visible
//! state of the references view, the currently selected reference(s), the
//! table model, and the available actions (go to, delete, edit type, set
//! primary, toggle follow-location, toggle goto-reference).
//!
//! In the Rust port, Swing-specific UI components (tables, panels, toolbars)
//! are replaced with a pure-data representation of the view state.

use super::edit_model::{EditReferencesModel, ReferenceRow};
use super::external_provider::ExternalReferencesProvider;
use ghidra_core::addr::Address;
use ghidra_core::symbol::{Reference, ReferenceManager};
use serde::{Deserialize, Serialize};
use std::fmt;

// ============================================================================
// Provider configuration
// ============================================================================

/// Configuration for the references provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferencesProviderConfig {
    /// Whether to follow location changes (navigate to reference target on
    /// selection).
    pub follow_location: bool,
    /// Whether to go to the reference location on double-click.
    pub goto_reference: bool,
    /// Whether to show the instruction panel above the references table.
    pub show_instruction_panel: bool,
    /// Whether to show external references in the table.
    pub show_external_refs: bool,
}

impl Default for ReferencesProviderConfig {
    fn default() -> Self {
        Self {
            follow_location: true,
            goto_reference: true,
            show_instruction_panel: true,
            show_external_refs: true,
        }
    }
}

impl ReferencesProviderConfig {
    /// Create a new default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the follow-location option.
    pub fn with_follow_location(mut self, follow: bool) -> Self {
        self.follow_location = follow;
        self
    }

    /// Set the goto-reference option.
    pub fn with_goto_reference(mut self, goto_ref: bool) -> Self {
        self.goto_reference = goto_ref;
        self
    }

    /// Set the show-instruction-panel option.
    pub fn with_show_instruction_panel(mut self, show: bool) -> Self {
        self.show_instruction_panel = show;
        self
    }

    /// Set the show-external-refs option.
    pub fn with_show_external_refs(mut self, show: bool) -> Self {
        self.show_external_refs = show;
        self
    }
}

// ============================================================================
// Action enablement state
// ============================================================================

/// Which references-provider actions are currently enabled.
///
/// Mirrors the enable/disable logic in `ReferencesProvider.enableActions`.
#[derive(Debug, Clone, Default)]
pub struct RefsActionEnablement {
    /// Whether the "Go To" action is available (a reference is selected).
    pub go_to: bool,
    /// Whether the "Delete" action is available (one or more refs selected).
    pub delete: bool,
    /// Whether the "Delete All" action is available.
    pub delete_all: bool,
    /// Whether the "Edit Type" action is available (exactly one ref selected).
    pub edit_type: bool,
    /// Whether the "Set Primary" action is available.
    pub set_primary: bool,
    /// Whether the "Add Reference" action is available.
    pub add_ref: bool,
}

// ============================================================================
// ReferencesProvider
// ============================================================================

/// View-state manager for the references panel.
///
/// Ported from Ghidra's `ReferencesProvider` in Java. This struct tracks:
/// - Whether the view is visible
/// - The table model backing the references table
/// - Which references are selected
/// - Which actions are enabled
/// - Navigation state (follow-location-changes toggle, goto-reference toggle)
/// - The source address whose references are being displayed
///
/// # Usage
///
/// ```ignore
/// use ghidra_features::base::references::references_provider::ReferencesProvider;
///
/// let mut provider = ReferencesProvider::new();
/// provider.set_visible(true);
/// provider.set_source_address(Some(Address::new(0x401000)));
/// assert!(provider.is_visible());
/// assert_eq!(provider.source_address(), Some(Address::new(0x401000)));
/// ```
#[derive(Debug)]
pub struct ReferencesProvider {
    /// Whether the provider's component is currently visible.
    visible: bool,
    /// The table model for the references.
    table_model: EditReferencesModel,
    /// Indices of selected rows in the references table.
    selected_rows: Vec<usize>,
    /// Current action enablement state.
    actions: RefsActionEnablement,
    /// Provider configuration.
    config: ReferencesProviderConfig,
    /// Status text to display.
    status_text: String,
    /// The source address whose references are being displayed.
    source_address: Option<Address>,
    /// The operand index for the source address.
    source_op_index: i32,
    /// The program name for the currently displayed program.
    program_name: Option<String>,
    /// Total number of references currently displayed.
    ref_count: usize,
}

impl Default for ReferencesProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ReferencesProvider {
    /// Create a new references provider.
    pub fn new() -> Self {
        Self {
            visible: false,
            table_model: EditReferencesModel::new(),
            selected_rows: Vec::new(),
            actions: RefsActionEnablement::default(),
            config: ReferencesProviderConfig::default(),
            status_text: String::new(),
            source_address: None,
            source_op_index: 0,
            program_name: None,
            ref_count: 0,
        }
    }

    /// Create a new references provider with custom configuration.
    pub fn with_config(config: ReferencesProviderConfig) -> Self {
        Self {
            config,
            ..Self::new()
        }
    }

    // -- Visibility --

    /// Returns whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Sets the provider visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Toggles the provider visibility.
    pub fn toggle_visible(&mut self) {
        self.visible = !self.visible;
    }

    // -- Configuration --

    /// Returns a reference to the provider configuration.
    pub fn config(&self) -> &ReferencesProviderConfig {
        &self.config
    }

    /// Returns a mutable reference to the provider configuration.
    pub fn config_mut(&mut self) -> &mut ReferencesProviderConfig {
        &mut self.config
    }

    /// Sets the follow-location option.
    pub fn set_follow_location(&mut self, follow: bool) {
        self.config.follow_location = follow;
    }

    /// Returns whether follow-location is enabled.
    pub fn follow_location(&self) -> bool {
        self.config.follow_location
    }

    /// Sets the goto-reference option.
    pub fn set_goto_reference(&mut self, goto_ref: bool) {
        self.config.goto_reference = goto_ref;
    }

    /// Returns whether goto-reference is enabled.
    pub fn goto_reference(&self) -> bool {
        self.config.goto_reference
    }

    // -- Source address --

    /// Returns the source address whose references are displayed.
    pub fn source_address(&self) -> Option<Address> {
        self.source_address
    }

    /// Sets the source address and refreshes the display.
    pub fn set_source_address(&mut self, addr: Option<Address>) {
        self.source_address = addr;
        self.selected_rows.clear();
    }

    /// Returns the operand index for the source address.
    pub fn source_op_index(&self) -> i32 {
        self.source_op_index
    }

    /// Sets the operand index for the source address.
    pub fn set_source_op_index(&mut self, op_index: i32) {
        self.source_op_index = op_index;
    }

    // -- Program name --

    /// Returns the program name.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    /// Sets the program name.
    pub fn set_program_name(&mut self, name: Option<String>) {
        self.program_name = name;
    }

    // -- Table model --

    /// Returns a reference to the table model.
    pub fn table_model(&self) -> &EditReferencesModel {
        &self.table_model
    }

    /// Returns a mutable reference to the table model.
    pub fn table_model_mut(&mut self) -> &mut EditReferencesModel {
        &mut self.table_model
    }

    // -- Selection --

    /// Returns the selected rows.
    pub fn selected_rows(&self) -> &[usize] {
        &self.selected_rows
    }

    /// Sets the selected rows and updates action enablement.
    pub fn set_selected_rows(&mut self, rows: Vec<usize>) {
        self.selected_rows = rows;
        self.update_action_enablement();
    }

    /// Clears the selection.
    pub fn clear_selection(&mut self) {
        self.selected_rows.clear();
        self.update_action_enablement();
    }

    // -- Actions --

    /// Returns the current action enablement state.
    pub fn action_enablement(&self) -> &RefsActionEnablement {
        &self.actions
    }

    // -- Status --

    /// Returns the status text.
    pub fn status_text(&self) -> &str {
        &self.status_text
    }

    /// Sets the status text.
    pub fn set_status_text(&mut self, text: impl Into<String>) {
        self.status_text = text.into();
    }

    /// Returns the total number of references displayed.
    pub fn ref_count(&self) -> usize {
        self.ref_count
    }

    // -- Refresh --

    /// Refresh the references table from the reference manager.
    ///
    /// Updates the table model, ref count, status text, and action
    /// enablement.
    pub fn refresh_references(&mut self, ref_mgr: &ReferenceManager) {
        let src = self.source_address.unwrap_or(Address::new(0));
        let refs: Vec<Reference> = ref_mgr
            .get_references_from(src)
            .into_iter()
            .cloned()
            .collect();
        self.ref_count = refs.len();
        self.status_text = format!("{} reference(s)", self.ref_count);
        let rows: Vec<ReferenceRow> = refs
            .into_iter()
            .map(|r| {
                let label = format!("{}", r.get_to_address());
                ReferenceRow::new(r, label)
            })
            .collect();
        self.table_model.set_references(rows);
        self.update_action_enablement();
    }

    /// Clear the provider state.
    pub fn clear(&mut self) {
        self.table_model.clear();
        self.selected_rows.clear();
        self.actions = RefsActionEnablement::default();
        self.status_text.clear();
        self.source_address = None;
        self.source_op_index = 0;
        self.ref_count = 0;
    }

    // -- Internal --

    /// Update action enablement based on current selection.
    fn update_action_enablement(&mut self) {
        let has_selection = !self.selected_rows.is_empty();
        let single_selection = self.selected_rows.len() == 1;

        self.actions = RefsActionEnablement {
            go_to: has_selection,
            delete: has_selection,
            delete_all: self.ref_count > 0,
            edit_type: single_selection,
            set_primary: single_selection,
            add_ref: self.source_address.is_some(),
        };
    }
}

impl fmt::Display for ReferencesProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ReferencesProvider [visible={}, refs={}, addr={}]",
            self.visible,
            self.ref_count,
            self.source_address
                .map(|a| format!("0x{:x}", a.offset))
                .unwrap_or_else(|| "(none)".to_string()),
        )
    }
}

// ============================================================================
// ReferencesProviderState -- serializable snapshot
// ============================================================================

/// A serializable snapshot of the references provider state.
///
/// Used for saving/restoring the provider across sessions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReferencesProviderState {
    /// Whether the provider was visible.
    pub visible: bool,
    /// The source address.
    pub source_address: Option<u64>,
    /// The operand index.
    pub source_op_index: i32,
    /// The provider configuration.
    pub config: ReferencesProviderConfig,
    /// The program name.
    pub program_name: Option<String>,
}

impl ReferencesProvider {
    /// Save the provider state.
    pub fn save_state(&self) -> ReferencesProviderState {
        ReferencesProviderState {
            visible: self.visible,
            source_address: self.source_address.map(|a| a.offset),
            source_op_index: self.source_op_index,
            config: self.config.clone(),
            program_name: self.program_name.clone(),
        }
    }

    /// Restore the provider from saved state.
    pub fn restore_state(&mut self, state: &ReferencesProviderState) {
        self.visible = state.visible;
        self.source_address = state.source_address.map(Address::new);
        self.source_op_index = state.source_op_index;
        self.config = state.config.clone();
        self.program_name = state.program_name.clone();
    }
}

// ============================================================================
// Title helper
// ============================================================================

impl ReferencesProvider {
    /// Returns the window title for the provider.
    pub fn title(&self) -> String {
        match self.source_address {
            Some(addr) => format!("References to 0x{:x}", addr.offset),
            None => "References".to_string(),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_new() {
        let provider = ReferencesProvider::new();
        assert!(!provider.is_visible());
        assert!(provider.source_address().is_none());
        assert_eq!(provider.ref_count(), 0);
        assert_eq!(provider.source_op_index(), 0);
    }

    #[test]
    fn test_provider_visibility() {
        let mut provider = ReferencesProvider::new();
        assert!(!provider.is_visible());

        provider.set_visible(true);
        assert!(provider.is_visible());

        provider.toggle_visible();
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_provider_source_address() {
        let mut provider = ReferencesProvider::new();
        assert!(provider.source_address().is_none());

        provider.set_source_address(Some(Address::new(0x401000)));
        assert_eq!(provider.source_address(), Some(Address::new(0x401000)));
    }

    #[test]
    fn test_provider_selection() {
        let mut provider = ReferencesProvider::new();
        assert!(provider.selected_rows().is_empty());

        provider.set_selected_rows(vec![0, 2, 4]);
        assert_eq!(provider.selected_rows(), &[0, 2, 4]);

        provider.clear_selection();
        assert!(provider.selected_rows().is_empty());
    }

    #[test]
    fn test_provider_config() {
        let mut provider = ReferencesProvider::new();
        assert!(provider.follow_location());
        assert!(provider.goto_reference());

        provider.set_follow_location(false);
        assert!(!provider.follow_location());

        provider.set_goto_reference(false);
        assert!(!provider.goto_reference());
    }

    #[test]
    fn test_provider_with_config() {
        let config = ReferencesProviderConfig::new()
            .with_follow_location(false)
            .with_goto_reference(false)
            .with_show_instruction_panel(false)
            .with_show_external_refs(false);
        let provider = ReferencesProvider::with_config(config);
        assert!(!provider.follow_location());
        assert!(!provider.goto_reference());
        assert!(!provider.config().show_instruction_panel);
        assert!(!provider.config().show_external_refs);
    }

    #[test]
    fn test_provider_status_text() {
        let mut provider = ReferencesProvider::new();
        assert!(provider.status_text().is_empty());

        provider.set_status_text("3 reference(s)");
        assert_eq!(provider.status_text(), "3 reference(s)");
    }

    #[test]
    fn test_provider_program_name() {
        let mut provider = ReferencesProvider::new();
        assert!(provider.program_name().is_none());

        provider.set_program_name(Some("my_program".to_string()));
        assert_eq!(provider.program_name(), Some("my_program"));
    }

    #[test]
    fn test_provider_action_enablement_default() {
        let provider = ReferencesProvider::new();
        let actions = provider.action_enablement();
        assert!(!actions.go_to);
        assert!(!actions.delete);
        assert!(!actions.delete_all);
        assert!(!actions.edit_type);
        assert!(!actions.set_primary);
        assert!(!actions.add_ref);
    }

    #[test]
    fn test_provider_action_enablement_with_selection() {
        let mut provider = ReferencesProvider::new();
        provider.set_source_address(Some(Address::new(0x1000)));
        // Simulate having references by setting ref_count manually for test.
        provider.ref_count = 5;
        provider.set_selected_rows(vec![0]);
        let actions = provider.action_enablement();
        assert!(actions.go_to);
        assert!(actions.delete);
        assert!(actions.delete_all);
        assert!(actions.edit_type);
        assert!(actions.set_primary);
        assert!(actions.add_ref);
    }

    #[test]
    fn test_provider_action_enablement_multi_selection() {
        let mut provider = ReferencesProvider::new();
        provider.set_source_address(Some(Address::new(0x1000)));
        provider.ref_count = 5;
        provider.set_selected_rows(vec![0, 1, 2]);
        let actions = provider.action_enablement();
        assert!(actions.go_to);
        assert!(actions.delete);
        assert!(!actions.edit_type); // only for single selection
        assert!(!actions.set_primary); // only for single selection
    }

    #[test]
    fn test_provider_clear() {
        let mut provider = ReferencesProvider::new();
        provider.set_visible(true);
        provider.set_source_address(Some(Address::new(0x401000)));
        provider.set_source_op_index(2);
        provider.set_status_text("some status");
        provider.ref_count = 10;

        provider.clear();
        assert!(!provider.is_visible());
        assert!(provider.source_address().is_none());
        assert_eq!(provider.source_op_index(), 0);
        assert!(provider.status_text().is_empty());
        assert_eq!(provider.ref_count(), 0);
    }

    #[test]
    fn test_provider_title() {
        let mut provider = ReferencesProvider::new();
        assert_eq!(provider.title(), "References");

        provider.set_source_address(Some(Address::new(0x401000)));
        assert!(provider.title().contains("0x401000"));
    }

    #[test]
    fn test_provider_display() {
        let mut provider = ReferencesProvider::new();
        provider.set_visible(true);
        provider.set_source_address(Some(Address::new(0x401000)));
        let display = format!("{}", provider);
        assert!(display.contains("ReferencesProvider"));
        assert!(display.contains("visible=true"));
        assert!(display.contains("0x401000"));
    }

    #[test]
    fn test_provider_save_restore_state() {
        let mut provider = ReferencesProvider::new();
        provider.set_visible(true);
        provider.set_source_address(Some(Address::new(0x401000)));
        provider.set_source_op_index(1);
        provider.set_program_name(Some("test_prog".to_string()));

        let state = provider.save_state();
        assert!(state.visible);
        assert_eq!(state.source_address, Some(0x401000));
        assert_eq!(state.source_op_index, 1);
        assert_eq!(state.program_name.as_deref(), Some("test_prog"));

        let mut provider2 = ReferencesProvider::new();
        provider2.restore_state(&state);
        assert!(provider2.is_visible());
        assert_eq!(provider2.source_address(), Some(Address::new(0x401000)));
        assert_eq!(provider2.source_op_index(), 1);
        assert_eq!(provider2.program_name(), Some("test_prog"));
    }

    // -- ReferencesProviderConfig --

    #[test]
    fn test_config_default() {
        let config = ReferencesProviderConfig::default();
        assert!(config.follow_location);
        assert!(config.goto_reference);
        assert!(config.show_instruction_panel);
        assert!(config.show_external_refs);
    }

    #[test]
    fn test_config_builder() {
        let config = ReferencesProviderConfig::new()
            .with_follow_location(false)
            .with_goto_reference(false)
            .with_show_instruction_panel(false)
            .with_show_external_refs(false);
        assert!(!config.follow_location);
        assert!(!config.goto_reference);
        assert!(!config.show_instruction_panel);
        assert!(!config.show_external_refs);
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let config = ReferencesProviderConfig::new()
            .with_follow_location(false)
            .with_goto_reference(true);
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ReferencesProviderConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.follow_location, config.follow_location);
        assert_eq!(deserialized.goto_reference, config.goto_reference);
    }

    // -- ReferencesProviderState --

    #[test]
    fn test_provider_state_default() {
        let state = ReferencesProviderState::default();
        assert!(!state.visible);
        assert!(state.source_address.is_none());
        assert_eq!(state.source_op_index, 0);
        assert!(state.program_name.is_none());
    }

    #[test]
    fn test_provider_state_serialization_roundtrip() {
        let mut provider = ReferencesProvider::new();
        provider.set_visible(true);
        provider.set_source_address(Some(Address::new(0x1000)));
        let state = provider.save_state();

        let json = serde_json::to_string(&state).unwrap();
        let deserialized: ReferencesProviderState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.visible, state.visible);
        assert_eq!(deserialized.source_address, state.source_address);
    }

    // -- RefsActionEnablement --

    #[test]
    fn test_action_enablement_default() {
        let actions = RefsActionEnablement::default();
        assert!(!actions.go_to);
        assert!(!actions.delete);
        assert!(!actions.delete_all);
        assert!(!actions.edit_type);
        assert!(!actions.set_primary);
        assert!(!actions.add_ref);
    }
}
