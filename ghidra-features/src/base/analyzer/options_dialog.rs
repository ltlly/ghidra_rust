//! AnalysisOptionsDialog -- dialog for configuring analysis options.
//!
//! Ported from `ghidra.app.plugin.core.analysis.AnalysisOptionsDialog` and `AnalysisPanel`.
//! Provides a dialog for viewing and modifying analyzer enablement and options.

use std::collections::HashMap;

use crate::base::analyzer::core::*;
use crate::base::analyzer::table_model::*;
use crate::base::analyzer::worker::AnalyzerEnablementState;

/// Button clicked by the user in the analysis options dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogButton {
    /// User clicked "Analyze".
    Analyze,
    /// User clicked "Cancel".
    Cancel,
    /// User clicked "Apply".
    Apply,
    /// User clicked "OK" (same as Analyze in this context).
    Ok,
}

/// State of the analysis options dialog.
///
/// Manages the dialog state including analyzer enablement, options, and
/// user interaction results.
///
/// # Example
///
/// ```
/// use ghidra_features::base::analyzer::*;
///
/// let mut dialog = AnalysisOptionsDialog::new("Analysis Options");
/// dialog.add_analyzer(AnalyzerEnablementState::new("Function Start", true, false));
/// assert_eq!(dialog.row_count(), 1);
/// ```
#[derive(Debug)]
pub struct AnalysisOptionsDialog {
    /// Dialog title.
    title: String,
    /// Table model for analyzer enablement.
    table_model: AnalysisEnablementTableModel,
    /// Whether the "Analyze" button was selected.
    do_analysis: bool,
    /// Whether there are unsaved changes.
    has_changes: bool,
    /// Selected analyzer index (for showing options).
    selected_analyzer: Option<usize>,
    /// Analyzer-specific options.
    analyzer_options: HashMap<String, HashMap<String, AnalysisOptionValue>>,
    /// Description of the selected analyzer.
    description: String,
    /// Status text.
    status_text: String,
    /// Whether the dialog is visible.
    visible: bool,
}

impl AnalysisOptionsDialog {
    /// Creates a new analysis options dialog.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            table_model: AnalysisEnablementTableModel::new(),
            do_analysis: false,
            has_changes: false,
            selected_analyzer: None,
            analyzer_options: HashMap::new(),
            description: String::new(),
            status_text: String::new(),
            visible: false,
        }
    }

    /// Returns the dialog title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns whether the analyze button was selected.
    pub fn was_analyze_button_selected(&self) -> bool {
        self.do_analysis
    }

    /// Returns whether there are unsaved changes.
    pub fn has_changes(&self) -> bool {
        self.has_changes
    }

    /// Returns the table model.
    pub fn table_model(&self) -> &AnalysisEnablementTableModel {
        &self.table_model
    }

    /// Returns a mutable reference to the table model.
    pub fn table_model_mut(&mut self) -> &mut AnalysisEnablementTableModel {
        &mut self.table_model
    }

    /// Adds an analyzer state to the dialog.
    pub fn add_analyzer(&mut self, state: AnalyzerEnablementState) {
        let states = self.table_model.states_mut();
        states.push(state);
        self.has_changes = true;
    }

    /// Returns the number of analyzers.
    pub fn row_count(&self) -> usize {
        self.table_model.row_count()
    }

    /// Selects an analyzer row.
    pub fn select_analyzer(&mut self, index: usize) {
        if index < self.table_model.row_count() {
            self.selected_analyzer = Some(index);
            if let Some(state) = self.table_model.get_state(index) {
                self.description = format!("Options for {}", state.name());
            }
        }
    }

    /// Returns the selected analyzer index.
    pub fn selected_analyzer(&self) -> Option<usize> {
        self.selected_analyzer
    }

    /// Returns the description text.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Sets the enabled state for an analyzer.
    pub fn set_analyzer_enabled(&mut self, name: &str, enabled: bool) {
        self.table_model.set_enabled_by_name(name, enabled);
        self.has_changes = true;
    }

    /// Returns the status text.
    pub fn status_text(&self) -> &str {
        &self.status_text
    }

    /// Sets the status text.
    pub fn set_status_text(&mut self, text: impl Into<String>) {
        self.status_text = text.into();
    }

    /// Returns whether the dialog is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Shows the dialog.
    pub fn show(&mut self) {
        self.visible = true;
    }

    /// Hides the dialog.
    pub fn hide(&mut self) {
        self.visible = false;
    }

    /// Handles the "Analyze" button click.
    pub fn on_analyze(&mut self) {
        self.do_analysis = true;
        self.apply_changes();
        self.hide();
    }

    /// Handles the "Cancel" button click.
    pub fn on_cancel(&mut self) {
        if self.has_changes {
            // In a real implementation, this would show a "Save Changes?" dialog
            // For now, just close without saving
        }
        self.do_analysis = false;
        self.hide();
    }

    /// Handles the "Apply" button click.
    pub fn on_apply(&mut self) {
        self.apply_changes();
    }

    /// Applies the current changes.
    pub fn apply_changes(&mut self) {
        self.has_changes = false;
    }

    /// Sets analyzer-specific options.
    pub fn set_analyzer_options(
        &mut self,
        analyzer_name: &str,
        options: HashMap<String, AnalysisOptionValue>,
    ) {
        self.analyzer_options
            .insert(analyzer_name.to_string(), options);
    }

    /// Gets analyzer-specific options.
    pub fn get_analyzer_options(
        &self,
        analyzer_name: &str,
    ) -> Option<&HashMap<String, AnalysisOptionValue>> {
        self.analyzer_options.get(analyzer_name)
    }

    /// Returns all analyzer options.
    pub fn all_analyzer_options(&self) -> &HashMap<String, HashMap<String, AnalysisOptionValue>> {
        &self.analyzer_options
    }

    /// Resets all analyzers to their default enablement state.
    pub fn reset_to_defaults(&mut self) {
        self.table_model.reset_to_defaults();
        self.has_changes = true;
    }

    /// Sets the preferred dialog size.
    pub fn set_preferred_size(&mut self, _width: u32, _height: u32) {
        // In a real implementation, this would set the dialog size
    }

    /// Sets whether to remember the dialog size.
    pub fn set_remember_size(&mut self, _remember: bool) {
        // In a real implementation, this would persist the dialog size
    }
}

/// Analysis panel state for managing analyzer options.
///
/// This is a simplified version of the Java AnalysisPanel that manages
/// the core state without Swing UI dependencies.
#[derive(Debug)]
pub struct AnalysisPanelState {
    /// Current program name.
    program_name: String,
    /// Analysis options.
    options: HashMap<String, AnalysisOptionValue>,
    /// Whether options have changed.
    changed: bool,
    /// Last used options configuration file.
    last_used_config: Option<String>,
}

impl AnalysisPanelState {
    /// Creates a new analysis panel state.
    pub fn new(program_name: impl Into<String>) -> Self {
        Self {
            program_name: program_name.into(),
            options: HashMap::new(),
            changed: false,
            last_used_config: None,
        }
    }

    /// Returns the program name.
    pub fn program_name(&self) -> &str {
        &self.program_name
    }

    /// Sets an option value.
    pub fn set_option(&mut self, key: impl Into<String>, value: AnalysisOptionValue) {
        self.options.insert(key.into(), value);
        self.changed = true;
    }

    /// Gets an option value.
    pub fn get_option(&self, key: &str) -> Option<&AnalysisOptionValue> {
        self.options.get(key)
    }

    /// Returns whether options have changed.
    pub fn has_changed(&self) -> bool {
        self.changed
    }

    /// Marks options as applied.
    pub fn mark_applied(&mut self) {
        self.changed = false;
    }

    /// Returns all options.
    pub fn options(&self) -> &HashMap<String, AnalysisOptionValue> {
        &self.options
    }

    /// Sets the last used configuration file.
    pub fn set_last_used_config(&mut self, config: impl Into<String>) {
        self.last_used_config = Some(config.into());
    }

    /// Returns the last used configuration file.
    pub fn last_used_config(&self) -> Option<&str> {
        self.last_used_config.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dialog_creation() {
        let dialog = AnalysisOptionsDialog::new("Analysis Options");
        assert_eq!(dialog.title(), "Analysis Options");
        assert!(!dialog.was_analyze_button_selected());
        assert!(!dialog.has_changes());
        assert!(dialog.row_count() == 0);
    }

    #[test]
    fn test_dialog_add_analyzer() {
        let mut dialog = AnalysisOptionsDialog::new("Test");
        dialog.add_analyzer(AnalyzerEnablementState::new("Test Analyzer", true, false));
        assert_eq!(dialog.row_count(), 1);
        assert!(dialog.has_changes());
    }

    #[test]
    fn test_dialog_select_analyzer() {
        let mut dialog = AnalysisOptionsDialog::new("Test");
        dialog.add_analyzer(AnalyzerEnablementState::new("Test Analyzer", true, false));
        dialog.select_analyzer(0);
        assert_eq!(dialog.selected_analyzer(), Some(0));
        assert!(!dialog.description().is_empty());
    }

    #[test]
    fn test_dialog_set_enabled() {
        let mut dialog = AnalysisOptionsDialog::new("Test");
        dialog.add_analyzer(AnalyzerEnablementState::new("Test", true, false));
        dialog.set_analyzer_enabled("Test", false);
        let state = dialog.table_model().get_state(0).unwrap();
        assert!(!state.is_enabled());
    }

    #[test]
    fn test_dialog_analyze() {
        let mut dialog = AnalysisOptionsDialog::new("Test");
        dialog.on_analyze();
        assert!(dialog.was_analyze_button_selected());
        assert!(!dialog.is_visible());
    }

    #[test]
    fn test_dialog_cancel() {
        let mut dialog = AnalysisOptionsDialog::new("Test");
        dialog.show();
        dialog.on_cancel();
        assert!(!dialog.was_analyze_button_selected());
        assert!(!dialog.is_visible());
    }

    #[test]
    fn test_dialog_apply() {
        let mut dialog = AnalysisOptionsDialog::new("Test");
        dialog.add_analyzer(AnalyzerEnablementState::new("Test", true, false));
        assert!(dialog.has_changes());
        dialog.on_apply();
        assert!(!dialog.has_changes());
    }

    #[test]
    fn test_dialog_reset_to_defaults() {
        let mut dialog = AnalysisOptionsDialog::new("Test");
        dialog.add_analyzer(AnalyzerEnablementState::new("Test", true, false));
        dialog.set_analyzer_enabled("Test", false);
        dialog.reset_to_defaults();
        let state = dialog.table_model().get_state(0).unwrap();
        assert!(state.is_enabled());
    }

    #[test]
    fn test_dialog_analyzer_options() {
        let mut dialog = AnalysisOptionsDialog::new("Test");
        let mut opts = HashMap::new();
        opts.insert(
            "threshold".into(),
            AnalysisOptionValue::Integer(5),
        );
        dialog.set_analyzer_options("TestAnalyzer", opts);

        let retrieved = dialog.get_analyzer_options("TestAnalyzer");
        assert!(retrieved.is_some());
        assert_eq!(
            retrieved.unwrap().get("threshold"),
            Some(&AnalysisOptionValue::Integer(5))
        );
    }

    #[test]
    fn test_panel_state_creation() {
        let panel = AnalysisPanelState::new("test_program");
        assert_eq!(panel.program_name(), "test_program");
        assert!(!panel.has_changed());
    }

    #[test]
    fn test_panel_state_options() {
        let mut panel = AnalysisPanelState::new("test");
        panel.set_option("key1", AnalysisOptionValue::Bool(true));
        panel.set_option("key2", AnalysisOptionValue::Integer(42));
        assert!(panel.has_changed());
        assert_eq!(
            panel.get_option("key1"),
            Some(&AnalysisOptionValue::Bool(true))
        );
        assert_eq!(
            panel.get_option("key2"),
            Some(&AnalysisOptionValue::Integer(42))
        );
    }

    #[test]
    fn test_panel_state_applied() {
        let mut panel = AnalysisPanelState::new("test");
        panel.set_option("key", AnalysisOptionValue::Bool(true));
        assert!(panel.has_changed());
        panel.mark_applied();
        assert!(!panel.has_changed());
    }

    #[test]
    fn test_panel_state_config() {
        let mut panel = AnalysisPanelState::new("test");
        assert!(panel.last_used_config().is_none());
        panel.set_last_used_config("config.json");
        assert_eq!(panel.last_used_config(), Some("config.json"));
    }

    #[test]
    fn test_dialog_show_hide() {
        let mut dialog = AnalysisOptionsDialog::new("Test");
        assert!(!dialog.is_visible());
        dialog.show();
        assert!(dialog.is_visible());
        dialog.hide();
        assert!(!dialog.is_visible());
    }

    #[test]
    fn test_dialog_status_text() {
        let mut dialog = AnalysisOptionsDialog::new("Test");
        assert!(dialog.status_text().is_empty());
        dialog.set_status_text("Error occurred");
        assert_eq!(dialog.status_text(), "Error occurred");
    }
}
