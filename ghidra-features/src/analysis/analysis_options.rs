//! AnalysisOptionsDialog, AnalysisOptionsEditor, and AnalysisPanel.
//!
//! Ported from Ghidra's:
//! - `ghidra.app.plugin.core.analysis.AnalysisOptionsDialog`
//! - `ghidra.app.plugin.core.analysis.AnalysisOptionsEditor`
//! - `ghidra.app.plugin.core.analysis.AnalysisPanel`
//!
//! These are the UI components for configuring analysis options. In the
//! Rust port they provide the data model and logic without Swing dependency.

use crate::base::analyzer::Program;

// ---------------------------------------------------------------------------
// AnalysisOptionsDialog
// ---------------------------------------------------------------------------

/// Dialog for configuring and launching auto-analysis.
///
/// Ported from Ghidra's `AnalysisOptionsDialog`. Displays analysis options
/// to the user and allows them to choose whether to analyze the current
/// program.
///
/// In the Rust port, this is a data-driven configuration dialog that
/// collects user choices without requiring a GUI toolkit.
#[derive(Debug, Clone)]
pub struct AnalysisOptionsDialog {
    /// The program being analyzed.
    program_name: String,
    /// Whether the user selected the "Analyze" button.
    analyze_selected: bool,
    /// Whether the "Don't show this again" checkbox is checked.
    dont_show_again: bool,
    /// The list of available analysis options.
    options: Vec<AnalysisOptionEntry>,
}

/// A single analysis option entry for the dialog.
#[derive(Debug, Clone)]
pub struct AnalysisOptionEntry {
    /// The option name (unique identifier).
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Whether this option is currently enabled.
    pub enabled: bool,
    /// Default value for this option.
    pub default_enabled: bool,
    /// Category for grouping in the dialog.
    pub category: String,
}

impl AnalysisOptionsDialog {
    /// Create a new analysis options dialog for the given program.
    pub fn new(program: &Program) -> Self {
        Self {
            program_name: program.name.clone(),
            analyze_selected: false,
            dont_show_again: false,
            options: Vec::new(),
        }
    }

    /// Create with pre-configured options.
    pub fn with_options(
        program: &Program,
        options: Vec<AnalysisOptionEntry>,
    ) -> Self {
        Self {
            program_name: program.name.clone(),
            analyze_selected: false,
            dont_show_again: false,
            options,
        }
    }

    /// Check whether the user selected the "Analyze" button.
    pub fn was_analyze_button_selected(&self) -> bool {
        self.analyze_selected
    }

    /// Set the analyze button selection state.
    pub fn set_analyze_selected(&mut self, selected: bool) {
        self.analyze_selected = selected;
    }

    /// Get the "don't show again" state.
    pub fn dont_show_again(&self) -> bool {
        self.dont_show_again
    }

    /// Set the "don't show again" state.
    pub fn set_dont_show_again(&mut self, dont_show: bool) {
        self.dont_show_again = dont_show;
    }

    /// Get the program name.
    pub fn program_name(&self) -> &str {
        &self.program_name
    }

    /// Get all analysis options.
    pub fn options(&self) -> &[AnalysisOptionEntry] {
        &self.options
    }

    /// Add an analysis option.
    pub fn add_option(&mut self, option: AnalysisOptionEntry) {
        self.options.push(option);
    }

    /// Toggle the enabled state of an option by name.
    pub fn toggle_option(&mut self, name: &str) {
        if let Some(option) = self.options.iter_mut().find(|o| o.name == name) {
            option.enabled = !option.enabled;
        }
    }

    /// Get a list of enabled option names.
    pub fn enabled_options(&self) -> Vec<&str> {
        self.options
            .iter()
            .filter(|o| o.enabled)
            .map(|o| o.name.as_str())
            .collect()
    }

    /// Reset all options to their defaults.
    pub fn reset_to_defaults(&mut self) {
        for option in &mut self.options {
            option.enabled = option.default_enabled;
        }
    }
}

// ---------------------------------------------------------------------------
// AnalysisOptionsEditor
// ---------------------------------------------------------------------------

/// Editor for analysis options within the program options panel.
///
/// Ported from Ghidra's `AnalysisOptionsEditor`. Provides an editor
/// component that allows users to view and modify analysis options
/// for a specific program.
#[derive(Debug, Clone)]
pub struct AnalysisOptionsEditor {
    /// The program whose options are being edited.
    program_name: String,
    /// Options being edited.
    options: Vec<AnalysisOptionEntry>,
}

impl AnalysisOptionsEditor {
    /// Create a new analysis options editor.
    pub fn new(program: &Program) -> Self {
        Self {
            program_name: program.name.clone(),
            options: Vec::new(),
        }
    }

    /// Get the program name.
    pub fn program_name(&self) -> &str {
        &self.program_name
    }

    /// Get all options.
    pub fn options(&self) -> &[AnalysisOptionEntry] {
        &self.options
    }

    /// Add an option to the editor.
    pub fn add_option(&mut self, option: AnalysisOptionEntry) {
        self.options.push(option);
    }
}

// ---------------------------------------------------------------------------
// AnalysisPanel
// ---------------------------------------------------------------------------

/// Panel for displaying analysis status and options.
///
/// Ported from Ghidra's `AnalysisPanel`. Provides a view of the current
/// analysis state, including which analyzers are running and their progress.
#[derive(Debug, Clone)]
pub struct AnalysisPanel {
    /// Current analysis status message.
    status_message: String,
    /// Whether analysis is currently running.
    is_running: bool,
    /// Progress percentage (0-100).
    progress: u32,
    /// Name of the currently running analyzer.
    current_analyzer: Option<String>,
}

impl AnalysisPanel {
    /// Create a new analysis panel.
    pub fn new() -> Self {
        Self {
            status_message: String::new(),
            is_running: false,
            progress: 0,
            current_analyzer: None,
        }
    }

    /// Get the status message.
    pub fn status_message(&self) -> &str {
        &self.status_message
    }

    /// Set the status message.
    pub fn set_status_message(&mut self, message: String) {
        self.status_message = message;
    }

    /// Check if analysis is running.
    pub fn is_running(&self) -> bool {
        self.is_running
    }

    /// Set whether analysis is running.
    pub fn set_running(&mut self, running: bool) {
        self.is_running = running;
        if !running {
            self.progress = 0;
            self.current_analyzer = None;
        }
    }

    /// Get the current progress (0-100).
    pub fn progress(&self) -> u32 {
        self.progress
    }

    /// Set the progress.
    pub fn set_progress(&mut self, progress: u32) {
        self.progress = progress.min(100);
    }

    /// Get the name of the currently running analyzer.
    pub fn current_analyzer(&self) -> Option<&str> {
        self.current_analyzer.as_deref()
    }

    /// Set the name of the currently running analyzer.
    pub fn set_current_analyzer(&mut self, name: Option<String>) {
        self.current_analyzer = name;
    }
}

impl Default for AnalysisPanel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::analyzer::Program;

    #[test]
    fn test_options_dialog_creation() {
        let program = Program::default();
        let dialog = AnalysisOptionsDialog::new(&program);
        assert!(!dialog.was_analyze_button_selected());
        assert!(!dialog.dont_show_again());
        assert!(dialog.options().is_empty());
    }

    #[test]
    fn test_options_dialog_analyze_selected() {
        let program = Program::default();
        let mut dialog = AnalysisOptionsDialog::new(&program);
        dialog.set_analyze_selected(true);
        assert!(dialog.was_analyze_button_selected());
    }

    #[test]
    fn test_options_dialog_add_option() {
        let program = Program::default();
        let mut dialog = AnalysisOptionsDialog::new(&program);
        dialog.add_option(AnalysisOptionEntry {
            name: "TestOption".to_string(),
            description: "A test option".to_string(),
            enabled: true,
            default_enabled: true,
            category: "General".to_string(),
        });
        assert_eq!(dialog.options().len(), 1);
        assert_eq!(dialog.enabled_options(), vec!["TestOption"]);
    }

    #[test]
    fn test_options_dialog_toggle() {
        let program = Program::default();
        let mut dialog = AnalysisOptionsDialog::new(&program);
        dialog.add_option(AnalysisOptionEntry {
            name: "Test".to_string(),
            description: "desc".to_string(),
            enabled: true,
            default_enabled: true,
            category: "General".to_string(),
        });
        dialog.toggle_option("Test");
        assert!(dialog.enabled_options().is_empty());
    }

    #[test]
    fn test_options_dialog_reset() {
        let program = Program::default();
        let mut dialog = AnalysisOptionsDialog::new(&program);
        dialog.add_option(AnalysisOptionEntry {
            name: "A".to_string(),
            description: "desc".to_string(),
            enabled: false,
            default_enabled: true,
            category: "General".to_string(),
        });
        dialog.reset_to_defaults();
        assert!(dialog.options()[0].enabled);
    }

    #[test]
    fn test_analysis_panel() {
        let mut panel = AnalysisPanel::new();
        assert!(!panel.is_running());
        assert_eq!(panel.progress(), 0);
        panel.set_running(true);
        panel.set_progress(50);
        panel.set_status_message("Analyzing...".to_string());
        panel.set_current_analyzer(Some("TestAnalyzer".to_string()));
        assert!(panel.is_running());
        assert_eq!(panel.progress(), 50);
        assert_eq!(panel.current_analyzer(), Some("TestAnalyzer"));
        panel.set_running(false);
        assert!(!panel.is_running());
        assert_eq!(panel.progress(), 0);
        assert!(panel.current_analyzer().is_none());
    }

    #[test]
    fn test_analysis_options_editor() {
        let program = Program::default();
        let mut editor = AnalysisOptionsEditor::new(&program);
        editor.add_option(AnalysisOptionEntry {
            name: "opt".to_string(),
            description: "desc".to_string(),
            enabled: true,
            default_enabled: false,
            category: "Test".to_string(),
        });
        assert_eq!(editor.options().len(), 1);
    }
}
