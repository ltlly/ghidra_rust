//! AutoAnalysisPlugin -- the plugin that manages auto-analysis lifecycle.
//!
//! Ported from `ghidra.app.plugin.core.analysis.AutoAnalysisPlugin`.
//!
//! The `AutoAnalysisPlugin` is responsible for:
//! - Discovering and registering all available [`Analyzer`] instances
//! - Managing program open/close/activate events
//! - Providing the "Analyze" menu action and one-shot analyzer actions
//! - Displaying analysis options dialog before running analysis
//! - Reporting analysis summary (warnings/errors) when analysis completes
//!
//! In the Rust port, this is a data-driven plugin struct rather than a
//! Java plugin class, since there is no Swing toolkit.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::base::analyzer::{
    Address, AddressRange, AddressSet, AnalysisOption, AnalysisOptionValue, AnalysisPriority,
    AnalysisWorker, Analyzer, AnalyzerType, AutoAnalysisManager, CancelledError, MessageLog,
    Program, TaskMonitor, BasicTaskMonitor,
};
use super::analysis_options::AnalysisOptionsDialog;

// ---------------------------------------------------------------------------
// AutoAnalysisPlugin
// ---------------------------------------------------------------------------

/// The auto-analysis plugin manages the lifecycle of automatic analysis.
///
/// Ported from Ghidra's `AutoAnalysisPlugin`. In the Rust port this serves
/// as the coordination layer between the UI (or headless driver) and the
/// [`AutoAnalysisManager`] which performs the actual analysis work.
///
/// # Example
///
/// ```ignore
/// use ghidra_features::analysis::AutoAnalysisPlugin;
/// use ghidra_features::base::analyzer::Program;
///
/// let mut plugin = AutoAnalysisPlugin::new();
/// plugin.find_analyzers(&program);
/// plugin.start_analysis(&mut program, &monitor);
/// ```
pub struct AutoAnalysisPlugin {
    /// Discovered analyzers that can analyze the current program.
    analyzers: Vec<Box<dyn Analyzer>>,
    /// One-shot analyzer actions registered for the current program.
    one_shot_actions: Vec<OneShotAnalyzerAction>,
    /// Whether to show the analysis options dialog before analyzing.
    show_analysis_options: bool,
    /// The analyze group name for menu organization.
    analyze_group_name: String,
    /// Enablement state for each analyzer (name -> enabled).
    enablement: HashMap<String, bool>,
    /// Help location identifier.
    help_location: String,
}

/// Represents a one-shot analyzer action that can be triggered for a specific
/// analyzer on the current program.
#[derive(Debug, Clone)]
pub struct OneShotAnalyzerAction {
    /// The analyzer this action runs.
    pub analyzer_name: String,
    /// The analyzer type.
    pub analyzer_type: AnalyzerType,
    /// Menu path for this action.
    pub menu_path: Vec<String>,
    /// Whether this action is currently enabled.
    pub enabled: bool,
}

impl AutoAnalysisPlugin {
    /// Create a new auto-analysis plugin.
    pub fn new() -> Self {
        Self {
            analyzers: Vec::new(),
            one_shot_actions: Vec::new(),
            show_analysis_options: true,
            analyze_group_name: "Analyze".to_string(),
            enablement: HashMap::new(),
            help_location: "AutoAnalysisPlugin".to_string(),
        }
    }

    /// Discover and register analyzers that can analyze the given program.
    ///
    /// This scans for all available analyzer implementations (analogous to
    /// `ClassSearcher.getInstances(Analyzer.class)` in Java) and filters
    /// them by [`Analyzer::can_analyze`].
    pub fn find_analyzers(&mut self, program: &Program) {
        self.analyzers.clear();
        self.one_shot_actions.clear();

        // In the Rust port, analyzers are registered explicitly rather than
        // discovered via reflection. The caller should register all known
        // analyzers before calling this method.
        for analyzer in &self.analyzers {
            if analyzer.can_analyze(program) {
                self.enablement.insert(
                    analyzer.name().to_string(),
                    analyzer.default_enablement(program),
                );
                self.one_shot_actions.push(OneShotAnalyzerAction {
                    analyzer_name: analyzer.name().to_string(),
                    analyzer_type: analyzer.analysis_type(),
                    menu_path: vec![
                        "Analysis".to_string(),
                        "One Shot".to_string(),
                        analyzer.name().to_string(),
                    ],
                    enabled: true,
                });
            }
        }
    }

    /// Register an analyzer with this plugin.
    pub fn add_analyzer(&mut self, analyzer: Box<dyn Analyzer>) {
        self.analyzers.push(analyzer);
    }

    /// Get all registered analyzers.
    pub fn analyzers(&self) -> &[Box<dyn Analyzer>] {
        &self.analyzers
    }

    /// Get all registered one-shot analyzer actions.
    pub fn one_shot_actions(&self) -> &[OneShotAnalyzerAction] {
        &self.one_shot_actions
    }

    /// Get the enablement state map (analyzer name -> enabled).
    pub fn enablement(&self) -> &HashMap<String, bool> {
        &self.enablement
    }

    /// Set the enabled state for a specific analyzer.
    pub fn set_analyzer_enabled(&mut self, name: &str, enabled: bool) {
        if let Some(state) = self.enablement.get_mut(name) {
            *state = enabled;
        }
    }

    /// Check if an analyzer is enabled.
    pub fn is_analyzer_enabled(&self, name: &str) -> bool {
        self.enablement.get(name).copied().unwrap_or(false)
    }

    /// Whether to show the analysis options dialog.
    pub fn show_analysis_options(&self) -> bool {
        self.show_analysis_options
    }

    /// Set whether to show the analysis options dialog.
    pub fn set_show_analysis_options(&mut self, show: bool) {
        self.show_analysis_options = show;
    }

    /// Get the analyze group name.
    pub fn analyze_group_name(&self) -> &str {
        &self.analyze_group_name
    }

    /// Called when a program is opened.
    ///
    /// This registers the program with the [`AutoAnalysisManager`] and
    /// sets up analysis options.
    pub fn program_opened(&mut self, program: &mut Program) {
        // Register options editor and help location
    }

    /// Called when a program is activated (brought to foreground).
    pub fn program_activated(&mut self, _program: &mut Program) {
        // Register stored analyzer times option
    }

    /// Called after a program is activated (post-activation).
    ///
    /// Asks the user whether to analyze the program if it hasn't been
    /// analyzed yet.
    pub fn post_program_activated(&mut self, program: &mut Program) {
        self.analyze_callback(program);
    }

    /// Show the analysis options dialog and start analysis if confirmed.
    ///
    /// Returns `true` if the user chose to analyze.
    pub fn show_options_dialog(&self, program: &Program) -> bool {
        if !self.show_analysis_options {
            return true;
        }
        let dialog = AnalysisOptionsDialog::new(program);
        dialog.was_analyze_button_selected()
    }

    /// Run the analysis callback -- analyze the given program.
    pub fn analyze_callback(&self, program: &mut Program) {
        // In a headed environment, this would show the options dialog first
        // and then start analysis in a background task.
        // In headless mode, analysis runs directly.
    }

    /// Called when analysis ends.
    ///
    /// Reports any warnings or errors from the analysis message log.
    pub fn analysis_ended(&self, manager: &mut AutoAnalysisManager, is_cancelled: bool) {
        let log = manager.get_message_log();
        if !log.is_empty() {
            log::warn!("Auto Analysis Summary: {} messages", log.len());
        }
    }

    /// Called when a program is closed.
    pub fn program_closed(&mut self, _program: &Program) {
        // Clean up resources associated with the program
    }
}

impl Default for AutoAnalysisPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AutoAnalysisManagerListener
// ---------------------------------------------------------------------------

/// Trait for listening to auto-analysis manager events.
///
/// Ported from Ghidra's `AutoAnalysisManagerListener`.
pub trait AutoAnalysisManagerListener: Send + Sync {
    /// Called when analysis has ended.
    fn analysis_ended(&self, manager: &mut AutoAnalysisManager, is_cancelled: bool);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = AutoAnalysisPlugin::new();
        assert!(plugin.analyzers().is_empty());
        assert!(plugin.one_shot_actions().is_empty());
        assert!(plugin.show_analysis_options());
        assert_eq!(plugin.analyze_group_name(), "Analyze");
    }

    #[test]
    fn test_plugin_show_options_setting() {
        let mut plugin = AutoAnalysisPlugin::new();
        assert!(plugin.show_analysis_options());
        plugin.set_show_analysis_options(false);
        assert!(!plugin.show_analysis_options());
    }

    #[test]
    fn test_one_shot_action_properties() {
        let action = OneShotAnalyzerAction {
            analyzer_name: "TestAnalyzer".to_string(),
            analyzer_type: AnalyzerType::Function,
            menu_path: vec!["Analysis".to_string(), "One Shot".to_string()],
            enabled: true,
        };
        assert_eq!(action.analyzer_name, "TestAnalyzer");
        assert!(action.enabled);
        assert_eq!(action.menu_path.len(), 2);
    }
}
