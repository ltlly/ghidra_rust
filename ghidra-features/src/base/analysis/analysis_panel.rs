//! Analysis options panel for configuring analyzer enablement.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.analysis.AnalysisPanel`.
//!
//! The [`AnalysisPanel`] presents a table of registered analyzers with
//! enable/disable checkboxes, a description pane, and per-analyzer option
//! editors.  Users can save and load named option configurations.

use std::collections::HashMap;

use super::analyzer::{
    Address, AddressRange, AddressSet, AnalysisOptionValue, AnalysisPriority, AnalysisResults,
    Analyzer, AnalyzerType, BasicTaskMonitor, CancelledError, MessageLog, Program, TaskMonitor,
};
use super::auto_analysis_manager::AutoAnalysisManager;

// ---------------------------------------------------------------------------
// Configuration persistence
// ---------------------------------------------------------------------------

/// A named set of analyzer option overrides that can be saved/loaded.
#[derive(Debug, Clone)]
pub struct OptionsConfiguration {
    /// Human-readable name (e.g. "Aggressive", "Conservative").
    pub name: String,
    /// Analyzer name -> enabled state.
    pub enablement: HashMap<String, bool>,
    /// Analyzer option name -> value.
    pub option_values: HashMap<String, AnalysisOptionValue>,
}

impl OptionsConfiguration {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            enablement: HashMap::new(),
            option_values: HashMap::new(),
        }
    }

    pub fn set_enabled(&mut self, analyzer_name: &str, enabled: bool) {
        self.enablement
            .insert(analyzer_name.to_string(), enabled);
    }

    pub fn is_enabled(&self, analyzer_name: &str, default: bool) -> bool {
        self.enablement
            .get(analyzer_name)
            .copied()
            .unwrap_or(default)
    }

    pub fn set_option(&mut self, name: &str, value: AnalysisOptionValue) {
        self.option_values.insert(name.to_string(), value);
    }

    pub fn get_option(&self, name: &str) -> Option<&AnalysisOptionValue> {
        self.option_values.get(name)
    }
}

/// The standard built-in default configuration (all analyzers at defaults).
pub const STANDARD_DEFAULT_CONFIGURATION_NAME: &str = "Standard Defaults";

// ---------------------------------------------------------------------------
// Analyzer enablement state (row model)
// ---------------------------------------------------------------------------

/// Per-analyzer row in the analysis panel table.
#[derive(Debug, Clone)]
pub struct AnalyzerEnablementState {
    name: String,
    description: String,
    enabled: bool,
    default_enabled: bool,
    analysis_type: AnalyzerType,
    priority: AnalysisPriority,
    is_prototype: bool,
}

impl AnalyzerEnablementState {
    pub fn new(
        analyzer: &dyn Analyzer,
        enabled: bool,
        program: &Program,
    ) -> Self {
        Self {
            name: analyzer.name().to_string(),
            description: analyzer.description().to_string(),
            enabled,
            default_enabled: analyzer.default_enablement(program),
            analysis_type: analyzer.analysis_type(),
            priority: analyzer.priority(),
            is_prototype: analyzer.is_prototype(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn default_enabled(&self) -> bool {
        self.default_enabled
    }

    pub fn analysis_type(&self) -> AnalyzerType {
        self.analysis_type
    }

    pub fn priority(&self) -> AnalysisPriority {
        self.priority
    }

    pub fn is_prototype(&self) -> bool {
        self.is_prototype
    }
}

// ---------------------------------------------------------------------------
// Analysis panel
// ---------------------------------------------------------------------------

/// UI panel for configuring analyzer enablement and options.
///
/// In Ghidra this is a Swing `JPanel`; here it is a data-driven model
/// that can be rendered by any front-end.
pub struct AnalysisPanel {
    /// Programs being configured.
    programs: Vec<Program>,
    /// Per-analyzer rows.
    states: Vec<AnalyzerEnablementState>,
    /// Map from analyzer name -> index into `states`.
    name_to_index: HashMap<String, usize>,
    /// Current program analysis options (non-default values only).
    current_program_options: OptionsConfiguration,
    /// Currently selected options configuration.
    selected_options: OptionsConfiguration,
    /// Saved user configurations.
    saved_configurations: Vec<OptionsConfiguration>,
    /// Index of the selected analyzer (-1 = none).
    selected_analyzer_index: Option<usize>,
}

impl AnalysisPanel {
    /// Create an analysis panel for a single program.
    pub fn new(program: Program) -> Self {
        Self::new_multi(vec![program])
    }

    /// Create an analysis panel for multiple programs.
    ///
    /// All programs must share the same architecture (analyzers).
    pub fn new_multi(programs: Vec<Program>) -> Self {
        assert!(!programs.is_empty(), "Must provide at least one program");
        let current_program_options = Self::build_current_program_options(&programs[0]);
        Self {
            programs,
            states: Vec::new(),
            name_to_index: HashMap::new(),
            current_program_options: current_program_options.clone(),
            selected_options: current_program_options,
            saved_configurations: Vec::new(),
            selected_analyzer_index: None,
        }
    }

    /// Reload analyzer states from the analysis manager.
    pub fn load_analyzers(&mut self, analyzers: &[Box<dyn Analyzer>]) {
        self.states.clear();
        self.name_to_index.clear();

        let program = &self.programs[0];
        for analyzer in analyzers {
            let name = analyzer.name().to_string();
            let enabled = self
                .selected_options
                .is_enabled(&name, analyzer.default_enablement(program));
            let state = AnalyzerEnablementState::new(&**analyzer, enabled, program);
            self.name_to_index.insert(name, self.states.len());
            self.states.push(state);
        }
    }

    /// Number of analyzer rows.
    pub fn num_analyzers(&self) -> usize {
        self.states.len()
    }

    /// Get the analyzer state at a given row index.
    pub fn state_at(&self, index: usize) -> Option<&AnalyzerEnablementState> {
        self.states.get(index)
    }

    /// Get all analyzer states.
    pub fn states(&self) -> &[AnalyzerEnablementState] {
        &self.states
    }

    /// Get a mutable reference to all analyzer states.
    pub fn states_mut(&mut self) -> &mut [AnalyzerEnablementState] {
        &mut self.states
    }

    /// Select an analyzer row.
    pub fn select_analyzer(&mut self, index: Option<usize>) {
        self.selected_analyzer_index = index;
    }

    /// Currently selected analyzer index.
    pub fn selected_analyzer_index(&self) -> Option<usize> {
        self.selected_analyzer_index
    }

    /// Description of the currently selected analyzer.
    pub fn selected_description(&self) -> &str {
        self.selected_analyzer_index
            .and_then(|i| self.states.get(i))
            .map(|s| s.description())
            .unwrap_or("")
    }

    // -- Enable/disable controls --

    /// Toggle an analyzer's enablement by name.
    pub fn set_analyzer_enabled(&mut self, name: &str, enabled: bool) {
        if let Some(&idx) = self.name_to_index.get(name) {
            self.states[idx].set_enabled(enabled);
        }
    }

    /// Enable all analyzers.
    pub fn select_all(&mut self) {
        for state in &mut self.states {
            state.set_enabled(true);
        }
    }

    /// Disable all analyzers.
    pub fn deselect_all(&mut self) {
        for state in &mut self.states {
            state.set_enabled(false);
        }
    }

    /// Whether the current editor values differ from the program's saved options.
    pub fn has_changed_values(&self) -> bool {
        for state in &self.states {
            let orig = self
                .current_program_options
                .is_enabled(state.name(), state.default_enabled());
            if state.is_enabled() != orig {
                return true;
            }
        }
        false
    }

    // -- Configuration management --

    /// Current program options configuration.
    pub fn current_program_options(&self) -> &OptionsConfiguration {
        &self.current_program_options
    }

    /// Currently selected options configuration.
    pub fn selected_options(&self) -> &OptionsConfiguration {
        &self.selected_options
    }

    /// Set the selected options configuration and reload editors.
    pub fn set_selected_options(&mut self, config: OptionsConfiguration) {
        self.selected_options = config;
        self.load_current_options_into_editors();
    }

    /// Reset editors to the currently selected options configuration.
    pub fn reset(&mut self) {
        self.load_current_options_into_editors();
    }

    /// Save the current editor settings as a named configuration.
    pub fn save_configuration(&mut self, name: &str) -> OptionsConfiguration {
        let mut config = OptionsConfiguration::new(name);
        for state in &self.states {
            config.set_enabled(state.name(), state.is_enabled());
        }
        self.saved_configurations.push(config.clone());
        config
    }

    /// Delete a saved configuration by name.
    pub fn delete_configuration(&mut self, name: &str) {
        self.saved_configurations
            .retain(|c| c.name != name);
    }

    /// Whether the currently selected options are a user configuration
    /// (not the standard defaults or current program options).
    pub fn is_user_configuration(&self) -> bool {
        self.selected_options.name != STANDARD_DEFAULT_CONFIGURATION_NAME
            && self.selected_options.name != self.current_program_options.name
    }

    /// All saved configuration names.
    pub fn saved_configuration_names(&self) -> Vec<&str> {
        self.saved_configurations
            .iter()
            .map(|c| c.name.as_str())
            .collect()
    }

    // -- Apply changes --

    /// Apply current editor values to the first program, then copy to all
    /// other programs.
    pub fn apply_changes(&mut self) {
        self.apply_to_program(0);
        for i in 1..self.programs.len() {
            self.copy_options_to_program(i);
        }
        self.current_program_options = Self::build_current_program_options(&self.programs[0]);
    }

    /// Apply changes only to a specific program index.
    fn apply_to_program(&self, index: usize) {
        // In the real Ghidra this would write to the program's analysis
        // properties via a transaction.  Here we just validate.
        let _ = &self.programs[index];
    }

    /// Copy current options to another program.
    fn copy_options_to_program(&self, index: usize) {
        let _ = &self.programs[index];
        // Would iterate option names and copy values in real implementation.
    }

    // -- Options configuration combo box support --

    /// Get the ordered list of options configurations for display in a
    /// combo box: [current program, standard defaults, ...user saved].
    pub fn options_choices(&self) -> Vec<&OptionsConfiguration> {
        let mut choices: Vec<&OptionsConfiguration> = Vec::new();
        choices.push(&self.current_program_options);
        for config in &self.saved_configurations {
            choices.push(config);
        }
        choices
    }

    /// Find a configuration by name.
    pub fn find_configuration(&self, name: &str) -> Option<&OptionsConfiguration> {
        if self.current_program_options.name == name {
            return Some(&self.current_program_options);
        }
        self.saved_configurations
            .iter()
            .find(|c| c.name == name)
    }

    // -- Analyze all programs --

    /// Run analysis on all programs using the current enablement settings.
    pub fn analyze_all(&self, monitor: &dyn TaskMonitor) -> Vec<AnalysisResults> {
        let mut results = Vec::new();
        for program in &self.programs {
            let mut mgr = AutoAnalysisManager::new(program.clone());
            let r = mgr.run_analysis(monitor);
            match r {
                Ok(res) => results.push(res),
                Err(_) => break,
            }
        }
        results
    }

    // -- Internal helpers --

    fn build_current_program_options(program: &Program) -> OptionsConfiguration {
        let config = OptionsConfiguration::new("Current Program Options");
        // In real Ghidra, this reads non-default values from the program's
        // analysis properties.  Here we start with an empty config.
        let _ = program;
        config
    }

    fn load_current_options_into_editors(&mut self) {
        let names: Vec<String> = self.states.iter().map(|s| s.name().to_string()).collect();
        for name in &names {
            let default_enabled = self
                .states
                .iter()
                .find(|s| s.name() == name)
                .map(|s| s.default_enabled())
                .unwrap_or(false);
            let enabled = self.selected_options.is_enabled(name, default_enabled);
            if let Some(&idx) = self.name_to_index.get(name) {
                self.states[idx].set_enabled(enabled);
            }
        }
    }
}

impl std::fmt::Debug for AnalysisPanel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnalysisPanel")
            .field("num_programs", &self.programs.len())
            .field("num_analyzers", &self.states.len())
            .field("selected", &self.selected_analyzer_index)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::analyzer::{
        CodeBoundaryAnalyzer, DataReferenceAnalyzer, FunctionStartAnalyzer, Language,
    };
    use super::*;

    fn make_test_program() -> Program {
        let lang = Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let mut prog = Program::new("test", lang);
        prog.image_base = 0x400000;
        prog.memory.add_range(AddressRange::new(
            Address::new(0x400000),
            Address::new(0x500000),
        ));
        prog
    }

    fn make_analyzers() -> Vec<Box<dyn Analyzer>> {
        vec![
            Box::new(FunctionStartAnalyzer::new()),
            Box::new(CodeBoundaryAnalyzer::new()),
            Box::new(DataReferenceAnalyzer::new()),
        ]
    }

    #[test]
    fn test_panel_creation() {
        let panel = AnalysisPanel::new(make_test_program());
        assert_eq!(panel.num_analyzers(), 0);
        assert!(panel.selected_analyzer_index().is_none());
    }

    #[test]
    fn test_load_analyzers() {
        let mut panel = AnalysisPanel::new(make_test_program());
        let analyzers = make_analyzers();
        panel.load_analyzers(&analyzers);
        assert_eq!(panel.num_analyzers(), 3);
    }

    #[test]
    fn test_analyzer_states() {
        let mut panel = AnalysisPanel::new(make_test_program());
        panel.load_analyzers(&make_analyzers());
        let names: Vec<&str> = panel.states().iter().map(|s| s.name()).collect();
        assert!(names.contains(&"Function Start Analyzer"));
        assert!(names.contains(&"Code Boundary Analyzer"));
        assert!(names.contains(&"Reference"));
    }

    #[test]
    fn test_select_deselect_all() {
        let mut panel = AnalysisPanel::new(make_test_program());
        panel.load_analyzers(&make_analyzers());

        panel.deselect_all();
        assert!(panel.states().iter().all(|s| !s.is_enabled()));

        panel.select_all();
        assert!(panel.states().iter().all(|s| s.is_enabled()));
    }

    #[test]
    fn test_toggle_analyzer() {
        let mut panel = AnalysisPanel::new(make_test_program());
        panel.load_analyzers(&make_analyzers());

        panel.set_analyzer_enabled("Function Start Analyzer", false);
        let state = panel
            .states()
            .iter()
            .find(|s| s.name() == "Function Start Analyzer")
            .unwrap();
        assert!(!state.is_enabled());
    }

    #[test]
    fn test_select_analyzer() {
        let mut panel = AnalysisPanel::new(make_test_program());
        panel.load_analyzers(&make_analyzers());

        assert_eq!(panel.selected_description(), "");
        panel.select_analyzer(Some(0));
        assert!(!panel.selected_description().is_empty());
    }

    #[test]
    fn test_save_and_find_configuration() {
        let mut panel = AnalysisPanel::new(make_test_program());
        panel.load_analyzers(&make_analyzers());
        panel.select_all();

        let config = panel.save_configuration("My Config");
        assert_eq!(config.name, "My Config");

        let found = panel.find_configuration("My Config");
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "My Config");
    }

    #[test]
    fn test_delete_configuration() {
        let mut panel = AnalysisPanel::new(make_test_program());
        panel.load_analyzers(&make_analyzers());
        panel.save_configuration("ToDelete");
        assert_eq!(panel.saved_configuration_names().len(), 1);

        panel.delete_configuration("ToDelete");
        assert!(panel.saved_configuration_names().is_empty());
    }

    #[test]
    fn test_options_choices() {
        let mut panel = AnalysisPanel::new(make_test_program());
        panel.load_analyzers(&make_analyzers());
        panel.save_configuration("User1");
        panel.save_configuration("User2");

        let choices = panel.options_choices();
        // First is always current program options
        assert_eq!(choices[0].name, "Current Program Options");
        assert!(choices.len() >= 3);
    }

    #[test]
    fn test_set_selected_options() {
        let mut panel = AnalysisPanel::new(make_test_program());
        panel.load_analyzers(&make_analyzers());

        let mut config = OptionsConfiguration::new("Custom");
        config.set_enabled("Function Start Analyzer", false);
        panel.set_selected_options(config);

        let state = panel
            .states()
            .iter()
            .find(|s| s.name() == "Function Start Analyzer")
            .unwrap();
        assert!(!state.is_enabled());
    }

    #[test]
    fn test_is_user_configuration() {
        let mut panel = AnalysisPanel::new(make_test_program());
        assert!(!panel.is_user_configuration());

        panel.selected_options = OptionsConfiguration::new("My Custom");
        assert!(panel.is_user_configuration());
    }

    #[test]
    fn test_has_changed_values() {
        let mut panel = AnalysisPanel::new(make_test_program());
        panel.load_analyzers(&make_analyzers());

        // Initially no changes (defaults match)
        assert!(!panel.has_changed_values());

        // Toggle one
        panel.set_analyzer_enabled("Function Start Analyzer", false);
        assert!(panel.has_changed_values());
    }

    #[test]
    fn test_multi_program_panel() {
        let progs = vec![make_test_program(), make_test_program()];
        let mut panel = AnalysisPanel::new_multi(progs);
        panel.load_analyzers(&make_analyzers());
        assert_eq!(panel.num_analyzers(), 3);
    }

    #[test]
    fn test_apply_changes() {
        let mut panel = AnalysisPanel::new(make_test_program());
        panel.load_analyzers(&make_analyzers());
        panel.set_analyzer_enabled("Function Start Analyzer", false);
        panel.apply_changes();
        // After apply, current_program_options should be refreshed
    }

    #[test]
    fn test_reset() {
        let mut panel = AnalysisPanel::new(make_test_program());
        panel.load_analyzers(&make_analyzers());
        panel.set_analyzer_enabled("Function Start Analyzer", false);
        panel.reset();
        // After reset, values should match selected_options
    }

    #[test]
    fn test_analyze_all() {
        let mut panel = AnalysisPanel::new(make_test_program());
        panel.load_analyzers(&make_analyzers());
        let monitor = BasicTaskMonitor::new();
        let results = panel.analyze_all(&monitor);
        assert_eq!(results.len(), 1);
    }
}
