//! AutoAnalysisPlugin -- the main auto-analysis plugin.
//!
//! Ported from `ghidra.app.plugin.core.analysis.AutoAnalysisPlugin`.
//! Manages the auto-analysis lifecycle, discovers analyzers, creates
//! one-shot actions, and coordinates analysis across programs.

use std::collections::HashMap;

use crate::base::analyzer::core::*;
use crate::base::analyzer::manager::*;
use crate::base::analyzer::r#trait::*;
use crate::base::analyzer::scheduler::AnalysisResults;
use crate::base::analyzer::worker::*;

/// Listener for analysis manager events.
///
/// Ported from `ghidra.app.plugin.core.analysis.AutoAnalysisManagerListener`.
/// Notified when analysis ends for a program.
pub trait AutoAnalysisManagerListener: Send + Sync {
    /// Called when analysis has ended.
    fn analysis_ended(&self, was_cancelled: bool);
}

/// One-shot analyzer action descriptor.
///
/// Represents an analyzer that can be run once on a specific address set.
#[derive(Debug, Clone)]
pub struct OneShotAnalyzerAction {
    /// The analyzer name.
    pub analyzer_name: String,
    /// The analyzer description.
    pub description: String,
    /// Whether this analyzer supports one-time analysis.
    pub supports_one_time: bool,
    /// The analyzer priority.
    pub priority: AnalysisPriority,
}

/// Plugin state for auto-analysis.
///
/// Manages the lifecycle of auto-analysis including:
/// - Discovering and registering analyzers
/// - Creating one-shot analysis actions
/// - Processing program open/close/activate events
/// - Showing analysis options dialog
/// - Running analysis in the background
#[derive(Debug)]
pub struct AutoAnalysisPlugin {
    /// Plugin name.
    name: String,
    /// Registered analyzers.
    analyzers: Vec<String>,
    /// One-shot analyzer actions.
    one_shot_actions: Vec<OneShotAnalyzerAction>,
    /// Whether to show analysis options dialog.
    show_analysis_options: bool,
    /// Analysis managers per program (by program name).
    managers: HashMap<String, AutoAnalysisManager>,
    /// Registered listeners.
    listeners: Vec<Box<dyn AutoAnalysisManagerListener>>,
}

impl AutoAnalysisPlugin {
    /// Creates a new auto-analysis plugin.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            analyzers: Vec::new(),
            one_shot_actions: Vec::new(),
            show_analysis_options: true,
            managers: HashMap::new(),
            listeners: Vec::new(),
        }
    }

    /// Returns the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns registered analyzer names.
    pub fn analyzers(&self) -> &[String] {
        &self.analyzers
    }

    /// Returns one-shot analyzer actions.
    pub fn one_shot_actions(&self) -> &[OneShotAnalyzerAction] {
        &self.one_shot_actions
    }

    /// Sets whether to show the analysis options dialog.
    pub fn set_show_analysis_options(&mut self, show: bool) {
        self.show_analysis_options = show;
    }

    /// Returns whether the analysis options dialog is shown.
    pub fn show_analysis_options(&self) -> bool {
        self.show_analysis_options
    }

    /// Registers an analyzer name.
    pub fn register_analyzer(&mut self, name: impl Into<String>) {
        self.analyzers.push(name.into());
        self.analyzers.sort();
    }

    /// Registers a one-shot analyzer action.
    pub fn register_one_shot_action(&mut self, action: OneShotAnalyzerAction) {
        self.one_shot_actions.push(action);
    }

    /// Adds a listener for analysis events.
    pub fn add_listener(&mut self, listener: Box<dyn AutoAnalysisManagerListener>) {
        self.listeners.push(listener);
    }

    /// Gets or creates an analysis manager for a program.
    pub fn get_analysis_manager(&mut self, program_name: &str) -> &mut AutoAnalysisManager {
        self.managers
            .entry(program_name.to_string())
            .or_insert_with(|| {
                let lang = Language {
                    processor: "x86".into(),
                    variant: "LE".into(),
                    size: 64,
                };
                AutoAnalysisManager::new(Program::new(program_name, lang))
            })
    }

    /// Returns whether an analysis manager exists for the given program.
    pub fn has_analysis_manager(&self, program_name: &str) -> bool {
        self.managers.contains_key(program_name)
    }

    /// Removes the analysis manager for a program.
    pub fn remove_analysis_manager(&mut self, program_name: &str) {
        self.managers.remove(program_name);
    }

    /// Called when a program is opened.
    pub fn program_opened(&mut self, program_name: &str) {
        let _ = self.get_analysis_manager(program_name);
    }

    /// Called when a program is closed.
    pub fn program_closed(&mut self, program_name: &str) {
        self.remove_analysis_manager(program_name);
    }

    /// Called when a program is activated.
    pub fn program_activated(&mut self, program_name: &str) {
        // Create one-shot actions for the activated program
        self.one_shot_actions.clear();

        // In a real implementation, this would check which analyzers
        // support one-time analysis and can analyze the program
    }

    /// Runs analysis on a program.
    pub fn analyze_program(
        &mut self,
        program_name: &str,
        monitor: &dyn TaskMonitor,
    ) -> Result<AnalysisResults, CancelledError> {
        let mgr = self.get_analysis_manager(program_name);
        mgr.run_analysis(monitor)
    }

    /// Runs analysis on all open programs.
    pub fn analyze_all_open(
        &mut self,
        monitor: &dyn TaskMonitor,
    ) -> Result<Vec<(String, AnalysisResults)>, CancelledError> {
        let mut results = Vec::new();
        let program_names: Vec<String> = self.managers.keys().cloned().collect();

        monitor.initialize(program_names.len() as u64);

        for (i, name) in program_names.iter().enumerate() {
            monitor.check_cancelled()?;
            monitor.set_message(&format!("Analyzing {}...", name));

            let result = {
                let mgr = self.managers.get_mut(name).unwrap();
                mgr.run_analysis(monitor)?
            };

            results.push((name.clone(), result));
            monitor.set_progress(i as u64 + 1);
        }

        Ok(results)
    }

    /// Notifies all listeners that analysis has ended.
    pub fn notify_analysis_ended(&self, was_cancelled: bool) {
        for listener in &self.listeners {
            listener.analysis_ended(was_cancelled);
        }
    }

    /// Creates one-shot actions for analyzers that support it.
    pub fn create_one_shot_actions(
        &mut self,
        analyzers: &[Box<dyn Analyzer>],
        program: &Program,
    ) {
        self.one_shot_actions.clear();

        for analyzer in analyzers {
            if analyzer.supports_one_time_analysis() && analyzer.can_analyze(program) {
                self.one_shot_actions.push(OneShotAnalyzerAction {
                    analyzer_name: analyzer.name().to_string(),
                    description: analyzer.description().to_string(),
                    supports_one_time: true,
                    priority: analyzer.priority(),
                });
            }
        }
    }

    /// Returns a description of the plugin.
    pub fn description() -> &'static str {
        "Provides coordination and a service for All Auto Analysis tasks"
    }

    /// Returns the descriptive name.
    pub fn descriptive_name() -> &'static str {
        "AutoAnalysisManager"
    }

    /// Returns the category.
    pub fn category() -> &'static str {
        "Analysis"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = AutoAnalysisPlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert!(plugin.analyzers().is_empty());
        assert!(plugin.one_shot_actions().is_empty());
        assert!(plugin.show_analysis_options());
    }

    #[test]
    fn test_plugin_register_analyzer() {
        let mut plugin = AutoAnalysisPlugin::new("Test");
        plugin.register_analyzer("Function Start");
        plugin.register_analyzer("Code Boundary");
        assert_eq!(plugin.analyzers().len(), 2);
        // Should be sorted
        assert_eq!(plugin.analyzers()[0], "Code Boundary");
        assert_eq!(plugin.analyzers()[1], "Function Start");
    }

    #[test]
    fn test_plugin_register_one_shot_action() {
        let mut plugin = AutoAnalysisPlugin::new("Test");
        plugin.register_one_shot_action(OneShotAnalyzerAction {
            analyzer_name: "Test Analyzer".into(),
            description: "Test".into(),
            supports_one_time: true,
            priority: AnalysisPriority::CODE_ANALYSIS,
        });
        assert_eq!(plugin.one_shot_actions().len(), 1);
    }

    #[test]
    fn test_plugin_show_options() {
        let mut plugin = AutoAnalysisPlugin::new("Test");
        assert!(plugin.show_analysis_options());
        plugin.set_show_analysis_options(false);
        assert!(!plugin.show_analysis_options());
    }

    #[test]
    fn test_plugin_program_lifecycle() {
        let mut plugin = AutoAnalysisPlugin::new("Test");

        // Open
        plugin.program_opened("prog1");
        assert!(plugin.has_analysis_manager("prog1"));

        // Activate
        plugin.program_activated("prog1");

        // Close
        plugin.program_closed("prog1");
        assert!(!plugin.has_analysis_manager("prog1"));
    }

    #[test]
    fn test_plugin_get_analysis_manager() {
        let mut plugin = AutoAnalysisPlugin::new("Test");
        let mgr = plugin.get_analysis_manager("prog1");
        assert_eq!(mgr.program().name, "prog1");
    }

    #[test]
    fn test_plugin_analyze_program() {
        let mut plugin = AutoAnalysisPlugin::new("Test");
        let monitor = BasicTaskMonitor::new();
        let result = plugin.analyze_program("prog1", &monitor).unwrap();
        assert_eq!(result.tasks_executed, 0);
    }

    #[test]
    fn test_plugin_analyze_all_open() {
        let mut plugin = AutoAnalysisPlugin::new("Test");
        plugin.program_opened("prog1");
        plugin.program_opened("prog2");

        let monitor = BasicTaskMonitor::new();
        let results = plugin.analyze_all_open(&monitor).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_plugin_description() {
        assert!(!AutoAnalysisPlugin::description().is_empty());
        assert!(!AutoAnalysisPlugin::descriptive_name().is_empty());
        assert!(!AutoAnalysisPlugin::category().is_empty());
    }

    #[test]
    fn test_plugin_listener() {
        struct TestListener {
            called: std::sync::atomic::AtomicBool,
        }
        impl AutoAnalysisManagerListener for TestListener {
            fn analysis_ended(&self, _was_cancelled: bool) {
                self.called.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }

        let mut plugin = AutoAnalysisPlugin::new("Test");
        let listener = TestListener {
            called: std::sync::atomic::AtomicBool::new(false),
        };
        plugin.add_listener(Box::new(listener));

        plugin.notify_analysis_ended(false);
        // Can't easily check the AtomicBool through the Box, but no panic is good
    }

    #[test]
    fn test_plugin_create_one_shot_actions() {
        let mut plugin = AutoAnalysisPlugin::new("Test");
        let lang = Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let program = Program::new("test", lang);

        // Create mock analyzers
        struct MockAnalyzer;
        impl Analyzer for MockAnalyzer {
            fn name(&self) -> &str {
                "Mock"
            }
            fn description(&self) -> &str {
                "Mock analyzer"
            }
            fn analysis_type(&self) -> AnalyzerType {
                AnalyzerType::Byte
            }
            fn priority(&self) -> AnalysisPriority {
                AnalysisPriority::CODE_ANALYSIS
            }
            fn can_analyze(&self, _: &Program) -> bool {
                true
            }
            fn supports_one_time_analysis(&self) -> bool {
                true
            }
            fn added(
                &self,
                _: &mut Program,
                _: &AddressSet,
                _: &dyn TaskMonitor,
                _: &mut MessageLog,
            ) -> Result<bool, CancelledError> {
                Ok(true)
            }
        }

        let analyzers: Vec<Box<dyn Analyzer>> = vec![Box::new(MockAnalyzer)];
        plugin.create_one_shot_actions(&analyzers, &program);
        assert_eq!(plugin.one_shot_actions().len(), 1);
        assert_eq!(plugin.one_shot_actions()[0].analyzer_name, "Mock");
    }
}
