//! AnalyzeAllOpenProgramsTask -- batch analysis across multiple programs.
//!
//! Ported from `ghidra.app.plugin.core.analysis.AnalyzeAllOpenProgramsTask`.
//! Coordinates analysis of multiple open programs, filtering by architecture
//! compatibility and sharing analysis options.

use std::collections::HashMap;

use crate::base::analyzer::core::*;
use crate::base::analyzer::manager::*;
use crate::base::analyzer::scheduler::AnalysisResults;
use crate::base::analyzer::worker::*;

/// Program identifier based on language and compiler spec.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProgramID {
    /// The language ID (processor + variant).
    pub language_id: String,
    /// The compiler spec ID.
    pub compiler_spec_id: String,
}

impl ProgramID {
    /// Creates a ProgramID from a program.
    pub fn from_program(program: &Program) -> Self {
        Self {
            language_id: format!("{}:{}", program.language.processor, program.language.variant),
            compiler_spec_id: "default".into(),
        }
    }
}

/// Analysis options snapshot from a program.
#[derive(Debug, Clone)]
pub struct AnalysisOptionsSnapshot {
    /// The program ID these options apply to.
    pub program_id: ProgramID,
    /// Whether the program has been analyzed.
    pub is_analyzed: bool,
    /// Analysis options (key-value pairs).
    pub options: HashMap<String, String>,
}

/// Result of analyzing a single program.
#[derive(Debug, Clone)]
pub struct ProgramAnalysisResult {
    /// The program name.
    pub program_name: String,
    /// The program ID.
    pub program_id: ProgramID,
    /// Analysis results (if analysis was performed).
    pub results: Option<AnalysisResults>,
    /// Whether this program was skipped.
    pub skipped: bool,
    /// Skip reason (if skipped).
    pub skip_reason: Option<String>,
}

/// Strategy for analyzing a single program.
pub trait ProgramAnalysisStrategy: Send + Sync {
    /// Analyzes a program using the given manager.
    fn analyze_program(
        &self,
        program_name: &str,
        manager: &mut AutoAnalysisManager,
        monitor: &dyn TaskMonitor,
    ) -> Result<AnalysisResults, CancelledError>;
}

/// Default strategy that runs analysis inline.
pub struct InlineAnalysisStrategy;

impl ProgramAnalysisStrategy for InlineAnalysisStrategy {
    fn analyze_program(
        &self,
        _program_name: &str,
        manager: &mut AutoAnalysisManager,
        monitor: &dyn TaskMonitor,
    ) -> Result<AnalysisResults, CancelledError> {
        manager.run_analysis(monitor)
    }
}

/// Batch analysis task for multiple programs.
///
/// Coordinates analysis of all open programs, handling:
/// - Architecture compatibility checking
/// - Option sharing across compatible programs
/// - Progress tracking and cancellation
///
/// # Example
///
/// ```
/// use ghidra_features::base::analyzer::*;
///
/// let task = AnalyzeAllOpenProgramsTask::new("Batch Analysis");
/// assert_eq!(task.name(), "Batch Analysis");
/// ```
#[derive(Debug)]
pub struct AnalyzeAllOpenProgramsTask {
    /// Task name.
    name: String,
    /// Programs to analyze (names).
    programs: Vec<String>,
    /// Analysis strategy.
    strategy: Box<dyn ProgramAnalysisStrategy>,
    /// Results per program.
    results: Vec<ProgramAnalysisResult>,
}

impl AnalyzeAllOpenProgramsTask {
    /// Creates a new batch analysis task.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            programs: Vec::new(),
            strategy: Box::new(InlineAnalysisStrategy),
            results: Vec::new(),
        }
    }

    /// Creates a task with specific programs.
    pub fn with_programs(name: impl Into<String>, programs: Vec<String>) -> Self {
        Self {
            name: name.into(),
            programs,
            strategy: Box::new(InlineAnalysisStrategy),
            results: Vec::new(),
        }
    }

    /// Sets the analysis strategy.
    pub fn set_strategy(&mut self, strategy: Box<dyn ProgramAnalysisStrategy>) {
        self.strategy = strategy;
    }

    /// Returns the task name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the list of programs to analyze.
    pub fn programs(&self) -> &[String] {
        &self.programs
    }

    /// Adds a program to analyze.
    pub fn add_program(&mut self, name: impl Into<String>) {
        self.programs.push(name.into());
    }

    /// Returns analysis results.
    pub fn results(&self) -> &[ProgramAnalysisResult] {
        &self.results
    }

    /// Returns the number of programs analyzed.
    pub fn analyzed_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.results.is_some())
            .count()
    }

    /// Returns the number of programs skipped.
    pub fn skipped_count(&self) -> usize {
        self.results.iter().filter(|r| r.skipped).count()
    }

    /// Filters programs by architecture compatibility.
    ///
    /// Returns only programs that match the given program ID.
    pub fn filter_by_architecture(
        &self,
        programs: &[(&str, ProgramID)],
        target_id: &ProgramID,
    ) -> Vec<&str> {
        programs
            .iter()
            .filter(|(_, id)| id == target_id)
            .map(|(name, _)| *name)
            .collect()
    }

    /// Runs batch analysis on the given programs.
    pub fn run(
        &mut self,
        managers: &mut [(&str, AutoAnalysisManager)],
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledError> {
        self.results.clear();
        monitor.initialize(managers.len() as u64);

        for (i, (name, manager)) in managers.iter_mut().enumerate() {
            monitor.check_cancelled()?;
            monitor.set_message(&format!("Analyzing {}...", name));

            let result = self.strategy.analyze_program(name, manager, monitor);

            match result {
                Ok(results) => {
                    self.results.push(ProgramAnalysisResult {
                        program_name: name.to_string(),
                        program_id: ProgramID::from_program(manager.program()),
                        results: Some(results),
                        skipped: false,
                        skip_reason: None,
                    });
                }
                Err(CancelledError) => {
                    self.results.push(ProgramAnalysisResult {
                        program_name: name.to_string(),
                        program_id: ProgramID::from_program(manager.program()),
                        results: None,
                        skipped: true,
                        skip_reason: Some("Cancelled".into()),
                    });
                    return Err(CancelledError);
                }
            }

            monitor.set_progress(i as u64 + 1);
        }

        Ok(())
    }

    /// Returns total analysis time across all programs.
    pub fn total_time_ms(&self) -> u64 {
        self.results
            .iter()
            .filter_map(|r| r.results.as_ref().map(|r| r.total_time_ms))
            .sum()
    }

    /// Returns total tasks executed across all programs.
    pub fn total_tasks_executed(&self) -> usize {
        self.results
            .iter()
            .filter_map(|r| r.results.as_ref().map(|r| r.tasks_executed))
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_task_creation() {
        let task = AnalyzeAllOpenProgramsTask::new("Test Task");
        assert_eq!(task.name(), "Test Task");
        assert!(task.programs().is_empty());
    }

    #[test]
    fn test_batch_task_with_programs() {
        let task = AnalyzeAllOpenProgramsTask::with_programs(
            "Batch",
            vec!["prog1".into(), "prog2".into()],
        );
        assert_eq!(task.programs().len(), 2);
    }

    #[test]
    fn test_batch_task_add_program() {
        let mut task = AnalyzeAllOpenProgramsTask::new("Test");
        task.add_program("prog1");
        task.add_program("prog2");
        assert_eq!(task.programs().len(), 2);
    }

    #[test]
    fn test_program_id_from_program() {
        let lang = Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let p = Program::new("test", lang);
        let id = ProgramID::from_program(&p);
        assert_eq!(id.language_id, "x86:LE");
    }

    #[test]
    fn test_program_id_equality() {
        let id1 = ProgramID {
            language_id: "x86:LE".into(),
            compiler_spec_id: "default".into(),
        };
        let id2 = ProgramID {
            language_id: "x86:LE".into(),
            compiler_spec_id: "default".into(),
        };
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_filter_by_architecture() {
        let task = AnalyzeAllOpenProgramsTask::new("Test");
        let programs = vec![
            ("prog1", ProgramID { language_id: "x86:LE".into(), compiler_spec_id: "default".into() }),
            ("prog2", ProgramID { language_id: "ARM:LE".into(), compiler_spec_id: "default".into() }),
            ("prog3", ProgramID { language_id: "x86:LE".into(), compiler_spec_id: "gcc".into() }),
        ];
        let target = ProgramID { language_id: "x86:LE".into(), compiler_spec_id: "default".into() };
        let filtered = task.filter_by_architecture(&programs, &target);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0], "prog1");
    }

    #[test]
    fn test_batch_task_results_empty() {
        let task = AnalyzeAllOpenProgramsTask::new("Test");
        assert!(task.results().is_empty());
        assert_eq!(task.analyzed_count(), 0);
        assert_eq!(task.skipped_count(), 0);
        assert_eq!(task.total_time_ms(), 0);
    }

    #[test]
    fn test_batch_task_run() {
        let mut task = AnalyzeAllOpenProgramsTask::new("Test");
        let lang = Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let p1 = Program::new("prog1", lang.clone());
        let p2 = Program::new("prog2", lang);
        let mut mgr1 = AutoAnalysisManager::new(p1);
        let mut mgr2 = AutoAnalysisManager::new(p2);

        let monitor = BasicTaskMonitor::new();
        let mut managers: Vec<(&str, AutoAnalysisManager)> =
            vec![("prog1", mgr1), ("prog2", mgr2)];

        task.run(&mut managers, &monitor).unwrap();
        assert_eq!(task.results().len(), 2);
        assert_eq!(task.analyzed_count(), 2);
    }

    #[test]
    fn test_batch_task_total_tasks() {
        let mut task = AnalyzeAllOpenProgramsTask::new("Test");
        let lang = Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let p = Program::new("test", lang);
        let mut mgr = AutoAnalysisManager::new(p);
        let monitor = BasicTaskMonitor::new();
        let mut managers = vec![("test", mgr)];

        task.run(&mut managers, &monitor).unwrap();
        // No analyzers added, so 0 tasks executed
        assert_eq!(task.total_tasks_executed(), 0);
    }

    #[test]
    fn test_analysis_options_snapshot() {
        let lang = Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let p = Program::new("test", lang);
        let snapshot = AnalysisOptionsSnapshot {
            program_id: ProgramID::from_program(&p),
            is_analyzed: false,
            options: HashMap::new(),
        };
        assert!(!snapshot.is_analyzed);
    }
}
