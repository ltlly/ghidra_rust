//! Analyze all open programs task.
//!
//! Ported from `ghidra.app.plugin.core.analysis.AnalyzeAllOpenProgramsTask`
//! and `AnalyzeProgramStrategy`.
//!
//! Provides the infrastructure for analyzing multiple programs in a single
//! batch operation. The task iterates over all open programs, validates
//! that they share compatible architectures, applies a common set of
//! analysis options, and runs analysis on each program.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// ProgramInfo -- lightweight program metadata
// ---------------------------------------------------------------------------

/// Metadata about a program for batch analysis purposes.
#[derive(Debug, Clone)]
pub struct ProgramInfo {
    /// Program name (file name).
    pub name: String,
    /// Language ID (e.g., "x86:LE:64:default").
    pub language_id: String,
    /// Compiler spec ID (e.g., "default", "gcc").
    pub compiler_spec_id: String,
    /// Whether the program has been analyzed.
    pub is_analyzed: bool,
    /// Whether the program is closed.
    pub is_closed: bool,
    /// Program index in the open programs list.
    pub index: usize,
}

impl ProgramInfo {
    /// Create a new program info.
    pub fn new(
        name: impl Into<String>,
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
            is_analyzed: false,
            is_closed: false,
            index: 0,
        }
    }

    /// Get a unique identifier for the program's architecture.
    ///
    /// Two programs share the same architecture if their language ID
    /// and compiler spec ID match.
    pub fn architecture_id(&self) -> String {
        format!("{}:{}", self.language_id, self.compiler_spec_id)
    }
}

// ---------------------------------------------------------------------------
// AnalysisOptions -- analysis options snapshot
// ---------------------------------------------------------------------------

/// A snapshot of analysis options for a program.
///
/// Ported from the `AnalysisOptions` inner class in
/// `AnalyzeAllOpenProgramsTask.java`.
#[derive(Debug, Clone)]
pub struct AnalysisOptions {
    /// The architecture ID these options apply to.
    pub architecture_id: String,
    /// Per-analyzer enabled state.
    pub analyzer_enabled: HashMap<String, bool>,
    /// Per-analyzer option values.
    pub analyzer_options: HashMap<String, HashMap<String, String>>,
}

impl AnalysisOptions {
    /// Create new analysis options for an architecture.
    pub fn new(architecture_id: impl Into<String>) -> Self {
        Self {
            architecture_id: architecture_id.into(),
            analyzer_enabled: HashMap::new(),
            analyzer_options: HashMap::new(),
        }
    }

    /// Set whether an analyzer is enabled.
    pub fn set_analyzer_enabled(&mut self, name: &str, enabled: bool) {
        self.analyzer_enabled.insert(name.to_string(), enabled);
    }

    /// Check if an analyzer is enabled.
    pub fn is_analyzer_enabled(&self, name: &str) -> bool {
        self.analyzer_enabled.get(name).copied().unwrap_or(true)
    }

    /// Set an option value for an analyzer.
    pub fn set_option(&mut self, analyzer: &str, key: &str, value: &str) {
        self.analyzer_options
            .entry(analyzer.to_string())
            .or_default()
            .insert(key.to_string(), value.to_string());
    }

    /// Get an option value for an analyzer.
    pub fn get_option(&self, analyzer: &str, key: &str) -> Option<&str> {
        self.analyzer_options
            .get(analyzer)
            .and_then(|opts| opts.get(key))
            .map(|s| s.as_str())
    }

    /// Get the number of configured analyzers.
    pub fn analyzer_count(&self) -> usize {
        self.analyzer_enabled.len()
    }
}

// ---------------------------------------------------------------------------
// AnalyzeProgramStrategy -- strategy for analyzing a single program
// ---------------------------------------------------------------------------

/// Strategy for analyzing a single program.
///
/// Ported from `AnalyzeProgramStrategy.java`. Implementors define how
/// a program should be analyzed (e.g., in the foreground, background,
/// or using a specific set of analyzers).
pub trait AnalyzeProgramStrategy: Send + Sync {
    /// Analyze a program using the given options.
    ///
    /// # Arguments
    /// * `program` - The program to analyze.
    /// * `options` - Analysis options to apply.
    ///
    /// # Returns
    /// `true` if analysis completed successfully.
    fn analyze_program(&self, program: &ProgramInfo, options: &AnalysisOptions) -> bool;

    /// Get the strategy name for display purposes.
    fn name(&self) -> &str;
}

/// Default analysis strategy that runs all enabled analyzers.
pub struct DefaultAnalyzeStrategy {
    /// Whether to mark the program as analyzed after completion.
    pub mark_as_analyzed: bool,
}

impl DefaultAnalyzeStrategy {
    /// Create a new default strategy.
    pub fn new() -> Self {
        Self {
            mark_as_analyzed: true,
        }
    }
}

impl Default for DefaultAnalyzeStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalyzeProgramStrategy for DefaultAnalyzeStrategy {
    fn analyze_program(&self, _program: &ProgramInfo, _options: &AnalysisOptions) -> bool {
        // In a full implementation, this would:
        // 1. Create an AutoAnalysisManager for the program
        // 2. Apply the analysis options
        // 3. Call reAnalyzeAll(null) to schedule all analysis
        // 4. Start analysis and wait for completion
        // 5. Mark as analyzed if configured
        true
    }

    fn name(&self) -> &str {
        "Default Analysis"
    }
}

// ---------------------------------------------------------------------------
// BatchAnalysisResult -- result of a batch analysis operation
// ---------------------------------------------------------------------------

/// Result of analyzing a batch of programs.
#[derive(Debug, Clone, Default)]
pub struct BatchAnalysisResult {
    /// Programs that were analyzed successfully.
    pub successful: Vec<String>,
    /// Programs that failed analysis.
    pub failed: Vec<(String, String)>, // (name, error)
    /// Programs that were skipped (incompatible architecture).
    pub skipped: Vec<String>,
    /// Programs that were already closed.
    pub already_closed: Vec<String>,
    /// Whether the operation was cancelled.
    pub cancelled: bool,
    /// Total time in milliseconds.
    pub total_time_ms: u64,
}

impl BatchAnalysisResult {
    /// Get the total number of programs processed.
    pub fn total_processed(&self) -> usize {
        self.successful.len() + self.failed.len() + self.skipped.len() + self.already_closed.len()
    }

    /// Whether all programs were analyzed successfully.
    pub fn all_successful(&self) -> bool {
        self.failed.is_empty() && !self.cancelled
    }

    /// Get a summary string.
    pub fn summary(&self) -> String {
        format!(
            "{} successful, {} failed, {} skipped, {} already closed{}",
            self.successful.len(),
            self.failed.len(),
            self.skipped.len(),
            self.already_closed.len(),
            if self.cancelled { " (cancelled)" } else { "" }
        )
    }
}

// ---------------------------------------------------------------------------
// AnalyzeAllOpenPrograms -- batch analysis coordinator
// ---------------------------------------------------------------------------

/// Coordinates analysis of all open programs.
///
/// Ported from `AnalyzeAllOpenProgramsTask.java`. Validates that
/// programs share compatible architectures, applies common analysis
/// options, and runs analysis on each program using the configured
/// strategy.
pub struct AnalyzeAllOpenPrograms {
    /// The programs to analyze.
    programs: Vec<ProgramInfo>,
    /// The prototype program (source of analysis options).
    prototype_index: Option<usize>,
    /// The analysis strategy to use.
    strategy: Box<dyn AnalyzeProgramStrategy>,
    /// Whether to show the options dialog.
    show_options_dialog: bool,
    /// Analysis options (set externally or via dialog).
    options: Option<AnalysisOptions>,
}

impl AnalyzeAllOpenPrograms {
    /// Create a new batch analysis coordinator.
    pub fn new(programs: Vec<ProgramInfo>, strategy: Box<dyn AnalyzeProgramStrategy>) -> Self {
        Self {
            programs,
            prototype_index: None,
            strategy,
            show_options_dialog: true,
            options: None,
        }
    }

    /// Set the prototype program (source of analysis options).
    pub fn set_prototype(&mut self, index: usize) {
        if index < self.programs.len() {
            self.prototype_index = Some(index);
        }
    }

    /// Set whether to show the options dialog.
    pub fn set_show_options_dialog(&mut self, show: bool) {
        self.show_options_dialog = show;
    }

    /// Set the analysis options directly (bypassing the dialog).
    pub fn set_options(&mut self, options: AnalysisOptions) {
        self.options = Some(options);
    }

    /// Get programs that share the same architecture as the prototype.
    pub fn compatible_programs(&self) -> Vec<&ProgramInfo> {
        let proto_id = match self.prototype_index {
            Some(idx) => self.programs[idx].architecture_id(),
            None => return self.programs.iter().collect(),
        };

        self.programs
            .iter()
            .filter(|p| p.architecture_id() == proto_id)
            .collect()
    }

    /// Get programs that have a different architecture from the prototype.
    pub fn incompatible_programs(&self) -> Vec<&ProgramInfo> {
        let proto_id = match self.prototype_index {
            Some(idx) => self.programs[idx].architecture_id(),
            None => return Vec::new(),
        };

        self.programs
            .iter()
            .filter(|p| p.architecture_id() != proto_id)
            .collect()
    }

    /// Run batch analysis on all compatible programs.
    pub fn run(&self) -> BatchAnalysisResult {
        let mut result = BatchAnalysisResult::default();
        let start = std::time::Instant::now();

        let compatible = self.compatible_programs();

        for program in compatible {
            if program.is_closed {
                result.already_closed.push(program.name.clone());
                continue;
            }

            let options = match &self.options {
                Some(opts) => opts.clone(),
                None => AnalysisOptions::new(program.architecture_id()),
            };

            if self.strategy.analyze_program(program, &options) {
                result.successful.push(program.name.clone());
            } else {
                result
                    .failed
                    .push((program.name.clone(), "Analysis failed".to_string()));
            }
        }

        // Record skipped (incompatible) programs
        for program in self.incompatible_programs() {
            result.skipped.push(program.name.clone());
        }

        result.total_time_ms = start.elapsed().as_millis() as u64;
        result
    }

    /// Get the number of programs.
    pub fn program_count(&self) -> usize {
        self.programs.len()
    }

    /// Get a reference to the programs.
    pub fn programs(&self) -> &[ProgramInfo] {
        &self.programs
    }
}

impl fmt::Debug for AnalyzeAllOpenPrograms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnalyzeAllOpenPrograms")
            .field("program_count", &self.programs.len())
            .field("prototype_index", &self.prototype_index)
            .field("show_options_dialog", &self.show_options_dialog)
            .field("has_options", &self.options.is_some())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// ArchitectureWarning -- warning about incompatible architectures
// ---------------------------------------------------------------------------

/// Generates a warning message for programs with incompatible architectures.
///
/// Ported from the `showNonMatchingArchitecturesWarning` method in
/// `AnalyzeAllOpenProgramsTask.java`.
pub fn format_architecture_warning(
    prototype: &ProgramInfo,
    compatible: &[&ProgramInfo],
    incompatible: &[&ProgramInfo],
) -> String {
    let mut buf = String::new();

    buf.push_str("Found open programs with architectures differing from the current program.\n\n");
    buf.push_str("These programs WILL be analyzed:\n");
    buf.push_str(&format!(
        "  {:<30} {:<20} {}\n",
        "Name", "Language ID", "Compiler ID"
    ));
    buf.push_str(&format!(
        "  {:<30} {:<20} {}\n",
        "---", "---", "---"
    ));

    for program in compatible {
        let marker = if program.name == prototype.name {
            " <-- current"
        } else {
            ""
        };
        buf.push_str(&format!(
            "  {:<30} {:<20} {}{}\n",
            program.name, program.language_id, program.compiler_spec_id, marker
        ));
    }

    buf.push_str("\nThese programs will NOT be analyzed:\n");
    buf.push_str(&format!(
        "  {:<30} {:<20} {}\n",
        "Name", "Language ID", "Compiler ID"
    ));
    buf.push_str(&format!(
        "  {:<30} {:<20} {}\n",
        "---", "---", "---"
    ));

    for program in incompatible {
        buf.push_str(&format!(
            "  {:<30} {:<20} {}\n",
            program.name, program.language_id, program.compiler_spec_id
        ));
    }

    buf
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_program(name: &str, lang: &str, compiler: &str) -> ProgramInfo {
        ProgramInfo::new(name, lang, compiler)
    }

    #[test]
    fn test_program_info_architecture_id() {
        let p = make_program("test", "x86:LE:64:default", "gcc");
        assert_eq!(p.architecture_id(), "x86:LE:64:default:gcc");
    }

    #[test]
    fn test_analysis_options() {
        let mut opts = AnalysisOptions::new("x86:LE:64:default:gcc");
        assert_eq!(opts.architecture_id, "x86:LE:64:default:gcc");

        opts.set_analyzer_enabled("FuncAnalyzer", true);
        opts.set_analyzer_enabled("DataAnalyzer", false);

        assert!(opts.is_analyzer_enabled("FuncAnalyzer"));
        assert!(!opts.is_analyzer_enabled("DataAnalyzer"));
        assert!(opts.is_analyzer_enabled("UnknownAnalyzer")); // default true
    }

    #[test]
    fn test_analysis_options_per_analyzer() {
        let mut opts = AnalysisOptions::new("test");
        opts.set_option("MyAnalyzer", "max_depth", "100");
        assert_eq!(opts.get_option("MyAnalyzer", "max_depth"), Some("100"));
        assert!(opts.get_option("MyAnalyzer", "unknown").is_none());
    }

    #[test]
    fn test_compatible_programs() {
        let programs = vec![
            make_program("prog1", "x86:LE:64:default", "gcc"),
            make_program("prog2", "x86:LE:64:default", "gcc"),
            make_program("prog3", "ARM:LE:32:v8", "default"),
        ];

        let mut batch = AnalyzeAllOpenPrograms::new(
            programs,
            Box::new(DefaultAnalyzeStrategy::new()),
        );
        batch.set_prototype(0);

        let compatible = batch.compatible_programs();
        assert_eq!(compatible.len(), 2);

        let incompatible = batch.incompatible_programs();
        assert_eq!(incompatible.len(), 1);
        assert_eq!(incompatible[0].name, "prog3");
    }

    #[test]
    fn test_batch_analysis_run() {
        let programs = vec![
            make_program("prog1", "x86:LE:64:default", "gcc"),
            make_program("prog2", "x86:LE:64:default", "gcc"),
        ];

        let mut batch = AnalyzeAllOpenPrograms::new(
            programs,
            Box::new(DefaultAnalyzeStrategy::new()),
        );
        batch.set_prototype(0);

        let result = batch.run();
        assert_eq!(result.successful.len(), 2);
        assert!(result.all_successful());
    }

    #[test]
    fn test_batch_analysis_closed_program() {
        let mut prog = make_program("closed", "x86:LE:64:default", "gcc");
        prog.is_closed = true;

        let programs = vec![prog];
        let batch = AnalyzeAllOpenPrograms::new(
            programs,
            Box::new(DefaultAnalyzeStrategy::new()),
        );

        let result = batch.run();
        assert_eq!(result.already_closed.len(), 1);
    }

    #[test]
    fn test_batch_analysis_incompatible_skipped() {
        let programs = vec![
            make_program("compatible", "x86:LE:64:default", "gcc"),
            make_program("incompatible", "ARM:LE:32:v8", "default"),
        ];

        let mut batch = AnalyzeAllOpenPrograms::new(
            programs,
            Box::new(DefaultAnalyzeStrategy::new()),
        );
        batch.set_prototype(0);

        let result = batch.run();
        assert_eq!(result.successful.len(), 1);
        assert_eq!(result.skipped.len(), 1);
    }

    #[test]
    fn test_batch_result_summary() {
        let mut result = BatchAnalysisResult::default();
        result.successful.push("a".to_string());
        result.failed.push(("b".to_string(), "err".to_string()));
        result.skipped.push("c".to_string());

        let summary = result.summary();
        assert!(summary.contains("1 successful"));
        assert!(summary.contains("1 failed"));
        assert!(summary.contains("1 skipped"));
    }

    #[test]
    fn test_architecture_warning_format() {
        let proto = make_program("main", "x86:LE:64:default", "gcc");
        let compatible = vec![&proto];
        let incompat = vec![make_program("arm_prog", "ARM:LE:32:v8", "default")];
        let incompat_refs = vec![&incompat[0]];

        let warning = format_architecture_warning(&proto, &compatible, &incompat_refs);
        assert!(warning.contains("main"));
        assert!(warning.contains("arm_prog"));
        assert!(warning.contains("WILL be analyzed"));
        assert!(warning.contains("will NOT be analyzed"));
    }

    struct TestStrategy;
    impl AnalyzeProgramStrategy for TestStrategy {
        fn analyze_program(&self, program: &ProgramInfo, _options: &AnalysisOptions) -> bool {
            program.name != "fail_me"
        }
        fn name(&self) -> &str {
            "Test Strategy"
        }
    }

    #[test]
    fn test_custom_strategy() {
        let programs = vec![
            make_program("success", "x86:LE:64:default", "gcc"),
            make_program("fail_me", "x86:LE:64:default", "gcc"),
        ];

        let mut batch = AnalyzeAllOpenPrograms::new(programs, Box::new(TestStrategy));
        batch.set_prototype(0);

        let result = batch.run();
        assert_eq!(result.successful.len(), 1);
        assert_eq!(result.failed.len(), 1);
        assert!(!result.all_successful());
    }

    #[test]
    fn test_batch_no_prototype() {
        let programs = vec![
            make_program("p1", "x86:LE:64:default", "gcc"),
            make_program("p2", "ARM:LE:32:v8", "default"),
        ];

        let batch = AnalyzeAllOpenPrograms::new(
            programs,
            Box::new(DefaultAnalyzeStrategy::new()),
        );

        // No prototype set: all programs are compatible
        let compatible = batch.compatible_programs();
        assert_eq!(compatible.len(), 2);
        assert!(batch.incompatible_programs().is_empty());
    }
}
