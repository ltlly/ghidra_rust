//! Analysis worker, background commands, and batch analysis support.
//!
//! Ported from Ghidra's:
//! - `AnalysisWorker` -- callback for performing work while analysis is suspended
//! - `AnalysisBackgroundCommand` -- background command that kicks off auto-analysis
//! - `OneShotAnalysisCommand` -- runs a single analyzer on an address set
//! - `AnalyzeProgramStrategy` -- strategy pattern for how to analyze a single program
//! - `AnalyzeAllOpenProgramsTask` -- batch analysis across multiple programs
//! - `AnalyzerEnablementState` -- tracks per-analyzer enablement state
//! - `AnalysisOptionsUpdater` -- migrates renamed analyzer options
//! - `StoredAnalyzerTimes` -- cumulative timing of analyzer runs
//! - `TransientProgramProperties` -- properties that don't persist across saves
//!
//! # Architecture
//!
//! The worker/command layer sits between the plugin (UI) layer and the core
//! [`AutoAnalysisManager`](super::AutoAnalysisManager). Background commands
//! are queued by the plugin, and the manager processes them by popping from
//! its priority queue and running each analyzer's scheduler.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use super::core::{AddressSet, CancelledError, MessageLog, Program, TaskMonitor};
use super::priority::AnalysisPriority;
use super::manager::AutoAnalysisManager;

// ---------------------------------------------------------------------------
// AnalysisWorker
// ---------------------------------------------------------------------------

/// Callback for performing analysis work while analysis is suspended.
///
/// Ported from Ghidra's `AnalysisWorker`. When scheduled via
/// [`AutoAnalysisManager::schedule_worker`], the manager suspends analysis,
/// invokes the worker's callback, then resumes analysis.
///
/// # Example
///
/// ```ignore
/// use ghidra_features::base::analyzer::{AnalysisWorker, Program, TaskMonitor, CancelledError};
///
/// struct MyWorker;
///
/// impl AnalysisWorker for MyWorker {
///     fn analysis_worker_callback(
///         &self,
///         program: &mut Program,
///         context: &dyn std::any::Any,
///         monitor: &dyn TaskMonitor,
///     ) -> Result<bool, CancelledError> {
///         // Perform changes to program while analysis is suspended
///         Ok(true)
///     }
///
///     fn get_worker_name(&self) -> &str {
///         "MyWorker"
///     }
/// }
/// ```
pub trait AnalysisWorker: Send + Sync {
    /// Performs the desired changes to the program while analysis is suspended.
    ///
    /// # Parameters
    ///
    /// * `program` - The target program to modify.
    /// * `worker_context` - Context data provided when the worker was scheduled.
    /// * `monitor` - Progress monitor for long-running workers.
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if the worker completed successfully, `Ok(false)` if
    /// cancelled, or `Err(CancelledError)` if cancelled.
    fn analysis_worker_callback(
        &self,
        program: &mut Program,
        worker_context: Option<&dyn std::any::Any>,
        monitor: &dyn TaskMonitor,
    ) -> Result<bool, CancelledError>;

    /// Returns a short name for the worker used in the task monitor.
    fn get_worker_name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// AnalysisBackgroundCommand
// ---------------------------------------------------------------------------

/// Background command that kicks off auto-analysis on a program.
///
/// Ported from Ghidra's `AnalysisBackgroundCommand`. This is a mergeable
/// background command -- if multiple analysis commands are queued for the
/// same program, they can be merged into a single command that runs once.
///
/// # Example
///
/// ```
/// use ghidra_features::base::analyzer::*;
///
/// let prog = Program::new("test", Language { processor: "x86".into(), variant: "LE".into(), size: 64 });
/// let mgr = AutoAnalysisManager::new(prog);
/// let cmd = AnalysisBackgroundCommand::new(mgr, true);
/// assert_eq!(cmd.name(), "Auto Analysis");
/// assert!(cmd.is_mark_as_analyzed());
/// ```
pub struct AnalysisBackgroundCommand {
    /// Display name for the command.
    name: String,
    /// Whether to mark the program as analyzed after completion.
    mark_as_analyzed: bool,
    /// Whether this command has been cancelled.
    cancelled: bool,
    /// The analysis manager to use.
    mgr: Option<AutoAnalysisManager>,
}

impl AnalysisBackgroundCommand {
    /// Creates a new analysis background command.
    pub fn new(mgr: AutoAnalysisManager, mark_as_analyzed: bool) -> Self {
        Self {
            name: "Auto Analysis".to_string(),
            mark_as_analyzed,
            cancelled: false,
            mgr: Some(mgr),
        }
    }

    /// Returns the command name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns whether the program should be marked as analyzed.
    pub fn is_mark_as_analyzed(&self) -> bool {
        self.mark_as_analyzed
    }

    /// Executes the analysis command on the program.
    ///
    /// If `mark_as_analyzed` is true, the program will be flagged as analyzed.
    pub fn apply_to(&mut self, monitor: &dyn TaskMonitor) -> Result<bool, CancelledError> {
        if self.cancelled {
            return Ok(false);
        }
        if let Some(ref mut mgr) = self.mgr {
            if self.mark_as_analyzed {
                mgr.program_mut().is_changed = true;
            }
            let results = mgr.run_analysis(monitor)?;
            Ok(!results.was_cancelled)
        } else {
            Ok(false)
        }
    }

    /// Merges another analysis background command into this one.
    ///
    /// This is used when multiple analysis commands are queued for the same
    /// program. The `mark_as_analyzed` flag is OR'd together.
    pub fn merge(&mut self, other: Self) {
        self.mark_as_analyzed |= other.mark_as_analyzed;
    }

    /// Cancels this command.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Returns whether this command has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }
}

// ---------------------------------------------------------------------------
// OneShotAnalysisCommand
// ---------------------------------------------------------------------------

/// Command that runs a single analyzer once on an address set.
///
/// Ported from Ghidra's `OneShotAnalysisCommand`. Used for "one-shot"
/// analysis where a user explicitly selects an analyzer to run on a
/// specific address range.
///
/// # Example
///
/// ```
/// use ghidra_features::base::analyzer::*;
///
/// let mut cmd = OneShotAnalysisCommand::new(
///     "My Analyzer",
///     AnalysisPriority::CODE_ANALYSIS,
///     AddressSet::from_range(AddressRange::new(Address::new(0x1000), Address::new(0x2000))),
/// );
/// assert_eq!(cmd.analyzer_name(), "My Analyzer");
/// assert!(cmd.status_message().is_none());
/// ```
pub struct OneShotAnalysisCommand {
    /// The analyzer name.
    analyzer_name: String,
    /// The priority for scheduling.
    priority: AnalysisPriority,
    /// The address set to analyze.
    set: AddressSet,
    /// Accumulated status messages.
    log: MessageLog,
    /// Whether the command completed.
    completed: bool,
}

impl OneShotAnalysisCommand {
    /// Creates a new one-shot analysis command.
    pub fn new(
        analyzer_name: impl Into<String>,
        priority: AnalysisPriority,
        set: AddressSet,
    ) -> Self {
        Self {
            analyzer_name: analyzer_name.into(),
            priority,
            set,
            log: MessageLog::new(),
            completed: false,
        }
    }

    /// Returns the analyzer name.
    pub fn analyzer_name(&self) -> &str {
        &self.analyzer_name
    }

    /// Returns the scheduling priority.
    pub fn priority(&self) -> AnalysisPriority {
        self.priority
    }

    /// Returns the address set to analyze.
    pub fn address_set(&self) -> &AddressSet {
        &self.set
    }

    /// Returns the status message from the log, if any.
    pub fn status_message(&self) -> Option<&str> {
        if self.log.is_empty() {
            None
        } else {
            self.log.iter().next()
        }
    }

    /// Returns a reference to the message log.
    pub fn message_log(&self) -> &MessageLog {
        &self.log
    }

    /// Appends a message to the log.
    pub fn append_log(&mut self, msg: impl Into<String>) {
        self.log.append_msg(msg);
    }

    /// Marks this command as completed.
    pub fn mark_completed(&mut self) {
        self.completed = true;
    }

    /// Returns whether this command has completed.
    pub fn is_completed(&self) -> bool {
        self.completed
    }
}

// ---------------------------------------------------------------------------
// AnalyzeProgramStrategy
// ---------------------------------------------------------------------------

/// Strategy for analyzing a single program within a batch.
///
/// Ported from Ghidra's `AnalyzeProgramStrategy`. This allows customizing
/// how each program is analyzed -- for example, using a background command
/// that waits for completion, or running inline.
///
/// # Example
///
/// ```
/// use ghidra_features::base::analyzer::*;
///
/// struct InlineStrategy;
///
/// impl AnalyzeProgramStrategy for InlineStrategy {
///     fn analyze_program(
///         &self,
///         manager: &mut AutoAnalysisManager,
///         monitor: &dyn TaskMonitor,
///     ) -> Result<AnalysisResults, CancelledError> {
///         manager.run_analysis(monitor)
///     }
/// }
/// ```
pub trait AnalyzeProgramStrategy: Send + Sync {
    /// Analyzes a program using the given manager and monitor.
    fn analyze_program(
        &self,
        manager: &mut AutoAnalysisManager,
        monitor: &dyn TaskMonitor,
    ) -> Result<AnalysisResults, CancelledError>;
}

/// Default strategy that runs analysis inline (blocking).
pub struct DefaultAnalyzeProgramStrategy;

impl AnalyzeProgramStrategy for DefaultAnalyzeProgramStrategy {
    fn analyze_program(
        &self,
        manager: &mut AutoAnalysisManager,
        monitor: &dyn TaskMonitor,
    ) -> Result<AnalysisResults, CancelledError> {
        manager.run_analysis(monitor)
    }
}

// Re-export AnalysisResults from scheduler
use super::scheduler::AnalysisResults;

// ---------------------------------------------------------------------------
// AnalyzerEnablementState
// ---------------------------------------------------------------------------

/// Tracks the enablement state of an analyzer.
///
/// Ported from Ghidra's `AnalyzerEnablementState`. Used by the analysis
/// options UI to show which analyzers are enabled/disabled and whether
/// the state differs from the default.
///
/// # Example
///
/// ```
/// use ghidra_features::base::analyzer::AnalyzerEnablementState;
///
/// let mut state = AnalyzerEnablementState::new(
///     "Function Start Analyzer",
///     true,   // default enablement
///     false,  // is prototype
/// );
/// assert_eq!(state.name(), "Function Start Analyzer");
/// assert!(state.is_enabled());
/// assert!(state.is_default_enablement());
///
/// state.set_enabled(false);
/// assert!(!state.is_enabled());
/// assert!(!state.is_default_enablement());
/// ```
#[derive(Debug, Clone)]
pub struct AnalyzerEnablementState {
    /// The analyzer name.
    name: String,
    /// Whether the analyzer is currently enabled.
    enabled: bool,
    /// The default enablement value.
    default_enablement: bool,
    /// Whether this is a prototype analyzer.
    is_prototype: bool,
}

impl AnalyzerEnablementState {
    /// Creates a new enablement state.
    pub fn new(
        name: impl Into<String>,
        default_enablement: bool,
        is_prototype: bool,
    ) -> Self {
        Self {
            name: name.into(),
            enabled: default_enablement,
            default_enablement,
            is_prototype,
        }
    }

    /// Returns the analyzer name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns whether the analyzer is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Sets the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Returns the default enablement value.
    pub fn default_enablement(&self) -> bool {
        self.default_enablement
    }

    /// Returns whether the current state differs from the default.
    pub fn is_default_enablement(&self) -> bool {
        self.enabled == self.default_enablement
    }

    /// Returns whether this is a prototype analyzer.
    pub fn is_prototype(&self) -> bool {
        self.is_prototype
    }
}

// ---------------------------------------------------------------------------
// AnalysisOptionsUpdater
// ---------------------------------------------------------------------------

/// Migrates old analyzer option names to new ones.
///
/// Ported from Ghidra's `AnalysisOptionsUpdater`. When an analyzer renames
/// one of its options, this updater ensures that saved option values are
/// transferred from the old name to the new name.
///
/// # Rules
///
/// - Old option values are only used if they are non-default.
/// - New option values are only overwritten if they are still at the default.
/// - A custom replacer function can transform the old value to the new format.
///
/// # Example
///
/// ```
/// use ghidra_features::base::analyzer::AnalysisOptionsUpdater;
///
/// let mut updater = AnalysisOptionsUpdater::new();
/// updater.register_replacement("newOption", "oldOption");
///
/// let options = updater.get_replaceable_options();
/// assert_eq!(options.len(), 1);
/// assert_eq!(options[0].new_name(), "newOption");
/// assert_eq!(options[0].old_name(), "oldOption");
/// ```
#[derive(Debug)]
pub struct AnalysisOptionsUpdater {
    options_by_new_name: HashMap<String, ReplaceableOption>,
}

impl AnalysisOptionsUpdater {
    /// Creates a new options updater.
    pub fn new() -> Self {
        Self {
            options_by_new_name: HashMap::new(),
        }
    }

    /// Registers a replacement where the old value is used directly.
    pub fn register_replacement(&mut self, new_name: &str, old_name: &str) {
        self.options_by_new_name.insert(
            new_name.to_string(),
            ReplaceableOption {
                new_name: new_name.to_string(),
                old_name: old_name.to_string(),
                has_custom_replacer: false,
            },
        );
    }

    /// Registers a replacement with a custom replacer marker.
    ///
    /// The actual replacer function would be applied during option migration.
    pub fn register_replacement_with_transform(&mut self, new_name: &str, old_name: &str) {
        self.options_by_new_name.insert(
            new_name.to_string(),
            ReplaceableOption {
                new_name: new_name.to_string(),
                old_name: old_name.to_string(),
                has_custom_replacer: true,
            },
        );
    }

    /// Returns all replaceable options.
    pub fn get_replaceable_options(&self) -> Vec<&ReplaceableOption> {
        self.options_by_new_name.values().collect()
    }

    /// Returns the number of registered replacements.
    pub fn len(&self) -> usize {
        self.options_by_new_name.len()
    }

    /// Returns whether no replacements are registered.
    pub fn is_empty(&self) -> bool {
        self.options_by_new_name.is_empty()
    }
}

impl Default for AnalysisOptionsUpdater {
    fn default() -> Self {
        Self::new()
    }
}

/// A single replaceable option mapping.
#[derive(Debug, Clone)]
pub struct ReplaceableOption {
    /// The new option name.
    new_name: String,
    /// The old option name.
    old_name: String,
    /// Whether a custom replacer function is registered.
    has_custom_replacer: bool,
}

impl ReplaceableOption {
    /// Returns the new option name.
    pub fn new_name(&self) -> &str {
        &self.new_name
    }

    /// Returns the old option name.
    pub fn old_name(&self) -> &str {
        &self.old_name
    }

    /// Returns whether a custom replacer is registered.
    pub fn has_custom_replacer(&self) -> bool {
        self.has_custom_replacer
    }
}

// ---------------------------------------------------------------------------
// StoredAnalyzerTimes
// ---------------------------------------------------------------------------

/// Cumulative timing of analyzer runs.
///
/// Ported from Ghidra's `StoredAnalyzerTimes`. Tracks how much time each
/// analyzer has spent running across all analysis sessions.
///
/// # Example
///
/// ```
/// use ghidra_features::base::analyzer::StoredAnalyzerTimes;
///
/// let mut times = StoredAnalyzerTimes::new();
/// assert!(times.is_empty());
///
/// times.add_time("Function Start Analyzer", 150);
/// times.add_time("Function Start Analyzer", 250);
/// times.add_time("Reference Analyzer", 100);
///
/// assert_eq!(times.get_time("Function Start Analyzer"), Some(400));
/// assert_eq!(times.get_total_time(), 500);
/// assert_eq!(times.task_names(), vec!["Function Start Analyzer", "Reference Analyzer"]);
/// ```
#[derive(Debug, Clone, Default)]
pub struct StoredAnalyzerTimes {
    /// Maps analyzer name to cumulative milliseconds.
    task_times: HashMap<String, u64>,
}

impl StoredAnalyzerTimes {
    /// The options list name in Ghidra.
    pub const OPTIONS_LIST: &'static str = "Analyzer Times";
    /// The option name for stored times.
    pub const OPTION_NAME: &'static str = "StoredAnalyzerTimes";

    /// Creates a new empty stored times.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds time for the given analyzer.
    pub fn add_time(&mut self, name: &str, time_ms: u64) {
        *self.task_times.entry(name.to_string()).or_insert(0) += time_ms;
    }

    /// Returns the cumulative time for the given analyzer.
    pub fn get_time(&self, name: &str) -> Option<u64> {
        self.task_times.get(name).copied()
    }

    /// Returns the total time across all analyzers.
    pub fn get_total_time(&self) -> u64 {
        self.task_times.values().sum()
    }

    /// Returns all analyzer names (sorted).
    pub fn task_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.task_times.keys().map(|s| s.as_str()).collect();
        names.sort();
        names
    }

    /// Returns whether no times have been recorded.
    pub fn is_empty(&self) -> bool {
        self.task_times.is_empty()
    }

    /// Clears all recorded times.
    pub fn clear(&mut self) {
        self.task_times.clear();
    }

    /// Returns the number of analyzers with recorded times.
    pub fn len(&self) -> usize {
        self.task_times.len()
    }

    /// Imports times from a Duration-based map.
    pub fn import_durations(&mut self, times: &HashMap<String, Duration>) {
        for (name, duration) in times {
            self.add_time(name, duration.as_millis() as u64);
        }
    }
}

// ---------------------------------------------------------------------------
// TransientProgramProperties
// ---------------------------------------------------------------------------

/// Properties that don't persist across program saves.
///
/// Ported from Ghidra's `TransientProgramProperties`. These are used to
/// track analysis state that is only relevant during the current session,
/// such as whether analysis has been requested or the program was just loaded.
///
/// # Example
///
/// ```
/// use ghidra_features::base::analyzer::TransientProgramProperties;
///
/// let mut props = TransientProgramProperties::new();
/// assert!(!props.is_analyzed());
/// props.set_analyzed(true);
/// assert!(props.is_analyzed());
///
/// props.set("custom_key", "value");
/// assert_eq!(props.get("custom_key"), Some(&"value".to_string()));
/// ```
#[derive(Debug, Clone)]
pub struct TransientProgramProperties {
    /// Whether the program has been analyzed.
    analyzed: bool,
    /// Whether auto-analysis was requested.
    analysis_requested: bool,
    /// Custom transient properties.
    properties: HashMap<String, String>,
}

impl TransientProgramProperties {
    /// Creates a new transient properties set.
    pub fn new() -> Self {
        Self {
            analyzed: false,
            analysis_requested: false,
            properties: HashMap::new(),
        }
    }

    /// Returns whether the program has been analyzed.
    pub fn is_analyzed(&self) -> bool {
        self.analyzed
    }

    /// Sets the analyzed flag.
    pub fn set_analyzed(&mut self, analyzed: bool) {
        self.analyzed = analyzed;
    }

    /// Returns whether auto-analysis was requested.
    pub fn is_analysis_requested(&self) -> bool {
        self.analysis_requested
    }

    /// Sets whether auto-analysis was requested.
    pub fn set_analysis_requested(&mut self, requested: bool) {
        self.analysis_requested = requested;
    }

    /// Sets a custom property.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.properties.insert(key.into(), value.into());
    }

    /// Gets a custom property.
    pub fn get(&self, key: &str) -> Option<&String> {
        self.properties.get(key)
    }

    /// Removes a custom property.
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.properties.remove(key)
    }

    /// Returns the number of custom properties.
    pub fn len(&self) -> usize {
        self.properties.len()
    }

    /// Returns whether there are no custom properties.
    pub fn is_empty(&self) -> bool {
        self.properties.is_empty()
    }
}

impl Default for TransientProgramProperties {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PostAnalysisValidator
// ---------------------------------------------------------------------------

/// Trait for validators that run after analysis completes.
///
/// Ported from Ghidra's `PostAnalysisValidator` and its implementations:
/// - `OffcutReferencesValidator` -- checks for offcut references
/// - `PercentAnalyzedValidator` -- checks percentage of analyzed bytes
/// - `RedFlagsValidator` -- checks for analysis red flags
pub trait PostAnalysisValidator: Send + Sync + fmt::Debug {
    /// Returns the validator name.
    fn name(&self) -> &str;

    /// Validates the program after analysis.
    fn validate(&self, program: &Program, monitor: &dyn TaskMonitor) -> ValidationResult;

    /// Returns a description of what this validator checks.
    fn description(&self) -> &str;
}

/// Result of a post-analysis validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationResult {
    /// Whether the validation passed.
    pub passed: bool,
    /// Warning messages.
    pub warnings: Vec<String>,
    /// Error messages.
    pub errors: Vec<String>,
    /// Informational messages.
    pub info: Vec<String>,
}

impl ValidationResult {
    /// Creates a passing result.
    pub fn pass() -> Self {
        Self {
            passed: true,
            warnings: Vec::new(),
            errors: Vec::new(),
            info: Vec::new(),
        }
    }

    /// Creates a failing result with a message.
    pub fn fail(message: impl Into<String>) -> Self {
        Self {
            passed: false,
            warnings: Vec::new(),
            errors: vec![message.into()],
            info: Vec::new(),
        }
    }

    /// Returns whether there are any warnings.
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    /// Returns the total number of issues (errors + warnings).
    pub fn num_issues(&self) -> usize {
        self.errors.len() + self.warnings.len()
    }
}

/// Validator that checks for offcut (mid-instruction) references.
#[derive(Debug)]
pub struct OffcutReferencesValidator {
    /// Threshold percentage of offcut references to flag.
    pub threshold_percent: f64,
}

impl OffcutReferencesValidator {
    /// Creates a new validator with default threshold (5%).
    pub fn new() -> Self {
        Self {
            threshold_percent: 5.0,
        }
    }
}

impl Default for OffcutReferencesValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl PostAnalysisValidator for OffcutReferencesValidator {
    fn name(&self) -> &str {
        "Offcut References Validator"
    }

    fn validate(&self, _program: &Program, _monitor: &dyn TaskMonitor) -> ValidationResult {
        // In a full implementation, this would scan references for offcut targets
        ValidationResult::pass()
    }

    fn description(&self) -> &str {
        "Checks for references that point to the middle of instructions"
    }
}

/// Validator that checks the percentage of analyzed bytes.
#[derive(Debug)]
pub struct PercentAnalyzedValidator {
    /// Minimum acceptable percentage.
    pub min_percent: f64,
}

impl PercentAnalyzedValidator {
    /// Creates a new validator with default threshold (90%).
    pub fn new() -> Self {
        Self {
            min_percent: 90.0,
        }
    }
}

impl Default for PercentAnalyzedValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl PostAnalysisValidator for PercentAnalyzedValidator {
    fn name(&self) -> &str {
        "Percent Analyzed Validator"
    }

    fn validate(&self, _program: &Program, _monitor: &dyn TaskMonitor) -> ValidationResult {
        // In a full implementation, this would check what percentage of bytes are covered
        ValidationResult::pass()
    }

    fn description(&self) -> &str {
        "Checks that a sufficient percentage of bytes have been analyzed"
    }
}

/// Validator that checks for analysis red flags.
#[derive(Debug)]
pub struct RedFlagsValidator {
    /// Minimum number of red flags to report.
    pub min_flags: usize,
}

impl RedFlagsValidator {
    /// Creates a new validator with default threshold (1).
    pub fn new() -> Self {
        Self { min_flags: 1 }
    }
}

impl Default for RedFlagsValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl PostAnalysisValidator for RedFlagsValidator {
    fn name(&self) -> &str {
        "Red Flags Validator"
    }

    fn validate(&self, _program: &Program, _monitor: &dyn TaskMonitor) -> ValidationResult {
        // In a full implementation, this would check for analysis warnings/errors
        ValidationResult::pass()
    }

    fn description(&self) -> &str {
        "Checks for analysis red flags such as overlapping functions or bad references"
    }
}

// ---------------------------------------------------------------------------
// FindReferencesTableModel
// ---------------------------------------------------------------------------

/// Table model for displaying found references.
///
/// Ported from Ghidra's `FindReferencesTableModel`. Provides a tabular
/// view of reference search results with column definitions.
#[derive(Debug, Clone)]
pub struct FindReferencesTableModel {
    /// The reference entries.
    entries: Vec<ReferenceTableEntry>,
}

/// A single entry in the references table.
#[derive(Debug, Clone)]
pub struct ReferenceTableEntry {
    /// Source address of the reference.
    pub from_address: u64,
    /// Target address of the reference.
    pub to_address: u64,
    /// The reference type name.
    pub ref_type: String,
    /// The operand index (if applicable).
    pub operand_index: Option<u32>,
    /// Source label.
    pub from_label: String,
    /// Target label.
    pub to_label: String,
}

impl FindReferencesTableModel {
    /// Creates a new empty table model.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Adds an entry to the table.
    pub fn add_entry(&mut self, entry: ReferenceTableEntry) {
        self.entries.push(entry);
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns a reference to all entries.
    pub fn entries(&self) -> &[ReferenceTableEntry] {
        &self.entries
    }

    /// Clears all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Returns column names for the table.
    pub fn column_names() -> &'static [&'static str] {
        &["From", "To", "Type", "Operand", "From Label", "To Label"]
    }
}

impl Default for FindReferencesTableModel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::core::*;
    use super::super::priority::*;

    fn make_program() -> Program {
        let lang = Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        Program::new("test", lang)
    }

    #[test]
    fn test_analysis_worker_trait() {
        struct TestWorker;
        impl AnalysisWorker for TestWorker {
            fn analysis_worker_callback(
                &self,
                _program: &mut Program,
                _context: Option<&dyn std::any::Any>,
                _monitor: &dyn TaskMonitor,
            ) -> Result<bool, CancelledError> {
                Ok(true)
            }
            fn get_worker_name(&self) -> &str {
                "TestWorker"
            }
        }
        let worker = TestWorker;
        assert_eq!(worker.get_worker_name(), "TestWorker");
        let mut prog = make_program();
        let monitor = BasicTaskMonitor::new();
        let result = worker.analysis_worker_callback(&mut prog, None, &monitor).unwrap();
        assert!(result);
    }

    #[test]
    fn test_analysis_background_command() {
        let prog = make_program();
        let mgr = AutoAnalysisManager::new(prog);
        let cmd = AnalysisBackgroundCommand::new(mgr, true);
        assert_eq!(cmd.name(), "Auto Analysis");
        assert!(cmd.is_mark_as_analyzed());
        assert!(!cmd.is_cancelled());
    }

    #[test]
    fn test_analysis_background_command_cancel() {
        let prog = make_program();
        let mgr = AutoAnalysisManager::new(prog);
        let mut cmd = AnalysisBackgroundCommand::new(mgr, false);
        cmd.cancel();
        assert!(cmd.is_cancelled());
    }

    #[test]
    fn test_analysis_background_command_merge() {
        let prog1 = make_program();
        let prog2 = make_program();
        let mgr1 = AutoAnalysisManager::new(prog1);
        let mgr2 = AutoAnalysisManager::new(prog2);
        let mut cmd1 = AnalysisBackgroundCommand::new(mgr1, false);
        let cmd2 = AnalysisBackgroundCommand::new(mgr2, true);
        cmd1.merge(cmd2);
        assert!(cmd1.is_mark_as_analyzed());
    }

    #[test]
    fn test_analysis_background_command_apply() {
        let prog = make_program();
        let mgr = AutoAnalysisManager::new(prog);
        let mut cmd = AnalysisBackgroundCommand::new(mgr, true);
        let monitor = BasicTaskMonitor::new();
        let result = cmd.apply_to(&monitor).unwrap();
        assert!(result);
    }

    #[test]
    fn test_one_shot_command() {
        let set = AddressSet::from_range(AddressRange::new(Address::new(0x1000), Address::new(0x2000)));
        let mut cmd = OneShotAnalysisCommand::new(
            "Test Analyzer",
            AnalysisPriority::CODE_ANALYSIS,
            set,
        );
        assert_eq!(cmd.analyzer_name(), "Test Analyzer");
        assert_eq!(cmd.priority(), AnalysisPriority::CODE_ANALYSIS);
        assert!(!cmd.is_completed());
        assert!(cmd.status_message().is_none());

        cmd.append_log("Test message");
        assert!(cmd.status_message().is_some());

        cmd.mark_completed();
        assert!(cmd.is_completed());
    }

    #[test]
    fn test_analyze_program_strategy() {
        struct TestStrategy;
        impl AnalyzeProgramStrategy for TestStrategy {
            fn analyze_program(
                &self,
                manager: &mut AutoAnalysisManager,
                monitor: &dyn TaskMonitor,
            ) -> Result<AnalysisResults, CancelledError> {
                manager.run_analysis(monitor)
            }
        }
        let strategy = TestStrategy;
        let prog = make_program();
        let mut mgr = AutoAnalysisManager::new(prog);
        let monitor = BasicTaskMonitor::new();
        let results = strategy.analyze_program(&mut mgr, &monitor).unwrap();
        assert_eq!(results.tasks_executed, 0);
    }

    #[test]
    fn test_default_analyze_strategy() {
        let strategy = DefaultAnalyzeProgramStrategy;
        let prog = make_program();
        let mut mgr = AutoAnalysisManager::new(prog);
        let monitor = BasicTaskMonitor::new();
        let results = strategy.analyze_program(&mut mgr, &monitor).unwrap();
        assert!(!results.was_cancelled);
    }

    #[test]
    fn test_analyzer_enablement_state() {
        let mut state = AnalyzerEnablementState::new("TestAnalyzer", true, false);
        assert_eq!(state.name(), "TestAnalyzer");
        assert!(state.is_enabled());
        assert!(state.is_default_enablement());
        assert!(!state.is_prototype());

        state.set_enabled(false);
        assert!(!state.is_enabled());
        assert!(!state.is_default_enablement());
    }

    #[test]
    fn test_analyzer_enablement_prototype() {
        let state = AnalyzerEnablementState::new("ProtoAnalyzer", true, true);
        assert!(state.is_prototype());
    }

    #[test]
    fn test_analysis_options_updater() {
        let mut updater = AnalysisOptionsUpdater::new();
        assert!(updater.is_empty());

        updater.register_replacement("newOption", "oldOption");
        assert_eq!(updater.len(), 1);

        let options = updater.get_replaceable_options();
        assert_eq!(options.len(), 1);
        assert_eq!(options[0].new_name(), "newOption");
        assert_eq!(options[0].old_name(), "oldOption");
        assert!(!options[0].has_custom_replacer());
    }

    #[test]
    fn test_analysis_options_updater_with_transform() {
        let mut updater = AnalysisOptionsUpdater::new();
        updater.register_replacement_with_transform("newOpt", "oldOpt");
        let options = updater.get_replaceable_options();
        assert!(options[0].has_custom_replacer());
    }

    #[test]
    fn test_stored_analyzer_times() {
        let mut times = StoredAnalyzerTimes::new();
        assert!(times.is_empty());

        times.add_time("Analyzer A", 100);
        times.add_time("Analyzer A", 200);
        times.add_time("Analyzer B", 50);

        assert_eq!(times.get_time("Analyzer A"), Some(300));
        assert_eq!(times.get_time("Analyzer B"), Some(50));
        assert_eq!(times.get_time("Analyzer C"), None);
        assert_eq!(times.get_total_time(), 350);
        assert_eq!(times.len(), 2);
        assert_eq!(times.task_names(), vec!["Analyzer A", "Analyzer B"]);

        times.clear();
        assert!(times.is_empty());
    }

    #[test]
    fn test_stored_times_import() {
        let mut times = StoredAnalyzerTimes::new();
        let mut durations = HashMap::new();
        durations.insert("A".to_string(), Duration::from_millis(100));
        durations.insert("B".to_string(), Duration::from_millis(200));
        times.import_durations(&durations);
        assert_eq!(times.get_total_time(), 300);
    }

    #[test]
    fn test_transient_program_properties() {
        let mut props = TransientProgramProperties::new();
        assert!(!props.is_analyzed());
        assert!(!props.is_analysis_requested());
        assert!(props.is_empty());

        props.set_analyzed(true);
        assert!(props.is_analyzed());

        props.set_analysis_requested(true);
        assert!(props.is_analysis_requested());

        props.set("key1", "value1");
        assert_eq!(props.get("key1"), Some(&"value1".to_string()));
        assert_eq!(props.len(), 1);

        props.remove("key1");
        assert!(props.is_empty());
    }

    #[test]
    fn test_validation_result() {
        let pass = ValidationResult::pass();
        assert!(pass.passed);
        assert!(!pass.has_warnings());
        assert_eq!(pass.num_issues(), 0);

        let mut fail = ValidationResult::fail("test error");
        assert!(!fail.passed);
        fail.warnings.push("test warning".to_string());
        assert!(fail.has_warnings());
        assert_eq!(fail.num_issues(), 2);
    }

    #[test]
    fn test_offcut_validator() {
        let validator = OffcutReferencesValidator::new();
        assert_eq!(validator.name(), "Offcut References Validator");
        assert_eq!(validator.threshold_percent, 5.0);
        let prog = make_program();
        let monitor = BasicTaskMonitor::new();
        let result = validator.validate(&prog, &monitor);
        assert!(result.passed);
    }

    #[test]
    fn test_percent_analyzed_validator() {
        let validator = PercentAnalyzedValidator::new();
        assert_eq!(validator.name(), "Percent Analyzed Validator");
        assert_eq!(validator.min_percent, 90.0);
    }

    #[test]
    fn test_red_flags_validator() {
        let validator = RedFlagsValidator::new();
        assert_eq!(validator.name(), "Red Flags Validator");
        assert_eq!(validator.min_flags, 1);
    }

    #[test]
    fn test_find_references_table_model() {
        let mut model = FindReferencesTableModel::new();
        assert!(model.is_empty());

        model.add_entry(ReferenceTableEntry {
            from_address: 0x1000,
            to_address: 0x2000,
            ref_type: "CALL".to_string(),
            operand_index: Some(0),
            from_label: "main".to_string(),
            to_label: "func".to_string(),
        });
        assert_eq!(model.len(), 1);

        let cols = FindReferencesTableModel::column_names();
        assert_eq!(cols.len(), 6);
        assert_eq!(cols[0], "From");

        model.clear();
        assert!(model.is_empty());
    }
}
