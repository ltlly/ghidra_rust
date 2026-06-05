//! Analysis scheduler -- ported from `AnalysisScheduler.java`,
//! `AnalysisTask.java`, `AnalysisTaskList.java`, and
//! `AnalysisBackgroundCommand.java`.
//!
//! Manages the ordering and execution of analysis passes, including
//! scheduling, priority management, and background execution.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// AnalysisScheduler -- orchestrates analysis pass ordering
// ---------------------------------------------------------------------------

/// Schedules and orders analysis passes based on their priority.
///
/// Ported from `AnalysisScheduler.java`.
#[derive(Debug)]
pub struct AnalysisScheduler {
    /// Registered analysis task descriptors.
    tasks: Vec<AnalysisTaskDescriptor>,
    /// Whether the scheduler is running.
    running: bool,
    /// Current task index.
    current_index: usize,
}

impl AnalysisScheduler {
    /// Create a new analysis scheduler.
    pub fn new() -> Self {
        Self {
            tasks: Vec::new(),
            running: false,
            current_index: 0,
        }
    }

    /// Register an analysis task.
    pub fn register_task(&mut self, task: AnalysisTaskDescriptor) {
        self.tasks.push(task);
        // Keep tasks sorted by priority
        self.tasks.sort_by_key(|t| t.priority);
    }

    /// Get all registered tasks in priority order.
    pub fn tasks(&self) -> &[AnalysisTaskDescriptor] {
        &self.tasks
    }

    /// Get the next task to execute.
    pub fn next_task(&mut self) -> Option<&AnalysisTaskDescriptor> {
        if self.current_index < self.tasks.len() {
            let task = &self.tasks[self.current_index];
            self.current_index += 1;
            Some(task)
        } else {
            None
        }
    }

    /// Reset the scheduler to start from the first task.
    pub fn reset(&mut self) {
        self.current_index = 0;
    }

    /// Whether there are more tasks to execute.
    pub fn has_more_tasks(&self) -> bool {
        self.current_index < self.tasks.len()
    }

    /// Start the scheduler.
    pub fn start(&mut self) {
        self.running = true;
        self.current_index = 0;
    }

    /// Stop the scheduler.
    pub fn stop(&mut self) {
        self.running = false;
    }

    /// Whether the scheduler is currently running.
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Number of registered tasks.
    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }
}

impl Default for AnalysisScheduler {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AnalysisTaskDescriptor
// ---------------------------------------------------------------------------

/// Describes an analysis task for scheduling purposes.
///
/// Ported from `AnalysisTask.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisTaskDescriptor {
    /// Analyzer name.
    pub name: String,
    /// Analyzer description.
    pub description: String,
    /// Priority (lower = higher priority, runs first).
    pub priority: u32,
    /// Whether this task is enabled.
    pub enabled: bool,
    /// Whether this task requires exclusive access.
    pub exclusive: bool,
    /// The analyzer type.
    pub analyzer_type: AnalyzerType,
}

impl AnalysisTaskDescriptor {
    /// Create a new analysis task descriptor.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        priority: u32,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            priority,
            enabled: true,
            exclusive: false,
            analyzer_type: AnalyzerType::FunctionStarts,
        }
    }
}

// ---------------------------------------------------------------------------
// AnalyzerType -- classification of analyzer
// ---------------------------------------------------------------------------

/// Types of analyzers in the analysis pipeline.
///
/// Ported from `AnalyzerType` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnalyzerType {
    /// Analyzes function starts (creates functions at call targets).
    FunctionStarts,
    /// Analyzes code references (follows control flow).
    CodeReferences,
    /// Analyzes data references (follows pointer reads).
    DataReferences,
    /// Analyzes instruction patterns.
    InstructionPatterns,
    /// Propagates data types through the program.
    DataTypePropagation,
    /// Analyzes stack frames.
    StackAnalysis,
    /// Analyzes function signatures.
    SignatureAnalysis,
    /// Analyzes symbols and namespaces.
    SymbolAnalysis,
    /// Analyzes string data.
    StringAnalysis,
    /// General instruction-level analyzer.
    InstructionAnalysis,
    /// General byte-level analyzer.
    ByteAnalysis,
}

// ---------------------------------------------------------------------------
// AnalysisTaskList -- ordered list of tasks to run
// ---------------------------------------------------------------------------

/// An ordered list of analysis tasks to execute in sequence.
///
/// Ported from `AnalysisTaskList.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisTaskList {
    /// The tasks in execution order.
    tasks: Vec<AnalysisTaskDescriptor>,
    /// Current execution position.
    position: usize,
}

impl AnalysisTaskList {
    /// Create an empty task list.
    pub fn new() -> Self {
        Self {
            tasks: Vec::new(),
            position: 0,
        }
    }

    /// Add a task to the list.
    pub fn add(&mut self, task: AnalysisTaskDescriptor) {
        self.tasks.push(task);
    }

    /// Get the next task in the list.
    pub fn next(&mut self) -> Option<&AnalysisTaskDescriptor> {
        if self.position < self.tasks.len() {
            let task = &self.tasks[self.position];
            self.position += 1;
            Some(task) as Option<&AnalysisTaskDescriptor>
        } else {
            None
        }
    }

    /// Reset to the beginning.
    pub fn reset(&mut self) {
        self.position = 0;
    }

    /// Number of tasks.
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// Get all tasks.
    pub fn all_tasks(&self) -> &[AnalysisTaskDescriptor] {
        &self.tasks
    }
}

impl Default for AnalysisTaskList {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AnalysisOptionsUpdater -- updates analysis options from defaults
// ---------------------------------------------------------------------------

/// Updates analysis options to reflect changes in available analyzers.
///
/// Ported from `AnalysisOptionsUpdater.java`.
#[derive(Debug, Default)]
pub struct AnalysisOptionsUpdater;

impl AnalysisOptionsUpdater {
    /// Update the analysis options to reflect the current set of
    /// registered analyzers.
    pub fn update_options(
        registered_analyzers: &[String],
        current_options: &mut AnalysisOptionSet,
    ) {
        // Remove options for analyzers that no longer exist
        current_options
            .entries
            .retain(|e| registered_analyzers.contains(&e.analyzer_name));
    }
}

/// A set of analysis options for all registered analyzers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisOptionSet {
    /// Per-analyzer option entries.
    pub entries: Vec<AnalysisOptionEntry>,
}

impl AnalysisOptionSet {
    /// Create a new empty option set.
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Get an option by analyzer name.
    pub fn get(&self, analyzer_name: &str) -> Option<&AnalysisOptionEntry> {
        self.entries.iter().find(|e| e.analyzer_name == analyzer_name)
    }

    /// Set the enabled state for an analyzer.
    pub fn set_enabled(&mut self, analyzer_name: &str, enabled: bool) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.analyzer_name == analyzer_name) {
            entry.enabled = enabled;
        }
    }

    /// Add a new option entry.
    pub fn add(&mut self, entry: AnalysisOptionEntry) {
        self.entries.push(entry);
    }
}

/// A single analysis option entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisOptionEntry {
    /// Analyzer name.
    pub analyzer_name: String,
    /// Whether this analyzer is enabled.
    pub enabled: bool,
    /// Additional key-value options.
    pub options: Vec<(String, String)>,
}

impl AnalysisOptionEntry {
    /// Create a new option entry.
    pub fn new(analyzer_name: impl Into<String>, enabled: bool) -> Self {
        Self {
            analyzer_name: analyzer_name.into(),
            enabled,
            options: Vec::new(),
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_scheduler() {
        let mut scheduler = AnalysisScheduler::new();
        assert!(!scheduler.is_running());
        assert_eq!(scheduler.task_count(), 0);

        scheduler.register_task(AnalysisTaskDescriptor::new("A", "First", 10));
        scheduler.register_task(AnalysisTaskDescriptor::new("B", "Second", 5));
        assert_eq!(scheduler.task_count(), 2);

        // B should come first (priority 5 < 10)
        let first = scheduler.next_task().unwrap();
        assert_eq!(first.name, "B");

        let second = scheduler.next_task().unwrap();
        assert_eq!(second.name, "A");

        assert!(!scheduler.has_more_tasks());
    }

    #[test]
    fn test_analysis_scheduler_start_stop() {
        let mut scheduler = AnalysisScheduler::new();
        scheduler.start();
        assert!(scheduler.is_running());
        scheduler.stop();
        assert!(!scheduler.is_running());
    }

    #[test]
    fn test_analysis_scheduler_reset() {
        let mut scheduler = AnalysisScheduler::new();
        scheduler.register_task(AnalysisTaskDescriptor::new("T", "task", 0));
        scheduler.next_task();
        assert!(!scheduler.has_more_tasks());
        scheduler.reset();
        assert!(scheduler.has_more_tasks());
    }

    #[test]
    fn test_analysis_task_list() {
        let mut list = AnalysisTaskList::new();
        assert!(list.is_empty());

        list.add(AnalysisTaskDescriptor::new("A", "desc", 0));
        list.add(AnalysisTaskDescriptor::new("B", "desc", 1));
        assert_eq!(list.len(), 2);

        assert_eq!(list.next().unwrap().name, "A");
        assert_eq!(list.next().unwrap().name, "B");
        assert!(list.next().is_none());

        list.reset();
        assert!(list.next().is_some());
    }

    #[test]
    fn test_analysis_options_set() {
        let mut opts = AnalysisOptionSet::new();
        opts.add(AnalysisOptionEntry::new("FuncAnalyzer", true));
        opts.add(AnalysisOptionEntry::new("DataAnalyzer", false));

        assert!(opts.get("FuncAnalyzer").unwrap().enabled);
        assert!(!opts.get("DataAnalyzer").unwrap().enabled);

        opts.set_enabled("DataAnalyzer", true);
        assert!(opts.get("DataAnalyzer").unwrap().enabled);
    }

    #[test]
    fn test_analysis_options_updater() {
        let mut opts = AnalysisOptionSet::new();
        opts.add(AnalysisOptionEntry::new("Analyzer1", true));
        opts.add(AnalysisOptionEntry::new("Analyzer2", true));
        opts.add(AnalysisOptionEntry::new("Analyzer3", true));

        let registered = vec!["Analyzer1".to_string(), "Analyzer3".to_string()];
        AnalysisOptionsUpdater::update_options(&registered, &mut opts);

        assert_eq!(opts.entries.len(), 2);
        assert!(opts.get("Analyzer1").is_some());
        assert!(opts.get("Analyzer2").is_none());
        assert!(opts.get("Analyzer3").is_some());
    }

    #[test]
    fn test_analysis_task_descriptor() {
        let d = AnalysisTaskDescriptor::new("MyAnalyzer", "Does analysis", 50);
        assert_eq!(d.name, "MyAnalyzer");
        assert_eq!(d.priority, 50);
        assert!(d.enabled);
        assert!(!d.exclusive);
    }

    #[test]
    fn test_analyzer_type_variants() {
        let t = AnalyzerType::FunctionStarts;
        assert_eq!(t, AnalyzerType::FunctionStarts);
        assert_ne!(t, AnalyzerType::DataReferences);
    }
}
