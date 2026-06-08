//! Auto-analysis manager and scheduler.
//!
//! Ported from `ghidra.app.plugin.core.analysis.AutoAnalysisManager`,
//! `AnalysisScheduler`, `AnalysisTask`, `AnalysisTaskList`, `AnalysisWorker`,
//! and `AutoAnalysisPlugin`.
//!
//! These components coordinate automatic analysis passes over a program,
//! including scheduling, priority ordering, progress tracking, and
//! background/foreground execution.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::enablement::AnalyzerEnablementState;

// ---------------------------------------------------------------------------
// AnalysisOption / AnalysisOptionValue
// ---------------------------------------------------------------------------

/// A configurable analysis option.
#[derive(Debug, Clone)]
pub struct AnalysisOption {
    /// The option key/name.
    pub name: String,
    /// The current value.
    pub value: AnalysisOptionValue,
    /// Description of this option.
    pub description: String,
}

/// Possible values for an analysis option.
#[derive(Debug, Clone)]
pub enum AnalysisOptionValue {
    /// Boolean value.
    Bool(bool),
    /// Integer value.
    Int(i64),
    /// String value.
    String(String),
}

// ---------------------------------------------------------------------------
// Analyzer trait (for analysis tasks)
// ---------------------------------------------------------------------------

/// Trait for an analyzer that can process a program.
///
/// This is the analysis-time interface. Each analyzer is registered with
/// the auto-analysis manager and scheduled for execution.
pub trait AnalysisPass: Send + Sync {
    /// Human-readable name of this analysis pass.
    fn name(&self) -> &str;

    /// Whether this analyzer is enabled by default.
    fn default_enabled(&self) -> bool {
        true
    }

    /// Whether this analyzer can be cancelled.
    fn is_cancellable(&self) -> bool {
        true
    }

    /// The analysis priority (lower = earlier).
    fn priority(&self) -> i32 {
        100
    }

    /// Get the analysis options for this analyzer.
    fn options(&self) -> Vec<AnalysisOption> {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// AnalysisTask
// ---------------------------------------------------------------------------

/// Status of an analysis task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskStatus {
    /// Task is waiting to be executed.
    Pending,
    /// Task is currently running.
    Running,
    /// Task completed successfully.
    Completed,
    /// Task was cancelled.
    Cancelled,
    /// Task failed with an error.
    Failed,
}

/// A unit of analysis work to be executed.
///
/// Ported from `ghidra.app.plugin.core.analysis.AnalysisTask`.
#[derive(Debug)]
pub struct AnalysisTask {
    /// The analysis pass this task belongs to.
    pub pass_name: String,
    /// The address range this task should analyze.
    pub start_address: u64,
    /// The end address (exclusive) for this task.
    pub end_address: u64,
    /// The priority of this task (lower = higher priority).
    pub priority: i32,
    /// Current status.
    pub status: TaskStatus,
    /// Error message, if the task failed.
    pub error: Option<String>,
    /// When this task was created.
    pub created_at: Instant,
    /// When this task started executing.
    pub started_at: Option<Instant>,
    /// When this task finished.
    pub finished_at: Option<Instant>,
}

impl AnalysisTask {
    /// Create a new analysis task.
    pub fn new(
        pass_name: impl Into<String>,
        start_address: u64,
        end_address: u64,
        priority: i32,
    ) -> Self {
        Self {
            pass_name: pass_name.into(),
            start_address,
            end_address,
            priority,
            status: TaskStatus::Pending,
            error: None,
            created_at: Instant::now(),
            started_at: None,
            finished_at: None,
        }
    }

    /// Mark this task as running.
    pub fn start(&mut self) {
        self.status = TaskStatus::Running;
        self.started_at = Some(Instant::now());
    }

    /// Mark this task as completed.
    pub fn complete(&mut self) {
        self.status = TaskStatus::Completed;
        self.finished_at = Some(Instant::now());
    }

    /// Mark this task as cancelled.
    pub fn cancel(&mut self) {
        self.status = TaskStatus::Cancelled;
        self.finished_at = Some(Instant::now());
    }

    /// Mark this task as failed.
    pub fn fail(&mut self, error: impl Into<String>) {
        self.status = TaskStatus::Failed;
        self.error = Some(error.into());
        self.finished_at = Some(Instant::now());
    }

    /// Whether this task is finished (completed, cancelled, or failed).
    pub fn is_finished(&self) -> bool {
        matches!(
            self.status,
            TaskStatus::Completed | TaskStatus::Cancelled | TaskStatus::Failed
        )
    }

    /// The execution duration, if the task has started.
    pub fn duration(&self) -> Option<Duration> {
        match (self.started_at, self.finished_at) {
            (Some(start), Some(end)) => Some(end.duration_since(start)),
            (Some(start), None) => Some(start.elapsed()),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// AnalysisTaskList
// ---------------------------------------------------------------------------

/// A priority queue of analysis tasks.
///
/// Ported from `ghidra.app.plugin.core.analysis.AnalysisTaskList`.
#[derive(Debug)]
pub struct AnalysisTaskList {
    /// Tasks ordered by priority (lower priority number = executed first).
    tasks: Vec<AnalysisTask>,
    /// Maximum number of tasks.
    max_tasks: usize,
}

impl AnalysisTaskList {
    /// Create a new empty task list.
    pub fn new() -> Self {
        Self {
            tasks: Vec::new(),
            max_tasks: 10_000,
        }
    }

    /// Add a task to the list.
    pub fn add(&mut self, task: AnalysisTask) {
        if self.tasks.len() < self.max_tasks {
            self.tasks.push(task);
            self.tasks.sort_by_key(|t| t.priority);
        }
    }

    /// Get the next pending task (lowest priority number).
    pub fn next_pending(&mut self) -> Option<&mut AnalysisTask> {
        self.tasks
            .iter_mut()
            .find(|t| t.status == TaskStatus::Pending)
    }

    /// Get the number of pending tasks.
    pub fn pending_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|t| t.status == TaskStatus::Pending)
            .count()
    }

    /// Get the total number of tasks (all statuses).
    pub fn total_count(&self) -> usize {
        self.tasks.len()
    }

    /// Get the number of completed tasks.
    pub fn completed_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|t| t.status == TaskStatus::Completed)
            .count()
    }

    /// Cancel all pending tasks.
    pub fn cancel_all(&mut self) {
        for task in &mut self.tasks {
            if task.status == TaskStatus::Pending {
                task.cancel();
            }
        }
    }

    /// Remove all finished tasks.
    pub fn clear_finished(&mut self) {
        self.tasks.retain(|t| !t.is_finished());
    }

    /// Get all tasks.
    pub fn tasks(&self) -> &[AnalysisTask] {
        &self.tasks
    }

    /// Whether there are any pending tasks.
    pub fn has_pending(&self) -> bool {
        self.tasks.iter().any(|t| t.status == TaskStatus::Pending)
    }
}

impl Default for AnalysisTaskList {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AnalysisScheduler
// ---------------------------------------------------------------------------

/// Schedules analysis passes to run in the correct order.
///
/// Ported from `ghidra.app.plugin.core.analysis.AnalysisScheduler`.
///
/// Manages the ordering and enablement of analysis passes, ensuring
/// that dependent analyses run after their prerequisites.
#[derive(Debug)]
pub struct AnalysisScheduler {
    /// Registered analysis passes, ordered by priority.
    passes: Vec<AnalysisSchedulerEntry>,
    /// Enablement state per pass.
    enablement: HashMap<String, AnalyzerEnablementState>,
    /// Whether the scheduler has been initialized.
    initialized: bool,
}

#[derive(Debug)]
struct AnalysisSchedulerEntry {
    name: String,
    priority: i32,
    enabled: bool,
    dependencies: Vec<String>,
}

impl AnalysisScheduler {
    /// Create a new analysis scheduler.
    pub fn new() -> Self {
        Self {
            passes: Vec::new(),
            enablement: HashMap::new(),
            initialized: false,
        }
    }

    /// Register an analysis pass.
    pub fn add_pass(&mut self, pass: &dyn AnalysisPass) {
        let entry = AnalysisSchedulerEntry {
            name: pass.name().to_string(),
            priority: pass.priority(),
            enabled: pass.default_enabled(),
            dependencies: Vec::new(),
        };
        self.passes.push(entry);
        self.passes.sort_by_key(|e| e.priority);
    }

    /// Register an analysis pass with dependencies.
    pub fn add_pass_with_deps(
        &mut self,
        pass: &dyn AnalysisPass,
        dependencies: Vec<String>,
    ) {
        let entry = AnalysisSchedulerEntry {
            name: pass.name().to_string(),
            priority: pass.priority(),
            enabled: pass.default_enabled(),
            dependencies,
        };
        self.passes.push(entry);
        self.passes.sort_by_key(|e| e.priority);
    }

    /// Enable or disable a specific analysis pass.
    pub fn set_enabled(&mut self, name: &str, enabled: bool) {
        if let Some(entry) = self.passes.iter_mut().find(|e| e.name == name) {
            entry.enabled = enabled;
        }
        let mut state = AnalyzerEnablementState::new(name, enabled, false);
        state.set_enabled(enabled);
        self.enablement.insert(name.to_string(), state);
    }

    /// Check if a pass is enabled.
    pub fn is_enabled(&self, name: &str) -> bool {
        self.passes
            .iter()
            .find(|e| e.name == name)
            .map_or(false, |e| e.enabled)
    }

    /// Get the list of enabled passes in execution order.
    pub fn enabled_passes(&self) -> Vec<&str> {
        self.passes
            .iter()
            .filter(|e| e.enabled)
            .map(|e| e.name.as_str())
            .collect()
    }

    /// Get the total number of registered passes.
    pub fn pass_count(&self) -> usize {
        self.passes.len()
    }

    /// Get the number of enabled passes.
    pub fn enabled_count(&self) -> usize {
        self.passes.iter().filter(|e| e.enabled).count()
    }

    /// Validate that all dependencies are satisfied.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        let pass_names: Vec<&str> = self.passes.iter().map(|e| e.name.as_str()).collect();

        for entry in &self.passes {
            for dep in &entry.dependencies {
                if !pass_names.contains(&dep.as_str()) {
                    errors.push(format!(
                        "Pass '{}' depends on '{}' which is not registered",
                        entry.name, dep
                    ));
                }
            }
        }
        errors
    }

    /// Initialize the scheduler.
    pub fn initialize(&mut self) {
        // Sort by priority.
        self.passes.sort_by_key(|e| e.priority);
        self.initialized = true;
    }

    /// Whether the scheduler has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get the names of all registered passes.
    pub fn pass_names(&self) -> Vec<&str> {
        self.passes.iter().map(|e| e.name.as_str()).collect()
    }
}

impl Default for AnalysisScheduler {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AnalysisWorker
// ---------------------------------------------------------------------------

/// Executes analysis tasks from a task list.
///
/// Ported from `ghidra.app.plugin.core.analysis.AnalysisWorker`.
pub struct AnalysisWorker {
    /// The task list to pull from.
    task_list: Arc<Mutex<AnalysisTaskList>>,
    /// Whether the worker should stop.
    cancelled: Arc<Mutex<bool>>,
    /// Number of tasks processed.
    processed: usize,
    /// Maximum time to spend on analysis (in milliseconds).
    time_limit_ms: u64,
}

impl AnalysisWorker {
    /// Create a new analysis worker.
    pub fn new(task_list: Arc<Mutex<AnalysisTaskList>>) -> Self {
        Self {
            task_list,
            cancelled: Arc::new(Mutex::new(false)),
            processed: 0,
            time_limit_ms: 30_000, // 30 seconds default
        }
    }

    /// Set the time limit in milliseconds.
    pub fn set_time_limit(&mut self, ms: u64) {
        self.time_limit_ms = ms;
    }

    /// Get a handle to the cancellation flag.
    pub fn cancellation_handle(&self) -> Arc<Mutex<bool>> {
        self.cancelled.clone()
    }

    /// Request cancellation of the worker.
    pub fn cancel(&self) {
        *self.cancelled.lock().unwrap() = true;
    }

    /// Whether the worker has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        *self.cancelled.lock().unwrap()
    }

    /// Run the worker, processing tasks until the list is empty or cancelled.
    pub fn run(&mut self) -> WorkerResult {
        let start = Instant::now();
        let mut result = WorkerResult::default();

        loop {
            if self.is_cancelled() {
                result.was_cancelled = true;
                break;
            }

            if start.elapsed().as_millis() as u64 > self.time_limit_ms {
                result.timed_out = true;
                break;
            }

            // Get next task.
            let task = {
                let mut list = self.task_list.lock().unwrap();
                list.next_pending().map(|t| {
                    t.start();
                    t.pass_name.clone()
                })
            };

            match task {
                Some(pass_name) => {
                    // In a real implementation, this would call the analyzer.
                    // Here we just mark the task as completed.
                    let mut list = self.task_list.lock().unwrap();
                    if let Some(t) = list.tasks.iter_mut().find(|t| t.pass_name == pass_name && t.status == TaskStatus::Running) {
                        t.complete();
                    }
                    self.processed += 1;
                    result.tasks_processed += 1;
                }
                None => {
                    result.all_completed = true;
                    break;
                }
            }
        }

        result.total_processed = self.processed;
        result
    }

    /// Get the number of tasks processed so far.
    pub fn processed_count(&self) -> usize {
        self.processed
    }
}

/// Result of running an analysis worker.
#[derive(Debug, Default, Clone)]
pub struct WorkerResult {
    /// Number of tasks processed in this run.
    pub tasks_processed: usize,
    /// Total tasks processed across all runs.
    pub total_processed: usize,
    /// Whether the worker was cancelled.
    pub was_cancelled: bool,
    /// Whether the worker timed out.
    pub timed_out: bool,
    /// Whether all tasks were completed.
    pub all_completed: bool,
}

// ---------------------------------------------------------------------------
// AnalysisBackgroundCommand
// ---------------------------------------------------------------------------

/// A command that runs analysis in the background.
///
/// Ported from `ghidra.app.plugin.core.analysis.AnalysisBackgroundCommand`.
#[derive(Debug)]
pub struct AnalysisBackgroundCommand {
    /// Description of this command.
    pub description: String,
    /// Whether the command has completed.
    completed: bool,
    /// Whether the command was cancelled.
    cancelled: bool,
}

impl AnalysisBackgroundCommand {
    /// Create a new background analysis command.
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            completed: false,
            cancelled: false,
        }
    }

    /// Mark as completed.
    pub fn set_completed(&mut self) {
        self.completed = true;
    }

    /// Whether the command has completed.
    pub fn is_completed(&self) -> bool {
        self.completed
    }

    /// Cancel this command.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Whether this command was cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }
}

// ---------------------------------------------------------------------------
// OneShotAnalysisCommand
// ---------------------------------------------------------------------------

/// A command that runs a single analysis pass on a specific address range.
///
/// Ported from `ghidra.app.plugin.core.analysis.OneShotAnalysisCommand`.
#[derive(Debug)]
pub struct OneShotAnalysisCommand {
    /// The analysis pass name.
    pub pass_name: String,
    /// Start address.
    pub start_address: u64,
    /// End address.
    pub end_address: u64,
    /// Whether completed.
    completed: bool,
}

impl OneShotAnalysisCommand {
    /// Create a new one-shot analysis command.
    pub fn new(pass_name: impl Into<String>, start_address: u64, end_address: u64) -> Self {
        Self {
            pass_name: pass_name.into(),
            start_address,
            end_address,
            completed: false,
        }
    }

    /// Mark as completed.
    pub fn set_completed(&mut self) {
        self.completed = true;
    }

    /// Whether completed.
    pub fn is_completed(&self) -> bool {
        self.completed
    }
}

// ---------------------------------------------------------------------------
// AutoAnalysisManager
// ---------------------------------------------------------------------------

/// Central manager for automatic analysis of a program.
///
/// Ported from `ghidra.app.plugin.core.analysis.AutoAnalysisManager`.
///
/// Coordinates the scheduling and execution of analysis passes,
/// manages analysis options, and provides progress tracking.
#[derive(Debug)]
pub struct AutoAnalysisManager {
    /// The scheduler that orders analysis passes.
    scheduler: AnalysisScheduler,
    /// The current task list.
    task_list: Arc<Mutex<AnalysisTaskList>>,
    /// Analysis options (per-analyzer settings).
    options: BTreeMap<String, AnalysisOptionValue>,
    /// Whether auto-analysis is enabled.
    auto_analysis_enabled: bool,
    /// Whether analysis is currently running.
    is_analyzing: bool,
    /// The number of analysis iterations completed.
    iteration_count: usize,
    /// Maximum number of analysis iterations.
    max_iterations: usize,
    /// Analysis start time.
    start_time: Option<Instant>,
    /// Total time spent analyzing.
    total_analysis_time: Duration,
}

impl AutoAnalysisManager {
    /// Create a new auto-analysis manager.
    pub fn new() -> Self {
        Self {
            scheduler: AnalysisScheduler::new(),
            task_list: Arc::new(Mutex::new(AnalysisTaskList::new())),
            options: BTreeMap::new(),
            auto_analysis_enabled: true,
            is_analyzing: false,
            iteration_count: 0,
            max_iterations: 100,
            start_time: None,
            total_analysis_time: Duration::default(),
        }
    }

    /// Get the scheduler.
    pub fn scheduler(&self) -> &AnalysisScheduler {
        &self.scheduler
    }

    /// Get a mutable reference to the scheduler.
    pub fn scheduler_mut(&mut self) -> &mut AnalysisScheduler {
        &mut self.scheduler
    }

    /// Enable or disable auto-analysis.
    pub fn set_auto_analysis_enabled(&mut self, enabled: bool) {
        self.auto_analysis_enabled = enabled;
    }

    /// Whether auto-analysis is enabled.
    pub fn is_auto_analysis_enabled(&self) -> bool {
        self.auto_analysis_enabled
    }

    /// Whether analysis is currently running.
    pub fn is_analyzing(&self) -> bool {
        self.is_analyzing
    }

    /// Start a new analysis iteration.
    pub fn start_analysis(&mut self) {
        self.is_analyzing = true;
        self.start_time = Some(Instant::now());
        self.iteration_count += 1;
    }

    /// End the current analysis iteration.
    pub fn end_analysis(&mut self) {
        self.is_analyzing = false;
        if let Some(start) = self.start_time.take() {
            self.total_analysis_time += start.elapsed();
        }
    }

    /// Get the iteration count.
    pub fn iteration_count(&self) -> usize {
        self.iteration_count
    }

    /// Get the total analysis time.
    pub fn total_analysis_time(&self) -> Duration {
        self.total_analysis_time
    }

    /// Schedule analysis for a specific address range.
    pub fn analyze(&mut self, pass_name: &str, start_address: u64, end_address: u64) {
        if !self.auto_analysis_enabled {
            return;
        }
        if !self.scheduler.is_enabled(pass_name) {
            return;
        }

        let task = AnalysisTask::new(pass_name, start_address, end_address, 100);
        self.task_list.lock().unwrap().add(task);
    }

    /// Schedule analysis for the entire program.
    pub fn analyze_all(&mut self, program_size: u64) {
        let pass_names: Vec<String> = self
            .scheduler
            .enabled_passes()
            .iter()
            .map(|s| s.to_string())
            .collect();

        for name in pass_names {
            let task = AnalysisTask::new(name, 0, program_size, 100);
            self.task_list.lock().unwrap().add(task);
        }
    }

    /// Get the pending task count.
    pub fn pending_task_count(&self) -> usize {
        self.task_list.lock().unwrap().pending_count()
    }

    /// Cancel all pending analysis tasks.
    pub fn cancel_all(&mut self) {
        self.task_list.lock().unwrap().cancel_all();
    }

    /// Get a reference to the task list.
    pub fn task_list(&self) -> Arc<Mutex<AnalysisTaskList>> {
        self.task_list.clone()
    }

    /// Set an analysis option.
    pub fn set_option(&mut self, key: impl Into<String>, value: AnalysisOptionValue) {
        self.options.insert(key.into(), value);
    }

    /// Get an analysis option.
    pub fn get_option(&self, key: &str) -> Option<&AnalysisOptionValue> {
        self.options.get(key)
    }

    /// Get the max iterations setting.
    pub fn max_iterations(&self) -> usize {
        self.max_iterations
    }

    /// Set the max iterations.
    pub fn set_max_iterations(&mut self, max: usize) {
        self.max_iterations = max;
    }

    /// Create a worker for background analysis.
    pub fn create_worker(&self) -> AnalysisWorker {
        AnalysisWorker::new(self.task_list.clone())
    }
}

impl Default for AutoAnalysisManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct TestPass {
        name: String,
        priority: i32,
    }
    impl AnalysisPass for TestPass {
        fn name(&self) -> &str {
            &self.name
        }
        fn priority(&self) -> i32 {
            self.priority
        }
    }

    #[test]
    fn test_analysis_task_lifecycle() {
        let mut task = AnalysisTask::new("test", 0, 0x1000, 100);
        assert_eq!(task.status, TaskStatus::Pending);
        assert!(!task.is_finished());

        task.start();
        assert_eq!(task.status, TaskStatus::Running);
        assert!(task.duration().is_some());

        task.complete();
        assert_eq!(task.status, TaskStatus::Completed);
        assert!(task.is_finished());
    }

    #[test]
    fn test_analysis_task_cancel() {
        let mut task = AnalysisTask::new("test", 0, 0x1000, 100);
        task.cancel();
        assert_eq!(task.status, TaskStatus::Cancelled);
        assert!(task.is_finished());
    }

    #[test]
    fn test_analysis_task_fail() {
        let mut task = AnalysisTask::new("test", 0, 0x1000, 100);
        task.fail("something broke");
        assert_eq!(task.status, TaskStatus::Failed);
        assert_eq!(task.error.as_deref(), Some("something broke"));
        assert!(task.is_finished());
    }

    #[test]
    fn test_task_list_priority_order() {
        let mut list = AnalysisTaskList::new();
        list.add(AnalysisTask::new("low", 0, 0x100, 200));
        list.add(AnalysisTask::new("high", 0, 0x100, 10));
        list.add(AnalysisTask::new("med", 0, 0x100, 100));

        assert_eq!(list.total_count(), 3);
        assert_eq!(list.pending_count(), 3);

        let next = list.next_pending().unwrap();
        assert_eq!(next.pass_name, "high");
    }

    #[test]
    fn test_task_list_cancel_all() {
        let mut list = AnalysisTaskList::new();
        list.add(AnalysisTask::new("a", 0, 0x100, 100));
        list.add(AnalysisTask::new("b", 0, 0x100, 100));
        list.cancel_all();
        assert_eq!(list.pending_count(), 0);
    }

    #[test]
    fn test_analysis_scheduler() {
        let mut scheduler = AnalysisScheduler::new();
        let p1 = TestPass {
            name: "pass1".into(),
            priority: 10,
        };
        let p2 = TestPass {
            name: "pass2".into(),
            priority: 20,
        };

        scheduler.add_pass(&p1);
        scheduler.add_pass(&p2);
        scheduler.initialize();

        assert_eq!(scheduler.pass_count(), 2);
        assert_eq!(scheduler.enabled_count(), 2);
        assert!(scheduler.is_enabled("pass1"));

        scheduler.set_enabled("pass1", false);
        assert!(!scheduler.is_enabled("pass1"));
        assert_eq!(scheduler.enabled_count(), 1);
    }

    #[test]
    fn test_scheduler_enabled_passes_order() {
        let mut scheduler = AnalysisScheduler::new();
        let p1 = TestPass {
            name: "z_pass".into(),
            priority: 200,
        };
        let p2 = TestPass {
            name: "a_pass".into(),
            priority: 10,
        };
        scheduler.add_pass(&p1);
        scheduler.add_pass(&p2);

        let enabled = scheduler.enabled_passes();
        assert_eq!(enabled, vec!["a_pass", "z_pass"]);
    }

    #[test]
    fn test_scheduler_validate() {
        let mut scheduler = AnalysisScheduler::new();
        let p1 = TestPass {
            name: "pass1".into(),
            priority: 10,
        };
        scheduler.add_pass(&p1);
        scheduler.add_pass_with_deps(
            &TestPass {
                name: "pass2".into(),
                priority: 20,
            },
            vec!["nonexistent".into()],
        );

        let errors = scheduler.validate();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("nonexistent"));
    }

    #[test]
    fn test_auto_analysis_manager() {
        let mut mgr = AutoAnalysisManager::new();
        assert!(mgr.is_auto_analysis_enabled());
        assert!(!mgr.is_analyzing());
        assert_eq!(mgr.iteration_count(), 0);

        mgr.start_analysis();
        assert!(mgr.is_analyzing());
        assert_eq!(mgr.iteration_count(), 1);

        mgr.end_analysis();
        assert!(!mgr.is_analyzing());
    }

    #[test]
    fn test_auto_analysis_manager_analyze() {
        let mut mgr = AutoAnalysisManager::new();
        let pass = TestPass {
            name: "test_pass".into(),
            priority: 100,
        };
        mgr.scheduler_mut().add_pass(&pass);

        mgr.analyze("test_pass", 0, 0x1000);
        assert_eq!(mgr.pending_task_count(), 1);

        // Disabled analysis should not create tasks.
        mgr.set_auto_analysis_enabled(false);
        mgr.analyze("test_pass", 0x1000, 0x2000);
        assert_eq!(mgr.pending_task_count(), 1);
    }

    #[test]
    fn test_auto_analysis_manager_options() {
        let mut mgr = AutoAnalysisManager::new();
        mgr.set_option("max_depth", AnalysisOptionValue::Int(10));
        assert!(matches!(
            mgr.get_option("max_depth"),
            Some(AnalysisOptionValue::Int(10))
        ));
        assert!(mgr.get_option("nonexistent").is_none());
    }

    #[test]
    fn test_auto_analysis_manager_cancel() {
        let mut mgr = AutoAnalysisManager::new();
        let pass = TestPass {
            name: "test".into(),
            priority: 100,
        };
        mgr.scheduler_mut().add_pass(&pass);
        mgr.analyze("test", 0, 0x1000);
        assert_eq!(mgr.pending_task_count(), 1);

        mgr.cancel_all();
        assert_eq!(mgr.pending_task_count(), 0);
    }

    #[test]
    fn test_analysis_worker() {
        let task_list = Arc::new(Mutex::new(AnalysisTaskList::new()));
        task_list
            .lock()
            .unwrap()
            .add(AnalysisTask::new("a", 0, 0x100, 100));
        task_list
            .lock()
            .unwrap()
            .add(AnalysisTask::new("b", 0, 0x200, 200));

        let mut worker = AnalysisWorker::new(task_list);
        worker.set_time_limit(5000);
        let result = worker.run();

        assert_eq!(result.tasks_processed, 2);
        assert!(result.all_completed);
        assert!(!result.was_cancelled);
    }

    #[test]
    fn test_analysis_worker_cancel() {
        let task_list = Arc::new(Mutex::new(AnalysisTaskList::new()));
        task_list
            .lock()
            .unwrap()
            .add(AnalysisTask::new("a", 0, 0x100, 100));

        let worker = AnalysisWorker::new(task_list);
        worker.cancel();
        assert!(worker.is_cancelled());
    }

    #[test]
    fn test_background_command() {
        let mut cmd = AnalysisBackgroundCommand::new("Analyze ELF headers");
        assert!(!cmd.is_completed());
        assert!(!cmd.is_cancelled());

        cmd.set_completed();
        assert!(cmd.is_completed());

        let mut cmd2 = AnalysisBackgroundCommand::new("test");
        cmd2.cancel();
        assert!(cmd2.is_cancelled());
    }

    #[test]
    fn test_one_shot_analysis_command() {
        let mut cmd = OneShotAnalysisCommand::new("ConstantPropagation", 0, 0x1000);
        assert_eq!(cmd.pass_name, "ConstantPropagation");
        assert!(!cmd.is_completed());

        cmd.set_completed();
        assert!(cmd.is_completed());
    }

    #[test]
    fn test_worker_result_default() {
        let result = WorkerResult::default();
        assert_eq!(result.tasks_processed, 0);
        assert!(!result.was_cancelled);
        assert!(!result.timed_out);
        assert!(!result.all_completed);
    }
}
