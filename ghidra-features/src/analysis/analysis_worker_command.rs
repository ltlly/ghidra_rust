//! Analysis worker command infrastructure.
//!
//! Ported from `AutoAnalysisManager.AnalysisWorkerCommand` and
//! `AutoAnalysisManager.JointTaskMonitor`.
//!
//! Provides the command wrapper that executes an [`AnalysisWorker`]
//! callback while analysis is suspended, including joint monitor
//! delegation and cancellation propagation.

use std::fmt;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

// ---------------------------------------------------------------------------
// AnalysisWorker trait
// ---------------------------------------------------------------------------

/// Callback interface for performing work while analysis is suspended.
///
/// Ported from `AnalysisWorker.java`. Implementors provide a callback
/// that modifies the program while auto-analysis is paused, ensuring
/// no concurrent analysis interference.
///
/// # Usage
///
/// The worker is scheduled via [`crate::analysis::auto_analysis::AutoAnalysisManager::schedule_worker`].
/// While the worker runs, auto-analysis change events are suppressed.
pub trait AnalysisWorker: Send + Sync {
    /// Perform the desired program changes while analysis is suspended.
    ///
    /// # Arguments
    /// * `worker_context` - Context data provided when the worker was scheduled.
    ///
    /// # Returns
    /// `true` if the worker completed successfully, `false` if cancelled.
    fn analysis_worker_callback(&self, worker_context: Option<&dyn std::any::Any>) -> bool;

    /// Returns a short worker name for the analysis task monitor.
    fn get_worker_name(&self) -> &str;
}

impl fmt::Debug for dyn AnalysisWorker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AnalysisWorker({})", self.get_worker_name())
    }
}

// ---------------------------------------------------------------------------
// WorkerState -- execution state of a worker command
// ---------------------------------------------------------------------------

/// State of an analysis worker command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerState {
    /// The command has been created but not yet started.
    Queued,
    /// The command is currently executing.
    Running,
    /// The command completed successfully.
    Completed,
    /// The command was cancelled before or during execution.
    Cancelled,
    /// The command failed with an error.
    Failed,
}

// ---------------------------------------------------------------------------
// AnalysisWorkerCommand
// ---------------------------------------------------------------------------

/// Wraps an [`AnalysisWorker`] for execution within the analysis pipeline.
///
/// Ported from `AutoAnalysisManager.AnalysisWorkerCommand`. This command:
/// 1. Suspends auto-analysis change events while the worker runs
/// 2. Provides a joint monitor that propagates cancellation to both the
///    analysis monitor and the worker monitor
/// 3. Notifies waiting threads when the worker completes
///
/// In a headed environment, a modal dialog blocks user input when
/// `analyze_changes` is `false`.
pub struct AnalysisWorkerCommand {
    /// The worker to execute.
    worker: Box<dyn AnalysisWorker>,
    /// Whether program changes during the worker should trigger analysis.
    analyze_changes: bool,
    /// Whether the command supports cancellation.
    cancellable: bool,
    /// Current execution state.
    state: Arc<Mutex<WorkerState>>,
    /// Condition variable for waiting on completion.
    completion: Arc<(Mutex<bool>, Condvar)>,
    /// The worker's return value.
    return_value: Arc<Mutex<bool>>,
    /// Error message if the worker failed.
    error: Arc<Mutex<Option<String>>>,
    /// Whether the command has been killed (cancelled before execution).
    killed: Arc<Mutex<bool>>,
    /// Start time of execution.
    start_time: Arc<Mutex<Option<Instant>>>,
    /// End time of execution.
    end_time: Arc<Mutex<Option<Instant>>>,
}

impl AnalysisWorkerCommand {
    /// Create a new analysis worker command.
    ///
    /// # Arguments
    /// * `worker` - The worker to execute.
    /// * `analyze_changes` - If `false`, program changes during the worker
    ///   will not trigger follow-on analysis.
    /// * `cancellable` - Whether the command can be cancelled.
    pub fn new(
        worker: Box<dyn AnalysisWorker>,
        analyze_changes: bool,
        cancellable: bool,
    ) -> Self {
        Self {
            worker,
            analyze_changes,
            cancellable,
            state: Arc::new(Mutex::new(WorkerState::Queued)),
            completion: Arc::new((Mutex::new(false), Condvar::new())),
            return_value: Arc::new(Mutex::new(false)),
            error: Arc::new(Mutex::new(None)),
            killed: Arc::new(Mutex::new(false)),
            start_time: Arc::new(Mutex::new(None)),
            end_time: Arc::new(Mutex::new(None)),
        }
    }

    /// Get the worker name.
    pub fn worker_name(&self) -> &str {
        self.worker.get_worker_name()
    }

    /// Whether the command should suppress change events during execution.
    pub fn analyze_changes(&self) -> bool {
        self.analyze_changes
    }

    /// Whether the command can be cancelled.
    pub fn is_cancellable(&self) -> bool {
        self.cancellable
    }

    /// Get the current execution state.
    pub fn state(&self) -> WorkerState {
        *self.state.lock().unwrap()
    }

    /// Get the worker's return value (only valid after completion).
    pub fn return_value(&self) -> bool {
        *self.return_value.lock().unwrap()
    }

    /// Get the error message, if the worker failed.
    pub fn error(&self) -> Option<String> {
        self.error.lock().unwrap().clone()
    }

    /// Get the execution duration in milliseconds.
    pub fn duration_ms(&self) -> Option<u64> {
        let start = *self.start_time.lock().unwrap();
        let end = *self.end_time.lock().unwrap();
        match (start, end) {
            (Some(s), Some(e)) => Some(e.duration_since(s).as_millis() as u64),
            (Some(s), None) => Some(s.elapsed().as_millis() as u64),
            _ => None,
        }
    }

    /// Cancel the command.
    ///
    /// If the command is queued, it will be marked as killed and will not
    /// execute. If it is running, the worker will be notified via the
    /// cancellation mechanism.
    pub fn cancel(&self) {
        if !self.cancellable {
            return;
        }
        *self.killed.lock().unwrap() = true;
        *self.state.lock().unwrap() = WorkerState::Cancelled;
        self.notify_completion();
    }

    /// Whether the command has been killed/cancelled.
    pub fn is_killed(&self) -> bool {
        *self.killed.lock().unwrap()
    }

    /// Execute the worker callback.
    ///
    /// This is called by the analysis thread when the command reaches the
    /// front of the priority queue. It invokes the worker's callback and
    /// captures the result.
    ///
    /// # Returns
    /// `true` if the worker completed successfully.
    pub fn execute(&self, context: Option<&dyn std::any::Any>) -> bool {
        if self.is_killed() {
            return false;
        }

        *self.state.lock().unwrap() = WorkerState::Running;
        *self.start_time.lock().unwrap() = Some(Instant::now());

        let result = self.worker.analysis_worker_callback(context);

        *self.return_value.lock().unwrap() = result;
        *self.end_time.lock().unwrap() = Some(Instant::now());
        *self.state.lock().unwrap() = if result {
            WorkerState::Completed
        } else {
            WorkerState::Cancelled
        };

        self.notify_completion();
        result
    }

    /// Execute the worker within a transaction-like context.
    ///
    /// This wraps the execution with setup/teardown for change event
    /// suppression.
    pub fn execute_with_transaction(&self, context: Option<&dyn std::any::Any>) -> bool {
        // In a full implementation, this would start/end a program transaction
        // and manage change event suppression. Here we just delegate to execute.
        self.execute(context)
    }

    /// Wait for the command to complete.
    ///
    /// Blocks the calling thread until the worker finishes execution
    /// or is cancelled.
    pub fn wait_for_completion(&self) {
        let (lock, cvar) = &*self.completion;
        let mut done = lock.lock().unwrap();
        while !*done {
            done = cvar.wait(done).unwrap();
        }
    }

    /// Wait for completion with a timeout.
    ///
    /// Returns `true` if the command completed, `false` if the timeout
    /// was reached.
    pub fn wait_for_completion_timeout(&self, timeout: std::time::Duration) -> bool {
        let (lock, cvar) = &*self.completion;
        let done = lock.lock().unwrap();
        if *done {
            return true;
        }
        let result = cvar.wait_timeout(done, timeout).unwrap();
        *result.0
    }

    /// Notify all threads waiting on completion.
    fn notify_completion(&self) {
        let (lock, cvar) = &*self.completion;
        let mut done = lock.lock().unwrap();
        *done = true;
        cvar.notify_all();
    }

    /// Get a cancellation handle for external monitoring.
    pub fn cancellation_handle(&self) -> WorkerCancellationHandle {
        WorkerCancellationHandle {
            killed: self.killed.clone(),
            cancellable: self.cancellable,
        }
    }
}

impl fmt::Debug for AnalysisWorkerCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnalysisWorkerCommand")
            .field("worker_name", &self.worker.get_worker_name())
            .field("analyze_changes", &self.analyze_changes)
            .field("cancellable", &self.cancellable)
            .field("state", &self.state())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// WorkerCancellationHandle
// ---------------------------------------------------------------------------

/// A handle that allows checking and requesting cancellation of a worker
/// command from external code.
#[derive(Clone)]
pub struct WorkerCancellationHandle {
    killed: Arc<Mutex<bool>>,
    cancellable: bool,
}

impl WorkerCancellationHandle {
    /// Whether the worker has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        *self.killed.lock().unwrap()
    }

    /// Request cancellation.
    pub fn cancel(&self) {
        if self.cancellable {
            *self.killed.lock().unwrap() = true;
        }
    }

    /// Whether cancellation is supported.
    pub fn is_cancellable(&self) -> bool {
        self.cancellable
    }
}

// ---------------------------------------------------------------------------
// JointTaskMonitor -- delegates to two monitors simultaneously
// ---------------------------------------------------------------------------

/// A task monitor that delegates operations to two underlying monitors.
///
/// Ported from `AutoAnalysisManager.JointTaskMonitor`. This is used when
/// an analysis worker has its own monitor but also needs to propagate
/// state to the analysis thread's monitor.
#[derive(Debug)]
pub struct JointTaskMonitor {
    primary: Arc<Mutex<MonitorState>>,
    secondary: Arc<Mutex<MonitorState>>,
}

#[derive(Debug, Default)]
struct MonitorState {
    cancelled: bool,
    cancel_enabled: bool,
    message: String,
    progress: i64,
    maximum: i64,
    indeterminate: bool,
}

impl JointTaskMonitor {
    /// Create a new joint monitor wrapping two monitor states.
    pub fn new() -> Self {
        Self {
            primary: Arc::new(Mutex::new(MonitorState {
                cancel_enabled: true,
                ..Default::default()
            })),
            secondary: Arc::new(Mutex::new(MonitorState {
                cancel_enabled: true,
                ..Default::default()
            })),
        }
    }

    /// Whether either monitor has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.primary.lock().unwrap().cancelled || self.secondary.lock().unwrap().cancelled
    }

    /// Cancel both monitors.
    pub fn cancel(&self) {
        self.primary.lock().unwrap().cancelled = true;
        self.secondary.lock().unwrap().cancelled = true;
    }

    /// Clear the cancelled state on both monitors.
    pub fn clear_cancelled(&self) {
        self.primary.lock().unwrap().cancelled = false;
        self.secondary.lock().unwrap().cancelled = false;
    }

    /// Set cancel-enabled on both monitors.
    pub fn set_cancel_enabled(&self, enabled: bool) {
        self.primary.lock().unwrap().cancel_enabled = enabled;
        self.secondary.lock().unwrap().cancel_enabled = enabled;
    }

    /// Whether cancellation is enabled on the primary monitor.
    pub fn is_cancel_enabled(&self) -> bool {
        self.primary.lock().unwrap().cancel_enabled
    }

    /// Set the message on both monitors.
    pub fn set_message(&self, message: &str) {
        self.primary.lock().unwrap().message = message.to_string();
        self.secondary.lock().unwrap().message = message.to_string();
    }

    /// Get the primary monitor's message.
    pub fn message(&self) -> String {
        self.primary.lock().unwrap().message.clone()
    }

    /// Set progress on both monitors.
    pub fn set_progress(&self, value: i64) {
        self.primary.lock().unwrap().progress = value;
        self.secondary.lock().unwrap().progress = value;
    }

    /// Get the maximum of both monitors' progress values.
    pub fn progress(&self) -> i64 {
        std::cmp::max(
            self.primary.lock().unwrap().progress,
            self.secondary.lock().unwrap().progress,
        )
    }

    /// Increment progress on both monitors.
    pub fn increment_progress(&self, amount: i64) {
        self.primary.lock().unwrap().progress += amount;
        self.secondary.lock().unwrap().progress += amount;
    }

    /// Set the maximum on both monitors.
    pub fn set_maximum(&self, max: i64) {
        self.primary.lock().unwrap().maximum = max;
        self.secondary.lock().unwrap().maximum = max;
    }

    /// Get the maximum of both monitors' maximum values.
    pub fn maximum(&self) -> i64 {
        std::cmp::max(
            self.primary.lock().unwrap().maximum,
            self.secondary.lock().unwrap().maximum,
        )
    }

    /// Initialize both monitors with a maximum value.
    pub fn initialize(&self, max: i64) {
        self.set_maximum(max);
        self.set_progress(0);
    }

    /// Set indeterminate state on both monitors.
    pub fn set_indeterminate(&self, indeterminate: bool) {
        self.primary.lock().unwrap().indeterminate = indeterminate;
        self.secondary.lock().unwrap().indeterminate = indeterminate;
    }

    /// Whether the primary monitor is indeterminate.
    pub fn is_indeterminate(&self) -> bool {
        self.primary.lock().unwrap().indeterminate
    }

    /// Check if cancelled and return an error if so.
    pub fn check_cancelled(&self) -> Result<(), CancelledError> {
        if self.is_cancelled() {
            Err(CancelledError)
        } else {
            Ok(())
        }
    }
}

impl Default for JointTaskMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Error type for cancelled operations.
#[derive(Debug, Clone)]
pub struct CancelledError;

impl fmt::Display for CancelledError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Operation was cancelled")
    }
}

impl std::error::Error for CancelledError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct TestWorker {
        name: String,
        should_return: bool,
        was_called: Arc<AtomicBool>,
    }

    impl TestWorker {
        fn new(name: &str, should_return: bool) -> (Self, Arc<AtomicBool>) {
            let called = Arc::new(AtomicBool::new(false));
            (
                Self {
                    name: name.to_string(),
                    should_return,
                    was_called: called.clone(),
                },
                called,
            )
        }
    }

    impl AnalysisWorker for TestWorker {
        fn analysis_worker_callback(&self, _context: Option<&dyn std::any::Any>) -> bool {
            self.was_called.store(true, Ordering::SeqCst);
            self.should_return
        }

        fn get_worker_name(&self) -> &str {
            &self.name
        }
    }

    #[test]
    fn test_worker_command_execute() {
        let (worker, called) = TestWorker::new("TestWorker", true);
        let cmd = AnalysisWorkerCommand::new(Box::new(worker), true, true);

        assert_eq!(cmd.state(), WorkerState::Queued);
        let result = cmd.execute(None);

        assert!(result);
        assert!(called.load(Ordering::SeqCst));
        assert_eq!(cmd.state(), WorkerState::Completed);
        assert!(cmd.return_value());
    }

    #[test]
    fn test_worker_command_cancel_return() {
        let (worker, called) = TestWorker::new("TestWorker", false);
        let cmd = AnalysisWorkerCommand::new(Box::new(worker), true, true);

        let result = cmd.execute(None);
        assert!(!result);
        assert!(called.load(Ordering::SeqCst));
        assert_eq!(cmd.state(), WorkerState::Cancelled);
    }

    #[test]
    fn test_worker_command_cancel_before_execute() {
        let (worker, _) = TestWorker::new("TestWorker", true);
        let cmd = AnalysisWorkerCommand::new(Box::new(worker), true, true);

        cmd.cancel();
        assert!(cmd.is_killed());
        assert_eq!(cmd.state(), WorkerState::Cancelled);

        let result = cmd.execute(None);
        assert!(!result);
    }

    #[test]
    fn test_worker_command_non_cancellable() {
        let (worker, _) = TestWorker::new("TestWorker", true);
        let cmd = AnalysisWorkerCommand::new(Box::new(worker), true, false);

        cmd.cancel(); // should be a no-op
        assert!(!cmd.is_killed());

        let result = cmd.execute(None);
        assert!(result);
    }

    #[test]
    fn test_worker_command_wait() {
        let (worker, _) = TestWorker::new("TestWorker", true);
        let cmd = AnalysisWorkerCommand::new(Box::new(worker), true, true);

        // Execute in a thread
        let handle = {
            let state = cmd.state.clone();
            let completion = cmd.completion.clone();
            let return_value = cmd.return_value.clone();
            let killed = cmd.killed.clone();
            // We can't easily share the command across threads in this test,
            // so we test wait_for_completion_timeout instead
            std::thread::spawn(move || {
                // Small delay then simulate completion
                std::thread::sleep(std::time::Duration::from_millis(50));
                let (lock, cvar) = &*completion;
                let mut done = lock.lock().unwrap();
                *done = true;
                cvar.notify_all();
            })
        };

        let completed = cmd.wait_for_completion_timeout(std::time::Duration::from_secs(1));
        assert!(completed);
        handle.join().unwrap();
    }

    #[test]
    fn test_cancellation_handle() {
        let (worker, _) = TestWorker::new("TestWorker", true);
        let cmd = AnalysisWorkerCommand::new(Box::new(worker), true, true);

        let handle = cmd.cancellation_handle();
        assert!(!handle.is_cancelled());
        assert!(handle.is_cancellable());

        handle.cancel();
        assert!(handle.is_cancelled());
        assert!(cmd.is_killed());
    }

    #[test]
    fn test_cancellation_handle_non_cancellable() {
        let (worker, _) = TestWorker::new("TestWorker", true);
        let cmd = AnalysisWorkerCommand::new(Box::new(worker), true, false);

        let handle = cmd.cancellation_handle();
        handle.cancel(); // should be a no-op
        assert!(!handle.is_cancelled());
    }

    #[test]
    fn test_joint_monitor_basic() {
        let monitor = JointTaskMonitor::new();
        assert!(!monitor.is_cancelled());
        assert!(monitor.is_cancel_enabled());

        monitor.set_message("Testing");
        assert_eq!(monitor.message(), "Testing");

        monitor.set_progress(50);
        assert_eq!(monitor.progress(), 50);

        monitor.set_maximum(100);
        assert_eq!(monitor.maximum(), 100);
    }

    #[test]
    fn test_joint_monitor_cancel() {
        let monitor = JointTaskMonitor::new();
        monitor.cancel();
        assert!(monitor.is_cancelled());
        assert!(monitor.check_cancelled().is_err());

        monitor.clear_cancelled();
        assert!(!monitor.is_cancelled());
        assert!(monitor.check_cancelled().is_ok());
    }

    #[test]
    fn test_joint_monitor_initialize() {
        let monitor = JointTaskMonitor::new();
        monitor.set_progress(50);
        monitor.initialize(200);
        assert_eq!(monitor.progress(), 0);
        assert_eq!(monitor.maximum(), 200);
    }

    #[test]
    fn test_joint_monitor_increment() {
        let monitor = JointTaskMonitor::new();
        monitor.initialize(100);
        monitor.increment_progress(25);
        assert_eq!(monitor.progress(), 25);
        monitor.increment_progress(25);
        assert_eq!(monitor.progress(), 50);
    }

    #[test]
    fn test_worker_state_transitions() {
        let (worker, _) = TestWorker::new("Test", true);
        let cmd = AnalysisWorkerCommand::new(Box::new(worker), true, true);

        assert_eq!(cmd.state(), WorkerState::Queued);
        cmd.execute(None);
        assert_eq!(cmd.state(), WorkerState::Completed);
    }

    #[test]
    fn test_worker_command_duration() {
        let (worker, _) = TestWorker::new("Test", true);
        let cmd = AnalysisWorkerCommand::new(Box::new(worker), true, true);

        assert!(cmd.duration_ms().is_none());
        cmd.execute(None);
        assert!(cmd.duration_ms().is_some());
    }
}
