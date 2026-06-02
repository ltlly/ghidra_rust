//! Task monitoring and asynchronous work execution.
//!
//! Provides [`TaskMonitor`] for cooperative cancellation, [`ProgressMonitor`] for
//! elapsed-time tracking, and [`Worker`] for sequential job processing.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

// ---------------------------------------------------------------------------
// TaskMonitor
// ---------------------------------------------------------------------------

/// A cancellable task monitor for long-running operations.
///
/// Call [`is_cancelled`](TaskMonitor::is_cancelled) periodically to support
/// cooperative cancellation. Thread-safe and cheaply cloneable.
#[derive(Debug, Clone)]
pub struct TaskMonitor {
    cancelled: Arc<AtomicBool>,
    message: Arc<Mutex<String>>,
    progress: Arc<Mutex<i64>>,
    maximum: Arc<Mutex<i64>>,
    indeterminate: Arc<AtomicBool>,
    cancel_enabled: Arc<AtomicBool>,
}

impl Default for TaskMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskMonitor {
    /// Create an uncancelled monitor with no work units.
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            message: Arc::new(Mutex::new(String::new())),
            progress: Arc::new(Mutex::new(0)),
            maximum: Arc::new(Mutex::new(0)),
            indeterminate: Arc::new(AtomicBool::new(true)),
            cancel_enabled: Arc::new(AtomicBool::new(true)),
        }
    }

    /// A dummy monitor that ignores all updates (never cancels).
    pub fn dummy() -> Self {
        Self::new()
    }

    /// Returns `true` when cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    /// Request cancellation.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    /// Reset the cancellation flag.
    pub fn clear_cancelled(&self) {
        self.cancelled.store(false, Ordering::Relaxed);
    }

    /// Check cancellation and return an error if cancelled.
    pub fn check_cancelled(&self) -> Result<(), CancelledError> {
        if self.is_cancelled() {
            Err(CancelledError)
        } else {
            Ok(())
        }
    }

    /// Set a status message.
    pub fn set_message(&self, msg: impl Into<String>) {
        if let Ok(mut m) = self.message.lock() {
            *m = msg.into();
        }
    }

    /// Get the current status message.
    pub fn get_message(&self) -> String {
        self.message
            .lock()
            .map(|m| m.clone())
            .unwrap_or_default()
    }

    /// Initialize progress with a maximum value.
    pub fn initialize(&self, max: i64) {
        if let Ok(mut m) = self.maximum.lock() {
            *m = max;
        }
        if let Ok(mut p) = self.progress.lock() {
            *p = 0;
        }
        self.indeterminate.store(max <= 0, Ordering::Relaxed);
    }

    /// Set the current progress value.
    pub fn set_progress(&self, value: i64) {
        if let Ok(mut p) = self.progress.lock() {
            *p = value;
        }
    }

    /// Increment progress by `delta`.
    pub fn increment_progress(&self, delta: i64) {
        if let Ok(mut p) = self.progress.lock() {
            *p += delta;
        }
    }

    /// Increment progress by 1.
    pub fn increment(&self) {
        self.increment_progress(1);
    }

    /// Get current progress.
    pub fn get_progress(&self) -> i64 {
        self.progress.lock().map(|p| *p).unwrap_or(0)
    }

    /// Get the maximum progress value.
    pub fn get_maximum(&self) -> i64 {
        self.maximum.lock().map(|m| *m).unwrap_or(0)
    }

    /// Set the maximum progress value.
    pub fn set_maximum(&self, max: i64) {
        if let Ok(mut m) = self.maximum.lock() {
            *m = max;
        }
        if let Ok(p) = self.progress.lock() {
            if *p > max {
                drop(p);
                if let Ok(mut p) = self.progress.lock() {
                    *p = max;
                }
            }
        }
    }

    /// Returns `true` when progress is indeterminate.
    pub fn is_indeterminate(&self) -> bool {
        self.indeterminate.load(Ordering::Relaxed)
    }

    /// Set whether this monitor is indeterminate.
    pub fn set_indeterminate(&self, value: bool) {
        self.indeterminate.store(value, Ordering::Relaxed);
    }

    /// Set whether the cancel button is enabled.
    pub fn set_cancel_enabled(&self, enable: bool) {
        self.cancel_enabled.store(enable, Ordering::Relaxed);
    }

    /// Returns true if cancel ability is enabled.
    pub fn is_cancel_enabled(&self) -> bool {
        self.cancel_enabled.load(Ordering::Relaxed)
    }

    /// No progress value indicator (matches Java's NO_PROGRESS_VALUE = -1).
    pub const NO_PROGRESS_VALUE: i64 = -1;

    /// Returns the given task monitor if it is not None. Otherwise, returns a DUMMY monitor.
    pub fn dummy_if_null(tm: Option<&TaskMonitor>) -> TaskMonitor {
        match tm {
            Some(m) => m.clone(),
            None => TaskMonitor::dummy(),
        }
    }
}

// ---------------------------------------------------------------------------
// CancelledError
// ---------------------------------------------------------------------------

/// Error indicating that the user cancelled the current operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CancelledError;

impl std::fmt::Display for CancelledError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Operation cancelled")
    }
}

impl std::error::Error for CancelledError {}

// ---------------------------------------------------------------------------
// ProgressMonitor
// ---------------------------------------------------------------------------

/// A higher-level progress monitor with elapsed-time tracking.
#[derive(Debug, Clone)]
pub struct ProgressMonitor {
    task_monitor: TaskMonitor,
    start_time: Instant,
    completed: Arc<AtomicBool>,
}

impl Default for ProgressMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgressMonitor {
    /// Create a new progress monitor.
    pub fn new() -> Self {
        Self {
            task_monitor: TaskMonitor::new(),
            start_time: Instant::now(),
            completed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Create from an existing TaskMonitor.
    pub fn from_task_monitor(tm: TaskMonitor) -> Self {
        Self {
            task_monitor: tm,
            start_time: Instant::now(),
            completed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Returns `true` when the task has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.task_monitor.is_cancelled()
    }

    /// Request cancellation.
    pub fn cancel(&self) {
        self.task_monitor.cancel();
    }

    /// Mark the monitored work as done.
    pub fn done(&self) {
        self.completed.store(true, Ordering::Relaxed);
    }

    /// Returns `true` when done() has been called.
    pub fn is_done(&self) -> bool {
        self.completed.load(Ordering::Relaxed)
    }

    /// Elapsed time since this monitor was created.
    pub fn elapsed(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    /// Returns the underlying TaskMonitor.
    pub fn task_monitor(&self) -> &TaskMonitor {
        &self.task_monitor
    }

    /// Initialize work units.
    pub fn initialize(&self, max: i64) {
        self.task_monitor.initialize(max);
    }

    /// Set a status message.
    pub fn set_message(&self, msg: impl Into<String>) {
        self.task_monitor.set_message(msg);
    }

    /// Set current progress.
    pub fn set_progress(&self, value: i64) {
        self.task_monitor.set_progress(value);
    }

    /// Check cancellation.
    pub fn check_cancelled(&self) -> Result<(), CancelledError> {
        self.task_monitor.check_cancelled()
    }

    /// Increment progress and check for cancellation.
    pub fn increment_progress(&self, delta: i64) -> Result<(), CancelledError> {
        self.check_cancelled()?;
        self.task_monitor.increment_progress(delta);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CancelledListener
// ---------------------------------------------------------------------------

/// Callback trait for cancellation notification.
pub trait CancelledListener: Send + Sync {
    /// Called when a task is cancelled.
    fn cancelled(&self);
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

/// A job that can be executed by a [`Worker`].
pub trait Job: Send + 'static {
    /// Execute the job. Called from the worker thread.
    fn run(&self, monitor: &TaskMonitor);
}

/// Executes jobs sequentially in FIFO order on a background thread.
///
/// Corresponds to Ghidra's `Worker` class.
pub struct Worker {
    name: String,
    sender: Arc<std::sync::mpsc::Sender<Box<dyn Job>>>,
    handle: Option<std::thread::JoinHandle<()>>,
    monitor: TaskMonitor,
    shutdown: Arc<AtomicBool>,
}

impl Worker {
    /// Create a new Worker that runs jobs on its own persistent thread.
    pub fn new(name: impl Into<String>) -> Self {
        let name: String = name.into();
        let (sender, receiver) = std::sync::mpsc::channel::<Box<dyn Job>>();
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();
        let monitor = TaskMonitor::new();
        let worker_monitor = monitor.clone();
        let worker_name = name.clone();

        let handle = std::thread::Builder::new()
            .name(worker_name)
            .spawn(move || {
                while !shutdown_clone.load(Ordering::Relaxed) {
                    match receiver.recv() {
                        Ok(job) => {
                            if !worker_monitor.is_cancelled() {
                                job.run(&worker_monitor);
                            }
                        }
                        Err(_) => break,
                    }
                }
                // Drain remaining jobs
                while let Ok(job) = receiver.try_recv() {
                    job.run(&worker_monitor);
                }
            })
            .ok();

        Self {
            name,
            sender: Arc::new(sender),
            handle,
            monitor,
            shutdown,
        }
    }

    /// Create a new Worker with a shared task monitor.
    pub fn with_monitor(name: impl Into<String>, monitor: TaskMonitor) -> Self {
        let mut worker = Self::new(name);
        worker.monitor = monitor;
        worker
    }

    /// Schedule a job. Returns false if the worker has been shut down.
    pub fn schedule(&self, job: impl Job) -> bool {
        self.sender.send(Box::new(job)).is_ok()
    }

    /// Returns the worker's TaskMonitor.
    pub fn monitor(&self) -> &TaskMonitor {
        &self.monitor
    }

    /// Returns the worker's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Shut down the worker. Blocks until the worker thread finishes.
    pub fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        drop(self.sender.clone());
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        // sender is dropped, thread will exit
    }
}

// ---------------------------------------------------------------------------
// Job implementations for closures
// ---------------------------------------------------------------------------

/// A job backed by a closure.
pub struct FnJob<F: FnOnce(&TaskMonitor) + Send + 'static> {
    name: String,
    f: Mutex<Option<F>>,
}

impl<F: FnOnce(&TaskMonitor) + Send + 'static> FnJob<F> {
    pub fn new(name: impl Into<String>, f: F) -> Self {
        Self {
            name: name.into(),
            f: Mutex::new(Some(f)),
        }
    }
}

impl<F: FnOnce(&TaskMonitor) + Send + 'static> Job for FnJob<F> {
    fn run(&self, monitor: &TaskMonitor) {
        if let Ok(mut guard) = self.f.lock() {
            if let Some(f) = guard.take() {
                f(monitor);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_task_monitor_cancel() {
        let tm = TaskMonitor::new();
        assert!(!tm.is_cancelled());
        tm.cancel();
        assert!(tm.is_cancelled());
        assert!(tm.check_cancelled().is_err());
        tm.clear_cancelled();
        assert!(!tm.is_cancelled());
    }

    #[test]
    fn test_progress_monitor() {
        let pm = ProgressMonitor::new();
        pm.initialize(100);
        assert!(!pm.is_done());
        pm.set_progress(50);
        pm.done();
        assert!(pm.is_done());
    }

    #[test]
    fn test_worker_basic() {
        use std::sync::atomic::AtomicBool;
        let ran = Arc::new(AtomicBool::new(false));
        let ran_clone = ran.clone();

        let mut worker = Worker::new("test-worker");
        worker.schedule(FnJob::new("test", move |_monitor| {
            ran_clone.store(true, Ordering::Relaxed);
        }));
        std::thread::sleep(std::time::Duration::from_millis(100));
        worker.shutdown();
        assert!(ran.load(Ordering::Relaxed));
    }
}
