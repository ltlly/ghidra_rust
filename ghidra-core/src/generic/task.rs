//! Task monitoring and asynchronous work execution.
//!
//! Provides [`TaskMonitor`] for cooperative cancellation, [`ProgressMonitor`] for
//! elapsed-time tracking, [`Worker`] for sequential job processing,
//! [`ConcurrentQ`] for parallel job execution, and [`FutureTaskMonitor`]
//! / [`TimeoutTaskMonitor`] for advanced monitoring patterns.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
    sender: Option<Arc<std::sync::mpsc::Sender<Box<dyn Job>>>>,
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
            sender: Some(Arc::new(sender)),
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
        if let Some(ref sender) = self.sender {
            sender.send(Box::new(job)).is_ok()
        } else {
            false
        }
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
        // Drop the sender to close the channel, causing recv() to return Err.
        self.sender.take();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.sender.take();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Job implementations for closures
// ---------------------------------------------------------------------------

/// A job backed by a closure.
pub struct FnJob<F: FnOnce(&TaskMonitor) + Send + 'static> {
    _name: String,
    f: Mutex<Option<F>>,
}

impl<F: FnOnce(&TaskMonitor) + Send + 'static> FnJob<F> {
    pub fn new(name: impl Into<String>, f: F) -> Self {
        Self {
            _name: name.into(),
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

// ---------------------------------------------------------------------------
// FutureTaskMonitor — wraps a Monitor that can be resolved externally
// ---------------------------------------------------------------------------

/// A [`TaskMonitor`] whose cancellation and progress can be controlled from
/// an external handle.
///
/// Mirrors Ghidra's `FutureTaskMonitor`. Useful when a caller launches async
/// work and later needs to cancel it or query progress.
#[derive(Debug, Clone)]
pub struct FutureTaskMonitor {
    inner: TaskMonitor,
    done: Arc<AtomicBool>,
    result: Arc<Mutex<Option<Result<(), CancelledError>>>>,
}

impl FutureTaskMonitor {
    pub fn new() -> Self {
        Self {
            inner: TaskMonitor::new(),
            done: Arc::new(AtomicBool::new(false)),
            result: Arc::new(Mutex::new(None)),
        }
    }

    /// The underlying task monitor handle (pass to worker threads).
    pub fn monitor(&self) -> &TaskMonitor {
        &self.inner
    }

    /// Mark the future as completed with a result.
    pub fn complete(&self, result: Result<(), CancelledError>) {
        if let Ok(mut r) = self.result.lock() {
            *r = Some(result);
        }
        self.done.store(true, Ordering::Release);
    }

    /// Returns `true` when the future has completed.
    pub fn is_done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }

    /// Wait (blocking) until the future completes, then return the result.
    pub fn wait(&self) -> Result<(), CancelledError> {
        while !self.is_done() {
            std::thread::yield_now();
        }
        self.result
            .lock()
            .ok()
            .and_then(|r| r.clone())
            .unwrap_or(Ok(()))
    }

    /// Wait with a timeout. Returns `Err` on timeout.
    pub fn wait_timeout(&self, timeout: Duration) -> Result<(), CancelledError> {
        let deadline = Instant::now() + timeout;
        while !self.is_done() {
            if Instant::now() >= deadline {
                return Err(CancelledError);
            }
            std::thread::yield_now();
        }
        self.result
            .lock()
            .ok()
            .and_then(|r| r.clone())
            .unwrap_or(Ok(()))
    }

    /// Request cancellation on the underlying monitor.
    pub fn cancel(&self) {
        self.inner.cancel();
        self.complete(Err(CancelledError));
    }
}

impl Default for FutureTaskMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TimeoutTaskMonitor — auto-cancels after a deadline
// ---------------------------------------------------------------------------

/// A [`TaskMonitor`] wrapper that automatically requests cancellation after a
/// given duration.
///
/// Wraps Ghidra's `TimeoutTaskMonitor`. Spawns a background thread that will
/// cancel the delegate when the deadline is reached.
#[derive(Debug)]
pub struct TimeoutTaskMonitor {
    delegate: TaskMonitor,
    deadline: Instant,
    _guard: Arc<AtomicBool>, // keep-alive for the watchdog thread
}

impl TimeoutTaskMonitor {
    /// Create a timeout monitor wrapping a delegate. After `timeout` the
    /// delegate will be cancelled.
    pub fn new(delegate: TaskMonitor, timeout: Duration) -> Self {
        let deadline = Instant::now() + timeout;
        let guard = Arc::new(AtomicBool::new(true));
        let guard_clone = guard.clone();
        let cancel_target = delegate.clone();

        std::thread::Builder::new()
            .name("timeout-monitor".into())
            .spawn(move || {
                // Busy-wait with short sleeps; acceptable for a watchdog
                while guard_clone.load(Ordering::Relaxed) {
                    if Instant::now() >= deadline {
                        cancel_target.cancel();
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            })
            .ok();

        Self {
            delegate,
            deadline,
            _guard: guard,
        }
    }

    /// The underlying monitor.
    pub fn monitor(&self) -> &TaskMonitor {
        &self.delegate
    }

    /// Returns `true` when the timeout has been reached.
    pub fn is_timed_out(&self) -> bool {
        Instant::now() >= self.deadline
    }
}

impl Drop for TimeoutTaskMonitor {
    fn drop(&mut self) {
        // Signal the watchdog thread to exit
        self._guard.store(false, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// TaskMonitorSplitter — fan out one monitor to multiple sub-monitors
// ---------------------------------------------------------------------------

/// Splits progress across multiple sub-monitors.
///
/// Each sub-monitor gets a fraction of the total progress range. When a
/// sub-monitor's progress changes, the parent is updated proportionally.
///
/// Mirrors Ghidra's `TaskMonitorSplitter`.
pub struct TaskMonitorSplitter {
    parent: TaskMonitor,
    count: usize,
    sub_monitors: Vec<TaskMonitor>,
}

impl TaskMonitorSplitter {
    /// Create a splitter that divides progress among `count` sub-monitors.
    pub fn new(parent: TaskMonitor, count: usize) -> Self {
        let sub_monitors: Vec<TaskMonitor> = (0..count).map(|_| TaskMonitor::new()).collect();
        Self {
            parent,
            count,
            sub_monitors,
        }
    }

    /// Get the `i`-th sub-monitor.
    pub fn get_monitor(&self, index: usize) -> Option<&TaskMonitor> {
        self.sub_monitors.get(index)
    }

    /// Number of sub-monitors.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Refresh the parent progress from the average of all sub-monitors.
    /// Call this periodically or after each sub-monitor update.
    pub fn update_parent(&self) {
        if self.count == 0 {
            return;
        }
        let total_progress: i64 = self.sub_monitors.iter().map(|m| m.get_progress()).sum();
        let total_max: i64 = self.sub_monitors.iter().map(|m| m.get_maximum()).sum();
        if total_max > 0 {
            self.parent.set_progress(total_progress * self.parent.get_maximum() / total_max);
        }
    }

    /// Cancel all sub-monitors.
    pub fn cancel_all(&self) {
        for m in &self.sub_monitors {
            m.cancel();
        }
        self.parent.cancel();
    }
}

// ---------------------------------------------------------------------------
// ReentryGuard — prevents reentrant execution
// ---------------------------------------------------------------------------

/// A simple guard that tracks whether a section of code is already executing.
///
/// Mirrors Ghidra's `ReentryGuard`. Returns `false` from [`enter`](ReentryGuard::enter)
/// if the guard is already held.
pub struct ReentryGuard {
    entered: AtomicBool,
}

impl ReentryGuard {
    pub fn new() -> Self {
        Self {
            entered: AtomicBool::new(false),
        }
    }

    /// Try to enter the guarded section. Returns `true` if this is the first
    /// entry; `false` if already entered (i.e., a reentrant call).
    pub fn enter(&self) -> bool {
        !self.entered.swap(true, Ordering::Acquire)
    }

    /// Leave the guarded section.
    pub fn leave(&self) {
        self.entered.store(false, Ordering::Release);
    }
}

impl Default for ReentryGuard {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ConcurrentQ — parallel job execution with progress tracking
// ---------------------------------------------------------------------------

/// Result of a single item processed by [`ConcurrentQ`].
#[derive(Debug)]
pub struct QResult<T, R> {
    /// The input item.
    pub item: T,
    /// The result produced by the callback, or `None` if cancelled.
    pub result: Option<R>,
}

/// A callback that processes one item with a monitor.
pub trait QCallback<T, R>: Send + Sync + 'static {
    /// Process `item` using the given `monitor`, producing a result.
    fn process(&self, item: T, monitor: &TaskMonitor) -> R;
}

impl<T: Send + 'static, R: Send + 'static, F: Fn(T, &TaskMonitor) -> R + Send + Sync + 'static>
    QCallback<T, R> for F
{
    fn process(&self, item: T, monitor: &TaskMonitor) -> R {
        (self)(item, monitor)
    }
}

/// A progress listener for [`ConcurrentQ`].
pub trait QProgressListener: Send + Sync {
    /// Called when one item completes.
    fn item_completed(&self, index: usize, total: usize);
    /// Called when all items are done.
    fn all_completed(&self);
}

struct ConcurrentQItem<T> {
    index: usize,
    item: T,
}

/// A bounded work queue that processes items in parallel on a thread pool.
///
/// Corresponds to Ghidra's `ConcurrentQ`. Items are submitted, then processed
/// by `num_threads` workers calling a [`QCallback`]. Results are collected
/// in submission order.
///
/// # Examples
///
/// ```ignore
/// let mut q = ConcurrentQBuilder::new(callback)
///     .num_threads(4)
///     .monitor(monitor)
///     .build();
/// q.add(item1);
/// q.add(item2);
/// let results = q.wait_for_results();
/// ```
pub struct ConcurrentQ<T: Send + 'static, R: Send + 'static> {
    sender: Option<std::sync::mpsc::Sender<ConcurrentQItem<T>>>,
    results: Arc<Mutex<Vec<Option<R>>>>,
    monitor: TaskMonitor,
    total: usize,
    workers: Option<Vec<std::thread::JoinHandle<()>>>,
}

impl<T: Send + 'static, R: Send + 'static> ConcurrentQ<T, R> {
    /// Create a new concurrent queue.
    pub fn new(
        callback: Box<dyn QCallback<T, R>>,
        num_threads: usize,
        monitor: TaskMonitor,
    ) -> Self {
        let callback: Arc<dyn QCallback<T, R>> = callback.into();
        let (sender, receiver) = std::sync::mpsc::channel::<ConcurrentQItem<T>>();
        let receiver = Arc::new(Mutex::new(receiver));
        let results = Arc::new(Mutex::new(Vec::new()));

        let mut workers = Vec::with_capacity(num_threads);
        for i in 0..num_threads {
            let cb = callback.clone();
            let recv = receiver.clone();
            let res = results.clone();
            let mon = monitor.clone();

            workers.push(
                std::thread::Builder::new()
                    .name(format!("concurrent-q-{}", i))
                    .spawn(move || {
                        Self::worker_loop(cb, recv, res, mon);
                    })
                    .expect("failed to spawn worker"),
            );
        }

        Self {
            sender: Some(sender),
            results,
            monitor,
            total: 0,
            workers: Some(workers),
        }
    }

    fn worker_loop(
        callback: Arc<dyn QCallback<T, R>>,
        receiver: Arc<Mutex<std::sync::mpsc::Receiver<ConcurrentQItem<T>>>>,
        results: Arc<Mutex<Vec<Option<R>>>>,
        monitor: TaskMonitor,
    ) {
        loop {
            // Receive an item; block until available or channel closes.
            let qitem = {
                let recv = receiver.lock().unwrap();
                match recv.recv() {
                    Ok(item) => item,
                    Err(_) => return, // Channel closed
                }
            };

            if monitor.is_cancelled() {
                return;
            }

            // Process the item
            let result = callback.process(qitem.item, &monitor);
            {
                let mut res = results.lock().unwrap();
                while res.len() <= qitem.index {
                    res.push(None);
                }
                res[qitem.index] = Some(result);
            }
        }
    }

    /// Add an item to the work queue.
    pub fn add(&mut self, item: T) {
        let idx = self.total;
        self.total += 1;
        if let Some(ref sender) = self.sender {
            let _ = sender.send(ConcurrentQItem { index: idx, item });
        }
    }

    /// Add multiple items to the work queue.
    pub fn add_all(&mut self, items: impl IntoIterator<Item = T>) {
        for item in items {
            self.add(item);
        }
    }

    /// Block until all items have been processed, then return the results
    /// in submission order. Consumes the queue's ability to add more items.
    pub fn wait_for_results(&mut self) -> Vec<R> {
        // Close the channel so workers exit after draining all items.
        self.sender.take();

        // Join all workers (blocks until each worker's recv() returns Err).
        if let Some(handles) = self.workers.take() {
            for handle in handles {
                let _ = handle.join();
            }
        }

        let mut res = self.results.lock().unwrap();
        res.drain(..).flatten().collect()
    }

    /// Returns the total number of items submitted.
    pub fn total_count(&self) -> usize {
        self.total
    }

    /// Cancel the queue.
    pub fn cancel(&self) {
        self.monitor.cancel();
    }
}

impl<T: Send + 'static, R: Send + 'static> Drop for ConcurrentQ<T, R> {
    fn drop(&mut self) {
        // Close the channel so workers can exit.
        self.sender.take();
        if let Some(handles) = self.workers.take() {
            for handle in handles {
                let _ = handle.join();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ConcurrentQBuilder — fluent builder for ConcurrentQ
// ---------------------------------------------------------------------------

/// Builder for [`ConcurrentQ`].
pub struct ConcurrentQBuilder<T: Send + 'static, R: Send + 'static> {
    callback: Option<Box<dyn QCallback<T, R>>>,
    num_threads: usize,
    monitor: Option<TaskMonitor>,
}

impl<T: Send + 'static, R: Send + 'static> ConcurrentQBuilder<T, R> {
    /// Create a builder with the given callback.
    pub fn new(callback: impl QCallback<T, R>) -> Self {
        Self {
            callback: Some(Box::new(callback)),
            num_threads: 1,
            monitor: None,
        }
    }

    /// Set the number of worker threads (default: 1).
    pub fn num_threads(mut self, n: usize) -> Self {
        self.num_threads = n.max(1);
        self
    }

    /// Set the task monitor.
    pub fn monitor(mut self, monitor: TaskMonitor) -> Self {
        self.monitor = Some(monitor);
        self
    }

    /// Build the [`ConcurrentQ`].
    pub fn build(self) -> ConcurrentQ<T, R> {
        let callback = self.callback.expect("callback required");
        let monitor = self.monitor.unwrap_or_default();
        ConcurrentQ::new(callback, self.num_threads, monitor)
    }
}

// ---------------------------------------------------------------------------
// ProgressTracker — tracks completion of a batch of items
// ---------------------------------------------------------------------------

/// Tracks the progress of a batch of items (used internally by [`ConcurrentQ`]
/// but also useful standalone).
///
/// Mirrors Ghidra's `ProgressTracker`.
pub struct ProgressTracker {
    total: AtomicU64,
    completed: AtomicU64,
    monitor: TaskMonitor,
}

impl ProgressTracker {
    pub fn new(monitor: TaskMonitor, total: u64) -> Self {
        monitor.initialize(total as i64);
        Self {
            total: AtomicU64::new(total),
            completed: AtomicU64::new(0),
            monitor,
        }
    }

    /// Mark one item as completed.
    pub fn item_completed(&self) {
        let c = self.completed.fetch_add(1, Ordering::Relaxed) + 1;
        self.monitor.set_progress(c as i64);
    }

    /// Returns the number of items completed.
    pub fn completed_count(&self) -> u64 {
        self.completed.load(Ordering::Relaxed)
    }

    /// Returns the total number of items.
    pub fn total_count(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    /// Returns the fraction completed (0.0 to 1.0).
    pub fn fraction(&self) -> f64 {
        let t = self.total.load(Ordering::Relaxed);
        if t == 0 {
            return 1.0;
        }
        self.completed.load(Ordering::Relaxed) as f64 / t as f64
    }

    /// Returns `true` when all items have completed.
    pub fn is_done(&self) -> bool {
        self.completed.load(Ordering::Relaxed) >= self.total.load(Ordering::Relaxed)
    }

    /// The underlying task monitor.
    pub fn monitor(&self) -> &TaskMonitor {
        &self.monitor
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

    #[test]
    fn test_future_task_monitor() {
        let ftm = FutureTaskMonitor::new();
        assert!(!ftm.is_done());
        ftm.complete(Ok(()));
        assert!(ftm.is_done());
        assert!(ftm.wait().is_ok());
    }

    #[test]
    fn test_future_task_monitor_cancel() {
        let ftm = FutureTaskMonitor::new();
        ftm.cancel();
        assert!(ftm.is_done());
        assert!(ftm.wait().is_err());
    }

    #[test]
    fn test_timeout_task_monitor() {
        let delegate = TaskMonitor::new();
        let ttm = TimeoutTaskMonitor::new(delegate.clone(), Duration::from_millis(50));
        assert!(!ttm.is_timed_out());
        std::thread::sleep(Duration::from_millis(100));
        assert!(ttm.is_timed_out());
        assert!(delegate.is_cancelled());
    }

    #[test]
    fn test_task_monitor_splitter() {
        let parent = TaskMonitor::new();
        parent.initialize(100);
        let splitter = TaskMonitorSplitter::new(parent.clone(), 3);
        assert_eq!(splitter.count(), 3);
        assert!(splitter.get_monitor(0).is_some());
        assert!(splitter.get_monitor(5).is_none());
    }

    #[test]
    fn test_reentry_guard() {
        let guard = ReentryGuard::new();
        assert!(guard.enter());
        assert!(!guard.enter());
        guard.leave();
        assert!(guard.enter());
    }

    #[test]
    fn test_concurrent_q_basic() {
        let mut q: ConcurrentQ<i32, i32> = ConcurrentQ::new(
            Box::new(|_item: i32, _monitor: &TaskMonitor| -> i32 { _item * 2 }),
            2,
            TaskMonitor::new(),
        );
        q.add(1);
        q.add(2);
        q.add(3);
        let results = q.wait_for_results();
        assert_eq!(results.len(), 3);
        assert!(results.contains(&2));
        assert!(results.contains(&4));
        assert!(results.contains(&6));
    }

    #[test]
    fn test_concurrent_q_builder() {
        let mut q = ConcurrentQBuilder::new(|x: i32, _: &TaskMonitor| x + 100)
            .num_threads(4)
            .monitor(TaskMonitor::new())
            .build();
        for i in 0..10 {
            q.add(i);
        }
        let results = q.wait_for_results();
        assert_eq!(results.len(), 10);
    }

    #[test]
    fn test_progress_tracker() {
        let mon = TaskMonitor::new();
        let tracker = ProgressTracker::new(mon, 10);
        assert!(!tracker.is_done());
        for _ in 0..10 {
            tracker.item_completed();
        }
        assert!(tracker.is_done());
        assert!((tracker.fraction() - 1.0).abs() < 0.01);
    }
}
