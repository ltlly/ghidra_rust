//! Async update manager utilities.
//!
//! Ports Ghidra's `ghidra.util.task.AbstractSwingUpdateManager`,
//! `SwingUpdateManager`, `BufferedSwingRunner`, and `SwingRunnable`.
//!
//! In Ghidra's Java implementation, these classes manage coalescing multiple
//! rapid update requests into a single deferred execution. The Rust port
//! provides the same concept using async/timer-based scheduling rather than
//! Swing's event dispatch thread.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

// ============================================================================
// UpdateManager
// ============================================================================

/// A coalescing update manager that defers work until a quiet period.
///
/// Port of Ghidra's `AbstractSwingUpdateManager` and `SwingUpdateManager`.
///
/// When multiple updates are requested in rapid succession, the manager waits
/// until no new updates arrive for a configurable delay period before executing
/// the work. This prevents excessive recomputation during rapid UI interactions
/// like scrolling or typing.
///
/// # Usage
///
/// ```rust
/// use ghidra_gui::util::swing_update_manager::UpdateManager;
/// use std::sync::atomic::{AtomicUsize, Ordering};
/// use std::sync::Arc;
/// use std::time::Duration;
///
/// let counter = Arc::new(AtomicUsize::new(0));
/// let c = counter.clone();
/// let mut manager = UpdateManager::new(Duration::from_millis(100), move || {
///     c.fetch_add(1, Ordering::Relaxed);
/// });
///
/// // Multiple rapid updates are coalesced into a single execution.
/// manager.update();
/// manager.update();
/// manager.update();
/// assert_eq!(counter.load(Ordering::Relaxed), 0); // Not yet executed
/// ```
pub struct UpdateManager {
    /// The delay before executing pending work.
    delay: Duration,
    /// The work function to execute.
    work: Box<dyn FnMut() + Send>,
    /// Timestamp of the last update request.
    last_request: Option<Instant>,
    /// Whether work is pending.
    pending: bool,
    /// Whether the manager is enabled.
    enabled: bool,
    /// Maximum number of pending updates to coalesce (0 = unlimited).
    max_pending: usize,
    /// Number of updates received since last execution.
    update_count: usize,
}

impl std::fmt::Debug for UpdateManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateManager")
            .field("delay", &self.delay)
            .field("pending", &self.pending)
            .field("enabled", &self.enabled)
            .field("update_count", &self.update_count)
            .finish()
    }
}

impl UpdateManager {
    /// Create a new update manager with the given delay and work function.
    pub fn new(delay: Duration, work: impl FnMut() + Send + 'static) -> Self {
        Self {
            delay,
            work: Box::new(work),
            last_request: None,
            pending: false,
            enabled: true,
            max_pending: 0,
            update_count: 0,
        }
    }

    /// Create an update manager with a delay in milliseconds.
    pub fn with_delay_ms(delay_ms: u64, work: impl FnMut() + Send + 'static) -> Self {
        Self::new(Duration::from_millis(delay_ms), work)
    }

    /// Request an update. If the manager is enabled, this schedules the work
    /// function to run after the delay period (coalescing multiple requests).
    pub fn update(&mut self) {
        if !self.enabled {
            return;
        }
        self.last_request = Some(Instant::now());
        self.pending = true;
        self.update_count += 1;
    }

    /// Check if the scheduled work should run now (delay has elapsed since last request).
    pub fn should_execute(&self) -> bool {
        if !self.pending || !self.enabled {
            return false;
        }
        match self.last_request {
            Some(last) => last.elapsed() >= self.delay,
            None => false,
        }
    }

    /// Execute the pending work if the delay has elapsed.
    ///
    /// Returns `true` if work was executed, `false` otherwise.
    pub fn try_execute(&mut self) -> bool {
        if self.should_execute() {
            self.execute();
            true
        } else {
            false
        }
    }

    /// Force execution of the pending work immediately, regardless of the delay.
    pub fn execute_now(&mut self) {
        if self.pending {
            self.execute();
        }
    }

    /// Internal: execute the work function and reset state.
    fn execute(&mut self) {
        (self.work)();
        self.pending = false;
        self.last_request = None;
        self.update_count = 0;
    }

    /// Cancel any pending work.
    pub fn cancel(&mut self) {
        self.pending = false;
        self.last_request = None;
        self.update_count = 0;
    }

    /// Whether there is pending work.
    pub fn is_pending(&self) -> bool {
        self.pending
    }

    /// Enable or disable the manager.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            self.cancel();
        }
    }

    /// Whether the manager is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get the delay duration.
    pub fn delay(&self) -> Duration {
        self.delay
    }

    /// Set the delay duration.
    pub fn set_delay(&mut self, delay: Duration) {
        self.delay = delay;
    }

    /// Get the number of updates received since last execution.
    pub fn update_count(&self) -> usize {
        self.update_count
    }

    /// Set the maximum number of pending updates before forcing execution.
    /// A value of 0 means no limit.
    pub fn set_max_pending(&mut self, max: usize) {
        self.max_pending = max;
    }

    /// Whether the max pending threshold has been reached.
    pub fn is_max_pending_reached(&self) -> bool {
        self.max_pending > 0 && self.update_count >= self.max_pending
    }
}

// ============================================================================
// BufferedRunner
// ============================================================================

/// A buffered runner that queues work items and executes them in batches.
///
/// Port of Ghidra's `BufferedSwingRunner`. Work items are accumulated and
/// executed together when the buffer is flushed, either manually or when the
/// buffer reaches capacity.
pub struct BufferedRunner<T: Send + 'static> {
    /// Buffered work items.
    buffer: VecDeque<T>,
    /// The batch handler function.
    handler: Box<dyn FnMut(&[T]) + Send>,
    /// Maximum buffer size before auto-flush (0 = no auto-flush).
    capacity: usize,
}

impl<T: Send + 'static + std::fmt::Debug> std::fmt::Debug for BufferedRunner<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufferedRunner")
            .field("buffer_len", &self.buffer.len())
            .field("capacity", &self.capacity)
            .finish()
    }
}

impl<T: Send + 'static> BufferedRunner<T> {
    /// Create a new buffered runner with the given handler and capacity.
    pub fn new(capacity: usize, handler: impl FnMut(&[T]) + Send + 'static) -> Self {
        Self {
            buffer: VecDeque::new(),
            handler: Box::new(handler),
            capacity,
        }
    }

    /// Add a work item to the buffer. If the buffer is at capacity,
    /// it is flushed automatically.
    pub fn submit(&mut self, item: T) {
        self.buffer.push_back(item);
        if self.capacity > 0 && self.buffer.len() >= self.capacity {
            self.flush();
        }
    }

    /// Flush all buffered items, executing the handler on them.
    pub fn flush(&mut self) {
        if !self.buffer.is_empty() {
            let owned: Vec<T> = self.buffer.drain(..).collect();
            (self.handler)(&owned);
        }
    }

    /// Get the current number of buffered items.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Clear the buffer without executing the handler.
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

// ============================================================================
// RunnableTask
// ============================================================================

/// A runnable task that can be scheduled for later execution.
///
/// Port of Ghidra's `SwingRunnable`. Represents a unit of work that can be
/// run, cancelled, or checked for completion status.
#[derive(Debug, Clone)]
pub struct RunnableTask {
    /// The task name (for debugging).
    pub name: String,
    /// Whether the task has been run.
    pub ran: bool,
    /// Whether the task was cancelled.
    pub cancelled: bool,
    /// The task priority (lower = higher priority).
    pub priority: u32,
    /// When the task was created.
    pub created_at: Instant,
}

impl RunnableTask {
    /// Create a new runnable task.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ran: false,
            cancelled: false,
            priority: 0,
            created_at: Instant::now(),
        }
    }

    /// Create a task with a specific priority.
    pub fn with_priority(name: impl Into<String>, priority: u32) -> Self {
        Self {
            name: name.into(),
            ran: false,
            cancelled: false,
            priority,
            created_at: Instant::now(),
        }
    }

    /// Mark the task as having been run.
    pub fn mark_ran(&mut self) {
        self.ran = true;
    }

    /// Cancel the task.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Whether the task is ready to run (not yet run and not cancelled).
    pub fn is_runnable(&self) -> bool {
        !self.ran && !self.cancelled
    }

    /// Get the age of the task.
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }
}

// ============================================================================
// TaskQueue
// ============================================================================

/// A priority queue of runnable tasks.
///
/// Manages a queue of tasks that can be executed in priority order.
#[derive(Debug)]
pub struct TaskQueue {
    /// Pending tasks sorted by priority.
    tasks: Vec<RunnableTask>,
}

impl TaskQueue {
    /// Create a new empty task queue.
    pub fn new() -> Self {
        Self { tasks: Vec::new() }
    }

    /// Add a task to the queue.
    pub fn push(&mut self, task: RunnableTask) {
        self.tasks.push(task);
        // Maintain priority order (lower priority value = higher priority)
        self.tasks.sort_by_key(|t| t.priority);
    }

    /// Get the next runnable task (without removing it).
    pub fn peek(&self) -> Option<&RunnableTask> {
        self.tasks.iter().find(|t| t.is_runnable())
    }

    /// Remove and return the highest-priority runnable task.
    pub fn pop(&mut self) -> Option<RunnableTask> {
        if let Some(pos) = self.tasks.iter().position(|t| t.is_runnable()) {
            Some(self.tasks.remove(pos))
        } else {
            None
        }
    }

    /// Get the number of tasks in the queue (including non-runnable).
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Check if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// Get the number of runnable tasks.
    pub fn runnable_count(&self) -> usize {
        self.tasks.iter().filter(|t| t.is_runnable()).count()
    }

    /// Cancel all tasks in the queue.
    pub fn cancel_all(&mut self) {
        for task in &mut self.tasks {
            task.cancel();
        }
    }

    /// Clear all tasks from the queue.
    pub fn clear(&mut self) {
        self.tasks.clear();
    }

    /// Remove tasks older than the given duration.
    pub fn remove_stale(&mut self, max_age: Duration) {
        self.tasks.retain(|t| t.age() < max_age || t.is_runnable());
    }
}

impl Default for TaskQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[test]
    fn update_manager_basic() {
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        let mut manager = UpdateManager::new(Duration::from_millis(50), move || {
            c.fetch_add(1, Ordering::Relaxed);
        });

        manager.update();
        assert!(manager.is_pending());
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn update_manager_coalesce() {
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        let mut manager = UpdateManager::new(Duration::from_millis(100), move || {
            c.fetch_add(1, Ordering::Relaxed);
        });

        manager.update();
        manager.update();
        manager.update();
        assert_eq!(manager.update_count(), 3);
        // Force execution
        manager.execute_now();
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        assert_eq!(manager.update_count(), 0);
    }

    #[test]
    fn update_manager_cancel() {
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        let mut manager = UpdateManager::new(Duration::from_millis(100), move || {
            c.fetch_add(1, Ordering::Relaxed);
        });

        manager.update();
        manager.cancel();
        assert!(!manager.is_pending());
        manager.execute_now();
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn update_manager_disable() {
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        let mut manager = UpdateManager::new(Duration::from_millis(100), move || {
            c.fetch_add(1, Ordering::Relaxed);
        });

        manager.set_enabled(false);
        manager.update(); // Should be ignored
        assert!(!manager.is_pending());
    }

    #[test]
    fn update_manager_delay_check() {
        let mut manager = UpdateManager::with_delay_ms(10, || {});
        manager.update();
        assert!(!manager.should_execute()); // Not enough time elapsed

        // After waiting, should be ready
        std::thread::sleep(Duration::from_millis(20));
        assert!(manager.should_execute());
    }

    #[test]
    fn update_manager_try_execute() {
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        let mut manager = UpdateManager::new(Duration::from_millis(10), move || {
            c.fetch_add(1, Ordering::Relaxed);
        });

        manager.update();
        assert!(!manager.try_execute()); // Too early

        std::thread::sleep(Duration::from_millis(20));
        assert!(manager.try_execute());
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn update_manager_max_pending() {
        let mut manager = UpdateManager::with_delay_ms(1000, || {});
        manager.set_max_pending(3);

        manager.update();
        assert!(!manager.is_max_pending_reached());
        manager.update();
        assert!(!manager.is_max_pending_reached());
        manager.update();
        assert!(manager.is_max_pending_reached());
    }

    #[test]
    fn update_manager_set_delay() {
        let mut manager = UpdateManager::with_delay_ms(100, || {});
        assert_eq!(manager.delay(), Duration::from_millis(100));
        manager.set_delay(Duration::from_millis(200));
        assert_eq!(manager.delay(), Duration::from_millis(200));
    }

    #[test]
    fn buffered_runner_basic() {
        let collected = Arc::new(Mutex::new(Vec::new()));
        let c = collected.clone();
        let mut runner = BufferedRunner::new(3, move |items: &[i32]| {
            let mut lock = c.lock().unwrap();
            lock.extend_from_slice(items);
        });

        runner.submit(1);
        runner.submit(2);
        assert_eq!(runner.len(), 2);
        assert!(!runner.is_empty());

        // Third item triggers auto-flush (capacity = 3)
        runner.submit(3);
        assert_eq!(runner.len(), 0); // Flushed

        let lock = collected.lock().unwrap();
        assert_eq!(*lock, vec![1, 2, 3]);
    }

    #[test]
    fn buffered_runner_manual_flush() {
        let collected = Arc::new(Mutex::new(Vec::new()));
        let c = collected.clone();
        let mut runner = BufferedRunner::new(10, move |items: &[String]| {
            let mut lock = c.lock().unwrap();
            lock.extend_from_slice(items);
        });

        runner.submit("a".to_string());
        runner.submit("b".to_string());
        assert_eq!(runner.len(), 2);

        runner.flush();
        assert_eq!(runner.len(), 0);

        let lock = collected.lock().unwrap();
        assert_eq!(*lock, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn buffered_runner_clear() {
        let mut runner = BufferedRunner::new(10, |_: &[i32]| {});
        runner.submit(1);
        runner.submit(2);
        runner.clear();
        assert!(runner.is_empty());
    }

    #[test]
    fn runnable_task_basics() {
        let mut task = RunnableTask::new("test task");
        assert_eq!(task.name, "test task");
        assert!(task.is_runnable());
        assert!(!task.ran);
        assert!(!task.cancelled);

        task.mark_ran();
        assert!(!task.is_runnable());
    }

    #[test]
    fn runnable_task_cancel() {
        let mut task = RunnableTask::new("cancel me");
        assert!(task.is_runnable());

        task.cancel();
        assert!(!task.is_runnable());
        assert!(task.cancelled);
    }

    #[test]
    fn runnable_task_priority() {
        let low = RunnableTask::with_priority("low", 10);
        let high = RunnableTask::with_priority("high", 1);
        assert_eq!(low.priority, 10);
        assert_eq!(high.priority, 1);
    }

    #[test]
    fn runnable_task_age() {
        let task = RunnableTask::new("aged");
        // Task should have a non-zero age (very small)
        let age = task.age();
        assert!(age < Duration::from_secs(1));
    }

    #[test]
    fn task_queue_push_and_pop() {
        let mut queue = TaskQueue::new();
        assert!(queue.is_empty());

        queue.push(RunnableTask::with_priority("low", 10));
        queue.push(RunnableTask::with_priority("high", 1));
        queue.push(RunnableTask::with_priority("mid", 5));

        assert_eq!(queue.len(), 3);
        assert_eq!(queue.runnable_count(), 3);

        // Should pop highest priority (lowest number) first
        let task = queue.pop().unwrap();
        assert_eq!(task.name, "high");

        let task = queue.pop().unwrap();
        assert_eq!(task.name, "mid");

        let task = queue.pop().unwrap();
        assert_eq!(task.name, "low");

        assert!(queue.pop().is_none());
    }

    #[test]
    fn task_queue_cancel_all() {
        let mut queue = TaskQueue::new();
        queue.push(RunnableTask::new("a"));
        queue.push(RunnableTask::new("b"));

        queue.cancel_all();
        assert_eq!(queue.runnable_count(), 0);
        assert_eq!(queue.len(), 2); // Still in queue, just not runnable
    }

    #[test]
    fn task_queue_peek() {
        let mut queue = TaskQueue::new();
        assert!(queue.peek().is_none());

        queue.push(RunnableTask::with_priority("task", 5));
        let peeked = queue.peek().unwrap();
        assert_eq!(peeked.name, "task");
    }

    #[test]
    fn task_queue_default() {
        let queue = TaskQueue::default();
        assert!(queue.is_empty());
    }
}
