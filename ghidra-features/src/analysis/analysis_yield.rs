//! Analysis yield mechanism.
//!
//! Ported from `AutoAnalysisManager.yield()` and `waitForAnalysis()`.
//!
//! Provides the mechanism for analysis tasks to yield to higher-priority
//! tasks. When an analyzer needs to wait for dependent analyses to complete
//! before continuing, it can yield control back to the analysis manager,
//! which will run any higher-priority pending tasks before resuming the
//! yielding task.

use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Condvar, Mutex};

// ---------------------------------------------------------------------------
// YieldState
// ---------------------------------------------------------------------------

/// State of a yielded analysis task.
#[derive(Debug, Clone)]
pub struct YieldedTask {
    /// Name of the task that yielded.
    pub task_name: String,
    /// Priority of the yielding task.
    pub priority: i32,
    /// The priority limit -- tasks with priority < limit will run before resume.
    pub limit_priority: Option<i32>,
    /// Timestamp when the task yielded.
    pub yield_time: u64,
    /// Accumulated execution time before yielding.
    pub accumulated_time_ms: u64,
}

// ---------------------------------------------------------------------------
// YieldManager
// ---------------------------------------------------------------------------

/// Manages the yield stack for analysis tasks.
///
/// Ported from the yield mechanism in `AutoAnalysisManager`. When an
/// analysis task yields, it pushes itself onto the yield stack and allows
/// the analysis manager to run higher-priority tasks. When those tasks
/// complete, the yielded task is resumed.
///
/// The yield stack supports nested yields (a yielded task can itself yield),
/// but care must be taken to avoid infinite recursion.
///
/// # Priority Semantics
///
/// - Lower numeric priority value = higher priority (runs first)
/// - When a task with priority P yields with limit L, all tasks with
///   priority < L will run before the task resumes
/// - A limit_priority of `None` means yield to ALL pending tasks
/// - A limit_priority of `Some(0)` has special meaning: yield to all
///   pending analysis (used by scripts running in the analysis thread)
#[derive(Debug)]
pub struct YieldManager {
    /// Stack of yielded tasks (last yielded = top of stack).
    yield_stack: Vec<YieldedTask>,
    /// Maximum allowed yield depth.
    max_depth: usize,
    /// Whether a yield is currently in progress.
    yielding: bool,
}

impl YieldManager {
    /// Create a new yield manager.
    pub fn new() -> Self {
        Self {
            yield_stack: Vec::new(),
            max_depth: 10,
            yielding: false,
        }
    }

    /// Create a yield manager with a custom max depth.
    pub fn with_max_depth(max_depth: usize) -> Self {
        Self {
            yield_stack: Vec::new(),
            max_depth,
            yielding: false,
        }
    }

    /// Push a task onto the yield stack.
    ///
    /// # Errors
    /// Returns an error if the yield stack has reached its maximum depth.
    pub fn push_yield(
        &mut self,
        task_name: impl Into<String>,
        priority: i32,
        limit_priority: Option<i32>,
        accumulated_time_ms: u64,
    ) -> Result<(), YieldError> {
        if self.yield_stack.len() >= self.max_depth {
            return Err(YieldError::MaxDepthExceeded(self.max_depth));
        }

        self.yield_stack.push(YieldedTask {
            task_name: task_name.into(),
            priority,
            limit_priority,
            yield_time: 0,
            accumulated_time_ms,
        });
        self.yielding = true;
        Ok(())
    }

    /// Pop the most recently yielded task from the stack.
    pub fn pop_yield(&mut self) -> Option<YieldedTask> {
        let task = self.yield_stack.pop();
        self.yielding = !self.yield_stack.is_empty();
        task
    }

    /// Get the current yield depth (number of nested yields).
    pub fn depth(&self) -> usize {
        self.yield_stack.len()
    }

    /// Whether any task is currently yielded.
    pub fn is_yielding(&self) -> bool {
        self.yielding
    }

    /// Get the limit priority of the most recently yielded task.
    pub fn current_limit_priority(&self) -> Option<i32> {
        self.yield_stack.last().and_then(|t| t.limit_priority)
    }

    /// Get a reference to the yield stack.
    pub fn stack(&self) -> &[YieldedTask] {
        &self.yield_stack
    }

    /// Clear the yield stack.
    pub fn clear(&mut self) {
        self.yield_stack.clear();
        self.yielding = false;
    }

    /// Check if a task with the given priority should run given the
    /// current yield state.
    ///
    /// Returns `true` if the task should run (its priority is high enough
    /// relative to the current yield limit).
    pub fn should_run_task(&self, task_priority: i32) -> bool {
        match self.current_limit_priority() {
            Some(limit) => {
                if limit == 0 {
                    // Special case: yield to ALL pending analysis
                    true
                } else {
                    task_priority < limit
                }
            }
            None => true, // no yield active, all tasks can run
        }
    }

    /// Get the maximum allowed yield depth.
    pub fn max_depth(&self) -> usize {
        self.max_depth
    }

    /// Set the maximum allowed yield depth.
    pub fn set_max_depth(&mut self, max_depth: usize) {
        self.max_depth = max_depth;
    }
}

impl Default for YieldManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// YieldError
// ---------------------------------------------------------------------------

/// Errors that can occur during yield operations.
#[derive(Debug, Clone)]
pub enum YieldError {
    /// The yield stack has reached its maximum depth.
    MaxDepthExceeded(usize),
    /// Attempted to yield from a non-analysis thread.
    NotAnalysisThread,
}

impl fmt::Display for YieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MaxDepthExceeded(max) => {
                write!(f, "Yield depth exceeded maximum of {}", max)
            }
            Self::NotAnalysisThread => {
                write!(f, "Cannot yield from a non-analysis thread")
            }
        }
    }
}

impl std::error::Error for YieldError {}

// ---------------------------------------------------------------------------
// YieldBarrier -- synchronization for yield/resume
// ---------------------------------------------------------------------------

/// Synchronization primitive for coordinating yield and resume operations.
///
/// Allows a thread to wait for the analysis manager to complete processing
/// of higher-priority tasks before resuming the yielded task.
#[derive(Clone)]
pub struct YieldBarrier {
    state: Arc<(Mutex<YieldBarrierState>, Condvar)>,
}

#[derive(Debug)]
struct YieldBarrierState {
    /// Whether the barrier has been released.
    released: bool,
    /// Whether the wait was cancelled.
    cancelled: bool,
}

impl YieldBarrier {
    /// Create a new yield barrier.
    pub fn new() -> Self {
        Self {
            state: Arc::new((
                Mutex::new(YieldBarrierState {
                    released: false,
                    cancelled: false,
                }),
                Condvar::new(),
            )),
        }
    }

    /// Wait for the barrier to be released.
    ///
    /// Blocks until `release()` is called or the wait is cancelled.
    pub fn wait(&self) -> Result<(), YieldBarrierCancelled> {
        let (lock, cvar) = &*self.state;
        let mut state = lock.lock().unwrap();
        while !state.released && !state.cancelled {
            state = cvar.wait(state).unwrap();
        }
        if state.cancelled {
            Err(YieldBarrierCancelled)
        } else {
            Ok(())
        }
    }

    /// Wait with a timeout.
    pub fn wait_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> Result<YieldBarrierStatus, YieldBarrierCancelled> {
        let (lock, cvar) = &*self.state;
        let state = lock.lock().unwrap();
        if state.released {
            return Ok(YieldBarrierStatus::Released);
        }
        if state.cancelled {
            return Err(YieldBarrierCancelled);
        }

        let (state, timeout_result) = cvar.wait_timeout(state, timeout).unwrap();
        if state.cancelled {
            Err(YieldBarrierCancelled)
        } else if state.released {
            Ok(YieldBarrierStatus::Released)
        } else if timeout_result.timed_out() {
            Ok(YieldBarrierStatus::TimedOut)
        } else {
            Ok(YieldBarrierStatus::Released)
        }
    }

    /// Release the barrier, allowing waiting threads to proceed.
    pub fn release(&self) {
        let (lock, cvar) = &*self.state;
        let mut state = lock.lock().unwrap();
        state.released = true;
        cvar.notify_all();
    }

    /// Cancel the barrier, causing waiting threads to receive an error.
    pub fn cancel(&self) {
        let (lock, cvar) = &*self.state;
        let mut state = lock.lock().unwrap();
        state.cancelled = true;
        cvar.notify_all();
    }

    /// Reset the barrier for reuse.
    pub fn reset(&self) {
        let (lock, _) = &*self.state;
        let mut state = lock.lock().unwrap();
        state.released = false;
        state.cancelled = false;
    }
}

impl Default for YieldBarrier {
    fn default() -> Self {
        Self::new()
    }
}

/// Status returned by `wait_timeout`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum YieldBarrierStatus {
    /// The barrier was released.
    Released,
    /// The wait timed out.
    TimedOut,
}

/// Error indicating the yield barrier was cancelled.
#[derive(Debug, Clone)]
pub struct YieldBarrierCancelled;

impl fmt::Display for YieldBarrierCancelled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Yield barrier was cancelled")
    }
}

impl std::error::Error for YieldBarrierCancelled {}

// ---------------------------------------------------------------------------
// WaitForAnalysis -- blocking wait for analysis to complete
// ---------------------------------------------------------------------------

/// Result of a wait-for-analysis operation.
#[derive(Debug, Clone)]
pub struct WaitForAnalysisResult {
    /// Whether analysis completed normally.
    pub completed: bool,
    /// Whether the wait was cancelled.
    pub cancelled: bool,
    /// Whether the wait timed out.
    pub timed_out: bool,
    /// Total time waited in milliseconds.
    pub wait_time_ms: u64,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_yield_manager_basic() {
        let mut mgr = YieldManager::new();
        assert!(!mgr.is_yielding());
        assert_eq!(mgr.depth(), 0);

        mgr.push_yield("task1", 50, Some(100), 1000).unwrap();
        assert!(mgr.is_yielding());
        assert_eq!(mgr.depth(), 1);

        let task = mgr.pop_yield().unwrap();
        assert_eq!(task.task_name, "task1");
        assert!(!mgr.is_yielding());
    }

    #[test]
    fn test_yield_manager_nested() {
        let mut mgr = YieldManager::new();
        mgr.push_yield("task1", 50, Some(100), 1000).unwrap();
        mgr.push_yield("task2", 60, Some(80), 500).unwrap();

        assert_eq!(mgr.depth(), 2);

        mgr.pop_yield();
        assert_eq!(mgr.depth(), 1);

        mgr.pop_yield();
        assert_eq!(mgr.depth(), 0);
    }

    #[test]
    fn test_yield_manager_max_depth() {
        let mut mgr = YieldManager::with_max_depth(2);
        mgr.push_yield("task1", 50, None, 0).unwrap();
        mgr.push_yield("task2", 60, None, 0).unwrap();

        let result = mgr.push_yield("task3", 70, None, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_yield_manager_should_run() {
        let mut mgr = YieldManager::new();

        // No yield active: all tasks should run
        assert!(mgr.should_run_task(100));
        assert!(mgr.should_run_task(0));

        // Yield with limit 50: only tasks with priority < 50 should run
        mgr.push_yield("task", 100, Some(50), 0).unwrap();
        assert!(mgr.should_run_task(49));
        assert!(mgr.should_run_task(0));
        assert!(!mgr.should_run_task(50));
        assert!(!mgr.should_run_task(100));
    }

    #[test]
    fn test_yield_manager_special_zero_limit() {
        let mut mgr = YieldManager::new();
        mgr.push_yield("task", 100, Some(0), 0).unwrap();

        // Special case: limit 0 means yield to ALL
        assert!(mgr.should_run_task(0));
        assert!(mgr.should_run_task(100));
        assert!(mgr.should_run_task(1000));
    }

    #[test]
    fn test_yield_manager_none_limit() {
        let mut mgr = YieldManager::new();
        mgr.push_yield("task", 100, None, 0).unwrap();

        // None limit means yield to all
        assert!(mgr.should_run_task(0));
        assert!(mgr.should_run_task(100));
    }

    #[test]
    fn test_yield_manager_current_limit_priority() {
        let mut mgr = YieldManager::new();
        assert!(mgr.current_limit_priority().is_none());

        mgr.push_yield("task", 50, Some(100), 0).unwrap();
        assert_eq!(mgr.current_limit_priority(), Some(100));
    }

    #[test]
    fn test_yield_manager_clear() {
        let mut mgr = YieldManager::new();
        mgr.push_yield("task1", 50, None, 0).unwrap();
        mgr.push_yield("task2", 60, None, 0).unwrap();

        mgr.clear();
        assert!(!mgr.is_yielding());
        assert_eq!(mgr.depth(), 0);
    }

    #[test]
    fn test_yield_barrier_basic() {
        let barrier = YieldBarrier::new();
        barrier.release();
        assert!(barrier.wait().is_ok());
    }

    #[test]
    fn test_yield_barrier_wait_and_release() {
        let barrier = YieldBarrier::new();
        let barrier_clone = barrier.clone();

        let handle = thread::spawn(move || {
            // Small delay then release
            thread::sleep(std::time::Duration::from_millis(50));
            barrier_clone.release();
        });

        assert!(barrier.wait().is_ok());
        handle.join().unwrap();
    }

    #[test]
    fn test_yield_barrier_cancel() {
        let barrier = YieldBarrier::new();
        let barrier_clone = barrier.clone();

        let handle = thread::spawn(move || {
            thread::sleep(std::time::Duration::from_millis(50));
            barrier_clone.cancel();
        });

        assert!(barrier.wait().is_err());
        handle.join().unwrap();
    }

    #[test]
    fn test_yield_barrier_timeout() {
        let barrier = YieldBarrier::new();
        let result = barrier.wait_timeout(std::time::Duration::from_millis(10));
        assert_eq!(result.unwrap(), YieldBarrierStatus::TimedOut);
    }

    #[test]
    fn test_yield_barrier_timeout_released() {
        let barrier = YieldBarrier::new();
        barrier.release();
        let result = barrier.wait_timeout(std::time::Duration::from_secs(1));
        assert_eq!(result.unwrap(), YieldBarrierStatus::Released);
    }

    #[test]
    fn test_yield_barrier_reset() {
        let barrier = YieldBarrier::new();
        barrier.release();
        assert!(barrier.wait().is_ok());

        barrier.reset();
        // Now should time out
        let result = barrier.wait_timeout(std::time::Duration::from_millis(10));
        assert_eq!(result.unwrap(), YieldBarrierStatus::TimedOut);

        barrier.release();
        assert!(barrier.wait().is_ok());
    }

    #[test]
    fn test_yield_error_display() {
        let err = YieldError::MaxDepthExceeded(10);
        assert!(err.to_string().contains("10"));

        let err = YieldError::NotAnalysisThread;
        assert!(err.to_string().contains("non-analysis thread"));
    }
}
