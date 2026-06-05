//! Scheduler - a generator of an emulator's thread schedule.
//!
//! Ported from Ghidra's `Scheduler` interface.

use super::tick_step::TickStep;
use super::trace_schedule_full::TraceSchedule;

/// The result of running a machine according to a schedule.
///
/// Ported from Ghidra's `Scheduler.RunResult`.
#[derive(Debug, Clone)]
pub struct RunResult {
    /// The actual schedule executed.
    pub schedule: TraceSchedule,
    /// The error that interrupted execution, if any.
    pub error: Option<String>,
}

impl RunResult {
    /// Create a successful run result.
    pub fn success(schedule: TraceSchedule) -> Self {
        Self { schedule, error: None }
    }

    /// Create a run result with an error.
    pub fn with_error(schedule: TraceSchedule, error: impl Into<String>) -> Self {
        Self {
            schedule,
            error: Some(error.into()),
        }
    }

    /// Whether the run completed without error.
    pub fn is_success(&self) -> bool {
        self.error.is_none()
    }

    /// Whether the run was interrupted by a cancellation.
    pub fn is_cancelled(&self) -> bool {
        self.error.as_deref() == Some("cancelled")
    }
}

/// A generator of an emulator's thread schedule.
///
/// Ported from Ghidra's `Scheduler` interface. Determines which thread
/// gets the next slice of execution time and how many ticks it should execute.
pub trait Scheduler: Send + Sync {
    /// Get the next step to schedule.
    ///
    /// Returns the thread key and tick count for the next slice of execution.
    fn next_slice(&mut self) -> TickStep;
}

/// A scheduler that allocates all slices to a single thread.
///
/// Ported from Ghidra's `Scheduler.oneThread()`.
#[derive(Debug, Clone)]
pub struct OneThreadScheduler {
    thread_key: i64,
    slice_size: u64,
}

impl OneThreadScheduler {
    /// Create a new scheduler for a single thread.
    pub fn new(thread_key: i64, slice_size: u64) -> Self {
        Self { thread_key, slice_size }
    }

    /// Create with default slice size of 1000.
    pub fn with_default_slice(thread_key: i64) -> Self {
        Self::new(thread_key, 1000)
    }
}

impl Scheduler for OneThreadScheduler {
    fn next_slice(&mut self) -> TickStep {
        TickStep::new(self.thread_key, self.slice_size)
    }
}

/// A round-robin scheduler that alternates between threads.
#[derive(Debug, Clone)]
pub struct RoundRobinScheduler {
    threads: Vec<i64>,
    current_index: usize,
    slice_size: u64,
}

impl RoundRobinScheduler {
    /// Create a round-robin scheduler.
    pub fn new(threads: Vec<i64>, slice_size: u64) -> Self {
        Self {
            threads,
            current_index: 0,
            slice_size,
        }
    }
}

impl Scheduler for RoundRobinScheduler {
    fn next_slice(&mut self) -> TickStep {
        let key = self.threads[self.current_index];
        self.current_index = (self.current_index + 1) % self.threads.len();
        TickStep::new(key, self.slice_size)
    }
}

/// A trace-aware scheduler that resolves thread keys from trace snapshots.
///
/// Extends the basic Scheduler to provide trace-aware scheduling where
/// the event thread of the current snapshot determines the next thread.
#[derive(Debug, Clone)]
pub struct TraceScheduler {
    /// The snap being scheduled.
    pub snap: i64,
    /// Default slice size.
    pub slice_size: u64,
    /// Last known thread key.
    pub last_thread_key: i64,
}

impl TraceScheduler {
    /// Create a new trace scheduler.
    pub fn new(snap: i64) -> Self {
        Self {
            snap,
            slice_size: 1000,
            last_thread_key: -1,
        }
    }

    /// Set the last thread key.
    pub fn with_thread(mut self, thread_key: i64) -> Self {
        self.last_thread_key = thread_key;
        self
    }

    /// Set the slice size.
    pub fn with_slice_size(mut self, size: u64) -> Self {
        self.slice_size = size;
        self
    }
}

impl Scheduler for TraceScheduler {
    fn next_slice(&mut self) -> TickStep {
        TickStep::new(self.last_thread_key, self.slice_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_one_thread_scheduler() {
        let mut sched = OneThreadScheduler::new(1, 100);
        let step = sched.next_slice();
        assert_eq!(step.thread_key, 1);
        assert_eq!(step.tick_count, 100);

        let step2 = sched.next_slice();
        assert_eq!(step2.thread_key, 1);
        assert_eq!(step2.tick_count, 100);
    }

    #[test]
    fn test_one_thread_scheduler_default_slice() {
        let mut sched = OneThreadScheduler::with_default_slice(5);
        let step = sched.next_slice();
        assert_eq!(step.tick_count, 1000);
    }

    #[test]
    fn test_round_robin_scheduler() {
        let mut sched = RoundRobinScheduler::new(vec![1, 2, 3], 100);
        assert_eq!(sched.next_slice().thread_key, 1);
        assert_eq!(sched.next_slice().thread_key, 2);
        assert_eq!(sched.next_slice().thread_key, 3);
        assert_eq!(sched.next_slice().thread_key, 1); // Wraps around
    }

    #[test]
    fn test_trace_scheduler() {
        let mut sched = TraceScheduler::new(0).with_thread(1).with_slice_size(50);
        let step = sched.next_slice();
        assert_eq!(step.thread_key, 1);
        assert_eq!(step.tick_count, 50);
    }

    #[test]
    fn test_run_result_success() {
        let result = RunResult::success(TraceSchedule::snap(0));
        assert!(result.is_success());
        assert!(!result.is_cancelled());
        assert!(result.error.is_none());
    }

    #[test]
    fn test_run_result_error() {
        let result = RunResult::with_error(TraceSchedule::snap(0), "breakpoint hit");
        assert!(!result.is_success());
        assert!(!result.is_cancelled());
        assert_eq!(result.error.as_deref(), Some("breakpoint hit"));
    }

    #[test]
    fn test_run_result_cancelled() {
        let result = RunResult::with_error(TraceSchedule::snap(0), "cancelled");
        assert!(!result.is_success());
        assert!(result.is_cancelled());
    }
}
