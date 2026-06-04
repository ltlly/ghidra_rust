//! Graph job types ported from Ghidra's `ghidra.graph.job` package.
//!
//! Provides abstractions for graph animation and layout jobs.

use std::collections::VecDeque;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};

/// Trait for a graph job (animation, layout, etc.).
///
/// Mirrors `ghidra.graph.job.GraphJob`.
pub trait GraphJob: Debug + Send + Sync {
    /// Get the name of this job.
    fn name(&self) -> &str;

    /// Execute the job. Returns true if the job completed.
    fn execute(&self) -> bool;

    /// Cancel the job.
    fn cancel(&self);

    /// Check if the job was cancelled.
    fn is_cancelled(&self) -> bool;

    /// Get the progress (0.0 to 1.0).
    fn progress(&self) -> f64;
}

/// Listener for job completion events.
///
/// Mirrors `ghidra.graph.job.GraphJobListener`.
pub trait GraphJobListener: Debug + Send + Sync {
    /// Called when a job completes.
    fn on_job_completed(&self, job: &dyn GraphJob);

    /// Called when a job is cancelled.
    fn on_job_cancelled(&self, job: &dyn GraphJob);
}

/// A runner that manages and executes graph jobs sequentially.
///
/// Mirrors `ghidra.graph.job.GraphJobRunner`.
#[derive(Debug)]
pub struct GraphJobRunner {
    jobs: Mutex<VecDeque<Box<dyn GraphJob>>>,
    running: Mutex<bool>,
    listener: Mutex<Option<Arc<dyn GraphJobListener>>>,
}

impl GraphJobRunner {
    /// Create a new job runner.
    pub fn new() -> Self {
        Self {
            jobs: Mutex::new(VecDeque::new()),
            running: Mutex::new(false),
            listener: Mutex::new(None),
        }
    }

    /// Submit a job for execution.
    pub fn submit(&self, job: Box<dyn GraphJob>) {
        self.jobs.lock().unwrap().push_back(job);
    }

    /// Set a listener for job completion events.
    pub fn set_listener(&self, listener: Arc<dyn GraphJobListener>) {
        *self.listener.lock().unwrap() = Some(listener);
    }

    /// Run the next job in the queue.
    ///
    /// Returns true if a job was executed, false if the queue is empty.
    pub fn run_next(&self) -> bool {
        let job = self.jobs.lock().unwrap().pop_front();
        match job {
            Some(job) => {
                if job.is_cancelled() {
                    if let Some(ref listener) = *self.listener.lock().unwrap() {
                        listener.on_job_cancelled(job.as_ref());
                    }
                    return true;
                }

                let completed = job.execute();
                if completed {
                    if let Some(ref listener) = *self.listener.lock().unwrap() {
                        listener.on_job_completed(job.as_ref());
                    }
                }
                true
            }
            None => false,
        }
    }

    /// Run all queued jobs.
    pub fn run_all(&self) {
        while self.run_next() {}
    }

    /// Cancel all queued jobs.
    pub fn cancel_all(&self) {
        let mut jobs = self.jobs.lock().unwrap();
        for job in jobs.iter() {
            job.cancel();
        }
        jobs.clear();
    }

    /// Get the number of pending jobs.
    pub fn pending_count(&self) -> usize {
        self.jobs.lock().unwrap().len()
    }

    /// Check if the runner has pending jobs.
    pub fn has_pending(&self) -> bool {
        !self.jobs.lock().unwrap().is_empty()
    }
}

impl Default for GraphJobRunner {
    fn default() -> Self {
        Self::new()
    }
}

/// A simple job implementation for testing.
#[derive(Debug)]
pub struct SimpleJob {
    name: String,
    cancelled: Mutex<bool>,
    executed: Mutex<bool>,
}

impl SimpleJob {
    /// Create a new simple job.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            cancelled: Mutex::new(false),
            executed: Mutex::new(false),
        }
    }

    /// Check if the job was executed.
    pub fn was_executed(&self) -> bool {
        *self.executed.lock().unwrap()
    }
}

impl GraphJob for SimpleJob {
    fn name(&self) -> &str {
        &self.name
    }

    fn execute(&self) -> bool {
        *self.executed.lock().unwrap() = true;
        true
    }

    fn cancel(&self) {
        *self.cancelled.lock().unwrap() = true;
    }

    fn is_cancelled(&self) -> bool {
        *self.cancelled.lock().unwrap()
    }

    fn progress(&self) -> f64 {
        if *self.executed.lock().unwrap() { 1.0 } else { 0.0 }
    }
}

/// A recording job listener for testing.
#[derive(Debug, Default)]
pub struct RecordingJobListener {
    events: Mutex<Vec<String>>,
}

impl RecordingJobListener {
    /// Create a new recording listener.
    pub fn new() -> Self {
        Self { events: Mutex::new(Vec::new()) }
    }

    /// Get all recorded events.
    pub fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
}

impl GraphJobListener for RecordingJobListener {
    fn on_job_completed(&self, job: &dyn GraphJob) {
        self.events.lock().unwrap().push(format!("completed:{}", job.name()));
    }

    fn on_job_cancelled(&self, job: &dyn GraphJob) {
        self.events.lock().unwrap().push(format!("cancelled:{}", job.name()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_job() {
        let job = SimpleJob::new("test");
        assert_eq!(job.name(), "test");
        assert!(!job.was_executed());
        assert_eq!(job.progress(), 0.0);

        job.execute();
        assert!(job.was_executed());
        assert_eq!(job.progress(), 1.0);
    }

    #[test]
    fn test_simple_job_cancel() {
        let job = SimpleJob::new("cancel_me");
        assert!(!job.is_cancelled());
        job.cancel();
        assert!(job.is_cancelled());
    }

    #[test]
    fn test_job_runner_submit_and_run() {
        let runner = GraphJobRunner::new();
        assert_eq!(runner.pending_count(), 0);

        runner.submit(Box::new(SimpleJob::new("job1")));
        runner.submit(Box::new(SimpleJob::new("job2")));
        assert_eq!(runner.pending_count(), 2);

        assert!(runner.run_next());
        assert_eq!(runner.pending_count(), 1);

        assert!(runner.run_next());
        assert_eq!(runner.pending_count(), 0);

        assert!(!runner.run_next()); // queue empty
    }

    #[test]
    fn test_job_runner_run_all() {
        let runner = GraphJobRunner::new();
        runner.submit(Box::new(SimpleJob::new("a")));
        runner.submit(Box::new(SimpleJob::new("b")));
        runner.submit(Box::new(SimpleJob::new("c")));
        runner.run_all();
        assert_eq!(runner.pending_count(), 0);
    }

    #[test]
    fn test_job_runner_cancel_all() {
        let runner = GraphJobRunner::new();
        runner.submit(Box::new(SimpleJob::new("a")));
        runner.submit(Box::new(SimpleJob::new("b")));
        runner.cancel_all();
        assert_eq!(runner.pending_count(), 0);
    }

    #[test]
    fn test_job_runner_with_listener() {
        let runner = GraphJobRunner::new();
        let listener = Arc::new(RecordingJobListener::new());
        runner.set_listener(listener.clone());

        runner.submit(Box::new(SimpleJob::new("job1")));
        runner.run_all();

        let events = listener.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], "completed:job1");
    }

    #[test]
    fn test_job_runner_cancelled_job() {
        let runner = GraphJobRunner::new();
        let listener = Arc::new(RecordingJobListener::new());
        runner.set_listener(listener.clone());

        let job = SimpleJob::new("cancelled_job");
        job.cancel();
        runner.submit(Box::new(job));
        runner.run_next();

        let events = listener.events();
        assert_eq!(events[0], "cancelled:cancelled_job");
    }
}
