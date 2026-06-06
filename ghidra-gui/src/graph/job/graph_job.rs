//! Port of Ghidra's `ghidra.graph.job.GraphJob` interface.
//!
//! A graph job is a unit of work to be executed in the context of a visual
//! graph. Jobs are queued and run by a `GraphJobRunner`.

use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};

/// A discrete unit of work for the graph system.
///
/// Ports Ghidra's `GraphJob`. Jobs are enqueued into a `GraphJobRunner`
/// and executed sequentially.
pub trait GraphJob: Send + Sync + fmt::Debug {
    /// Human-readable name of this job (for logging / debugging).
    fn name(&self) -> &str;

    /// Execute the job.
    fn execute(&mut self);

    /// Return `true` if this job is an animation that should be scheduled
    /// with a delay.  Default is `false`.
    fn is_animation(&self) -> bool {
        false
    }
}

/// Listener for job execution events.
pub trait GraphJobListener: Send + Sync {
    /// Called when a job starts executing.
    fn job_started(&self, name: &str);

    /// Called when a job finishes.
    fn job_finished(&self, name: &str);
}

/// Runs `GraphJob` instances sequentially.
///
/// Ports Ghidra's `GraphJobRunner`. Jobs are enqueued and executed in FIFO
/// order. The runner keeps a history of executed job names for debugging.
#[derive(Debug)]
pub struct GraphJobRunner {
    queue: Arc<Mutex<VecDeque<Box<dyn GraphJob>>>>,
    history: Arc<Mutex<Vec<String>>>,
}

impl GraphJobRunner {
    /// Create a new, empty job runner.
    pub fn new() -> Self {
        Self {
            queue: Arc::new(Mutex::new(VecDeque::new())),
            history: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Enqueue a job for later execution.
    pub fn schedule(&self, job: Box<dyn GraphJob>) {
        self.queue.lock().unwrap().push_back(job);
    }

    /// Execute all queued jobs in order. Returns the number of jobs executed.
    pub fn run_all(&self) -> usize {
        let mut count = 0;
        loop {
            let mut job = {
                let mut q = self.queue.lock().unwrap();
                q.pop_front()
            };
            match job {
                Some(ref mut j) => {
                    let name = j.name().to_string();
                    j.execute();
                    self.history.lock().unwrap().push(name);
                    count += 1;
                }
                None => break,
            }
        }
        count
    }

    /// Return the number of jobs currently in the queue.
    pub fn pending_count(&self) -> usize {
        self.queue.lock().unwrap().len()
    }

    /// Return the names of all previously executed jobs.
    pub fn history(&self) -> Vec<String> {
        self.history.lock().unwrap().clone()
    }

    /// Clear the queue.
    pub fn clear(&self) {
        self.queue.lock().unwrap().clear();
    }
}

impl Default for GraphJobRunner {
    fn default() -> Self {
        Self::new()
    }
}

/// A simple named job that runs a closure.
#[derive(Debug)]
pub struct ClosureGraphJob {
    name: String,
    action: Option<Box<dyn FnOnce() + Send + Sync>>,
}

impl ClosureGraphJob {
    /// Create a new closure-based job.
    pub fn new(name: impl Into<String>, action: impl FnOnce() + Send + Sync + 'static) -> Self {
        Self {
            name: name.into(),
            action: Some(Box::new(action)),
        }
    }
}

impl GraphJob for ClosureGraphJob {
    fn name(&self) -> &str {
        &self.name
    }

    fn execute(&mut self) {
        if let Some(action) = self.action.take() {
            action();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct CountingJob {
        name: String,
        counter: Arc<AtomicUsize>,
    }

    impl CountingJob {
        fn new(name: &str, counter: Arc<AtomicUsize>) -> Self {
            Self { name: name.into(), counter }
        }
    }

    impl GraphJob for CountingJob {
        fn name(&self) -> &str { &self.name }
        fn execute(&mut self) {
            self.counter.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_runner_empty() {
        let runner = GraphJobRunner::new();
        assert_eq!(runner.pending_count(), 0);
        assert_eq!(runner.run_all(), 0);
    }

    #[test]
    fn test_runner_executes_jobs() {
        let counter = Arc::new(AtomicUsize::new(0));
        let runner = GraphJobRunner::new();

        runner.schedule(Box::new(CountingJob::new("a", counter.clone())));
        runner.schedule(Box::new(CountingJob::new("b", counter.clone())));

        assert_eq!(runner.pending_count(), 2);
        let executed = runner.run_all();
        assert_eq!(executed, 2);
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_runner_history() {
        let counter = Arc::new(AtomicUsize::new(0));
        let runner = GraphJobRunner::new();
        runner.schedule(Box::new(CountingJob::new("job1", counter.clone())));
        runner.schedule(Box::new(CountingJob::new("job2", counter)));
        runner.run_all();
        assert_eq!(runner.history(), vec!["job1", "job2"]);
    }

    #[test]
    fn test_closure_job() {
        let flag = Arc::new(AtomicUsize::new(0));
        let flag2 = flag.clone();
        let mut job = ClosureGraphJob::new("test", move || {
            flag2.store(42, Ordering::SeqCst);
        });
        assert_eq!(job.name(), "test");
        job.execute();
        assert_eq!(flag.load(Ordering::SeqCst), 42);
    }

    #[test]
    fn test_runner_clear() {
        let counter = Arc::new(AtomicUsize::new(0));
        let runner = GraphJobRunner::new();
        runner.schedule(Box::new(CountingJob::new("a", counter)));
        runner.clear();
        assert_eq!(runner.pending_count(), 0);
    }
}
