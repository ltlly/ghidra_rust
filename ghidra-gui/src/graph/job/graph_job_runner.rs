//! Graph job runner that executes animation and layout jobs.
//!
//! Ports Ghidra's `ghidra.graph.job.GraphJobRunner`.
//! Manages a queue of graph jobs and executes them sequentially.

/// A graph job that can be queued and executed by the runner.
#[derive(Debug, Clone)]
pub enum GraphJob {
    /// Fit the graph to the viewer.
    FitGraphToView,
    /// Relayout the entire graph.
    Relayout,
    /// Relayout and center on a specific vertex.
    RelayoutAndCenterVertex(String),
    /// Move the view to center on a vertex.
    MoveVertexToCenter(String),
    /// Move the view to center on a vertex at top.
    MoveVertexToCenterTop(String),
    /// Filter visible vertices.
    FilterVertices(Vec<String>),
    /// Move view to a specific layout-space point.
    MoveViewToLayoutPoint(f64, f64),
    /// Move view to a specific view-space point.
    MoveViewToViewPoint(f64, f64),
    /// Animate vertex twinkle effect.
    TwinkleVertex(String),
    /// Relayout and ensure vertex is visible.
    RelayoutAndEnsureVisible(String),
}

/// Runs graph animation and layout jobs.
///
/// The runner maintains a queue of jobs and executes them in FIFO order.
/// Jobs are typically animation frames or one-shot layout operations.
#[derive(Debug, Clone)]
pub struct GraphJobRunner {
    /// Pending jobs to execute.
    jobs: Vec<GraphJob>,
    /// Whether the runner is currently executing a job.
    executing: bool,
}

impl GraphJobRunner {
    /// Create a new empty job runner.
    pub fn new() -> Self {
        Self {
            jobs: Vec::new(),
            executing: false,
        }
    }

    /// Add a job to the end of the queue.
    pub fn add_job(&mut self, job: GraphJob) {
        self.jobs.push(job);
    }

    /// Get the number of pending jobs.
    pub fn pending_count(&self) -> usize {
        self.jobs.len()
    }

    /// Whether there are pending jobs.
    pub fn has_jobs(&self) -> bool {
        !self.jobs.is_empty()
    }

    /// Whether the runner is currently executing a job.
    pub fn is_executing(&self) -> bool {
        self.executing
    }

    /// Execute the next job in the queue. Returns the job if one was executed.
    pub fn execute_next(&mut self) -> Option<GraphJob> {
        if self.jobs.is_empty() {
            return None;
        }
        self.executing = true;
        let job = self.jobs.remove(0);
        self.executing = false;
        Some(job)
    }

    /// Clear all pending jobs.
    pub fn clear(&mut self) {
        self.jobs.clear();
        self.executing = false;
    }

    /// Replace all pending jobs with a single job.
    pub fn replace_all(&mut self, job: GraphJob) {
        self.jobs.clear();
        self.jobs.push(job);
    }
}

impl Default for GraphJobRunner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let r = GraphJobRunner::new();
        assert!(!r.has_jobs());
        assert!(!r.is_executing());
        assert_eq!(r.pending_count(), 0);
    }

    #[test]
    fn test_add_and_execute() {
        let mut r = GraphJobRunner::new();
        r.add_job(GraphJob::FitGraphToView);
        r.add_job(GraphJob::Relayout);
        assert_eq!(r.pending_count(), 2);

        let job = r.execute_next();
        assert!(matches!(job, Some(GraphJob::FitGraphToView)));
        assert_eq!(r.pending_count(), 1);

        let job2 = r.execute_next();
        assert!(matches!(job2, Some(GraphJob::Relayout)));
        assert_eq!(r.pending_count(), 0);

        let job3 = r.execute_next();
        assert!(job3.is_none());
    }

    #[test]
    fn test_clear() {
        let mut r = GraphJobRunner::new();
        r.add_job(GraphJob::Relayout);
        r.add_job(GraphJob::FitGraphToView);
        r.clear();
        assert!(!r.has_jobs());
    }

    #[test]
    fn test_replace_all() {
        let mut r = GraphJobRunner::new();
        r.add_job(GraphJob::Relayout);
        r.add_job(GraphJob::FitGraphToView);
        r.replace_all(GraphJob::TwinkleVertex("v1".to_string()));
        assert_eq!(r.pending_count(), 1);
    }

    #[test]
    fn test_vertex_center_job() {
        let mut r = GraphJobRunner::new();
        r.add_job(GraphJob::MoveVertexToCenter("v1".to_string()));
        let job = r.execute_next();
        assert!(matches!(job, Some(GraphJob::MoveVertexToCenter(ref id)) if id == "v1"));
    }
}
