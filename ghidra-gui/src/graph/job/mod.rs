//! Graph jobs: animated operations on visual graphs.
//!
//! Ports Ghidra's `ghidra.graph.job` package.

use std::collections::VecDeque;

use super::viewer::{Point2D, VisualGraph};

/// A graph job that can be queued and executed.
pub trait GraphJob {
    /// Human-readable name for the job.
    fn name(&self) -> &str;

    /// Execute the job on the given graph.  Returns `true` if the graph was
    /// modified.
    fn execute(&mut self, graph: &mut VisualGraph) -> bool;

    /// Progress fraction (0.0 ..= 1.0).
    fn progress(&self) -> f32 {
        1.0
    }
}

/// Job runner that processes a queue of graph jobs sequentially.
/// Job runner that processes a queue of graph jobs sequentially.
pub struct GraphJobRunner {
    queue: VecDeque<Box<dyn GraphJob>>,
    current_name: Option<String>,
}

impl std::fmt::Debug for GraphJobRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GraphJobRunner")
            .field("pending", &self.queue.len())
            .field("current_name", &self.current_name)
            .finish()
    }
}

impl GraphJobRunner {
    /// Create an empty job runner.
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            current_name: None,
        }
    }

    /// Enqueue a job.
    pub fn schedule(&mut self, job: Box<dyn GraphJob>) {
        self.queue.push_back(job);
    }

    /// Number of pending jobs.
    pub fn pending_count(&self) -> usize {
        self.queue.len()
    }

    /// The name of the currently-executing job, if any.
    pub fn current_job_name(&self) -> Option<&str> {
        self.current_name.as_deref()
    }

    /// Run all pending jobs to completion.
    pub fn run_all(&mut self, graph: &mut VisualGraph) -> usize {
        let mut count = 0;
        while let Some(mut job) = self.queue.pop_front() {
            self.current_name = Some(job.name().to_string());
            job.execute(graph);
            count += 1;
        }
        self.current_name = None;
        count
    }

    /// Clear the job queue.
    pub fn clear(&mut self) {
        self.queue.clear();
        self.current_name = None;
    }
}

impl Default for GraphJobRunner {
    fn default() -> Self {
        Self::new()
    }
}

/// Filter vertices: hide/show vertices matching a predicate.
pub struct FilterVerticesJob {
    /// Vertex ids to hide.
    pub hide_ids: Vec<String>,
    /// Whether this is a show (false) or hide (true) operation.
    pub hide: bool,
}

impl GraphJob for FilterVerticesJob {
    fn name(&self) -> &str {
        "FilterVertices"
    }

    fn execute(&mut self, graph: &mut VisualGraph) -> bool {
        // In a real implementation, this would toggle visibility.
        // For now, mark as modified.
        !self.hide_ids.is_empty()
    }
}

/// Move a vertex to the center of the view.
pub struct MoveVertexToCenterJob {
    pub vertex_id: String,
    pub target_position: Point2D,
}

impl GraphJob for MoveVertexToCenterJob {
    fn name(&self) -> &str {
        "MoveVertexToCenter"
    }

    fn execute(&mut self, graph: &mut VisualGraph) -> bool {
        if let Some(v) = graph.vertex_mut(&self.vertex_id) {
            v.position = self.target_position;
            true
        } else {
            false
        }
    }
}

/// Fit the graph into the visible area.
pub struct FitGraphToViewJob {
    pub view_width: f64,
    pub view_height: f64,
}

impl GraphJob for FitGraphToViewJob {
    fn name(&self) -> &str {
        "FitGraphToView"
    }

    fn execute(&mut self, graph: &mut VisualGraph) -> bool {
        let bounds = match graph.bounds() {
            Some(b) => b,
            None => return false,
        };

        if bounds.width == 0.0 || bounds.height == 0.0 {
            return false;
        }

        let scale_x = self.view_width / bounds.width;
        let scale_y = self.view_height / bounds.height;
        let _scale = scale_x.min(scale_y).min(2.0); // cap at 2x zoom

        // Center the graph in the view.
        let offset_x = (self.view_width - bounds.width) / 2.0 - bounds.x;
        let offset_y = (self.view_height - bounds.height) / 2.0 - bounds.y;

        for v in graph.all_vertices_mut() {
            v.position.x += offset_x;
            v.position.y += offset_y;
        }

        true
    }
}
