//! Status listener for graph algorithms.
//!
//! Ports `ghidra.graph.algo.GraphAlgorithmStatusListener`.

/// Status update from a running graph algorithm.
#[derive(Debug, Clone)]
pub struct AlgorithmStatus {
    /// The algorithm name.
    pub algorithm: String,
    /// Current phase description.
    pub phase: String,
    /// Progress fraction (0.0 to 1.0), if known.
    pub progress: Option<f64>,
    /// Whether the algorithm was cancelled.
    pub cancelled: bool,
}

impl AlgorithmStatus {
    /// Create a new status.
    pub fn new(algorithm: impl Into<String>, phase: impl Into<String>) -> Self {
        Self {
            algorithm: algorithm.into(),
            phase: phase.into(),
            progress: None,
            cancelled: false,
        }
    }

    /// Set progress.
    pub fn with_progress(mut self, progress: f64) -> Self {
        self.progress = Some(progress);
        self
    }
}

/// Trait for receiving status updates from graph algorithms.
pub trait GraphAlgorithmStatusListener: Send + Sync {
    /// Called when the algorithm status changes.
    fn status_changed(&self, status: &AlgorithmStatus);
    /// Called to check if the algorithm should be cancelled.
    fn is_cancelled(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_status() {
        let status = AlgorithmStatus::new("Tarjan", "Finding SCCs").with_progress(0.5);
        assert_eq!(status.algorithm, "Tarjan");
        assert_eq!(status.phase, "Finding SCCs");
        assert_eq!(status.progress, Some(0.5));
    }

    #[test]
    fn test_sorter_exception_display() {
        use super::super::sorter_exception::SorterException;
        let e = SorterException::with_vertex("cycle detected", "node_42");
        assert!(e.to_string().contains("node_42"));
        assert!(e.to_string().contains("cycle detected"));
    }
}
