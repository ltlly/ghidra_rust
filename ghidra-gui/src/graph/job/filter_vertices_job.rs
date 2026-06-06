//! Filter vertices job for graph visibility control.
//!
//! Ports Ghidra's `ghidra.graph.job.FilterVerticesJob`.
//! Controls which vertices are visible in the graph by applying a filter.

use std::collections::HashSet;

/// A job that filters the visible vertices in a graph.
///
/// Only vertices matching the filter predicate are shown; all others are hidden.
/// This is used for search results filtering, function grouping, etc.
#[derive(Debug, Clone)]
pub struct FilterVerticesJob {
    /// The set of vertex ids that should be visible after filtering.
    pub visible_vertex_ids: HashSet<String>,
    /// Whether the filter has been applied.
    pub applied: bool,
    /// Whether to show all vertices (clear the filter).
    pub show_all: bool,
}

impl FilterVerticesJob {
    /// Create a new filter job with the given visible vertex set.
    pub fn new(visible_ids: impl IntoIterator<Item = String>) -> Self {
        Self {
            visible_vertex_ids: visible_ids.into_iter().collect(),
            applied: false,
            show_all: false,
        }
    }

    /// Create a job that clears all filters (shows all vertices).
    pub fn show_all() -> Self {
        Self {
            visible_vertex_ids: HashSet::new(),
            applied: false,
            show_all: true,
        }
    }

    /// Execute the filter job. Returns the set of visible vertex ids.
    pub fn execute(&mut self) -> &HashSet<String> {
        self.applied = true;
        &self.visible_vertex_ids
    }

    /// Whether a given vertex id should be visible.
    pub fn is_visible(&self, vertex_id: &str) -> bool {
        if self.show_all {
            return true;
        }
        self.visible_vertex_ids.contains(vertex_id)
    }

    /// Get the number of visible vertices.
    pub fn visible_count(&self) -> usize {
        self.visible_vertex_ids.len()
    }
}

impl Default for FilterVerticesJob {
    fn default() -> Self {
        Self::show_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let j = FilterVerticesJob::new(vec!["v1".to_string(), "v2".to_string()]);
        assert_eq!(j.visible_count(), 2);
        assert!(!j.applied);
    }

    #[test]
    fn test_show_all() {
        let j = FilterVerticesJob::show_all();
        assert!(j.is_visible("anything"));
    }

    #[test]
    fn test_is_visible() {
        let j = FilterVerticesJob::new(vec!["v1".to_string(), "v3".to_string()]);
        assert!(j.is_visible("v1"));
        assert!(!j.is_visible("v2"));
        assert!(j.is_visible("v3"));
    }

    #[test]
    fn test_execute() {
        let mut j = FilterVerticesJob::new(vec!["v1".to_string()]);
        j.execute();
        assert!(j.applied);
    }
}
