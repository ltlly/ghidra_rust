//! Graph viewer options and configuration.
//!
//! Ports Ghidra's `ghidra.graph.viewer.options` package.
//!
//! Re-exports `RelayoutOption` and `ViewRestoreOption` from `layout_provider`
//! to avoid duplication.

pub use super::layout_provider::{RelayoutOption, ViewRestoreOption};

/// Aggregated options for the visual graph viewer.
///
/// Ports `ghidra.graph.viewer.options.VisualGraphOptions`.
#[derive(Debug, Clone)]
pub struct VisualGraphOptions {
    /// What to do when a relayout is triggered.
    pub relayout_option: RelayoutOption,
    /// What to do when restoring a saved graph.
    pub view_restore_option: ViewRestoreOption,
    /// Whether to show edge labels.
    pub show_edge_labels: bool,
    /// Whether to show vertex labels.
    pub show_vertex_labels: bool,
    /// Whether to animate layout transitions.
    pub animate_layout: bool,
    /// Whether to show the grid.
    pub show_grid: bool,
    /// Whether to show the satellite view.
    pub show_satellite: bool,
    /// Whether to enable vertex dragging.
    pub enable_vertex_drag: bool,
    /// Whether to show the path highlight.
    pub enable_path_highlight: bool,
    /// Maximum number of vertices before labels are hidden.
    pub label_vertex_limit: usize,
    /// Maximum number of edges before labels are hidden.
    pub label_edge_limit: usize,
}

impl Default for VisualGraphOptions {
    fn default() -> Self {
        Self {
            relayout_option: RelayoutOption::default(),
            view_restore_option: ViewRestoreOption::default(),
            show_edge_labels: false,
            show_vertex_labels: true,
            animate_layout: true,
            show_grid: false,
            show_satellite: false,
            enable_vertex_drag: true,
            enable_path_highlight: true,
            label_vertex_limit: 500,
            label_edge_limit: 1000,
        }
    }
}

impl VisualGraphOptions {
    /// Create new options with all defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether labels should be shown given the current vertex count.
    pub fn should_show_vertex_labels(&self, vertex_count: usize) -> bool {
        self.show_vertex_labels && vertex_count <= self.label_vertex_limit
    }

    /// Whether labels should be shown given the current edge count.
    pub fn should_show_edge_labels(&self, edge_count: usize) -> bool {
        self.show_edge_labels && edge_count <= self.label_edge_limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relayout_option_default() {
        let opt = RelayoutOption::default();
        assert_eq!(opt, RelayoutOption::Full);
    }

    #[test]
    fn test_view_restore_option_default() {
        let opt = ViewRestoreOption::default();
        assert_eq!(opt, ViewRestoreOption::FitGraph);
    }

    #[test]
    fn test_visual_graph_options_default() {
        let opts = VisualGraphOptions::default();
        // relayout_option uses the layout_provider::RelayoutOption default
        assert!(opts.show_vertex_labels);
        assert!(!opts.show_edge_labels);
        assert!(opts.animate_layout);
        assert!(!opts.show_grid);
    }

    #[test]
    fn test_label_limits() {
        let mut opts = VisualGraphOptions::default();
        opts.label_vertex_limit = 100;

        assert!(opts.should_show_vertex_labels(50));
        assert!(!opts.should_show_vertex_labels(200));
    }

    #[test]
    fn test_edge_label_limit() {
        let mut opts = VisualGraphOptions::default();
        opts.show_edge_labels = true;
        opts.label_edge_limit = 500;

        assert!(opts.should_show_edge_labels(100));
        assert!(!opts.should_show_edge_labels(600));
    }
}
