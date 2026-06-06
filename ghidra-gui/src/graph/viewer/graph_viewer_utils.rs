//! Port of `GraphViewerUtils`.
use std::collections::HashMap;
/// Struct porting `GraphViewerUtils`.
#[derive(Debug, Clone)]
pub struct GraphViewerUtils {
    /// graph_decorator_thread_pool_name.
    pub graph_decorator_thread_pool_name: String,
    /// graph_builder_thread_pool_name.
    pub graph_builder_thread_pool_name: String,
    /// interaction_zoom_threshold.
    pub interaction_zoom_threshold: f64,
    /// paint_zoom_threshold.
    pub paint_zoom_threshold: f64,
    /// edge_row_spacing.
    pub edge_row_spacing: i32,
    /// edge_column_spacing.
    pub edge_column_spacing: i32,
}

impl GraphViewerUtils {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for GraphViewerUtils {
    fn default() -> Self {
        Self {
            graph_decorator_thread_pool_name: String::new(),
            graph_builder_thread_pool_name: String::new(),
            interaction_zoom_threshold: 0,
            paint_zoom_threshold: 0,
            edge_row_spacing: 0,
            edge_column_spacing: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_graph_viewer_utils_new() { let _ = GraphViewerUtils::new(); }
}
