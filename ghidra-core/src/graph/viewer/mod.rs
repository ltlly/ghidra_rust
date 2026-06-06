//! Graph viewer types ported from Ghidra's `ghidra.graph.viewer` package.
//!
//! Provides non-GUI types for graph visualization: layout, picking, options,
//! satellite view parameters, and shape routing.

pub mod abstract_visual_graph_layout;
pub mod actions;
pub mod edge;
pub mod graph_component;
pub mod graph_perspective;
pub mod graph_viewer_utils;
pub mod layout_provider;
pub mod mouse;
pub mod options;
pub mod picking;
pub mod popup;
pub mod renderer;
pub mod satellite;
pub mod shape;
pub mod vertex;
pub mod visual_types;

pub use layout_provider::{
    Column, GridBounds, GridLocationMap, GridPoint, LayoutPositions, LayoutProvider, RelayoutOption,
    Row, ViewRestoreOption,
};
pub use visual_types::{
    EdgeRendererConfig, EdgeRenderingStyle, GraphDirection, LayoutChangeType, LayoutListener,
    Point2d, Rect2d, RgbaColor, VertexRendererConfig, VisualEdge, VisualEdgeRenderer,
    VisualGraphLayout, VisualVertex, VisualVertexRenderer,
};

/// How vertices are picked (selected) in the graph viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PickingMode {
    /// Click to select a single vertex (deselects others).
    Single,
    /// Ctrl+click to toggle individual vertex selection.
    Toggle,
    /// Click to select a vertex and all its neighbors.
    Neighborhood,
}

impl Default for PickingMode {
    fn default() -> Self {
        Self::Single
    }
}

/// Path highlight modes for edge highlighting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum PathHighlightMode {
    /// Do not highlight paths.
    None,
    /// Highlight the shortest path between selected vertices.
    ShortestPath,
    /// Highlight all paths between selected vertices.
    AllPaths,
    /// Highlight the dominator path.
    DominatorPath,
}

impl Default for PathHighlightMode {
    fn default() -> Self {
        Self::None
    }
}

impl std::fmt::Display for PathHighlightMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::ShortestPath => write!(f, "Shortest Path"),
            Self::AllPaths => write!(f, "All Paths"),
            Self::DominatorPath => write!(f, "Dominator Path"),
        }
    }
}

/// Layout options for graph visualization.
#[derive(Debug, Clone)]
pub struct LayoutOptions {
    /// The layout algorithm name.
    pub algorithm: String,
    /// Whether to animate transitions between layouts.
    pub animate: bool,
    /// Padding between vertices (in pixels).
    pub padding: f64,
    /// Whether to fit the graph to the viewport after layout.
    pub fit_to_view: bool,
    /// Maximum number of layout iterations (for iterative algorithms).
    pub max_iterations: usize,
}

impl Default for LayoutOptions {
    fn default() -> Self {
        Self {
            algorithm: "Hierarchical".to_string(),
            animate: true,
            padding: 20.0,
            fit_to_view: true,
            max_iterations: 100,
        }
    }
}

/// Zoom/pan state for a graph viewer.
#[derive(Debug, Clone)]
pub struct ViewState {
    /// Current zoom level (1.0 = 100%).
    pub zoom: f64,
    /// Pan offset X.
    pub pan_x: f64,
    /// Pan offset Y.
    pub pan_y: f64,
    /// Viewport width.
    pub viewport_width: f64,
    /// Viewport height.
    pub viewport_height: f64,
}

impl Default for ViewState {
    fn default() -> Self {
        Self {
            zoom: 1.0,
            pan_x: 0.0,
            pan_y: 0.0,
            viewport_width: 800.0,
            viewport_height: 600.0,
        }
    }
}

impl ViewState {
    /// Zoom in by a factor.
    pub fn zoom_in(&mut self, factor: f64) {
        self.zoom = (self.zoom * factor).min(10.0);
    }

    /// Zoom out by a factor.
    pub fn zoom_out(&mut self, factor: f64) {
        self.zoom = (self.zoom / factor).max(0.1);
    }

    /// Reset to default zoom and pan.
    pub fn reset(&mut self) {
        self.zoom = 1.0;
        self.pan_x = 0.0;
        self.pan_y = 0.0;
    }

    /// Center the view on a point.
    pub fn center_on(&mut self, x: f64, y: f64) {
        self.pan_x = x - self.viewport_width / 2.0;
        self.pan_y = y - self.viewport_height / 2.0;
    }
}

/// Configuration for a graph viewer component.
#[derive(Debug, Clone)]
pub struct GraphViewerConfig {
    /// Picking mode.
    pub picking_mode: PickingMode,
    /// Path highlight mode.
    pub highlight_mode: PathHighlightMode,
    /// Layout options.
    pub layout: LayoutOptions,
    /// Whether to show vertex labels.
    pub show_labels: bool,
    /// Whether to show edge labels.
    pub show_edge_labels: bool,
    /// Whether to allow vertex dragging.
    pub allow_drag: bool,
    /// Whether to show the satellite (overview) view.
    pub show_satellite: bool,
}

impl Default for GraphViewerConfig {
    fn default() -> Self {
        Self {
            picking_mode: PickingMode::default(),
            highlight_mode: PathHighlightMode::default(),
            layout: LayoutOptions::default(),
            show_labels: true,
            show_edge_labels: false,
            allow_drag: true,
            show_satellite: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_picking_mode_default() {
        assert_eq!(PickingMode::default(), PickingMode::Single);
    }

    #[test]
    fn test_path_highlight_mode_display() {
        assert_eq!(PathHighlightMode::None.to_string(), "None");
        assert_eq!(PathHighlightMode::ShortestPath.to_string(), "Shortest Path");
    }

    #[test]
    fn test_layout_options_default() {
        let opts = LayoutOptions::default();
        assert_eq!(opts.algorithm, "Hierarchical");
        assert!(opts.animate);
        assert_eq!(opts.padding, 20.0);
    }

    #[test]
    fn test_view_state_zoom() {
        let mut vs = ViewState::default();
        assert_eq!(vs.zoom, 1.0);

        vs.zoom_in(2.0);
        assert_eq!(vs.zoom, 2.0);

        vs.zoom_out(2.0);
        assert_eq!(vs.zoom, 1.0);

        // Clamp at limits
        vs.zoom_in(100.0);
        assert_eq!(vs.zoom, 10.0);

        vs.zoom_out(100.0);
        vs.zoom_out(100.0);
        assert_eq!(vs.zoom, 0.1);
    }

    #[test]
    fn test_view_state_reset() {
        let mut vs = ViewState::default();
        vs.zoom_in(3.0);
        vs.pan_x = 100.0;
        vs.pan_y = 200.0;
        vs.reset();
        assert_eq!(vs.zoom, 1.0);
        assert_eq!(vs.pan_x, 0.0);
        assert_eq!(vs.pan_y, 0.0);
    }

    #[test]
    fn test_view_state_center_on() {
        let mut vs = ViewState::default();
        vs.viewport_width = 800.0;
        vs.viewport_height = 600.0;
        vs.center_on(500.0, 400.0);
        assert_eq!(vs.pan_x, 100.0);
        assert_eq!(vs.pan_y, 100.0);
    }

    #[test]
    fn test_graph_viewer_config_default() {
        let config = GraphViewerConfig::default();
        assert_eq!(config.picking_mode, PickingMode::Single);
        assert!(config.show_labels);
        assert!(!config.show_edge_labels);
        assert!(config.allow_drag);
        assert!(!config.show_satellite);
    }
}
