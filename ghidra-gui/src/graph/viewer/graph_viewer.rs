//! GraphViewer -- the main viewer for visual graphs.
//!
//! Port of Ghidra's `ghidra.graph.viewer.GraphViewer`.
//!
//! The `GraphViewer` is the primary widget for displaying and interacting
//! with a visual graph. It manages:
//! - Rendering vertices and edges
//! - Mouse interaction (picking, hovering, panning, zooming)
//! - Popup/tooltip display
//! - Path highlighting
//! - Satellite view synchronization

use std::collections::HashSet;

use super::edge::EdgePathHighlighter;
use super::event::mouse::{GraphMouseEvent, MouseEventType};
use super::popup::popup_source::PopupSource;
use super::renderer::RenderContext;
use super::satellite::SatelliteView;
use super::visual_graph_view::VisualGraphView;
use super::{Point2D, VisualEdge, VisualGraph};

/// Graph viewer mode controls the primary interaction behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphViewerMode {
    /// Normal interactive mode (default).
    Normal,
    /// Read-only mode (no picking/editing).
    ReadOnly,
    /// Overview mode (zoomed out, for navigation).
    Overview,
}

impl Default for GraphViewerMode {
    fn default() -> Self {
        Self::Normal
    }
}

/// The main graph viewer widget.
///
/// Port of `ghidra.graph.viewer.GraphViewer`.
///
/// This is the top-level container that:
/// - Hosts the `VisualGraphView` for rendering
/// - Manages mouse input delegation
/// - Coordinates path highlighting
/// - Handles popup/tooltip display
/// - Manages the satellite view
#[derive(Debug, Clone)]
pub struct GraphViewer {
    /// The underlying graph.
    graph: VisualGraph,
    /// The view for rendering.
    view: VisualGraphView,
    /// The render context.
    render_context: RenderContext,
    /// The satellite view (mini-map).
    satellite: Option<SatelliteView>,
    /// Current viewer mode.
    mode: GraphViewerMode,
    /// Selected vertex ids.
    selected_vertices: HashSet<String>,
    /// Hovered vertex id.
    hovered_vertex: Option<String>,
    /// Hovered edge id.
    hovered_edge: Option<String>,
    /// Path highlighter.
    path_highlighter: EdgePathHighlighter,
    /// Whether the viewer has been initialized.
    initialized: bool,
    /// Whether tooltips are enabled.
    tooltip_enabled: bool,
    /// Maximum number of picked vertices.
    max_picked_vertices: usize,
    /// Whether a repaint is needed.
    needs_repaint: bool,
}

impl GraphViewer {
    /// Create a new graph viewer with the given graph.
    pub fn new(graph: VisualGraph) -> Self {
        Self {
            graph,
            view: VisualGraphView::default(),
            render_context: RenderContext::default(),
            satellite: None,
            mode: GraphViewerMode::Normal,
            selected_vertices: HashSet::new(),
            hovered_vertex: None,
            hovered_edge: None,
            path_highlighter: EdgePathHighlighter::new(),
            initialized: false,
            tooltip_enabled: true,
            max_picked_vertices: 1,
            needs_repaint: false,
        }
    }

    /// Get the underlying graph.
    pub fn graph(&self) -> &VisualGraph {
        &self.graph
    }

    /// Get a mutable reference to the graph.
    pub fn graph_mut(&mut self) -> &mut VisualGraph {
        &mut self.graph
    }

    /// Set the graph (replaces the current graph).
    pub fn set_graph(&mut self, graph: VisualGraph) {
        self.graph = graph;
        self.selected_vertices.clear();
        self.hovered_vertex = None;
        self.hovered_edge = None;
        self.needs_repaint = true;
    }

    /// Get the view.
    pub fn view(&self) -> &VisualGraphView {
        &self.view
    }

    /// Get a mutable reference to the view.
    pub fn view_mut(&mut self) -> &mut VisualGraphView {
        &mut self.view
    }

    /// Get the render context.
    pub fn render_context(&self) -> &RenderContext {
        &self.render_context
    }

    /// Get a mutable reference to the render context.
    pub fn render_context_mut(&mut self) -> &mut RenderContext {
        &mut self.render_context
    }

    /// Get the viewer mode.
    pub fn mode(&self) -> GraphViewerMode {
        self.mode
    }

    /// Set the viewer mode.
    pub fn set_mode(&mut self, mode: GraphViewerMode) {
        self.mode = mode;
    }

    /// Enable or disable the satellite view.
    pub fn set_satellite_enabled(&mut self, enabled: bool) {
        if enabled && self.satellite.is_none() {
            self.satellite = Some(SatelliteView::default());
        } else if !enabled {
            self.satellite = None;
        }
    }

    /// Get the satellite view (if enabled).
    pub fn satellite(&self) -> Option<&SatelliteView> {
        self.satellite.as_ref()
    }

    /// Get a mutable reference to the satellite view.
    pub fn satellite_mut(&mut self) -> Option<&mut SatelliteView> {
        self.satellite.as_mut()
    }

    /// Handle a mouse event.
    pub fn handle_mouse_event(&mut self, event: &GraphMouseEvent) {
        if self.mode == GraphViewerMode::ReadOnly && event.event_type == MouseEventType::Clicked {
            return;
        }

        match event.event_type {
            MouseEventType::Clicked => {
                let position = Point2D::new(event.graph_x, event.graph_y);
                self.handle_click(position);
            }
            MouseEventType::Moved => {
                let position = Point2D::new(event.graph_x, event.graph_y);
                self.handle_hover(position);
            }
            MouseEventType::Exited => {
                self.hovered_vertex = None;
                self.hovered_edge = None;
                self.path_highlighter.clear();
            }
            MouseEventType::Dragged => {
                self.view.pan(event.view_x, event.view_y);
                self.needs_repaint = true;
            }
            _ => {}
        }
    }

    /// Select a vertex by id.
    pub fn select_vertex(&mut self, id: &str) {
        self.selected_vertices.clear();
        self.selected_vertices.insert(id.to_string());
        self.graph.select_vertex(id);
        self.path_highlighter
            .highlight(id.to_string(), "#ffff00");
        self.needs_repaint = true;
    }

    /// Get the selected vertex ids.
    pub fn selected_vertices(&self) -> &HashSet<String> {
        &self.selected_vertices
    }

    /// Clear all vertex selections.
    pub fn clear_selection(&mut self) {
        self.selected_vertices.clear();
        self.graph.clear_selection();
        self.path_highlighter.clear();
        self.needs_repaint = true;
    }

    /// Get the hovered vertex.
    pub fn hovered_vertex(&self) -> Option<&str> {
        self.hovered_vertex.as_deref()
    }

    /// Get the hovered edge.
    pub fn hovered_edge(&self) -> Option<&str> {
        self.hovered_edge.as_deref()
    }

    /// Fit the view to show the entire graph.
    pub fn fit_graph_to_view(&mut self) {
        if let Some(bounds) = self.graph.bounds() {
            self.view.set_zoom(1.0);
            self.view.center_on(bounds.center());
        }
    }

    /// Center the view on a specific vertex.
    pub fn center_on_vertex(&mut self, id: &str) {
        if let Some(v) = self.graph.vertex(id) {
            let center = v.center();
            self.view.center_on(center);
            self.needs_repaint = true;
        }
    }

    /// Whether a repaint is needed.
    pub fn needs_repaint(&self) -> bool {
        self.needs_repaint
    }

    /// Clear the repaint flag.
    pub fn clear_repaint(&mut self) {
        self.needs_repaint = false;
    }

    /// Enable or disable tooltips.
    pub fn set_tooltips_enabled(&mut self, enabled: bool) {
        self.tooltip_enabled = enabled;
    }

    /// Whether tooltips are enabled.
    pub fn tooltips_enabled(&self) -> bool {
        self.tooltip_enabled
    }

    /// Initialize the viewer (called once after creation).
    pub fn initialize(&mut self) {
        if !self.initialized {
            self.fit_graph_to_view();
            self.initialized = true;
        }
    }

    /// Whether the viewer is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get the path highlighter.
    pub fn path_highlighter(&self) -> &EdgePathHighlighter {
        &self.path_highlighter
    }

    /// Get a mutable reference to the path highlighter.
    pub fn path_highlighter_mut(&mut self) -> &mut EdgePathHighlighter {
        &mut self.path_highlighter
    }

    /// Set the maximum number of picked vertices.
    pub fn set_max_picked_vertices(&mut self, max: usize) {
        self.max_picked_vertices = max;
    }

    /// Get the popup source at the given position (if any).
    pub fn popup_source_at(&self, position: Point2D) -> Option<PopupSource> {
        // Check vertices first (they're on top).
        for v in self.graph.vertices() {
            if v.bounding_rect().contains(position) {
                return Some(PopupSource::Vertex(0));
            }
        }
        // Then check edges.
        for e in self.graph.edges() {
            if edge_hit_test(e, position, 5.0) {
                return Some(PopupSource::Edge(0));
            }
        }
        None
    }

    // --- Private helpers ---

    fn handle_click(&mut self, position: Point2D) {
        // Find vertex at click position.
        for v in self.graph.vertices() {
            if v.bounding_rect().contains(position) {
                let id = v.id.clone();
                if self.selected_vertices.contains(&id) {
                    self.clear_selection();
                } else {
                    self.select_vertex(&id);
                }
                return;
            }
        }
        // Clicked on empty space -> clear selection.
        self.clear_selection();
    }

    fn handle_hover(&mut self, position: Point2D) {
        // Check vertices.
        for v in self.graph.vertices() {
            if v.bounding_rect().contains(position) {
                self.hovered_vertex = Some(v.id.clone());
                self.hovered_edge = None;
                self.path_highlighter
                    .highlight(v.id.clone(), "#ffff00");
                self.needs_repaint = true;
                return;
            }
        }

        // Check edges.
        self.hovered_vertex = None;
        for e in self.graph.edges() {
            if edge_hit_test(e, position, 5.0) {
                self.hovered_edge = Some(e.id.clone());
                self.needs_repaint = true;
                return;
            }
        }
        self.hovered_edge = None;
    }
}

impl Default for GraphViewer {
    fn default() -> Self {
        Self::new(VisualGraph::new())
    }
}

/// Simple edge hit-testing (point-to-line-segment distance).
fn edge_hit_test(edge: &VisualEdge, point: Point2D, tolerance: f64) -> bool {
    if edge.articulations.is_empty() {
        return false;
    }
    let points: Vec<Point2D> = edge.articulations.clone();
    for window in points.windows(2) {
        let dist = point_to_segment_distance(point, window[0], window[1]);
        if dist <= tolerance {
            return true;
        }
    }
    false
}

/// Calculate the distance from a point to a line segment.
fn point_to_segment_distance(p: Point2D, a: Point2D, b: Point2D) -> f64 {
    let dx = b.x - a.x;
    let dy = b.y - a.y;
    let len_sq = dx * dx + dy * dy;
    if len_sq < f64::EPSILON {
        return ((p.x - a.x).powi(2) + (p.y - a.y).powi(2)).sqrt();
    }
    let t = ((p.x - a.x) * dx + (p.y - a.y) * dy) / len_sq;
    let t = t.clamp(0.0, 1.0);
    let proj_x = a.x + t * dx;
    let proj_y = a.y + t * dy;
    ((p.x - proj_x).powi(2) + (p.y - proj_y).powi(2)).sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::VisualVertex;

    #[test]
    fn test_graph_viewer_default() {
        let viewer = GraphViewer::default();
        assert_eq!(viewer.mode(), GraphViewerMode::Normal);
        assert!(viewer.selected_vertices().is_empty());
        assert!(viewer.hovered_vertex().is_none());
        assert!(!viewer.is_initialized());
        assert!(viewer.tooltips_enabled());
    }

    #[test]
    fn test_graph_viewer_select() {
        let mut graph = VisualGraph::new();
        let mut v = VisualVertex::new("a", "A");
        v.position = Point2D::new(10.0, 10.0);
        graph.add_vertex(v);

        let mut viewer = GraphViewer::new(graph);
        viewer.select_vertex("a");
        assert!(viewer.selected_vertices().contains("a"));
    }

    #[test]
    fn test_graph_viewer_click_vertex() {
        let mut graph = VisualGraph::new();
        let mut v = VisualVertex::new("a", "A");
        v.position = Point2D::new(10.0, 10.0);
        graph.add_vertex(v);

        let mut viewer = GraphViewer::new(graph);
        let mut evt = GraphMouseEvent::new(MouseEventType::Clicked, 50.0, 30.0);
        evt.graph_x = 50.0;
        evt.graph_y = 30.0;
        viewer.handle_mouse_event(&evt);
        assert!(viewer.selected_vertices().contains("a"));
    }

    #[test]
    fn test_graph_viewer_click_empty() {
        let mut graph = VisualGraph::new();
        let mut v = VisualVertex::new("a", "A");
        v.position = Point2D::new(10.0, 10.0);
        graph.add_vertex(v);

        let mut viewer = GraphViewer::new(graph);
        viewer.select_vertex("a");
        let mut evt = GraphMouseEvent::new(MouseEventType::Clicked, 500.0, 500.0);
        evt.graph_x = 500.0;
        evt.graph_y = 500.0;
        viewer.handle_mouse_event(&evt);
        assert!(viewer.selected_vertices().is_empty());
    }

    #[test]
    fn test_graph_viewer_hover() {
        let mut graph = VisualGraph::new();
        let mut v = VisualVertex::new("a", "A");
        v.position = Point2D::new(0.0, 0.0);
        graph.add_vertex(v);

        let mut viewer = GraphViewer::new(graph);
        let mut evt = GraphMouseEvent::new(MouseEventType::Moved, 50.0, 20.0);
        evt.graph_x = 50.0;
        evt.graph_y = 20.0;
        viewer.handle_mouse_event(&evt);
        assert_eq!(viewer.hovered_vertex(), Some("a"));
    }

    #[test]
    fn test_graph_viewer_hover_exit() {
        let mut viewer = GraphViewer::default();
        viewer.hovered_vertex = Some("a".to_string());
        let evt = GraphMouseEvent::new(MouseEventType::Exited, 0.0, 0.0);
        viewer.handle_mouse_event(&evt);
        assert!(viewer.hovered_vertex().is_none());
    }

    #[test]
    fn test_graph_viewer_mode() {
        let mut viewer = GraphViewer::default();
        viewer.set_mode(GraphViewerMode::ReadOnly);
        assert_eq!(viewer.mode(), GraphViewerMode::ReadOnly);
    }

    #[test]
    fn test_graph_viewer_satellite() {
        let mut viewer = GraphViewer::default();
        assert!(viewer.satellite().is_none());
        viewer.set_satellite_enabled(true);
        assert!(viewer.satellite().is_some());
        viewer.set_satellite_enabled(false);
        assert!(viewer.satellite().is_none());
    }

    #[test]
    fn test_graph_viewer_initialize() {
        let mut viewer = GraphViewer::default();
        assert!(!viewer.is_initialized());
        viewer.initialize();
        assert!(viewer.is_initialized());
    }

    #[test]
    fn test_point_to_segment_distance() {
        let dist = point_to_segment_distance(
            Point2D::new(5.0, 0.0),
            Point2D::new(0.0, 0.0),
            Point2D::new(10.0, 0.0),
        );
        assert!(dist.abs() < 1e-10);

        let dist = point_to_segment_distance(
            Point2D::new(5.0, 3.0),
            Point2D::new(0.0, 0.0),
            Point2D::new(10.0, 0.0),
        );
        assert!((dist - 3.0).abs() < 1e-10);
    }
}
