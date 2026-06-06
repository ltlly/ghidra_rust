//! Edge rendering and interaction for visual graphs.
//!
//! Ports Ghidra's `ghidra.graph.viewer.edge` package.  Provides abstract
//! base types for edges, edge renderers, edge routing (articulated paths),
//! and path highlighting.

use super::visual_types::{Point2d, RgbaColor};

// ============================================================================
// AbstractVisualEdge -- base implementation of a visual edge
// ============================================================================

/// Abstract base implementation of a visual edge with UI state.
///
/// Ports `ghidra.graph.viewer.edge.AbstractVisualEdge`.  Stores source/target
/// vertex IDs, selection state, emphasis, and articulation points for routing.
#[derive(Debug, Clone)]
pub struct AbstractVisualEdge {
    /// Unique identifier for this edge.
    pub id: usize,
    /// Source vertex ID.
    pub start_id: usize,
    /// Target vertex ID.
    pub end_id: usize,
    /// Whether this edge is selected.
    selected: bool,
    /// Whether this edge is hovered.
    hovered: bool,
    /// Whether this edge is emphasized.
    emphasized: bool,
    /// Opacity (0.0 = transparent, 1.0 = opaque).
    alpha: f32,
    /// Intermediate (articulation) points for non-straight edges.
    articulation_points: Vec<Point2d>,
    /// Edge label text.
    label: String,
    /// Edge weight (for weighted graphs).
    weight: f64,
}

impl AbstractVisualEdge {
    /// Create a new abstract visual edge.
    pub fn new(id: usize, start_id: usize, end_id: usize) -> Self {
        Self {
            id,
            start_id,
            end_id,
            selected: false,
            hovered: false,
            emphasized: false,
            alpha: 1.0,
            articulation_points: Vec::new(),
            label: String::new(),
            weight: 1.0,
        }
    }

    /// Get the start vertex ID.
    pub fn start_id(&self) -> usize {
        self.start_id
    }

    /// Get the end vertex ID.
    pub fn end_id(&self) -> usize {
        self.end_id
    }

    /// Whether this edge is selected.
    pub fn is_selected(&self) -> bool {
        self.selected
    }

    /// Set the selected state.
    pub fn set_selected(&mut self, selected: bool) {
        self.selected = selected;
    }

    /// Whether this edge is hovered.
    pub fn is_hovered(&self) -> bool {
        self.hovered
    }

    /// Set the hover state.
    pub fn set_hovered(&mut self, hovered: bool) {
        self.hovered = hovered;
    }

    /// Whether this edge is emphasized.
    pub fn is_emphasized(&self) -> bool {
        self.emphasized
    }

    /// Set the emphasis state.
    pub fn set_emphasized(&mut self, emphasized: bool) {
        self.emphasized = emphasized;
    }

    /// Get the alpha (opacity) value.
    pub fn alpha(&self) -> f32 {
        self.alpha
    }

    /// Set the alpha (opacity) value.
    pub fn set_alpha(&mut self, alpha: f32) {
        self.alpha = alpha.clamp(0.0, 1.0);
    }

    /// Get the articulation points (intermediate routing points).
    pub fn articulation_points(&self) -> &[Point2d] {
        &self.articulation_points
    }

    /// Set the articulation points.
    pub fn set_articulation_points(&mut self, points: Vec<Point2d>) {
        self.articulation_points = points;
    }

    /// Add an articulation point.
    pub fn add_articulation_point(&mut self, point: Point2d) {
        self.articulation_points.push(point);
    }

    /// Clear all articulation points (edge will be drawn straight).
    pub fn clear_articulation_points(&mut self) {
        self.articulation_points.clear();
    }

    /// Get the label text.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Set the label text.
    pub fn set_label(&mut self, label: impl Into<String>) {
        self.label = label.into();
    }

    /// Get the edge weight.
    pub fn weight(&self) -> f64 {
        self.weight
    }

    /// Set the edge weight.
    pub fn set_weight(&mut self, weight: f64) {
        self.weight = weight;
    }

    /// Whether this edge has articulation points (i.e., is not a straight line).
    pub fn has_articulation_points(&self) -> bool {
        !self.articulation_points.is_empty()
    }

    /// Get the full point sequence for rendering: [start, ...articulations, end].
    /// Requires the actual start/end positions to be provided.
    pub fn render_points(&self, start: Point2d, end: Point2d) -> Vec<Point2d> {
        let mut points = Vec::with_capacity(self.articulation_points.len() + 2);
        points.push(start);
        points.extend_from_slice(&self.articulation_points);
        points.push(end);
        points
    }
}

impl PartialEq for AbstractVisualEdge {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for AbstractVisualEdge {}

impl std::hash::Hash for AbstractVisualEdge {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

// ============================================================================
// Edge renderer configurations
// ============================================================================

/// Rendering style for an edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeRenderingStyle {
    /// Straight line between start and end.
    Straight,
    /// Orthogonal (right-angle) routing.
    Orthogonal,
    /// Curved (bezier) routing.
    Curved,
    /// Articulated: goes through explicit intermediate points.
    Articulated,
}

impl Default for EdgeRenderingStyle {
    fn default() -> Self {
        Self::Straight
    }
}

/// Configuration for edge rendering.
///
/// Ports `ghidra.graph.viewer.edge.VisualEdgeRenderer`.
#[derive(Debug, Clone)]
pub struct EdgeRendererConfig {
    /// Default rendering style.
    pub style: EdgeRenderingStyle,
    /// Default edge color.
    pub color: RgbaColor,
    /// Selected edge color.
    pub selected_color: RgbaColor,
    /// Hovered edge color.
    pub hovered_color: RgbaColor,
    /// Emphasized edge color.
    pub emphasized_color: RgbaColor,
    /// Line width in pixels.
    pub line_width: f32,
    /// Whether to show edge arrows.
    pub show_arrows: bool,
    /// Whether to show edge labels.
    pub show_labels: bool,
    /// Arrow size in pixels.
    pub arrow_size: f32,
}

impl Default for EdgeRendererConfig {
    fn default() -> Self {
        Self {
            style: EdgeRenderingStyle::default(),
            color: RgbaColor::new(120, 120, 120, 255),
            selected_color: RgbaColor::new(50, 100, 255, 255),
            hovered_color: RgbaColor::new(150, 150, 200, 255),
            emphasized_color: RgbaColor::new(255, 180, 50, 255),
            line_width: 1.5,
            show_arrows: true,
            show_labels: false,
            arrow_size: 8.0,
        }
    }
}

impl EdgeRendererConfig {
    /// Get the color based on edge state.
    pub fn color_for_state(&self, selected: bool, hovered: bool, emphasized: bool) -> RgbaColor {
        if selected {
            return self.selected_color;
        }
        if emphasized {
            return self.emphasized_color;
        }
        if hovered {
            return self.hovered_color;
        }
        self.color
    }
}

// ============================================================================
// Edge label renderer
// ============================================================================

/// Renderer for edge labels.
///
/// Ports `ghidra.graph.viewer.edge.BasicEdgeLabelRenderer`.
#[derive(Debug, Clone, Default)]
pub struct EdgeLabelRenderer {
    /// Font size in pixels.
    pub font_size: f32,
    /// Label text color.
    pub text_color: RgbaColor,
    /// Label background color (transparent by default).
    pub background_color: RgbaColor,
    /// Padding around the label text.
    pub padding: f32,
}

impl EdgeLabelRenderer {
    /// Create a new edge label renderer with defaults.
    pub fn new() -> Self {
        Self {
            font_size: 11.0,
            text_color: RgbaColor::new(200, 200, 200, 255),
            background_color: RgbaColor::new(0, 0, 0, 0),
            padding: 2.0,
        }
    }
}

// ============================================================================
// Edge routing
// ============================================================================

/// Computes articulated edge paths that avoid vertex overlaps.
///
/// Ports `ghidra.graph.viewer.edge.routing.ArticulatedEdgeRouter`.
#[derive(Debug, Default)]
pub struct ArticulatedEdgeRouter;

impl ArticulatedEdgeRouter {
    /// Compute articulation points for an edge between two rectangular vertices.
    ///
    /// Returns intermediate points that route the edge around obstacles.
    pub fn compute_route(
        start_center: Point2d,
        start_size: (f64, f64),
        end_center: Point2d,
        end_size: (f64, f64),
    ) -> Vec<Point2d> {
        // Simple routing: go from bottom of source to top of target
        // with a midpoint if they're not aligned vertically.
        let start_bottom = Point2d::new(start_center.x, start_center.y + start_size.1 / 2.0);
        let end_top = Point2d::new(end_center.x, end_center.y - end_size.1 / 2.0);

        // If the endpoints are nearly vertically aligned, no articulation needed.
        let dx = (start_bottom.x - end_top.x).abs();
        if dx < 5.0 {
            return Vec::new();
        }

        // Route through a midpoint.
        let mid_y = (start_bottom.y + end_top.y) / 2.0;
        vec![Point2d::new(start_bottom.x, mid_y), Point2d::new(end_top.x, mid_y)]
    }
}

/// Basic edge router that draws straight lines.
///
/// Ports `ghidra.graph.viewer.edge.routing.BasicEdgeRouter`.
#[derive(Debug, Default)]
pub struct BasicEdgeRouter;

impl BasicEdgeRouter {
    /// Return an empty articulation set (straight line).
    pub fn compute_route() -> Vec<Point2d> {
        Vec::new()
    }
}

// ============================================================================
// Path highlighter -- highlights paths between selected vertices
// ============================================================================

/// Manages path highlighting between selected vertices.
///
/// Ports `ghidra.graph.viewer.edge.VisualGraphPathHighlighter`.
#[derive(Debug, Default)]
pub struct PathHighlighter {
    /// Edge IDs that are currently highlighted as part of a path.
    highlighted_edges: Vec<usize>,
    /// Vertex IDs that are currently highlighted as part of a path.
    highlighted_vertices: Vec<usize>,
    /// Whether path highlighting is active.
    active: bool,
}

impl PathHighlighter {
    /// Create a new path highlighter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the highlighted path (a sequence of vertex and edge IDs).
    pub fn set_highlighted_path(&mut self, vertices: Vec<usize>, edges: Vec<usize>) {
        self.highlighted_vertices = vertices;
        self.highlighted_edges = edges;
        self.active = true;
    }

    /// Get the highlighted edge IDs.
    pub fn highlighted_edges(&self) -> &[usize] {
        &self.highlighted_edges
    }

    /// Get the highlighted vertex IDs.
    pub fn highlighted_vertices(&self) -> &[usize] {
        &self.highlighted_vertices
    }

    /// Whether path highlighting is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Clear path highlighting.
    pub fn clear(&mut self) {
        self.highlighted_edges.clear();
        self.highlighted_vertices.clear();
        self.active = false;
    }
}

/// Listener for path highlight changes.
///
/// Ports `ghidra.graph.viewer.edge.PathHighlightListener`.
pub trait PathHighlightListener: std::fmt::Debug + Send + Sync {
    /// Called when the highlighted path changes.
    fn path_changed(&self, vertices: &[usize], edges: &[usize]);
}

// ============================================================================
// Edge stroke transformer
// ============================================================================

/// Controls the stroke (width, dash pattern) of edges based on their state.
///
/// Ports `ghidra.graph.viewer.edge.VisualGraphEdgeStrokeTransformer`.
#[derive(Debug, Clone)]
pub struct EdgeStrokeTransformer {
    /// Default line width.
    pub default_width: f32,
    /// Selected line width.
    pub selected_width: f32,
    /// Hovered line width.
    pub hovered_width: f32,
    /// Highlighted (path) line width.
    pub highlighted_width: f32,
    /// Whether to use dashed lines for highlighted edges.
    pub dashed_highlight: bool,
}

impl Default for EdgeStrokeTransformer {
    fn default() -> Self {
        Self {
            default_width: 1.5,
            selected_width: 2.5,
            hovered_width: 2.0,
            highlighted_width: 3.0,
            dashed_highlight: false,
        }
    }
}

impl EdgeStrokeTransformer {
    /// Get the line width for the given edge state.
    pub fn width_for_state(&self, selected: bool, hovered: bool, highlighted: bool) -> f32 {
        if highlighted {
            return self.highlighted_width;
        }
        if selected {
            return self.selected_width;
        }
        if hovered {
            return self.hovered_width;
        }
        self.default_width
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abstract_visual_edge() {
        let mut e = AbstractVisualEdge::new(1, 10, 20);
        assert_eq!(e.start_id(), 10);
        assert_eq!(e.end_id(), 20);
        assert!(!e.is_selected());

        e.set_selected(true);
        assert!(e.is_selected());

        e.add_articulation_point(Point2d::new(50.0, 100.0));
        assert!(e.has_articulation_points());
        assert_eq!(e.articulation_points().len(), 1);
    }

    #[test]
    fn test_edge_render_points() {
        let mut e = AbstractVisualEdge::new(1, 10, 20);
        e.add_articulation_point(Point2d::new(50.0, 100.0));
        let points = e.render_points(Point2d::new(0.0, 0.0), Point2d::new(100.0, 100.0));
        assert_eq!(points.len(), 3);
        assert_eq!(points[0], Point2d::new(0.0, 0.0));
        assert_eq!(points[1], Point2d::new(50.0, 100.0));
        assert_eq!(points[2], Point2d::new(100.0, 100.0));
    }

    #[test]
    fn test_edge_renderer_config() {
        let config = EdgeRendererConfig::default();
        let color = config.color_for_state(false, false, false);
        assert_eq!(color, config.color);

        let color = config.color_for_state(true, false, false);
        assert_eq!(color, config.selected_color);
    }

    #[test]
    fn test_articulated_edge_router() {
        let points = ArticulatedEdgeRouter::compute_route(
            Point2d::new(0.0, 0.0),
            (100.0, 30.0),
            Point2d::new(200.0, 200.0),
            (100.0, 30.0),
        );
        assert_eq!(points.len(), 2); // Two articulation points for misaligned vertices
    }

    #[test]
    fn test_path_highlighter() {
        let mut ph = PathHighlighter::new();
        assert!(!ph.is_active());

        ph.set_highlighted_path(vec![1, 2, 3], vec![10, 20]);
        assert!(ph.is_active());
        assert_eq!(ph.highlighted_vertices().len(), 3);

        ph.clear();
        assert!(!ph.is_active());
    }

    #[test]
    fn test_edge_stroke_transformer() {
        let transformer = EdgeStrokeTransformer::default();
        assert_eq!(transformer.width_for_state(false, false, false), 1.5);
        assert_eq!(transformer.width_for_state(true, false, false), 2.5);
        assert_eq!(transformer.width_for_state(false, false, true), 3.0);
    }
}
