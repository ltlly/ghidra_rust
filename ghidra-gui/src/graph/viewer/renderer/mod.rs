//! Graph rendering pipeline.
//!
//! Ports `ghidra.graph.viewer.renderer` package.

// New modules ported from Ghidra's graph viewer renderer package
pub mod paintable_shape;
pub mod debug_shape;
pub mod articulated_edge_renderer;
pub mod vertex_satellite_renderer;
pub mod edge_label_renderer;
pub mod visual_graph_renderer;
pub mod paintable_shapes_ext;

use crate::graph::viewer::edge::EdgeRenderConfig;
use crate::graph::service::VertexShape;
use crate::graph::viewer::{Rect2D, VisualEdge, VisualGraph, VisualVertex};

/// Rendering context that holds current rendering state and configuration.
#[derive(Debug, Clone)]
pub struct RenderContext {
    /// Vertex fill color (CSS hex string).
    pub vertex_fill_color: String,
    /// Vertex border color.
    pub vertex_border_color: String,
    /// Vertex border width in pixels.
    pub vertex_border_width: f32,
    /// Vertex label font size.
    pub vertex_font_size: f32,
    /// Edge render configuration.
    pub edge_config: EdgeRenderConfig,
    /// Whether to render vertex labels.
    pub show_vertex_labels: bool,
    /// Whether to render edge labels.
    pub show_edge_labels: bool,
    /// Background color.
    pub background_color: String,
}

impl Default for RenderContext {
    fn default() -> Self {
        Self {
            vertex_fill_color: "#FFFFFF".to_string(),
            vertex_border_color: "#333333".to_string(),
            vertex_border_width: 1.0,
            vertex_font_size: 12.0,
            edge_config: EdgeRenderConfig::default(),
            show_vertex_labels: true,
            show_edge_labels: false,
            background_color: "#FAFAFA".to_string(),
        }
    }
}

/// A render command representing a single drawing operation.
#[derive(Debug, Clone)]
pub enum RenderCommand {
    /// Fill a rectangle.
    FillRect {
        /// The rectangle bounds.
        rect: Rect2D,
        /// Fill color (CSS hex).
        color: String,
        /// Corner radius for rounded rectangles.
        corner_radius: f32,
    },
    /// Stroke (outline) a rectangle.
    StrokeRect {
        /// The rectangle bounds.
        rect: Rect2D,
        /// Stroke color.
        color: String,
        /// Line width.
        line_width: f32,
    },
    /// Draw a line segment.
    DrawLine {
        /// Start point.
        x1: f64,
        y1: f64,
        /// End point.
        x2: f64,
        y2: f64,
        /// Line color.
        color: String,
        /// Line width.
        line_width: f32,
    },
    /// Draw a text label.
    DrawText {
        /// Text content.
        text: String,
        /// Position.
        x: f64,
        y: f64,
        /// Font size.
        font_size: f32,
        /// Text color.
        color: String,
    },
    /// Draw an ellipse.
    FillEllipse {
        /// Center x.
        cx: f64,
        /// Center y.
        cy: f64,
        /// X radius.
        rx: f64,
        /// Y radius.
        ry: f64,
        /// Fill color.
        color: String,
    },
    /// Draw a polygon (for diamonds, etc.).
    FillPolygon {
        /// Ordered vertices of the polygon.
        points: Vec<(f64, f64)>,
        /// Fill color.
        color: String,
    },
    /// Draw an arrowhead.
    DrawArrow {
        /// Triangle vertices: (tip, left_wing, right_wing).
        points: [(f64, f64); 3],
        /// Fill color.
        color: String,
    },
}

/// The graph renderer translates a VisualGraph into a sequence of
/// RenderCommands that can be executed by any graphics backend.
#[derive(Debug, Clone, Default)]
pub struct GraphRenderer {
    context: RenderContext,
}

impl GraphRenderer {
    /// Create a new graph renderer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a renderer with a custom context.
    pub fn with_context(context: RenderContext) -> Self {
        Self { context }
    }

    /// Get the render context.
    pub fn context(&self) -> &RenderContext {
        &self.context
    }

    /// Get the render context mutably.
    pub fn context_mut(&mut self) -> &mut RenderContext {
        &mut self.context
    }

    /// Render the graph into a list of render commands.
    pub fn render(&self, graph: &VisualGraph) -> Vec<RenderCommand> {
        let mut commands = Vec::new();

        // Render edges first (behind vertices).
        for edge in graph.edges() {
            commands.extend(self.render_edge(edge, graph));
        }

        // Render vertices on top.
        for vertex in graph.vertices() {
            commands.extend(self.render_vertex(vertex));
        }

        commands
    }

    /// Render a single vertex.
    fn render_vertex(&self, vertex: &VisualVertex) -> Vec<RenderCommand> {
        let mut commands = Vec::new();
        let rect = vertex.bounding_rect();
        let fill = if vertex.selected {
            "#BBDDFF".to_string()
        } else if vertex.focused {
            "#DDDDFF".to_string()
        } else {
            self.context.vertex_fill_color.clone()
        };

        match vertex.shape {
            VertexShape::Rectangle | VertexShape::RoundedRectangle => {
                let radius = if vertex.shape == VertexShape::RoundedRectangle { 8.0 } else { 0.0 };
                commands.push(RenderCommand::FillRect {
                    rect,
                    color: fill,
                    corner_radius: radius,
                });
                commands.push(RenderCommand::StrokeRect {
                    rect,
                    color: self.context.vertex_border_color.clone(),
                    line_width: self.context.vertex_border_width,
                });
            }
            VertexShape::Ellipse => {
                let center = rect.center();
                commands.push(RenderCommand::FillEllipse {
                    cx: center.x,
                    cy: center.y,
                    rx: rect.width / 2.0,
                    ry: rect.height / 2.0,
                    color: fill,
                });
            }
            VertexShape::Diamond => {
                let center = rect.center();
                let hw = rect.width / 2.0;
                let hh = rect.height / 2.0;
                commands.push(RenderCommand::FillPolygon {
                    points: vec![
                        (center.x, center.y - hh), // top
                        (center.x + hw, center.y),  // right
                        (center.x, center.y + hh),  // bottom
                        (center.x - hw, center.y),  // left
                    ],
                    color: fill,
                });
            }
            VertexShape::TriangleUp => {
                let center = rect.center();
                let hw = rect.width / 2.0;
                let hh = rect.height / 2.0;
                commands.push(RenderCommand::FillPolygon {
                    points: vec![
                        (center.x - hw, center.y + hh),
                        (center.x + hw, center.y + hh),
                        (center.x, center.y - hh),
                    ],
                    color: fill,
                });
            }
            VertexShape::TriangleDown => {
                let center = rect.center();
                let hw = rect.width / 2.0;
                let hh = rect.height / 2.0;
                commands.push(RenderCommand::FillPolygon {
                    points: vec![
                        (center.x - hw, center.y - hh),
                        (center.x + hw, center.y - hh),
                        (center.x, center.y + hh),
                    ],
                    color: fill,
                });
            }
            VertexShape::Star => {
                let center = rect.center();
                let r = rect.width.min(rect.height) / 2.0;
                let points = polygon_points(center.x, center.y, r, 7, 0.5, std::f64::consts::PI * 1.5);
                commands.push(RenderCommand::FillPolygon { points, color: fill });
            }
            VertexShape::Pentagon => {
                let center = rect.center();
                let r = rect.width.min(rect.height) / 2.0;
                let points = polygon_points(center.x, center.y, r, 5, 1.0, std::f64::consts::PI + std::f64::consts::PI / 10.0);
                commands.push(RenderCommand::FillPolygon { points, color: fill });
            }
            VertexShape::Hexagon => {
                let center = rect.center();
                let r = rect.width.min(rect.height) / 2.0;
                let points = polygon_points(center.x, center.y, r, 6, 1.0, 0.0);
                commands.push(RenderCommand::FillPolygon { points, color: fill });
            }
            VertexShape::Octagon => {
                let center = rect.center();
                let r = rect.width.min(rect.height) / 2.0;
                let points = polygon_points(center.x, center.y, r, 8, 1.0, 0.0);
                commands.push(RenderCommand::FillPolygon { points, color: fill });
            }
        }

        // Label
        if self.context.show_vertex_labels {
            let center = rect.center();
            commands.push(RenderCommand::DrawText {
                text: vertex.label.clone(),
                x: center.x,
                y: center.y,
                font_size: self.context.vertex_font_size,
                color: "#000000".to_string(),
            });
        }

        commands
    }

    /// Render a single edge.
    fn render_edge(&self, edge: &VisualEdge, graph: &VisualGraph) -> Vec<RenderCommand> {
        let mut commands = Vec::new();

        let color = if edge.highlighted || edge.hovered {
            self.context.edge_config.highlight_color.clone()
        } else {
            self.context.edge_config.color.clone()
        };

        // Draw edge segments.
        let points = if edge.articulations.len() >= 2 {
            edge.articulations.clone()
        } else if let (Some(from), Some(to)) = (graph.vertex(&edge.from_id), graph.vertex(&edge.to_id)) {
            vec![from.center(), to.center()]
        } else {
            return commands;
        };

        for window in points.windows(2) {
            commands.push(RenderCommand::DrawLine {
                x1: window[0].x,
                y1: window[0].y,
                x2: window[1].x,
                y2: window[1].y,
                color: color.clone(),
                line_width: self.context.edge_config.stroke_width,
            });
        }

        // Draw arrowhead at the end.
        if self.context.edge_config.show_arrow && points.len() >= 2 {
            let n = points.len();
            let from = points[n - 2];
            let to = points[n - 1];
            let arrow_renderer = crate::graph::viewer::edge::EdgeArrowRenderer::new();
            let (tip, left, right) = arrow_renderer.arrow_points(&from, &to);
            commands.push(RenderCommand::DrawArrow {
                points: [
                    (tip.x, tip.y),
                    (left.x, left.y),
                    (right.x, right.y),
                ],
                color,
            });
        }

        commands
    }
}

/// Generate polygon points for a shape centered at (cx, cy).
///
/// `num_points` is the number of vertices. For stars, `inner_ratio` is the
/// ratio of inner radius to outer radius. `start_angle` is the initial angle
/// in radians.
fn polygon_points(
    cx: f64,
    cy: f64,
    radius: f64,
    num_points: usize,
    inner_ratio: f64,
    start_angle: f64,
) -> Vec<(f64, f64)> {
    if inner_ratio < 1.0 {
        // Star pattern: alternate between outer and inner radii
        let outer_r = radius;
        let inner_r = radius * inner_ratio;
        let delta = std::f64::consts::PI / num_points as f64;
        let mut angle = start_angle;
        let mut pts = Vec::with_capacity(num_points * 2 + 1);
        // First outer point
        pts.push((cx + outer_r * angle.cos(), cy + outer_r * angle.sin()));
        for _ in 0..num_points {
            angle += delta;
            pts.push((cx + inner_r * angle.cos(), cy + inner_r * angle.sin()));
            angle += delta;
            pts.push((cx + outer_r * angle.cos(), cy + outer_r * angle.sin()));
        }
        pts
    } else {
        // Regular polygon
        let delta = std::f64::consts::TAU / num_points as f64;
        let mut angle = start_angle;
        (0..num_points)
            .map(|_| {
                let pt = (cx + radius * angle.cos(), cy + radius * angle.sin());
                angle += delta;
                pt
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::viewer::{Point2D, VisualVertex};

    #[test]
    fn render_empty_graph() {
        let renderer = GraphRenderer::new();
        let graph = VisualGraph::new();
        let commands = renderer.render(&graph);
        assert!(commands.is_empty());
    }

    #[test]
    fn render_single_vertex() {
        let renderer = GraphRenderer::new();
        let mut graph = VisualGraph::new();
        graph.add_vertex(VisualVertex::new("v1", "Hello"));
        let commands = renderer.render(&graph);
        assert!(!commands.is_empty());
        // Should have at least fill + stroke + text
        assert!(commands.len() >= 2);
    }

    #[test]
    fn render_vertex_with_edge() {
        let renderer = GraphRenderer::new();
        let mut graph = VisualGraph::new();
        graph.add_vertex(VisualVertex::new("a", "A"));
        graph.add_vertex(VisualVertex::new("b", "B"));
        graph.add_edge(VisualEdge::new("e1", "a", "b"));
        let commands = renderer.render(&graph);
        // Edge commands + vertex commands
        assert!(commands.len() >= 4);
    }

    #[test]
    fn render_selected_vertex_uses_different_color() {
        let renderer = GraphRenderer::new();
        let mut graph = VisualGraph::new();
        let mut v = VisualVertex::new("v1", "V");
        v.selected = true;
        graph.add_vertex(v);
        let commands = renderer.render(&graph);
        // The fill rect should use the selected color
        if let Some(RenderCommand::FillRect { color, .. }) = commands.first() {
            assert_eq!(color, "#BBDDFF");
        }
    }

    #[test]
    fn render_diamond_vertex() {
        let renderer = GraphRenderer::new();
        let mut graph = VisualGraph::new();
        let mut v = VisualVertex::new("v1", "D");
        v.shape = VertexShape::Diamond;
        graph.add_vertex(v);
        let commands = renderer.render(&graph);
        assert!(commands.iter().any(|c| matches!(c, RenderCommand::FillPolygon { .. })));
    }

    #[test]
    fn render_ellipse_vertex() {
        let renderer = GraphRenderer::new();
        let mut graph = VisualGraph::new();
        let mut v = VisualVertex::new("v1", "E");
        v.shape = VertexShape::Ellipse;
        graph.add_vertex(v);
        let commands = renderer.render(&graph);
        assert!(commands.iter().any(|c| matches!(c, RenderCommand::FillEllipse { .. })));
    }

    #[test]
    fn render_arrow_on_edge() {
        let renderer = GraphRenderer::new();
        let mut graph = VisualGraph::new();
        graph.add_vertex(VisualVertex::new("a", "A"));
        graph.add_vertex(VisualVertex::new("b", "B"));
        graph.add_edge(VisualEdge::new("e1", "a", "b"));
        let commands = renderer.render(&graph);
        assert!(commands.iter().any(|c| matches!(c, RenderCommand::DrawArrow { .. })));
    }

    #[test]
    fn custom_render_context() {
        let ctx = RenderContext {
            show_vertex_labels: false,
            background_color: "#000000".to_string(),
            ..Default::default()
        };
        let renderer = GraphRenderer::with_context(ctx);
        let mut graph = VisualGraph::new();
        graph.add_vertex(VisualVertex::new("v1", "V"));
        let commands = renderer.render(&graph);
        // No DrawText since labels are hidden
        assert!(!commands.iter().any(|c| matches!(c, RenderCommand::DrawText { .. })));
    }
}
