//! Visual graph renderer with Z-ordering support.
//!
//! Ports `ghidra.graph.viewer.renderer.VisualGraphRenderer`.
//!
//! The VisualGraphRenderer renders edges first, then vertices with a
//! Z-order that paints selected vertices on top of non-selected vertices.
//! This is necessary because the underlying graph library has no Z-order
//! concept.

use std::collections::HashMap;

use super::{RenderCommand, RenderContext};
use crate::graph::viewer::{Point2D, Rect2D, VisualEdge, VisualGraph, VisualVertex};
use crate::graph::service::VertexShape;

/// Painter for showing an underlying layout grid.
#[derive(Debug, Clone, Default)]
pub struct GridPainter {
    /// Grid line color.
    pub line_color: String,
    /// Grid cell width.
    pub cell_width: f64,
    /// Grid cell height.
    pub cell_height: f64,
    /// Whether the grid is visible.
    pub visible: bool,
}

impl GridPainter {
    /// Create a new grid painter.
    pub fn new() -> Self {
        Self {
            line_color: "#E0E0E0".to_string(),
            cell_width: 100.0,
            cell_height: 50.0,
            visible: false,
        }
    }

    /// Paint the layout grid cells into the render commands.
    pub fn paint_layout_grid_cells(&self, bounds: Rect2D) -> Vec<RenderCommand> {
        if !self.visible {
            return Vec::new();
        }
        let mut commands = Vec::new();
        let mut x = bounds.x;
        while x <= bounds.x + bounds.width {
            commands.push(RenderCommand::DrawLine {
                x1: x,
                y1: bounds.y,
                x2: x,
                y2: bounds.y + bounds.height,
                color: self.line_color.clone(),
                line_width: 0.5,
            });
            x += self.cell_width;
        }
        let mut y = bounds.y;
        while y <= bounds.y + bounds.height {
            commands.push(RenderCommand::DrawLine {
                x1: bounds.x,
                y1: y,
                x2: bounds.x + bounds.width,
                y2: y,
                color: self.line_color.clone(),
                line_width: 0.5,
            });
            y += self.cell_height;
        }
        commands
    }
}

/// The visual graph renderer.
///
/// Renders a graph with Z-ordering so that selected vertices appear above
/// other vertices. Ports `ghidra.graph.viewer.renderer.VisualGraphRenderer`.
///
/// # Rendering Order
///
/// 1. Grid (optional)
/// 2. Edges
/// 3. Vertices (sorted by selection state -- selected vertices last)
/// 4. Vertex labels
/// 5. Edge labels
#[derive(Debug, Clone)]
pub struct VisualGraphRenderer {
    /// Optional grid painter.
    grid_painter: Option<GridPainter>,
    /// Whether to render vertex labels.
    pub show_vertex_labels: bool,
    /// Whether to render edge labels.
    pub show_edge_labels: bool,
}

impl VisualGraphRenderer {
    /// Create a new visual graph renderer.
    pub fn new() -> Self {
        Self {
            grid_painter: None,
            show_vertex_labels: true,
            show_edge_labels: false,
        }
    }

    /// Set the grid painter.
    pub fn set_grid_painter(&mut self, painter: GridPainter) {
        self.grid_painter = Some(painter);
    }

    /// Render the graph with Z-ordering (selected vertices on top).
    pub fn render_ordered(&self, graph: &VisualGraph, context: &RenderContext) -> Vec<RenderCommand> {
        let mut commands = Vec::new();

        // 1. Grid
        if let Some(ref grid) = self.grid_painter {
            let bounds = graph.bounding_rect();
            commands.extend(grid.paint_layout_grid_cells(bounds));
        }

        // 2. Edges (behind vertices)
        for edge in graph.edges() {
            commands.extend(self.render_edge(edge, graph, context));
        }

        // 3. Vertices with Z-ordering
        let ordered_vertices = self.order_vertices_by_z(graph);
        for vertex in ordered_vertices {
            commands.extend(self.render_vertex(vertex, context));
        }

        // 4. Edge labels (on top)
        if self.show_edge_labels {
            for edge in graph.edges() {
                if let Some(label) = &edge.label {
                    if let (Some(from), Some(to)) =
                        (graph.vertex(&edge.from_id), graph.vertex(&edge.to_id))
                    {
                        let center = from.center().lerp(&to.center(), 0.5);
                        commands.push(RenderCommand::DrawText {
                            text: label.clone(),
                            x: center.x,
                            y: center.y,
                            font_size: 10.0,
                            color: "#666666".to_string(),
                        });
                    }
                }
            }
        }

        commands
    }

    /// Order vertices by Z-order: non-selected first, selected last.
    fn order_vertices_by_z<'a>(&self, graph: &'a VisualGraph) -> Vec<&'a VisualVertex> {
        let mut vertices = graph.vertices();
        vertices.sort_by_key(|v| if v.selected { 1 } else { 0 });
        vertices
    }

    fn render_vertex(&self, vertex: &VisualVertex, context: &RenderContext) -> Vec<RenderCommand> {
        let mut commands = Vec::new();
        let rect = vertex.bounding_rect();
        let fill = if vertex.selected {
            "#BBDDFF".to_string()
        } else if vertex.focused {
            "#DDDDFF".to_string()
        } else {
            context.vertex_fill_color.clone()
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
                    color: context.vertex_border_color.clone(),
                    line_width: context.vertex_border_width,
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
                        (center.x, center.y - hh),
                        (center.x + hw, center.y),
                        (center.x, center.y + hh),
                        (center.x - hw, center.y),
                    ],
                    color: fill,
                });
            }
            VertexShape::TriangleUp | VertexShape::TriangleDown => {
                let center = rect.center();
                let hw = rect.width / 2.0;
                let hh = rect.height / 2.0;
                let points = if vertex.shape == VertexShape::TriangleUp {
                    vec![(center.x - hw, center.y + hh), (center.x + hw, center.y + hh), (center.x, center.y - hh)]
                } else {
                    vec![(center.x - hw, center.y - hh), (center.x + hw, center.y - hh), (center.x, center.y + hh)]
                };
                commands.push(RenderCommand::FillPolygon { points, color: fill });
            }
            VertexShape::Star | VertexShape::Pentagon | VertexShape::Hexagon | VertexShape::Octagon => {
                let center = rect.center();
                commands.push(RenderCommand::FillEllipse {
                    cx: center.x,
                    cy: center.y,
                    rx: rect.width / 2.0,
                    ry: rect.height / 2.0,
                    color: fill,
                });
            }
        }

        if self.show_vertex_labels {
            let center = rect.center();
            commands.push(RenderCommand::DrawText {
                text: vertex.label.clone(),
                x: center.x,
                y: center.y,
                font_size: context.vertex_font_size,
                color: "#000000".to_string(),
            });
        }

        commands
    }

    fn render_edge(&self, edge: &VisualEdge, graph: &VisualGraph, context: &RenderContext) -> Vec<RenderCommand> {
        let mut commands = Vec::new();
        let color = if edge.highlighted || edge.hovered {
            context.edge_config.highlight_color.clone()
        } else {
            context.edge_config.color.clone()
        };

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
                line_width: context.edge_config.stroke_width,
            });
        }

        commands
    }
}

impl Default for VisualGraphRenderer {
    fn default() -> Self {
        Self::new()
    }
}

/// Render support for edge arrow rendering.
///
/// Ports `ghidra.graph.viewer.edge.VisualEdgeArrowRenderingSupport`.
#[derive(Debug, Clone, Default)]
pub struct VisualEdgeArrowRenderingSupport {
    /// Arrow size in pixels.
    pub arrow_size: f64,
    /// Whether to fill the arrow.
    pub filled: bool,
    /// Arrow outline color.
    pub outline_color: String,
}

impl VisualEdgeArrowRenderingSupport {
    /// Create a new arrow rendering support.
    pub fn new() -> Self {
        Self {
            arrow_size: 10.0,
            filled: true,
            outline_color: "#666666".to_string(),
        }
    }

    /// Compute arrow polygon points.
    pub fn compute_arrow(&self, from: &Point2D, to: &Point2D) -> Vec<Point2D> {
        let dx = to.x - from.x;
        let dy = to.y - from.y;
        let len = (dx * dx + dy * dy).sqrt();
        if len == 0.0 {
            return vec![*to; 3];
        }
        let ux = dx / len;
        let uy = dy / len;
        let px = -uy;
        let py = ux;
        let half = self.arrow_size / 2.0;
        let back = self.arrow_size;
        vec![
            *to,
            Point2D::new(to.x - ux * back + px * half, to.y - uy * back + py * half),
            Point2D::new(to.x - ux * back - px * half, to.y - uy * back - py * half),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visual_graph_renderer_default() {
        let renderer = VisualGraphRenderer::new();
        assert!(renderer.show_vertex_labels);
        assert!(!renderer.show_edge_labels);
        assert!(renderer.grid_painter.is_none());
    }

    #[test]
    fn render_ordered_empty_graph() {
        let renderer = VisualGraphRenderer::new();
        let graph = VisualGraph::new();
        let ctx = RenderContext::default();
        let commands = renderer.render_ordered(&graph, &ctx);
        assert!(commands.is_empty());
    }

    #[test]
    fn render_ordered_selected_on_top() {
        let renderer = VisualGraphRenderer::new();
        let mut graph = VisualGraph::new();
        let mut v1 = VisualVertex::new("v1", "A");
        v1.selected = false;
        let mut v2 = VisualVertex::new("v2", "B");
        v2.selected = true;
        graph.add_vertex(v1);
        graph.add_vertex(v2);
        let ctx = RenderContext::default();
        let commands = renderer.render_ordered(&graph, &ctx);
        // Both vertices should be rendered
        assert!(!commands.is_empty());
    }

    #[test]
    fn grid_painter_inactive() {
        let grid = GridPainter::new();
        assert!(!grid.visible);
        let commands = grid.paint_layout_grid_cells(Rect2D::new(0.0, 0.0, 100.0, 100.0));
        assert!(commands.is_empty());
    }

    #[test]
    fn grid_painter_active() {
        let mut grid = GridPainter::new();
        grid.visible = true;
        grid.cell_width = 50.0;
        grid.cell_height = 50.0;
        let commands = grid.paint_layout_grid_cells(Rect2D::new(0.0, 0.0, 100.0, 100.0));
        // Should have vertical and horizontal grid lines
        assert!(!commands.is_empty());
    }

    #[test]
    fn arrow_rendering_support() {
        let support = VisualEdgeArrowRenderingSupport::new();
        let from = Point2D::new(0.0, 0.0);
        let to = Point2D::new(100.0, 0.0);
        let points = support.compute_arrow(&from, &to);
        assert_eq!(points.len(), 3);
        assert_eq!(points[0], to); // tip
    }

    #[test]
    fn z_order_vertices() {
        let renderer = VisualGraphRenderer::new();
        let mut graph = VisualGraph::new();
        let mut v1 = VisualVertex::new("v1", "Not Selected");
        v1.selected = false;
        let mut v2 = VisualVertex::new("v2", "Selected");
        v2.selected = true;
        let mut v3 = VisualVertex::new("v3", "Not Selected 2");
        v3.selected = false;
        graph.add_vertex(v1);
        graph.add_vertex(v2);
        graph.add_vertex(v3);
        let ordered = renderer.order_vertices_by_z(&graph);
        assert_eq!(ordered.len(), 3);
        // Selected vertex should be last
        assert!(ordered[2].selected);
        assert!(!ordered[0].selected);
        assert!(!ordered[1].selected);
    }
}
