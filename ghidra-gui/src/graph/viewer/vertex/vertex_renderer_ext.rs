//! Extended vertex renderer types.
//!
//! Ports Ghidra's vertex rendering classes:
//! - [`AbstractVisualVertexRenderer`] -- base class for vertex renderers.
//! - [`DockingVisualVertex`] -- vertex with docking panel support.

use super::super::{Point2D, Rect2D, VisualVertex};
use super::super::renderer::RenderCommand;
use crate::graph::service::VertexShape;

/// Abstract base for visual vertex renderers.
///
/// Ports `ghidra.graph.viewer.vertex.AbstractVisualVertexRenderer`.
/// Provides a template method pattern for rendering vertices: subclasses
/// customize the fill, border, and label rendering.
#[derive(Debug, Clone)]
pub struct AbstractVisualVertexRenderer {
    /// Default fill color.
    pub fill_color: String,
    /// Default border color.
    pub border_color: String,
    /// Default border width.
    pub border_width: f32,
    /// Selected fill color.
    pub selected_fill_color: String,
    /// Selected border color.
    pub selected_border_color: String,
    /// Focused fill color.
    pub focused_fill_color: String,
    /// Font size for labels.
    pub font_size: f32,
}

impl AbstractVisualVertexRenderer {
    /// Create a new abstract vertex renderer with default colors.
    pub fn new() -> Self {
        Self {
            fill_color: "#FFFFFF".to_string(),
            border_color: "#333333".to_string(),
            border_width: 1.0,
            selected_fill_color: "#BBDDFF".to_string(),
            selected_border_color: "#4488CC".to_string(),
            focused_fill_color: "#DDDDFF".to_string(),
            font_size: 12.0,
        }
    }

    /// Determine the fill color for a vertex based on its state.
    pub fn compute_fill_color(&self, vertex: &VisualVertex) -> String {
        if vertex.selected {
            self.selected_fill_color.clone()
        } else if vertex.focused {
            self.focused_fill_color.clone()
        } else {
            self.fill_color.clone()
        }
    }

    /// Determine the border color for a vertex.
    pub fn compute_border_color(&self, vertex: &VisualVertex) -> String {
        if vertex.selected {
            self.selected_border_color.clone()
        } else {
            self.border_color.clone()
        }
    }

    /// Render a vertex into render commands.
    pub fn render(&self, vertex: &VisualVertex) -> Vec<RenderCommand> {
        let mut commands = Vec::new();
        let rect = vertex.bounding_rect();
        let fill = self.compute_fill_color(vertex);
        let border = self.compute_border_color(vertex);

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
                    color: border,
                    line_width: self.border_width,
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
                // Render as ellipse for polygon shapes without dedicated polygon rendering
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

        // Label
        let center = rect.center();
        commands.push(RenderCommand::DrawText {
            text: vertex.label.clone(),
            x: center.x,
            y: center.y,
            font_size: self.font_size,
            color: "#000000".to_string(),
        });

        commands
    }
}

impl Default for AbstractVisualVertexRenderer {
    fn default() -> Self {
        Self::new()
    }
}

/// A visual vertex with docking panel support.
///
/// Ports `ghidra.graph.viewer.vertex.DockingVisualVertex`.
/// Extends a visual vertex with the ability to host a docking panel
/// (component) for inline editing.
#[derive(Debug, Clone)]
pub struct DockingVisualVertex {
    /// The underlying visual vertex data.
    pub vertex: VisualVertex,
    /// Whether this vertex has a docking panel.
    pub has_dock: bool,
    /// The panel title.
    pub panel_title: String,
    /// Whether the panel is expanded.
    pub panel_expanded: bool,
    /// The panel size when expanded.
    pub panel_size: (f64, f64),
}

impl DockingVisualVertex {
    /// Create a new docking visual vertex.
    pub fn new(vertex: VisualVertex) -> Self {
        Self {
            vertex,
            has_dock: false,
            panel_title: String::new(),
            panel_expanded: false,
            panel_size: (200.0, 150.0),
        }
    }

    /// Enable docking panel with a title.
    pub fn with_panel(mut self, title: impl Into<String>) -> Self {
        self.has_dock = true;
        self.panel_title = title.into();
        self
    }

    /// Expand or collapse the panel.
    pub fn set_panel_expanded(&mut self, expanded: bool) {
        self.panel_expanded = expanded;
    }

    /// Get the bounding rectangle including the panel if expanded.
    pub fn full_bounding_rect(&self) -> Rect2D {
        let base = self.vertex.bounding_rect();
        if self.has_dock && self.panel_expanded {
            Rect2D::new(
                base.x,
                base.y,
                base.width.max(self.panel_size.0),
                base.height + self.panel_size.1,
            )
        } else {
            base
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abstract_renderer_default() {
        let renderer = AbstractVisualVertexRenderer::new();
        assert_eq!(renderer.fill_color, "#FFFFFF");
        assert_eq!(renderer.selected_fill_color, "#BBDDFF");
    }

    #[test]
    fn compute_fill_color_normal() {
        let renderer = AbstractVisualVertexRenderer::new();
        let v = VisualVertex::new("v1", "Test");
        assert_eq!(renderer.compute_fill_color(&v), "#FFFFFF");
    }

    #[test]
    fn compute_fill_color_selected() {
        let renderer = AbstractVisualVertexRenderer::new();
        let mut v = VisualVertex::new("v1", "Test");
        v.selected = true;
        assert_eq!(renderer.compute_fill_color(&v), "#BBDDFF");
    }

    #[test]
    fn render_vertex_commands() {
        let renderer = AbstractVisualVertexRenderer::new();
        let v = VisualVertex::new("v1", "Hello");
        let commands = renderer.render(&v);
        // FillRect + StrokeRect + DrawText
        assert!(commands.len() >= 3);
    }

    #[test]
    fn docking_vertex_no_panel() {
        let v = VisualVertex::new("v1", "Test");
        let dock = DockingVisualVertex::new(v);
        assert!(!dock.has_dock);
        assert!(!dock.panel_expanded);
    }

    #[test]
    fn docking_vertex_with_panel() {
        let v = VisualVertex::new("v1", "Test");
        let mut dock = DockingVisualVertex::new(v).with_panel("Details");
        assert!(dock.has_dock);
        assert_eq!(dock.panel_title, "Details");
        dock.set_panel_expanded(true);
        let rect = dock.full_bounding_rect();
        assert!(rect.height > 40.0); // expanded should be taller
    }
}
