//! Visual vertex rendering, shapes, and interaction.
//!
//! Ports `ghidra.graph.viewer.vertex` package.

use crate::graph::viewer::{Point2D, Rect2D, VisualVertex};
use crate::graph::service::VertexShape;

/// Trait for vertex shape providers.
///
/// Allows vertex implementations to provide custom shapes for
/// rendering vs. hit-testing.
pub trait VertexShapeProvider {
    /// The shape used for rendering the vertex.
    fn render_shape(&self) -> VertexShape;

    /// The shape used for hit-testing (click detection).
    /// By default, same as render shape.
    fn hit_test_shape(&self) -> VertexShape {
        self.render_shape()
    }
}

/// Transforms a vertex into its display shape.
///
/// Ports `ghidra.graph.viewer.vertex.VisualGraphVertexShapeTransformer`.
pub struct VertexShapeTransformer;

impl VertexShapeTransformer {
    /// Compute the shape bounds for a vertex.
    pub fn transform(vertex: &VisualVertex) -> VertexShapeGeometry {
        let rect = vertex.bounding_rect();
        VertexShapeGeometry {
            shape: vertex.shape,
            bounds: rect,
        }
    }
}

/// Geometry description of a vertex's rendered shape.
#[derive(Debug, Clone)]
pub struct VertexShapeGeometry {
    /// The shape type.
    pub shape: VertexShape,
    /// The bounding rectangle.
    pub bounds: Rect2D,
}

impl VertexShapeGeometry {
    /// Test if a point is inside the shape.
    pub fn contains(&self, point: Point2D) -> bool {
        match self.shape {
            VertexShape::Rectangle => self.bounds.contains(point),
            VertexShape::RoundedRectangle => {
                // Approximate: use rectangle for hit testing
                self.bounds.contains(point)
            }
            VertexShape::Ellipse => {
                let center = self.bounds.center();
                let rx = self.bounds.width / 2.0;
                let ry = self.bounds.height / 2.0;
                if rx == 0.0 || ry == 0.0 {
                    return false;
                }
                let dx = (point.x - center.x) / rx;
                let dy = (point.y - center.y) / ry;
                dx * dx + dy * dy <= 1.0
            }
            VertexShape::Diamond => {
                let center = self.bounds.center();
                let rx = self.bounds.width / 2.0;
                let ry = self.bounds.height / 2.0;
                if rx == 0.0 || ry == 0.0 {
                    return false;
                }
                let dx = (point.x - center.x).abs() / rx;
                let dy = (point.y - center.y).abs() / ry;
                dx + dy <= 1.0
            }
        }
    }
}

/// Trait for vertex click listeners.
pub trait VertexClickListener: Send + Sync {
    /// Called when a vertex is double-clicked.
    fn on_vertex_double_click(&self, vertex_id: &str);

    /// Called when a vertex is single-clicked.
    fn on_vertex_click(&self, vertex_id: &str);
}

/// Trait for vertex focus listeners.
pub trait VertexFocusListener: Send + Sync {
    /// Called when a vertex gains focus.
    fn on_vertex_focused(&self, vertex_id: &str);

    /// Called when a vertex loses focus.
    fn on_vertex_unfocused(&self, vertex_id: &str);
}

/// Mouse information for a vertex interaction event.
#[derive(Debug, Clone)]
pub struct VertexMouseInfo {
    /// The vertex id.
    pub vertex_id: String,
    /// Mouse position in graph coordinates.
    pub graph_point: Point2D,
    /// Mouse position in screen coordinates.
    pub screen_point: Point2D,
    /// Whether this was a double-click.
    pub is_double_click: bool,
    /// Mouse button (1 = left, 2 = middle, 3 = right).
    pub button: u8,
}

impl VertexMouseInfo {
    /// Create new vertex mouse info.
    pub fn new(vertex_id: impl Into<String>, graph_point: Point2D, screen_point: Point2D) -> Self {
        Self {
            vertex_id: vertex_id.into(),
            graph_point,
            screen_point,
            is_double_click: false,
            button: 1,
        }
    }
}

/// A visual vertex implementation with docking-style header.
///
/// Ports `ghidra.graph.viewer.vertex.DockingVisualVertex`.
#[derive(Debug, Clone)]
pub struct DockingVisualVertex {
    /// Base vertex data.
    pub vertex: VisualVertex,
    /// Header title text.
    pub header_title: String,
    /// Whether the header is collapsible.
    pub collapsible: bool,
    /// Whether the vertex is collapsed.
    pub collapsed: bool,
    /// Vertex emphasis level (0.0 - 1.0).
    pub emphasis: f64,
    /// Alpha transparency (0.0 - 1.0).
    pub alpha: f64,
}

impl DockingVisualVertex {
    /// Create a new docking visual vertex.
    pub fn new(id: impl Into<String>, label: impl Into<String>, header_title: impl Into<String>) -> Self {
        Self {
            vertex: VisualVertex::new(id, label),
            header_title: header_title.into(),
            collapsible: true,
            collapsed: false,
            emphasis: 0.0,
            alpha: 1.0,
        }
    }

    /// Toggle collapsed state.
    pub fn toggle_collapsed(&mut self) {
        if self.collapsible {
            self.collapsed = !self.collapsed;
        }
    }
}

/// Vertex tooltip provider trait.
pub trait VertexTooltipProvider: Send + Sync {
    /// Get tooltip text for a vertex.
    fn get_tooltip(&self, vertex_id: &str) -> Option<String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rectangle_contains() {
        let geom = VertexShapeGeometry {
            shape: VertexShape::Rectangle,
            bounds: Rect2D::new(0.0, 0.0, 100.0, 50.0),
        };
        assert!(geom.contains(Point2D::new(50.0, 25.0)));
        assert!(!geom.contains(Point2D::new(150.0, 25.0)));
    }

    #[test]
    fn ellipse_contains() {
        let geom = VertexShapeGeometry {
            shape: VertexShape::Ellipse,
            bounds: Rect2D::new(0.0, 0.0, 100.0, 80.0),
        };
        assert!(geom.contains(Point2D::new(50.0, 40.0))); // center
        assert!(!geom.contains(Point2D::new(150.0, 40.0))); // outside
    }

    #[test]
    fn diamond_contains() {
        let geom = VertexShapeGeometry {
            shape: VertexShape::Diamond,
            bounds: Rect2D::new(0.0, 0.0, 100.0, 100.0),
        };
        assert!(geom.contains(Point2D::new(50.0, 50.0))); // center
        assert!(geom.contains(Point2D::new(50.0, 10.0))); // near top
        assert!(!geom.contains(Point2D::new(10.0, 10.0))); // corner
    }

    #[test]
    fn shape_transformer() {
        let v = VisualVertex::new("v1", "Vertex 1");
        let geom = VertexShapeTransformer::transform(&v);
        assert_eq!(geom.shape, VertexShape::RoundedRectangle);
    }

    #[test]
    fn docking_vertex_toggle() {
        let mut dv = DockingVisualVertex::new("v1", "V1", "Header");
        assert!(!dv.collapsed);
        dv.toggle_collapsed();
        assert!(dv.collapsed);
        dv.toggle_collapsed();
        assert!(!dv.collapsed);
    }

    #[test]
    fn vertex_mouse_info() {
        let info = VertexMouseInfo::new("v1", Point2D::new(10.0, 20.0), Point2D::new(100.0, 200.0));
        assert_eq!(info.vertex_id, "v1");
        assert!(!info.is_double_click);
        assert_eq!(info.button, 1);
    }
}
