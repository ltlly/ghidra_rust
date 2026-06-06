//! Visual vertex and edge interfaces.
//!
//! Port of Ghidra's `ghidra.graph.viewer.VisualVertex` and
//! `ghidra.graph.viewer.VisualEdge`.

use super::Point2D;

/// Trait for visual vertices in a graph viewer.
///
/// Port of `ghidra.graph.viewer.VisualVertex`.
pub trait VisualVertex: std::fmt::Debug {
    /// Get the vertex id.
    fn id(&self) -> &str;

    /// Get the vertex position.
    fn position(&self) -> Point2D;

    /// Set the vertex position.
    fn set_position(&mut self, pos: Point2D);

    /// Whether this vertex is selected.
    fn is_selected(&self) -> bool;

    /// Set whether this vertex is selected.
    fn set_selected(&mut self, selected: bool);

    /// Whether this vertex is visible.
    fn is_visible(&self) -> bool {
        true
    }

    /// Get the vertex label.
    fn label(&self) -> Option<&str> {
        None
    }
}

/// Trait for visual edges in a graph viewer.
///
/// Port of `ghidra.graph.viewer.VisualEdge`.
pub trait VisualEdge: std::fmt::Debug {
    /// Get the edge id.
    fn id(&self) -> &str;

    /// Get the source vertex id.
    fn source_id(&self) -> &str;

    /// Get the target vertex id.
    fn target_id(&self) -> &str;

    /// Whether this edge is selected.
    fn is_selected(&self) -> bool;

    /// Set whether this edge is selected.
    fn set_selected(&mut self, selected: bool);

    /// Whether this edge is visible.
    fn is_visible(&self) -> bool {
        true
    }

    /// Whether this edge is emphasized (hover highlight).
    fn is_emphasized(&self) -> bool {
        false
    }

    /// Set emphasis.
    fn set_emphasized(&mut self, emphasized: bool);
}

/// Vertex click listener callback.
///
/// Port of `ghidra.graph.viewer.vertex.VertexClickListener`.
pub trait VertexClickListener: std::fmt::Debug {
    /// Called when a vertex is clicked.
    fn vertex_clicked(&self, vertex_id: &str);
}

/// Vertex focus listener callback.
///
/// Port of `ghidra.graph.viewer.vertex.VertexFocusListener`.
pub trait VertexFocusListener: std::fmt::Debug {
    /// Called when a vertex gains focus.
    fn focus_gained(&self, vertex_id: &str);

    /// Called when a vertex loses focus.
    fn focus_lost(&self, vertex_id: &str);
}

/// Vertex shape provider trait.
///
/// Port of `ghidra.graph.viewer.vertex.VertexShapeProvider`.
pub trait VertexShapeProvider: std::fmt::Debug {
    /// Get the compact shape type for the vertex.
    fn shape_type(&self) -> VertexShapeType;

    /// Get the corner radius for rounded shapes.
    fn corner_radius(&self) -> f64 {
        8.0
    }
}

/// Shape type for a visual vertex.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VertexShapeType {
    /// Rounded rectangle.
    RoundedRectangle,
    /// Ellipse.
    Ellipse,
    /// Regular rectangle.
    Rectangle,
    /// Diamond.
    Diamond,
}

impl Default for VertexShapeType {
    fn default() -> Self {
        VertexShapeType::RoundedRectangle
    }
}

/// A vertex shape transformer that maps vertices to their shape.
///
/// Port of `ghidra.graph.viewer.vertex.VisualGraphVertexShapeTransformer`.
#[derive(Debug, Default)]
pub struct VisualGraphVertexShapeTransformer;

impl VisualGraphVertexShapeTransformer {
    /// Transform a vertex to its shape type.
    pub fn transform(&self, _vertex_id: &str) -> VertexShapeType {
        VertexShapeType::RoundedRectangle
    }
}

/// A docking visual vertex -- a vertex that has a "docked" state
/// within the graph component.
///
/// Port of `ghidra.graph.viewer.vertex.DockingVisualVertex`.
#[derive(Debug, Clone)]
pub struct DockingVisualVertex {
    /// Vertex id.
    pub id: String,
    /// Position.
    pub position: Point2D,
    /// Whether this vertex is the "center of attention" (docked).
    pub docked: bool,
    /// Whether selected.
    pub selected: bool,
}

impl DockingVisualVertex {
    /// Create a new docking visual vertex.
    pub fn new(id: impl Into<String>, position: Point2D) -> Self {
        Self { id: id.into(), position, docked: false, selected: false }
    }
}

impl VisualVertex for DockingVisualVertex {
    fn id(&self) -> &str {
        &self.id
    }
    fn position(&self) -> Point2D {
        self.position
    }
    fn set_position(&mut self, pos: Point2D) {
        self.position = pos;
    }
    fn is_selected(&self) -> bool {
        self.selected
    }
    fn set_selected(&mut self, selected: bool) {
        self.selected = selected;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_visual_vertex_shape_transformer() {
        let t = VisualGraphVertexShapeTransformer;
        assert_eq!(t.transform("v1"), VertexShapeType::RoundedRectangle);
    }

    #[test]
    fn test_docking_visual_vertex() {
        let mut v = DockingVisualVertex::new("v1", Point2D { x: 10.0, y: 20.0 });
        assert_eq!(v.id(), "v1");
        assert!(!v.is_selected());
        v.set_selected(true);
        assert!(v.is_selected());
    }
}
