//! Base graph vertex types.
//!
//! Ported from `ghidra.base.graph` -- provides vertex shapes and expansion
//! listener interfaces for the graph visualization framework.
//!
//! # Types
//!
//! - [`CircleWithLabelVertex`]: A vertex rendered as a circle with a text label.
//! - [`VertexExpansionListener`]: Listener for vertex expansion/collapse events.
//! - [`VertexShapeProvider`]: Trait for vertices that provide their own shapes.

use std::fmt;

// ---------------------------------------------------------------------------
// VertexShapeProvider
// ---------------------------------------------------------------------------

/// Trait for vertices that provide their own shape for rendering.
///
/// Ported from `ghidra.graph.viewer.vertex.VertexShapeProvider`.
pub trait VertexShapeProvider: fmt::Debug {
    /// Get the compact shape (used when zoomed out).
    fn compact_shape(&self) -> VertexShape;

    /// Get the full shape (used when zoomed in).
    fn full_shape(&self) -> VertexShape;

    /// Get the vertex name/label.
    fn name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// VertexShape
// ---------------------------------------------------------------------------

/// Shape types for graph vertices.
#[derive(Debug, Clone, PartialEq)]
pub enum VertexShape {
    /// A circle with the given radius.
    Circle { radius: f64 },
    /// A rectangle with width and height.
    Rectangle { width: f64, height: f64 },
    /// A rounded rectangle.
    RoundedRectangle { width: f64, height: f64, arc: f64 },
    /// An ellipse.
    Ellipse { width: f64, height: f64 },
}

impl VertexShape {
    /// Create a circle shape.
    pub fn circle(radius: f64) -> Self {
        Self::Circle { radius }
    }

    /// Create a rectangle shape.
    pub fn rectangle(width: f64, height: f64) -> Self {
        Self::Rectangle { width, height }
    }

    /// Create a rounded rectangle shape.
    pub fn rounded_rectangle(width: f64, height: f64, arc: f64) -> Self {
        Self::RoundedRectangle { width, height, arc }
    }

    /// Create an ellipse shape.
    pub fn ellipse(width: f64, height: f64) -> Self {
        Self::Ellipse { width, height }
    }

    /// Get the bounding width.
    pub fn width(&self) -> f64 {
        match self {
            Self::Circle { radius } => radius * 2.0,
            Self::Rectangle { width, .. } => *width,
            Self::RoundedRectangle { width, .. } => *width,
            Self::Ellipse { width, .. } => *width,
        }
    }

    /// Get the bounding height.
    pub fn height(&self) -> f64 {
        match self {
            Self::Circle { radius } => radius * 2.0,
            Self::Rectangle { height, .. } => *height,
            Self::RoundedRectangle { height, .. } => *height,
            Self::Ellipse { height, .. } => *height,
        }
    }
}

// ---------------------------------------------------------------------------
// CircleWithLabelVertex
// ---------------------------------------------------------------------------

/// A vertex that is a circle shape with a label below the circle.
///
/// Ported from `ghidra.base.graph.CircleWithLabelVertex`.
#[derive(Debug, Clone)]
pub struct CircleWithLabelVertex {
    /// The vertex label.
    label: String,
    /// Circle radius.
    radius: f64,
    /// Font size for the label.
    font_size: f64,
}

impl CircleWithLabelVertex {
    /// Create a new circle-with-label vertex.
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            radius: 20.0,
            font_size: 12.0,
        }
    }

    /// Create with a specific radius.
    pub fn with_radius(mut self, radius: f64) -> Self {
        self.radius = radius;
        self
    }

    /// Create with a specific font size.
    pub fn with_font_size(mut self, font_size: f64) -> Self {
        self.font_size = font_size;
        self
    }

    /// Get the label.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Get the radius.
    pub fn radius(&self) -> f64 {
        self.radius
    }

    /// Get the font size.
    pub fn font_size(&self) -> f64 {
        self.font_size
    }
}

impl VertexShapeProvider for CircleWithLabelVertex {
    fn compact_shape(&self) -> VertexShape {
        VertexShape::circle(self.radius)
    }

    fn full_shape(&self) -> VertexShape {
        // Full shape includes label area below the circle.
        let width = self.radius * 2.0 + 20.0; // some padding
        let height = self.radius * 2.0 + self.font_size + 10.0; // circle + label
        VertexShape::rounded_rectangle(width, height, 5.0)
    }

    fn name(&self) -> &str {
        &self.label
    }
}

impl fmt::Display for CircleWithLabelVertex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label)
    }
}

// ---------------------------------------------------------------------------
// CircleWithLabelVertexShapeProvider
// ---------------------------------------------------------------------------

/// Standalone shape provider for circle-with-label vertices.
///
/// Ported from `CircleWithLabelVertexShapeProvider.java`.
#[derive(Debug, Clone)]
pub struct CircleWithLabelVertexShapeProvider {
    label: String,
    radius: f64,
}

impl CircleWithLabelVertexShapeProvider {
    /// Create a new shape provider.
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            radius: 20.0,
        }
    }

    /// Get the compact circle shape.
    pub fn compact_shape(&self) -> VertexShape {
        VertexShape::circle(self.radius)
    }

    /// Get the full shape with label.
    pub fn full_shape(&self) -> VertexShape {
        VertexShape::rounded_rectangle(
            self.radius * 2.0 + 20.0,
            self.radius * 2.0 + 20.0,
            5.0,
        )
    }

    /// Get the label.
    pub fn name(&self) -> &str {
        &self.label
    }
}

// ---------------------------------------------------------------------------
// VertexExpansionListener
// ---------------------------------------------------------------------------

/// Listener trait for vertex expansion/collapse events.
///
/// Ported from `ghidra.base.graph.VertexExpansionListener`.
pub trait VertexExpansionListener: fmt::Debug {
    /// Toggle (show/hide) vertices on incoming edges to the given vertex.
    fn toggle_incoming_vertices(&mut self, vertex_label: &str);

    /// Toggle (show/hide) vertices on outgoing edges from the given vertex.
    fn toggle_outgoing_vertices(&mut self, vertex_label: &str);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circle_with_label_vertex() {
        let v = CircleWithLabelVertex::new("main");
        assert_eq!(v.label(), "main");
        assert_eq!(v.radius(), 20.0);
        assert_eq!(v.font_size(), 12.0);
    }

    #[test]
    fn test_circle_with_label_vertex_builder() {
        let v = CircleWithLabelVertex::new("func")
            .with_radius(30.0)
            .with_font_size(14.0);
        assert_eq!(v.radius(), 30.0);
        assert_eq!(v.font_size(), 14.0);
    }

    #[test]
    fn test_circle_vertex_shape_provider() {
        let v = CircleWithLabelVertex::new("test");
        let compact = v.compact_shape();
        assert_eq!(compact, VertexShape::circle(20.0));
        assert_eq!(compact.width(), 40.0);

        let full = v.full_shape();
        assert!(full.width() > compact.width());
        assert!(full.height() > compact.height());
    }

    #[test]
    fn test_vertex_shapes() {
        let circle = VertexShape::circle(10.0);
        assert_eq!(circle.width(), 20.0);
        assert_eq!(circle.height(), 20.0);

        let rect = VertexShape::rectangle(100.0, 50.0);
        assert_eq!(rect.width(), 100.0);
        assert_eq!(rect.height(), 50.0);

        let ellipse = VertexShape::ellipse(80.0, 40.0);
        assert_eq!(ellipse.width(), 80.0);
        assert_eq!(ellipse.height(), 40.0);

        let rounded = VertexShape::rounded_rectangle(100.0, 50.0, 10.0);
        assert_eq!(rounded.width(), 100.0);
        assert_eq!(rounded.height(), 50.0);
    }

    #[test]
    fn test_vertex_display() {
        let v = CircleWithLabelVertex::new("printf");
        assert_eq!(v.to_string(), "printf");
    }

    #[test]
    fn test_standalone_shape_provider() {
        let provider = CircleWithLabelVertexShapeProvider::new("main");
        assert_eq!(provider.name(), "main");

        let compact = provider.compact_shape();
        assert_eq!(compact, VertexShape::circle(20.0));

        let full = provider.full_shape();
        assert!(full.width() > 0.0);
    }
}
