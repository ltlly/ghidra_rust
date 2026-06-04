//! Port of `ghidra.service.graph.VertexShape`.
//!
//! Enum for vertex shapes used in graph rendering.

/// The shape of a vertex in a graph visualization.
///
/// Mirrors `ghidra.service.graph.VertexShape`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum VertexShape {
    /// A rectangular box.
    Box,
    /// A rounded rectangle.
    RoundRect,
    /// A circle/ellipse.
    Ellipse,
    /// A diamond shape.
    Diamond,
    /// A hexagonal shape.
    Hexagon,
    /// A triangle pointing up.
    TriangleUp,
    /// A triangle pointing down.
    TriangleDown,
}

impl VertexShape {
    /// Parse from a string (case-insensitive).
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "box" | "rectangle" | "rect" => Some(Self::Box),
            "roundrect" | "rounded" | "roundedrect" => Some(Self::RoundRect),
            "ellipse" | "circle" | "oval" => Some(Self::Ellipse),
            "diamond" => Some(Self::Diamond),
            "hexagon" => Some(Self::Hexagon),
            "triangle_up" | "triangleup" | "triangle" => Some(Self::TriangleUp),
            "triangle_down" | "triangledown" => Some(Self::TriangleDown),
            _ => None,
        }
    }
}

impl Default for VertexShape {
    fn default() -> Self {
        Self::Box
    }
}

impl std::fmt::Display for VertexShape {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Box => write!(f, "Box"),
            Self::RoundRect => write!(f, "RoundRect"),
            Self::Ellipse => write!(f, "Ellipse"),
            Self::Diamond => write!(f, "Diamond"),
            Self::Hexagon => write!(f, "Hexagon"),
            Self::TriangleUp => write!(f, "TriangleUp"),
            Self::TriangleDown => write!(f, "TriangleDown"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vertex_shape_default() {
        assert_eq!(VertexShape::default(), VertexShape::Box);
    }

    #[test]
    fn test_vertex_shape_parse() {
        assert_eq!(VertexShape::from_str("box"), Some(VertexShape::Box));
        assert_eq!(VertexShape::from_str("CIRCLE"), Some(VertexShape::Ellipse));
        assert_eq!(VertexShape::from_str("diamond"), Some(VertexShape::Diamond));
        assert_eq!(VertexShape::from_str("rounded"), Some(VertexShape::RoundRect));
        assert_eq!(VertexShape::from_str("hexagon"), Some(VertexShape::Hexagon));
        assert_eq!(VertexShape::from_str("unknown"), None);
    }

    #[test]
    fn test_vertex_shape_display() {
        assert_eq!(VertexShape::Box.to_string(), "Box");
        assert_eq!(VertexShape::Ellipse.to_string(), "Ellipse");
    }
}
