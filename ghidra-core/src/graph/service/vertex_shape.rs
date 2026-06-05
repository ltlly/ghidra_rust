//! Port of `ghidra.service.graph.VertexShape`.
//!
//! Enum for vertex shapes used in graph rendering.
//!
//! All 9 shape types from Ghidra's Java implementation are included,
//! each with geometry properties (label position, shape-to-label ratio,
//! max width-to-height ratio) that control rendering behavior.

/// The shape of a vertex in a graph visualization.
///
/// Mirrors `ghidra.service.graph.VertexShape` with all 9 shape types.
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
    /// A five-pointed star.
    Star,
    /// A five-sided pentagon.
    Pentagon,
    /// An eight-sided octagon.
    Octagon,
}

impl VertexShape {
    /// All available shape variants.
    pub const ALL: &[VertexShape] = &[
        Self::Box,
        Self::RoundRect,
        Self::Ellipse,
        Self::Diamond,
        Self::Hexagon,
        Self::TriangleUp,
        Self::TriangleDown,
        Self::Star,
        Self::Pentagon,
        Self::Octagon,
    ];

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
            "star" => Some(Self::Star),
            "pentagon" | "pentaon" => Some(Self::Pentagon),
            "octagon" => Some(Self::Octagon),
            _ => None,
        }
    }

    /// Relative label position within the shape (0.0 = top, 1.0 = bottom).
    pub fn label_position(&self) -> f64 {
        match self {
            Self::Box | Self::RoundRect | Self::Ellipse | Self::Diamond => 0.5,
            Self::Hexagon | Self::Star | Self::Pentagon | Self::Octagon => 0.5,
            Self::TriangleUp => 0.90,
            Self::TriangleDown => 0.10,
        }
    }

    /// Scale factor for the shape relative to its label.
    pub fn shape_to_label_ratio(&self) -> f64 {
        match self {
            Self::Box | Self::RoundRect => 1.0,
            Self::Ellipse | Self::Hexagon | Self::Pentagon | Self::Octagon => 1.4,
            Self::Diamond | Self::TriangleUp | Self::TriangleDown => 1.6,
            Self::Star => 2.0,
        }
    }

    /// Maximum width-to-height ratio before the shape becomes too distorted.
    pub fn max_width_to_height_ratio(&self) -> u32 {
        match self {
            Self::Pentagon | Self::Hexagon | Self::Octagon => 2,
            _ => 10,
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
            Self::Star => write!(f, "Star"),
            Self::Pentagon => write!(f, "Pentagon"),
            Self::Octagon => write!(f, "Octagon"),
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
        assert_eq!(VertexShape::from_str("star"), Some(VertexShape::Star));
        assert_eq!(VertexShape::from_str("pentagon"), Some(VertexShape::Pentagon));
        assert_eq!(VertexShape::from_str("octagon"), Some(VertexShape::Octagon));
        assert_eq!(VertexShape::from_str("unknown"), None);
    }

    #[test]
    fn test_vertex_shape_display() {
        assert_eq!(VertexShape::Box.to_string(), "Box");
        assert_eq!(VertexShape::Ellipse.to_string(), "Ellipse");
        assert_eq!(VertexShape::Star.to_string(), "Star");
        assert_eq!(VertexShape::Pentagon.to_string(), "Pentagon");
        assert_eq!(VertexShape::Octagon.to_string(), "Octagon");
    }

    #[test]
    fn test_vertex_shape_all_count() {
        assert_eq!(VertexShape::ALL.len(), 10);
    }

    #[test]
    fn test_vertex_shape_label_position() {
        assert!((VertexShape::Box.label_position() - 0.5).abs() < 1e-6);
        assert!((VertexShape::TriangleUp.label_position() - 0.90).abs() < 1e-6);
        assert!((VertexShape::TriangleDown.label_position() - 0.10).abs() < 1e-6);
        assert!((VertexShape::Star.label_position() - 0.5).abs() < 1e-6);
    }

    #[test]
    fn test_vertex_shape_ratio() {
        assert!((VertexShape::Box.shape_to_label_ratio() - 1.0).abs() < 1e-6);
        assert!((VertexShape::Star.shape_to_label_ratio() - 2.0).abs() < 1e-6);
        assert!((VertexShape::Diamond.shape_to_label_ratio() - 1.6).abs() < 1e-6);
        assert!((VertexShape::Hexagon.shape_to_label_ratio() - 1.4).abs() < 1e-6);
    }

    #[test]
    fn test_vertex_shape_max_ratio() {
        assert_eq!(VertexShape::Box.max_width_to_height_ratio(), 10);
        assert_eq!(VertexShape::Hexagon.max_width_to_height_ratio(), 2);
        assert_eq!(VertexShape::Pentagon.max_width_to_height_ratio(), 2);
        assert_eq!(VertexShape::Octagon.max_width_to_height_ratio(), 2);
    }
}
