//! Port of `ghidra.service.graph.GraphLabelPosition`.
//!
//! Enum for label placement on graph vertices.

/// Where to place the label on a graph vertex.
///
/// Mirrors `ghidra.service.graph.GraphLabelPosition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum GraphLabelPosition {
    /// Label above the vertex.
    Top,
    /// Label inside the vertex (centered).
    Center,
    /// Label below the vertex.
    Bottom,
    /// Label to the left of the vertex.
    Left,
    /// Label to the right of the vertex.
    Right,
    /// No label displayed.
    Hidden,
}

impl GraphLabelPosition {
    /// Parse from a string (case-insensitive).
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "top" => Some(Self::Top),
            "center" | "middle" => Some(Self::Center),
            "bottom" => Some(Self::Bottom),
            "left" => Some(Self::Left),
            "right" => Some(Self::Right),
            "hidden" | "none" => Some(Self::Hidden),
            _ => None,
        }
    }
}

impl Default for GraphLabelPosition {
    fn default() -> Self {
        Self::Center
    }
}

impl std::fmt::Display for GraphLabelPosition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Top => write!(f, "Top"),
            Self::Center => write!(f, "Center"),
            Self::Bottom => write!(f, "Bottom"),
            Self::Left => write!(f, "Left"),
            Self::Right => write!(f, "Right"),
            Self::Hidden => write!(f, "Hidden"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_position_default() {
        assert_eq!(GraphLabelPosition::default(), GraphLabelPosition::Center);
    }

    #[test]
    fn test_label_position_parse() {
        assert_eq!(GraphLabelPosition::from_str("top"), Some(GraphLabelPosition::Top));
        assert_eq!(GraphLabelPosition::from_str("BOTTOM"), Some(GraphLabelPosition::Bottom));
        assert_eq!(GraphLabelPosition::from_str("Center"), Some(GraphLabelPosition::Center));
        assert_eq!(GraphLabelPosition::from_str("none"), Some(GraphLabelPosition::Hidden));
        assert_eq!(GraphLabelPosition::from_str("invalid"), None);
    }

    #[test]
    fn test_label_position_display() {
        assert_eq!(GraphLabelPosition::Top.to_string(), "Top");
        assert_eq!(GraphLabelPosition::Hidden.to_string(), "Hidden");
    }
}
