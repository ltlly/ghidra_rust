//! Port of Ghidra's `ghidra.service.graph.GraphLabelPosition`.

/// Position of the label relative to the vertex shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GraphLabelPosition {
    /// Label centered on the vertex.
    Center,
    /// Label above the vertex.
    Top,
    /// Label below the vertex.
    Bottom,
    /// Label to the left of the vertex.
    Left,
    /// Label to the right of the vertex.
    Right,
    /// Label above and centered.
    TopCenter,
    /// Label below and centered.
    BottomCenter,
    /// No label displayed.
    None,
}

impl Default for GraphLabelPosition {
    fn default() -> Self { Self::Center }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() { assert_eq!(GraphLabelPosition::default(), GraphLabelPosition::Center); }

    #[test]
    fn test_variants() {
        assert_ne!(GraphLabelPosition::Top, GraphLabelPosition::Bottom);
        assert_ne!(GraphLabelPosition::Left, GraphLabelPosition::Right);
    }
}
