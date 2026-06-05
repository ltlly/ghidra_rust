//! Path highlight mode for graph edges.
//!
//! Port of `ghidra.graph.viewer.PathHighlightMode`.

/// Controls how edges are highlighted when a vertex is hovered or selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathHighlightMode {
    /// No path highlighting.
    None,
    /// Highlight the edges on the path to/from the hovered vertex.
    HoveredVertexPath,
    /// Highlight the edges on the path to/from the selected (focused) vertex.
    SelectedVertexPath,
    /// Highlight edges on the path to/from both hovered and selected vertices.
    Both,
}

impl Default for PathHighlightMode {
    fn default() -> Self {
        Self::HoveredVertexPath
    }
}

impl PathHighlightMode {
    /// Whether this mode highlights hovered paths.
    pub fn highlights_hovered(&self) -> bool {
        matches!(self, Self::HoveredVertexPath | Self::Both)
    }

    /// Whether this mode highlights selected paths.
    pub fn highlights_selected(&self) -> bool {
        matches!(self, Self::SelectedVertexPath | Self::Both)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_hovered() {
        assert_eq!(PathHighlightMode::default(), PathHighlightMode::HoveredVertexPath);
    }

    #[test]
    fn none_highlights_nothing() {
        let m = PathHighlightMode::None;
        assert!(!m.highlights_hovered());
        assert!(!m.highlights_selected());
    }

    #[test]
    fn both_highlights_everything() {
        let m = PathHighlightMode::Both;
        assert!(m.highlights_hovered());
        assert!(m.highlights_selected());
    }

    #[test]
    fn hovered_only() {
        let m = PathHighlightMode::HoveredVertexPath;
        assert!(m.highlights_hovered());
        assert!(!m.highlights_selected());
    }

    #[test]
    fn selected_only() {
        let m = PathHighlightMode::SelectedVertexPath;
        assert!(!m.highlights_hovered());
        assert!(m.highlights_selected());
    }
}
