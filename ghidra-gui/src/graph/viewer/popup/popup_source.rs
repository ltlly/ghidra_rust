//! Popup source for graph viewer popups.
//!
//! Ports `ghidra.graph.viewer.popup.PopupSource`.

use crate::graph::viewer::Point2D;

/// Identifies what triggered a popup in the graph viewer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PopupSource {
    /// Popup triggered on a vertex.
    Vertex(u64),
    /// Popup triggered on an edge.
    Edge(u64),
    /// Popup triggered on the graph background.
    Background,
}

/// A popup request with its location and source.
#[derive(Debug, Clone)]
pub struct PopupRequest {
    /// The source of the popup.
    pub source: PopupSource,
    /// The location where the popup should appear.
    pub location: Point2D,
    /// The popup content (HTML).
    pub content: String,
}

impl PopupRequest {
    /// Create a popup request.
    pub fn new(source: PopupSource, location: Point2D, content: impl Into<String>) -> Self {
        Self {
            source,
            location,
            content: content.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_popup_source_vertex() {
        let source = PopupSource::Vertex(42);
        assert!(matches!(source, PopupSource::Vertex(42)));
    }

    #[test]
    fn test_popup_request() {
        let req = PopupRequest::new(
            PopupSource::Background,
            Point2D::new(10.0, 20.0),
            "Hello",
        );
        assert_eq!(req.location, Point2D::new(10.0, 20.0));
    }
}
