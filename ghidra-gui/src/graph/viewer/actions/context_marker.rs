//! Context markers for graph action enablement.
//!
//! Ports `ghidra.graph.viewer.actions.VisualGraphContextMarker`.

/// Marker types used to classify graph action contexts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VisualGraphContextMarker {
    /// A general graph context (background click).
    Graph,
    /// A vertex was clicked/hovered.
    Vertex,
    /// The satellite was clicked.
    Satellite,
}

impl VisualGraphContextMarker {
    /// Check if this is a vertex marker.
    pub fn is_vertex(&self) -> bool {
        *self == VisualGraphContextMarker::Vertex
    }

    /// Check if this is a graph marker.
    pub fn is_graph(&self) -> bool {
        *self == VisualGraphContextMarker::Graph
    }

    /// Check if this is a satellite marker.
    pub fn is_satellite(&self) -> bool {
        *self == VisualGraphContextMarker::Satellite
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_marker_types() {
        assert!(VisualGraphContextMarker::Vertex.is_vertex());
        assert!(!VisualGraphContextMarker::Vertex.is_graph());
        assert!(VisualGraphContextMarker::Graph.is_graph());
        assert!(VisualGraphContextMarker::Satellite.is_satellite());
    }
}
