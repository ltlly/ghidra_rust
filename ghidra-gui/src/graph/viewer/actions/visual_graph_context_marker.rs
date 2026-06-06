//! Port of Ghidra's `ghidra.graph.viewer.actions.VisualGraphContextMarker`.

/// Marker for determining which type of visual graph element was the source
/// of an action context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VisualGraphContextMarker {
    /// Action originated from a vertex.
    Vertex,
    /// Action originated from an edge.
    Edge,
    /// Action originated from the graph background.
    Graph,
    /// Action originated from the satellite view.
    Satellite,
    /// Action originated from the toolbar.
    Toolbar,
    /// Unknown or unspecified source.
    Unknown,
}

impl Default for VisualGraphContextMarker {
    fn default() -> Self { Self::Unknown }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() { assert_eq!(VisualGraphContextMarker::default(), VisualGraphContextMarker::Unknown); }

    #[test]
    fn test_variants() { assert_ne!(VisualGraphContextMarker::Vertex, VisualGraphContextMarker::Edge); }
}
