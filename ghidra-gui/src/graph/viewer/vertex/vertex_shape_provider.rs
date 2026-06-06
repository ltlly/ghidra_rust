//! Port of Ghidra's `ghidra.graph.viewer.vertex.VertexShapeProvider`.

use crate::graph::service::VertexShape;

/// Trait for providing vertex shapes based on vertex properties.
pub trait VertexShapeProvider: Send + Sync {
    /// Get the shape for a vertex with the given ID.
    fn get_shape(&self, vertex_id: &str) -> VertexShape;
    /// Get the shape for a selected vertex.
    fn get_selected_shape(&self, vertex_id: &str) -> VertexShape {
        self.get_shape(vertex_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct BoxProvider;
    impl VertexShapeProvider for BoxProvider {
        fn get_shape(&self, _id: &str) -> VertexShape { VertexShape::Rectangle }
    }

    #[test]
    fn test_shape_provider() {
        let p = BoxProvider;
        assert_eq!(p.get_shape("v1"), VertexShape::Rectangle);
        assert_eq!(p.get_selected_shape("v1"), VertexShape::Rectangle);
    }
}
