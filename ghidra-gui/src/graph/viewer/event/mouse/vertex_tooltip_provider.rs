//! Port of Ghidra's `ghidra.graph.viewer.event.mouse.VertexTooltipProvider`.

/// Trait for providing tooltip text when hovering over vertices.
pub trait VertexTooltipProvider: Send + Sync {
    /// Get the tooltip text for a vertex. Return None for no tooltip.
    fn get_tooltip(&self, vertex_id: &str) -> Option<String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct NameTooltipProvider;
    impl VertexTooltipProvider for NameTooltipProvider {
        fn get_tooltip(&self, vertex_id: &str) -> Option<String> {
            Some(format!("Vertex: {}", vertex_id))
        }
    }

    #[test]
    fn test_tooltip() {
        let p = NameTooltipProvider;
        assert_eq!(p.get_tooltip("v1"), Some("Vertex: v1".into()));
    }
}
