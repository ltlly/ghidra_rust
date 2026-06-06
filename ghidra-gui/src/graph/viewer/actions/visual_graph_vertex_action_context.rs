//! Port of Ghidra's `ghidra.graph.viewer.actions.VisualGraphVertexActionContext`.

/// Context for actions that are targeting a specific vertex.
#[derive(Debug, Clone)]
pub struct VisualGraphVertexActionContext {
    /// The ID of the target vertex.
    pub vertex_id: String,
    /// The display label of the vertex.
    pub vertex_label: String,
    /// Whether the vertex was selected when the action was triggered.
    pub was_selected: bool,
    /// Whether the vertex was focused when the action was triggered.
    pub was_focused: bool,
}

impl VisualGraphVertexActionContext {
    /// Create a new vertex action context.
    pub fn new(vertex_id: impl Into<String>, vertex_label: impl Into<String>) -> Self {
        Self {
            vertex_id: vertex_id.into(),
            vertex_label: vertex_label.into(),
            was_selected: false,
            was_focused: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vertex_context() {
        let ctx = VisualGraphVertexActionContext::new("v1", "main()");
        assert_eq!(ctx.vertex_id, "v1");
        assert_eq!(ctx.vertex_label, "main()");
        assert!(!ctx.was_selected);
    }
}
