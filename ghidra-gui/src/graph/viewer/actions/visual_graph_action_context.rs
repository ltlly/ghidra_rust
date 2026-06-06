//! Port of Ghidra's `ghidra.graph.viewer.actions.VisualGraphActionContext`.

/// Context for actions performed on a visual graph.
#[derive(Debug, Clone)]
pub struct VisualGraphActionContext {
    /// The source of the action (e.g., "toolbar", "context_menu", "keyboard").
    pub source: String,
    /// Optional vertex ID that the action is targeting.
    pub target_vertex_id: Option<String>,
    /// Optional edge ID that the action is targeting.
    pub target_edge_id: Option<String>,
    /// Whether this action was triggered by a shortcut key.
    pub from_keyboard: bool,
    /// Mouse position at time of action.
    pub mouse_position: Option<(f64, f64)>,
}

impl VisualGraphActionContext {
    /// Create a new action context.
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            target_vertex_id: None,
            target_edge_id: None,
            from_keyboard: false,
            mouse_position: None,
        }
    }

    /// Set the target vertex.
    pub fn with_vertex(mut self, id: impl Into<String>) -> Self {
        self.target_vertex_id = Some(id.into());
        self
    }

    /// Set the target edge.
    pub fn with_edge(mut self, id: impl Into<String>) -> Self {
        self.target_edge_id = Some(id.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_basic() {
        let ctx = VisualGraphActionContext::new("toolbar");
        assert_eq!(ctx.source, "toolbar");
        assert!(ctx.target_vertex_id.is_none());
    }

    #[test]
    fn test_context_with_vertex() {
        let ctx = VisualGraphActionContext::new("menu").with_vertex("v1");
        assert_eq!(ctx.target_vertex_id, Some("v1".into()));
    }
}
