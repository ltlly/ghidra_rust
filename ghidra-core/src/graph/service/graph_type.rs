//! Port of `ghidra.service.graph.GraphType`.
//!
//! Defines the type of a graph (e.g., "call graph", "control flow graph").

/// Describes the type of a graph.
///
/// Mirrors `ghidra.service.graph.GraphType`.
/// Equality and hashing are based solely on the `id` field.
#[derive(Debug, Clone)]
pub struct GraphType {
    /// Unique id for this graph type.
    id: String,
    /// Human-readable display name.
    name: String,
    /// Description of this graph type.
    description: Option<String>,
}

impl PartialEq for GraphType {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for GraphType {}

impl std::hash::Hash for GraphType {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl GraphType {
    /// Create a new graph type.
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: None,
        }
    }

    /// Create a graph type with a description.
    pub fn with_description(
        id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: Some(description.into()),
        }
    }

    /// Get the graph type id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the display name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the description.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

impl std::fmt::Display for GraphType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_type_basic() {
        let gt = GraphType::new("cfg", "Control Flow Graph");
        assert_eq!(gt.id(), "cfg");
        assert_eq!(gt.name(), "Control Flow Graph");
        assert!(gt.description().is_none());
    }

    #[test]
    fn test_graph_type_with_description() {
        let gt = GraphType::with_description("cg", "Call Graph", "Shows caller-callee relationships");
        assert_eq!(gt.description(), Some("Shows caller-callee relationships"));
    }

    #[test]
    fn test_graph_type_display() {
        let gt = GraphType::new("cfg", "CFG");
        assert_eq!(gt.to_string(), "CFG");
    }

    #[test]
    fn test_graph_type_equality() {
        let gt1 = GraphType::new("cfg", "CFG");
        let gt2 = GraphType::new("cfg", "Different Name");
        assert_eq!(gt1, gt2); // equality by id
    }
}
