//! Port of `ghidra.service.graph.GraphTypeBuilder`.
//!
//! Builder for constructing [`GraphType`] instances.

use super::graph_type::GraphType;

/// Builder for constructing [`GraphType`] instances.
///
/// Mirrors `ghidra.service.graph.GraphTypeBuilder`.
#[derive(Debug, Clone)]
pub struct GraphTypeBuilder {
    id: String,
    name: String,
    description: Option<String>,
}

impl GraphTypeBuilder {
    /// Create a new builder with the given id.
    pub fn new(id: impl Into<String>) -> Self {
        let id = id.into();
        Self {
            name: id.clone(),
            id,
            description: None,
        }
    }

    /// Set the display name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Set the description.
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Build the [`GraphType`].
    pub fn build(self) -> GraphType {
        match self.description {
            Some(desc) => GraphType::with_description(self.id, self.name, desc),
            None => GraphType::new(self.id, self.name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_minimal() {
        let gt = GraphTypeBuilder::new("cfg").build();
        assert_eq!(gt.id(), "cfg");
        assert_eq!(gt.name(), "cfg"); // defaults to id
        assert!(gt.description().is_none());
    }

    #[test]
    fn test_builder_full() {
        let gt = GraphTypeBuilder::new("cg")
            .name("Call Graph")
            .description("Shows call relationships")
            .build();
        assert_eq!(gt.id(), "cg");
        assert_eq!(gt.name(), "Call Graph");
        assert_eq!(gt.description(), Some("Shows call relationships"));
    }
}
