//! Graph plugin for program visualization.
//!
//! Ported from `ghidra.app.plugin.core.graph` classes.
//!
//! Provides the graph display broker and graph plugin for program
//! visualization, supporting function graphs, call graphs, and
//! custom graph displays.

/// Graph display types supported by the graph plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GraphDisplayType {
    /// Function flow graph (basic blocks and edges).
    FunctionFlow,
    /// Call graph (function call relationships).
    CallGraph,
    /// Class hierarchy graph.
    ClassHierarchy,
    /// Import/export dependency graph.
    ImportExport,
    /// Custom user-defined graph.
    Custom,
}

impl GraphDisplayType {
    /// Get the display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::FunctionFlow => "Function Flow Graph",
            Self::CallGraph => "Call Graph",
            Self::ClassHierarchy => "Class Hierarchy",
            Self::ImportExport => "Import/Export Dependencies",
            Self::Custom => "Custom Graph",
        }
    }
}

/// Configuration for graph display.
#[derive(Debug, Clone)]
pub struct GraphDisplayConfig {
    /// The graph type.
    pub graph_type: GraphDisplayType,
    /// Whether to show addresses on nodes.
    pub show_addresses: bool,
    /// Whether to show instruction bytes on nodes.
    pub show_bytes: bool,
    /// Maximum nodes before auto-grouping.
    pub max_ungrouped_nodes: usize,
    /// Layout algorithm name.
    pub layout_algorithm: String,
    /// Whether to enable satellite view.
    pub show_satellite: bool,
}

impl Default for GraphDisplayConfig {
    fn default() -> Self {
        Self {
            graph_type: GraphDisplayType::FunctionFlow,
            show_addresses: true,
            show_bytes: false,
            max_ungrouped_nodes: 1000,
            layout_algorithm: "Hierarchical".to_string(),
            show_satellite: true,
        }
    }
}

/// Graph display broker for managing graph providers.
///
/// Ported from `ghidra.app.plugin.core.graph.GraphDisplayBroker`.
#[derive(Debug)]
pub struct GraphDisplayBroker {
    /// Registered graph display types.
    registered_types: Vec<GraphDisplayType>,
    /// Current configuration.
    config: GraphDisplayConfig,
}

impl GraphDisplayBroker {
    pub fn new() -> Self {
        Self {
            registered_types: vec![
                GraphDisplayType::FunctionFlow,
                GraphDisplayType::CallGraph,
            ],
            config: GraphDisplayConfig::default(),
        }
    }

    pub fn registered_types(&self) -> &[GraphDisplayType] {
        &self.registered_types
    }

    pub fn is_registered(&self, gtype: GraphDisplayType) -> bool {
        self.registered_types.contains(&gtype)
    }

    pub fn register_type(&mut self, gtype: GraphDisplayType) {
        if !self.registered_types.contains(&gtype) {
            self.registered_types.push(gtype);
        }
    }

    pub fn config(&self) -> &GraphDisplayConfig {
        &self.config
    }

    pub fn config_mut(&mut self) -> &mut GraphDisplayConfig {
        &mut self.config
    }
}

impl Default for GraphDisplayBroker {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_display_type_names() {
        assert_eq!(GraphDisplayType::FunctionFlow.display_name(), "Function Flow Graph");
        assert_eq!(GraphDisplayType::CallGraph.display_name(), "Call Graph");
    }

    #[test]
    fn test_graph_display_broker() {
        let broker = GraphDisplayBroker::new();
        assert!(broker.is_registered(GraphDisplayType::FunctionFlow));
        assert!(!broker.is_registered(GraphDisplayType::Custom));
    }

    #[test]
    fn test_register_type() {
        let mut broker = GraphDisplayBroker::new();
        broker.register_type(GraphDisplayType::Custom);
        assert!(broker.is_registered(GraphDisplayType::Custom));
    }

    #[test]
    fn test_default_config() {
        let config = GraphDisplayConfig::default();
        assert_eq!(config.graph_type, GraphDisplayType::FunctionFlow);
        assert!(config.show_addresses);
        assert!(!config.show_bytes);
        assert_eq!(config.max_ungrouped_nodes, 1000);
    }

    #[test]
    fn test_config_mutability() {
        let mut broker = GraphDisplayBroker::new();
        broker.config_mut().show_satellite = false;
        assert!(!broker.config().show_satellite);
    }
}
