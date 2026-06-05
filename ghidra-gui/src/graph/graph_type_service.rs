//! Graph type service layer: registry of graph types and their display options.
//!
//! Ports `ghidra.service.graph.GraphType` (the full implementation with
//! vertex/edge type sets), `EmptyGraphType`, and the graph type registration
//! system.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use super::service::{GraphDisplayOptions, GraphLabelPosition, GraphType, VertexShape};

/// A registry of graph types and their associated display options.
///
/// Port of Ghidra's graph type registration system.
#[derive(Debug)]
pub struct GraphTypeRegistry {
    types: RwLock<HashMap<String, GraphTypeInfo>>,
}

/// Information about a registered graph type.
#[derive(Debug, Clone)]
pub struct GraphTypeInfo {
    /// The graph type definition.
    pub graph_type: GraphType,
    /// Display options for this graph type.
    pub display_options: GraphDisplayOptions,
    /// Whether this type is the default.
    pub is_default: bool,
}

impl GraphTypeRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            types: RwLock::new(HashMap::new()),
        }
    }

    /// Register a graph type.
    pub fn register(&self, graph_type: GraphType, display_options: GraphDisplayOptions) {
        let name = graph_type.name.clone();
        let info = GraphTypeInfo {
            graph_type,
            display_options,
            is_default: false,
        };
        self.types.write().unwrap().insert(name, info);
    }

    /// Get a graph type by name.
    pub fn get(&self, name: &str) -> Option<GraphTypeInfo> {
        self.types.read().unwrap().get(name).cloned()
    }

    /// Get the names of all registered graph types.
    pub fn type_names(&self) -> Vec<String> {
        self.types.read().unwrap().keys().cloned().collect()
    }

    /// Check if a graph type is registered.
    pub fn contains(&self, name: &str) -> bool {
        self.types.read().unwrap().contains_key(name)
    }

    /// Get the number of registered graph types.
    pub fn len(&self) -> usize {
        self.types.read().unwrap().len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.types.read().unwrap().is_empty()
    }
}

impl Default for GraphTypeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Create an empty graph type (no vertex or edge types defined).
///
/// Port of `ghidra.service.graph.EmptyGraphType`.
pub fn create_empty_graph_type() -> GraphType {
    GraphType::new("empty", "Empty Graph Type")
}

/// Create a CFG graph type with standard vertex types.
pub fn create_cfg_graph_type() -> GraphType {
    let mut gt = GraphType::new("cfg", "Control Flow Graph");
    gt.add_vertex_type("entry");
    gt.add_vertex_type("exit");
    gt.add_vertex_type("basic_block");
    gt.add_vertex_type("call");
    gt
}

/// Create a call graph type.
pub fn create_call_graph_type() -> GraphType {
    let mut gt = GraphType::new("callgraph", "Call Graph");
    gt.add_vertex_type("function");
    gt.add_vertex_type("thunk");
    gt.add_vertex_type("external");
    gt
}

/// Create a class hierarchy graph type.
pub fn create_class_hierarchy_type() -> GraphType {
    let mut gt = GraphType::new("class_hierarchy", "Class Hierarchy");
    gt.add_vertex_type("class");
    gt.add_vertex_type("interface");
    gt.add_vertex_type("abstract_class");
    gt
}

/// Create default display options for a graph type.
pub fn create_default_display_options(
    graph_type: &GraphType,
) -> GraphDisplayOptions {
    // Use different default colors based on graph type
    let (vertex_color, edge_color) = match graph_type.name.as_str() {
        "cfg" => ("#FFFFFF", "#000000"),
        "callgraph" => ("#E0FFE0", "#336633"),
        "class_hierarchy" => ("#E0F0FF", "#0066CC"),
        _ => ("#FFFFFF", "#000000"),
    };

    let mut opts = GraphDisplayOptions::default();
    opts.default_vertex_color = vertex_color.to_string();
    opts.default_edge_color = edge_color.to_string();
    opts
}

/// Create a registry pre-populated with standard graph types.
pub fn create_standard_registry() -> GraphTypeRegistry {
    let registry = GraphTypeRegistry::new();

    let cfg = create_cfg_graph_type();
    let cfg_opts = create_default_display_options(&cfg);
    registry.register(cfg, cfg_opts);

    let callgraph = create_call_graph_type();
    let callgraph_opts = create_default_display_options(&callgraph);
    registry.register(callgraph, callgraph_opts);

    let hierarchy = create_class_hierarchy_type();
    let hierarchy_opts = create_default_display_options(&hierarchy);
    registry.register(hierarchy, hierarchy_opts);

    registry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_register_and_get() {
        let registry = GraphTypeRegistry::new();
        let gt = GraphType::new("test", "Test Graph");
        let opts = GraphDisplayOptions::default();
        registry.register(gt, opts);

        assert!(registry.contains("test"));
        assert_eq!(registry.len(), 1);

        let info = registry.get("test").unwrap();
        assert_eq!(info.graph_type.name, "test");
    }

    #[test]
    fn test_registry_type_names() {
        let registry = GraphTypeRegistry::new();
        let gt1 = GraphType::new("a", "A");
        let gt2 = GraphType::new("b", "B");
        registry.register(gt1, GraphDisplayOptions::default());
        registry.register(gt2, GraphDisplayOptions::default());

        let mut names = registry.type_names();
        names.sort();
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn test_registry_not_found() {
        let registry = GraphTypeRegistry::new();
        assert!(registry.get("nonexistent").is_none());
        assert!(!registry.contains("nonexistent"));
    }

    #[test]
    fn test_empty_graph_type() {
        let gt = create_empty_graph_type();
        assert_eq!(gt.name, "empty");
        assert!(gt.vertex_types.is_empty());
    }

    #[test]
    fn test_cfg_graph_type() {
        let gt = create_cfg_graph_type();
        assert_eq!(gt.name, "cfg");
        assert_eq!(gt.vertex_types.len(), 4);
        assert!(gt.vertex_types.contains(&"entry".to_string()));
        assert!(gt.vertex_types.contains(&"exit".to_string()));
        assert!(gt.vertex_types.contains(&"basic_block".to_string()));
    }

    #[test]
    fn test_call_graph_type() {
        let gt = create_call_graph_type();
        assert_eq!(gt.name, "callgraph");
        assert!(gt.vertex_types.contains(&"function".to_string()));
    }

    #[test]
    fn test_class_hierarchy_type() {
        let gt = create_class_hierarchy_type();
        assert_eq!(gt.name, "class_hierarchy");
        assert!(gt.vertex_types.contains(&"class".to_string()));
        assert!(gt.vertex_types.contains(&"interface".to_string()));
    }

    #[test]
    fn test_default_display_options() {
        let cfg = create_cfg_graph_type();
        let opts = create_default_display_options(&cfg);
        assert_eq!(opts.default_vertex_color, "#FFFFFF");
        assert_eq!(opts.default_edge_color, "#000000");

        let cg = create_call_graph_type();
        let cg_opts = create_default_display_options(&cg);
        assert_eq!(cg_opts.default_vertex_color, "#E0FFE0");
    }

    #[test]
    fn test_standard_registry() {
        let registry = create_standard_registry();
        assert_eq!(registry.len(), 3);
        assert!(registry.contains("cfg"));
        assert!(registry.contains("callgraph"));
        assert!(registry.contains("class_hierarchy"));
    }

    #[test]
    fn test_registry_empty() {
        let registry = GraphTypeRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }
}
