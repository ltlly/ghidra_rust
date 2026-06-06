//! Program graph types and display options.
//!
//! Ported from `ghidra.graph`.
//!
//! Defines graph type enumerations for various program analysis views
//! (control flow, call graph, data flow, code flow) and display option
//! configurations.

// ---------------------------------------------------------------------------
// ProgramGraphType
// ---------------------------------------------------------------------------

/// The type of graph being displayed in a program analysis view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramGraphType {
    /// Basic block flow graph (CFG).
    BlockFlow,
    /// Function call graph.
    CallGraph,
    /// Data flow graph.
    DataFlow,
    /// Code flow graph (instruction-level).
    CodeFlow,
}

impl ProgramGraphType {
    /// Human-readable name.
    pub fn name(&self) -> &str {
        match self {
            Self::BlockFlow => "Block Flow Graph",
            Self::CallGraph => "Call Graph",
            Self::DataFlow => "Data Flow Graph",
            Self::CodeFlow => "Code Flow Graph",
        }
    }

    /// Short identifier.
    pub fn id(&self) -> &str {
        match self {
            Self::BlockFlow => "block_flow",
            Self::CallGraph => "call_graph",
            Self::DataFlow => "data_flow",
            Self::CodeFlow => "code_flow",
        }
    }
}

// ---------------------------------------------------------------------------
// BlockFlowGraphType
// ---------------------------------------------------------------------------

/// Subtypes of block flow graphs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockFlowGraphType {
    /// Basic blocks only.
    Basic,
    /// With call edges.
    WithCalls,
    /// With exception handler edges.
    WithExceptions,
}

impl BlockFlowGraphType {
    /// Human-readable name.
    pub fn name(&self) -> &str {
        match self {
            Self::Basic => "Basic Block Flow",
            Self::WithCalls => "Block Flow with Calls",
            Self::WithExceptions => "Block Flow with Exceptions",
        }
    }
}

// ---------------------------------------------------------------------------
// ProgramGraphDisplayOptions
// ---------------------------------------------------------------------------

/// Display options for a program graph view.
#[derive(Debug, Clone)]
pub struct ProgramGraphDisplayOptions {
    /// Whether to show addresses on nodes.
    pub show_addresses: bool,
    /// Whether to show mnemonics on nodes.
    pub show_mnemonics: bool,
    /// Whether to show register values.
    pub show_register_values: bool,
    /// Maximum number of nodes before graph is simplified.
    pub max_nodes: usize,
    /// The graph type.
    pub graph_type: ProgramGraphType,
    /// Node font size.
    pub font_size: f32,
    /// Whether to use orthogonal edge routing.
    pub orthogonal_edges: bool,
}

impl ProgramGraphDisplayOptions {
    /// Create default options for the given graph type.
    pub fn new(graph_type: ProgramGraphType) -> Self {
        Self {
            show_addresses: true,
            show_mnemonics: true,
            show_register_values: false,
            max_nodes: 1000,
            graph_type,
            font_size: 11.0,
            orthogonal_edges: true,
        }
    }

    /// Create options for a block flow graph.
    pub fn block_flow() -> Self {
        Self::new(ProgramGraphType::BlockFlow)
    }

    /// Create options for a call graph.
    pub fn call_graph() -> Self {
        Self::new(ProgramGraphType::CallGraph)
    }

    /// Create options for a data flow graph.
    pub fn data_flow() -> Self {
        Self::new(ProgramGraphType::DataFlow)
    }

    /// Create options for a code flow graph.
    pub fn code_flow() -> Self {
        Self::new(ProgramGraphType::CodeFlow)
    }
}

impl Default for ProgramGraphDisplayOptions {
    fn default() -> Self {
        Self::block_flow()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_type_names() {
        assert_eq!(ProgramGraphType::BlockFlow.name(), "Block Flow Graph");
        assert_eq!(ProgramGraphType::CallGraph.name(), "Call Graph");
        assert_eq!(ProgramGraphType::DataFlow.name(), "Data Flow Graph");
        assert_eq!(ProgramGraphType::CodeFlow.name(), "Code Flow Graph");
    }

    #[test]
    fn test_graph_type_ids() {
        assert_eq!(ProgramGraphType::BlockFlow.id(), "block_flow");
        assert_eq!(ProgramGraphType::CallGraph.id(), "call_graph");
    }

    #[test]
    fn test_block_flow_subtypes() {
        assert_eq!(BlockFlowGraphType::Basic.name(), "Basic Block Flow");
        assert_eq!(
            BlockFlowGraphType::WithCalls.name(),
            "Block Flow with Calls"
        );
        assert_eq!(
            BlockFlowGraphType::WithExceptions.name(),
            "Block Flow with Exceptions"
        );
    }

    #[test]
    fn test_display_options_default() {
        let opts = ProgramGraphDisplayOptions::default();
        assert!(opts.show_addresses);
        assert!(opts.show_mnemonics);
        assert!(!opts.show_register_values);
        assert_eq!(opts.graph_type, ProgramGraphType::BlockFlow);
        assert_eq!(opts.max_nodes, 1000);
        assert_eq!(opts.font_size, 11.0);
        assert!(opts.orthogonal_edges);
    }

    #[test]
    fn test_display_options_constructors() {
        let cg = ProgramGraphDisplayOptions::call_graph();
        assert_eq!(cg.graph_type, ProgramGraphType::CallGraph);

        let df = ProgramGraphDisplayOptions::data_flow();
        assert_eq!(df.graph_type, ProgramGraphType::DataFlow);

        let cf = ProgramGraphDisplayOptions::code_flow();
        assert_eq!(cf.graph_type, ProgramGraphType::CodeFlow);
    }

    #[test]
    fn test_graph_type_equality() {
        assert_eq!(ProgramGraphType::BlockFlow, ProgramGraphType::BlockFlow);
        assert_ne!(ProgramGraphType::BlockFlow, ProgramGraphType::CallGraph);
    }
}
