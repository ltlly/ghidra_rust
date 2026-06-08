//! Program graph type definitions.
//!
//! Ported from Ghidra's program graph type classes.

use std::fmt;

/// The type of program graph to generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramGraphType {
    /// Block-level control flow graph.
    BlockFlow,
    /// Instruction-level code flow graph.
    CodeFlow,
    /// Function call graph.
    Call,
    /// Data cross-reference graph.
    DataReference,
    /// Custom graph type.
    Custom(u32),
}

impl fmt::Display for ProgramGraphType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlockFlow => write!(f, "Block Flow"),
            Self::CodeFlow => write!(f, "Code Flow"),
            Self::Call => write!(f, "Call"),
            Self::DataReference => write!(f, "Data Reference"),
            Self::Custom(id) => write!(f, "Custom({})", id),
        }
    }
}

/// Graph type for block flow visualization.
#[derive(Debug, Clone)]
pub struct BlockFlowGraphType {
    /// Display name.
    pub name: String,
}

impl Default for BlockFlowGraphType {
    fn default() -> Self {
        Self {
            name: "Block Flow".to_string(),
        }
    }
}

/// Graph type for code flow visualization.
#[derive(Debug, Clone)]
pub struct CodeFlowGraphType {
    /// Display name.
    pub name: String,
}

impl Default for CodeFlowGraphType {
    fn default() -> Self {
        Self {
            name: "Code Flow".to_string(),
        }
    }
}

/// Graph type for call graph visualization.
#[derive(Debug, Clone)]
pub struct CallGraphType {
    /// Display name.
    pub name: String,
}

impl Default for CallGraphType {
    fn default() -> Self {
        Self {
            name: "Call Graph".to_string(),
        }
    }
}

/// Graph type for data flow visualization.
#[derive(Debug, Clone)]
pub struct DataFlowGraphType {
    /// Display name.
    pub name: String,
}

impl Default for DataFlowGraphType {
    fn default() -> Self {
        Self {
            name: "Data Flow".to_string(),
        }
    }
}

/// Configuration for program graph display options.
#[derive(Debug, Clone)]
pub struct ProgramGraphDisplayOptions {
    /// Whether to reuse an existing graph display.
    pub reuse_graph: bool,
    /// Whether to append to an existing graph.
    pub append_to_graph: bool,
    /// Whether to use an entry point nexus node.
    pub graph_entry_point_nexus: bool,
    /// Maximum code lines to display per block.
    pub code_limit_per_block: usize,
    /// Maximum depth of data references (0 for unlimited).
    pub data_max_depth: usize,
}

impl Default for ProgramGraphDisplayOptions {
    fn default() -> Self {
        Self {
            reuse_graph: false,
            append_to_graph: false,
            graph_entry_point_nexus: false,
            code_limit_per_block: 10,
            data_max_depth: 1,
        }
    }
}

/// The default block model used for call graphs.
pub const DEFAULT_BLOCK_MODEL_FOR_CALL_GRAPH: &str = "Subroutine";

/// The menu path prefix for graph actions.
pub const MENU_GRAPH: &str = "Graph";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_type_display() {
        assert_eq!(ProgramGraphType::BlockFlow.to_string(), "Block Flow");
        assert_eq!(ProgramGraphType::CodeFlow.to_string(), "Code Flow");
        assert_eq!(ProgramGraphType::Call.to_string(), "Call");
        assert_eq!(ProgramGraphType::DataReference.to_string(), "Data Reference");
    }

    #[test]
    fn test_default_graph_display_options() {
        let opts = ProgramGraphDisplayOptions::default();
        assert!(!opts.reuse_graph);
        assert!(!opts.append_to_graph);
        assert!(!opts.graph_entry_point_nexus);
        assert_eq!(opts.code_limit_per_block, 10);
        assert_eq!(opts.data_max_depth, 1);
    }

    #[test]
    fn test_graph_type_defaults() {
        assert_eq!(BlockFlowGraphType::default().name, "Block Flow");
        assert_eq!(CodeFlowGraphType::default().name, "Code Flow");
        assert_eq!(CallGraphType::default().name, "Call Graph");
        assert_eq!(DataFlowGraphType::default().name, "Data Flow");
    }

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_BLOCK_MODEL_FOR_CALL_GRAPH, "Subroutine");
        assert_eq!(MENU_GRAPH, "Graph");
    }
}
