//! Block graph generation task.
//!
//! Ported from Ghidra's `BlockGraphTask` Java class.
//!
//! A background task that generates program block graphs (block flow,
//! code flow, call graphs) and displays or exports them.

use super::ProgramGraphType;

/// Configuration for a block graph generation task.
#[derive(Debug, Clone)]
pub struct BlockGraphTaskConfig {
    /// The type of graph to generate.
    pub graph_type: ProgramGraphType,
    /// Whether to include an entry point nexus node.
    pub entry_point_nexus: bool,
    /// Whether to reuse an existing graph display.
    pub reuse_graph: bool,
    /// Whether to append to an existing graph.
    pub append_to_graph: bool,
    /// Maximum code lines to display per block.
    pub code_limit_per_block: usize,
    /// Name of the block model to use.
    pub block_model_name: String,
    /// Minimum address of the selection (0 if no selection).
    pub selection_min: u64,
    /// Maximum address of the selection (0 if no selection).
    pub selection_max: u64,
}

impl BlockGraphTaskConfig {
    /// Create a new block graph task configuration.
    pub fn new(
        graph_type: ProgramGraphType,
        entry_point_nexus: bool,
        reuse_graph: bool,
        append_to_graph: bool,
        block_model_name: String,
    ) -> Self {
        Self {
            graph_type,
            entry_point_nexus,
            reuse_graph,
            append_to_graph,
            code_limit_per_block: 10,
            block_model_name,
            selection_min: 0,
            selection_max: 0,
        }
    }

    /// Set the code limit per block.
    pub fn set_code_limit_per_block(&mut self, limit: usize) {
        self.code_limit_per_block = limit;
    }
}

/// Status of a graph generation task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphTaskStatus {
    /// Task has not started yet.
    Pending,
    /// Task is running.
    Running,
    /// Task completed successfully.
    Completed,
    /// Task was cancelled.
    Cancelled,
    /// Task failed with an error.
    Failed,
}

/// Result of a block graph generation.
#[derive(Debug)]
pub struct BlockGraphResult {
    /// Number of vertices in the generated graph.
    pub vertex_count: usize,
    /// Number of edges in the generated graph.
    pub edge_count: usize,
    /// The graph type that was generated.
    pub graph_type: ProgramGraphType,
    /// Status of the task.
    pub status: GraphTaskStatus,
}

impl BlockGraphResult {
    /// Create a new result.
    pub fn new(graph_type: ProgramGraphType, vertex_count: usize, edge_count: usize) -> Self {
        Self {
            vertex_count,
            edge_count,
            graph_type,
            status: GraphTaskStatus::Completed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_graph_task_config() {
        let config = BlockGraphTaskConfig::new(
            ProgramGraphType::BlockFlow,
            false,
            false,
            false,
            "Subroutine".to_string(),
        );
        assert_eq!(config.graph_type, ProgramGraphType::BlockFlow);
        assert_eq!(config.code_limit_per_block, 10);
        assert_eq!(config.block_model_name, "Subroutine");
    }

    #[test]
    fn test_task_status() {
        assert_ne!(GraphTaskStatus::Pending, GraphTaskStatus::Completed);
        assert_eq!(GraphTaskStatus::Failed, GraphTaskStatus::Failed);
    }

    #[test]
    fn test_block_graph_result() {
        let result = BlockGraphResult::new(ProgramGraphType::Call, 10, 15);
        assert_eq!(result.vertex_count, 10);
        assert_eq!(result.edge_count, 15);
        assert_eq!(result.graph_type, ProgramGraphType::Call);
        assert_eq!(result.status, GraphTaskStatus::Completed);
    }
}
