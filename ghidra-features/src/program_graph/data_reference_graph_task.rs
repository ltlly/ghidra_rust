//! Data reference graph generation task.
//!
//! Ported from Ghidra's `DataReferenceGraphTask` Java class.
//!
//! A background task that generates data reference graphs from a selected
//! address or selection in a program.

use super::data_reference_graph::Directions;

/// Configuration for a data reference graph task.
#[derive(Debug, Clone)]
pub struct DataReferenceGraphTaskConfig {
    /// Whether to reuse an existing graph display.
    pub reuse_graph: bool,
    /// Whether to append to an existing graph.
    pub append_to_graph: bool,
    /// Maximum depth of data references (0 for unlimited).
    pub data_max_depth: usize,
    /// Maximum code lines per block.
    pub code_limit_per_block: usize,
    /// Direction of references to follow.
    pub direction: Directions,
    /// Minimum address of the selection.
    pub selection_min: u64,
    /// Maximum address of the selection.
    pub selection_max: u64,
}

impl DataReferenceGraphTaskConfig {
    /// Create a new task configuration.
    pub fn new(
        reuse_graph: bool,
        append_to_graph: bool,
        data_max_depth: usize,
        code_limit_per_block: usize,
        direction: Directions,
    ) -> Self {
        Self {
            reuse_graph,
            append_to_graph,
            data_max_depth,
            code_limit_per_block,
            direction,
            selection_min: 0,
            selection_max: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let config = DataReferenceGraphTaskConfig::new(false, false, 2, 10, Directions::BothWays);
        assert!(!config.reuse_graph);
        assert!(!config.append_to_graph);
        assert_eq!(config.data_max_depth, 2);
        assert_eq!(config.code_limit_per_block, 10);
        assert_eq!(config.direction, Directions::BothWays);
    }
}
