//! Call tree table model.
//!
//! Ported from Ghidra's call tree table and tree node types.

use serde::{Deserialize, Serialize};

/// A node in the call tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallTreeNode {
    /// Function name.
    pub function_name: String,
    /// Function address.
    pub address: String,
    /// Depth in the call tree.
    pub depth: usize,
    /// Number of callees.
    pub callee_count: usize,
    /// Whether the function is a library function.
    pub is_library: bool,
    /// Whether the function is a thunk.
    pub is_thunk: bool,
}

impl CallTreeNode {
    pub fn new(name: &str, address: &str, depth: usize) -> Self {
        Self {
            function_name: name.to_string(),
            address: address.to_string(),
            depth,
            callee_count: 0,
            is_library: false,
            is_thunk: false,
        }
    }
    pub fn with_callee_count(mut self, count: usize) -> Self {
        self.callee_count = count; self
    }
    pub fn with_library(mut self, lib: bool) -> Self {
        self.is_library = lib; self
    }
    pub fn with_thunk(mut self, thunk: bool) -> Self {
        self.is_thunk = thunk; self
    }
}

/// The call tree table model.
#[derive(Debug, Default)]
pub struct CallTreeTableModel {
    nodes: Vec<CallTreeNode>,
    /// Whether to show callers (ancestors) or callees (descendants).
    pub show_callers: bool,
}

impl CallTreeTableModel {
    pub fn new() -> Self { Self::default() }
    pub fn add_node(&mut self, node: CallTreeNode) { self.nodes.push(node); }
    pub fn nodes(&self) -> &[CallTreeNode] { &self.nodes }
    pub fn len(&self) -> usize { self.nodes.len() }
    pub fn is_empty(&self) -> bool { self.nodes.is_empty() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_tree_node() {
        let node = CallTreeNode::new("main", "0x401000", 0)
            .with_callee_count(3).with_library(false);
        assert_eq!(node.function_name, "main");
        assert_eq!(node.depth, 0);
        assert_eq!(node.callee_count, 3);
    }

    #[test]
    fn test_call_tree_table_model() {
        let mut model = CallTreeTableModel::new();
        model.add_node(CallTreeNode::new("main", "0x401000", 0));
        model.add_node(CallTreeNode::new("foo", "0x402000", 1));
        model.add_node(CallTreeNode::new("bar", "0x403000", 2));
        assert_eq!(model.len(), 3);
    }
}
