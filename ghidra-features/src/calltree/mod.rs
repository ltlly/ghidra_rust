//! Call Tree -- function call and reference trees.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.calltree` Java package.
//!
//! Provides two trees for a given function `foo`:
//!
//! 1. **Callers tree** -- all functions that call or reference `foo`.
//! 2. **Callees tree** -- all functions that `foo` calls or references.
//!
//! # Architecture
//!
//! - [`CallTreeNode`] -- a node in the call tree (function + depth + children).
//! - [`CallTree`] -- a complete call tree for a function.
//! - [`CallTreeBuilder`] -- builds call trees from function metadata.
//! - [`CallTreeDirection`] -- incoming (callers) or outgoing (callees).

use ghidra_core::Address;
use std::collections::{HashMap, HashSet, VecDeque};

// ============================================================================
// CallTreeDirection -- incoming or outgoing
// ============================================================================

/// Direction of the call tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallTreeDirection {
    /// Callers (incoming calls / references to a function).
    Incoming,
    /// Callees (outgoing calls / references from a function).
    Outgoing,
}

// ============================================================================
// CallTreeEdgeType -- call or reference
// ============================================================================

/// The type of edge between two functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallTreeEdgeType {
    /// A direct call instruction.
    Call,
    /// A data or other non-call reference.
    Reference,
}

// ============================================================================
// CallTreeNode -- a node in the call tree
// ============================================================================

/// A node in the call tree representing a function at a given depth.
#[derive(Debug, Clone)]
pub struct CallTreeNode {
    /// The function name.
    pub name: String,
    /// The entry point address.
    pub address: Address,
    /// Depth in the tree (0 = root).
    pub depth: usize,
    /// Edge type connecting this node to its parent.
    pub edge_type: CallTreeEdgeType,
    /// Child nodes.
    pub children: Vec<CallTreeNode>,
    /// Whether this node has been fully expanded.
    pub expanded: bool,
}

impl CallTreeNode {
    /// Create a new call tree node.
    pub fn new(name: impl Into<String>, address: Address, depth: usize) -> Self {
        Self {
            name: name.into(),
            address,
            depth,
            edge_type: CallTreeEdgeType::Call,
            children: Vec::new(),
            expanded: false,
        }
    }

    /// Add a child node.
    pub fn add_child(&mut self, child: CallTreeNode) {
        self.children.push(child);
    }

    /// Count the total number of nodes in this subtree.
    pub fn node_count(&self) -> usize {
        1 + self.children.iter().map(|c| c.node_count()).sum::<usize>()
    }

    /// Find the maximum depth of this subtree.
    pub fn max_depth(&self) -> usize {
        if self.children.is_empty() {
            self.depth
        } else {
            self.children
                .iter()
                .map(|c| c.max_depth())
                .max()
                .unwrap_or(self.depth)
        }
    }

    /// Flatten this subtree into a list of (depth, name, address) tuples.
    pub fn flatten(&self) -> Vec<(usize, &str, Address)> {
        let mut result = Vec::new();
        self.flatten_into(&mut result);
        result
    }

    fn flatten_into<'a>(&'a self, out: &mut Vec<(usize, &'a str, Address)>) {
        out.push((self.depth, &self.name, self.address));
        for child in &self.children {
            child.flatten_into(out);
        }
    }
}

// ============================================================================
// CallTree -- a complete call tree
// ============================================================================

/// A complete call tree for a target function.
#[derive(Debug, Clone)]
pub struct CallTree {
    /// The root node (the target function).
    pub root: CallTreeNode,
    /// The direction of this tree.
    pub direction: CallTreeDirection,
    /// Total unique functions in the tree.
    pub unique_function_count: usize,
}

impl CallTree {
    /// Create a new call tree.
    pub fn new(root: CallTreeNode, direction: CallTreeDirection) -> Self {
        let unique_function_count = root.node_count();
        Self {
            root,
            direction,
            unique_function_count,
        }
    }
}

// ============================================================================
// FunctionRef -- lightweight function reference for building trees
// ============================================================================

/// A reference to a function (name, address).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FunctionRef {
    /// The function name.
    pub name: String,
    /// The function entry point address.
    pub address: Address,
}

impl FunctionRef {
    /// Create a new function reference.
    pub fn new(name: impl Into<String>, address: Address) -> Self {
        Self {
            name: name.into(),
            address,
        }
    }
}

// ============================================================================
// CallTreeBuilder -- builds call trees from function metadata
// ============================================================================

/// Builds call trees from caller/callee relationship data.
///
/// Callers and callees are provided as adjacency lists:
/// - `callers[f]` = set of functions that call `f`.
/// - `callees[f]` = set of functions that `f` calls.
#[derive(Debug, Default)]
pub struct CallTreeBuilder {
    /// Caller relationships: function address -> addresses of callers.
    callers: HashMap<u64, Vec<(u64, CallTreeEdgeType)>>,
    /// Callee relationships: function address -> addresses of callees.
    callees: HashMap<u64, Vec<(u64, CallTreeEdgeType)>>,
    /// Function metadata: address -> FunctionRef.
    functions: HashMap<u64, FunctionRef>,
}

impl CallTreeBuilder {
    /// Create a new call tree builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a function.
    pub fn add_function(&mut self, func: FunctionRef) {
        self.functions.insert(func.address.offset, func);
    }

    /// Record that `caller` calls `callee`.
    pub fn add_call(&mut self, caller: Address, callee: Address, edge_type: CallTreeEdgeType) {
        self.callees
            .entry(caller.offset)
            .or_default()
            .push((callee.offset, edge_type));
        self.callers
            .entry(callee.offset)
            .or_default()
            .push((caller.offset, edge_type));
    }

    /// Build an incoming call tree (callers of the target function).
    pub fn build_incoming(&self, target: Address, max_depth: usize) -> CallTree {
        let root_name = self
            .functions
            .get(&target.offset)
            .map(|f| f.name.clone())
            .unwrap_or_else(|| format!("FUN_{:x}", target.offset));
        let mut root = CallTreeNode::new(root_name, target, 0);
        let mut visited = HashSet::new();
        visited.insert(target.offset);
        self.build_incoming_recursive(&mut root, &mut visited, max_depth);
        CallTree::new(root, CallTreeDirection::Incoming)
    }

    /// Build an outgoing call tree (callees of the target function).
    pub fn build_outgoing(&self, target: Address, max_depth: usize) -> CallTree {
        let root_name = self
            .functions
            .get(&target.offset)
            .map(|f| f.name.clone())
            .unwrap_or_else(|| format!("FUN_{:x}", target.offset));
        let mut root = CallTreeNode::new(root_name, target, 0);
        let mut visited = HashSet::new();
        visited.insert(target.offset);
        self.build_outgoing_recursive(&mut root, &mut visited, max_depth);
        CallTree::new(root, CallTreeDirection::Outgoing)
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn build_incoming_recursive(
        &self,
        node: &mut CallTreeNode,
        visited: &mut HashSet<u64>,
        max_depth: usize,
    ) {
        if node.depth >= max_depth {
            return;
        }
        if let Some(caller_list) = self.callers.get(&node.address.offset) {
            for &(caller_addr, edge_type) in caller_list {
                if visited.contains(&caller_addr) {
                    continue;
                }
                visited.insert(caller_addr);
                let name = self
                    .functions
                    .get(&caller_addr)
                    .map(|f| f.name.clone())
                    .unwrap_or_else(|| format!("FUN_{:x}", caller_addr));
                let mut child = CallTreeNode::new(name, Address::new(caller_addr), node.depth + 1);
                child.edge_type = edge_type;
                self.build_incoming_recursive(&mut child, visited, max_depth);
                node.add_child(child);
            }
        }
    }

    fn build_outgoing_recursive(
        &self,
        node: &mut CallTreeNode,
        visited: &mut HashSet<u64>,
        max_depth: usize,
    ) {
        if node.depth >= max_depth {
            return;
        }
        if let Some(callee_list) = self.callees.get(&node.address.offset) {
            for &(callee_addr, edge_type) in callee_list {
                if visited.contains(&callee_addr) {
                    continue;
                }
                visited.insert(callee_addr);
                let name = self
                    .functions
                    .get(&callee_addr)
                    .map(|f| f.name.clone())
                    .unwrap_or_else(|| format!("FUN_{:x}", callee_addr));
                let mut child = CallTreeNode::new(name, Address::new(callee_addr), node.depth + 1);
                child.edge_type = edge_type;
                self.build_outgoing_recursive(&mut child, visited, max_depth);
                node.add_child(child);
            }
        }
    }
}

// ============================================================================
// CallTreeStatistics -- compute statistics about a call tree
// ============================================================================

/// Statistics about a call tree.
#[derive(Debug, Clone)]
pub struct CallTreeStatistics {
    /// Total number of unique functions.
    pub total_functions: usize,
    /// Maximum call depth.
    pub max_depth: usize,
    /// The function with the most callers/callees.
    pub most_connected: Option<String>,
    /// Number of direct calls (vs references).
    pub direct_calls: usize,
    /// Number of references (non-call).
    pub references: usize,
    /// The average number of children per node.
    pub avg_children: f64,
}

impl CallTreeStatistics {
    /// Compute statistics from a call tree.
    pub fn from_tree(tree: &CallTree) -> Self {
        let total = tree.root.node_count();
        let max_depth = tree.root.max_depth();
        let mut most_connected_name = None;
        let mut max_children = 0;
        let mut total_children = 0;
        let mut direct_calls = 0;
        let mut references = 0;

        Self::walk_tree(&tree.root, &mut most_connected_name, &mut max_children,
                        &mut total_children, &mut direct_calls, &mut references);

        let avg_children = if total > 0 {
            total_children as f64 / total as f64
        } else {
            0.0
        };

        Self {
            total_functions: total,
            max_depth,
            most_connected: most_connected_name,
            direct_calls,
            references,
            avg_children,
        }
    }

    fn walk_tree(
        node: &CallTreeNode,
        most_connected: &mut Option<String>,
        max_children: &mut usize,
        total_children: &mut usize,
        direct_calls: &mut usize,
        references: &mut usize,
    ) {
        let child_count = node.children.len();
        *total_children += child_count;
        if child_count > *max_children {
            *max_children = child_count;
            *most_connected = Some(node.name.clone());
        }

        for child in &node.children {
            match child.edge_type {
                CallTreeEdgeType::Call => *direct_calls += 1,
                CallTreeEdgeType::Reference => *references += 1,
            }
            Self::walk_tree(child, most_connected, max_children, total_children, direct_calls, references);
        }
    }
}

/// Find all paths from the root to a specific function in the tree.
pub fn find_paths_to(root: &CallTreeNode, target_address: Address) -> Vec<Vec<String>> {
    let mut paths = Vec::new();
    let mut current_path = Vec::new();
    find_paths_recursive(root, target_address, &mut current_path, &mut paths);
    paths
}

fn find_paths_recursive(
    node: &CallTreeNode,
    target: Address,
    current_path: &mut Vec<String>,
    all_paths: &mut Vec<Vec<String>>,
) {
    current_path.push(node.name.clone());

    if node.address == target {
        all_paths.push(current_path.clone());
    }

    for child in &node.children {
        find_paths_recursive(child, target, current_path, all_paths);
    }

    current_path.pop();
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_builder() -> CallTreeBuilder {
        let mut builder = CallTreeBuilder::new();
        builder.add_function(FunctionRef::new("main", Address::new(0x1000)));
        builder.add_function(FunctionRef::new("foo", Address::new(0x2000)));
        builder.add_function(FunctionRef::new("bar", Address::new(0x3000)));
        builder.add_function(FunctionRef::new("baz", Address::new(0x4000)));
        // main calls foo, foo calls bar, foo calls baz
        builder.add_call(Address::new(0x1000), Address::new(0x2000), CallTreeEdgeType::Call);
        builder.add_call(Address::new(0x2000), Address::new(0x3000), CallTreeEdgeType::Call);
        builder.add_call(Address::new(0x2000), Address::new(0x4000), CallTreeEdgeType::Call);
        builder
    }

    #[test]
    fn test_outgoing_tree_from_main() {
        let builder = setup_builder();
        let tree = builder.build_outgoing(Address::new(0x1000), 10);
        assert_eq!(tree.direction, CallTreeDirection::Outgoing);
        assert_eq!(tree.root.name, "main");
        assert_eq!(tree.root.children.len(), 1); // foo
        assert_eq!(tree.root.children[0].name, "foo");
        assert_eq!(tree.root.children[0].children.len(), 2); // bar, baz
    }

    #[test]
    fn test_incoming_tree_from_bar() {
        let builder = setup_builder();
        let tree = builder.build_incoming(Address::new(0x3000), 10);
        assert_eq!(tree.direction, CallTreeDirection::Incoming);
        assert_eq!(tree.root.name, "bar");
        assert_eq!(tree.root.children.len(), 1); // foo
        assert_eq!(tree.root.children[0].name, "foo");
        assert_eq!(tree.root.children[0].children.len(), 1); // main
        assert_eq!(tree.root.children[0].children[0].name, "main");
    }

    #[test]
    fn test_max_depth_limit() {
        let builder = setup_builder();
        let tree = builder.build_outgoing(Address::new(0x1000), 1);
        // Depth 1 means only one level of children
        assert_eq!(tree.root.children.len(), 1);
        assert!(tree.root.children[0].children.is_empty());
    }

    #[test]
    fn test_node_count() {
        let builder = setup_builder();
        let tree = builder.build_outgoing(Address::new(0x1000), 10);
        // main, foo, bar, baz = 4 nodes
        assert_eq!(tree.unique_function_count, 4);
    }

    #[test]
    fn test_flatten() {
        let builder = setup_builder();
        let tree = builder.build_outgoing(Address::new(0x1000), 10);
        let flat = tree.root.flatten();
        assert_eq!(flat.len(), 4);
        assert_eq!(flat[0].1, "main");
        assert_eq!(flat[0].0, 0);
    }

    #[test]
    fn test_unknown_function() {
        let builder = CallTreeBuilder::new();
        let tree = builder.build_outgoing(Address::new(0x9999), 5);
        assert_eq!(tree.root.name, "FUN_9999");
        assert!(tree.root.children.is_empty());
    }

    #[test]
    fn test_circular_calls_no_infinite_loop() {
        let mut builder = CallTreeBuilder::new();
        builder.add_function(FunctionRef::new("a", Address::new(0x1000)));
        builder.add_function(FunctionRef::new("b", Address::new(0x2000)));
        builder.add_call(Address::new(0x1000), Address::new(0x2000), CallTreeEdgeType::Call);
        builder.add_call(Address::new(0x2000), Address::new(0x1000), CallTreeEdgeType::Call);
        let tree = builder.build_outgoing(Address::new(0x1000), 100);
        // Should terminate without infinite loop
        assert!(tree.unique_function_count <= 2);
    }

    #[test]
    fn test_reference_edge_type() {
        let mut builder = CallTreeBuilder::new();
        builder.add_function(FunctionRef::new("main", Address::new(0x1000)));
        builder.add_function(FunctionRef::new("data", Address::new(0x2000)));
        builder.add_call(
            Address::new(0x1000),
            Address::new(0x2000),
            CallTreeEdgeType::Reference,
        );
        let tree = builder.build_outgoing(Address::new(0x1000), 10);
        assert_eq!(tree.root.children[0].edge_type, CallTreeEdgeType::Reference);
    }

    #[test]
    fn test_call_tree_statistics() {
        let builder = setup_builder();
        let tree = builder.build_outgoing(Address::new(0x1000), 10);
        let stats = CallTreeStatistics::from_tree(&tree);
        assert_eq!(stats.total_functions, 4);
        assert_eq!(stats.max_depth, 2);
        assert!(stats.direct_calls > 0);
        assert_eq!(stats.references, 0); // all are calls in setup
    }

    #[test]
    fn test_find_paths_to() {
        let builder = setup_builder();
        let tree = builder.build_outgoing(Address::new(0x1000), 10);
        let paths = find_paths_to(&tree.root, Address::new(0x3000));
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], vec!["main", "foo", "bar"]);
    }

    #[test]
    fn test_find_paths_to_nonexistent() {
        let builder = setup_builder();
        let tree = builder.build_outgoing(Address::new(0x1000), 10);
        let paths = find_paths_to(&tree.root, Address::new(0x9999));
        assert!(paths.is_empty());
    }

    #[test]
    fn test_statistics_most_connected() {
        let builder = setup_builder();
        let tree = builder.build_outgoing(Address::new(0x1000), 10);
        let stats = CallTreeStatistics::from_tree(&tree);
        // foo has 2 children (bar, baz) so it should be most connected
        assert_eq!(stats.most_connected, Some("foo".into()));
    }

    #[test]
    fn test_statistics_with_references() {
        let mut builder = CallTreeBuilder::new();
        builder.add_function(FunctionRef::new("main", Address::new(0x1000)));
        builder.add_function(FunctionRef::new("func", Address::new(0x2000)));
        builder.add_function(FunctionRef::new("data", Address::new(0x3000)));
        builder.add_call(Address::new(0x1000), Address::new(0x2000), CallTreeEdgeType::Call);
        builder.add_call(Address::new(0x1000), Address::new(0x3000), CallTreeEdgeType::Reference);

        let tree = builder.build_outgoing(Address::new(0x1000), 10);
        let stats = CallTreeStatistics::from_tree(&tree);
        assert_eq!(stats.direct_calls, 1);
        assert_eq!(stats.references, 1);
    }
}
