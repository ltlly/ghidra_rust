//! Call Tree -- function call and reference trees.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.calltree` Java package
//! and `functioncalls.graph` / `functioncalls.plugin` from
//! `Features/GraphFunctionCalls`.
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
//!
//! # Function Call Graph (ported from GraphFunctionCalls)
//!
//! - [`fcg_direction`] -- vertex direction enum (In, InAndOut, Out).
//! - [`fcg_level`] -- vertex level / row in the bow-tie layout.
//! - [`fcg_vertex`] -- a vertex in the function call graph.
//! - [`fcg_edge`] -- an edge in the function call graph.
//! - [`function_call_graph`] -- the main graph data structure.
//! - [`function_edge`] -- simple function-to-function edge.
//! - [`function_edge_cache`] -- cache of known function edges.
//! - [`fcg_data`] -- data abstraction layer (trait + valid/empty impls + factory).

/// Call tree options and configuration.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.calltree.CallTreeOptions`.
pub mod options;

/// Call tree table model.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.calltree.CallTreeTableModel`.
pub mod table;

/// Call tree provider and display configuration.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.calltree.CallTreeProvider`.
pub mod provider;

/// Call tree plugin -- top-level plugin coordinating providers.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.calltree.CallTreePlugin`.
pub mod plugin;

/// Function Call Graph direction enum (In, InAndOut, Out).
///
/// Ported from `functioncalls.graph.FcgDirection`.
pub mod fcg_direction;

/// Function Call Graph level (row + direction).
///
/// Ported from `functioncalls.graph.FcgLevel`.
pub mod fcg_level;

/// Function Call Graph vertex.
///
/// Ported from `functioncalls.graph.FcgVertex`.
pub mod fcg_vertex;

/// Function Call Graph edge.
///
/// Ported from `functioncalls.graph.FcgEdge`.
pub mod fcg_edge;

/// Function Call Graph -- the main graph data structure.
///
/// Ported from `functioncalls.graph.FunctionCallGraph`.
pub mod function_call_graph;

/// Simple function-to-function edge (not added to the visual graph).
///
/// Ported from `functioncalls.plugin.FunctionEdge`.
pub mod function_edge;

/// Cache of known function edges.
///
/// Ported from `functioncalls.plugin.FunctionEdgeCache`.
pub mod function_edge_cache;

/// FCG data abstraction (trait + valid/empty implementations + factory).
///
/// Ported from `functioncalls.plugin.FcgData`, `ValidFcgData`,
/// `EmptyFcgData`, and `FcgDataFactory`.
pub mod fcg_data;

use ghidra_core::Address;
use std::collections::{HashMap, HashSet};

use options::CallTreeOptions;

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

// ============================================================================
// CallNode hierarchy -- ported from Java CallNode, IncomingCallNode, etc.
// ============================================================================

/// A reference to a function in the call tree, including source address
/// and whether the reference is a call or a data reference.
///
/// Ported from Ghidra's `CallNode`, `IncomingCallNode`, `OutgoingCallNode`,
/// `ExternalCallNode`, and `DeadEndNode` Java classes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallRefNode {
    /// The name of the referenced function.
    pub name: String,
    /// The entry point address of the referenced function.
    pub address: Address,
    /// The source address where the reference originates.
    pub source_address: Address,
    /// Whether this is a call reference (vs. a data reference).
    pub is_call_reference: bool,
    /// The kind of call node.
    pub kind: CallNodeKind,
    /// Whether this node is a leaf (external or dead-end).
    pub is_leaf: bool,
}

/// The kind of call tree node.
///
/// Ported from the different `CallNode` subclasses in Java.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallNodeKind {
    /// An incoming (caller) node.
    Incoming,
    /// An outgoing (callee) node.
    Outgoing,
    /// An external library function.
    External,
    /// A dead-end reference (no target function found).
    DeadEnd,
}

impl CallRefNode {
    /// Create an incoming call node.
    pub fn incoming(
        name: impl Into<String>,
        address: Address,
        source_address: Address,
        is_call_reference: bool,
    ) -> Self {
        Self {
            name: name.into(),
            address,
            source_address,
            is_call_reference,
            kind: CallNodeKind::Incoming,
            is_leaf: false,
        }
    }

    /// Create an outgoing call node.
    pub fn outgoing(
        name: impl Into<String>,
        address: Address,
        source_address: Address,
        is_call_reference: bool,
    ) -> Self {
        Self {
            name: name.into(),
            address,
            source_address,
            is_call_reference,
            kind: CallNodeKind::Outgoing,
            is_leaf: false,
        }
    }

    /// Create an external call node.
    pub fn external(
        name: impl Into<String>,
        address: Address,
        source_address: Address,
        is_call_reference: bool,
    ) -> Self {
        Self {
            name: name.into(),
            address,
            source_address,
            is_call_reference,
            kind: CallNodeKind::External,
            is_leaf: true,
        }
    }

    /// Create a dead-end node.
    pub fn dead_end(
        name: impl Into<String>,
        address: Address,
        source_address: Address,
        is_call_reference: bool,
    ) -> Self {
        Self {
            name: name.into(),
            address,
            source_address,
            is_call_reference,
            kind: CallNodeKind::DeadEnd,
            is_leaf: true,
        }
    }

    /// Tooltip text for this node.
    pub fn tooltip(&self) -> String {
        let prefix = match self.kind {
            CallNodeKind::External => "(External) ",
            _ => "",
        };
        let ref_str = if self.is_call_reference {
            "Called from "
        } else {
            "Referenced from "
        };
        format!("{}{}{}", prefix, ref_str, self.source_address)
    }
}

// ---------------------------------------------------------------------------
// CallNodeConflictResolver -- resolves conflicting reference types
// ---------------------------------------------------------------------------

/// Resolves conflicts when both a call reference and a non-call reference
/// exist for the same source address to the same target function.
///
/// Ported from `CallNode.resovleConflictingReferenceTypes()`.
///
/// Returns `true` if the conflict was resolved (the new node was handled),
/// meaning the caller should not add it again.
pub fn resolve_conflicting_reference_types(
    nodes: &mut Vec<CallRefNode>,
    existing_idx: usize,
    new_node: &CallRefNode,
) -> bool {
    if existing_idx >= nodes.len() {
        return false;
    }
    let existing = &nodes[existing_idx];

    // Different source addresses -- nothing to do
    if existing.source_address != new_node.source_address {
        return false;
    }

    // Same reference type -- nothing to do
    if existing.is_call_reference == new_node.is_call_reference {
        return false;
    }

    // Same source address, same target, different reference types.
    // Prefer the call reference over the non-call reference.
    if !existing.is_call_reference && new_node.is_call_reference {
        // Swap: replace existing non-call with new call reference
        nodes[existing_idx] = new_node.clone();
    }
    // else: existing is already a call reference, discard the new non-call reference
    true
}

/// Add a node to a collection of call ref nodes, resolving duplicates
/// and conflicts according to the call tree options.
///
/// Ported from `CallNode.addNode()`.
pub fn add_call_ref_node(
    nodes: &mut Vec<CallRefNode>,
    new_node: CallRefNode,
    options: &CallTreeOptions,
) -> bool {
    // If the new node is a non-call reference and references are filtered, skip it
    if !new_node.is_call_reference && !options.show_references {
        return false;
    }

    // Check for duplicates
    for i in 0..nodes.len() {
        if nodes[i].address == new_node.address
            && nodes[i].source_address == new_node.source_address
            && nodes[i].is_call_reference == new_node.is_call_reference
        {
            return false; // exact duplicate, skip
        }

        // Resolve call vs. non-call conflicts
        if resolve_conflicting_reference_types(nodes, i, &new_node) {
            return true;
        }
    }

    // If duplicates are allowed or this is the first node for this function, add it
    if options.show_references || new_node.is_call_reference {
        nodes.push(new_node);
        return true;
    }
    false
}

/// Sort call ref nodes by source address, then by reference type.
///
/// Ported from `CallNodeComparator`.
pub fn sort_call_ref_nodes(nodes: &mut [CallRefNode]) {
    nodes.sort_by(|a, b| {
        a.source_address
            .offset
            .cmp(&b.source_address.offset)
            .then_with(|| a.is_call_reference.cmp(&b.is_call_reference))
    });
}

// ===========================================================================
// Tests for CallNode hierarchy
// ===========================================================================

#[cfg(test)]
mod call_node_tests {
    use super::*;

    #[test]
    fn test_call_ref_node_incoming() {
        let node = CallRefNode::incoming(
            "main",
            Address::new(0x1000),
            Address::new(0x2000),
            true,
        );
        assert_eq!(node.kind, CallNodeKind::Incoming);
        assert!(!node.is_leaf);
        assert!(node.is_call_reference);
        assert!(node.tooltip().contains("Called from"));
    }

    #[test]
    fn test_call_ref_node_outgoing() {
        let node = CallRefNode::outgoing(
            "foo",
            Address::new(0x2000),
            Address::new(0x1000),
            true,
        );
        assert_eq!(node.kind, CallNodeKind::Outgoing);
        assert!(!node.is_leaf);
    }

    #[test]
    fn test_call_ref_node_external() {
        let node = CallRefNode::external(
            "printf",
            Address::new(0x3000),
            Address::new(0x1000),
            true,
        );
        assert_eq!(node.kind, CallNodeKind::External);
        assert!(node.is_leaf);
        assert!(node.tooltip().contains("(External)"));
    }

    #[test]
    fn test_call_ref_node_dead_end() {
        let node = CallRefNode::dead_end(
            "0xdeadbeef",
            Address::new(0xdeadbeef),
            Address::new(0x1000),
            true,
        );
        assert_eq!(node.kind, CallNodeKind::DeadEnd);
        assert!(node.is_leaf);
    }

    #[test]
    fn test_tooltip_reference() {
        let node = CallRefNode::incoming(
            "main",
            Address::new(0x1000),
            Address::new(0x2000),
            false,
        );
        assert!(node.tooltip().contains("Referenced from"));
    }

    #[test]
    fn test_resolve_conflicting_reference_types_prefers_call() {
        let existing = CallRefNode::incoming("foo", Address::new(0x2000), Address::new(0x1000), false);
        let new_node = CallRefNode::incoming("foo", Address::new(0x2000), Address::new(0x1000), true);
        let mut nodes = vec![existing];
        let resolved = resolve_conflicting_reference_types(&mut nodes, 0, &new_node);
        assert!(resolved);
        assert!(nodes[0].is_call_reference);
    }

    #[test]
    fn test_resolve_conflicting_different_source_returns_false() {
        let existing = CallRefNode::incoming("foo", Address::new(0x2000), Address::new(0x1000), false);
        let new_node = CallRefNode::incoming("foo", Address::new(0x2000), Address::new(0x3000), true);
        let mut nodes = vec![existing];
        let resolved = resolve_conflicting_reference_types(&mut nodes, 0, &new_node);
        assert!(!resolved);
    }

    #[test]
    fn test_add_call_ref_node_dedup() {
        let mut nodes = Vec::new();
        let opts = CallTreeOptions::default();
        let node1 = CallRefNode::incoming("foo", Address::new(0x2000), Address::new(0x1000), true);
        let node2 = CallRefNode::incoming("foo", Address::new(0x2000), Address::new(0x1000), true);
        assert!(add_call_ref_node(&mut nodes, node1, &opts));
        assert!(!add_call_ref_node(&mut nodes, node2, &opts));
        assert_eq!(nodes.len(), 1);
    }

    #[test]
    fn test_add_call_ref_node_different_source() {
        let mut nodes = Vec::new();
        let opts = CallTreeOptions::default();
        let node1 = CallRefNode::incoming("foo", Address::new(0x2000), Address::new(0x1000), true);
        let node2 = CallRefNode::incoming("foo", Address::new(0x2000), Address::new(0x1500), true);
        assert!(add_call_ref_node(&mut nodes, node1, &opts));
        assert!(add_call_ref_node(&mut nodes, node2, &opts));
        assert_eq!(nodes.len(), 2);
    }

    #[test]
    fn test_sort_call_ref_nodes() {
        let mut nodes = vec![
            CallRefNode::incoming("b", Address::new(0x2000), Address::new(0x3000), true),
            CallRefNode::incoming("a", Address::new(0x1000), Address::new(0x1000), true),
            CallRefNode::incoming("c", Address::new(0x3000), Address::new(0x2000), false),
        ];
        sort_call_ref_nodes(&mut nodes);
        assert_eq!(nodes[0].source_address.offset, 0x1000);
        assert_eq!(nodes[1].source_address.offset, 0x2000);
        assert_eq!(nodes[2].source_address.offset, 0x3000);
    }

    // -- IncomingCallsRootNode / OutgoingCallsRootNode tests --

    #[test]
    fn test_incoming_calls_root_node() {
        let root = IncomingCallsRootNode::new("main", Address::new(0x401000));
        assert_eq!(root.name(), "main");
        assert_eq!(root.direction(), CallTreeDirection::Incoming);
        assert!(root.children().is_empty());
    }

    #[test]
    fn test_outgoing_calls_root_node() {
        let root = OutgoingCallsRootNode::new("main", Address::new(0x401000));
        assert_eq!(root.name(), "main");
        assert_eq!(root.direction(), CallTreeDirection::Outgoing);
    }

    #[test]
    fn test_incoming_calls_root_node_add_child() {
        let mut root = IncomingCallsRootNode::new("main", Address::new(0x401000));
        root.add_child(CallRefNode::incoming("caller1", Address::new(0x402000), Address::new(0x401000), true));
        root.add_child(CallRefNode::incoming("caller2", Address::new(0x403000), Address::new(0x401000), false));
        assert_eq!(root.children().len(), 2);
        assert_eq!(root.total_count(), 2);
    }

    #[test]
    fn test_outgoing_calls_root_node_filter() {
        let mut root = OutgoingCallsRootNode::new("main", Address::new(0x401000));
        root.add_child(CallRefNode::outgoing("func_a", Address::new(0x401000), Address::new(0x404000), true));
        root.add_child(CallRefNode::outgoing("func_b", Address::new(0x401000), Address::new(0x405000), false));
        let calls_only = root.children_calls_only();
        assert_eq!(calls_only.len(), 1);
        assert_eq!(calls_only[0].name, "func_a");
    }
}

// ---------------------------------------------------------------------------
// IncomingCallsRootNode / OutgoingCallsRootNode
//
// Ported from `IncomingCallsRootNode.java` and `OutgoingCallsRootNode.java`
// in `ghidra.app.plugin.core.calltree`.
//
// These are the root nodes of the incoming and outgoing call trees.
// They wrap the target function and provide the typed children list.
// ---------------------------------------------------------------------------

/// Root node of the incoming (callers) call tree.
///
/// This node represents the target function at the root of the
/// "Who calls this function?" tree.
#[derive(Debug, Clone)]
pub struct IncomingCallsRootNode {
    /// Name of the target function.
    name: String,
    /// Entry point address of the target function.
    address: Address,
    /// Child nodes (callers).
    children: Vec<CallRefNode>,
}

impl IncomingCallsRootNode {
    /// Create a new incoming calls root node.
    pub fn new(name: impl Into<String>, address: Address) -> Self {
        Self {
            name: name.into(),
            address,
            children: Vec::new(),
        }
    }

    /// Get the function name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the function address.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Get the tree direction.
    pub fn direction(&self) -> CallTreeDirection {
        CallTreeDirection::Incoming
    }

    /// Add a caller node.
    pub fn add_child(&mut self, child: CallRefNode) {
        self.children.push(child);
    }

    /// Get the children (callers).
    pub fn children(&self) -> &[CallRefNode] {
        &self.children
    }

    /// Total number of callers.
    pub fn total_count(&self) -> usize {
        self.children.len()
    }

    /// Get only callers that are direct calls (not references).
    pub fn children_calls_only(&self) -> Vec<&CallRefNode> {
        self.children.iter().filter(|c| c.is_call_reference).collect()
    }
}

/// Root node of the outgoing (callees) call tree.
///
/// This node represents the target function at the root of the
/// "What does this function call?" tree.
#[derive(Debug, Clone)]
pub struct OutgoingCallsRootNode {
    /// Name of the target function.
    name: String,
    /// Entry point address of the target function.
    address: Address,
    /// Child nodes (callees).
    children: Vec<CallRefNode>,
}

impl OutgoingCallsRootNode {
    /// Create a new outgoing calls root node.
    pub fn new(name: impl Into<String>, address: Address) -> Self {
        Self {
            name: name.into(),
            address,
            children: Vec::new(),
        }
    }

    /// Get the function name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the function address.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Get the tree direction.
    pub fn direction(&self) -> CallTreeDirection {
        CallTreeDirection::Outgoing
    }

    /// Add a callee node.
    pub fn add_child(&mut self, child: CallRefNode) {
        self.children.push(child);
    }

    /// Get the children (callees).
    pub fn children(&self) -> &[CallRefNode] {
        &self.children
    }

    /// Total number of callees.
    pub fn total_count(&self) -> usize {
        self.children.len()
    }

    /// Get only callees that are direct calls (not references).
    pub fn children_calls_only(&self) -> Vec<&CallRefNode> {
        self.children.iter().filter(|c| c.is_call_reference).collect()
    }
}
