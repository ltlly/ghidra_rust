//! Extended call tree GUI types for the debugger.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.tracecalltree` package.
//! Provides the call tree plugin data model for rendering call stacks as a tree.

use std::collections::BTreeMap;

/// Kind of node in the call tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallTreeNodeKind {
    /// A regular function call.
    Call,
    /// A return from a function.
    Return,
    /// An external (library) call.
    External,
    /// A tail call.
    TailCall,
}

/// A node in the trace call tree.
///
/// Corresponds to Java's `AbstractTraceCallTreeNode` and its subclasses.
#[derive(Debug, Clone)]
pub struct TraceCallTreeNode {
    /// Node identifier.
    pub node_id: u64,
    /// The kind of node.
    pub kind: CallTreeNodeKind,
    /// Function name or symbol.
    pub function_name: String,
    /// Address of the call/return.
    pub address: u64,
    /// Depth in the call stack.
    pub depth: u32,
    /// Snap (time point) when this was recorded.
    pub snap: i64,
    /// Child node IDs.
    pub children: Vec<u64>,
    /// Parent node ID, if any.
    pub parent_id: Option<u64>,
}

impl TraceCallTreeNode {
    /// Create a new call tree node.
    pub fn new(
        node_id: u64,
        kind: CallTreeNodeKind,
        function_name: impl Into<String>,
        address: u64,
        depth: u32,
        snap: i64,
    ) -> Self {
        Self {
            node_id,
            kind,
            function_name: function_name.into(),
            address,
            depth,
            snap,
            children: Vec::new(),
            parent_id: None,
        }
    }

    /// Add a child node.
    pub fn add_child(&mut self, child_id: u64) {
        self.children.push(child_id);
    }

    /// Get the number of children.
    pub fn child_count(&self) -> usize {
        self.children.len()
    }

    /// Check if this is a leaf node.
    pub fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }
}

/// Log context for call tree operations.
#[derive(Debug, Clone)]
pub struct TraceCallTreeLogContext {
    /// Thread ID.
    pub thread_id: u64,
    /// Process ID.
    pub process_id: u64,
    /// The snap range being viewed.
    pub snap_range: Option<(i64, i64)>,
}

impl TraceCallTreeLogContext {
    /// Create a new log context.
    pub fn new(thread_id: u64, process_id: u64) -> Self {
        Self {
            thread_id,
            process_id,
            snap_range: None,
        }
    }
}

/// Model for the trace call tree display.
///
/// Corresponds to Java's `TraceCallTreeModel` and `TraceCallTreeLogModel`.
#[derive(Debug)]
pub struct TraceCallTreeModel {
    /// All nodes by ID.
    nodes: BTreeMap<u64, TraceCallTreeNode>,
    /// Root node IDs.
    roots: Vec<u64>,
    /// Next available node ID.
    next_id: u64,
    /// Current log context.
    pub log_context: Option<TraceCallTreeLogContext>,
}

impl TraceCallTreeModel {
    /// Create a new call tree model.
    pub fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            roots: Vec::new(),
            next_id: 1,
            log_context: None,
        }
    }

    /// Add a root node.
    pub fn add_root(&mut self, mut node: TraceCallTreeNode) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        node.node_id = id;
        node.parent_id = None;
        self.roots.push(id);
        self.nodes.insert(id, node);
        id
    }

    /// Add a child to an existing node.
    pub fn add_child(&mut self, parent_id: u64, mut child: TraceCallTreeNode) -> Option<u64> {
        let id = self.next_id;
        self.next_id += 1;
        child.node_id = id;
        child.parent_id = Some(parent_id);

        if let Some(parent) = self.nodes.get_mut(&parent_id) {
            parent.add_child(id);
        } else {
            return None;
        }

        self.nodes.insert(id, child);
        Some(id)
    }

    /// Get a node by ID.
    pub fn get_node(&self, node_id: u64) -> Option<&TraceCallTreeNode> {
        self.nodes.get(&node_id)
    }

    /// Get the root nodes.
    pub fn roots(&self) -> Vec<&TraceCallTreeNode> {
        self.roots.iter().filter_map(|id| self.nodes.get(id)).collect()
    }

    /// Get the total number of nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get the maximum depth in the tree.
    pub fn max_depth(&self) -> u32 {
        self.nodes.values().map(|n| n.depth).max().unwrap_or(0)
    }

    /// Clear all nodes.
    pub fn clear(&mut self) {
        self.nodes.clear();
        self.roots.clear();
    }

    /// Get all nodes as a flat list.
    pub fn all_nodes(&self) -> Vec<&TraceCallTreeNode> {
        self.nodes.values().collect()
    }
}

impl Default for TraceCallTreeModel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_tree_node() {
        let node = TraceCallTreeNode::new(1, CallTreeNodeKind::Call, "main", 0x400000, 0, 0);
        assert_eq!(node.function_name, "main");
        assert_eq!(node.kind, CallTreeNodeKind::Call);
        assert!(node.is_leaf());
    }

    #[test]
    fn test_call_tree_model_add_root() {
        let mut model = TraceCallTreeModel::new();
        let root = TraceCallTreeNode::new(0, CallTreeNodeKind::Call, "main", 0x400000, 0, 0);
        let id = model.add_root(root);
        assert_eq!(id, 1);
        assert_eq!(model.roots().len(), 1);
        assert_eq!(model.node_count(), 1);
    }

    #[test]
    fn test_call_tree_model_add_child() {
        let mut model = TraceCallTreeModel::new();
        let root = TraceCallTreeNode::new(0, CallTreeNodeKind::Call, "main", 0x400000, 0, 0);
        let root_id = model.add_root(root);

        let child = TraceCallTreeNode::new(0, CallTreeNodeKind::Call, "foo", 0x400100, 1, 0);
        let child_id = model.add_child(root_id, child).unwrap();

        let parent = model.get_node(root_id).unwrap();
        assert_eq!(parent.child_count(), 1);
        assert!(!parent.is_leaf());

        let c = model.get_node(child_id).unwrap();
        assert_eq!(c.parent_id, Some(root_id));
    }

    #[test]
    fn test_call_tree_model_add_child_to_nonexistent() {
        let mut model = TraceCallTreeModel::new();
        let child = TraceCallTreeNode::new(0, CallTreeNodeKind::Call, "foo", 0x400100, 1, 0);
        assert!(model.add_child(999, child).is_none());
    }

    #[test]
    fn test_call_tree_model_max_depth() {
        let mut model = TraceCallTreeModel::new();
        let root = TraceCallTreeNode::new(0, CallTreeNodeKind::Call, "main", 0, 0, 0);
        let id = model.add_root(root);

        let child = TraceCallTreeNode::new(0, CallTreeNodeKind::Call, "a", 0, 1, 0);
        let c_id = model.add_child(id, child).unwrap();

        let grandchild = TraceCallTreeNode::new(0, CallTreeNodeKind::Call, "b", 0, 2, 0);
        model.add_child(c_id, grandchild);

        assert_eq!(model.max_depth(), 2);
    }

    #[test]
    fn test_call_tree_model_clear() {
        let mut model = TraceCallTreeModel::new();
        model.add_root(TraceCallTreeNode::new(0, CallTreeNodeKind::Call, "main", 0, 0, 0));
        model.clear();
        assert_eq!(model.node_count(), 0);
        assert!(model.roots().is_empty());
    }

    #[test]
    fn test_call_tree_log_context() {
        let ctx = TraceCallTreeLogContext::new(100, 1);
        assert_eq!(ctx.thread_id, 100);
        assert!(ctx.snap_range.is_none());
    }

    #[test]
    fn test_call_tree_node_kinds() {
        let kinds = [
            CallTreeNodeKind::Call,
            CallTreeNodeKind::Return,
            CallTreeNodeKind::External,
            CallTreeNodeKind::TailCall,
        ];
        for kind in &kinds {
            let node = TraceCallTreeNode::new(1, *kind, "func", 0, 0, 0);
            assert_eq!(node.kind, *kind);
        }
    }
}
