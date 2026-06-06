//! Call tree panel types ported from
//! ghidra.app.plugin.core.debug.gui.tracecalltree.
//!
//! Provides the data model for the call tree panel.

use serde::{Deserialize, Serialize};

/// The kind of a call tree node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallTreeNodeKind {
    /// A function call.
    Function,
    /// A library call.
    Library,
    /// A system call.
    Syscall,
    /// An indirect call.
    Indirect,
    /// A return.
    Return,
    /// An unknown call.
    Unknown,
}

/// A node in the call tree (trace-aware version).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCallTreeNode {
    /// The node kind.
    pub kind: CallTreeNodeKind,
    /// Function name.
    pub name: String,
    /// Entry address.
    pub address: u64,
    /// Depth in the call stack.
    pub depth: usize,
    /// The snap at which this node was recorded.
    pub snap: i64,
    /// The thread key.
    pub thread_key: Option<u64>,
    /// Children (callees).
    pub children: Vec<TraceCallTreeNode>,
}

impl TraceCallTreeNode {
    /// Create a new call tree node.
    pub fn new(kind: CallTreeNodeKind, name: impl Into<String>, address: u64, depth: usize) -> Self {
        Self {
            kind,
            name: name.into(),
            address,
            depth,
            snap: 0,
            thread_key: None,
            children: Vec::new(),
        }
    }

    /// Add a child node.
    pub fn add_child(&mut self, child: TraceCallTreeNode) {
        self.children.push(child);
    }

    /// Total number of descendants.
    pub fn descendant_count(&self) -> usize {
        self.children.len() + self.children.iter().map(|c| c.descendant_count()).sum::<usize>()
    }
}

/// A log context for call tree operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCallTreeLogContext {
    /// The operation description.
    pub operation: String,
    /// The snap.
    pub snap: i64,
    /// The thread key.
    pub thread_key: Option<u64>,
    /// Whether this was a successful operation.
    pub success: bool,
    /// Error message if failed.
    pub error: Option<String>,
}

impl TraceCallTreeLogContext {
    /// Create a new log context.
    pub fn new(operation: impl Into<String>, snap: i64) -> Self {
        Self {
            operation: operation.into(),
            snap,
            thread_key: None,
            success: true,
            error: None,
        }
    }
}

/// The model for the call tree panel.
#[derive(Debug, Default)]
pub struct TraceCallTreeModel {
    /// Root nodes.
    pub roots: Vec<TraceCallTreeNode>,
    /// Log entries.
    pub log: Vec<TraceCallTreeLogContext>,
}

impl TraceCallTreeModel {
    /// Create a new empty model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a root node.
    pub fn add_root(&mut self, node: TraceCallTreeNode) {
        self.roots.push(node);
    }

    /// Add a log entry.
    pub fn log(&mut self, entry: TraceCallTreeLogContext) {
        self.log.push(entry);
    }

    /// Total number of nodes in the tree.
    pub fn total_nodes(&self) -> usize {
        self.roots.len() + self.roots.iter().map(|r| r.descendant_count()).sum::<usize>()
    }
}

/// A node in the call tree (simple version).
#[derive(Debug, Clone)]
pub struct CallTreeNode {
    /// Function name.
    pub name: String,
    /// Entry address.
    pub address: u64,
    /// Depth in the call stack.
    pub depth: usize,
    /// Children (callees).
    pub children: Vec<CallTreeNode>,
}

impl CallTreeNode {
    /// Create a new call tree node.
    pub fn new(name: impl Into<String>, address: u64, depth: usize) -> Self {
        Self {
            name: name.into(),
            address,
            depth,
            children: Vec::new(),
        }
    }

    /// Add a child node.
    pub fn add_child(&mut self, child: CallTreeNode) {
        self.children.push(child);
    }

    /// Total number of descendants.
    pub fn descendant_count(&self) -> usize {
        self.children.len() + self.children.iter().map(|c| c.descendant_count()).sum::<usize>()
    }
}

/// A call tree representing the call stack.
#[derive(Debug, Default)]
pub struct CallTree {
    /// Root nodes.
    pub roots: Vec<CallTreeNode>,
}

impl CallTree {
    /// Create a new empty call tree.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a root node.
    pub fn add_root(&mut self, node: CallTreeNode) {
        self.roots.push(node);
    }

    /// Total number of nodes in the tree.
    pub fn total_nodes(&self) -> usize {
        self.roots.len() + self.roots.iter().map(|r| r.descendant_count()).sum::<usize>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_tree() {
        let mut tree = CallTree::new();
        let mut root = CallTreeNode::new("main", 0x1000, 0);
        let mut func_a = CallTreeNode::new("funcA", 0x2000, 1);
        func_a.add_child(CallTreeNode::new("funcB", 0x3000, 2));
        root.add_child(func_a);
        tree.add_root(root);

        assert_eq!(tree.total_nodes(), 3);
        assert_eq!(tree.roots[0].descendant_count(), 2);
    }

    #[test]
    fn test_trace_call_tree_node() {
        let mut node = TraceCallTreeNode::new(CallTreeNodeKind::Function, "main", 0x1000, 0);
        node.snap = 42;
        node.add_child(TraceCallTreeNode::new(CallTreeNodeKind::Library, "printf", 0x2000, 1));
        assert_eq!(node.descendant_count(), 1);
    }

    #[test]
    fn test_trace_call_tree_model() {
        let mut model = TraceCallTreeModel::new();
        model.add_root(TraceCallTreeNode::new(CallTreeNodeKind::Function, "main", 0x1000, 0));
        assert_eq!(model.total_nodes(), 1);

        let ctx = TraceCallTreeLogContext::new("build_tree", 10);
        model.log(ctx);
        assert_eq!(model.log.len(), 1);
    }
}
