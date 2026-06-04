//! Trace call tree GUI data model types.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.tracecalltree`
//! package in the Debugger module. Provides the call tree model types
//! for representing call hierarchies from trace data.

use serde::{Deserialize, Serialize};

/// The kind of a call tree node.
///
/// Ported from Ghidra's call tree node types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallTreeNodeKind {
    /// A regular function call.
    Call,
    /// A return from function.
    Return,
    /// An external/library function.
    External,
    /// A tail call.
    TailCall,
}

/// A node in the trace call tree.
///
/// Ported from Ghidra's `AbstractTraceCallTreeNode`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCallTreeNode {
    /// Unique key for this node.
    pub key: i64,
    /// The kind of node.
    pub kind: CallTreeNodeKind,
    /// Function name or address string.
    pub label: String,
    /// Start address of the function.
    pub address: u64,
    /// Depth in the call tree (0 = root).
    pub depth: u32,
    /// Parent node key (None for root).
    pub parent_key: Option<i64>,
    /// Child node keys.
    pub children: Vec<i64>,
    /// The snap at which this call was observed.
    pub snap: i64,
    /// Thread key this call belongs to.
    pub thread_key: i64,
    /// Optional library/module name for external calls.
    pub module_name: Option<String>,
}

impl TraceCallTreeNode {
    /// Create a new call tree node.
    pub fn new(
        key: i64,
        kind: CallTreeNodeKind,
        label: impl Into<String>,
        address: u64,
        depth: u32,
    ) -> Self {
        Self {
            key,
            kind,
            label: label.into(),
            address,
            depth,
            parent_key: None,
            children: Vec::new(),
            snap: 0,
            thread_key: 0,
            module_name: None,
        }
    }

    /// Whether this is a leaf node (no children).
    pub fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }

    /// Whether this is a root node (no parent).
    pub fn is_root(&self) -> bool {
        self.parent_key.is_none()
    }

    /// Whether this represents an external/library call.
    pub fn is_external(&self) -> bool {
        self.kind == CallTreeNodeKind::External
    }

    /// Add a child node key.
    pub fn add_child(&mut self, child_key: i64) {
        self.children.push(child_key);
    }
}

/// The call tree model managing a forest of call tree nodes.
///
/// Ported from Ghidra's `TraceCallTreeModel`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceCallTreeModel {
    /// All nodes, keyed by node key.
    nodes: std::collections::BTreeMap<i64, TraceCallTreeNode>,
    /// Root node keys (in display order).
    root_keys: Vec<i64>,
    next_key: i64,
}

impl TraceCallTreeModel {
    /// Create a new empty model.
    pub fn new() -> Self {
        Self::default()
    }

    fn allocate_key(&mut self) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        key
    }

    /// Add a root-level node.
    pub fn add_root(&mut self, mut node: TraceCallTreeNode) -> i64 {
        let key = node.key;
        node.parent_key = None;
        self.root_keys.push(key);
        self.nodes.insert(key, node);
        key
    }

    /// Add a child node to a parent.
    pub fn add_child(&mut self, parent_key: i64, mut node: TraceCallTreeNode) -> Option<i64> {
        let child_key = node.key;
        node.parent_key = Some(parent_key);
        node.depth = self.nodes.get(&parent_key).map_or(0, |p| p.depth + 1);
        self.nodes.insert(child_key, node);
        if let Some(parent) = self.nodes.get_mut(&parent_key) {
            parent.add_child(child_key);
            Some(child_key)
        } else {
            None
        }
    }

    /// Create and add a root node.
    pub fn create_root(
        &mut self,
        kind: CallTreeNodeKind,
        label: impl Into<String>,
        address: u64,
    ) -> i64 {
        let key = self.allocate_key();
        let node = TraceCallTreeNode::new(key, kind, label, address, 0);
        self.add_root(node);
        key
    }

    /// Create and add a child node.
    pub fn create_child(
        &mut self,
        parent_key: i64,
        kind: CallTreeNodeKind,
        label: impl Into<String>,
        address: u64,
    ) -> Option<i64> {
        let key = self.allocate_key();
        let depth = self.nodes.get(&parent_key).map_or(0, |p| p.depth + 1);
        let node = TraceCallTreeNode::new(key, kind, label, address, depth);
        self.add_child(parent_key, node)
    }

    /// Get a node by key.
    pub fn get_node(&self, key: i64) -> Option<&TraceCallTreeNode> {
        self.nodes.get(&key)
    }

    /// Get a mutable reference to a node by key.
    pub fn get_node_mut(&mut self, key: i64) -> Option<&mut TraceCallTreeNode> {
        self.nodes.get_mut(&key)
    }

    /// Get root node keys.
    pub fn root_keys(&self) -> &[i64] {
        &self.root_keys
    }

    /// Get children of a node.
    pub fn children(&self, parent_key: i64) -> Vec<&TraceCallTreeNode> {
        if let Some(parent) = self.nodes.get(&parent_key) {
            parent
                .children
                .iter()
                .filter_map(|&k| self.nodes.get(&k))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// The total number of nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// The depth of the deepest node.
    pub fn max_depth(&self) -> u32 {
        self.nodes.values().map(|n| n.depth).max().unwrap_or(0)
    }

    /// Remove a node and all its descendants.
    pub fn remove_node(&mut self, key: i64) -> bool {
        if let Some(node) = self.nodes.remove(&key) {
            // Remove from parent's children list
            if let Some(parent_key) = node.parent_key {
                if let Some(parent) = self.nodes.get_mut(&parent_key) {
                    parent.children.retain(|&k| k != key);
                }
            } else {
                self.root_keys.retain(|&k| k != key);
            }
            // Remove all descendants
            for child_key in &node.children {
                self.remove_subtree(*child_key);
            }
            true
        } else {
            false
        }
    }

    fn remove_subtree(&mut self, key: i64) {
        if let Some(node) = self.nodes.remove(&key) {
            for child_key in &node.children {
                self.remove_subtree(*child_key);
            }
        }
    }
}

/// A log context for the call tree, representing a position in the
/// call stack at a particular snap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCallTreeLogContext {
    /// The snap at which this log entry exists.
    pub snap: i64,
    /// The thread key.
    pub thread_key: i64,
    /// Stack of return addresses (deepest first).
    pub return_addresses: Vec<u64>,
    /// Stack of function addresses (deepest first).
    pub function_addresses: Vec<u64>,
}

impl TraceCallTreeLogContext {
    /// Create a new log context.
    pub fn new(snap: i64, thread_key: i64) -> Self {
        Self {
            snap,
            thread_key,
            return_addresses: Vec::new(),
            function_addresses: Vec::new(),
        }
    }

    /// Push a call frame.
    pub fn push_frame(&mut self, function_addr: u64, return_addr: u64) {
        self.function_addresses.push(function_addr);
        self.return_addresses.push(return_addr);
    }

    /// Pop a call frame.
    pub fn pop_frame(&mut self) -> Option<(u64, u64)> {
        let func = self.function_addresses.pop()?;
        let ret = self.return_addresses.pop()?;
        Some((func, ret))
    }

    /// The current call depth.
    pub fn depth(&self) -> usize {
        self.function_addresses.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_tree_node() {
        let node = TraceCallTreeNode::new(1, CallTreeNodeKind::Call, "main", 0x400000, 0);
        assert!(node.is_root());
        assert!(node.is_leaf());
        assert!(!node.is_external());
    }

    #[test]
    fn test_call_tree_node_external() {
        let mut node = TraceCallTreeNode::new(1, CallTreeNodeKind::External, "printf", 0x7f0000, 1);
        node.module_name = Some("libc.so".to_string());
        assert!(node.is_external());
        assert_eq!(node.module_name.as_deref(), Some("libc.so"));
    }

    #[test]
    fn test_call_tree_model() {
        let mut model = TraceCallTreeModel::new();
        let root = model.create_root(CallTreeNodeKind::Call, "main", 0x400000);
        let child = model.create_child(root, CallTreeNodeKind::Call, "funcA", 0x400100);

        assert!(child.is_some());
        assert_eq!(model.node_count(), 2);
        assert_eq!(model.root_keys().len(), 1);
        assert_eq!(model.max_depth(), 1);

        let children = model.children(root);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].label, "funcA");
    }

    #[test]
    fn test_call_tree_model_remove() {
        let mut model = TraceCallTreeModel::new();
        let root = model.create_root(CallTreeNodeKind::Call, "main", 0x400000);
        model.create_child(root, CallTreeNodeKind::Call, "funcA", 0x400100);
        model.create_child(root, CallTreeNodeKind::Call, "funcB", 0x400200);

        assert_eq!(model.node_count(), 3);
        model.remove_node(root);
        assert_eq!(model.node_count(), 0);
        assert!(model.root_keys().is_empty());
    }

    #[test]
    fn test_call_tree_model_get_node() {
        let mut model = TraceCallTreeModel::new();
        let root = model.create_root(CallTreeNodeKind::Call, "main", 0x400000);
        let node = model.get_node(root);
        assert!(node.is_some());
        assert_eq!(node.unwrap().label, "main");
    }

    #[test]
    fn test_call_tree_log_context() {
        let mut ctx = TraceCallTreeLogContext::new(10, 1);
        ctx.push_frame(0x400000, 0x400050);
        ctx.push_frame(0x400100, 0x400010);
        assert_eq!(ctx.depth(), 2);

        let (func, ret) = ctx.pop_frame().unwrap();
        assert_eq!(func, 0x400100);
        assert_eq!(ret, 0x400010);
        assert_eq!(ctx.depth(), 1);
    }
}
