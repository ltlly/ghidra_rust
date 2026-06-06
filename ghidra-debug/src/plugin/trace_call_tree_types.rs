//! Trace call tree node types and model.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.tracecalltree` package.
//! Provides the data model types for the trace call tree panel, which displays
//! the call stack hierarchy from a debug trace.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

// ---------------------------------------------------------------------------
// CallTreeNodeKind
// ---------------------------------------------------------------------------

/// The kind of a node in the trace call tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallTreeNodeKind {
    /// A regular function call node.
    Call,
    /// A return from function node.
    Return,
    /// A tail call (call that does not return to caller).
    TailCall,
    /// An external/library function call.
    External,
    /// A signal handler entry.
    Signal,
    /// A synthetic node (e.g., thread entry).
    Synthetic,
}

impl CallTreeNodeKind {
    /// Display name for this node kind.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Call => "Call",
            Self::Return => "Return",
            Self::TailCall => "Tail Call",
            Self::External => "External",
            Self::Signal => "Signal",
            Self::Synthetic => "Synthetic",
        }
    }

    /// Whether this represents an actual function call.
    pub fn is_call(&self) -> bool {
        matches!(self, Self::Call | Self::TailCall)
    }

    /// Whether this is a return-related node.
    pub fn is_return(&self) -> bool {
        matches!(self, Self::Return)
    }

    /// Whether this is an external call.
    pub fn is_external(&self) -> bool {
        matches!(self, Self::External)
    }
}

impl fmt::Display for CallTreeNodeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ---------------------------------------------------------------------------
// AbstractTraceCallTreeNode -- base for all call tree nodes
// ---------------------------------------------------------------------------

/// Data shared by all call tree node types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallTreeNodeData {
    /// Unique node ID within the tree.
    pub id: u64,
    /// The kind of this node.
    pub kind: CallTreeNodeKind,
    /// The address of the instruction (PC at this point).
    pub address: u64,
    /// The snapshot (time) at which this node was observed.
    pub snap: i64,
    /// The depth in the call stack (0 = innermost).
    pub depth: usize,
    /// The thread key this node belongs to.
    pub thread_key: Option<i64>,
    /// The function name, if known.
    pub function_name: Option<String>,
    /// The parent node ID, if any.
    pub parent_id: Option<u64>,
    /// Child node IDs.
    pub children: Vec<u64>,
    /// Additional metadata.
    pub metadata: HashMap<String, String>,
}

impl CallTreeNodeData {
    /// Create new node data.
    pub fn new(
        id: u64,
        kind: CallTreeNodeKind,
        address: u64,
        snap: i64,
        depth: usize,
    ) -> Self {
        Self {
            id,
            kind,
            address,
            snap,
            depth,
            thread_key: None,
            function_name: None,
            parent_id: None,
            children: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Set the thread key.
    pub fn with_thread_key(mut self, key: i64) -> Self {
        self.thread_key = Some(key);
        self
    }

    /// Set the function name.
    pub fn with_function_name(mut self, name: impl Into<String>) -> Self {
        self.function_name = Some(name.into());
        self
    }

    /// Set the parent node ID.
    pub fn with_parent(mut self, parent_id: u64) -> Self {
        self.parent_id = Some(parent_id);
        self
    }

    /// Add a child node ID.
    pub fn add_child(&mut self, child_id: u64) {
        if !self.children.contains(&child_id) {
            self.children.push(child_id);
        }
    }

    /// Whether this node is a leaf (no children).
    pub fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }

    /// Whether this node is the root (no parent).
    pub fn is_root(&self) -> bool {
        self.parent_id.is_none()
    }

    /// Display text for this node.
    pub fn display_text(&self) -> String {
        let name = self
            .function_name
            .as_deref()
            .unwrap_or("<unknown>");
        format!(
            "{} {} @ 0x{:x} [snap={}]",
            self.kind.display_name(),
            name,
            self.address,
            self.snap
        )
    }
}

// ---------------------------------------------------------------------------
// Concrete node types
// ---------------------------------------------------------------------------

/// A call node in the trace call tree.
///
/// Represents a function call observed in the trace, including the
/// caller and callee information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCallTreeCallNode {
    /// Base node data.
    pub data: CallTreeNodeData,
    /// The callee function address.
    pub callee_address: u64,
    /// The callee function name.
    pub callee_name: Option<String>,
    /// The return address (where execution resumes after the callee returns).
    pub return_address: Option<u64>,
    /// The number of times this call was observed.
    pub call_count: u32,
}

impl TraceCallTreeCallNode {
    /// Create a new call node.
    pub fn new(data: CallTreeNodeData, callee_address: u64) -> Self {
        Self {
            data,
            callee_address,
            callee_name: None,
            return_address: None,
            call_count: 1,
        }
    }

    /// Set the callee name.
    pub fn with_callee_name(mut self, name: impl Into<String>) -> Self {
        self.callee_name = Some(name.into());
        self
    }

    /// Set the return address.
    pub fn with_return_address(mut self, addr: u64) -> Self {
        self.return_address = Some(addr);
        self
    }

    /// Display text for this call node.
    pub fn display_text(&self) -> String {
        let callee = self.callee_name.as_deref().unwrap_or("?");
        format!(
            "call {} @ 0x{:x} (return: {})",
            callee,
            self.callee_address,
            self.return_address
                .map(|a| format!("0x{:x}", a))
                .unwrap_or_else(|| "none".to_string())
        )
    }
}

/// A return node in the trace call tree.
///
/// Represents a function return observed in the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCallTreeReturnNode {
    /// Base node data.
    pub data: CallTreeNodeData,
    /// The return address (where execution continues).
    pub return_address: u64,
    /// The function that returned.
    pub returning_function: Option<String>,
}

impl TraceCallTreeReturnNode {
    /// Create a new return node.
    pub fn new(data: CallTreeNodeData, return_address: u64) -> Self {
        Self {
            data,
            return_address,
            returning_function: None,
        }
    }

    /// Set the returning function name.
    pub fn with_returning_function(mut self, name: impl Into<String>) -> Self {
        self.returning_function = Some(name.into());
        self
    }
}

/// A tail call node in the trace call tree.
///
/// Represents a tail call optimization where the callee replaces the
/// current stack frame instead of creating a new one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCallTreeTailCallNode {
    /// Base node data.
    pub data: CallTreeNodeData,
    /// The callee function address.
    pub callee_address: u64,
    /// The callee function name.
    pub callee_name: Option<String>,
}

impl TraceCallTreeTailCallNode {
    /// Create a new tail call node.
    pub fn new(data: CallTreeNodeData, callee_address: u64) -> Self {
        Self {
            data,
            callee_address,
            callee_name: None,
        }
    }

    /// Set the callee name.
    pub fn with_callee_name(mut self, name: impl Into<String>) -> Self {
        self.callee_name = Some(name.into());
        self
    }
}

/// An external function node in the trace call tree.
///
/// Represents a call to a function outside the analyzed program
/// (e.g., a library function or system call).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCallTreeExternalNode {
    /// Base node data.
    pub data: CallTreeNodeData,
    /// The library or module name.
    pub module_name: Option<String>,
    /// The external function name.
    pub external_function: Option<String>,
    /// Whether the external function was resolved.
    pub resolved: bool,
}

impl TraceCallTreeExternalNode {
    /// Create a new external node.
    pub fn new(data: CallTreeNodeData) -> Self {
        Self {
            data,
            module_name: None,
            external_function: None,
            resolved: false,
        }
    }

    /// Set the module name.
    pub fn with_module_name(mut self, name: impl Into<String>) -> Self {
        self.module_name = Some(name.into());
        self
    }

    /// Set the external function name.
    pub fn with_external_function(mut self, name: impl Into<String>) -> Self {
        self.external_function = Some(name.into());
        self.resolved = true;
        self
    }

    /// Display text for this external node.
    pub fn display_text(&self) -> String {
        let func = self.external_function.as_deref().unwrap_or("<unknown>");
        let module = self.module_name.as_deref().unwrap_or("?");
        format!("{} ({})", func, module)
    }
}

// ---------------------------------------------------------------------------
// TraceCallTreeNode -- unified enum
// ---------------------------------------------------------------------------

/// A unified enum for any call tree node type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TraceCallTreeNode {
    /// A function call.
    Call(TraceCallTreeCallNode),
    /// A function return.
    Return(TraceCallTreeReturnNode),
    /// A tail call.
    TailCall(TraceCallTreeTailCallNode),
    /// An external function call.
    External(TraceCallTreeExternalNode),
}

impl TraceCallTreeNode {
    /// Get a reference to the base node data.
    pub fn data(&self) -> &CallTreeNodeData {
        match self {
            Self::Call(n) => &n.data,
            Self::Return(n) => &n.data,
            Self::TailCall(n) => &n.data,
            Self::External(n) => &n.data,
        }
    }

    /// Get the node kind.
    pub fn kind(&self) -> CallTreeNodeKind {
        self.data().kind
    }

    /// Get the address.
    pub fn address(&self) -> u64 {
        self.data().address
    }

    /// Get the snapshot.
    pub fn snap(&self) -> i64 {
        self.data().snap
    }

    /// Get the depth.
    pub fn depth(&self) -> usize {
        self.data().depth
    }

    /// Get the function name.
    pub fn function_name(&self) -> Option<&str> {
        self.data().function_name.as_deref()
    }

    /// Get the node ID.
    pub fn id(&self) -> u64 {
        self.data().id
    }

    /// Whether this is a call node.
    pub fn is_call(&self) -> bool {
        matches!(self, Self::Call(_) | Self::TailCall(_))
    }

    /// Whether this is an external node.
    pub fn is_external(&self) -> bool {
        matches!(self, Self::External(_))
    }
}

// ---------------------------------------------------------------------------
// TraceCallTreeLogContext -- context for logging call tree operations
// ---------------------------------------------------------------------------

/// Context information for logging call tree operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCallTreeLogContext {
    /// The trace name.
    pub trace_name: Option<String>,
    /// The thread name.
    pub thread_name: Option<String>,
    /// The snap being viewed.
    pub snap: i64,
    /// Number of nodes in the tree.
    pub node_count: usize,
    /// Maximum depth of the tree.
    pub max_depth: usize,
    /// The time range (span) covered by the tree.
    pub span: Option<Lifespan>,
}

impl TraceCallTreeLogContext {
    /// Create a new log context.
    pub fn new(snap: i64) -> Self {
        Self {
            trace_name: None,
            thread_name: None,
            snap,
            node_count: 0,
            max_depth: 0,
            span: None,
        }
    }

    /// Set the trace name.
    pub fn with_trace_name(mut self, name: impl Into<String>) -> Self {
        self.trace_name = Some(name.into());
        self
    }

    /// Set the thread name.
    pub fn with_thread_name(mut self, name: impl Into<String>) -> Self {
        self.thread_name = Some(name.into());
        self
    }

    /// Set the node count.
    pub fn with_node_count(mut self, count: usize) -> Self {
        self.node_count = count;
        self
    }

    /// Set the maximum depth.
    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    /// Set the span.
    pub fn with_span(mut self, span: Lifespan) -> Self {
        self.span = Some(span);
        self
    }

    /// Summary text for logging.
    pub fn summary(&self) -> String {
        format!(
            "Call tree: {} nodes, depth {} @ snap {}{}",
            self.node_count,
            self.max_depth,
            self.snap,
            self.thread_name
                .as_deref()
                .map(|n| format!(" (thread: {})", n))
                .unwrap_or_default()
        )
    }
}

// ---------------------------------------------------------------------------
// TraceCallTreeModel -- model for the call tree view
// ---------------------------------------------------------------------------

/// The model backing the trace call tree view.
///
/// Holds the tree structure and provides query methods for the GUI panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCallTreeModel {
    /// All nodes in the tree, keyed by node ID.
    pub nodes: HashMap<u64, TraceCallTreeNode>,
    /// Root node IDs (nodes with no parent).
    pub roots: Vec<u64>,
    /// The current snapshot being viewed.
    pub current_snap: i64,
    /// The log context.
    pub log_context: TraceCallTreeLogContext,
    /// Whether the tree is currently being loaded.
    pub loading: bool,
}

impl TraceCallTreeModel {
    /// Create a new empty call tree model.
    pub fn new(snap: i64) -> Self {
        Self {
            nodes: HashMap::new(),
            roots: Vec::new(),
            current_snap: snap,
            log_context: TraceCallTreeLogContext::new(snap),
            loading: false,
        }
    }

    /// Add a node to the tree.
    pub fn add_node(&mut self, node: TraceCallTreeNode) {
        let id = node.data().id;
        let parent_id = node.data().parent_id;
        if parent_id.is_none() {
            self.roots.push(id);
        }
        self.nodes.insert(id, node);
    }

    /// Get a node by ID.
    pub fn get_node(&self, id: u64) -> Option<&TraceCallTreeNode> {
        self.nodes.get(&id)
    }

    /// Get the children of a node.
    pub fn children_of(&self, id: u64) -> Vec<&TraceCallTreeNode> {
        self.nodes
            .get(&id)
            .map(|node| {
                node.data()
                    .children
                    .iter()
                    .filter_map(|child_id| self.nodes.get(child_id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all root nodes.
    pub fn root_nodes(&self) -> Vec<&TraceCallTreeNode> {
        self.roots
            .iter()
            .filter_map(|id| self.nodes.get(id))
            .collect()
    }

    /// Get the total number of nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get the maximum depth in the tree.
    pub fn max_depth(&self) -> usize {
        self.nodes
            .values()
            .map(|n| n.depth())
            .max()
            .unwrap_or(0)
    }

    /// Clear all nodes.
    pub fn clear(&mut self) {
        self.nodes.clear();
        self.roots.clear();
        self.log_context.node_count = 0;
        self.log_context.max_depth = 0;
    }

    /// Update the log context from the current tree state.
    pub fn update_log_context(&mut self) {
        self.log_context.node_count = self.node_count();
        self.log_context.max_depth = self.max_depth();
        self.log_context.snap = self.current_snap;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_tree_node_kind_display() {
        assert_eq!(CallTreeNodeKind::Call.display_name(), "Call");
        assert_eq!(CallTreeNodeKind::Return.display_name(), "Return");
        assert_eq!(CallTreeNodeKind::TailCall.display_name(), "Tail Call");
        assert_eq!(CallTreeNodeKind::External.display_name(), "External");
    }

    #[test]
    fn test_call_tree_node_kind_categories() {
        assert!(CallTreeNodeKind::Call.is_call());
        assert!(CallTreeNodeKind::TailCall.is_call());
        assert!(!CallTreeNodeKind::Return.is_call());
        assert!(!CallTreeNodeKind::External.is_call());

        assert!(CallTreeNodeKind::Return.is_return());
        assert!(!CallTreeNodeKind::Call.is_return());

        assert!(CallTreeNodeKind::External.is_external());
        assert!(!CallTreeNodeKind::Call.is_external());
    }

    #[test]
    fn test_call_tree_node_data() {
        let data = CallTreeNodeData::new(
            1,
            CallTreeNodeKind::Call,
            0x401000,
            5,
            0,
        )
        .with_thread_key(42)
        .with_function_name("main")
        .with_parent(0);

        assert_eq!(data.id, 1);
        assert_eq!(data.kind, CallTreeNodeKind::Call);
        assert_eq!(data.address, 0x401000);
        assert_eq!(data.snap, 5);
        assert_eq!(data.depth, 0);
        assert_eq!(data.thread_key, Some(42));
        assert_eq!(data.function_name.as_deref(), Some("main"));
        assert_eq!(data.parent_id, Some(0));
        assert!(data.is_leaf());
        assert!(!data.is_root());
    }

    #[test]
    fn test_call_tree_node_data_children() {
        let mut data = CallTreeNodeData::new(1, CallTreeNodeKind::Call, 0x401000, 0, 0);
        assert!(data.is_leaf());

        data.add_child(2);
        data.add_child(3);
        data.add_child(2); // duplicate, should not add
        assert_eq!(data.children.len(), 2);
        assert!(!data.is_leaf());
    }

    #[test]
    fn test_call_tree_node_data_display() {
        let data = CallTreeNodeData::new(1, CallTreeNodeKind::Call, 0x401000, 5, 0)
            .with_function_name("main");
        let text = data.display_text();
        assert!(text.contains("Call"));
        assert!(text.contains("main"));
        assert!(text.contains("0x401000"));
        assert!(text.contains("snap=5"));
    }

    #[test]
    fn test_call_node() {
        let data = CallTreeNodeData::new(1, CallTreeNodeKind::Call, 0x401000, 5, 0);
        let node = TraceCallTreeCallNode::new(data, 0x402000)
            .with_callee_name("printf")
            .with_return_address(0x401005);

        assert_eq!(node.callee_address, 0x402000);
        assert_eq!(node.callee_name.as_deref(), Some("printf"));
        assert_eq!(node.return_address, Some(0x401005));
        assert_eq!(node.call_count, 1);
    }

    #[test]
    fn test_return_node() {
        let data = CallTreeNodeData::new(2, CallTreeNodeKind::Return, 0x401005, 5, 0);
        let node = TraceCallTreeReturnNode::new(data, 0x401005)
            .with_returning_function("printf");
        assert_eq!(node.return_address, 0x401005);
        assert_eq!(node.returning_function.as_deref(), Some("printf"));
    }

    #[test]
    fn test_tail_call_node() {
        let data = CallTreeNodeData::new(3, CallTreeNodeKind::TailCall, 0x401000, 5, 0);
        let node = TraceCallTreeTailCallNode::new(data, 0x403000)
            .with_callee_name("optimized_call");
        assert_eq!(node.callee_address, 0x403000);
        assert_eq!(node.callee_name.as_deref(), Some("optimized_call"));
    }

    #[test]
    fn test_external_node() {
        let data = CallTreeNodeData::new(4, CallTreeNodeKind::External, 0x7fff0000, 5, 1);
        let node = TraceCallTreeExternalNode::new(data)
            .with_module_name("libc.so")
            .with_external_function("malloc");
        assert_eq!(node.module_name.as_deref(), Some("libc.so"));
        assert_eq!(node.external_function.as_deref(), Some("malloc"));
        assert!(node.resolved);

        let text = node.display_text();
        assert!(text.contains("malloc"));
        assert!(text.contains("libc.so"));
    }

    #[test]
    fn test_external_node_unresolved() {
        let data = CallTreeNodeData::new(4, CallTreeNodeKind::External, 0x7fff0000, 5, 1);
        let node = TraceCallTreeExternalNode::new(data);
        assert!(!node.resolved);
        assert!(node.external_function.is_none());
    }

    #[test]
    fn test_trace_call_tree_node_enum() {
        let data = CallTreeNodeData::new(1, CallTreeNodeKind::Call, 0x401000, 5, 0)
            .with_function_name("main");
        let node = TraceCallTreeNode::Call(TraceCallTreeCallNode::new(data, 0x402000));

        assert_eq!(node.kind(), CallTreeNodeKind::Call);
        assert_eq!(node.address(), 0x401000);
        assert_eq!(node.snap(), 5);
        assert_eq!(node.depth(), 0);
        assert_eq!(node.function_name(), Some("main"));
        assert!(node.is_call());
        assert!(!node.is_external());
    }

    #[test]
    fn test_trace_call_tree_node_external_enum() {
        let data = CallTreeNodeData::new(2, CallTreeNodeKind::External, 0x7fff0000, 5, 1);
        let node = TraceCallTreeNode::External(TraceCallTreeExternalNode::new(data));
        assert!(node.is_external());
        assert!(!node.is_call());
    }

    #[test]
    fn test_call_tree_log_context() {
        let ctx = TraceCallTreeLogContext::new(5)
            .with_trace_name("test.trace")
            .with_thread_name("main")
            .with_node_count(42)
            .with_max_depth(8);

        let summary = ctx.summary();
        assert!(summary.contains("42 nodes"));
        assert!(summary.contains("depth 8"));
        assert!(summary.contains("snap 5"));
        assert!(summary.contains("main"));
    }

    #[test]
    fn test_call_tree_model_basics() {
        let mut model = TraceCallTreeModel::new(5);
        assert_eq!(model.node_count(), 0);
        assert!(model.roots.is_empty());

        let root_data = CallTreeNodeData::new(0, CallTreeNodeKind::Synthetic, 0, 5, 0);
        model.add_node(TraceCallTreeNode::Call(TraceCallTreeCallNode::new(
            root_data,
            0x401000,
        )));
        assert_eq!(model.node_count(), 1);
        assert_eq!(model.roots.len(), 1);
    }

    #[test]
    fn test_call_tree_model_hierarchy() {
        let mut model = TraceCallTreeModel::new(5);

        // Root node
        let root_data = CallTreeNodeData::new(0, CallTreeNodeKind::Call, 0x401000, 5, 0);
        model.add_node(TraceCallTreeNode::Call(TraceCallTreeCallNode::new(
            root_data,
            0x402000,
        )));

        // Child node
        let child_data =
            CallTreeNodeData::new(1, CallTreeNodeKind::Call, 0x402000, 5, 1).with_parent(0);
        model.add_node(TraceCallTreeNode::Call(TraceCallTreeCallNode::new(
            child_data,
            0x403000,
        )));

        // Add child reference to parent
        if let Some(TraceCallTreeNode::Call(ref mut parent)) = model.nodes.get_mut(&0) {
            parent.data.add_child(1);
        }

        let children = model.children_of(0);
        assert_eq!(children.len(), 1);

        let roots = model.root_nodes();
        assert_eq!(roots.len(), 1);

        assert_eq!(model.max_depth(), 1);
    }

    #[test]
    fn test_call_tree_model_clear() {
        let mut model = TraceCallTreeModel::new(5);
        let root_data = CallTreeNodeData::new(0, CallTreeNodeKind::Call, 0x401000, 5, 0);
        model.add_node(TraceCallTreeNode::Call(TraceCallTreeCallNode::new(
            root_data,
            0x402000,
        )));

        model.clear();
        assert_eq!(model.node_count(), 0);
        assert!(model.roots.is_empty());
    }

    #[test]
    fn test_call_tree_model_update_log_context() {
        let mut model = TraceCallTreeModel::new(5);
        let root_data = CallTreeNodeData::new(0, CallTreeNodeKind::Call, 0x401000, 5, 0);
        model.add_node(TraceCallTreeNode::Call(TraceCallTreeCallNode::new(
            root_data,
            0x402000,
        )));

        model.update_log_context();
        assert_eq!(model.log_context.node_count, 1);
        assert_eq!(model.log_context.max_depth, 0);
    }

    #[test]
    fn test_children_of_nonexistent() {
        let model = TraceCallTreeModel::new(0);
        assert!(model.children_of(999).is_empty());
    }

    #[test]
    fn test_get_node() {
        let mut model = TraceCallTreeModel::new(5);
        let data = CallTreeNodeData::new(42, CallTreeNodeKind::Return, 0x401000, 5, 0);
        model.add_node(TraceCallTreeNode::Return(TraceCallTreeReturnNode::new(
            data,
            0x401005,
        )));

        let node = model.get_node(42).unwrap();
        assert_eq!(node.kind(), CallTreeNodeKind::Return);
        assert!(model.get_node(999).is_none());
    }
}
