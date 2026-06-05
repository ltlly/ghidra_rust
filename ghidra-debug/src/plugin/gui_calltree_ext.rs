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

// ---------------------------------------------------------------------------
// Parameter name-to-bytes record (ported from AbstractTraceCallTreeNode)
// ---------------------------------------------------------------------------

/// A parameter name with its raw bytes.
///
/// Ported from Ghidra's `AbstractTraceCallTreeNode.ParamNameToBytes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamNameToBytes {
    /// Parameter name (e.g., "rdi", "arg0").
    pub name: String,
    /// Raw bytes of the parameter value.
    pub bytes: Vec<u8>,
}

impl ParamNameToBytes {
    /// Create a new parameter entry.
    pub fn new(name: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            bytes,
        }
    }

    /// Format as "name: hex_bytes".
    pub fn display_string(&self) -> String {
        let hex: String = self.bytes.iter().map(|b| format!("{:02x}", b)).collect();
        format!("{}: {}", self.name, hex)
    }
}

// ---------------------------------------------------------------------------
// Concrete call tree node types (ported from tracecalltree package)
// ---------------------------------------------------------------------------

/// A call tree node representing a regular function call.
///
/// Ported from Ghidra's `TraceCallTreeCallNode`. Contains the function name,
/// module, snapshot key, parameters, and return value.
#[derive(Debug, Clone)]
pub struct TraceCallTreeCallNode {
    /// The function name.
    pub name: String,
    /// The module (shared library / binary) containing this function.
    pub module: String,
    /// Snapshot key at which this call was recorded (-1 if none).
    pub snap_key: i64,
    /// Parameters passed to the call.
    pub parameters: Vec<ParamNameToBytes>,
    /// Return value bytes (if available).
    pub return_val: Option<Vec<u8>>,
    /// Largest parameter size in bytes (for column sizing).
    pub largest_param_size: usize,
}

impl TraceCallTreeCallNode {
    /// Create a new call node.
    pub fn new(
        name: impl Into<String>,
        module: impl Into<String>,
        snap_key: i64,
        parameters: Vec<ParamNameToBytes>,
        return_val: Option<Vec<u8>>,
    ) -> Self {
        let largest = parameters.iter().map(|p| p.bytes.len()).max().unwrap_or(0);
        Self {
            name: name.into(),
            module: module.into(),
            snap_key,
            parameters,
            return_val,
            largest_param_size: largest,
        }
    }

    /// Get the display string for this node (default: just the name).
    pub fn tree_data(&self) -> &str {
        &self.name
    }

    /// Get the number of parameters.
    pub fn parameter_count(&self) -> usize {
        self.parameters.len()
    }

    /// Get a parameter by index.
    pub fn parameter(&self, index: usize) -> Option<&ParamNameToBytes> {
        self.parameters.get(index)
    }

    /// Get the parameter display string at the given index.
    pub fn parameter_string(&self, index: usize) -> String {
        self.parameter(index)
            .map(|p| p.display_string())
            .unwrap_or_default()
    }

    /// Get the return value display string.
    pub fn return_val_string(&self) -> String {
        match &self.return_val {
            Some(bytes) => {
                let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                format!("Return: {}", hex)
            }
            None => String::new(),
        }
    }
}

/// A call tree node representing an external (library) function call.
///
/// Ported from Ghidra's `TraceCallTreeExternalNode`. Displays with a
/// warning icon to indicate the call target is outside the traced binary.
#[derive(Debug, Clone)]
pub struct TraceCallTreeExternalNode {
    /// The external function name.
    pub name: String,
    /// The module (shared library) containing this function.
    pub module: String,
    /// Snapshot key at which this call was recorded (-1 if none).
    pub snap_key: i64,
    /// Parameters passed to the call.
    pub parameters: Vec<ParamNameToBytes>,
    /// Return value bytes (if available).
    pub return_val: Option<Vec<u8>>,
    /// Largest parameter size in bytes.
    pub largest_param_size: usize,
}

impl TraceCallTreeExternalNode {
    /// Create a new external node.
    pub fn new(
        name: impl Into<String>,
        module: impl Into<String>,
        snap_key: i64,
        parameters: Vec<ParamNameToBytes>,
        return_val: Option<Vec<u8>>,
    ) -> Self {
        let largest = parameters.iter().map(|p| p.bytes.len()).max().unwrap_or(0);
        Self {
            name: name.into(),
            module: module.into(),
            snap_key,
            parameters,
            return_val,
            largest_param_size: largest,
        }
    }

    /// Get the display string: "External: <name>".
    pub fn tree_data(&self) -> String {
        format!("External: {}", self.name)
    }

    /// Get the number of parameters.
    pub fn parameter_count(&self) -> usize {
        self.parameters.len()
    }

    /// Get a parameter by index.
    pub fn parameter(&self, index: usize) -> Option<&ParamNameToBytes> {
        self.parameters.get(index)
    }

    /// Get the parameter display string at the given index.
    pub fn parameter_string(&self, index: usize) -> String {
        self.parameter(index)
            .map(|p| p.display_string())
            .unwrap_or_default()
    }

    /// Get the return value display string.
    pub fn return_val_string(&self) -> String {
        match &self.return_val {
            Some(bytes) => {
                let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                format!("Return: {}", hex)
            }
            None => String::new(),
        }
    }
}

/// A call tree node representing a function return.
///
/// Ported from Ghidra's `TraceCallTreeReturnNode`. Displays with an
/// arrow-up-left icon to indicate a return from a function call.
#[derive(Debug, Clone)]
pub struct TraceCallTreeReturnNode {
    /// The function name that returned.
    pub name: String,
    /// The module containing this function.
    pub module: String,
    /// Snapshot key at which this return was recorded (-1 if none).
    pub snap_key: i64,
    /// Parameters (typically empty for returns, but supported).
    pub parameters: Vec<ParamNameToBytes>,
    /// Return value bytes (if available).
    pub return_val: Option<Vec<u8>>,
    /// Largest parameter size in bytes.
    pub largest_param_size: usize,
}

impl TraceCallTreeReturnNode {
    /// Create a new return node.
    pub fn new(
        name: impl Into<String>,
        module: impl Into<String>,
        snap_key: i64,
        parameters: Vec<ParamNameToBytes>,
        return_val: Option<Vec<u8>>,
    ) -> Self {
        let largest = parameters.iter().map(|p| p.bytes.len()).max().unwrap_or(0);
        Self {
            name: name.into(),
            module: module.into(),
            snap_key,
            parameters,
            return_val,
            largest_param_size: largest,
        }
    }

    /// Get the display string: "Return: <name>".
    pub fn tree_data(&self) -> String {
        format!("Return: {}", self.name)
    }

    /// Get the number of parameters.
    pub fn parameter_count(&self) -> usize {
        self.parameters.len()
    }

    /// Get the return value display string.
    pub fn return_val_string(&self) -> String {
        match &self.return_val {
            Some(bytes) => {
                let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                format!("Return: {}", hex)
            }
            None => String::new(),
        }
    }
}

/// A call tree node representing a tail call.
///
/// Ported from Ghidra's `TraceCallTreeTailCallNode`. Displays with a
/// navigate-on-incoming-event icon to indicate a tail call optimization.
#[derive(Debug, Clone)]
pub struct TraceCallTreeTailCallNode {
    /// The function name that was tail-called.
    pub name: String,
    /// The module containing this function.
    pub module: String,
    /// Snapshot key at which this tail call was recorded (-1 if none).
    pub snap_key: i64,
    /// Parameters passed to the tail call.
    pub parameters: Vec<ParamNameToBytes>,
    /// Return value bytes (if available).
    pub return_val: Option<Vec<u8>>,
    /// Largest parameter size in bytes.
    pub largest_param_size: usize,
}

impl TraceCallTreeTailCallNode {
    /// Create a new tail call node.
    pub fn new(
        name: impl Into<String>,
        module: impl Into<String>,
        snap_key: i64,
        parameters: Vec<ParamNameToBytes>,
        return_val: Option<Vec<u8>>,
    ) -> Self {
        let largest = parameters.iter().map(|p| p.bytes.len()).max().unwrap_or(0);
        Self {
            name: name.into(),
            module: module.into(),
            snap_key,
            parameters,
            return_val,
            largest_param_size: largest,
        }
    }

    /// Get the display string: "Tail Call: <name>".
    pub fn tree_data(&self) -> String {
        format!("Tail Call: {}", self.name)
    }

    /// Get the number of parameters.
    pub fn parameter_count(&self) -> usize {
        self.parameters.len()
    }

    /// Get a parameter by index.
    pub fn parameter(&self, index: usize) -> Option<&ParamNameToBytes> {
        self.parameters.get(index)
    }

    /// Get the parameter display string at the given index.
    pub fn parameter_string(&self, index: usize) -> String {
        self.parameter(index)
            .map(|p| p.display_string())
            .unwrap_or_default()
    }

    /// Get the return value display string.
    pub fn return_val_string(&self) -> String {
        match &self.return_val {
            Some(bytes) => {
                let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                format!("Return: {}", hex)
            }
            None => String::new(),
        }
    }
}

/// Unified enum for all concrete call tree node types.
///
/// This allows storing any of the four concrete node types in a single
/// collection, mirroring how Java uses the abstract base class.
#[derive(Debug, Clone)]
pub enum AnyCallTreeNode {
    /// A regular function call node.
    Call(TraceCallTreeCallNode),
    /// An external (library) call node.
    External(TraceCallTreeExternalNode),
    /// A function return node.
    Return(TraceCallTreeReturnNode),
    /// A tail call node.
    TailCall(TraceCallTreeTailCallNode),
}

impl AnyCallTreeNode {
    /// Get the function name regardless of node kind.
    pub fn name(&self) -> &str {
        match self {
            Self::Call(n) => &n.name,
            Self::External(n) => &n.name,
            Self::Return(n) => &n.name,
            Self::TailCall(n) => &n.name,
        }
    }

    /// Get the module name regardless of node kind.
    pub fn module(&self) -> &str {
        match self {
            Self::Call(n) => &n.module,
            Self::External(n) => &n.module,
            Self::Return(n) => &n.module,
            Self::TailCall(n) => &n.module,
        }
    }

    /// Get the snap key regardless of node kind.
    pub fn snap_key(&self) -> i64 {
        match self {
            Self::Call(n) => n.snap_key,
            Self::External(n) => n.snap_key,
            Self::Return(n) => n.snap_key,
            Self::TailCall(n) => n.snap_key,
        }
    }

    /// Get the tree display string regardless of node kind.
    pub fn tree_data(&self) -> String {
        match self {
            Self::Call(n) => n.tree_data().to_string(),
            Self::External(n) => n.tree_data(),
            Self::Return(n) => n.tree_data(),
            Self::TailCall(n) => n.tree_data(),
        }
    }

    /// Get the parameter count regardless of node kind.
    pub fn parameter_count(&self) -> usize {
        match self {
            Self::Call(n) => n.parameter_count(),
            Self::External(n) => n.parameter_count(),
            Self::Return(n) => n.parameter_count(),
            Self::TailCall(n) => n.parameter_count(),
        }
    }

    /// Get the return value display string regardless of node kind.
    pub fn return_val_string(&self) -> String {
        match self {
            Self::Call(n) => n.return_val_string(),
            Self::External(n) => n.return_val_string(),
            Self::Return(n) => n.return_val_string(),
            Self::TailCall(n) => n.return_val_string(),
        }
    }

    /// Get the corresponding `CallTreeNodeKind`.
    pub fn kind(&self) -> CallTreeNodeKind {
        match self {
            Self::Call(_) => CallTreeNodeKind::Call,
            Self::External(_) => CallTreeNodeKind::External,
            Self::Return(_) => CallTreeNodeKind::Return,
            Self::TailCall(_) => CallTreeNodeKind::TailCall,
        }
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

    // ====================================================================
    // ParamNameToBytes tests
    // ====================================================================

    #[test]
    fn test_param_name_to_bytes_display() {
        let param = ParamNameToBytes::new("rdi", vec![0x42, 0x01, 0x00, 0x00]);
        assert_eq!(param.display_string(), "rdi: 42010000");
    }

    #[test]
    fn test_param_name_to_bytes_empty() {
        let param = ParamNameToBytes::new("void", vec![]);
        assert_eq!(param.display_string(), "void: ");
    }

    #[test]
    fn test_param_name_to_bytes_equality() {
        let a = ParamNameToBytes::new("rax", vec![0x10]);
        let b = ParamNameToBytes::new("rax", vec![0x10]);
        let c = ParamNameToBytes::new("rbx", vec![0x10]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // ====================================================================
    // TraceCallTreeCallNode tests
    // ====================================================================

    #[test]
    fn test_call_node_creation() {
        let node = TraceCallTreeCallNode::new("main", "a.out", 5, vec![], None);
        assert_eq!(node.name, "main");
        assert_eq!(node.module, "a.out");
        assert_eq!(node.snap_key, 5);
        assert_eq!(node.parameter_count(), 0);
        assert_eq!(node.largest_param_size, 0);
    }

    #[test]
    fn test_call_node_with_params() {
        let params = vec![
            ParamNameToBytes::new("rdi", vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            ParamNameToBytes::new("rsi", vec![0xff]),
        ];
        let node = TraceCallTreeCallNode::new("printf", "libc.so", 10, params, None);
        assert_eq!(node.parameter_count(), 2);
        assert_eq!(node.largest_param_size, 8);
        assert_eq!(node.parameter(0).unwrap().name, "rdi");
        assert!(node.parameter(999).is_none());
    }

    #[test]
    fn test_call_node_parameter_string() {
        let params = vec![
            ParamNameToBytes::new("rdi", vec![0xAB]),
        ];
        let node = TraceCallTreeCallNode::new("foo", "mod", 0, params, None);
        assert_eq!(node.parameter_string(0), "rdi: ab");
        assert_eq!(node.parameter_string(99), "");
    }

    #[test]
    fn test_call_node_return_val() {
        let node = TraceCallTreeCallNode::new(
            "malloc", "libc.so", 1, vec![], Some(vec![0x00, 0x10, 0x40, 0x00]),
        );
        assert_eq!(node.return_val_string(), "Return: 00104000");
    }

    #[test]
    fn test_call_node_no_return_val() {
        let node = TraceCallTreeCallNode::new("void_func", "mod", 0, vec![], None);
        assert_eq!(node.return_val_string(), "");
    }

    #[test]
    fn test_call_node_tree_data() {
        let node = TraceCallTreeCallNode::new("main", "a.out", 0, vec![], None);
        assert_eq!(node.tree_data(), "main");
    }

    // ====================================================================
    // TraceCallTreeExternalNode tests
    // ====================================================================

    #[test]
    fn test_external_node_creation() {
        let node = TraceCallTreeExternalNode::new("printf", "libc.so", 3, vec![], None);
        assert_eq!(node.name, "printf");
        assert_eq!(node.module, "libc.so");
    }

    #[test]
    fn test_external_node_tree_data() {
        let node = TraceCallTreeExternalNode::new("printf", "libc.so", 0, vec![], None);
        assert_eq!(node.tree_data(), "External: printf");
    }

    #[test]
    fn test_external_node_with_params_and_return() {
        let params = vec![ParamNameToBytes::new("fmt", vec![0x41, 0x42])];
        let node = TraceCallTreeExternalNode::new(
            "printf", "libc.so", 5, params, Some(vec![0x03]),
        );
        assert_eq!(node.parameter_count(), 1);
        assert_eq!(node.parameter_string(0), "fmt: 4142");
        assert_eq!(node.return_val_string(), "Return: 03");
    }

    // ====================================================================
    // TraceCallTreeReturnNode tests
    // ====================================================================

    #[test]
    fn test_return_node_creation() {
        let node = TraceCallTreeReturnNode::new("main", "a.out", 7, vec![], Some(vec![0x00]));
        assert_eq!(node.name, "main");
        assert_eq!(node.snap_key, 7);
    }

    #[test]
    fn test_return_node_tree_data() {
        let node = TraceCallTreeReturnNode::new("main", "a.out", 0, vec![], None);
        assert_eq!(node.tree_data(), "Return: main");
    }

    #[test]
    fn test_return_node_no_params() {
        let node = TraceCallTreeReturnNode::new("func", "mod", 0, vec![], None);
        assert_eq!(node.parameter_count(), 0);
    }

    // ====================================================================
    // TraceCallTreeTailCallNode tests
    // ====================================================================

    #[test]
    fn test_tail_call_node_creation() {
        let node = TraceCallTreeTailCallNode::new("target", "a.out", 2, vec![], None);
        assert_eq!(node.name, "target");
        assert_eq!(node.module, "a.out");
    }

    #[test]
    fn test_tail_call_node_tree_data() {
        let node = TraceCallTreeTailCallNode::new("target", "mod", 0, vec![], None);
        assert_eq!(node.tree_data(), "Tail Call: target");
    }

    #[test]
    fn test_tail_call_node_with_params() {
        let params = vec![
            ParamNameToBytes::new("arg0", vec![0x01]),
            ParamNameToBytes::new("arg1", vec![0x02, 0x03]),
        ];
        let node = TraceCallTreeTailCallNode::new("tail", "mod", 0, params, Some(vec![0xFF]));
        assert_eq!(node.parameter_count(), 2);
        assert_eq!(node.parameter_string(1), "arg1: 0203");
        assert_eq!(node.return_val_string(), "Return: ff");
        assert_eq!(node.largest_param_size, 2);
    }

    #[test]
    fn test_tail_call_node_out_of_bounds_parameter() {
        let node = TraceCallTreeTailCallNode::new("f", "m", 0, vec![], None);
        assert!(node.parameter(0).is_none());
        assert_eq!(node.parameter_string(0), "");
    }

    // ====================================================================
    // AnyCallTreeNode tests
    // ====================================================================

    #[test]
    fn test_any_call_node_call() {
        let node = AnyCallTreeNode::Call(TraceCallTreeCallNode::new("main", "a.out", 1, vec![], None));
        assert_eq!(node.name(), "main");
        assert_eq!(node.module(), "a.out");
        assert_eq!(node.snap_key(), 1);
        assert_eq!(node.kind(), CallTreeNodeKind::Call);
        assert_eq!(node.tree_data(), "main");
    }

    #[test]
    fn test_any_call_node_external() {
        let node = AnyCallTreeNode::External(
            TraceCallTreeExternalNode::new("printf", "libc", 2, vec![], None),
        );
        assert_eq!(node.kind(), CallTreeNodeKind::External);
        assert_eq!(node.tree_data(), "External: printf");
    }

    #[test]
    fn test_any_call_node_return() {
        let node = AnyCallTreeNode::Return(
            TraceCallTreeReturnNode::new("foo", "mod", 3, vec![], None),
        );
        assert_eq!(node.kind(), CallTreeNodeKind::Return);
        assert_eq!(node.tree_data(), "Return: foo");
    }

    #[test]
    fn test_any_call_node_tail_call() {
        let node = AnyCallTreeNode::TailCall(
            TraceCallTreeTailCallNode::new("bar", "mod", 4, vec![], None),
        );
        assert_eq!(node.kind(), CallTreeNodeKind::TailCall);
        assert_eq!(node.tree_data(), "Tail Call: bar");
    }

    #[test]
    fn test_any_call_node_return_val_string() {
        let node = AnyCallTreeNode::Call(TraceCallTreeCallNode::new(
            "malloc", "libc", 0, vec![], Some(vec![0xDE, 0xAD]),
        ));
        assert_eq!(node.return_val_string(), "Return: dead");

        let node_none = AnyCallTreeNode::Call(TraceCallTreeCallNode::new(
            "void_fn", "mod", 0, vec![], None,
        ));
        assert_eq!(node_none.return_val_string(), "");
    }

    #[test]
    fn test_any_call_node_parameter_count() {
        let params = vec![ParamNameToBytes::new("a", vec![1])];
        let node = AnyCallTreeNode::External(
            TraceCallTreeExternalNode::new("ext", "lib", 0, params, None),
        );
        assert_eq!(node.parameter_count(), 1);
    }

    #[test]
    fn test_call_tree_with_model_integration() {
        let mut model = TraceCallTreeModel::new();

        // Add a call node as root
        let call = TraceCallTreeCallNode::new("main", "a.out", 0, vec![], None);
        let root = TraceCallTreeNode::new(0, CallTreeNodeKind::Call, &call.name, 0x400000, 0, 0);
        let root_id = model.add_root(root);

        // Add an external call as child
        let ext = TraceCallTreeExternalNode::new("printf", "libc", 0, vec![], None);
        let child = TraceCallTreeNode::new(
            0,
            CallTreeNodeKind::External,
            ext.tree_data(),
            0x7fff0000,
            1,
            0,
        );
        let child_id = model.add_child(root_id, child).unwrap();

        // Add a return node
        let ret = TraceCallTreeReturnNode::new("printf", "libc", 0, vec![], None);
        let ret_child = TraceCallTreeNode::new(
            0,
            CallTreeNodeKind::Return,
            ret.tree_data(),
            0x7fff0000,
            1,
            0,
        );
        model.add_child(child_id, ret_child);

        assert_eq!(model.node_count(), 3);
        assert_eq!(model.max_depth(), 1);

        // Verify node content
        let ext_node = model.get_node(child_id).unwrap();
        assert!(ext_node.function_name.starts_with("External:"));
    }
}
