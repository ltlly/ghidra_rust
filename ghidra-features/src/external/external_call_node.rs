//! ExternalCallNode -- call tree node for external functions.
//!
//! Ported from `ghidra.app.plugin.core.calltree.ExternalCallNode`.
//!
//! An `ExternalCallNode` represents an external function in the call
//! tree.  It is always a leaf node (external functions cannot be
//! expanded to show their callees).  It carries the function reference,
//! the source address of the call, and whether the reference is a
//! call reference or a non-call reference (e.g., a data reference to
//! an external function pointer).
//!
//! # Examples
//!
//! ```rust
//! use ghidra_features::external::ExternalCallNode;
//! use ghidra_core::addr::Address;
//!
//! let node = ExternalCallNode::new(
//!     "printf",
//!     Address::new(0x401000),
//!     Address::new(0x400100),
//!     true,
//! );
//!
//! assert_eq!(node.name(), "printf");
//! assert!(node.is_leaf());
//! assert!(node.is_call_reference());
//! assert_eq!(node.source_address(), Address::new(0x400100));
//! ```

use ghidra_core::addr::Address;

// ---------------------------------------------------------------------------
// ExternalCallNode
// ---------------------------------------------------------------------------

/// A call tree node representing an external function.
///
/// This is the Rust port of Ghidra's `ExternalCallNode`.  External call
/// nodes are always leaf nodes -- they cannot be expanded to show callees
/// because the callee information is not available for external functions.
///
/// # Fields
///
/// * `function_name` -- the name of the external function.
/// * `entry_point` -- the entry point address of the external function
///   (in the external program's address space).
/// * `source_address` -- the address in the calling program that contains
///   the reference to this external function.
/// * `is_call_reference` -- whether the reference is a call reference
///   (as opposed to a non-call reference, e.g., taking the address of
///   the function).
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::ExternalCallNode;
/// use ghidra_core::addr::Address;
///
/// // Create a node for a call to printf
/// let node = ExternalCallNode::new(
///     "printf",
///     Address::new(0x1000),
///     Address::new(0x400100),
///     true,
/// );
/// assert_eq!(node.name(), "printf");
/// assert!(node.is_leaf());
/// assert_eq!(node.entry_point(), Some(Address::new(0x1000)));
///
/// // Create a node for taking the address of an external function
/// let node = ExternalCallNode::new(
///     "malloc",
///     Address::new(0x2000),
///     Address::new(0x400200),
///     false,
/// );
/// assert!(!node.is_call_reference());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalCallNode {
    /// The name of the external function.
    function_name: String,
    /// The entry point address of the external function.
    entry_point: Option<Address>,
    /// The address in the calling program that references this function.
    source_address: Address,
    /// Whether this is a call reference (true) or a non-call reference.
    is_call_ref: bool,
}

impl ExternalCallNode {
    /// Create a new external call node.
    ///
    /// # Arguments
    ///
    /// * `function_name` -- the name of the external function.
    /// * `entry_point` -- the entry point address of the external function.
    /// * `source_address` -- the address of the call/reference site.
    /// * `is_call_reference` -- whether this is a call reference.
    pub fn new(
        function_name: impl Into<String>,
        entry_point: Address,
        source_address: Address,
        is_call_reference: bool,
    ) -> Self {
        Self {
            function_name: function_name.into(),
            entry_point: Some(entry_point),
            source_address,
            is_call_ref: is_call_reference,
        }
    }

    /// Create a new external call node without an entry point address.
    ///
    /// This is used when the external function's address is not known.
    pub fn new_without_address(
        function_name: impl Into<String>,
        source_address: Address,
        is_call_reference: bool,
    ) -> Self {
        Self {
            function_name: function_name.into(),
            entry_point: None,
            source_address,
            is_call_ref: is_call_reference,
        }
    }

    /// Returns the name of the external function.
    pub fn name(&self) -> &str {
        &self.function_name
    }

    /// Returns the entry point address of the external function.
    pub fn entry_point(&self) -> Option<Address> {
        self.entry_point
    }

    /// Returns the address of the call/reference site.
    pub fn source_address(&self) -> Address {
        self.source_address
    }

    /// Returns whether this is a call reference.
    pub fn is_call_reference(&self) -> bool {
        self.is_call_ref
    }

    /// Returns whether this is a leaf node.
    ///
    /// External call nodes are always leaf nodes because the callee
    /// information is not available for external functions.
    pub fn is_leaf(&self) -> bool {
        true
    }

    /// Returns the tooltip text for this node.
    ///
    /// In the Java implementation this is `"(External) " + super.getToolTip()`.
    pub fn tooltip(&self) -> String {
        format!("(External) {}", self.function_name)
    }

    /// Returns the number of children (always 0 for external nodes).
    pub fn child_count(&self) -> usize {
        0
    }

    /// Returns an empty list of children (external nodes cannot be expanded).
    pub fn children(&self) -> Vec<ExternalCallNode> {
        Vec::new()
    }

    /// Recreate this node with the same parameters.
    ///
    /// In the Java implementation this is used when the call tree is
    /// refreshed and nodes need to be recreated with updated options.
    pub fn recreate(&self) -> Self {
        Self {
            function_name: self.function_name.clone(),
            entry_point: self.entry_point,
            source_address: self.source_address,
            is_call_ref: self.is_call_ref,
        }
    }

    /// Load all children (returns 1 for leaf nodes).
    ///
    /// In the Java implementation `loadAll()` returns 1 for leaf nodes
    /// because they have no children to load.
    pub fn load_all(&self) -> usize {
        1
    }

    /// Returns the icon identifier for this node.
    ///
    /// Returns different icons depending on whether this is a call
    /// reference or a non-call reference.
    pub fn icon_id(&self) -> &'static str {
        if self.is_call_ref {
            "icon.plugin.calltree.node.external.call"
        } else {
            "icon.plugin.calltree.node.external"
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_properties() {
        let node =
            ExternalCallNode::new("printf", Address::new(0x1000), Address::new(0x400100), true);
        assert_eq!(node.name(), "printf");
        assert_eq!(node.entry_point(), Some(Address::new(0x1000)));
        assert_eq!(node.source_address(), Address::new(0x400100));
        assert!(node.is_call_reference());
    }

    #[test]
    fn test_node_without_address() {
        let node = ExternalCallNode::new_without_address("malloc", Address::new(0x400200), false);
        assert_eq!(node.name(), "malloc");
        assert_eq!(node.entry_point(), None);
        assert_eq!(node.source_address(), Address::new(0x400200));
        assert!(!node.is_call_reference());
    }

    #[test]
    fn test_is_leaf() {
        let node =
            ExternalCallNode::new("printf", Address::new(0x1000), Address::new(0x400100), true);
        assert!(node.is_leaf());
    }

    #[test]
    fn test_child_count() {
        let node =
            ExternalCallNode::new("printf", Address::new(0x1000), Address::new(0x400100), true);
        assert_eq!(node.child_count(), 0);
    }

    #[test]
    fn test_children_empty() {
        let node =
            ExternalCallNode::new("printf", Address::new(0x1000), Address::new(0x400100), true);
        assert!(node.children().is_empty());
    }

    #[test]
    fn test_tooltip() {
        let node =
            ExternalCallNode::new("printf", Address::new(0x1000), Address::new(0x400100), true);
        assert_eq!(node.tooltip(), "(External) printf");
    }

    #[test]
    fn test_load_all() {
        let node =
            ExternalCallNode::new("printf", Address::new(0x1000), Address::new(0x400100), true);
        assert_eq!(node.load_all(), 1);
    }

    #[test]
    fn test_recreate() {
        let node =
            ExternalCallNode::new("printf", Address::new(0x1000), Address::new(0x400100), true);
        let recreated = node.recreate();
        assert_eq!(recreated, node);
    }

    #[test]
    fn test_icon_call_reference() {
        let node =
            ExternalCallNode::new("printf", Address::new(0x1000), Address::new(0x400100), true);
        assert_eq!(node.icon_id(), "icon.plugin.calltree.node.external.call");
    }

    #[test]
    fn test_icon_non_call_reference() {
        let node = ExternalCallNode::new(
            "printf",
            Address::new(0x1000),
            Address::new(0x400100),
            false,
        );
        assert_eq!(node.icon_id(), "icon.plugin.calltree.node.external");
    }

    #[test]
    fn test_clone_and_eq() {
        let node1 =
            ExternalCallNode::new("printf", Address::new(0x1000), Address::new(0x400100), true);
        let node2 = node1.clone();
        assert_eq!(node1, node2);
    }

    #[test]
    fn test_different_nodes_not_equal() {
        let node1 =
            ExternalCallNode::new("printf", Address::new(0x1000), Address::new(0x400100), true);
        let node2 = ExternalCallNode::new(
            "malloc",
            Address::new(0x2000),
            Address::new(0x400200),
            false,
        );
        assert_ne!(node1, node2);
    }

    #[test]
    fn test_debug_format() {
        let node =
            ExternalCallNode::new("printf", Address::new(0x1000), Address::new(0x400100), true);
        let debug_str = format!("{:?}", node);
        assert!(debug_str.contains("printf"));
        assert!(debug_str.contains("ExternalCallNode"));
    }
}
