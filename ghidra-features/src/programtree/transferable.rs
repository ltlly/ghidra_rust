//! Transferable data objects for program tree drag-drop and clipboard.
//!
//! Ported from `ghidra.app.plugin.core.programtree.GroupTransferable` and
//! `ghidra.app.plugin.core.programtree.ProgramTreeTransferable`.
//!
//! In the Java version these implement `java.awt.datatransfer.Transferable`
//! and `ClipboardOwner`.  In Rust we model the data and serialization;
//! the actual clipboard integration is handled by the GUI layer.

use std::collections::HashMap;

use super::node::ProgramNode;

/// A unique identifier for a data flavor (analogous to Java's `DataFlavor`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DataFlavorId {
    /// Human-readable name for the flavor.
    pub name: String,
    /// MIME type.
    pub mime_type: String,
}

impl DataFlavorId {
    /// Create a new data flavor identifier.
    pub fn new(name: impl Into<String>, mime_type: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            mime_type: mime_type.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// GroupTransferable
// ---------------------------------------------------------------------------

/// Data flavor for local group transfers within Ghidra.
pub static LOCAL_GROUP_FLAVOR: &str = "application/x-ghidra-local-group";

/// Represents a [`Group`] that can be transferred via drag-drop or clipboard.
///
/// Ported from `ghidra.app.plugin.core.programtree.GroupTransferable`.
#[derive(Debug, Clone)]
pub struct GroupTransferable {
    /// The group name.
    group_name: String,
    /// The tree name the group belongs to.
    tree_name: String,
    /// Whether the group is a module or fragment.
    is_module: bool,
}

impl GroupTransferable {
    /// Create a new group transferable.
    pub fn new(group_name: impl Into<String>, tree_name: impl Into<String>, is_module: bool) -> Self {
        Self {
            group_name: group_name.into(),
            tree_name: tree_name.into(),
            is_module,
        }
    }

    /// Returns the group name.
    pub fn group_name(&self) -> &str {
        &self.group_name
    }

    /// Returns the tree name.
    pub fn tree_name(&self) -> &str {
        &self.tree_name
    }

    /// Returns `true` if the group is a module.
    pub fn is_module(&self) -> bool {
        self.is_module
    }

    /// Returns `true` if this transferable supports the given flavor.
    pub fn is_flavor_supported(&self, flavor: &str) -> bool {
        flavor == LOCAL_GROUP_FLAVOR
    }

    /// Get the transfer data for the given flavor.
    pub fn get_transfer_data(&self, flavor: &str) -> Option<TransferData> {
        if flavor == LOCAL_GROUP_FLAVOR {
            Some(TransferData::Group(self.clone()))
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// ProgramTreeTransferable
// ---------------------------------------------------------------------------

/// Data flavor for local tree node transfers within Ghidra.
pub static LOCAL_TREE_NODE_FLAVOR: &str = "application/x-ghidra-local-tree-nodes";

/// Represents a list of [`ProgramNode`]s that can be transferred via
/// drag-drop or clipboard.
///
/// Ported from `ghidra.app.plugin.core.programtree.ProgramTreeTransferable`.
#[derive(Debug, Clone)]
pub struct ProgramTreeTransferable {
    /// The nodes being transferred.
    nodes: Vec<ProgramNode>,
    /// The tree name.
    tree_name: String,
    /// Additional properties for the transfer.
    properties: HashMap<String, String>,
}

impl ProgramTreeTransferable {
    /// Create a new tree node transferable.
    pub fn new(nodes: Vec<ProgramNode>, tree_name: impl Into<String>) -> Self {
        Self {
            nodes,
            tree_name: tree_name.into(),
            properties: HashMap::new(),
        }
    }

    /// Returns the nodes being transferred.
    pub fn nodes(&self) -> &[ProgramNode] {
        &self.nodes
    }

    /// Returns the tree name.
    pub fn tree_name(&self) -> &str {
        &self.tree_name
    }

    /// Returns the transfer data flavors supported.
    pub fn get_transfer_data_flavors(&self) -> Vec<&str> {
        vec![LOCAL_TREE_NODE_FLAVOR]
    }

    /// Returns `true` if this transferable supports the given flavor.
    pub fn is_flavor_supported(&self, flavor: &str) -> bool {
        flavor == LOCAL_TREE_NODE_FLAVOR
    }

    /// Get the transfer data for the given flavor.
    pub fn get_transfer_data(&self, flavor: &str) -> Option<TransferData> {
        if flavor == LOCAL_TREE_NODE_FLAVOR {
            Some(TransferData::TreeNodes(self.clone()))
        } else {
            None
        }
    }

    /// Set a property on this transferable.
    pub fn set_property(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.properties.insert(key.into(), value.into());
    }

    /// Get a property from this transferable.
    pub fn get_property(&self, key: &str) -> Option<&str> {
        self.properties.get(key).map(|s| s.as_str())
    }

    /// Returns the number of nodes being transferred.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Returns `true` if the transferable is empty.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

// ---------------------------------------------------------------------------
// TransferData -- unified enum for clipboard/drag-drop payloads
// ---------------------------------------------------------------------------

/// Data that can be transferred via clipboard or drag-drop.
#[derive(Debug, Clone)]
pub enum TransferData {
    /// A group (module or fragment) transfer.
    Group(GroupTransferable),
    /// Tree nodes transfer.
    TreeNodes(ProgramTreeTransferable),
    /// Plain text transfer.
    Text(String),
}

impl TransferData {
    /// Returns the transfer data as tree nodes, if applicable.
    pub fn as_tree_nodes(&self) -> Option<&ProgramTreeTransferable> {
        match self {
            TransferData::TreeNodes(t) => Some(t),
            _ => None,
        }
    }

    /// Returns the transfer data as a group, if applicable.
    pub fn as_group(&self) -> Option<&GroupTransferable> {
        match self {
            TransferData::Group(g) => Some(g),
            _ => None,
        }
    }

    /// Returns the transfer data as text, if applicable.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            TransferData::Text(s) => Some(s),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_transferable() {
        let gt = GroupTransferable::new("my_group", "tree1", true);
        assert_eq!(gt.group_name(), "my_group");
        assert_eq!(gt.tree_name(), "tree1");
        assert!(gt.is_module());
        assert!(gt.is_flavor_supported(LOCAL_GROUP_FLAVOR));
        assert!(!gt.is_flavor_supported("unknown"));

        let data = gt.get_transfer_data(LOCAL_GROUP_FLAVOR);
        assert!(data.is_some());
    }

    #[test]
    fn test_tree_transferable() {
        let nodes = vec![
            ProgramNode::new_fragment(".text", None, None),
            ProgramNode::new_fragment(".data", None, None),
        ];
        let tt = ProgramTreeTransferable::new(nodes, "tree1");
        assert_eq!(tt.node_count(), 2);
        assert!(!tt.is_empty());
        assert!(tt.is_flavor_supported(LOCAL_TREE_NODE_FLAVOR));

        let flavors = tt.get_transfer_data_flavors();
        assert_eq!(flavors.len(), 1);
        assert_eq!(flavors[0], LOCAL_TREE_NODE_FLAVOR);
    }

    #[test]
    fn test_tree_transferable_properties() {
        let nodes = vec![ProgramNode::new_module("root")];
        let mut tt = ProgramTreeTransferable::new(nodes, "tree1");
        tt.set_property("operation", "copy");
        assert_eq!(tt.get_property("operation"), Some("copy"));
        assert_eq!(tt.get_property("nonexistent"), None);
    }

    #[test]
    fn test_empty_transferable() {
        let tt = ProgramTreeTransferable::new(vec![], "tree1");
        assert!(tt.is_empty());
        assert_eq!(tt.node_count(), 0);
    }

    #[test]
    fn test_transfer_data_variants() {
        let gt = GroupTransferable::new("grp", "t", false);
        let td = TransferData::Group(gt);
        assert!(td.as_group().is_some());
        assert!(td.as_tree_nodes().is_none());
        assert!(td.as_text().is_none());

        let td_text = TransferData::Text("hello".into());
        assert_eq!(td_text.as_text(), Some("hello"));
    }

    #[test]
    fn test_data_flavor_id() {
        let flavor = DataFlavorId::new("test", "application/x-test");
        assert_eq!(flavor.name, "test");
        assert_eq!(flavor.mime_type, "application/x-test");
    }
}
