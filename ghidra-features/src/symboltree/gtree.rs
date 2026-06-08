//! Symbol GTree widget model -- ported from
//! `ghidra.app.plugin.core.symboltree.SymbolGTree`,
//! `SymbolGTreeDragNDropHandler`, and `DisconnectedSymbolTreeProvider`.
//!
//! Provides a generic tree widget model that supports:
//! - Hierarchical node expansion/collapse
//! - Drag-and-drop with move/copy semantics
//! - Snapshot/disconnected copies of the tree
//! - Inline editing of node names

use std::collections::HashMap;

use super::{ExternalLocation, SymbolCategory, SymbolDragDropAction, SymbolType};

// ---------------------------------------------------------------------------
// GTreeNode -- generic tree node with parent/child relationships
// ---------------------------------------------------------------------------

/// A node in the generic tree widget.
///
/// Each node has a unique ID, a display name, optional children,
/// and metadata about its expansion state.
#[derive(Debug, Clone)]
pub struct GTreeNode {
    /// Unique node ID.
    pub id: u64,
    /// Display name.
    pub name: String,
    /// Child node IDs (ordered).
    pub children: Vec<u64>,
    /// Parent node ID (None for root).
    pub parent: Option<u64>,
    /// Whether this node is expanded in the tree view.
    pub expanded: bool,
    /// Whether this node is editable.
    pub editable: bool,
    /// The associated symbol type (if any).
    pub symbol_type: Option<SymbolType>,
    /// Leaf data -- address for symbol nodes, or category label for category nodes.
    pub data: GTreeNodeData,
}

/// Data payload for a GTreeNode.
#[derive(Debug, Clone)]
pub enum GTreeNodeData {
    /// A category node (Functions, Labels, Classes, etc.).
    Category(SymbolCategory),
    /// A symbol node with address.
    Symbol {
        /// The symbol address.
        address: u64,
        /// The namespace path.
        namespace: String,
    },
    /// An external location node.
    External(ExternalLocation),
    /// An "organization" node that groups children by prefix.
    Organization {
        /// The prefix used for grouping.
        prefix: String,
    },
    /// A "more..." pagination node.
    More {
        /// The offset into the children list to continue from.
        offset: usize,
    },
}

impl GTreeNodeData {
    /// Whether this is a leaf node (no logical children).
    pub fn is_leaf(&self) -> bool {
        matches!(self, Self::Symbol { .. } | Self::More { .. })
    }
}

// ---------------------------------------------------------------------------
// SymbolGTree -- the tree widget model
// ---------------------------------------------------------------------------

/// The symbol tree widget model.
///
/// Ported from `ghidra.app.plugin.core.symboltree.SymbolGTree`.
///
/// Manages a hierarchy of [`GTreeNode`]s with expansion state,
/// selection tracking, and inline editing support.
#[derive(Debug)]
pub struct SymbolGTree {
    /// All nodes by ID.
    nodes: HashMap<u64, GTreeNode>,
    /// Root node IDs (ordered by category).
    root_ids: Vec<u64>,
    /// Next node ID.
    next_id: u64,
    /// Currently selected node IDs.
    selected_ids: Vec<u64>,
    /// The node currently being edited (if any).
    editing_node_id: Option<u64>,
    /// The view root (may differ from data root when filtering).
    view_root_id: Option<u64>,
    /// Whether the tree is in a disconnected (snapshot) state.
    disconnected: bool,
}

impl SymbolGTree {
    /// Create a new empty symbol tree.
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            root_ids: Vec::new(),
            next_id: 1,
            selected_ids: Vec::new(),
            editing_node_id: None,
            view_root_id: None,
            disconnected: false,
        }
    }

    /// Allocate a unique node ID.
    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Add a root category node.
    pub fn add_root_category(&mut self, category: SymbolCategory) -> u64 {
        let id = self.alloc_id();
        let node = GTreeNode {
            id,
            name: category.display_name().to_string(),
            children: Vec::new(),
            parent: None,
            expanded: false,
            editable: false,
            symbol_type: None,
            data: GTreeNodeData::Category(category),
        };
        self.nodes.insert(id, node);
        self.root_ids.push(id);
        id
    }

    /// Add a child node under a parent.
    ///
    /// Returns the new node's ID.
    pub fn add_child(
        &mut self,
        parent_id: u64,
        name: impl Into<String>,
        data: GTreeNodeData,
        symbol_type: Option<SymbolType>,
    ) -> Option<u64> {
        if !self.nodes.contains_key(&parent_id) {
            return None;
        }
        let id = self.alloc_id();
        let node = GTreeNode {
            id,
            name: name.into(),
            children: Vec::new(),
            parent: Some(parent_id),
            expanded: false,
            editable: true,
            symbol_type,
            data,
        };
        self.nodes.insert(id, node);
        if let Some(parent) = self.nodes.get_mut(&parent_id) {
            parent.children.push(id);
        }
        Some(id)
    }

    /// Get a node by ID.
    pub fn node(&self, id: u64) -> Option<&GTreeNode> {
        self.nodes.get(&id)
    }

    /// Get a mutable node by ID.
    pub fn node_mut(&mut self, id: u64) -> Option<&mut GTreeNode> {
        self.nodes.get_mut(&id)
    }

    /// Get the root node IDs.
    pub fn root_ids(&self) -> &[u64] {
        &self.root_ids
    }

    /// Expand a node (mark it as expanded).
    pub fn expand_node(&mut self, id: u64) -> bool {
        if let Some(node) = self.nodes.get_mut(&id) {
            node.expanded = true;
            true
        } else {
            false
        }
    }

    /// Collapse a node.
    pub fn collapse_node(&mut self, id: u64) -> bool {
        if let Some(node) = self.nodes.get_mut(&id) {
            node.expanded = false;
            true
        } else {
            false
        }
    }

    /// Toggle the expansion state of a node.
    pub fn toggle_node(&mut self, id: u64) -> bool {
        if let Some(node) = self.nodes.get_mut(&id) {
            node.expanded = !node.expanded;
            true
        } else {
            false
        }
    }

    /// Select a node.
    pub fn select_node(&mut self, id: u64) {
        self.selected_ids.clear();
        self.selected_ids.push(id);
    }

    /// Add a node to the current selection.
    pub fn add_to_selection(&mut self, id: u64) {
        if !self.selected_ids.contains(&id) {
            self.selected_ids.push(id);
        }
    }

    /// Clear the selection.
    pub fn clear_selection(&mut self) {
        self.selected_ids.clear();
    }

    /// Get selected node IDs.
    pub fn selected_ids(&self) -> &[u64] {
        &self.selected_ids
    }

    /// Start editing a node's name.
    pub fn start_editing(&mut self, id: u64) -> bool {
        if let Some(node) = self.nodes.get(&id) {
            if node.editable {
                self.editing_node_id = Some(id);
                return true;
            }
        }
        false
    }

    /// Finish editing -- rename the node.
    pub fn finish_editing(&mut self, new_name: impl Into<String>) -> bool {
        if let Some(edit_id) = self.editing_node_id.take() {
            if let Some(node) = self.nodes.get_mut(&edit_id) {
                node.name = new_name.into();
                return true;
            }
        }
        false
    }

    /// Cancel editing.
    pub fn cancel_editing(&mut self) {
        self.editing_node_id = None;
    }

    /// Whether a node is being edited.
    pub fn is_editing(&self) -> bool {
        self.editing_node_id.is_some()
    }

    /// The ID of the node being edited (if any).
    pub fn editing_node_id(&self) -> Option<u64> {
        self.editing_node_id
    }

    /// Remove a node and all its descendants.
    pub fn remove_node(&mut self, id: u64) -> bool {
        // Collect all descendant IDs to remove
        let mut to_remove = Vec::new();
        self.collect_descendant_ids(id, &mut to_remove);
        to_remove.push(id);

        // Remove from parent's children list
        if let Some(node) = self.nodes.get(&id) {
            if let Some(parent_id) = node.parent {
                if let Some(parent) = self.nodes.get_mut(&parent_id) {
                    parent.children.retain(|&c| c != id);
                }
            }
        }

        // Remove from root list if it's a root
        self.root_ids.retain(|&r| r != id);

        // Remove all nodes
        for remove_id in &to_remove {
            self.nodes.remove(remove_id);
        }

        // Clean up selection
        self.selected_ids.retain(|s| !to_remove.contains(s));

        !to_remove.is_empty()
    }

    fn collect_descendant_ids(&self, id: u64, result: &mut Vec<u64>) {
        if let Some(node) = self.nodes.get(&id) {
            for &child_id in &node.children {
                result.push(child_id);
                self.collect_descendant_ids(child_id, result);
            }
        }
    }

    /// Total number of nodes in the tree.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Whether this is a disconnected (snapshot) tree.
    pub fn is_disconnected(&self) -> bool {
        self.disconnected
    }

    /// Set the disconnected state.
    pub fn set_disconnected(&mut self, disconnected: bool) {
        self.disconnected = disconnected;
    }

    /// Create a snapshot (disconnected copy) of the tree.
    ///
    /// Ported from `DisconnectedSymbolTreeProvider`.
    pub fn snapshot(&self) -> Self {
        let mut copy = Self {
            nodes: self.nodes.clone(),
            root_ids: self.root_ids.clone(),
            next_id: self.next_id,
            selected_ids: Vec::new(),
            editing_node_id: None,
            view_root_id: self.view_root_id,
            disconnected: true,
        };
        // Mark all nodes as non-editable in the snapshot
        for node in copy.nodes.values_mut() {
            node.editable = false;
        }
        copy
    }

    /// Get the path from root to a node.
    pub fn path_to_node(&self, id: u64) -> Vec<String> {
        let mut path = Vec::new();
        self.build_path(id, &mut path);
        path
    }

    fn build_path(&self, id: u64, path: &mut Vec<String>) {
        if let Some(node) = self.nodes.get(&id) {
            if let Some(parent_id) = node.parent {
                self.build_path(parent_id, path);
            }
            path.push(node.name.clone());
        }
    }

    /// Find a node by name within a parent's children.
    pub fn find_child_by_name(&self, parent_id: u64, name: &str) -> Option<u64> {
        let parent = self.nodes.get(&parent_id)?;
        parent
            .children
            .iter()
            .find(|&&child_id| {
                self.nodes
                    .get(&child_id)
                    .map_or(false, |n| n.name == name)
            })
            .copied()
    }
}

impl Default for SymbolGTree {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SymbolGTreeDragNDropHandler
// ---------------------------------------------------------------------------

/// Handles drag-and-drop operations in the symbol tree.
///
/// Ported from `ghidra.app.plugin.core.symboltree.SymbolGTreeDragNDropHandler`.
///
/// Validates drop targets and performs the actual move/copy/link
/// of symbols between namespaces.
#[derive(Debug, Clone)]
pub struct SymbolGTreeDragNDropHandler {
    /// The allowed drag-drop actions.
    allowed_actions: Vec<SymbolDragDropAction>,
    /// Whether external drops (from other trees) are accepted.
    accept_external: bool,
}

impl SymbolGTreeDragNDropHandler {
    /// Create a new drag-drop handler with default settings.
    pub fn new() -> Self {
        Self {
            allowed_actions: vec![
                SymbolDragDropAction::Move,
                SymbolDragDropAction::Copy,
            ],
            accept_external: false,
        }
    }

    /// Whether a drop on the given target is valid.
    pub fn can_drop(&self, source_ids: &[u64], target_id: u64, tree: &SymbolGTree) -> bool {
        if source_ids.is_empty() {
            return false;
        }
        // Cannot drop onto itself
        if source_ids.contains(&target_id) {
            return false;
        }
        // Target must exist and be a namespace type
        match tree.node(target_id) {
            Some(target) => {
                target
                    .symbol_type
                    .map_or(true, |st| st.is_namespace() || target.data.is_leaf())
            }
            None => false,
        }
    }

    /// Perform a drop operation.
    ///
    /// Returns the number of symbols moved/copied.
    pub fn drop(
        &self,
        tree: &mut SymbolGTree,
        source_ids: &[u64],
        target_id: u64,
        action: SymbolDragDropAction,
    ) -> Result<usize, String> {
        if !self.allowed_actions.contains(&action) {
            return Err(format!("Action {:?} is not allowed", action));
        }
        if !self.can_drop(source_ids, target_id, tree) {
            return Err("Invalid drop target".into());
        }

        let mut moved = 0;
        match action {
            SymbolDragDropAction::Move => {
                for &source_id in source_ids {
                    // Collect node data before removing
                    let (name, data, sym_type) = if let Some(node) = tree.node(source_id) {
                        (node.name.clone(), node.data.clone(), node.symbol_type)
                    } else {
                        continue;
                    };
                    let _ = tree.remove_node(source_id);
                    tree.add_child(target_id, name, data, sym_type);
                    moved += 1;
                }
            }
            SymbolDragDropAction::Copy => {
                for &source_id in source_ids {
                    if let Some(node) = tree.node(source_id) {
                        let name = node.name.clone();
                        let data = node.data.clone();
                        let sym_type = node.symbol_type;
                        tree.add_child(target_id, name, data, sym_type);
                        moved += 1;
                    }
                }
            }
            SymbolDragDropAction::Link => {
                return Err("Link action not yet supported".into());
            }
        }
        Ok(moved)
    }

    /// Get the allowed actions.
    pub fn allowed_actions(&self) -> &[SymbolDragDropAction] {
        &self.allowed_actions
    }

    /// Set the allowed actions.
    pub fn set_allowed_actions(&mut self, actions: Vec<SymbolDragDropAction>) {
        self.allowed_actions = actions;
    }

    /// Whether external drops are accepted.
    pub fn accepts_external(&self) -> bool {
        self.accept_external
    }

    /// Set whether external drops are accepted.
    pub fn set_accept_external(&mut self, accept: bool) {
        self.accept_external = accept;
    }
}

impl Default for SymbolGTreeDragNDropHandler {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DisconnectedSymbolTreeProvider
// ---------------------------------------------------------------------------

/// A disconnected (snapshot) provider that displays a frozen copy of the
/// symbol tree.
///
/// Ported from `ghidra.app.plugin.core.symboltree.DisconnectedSymbolTreeProvider`.
///
/// The snapshot does not update when the program changes. It can be
/// used for comparison or inspection without modifying the live tree.
#[derive(Debug)]
pub struct DisconnectedSymbolTreeProvider {
    /// The snapshot tree.
    tree: SymbolGTree,
    /// The title for the snapshot window.
    title: String,
    /// The source program name.
    program_name: String,
}

impl DisconnectedSymbolTreeProvider {
    /// Create a new disconnected provider from a live tree.
    pub fn new(live_tree: &SymbolGTree, program_name: impl Into<String>) -> Self {
        Self {
            tree: live_tree.snapshot(),
            title: format!("Symbol Tree [Snapshot]"),
            program_name: program_name.into(),
        }
    }

    /// Get the snapshot tree.
    pub fn tree(&self) -> &SymbolGTree {
        &self.tree
    }

    /// Get the mutable snapshot tree.
    pub fn tree_mut(&mut self) -> &mut SymbolGTree {
        &mut self.tree
    }

    /// The title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// The source program name.
    pub fn program_name(&self) -> &str {
        &self.program_name
    }

    /// Node count in the snapshot.
    pub fn node_count(&self) -> usize {
        self.tree.node_count()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtree_node_creation() {
        let mut tree = SymbolGTree::new();
        let root_id = tree.add_root_category(SymbolCategory::Functions);
        let node = tree.node(root_id).unwrap();
        assert_eq!(node.name, "Functions");
        assert!(node.parent.is_none());
        assert!(!node.expanded);
    }

    #[test]
    fn test_gtree_add_child() {
        let mut tree = SymbolGTree::new();
        let root_id = tree.add_root_category(SymbolCategory::Functions);
        let child_id = tree
            .add_child(
                root_id,
                "main",
                GTreeNodeData::Symbol {
                    address: 0x401000,
                    namespace: String::new(),
                },
                Some(SymbolType::Function),
            )
            .unwrap();

        let child = tree.node(child_id).unwrap();
        assert_eq!(child.name, "main");
        assert_eq!(child.parent, Some(root_id));

        let root = tree.node(root_id).unwrap();
        assert_eq!(root.children, vec![child_id]);
    }

    #[test]
    fn test_gtree_expand_collapse() {
        let mut tree = SymbolGTree::new();
        let root_id = tree.add_root_category(SymbolCategory::Classes);

        assert!(!tree.node(root_id).unwrap().expanded);
        tree.expand_node(root_id);
        assert!(tree.node(root_id).unwrap().expanded);
        tree.collapse_node(root_id);
        assert!(!tree.node(root_id).unwrap().expanded);
    }

    #[test]
    fn test_gtree_toggle() {
        let mut tree = SymbolGTree::new();
        let root_id = tree.add_root_category(SymbolCategory::Labels);

        tree.toggle_node(root_id);
        assert!(tree.node(root_id).unwrap().expanded);
        tree.toggle_node(root_id);
        assert!(!tree.node(root_id).unwrap().expanded);
    }

    #[test]
    fn test_gtree_selection() {
        let mut tree = SymbolGTree::new();
        let r1 = tree.add_root_category(SymbolCategory::Functions);
        let r2 = tree.add_root_category(SymbolCategory::Labels);

        tree.select_node(r1);
        assert_eq!(tree.selected_ids(), &[r1]);

        tree.add_to_selection(r2);
        assert_eq!(tree.selected_ids().len(), 2);

        tree.clear_selection();
        assert!(tree.selected_ids().is_empty());
    }

    #[test]
    fn test_gtree_editing() {
        let mut tree = SymbolGTree::new();
        let root_id = tree.add_root_category(SymbolCategory::Functions);
        let child_id = tree
            .add_child(
                root_id,
                "old_name",
                GTreeNodeData::Symbol {
                    address: 0x100,
                    namespace: String::new(),
                },
                Some(SymbolType::Function),
            )
            .unwrap();

        assert!(!tree.is_editing());
        assert!(tree.start_editing(child_id));
        assert!(tree.is_editing());
        assert_eq!(tree.editing_node_id(), Some(child_id));

        assert!(tree.finish_editing("new_name"));
        assert!(!tree.is_editing());
        assert_eq!(tree.node(child_id).unwrap().name, "new_name");
    }

    #[test]
    fn test_gtree_cancel_editing() {
        let mut tree = SymbolGTree::new();
        let root_id = tree.add_root_category(SymbolCategory::Functions);
        let child_id = tree
            .add_child(
                root_id,
                "func",
                GTreeNodeData::Symbol {
                    address: 0x100,
                    namespace: String::new(),
                },
                Some(SymbolType::Function),
            )
            .unwrap();

        tree.start_editing(child_id);
        tree.cancel_editing();
        assert!(!tree.is_editing());
        assert_eq!(tree.node(child_id).unwrap().name, "func");
    }

    #[test]
    fn test_gtree_remove_node() {
        let mut tree = SymbolGTree::new();
        let root_id = tree.add_root_category(SymbolCategory::Functions);
        let c1 = tree
            .add_child(
                root_id,
                "f1",
                GTreeNodeData::Symbol {
                    address: 0x100,
                    namespace: String::new(),
                },
                Some(SymbolType::Function),
            )
            .unwrap();
        let _c2 = tree
            .add_child(
                root_id,
                "f2",
                GTreeNodeData::Symbol {
                    address: 0x200,
                    namespace: String::new(),
                },
                Some(SymbolType::Function),
            )
            .unwrap();

        assert_eq!(tree.node_count(), 3); // root + 2 children
        assert!(tree.remove_node(c1));
        assert_eq!(tree.node_count(), 2);
        assert!(tree.node(c1).is_none());

        let root = tree.node(root_id).unwrap();
        assert_eq!(root.children.len(), 1);
    }

    #[test]
    fn test_gtree_remove_cascades() {
        let mut tree = SymbolGTree::new();
        let root_id = tree.add_root_category(SymbolCategory::Classes);
        let ns_id = tree
            .add_child(
                root_id,
                "NS",
                GTreeNodeData::Organization {
                    prefix: "N".into(),
                },
                Some(SymbolType::Class),
            )
            .unwrap();
        tree.add_child(
            ns_id,
            "method",
            GTreeNodeData::Symbol {
                address: 0x300,
                namespace: "NS".into(),
            },
            Some(SymbolType::Function),
        );

        assert_eq!(tree.node_count(), 3);
        tree.remove_node(ns_id);
        assert_eq!(tree.node_count(), 1); // only root remains
    }

    #[test]
    fn test_gtree_snapshot() {
        let mut tree = SymbolGTree::new();
        let root_id = tree.add_root_category(SymbolCategory::Functions);
        tree.add_child(
            root_id,
            "main",
            GTreeNodeData::Symbol {
                address: 0x401000,
                namespace: String::new(),
            },
            Some(SymbolType::Function),
        );

        let snapshot = tree.snapshot();
        assert!(snapshot.is_disconnected());
        assert_eq!(snapshot.node_count(), tree.node_count());
        // Snapshot nodes should not be editable
        for node in snapshot.nodes.values() {
            assert!(!node.editable);
        }
    }

    #[test]
    fn test_gtree_path_to_node() {
        let mut tree = SymbolGTree::new();
        let root_id = tree.add_root_category(SymbolCategory::Functions);
        let child_id = tree
            .add_child(
                root_id,
                "main",
                GTreeNodeData::Symbol {
                    address: 0x401000,
                    namespace: String::new(),
                },
                Some(SymbolType::Function),
            )
            .unwrap();

        let path = tree.path_to_node(child_id);
        assert_eq!(path, vec!["Functions", "main"]);
    }

    #[test]
    fn test_gtree_find_child_by_name() {
        let mut tree = SymbolGTree::new();
        let root_id = tree.add_root_category(SymbolCategory::Labels);
        let child_id = tree
            .add_child(
                root_id,
                "L_entry",
                GTreeNodeData::Symbol {
                    address: 0x1000,
                    namespace: String::new(),
                },
                Some(SymbolType::Label),
            )
            .unwrap();

        assert_eq!(tree.find_child_by_name(root_id, "L_entry"), Some(child_id));
        assert_eq!(tree.find_child_by_name(root_id, "missing"), None);
    }

    #[test]
    fn test_drag_drop_handler_can_drop() {
        let mut tree = SymbolGTree::new();
        let root_id = tree.add_root_category(SymbolCategory::Classes);
        let ns_id = tree
            .add_child(
                root_id,
                "NS",
                GTreeNodeData::Organization {
                    prefix: "N".into(),
                },
                Some(SymbolType::Class),
            )
            .unwrap();
        let func_id = tree
            .add_child(
                ns_id,
                "method",
                GTreeNodeData::Symbol {
                    address: 0x100,
                    namespace: "NS".into(),
                },
                Some(SymbolType::Function),
            )
            .unwrap();

        let handler = SymbolGTreeDragNDropHandler::new();
        // Can drop onto namespace
        assert!(handler.can_drop(&[func_id], ns_id, &tree));
        // Cannot drop onto self
        assert!(!handler.can_drop(&[func_id], func_id, &tree));
        // Cannot drop empty
        assert!(!handler.can_drop(&[], ns_id, &tree));
    }

    #[test]
    fn test_drag_drop_handler_move() {
        let mut tree = SymbolGTree::new();
        let r1 = tree.add_root_category(SymbolCategory::Functions);
        let r2 = tree.add_root_category(SymbolCategory::Labels);
        let func_id = tree
            .add_child(
                r1,
                "main",
                GTreeNodeData::Symbol {
                    address: 0x401000,
                    namespace: String::new(),
                },
                Some(SymbolType::Function),
            )
            .unwrap();

        let handler = SymbolGTreeDragNDropHandler::new();
        let result = handler.drop(&mut tree, &[func_id], r2, SymbolDragDropAction::Move);
        assert_eq!(result.unwrap(), 1);

        // After move, the old node is removed and a new one is created under r2
        assert!(tree.node(func_id).is_none());
        let r2_node = tree.node(r2).unwrap();
        assert_eq!(r2_node.children.len(), 1);
        let moved_id = r2_node.children[0];
        let moved_node = tree.node(moved_id).unwrap();
        assert_eq!(moved_node.name, "main");
        assert_eq!(moved_node.parent, Some(r2));
    }

    #[test]
    fn test_drag_drop_handler_copy() {
        let mut tree = SymbolGTree::new();
        let r1 = tree.add_root_category(SymbolCategory::Functions);
        let r2 = tree.add_root_category(SymbolCategory::Labels);
        tree.add_child(
            r1,
            "main",
            GTreeNodeData::Symbol {
                address: 0x401000,
                namespace: String::new(),
            },
            Some(SymbolType::Function),
        );

        let handler = SymbolGTreeDragNDropHandler::new();
        let count = handler
            .drop(&mut tree, &[1], r2, SymbolDragDropAction::Copy)
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(tree.node_count(), 4); // 2 roots + 2 copies
    }

    #[test]
    fn test_disconnected_provider() {
        let mut tree = SymbolGTree::new();
        let root_id = tree.add_root_category(SymbolCategory::Functions);
        tree.add_child(
            root_id,
            "main",
            GTreeNodeData::Symbol {
                address: 0x401000,
                namespace: String::new(),
            },
            Some(SymbolType::Function),
        );

        let provider = DisconnectedSymbolTreeProvider::new(&tree, "test.exe");
        assert_eq!(provider.program_name(), "test.exe");
        assert_eq!(provider.node_count(), 2);
        assert!(provider.tree().is_disconnected());
    }

    #[test]
    fn test_gtree_node_data_is_leaf() {
        assert!(GTreeNodeData::Symbol {
            address: 0x100,
            namespace: String::new(),
        }
        .is_leaf());
        assert!(!GTreeNodeData::Category(SymbolCategory::Functions).is_leaf());
        assert!(!GTreeNodeData::Organization {
            prefix: "A".into()
        }
        .is_leaf());
        assert!(GTreeNodeData::More { offset: 100 }.is_leaf());
    }
}
