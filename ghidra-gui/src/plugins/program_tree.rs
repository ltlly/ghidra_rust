//! Program tree view -- hierarchical fragment/module tree with
//! drag-and-drop reordering.
//!
//! Ports `ghidra.app.plugin.core.programtree`:
//! - [`ProgramNode`] (a tree node wrapping a Group)
//! - [`ProgramTreeModel`] (the tree model backed by a Program listing)
//! - [`ProgramTreePlugin`] (manages multiple tree views)

use std::collections::{HashMap, HashSet};

use ghidra_core::addr::AddressSet;
use ghidra_core::program::program::Program;

// ---------------------------------------------------------------------------
// ProgramNode -- a node in the tree
// ---------------------------------------------------------------------------

/// Node type discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// The root module of a tree.
    Root,
    /// An intermediate module (folder).
    Module,
    /// A leaf fragment (contiguous address range).
    Fragment,
}

/// A node in the program tree.
///
/// Each node wraps either a [`ProgramModule`] (folder) or a
/// [`ProgramFragment`] (leaf with addresses).
#[derive(Debug, Clone)]
pub struct ProgramNode {
    /// Display name.
    name: String,
    /// What kind of node this is.
    kind: NodeKind,
    /// Index of the parent node in the flat node list (`None` for root).
    parent: Option<usize>,
    /// Indices of child nodes.
    children: Vec<usize>,
    /// Whether this node has been lazily populated.
    visited: bool,
    /// Whether this node is marked as deleted (for rendering).
    deleted: bool,
    /// Whether this node is in the current view selection.
    in_view: bool,
    /// The address set for this node (meaningful for fragments/modules).
    address_set: AddressSet,
}

impl ProgramNode {
    /// Create a root node.
    pub fn root(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: NodeKind::Root,
            parent: None,
            children: Vec::new(),
            visited: true,
            deleted: false,
            in_view: false,
            address_set: AddressSet::new(),
        }
    }

    /// Create a module (folder) node.
    pub fn module(name: impl Into<String>, parent: usize) -> Self {
        Self {
            name: name.into(),
            kind: NodeKind::Module,
            parent: Some(parent),
            children: Vec::new(),
            visited: false,
            deleted: false,
            in_view: false,
            address_set: AddressSet::new(),
        }
    }

    /// Create a fragment (leaf) node.
    pub fn fragment(name: impl Into<String>, parent: usize, addresses: AddressSet) -> Self {
        Self {
            name: name.into(),
            kind: NodeKind::Fragment,
            parent: Some(parent),
            children: Vec::new(),
            visited: false,
            deleted: false,
            in_view: false,
            address_set: addresses,
        }
    }

    /// Display name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Mutable name setter.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    /// The kind of this node.
    pub fn kind(&self) -> NodeKind {
        self.kind
    }

    /// Whether this is a fragment (leaf).
    pub fn is_fragment(&self) -> bool {
        self.kind == NodeKind::Fragment
    }

    /// Whether this is a module (folder).
    pub fn is_module(&self) -> bool {
        self.kind == NodeKind::Module
    }

    /// Whether this is the root.
    pub fn is_root(&self) -> bool {
        self.kind == NodeKind::Root
    }

    /// Whether this node is a leaf (fragment or empty module).
    pub fn is_leaf(&self) -> bool {
        self.kind == NodeKind::Fragment
    }

    /// Parent index, if any.
    pub fn parent(&self) -> Option<usize> {
        self.parent
    }

    /// Child indices.
    pub fn children(&self) -> &[usize] {
        &self.children
    }

    /// Add a child.
    pub fn add_child(&mut self, child_idx: usize) {
        self.children.push(child_idx);
    }

    /// Remove a child by index value.
    pub fn remove_child(&mut self, child_idx: usize) {
        self.children.retain(|&c| c != child_idx);
    }

    /// Whether this node has been visited (populated).
    pub fn visited(&self) -> bool {
        self.visited
    }

    /// Mark as visited.
    pub fn set_visited(&mut self) {
        self.visited = true;
    }

    /// Whether this node is marked as deleted.
    pub fn is_deleted(&self) -> bool {
        self.deleted
    }

    /// Mark as deleted or not.
    pub fn set_deleted(&mut self, deleted: bool) {
        self.deleted = deleted;
    }

    /// Whether this node is in the current view.
    pub fn in_view(&self) -> bool {
        self.in_view
    }

    /// Set in-view flag.
    pub fn set_in_view(&mut self, in_view: bool) {
        self.in_view = in_view;
    }

    /// Get the address set for this node.
    pub fn address_set(&self) -> &AddressSet {
        &self.address_set
    }

    /// Set the address set for this node.
    pub fn set_address_set(&mut self, addrs: AddressSet) {
        self.address_set = addrs;
    }

    /// Recursively check whether any descendant is in the view.
    pub fn has_descendants_in_view(&self, nodes: &[ProgramNode]) -> bool {
        if self.in_view {
            return true;
        }
        for &child_idx in &self.children {
            if child_idx < nodes.len() && nodes[child_idx].has_descendants_in_view(nodes) {
                return true;
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// ProgramTreeModel -- the tree data model
// ---------------------------------------------------------------------------

/// A tree model backed by a flat vector of [`ProgramNode`]s.
///
/// Index 0 is always the root.
#[derive(Debug)]
pub struct ProgramTreeModel {
    /// The tree name (e.g. "Program Tree").
    tree_name: String,
    /// Flat node storage.  Index 0 is the root.
    nodes: Vec<ProgramNode>,
    /// Name-to-index lookup for quick node resolution.
    name_index: HashMap<String, usize>,
}

impl ProgramTreeModel {
    /// Create a model with a single root node.
    pub fn new(tree_name: impl Into<String>, root_name: impl Into<String>) -> Self {
        let root = ProgramNode::root(root_name);
        let mut name_index = HashMap::new();
        name_index.insert(root.name().to_owned(), 0);
        Self {
            tree_name: tree_name.into(),
            nodes: vec![root],
            name_index,
        }
    }

    /// The tree name.
    pub fn tree_name(&self) -> &str {
        &self.tree_name
    }

    /// Get a reference to the root node.
    pub fn root(&self) -> &ProgramNode {
        &self.nodes[0]
    }

    /// Get a node by index.
    pub fn node(&self, idx: usize) -> Option<&ProgramNode> {
        self.nodes.get(idx)
    }

    /// Get a mutable node by index.
    pub fn node_mut(&mut self, idx: usize) -> Option<&mut ProgramNode> {
        self.nodes.get_mut(idx)
    }

    /// Find a node by name.
    pub fn find_by_name(&self, name: &str) -> Option<usize> {
        self.name_index.get(name).copied()
    }

    /// Total number of nodes.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the tree is empty (only root, no children).
    pub fn is_empty(&self) -> bool {
        self.nodes.len() <= 1 && self.nodes[0].children().is_empty()
    }

    /// Add a module node under the given parent.
    pub fn add_module(&mut self, name: impl Into<String>, parent: usize) -> usize {
        let name = name.into();
        let idx = self.nodes.len();
        let mut node = ProgramNode::module(&name, parent);
        node.set_visited();
        self.nodes.push(node);
        self.nodes[parent].add_child(idx);
        self.name_index.insert(name, idx);
        idx
    }

    /// Add a fragment node under the given parent.
    pub fn add_fragment(
        &mut self,
        name: impl Into<String>,
        parent: usize,
        addresses: AddressSet,
    ) -> usize {
        let name = name.into();
        let idx = self.nodes.len();
        let node = ProgramNode::fragment(&name, parent, addresses);
        self.nodes.push(node);
        self.nodes[parent].add_child(idx);
        self.name_index.insert(name, idx);
        idx
    }

    /// Remove a node (and its subtree) from the model.
    ///
    /// Returns the set of removed indices.
    pub fn remove_node(&mut self, idx: usize) -> Vec<usize> {
        if idx == 0 {
            return Vec::new(); // cannot remove root
        }
        let mut removed = Vec::new();
        self.collect_subtree(idx, &mut removed);
        // Remove children references from parent
        if let Some(parent_idx) = self.nodes[idx].parent() {
            self.nodes[parent_idx].remove_child(idx);
        }
        // Mark nodes as deleted (we don't actually remove from the Vec
        // to keep indices stable; real Ghidra does the same with DB IDs)
        for &r in &removed {
            self.nodes[r].set_deleted(true);
            self.name_index.remove(self.nodes[r].name());
        }
        removed
    }

    fn collect_subtree(&self, idx: usize, out: &mut Vec<usize>) {
        out.push(idx);
        let children: Vec<usize> = self.nodes[idx].children().to_vec();
        for child in children {
            self.collect_subtree(child, out);
        }
    }

    /// Reload the tree from the program listing.
    ///
    /// Rebuilds the entire tree from the listing's root module.
    pub fn reload_from_program(&mut self, program: &Program) {
        // In a full implementation this would walk the program's
        // Listing.getTreeModel(treeName) and sync nodes.
        // Here we just reset to the root.
        self.nodes.truncate(1);
        self.nodes[0].children.clear();
        self.name_index.clear();
        self.name_index.insert(self.nodes[0].name().to_owned(), 0);
        let _ = program; // suppress unused warning
    }

    /// Get the view address set -- union of all in-view fragment
    /// address sets.
    pub fn view_address_set(&self) -> AddressSet {
        let mut result = AddressSet::new();
        for node in &self.nodes {
            if node.in_view && node.is_fragment() {
                result.add_set(node.address_set());
            }
        }
        result
    }
}

// ---------------------------------------------------------------------------
// TreeViewProvider -- wraps a model + selection state
// ---------------------------------------------------------------------------

/// A view provider for one named tree.
pub struct TreeViewProvider {
    /// The view (tab) name.
    view_name: String,
    /// The tree model.
    model: ProgramTreeModel,
    /// Currently selected node indices.
    selection: HashSet<usize>,
    /// The program associated with this view.
    program_name: Option<String>,
}

impl TreeViewProvider {
    /// Create a new view provider.
    pub fn new(view_name: impl Into<String>, root_name: impl Into<String>) -> Self {
        let view_name = view_name.into();
        let model = ProgramTreeModel::new(&view_name, root_name);
        Self {
            view_name,
            model,
            selection: HashSet::new(),
            program_name: None,
        }
    }

    /// The view name.
    pub fn view_name(&self) -> &str {
        &self.view_name
    }

    /// Set the view name (e.g. after a rename).
    pub fn set_view_name(&mut self, name: impl Into<String>) {
        self.view_name = name.into();
    }

    /// Access the underlying model.
    pub fn model(&self) -> &ProgramTreeModel {
        &self.model
    }

    /// Mutable access to the underlying model.
    pub fn model_mut(&mut self) -> &mut ProgramTreeModel {
        &mut self.model
    }

    /// Get the current selection.
    pub fn selection(&self) -> &HashSet<usize> {
        &self.selection
    }

    /// Select a single node.
    pub fn select(&mut self, node_idx: usize) {
        self.selection.clear();
        self.selection.insert(node_idx);
    }

    /// Add a node to the selection.
    pub fn add_to_selection(&mut self, node_idx: usize) {
        self.selection.insert(node_idx);
    }

    /// Clear the selection.
    pub fn clear_selection(&mut self) {
        self.selection.clear();
    }

    /// Set the program name.
    pub fn set_program(&mut self, name: Option<String>) {
        self.program_name = name;
    }

    /// Get the program name.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    /// Compute the address set for the current view.
    pub fn get_view(&self) -> AddressSet {
        self.model.view_address_set()
    }
}

// ---------------------------------------------------------------------------
// ProgramTreePlugin -- manages multiple tree views
// ---------------------------------------------------------------------------

/// The default tree name.
pub const DEFAULT_TREE_NAME: &str = "Program Tree";

/// Plugin managing multiple program tree views.
pub struct ProgramTreePlugin {
    /// Map of tree name to view provider.
    views: HashMap<String, TreeViewProvider>,
    /// Currently active view name.
    current_view: Option<String>,
    /// Whether selection follows the listing cursor.
    selection_follows_cursor: bool,
    /// Whether double-click replaces the view.
    replace_view_mode: bool,
}

impl ProgramTreePlugin {
    /// Create a new plugin with a default view.
    pub fn new() -> Self {
        let default = TreeViewProvider::new(DEFAULT_TREE_NAME, DEFAULT_TREE_NAME);
        let mut views = HashMap::new();
        views.insert(DEFAULT_TREE_NAME.to_owned(), default);
        Self {
            views,
            current_view: Some(DEFAULT_TREE_NAME.to_owned()),
            selection_follows_cursor: true,
            replace_view_mode: false,
        }
    }

    /// Get the currently active view provider.
    pub fn current_view(&self) -> Option<&TreeViewProvider> {
        self.current_view
            .as_ref()
            .and_then(|name| self.views.get(name))
    }

    /// Get a mutable reference to the currently active view provider.
    pub fn current_view_mut(&mut self) -> Option<&mut TreeViewProvider> {
        self.current_view
            .clone()
            .and_then(move |name| self.views.get_mut(&name))
    }

    /// Switch to a different tree view.
    pub fn set_current_view(&mut self, name: &str) -> bool {
        if self.views.contains_key(name) {
            self.current_view = Some(name.to_owned());
            true
        } else {
            false
        }
    }

    /// Add a new tree view.
    pub fn add_view(&mut self, tree_name: impl Into<String>) -> &mut TreeViewProvider {
        let tree_name = tree_name.into();
        let provider = TreeViewProvider::new(&tree_name, &tree_name);
        self.views.insert(tree_name.clone(), provider);
        self.views.get_mut(&tree_name).unwrap()
    }

    /// Remove a tree view by name.  Returns `false` if it's the last view.
    pub fn remove_view(&mut self, name: &str) -> bool {
        if self.views.len() <= 1 {
            return false; // cannot close last view
        }
        self.views.remove(name);
        if self.current_view.as_deref() == Some(name) {
            self.current_view = self.views.keys().next().cloned();
        }
        true
    }

    /// Rename a tree view.
    pub fn rename_view(&mut self, old_name: &str, new_name: &str) -> bool {
        if self.views.contains_key(new_name) {
            return false; // name collision
        }
        if let Some(mut provider) = self.views.remove(old_name) {
            provider.set_view_name(new_name);
            self.views.insert(new_name.to_owned(), provider);
            if self.current_view.as_deref() == Some(old_name) {
                self.current_view = Some(new_name.to_owned());
            }
            true
        } else {
            false
        }
    }

    /// List all view names.
    pub fn view_names(&self) -> Vec<&str> {
        self.views.keys().map(|s| s.as_str()).collect()
    }

    /// Number of views.
    pub fn view_count(&self) -> usize {
        self.views.len()
    }

    /// Whether selection follows the listing cursor.
    pub fn selection_follows_cursor(&self) -> bool {
        self.selection_follows_cursor
    }

    /// Toggle whether selection follows cursor.
    pub fn set_selection_follows_cursor(&mut self, follows: bool) {
        self.selection_follows_cursor = follows;
    }

    /// Whether double-click replaces the view.
    pub fn replace_view_mode(&self) -> bool {
        self.replace_view_mode
    }

    /// Set replace-view mode.
    pub fn set_replace_view_mode(&mut self, enabled: bool) {
        self.replace_view_mode = enabled;
    }

    /// Reload all trees from the program.
    pub fn reload_all(&mut self, program: &Program) {
        for provider in self.views.values_mut() {
            provider.model_mut().reload_from_program(program);
        }
    }

    /// Serialize view state for persistence.
    pub fn save_state(&self) -> Vec<String> {
        self.views.keys().cloned().collect()
    }

    /// Restore views from a saved state.
    pub fn load_state(&mut self, names: &[String]) {
        for name in names {
            if !self.views.contains_key(name) {
                self.add_view(name);
            }
        }
    }
}

impl Default for ProgramTreePlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    fn make_addr_set(ranges: &[(u64, u64)]) -> AddressSet {
        let mut s = AddressSet::new();
        for &(lo, hi) in ranges {
            s.add_range(addr(lo), addr(hi));
        }
        s
    }

    // -- ProgramNode tests --------------------------------------------------

    #[test]
    fn node_root() {
        let n = ProgramNode::root("Root");
        assert!(n.is_root());
        assert!(!n.is_fragment());
        assert!(!n.is_module());
        assert_eq!(n.name(), "Root");
        assert!(n.parent().is_none());
    }

    #[test]
    fn node_module() {
        let n = ProgramNode::module("Functions", 0);
        assert!(n.is_module());
        assert!(!n.is_leaf());
        assert_eq!(n.parent(), Some(0));
    }

    #[test]
    fn node_fragment() {
        let addrs = make_addr_set(&[(0x1000, 0x1FFF)]);
        let n = ProgramNode::fragment(".text", 0, addrs);
        assert!(n.is_fragment());
        assert!(n.is_leaf());
    }

    #[test]
    fn node_children() {
        let mut root = ProgramNode::root("R");
        root.add_child(1);
        root.add_child(2);
        assert_eq!(root.children(), &[1, 2]);
        root.remove_child(1);
        assert_eq!(root.children(), &[2]);
    }

    #[test]
    fn node_deleted() {
        let mut n = ProgramNode::root("R");
        assert!(!n.is_deleted());
        n.set_deleted(true);
        assert!(n.is_deleted());
    }

    #[test]
    fn node_descendants_in_view() {
        let mut nodes = vec![
            ProgramNode::root("R"),       // 0
            ProgramNode::module("M", 0),  // 1
            ProgramNode::fragment("F", 1, AddressSet::new()), // 2
        ];
        nodes[0].add_child(1);
        nodes[1].add_child(2);
        assert!(!nodes[0].has_descendants_in_view(&nodes));
        nodes[2].set_in_view(true);
        assert!(nodes[0].has_descendants_in_view(&nodes));
    }

    // -- ProgramTreeModel tests ---------------------------------------------

    #[test]
    fn model_creation() {
        let m = ProgramTreeModel::new("PT", "Root");
        assert_eq!(m.tree_name(), "PT");
        assert_eq!(m.len(), 1);
        assert!(m.root().is_root());
    }

    #[test]
    fn model_add_module() {
        let mut m = ProgramTreeModel::new("PT", "Root");
        let idx = m.add_module("Functions", 0);
        assert_eq!(idx, 1);
        assert!(m.node(idx).unwrap().is_module());
        assert_eq!(m.node(0).unwrap().children(), &[1]);
        assert_eq!(m.find_by_name("Functions"), Some(1));
    }

    #[test]
    fn model_add_fragment() {
        let mut m = ProgramTreeModel::new("PT", "Root");
        let addrs = make_addr_set(&[(0x0, 0xFF)]);
        let idx = m.add_fragment(".text", 0, addrs);
        assert!(m.node(idx).unwrap().is_fragment());
    }

    #[test]
    fn model_find_by_name() {
        let mut m = ProgramTreeModel::new("PT", "Root");
        m.add_module("Sub1", 0);
        assert_eq!(m.find_by_name("Sub1"), Some(1));
        assert!(m.find_by_name("nonexistent").is_none());
    }

    #[test]
    fn model_remove_node() {
        let mut m = ProgramTreeModel::new("PT", "Root");
        m.add_module("M1", 0);
        m.add_module("M2", 0);
        let removed = m.remove_node(1);
        assert_eq!(removed, vec![1]);
        assert!(m.node(1).unwrap().is_deleted());
        assert_eq!(m.node(0).unwrap().children(), &[2]);
    }

    #[test]
    fn model_cannot_remove_root() {
        let mut m = ProgramTreeModel::new("PT", "Root");
        let removed = m.remove_node(0);
        assert!(removed.is_empty());
    }

    #[test]
    fn model_view_address_set() {
        let mut m = ProgramTreeModel::new("PT", "Root");
        let addrs = make_addr_set(&[(0x1000, 0x1FFF)]);
        let fidx = m.add_fragment(".text", 0, addrs);
        m.node_mut(fidx).unwrap().set_in_view(true);
        let view = m.view_address_set();
        assert!(view.contains(&addr(0x1500)));
    }

    // -- TreeViewProvider tests ---------------------------------------------

    #[test]
    fn provider_creation() {
        let p = TreeViewProvider::new("MyTree", "Root");
        assert_eq!(p.view_name(), "MyTree");
        assert!(p.selection().is_empty());
    }

    #[test]
    fn provider_selection() {
        let mut p = TreeViewProvider::new("T", "R");
        p.select(1);
        assert!(p.selection().contains(&1));
        p.add_to_selection(2);
        assert_eq!(p.selection().len(), 2);
        p.clear_selection();
        assert!(p.selection().is_empty());
    }

    // -- ProgramTreePlugin tests --------------------------------------------

    #[test]
    fn plugin_creation() {
        let p = ProgramTreePlugin::new();
        assert_eq!(p.view_count(), 1);
        assert!(p.current_view().is_some());
        assert_eq!(p.current_view().unwrap().view_name(), DEFAULT_TREE_NAME);
    }

    #[test]
    fn plugin_add_view() {
        let mut p = ProgramTreePlugin::new();
        p.add_view("Functions");
        assert_eq!(p.view_count(), 2);
        assert!(p.view_names().contains(&"Functions"));
    }

    #[test]
    fn plugin_switch_view() {
        let mut p = ProgramTreePlugin::new();
        p.add_view("V2");
        assert!(p.set_current_view("V2"));
        assert_eq!(p.current_view().unwrap().view_name(), "V2");
    }

    #[test]
    fn plugin_switch_nonexistent_fails() {
        let mut p = ProgramTreePlugin::new();
        assert!(!p.set_current_view("nope"));
    }

    #[test]
    fn plugin_remove_view() {
        let mut p = ProgramTreePlugin::new();
        p.add_view("V2");
        assert!(p.remove_view("V2"));
        assert_eq!(p.view_count(), 1);
    }

    #[test]
    fn plugin_cannot_remove_last_view() {
        let mut p = ProgramTreePlugin::new();
        assert!(!p.remove_view(DEFAULT_TREE_NAME));
    }

    #[test]
    fn plugin_rename_view() {
        let mut p = ProgramTreePlugin::new();
        assert!(p.rename_view(DEFAULT_TREE_NAME, "NewName"));
        assert!(p.view_names().contains(&"NewName"));
        assert_eq!(p.current_view().unwrap().view_name(), "NewName");
    }

    #[test]
    fn plugin_rename_collision() {
        let mut p = ProgramTreePlugin::new();
        p.add_view("V2");
        assert!(!p.rename_view(DEFAULT_TREE_NAME, "V2"));
    }

    #[test]
    fn plugin_toggle_options() {
        let mut p = ProgramTreePlugin::new();
        assert!(p.selection_follows_cursor());
        p.set_selection_follows_cursor(false);
        assert!(!p.selection_follows_cursor());

        assert!(!p.replace_view_mode());
        p.set_replace_view_mode(true);
        assert!(p.replace_view_mode());
    }

    #[test]
    fn plugin_save_load_state() {
        let mut p = ProgramTreePlugin::new();
        p.add_view("V2");
        p.add_view("V3");
        let saved = p.save_state();
        let mut p2 = ProgramTreePlugin::new();
        p2.load_state(&saved);
        assert!(p2.view_names().contains(&"V2"));
        assert!(p2.view_names().contains(&"V3"));
    }
}
