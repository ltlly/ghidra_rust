//! TreeViewProvider -- provides a view of a single program tree.
//!
//! Ported from `ghidra.app.plugin.core.programtree.TreeViewProvider`.
//!
//! Each provider owns a [`ProgramTree`] and tracks the address set
//! that forms the current view.  It supports selecting nodes by
//! program location and notifying listeners of view changes.


use ghidra_core::addr::AddressSet;
use ghidra_core::Address;

use super::node::ProgramNode;
use super::tree::ProgramTree;
use super::GroupPath;

/// A listener for view changes.
pub trait ViewChangeListener: Send + Sync {
    /// Called when the view changes (different address ranges become visible).
    fn view_changed(&self, tree_name: &str, view: &AddressSet);
}

/// Provides a view of a single program tree.
///
/// Each view has:
/// - a unique name (the tree name)
/// - a [`ProgramTree`] with the full node hierarchy
/// - a computed address set representing the current view
/// - methods to select, expand, and navigate the tree
pub struct TreeViewProvider {
    /// The name of this view (matches the tree name).
    view_name: String,
    /// The underlying program tree.
    tree: ProgramTree,
    /// Computed address set for the current view.
    view_set: AddressSet,
    /// Whether this view currently has focus.
    has_focus: bool,
    /// Listeners for view changes.
    listeners: Vec<Box<dyn ViewChangeListener>>,
    /// Program name (for context).
    program_name: Option<String>,
}

impl std::fmt::Debug for TreeViewProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TreeViewProvider")
            .field("view_name", &self.view_name)
            .field("tree", &self.tree)
            .field("view_set", &self.view_set)
            .field("has_focus", &self.has_focus)
            .field("listeners", &format!("{} listeners", self.listeners.len()))
            .field("program_name", &self.program_name)
            .finish()
    }
}

impl TreeViewProvider {
    /// Create a new TreeViewProvider with the given tree name.
    pub fn new(tree_name: impl Into<String>) -> Self {
        let name = tree_name.into();
        let root = ProgramNode::new_module(&name);
        let tree = ProgramTree::new(&name, root);

        Self {
            view_name: name,
            tree,
            view_set: AddressSet::new(),
            has_focus: false,
            listeners: Vec::new(),
            program_name: None,
        }
    }

    /// Create a new TreeViewProvider with an existing tree.
    pub fn with_tree(tree: ProgramTree) -> Self {
        let name = tree.tree_name().to_string();
        Self {
            view_name: name,
            tree,
            view_set: AddressSet::new(),
            has_focus: false,
            listeners: Vec::new(),
            program_name: None,
        }
    }

    /// Returns the view name.
    pub fn view_name(&self) -> &str {
        &self.view_name
    }

    /// Set the view name.
    pub fn set_view_name(&mut self, name: impl Into<String>) {
        self.view_name = name.into();
    }

    /// Returns a reference to the underlying program tree.
    pub fn tree(&self) -> &ProgramTree {
        &self.tree
    }

    /// Returns a mutable reference to the underlying program tree.
    pub fn tree_mut(&mut self) -> &mut ProgramTree {
        &mut self.tree
    }

    /// Returns the computed address set for the current view.
    pub fn view_address_set(&self) -> &AddressSet {
        &self.view_set
    }

    /// Returns `true` if this view currently has focus.
    pub fn has_focus(&self) -> bool {
        self.has_focus
    }

    /// Set whether this view has focus.
    pub fn set_has_focus(&mut self, has_focus: bool) {
        self.has_focus = has_focus;
    }

    /// Set the program name.
    pub fn set_program_name(&mut self, name: Option<String>) {
        self.program_name = name;
    }

    /// Returns the program name.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    /// Add a listener for view changes.
    pub fn add_listener(&mut self, listener: Box<dyn ViewChangeListener>) {
        self.listeners.push(listener);
    }

    /// Notify all listeners that the view has changed.
    pub fn notify_listeners(&self) {
        for listener in &self.listeners {
            listener.view_changed(&self.view_name, &self.view_set);
        }
    }

    // ------------------------------------------------------------------
    // View management
    // ------------------------------------------------------------------

    /// Set the view to the given group path.
    pub fn set_view(&mut self, path: GroupPath) {
        self.tree.clear_view();
        self.tree.add_to_view(path);
        self.recompute_view();
    }

    /// Add a group path to the view.
    pub fn add_to_view(&mut self, path: GroupPath) {
        self.tree.add_to_view(path);
        self.recompute_view();
    }

    /// Remove a group path from the view.
    pub fn remove_from_view(&mut self, path: &GroupPath) {
        self.tree.remove_from_view(path);
        self.recompute_view();
    }

    /// Replace the view with the node at the given path.
    pub fn replace_view(&mut self, node: &ProgramNode) {
        if let Some(path) = node.group_path() {
            self.set_view(path.clone());
        }
    }

    /// Recompute the view address set from the tree's view paths.
    fn recompute_view(&mut self) {
        let ranges = self.tree.compute_view_address_ranges();
        self.view_set = AddressSet::new();
        for (min, max) in ranges {
            self.view_set.add_range(min, max);
        }
        self.notify_listeners();
    }

    // ------------------------------------------------------------------
    // Selection
    // ------------------------------------------------------------------

    /// Select the paths that correspond to the given address.
    pub fn select_paths_for_address(&mut self, addr: Address) {
        self.tree.clear_selection();
        // Walk the tree and find all fragment nodes whose range contains the address.
        self.select_matching_recursive(&self.tree.root().clone(), addr);
        // If nothing found, select the root
        if self.tree.is_selection_empty() {
            if let Some(gp) = self.tree.root().group_path() {
                self.tree.select(gp.clone());
            }
        }
    }

    fn select_matching_recursive(&mut self, node: &ProgramNode, addr: Address) {
        if node.is_fragment() {
            if let (Some(min), Some(max)) = (node.min_address(), node.max_address()) {
                if addr >= min && addr <= max {
                    if let Some(gp) = node.group_path() {
                        self.tree.select(gp.clone());
                    }
                }
            }
        }
        for child in node.children() {
            self.select_matching_recursive(child, addr);
        }
    }

    /// Set the selection from a set of group paths.
    pub fn set_group_selection(&mut self, paths: &[GroupPath]) {
        self.tree.set_selection(paths.to_vec());
    }

    // ------------------------------------------------------------------
    // Expansion
    // ------------------------------------------------------------------

    /// Expand the node at the given group path.
    pub fn expand_path(&mut self, path: &GroupPath) {
        self.tree.expand(path);
    }

    /// Collapse the node at the given group path.
    pub fn collapse_path(&mut self, path: &GroupPath) {
        self.tree.collapse(path);
    }

    // ------------------------------------------------------------------
    // Persistence
    // ------------------------------------------------------------------

    /// Serialize the view state (view paths, expansion, selection) into a map.
    pub fn save_state(&self) -> ViewState {
        ViewState {
            view_paths: self.tree.view_paths().to_vec(),
            expanded_paths: self.tree.expanded_paths().iter().cloned().collect(),
            selected_paths: self.tree.selected_paths().to_vec(),
        }
    }

    /// Restore the view state from a serialized map.
    pub fn restore_state(&mut self, state: &ViewState) {
        self.tree.clear_view();
        for p in &state.view_paths {
            self.tree.add_to_view(p.clone());
        }
        for p in &state.expanded_paths {
            self.tree.expand(p);
        }
        self.tree.set_selection(state.selected_paths.clone());
        self.recompute_view();
    }

    /// Dispose of resources.
    pub fn dispose(&mut self) {
        self.listeners.clear();
        self.view_set = AddressSet::new();
    }
}

/// Serializable view state for persistence.
#[derive(Debug, Clone, Default)]
pub struct ViewState {
    /// Paths defining the current view.
    pub view_paths: Vec<GroupPath>,
    /// Paths that are expanded.
    pub expanded_paths: Vec<GroupPath>,
    /// Paths that are selected.
    pub selected_paths: Vec<GroupPath>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::node::ProgramNode;
    use super::super::tree::ProgramTree;

    fn make_view_provider() -> TreeViewProvider {
        let mut root = ProgramNode::new_module("Program Tree");
        let mut folder = ProgramNode::new_module("src");
        folder.add_child(ProgramNode::new_fragment(
            ".text",
            Some(Address::new(0x1000)),
            Some(Address::new(0x2000)),
        ));
        folder.add_child(ProgramNode::new_fragment(
            ".data",
            Some(Address::new(0x3000)),
            Some(Address::new(0x3500)),
        ));
        root.add_child(folder);
        root.add_child(ProgramNode::new_fragment(
            ".bss",
            Some(Address::new(0x4000)),
            Some(Address::new(0x5000)),
        ));

        let tree = ProgramTree::new("Program Tree", root);
        TreeViewProvider::with_tree(tree)
    }

    #[test]
    fn test_view_provider_creation() {
        let vp = TreeViewProvider::new("Test Tree");
        assert_eq!(vp.view_name(), "Test Tree");
        assert!(!vp.has_focus());
    }

    #[test]
    fn test_view_address_set() {
        let vp = make_view_provider();
        // Default view is root, so all fragments
        let ranges = vp.tree().compute_view_address_ranges();
        assert_eq!(ranges.len(), 3);
    }

    #[test]
    fn test_select_paths_for_address() {
        let mut vp = make_view_provider();
        let addr = Address::new(0x1500); // in .text range
        vp.select_paths_for_address(addr);
        assert!(!vp.tree().selected_paths().is_empty());
    }

    #[test]
    fn test_save_restore_state() {
        let mut vp = make_view_provider();
        let path = GroupPath::new(vec!["Program Tree".into(), "src".into()]);
        vp.expand_path(&path);
        vp.add_to_view(path.clone());

        let state = vp.save_state();
        assert!(state.expanded_paths.contains(&path));

        // Create fresh provider and restore
        let mut vp2 = make_view_provider();
        vp2.restore_state(&state);
        assert!(vp2.tree().is_expanded(&path));
    }

    #[test]
    fn test_set_view_name() {
        let mut vp = TreeViewProvider::new("old_name");
        vp.set_view_name("new_name");
        assert_eq!(vp.view_name(), "new_name");
    }
}
