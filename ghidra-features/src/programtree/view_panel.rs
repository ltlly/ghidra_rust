//! ViewPanel -- a panel holding a program tree view with its own selection state.
//!
//! Ported from `ghidra.app.plugin.core.programtree.ViewPanel`.
//!
//! In Ghidra, `ViewPanel` wraps a `ProgramDnDTree` and tracks the
//! current group view.  The Rust port models the selection and view
//! state without the Swing components.

use std::collections::HashSet;

use super::group_path::GroupPath;
use super::node::ProgramNode;

/// A panel containing a program tree view with selection tracking.
///
/// Mirrors Ghidra's `ViewPanel` which wraps `ProgramDnDTree` and provides
/// view-level operations like group selection, path tracking, and view name.
#[derive(Debug, Clone)]
pub struct ViewPanel {
    /// The name of this tree view.
    tree_name: String,
    /// The root node of the tree.
    root: Option<ProgramNode>,
    /// Currently selected group paths.
    selected_paths: Vec<GroupPath>,
    /// The set of expanded group paths.
    expanded_paths: HashSet<String>,
    /// Whether this panel has focus.
    has_focus: bool,
    /// The current group view (visible groups).
    group_view: Vec<GroupPath>,
}

impl ViewPanel {
    /// Create a new empty view panel with the given tree name.
    pub fn new(tree_name: impl Into<String>) -> Self {
        Self {
            tree_name: tree_name.into(),
            root: None,
            selected_paths: Vec::new(),
            expanded_paths: HashSet::new(),
            has_focus: false,
            group_view: Vec::new(),
        }
    }

    /// Returns the tree name.
    pub fn tree_name(&self) -> &str {
        &self.tree_name
    }

    /// Set the tree name.
    pub fn set_tree_name(&mut self, name: impl Into<String>) {
        self.tree_name = name.into();
    }

    /// Returns a reference to the root node.
    pub fn root(&self) -> Option<&ProgramNode> {
        self.root.as_ref()
    }

    /// Set the root node.
    pub fn set_root(&mut self, root: Option<ProgramNode>) {
        self.root = root;
    }

    /// Returns the currently selected group paths.
    pub fn selected_paths(&self) -> &[GroupPath] {
        &self.selected_paths
    }

    /// Set the selected group paths.
    pub fn set_selected_paths(&mut self, paths: Vec<GroupPath>) {
        self.selected_paths = paths;
    }

    /// Add a path to the selection.
    pub fn add_selected_path(&mut self, path: GroupPath) {
        if !self.selected_paths.contains(&path) {
            self.selected_paths.push(path);
        }
    }

    /// Clear the selection.
    pub fn clear_selection(&mut self) {
        self.selected_paths.clear();
    }

    /// Returns `true` if this panel has focus.
    pub fn has_focus(&self) -> bool {
        self.has_focus
    }

    /// Set whether this panel has focus.
    pub fn set_has_focus(&mut self, has_focus: bool) {
        self.has_focus = has_focus;
    }

    /// Mark a group path as expanded.
    pub fn set_expanded(&mut self, path: &GroupPath, expanded: bool) {
        let key = path.to_string();
        if expanded {
            self.expanded_paths.insert(key);
        } else {
            self.expanded_paths.remove(&key);
        }
    }

    /// Check if a group path is expanded.
    pub fn is_expanded(&self, path: &GroupPath) -> bool {
        self.expanded_paths.contains(&path.to_string())
    }

    /// Returns the expanded paths.
    pub fn expanded_paths(&self) -> &HashSet<String> {
        &self.expanded_paths
    }

    /// Returns the current group view (visible groups).
    pub fn group_view(&self) -> &[GroupPath] {
        &self.group_view
    }

    /// Set the group view.
    pub fn set_group_view(&mut self, view: Vec<GroupPath>) {
        self.group_view = view;
    }

    /// Add a path to the group view.
    pub fn add_group_view_path(&mut self, path: GroupPath) {
        if !self.group_view.contains(&path) {
            self.group_view.push(path);
        }
    }

    /// Replace the view for a given node.
    pub fn replace_view(&mut self, node: &ProgramNode) {
        self.group_view.clear();
        if let Some(gp) = node.group_path() {
            self.group_view.push(gp.clone());
        }
    }

    /// Returns the selected node (first selected path's leaf).
    pub fn get_selected_node(&self) -> Option<&GroupPath> {
        self.selected_paths.first()
    }

    /// Returns the number of selected paths.
    pub fn selection_count(&self) -> usize {
        self.selected_paths.len()
    }

    /// Returns `true` if the selection is empty.
    pub fn is_selection_empty(&self) -> bool {
        self.selected_paths.is_empty()
    }

    /// Dispose of this panel's resources.
    pub fn dispose(&mut self) {
        self.root = None;
        self.selected_paths.clear();
        self.expanded_paths.clear();
        self.group_view.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_view_panel_basic() {
        let mut panel = ViewPanel::new("tree1");
        assert_eq!(panel.tree_name(), "tree1");
        assert!(!panel.has_focus());
        assert!(panel.root().is_none());
        assert!(panel.is_selection_empty());
    }

    #[test]
    fn test_view_panel_focus() {
        let mut panel = ViewPanel::new("tree1");
        panel.set_has_focus(true);
        assert!(panel.has_focus());
    }

    #[test]
    fn test_view_panel_selection() {
        let mut panel = ViewPanel::new("tree1");
        let path = GroupPath::new(vec!["root".into(), ".text".into()]);

        panel.add_selected_path(path.clone());
        assert_eq!(panel.selection_count(), 1);
        assert!(!panel.is_selection_empty());
        assert_eq!(panel.get_selected_node().unwrap().names(), &["root", ".text"]);

        panel.clear_selection();
        assert!(panel.is_selection_empty());
    }

    #[test]
    fn test_view_panel_no_duplicate_selection() {
        let mut panel = ViewPanel::new("tree1");
        let path = GroupPath::new(vec!["root".into(), ".text".into()]);

        panel.add_selected_path(path.clone());
        panel.add_selected_path(path.clone());
        assert_eq!(panel.selection_count(), 1);
    }

    #[test]
    fn test_view_panel_expanded() {
        let mut panel = ViewPanel::new("tree1");
        let path = GroupPath::new(vec!["root".into()]);

        assert!(!panel.is_expanded(&path));
        panel.set_expanded(&path, true);
        assert!(panel.is_expanded(&path));
        panel.set_expanded(&path, false);
        assert!(!panel.is_expanded(&path));
    }

    #[test]
    fn test_view_panel_group_view() {
        let mut panel = ViewPanel::new("tree1");
        assert!(panel.group_view().is_empty());

        let path = GroupPath::new(vec!["root".into()]);
        panel.add_group_view_path(path);
        assert_eq!(panel.group_view().len(), 1);
    }

    #[test]
    fn test_view_panel_root() {
        let mut panel = ViewPanel::new("tree1");
        let root = ProgramNode::new_module("root");
        panel.set_root(Some(root));
        assert!(panel.root().is_some());
        assert_eq!(panel.root().unwrap().name(), "root");
    }

    #[test]
    fn test_view_panel_dispose() {
        let mut panel = ViewPanel::new("tree1");
        panel.set_root(Some(ProgramNode::new_module("root")));
        panel.add_selected_path(GroupPath::new(vec!["root".into()]));

        panel.dispose();
        assert!(panel.root().is_none());
        assert!(panel.is_selection_empty());
    }

    #[test]
    fn test_view_panel_rename() {
        let mut panel = ViewPanel::new("tree1");
        panel.set_tree_name("tree2");
        assert_eq!(panel.tree_name(), "tree2");
    }
}
