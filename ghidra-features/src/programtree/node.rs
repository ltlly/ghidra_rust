//! ProgramNode -- a node in a program tree.
//!
//! Ported from `ghidra.app.plugin.core.programtree.ProgramNode`.
//!
//! Each node wraps a [`Group`] which is either a [`ProgramModule`] (has
//! children) or a [`ProgramFragment`] (leaf, represents an address range).

use std::fmt;

use ghidra_core::program::listing::{Group, ProgramFragment, ProgramModule};
use ghidra_core::Address;

use super::GroupPath;

/// The kind of group a node represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeKind {
    /// The node represents a module (can have children).
    Module,
    /// The node represents a fragment (leaf, has an address range).
    Fragment,
}

/// A node in the program tree.
///
/// Mirrors Ghidra's `ProgramNode` which extends `DefaultMutableTreeNode`.
/// Each node tracks:
/// - its group (module or fragment)
/// - its name, tree path, and group path
/// - whether it has been visited (populated with children)
/// - whether it is in the current view
/// - whether it is marked as deleted
///
/// Children are stored by index in a `Vec<ProgramNode>`.
#[derive(Debug, Clone)]
pub struct ProgramNode {
    /// Display name of this node.
    name: String,
    /// Whether this node represents a module or fragment.
    kind: NodeKind,
    /// Group name (the same as `name` for modules, or fragment name for fragments).
    group_name: String,
    /// Parent module name, if any.
    parent_module_name: Option<String>,
    /// Children (only for modules).
    children: Vec<ProgramNode>,
    /// Whether the children have been populated.
    visited: bool,
    /// The group path from root to this node.
    group_path: Option<GroupPath>,
    /// Whether this node is in the current view.
    is_in_view: bool,
    /// Whether this node is marked as deleted.
    deleted: bool,
    /// Minimum address of this node's address range (for fragments).
    min_address: Option<Address>,
    /// Maximum address of this node's address range (for fragments).
    max_address: Option<Address>,
    /// Version tag for cache invalidation (module version).
    version_tag: Option<u64>,
}

impl ProgramNode {
    // ------------------------------------------------------------------
    // Constructors
    // ------------------------------------------------------------------

    /// Create a new module node.
    pub fn new_module(name: impl Into<String>) -> Self {
        let n = name.into();
        Self {
            name: n.clone(),
            kind: NodeKind::Module,
            group_name: n,
            parent_module_name: None,
            children: Vec::new(),
            visited: false,
            group_path: None,
            is_in_view: false,
            deleted: false,
            min_address: None,
            max_address: None,
            version_tag: None,
        }
    }

    /// Create a new fragment node with an optional address range.
    pub fn new_fragment(
        name: impl Into<String>,
        min_address: Option<Address>,
        max_address: Option<Address>,
    ) -> Self {
        let n = name.into();
        Self {
            name: n.clone(),
            kind: NodeKind::Fragment,
            group_name: n,
            parent_module_name: None,
            children: Vec::new(),
            visited: true, // fragments don't need visiting
            group_path: None,
            is_in_view: false,
            deleted: false,
            min_address,
            max_address,
            version_tag: None,
        }
    }

    /// Create a root module node from a [`ProgramModule`].
    pub fn from_module(module: &dyn ProgramModule) -> Self {
        let mut node = Self::new_module(module.get_name());
        node.parent_module_name = None;
        node
    }

    /// Create a fragment node from a [`ProgramFragment`].
    pub fn from_fragment(fragment: &ProgramFragment) -> Self {
        Self::new_fragment(
            fragment.get_name(),
            fragment.get_min_address(),
            fragment.get_max_address(),
        )
    }

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    /// Returns the display name of this node.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the kind of this node (Module or Fragment).
    pub fn kind(&self) -> NodeKind {
        self.kind
    }

    /// Returns `true` if this node represents a module.
    pub fn is_module(&self) -> bool {
        self.kind == NodeKind::Module
    }

    /// Returns `true` if this node represents a fragment.
    pub fn is_fragment(&self) -> bool {
        self.kind == NodeKind::Fragment
    }

    /// Returns `true` if this node is a leaf (has no children or is a fragment).
    pub fn is_leaf(&self) -> bool {
        match self.kind {
            NodeKind::Fragment => true,
            NodeKind::Module => self.children.is_empty(),
        }
    }

    /// Returns `true` if this node is allowed to have children.
    pub fn allows_children(&self) -> bool {
        self.kind == NodeKind::Module
    }

    /// Returns the parent module name, if any.
    pub fn parent_module_name(&self) -> Option<&str> {
        self.parent_module_name.as_deref()
    }

    /// Returns the group name.
    pub fn group_name(&self) -> &str {
        &self.group_name
    }

    /// Returns a reference to the children of this node.
    pub fn children(&self) -> &[ProgramNode] {
        &self.children
    }

    /// Returns the number of children.
    pub fn child_count(&self) -> usize {
        self.children.len()
    }

    /// Returns the child at the given index.
    pub fn child_at(&self, index: usize) -> Option<&ProgramNode> {
        self.children.get(index)
    }

    /// Returns a mutable reference to the child at the given index.
    pub fn child_at_mut(&mut self, index: usize) -> Option<&mut ProgramNode> {
        self.children.get_mut(index)
    }

    /// Find a direct child by name.
    pub fn find_child(&self, name: &str) -> Option<&ProgramNode> {
        self.children.iter().find(|c| c.name == name)
    }

    /// Find a direct child by name (mutable).
    pub fn find_child_mut(&mut self, name: &str) -> Option<&mut ProgramNode> {
        self.children.iter_mut().find(|c| c.name == name)
    }

    /// Returns `true` if this node has been visited (children populated).
    pub fn was_visited(&self) -> bool {
        self.visited
    }

    /// Mark this node as visited.
    pub fn visit(&mut self) {
        if self.kind == NodeKind::Module {
            self.visited = true;
        }
    }

    /// Returns the group path for this node.
    pub fn group_path(&self) -> Option<&GroupPath> {
        self.group_path.as_ref()
    }

    /// Set the group path for this node.
    pub fn set_group_path(&mut self, path: GroupPath) {
        self.group_path = Some(path);
    }

    /// Returns `true` if this node is in the current view.
    pub fn is_in_view(&self) -> bool {
        self.is_in_view
    }

    /// Set whether this node is in the current view.
    pub fn set_in_view(&mut self, in_view: bool) {
        self.is_in_view = in_view;
    }

    /// Returns `true` if this node is marked as deleted.
    pub fn is_deleted(&self) -> bool {
        self.deleted
    }

    /// Mark this node as deleted or not.
    pub fn set_deleted(&mut self, deleted: bool) {
        self.deleted = deleted;
    }

    /// Returns the minimum address of this node's address range.
    pub fn min_address(&self) -> Option<Address> {
        self.min_address
    }

    /// Returns the maximum address of this node's address range.
    pub fn max_address(&self) -> Option<Address> {
        self.max_address
    }

    /// Returns the version tag for this node.
    pub fn version_tag(&self) -> Option<u64> {
        self.version_tag
    }

    /// Set the version tag.
    pub fn set_version_tag(&mut self, tag: Option<u64>) {
        self.version_tag = tag;
    }

    /// Set the display name.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    /// Set the parent module name.
    pub fn set_parent_module_name(&mut self, name: Option<String>) {
        self.parent_module_name = name;
    }

    /// Set the children of this node.
    pub fn set_children(&mut self, children: Vec<ProgramNode>) {
        self.children = children;
    }

    /// Add a child node.
    pub fn add_child(&mut self, child: ProgramNode) {
        self.children.push(child);
    }

    /// Insert a child at the given index.
    pub fn insert_child(&mut self, index: usize, child: ProgramNode) {
        let idx = index.min(self.children.len());
        self.children.insert(idx, child);
    }

    /// Remove and return the child at the given index.
    pub fn remove_child(&mut self, index: usize) -> Option<ProgramNode> {
        if index < self.children.len() {
            Some(self.children.remove(index))
        } else {
            None
        }
    }

    /// Remove a child by name, returning it if found.
    pub fn remove_child_by_name(&mut self, name: &str) -> Option<ProgramNode> {
        if let Some(pos) = self.children.iter().position(|c| c.name == name) {
            Some(self.children.remove(pos))
        } else {
            None
        }
    }

    /// Move a child from `from_index` to `to_index`.
    ///
    /// `to_index` is the desired index in the result (0-based).
    pub fn move_child(&mut self, from_index: usize, to_index: usize) -> Result<(), String> {
        if from_index >= self.children.len() {
            return Err(format!("from_index {} out of bounds", from_index));
        }
        if to_index >= self.children.len() {
            return Err(format!("to_index {} out of bounds", to_index));
        }
        if from_index == to_index {
            return Ok(());
        }
        let child = self.children.remove(from_index);
        self.children.insert(to_index, child);
        Ok(())
    }

    // ------------------------------------------------------------------
    // Tree queries
    // ------------------------------------------------------------------

    /// Check if this node is valid relative to a version tag.
    /// Returns `true` if the node's module version matches the tag (or is a fragment).
    pub fn is_valid(&self, version_tag: Option<u64>) -> bool {
        match self.kind {
            NodeKind::Module => self.version_tag == version_tag,
            NodeKind::Fragment => true,
        }
    }

    /// Recursively check if any descendant of this node is in the view.
    pub fn has_descendants_in_view(&self) -> bool {
        if self.is_in_view {
            return true;
        }
        self.children.iter().any(|child| {
            child.is_in_view || (child.allows_children() && child.has_descendants_in_view())
        })
    }

    /// Find all nodes in the subtree that are in the view.
    pub fn collect_in_view(&self) -> Vec<&GroupPath> {
        let mut result = Vec::new();
        self.collect_in_view_recursive(&mut result);
        result
    }

    fn collect_in_view_recursive<'a>(&'a self, result: &mut Vec<&'a GroupPath>) {
        if self.is_in_view {
            if let Some(ref gp) = self.group_path {
                result.push(gp);
            }
        }
        for child in &self.children {
            child.collect_in_view_recursive(result);
        }
    }

    /// Find all expanded group paths.
    pub fn collect_expanded<F>(&self, is_expanded: &F) -> Vec<GroupPath>
    where
        F: Fn(&ProgramNode) -> bool,
    {
        let mut result = Vec::new();
        self.collect_expanded_recursive(is_expanded, &mut result);
        result
    }

    fn collect_expanded_recursive<F>(&self, is_expanded: &F, result: &mut Vec<GroupPath>)
    where
        F: Fn(&ProgramNode) -> bool,
    {
        if is_expanded(self) {
            if let Some(ref gp) = self.group_path {
                result.push(gp.clone());
            }
        }
        for child in &self.children {
            child.collect_expanded_recursive(is_expanded, result);
        }
    }

    /// Find a node by group path.
    pub fn find_by_path(&self, path: &GroupPath) -> Option<&ProgramNode> {
        let names = path.names();
        if names.is_empty() || self.name != names[0] {
            return None;
        }
        let mut current = self;
        for name in &names[1..] {
            match current.find_child(name) {
                Some(child) => current = child,
                None => return None,
            }
        }
        Some(current)
    }

    /// Find a node by group path (mutable).
    pub fn find_by_path_mut(&mut self, path: &GroupPath) -> Option<&mut ProgramNode> {
        let names = path.names();
        if names.is_empty() || self.name != names[0] {
            return None;
        }
        let mut current = self;
        for name in &names[1..] {
            // This requires a helper to avoid the borrow checker issue.
            // We use a raw pointer approach or restructure.
            // For now, use the safe recursive approach.
            match current.children.iter_mut().find(|c| &c.name == name) {
                Some(child) => current = child,
                None => return None,
            }
        }
        Some(current)
    }

    /// Collect the names of all nodes (depth-first).
    pub fn collect_all_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        self.collect_names_recursive(&mut names);
        names
    }

    fn collect_names_recursive(&self, names: &mut Vec<String>) {
        names.push(self.name.clone());
        for child in &self.children {
            child.collect_names_recursive(names);
        }
    }

    /// Returns the total number of nodes in this subtree (including self).
    pub fn total_count(&self) -> usize {
        1 + self.children.iter().map(|c| c.total_count()).sum::<usize>()
    }

    /// Clear all fields for disposal.
    pub fn dispose(&mut self) {
        self.children.clear();
        self.group_path = None;
        self.visited = false;
    }
}

impl fmt::Display for ProgramNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind_str = match self.kind {
            NodeKind::Module => "Module",
            NodeKind::Fragment => "Fragment",
        };
        write!(f, "{}({})", self.name, kind_str)
    }
}

// Ensure equality is based on group name and parent (like the Java version).
impl PartialEq for ProgramNode {
    fn eq(&self, other: &Self) -> bool {
        self.group_name == other.group_name
            && self.parent_module_name == other.parent_module_name
    }
}
impl Eq for ProgramNode {}

impl std::hash::Hash for ProgramNode {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.group_name.hash(state);
        self.parent_module_name.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_node() {
        let node = ProgramNode::new_module("root");
        assert!(node.is_module());
        assert!(!node.is_fragment());
        assert!(node.allows_children());
        assert!(node.is_leaf()); // no children yet
        assert!(!node.was_visited());
    }

    #[test]
    fn test_fragment_node() {
        let addr = Address::new(0x1000);
        let frag = ProgramNode::new_fragment(".text", Some(addr), Some(Address::new(0x2000)));
        assert!(frag.is_fragment());
        assert!(!frag.is_module());
        assert!(!frag.allows_children());
        assert!(frag.is_leaf());
        assert_eq!(frag.min_address(), Some(addr));
    }

    #[test]
    fn test_children() {
        let mut root = ProgramNode::new_module("root");
        let child1 = ProgramNode::new_fragment(".text", None, None);
        let child2 = ProgramNode::new_fragment(".data", None, None);

        root.add_child(child1);
        root.add_child(child2);
        assert_eq!(root.child_count(), 2);
        assert!(!root.is_leaf());

        assert_eq!(root.find_child(".text").unwrap().name(), ".text");
        assert_eq!(root.find_child(".data").unwrap().name(), ".data");
        assert!(root.find_child(".bss").is_none());
    }

    #[test]
    fn test_remove_child() {
        let mut root = ProgramNode::new_module("root");
        root.add_child(ProgramNode::new_fragment(".text", None, None));
        root.add_child(ProgramNode::new_fragment(".data", None, None));

        let removed = root.remove_child(0).unwrap();
        assert_eq!(removed.name(), ".text");
        assert_eq!(root.child_count(), 1);
    }

    #[test]
    fn test_move_child() {
        let mut root = ProgramNode::new_module("root");
        root.add_child(ProgramNode::new_fragment("a", None, None));
        root.add_child(ProgramNode::new_fragment("b", None, None));
        root.add_child(ProgramNode::new_fragment("c", None, None));

        // Move "a" (index 0) to position 2 in result -> [b, c, a]
        root.move_child(0, 2).unwrap();
        assert_eq!(root.child_at(0).unwrap().name(), "b");
        assert_eq!(root.child_at(1).unwrap().name(), "c");
        assert_eq!(root.child_at(2).unwrap().name(), "a");
    }

    #[test]
    fn test_version_validation() {
        let frag = ProgramNode::new_fragment(".text", None, None);
        assert!(frag.is_valid(Some(42))); // fragments always valid

        let mut module = ProgramNode::new_module("mod");
        module.set_version_tag(Some(10));
        assert!(module.is_valid(Some(10)));
        assert!(!module.is_valid(Some(11)));
        assert!(!module.is_valid(None));
    }

    #[test]
    fn test_descendants_in_view() {
        let mut root = ProgramNode::new_module("root");
        let mut child = ProgramNode::new_module("child");
        let grandchild = ProgramNode::new_fragment(".text", None, None);

        child.add_child(grandchild);
        root.add_child(child);

        assert!(!root.has_descendants_in_view());

        // Simulate setting a descendant in view
        root.children_mut_at(0).unwrap().children_mut_at(0).unwrap().set_in_view(true);
        assert!(root.has_descendants_in_view());
    }

    // Helper to access mutable children by index
    trait NodeChildrenMut {
        fn children_mut_at(&mut self, index: usize) -> Option<&mut ProgramNode>;
    }
    impl NodeChildrenMut for ProgramNode {
        fn children_mut_at(&mut self, index: usize) -> Option<&mut ProgramNode> {
            self.children.get_mut(index)
        }
    }

    #[test]
    fn test_find_by_path() {
        let mut root = ProgramNode::new_module("root");
        let mut child = ProgramNode::new_module("folder");
        child.add_child(ProgramNode::new_fragment(".text", None, None));
        root.add_child(child);

        let path = GroupPath::new(vec!["root".into(), "folder".into(), ".text".into()]);
        let found = root.find_by_path(&path);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name(), ".text");

        let bad_path = GroupPath::new(vec!["root".into(), "nonexistent".into()]);
        assert!(root.find_by_path(&bad_path).is_none());
    }

    #[test]
    fn test_collect_all_names() {
        let mut root = ProgramNode::new_module("root");
        let mut folder = ProgramNode::new_module("folder");
        folder.add_child(ProgramNode::new_fragment(".text", None, None));
        folder.add_child(ProgramNode::new_fragment(".data", None, None));
        root.add_child(folder);

        let names = root.collect_all_names();
        assert_eq!(names, vec!["root", "folder", ".text", ".data"]);
    }

    #[test]
    fn test_display() {
        let node = ProgramNode::new_module("my_mod");
        assert_eq!(node.to_string(), "my_mod(Module)");

        let frag = ProgramNode::new_fragment(".text", None, None);
        assert_eq!(frag.to_string(), ".text(Fragment)");
    }
}
