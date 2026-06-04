//! GroupPath -- a hierarchical path through the program tree.
//!
//! Ported from `ghidra.program.util.GroupPath`.

use serde::{Deserialize, Serialize};

/// A path through the program tree from root to a specific group.
///
/// Each element in the path is a group name (module or fragment).
/// The first element is always the root module name.
///
/// # Example
///
/// ```rust
/// use ghidra_features::programtree::GroupPath;
///
/// let path = GroupPath::new(vec![
///     "Program Tree".into(),
///     "my_folder".into(),
///     ".text".into(),
/// ]);
/// assert_eq!(path.root_name(), "Program Tree");
/// assert_eq!(path.leaf_name(), ".text");
/// assert_eq!(path.depth(), 3);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupPath {
    /// The ordered list of group names from root to leaf.
    path: Vec<String>,
}

impl GroupPath {
    /// Create a new GroupPath from an ordered list of group names.
    ///
    /// # Panics
    ///
    /// Panics if `path` is empty.
    pub fn new(path: Vec<String>) -> Self {
        assert!(!path.is_empty(), "GroupPath must have at least one element");
        Self { path }
    }

    /// Create a GroupPath consisting of a single root name.
    pub fn root(name: impl Into<String>) -> Self {
        Self { path: vec![name.into()] }
    }

    /// Returns the name of the root node.
    pub fn root_name(&self) -> &str {
        &self.path[0]
    }

    /// Returns the name of the leaf (last) node.
    pub fn leaf_name(&self) -> &str {
        self.path.last().unwrap()
    }

    /// Returns the depth (number of elements) of this path.
    pub fn depth(&self) -> usize {
        self.path.len()
    }

    /// Returns `true` if this path is the root (depth == 1).
    pub fn is_root(&self) -> bool {
        self.path.len() == 1
    }

    /// Returns the parent path, or `None` if this is the root.
    pub fn parent(&self) -> Option<GroupPath> {
        if self.path.len() <= 1 {
            return None;
        }
        Some(GroupPath {
            path: self.path[..self.path.len() - 1].to_vec(),
        })
    }

    /// Append a child name to this path, returning a new deeper path.
    pub fn child(&self, name: impl Into<String>) -> GroupPath {
        let mut new_path = self.path.clone();
        new_path.push(name.into());
        GroupPath { path: new_path }
    }

    /// Returns a slice of all names in this path.
    pub fn names(&self) -> &[String] {
        &self.path
    }

    /// Returns `true` if `self` is an ancestor of `other`.
    pub fn is_ancestor_of(&self, other: &GroupPath) -> bool {
        if self.path.len() >= other.path.len() {
            return false;
        }
        self.path.iter().zip(other.path.iter()).all(|(a, b)| a == b)
    }

    /// Returns `true` if `self` is a descendant of `other`.
    pub fn is_descendant_of(&self, other: &GroupPath) -> bool {
        other.is_ancestor_of(self)
    }

    /// Returns `true` if `self` and `other` share the same root.
    pub fn same_tree(&self, other: &GroupPath) -> bool {
        self.root_name() == other.root_name()
    }
}

impl std::fmt::Display for GroupPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.path.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_path() {
        let path = GroupPath::new(vec!["root".into(), "folder".into(), "leaf".into()]);
        assert_eq!(path.root_name(), "root");
        assert_eq!(path.leaf_name(), "leaf");
        assert_eq!(path.depth(), 3);
        assert!(!path.is_root());
    }

    #[test]
    fn test_root_path() {
        let path = GroupPath::root("Program Tree");
        assert!(path.is_root());
        assert_eq!(path.parent(), None);
        assert_eq!(path.depth(), 1);
    }

    #[test]
    fn test_child_and_parent() {
        let root = GroupPath::root("root");
        let child = root.child("sub");
        let grandchild = child.child("leaf");

        assert_eq!(grandchild.depth(), 3);
        assert_eq!(grandchild.parent(), Some(child.clone()));
        assert_eq!(grandchild.parent().unwrap().parent(), Some(root.clone()));
    }

    #[test]
    fn test_ancestor_descendant() {
        let root = GroupPath::root("root");
        let mid = root.child("mid");
        let leaf = mid.child("leaf");

        assert!(root.is_ancestor_of(&leaf));
        assert!(leaf.is_descendant_of(&root));
        assert!(!leaf.is_ancestor_of(&root));
        assert!(!root.is_descendant_of(&leaf));
        assert!(mid.is_ancestor_of(&leaf));
        assert!(mid.is_descendant_of(&root));
    }

    #[test]
    fn test_same_tree() {
        let a = GroupPath::new(vec!["Tree1".into(), "a".into()]);
        let b = GroupPath::new(vec!["Tree1".into(), "b".into()]);
        let c = GroupPath::new(vec!["Tree2".into(), "a".into()]);

        assert!(a.same_tree(&b));
        assert!(!a.same_tree(&c));
    }

    #[test]
    fn test_display() {
        let path = GroupPath::new(vec!["root".into(), "sub".into(), "leaf".into()]);
        assert_eq!(path.to_string(), "root/sub/leaf");
    }

    #[test]
    #[should_panic(expected = "GroupPath must have at least one element")]
    fn test_empty_path_panics() {
        GroupPath::new(vec![]);
    }
}
