//! Visitor patterns for trace object tree traversal.
//!
//! Ported from Ghidra's `ghidra.trace.database.target.visitors` package:
//! - AllPathsVisitor
//! - AncestorsRelativeVisitor / AncestorsRootVisitor
//! - CanonicalSuccessorsRelativeVisitor
//! - OrderedSuccessorsVisitor
//! - SuccessorsRelativeVisitor
//! - TreeTraversal
//!
//! These provide different strategies for traversing the trace object tree.

use serde::{Deserialize, Serialize};

use crate::target::KeyPath;

/// The direction of tree traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TraversalDirection {
    /// Traverse from root to leaves.
    Down,
    /// Traverse from leaves to root.
    Up,
}

/// A visitor for traversing trace object paths.
///
/// Ported from Ghidra's visitor pattern for trace object trees.
pub trait TraceObjectVisitor {
    /// The result type produced by visiting.
    type Output;

    /// Visit a node at the given path.
    fn visit(&mut self, path: &KeyPath) -> VisitorAction<Self::Output>;

    /// Called when traversal is complete.
    fn finish(self) -> Self::Output;
}

/// The action to take after visiting a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VisitorAction<T> {
    /// Continue traversal.
    Continue,
    /// Stop traversal with a result.
    Stop(T),
    /// Skip children of this node (for downward traversal).
    SkipChildren,
}

/// A visitor that collects all paths encountered during traversal.
///
/// Ported from Ghidra's `AllPathsVisitor`.
#[derive(Debug, Clone, Default)]
pub struct AllPathsVisitor {
    /// All paths visited.
    pub paths: Vec<KeyPath>,
}

impl AllPathsVisitor {
    /// Create a new all-paths visitor.
    pub fn new() -> Self {
        Self { paths: Vec::new() }
    }
}

impl TraceObjectVisitor for AllPathsVisitor {
    type Output = Vec<KeyPath>;

    fn visit(&mut self, path: &KeyPath) -> VisitorAction<Self::Output> {
        self.paths.push(path.clone());
        VisitorAction::Continue
    }

    fn finish(self) -> Self::Output {
        self.paths
    }
}

/// A visitor that walks ancestors relative to a starting point.
///
/// Ported from Ghidra's `AncestorsRelativeVisitor`.
#[derive(Debug, Clone)]
pub struct AncestorsRelativeVisitor {
    /// The starting path.
    pub start: KeyPath,
    /// The ancestors found (from start to root).
    pub ancestors: Vec<KeyPath>,
    /// Maximum depth to traverse.
    pub max_depth: usize,
}

impl AncestorsRelativeVisitor {
    /// Create a new ancestors visitor.
    pub fn new(start: KeyPath, max_depth: usize) -> Self {
        Self {
            start,
            ancestors: Vec::new(),
            max_depth,
        }
    }
}

impl TraceObjectVisitor for AncestorsRelativeVisitor {
    type Output = Vec<KeyPath>;

    fn visit(&mut self, path: &KeyPath) -> VisitorAction<Self::Output> {
        self.ancestors.push(path.clone());
        if self.ancestors.len() >= self.max_depth {
            return VisitorAction::Stop(self.ancestors.clone());
        }
        VisitorAction::Continue
    }

    fn finish(self) -> Self::Output {
        self.ancestors
    }
}

/// A visitor that walks up to the root from a starting point.
///
/// Ported from Ghidra's `AncestorsRootVisitor`.
#[derive(Debug, Clone)]
pub struct AncestorsRootVisitor {
    /// The path from start to root.
    pub path_to_root: Vec<KeyPath>,
}

impl AncestorsRootVisitor {
    /// Create a new root-walking visitor.
    pub fn new() -> Self {
        Self {
            path_to_root: Vec::new(),
        }
    }
}

impl TraceObjectVisitor for AncestorsRootVisitor {
    type Output = Vec<KeyPath>;

    fn visit(&mut self, path: &KeyPath) -> VisitorAction<Self::Output> {
        self.path_to_root.push(path.clone());
        if path.is_root() {
            return VisitorAction::Stop(self.path_to_root.clone());
        }
        VisitorAction::Continue
    }

    fn finish(self) -> Self::Output {
        self.path_to_root
    }
}

/// A visitor that walks canonical successors.
///
/// Ported from Ghidra's `CanonicalSuccessorsRelativeVisitor`.
#[derive(Debug, Clone, Default)]
pub struct CanonicalSuccessorsRelativeVisitor {
    /// The successor paths found.
    pub successors: Vec<KeyPath>,
    /// Maximum depth to traverse.
    pub max_depth: usize,
}

impl CanonicalSuccessorsRelativeVisitor {
    /// Create a new canonical successors visitor.
    pub fn new(max_depth: usize) -> Self {
        Self {
            successors: Vec::new(),
            max_depth,
        }
    }
}

impl TraceObjectVisitor for CanonicalSuccessorsRelativeVisitor {
    type Output = Vec<KeyPath>;

    fn visit(&mut self, path: &KeyPath) -> VisitorAction<Self::Output> {
        self.successors.push(path.clone());
        if path.size() >= self.max_depth {
            return VisitorAction::SkipChildren;
        }
        VisitorAction::Continue
    }

    fn finish(self) -> Self::Output {
        self.successors
    }
}

/// A visitor that walks ordered successors.
///
/// Ported from Ghidra's `OrderedSuccessorsVisitor`.
#[derive(Debug, Clone, Default)]
pub struct OrderedSuccessorsVisitor {
    /// The successor paths found, in order.
    pub ordered_paths: Vec<KeyPath>,
}

impl OrderedSuccessorsVisitor {
    /// Create a new ordered successors visitor.
    pub fn new() -> Self {
        Self {
            ordered_paths: Vec::new(),
        }
    }
}

impl TraceObjectVisitor for OrderedSuccessorsVisitor {
    type Output = Vec<KeyPath>;

    fn visit(&mut self, path: &KeyPath) -> VisitorAction<Self::Output> {
        self.ordered_paths.push(path.clone());
        VisitorAction::Continue
    }

    fn finish(self) -> Self::Output {
        self.ordered_paths
    }
}

/// A visitor that walks successors relative to a starting point.
///
/// Ported from Ghidra's `SuccessorsRelativeVisitor`.
#[derive(Debug, Clone)]
pub struct SuccessorsRelativeVisitor {
    /// The starting path.
    pub start: KeyPath,
    /// The successor paths found.
    pub successors: Vec<KeyPath>,
    /// Maximum depth to traverse.
    pub max_depth: usize,
}

impl SuccessorsRelativeVisitor {
    /// Create a new successors visitor.
    pub fn new(start: KeyPath, max_depth: usize) -> Self {
        Self {
            start,
            successors: Vec::new(),
            max_depth,
        }
    }
}

impl TraceObjectVisitor for SuccessorsRelativeVisitor {
    type Output = Vec<KeyPath>;

    fn visit(&mut self, path: &KeyPath) -> VisitorAction<Self::Output> {
        self.successors.push(path.clone());
        if path.size() - self.start.size() >= self.max_depth {
            return VisitorAction::SkipChildren;
        }
        VisitorAction::Continue
    }

    fn finish(self) -> Self::Output {
        self.successors
    }
}

/// A tree traversal utility that drives a visitor through a tree structure.
///
/// Ported from Ghidra's `TreeTraversal`.
#[derive(Debug, Clone)]
pub struct TreeTraversal {
    /// The direction of traversal.
    pub direction: TraversalDirection,
    /// The root path to start from.
    pub root: KeyPath,
    /// Whether to include the root in the traversal.
    pub include_root: bool,
    /// Maximum depth to traverse (0 = unlimited).
    pub max_depth: usize,
}

impl TreeTraversal {
    /// Create a new downward traversal from the root.
    pub fn downward(root: KeyPath) -> Self {
        Self {
            direction: TraversalDirection::Down,
            root,
            include_root: true,
            max_depth: 0,
        }
    }

    /// Create a new upward traversal from a leaf.
    pub fn upward(leaf: KeyPath) -> Self {
        Self {
            direction: TraversalDirection::Up,
            root: leaf,
            include_root: true,
            max_depth: 0,
        }
    }

    /// Set whether to include the root.
    pub fn include_root(mut self, include: bool) -> Self {
        self.include_root = include;
        self
    }

    /// Set the maximum depth.
    pub fn max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    /// Execute the traversal with the given paths.
    pub fn traverse<V: TraceObjectVisitor>(
        &self,
        visitor: &mut V,
        children_fn: impl Fn(&KeyPath) -> Vec<KeyPath>,
    ) {
        let mut stack = vec![self.root.clone()];
        while let Some(path) = stack.pop() {
            if !self.include_root && path == self.root {
                // Still need to process children
                for child in children_fn(&path).into_iter().rev() {
                    stack.push(child);
                }
                continue;
            }

            match visitor.visit(&path) {
                VisitorAction::Continue => {
                    if self.max_depth == 0 || path.size() < self.max_depth {
                        let children = children_fn(&path);
                        match self.direction {
                            TraversalDirection::Down => {
                                for child in children.into_iter().rev() {
                                    stack.push(child);
                                }
                            }
                            TraversalDirection::Up => {
                                // For upward, we don't typically recurse into children
                            }
                        }
                    }
                }
                VisitorAction::SkipChildren => {
                    // Don't push children
                }
                VisitorAction::Stop(_) => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_path(segments: &[&str]) -> KeyPath {
        KeyPath::new(segments.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn test_all_paths_visitor() {
        let mut visitor = AllPathsVisitor::new();
        visitor.visit(&make_path(&["a"]));
        visitor.visit(&make_path(&["a", "b"]));
        visitor.visit(&make_path(&["a", "b", "c"]));
        let result = visitor.finish();
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_ancestors_relative_visitor() {
        let start = make_path(&["a", "b", "c"]);
        let mut visitor = AncestorsRelativeVisitor::new(start, 5);
        visitor.visit(&make_path(&["a", "b", "c"]));
        visitor.visit(&make_path(&["a", "b"]));
        visitor.visit(&make_path(&["a"]));
        let result = visitor.finish();
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_ancestors_relative_visitor_max_depth() {
        let start = make_path(&["a", "b", "c"]);
        let mut visitor = AncestorsRelativeVisitor::new(start, 2);
        let action = visitor.visit(&make_path(&["a", "b", "c"]));
        assert_eq!(action, VisitorAction::Continue);
        let action = visitor.visit(&make_path(&["a", "b"]));
        assert!(matches!(action, VisitorAction::Stop(_)));
    }

    #[test]
    fn test_ancestors_root_visitor() {
        let mut visitor = AncestorsRootVisitor::new();
        visitor.visit(&make_path(&["a", "b"]));
        visitor.visit(&make_path(&["a"]));
        let action = visitor.visit(&KeyPath::new(vec![]));
        assert!(matches!(action, VisitorAction::Stop(_)));
    }

    #[test]
    fn test_canonical_successors_visitor() {
        let mut visitor = CanonicalSuccessorsRelativeVisitor::new(3);
        visitor.visit(&make_path(&["a"]));
        visitor.visit(&make_path(&["a", "b"]));
        let action = visitor.visit(&make_path(&["a", "b", "c"]));
        assert_eq!(action, VisitorAction::SkipChildren);
    }

    #[test]
    fn test_ordered_successors_visitor() {
        let mut visitor = OrderedSuccessorsVisitor::new();
        visitor.visit(&make_path(&["b"]));
        visitor.visit(&make_path(&["a"]));
        visitor.visit(&make_path(&["c"]));
        let result = visitor.finish();
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_successors_relative_visitor() {
        let start = make_path(&["a"]);
        let mut visitor = SuccessorsRelativeVisitor::new(start, 2);
        visitor.visit(&make_path(&["a", "b"]));
        let action = visitor.visit(&make_path(&["a", "b", "c"]));
        assert!(matches!(action, VisitorAction::SkipChildren));
    }

    #[test]
    fn test_tree_traversal_downward() {
        let traversal = TreeTraversal::downward(make_path(&["root"]));

        let children_map: std::collections::HashMap<KeyPath, Vec<KeyPath>> = vec![
            (make_path(&["root"]), vec![make_path(&["root", "a"]), make_path(&["root", "b"])]),
            (make_path(&["root", "a"]), vec![make_path(&["root", "a", "x"])]),
            (make_path(&["root", "b"]), vec![]),
            (make_path(&["root", "a", "x"]), vec![]),
        ]
        .into_iter()
        .collect();

        let mut visitor = AllPathsVisitor::new();
        traversal.traverse(&mut visitor, |path| {
            children_map.get(path).cloned().unwrap_or_default()
        });
        let result = visitor.finish();
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn test_tree_traversal_no_root() {
        let traversal = TreeTraversal::downward(make_path(&["root"])).include_root(false);

        let children_map: std::collections::HashMap<KeyPath, Vec<KeyPath>> = vec![
            (make_path(&["root"]), vec![make_path(&["root", "a"])]),
            (make_path(&["root", "a"]), vec![]),
        ]
        .into_iter()
        .collect();

        let mut visitor = AllPathsVisitor::new();
        traversal.traverse(&mut visitor, |path| {
            children_map.get(path).cloned().unwrap_or_default()
        });
        let result = visitor.finish();
        assert_eq!(result.len(), 1);
    }
}
