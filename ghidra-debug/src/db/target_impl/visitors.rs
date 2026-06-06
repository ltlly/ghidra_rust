//! Tree traversal visitors for the target object hierarchy.
//!
//! Ported from Ghidra's `ghidra.trace.database.target.visitors` package:
//! - `AllPathsVisitor`: Visit all paths in the object tree.
//! - `AncestorsRelativeVisitor`: Visit ancestors relative to a starting point.
//! - `AncestorsRootVisitor`: Visit all ancestors up to the root.
//! - `CanonicalSuccessorsRelativeVisitor`: Visit canonical successors.
//! - `SuccessorsRelativeVisitor`: Visit all successors relative to a starting point.
//! - `OrderedSuccessorsVisitor`: Visit successors in order.
//! - `TreeTraversal`: Generic tree traversal utilities.

use std::collections::{HashSet, VecDeque};

use crate::db::target_impl::value_storage::ValueSpace;

/// A path in the target object tree.
pub type ObjectPath = Vec<ValueSpace>;

/// A visitor that can process nodes during tree traversal.
pub trait TreeVisitor {
    /// The return type for this visitor.
    type Output;

    /// Visit a node at the given path.
    /// Return `true` to continue traversing children, `false` to skip.
    fn visit(&mut self, path: &[ValueSpace]) -> bool;

    /// Called after all children of a node have been visited.
    fn after_children(&mut self, _path: &[ValueSpace]) {}

    /// Get the final result.
    fn finish(self) -> Self::Output;
}

/// Visits all paths in the object tree.
pub struct AllPathsVisitor {
    paths: Vec<ObjectPath>,
    max_depth: usize,
}

impl AllPathsVisitor {
    /// Create a new all-paths visitor.
    pub fn new(max_depth: usize) -> Self {
        Self {
            paths: Vec::new(),
            max_depth,
        }
    }

    /// Get the collected paths.
    pub fn paths(&self) -> &[ObjectPath] {
        &self.paths
    }
}

impl TreeVisitor for AllPathsVisitor {
    type Output = Vec<ObjectPath>;

    fn visit(&mut self, path: &[ValueSpace]) -> bool {
        self.paths.push(path.to_vec());
        path.len() < self.max_depth
    }

    fn finish(self) -> Self::Output {
        self.paths
    }
}

/// Visits ancestors relative to a starting path, stopping at a boundary.
///
/// For a starting path `[A, B, C, D]`, this visits:
/// - `[A, B, C]` (parent)
/// - `[A, B]` (grandparent)
/// - `[A]` (root ancestor)
pub struct AncestorsRelativeVisitor {
    ancestors: Vec<ObjectPath>,
    start_path: ObjectPath,
    max_levels: usize,
}

impl AncestorsRelativeVisitor {
    /// Create a new ancestors-relative visitor.
    pub fn new(start_path: ObjectPath, max_levels: usize) -> Self {
        Self {
            ancestors: Vec::new(),
            start_path,
            max_levels,
        }
    }

    /// Run the visitor, collecting ancestors.
    pub fn run(&mut self) {
        let mut current = self.start_path.clone();
        for _ in 0..self.max_levels {
            if current.is_empty() {
                break;
            }
            current.pop();
            self.ancestors.push(current.clone());
        }
    }

    /// Get the collected ancestors.
    pub fn ancestors(&self) -> &[ObjectPath] {
        &self.ancestors
    }
}

/// Visits all ancestors from a starting path up to the root.
pub struct AncestorsRootVisitor {
    ancestors: Vec<ObjectPath>,
}

impl AncestorsRootVisitor {
    /// Create a new ancestors-root visitor with a starting path.
    pub fn new(start_path: ObjectPath) -> Self {
        let mut ancestors = Vec::new();
        let mut current = start_path;
        while !current.is_empty() {
            current.pop();
            ancestors.push(current.clone());
        }
        Self { ancestors }
    }

    /// Get the collected ancestors up to and including root.
    pub fn ancestors(&self) -> &[ObjectPath] {
        &self.ancestors
    }

    /// Check if root was reached.
    pub fn reached_root(&self) -> bool {
        self.ancestors
            .last()
            .map_or(false, |p| p.is_empty())
    }
}

/// Visits canonical successors of a path.
///
/// Canonical successors are the "primary" children along the canonical
/// path through the object hierarchy.
#[allow(dead_code)]
pub struct CanonicalSuccessorsRelativeVisitor {
    successors: Vec<ObjectPath>,
    base_path: ObjectPath,
    max_depth: usize,
    depth: usize,
}

impl CanonicalSuccessorsRelativeVisitor {
    /// Create a new canonical successors visitor.
    pub fn new(base_path: ObjectPath, max_depth: usize) -> Self {
        Self {
            successors: Vec::new(),
            base_path,
            max_depth,
            depth: 0,
        }
    }

    /// Add a canonical successor path.
    pub fn add_successor(&mut self, successor: ObjectPath) {
        if self.depth < self.max_depth {
            self.successors.push(successor);
            self.depth += 1;
        }
    }

    /// Get the collected successors.
    pub fn successors(&self) -> &[ObjectPath] {
        &self.successors
    }
}

/// Visits all successors (children, grandchildren, etc.) relative to a base path.
pub struct SuccessorsRelativeVisitor {
    visited: HashSet<Vec<String>>,
    successors: Vec<ObjectPath>,
    base_path: ObjectPath,
    max_depth: usize,
}

impl SuccessorsRelativeVisitor {
    /// Create a new successors-relative visitor.
    pub fn new(base_path: ObjectPath, max_depth: usize) -> Self {
        Self {
            visited: HashSet::new(),
            successors: Vec::new(),
            base_path,
            max_depth,
        }
    }

    /// Record a successor path.
    pub fn record_successor(&mut self, path: ObjectPath) -> bool {
        let key: Vec<String> = path.iter().map(|s| format!("{:?}", s)).collect();
        if self.visited.contains(&key) {
            return false;
        }
        if path.len() <= self.base_path.len() + self.max_depth {
            self.visited.insert(key);
            self.successors.push(path);
            true
        } else {
            false
        }
    }

    /// Get the collected successors.
    pub fn successors(&self) -> &[ObjectPath] {
        &self.successors
    }
}

/// Visits successors in breadth-first order.
pub struct OrderedSuccessorsVisitor {
    queue: VecDeque<ObjectPath>,
    result: Vec<ObjectPath>,
    visited: HashSet<Vec<String>>,
    max_depth: usize,
    base_path: ObjectPath,
}

impl OrderedSuccessorsVisitor {
    /// Create a new ordered successors visitor.
    pub fn new(base_path: ObjectPath, max_depth: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            result: Vec::new(),
            visited: HashSet::new(),
            max_depth,
            base_path,
        }
    }

    /// Enqueue a successor for visiting.
    pub fn enqueue(&mut self, path: ObjectPath) {
        let key: Vec<String> = path.iter().map(|s| format!("{:?}", s)).collect();
        if !self.visited.contains(&key)
            && path.len() <= self.base_path.len() + self.max_depth
        {
            self.visited.insert(key);
            self.queue.push_back(path);
        }
    }

    /// Process the next item in the queue. Returns the path, or None if empty.
    pub fn next(&mut self) -> Option<ObjectPath> {
        let path = self.queue.pop_front()?;
        self.result.push(path.clone());
        Some(path)
    }

    /// Check if there are more items to process.
    pub fn has_next(&self) -> bool {
        !self.queue.is_empty()
    }

    /// Get the collected result.
    pub fn result(&self) -> &[ObjectPath] {
        &self.result
    }
}

/// Generic tree traversal utilities.
pub struct TreeTraversal;

impl TreeTraversal {
    /// Breadth-first traversal, returning all visited paths.
    pub fn bfs<F>(
        root: ObjectPath,
        get_children: F,
        max_depth: usize,
    ) -> Vec<ObjectPath>
    where
        F: Fn(&[ValueSpace]) -> Vec<ObjectPath>,
    {
        let mut result = Vec::new();
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();

        let key: Vec<String> = root.iter().map(|s| format!("{:?}", s)).collect();
        visited.insert(key);
        queue.push_back(root.clone());
        result.push(root);

        while let Some(current) = queue.pop_front() {
            if current.len() >= max_depth {
                continue;
            }
            for child in get_children(&current) {
                let key: Vec<String> = child.iter().map(|s| format!("{:?}", s)).collect();
                if !visited.contains(&key) {
                    visited.insert(key);
                    result.push(child.clone());
                    queue.push_back(child);
                }
            }
        }

        result
    }

    /// Depth-first traversal, returning all visited paths.
    pub fn dfs<F>(
        root: ObjectPath,
        get_children: F,
        max_depth: usize,
    ) -> Vec<ObjectPath>
    where
        F: Fn(&[ValueSpace]) -> Vec<ObjectPath>,
    {
        let mut result = Vec::new();
        let mut visited = HashSet::new();
        Self::dfs_inner(root, &get_children, max_depth, &mut visited, &mut result);
        result
    }

    fn dfs_inner<F>(
        path: ObjectPath,
        get_children: &F,
        max_depth: usize,
        visited: &mut HashSet<Vec<String>>,
        result: &mut Vec<ObjectPath>,
    ) where
        F: Fn(&[ValueSpace]) -> Vec<ObjectPath>,
    {
        let key: Vec<String> = path.iter().map(|s| format!("{:?}", s)).collect();
        if visited.contains(&key) {
            return;
        }
        visited.insert(key);
        result.push(path.clone());

        if path.len() >= max_depth {
            return;
        }

        for child in get_children(&path) {
            Self::dfs_inner(child, get_children, max_depth, visited, result);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_path(components: &[&str]) -> ObjectPath {
        components
            .iter()
            .map(|s| ValueSpace::ByName(s.to_string()))
            .collect()
    }

    #[test]
    fn test_ancestors_relative() {
        let start = make_path(&["root", "process", "thread", "frame"]);
        let mut visitor = AncestorsRelativeVisitor::new(start, 3);
        visitor.run();

        let ancestors = visitor.ancestors();
        assert_eq!(ancestors.len(), 3);
        assert_eq!(ancestors[0].len(), 3); // parent
        assert_eq!(ancestors[1].len(), 2); // grandparent
        assert_eq!(ancestors[2].len(), 1); // great-grandparent
    }

    #[test]
    fn test_ancestors_root() {
        let start = make_path(&["root", "process", "thread"]);
        let visitor = AncestorsRootVisitor::new(start);

        assert!(visitor.reached_root());
        assert_eq!(visitor.ancestors().len(), 3); // 3, 2, 1, 0 = 3 pops
    }

    #[test]
    fn test_ordered_successors() {
        let base = make_path(&["root"]);
        let mut visitor = OrderedSuccessorsVisitor::new(base, 2);

        visitor.enqueue(make_path(&["root", "a"]));
        visitor.enqueue(make_path(&["root", "b"]));
        visitor.enqueue(make_path(&["root", "a", "x"]));

        assert!(visitor.has_next());
        let first = visitor.next().unwrap();
        assert_eq!(first.len(), 2); // root/a

        let second = visitor.next().unwrap();
        assert_eq!(second.len(), 2); // root/b

        let third = visitor.next().unwrap();
        assert_eq!(third.len(), 3); // root/a/x

        assert!(!visitor.has_next());
    }

    #[test]
    fn test_bfs() {
        let root = make_path(&["root"]);
        let result = TreeTraversal::bfs(
            root,
            |path| {
                if path.len() < 3 {
                    vec![
                        {
                            let mut p = path.to_vec();
                            p.push(ValueSpace::ByName("a".into()));
                            p
                        },
                        {
                            let mut p = path.to_vec();
                            p.push(ValueSpace::ByName("b".into()));
                            p
                        },
                    ]
                } else {
                    vec![]
                }
            },
            3,
        );

        // root, root/a, root/b, root/a/a, root/a/b, root/b/a, root/b/b
        assert_eq!(result.len(), 7);
        // BFS: root first
        assert_eq!(result[0].len(), 1);
        // Then depth 2
        assert_eq!(result[1].len(), 2);
        assert_eq!(result[2].len(), 2);
    }

    #[test]
    fn test_dfs() {
        let root = make_path(&["root"]);
        let result = TreeTraversal::dfs(
            root,
            |path| {
                if path.len() < 2 {
                    vec![{
                        let mut p = path.to_vec();
                        p.push(ValueSpace::ByName("child".into()));
                        p
                    }]
                } else {
                    vec![]
                }
            },
            3,
        );

        assert_eq!(result.len(), 2); // root, root/child
    }
}
