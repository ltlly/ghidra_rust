//! Graph path types for storing paths with fast containment checks.
//!
//! Port of `ghidra.graph.GraphPath<V>` and `ghidra.graph.GraphPathSet<V>`.

use std::collections::HashSet;
use std::fmt;
use std::hash::Hash;

// ============================================================================
// GraphPath  (port of GraphPath.java)
// ============================================================================

/// A path through a graph, stored as an ordered list of vertices with a
/// companion set for O(1) containment checks.
///
/// Note: a path can only contain each vertex once.
///
/// Mirrors `ghidra.graph.GraphPath<V>`.
#[derive(Debug, Clone)]
pub struct GraphPath<V: Eq + Hash + Clone> {
    path_set: HashSet<V>,
    path_list: Vec<V>,
}

impl<V: Eq + Hash + Clone> GraphPath<V> {
    /// Create an empty path.
    pub fn new() -> Self {
        Self {
            path_set: HashSet::new(),
            path_list: Vec::new(),
        }
    }

    /// Create a path initialized with a single vertex.
    pub fn with_vertex(v: V) -> Self {
        let mut p = Self::new();
        p.add(v);
        p
    }

    /// Create a shallow copy of this path.
    pub fn copy(&self) -> Self {
        Self {
            path_set: self.path_set.clone(),
            path_list: self.path_list.clone(),
        }
    }

    /// Check if this path starts with the given other path.
    pub fn starts_with(&self, other: &GraphPath<V>) -> bool {
        if self.size() < other.size() {
            return false;
        }
        for i in 0..other.size() {
            if self.path_list[i] != other.path_list[i] {
                return false;
            }
        }
        true
    }

    /// Return the common start path shared by this path and `other`.
    ///
    /// For example, `a-b-c-d-e-f` and `a-b-c-d-k-l-z` share `a-b-c-d`.
    pub fn get_common_start_path(&self, other: &GraphPath<V>) -> GraphPath<V> {
        let n = self.size().min(other.size());
        for i in 0..n {
            if self.get(i) != other.get(i) {
                return self.sub_path(0, i);
            }
        }
        self.sub_path(0, n)
    }

    /// Return the number of vertices in this path.
    pub fn size(&self) -> usize {
        self.path_list.len()
    }

    /// Check if the path is empty.
    pub fn is_empty(&self) -> bool {
        self.path_list.is_empty()
    }

    /// Check if a vertex is in this path.
    pub fn contains(&self, v: &V) -> bool {
        self.path_set.contains(v)
    }

    /// Add a vertex to the end of this path.
    ///
    /// Returns `true` if the vertex was added (not already present), `false` if
    /// it was a duplicate.
    pub fn add(&mut self, v: V) -> bool {
        if self.path_set.contains(&v) {
            return false;
        }
        self.path_set.insert(v.clone());
        self.path_list.push(v);
        true
    }

    /// Get the vertex at the given index.
    pub fn get(&self, index: usize) -> &V {
        &self.path_list[index]
    }

    /// Get the first vertex in the path.
    pub fn first(&self) -> Option<&V> {
        self.path_list.first()
    }

    /// Get the last vertex in the path.
    pub fn last(&self) -> Option<&V> {
        self.path_list.last()
    }

    /// Return all vertices in the path as a slice.
    pub fn as_slice(&self) -> &[V] {
        &self.path_list
    }

    /// Return the ordered list of vertices.
    pub fn vertices(&self) -> &[V] {
        &self.path_list
    }

    /// Return all predecessors of the vertex in this path (vertices before and
    /// including `v`).
    pub fn get_predecessors(&self, v: &V) -> HashSet<V> {
        if let Some(index) = self.path_list.iter().position(|x| x == v) {
            self.path_list[0..=index].iter().cloned().collect()
        } else {
            HashSet::new()
        }
    }

    /// Return all successors of the vertex in this path (vertices at and
    /// after `v`).
    pub fn get_successors(&self, v: &V) -> HashSet<V> {
        if let Some(index) = self.path_list.iter().position(|x| x == v) {
            self.path_list[index..].iter().cloned().collect()
        } else {
            HashSet::new()
        }
    }

    /// Return a sub-path from `start` (inclusive) to `end` (exclusive).
    pub fn sub_path(&self, start: usize, end: usize) -> GraphPath<V> {
        let sub_list: Vec<V> = self.path_list[start..end].to_vec();
        let sub_set: HashSet<V> = sub_list.iter().cloned().collect();
        GraphPath {
            path_list: sub_list,
            path_set: sub_set,
        }
    }
}

impl<V: Eq + Hash + Clone> Default for GraphPath<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V: Eq + Hash + Clone + fmt::Display> fmt::Display for GraphPath<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;
        for (i, v) in self.path_list.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", v)?;
        }
        write!(f, "]")
    }
}

// ============================================================================
// GraphPathSet  (port of GraphPathSet.java)
// ============================================================================

/// A collection of [`GraphPath`]s with utility methods.
///
/// Mirrors `ghidra.graph.GraphPathSet<V>`.
#[derive(Debug, Clone)]
pub struct GraphPathSet<V: Eq + Hash + Clone> {
    paths: HashSet<GraphPath<V>>,
}

impl<V: Eq + Hash + Clone> GraphPathSet<V> {
    /// Create an empty path set.
    pub fn new() -> Self {
        Self {
            paths: HashSet::new(),
        }
    }

    /// Check if any path in the set starts with the given path prefix.
    pub fn contain_some_path_starting_with(&self, other_path: &GraphPath<V>) -> bool {
        self.paths.iter().any(|p| p.starts_with(other_path))
    }

    /// Add a path to the set.
    pub fn add(&mut self, path: GraphPath<V>) {
        self.paths.insert(path);
    }

    /// Return all paths that contain the given vertex.
    pub fn get_paths_containing(&self, v: &V) -> HashSet<&GraphPath<V>> {
        self.paths.iter().filter(|p| p.contains(v)).collect()
    }

    /// Return the number of paths in the set.
    pub fn size(&self) -> usize {
        self.paths.len()
    }

    /// Check if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    /// Iterate over all paths.
    pub fn iter(&self) -> impl Iterator<Item = &GraphPath<V>> {
        self.paths.iter()
    }
}

impl<V: Eq + Hash + Clone> Default for GraphPathSet<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V: Eq + Hash + Clone> fmt::Display for GraphPathSet<V>
where
    V: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for path in &self.paths {
            writeln!(f, "{}", path)?;
        }
        Ok(())
    }
}

// GraphPath needs Hash and Eq for GraphPathSet
impl<V: Eq + Hash + Clone> PartialEq for GraphPath<V> {
    fn eq(&self, other: &Self) -> bool {
        self.path_list == other.path_list
    }
}

impl<V: Eq + Hash + Clone> Eq for GraphPath<V> {}

impl<V: Eq + Hash + Clone> Hash for GraphPath<V> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.path_list.hash(state);
    }
}
