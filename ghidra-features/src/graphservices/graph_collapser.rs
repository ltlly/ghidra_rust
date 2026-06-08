//! Graph collapser for grouping and ungrouping vertices.
//!
//! Ported from Ghidra's `ghidra.graph.visualization.GhidraGraphCollapser`
//! Java class.
//!
//! Provides the logic for collapsing selected vertices into a single
//! `GroupVertex`, and expanding them back. Manages the mapping between
//! the original graph and a view with collapsed groups.

use std::collections::{HashMap, HashSet};

use super::attributed::{Attributed, AttributedGraph, AttributedVertex};
use super::group_vertex::GroupVertex;

/// Manages graph node collapsing and expanding.
///
/// The collapser maintains a mapping between a "real" graph (with all
/// original vertices) and a "view" graph (with collapsed groups). It
/// tracks which vertices are grouped and handles the bookkeeping of
/// rewiring edges when groups are formed or dissolved.
#[derive(Debug, Clone)]
pub struct GraphCollapser {
    /// The original (full) graph.
    graph: AttributedGraph,
    /// Map from group vertex id to its GroupVertex.
    groups: HashMap<String, GroupVertex>,
    /// Map from child vertex id to its containing group id.
    child_to_group: HashMap<String, String>,
}

impl GraphCollapser {
    /// Create a new collapser for the given graph.
    pub fn new(graph: AttributedGraph) -> Self {
        Self {
            graph,
            groups: HashMap::new(),
            child_to_group: HashMap::new(),
        }
    }

    /// Get a reference to the underlying graph.
    pub fn graph(&self) -> &AttributedGraph {
        &self.graph
    }

    /// Get a mutable reference to the underlying graph.
    pub fn graph_mut(&mut self) -> &mut AttributedGraph {
        &mut self.graph
    }

    /// Collapse a set of vertices into a single GroupVertex.
    ///
    /// Returns the id of the new group vertex, or `None` if fewer than
    /// 2 vertices are provided.
    ///
    /// All edges between the collapsed vertices become internal to the
    /// group. External edges are rewired to/from the group vertex.
    pub fn collapse(&mut self, vertex_ids: &HashSet<&str>) -> Option<String> {
        let group = GroupVertex::group_vertices(&self.graph, vertex_ids)?;
        let group_id = group.id().to_string();

        // Register children -> group mapping
        for child_id in group.children() {
            self.child_to_group
                .insert(child_id.clone(), group_id.clone());
        }

        self.groups.insert(group_id.clone(), group);
        Some(group_id)
    }

    /// Expand a group vertex back into its contained vertices.
    ///
    /// Returns the set of vertex ids that were in the group, or `None`
    /// if the id does not refer to a group.
    pub fn expand(&mut self, group_id: &str) -> Option<HashSet<String>> {
        let group = self.groups.remove(group_id)?;
        let children = group.children().clone();

        // Remove child -> group mapping
        for child_id in &children {
            self.child_to_group.remove(child_id);
        }

        Some(children)
    }

    /// Get the outermost group containing a vertex.
    ///
    /// If the vertex is directly in a group, returns that group's id.
    /// If it is in a group that is itself in another group, returns the
    /// outermost group's id. If the vertex is not in any group, returns
    /// the vertex id itself.
    pub fn get_outermost_group(&self, vertex_id: &str) -> String {
        let mut current = vertex_id.to_string();
        while let Some(group_id) = self.child_to_group.get(&current) {
            if group_id == &current {
                break; // prevent infinite loop
            }
            current = group_id.clone();
        }
        current
    }

    /// Convert a set of vertex ids to their outermost containing group ids.
    ///
    /// Any vertex that is part of a group (directly or transitively) is
    /// replaced with its outermost group's id.
    pub fn to_outermost_vertices(&self, vertex_ids: &HashSet<&str>) -> HashSet<String> {
        vertex_ids
            .iter()
            .map(|id| self.get_outermost_group(id))
            .collect()
    }

    /// Check if a vertex id refers to a group vertex.
    pub fn is_group(&self, vertex_id: &str) -> bool {
        self.groups.contains_key(vertex_id)
    }

    /// Get a reference to a group vertex by id.
    pub fn get_group(&self, group_id: &str) -> Option<&GroupVertex> {
        self.groups.get(group_id)
    }

    /// Get all group vertex ids.
    pub fn group_ids(&self) -> impl Iterator<Item = &str> {
        self.groups.keys().map(|s| s.as_str())
    }

    /// The number of active groups.
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Get the containing group id for a vertex, if any.
    pub fn containing_group(&self, vertex_id: &str) -> Option<&str> {
        self.child_to_group.get(vertex_id).map(|s| s.as_str())
    }

    /// Get the ids of all vertices that are not contained in any group.
    ///
    /// This includes both regular vertices and group vertices.
    pub fn visible_vertices(&self) -> HashSet<String> {
        let mut visible = HashSet::new();
        for id in self.graph.vertex_ids() {
            if !self.child_to_group.contains_key(id) {
                visible.insert(id.to_string());
            }
        }
        // Add group vertices
        for group_id in self.groups.keys() {
            visible.insert(group_id.clone());
        }
        visible
    }

    /// Expand all groups, restoring the graph to its original state.
    pub fn expand_all(&mut self) {
        let group_ids: Vec<String> = self.groups.keys().cloned().collect();
        for gid in group_ids {
            self.expand(&gid);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graphservices::attributed::AttributedGraph;

    fn diamond_graph() -> AttributedGraph {
        let mut g = AttributedGraph::new("test", "cfg");
        g.add_vertex(AttributedVertex::new("A", "Entry"));
        g.add_vertex(AttributedVertex::new("B", "Left"));
        g.add_vertex(AttributedVertex::new("C", "Right"));
        g.add_vertex(AttributedVertex::new("D", "Merge"));
        g.add_edge("A", "B", Some("true_branch".to_string()));
        g.add_edge("A", "C", Some("false_branch".to_string()));
        g.add_edge("B", "D", Some("fallthrough".to_string()));
        g.add_edge("C", "D", Some("fallthrough".to_string()));
        g
    }

    #[test]
    fn test_collapse_creates_group() {
        let g = diamond_graph();
        let mut collapser = GraphCollapser::new(g);

        let ids: HashSet<&str> = vec!["B", "C"].into_iter().collect();
        let group_id = collapser.collapse(&ids).unwrap();

        assert!(collapser.is_group(&group_id));
        assert_eq!(collapser.group_count(), 1);
    }

    #[test]
    fn test_collapse_too_few_returns_none() {
        let g = diamond_graph();
        let mut collapser = GraphCollapser::new(g);

        let ids: HashSet<&str> = vec!["A"].into_iter().collect();
        assert!(collapser.collapse(&ids).is_none());
    }

    #[test]
    fn test_expand_restores_children() {
        let g = diamond_graph();
        let mut collapser = GraphCollapser::new(g);

        let ids: HashSet<&str> = vec!["B", "C"].into_iter().collect();
        let group_id = collapser.collapse(&ids).unwrap();

        let children = collapser.expand(&group_id).unwrap();
        assert_eq!(children.len(), 2);
        assert!(children.contains("B"));
        assert!(children.contains("C"));
        assert_eq!(collapser.group_count(), 0);
    }

    #[test]
    fn test_containing_group() {
        let g = diamond_graph();
        let mut collapser = GraphCollapser::new(g);

        let ids: HashSet<&str> = vec!["B", "C"].into_iter().collect();
        let group_id = collapser.collapse(&ids).unwrap();

        assert_eq!(collapser.containing_group("B"), Some(group_id.as_str()));
        assert_eq!(collapser.containing_group("A"), None);
    }

    #[test]
    fn test_outermost_group_direct() {
        let g = diamond_graph();
        let mut collapser = GraphCollapser::new(g);

        let ids: HashSet<&str> = vec!["B", "C"].into_iter().collect();
        collapser.collapse(&ids);

        let outer = collapser.get_outermost_group("B");
        assert!(collapser.is_group(&outer));
        // A is not in any group
        assert_eq!(collapser.get_outermost_group("A"), "A");
    }

    #[test]
    fn test_to_outermost_vertices() {
        let g = diamond_graph();
        let mut collapser = GraphCollapser::new(g);

        let ids: HashSet<&str> = vec!["B", "C"].into_iter().collect();
        collapser.collapse(&ids);

        let query: HashSet<&str> = vec!["B", "A"].into_iter().collect();
        let outer = collapser.to_outermost_vertices(&query);
        assert_eq!(outer.len(), 2); // group + A
        assert!(outer.contains("A"));
    }

    #[test]
    fn test_visible_vertices() {
        let g = diamond_graph();
        let mut collapser = GraphCollapser::new(g);

        let ids: HashSet<&str> = vec!["B", "C"].into_iter().collect();
        collapser.collapse(&ids);

        let visible = collapser.visible_vertices();
        // Should see A, D, and the group -- not B, C directly
        assert!(visible.contains("A"));
        assert!(visible.contains("D"));
        assert!(!visible.contains("B"));
        assert!(!visible.contains("C"));
        assert_eq!(visible.len(), 3); // A, D, group
    }

    #[test]
    fn test_expand_all() {
        let g = diamond_graph();
        let mut collapser = GraphCollapser::new(g);

        collapser.collapse(&vec!["B", "C"].into_iter().collect());
        collapser.expand_all();

        assert_eq!(collapser.group_count(), 0);
        let visible = collapser.visible_vertices();
        assert_eq!(visible.len(), 4); // A, B, C, D all visible
    }

    #[test]
    fn test_get_group() {
        let g = diamond_graph();
        let mut collapser = GraphCollapser::new(g);

        let ids: HashSet<&str> = vec!["B", "C"].into_iter().collect();
        let group_id = collapser.collapse(&ids).unwrap();

        let group = collapser.get_group(&group_id).unwrap();
        assert_eq!(group.len(), 2);
        assert!(group.contains("B"));
        assert!(group.contains("C"));
    }
}
