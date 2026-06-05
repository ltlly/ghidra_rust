//! Grouping visual graph: supports collapsing multiple vertices into groups.
//!
//! Ports `ghidra.graph.GroupingVisualGraph` from Ghidra's Java graph framework.
//! Allows vertices to be grouped together and displayed as a single "super-vertex",
//! reducing visual complexity in large graphs.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use super::{GDirectedGraph, GEdge};

/// Identifier for a vertex group.
pub type GroupId = u64;

/// A group of vertices that are collapsed into a single visual node.
#[derive(Debug, Clone)]
pub struct VertexGroup<V: Eq + Hash + Clone> {
    /// Unique identifier for this group.
    pub id: GroupId,
    /// Label displayed when the group is collapsed.
    pub label: String,
    /// Vertices contained in this group.
    pub members: HashSet<V>,
    /// Whether the group is currently expanded (showing individual vertices).
    pub expanded: bool,
}

impl<V: Eq + Hash + Clone> VertexGroup<V> {
    /// Create a new vertex group.
    pub fn new(id: GroupId, label: impl Into<String>) -> Self {
        Self {
            id,
            label: label.into(),
            members: HashSet::new(),
            expanded: false,
        }
    }

    /// Add a vertex to this group.
    pub fn add_member(&mut self, v: V) {
        self.members.insert(v);
    }

    /// Remove a vertex from this group.
    pub fn remove_member(&mut self, v: &V) {
        self.members.remove(v);
    }

    /// Number of members in this group.
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Whether this group contains the given vertex.
    pub fn contains(&self, v: &V) -> bool {
        self.members.contains(v)
    }

    /// Toggle the expanded/collapsed state.
    pub fn toggle(&mut self) {
        self.expanded = !self.expanded;
    }

    /// Expand this group.
    pub fn expand(&mut self) {
        self.expanded = true;
    }

    /// Collapse this group.
    pub fn collapse(&mut self) {
        self.expanded = false;
    }
}

/// A graph wrapper that supports grouping (collapsing) vertices.
///
/// When a group is collapsed, its members are replaced by a single synthetic
/// vertex (the group id as a `String`).  Edges between group members become
/// self-loops on the group; edges from group members to outside vertices become
/// edges from the group to those vertices.
///
/// Ports Ghidra's `GroupingVisualGraph<V, E>`.
#[derive(Debug, Clone)]
pub struct GroupingGraph<V, E>
where
    V: Eq + Hash + Clone + std::fmt::Debug,
    E: GEdge<V> + Clone,
{
    /// The underlying graph.
    inner: super::DefaultDirectedGraph<V, E>,
    /// Vertex groups, indexed by group id.
    groups: HashMap<GroupId, VertexGroup<V>>,
    /// Mapping from vertex to the group it belongs to.
    vertex_to_group: HashMap<V, GroupId>,
    /// Next group id.
    next_group_id: GroupId,
}

impl<V, E> GroupingGraph<V, E>
where
    V: Eq + Hash + Clone + std::fmt::Debug,
    E: GEdge<V> + Clone,
{
    /// Create a new grouping graph wrapping the given graph.
    pub fn new(inner: super::DefaultDirectedGraph<V, E>) -> Self {
        Self {
            inner,
            groups: HashMap::new(),
            vertex_to_group: HashMap::new(),
            next_group_id: 1,
        }
    }

    /// Create an empty grouping graph.
    pub fn empty() -> Self {
        Self::new(super::DefaultDirectedGraph::new())
    }

    /// Create a new group with the given label and return its id.
    pub fn create_group(&mut self, label: impl Into<String>) -> GroupId {
        let id = self.next_group_id;
        self.next_group_id += 1;
        self.groups.insert(id, VertexGroup::new(id, label));
        id
    }

    /// Add a vertex to a group.
    pub fn add_to_group(&mut self, group_id: GroupId, v: V) -> bool {
        if let Some(group) = self.groups.get_mut(&group_id) {
            group.add_member(v.clone());
            self.vertex_to_group.insert(v, group_id);
            true
        } else {
            false
        }
    }

    /// Remove a vertex from its group.
    pub fn remove_from_group(&mut self, v: &V) {
        if let Some(group_id) = self.vertex_to_group.remove(v) {
            if let Some(group) = self.groups.get_mut(&group_id) {
                group.remove_member(v);
            }
        }
    }

    /// Get the group a vertex belongs to, if any.
    pub fn group_of(&self, v: &V) -> Option<&VertexGroup<V>> {
        self.vertex_to_group
            .get(v)
            .and_then(|gid| self.groups.get(gid))
    }

    /// Get a group by id.
    pub fn get_group(&self, id: GroupId) -> Option<&VertexGroup<V>> {
        self.groups.get(&id)
    }

    /// Get a mutable reference to a group by id.
    pub fn get_group_mut(&mut self, id: GroupId) -> Option<&mut VertexGroup<V>> {
        self.groups.get_mut(&id)
    }

    /// Collapse a group (hide individual members, show group node).
    pub fn collapse_group(&mut self, group_id: GroupId) {
        if let Some(group) = self.groups.get_mut(&group_id) {
            group.collapse();
        }
    }

    /// Expand a group (show individual members).
    pub fn expand_group(&mut self, group_id: GroupId) {
        if let Some(group) = self.groups.get_mut(&group_id) {
            group.expand();
        }
    }

    /// Remove a group entirely (members become ungrouped).
    pub fn remove_group(&mut self, group_id: GroupId) {
        if let Some(group) = self.groups.remove(&group_id) {
            for v in &group.members {
                self.vertex_to_group.remove(v);
            }
        }
    }

    /// All group ids.
    pub fn group_ids(&self) -> Vec<GroupId> {
        self.groups.keys().copied().collect()
    }

    /// Number of groups.
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Whether a group is currently expanded.
    pub fn is_group_expanded(&self, group_id: GroupId) -> bool {
        self.groups
            .get(&group_id)
            .map(|g| g.expanded)
            .unwrap_or(false)
    }

    /// Get all collapsed groups.
    pub fn collapsed_groups(&self) -> Vec<&VertexGroup<V>> {
        self.groups.values().filter(|g| !g.expanded).collect()
    }

    /// Get all expanded groups.
    pub fn expanded_groups(&self) -> Vec<&VertexGroup<V>> {
        self.groups.values().filter(|g| g.expanded).collect()
    }

    /// Get the underlying graph.
    pub fn inner(&self) -> &super::DefaultDirectedGraph<V, E> {
        &self.inner
    }

    /// Get a mutable reference to the underlying graph.
    pub fn inner_mut(&mut self) -> &mut super::DefaultDirectedGraph<V, E> {
        &mut self.inner
    }

    /// Compute the set of vertices that should be visible given the current
    /// group states.  Expanded groups show their members; collapsed groups
    /// show a synthetic "group" vertex.
    pub fn compute_visible_vertices(&self) -> HashSet<V>
    where
        V: std::fmt::Display,
    {
        let all_vertices: HashSet<V> = self.inner.vertices().into_iter().collect();
        let mut hidden = HashSet::new();

        for group in self.groups.values() {
            if !group.expanded {
                // Collapsed: hide all members
                for v in &group.members {
                    hidden.insert(v.clone());
                }
            }
        }

        all_vertices
            .into_iter()
            .filter(|v| !hidden.contains(v))
            .collect()
    }

    /// Get inter-group edges: edges that cross group boundaries.
    /// Returns (from_group_id, to_group_id, edge_count).
    pub fn inter_group_edges(&self) -> Vec<(GroupId, GroupId, usize)> {
        let mut counts: HashMap<(GroupId, GroupId), usize> = HashMap::new();

        for e in self.inner.edges() {
            let from_group = self.vertex_to_group.get(e.start());
            let to_group = self.vertex_to_group.get(e.end());
            if let (Some(&fg), Some(&tg)) = (from_group, to_group) {
                if fg != tg {
                    *counts.entry((fg, tg)).or_insert(0) += 1;
                }
            }
        }

        counts.into_iter().map(|((f, t), c)| (f, t, c)).collect()
    }

    /// Get intra-group edges: edges where both endpoints are in the same group.
    pub fn intra_group_edges(&self) -> Vec<(GroupId, usize)> {
        let mut counts: HashMap<GroupId, usize> = HashMap::new();

        for e in self.inner.edges() {
            let from_group = self.vertex_to_group.get(e.start());
            let to_group = self.vertex_to_group.get(e.end());
            if let (Some(&fg), Some(&tg)) = (from_group, to_group) {
                if fg == tg {
                    *counts.entry(fg).or_insert(0) += 1;
                }
            }
        }

        counts.into_iter().collect()
    }
}

impl<V, E> Default for GroupingGraph<V, E>
where
    V: Eq + Hash + Clone + std::fmt::Debug,
    E: GEdge<V> + Clone,
{
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::DefaultGEdge;

    type E = DefaultGEdge<i32>;
    type G = super::super::DefaultDirectedGraph<i32, E>;
    type GG = GroupingGraph<i32, E>;

    fn make_graph() -> G {
        let mut g = G::new();
        g.add_edge(E::new(1, 2));
        g.add_edge(E::new(2, 3));
        g.add_edge(E::new(3, 4));
        g.add_edge(E::new(4, 5));
        g
    }

    #[test]
    fn create_group_and_add_members() {
        let mut gg = GG::new(make_graph());
        let gid = gg.create_group("cluster A");
        assert!(gg.add_to_group(gid, 1));
        assert!(gg.add_to_group(gid, 2));
        assert_eq!(gg.get_group(gid).unwrap().member_count(), 2);
    }

    #[test]
    fn group_of_returns_correct_group() {
        let mut gg = GG::new(make_graph());
        let gid = gg.create_group("g1");
        gg.add_to_group(gid, 1);
        let group = gg.group_of(&1).unwrap();
        assert_eq!(group.id, gid);
        assert_eq!(group.label, "g1");
    }

    #[test]
    fn group_of_returns_none_for_ungrouped() {
        let gg = GG::new(make_graph());
        assert!(gg.group_of(&1).is_none());
    }

    #[test]
    fn remove_from_group() {
        let mut gg = GG::new(make_graph());
        let gid = gg.create_group("g1");
        gg.add_to_group(gid, 1);
        assert!(gg.group_of(&1).is_some());
        gg.remove_from_group(&1);
        assert!(gg.group_of(&1).is_none());
    }

    #[test]
    fn collapse_and_expand_group() {
        let mut gg = GG::new(make_graph());
        let gid = gg.create_group("g1");
        gg.add_to_group(gid, 1);
        gg.add_to_group(gid, 2);

        gg.collapse_group(gid);
        assert!(!gg.is_group_expanded(gid));
        assert_eq!(gg.collapsed_groups().len(), 1);
        assert_eq!(gg.expanded_groups().len(), 0);

        gg.expand_group(gid);
        assert!(gg.is_group_expanded(gid));
        assert_eq!(gg.collapsed_groups().len(), 0);
        assert_eq!(gg.expanded_groups().len(), 1);
    }

    #[test]
    fn toggle_group() {
        let mut gg = GG::new(make_graph());
        let gid = gg.create_group("g1");
        assert!(!gg.is_group_expanded(gid));
        gg.get_group_mut(gid).unwrap().toggle();
        assert!(gg.is_group_expanded(gid));
        gg.get_group_mut(gid).unwrap().toggle();
        assert!(!gg.is_group_expanded(gid));
    }

    #[test]
    fn remove_group_unassigns_members() {
        let mut gg = GG::new(make_graph());
        let gid = gg.create_group("g1");
        gg.add_to_group(gid, 1);
        gg.add_to_group(gid, 2);
        assert_eq!(gg.group_count(), 1);

        gg.remove_group(gid);
        assert_eq!(gg.group_count(), 0);
        assert!(gg.group_of(&1).is_none());
        assert!(gg.group_of(&2).is_none());
    }

    #[test]
    fn inter_group_edges() {
        let mut gg = GG::new(make_graph());
        let g1 = gg.create_group("A");
        let g2 = gg.create_group("B");
        gg.add_to_group(g1, 1);
        gg.add_to_group(g1, 2);
        gg.add_to_group(g2, 3);
        gg.add_to_group(g2, 4);

        let inter = gg.inter_group_edges();
        // Edge 2->3 goes from group A to group B
        assert!(!inter.is_empty());
        let has_ab = inter.iter().any(|&(f, t, c)| f == g1 && t == g2 && c >= 1);
        assert!(has_ab, "should have A->B inter-group edge");
    }

    #[test]
    fn intra_group_edges() {
        let mut gg = GG::new(make_graph());
        let g1 = gg.create_group("A");
        gg.add_to_group(g1, 1);
        gg.add_to_group(g1, 2);
        // Edge 1->2 is intra-group
        let intra = gg.intra_group_edges();
        assert!(intra.iter().any(|&(gid, c)| gid == g1 && c >= 1));
    }

    #[test]
    fn multiple_groups() {
        let mut gg = GG::new(make_graph());
        let g1 = gg.create_group("A");
        let g2 = gg.create_group("B");
        gg.add_to_group(g1, 1);
        gg.add_to_group(g2, 3);
        assert_eq!(gg.group_count(), 2);
        assert_eq!(gg.group_ids().len(), 2);
    }

    #[test]
    fn add_to_nonexistent_group_fails() {
        let mut gg = GG::new(make_graph());
        assert!(!gg.add_to_group(999, 1));
    }

    #[test]
    fn inner_graph_unaffected() {
        let mut gg = GG::new(make_graph());
        let gid = gg.create_group("A");
        gg.add_to_group(gid, 1);
        gg.add_to_group(gid, 2);
        gg.collapse_group(gid);
        assert_eq!(gg.inner().vertex_count(), 5);
        assert_eq!(gg.inner().edge_count(), 4);
    }

    #[test]
    fn default_is_empty() {
        let gg = GG::default();
        assert_eq!(gg.group_count(), 0);
        assert_eq!(gg.inner().vertex_count(), 0);
    }
}
