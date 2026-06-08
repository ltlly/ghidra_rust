//! GroupVertex: collapsed node grouping for graph visualization.
//!
//! Ported from Ghidra's `ghidra.graph.visualization.GroupVertex` Java class.
//!
//! A `GroupVertex` represents a set of vertices that have been collapsed
//! into a single visual node. It is used to simplify large graphs by
//! grouping related vertices.

use std::collections::HashSet;

use super::attributed::{Attributed, AttributedGraph, AttributedVertex, AttributeMap};

/// Maximum number of vertex names shown in the group label.
const MAX_IDS_TO_COMBINE: usize = 6;

/// A vertex that represents a collapsed group of vertices.
///
/// When multiple vertices are grouped, a `GroupVertex` is created that
/// contains references to all the original vertices. The group vertex
/// gets a composite id showing the names of contained vertices.
#[derive(Debug, Clone)]
pub struct GroupVertex {
    /// The underlying attributed vertex (id is the composite label).
    vertex: AttributedVertex,
    /// The set of non-group vertices contained in this group.
    children: HashSet<String>, // vertex ids
    /// The vertex id that is "first" (alphabetically sorted).
    first_vertex_id: String,
}

impl GroupVertex {
    /// Create a new GroupVertex from a collection of vertex ids.
    ///
    /// The vertex names are looked up from the provided graph. If a
    /// vertex id in `vertices` refers to another GroupVertex, its
    /// children are included recursively (flattening).
    ///
    /// Returns `None` if fewer than 2 vertices are provided or if no
    /// valid vertices are found.
    pub fn group_vertices(
        graph: &AttributedGraph,
        vertex_ids: &HashSet<&str>,
    ) -> Option<Self> {
        // Flatten: expand any GroupVertex ids to their children
        let flat_ids = Self::flatten_ids(graph, vertex_ids);
        if flat_ids.len() < 2 {
            return None;
        }

        // Sort for deterministic ordering
        let mut sorted_ids: Vec<&str> = flat_ids.iter().copied().collect();
        sorted_ids.sort();

        // Build composite label from vertex names
        let id = Self::get_unique_id(graph, &sorted_ids);
        let first_id = sorted_ids[0].to_string();

        let mut vertex = AttributedVertex::new(&id, &id);
        vertex.set("VertexType", "Collapsed Group");

        Some(Self {
            vertex,
            children: flat_ids.into_iter().map(|s| s.to_string()).collect(),
            first_vertex_id: first_id,
        })
    }

    /// Flatten a set of vertex ids, expanding any group vertices to their
    /// children.
    ///
    /// If a vertex id refers to a vertex with `VertexType == "Collapsed Group"`,
    /// its children are included instead. Returns the set of non-group vertex ids.
    pub fn flatten_ids<'a>(
        graph: &'a AttributedGraph,
        vertex_ids: &HashSet<&'a str>,
    ) -> HashSet<&'a str> {
        let mut result = HashSet::new();
        for &id in vertex_ids {
            if let Some(v) = graph.vertex(id) {
                if v.get("VertexType") == Some("Collapsed Group") {
                    // This is a group vertex; recurse into its children attribute
                    if let Some(children_str) = v.get("children") {
                        for child_id in children_str.split(',') {
                            let child_id = child_id.trim();
                            if !child_id.is_empty() {
                                result.insert(child_id);
                            }
                        }
                    }
                } else {
                    result.insert(id);
                }
            }
        }
        result
    }

    /// The underlying attributed vertex for this group.
    pub fn vertex(&self) -> &AttributedVertex {
        &self.vertex
    }

    /// The id of this group vertex.
    pub fn id(&self) -> &str {
        self.vertex.id()
    }

    /// The set of non-group vertex ids contained in this group.
    pub fn children(&self) -> &HashSet<String> {
        &self.children
    }

    /// The id of the first (alphabetically) vertex in the group.
    pub fn first_vertex_id(&self) -> &str {
        &self.first_vertex_id
    }

    /// Whether this group contains the given vertex id.
    pub fn contains(&self, vertex_id: &str) -> bool {
        self.children.contains(vertex_id)
    }

    /// Number of vertices in this group.
    pub fn len(&self) -> usize {
        self.children.len()
    }

    /// Whether this group is empty.
    pub fn is_empty(&self) -> bool {
        self.children.is_empty()
    }

    /// Build a unique display id from a sorted list of vertex names.
    fn get_unique_id(graph: &AttributedGraph, sorted_ids: &[&str]) -> String {
        let names: Vec<String> = sorted_ids
            .iter()
            .map(|id| {
                graph
                    .vertex(id)
                    .map(|v| v.name().to_string())
                    .unwrap_or_else(|| id.to_string())
            })
            .collect();

        if names.len() > MAX_IDS_TO_COMBINE {
            let shown = names[..MAX_IDS_TO_COMBINE].join("\n");
            let remaining = names.len() - MAX_IDS_TO_COMBINE;
            format!("{}\n...\n + {} Others", shown, remaining)
        } else {
            names.join("\n")
        }
    }
}

impl Attributed for GroupVertex {
    fn attributes(&self) -> &AttributeMap {
        self.vertex.attributes()
    }

    fn attributes_mut(&mut self) -> &mut AttributeMap {
        self.vertex.attributes_mut()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graphservices::attributed::AttributedGraph;

    fn make_graph_with_vertices(ids: &[&str]) -> AttributedGraph {
        let mut g = AttributedGraph::new("test", "cfg");
        for id in ids {
            g.add_vertex(AttributedVertex::new(*id, format!("Vertex_{}", id)));
        }
        g
    }

    #[test]
    fn test_group_two_vertices() {
        let g = make_graph_with_vertices(&["A", "B", "C"]);
        let ids: HashSet<&str> = vec!["A", "B"].into_iter().collect();
        let group = GroupVertex::group_vertices(&g, &ids).unwrap();

        assert_eq!(group.len(), 2);
        assert!(group.contains("A"));
        assert!(group.contains("B"));
        assert!(!group.contains("C"));
    }

    #[test]
    fn test_group_single_vertex_returns_none() {
        let g = make_graph_with_vertices(&["A"]);
        let ids: HashSet<&str> = vec!["A"].into_iter().collect();
        assert!(GroupVertex::group_vertices(&g, &ids).is_none());
    }

    #[test]
    fn test_group_label_combines_names() {
        let g = make_graph_with_vertices(&["alpha", "beta", "gamma"]);
        let ids: HashSet<&str> = vec!["alpha", "beta", "gamma"].into_iter().collect();
        let group = GroupVertex::group_vertices(&g, &ids).unwrap();

        let label = group.vertex().name();
        assert!(label.contains("Vertex_alpha"));
        assert!(label.contains("Vertex_beta"));
        assert!(label.contains("Vertex_gamma"));
    }

    #[test]
    fn test_group_label_truncates_many() {
        let ids: Vec<String> = (0..10).map(|i| format!("v{}", i)).collect();
        let str_ids: Vec<&str> = ids.iter().map(|s| s.as_str()).collect();
        let g = make_graph_with_vertices(&str_ids);

        let set: HashSet<&str> = str_ids.into_iter().collect();
        let group = GroupVertex::group_vertices(&g, &set).unwrap();

        let label = group.vertex().name();
        assert!(label.contains("..."));
        assert!(label.contains("+ 4 Others"));
    }

    #[test]
    fn test_group_vertex_type_is_set() {
        let g = make_graph_with_vertices(&["A", "B"]);
        let ids: HashSet<&str> = vec!["A", "B"].into_iter().collect();
        let group = GroupVertex::group_vertices(&g, &ids).unwrap();

        assert_eq!(
            group.vertex().get("VertexType"),
            Some("Collapsed Group")
        );
    }

    #[test]
    fn test_group_first_vertex_is_alphabetically_first() {
        let g = make_graph_with_vertices(&["Z", "A", "M"]);
        let ids: HashSet<&str> = vec!["Z", "A", "M"].into_iter().collect();
        let group = GroupVertex::group_vertices(&g, &ids).unwrap();

        assert_eq!(group.first_vertex_id(), "A");
    }

    #[test]
    fn test_group_contains_and_len() {
        let g = make_graph_with_vertices(&["X", "Y", "Z"]);
        let ids: HashSet<&str> = vec!["X", "Y"].into_iter().collect();
        let group = GroupVertex::group_vertices(&g, &ids).unwrap();

        assert_eq!(group.len(), 2);
        assert!(!group.is_empty());
        assert!(group.contains("X"));
        assert!(!group.contains("Z"));
    }

    #[test]
    fn test_flatten_ids_non_group() {
        let g = make_graph_with_vertices(&["A", "B"]);
        let ids: HashSet<&str> = vec!["A", "B"].into_iter().collect();
        let flat = GroupVertex::flatten_ids(&g, &ids);
        assert_eq!(flat.len(), 2);
        assert!(flat.contains("A"));
        assert!(flat.contains("B"));
    }

    #[test]
    fn test_flatten_ids_expands_group() {
        let mut g = make_graph_with_vertices(&["A", "B", "C"]);
        // Create a group vertex manually
        let mut group_v = AttributedVertex::new("group_1", "Group");
        group_v.set("VertexType", "Collapsed Group");
        group_v.set("children", "A,B");
        g.add_vertex(group_v);

        let ids: HashSet<&str> = vec!["group_1", "C"].into_iter().collect();
        let flat = GroupVertex::flatten_ids(&g, &ids);
        assert_eq!(flat.len(), 3);
        assert!(flat.contains("A"));
        assert!(flat.contains("B"));
        assert!(flat.contains("C"));
    }
}
