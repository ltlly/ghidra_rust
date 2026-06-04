//! Sample graph data structures and visualization.
//!
//! Ported from the `ghidra.examples.graph` package in the sample extension.
//!
//! Provides example graph data structures demonstrating Ghidra's
//! graph visualization framework.

use std::collections::BTreeMap;

/// A vertex in a sample graph.
#[derive(Debug, Clone)]
pub struct SampleVertex {
    /// Vertex ID.
    pub id: u64,
    /// Display label.
    pub label: String,
    /// X position for layout.
    pub x: f64,
    /// Y position for layout.
    pub y: f64,
}

impl SampleVertex {
    /// Create a new vertex.
    pub fn new(id: u64, label: impl Into<String>) -> Self {
        Self {
            id,
            label: label.into(),
            x: 0.0,
            y: 0.0,
        }
    }

    /// Set the position.
    pub fn with_position(mut self, x: f64, y: f64) -> Self {
        self.x = x;
        self.y = y;
        self
    }
}

/// An edge in a sample graph.
#[derive(Debug, Clone)]
pub struct SampleEdge {
    /// Edge ID.
    pub id: u64,
    /// Source vertex ID.
    pub source: u64,
    /// Target vertex ID.
    pub target: u64,
    /// Display label.
    pub label: String,
}

impl SampleEdge {
    /// Create a new edge.
    pub fn new(id: u64, source: u64, target: u64, label: impl Into<String>) -> Self {
        Self {
            id,
            source,
            target,
            label: label.into(),
        }
    }
}

/// A sample graph for demonstrating graph visualization.
///
/// Contains vertices and edges, supporting basic graph operations
/// like BFS traversal and layout computation.
#[derive(Debug, Clone)]
pub struct SampleGraph {
    /// Vertices by ID.
    vertices: BTreeMap<u64, SampleVertex>,
    /// Edges by ID.
    edges: BTreeMap<u64, SampleEdge>,
    /// Adjacency list: vertex_id -> list of edge_ids.
    adjacency: BTreeMap<u64, Vec<u64>>,
    /// Next vertex ID.
    next_vertex_id: u64,
    /// Next edge ID.
    next_edge_id: u64,
}

impl SampleGraph {
    /// Create an empty graph.
    pub fn new() -> Self {
        Self {
            vertices: BTreeMap::new(),
            edges: BTreeMap::new(),
            adjacency: BTreeMap::new(),
            next_vertex_id: 0,
            next_edge_id: 0,
        }
    }

    /// Add a vertex and return its ID.
    pub fn add_vertex(&mut self, label: impl Into<String>) -> u64 {
        let id = self.next_vertex_id;
        self.next_vertex_id += 1;
        self.vertices.insert(id, SampleVertex::new(id, label));
        self.adjacency.insert(id, Vec::new());
        id
    }

    /// Add an edge and return its ID.
    pub fn add_edge(
        &mut self,
        source: u64,
        target: u64,
        label: impl Into<String>,
    ) -> Option<u64> {
        if !self.vertices.contains_key(&source) || !self.vertices.contains_key(&target) {
            return None;
        }
        let id = self.next_edge_id;
        self.next_edge_id += 1;
        self.edges
            .insert(id, SampleEdge::new(id, source, target, label));
        self.adjacency.entry(source).or_default().push(id);
        Some(id)
    }

    /// Get a vertex by ID.
    pub fn vertex(&self, id: u64) -> Option<&SampleVertex> {
        self.vertices.get(&id)
    }

    /// Get a mutable reference to a vertex.
    pub fn vertex_mut(&mut self, id: u64) -> Option<&mut SampleVertex> {
        self.vertices.get_mut(&id)
    }

    /// Get an edge by ID.
    pub fn edge(&self, id: u64) -> Option<&SampleEdge> {
        self.edges.get(&id)
    }

    /// Number of vertices.
    pub fn num_vertices(&self) -> usize {
        self.vertices.len()
    }

    /// Number of edges.
    pub fn num_edges(&self) -> usize {
        self.edges.len()
    }

    /// Get outgoing edge IDs for a vertex.
    pub fn outgoing_edges(&self, vertex_id: u64) -> &[u64] {
        self.adjacency
            .get(&vertex_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Breadth-first search from a start vertex.
    ///
    /// Returns the vertices in BFS order.
    pub fn bfs(&self, start: u64) -> Vec<u64> {
        let mut visited = std::collections::HashSet::new();
        let mut queue = std::collections::VecDeque::new();
        let mut result = Vec::new();

        if !self.vertices.contains_key(&start) {
            return result;
        }

        queue.push_back(start);
        visited.insert(start);

        while let Some(current) = queue.pop_front() {
            result.push(current);
            for &edge_id in self.outgoing_edges(current) {
                if let Some(edge) = self.edges.get(&edge_id) {
                    if visited.insert(edge.target) {
                        queue.push_back(edge.target);
                    }
                }
            }
        }

        result
    }

    /// Compute a simple grid layout for the graph.
    ///
    /// Places vertices in a grid pattern with the given spacing.
    pub fn compute_grid_layout(&mut self, spacing: f64) {
        let num = self.vertices.len();
        let cols = (num as f64).sqrt().ceil() as usize;
        for (i, vertex) in self.vertices.values_mut().enumerate() {
            let col = i % cols;
            let row = i / cols;
            vertex.x = col as f64 * spacing;
            vertex.y = row as f64 * spacing;
        }
    }

    /// Check if the graph is a DAG (no cycles).
    pub fn is_dag(&self) -> bool {
        // DFS-based cycle detection
        let mut visited = std::collections::HashSet::new();
        let mut in_stack = std::collections::HashSet::new();

        for &vertex_id in self.vertices.keys() {
            if !visited.contains(&vertex_id)
                && self.has_cycle_dfs(vertex_id, &mut visited, &mut in_stack)
            {
                return false;
            }
        }
        true
    }

    fn has_cycle_dfs(
        &self,
        node: u64,
        visited: &mut std::collections::HashSet<u64>,
        in_stack: &mut std::collections::HashSet<u64>,
    ) -> bool {
        visited.insert(node);
        in_stack.insert(node);

        for &edge_id in self.outgoing_edges(node) {
            if let Some(edge) = self.edges.get(&edge_id) {
                if in_stack.contains(&edge.target) {
                    return true;
                }
                if !visited.contains(&edge.target)
                    && self.has_cycle_dfs(edge.target, visited, in_stack)
                {
                    return true;
                }
            }
        }

        in_stack.remove(&node);
        false
    }
}

impl Default for SampleGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// A graph layout provider.
///
/// Computes positions for graph vertices using a layout algorithm.
#[derive(Debug)]
pub struct SampleGraphLayout {
    /// The spacing between vertices.
    pub spacing: f64,
}

impl SampleGraphLayout {
    /// Create a new layout provider with the given spacing.
    pub fn new(spacing: f64) -> Self {
        Self { spacing }
    }

    /// Apply a grid layout to the graph.
    pub fn apply_grid_layout(&self, graph: &mut SampleGraph) {
        graph.compute_grid_layout(self.spacing);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_add_vertex() {
        let mut graph = SampleGraph::new();
        let id = graph.add_vertex("A");
        assert_eq!(graph.num_vertices(), 1);
        assert_eq!(graph.vertex(id).unwrap().label, "A");
    }

    #[test]
    fn test_graph_add_edge() {
        let mut graph = SampleGraph::new();
        let a = graph.add_vertex("A");
        let b = graph.add_vertex("B");
        let e = graph.add_edge(a, b, "AB").unwrap();
        assert_eq!(graph.num_edges(), 1);
        assert_eq!(graph.edge(e).unwrap().label, "AB");
    }

    #[test]
    fn test_graph_add_edge_invalid() {
        let mut graph = SampleGraph::new();
        assert!(graph.add_edge(0, 1, "AB").is_none());
    }

    #[test]
    fn test_graph_bfs() {
        let mut graph = SampleGraph::new();
        let a = graph.add_vertex("A");
        let b = graph.add_vertex("B");
        let c = graph.add_vertex("C");
        graph.add_edge(a, b, "").unwrap();
        graph.add_edge(a, c, "").unwrap();

        let order = graph.bfs(a);
        assert_eq!(order.len(), 3);
        assert_eq!(order[0], a);
    }

    #[test]
    fn test_graph_grid_layout() {
        let mut graph = SampleGraph::new();
        graph.add_vertex("A");
        graph.add_vertex("B");
        graph.add_vertex("C");
        graph.add_vertex("D");

        graph.compute_grid_layout(100.0);
        // Should have 2x2 grid - all vertices should be at multiples of 100
        for i in 0..4 {
            let v = graph.vertex(i).unwrap();
            assert!(v.x % 100.0 < 0.001, "vertex {} x={} not on grid", i, v.x);
            assert!(v.y % 100.0 < 0.001, "vertex {} y={} not on grid", i, v.y);
        }
    }

    #[test]
    fn test_graph_is_dag() {
        let mut graph = SampleGraph::new();
        let a = graph.add_vertex("A");
        let b = graph.add_vertex("B");
        let c = graph.add_vertex("C");
        graph.add_edge(a, b, "").unwrap();
        graph.add_edge(b, c, "").unwrap();
        assert!(graph.is_dag());

        // Add cycle
        graph.add_edge(c, a, "").unwrap();
        assert!(!graph.is_dag());
    }

    #[test]
    fn test_graph_outgoing_edges() {
        let mut graph = SampleGraph::new();
        let a = graph.add_vertex("A");
        let b = graph.add_vertex("B");
        let c = graph.add_vertex("C");
        graph.add_edge(a, b, "").unwrap();
        graph.add_edge(a, c, "").unwrap();

        assert_eq!(graph.outgoing_edges(a).len(), 2);
        assert!(graph.outgoing_edges(b).is_empty());
    }

    #[test]
    fn test_vertex_with_position() {
        let v = SampleVertex::new(0, "test").with_position(10.0, 20.0);
        assert!((v.x - 10.0).abs() < 0.001);
        assert!((v.y - 20.0).abs() < 0.001);
    }

    #[test]
    fn test_sample_graph_layout() {
        let layout = SampleGraphLayout::new(50.0);
        let mut graph = SampleGraph::new();
        graph.add_vertex("A");
        graph.add_vertex("B");
        layout.apply_grid_layout(&mut graph);
        let v0 = graph.vertex(0).unwrap();
        assert!((v0.x - 0.0).abs() < 0.001);
    }
}
