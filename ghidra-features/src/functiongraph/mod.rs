//! Function Graph module.
//!
//! Provides widget-level data structures for the function graph viewer,
//! graph layout algorithms (hierarchical, force-directed, circular, radial),
//! and edge routing.

use ghidra_core::addr::Address;
use ghidra_core::program::listing::Function;
use ghidra_decompile::pcode::PcodeOperation;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};
use std::f32::consts::PI;

// ---------------------------------------------------------------------------
// Types shared with GraphServices
// ---------------------------------------------------------------------------

/// The type of a control-flow edge between two vertices in the function graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CfgEdgeType {
    /// Normal fall-through to the next block.
    Fallthrough,
    /// Direct unconditional branch.
    Branch,
    /// Conditional branch (true path).
    TrueBranch,
    /// Conditional branch (false path).
    FalseBranch,
    /// Indirect branch (target unknown).
    IndirectBranch,
    /// Call edge (call returns to fall-through).
    Call,
    /// Return from function.
    Return,
}

impl std::fmt::Display for CfgEdgeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CfgEdgeType::Fallthrough => write!(f, "fallthrough"),
            CfgEdgeType::Branch => write!(f, "branch"),
            CfgEdgeType::TrueBranch => write!(f, "true_branch"),
            CfgEdgeType::FalseBranch => write!(f, "false_branch"),
            CfgEdgeType::IndirectBranch => write!(f, "indirect_branch"),
            CfgEdgeType::Call => write!(f, "call"),
            CfgEdgeType::Return => write!(f, "return"),
        }
    }
}

/// The layout algorithm used to position vertices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LayoutAlgorithm {
    /// Hierarchical (Sugiyama-style) layered layout.
    Hierarchical,
    /// Force-directed (spring-electric) layout.
    ForceDirected,
    /// Circular layout — vertices on a ring.
    Circular,
    /// Radial layout — concentric layers around a root.
    Radial,
}

/// The primary direction of flow in the graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LayoutDirection {
    /// Flow from top to bottom.
    TopToBottom,
    /// Flow from left to right.
    LeftToRight,
    /// Flow from bottom to top.
    BottomToTop,
    /// Flow from right to left.
    RightToLeft,
}

/// Configuration for a specific layout algorithm.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphLayout {
    /// The layout algorithm.
    pub algorithm: LayoutAlgorithm,
    /// The primary flow direction.
    pub direction: LayoutDirection,
    /// Spacing between layers (hierarchical) or between rings (radial).
    pub layer_spacing: f32,
    /// Minimum horizontal spacing between sibling vertices.
    pub node_spacing: f32,
    /// Maximum number of iterations for iterative algorithms (force-directed).
    pub max_iterations: usize,
}

impl Default for GraphLayout {
    fn default() -> Self {
        Self {
            algorithm: LayoutAlgorithm::Hierarchical,
            direction: LayoutDirection::TopToBottom,
            layer_spacing: 80.0,
            node_spacing: 60.0,
            max_iterations: 200,
        }
    }
}

impl GraphLayout {
    /// Create a layout with the given algorithm and direction.
    pub fn new(algorithm: LayoutAlgorithm, direction: LayoutDirection) -> Self {
        Self {
            algorithm,
            direction,
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Core data structures
// ---------------------------------------------------------------------------

/// A vertex in the function graph, representing a basic block or code unit.
#[derive(Debug, Clone)]
pub struct FGVertex {
    /// The starting address of this vertex.
    pub address: Address,
    /// A human-readable label (block label, instruction mnemonic, etc.).
    pub label: String,
    /// The P-code operations contained in this vertex.
    pub code_units: Vec<PcodeOperation>,
    /// Position: x-coordinate in the layout.
    pub x: f32,
    /// Position: y-coordinate in the layout.
    pub y: f32,
    /// Width of the vertex bounding box.
    pub width: f32,
    /// Height of the vertex bounding box.
    pub height: f32,
}

impl FGVertex {
    /// Create a new vertex with default layout metrics.
    pub fn new(address: Address, label: String, code_units: Vec<PcodeOperation>) -> Self {
        Self {
            address,
            label,
            code_units,
            x: 0.0,
            y: 0.0,
            width: 120.0,
            height: 40.0,
        }
    }

    /// The centre point of the vertex.
    pub fn centre(&self) -> (f32, f32) {
        (self.x + self.width / 2.0, self.y + self.height / 2.0)
    }

    /// Bottom edge of the vertex.
    pub fn bottom(&self) -> f32 {
        self.y + self.height
    }

    /// Right edge of the vertex.
    pub fn right(&self) -> f32 {
        self.x + self.width
    }
}

/// An edge in the function graph connecting two vertices.
#[derive(Debug, Clone)]
pub struct FGEdge {
    /// Index of the source vertex in [`FunctionGraph::vertices`].
    pub from: usize,
    /// Index of the target vertex in [`FunctionGraph::vertices`].
    pub to: usize,
    /// The type of control-flow this edge represents.
    pub edge_type: CfgEdgeType,
    /// Polyline control points (in layout space).  If empty the edge is drawn
    /// as a straight line from source centre to target centre.
    pub points: Vec<(f32, f32)>,
}

impl FGEdge {
    /// Create a new edge with no control points.
    pub fn new(from: usize, to: usize, edge_type: CfgEdgeType) -> Self {
        Self {
            from,
            to,
            edge_type,
            points: Vec::new(),
        }
    }
}

/// The top-level function graph holding vertices, edges, layout configuration,
/// and the parent function metadata.
#[derive(Debug, Clone)]
pub struct FunctionGraph {
    /// The function this graph represents.
    pub function: Function,
    /// All vertices (basic blocks) in the graph.
    pub vertices: Vec<FGVertex>,
    /// All control-flow edges between vertices.
    pub edges: Vec<FGEdge>,
    /// Layout parameters for positioning vertices.
    pub layout: GraphLayout,
}

impl FunctionGraph {
    /// Create an empty function graph for the given function.
    pub fn new(function: Function) -> Self {
        Self {
            function,
            vertices: Vec::new(),
            edges: Vec::new(),
            layout: GraphLayout::default(),
        }
    }

    /// Build the graph from a vector of vertices and edges.
    pub fn from_parts(
        function: Function,
        vertices: Vec<FGVertex>,
        edges: Vec<FGEdge>,
    ) -> Self {
        Self {
            function,
            vertices,
            edges,
            layout: GraphLayout::default(),
        }
    }

    /// Compute the bounding box of the layout.
    pub fn bounds(&self) -> (f32, f32, f32, f32) {
        if self.vertices.is_empty() {
            return (0.0, 0.0, 0.0, 0.0);
        }
        let min_x = self.vertices.iter().map(|v| v.x).fold(f32::INFINITY, f32::min);
        let min_y = self.vertices.iter().map(|v| v.y).fold(f32::INFINITY, f32::min);
        let max_x = self.vertices.iter().map(|v| v.right()).fold(f32::NEG_INFINITY, f32::max);
        let max_y = self.vertices.iter().map(|v| v.bottom()).fold(f32::NEG_INFINITY, f32::max);
        (min_x, min_y, max_x - min_x, max_y - min_y)
    }

    /// Build a [`petgraph::DiGraph`] for use by layout algorithms.
    pub fn to_petgraph(&self) -> DiGraph<usize, CfgEdgeType> {
        let mut g = DiGraph::new();
        let nodes: Vec<NodeIndex> = (0..self.vertices.len()).map(|i| g.add_node(i)).collect();
        for edge in &self.edges {
            if edge.from < nodes.len() && edge.to < nodes.len() {
                g.add_edge(nodes[edge.from], nodes[edge.to], edge.edge_type);
            }
        }
        g
    }

    /// -----------------------------------------------------------------------
    /// Hierarchical layout (Sugiyama-style)
    /// -----------------------------------------------------------------------
    /// Layers are assigned via longest-path layering.  Vertices within a layer
    /// are ordered to minimise crossings (barycentre heuristic).  Positions are
    /// mapped from (layer, order) to Euclidean space according to
    /// [`GraphLayout::direction`].
    pub fn layout_hierarchical(&mut self) {
        let n = self.vertices.len();
        if n == 0 {
            return;
        }

        // In-degree for topological-style ordering; we use a longest-path
        // algorithm that respects edge directions.
        let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];
        let mut rev_adj: Vec<Vec<usize>> = vec![Vec::new(); n];
        for edge in &self.edges {
            if edge.from < n && edge.to < n {
                adj[edge.from].push(edge.to);
                rev_adj[edge.to].push(edge.from);
            }
        }

        // ---- Layer assignment (longest path from sources) ----
        let mut in_degree: Vec<usize> = rev_adj.iter().map(|v| v.len()).collect();
        let mut layer: Vec<usize> = vec![0; n];
        let mut queue: VecDeque<usize> = VecDeque::new();

        for (i, &deg) in in_degree.iter().enumerate() {
            if deg == 0 {
                queue.push_back(i);
            }
        }

        // If no sources (all in a cycle), seed with vertex 0.
        if queue.is_empty() && n > 0 {
            queue.push_back(0);
        }

        while let Some(u) = queue.pop_front() {
            for &v in &adj[u] {
                layer[v] = layer[v].max(layer[u] + 1);
                in_degree[v] -= 1;
                if in_degree[v] == 0 {
                    queue.push_back(v);
                }
            }
        }

        // ---- Order vertices within each layer (barycentre heuristic) ----
        let max_layer = layer.iter().copied().max().unwrap_or(0);
        let mut layers: Vec<Vec<usize>> = vec![Vec::new(); max_layer + 1];
        for (i, &l) in layer.iter().enumerate() {
            layers[l].push(i);
        }

        // One barycentre pass
        for l in 1..=max_layer {
            layers[l].sort_by(|&a, &b| {
                let avg_pos = |v: usize| -> f32 {
                    let preds: Vec<usize> = rev_adj[v]
                        .iter()
                        .filter(|&&p| layer[p] == l - 1)
                        .copied()
                        .collect();
                    if preds.is_empty() {
                        return 0.0;
                    }
                    preds
                        .iter()
                        .map(|p| {
                            layers[l - 1]
                                .iter()
                                .position(|&x| x == *p)
                                .unwrap_or(0) as f32
                        })
                        .sum::<f32>()
                        / preds.len() as f32
                };
                avg_pos(a)
                    .partial_cmp(&avg_pos(b))
                    .unwrap_or(Ordering::Equal)
            });
        }

        // ---- Position in Euclidean space ----
        let is_horizontal = matches!(
            self.layout.direction,
            LayoutDirection::LeftToRight | LayoutDirection::RightToLeft
        );

        for (l_idx, layer_nodes) in layers.iter().enumerate() {
            for (o_idx, &node_idx) in layer_nodes.iter().enumerate() {
                let (px, py) = match self.layout.direction {
                    LayoutDirection::TopToBottom => (
                        o_idx as f32 * self.layout.node_spacing,
                        l_idx as f32 * self.layout.layer_spacing,
                    ),
                    LayoutDirection::BottomToTop => (
                        o_idx as f32 * self.layout.node_spacing,
                        (max_layer - l_idx) as f32 * self.layout.layer_spacing,
                    ),
                    LayoutDirection::LeftToRight => (
                        l_idx as f32 * self.layout.layer_spacing,
                        o_idx as f32 * self.layout.node_spacing,
                    ),
                    LayoutDirection::RightToLeft => (
                        (max_layer - l_idx) as f32 * self.layout.layer_spacing,
                        o_idx as f32 * self.layout.node_spacing,
                    ),
                };
                self.vertices[node_idx].x = px;
                self.vertices[node_idx].y = py;
            }
        }

        // ---- Edge routing (orthogonal) ----
        self.route_edges_orthogonal();
    }

    /// -----------------------------------------------------------------------
    /// Force-directed layout (Fruchterman-Reingold).
    /// -----------------------------------------------------------------------
    pub fn layout_force_directed(&mut self) {
        let n = self.vertices.len();
        if n == 0 {
            return;
        }

        // Build adjacency for repulsion/attraction
        let mut adj_set: Vec<HashSet<usize>> = vec![HashSet::new(); n];
        for edge in &self.edges {
            if edge.from < n && edge.to < n && edge.from != edge.to {
                adj_set[edge.from].insert(edge.to);
                adj_set[edge.to].insert(edge.from);
            }
        }

        // Initial positions on a circle to avoid degenerate starts
        let radius = 200.0 * (n as f32).sqrt();
        for (i, v) in self.vertices.iter_mut().enumerate() {
            let angle = 2.0 * PI * (i as f32) / (n as f32);
            v.x = radius * angle.cos();
            v.y = radius * angle.sin();
        }

        let area = 100_000.0;
        let k = (area / n as f32).sqrt(); // optimal distance
        let k_sq = k * k;
        let mut t = k * 0.8; // initial temperature
        let cooling = 0.95;

        for _iter in 0..self.layout.max_iterations {
            // Displacement reset
            let mut dx: Vec<f32> = vec![0.0; n];
            let mut dy: Vec<f32> = vec![0.0; n];

            // Repulsive forces (all pairs — O(n^2); fine for typical CFG sizes)
            for i in 0..n {
                for j in (i + 1)..n {
                    let deltax = self.vertices[i].x - self.vertices[j].x;
                    let deltay = self.vertices[i].y - self.vertices[j].y;
                    let dist = (deltax * deltax + deltay * deltay).sqrt().max(0.01);
                    let force = k_sq / dist;
                    let fx = force * deltax / dist;
                    let fy = force * deltay / dist;
                    dx[i] += fx;
                    dy[i] += fy;
                    dx[j] -= fx;
                    dy[j] -= fy;
                }
            }

            // Attractive forces (edges)
            for i in 0..n {
                for &j in &adj_set[i] {
                    if i >= j {
                        continue;
                    }
                    let deltax = self.vertices[j].x - self.vertices[i].x;
                    let deltay = self.vertices[j].y - self.vertices[i].y;
                    let dist = (deltax * deltax + deltay * deltay).sqrt().max(0.01);
                    let force = dist * dist / k;
                    let fx = force * deltax / dist;
                    let fy = force * deltay / dist;
                    dx[i] += fx;
                    dy[i] += fy;
                    dx[j] -= fx;
                    dy[j] -= fy;
                }
            }

            // Apply displacements, clipped to temperature
            for i in 0..n {
                let mag = (dx[i] * dx[i] + dy[i] * dy[i]).sqrt().max(0.01);
                let capped = mag.min(t);
                self.vertices[i].x += dx[i] / mag * capped;
                self.vertices[i].y += dy[i] / mag * capped;
            }

            t *= cooling;
            if t < 1.0 {
                break;
            }
        }

        self.route_edges_straight();
    }

    /// -----------------------------------------------------------------------
    /// Circular layout.
    /// -----------------------------------------------------------------------
    pub fn layout_circular(&mut self) {
        let n = self.vertices.len();
        if n == 0 {
            return;
        }

        let cx = 400.0;
        let cy = 400.0;
        let radius = 200.0 * (n as f32).sqrt().max(200.0);

        // Attempt to order vertices so that edges span shorter arcs.
        // Use a depth-first traversal of the undirected graph to get a linear
        // order, then lay out in that order on the circle.
        let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];
        for edge in &self.edges {
            if edge.from < n && edge.to < n && edge.from != edge.to {
                adj[edge.from].push(edge.to);
                adj[edge.to].push(edge.from);
            }
        }

        let mut order: Vec<usize> = Vec::with_capacity(n);
        let mut visited = vec![false; n];

        // DFS pre-order for a reasonable cyclic ordering
        fn dfs(u: usize, adj: &[Vec<usize>], visited: &mut [bool], order: &mut Vec<usize>) {
            visited[u] = true;
            order.push(u);
            for &v in &adj[u] {
                if !visited[v] {
                    dfs(v, adj, visited, order);
                }
            }
        }

        for i in 0..n {
            if !visited[i] {
                dfs(i, &adj, visited, &mut order);
            }
        }

        for (idx, &v_idx) in order.iter().enumerate() {
            let angle = 2.0 * PI * (idx as f32) / (n as f32) - PI / 2.0;
            self.vertices[v_idx].x = cx + radius * angle.cos();
            self.vertices[v_idx].y = cy + radius * angle.sin();
        }

        self.route_edges_straight();
    }

    /// -----------------------------------------------------------------------
    /// Radial layout — concentric rings around a root.
    /// -----------------------------------------------------------------------
    pub fn layout_radial(&mut self) {
        let n = self.vertices.len();
        if n == 0 {
            return;
        }

        // Build adjacency
        let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];
        for edge in &self.edges {
            if edge.from < n && edge.to < n {
                adj[edge.from].push(edge.to);
                adj[edge.to].push(edge.from);
            }
        }

        // BFS tree from vertex 0 (entry)
        let mut depth: Vec<Option<usize>> = vec![None; n];
        let mut parent: Vec<Option<usize>> = vec![None; n];
        let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];
        let mut queue = VecDeque::new();

        depth[0] = Some(0);
        queue.push_back(0);

        while let Some(u) = queue.pop_front() {
            for &v in &adj[u] {
                if depth[v].is_none() {
                    depth[v] = Some(depth[u].unwrap() + 1);
                    parent[v] = Some(u);
                    children[u].push(v);
                    queue.push_back(v);
                }
            }
        }

        // Place unvisited nodes at depth 0
        for i in 0..n {
            if depth[i].is_none() {
                depth[i] = Some(0);
            }
        }

        let max_depth = depth.iter().filter_map(|&d| d).max().unwrap_or(0);

        // Group nodes by depth
        let mut layers: Vec<Vec<usize>> = vec![Vec::new(); max_depth + 1];
        for (i, &d) in depth.iter().enumerate() {
            if let Some(d) = d {
                layers[d].push(i);
            }
        }

        let cx = 400.0;
        let cy = 400.0;
        let ring_spacing = self.layout.layer_spacing.max(60.0);

        for (d, layer_nodes) in layers.iter().enumerate() {
            let radius = if d == 0 {
                0.0
            } else {
                d as f32 * ring_spacing
            };
            let count = layer_nodes.len();
            for (o_idx, &node_idx) in layer_nodes.iter().enumerate() {
                let angle = if count > 0 {
                    2.0 * PI * (o_idx as f32) / (count as f32)
                } else {
                    0.0
                };
                self.vertices[node_idx].x = cx + radius * angle.cos();
                self.vertices[node_idx].y = cy + radius * angle.sin();
            }
        }

        self.route_edges_straight();
    }

    /// -----------------------------------------------------------------------
    /// Top-level layout dispatcher.
    /// -----------------------------------------------------------------------
    ///
    /// Applies the layout algorithm specified by `self.layout.algorithm` and
    /// recomputes edge routes.
    pub fn apply_layout(&mut self) {
        match self.layout.algorithm {
            LayoutAlgorithm::Hierarchical => self.layout_hierarchical(),
            LayoutAlgorithm::ForceDirected => self.layout_force_directed(),
            LayoutAlgorithm::Circular => self.layout_circular(),
            LayoutAlgorithm::Radial => self.layout_radial(),
        }
    }

    /// -----------------------------------------------------------------------
    /// Edge routing
    /// -----------------------------------------------------------------------

    /// Route every edge as a straight line from source centre to target centre.
    pub fn route_edges_straight(&mut self) {
        let n = self.vertices.len();
        for edge in &mut self.edges {
            if edge.from < n && edge.to < n {
                let (sx, sy) = self.vertices[edge.from].centre();
                let (tx, ty) = self.vertices[edge.to].centre();
                edge.points = vec![(sx, sy), (tx, ty)];
            }
        }
    }

    /// Route every edge as an orthogonal polyline (2-segment "L" or 3-segment
    /// "Z" shape).
    pub fn route_edges_orthogonal(&mut self) {
        let n = self.vertices.len();
        let is_horizontal = matches!(
            self.layout.direction,
            LayoutDirection::LeftToRight | LayoutDirection::RightToLeft
        );

        for edge in &mut self.edges {
            if edge.from >= n || edge.to >= n {
                continue;
            }

            let (sx, sy) = self.vertices[edge.from].centre();
            let (tx, ty) = self.vertices[edge.to].centre();

            if is_horizontal {
                // Source → horizontal midpoint → target
                let mid = (sx + tx) / 2.0;
                edge.points = vec![(sx, sy), (mid, sy), (mid, ty), (tx, ty)];
            } else {
                let mid = (sy + ty) / 2.0;
                edge.points = vec![(sx, sy), (sx, mid), (tx, mid), (tx, ty)];
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: convert from ghidra_decompile CfgEdge to functiongraph CfgEdgeType
// ---------------------------------------------------------------------------

#[doc(hidden)]
pub fn convert_cfg_edge_type(de_edge: ghidra_decompile::pcode::analysis::CfgEdge) -> CfgEdgeType {
    match de_edge {
        ghidra_decompile::pcode::analysis::CfgEdge::Fallthrough => CfgEdgeType::Fallthrough,
        ghidra_decompile::pcode::analysis::CfgEdge::Branch => CfgEdgeType::Branch,
        ghidra_decompile::pcode::analysis::CfgEdge::TrueBranch => CfgEdgeType::TrueBranch,
        ghidra_decompile::pcode::analysis::CfgEdge::FalseBranch => CfgEdgeType::FalseBranch,
        ghidra_decompile::pcode::analysis::CfgEdge::IndirectBranch => CfgEdgeType::IndirectBranch,
        ghidra_decompile::pcode::analysis::CfgEdge::Call => CfgEdgeType::Call,
        ghidra_decompile::pcode::analysis::CfgEdge::Return => CfgEdgeType::Return,
    }
}

/// Build a `FunctionGraph` from a decompiler `ControlFlowGraph`, mapping blocks
/// to vertices and CFG edges to FGEdges.
pub fn from_decompiler_cfg(
    function: Function,
    cfg: &ghidra_decompile::pcode::analysis::ControlFlowGraph,
) -> FunctionGraph {
    let mut vertices: Vec<FGVertex> = Vec::with_capacity(cfg.blocks.len());
    let mut block_to_vertex: HashMap<usize, usize> = HashMap::new();

    for block in &cfg.blocks {
        let label = if let Some(addr) = block.start_address {
            format!("block_{:08x}", addr.offset)
        } else {
            format!("block_{}", block.id)
        };
        let v_idx = vertices.len();
        block_to_vertex.insert(block.id, v_idx);
        vertices.push(FGVertex::new(
            block.start_address.unwrap_or(Address::new(0)),
            label,
            block.operations.clone(),
        ));
    }

    let mut edges: Vec<FGEdge> = Vec::new();
    for eref in cfg.graph.edge_references() {
        let from_block = cfg.graph[eref.source()];
        let to_block = cfg.graph[eref.target()];
        if let (Some(&from), Some(&to)) =
            (block_to_vertex.get(&from_block), block_to_vertex.get(&to_block))
        {
            edges.push(FGEdge::new(from, to, convert_cfg_edge_type(*eref.weight())));
        }
    }

    FunctionGraph::from_parts(function, vertices, edges)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::AddressRange;

    fn dummy_function() -> Function {
        Function {
            name: "test_fn".to_string(),
            entry_point: Address::new(0x1000),
            body: AddressRange::new(Address::new(0x1000), Address::new(0x1100)),
            signature: "void test_fn(int)".to_string(),
        }
    }

    #[test]
    fn test_empty_graph_layout() {
        let mut g = FunctionGraph::new(dummy_function());
        g.apply_layout();
        assert!(g.vertices.is_empty());
    }

    #[test]
    fn test_single_vertex_layout() {
        let mut g = FunctionGraph::from_parts(
            dummy_function(),
            vec![FGVertex::new(Address::new(0x1000), "entry".into(), vec![])],
            vec![],
        );
        g.layout.circular();
        assert_eq!(g.vertices.len(), 1);
    }

    #[test]
    fn test_hierarchical_layout_chain() {
        let mut g = FunctionGraph::from_parts(
            dummy_function(),
            vec![
                FGVertex::new(Address::new(0x1000), "A".into(), vec![]),
                FGVertex::new(Address::new(0x1010), "B".into(), vec![]),
                FGVertex::new(Address::new(0x1020), "C".into(), vec![]),
            ],
            vec![
                FGEdge::new(0, 1, CfgEdgeType::Fallthrough),
                FGEdge::new(1, 2, CfgEdgeType::Fallthrough),
            ],
        );
        g.layout_hierarchical();
        // Vertices should be placed in distinct y layers
        assert!(g.vertices[0].y < g.vertices[1].y);
        assert!(g.vertices[1].y < g.vertices[2].y);
    }

    #[test]
    fn test_force_directed_layout() {
        let mut g = FunctionGraph::from_parts(
            dummy_function(),
            vec![
                FGVertex::new(Address::new(0x1000), "A".into(), vec![]),
                FGVertex::new(Address::new(0x1010), "B".into(), vec![]),
            ],
            vec![FGEdge::new(0, 1, CfgEdgeType::Fallthrough)],
        );
        g.layout_force_directed();
        // Positions should be non-zero after force placement.
        assert_ne!(g.vertices[0].x, 0.0);
    }

    #[test]
    fn test_circular_layout() {
        let mut g = FunctionGraph::from_parts(
            dummy_function(),
            vec![
                FGVertex::new(Address::new(0x1000), "A".into(), vec![]),
                FGVertex::new(Address::new(0x1010), "B".into(), vec![]),
                FGVertex::new(Address::new(0x1020), "C".into(), vec![]),
                FGVertex::new(Address::new(0x1030), "D".into(), vec![]),
            ],
            vec![
                FGEdge::new(0, 1, CfgEdgeType::Fallthrough),
                FGEdge::new(1, 2, CfgEdgeType::Fallthrough),
                FGEdge::new(2, 3, CfgEdgeType::Fallthrough),
            ],
        );
        g.layout_circular();
        for v in &g.vertices {
            let dx = v.x - 400.0;
            let dy = v.y - 400.0;
            let dist = (dx * dx + dy * dy).sqrt();
            assert!(dist > 10.0, "vertex should be placed on circle");
        }
    }

    #[test]
    fn test_radial_layout() {
        let mut g = FunctionGraph::from_parts(
            dummy_function(),
            vec![
                FGVertex::new(Address::new(0x1000), "root".into(), vec![]),
                FGVertex::new(Address::new(0x1010), "child1".into(), vec![]),
                FGVertex::new(Address::new(0x1020), "child2".into(), vec![]),
            ],
            vec![
                FGEdge::new(0, 1, CfgEdgeType::Fallthrough),
                FGEdge::new(0, 2, CfgEdgeType::Branch),
            ],
        );
        g.layout_radial();
        // Root should be near centre.
        let (rx, ry) = g.vertices[0].centre();
        let root_dist = ((rx - 400.0).powi(2) + (ry - 400.0).powi(2)).sqrt();
        assert!(root_dist < 10.0, "root should be at centre");
    }

    #[test]
    fn test_straight_edge_routing() {
        let mut g = FunctionGraph::from_parts(
            dummy_function(),
            vec![
                FGVertex::new(Address::new(0x1000), "A".into(), vec![]),
                FGVertex::new(Address::new(0x1010), "B".into(), vec![]),
            ],
            vec![FGEdge::new(0, 1, CfgEdgeType::Fallthrough)],
        );
        g.route_edges_straight();
        assert_eq!(g.edges[0].points.len(), 2);
        // Points should connect source centre to target centre.
        assert_eq!(g.edges[0].points[0], g.vertices[0].centre());
        assert_eq!(g.edges[0].points[1], g.vertices[1].centre());
    }

    #[test]
    fn test_orthogonal_edge_routing() {
        let mut g = FunctionGraph::from_parts(
            dummy_function(),
            vec![
                FGVertex::new(Address::new(0x1000), "A".into(), vec![]),
                FGVertex::new(Address::new(0x1010), "B".into(), vec![]),
            ],
            vec![FGEdge::new(0, 1, CfgEdgeType::Fallthrough)],
        );
        g.layout.direction = LayoutDirection::TopToBottom;
        g.route_edges_orthogonal();
        assert_eq!(g.edges[0].points.len(), 4);
    }
}
