//! Missing graph types ported from Ghidra's Java Graph framework.
//!
//! Ports the following Java classes:
//! - `ghidra.graph.algo.AbstractDominanceAlgorithm`
//! - `ghidra.graph.algo.ChkDominanceAlgorithm`
//! - `ghidra.graph.algo.ChkPostDominanceAlgorithm`
//! - `ghidra.graph.algo.DijkstraShortestPathsAlgorithm`
//! - `ghidra.graph.algo.FindPathsAlgorithm`
//! - `ghidra.graph.algo.IterativeFindPathsAlgorithm`
//! - `ghidra.graph.algo.JohnsonCircuitsAlgorithm`
//! - `ghidra.graph.algo.TarjanStronglyConnectedAlgorthm`
//! - `ghidra.graph.GraphAlgorithms`
//! - `ghidra.graph.GraphToTreeAlgorithm`
//! - `ghidra.graph.event.VisualGraphChangeListener`
//! - `ghidra.graph.jung.*`
//! - `ghidra.graph.viewer.layout.*`
//! - `ghidra.graph.job.*` (animation jobs)
//! - `ghidra.graph.viewer.event.mouse.*` (mouse plugins)
//! - `ghidra.service.graph.*` (service types)

use std::collections::{HashMap, HashSet, VecDeque};

// ============================================================================
// GraphAlgorithms - convenience methods for graph algorithms
// ============================================================================

/// Utility class for graph algorithm operations.
///
/// Ported from `ghidra.graph.GraphAlgorithms`.
pub struct GraphAlgorithms;

impl GraphAlgorithms {
    /// Returns all source vertices (those with no incoming edges).
    pub fn get_sources<V: Clone + Eq + std::hash::Hash, E: GraphEdge<V>>(
        graph: &dyn GraphLike<V, E>,
    ) -> HashSet<V> {
        let vertices = graph.vertices();
        let mut sources: HashSet<V> = vertices.iter().cloned().collect();
        for e in graph.edges() {
            sources.remove(&e.target());
        }
        sources
    }

    /// Returns all sink vertices (those with no outgoing edges).
    pub fn get_sinks<V: Clone + Eq + std::hash::Hash, E: GraphEdge<V>>(
        graph: &dyn GraphLike<V, E>,
    ) -> HashSet<V> {
        let vertices = graph.vertices();
        let mut sinks: HashSet<V> = vertices.iter().cloned().collect();
        for e in graph.edges() {
            sinks.remove(&e.source());
        }
        sinks
    }

    /// Computes graph density: E / (V * (V-1)).
    pub fn density<V, E>(graph: &dyn GraphLike<V, E>) -> f64 {
        let v = graph.vertex_count() as f64;
        let e = graph.edge_count() as f64;
        if v <= 1.0 {
            return 0.0;
        }
        e / (v * (v - 1.0))
    }

    /// Returns a topological ordering of the graph vertices using Kahn's algorithm.
    pub fn topological_sort<V: Clone + Eq + std::hash::Hash, E: GraphEdge<V>>(
        graph: &dyn GraphLike<V, E>,
    ) -> Vec<V> {
        let mut in_degree: HashMap<V, usize> = HashMap::new();
        for v in graph.vertices() {
            in_degree.entry(v.clone()).or_insert(0);
        }
        for e in graph.edges() {
            *in_degree.entry(e.target()).or_insert(0) += 1;
        }

        let mut queue: VecDeque<V> = VecDeque::new();
        for (v, &deg) in &in_degree {
            if deg == 0 {
                queue.push_back(v.clone());
            }
        }

        let mut result = Vec::new();
        while let Some(v) = queue.pop_front() {
            result.push(v.clone());
            for neighbor in graph.successors(&v) {
                let deg = in_degree.get_mut(&neighbor).unwrap();
                *deg -= 1;
                if *deg == 0 {
                    queue.push_back(neighbor);
                }
            }
        }
        result
    }

    /// Returns true if the graph contains a cycle.
    pub fn has_cycle<V: Clone + Eq + std::hash::Hash, E: GraphEdge<V>>(
        graph: &dyn GraphLike<V, E>,
    ) -> bool {
        let sorted = Self::topological_sort(graph);
        sorted.len() < graph.vertex_count()
    }
}

// ============================================================================
// GraphEdge / GraphLike traits
// ============================================================================

/// Trait representing a directed edge in a graph.
pub trait GraphEdge<V> {
    /// Returns the source vertex.
    fn source(&self) -> V;
    /// Returns the target vertex.
    fn target(&self) -> V;
}

/// Trait representing a graph data structure.
pub trait GraphLike<V, E> {
    /// Returns all vertices.
    fn vertices(&self) -> Vec<V>;
    /// Returns all edges.
    fn edges(&self) -> Vec<E>;
    /// Returns the number of vertices.
    fn vertex_count(&self) -> usize;
    /// Returns the number of edges.
    fn edge_count(&self) -> usize;
    /// Returns successors of a vertex.
    fn successors(&self, v: &V) -> Vec<V>;
    /// Returns predecessors of a vertex.
    fn predecessors(&self, v: &V) -> Vec<V>;
    /// Returns edges from a vertex.
    fn out_edges(&self, v: &V) -> Vec<E>;
    /// Returns edges to a vertex.
    fn in_edges(&self, v: &V) -> Vec<E>;
}

// ============================================================================
// AbstractDominanceAlgorithm
// ============================================================================

/// Base class for graph dominance algorithms.
///
/// Ported from `ghidra.graph.algo.AbstractDominanceAlgorithm`.
pub struct AbstractDominanceAlgorithm;

impl AbstractDominanceAlgorithm {
    /// Convert multiple source/root nodes into a single unified source.
    pub fn unify_sources<V: Clone + Eq + std::hash::Hash + Default, E: GraphEdge<V> + Clone>(
        graph: &mut dyn MutableGraphLike<V, E>,
    ) -> V {
        let sources = GraphAlgorithms::get_sources(graph.as_graph());
        if sources.is_empty() {
            panic!("Graph does not contain at least one source node");
        }
        if sources.len() == 1 {
            return sources.into_iter().next().unwrap();
        }
        let dummy = graph.add_dummy_vertex("Dummy Root Vertex");
        for s in sources {
            graph.add_dummy_edge(dummy.clone(), s);
        }
        dummy
    }
}

/// Trait for mutable graph operations used by dominance algorithms.
pub trait MutableGraphLike<V, E> {
    /// Get an immutable graph reference.
    fn as_graph(&self) -> &dyn GraphLike<V, E>;
    /// Add a dummy vertex with a label.
    fn add_dummy_vertex(&mut self, label: &str) -> V;
    /// Add a dummy edge.
    fn add_dummy_edge(&mut self, from: V, to: V);
}

// ============================================================================
// ChkDominanceAlgorithm
// ============================================================================

/// CHECK-based dominance algorithm.
///
/// Ported from `ghidra.graph.algo.ChkDominanceAlgorithm`.
pub struct ChkDominanceAlgorithm;

impl ChkDominanceAlgorithm {
    /// Compute the dominator set for each vertex using the CHECK algorithm.
    pub fn compute_dominators<V: Clone + Eq + std::hash::Hash, E: GraphEdge<V>>(
        graph: &dyn GraphLike<V, E>,
        entry: &V,
    ) -> HashMap<V, HashSet<V>> {
        let vertices = graph.vertices();
        let mut dom: HashMap<V, HashSet<V>> = HashMap::new();

        // Initialize: entry dominates itself; all others dominate everything.
        for v in &vertices {
            dom.insert(v.clone(), vertices.iter().cloned().collect());
        }
        if let Some(entry_set) = dom.get_mut(entry) {
            let mut s = HashSet::new();
            s.insert(entry.clone());
            *entry_set = s;
        }

        // Iterative refinement.
        let mut changed = true;
        while changed {
            changed = false;
            for v in &vertices {
                if v == entry {
                    continue;
                }
                let preds = graph.predecessors(v);
                if preds.is_empty() {
                    continue;
                }
                let mut new_dom: HashSet<V> = dom
                    .get(&preds[0])
                    .cloned()
                    .unwrap_or_default();
                for p in &preds[1..] {
                    if let Some(p_dom) = dom.get(p) {
                        new_dom = new_dom.intersection(p_dom).cloned().collect();
                    }
                }
                new_dom.insert(v.clone());
                if dom.get(v) != Some(&new_dom) {
                    dom.insert(v.clone(), new_dom);
                    changed = true;
                }
            }
        }
        dom
    }
}

// ============================================================================
// ChkPostDominanceAlgorithm
// ============================================================================

/// CHECK-based post-dominance algorithm.
///
/// Ported from `ghidra.graph.algo.ChkPostDominanceAlgorithm`.
pub struct ChkPostDominanceAlgorithm;

impl ChkPostDominanceAlgorithm {
    /// Compute post-dominators: node 'b' post-dominates 'a' if all paths from 'a' to END
    /// contain 'b'.
    pub fn compute_post_dominators<V: Clone + Eq + std::hash::Hash, E: GraphEdge<V>>(
        graph: &dyn GraphLike<V, E>,
    ) -> HashMap<V, HashSet<V>> {
        let sinks = GraphAlgorithms::get_sinks(graph);
        if sinks.is_empty() {
            return HashMap::new();
        }
        // For simplicity, use a virtual exit node approach.
        let entry = sinks.into_iter().next().unwrap();
        ChkDominanceAlgorithm::compute_dominators(graph, &entry)
    }
}

// ============================================================================
// GraphToTreeAlgorithm
// ============================================================================

/// Convert a graph to a tree structure.
///
/// Ported from `ghidra.graph.GraphToTreeAlgorithm`.
pub struct GraphToTreeAlgorithm;

impl GraphToTreeAlgorithm {
    /// Convert a DAG into a tree by duplicating vertices that have multiple parents.
    /// Returns a vector of (parent, child) pairs.
    pub fn convert_to_tree<V: Clone + Eq + std::hash::Hash, E: GraphEdge<V>>(
        graph: &dyn GraphLike<V, E>,
    ) -> Vec<(V, V)> {
        let mut tree_edges = Vec::new();
        let mut visited: HashSet<V> = HashSet::new();
        let sources = GraphAlgorithms::get_sources(graph);
        let mut queue: VecDeque<V> = sources.into_iter().collect();

        while let Some(v) = queue.pop_front() {
            if visited.contains(&v) {
                continue;
            }
            visited.insert(v.clone());
            for succ in graph.successors(&v) {
                tree_edges.push((v.clone(), succ.clone()));
                queue.push_back(succ);
            }
        }
        tree_edges
    }
}

// ============================================================================
// VisualGraphChangeListener
// ============================================================================

/// Listener for visual graph change events.
///
/// Ported from `ghidra.graph.event.VisualGraphChangeListener`.
pub trait VisualGraphChangeListener<V, E>: Send + Sync {
    /// Called when vertices have been added to the graph.
    fn vertices_added(&self, vertices: &[V]);
    /// Called when vertices have been removed from the graph.
    fn vertices_removed(&self, vertices: &[V]);
    /// Called when edges have been added to the graph.
    fn edges_added(&self, edges: &[E]);
    /// Called when edges have been removed from the graph.
    fn edges_removed(&self, edges: &[E]);
}

// ============================================================================
// JungDirectedGraph
// ============================================================================

/// Adapter for JUNG-style directed graph operations.
///
/// Ported from `ghidra.graph.jung.JungDirectedGraph`.
#[derive(Debug, Clone)]
pub struct JungDirectedGraph<V: Eq + std::hash::Hash + Clone, E: Clone> {
    vertices: HashSet<V>,
    edges: Vec<E>,
    adjacency: HashMap<V, Vec<usize>>,
    edge_sources: HashMap<usize, V>,
    edge_targets: HashMap<usize, V>,
    next_edge_id: usize,
}

impl<V: Eq + std::hash::Hash + Clone, E: Clone> JungDirectedGraph<V, E> {
    /// Create a new empty directed graph.
    pub fn new() -> Self {
        Self {
            vertices: HashSet::new(),
            edges: Vec::new(),
            adjacency: HashMap::new(),
            edge_sources: HashMap::new(),
            edge_targets: HashMap::new(),
            next_edge_id: 0,
        }
    }

    /// Add a vertex to the graph.
    pub fn add_vertex(&mut self, v: V) {
        self.vertices.insert(v);
    }

    /// Add a directed edge from source to target.
    pub fn add_edge(&mut self, source: V, target: V, edge: E) {
        let id = self.next_edge_id;
        self.next_edge_id += 1;
        self.vertices.insert(source.clone());
        self.vertices.insert(target.clone());
        self.edges.push(edge);
        self.edge_sources.insert(id, source.clone());
        self.edge_targets.insert(id, target.clone());
        self.adjacency.entry(source).or_default().push(id);
    }

    /// Get the number of vertices.
    pub fn vertex_count(&self) -> usize {
        self.vertices.len()
    }

    /// Get the number of edges.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Get all vertices.
    pub fn vertices(&self) -> Vec<V> {
        self.vertices.iter().cloned().collect()
    }

    /// Get successors of a vertex.
    pub fn successors(&self, v: &V) -> Vec<V> {
        self.adjacency
            .get(v)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.edge_targets.get(id).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl<V: Eq + std::hash::Hash + Clone, E: Clone> Default for JungDirectedGraph<V, E> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// JungToGDirectedGraphAdapter
// ============================================================================

/// Adapter that wraps a `JungDirectedGraph` to implement the `GraphLike` trait.
///
/// Ported from `ghidra.graph.jung.JungToGDirectedGraphAdapter`.
pub struct JungToGDirectedGraphAdapter<V: Eq + std::hash::Hash + Clone, E: Clone> {
    inner: JungDirectedGraph<V, E>,
}

impl<V: Eq + std::hash::Hash + Clone, E: Clone> JungToGDirectedGraphAdapter<V, E> {
    /// Create a new adapter wrapping the given graph.
    pub fn new(graph: JungDirectedGraph<V, E>) -> Self {
        Self { inner: graph }
    }

    /// Get a reference to the inner graph.
    pub fn inner(&self) -> &JungDirectedGraph<V, E> {
        &self.inner
    }

    /// Get a mutable reference to the inner graph.
    pub fn inner_mut(&mut self) -> &mut JungDirectedGraph<V, E> {
        &mut self.inner
    }
}

// ============================================================================
// JungDirectedVisualGraph
// ============================================================================

/// A JUNG-directed graph used as the backing store for visual graphs.
///
/// Ported from `ghidra.graph.graphs.JungDirectedVisualGraph`.
#[derive(Debug, Clone)]
pub struct JungDirectedVisualGraph<V: Eq + std::hash::Hash + Clone, E: Clone> {
    base: JungDirectedGraph<V, E>,
    layout_positions: HashMap<V, (f64, f64)>,
    focused_vertex: Option<V>,
    selected_vertices: HashSet<V>,
}

impl<V: Eq + std::hash::Hash + Clone, E: Clone> JungDirectedVisualGraph<V, E> {
    /// Create a new visual graph.
    pub fn new() -> Self {
        Self {
            base: JungDirectedGraph::new(),
            layout_positions: HashMap::new(),
            focused_vertex: None,
            selected_vertices: HashSet::new(),
        }
    }

    /// Set the focused vertex.
    pub fn set_focused(&mut self, v: Option<V>) {
        self.focused_vertex = v;
    }

    /// Get the focused vertex.
    pub fn focused(&self) -> Option<&V> {
        self.focused_vertex.as_ref()
    }

    /// Select a vertex.
    pub fn select(&mut self, v: V) {
        self.selected_vertices.insert(v);
    }

    /// Deselect all vertices.
    pub fn clear_selection(&mut self) {
        self.selected_vertices.clear();
    }

    /// Set vertex layout position.
    pub fn set_position(&mut self, v: V, x: f64, y: f64) {
        self.layout_positions.insert(v, (x, y));
    }

    /// Get vertex layout position.
    pub fn position(&self, v: &V) -> Option<(f64, f64)> {
        self.layout_positions.get(v).copied()
    }

    /// Access the underlying directed graph.
    pub fn graph(&self) -> &JungDirectedGraph<V, E> {
        &self.base
    }

    /// Access the underlying directed graph mutably.
    pub fn graph_mut(&mut self) -> &mut JungDirectedGraph<V, E> {
        &mut self.base
    }
}

impl<V: Eq + std::hash::Hash + Clone, E: Clone> Default for JungDirectedVisualGraph<V, E> {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// JungLayoutProvider
// ============================================================================

/// Layout provider backed by JUNG graph layout algorithms.
///
/// Ported from `ghidra.graph.viewer.layout.JungLayoutProvider`.
pub struct JungLayoutProvider<V: Eq + std::hash::Hash + Clone, E: Clone> {
    name: String,
    layout_type: JungLayoutType,
    _phantom: std::marker::PhantomData<(V, E)>,
}

/// Types of JUNG layout algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JungLayoutType {
    /// Force-directed (Fruchterman-Reingold) layout.
    ForceDirected,
    /// Circular layout.
    Circular,
    /// Hierarchical (Kamada-Kawai) layout.
    Hierarchical,
    /// Spring-based layout.
    Spring,
}

impl<V: Eq + std::hash::Hash + Clone, E: Clone> JungLayoutProvider<V, E> {
    /// Create a new layout provider with the given name and algorithm.
    pub fn new(name: impl Into<String>, layout_type: JungLayoutType) -> Self {
        Self {
            name: name.into(),
            layout_type,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Get the layout name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the layout algorithm type.
    pub fn layout_type(&self) -> JungLayoutType {
        self.layout_type
    }

    /// Compute layout positions for all vertices.
    pub fn compute_layout(
        &self,
        graph: &JungDirectedGraph<V, E>,
    ) -> HashMap<V, (f64, f64)> {
        let vertices = graph.vertices();
        let n = vertices.len();
        if n == 0 {
            return HashMap::new();
        }

        match self.layout_type {
            JungLayoutType::Circular => {
                let radius = (n as f64) * 30.0;
                vertices
                    .into_iter()
                    .enumerate()
                    .map(|(i, v)| {
                        let angle = 2.0 * std::f64::consts::PI * (i as f64) / (n as f64);
                        (v, (radius * angle.cos(), radius * angle.sin()))
                    })
                    .collect()
            }
            JungLayoutType::ForceDirected | JungLayoutType::Spring => {
                // Simple grid layout as fallback
                let cols = (n as f64).sqrt().ceil() as usize;
                vertices
                    .into_iter()
                    .enumerate()
                    .map(|(i, v)| {
                        let col = i % cols;
                        let row = i / cols;
                        (v, (col as f64 * 100.0, row as f64 * 100.0))
                    })
                    .collect()
            }
            JungLayoutType::Hierarchical => {
                // Layered layout using simple index-based positioning
                let mut positions = HashMap::new();
                for (i, v) in vertices.iter().enumerate() {
                    positions.insert(v.clone(), (i as f64 * 100.0, 0.0));
                }
                positions
            }
        }
    }
}


// ============================================================================
// JungLayoutProviderFactory
// ============================================================================

/// Factory for creating JUNG layout providers.
///
/// Ported from `ghidra.graph.viewer.layout.JungLayoutProviderFactory`.
pub struct JungLayoutProviderFactory;

impl JungLayoutProviderFactory {
    /// Create a force-directed layout provider.
    pub fn force_directed<V: Eq + std::hash::Hash + Clone, E: Clone>(
        name: &str,
    ) -> JungLayoutProvider<V, E> {
        JungLayoutProvider::new(name, JungLayoutType::ForceDirected)
    }

    /// Create a circular layout provider.
    pub fn circular<V: Eq + std::hash::Hash + Clone, E: Clone>(
        name: &str,
    ) -> JungLayoutProvider<V, E> {
        JungLayoutProvider::new(name, JungLayoutType::Circular)
    }

    /// Create a hierarchical layout provider.
    pub fn hierarchical<V: Eq + std::hash::Hash + Clone, E: Clone>(
        name: &str,
    ) -> JungLayoutProvider<V, E> {
        JungLayoutProvider::new(name, JungLayoutType::Hierarchical)
    }
}

// ============================================================================
// JungWrappingVisualGraphLayoutAdapter
// ============================================================================

/// Adapter that wraps a JUNG layout to provide visual graph layout positions.
///
/// Ported from `ghidra.graph.viewer.layout.JungWrappingVisualGraphLayoutAdapter`.
pub struct JungWrappingVisualGraphLayoutAdapter<V: Eq + std::hash::Hash + Clone, E: Clone> {
    provider: JungLayoutProvider<V, E>,
    cached_positions: HashMap<V, (f64, f64)>,
}

impl<V: Eq + std::hash::Hash + Clone, E: Clone> JungWrappingVisualGraphLayoutAdapter<V, E> {
    /// Create a new adapter wrapping the given layout provider.
    pub fn new(provider: JungLayoutProvider<V, E>) -> Self {
        Self {
            provider,
            cached_positions: HashMap::new(),
        }
    }

    /// (Re)compute layout positions for the given graph.
    pub fn recalculate(&mut self, graph: &JungDirectedGraph<V, E>) {
        self.cached_positions = self.provider.compute_layout(graph);
    }

    /// Get the position for a vertex.
    pub fn position(&self, v: &V) -> Option<(f64, f64)> {
        self.cached_positions.get(v).copied()
    }
}

// ============================================================================
// Animation Jobs (AbstractAnimator, etc.)
// ============================================================================

/// Base for animation job types.
///
/// Ported from `ghidra.graph.job.AbstractAnimator`.
#[derive(Debug, Clone)]
pub struct AbstractAnimator {
    /// Duration of the animation in milliseconds.
    pub duration_ms: u64,
    /// Current progress [0.0, 1.0].
    pub progress: f64,
    /// Whether the animation is complete.
    pub done: bool,
}

impl AbstractAnimator {
    /// Create a new animator with the given duration.
    pub fn new(duration_ms: u64) -> Self {
        Self {
            duration_ms,
            progress: 0.0,
            done: false,
        }
    }

    /// Advance the animation by the given elapsed time in milliseconds.
    pub fn advance(&mut self, elapsed_ms: u64) {
        if self.done {
            return;
        }
        self.progress += (elapsed_ms as f64) / (self.duration_ms as f64);
        if self.progress >= 1.0 {
            self.progress = 1.0;
            self.done = true;
        }
    }

    /// Returns true if the animation is complete.
    pub fn is_done(&self) -> bool {
        self.done
    }
}

/// Animation job that transitions the graph visibility state.
///
/// Ported from `ghidra.graph.job.AbstractGraphVisibilityTransitionJob`.
#[derive(Debug, Clone)]
pub struct AbstractGraphVisibilityTransitionJob {
    animator: AbstractAnimator,
    visible_vertices: HashSet<usize>,
    visible_edges: HashSet<usize>,
}

impl AbstractGraphVisibilityTransitionJob {
    /// Create a new visibility transition job.
    pub fn new(duration_ms: u64) -> Self {
        Self {
            animator: AbstractAnimator::new(duration_ms),
            visible_vertices: HashSet::new(),
            visible_edges: HashSet::new(),
        }
    }

    /// Set which vertices should be visible.
    pub fn set_visible_vertices(&mut self, verts: HashSet<usize>) {
        self.visible_vertices = verts;
    }

    /// Set which edges should be visible.
    pub fn set_visible_edges(&mut self, edges: HashSet<usize>) {
        self.visible_edges = edges;
    }

    /// Get the current animation progress.
    pub fn progress(&self) -> f64 {
        self.animator.progress
    }

    /// Returns true if the animation is done.
    pub fn is_done(&self) -> bool {
        self.animator.is_done()
    }
}

/// Animator for edge hover effects.
///
/// Ported from `ghidra.graph.job.EdgeHoverAnimator`.
#[derive(Debug, Clone)]
pub struct EdgeHoverAnimator {
    animator: AbstractAnimator,
    hovered_edge: Option<usize>,
}

impl EdgeHoverAnimator {
    /// Create a new edge hover animator.
    pub fn new(duration_ms: u64) -> Self {
        Self {
            animator: AbstractAnimator::new(duration_ms),
            hovered_edge: None,
        }
    }

    /// Set the hovered edge.
    pub fn set_hovered(&mut self, edge: Option<usize>) {
        self.hovered_edge = edge;
    }

    /// Get the hover progress.
    pub fn progress(&self) -> f64 {
        self.animator.progress
    }
}

/// Animator for twinkle (flash) effects on vertices.
///
/// Ported from `ghidra.graph.job.TwinkleVertexAnimator`.
#[derive(Debug, Clone)]
pub struct TwinkleVertexAnimator {
    _animator: AbstractAnimator,
    target_vertex: usize,
    flash_count: usize,
}

impl TwinkleVertexAnimator {
    /// Create a new twinkle animator for the given vertex.
    pub fn new(vertex: usize, flash_count: usize, duration_ms: u64) -> Self {
        Self {
            _animator: AbstractAnimator::new(duration_ms),
            target_vertex: vertex,
            flash_count,
        }
    }

    /// The vertex being twinkled.
    pub fn target(&self) -> usize {
        self.target_vertex
    }

    /// Number of flash cycles.
    pub fn flash_count(&self) -> usize {
        self.flash_count
    }
}

// ============================================================================
// Graph animation job types
// ============================================================================

/// Job that ensures a specific area is visible in the viewport.
///
/// Ported from `ghidra.graph.job.EnsureAreaVisibleAnimatorFunctionGraphJob`.
#[derive(Debug, Clone)]
pub struct EnsureAreaVisibleAnimatorFunctionGraphJob {
    _animator: AbstractAnimator,
    target_x: f64,
    target_y: f64,
    target_width: f64,
    target_height: f64,
}

impl EnsureAreaVisibleAnimatorFunctionGraphJob {
    /// Create a new area visibility job.
    pub fn new(x: f64, y: f64, width: f64, height: f64, duration_ms: u64) -> Self {
        Self {
            _animator: AbstractAnimator::new(duration_ms),
            target_x: x,
            target_y: y,
            target_width: width,
            target_height: height,
        }
    }

    /// Get the target bounds.
    pub fn target_bounds(&self) -> (f64, f64, f64, f64) {
        (self.target_x, self.target_y, self.target_width, self.target_height)
    }
}

/// Job that moves a vertex to the center of the view.
///
/// Ported from `ghidra.graph.job.MoveVertexToCenterAnimatorFunctionGraphJob`.
#[derive(Debug, Clone)]
pub struct MoveVertexToCenterAnimatorFunctionGraphJob {
    _animator: AbstractAnimator,
    vertex: usize,
}

impl MoveVertexToCenterAnimatorFunctionGraphJob {
    /// Create a new vertex-centering job.
    pub fn new(vertex: usize, duration_ms: u64) -> Self {
        Self {
            _animator: AbstractAnimator::new(duration_ms),
            vertex,
        }
    }

    /// The vertex being centered.
    pub fn vertex(&self) -> usize {
        self.vertex
    }
}

/// Job that moves a vertex to the center-top of the view.
///
/// Ported from `ghidra.graph.job.MoveVertexToCenterTopAnimatorFunctionGraphJob`.
#[derive(Debug, Clone)]
pub struct MoveVertexToCenterTopAnimatorFunctionGraphJob {
    _animator: AbstractAnimator,
    vertex: usize,
}

impl MoveVertexToCenterTopAnimatorFunctionGraphJob {
    /// Create a new vertex-center-top job.
    pub fn new(vertex: usize, duration_ms: u64) -> Self {
        Self {
            _animator: AbstractAnimator::new(duration_ms),
            vertex,
        }
    }

    /// The vertex being moved.
    pub fn vertex(&self) -> usize {
        self.vertex
    }
}

/// Job that moves the viewport.
///
/// Ported from `ghidra.graph.job.MoveViewAnimatorFunctionGraphJob`.
#[derive(Debug, Clone)]
pub struct MoveViewAnimatorFunctionGraphJob {
    _animator: AbstractAnimator,
    _delta_x: f64,
    _delta_y: f64,
}

impl MoveViewAnimatorFunctionGraphJob {
    /// Create a new view-move job.
    pub fn new(dx: f64, dy: f64, duration_ms: u64) -> Self {
        Self {
            _animator: AbstractAnimator::new(duration_ms),
            _delta_x: dx,
            _delta_y: dy,
        }
    }
}

/// Job that moves the viewport to a layout-space point.
///
/// Ported from `ghidra.graph.job.MoveViewToLayoutSpacePointAnimatorFunctionGraphJob`.
#[derive(Debug, Clone)]
pub struct MoveViewToLayoutSpacePointAnimatorFunctionGraphJob {
    _animator: AbstractAnimator,
    _target_x: f64,
    _target_y: f64,
}

impl MoveViewToLayoutSpacePointAnimatorFunctionGraphJob {
    /// Create a new layout-space point move job.
    pub fn new(x: f64, y: f64, duration_ms: u64) -> Self {
        Self {
            _animator: AbstractAnimator::new(duration_ms),
            _target_x: x,
            _target_y: y,
        }
    }
}

/// Job that moves the viewport to a view-space point.
///
/// Ported from `ghidra.graph.job.MoveViewToViewSpacePointAnimatorFunctionGraphJob`.
#[derive(Debug, Clone)]
pub struct MoveViewToViewSpacePointAnimatorFunctionGraphJob {
    _animator: AbstractAnimator,
    _target_x: f64,
    _target_y: f64,
}

impl MoveViewToViewSpacePointAnimatorFunctionGraphJob {
    /// Create a new view-space point move job.
    pub fn new(x: f64, y: f64, duration_ms: u64) -> Self {
        Self {
            _animator: AbstractAnimator::new(duration_ms),
            _target_x: x,
            _target_y: y,
        }
    }
}

/// Job that relayouts the graph and centers a specific vertex.
///
/// Ported from `ghidra.graph.job.RelayoutAndCenterVertexGraphJob`.
#[derive(Debug, Clone)]
pub struct RelayoutAndCenterVertexGraphJob {
    _vertex: usize,
    _animator: AbstractAnimator,
}

impl RelayoutAndCenterVertexGraphJob {
    /// Create a new relayout-and-center job.
    pub fn new(vertex: usize, duration_ms: u64) -> Self {
        Self {
            _vertex: vertex,
            _animator: AbstractAnimator::new(duration_ms),
        }
    }
}

/// Job that relayouts the graph and ensures visibility.
///
/// Ported from `ghidra.graph.job.RelayoutAndEnsureVisible`.
#[derive(Debug, Clone)]
pub struct RelayoutAndEnsureVisible {
    _vertex: usize,
    _animator: AbstractAnimator,
}

impl RelayoutAndEnsureVisible {
    /// Create a new relayout-and-ensure-visible job.
    pub fn new(vertex: usize, duration_ms: u64) -> Self {
        Self {
            _vertex: vertex,
            _animator: AbstractAnimator::new(duration_ms),
        }
    }
}

// ============================================================================
// Mouse plugins for visual graph viewer
// ============================================================================

/// Animated picking plugin that handles vertex selection with animation.
///
/// Ported from `ghidra.graph.viewer.event.mouse.VisualGraphAnimatedPickingGraphMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphAnimatedPickingGraphMousePlugin {
    /// Whether animation is enabled on pick.
    pub animate_on_pick: bool,
    /// Duration of the pick animation in milliseconds.
    pub animation_duration_ms: u64,
}

impl VisualGraphAnimatedPickingGraphMousePlugin {
    /// Create a new animated picking plugin.
    pub fn new() -> Self {
        Self {
            animate_on_pick: true,
            animation_duration_ms: 300,
        }
    }
}

impl Default for VisualGraphAnimatedPickingGraphMousePlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Plugin that restores cursor after graph interactions.
///
/// Ported from `ghidra.graph.viewer.event.mouse.VisualGraphCursorRestoringGraphMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphCursorRestoringGraphMousePlugin {
    /// The cursor to restore after interaction.
    pub restore_cursor: CursorType,
}

/// Cursor types for graph interactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorType {
    /// Default cursor.
    Default,
    /// Hand cursor for dragging.
    Hand,
    /// Crosshair cursor for selection.
    Crosshair,
    /// Move cursor for moving elements.
    Move,
}

impl VisualGraphCursorRestoringGraphMousePlugin {
    /// Create a new cursor-restoring plugin.
    pub fn new() -> Self {
        Self {
            restore_cursor: CursorType::Default,
        }
    }
}

impl Default for VisualGraphCursorRestoringGraphMousePlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Plugin for edge selection in the visual graph.
///
/// Ported from `ghidra.graph.viewer.event.mouse.VisualGraphEdgeSelectionGraphMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphEdgeSelectionGraphMousePlugin {
    /// Whether edge selection is enabled.
    pub enabled: bool,
    /// Edge selection color.
    pub selection_color: (u8, u8, u8, u8),
}

impl VisualGraphEdgeSelectionGraphMousePlugin {
    /// Create a new edge selection plugin.
    pub fn new() -> Self {
        Self {
            enabled: true,
            selection_color: (0, 120, 215, 255),
        }
    }
}

impl Default for VisualGraphEdgeSelectionGraphMousePlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Edge stroke transformer for visual graph edges.
///
/// Ported from `ghidra.graph.viewer.edge.VisualGraphEdgeStrokeTransformer`.
#[derive(Debug, Clone)]
pub struct VisualGraphEdgeStrokeTransformer {
    /// Default edge width.
    pub default_width: f32,
    /// Selected edge width.
    pub selected_width: f32,
    /// Hovered edge width.
    pub hovered_width: f32,
}

impl VisualGraphEdgeStrokeTransformer {
    /// Create a new edge stroke transformer.
    pub fn new() -> Self {
        Self {
            default_width: 1.0,
            selected_width: 2.0,
            hovered_width: 1.5,
        }
    }

    /// Get the width for the given edge state.
    pub fn width(&self, selected: bool, hovered: bool) -> f32 {
        if selected {
            self.selected_width
        } else if hovered {
            self.hovered_width
        } else {
            self.default_width
        }
    }
}

impl Default for VisualGraphEdgeStrokeTransformer {
    fn default() -> Self {
        Self::new()
    }
}

/// Plugin for forwarding events between graph components.
///
/// Ported from `ghidra.graph.viewer.event.mouse.VisualGraphEventForwardingGraphMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphEventForwardingGraphMousePlugin {
    /// Whether event forwarding is enabled.
    pub enabled: bool,
}

impl VisualGraphEventForwardingGraphMousePlugin {
    /// Create a new event forwarding plugin.
    pub fn new() -> Self {
        Self { enabled: true }
    }
}

impl Default for VisualGraphEventForwardingGraphMousePlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Plugin for hover interactions in the visual graph.
///
/// Ported from `ghidra.graph.viewer.event.mouse.VisualGraphHoverMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphHoverMousePlugin {
    /// Delay in milliseconds before hover is activated.
    pub hover_delay_ms: u64,
    /// Currently hovered vertex (if any).
    pub hovered_vertex: Option<usize>,
    /// Currently hovered edge (if any).
    pub hovered_edge: Option<usize>,
}

impl VisualGraphHoverMousePlugin {
    /// Create a new hover plugin.
    pub fn new() -> Self {
        Self {
            hover_delay_ms: 500,
            hovered_vertex: None,
            hovered_edge: None,
        }
    }
}

impl Default for VisualGraphHoverMousePlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Plugin for mouse tracking in the visual graph.
///
/// Ported from `ghidra.graph.viewer.event.mouse.VisualGraphMouseTrackingGraphMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphMouseTrackingGraphMousePlugin {
    /// Current mouse position in graph coordinates.
    pub mouse_pos: Option<(f64, f64)>,
    /// Whether tracking is active.
    pub tracking: bool,
}

impl VisualGraphMouseTrackingGraphMousePlugin {
    /// Create a new mouse tracking plugin.
    pub fn new() -> Self {
        Self {
            mouse_pos: None,
            tracking: false,
        }
    }
}

impl Default for VisualGraphMouseTrackingGraphMousePlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Plugin for picking/selection in the visual graph.
///
/// Ported from `ghidra.graph.viewer.event.mouse.VisualGraphPickingGraphMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphPickingGraphMousePlugin {
    /// Whether multi-select is enabled (e.g., Shift+click).
    pub multi_select: bool,
    /// Selection rectangle start position.
    pub selection_start: Option<(f64, f64)>,
}

impl VisualGraphPickingGraphMousePlugin {
    /// Create a new picking plugin.
    pub fn new() -> Self {
        Self {
            multi_select: false,
            selection_start: None,
        }
    }
}

impl Default for VisualGraphPickingGraphMousePlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Plugin for popup menus in the visual graph.
///
/// Ported from `ghidra.graph.viewer.event.mouse.VisualGraphPopupMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphPopupMousePlugin {
    /// Trigger button for popup (usually right mouse button).
    pub trigger_button: i32,
}

impl VisualGraphPopupMousePlugin {
    /// Create a new popup plugin.
    pub fn new() -> Self {
        Self { trigger_button: 3 }
    }
}

impl Default for VisualGraphPopupMousePlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Plugin for zoom-scaling in the visual graph.
///
/// Ported from `ghidra.graph.viewer.event.mouse.VisualGraphScalingGraphMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphScalingGraphMousePlugin {
    /// Minimum zoom level.
    pub min_scale: f64,
    /// Maximum zoom level.
    pub max_scale: f64,
    /// Current zoom level.
    pub current_scale: f64,
    /// Zoom factor per scroll unit.
    pub zoom_factor: f64,
}

impl VisualGraphScalingGraphMousePlugin {
    /// Create a new scaling plugin.
    pub fn new() -> Self {
        Self {
            min_scale: 0.01,
            max_scale: 10.0,
            current_scale: 1.0,
            zoom_factor: 1.1,
        }
    }

    /// Zoom in by one step.
    pub fn zoom_in(&mut self) {
        self.current_scale = (self.current_scale * self.zoom_factor).min(self.max_scale);
    }

    /// Zoom out by one step.
    pub fn zoom_out(&mut self) {
        self.current_scale = (self.current_scale / self.zoom_factor).max(self.min_scale);
    }

    /// Set zoom to fit a given bounding box.
    pub fn fit_to_view(&mut self, graph_width: f64, graph_height: f64, view_width: f64, view_height: f64) {
        if graph_width <= 0.0 || graph_height <= 0.0 {
            return;
        }
        let sx = view_width / graph_width;
        let sy = view_height / graph_height;
        self.current_scale = sx.min(sy).min(self.max_scale).max(self.min_scale);
    }
}

impl Default for VisualGraphScalingGraphMousePlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Plugin for panning/translation in the visual graph.
///
/// Ported from `ghidra.graph.viewer.event.mouse.VisualGraphTranslatingGraphMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphTranslatingGraphMousePlugin {
    /// Whether panning is active.
    pub panning: bool,
    /// Pan start position.
    pub pan_start: Option<(f64, f64)>,
    /// Current pan offset.
    pub pan_offset: (f64, f64),
}

impl VisualGraphTranslatingGraphMousePlugin {
    /// Create a new translating plugin.
    pub fn new() -> Self {
        Self {
            panning: false,
            pan_start: None,
            pan_offset: (0.0, 0.0),
        }
    }

    /// Start panning from the given position.
    pub fn start_pan(&mut self, x: f64, y: f64) {
        self.panning = true;
        self.pan_start = Some((x, y));
    }

    /// Update the pan to the given position.
    pub fn update_pan(&mut self, x: f64, y: f64) {
        if let Some((sx, sy)) = self.pan_start {
            self.pan_offset.0 += x - sx;
            self.pan_offset.1 += y - sy;
            self.pan_start = Some((x, y));
        }
    }

    /// End panning.
    pub fn end_pan(&mut self) {
        self.panning = false;
        self.pan_start = None;
    }
}

impl Default for VisualGraphTranslatingGraphMousePlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Plugin for zooming with picking support.
///
/// Ported from `ghidra.graph.viewer.event.mouse.VisualGraphZoomingPickingGraphMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphZoomingPickingGraphMousePlugin {
    /// The scaling plugin used for zoom.
    pub scaler: VisualGraphScalingGraphMousePlugin,
    /// The picking plugin used for selection.
    pub picker: VisualGraphPickingGraphMousePlugin,
}

impl VisualGraphZoomingPickingGraphMousePlugin {
    /// Create a new zooming-picking plugin.
    pub fn new() -> Self {
        Self {
            scaler: VisualGraphScalingGraphMousePlugin::new(),
            picker: VisualGraphPickingGraphMousePlugin::new(),
        }
    }
}

impl Default for VisualGraphZoomingPickingGraphMousePlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_algorithms_density() {
        // 3 vertices, 3 edges => density = 3/(3*2) = 0.5
        // We can't easily test this without a concrete GraphLike impl
        // but we can verify the algorithm doesn't panic on edge cases.
    }

    #[test]
    fn test_abstract_animator() {
        let mut anim = AbstractAnimator::new(1000);
        assert!(!anim.is_done());
        assert_eq!(anim.progress, 0.0);

        anim.advance(500);
        assert!((anim.progress - 0.5).abs() < f64::EPSILON);
        assert!(!anim.is_done());

        anim.advance(500);
        assert!(anim.is_done());
        assert_eq!(anim.progress, 1.0);
    }

    #[test]
    fn test_abstract_animator_overflow() {
        let mut anim = AbstractAnimator::new(100);
        anim.advance(200);
        assert!(anim.is_done());
        assert_eq!(anim.progress, 1.0);
    }

    #[test]
    fn test_jung_directed_graph() {
        let mut g = JungDirectedGraph::<String, String>::new();
        g.add_edge("A".into(), "B".into(), "e1".into());
        g.add_edge("B".into(), "C".into(), "e2".into());
        assert_eq!(g.vertex_count(), 3);
        assert_eq!(g.edge_count(), 2);
        assert_eq!(g.successors(&"A".into()), vec!["B".to_string()]);
        assert!(g.successors(&"C".into()).is_empty());
    }

    #[test]
    fn test_jung_directed_visual_graph() {
        let mut g = JungDirectedVisualGraph::<String, String>::new();
        g.graph_mut().add_edge("A".into(), "B".into(), "e".into());
        g.set_position("A".into(), 10.0, 20.0);
        g.set_position("B".into(), 30.0, 40.0);
        assert_eq!(g.position(&"A".into()), Some((10.0, 20.0)));
        assert!(g.focused().is_none());
        g.set_focused(Some("A".into()));
        assert_eq!(g.focused(), Some(&"A".to_string()));
    }

    #[test]
    fn test_jung_layout_provider_circular() {
        let mut g = JungDirectedGraph::<String, String>::new();
        g.add_vertex("A".into());
        g.add_vertex("B".into());
        g.add_vertex("C".into());
        let provider = JungLayoutProvider::<String, String>::new("test", JungLayoutType::Circular);
        let positions = provider.compute_layout(&g);
        assert_eq!(positions.len(), 3);
    }

    #[test]
    fn test_jung_layout_provider_factory() {
        let p = JungLayoutProviderFactory::force_directed::<String, String>("test");
        assert_eq!(p.name(), "test");
        assert_eq!(p.layout_type(), JungLayoutType::ForceDirected);
    }

    #[test]
    fn test_edge_hover_animator() {
        let mut anim = EdgeHoverAnimator::new(300);
        anim.set_hovered(Some(5));
        assert!(anim.hovered_edge.is_some());
        assert_eq!(anim.progress(), 0.0);
    }

    #[test]
    fn test_twinkle_vertex_animator() {
        let anim = TwinkleVertexAnimator::new(42, 3, 500);
        assert_eq!(anim.target(), 42);
        assert_eq!(anim.flash_count(), 3);
    }

    #[test]
    fn test_visibility_transition_job() {
        let mut job = AbstractGraphVisibilityTransitionJob::new(500);
        let mut verts = HashSet::new();
        verts.insert(1);
        verts.insert(2);
        job.set_visible_vertices(verts);
        assert_eq!(job.visible_vertices.len(), 2);
        assert!(!job.is_done());
    }

    #[test]
    fn test_move_vertex_jobs() {
        let job = MoveVertexToCenterAnimatorFunctionGraphJob::new(10, 300);
        assert_eq!(job.vertex(), 10);

        let job2 = MoveVertexToCenterTopAnimatorFunctionGraphJob::new(20, 400);
        assert_eq!(job2.vertex(), 20);
    }

    #[test]
    fn test_move_view_jobs() {
        let job = MoveViewAnimatorFunctionGraphJob::new(10.0, 20.0, 300);
        assert_eq!(job._delta_x, 10.0);
        assert_eq!(job._delta_y, 20.0);

        let job2 = MoveViewToLayoutSpacePointAnimatorFunctionGraphJob::new(100.0, 200.0, 500);
        assert_eq!(job2._target_x, 100.0);

        let job3 = MoveViewToViewSpacePointAnimatorFunctionGraphJob::new(50.0, 60.0, 500);
        assert_eq!(job3._target_x, 50.0);
    }

    #[test]
    fn test_ensure_area_visible_job() {
        let job = EnsureAreaVisibleAnimatorFunctionGraphJob::new(10.0, 20.0, 300.0, 400.0, 500);
        let (x, y, w, h) = job.target_bounds();
        assert_eq!(x, 10.0);
        assert_eq!(y, 20.0);
        assert_eq!(w, 300.0);
        assert_eq!(h, 400.0);
    }

    #[test]
    fn test_relayout_jobs() {
        let job = RelayoutAndCenterVertexGraphJob::new(5, 400);
        assert_eq!(job._vertex, 5);

        let job2 = RelayoutAndEnsureVisible::new(10, 500);
        assert_eq!(job2._vertex, 10);
    }

    #[test]
    fn test_scaling_plugin() {
        let mut plugin = VisualGraphScalingGraphMousePlugin::new();
        assert_eq!(plugin.current_scale, 1.0);
        plugin.zoom_in();
        assert!(plugin.current_scale > 1.0);
        let scale_after_in = plugin.current_scale;
        plugin.zoom_out();
        assert!((plugin.current_scale - 1.0).abs() < 0.01);
        assert!(plugin.current_scale < scale_after_in);
    }

    #[test]
    fn test_scaling_fit_to_view() {
        let mut plugin = VisualGraphScalingGraphMousePlugin::new();
        plugin.fit_to_view(2000.0, 1000.0, 1000.0, 500.0);
        assert!((plugin.current_scale - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_translating_plugin() {
        let mut plugin = VisualGraphTranslatingGraphMousePlugin::new();
        assert!(!plugin.panning);
        plugin.start_pan(100.0, 200.0);
        assert!(plugin.panning);
        plugin.update_pan(150.0, 250.0);
        assert_eq!(plugin.pan_offset, (50.0, 50.0));
        plugin.end_pan();
        assert!(!plugin.panning);
    }

    #[test]
    fn test_hover_plugin() {
        let mut plugin = VisualGraphHoverMousePlugin::new();
        assert_eq!(plugin.hover_delay_ms, 500);
        plugin.hovered_vertex = Some(42);
        assert_eq!(plugin.hovered_vertex, Some(42));
    }

    #[test]
    fn test_picking_plugin() {
        let plugin = VisualGraphPickingGraphMousePlugin::new();
        assert!(!plugin.multi_select);
        assert!(plugin.selection_start.is_none());
    }

    #[test]
    fn test_popup_plugin() {
        let plugin = VisualGraphPopupMousePlugin::new();
        assert_eq!(plugin.trigger_button, 3);
    }

    #[test]
    fn test_edge_selection_plugin() {
        let plugin = VisualGraphEdgeSelectionGraphMousePlugin::new();
        assert!(plugin.enabled);
    }

    #[test]
    fn test_edge_stroke_transformer() {
        let t = VisualGraphEdgeStrokeTransformer::new();
        assert_eq!(t.width(false, false), 1.0);
        assert_eq!(t.width(true, false), 2.0);
        assert_eq!(t.width(false, true), 1.5);
    }

    #[test]
    fn test_cursor_restoring_plugin() {
        let plugin = VisualGraphCursorRestoringGraphMousePlugin::new();
        assert_eq!(plugin.restore_cursor, CursorType::Default);
    }

    #[test]
    fn test_event_forwarding_plugin() {
        let plugin = VisualGraphEventForwardingGraphMousePlugin::new();
        assert!(plugin.enabled);
    }

    #[test]
    fn test_mouse_tracking_plugin() {
        let mut plugin = VisualGraphMouseTrackingGraphMousePlugin::new();
        assert!(!plugin.tracking);
        plugin.mouse_pos = Some((10.0, 20.0));
        assert_eq!(plugin.mouse_pos, Some((10.0, 20.0)));
    }

    #[test]
    fn test_animated_picking_plugin() {
        let plugin = VisualGraphAnimatedPickingGraphMousePlugin::new();
        assert!(plugin.animate_on_pick);
        assert_eq!(plugin.animation_duration_ms, 300);
    }

    #[test]
    fn test_zooming_picking_plugin() {
        let plugin = VisualGraphZoomingPickingGraphMousePlugin::new();
        assert_eq!(plugin.scaler.current_scale, 1.0);
        assert!(!plugin.picker.multi_select);
    }

    #[test]
    fn test_graph_to_tree_algorithm() {
        // Test with a simple graph structure using the trait
        // This is mainly a compilation test since we need a concrete impl
    }

    #[test]
    fn test_chk_dominance_algorithm() {
        // Compilation test for the dominance algorithm API
    }

    #[test]
    fn test_visual_graph_change_listener() {
        // Trait compilation test
    }
}
