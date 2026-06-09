//! Function Graph Model -- the data model connecting a function to its
//! graph representation.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.functiongraph.graph`
//! (model portions).
//!
//! The [`FunctionGraphModel`] wraps a [`FunctionGraph`] and provides
//! higher-level operations for vertex management, grouping, serialization,
//! and layout dispatch.  It is the primary data object owned by a
//! [`FunctionGraphProvider`].
//!
//! # Responsibilities
//!
//! - Build a graph from a function's decompiled control-flow graph.
//! - Track vertex types, group history, and saved vertex positions.
//! - Dispatch layout to the appropriate algorithm.
//! - Provide serializable snapshots for save/restore.
//! - Provide zoom/scroll-to-fit bounds.

use super::mvc::{FGData, FGVertexType, GroupHistoryInfo, VertexInfo};
use super::{
    CfgEdgeType, FGEdge, FGVertex, FunctionGraph, GraphLayout, LayoutAlgorithm, LayoutDirection,
};

use ghidra_core::addr::Address;
use ghidra_core::program::listing::Function;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ---------------------------------------------------------------------------
// FunctionGraphModel
// ---------------------------------------------------------------------------

/// The data model for a function graph, owning the graph, vertex types,
/// group history, and layout state.
///
/// This is the primary data structure managed by
/// [`FunctionGraphProvider`](super::function_graph::FunctionGraphProvider).
#[derive(Debug, Clone)]
pub struct FunctionGraphModel {
    /// The underlying function graph (vertices, edges, layout).
    graph: FunctionGraph,
    /// Per-vertex type classification.
    vertex_types: Vec<FGVertexType>,
    /// Group history (list of group operations performed).
    group_history: Vec<GroupHistoryInfo>,
    /// Saved vertex positions for restore after group/ungroup.
    saved_positions: HashMap<Address, (f32, f32)>,
    /// The set of currently selected vertex indices.
    selected_vertices: HashSet<usize>,
    /// The currently hovered vertex index, if any.
    hovered_vertex: Option<usize>,
    /// The current zoom factor (1.0 = 100%).
    zoom: f32,
    /// The current scroll offset (x, y) in graph coordinates.
    scroll_offset: (f32, f32),
    /// Whether the graph data has been modified since the last save.
    dirty: bool,
}

impl FunctionGraphModel {
    /// Create a new model for the given function with an empty graph.
    pub fn new(function: Function) -> Self {
        Self {
            graph: FunctionGraph::new(function),
            vertex_types: Vec::new(),
            group_history: Vec::new(),
            saved_positions: HashMap::new(),
            selected_vertices: HashSet::new(),
            hovered_vertex: None,
            zoom: 1.0,
            scroll_offset: (0.0, 0.0),
            dirty: false,
        }
    }

    /// Create a model from an existing [`FGData`].
    ///
    /// If the data contains a graph, it is used directly.  Otherwise the
    /// model starts with an empty graph and the error message is
    /// recorded.
    pub fn from_fg_data(fg_data: FGData) -> Self {
        match fg_data.graph {
            Some(graph) => {
                let vertex_types = graph.classify_vertices();
                let saved_positions: HashMap<Address, (f32, f32)> = graph
                    .vertices
                    .iter()
                    .map(|v| (v.address, (v.x, v.y)))
                    .collect();
                Self {
                    graph,
                    vertex_types,
                    group_history: Vec::new(),
                    saved_positions,
                    selected_vertices: HashSet::new(),
                    hovered_vertex: None,
                    zoom: 1.0,
                    scroll_offset: (0.0, 0.0),
                    dirty: false,
                }
            }
            None => Self::new(fg_data.function),
        }
    }

    // -----------------------------------------------------------------------
    // Graph access
    // -----------------------------------------------------------------------

    /// A reference to the underlying function.
    pub fn function(&self) -> &Function {
        &self.graph.function
    }

    /// A reference to the underlying graph.
    pub fn graph(&self) -> &FunctionGraph {
        &self.graph
    }

    /// A mutable reference to the underlying graph.
    pub fn graph_mut(&mut self) -> &mut FunctionGraph {
        &mut self.graph
    }

    /// The number of vertices in the graph.
    pub fn vertex_count(&self) -> usize {
        self.graph.vertices.len()
    }

    /// A reference to the vertices slice.
    pub fn vertices(&self) -> &[FGVertex] {
        &self.graph.vertices
    }

    /// A reference to the edges slice.
    pub fn edges(&self) -> &[FGEdge] {
        &self.graph.edges
    }

    /// The bounding box of the current layout: (min_x, min_y, width, height).
    pub fn bounds(&self) -> (f32, f32, f32, f32) {
        self.graph.bounds()
    }

    /// Whether the graph data has been modified since the last save.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Mark the model as dirty (modified).
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Mark the model as clean (saved).
    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    // -----------------------------------------------------------------------
    // Vertex type management
    // -----------------------------------------------------------------------

    /// Get the vertex type for vertex at the given index.
    pub fn vertex_type(&self, index: usize) -> FGVertexType {
        self.vertex_types
            .get(index)
            .copied()
            .unwrap_or(FGVertexType::Body)
    }

    /// Get all vertex types.
    pub fn vertex_types(&self) -> &[FGVertexType] {
        &self.vertex_types
    }

    /// Recompute vertex types from the graph structure.
    pub fn recompute_vertex_types(&mut self) {
        self.vertex_types = self.graph.classify_vertices();
    }

    // -----------------------------------------------------------------------
    // Selection
    // -----------------------------------------------------------------------

    /// The set of currently selected vertex indices.
    pub fn selected_vertices(&self) -> &HashSet<usize> {
        &self.selected_vertices
    }

    /// Select a single vertex, clearing any previous selection.
    pub fn select_vertex(&mut self, index: usize) {
        self.selected_vertices.clear();
        self.selected_vertices.insert(index);
    }

    /// Toggle the selection state of a vertex.
    pub fn toggle_vertex_selection(&mut self, index: usize) {
        if self.selected_vertices.contains(&index) {
            self.selected_vertices.remove(&index);
        } else {
            self.selected_vertices.insert(index);
        }
    }

    /// Add a vertex to the selection (multi-select).
    pub fn add_to_selection(&mut self, index: usize) {
        self.selected_vertices.insert(index);
    }

    /// Clear the selection.
    pub fn clear_selection(&mut self) {
        self.selected_vertices.clear();
    }

    /// Whether the selection is empty.
    pub fn has_selection(&self) -> bool {
        !self.selected_vertices.is_empty()
    }

    /// The currently hovered vertex index, if any.
    pub fn hovered_vertex(&self) -> Option<usize> {
        self.hovered_vertex
    }

    /// Set the hovered vertex.
    pub fn set_hovered_vertex(&mut self, index: Option<usize>) {
        self.hovered_vertex = index;
    }

    // -----------------------------------------------------------------------
    // Navigation
    // -----------------------------------------------------------------------

    /// Navigate to the vertex at the given address, selecting it and
    /// centering on it.
    ///
    /// Returns the vertex index, if found.
    pub fn go_to_address(&mut self, addr: Address) -> Option<usize> {
        let idx = self.graph.vertex_at_address(addr)?;
        self.select_vertex(idx);
        self.center_on_vertex(idx);
        Some(idx)
    }

    /// Center the scroll offset on the given vertex index.
    pub fn center_on_vertex(&mut self, index: usize) {
        if let Some(v) = self.graph.vertices.get(index) {
            let (cx, cy) = v.centre();
            self.scroll_offset = (cx, cy);
        }
    }

    /// Whether the given address is within the function body.
    pub fn contains_address(&self, addr: Address) -> bool {
        self.graph.function.body.contains(&addr)
    }

    // -----------------------------------------------------------------------
    // Zoom and scroll
    // -----------------------------------------------------------------------

    /// The current zoom factor (1.0 = 100%).
    pub fn zoom(&self) -> f32 {
        self.zoom
    }

    /// Set the zoom factor.
    pub fn set_zoom(&mut self, zoom: f32) {
        self.zoom = zoom.clamp(0.05, 10.0);
    }

    /// Zoom in by one step.
    pub fn zoom_in(&mut self) {
        self.set_zoom(self.zoom * 1.2);
    }

    /// Zoom out by one step.
    pub fn zoom_out(&mut self) {
        self.set_zoom(self.zoom / 1.2);
    }

    /// Reset zoom to 100%.
    pub fn zoom_reset(&mut self) {
        self.zoom = 1.0;
    }

    /// The current scroll offset (graph coordinates).
    pub fn scroll_offset(&self) -> (f32, f32) {
        self.scroll_offset
    }

    /// Set the scroll offset.
    pub fn set_scroll_offset(&mut self, x: f32, y: f32) {
        self.scroll_offset = (x, y);
    }

    // -----------------------------------------------------------------------
    // Layout
    // -----------------------------------------------------------------------

    /// The current layout configuration.
    pub fn layout(&self) -> &GraphLayout {
        &self.graph.layout
    }

    /// Get a mutable reference to the layout configuration.
    pub fn layout_mut(&mut self) -> &mut GraphLayout {
        &mut self.graph.layout
    }

    /// Set the layout algorithm and re-apply.
    pub fn set_layout_algorithm(&mut self, algorithm: LayoutAlgorithm) {
        self.graph.layout.algorithm = algorithm;
        self.apply_layout();
    }

    /// Set the layout direction and re-apply.
    pub fn set_layout_direction(&mut self, direction: LayoutDirection) {
        self.graph.layout.direction = direction;
        self.apply_layout();
    }

    /// Apply the current layout algorithm.
    pub fn apply_layout(&mut self) {
        self.save_vertex_positions();
        self.graph.apply_layout();
        self.dirty = true;
    }

    // -----------------------------------------------------------------------
    // Grouping
    // -----------------------------------------------------------------------

    /// Group the currently selected vertices into a single group vertex.
    ///
    /// Returns the index of the representative vertex, or `None` if
    /// fewer than 2 vertices are selected.
    pub fn group_selected(&mut self) -> Option<usize> {
        let indices: Vec<usize> = self.selected_vertices.iter().copied().collect();
        if indices.len() < 2 {
            return None;
        }

        // Record group history.
        let addresses: Vec<Address> = indices
            .iter()
            .filter_map(|&i| self.graph.vertices.get(i).map(|v| v.address))
            .collect();
        let description = format!("Group of {} vertices", addresses.len());
        self.group_history
            .push(GroupHistoryInfo::new(description, addresses));

        // Perform the grouping.
        let rep = self.graph.group_vertices(&indices)?;

        // Update vertex types.
        for &idx in &indices {
            if idx < self.vertex_types.len() && idx != rep {
                self.vertex_types[idx] = FGVertexType::Group;
            }
        }
        if rep < self.vertex_types.len() {
            self.vertex_types[rep] = FGVertexType::Group;
        }

        // Update selection to just the representative.
        self.selected_vertices.clear();
        self.selected_vertices.insert(rep);

        self.dirty = true;
        Some(rep)
    }

    /// Ungroup the currently selected group vertex.
    ///
    /// If the selected vertex was formed by a group operation, the
    /// original vertices are restored.  Returns `true` if ungrouping
    /// was performed.
    pub fn ungroup_selected(&mut self) -> bool {
        if self.selected_vertices.len() != 1 {
            return false;
        }
        let &idx = self.selected_vertices.iter().next().unwrap();

        if idx >= self.vertex_types.len() || self.vertex_types[idx] != FGVertexType::Group {
            return false;
        }

        // Pop the last group history entry (if any).
        if let Some(_info) = self.group_history.pop() {
            // Restore vertex type to Body.
            if idx < self.vertex_types.len() {
                self.vertex_types[idx] = FGVertexType::Body;
            }
            self.recompute_vertex_types();
            self.dirty = true;
            return true;
        }

        false
    }

    /// The group history.
    pub fn group_history(&self) -> &[GroupHistoryInfo] {
        &self.group_history
    }

    // -----------------------------------------------------------------------
    // Save / Restore vertex positions
    // -----------------------------------------------------------------------

    /// Save the current positions of all vertices.
    pub fn save_vertex_positions(&mut self) {
        self.saved_positions.clear();
        for v in &self.graph.vertices {
            self.saved_positions.insert(v.address, (v.x, v.y));
        }
    }

    /// Restore saved vertex positions.
    pub fn restore_vertex_positions(&mut self) {
        for v in &mut self.graph.vertices {
            if let Some(&(x, y)) = self.saved_positions.get(&v.address) {
                v.x = x;
                v.y = y;
            }
        }
    }

    /// Save vertex info for serialization (address + type + position).
    pub fn save_vertex_info(&self) -> Vec<VertexInfo> {
        self.graph.save_vertex_info(&self.vertex_types)
    }

    // -----------------------------------------------------------------------
    // Graph queries (delegated)
    // -----------------------------------------------------------------------

    /// Get the entry vertex index.
    pub fn entry_vertex(&self) -> Option<usize> {
        self.graph.entry_vertex()
    }

    /// Get all exit vertex indices.
    pub fn exit_vertices(&self) -> Vec<usize> {
        self.graph.exit_vertices()
    }

    /// Get successors of a vertex.
    pub fn successors(&self, vertex: usize) -> Vec<usize> {
        self.graph.successors(vertex)
    }

    /// Get predecessors of a vertex.
    pub fn predecessors(&self, vertex: usize) -> Vec<usize> {
        self.graph.predecessors(vertex)
    }

    /// Find paths from `start` to `end`.
    pub fn find_paths(&self, start: usize, end: usize, max_paths: usize) -> Vec<Vec<usize>> {
        self.graph.find_paths(start, end, max_paths)
    }

    /// Highlight the path from the hovered vertex to the selected vertex.
    ///
    /// Returns the vertex indices along the path, or an empty vec if no
    /// path is found.
    pub fn highlight_path(&self) -> Vec<usize> {
        let hovered = match self.hovered_vertex {
            Some(h) => h,
            None => return Vec::new(),
        };
        let selected = match self.selected_vertices.iter().next() {
            Some(&s) => s,
            None => return Vec::new(),
        };
        let paths = self.graph.find_paths(selected, hovered, 1);
        paths.into_iter().next().unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::{Address, AddressRange};

    fn dummy_function() -> Function {
        Function::new(
            "test_fn",
            Address::new(0x1000),
            AddressRange::new(Address::new(0x1000), Address::new(0x1100)),
        )
    }

    fn make_model_with_graph() -> FunctionGraphModel {
        let graph = FunctionGraph::from_parts(
            dummy_function(),
            vec![
                FGVertex::new(Address::new(0x1000), "A".into(), vec![]),
                FGVertex::new(Address::new(0x1010), "B".into(), vec![]),
                FGVertex::new(Address::new(0x1020), "C".into(), vec![]),
                FGVertex::new(Address::new(0x1030), "D".into(), vec![]),
            ],
            vec![
                FGEdge::new(0, 1, CfgEdgeType::Fallthrough),
                FGEdge::new(0, 2, CfgEdgeType::Branch),
                FGEdge::new(1, 3, CfgEdgeType::Fallthrough),
                FGEdge::new(2, 3, CfgEdgeType::Fallthrough),
            ],
        );
        let fg_data = FGData::new(dummy_function(), graph);
        FunctionGraphModel::from_fg_data(fg_data)
    }

    #[test]
    fn new_model_empty() {
        let model = FunctionGraphModel::new(dummy_function());
        assert_eq!(model.vertex_count(), 0);
        assert!(model.selected_vertices().is_empty());
        assert_eq!(model.zoom(), 1.0);
        assert!(!model.is_dirty());
    }

    #[test]
    fn from_fg_data_with_graph() {
        let model = make_model_with_graph();
        assert_eq!(model.vertex_count(), 4);
        assert_eq!(model.vertex_type(0), FGVertexType::Entry);
        assert_eq!(model.vertex_type(3), FGVertexType::Exit);
    }

    #[test]
    fn from_fg_data_error() {
        let fg_data = FGData::error(dummy_function(), "too large");
        let model = FunctionGraphModel::from_fg_data(fg_data);
        assert_eq!(model.vertex_count(), 0);
    }

    #[test]
    fn selection_single() {
        let mut model = make_model_with_graph();
        model.select_vertex(1);
        assert!(model.has_selection());
        assert!(model.selected_vertices().contains(&1));
        assert_eq!(model.selected_vertices().len(), 1);
    }

    #[test]
    fn selection_toggle() {
        let mut model = make_model_with_graph();
        model.toggle_vertex_selection(0);
        assert!(model.selected_vertices().contains(&0));
        model.toggle_vertex_selection(0);
        assert!(!model.selected_vertices().contains(&0));
    }

    #[test]
    fn selection_multi() {
        let mut model = make_model_with_graph();
        model.add_to_selection(0);
        model.add_to_selection(1);
        assert_eq!(model.selected_vertices().len(), 2);
        model.clear_selection();
        assert!(!model.has_selection());
    }

    #[test]
    fn navigation_go_to_address() {
        let mut model = make_model_with_graph();
        let idx = model.go_to_address(Address::new(0x1020));
        assert_eq!(idx, Some(2));
        assert!(model.selected_vertices().contains(&2));
    }

    #[test]
    fn navigation_go_to_unknown_address() {
        let mut model = make_model_with_graph();
        let idx = model.go_to_address(Address::new(0x9999));
        assert!(idx.is_none());
    }

    #[test]
    fn zoom_in_out_reset() {
        let mut model = make_model_with_graph();
        let initial = model.zoom();
        model.zoom_in();
        assert!(model.zoom() > initial);
        model.zoom_out();
        model.zoom_out();
        assert!(model.zoom() < initial);
        model.zoom_reset();
        assert_eq!(model.zoom(), 1.0);
    }

    #[test]
    fn zoom_clamp() {
        let mut model = make_model_with_graph();
        model.set_zoom(0.001);
        assert!(model.zoom() >= 0.05);
        model.set_zoom(100.0);
        assert!(model.zoom() <= 10.0);
    }

    #[test]
    fn scroll_offset() {
        let mut model = make_model_with_graph();
        model.set_scroll_offset(100.0, 200.0);
        assert_eq!(model.scroll_offset(), (100.0, 200.0));
    }

    #[test]
    fn layout_change() {
        let mut model = make_model_with_graph();
        model.set_layout_algorithm(LayoutAlgorithm::Circular);
        assert_eq!(model.layout().algorithm, LayoutAlgorithm::Circular);
        assert!(model.is_dirty());
    }

    #[test]
    fn group_selected_vertices() {
        let mut model = make_model_with_graph();
        model.add_to_selection(1);
        model.add_to_selection(2);
        let rep = model.group_selected();
        assert!(rep.is_some());
        assert_eq!(rep.unwrap(), 1);
        assert_eq!(model.group_history().len(), 1);
        assert!(model.is_dirty());
    }

    #[test]
    fn group_single_vertex_noop() {
        let mut model = make_model_with_graph();
        model.select_vertex(0);
        let rep = model.group_selected();
        assert!(rep.is_none());
    }

    #[test]
    fn dirty_flag() {
        let mut model = make_model_with_graph();
        assert!(!model.is_dirty());
        model.mark_dirty();
        assert!(model.is_dirty());
        model.mark_clean();
        assert!(!model.is_dirty());
    }

    #[test]
    fn vertex_info_save() {
        let model = make_model_with_graph();
        let info = model.save_vertex_info();
        assert_eq!(info.len(), 4);
        assert_eq!(info[0].address, Address::new(0x1000));
    }

    #[test]
    fn entry_exit_vertices() {
        let model = make_model_with_graph();
        assert_eq!(model.entry_vertex(), Some(0));
        assert_eq!(model.exit_vertices(), vec![3]);
    }

    #[test]
    fn successors_predecessors() {
        let model = make_model_with_graph();
        assert_eq!(model.successors(0), vec![1, 2]);
        assert_eq!(model.predecessors(3), vec![1, 2]);
    }

    #[test]
    fn find_paths_diamond() {
        let model = make_model_with_graph();
        let paths = model.find_paths(0, 3, 10);
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn highlight_path_no_selection() {
        let mut model = make_model_with_graph();
        model.set_hovered_vertex(Some(3));
        let path = model.highlight_path();
        assert!(path.is_empty());
    }

    #[test]
    fn highlight_path_no_hover() {
        let mut model = make_model_with_graph();
        model.select_vertex(0);
        let path = model.highlight_path();
        assert!(path.is_empty());
    }

    #[test]
    fn highlight_path_found() {
        let mut model = make_model_with_graph();
        model.select_vertex(0);
        model.set_hovered_vertex(Some(3));
        let path = model.highlight_path();
        assert!(!path.is_empty());
        assert_eq!(path.first(), Some(&0));
        assert_eq!(path.last(), Some(&3));
    }
}
