//! Graph viewer types for graph services.
//!
//! Ported from Ghidra's `ghidra.graph.viewer.GraphViewer` Java class and
//! the `ghidra.service.graph.GraphViewer` interface.
//!
//! The [`GraphViewer`] struct represents a graph visualization component that
//! manages the rendering, interaction, and layout of a graph. It provides
//! methods for selection, zoom/pan, path highlighting, and vertex/edge
//! navigation.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock};

use super::layout::{
    GridLocationMap, LayoutPositions, LayoutProvider, LayoutProviderRegistry,
    RelayoutOption, ViewRestoreOption,
};

// ============================================================================
// Point2d / Rect2d
// ============================================================================

/// A 2D point with f64 coordinates.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Point2d {
    pub x: f64,
    pub y: f64,
}

impl Point2d {
    pub fn new(x: f64, y: f64) -> Self {
        Self { x, y }
    }

    pub fn distance_to(&self, other: &Point2d) -> f64 {
        ((self.x - other.x).powi(2) + (self.y - other.y).powi(2)).sqrt()
    }
}

impl Default for Point2d {
    fn default() -> Self {
        Self { x: 0.0, y: 0.0 }
    }
}

/// A rectangle defined by position and size.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rect2d {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

impl Rect2d {
    pub fn new(x: f64, y: f64, width: f64, height: f64) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    /// Check if this rectangle contains a point.
    pub fn contains_point(&self, px: f64, py: f64) -> bool {
        px >= self.x
            && px <= self.x + self.width
            && py >= self.y
            && py <= self.y + self.height
    }

    /// Get the center of this rectangle.
    pub fn center(&self) -> Point2d {
        Point2d::new(self.x + self.width / 2.0, self.y + self.height / 2.0)
    }

    /// Check if this rectangle intersects another.
    pub fn intersects(&self, other: &Rect2d) -> bool {
        self.x < other.x + other.width
            && self.x + self.width > other.x
            && self.y < other.y + other.height
            && self.y + self.height > other.y
    }
}

impl Default for Rect2d {
    fn default() -> Self {
        Self {
            x: 0.0,
            y: 0.0,
            width: 0.0,
            height: 0.0,
        }
    }
}

// ============================================================================
// PathHighlightMode
// ============================================================================

/// Path highlight modes for edge highlighting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathHighlightMode {
    /// Do not highlight paths.
    None,
    /// Highlight the shortest path between selected vertices.
    ShortestPath,
    /// Highlight all paths between selected vertices.
    AllPaths,
    /// Highlight the dominator path.
    DominatorPath,
}

impl Default for PathHighlightMode {
    fn default() -> Self {
        Self::None
    }
}

impl std::fmt::Display for PathHighlightMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::ShortestPath => write!(f, "Shortest Path"),
            Self::AllPaths => write!(f, "All Paths"),
            Self::DominatorPath => write!(f, "Dominator Path"),
        }
    }
}

// ============================================================================
// PickingMode
// ============================================================================

/// How vertices are picked (selected) in the graph viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PickingMode {
    /// Click to select a single vertex (deselects others).
    Single,
    /// Ctrl+click to toggle individual vertex selection.
    Toggle,
    /// Click to select a vertex and all its neighbors.
    Neighborhood,
}

impl Default for PickingMode {
    fn default() -> Self {
        Self::Single
    }
}

// ============================================================================
// ViewState
// ============================================================================

/// Zoom/pan state for a graph viewer.
#[derive(Debug, Clone)]
pub struct ViewState {
    /// Current zoom level (1.0 = 100%).
    pub zoom: f64,
    /// Pan offset X.
    pub pan_x: f64,
    /// Pan offset Y.
    pub pan_y: f64,
    /// Viewport width.
    pub viewport_width: f64,
    /// Viewport height.
    pub viewport_height: f64,
}

impl Default for ViewState {
    fn default() -> Self {
        Self {
            zoom: 1.0,
            pan_x: 0.0,
            pan_y: 0.0,
            viewport_width: 800.0,
            viewport_height: 600.0,
        }
    }
}

impl ViewState {
    /// Zoom in by a factor.
    pub fn zoom_in(&mut self, factor: f64) {
        self.zoom = (self.zoom * factor).min(10.0);
    }

    /// Zoom out by a factor.
    pub fn zoom_out(&mut self, factor: f64) {
        self.zoom = (self.zoom / factor).max(0.1);
    }

    /// Reset to default zoom and pan.
    pub fn reset(&mut self) {
        self.zoom = 1.0;
        self.pan_x = 0.0;
        self.pan_y = 0.0;
    }

    /// Center the view on a point.
    pub fn center_on(&mut self, x: f64, y: f64) {
        self.pan_x = x - self.viewport_width / 2.0;
        self.pan_y = y - self.viewport_height / 2.0;
    }

    /// Convert a screen point to world coordinates.
    pub fn screen_to_world(&self, screen_x: f64, screen_y: f64) -> Point2d {
        Point2d::new(
            (screen_x - self.pan_x) / self.zoom,
            (screen_y - self.pan_y) / self.zoom,
        )
    }

    /// Convert a world point to screen coordinates.
    pub fn world_to_screen(&self, world_x: f64, world_y: f64) -> Point2d {
        Point2d::new(
            world_x * self.zoom + self.pan_x,
            world_y * self.zoom + self.pan_y,
        )
    }
}

// ============================================================================
// GraphViewerOptions
// ============================================================================

/// Configuration options for a graph viewer.
#[derive(Debug, Clone)]
pub struct GraphViewerOptions {
    /// Picking mode.
    pub picking_mode: PickingMode,
    /// Path highlight mode.
    pub highlight_mode: PathHighlightMode,
    /// Whether to show vertex labels.
    pub show_labels: bool,
    /// Whether to show edge labels.
    pub show_edge_labels: bool,
    /// Whether to allow vertex dragging.
    pub allow_drag: bool,
    /// Whether to show the satellite (overview) view.
    pub show_satellite: bool,
    /// Padding between vertices (in pixels).
    pub padding: f64,
    /// Whether to animate layout transitions.
    pub animate_transitions: bool,
}

impl Default for GraphViewerOptions {
    fn default() -> Self {
        Self {
            picking_mode: PickingMode::default(),
            highlight_mode: PathHighlightMode::default(),
            show_labels: true,
            show_edge_labels: false,
            allow_drag: true,
            show_satellite: false,
            padding: 20.0,
            animate_transitions: true,
        }
    }
}

// ============================================================================
// GraphViewer
// ============================================================================

/// The main graph viewer component.
///
/// Ported from Ghidra's `ghidra.graph.viewer.GraphViewer` and
/// `ghidra.service.graph.GraphViewer`.
///
/// Manages the rendering, interaction, and layout of a graph. Provides
/// methods for selection, zoom/pan, path highlighting, and vertex/edge
/// navigation.
pub struct GraphViewer {
    /// Viewer configuration options.
    pub options: GraphViewerOptions,
    /// Current view state (zoom, pan).
    view_state: ViewState,
    /// Selected vertex IDs.
    selected_vertices: HashSet<usize>,
    /// Focused vertex ID (the "primary" selection).
    focused_vertex: Option<usize>,
    /// Hovered vertex ID.
    hovered_vertex: Option<usize>,
    /// Hovered edge ID.
    hovered_edge: Option<(usize, usize)>,
    /// Layout provider registry.
    layout_registry: LayoutProviderRegistry,
    /// Current layout positions.
    layout_positions: LayoutPositions,
    /// Vertex positions in world space.
    vertex_positions: HashMap<usize, Point2d>,
    /// Edge routes: (from, to) -> list of waypoints.
    edge_routes: HashMap<(usize, usize), Vec<Point2d>>,
    /// Adjacency list: vertex_id -> list of successor vertex_ids.
    adjacency: HashMap<usize, Vec<usize>>,
    /// Reverse adjacency list: vertex_id -> list of predecessor vertex_ids.
    reverse_adjacency: HashMap<usize, Vec<usize>>,
    /// Whether the viewer is enabled (responds to input).
    enabled: bool,
}

impl GraphViewer {
    /// Create a new graph viewer with default settings.
    pub fn new() -> Self {
        Self {
            options: GraphViewerOptions::default(),
            view_state: ViewState::default(),
            selected_vertices: HashSet::new(),
            focused_vertex: None,
            hovered_vertex: None,
            hovered_edge: None,
            layout_registry: LayoutProviderRegistry::new(),
            layout_positions: LayoutPositions::new(),
            vertex_positions: HashMap::new(),
            edge_routes: HashMap::new(),
            adjacency: HashMap::new(),
            reverse_adjacency: HashMap::new(),
            enabled: true,
        }
    }

    /// Create a new graph viewer with custom options.
    pub fn with_options(options: GraphViewerOptions) -> Self {
        Self {
            options,
            ..Self::new()
        }
    }

    // ------------------------------------------------------------------
    // View state
    // ------------------------------------------------------------------

    /// Get the current view state.
    pub fn view_state(&self) -> &ViewState {
        &self.view_state
    }

    /// Get a mutable reference to the view state.
    pub fn view_state_mut(&mut self) -> &mut ViewState {
        &mut self.view_state
    }

    /// Get the current zoom level.
    pub fn zoom(&self) -> f64 {
        self.view_state.zoom
    }

    /// Set the zoom level.
    pub fn set_zoom(&mut self, zoom: f64) {
        self.view_state.zoom = zoom.clamp(0.01, 10.0);
    }

    /// Zoom in.
    pub fn zoom_in(&mut self) {
        self.view_state.zoom_in(1.2);
    }

    /// Zoom out.
    pub fn zoom_out(&mut self) {
        self.view_state.zoom_out(1.2);
    }

    /// Fit the graph within the viewport.
    pub fn fit_graph(&mut self) {
        if self.vertex_positions.is_empty() {
            return;
        }

        let mut min_x = f64::MAX;
        let mut min_y = f64::MAX;
        let mut max_x = f64::MIN;
        let mut max_y = f64::MIN;

        for pos in self.vertex_positions.values() {
            min_x = min_x.min(pos.x);
            min_y = min_y.min(pos.y);
            max_x = max_x.max(pos.x);
            max_y = max_y.max(pos.y);
        }

        let padding = self.options.padding;
        let graph_width = max_x - min_x + 2.0 * padding;
        let graph_height = max_y - min_y + 2.0 * padding;

        if graph_width > 0.0 && graph_height > 0.0 {
            let zoom_x = self.view_state.viewport_width / graph_width;
            let zoom_y = self.view_state.viewport_height / graph_height;
            self.view_state.zoom = zoom_x.min(zoom_y).min(2.0).max(0.1);

            self.view_state.pan_x =
                (self.view_state.viewport_width - graph_width * self.view_state.zoom) / 2.0;
            self.view_state.pan_y =
                (self.view_state.viewport_height - graph_height * self.view_state.zoom) / 2.0;
        }
    }

    // ------------------------------------------------------------------
    // Selection
    // ------------------------------------------------------------------

    /// Get the set of selected vertex IDs.
    pub fn selected_vertices(&self) -> &HashSet<usize> {
        &self.selected_vertices
    }

    /// Select a vertex.
    pub fn select_vertex(&mut self, vertex_id: usize) {
        match self.options.picking_mode {
            PickingMode::Single => {
                self.selected_vertices.clear();
                self.selected_vertices.insert(vertex_id);
                self.focused_vertex = Some(vertex_id);
            }
            PickingMode::Toggle => {
                if self.selected_vertices.contains(&vertex_id) {
                    self.selected_vertices.remove(&vertex_id);
                    if self.focused_vertex == Some(vertex_id) {
                        self.focused_vertex = self.selected_vertices.iter().next().copied();
                    }
                } else {
                    self.selected_vertices.insert(vertex_id);
                    self.focused_vertex = Some(vertex_id);
                }
            }
            PickingMode::Neighborhood => {
                self.selected_vertices.clear();
                self.selected_vertices.insert(vertex_id);
                // Add neighbors
                if let Some(successors) = self.adjacency.get(&vertex_id) {
                    self.selected_vertices.extend(successors);
                }
                if let Some(predecessors) = self.reverse_adjacency.get(&vertex_id) {
                    self.selected_vertices.extend(predecessors);
                }
                self.focused_vertex = Some(vertex_id);
            }
        }
    }

    /// Deselect a vertex.
    pub fn deselect_vertex(&mut self, vertex_id: usize) {
        self.selected_vertices.remove(&vertex_id);
        if self.focused_vertex == Some(vertex_id) {
            self.focused_vertex = self.selected_vertices.iter().next().copied();
        }
    }

    /// Clear all selections.
    pub fn clear_selection(&mut self) {
        self.selected_vertices.clear();
        self.focused_vertex = None;
    }

    /// Get the focused vertex ID.
    pub fn focused_vertex(&self) -> Option<usize> {
        self.focused_vertex
    }

    /// Set the focused vertex.
    pub fn set_focused_vertex(&mut self, vertex_id: Option<usize>) {
        self.focused_vertex = vertex_id;
        if let Some(id) = vertex_id {
            self.selected_vertices.insert(id);
        }
    }

    // ------------------------------------------------------------------
    // Hover
    // ------------------------------------------------------------------

    /// Get the hovered vertex ID.
    pub fn hovered_vertex(&self) -> Option<usize> {
        self.hovered_vertex
    }

    /// Set the hovered vertex.
    pub fn set_hovered_vertex(&mut self, vertex_id: Option<usize>) {
        self.hovered_vertex = vertex_id;
    }

    /// Get the hovered edge.
    pub fn hovered_edge(&self) -> Option<(usize, usize)> {
        self.hovered_edge
    }

    /// Set the hovered edge.
    pub fn set_hovered_edge(&mut self, edge: Option<(usize, usize)>) {
        self.hovered_edge = edge;
    }

    // ------------------------------------------------------------------
    // Graph structure
    // ------------------------------------------------------------------

    /// Add a vertex to the viewer.
    pub fn add_vertex(&mut self, vertex_id: usize, position: Point2d) {
        self.vertex_positions.insert(vertex_id, position);
        self.adjacency.entry(vertex_id).or_default();
        self.reverse_adjacency.entry(vertex_id).or_default();
    }

    /// Remove a vertex from the viewer.
    pub fn remove_vertex(&mut self, vertex_id: usize) {
        self.vertex_positions.remove(&vertex_id);
        self.selected_vertices.remove(&vertex_id);
        if self.focused_vertex == Some(vertex_id) {
            self.focused_vertex = None;
        }
        if self.hovered_vertex == Some(vertex_id) {
            self.hovered_vertex = None;
        }

        // Remove edges involving this vertex
        if let Some(successors) = self.adjacency.remove(&vertex_id) {
            for succ in &successors {
                if let Some(preds) = self.reverse_adjacency.get_mut(succ) {
                    preds.retain(|&id| id != vertex_id);
                }
                self.edge_routes.remove(&(vertex_id, *succ));
            }
        }
        if let Some(predecessors) = self.reverse_adjacency.remove(&vertex_id) {
            for pred in &predecessors {
                if let Some(succs) = self.adjacency.get_mut(pred) {
                    succs.retain(|&id| id != vertex_id);
                }
                self.edge_routes.remove(&(*pred, vertex_id));
            }
        }
    }

    /// Add an edge between two vertices.
    pub fn add_edge(&mut self, from_id: usize, to_id: usize) {
        self.adjacency
            .entry(from_id)
            .or_default()
            .push(to_id);
        self.reverse_adjacency
            .entry(to_id)
            .or_default()
            .push(from_id);
    }

    /// Add an edge with route waypoints.
    pub fn add_edge_with_route(
        &mut self,
        from_id: usize,
        to_id: usize,
        route: Vec<Point2d>,
    ) {
        self.add_edge(from_id, to_id);
        self.edge_routes.insert((from_id, to_id), route);
    }

    /// Remove an edge.
    pub fn remove_edge(&mut self, from_id: usize, to_id: usize) {
        if let Some(successors) = self.adjacency.get_mut(&from_id) {
            successors.retain(|&id| id != to_id);
        }
        if let Some(predecessors) = self.reverse_adjacency.get_mut(&to_id) {
            predecessors.retain(|&id| id != from_id);
        }
        self.edge_routes.remove(&(from_id, to_id));
    }

    /// Get the successors of a vertex.
    pub fn successors(&self, vertex_id: usize) -> &[usize] {
        self.adjacency
            .get(&vertex_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get the predecessors of a vertex.
    pub fn predecessors(&self, vertex_id: usize) -> &[usize] {
        self.reverse_adjacency
            .get(&vertex_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get the position of a vertex.
    pub fn vertex_position(&self, vertex_id: usize) -> Option<Point2d> {
        self.vertex_positions.get(&vertex_id).copied()
    }

    /// Set the position of a vertex.
    pub fn set_vertex_position(&mut self, vertex_id: usize, position: Point2d) {
        self.vertex_positions.insert(vertex_id, position);
    }

    /// Get the number of vertices.
    pub fn vertex_count(&self) -> usize {
        self.vertex_positions.len()
    }

    /// Get the number of edges.
    pub fn edge_count(&self) -> usize {
        self.adjacency.values().map(|v| v.len()).sum()
    }

    /// Get all vertex IDs.
    pub fn vertex_ids(&self) -> Vec<usize> {
        self.vertex_positions.keys().copied().collect()
    }

    /// Get all edges as (from, to) pairs.
    pub fn edges(&self) -> Vec<(usize, usize)> {
        let mut result = Vec::new();
        for (&from, tos) in &self.adjacency {
            for &to in tos {
                result.push((from, to));
            }
        }
        result
    }

    /// Get the bounding box of all vertices.
    pub fn bounds(&self) -> Rect2d {
        if self.vertex_positions.is_empty() {
            return Rect2d::default();
        }

        let mut min_x = f64::MAX;
        let mut min_y = f64::MAX;
        let mut max_x = f64::MIN;
        let mut max_y = f64::MIN;

        for pos in self.vertex_positions.values() {
            min_x = min_x.min(pos.x);
            min_y = min_y.min(pos.y);
            max_x = max_x.max(pos.x);
            max_y = max_y.max(pos.y);
        }

        let padding = self.options.padding;
        Rect2d::new(
            min_x - padding,
            min_y - padding,
            max_x - min_x + 2.0 * padding,
            max_y - min_y + 2.0 * padding,
        )
    }

    // ------------------------------------------------------------------
    // Hit testing
    // ------------------------------------------------------------------

    /// Find the vertex at the given world coordinates.
    pub fn find_vertex_at(&self, world_x: f64, world_y: f64) -> Option<usize> {
        // Simple point-in-rect test with a default vertex size
        let hit_size = 40.0; // Default vertex size
        for (&id, pos) in &self.vertex_positions {
            let rect = Rect2d::new(
                pos.x - hit_size / 2.0,
                pos.y - hit_size / 2.0,
                hit_size,
                hit_size,
            );
            if rect.contains_point(world_x, world_y) {
                return Some(id);
            }
        }
        None
    }

    /// Find the vertex at the given screen coordinates.
    pub fn find_vertex_at_screen(&self, screen_x: f64, screen_y: f64) -> Option<usize> {
        let world = self.view_state.screen_to_world(screen_x, screen_y);
        self.find_vertex_at(world.x, world.y)
    }

    // ------------------------------------------------------------------
    // Layout
    // ------------------------------------------------------------------

    /// Get the layout provider registry.
    pub fn layout_registry(&self) -> &LayoutProviderRegistry {
        &self.layout_registry
    }

    /// Get a mutable reference to the layout provider registry.
    pub fn layout_registry_mut(&mut self) -> &mut LayoutProviderRegistry {
        &mut self.layout_registry
    }

    /// Apply a layout algorithm to the graph.
    pub fn apply_layout(&mut self, layout_name: &str) -> Result<(), String> {
        let provider = self
            .layout_registry
            .get(layout_name)
            .ok_or_else(|| format!("Layout provider '{}' not found", layout_name))?
            .clone();

        let vertex_ids: Vec<usize> = self.vertex_positions.keys().copied().collect();
        let edges: Vec<(usize, usize)> = self.edges();

        let grid_map = provider.compute_grid_locations(&vertex_ids, &edges);

        // Convert grid positions to world positions
        let cell_width = 200.0;
        let cell_height = 100.0;

        for (id, point) in grid_map.iter() {
            let x = point.col.index() as f64 * cell_width;
            let y = point.row.index() as f64 * cell_height;
            self.vertex_positions.insert(id, Point2d::new(x, y));
        }

        // Fit the graph within the viewport
        self.fit_graph();

        Ok(())
    }

    /// Get the current layout positions.
    pub fn layout_positions(&self) -> &LayoutPositions {
        &self.layout_positions
    }

    // ------------------------------------------------------------------
    // Path finding
    // ------------------------------------------------------------------

    /// Find the shortest path between two vertices using BFS.
    pub fn find_shortest_path(&self, from_id: usize, to_id: usize) -> Option<Vec<usize>> {
        if !self.vertex_positions.contains_key(&from_id)
            || !self.vertex_positions.contains_key(&to_id)
        {
            return None;
        }

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut parent: HashMap<usize, usize> = HashMap::new();

        visited.insert(from_id);
        queue.push_back(from_id);

        while let Some(u) = queue.pop_front() {
            if u == to_id {
                // Reconstruct path
                let mut path = Vec::new();
                let mut cur = to_id;
                path.push(cur);
                while cur != from_id {
                    cur = *parent.get(&cur)?;
                    path.push(cur);
                }
                path.reverse();
                return Some(path);
            }

            for &succ in self.successors(u) {
                if !visited.contains(&succ) {
                    visited.insert(succ);
                    parent.insert(succ, u);
                    queue.push_back(succ);
                }
            }
        }

        None
    }

    /// Find all paths between two vertices using DFS.
    pub fn find_all_paths(
        &self,
        from_id: usize,
        to_id: usize,
        max_paths: usize,
    ) -> Vec<Vec<usize>> {
        let mut paths = Vec::new();
        let mut current_path = Vec::new();
        let mut visited = HashSet::new();

        self.dfs_find_paths(from_id, to_id, &mut visited, &mut current_path, &mut paths, max_paths);
        paths
    }

    fn dfs_find_paths(
        &self,
        current: usize,
        target: usize,
        visited: &mut HashSet<usize>,
        current_path: &mut Vec<usize>,
        paths: &mut Vec<Vec<usize>>,
        max_paths: usize,
    ) {
        if paths.len() >= max_paths {
            return;
        }

        visited.insert(current);
        current_path.push(current);

        if current == target {
            paths.push(current_path.clone());
        } else {
            for &succ in self.successors(current) {
                if !visited.contains(&succ) {
                    self.dfs_find_paths(succ, target, visited, current_path, paths, max_paths);
                }
            }
        }

        current_path.pop();
        visited.remove(&current);
    }

    // ------------------------------------------------------------------
    // Enabled state
    // ------------------------------------------------------------------

    /// Whether the viewer is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set whether the viewer is enabled.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl Default for GraphViewer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_point2d() {
        let p1 = Point2d::new(0.0, 0.0);
        let p2 = Point2d::new(3.0, 4.0);
        assert_eq!(p1.distance_to(&p2), 5.0);
    }

    #[test]
    fn test_rect2d_contains() {
        let rect = Rect2d::new(10.0, 10.0, 100.0, 100.0);
        assert!(rect.contains_point(50.0, 50.0));
        assert!(!rect.contains_point(5.0, 5.0));
        assert!(!rect.contains_point(150.0, 150.0));
    }

    #[test]
    fn test_rect2d_intersects() {
        let r1 = Rect2d::new(0.0, 0.0, 100.0, 100.0);
        let r2 = Rect2d::new(50.0, 50.0, 100.0, 100.0);
        let r3 = Rect2d::new(200.0, 200.0, 100.0, 100.0);

        assert!(r1.intersects(&r2));
        assert!(!r1.intersects(&r3));
    }

    #[test]
    fn test_view_state_zoom() {
        let mut vs = ViewState::default();
        assert_eq!(vs.zoom, 1.0);

        vs.zoom_in(2.0);
        assert_eq!(vs.zoom, 2.0);

        vs.zoom_out(2.0);
        assert_eq!(vs.zoom, 1.0);

        vs.zoom_in(100.0);
        assert_eq!(vs.zoom, 10.0);

        vs.zoom_out(100.0);
        vs.zoom_out(100.0);
        assert_eq!(vs.zoom, 0.1);
    }

    #[test]
    fn test_view_state_reset() {
        let mut vs = ViewState::default();
        vs.zoom_in(3.0);
        vs.pan_x = 100.0;
        vs.pan_y = 200.0;
        vs.reset();
        assert_eq!(vs.zoom, 1.0);
        assert_eq!(vs.pan_x, 0.0);
        assert_eq!(vs.pan_y, 0.0);
    }

    #[test]
    fn test_view_state_coordinate_conversion() {
        let mut vs = ViewState::default();
        vs.zoom = 2.0;
        vs.pan_x = 100.0;
        vs.pan_y = 50.0;

        let world = vs.screen_to_world(200.0, 150.0);
        assert_eq!(world.x, 50.0);
        assert_eq!(world.y, 50.0);

        let screen = vs.world_to_screen(50.0, 50.0);
        assert_eq!(screen.x, 200.0);
        assert_eq!(screen.y, 150.0);
    }

    #[test]
    fn test_path_highlight_mode_display() {
        assert_eq!(PathHighlightMode::None.to_string(), "None");
        assert_eq!(PathHighlightMode::ShortestPath.to_string(), "Shortest Path");
    }

    #[test]
    fn test_graph_viewer_creation() {
        let viewer = GraphViewer::new();
        assert!(viewer.is_enabled());
        assert_eq!(viewer.vertex_count(), 0);
        assert_eq!(viewer.edge_count(), 0);
        assert!(viewer.selected_vertices().is_empty());
    }

    #[test]
    fn test_graph_viewer_add_remove_vertices() {
        let mut viewer = GraphViewer::new();

        viewer.add_vertex(0, Point2d::new(0.0, 0.0));
        viewer.add_vertex(1, Point2d::new(100.0, 0.0));
        viewer.add_vertex(2, Point2d::new(50.0, 100.0));

        assert_eq!(viewer.vertex_count(), 3);

        viewer.remove_vertex(1);
        assert_eq!(viewer.vertex_count(), 2);
        assert!(viewer.vertex_position(1).is_none());
    }

    #[test]
    fn test_graph_viewer_edges() {
        let mut viewer = GraphViewer::new();

        viewer.add_vertex(0, Point2d::new(0.0, 0.0));
        viewer.add_vertex(1, Point2d::new(100.0, 0.0));
        viewer.add_vertex(2, Point2d::new(50.0, 100.0));

        viewer.add_edge(0, 1);
        viewer.add_edge(0, 2);
        viewer.add_edge(1, 2);

        assert_eq!(viewer.edge_count(), 3);

        let succs = viewer.successors(0);
        assert_eq!(succs.len(), 2);
        assert!(succs.contains(&1));
        assert!(succs.contains(&2));

        let preds = viewer.predecessors(2);
        assert_eq!(preds.len(), 2);
        assert!(preds.contains(&0));
        assert!(preds.contains(&1));
    }

    #[test]
    fn test_graph_viewer_selection() {
        let mut viewer = GraphViewer::new();

        viewer.add_vertex(0, Point2d::new(0.0, 0.0));
        viewer.add_vertex(1, Point2d::new(100.0, 0.0));
        viewer.add_vertex(2, Point2d::new(50.0, 100.0));

        viewer.select_vertex(0);
        assert!(viewer.selected_vertices().contains(&0));
        assert_eq!(viewer.focused_vertex(), Some(0));

        viewer.select_vertex(1);
        assert!(viewer.selected_vertices().contains(&1));
        assert_eq!(viewer.focused_vertex(), Some(1));
    }

    #[test]
    fn test_graph_viewer_toggle_selection() {
        let mut viewer = GraphViewer::new();
        viewer.options.picking_mode = PickingMode::Toggle;

        viewer.add_vertex(0, Point2d::new(0.0, 0.0));
        viewer.add_vertex(1, Point2d::new(100.0, 0.0));

        viewer.select_vertex(0);
        assert!(viewer.selected_vertices().contains(&0));

        viewer.select_vertex(1);
        assert!(viewer.selected_vertices().contains(&0));
        assert!(viewer.selected_vertices().contains(&1));

        viewer.select_vertex(0);
        assert!(!viewer.selected_vertices().contains(&0));
        assert!(viewer.selected_vertices().contains(&1));
    }

    #[test]
    fn test_graph_viewer_hover() {
        let mut viewer = GraphViewer::new();

        viewer.set_hovered_vertex(Some(5));
        assert_eq!(viewer.hovered_vertex(), Some(5));

        viewer.set_hovered_edge(Some((0, 1)));
        assert_eq!(viewer.hovered_edge(), Some((0, 1)));
    }

    #[test]
    fn test_graph_viewer_find_vertex_at() {
        let mut viewer = GraphViewer::new();

        viewer.add_vertex(0, Point2d::new(100.0, 100.0));
        viewer.add_vertex(1, Point2d::new(300.0, 300.0));

        assert_eq!(viewer.find_vertex_at(100.0, 100.0), Some(0));
        assert_eq!(viewer.find_vertex_at(300.0, 300.0), Some(1));
        assert_eq!(viewer.find_vertex_at(500.0, 500.0), None);
    }

    #[test]
    fn test_graph_viewer_bounds() {
        let mut viewer = GraphViewer::new();

        viewer.add_vertex(0, Point2d::new(0.0, 0.0));
        viewer.add_vertex(1, Point2d::new(200.0, 100.0));

        let bounds = viewer.bounds();
        assert!(bounds.x < 0.0); // Includes padding
        assert!(bounds.y < 0.0);
        assert!(bounds.width > 200.0);
        assert!(bounds.height > 100.0);
    }

    #[test]
    fn test_graph_viewer_shortest_path() {
        let mut viewer = GraphViewer::new();

        viewer.add_vertex(0, Point2d::new(0.0, 0.0));
        viewer.add_vertex(1, Point2d::new(100.0, 0.0));
        viewer.add_vertex(2, Point2d::new(200.0, 0.0));
        viewer.add_vertex(3, Point2d::new(300.0, 0.0));

        viewer.add_edge(0, 1);
        viewer.add_edge(1, 2);
        viewer.add_edge(2, 3);
        viewer.add_edge(0, 2); // Shortcut

        let path = viewer.find_shortest_path(0, 3).unwrap();
        assert_eq!(path, vec![0, 2, 3]);
    }

    #[test]
    fn test_graph_viewer_all_paths() {
        let mut viewer = GraphViewer::new();

        viewer.add_vertex(0, Point2d::new(0.0, 0.0));
        viewer.add_vertex(1, Point2d::new(100.0, 0.0));
        viewer.add_vertex(2, Point2d::new(0.0, 100.0));
        viewer.add_vertex(3, Point2d::new(100.0, 100.0));

        viewer.add_edge(0, 1);
        viewer.add_edge(0, 2);
        viewer.add_edge(1, 3);
        viewer.add_edge(2, 3);

        let paths = viewer.find_all_paths(0, 3, 10);
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&vec![0, 1, 3]));
        assert!(paths.contains(&vec![0, 2, 3]));
    }

    #[test]
    fn test_graph_viewer_clear_selection() {
        let mut viewer = GraphViewer::new();

        viewer.add_vertex(0, Point2d::new(0.0, 0.0));
        viewer.add_vertex(1, Point2d::new(100.0, 0.0));

        viewer.select_vertex(0);
        viewer.select_vertex(1);
        assert!(!viewer.selected_vertices().is_empty());

        viewer.clear_selection();
        assert!(viewer.selected_vertices().is_empty());
        assert!(viewer.focused_vertex().is_none());
    }

    #[test]
    fn test_graph_viewer_options_default() {
        let opts = GraphViewerOptions::default();
        assert!(opts.show_labels);
        assert!(!opts.show_edge_labels);
        assert!(opts.allow_drag);
        assert!(!opts.show_satellite);
        assert_eq!(opts.padding, 20.0);
    }
}
