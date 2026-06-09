//! Graph component -- the main visual container for a graph.
//!
//! Ported from Ghidra's `ghidra.graph.viewer.GraphComponent` Java class.
//!
//! The [`GraphComponent`] is the top-level component that holds a graph, its
//! layout, and manages interactions (selection, hover, zoom, pan, satellite).
//! It wraps a [`GraphViewer`] and provides additional functionality for
//! managing graph lifecycle, undo/redo, and keyboard navigation.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock};

use super::graph_viewer::{
    GraphViewer, GraphViewerOptions, PathHighlightMode, PickingMode, Point2d, Rect2d, ViewState,
};
use super::layout::{
    LayoutPositions, LayoutProvider, LayoutProviderRegistry, RelayoutOption, ViewRestoreOption,
};

// ============================================================================
// SatellitePosition
// ============================================================================

/// Position of the satellite (overview) view relative to the main view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SatellitePosition {
    UpperLeft,
    UpperRight,
    LowerLeft,
    LowerRight,
}

impl Default for SatellitePosition {
    fn default() -> Self {
        Self::UpperRight
    }
}

// ============================================================================
// GraphComponentOptions
// ============================================================================

/// Configuration options for a graph component.
#[derive(Debug, Clone)]
pub struct GraphComponentOptions {
    /// Position of the satellite view.
    pub satellite_position: SatellitePosition,
    /// Whether to show the satellite view.
    pub show_satellite: bool,
    /// Whether to show stale graph overlay.
    pub show_stale_overlay: bool,
    /// Whether to enable keyboard navigation.
    pub enable_keyboard_navigation: bool,
    /// Whether to enable mouse wheel zoom.
    pub enable_mouse_wheel_zoom: bool,
    /// Whether to enable double-click to fit.
    pub enable_double_click_fit: bool,
    /// Maximum vertex count for "really big graph" optimizations.
    pub really_big_graph_threshold: usize,
}

impl Default for GraphComponentOptions {
    fn default() -> Self {
        Self {
            satellite_position: SatellitePosition::default(),
            show_satellite: false,
            show_stale_overlay: true,
            enable_keyboard_navigation: true,
            enable_mouse_wheel_zoom: true,
            enable_double_click_fit: true,
            really_big_graph_threshold: 500,
        }
    }
}

// ============================================================================
// SatelliteGraphViewer
// ============================================================================

/// A miniature overview of the graph.
///
/// Shows the entire graph in a small viewport with a visible region
/// indicator that the user can drag to navigate.
#[derive(Debug, Clone)]
pub struct SatelliteGraphViewer {
    /// Whether the satellite view is visible.
    visible: bool,
    /// Size of the satellite view.
    width: f64,
    height: f64,
    /// The visible region in world coordinates.
    visible_region: Rect2d,
    /// The full graph bounds.
    graph_bounds: Rect2d,
}

impl SatelliteGraphViewer {
    /// Create a new satellite view.
    pub fn new() -> Self {
        Self {
            visible: false,
            width: 150.0,
            height: 112.5,
            visible_region: Rect2d::default(),
            graph_bounds: Rect2d::default(),
        }
    }

    /// Whether the satellite view is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set whether the satellite view is visible.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Get the size of the satellite view.
    pub fn size(&self) -> (f64, f64) {
        (self.width, self.height)
    }

    /// Set the size of the satellite view.
    pub fn set_size(&mut self, width: f64, height: f64) {
        self.width = width;
        self.height = height;
    }

    /// Update the visible region based on the main view's state.
    pub fn update_visible_region(&mut self, view_state: &ViewState, graph_bounds: Rect2d) {
        self.graph_bounds = graph_bounds;

        let world_x = -view_state.pan_x / view_state.zoom;
        let world_y = -view_state.pan_y / view_state.zoom;
        let world_width = view_state.viewport_width / view_state.zoom;
        let world_height = view_state.viewport_height / view_state.zoom;

        self.visible_region = Rect2d::new(world_x, world_y, world_width, world_height);
    }

    /// Get the visible region in world coordinates.
    pub fn visible_region(&self) -> Rect2d {
        self.visible_region
    }

    /// Convert a satellite click position to a world point.
    pub fn satellite_to_world(&self, sat_x: f64, sat_y: f64) -> Point2d {
        let scale_x = self.graph_bounds.width / self.width;
        let scale_y = self.graph_bounds.height / self.height;
        let scale = scale_x.max(scale_y);

        Point2d::new(
            self.graph_bounds.x + sat_x * scale,
            self.graph_bounds.y + sat_y * scale,
        )
    }
}

impl Default for SatelliteGraphViewer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// NavigationState
// ============================================================================

/// Tracks navigation history for undo/redo of vertex focus changes.
#[derive(Debug, Clone)]
pub struct NavigationState {
    /// History of focused vertex IDs.
    history: Vec<Option<usize>>,
    /// Current position in history.
    current_index: usize,
    /// Maximum history size.
    max_history: usize,
}

impl NavigationState {
    /// Create a new navigation state.
    pub fn new() -> Self {
        Self {
            history: vec![None],
            current_index: 0,
            max_history: 100,
        }
    }

    /// Push a new focus vertex onto the history.
    pub fn push(&mut self, vertex_id: Option<usize>) {
        // Remove any forward history
        self.history.truncate(self.current_index + 1);
        self.history.push(vertex_id);
        self.current_index = self.history.len() - 1;

        // Trim history if too long
        if self.history.len() > self.max_history {
            self.history.remove(0);
            self.current_index = self.current_index.saturating_sub(1);
        }
    }

    /// Go back in history. Returns the previous focus vertex.
    pub fn go_back(&mut self) -> Option<usize> {
        if self.current_index > 0 {
            self.current_index -= 1;
            self.history[self.current_index]
        } else {
            None
        }
    }

    /// Go forward in history. Returns the next focus vertex.
    pub fn go_forward(&mut self) -> Option<usize> {
        if self.current_index < self.history.len() - 1 {
            self.current_index += 1;
            self.history[self.current_index]
        } else {
            None
        }
    }

    /// Whether there is history to go back to.
    pub fn can_go_back(&self) -> bool {
        self.current_index > 0
    }

    /// Whether there is history to go forward to.
    pub fn can_go_forward(&self) -> bool {
        self.current_index < self.history.len() - 1
    }
}

impl Default for NavigationState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// GraphComponent
// ============================================================================

/// The primary component for rendering and interacting with a visual graph.
///
/// Ported from Ghidra's `ghidra.graph.viewer.GraphComponent`.
///
/// Manages layout, selection, zoom/pan, hover state, the satellite view,
/// and popup menus. Wraps a [`GraphViewer`] and provides additional
/// functionality for managing graph lifecycle and keyboard navigation.
pub struct GraphComponent {
    /// The primary graph viewer.
    viewer: GraphViewer,
    /// Component-level options.
    pub options: GraphComponentOptions,
    /// Satellite view.
    satellite: SatelliteGraphViewer,
    /// Navigation history.
    navigation: NavigationState,
    /// Whether the graph is stale (needs relayout).
    stale: bool,
    /// Whether the component has been initialized.
    initialized: bool,
    /// The graph's title/name.
    title: String,
    /// Layout listener callbacks.
    layout_listeners: Vec<Box<dyn Fn(&str) + Send + Sync>>,
    /// Selection change callbacks.
    selection_listeners: Vec<Box<dyn Fn(&HashSet<usize>) + Send + Sync>>,
}

impl GraphComponent {
    /// Create a new graph component with default settings.
    pub fn new() -> Self {
        Self {
            viewer: GraphViewer::new(),
            options: GraphComponentOptions::default(),
            satellite: SatelliteGraphViewer::new(),
            navigation: NavigationState::new(),
            stale: false,
            initialized: false,
            title: String::new(),
            layout_listeners: Vec::new(),
            selection_listeners: Vec::new(),
        }
    }

    /// Create a new graph component with a title.
    pub fn with_title(title: impl Into<String>) -> Self {
        let mut comp = Self::new();
        comp.title = title.into();
        comp
    }

    /// Create a new graph component with custom viewer options.
    pub fn with_viewer_options(viewer_options: GraphViewerOptions) -> Self {
        Self {
            viewer: GraphViewer::with_options(viewer_options),
            ..Self::new()
        }
    }

    // ------------------------------------------------------------------
    // Initialization
    // ------------------------------------------------------------------

    /// Initialize the component. Should be called after the graph is set up.
    pub fn initialize(&mut self) {
        if self.initialized {
            return;
        }
        self.initialized = true;
        self.stale = false;
    }

    /// Whether the component has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // ------------------------------------------------------------------
    // Title
    // ------------------------------------------------------------------

    /// Get the graph title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Set the graph title.
    pub fn set_title(&mut self, title: impl Into<String>) {
        self.title = title.into();
    }

    // ------------------------------------------------------------------
    // Viewer access
    // ------------------------------------------------------------------

    /// Get a reference to the underlying graph viewer.
    pub fn viewer(&self) -> &GraphViewer {
        &self.viewer
    }

    /// Get a mutable reference to the underlying graph viewer.
    pub fn viewer_mut(&mut self) -> &mut GraphViewer {
        &mut self.viewer
    }

    // ------------------------------------------------------------------
    // Satellite view
    // ------------------------------------------------------------------

    /// Get a reference to the satellite view.
    pub fn satellite(&self) -> &SatelliteGraphViewer {
        &self.satellite
    }

    /// Get a mutable reference to the satellite view.
    pub fn satellite_mut(&mut self) -> &mut SatelliteGraphViewer {
        &mut self.satellite
    }

    /// Update the satellite view based on the current view state.
    pub fn update_satellite(&mut self) {
        let bounds = self.viewer.bounds();
        self.satellite
            .update_visible_region(self.viewer.view_state(), bounds);
    }

    // ------------------------------------------------------------------
    // Navigation
    // ------------------------------------------------------------------

    /// Get a reference to the navigation state.
    pub fn navigation(&self) -> &NavigationState {
        &self.navigation
    }

    /// Go back in navigation history.
    pub fn navigate_back(&mut self) -> Option<usize> {
        let vertex_id = self.navigation.go_back();
        if let Some(id) = vertex_id {
            self.viewer.set_focused_vertex(Some(id));
        }
        vertex_id
    }

    /// Go forward in navigation history.
    pub fn navigate_forward(&mut self) -> Option<usize> {
        let vertex_id = self.navigation.go_forward();
        if let Some(id) = vertex_id {
            self.viewer.set_focused_vertex(Some(id));
        }
        vertex_id
    }

    /// Navigate to a specific vertex.
    pub fn navigate_to(&mut self, vertex_id: usize) {
        self.navigation.push(Some(vertex_id));
        self.viewer.set_focused_vertex(Some(vertex_id));
    }

    // ------------------------------------------------------------------
    // Keyboard navigation
    // ------------------------------------------------------------------

    /// Handle keyboard navigation input.
    ///
    /// Returns true if the key was handled.
    pub fn handle_key_input(&mut self, key: &str) -> bool {
        if !self.options.enable_keyboard_navigation {
            return false;
        }

        match key {
            "ArrowUp" | "k" => {
                self.navigate_to_predecessor();
                true
            }
            "ArrowDown" | "j" => {
                self.navigate_to_successor();
                true
            }
            "ArrowLeft" | "h" => {
                self.navigate_back();
                true
            }
            "ArrowRight" | "l" => {
                self.navigate_forward();
                true
            }
            "Home" => {
                self.navigate_to_entry();
                true
            }
            "End" => {
                self.navigate_to_exit();
                true
            }
            "f" => {
                self.viewer.fit_graph();
                true
            }
            "+" | "=" => {
                self.viewer.zoom_in();
                true
            }
            "-" => {
                self.viewer.zoom_out();
                true
            }
            _ => false,
        }
    }

    /// Navigate to the first predecessor of the focused vertex.
    pub fn navigate_to_predecessor(&mut self) {
        if let Some(focused) = self.viewer.focused_vertex() {
            let preds = self.viewer.predecessors(focused);
            if let Some(&pred) = preds.first() {
                self.navigate_to(pred);
            }
        }
    }

    /// Navigate to the first successor of the focused vertex.
    pub fn navigate_to_successor(&mut self) {
        if let Some(focused) = self.viewer.focused_vertex() {
            let succs = self.viewer.successors(focused);
            if let Some(&succ) = succs.first() {
                self.navigate_to(succ);
            }
        }
    }

    /// Navigate to the entry vertex (first vertex added).
    pub fn navigate_to_entry(&mut self) {
        let vertex_ids = self.viewer.vertex_ids();
        if let Some(&first) = vertex_ids.first() {
            self.navigate_to(first);
        }
    }

    /// Navigate to an exit vertex (vertex with no successors).
    pub fn navigate_to_exit(&mut self) {
        let vertex_ids = self.viewer.vertex_ids();
        for &id in &vertex_ids {
            if self.viewer.successors(id).is_empty() {
                self.navigate_to(id);
                return;
            }
        }
    }

    // ------------------------------------------------------------------
    // Stale state
    // ------------------------------------------------------------------

    /// Whether the graph is stale (needs relayout).
    pub fn is_stale(&self) -> bool {
        self.stale
    }

    /// Mark the graph as stale.
    pub fn set_stale(&mut self, stale: bool) {
        self.stale = stale;
    }

    // ------------------------------------------------------------------
    // Layout
    // ------------------------------------------------------------------

    /// Apply a layout algorithm to the graph.
    pub fn apply_layout(&mut self, layout_name: &str) -> Result<(), String> {
        self.stale = false;
        self.viewer.apply_layout(layout_name)?;

        // Notify listeners
        for listener in &self.layout_listeners {
            listener(layout_name);
        }

        // Update satellite view
        self.update_satellite();

        Ok(())
    }

    /// Add a layout change listener.
    pub fn add_layout_listener(&mut self, listener: Box<dyn Fn(&str) + Send + Sync>) {
        self.layout_listeners.push(listener);
    }

    // ------------------------------------------------------------------
    // Selection listeners
    // ------------------------------------------------------------------

    /// Add a selection change listener.
    pub fn add_selection_listener(
        &mut self,
        listener: Box<dyn Fn(&HashSet<usize>) + Send + Sync>,
    ) {
        self.selection_listeners.push(listener);
    }

    /// Notify selection listeners of a change.
    fn notify_selection_change(&self) {
        let selected = self.viewer.selected_vertices();
        for listener in &self.selection_listeners {
            listener(selected);
        }
    }

    // ------------------------------------------------------------------
    // Delegate methods to viewer
    // ------------------------------------------------------------------

    /// Get the current zoom level.
    pub fn zoom(&self) -> f64 {
        self.viewer.zoom()
    }

    /// Set the zoom level.
    pub fn set_zoom(&mut self, zoom: f64) {
        self.viewer.set_zoom(zoom);
    }

    /// Zoom in.
    pub fn zoom_in(&mut self) {
        self.viewer.zoom_in();
    }

    /// Zoom out.
    pub fn zoom_out(&mut self) {
        self.viewer.zoom_out();
    }

    /// Fit the graph within the viewport.
    pub fn fit_graph(&mut self) {
        self.viewer.fit_graph();
        self.update_satellite();
    }

    /// Select a vertex.
    pub fn select_vertex(&mut self, vertex_id: usize) {
        self.viewer.select_vertex(vertex_id);
        self.notify_selection_change();
    }

    /// Deselect a vertex.
    pub fn deselect_vertex(&mut self, vertex_id: usize) {
        self.viewer.deselect_vertex(vertex_id);
        self.notify_selection_change();
    }

    /// Clear all selections.
    pub fn clear_selection(&mut self) {
        self.viewer.clear_selection();
        self.notify_selection_change();
    }

    /// Get the set of selected vertex IDs.
    pub fn selected_vertices(&self) -> &HashSet<usize> {
        self.viewer.selected_vertices()
    }

    /// Get the focused vertex ID.
    pub fn focused_vertex(&self) -> Option<usize> {
        self.viewer.focused_vertex()
    }

    /// Set the focused vertex.
    pub fn set_focused_vertex(&mut self, vertex_id: Option<usize>) {
        self.viewer.set_focused_vertex(vertex_id);
        if let Some(id) = vertex_id {
            self.navigation.push(Some(id));
        }
        self.notify_selection_change();
    }

    /// Get the hovered vertex ID.
    pub fn hovered_vertex(&self) -> Option<usize> {
        self.viewer.hovered_vertex()
    }

    /// Set the hovered vertex.
    pub fn set_hovered_vertex(&mut self, vertex_id: Option<usize>) {
        self.viewer.set_hovered_vertex(vertex_id);
    }

    /// Get the hovered edge.
    pub fn hovered_edge(&self) -> Option<(usize, usize)> {
        self.viewer.hovered_edge()
    }

    /// Set the hovered edge.
    pub fn set_hovered_edge(&mut self, edge: Option<(usize, usize)>) {
        self.viewer.set_hovered_edge(edge);
    }

    /// Add a vertex to the graph.
    pub fn add_vertex(&mut self, vertex_id: usize, position: Point2d) {
        self.viewer.add_vertex(vertex_id, position);
        self.stale = true;
    }

    /// Remove a vertex from the graph.
    pub fn remove_vertex(&mut self, vertex_id: usize) {
        self.viewer.remove_vertex(vertex_id);
        self.stale = true;
    }

    /// Add an edge to the graph.
    pub fn add_edge(&mut self, from_id: usize, to_id: usize) {
        self.viewer.add_edge(from_id, to_id);
        self.stale = true;
    }

    /// Add an edge with route waypoints.
    pub fn add_edge_with_route(
        &mut self,
        from_id: usize,
        to_id: usize,
        route: Vec<Point2d>,
    ) {
        self.viewer.add_edge_with_route(from_id, to_id, route);
        self.stale = true;
    }

    /// Remove an edge from the graph.
    pub fn remove_edge(&mut self, from_id: usize, to_id: usize) {
        self.viewer.remove_edge(from_id, to_id);
        self.stale = true;
    }

    /// Get the number of vertices.
    pub fn vertex_count(&self) -> usize {
        self.viewer.vertex_count()
    }

    /// Get the number of edges.
    pub fn edge_count(&self) -> usize {
        self.viewer.edge_count()
    }

    /// Get the bounding box of all vertices.
    pub fn bounds(&self) -> Rect2d {
        self.viewer.bounds()
    }

    /// Find the vertex at the given screen coordinates.
    pub fn find_vertex_at_screen(&self, screen_x: f64, screen_y: f64) -> Option<usize> {
        self.viewer.find_vertex_at_screen(screen_x, screen_y)
    }

    /// Find the shortest path between two vertices.
    pub fn find_shortest_path(&self, from_id: usize, to_id: usize) -> Option<Vec<usize>> {
        self.viewer.find_shortest_path(from_id, to_id)
    }

    /// Find all paths between two vertices.
    pub fn find_all_paths(
        &self,
        from_id: usize,
        to_id: usize,
        max_paths: usize,
    ) -> Vec<Vec<usize>> {
        self.viewer.find_all_paths(from_id, to_id, max_paths)
    }

    // ------------------------------------------------------------------
    // Enabled state
    // ------------------------------------------------------------------

    /// Whether the component is enabled.
    pub fn is_enabled(&self) -> bool {
        self.viewer.is_enabled()
    }

    /// Set whether the component is enabled.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.viewer.set_enabled(enabled);
    }
}

impl Default for GraphComponent {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_satellite_position_default() {
        assert_eq!(
            SatellitePosition::default(),
            SatellitePosition::UpperRight
        );
    }

    #[test]
    fn test_satellite_graph_viewer() {
        let mut satellite = SatelliteGraphViewer::new();
        assert!(!satellite.is_visible());

        satellite.set_visible(true);
        assert!(satellite.is_visible());

        satellite.set_size(200.0, 150.0);
        assert_eq!(satellite.size(), (200.0, 150.0));
    }

    #[test]
    fn test_satellite_visible_region() {
        let mut satellite = SatelliteGraphViewer::new();

        let view_state = ViewState {
            zoom: 1.0,
            pan_x: 0.0,
            pan_y: 0.0,
            viewport_width: 800.0,
            viewport_height: 600.0,
        };
        let graph_bounds = Rect2d::new(0.0, 0.0, 1600.0, 1200.0);

        satellite.update_visible_region(&view_state, graph_bounds);

        let region = satellite.visible_region();
        assert_eq!(region.x, 0.0);
        assert_eq!(region.y, 0.0);
        assert_eq!(region.width, 800.0);
        assert_eq!(region.height, 600.0);
    }

    #[test]
    fn test_navigation_state() {
        let mut nav = NavigationState::new();

        assert!(!nav.can_go_back());
        assert!(!nav.can_go_forward());

        nav.push(Some(0));
        nav.push(Some(1));
        nav.push(Some(2));

        assert!(nav.can_go_back());
        assert!(!nav.can_go_forward());

        assert_eq!(nav.go_back(), Some(1));
        assert_eq!(nav.go_back(), Some(0));
        assert_eq!(nav.go_back(), None); // Already at start (initial None entry)

        assert!(nav.can_go_forward());
        assert_eq!(nav.go_forward(), Some(0)); // Go forward to first pushed item
        assert_eq!(nav.go_forward(), Some(1));
        assert_eq!(nav.go_forward(), Some(2));
        assert_eq!(nav.go_forward(), None); // Already at end
    }

    #[test]
    fn test_graph_component_creation() {
        let comp = GraphComponent::new();
        assert!(!comp.is_initialized());
        assert_eq!(comp.title(), "");
        assert_eq!(comp.vertex_count(), 0);
        assert_eq!(comp.edge_count(), 0);
    }

    #[test]
    fn test_graph_component_with_title() {
        let comp = GraphComponent::with_title("Test Graph");
        assert_eq!(comp.title(), "Test Graph");
    }

    #[test]
    fn test_graph_component_initialize() {
        let mut comp = GraphComponent::new();
        assert!(!comp.is_initialized());

        comp.initialize();
        assert!(comp.is_initialized());

        // Double initialization is a no-op
        comp.initialize();
        assert!(comp.is_initialized());
    }

    #[test]
    fn test_graph_component_vertices_and_edges() {
        let mut comp = GraphComponent::new();

        comp.add_vertex(0, Point2d::new(0.0, 0.0));
        comp.add_vertex(1, Point2d::new(100.0, 0.0));
        comp.add_vertex(2, Point2d::new(50.0, 100.0));

        assert_eq!(comp.vertex_count(), 3);
        assert!(comp.is_stale());

        comp.add_edge(0, 1);
        comp.add_edge(1, 2);

        assert_eq!(comp.edge_count(), 2);
    }

    #[test]
    fn test_graph_component_selection() {
        let mut comp = GraphComponent::new();

        comp.viewer_mut().add_vertex(0, Point2d::new(0.0, 0.0));
        comp.viewer_mut().add_vertex(1, Point2d::new(100.0, 0.0));

        comp.select_vertex(0);
        assert!(comp.selected_vertices().contains(&0));
        assert_eq!(comp.focused_vertex(), Some(0));

        comp.select_vertex(1);
        assert!(comp.selected_vertices().contains(&1));
        assert_eq!(comp.focused_vertex(), Some(1));

        comp.clear_selection();
        assert!(comp.selected_vertices().is_empty());
    }

    #[test]
    fn test_graph_component_navigation() {
        let mut comp = GraphComponent::new();

        comp.viewer_mut().add_vertex(0, Point2d::new(0.0, 0.0));
        comp.viewer_mut().add_vertex(1, Point2d::new(100.0, 0.0));
        comp.viewer_mut().add_vertex(2, Point2d::new(200.0, 0.0));

        comp.viewer_mut().add_edge(0, 1);
        comp.viewer_mut().add_edge(1, 2);

        comp.navigate_to(0);
        assert_eq!(comp.focused_vertex(), Some(0));

        comp.navigate_to_successor();
        assert_eq!(comp.focused_vertex(), Some(1));

        comp.navigate_to_successor();
        assert_eq!(comp.focused_vertex(), Some(2));

        comp.navigate_to_predecessor();
        assert_eq!(comp.focused_vertex(), Some(1));
    }

    #[test]
    fn test_graph_component_keyboard_navigation() {
        let mut comp = GraphComponent::new();

        comp.viewer_mut().add_vertex(0, Point2d::new(0.0, 0.0));
        comp.viewer_mut().add_vertex(1, Point2d::new(100.0, 0.0));

        comp.viewer_mut().add_edge(0, 1);
        comp.navigate_to(0);

        assert!(comp.handle_key_input("ArrowDown"));
        assert_eq!(comp.focused_vertex(), Some(1));

        assert!(comp.handle_key_input("ArrowUp"));
        assert_eq!(comp.focused_vertex(), Some(0));

        assert!(comp.handle_key_input("f")); // Fit graph
        assert!(comp.handle_key_input("+")); // Zoom in

        assert!(!comp.handle_key_input("x")); // Unknown key
    }

    #[test]
    fn test_graph_component_keyboard_navigation_disabled() {
        let mut comp = GraphComponent::new();
        comp.options.enable_keyboard_navigation = false;

        assert!(!comp.handle_key_input("ArrowDown"));
    }

    #[test]
    fn test_graph_component_stale() {
        let mut comp = GraphComponent::new();
        assert!(!comp.is_stale());

        comp.set_stale(true);
        assert!(comp.is_stale());

        comp.set_stale(false);
        assert!(!comp.is_stale());
    }

    #[test]
    fn test_graph_component_enabled() {
        let mut comp = GraphComponent::new();
        assert!(comp.is_enabled());

        comp.set_enabled(false);
        assert!(!comp.is_enabled());
    }

    #[test]
    fn test_graph_component_satellite() {
        let mut comp = GraphComponent::new();
        assert!(!comp.satellite().is_visible());

        comp.satellite_mut().set_visible(true);
        assert!(comp.satellite().is_visible());
    }

    #[test]
    fn test_graph_component_bounds() {
        let mut comp = GraphComponent::new();

        comp.viewer_mut().add_vertex(0, Point2d::new(0.0, 0.0));
        comp.viewer_mut().add_vertex(1, Point2d::new(200.0, 100.0));

        let bounds = comp.bounds();
        assert!(bounds.width > 0.0);
        assert!(bounds.height > 0.0);
    }

    #[test]
    fn test_graph_component_path_finding() {
        let mut comp = GraphComponent::new();

        comp.viewer_mut().add_vertex(0, Point2d::new(0.0, 0.0));
        comp.viewer_mut().add_vertex(1, Point2d::new(100.0, 0.0));
        comp.viewer_mut().add_vertex(2, Point2d::new(200.0, 0.0));

        comp.viewer_mut().add_edge(0, 1);
        comp.viewer_mut().add_edge(1, 2);

        let path = comp.find_shortest_path(0, 2).unwrap();
        assert_eq!(path, vec![0, 1, 2]);

        let paths = comp.find_all_paths(0, 2, 10);
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn test_graph_component_options_default() {
        let opts = GraphComponentOptions::default();
        assert_eq!(opts.satellite_position, SatellitePosition::UpperRight);
        assert!(!opts.show_satellite);
        assert!(opts.show_stale_overlay);
        assert!(opts.enable_keyboard_navigation);
        assert!(opts.enable_mouse_wheel_zoom);
        assert!(opts.enable_double_click_fit);
        assert_eq!(opts.really_big_graph_threshold, 500);
    }

    #[test]
    fn test_navigation_state_history_limit() {
        let mut nav = NavigationState::new();
        nav.max_history = 5;

        for i in 0..10 {
            nav.push(Some(i));
        }

        assert!(nav.can_go_back());
        // Should not exceed max_history
        let mut count = 0;
        while nav.can_go_back() {
            nav.go_back();
            count += 1;
        }
        assert!(count <= 5);
    }
}
