//! Graph component -- the main visual container for a graph.
//!
//! Ports Ghidra's `ghidra.graph.viewer.GraphComponent`,
//! `ghidra.graph.viewer.GraphViewer`, `ghidra.graph.viewer.VisualGraphView`,
//! and `ghidra.graph.viewer.VisualGraphViewUpdater` packages.  Provides
//! the top-level component that holds a graph, its layout, and manages
//! interactions (selection, hover, zoom, pan, satellite).

use std::collections::HashSet;

use super::layout_provider::LayoutPositions;
use super::mouse::{
    EdgeSelectionGraphMousePlugin, HoverMousePlugin, PickingGraphMousePlugin,
    ScalingGraphMousePlugin, TranslatingGraphMousePlugin,
};
use super::options::VisualGraphOptions;
use super::popup::PopupRegulator;
use super::satellite::SatelliteGraphViewer;
use super::visual_types::{Point2d, Rect2d};

// ============================================================================
// GraphComponent -- the primary graph viewing component
// ============================================================================

/// The primary component for rendering and interacting with a visual graph.
///
/// Ports `ghidra.graph.viewer.GraphComponent` and
/// `ghidra.graph.viewer.GraphViewer`.  Manages layout, selection, zoom/pan,
/// hover state, the satellite view, and popup menus.
#[derive(Debug)]
pub struct GraphComponent {
    /// Graph viewer options.
    pub options: VisualGraphOptions,
    /// Viewport rectangle in world coordinates.
    viewport: Rect2d,
    /// Zoom scale factor.
    zoom: f64,
    /// Pan offset.
    pan: Point2d,
    /// Selected vertex IDs.
    selected_vertices: HashSet<usize>,
    /// Focused vertex ID (the "primary" selection).
    focused_vertex: Option<usize>,
    /// Hovered vertex ID.
    hovered_vertex: Option<usize>,
    /// Hovered edge ID.
    hovered_edge: Option<usize>,
    /// Satellite view.
    satellite: SatelliteGraphViewer,
    /// Popup regulator.
    popup: PopupRegulator,
    /// Mouse picking plugin.
    _picking: PickingGraphMousePlugin,
    /// Mouse scaling plugin.
    _scaling: ScalingGraphMousePlugin,
    /// Mouse translating plugin.
    _translating: TranslatingGraphMousePlugin,
    /// Edge selection plugin.
    _edge_selection: EdgeSelectionGraphMousePlugin,
    /// Hover plugin.
    hover: HoverMousePlugin,
    /// Whether the component is enabled (responds to input).
    enabled: bool,
}

impl GraphComponent {
    /// Create a new graph component with default settings.
    pub fn new() -> Self {
        Self {
            options: VisualGraphOptions::default(),
            viewport: Rect2d::new(0.0, 0.0, 800.0, 600.0),
            zoom: 1.0,
            pan: Point2d::new(0.0, 0.0),
            selected_vertices: HashSet::new(),
            focused_vertex: None,
            hovered_vertex: None,
            hovered_edge: None,
            satellite: SatelliteGraphViewer::default(),
            popup: PopupRegulator::default(),
            _picking: PickingGraphMousePlugin::new(),
            _scaling: ScalingGraphMousePlugin::new(),
            _translating: TranslatingGraphMousePlugin::new(),
            _edge_selection: EdgeSelectionGraphMousePlugin::new(),
            hover: HoverMousePlugin::new(),
            enabled: true,
        }
    }

    /// Get the current zoom level.
    pub fn zoom(&self) -> f64 {
        self.zoom
    }

    /// Set the zoom level.
    pub fn set_zoom(&mut self, zoom: f64) {
        self.zoom = zoom.clamp(0.01, 10.0);
    }

    /// Zoom in.
    pub fn zoom_in(&mut self) {
        self.zoom = (self.zoom * 1.2).min(10.0);
    }

    /// Zoom out.
    pub fn zoom_out(&mut self) {
        self.zoom = (self.zoom / 1.2).max(0.01);
    }

    /// Get the pan offset.
    pub fn pan(&self) -> Point2d {
        self.pan
    }

    /// Set the pan offset.
    pub fn set_pan(&mut self, pan: Point2d) {
        self.pan = pan;
    }

    /// Pan by a delta.
    pub fn pan_by(&mut self, dx: f64, dy: f64) {
        self.pan.x += dx;
        self.pan.y += dy;
    }

    /// Get the viewport rectangle in world coordinates.
    pub fn viewport(&self) -> Rect2d {
        self.viewport
    }

    /// Set the viewport size.
    pub fn set_viewport_size(&mut self, width: f64, height: f64) {
        self.viewport.width = width;
        self.viewport.height = height;
    }

    /// Select a vertex.
    pub fn select_vertex(&mut self, vertex_id: usize) {
        self.selected_vertices.insert(vertex_id);
    }

    /// Deselect a vertex.
    pub fn deselect_vertex(&mut self, vertex_id: usize) {
        self.selected_vertices.remove(&vertex_id);
        if self.focused_vertex == Some(vertex_id) {
            self.focused_vertex = None;
        }
    }

    /// Select a single vertex, deselecting all others.
    pub fn select_single_vertex(&mut self, vertex_id: usize) {
        self.selected_vertices.clear();
        self.selected_vertices.insert(vertex_id);
        self.focused_vertex = Some(vertex_id);
    }

    /// Clear all vertex selections.
    pub fn clear_selection(&mut self) {
        self.selected_vertices.clear();
        self.focused_vertex = None;
    }

    /// Get the selected vertex IDs.
    pub fn selected_vertices(&self) -> &HashSet<usize> {
        &self.selected_vertices
    }

    /// Set the focused vertex.
    pub fn set_focused_vertex(&mut self, vertex_id: Option<usize>) {
        self.focused_vertex = vertex_id;
    }

    /// Get the focused vertex.
    pub fn focused_vertex(&self) -> Option<usize> {
        self.focused_vertex
    }

    /// Set the hovered vertex.
    pub fn set_hovered_vertex(&mut self, vertex_id: Option<usize>) {
        self.hovered_vertex = vertex_id;
        self.hover.set_hovered_vertex(vertex_id);
    }

    /// Get the hovered vertex.
    pub fn hovered_vertex(&self) -> Option<usize> {
        self.hovered_vertex
    }

    /// Set the hovered edge.
    pub fn set_hovered_edge(&mut self, edge_id: Option<usize>) {
        self.hovered_edge = edge_id;
        self.hover.set_hovered_edge(edge_id);
    }

    /// Get the hovered edge.
    pub fn hovered_edge(&self) -> Option<usize> {
        self.hovered_edge
    }

    /// Get a reference to the satellite view.
    pub fn satellite(&self) -> &SatelliteGraphViewer {
        &self.satellite
    }

    /// Get a mutable reference to the satellite view.
    pub fn satellite_mut(&mut self) -> &mut SatelliteGraphViewer {
        &mut self.satellite
    }

    /// Enable or disable the satellite view.
    pub fn set_satellite_visible(&mut self, visible: bool) {
        self.satellite.set_visible(visible);
        self.options.show_satellite = visible;
    }

    /// Fit the graph to the viewport.
    pub fn fit_to_view(&mut self, graph_bounds: Rect2d) {
        if graph_bounds.width <= 0.0 || graph_bounds.height <= 0.0 {
            return;
        }
        let scale_x = self.viewport.width / graph_bounds.width;
        let scale_y = self.viewport.height / graph_bounds.height;
        self.zoom = scale_x.min(scale_y) * 0.9; // 90% to add padding
        self.pan.x = -graph_bounds.x * self.zoom;
        self.pan.y = -graph_bounds.y * self.zoom;
    }

    /// Center the view on a specific world-coordinate point.
    pub fn center_on(&mut self, point: Point2d) {
        self.pan.x = self.viewport.width / 2.0 - point.x * self.zoom;
        self.pan.y = self.viewport.height / 2.0 - point.y * self.zoom;
    }

    /// Convert a screen point to a world point.
    pub fn screen_to_world(&self, screen: Point2d) -> Point2d {
        Point2d::new(
            (screen.x - self.pan.x) / self.zoom,
            (screen.y - self.pan.y) / self.zoom,
        )
    }

    /// Convert a world point to a screen point.
    pub fn world_to_screen(&self, world: Point2d) -> Point2d {
        Point2d::new(
            world.x * self.zoom + self.pan.x,
            world.y * self.zoom + self.pan.y,
        )
    }

    /// Enable or disable the component.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Whether the component is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get the popup regulator.
    pub fn popup_regulator(&self) -> &PopupRegulator {
        &self.popup
    }

    /// Get a mutable reference to the popup regulator.
    pub fn popup_regulator_mut(&mut self) -> &mut PopupRegulator {
        &mut self.popup
    }

    /// Get the current graph options.
    pub fn options(&self) -> &VisualGraphOptions {
        &self.options
    }

    /// Get mutable graph options.
    pub fn options_mut(&mut self) -> &mut VisualGraphOptions {
        &mut self.options
    }
}

impl Default for GraphComponent {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// GraphViewer -- higher-level viewer that wraps GraphComponent
// ============================================================================

/// A higher-level graph viewer that wraps a [`GraphComponent`] with additional
/// convenience methods.
///
/// Ports `ghidra.graph.viewer.GraphViewer`.
#[derive(Debug)]
pub struct GraphViewer {
    /// The underlying graph component.
    pub component: GraphComponent,
    /// The name of this viewer.
    name: String,
}

impl GraphViewer {
    /// Create a new graph viewer.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            component: GraphComponent::new(),
            name: name.into(),
        }
    }

    /// Get the viewer name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

// ============================================================================
// VisualGraphView -- the view model for a visual graph
// ============================================================================

/// The view model that tracks the visual state of a graph.
///
/// Ports `ghidra.graph.viewer.VisualGraphView`.
#[derive(Debug, Default)]
pub struct VisualGraphView {
    /// The layout positions for all vertices.
    positions: LayoutPositions,
    /// Visible vertex IDs (not filtered out).
    visible_vertices: HashSet<usize>,
    /// Visible edge IDs (not filtered out).
    visible_edges: HashSet<usize>,
}

impl VisualGraphView {
    /// Create a new visual graph view.
    pub fn new() -> Self {
        Self {
            positions: LayoutPositions::new(),
            visible_vertices: HashSet::new(),
            visible_edges: HashSet::new(),
        }
    }

    /// Get a reference to the layout positions.
    pub fn positions(&self) -> &LayoutPositions {
        &self.positions
    }

    /// Get a mutable reference to the layout positions.
    pub fn positions_mut(&mut self) -> &mut LayoutPositions {
        &mut self.positions
    }

    /// Add a visible vertex.
    pub fn add_visible_vertex(&mut self, vertex_id: usize) {
        self.visible_vertices.insert(vertex_id);
    }

    /// Remove a visible vertex.
    pub fn remove_visible_vertex(&mut self, vertex_id: usize) {
        self.visible_vertices.remove(&vertex_id);
    }

    /// Get visible vertex IDs.
    pub fn visible_vertices(&self) -> &HashSet<usize> {
        &self.visible_vertices
    }

    /// Add a visible edge.
    pub fn add_visible_edge(&mut self, edge_id: usize) {
        self.visible_edges.insert(edge_id);
    }

    /// Remove a visible edge.
    pub fn remove_visible_edge(&mut self, edge_id: usize) {
        self.visible_edges.remove(&edge_id);
    }

    /// Get visible edge IDs.
    pub fn visible_edges(&self) -> &HashSet<usize> {
        &self.visible_edges
    }

    /// Set the visibility of all vertices.
    pub fn set_all_vertices_visible(&mut self, vertices: HashSet<usize>) {
        self.visible_vertices = vertices;
    }

    /// Set the visibility of all edges.
    pub fn set_all_edges_visible(&mut self, edges: HashSet<usize>) {
        self.visible_edges = edges;
    }
}

// ============================================================================
// VisualGraphViewUpdater -- manages view updates (layout, animation)
// ============================================================================

/// Manages updates to the visual graph view: relayout, animation, filtering.
///
/// Ports `ghidra.graph.viewer.VisualGraphViewUpdater`.
#[derive(Debug)]
pub struct VisualGraphViewUpdater {
    /// Whether a layout is currently being computed.
    layouting: bool,
    /// Whether an animation is currently running.
    animating: bool,
}

impl VisualGraphViewUpdater {
    /// Create a new view updater.
    pub fn new() -> Self {
        Self {
            layouting: false,
            animating: false,
        }
    }

    /// Start a layout computation.
    pub fn start_layout(&mut self) {
        self.layouting = true;
    }

    /// Mark layout as complete.
    pub fn finish_layout(&mut self) {
        self.layouting = false;
    }

    /// Whether a layout is being computed.
    pub fn is_layouting(&self) -> bool {
        self.layouting
    }

    /// Start an animation.
    pub fn start_animation(&mut self) {
        self.animating = true;
    }

    /// Mark animation as complete.
    pub fn finish_animation(&mut self) {
        self.animating = false;
    }

    /// Whether an animation is running.
    pub fn is_animating(&self) -> bool {
        self.animating
    }
}

impl Default for VisualGraphViewUpdater {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// GraphPerspectiveInfo -- saved view state for undo/redo
// ============================================================================

/// Information about a graph view perspective (zoom, pan, selected vertex)
/// that can be saved and restored.
///
/// Ports `ghidra.graph.viewer.GraphPerspectiveInfo`.
#[derive(Debug, Clone)]
pub struct GraphPerspectiveInfo {
    /// Saved zoom level.
    pub zoom: f64,
    /// Saved pan offset.
    pub pan: Point2d,
    /// Saved focused vertex.
    pub focused_vertex: Option<usize>,
    /// Saved selected vertices.
    pub selected_vertices: HashSet<usize>,
}

impl GraphPerspectiveInfo {
    /// Create a perspective from a graph component.
    pub fn from_component(component: &GraphComponent) -> Self {
        Self {
            zoom: component.zoom(),
            pan: component.pan(),
            focused_vertex: component.focused_vertex(),
            selected_vertices: component.selected_vertices().clone(),
        }
    }

    /// Apply this perspective to a graph component.
    pub fn apply_to(&self, component: &mut GraphComponent) {
        component.set_zoom(self.zoom);
        component.set_pan(self.pan);
        component.set_focused_vertex(self.focused_vertex);
        component.clear_selection();
        for &v in &self.selected_vertices {
            component.select_vertex(v);
        }
    }
}

// ============================================================================
// VisualGraphLayeredPaneButton -- button overlay on the graph
// ============================================================================

/// A button that can be overlaid on the graph component (e.g., for "zoom to fit").
///
/// Ports `ghidra.graph.viewer.VisualGraphLayeredPaneButton`.
#[derive(Debug, Clone)]
pub struct VisualGraphLayeredPaneButton {
    /// Button label.
    pub label: String,
    /// Position in screen coordinates.
    pub position: Point2d,
    /// Button width.
    pub width: f64,
    /// Button height.
    pub height: f64,
    /// Whether the button is visible.
    pub visible: bool,
    /// Whether the button is enabled.
    pub enabled: bool,
}

impl VisualGraphLayeredPaneButton {
    /// Create a new layered pane button.
    pub fn new(label: impl Into<String>, position: Point2d) -> Self {
        Self {
            label: label.into(),
            position,
            width: 80.0,
            height: 24.0,
            visible: true,
            enabled: true,
        }
    }

    /// Check if a point is inside this button.
    pub fn hit_test(&self, point: &Point2d) -> bool {
        self.enabled
            && self.visible
            && point.x >= self.position.x
            && point.x <= self.position.x + self.width
            && point.y >= self.position.y
            && point.y <= self.position.y + self.height
    }
}

// ============================================================================
// VisualGraphScalingControl -- controls zoom level
// ============================================================================

/// Controls the zoom level of the graph viewer.
///
/// Ports `ghidra.graph.viewer.VisualGraphScalingControl`.
#[derive(Debug, Default)]
pub struct VisualGraphScalingControl {
    /// Current scale factor.
    scale: f64,
    /// Minimum scale.
    min_scale: f64,
    /// Maximum scale.
    max_scale: f64,
}

impl VisualGraphScalingControl {
    /// Create a new scaling control.
    pub fn new() -> Self {
        Self {
            scale: 1.0,
            min_scale: 0.01,
            max_scale: 10.0,
        }
    }

    /// Get the current scale.
    pub fn scale(&self) -> f64 {
        self.scale
    }

    /// Set the scale.
    pub fn set_scale(&mut self, scale: f64) {
        self.scale = scale.clamp(self.min_scale, self.max_scale);
    }

    /// Zoom in.
    pub fn zoom_in(&mut self) {
        self.set_scale(self.scale * 1.2);
    }

    /// Zoom out.
    pub fn zoom_out(&mut self) {
        self.set_scale(self.scale / 1.2);
    }

    /// Reset to default scale.
    pub fn reset(&mut self) {
        self.scale = 1.0;
    }
}

/// Provider interface for graph components that provide a graph to render.
///
/// Ports `ghidra.graph.VisualGraphComponentProvider`.
pub trait VisualGraphComponentProvider: std::fmt::Debug + Send + Sync {
    /// Get the name of this provider.
    fn name(&self) -> &str;

    /// Get the title for the graph component.
    fn title(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_component_zoom() {
        let mut gc = GraphComponent::new();
        assert_eq!(gc.zoom(), 1.0);
        gc.zoom_in();
        assert!(gc.zoom() > 1.0);
        gc.zoom_out();
        gc.zoom_out();
        assert!(gc.zoom() < 1.0);
    }

    #[test]
    fn test_graph_component_selection() {
        let mut gc = GraphComponent::new();
        gc.select_vertex(1);
        gc.select_vertex(2);
        assert_eq!(gc.selected_vertices().len(), 2);

        gc.select_single_vertex(3);
        assert_eq!(gc.selected_vertices().len(), 1);
        assert_eq!(gc.focused_vertex(), Some(3));
    }

    #[test]
    fn test_graph_component_clear_selection() {
        let mut gc = GraphComponent::new();
        gc.select_vertex(1);
        gc.clear_selection();
        assert!(gc.selected_vertices().is_empty());
        assert!(gc.focused_vertex().is_none());
    }

    #[test]
    fn test_graph_component_screen_world_conversion() {
        let mut gc = GraphComponent::new();
        gc.set_zoom(2.0);
        gc.set_pan(Point2d::new(100.0, 50.0));

        let world = gc.screen_to_world(Point2d::new(300.0, 250.0));
        assert_eq!(world.x, 100.0);
        assert_eq!(world.y, 100.0);

        let screen = gc.world_to_screen(world);
        assert!((screen.x - 300.0).abs() < 0.001);
        assert!((screen.y - 250.0).abs() < 0.001);
    }

    #[test]
    fn test_graph_component_fit_to_view() {
        let mut gc = GraphComponent::new();
        gc.set_viewport_size(800.0, 600.0);
        gc.fit_to_view(Rect2d::new(0.0, 0.0, 1600.0, 1200.0));
        assert!(gc.zoom() < 1.0); // should zoom out
    }

    #[test]
    fn test_graph_component_center_on() {
        let mut gc = GraphComponent::new();
        gc.set_viewport_size(800.0, 600.0);
        gc.center_on(Point2d::new(400.0, 300.0));
        // After centering on (400,300) with zoom 1.0, pan should be (0, 0)
        assert_eq!(gc.pan().x, 0.0);
        assert_eq!(gc.pan().y, 0.0);
    }

    #[test]
    fn test_graph_component_pan() {
        let mut gc = GraphComponent::new();
        gc.pan_by(10.0, 20.0);
        assert_eq!(gc.pan().x, 10.0);
        assert_eq!(gc.pan().y, 20.0);
    }

    #[test]
    fn test_graph_viewer() {
        let gv = GraphViewer::new("test_viewer");
        assert_eq!(gv.name(), "test_viewer");
    }

    #[test]
    fn test_visual_graph_view() {
        let mut view = VisualGraphView::new();
        view.add_visible_vertex(1);
        view.add_visible_vertex(2);
        view.add_visible_edge(10);
        assert_eq!(view.visible_vertices().len(), 2);
        assert_eq!(view.visible_edges().len(), 1);

        view.remove_visible_vertex(1);
        assert_eq!(view.visible_vertices().len(), 1);
    }

    #[test]
    fn test_visual_graph_view_updater() {
        let mut updater = VisualGraphViewUpdater::new();
        assert!(!updater.is_layouting());
        updater.start_layout();
        assert!(updater.is_layouting());
        updater.finish_layout();
        assert!(!updater.is_layouting());
    }

    #[test]
    fn test_graph_perspective_info() {
        let mut gc = GraphComponent::new();
        gc.set_zoom(2.5);
        gc.set_pan(Point2d::new(100.0, 200.0));
        gc.select_vertex(42);

        let perspective = GraphPerspectiveInfo::from_component(&gc);
        assert_eq!(perspective.zoom, 2.5);
        assert_eq!(perspective.pan, Point2d::new(100.0, 200.0));

        let mut gc2 = GraphComponent::new();
        perspective.apply_to(&mut gc2);
        assert_eq!(gc2.zoom(), 2.5);
        assert!(gc2.selected_vertices().contains(&42));
    }

    #[test]
    fn test_layered_pane_button() {
        let btn = VisualGraphLayeredPaneButton::new("Fit", Point2d::new(10.0, 10.0));
        assert!(btn.hit_test(&Point2d::new(50.0, 22.0)));
        assert!(!btn.hit_test(&Point2d::new(200.0, 200.0)));
    }

    #[test]
    fn test_scaling_control() {
        let mut ctrl = VisualGraphScalingControl::new();
        assert_eq!(ctrl.scale(), 1.0);
        ctrl.zoom_in();
        assert!(ctrl.scale() > 1.0);
        ctrl.reset();
        assert_eq!(ctrl.scale(), 1.0);
    }
}
