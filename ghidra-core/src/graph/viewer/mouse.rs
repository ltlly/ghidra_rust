//! Mouse event handling for visual graph viewers.
//!
//! Ports Ghidra's `ghidra.graph.viewer.event.mouse` package.  Provides
//! plugin-based mouse interaction: vertex picking, edge selection, dragging,
//! hover, zooming, panning, popup menus, and satellite view interaction.

use std::collections::HashSet;
use std::fmt::Debug;

use super::visual_types::{Point2d, VisualEdge, VisualVertex};

// ============================================================================
// VertexMouseInfo -- information about a mouse event over a vertex
// ============================================================================

/// Information about a mouse event relative to a vertex.
///
/// Ports `ghidra.graph.viewer.event.mouse.VertexMouseInfo`.
#[derive(Debug, Clone)]
pub struct VertexMouseInfo {
    /// The vertex ID under the mouse.
    pub vertex_id: usize,
    /// Mouse position in graph (world) coordinates.
    pub graph_point: Point2d,
    /// Mouse position relative to the vertex's top-left corner.
    pub vertex_point: Point2d,
    /// Whether the mouse is within the vertex bounds.
    pub in_vertex: bool,
}

impl VertexMouseInfo {
    /// Create new vertex mouse info.
    pub fn new(vertex_id: usize, graph_point: Point2d, vertex_point: Point2d, in_vertex: bool) -> Self {
        Self { vertex_id, graph_point, vertex_point, in_vertex }
    }
}

// ============================================================================
// VertexTooltipProvider -- provides tooltips for vertices
// ============================================================================

/// Trait for providing tooltip text when hovering over a vertex.
///
/// Ports `ghidra.graph.viewer.event.mouse.VertexTooltipProvider`.
pub trait VertexTooltipProvider<V: VisualVertex>: Debug + Send + Sync {
    /// Return the tooltip text for the given vertex, or `None` for no tooltip.
    fn get_tooltip(&self, vertex: &V) -> Option<String>;
}

// ============================================================================
// Mouse plugin trait
// ============================================================================

/// A pluggable mouse handler for graph viewer components.
///
/// Ports `ghidra.graph.viewer.event.mouse.VisualGraphMousePlugin`.
pub trait VisualGraphMousePlugin<V, E>: Debug + Send + Sync
where
    V: VisualVertex,
    E: VisualEdge<V>,
{
    /// Get the name of this plugin.
    fn name(&self) -> &str;

    /// Called when the mouse is pressed on a vertex.
    fn mouse_pressed_on_vertex(&mut self, _vertex: &V, _point: &Point2d) -> bool {
        false
    }

    /// Called when the mouse is pressed on an edge.
    fn mouse_pressed_on_edge(&mut self, _edge: &E, _point: &Point2d) -> bool {
        false
    }

    /// Called when the mouse is pressed on the background (no vertex/edge).
    fn mouse_pressed_on_background(&mut self, _point: &Point2d) -> bool {
        false
    }

    /// Called when the mouse is dragged.
    fn mouse_dragged(&mut self, _point: &Point2d) -> bool {
        false
    }

    /// Called when the mouse is released.
    fn mouse_released(&mut self, _point: &Point2d) -> bool {
        false
    }

    /// Called when the mouse hovers over a vertex.
    fn mouse_hover_vertex(&mut self, _vertex: &V, _point: &Point2d) -> bool {
        false
    }

    /// Called when the mouse hovers over the background.
    fn mouse_hover_background(&mut self, _point: &Point2d) -> bool {
        false
    }
}

// ============================================================================
// PickingGraphMousePlugin -- standard vertex selection by clicking
// ============================================================================

/// Mouse plugin that handles vertex picking (selection).
///
/// Ports `ghidra.graph.viewer.event.mouse.VisualGraphPickingGraphMousePlugin`.
#[derive(Debug)]
pub struct PickingGraphMousePlugin {
    /// Currently picked (selected) vertices.
    picked: HashSet<usize>,
    /// Whether a multi-select modifier (Ctrl) is held.
    multi_select: bool,
    /// Last picked vertex ID (for range-select).
    last_picked: Option<usize>,
}

impl PickingGraphMousePlugin {
    /// Create a new picking plugin.
    pub fn new() -> Self {
        Self {
            picked: HashSet::new(),
            multi_select: false,
            last_picked: None,
        }
    }

    /// Get the currently picked (selected) vertex IDs.
    pub fn picked_vertices(&self) -> &HashSet<usize> {
        &self.picked
    }

    /// Clear all picked vertices.
    pub fn clear_picked(&mut self) {
        self.picked.clear();
        self.last_picked = None;
    }

    /// Pick a single vertex (deselects all others).
    pub fn pick_single(&mut self, vertex_id: usize) {
        self.picked.clear();
        self.picked.insert(vertex_id);
        self.last_picked = Some(vertex_id);
    }

    /// Toggle a vertex in the picked set (for multi-select).
    pub fn toggle_pick(&mut self, vertex_id: usize) {
        if self.picked.contains(&vertex_id) {
            self.picked.remove(&vertex_id);
        } else {
            self.picked.insert(vertex_id);
        }
        self.last_picked = Some(vertex_id);
    }

    /// Set whether multi-select mode is active.
    pub fn set_multi_select(&mut self, multi: bool) {
        self.multi_select = multi;
    }

    /// Check if multi-select mode is active.
    pub fn is_multi_select(&self) -> bool {
        self.multi_select
    }
}

impl Default for PickingGraphMousePlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ScalingGraphMousePlugin -- zoom via mouse wheel / pinch
// ============================================================================

/// Mouse plugin that handles zooming via scroll wheel.
///
/// Ports `ghidra.graph.viewer.event.mouse.VisualGraphScalingGraphMousePlugin`.
#[derive(Debug)]
pub struct ScalingGraphMousePlugin {
    /// Current zoom scale factor.
    scale: f64,
    /// Minimum allowed zoom.
    min_scale: f64,
    /// Maximum allowed zoom.
    max_scale: f64,
    /// Zoom increment per scroll tick.
    zoom_increment: f64,
}

impl ScalingGraphMousePlugin {
    /// Create a new scaling plugin with default parameters.
    pub fn new() -> Self {
        Self {
            scale: 1.0,
            min_scale: 0.01,
            max_scale: 10.0,
            zoom_increment: 0.1,
        }
    }

    /// Get the current scale.
    pub fn scale(&self) -> f64 {
        self.scale
    }

    /// Set the current scale.
    pub fn set_scale(&mut self, scale: f64) {
        self.scale = scale.clamp(self.min_scale, self.max_scale);
    }

    /// Zoom in by the zoom increment.
    pub fn zoom_in(&mut self) {
        self.set_scale(self.scale + self.zoom_increment);
    }

    /// Zoom out by the zoom increment.
    pub fn zoom_out(&mut self) {
        self.set_scale(self.scale - self.zoom_increment);
    }

    /// Process a scroll event: positive = zoom in, negative = zoom out.
    pub fn process_scroll(&mut self, delta: f64) {
        if delta > 0.0 {
            self.zoom_in();
        } else if delta < 0.0 {
            self.zoom_out();
        }
    }

    /// Set the zoom limits.
    pub fn set_zoom_limits(&mut self, min: f64, max: f64) {
        self.min_scale = min;
        self.max_scale = max;
        self.scale = self.scale.clamp(min, max);
    }

    /// Set the zoom increment per scroll tick.
    pub fn set_zoom_increment(&mut self, increment: f64) {
        self.zoom_increment = increment;
    }
}

impl Default for ScalingGraphMousePlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// TranslatingGraphMousePlugin -- pan via mouse drag
// ============================================================================

/// Mouse plugin that handles panning (translating) the graph view by dragging.
///
/// Ports `ghidra.graph.viewer.event.mouse.VisualGraphTranslatingGraphMousePlugin`.
#[derive(Debug)]
pub struct TranslatingGraphMousePlugin {
    /// Whether a drag is currently in progress.
    dragging: bool,
    /// The start point of the current drag.
    drag_start: Point2d,
    /// Accumulated translation offset.
    pub translate_x: f64,
    /// Accumulated translation offset.
    pub translate_y: f64,
}

impl TranslatingGraphMousePlugin {
    /// Create a new translating plugin.
    pub fn new() -> Self {
        Self {
            dragging: false,
            drag_start: Point2d::new(0.0, 0.0),
            translate_x: 0.0,
            translate_y: 0.0,
        }
    }

    /// Start a drag operation.
    pub fn start_drag(&mut self, point: Point2d) {
        self.dragging = true;
        self.drag_start = point;
    }

    /// Update drag and compute delta.
    pub fn update_drag(&mut self, point: Point2d) -> (f64, f64) {
        if !self.dragging {
            return (0.0, 0.0);
        }
        let dx = point.x - self.drag_start.x;
        let dy = point.y - self.drag_start.y;
        self.translate_x += dx;
        self.translate_y += dy;
        self.drag_start = point;
        (dx, dy)
    }

    /// End the drag operation.
    pub fn end_drag(&mut self) {
        self.dragging = false;
    }

    /// Whether a drag is in progress.
    pub fn is_dragging(&self) -> bool {
        self.dragging
    }

    /// Reset translation to origin.
    pub fn reset(&mut self) {
        self.translate_x = 0.0;
        self.translate_y = 0.0;
        self.dragging = false;
    }
}

impl Default for TranslatingGraphMousePlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// EdgeSelectionGraphMousePlugin -- select edges by clicking
// ============================================================================

/// Mouse plugin that handles edge selection by clicking on edges.
///
/// Ports `ghidra.graph.viewer.event.mouse.VisualGraphEdgeSelectionGraphMousePlugin`.
#[derive(Debug)]
pub struct EdgeSelectionGraphMousePlugin {
    /// IDs of currently selected edges.
    selected: HashSet<usize>,
}

impl EdgeSelectionGraphMousePlugin {
    /// Create a new edge selection plugin.
    pub fn new() -> Self {
        Self { selected: HashSet::new() }
    }

    /// Select an edge by ID.
    pub fn select_edge(&mut self, edge_id: usize) {
        self.selected.insert(edge_id);
    }

    /// Deselect an edge.
    pub fn deselect_edge(&mut self, edge_id: usize) {
        self.selected.remove(&edge_id);
    }

    /// Toggle selection of an edge.
    pub fn toggle_edge(&mut self, edge_id: usize) {
        if !self.selected.remove(&edge_id) {
            self.selected.insert(edge_id);
        }
    }

    /// Get the selected edge IDs.
    pub fn selected_edges(&self) -> &HashSet<usize> {
        &self.selected
    }

    /// Clear all selected edges.
    pub fn clear(&mut self) {
        self.selected.clear();
    }
}

impl Default for EdgeSelectionGraphMousePlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// HoverMousePlugin -- provide hover feedback
// ============================================================================

/// Mouse plugin that tracks the currently hovered vertex/edge.
///
/// Ports `ghidra.graph.viewer.event.mouse.VisualGraphHoverMousePlugin`.
#[derive(Debug, Default)]
pub struct HoverMousePlugin {
    /// ID of the currently hovered vertex, if any.
    hovered_vertex: Option<usize>,
    /// ID of the currently hovered edge, if any.
    hovered_edge: Option<usize>,
    /// Whether the cursor is over the graph background.
    over_background: bool,
}

impl HoverMousePlugin {
    /// Create a new hover plugin.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the currently hovered vertex (or `None` to clear).
    pub fn set_hovered_vertex(&mut self, vertex: Option<usize>) {
        self.hovered_vertex = vertex;
        if vertex.is_some() {
            self.hovered_edge = None;
            self.over_background = false;
        }
    }

    /// Get the currently hovered vertex, if any.
    pub fn hovered_vertex(&self) -> Option<usize> {
        self.hovered_vertex
    }

    /// Set the currently hovered edge (or `None` to clear).
    pub fn set_hovered_edge(&mut self, edge: Option<usize>) {
        self.hovered_edge = edge;
        if edge.is_some() {
            self.hovered_vertex = None;
            self.over_background = false;
        }
    }

    /// Get the currently hovered edge, if any.
    pub fn hovered_edge(&self) -> Option<usize> {
        self.hovered_edge
    }

    /// Mark that the cursor is over the background.
    pub fn set_over_background(&mut self, over: bool) {
        self.over_background = over;
        if over {
            self.hovered_vertex = None;
            self.hovered_edge = None;
        }
    }

    /// Check if the cursor is over the background.
    pub fn is_over_background(&self) -> bool {
        self.over_background
    }

    /// Clear all hover state.
    pub fn clear(&mut self) {
        self.hovered_vertex = None;
        self.hovered_edge = None;
        self.over_background = false;
    }
}

// ============================================================================
// PopupMousePlugin -- trigger popup menus on right-click
// ============================================================================

/// Mouse plugin that triggers context menus on right-click.
///
/// Ports `ghidra.graph.viewer.event.mouse.VisualGraphPopupMousePlugin`.
#[derive(Debug, Default)]
pub struct PopupMousePlugin {
    /// Last popup trigger point.
    trigger_point: Option<Point2d>,
    /// The vertex ID under the cursor when the popup was triggered, if any.
    trigger_vertex: Option<usize>,
}

impl PopupMousePlugin {
    /// Create a new popup plugin.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a popup trigger event.
    pub fn trigger(&mut self, point: Point2d, vertex_id: Option<usize>) {
        self.trigger_point = Some(point);
        self.trigger_vertex = vertex_id;
    }

    /// Get the last trigger point.
    pub fn trigger_point(&self) -> Option<Point2d> {
        self.trigger_point
    }

    /// Get the vertex under the cursor when popup was triggered.
    pub fn trigger_vertex(&self) -> Option<usize> {
        self.trigger_vertex
    }

    /// Consume (clear) the trigger.
    pub fn consume(&mut self) {
        self.trigger_point = None;
        self.trigger_vertex = None;
    }
}

// ============================================================================
// MouseTrackingPlugin -- raw mouse position tracking
// ============================================================================

/// Tracks the raw mouse position within the graph component.
///
/// Ports `ghidra.graph.viewer.event.mouse.VisualGraphMouseTrackingGraphMousePlugin`.
#[derive(Debug, Default)]
pub struct MouseTrackingPlugin {
    /// Current mouse position in graph (world) coordinates.
    graph_position: Point2d,
    /// Current mouse position in screen (viewport) coordinates.
    screen_position: Point2d,
    /// Whether the mouse is currently within the component bounds.
    in_bounds: bool,
}

impl MouseTrackingPlugin {
    /// Create a new mouse tracking plugin.
    pub fn new() -> Self {
        Self::default()
    }

    /// Update the mouse position.
    pub fn update_position(&mut self, graph_pos: Point2d, screen_pos: Point2d, in_bounds: bool) {
        self.graph_position = graph_pos;
        self.screen_position = screen_pos;
        self.in_bounds = in_bounds;
    }

    /// Get the current mouse position in graph coordinates.
    pub fn graph_position(&self) -> Point2d {
        self.graph_position
    }

    /// Get the current mouse position in screen coordinates.
    pub fn screen_position(&self) -> Point2d {
        self.screen_position
    }

    /// Whether the mouse is within the component bounds.
    pub fn is_in_bounds(&self) -> bool {
        self.in_bounds
    }
}

// ============================================================================
// CursorRestoringPlugin -- restores the cursor after drag/hover operations
// ============================================================================

/// Plugin that saves and restores the cursor shape during graph interactions.
///
/// Ports `ghidra.graph.viewer.event.mouse.VisualGraphCursorRestoringGraphMousePlugin`.
#[derive(Debug, Default)]
pub struct CursorRestoringPlugin {
    /// Saved cursor type.
    saved_cursor: Option<CursorType>,
}

/// Cursor types used during graph interactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorType {
    /// Default arrow cursor.
    Default,
    /// Hand cursor (for dragging/panning).
    Hand,
    /// Crosshair cursor (for selection).
    Crosshair,
    /// Move cursor (for vertex dragging).
    Move,
    /// Text cursor (for renaming).
    Text,
}

impl Default for CursorType {
    fn default() -> Self {
        Self::Default
    }
}

impl CursorRestoringPlugin {
    /// Create a new cursor restoring plugin.
    pub fn new() -> Self {
        Self::default()
    }

    /// Save the current cursor and set a new one.
    pub fn save_and_set(&mut self, new_cursor: CursorType) -> Option<CursorType> {
        let prev = self.saved_cursor;
        self.saved_cursor = Some(new_cursor);
        prev
    }

    /// Restore the previously saved cursor.
    pub fn restore(&mut self) -> Option<CursorType> {
        self.saved_cursor.take()
    }
}

// ============================================================================
// PluggableGraphMouse -- composite mouse handler
// ============================================================================

/// A composite mouse handler that dispatches events to registered plugins.
///
/// Ports `ghidra.graph.viewer.event.mouse.VisualGraphPluggableGraphMouse`.
#[derive(Debug)]
pub struct PluggableGraphMouse {
    /// Name of this mouse handler.
    name: String,
    /// Whether the composite handler is enabled.
    enabled: bool,
}

impl PluggableGraphMouse {
    /// Create a new pluggable graph mouse handler.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            enabled: true,
        }
    }

    /// Get the handler name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Enable or disable this handler.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Check if the handler is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

// ============================================================================
// ScreenPositioningPlugin -- position vertex at specific screen coordinates
// ============================================================================

/// Plugin for programmatically positioning vertices in screen space.
///
/// Ports `ghidra.graph.viewer.event.mouse.VisualGraphScreenPositioningPlugin`.
#[derive(Debug, Default)]
pub struct ScreenPositioningPlugin {
    /// Target vertex to position.
    target_vertex: Option<usize>,
    /// Target screen position.
    target_position: Option<Point2d>,
}

impl ScreenPositioningPlugin {
    /// Create a new screen positioning plugin.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a target position for a vertex.
    pub fn set_target(&mut self, vertex_id: usize, position: Point2d) {
        self.target_vertex = Some(vertex_id);
        self.target_position = Some(position);
    }

    /// Consume the positioning request, returning (vertex_id, position) if set.
    pub fn consume_target(&mut self) -> Option<(usize, Point2d)> {
        let result = match (self.target_vertex, self.target_position) {
            (Some(v), Some(p)) => Some((v, p)),
            _ => None,
        };
        self.target_vertex = None;
        self.target_position = None;
        result
    }
}

// ============================================================================
// Satellite mouse plugins
// ============================================================================

/// Mouse plugin for the satellite (overview) view that handles navigation clicks.
///
/// Ports `ghidra.graph.viewer.event.mouse.VisualGraphSatelliteNavigationGraphMousePlugin`.
#[derive(Debug, Default)]
pub struct SatelliteNavigationPlugin {
    /// Last click position in the satellite view.
    click_position: Option<Point2d>,
}

impl SatelliteNavigationPlugin {
    /// Create a new satellite navigation plugin.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a click at the given position.
    pub fn click(&mut self, point: Point2d) {
        self.click_position = Some(point);
    }

    /// Get the last click position.
    pub fn last_click(&self) -> Option<Point2d> {
        self.click_position
    }
}

/// Mouse plugin for the satellite view that handles zooming via scroll.
///
/// Ports `ghidra.graph.viewer.event.mouse.VisualGraphSatelliteScalingGraphMousePlugin`.
#[derive(Debug, Default)]
pub struct SatelliteScalingPlugin {
    /// Current satellite zoom level.
    zoom: f64,
}

impl SatelliteScalingPlugin {
    /// Create a new satellite scaling plugin.
    pub fn new() -> Self {
        Self { zoom: 1.0 }
    }

    /// Get the current zoom level.
    pub fn zoom(&self) -> f64 {
        self.zoom
    }

    /// Process a scroll event.
    pub fn scroll(&mut self, delta: f64) {
        self.zoom = (self.zoom + delta * 0.1).clamp(0.1, 5.0);
    }
}

/// Mouse plugin for the satellite view that handles panning.
///
/// Ports `ghidra.graph.viewer.event.mouse.VisualGraphSatelliteTranslatingGraphMousePlugin`.
#[derive(Debug, Default)]
pub struct SatelliteTranslatingPlugin {
    /// Whether a drag is in progress.
    dragging: bool,
    /// Drag start position.
    drag_start: Option<Point2d>,
}

impl SatelliteTranslatingPlugin {
    /// Create a new satellite translating plugin.
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a drag at the given point.
    pub fn start_drag(&mut self, point: Point2d) {
        self.dragging = true;
        self.drag_start = Some(point);
    }

    /// End the drag.
    pub fn end_drag(&mut self) {
        self.dragging = false;
        self.drag_start = None;
    }

    /// Whether a drag is in progress.
    pub fn is_dragging(&self) -> bool {
        self.dragging
    }

    /// Get the drag start position.
    pub fn drag_start(&self) -> Option<Point2d> {
        self.drag_start
    }
}

// ============================================================================
// AnimatedPickingPlugin -- picking with animation
// ============================================================================

/// A picking plugin that animates the view to the selected vertex.
///
/// Ports `ghidra.graph.viewer.event.mouse.VisualGraphAnimatedPickingGraphMousePlugin`.
#[derive(Debug)]
pub struct AnimatedPickingPlugin {
    /// The base picking behavior.
    _picking: PickingGraphMousePlugin,
    /// Whether animation is enabled.
    animate: bool,
}

impl AnimatedPickingPlugin {
    /// Create a new animated picking plugin.
    pub fn new() -> Self {
        Self {
            _picking: PickingGraphMousePlugin::new(),
            animate: true,
        }
    }

    /// Enable or disable animation.
    pub fn set_animate(&mut self, animate: bool) {
        self.animate = animate;
    }

    /// Whether animation is enabled.
    pub fn is_animate(&self) -> bool {
        self.animate
    }
}

impl Default for AnimatedPickingPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// EventForwardingPlugin -- forward events to external listeners
// ============================================================================

/// Plugin that forwards graph mouse events to external listeners.
///
/// Ports `ghidra.graph.viewer.event.mouse.VisualGraphEventForwardingGraphMousePlugin`.
#[derive(Debug, Default)]
pub struct EventForwardingPlugin {
    /// Whether forwarding is enabled.
    enabled: bool,
}

impl EventForwardingPlugin {
    /// Create a new event forwarding plugin.
    pub fn new() -> Self {
        Self { enabled: true }
    }

    /// Enable or disable forwarding.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Whether forwarding is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

// ============================================================================
// ScrollWheelPanningPlugin -- pan via scroll wheel (Shift+scroll)
// ============================================================================

/// Plugin that pans the graph view using Shift+scroll wheel.
///
/// Ports `ghidra.graph.viewer.event.mouse.VisualGraphScrollWheelPanningPlugin`.
#[derive(Debug, Default)]
pub struct ScrollWheelPanningPlugin {
    /// Accumulated horizontal pan offset.
    pub pan_x: f64,
    /// Accumulated vertical pan offset.
    pub pan_y: f64,
    /// Pan speed multiplier.
    speed: f64,
}

impl ScrollWheelPanningPlugin {
    /// Create a new scroll wheel panning plugin.
    pub fn new() -> Self {
        Self { pan_x: 0.0, pan_y: 0.0, speed: 10.0 }
    }

    /// Process a scroll event for panning.
    pub fn scroll(&mut self, delta_x: f64, delta_y: f64) {
        self.pan_x += delta_x * self.speed;
        self.pan_y += delta_y * self.speed;
    }

    /// Set the pan speed.
    pub fn set_speed(&mut self, speed: f64) {
        self.speed = speed;
    }

    /// Reset pan offsets.
    pub fn reset(&mut self) {
        self.pan_x = 0.0;
        self.pan_y = 0.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_picking_plugin_single() {
        let mut plugin = PickingGraphMousePlugin::new();
        plugin.pick_single(1);
        assert!(plugin.picked_vertices().contains(&1));
        assert_eq!(plugin.picked_vertices().len(), 1);

        plugin.pick_single(2);
        assert!(plugin.picked_vertices().contains(&2));
        assert!(!plugin.picked_vertices().contains(&1));
    }

    #[test]
    fn test_picking_plugin_toggle() {
        let mut plugin = PickingGraphMousePlugin::new();
        plugin.toggle_pick(1);
        assert!(plugin.picked_vertices().contains(&1));

        plugin.toggle_pick(1);
        assert!(!plugin.picked_vertices().contains(&1));
    }

    #[test]
    fn test_scaling_plugin_zoom() {
        let mut plugin = ScalingGraphMousePlugin::new();
        assert_eq!(plugin.scale(), 1.0);

        plugin.process_scroll(1.0);
        assert_eq!(plugin.scale(), 1.1);

        plugin.process_scroll(-1.0);
        assert_eq!(plugin.scale(), 1.0);
    }

    #[test]
    fn test_scaling_plugin_limits() {
        let mut plugin = ScalingGraphMousePlugin::new();
        plugin.set_zoom_limits(0.5, 2.0);
        plugin.set_scale(3.0);
        assert_eq!(plugin.scale(), 2.0);

        plugin.set_scale(0.1);
        assert_eq!(plugin.scale(), 0.5);
    }

    #[test]
    fn test_translating_plugin_drag() {
        let mut plugin = TranslatingGraphMousePlugin::new();
        plugin.start_drag(Point2d::new(0.0, 0.0));
        assert!(plugin.is_dragging());

        let (dx, dy) = plugin.update_drag(Point2d::new(10.0, 20.0));
        assert_eq!(dx, 10.0);
        assert_eq!(dy, 20.0);
        assert_eq!(plugin.translate_x, 10.0);
        assert_eq!(plugin.translate_y, 20.0);

        plugin.end_drag();
        assert!(!plugin.is_dragging());
    }

    #[test]
    fn test_edge_selection() {
        let mut plugin = EdgeSelectionGraphMousePlugin::new();
        plugin.select_edge(1);
        plugin.select_edge(2);
        assert_eq!(plugin.selected_edges().len(), 2);

        plugin.deselect_edge(1);
        assert_eq!(plugin.selected_edges().len(), 1);
        assert!(plugin.selected_edges().contains(&2));

        plugin.toggle_edge(2);
        assert!(plugin.selected_edges().is_empty());
    }

    #[test]
    fn test_hover_plugin() {
        let mut plugin = HoverMousePlugin::new();
        assert!(plugin.hovered_vertex().is_none());

        plugin.set_hovered_vertex(Some(5));
        assert_eq!(plugin.hovered_vertex(), Some(5));
        assert!(plugin.hovered_edge().is_none());

        plugin.set_hovered_edge(Some(3));
        assert_eq!(plugin.hovered_edge(), Some(3));
        assert!(plugin.hovered_vertex().is_none());

        plugin.clear();
        assert!(plugin.hovered_vertex().is_none());
    }

    #[test]
    fn test_popup_plugin() {
        let mut plugin = PopupMousePlugin::new();
        plugin.trigger(Point2d::new(100.0, 200.0), Some(42));
        assert_eq!(plugin.trigger_point(), Some(Point2d::new(100.0, 200.0)));
        assert_eq!(plugin.trigger_vertex(), Some(42));

        plugin.consume();
        assert!(plugin.trigger_point().is_none());
    }

    #[test]
    fn test_mouse_tracking_plugin() {
        let mut plugin = MouseTrackingPlugin::new();
        plugin.update_position(Point2d::new(50.0, 60.0), Point2d::new(100.0, 120.0), true);
        assert_eq!(plugin.graph_position(), Point2d::new(50.0, 60.0));
        assert!(plugin.is_in_bounds());
    }

    #[test]
    fn test_cursor_restoring_plugin() {
        let mut plugin = CursorRestoringPlugin::new();
        plugin.save_and_set(CursorType::Hand);
        assert_eq!(plugin.restore(), Some(CursorType::Hand));
    }

    #[test]
    fn test_screen_positioning_plugin() {
        let mut plugin = ScreenPositioningPlugin::new();
        plugin.set_target(7, Point2d::new(300.0, 400.0));
        let result = plugin.consume_target();
        assert_eq!(result, Some((7, Point2d::new(300.0, 400.0))));
        assert!(plugin.consume_target().is_none());
    }

    #[test]
    fn test_satellite_navigation() {
        let mut plugin = SatelliteNavigationPlugin::new();
        plugin.click(Point2d::new(50.0, 75.0));
        assert_eq!(plugin.last_click(), Some(Point2d::new(50.0, 75.0)));
    }

    #[test]
    fn test_satellite_scaling() {
        let mut plugin = SatelliteScalingPlugin::new();
        assert_eq!(plugin.zoom(), 1.0);
        plugin.scroll(1.0);
        assert_eq!(plugin.zoom(), 1.1);
    }

    #[test]
    fn test_satellite_translating() {
        let mut plugin = SatelliteTranslatingPlugin::new();
        assert!(!plugin.is_dragging());
        plugin.start_drag(Point2d::new(10.0, 20.0));
        assert!(plugin.is_dragging());
        plugin.end_drag();
        assert!(!plugin.is_dragging());
    }

    #[test]
    fn test_scroll_wheel_panning() {
        let mut plugin = ScrollWheelPanningPlugin::new();
        plugin.set_speed(5.0);
        plugin.scroll(1.0, 2.0);
        assert_eq!(plugin.pan_x, 5.0);
        assert_eq!(plugin.pan_y, 10.0);
        plugin.reset();
        assert_eq!(plugin.pan_x, 0.0);
    }

    #[test]
    fn test_pluggable_graph_mouse() {
        let mut mouse = PluggableGraphMouse::new("test");
        assert_eq!(mouse.name(), "test");
        assert!(mouse.is_enabled());
        mouse.set_enabled(false);
        assert!(!mouse.is_enabled());
    }

    #[test]
    fn test_vertex_mouse_info() {
        let info = VertexMouseInfo::new(
            42,
            Point2d::new(10.0, 20.0),
            Point2d::new(5.0, 10.0),
            true,
        );
        assert!(info.in_vertex);
        assert_eq!(info.vertex_id, 42);
        assert_eq!(info.graph_point, Point2d::new(10.0, 20.0));
    }
}
