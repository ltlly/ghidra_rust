//! Extended mouse plugin implementations for visual graph interaction.
//!
//! Ports Ghidra's visual graph mouse plugin classes:
//! - [`VisualGraphAbstractGraphMousePlugin`] -- base for all graph mouse plugins.
//! - [`VisualGraphSatelliteGraphMouse`] -- mouse handler for the satellite view.
//! - [`VisualGraphSatelliteAbstractGraphMousePlugin`] -- base for satellite mouse plugins.
//! - [`VisualGraphSatelliteScalingGraphMousePlugin`] -- satellite view zoom.
//! - [`VisualGraphSatelliteTranslatingGraphMousePlugin`] -- satellite view panning.
//! - [`VisualGraphSatelliteNavigationGraphMousePlugin`] -- satellite view click navigation.
//! - [`JungPickingGraphMousePlugin`] -- vertex picking/selection.
//! - [`VisualGraphScreenPositioningPlugin`] -- screen-position-based navigation.
//! - [`VisualGraphScrollWheelPanningPlugin`] -- scroll wheel panning.

use crate::graph::viewer::{Point2D, Rect2D};

// ============================================================================
// Mouse event types
// ============================================================================

/// Mouse button identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButton {
    /// Left mouse button.
    Left,
    /// Right mouse button.
    Right,
    /// Middle mouse button.
    Middle,
}

/// A mouse event in the graph viewer.
#[derive(Debug, Clone)]
pub struct GraphMouseEvent {
    /// Mouse position in view coordinates.
    pub position: Point2D,
    /// Mouse position in layout (graph) coordinates.
    pub layout_position: Point2D,
    /// Which button was pressed/released.
    pub button: MouseButton,
    /// Whether shift was held.
    pub shift: bool,
    /// Whether control was held.
    pub control: bool,
    /// Whether alt was held.
    pub alt: bool,
    /// Scroll wheel delta (if scroll event).
    pub scroll_delta: f64,
}

impl GraphMouseEvent {
    /// Create a new mouse event.
    pub fn new(position: Point2D, button: MouseButton) -> Self {
        Self {
            position,
            layout_position: position,
            button,
            shift: false,
            control: false,
            alt: false,
            scroll_delta: 0.0,
        }
    }

    /// Create a scroll event.
    pub fn scroll(position: Point2D, delta: f64) -> Self {
        Self {
            position,
            layout_position: position,
            button: MouseButton::Left,
            shift: false,
            control: false,
            alt: false,
            scroll_delta: delta,
        }
    }
}

// ============================================================================
// GraphMousePlugin trait
// ============================================================================

/// Trait for graph mouse plugins that handle specific mouse interactions.
///
/// Ports Ghidra's `VisualGraphMousePlugin` interface.
pub trait GraphMousePlugin: Send + std::fmt::Debug {
    /// The name of this plugin.
    fn name(&self) -> &str;

    /// Called when a mouse button is pressed.
    fn mouse_pressed(&mut self, event: &GraphMouseEvent) -> bool {
        false
    }

    /// Called when a mouse button is released.
    fn mouse_released(&mut self, event: &GraphMouseEvent) -> bool {
        false
    }

    /// Called when the mouse is moved (with button held).
    fn mouse_dragged(&mut self, event: &GraphMouseEvent) -> bool {
        false
    }

    /// Called when the mouse is moved (without button held).
    fn mouse_moved(&mut self, event: &GraphMouseEvent) -> bool {
        false
    }

    /// Called on scroll wheel events.
    fn mouse_scrolled(&mut self, event: &GraphMouseEvent) -> bool {
        false
    }

    /// Whether this plugin is currently active.
    fn is_active(&self) -> bool {
        false
    }
}

// ============================================================================
// VisualGraphAbstractGraphMousePlugin
// ============================================================================

/// Abstract base for graph mouse plugins.
///
/// Ports `ghidra.graph.viewer.event.mouse.VisualGraphAbstractGraphMousePlugin`.
/// Provides common state tracking (pressed position, modifiers).
#[derive(Debug, Clone)]
pub struct VisualGraphAbstractGraphMousePlugin {
    /// The name of this plugin.
    plugin_name: String,
    /// Whether the plugin is currently active (mouse pressed).
    active: bool,
    /// The position where the mouse was last pressed.
    pub pressed_position: Option<Point2D>,
    /// The current position during a drag.
    pub current_position: Option<Point2D>,
    /// Whether shift was held during the last press.
    pub shift_held: bool,
    /// Whether control was held during the last press.
    pub control_held: bool,
}

impl VisualGraphAbstractGraphMousePlugin {
    /// Create a new abstract mouse plugin.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            plugin_name: name.into(),
            active: false,
            pressed_position: None,
            current_position: None,
            shift_held: false,
            control_held: false,
        }
    }

    /// Compute the drag delta since the last press.
    pub fn drag_delta(&self) -> Option<Point2D> {
        match (self.pressed_position, self.current_position) {
            (Some(press), Some(current)) => Some(Point2D::new(
                current.x - press.x,
                current.y - press.y,
            )),
            _ => None,
        }
    }

    /// Reset the plugin state.
    pub fn reset(&mut self) {
        self.active = false;
        self.pressed_position = None;
        self.current_position = None;
    }
}

impl GraphMousePlugin for VisualGraphAbstractGraphMousePlugin {
    fn name(&self) -> &str {
        &self.plugin_name
    }

    fn mouse_pressed(&mut self, event: &GraphMouseEvent) -> bool {
        self.active = true;
        self.pressed_position = Some(event.position);
        self.current_position = Some(event.position);
        self.shift_held = event.shift;
        self.control_held = event.control;
        false
    }

    fn mouse_released(&mut self, _event: &GraphMouseEvent) -> bool {
        self.active = false;
        self.pressed_position = None;
        self.current_position = None;
        false
    }

    fn mouse_dragged(&mut self, event: &GraphMouseEvent) -> bool {
        self.current_position = Some(event.position);
        false
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ============================================================================
// VisualGraphSatelliteGraphMouse
// ============================================================================

/// Mouse handler for the satellite (overview) view.
///
/// Ports `ghidra.graph.viewer.event.mouse.VisualGraphSatelliteGraphMouse`.
/// Manages a collection of mouse plugins specific to the satellite view
/// and dispatches events to them.
#[derive(Debug)]
pub struct VisualGraphSatelliteGraphMouse {
    /// Registered satellite mouse plugins.
    plugins: Vec<Box<dyn GraphMousePlugin>>,
    /// Whether the satellite mouse is enabled.
    enabled: bool,
}

impl VisualGraphSatelliteGraphMouse {
    /// Create a new satellite graph mouse handler.
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
            enabled: true,
        }
    }

    /// Register a plugin.
    pub fn add_plugin(&mut self, plugin: Box<dyn GraphMousePlugin>) {
        self.plugins.push(plugin);
    }

    /// Enable or disable this mouse handler.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Whether this handler is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Dispatch a press event to all plugins.
    pub fn on_mouse_pressed(&mut self, event: &GraphMouseEvent) -> bool {
        if !self.enabled {
            return false;
        }
        for plugin in &mut self.plugins {
            if plugin.mouse_pressed(event) {
                return true;
            }
        }
        false
    }

    /// Dispatch a release event.
    pub fn on_mouse_released(&mut self, event: &GraphMouseEvent) -> bool {
        if !self.enabled {
            return false;
        }
        for plugin in &mut self.plugins {
            if plugin.mouse_released(event) {
                return true;
            }
        }
        false
    }

    /// Dispatch a drag event.
    pub fn on_mouse_dragged(&mut self, event: &GraphMouseEvent) -> bool {
        if !self.enabled {
            return false;
        }
        for plugin in &mut self.plugins {
            if plugin.mouse_dragged(event) {
                return true;
            }
        }
        false
    }
}

impl Default for VisualGraphSatelliteGraphMouse {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// VisualGraphSatelliteAbstractGraphMousePlugin
// ============================================================================

/// Abstract base for satellite view mouse plugins.
///
/// Ports `ghidra.graph.viewer.event.mouse.VisualGraphSatelliteAbstractGraphMousePlugin`.
#[derive(Debug, Clone)]
pub struct VisualGraphSatelliteAbstractGraphMousePlugin {
    /// The name.
    name: String,
    /// Whether the plugin is active.
    active: bool,
}

impl VisualGraphSatelliteAbstractGraphMousePlugin {
    /// Create a new satellite mouse plugin.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            active: false,
        }
    }
}

impl GraphMousePlugin for VisualGraphSatelliteAbstractGraphMousePlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ============================================================================
// VisualGraphSatelliteScalingGraphMousePlugin
// ============================================================================

/// Satellite view zoom (scaling) plugin.
///
/// Ports `ghidra.graph.viewer.event.mouse.VisualGraphSatelliteScalingGraphMousePlugin`.
/// Handles scroll wheel zooming in the satellite view.
#[derive(Debug, Clone)]
pub struct VisualGraphSatelliteScalingGraphMousePlugin {
    /// Base plugin state.
    base: VisualGraphSatelliteAbstractGraphMousePlugin,
    /// Zoom factor per scroll step.
    pub zoom_factor: f64,
    /// Minimum zoom level.
    pub min_zoom: f64,
    /// Maximum zoom level.
    pub max_zoom: f64,
}

impl VisualGraphSatelliteScalingGraphMousePlugin {
    /// Create a new satellite scaling plugin.
    pub fn new() -> Self {
        Self {
            base: VisualGraphSatelliteAbstractGraphMousePlugin::new("Satellite Scaling"),
            zoom_factor: 1.1,
            min_zoom: 0.01,
            max_zoom: 10.0,
        }
    }

    /// Compute the new zoom level after a scroll event.
    pub fn compute_zoom(&self, current_zoom: f64, scroll_delta: f64) -> f64 {
        let factor = if scroll_delta > 0.0 {
            self.zoom_factor
        } else {
            1.0 / self.zoom_factor
        };
        (current_zoom * factor).clamp(self.min_zoom, self.max_zoom)
    }
}

impl Default for VisualGraphSatelliteScalingGraphMousePlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl GraphMousePlugin for VisualGraphSatelliteScalingGraphMousePlugin {
    fn name(&self) -> &str {
        self.base.name()
    }

    fn mouse_scrolled(&mut self, _event: &GraphMouseEvent) -> bool {
        // In a full implementation, this would update the zoom level
        true
    }
}

// ============================================================================
// VisualGraphSatelliteTranslatingGraphMousePlugin
// ============================================================================

/// Satellite view panning (translating) plugin.
///
/// Ports `ghidra.graph.viewer.event.mouse.VisualGraphSatelliteTranslatingGraphMousePlugin`.
/// Handles click-and-drag panning in the satellite view.
#[derive(Debug, Clone)]
pub struct VisualGraphSatelliteTranslatingGraphMousePlugin {
    /// Base plugin state.
    base: VisualGraphAbstractGraphMousePlugin,
    /// Accumulated translation offset.
    pub translation: Point2D,
}

impl VisualGraphSatelliteTranslatingGraphMousePlugin {
    /// Create a new satellite translating plugin.
    pub fn new() -> Self {
        Self {
            base: VisualGraphAbstractGraphMousePlugin::new("Satellite Translating"),
            translation: Point2D::ZERO,
        }
    }

    /// Apply a translation delta.
    pub fn translate(&mut self, dx: f64, dy: f64) {
        self.translation.x += dx;
        self.translation.y += dy;
    }

    /// Reset the translation to origin.
    pub fn reset_translation(&mut self) {
        self.translation = Point2D::ZERO;
    }
}

impl Default for VisualGraphSatelliteTranslatingGraphMousePlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl GraphMousePlugin for VisualGraphSatelliteTranslatingGraphMousePlugin {
    fn name(&self) -> &str {
        self.base.name()
    }

    fn mouse_pressed(&mut self, event: &GraphMouseEvent) -> bool {
        self.base.mouse_pressed(event);
        true
    }

    fn mouse_released(&mut self, event: &GraphMouseEvent) -> bool {
        self.base.mouse_released(event);
        true
    }

    fn mouse_dragged(&mut self, event: &GraphMouseEvent) -> bool {
        let old = self.base.current_position;
        self.base.mouse_dragged(event);
        if let (Some(prev), Some(curr)) = (old, self.base.current_position) {
            self.translate(curr.x - prev.x, curr.y - prev.y);
        }
        true
    }

    fn is_active(&self) -> bool {
        self.base.is_active()
    }
}

// ============================================================================
// VisualGraphSatelliteNavigationGraphMousePlugin
// ============================================================================

/// Satellite view click-to-navigate plugin.
///
/// Ports `ghidra.graph.viewer.event.mouse.VisualGraphSatelliteNavigationGraphMousePlugin`.
/// Handles clicks in the satellite view to navigate the main view.
#[derive(Debug, Clone)]
pub struct VisualGraphSatelliteNavigationGraphMousePlugin {
    /// Base state.
    base: VisualGraphSatelliteAbstractGraphMousePlugin,
    /// The target viewport center after navigation.
    pub target_center: Option<Point2D>,
}

impl VisualGraphSatelliteNavigationGraphMousePlugin {
    /// Create a new satellite navigation plugin.
    pub fn new() -> Self {
        Self {
            base: VisualGraphSatelliteAbstractGraphMousePlugin::new("Satellite Navigation"),
            target_center: None,
        }
    }

    /// Get the target center set by the last click.
    pub fn navigate_to(&mut self, point: Point2D) {
        self.target_center = Some(point);
    }
}

impl Default for VisualGraphSatelliteNavigationGraphMousePlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl GraphMousePlugin for VisualGraphSatelliteNavigationGraphMousePlugin {
    fn name(&self) -> &str {
        self.base.name()
    }

    fn mouse_pressed(&mut self, event: &GraphMouseEvent) -> bool {
        self.target_center = Some(event.layout_position);
        true
    }
}

// ============================================================================
// JungPickingGraphMousePlugin
// ============================================================================

/// Vertex picking/selection plugin.
///
/// Ports `ghidra.graph.viewer.event.mouse.JungPickingGraphMousePlugin`.
/// Handles click-to-select vertices in the main graph view.
#[derive(Debug, Clone)]
pub struct JungPickingGraphMousePlugin {
    /// Base state.
    base: VisualGraphAbstractGraphMousePlugin,
    /// IDs of vertices picked during the current interaction.
    pub picked_vertices: Vec<String>,
    /// Whether to add to the current selection (shift held).
    pub additive: bool,
}

impl JungPickingGraphMousePlugin {
    /// Create a new picking plugin.
    pub fn new() -> Self {
        Self {
            base: VisualGraphAbstractGraphMousePlugin::new("Picking"),
            picked_vertices: Vec::new(),
            additive: false,
        }
    }

    /// Clear picked vertices.
    pub fn clear_picked(&mut self) {
        self.picked_vertices.clear();
    }

    /// Pick a vertex.
    pub fn pick_vertex(&mut self, vertex_id: impl Into<String>) {
        self.picked_vertices.push(vertex_id.into());
    }
}

impl Default for JungPickingGraphMousePlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl GraphMousePlugin for JungPickingGraphMousePlugin {
    fn name(&self) -> &str {
        self.base.name()
    }

    fn mouse_pressed(&mut self, event: &GraphMouseEvent) -> bool {
        self.additive = event.shift;
        if !self.additive {
            self.picked_vertices.clear();
        }
        self.base.mouse_pressed(event);
        true
    }

    fn mouse_released(&mut self, event: &GraphMouseEvent) -> bool {
        self.base.mouse_released(event);
        true
    }

    fn is_active(&self) -> bool {
        self.base.is_active()
    }
}

// ============================================================================
// VisualGraphScreenPositioningPlugin
// ============================================================================

/// Screen-position-based navigation plugin.
///
/// Ports `ghidra.graph.viewer.event.mouse.VisualGraphScreenPositioningPlugin`.
/// Handles clicking at a screen position to reposition the graph viewport.
#[derive(Debug, Clone, Default)]
pub struct VisualGraphScreenPositioningPlugin {
    /// The screen position that was clicked.
    pub click_position: Option<Point2D>,
    /// Whether the plugin is active.
    active: bool,
}

impl VisualGraphScreenPositioningPlugin {
    /// Create a new screen positioning plugin.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the graph-space position from a screen click.
    pub fn screen_to_graph(&self, screen_pos: Point2D, offset: Point2D, zoom: f64) -> Point2D {
        Point2D::new(
            (screen_pos.x - offset.x) / zoom,
            (screen_pos.y - offset.y) / zoom,
        )
    }
}

impl GraphMousePlugin for VisualGraphScreenPositioningPlugin {
    fn name(&self) -> &str {
        "Screen Positioning"
    }

    fn mouse_pressed(&mut self, event: &GraphMouseEvent) -> bool {
        self.click_position = Some(event.position);
        self.active = true;
        true
    }

    fn mouse_released(&mut self, _event: &GraphMouseEvent) -> bool {
        self.active = false;
        true
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

// ============================================================================
// VisualGraphScrollWheelPanningPlugin
// ============================================================================

/// Scroll wheel panning plugin.
///
/// Ports `ghidra.graph.viewer.event.mouse.VisualGraphScrollWheelPanningPlugin`.
/// Handles scroll wheel events for vertical/horizontal panning.
#[derive(Debug, Clone)]
pub struct VisualGraphScrollWheelPanningPlugin {
    /// Pixels per scroll notch.
    pub scroll_speed: f64,
    /// Accumulated scroll offset.
    pub offset: Point2D,
}

impl VisualGraphScrollWheelPanningPlugin {
    /// Create a new scroll wheel panning plugin.
    pub fn new() -> Self {
        Self {
            scroll_speed: 30.0,
            offset: Point2D::ZERO,
        }
    }

    /// Apply a scroll delta.
    pub fn apply_scroll(&mut self, delta: f64, shift_held: bool) {
        if shift_held {
            self.offset.x += delta * self.scroll_speed;
        } else {
            self.offset.y += delta * self.scroll_speed;
        }
    }

    /// Reset the scroll offset.
    pub fn reset(&mut self) {
        self.offset = Point2D::ZERO;
    }
}

impl Default for VisualGraphScrollWheelPanningPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl GraphMousePlugin for VisualGraphScrollWheelPanningPlugin {
    fn name(&self) -> &str {
        "Scroll Wheel Panning"
    }

    fn mouse_scrolled(&mut self, event: &GraphMouseEvent) -> bool {
        self.apply_scroll(event.scroll_delta, event.shift);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_mouse_event_new() {
        let event = GraphMouseEvent::new(Point2D::new(10.0, 20.0), MouseButton::Left);
        assert_eq!(event.position, Point2D::new(10.0, 20.0));
        assert_eq!(event.button, MouseButton::Left);
        assert!(!event.shift);
    }

    #[test]
    fn abstract_plugin_drag_delta() {
        let mut plugin = VisualGraphAbstractGraphMousePlugin::new("Test");
        let press = GraphMouseEvent::new(Point2D::new(0.0, 0.0), MouseButton::Left);
        plugin.mouse_pressed(&press);
        let drag = GraphMouseEvent::new(Point2D::new(50.0, 30.0), MouseButton::Left);
        plugin.mouse_dragged(&drag);
        let delta = plugin.drag_delta().unwrap();
        assert!((delta.x - 50.0).abs() < 1e-6);
        assert!((delta.y - 30.0).abs() < 1e-6);
    }

    #[test]
    fn abstract_plugin_reset() {
        let mut plugin = VisualGraphAbstractGraphMousePlugin::new("Test");
        let event = GraphMouseEvent::new(Point2D::new(10.0, 10.0), MouseButton::Left);
        plugin.mouse_pressed(&event);
        assert!(plugin.is_active());
        plugin.reset();
        assert!(!plugin.is_active());
    }

    #[test]
    fn satellite_graph_mouse_dispatch() {
        let mut mouse = VisualGraphSatelliteGraphMouse::new();
        assert!(mouse.is_enabled());
        mouse.set_enabled(false);
        let event = GraphMouseEvent::new(Point2D::new(0.0, 0.0), MouseButton::Left);
        assert!(!mouse.on_mouse_pressed(&event));
    }

    #[test]
    fn satellite_scaling_compute_zoom() {
        let plugin = VisualGraphSatelliteScalingGraphMousePlugin::new();
        let zoom = plugin.compute_zoom(1.0, 1.0);
        assert!((zoom - 1.1).abs() < 1e-6);
        let zoom_out = plugin.compute_zoom(1.0, -1.0);
        assert!((zoom_out - 1.0 / 1.1).abs() < 1e-6);
    }

    #[test]
    fn satellite_scaling_zoom_clamp() {
        let plugin = VisualGraphSatelliteScalingGraphMousePlugin::new();
        let zoom = plugin.compute_zoom(0.001, -1.0);
        assert!(zoom >= plugin.min_zoom);
        let zoom = plugin.compute_zoom(100.0, 1.0);
        assert!(zoom <= plugin.max_zoom);
    }

    #[test]
    fn satellite_translating_translate() {
        let mut plugin = VisualGraphSatelliteTranslatingGraphMousePlugin::new();
        plugin.translate(10.0, 20.0);
        assert!((plugin.translation.x - 10.0).abs() < 1e-6);
        assert!((plugin.translation.y - 20.0).abs() < 1e-6);
        plugin.reset_translation();
        assert_eq!(plugin.translation, Point2D::ZERO);
    }

    #[test]
    fn satellite_navigation_click() {
        let mut plugin = VisualGraphSatelliteNavigationGraphMousePlugin::new();
        let event = GraphMouseEvent::new(Point2D::new(100.0, 200.0), MouseButton::Left);
        plugin.mouse_pressed(&event);
        assert_eq!(plugin.target_center, Some(Point2D::new(100.0, 200.0)));
    }

    #[test]
    fn picking_plugin_select() {
        let mut plugin = JungPickingGraphMousePlugin::new();
        plugin.pick_vertex("v1");
        plugin.pick_vertex("v2");
        assert_eq!(plugin.picked_vertices.len(), 2);
        plugin.clear_picked();
        assert!(plugin.picked_vertices.is_empty());
    }

    #[test]
    fn screen_positioning_screen_to_graph() {
        let plugin = VisualGraphScreenPositioningPlugin::new();
        let result = plugin.screen_to_graph(
            Point2D::new(200.0, 300.0),
            Point2D::new(100.0, 100.0),
            2.0,
        );
        assert!((result.x - 50.0).abs() < 1e-6);
        assert!((result.y - 100.0).abs() < 1e-6);
    }

    #[test]
    fn scroll_panning_apply() {
        let mut plugin = VisualGraphScrollWheelPanningPlugin::new();
        plugin.apply_scroll(1.0, false);
        assert!((plugin.offset.y - 30.0).abs() < 1e-6);
        assert!((plugin.offset.x).abs() < 1e-6);

        plugin.apply_scroll(1.0, true);
        assert!((plugin.offset.x - 30.0).abs() < 1e-6);
    }

    #[test]
    fn scroll_panning_reset() {
        let mut plugin = VisualGraphScrollWheelPanningPlugin::new();
        plugin.apply_scroll(5.0, false);
        plugin.reset();
        assert_eq!(plugin.offset, Point2D::ZERO);
    }
}
