//! Visual graph mouse plugins.
//!
//! Ports Ghidra's `ghidra.graph.viewer.event.mouse` plugin classes:
//! `VisualGraphPickingGraphMousePlugin`, `VisualGraphHoverMousePlugin`,
//! `VisualGraphPopupMousePlugin`, `VisualGraphEdgeSelectionGraphMousePlugin`,
//! `VisualGraphScalingGraphMousePlugin`, `VisualGraphTranslatingGraphMousePlugin`,
//! `VisualGraphScrollWheelPanningPlugin`, `VisualGraphScreenPositioningPlugin`,
//! `VisualGraphZoomingPickingGraphMousePlugin`,
//! `VisualGraphAnimatedPickingGraphMousePlugin`,
//! `VisualGraphEventForwardingGraphMousePlugin`,
//! `VisualGraphCursorRestoringGraphMousePlugin`,
//! `VisualGraphMouseTrackingGraphMousePlugin`.

use serde::{Deserialize, Serialize};

/// Type of mouse event in the visual graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MouseEventType {
    /// Mouse click.
    Click,
    /// Double click.
    DoubleClick,
    /// Mouse drag start.
    DragStart,
    /// Mouse drag.
    Drag,
    /// Mouse drag end.
    DragEnd,
    /// Mouse hover (enter).
    HoverEnter,
    /// Mouse hover (exit).
    HoverExit,
    /// Mouse wheel scroll.
    Scroll,
    /// Right click (context menu).
    RightClick,
}

/// Mouse button identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MouseButton {
    /// Left mouse button.
    Left,
    /// Middle mouse button.
    Middle,
    /// Right mouse button.
    Right,
}

/// A mouse event in the graph viewer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphMouseEvent {
    /// The type of event.
    pub event_type: MouseEventType,
    /// Which button was pressed (if applicable).
    pub button: Option<MouseButton>,
    /// X coordinate in view space.
    pub x: f64,
    /// Y coordinate in view space.
    pub y: f64,
    /// Whether Ctrl was held.
    pub ctrl_down: bool,
    /// Whether Shift was held.
    pub shift_down: bool,
    /// Whether Alt was held.
    pub alt_down: bool,
    /// The vertex ID under the cursor (if any).
    pub vertex_id: Option<String>,
    /// The edge ID under the cursor (if any).
    pub edge_id: Option<String>,
}

impl GraphMouseEvent {
    /// Create a new graph mouse event.
    pub fn new(event_type: MouseEventType, x: f64, y: f64) -> Self {
        Self {
            event_type,
            button: None,
            x,
            y,
            ctrl_down: false,
            shift_down: false,
            alt_down: false,
            vertex_id: None,
            edge_id: None,
        }
    }
}

/// Trait for visual graph mouse plugins.
///
/// Port of Ghidra's `VisualGraphMousePlugin`.
pub trait VisualGraphMousePlugin: std::fmt::Debug {
    /// The name of this plugin.
    fn name(&self) -> &str;

    /// Whether this plugin handles the given event type.
    fn handles_event(&self, event_type: MouseEventType) -> bool;

    /// Process a mouse event. Returns true if the event was consumed.
    fn process_event(&mut self, event: &GraphMouseEvent) -> bool;
}

/// Picking plugin for selecting vertices and edges.
///
/// Port of Ghidra's `VisualGraphPickingGraphMousePlugin`.
#[derive(Debug, Clone, Default)]
pub struct PickingGraphMousePlugin {
    /// Currently selected vertex IDs.
    pub selected_vertices: Vec<String>,
    /// Currently selected edge IDs.
    pub selected_edges: Vec<String>,
    /// Whether multi-select mode is active.
    pub multi_select: bool,
}

impl PickingGraphMousePlugin {
    /// Create a new picking plugin.
    pub fn new() -> Self {
        Self::default()
    }

    /// Select a vertex.
    pub fn select_vertex(&mut self, vertex_id: impl Into<String>) {
        let id = vertex_id.into();
        if !self.multi_select {
            self.selected_vertices.clear();
            self.selected_edges.clear();
        }
        if !self.selected_vertices.contains(&id) {
            self.selected_vertices.push(id);
        }
    }

    /// Select an edge.
    pub fn select_edge(&mut self, edge_id: impl Into<String>) {
        let id = edge_id.into();
        if !self.multi_select {
            self.selected_vertices.clear();
            self.selected_edges.clear();
        }
        if !self.selected_edges.contains(&id) {
            self.selected_edges.push(id);
        }
    }

    /// Clear the selection.
    pub fn clear_selection(&mut self) {
        self.selected_vertices.clear();
        self.selected_edges.clear();
    }
}

impl VisualGraphMousePlugin for PickingGraphMousePlugin {
    fn name(&self) -> &str {
        "PickingGraphMousePlugin"
    }

    fn handles_event(&self, event_type: MouseEventType) -> bool {
        matches!(event_type, MouseEventType::Click | MouseEventType::DoubleClick)
    }

    fn process_event(&mut self, event: &GraphMouseEvent) -> bool {
        if let Some(ref vid) = event.vertex_id {
            self.select_vertex(vid.clone());
            return true;
        }
        if let Some(ref eid) = event.edge_id {
            self.select_edge(eid.clone());
            return true;
        }
        self.clear_selection();
        true
    }
}

/// Hover plugin for tooltips.
///
/// Port of Ghidra's `VisualGraphHoverMousePlugin`.
#[derive(Debug, Clone, Default)]
pub struct HoverMousePlugin {
    /// The currently hovered vertex ID.
    pub hovered_vertex: Option<String>,
    /// The currently hovered edge ID.
    pub hovered_edge: Option<String>,
    /// Hover delay in milliseconds.
    pub hover_delay_ms: u64,
}

impl HoverMousePlugin {
    /// Create a new hover plugin.
    pub fn new() -> Self {
        Self {
            hovered_vertex: None,
            hovered_edge: None,
            hover_delay_ms: 500,
        }
    }
}

impl VisualGraphMousePlugin for HoverMousePlugin {
    fn name(&self) -> &str {
        "HoverMousePlugin"
    }

    fn handles_event(&self, event_type: MouseEventType) -> bool {
        matches!(
            event_type,
            MouseEventType::HoverEnter | MouseEventType::HoverExit
        )
    }

    fn process_event(&mut self, event: &GraphMouseEvent) -> bool {
        match event.event_type {
            MouseEventType::HoverEnter => {
                self.hovered_vertex = event.vertex_id.clone();
                self.hovered_edge = event.edge_id.clone();
                true
            }
            MouseEventType::HoverExit => {
                self.hovered_vertex = None;
                self.hovered_edge = None;
                true
            }
            _ => false,
        }
    }
}

/// Popup plugin for context menus.
///
/// Port of Ghidra's `VisualGraphPopupMousePlugin`.
#[derive(Debug, Clone, Default)]
pub struct PopupMousePlugin {
    /// Whether the popup is currently visible.
    pub popup_visible: bool,
}

impl PopupMousePlugin {
    /// Create a new popup plugin.
    pub fn new() -> Self {
        Self::default()
    }
}

impl VisualGraphMousePlugin for PopupMousePlugin {
    fn name(&self) -> &str {
        "PopupMousePlugin"
    }

    fn handles_event(&self, event_type: MouseEventType) -> bool {
        event_type == MouseEventType::RightClick
    }

    fn process_event(&mut self, event: &GraphMouseEvent) -> bool {
        if event.event_type == MouseEventType::RightClick {
            self.popup_visible = true;
            true
        } else {
            false
        }
    }
}

/// Edge selection plugin.
///
/// Port of Ghidra's `VisualGraphEdgeSelectionGraphMousePlugin`.
#[derive(Debug, Clone, Default)]
pub struct EdgeSelectionPlugin {
    /// The currently selected edge.
    pub selected_edge: Option<String>,
}

impl EdgeSelectionPlugin {
    /// Create a new edge selection plugin.
    pub fn new() -> Self {
        Self::default()
    }
}

impl VisualGraphMousePlugin for EdgeSelectionPlugin {
    fn name(&self) -> &str {
        "EdgeSelectionGraphMousePlugin"
    }

    fn handles_event(&self, event_type: MouseEventType) -> bool {
        event_type == MouseEventType::Click
    }

    fn process_event(&mut self, event: &GraphMouseEvent) -> bool {
        self.selected_edge = event.edge_id.clone();
        event.edge_id.is_some()
    }
}

/// Scaling plugin for zoom.
///
/// Port of Ghidra's `VisualGraphScalingGraphMousePlugin`.
#[derive(Debug, Clone)]
pub struct ScalingPlugin {
    /// Current zoom level.
    pub zoom: f64,
    /// Minimum zoom.
    pub min_zoom: f64,
    /// Maximum zoom.
    pub max_zoom: f64,
}

impl ScalingPlugin {
    /// Create a new scaling plugin.
    pub fn new() -> Self {
        Self {
            zoom: 1.0,
            min_zoom: 0.1,
            max_zoom: 5.0,
        }
    }

    /// Zoom in by a factor.
    pub fn zoom_in(&mut self, factor: f64) {
        self.zoom = (self.zoom * factor).min(self.max_zoom);
    }

    /// Zoom out by a factor.
    pub fn zoom_out(&mut self, factor: f64) {
        self.zoom = (self.zoom / factor).max(self.min_zoom);
    }

    /// Reset zoom to 1.0.
    pub fn reset_zoom(&mut self) {
        self.zoom = 1.0;
    }
}

impl Default for ScalingPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl VisualGraphMousePlugin for ScalingPlugin {
    fn name(&self) -> &str {
        "ScalingGraphMousePlugin"
    }

    fn handles_event(&self, event_type: MouseEventType) -> bool {
        event_type == MouseEventType::Scroll
    }

    fn process_event(&mut self, _event: &GraphMouseEvent) -> bool {
        // In a real impl, this would zoom based on scroll direction.
        true
    }
}

/// Translating (panning) plugin.
///
/// Port of Ghidra's `VisualGraphTranslatingGraphMousePlugin`.
#[derive(Debug, Clone, Default)]
pub struct TranslatingPlugin {
    /// Whether the user is currently panning.
    pub is_panning: bool,
    /// Pan offset X.
    pub offset_x: f64,
    /// Pan offset Y.
    pub offset_y: f64,
}

impl TranslatingPlugin {
    /// Create a new translating plugin.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply a pan delta.
    pub fn pan(&mut self, dx: f64, dy: f64) {
        self.offset_x += dx;
        self.offset_y += dy;
    }

    /// Reset the pan offset.
    pub fn reset(&mut self) {
        self.offset_x = 0.0;
        self.offset_y = 0.0;
    }
}

impl VisualGraphMousePlugin for TranslatingPlugin {
    fn name(&self) -> &str {
        "TranslatingGraphMousePlugin"
    }

    fn handles_event(&self, event_type: MouseEventType) -> bool {
        matches!(
            event_type,
            MouseEventType::DragStart | MouseEventType::Drag | MouseEventType::DragEnd
        )
    }

    fn process_event(&mut self, event: &GraphMouseEvent) -> bool {
        match event.event_type {
            MouseEventType::DragStart => {
                self.is_panning = true;
                true
            }
            MouseEventType::Drag => {
                if self.is_panning {
                    // In a real impl, delta would be computed from last position.
                    true
                } else {
                    false
                }
            }
            MouseEventType::DragEnd => {
                self.is_panning = false;
                true
            }
            _ => false,
        }
    }
}

/// Collection of mouse plugins for a graph viewer.
#[derive(Debug)]
pub struct GraphMousePluginSet {
    /// The picking plugin.
    pub picking: PickingGraphMousePlugin,
    /// The hover plugin.
    pub hover: HoverMousePlugin,
    /// The popup plugin.
    pub popup: PopupMousePlugin,
    /// The edge selection plugin.
    pub edge_selection: EdgeSelectionPlugin,
    /// The scaling plugin.
    pub scaling: ScalingPlugin,
    /// The translating plugin.
    pub translating: TranslatingPlugin,
}

impl GraphMousePluginSet {
    /// Create a new plugin set with all default plugins.
    pub fn new() -> Self {
        Self {
            picking: PickingGraphMousePlugin::new(),
            hover: HoverMousePlugin::new(),
            popup: PopupMousePlugin::new(),
            edge_selection: EdgeSelectionPlugin::new(),
            scaling: ScalingPlugin::new(),
            translating: TranslatingPlugin::new(),
        }
    }
}

impl Default for GraphMousePluginSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picking_plugin_select_vertex() {
        let mut plugin = PickingGraphMousePlugin::new();
        plugin.select_vertex("v1");
        assert_eq!(plugin.selected_vertices, vec!["v1"]);
        plugin.select_vertex("v2");
        assert_eq!(plugin.selected_vertices, vec!["v2"]); // replaces in single-select mode
    }

    #[test]
    fn picking_plugin_multi_select() {
        let mut plugin = PickingGraphMousePlugin::new();
        plugin.multi_select = true;
        plugin.select_vertex("v1");
        plugin.select_vertex("v2");
        assert_eq!(plugin.selected_vertices.len(), 2);
    }

    #[test]
    fn picking_plugin_clear() {
        let mut plugin = PickingGraphMousePlugin::new();
        plugin.select_vertex("v1");
        plugin.select_edge("e1");
        plugin.clear_selection();
        assert!(plugin.selected_vertices.is_empty());
        assert!(plugin.selected_edges.is_empty());
    }

    #[test]
    fn hover_plugin() {
        let mut plugin = HoverMousePlugin::new();
        let mut event = GraphMouseEvent::new(MouseEventType::HoverEnter, 10.0, 20.0);
        event.vertex_id = Some("v1".to_string());
        plugin.process_event(&event);
        assert_eq!(plugin.hovered_vertex.as_deref(), Some("v1"));

        let exit = GraphMouseEvent::new(MouseEventType::HoverExit, 10.0, 20.0);
        plugin.process_event(&exit);
        assert!(plugin.hovered_vertex.is_none());
    }

    #[test]
    fn popup_plugin_right_click() {
        let mut plugin = PopupMousePlugin::new();
        let event = GraphMouseEvent::new(MouseEventType::RightClick, 50.0, 50.0);
        assert!(plugin.process_event(&event));
        assert!(plugin.popup_visible);
    }

    #[test]
    fn scaling_plugin_zoom() {
        let mut plugin = ScalingPlugin::new();
        assert_eq!(plugin.zoom, 1.0);
        plugin.zoom_in(2.0);
        assert_eq!(plugin.zoom, 2.0);
        plugin.zoom_out(4.0);
        assert_eq!(plugin.zoom, 0.5);
        plugin.reset_zoom();
        assert_eq!(plugin.zoom, 1.0);
    }

    #[test]
    fn scaling_plugin_clamp() {
        let mut plugin = ScalingPlugin::new();
        plugin.zoom_in(100.0);
        assert_eq!(plugin.zoom, 5.0);
        plugin.zoom_out(100.0);
        assert_eq!(plugin.zoom, 0.1);
    }

    #[test]
    fn translating_plugin_pan() {
        let mut plugin = TranslatingPlugin::new();
        plugin.pan(10.0, 20.0);
        assert_eq!(plugin.offset_x, 10.0);
        assert_eq!(plugin.offset_y, 20.0);
        plugin.pan(5.0, 5.0);
        assert_eq!(plugin.offset_x, 15.0);
        plugin.reset();
        assert_eq!(plugin.offset_x, 0.0);
    }

    #[test]
    fn edge_selection_plugin() {
        let mut plugin = EdgeSelectionPlugin::new();
        let mut event = GraphMouseEvent::new(MouseEventType::Click, 0.0, 0.0);
        event.edge_id = Some("e1".to_string());
        assert!(plugin.process_event(&event));
        assert_eq!(plugin.selected_edge.as_deref(), Some("e1"));
    }

    #[test]
    fn graph_mouse_event() {
        let mut event = GraphMouseEvent::new(MouseEventType::Click, 100.0, 200.0);
        event.button = Some(MouseButton::Left);
        event.ctrl_down = true;
        event.vertex_id = Some("v1".to_string());
        assert_eq!(event.event_type, MouseEventType::Click);
        assert!(event.ctrl_down);
    }

    #[test]
    fn plugin_handles_event() {
        let picking = PickingGraphMousePlugin::new();
        assert!(picking.handles_event(MouseEventType::Click));
        assert!(picking.handles_event(MouseEventType::DoubleClick));
        assert!(!picking.handles_event(MouseEventType::Scroll));
    }

    #[test]
    fn plugin_set() {
        let set = GraphMousePluginSet::new();
        assert_eq!(set.picking.name(), "PickingGraphMousePlugin");
        assert_eq!(set.hover.name(), "HoverMousePlugin");
        assert_eq!(set.scaling.name(), "ScalingGraphMousePlugin");
    }
}
