//! Mouse event handling for the visual graph.
//!
//! Ports Ghidra's extensive mouse plugin system including:
//! - Picking (click-to-select vertices/edges)
//! - Hovering
//! - Zooming (scroll wheel + mouse drag)
//! - Panning (translating)
//! - Popup menus
//! - Edge selection
//! - Satellite navigation
//! - Animated transitions

pub mod plugins;
pub mod plugins_ext;

/// Mouse event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseEventType {
    /// Mouse pressed.
    Pressed,
    /// Mouse released.
    Released,
    /// Mouse clicked (pressed + released).
    Clicked,
    /// Mouse dragged.
    Dragged,
    /// Mouse moved (no button).
    Moved,
    /// Mouse entered a component.
    Entered,
    /// Mouse exited a component.
    Exited,
    /// Mouse wheel scrolled.
    Wheel,
}

/// Mouse button.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButton {
    /// Left button.
    Left,
    /// Middle button.
    Middle,
    /// Right button.
    Right,
}

/// A mouse event on the graph viewer.
#[derive(Debug, Clone)]
pub struct GraphMouseEvent {
    /// The type of mouse event.
    pub event_type: MouseEventType,
    /// The mouse button involved.
    pub button: Option<MouseButton>,
    /// X position in view coordinates.
    pub view_x: f64,
    /// Y position in view coordinates.
    pub view_y: f64,
    /// X position in graph/model coordinates.
    pub graph_x: f64,
    /// Y position in graph/model coordinates.
    pub graph_y: f64,
    /// Whether shift was held.
    pub shift_down: bool,
    /// Whether ctrl was held.
    pub ctrl_down: bool,
    /// Whether alt was held.
    pub alt_down: bool,
    /// The vertex ID under the mouse (if any).
    pub vertex_id: Option<u64>,
    /// The edge ID under the mouse (if any).
    pub edge_id: Option<u64>,
    /// Wheel rotation amount (for scroll events).
    pub wheel_rotation: i32,
}

impl GraphMouseEvent {
    /// Create a new mouse event.
    pub fn new(event_type: MouseEventType, view_x: f64, view_y: f64) -> Self {
        Self {
            event_type,
            button: None,
            view_x,
            view_y,
            graph_x: view_x,
            graph_y: view_y,
            shift_down: false,
            ctrl_down: false,
            alt_down: false,
            vertex_id: None,
            edge_id: None,
            wheel_rotation: 0,
        }
    }

    /// Check if this is a left click event.
    pub fn is_left_click(&self) -> bool {
        self.event_type == MouseEventType::Clicked && self.button == Some(MouseButton::Left)
    }

    /// Check if this is a right click event.
    pub fn is_right_click(&self) -> bool {
        self.event_type == MouseEventType::Clicked && self.button == Some(MouseButton::Right)
    }
}

/// Plugin trait for handling mouse events on the graph.
pub trait GraphMousePlugin: Send + Sync {
    /// Handle a mouse event. Returns true if the event was consumed.
    fn handle_event(&mut self, event: &GraphMouseEvent) -> bool;
    /// Get the name of this plugin.
    fn name(&self) -> &str;
}

/// Picking plugin: click to select vertices/edges.
#[derive(Debug, Default)]
pub struct PickingGraphMousePlugin;

impl PickingGraphMousePlugin {
    pub fn new() -> Self {
        Self
    }
}

impl GraphMousePlugin for PickingGraphMousePlugin {
    fn handle_event(&mut self, event: &GraphMouseEvent) -> bool {
        event.vertex_id.is_some() && event.is_left_click()
    }

    fn name(&self) -> &str {
        "PickingGraphMousePlugin"
    }
}

/// Hover plugin: mouse-over vertex/edge highlighting.
#[derive(Debug, Default)]
pub struct HoverMousePlugin {
    /// Delay in ms before showing hover.
    pub hover_delay_ms: u64,
}

impl HoverMousePlugin {
    pub fn new() -> Self {
        Self { hover_delay_ms: 500 }
    }
}

impl GraphMousePlugin for HoverMousePlugin {
    fn handle_event(&mut self, event: &GraphMouseEvent) -> bool {
        event.event_type == MouseEventType::Moved && event.vertex_id.is_some()
    }

    fn name(&self) -> &str {
        "HoverMousePlugin"
    }
}

/// Popup plugin: right-click context menus.
#[derive(Debug, Default)]
pub struct PopupMousePlugin;

impl PopupMousePlugin {
    pub fn new() -> Self {
        Self
    }
}

impl GraphMousePlugin for PopupMousePlugin {
    fn handle_event(&mut self, event: &GraphMouseEvent) -> bool {
        event.is_right_click()
    }

    fn name(&self) -> &str {
        "PopupMousePlugin"
    }
}

/// Zooming plugin: scroll wheel zoom.
#[derive(Debug, Default)]
pub struct ZoomingGraphMousePlugin {
    /// Zoom factor per scroll unit.
    pub zoom_factor: f64,
}

impl ZoomingGraphMousePlugin {
    pub fn new() -> Self {
        Self { zoom_factor: 1.1 }
    }
}

impl GraphMousePlugin for ZoomingGraphMousePlugin {
    fn handle_event(&mut self, event: &GraphMouseEvent) -> bool {
        event.event_type == MouseEventType::Wheel && event.wheel_rotation != 0
    }

    fn name(&self) -> &str {
        "ZoomingGraphMousePlugin"
    }
}

/// Translating (panning) plugin: drag to pan.
#[derive(Debug, Default)]
pub struct TranslatingGraphMousePlugin;

impl TranslatingGraphMousePlugin {
    pub fn new() -> Self {
        Self
    }
}

impl GraphMousePlugin for TranslatingGraphMousePlugin {
    fn handle_event(&mut self, event: &GraphMouseEvent) -> bool {
        event.event_type == MouseEventType::Dragged
            && event.button == Some(MouseButton::Left)
            && event.vertex_id.is_none()
    }

    fn name(&self) -> &str {
        "TranslatingGraphMousePlugin"
    }
}

/// Edge selection plugin: click to select edges.
#[derive(Debug, Default)]
pub struct EdgeSelectionGraphMousePlugin;

impl EdgeSelectionGraphMousePlugin {
    pub fn new() -> Self {
        Self
    }
}

impl GraphMousePlugin for EdgeSelectionGraphMousePlugin {
    fn handle_event(&mut self, event: &GraphMouseEvent) -> bool {
        event.is_left_click() && event.edge_id.is_some()
    }

    fn name(&self) -> &str {
        "EdgeSelectionGraphMousePlugin"
    }
}

/// The main pluggable graph mouse that dispatches events to registered plugins.
pub struct VisualGraphPluggableGraphMouse {
    /// Registered plugins.
    plugins: Vec<Box<dyn GraphMousePlugin>>,
}

impl VisualGraphPluggableGraphMouse {
    /// Create with default plugins.
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    /// Add a plugin.
    pub fn add_plugin(&mut self, plugin: Box<dyn GraphMousePlugin>) {
        self.plugins.push(plugin);
    }

    /// Dispatch a mouse event to plugins (first match wins).
    pub fn dispatch(&mut self, event: &GraphMouseEvent) -> bool {
        for plugin in &mut self.plugins {
            if plugin.handle_event(event) {
                return true;
            }
        }
        false
    }

    /// Get the number of registered plugins.
    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }
}

impl Default for VisualGraphPluggableGraphMouse {
    fn default() -> Self {
        let mut mouse = Self::new();
        mouse.add_plugin(Box::new(PopupMousePlugin::new()));
        mouse.add_plugin(Box::new(PickingGraphMousePlugin::new()));
        mouse.add_plugin(Box::new(EdgeSelectionGraphMousePlugin::new()));
        mouse.add_plugin(Box::new(ZoomingGraphMousePlugin::new()));
        mouse.add_plugin(Box::new(TranslatingGraphMousePlugin::new()));
        mouse.add_plugin(Box::new(HoverMousePlugin::new()));
        mouse
    }
}

/// Satellite-specific mouse plugins.
pub mod satellite {
    //! Mouse plugins for the satellite (minimap) view.

    use super::*;

    /// Panning plugin for satellite view.
    #[derive(Debug, Default)]
    pub struct SatelliteTranslatingPlugin;

    impl SatelliteTranslatingPlugin {
        pub fn new() -> Self {
            Self
        }
    }

    impl GraphMousePlugin for SatelliteTranslatingPlugin {
        fn handle_event(&mut self, event: &GraphMouseEvent) -> bool {
            event.event_type == MouseEventType::Dragged
                && event.button == Some(MouseButton::Left)
        }

        fn name(&self) -> &str {
            "SatelliteTranslatingPlugin"
        }
    }

    /// Zooming plugin for satellite view.
    #[derive(Debug, Default)]
    pub struct SatelliteScalingPlugin;

    impl SatelliteScalingPlugin {
        pub fn new() -> Self {
            Self
        }
    }

    impl GraphMousePlugin for SatelliteScalingPlugin {
        fn handle_event(&mut self, event: &GraphMouseEvent) -> bool {
            event.event_type == MouseEventType::Wheel
        }

        fn name(&self) -> &str {
            "SatelliteScalingPlugin"
        }
    }

    /// Navigation plugin: click in satellite to navigate main view.
    #[derive(Debug, Default)]
    pub struct SatelliteNavigationPlugin;

    impl SatelliteNavigationPlugin {
        pub fn new() -> Self {
            Self
        }
    }

    impl GraphMousePlugin for SatelliteNavigationPlugin {
        fn handle_event(&mut self, event: &GraphMouseEvent) -> bool {
            event.is_left_click()
        }

        fn name(&self) -> &str {
            "SatelliteNavigationPlugin"
        }
    }

    /// The satellite graph mouse with all satellite plugins.
    pub struct SatelliteGraphMouse {
        plugins: Vec<Box<dyn GraphMousePlugin>>,
    }

    impl SatelliteGraphMouse {
        pub fn new() -> Self {
            let mut mouse = Self { plugins: Vec::new() };
            mouse.plugins.push(Box::new(SatelliteNavigationPlugin::new()));
            mouse.plugins.push(Box::new(SatelliteScalingPlugin::new()));
            mouse.plugins.push(Box::new(SatelliteTranslatingPlugin::new()));
            mouse
        }

        pub fn dispatch(&mut self, event: &GraphMouseEvent) -> bool {
            for plugin in &mut self.plugins {
                if plugin.handle_event(event) {
                    return true;
                }
            }
            false
        }
    }

    impl Default for SatelliteGraphMouse {
        fn default() -> Self {
            Self::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mouse_event() {
        let mut evt = GraphMouseEvent::new(MouseEventType::Clicked, 100.0, 200.0);
        evt.button = Some(MouseButton::Left);
        assert!(evt.is_left_click());
        assert!(!evt.is_right_click());
    }

    #[test]
    fn test_picking_plugin() {
        let mut plugin = PickingGraphMousePlugin::new();
        let mut evt = GraphMouseEvent::new(MouseEventType::Clicked, 10.0, 20.0);
        evt.button = Some(MouseButton::Left);
        evt.vertex_id = Some(42);
        assert!(plugin.handle_event(&evt));

        evt.vertex_id = None;
        assert!(!plugin.handle_event(&evt));
    }

    #[test]
    fn test_popup_plugin() {
        let mut plugin = PopupMousePlugin::new();
        let mut evt = GraphMouseEvent::new(MouseEventType::Clicked, 10.0, 20.0);
        evt.button = Some(MouseButton::Right);
        assert!(plugin.handle_event(&evt));
    }

    #[test]
    fn test_zooming_plugin() {
        let mut plugin = ZoomingGraphMousePlugin::new();
        let mut evt = GraphMouseEvent::new(MouseEventType::Wheel, 0.0, 0.0);
        evt.wheel_rotation = 1;
        assert!(plugin.handle_event(&evt));
    }

    #[test]
    fn test_pluggable_mouse_dispatch() {
        let mut mouse = VisualGraphPluggableGraphMouse::default();
        assert_eq!(mouse.plugin_count(), 6);
        let mut evt = GraphMouseEvent::new(MouseEventType::Clicked, 10.0, 20.0);
        evt.button = Some(MouseButton::Right);
        assert!(mouse.dispatch(&evt));
    }

    #[test]
    fn test_satellite_mouse() {
        use satellite::*;
        let mut mouse = SatelliteGraphMouse::new();
        let mut evt = GraphMouseEvent::new(MouseEventType::Clicked, 10.0, 20.0);
        evt.button = Some(MouseButton::Left);
        assert!(mouse.dispatch(&evt));
    }
}
