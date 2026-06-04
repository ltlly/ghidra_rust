//! Mouse event handling for graph viewers.
//!
//! Ports `ghidra.graph.viewer.event.mouse` package.

use crate::graph::viewer::Point2D;

/// Mouse button identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButton {
    /// Left mouse button.
    Left,
    /// Middle mouse button.
    Middle,
    /// Right mouse button.
    Right,
}

/// Type of mouse event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseEventType {
    /// Mouse button pressed.
    Press,
    /// Mouse button released.
    Release,
    /// Mouse moved (with button held).
    Drag,
    /// Mouse moved (no button held).
    Move,
    /// Mouse wheel scrolled.
    Scroll,
    /// Double-click.
    DoubleClick,
}

/// A mouse event in graph coordinates.
#[derive(Debug, Clone)]
pub struct GraphMouseEvent {
    /// Type of event.
    pub event_type: MouseEventType,
    /// Mouse position in graph coordinates.
    pub graph_point: Point2D,
    /// Mouse position in screen/widget coordinates.
    pub screen_point: Point2D,
    /// Which button was pressed/released.
    pub button: Option<MouseButton>,
    /// Scroll delta (positive = up, negative = down).
    pub scroll_delta: f64,
    /// Whether shift was held.
    pub shift: bool,
    /// Whether ctrl/cmd was held.
    pub ctrl: bool,
    /// Whether alt was held.
    pub alt: bool,
}

impl GraphMouseEvent {
    /// Create a new mouse event.
    pub fn new(event_type: MouseEventType, graph_point: Point2D, screen_point: Point2D) -> Self {
        Self {
            event_type,
            graph_point,
            screen_point,
            button: None,
            scroll_delta: 0.0,
            shift: false,
            ctrl: false,
            alt: false,
        }
    }
}

/// Mouse plugin trait for handling graph mouse events.
pub trait GraphMousePlugin: Send + Sync {
    /// Called when a mouse event occurs on the graph.
    fn on_mouse_event(&mut self, event: &GraphMouseEvent) -> bool;

    /// Whether this plugin wants to consume the event.
    fn wants_event(&self, event: &GraphMouseEvent) -> bool;
}

/// Picking plugin that handles vertex/edge selection via mouse clicks.
#[derive(Debug, Clone, Default)]
pub struct PickingGraphMousePlugin {
    /// Whether to allow multi-selection via ctrl+click.
    pub allow_multi_select: bool,
}

impl PickingGraphMousePlugin {
    /// Create a new picking plugin.
    pub fn new() -> Self {
        Self {
            allow_multi_select: true,
        }
    }
}

impl GraphMousePlugin for PickingGraphMousePlugin {
    fn on_mouse_event(&mut self, _event: &GraphMouseEvent) -> bool {
        // Selection logic would go here in a full implementation
        true
    }

    fn wants_event(&self, event: &GraphMouseEvent) -> bool {
        matches!(
            event.event_type,
            MouseEventType::Press | MouseEventType::DoubleClick
        )
    }
}

/// Animated picking plugin with hover effects.
#[derive(Debug, Clone, Default)]
pub struct AnimatedPickingGraphMousePlugin {
    /// Hover delay in milliseconds.
    pub hover_delay_ms: u32,
    /// Currently hovered element id.
    pub hovered_id: Option<String>,
}

impl AnimatedPickingGraphMousePlugin {
    /// Create a new animated picking plugin.
    pub fn new() -> Self {
        Self {
            hover_delay_ms: 300,
            hovered_id: None,
        }
    }
}

impl GraphMousePlugin for AnimatedPickingGraphMousePlugin {
    fn on_mouse_event(&mut self, event: &GraphMouseEvent) -> bool {
        if event.event_type == MouseEventType::Move {
            // Hover detection would go here
            return true;
        }
        false
    }

    fn wants_event(&self, event: &GraphMouseEvent) -> bool {
        matches!(
            event.event_type,
            MouseEventType::Move | MouseEventType::Press | MouseEventType::DoubleClick
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mouse_event_creation() {
        let event = GraphMouseEvent::new(
            MouseEventType::Press,
            Point2D::new(100.0, 200.0),
            Point2D::new(300.0, 400.0),
        );
        assert_eq!(event.event_type, MouseEventType::Press);
        assert!(!event.shift);
    }

    #[test]
    fn picking_plugin_wants_clicks() {
        let plugin = PickingGraphMousePlugin::new();
        let click = GraphMouseEvent::new(MouseEventType::Press, Point2D::ZERO, Point2D::ZERO);
        assert!(plugin.wants_event(&click));

        let move_event = GraphMouseEvent::new(MouseEventType::Move, Point2D::ZERO, Point2D::ZERO);
        assert!(!plugin.wants_event(&move_event));
    }

    #[test]
    fn animated_plugin_wants_hover() {
        let plugin = AnimatedPickingGraphMousePlugin::new();
        let move_event = GraphMouseEvent::new(MouseEventType::Move, Point2D::ZERO, Point2D::ZERO);
        assert!(plugin.wants_event(&move_event));
    }

    #[test]
    fn mouse_button_equality() {
        assert_eq!(MouseButton::Left, MouseButton::Left);
        assert_ne!(MouseButton::Left, MouseButton::Right);
    }

    #[test]
    fn mouse_event_types() {
        assert_ne!(MouseEventType::Press, MouseEventType::Release);
        assert_ne!(MouseEventType::Drag, MouseEventType::Move);
    }
}

// Point2D::ZERO is defined in the parent viewer module.
