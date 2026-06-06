//! Port of Ghidra's `ghidra.graph.viewer.event.mouse.VisualGraphMousePlugin`.

/// Trait for mouse event plugins in the visual graph viewer.
///
/// Plugins intercept mouse events and can consume them to prevent
/// further processing.
pub trait VisualGraphMousePlugin: Send + Sync + std::fmt::Debug {
    /// Called on mouse press. Return true to consume the event.
    fn mouse_pressed(&self, _x: f64, _y: f64, _button: u8) -> bool { false }
    /// Called on mouse release. Return true to consume the event.
    fn mouse_released(&self, _x: f64, _y: f64, _button: u8) -> bool { false }
    /// Called on mouse drag. Return true to consume the event.
    fn mouse_dragged(&self, _x: f64, _y: f64, _dx: f64, _dy: f64) -> bool { false }
    /// Called on mouse move. Return true to consume the event.
    fn mouse_moved(&self, _x: f64, _y: f64) -> bool { false }
    /// Called on mouse wheel scroll. Return true to consume the event.
    fn mouse_wheel_moved(&self, _x: f64, _y: f64, _delta: f64) -> bool { false }
    /// Priority of this plugin (lower = higher priority).
    fn priority(&self) -> i32 { 0 }
}

/// Pan plugin: drag to pan the graph view.
#[derive(Debug)]
pub struct PanGraphMousePlugin { pub active: bool }
impl PanGraphMousePlugin {
    pub fn new() -> Self { Self { active: false } }
}
impl Default for PanGraphMousePlugin { fn default() -> Self { Self::new() } }
impl VisualGraphMousePlugin for PanGraphMousePlugin {
    fn mouse_pressed(&self, _x: f64, _y: f64, button: u8) -> bool { button == 2 }
    fn mouse_dragged(&self, _x: f64, _y: f64, _dx: f64, _dy: f64) -> bool { true }
    fn priority(&self) -> i32 { 10 }
}

/// Zoom plugin: scroll wheel to zoom.
#[derive(Debug)]
pub struct ZoomGraphMousePlugin;
impl VisualGraphMousePlugin for ZoomGraphMousePlugin {
    fn mouse_wheel_moved(&self, _x: f64, _y: f64, _delta: f64) -> bool { true }
    fn priority(&self) -> i32 { 20 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pan_plugin() {
        let p = PanGraphMousePlugin::new();
        assert!(p.mouse_pressed(0.0, 0.0, 2)); // right-click
        assert!(!p.mouse_pressed(0.0, 0.0, 1)); // left-click
        assert!(p.mouse_dragged(0.0, 0.0, 10.0, 5.0));
        assert_eq!(p.priority(), 10);
    }

    #[test]
    fn test_zoom_plugin() {
        let p = ZoomGraphMousePlugin;
        assert!(p.mouse_wheel_moved(0.0, 0.0, 1.0));
    }

    #[test]
    fn test_default_trait_methods() {
        let p = ZoomGraphMousePlugin;
        assert!(!p.mouse_pressed(0.0, 0.0, 1));
        assert!(!p.mouse_released(0.0, 0.0, 1));
        assert!(!p.mouse_moved(0.0, 0.0));
    }
}
