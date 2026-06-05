//! Visual graph layered pane button.
//!
//! Ports `ghidra.graph.viewer.VisualGraphLayeredPaneButton`.
//!
//! A button that floats above the graph in the layered pane, used for
//! graph-level actions like "Fit to View", "Zoom In", "Zoom Out",
//! "Toggle Satellite View", etc.

use super::Point2D;

/// A button rendered in the graph's layered pane.
///
/// In the Java version, this extends `JButton` and is placed on a
/// `JLayeredPane` to float above the graph visualization. In the
/// Rust/egui port, this stores the button configuration for rendering
/// in the egui widget tree.
#[derive(Debug, Clone)]
pub struct VisualGraphLayeredPaneButton {
    /// Button label text.
    pub label: String,
    /// Tooltip text.
    pub tooltip: String,
    /// Button position (relative to the graph viewport).
    pub position: Point2D,
    /// Button size.
    pub size: (f64, f64),
    /// Whether the button is visible.
    pub visible: bool,
    /// Whether the button is enabled.
    pub enabled: bool,
    /// Icon identifier (optional).
    pub icon: Option<String>,
    /// Action identifier (what happens when clicked).
    pub action_id: String,
}

impl VisualGraphLayeredPaneButton {
    /// Create a new layered pane button.
    pub fn new(label: impl Into<String>, action_id: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            tooltip: String::new(),
            position: Point2D::ZERO,
            size: (24.0, 24.0),
            visible: true,
            enabled: true,
            icon: None,
            action_id: action_id.into(),
        }
    }

    /// Set the tooltip.
    pub fn with_tooltip(mut self, tooltip: impl Into<String>) -> Self {
        self.tooltip = tooltip.into();
        self
    }

    /// Set the position.
    pub fn with_position(mut self, x: f64, y: f64) -> Self {
        self.position = Point2D::new(x, y);
        self
    }

    /// Set the size.
    pub fn with_size(mut self, width: f64, height: f64) -> Self {
        self.size = (width, height);
        self
    }

    /// Set the icon.
    pub fn with_icon(mut self, icon: impl Into<String>) -> Self {
        self.icon = Some(icon.into());
        self
    }

    /// Whether a point is within the button bounds.
    pub fn contains(&self, point: Point2D) -> bool {
        point.x >= self.position.x
            && point.x <= self.position.x + self.size.0
            && point.y >= self.position.y
            && point.y <= self.position.y + self.size.1
    }

    /// Create the default set of graph control buttons.
    pub fn default_graph_controls() -> Vec<Self> {
        vec![
            Self::new("+", "zoom_in")
                .with_tooltip("Zoom In")
                .with_position(0.0, 0.0),
            Self::new("-", "zoom_out")
                .with_tooltip("Zoom Out")
                .with_position(28.0, 0.0),
            Self::new("F", "fit_to_view")
                .with_tooltip("Fit Graph to View")
                .with_position(56.0, 0.0),
            Self::new("S", "toggle_satellite")
                .with_tooltip("Toggle Satellite View")
                .with_position(84.0, 0.0),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layered_pane_button_new() {
        let btn = VisualGraphLayeredPaneButton::new("OK", "confirm");
        assert_eq!(btn.label, "OK");
        assert_eq!(btn.action_id, "confirm");
        assert!(btn.visible);
        assert!(btn.enabled);
    }

    #[test]
    fn layered_pane_button_builder() {
        let btn = VisualGraphLayeredPaneButton::new("+", "zoom")
            .with_tooltip("Zoom In")
            .with_position(10.0, 20.0)
            .with_size(32.0, 32.0)
            .with_icon("zoom_icon");
        assert_eq!(btn.tooltip, "Zoom In");
        assert_eq!(btn.position, Point2D::new(10.0, 20.0));
        assert_eq!(btn.size, (32.0, 32.0));
        assert_eq!(btn.icon.as_deref(), Some("zoom_icon"));
    }

    #[test]
    fn layered_pane_button_contains() {
        let btn = VisualGraphLayeredPaneButton::new("X", "close")
            .with_position(100.0, 100.0)
            .with_size(24.0, 24.0);
        assert!(btn.contains(Point2D::new(112.0, 112.0)));
        assert!(!btn.contains(Point2D::new(50.0, 50.0)));
        assert!(!btn.contains(Point2D::new(200.0, 200.0)));
    }

    #[test]
    fn default_controls() {
        let controls = VisualGraphLayeredPaneButton::default_graph_controls();
        assert_eq!(controls.len(), 4);
        assert_eq!(controls[0].label, "+");
        assert_eq!(controls[1].label, "-");
        assert_eq!(controls[2].label, "F");
        assert_eq!(controls[3].label, "S");
    }
}
