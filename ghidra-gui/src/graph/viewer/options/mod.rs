//! Graph viewer display options.
//!
//! Ports `ghidra.graph.viewer.options` package.

use std::collections::HashMap;

use crate::graph::service::{GraphLabelPosition, VertexShape};

/// Options controlling how a visual graph is rendered.
#[derive(Debug, Clone)]
pub struct VisualGraphOptions {
    /// Default vertex fill color.
    pub vertex_fill_color: String,
    /// Default vertex border color.
    pub vertex_border_color: String,
    /// Default edge color.
    pub edge_color: String,
    /// Highlighted edge color.
    pub edge_highlight_color: String,
    /// Whether to show vertex labels.
    pub show_vertex_labels: bool,
    /// Whether to show edge labels.
    pub show_edge_labels: bool,
    /// Vertex label position.
    pub vertex_label_position: GraphLabelPosition,
    /// Whether to use anti-aliasing.
    pub anti_alias: bool,
    /// Background color.
    pub background_color: String,
    /// Grid visibility.
    pub show_grid: bool,
    /// Grid color.
    pub grid_color: String,
    /// Grid spacing in pixels.
    pub grid_spacing: f64,
    /// Animation duration in milliseconds.
    pub animation_duration_ms: u32,
    /// Per-vertex-type color overrides.
    vertex_type_colors: HashMap<String, String>,
    /// Per-vertex-type shape overrides.
    vertex_type_shapes: HashMap<String, VertexShape>,
}

impl Default for VisualGraphOptions {
    fn default() -> Self {
        Self {
            vertex_fill_color: "#FFFFFF".to_string(),
            vertex_border_color: "#333333".to_string(),
            edge_color: "#666666".to_string(),
            edge_highlight_color: "#FF0000".to_string(),
            show_vertex_labels: true,
            show_edge_labels: false,
            vertex_label_position: GraphLabelPosition::Center,
            anti_alias: true,
            background_color: "#FAFAFA".to_string(),
            show_grid: false,
            grid_color: "#E0E0E0".to_string(),
            grid_spacing: 20.0,
            animation_duration_ms: 300,
            vertex_type_colors: HashMap::new(),
            vertex_type_shapes: HashMap::new(),
        }
    }
}

impl VisualGraphOptions {
    /// Create new default options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the fill color for a specific vertex type.
    pub fn set_vertex_type_color(&mut self, vertex_type: impl Into<String>, color: impl Into<String>) {
        self.vertex_type_colors.insert(vertex_type.into(), color.into());
    }

    /// Get the fill color for a vertex type, falling back to the default.
    pub fn vertex_type_color(&self, vertex_type: &str) -> &str {
        self.vertex_type_colors
            .get(vertex_type)
            .map(|s| s.as_str())
            .unwrap_or(&self.vertex_fill_color)
    }

    /// Set the shape for a specific vertex type.
    pub fn set_vertex_type_shape(&mut self, vertex_type: impl Into<String>, shape: VertexShape) {
        self.vertex_type_shapes.insert(vertex_type.into(), shape);
    }

    /// Get the shape for a vertex type, falling back to the default.
    pub fn vertex_type_shape(&self, vertex_type: &str) -> VertexShape {
        self.vertex_type_shapes
            .get(vertex_type)
            .copied()
            .unwrap_or(VertexShape::RoundedRectangle)
    }

    /// Check if there are any vertex type color overrides.
    pub fn has_type_overrides(&self) -> bool {
        !self.vertex_type_colors.is_empty() || !self.vertex_type_shapes.is_empty()
    }
}

/// Builder for VisualGraphOptions.
#[derive(Debug, Clone)]
pub struct VisualGraphOptionsBuilder {
    options: VisualGraphOptions,
}

impl VisualGraphOptionsBuilder {
    /// Create a new builder with default options.
    pub fn new() -> Self {
        Self {
            options: VisualGraphOptions::default(),
        }
    }

    /// Set vertex fill color.
    pub fn vertex_fill_color(mut self, color: impl Into<String>) -> Self {
        self.options.vertex_fill_color = color.into();
        self
    }

    /// Set edge color.
    pub fn edge_color(mut self, color: impl Into<String>) -> Self {
        self.options.edge_color = color.into();
        self
    }

    /// Set background color.
    pub fn background_color(mut self, color: impl Into<String>) -> Self {
        self.options.background_color = color.into();
        self
    }

    /// Show/hide vertex labels.
    pub fn show_vertex_labels(mut self, show: bool) -> Self {
        self.options.show_vertex_labels = show;
        self
    }

    /// Show/hide edge labels.
    pub fn show_edge_labels(mut self, show: bool) -> Self {
        self.options.show_edge_labels = show;
        self
    }

    /// Set grid visibility.
    pub fn show_grid(mut self, show: bool) -> Self {
        self.options.show_grid = show;
        self
    }

    /// Set animation duration.
    pub fn animation_duration_ms(mut self, ms: u32) -> Self {
        self.options.animation_duration_ms = ms;
        self
    }

    /// Build the options.
    pub fn build(self) -> VisualGraphOptions {
        self.options
    }
}

impl Default for VisualGraphOptionsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// RelayoutOption
// ============================================================================

/// Controls when the graph layout should be recalculated.
///
/// Ports `ghidra.graph.viewer.options.RelayoutOption`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayoutOption {
    /// Always relayout when the graph changes.
    Always,
    /// Only relayout when the block model changes.
    BlockModelChanges,
    /// Only relayout when vertex grouping changes.
    VertexGroupingChanges,
    /// Never automatically relayout.
    Never,
}

impl RelayoutOption {
    /// Human-readable display name.
    pub fn display_name(&self) -> &str {
        match self {
            Self::Always => "Always",
            Self::BlockModelChanges => "Block Model Changes Only",
            Self::VertexGroupingChanges => "Vertex Grouping Changes Only",
            Self::Never => "Never",
        }
    }
}

impl Default for RelayoutOption {
    fn default() -> Self {
        Self::Always
    }
}

impl std::fmt::Display for RelayoutOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ============================================================================
// ViewRestoreOption
// ============================================================================

/// Controls how the graph view is restored when switching between graphs.
///
/// Ports `ghidra.graph.viewer.options.ViewRestoreOption`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewRestoreOption {
    /// Start fully zoomed out to show the entire graph.
    StartFullyZoomedOut,
    /// Start fully zoomed in on the selected vertex.
    StartFullyZoomedIn,
    /// Remember and restore the user's previous zoom/pan settings.
    RememberSettings,
}

impl ViewRestoreOption {
    /// Human-readable display name.
    pub fn display_name(&self) -> &str {
        match self {
            Self::StartFullyZoomedOut => "Start Fully Zoomed Out",
            Self::StartFullyZoomedIn => "Start Fully Zoomed In",
            Self::RememberSettings => "Remember User Settings",
        }
    }
}

impl Default for ViewRestoreOption {
    fn default() -> Self {
        Self::StartFullyZoomedOut
    }
}

impl std::fmt::Display for ViewRestoreOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ============================================================================
// ScrollWheelMode
// ============================================================================

/// Controls what the scroll wheel does in the graph view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrollWheelMode {
    /// Scroll wheel zooms (default).
    Zoom,
    /// Scroll wheel pans vertically.
    Pan,
}

impl Default for ScrollWheelMode {
    fn default() -> Self {
        Self::Zoom
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_options() {
        let opts = VisualGraphOptions::default();
        assert!(opts.show_vertex_labels);
        assert!(!opts.show_edge_labels);
        assert!(opts.anti_alias);
        assert_eq!(opts.animation_duration_ms, 300);
    }

    #[test]
    fn vertex_type_color_override() {
        let mut opts = VisualGraphOptions::new();
        assert_eq!(opts.vertex_type_color("CodeBlock"), "#FFFFFF");
        opts.set_vertex_type_color("CodeBlock", "#FF0000");
        assert_eq!(opts.vertex_type_color("CodeBlock"), "#FF0000");
        assert!(opts.has_type_overrides());
    }

    #[test]
    fn vertex_type_shape_override() {
        let mut opts = VisualGraphOptions::new();
        assert_eq!(opts.vertex_type_shape("CodeBlock"), VertexShape::RoundedRectangle);
        opts.set_vertex_type_shape("CodeBlock", VertexShape::Diamond);
        assert_eq!(opts.vertex_type_shape("CodeBlock"), VertexShape::Diamond);
    }

    #[test]
    fn options_builder() {
        let opts = VisualGraphOptionsBuilder::new()
            .background_color("#000000")
            .show_grid(true)
            .animation_duration_ms(500)
            .build();

        assert_eq!(opts.background_color, "#000000");
        assert!(opts.show_grid);
        assert_eq!(opts.animation_duration_ms, 500);
    }

    #[test]
    fn relayout_option_display() {
        assert_eq!(RelayoutOption::Always.display_name(), "Always");
        assert_eq!(RelayoutOption::Never.display_name(), "Never");
        assert_eq!(RelayoutOption::default(), RelayoutOption::Always);
    }

    #[test]
    fn view_restore_option_display() {
        assert_eq!(
            ViewRestoreOption::StartFullyZoomedOut.display_name(),
            "Start Fully Zoomed Out"
        );
        assert_eq!(
            ViewRestoreOption::RememberSettings.display_name(),
            "Remember User Settings"
        );
        assert_eq!(
            ViewRestoreOption::default(),
            ViewRestoreOption::StartFullyZoomedOut
        );
    }

    #[test]
    fn scroll_wheel_mode_default() {
        assert_eq!(ScrollWheelMode::default(), ScrollWheelMode::Zoom);
    }
}
