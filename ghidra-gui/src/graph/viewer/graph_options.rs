//! Visual graph display and interaction options.
//!
//! Ports Ghidra's `ghidra.graph.viewer.VisualGraphOptions` and related types.
//! These options control how the visual graph is displayed and how the user
//! can interact with it.

use super::path_highlight_mode::PathHighlightMode;

/// Options controlling the visual display and interaction of a graph.
///
/// Ports Ghidra's `VisualGraphOptions`.
#[derive(Debug, Clone)]
pub struct VisualGraphOptions {
    /// How paths are highlighted on hover/selection.
    pub path_highlight_mode: PathHighlightMode,
    /// Whether to show edge labels.
    pub show_edge_labels: bool,
    /// Whether to use icon rendering mode (pre-rendered shapes with labels inside).
    pub use_icons: bool,
    /// Maximum number of nodes before auto-folding hides details.
    pub max_node_count: usize,
    /// Arrow length for edge rendering.
    pub arrow_length: f64,
    /// Whether vertex animation is enabled.
    pub animation_enabled: bool,
    /// Whether to allow vertex dragging.
    pub allow_drag: bool,
    /// Whether to show a satellite (minimap) view.
    pub show_satellite: bool,
    /// Whether the popup on hover is enabled.
    pub popup_on_hover: bool,
    /// Whether scrolling should zoom (vs pan).
    pub scroll_zooms: bool,
    /// Size of the grid for snapping.
    pub grid_snap_size: f64,
}

impl Default for VisualGraphOptions {
    fn default() -> Self {
        Self {
            path_highlight_mode: PathHighlightMode::default(),
            show_edge_labels: false,
            use_icons: true,
            max_node_count: 5000,
            arrow_length: 10.0,
            animation_enabled: true,
            allow_drag: true,
            show_satellite: true,
            popup_on_hover: true,
            scroll_zooms: true,
            grid_snap_size: 10.0,
        }
    }
}

impl VisualGraphOptions {
    /// Create options suitable for a control-flow graph.
    pub fn for_cfg() -> Self {
        Self {
            path_highlight_mode: PathHighlightMode::HoveredVertexPath,
            show_edge_labels: false,
            use_icons: true,
            max_node_count: 5000,
            arrow_length: 10.0,
            ..Self::default()
        }
    }

    /// Create options suitable for a data-flow graph.
    pub fn for_dfg() -> Self {
        Self {
            path_highlight_mode: PathHighlightMode::Both,
            show_edge_labels: true,
            use_icons: false,
            max_node_count: 2000,
            arrow_length: 8.0,
            ..Self::default()
        }
    }

    /// Create options suitable for a call graph.
    pub fn for_call_graph() -> Self {
        Self {
            path_highlight_mode: PathHighlightMode::SelectedVertexPath,
            show_edge_labels: false,
            use_icons: true,
            max_node_count: 10000,
            arrow_length: 12.0,
            ..Self::default()
        }
    }

    /// Create options for satellite/minimap use.
    pub fn for_satellite() -> Self {
        Self {
            path_highlight_mode: PathHighlightMode::None,
            show_edge_labels: false,
            use_icons: false,
            animation_enabled: false,
            allow_drag: false,
            popup_on_hover: false,
            scroll_zooms: false,
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_options() {
        let opts = VisualGraphOptions::default();
        assert_eq!(opts.path_highlight_mode, PathHighlightMode::HoveredVertexPath);
        assert!(!opts.show_edge_labels);
        assert!(opts.use_icons);
        assert_eq!(opts.max_node_count, 5000);
        assert!(opts.animation_enabled);
        assert!(opts.allow_drag);
        assert!(opts.show_satellite);
        assert!(opts.popup_on_hover);
        assert!(opts.scroll_zooms);
    }

    #[test]
    fn cfg_options() {
        let opts = VisualGraphOptions::for_cfg();
        assert_eq!(opts.path_highlight_mode, PathHighlightMode::HoveredVertexPath);
        assert!(!opts.show_edge_labels);
        assert!(opts.use_icons);
    }

    #[test]
    fn dfg_options() {
        let opts = VisualGraphOptions::for_dfg();
        assert_eq!(opts.path_highlight_mode, PathHighlightMode::Both);
        assert!(opts.show_edge_labels);
        assert!(!opts.use_icons);
    }

    #[test]
    fn call_graph_options() {
        let opts = VisualGraphOptions::for_call_graph();
        assert_eq!(opts.path_highlight_mode, PathHighlightMode::SelectedVertexPath);
        assert_eq!(opts.max_node_count, 10000);
    }

    #[test]
    fn satellite_options() {
        let opts = VisualGraphOptions::for_satellite();
        assert_eq!(opts.path_highlight_mode, PathHighlightMode::None);
        assert!(!opts.animation_enabled);
        assert!(!opts.allow_drag);
        assert!(!opts.popup_on_hover);
    }

    #[test]
    fn arrow_length_varies_by_preset() {
        let cfg = VisualGraphOptions::for_cfg();
        let dfg = VisualGraphOptions::for_dfg();
        let cg = VisualGraphOptions::for_call_graph();
        assert_ne!(cfg.arrow_length, dfg.arrow_length);
        assert_ne!(dfg.arrow_length, cg.arrow_length);
    }
}
