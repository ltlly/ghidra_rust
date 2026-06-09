//! Function Graph Options -- plugin-level option management and registration.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.functiongraph.FunctionGraphOptions`
//! (the plugin-level options class, distinct from the MVC-level
//! [`FunctionGraphOptions`] in [`super::mvc`]).
//!
//! This module defines option keys, categories, default values, and a
//! [`FunctionGraphPluginOptions`] struct that aggregates all configurable
//! settings for the function graph feature.
//!
//! # Option Categories
//!
//! - **Function Graph Display** -- colour schemes, background colours,
//!   satellite view visibility.
//! - **Function Graph Layout** -- algorithm choice, direction, spacing,
//!   iteration limits.
//! - **Function Graph Behaviour** -- grouping, navigation history,
//!   relayout triggers, maximum node limits.

use super::mvc::{
    EdgeColorScheme, FunctionGraphOptions, NavigationHistoryMode, RelayoutOption,
};
use super::LayoutAlgorithm;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Option key constants
// ---------------------------------------------------------------------------

/// Option keys for the function graph feature.
pub mod option_keys {
    /// Colour scheme category.
    pub const CATEGORY_FUNCTION_GRAPH: &str = "Function Graph";
    /// Layout sub-category.
    pub const CATEGORY_LAYOUT: &str = "Function Graph.Layout";

    /// Maximum number of nodes before the viewer refuses to load.
    pub const MAX_NODES: &str = "Function Graph.Max Nodes";
    /// Default background colour for vertices (RGBA u32).
    pub const DEFAULT_VERTEX_BACKGROUND_COLOR: &str =
        "Function Graph.Default Vertex Background Color";
    /// Default background colour for group vertices (RGBA u32).
    pub const DEFAULT_GROUP_BACKGROUND_COLOR: &str =
        "Function Graph.Default Group Background Color";
    /// Whether to show the satellite (overview) viewer.
    pub const SHOW_SATELLITE: &str = "Function Graph.Show Satellite";
    /// Whether to use full-size vertices in tooltips.
    pub const FULL_SIZE_TOOLTIP: &str = "Function Graph.Full Size Tooltip";
    /// Whether to automatically update vertex colours when grouping.
    pub const UPDATE_GROUP_COLORS: &str =
        "Function Graph.Update Group Colors Automatically";
    /// Navigation history tracking mode.
    pub const NAVIGATION_HISTORY_MODE: &str = "Function Graph.Navigation History Mode";
    /// When to trigger automatic re-layout.
    pub const RELAYOUT_OPTION: &str = "Function Graph.Relayout Option";

    /// Edge colour for fallthrough edges (RGBA u32).
    pub const EDGE_COLOR_FALLTHROUGH: &str = "Function Graph.Edge Colors.Fallthrough";
    /// Edge colour for unconditional jump edges (RGBA u32).
    pub const EDGE_COLOR_UNCONDITIONAL_JUMP: &str =
        "Function Graph.Edge Colors.Unconditional Jump";
    /// Edge colour for conditional true branch (RGBA u32).
    pub const EDGE_COLOR_CONDITIONAL_TRUE: &str =
        "Function Graph.Edge Colors.Conditional True";
    /// Edge colour for conditional false branch (RGBA u32).
    pub const EDGE_COLOR_CONDITIONAL_FALSE: &str =
        "Function Graph.Edge Colors.Conditional False";
    /// Default alpha value for non-highlighted edges (0-255).
    pub const EDGE_DEFAULT_ALPHA: &str = "Function Graph.Edge Colors.Default Alpha";

    /// Layout algorithm name.
    pub const LAYOUT_ALGORITHM: &str = "Function Graph.Layout.Algorithm";
    /// Layout direction.
    pub const LAYOUT_DIRECTION: &str = "Function Graph.Layout.Direction";
    /// Layer spacing (pixels).
    pub const LAYOUT_LAYER_SPACING: &str = "Function Graph.Layout.Layer Spacing";
    /// Node spacing (pixels).
    pub const LAYOUT_NODE_SPACING: &str = "Function Graph.Layout.Node Spacing";
    /// Maximum iterations for force-directed layout.
    pub const LAYOUT_MAX_ITERATIONS: &str = "Function Graph.Layout.Max Iterations";
}

// ---------------------------------------------------------------------------
// FunctionGraphPluginOptions
// ---------------------------------------------------------------------------

/// Plugin-level options that combine all function graph settings.
///
/// This struct is owned by [`FunctionGraphPlugin`] and serializable so
/// that user preferences persist across sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionGraphPluginOptions {
    /// The graph-level options (edge colours, layout, limits).
    pub graph_options: FunctionGraphOptions,
    /// The layout algorithm name (stored as a string for serialization
    /// flexibility; parsed into [`LayoutAlgorithm`] on use).
    pub layout_algorithm_name: String,
    /// Window geometry: width (pixels).
    pub window_width: u32,
    /// Window geometry: height (pixels).
    pub window_height: u32,
    /// Whether to restore the previous window position on open.
    pub restore_window_position: bool,
    /// Whether to center the graph on the entry vertex when first opened.
    pub center_on_entry: bool,
    /// Keyboard shortcut for grouping selected vertices.
    pub group_shortcut: String,
    /// Keyboard shortcut for ungrouping the selected group vertex.
    pub ungroup_shortcut: String,
    /// Whether to merge edges with the same source and target.
    pub merge_edges: bool,
    /// Whether to highlight paths on hover.
    pub highlight_hover_path: bool,
}

impl Default for FunctionGraphPluginOptions {
    fn default() -> Self {
        Self {
            graph_options: FunctionGraphOptions::default(),
            layout_algorithm_name: "Hierarchical".to_string(),
            window_width: 1024,
            window_height: 768,
            restore_window_position: true,
            center_on_entry: true,
            group_shortcut: "G".to_string(),
            ungroup_shortcut: "U".to_string(),
            merge_edges: false,
            highlight_hover_path: true,
        }
    }
}

impl FunctionGraphPluginOptions {
    /// Parse the stored layout algorithm name into a [`LayoutAlgorithm`].
    pub fn layout_algorithm(&self) -> LayoutAlgorithm {
        match self.layout_algorithm_name.as_str() {
            "Hierarchical" => LayoutAlgorithm::Hierarchical,
            "ForceDirected" | "Force Directed" => LayoutAlgorithm::ForceDirected,
            "Circular" => LayoutAlgorithm::Circular,
            "Radial" => LayoutAlgorithm::Radial,
            _ => LayoutAlgorithm::Hierarchical,
        }
    }

    /// Set the layout algorithm by name.
    pub fn set_layout_algorithm(&mut self, algorithm: LayoutAlgorithm) {
        self.layout_algorithm_name = match algorithm {
            LayoutAlgorithm::Hierarchical => "Hierarchical".to_string(),
            LayoutAlgorithm::ForceDirected => "ForceDirected".to_string(),
            LayoutAlgorithm::Circular => "Circular".to_string(),
            LayoutAlgorithm::Radial => "Radial".to_string(),
        };
    }
}

// ---------------------------------------------------------------------------
// Option registration helper
// ---------------------------------------------------------------------------

/// Description of a single option for registration with the options system.
#[derive(Debug, Clone)]
pub struct OptionDescriptor {
    /// The option key (dotted path).
    pub key: String,
    /// The option category.
    pub category: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Human-readable description.
    pub description: String,
    /// The default value as a string (for display purposes).
    pub default_value: String,
}

impl OptionDescriptor {
    /// Create a new option descriptor.
    pub fn new(
        key: impl Into<String>,
        category: impl Into<String>,
        display_name: impl Into<String>,
        description: impl Into<String>,
        default_value: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            category: category.into(),
            display_name: display_name.into(),
            description: description.into(),
            default_value: default_value.into(),
        }
    }
}

/// Build the full list of option descriptors for the function graph feature.
///
/// This is used by the options registration system to present the
/// options UI to the user.
pub fn build_option_descriptors() -> Vec<OptionDescriptor> {
    let defaults = FunctionGraphPluginOptions::default();
    vec![
        OptionDescriptor::new(
            option_keys::MAX_NODES,
            option_keys::CATEGORY_FUNCTION_GRAPH,
            "Maximum Nodes",
            "Maximum number of nodes before the function graph viewer refuses to load the function.",
            defaults.graph_options.max_nodes.to_string(),
        ),
        OptionDescriptor::new(
            option_keys::SHOW_SATELLITE,
            option_keys::CATEGORY_FUNCTION_GRAPH,
            "Show Satellite",
            "Whether to show the satellite (overview) viewer.",
            defaults.graph_options.show_satellite.to_string(),
        ),
        OptionDescriptor::new(
            option_keys::FULL_SIZE_TOOLTIP,
            option_keys::CATEGORY_FUNCTION_GRAPH,
            "Full Size Tooltip",
            "Whether to use full-size vertices in tooltips.",
            defaults.graph_options.full_size_tooltip.to_string(),
        ),
        OptionDescriptor::new(
            option_keys::UPDATE_GROUP_COLORS,
            option_keys::CATEGORY_FUNCTION_GRAPH,
            "Update Group Colors Automatically",
            "Automatically update vertex colours when grouping.",
            defaults
                .graph_options
                .update_group_colors_automatically
                .to_string(),
        ),
        OptionDescriptor::new(
            option_keys::LAYOUT_ALGORITHM,
            option_keys::CATEGORY_LAYOUT,
            "Layout Algorithm",
            "The default layout algorithm for new graphs.",
            &defaults.layout_algorithm_name,
        ),
        OptionDescriptor::new(
            option_keys::LAYOUT_LAYER_SPACING,
            option_keys::CATEGORY_LAYOUT,
            "Layer Spacing",
            "Spacing between layers (hierarchical) or rings (radial) in pixels.",
            "80.0",
        ),
        OptionDescriptor::new(
            option_keys::LAYOUT_NODE_SPACING,
            option_keys::CATEGORY_LAYOUT,
            "Node Spacing",
            "Minimum horizontal spacing between sibling vertices in pixels.",
            "60.0",
        ),
        OptionDescriptor::new(
            option_keys::LAYOUT_MAX_ITERATIONS,
            option_keys::CATEGORY_LAYOUT,
            "Max Iterations",
            "Maximum number of iterations for iterative layout algorithms.",
            "200",
        ),
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_options() {
        let opts = FunctionGraphPluginOptions::default();
        assert_eq!(opts.layout_algorithm(), LayoutAlgorithm::Hierarchical);
        assert_eq!(opts.window_width, 1024);
        assert_eq!(opts.window_height, 768);
        assert!(opts.center_on_entry);
        assert!(opts.restore_window_position);
        assert!(opts.highlight_hover_path);
        assert!(!opts.merge_edges);
    }

    #[test]
    fn layout_algorithm_round_trip() {
        let mut opts = FunctionGraphPluginOptions::default();

        opts.set_layout_algorithm(LayoutAlgorithm::Circular);
        assert_eq!(opts.layout_algorithm(), LayoutAlgorithm::Circular);
        assert_eq!(opts.layout_algorithm_name, "Circular");

        opts.set_layout_algorithm(LayoutAlgorithm::ForceDirected);
        assert_eq!(opts.layout_algorithm(), LayoutAlgorithm::ForceDirected);

        opts.set_layout_algorithm(LayoutAlgorithm::Radial);
        assert_eq!(opts.layout_algorithm(), LayoutAlgorithm::Radial);

        // Unknown name falls back to Hierarchical.
        opts.layout_algorithm_name = "UnknownAlgo".to_string();
        assert_eq!(opts.layout_algorithm(), LayoutAlgorithm::Hierarchical);
    }

    #[test]
    fn option_descriptors_present() {
        let descriptors = build_option_descriptors();
        assert!(descriptors.len() >= 8);
        // All descriptors should have non-empty keys.
        for d in &descriptors {
            assert!(!d.key.is_empty());
            assert!(!d.category.is_empty());
            assert!(!d.display_name.is_empty());
        }
    }

    #[test]
    fn serialization_round_trip() {
        let opts = FunctionGraphPluginOptions::default();
        let json = serde_json::to_string(&opts).unwrap();
        let restored: FunctionGraphPluginOptions = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.layout_algorithm(), opts.layout_algorithm());
        assert_eq!(restored.window_width, opts.window_width);
        assert_eq!(
            restored.graph_options.max_nodes,
            opts.graph_options.max_nodes
        );
    }
}
