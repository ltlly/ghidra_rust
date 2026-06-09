//! Graph plugin for program visualization.
//!
//! Ported from Ghidra's `ghidra.features.graph` GraphPlugin Java class
//! (Features/Graph/src/main/java/ghidra/features/graph/GraphPlugin.java).
//!
//! The main plugin that provides graph visualization capabilities for the
//! current program. It integrates with the graph display broker to create
//! and manage graph displays (call graphs, control flow graphs, data
//! dependency graphs, etc.).
//!
//! # Key Types
//!
//! - [`GraphPlugin`] -- The main graph plugin managing graph lifecycle
//! - [`GraphPluginConfig`] -- Configuration for the graph plugin
//! - [`GraphAction`] -- Actions that can be performed on graph displays

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// GraphAction
// ---------------------------------------------------------------------------

/// Actions available on a graph display.
///
/// Ported from Ghidra's graph plugin action constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GraphAction {
    /// Export the graph to an image file.
    ExportImage,
    /// Print the graph.
    Print,
    /// Zoom to fit all vertices in the viewport.
    ZoomToFit,
    /// Zoom to the selected vertices.
    ZoomToSelection,
    /// Clear the current graph and start fresh.
    Clear,
    /// Undo the last graph modification.
    Undo,
    /// Redo the last undone graph modification.
    Redo,
    /// Toggle satellite (overview) view.
    ToggleSatellite,
    /// Toggle the vertex label display.
    ToggleLabels,
    /// Run a layout algorithm on the current graph.
    Layout,
}

impl GraphAction {
    /// Human-readable name of this action.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::ExportImage => "Export Image",
            Self::Print => "Print",
            Self::ZoomToFit => "Zoom to Fit",
            Self::ZoomToSelection => "Zoom to Selection",
            Self::Clear => "Clear Graph",
            Self::Undo => "Undo",
            Self::Redo => "Redo",
            Self::ToggleSatellite => "Toggle Satellite View",
            Self::ToggleLabels => "Toggle Labels",
            Self::Layout => "Run Layout",
        }
    }

    /// Keyboard accelerator (if any).
    pub fn accelerator(&self) -> Option<&'static str> {
        match self {
            Self::ZoomToFit => Some("ctrl EQUALS"),
            Self::Undo => Some("ctrl Z"),
            Self::Redo => Some("ctrl Y"),
            Self::Print => Some("ctrl P"),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// GraphPluginConfig
// ---------------------------------------------------------------------------

/// Configuration for the graph plugin.
///
/// Ported from the graph plugin's preference and option handling.
#[derive(Debug, Clone)]
pub struct GraphPluginConfig {
    /// Whether to automatically fit the graph after layout.
    pub auto_fit: bool,
    /// Whether to animate transitions between layouts.
    pub animate_layouts: bool,
    /// Duration of layout animation in milliseconds.
    pub animation_duration_ms: u32,
    /// Default vertex size (diameter in pixels).
    pub default_vertex_size: f64,
    /// Whether to group vertices by their type.
    pub group_by_type: bool,
    /// The default layout algorithm name.
    pub default_layout: String,
    /// Maximum number of vertices before auto-grouping kicks in.
    pub auto_group_threshold: usize,
    /// Whether to show edge arrows.
    pub show_edge_arrows: bool,
    /// Custom vertex colors keyed by vertex type name.
    pub vertex_colors: HashMap<String, u32>,
}

impl Default for GraphPluginConfig {
    fn default() -> Self {
        Self {
            auto_fit: true,
            animate_layouts: true,
            animation_duration_ms: 500,
            default_vertex_size: 30.0,
            group_by_type: false,
            default_layout: "Hierarchical".to_string(),
            auto_group_threshold: 200,
            show_edge_arrows: true,
            vertex_colors: HashMap::new(),
        }
    }
}

impl GraphPluginConfig {
    /// Set the color for a vertex type.
    pub fn set_vertex_color(&mut self, vertex_type: impl Into<String>, color: u32) {
        self.vertex_colors.insert(vertex_type.into(), color);
    }

    /// Get the color for a vertex type, or `None` if not set.
    pub fn vertex_color(&self, vertex_type: &str) -> Option<u32> {
        self.vertex_colors.get(vertex_type).copied()
    }

    /// Whether the vertex count exceeds the auto-group threshold.
    pub fn should_auto_group(&self, vertex_count: usize) -> bool {
        self.group_by_type && vertex_count >= self.auto_group_threshold
    }
}

// ---------------------------------------------------------------------------
// GraphPlugin
// ---------------------------------------------------------------------------

/// The main graph plugin for program visualization.
///
/// Manages graph display lifecycle, integrates with the graph display broker,
/// and provides the entry point for creating graph views of a program.
///
/// Ported from `ghidra.features.graph.GraphPlugin`.
#[derive(Debug)]
pub struct GraphPlugin {
    /// Plugin configuration.
    config: GraphPluginConfig,
    /// Whether the plugin is currently enabled.
    enabled: bool,
    /// Names of registered graph providers.
    providers: Vec<String>,
    /// The name of the active graph provider.
    active_provider: Option<String>,
    /// The currently displayed graph title (if any).
    current_graph_title: Option<String>,
}

impl GraphPlugin {
    /// Create a new graph plugin.
    pub fn new() -> Self {
        Self {
            config: GraphPluginConfig::default(),
            enabled: true,
            providers: Vec::new(),
            active_provider: None,
            current_graph_title: None,
        }
    }

    /// Whether the plugin is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the plugin.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get the plugin configuration.
    pub fn config(&self) -> &GraphPluginConfig {
        &self.config
    }

    /// Get a mutable reference to the plugin configuration.
    pub fn config_mut(&mut self) -> &mut GraphPluginConfig {
        &mut self.config
    }

    /// Register a graph display provider.
    pub fn register_provider(&mut self, name: impl Into<String>) {
        let name = name.into();
        if !self.providers.contains(&name) {
            self.providers.push(name.clone());
        }
        if self.active_provider.is_none() {
            self.active_provider = Some(name);
        }
    }

    /// Get the list of registered provider names.
    pub fn providers(&self) -> &[String] {
        &self.providers
    }

    /// Get the active provider name.
    pub fn active_provider(&self) -> Option<&str> {
        self.active_provider.as_deref()
    }

    /// Set the active graph provider by name.
    ///
    /// Returns `true` if the provider was found and activated.
    pub fn set_active_provider(&mut self, name: impl Into<String>) -> bool {
        let name = name.into();
        if self.providers.contains(&name) {
            self.active_provider = Some(name);
            true
        } else {
            false
        }
    }

    /// Get the current graph title.
    pub fn current_graph_title(&self) -> Option<&str> {
        self.current_graph_title.as_deref()
    }

    /// Set the current graph title.
    pub fn set_current_graph_title(&mut self, title: Option<String>) {
        self.current_graph_title = title;
    }

    /// Number of registered providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Whether an action is available in the current state.
    pub fn is_action_available(&self, action: GraphAction) -> bool {
        if !self.enabled {
            return false;
        }
        match action {
            GraphAction::ExportImage | GraphAction::Print => self.current_graph_title.is_some(),
            GraphAction::ZoomToFit | GraphAction::ZoomToSelection => {
                self.current_graph_title.is_some()
            }
            GraphAction::Undo | GraphAction::Redo => self.current_graph_title.is_some(),
            GraphAction::Clear => self.current_graph_title.is_some(),
            GraphAction::ToggleSatellite
            | GraphAction::ToggleLabels
            | GraphAction::Layout => self.current_graph_title.is_some(),
        }
    }
}

impl Default for GraphPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_action_display_names() {
        assert_eq!(GraphAction::ExportImage.display_name(), "Export Image");
        assert_eq!(GraphAction::ZoomToFit.display_name(), "Zoom to Fit");
        assert_eq!(GraphAction::ToggleSatellite.display_name(), "Toggle Satellite View");
    }

    #[test]
    fn test_graph_action_accelerators() {
        assert_eq!(GraphAction::ZoomToFit.accelerator(), Some("ctrl EQUALS"));
        assert_eq!(GraphAction::Undo.accelerator(), Some("ctrl Z"));
        assert_eq!(GraphAction::ExportImage.accelerator(), None);
    }

    #[test]
    fn test_graph_plugin_config_default() {
        let config = GraphPluginConfig::default();
        assert!(config.auto_fit);
        assert!(config.animate_layouts);
        assert_eq!(config.animation_duration_ms, 500);
        assert_eq!(config.default_vertex_size, 30.0);
        assert!(!config.group_by_type);
        assert_eq!(config.default_layout, "Hierarchical");
        assert_eq!(config.auto_group_threshold, 200);
        assert!(config.show_edge_arrows);
    }

    #[test]
    fn test_graph_plugin_config_vertex_colors() {
        let mut config = GraphPluginConfig::default();
        config.set_vertex_color("function", 0xFF0000);
        assert_eq!(config.vertex_color("function"), Some(0xFF0000));
        assert_eq!(config.vertex_color("data"), None);
    }

    #[test]
    fn test_graph_plugin_config_auto_group() {
        let mut config = GraphPluginConfig::default();
        assert!(!config.should_auto_group(300)); // group_by_type is false

        config.group_by_type = true;
        assert!(!config.should_auto_group(100)); // below threshold
        assert!(config.should_auto_group(200)); // at threshold
        assert!(config.should_auto_group(500)); // above threshold
    }

    #[test]
    fn test_graph_plugin_lifecycle() {
        let mut plugin = GraphPlugin::new();
        assert!(plugin.is_enabled());
        assert_eq!(plugin.provider_count(), 0);
        assert!(plugin.active_provider().is_none());
        assert!(plugin.current_graph_title().is_none());

        plugin.register_provider("ProviderA");
        assert_eq!(plugin.provider_count(), 1);
        assert_eq!(plugin.active_provider(), Some("ProviderA"));

        plugin.register_provider("ProviderB");
        assert_eq!(plugin.provider_count(), 2);
        assert_eq!(plugin.active_provider(), Some("ProviderA")); // unchanged

        assert!(plugin.set_active_provider("ProviderB"));
        assert_eq!(plugin.active_provider(), Some("ProviderB"));

        plugin.set_current_graph_title(Some("Call Graph - main".to_string()));
        assert_eq!(plugin.current_graph_title(), Some("Call Graph - main"));

        plugin.set_enabled(false);
        assert!(!plugin.is_enabled());
    }

    #[test]
    fn test_graph_plugin_action_availability() {
        let mut plugin = GraphPlugin::new();
        plugin.register_provider("default");

        // No graph displayed yet -- actions should not be available
        assert!(!plugin.is_action_available(GraphAction::ExportImage));
        assert!(!plugin.is_action_available(GraphAction::ZoomToFit));
        assert!(!plugin.is_action_available(GraphAction::Clear));

        // Display a graph
        plugin.set_current_graph_title(Some("Test Graph".to_string()));
        assert!(plugin.is_action_available(GraphAction::ExportImage));
        assert!(plugin.is_action_available(GraphAction::ZoomToFit));
        assert!(plugin.is_action_available(GraphAction::Clear));
        assert!(plugin.is_action_available(GraphAction::Layout));
    }

    #[test]
    fn test_graph_plugin_disabled_actions() {
        let mut plugin = GraphPlugin::new();
        plugin.set_current_graph_title(Some("Graph".to_string()));
        plugin.set_enabled(false);

        // Even with a graph title, disabled plugin means no actions
        assert!(!plugin.is_action_available(GraphAction::ExportImage));
        assert!(!plugin.is_action_available(GraphAction::Layout));
    }

    #[test]
    fn test_graph_plugin_duplicate_provider() {
        let mut plugin = GraphPlugin::new();
        plugin.register_provider("A");
        plugin.register_provider("A");
        assert_eq!(plugin.provider_count(), 1);
    }

    #[test]
    fn test_graph_plugin_set_nonexistent_provider() {
        let mut plugin = GraphPlugin::new();
        plugin.register_provider("A");
        assert!(!plugin.set_active_provider("NonExistent"));
        assert_eq!(plugin.active_provider(), Some("A"));
    }

    #[test]
    fn test_graph_plugin_config_mutability() {
        let mut plugin = GraphPlugin::new();
        plugin.config_mut().animate_layouts = false;
        plugin.config_mut().default_layout = "Circular".to_string();
        assert!(!plugin.config().animate_layouts);
        assert_eq!(plugin.config().default_layout, "Circular");
    }
}
