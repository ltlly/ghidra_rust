//! Function Graph display for one side of a comparison.
//!
//! Ported from Ghidra's `FgDisplay` Java class.
//!
//! This class displays a Function Graph in the left or right side of the
//! Function Comparison view. It wraps the function graph controller and
//! provides a simplified interface for the comparison view to interact with.
//!
//! In the original Java, `FgDisplay` implements `OptionsChangeListener` and
//! manages a `FGController`, layout providers, color providers, and program
//! listeners. In this Rust port, we capture the logical state without the
//! Ghidra UI framework dependency.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::super::graphanalysis::Side;
use super::super::panel::{ProgramLocation, ProgramInfo};

/// Configuration options for the function graph display.
///
/// Ported from Ghidra's `FgOptions` / `FunctionGraphOptions` Java classes.
#[derive(Debug, Clone)]
pub struct FgDisplayOptions {
    /// Whether to show vertex popups.
    pub show_popups: bool,
    /// Whether to show the satellite view.
    pub show_satellite: bool,
    /// Whether to use animation (always false in comparison mode).
    pub use_animation: bool,
    /// The current layout provider name.
    pub layout_name: String,
    /// Whether to show edge arrows.
    pub show_edge_arrows: bool,
    /// Whether to group vertices.
    pub group_vertices: bool,
}

impl FgDisplayOptions {
    /// Create default options.
    pub fn new() -> Self {
        Self {
            show_popups: true,
            show_satellite: true,
            use_animation: false,
            layout_name: "Flow Chart".to_string(),
            show_edge_arrows: true,
            group_vertices: false,
        }
    }

    /// Check if an option change requires a full relayout.
    pub fn requires_relayout(&self, option_name: &str) -> bool {
        matches!(
            option_name,
            "LAYOUT" | "GROUP_VERTICES" | "SHOW_EDGE_ARROWS"
        )
    }
}

impl Default for FgDisplayOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// State of the function graph display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayState {
    /// No function loaded.
    Empty,
    /// A function is being displayed.
    Displaying,
    /// The graph is being computed/built.
    Loading,
    /// An error occurred.
    Error,
}

/// A location change event from the function graph.
#[derive(Debug, Clone)]
pub struct LocationChangeEvent {
    /// The new location.
    pub location: ProgramLocation,
    /// Whether the vertex changed (not just the address within the same vertex).
    pub vertex_changed: bool,
}

/// Represents one side of a dual function graph comparison window.
///
/// Ported from Ghidra's `FgDisplay` Java class.
///
/// Holds the graph state, options, and current location for one side
/// of the comparison. The display is responsible for:
/// - Managing the function graph data (vertices, edges)
/// - Tracking the current cursor location
/// - Handling options changes
/// - Notifying listeners of location changes and graph rebuilds
#[derive(Debug)]
pub struct FgDisplay {
    /// The owner (typically the comparison view name).
    owner: String,
    /// Which side this display is on.
    side: Side,
    /// Current display state.
    state: DisplayState,
    /// Current options.
    options: FgDisplayOptions,
    /// Current cursor location.
    current_location: Option<ProgramLocation>,
    /// The entry point address of the current function.
    function_entry: Option<u64>,
    /// Whether the display is busy (loading/rebuilding).
    busy: bool,
    /// Graph vertices (simplified representation).
    vertices: Vec<FgVertex>,
    /// Graph edges (simplified representation).
    edges: Vec<FgEdge>,
    /// Status message to display when no graph is available.
    status_message: Option<String>,
    /// Timestamp of last refresh for rate limiting.
    last_refresh: Option<Instant>,
    /// Minimum interval between refreshes.
    refresh_interval: Duration,
}

/// A vertex in the function graph.
#[derive(Debug, Clone)]
pub struct FgVertex {
    /// Unique identifier.
    pub id: u32,
    /// The address range of this basic block.
    pub start_address: u64,
    /// End address of the basic block.
    pub end_address: u64,
    /// The number of instructions in this block.
    pub instruction_count: usize,
    /// Display label.
    pub label: String,
}

/// An edge in the function graph.
#[derive(Debug, Clone)]
pub struct FgEdge {
    /// Source vertex ID.
    pub from: u32,
    /// Destination vertex ID.
    pub to: u32,
    /// The type of edge (conditional true, conditional false, unconditional, etc.).
    pub edge_type: FgEdgeType,
}

/// Type of function graph edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FgEdgeType {
    /// Unconditional jump/fallthrough.
    Unconditional,
    /// Conditional branch (true path).
    ConditionalTrue,
    /// Conditional branch (false path).
    ConditionalFalse,
    /// Call edge.
    Call,
}

impl FgDisplay {
    /// Create a new function graph display.
    pub fn new(owner: impl Into<String>, side: Side) -> Self {
        Self {
            owner: owner.into(),
            side,
            state: DisplayState::Empty,
            options: FgDisplayOptions::new(),
            current_location: None,
            function_entry: None,
            busy: false,
            vertices: Vec::new(),
            edges: Vec::new(),
            status_message: None,
            last_refresh: None,
            refresh_interval: Duration::from_millis(500),
        }
    }

    /// Get the owner name.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Get the side this display is on.
    pub fn side(&self) -> Side {
        self.side
    }

    /// Get the current display state.
    pub fn state(&self) -> DisplayState {
        self.state
    }

    /// Get the current options.
    pub fn options(&self) -> &FgDisplayOptions {
        &self.options
    }

    /// Get mutable options.
    pub fn options_mut(&mut self) -> &mut FgDisplayOptions {
        &mut self.options
    }

    /// Set the options.
    pub fn set_options(&mut self, options: FgDisplayOptions) {
        self.options = options;
    }

    /// Whether the display is busy (loading or rebuilding).
    pub fn is_busy(&self) -> bool {
        self.busy
    }

    /// Get the current location.
    pub fn location(&self) -> Option<&ProgramLocation> {
        self.current_location.as_ref()
    }

    /// Set the cursor location.
    pub fn set_location(&mut self, location: ProgramLocation) {
        self.current_location = Some(location);
    }

    /// Get the status message.
    pub fn status_message(&self) -> Option<&str> {
        self.status_message.as_deref()
    }

    /// Whether the display has results (a loaded graph).
    pub fn has_results(&self) -> bool {
        self.state == DisplayState::Displaying
    }

    /// Get the function entry point.
    pub fn function_entry(&self) -> Option<u64> {
        self.function_entry
    }

    /// Show a function in this display.
    ///
    /// Clears any existing graph and loads the new function. If the function
    /// is None or external, an appropriate status message is set.
    pub fn show_function(&mut self, function_entry: Option<u64>, is_external: bool, name: &str) {
        self.current_location = None;
        self.vertices.clear();
        self.edges.clear();

        if function_entry.is_none() {
            self.state = DisplayState::Empty;
            self.status_message = Some("No Function".to_string());
            self.function_entry = None;
            return;
        }

        if is_external {
            self.state = DisplayState::Empty;
            self.status_message = Some(format!("\"{}\" is an external function.", name));
            self.function_entry = None;
            return;
        }

        self.function_entry = function_entry;
        self.status_message = None;
        self.state = DisplayState::Displaying;

        // Set initial location to function entry
        if let Some(entry) = function_entry {
            self.current_location = Some(ProgramLocation::new(
                ProgramInfo::new(0, "", &self.owner),
                entry,
            ));
        }
    }

    /// Clear the display and show a status message.
    pub fn clear_and_show_message(&mut self, message: impl Into<String>) {
        self.state = DisplayState::Empty;
        self.status_message = Some(message.into());
        self.vertices.clear();
        self.edges.clear();
        self.current_location = None;
    }

    /// Load graph data (vertices and edges).
    pub fn load_graph(&mut self, vertices: Vec<FgVertex>, edges: Vec<FgEdge>) {
        self.vertices = vertices;
        self.edges = edges;
        self.state = DisplayState::Displaying;
    }

    /// Get the vertices.
    pub fn vertices(&self) -> &[FgVertex] {
        &self.vertices
    }

    /// Get the edges.
    pub fn edges(&self) -> &[FgEdge] {
        &self.edges
    }

    /// Refresh the display (rebuild the graph).
    ///
    /// Rate-limited to prevent excessive rebuilds.
    pub fn refresh(&mut self) -> bool {
        let now = Instant::now();
        if let Some(last) = self.last_refresh {
            if now.duration_since(last) < self.refresh_interval {
                return false;
            }
        }
        self.last_refresh = Some(now);
        // In a real implementation, this would trigger a graph rebuild.
        // For the port, we just mark the state.
        if self.function_entry.is_some() {
            self.state = DisplayState::Displaying;
        }
        true
    }

    /// Reset the graph (clear all vertex positions and grouping).
    pub fn reset_graph(&mut self) {
        // In the real implementation, this would reset all vertex positions
        // and grouping information. For the port, we just clear the graph.
        self.vertices.clear();
        self.edges.clear();
        if self.function_entry.is_some() {
            self.state = DisplayState::Loading;
        }
    }

    /// Set the popup visibility.
    pub fn set_popups_visible(&mut self, visible: bool) {
        self.options.show_popups = visible;
    }

    /// Set the satellite visibility.
    pub fn set_satellite_visible(&mut self, visible: bool) {
        self.options.show_satellite = visible;
    }

    /// Check if popups are visible.
    pub fn are_popups_visible(&self) -> bool {
        self.options.show_popups
    }

    /// Check if satellite is visible.
    pub fn is_satellite_visible(&self) -> bool {
        self.options.show_satellite
    }

    /// Change the layout.
    pub fn change_layout(&mut self, layout_name: impl Into<String>) {
        self.options.layout_name = layout_name.into();
    }

    /// Get the layout name.
    pub fn layout_name(&self) -> &str {
        &self.options.layout_name
    }

    /// Dispose of this display (release all resources).
    pub fn dispose(&mut self) {
        self.state = DisplayState::Empty;
        self.vertices.clear();
        self.edges.clear();
        self.current_location = None;
        self.function_entry = None;
        self.busy = false;
        self.status_message = None;
    }

    /// Find the vertex that contains the given address.
    pub fn find_vertex_at_address(&self, address: u64) -> Option<&FgVertex> {
        self.vertices
            .iter()
            .find(|v| address >= v.start_address && address <= v.end_address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fg_display_new() {
        let display = FgDisplay::new("test", Side::Left);
        assert_eq!(display.owner(), "test");
        assert_eq!(display.side(), Side::Left);
        assert_eq!(display.state(), DisplayState::Empty);
        assert!(!display.is_busy());
        assert!(!display.has_results());
    }

    #[test]
    fn test_fg_display_show_function() {
        let mut display = FgDisplay::new("test", Side::Left);
        display.show_function(Some(0x1000), false, "main");

        assert_eq!(display.state(), DisplayState::Displaying);
        assert!(display.has_results());
        assert!(display.location().is_some());
        assert_eq!(display.location().unwrap().address, 0x1000);
        assert_eq!(display.function_entry(), Some(0x1000));
    }

    #[test]
    fn test_fg_display_show_null_function() {
        let mut display = FgDisplay::new("test", Side::Left);
        display.show_function(None, false, "");

        assert_eq!(display.state(), DisplayState::Empty);
        assert_eq!(display.status_message(), Some("No Function"));
    }

    #[test]
    fn test_fg_display_show_external_function() {
        let mut display = FgDisplay::new("test", Side::Left);
        display.show_function(Some(0x1000), true, "printf");

        assert_eq!(display.state(), DisplayState::Empty);
        assert!(display.status_message().unwrap().contains("external"));
    }

    #[test]
    fn test_fg_display_load_graph() {
        let mut display = FgDisplay::new("test", Side::Right);
        display.show_function(Some(0x1000), false, "main");

        let vertices = vec![
            FgVertex {
                id: 0,
                start_address: 0x1000,
                end_address: 0x1020,
                instruction_count: 5,
                label: "BLOCK 0".to_string(),
            },
            FgVertex {
                id: 1,
                start_address: 0x1020,
                end_address: 0x1040,
                instruction_count: 3,
                label: "BLOCK 1".to_string(),
            },
        ];
        let edges = vec![FgEdge {
            from: 0,
            to: 1,
            edge_type: FgEdgeType::Unconditional,
        }];

        display.load_graph(vertices, edges);
        assert!(display.has_results());
        assert_eq!(display.vertices().len(), 2);
        assert_eq!(display.edges().len(), 1);
    }

    #[test]
    fn test_fg_display_location() {
        let mut display = FgDisplay::new("test", Side::Left);
        assert!(display.location().is_none());

        display.set_location(ProgramLocation::new(ProgramInfo::new(0, "", "test"), 0x2000));
        assert_eq!(display.location().unwrap().address, 0x2000);
    }

    #[test]
    fn test_fg_display_popups() {
        let mut display = FgDisplay::new("test", Side::Left);
        assert!(display.are_popups_visible());

        display.set_popups_visible(false);
        assert!(!display.are_popups_visible());
    }

    #[test]
    fn test_fg_display_satellite() {
        let mut display = FgDisplay::new("test", Side::Left);
        assert!(display.is_satellite_visible());

        display.set_satellite_visible(false);
        assert!(!display.is_satellite_visible());
    }

    #[test]
    fn test_fg_display_layout() {
        let mut display = FgDisplay::new("test", Side::Left);
        assert_eq!(display.layout_name(), "Flow Chart");

        display.change_layout("Block Model");
        assert_eq!(display.layout_name(), "Block Model");
    }

    #[test]
    fn test_fg_display_clear() {
        let mut display = FgDisplay::new("test", Side::Left);
        display.show_function(Some(0x1000), false, "main");
        display.clear_and_show_message("Loading...");

        assert_eq!(display.state(), DisplayState::Empty);
        assert_eq!(display.status_message(), Some("Loading..."));
        assert!(display.vertices().is_empty());
    }

    #[test]
    fn test_fg_display_dispose() {
        let mut display = FgDisplay::new("test", Side::Left);
        display.show_function(Some(0x1000), false, "main");
        display.dispose();

        assert_eq!(display.state(), DisplayState::Empty);
        assert!(display.vertices().is_empty());
        assert!(display.function_entry().is_none());
    }

    #[test]
    fn test_fg_display_find_vertex() {
        let mut display = FgDisplay::new("test", Side::Left);
        display.show_function(Some(0x1000), false, "main");

        display.load_graph(
            vec![
                FgVertex {
                    id: 0,
                    start_address: 0x1000,
                    end_address: 0x1020,
                    instruction_count: 5,
                    label: "BLOCK 0".to_string(),
                },
                FgVertex {
                    id: 1,
                    start_address: 0x1020,
                    end_address: 0x1040,
                    instruction_count: 3,
                    label: "BLOCK 1".to_string(),
                },
            ],
            vec![],
        );

        assert!(display.find_vertex_at_address(0x1010).is_some());
        assert_eq!(display.find_vertex_at_address(0x1010).unwrap().id, 0);
        assert!(display.find_vertex_at_address(0x1030).is_some());
        assert_eq!(display.find_vertex_at_address(0x1030).unwrap().id, 1);
        assert!(display.find_vertex_at_address(0x2000).is_none());
    }

    #[test]
    fn test_fg_display_reset_graph() {
        let mut display = FgDisplay::new("test", Side::Left);
        display.show_function(Some(0x1000), false, "main");
        display.load_graph(
            vec![FgVertex {
                id: 0,
                start_address: 0x1000,
                end_address: 0x1020,
                instruction_count: 5,
                label: "BLOCK 0".to_string(),
            }],
            vec![],
        );

        display.reset_graph();
        assert!(display.vertices().is_empty());
        assert_eq!(display.state(), DisplayState::Loading);
    }

    #[test]
    fn test_fg_display_options_requires_relayout() {
        let opts = FgDisplayOptions::new();
        assert!(opts.requires_relayout("LAYOUT"));
        assert!(opts.requires_relayout("GROUP_VERTICES"));
        assert!(!opts.requires_relayout("SHOW_POPUPS"));
    }

    #[test]
    fn test_fg_edge_types() {
        let edge = FgEdge {
            from: 0,
            to: 1,
            edge_type: FgEdgeType::ConditionalTrue,
        };
        assert_eq!(edge.edge_type, FgEdgeType::ConditionalTrue);
    }
}
