//! FunctionGraph MVC types -- Rust port of Ghidra's `functiongraph.mvc` package.
//!
//! These types model the data, options, and navigation state that drive
//! the function-graph viewer.
//!
//! - [`FGVertexType`] -- classification of a vertex in the graph
//! - [`NavigationHistoryMode`] -- how the viewer tracks navigation history
//! - [`RelayoutOption`] -- when to trigger automatic re-layout
//! - [`EdgeColorScheme`] -- per-edge-type colour configuration
//! - [`FunctionGraphOptions`] -- all configurable options
//! - [`FGData`] -- MVC data holder (function + graph + error)
//! - [`GroupHistoryInfo`] -- records which vertices were grouped together
//! - [`VertexInfo`] -- saved address and position for a vertex

use ghidra_core::addr::Address;
use ghidra_core::program::listing::Function;
use serde::{Deserialize, Serialize};

use crate::functiongraph::{CfgEdgeType, FunctionGraph};

// ---------------------------------------------------------------------------
// FGVertexType
// ---------------------------------------------------------------------------

/// Classification of a vertex within the function graph.
///
/// Mirrors the Java `FGVertexType` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FGVertexType {
    /// A normal body block (not entry, not exit).
    Body,
    /// The entry point of the function.
    Entry,
    /// An exit point of the function.
    Exit,
    /// A grouped vertex (containing multiple body vertices).
    Group,
    /// The function has exactly one block -- it is simultaneously entry and exit.
    Singleton,
}

impl FGVertexType {
    /// Whether this vertex type represents an entry point.
    pub fn is_entry(&self) -> bool {
        matches!(self, FGVertexType::Entry | FGVertexType::Singleton)
    }

    /// Whether this vertex type represents an exit point.
    pub fn is_exit(&self) -> bool {
        matches!(self, FGVertexType::Exit | FGVertexType::Singleton)
    }
}

impl std::fmt::Display for FGVertexType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FGVertexType::Body => write!(f, "BODY"),
            FGVertexType::Entry => write!(f, "ENTRY"),
            FGVertexType::Exit => write!(f, "EXIT"),
            FGVertexType::Group => write!(f, "GROUP"),
            FGVertexType::Singleton => write!(f, "SINGLETON"),
        }
    }
}

// ---------------------------------------------------------------------------
// NavigationHistoryMode
// ---------------------------------------------------------------------------

/// How the viewer tracks navigation history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NavigationHistoryMode {
    /// Save a history entry when a navigation takes place (double-click, Go To).
    NavigationEvents,
    /// Save a history entry each time a new vertex is selected.
    VertexChanges,
}

impl Default for NavigationHistoryMode {
    fn default() -> Self {
        Self::NavigationEvents
    }
}

// ---------------------------------------------------------------------------
// RelayoutOption
// ---------------------------------------------------------------------------

/// When to trigger automatic re-layout of the graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RelayoutOption {
    /// Always relayout when the block model changes.
    Always,
    /// Relayout only when the block model changes (not user colour changes, etc.).
    BlockModelChangesOnly,
    /// Never relayout automatically.
    Never,
}

impl Default for RelayoutOption {
    fn default() -> Self {
        Self::Always
    }
}

// ---------------------------------------------------------------------------
// EdgeColorScheme
// ---------------------------------------------------------------------------

/// Configurable colours for each edge type.
///
/// Each field is an RGBA hex value (e.g. `0xFF0000FF` for red opaque).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeColorScheme {
    /// Colour for fallthrough edges.
    pub fallthrough: u32,
    /// Colour for unconditional-jump edges.
    pub unconditional_jump: u32,
    /// Colour for conditional true-branch edges.
    pub conditional_true: u32,
    /// Colour for conditional false-branch edges.
    pub conditional_false: u32,
    /// Default alpha for non-highlighted edges (0-255).
    pub default_alpha: u8,
}

impl Default for EdgeColorScheme {
    fn default() -> Self {
        Self {
            fallthrough: 0x808080FF,     // grey
            unconditional_jump: 0x0000FFFF, // blue
            conditional_true: 0x00FF00FF,  // green
            conditional_false: 0xFF0000FF, // red
            default_alpha: 128,
        }
    }
}

impl EdgeColorScheme {
    /// Get the colour for a specific edge type.
    pub fn color_for_edge(&self, edge_type: CfgEdgeType) -> u32 {
        match edge_type {
            CfgEdgeType::Fallthrough => self.fallthrough,
            CfgEdgeType::Branch => self.unconditional_jump,
            CfgEdgeType::TrueBranch => self.conditional_true,
            CfgEdgeType::FalseBranch => self.conditional_false,
            _ => self.fallthrough,
        }
    }
}

// ---------------------------------------------------------------------------
// FunctionGraphOptions
// ---------------------------------------------------------------------------

/// All configurable options for the function graph viewer.
///
/// Mirrors the Java `FunctionGraphOptions` class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionGraphOptions {
    /// Edge colour scheme.
    pub edge_colors: EdgeColorScheme,
    /// Navigation history tracking mode.
    pub navigation_history: NavigationHistoryMode,
    /// When to trigger automatic re-layout.
    pub relayout: RelayoutOption,
    /// Maximum number of nodes before the graph refuses to load.
    pub max_nodes: usize,
    /// Whether to use full-size vertices in tooltips.
    pub full_size_tooltip: bool,
    /// Whether to automatically update vertex colours when grouping.
    pub update_group_colors_automatically: bool,
    /// Default background colour for group vertices (RGBA).
    pub default_group_background_color: u32,
    /// Default vertex background colour (RGBA).
    pub default_vertex_background_color: u32,
    /// Whether to show the satellite (overview) viewer.
    pub show_satellite: bool,
}

impl Default for FunctionGraphOptions {
    fn default() -> Self {
        Self {
            edge_colors: EdgeColorScheme::default(),
            navigation_history: NavigationHistoryMode::default(),
            relayout: RelayoutOption::default(),
            max_nodes: 5000,
            full_size_tooltip: true,
            update_group_colors_automatically: true,
            default_group_background_color: 0xC8C8C8FF,
            default_vertex_background_color: 0xFFFFFFFF,
            show_satellite: true,
        }
    }
}

// ---------------------------------------------------------------------------
// FGData
// ---------------------------------------------------------------------------

/// MVC data holder for the function graph.
///
/// Bundles a [`Function`] with its computed [`FunctionGraph`] and an optional
/// error message.  Mirrors the Java `FGData` class.
#[derive(Debug, Clone)]
pub struct FGData {
    /// The function this data describes.
    pub function: Function,
    /// The computed graph (if loading succeeded).
    pub graph: Option<FunctionGraph>,
    /// Error message if graph loading failed.
    pub error_message: Option<String>,
}

impl FGData {
    /// Create a successful data holder.
    pub fn new(function: Function, graph: FunctionGraph) -> Self {
        Self {
            function,
            graph: Some(graph),
            error_message: None,
        }
    }

    /// Create a data holder for a failed graph load.
    pub fn error(function: Function, message: impl Into<String>) -> Self {
        Self {
            function,
            graph: None,
            error_message: Some(message.into()),
        }
    }

    /// Whether this data contains a usable graph.
    pub fn has_results(&self) -> bool {
        self.graph.is_some()
    }

    /// The error message, if any.
    pub fn message(&self) -> Option<&str> {
        self.error_message.as_deref()
    }

    /// Whether the function body contains the given address.
    pub fn contains_address(&self, addr: Address) -> bool {
        self.function.body.contains(&addr)
    }
}

// ---------------------------------------------------------------------------
// GroupHistoryInfo
// ---------------------------------------------------------------------------

/// Records that a set of vertices were grouped together under a description.
///
/// Used by the graph viewer to allow undo/redo of group operations and to
/// display a meaningful label for the group vertex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupHistoryInfo {
    /// Human-readable description of the group (editable).
    pub group_description: String,
    /// The addresses of all vertices that were folded into this group.
    pub grouped_addresses: Vec<Address>,
}

impl GroupHistoryInfo {
    /// Create a new group history record.
    pub fn new(description: impl Into<String>, addresses: Vec<Address>) -> Self {
        Self {
            group_description: description.into(),
            grouped_addresses: addresses,
        }
    }

    /// Update the group description.
    pub fn set_group_description(&mut self, desc: impl Into<String>) {
        self.group_description = desc.into();
    }

    /// The number of vertices in this group.
    pub fn vertex_count(&self) -> usize {
        self.grouped_addresses.len()
    }
}

// ---------------------------------------------------------------------------
// VertexInfo
// ---------------------------------------------------------------------------

/// Saved information about a vertex's address and position.
///
/// Used for serializing/deserializing graph layouts and for restoring
/// vertex positions after group/ungroup operations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VertexInfo {
    /// The address of the vertex.
    pub address: Address,
    /// The vertex type.
    pub vertex_type: FGVertexType,
    /// X position in layout space.
    pub x: f32,
    /// Y position in layout space.
    pub y: f32,
}

impl VertexInfo {
    /// Create a new vertex info.
    pub fn new(address: Address, vertex_type: FGVertexType, x: f32, y: f32) -> Self {
        Self {
            address,
            vertex_type,
            x,
            y,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::functiongraph::{FGVertex, FunctionGraph};
    use ghidra_core::addr::{Address, AddressRange};

    fn dummy_fn() -> Function {
        Function::new(
            "test_fn",
            Address::new(0x1000),
            AddressRange::new(Address::new(0x1000), Address::new(0x1100)),
        )
    }

    // -- FGVertexType tests --------------------------------------------------

    #[test]
    fn vertex_type_entry_exit() {
        assert!(FGVertexType::Entry.is_entry());
        assert!(!FGVertexType::Entry.is_exit());
        assert!(FGVertexType::Exit.is_exit());
        assert!(!FGVertexType::Exit.is_entry());
        assert!(FGVertexType::Singleton.is_entry());
        assert!(FGVertexType::Singleton.is_exit());
        assert!(!FGVertexType::Body.is_entry());
        assert!(!FGVertexType::Body.is_exit());
        assert!(!FGVertexType::Group.is_entry());
        assert!(!FGVertexType::Group.is_exit());
    }

    #[test]
    fn vertex_type_display() {
        assert_eq!(format!("{}", FGVertexType::Body), "BODY");
        assert_eq!(format!("{}", FGVertexType::Singleton), "SINGLETON");
    }

    // -- NavigationHistoryMode tests -----------------------------------------

    #[test]
    fn navigation_history_default() {
        assert_eq!(
            NavigationHistoryMode::default(),
            NavigationHistoryMode::NavigationEvents
        );
    }

    // -- RelayoutOption tests ------------------------------------------------

    #[test]
    fn relayout_default() {
        assert_eq!(RelayoutOption::default(), RelayoutOption::Always);
    }

    // -- EdgeColorScheme tests -----------------------------------------------

    #[test]
    fn edge_color_scheme_defaults() {
        let scheme = EdgeColorScheme::default();
        assert_eq!(scheme.color_for_edge(CfgEdgeType::Fallthrough), scheme.fallthrough);
        assert_eq!(scheme.color_for_edge(CfgEdgeType::Branch), scheme.unconditional_jump);
        assert_eq!(scheme.color_for_edge(CfgEdgeType::TrueBranch), scheme.conditional_true);
        assert_eq!(scheme.color_for_edge(CfgEdgeType::FalseBranch), scheme.conditional_false);
    }

    // -- FunctionGraphOptions tests ------------------------------------------

    #[test]
    fn options_defaults() {
        let opts = FunctionGraphOptions::default();
        assert_eq!(opts.max_nodes, 5000);
        assert!(opts.full_size_tooltip);
        assert!(opts.update_group_colors_automatically);
        assert!(opts.show_satellite);
        assert_eq!(opts.relayout, RelayoutOption::Always);
    }

    // -- FGData tests --------------------------------------------------------

    #[test]
    fn fgdata_with_graph() {
        let graph = FunctionGraph::new(dummy_fn());
        let data = FGData::new(dummy_fn(), graph);
        assert!(data.has_results());
        assert!(data.message().is_none());
    }

    #[test]
    fn fgdata_error() {
        let data = FGData::error(dummy_fn(), "Too many nodes");
        assert!(!data.has_results());
        assert_eq!(data.message(), Some("Too many nodes"));
    }

    #[test]
    fn fgdata_contains_address() {
        let graph = FunctionGraph::new(dummy_fn());
        let data = FGData::new(dummy_fn(), graph);
        assert!(data.contains_address(Address::new(0x1050)));
        assert!(!data.contains_address(Address::new(0x2000)));
    }

    // -- GroupHistoryInfo tests ----------------------------------------------

    #[test]
    fn group_history_basic() {
        let info = GroupHistoryInfo::new(
            "Loop body",
            vec![Address::new(0x1000), Address::new(0x1010)],
        );
        assert_eq!(info.vertex_count(), 2);
        assert_eq!(info.group_description, "Loop body");
    }

    #[test]
    fn group_history_update_description() {
        let mut info = GroupHistoryInfo::new("Old", vec![]);
        info.set_group_description("New");
        assert_eq!(info.group_description, "New");
    }

    // -- VertexInfo tests ----------------------------------------------------

    #[test]
    fn vertex_info_create() {
        let vi = VertexInfo::new(Address::new(0x1000), FGVertexType::Entry, 10.0, 20.0);
        assert_eq!(vi.address, Address::new(0x1000));
        assert_eq!(vi.vertex_type, FGVertexType::Entry);
        assert_eq!(vi.x, 10.0);
        assert_eq!(vi.y, 20.0);
    }
}
