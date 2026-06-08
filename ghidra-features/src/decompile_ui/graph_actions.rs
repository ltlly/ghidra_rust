//! PCode graph actions -- Rust port of the graph-related classes in
//! `ghidra.app.plugin.core.decompile.actions`.
//!
//! This module models:
//!
//! * [`PCodeCfgGraphType`] -- graph type descriptor for the PCode
//!   control-flow graph.
//! * [`PCodeDfgGraphType`] -- graph type descriptor for the PCode
//!   data-flow graph.
//! * [`PCodeDfgDisplayOptions`] -- display options (vertex/edge colors
//!   and shapes) for the DFG.
//! * [`PCodeCfgGraphSubType`] -- whether the CFG graph is a full
//!   control-flow graph or a combined AST/CFG.
//! * [`PCodeCfgAction`] -- user action that launches the CFG graph.
//! * [`PCodeDfgAction`] -- user action that launches the DFG graph.
//! * [`PCodeCfgDisplayListener`] -- listener that maps graph vertices
//!   to program addresses for the CFG.
//! * [`PCodeDfgDisplayListener`] -- listener that maps graph vertices
//!   to program addresses for the DFG.
//!
//! # Architecture
//!
//! ```text
//! PCodeCfgAction ──► launches PCodeCfgGraphTask
//! PCodeDfgAction ──► launches PCodeDfgGraphTask
//!
//! PCodeCfgGraphType / PCodeDfgGraphType
//!   describe vertex and edge types for the graph service.
//!
//! PCodeDfgDisplayOptions
//!   configures colours, shapes, and layout for the DFG.
//!
//! PCodeCfgDisplayListener / PCodeDfgDisplayListener
//!   bridge between graph display and program addresses.
//! ```

use ghidra_core::addr::Address;

// ---------------------------------------------------------------------------
// Graph type constants -- vertex types
// ---------------------------------------------------------------------------

/// Vertex type identifiers for the PCode DFG.
///
/// Each variant names a category of node in the data-flow graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DfgVertexType {
    /// Catch-all vertex type.
    Default,
    /// A constant value (immediate).
    Constant,
    /// A CPU register varnode.
    Register,
    /// A temporary / unique varnode.
    Unique,
    /// A persistent (RAM) varnode.
    Persistent,
    /// A varnode tied to a specific address.
    AddressTied,
    /// A PCode operation node.
    Op,
}

impl DfgVertexType {
    /// Return all vertex types in display order.
    pub fn all() -> &'static [DfgVertexType] {
        &[
            DfgVertexType::Default,
            DfgVertexType::Constant,
            DfgVertexType::Register,
            DfgVertexType::Unique,
            DfgVertexType::Persistent,
            DfgVertexType::AddressTied,
            DfgVertexType::Op,
        ]
    }

    /// Human-readable label for the vertex type.
    pub fn label(self) -> &'static str {
        match self {
            DfgVertexType::Default => "Default",
            DfgVertexType::Constant => "Constant",
            DfgVertexType::Register => "Register",
            DfgVertexType::Unique => "Unique",
            DfgVertexType::Persistent => "Persistent",
            DfgVertexType::AddressTied => "Address Tied",
            DfgVertexType::Op => "Op",
        }
    }
}

// ---------------------------------------------------------------------------
// Graph type constants -- edge types
// ---------------------------------------------------------------------------

/// Edge type identifiers for the PCode DFG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DfgEdgeType {
    /// Catch-all edge type.
    Default,
    /// An edge within a single basic block.
    WithinBlock,
    /// An edge that crosses basic-block boundaries.
    BetweenBlocks,
}

impl DfgEdgeType {
    /// Return all edge types in display order.
    pub fn all() -> &'static [DfgEdgeType] {
        &[
            DfgEdgeType::Default,
            DfgEdgeType::WithinBlock,
            DfgEdgeType::BetweenBlocks,
        ]
    }

    /// Human-readable label for the edge type.
    pub fn label(self) -> &'static str {
        match self {
            DfgEdgeType::Default => "Default",
            DfgEdgeType::WithinBlock => "Within Block",
            DfgEdgeType::BetweenBlocks => "Between Blocks",
        }
    }
}

// ---------------------------------------------------------------------------
// PCodeCfgGraphType
// ---------------------------------------------------------------------------

/// Graph type descriptor for the PCode control-flow graph.
///
/// Mirrors `PCodeCfgGraphType` which extends `ProgramGraphType` with
/// the name `"Pcode"` and description `"Graph to show pcode for function"`.
#[derive(Debug, Clone)]
pub struct PCodeCfgGraphType {
    name: String,
    description: String,
}

impl PCodeCfgGraphType {
    /// Create a new CFG graph type descriptor.
    pub fn new() -> Self {
        Self {
            name: "Pcode".into(),
            description: "Graph to show pcode for function".into(),
        }
    }

    /// The graph type name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The graph type description.
    pub fn description(&self) -> &str {
        &self.description
    }
}

impl Default for PCodeCfgGraphType {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PCodeDfgGraphType
// ---------------------------------------------------------------------------

/// Graph type descriptor for the PCode data-flow graph.
///
/// Mirrors `PCodeDfgGraphType` which extends `GraphType` with vertex
/// and edge type definitions for the AST/DFG graph.
#[derive(Debug, Clone)]
pub struct PCodeDfgGraphType {
    name: String,
    description: String,
    vertex_types: Vec<String>,
    edge_types: Vec<String>,
}

impl PCodeDfgGraphType {
    /// Create a new DFG graph type descriptor.
    pub fn new() -> Self {
        Self {
            name: "AST Graph".into(),
            description: "Displays an AST graph for the current function".into(),
            vertex_types: DfgVertexType::all().iter().map(|v| v.label().to_string()).collect(),
            edge_types: DfgEdgeType::all().iter().map(|e| e.label().to_string()).collect(),
        }
    }

    /// The graph type name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The graph type description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// The registered vertex types.
    pub fn vertex_types(&self) -> &[String] {
        &self.vertex_types
    }

    /// The registered edge types.
    pub fn edge_types(&self) -> &[String] {
        &self.edge_types
    }
}

impl Default for PCodeDfgGraphType {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Graph label position and layout
// ---------------------------------------------------------------------------

/// Where vertex labels are drawn relative to the vertex shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphLabelPosition {
    North,
    South,
    East,
    West,
    Center,
}

impl Default for GraphLabelPosition {
    fn default() -> Self {
        GraphLabelPosition::South
    }
}

/// Named layout algorithms for graph display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutAlgorithmName {
    /// The Sugiyama / min-cross layout.
    MinCrossCoffmanGraham,
    /// A hierarchical (top-down) layout.
    Hierarchical,
    /// Circular layout.
    Circular,
    /// Force-directed layout.
    ForceDirected,
}

impl Default for LayoutAlgorithmName {
    fn default() -> Self {
        LayoutAlgorithmName::MinCrossCoffmanGraham
    }
}

/// Vertex shape for rendering graph nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VertexShape {
    Ellipse,
    Rectangle,
    RoundedRectangle,
    Diamond,
    Hexagon,
    Octagon,
}

impl Default for VertexShape {
    fn default() -> Self {
        VertexShape::Ellipse
    }
}

// ---------------------------------------------------------------------------
// PCodeDfgDisplayOptions
// ---------------------------------------------------------------------------

/// Display options for the PCode data-flow graph.
///
/// Configures vertex/edge colours, shapes, layout algorithm, and
/// rendering parameters.  Mirrors `PCodeDfgDisplayOptions`.
#[derive(Debug, Clone)]
pub struct PCodeDfgDisplayOptions {
    /// The shape attribute key used to override individual vertex shapes.
    pub shape_attribute: String,
    /// Default vertex shape.
    default_vertex_shape: VertexShape,
    /// Default vertex background colour (theme key).
    default_vertex_color: String,
    /// Default edge background colour (theme key).
    default_edge_color: String,
    /// Selected vertex background colour (theme key).
    vertex_selection_color: String,
    /// Selected edge background colour (theme key).
    edge_selection_color: String,
    /// The default layout algorithm.
    layout_algorithm: LayoutAlgorithmName,
    /// Whether to use icons on vertices.
    uses_icons: bool,
    /// Arrow length in pixels.
    arrow_length: u32,
    /// Label position relative to vertex.
    label_position: GraphLabelPosition,
    /// Maximum number of nodes before the graph refuses to render.
    max_node_count: usize,
    /// Per-vertex-type shape overrides.
    vertex_type_shapes: Vec<(DfgVertexType, VertexShape)>,
    /// Per-vertex-type colour overrides (theme keys).
    vertex_type_colors: Vec<(DfgVertexType, String)>,
    /// Per-edge-type colour overrides (theme keys).
    edge_type_colors: Vec<(DfgEdgeType, String)>,
}

impl PCodeDfgDisplayOptions {
    /// Create display options with default values (matching the Java
    /// `initializeDefaults()` method).
    pub fn new() -> Self {
        let mut opts = Self {
            shape_attribute: "Shape".into(),
            default_vertex_shape: VertexShape::Ellipse,
            default_vertex_color: "color.bg.decompiler.pcode.dfg.vertex.default".into(),
            default_edge_color: "color.bg.decompiler.pcode.dfg.edge.default".into(),
            vertex_selection_color: "color.bg.decompiler.pcode.dfg.vertex.selected".into(),
            edge_selection_color: "color.bg.decompiler.pcode.dfg.edge.selected".into(),
            layout_algorithm: LayoutAlgorithmName::MinCrossCoffmanGraham,
            uses_icons: false,
            arrow_length: 15,
            label_position: GraphLabelPosition::South,
            max_node_count: 1000,
            vertex_type_shapes: Vec::new(),
            vertex_type_colors: Vec::new(),
            edge_type_colors: Vec::new(),
        };
        opts.initialize_defaults();
        opts
    }

    /// Set up the default vertex/edge type configurations.
    fn initialize_defaults(&mut self) {
        // Vertex types
        let vertex_colors: &[(DfgVertexType, &str)] = &[
            (DfgVertexType::Default, "color.bg.decompiler.pcode.dfg.vertex.default"),
            (DfgVertexType::Constant, "color.bg.decompiler.pcode.dfg.vertex.constant"),
            (DfgVertexType::Register, "color.bg.decompiler.pcode.dfg.vertex.register"),
            (DfgVertexType::Unique, "color.bg.decompiler.pcode.dfg.vertex.unique"),
            (DfgVertexType::Persistent, "color.bg.decompiler.pcode.dfg.vertex.persistent"),
            (DfgVertexType::AddressTied, "color.bg.decompiler.pcode.dfg.vertex.address.tied"),
            (DfgVertexType::Op, "color.bg.decompiler.pcode.dfg.vertex.op"),
        ];
        for &(vt, color) in vertex_colors {
            self.vertex_type_shapes.push((vt, VertexShape::Ellipse));
            self.vertex_type_colors.push((vt, color.into()));
        }

        // Edge types
        let edge_colors: &[(DfgEdgeType, &str)] = &[
            (DfgEdgeType::Default, "color.bg.decompiler.pcode.dfg.edge.default"),
            (DfgEdgeType::WithinBlock, "color.bg.decompiler.pcode.dfg.edge.within.block"),
            (DfgEdgeType::BetweenBlocks, "color.bg.decompiler.pcode.dfg.edge.between.blocks"),
        ];
        for &(et, color) in edge_colors {
            self.edge_type_colors.push((et, color.into()));
        }
    }

    /// Get the shape override for a vertex type, if any.
    pub fn vertex_shape(&self, vt: DfgVertexType) -> VertexShape {
        self.vertex_type_shapes
            .iter()
            .find(|(v, _)| *v == vt)
            .map(|(_, s)| *s)
            .unwrap_or(self.default_vertex_shape)
    }

    /// Get the colour theme key for a vertex type.
    pub fn vertex_color(&self, vt: DfgVertexType) -> &str {
        self.vertex_type_colors
            .iter()
            .find(|(v, _)| *v == vt)
            .map(|(_, c)| c.as_str())
            .unwrap_or(&self.default_vertex_color)
    }

    /// Get the colour theme key for an edge type.
    pub fn edge_color(&self, et: DfgEdgeType) -> &str {
        self.edge_type_colors
            .iter()
            .find(|(e, _)| *e == et)
            .map(|(_, c)| c.as_str())
            .unwrap_or(&self.default_edge_color)
    }

    /// The default layout algorithm.
    pub fn layout_algorithm(&self) -> LayoutAlgorithmName {
        self.layout_algorithm
    }

    /// Maximum node count before the graph refuses to render.
    pub fn max_node_count(&self) -> usize {
        self.max_node_count
    }

    /// Arrow length in pixels.
    pub fn arrow_length(&self) -> u32 {
        self.arrow_length
    }

    /// Whether the graph uses icons.
    pub fn uses_icons(&self) -> bool {
        self.uses_icons
    }

    /// The label position.
    pub fn label_position(&self) -> GraphLabelPosition {
        self.label_position
    }
}

impl Default for PCodeDfgDisplayOptions {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PCodeCfgGraphSubType
// ---------------------------------------------------------------------------

/// Sub-type of the PCode CFG graph.
///
/// Determines whether the graph is a pure control-flow graph or a
/// combined AST/CFG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PCodeCfgGraphSubType {
    /// A standard control-flow graph of basic blocks.
    ControlFlowGraph,
    /// A combined AST/CFG that includes PCode op nodes.
    CombinedGraph,
}

impl Default for PCodeCfgGraphSubType {
    fn default() -> Self {
        Self::ControlFlowGraph
    }
}

// ---------------------------------------------------------------------------
// PCodeCfgAction
// ---------------------------------------------------------------------------

/// Action: Launch the PCode control-flow graph for the current function.
///
/// Mirrors `PCodeCfgAction` which extends `AbstractDecompilerAction`.
#[derive(Debug, Default)]
pub struct PCodeCfgAction {
    /// The graph sub-type to produce.
    pub graph_sub_type: PCodeCfgGraphSubType,
    /// Whether to reuse an existing graph window.
    pub reuse_graph: bool,
    /// Maximum code lines displayed per block.
    pub code_limit_per_block: usize,
}

impl PCodeCfgAction {
    /// Create a new CFG action with default settings.
    pub fn new() -> Self {
        Self {
            graph_sub_type: PCodeCfgGraphSubType::ControlFlowGraph,
            reuse_graph: false,
            code_limit_per_block: 10,
        }
    }

    /// The action name.
    pub fn name(&self) -> &str {
        "Graph PCode Control Flow"
    }

    /// Human-readable description.
    pub fn description(&self) -> &str {
        "Display the PCode control-flow graph for the current function"
    }

    /// Menu bar path.
    pub fn menu_path(&self) -> &[&str] {
        &["Graph Control Flow"]
    }

    /// Menu group.
    pub fn menu_group(&self) -> &str {
        "graph"
    }

    /// Whether the action is enabled.  Requires a non-null function in
    /// the context.
    pub fn is_enabled(&self, has_function: bool) -> bool {
        has_function
    }

    /// Execute the action.  Returns a description of the graph task
    /// that would be launched.
    pub fn execute(&self, function_entry: Address) -> String {
        format!(
            "Launching PCode CFG graph at 0x{:x} (sub_type={:?}, reuse={}, limit={})",
            function_entry.offset,
            self.graph_sub_type,
            self.reuse_graph,
            self.code_limit_per_block,
        )
    }
}

// ---------------------------------------------------------------------------
// PCodeDfgAction
// ---------------------------------------------------------------------------

/// Action: Launch the PCode data-flow graph for the current function.
///
/// Mirrors `PCodeDfgAction` which extends `AbstractDecompilerAction`.
#[derive(Debug, Default)]
pub struct PCodeDfgAction;

impl PCodeDfgAction {
    /// Create a new DFG action.
    pub fn new() -> Self {
        Self
    }

    /// The action name.
    pub fn name(&self) -> &str {
        "Graph PCode Data Flow"
    }

    /// Human-readable description.
    pub fn description(&self) -> &str {
        "Display the PCode data-flow graph for the current function"
    }

    /// Menu bar path.
    pub fn menu_path(&self) -> &[&str] {
        &["Graph Data Flow"]
    }

    /// Menu group.
    pub fn menu_group(&self) -> &str {
        "graph"
    }

    /// Whether the action is enabled.
    pub fn is_enabled(&self, has_function: bool) -> bool {
        has_function
    }

    /// Execute the action.  Returns a description of the graph task
    /// that would be launched.
    pub fn execute(&self, function_entry: Address) -> String {
        format!(
            "Launching PCode DFG graph at 0x{:x}",
            function_entry.offset,
        )
    }
}

// ---------------------------------------------------------------------------
// PCodeCfgDisplayListener
// ---------------------------------------------------------------------------

/// A basic-block reference used by the CFG display listener.
///
/// Mirrors the address range of a `PcodeBlockBasic`.
#[derive(Debug, Clone)]
pub struct BasicBlockInfo {
    /// The 0-based index of this block.
    pub index: usize,
    /// Start address of the block.
    pub start: Address,
    /// End address of the block (inclusive).
    pub end: Address,
}

/// Listener that maps graph vertices to program addresses for the
/// PCode CFG.
///
/// Mirrors `PCodeCfgDisplayListener` which extends
/// `AddressBasedGraphDisplayListener`.
#[derive(Debug, Clone)]
pub struct PCodeCfgDisplayListener {
    /// The basic blocks of the function being graphed.
    blocks: Vec<BasicBlockInfo>,
    /// The graph sub-type this listener was created for.
    graph_type: PCodeCfgGraphSubType,
}

impl PCodeCfgDisplayListener {
    /// Create a new listener for the given basic blocks.
    pub fn new(blocks: Vec<BasicBlockInfo>, graph_type: PCodeCfgGraphSubType) -> Self {
        Self { blocks, graph_type }
    }

    /// Given a set of selected addresses, return the vertex IDs of
    /// blocks whose address range intersects the selection.
    ///
    /// Returns `None` if the graph type is not `ControlFlowGraph`.
    pub fn get_vertices_for_selection(
        &self,
        sel_start: Address,
        sel_end: Address,
    ) -> Option<Vec<String>> {
        if self.graph_type != PCodeCfgGraphSubType::ControlFlowGraph {
            return None;
        }
        let mut ids = Vec::new();
        for block in &self.blocks {
            if block.start.offset <= sel_end.offset && block.end.offset >= sel_start.offset {
                ids.push(block.index.to_string());
            }
        }
        Some(ids)
    }

    /// Given a set of vertex IDs, return the union of their address
    /// ranges.
    ///
    /// Returns `None` if the graph type is not `ControlFlowGraph`.
    pub fn get_addresses_for_vertices(&self, vertex_ids: &[String]) -> Option<Vec<(Address, Address)>> {
        if self.graph_type != PCodeCfgGraphSubType::ControlFlowGraph {
            return None;
        }
        let mut ranges = Vec::new();
        for id in vertex_ids {
            if let Ok(index) = id.parse::<usize>() {
                if let Some(block) = self.blocks.iter().find(|b| b.index == index) {
                    ranges.push((block.start, block.end));
                }
            }
        }
        Some(ranges)
    }

    /// Given an address, return the vertex ID of the block that
    /// contains it.
    ///
    /// Returns `None` if no block contains the address or the graph
    /// type is not `ControlFlowGraph`.
    pub fn get_vertex_id_for_address(&self, address: Address) -> Option<String> {
        if self.graph_type != PCodeCfgGraphSubType::ControlFlowGraph {
            return None;
        }
        for block in &self.blocks {
            if address.offset >= block.start.offset && address.offset <= block.end.offset {
                return Some(block.index.to_string());
            }
        }
        None
    }

    /// Given a vertex ID, return the start address of the
    /// corresponding block.
    pub fn get_address_for_vertex(&self, vertex_id: &str) -> Option<Address> {
        let index = vertex_id.parse::<usize>().ok()?;
        self.blocks.iter().find(|b| b.index == index).map(|b| b.start)
    }
}

// ---------------------------------------------------------------------------
// PCodeDfgDisplayListener
// ---------------------------------------------------------------------------

/// Listener that maps graph vertices to program addresses for the
/// PCode DFG.
///
/// Mirrors `PCodeDfgDisplayListener` which extends
/// `AddressBasedGraphDisplayListener`.
///
/// In the DFG, vertex IDs have the format `"<address>:<suffix>"` where
/// the address portion is parsed to produce a program address.
#[derive(Debug, Clone)]
pub struct PCodeDfgDisplayListener;

impl PCodeDfgDisplayListener {
    /// Create a new DFG display listener.
    pub fn new() -> Self {
        Self
    }

    /// Extract the address portion from a DFG vertex ID.
    ///
    /// The vertex ID format is `"<hex_addr>:<rest> ..."`.  The method
    /// finds the first colon, then takes the substring before the first
    /// space as the address string.
    pub fn get_address_for_vertex(vertex_id: &str) -> Option<Address> {
        // Format: "0xADDR:V0 description..."
        let colon = vertex_id.find(':')?;
        let addr_str = &vertex_id[..colon];
        let offset = u64::from_str_radix(addr_str.trim_start_matches("0x"), 16).ok()?;
        Some(Address::new(offset))
    }

    /// Given a set of vertex IDs, return the union of their addresses.
    pub fn get_addresses_for_vertices(vertex_ids: &[String]) -> Vec<Address> {
        vertex_ids
            .iter()
            .filter_map(|id| Self::get_address_for_vertex(id))
            .collect()
    }
}

impl Default for PCodeDfgDisplayListener {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Graph types --

    #[test]
    fn test_cfg_graph_type() {
        let gt = PCodeCfgGraphType::new();
        assert_eq!(gt.name(), "Pcode");
        assert!(gt.description().contains("pcode"));
    }

    #[test]
    fn test_dfg_graph_type() {
        let gt = PCodeDfgGraphType::new();
        assert_eq!(gt.name(), "AST Graph");
        assert_eq!(gt.vertex_types().len(), 7);
        assert_eq!(gt.edge_types().len(), 3);
    }

    #[test]
    fn test_dfg_vertex_type_labels() {
        assert_eq!(DfgVertexType::Constant.label(), "Constant");
        assert_eq!(DfgVertexType::Op.label(), "Op");
    }

    #[test]
    fn test_dfg_edge_type_labels() {
        assert_eq!(DfgEdgeType::WithinBlock.label(), "Within Block");
        assert_eq!(DfgEdgeType::BetweenBlocks.label(), "Between Blocks");
    }

    // -- Display options --

    #[test]
    fn test_dfg_display_options_defaults() {
        let opts = PCodeDfgDisplayOptions::new();
        assert_eq!(opts.shape_attribute, "Shape");
        assert_eq!(opts.max_node_count(), 1000);
        assert_eq!(opts.arrow_length(), 15);
        assert!(!opts.uses_icons());
        assert_eq!(opts.label_position(), GraphLabelPosition::South);
        assert_eq!(opts.layout_algorithm(), LayoutAlgorithmName::MinCrossCoffmanGraham);
    }

    #[test]
    fn test_dfg_display_options_vertex_shape() {
        let opts = PCodeDfgDisplayOptions::new();
        assert_eq!(opts.vertex_shape(DfgVertexType::Constant), VertexShape::Ellipse);
        assert_eq!(opts.vertex_shape(DfgVertexType::Op), VertexShape::Ellipse);
    }

    #[test]
    fn test_dfg_display_options_vertex_color() {
        let opts = PCodeDfgDisplayOptions::new();
        assert!(opts.vertex_color(DfgVertexType::Register).contains("register"));
        assert!(opts.vertex_color(DfgVertexType::Op).contains("op"));
    }

    #[test]
    fn test_dfg_display_options_edge_color() {
        let opts = PCodeDfgDisplayOptions::new();
        assert!(opts.edge_color(DfgEdgeType::WithinBlock).contains("within.block"));
        assert!(opts.edge_color(DfgEdgeType::BetweenBlocks).contains("between.blocks"));
    }

    // -- Actions --

    #[test]
    fn test_cfg_action_new() {
        let action = PCodeCfgAction::new();
        assert_eq!(action.name(), "Graph PCode Control Flow");
        assert!(action.description().contains("control"));
        assert_eq!(action.menu_path(), &["Graph Control Flow"]);
        assert_eq!(action.menu_group(), "graph");
    }

    #[test]
    fn test_cfg_action_enabled() {
        let action = PCodeCfgAction::new();
        assert!(action.is_enabled(true));
        assert!(!action.is_enabled(false));
    }

    #[test]
    fn test_cfg_action_execute() {
        let action = PCodeCfgAction::new();
        let result = action.execute(Address::new(0x4000));
        assert!(result.contains("0x4000"));
        assert!(result.contains("CFG"));
    }

    #[test]
    fn test_cfg_action_custom_settings() {
        let action = PCodeCfgAction {
            graph_sub_type: PCodeCfgGraphSubType::CombinedGraph,
            reuse_graph: true,
            code_limit_per_block: 20,
        };
        assert_eq!(action.graph_sub_type, PCodeCfgGraphSubType::CombinedGraph);
        assert!(action.reuse_graph);
        assert_eq!(action.code_limit_per_block, 20);
    }

    #[test]
    fn test_dfg_action_new() {
        let action = PCodeDfgAction::new();
        assert_eq!(action.name(), "Graph PCode Data Flow");
        assert!(action.description().contains("data"));
        assert_eq!(action.menu_path(), &["Graph Data Flow"]);
    }

    #[test]
    fn test_dfg_action_enabled() {
        let action = PCodeDfgAction::new();
        assert!(action.is_enabled(true));
        assert!(!action.is_enabled(false));
    }

    #[test]
    fn test_dfg_action_execute() {
        let action = PCodeDfgAction::new();
        let result = action.execute(Address::new(0x8000));
        assert!(result.contains("0x8000"));
        assert!(result.contains("DFG"));
    }

    // -- CFG display listener --

    fn make_test_blocks() -> Vec<BasicBlockInfo> {
        vec![
            BasicBlockInfo { index: 0, start: Address::new(0x1000), end: Address::new(0x101f) },
            BasicBlockInfo { index: 1, start: Address::new(0x1020), end: Address::new(0x103f) },
            BasicBlockInfo { index: 2, start: Address::new(0x1040), end: Address::new(0x105f) },
        ]
    }

    #[test]
    fn test_cfg_listener_vertices_for_selection() {
        let listener = PCodeCfgDisplayListener::new(
            make_test_blocks(),
            PCodeCfgGraphSubType::ControlFlowGraph,
        );
        // Select range that intersects block 1
        let ids = listener.get_vertices_for_selection(Address::new(0x1030), Address::new(0x1035));
        assert_eq!(ids, Some(vec!["1".to_string()]));
    }

    #[test]
    fn test_cfg_listener_vertices_for_selection_multiple() {
        let listener = PCodeCfgDisplayListener::new(
            make_test_blocks(),
            PCodeCfgGraphSubType::ControlFlowGraph,
        );
        // Select range that intersects blocks 0 and 1
        let ids = listener.get_vertices_for_selection(Address::new(0x1010), Address::new(0x1025));
        assert_eq!(ids, Some(vec!["0".to_string(), "1".to_string()]));
    }

    #[test]
    fn test_cfg_listener_vertices_wrong_type() {
        let listener = PCodeCfgDisplayListener::new(
            make_test_blocks(),
            PCodeCfgGraphSubType::CombinedGraph,
        );
        assert!(listener.get_vertices_for_selection(Address::new(0x1000), Address::new(0x1010)).is_none());
    }

    #[test]
    fn test_cfg_listener_addresses_for_vertices() {
        let listener = PCodeCfgDisplayListener::new(
            make_test_blocks(),
            PCodeCfgGraphSubType::ControlFlowGraph,
        );
        let ranges = listener.get_addresses_for_vertices(&["0".to_string(), "2".to_string()]);
        assert_eq!(ranges.as_ref().unwrap().len(), 2);
        assert_eq!(ranges.as_ref().unwrap()[0].0, Address::new(0x1000));
        assert_eq!(ranges.as_ref().unwrap()[1].1, Address::new(0x105f));
    }

    #[test]
    fn test_cfg_listener_vertex_id_for_address() {
        let listener = PCodeCfgDisplayListener::new(
            make_test_blocks(),
            PCodeCfgGraphSubType::ControlFlowGraph,
        );
        assert_eq!(
            listener.get_vertex_id_for_address(Address::new(0x1005)),
            Some("0".to_string()),
        );
        assert_eq!(
            listener.get_vertex_id_for_address(Address::new(0x1045)),
            Some("2".to_string()),
        );
        // Outside all blocks
        assert!(listener.get_vertex_id_for_address(Address::new(0x2000)).is_none());
    }

    #[test]
    fn test_cfg_listener_address_for_vertex() {
        let listener = PCodeCfgDisplayListener::new(
            make_test_blocks(),
            PCodeCfgGraphSubType::ControlFlowGraph,
        );
        assert_eq!(listener.get_address_for_vertex("1"), Some(Address::new(0x1020)));
        assert!(listener.get_address_for_vertex("99").is_none());
        assert!(listener.get_address_for_vertex("abc").is_none());
    }

    // -- DFG display listener --

    #[test]
    fn test_dfg_listener_address_from_vertex() {
        // Vertex ID format: "0x1234:some_suffix rest..."
        let addr = PCodeDfgDisplayListener::get_address_for_vertex("0x4000:V0 op");
        assert_eq!(addr, Some(Address::new(0x4000)));
    }

    #[test]
    fn test_dfg_listener_address_no_space() {
        let addr = PCodeDfgDisplayListener::get_address_for_vertex("badformat");
        assert!(addr.is_none());
    }

    #[test]
    fn test_dfg_listener_addresses_for_vertices() {
        let ids = vec![
            "0x1000:V0 stuff".to_string(),
            "0x2000:V1 more".to_string(),
            "bad".to_string(),
        ];
        let addrs = PCodeDfgDisplayListener::get_addresses_for_vertices(&ids);
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], Address::new(0x1000));
        assert_eq!(addrs[1], Address::new(0x2000));
    }

    // -- Sub types --

    #[test]
    fn test_cfg_graph_sub_types() {
        assert_ne!(
            PCodeCfgGraphSubType::ControlFlowGraph,
            PCodeCfgGraphSubType::CombinedGraph,
        );
    }
}
