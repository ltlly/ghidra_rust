//! PCode graph tasks -- Rust port of the graph-building task classes
//! from `ghidra.app.plugin.core.decompile.actions`.
//!
//! This module provides the background tasks that construct PCode
//! control-flow and data-flow graphs from decompiler output and display
//! them via the graph service.
//!
//! # Architecture
//!
//! ```text
//! PCodeCfgGraphTask          -- builds CFG from basic blocks
//!   ├── create_control_flow_graph()
//!   └── create_data_flow_graph()
//!
//! PCodeDfgGraphTask          -- builds DFG from PCode ops
//!   ├── build_graph()  [overridable]
//!   ├── create_op_vertex()
//!   ├── create_varnode_vertex()
//!   └── get_varnode_vertex()
//!
//! PCodeCombinedGraphTask     -- extends DFG with intra-block CFG edges
//!   └── build_graph()  [override]
//!
//! SelectedPCodeDfgGraphTask  -- DFG filtered to a single address
//!   └── get_pcode_op_iterator()  [override]
//! ```
//!
//! Each task produces an `AttributedGraph` that is handed to the graph
//! display service for rendering.

use std::collections::{HashMap, HashSet};

use ghidra_core::addr::Address;

use super::graph_actions::{
    DfgEdgeType, DfgVertexType, PCodeCfgGraphSubType, PCodeCfgGraphType, PCodeDfgGraphType,
    VertexShape,
};

// ---------------------------------------------------------------------------
// PCode opcode model
// ---------------------------------------------------------------------------

/// Lightweight model of a PCode opcode.
///
/// Mirrors the integer opcode constants from `PcodeOp` in Ghidra.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GraphPcodeOpcode {
    Copy,
    Load,
    Store,
    Branch,
    BranchInd,
    CBranch,
    Call,
    CallInd,
    Return,
    IntAdd,
    IntSub,
    IntMul,
    IntDiv,
    IntSLess,
    IntLess,
    IntAnd,
    IntOr,
    IntXor,
    IntLeft,
    IntRight,
    IntSRight,
    IntEqual,
    IntNotEqual,
    Indirect,
    /// Catch-all for opcodes not explicitly listed.
    Other(u16),
}

impl GraphPcodeOpcode {
    /// Return the mnemonic string for this opcode.
    pub fn mnemonic(self) -> &'static str {
        match self {
            GraphPcodeOpcode::Copy => "COPY",
            GraphPcodeOpcode::Load => "LOAD",
            GraphPcodeOpcode::Store => "STORE",
            GraphPcodeOpcode::Branch => "BRANCH",
            GraphPcodeOpcode::BranchInd => "BRANCHIND",
            GraphPcodeOpcode::CBranch => "CBRANCH",
            GraphPcodeOpcode::Call => "CALL",
            GraphPcodeOpcode::CallInd => "CALLIND",
            GraphPcodeOpcode::Return => "RETURN",
            GraphPcodeOpcode::IntAdd => "INT_ADD",
            GraphPcodeOpcode::IntSub => "INT_SUB",
            GraphPcodeOpcode::IntMul => "INT_MUL",
            GraphPcodeOpcode::IntDiv => "INT_DIV",
            GraphPcodeOpcode::IntSLess => "INT_SLESS",
            GraphPcodeOpcode::IntLess => "INT_LESS",
            GraphPcodeOpcode::IntAnd => "INT_AND",
            GraphPcodeOpcode::IntOr => "INT_OR",
            GraphPcodeOpcode::IntXor => "INT_XOR",
            GraphPcodeOpcode::IntLeft => "INT_LEFT",
            GraphPcodeOpcode::IntRight => "INT_RIGHT",
            GraphPcodeOpcode::IntSRight => "INT_SRIGHT",
            GraphPcodeOpcode::IntEqual => "INT_EQUAL",
            GraphPcodeOpcode::IntNotEqual => "INT_NOTEQUAL",
            GraphPcodeOpcode::Indirect => "INDIRECT",
            GraphPcodeOpcode::Other(_) => "OTHER",
        }
    }

    /// Whether this opcode is a branch/call/return.
    pub fn is_control_flow(self) -> bool {
        matches!(
            self,
            GraphPcodeOpcode::Branch
                | GraphPcodeOpcode::BranchInd
                | GraphPcodeOpcode::CBranch
                | GraphPcodeOpcode::Call
                | GraphPcodeOpcode::CallInd
                | GraphPcodeOpcode::Return
        )
    }
}

// ---------------------------------------------------------------------------
// Varnode model
// ---------------------------------------------------------------------------

/// The kind of storage a varnode uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VarnodeKind {
    /// A constant (immediate) value.
    Constant,
    /// A CPU register.
    Register,
    /// A temporary / unique varnode.
    Unique,
    /// A persistent (RAM) address.
    Persistent,
    /// An address-tied varnode.
    AddressTied,
    /// A stack-relative varnode.
    Stack,
    /// An input varnode (function parameter).
    Input,
}

/// A lightweight model of a PCode varnode.
///
/// Mirrors `VarnodeAST` from Ghidra.
#[derive(Debug, Clone)]
pub struct GraphVarnode {
    /// Unique ID within the high function.
    pub unique_id: u32,
    /// The address (register, memory, or unique offset).
    pub address: Address,
    /// Size in bytes.
    pub size: u32,
    /// The kind of storage.
    pub kind: VarnodeKind,
    /// The high-level variable name, if known.
    pub high_name: Option<String>,
    /// The display label (computed from address/kind).
    pub label: String,
}

impl GraphVarnode {
    /// Create a new varnode.
    pub fn new(unique_id: u32, address: Address, size: u32, kind: VarnodeKind) -> Self {
        let label = Self::compute_label(address, size, kind, &None);
        Self {
            unique_id,
            address,
            size,
            kind,
            high_name: None,
            label,
        }
    }

    /// Create a varnode with a high-level variable name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.high_name = Some(name.into());
        self.label =
            Self::compute_label(self.address, self.size, self.kind, &self.high_name);
        self
    }

    fn compute_label(
        address: Address,
        size: u32,
        kind: VarnodeKind,
        high_name: &Option<String>,
    ) -> String {
        match kind {
            VarnodeKind::Constant => format!("#{:x}", address.offset),
            VarnodeKind::Unique => format!("u_{:x}", address.offset),
            VarnodeKind::Stack => {
                if let Some(name) = high_name {
                    name.clone()
                } else {
                    let sign = if address.offset as i64 >= 0 { "+" } else { "-" };
                    let abs = (address.offset as i64).unsigned_abs();
                    format!("Stack[{}{:x}]", sign, abs)
                }
            }
            VarnodeKind::Register | VarnodeKind::Input => {
                if let Some(name) = high_name {
                    name.clone()
                } else {
                    format!("R_{:x}", address.offset)
                }
            }
            VarnodeKind::Persistent | VarnodeKind::AddressTied => {
                format!("0x{:x}", address.offset)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PCode op model
// ---------------------------------------------------------------------------

/// A lightweight model of a PCode op (AST node).
///
/// Mirrors `PcodeOpAST` from Ghidra.
#[derive(Debug, Clone)]
pub struct GraphPcodeOp {
    /// The sequence number (address + time).
    pub seq_time: u32,
    /// The opcode.
    pub opcode: GraphPcodeOpcode,
    /// The output varnode, if any.
    pub output: Option<GraphVarnode>,
    /// The input varnodes.
    pub inputs: Vec<GraphVarnode>,
    /// The address of the machine instruction this op belongs to.
    pub address: Address,
    /// The basic block index this op belongs to.
    pub block_index: usize,
}

impl GraphPcodeOp {
    /// Create a new PCode op.
    pub fn new(
        seq_time: u32,
        opcode: GraphPcodeOpcode,
        address: Address,
        block_index: usize,
    ) -> Self {
        Self {
            seq_time,
            opcode,
            output: None,
            inputs: Vec::new(),
            address,
            block_index,
        }
    }

    /// Set the output varnode.
    pub fn with_output(mut self, output: GraphVarnode) -> Self {
        self.output = Some(output);
        self
    }

    /// Add an input varnode.
    pub fn with_input(mut self, input: GraphVarnode) -> Self {
        self.inputs.push(input);
        self
    }

    /// The op key used as a graph vertex ID.
    pub fn op_key(&self) -> String {
        format!("{:x} o {}", self.address.offset, self.seq_time)
    }
}

// ---------------------------------------------------------------------------
// Basic block model
// ---------------------------------------------------------------------------

/// A basic block of PCode ops.
///
/// Mirrors `PcodeBlockBasic` from Ghidra.
#[derive(Debug, Clone)]
pub struct GraphBasicBlock {
    /// The 0-based index of this block.
    pub index: usize,
    /// Start address.
    pub start: Address,
    /// End address (inclusive).
    pub end: Address,
    /// Indices of successor blocks.
    pub successors: Vec<usize>,
    /// Indices of predecessor blocks.
    pub predecessors: Vec<usize>,
    /// The PCode ops in this block.
    pub ops: Vec<GraphPcodeOp>,
}

impl GraphBasicBlock {
    /// Create a new basic block.
    pub fn new(index: usize, start: Address, end: Address) -> Self {
        Self {
            index,
            start,
            end,
            successors: Vec::new(),
            predecessors: Vec::new(),
            ops: Vec::new(),
        }
    }

    /// Whether this block has no predecessors (entry block).
    pub fn is_entry(&self) -> bool {
        self.predecessors.is_empty()
    }

    /// Whether this block has no successors (exit block).
    pub fn is_exit(&self) -> bool {
        self.successors.is_empty()
    }
}

// ---------------------------------------------------------------------------
// AttributedGraph -- the graph produced by tasks
// ---------------------------------------------------------------------------

/// A vertex in the attributed graph.
#[derive(Debug, Clone)]
pub struct GraphVertex {
    /// The vertex ID (unique within the graph).
    pub id: String,
    /// The display label.
    pub label: String,
    /// The vertex type (for coloring/shaping).
    pub vertex_type: String,
    /// The shape override, if any.
    pub shape: Option<VertexShape>,
    /// Additional attributes.
    pub attributes: HashMap<String, String>,
}

impl GraphVertex {
    /// Create a new vertex.
    pub fn new(id: impl Into<String>, label: impl Into<String>, vertex_type: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            vertex_type: vertex_type.into(),
            shape: None,
            attributes: HashMap::new(),
        }
    }

    /// Set an attribute.
    pub fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.attributes.insert(key.into(), value.into());
    }
}

/// An edge in the attributed graph.
#[derive(Debug, Clone)]
pub struct GraphEdge {
    /// Index of the source vertex.
    pub from: usize,
    /// Index of the target vertex.
    pub to: usize,
    /// The edge type (for coloring).
    pub edge_type: String,
}

impl GraphEdge {
    /// Create a new edge.
    pub fn new(from: usize, to: usize, edge_type: impl Into<String>) -> Self {
        Self {
            from,
            to,
            edge_type: edge_type.into(),
        }
    }
}

/// An attributed graph produced by a PCode graph task.
///
/// Contains vertices (operations and varnodes) and edges (data flow
/// and/or control flow).
#[derive(Debug, Clone)]
pub struct AttributedGraph {
    /// The graph name.
    pub name: String,
    /// The vertices.
    pub vertices: Vec<GraphVertex>,
    /// The edges.
    pub edges: Vec<GraphEdge>,
}

impl AttributedGraph {
    /// Create a new empty graph.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            vertices: Vec::new(),
            edges: Vec::new(),
        }
    }

    /// Add a vertex and return its index.
    pub fn add_vertex(
        &mut self,
        id: impl Into<String>,
        label: impl Into<String>,
        vertex_type: impl Into<String>,
    ) -> usize {
        let idx = self.vertices.len();
        self.vertices.push(GraphVertex::new(id, label, vertex_type));
        idx
    }

    /// Add an edge and return its index.
    pub fn add_edge(&mut self, from: usize, to: usize, edge_type: impl Into<String>) -> usize {
        let idx = self.edges.len();
        self.edges.push(GraphEdge::new(from, to, edge_type));
        idx
    }

    /// Find a vertex index by ID.
    pub fn find_vertex(&self, id: &str) -> Option<usize> {
        self.vertices.iter().position(|v| v.id == id)
    }

    /// Get a vertex by index.
    pub fn vertex(&self, index: usize) -> Option<&GraphVertex> {
        self.vertices.get(index)
    }

    /// Get a mutable vertex by index.
    pub fn vertex_mut(&mut self, index: usize) -> Option<&mut GraphVertex> {
        self.vertices.get_mut(index)
    }

    /// Number of vertices.
    pub fn vertex_count(&self) -> usize {
        self.vertices.len()
    }

    /// Number of edges.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }
}

// ---------------------------------------------------------------------------
// GraphTaskResult -- outcome of running a graph task
// ---------------------------------------------------------------------------

/// The result of running a graph task.
#[derive(Debug, Clone)]
pub struct GraphTaskResult {
    /// The produced graph.
    pub graph: AttributedGraph,
    /// A human-readable description.
    pub description: String,
    /// The function name.
    pub function_name: String,
}

// ---------------------------------------------------------------------------
// VarnodeTranslator -- translates varnodes to display strings
// ---------------------------------------------------------------------------

/// Translates varnodes to human-readable strings.
///
/// Mirrors the `translateVarnode()` method in `PCodeCfgGraphTask`.
pub struct VarnodeTranslator;

impl VarnodeTranslator {
    /// Translate a varnode to a display string.
    pub fn translate(vn: &GraphVarnode, use_var_name: bool) -> String {
        match vn.kind {
            VarnodeKind::Constant => format!("#{:x}", vn.address.offset),
            VarnodeKind::Unique => format!("u_{:x}", vn.address.offset),
            VarnodeKind::Register => {
                if let Some(ref name) = vn.high_name {
                    if use_var_name {
                        return name.clone();
                    }
                }
                format!("R_{:x}", vn.address.offset)
            }
            VarnodeKind::Stack => {
                if use_var_name {
                    if let Some(ref name) = vn.high_name {
                        return name.clone();
                    }
                }
                let sign = if vn.address.offset as i64 >= 0 { "+" } else { "-" };
                let abs = (vn.address.offset as i64).unsigned_abs();
                format!("Stack[{}{:x}]", sign, abs)
            }
            VarnodeKind::Input => {
                if let Some(ref name) = vn.high_name {
                    name.clone()
                } else {
                    format!("in_{:x}", vn.address.offset)
                }
            }
            VarnodeKind::Persistent | VarnodeKind::AddressTied => {
                format!("0x{:x}", vn.address.offset)
            }
        }
    }

    /// Format a PCode op mnemonic with optional size suffix.
    pub fn format_op_mnemonic(op: &GraphPcodeOpcode, output_size: Option<u32>) -> String {
        let mut mnemonic = op.mnemonic().to_string();
        if let Some(size) = output_size {
            let suffix = match size {
                1 => Some("b"),
                2 => Some("w"),
                4 => Some("d"),
                8 => Some("q"),
                _ => None,
            };
            if let Some(s) = suffix {
                mnemonic.push('.');
                mnemonic.push_str(s);
            }
        }
        mnemonic
    }

    /// Format a PCode op as a full instruction line.
    pub fn format_op(op: &GraphPcodeOp) -> String {
        let mut buf = String::new();
        if let Some(ref output) = op.output {
            buf.push_str(&Self::translate(output, true));
            buf.push_str(" = ");
        }
        let output_size = op.output.as_ref().map(|o| o.size);
        buf.push_str(&Self::format_op_mnemonic(&op.opcode, output_size));
        for (i, input) in op.inputs.iter().enumerate() {
            if i != 0 {
                buf.push(',');
            }
            buf.push(' ');
            buf.push_str(&Self::translate(input, true));
        }
        buf
    }
}

// ---------------------------------------------------------------------------
// PCodeCfgGraphTask -- builds CFG from basic blocks
// ---------------------------------------------------------------------------

/// Task to create a PCode control flow graph based on decompiler output.
///
/// Mirrors `PCodeCfgGraphTask` from the Java source.  The task iterates
/// over basic blocks and their PCode ops, building an `AttributedGraph`
/// that represents either a control-flow graph or a data-flow graph.
#[derive(Debug)]
pub struct PCodeCfgGraphTask {
    /// The function name.
    function_name: String,
    /// The basic blocks of the function.
    blocks: Vec<GraphBasicBlock>,
    /// The graph sub-type (CFG or data-flow).
    graph_sub_type: PCodeCfgGraphSubType,
    /// Maximum code lines displayed per block.
    code_limit_per_block: usize,
    /// The current unique number for generating vertex IDs.
    unique_num: u32,
}

impl PCodeCfgGraphTask {
    /// Create a new CFG graph task.
    pub fn new(
        function_name: impl Into<String>,
        blocks: Vec<GraphBasicBlock>,
        graph_sub_type: PCodeCfgGraphSubType,
        code_limit_per_block: usize,
    ) -> Self {
        Self {
            function_name: function_name.into(),
            blocks,
            graph_sub_type,
            code_limit_per_block,
            unique_num: 0,
        }
    }

    /// Run the task and produce a graph result.
    pub fn run(&mut self) -> GraphTaskResult {
        let mut graph = AttributedGraph::new("PCode Graph");

        match self.graph_sub_type {
            PCodeCfgGraphSubType::ControlFlowGraph => {
                self.create_control_flow_graph(&mut graph);
            }
            PCodeCfgGraphSubType::CombinedGraph => {
                self.create_data_flow_graph(&mut graph);
            }
        }

        let description = match self.graph_sub_type {
            PCodeCfgGraphSubType::ControlFlowGraph => {
                format!("AST Control Flow for {}", self.function_name)
            }
            PCodeCfgGraphSubType::CombinedGraph => {
                format!("AST Data Flow for {}", self.function_name)
            }
        };

        GraphTaskResult {
            graph,
            description,
            function_name: self.function_name.clone(),
        }
    }

    /// Build a control-flow graph from basic blocks.
    fn create_control_flow_graph(&mut self, graph: &mut AttributedGraph) {
        // First, create all block vertices.
        let blocks = self.blocks.clone();
        let limit = self.code_limit_per_block;
        let block_vertex_indices: Vec<usize> = blocks
            .iter()
            .map(|block| {
                let key = block.index.to_string();
                let label = Self::format_block_label_static(block, limit);
                let vertex_type = Self::block_vertex_type_static(block);
                graph.add_vertex(key, label, vertex_type)
            })
            .collect();

        // Then, add edges between blocks.
        for block in &blocks {
            let from_idx = block_vertex_indices[block.index];
            for &succ_idx in &block.successors {
                if succ_idx < block_vertex_indices.len() {
                    let to_idx = block_vertex_indices[succ_idx];
                    graph.add_edge(from_idx, to_idx, "CFG");
                }
            }
        }
    }

    /// Build a data-flow graph from PCode ops.
    fn create_data_flow_graph(&mut self, graph: &mut AttributedGraph) {
        let mut varnode_vertices: HashMap<String, usize> = HashMap::new();
        let blocks = self.blocks.clone();

        for block in &blocks {
            for op in &block.ops {
                if op.opcode == GraphPcodeOpcode::Indirect {
                    continue;
                }
                let op_idx = Self::get_or_create_op_vertex_static(graph, op);

                // Process inputs.
                let start = if (op.opcode == GraphPcodeOpcode::Load
                    || op.opcode == GraphPcodeOpcode::Store)
                    && !op.inputs.is_empty()
                {
                    1
                } else if op.opcode == GraphPcodeOpcode::Indirect && op.inputs.len() > 1 {
                    1
                } else {
                    0
                };

                for i in start..op.inputs.len() {
                    let vn = &op.inputs[i];
                    let vn_idx = Self::get_or_create_varnode_vertex_static(graph, vn, &mut varnode_vertices);
                    graph.add_edge(vn_idx, op_idx, "data");
                }

                // Process output.
                if let Some(ref output) = op.output {
                    let out_idx =
                        Self::get_or_create_varnode_vertex_static(graph, output, &mut varnode_vertices);
                    graph.add_edge(op_idx, out_idx, "data");
                }
            }
        }
    }

    fn get_or_create_op_vertex_static(
        graph: &mut AttributedGraph,
        op: &GraphPcodeOp,
    ) -> usize {
        let key = format!("O_{}", op.seq_time);
        if let Some(idx) = graph.find_vertex(&key) {
            return idx;
        }

        let mnemonic = VarnodeTranslator::format_op_mnemonic(
            &op.opcode,
            op.output.as_ref().map(|o| o.size),
        );
        let vertex_type = Self::op_vertex_type_static(&op.opcode);
        graph.add_vertex(key, mnemonic, vertex_type)
    }

    fn get_or_create_varnode_vertex_static(
        graph: &mut AttributedGraph,
        vn: &GraphVarnode,
        cache: &mut HashMap<String, usize>,
    ) -> usize {
        let key = format!("V_{}", vn.unique_id);
        if let Some(&idx) = cache.get(&key) {
            return idx;
        }

        let label = if let Some(ref name) = vn.high_name {
            format!("{}: {}", name, VarnodeTranslator::translate(vn, false))
        } else {
            VarnodeTranslator::translate(vn, false)
        };
        let vertex_type = Self::varnode_vertex_type_static(vn);
        let idx = graph.add_vertex(key.clone(), label, vertex_type);
        cache.insert(key, idx);
        idx
    }

    fn format_block_label_static(block: &GraphBasicBlock, limit: usize) -> String {
        let mut buf = String::new();
        let mut count = 0;
        for op in &block.ops {
            if !buf.is_empty() {
                buf.push('\n');
            }
            buf.push_str(&VarnodeTranslator::format_op(op));
            count += 1;
            if count >= limit {
                buf.push_str("\n...");
                break;
            }
        }
        buf
    }

    fn block_vertex_type_static(block: &GraphBasicBlock) -> &'static str {
        if block.is_entry() {
            "Entry"
        } else if block.is_exit() {
            "Exit"
        } else if block.successors.len() > 1 {
            "Switch"
        } else {
            "Body"
        }
    }

    fn op_vertex_type_static(opcode: &GraphPcodeOpcode) -> &'static str {
        match opcode {
            GraphPcodeOpcode::Branch
            | GraphPcodeOpcode::BranchInd
            | GraphPcodeOpcode::CBranch
            | GraphPcodeOpcode::Call
            | GraphPcodeOpcode::CallInd => "Switch",
            GraphPcodeOpcode::Return => "Exit",
            _ => "Body",
        }
    }

    fn varnode_vertex_type_static(vn: &GraphVarnode) -> &'static str {
        match vn.kind {
            VarnodeKind::Constant => "Constant",
            VarnodeKind::Register | VarnodeKind::Input => "Register",
            VarnodeKind::Unique => "Unique",
            VarnodeKind::Persistent => "Persistent",
            VarnodeKind::AddressTied => "AddressTied",
            VarnodeKind::Stack => "Default",
        }
    }
}

// ---------------------------------------------------------------------------
// PCodeDfgGraphTask -- builds DFG from PCode ops
// ---------------------------------------------------------------------------

/// Task for creating PCode data flow graphs from decompiler output.
///
/// Mirrors `PCodeDfgGraphTask` from the Java source.  Builds a graph
/// where vertices are PCode operations and varnodes, and edges represent
/// data-flow dependencies.
#[derive(Debug)]
pub struct PCodeDfgGraphTask {
    /// The function name.
    function_name: String,
    /// The basic blocks of the function.
    blocks: Vec<GraphBasicBlock>,
}

impl PCodeDfgGraphTask {
    /// Create a new DFG graph task.
    pub fn new(function_name: impl Into<String>, blocks: Vec<GraphBasicBlock>) -> Self {
        Self {
            function_name: function_name.into(),
            blocks,
        }
    }

    /// Run the task and produce a graph result.
    pub fn run(&mut self) -> GraphTaskResult {
        let mut graph = AttributedGraph::new("Data Flow Graph");
        self.build_graph(&mut graph);

        let description = format!("AST Data Flow Graph For {}", self.function_name);

        GraphTaskResult {
            graph,
            description,
            function_name: self.function_name.clone(),
        }
    }

    /// Build the data-flow graph.
    ///
    /// Iterates over all PCode ops and creates vertices for ops and
    /// varnodes, with data-flow edges between them.
    fn build_graph(&self, graph: &mut AttributedGraph) {
        let mut varnode_vertices: HashMap<u32, usize> = HashMap::new();

        for block in &self.blocks {
            for op in &block.ops {
                let op_idx = Self::create_op_vertex_dfg(graph, op);

                for (i, vn) in op.inputs.iter().enumerate() {
                    let opcode = op.opcode;
                    if (i == 0)
                        && (opcode == GraphPcodeOpcode::Load
                            || opcode == GraphPcodeOpcode::Store)
                    {
                        continue;
                    }
                    if (i == 1) && opcode == GraphPcodeOpcode::Indirect {
                        continue;
                    }
                    let vn_idx = Self::get_varnode_vertex_dfg(graph, vn, &mut varnode_vertices);
                    Self::create_edge_dfg(graph, vn_idx, op_idx);
                }

                if let Some(ref output) = op.output {
                    let out_idx =
                        Self::get_varnode_vertex_dfg(graph, output, &mut varnode_vertices);
                    Self::create_edge_dfg(graph, op_idx, out_idx);
                }
            }
        }
    }

    /// Create a vertex for a PCode op.
    fn create_op_vertex_dfg(graph: &mut AttributedGraph, op: &GraphPcodeOp) -> usize {
        let id = format!("{:x} o {}", op.address.offset, op.seq_time);
        let mut name = op.opcode.mnemonic().to_string();

        if op.opcode == GraphPcodeOpcode::Load || op.opcode == GraphPcodeOpcode::Store {
            if let Some(ref output) = op.output {
                name.push(' ');
                name.push_str(&format!("0x{:x}", output.address.offset));
            }
        } else if op.opcode == GraphPcodeOpcode::Indirect {
            if op.inputs.len() > 1 {
                name.push_str(" (indirect)");
            }
        }

        graph.add_vertex(id, name, DfgVertexType::Op.label())
    }

    /// Create a vertex for a varnode.
    fn create_varnode_vertex_dfg(graph: &mut AttributedGraph, vn: &GraphVarnode) -> usize {
        let id = format!("v_{}", vn.unique_id);
        let name = vn.address.to_string();
        let vertex_type = Self::varnode_dfg_type(vn);
        let idx = graph.add_vertex(id, name, vertex_type);

        // Input varnodes get a special shape override.
        if vn.kind == VarnodeKind::Input {
            if let Some(v) = graph.vertex_mut(idx) {
                v.shape = Some(VertexShape::Hexagon);
            }
        }

        idx
    }

    /// Get or create a varnode vertex (cached by unique ID).
    fn get_varnode_vertex_dfg(
        graph: &mut AttributedGraph,
        vn: &GraphVarnode,
        cache: &mut HashMap<u32, usize>,
    ) -> usize {
        if let Some(&idx) = cache.get(&vn.unique_id) {
            return idx;
        }
        let idx = Self::create_varnode_vertex_dfg(graph, vn);
        cache.insert(vn.unique_id, idx);
        idx
    }

    /// Create an edge with the default DFG edge type.
    fn create_edge_dfg(graph: &mut AttributedGraph, from: usize, to: usize) -> usize {
        graph.add_edge(from, to, DfgEdgeType::Default.label())
    }

    fn varnode_dfg_type(vn: &GraphVarnode) -> &'static str {
        match vn.kind {
            VarnodeKind::Constant => DfgVertexType::Constant.label(),
            VarnodeKind::Register | VarnodeKind::Input => DfgVertexType::Register.label(),
            VarnodeKind::Unique => DfgVertexType::Unique.label(),
            VarnodeKind::Persistent => DfgVertexType::Persistent.label(),
            VarnodeKind::AddressTied => DfgVertexType::AddressTied.label(),
            VarnodeKind::Stack => DfgVertexType::Default.label(),
        }
    }
}

// ---------------------------------------------------------------------------
// PCodeCombinedGraphTask -- extends DFG with intra-block CFG edges
// ---------------------------------------------------------------------------

/// Task to create a combined PCode control flow and data flow graph.
///
/// Mirrors `PCodeCombinedGraphTask` from the Java source.  This extends
/// the DFG with edges that represent the sequential execution order
/// within basic blocks, and edges between the last op of a predecessor
/// block and the first op of a successor block.
#[derive(Debug)]
pub struct PCodeCombinedGraphTask {
    /// The function name.
    function_name: String,
    /// The basic blocks of the function.
    blocks: Vec<GraphBasicBlock>,
}

impl PCodeCombinedGraphTask {
    /// Create a new combined graph task.
    pub fn new(function_name: impl Into<String>, blocks: Vec<GraphBasicBlock>) -> Self {
        Self {
            function_name: function_name.into(),
            blocks,
        }
    }

    /// Run the task and produce a graph result.
    pub fn run(&mut self) -> GraphTaskResult {
        let mut graph = AttributedGraph::new("Combined Graph");
        self.build_graph(&mut graph);

        let description = format!("AST Combined Graph For {}", self.function_name);

        GraphTaskResult {
            graph,
            description,
            function_name: self.function_name.clone(),
        }
    }

    /// Build the combined graph.
    ///
    /// First builds the DFG (op/varnode vertices with data-flow edges),
    /// then adds intra-block sequential edges and inter-block control
    /// edges.
    fn build_graph(&self, graph: &mut AttributedGraph) {
        let mut varnode_vertices: HashMap<u32, usize> = HashMap::new();
        let mut op_indices: HashMap<String, usize> = HashMap::new();

        // Phase 1: Build DFG (same as PCodeDfgGraphTask).
        for block in &self.blocks {
            for op in &block.ops {
                let op_key = self.get_op_key(op);
                let op_idx = self.create_op_vertex(graph, op);
                op_indices.insert(op_key, op_idx);

                for (i, vn) in op.inputs.iter().enumerate() {
                    let opcode = op.opcode;
                    if (i == 0)
                        && (opcode == GraphPcodeOpcode::Load
                            || opcode == GraphPcodeOpcode::Store)
                    {
                        continue;
                    }
                    if (i == 1) && opcode == GraphPcodeOpcode::Indirect {
                        continue;
                    }
                    let vn_idx = self.get_varnode_vertex(graph, vn, &mut varnode_vertices);
                    graph.add_edge(vn_idx, op_idx, DfgEdgeType::Default.label());
                }

                if let Some(ref output) = op.output {
                    let out_idx =
                        self.get_varnode_vertex(graph, output, &mut varnode_vertices);
                    graph.add_edge(op_idx, out_idx, DfgEdgeType::Default.label());
                }
            }
        }

        // Phase 2: Add intra-block sequential edges.
        for block in &self.blocks {
            let mut prev_op_idx: Option<usize> = None;
            for op in &block.ops {
                let op_key = self.get_op_key(op);
                if let Some(&cur_idx) = op_indices.get(&op_key) {
                    if let Some(prev_idx) = prev_op_idx {
                        graph.add_edge(prev_idx, cur_idx, DfgEdgeType::WithinBlock.label());
                    }
                    prev_op_idx = Some(cur_idx);
                }
            }
        }

        // Phase 3: Add inter-block control edges.
        for block in &self.blocks {
            if block.ops.is_empty() {
                continue;
            }
            let last_op = block.ops.last().unwrap();
            let last_key = self.get_op_key(last_op);
            let last_idx = op_indices.get(&last_key).copied();

            for &succ_idx in &block.successors {
                if succ_idx >= self.blocks.len() {
                    continue;
                }
                let succ_block = &self.blocks[succ_idx];
                if succ_block.ops.is_empty() {
                    continue;
                }
                let first_op = &succ_block.ops[0];
                let first_key = self.get_op_key(first_op);
                let first_idx = op_indices.get(&first_key).copied();

                if let (Some(from), Some(to)) = (last_idx, first_idx) {
                    graph.add_edge(from, to, DfgEdgeType::BetweenBlocks.label());
                }
            }
        }
    }

    // Helpers (same as PCodeDfgGraphTask).

    fn create_op_vertex(&self, graph: &mut AttributedGraph, op: &GraphPcodeOp) -> usize {
        let id = self.get_op_key(op);
        let mut name = op.opcode.mnemonic().to_string();

        if op.opcode == GraphPcodeOpcode::Load || op.opcode == GraphPcodeOpcode::Store {
            if let Some(ref output) = op.output {
                name.push(' ');
                name.push_str(&format!("0x{:x}", output.address.offset));
            }
        } else if op.opcode == GraphPcodeOpcode::Indirect {
            if op.inputs.len() > 1 {
                name.push_str(" (indirect)");
            }
        }

        graph.add_vertex(&id, &name, DfgVertexType::Op.label())
    }

    fn create_varnode_vertex(&self, graph: &mut AttributedGraph, vn: &GraphVarnode) -> usize {
        let id = format!("v_{}", vn.unique_id);
        let name = vn.address.to_string();
        let vertex_type = match vn.kind {
            VarnodeKind::Constant => DfgVertexType::Constant.label(),
            VarnodeKind::Register | VarnodeKind::Input => DfgVertexType::Register.label(),
            VarnodeKind::Unique => DfgVertexType::Unique.label(),
            VarnodeKind::Persistent => DfgVertexType::Persistent.label(),
            VarnodeKind::AddressTied => DfgVertexType::AddressTied.label(),
            VarnodeKind::Stack => DfgVertexType::Default.label(),
        };
        graph.add_vertex(&id, &name, vertex_type)
    }

    fn get_varnode_vertex(
        &self,
        graph: &mut AttributedGraph,
        vn: &GraphVarnode,
        cache: &mut HashMap<u32, usize>,
    ) -> usize {
        if let Some(&idx) = cache.get(&vn.unique_id) {
            return idx;
        }
        let idx = self.create_varnode_vertex(graph, vn);
        cache.insert(vn.unique_id, idx);
        idx
    }

    fn get_op_key(&self, op: &GraphPcodeOp) -> String {
        format!("{:x} o {}", op.address.offset, op.seq_time)
    }
}

// ---------------------------------------------------------------------------
// SelectedPCodeDfgGraphTask -- DFG filtered to a single address
// ---------------------------------------------------------------------------

/// Task for creating a PCode data flow graph from a selected address.
///
/// Mirrors `SelectedPCodeDfgGraphTask` from the Java source.  This
/// extends `PCodeDfgGraphTask` but filters the PCode ops to only those
/// at the given address.
#[derive(Debug)]
pub struct SelectedPCodeDfgGraphTask {
    /// The function name.
    function_name: String,
    /// The basic blocks of the function.
    blocks: Vec<GraphBasicBlock>,
    /// The address to filter on.
    address: Address,
}

impl SelectedPCodeDfgGraphTask {
    /// Create a new selected DFG graph task.
    pub fn new(
        function_name: impl Into<String>,
        blocks: Vec<GraphBasicBlock>,
        address: Address,
    ) -> Self {
        Self {
            function_name: function_name.into(),
            blocks,
            address,
        }
    }

    /// Run the task and produce a graph result.
    pub fn run(&mut self) -> GraphTaskResult {
        let mut graph = AttributedGraph::new("Selected Data Flow Graph");
        self.build_graph(&mut graph);

        let description = format!(
            "AST Data Flow Graph For {} at 0x{:x}",
            self.function_name, self.address.offset
        );

        GraphTaskResult {
            graph,
            description,
            function_name: self.function_name.clone(),
        }
    }

    /// Build the DFG filtered to the selected address.
    fn build_graph(&self, graph: &mut AttributedGraph) {
        let mut varnode_vertices: HashMap<u32, usize> = HashMap::new();

        for block in &self.blocks {
            for op in &block.ops {
                // Only include ops at the selected address.
                if op.address != self.address {
                    continue;
                }

                let op_idx = self.create_op_vertex(graph, op);

                for (i, vn) in op.inputs.iter().enumerate() {
                    let opcode = op.opcode;
                    if (i == 0)
                        && (opcode == GraphPcodeOpcode::Load
                            || opcode == GraphPcodeOpcode::Store)
                    {
                        continue;
                    }
                    if (i == 1) && opcode == GraphPcodeOpcode::Indirect {
                        continue;
                    }
                    let vn_idx = self.get_varnode_vertex(graph, vn, &mut varnode_vertices);
                    graph.add_edge(vn_idx, op_idx, DfgEdgeType::Default.label());
                }

                if let Some(ref output) = op.output {
                    let out_idx =
                        self.get_varnode_vertex(graph, output, &mut varnode_vertices);
                    graph.add_edge(op_idx, out_idx, DfgEdgeType::Default.label());
                }
            }
        }
    }

    fn create_op_vertex(&self, graph: &mut AttributedGraph, op: &GraphPcodeOp) -> usize {
        let id = format!("{:x} o {}", op.address.offset, op.seq_time);
        let mut name = op.opcode.mnemonic().to_string();

        if op.opcode == GraphPcodeOpcode::Load || op.opcode == GraphPcodeOpcode::Store {
            if let Some(ref output) = op.output {
                name.push(' ');
                name.push_str(&format!("0x{:x}", output.address.offset));
            }
        } else if op.opcode == GraphPcodeOpcode::Indirect {
            if op.inputs.len() > 1 {
                name.push_str(" (indirect)");
            }
        }

        graph.add_vertex(&id, &name, DfgVertexType::Op.label())
    }

    fn create_varnode_vertex(&self, graph: &mut AttributedGraph, vn: &GraphVarnode) -> usize {
        let id = format!("v_{}", vn.unique_id);
        let name = vn.address.to_string();
        let vertex_type = match vn.kind {
            VarnodeKind::Constant => DfgVertexType::Constant.label(),
            VarnodeKind::Register | VarnodeKind::Input => DfgVertexType::Register.label(),
            VarnodeKind::Unique => DfgVertexType::Unique.label(),
            VarnodeKind::Persistent => DfgVertexType::Persistent.label(),
            VarnodeKind::AddressTied => DfgVertexType::AddressTied.label(),
            VarnodeKind::Stack => DfgVertexType::Default.label(),
        };
        graph.add_vertex(&id, &name, vertex_type)
    }

    fn get_varnode_vertex(
        &self,
        graph: &mut AttributedGraph,
        vn: &GraphVarnode,
        cache: &mut HashMap<u32, usize>,
    ) -> usize {
        if let Some(&idx) = cache.get(&vn.unique_id) {
            return idx;
        }
        let idx = self.create_varnode_vertex(graph, vn);
        cache.insert(vn.unique_id, idx);
        idx
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Helper builders ---

    fn make_varnode(id: u32, offset: u64, kind: VarnodeKind) -> GraphVarnode {
        GraphVarnode::new(id, Address::new(offset), 4, kind)
    }

    fn make_op(
        seq: u32,
        opcode: GraphPcodeOpcode,
        addr: u64,
        block: usize,
    ) -> GraphPcodeOp {
        GraphPcodeOp::new(seq, opcode, Address::new(addr), block)
    }

    fn make_simple_blocks() -> Vec<GraphBasicBlock> {
        // Block 0: 0x1000 - 0x100f
        // Block 1: 0x1010 - 0x101f
        let mut block0 = GraphBasicBlock::new(0, Address::new(0x1000), Address::new(0x100f));
        block0.successors.push(1);

        let mut op0 = make_op(0, GraphPcodeOpcode::IntAdd, 0x1000, 0);
        op0.output = Some(make_varnode(0, 0x100, VarnodeKind::Register));
        op0.inputs.push(make_varnode(1, 0x104, VarnodeKind::Register));
        op0.inputs.push(make_varnode(2, 0x108, VarnodeKind::Register));
        block0.ops.push(op0);

        let mut block1 = GraphBasicBlock::new(1, Address::new(0x1010), Address::new(0x101f));
        block1.predecessors.push(0);

        let mut op1 = make_op(1, GraphPcodeOpcode::Copy, 0x1010, 1);
        op1.output = Some(make_varnode(3, 0x10c, VarnodeKind::Register));
        op1.inputs.push(make_varnode(0, 0x100, VarnodeKind::Register));
        block1.ops.push(op1);

        vec![block0, block1]
    }

    // --- GraphPcodeOpcode ---

    #[test]
    fn test_opcode_mnemonic() {
        assert_eq!(GraphPcodeOpcode::IntAdd.mnemonic(), "INT_ADD");
        assert_eq!(GraphPcodeOpcode::Branch.mnemonic(), "BRANCH");
        assert_eq!(GraphPcodeOpcode::Return.mnemonic(), "RETURN");
    }

    #[test]
    fn test_opcode_is_control_flow() {
        assert!(GraphPcodeOpcode::Branch.is_control_flow());
        assert!(GraphPcodeOpcode::CBranch.is_control_flow());
        assert!(GraphPcodeOpcode::Call.is_control_flow());
        assert!(GraphPcodeOpcode::Return.is_control_flow());
        assert!(!GraphPcodeOpcode::IntAdd.is_control_flow());
        assert!(!GraphPcodeOpcode::Copy.is_control_flow());
    }

    // --- GraphVarnode ---

    #[test]
    fn test_varnode_label_constant() {
        let vn = make_varnode(1, 0x42, VarnodeKind::Constant);
        assert_eq!(vn.label, "#42");
    }

    #[test]
    fn test_varnode_label_unique() {
        let vn = make_varnode(2, 0xabc, VarnodeKind::Unique);
        assert_eq!(vn.label, "u_abc");
    }

    #[test]
    fn test_varnode_with_name() {
        let vn = make_varnode(3, 0x100, VarnodeKind::Register).with_name("myVar");
        assert_eq!(vn.high_name, Some("myVar".to_string()));
    }

    // --- VarnodeTranslator ---

    #[test]
    fn test_translate_constant() {
        let vn = make_varnode(1, 0xff, VarnodeKind::Constant);
        assert_eq!(VarnodeTranslator::translate(&vn, false), "#ff");
    }

    #[test]
    fn test_translate_register_with_name() {
        let vn = make_varnode(2, 0x100, VarnodeKind::Register).with_name("eax");
        assert_eq!(VarnodeTranslator::translate(&vn, true), "eax");
    }

    #[test]
    fn test_format_op_mnemonic_with_size() {
        let m = VarnodeTranslator::format_op_mnemonic(&GraphPcodeOpcode::IntAdd, Some(4));
        assert_eq!(m, "INT_ADD.d");
    }

    #[test]
    fn test_format_op_mnemonic_no_size() {
        let m = VarnodeTranslator::format_op_mnemonic(&GraphPcodeOpcode::Branch, None);
        assert_eq!(m, "BRANCH");
    }

    #[test]
    fn test_format_op() {
        let mut op = make_op(0, GraphPcodeOpcode::IntAdd, 0x1000, 0);
        op.output = Some(make_varnode(0, 0x100, VarnodeKind::Register).with_name("result"));
        op.inputs.push(make_varnode(1, 0x104, VarnodeKind::Register).with_name("a"));
        op.inputs.push(make_varnode(2, 0x108, VarnodeKind::Register).with_name("b"));
        let line = VarnodeTranslator::format_op(&op);
        assert!(line.contains("result"));
        assert!(line.contains("INT_ADD"));
        assert!(line.contains("a"));
        assert!(line.contains("b"));
    }

    // --- AttributedGraph ---

    #[test]
    fn test_graph_add_vertex() {
        let mut graph = AttributedGraph::new("test");
        let idx = graph.add_vertex("v0", "label0", "Body");
        assert_eq!(idx, 0);
        assert_eq!(graph.vertex_count(), 1);
        assert_eq!(graph.vertex(0).unwrap().id, "v0");
    }

    #[test]
    fn test_graph_add_edge() {
        let mut graph = AttributedGraph::new("test");
        graph.add_vertex("v0", "a", "Body");
        graph.add_vertex("v1", "b", "Body");
        let eidx = graph.add_edge(0, 1, "data");
        assert_eq!(eidx, 0);
        assert_eq!(graph.edge_count(), 1);
    }

    #[test]
    fn test_graph_find_vertex() {
        let mut graph = AttributedGraph::new("test");
        graph.add_vertex("v0", "a", "Body");
        graph.add_vertex("v1", "b", "Body");
        assert_eq!(graph.find_vertex("v0"), Some(0));
        assert_eq!(graph.find_vertex("v1"), Some(1));
        assert_eq!(graph.find_vertex("v2"), None);
    }

    // --- PCodeCfgGraphTask ---

    #[test]
    fn test_cfg_task_control_flow() {
        let blocks = make_simple_blocks();
        let mut task = PCodeCfgGraphTask::new(
            "test_func",
            blocks,
            PCodeCfgGraphSubType::ControlFlowGraph,
            10,
        );
        let result = task.run();
        assert!(result.description.contains("Control Flow"));
        assert!(result.description.contains("test_func"));
        // Should have 2 block vertices and 1 edge.
        assert_eq!(result.graph.vertex_count(), 2);
        assert_eq!(result.graph.edge_count(), 1);
    }

    #[test]
    fn test_cfg_task_data_flow() {
        let blocks = make_simple_blocks();
        let mut task = PCodeCfgGraphTask::new(
            "test_func",
            blocks,
            PCodeCfgGraphSubType::CombinedGraph,
            10,
        );
        let result = task.run();
        assert!(result.description.contains("Data Flow"));
        // Should have op vertices and varnode vertices.
        assert!(result.graph.vertex_count() > 2);
    }

    #[test]
    fn test_cfg_task_empty_blocks() {
        let mut task = PCodeCfgGraphTask::new(
            "empty_func",
            vec![],
            PCodeCfgGraphSubType::ControlFlowGraph,
            10,
        );
        let result = task.run();
        assert_eq!(result.graph.vertex_count(), 0);
        assert_eq!(result.graph.edge_count(), 0);
    }

    // --- PCodeDfgGraphTask ---

    #[test]
    fn test_dfg_task_basic() {
        let blocks = make_simple_blocks();
        let mut task = PCodeDfgGraphTask::new("test_func", blocks);
        let result = task.run();
        assert!(result.description.contains("Data Flow"));
        assert!(result.description.contains("test_func"));
        // Should have op vertices + varnode vertices + edges.
        assert!(result.graph.vertex_count() >= 2);
    }

    #[test]
    fn test_dfg_task_empty() {
        let mut task = PCodeDfgGraphTask::new("empty_func", vec![]);
        let result = task.run();
        assert_eq!(result.graph.vertex_count(), 0);
    }

    // --- PCodeCombinedGraphTask ---

    #[test]
    fn test_combined_task_basic() {
        let blocks = make_simple_blocks();
        let mut task = PCodeCombinedGraphTask::new("test_func", blocks);
        let result = task.run();
        assert!(result.description.contains("Combined"));
        // Combined graph should have more edges than pure DFG because
        // it adds intra-block and inter-block edges.
        assert!(result.graph.edge_count() > 0);
    }

    #[test]
    fn test_combined_task_single_block() {
        let mut block = GraphBasicBlock::new(0, Address::new(0x1000), Address::new(0x100f));
        let mut op = make_op(0, GraphPcodeOpcode::Copy, 0x1000, 0);
        op.output = Some(make_varnode(0, 0x100, VarnodeKind::Register));
        op.inputs.push(make_varnode(1, 0x104, VarnodeKind::Constant));
        block.ops.push(op);

        let mut task = PCodeCombinedGraphTask::new("single_block", vec![block]);
        let result = task.run();
        // 1 op + 2 varnodes = 3 vertices, 2 data edges + 0 intra-block edges.
        assert_eq!(result.graph.vertex_count(), 3);
        assert_eq!(result.graph.edge_count(), 2);
    }

    // --- SelectedPCodeDfgGraphTask ---

    #[test]
    fn test_selected_task_filters() {
        let blocks = make_simple_blocks();
        let mut task = SelectedPCodeDfgGraphTask::new(
            "test_func",
            blocks,
            Address::new(0x1000),
        );
        let result = task.run();
        assert!(result.description.contains("0x1000"));
        // Only op at 0x1000 should be included.
        let op_vertices: Vec<_> = result
            .graph
            .vertices
            .iter()
            .filter(|v| v.vertex_type == DfgVertexType::Op.label())
            .collect();
        assert_eq!(op_vertices.len(), 1);
    }

    #[test]
    fn test_selected_task_no_match() {
        let blocks = make_simple_blocks();
        let mut task = SelectedPCodeDfgGraphTask::new(
            "test_func",
            blocks,
            Address::new(0x9999),
        );
        let result = task.run();
        // No ops at 0x9999, so no vertices.
        assert_eq!(result.graph.vertex_count(), 0);
    }

    // --- GraphBasicBlock ---

    #[test]
    fn test_basic_block_entry_exit() {
        let block = GraphBasicBlock::new(0, Address::new(0x1000), Address::new(0x100f));
        assert!(block.is_entry());
        assert!(block.is_exit());
    }

    #[test]
    fn test_basic_block_with_successors() {
        let mut block = GraphBasicBlock::new(0, Address::new(0x1000), Address::new(0x100f));
        block.successors.push(1);
        assert!(block.is_entry());
        assert!(!block.is_exit());
    }

    // --- VertexShape ---

    #[test]
    fn test_vertex_shape_default() {
        assert_eq!(VertexShape::default(), VertexShape::Ellipse);
    }

    // --- GraphVertex attributes ---

    #[test]
    fn test_vertex_attributes() {
        let mut v = GraphVertex::new("v0", "label", "Body");
        v.set_attribute("Code", "INT_ADD.d");
        assert_eq!(v.attributes.get("Code").unwrap(), "INT_ADD.d");
    }

    // --- Integration test ---

    #[test]
    fn test_full_cfg_dfg_combined_pipeline() {
        let blocks = make_simple_blocks();

        // CFG
        let mut cfg_task = PCodeCfgGraphTask::new(
            "main",
            blocks.clone(),
            PCodeCfgGraphSubType::ControlFlowGraph,
            5,
        );
        let cfg_result = cfg_task.run();
        assert!(cfg_result.graph.vertex_count() >= 2);

        // DFG
        let mut dfg_task = PCodeDfgGraphTask::new("main", blocks.clone());
        let dfg_result = dfg_task.run();
        assert!(dfg_result.graph.vertex_count() >= 3);

        // Combined
        let mut combined_task = PCodeCombinedGraphTask::new("main", blocks.clone());
        let combined_result = combined_task.run();
        assert!(combined_result.graph.vertex_count() >= 3);

        // Selected
        let mut selected_task = SelectedPCodeDfgGraphTask::new(
            "main",
            blocks,
            Address::new(0x1000),
        );
        let selected_result = selected_task.run();
        assert!(selected_result.graph.vertex_count() >= 1);
    }
}
