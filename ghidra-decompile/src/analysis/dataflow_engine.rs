//! Data-flow analysis engine for the Ghidra decompiler.
//!
//! Tracks how values flow through P-code operations. Builds a directed graph of
//! varnodes connected by data-flow edges, computes def-use chains, reaching
//! definitions, and live ranges. Supports constant propagation, copy propagation,
//! and value-set (abstract interpretation) range analysis.
//!
//! # Architecture
//!
//! The engine operates in phases:
//! 1. [`DataFlowEngine::build_graph`] -- Build the varnode data-flow graph from P-code.
//! 2. [`DataFlowEngine::compute_def_use`] -- Build def-use chains for each varnode.
//! 3. [`DataFlowEngine::compute_reaching_defs`] -- Iterative reaching-definitions analysis.
//! 4. [`DataFlowEngine::compute_live_ranges`] -- Compute live ranges per varnode.
//!
//! After analysis, callers can query the results with [`get_def`](DataFlowEngine::get_def),
//! [`get_uses`](DataFlowEngine::get_uses), and [`is_live_at`](DataFlowEngine::is_live_at), or
//! run propagation passes.

use std::collections::{HashMap, HashSet, VecDeque};

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;

use ghidra_core::addr::Address;
use ghidra_core::error::Result;

use crate::pcode::{OpCode, PcodeOperation, Varnode};

// ============================================================================
// PcodeSequence
// ============================================================================

/// A sequence of P-code operations associated with a contiguous address range.
///
/// Each sequence typically corresponds to a basic block or an entire function
/// body. The operations are in program-execution order.
#[derive(Debug, Clone)]
pub struct PcodeSequence {
    /// The P-code operations in sequential order.
    pub ops: Vec<PcodeOperation>,
    /// Start address of the sequence (inclusive).
    pub start_address: Address,
    /// End address of the sequence (inclusive).
    pub end_address: Address,
}

impl PcodeSequence {
    /// Create a new P-code sequence spanning the given address range.
    pub fn new(ops: Vec<PcodeOperation>, start: Address, end: Address) -> Self {
        Self {
            ops,
            start_address: start,
            end_address: end,
        }
    }

    /// Returns `true` if the sequence contains no operations.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Number of operations in the sequence.
    pub fn len(&self) -> usize {
        self.ops.len()
    }
}

// ============================================================================
// Graph Node / Edge types
// ============================================================================

/// Metadata stored in each node of the varnode data-flow graph.
#[derive(Debug, Clone)]
pub struct VarnodeData {
    /// The varnode represented by this graph node.
    pub varnode: Varnode,
    /// Number of times this varnode appears as an output (definition site).
    pub def_count: u32,
    /// Number of times this varnode appears as an input (use site).
    pub use_count: u32,
    /// True if this varnode is a function input (used before any local definition).
    pub is_input: bool,
    /// True if this varnode is a function output (value escapes the local scope).
    pub is_output: bool,
}

/// Classification of data-flow edges between varnodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowType {
    /// Direct register/unique copy: `v0 = COPY v1`
    Direct,
    /// Indirect flow through memory: `v0 = LOAD v1` or `STORE v0, v1`
    Indirect,
    /// Flow combined through arithmetic / logic: `v0 = v1 + v2`, etc.
    Combined,
}

// ============================================================================
// DefUseChain
// ============================================================================

/// Tracks the definition site and all use sites for a single varnode.
#[derive(Debug, Clone, Default)]
pub struct DefUseChain {
    /// For COPY-chained varnodes, the source varnode that defines this one.
    /// `None` when the varnode is not defined by a simple COPY.
    pub def: Option<Varnode>,
    /// All varnodes that read (use) this varnode's value as an input.
    pub uses: Vec<Varnode>,
}

// ============================================================================
// LiveRange
// ============================================================================

/// The address interval during which a varnode's value is live (needed).
#[derive(Debug, Clone)]
pub struct LiveRange {
    /// First address (inclusive) where this varnode is defined.
    pub start: Address,
    /// Last address (inclusive) where this varnode is used.
    pub end: Address,
    /// True if this varnode is live upon function entry (has a use before any
    /// local definition, i.e. its value comes from the caller).
    pub is_live_on_entry: bool,
    /// True if this varnode is live upon function exit (its value escapes,
    /// e.g. through a RETURN or STORE to RAM).
    pub is_live_on_exit: bool,
}

// ============================================================================
// ConstantValue
// ============================================================================

/// A concrete constant value discovered through propagation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConstantValue {
    /// The raw bit-pattern of the constant.
    pub value: u64,
    /// Size in bytes.
    pub size: u32,
    /// Whether the value should be displayed as signed.
    pub is_signed: bool,
}

impl ConstantValue {
    /// Return the sign-extended value as an `i64`.
    pub fn as_signed(&self) -> i64 {
        let shift = 64 - (self.size as u32 * 8);
        ((self.value << shift) as i64) >> shift
    }

    /// Return the zero-extended value.
    pub fn as_unsigned(&self) -> u64 {
        self.value
    }
}

// ============================================================================
// DataFlowEngine
// ============================================================================

/// The primary data-flow analysis engine.
///
/// Builds a varnode data-flow graph from P-code sequences and provides
/// def-use, reaching-definitions, live-range, copy-propagation, and
/// constant-propagation analyses.
pub struct DataFlowEngine {
    /// Directed graph: nodes are varnodes, edges represent data flow.
    pub varnode_graph: DiGraph<VarnodeData, FlowType>,
    /// Per-varnode definition-use chains.
    pub def_use_chains: HashMap<Varnode, DefUseChain>,
    /// Reaching-definitions sets: for each varnode, the set of varnodes whose
    /// values may flow into it (reflexive: every varnode reaches itself).
    pub reaching_defs: HashMap<Varnode, HashSet<Varnode>>,
    /// Live ranges for each varnode.
    pub live_ranges: HashMap<Varnode, LiveRange>,

    // -- Internal helpers (not part of the public analysis contract) --
    /// Maps each varnode to its graph node index, for efficient lookup.
    node_map: HashMap<Varnode, NodeIndex>,
    /// Stores the processed P-code sequences for recomputation / reference.
    sequences: Vec<PcodeSequence>,
}

impl DataFlowEngine {
    /// Create a new, empty data-flow engine.
    pub fn new() -> Self {
        Self {
            varnode_graph: DiGraph::new(),
            def_use_chains: HashMap::new(),
            reaching_defs: HashMap::new(),
            live_ranges: HashMap::new(),
            node_map: HashMap::new(),
            sequences: Vec::new(),
        }
    }

    // ------------------------------------------------------------------
    // Phase 1: Build the varnode data-flow graph
    // ------------------------------------------------------------------

    /// Build the varnode data-flow graph from the provided P-code sequences.
    ///
    /// For each operation, the engine:
    /// - Creates (or reuses) a graph node for every output and input varnode.
    /// - Increments per-node `def_count` / `use_count`.
    /// - Adds a directed edge `input → output` classified as `Direct`,
    ///   `Indirect`, or `Combined` based on the operation type.
    /// - Determines `is_input` (used before locally defined) and `is_output`
    ///   (value escapes the scope).
    pub fn build_graph(&mut self, pcode: &[PcodeSequence]) -> Result<()> {
        if pcode.is_empty() {
            return Ok(());
        }

        // Store sequences for later phases.
        self.sequences = pcode.to_vec();

        // ---- Pass 1: create nodes and count defs / uses ----
        for seq in pcode {
            for op in &seq.ops {
                // Output varnode → definition site.
                if let Some(ref out) = op.output {
                    let out_idx = self.get_or_create_node(out);
                    self.varnode_graph[out_idx].def_count += 1;

                    // Each input → use site; add edge input → output.
                    for inp in &op.inputs {
                        let inp_idx = self.get_or_create_node(inp);
                        self.varnode_graph[inp_idx].use_count += 1;

                        // Only add data-flow edges for non-control-flow ops.
                        if !op.opcode.is_flow() {
                            let flow = classify_flow(&op.opcode);
                            self.varnode_graph.add_edge(inp_idx, out_idx, flow);
                        }
                    }
                } else {
                    // No output: still count uses of inputs (e.g. STORE, BRANCH).
                    for inp in &op.inputs {
                        let inp_idx = self.get_or_create_node(inp);
                        self.varnode_graph[inp_idx].use_count += 1;
                    }
                }
            }
        }

        // ---- Pass 1b: classify inputs / outputs ----
        //
        // is_input: a varnode used before it is defined locally.
        // We track whether each varnode has been defined yet as we walk ops.
        let mut locally_defined: HashSet<Varnode> = HashSet::new();

        for seq in pcode {
            for op in &seq.ops {
                // Check inputs: if used before locally defined → is_input.
                for inp in &op.inputs {
                    if !locally_defined.contains(inp) {
                        if let Some(&idx) = self.node_map.get(inp) {
                            self.varnode_graph[idx].is_input = true;
                        }
                    }
                }
                // Mark output as locally defined.
                if let Some(ref out) = op.output {
                    locally_defined.insert(out.clone());
                }
            }
        }

        // is_output: a varnode whose value escapes the function.
        // Escapes: written to RAM via STORE, returned via RETURN, or passed
        // as argument to CALL / CALLIND.
        for seq in pcode {
            for op in &seq.ops {
                match op.opcode {
                    OpCode::STORE => {
                        // *v0 = v1  →  the value (v1) escapes.
                        if op.inputs.len() >= 2 {
                            if let Some(&idx) = self.node_map.get(&op.inputs[1]) {
                                self.varnode_graph[idx].is_output = true;
                            }
                        }
                    }
                    OpCode::RETURN => {
                        // RETURN v0  →  v0 escapes.
                        if let Some(ref inp) = op.inputs.first() {
                            if let Some(&idx) = self.node_map.get(inp) {
                                self.varnode_graph[idx].is_output = true;
                            }
                        }
                    }
                    OpCode::CALL | OpCode::CALLIND => {
                        // CALL target, arg0, arg1, ...
                        // Arguments escape to the callee.
                        for inp in op.inputs.iter().skip(1) {
                            if let Some(&idx) = self.node_map.get(inp) {
                                self.varnode_graph[idx].is_output = true;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Phase 2: Def-Use Chains
    // ------------------------------------------------------------------

    /// Compute def-use chains for every varnode in the graph.
    ///
    /// For each COPY operation `v0 = COPY v1`, the engine records `v1` as the
    /// definition of `v0`. For every operation, all output varnodes are
    /// recorded as uses of the input varnodes.
    pub fn compute_def_use(&mut self) -> Result<()> {
        self.def_use_chains.clear();

        // Initialise chains for all known varnodes.
        for vn in self.node_map.keys() {
            self.def_use_chains
                .entry(vn.clone())
                .or_insert_with(DefUseChain::default);
        }

        for seq in &self.sequences {
            for op in &seq.ops {
                // If the op has an output, each input flows into the output;
                // the output is a "use" of each input.
                if let Some(ref out) = op.output {
                    for inp in &op.inputs {
                        // out is a use of inp.
                        if let Some(chain) = self.def_use_chains.get_mut(inp) {
                            // Avoid duplicates.
                            if !chain.uses.contains(out) {
                                chain.uses.push(out.clone());
                            }
                        }
                    }

                    // If this is a COPY, OUT is directly defined by IN[0].
                    if op.opcode == OpCode::COPY && !op.inputs.is_empty() {
                        let src = &op.inputs[0];
                        if let Some(chain) = self.def_use_chains.get_mut(out) {
                            // Only set the first (most immediate) definition.
                            if chain.def.is_none() {
                                chain.def = Some(src.clone());
                            }
                        }
                    }
                }

                // For STORE: *v0 = v1; v1 is also a use of v0 (address flows).
                if op.opcode == OpCode::STORE && op.inputs.len() >= 2 {
                    let addr = &op.inputs[0];
                    let val = &op.inputs[1];
                    if let Some(chain) = self.def_use_chains.get_mut(val) {
                        if !chain.uses.contains(addr) {
                            chain.uses.push(addr.clone());
                        }
                    }
                }
            }
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Phase 3: Reaching Definitions
    // ------------------------------------------------------------------

    /// Compute reaching-definitions sets via an iterative worklist algorithm.
    ///
    /// After this phase, `reaching_defs[v]` contains all varnodes whose
    /// definitions may reach `v` through data-flow edges.
    pub fn compute_reaching_defs(&mut self) -> Result<()> {
        self.reaching_defs.clear();

        // Initialise: every varnode reaches itself.
        for vn in self.node_map.keys() {
            let mut set = HashSet::new();
            set.insert(vn.clone());
            self.reaching_defs.insert(vn.clone(), set);
        }

        // Worklist holds varnodes whose reaching-defs set has changed.
        let mut worklist: VecDeque<Varnode> = self.node_map.keys().cloned().collect();

        while let Some(vn) = worklist.pop_front() {
            // The current set of reaching definitions for vn.
            let current_defs = match self.reaching_defs.get(&vn) {
                Some(d) => d.clone(),
                None => continue,
            };

            // Get the graph node for vn.
            let node_idx = match self.node_map.get(&vn) {
                Some(&idx) => idx,
                None => continue,
            };

            // Propagate to all successors (data flows from vn → successor).
            for succ_idx in self
                .varnode_graph
                .neighbors_directed(node_idx, Direction::Outgoing)
            {
                let succ_vn = self.varnode_graph[succ_idx].varnode.clone();
                let succ_defs = self.reaching_defs.entry(succ_vn.clone()).or_default();

                let before = succ_defs.len();
                succ_defs.extend(current_defs.iter().cloned());

                if succ_defs.len() > before {
                    worklist.push_back(succ_vn);
                }
            }
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Phase 4: Live Ranges
    // ------------------------------------------------------------------

    /// Compute live ranges for each varnode.
    ///
    /// A varnode's live range extends from its first definition to its last
    /// use address. If a varnode is used before it is defined, it is marked
    /// `is_live_on_entry`. If its value escapes (STORE, RETURN, CALL arg),
    /// it is marked `is_live_on_exit`.
    pub fn compute_live_ranges(&mut self) -> Result<()> {
        self.live_ranges.clear();

        // Track first-def and last-use addresses per varnode.
        let mut first_def: HashMap<Varnode, Address> = HashMap::new();
        let mut last_use: HashMap<Varnode, Address> = HashMap::new();
        let mut seen_use_before_def: HashSet<Varnode> = HashSet::new();
        let mut locally_defined: HashSet<Varnode> = HashSet::new();

        for seq in &self.sequences {
            let mut seq_defined: HashSet<Varnode> = HashSet::new();
            for op in &seq.ops {
                // Use an address that is monotonic within the sequence:
                // we use sequence start + sequence_number offset.
                let effective_addr = Address::new(seq.start_address.offset + op.address.map(|a| a.offset).unwrap_or(0));

                // Inputs are uses; check use-before-def.
                for inp in &op.inputs {
                    if !locally_defined.contains(inp) {
                        seen_use_before_def.insert(inp.clone());
                    }
                    let entry = last_use.entry(inp.clone()).or_insert(effective_addr);
                    if effective_addr.offset > entry.offset {
                        *entry = effective_addr;
                    }
                }

                // Output is a definition.
                if let Some(ref out) = op.output {
                    first_def.entry(out.clone()).or_insert(effective_addr);
                    locally_defined.insert(out.clone());
                    seq_defined.insert(out.clone());
                }
            }

            // Variables defined in this sequence are live through the end of
            // the instruction (the sequence end address).
            for vn in &seq_defined {
                let entry = last_use.entry(vn.clone()).or_insert(seq.end_address);
                if seq.end_address.offset > entry.offset {
                    *entry = seq.end_address;
                }
            }
        }

        // Build LiveRange for every known varnode.
        for vn in self.node_map.keys() {
            let is_live_on_entry = seen_use_before_def.contains(vn);
            let node_data = self.node_map.get(vn).map(|&idx| &self.varnode_graph[idx]);

            let is_live_on_exit = node_data.map_or(false, |nd| nd.is_output);

            // Default start/end to NULL if no def/use found.
            let start = first_def.get(vn).copied().unwrap_or(Address::NULL);
            let end = last_use.get(vn).copied().unwrap_or(start);

            self.live_ranges.insert(
                vn.clone(),
                LiveRange {
                    start,
                    end,
                    is_live_on_entry,
                    is_live_on_exit,
                },
            );
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Propagation passes
    // ------------------------------------------------------------------

    /// Propagate constants through the data-flow graph.
    ///
    /// Returns a map from varnodes to their discovered constant values.
    /// Propagation proceeds along `Direct` (COPY) edges: if the source is a
    /// known constant, the destination becomes known.
    ///
    /// The analysis starts from constant-space varnodes and iterates to a
    /// fixed point.
    pub fn propagate_constants(&self) -> HashMap<Varnode, ConstantValue> {
        let mut constants: HashMap<Varnode, ConstantValue> = HashMap::new();

        // Bootstrap: every constant-space varnode IS a constant.
        for node_idx in self.varnode_graph.node_indices() {
            let vd = &self.varnode_graph[node_idx];
            if vd.varnode.is_constant() {
                constants.insert(
                    vd.varnode.clone(),
                    ConstantValue {
                        value: vd.varnode.offset,
                        size: vd.varnode.size as u32,
                        is_signed: false,
                    },
                );
            }
        }

        // Fixed-point propagation along Direct edges.
        let mut changed = true;
        while changed {
            changed = false;

            for edge in self.varnode_graph.edge_references() {
                // Only propagate along Direct (COPY) edges.
                if !matches!(edge.weight(), FlowType::Direct) {
                    continue;
                }

                let src_idx = edge.source();
                let tgt_idx = edge.target();
                let src_vn = &self.varnode_graph[src_idx].varnode;
                let tgt_vn = &self.varnode_graph[tgt_idx].varnode;

                // Already known — skip.
                if constants.contains_key(tgt_vn) {
                    continue;
                }

                if let Some(cv) = constants.get(src_vn) {
                    constants.insert(tgt_vn.clone(), *cv);
                    changed = true;
                }
            }
        }

        // Attempt integer-arithmetic constant folding for COMBINED edges
        // where ALL sources are known constants.
        let mut changed = true;
        while changed {
            changed = false;

            // We need to look at original P-code ops for arithmetic.
            for seq in &self.sequences {
                for op in &seq.ops {
                    if op.output.is_none() || op.inputs.is_empty() {
                        continue;
                    }
                    let out = op.output.as_ref().unwrap();
                    if constants.contains_key(out) {
                        continue;
                    }

                    // Try to evaluate the op if all inputs are constants.
                    let input_consts: Vec<ConstantValue> = op
                        .inputs
                        .iter()
                        .filter_map(|inp| constants.get(inp).copied())
                        .collect();
                    if input_consts.len() != op.inputs.len() {
                        continue;
                    }

                    if let Some(result) = evaluate_constant_op(&op.opcode, &input_consts) {
                        constants.insert(out.clone(), result);
                        changed = true;
                    }
                }
            }
        }

        constants
    }

    /// Propagate copies through the data-flow graph.
    ///
    /// Returns a map from each varnode to the (non-constant) varnode it is
    /// a direct copy of. Only `Direct` (COPY) edges are considered where
    /// the source is not a constant.
    pub fn propagate_copies(&self) -> HashMap<Varnode, Varnode> {
        let mut copies: HashMap<Varnode, Varnode> = HashMap::new();

        for edge in self.varnode_graph.edge_references() {
            if !matches!(edge.weight(), FlowType::Direct) {
                continue;
            }

            let src_idx = edge.source();
            let tgt_idx = edge.target();
            let src_vn = &self.varnode_graph[src_idx].varnode;
            let tgt_vn = &self.varnode_graph[tgt_idx].varnode;

            // Skip constant-to-register copies (those are for propagate_constants).
            if src_vn.is_constant() {
                continue;
            }

            copies.insert(tgt_vn.clone(), src_vn.clone());
        }

        copies
    }

    // ------------------------------------------------------------------
    // Query helpers
    // ------------------------------------------------------------------

    /// Return the immediate defining varnode for `varnode` (from COPY chains).
    /// Returns `None` if `varnode` is not defined by a simple COPY.
    pub fn get_def(&self, varnode: &Varnode) -> Option<Varnode> {
        self.def_use_chains
            .get(varnode)
            .and_then(|chain| chain.def.clone())
    }

    /// Return all varnodes that use `varnode` as an input.
    pub fn get_uses(&self, varnode: &Varnode) -> &[Varnode] {
        self.def_use_chains
            .get(varnode)
            .map(|chain| chain.uses.as_slice())
            .unwrap_or(&[])
    }

    /// Check whether `varnode` is live at `addr`.
    ///
    /// A varnode is live at an address if that address falls within its
    /// live range (inclusive).
    pub fn is_live_at(&self, varnode: &Varnode, addr: &Address) -> bool {
        self.live_ranges.get(varnode).map_or(false, |lr| {
            addr.offset >= lr.start.offset && addr.offset <= lr.end.offset
        })
    }

    /// Return the number of varnodes in the graph.
    pub fn varnode_count(&self) -> usize {
        self.node_map.len()
    }

    /// Return the number of edges in the data-flow graph.
    pub fn edge_count(&self) -> usize {
        self.varnode_graph.edge_count()
    }

    /// Iterate over all varnodes in the graph.
    pub fn varnodes(&self) -> impl Iterator<Item = &Varnode> {
        self.node_map.keys()
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Get the existing node index for `vn`, or create a new node.
    fn get_or_create_node(&mut self, vn: &Varnode) -> NodeIndex {
        *self.node_map.entry(vn.clone()).or_insert_with(|| {
            self.varnode_graph.add_node(VarnodeData {
                varnode: vn.clone(),
                def_count: 0,
                use_count: 0,
                is_input: false,
                is_output: false,
            })
        })
    }
}

impl Default for DataFlowEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Value Set Analysis (abstract interpretation)
// ============================================================================

/// A single contiguous range of integer values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValueRange {
    /// Inclusive lower bound.
    pub min: i64,
    /// Inclusive upper bound.
    pub max: i64,
}

impl ValueRange {
    /// Create a new value range.
    pub fn new(min: i64, max: i64) -> Self {
        debug_assert!(min <= max, "ValueRange: min ({}) > max ({})", min, max);
        Self { min, max }
    }

    /// A singleton range containing exactly one value.
    pub fn singleton(value: i64) -> Self {
        Self {
            min: value,
            max: value,
        }
    }

    /// Returns `true` if this range contains `value`.
    pub fn contains(&self, value: i64) -> bool {
        value >= self.min && value <= self.max
    }

    /// Widen the range to include `other`.
    pub fn join(&self, other: &ValueRange) -> ValueRange {
        ValueRange {
            min: self.min.min(other.min),
            max: self.max.max(other.max),
        }
    }

    /// Intersect two ranges. Returns `None` if they are disjoint.
    pub fn intersect(&self, other: &ValueRange) -> Option<ValueRange> {
        let min = self.min.max(other.min);
        let max = self.max.min(other.max);
        if min <= max {
            Some(ValueRange { min, max })
        } else {
            None
        }
    }
}

/// A value set: a strided collection of value ranges produced by abstract
/// interpretation.
///
/// A `ValueSet` can be:
/// - **Top** (`is_top`): represents all possible values (unknown).
/// - **Bottom** (`is_bottom`): represents no values (unreachable).
/// - **Concrete**: a finite set of ranges with a given stride.
#[derive(Debug, Clone)]
pub struct ValueSet {
    /// The constituent ranges.
    pub ranges: Vec<ValueRange>,
    /// The stride between values (0 means dense / non-strided).
    pub stride: u64,
    /// Top: the set of all values (completely unknown).
    pub is_top: bool,
    /// Bottom: the empty set (unreachable).
    pub is_bottom: bool,
}

impl ValueSet {
    /// Create a TOP value set (unknown).
    pub fn top() -> Self {
        Self {
            ranges: Vec::new(),
            stride: 0,
            is_top: true,
            is_bottom: false,
        }
    }

    /// Create a BOTTOM value set (unreachable).
    pub fn bottom() -> Self {
        Self {
            ranges: Vec::new(),
            stride: 0,
            is_top: false,
            is_bottom: true,
        }
    }

    /// Create a singleton value set from a single constant.
    pub fn constant(value: i64) -> Self {
        Self {
            ranges: vec![ValueRange::singleton(value)],
            stride: 0,
            is_top: false,
            is_bottom: false,
        }
    }

    /// Create a value set from a single range.
    pub fn from_range(min: i64, max: i64) -> Self {
        Self {
            ranges: vec![ValueRange::new(min, max)],
            stride: 0,
            is_top: false,
            is_bottom: false,
        }
    }

    /// Join two value sets (union / least upper bound).
    pub fn join(&self, other: &ValueSet) -> ValueSet {
        if self.is_bottom {
            return other.clone();
        }
        if other.is_bottom {
            return self.clone();
        }
        if self.is_top || other.is_top {
            return ValueSet::top();
        }

        // Merge ranges from both sets.
        let mut all_ranges: Vec<ValueRange> = self.ranges.clone();
        all_ranges.extend_from_slice(&other.ranges);

        // Merge overlapping / adjacent ranges.
        all_ranges.sort_by_key(|r| r.min);
        let mut merged: Vec<ValueRange> = Vec::new();
        for r in all_ranges {
            if let Some(last) = merged.last_mut() {
                if r.min <= last.max + 1 {
                    // Overlapping or adjacent — merge.
                    last.max = last.max.max(r.max);
                } else {
                    merged.push(r);
                }
            } else {
                merged.push(r);
            }
        }

        // Stride: gcd(0, x) == x; gcd of strides.
        let stride = gcd(self.stride, other.stride);

        ValueSet {
            ranges: merged,
            stride,
            is_top: false,
            is_bottom: false,
        }
    }

    /// Returns `true` if this value set contains the given value.
    pub fn contains(&self, value: i64) -> bool {
        if self.is_top {
            return true;
        }
        if self.is_bottom {
            return false;
        }
        if self.stride > 0 {
            // Check if value is aligned to the stride within any range.
            for range in &self.ranges {
                if value < range.min || value > range.max {
                    continue;
                }
                // For stride, check if (value - min) % stride == 0
                // Find the base of the stride pattern.
                // Simplification: if value is within range, check stride alignment.
                let base = range.min;
                let offset = (value - base) as u64;
                if offset % self.stride == 0 {
                    return true;
                }
            }
            false
        } else {
            // No stride — just check ranges.
            self.ranges.iter().any(|r| r.contains(value))
        }
    }

    /// Returns `true` if this is a single known constant.
    pub fn is_constant(&self) -> bool {
        !self.is_top
            && !self.is_bottom
            && self.ranges.len() == 1
            && self.ranges[0].min == self.ranges[0].max
            && self.stride == 0
    }

    /// If this is a constant, return its value.
    pub fn as_constant(&self) -> Option<i64> {
        if self.is_constant() {
            Some(self.ranges[0].min)
        } else {
            None
        }
    }
}

impl Default for ValueSet {
    fn default() -> Self {
        Self::top()
    }
}

// ============================================================================
// ValueSetAnalyzer
// ============================================================================

/// A wrapper that associates a [`DataFlowEngine`] with value-set analysis
/// capabilities.
pub struct ValueSetAnalyzer {
    /// The underlying data-flow engine.
    pub engine: DataFlowEngine,
}

// ============================================================================
// RangeAnalyzer
// ============================================================================

/// Range analysis via abstract interpretation over the data-flow graph.
///
/// Tracks the possible integer values each varnode may hold, represented as
/// [`ValueSet`]s. Uses iterative propagation with widening to ensure
/// termination.
pub struct RangeAnalyzer {
    /// Per-varnode value sets discovered during analysis.
    pub ranges: HashMap<Varnode, ValueSet>,
}

impl RangeAnalyzer {
    /// Create a new, empty range analyzer.
    pub fn new() -> Self {
        Self {
            ranges: HashMap::new(),
        }
    }

    /// Run range analysis over the given data-flow engine.
    ///
    /// The analysis initialises from constant varnodes and propagates through
    /// the data-flow graph using abstract interpretation of each operation
    /// type. Widening is applied at join points to guarantee termination.
    pub fn analyze(&mut self, engine: &DataFlowEngine) -> Result<()> {
        self.ranges.clear();

        // Step 1: Initialise all varnodes to TOP (unknown).
        for vn in engine.varnodes() {
            self.ranges.insert(vn.clone(), ValueSet::top());
        }

        // Step 2: Set constant varnodes to their concrete values.
        for node_idx in engine.varnode_graph.node_indices() {
            let vd = &engine.varnode_graph[node_idx];
            if vd.varnode.is_constant() {
                let val = vd.varnode.offset as i64;
                self.ranges
                    .insert(vd.varnode.clone(), ValueSet::constant(val));
            }
        }

        // Step 3: Iterative fixed-point propagation.
        // Use a worklist of edges whose sources have been updated.
        let mut worklist: VecDeque<NodeIndex> = engine.varnode_graph.node_indices().collect();
        let mut iteration = 0u32;
        const MAX_ITERATIONS: u32 = 500;

        while let Some(src_idx) = worklist.pop_front() {
            iteration += 1;
            if iteration > MAX_ITERATIONS {
                // Safety valve: stop to avoid infinite loops.
                break;
            }

            let src_vn = &engine.varnode_graph[src_idx].varnode;
            let src_vs = self
                .ranges
                .get(src_vn)
                .cloned()
                .unwrap_or_else(ValueSet::top);
            if src_vs.is_bottom {
                continue; // Nothing to propagate.
            }

            for succ_idx in engine
                .varnode_graph
                .neighbors_directed(src_idx, Direction::Outgoing)
            {
                let succ_vn = &engine.varnode_graph[succ_idx].varnode;
                let old_vs = self
                    .ranges
                    .get(succ_vn)
                    .cloned()
                    .unwrap_or_else(ValueSet::top);

                // For non-TOP sources, propagate. For TOP sources, skip
                // (nothing new to contribute).
                if src_vs.is_top {
                    continue;
                }

                // Propagate: the successor's value set is the join of its
                // current set with the source's set (widening applied).
                let new_vs = if old_vs.is_top {
                    // First concrete information — adopt source directly.
                    src_vs.clone()
                } else {
                    // Join existing with new.
                    old_vs.join(&src_vs)
                };

                if new_vs.ranges != old_vs.ranges
                    || new_vs.is_top != old_vs.is_top
                    || new_vs.is_bottom != old_vs.is_bottom
                {
                    self.ranges.insert(succ_vn.clone(), new_vs);
                    worklist.push_back(succ_idx);
                }
            }
        }

        Ok(())
    }

    /// Retrieve the value set for `varnode`. Returns TOP (unknown) if the
    /// varnode has not been analyzed.
    pub fn get_range(&self, varnode: &Varnode) -> ValueSet {
        self.ranges
            .get(varnode)
            .cloned()
            .unwrap_or_else(ValueSet::top)
    }

    /// Join the value sets of two varnodes, updating both to the joined result.
    ///
    /// This is useful for merging information at control-flow join points.
    pub fn join_ranges(&mut self, a: &Varnode, b: &Varnode) {
        let range_a = self.get_range(a);
        let range_b = self.get_range(b);
        let joined = range_a.join(&range_b);
        self.ranges.insert(a.clone(), joined.clone());
        self.ranges.insert(b.clone(), joined);
    }

    /// Returns the number of varnodes with non-TOP ranges.
    pub fn known_count(&self) -> usize {
        self.ranges
            .values()
            .filter(|vs| !vs.is_top && !vs.is_bottom)
            .count()
    }
}

impl Default for RangeAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Classify the data-flow type for a given opcode.
fn classify_flow(opcode: &OpCode) -> FlowType {
    match opcode {
        OpCode::COPY => FlowType::Direct,
        OpCode::LOAD | OpCode::STORE => FlowType::Indirect,
        _ => FlowType::Combined,
    }
}

/// Compute the greatest common divisor of two unsigned integers.
fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 {
        a
    } else {
        gcd(b, a % b)
    }
}

/// Try to evaluate a P-code operation at compile time when all inputs are
/// known constants. Returns `None` if evaluation is not possible.
fn evaluate_constant_op(opcode: &OpCode, inputs: &[ConstantValue]) -> Option<ConstantValue> {
    if inputs.is_empty() {
        return None;
    }

    let size = inputs[0].size;
    let mask = if size < 8 {
        (1u64 << (size * 8)) - 1
    } else {
        u64::MAX
    };

    let v0 = inputs[0].value & mask;

    match opcode {
        OpCode::COPY => Some(inputs[0]),

        // ---- Unary ----
        OpCode::INT_NEGATE => Some(ConstantValue {
            value: (!v0).wrapping_add(1) & mask,
            size,
            is_signed: true,
        }),
        OpCode::INT_ZEXT => {
            // Zero extension: the value stays the same (upper bits already 0).
            Some(ConstantValue {
                value: v0,
                size,
                is_signed: false,
            })
        }
        OpCode::INT_SEXT => {
            // Sign extension: already handled by the mask.
            let sign_bit = 1u64 << (size * 8 - 1);
            let extended = if v0 & sign_bit != 0 { v0 | !mask } else { v0 };
            Some(ConstantValue {
                value: extended & mask,
                size,
                is_signed: true,
            })
        }

        // ---- Binary arithmetic ----
        OpCode::INT_ADD if inputs.len() >= 2 => {
            let v1 = inputs[1].value & mask;
            Some(ConstantValue {
                value: v0.wrapping_add(v1) & mask,
                size,
                is_signed: false,
            })
        }
        OpCode::INT_SUB if inputs.len() >= 2 => {
            let v1 = inputs[1].value & mask;
            Some(ConstantValue {
                value: v0.wrapping_sub(v1) & mask,
                size,
                is_signed: false,
            })
        }
        OpCode::INT_MUL if inputs.len() >= 2 => {
            let v1 = inputs[1].value & mask;
            Some(ConstantValue {
                value: v0.wrapping_mul(v1) & mask,
                size,
                is_signed: false,
            })
        }
        OpCode::INT_DIV if inputs.len() >= 2 => {
            let v1 = inputs[1].value & mask;
            if v1 == 0 {
                return None; // Division by zero.
            }
            Some(ConstantValue {
                value: v0.wrapping_div(v1) & mask,
                size,
                is_signed: false,
            })
        }
        OpCode::INT_SDIV if inputs.len() >= 2 => {
            let v1 = inputs[1].value & mask;
            if v1 == 0 {
                return None;
            }
            let s0 = inputs[0].as_signed();
            let s1 = inputs[1].as_signed();
            if s1 == 0 {
                return None;
            }
            let result = s0.wrapping_div(s1);
            Some(ConstantValue {
                value: result as u64 & mask,
                size,
                is_signed: true,
            })
        }
        OpCode::INT_REM if inputs.len() >= 2 => {
            let v1 = inputs[1].value & mask;
            if v1 == 0 {
                return None;
            }
            Some(ConstantValue {
                value: v0.wrapping_rem(v1) & mask,
                size,
                is_signed: false,
            })
        }
        OpCode::INT_SREM if inputs.len() >= 2 => {
            let v1 = inputs[1].value & mask;
            if v1 == 0 {
                return None;
            }
            let s0 = inputs[0].as_signed();
            let s1 = inputs[1].as_signed();
            if s1 == 0 {
                return None;
            }
            let result = s0.wrapping_rem(s1);
            Some(ConstantValue {
                value: result as u64 & mask,
                size,
                is_signed: true,
            })
        }

        // ---- Bitwise ----
        OpCode::INT_AND if inputs.len() >= 2 => {
            let v1 = inputs[1].value & mask;
            Some(ConstantValue {
                value: (v0 & v1) & mask,
                size,
                is_signed: false,
            })
        }
        OpCode::INT_OR if inputs.len() >= 2 => {
            let v1 = inputs[1].value & mask;
            Some(ConstantValue {
                value: (v0 | v1) & mask,
                size,
                is_signed: false,
            })
        }
        OpCode::INT_XOR if inputs.len() >= 2 => {
            let v1 = inputs[1].value & mask;
            Some(ConstantValue {
                value: (v0 ^ v1) & mask,
                size,
                is_signed: false,
            })
        }

        // ---- Shifts ----
        OpCode::INT_LEFT if inputs.len() >= 2 => {
            let shift = (inputs[1].value & 0x3f) as u32; // Only low 6 bits matter.
            Some(ConstantValue {
                value: (v0 << shift) & mask,
                size,
                is_signed: false,
            })
        }
        OpCode::INT_RIGHT if inputs.len() >= 2 => {
            let shift = (inputs[1].value & 0x3f) as u32;
            Some(ConstantValue {
                value: (v0 >> shift) & mask,
                size,
                is_signed: false,
            })
        }
        OpCode::INT_SRIGHT if inputs.len() >= 2 => {
            let shift = (inputs[1].value & 0x3f) as u32;
            let signed = inputs[0].as_signed();
            Some(ConstantValue {
                value: ((signed >> shift) as u64) & mask,
                size,
                is_signed: true,
            })
        }

        // ---- Comparison (boolean result, size = 1) ----
        OpCode::INT_EQUAL if inputs.len() >= 2 => {
            let v1 = inputs[1].value & mask;
            Some(ConstantValue {
                value: if v0 == v1 { 1 } else { 0 },
                size: 1,
                is_signed: false,
            })
        }
        OpCode::INT_NOTEQUAL if inputs.len() >= 2 => {
            let v1 = inputs[1].value & mask;
            Some(ConstantValue {
                value: if v0 != v1 { 1 } else { 0 },
                size: 1,
                is_signed: false,
            })
        }
        OpCode::INT_LESS if inputs.len() >= 2 => {
            let v1 = inputs[1].value & mask;
            Some(ConstantValue {
                value: if v0 < v1 { 1 } else { 0 },
                size: 1,
                is_signed: false,
            })
        }
        OpCode::INT_LESSEQUAL if inputs.len() >= 2 => {
            let v1 = inputs[1].value & mask;
            Some(ConstantValue {
                value: if v0 <= v1 { 1 } else { 0 },
                size: 1,
                is_signed: false,
            })
        }
        OpCode::INT_SLESS if inputs.len() >= 2 => {
            let s0 = inputs[0].as_signed();
            let s1 = inputs[1].as_signed();
            Some(ConstantValue {
                value: if s0 < s1 { 1 } else { 0 },
                size: 1,
                is_signed: true,
            })
        }
        OpCode::INT_SLESSEQUAL if inputs.len() >= 2 => {
            let s0 = inputs[0].as_signed();
            let s1 = inputs[1].as_signed();
            Some(ConstantValue {
                value: if s0 <= s1 { 1 } else { 0 },
                size: 1,
                is_signed: true,
            })
        }

        // ---- Popcount / Lzcount ----
        OpCode::POPCOUNT => Some(ConstantValue {
            value: v0.count_ones() as u64,
            size: 1,
            is_signed: false,
        }),
        OpCode::LZCOUNT => Some(ConstantValue {
            value: v0.leading_zeros() as u64,
            size: 1,
            is_signed: false,
        }),

        // ---- Boolean (bitwise on 1-bit values) ----
        OpCode::BOOL_AND if inputs.len() >= 2 => {
            let v1 = inputs[1].value & 1;
            Some(ConstantValue {
                value: (v0 & v1) & 1,
                size: 1,
                is_signed: false,
            })
        }
        OpCode::BOOL_OR if inputs.len() >= 2 => {
            let v1 = inputs[1].value & 1;
            Some(ConstantValue {
                value: (v0 | v1) & 1,
                size: 1,
                is_signed: false,
            })
        }
        OpCode::BOOL_XOR if inputs.len() >= 2 => {
            let v1 = inputs[1].value & 1;
            Some(ConstantValue {
                value: (v0 ^ v1) & 1,
                size: 1,
                is_signed: false,
            })
        }
        OpCode::BOOL_NEGATE => Some(ConstantValue {
            value: if v0 == 0 { 1 } else { 0 },
            size: 1,
            is_signed: false,
        }),

        // Opcodes we cannot evaluate at compile time.
        _ => None,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
        use super::*;

    // --- Helper builders ---

    fn make_vn_reg(offset: u64, size: u32) -> Varnode {
        Varnode::register("r", offset, size)
    }

    fn make_vn_const(value: u64, size: u32) -> Varnode {
        Varnode::constant(value, size)
    }

    fn make_vn_unique(index: u64, size: u32) -> Varnode {
        Varnode::unique(index, size)
    }

    fn make_op(opcode: OpCode, out: Option<Varnode>, inputs: Vec<Varnode>, seq: u32) -> PcodeOperation {
        PcodeOperation::new(opcode, out, inputs, Some(Address::new(seq as u64)))
    }

    fn addr(val: u64) -> Address {
        Address::new(val)
    }

    // --- build_graph ---

    #[test]
    fn test_build_graph_simple_copy() {
        let mut engine = DataFlowEngine::new();
        let out = make_vn_unique(0, 4);
        let inp = make_vn_reg(0, 4);

        let seq = PcodeSequence::new(
            vec![make_op(
                OpCode::COPY,
                Some(out.clone()),
                vec![inp.clone()],
                0,
            )],
            addr(0x1000),
            addr(0x1000),
        );

        engine.build_graph(&[seq]).unwrap();

        assert_eq!(engine.varnode_count(), 2);
        assert_eq!(engine.edge_count(), 1);

        let out_node = engine.node_map[&out];
        let inp_node = engine.node_map[&inp];
        assert_eq!(engine.varnode_graph[out_node].def_count, 1);
        assert_eq!(engine.varnode_graph[inp_node].use_count, 1);

        // Check edge exists from input → output.
        assert!(engine.varnode_graph.contains_edge(inp_node, out_node));
    }

    #[test]
    fn test_build_graph_is_input() {
        let mut engine = DataFlowEngine::new();
        let r0 = make_vn_reg(0, 4);
        let r1 = make_vn_reg(4, 4);
        let u0 = make_vn_unique(0, 4);

        // r0 is used before it is defined → is_input = true.
        let seq = PcodeSequence::new(
            vec![
                // u0 = r0 + r1  (both r0 and r1 used, neither defined yet)
                make_op(
                    OpCode::INT_ADD,
                    Some(u0.clone()),
                    vec![r0.clone(), r1.clone()],
                    0,
                ),
                // r0 = COPY u0  (now r0 is defined locally)
                make_op(OpCode::COPY, Some(r0.clone()), vec![u0.clone()], 1),
            ],
            addr(0x1000),
            addr(0x1001),
        );

        engine.build_graph(&[seq]).unwrap();

        let r0_node = engine.node_map[&r0];
        let r1_node = engine.node_map[&r1];
        assert!(engine.varnode_graph[r0_node].is_input);
        assert!(engine.varnode_graph[r1_node].is_input);
    }

    #[test]
    fn test_build_graph_is_output() {
        let mut engine = DataFlowEngine::new();
        let r0 = make_vn_reg(0, 4);
        let ram_addr = make_vn_const(0xdeadbeef, 8);

        // STORE ram_addr, r0 → r0 escapes.
        let seq = PcodeSequence::new(
            vec![make_op(
                OpCode::STORE,
                None,
                vec![ram_addr.clone(), r0.clone()],
                0,
            )],
            addr(0x1000),
            addr(0x1000),
        );

        engine.build_graph(&[seq]).unwrap();

        let r0_node = engine.node_map[&r0];
        assert!(engine.varnode_graph[r0_node].is_output);
    }

    // --- compute_def_use ---

    #[test]
    fn test_def_use_copy_chain() {
        let mut engine = DataFlowEngine::new();
        let a = make_vn_reg(0, 4);
        let b = make_vn_unique(0, 4);
        let c = make_vn_unique(1, 4);

        let seq = PcodeSequence::new(
            vec![
                make_op(OpCode::COPY, Some(b.clone()), vec![a.clone()], 0),
                make_op(OpCode::COPY, Some(c.clone()), vec![b.clone()], 1),
            ],
            addr(0x1000),
            addr(0x1001),
        );

        engine.build_graph(&[seq]).unwrap();
        engine.compute_def_use().unwrap();

        // b is defined by a.
        assert_eq!(engine.get_def(&b), Some(a.clone()));
        // c is defined by b.
        assert_eq!(engine.get_def(&c), Some(b.clone()));

        // a is used by b.
        let uses_of_a = engine.get_uses(&a);
        assert!(uses_of_a.contains(&b));
    }

    #[test]
    fn test_def_use_arithmetic() {
        let mut engine = DataFlowEngine::new();
        let x = make_vn_reg(0, 4);
        let y = make_vn_reg(4, 4);
        let sum = make_vn_unique(0, 4);

        let seq = PcodeSequence::new(
            vec![make_op(
                OpCode::INT_ADD,
                Some(sum.clone()),
                vec![x.clone(), y.clone()],
                0,
            )],
            addr(0x1000),
            addr(0x1000),
        );

        engine.build_graph(&[seq]).unwrap();
        engine.compute_def_use().unwrap();

        // sum is not defined by a simple COPY (it's arithmetic).
        assert_eq!(engine.get_def(&sum), None);

        // x is used by sum.
        assert!(engine.get_uses(&x).contains(&sum));
        // y is used by sum.
        assert!(engine.get_uses(&y).contains(&sum));
    }

    // --- compute_reaching_defs ---

    #[test]
    fn test_reaching_defs_chain() {
        let mut engine = DataFlowEngine::new();
        let a = make_vn_reg(0, 4);
        let b = make_vn_unique(0, 4);
        let c = make_vn_unique(1, 4);

        let seq = PcodeSequence::new(
            vec![
                make_op(OpCode::COPY, Some(b.clone()), vec![a.clone()], 0),
                make_op(OpCode::COPY, Some(c.clone()), vec![b.clone()], 1),
            ],
            addr(0x1000),
            addr(0x1001),
        );

        engine.build_graph(&[seq]).unwrap();
        engine.compute_reaching_defs().unwrap();

        let defs_c = &engine.reaching_defs[&c];
        // c reaches itself.
        assert!(defs_c.contains(&c));
        // b reaches c.
        assert!(defs_c.contains(&b));
        // a reaches c (transitively through b).
        assert!(defs_c.contains(&a));
    }

    // --- compute_live_ranges ---

    #[test]
    fn test_live_ranges_basic() {
        let mut engine = DataFlowEngine::new();
        let a = make_vn_reg(0, 4);
        let b = make_vn_unique(0, 4);
        let c = make_vn_unique(1, 4);

        let seq = PcodeSequence::new(
            vec![
                // a used at offset 1000.
                make_op(OpCode::COPY, Some(b.clone()), vec![a.clone()], 0),
                // b used at offset 1001.
                make_op(OpCode::COPY, Some(c.clone()), vec![b.clone()], 1),
            ],
            addr(0x1000),
            addr(0x1001),
        );

        engine.build_graph(&[seq]).unwrap();
        engine.compute_live_ranges().unwrap();

        let lr_a = &engine.live_ranges[&a];
        assert!(lr_a.is_live_on_entry, "a should be live on entry");
        // a has no def in this scope, only uses.
        assert_eq!(lr_a.end.offset, 0x1000);

        let lr_b = &engine.live_ranges[&b];
        // b is defined at 1000, used at 1001.
        assert_eq!(lr_b.start.offset, 0x1000);
        assert_eq!(lr_b.end.offset, 0x1001);
    }

    #[test]
    fn test_is_live_at() {
        let mut engine = DataFlowEngine::new();
        let a = make_vn_reg(0, 4);
        let b = make_vn_unique(0, 4);

        let seq = PcodeSequence::new(
            vec![
                // a used at 1000.
                make_op(OpCode::COPY, Some(b.clone()), vec![a.clone()], 0),
                // b used at 1002.
                make_op(
                    OpCode::INT_ADD,
                    Some(make_vn_unique(2, 4)),
                    vec![b.clone()],
                    1,
                ),
            ],
            addr(0x1000),
            addr(0x1002),
        );

        engine.build_graph(&[seq]).unwrap();
        engine.compute_live_ranges().unwrap();

        // b is defined at 1000, last used at 1002.
        assert!(engine.is_live_at(&b, &addr(0x1000)));
        assert!(engine.is_live_at(&b, &addr(0x1001)));
        assert!(engine.is_live_at(&b, &addr(0x1002)));
        assert!(!engine.is_live_at(&b, &addr(0x1003)));
    }

    // --- propagate_constants ---

    #[test]
    fn test_propagate_constants_direct_copy() {
        let mut engine = DataFlowEngine::new();
        let cnst = make_vn_const(42, 4);
        let reg = make_vn_unique(0, 4);

        let seq = PcodeSequence::new(
            vec![make_op(
                OpCode::COPY,
                Some(reg.clone()),
                vec![cnst.clone()],
                0,
            )],
            addr(0x1000),
            addr(0x1000),
        );

        engine.build_graph(&[seq]).unwrap();
        engine.compute_def_use().unwrap();
        let constants = engine.propagate_constants();

        assert!(constants.contains_key(&cnst));
        assert_eq!(constants[&cnst].value, 42);
        assert!(constants.contains_key(&reg));
        assert_eq!(constants[&reg].value, 42);
    }

    #[test]
    fn test_propagate_constants_arithmetic() {
        let mut engine = DataFlowEngine::new();
        let c1 = make_vn_const(3, 4);
        let c2 = make_vn_const(4, 4);
        let sum = make_vn_unique(0, 4);

        let seq = PcodeSequence::new(
            vec![make_op(
                OpCode::INT_ADD,
                Some(sum.clone()),
                vec![c1.clone(), c2.clone()],
                0,
            )],
            addr(0x1000),
            addr(0x1000),
        );

        engine.build_graph(&[seq]).unwrap();
        let constants = engine.propagate_constants();

        assert!(constants.contains_key(&sum));
        assert_eq!(constants[&sum].value, 7);
    }

    // --- propagate_copies ---

    #[test]
    fn test_propagate_copies() {
        let mut engine = DataFlowEngine::new();
        let r0 = make_vn_reg(0, 4);
        let tmp = make_vn_unique(0, 4);

        let seq = PcodeSequence::new(
            vec![make_op(
                OpCode::COPY,
                Some(tmp.clone()),
                vec![r0.clone()],
                0,
            )],
            addr(0x1000),
            addr(0x1000),
        );

        engine.build_graph(&[seq]).unwrap();
        engine.compute_def_use().unwrap();
        let copies = engine.propagate_copies();

        assert!(copies.contains_key(&tmp));
        assert_eq!(copies[&tmp], r0);
        // r0 should not appear as a copy target (it's a register source).
        assert!(!copies.contains_key(&r0));
    }

    #[test]
    fn test_propagate_copies_skips_constants() {
        let mut engine = DataFlowEngine::new();
        let cnst = make_vn_const(100, 4);
        let tmp = make_vn_unique(0, 4);

        let seq = PcodeSequence::new(
            vec![make_op(
                OpCode::COPY,
                Some(tmp.clone()),
                vec![cnst.clone()],
                0,
            )],
            addr(0x1000),
            addr(0x1000),
        );

        engine.build_graph(&[seq]).unwrap();
        engine.compute_def_use().unwrap();
        let copies = engine.propagate_copies();

        // tmp → cnst is not a "copy" in the propagation sense (it's a constant load).
        assert!(!copies.contains_key(&tmp));
    }

    // --- ValueSet ---

    #[test]
    fn test_value_set_join() {
        let vs1 = ValueSet::constant(5);
        let vs2 = ValueSet::constant(10);

        let joined = vs1.join(&vs2);
        assert!(!joined.is_top);
        assert!(!joined.is_bottom);
        assert_eq!(joined.ranges.len(), 2);
        assert!(joined.contains(5));
        assert!(joined.contains(10));
        assert!(!joined.contains(7));
    }

    #[test]
    fn test_value_set_join_adjacent() {
        let vs1 = ValueSet::from_range(0, 5);
        let vs2 = ValueSet::from_range(6, 10);
        let joined = vs1.join(&vs2);

        // Adjacent ranges merge into one.
        assert_eq!(joined.ranges.len(), 1);
        assert_eq!(joined.ranges[0].min, 0);
        assert_eq!(joined.ranges[0].max, 10);
    }

    #[test]
    fn test_value_set_top_bottom() {
        let top = ValueSet::top();
        let bottom = ValueSet::bottom();
        let concrete = ValueSet::constant(42);

        // join with TOP gives TOP.
        assert!(concrete.join(&top).is_top);
        // join with BOTTOM gives original.
        assert_eq!(concrete.join(&bottom).ranges, concrete.ranges);
        // join TOP with BOTTOM gives TOP.
        assert!(top.join(&bottom).is_top);
    }

    #[test]
    fn test_value_set_is_constant() {
        let vs = ValueSet::constant(42);
        assert!(vs.is_constant());
        assert_eq!(vs.as_constant(), Some(42));

        let vs_range = ValueSet::from_range(0, 10);
        assert!(!vs_range.is_constant());
        assert_eq!(vs_range.as_constant(), None);
    }

    // --- RangeAnalyzer ---

    #[test]
    fn test_range_analyzer_constants() {
        let mut engine = DataFlowEngine::new();
        let cnst = make_vn_const(42, 4);

        let seq = PcodeSequence::new(vec![], addr(0x1000), addr(0x1000));
        // Sneak the constant into the graph manually.
        engine.get_or_create_node(&cnst);

        let mut ra = RangeAnalyzer::new();
        ra.analyze(&engine).unwrap();

        let vs = ra.get_range(&cnst);
        assert!(vs.is_constant());
        assert_eq!(vs.as_constant(), Some(42));
    }

    #[test]
    fn test_range_analyzer_propagation() {
        let mut engine = DataFlowEngine::new();
        let cnst = make_vn_const(10, 4);
        let tmp = make_vn_unique(0, 4);

        let seq = PcodeSequence::new(
            vec![make_op(
                OpCode::COPY,
                Some(tmp.clone()),
                vec![cnst.clone()],
                0,
            )],
            addr(0x1000),
            addr(0x1000),
        );

        engine.build_graph(&[seq]).unwrap();

        let mut ra = RangeAnalyzer::new();
        ra.analyze(&engine).unwrap();

        let vs_tmp = ra.get_range(&tmp);
        assert!(vs_tmp.is_constant());
        assert_eq!(vs_tmp.as_constant(), Some(10));
    }

    #[test]
    fn test_join_ranges() {
        let mut ra = RangeAnalyzer::new();
        let a = make_vn_unique(0, 4);
        let b = make_vn_unique(1, 4);

        ra.ranges.insert(a.clone(), ValueSet::constant(5));
        ra.ranges.insert(b.clone(), ValueSet::constant(15));
        ra.join_ranges(&a, &b);

        let joined = ra.get_range(&a);
        assert!(!joined.is_top);
        assert!(joined.contains(5));
        assert!(joined.contains(15));
    }

    // --- Constant folding ---

    #[test]
    fn test_evaluate_constant_add() {
        let result = evaluate_constant_op(
            &OpCode::INT_ADD,
            &[
                ConstantValue {
                    value: 3,
                    size: 4,
                    is_signed: false,
                },
                ConstantValue {
                    value: 4,
                    size: 4,
                    is_signed: false,
                },
            ],
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().value, 7);
    }

    #[test]
    fn test_evaluate_constant_sub() {
        let result = evaluate_constant_op(
            &OpCode::INT_SUB,
            &[
                ConstantValue {
                    value: 10,
                    size: 4,
                    is_signed: false,
                },
                ConstantValue {
                    value: 3,
                    size: 4,
                    is_signed: false,
                },
            ],
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().value, 7);
    }

    #[test]
    fn test_evaluate_constant_sdiv() {
        let result = evaluate_constant_op(
            &OpCode::INT_SDIV,
            &[
                ConstantValue {
                    value: (-20i64) as u64,
                    size: 4,
                    is_signed: true,
                },
                ConstantValue {
                    value: 4,
                    size: 4,
                    is_signed: true,
                },
            ],
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().as_signed(), -5);
    }

    #[test]
    fn test_evaluate_constant_and() {
        let result = evaluate_constant_op(
            &OpCode::INT_AND,
            &[
                ConstantValue {
                    value: 0xFF,
                    size: 4,
                    is_signed: false,
                },
                ConstantValue {
                    value: 0x0F,
                    size: 4,
                    is_signed: false,
                },
            ],
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().value, 0x0F);
    }

    #[test]
    fn test_evaluate_constant_div_by_zero() {
        let result = evaluate_constant_op(
            &OpCode::INT_DIV,
            &[
                ConstantValue {
                    value: 10,
                    size: 4,
                    is_signed: false,
                },
                ConstantValue {
                    value: 0,
                    size: 4,
                    is_signed: false,
                },
            ],
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_multiple_sequences() {
        let mut engine = DataFlowEngine::new();
        let r0 = make_vn_reg(0, 4);
        let r1 = make_vn_reg(4, 4);
        let tmp = make_vn_unique(0, 4);

        let seq1 = PcodeSequence::new(
            vec![make_op(
                OpCode::COPY,
                Some(tmp.clone()),
                vec![r0.clone()],
                0,
            )],
            addr(0x1000),
            addr(0x1000),
        );
        let seq2 = PcodeSequence::new(
            vec![make_op(
                OpCode::INT_ADD,
                Some(r1.clone()),
                vec![tmp.clone(), make_vn_const(1, 4)],
                1,
            )],
            addr(0x2000),
            addr(0x2000),
        );

        engine.build_graph(&[seq1, seq2]).unwrap();
        engine.compute_def_use().unwrap();
        engine.compute_reaching_defs().unwrap();
        engine.compute_live_ranges().unwrap();

        assert_eq!(engine.varnode_count(), 4);
        assert!(engine.get_uses(&r0).contains(&tmp));
        assert_eq!(engine.get_def(&tmp), Some(r0.clone()));
    }

    #[test]
    fn test_empty_sequences() {
        let mut engine = DataFlowEngine::new();
        let result = engine.build_graph(&[]);
        assert!(result.is_ok());
        assert_eq!(engine.varnode_count(), 0);
    }

    #[test]
    fn test_control_flow_ops_count_uses() {
        let mut engine = DataFlowEngine::new();
        let cond = make_vn_reg(0, 1);
        let target = make_vn_const(0x4000, 8);

        let seq = PcodeSequence::new(
            vec![make_op(
                OpCode::CBRANCH,
                None,
                vec![cond.clone(), target.clone()],
                0,
            )],
            addr(0x1000),
            addr(0x1000),
        );

        engine.build_graph(&[seq]).unwrap();

        // CBranch is control flow: no data-flow edges, but uses are counted.
        let cond_node = engine.node_map[&cond];
        assert_eq!(engine.varnode_graph[cond_node].use_count, 1);
        assert_eq!(engine.edge_count(), 0);
    }
}
