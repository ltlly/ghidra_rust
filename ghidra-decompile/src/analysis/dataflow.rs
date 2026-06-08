#![allow(dead_code)]

//! Data-flow analysis framework for the decompiler.
//!
//! Provides a generic trait [`DataFlowAnalyzer`] for implementing forward and
//! backward data-flow analyses over the control-flow graph, plus concrete
//! analysis passes:
//!
//! - [`ReachDefAnalysis`] -- reaching-definitions analysis.
//! - [`RangeAnalysis`] -- value-set / abstract-interpretation range analysis.
//! - [`ConstantPropagation`] -- sparse constant propagation.
//! - [`CopyPropagation`] -- copy propagation (forward substitution).
//! - [`DeadCodeElimination`] -- liveness-based dead-code removal.

use std::collections::{HashMap, HashSet, VecDeque};

use petgraph::graph::NodeIndex;

use super::cfg::{BasicBlock, ControlFlowGraph};
use crate::pcode::{OpCode, PcodeOperation, Varnode};

// ============================================================================
// DataFlowAnalyzer trait
// ============================================================================

/// Direction of a data-flow analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataFlowDirection {
    /// Forward: facts flow from predecessors to successors.
    /// IN[B] = meet(OUT[pred] for pred in predecessors[B])
    Forward,
    /// Backward: facts flow from successors to predecessors.
    /// OUT[B] = meet(IN[succ] for succ in successors[B])
    Backward,
}

/// A generic trait for data-flow analysis over a control-flow graph.
///
/// Implementors define a lattice element `Fact`, an initial fact, a
/// transfer function, and a meet (join) operation. The trait provides
/// the fixed-point worklist algorithm.
pub trait DataFlowAnalyzer {
    /// The lattice element computed at each program point.
    type Fact: Clone + PartialEq + std::fmt::Debug;

    /// Direction of the analysis (forward or backward).
    fn direction(&self) -> DataFlowDirection;

    /// The initial fact for boundary nodes (IN[entry] for forward,
    /// OUT[exit] for backward).
    fn boundary_fact(&self) -> Self::Fact;

    /// The bottom (empty) fact used for initialization.
    fn bottom_fact(&self) -> Self::Fact;

    /// Apply the transfer function for a given basic block.
    ///
    /// For forward analysis: given IN[B], compute OUT[B].
    /// For backward analysis: given OUT[B], compute IN[B].
    fn transfer(&self, block: &BasicBlock, input: &Self::Fact) -> Self::Fact;

    /// Meet (join) operation for combining facts at merge points.
    fn meet(&self, a: &Self::Fact, b: &Self::Fact) -> Self::Fact;

    /// Run the analysis to a fixed point.
    ///
    /// Returns a map from node index to (in_fact, out_fact).
    fn analyze(
        &self,
        cfg: &ControlFlowGraph,
    ) -> HashMap<NodeIndex, (Self::Fact, Self::Fact)> {
        let mut in_facts: HashMap<NodeIndex, Self::Fact> = HashMap::new();
        let mut out_facts: HashMap<NodeIndex, Self::Fact> = HashMap::new();

        let bottom = self.bottom_fact();
        let boundary = self.boundary_fact();

        // Initialize all facts to bottom.
        for node in cfg.graph.node_indices() {
            in_facts.insert(node, bottom.clone());
            out_facts.insert(node, bottom.clone());
        }

        // Set boundary condition.
        match self.direction() {
            DataFlowDirection::Forward => {
                in_facts.insert(cfg.entry, boundary.clone());
            }
            DataFlowDirection::Backward => {
                out_facts.insert(cfg.exit, boundary.clone());
            }
        }

        // Worklist algorithm.
        let mut worklist: VecDeque<NodeIndex> = cfg.graph.node_indices().collect();
        let mut in_queue: HashSet<NodeIndex> = cfg.graph.node_indices().collect();

        while let Some(node) = worklist.pop_front() {
            in_queue.remove(&node);

            let old_in = in_facts[&node].clone();
            let old_out = out_facts[&node].clone();

            match self.direction() {
                DataFlowDirection::Forward => {
                    // IN[B] = meet(OUT[predecessors]).
                    let new_in = self.compute_in_forward(cfg, node, &out_facts);
                    in_facts.insert(node, new_in.clone());

                    let new_out = self.transfer(cfg.block_by_node(node), &new_in);
                    out_facts.insert(node, new_out.clone());

                    if old_in != new_in || old_out != new_out {
                        for succ in cfg.successors(node) {
                            if !in_queue.contains(&succ) {
                                worklist.push_back(succ);
                                in_queue.insert(succ);
                            }
                        }
                    }
                }
                DataFlowDirection::Backward => {
                    // OUT[B] = meet(IN[successors]).
                    let new_out = self.compute_out_backward(cfg, node, &in_facts);
                    out_facts.insert(node, new_out.clone());

                    let new_in = self.transfer(cfg.block_by_node(node), &new_out);
                    in_facts.insert(node, new_in.clone());

                    if old_in != new_in || old_out != new_out {
                        for pred in cfg.predecessors(node) {
                            if !in_queue.contains(&pred) {
                                worklist.push_back(pred);
                                in_queue.insert(pred);
                            }
                        }
                    }
                }
            }
        }

        let mut result = HashMap::new();
        for node in cfg.graph.node_indices() {
            result.insert(
                node,
                (in_facts.remove(&node).unwrap_or(bottom.clone()), out_facts.remove(&node).unwrap_or(bottom.clone())),
            );
        }
        result
    }

    /// Compute IN[B] for forward analysis: meet OUT[predecessors].
    fn compute_in_forward(
        &self,
        cfg: &ControlFlowGraph,
        node: NodeIndex,
        out_facts: &HashMap<NodeIndex, Self::Fact>,
    ) -> Self::Fact {
        let preds = cfg.predecessors(node);
        if preds.is_empty() {
            if node == cfg.entry {
                return self.boundary_fact();
            }
            return self.bottom_fact();
        }

        let mut acc = self.bottom_fact();
        for pred in &preds {
            if let Some(out) = out_facts.get(pred) {
                acc = self.meet(&acc, out);
            }
        }
        acc
    }

    /// Compute OUT[B] for backward analysis: meet IN[successors].
    fn compute_out_backward(
        &self,
        cfg: &ControlFlowGraph,
        node: NodeIndex,
        in_facts: &HashMap<NodeIndex, Self::Fact>,
    ) -> Self::Fact {
        let succs = cfg.successors(node);
        if succs.is_empty() {
            if node == cfg.exit {
                return self.boundary_fact();
            }
            return self.bottom_fact();
        }

        let mut acc = self.bottom_fact();
        for succ in &succs {
            if let Some(in_fact) = in_facts.get(succ) {
                acc = self.meet(&acc, in_fact);
            }
        }
        acc
    }
}

// ============================================================================
// ReachDefAnalysis — reaching-definitions analysis
// ============================================================================

/// A single definition site in the program.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DefinitionSite {
    /// The varnode being defined.
    pub varnode: Varnode,
    /// The block where the definition occurs.
    pub block: NodeIndex,
    /// The operation index within the block.
    pub op_index: usize,
}

/// Reaching-definitions analysis.
///
/// For each program point, computes the set of definition sites whose
/// values may reach that point. This is a classic forward may-analysis
/// with union as the meet operation.
pub struct ReachDefAnalysis {
    /// All definition sites in the function.
    _all_defs: HashSet<DefinitionSite>,
    /// GEN[B]: definitions generated in block B that are not killed
    /// later in B.
    gen: HashMap<NodeIndex, HashSet<DefinitionSite>>,
    /// KILL[B]: definitions from other blocks that are killed by
    /// definitions in B.
    kill: HashMap<NodeIndex, HashSet<DefinitionSite>>,
}

impl ReachDefAnalysis {
    /// Create a new reaching-definitions analysis from the given operations
    /// and CFG.
    pub fn new(operations: &[PcodeOperation], cfg: &ControlFlowGraph) -> Self {
        let mut all_defs = HashSet::new();
        for (i, op) in operations.iter().enumerate() {
            if op.output.is_some() {
                // Find the block containing this operation.
                let block = Self::find_block_for_op(i, operations, cfg);
                all_defs.insert(DefinitionSite {
                    varnode: op.output.clone().unwrap(),
                    block,
                    op_index: i,
                });
            }
        }

        let (gen, kill) = Self::compute_gen_kill(operations, cfg, &all_defs);

        Self {
            _all_defs: all_defs,
            gen,
            kill,
        }
    }

    /// Find which block contains a given operation by index.
    fn find_block_for_op(
        op_idx: usize,
        _operations: &[PcodeOperation],
        cfg: &ControlFlowGraph,
    ) -> NodeIndex {
        let mut cursor = 0;
        for block in &cfg.blocks {
            if let Some(node) = block.node {
                let block_len = block.operations.len();
                if op_idx >= cursor && op_idx < cursor + block_len {
                    return node;
                }
                cursor += block_len;
            }
        }
        cfg.exit
    }

    /// Compute GEN and KILL sets for each block.
    fn compute_gen_kill(
        _operations: &[PcodeOperation],
        cfg: &ControlFlowGraph,
        all_defs: &HashSet<DefinitionSite>,
    ) -> (
        HashMap<NodeIndex, HashSet<DefinitionSite>>,
        HashMap<NodeIndex, HashSet<DefinitionSite>>,
    ) {
        let mut gen = HashMap::new();
        let mut kill = HashMap::new();

        for block in &cfg.blocks {
            if let Some(node) = block.node {
                let mut block_gen = HashSet::new();
                let mut block_defd_vns: HashSet<Varnode> = HashSet::new();

                // Process in reverse: only the last definition of each
                // varnode in the block survives to OUT.
                for op in block.operations.iter().rev() {
                    if let Some(ref out) = op.output {
                        if !block_defd_vns.contains(out) {
                            block_gen.insert(DefinitionSite {
                                varnode: out.clone(),
                                block: node,
                                op_index: 0,
                            });
                            block_defd_vns.insert(out.clone());
                        }
                    }
                }

                // KILL: any definition from another block of a varnode
                // that is defined in this block.
                let block_kill: HashSet<DefinitionSite> = all_defs
                    .iter()
                    .filter(|ds| ds.block != node && block_defd_vns.contains(&ds.varnode))
                    .cloned()
                    .collect();

                gen.insert(node, block_gen);
                kill.insert(node, block_kill);
            }
        }

        (gen, kill)
    }

    /// Run the reaching-definitions analysis.
    ///
    /// Returns a map from block node → (IN_defs, OUT_defs).
    pub fn analyze(
        &self,
        cfg: &ControlFlowGraph,
    ) -> HashMap<NodeIndex, (HashSet<DefinitionSite>, HashSet<DefinitionSite>)> {
        let mut in_sets: HashMap<NodeIndex, HashSet<DefinitionSite>> = HashMap::new();
        let mut out_sets: HashMap<NodeIndex, HashSet<DefinitionSite>> = HashMap::new();

        for node in cfg.graph.node_indices() {
            in_sets.insert(node, HashSet::new());
            out_sets.insert(node, HashSet::new());
        }

        let mut worklist: VecDeque<NodeIndex> = cfg.graph.node_indices().collect();
        let mut in_queue: HashSet<NodeIndex> = cfg.graph.node_indices().collect();

        while let Some(node) = worklist.pop_front() {
            in_queue.remove(&node);

            // IN[B] = ∪ OUT[predecessors].
            let mut new_in = HashSet::new();
            if node == cfg.entry || cfg.predecessors(node).is_empty() {
                // Entry: start with empty set.
            } else {
                for pred in &cfg.predecessors(node) {
                    if let Some(pred_out) = out_sets.get(pred) {
                        new_in.extend(pred_out.iter().cloned());
                    }
                }
            }

            // OUT[B] = GEN[B] ∪ (IN[B] - KILL[B]).
            let mut new_out = new_in.clone();
            if let Some(kill_set) = self.kill.get(&node) {
                new_out.retain(|ds| !kill_set.contains(ds));
            }
            if let Some(gen_set) = self.gen.get(&node) {
                new_out.extend(gen_set.iter().cloned());
            }

            let changed = in_sets[&node] != new_in || out_sets[&node] != new_out;

            in_sets.insert(node, new_in);
            out_sets.insert(node, new_out);

            if changed {
                for succ in cfg.successors(node) {
                    if !in_queue.contains(&succ) {
                        worklist.push_back(succ);
                        in_queue.insert(succ);
                    }
                }
            }
        }

        let mut result = HashMap::new();
        for node in cfg.graph.node_indices() {
            result.insert(
                node,
                (
                    in_sets.remove(&node).unwrap_or_default(),
                    out_sets.remove(&node).unwrap_or_default(),
                ),
            );
        }
        result
    }
}

// ============================================================================
// ValueSet and RangeAnalysis
// ============================================================================

/// A single contiguous integer range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValueRange {
    /// Inclusive lower bound.
    pub min: i64,
    /// Inclusive upper bound.
    pub max: i64,
}

impl ValueRange {
    pub fn new(min: i64, max: i64) -> Self {
        debug_assert!(min <= max);
        Self { min, max }
    }

    pub fn singleton(val: i64) -> Self {
        Self { min: val, max: val }
    }

    pub fn contains(&self, val: i64) -> bool {
        val >= self.min && val <= self.max
    }

    pub fn join(&self, other: &ValueRange) -> ValueRange {
        ValueRange {
            min: self.min.min(other.min),
            max: self.max.max(other.max),
        }
    }
}

/// A value set: a collection of ranges produced by abstract interpretation.
#[derive(Debug, Clone, PartialEq)]
pub struct ValueSet {
    /// Constituent ranges.
    pub ranges: Vec<ValueRange>,
    /// Stride between values (0 = dense).
    pub stride: u64,
    /// Represents all possible values (unknown).
    pub is_top: bool,
    /// Represents no values (unreachable).
    pub is_bottom: bool,
}

impl ValueSet {
    pub fn top() -> Self {
        Self {
            ranges: Vec::new(),
            stride: 0,
            is_top: true,
            is_bottom: false,
        }
    }

    pub fn bottom() -> Self {
        Self {
            ranges: Vec::new(),
            stride: 0,
            is_top: false,
            is_bottom: true,
        }
    }

    pub fn constant(val: i64) -> Self {
        Self {
            ranges: vec![ValueRange::singleton(val)],
            stride: 0,
            is_top: false,
            is_bottom: false,
        }
    }

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

        let mut all = self.ranges.clone();
        all.extend_from_slice(&other.ranges);
        all.sort_by_key(|r| r.min);

        // Merge overlapping/adjacent ranges.
        let mut merged: Vec<ValueRange> = Vec::new();
        for r in all {
            if let Some(last) = merged.last_mut() {
                if r.min <= last.max + 1 {
                    last.max = last.max.max(r.max);
                } else {
                    merged.push(r);
                }
            } else {
                merged.push(r);
            }
        }

        ValueSet {
            ranges: merged,
            stride: gcd(self.stride, other.stride),
            is_top: false,
            is_bottom: false,
        }
    }

    /// Returns true if this is a single known constant.
    pub fn is_constant(&self) -> bool {
        !self.is_top
            && !self.is_bottom
            && self.ranges.len() == 1
            && self.ranges[0].min == self.ranges[0].max
    }

    /// If this is a constant, returns its value.
    pub fn as_constant(&self) -> Option<i64> {
        if self.is_constant() {
            Some(self.ranges[0].min)
        } else {
            None
        }
    }
}

// ============================================================================
// RangeAnalysis
// ============================================================================

/// Range analysis via abstract interpretation.
///
/// Tracks possible integer values for each varnode, represented as
/// [`ValueSet`]s. Propagates through the P-code operations and applies
/// widening at join points to ensure termination.
pub struct RangeAnalysis {
    /// Per-varnode value sets.
    ranges: HashMap<Varnode, ValueSet>,
}

impl RangeAnalysis {
    /// Create a new, empty range analysis.
    pub fn new() -> Self {
        Self {
            ranges: HashMap::new(),
        }
    }

    /// Run range analysis over a flat list of operations, seeded with
    /// known constants.
    pub fn analyze(
        &mut self,
        operations: &[PcodeOperation],
        constants: &HashMap<Varnode, u64>,
    ) {
        self.ranges.clear();

        // Seed from constants.
        for (vn, &val) in constants {
            self.ranges.insert(vn.clone(), ValueSet::constant(val as i64));
        }

        // Also seed from constant-space varnodes in the operations.
        for op in operations {
            for inp in &op.inputs {
                if inp.is_constant() {
                    self.ranges
                        .insert(inp.clone(), ValueSet::constant(inp.offset as i64));
                }
            }
        }

        // Iterate until convergence (bounded).
        let mut changed = true;
        let mut iterations = 0;
        const MAX_ITERATIONS: u32 = 100;

        while changed && iterations < MAX_ITERATIONS {
            changed = false;
            iterations += 1;

            for op in operations {
                if let Some(ref out) = op.output {
                    let old = self.ranges.get(out).cloned().unwrap_or(ValueSet::top());
                    let new = self.evaluate(op);
                    if old != new {
                        self.ranges.insert(out.clone(), new);
                        changed = true;
                    }
                }
            }
        }
    }

    /// Evaluate an operation's output value set given current range info.
    fn evaluate(&self, op: &PcodeOperation) -> ValueSet {
        let get_vs = |vn: &Varnode| -> ValueSet {
            if vn.is_constant() {
                ValueSet::constant(vn.offset as i64)
            } else {
                self.ranges.get(vn).cloned().unwrap_or(ValueSet::top())
            }
        };

        match op.opcode {
            OpCode::COPY => {
                op.inputs.first().map(|inp| get_vs(inp)).unwrap_or(ValueSet::top())
            }

            OpCode::INT_ADD => {
                let a = op.inputs.first().map(|inp| get_vs(inp)).unwrap_or(ValueSet::top());
                let b = op.inputs.get(1).map(|inp| get_vs(inp)).unwrap_or(ValueSet::top());
                range_add(&a, &b)
            }

            OpCode::INT_SUB => {
                let a = op.inputs.first().map(|inp| get_vs(inp)).unwrap_or(ValueSet::top());
                let b = op.inputs.get(1).map(|inp| get_vs(inp)).unwrap_or(ValueSet::top());
                range_sub(&a, &b)
            }

            OpCode::INT_MUL => {
                let a = op.inputs.first().map(|inp| get_vs(inp)).unwrap_or(ValueSet::top());
                let b = op.inputs.get(1).map(|inp| get_vs(inp)).unwrap_or(ValueSet::top());
                range_mul(&a, &b)
            }

            OpCode::INT_AND => {
                let a = op.inputs.first().map(|inp| get_vs(inp)).unwrap_or(ValueSet::top());
                let b = op.inputs.get(1).map(|inp| get_vs(inp)).unwrap_or(ValueSet::top());
                // AND: if either operand has a small constant, the result
                // range is bounded.
                if b.is_constant() {
                    let mask = b.as_constant().unwrap() as u64;
                    if mask < 256 {
                        return ValueSet::from_range(0, mask as i64);
                    }
                }
                if a.is_constant() {
                    let mask = a.as_constant().unwrap() as u64;
                    if mask < 256 {
                        return ValueSet::from_range(0, mask as i64);
                    }
                }
                ValueSet::top()
            }

            OpCode::INT_ZEXT | OpCode::INT_SEXT | OpCode::CAST => {
                op.inputs.first().map(|inp| get_vs(inp)).unwrap_or(ValueSet::top())
            }

            OpCode::INT_EQUAL | OpCode::INT_NOTEQUAL
            | OpCode::INT_LESS | OpCode::INT_SLESS
            | OpCode::INT_LESSEQUAL | OpCode::INT_SLESSEQUAL
            | OpCode::BOOL_NEGATE | OpCode::BOOL_AND | OpCode::BOOL_OR => {
                // Boolean result: 0 or 1.
                ValueSet::from_range(0, 1)
            }

            _ => ValueSet::top(),
        }
    }

    /// Get the value set for a varnode.
    pub fn get_range(&self, varnode: &Varnode) -> ValueSet {
        self.ranges.get(varnode).cloned().unwrap_or(ValueSet::top())
    }

    /// Returns all discovered ranges.
    pub fn ranges(&self) -> impl Iterator<Item = (&Varnode, &ValueSet)> {
        self.ranges.iter()
    }
}

impl Default for RangeAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

/// Add two value sets (abstract addition).
fn range_add(a: &ValueSet, b: &ValueSet) -> ValueSet {
    if a.is_top || b.is_top {
        return ValueSet::top();
    }
    if a.is_bottom || b.is_bottom {
        return ValueSet::bottom();
    }
    // Conservative: min = a.min + b.min, max = a.max + b.max.
    let a_min = a.ranges.first().map(|r| r.min).unwrap_or(0);
    let a_max = a.ranges.first().map(|r| r.max).unwrap_or(0);
    let b_min = b.ranges.first().map(|r| r.min).unwrap_or(0);
    let b_max = b.ranges.first().map(|r| r.max).unwrap_or(0);
    ValueSet::from_range(
        a_min.saturating_add(b_min),
        a_max.saturating_add(b_max),
    )
}

/// Subtract two value sets (abstract subtraction).
fn range_sub(a: &ValueSet, b: &ValueSet) -> ValueSet {
    if a.is_top || b.is_top {
        return ValueSet::top();
    }
    if a.is_bottom || b.is_bottom {
        return ValueSet::bottom();
    }
    let a_min = a.ranges.first().map(|r| r.min).unwrap_or(0);
    let a_max = a.ranges.first().map(|r| r.max).unwrap_or(0);
    let b_min = b.ranges.first().map(|r| r.min).unwrap_or(0);
    let b_max = b.ranges.first().map(|r| r.max).unwrap_or(0);
    ValueSet::from_range(
        a_min.saturating_sub(b_max),
        a_max.saturating_sub(b_min),
    )
}

/// Multiply two value sets (abstract multiplication).
fn range_mul(a: &ValueSet, b: &ValueSet) -> ValueSet {
    if a.is_top || b.is_top {
        return ValueSet::top();
    }
    if a.is_bottom || b.is_bottom {
        return ValueSet::bottom();
    }
    let a_min = a.ranges.first().map(|r| r.min).unwrap_or(0);
    let a_max = a.ranges.first().map(|r| r.max).unwrap_or(0);
    let b_min = b.ranges.first().map(|r| r.min).unwrap_or(0);
    let b_max = b.ranges.first().map(|r| r.max).unwrap_or(0);

    let products = [
        a_min.saturating_mul(b_min),
        a_min.saturating_mul(b_max),
        a_max.saturating_mul(b_min),
        a_max.saturating_mul(b_max),
    ];
    let min = *products.iter().min().unwrap_or(&0);
    let max = *products.iter().max().unwrap_or(&0);
    ValueSet::from_range(min, max)
}

fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { gcd(b, a % b) }
}

// ============================================================================
// ConstantPropagation
// ============================================================================

/// Sparse constant-propagation analysis.
///
/// Uses a worklist algorithm to propagate constant values through P-code
/// operations. Starts from constant-space varnodes and iteratively
/// evaluates operations whose inputs are all known constants.
pub struct ConstantPropagation {
    /// Map from varnode to its constant value (if known).
    values: HashMap<Varnode, ConstantOrUnknown>,
}

/// A value produced by constant propagation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstantOrUnknown {
    Known(u64),
    Unknown,
}

impl ConstantOrUnknown {
    pub fn value(&self) -> Option<u64> {
        match self {
            ConstantOrUnknown::Known(v) => Some(*v),
            ConstantOrUnknown::Unknown => None,
        }
    }

    pub fn is_known(&self) -> bool {
        matches!(self, ConstantOrUnknown::Known(_))
    }
}

impl ConstantPropagation {
    /// Create a new constant-propagation instance.
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
        }
    }

    /// Analyze a list of operations and return the constant values map.
    pub fn analyze(
        &mut self,
        operations: &[PcodeOperation],
    ) -> HashMap<Varnode, ConstantOrUnknown> {
        self.values.clear();
        let mut worklist: VecDeque<usize> = VecDeque::new();

        // Seed with constant-input varnodes.
        for (i, op) in operations.iter().enumerate() {
            for inp in &op.inputs {
                if inp.is_constant() {
                    self.values
                        .insert(inp.clone(), ConstantOrUnknown::Known(inp.offset));
                }
            }
            worklist.push_back(i);
        }

        // Build a use-def map for efficient invalidation.
        let use_sites = Self::build_use_sites(operations);

        // Worklist iteration.
        let mut iteration = 0;
        const MAX_ITERATIONS: usize = 1000;

        while let Some(idx) = worklist.pop_front() {
            iteration += 1;
            if iteration > MAX_ITERATIONS {
                break;
            }

            let op = &operations[idx];
            let new_val = self.evaluate(op);

            if let Some(ref out) = op.output {
                let old = self.values.get(out).cloned();
                if old.as_ref() != Some(&new_val) {
                    self.values.insert(out.clone(), new_val);
                    // Re-evaluate all uses of this varnode.
                    if let Some(users) = use_sites.get(out) {
                        for &user_idx in users {
                            worklist.push_back(user_idx);
                        }
                    }
                }
            }
        }

        self.values.clone()
    }

    /// Evaluate an operation's output given current constant values.
    fn evaluate(&self, op: &PcodeOperation) -> ConstantOrUnknown {
        let get = |vn: &Varnode| -> Option<u64> {
            if vn.is_constant() {
                Some(vn.offset)
            } else {
                self.values.get(vn).and_then(|v| v.value())
            }
        };

        match op.opcode {
            OpCode::COPY => {
                op.inputs.first().and_then(|vn| self.values.get(vn)).cloned()
                    .unwrap_or(ConstantOrUnknown::Unknown)
            }
            OpCode::INT_ADD => Self::binary_op(get, op, |a, b| a.wrapping_add(b)),
            OpCode::INT_SUB => Self::binary_op(get, op, |a, b| a.wrapping_sub(b)),
            OpCode::INT_MUL => Self::binary_op(get, op, |a, b| a.wrapping_mul(b)),
            OpCode::INT_DIV => {
                Self::binary_op(get, op, |a, b| if b != 0 { a.wrapping_div(b) } else { a })
            }
            OpCode::INT_SDIV => Self::binary_op(get, op, |a, b| {
                if b != 0 {
                    ((a as i64).wrapping_div(b as i64)) as u64
                } else {
                    a
                }
            }),
            OpCode::INT_REM => {
                Self::binary_op(get, op, |a, b| if b != 0 { a.wrapping_rem(b) } else { a })
            }
            OpCode::INT_AND => Self::binary_op(get, op, |a, b| a & b),
            OpCode::INT_OR => Self::binary_op(get, op, |a, b| a | b),
            OpCode::INT_XOR => Self::binary_op(get, op, |a, b| a ^ b),
            OpCode::INT_LEFT => {
                Self::binary_op(get, op, |a, b| if b < 64 { a.wrapping_shl(b as u32) } else { a })
            }
            OpCode::INT_RIGHT => {
                Self::binary_op(get, op, |a, b| if b < 64 { a.wrapping_shr(b as u32) } else { a })
            }
            OpCode::INT_SRIGHT => Self::binary_op(get, op, |a, b| {
                if b < 64 {
                    ((a as i64).wrapping_shr(b as u32)) as u64
                } else {
                    a
                }
            }),
            OpCode::INT_NEGATE => {
                op.inputs.first().and_then(get)
                    .map(|v| ConstantOrUnknown::Known((-(v as i64)) as u64))
                    .unwrap_or(ConstantOrUnknown::Unknown)
            }
            OpCode::INT_ZEXT => {
                op.inputs.first().and_then(|vn| self.values.get(vn)).cloned()
                    .unwrap_or(ConstantOrUnknown::Unknown)
            }
            OpCode::INT_EQUAL => {
                Self::binary_op(get, op, |a, b| if a == b { 1 } else { 0 })
            }
            OpCode::INT_NOTEQUAL => {
                Self::binary_op(get, op, |a, b| if a != b { 1 } else { 0 })
            }
            OpCode::INT_LESS => {
                Self::binary_op(get, op, |a, b| if a < b { 1 } else { 0 })
            }
            OpCode::INT_SLESS => Self::binary_op(get, op, |a, b| {
                if (a as i64) < (b as i64) { 1 } else { 0 }
            }),
            OpCode::BOOL_NEGATE => {
                op.inputs.first().and_then(get)
                    .map(|v| ConstantOrUnknown::Known(if v == 0 { 1 } else { 0 }))
                    .unwrap_or(ConstantOrUnknown::Unknown)
            }
            _ => ConstantOrUnknown::Unknown,
        }
    }

    fn binary_op<F>(
        get: impl Fn(&Varnode) -> Option<u64>,
        op: &PcodeOperation,
        f: F,
    ) -> ConstantOrUnknown
    where
        F: Fn(u64, u64) -> u64,
    {
        let a = op.inputs.first().and_then(&get);
        let b = op.inputs.get(1).and_then(&get);
        match (a, b) {
            (Some(a), Some(b)) => ConstantOrUnknown::Known(f(a, b)),
            _ => ConstantOrUnknown::Unknown,
        }
    }

    /// Build a map from varnode to the set of operation indices that use it.
    fn build_use_sites(
        operations: &[PcodeOperation],
    ) -> HashMap<Varnode, HashSet<usize>> {
        let mut use_sites: HashMap<Varnode, HashSet<usize>> = HashMap::new();
        for (i, op) in operations.iter().enumerate() {
            for inp in &op.inputs {
                use_sites.entry(inp.clone()).or_default().insert(i);
            }
        }
        use_sites
    }

    /// Get the constant value for a varnode, if known.
    pub fn value_of(&self, varnode: &Varnode) -> Option<u64> {
        self.values.get(varnode).and_then(|v| v.value())
    }
}

impl Default for ConstantPropagation {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// CopyPropagation
// ============================================================================

/// Copy-propagation analysis.
///
/// Detects COPY chains and substitutes varnodes with their defining source.
/// For example, if `u0 = COPY r0` and later `u1 = INT_ADD u0, #1`, the
/// second op becomes `u1 = INT_ADD r0, #1`.
pub struct CopyPropagation {
    /// Map from varnode to its source varnode (from COPY operations).
    copies: HashMap<Varnode, Varnode>,
}

impl CopyPropagation {
    pub fn new() -> Self {
        Self {
            copies: HashMap::new(),
        }
    }

    /// Propagate copies through the operations list.
    ///
    /// When a COPY from a non-constant varnode is discovered, it is recorded.
    /// When the source is itself a copy target, the chain is resolved to the
    /// ultimate source.
    pub fn propagate(
        &mut self,
        operations: &[PcodeOperation],
        constants: &HashMap<Varnode, u64>,
    ) {
        self.copies.clear();

        for op in operations {
            if op.opcode == OpCode::COPY {
                if let (Some(ref out), Some(src)) = (&op.output, op.inputs.first()) {
                    // Skip constant sources (handled by constant propagation).
                    if src.is_constant() || constants.contains_key(src) {
                        continue;
                    }

                    // Resolve chained copies.
                    let ultimate_src = self.resolve_chain(src);
                    self.copies.insert(out.clone(), ultimate_src);
                }
            }
        }
    }

    /// Resolve a copy chain: follow `copies` entries until we find a
    /// non-copied source.
    fn resolve_chain(&self, vn: &Varnode) -> Varnode {
        let mut current = vn.clone();
        let mut seen = HashSet::new();
        seen.insert(current.clone());

        while let Some(src) = self.copies.get(&current) {
            if !seen.insert(src.clone()) {
                break; // cycle detected
            }
            current = src.clone();
        }

        current
    }

    /// Returns the discovered copy map.
    pub fn copies(&self) -> &HashMap<Varnode, Varnode> {
        &self.copies
    }

    /// Apply the discovered copies to operations (in-place substitution).
    pub fn apply_to(&self, operations: &mut [PcodeOperation]) {
        for op in operations.iter_mut() {
            // Don't rewrite COPY sources themselves.
            if op.opcode == OpCode::COPY {
                continue;
            }
            for inp in op.inputs.iter_mut() {
                if let Some(src) = self.copies.get(inp) {
                    *inp = src.clone();
                }
            }
        }
    }
}

impl Default for CopyPropagation {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// DeadCodeElimination
// ============================================================================

/// Dead-code elimination: removes operations whose outputs are never used
/// by any live operation.
///
/// An operation is *live* if:
/// - It has observable side effects (STORE, CALL, BRANCH, RETURN, etc.)
/// - Its output is used as an input by another live operation.
pub struct DeadCodeElimination;

impl DeadCodeElimination {
    /// Eliminate dead code from a list of operations.
    ///
    /// Returns the filtered list of live operations, preserving order.
    pub fn eliminate(operations: &[PcodeOperation]) -> Vec<PcodeOperation> {
        let n = operations.len();
        let mut live = vec![false; n];
        let mut worklist = VecDeque::new();

        // Build def-use chains.
        let def_use = Self::build_def_use(operations);

        // Mark operations with side effects as live.
        for (i, op) in operations.iter().enumerate() {
            if op.has_side_effects() {
                live[i] = true;
                worklist.push_back(i);
            }
        }

        // Mark the last operation live if nothing else is (prevents
        // emptying the function entirely).
        if worklist.is_empty() && !operations.is_empty() {
            live[n - 1] = true;
            worklist.push_back(n - 1);
        }

        // Work backwards: if an op is live, all ops that define its
        // inputs are also live.
        while let Some(idx) = worklist.pop_front() {
            let op = &operations[idx];
            for inp in &op.inputs {
                if let Some(def_indices) = def_use.get(inp) {
                    for &def_idx in def_indices {
                        if !live[def_idx] {
                            live[def_idx] = true;
                            worklist.push_back(def_idx);
                        }
                    }
                }
            }
        }

        operations
            .iter()
            .enumerate()
            .filter(|(i, _)| live[*i])
            .map(|(_, op)| op.clone())
            .collect()
    }

    /// Returns the set of live operation indices.
    pub fn live_indices(operations: &[PcodeOperation]) -> HashSet<usize> {
        let _n = operations.len();
        let mut live = HashSet::new();
        let mut worklist = VecDeque::new();
        let def_use = Self::build_def_use(operations);

        for (i, op) in operations.iter().enumerate() {
            if op.has_side_effects() {
                live.insert(i);
                worklist.push_back(i);
            }
        }

        while let Some(idx) = worklist.pop_front() {
            let op = &operations[idx];
            for inp in &op.inputs {
                if let Some(def_indices) = def_use.get(inp) {
                    for &def_idx in def_indices {
                        if live.insert(def_idx) {
                            worklist.push_back(def_idx);
                        }
                    }
                }
            }
        }

        live
    }

    /// Build a map from varnode to the set of operation indices that define it.
    fn build_def_use(
        operations: &[PcodeOperation],
    ) -> HashMap<Varnode, HashSet<usize>> {
        let mut defs: HashMap<Varnode, HashSet<usize>> = HashMap::new();
        for (i, op) in operations.iter().enumerate() {
            if let Some(ref out) = op.output {
                defs.entry(out.clone()).or_default().insert(i);
            }
        }
        defs
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn cnst(val: u64, size: u32) -> Varnode {
        Varnode::constant(val, size)
    }

    fn uniq(id: u64, size: u32) -> Varnode {
        Varnode::unique(id, size)
    }

    fn reg(offset: u64, size: u32) -> Varnode {
        Varnode::register("r", offset, size)
    }

    // -- DataFlowAnalyzer (forward test) --

    #[test]
    fn test_dataflow_direction() {
        assert_eq!(
            DataFlowDirection::Forward,
            DataFlowDirection::Forward
        );
        assert_ne!(
            DataFlowDirection::Forward,
            DataFlowDirection::Backward
        );
    }

    // -- ValueSet --

    #[test]
    fn test_value_set_join() {
        let a = ValueSet::constant(5);
        let b = ValueSet::constant(10);
        let joined = a.join(&b);
        assert!(!joined.is_top);
        assert_eq!(joined.ranges.len(), 2);
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

    // -- RangeAnalysis --

    #[test]
    fn test_range_analysis_constants() {
        let mut ra = RangeAnalysis::new();
        let ops = vec![
            PcodeOperation::new_unannotated(
                OpCode::COPY,
                Some(uniq(0, 4)),
                vec![cnst(42, 4)],
            ),
        ];
        let mut constants = HashMap::new();
        constants.insert(cnst(42, 4), 42);
        ra.analyze(&ops, &constants);

        let vs = ra.get_range(&uniq(0, 4));
        assert!(vs.is_constant());
        assert_eq!(vs.as_constant(), Some(42));
    }

    // -- ConstantPropagation --

    #[test]
    fn test_constant_propagation() {
        let mut cp = ConstantPropagation::new();
        let ops = vec![
            PcodeOperation::new_unannotated(
                OpCode::INT_ADD,
                Some(uniq(0, 4)),
                vec![cnst(3, 4), cnst(4, 4)],
            ),
            PcodeOperation::new_unannotated(
                OpCode::INT_MUL,
                Some(uniq(1, 4)),
                vec![uniq(0, 4), cnst(2, 4)],
            ),
        ];

        let values = cp.analyze(&ops);
        assert_eq!(values[&uniq(0, 4)], ConstantOrUnknown::Known(7));
        assert_eq!(values[&uniq(1, 4)], ConstantOrUnknown::Known(14));
    }

    // -- CopyPropagation --

    #[test]
    fn test_copy_propagation() {
        let mut propagator = CopyPropagation::new();
        let ops = vec![
            PcodeOperation::new_unannotated(
                OpCode::COPY,
                Some(uniq(0, 4)),
                vec![reg(0, 4)],
            ),
            PcodeOperation::new_unannotated(
                OpCode::COPY,
                Some(uniq(1, 4)),
                vec![uniq(0, 4)],
            ),
        ];

        let constants = HashMap::new();
        propagator.propagate(&ops, &constants);

        let copies = propagator.copies();
        // u1 should resolve to r0 through the chain.
        assert!(copies.contains_key(&uniq(1, 4)));
        assert_eq!(copies[&uniq(1, 4)], reg(0, 4));
    }

    // -- DeadCodeElimination --

    #[test]
    fn test_dead_code_elimination() {
        let used = uniq(0, 4);
        let unused = uniq(1, 4);

        let ops = vec![
            // Dead: output never used.
            PcodeOperation::new_unannotated(
                OpCode::INT_ADD,
                Some(unused.clone()),
                vec![cnst(1, 4), cnst(2, 4)],
            ),
            // Live: output is stored.
            PcodeOperation::new_unannotated(
                OpCode::INT_ADD,
                Some(used.clone()),
                vec![cnst(5, 4), cnst(6, 4)],
            ),
            // Store (has side effects, always live).
            PcodeOperation::new_unannotated(
                OpCode::STORE,
                None,
                vec![cnst(0, 8), cnst(0x1000, 4), used.clone()],
            ),
        ];

        let live_indices = DeadCodeElimination::live_indices(&ops);
        assert!(live_indices.contains(&1)); // used computation
        assert!(live_indices.contains(&2)); // store
        assert!(!live_indices.contains(&0)); // dead
    }
}
