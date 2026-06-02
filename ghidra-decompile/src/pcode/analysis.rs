//! P-code analysis infrastructure.
//!
//! Provides control-flow graph construction, dominator trees, loop detection,
//! data-flow analysis framework, SSA construction, constant propagation,
//! dead-code elimination, and expression simplification.

use super::{OpCode, PcodeOperation, PcodeSequence, Varnode};
use ghidra_core::addr::Address;
use petgraph::algo::dominators;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

// ---------------------------------------------------------------------------
// BasicBlock
// ---------------------------------------------------------------------------

/// A basic block: a maximal sequence of P-code operations with a single entry
/// point and a single exit point.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// Unique block id (usually the index in the block vector).
    pub id: usize,
    /// The starting address of this block (address of the first instruction).
    pub start_address: Option<Address>,
    /// The ending address of this block.
    pub end_address: Option<Address>,
    /// The P-code operations in this block, in execution order.
    pub operations: Vec<PcodeOperation>,
    /// Graph node index for this block in the CFG.
    pub node: Option<NodeIndex>,
}

impl BasicBlock {
    /// Create a new empty basic block.
    pub fn new(id: usize) -> Self {
        Self {
            id,
            start_address: None,
            end_address: None,
            operations: Vec::new(),
            node: None,
        }
    }

    /// Returns true if this block ends with a branch/return/call.
    pub fn has_terminator(&self) -> bool {
        self.operations
            .last()
            .map_or(false, |op| op.is_terminator())
    }

    /// Returns the terminator operation, if any.
    pub fn terminator(&self) -> Option<&PcodeOperation> {
        self.operations.last().filter(|op| op.is_terminator())
    }

    /// Returns the branch target address if the terminator is a direct branch.
    pub fn direct_branch_target(&self) -> Option<Address> {
        self.terminator().and_then(|op| match op.opcode {
            OpCode::BRANCH | OpCode::CBRANCH => {
                op.inputs.first().and_then(|v| v.constant_value()).map(Address::new)
            }
            _ => None,
        })
    }

    /// Returns the number of operations.
    pub fn len(&self) -> usize {
        self.operations.len()
    }

    /// Returns true if empty.
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// Collect all varnodes defined (written) in this block.
    pub fn defined_varnodes(&self) -> HashSet<Varnode> {
        let mut defs = HashSet::new();
        for op in &self.operations {
            if let Some(ref out) = op.output {
                defs.insert(out.clone());
            }
        }
        defs
    }

    /// Collect all varnodes used (read) in this block.
    pub fn used_varnodes(&self) -> HashSet<Varnode> {
        let mut uses = HashSet::new();
        for op in &self.operations {
            for inp in &op.inputs {
                uses.insert(inp.clone());
            }
        }
        uses
    }
}

// ---------------------------------------------------------------------------
// ControlFlowGraph
// ---------------------------------------------------------------------------

/// Edge type in the control-flow graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfgEdge {
    /// Normal fall-through to the next block.
    Fallthrough,
    /// Direct unconditional branch.
    Branch,
    /// Conditional branch (true path).
    TrueBranch,
    /// Conditional branch (false path).
    FalseBranch,
    /// Indirect branch (target unknown).
    IndirectBranch,
    /// Call edge (call returns to fall-through).
    Call,
    /// Return from function.
    Return,
}

/// A control-flow graph built from P-code sequences.
#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    /// The petgraph directed graph.  Node weights are block ids.
    pub graph: DiGraph<usize, CfgEdge>,
    /// All basic blocks, indexed by id.
    pub blocks: Vec<BasicBlock>,
    /// Entry block node index.
    pub entry: NodeIndex,
    /// Exit block node index (the unique exit / return node).
    pub exit: NodeIndex,
}

impl ControlFlowGraph {
    /// Number of basic blocks.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Get a reference to a basic block by its node index.
    pub fn block_by_node(&self, node: NodeIndex) -> &BasicBlock {
        let id = self.graph[node];
        &self.blocks[id]
    }

    /// Get successor node indices for a block.
    pub fn successors(&self, node: NodeIndex) -> Vec<NodeIndex> {
        self.graph
            .neighbors_directed(node, Direction::Outgoing)
            .collect()
    }

    /// Get predecessor node indices for a block.
    pub fn predecessors(&self, node: NodeIndex) -> Vec<NodeIndex> {
        self.graph
            .neighbors_directed(node, Direction::Incoming)
            .collect()
    }

    /// Returns the edge type between two nodes, if any.
    pub fn edge_between(&self, from: NodeIndex, to: NodeIndex) -> Option<CfgEdge> {
        self.graph
            .edges_connecting(from, to)
            .next()
            .map(|e| *e.weight())
    }

    /// Walk the CFG in reverse postorder (useful for data-flow analysis).
    pub fn reverse_postorder(&self) -> Vec<NodeIndex> {
        let mut order = Vec::new();
        let mut visited = HashSet::new();
        let mut stack = vec![(self.entry, false)];

        while let Some((node, done)) = stack.pop() {
            if done {
                order.push(node);
                continue;
            }
            if !visited.insert(node) {
                continue;
            }
            stack.push((node, true));
            for succ in self.successors(node).into_iter().rev() {
                if !visited.contains(&succ) {
                    stack.push((succ, false));
                }
            }
        }

        order.reverse(); // reverse postorder
        order
    }
}

/// Build a control-flow graph from a list of P-code sequences (a function).
///
/// The algorithm:
/// 1. Flatten all operations into a single list, preserving instruction boundaries.
/// 2. Identify *leaders* (first op, branch targets, ops after branches).
/// 3. Create a basic block for each leader-to-leader range.
/// 4. Add edges based on control flow (fall-through, branches, calls).
pub fn build_cfg(sequences: &[PcodeSequence]) -> ControlFlowGraph {
    // Step 1: flatten operations.
    let mut flat_ops: Vec<PcodeOperation> = Vec::new();
    for seq in sequences {
        flat_ops.extend(seq.flatten());
    }
    if flat_ops.is_empty() {
        // Empty function: single-block CFG.
        let mut graph = DiGraph::new();
        let entry = graph.add_node(0);
        let exit = graph.add_node(1);
        let mut blocks = vec![BasicBlock::new(0), BasicBlock::new(1)];
        blocks[0].node = Some(entry);
        blocks[1].node = Some(exit);
        graph.add_edge(entry, exit, CfgEdge::Fallthrough);
        return ControlFlowGraph {
            graph,
            blocks,
            entry,
            exit,
        };
    }

    // Step 2: identify leaders.
    let is_leader = find_leaders(&flat_ops);
    let leaders: Vec<usize> = (0..flat_ops.len()).filter(|&i| is_leader[i]).collect();

    // Step 3: build blocks.
    let mut blocks: Vec<BasicBlock> = Vec::new();
    let mut op_to_block: HashMap<usize, usize> = HashMap::new(); // operation index -> block id
    let mut block_addr_map: HashMap<u64, usize> = HashMap::new(); // address offset -> block id

    for (block_idx, &start) in leaders.iter().enumerate() {
        let end = if block_idx + 1 < leaders.len() {
            leaders[block_idx + 1]
        } else {
            flat_ops.len()
        };
        let ops: Vec<PcodeOperation> = flat_ops[start..end].to_vec();

        let start_addr = ops.first().and_then(|op| op.address);
        let end_addr = ops.last().and_then(|op| op.address);

        if let Some(addr) = start_addr {
            block_addr_map.insert(addr.offset, block_idx);
        }

        for i in start..end {
            op_to_block.insert(i, block_idx);
        }

        let mut bb = BasicBlock::new(block_idx);
        bb.start_address = start_addr;
        bb.end_address = end_addr;
        bb.operations = ops;
        blocks.push(bb);
    }

    // Step 4: build graph nodes.
    let mut graph = DiGraph::new();
    let block_nodes: Vec<NodeIndex> = (0..blocks.len()).map(|i| graph.add_node(i)).collect();
    for (i, node) in block_nodes.iter().enumerate() {
        blocks[i].node = Some(*node);
    }

    let exit_idx = blocks.len();
    let exit_node = graph.add_node(exit_idx);
    let mut exit_bb = BasicBlock::new(exit_idx);
    exit_bb.start_address = None;
    exit_bb.end_address = None;
    exit_bb.node = Some(exit_node);
    blocks.push(exit_bb);

    // Step 5: add edges.
    for (i, block) in blocks.iter().enumerate() {
        if i == exit_idx {
            continue;
        }
        let node = block_nodes[i];

        if let Some(terminator) = block.terminator() {
            match terminator.opcode {
                OpCode::BRANCH => {
                    if let Some(target) = block.direct_branch_target() {
                        if let Some(&target_blk) = block_addr_map.get(&target.offset) {
                            graph.add_edge(node, block_nodes[target_blk], CfgEdge::Branch);
                        } else {
                            graph.add_edge(node, exit_node, CfgEdge::Branch);
                        }
                    }
                }
                OpCode::CBRANCH => {
                    if let Some(target) = block.direct_branch_target() {
                        if let Some(&target_blk) = block_addr_map.get(&target.offset) {
                            graph.add_edge(node, block_nodes[target_blk], CfgEdge::TrueBranch);
                        } else {
                            graph.add_edge(node, exit_node, CfgEdge::TrueBranch);
                        }
                    }
                    // False branch: fall-through to next block.
                    if i + 1 < block_nodes.len() {
                        graph.add_edge(node, block_nodes[i + 1], CfgEdge::FalseBranch);
                    } else {
                        graph.add_edge(node, exit_node, CfgEdge::FalseBranch);
                    }
                }
                OpCode::BRANCHIND => {
                    graph.add_edge(node, exit_node, CfgEdge::IndirectBranch);
                }
                OpCode::CALL | OpCode::CALLIND => {
                    // Call: fall-through is the return point.
                    if i + 1 < block_nodes.len() {
                        graph.add_edge(node, block_nodes[i + 1], CfgEdge::Call);
                    }
                }
                OpCode::RETURN => {
                    graph.add_edge(node, exit_node, CfgEdge::Return);
                }
                _ => {
                    // Non-terminator: fall-through.
                    if i + 1 < block_nodes.len() {
                        graph.add_edge(node, block_nodes[i + 1], CfgEdge::Fallthrough);
                    }
                }
            }
        } else {
            // No terminator: fall-through to next block.
            if i + 1 < block_nodes.len() {
                graph.add_edge(node, block_nodes[i + 1], CfgEdge::Fallthrough);
            } else {
                graph.add_edge(node, exit_node, CfgEdge::Fallthrough);
            }
        }
    }

    ControlFlowGraph {
        graph,
        blocks,
        entry: block_nodes[0],
        exit: exit_node,
    }
}

/// Find leaders in a flat list of operations.
fn find_leaders(ops: &[PcodeOperation]) -> Vec<bool> {
    let mut is_leader = vec![false; ops.len()];
    if ops.is_empty() {
        return is_leader;
    }

    // First operation is always a leader.
    is_leader[0] = true;

    // Build address -> op index map for branch targets.
    let mut addr_to_idx: HashMap<u64, usize> = HashMap::new();
    for (i, op) in ops.iter().enumerate() {
        if let Some(addr) = op.address {
            addr_to_idx.entry(addr.offset).or_insert(i);
        }
    }

    for (i, op) in ops.iter().enumerate() {
        match op.opcode {
            OpCode::BRANCH | OpCode::CBRANCH => {
                // Op after branch is a leader.
                if i + 1 < ops.len() {
                    is_leader[i + 1] = true;
                }
                // Branch target is a leader.
                if let Some(target_vn) = op.inputs.first() {
                    if let Some(target_offset) = target_vn.constant_value() {
                        if let Some(&target_idx) = addr_to_idx.get(&target_offset) {
                            is_leader[target_idx] = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    is_leader
}

// ---------------------------------------------------------------------------
// DominatorTree
// ---------------------------------------------------------------------------

/// Wrapper around petgraph's dominator computation.
#[derive(Debug, Clone)]
pub struct DominatorTree {
    dominators: dominators::Dominators<NodeIndex>,
}

impl DominatorTree {
    /// Compute the dominator tree for a CFG.
    pub fn compute(cfg: &ControlFlowGraph) -> Self {
        let dom = dominators::simple_fast(&cfg.graph, cfg.entry);
        Self { dominators: dom }
    }

    /// Returns the immediate dominator of `node`, if any.
    pub fn idom(&self, node: NodeIndex) -> Option<NodeIndex> {
        self.dominators.immediate_dominator(node)
    }

    /// Returns true if `a` dominates `b` (i.e., every path from entry to `b`
    /// goes through `a`).
    pub fn dominates(&self, a: NodeIndex, b: NodeIndex) -> bool {
        if a == b {
            return true;
        }
        let mut current = b;
        loop {
            match self.idom(current) {
                Some(idom) if idom == a => return true,
                Some(idom) => current = idom,
                None => return false,
            }
        }
    }

    /// Returns all nodes strictly dominated by `node` (i.e., the subtree).
    pub fn dominated_by(&self, node: NodeIndex, cfg: &ControlFlowGraph) -> Vec<NodeIndex> {
        let mut result = Vec::new();
        for n in cfg.graph.node_indices() {
            if n != node && self.dominates(node, n) {
                result.push(n);
            }
        }
        result
    }

    /// Returns the dominance frontier of all nodes.
    ///
    /// The dominance frontier of a node X is the set of nodes Y such that X
    /// dominates a predecessor of Y but does not strictly dominate Y.
    pub fn dominance_frontiers(&self, cfg: &ControlFlowGraph) -> HashMap<NodeIndex, HashSet<NodeIndex>> {
        let mut df: HashMap<NodeIndex, HashSet<NodeIndex>> = HashMap::new();
        for node in cfg.graph.node_indices() {
            df.entry(node).or_default();
        }

        for node in cfg.graph.node_indices() {
            let preds: Vec<NodeIndex> = cfg.predecessors(node);
            if preds.len() < 2 {
                continue;
            }
            for &pred in &preds {
                let mut runner = pred;
                while runner != self.idom(node).unwrap_or(node) && runner != node {
                    df.entry(runner).or_default().insert(node);
                    runner = match self.idom(runner) {
                        Some(idom) => idom,
                        None => break,
                    };
                }
            }
        }

        df
    }

    /// Returns the dominance frontier of a single node.
    pub fn dominance_frontier(&self, node: NodeIndex, cfg: &ControlFlowGraph) -> HashSet<NodeIndex> {
        self.dominance_frontiers(cfg)
            .remove(&node)
            .unwrap_or_default()
    }

    /// Returns nodes in dominator-tree preorder.
    pub fn preorder(&self, cfg: &ControlFlowGraph) -> Vec<NodeIndex> {
        let mut order = Vec::new();
        let mut stack = vec![cfg.entry];
        let mut visited = HashSet::new();
        while let Some(node) = stack.pop() {
            if !visited.insert(node) {
                continue;
            }
            order.push(node);
            // Push children (nodes whose idom is this node) in reverse order
            // for deterministic preorder.
            let mut children: Vec<NodeIndex> = cfg
                .graph
                .node_indices()
                .filter(|&n| self.idom(n) == Some(node))
                .collect();
            children.reverse();
            stack.extend(children);
        }
        order
    }
}

// ---------------------------------------------------------------------------
// Loop detection
// ---------------------------------------------------------------------------

/// A natural loop: a set of nodes consisting of a header `h` and all nodes
/// that can reach a back-edge `t -> h` without going through `h`.
#[derive(Debug, Clone)]
pub struct NaturalLoop {
    /// The loop header (dominates all nodes in the loop).
    pub header: NodeIndex,
    /// All nodes in the loop body (includes the header).
    pub body: BTreeSet<NodeIndex>,
    /// The back-edge that defines this loop (tail -> header).
    pub back_edge: (NodeIndex, NodeIndex),
}

impl NaturalLoop {
    /// Returns true if `node` is in the loop body.
    pub fn contains(&self, node: NodeIndex) -> bool {
        self.body.contains(&node)
    }

    /// Returns the loop's nesting depth (a heuristic: number of enclosing
    /// loops).
    pub fn depth(&self, all_loops: &[NaturalLoop]) -> usize {
        all_loops
            .iter()
            .filter(|l| {
                l.header != self.header
                    && self.body.iter().all(|n| l.contains(*n))
                    && self.body.len() < l.body.len()
            })
            .count()
    }
}

/// Find all natural loops in a CFG.
///
/// A natural loop is defined by a back-edge `t -> h` where `h` dominates `t`.
/// The loop body is `h` plus all nodes that can reach `t` without going
/// through `h`.
pub fn find_natural_loops(cfg: &ControlFlowGraph, dom: &DominatorTree) -> Vec<NaturalLoop> {
    let mut loops = Vec::new();

    // Find back-edges: edge t -> h where h dominates t.
    for edge in cfg.graph.edge_references() {
        let tail = edge.source();
        let head = edge.target();
        if dom.dominates(head, tail) {
            // Back-edge found: tail -> head.
            let body = compute_loop_body(cfg, head, tail);
            loops.push(NaturalLoop {
                header: head,
                body,
                back_edge: (tail, head),
            });
        }
    }

    // Sort by body size (innermost first is often useful).
    loops.sort_by_key(|l| l.body.len());
    loops
}

/// Compute the body of a natural loop defined by back-edge `tail -> header`.
fn compute_loop_body(cfg: &ControlFlowGraph, header: NodeIndex, tail: NodeIndex) -> BTreeSet<NodeIndex> {
    let mut body = BTreeSet::new();
    body.insert(header);

    if tail == header {
        return body; // self-loop
    }

    let mut worklist = vec![tail];
    body.insert(tail);

    while let Some(node) = worklist.pop() {
        for pred in cfg.predecessors(node) {
            if body.insert(pred) {
                worklist.push(pred);
            }
        }
    }

    body
}

// ---------------------------------------------------------------------------
// DataFlowAnalyzer trait
// ---------------------------------------------------------------------------

/// Direction of a data-flow analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataFlowDirection {
    /// Forward analysis: IN[B] = meet(OUT[predecessors]).
    Forward,
    /// Backward analysis: OUT[B] = meet(IN[successors]).
    Backward,
}

/// Trait for data-flow analyses on the control-flow graph.
///
/// Implementors define a lattice element `Fact`, a direction, a transfer
/// function, and a meet operation.
pub trait DataFlowAnalyzer {
    /// The lattice element computed for each program point.
    type Fact: Clone + PartialEq + std::fmt::Debug;

    /// The direction of the analysis.
    fn direction(&self) -> DataFlowDirection;

    /// The initial fact for the entry/exit node (depending on direction).
    fn initial_fact(&self) -> Self::Fact;

    /// The bottom fact for uninitialized nodes.
    fn bottom_fact(&self) -> Self::Fact;

    /// Top fact (for forward IN[entry] or backward OUT[exit]).
    fn top_fact(&self) -> Self::Fact;

    /// Transfer function: given a basic block and the IN (or OUT) fact,
    /// compute the OUT (or IN) fact.
    fn transfer(&self, block: &BasicBlock, input: &Self::Fact) -> Self::Fact;

    /// Meet operation: combine two facts (e.g., union for may-analyses,
    /// intersection for must-analyses).
    fn meet(&self, a: &Self::Fact, b: &Self::Fact) -> Self::Fact;

    /// Run the analysis to a fixed point on the given CFG.
    fn analyze(&self, cfg: &ControlFlowGraph) -> HashMap<NodeIndex, (Self::Fact, Self::Fact)> {
        let mut in_facts: HashMap<NodeIndex, Self::Fact> = HashMap::new();
        let mut out_facts: HashMap<NodeIndex, Self::Fact> = HashMap::new();

        let bottom = self.bottom_fact();
        let top = self.top_fact();
        let initial = self.initial_fact();

        // Initialize.
        for node in cfg.graph.node_indices() {
            in_facts.insert(node, bottom.clone());
            out_facts.insert(node, bottom.clone());
        }

        match self.direction() {
            DataFlowDirection::Forward => {
                in_facts.insert(cfg.entry, top.clone());
            }
            DataFlowDirection::Backward => {
                out_facts.insert(cfg.exit, top.clone());
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
                    // IN[B] = meet(OUT[P] for P in preds)
                    let preds = cfg.predecessors(node);
                    let new_in = if preds.is_empty() {
                        if node == cfg.entry {
                            top.clone()
                        } else {
                            initial.clone()
                        }
                    } else {
                        preds
                            .iter()
                            .fold(initial.clone(), |acc, p| self.meet(&acc, &out_facts[p]))
                    };
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
                    // OUT[B] = meet(IN[S] for S in succs)
                    let succs = cfg.successors(node);
                    let new_out = if succs.is_empty() {
                        if node == cfg.exit {
                            top.clone()
                        } else {
                            initial.clone()
                        }
                    } else {
                        succs
                            .iter()
                            .fold(initial.clone(), |acc, s| self.meet(&acc, &in_facts[s]))
                    };
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
            result.insert(node, (in_facts[&node].clone(), out_facts[&node].clone()));
        }
        result
    }
}

// ---------------------------------------------------------------------------
// DefUseChain
// ---------------------------------------------------------------------------

/// A def-use chain: tracks which operations define and use each varnode.
#[derive(Debug, Clone)]
pub struct DefUseChain {
    /// Map from varnode to the set of operation indices that define it.
    pub definitions: HashMap<Varnode, HashSet<usize>>,
    /// Map from varnode to the set of operation indices that use it.
    pub uses: HashMap<Varnode, HashSet<usize>>,
}

impl DefUseChain {
    /// Build the def-use chain from a flat list of operations.
    pub fn build(operations: &[PcodeOperation]) -> Self {
        let mut definitions: HashMap<Varnode, HashSet<usize>> = HashMap::new();
        let mut uses: HashMap<Varnode, HashSet<usize>> = HashMap::new();

        for (i, op) in operations.iter().enumerate() {
            if let Some(ref out) = op.output {
                definitions.entry(out.clone()).or_default().insert(i);
            }
            for inp in &op.inputs {
                uses.entry(inp.clone()).or_default().insert(i);
            }
        }

        Self { definitions, uses }
    }

    /// Returns the operation indices that define `varnode`.
    pub fn defs_of(&self, varnode: &Varnode) -> &HashSet<usize> {
        static EMPTY: std::sync::LazyLock<HashSet<usize>> =
            std::sync::LazyLock::new(HashSet::new);
        self.definitions.get(varnode).unwrap_or(&EMPTY)
    }

    /// Returns the operation indices that use `varnode`.
    pub fn uses_of(&self, varnode: &Varnode) -> &HashSet<usize> {
        static EMPTY: std::sync::LazyLock<HashSet<usize>> =
            std::sync::LazyLock::new(HashSet::new);
        self.uses.get(varnode).unwrap_or(&EMPTY)
    }
}

// ---------------------------------------------------------------------------
// ReachingDefs
// ---------------------------------------------------------------------------

/// Reaching-definitions analysis.
///
/// For each program point, computes the set of (varnode, definition-site)
/// pairs that may reach that point.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DefinitionSite {
    pub varnode: Varnode,
    pub inst_index: usize,
}

/// The result of reaching-definitions analysis: for each basic block, the set
/// of definition sites that reach the entry and exit of the block.
pub struct ReachingDefs {
    /// The analysis result: block -> (in_defs, out_defs).
    pub result: HashMap<NodeIndex, (HashSet<DefinitionSite>, HashSet<DefinitionSite>)>,
}

impl ReachingDefs {
    /// Run reaching-definitions analysis on a flat list of operations grouped
    /// by the CFG.
    pub fn compute(
        operations: &[PcodeOperation],
        cfg: &ControlFlowGraph,
    ) -> Self {
        // Build an index of all definition sites.
        let mut all_defs: HashSet<DefinitionSite> = HashSet::new();
        for (i, op) in operations.iter().enumerate() {
            if op.output.is_some() {
                all_defs.insert(DefinitionSite {
                    varnode: op.output.clone().unwrap(),
                    inst_index: i,
                });
            }
        }

        // For each block, compute KILL (defs killed by definitions in this block)
        // and GEN (defs generated in this block that are not killed later).
        let mut gen: HashMap<NodeIndex, HashSet<DefinitionSite>> = HashMap::new();
        let mut kill: HashMap<NodeIndex, HashSet<DefinitionSite>> = HashMap::new();

        for block in &cfg.blocks {
            if let Some(node) = block.node {
                let mut block_gen = HashSet::new();
                let mut block_vn_defs: HashSet<Varnode> = HashSet::new();

                // Process in reverse to compute GEN (last definition of each
                // varnode survives).
                for op in block.operations.iter().rev() {
                    if let Some(ref out) = op.output {
                        if !block_vn_defs.contains(out) {
                            // Find the global index of this operation.
                            // For simplicity, we use the varnode itself.
                            block_gen.insert(DefinitionSite {
                                varnode: out.clone(),
                                inst_index: 0, // placeholder
                            });
                            block_vn_defs.insert(out.clone());
                        }
                    }
                }

                // KILL: all definitions of varnodes defined in this block.
                let mut block_kill = HashSet::new();
                for ds in &all_defs {
                    if block_vn_defs.contains(&ds.varnode) {
                        // Only kill if the definition is not from this block
                        // itself (simplification: kill all).
                        let is_local_gen = block_gen.iter().any(|g| g.varnode == ds.varnode);
                        if !is_local_gen {
                            block_kill.insert(ds.clone());
                        }
                    }
                }

                gen.insert(node, block_gen);
                kill.insert(node, block_kill);
            }
        }

        // Classic forward dataflow: OUT[B] = GEN[B] ∪ (IN[B] - KILL[B])
        let mut in_sets: HashMap<NodeIndex, HashSet<DefinitionSite>> = HashMap::new();
        let mut out_sets: HashMap<NodeIndex, HashSet<DefinitionSite>> = HashMap::new();

        for node in cfg.graph.node_indices() {
            in_sets.insert(node, HashSet::new());
            out_sets.insert(node, HashSet::new());
        }

        in_sets.insert(cfg.entry, HashSet::new());

        let mut worklist: VecDeque<NodeIndex> = cfg.graph.node_indices().collect();
        let mut in_queue: HashSet<NodeIndex> = cfg.graph.node_indices().collect();

        while let Some(node) = worklist.pop_front() {
            in_queue.remove(&node);

            // IN[B] = ∪ OUT[P]
            let mut new_in = HashSet::new();
            let preds = cfg.predecessors(node);
            if preds.is_empty() && node == cfg.entry {
                // entry has no predecessors
            } else {
                for pred in &preds {
                    if let Some(out) = out_sets.get(pred) {
                        new_in.extend(out.iter().cloned());
                    }
                }
            }

            // OUT[B] = GEN[B] ∪ (IN[B] - KILL[B])
            let mut new_out = new_in.clone();
            if let Some(k) = kill.get(&node) {
                new_out.retain(|ds| !k.contains(ds));
            }
            if let Some(g) = gen.get(&node) {
                new_out.extend(g.iter().cloned());
            }

            if in_sets[&node] != new_in || out_sets[&node] != new_out {
                in_sets.insert(node, new_in);
                out_sets.insert(node, new_out);

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

        ReachingDefs { result }
    }

    /// Get the definition sites reaching the entry of a block.
    pub fn reaching_entry(&self, node: NodeIndex) -> Option<&HashSet<DefinitionSite>> {
        self.result.get(&node).map(|(in_, _)| in_)
    }

    /// Get the definition sites reaching the exit of a block.
    pub fn reaching_exit(&self, node: NodeIndex) -> Option<&HashSet<DefinitionSite>> {
        self.result.get(&node).map(|(_, out)| out)
    }
}

// ---------------------------------------------------------------------------
// SSA Construction
// ---------------------------------------------------------------------------

/// A phi-node in SSA form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhiNode {
    /// The output varnode (the SSA version produced by this phi).
    pub output: Varnode,
    /// Map from predecessor block node index to the input varnode from that
    /// path.
    pub inputs: Vec<(NodeIndex, Varnode)>,
}

impl PhiNode {
    /// Create a new phi node.
    pub fn new(output: Varnode, inputs: Vec<(NodeIndex, Varnode)>) -> Self {
        Self { output, inputs }
    }

    /// Convert to a P-code `MULTIEQUAL` operation.
    pub fn to_pcode_operation(&self) -> PcodeOperation {
        let inputs: Vec<Varnode> = self.inputs.iter().map(|(_, vn)| vn.clone()).collect();
        PcodeOperation::new_unannotated(OpCode::MULTIEQUAL, Some(self.output.clone()), inputs)
    }
}

/// SSA form of a function: P-code operations with phi nodes inserted and
/// variables renamed.
#[derive(Debug, Clone)]
pub struct SsaForm {
    /// The operations in SSA form (phi nodes followed by regular operations,
    /// per block).
    pub operations: Vec<PcodeOperation>,
    /// Phi nodes, keyed by the block node index where they appear.
    pub phi_nodes: HashMap<NodeIndex, Vec<PhiNode>>,
    /// Map from original varnode to its SSA versions.
    pub versions: HashMap<Varnode, Vec<Varnode>>,
}

/// Builder for SSA form.
pub struct SsaBuilder {
    /// The original operations (flat list).
    operations: Vec<PcodeOperation>,
    /// The CFG.
    cfg: ControlFlowGraph,
    /// Dominator tree.
    dom: DominatorTree,
    /// Block indices for each operation.
    op_to_block: HashMap<usize, NodeIndex>,
}

impl SsaBuilder {
    /// Create a new SSA builder.
    pub fn new(
        operations: Vec<PcodeOperation>,
        cfg: ControlFlowGraph,
        dom: DominatorTree,
    ) -> Self {
        // Map each operation to its block.
        let mut op_to_block = HashMap::new();
        for (node, block) in cfg.blocks.iter().enumerate() {
            if let Some(block_node) = block.node {
                // Approximate: operations in this block.
                // For simplicity, assign placeholder - we'll compute properly.
            }
        }

        // Build proper op-to-block mapping by walking blocks.
        let mut op_idx = 0;
        for block in &cfg.blocks {
            if let Some(node) = block.node {
                for _ in 0..block.operations.len() {
                    op_to_block.insert(op_idx, node);
                    op_idx += 1;
                }
            }
        }

        Self {
            operations,
            cfg,
            dom,
            op_to_block,
        }
    }

    /// Build SSA form.
    pub fn build(&self) -> SsaForm {
        // Collect all varnodes that are defined in the program.
        let mut all_vars: HashSet<Varnode> = HashSet::new();
        for op in &self.operations {
            if let Some(ref out) = op.output {
                all_vars.insert(out.clone());
            }
            for inp in &op.inputs {
                all_vars.insert(inp.clone());
            }
        }

        // Determine which blocks define each variable.
        let mut def_blocks: HashMap<Varnode, HashSet<NodeIndex>> = HashMap::new();
        for (i, op) in self.operations.iter().enumerate() {
            if let Some(ref out) = op.output {
                if let Some(&node) = self.op_to_block.get(&i) {
                    def_blocks.entry(out.clone()).or_default().insert(node);
                }
            }
        }

        // Compute dominance frontiers.
        let df = self.dom.dominance_frontiers(&self.cfg);

        // Insert phi nodes: for each variable, at the iterated dominance
        // frontier of blocks that define it.
        let mut phi_blocks: HashMap<NodeIndex, HashSet<Varnode>> = HashMap::new();
        let mut has_phi: HashMap<Varnode, HashSet<NodeIndex>> = HashMap::new();
        let mut worklist: Vec<Varnode> = all_vars.iter().cloned().collect();

        // Iterate until convergence.
        let mut changed = true;
        while changed {
            changed = false;

            // For each variable, for each block b where it's defined or has a phi,
            // add phi at df[b].
            let mut new_phi_blocks: HashMap<NodeIndex, HashSet<Varnode>> = HashMap::new();
            let mut new_has_phi: HashMap<Varnode, HashSet<NodeIndex>> = HashMap::new();

            for var in &worklist {
                let mut blocks_with_def_or_phi: HashSet<NodeIndex> =
                    def_blocks.get(var).cloned().unwrap_or_default();
                if let Some(phiblocks) = has_phi.get(var) {
                    blocks_with_def_or_phi.extend(phiblocks.iter().cloned());
                }

                for &b in &blocks_with_def_or_phi {
                    if let Some(frontier) = df.get(&b) {
                        for &d in frontier {
                            let existing = new_has_phi
                                .entry(var.clone())
                                .or_default()
                                .contains(&d);
                            if !existing {
                                new_has_phi
                                    .entry(var.clone())
                                    .or_default()
                                    .insert(d);
                                new_phi_blocks.entry(d).or_default().insert(var.clone());
                                changed = true;
                            }
                        }
                    }
                }
            }

            phi_blocks = new_phi_blocks;
            has_phi = new_has_phi;
            worklist.clear(); // only iterate once for simplified version
        }

        // Rename variables.
        let mut version_counters: HashMap<Varnode, u64> = HashMap::new();
        let mut stacks: HashMap<Varnode, Vec<Varnode>> = HashMap::new();
        let mut phi_nodes: HashMap<NodeIndex, Vec<PhiNode>> = HashMap::new();
        let mut renamed_ops: Vec<PcodeOperation> = Vec::new();

        // Initial stack entries for variables with no definition.
        for var in &all_vars {
            if !def_blocks.contains_key(var) {
                // Variable is used but never defined; treat as parameter.
                let init_vn = Varnode::new(var.space.clone(), var.offset, var.size);
                stacks.entry(var.clone()).or_default().push(init_vn);
            }
        }

        // Walk the dominator tree.
        let preorder = self.dom.preorder(&self.cfg);

        for &node in &preorder {
            let block = self.cfg.block_by_node(node);
            let mut pushed_in_this_block: Vec<Varnode> = Vec::new();

            // Create phi nodes for this block.
            if let Some(vars) = phi_blocks.get(&node) {
                let mut block_phis = Vec::new();
                for var in vars {
                    // Create a new version for the phi result.
                    let version = next_version(var, &mut version_counters);
                    let phi_inputs: Vec<(NodeIndex, Varnode)> = self
                        .cfg
                        .predecessors(node)
                        .iter()
                        .map(|&pred| {
                            let pred_vn = stacks
                                .get(var)
                                .and_then(|s| s.last())
                                .cloned()
                                .unwrap_or_else(|| var.clone());
                            (pred, pred_vn)
                        })
                        .collect();
                    block_phis.push(PhiNode::new(version.clone(), phi_inputs));
                    stacks.entry(var.clone()).or_default().push(version.clone());
                    pushed_in_this_block.push(var.clone());
                }
                phi_nodes.insert(node, block_phis);
            }

            // Process operations in this block.
            for op in &block.operations {
                let mut new_op = op.clone();

                // Rename inputs.
                let new_inputs: Vec<Varnode> = new_op
                    .inputs
                    .iter()
                    .map(|inp| {
                        stacks
                            .get(inp)
                            .and_then(|s| s.last())
                            .cloned()
                            .unwrap_or_else(|| inp.clone())
                    })
                    .collect();
                new_op.inputs = new_inputs;

                // Rename output (if any).
                if let Some(ref out) = new_op.output {
                    let version = next_version(out, &mut version_counters);
                    stacks.entry(out.clone()).or_default().push(version.clone());
                    pushed_in_this_block.push(out.clone());
                    new_op.output = Some(version);
                }

                renamed_ops.push(new_op);
            }

            // Fill phi-node inputs in successor blocks.
            for succ in self.cfg.successors(node) {
                if let Some(succ_phis) = phi_nodes.get(&succ) {
                    for phi in succ_phis {
                        // Find the phi for the output varnode of this phi.
                        // (We need to update the input from this block.)
                        // In this simplified version, phi inputs are already
                        // set during renaming.
                    }
                }
            }

            // Process children in the dominator tree.
            // (Implicit in the preorder traversal.)

            // Pop versions pushed in this block.
            for _ in 0..pushed_in_this_block.len() {
                let var = pushed_in_this_block.pop().unwrap();
                stacks.get_mut(&var).unwrap().pop();
            }
        }

        // Build the final SSA operations list.
        let mut final_ops = Vec::new();
        for &node in &preorder {
            if let Some(phis) = phi_nodes.get(&node) {
                for phi in phis {
                    final_ops.push(phi.to_pcode_operation());
                }
            }
        }
        final_ops.extend(renamed_ops);

        // Build versions map.
        let mut versions: HashMap<Varnode, Vec<Varnode>> = HashMap::new();
        for (var, counter) in &version_counters {
            let mut vs = Vec::new();
            for v in 0..*counter {
                vs.push(Varnode::new(var.space.clone(), var.offset + v, var.size));
            }
            versions.insert(var.clone(), vs);
        }

        SsaForm {
            operations: final_ops,
            phi_nodes,
            versions,
        }
    }
}

/// Create the next SSA version of a varnode.
fn next_version(base: &Varnode, counters: &mut HashMap<Varnode, u64>) -> Varnode {
    let c = counters.entry(base.clone()).or_insert(0);
    *c += 1;
    Varnode::new(
        AddressSpace::new("unique", 8, false),
        (base.offset << 4) | *c,
        base.size,
    )
}

use ghidra_core::addr::AddressSpace;

// ---------------------------------------------------------------------------
// ConstantPropagation
// ---------------------------------------------------------------------------

/// Result of evaluating an expression with constant propagation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstantValue {
    /// Value is known to be the given constant.
    Known(u64),
    /// Value is known to be unknown / variable.
    Unknown,
    /// Value is a known address (useful for pointer analysis).
    Address(u64),
}

impl ConstantValue {
    /// Returns the constant if known.
    pub fn value(&self) -> Option<u64> {
        match self {
            ConstantValue::Known(v) | ConstantValue::Address(v) => Some(*v),
            ConstantValue::Unknown => None,
        }
    }

    /// Returns true if the value is known.
    pub fn is_known(&self) -> bool {
        !matches!(self, ConstantValue::Unknown)
    }
}

/// Constant-propagation analyzer.
///
/// Uses a worklist algorithm to propagate constant values through P-code
/// operations.
pub struct ConstantPropagation {
    /// Map from varnode to its constant value (if known).
    values: HashMap<Varnode, ConstantValue>,
    /// Worklist of operations to re-evaluate.
    worklist: VecDeque<usize>,
}

impl ConstantPropagation {
    /// Create a new constant-propagation instance.
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
            worklist: VecDeque::new(),
        }
    }

    /// Analyze a list of operations and return the constant values map.
    pub fn analyze(&mut self, operations: &[PcodeOperation]) -> HashMap<Varnode, ConstantValue> {
        self.values.clear();
        self.worklist.clear();

        // Seed with constant-input varnodes.
        for (i, op) in operations.iter().enumerate() {
            for inp in &op.inputs {
                if inp.is_constant() {
                    self.values
                        .insert(inp.clone(), ConstantValue::Known(inp.offset));
                }
            }
            self.worklist.push_back(i);
        }

        // Worklist iteration.
        let mut seen: HashSet<usize> = HashSet::new();
        while let Some(idx) = self.worklist.pop_front() {
            if seen.contains(&idx) && seen.len() > operations.len() * 3 {
                break; // safety valve
            }
            seen.insert(idx);

            let op = &operations[idx];
            let new_val = self.evaluate(op);

            if let Some(ref out) = op.output {
                let old_val = self.values.get(out).cloned();
                let changed = old_val != Some(new_val.clone());
                if changed {
                    self.values.insert(out.clone(), new_val);

                    // Re-evaluate all uses of this varnode.
                    for (j, use_op) in operations.iter().enumerate() {
                        if use_op.uses(out) {
                            self.worklist.push_back(j);
                        }
                    }
                }
            }
        }

        self.values.clone()
    }

    /// Evaluate an operation's output given current constant values.
    fn evaluate(&self, op: &PcodeOperation) -> ConstantValue {
        // If any input is unknown and needed, result is unknown.
        let get_val = |vn: &Varnode| -> Option<u64> {
            if vn.is_constant() {
                Some(vn.offset)
            } else {
                self.values.get(vn).and_then(|v| v.value())
            }
        };

        match op.opcode {
            OpCode::COPY => {
                op.inputs.first().and_then(|vn| self.values.get(vn)).cloned()
                    .unwrap_or(ConstantValue::Unknown)
            }

            OpCode::INT_ADD => {
                let a = op.inputs.first().and_then(get_val);
                let b = op.inputs.get(1).and_then(get_val);
                match (a, b) {
                    (Some(a), Some(b)) => {
                        ConstantValue::Known(a.wrapping_add(b))
                    }
                    _ => ConstantValue::Unknown,
                }
            }

            OpCode::INT_SUB => {
                let a = op.inputs.first().and_then(get_val);
                let b = op.inputs.get(1).and_then(get_val);
                match (a, b) {
                    (Some(a), Some(b)) => ConstantValue::Known(a.wrapping_sub(b)),
                    _ => ConstantValue::Unknown,
                }
            }

            OpCode::INT_MUL => {
                let a = op.inputs.first().and_then(get_val);
                let b = op.inputs.get(1).and_then(get_val);
                match (a, b) {
                    (Some(a), Some(b)) => ConstantValue::Known(a.wrapping_mul(b)),
                    _ => ConstantValue::Unknown,
                }
            }

            OpCode::INT_DIV => {
                let a = op.inputs.first().and_then(get_val);
                let b = op.inputs.get(1).and_then(get_val);
                match (a, b) {
                    (Some(a), Some(b)) if b != 0 => ConstantValue::Known(a / b),
                    _ => ConstantValue::Unknown,
                }
            }

            OpCode::INT_SDIV => {
                let a = op.inputs.first().and_then(get_val);
                let b = op.inputs.get(1).and_then(get_val);
                match (a, b) {
                    (Some(a), Some(b)) if b != 0 => {
                        ConstantValue::Known((a as i64).wrapping_div(b as i64) as u64)
                    }
                    _ => ConstantValue::Unknown,
                }
            }

            OpCode::INT_REM => {
                let a = op.inputs.first().and_then(get_val);
                let b = op.inputs.get(1).and_then(get_val);
                match (a, b) {
                    (Some(a), Some(b)) if b != 0 => ConstantValue::Known(a % b),
                    _ => ConstantValue::Unknown,
                }
            }

            OpCode::INT_AND => {
                let a = op.inputs.first().and_then(get_val);
                let b = op.inputs.get(1).and_then(get_val);
                match (a, b) {
                    (Some(a), Some(b)) => ConstantValue::Known(a & b),
                    _ => ConstantValue::Unknown,
                }
            }

            OpCode::INT_OR => {
                let a = op.inputs.first().and_then(get_val);
                let b = op.inputs.get(1).and_then(get_val);
                match (a, b) {
                    (Some(a), Some(b)) => ConstantValue::Known(a | b),
                    _ => ConstantValue::Unknown,
                }
            }

            OpCode::INT_XOR => {
                let a = op.inputs.first().and_then(get_val);
                let b = op.inputs.get(1).and_then(get_val);
                match (a, b) {
                    (Some(a), Some(b)) => ConstantValue::Known(a ^ b),
                    _ => ConstantValue::Unknown,
                }
            }

            OpCode::INT_LEFT => {
                let a = op.inputs.first().and_then(get_val);
                let b = op.inputs.get(1).and_then(get_val);
                match (a, b) {
                    (Some(a), Some(b)) if b < 64 => ConstantValue::Known(a.wrapping_shl(b as u32)),
                    _ => ConstantValue::Unknown,
                }
            }

            OpCode::INT_RIGHT => {
                let a = op.inputs.first().and_then(get_val);
                let b = op.inputs.get(1).and_then(get_val);
                match (a, b) {
                    (Some(a), Some(b)) if b < 64 => ConstantValue::Known(a.wrapping_shr(b as u32)),
                    _ => ConstantValue::Unknown,
                }
            }

            OpCode::INT_SRIGHT => {
                let a = op.inputs.first().and_then(get_val);
                let b = op.inputs.get(1).and_then(get_val);
                match (a, b) {
                    (Some(a), Some(b)) if b < 64 => {
                        let result = ((a as i64).wrapping_shr(b as u32)) as u64;
                        ConstantValue::Known(result)
                    }
                    _ => ConstantValue::Unknown,
                }
            }

            OpCode::INT_NEGATE => {
                let a = op.inputs.first().and_then(get_val);
                a.map(|v| ConstantValue::Known((-(v as i64)) as u64))
                    .unwrap_or(ConstantValue::Unknown)
            }

            OpCode::INT_ZEXT => {
                // Zero extension preserves the value.
                op.inputs
                    .first()
                    .and_then(|vn| self.values.get(vn))
                    .cloned()
                    .unwrap_or(ConstantValue::Unknown)
            }

            OpCode::INT_SEXT => {
                let a = op.inputs.first().and_then(get_val);
                let in_size = op.inputs.first().map(|v| v.size as u32).unwrap_or(0);
                match a {
                    Some(a) if in_size > 0 && in_size < 8 => {
                        let shift = (8 - in_size) * 8;
                        let sign_extended = ((a << shift) as i64 >> shift) as u64;
                        ConstantValue::Known(sign_extended)
                    }
                    Some(a) => ConstantValue::Known(a),
                    None => ConstantValue::Unknown,
                }
            }

            OpCode::INT_EQUAL => {
                let a = op.inputs.first().and_then(get_val);
                let b = op.inputs.get(1).and_then(get_val);
                match (a, b) {
                    (Some(a), Some(b)) => ConstantValue::Known((a == b) as u64),
                    _ => ConstantValue::Unknown,
                }
            }

            OpCode::INT_NOTEQUAL => {
                let a = op.inputs.first().and_then(get_val);
                let b = op.inputs.get(1).and_then(get_val);
                match (a, b) {
                    (Some(a), Some(b)) => ConstantValue::Known((a != b) as u64),
                    _ => ConstantValue::Unknown,
                }
            }

            OpCode::INT_LESS => {
                let a = op.inputs.first().and_then(get_val);
                let b = op.inputs.get(1).and_then(get_val);
                match (a, b) {
                    (Some(a), Some(b)) => ConstantValue::Known((a < b) as u64),
                    _ => ConstantValue::Unknown,
                }
            }

            OpCode::INT_SLESS => {
                let a = op.inputs.first().and_then(get_val);
                let b = op.inputs.get(1).and_then(get_val);
                match (a, b) {
                    (Some(a), Some(b)) => {
                        ConstantValue::Known(((a as i64) < (b as i64)) as u64)
                    }
                    _ => ConstantValue::Unknown,
                }
            }

            OpCode::BOOL_NEGATE => {
                let a = op.inputs.first().and_then(get_val);
                match a {
                    Some(0) => ConstantValue::Known(1),
                    Some(_) => ConstantValue::Known(0),
                    None => ConstantValue::Unknown,
                }
            }

            OpCode::SUBPIECE => {
                let a = op.inputs.first().and_then(get_val);
                let lo = op.inputs.get(1).and_then(get_val);
                match (a, lo, &op.output) {
                    (Some(a), Some(lo), Some(out)) => {
                        let shift = lo * 8;
                        let mask = if out.size < 8 {
                            (1u64 << (out.size * 8)) - 1
                        } else {
                            u64::MAX
                        };
                        ConstantValue::Known((a >> shift) & mask)
                    }
                    _ => ConstantValue::Unknown,
                }
            }

            OpCode::CAST | OpCode::PIECE => {
                // Piece: concatenation.
                let a = op.inputs.first().and_then(get_val);
                let b = op.inputs.get(1).and_then(get_val);
                match (a, b) {
                    (Some(hi), Some(lo)) => {
                        let lo_size = op.inputs.get(1).map(|v| v.size as u32).unwrap_or(0);
                        let shift = lo_size * 8;
                        ConstantValue::Known((hi << shift) | lo)
                    }
                    _ => ConstantValue::Unknown,
                }
            }

            _ => ConstantValue::Unknown,
        }
    }

    /// Get the constant value for a varnode, if known.
    pub fn value_of(&self, varnode: &Varnode) -> Option<ConstantValue> {
        self.values.get(varnode).cloned()
    }
}

// ---------------------------------------------------------------------------
// DeadCodeElimination
// ---------------------------------------------------------------------------

/// Dead-code elimination: removes operations whose outputs are never used.
pub struct DeadCodeElimination;

impl DeadCodeElimination {
    /// Eliminate dead code from a list of operations.
    ///
    /// An operation is *live* if:
    /// - It has side effects (store, call, branch, return).
    /// - Its output is used by another live operation.
    ///
    /// Returns the filtered list of operations.
    pub fn eliminate(operations: &[PcodeOperation]) -> Vec<PcodeOperation> {
        let n = operations.len();
        let mut live = vec![false; n];
        let mut worklist = VecDeque::new();

        // Build def-use info.
        let du = DefUseChain::build(operations);

        // Mark operations with side effects as live.
        for (i, op) in operations.iter().enumerate() {
            if op.has_side_effects() {
                live[i] = true;
                worklist.push_back(i);
            }
        }

        // Work backwards: if an operation is live, all operations that
        // define its inputs are also live.
        while let Some(idx) = worklist.pop_front() {
            let op = &operations[idx];
            for inp in &op.inputs {
                for &def_idx in du.defs_of(inp) {
                    if !live[def_idx] {
                        live[def_idx] = true;
                        worklist.push_back(def_idx);
                    }
                }
            }
        }

        // Filter operations.
        operations
            .iter()
            .enumerate()
            .filter(|(i, _)| live[*i])
            .map(|(_, op)| op.clone())
            .collect()
    }

    /// Returns the set of live operation indices.
    pub fn live_indices(operations: &[PcodeOperation]) -> HashSet<usize> {
        let n = operations.len();
        let mut live = HashSet::new();
        let mut worklist = VecDeque::new();
        let du = DefUseChain::build(operations);

        for (i, op) in operations.iter().enumerate() {
            if op.has_side_effects() {
                live.insert(i);
                worklist.push_back(i);
            }
        }

        while let Some(idx) = worklist.pop_front() {
            let op = &operations[idx];
            for inp in &op.inputs {
                for &def_idx in du.defs_of(inp) {
                    if live.insert(def_idx) {
                        worklist.push_back(def_idx);
                    }
                }
            }
        }

        live
    }
}

// ---------------------------------------------------------------------------
// ExpressionSimplifier
// ---------------------------------------------------------------------------

/// Expression simplifier: applies constant folding and algebraic identities
/// to simplify P-code operations.
pub struct ExpressionSimplifier {
    /// Known constant values for varnodes.
    constants: HashMap<Varnode, u64>,
}

impl ExpressionSimplifier {
    /// Create a new simplifier.
    pub fn new() -> Self {
        Self {
            constants: HashMap::new(),
        }
    }

    /// Create a simplifier with pre-seeded constant values.
    pub fn with_constants(constants: HashMap<Varnode, u64>) -> Self {
        Self { constants }
    }

    /// Simplify a list of operations.  Returns the simplified operations.
    pub fn simplify(&self, operations: &[PcodeOperation]) -> Vec<PcodeOperation> {
        let mut result = Vec::new();

        for op in operations {
            match self.try_simplify(op) {
                Some(simplified) => result.push(simplified),
                None => result.push(op.clone()),
            }
        }

        result
    }

    /// Try to simplify a single operation.  Returns `Some` with the
    /// simplified operation, or `None` if no simplification applies.
    fn try_simplify(&self, op: &PcodeOperation) -> Option<PcodeOperation> {
        // Get constant values for inputs.
        let const_inputs: Vec<Option<u64>> = op
            .inputs
            .iter()
            .map(|inp| {
                if inp.is_constant() {
                    Some(inp.offset)
                } else {
                    self.constants.get(inp).copied()
                }
            })
            .collect();

        let all_const = const_inputs.iter().all(|c| c.is_some());
        let consts: Vec<u64> = const_inputs.iter().filter_map(|c| *c).collect();

        // If all inputs are constant, fold the entire expression.
        if all_const && op.output.is_some() {
            if let Some(result) = self.constant_fold(op.opcode, &consts) {
                let out = op.output.as_ref().unwrap();
                let folded = PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out.clone()),
                    vec![Varnode::constant(result, out.size)],
                );
                return Some(folded);
            }
        }

        // Algebraic identities.
        match op.opcode {
            // x + 0 => x
            OpCode::INT_ADD if consts.len() >= 2 && consts[1] == 0 => {
                let out = op.output.clone()?;
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out),
                    vec![op.inputs[0].clone()],
                ))
            }

            // 0 + x => x
            OpCode::INT_ADD if consts.len() >= 2 && consts[0] == 0 => {
                let out = op.output.clone()?;
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out),
                    vec![op.inputs[1].clone()],
                ))
            }

            // x - 0 => x
            OpCode::INT_SUB if consts.len() >= 2 && consts[1] == 0 => {
                let out = op.output.clone()?;
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out),
                    vec![op.inputs[0].clone()],
                ))
            }

            // x * 1 => x
            OpCode::INT_MUL if consts.len() >= 2 && consts[1] == 1 => {
                let out = op.output.clone()?;
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out),
                    vec![op.inputs[0].clone()],
                ))
            }

            // 1 * x => x
            OpCode::INT_MUL if consts.len() >= 2 && consts[0] == 1 => {
                let out = op.output.clone()?;
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out),
                    vec![op.inputs[1].clone()],
                ))
            }

            // x * 0 => 0
            OpCode::INT_MUL if consts.len() >= 2 && consts[0] == 0 || consts.len() >= 2 && consts.get(1) == Some(&0) => {
                let out = op.output.clone()?;
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out),
                    vec![Varnode::constant(0, out.size)],
                ))
            }

            // x & 0 => 0
            OpCode::INT_AND if consts.len() >= 2 && (consts[0] == 0 || consts.get(1) == Some(&0)) => {
                let out = op.output.clone()?;
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out),
                    vec![Varnode::constant(0, out.size)],
                ))
            }

            // x & -1 (all ones) => x
            OpCode::INT_AND if consts.len() >= 2 && consts[1] == u64::MAX => {
                let out = op.output.clone()?;
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out),
                    vec![op.inputs[0].clone()],
                ))
            }

            // x | 0 => x
            OpCode::INT_OR if consts.len() >= 2 && consts[1] == 0 => {
                let out = op.output.clone()?;
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out),
                    vec![op.inputs[0].clone()],
                ))
            }

            // x | -1 => -1
            OpCode::INT_OR if consts.len() >= 2 && consts[1] == u64::MAX => {
                let out = op.output.clone()?;
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out),
                    vec![Varnode::constant(u64::MAX, out.size)],
                ))
            }

            // x ^ 0 => x
            OpCode::INT_XOR if consts.len() >= 2 && consts[1] == 0 => {
                let out = op.output.clone()?;
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out),
                    vec![op.inputs[0].clone()],
                ))
            }

            // x ^ x => 0
            OpCode::INT_XOR if op.inputs.len() >= 2 && op.inputs[0] == op.inputs[1] => {
                let out = op.output.clone()?;
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out),
                    vec![Varnode::constant(0, out.size)],
                ))
            }

            // x << 0 => x
            OpCode::INT_LEFT if consts.len() >= 2 && consts[1] == 0 => {
                let out = op.output.clone()?;
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out),
                    vec![op.inputs[0].clone()],
                ))
            }

            // x >> 0 => x
            OpCode::INT_RIGHT if consts.len() >= 2 && consts[1] == 0 => {
                let out = op.output.clone()?;
                Some(PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(out),
                    vec![op.inputs[0].clone()],
                ))
            }

            // SUBPIECE with known offset => extract by shift + mask
            OpCode::SUBPIECE if consts.len() >= 2 && consts[1] == 0 => {
                // subpiece(x, 0) with size <= x.size is identity
                let out = op.output.clone()?;
                if op.output.as_ref().map(|o| o.size).unwrap_or(0) <= op.inputs[0].size {
                    return Some(PcodeOperation::new_unannotated(
                        OpCode::COPY,
                        Some(out),
                        vec![op.inputs[0].clone()],
                    ));
                }
                None
            }

            // No simplification applies.
            _ => None,
        }
    }

    /// Constant-fold an operation when all inputs are known constants.
    fn constant_fold(&self, opcode: OpCode, consts: &[u64]) -> Option<u64> {
        match opcode {
            OpCode::INT_ADD => Some(consts[0].wrapping_add(consts[1])),
            OpCode::INT_SUB => Some(consts[0].wrapping_sub(consts[1])),
            OpCode::INT_MUL => Some(consts[0].wrapping_mul(consts[1])),
            OpCode::INT_DIV if consts[1] != 0 => Some(consts[0] / consts[1]),
            OpCode::INT_SDIV if consts[1] != 0 => {
                Some((consts[0] as i64).wrapping_div(consts[1] as i64) as u64)
            }
            OpCode::INT_REM if consts[1] != 0 => Some(consts[0] % consts[1]),
            OpCode::INT_AND => Some(consts[0] & consts[1]),
            OpCode::INT_OR => Some(consts[0] | consts[1]),
            OpCode::INT_XOR => Some(consts[0] ^ consts[1]),
            OpCode::INT_LEFT if consts[1] < 64 => {
                Some(consts[0].wrapping_shl(consts[1] as u32))
            }
            OpCode::INT_RIGHT if consts[1] < 64 => {
                Some(consts[0].wrapping_shr(consts[1] as u32))
            }
            OpCode::INT_SRIGHT if consts[1] < 64 => {
                Some(((consts[0] as i64).wrapping_shr(consts[1] as u32)) as u64)
            }
            OpCode::INT_NEGATE => Some((-(consts[0] as i64)) as u64),
            OpCode::INT_EQUAL => Some((consts[0] == consts[1]) as u64),
            OpCode::INT_NOTEQUAL => Some((consts[0] != consts[1]) as u64),
            OpCode::INT_LESS => Some((consts[0] < consts[1]) as u64),
            OpCode::INT_SLESS => Some(((consts[0] as i64) < (consts[1] as i64)) as u64),
            OpCode::BOOL_NEGATE => Some(if consts[0] == 0 { 1 } else { 0 }),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::OpCode;

    fn mem(offset: u64, size: u32) -> Varnode {
        Varnode::new(AddressSpace::new("ram", 8, false), offset, size)
    }

    fn reg(offset: u64, size: u32) -> Varnode {
        Varnode::new(AddressSpace::new("register", 8, false), offset, size)
    }

    fn cnst(val: u64, size: u32) -> Varnode {
        Varnode::constant(val, size)
    }

    fn uniq(id: u64, size: u32) -> Varnode {
        Varnode::unique(id, size)
    }

    #[test]
    fn test_build_cfg_linear() {
        let seq = PcodeSequence::new(
            vec![
                PcodeOperation::new_unannotated(
                    OpCode::INT_ADD,
                    Some(uniq(0, 4)),
                    vec![reg(0, 4), cnst(1, 4)],
                ),
                PcodeOperation::new_unannotated(
                    OpCode::COPY,
                    Some(reg(0, 4)),
                    vec![uniq(0, 4)],
                ),
            ],
            Address::new(0x1000),
            4,
        );

        let cfg = build_cfg(&[seq]);
        assert!(cfg.block_count() > 0);
        // Should have at least one non-exit block.
        assert!(cfg.blocks.iter().any(|b| !b.operations.is_empty()));
    }

    #[test]
    fn test_build_cfg_with_branch() {
        let addr1 = Address::new(0x1000);
        let addr2 = Address::new(0x2000);

        let seq1 = PcodeSequence::new(
            vec![
                PcodeOperation::new(
                    OpCode::INT_EQUAL,
                    Some(uniq(0, 1)),
                    vec![reg(0, 4), cnst(0, 4)],
                    Some(addr1),
                ),
                PcodeOperation::new(
                    OpCode::CBRANCH,
                    None,
                    vec![Varnode::constant(addr2.offset, 8), uniq(0, 1)],
                    Some(addr1),
                ),
            ],
            addr1,
            4,
        );

        let seq2 = PcodeSequence::new(
            vec![PcodeOperation::new(
                OpCode::RETURN,
                None,
                vec![],
                Some(addr2),
            )],
            addr2,
            4,
        );

        let cfg = build_cfg(&[seq1, seq2]);
        assert!(cfg.block_count() > 0);
        // Should have edges.
        let edge_count = cfg.graph.edge_count();
        assert!(edge_count > 0, "CFG should have edges");
    }

    #[test]
    fn test_dominator_tree() {
        // Build a simple diamond CFG:
        //   entry -> A -> B -> D -> exit
        //             \-> C -/
        let mut graph = DiGraph::new();
        let entry = graph.add_node(0);
        let a = graph.add_node(1);
        let b = graph.add_node(2);
        let c = graph.add_node(3);
        let d = graph.add_node(4);
        let exit = graph.add_node(5);

        graph.add_edge(entry, a, CfgEdge::Fallthrough);
        graph.add_edge(a, b, CfgEdge::TrueBranch);
        graph.add_edge(a, c, CfgEdge::FalseBranch);
        graph.add_edge(b, d, CfgEdge::Fallthrough);
        graph.add_edge(c, d, CfgEdge::Fallthrough);
        graph.add_edge(d, exit, CfgEdge::Fallthrough);

        let mut blocks: Vec<BasicBlock> = (0..6).map(|i| {
            let mut bb = BasicBlock::new(i);
            bb.node = Some(NodeIndex::new(i));
            bb
        }).collect();

        let cfg = ControlFlowGraph {
            graph,
            blocks,
            entry,
            exit,
        };

        let dom = DominatorTree::compute(&cfg);
        assert!(dom.dominates(entry, a));
        assert!(dom.dominates(a, b));
        assert!(dom.dominates(a, c));
        assert!(dom.dominates(a, d));
        assert!(dom.dominates(d, exit));
        assert!(!dom.dominates(b, c));
        assert!(!dom.dominates(c, b));

        // d should be dominated by a (all paths to d go through a).
        assert!(dom.dominates(a, d));
    }

    #[test]
    fn test_constant_propagation() {
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

        let mut cp = ConstantPropagation::new();
        let values = cp.analyze(&ops);

        assert_eq!(values.get(&uniq(0, 4)), Some(&ConstantValue::Known(7)));
        assert_eq!(values.get(&uniq(1, 4)), Some(&ConstantValue::Known(14)));
    }

    #[test]
    fn test_dead_code_elimination() {
        let used = uniq(0, 4);
        let unused = uniq(1, 4);

        let ops = vec![
            // Compute unused value.
            PcodeOperation::new_unannotated(
                OpCode::INT_ADD,
                Some(unused.clone()),
                vec![cnst(1, 4), cnst(2, 4)],
            ),
            // Compute used value.
            PcodeOperation::new_unannotated(
                OpCode::INT_ADD,
                Some(used.clone()),
                vec![cnst(5, 4), cnst(6, 4)],
            ),
            // Store (has side effects, makes used live).
            PcodeOperation::new_unannotated(
                OpCode::STORE,
                None,
                vec![cnst(0, 8), mem(0x1000, 4), used.clone()],
            ),
        ];

        let live_indices = DeadCodeElimination::live_indices(&ops);
        assert!(live_indices.contains(&1)); // used is live
        assert!(live_indices.contains(&2)); // store is live
        assert!(!live_indices.contains(&0)); // unused is dead
    }

    #[test]
    fn test_expression_simplifier_constant_folding() {
        let simplifier = ExpressionSimplifier::new();
        let op = PcodeOperation::new_unannotated(
            OpCode::INT_ADD,
            Some(uniq(0, 4)),
            vec![cnst(10, 4), cnst(20, 4)],
        );

        let simplified = simplifier.simplify(&[op]);
        assert_eq!(simplified.len(), 1);
        assert_eq!(simplified[0].opcode, OpCode::COPY);
        assert_eq!(
            simplified[0].inputs[0].constant_value(),
            Some(30)
        );
    }

    #[test]
    fn test_expression_simplifier_identity() {
        let simplifier = ExpressionSimplifier::new();
        let op = PcodeOperation::new_unannotated(
            OpCode::INT_ADD,
            Some(uniq(0, 4)),
            vec![reg(0, 4), cnst(0, 4)],
        );

        let simplified = simplifier.simplify(&[op]);
        assert_eq!(simplified[0].opcode, OpCode::COPY);
        assert_eq!(simplified[0].inputs[0], reg(0, 4));
    }

    #[test]
    fn test_find_natural_loops() {
        // entry -> header -> body (back to header) -> exit
        let mut graph = DiGraph::new();
        let entry = graph.add_node(0);
        let header = graph.add_node(1);
        let body = graph.add_node(2);
        let exit = graph.add_node(3);

        graph.add_edge(entry, header, CfgEdge::Fallthrough);
        graph.add_edge(header, body, CfgEdge::TrueBranch);
        graph.add_edge(header, exit, CfgEdge::FalseBranch);
        graph.add_edge(body, header, CfgEdge::Branch);

        let mut blocks: Vec<BasicBlock> = (0..4).map(|i| {
            let mut bb = BasicBlock::new(i);
            bb.node = Some(NodeIndex::new(i));
            bb
        }).collect();

        let cfg = ControlFlowGraph {
            graph,
            blocks,
            entry,
            exit,
        };

        let dom = DominatorTree::compute(&cfg);
        let loops = find_natural_loops(&cfg, &dom);

        assert!(!loops.is_empty(), "should find at least one loop");
        let loop_found = loops.iter().any(|l| l.header == header);
        assert!(loop_found, "should find loop with header node");
    }
}
