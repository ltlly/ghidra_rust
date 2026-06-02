//! Control-flow graph construction for the decompiler.
//!
//! Builds a petgraph-based control-flow graph from P-code sequences.
//! Each basic block is a maximal sequence of operations with single entry
//! and single exit; edges represent control-flow transfers (branches,
//! calls, returns, fall-through).

use std::collections::HashMap;

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;

use ghidra_core::addr::Address;
use ghidra_core::error::Result as GhidraResult;

use crate::pcode::{OpCode, PcodeOperation, PcodeSequence, Varnode};

// ============================================================================
// BasicBlock
// ============================================================================

/// A basic block: a maximal straight-line sequence of P-code operations
/// with a single entry point and a single exit (terminator) point.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// The starting address of this block (address of the first operation).
    pub start: Address,
    /// The ending address of this block (address of the last operation).
    pub end: Address,
    /// The P-code operations in execution order.
    pub operations: Vec<PcodeOperation>,
    /// Assigned node index in the CFG after construction.
    pub node: Option<NodeIndex>,
    /// Unique block identifier.
    pub id: usize,
}

impl BasicBlock {
    /// Create a new empty basic block with the given id.
    pub fn new(id: usize) -> Self {
        Self {
            start: Address::NULL,
            end: Address::NULL,
            operations: Vec::new(),
            node: None,
            id,
        }
    }

    /// Create a basic block from a slice of operations and an address range.
    pub fn with_ops(
        id: usize,
        operations: Vec<PcodeOperation>,
        start: Address,
        end: Address,
    ) -> Self {
        Self {
            start,
            end,
            operations,
            node: None,
            id,
        }
    }

    /// Returns the terminator operation (last op if it is a control-flow op).
    pub fn terminator(&self) -> Option<&PcodeOperation> {
        self.operations.last().filter(|op| op.is_terminator())
    }

    /// Returns true if this block ends with a branch, call, or return.
    pub fn has_terminator(&self) -> bool {
        self.terminator().is_some()
    }

    /// Returns the direct branch target address, if the terminator is a
    /// direct BRANCH or CBRANCH whose target is a constant.
    pub fn direct_branch_target(&self) -> Option<Address> {
        self.terminator().and_then(|op| match op.opcode {
            OpCode::BRANCH | OpCode::CBRANCH => {
                op.inputs.first().and_then(|v| v.constant_value()).map(Address::new)
            }
            _ => None,
        })
    }

    /// Number of operations in this block.
    pub fn len(&self) -> usize {
        self.operations.len()
    }

    /// Returns true if the block has no operations.
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// Collect the set of varnodes defined (written) in this block.
    pub fn defined_varnodes(&self) -> Vec<&Varnode> {
        self.operations
            .iter()
            .filter_map(|op| op.output.as_ref())
            .collect()
    }

    /// Collect the set of varnodes used (read) in this block.
    pub fn used_varnodes(&self) -> Vec<&Varnode> {
        self.operations
            .iter()
            .flat_map(|op| op.inputs.iter())
            .collect()
    }
}

// ============================================================================
// CfgEdge
// ============================================================================

/// Edge type in the control-flow graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CfgEdge {
    /// Normal fall-through to the next block (sequential execution).
    FallThrough,
    /// Conditional or unconditional branch. The `bool` indicates the branch
    /// polarity: `true` means taken, `false` means not-taken.
    Branch(bool),
    /// Call edge: the call returns here (fall-through edge after call).
    Call,
    /// Return from function (edge to the exit node).
    Return,
}

impl CfgEdge {
    /// Returns `true` if this edge represents an unconditional transfer.
    pub fn is_unconditional(&self) -> bool {
        matches!(self, CfgEdge::Branch(true))
    }

    /// Returns `true` if this edge represents a conditional transfer.
    pub fn is_conditional(&self) -> bool {
        matches!(self, CfgEdge::Branch(false))
    }

    /// Returns `true` if this is a fall-through edge.
    pub fn is_fallthrough(&self) -> bool {
        matches!(self, CfgEdge::FallThrough)
    }
}

// ============================================================================
// ControlFlowGraph
// ============================================================================

/// A control-flow graph built from P-code sequences.
///
/// The graph is represented as a petgraph `DiGraph`. Node weights are block
/// indices into the `blocks` vector. Edges carry [`CfgEdge`] labels.
///
/// The CFG always has a distinguished `entry` node (the first basic block)
/// and an `exit` node (the unique sink for returns and edges leaving the
/// function).
#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    /// The petgraph directed graph. Node weights are block ids.
    pub graph: DiGraph<usize, CfgEdge>,
    /// All basic blocks, indexed by their `id`.
    pub blocks: Vec<BasicBlock>,
    /// Entry block node index.
    pub entry: NodeIndex,
    /// Exit block node index (the universal sink for returns).
    pub exit: NodeIndex,
}

impl ControlFlowGraph {
    /// Number of basic blocks (including the exit block).
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Get a reference to a basic block by its node index.
    pub fn block_by_node(&self, node: NodeIndex) -> &BasicBlock {
        let id = self.graph[node];
        &self.blocks[id]
    }

    /// Get a mutable reference to a basic block by its node index.
    pub fn block_by_node_mut(&mut self, node: NodeIndex) -> &mut BasicBlock {
        let id = self.graph[node];
        &mut self.blocks[id]
    }

    /// Get a reference to a basic block by its id.
    pub fn block_by_id(&self, id: usize) -> Option<&BasicBlock> {
        self.blocks.get(id)
    }

    /// Returns the successor node indices for a given node.
    pub fn successors(&self, node: NodeIndex) -> Vec<NodeIndex> {
        self.graph
            .neighbors_directed(node, Direction::Outgoing)
            .collect()
    }

    /// Returns the predecessor node indices for a given node.
    pub fn predecessors(&self, node: NodeIndex) -> Vec<NodeIndex> {
        self.graph
            .neighbors_directed(node, Direction::Incoming)
            .collect()
    }

    /// Returns the edge type between two nodes, if an edge exists.
    pub fn edge_between(&self, from: NodeIndex, to: NodeIndex) -> Option<CfgEdge> {
        self.graph
            .edges_connecting(from, to)
            .next()
            .map(|e| *e.weight())
    }

    /// Returns true if there is an edge from `from` to `to`.
    pub fn has_edge(&self, from: NodeIndex, to: NodeIndex) -> bool {
        self.graph.contains_edge(from, to)
    }

    /// Returns the number of edges in the CFG.
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Returns all node indices in the graph.
    pub fn nodes(&self) -> Vec<NodeIndex> {
        self.graph.node_indices().collect()
    }

    /// Walk the CFG in reverse postorder (useful for data-flow analysis
    /// where we want definitions to be processed before uses).
    pub fn reverse_postorder(&self) -> Vec<NodeIndex> {
        let mut order = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut stack: Vec<(NodeIndex, bool)> = vec![(self.entry, false)];

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

        order.reverse();
        order
    }

    /// Returns an iterator over all edges with their source, target, and
    /// edge type.
    pub fn edges(&self) -> impl Iterator<Item = (NodeIndex, NodeIndex, CfgEdge)> + '_ {
        self.graph
            .edge_references()
            .map(|e| (e.source(), e.target(), *e.weight()))
    }
}

// ============================================================================
// CFG Construction
// ============================================================================

/// Build a control-flow graph from a list of P-code sequences.
///
/// This is the main entry point for CFG construction. The algorithm:
///
/// 1. **Flatten** all sequences into a single list of operations, preserving
///    instruction-address annotations.
/// 2. **Identify leaders** -- the first operation, branch targets, and
///    operations following branches.
/// 3. **Create basic blocks** for each leader-to-leader range.
/// 4. **Add edges** based on each block's terminator.
///
/// # Errors
///
/// Returns an error if the input contains operations that cannot be
/// resolved to known addresses.
pub fn build_cfg(sequences: &[PcodeSequence]) -> GhidraResult<ControlFlowGraph> {
    // Step 1: flatten all operations.
    let mut flat_ops: Vec<PcodeOperation> = Vec::new();
    for seq in sequences {
        flat_ops.extend(seq.flatten());
    }

    if flat_ops.is_empty() {
        return Ok(empty_cfg());
    }

    // Step 2: identify leaders.
    let leader_mask = find_leaders(&flat_ops);
    let leader_indices: Vec<usize> =
        (0..flat_ops.len()).filter(|&i| leader_mask[i]).collect();

    // Step 3: build blocks from leader ranges.
    let mut blocks: Vec<BasicBlock> = Vec::new();
    let mut op_to_block: HashMap<usize, usize> = HashMap::new();
    let mut addr_to_block: HashMap<u64, usize> = HashMap::new();

    for (blk_idx, &start_idx) in leader_indices.iter().enumerate() {
        let end_idx = if blk_idx + 1 < leader_indices.len() {
            leader_indices[blk_idx + 1]
        } else {
            flat_ops.len()
        };

        let ops: Vec<PcodeOperation> = flat_ops[start_idx..end_idx].to_vec();

        let start_addr = ops
            .first()
            .and_then(|op| op.address)
            .unwrap_or(Address::NULL);
        let end_addr = ops
            .last()
            .and_then(|op| op.address)
            .unwrap_or(start_addr);

        // Register address-to-block mapping for branch resolution.
        if !start_addr.is_null() {
            addr_to_block.insert(start_addr.offset, blk_idx);
        }
        for i in start_idx..end_idx {
            op_to_block.insert(i, blk_idx);
        }

        let mut bb = BasicBlock::with_ops(blk_idx, ops, start_addr, end_addr);
        blocks.push(bb);
    }

    // Step 4: create graph nodes.
    let mut graph: DiGraph<usize, CfgEdge> = DiGraph::new();
    let block_nodes: Vec<NodeIndex> =
        (0..blocks.len()).map(|id| graph.add_node(id)).collect();

    for (i, node) in block_nodes.iter().enumerate() {
        blocks[i].node = Some(*node);
    }

    // Create the exit node.
    let exit_id = blocks.len();
    let exit_node = graph.add_node(exit_id);
    let exit_bb = BasicBlock::new(exit_id);
    blocks.push(exit_bb);

    // Step 5: add edges based on terminators.
    for i in 0..block_nodes.len() {
        let node = block_nodes[i];
        let block = &blocks[i];

        if let Some(terminator) = block.terminator() {
            match terminator.opcode {
                OpCode::BRANCH => {
                    if let Some(target) = block.direct_branch_target() {
                        if let Some(&target_blk) = addr_to_block.get(&target.offset) {
                            graph.add_edge(node, block_nodes[target_blk], CfgEdge::Branch(true));
                        } else {
                            // Target outside known blocks: edge to exit.
                            graph.add_edge(node, exit_node, CfgEdge::Branch(true));
                        }
                    } else {
                        // Indirect or unresolvable: fall through.
                        if i + 1 < block_nodes.len() {
                            graph.add_edge(node, block_nodes[i + 1], CfgEdge::FallThrough);
                        } else {
                            graph.add_edge(node, exit_node, CfgEdge::FallThrough);
                        }
                    }
                }
                OpCode::CBRANCH => {
                    // Taken path.
                    if let Some(target) = block.direct_branch_target() {
                        if let Some(&target_blk) = addr_to_block.get(&target.offset) {
                            graph.add_edge(node, block_nodes[target_blk], CfgEdge::Branch(true));
                        } else {
                            graph.add_edge(node, exit_node, CfgEdge::Branch(true));
                        }
                    }
                    // Not-taken path: fall-through to next block.
                    if i + 1 < block_nodes.len() {
                        graph.add_edge(node, block_nodes[i + 1], CfgEdge::Branch(false));
                    } else {
                        graph.add_edge(node, exit_node, CfgEdge::Branch(false));
                    }
                }
                OpCode::BRANCHIND => {
                    // Indirect branch: edges to all possible targets are unknown.
                    // Add a single edge to exit for conservativeness.
                    graph.add_edge(node, exit_node, CfgEdge::Branch(true));
                }
                OpCode::CALL | OpCode::CALLIND => {
                    // Call: fall-through is the return point.
                    if i + 1 < block_nodes.len() {
                        graph.add_edge(node, block_nodes[i + 1], CfgEdge::Call);
                    } else {
                        graph.add_edge(node, exit_node, CfgEdge::Call);
                    }
                }
                OpCode::RETURN => {
                    graph.add_edge(node, exit_node, CfgEdge::Return);
                }
                _ => {
                    // Non-terminator: fall-through.
                    add_fallthrough(&mut graph, node, i, &block_nodes, exit_node);
                }
            }
        } else {
            // No terminator: natural fall-through.
            add_fallthrough(&mut graph, node, i, &block_nodes, exit_node);
        }
    }

    Ok(ControlFlowGraph {
        graph,
        blocks,
        entry: block_nodes[0],
        exit: exit_node,
    })
}

/// Add a fall-through edge from a block to its successor (or to exit).
fn add_fallthrough(
    graph: &mut DiGraph<usize, CfgEdge>,
    node: NodeIndex,
    block_idx: usize,
    block_nodes: &[NodeIndex],
    exit_node: NodeIndex,
) {
    if block_idx + 1 < block_nodes.len() {
        graph.add_edge(node, block_nodes[block_idx + 1], CfgEdge::FallThrough);
    } else {
        graph.add_edge(node, exit_node, CfgEdge::FallThrough);
    }
}

/// Create an empty CFG (no P-code operations).
fn empty_cfg() -> ControlFlowGraph {
    let mut graph = DiGraph::new();
    let entry = graph.add_node(0);
    let exit = graph.add_node(1);

    let blocks = vec![
        {
            let mut bb = BasicBlock::new(0);
            bb.node = Some(entry);
            bb
        },
        {
            let mut bb = BasicBlock::new(1);
            bb.node = Some(exit);
            bb
        },
    ];

    graph.add_edge(entry, exit, CfgEdge::FallThrough);

    ControlFlowGraph {
        graph,
        blocks,
        entry,
        exit,
    }
}

/// Identify leader operations in a flat list.
///
/// Leaders are:
/// - The first operation.
/// - The target of any branch.
/// - The operation immediately after any branch.
fn find_leaders(ops: &[PcodeOperation]) -> Vec<bool> {
    let n = ops.len();
    let mut is_leader = vec![false; n];
    if n == 0 {
        return is_leader;
    }

    is_leader[0] = true; // first op is always a leader.

    // Build address-to-index map for branch-target resolution.
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
                if i + 1 < n {
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::AddressSpace;

    fn test_addr(offset: u64) -> Address {
        Address::new(offset)
    }

    fn uniq(id: u64, size: u32) -> Varnode {
        Varnode::unique(id, size)
    }

    fn cnst(val: u64, size: u32) -> Varnode {
        Varnode::constant(val, size)
    }

    fn reg(offset: u64, size: u32) -> Varnode {
        Varnode::register("r", offset, size)
    }

    #[test]
    fn test_empty_cfg() {
        let cfg = build_cfg(&[]).unwrap();
        assert_eq!(cfg.block_count(), 2); // entry + exit
        assert!(cfg.has_edge(cfg.entry, cfg.exit));
    }

    #[test]
    fn test_single_linear_block() {
        let seq = PcodeSequence::new(
            vec![PcodeOperation::new(
                OpCode::INT_ADD,
                Some(uniq(0, 4)),
                vec![reg(0, 4), cnst(1, 4)],
                Some(test_addr(0x1000)),
            )],
            test_addr(0x1000),
            4,
        );

        let cfg = build_cfg(&[seq]).unwrap();
        assert!(cfg.block_count() > 0);
        // Should have at least one non-exit block with ops.
        let has_ops = cfg.blocks.iter().any(|b| !b.is_empty());
        assert!(has_ops);
    }

    #[test]
    fn test_branch_to_address() {
        let addr1 = test_addr(0x1000);
        let addr2 = test_addr(0x2000);

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
                    vec![cnst(addr2.offset, 8), uniq(0, 1)],
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

        let cfg = build_cfg(&[seq1, seq2]).unwrap();
        assert!(cfg.edge_count() > 0, "CFG should have edges");
    }

    #[test]
    fn test_successors_and_predecessors() {
        let addr = test_addr(0x1000);
        let seq = PcodeSequence::new(
            vec![PcodeOperation::new(
                OpCode::RETURN,
                None,
                vec![],
                Some(addr),
            )],
            addr,
            4,
        );

        let cfg = build_cfg(&[seq]).unwrap();
        let entry = cfg.entry;
        let succs = cfg.successors(entry);
        assert!(!succs.is_empty());
    }

    #[test]
    fn test_reverse_postorder() {
        let addr = test_addr(0x1000);
        let seq = PcodeSequence::new(
            vec![
                PcodeOperation::new(
                    OpCode::INT_ADD,
                    Some(uniq(0, 4)),
                    vec![cnst(1, 4), cnst(2, 4)],
                    Some(addr),
                ),
                PcodeOperation::new(
                    OpCode::RETURN,
                    None,
                    vec![],
                    Some(addr),
                ),
            ],
            addr,
            4,
        );

        let cfg = build_cfg(&[seq]).unwrap();
        let rpo = cfg.reverse_postorder();
        assert!(!rpo.is_empty());
        // Entry should appear somewhere in RPO.
        assert!(rpo.contains(&cfg.entry));
    }

    #[test]
    fn test_basic_block_terminator() {
        let addr = test_addr(0x1000);
        let bb = BasicBlock::with_ops(
            0,
            vec![PcodeOperation::new(
                OpCode::RETURN,
                None,
                vec![],
                Some(addr),
            )],
            addr,
            addr,
        );
        assert!(bb.has_terminator());
        assert!(bb.terminator().is_some());
        assert_eq!(bb.terminator().unwrap().opcode, OpCode::RETURN);
    }

    #[test]
    fn test_basic_block_no_terminator() {
        let bb = BasicBlock::with_ops(
            0,
            vec![PcodeOperation::new_unannotated(
                OpCode::INT_ADD,
                Some(uniq(0, 4)),
                vec![cnst(1, 4), cnst(2, 4)],
            )],
            test_addr(0x1000),
            test_addr(0x1000),
        );
        assert!(!bb.has_terminator());
    }

    #[test]
    fn test_cfg_edge_classification() {
        assert!(CfgEdge::Branch(true).is_unconditional());
        assert!(!CfgEdge::Branch(true).is_conditional());
        assert!(CfgEdge::Branch(false).is_conditional());
        assert!(CfgEdge::FallThrough.is_fallthrough());
        assert!(!CfgEdge::Call.is_fallthrough());
    }
}
