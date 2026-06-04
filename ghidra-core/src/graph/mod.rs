//! Graph analysis types for control flow, data flow, and call graphs.
//!
//! Provides [`ControlFlowGraph`] for block-level CFG operations using petgraph,
//! [`CallGraph`] for caller-callee relationships, [`DominatorTree`] /
//! [`PostDominatorTree`] for dominance analysis, [`LoopInfo`] for natural loop
//! detection, and [`GraphAlgorithms`] for generic graph traversal and analysis.
//!
//! Built on top of the [`petgraph`] crate for efficient graph algorithms.
//!
//! ## Generic Graph Framework
//!
//! Also provides the generic graph framework ported from Ghidra's Java code:
//! - Core traits: [`traits::GEdge`], [`traits::GDirectedGraph`], [`traits::GImplicitDirectedGraph`]
//! - Default edge: [`default_edge::DefaultGEdge`]
//! - Graph implementations: [`hash_graph::HashDirectedGraph`]
//! - Path types: [`graph_path::GraphPath`], [`graph_path::GraphPathSet`]
//! - Edge metrics: [`edge_weight::GEdgeWeightMetric`]
//! - Factory: [`factory::GraphFactory`]
//! - Tree conversion: [`graph_to_tree::GraphToTreeAlgorithm`]
//! - Algorithms: [`algo::GraphNavigator`], [`algo::DepthFirstSorter`],
//!   [`algo::DijkstraShortestPaths`], [`algo::JohnsonCircuitsAlgorithm`],
//!   [`algo::TarjanSCC`], [`algo::ChkDominanceAlgorithm`]
//! - Path finding: [`algo::find_paths_iterative`], [`algo::find_paths_recursive`]

// Submodules for the generic graph framework
pub mod traits;
pub mod default_edge;
pub mod edge_weight;
pub mod graph_path;
pub mod hash_graph;
pub mod factory;
pub mod graph_to_tree;
pub mod algo;
mod tests_new;

use std::collections::{HashMap, HashSet, VecDeque};

use petgraph::algo as petalgo;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::{Dfs, EdgeRef};
use petgraph::Direction;

use crate::addr::Address;

// ============================================================================
// ControlFlowGraph
// ============================================================================

/// An index into a [`ControlFlowGraph`], opaque wrapper over `NodeIndex`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockIndex(NodeIndex);

impl BlockIndex {
    /// Return the underlying petgraph node index.
    pub fn index(&self) -> NodeIndex {
        self.0
    }
}

/// A basic block in the control-flow graph.
///
/// Each block has an optional start/end address and a list of instruction
/// addresses contained within it.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// Unique numeric identifier for this block (0-based insertion order).
    pub id: usize,
    /// Optional human-readable label (e.g., "entry", "loop_header").
    pub label: Option<String>,
    /// Start address of the block (inclusive).
    pub start_address: Option<Address>,
    /// End address of the block (exclusive).
    pub end_address: Option<Address>,
    /// Instruction addresses within this block, in order.
    pub instructions: Vec<Address>,
    /// Whether this block is the entry block.
    pub is_entry: bool,
    /// Whether this block is an exit block (no outgoing edges).
    pub is_exit: bool,
}

impl BasicBlock {
    /// Create a new basic block with the given label.
    pub fn new(id: usize, label: impl Into<String>) -> Self {
        Self {
            id,
            label: Some(label.into()),
            start_address: None,
            end_address: None,
            instructions: Vec::new(),
            is_entry: false,
            is_exit: false,
        }
    }

    /// Create a basic block with an address range.
    pub fn with_range(id: usize, start: Address, end: Address) -> Self {
        Self {
            id,
            label: None,
            start_address: Some(start),
            end_address: Some(end),
            instructions: Vec::new(),
            is_entry: false,
            is_exit: false,
        }
    }

    /// Returns the number of instructions in this block.
    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    /// Returns the first instruction address, if any.
    pub fn first_instruction(&self) -> Option<Address> {
        self.instructions.first().copied()
    }

    /// Returns the last instruction address, if any.
    pub fn last_instruction(&self) -> Option<Address> {
        self.instructions.last().copied()
    }
}

/// Data associated with a control-flow edge.
#[derive(Debug, Clone)]
pub struct ControlFlowEdge {
    /// The type of control-flow transition.
    pub edge_type: ControlFlowEdgeType,
    /// Optional condition expression (for conditional jumps).
    pub condition: Option<String>,
    /// Whether this edge is a back edge (target dominates source).
    pub is_back_edge: bool,
}

/// Classification of a control-flow edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControlFlowEdgeType {
    /// Sequential fall-through to the next instruction.
    FallThrough,
    /// Unconditional jump to a target block.
    Jump,
    /// Conditional branch: `true` means the branch is taken when the condition holds.
    ConditionalBranch(bool),
    /// A call instruction (target is the called function or call stub).
    Call,
    /// Return from a function.
    Return,
    /// Indirect jump (jump table, computed goto).
    IndirectJump,
    /// Unreachable / abnormal edge.
    Abnormal,
}

impl Default for ControlFlowEdgeType {
    fn default() -> Self {
        ControlFlowEdgeType::FallThrough
    }
}

/// A control-flow graph built on top of `petgraph::DiGraph`.
///
/// Represents the intra-procedural control flow of a function as a directed
/// graph of basic blocks. Provides methods for dominator computation, natural
/// loop detection, reducibility checking, and critical edge splitting.
///
/// # Examples
///
/// ```
/// use ghidra_core::graph::{ControlFlowGraph, ControlFlowEdgeType};
/// use ghidra_core::addr::Address;
///
/// let mut cfg = ControlFlowGraph::new();
/// let entry = cfg.add_block("entry");
/// let body = cfg.add_block("body");
/// let exit = cfg.add_block("exit");
/// cfg.set_entry(entry);
///
/// cfg.add_edge(entry, body, ControlFlowEdgeType::FallThrough);
/// cfg.add_edge(body, body, ControlFlowEdgeType::ConditionalBranch(true));
/// cfg.add_edge(body, exit, ControlFlowEdgeType::ConditionalBranch(false));
///
/// assert!(cfg.has_loops());
/// ```
#[derive(Debug, Clone, Default)]
pub struct ControlFlowGraph {
    /// The underlying directed graph.
    graph: DiGraph<BasicBlock, ControlFlowEdge>,
    /// The entry block index (set via [`set_entry`]).
    entry: Option<NodeIndex>,
    /// Maps user-facing block IDs to underlying node indices.
    id_to_index: HashMap<usize, NodeIndex>,
    /// Next block ID to assign.
    next_id: usize,
}

impl ControlFlowGraph {
    /// Create an empty control-flow graph.
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            entry: None,
            id_to_index: HashMap::new(),
            next_id: 0,
        }
    }

    // ------------------------------------------------------------------
    // Block management
    // ------------------------------------------------------------------

    /// Add a basic block with an optional label.
    ///
    /// Returns the [`BlockIndex`] that identifies this block for subsequent
    /// operations.
    pub fn add_block(&mut self, label: impl Into<String>) -> BlockIndex {
        let id = self.next_id;
        self.next_id += 1;

        let mut block = BasicBlock::new(id, label);
        // First block added is the entry by default
        if self.entry.is_none() {
            block.is_entry = true;
        }

        let ni = self.graph.add_node(block);
        if self.entry.is_none() {
            self.entry = Some(ni);
        }
        self.id_to_index.insert(id, ni);

        BlockIndex(ni)
    }

    /// Add a basic block with an address range.
    pub fn add_block_with_range(
        &mut self,
        label: impl Into<String>,
        start: Address,
        end: Address,
    ) -> BlockIndex {
        let id = self.next_id;
        self.next_id += 1;

        let mut block = BasicBlock::with_range(id, start, end);
        block.label = Some(label.into());
        if self.entry.is_none() {
            block.is_entry = true;
        }

        let ni = self.graph.add_node(block);
        if self.entry.is_none() {
            self.entry = Some(ni);
        }
        self.id_to_index.insert(id, ni);

        BlockIndex(ni)
    }

    /// Add an edge from `from_block` to `to_block` with the given edge type.
    pub fn add_edge(
        &mut self,
        from: BlockIndex,
        to: BlockIndex,
        edge_type: ControlFlowEdgeType,
    ) {
        self.graph.add_edge(
            from.0,
            to.0,
            ControlFlowEdge {
                edge_type,
                condition: None,
                is_back_edge: false,
            },
        );

        // Update is_exit flag on the source
        if let Some(src) = self.graph.node_weight_mut(from.0) {
            src.is_exit = false;
        }
    }

    /// Add an edge with a condition string (for conditional branches).
    pub fn add_conditional_edge(
        &mut self,
        from: BlockIndex,
        to: BlockIndex,
        condition: impl Into<String>,
        when_true: bool,
    ) {
        self.graph.add_edge(
            from.0,
            to.0,
            ControlFlowEdge {
                edge_type: ControlFlowEdgeType::ConditionalBranch(when_true),
                condition: Some(condition.into()),
                is_back_edge: false,
            },
        );

        if let Some(src) = self.graph.node_weight_mut(from.0) {
            src.is_exit = false;
        }
    }

    /// Mark `block` as the entry block of the CFG.
    pub fn set_entry(&mut self, block: BlockIndex) {
        self.entry = Some(block.0);
        // Clear is_entry on all blocks
        for node in self.graph.node_weights_mut() {
            node.is_entry = false;
        }
        // Set on the chosen block
        if let Some(entry) = self.graph.node_weight_mut(block.0) {
            entry.is_entry = true;
        }
    }

    /// Return the number of blocks in the CFG.
    pub fn block_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Return the number of edges in the CFG.
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Get a reference to a basic block.
    pub fn get_block(&self, block: BlockIndex) -> Option<&BasicBlock> {
        self.graph.node_weight(block.0)
    }

    /// Get a mutable reference to a basic block.
    pub fn get_block_mut(&mut self, block: BlockIndex) -> Option<&mut BasicBlock> {
        self.graph.node_weight_mut(block.0)
    }

    /// Find a block by its label.
    pub fn find_by_label(&self, label: &str) -> Option<BlockIndex> {
        self.graph
            .node_indices()
            .find(|&ni| {
                self.graph[ni]
                    .label
                    .as_ref()
                    .map(|l| l == label)
                    .unwrap_or(false)
            })
            .map(BlockIndex)
    }

    /// Returns all block indices in the graph.
    pub fn blocks(&self) -> Vec<BlockIndex> {
        self.graph.node_indices().map(BlockIndex).collect()
    }

    // ------------------------------------------------------------------
    // Entry / exit
    // ------------------------------------------------------------------

    /// Return the entry block index, if set.
    pub fn entry_block(&self) -> Option<BlockIndex> {
        self.entry.map(BlockIndex)
    }

    /// Return all exit blocks (blocks with no outgoing edges).
    pub fn exit_blocks(&self) -> Vec<BlockIndex> {
        self.graph
            .node_indices()
            .filter(|&ni| {
                self.graph.edges_directed(ni, Direction::Outgoing).count() == 0
            })
            .map(BlockIndex)
            .collect()
    }

    // ------------------------------------------------------------------
    // Successors / predecessors
    // ------------------------------------------------------------------

    /// Return the successors of a block (blocks reachable via outgoing edges).
    pub fn successors(&self, block: BlockIndex) -> Vec<BlockIndex> {
        self.graph
            .neighbors_directed(block.0, Direction::Outgoing)
            .map(BlockIndex)
            .collect()
    }

    /// Return the predecessors of a block (blocks that have edges to this block).
    pub fn predecessors(&self, block: BlockIndex) -> Vec<BlockIndex> {
        self.graph
            .neighbors_directed(block.0, Direction::Incoming)
            .map(BlockIndex)
            .collect()
    }

    /// Return successor edges with their edge types.
    pub fn successor_edges(&self, block: BlockIndex) -> Vec<(BlockIndex, &ControlFlowEdge)> {
        self.graph
            .edges_directed(block.0, Direction::Outgoing)
            .map(|e| (BlockIndex(e.target()), e.weight()))
            .collect()
    }

    /// Return all edges in the graph.
    pub fn edges(&self) -> Vec<(BlockIndex, BlockIndex, &ControlFlowEdge)> {
        self.graph
            .edge_references()
            .map(|e| (BlockIndex(e.source()), BlockIndex(e.target()), e.weight()))
            .collect()
    }

    // ------------------------------------------------------------------
    // Traversal
    // ------------------------------------------------------------------

    /// Return blocks in post-order (children before parents) starting from
    /// the entry block.
    pub fn post_order(&self) -> Vec<BlockIndex> {
        let entry = match self.entry {
            Some(e) => e,
            None => return Vec::new(),
        };
        let mut visited = vec![false; self.graph.node_count()];
        let mut order = Vec::new();

        fn dfs_post(
            node: NodeIndex,
            graph: &DiGraph<BasicBlock, ControlFlowEdge>,
            visited: &mut [bool],
            order: &mut Vec<BlockIndex>,
        ) {
            visited[node.index()] = true;
            for succ in graph.neighbors_directed(node, Direction::Outgoing) {
                if !visited[succ.index()] {
                    dfs_post(succ, graph, visited, order);
                }
            }
            order.push(BlockIndex(node));
        }

        dfs_post(entry, &self.graph, &mut visited, &mut order);
        order
    }

    /// Return blocks in reverse post-order (approximately topological order)
    /// starting from the entry block.
    pub fn reverse_post_order(&self) -> Vec<BlockIndex> {
        let mut order = self.post_order();
        order.reverse();
        order
    }

    /// Breadth-first search from the entry block.
    pub fn bfs_order(&self) -> Vec<BlockIndex> {
        let entry = match self.entry {
            Some(e) => e,
            None => return Vec::new(),
        };
        let mut visited = vec![false; self.graph.node_count()];
        let mut queue = VecDeque::new();
        let mut order = Vec::new();

        visited[entry.index()] = true;
        queue.push_back(entry);

        while let Some(node) = queue.pop_front() {
            order.push(BlockIndex(node));
            for succ in self.graph.neighbors_directed(node, Direction::Outgoing) {
                if !visited[succ.index()] {
                    visited[succ.index()] = true;
                    queue.push_back(succ);
                }
            }
        }
        order
    }

    // ------------------------------------------------------------------
    // Dominator tree
    // ------------------------------------------------------------------

    /// Compute the dominator tree for this CFG using the Lengauer-Tarjan
    /// algorithm.
    ///
    /// Returns `None` when the graph has no entry block.
    pub fn dominator_tree(&self) -> Option<DominatorTree> {
        let _entry = self.entry?;
        let node_count = self.graph.node_count();

        // Build a mapping: petgraph NodeIndex -> sequential usize
        let idx_map: HashMap<NodeIndex, usize> = self
            .graph
            .node_indices()
            .enumerate()
            .map(|(i, ni)| (ni, i))
            .collect();
        let rev_map: Vec<NodeIndex> = self
            .graph
            .node_indices()
            .collect();

        let successors_fn = |n: usize| -> Vec<usize> {
            let ni = rev_map[n];
            self.graph
                .neighbors_directed(ni, Direction::Outgoing)
                .filter_map(|s| idx_map.get(&s).copied())
                .collect()
        };

        Some(DominatorTree::build(node_count, successors_fn))
    }

    // ------------------------------------------------------------------
    // Loop detection
    // ------------------------------------------------------------------

    /// Detect all natural loops in this CFG.
    ///
    /// Uses back-edge detection via the dominator tree. Returns top-level
    /// loops (nested loops are stored in the `children` field).
    pub fn find_loops(&self) -> Vec<LoopInfo> {
        let node_count = self.graph.node_count();

        let idx_map: HashMap<NodeIndex, usize> = self
            .graph
            .node_indices()
            .enumerate()
            .map(|(i, ni)| (ni, i))
            .collect();
        let rev_map: Vec<NodeIndex> = self
            .graph
            .node_indices()
            .collect();

        let successors_fn = |n: usize| -> Vec<usize> {
            let ni = rev_map[n];
            self.graph
                .neighbors_directed(ni, Direction::Outgoing)
                .filter_map(|s| idx_map.get(&s).copied())
                .collect()
        };

        // Compute predecessors once -- used by the loop detection algorithm.
        let predecessors = Predecessors::build(node_count, &successors_fn);

        match self.dominator_tree() {
            Some(dt) => detect_natural_loops(node_count, &successors_fn, &predecessors, &dt),
            None => Vec::new(),
        }
    }

    /// Check whether this CFG contains any loops.
    pub fn has_loops(&self) -> bool {
        !self.find_loops().is_empty()
    }

    // ------------------------------------------------------------------
    // Reducibility
    // ------------------------------------------------------------------

    /// Returns `true` when this CFG is reducible.
    ///
    /// A CFG is reducible if all its back edges are to nodes that dominate
    /// their sources. This is a fundamental property for many compiler
    /// optimizations.
    pub fn is_reducible(&self) -> bool {
        let node_count = self.graph.node_count();

        let idx_map: HashMap<NodeIndex, usize> = self
            .graph
            .node_indices()
            .enumerate()
            .map(|(i, ni)| (ni, i))
            .collect();
        let rev_map: Vec<NodeIndex> = self
            .graph
            .node_indices()
            .collect();

        let successors_fn = |n: usize| -> Vec<usize> {
            let ni = rev_map[n];
            self.graph
                .neighbors_directed(ni, Direction::Outgoing)
                .filter_map(|s| idx_map.get(&s).copied())
                .collect()
        };

        let dt = match self.dominator_tree() {
            Some(dt) => dt,
            None => return true, // Empty graph is trivially reducible
        };

        // Check every edge: if target dominates source, it's a valid back edge.
        // If no other edge violates reducibility, the graph is reducible.
        // Reducibility condition: for every edge (u -> v), either:
        //   - v dominates u (back edge), OR
        //   - u strictly dominates v (forward edge in DAG)
        // Equivalently: the graph has no "irreducible" loops where two
        // entry points enter a cycle.

        for i in 0..node_count {
            for &s in &successors_fn(i) {
                // Edge i -> s
                // Back edge: s dominates i (always OK)
                if dt.dominates(s, i) {
                    continue;
                }
                // Forward/structural edge: OK
                // Irreducible: neither dominates the other,
                // check if there is a path s ->* i (cycle entry point ambiguity)
                let visited = GraphAlgorithms::bfs(s, node_count, &successors_fn);
                if visited.contains(&i) && !dt.dominates(i, s) && !dt.dominates(s, i) {
                    // This is an irreducible edge pattern: s can reach i,
                    // but neither dominates the other
                    return false;
                }
            }
        }
        true
    }

    // ------------------------------------------------------------------
    // Block merging
    // ------------------------------------------------------------------

    /// Merge two adjacent blocks connected by a single fall-through edge.
    ///
    /// Block `a` must have exactly one outgoing edge to block `b`, and block
    /// `b` must have exactly one incoming edge from block `a`. The contents of
    /// `b` are appended to `a`, and `b` is removed. All outgoing edges from
    /// `b` are rewired to originate from `a`.
    ///
    /// Returns the merged block index (which is `a`), or `Err` if the merge
    /// preconditions are not met.
    pub fn merge_blocks(
        &mut self,
        a: BlockIndex,
        b: BlockIndex,
    ) -> Result<BlockIndex, String> {
        // Precondition: a -> b must be the only outgoing edge from a
        let a_outgoing: Vec<NodeIndex> = self
            .graph
            .neighbors_directed(a.0, Direction::Outgoing)
            .collect();
        if a_outgoing.len() != 1 || a_outgoing[0] != b.0 {
            return Err("Block a must have exactly one outgoing edge to block b".into());
        }

        // Precondition: b must have exactly one incoming edge from a
        let b_incoming: Vec<NodeIndex> = self
            .graph
            .neighbors_directed(b.0, Direction::Incoming)
            .collect();
        if b_incoming.len() != 1 || b_incoming[0] != a.0 {
            return Err("Block b must have exactly one incoming edge from block a".into());
        }

        // Collect b's outgoing edges
        let b_outgoing: Vec<(NodeIndex, ControlFlowEdgeType, Option<String>)> = self
            .graph
            .edges_directed(b.0, Direction::Outgoing)
            .map(|e| {
                (e.target(), e.weight().edge_type, e.weight().condition.clone())
            })
            .collect();

        // Collect b's instructions and address info
        let b_block_data = {
            let b_block = &self.graph[b.0];
            (b_block.instructions.clone(), b_block.end_address)
        };

        // Remove the edge a -> b
        if let Some(edge) = self.graph.find_edge(a.0, b.0) {
            self.graph.remove_edge(edge);
        }

        // Add b's outgoing edges to a
        for (target, edge_type, condition) in b_outgoing {
            if condition.is_some() {
                self.graph.add_edge(
                    a.0,
                    target,
                    ControlFlowEdge {
                        edge_type,
                        condition,
                        is_back_edge: false,
                    },
                );
            } else {
                self.graph.add_edge(
                    a.0,
                    target,
                    ControlFlowEdge {
                        edge_type,
                        condition: None,
                        is_back_edge: false,
                    },
                );
            }
        }

        // Update block a's data
        if let Some(a_block) = self.graph.node_weight_mut(a.0) {
            a_block.instructions.extend(b_block_data.0);
            a_block.end_address = b_block_data.1;
        }

        // Remove block b
        // Find and remove b's node
        let b_id = self.graph[b.0].id;
        self.graph.remove_node(b.0);
        self.id_to_index.remove(&b_id);

        Ok(a)
    }

    // ------------------------------------------------------------------
    // Critical edge splitting
    // ------------------------------------------------------------------

    /// Split all critical edges in the CFG.
    ///
    /// A critical edge is an edge from a block with multiple successors to
    /// a block with multiple predecessors. Splitting is necessary for many
    /// compiler optimizations (e.g., SSA construction).
    ///
    /// Each critical edge is split by inserting a new empty basic block
    /// between the source and target.
    ///
    /// Returns the number of critical edges that were split.
    pub fn split_critical_edges(&mut self) -> usize {
        let mut edges_to_split = Vec::new();

        // Find critical edges first (to avoid borrow issues)
        for edge_ref in self.graph.edge_references() {
            let source = edge_ref.source();
            let target = edge_ref.target();

            let source_outdegree = self
                .graph
                .edges_directed(source, Direction::Outgoing)
                .count();
            let target_indegree = self
                .graph
                .edges_directed(target, Direction::Incoming)
                .count();

            if source_outdegree > 1 && target_indegree > 1 {
                edges_to_split.push((source, target));
            }
        }

        let count = edges_to_split.len();

        for (source, target) in edges_to_split {
            // Remove the original edge
            if let Some(edge_idx) = self.graph.find_edge(source, target) {
                let edge_weight = self.graph[edge_idx].clone();
                self.graph.remove_edge(edge_idx);

                // Create a new intermediate block
                let id = self.next_id;
                self.next_id += 1;
                let mut new_block = BasicBlock::new(id, format!("crit_edge_{}", id));
                new_block.start_address = None;
                new_block.end_address = None;
                let ni = self.graph.add_node(new_block);
                self.id_to_index.insert(id, ni);

                // Add edge source -> new_block
                self.graph.add_edge(
                    source,
                    ni,
                    ControlFlowEdge {
                        edge_type: edge_weight.edge_type,
                        condition: edge_weight.condition.clone(),
                        is_back_edge: false,
                    },
                );

                // Add edge new_block -> target (always fall-through)
                self.graph.add_edge(
                    ni,
                    target,
                    ControlFlowEdge {
                        edge_type: ControlFlowEdgeType::FallThrough,
                        condition: None,
                        is_back_edge: false,
                    },
                );
            }
        }

        count
    }

    // ------------------------------------------------------------------
    // Utility
    // ------------------------------------------------------------------

    /// Return an iterator over all block indices with their basic block data.
    pub fn iter_blocks(&self) -> impl Iterator<Item = (BlockIndex, &BasicBlock)> {
        self.graph
            .node_indices()
            .map(|ni| (BlockIndex(ni), &self.graph[ni]))
    }

    /// Clear all blocks and edges, resetting to an empty graph.
    pub fn clear(&mut self) {
        self.graph.clear();
        self.entry = None;
        self.id_to_index.clear();
        self.next_id = 0;
    }
}

// ============================================================================
// CallGraph
// ============================================================================

/// A call graph represents caller-callee relationships between functions.
///
/// Each node represents a function, and each directed edge represents
/// a call from one function to another.
#[derive(Debug, Clone, Default)]
pub struct CallGraph {
    /// Underlying directed graph. Node weights are [`CallGraphNode`] values.
    pub graph: DiGraph<CallGraphNode, CallEdge>,
    /// Maps addresses to node indices for fast lookup.
    index: HashMap<Address, NodeIndex>,
}

/// Represents a function node in the call graph.
#[derive(Debug, Clone)]
pub struct CallGraphNode {
    /// The entry address of the function.
    pub address: Address,
    /// The function name.
    pub name: String,
    /// Whether this function is external (imported / not defined in the binary).
    pub is_external: bool,
    /// Whether this function is a library/thunk.
    pub is_thunk: bool,
}

/// Edge data in the call graph, describing the type of call.
#[derive(Debug, Clone)]
pub struct CallEdge {
    /// The type of call.
    pub call_type: CallType,
    /// The address of the call instruction (if known).
    pub call_site: Option<Address>,
}

/// Classification of a call edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallType {
    /// A direct call with a known target address.
    Direct,
    /// An indirect call (register or memory operand).
    Indirect,
    /// A conditional call (rare).
    Conditional,
    /// An unconditional jump that acts as a tail call.
    Unconditional,
    /// A computed call determined at runtime.
    Computed,
}

impl Default for CallType {
    fn default() -> Self {
        CallType::Direct
    }
}

/// Represents a function with its associated metadata for graph building.
///
/// Used as input when constructing a [`CallGraph`].
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    /// The entry address of the function.
    pub entry: Address,
    /// The function name.
    pub name: String,
    /// Whether this function is external.
    pub is_external: bool,
    /// Whether this function is a thunk.
    pub is_thunk: bool,
    /// List of call targets from this function.
    pub callees: Vec<(Address, CallType, Option<Address>)>,
}

impl CallGraph {
    /// Create an empty call graph.
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            index: HashMap::new(),
        }
    }

    /// Build a call graph from a list of function descriptors.
    ///
    /// Each function in `functions` is added as a node, and edges are added
    /// for each callee relationship. If a callee address does not match any
    /// known function, a placeholder external node is created.
    pub fn build_from_functions(&mut self, functions: &[FunctionInfo]) {
        // Clear existing data
        self.graph = DiGraph::new();
        self.index.clear();

        // First pass: add all known functions as nodes
        for func in functions {
            let idx = self.graph.add_node(CallGraphNode {
                address: func.entry,
                name: func.name.clone(),
                is_external: func.is_external,
                is_thunk: func.is_thunk,
            });
            self.index.insert(func.entry, idx);
        }

        // Second pass: add edges
        for func in functions {
            let caller_idx = self.index[&func.entry];
            for (callee_addr, call_type, call_site) in &func.callees {
                let callee_idx = if let Some(&idx) = self.index.get(callee_addr) {
                    idx
                } else {
                    // Create an external placeholder node
                    let idx = self.graph.add_node(CallGraphNode {
                        address: *callee_addr,
                        name: format!("sub_{}", callee_addr),
                        is_external: true,
                        is_thunk: false,
                    });
                    self.index.insert(*callee_addr, idx);
                    idx
                };
                self.graph.add_edge(
                    caller_idx,
                    callee_idx,
                    CallEdge {
                        call_type: *call_type,
                        call_site: *call_site,
                    },
                );
            }
        }
    }

    /// Add a single function node to the call graph.
    ///
    /// Returns the [`NodeIndex`] of the new node.
    pub fn add_function(
        &mut self,
        address: Address,
        name: impl Into<String>,
        is_external: bool,
        is_thunk: bool,
    ) -> NodeIndex {
        if let Some(&existing) = self.index.get(&address) {
            return existing;
        }
        let idx = self.graph.add_node(CallGraphNode {
            address,
            name: name.into(),
            is_external,
            is_thunk,
        });
        self.index.insert(address, idx);
        idx
    }

    /// Add a call edge between two functions.
    ///
    /// If either function does not exist, they are created as placeholder nodes.
    pub fn add_call_edge(
        &mut self,
        caller: Address,
        callee: Address,
        call_type: CallType,
        call_site: Option<Address>,
    ) {
        let caller_idx = *self
            .index
            .entry(caller)
            .or_insert_with(|| {
                self.graph.add_node(CallGraphNode {
                    address: caller,
                    name: format!("sub_{}", caller),
                    is_external: false,
                    is_thunk: false,
                })
            });

        let callee_idx = *self
            .index
            .entry(callee)
            .or_insert_with(|| {
                self.graph.add_node(CallGraphNode {
                    address: callee,
                    name: format!("sub_{}", callee),
                    is_external: false,
                    is_thunk: false,
                })
            });

        self.graph.add_edge(
            caller_idx,
            callee_idx,
            CallEdge {
                call_type,
                call_site,
            },
        );
    }

    /// Returns the number of function nodes in the graph.
    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Returns the number of call edges in the graph.
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Get a reference to a node by its address.
    pub fn node_by_address(&self, addr: Address) -> Option<&CallGraphNode> {
        self.index.get(&addr).map(|&idx| &self.graph[idx])
    }

    /// Get the index of a node by its address.
    pub fn node_index(&self, addr: Address) -> Option<NodeIndex> {
        self.index.get(&addr).copied()
    }

    /// Returns the callers of the function at `addr` (callees_of in Ghidra
    /// terminology: who calls this function?).
    pub fn callers_of(&self, addr: Address) -> Vec<&CallGraphNode> {
        if let Some(&idx) = self.index.get(&addr) {
            self.graph
                .neighbors_directed(idx, Direction::Incoming)
                .map(|ni| &self.graph[ni])
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Alias for callers_of (Ghidra naming).
    pub fn callers(&self, addr: Address) -> Vec<&CallGraphNode> {
        self.callers_of(addr)
    }

    /// Returns the callees of the function at `addr` (who does this function
    /// call?).
    pub fn callees_of(&self, addr: Address) -> Vec<(&CallGraphNode, &CallEdge)> {
        if let Some(&idx) = self.index.get(&addr) {
            self.graph
                .edges_directed(idx, Direction::Outgoing)
                .map(|e| (&self.graph[e.target()], e.weight()))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Alias for callees_of (Ghidra naming).
    pub fn callees(&self, addr: Address) -> Vec<(&CallGraphNode, &CallEdge)> {
        self.callees_of(addr)
    }

    /// Returns a topological ordering of the call graph nodes (callees before
    /// callers, i.e., leaves first).
    pub fn topological_order(&self) -> Vec<Address> {
        let mut order = Vec::new();
        if let Ok(sorted) = petalgo::toposort(&self.graph, None) {
            for idx in sorted {
                order.push(self.graph[idx].address);
            }
        }
        order
    }

    /// Returns strongly-connected components (mutually recursive function groups).
    pub fn strongly_connected_components(&self) -> Vec<Vec<Address>> {
        petalgo::kosaraju_scc(&self.graph)
            .into_iter()
            .map(|scc| scc.iter().map(|&idx| self.graph[idx].address).collect())
            .collect()
    }

    /// Find all functions reachable from the given entry point address.
    pub fn reachable_from(&self, addr: Address) -> HashSet<Address> {
        let mut reachable = HashSet::new();
        if let Some(&start) = self.index.get(&addr) {
            let mut dfs = Dfs::new(&self.graph, start);
            while let Some(nx) = dfs.next(&self.graph) {
                reachable.insert(self.graph[nx].address);
            }
        }
        reachable
    }

    /// Returns the root nodes (functions that are not called by any other
    /// function in the graph, i.e., entry points or unreferenced functions).
    pub fn root_nodes(&self) -> Vec<Address> {
        self.graph
            .externals(Direction::Incoming)
            .map(|idx| self.graph[idx].address)
            .collect()
    }

    /// Returns the leaf nodes (functions that do not call any other function).
    pub fn leaf_functions(&self) -> Vec<&CallGraphNode> {
        self.graph
            .externals(Direction::Outgoing)
            .map(|idx| &self.graph[idx])
            .collect()
    }

    /// Alias for leaf_functions (Ghidra naming).
    pub fn leaf_nodes(&self) -> Vec<Address> {
        self.leaf_functions()
            .iter()
            .map(|n| n.address)
            .collect()
    }

    /// Check whether the call graph contains recursion (a cycle involving
    /// the function at `addr`).
    ///
    /// Returns `true` if the function is part of a strongly connected
    /// component with more than one node.
    pub fn has_recursion(&self, addr: Address) -> bool {
        let sccs = petalgo::tarjan_scc(&self.graph);
        for scc in &sccs {
            if scc.len() > 1 {
                let addrs: HashSet<Address> = scc
                    .iter()
                    .map(|&ni| self.graph[ni].address)
                    .collect();
                if addrs.contains(&addr) {
                    return true;
                }
            }
        }
        false
    }

    /// Returns the maximum call depth from the given root.
    ///
    /// Uses BFS; returns `None` if the graph has cycles.
    pub fn max_call_depth(&self, root: Address) -> Option<usize> {
        let start = self.index.get(&root)?;
        let mut depth: HashMap<NodeIndex, usize> = HashMap::new();
        let mut queue = VecDeque::new();
        depth.insert(*start, 0);
        queue.push_back(*start);

        let mut max_depth = 0usize;

        while let Some(current) = queue.pop_front() {
            let current_depth = depth[&current];
            max_depth = max_depth.max(current_depth);

            for edge in self.graph.edges_directed(current, Direction::Outgoing) {
                let target = edge.target();
                let new_depth = current_depth + 1;

                if let Some(&existing) = depth.get(&target) {
                    // Cycle or alternative path
                    if new_depth > existing {
                        depth.insert(target, new_depth);
                        queue.push_back(target);
                    }
                } else {
                    depth.insert(target, new_depth);
                    queue.push_back(target);
                }
            }
        }

        Some(max_depth)
    }

    /// Returns all addresses of nodes in the graph.
    pub fn all_addresses(&self) -> Vec<Address> {
        self.graph
            .node_indices()
            .map(|ni| self.graph[ni].address)
            .collect()
    }

    /// Returns an iterator over all call edges.
    pub fn edges(&self) -> Vec<(Address, Address, &CallType)> {
        self.graph
            .edge_references()
            .map(|e| {
                (
                    self.graph[e.source()].address,
                    self.graph[e.target()].address,
                    &e.weight().call_type,
                )
            })
            .collect()
    }

    /// Returns the number of indirect calls in the graph.
    pub fn indirect_call_count(&self) -> usize {
        self.graph
            .edge_references()
            .filter(|e| e.weight().call_type == CallType::Indirect)
            .count()
    }
}

// ============================================================================
// DominatorTree
// ============================================================================

/// A dominator tree for a control-flow graph.
///
/// Node `A` dominates node `B` if every path from the entry node to `B`
/// must pass through `A`. The dominator tree encodes the immediate dominator
/// relationship.
#[derive(Debug, Clone)]
pub struct DominatorTree {
    /// Number of nodes in the CFG.
    node_count: usize,
    /// `idom[i]` is the immediate dominator of node `i`, or `None` for the
    /// entry node. Stored as an `Option<usize>` where `usize` is the CFG
    /// node index (0-based).
    idom: Vec<Option<usize>>,
    /// `dominators[i]` contains the set of all nodes that dominate `i`.
    dominators: Vec<HashSet<usize>>,
    /// `dominated[i]` contains the set of all nodes dominated by `i`
    /// (the dominator tree children).
    dominated: Vec<Vec<usize>>,
    /// The entry node index.
    entry: usize,
    /// Reverse postorder numbering (used by the algorithm).
    #[allow(dead_code)]
    rpo: Vec<usize>,
}

impl DominatorTree {
    /// Build a dominator tree from a control-flow graph.
    ///
    /// `successors(i)` returns the outgoing edge targets for each node `0..n`.
    /// The entry node is `0`.
    ///
    /// Uses the Lengauer-Tarjan algorithm for near-linear construction.
    /// Predecessors are computed once (O(V+E)) and reused across all RPO nodes,
    /// eliminating the prior O(V*(V+E)) inner-loop predecessor scan.
    pub fn build(
        node_count: usize,
        successors: impl Fn(usize) -> Vec<usize>,
    ) -> Self {
        if node_count == 0 {
            return Self {
                node_count: 0,
                idom: Vec::new(),
                dominators: Vec::new(),
                dominated: Vec::new(),
                entry: 0,
                rpo: Vec::new(),
            };
        }

        // Compute predecessors ONCE (fixes O(n^2) bug).
        let predecessors = Predecessors::build(node_count, &successors);

        // Build DFS preorder numbering and DFS parent tree.
        let (preorder, dfs_parent) = compute_dfs_preorder(node_count, &successors);

        // Map node -> preorder position
        let mut preorder_pos = vec![0usize; node_count];
        for (i, &node) in preorder.iter().enumerate() {
            preorder_pos[node] = i;
        }

        // --- Lengauer-Tarjan algorithm ---
        let mut idom = vec![None; node_count];
        let mut semi = vec![0usize; node_count];
        let mut label = vec![0usize; node_count];
        let mut ancestor: Vec<Option<usize>> = vec![None; node_count];
        let mut bucket: Vec<Vec<usize>> = vec![Vec::new(); node_count];

        for i in 0..node_count {
            semi[i] = i;
            label[i] = i;
        }

        // Process nodes in reverse preorder (skip entry at preorder[0]).
        for &w in preorder.iter().skip(1).rev() {
            let w_pos = preorder_pos[w];

            // Step 2: compute semi-dominator using precomputed predecessors.
            for &v in predecessors.get(w) {
                let u = eval(v, &mut ancestor, &semi, &mut label, &preorder_pos);
                if preorder_pos[semi[u]] < preorder_pos[semi[w]] {
                    semi[w] = semi[u];
                }
            }
            bucket[semi[w]].push(w);

            // Link w to its DFS-tree parent.
            let parent_w = preorder[dfs_parent[w_pos]];
            link(parent_w, w, &mut ancestor);

            // Step 3: implicitly define idom for nodes in bucket[parent_w].
            for &v in bucket[parent_w].clone().iter() {
                let u = eval(v, &mut ancestor, &semi, &mut label, &preorder_pos);
                if semi[u] == semi[v] {
                    idom[v] = Some(semi[v]);
                } else {
                    idom[v] = Some(u);
                }
            }
            bucket[parent_w].clear();
        }

        // Step 4: explicitly define idom.
        for &w in preorder.iter().skip(1) {
            if let Some(id) = idom[w] {
                if id != semi[w] {
                    idom[w] = idom[id];
                }
            }
        }
        idom[0] = None; // Entry node has no idom.

        // Compute full dominator sets (transitive closure along idom chain).
        let mut dominators: Vec<HashSet<usize>> = vec![HashSet::new(); node_count];
        dominators[0].insert(0);
        for &w in preorder.iter().skip(1) {
            if let Some(id) = idom[w] {
                let mut doms = dominators[id].clone();
                doms.insert(w);
                dominators[w] = doms;
            }
        }

        // Compute children in the dominator tree.
        let mut dominated: Vec<Vec<usize>> = vec![Vec::new(); node_count];
        for i in 0..node_count {
            if let Some(id) = idom[i] {
                dominated[id].push(i);
            }
        }

        Self {
            node_count,
            idom,
            dominators,
            dominated,
            entry: 0,
            rpo: preorder,
        }
    }

    /// Returns the immediate dominator of `node`, or `None` if `node` is
    /// the entry.
    pub fn immediate_dominator(&self, node: usize) -> Option<usize> {
        self.idom.get(node).copied().flatten()
    }

    /// Returns all nodes that dominate `node` (including `node` itself).
    pub fn dominators(&self, node: usize) -> &HashSet<usize> {
        &self.dominators[node]
    }

    /// Returns all nodes that are strictly dominated by `node`.
    pub fn strictly_dominated(&self, node: usize) -> &[usize] {
        &self.dominated[node]
    }

    /// Returns `true` when `a` dominates `b`.
    pub fn dominates(&self, a: usize, b: usize) -> bool {
        self.dominators[b].contains(&a)
    }

    /// Returns `true` when `a` strictly dominates `b` (a != b and a dominates b).
    pub fn strictly_dominates(&self, a: usize, b: usize) -> bool {
        a != b && self.dominates(a, b)
    }

    /// Returns the number of nodes.
    pub fn node_count(&self) -> usize {
        self.node_count
    }

    /// Returns the entry node index.
    pub fn entry(&self) -> usize {
        self.entry
    }

    /// Returns the dominance frontier of each node.
    ///
    /// The dominance frontier of node `X` is the set of nodes `Y` such that
    /// `X` dominates a predecessor of `Y` but does not strictly dominate `Y`.
    pub fn dominance_frontiers(
        &self,
        predecessors: &Predecessors,
    ) -> Vec<HashSet<usize>> {
        let mut frontiers = vec![HashSet::new(); self.node_count];
        for b in 0..self.node_count {
            if predecessors.get(b).len() >= 2 {
                for &p in predecessors.get(b) {
                    let mut runner = Some(p);
                    while let Some(r) = runner {
                        if r == b {
                            break;
                        }
                        frontiers[r].insert(b);
                        runner = self.idom[r];
                    }
                }
            }
        }
        frontiers
    }
}

/// Precomputed predecessor lists for each node.
///
/// `predecessors[i]` contains all nodes that have an edge to node `i`.
/// Used by Lengauer-Tarjan, dominance frontiers, and loop detection.
#[derive(Debug, Clone)]
pub struct Predecessors {
    /// predecessors[i] = list of nodes with edges to node i.
    preds: Vec<Vec<usize>>,
}

impl Predecessors {
    /// Build predecessor lists from a successor function.
    pub fn build(node_count: usize, successors: impl Fn(usize) -> Vec<usize>) -> Self {
        let mut preds: Vec<Vec<usize>> = vec![Vec::new(); node_count];
        for i in 0..node_count {
            for s in successors(i) {
                if s < node_count {
                    preds[s].push(i);
                }
            }
        }
        Self { preds }
    }

    /// Get the predecessors of a node.
    pub fn get(&self, node: usize) -> &[usize] {
        &self.preds[node]
    }

    /// Number of nodes.
    pub fn node_count(&self) -> usize {
        self.preds.len()
    }
}

impl ControlFlowGraph {
    /// Compute predecessor lists for all nodes in this CFG.
    pub fn cfg_predecessors(&self) -> Predecessors {
        let node_count = self.graph.node_count();
        let idx_map: HashMap<NodeIndex, usize> = self
            .graph
            .node_indices()
            .enumerate()
            .map(|(i, ni)| (ni, i))
            .collect();
        let rev_map: Vec<NodeIndex> = self.graph.node_indices().collect();

        Predecessors::build(node_count, |n: usize| -> Vec<usize> {
            let ni = rev_map[n];
            self.graph
                .neighbors_directed(ni, Direction::Outgoing)
                .filter_map(|s| idx_map.get(&s).copied())
                .collect()
        })
    }
}

/// Helper: compute DFS preorder numbering and DFS parent via DFS.
/// Returns `(preorder, dfs_parent)` where `dfs_parent[i]` is the preorder
/// index of the DFS-tree parent of the node at preorder position `i`
/// (or `0` for the root).
fn compute_dfs_preorder(
    node_count: usize,
    successors: impl Fn(usize) -> Vec<usize>,
) -> (Vec<usize>, Vec<usize>) {
    let mut visited = vec![false; node_count];
    let mut order = Vec::with_capacity(node_count);
    // Indexed by node id: parent_node_id.
    let mut parent_by_node = vec![0usize; node_count];

    fn dfs(
        node: usize,
        visited: &mut [bool],
        order: &mut Vec<usize>,
        parent_by_node: &mut [usize],
        successors: &dyn Fn(usize) -> Vec<usize>,
    ) {
        visited[node] = true;
        order.push(node); // preorder: push on entry
        for &succ in &successors(node) {
            if succ < visited.len() && !visited[succ] {
                parent_by_node[succ] = node;
                dfs(succ, visited, order, parent_by_node, successors);
            }
        }
    }

    dfs(0, &mut visited, &mut order, &mut parent_by_node, &successors);

    // Map node id -> preorder position.
    let pos: HashMap<usize, usize> =
        order.iter().enumerate().map(|(i, &n)| (n, i)).collect();
    // Remap so dfs_parent[preorder_index] = preorder_index of DFS parent.
    let dfs_parent: Vec<usize> = order
        .iter()
        .map(|&n| *pos.get(&parent_by_node[n]).unwrap_or(&0))
        .collect();

    (order, dfs_parent)
}

/// Helper: Lengauer-Tarjan `eval` function.
fn eval(
    v: usize,
    ancestor: &mut [Option<usize>],
    semi: &[usize],
    label: &mut [usize],
    preorder_pos: &[usize],
) -> usize {
    if ancestor[v].is_none() {
        return label[v];
    }
    compress(v, ancestor, semi, label, preorder_pos);
    label[v]
}

/// Helper: Lengauer-Tarjan `compress` function.
fn compress(
    v: usize,
    ancestor: &mut [Option<usize>],
    semi: &[usize],
    label: &mut [usize],
    preorder_pos: &[usize],
) {
    if let Some(a) = ancestor[v] {
        if ancestor[a].is_some() {
            compress(a, ancestor, semi, label, preorder_pos);
            if preorder_pos[semi[label[a]]] < preorder_pos[semi[label[v]]] {
                label[v] = label[a];
            }
            ancestor[v] = ancestor[a]; // path compression
        }
    }
}

/// Helper: Lengauer-Tarjan `link` function.
fn link(v: usize, w: usize, ancestor: &mut [Option<usize>]) {
    ancestor[w] = Some(v);
}

// ============================================================================
// PostDominatorTree
// ============================================================================

/// A post-dominator tree for a control-flow graph.
///
/// Node `A` post-dominates node `B` if every path from `B` to the exit node
/// must pass through `A`. This is built by reversing the CFG and computing
/// dominators from the exit.
#[derive(Debug, Clone)]
pub struct PostDominatorTree {
    inner: DominatorTree,
}

impl PostDominatorTree {
    /// Build a post-dominator tree from a CFG.
    ///
    /// `node_count` is the number of nodes. `successors(i)` returns outgoing
    /// edges. `exit_node` is the index of the unique exit node.
    ///
    /// Handles multiple exit nodes by adding a virtual entry node (index 0 in
    /// the internal reversed graph) that reaches all actual exit nodes.
    /// Original nodes are mapped to indices 1..=n in the reversed graph.
    pub fn build(
        node_count: usize,
        successors: impl Fn(usize) -> Vec<usize>,
        exit_node: usize,
    ) -> Self {
        // Build predecessor lists from the original forward graph.
        let preds: Vec<Vec<usize>> = {
            let mut p: Vec<Vec<usize>> = vec![Vec::new(); node_count];
            for i in 0..node_count {
                for s in successors(i) {
                    if s < node_count {
                        p[s].push(i);
                    }
                }
            }
            p
        };

        // Identify actual exit nodes: have no outgoing edges or only connect to
        // the given exit_node.
        let actual_exits: Vec<usize> = (0..node_count)
            .filter(|&i| {
                let succs = successors(i);
                succs.is_empty() || (succs.len() == 1 && succs[0] == exit_node)
            })
            .collect();

        // Reversed graph with a virtual entry node (index 0).
        // - Virtual entry (0) -> each actual exit (i+1) -- so actual exits are
        //   reachable from the root in the reversed graph.
        // - Original node i (mapped to i+1) -> its original predecessors
        //   (mapped to p+1) -- the reversed edge direction.
        let n = node_count;
        let rev_successors = |node: usize| -> Vec<usize> {
            match node {
                0 => actual_exits.iter().map(|&e| e + 1).collect(),
                i if i >= 1 && i <= n => preds[i - 1].iter().map(|&p| p + 1).collect(),
                _ => Vec::new(),
            }
        };

        // Dominator tree on the extended graph (0..=n).
        let inner = DominatorTree::build(n + 1, rev_successors);

        Self { inner }
    }

    /// Returns the immediate post-dominator of `node`, or `None` if `node`
    /// is an exit (has no actual post-dominator).
    pub fn immediate_post_dominator(&self, node: usize) -> Option<usize> {
        // In the extended dominator tree, the virtual entry is index 0.
        // Actual nodes are stored at index `node+1` in the extended tree.
        let extended_idx = node + 1;
        match self.inner.immediate_dominator(extended_idx) {
            Some(0) => None, // idom is the virtual entry -- no real post-dominator
            Some(id) => Some(id - 1), // map back to original node index
            None => None,
        }
    }

    /// Returns all nodes that post-dominate `node`.
    ///
    /// Both arguments and results use original node indices.
    pub fn post_dominators(&self, node: usize) -> HashSet<usize> {
        let extended_idx = node + 1;
        self.inner
            .dominators(extended_idx)
            .iter()
            .filter_map(|&d| if d == 0 { None } else { Some(d - 1) })
            .collect()
    }

    /// Returns `true` when `a` post-dominates `b`.
    pub fn post_dominates(&self, a: usize, b: usize) -> bool {
        self.inner.dominates(a + 1, b + 1)
    }

    /// Returns `true` when `a` strictly post-dominates `b`.
    pub fn strictly_post_dominates(&self, a: usize, b: usize) -> bool {
        self.inner.strictly_dominates(a + 1, b + 1)
    }

    /// Returns the number of nodes in the original graph.
    pub fn node_count(&self) -> usize {
        // Extended tree has n+1 nodes; original has n.
        self.inner.node_count().saturating_sub(1)
    }
}

// ============================================================================
// LoopInfo -- natural loop detection
// ============================================================================

/// Information about a natural loop in a control-flow graph.
///
/// A natural loop has a single header node that dominates all nodes in the
/// loop, and at least one back edge pointing to the header.
#[derive(Debug, Clone)]
pub struct LoopInfo {
    /// The loop header (the entry point of the loop).
    pub header: usize,
    /// All nodes that belong to this loop (including the header).
    pub nodes: HashSet<usize>,
    /// The back edges that define this loop (target -> source pairs,
    /// where source jumps back to the header).
    pub back_edges: Vec<(usize, usize)>,
    /// Nested loops contained within this loop.
    pub children: Vec<LoopInfo>,
    /// The parent loop, if this loop is nested inside another.
    pub parent: Option<Box<LoopInfo>>,
    /// Whether this is an irreducible loop (no single header dominates
    /// all nodes). If `true`, the loop was created by the algorithm
    /// for completeness but may not represent a well-structured loop.
    pub is_irreducible: bool,
}

impl LoopInfo {
    /// Create a new loop with the given header.
    pub fn new(header: usize) -> Self {
        Self {
            header,
            nodes: {
                let mut set = HashSet::new();
                set.insert(header);
                set
            },
            back_edges: Vec::new(),
            children: Vec::new(),
            parent: None,
            is_irreducible: false,
        }
    }

    /// Returns `true` when `node` is in this loop.
    pub fn contains(&self, node: usize) -> bool {
        self.nodes.contains(&node)
    }

    /// Returns the depth of the loop nest (0 = outermost, 1 = nested once, etc.).
    pub fn nest_depth(&self) -> usize {
        self.parent.as_ref().map(|p| p.nest_depth() + 1).unwrap_or(0)
    }

    /// Returns all nodes in the loop in depth-first order (header first).
    pub fn ordered_nodes(&self) -> Vec<usize> {
        let mut result = vec![self.header];
        let mut rest: Vec<usize> = self
            .nodes
            .iter()
            .copied()
            .filter(|&n| n != self.header)
            .collect();
        rest.sort();
        result.extend(rest);
        result
    }

    /// Returns the total number of nodes across all nested loops.
    pub fn total_nodes(&self) -> usize {
        self.nodes.len()
            + self
                .children
                .iter()
                .map(|c| c.total_nodes())
                .sum::<usize>()
    }
}

/// Detect all natural loops in a control-flow graph.
///
/// Uses the algorithm from "Compilers: Principles, Techniques, and Tools"
/// (Aho, Lam, Sethi, Ullman). Requires a dominator tree and precomputed
/// predecessor lists (avoids recomputing predecessors for every back edge).
///
/// Returns a list of top-level loops (not nested within any other loop).
/// Each loop's `children` field contains its nested loops.
pub fn detect_natural_loops(
    node_count: usize,
    successors: impl Fn(usize) -> Vec<usize>,
    predecessors: &Predecessors,
    dominator_tree: &DominatorTree,
) -> Vec<LoopInfo> {
    // Step 1: find back edges
    let mut back_edges = Vec::new();
    for i in 0..node_count {
        for &succ in &successors(i) {
            if dominator_tree.dominates(succ, i) {
                back_edges.push((succ, i)); // (header, source)
            }
        }
    }

    // Step 2: for each back edge, construct the natural loop
    let mut loops: Vec<LoopInfo> = Vec::new();

    for &(header, source) in &back_edges {
        let mut loop_nodes = HashSet::new();
        loop_nodes.insert(header);
        loop_nodes.insert(source);

        // Add all predecessors of source until we reach the header
        let mut stack = vec![source];

        while let Some(node) = stack.pop() {
            for &pred in predecessors.get(node) {
                if !loop_nodes.contains(&pred) {
                    loop_nodes.insert(pred);
                    stack.push(pred);
                }
            }
        }

        // Check if this loop shares a header with an existing loop
        if let Some(existing) = loops.iter_mut().find(|l| l.header == header) {
            existing.nodes.extend(loop_nodes);
            existing.back_edges.push((header, source));
        } else {
            loops.push(LoopInfo {
                header,
                nodes: loop_nodes,
                back_edges: vec![(header, source)],
                children: Vec::new(),
                parent: None,
                is_irreducible: false,
            });
        }
    }

    // Step 3: determine nesting relationships.
    // A loop A is nested inside loop B if A's header differs from B's and
    // all of A's nodes are contained in B's node set.  We find the direct
    // (innermost) parent for each loop.
    let mut sorted_loops = loops.clone();
    sorted_loops.sort_by_key(|l| l.nodes.len()); // smallest first

    // Place each loop inside its direct parent.  Process from largest to
    // smallest so that when a small loop is placed, its parent (larger) is
    // already in the tree and searchable.
    fn place_loop(parents: &mut Vec<LoopInfo>, child: LoopInfo) {
        for p in parents.iter_mut() {
            if p.nodes.is_superset(&child.nodes) {
                place_loop(&mut p.children, child);
                return;
            }
        }
        parents.push(child);
    }

    let mut top_level: Vec<LoopInfo> = Vec::new();
    for loop_info in sorted_loops.into_iter().rev() {
        // Only place loops that are nested inside some other loop; top-level
        // loops have no enclosing loop (other than themselves).
        let has_parent = loops
            .iter()
            .any(|other| {
                other.header != loop_info.header
                    && loop_info.nodes.is_subset(&other.nodes)
            });
        if has_parent {
            place_loop(&mut top_level, loop_info);
        } else {
            top_level.push(loop_info);
        }
    }

    // Set parent pointers on each child so nest_depth() works correctly.
    fn set_parent_pointers(loops: &mut [LoopInfo]) {
        for i in 0..loops.len() {
            // Collect children, set parent, then write them back.
            let mut children: Vec<LoopInfo> =
                std::mem::take(&mut loops[i].children);
            for child in children.iter_mut() {
                child.parent = Some(Box::new(loops[i].clone()));
            }
            loops[i].children = children;
            set_parent_pointers(&mut loops[i].children);
        }
    }
    set_parent_pointers(&mut top_level);

    top_level
}

// ============================================================================
// GraphAlgorithms
// ============================================================================

/// Collection of graph algorithms operating on a control-flow or call graph.
pub struct GraphAlgorithms;

impl GraphAlgorithms {
    /// Compute strongly connected components (SCCs) using Kosaraju's algorithm.
    ///
    /// Returns a list of SCCs, where each SCC is a list of node indices.
    /// The components are returned in reverse topological order.
    pub fn scc(
        node_count: usize,
        successors: impl Fn(usize) -> Vec<usize>,
    ) -> Vec<Vec<usize>> {
        let mut graph = DiGraph::<(), ()>::new();
        let nodes: Vec<_> = (0..node_count).map(|_| graph.add_node(())).collect();
        for i in 0..node_count {
            for &s in &successors(i) {
                if s < node_count {
                    graph.add_edge(nodes[i], nodes[s], ());
                }
            }
        }
        petalgo::kosaraju_scc(&graph)
            .into_iter()
            .map(|scc| scc.into_iter().map(|ni| ni.index()).collect())
            .collect()
    }

    /// Compute strongly connected components (SCCs) using Tarjan's algorithm.
    ///
    /// Returns a list of SCCs, where each SCC is a list of node indices.
    /// Tarjan's algorithm has better constant factors than Kosaraju and
    /// requires only a single DFS pass.
    pub fn scc_tarjan(
        node_count: usize,
        successors: impl Fn(usize) -> Vec<usize>,
    ) -> Vec<Vec<usize>> {
        let mut index = 0usize;
        let mut indices = vec![None; node_count];
        let mut lowlink = vec![0usize; node_count];
        let mut on_stack = vec![false; node_count];
        let mut stack = Vec::new();
        let mut components = Vec::new();

        fn strongconnect(
            v: usize,
            index: &mut usize,
            indices: &mut [Option<usize>],
            lowlink: &mut [usize],
            on_stack: &mut [bool],
            stack: &mut Vec<usize>,
            components: &mut Vec<Vec<usize>>,
            node_count: usize,
            successors: &dyn Fn(usize) -> Vec<usize>,
        ) {
            indices[v] = Some(*index);
            lowlink[v] = *index;
            *index += 1;
            stack.push(v);
            on_stack[v] = true;

            for &w in &successors(v) {
                if w >= node_count {
                    continue;
                }
                if indices[w].is_none() {
                    strongconnect(
                        w, index, indices, lowlink, on_stack, stack,
                        components, node_count, successors,
                    );
                    lowlink[v] = lowlink[v].min(lowlink[w]);
                } else if on_stack[w] {
                    lowlink[v] = lowlink[v].min(indices[w].unwrap());
                }
            }

            if lowlink[v] == indices[v].unwrap() {
                let mut component = Vec::new();
                loop {
                    let w = stack.pop().unwrap();
                    on_stack[w] = false;
                    component.push(w);
                    if w == v {
                        break;
                    }
                }
                components.push(component);
            }
        }

        for v in 0..node_count {
            if indices[v].is_none() {
                strongconnect(
                    v,
                    &mut index,
                    &mut indices,
                    &mut lowlink,
                    &mut on_stack,
                    &mut stack,
                    &mut components,
                    node_count,
                    &successors,
                );
            }
        }

        // Return in reverse topological order (as Kosaraju does)
        components
    }

    /// Perform a topological sort on a directed graph.
    ///
    /// Returns the nodes in topological order (predecessors before successors).
    /// Returns an empty vector if the graph has cycles.
    pub fn topological_sort(
        node_count: usize,
        successors: impl Fn(usize) -> Vec<usize>,
    ) -> Vec<usize> {
        let mut indegree = vec![0usize; node_count];
        for i in 0..node_count {
            for &s in &successors(i) {
                if s < node_count {
                    indegree[s] += 1;
                }
            }
        }

        let mut queue: VecDeque<usize> = indegree
            .iter()
            .enumerate()
            .filter(|(_, &d)| d == 0)
            .map(|(i, _)| i)
            .collect();

        let mut result = Vec::with_capacity(node_count);

        while let Some(node) = queue.pop_front() {
            result.push(node);
            for &s in &successors(node) {
                if s < node_count {
                    indegree[s] -= 1;
                    if indegree[s] == 0 {
                        queue.push_back(s);
                    }
                }
            }
        }

        // If we didn't visit all nodes, there's a cycle
        if result.len() < node_count {
            Vec::new()
        } else {
            result
        }
    }

    /// Breadth-first search from a start node.
    ///
    /// Returns the nodes in BFS order.
    pub fn bfs(
        start: usize,
        node_count: usize,
        successors: impl Fn(usize) -> Vec<usize>,
    ) -> Vec<usize> {
        let mut visited = vec![false; node_count];
        let mut queue = VecDeque::new();
        let mut result = Vec::new();

        if start < node_count {
            visited[start] = true;
            queue.push_back(start);
        }

        while let Some(node) = queue.pop_front() {
            result.push(node);
            for &s in &successors(node) {
                if s < node_count && !visited[s] {
                    visited[s] = true;
                    queue.push_back(s);
                }
            }
        }

        result
    }

    /// Depth-first search from a start node.
    ///
    /// Returns the nodes in DFS preorder.
    pub fn dfs(
        start: usize,
        node_count: usize,
        successors: impl Fn(usize) -> Vec<usize>,
    ) -> Vec<usize> {
        let mut visited = vec![false; node_count];
        let mut result = Vec::new();

        fn dfs_visit(
            node: usize,
            visited: &mut [bool],
            result: &mut Vec<usize>,
            node_count: usize,
            successors: &dyn Fn(usize) -> Vec<usize>,
        ) {
            visited[node] = true;
            result.push(node);
            for &s in &successors(node) {
                if s < node_count && !visited[s] {
                    dfs_visit(s, visited, result, node_count, successors);
                }
            }
        }

        if start < node_count {
            dfs_visit(start, &mut visited, &mut result, node_count, &successors);
        }

        result
    }

    /// Compute the shortest path distances from a start node using BFS
    /// (unweighted graph).
    ///
    /// Returns a map from node index to distance. Unreachable nodes are
    /// not included.
    pub fn shortest_paths_bfs(
        start: usize,
        node_count: usize,
        successors: impl Fn(usize) -> Vec<usize>,
    ) -> HashMap<usize, usize> {
        let mut distances = HashMap::new();
        let mut queue = VecDeque::new();

        if start < node_count {
            distances.insert(start, 0);
            queue.push_back(start);
        }

        while let Some(node) = queue.pop_front() {
            let current_dist = distances[&node];
            for &s in &successors(node) {
                if s < node_count && !distances.contains_key(&s) {
                    distances.insert(s, current_dist + 1);
                    queue.push_back(s);
                }
            }
        }

        distances
    }

    /// Detect cycles in a directed graph using DFS.
    ///
    /// Returns `true` if the graph contains at least one cycle.
    pub fn has_cycle(
        node_count: usize,
        successors: impl Fn(usize) -> Vec<usize>,
    ) -> bool {
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Color {
            White,
            Gray,
            Black,
        }

        let mut color = vec![Color::White; node_count];

        fn dfs_cycle(
            node: usize,
            color: &mut [Color],
            node_count: usize,
            successors: &dyn Fn(usize) -> Vec<usize>,
        ) -> bool {
            color[node] = Color::Gray;
            for &s in &successors(node) {
                if s < node_count {
                    if color[s] == Color::Gray {
                        return true;
                    }
                    if color[s] == Color::White {
                        if dfs_cycle(s, color, node_count, successors) {
                            return true;
                        }
                    }
                }
            }
            color[node] = Color::Black;
            false
        }

        for i in 0..node_count {
            if color[i] == Color::White {
                if dfs_cycle(i, &mut color, node_count, &successors) {
                    return true;
                }
            }
        }

        false
    }

    /// Compute the articulation points (cut vertices) of an undirected graph.
    ///
    /// A node is an articulation point if removing it disconnects the graph.
    pub fn articulation_points(
        node_count: usize,
        neighbors: impl Fn(usize) -> Vec<usize>,
    ) -> HashSet<usize> {
        let mut visited = vec![false; node_count];
        let mut disc = vec![0usize; node_count];
        let mut low = vec![0usize; node_count];
        let mut parent = vec![None; node_count];
        let mut ap = HashSet::new();
        let mut time = 0usize;

        fn dfs_ap(
            u: usize,
            visited: &mut [bool],
            disc: &mut [usize],
            low: &mut [usize],
            parent: &mut [Option<usize>],
            ap: &mut HashSet<usize>,
            time: &mut usize,
            node_count: usize,
            neighbors: &dyn Fn(usize) -> Vec<usize>,
        ) {
            let mut children = 0usize;
            visited[u] = true;
            *time += 1;
            disc[u] = *time;
            low[u] = *time;

            for &v in &neighbors(u) {
                if v >= node_count {
                    continue;
                }
                if !visited[v] {
                    children += 1;
                    parent[v] = Some(u);
                    dfs_ap(v, visited, disc, low, parent, ap, time, node_count, neighbors);
                    low[u] = low[u].min(low[v]);

                    if parent[u].is_none() && children > 1 {
                        ap.insert(u);
                    }
                    if parent[u].is_some() && low[v] >= disc[u] {
                        ap.insert(u);
                    }
                } else if Some(v) != parent[u] {
                    low[u] = low[u].min(disc[v]);
                }
            }
        }

        for i in 0..node_count {
            if !visited[i] {
                dfs_ap(
                    i,
                    &mut visited,
                    &mut disc,
                    &mut low,
                    &mut parent,
                    &mut ap,
                    &mut time,
                    node_count,
                    &neighbors,
                );
            }
        }

        ap
    }

    /// Compute an approximate maximum independent set using a greedy algorithm.
    ///
    /// Returns the set of node indices in the independent set.
    pub fn greedy_independent_set(
        node_count: usize,
        neighbors: impl Fn(usize) -> Vec<usize>,
    ) -> HashSet<usize> {
        let mut included = HashSet::new();
        let mut excluded = HashSet::new();

        // Order nodes by degree (fewest neighbors first)
        let mut nodes_by_degree: Vec<(usize, usize)> = (0..node_count)
            .map(|i| (i, neighbors(i).len()))
            .collect();
        nodes_by_degree.sort_by_key(|(_, deg)| *deg);

        for (node, _) in nodes_by_degree {
            if !excluded.contains(&node) {
                included.insert(node);
                for &n in &neighbors(node) {
                    excluded.insert(n);
                }
            }
        }

        included
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create Address values for testing
    fn addr(val: u64) -> Address {
        Address::from(val)
    }

    // ------------------------------------------------------------------
    // ControlFlowGraph tests
    // ------------------------------------------------------------------

    #[test]
    fn test_cfg_create_empty() {
        let cfg = ControlFlowGraph::new();
        assert_eq!(cfg.block_count(), 0);
        assert_eq!(cfg.edge_count(), 0);
        assert!(cfg.entry_block().is_none());
    }

    #[test]
    fn test_cfg_add_block() {
        let mut cfg = ControlFlowGraph::new();
        let entry = cfg.add_block("entry");
        assert_eq!(cfg.block_count(), 1);
        let block = cfg.get_block(entry).unwrap();
        assert_eq!(block.label.as_deref(), Some("entry"));
        assert!(block.is_entry);
    }

    #[test]
    fn test_cfg_entry_and_exit() {
        let mut cfg = ControlFlowGraph::new();
        let a = cfg.add_block("a");
        let b = cfg.add_block("b");
        cfg.add_edge(a, b, ControlFlowEdgeType::FallThrough);

        assert_eq!(cfg.entry_block(), Some(a));
        assert_eq!(cfg.exit_blocks(), vec![b]);
    }

    #[test]
    fn test_cfg_successors_predecessors() {
        let mut cfg = ControlFlowGraph::new();
        let a = cfg.add_block("a");
        let b = cfg.add_block("b");
        let c = cfg.add_block("c");
        cfg.add_edge(a, b, ControlFlowEdgeType::FallThrough);
        cfg.add_edge(a, c, ControlFlowEdgeType::ConditionalBranch(true));

        let succs = cfg.successors(a);
        assert_eq!(succs.len(), 2);
        assert!(succs.contains(&b));
        assert!(succs.contains(&c));

        let preds = cfg.predecessors(b);
        assert_eq!(preds.len(), 1);
        assert_eq!(preds[0], a);
    }

    #[test]
    fn test_cfg_post_order() {
        let mut cfg = ControlFlowGraph::new();
        let a = cfg.add_block("a");
        let b = cfg.add_block("b");
        let c = cfg.add_block("c");
        cfg.add_edge(a, b, ControlFlowEdgeType::FallThrough);
        cfg.add_edge(b, c, ControlFlowEdgeType::FallThrough);

        let po = cfg.post_order();
        // Post-order: c, b, a
        assert_eq!(po.len(), 3);
        assert_eq!(po[2], a); // entry last in post-order
    }

    #[test]
    fn test_cfg_reverse_post_order() {
        let mut cfg = ControlFlowGraph::new();
        let a = cfg.add_block("a");
        let b = cfg.add_block("b");
        let c = cfg.add_block("c");
        cfg.add_edge(a, b, ControlFlowEdgeType::FallThrough);
        cfg.add_edge(b, c, ControlFlowEdgeType::FallThrough);

        let rpo = cfg.reverse_post_order();
        assert_eq!(rpo.len(), 3);
        assert_eq!(rpo[0], a); // entry first in reverse-post-order
    }

    #[test]
    fn test_cfg_dominator_tree() {
        // Diamond CFG: 0 -> 1, 0 -> 2, 1 -> 3, 2 -> 3
        let mut cfg = ControlFlowGraph::new();
        let a = cfg.add_block("entry");
        let b = cfg.add_block("left");
        let c = cfg.add_block("right");
        let d = cfg.add_block("merge");
        cfg.add_edge(a, b, ControlFlowEdgeType::ConditionalBranch(true));
        cfg.add_edge(a, c, ControlFlowEdgeType::ConditionalBranch(false));
        cfg.add_edge(b, d, ControlFlowEdgeType::FallThrough);
        cfg.add_edge(c, d, ControlFlowEdgeType::FallThrough);

        let dt = cfg.dominator_tree().unwrap();
        assert_eq!(dt.node_count(), 4);
        // Entry (node 0) dominates all
        assert!(dt.dominates(0, 1));
        assert!(dt.dominates(0, 2));
        assert!(dt.dominates(0, 3));
        // Merge (node 3) is dominated by entry
        assert!(dt.dominates(0, 3));
    }

    #[test]
    fn test_cfg_find_loops_simple() {
        // Simple loop: entry -> header -> body -> header, body -> exit
        let mut cfg = ControlFlowGraph::new();
        let entry = cfg.add_block("entry");
        let header = cfg.add_block("header");
        let body = cfg.add_block("body");
        let exit = cfg.add_block("exit");

        cfg.add_edge(entry, header, ControlFlowEdgeType::FallThrough);
        cfg.add_edge(header, body, ControlFlowEdgeType::FallThrough);
        cfg.add_edge(body, header, ControlFlowEdgeType::Jump);
        cfg.add_edge(body, exit, ControlFlowEdgeType::ConditionalBranch(false));

        assert!(cfg.has_loops());
        let loops = cfg.find_loops();
        assert!(!loops.is_empty());
        // The loop header should dominate body
        let header_loop = &loops[0];
        assert!(header_loop.contains(1) || header_loop.contains(2));
    }

    #[test]
    fn test_cfg_is_reducible_diamond() {
        let mut cfg = ControlFlowGraph::new();
        let a = cfg.add_block("entry");
        let b = cfg.add_block("then");
        let c = cfg.add_block("else");
        let d = cfg.add_block("merge");
        cfg.add_edge(a, b, ControlFlowEdgeType::ConditionalBranch(true));
        cfg.add_edge(a, c, ControlFlowEdgeType::ConditionalBranch(false));
        cfg.add_edge(b, d, ControlFlowEdgeType::FallThrough);
        cfg.add_edge(c, d, ControlFlowEdgeType::FallThrough);

        assert!(cfg.is_reducible());
    }

    #[test]
    fn test_cfg_is_reducible_loop() {
        // Natural loop is reducible
        let mut cfg = ControlFlowGraph::new();
        let entry = cfg.add_block("entry");
        let loop_hdr = cfg.add_block("loop");
        cfg.add_edge(entry, loop_hdr, ControlFlowEdgeType::FallThrough);
        cfg.add_edge(loop_hdr, loop_hdr, ControlFlowEdgeType::ConditionalBranch(true));

        assert!(cfg.is_reducible());
    }

    #[test]
    fn test_cfg_merge_blocks() {
        let mut cfg = ControlFlowGraph::new();
        let a = cfg.add_block("a");
        let b = cfg.add_block("b");
        let c = cfg.add_block("c");
        cfg.add_edge(a, b, ControlFlowEdgeType::FallThrough);
        cfg.add_edge(b, c, ControlFlowEdgeType::FallThrough);

        let result = cfg.merge_blocks(a, b);
        assert!(result.is_ok());
        assert_eq!(cfg.block_count(), 2);
    }

    #[test]
    fn test_cfg_merge_blocks_rejects_multiple_successors() {
        let mut cfg = ControlFlowGraph::new();
        let a = cfg.add_block("a");
        let b = cfg.add_block("b");
        let c = cfg.add_block("c");
        cfg.add_edge(a, b, ControlFlowEdgeType::FallThrough);
        cfg.add_edge(a, c, ControlFlowEdgeType::ConditionalBranch(true));

        let result = cfg.merge_blocks(a, b);
        assert!(result.is_err());
    }

    #[test]
    fn test_cfg_split_critical_edges() {
        // Diamond with entry -> then, entry -> else, then -> merge, else -> merge
        // No critical edges in a diamond unless there are more indirections.
        // Create a CFG with a critical edge:
        // entry -> A, entry -> B, A -> C, B -> C (C has 2 preds, both A and B have 1 succ)
        // No -- that's not critical.
        // Critical: source has >1 succ, target has >1 pred.
        // A -> C, A -> D, B -> C, C -> D (edge A->C is not critical; A has 2 succ, C has 2 pred)
        // Actually, build it differently: A -> B, A -> C, D -> B -> E, D -> F
        // Critical edge: A -> B (A has 2 succ [B,C], B has 2 pred [A,D])

        let mut cfg = ControlFlowGraph::new();
        let a = cfg.add_block("A");
        let b = cfg.add_block("B");
        let c = cfg.add_block("C");
        let d = cfg.add_block("D");
        let e = cfg.add_block("E");

        cfg.add_edge(a, b, ControlFlowEdgeType::ConditionalBranch(true));
        cfg.add_edge(a, c, ControlFlowEdgeType::ConditionalBranch(false));
        cfg.add_edge(d, b, ControlFlowEdgeType::Jump);
        cfg.add_edge(b, e, ControlFlowEdgeType::FallThrough);
        cfg.add_edge(c, e, ControlFlowEdgeType::FallThrough);

        // Edge A->B: A has 2 outgoing (B,C), B has 2 incoming (A,D) -- critical
        let split_count = cfg.split_critical_edges();
        assert!(split_count >= 1);
        // After splitting, there should be an extra block
        assert!(cfg.block_count() >= 6);
    }

    #[test]
    fn test_cfg_clear() {
        let mut cfg = ControlFlowGraph::new();
        cfg.add_block("test");
        cfg.clear();
        assert_eq!(cfg.block_count(), 0);
        assert!(cfg.entry_block().is_none());
    }

    #[test]
    fn test_cfg_find_by_label() {
        let mut cfg = ControlFlowGraph::new();
        cfg.add_block("my_block");
        let found = cfg.find_by_label("my_block");
        assert!(found.is_some());
        let not_found = cfg.find_by_label("nonexistent");
        assert!(not_found.is_none());
    }

    // ------------------------------------------------------------------
    // CallGraph tests
    // ------------------------------------------------------------------

    #[test]
    fn test_call_graph_build() {
        let mut graph = CallGraph::new();
        let functions = vec![
            FunctionInfo {
                entry: addr(0x1000),
                name: "main".into(),
                is_external: false,
                is_thunk: false,
                callees: vec![
                    (addr(0x2000), CallType::Direct, Some(addr(0x1010))),
                    (addr(0x3000), CallType::Direct, Some(addr(0x1020))),
                ],
            },
            FunctionInfo {
                entry: addr(0x2000),
                name: "foo".into(),
                is_external: false,
                is_thunk: false,
                callees: vec![(addr(0x3000), CallType::Direct, Some(addr(0x2010)))],
            },
            FunctionInfo {
                entry: addr(0x3000),
                name: "bar".into(),
                is_external: false,
                is_thunk: false,
                callees: vec![],
            },
        ];

        graph.build_from_functions(&functions);
        assert_eq!(graph.node_count(), 3);
        assert_eq!(graph.edge_count(), 3);

        let callers = graph.callers(addr(0x3000));
        assert_eq!(callers.len(), 2);
        assert!(callers.iter().any(|n| n.name == "main"));
        assert!(callers.iter().any(|n| n.name == "foo"));
    }

    #[test]
    fn test_call_graph_leaves() {
        let mut graph = CallGraph::new();
        let functions = vec![
            FunctionInfo {
                entry: addr(0x1000),
                name: "main".into(),
                is_external: false,
                is_thunk: false,
                callees: vec![(addr(0x2000), CallType::Direct, None)],
            },
            FunctionInfo {
                entry: addr(0x2000),
                name: "leaf".into(),
                is_external: false,
                is_thunk: false,
                callees: vec![],
            },
        ];
        graph.build_from_functions(&functions);

        let leaves = graph.leaf_nodes();
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0], addr(0x2000));

        let leaf_funcs = graph.leaf_functions();
        assert_eq!(leaf_funcs.len(), 1);
        assert_eq!(leaf_funcs[0].name, "leaf");

        let roots = graph.root_nodes();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0], addr(0x1000));
    }

    #[test]
    fn test_call_graph_cycles() {
        let mut graph = CallGraph::new();
        let functions = vec![
            FunctionInfo {
                entry: addr(0x1000),
                name: "a".into(),
                is_external: false,
                is_thunk: false,
                callees: vec![(addr(0x2000), CallType::Direct, None)],
            },
            FunctionInfo {
                entry: addr(0x2000),
                name: "b".into(),
                is_external: false,
                is_thunk: false,
                callees: vec![(addr(0x1000), CallType::Direct, None)],
            },
        ];
        graph.build_from_functions(&functions);

        let sccs = graph.strongly_connected_components();
        // Both nodes should be in one SCC
        assert_eq!(sccs.len(), 1);
        assert_eq!(sccs[0].len(), 2);
    }

    #[test]
    fn test_call_graph_max_depth() {
        let mut graph = CallGraph::new();
        let functions = vec![
            FunctionInfo {
                entry: addr(0x1000),
                name: "level0".into(),
                is_external: false,
                is_thunk: false,
                callees: vec![(addr(0x2000), CallType::Direct, None)],
            },
            FunctionInfo {
                entry: addr(0x2000),
                name: "level1".into(),
                is_external: false,
                is_thunk: false,
                callees: vec![(addr(0x3000), CallType::Direct, None)],
            },
            FunctionInfo {
                entry: addr(0x3000),
                name: "level2".into(),
                is_external: false,
                is_thunk: false,
                callees: vec![],
            },
        ];
        graph.build_from_functions(&functions);

        let depth = graph.max_call_depth(addr(0x1000));
        assert_eq!(depth, Some(2));
    }

    #[test]
    fn test_call_graph_add_function() {
        let mut graph = CallGraph::new();
        graph.add_function(addr(0x1000), "main", false, false);
        assert_eq!(graph.node_count(), 1);
        let node = graph.node_by_address(addr(0x1000)).unwrap();
        assert_eq!(node.name, "main");
    }

    #[test]
    fn test_call_graph_add_call_edge() {
        let mut graph = CallGraph::new();
        graph.add_call_edge(
            addr(0x1000),
            addr(0x2000),
            CallType::Direct,
            Some(addr(0x1010)),
        );
        assert_eq!(graph.node_count(), 2);
        assert_eq!(graph.edge_count(), 1);

        let callees = graph.callees_of(addr(0x1000));
        assert_eq!(callees.len(), 1);
        assert_eq!(callees[0].0.address, addr(0x2000));

        let callers = graph.callers_of(addr(0x2000));
        assert_eq!(callers.len(), 1);
        assert_eq!(callers[0].address, addr(0x1000));
    }

    #[test]
    fn test_call_graph_has_recursion() {
        let mut graph = CallGraph::new();
        graph.add_call_edge(addr(0x1000), addr(0x2000), CallType::Direct, None);
        graph.add_call_edge(addr(0x2000), addr(0x1000), CallType::Direct, None);

        assert!(graph.has_recursion(addr(0x1000)));
        assert!(graph.has_recursion(addr(0x2000)));
    }

    #[test]
    fn test_call_graph_no_recursion() {
        let mut graph = CallGraph::new();
        graph.add_call_edge(addr(0x1000), addr(0x2000), CallType::Direct, None);
        graph.add_call_edge(addr(0x2000), addr(0x3000), CallType::Direct, None);

        assert!(!graph.has_recursion(addr(0x1000)));
    }

    // ------------------------------------------------------------------
    // DominatorTree tests
    // ------------------------------------------------------------------

    #[test]
    fn test_dominator_tree_simple() {
        // A simple CFG: 0 -> 1, 0 -> 2, 1 -> 3, 2 -> 3, 3 -> 4
        let successors = |n: usize| -> Vec<usize> {
            match n {
                0 => vec![1, 2],
                1 => vec![3],
                2 => vec![3],
                3 => vec![4],
                4 => vec![],
                _ => vec![],
            }
        };

        let dt = DominatorTree::build(5, successors);

        // Node 0 should dominate everyone
        assert!(dt.dominates(0, 0));
        assert!(dt.dominates(0, 1));
        assert!(dt.dominates(0, 2));
        assert!(dt.dominates(0, 3));
        assert!(dt.dominates(0, 4));

        // Node 3 dominates 4
        assert!(dt.dominates(3, 4));

        // Node 1 does NOT dominate 2 or 4
        assert!(!dt.dominates(1, 2));
        assert!(!dt.dominates(1, 4));

        // idom(1) = 0, idom(3) = 0
        assert_eq!(dt.immediate_dominator(1), Some(0));
        assert_eq!(dt.immediate_dominator(3), Some(0));
        assert_eq!(dt.immediate_dominator(4), Some(3));

        // Entry has no idom
        assert_eq!(dt.immediate_dominator(0), None);
    }

    #[test]
    fn test_dominator_tree_if_else() {
        let successors = |n: usize| -> Vec<usize> {
            match n {
                0 => vec![1],
                1 => vec![2, 3],
                2 => vec![4],
                3 => vec![4],
                4 => vec![5],
                5 => vec![],
                _ => vec![],
            }
        };

        let dt = DominatorTree::build(6, successors);

        assert!(dt.dominates(0, 1));
        assert!(dt.dominates(1, 2));
        assert!(dt.dominates(1, 3));
        assert!(dt.dominates(1, 4));
        assert!(dt.dominates(4, 5));

        // Node 2 does NOT dominate node 4 (node 3 is another predecessor)
        assert!(!dt.dominates(2, 4));
    }

    // ------------------------------------------------------------------
    // GraphAlgorithms tests
    // ------------------------------------------------------------------

    #[test]
    fn test_topological_sort() {
        let successors = |n: usize| -> Vec<usize> {
            match n {
                0 => vec![1],
                1 => vec![2],
                _ => vec![],
            }
        };

        let order = GraphAlgorithms::topological_sort(3, successors);
        assert_eq!(order, vec![0, 1, 2]);
    }

    #[test]
    fn test_topological_sort_dag() {
        let successors = |n: usize| -> Vec<usize> {
            match n {
                0 => vec![1, 2],
                1 => vec![3],
                2 => vec![3],
                3 => vec![],
                _ => vec![],
            }
        };

        let order = GraphAlgorithms::topological_sort(4, successors);
        assert_eq!(order.len(), 4);
        let pos0 = order.iter().position(|&x| x == 0).unwrap();
        let pos1 = order.iter().position(|&x| x == 1).unwrap();
        let pos2 = order.iter().position(|&x| x == 2).unwrap();
        let pos3 = order.iter().position(|&x| x == 3).unwrap();
        assert!(pos0 < pos1);
        assert!(pos0 < pos2);
        assert!(pos1 < pos3);
        assert!(pos2 < pos3);
    }

    #[test]
    fn test_topological_sort_cycle() {
        let successors = |n: usize| -> Vec<usize> {
            match n {
                0 => vec![1],
                1 => vec![2],
                2 => vec![0],
                _ => vec![],
            }
        };

        let order = GraphAlgorithms::topological_sort(3, successors);
        assert!(order.is_empty());
    }

    #[test]
    fn test_bfs() {
        let successors = |n: usize| -> Vec<usize> {
            match n {
                0 => vec![1, 2],
                1 => vec![3],
                _ => vec![],
            }
        };

        let order = GraphAlgorithms::bfs(0, 4, successors);
        assert_eq!(order[0], 0);
        let pos1 = order.iter().position(|&x| x == 1).unwrap();
        let pos2 = order.iter().position(|&x| x == 2).unwrap();
        let pos3 = order.iter().position(|&x| x == 3).unwrap();
        assert!(pos1 < pos3);
        assert!(pos2 < pos3);
    }

    #[test]
    fn test_dfs() {
        let successors = |n: usize| -> Vec<usize> {
            match n {
                0 => vec![1, 2],
                1 => vec![3],
                _ => vec![],
            }
        };

        let order = GraphAlgorithms::dfs(0, 4, successors);
        assert_eq!(order[0], 0);
        assert_eq!(order.len(), 4);
    }

    #[test]
    fn test_scc() {
        let successors = |n: usize| -> Vec<usize> {
            match n {
                0 => vec![1],
                1 => vec![0, 2],
                _ => vec![],
            }
        };

        let sccs = GraphAlgorithms::scc(3, successors);
        assert_eq!(sccs.len(), 2);
        let has_single = sccs.iter().any(|c| c.len() == 1 && c[0] == 2);
        let has_pair = sccs.iter().any(|c| c.len() == 2);
        assert!(has_single);
        assert!(has_pair);
    }

    #[test]
    fn test_scc_tarjan() {
        let successors = |n: usize| -> Vec<usize> {
            match n {
                0 => vec![1],
                1 => vec![0, 2],
                _ => vec![],
            }
        };

        let sccs = GraphAlgorithms::scc_tarjan(3, successors);
        assert_eq!(sccs.len(), 2);
        let has_single = sccs.iter().any(|c| c.len() == 1 && c[0] == 2);
        let has_pair = sccs.iter().any(|c| c.len() == 2);
        assert!(has_single);
        assert!(has_pair);
    }

    #[test]
    fn test_scc_tarjan_single_component() {
        // 0 -> 1 -> 2 -> 0 (single SCC)
        let successors = |n: usize| -> Vec<usize> {
            match n {
                0 => vec![1],
                1 => vec![2],
                2 => vec![0],
                _ => vec![],
            }
        };

        let sccs = GraphAlgorithms::scc_tarjan(3, successors);
        assert_eq!(sccs.len(), 1);
        assert_eq!(sccs[0].len(), 3);
    }

    #[test]
    fn test_has_cycle_true() {
        let successors = |n: usize| -> Vec<usize> {
            match n {
                0 => vec![1],
                1 => vec![2],
                2 => vec![0],
                _ => vec![],
            }
        };
        assert!(GraphAlgorithms::has_cycle(3, successors));
    }

    #[test]
    fn test_has_cycle_false() {
        let successors = |n: usize| -> Vec<usize> {
            match n {
                0 => vec![1, 2],
                1 => vec![3],
                _ => vec![],
            }
        };
        assert!(!GraphAlgorithms::has_cycle(4, successors));
    }

    #[test]
    fn test_shortest_paths() {
        let successors = |n: usize| -> Vec<usize> {
            match n {
                0 => vec![1, 2],
                1 => vec![3],
                2 => vec![3],
                _ => vec![],
            }
        };

        let dists = GraphAlgorithms::shortest_paths_bfs(0, 4, successors);
        assert_eq!(dists.get(&0), Some(&0));
        assert_eq!(dists.get(&1), Some(&1));
        assert_eq!(dists.get(&2), Some(&1));
        assert_eq!(dists.get(&3), Some(&2));
    }

    #[test]
    fn test_articulation_points() {
        let neighbors = |n: usize| -> Vec<usize> {
            match n {
                0 => vec![1],
                1 => vec![0, 2],
                2 => vec![1, 3],
                3 => vec![2],
                _ => vec![],
            }
        };

        let aps = GraphAlgorithms::articulation_points(4, neighbors);
        assert!(aps.contains(&1));
        assert!(aps.contains(&2));
        assert!(!aps.contains(&0));
        assert!(!aps.contains(&3));
    }

    // ------------------------------------------------------------------
    // LoopInfo tests
    // ------------------------------------------------------------------

    #[test]
    fn test_natural_loops_simple() {
        let successors = |n: usize| -> Vec<usize> {
            match n {
                0 => vec![1],
                1 => vec![2],
                2 => vec![1, 3],
                3 => vec![],
                _ => vec![],
            }
        };

        let dt = DominatorTree::build(4, successors);
        let preds = Predecessors::build(4, successors);
        let loops = detect_natural_loops(4, successors, &preds, &dt);

        assert_eq!(loops.len(), 1);
        let loop_info = &loops[0];
        assert_eq!(loop_info.header, 1);
        assert!(loop_info.contains(1));
        assert!(loop_info.contains(2));
        assert!(!loop_info.contains(0));
        assert!(!loop_info.contains(3));
    }

    #[test]
    fn test_natural_loops_nested() {
        let successors = |n: usize| -> Vec<usize> {
            match n {
                0 => vec![1],
                1 => vec![2],
                2 => vec![3],
                3 => vec![2, 4],
                4 => vec![1, 5],
                5 => vec![],
                _ => vec![],
            }
        };

        let dt = DominatorTree::build(6, successors);
        let preds = Predecessors::build(6, successors);
        let loops = detect_natural_loops(6, successors, &preds, &dt);

        // We expect at least one loop
        assert!(!loops.is_empty());
    }

    #[test]
    fn test_loop_info_nest_depth() {
        let mut outer = LoopInfo::new(1);
        outer.nodes.extend([2, 3, 4].iter().copied());

        let mut inner = LoopInfo::new(2);
        inner.nodes.extend([3].iter().copied());
        inner.parent = Some(Box::new(outer.clone()));

        outer.children.push(inner.clone());

        assert_eq!(outer.nest_depth(), 0);
        assert_eq!(inner.nest_depth(), 1);
    }
}
