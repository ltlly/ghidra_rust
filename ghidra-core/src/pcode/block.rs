//! PcodeBlock -- control-flow blocks in the pcode model.
//!
//! Ported from `ghidra.program.model.pcode.PcodeBlock` and its subclasses.
//! These types model the structured control-flow graph produced by Ghidra's
//! decompiler.

use crate::addr::Address;
use serde::{Deserialize, Serialize};
use std::fmt;

// ============================================================================
// BlockType -- type identifiers for PcodeBlock subclasses
// ============================================================================

/// Identifies the concrete type of a [`PcodeBlock`].
///
/// Matches the Java `PcodeBlock.*` type constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
pub enum BlockType {
    /// Plain block.
    Plain = 0,
    /// Basic block (linear sequence of pcode ops).
    Basic = 1,
    /// Graph (container of blocks).
    Graph = 2,
    /// Copy block (alias for plain).
    Copy = 3,
    /// Goto block (unconditional jump).
    Goto = 4,
    /// Multi-goto block (multiple unconditional jumps).
    MultiGoto = 5,
    /// List block (ordered sequence of blocks).
    List = 6,
    /// Condition block (two-way conditional).
    Condition = 7,
    /// Proper if block (if-then).
    ProperIf = 8,
    /// If-else block.
    IfElse = 9,
    /// If-goto block (conditional goto).
    IfGoto = 10,
    /// While-do loop.
    WhileDo = 11,
    /// Do-while loop.
    DoWhile = 12,
    /// Switch block.
    Switch = 13,
    /// Infinite loop.
    InfLoop = 14,
}

impl BlockType {
    /// Returns the numeric type identifier.
    pub fn id(self) -> u16 {
        self as u16
    }

    /// Returns the `BlockType` for a given numeric value.
    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            0 => Some(BlockType::Plain),
            1 => Some(BlockType::Basic),
            2 => Some(BlockType::Graph),
            3 => Some(BlockType::Copy),
            4 => Some(BlockType::Goto),
            5 => Some(BlockType::MultiGoto),
            6 => Some(BlockType::List),
            7 => Some(BlockType::Condition),
            8 => Some(BlockType::ProperIf),
            9 => Some(BlockType::IfElse),
            10 => Some(BlockType::IfGoto),
            11 => Some(BlockType::WhileDo),
            12 => Some(BlockType::DoWhile),
            13 => Some(BlockType::Switch),
            14 => Some(BlockType::InfLoop),
            _ => None,
        }
    }

    /// Returns a human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            BlockType::Plain => "plain",
            BlockType::Basic => "basic",
            BlockType::Graph => "graph",
            BlockType::Copy => "plain",
            BlockType::Goto => "goto",
            BlockType::MultiGoto => "multigoto",
            BlockType::List => "list",
            BlockType::Condition => "condition",
            BlockType::ProperIf => "properif",
            BlockType::IfElse => "ifelse",
            BlockType::IfGoto => "ifgoto",
            BlockType::WhileDo => "whiledo",
            BlockType::DoWhile => "dowhile",
            BlockType::Switch => "switch",
            BlockType::InfLoop => "infloop",
        }
    }
}

impl fmt::Display for BlockType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ============================================================================
// BlockEdge -- an edge between PcodeBlocks
// ============================================================================

/// An edge between two blocks in a control-flow graph.
///
/// The `label` field distinguishes the kind of flow:
/// - 0 = fall-through
/// - 1 = true branch
/// - 2 = false branch
/// - other values = switch case indices
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockEdge {
    /// Index of the source or target block.
    pub block_index: u32,
    /// Edge label (0=fallthrough, 1=true, 2=false, 3+=case index).
    pub label: u32,
}

impl BlockEdge {
    /// Create a new block edge.
    pub fn new(block_index: u32, label: u32) -> Self {
        Self { block_index, label }
    }

    /// Returns `true` if this is a fall-through edge.
    pub fn is_fallthrough(&self) -> bool {
        self.label == 0
    }

    /// Returns `true` if this is a true-branch edge.
    pub fn is_true_branch(&self) -> bool {
        self.label == 1
    }

    /// Returns `true` if this is a false-branch edge.
    pub fn is_false_branch(&self) -> bool {
        self.label == 2
    }
}

// ============================================================================
// PcodeBlock -- base control-flow block
// ============================================================================

/// A block in the pcode control-flow graph.
///
/// Corresponds to Ghidra's `PcodeBlock`. Each block has:
/// - A type ([`BlockType`]).
/// - An index within the block graph.
/// - Incoming and outgoing edges ([`BlockEdge`]).
/// - Start/stop addresses of the first/last instructions.
/// - An optional parent block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeBlock {
    /// The type of this block.
    pub block_type: BlockType,
    /// Index of this block within its graph.
    pub index: u32,
    /// Index of the parent block (u32::MAX if none).
    pub parent_index: u32,
    /// Edges into this block.
    pub into_this: Vec<BlockEdge>,
    /// Edges out of this block.
    pub out_of_this: Vec<BlockEdge>,
    /// Address of the first instruction in this block.
    pub start: Address,
    /// Address of the last instruction in this block.
    pub stop: Address,
}

impl PcodeBlock {
    /// Create a new pcode block.
    pub fn new(block_type: BlockType, index: u32) -> Self {
        Self {
            block_type,
            index,
            parent_index: u32::MAX,
            into_this: Vec::new(),
            out_of_this: Vec::new(),
            start: Address::NULL,
            stop: Address::NULL,
        }
    }

    /// Create a basic block with start/stop addresses.
    pub fn basic(index: u32, start: Address, stop: Address) -> Self {
        Self {
            block_type: BlockType::Basic,
            index,
            parent_index: u32::MAX,
            into_this: Vec::new(),
            out_of_this: Vec::new(),
            start,
            stop,
        }
    }

    /// Returns the block type.
    pub fn get_block_type(&self) -> BlockType {
        self.block_type
    }

    /// Returns the block index.
    pub fn get_index(&self) -> u32 {
        self.index
    }

    /// Returns the start address.
    pub fn get_start(&self) -> Address {
        self.start
    }

    /// Returns the stop address.
    pub fn get_stop(&self) -> Address {
        self.stop
    }

    /// Set the start address.
    pub fn set_start(&mut self, addr: Address) {
        self.start = addr;
    }

    /// Set the stop address.
    pub fn set_stop(&mut self, addr: Address) {
        self.stop = addr;
    }

    /// Set the parent block index.
    pub fn set_parent(&mut self, parent: u32) {
        self.parent_index = parent;
    }

    /// Returns the parent block index, or `None`.
    pub fn get_parent_index(&self) -> Option<u32> {
        if self.parent_index == u32::MAX {
            None
        } else {
            Some(self.parent_index)
        }
    }

    /// Add an incoming edge.
    pub fn add_incoming(&mut self, edge: BlockEdge) {
        self.into_this.push(edge);
    }

    /// Add an outgoing edge.
    pub fn add_outgoing(&mut self, edge: BlockEdge) {
        self.out_of_this.push(edge);
    }

    /// Returns the number of incoming edges.
    pub fn get_in_size(&self) -> usize {
        self.into_this.len()
    }

    /// Returns the number of outgoing edges.
    pub fn get_out_size(&self) -> usize {
        self.out_of_this.len()
    }

    /// Returns a reference to the incoming edges.
    pub fn get_in_edges(&self) -> &[BlockEdge] {
        &self.into_this
    }

    /// Returns a reference to the outgoing edges.
    pub fn get_out_edges(&self) -> &[BlockEdge] {
        &self.out_of_this
    }

    /// Returns `true` if the given block index appears among this block's
    /// outgoing targets.
    pub fn contains_outgoing(&self, block_index: u32) -> bool {
        self.out_of_this.iter().any(|e| e.block_index == block_index)
    }

    /// Returns `true` if the given block index appears among this block's
    /// incoming sources.
    pub fn contains_incoming(&self, block_index: u32) -> bool {
        self.into_this.iter().any(|e| e.block_index == block_index)
    }

    /// Returns the type name string.
    pub fn type_name(&self) -> &'static str {
        self.block_type.name()
    }
}

impl fmt::Display for PcodeBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Block[{}] {} ({}, in: {}, out: {})",
            self.index,
            self.block_type,
            self.start,
            self.into_this.len(),
            self.out_of_this.len()
        )
    }
}

// ============================================================================
// PcodeBlockBasic -- a basic block of sequential pcode ops
// ============================================================================

/// A basic block containing a linear sequence of pcode operations.
///
/// Corresponds to Ghidra's `PcodeBlockBasic`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeBlockBasic {
    /// The underlying block data.
    pub block: PcodeBlock,
    /// Indices of PcodeOpAST nodes in this block (in execution order).
    pub op_indices: Vec<u32>,
}

impl PcodeBlockBasic {
    /// Create a new basic block.
    pub fn new(index: u32) -> Self {
        Self {
            block: PcodeBlock::new(BlockType::Basic, index),
            op_indices: Vec::new(),
        }
    }

    /// Add a pcode op index to this block.
    pub fn add_op(&mut self, op_index: u32) {
        self.op_indices.push(op_index);
    }

    /// Returns the number of pcode ops in this block.
    pub fn num_ops(&self) -> usize {
        self.op_indices.len()
    }

    /// Returns the op indices.
    pub fn get_op_indices(&self) -> &[u32] {
        &self.op_indices
    }
}

// ============================================================================
// BlockGraph -- a container of blocks forming a graph
// ============================================================================

/// A graph of [`PcodeBlock`]s forming a control-flow structure.
///
/// Corresponds to Ghidra's `BlockGraph`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockGraph {
    /// The underlying block data.
    pub block: PcodeBlock,
    /// Indices of child blocks in this graph.
    pub child_indices: Vec<u32>,
}

impl BlockGraph {
    /// Create a new block graph.
    pub fn new(index: u32) -> Self {
        Self {
            block: PcodeBlock::new(BlockType::Graph, index),
            child_indices: Vec::new(),
        }
    }

    /// Add a child block index.
    pub fn add_child(&mut self, child_index: u32) {
        self.child_indices.push(child_index);
    }

    /// Returns the number of child blocks.
    pub fn num_blocks(&self) -> usize {
        self.child_indices.len()
    }

    /// Returns the child block indices.
    pub fn get_block_indices(&self) -> &[u32] {
        &self.child_indices
    }
}

// ============================================================================
// Structured block types
// ============================================================================

/// A goto block (unconditional jump to a target).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockGoto {
    pub block: PcodeBlock,
    /// Index of the target block.
    pub goto_index: u32,
}

impl BlockGoto {
    pub fn new(index: u32, goto_index: u32) -> Self {
        Self {
            block: PcodeBlock::new(BlockType::Goto, index),
            goto_index,
        }
    }
}

/// A multi-goto block (multiple unconditional jumps).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockMultiGoto {
    pub block: PcodeBlock,
    /// Indices of the target blocks.
    pub goto_indices: Vec<u32>,
}

impl BlockMultiGoto {
    pub fn new(index: u32) -> Self {
        Self {
            block: PcodeBlock::new(BlockType::MultiGoto, index),
            goto_indices: Vec::new(),
        }
    }

    pub fn add_goto(&mut self, target: u32) {
        self.goto_indices.push(target);
    }
}

/// A list block (ordered sequence of blocks).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockList {
    pub graph: BlockGraph,
}

impl BlockList {
    pub fn new(index: u32) -> Self {
        Self {
            graph: BlockGraph::new(index),
        }
    }
}

/// A condition block (two-way conditional branching).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockCondition {
    pub block: PcodeBlock,
    /// The index of the condition expression block (or op).
    pub cond_index: u32,
}

impl BlockCondition {
    pub fn new(index: u32, cond_index: u32) -> Self {
        Self {
            block: PcodeBlock::new(BlockType::Condition, index),
            cond_index,
        }
    }
}

/// A copy block (alias for plain -- used internally by the decompiler).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockCopy {
    pub block: PcodeBlock,
}

impl BlockCopy {
    pub fn new(index: u32) -> Self {
        Self {
            block: PcodeBlock::new(BlockType::Copy, index),
        }
    }
}

/// A proper if block (if-then without else).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProperIf {
    pub graph: BlockGraph,
}

impl BlockProperIf {
    pub fn new(index: u32) -> Self {
        Self {
            graph: BlockGraph::new(index),
        }
    }
}

/// An if-else block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockIfElse {
    pub graph: BlockGraph,
}

impl BlockIfElse {
    pub fn new(index: u32) -> Self {
        Self {
            graph: BlockGraph::new(index),
        }
    }
}

/// An if-goto block (conditional jump out of a structured block).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockIfGoto {
    pub block: PcodeBlock,
}

impl BlockIfGoto {
    pub fn new(index: u32) -> Self {
        Self {
            block: PcodeBlock::new(BlockType::IfGoto, index),
        }
    }
}

/// A while-do loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockWhileDo {
    pub graph: BlockGraph,
}

impl BlockWhileDo {
    pub fn new(index: u32) -> Self {
        Self {
            graph: BlockGraph::new(index),
        }
    }
}

/// A do-while loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockDoWhile {
    pub graph: BlockGraph,
}

impl BlockDoWhile {
    pub fn new(index: u32) -> Self {
        Self {
            graph: BlockGraph::new(index),
        }
    }
}

/// A switch block (multi-way branch).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockSwitch {
    pub graph: BlockGraph,
}

impl BlockSwitch {
    pub fn new(index: u32) -> Self {
        Self {
            graph: BlockGraph::new(index),
        }
    }
}

/// An infinite loop block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockInfLoop {
    pub graph: BlockGraph,
}

impl BlockInfLoop {
    pub fn new(index: u32) -> Self {
        Self {
            graph: BlockGraph::new(index),
        }
    }
}

/// Block map for building a block graph from decoder output.
///
/// Corresponds to Ghidra's `BlockMap`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockMap {
    /// Sorted list of blocks by index.
    pub sort_list: Vec<u32>,
    /// Leaf blocks (basic blocks with no children).
    pub leaf_list: Vec<u32>,
    /// Goto references to resolve after building.
    pub goto_refs: Vec<BlockEdge>,
}

impl BlockMap {
    /// Create a new empty block map.
    pub fn new() -> Self {
        Self {
            sort_list: Vec::new(),
            leaf_list: Vec::new(),
            goto_refs: Vec::new(),
        }
    }

    /// Add a block index to the sorted list.
    pub fn add_block(&mut self, index: u32) {
        self.sort_list.push(index);
    }

    /// Add a leaf block index.
    pub fn add_leaf(&mut self, index: u32) {
        self.leaf_list.push(index);
    }

    /// Add a goto reference for later resolution.
    pub fn add_goto_ref(&mut self, goto: BlockEdge) {
        self.goto_refs.push(goto);
    }
}

impl Default for BlockMap {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_type_from_id_roundtrip() {
        for id in 0..=14u16 {
            let bt = BlockType::from_id(id).unwrap();
            assert_eq!(bt.id(), id);
        }
        assert!(BlockType::from_id(15).is_none());
    }

    #[test]
    fn test_block_type_name() {
        assert_eq!(BlockType::Basic.name(), "basic");
        assert_eq!(BlockType::WhileDo.name(), "whiledo");
        assert_eq!(BlockType::Switch.name(), "switch");
    }

    #[test]
    fn test_block_edge_labels() {
        let e = BlockEdge::new(5, 0);
        assert!(e.is_fallthrough());
        assert!(!e.is_true_branch());
        let e2 = BlockEdge::new(6, 1);
        assert!(e2.is_true_branch());
        let e3 = BlockEdge::new(7, 2);
        assert!(e3.is_false_branch());
    }

    #[test]
    fn test_pcode_block_creation() {
        let mut b = PcodeBlock::basic(0, Address::new(0x1000), Address::new(0x1010));
        assert_eq!(b.get_block_type(), BlockType::Basic);
        assert_eq!(b.get_start(), Address::new(0x1000));
        assert_eq!(b.get_stop(), Address::new(0x1010));
        assert_eq!(b.get_in_size(), 0);
        assert_eq!(b.get_out_size(), 0);

        b.add_incoming(BlockEdge::new(1, 0));
        b.add_outgoing(BlockEdge::new(2, 0));
        assert_eq!(b.get_in_size(), 1);
        assert_eq!(b.get_out_size(), 1);
        assert!(b.contains_outgoing(2));
        assert!(b.contains_incoming(1));
        assert!(!b.contains_outgoing(3));
    }

    #[test]
    fn test_pcode_block_parent() {
        let mut b = PcodeBlock::new(BlockType::Basic, 0);
        assert!(b.get_parent_index().is_none());
        b.set_parent(5);
        assert_eq!(b.get_parent_index(), Some(5));
    }

    #[test]
    fn test_pcode_block_display() {
        let b = PcodeBlock::basic(3, Address::new(0x401000), Address::new(0x401020));
        let s = format!("{}", b);
        assert!(s.contains("basic"));
        assert!(s.contains("3"));
    }

    #[test]
    fn test_pcode_block_basic_ops() {
        let mut bb = PcodeBlockBasic::new(0);
        bb.add_op(10);
        bb.add_op(11);
        bb.add_op(12);
        assert_eq!(bb.num_ops(), 3);
        assert_eq!(bb.get_op_indices(), &[10, 11, 12]);
    }

    #[test]
    fn test_block_graph() {
        let mut g = BlockGraph::new(0);
        g.add_child(1);
        g.add_child(2);
        assert_eq!(g.num_blocks(), 2);
    }

    #[test]
    fn test_block_goto() {
        let bg = BlockGoto::new(0, 5);
        assert_eq!(bg.goto_index, 5);
    }

    #[test]
    fn test_block_multi_goto() {
        let mut bg = BlockMultiGoto::new(0);
        bg.add_goto(1);
        bg.add_goto(2);
        bg.add_goto(3);
        assert_eq!(bg.goto_indices.len(), 3);
    }

    #[test]
    fn test_structured_blocks() {
        let _ = BlockCondition::new(0, 1);
        let _ = BlockCopy::new(0);
        let _ = BlockProperIf::new(0);
        let _ = BlockIfElse::new(0);
        let _ = BlockIfGoto::new(0);
        let _ = BlockWhileDo::new(0);
        let _ = BlockDoWhile::new(0);
        let _ = BlockSwitch::new(0);
        let _ = BlockInfLoop::new(0);
        let _ = BlockList::new(0);
    }

    #[test]
    fn test_block_map() {
        let mut bm = BlockMap::new();
        bm.add_block(0);
        bm.add_block(1);
        bm.add_leaf(2);
        bm.add_goto_ref(BlockEdge::new(3, 0));
        assert_eq!(bm.sort_list.len(), 2);
        assert_eq!(bm.leaf_list.len(), 1);
        assert_eq!(bm.goto_refs.len(), 1);
    }
}
