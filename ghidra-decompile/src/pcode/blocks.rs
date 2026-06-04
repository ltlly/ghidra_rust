//! Structured control-flow block types for the decompiler.
//!
//! Ports Ghidra's `PcodeBlock`, `PcodeBlockBasic`, `BlockGraph`,
//! `BlockCondition`, `BlockCopy`, `BlockDoWhile`, `BlockGoto`,
//! `BlockIfElse`, `BlockIfGoto`, `BlockInfLoop`, `BlockList`,
//! `BlockMultiGoto`, `BlockProperIf`, `BlockSwitch`, `BlockWhileDo`,
//! and `BlockMap`.
//!
//! These types represent the hierarchical structured control-flow graph
//! produced by the decompiler's control-flow structuring algorithm.

use ghidra_core::addr::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// BlockType enum
// ============================================================================

/// Types of structured control-flow blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BlockType {
    /// Plain block (unstructured).
    Plain = 0,
    /// Basic block (straight-line code).
    Basic = 1,
    /// Block graph (container for other blocks).
    Graph = 2,
    /// Copy of a basic block (used during structuring).
    Copy = 3,
    /// Goto (unconditional jump to a label).
    Goto = 4,
    /// Multi-goto (switch-like dispatch).
    MultiGoto = 5,
    /// List of sequential blocks.
    List = 6,
    /// Condition block (if-then).
    Condition = 7,
    /// Proper if (if-then without else).
    ProperIf = 8,
    /// If-else block.
    IfElse = 9,
    /// If with goto.
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
    /// Convert a block type to its string name.
    pub fn to_name(self) -> &'static str {
        match self {
            BlockType::Plain => "plain",
            BlockType::Basic => "basic",
            BlockType::Graph => "graph",
            BlockType::Copy => "plain", // trick for decompiler c-side
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

    /// Parse a block type from a string name.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "plain" => Some(BlockType::Plain),
            "basic" => Some(BlockType::Basic),
            "graph" => Some(BlockType::Graph),
            "goto" => Some(BlockType::Goto),
            "multigoto" => Some(BlockType::MultiGoto),
            "list" => Some(BlockType::List),
            "condition" => Some(BlockType::Condition),
            "properif" => Some(BlockType::ProperIf),
            "ifelse" => Some(BlockType::IfElse),
            "ifgoto" => Some(BlockType::IfGoto),
            "whiledo" => Some(BlockType::WhileDo),
            "dowhile" => Some(BlockType::DoWhile),
            "switch" => Some(BlockType::Switch),
            "infloop" => Some(BlockType::InfLoop),
            _ => None,
        }
    }
}

// ============================================================================
// BlockEdge
// ============================================================================

/// An edge between two structured blocks.
#[derive(Debug, Clone)]
pub struct BlockEdge {
    /// Label of this edge.
    pub label: i32,
    /// Index of the destination block in the graph's block list.
    pub target_index: i32,
    /// Reverse index: the index of the reverse edge in the target's edge list.
    pub reverse_index: i32,
}

impl BlockEdge {
    /// Create a new block edge.
    pub fn new(target_index: i32, label: i32, reverse_index: i32) -> Self {
        Self {
            label,
            target_index,
            reverse_index,
        }
    }
}

// ============================================================================
// PcodeBlock
// ============================================================================

/// A structured control-flow block.
///
/// This is the base type for all structured blocks. It contains edges
/// flowing into and out of the block, an index, and a type tag.
#[derive(Debug, Clone)]
pub struct PcodeBlock {
    /// The block index.
    pub index: i32,
    /// The type of this block.
    pub block_type: BlockType,
    /// Index of the parent block (-1 if none).
    pub parent_index: Option<i32>,
    /// Edges flowing into this block.
    pub in_edges: Vec<BlockEdge>,
    /// Edges flowing out of this block.
    pub out_edges: Vec<BlockEdge>,
    /// Start address of the block.
    pub start_address: Option<Address>,
    /// End address of the block.
    pub end_address: Option<Address>,
    /// The sub-blocks (for BlockGraph, BlockList, etc.).
    pub sub_blocks: Vec<i32>,
}

impl PcodeBlock {
    /// Create a new PcodeBlock.
    pub fn new(index: i32, block_type: BlockType) -> Self {
        Self {
            index,
            block_type,
            parent_index: None,
            in_edges: Vec::new(),
            out_edges: Vec::new(),
            start_address: None,
            end_address: None,
            sub_blocks: Vec::new(),
        }
    }

    /// Get the block type.
    pub fn get_type(&self) -> BlockType {
        self.block_type
    }

    /// Get the block index.
    pub fn get_index(&self) -> i32 {
        self.index
    }

    /// Set the block index.
    pub fn set_index(&mut self, i: i32) {
        self.index = i;
    }

    /// Get the parent block index.
    pub fn get_parent_index(&self) -> Option<i32> {
        self.parent_index
    }

    /// Get the start address.
    pub fn get_start(&self) -> Option<Address> {
        self.start_address
    }

    /// Get the end address.
    pub fn get_stop(&self) -> Option<Address> {
        self.end_address
    }

    /// Add an incoming edge.
    pub fn add_in_edge(&mut self, from_index: i32, label: i32) {
        let rev = self.out_edges.len() as i32;
        self.in_edges.push(BlockEdge::new(from_index, label, rev));
    }

    /// Add an outgoing edge.
    pub fn add_out_edge(&mut self, to_index: i32, label: i32) {
        let rev = self.in_edges.len() as i32;
        self.out_edges.push(BlockEdge::new(to_index, label, rev));
    }

    /// Get the i-th incoming block index.
    pub fn get_in(&self, i: usize) -> Option<i32> {
        self.in_edges.get(i).map(|e| e.target_index)
    }

    /// Get the i-th outgoing block index.
    pub fn get_out(&self, i: usize) -> Option<i32> {
        self.out_edges.get(i).map(|e| e.target_index)
    }

    /// Get the number of incoming edges.
    pub fn get_in_size(&self) -> usize {
        self.in_edges.len()
    }

    /// Get the number of outgoing edges.
    pub fn get_out_size(&self) -> usize {
        self.out_edges.len()
    }

    /// Assuming a conditional branch, get the "false" outgoing block index.
    pub fn get_false_out(&self) -> Option<i32> {
        self.out_edges.first().map(|e| e.target_index)
    }

    /// Assuming a conditional branch, get the "true" outgoing block index.
    pub fn get_true_out(&self) -> Option<i32> {
        self.out_edges.get(1).map(|e| e.target_index)
    }

    /// Get the reverse index for the i-th outgoing edge.
    pub fn get_out_rev_index(&self, i: usize) -> Option<i32> {
        self.out_edges.get(i).map(|e| e.reverse_index)
    }

    /// Get the reverse index for the i-th incoming edge.
    pub fn get_in_rev_index(&self, i: usize) -> Option<i32> {
        self.in_edges.get(i).map(|e| e.reverse_index)
    }

    /// Returns true if this block is a leaf (no sub-blocks).
    pub fn is_leaf(&self) -> bool {
        self.sub_blocks.is_empty()
    }

    /// Returns the type name as a string.
    pub fn type_name(&self) -> &'static str {
        self.block_type.to_name()
    }
}

// ============================================================================
// PcodeBlockBasic - a basic block with P-code operations
// ============================================================================

/// A basic block constructed from P-code operations.
///
/// Contains a list of operation indices and an address cover.
#[derive(Debug, Clone)]
pub struct PcodeBlockBasic {
    /// The base block.
    pub base: PcodeBlock,
    /// Address ranges covered by this block (min_offset, max_offset pairs).
    pub address_ranges: Vec<(u64, u64)>,
    /// Indices of operations in this block (into the function's op list).
    pub op_indices: Vec<usize>,
}

impl PcodeBlockBasic {
    /// Create a new basic block.
    pub fn new(index: i32) -> Self {
        let mut base = PcodeBlock::new(index, BlockType::Basic);
        base.start_address = None;
        base.end_address = None;
        Self {
            base,
            address_ranges: Vec::new(),
            op_indices: Vec::new(),
        }
    }

    /// Add an address range to the block's cover.
    pub fn add_range(&mut self, min: Address, max: Address) {
        self.address_ranges.push((min.offset, max.offset));
        // Update start/end
        if self.base.start_address.is_none()
            || min.offset < self.base.start_address.unwrap().offset
        {
            self.base.start_address = Some(min);
        }
        if self.base.end_address.is_none()
            || max.offset > self.base.end_address.unwrap().offset
        {
            self.base.end_address = Some(max);
        }
    }

    /// Add an operation index to this block.
    pub fn add_op(&mut self, index: usize) {
        self.op_indices.push(index);
    }

    /// Returns true if the block contains the given address.
    pub fn contains(&self, addr: Address) -> bool {
        self.address_ranges
            .iter()
            .any(|&(min, max)| addr.offset >= min && addr.offset <= max)
    }

    /// Get the first operation index, if any.
    pub fn get_first_op_index(&self) -> Option<usize> {
        self.op_indices.first().copied()
    }

    /// Get the last operation index, if any.
    pub fn get_last_op_index(&self) -> Option<usize> {
        self.op_indices.last().copied()
    }

    /// Get the number of operations in this block.
    pub fn op_count(&self) -> usize {
        self.op_indices.len()
    }
}

// ============================================================================
// BlockGraph - container for sub-blocks
// ============================================================================

/// A block that contains other blocks (a structured region).
#[derive(Debug, Clone)]
pub struct BlockGraph {
    /// The base block.
    pub base: PcodeBlock,
    /// Maximum index among contained blocks.
    pub max_index: i32,
}

impl BlockGraph {
    /// Create a new block graph.
    pub fn new() -> Self {
        let mut base = PcodeBlock::new(-1, BlockType::Graph);
        base.start_address = None;
        base.end_address = None;
        Self {
            base,
            max_index: -1,
        }
    }

    /// Add a sub-block index.
    pub fn add_block(&mut self, block_index: i32) {
        if self.base.sub_blocks.is_empty() {
            self.base.index = block_index;
            self.max_index = block_index;
        } else {
            if block_index < self.base.index {
                self.base.index = block_index;
            }
            if block_index > self.max_index {
                self.max_index = block_index;
            }
        }
        self.base.sub_blocks.push(block_index);
    }

    /// Get the number of sub-blocks.
    pub fn get_size(&self) -> usize {
        self.base.sub_blocks.len()
    }

    /// Get the i-th sub-block index.
    pub fn get_block(&self, i: usize) -> Option<i32> {
        self.base.sub_blocks.get(i).copied()
    }

    /// Add a directed edge between two blocks in this container.
    pub fn add_edge(&mut self, begin: i32, end: i32) {
        // Edge is recorded in the child blocks, not in the graph itself
        // This is a placeholder; actual edge building uses the block pool
        let _ = (begin, end);
    }
}

impl Default for BlockGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// BlockCondition - conditional block (if-then)
// ============================================================================

/// A condition block: represents an if-then structure.
#[derive(Debug, Clone)]
pub struct BlockCondition {
    /// The base block.
    pub base: PcodeBlock,
}

impl BlockCondition {
    /// Create a new condition block.
    pub fn new(index: i32) -> Self {
        Self {
            base: PcodeBlock::new(index, BlockType::Condition),
        }
    }
}

// ============================================================================
// BlockCopy - a copy of a basic block
// ============================================================================

/// A copy of a basic block, used during control-flow structuring.
#[derive(Debug, Clone)]
pub struct BlockCopy {
    /// The base block.
    pub base: PcodeBlock,
    /// The alternate index (references the original block).
    pub alt_index: i32,
    /// Reference object (optional opaque reference).
    pub reference: Option<usize>,
}

impl BlockCopy {
    /// Create a new block copy.
    pub fn new(index: i32, alt_index: i32) -> Self {
        Self {
            base: PcodeBlock::new(index, BlockType::Copy),
            alt_index,
            reference: None,
        }
    }

    /// Get the alternate index.
    pub fn get_alt_index(&self) -> i32 {
        self.alt_index
    }

    /// Set the reference and address.
    pub fn set(&mut self, reference: Option<usize>, address: Option<Address>) {
        self.reference = reference;
        self.base.start_address = address;
    }

    /// Get the reference.
    pub fn get_ref(&self) -> Option<usize> {
        self.reference
    }
}

// ============================================================================
// BlockGoto - goto block
// ============================================================================

/// A goto block: an unconditional jump to a target.
#[derive(Debug, Clone)]
pub struct BlockGoto {
    /// The base block.
    pub base: PcodeBlock,
    /// Index of the goto target block.
    pub goto_target: Option<i32>,
    /// The depth of the goto (how far up the nesting).
    pub depth: i32,
}

impl BlockGoto {
    /// Create a new goto block.
    pub fn new(index: i32) -> Self {
        Self {
            base: PcodeBlock::new(index, BlockType::Goto),
            goto_target: None,
            depth: 0,
        }
    }

    /// Set the goto target.
    pub fn set_goto_target(&mut self, target: i32) {
        self.goto_target = Some(target);
    }

    /// Get the goto target.
    pub fn get_goto_target(&self) -> Option<i32> {
        self.goto_target
    }
}

// ============================================================================
// BlockIfGoto - if-goto block
// ============================================================================

/// An if-goto block: a conditional jump to a target.
#[derive(Debug, Clone)]
pub struct BlockIfGoto {
    /// The base block.
    pub base: PcodeBlock,
    /// Index of the goto target block.
    pub goto_target: Option<i32>,
    /// The depth of the goto.
    pub depth: i32,
}

impl BlockIfGoto {
    /// Create a new if-goto block.
    pub fn new(index: i32) -> Self {
        Self {
            base: PcodeBlock::new(index, BlockType::IfGoto),
            goto_target: None,
            depth: 0,
        }
    }

    /// Set the goto target.
    pub fn set_goto_target(&mut self, target: i32) {
        self.goto_target = Some(target);
    }

    /// Get the goto target.
    pub fn get_goto_target(&self) -> Option<i32> {
        self.goto_target
    }
}

// ============================================================================
// BlockMultiGoto - multi-destination goto
// ============================================================================

/// A multi-goto block: dispatches to multiple targets.
#[derive(Debug, Clone)]
pub struct BlockMultiGoto {
    /// The base block.
    pub base: PcodeBlock,
    /// Target block indices.
    pub targets: Vec<i32>,
}

impl BlockMultiGoto {
    /// Create a new multi-goto block.
    pub fn new(index: i32) -> Self {
        Self {
            base: PcodeBlock::new(index, BlockType::MultiGoto),
            targets: Vec::new(),
        }
    }

    /// Add a target block.
    pub fn add_block(&mut self, target: i32) {
        self.targets.push(target);
    }

    /// Get the targets.
    pub fn get_targets(&self) -> &[i32] {
        &self.targets
    }
}

// ============================================================================
// BlockProperIf - if-then block
// ============================================================================

/// A proper if block: if-then without else.
#[derive(Debug, Clone)]
pub struct BlockProperIf {
    /// The base block.
    pub base: PcodeBlock,
}

impl BlockProperIf {
    /// Create a new proper if block.
    pub fn new(index: i32) -> Self {
        Self {
            base: PcodeBlock::new(index, BlockType::ProperIf),
        }
    }
}

// ============================================================================
// BlockIfElse - if-then-else block
// ============================================================================

/// An if-else block.
#[derive(Debug, Clone)]
pub struct BlockIfElse {
    /// The base block.
    pub base: PcodeBlock,
}

impl BlockIfElse {
    /// Create a new if-else block.
    pub fn new(index: i32) -> Self {
        Self {
            base: PcodeBlock::new(index, BlockType::IfElse),
        }
    }
}

// ============================================================================
// BlockWhileDo - while-do loop
// ============================================================================

/// A while-do loop block.
#[derive(Debug, Clone)]
pub struct BlockWhileDo {
    /// The base block.
    pub base: PcodeBlock,
}

impl BlockWhileDo {
    /// Create a new while-do block.
    pub fn new(index: i32) -> Self {
        Self {
            base: PcodeBlock::new(index, BlockType::WhileDo),
        }
    }
}

// ============================================================================
// BlockDoWhile - do-while loop
// ============================================================================

/// A do-while loop block.
#[derive(Debug, Clone)]
pub struct BlockDoWhile {
    /// The base block.
    pub base: PcodeBlock,
}

impl BlockDoWhile {
    /// Create a new do-while block.
    pub fn new(index: i32) -> Self {
        Self {
            base: PcodeBlock::new(index, BlockType::DoWhile),
        }
    }
}

// ============================================================================
// BlockSwitch - switch block
// ============================================================================

/// A switch block.
#[derive(Debug, Clone)]
pub struct BlockSwitch {
    /// The base block.
    pub base: PcodeBlock,
}

impl BlockSwitch {
    /// Create a new switch block.
    pub fn new(index: i32) -> Self {
        Self {
            base: PcodeBlock::new(index, BlockType::Switch),
        }
    }
}

// ============================================================================
// BlockInfLoop - infinite loop
// ============================================================================

/// An infinite loop block.
#[derive(Debug, Clone)]
pub struct BlockInfLoop {
    /// The base block.
    pub base: PcodeBlock,
}

impl BlockInfLoop {
    /// Create a new infinite loop block.
    pub fn new(index: i32) -> Self {
        Self {
            base: PcodeBlock::new(index, BlockType::InfLoop),
        }
    }
}

// ============================================================================
// BlockList - list of sequential blocks
// ============================================================================

/// A list block: a sequence of sub-blocks.
#[derive(Debug, Clone)]
pub struct BlockList {
    /// The base block.
    pub base: PcodeBlock,
}

impl BlockList {
    /// Create a new list block.
    pub fn new(index: i32) -> Self {
        Self {
            base: PcodeBlock::new(index, BlockType::List),
        }
    }
}

// ============================================================================
// BlockMap - resolver for block indices during deserialization
// ============================================================================

/// A mapping structure used during block deserialization to resolve
/// block indices to block objects.
#[derive(Debug, Clone)]
pub struct BlockMap {
    /// All blocks, indexed by their index.
    pub blocks: HashMap<i32, PcodeBlock>,
    /// Leaf blocks (blocks with no sub-blocks).
    pub leaf_list: Vec<i32>,
    /// Goto references to resolve.
    pub goto_refs: Vec<GotoReference>,
}

/// A goto reference to be resolved after deserialization.
#[derive(Debug, Clone)]
pub struct GotoReference {
    /// Index of the goto block.
    pub goto_block: i32,
    /// Root index of the target.
    pub root_index: i32,
    /// Nesting depth.
    pub depth: i32,
}

impl BlockMap {
    /// Create a new empty block map.
    pub fn new() -> Self {
        Self {
            blocks: HashMap::new(),
            leaf_list: Vec::new(),
            goto_refs: Vec::new(),
        }
    }

    /// Add a block to the map.
    pub fn add_block(&mut self, block: PcodeBlock) {
        let idx = block.index;
        if block.sub_blocks.is_empty() {
            self.leaf_list.push(idx);
        }
        self.blocks.insert(idx, block);
    }

    /// Find a block by its level index.
    pub fn find_level_block(&self, index: i32) -> Option<&PcodeBlock> {
        self.blocks.get(&index)
    }

    /// Create a block of the given type and index.
    pub fn create_block(&mut self, type_name: &str, index: i32) -> PcodeBlock {
        let block_type = BlockType::from_name(type_name).unwrap_or(BlockType::Plain);
        let block = PcodeBlock::new(index, block_type);
        block
    }

    /// Add a goto reference.
    pub fn add_goto_ref(&mut self, goto_block: i32, root_index: i32, depth: i32) {
        self.goto_refs.push(GotoReference {
            goto_block,
            root_index,
            depth,
        });
    }

    /// Resolve all goto references.
    pub fn resolve_goto_references(&mut self) {
        // Sort leaf list by index for binary search
        self.leaf_list.sort();
        // Goto resolution requires block type introspection;
        // in the Rust port this is handled at a higher level.
    }

    /// Sort the level list.
    pub fn sort_level_list(&mut self) {
        self.leaf_list.sort();
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
    fn test_block_type_from_to_name() {
        for bt in &[
            BlockType::Plain,
            BlockType::Basic,
            BlockType::Graph,
            BlockType::Goto,
            BlockType::List,
            BlockType::Condition,
            BlockType::ProperIf,
            BlockType::IfElse,
            BlockType::WhileDo,
            BlockType::DoWhile,
            BlockType::Switch,
            BlockType::InfLoop,
        ] {
            let name = bt.to_name();
            let parsed = BlockType::from_name(name);
            assert_eq!(parsed, Some(*bt), "roundtrip failed for {:?}", bt);
        }
    }

    #[test]
    fn test_pcode_block_basic() {
        let mut block = PcodeBlock::new(0, BlockType::Basic);
        assert_eq!(block.get_index(), 0);
        assert_eq!(block.get_type(), BlockType::Basic);
        assert!(block.is_leaf());
    }

    #[test]
    fn test_pcode_block_edges() {
        let mut block = PcodeBlock::new(0, BlockType::Basic);
        block.add_in_edge(1, 0);
        block.add_in_edge(2, 0);
        assert_eq!(block.get_in_size(), 2);
        assert_eq!(block.get_in(0), Some(1));
        assert_eq!(block.get_in(1), Some(2));
    }

    #[test]
    fn test_pcode_block_out_edges() {
        let mut block = PcodeBlock::new(0, BlockType::Basic);
        block.add_out_edge(1, 0);
        block.add_out_edge(2, 1);
        assert_eq!(block.get_out_size(), 2);
        assert_eq!(block.get_false_out(), Some(1));
        assert_eq!(block.get_true_out(), Some(2));
    }

    #[test]
    fn test_pcode_block_basic_ops() {
        let mut bb = PcodeBlockBasic::new(0);
        bb.add_op(0);
        bb.add_op(1);
        bb.add_op(2);
        assert_eq!(bb.op_count(), 3);
        assert_eq!(bb.get_first_op_index(), Some(0));
        assert_eq!(bb.get_last_op_index(), Some(2));
    }

    #[test]
    fn test_pcode_block_basic_address() {
        let mut bb = PcodeBlockBasic::new(0);
        bb.add_range(Address::new(0x1000), Address::new(0x1010));
        assert!(bb.contains(Address::new(0x1008)));
        assert!(!bb.contains(Address::new(0x2000)));
        assert_eq!(bb.base.start_address, Some(Address::new(0x1000)));
        assert_eq!(bb.base.end_address, Some(Address::new(0x1010)));
    }

    #[test]
    fn test_block_graph() {
        let mut graph = BlockGraph::new();
        graph.add_block(0);
        graph.add_block(1);
        graph.add_block(2);
        assert_eq!(graph.get_size(), 3);
        assert_eq!(graph.base.index, 0);
        assert_eq!(graph.max_index, 2);
    }

    #[test]
    fn test_block_goto() {
        let mut goto = BlockGoto::new(5);
        goto.set_goto_target(3);
        assert_eq!(goto.get_goto_target(), Some(3));
        assert_eq!(goto.base.block_type, BlockType::Goto);
    }

    #[test]
    fn test_block_if_goto() {
        let mut ig = BlockIfGoto::new(5);
        ig.set_goto_target(10);
        assert_eq!(ig.get_goto_target(), Some(10));
    }

    #[test]
    fn test_block_multi_goto() {
        let mut mg = BlockMultiGoto::new(0);
        mg.add_block(1);
        mg.add_block(2);
        mg.add_block(3);
        assert_eq!(mg.get_targets().len(), 3);
    }

    #[test]
    fn test_block_copy() {
        let mut copy = BlockCopy::new(5, 3);
        assert_eq!(copy.get_alt_index(), 3);
        copy.set(Some(42), Some(Address::new(0x1000)));
        assert_eq!(copy.get_ref(), Some(42));
    }

    #[test]
    fn test_block_map() {
        let mut map = BlockMap::new();
        map.add_block(PcodeBlock::new(0, BlockType::Basic));
        map.add_block(PcodeBlock::new(1, BlockType::Basic));
        map.add_block(PcodeBlock::new(2, BlockType::Goto));
        assert!(map.find_level_block(0).is_some());
        assert!(map.find_level_block(99).is_none());
        assert_eq!(map.leaf_list.len(), 3);
    }

    #[test]
    fn test_block_map_goto_refs() {
        let mut map = BlockMap::new();
        map.add_goto_ref(5, 3, 1);
        map.add_goto_ref(6, 2, 0);
        assert_eq!(map.goto_refs.len(), 2);
    }

    #[test]
    fn test_block_condition() {
        let bc = BlockCondition::new(0);
        assert_eq!(bc.base.block_type, BlockType::Condition);
    }

    #[test]
    fn test_block_while_do() {
        let bw = BlockWhileDo::new(0);
        assert_eq!(bw.base.block_type, BlockType::WhileDo);
    }

    #[test]
    fn test_block_do_while() {
        let bd = BlockDoWhile::new(0);
        assert_eq!(bd.base.block_type, BlockType::DoWhile);
    }

    #[test]
    fn test_block_switch() {
        let bs = BlockSwitch::new(0);
        assert_eq!(bs.base.block_type, BlockType::Switch);
    }

    #[test]
    fn test_block_inf_loop() {
        let bi = BlockInfLoop::new(0);
        assert_eq!(bi.base.block_type, BlockType::InfLoop);
    }

    #[test]
    fn test_block_list() {
        let bl = BlockList::new(0);
        assert_eq!(bl.base.block_type, BlockType::List);
    }

    #[test]
    fn test_block_proper_if() {
        let bp = BlockProperIf::new(0);
        assert_eq!(bp.base.block_type, BlockType::ProperIf);
    }

    #[test]
    fn test_block_if_else() {
        let be = BlockIfElse::new(0);
        assert_eq!(be.base.block_type, BlockType::IfElse);
    }
}
