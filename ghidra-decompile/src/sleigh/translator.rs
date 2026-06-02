//! SLEIGH instruction translator: byte patterns to P-code.
//!
//! The translator is the bridge between raw instruction bytes and the P-code
//! intermediate representation. It walks the parse tree produced by pattern
//! matching, extracts operand values, and instantiates constructor templates.
//!
//! # Key Types
//! - [`TranslateEngine`] - Orchestrates translation of bytes to P-code
//! - [`ParserContext`] - Mutable state during parsing of one instruction
//! - [`ParserWalker`] - Stateful walker for traversing the parse tree
//! - [`ParseTree`] - The tree of matched constructors for an instruction
//! - [`ParseNode`] - A single node in the parse tree (one matched constructor)

use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;

use super::construct::OperandVal;
use super::context::ContextDatabase;
use super::pcode::{OpCode, PcodeOp};
use super::sleigh::{DisassemblyResult, FlowState, SleighContext, SleighEngine};

// ---------------------------------------------------------------------------
// ParseNode
// ---------------------------------------------------------------------------

/// A single node in the parse tree, representing one matched constructor.
///
/// When a constructor matches, it becomes a `ParseNode`. If the constructor
/// references sub-tables, those become child nodes. The tree captures the
/// full hierarchical decoding of an instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseNode {
    /// The ID of the constructor that matched at this node
    pub constructor_id: usize,
    /// Indices of child nodes (sub-table matches) in the parse tree's node list
    pub children: Vec<usize>,
    /// Resolved operand values for this constructor
    pub operands: Vec<OperandVal>,
    /// Starting address of this instruction fragment
    pub addr_start: u64,
    /// Ending address (addr_start + length)
    pub addr_end: u64,
    /// The P-code operations emitted by this node's template
    pub pcode_ops: Vec<PcodeOp>,
    /// Whether this node was successfully resolved
    pub resolved: bool,
}

impl ParseNode {
    /// Create a new parse node for a given constructor at a given address.
    pub fn new(constructor_id: usize, addr_start: u64, length: usize) -> Self {
        Self {
            constructor_id,
            children: Vec::new(),
            operands: Vec::new(),
            addr_start,
            addr_end: addr_start + length as u64,
            pcode_ops: Vec::new(),
            resolved: false,
        }
    }

    /// Returns the instruction length in bytes.
    pub fn length(&self) -> usize {
        (self.addr_end - self.addr_start) as usize
    }

    /// Add a child node index.
    pub fn add_child(&mut self, child_idx: usize) {
        self.children.push(child_idx);
    }

    /// Returns `true` if this is a leaf node (no children).
    pub fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }
}

// ---------------------------------------------------------------------------
// ParseTree
// ---------------------------------------------------------------------------

/// The complete parse tree for a successfully disassembled instruction.
///
/// The parse tree captures the hierarchical resolution of constructors.
/// For simple instructions with no sub-tables, the tree has a single node.
/// For complex instructions (e.g., ARM with coprocessor-dependent encoding),
/// the tree may have multiple levels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseTree {
    /// All nodes in the tree (root is at index 0 if present)
    pub nodes: Vec<ParseNode>,
    /// Index of the root node, if any
    pub root: Option<usize>,
    /// Total instruction length in bytes
    pub total_length: usize,
}

impl ParseTree {
    /// Create an empty parse tree.
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            root: None,
            total_length: 0,
        }
    }

    /// Create a single-node parse tree for a simple instruction.
    pub fn single_node(node: ParseNode) -> Self {
        let length = node.length();
        Self {
            nodes: vec![node],
            root: Some(0),
            total_length: length,
        }
    }

    /// Add a node and return its index.
    pub fn add_node(&mut self, node: ParseNode) -> usize {
        let idx = self.nodes.len();
        self.nodes.push(node);
        if self.root.is_none() {
            self.root = Some(idx);
        }
        idx
    }

    /// Get a node by index.
    pub fn get_node(&self, idx: usize) -> Option<&ParseNode> {
        self.nodes.get(idx)
    }

    /// Get the root node.
    pub fn root_node(&self) -> Option<&ParseNode> {
        self.root.and_then(|idx| self.nodes.get(idx))
    }

    /// Returns all P-code operations from all nodes, in tree order.
    pub fn collect_pcode_ops(&self) -> Vec<PcodeOp> {
        let mut ops = Vec::new();
        if let Some(root_idx) = self.root {
            self.collect_pcode_from(root_idx, &mut ops);
        }
        ops
    }

    fn collect_pcode_from(&self, node_idx: usize, ops: &mut Vec<PcodeOp>) {
        if let Some(node) = self.nodes.get(node_idx) {
            for op in &node.pcode_ops {
                ops.push(op.clone());
            }
            for &child_idx in &node.children {
                self.collect_pcode_from(child_idx, ops);
            }
        }
    }

    /// Returns the number of nodes in the tree.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Returns `true` if the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

impl Default for ParseTree {
    fn default() -> Self {
        Self::new()
    }
}

impl ParseTree {
    /// Format this parse tree as an indented tree for debugging.
    pub fn format_tree(&self, f: &mut fmt::Formatter<'_>, depth: usize) -> fmt::Result {
        if let Some(root_idx) = self.root {
            self.display_node(root_idx, f, depth)
        } else {
            write!(f, "<empty parse tree>")
        }
    }

    fn display_node(
        &self,
        node_idx: usize,
        f: &mut fmt::Formatter<'_>,
        depth: usize,
    ) -> fmt::Result {
        let indent = "  ".repeat(depth);
        if let Some(node) = self.nodes.get(node_idx) {
            writeln!(
                f,
                "{}ctor#{} @ 0x{:x}-0x{:x} ({} ops, {} children)",
                indent,
                node.constructor_id,
                node.addr_start,
                node.addr_end,
                node.pcode_ops.len(),
                node.children.len()
            )?;
            for &child_idx in &node.children {
                self.display_node(child_idx, f, depth + 1)?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ParserContext
// ---------------------------------------------------------------------------

/// Mutable state for parsing a single instruction.
///
/// `ParserContext` holds the raw bytes, the address, the context snapshot,
/// and accumulates the matched constructors during the disassembly of one
/// instruction.
#[derive(Debug, Clone)]
pub struct ParserContext {
    /// Address of the instruction being parsed
    pub addr: u64,
    /// Raw instruction bytes
    pub bytes: Vec<u8>,
    /// Current byte position within the instruction
    pub pos: usize,
    /// Context state at this instruction's address
    pub context: SleighContext,
    /// Constructor IDs that matched (in matching order)
    pub matched_constructors: Vec<usize>,
    /// Extracted operand values, indexed by operand slot
    pub operands: Vec<OperandVal>,
    /// Number of bytes consumed so far
    pub consumed: usize,
    /// Whether parsing is complete
    pub complete: bool,
}

impl ParserContext {
    /// Create a new parser context for an instruction at the given address.
    pub fn new(addr: u64, bytes: Vec<u8>, context: SleighContext) -> Self {
        Self {
            addr,
            bytes,
            pos: 0,
            context,
            matched_constructors: Vec::new(),
            operands: Vec::new(),
            consumed: 0,
            complete: false,
        }
    }

    /// Returns the remaining unconsumed bytes.
    pub fn remaining_bytes(&self) -> &[u8] {
        &self.bytes[self.pos..]
    }

    /// Returns the number of remaining bytes.
    pub fn remaining_len(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    /// Mark a constructor as matched and advance the position.
    pub fn match_constructor(&mut self, ctor_id: usize, length: usize) {
        self.matched_constructors.push(ctor_id);
        self.pos += length;
        self.consumed += length;
        if self.pos >= self.bytes.len() {
            self.complete = true;
        }
    }

    /// Set an operand value at the given operand slot index.
    pub fn set_operand(&mut self, index: usize, value: OperandVal) {
        while self.operands.len() <= index {
            self.operands
                .push(OperandVal::Immediate { value: 0, size: 0 });
        }
        self.operands[index] = value;
    }

    /// Get an operand value by slot index.
    pub fn get_operand(&self, index: usize) -> Option<&OperandVal> {
        self.operands.get(index)
    }

    /// Returns the last matched constructor ID, if any.
    pub fn last_constructor(&self) -> Option<usize> {
        self.matched_constructors.last().copied()
    }
}

// ---------------------------------------------------------------------------
// ParserWalker
// ---------------------------------------------------------------------------

/// A stateful walker that traverses the parse tree to extract operand values
/// and generate P-code operations.
///
/// The walker maintains a current position in the tree and provides methods to:
/// - Move to child nodes (for sub-table resolution)
/// - Move to parent nodes
/// - Extract operand values at the current position
/// - Collect P-code operations in tree order
#[derive(Debug, Clone)]
pub struct ParserWalker {
    /// The parser context for the current instruction
    pub ctx: ParserContext,
    /// The parse tree being walked
    pub tree: ParseTree,
    /// Stack of node indices representing the current path from root
    pub node_path: Vec<usize>,
    /// Current node index (top of node_path)
    pub current_node: Option<usize>,
    /// Accumulated P-code operations
    pub pcode_ops: Vec<PcodeOp>,
    /// Current flow state
    pub flow_state: FlowState,
}

impl ParserWalker {
    /// Create a new walker starting at the parse tree root.
    pub fn new(ctx: ParserContext, tree: ParseTree) -> Self {
        let current_node = tree.root;
        let node_path = current_node.map(|idx| vec![idx]).unwrap_or_default();

        Self {
            ctx,
            tree,
            node_path,
            current_node,
            pcode_ops: Vec::new(),
            flow_state: FlowState::Normal,
        }
    }

    /// Returns a reference to the current parse node, if any.
    pub fn current_node(&self) -> Option<&ParseNode> {
        self.current_node.and_then(|idx| self.tree.nodes.get(idx))
    }

    /// Returns a mutable reference to the current parse node, if any.
    pub fn current_node_mut(&mut self) -> Option<&mut ParseNode> {
        self.current_node
            .and_then(|idx| self.tree.nodes.get_mut(idx))
    }

    /// Move to the specified child of the current node.
    ///
    /// Returns `true` if the move was successful.
    pub fn descend_to_child(&mut self, child_index: usize) -> bool {
        if let Some(node) = self.current_node() {
            if let Some(&child_idx) = node.children.get(child_index) {
                self.current_node = Some(child_idx);
                self.node_path.push(child_idx);
                return true;
            }
        }
        false
    }

    /// Move to the parent of the current node.
    ///
    /// Returns `true` if the move was successful (i.e., we were not at root).
    pub fn ascend_to_parent(&mut self) -> bool {
        if self.node_path.len() > 1 {
            self.node_path.pop();
            self.current_node = self.node_path.last().copied();
            true
        } else {
            false
        }
    }

    /// Reset the walker back to the root node.
    pub fn reset_to_root(&mut self) {
        self.current_node = self.tree.root;
        self.node_path = self.current_node.map(|idx| vec![idx]).unwrap_or_default();
        self.pcode_ops.clear();
    }

    /// Add a P-code operation to the accumulated list.
    pub fn emit_pcode(&mut self, op: PcodeOp) {
        self.pcode_ops.push(op);
    }

    /// Determine flow state from the accumulated P-code operations.
    pub fn determine_flow_state(&mut self) {
        let mut has_branch = false;
        let mut has_conditional = false;
        let mut has_call = false;
        let mut has_return = false;
        let mut has_indirect = false;

        for op in &self.pcode_ops {
            match op.opcode {
                OpCode::Branch => has_branch = true,
                OpCode::Cbranch => has_conditional = true,
                OpCode::BranchInd => has_indirect = true,
                OpCode::Call | OpCode::Callother => has_call = true,
                OpCode::CallInd => {
                    has_call = true;
                    has_indirect = true;
                }
                OpCode::Return => has_return = true,
                _ => {}
            }
        }

        self.flow_state = if has_return {
            FlowState::Return
        } else if has_call {
            FlowState::Call
        } else if has_indirect {
            FlowState::Indirect
        } else if has_conditional {
            FlowState::ConditionalBranch
        } else if has_branch {
            FlowState::Branch
        } else {
            FlowState::Normal
        };
    }

    /// Returns the total instruction length by walking the tree.
    pub fn total_length(&self) -> usize {
        self.tree.total_length
    }
}

// ---------------------------------------------------------------------------
// TranslateEngine
// ---------------------------------------------------------------------------

/// Orchestrates translation of raw instruction bytes to P-code.
///
/// `TranslateEngine` uses a [`SleighEngine`] for constructor matching and
/// manages the parse tree, context database, and P-code emission.
///
/// # Lifecycle
///
/// 1. Create a `TranslateEngine` with a reference to a `SleighEngine`
/// 2. Call [`translate`] with instruction bytes to get P-code
/// 3. Use [`ParserWalker`] to traverse the parse tree and extract operands
#[derive(Debug, Clone)]
pub struct TranslateEngine {
    /// Reference to the SLEIGH engine for constructor matching
    pub sleigh: Arc<SleighEngine>,
    /// Context database for tracking processor state
    pub context_db: ContextDatabase,
    /// Current parse tree (set after translation)
    pub parse_tree: Option<ParseTree>,
    /// Cached disassembly results for the last translation
    pub last_result: Option<DisassemblyResult>,
    /// Base address for relative address computation
    pub base_addr: u64,
    /// Alignment requirement for instruction addresses
    pub alignment: u8,
    /// Maximum number of bytes to consider for one instruction
    pub max_instruction_bytes: usize,
}

impl TranslateEngine {
    /// Create a new translation engine backed by the given SLEIGH engine.
    pub fn new(sleigh: Arc<SleighEngine>) -> Self {
        Self {
            sleigh,
            context_db: ContextDatabase::new(),
            parse_tree: None,
            last_result: None,
            base_addr: 0,
            alignment: 1,
            max_instruction_bytes: 16,
        }
    }

    /// Set the base address for relative address computation.
    pub fn set_base_address(&mut self, addr: u64) {
        self.base_addr = addr;
    }

    /// Set the alignment requirement.
    pub fn set_alignment(&mut self, alignment: u8) {
        self.alignment = alignment;
    }

    /// Set the maximum number of bytes to examine for one instruction.
    pub fn set_max_instruction_bytes(&mut self, max_bytes: usize) {
        self.max_instruction_bytes = max_bytes;
    }

    /// Translate raw instruction bytes to P-code operations.
    ///
    /// This is the main entry point. It:
    /// 1. Creates a [`ParserContext`] from the bytes and context
    /// 2. Uses the SLEIGH engine to find a matching constructor
    /// 3. Builds the parse tree
    /// 4. Walks the tree to extract operands and emit P-code
    /// 5. Returns the complete disassembly result
    ///
    /// # Arguments
    /// * `addr` - Address of the instruction in memory
    /// * `bytes` - Raw instruction bytes
    ///
    /// # Returns
    /// A [`DisassemblyResult`] containing mnemonic, operands, P-code, and metadata.
    pub fn translate(&mut self, addr: u64, bytes: &[u8]) -> Result<DisassemblyResult, String> {
        let context = SleighContext::new(self.context_db.total_bits());
        let ctx = ParserContext::new(addr, bytes.to_vec(), context);

        // Delegate to the SLEIGH engine for pattern matching and disassembly
        let ic =
            super::sleigh::SleighInstructionContext::new(addr, bytes.to_vec(), ctx.context.clone());
        let result = self.sleigh.disassemble(&ic)?;

        // Build the parse tree
        let mut node = ParseNode::new(result.constructor_id, addr, result.length);
        node.operands = result.operands.clone();
        node.pcode_ops = result.pcode_ops.clone();
        node.resolved = true;

        let tree = ParseTree::single_node(node);
        self.parse_tree = Some(tree.clone());
        self.last_result = Some(result.clone());

        Ok(result)
    }

    /// Get a [`ParserWalker`] for the current parse tree.
    ///
    /// The walker can be used to traverse the hierarchical decoding and
    /// extract operand values at each level.
    pub fn get_walker(&self) -> Result<ParserWalker, String> {
        let tree = self
            .parse_tree
            .clone()
            .ok_or_else(|| "No parse tree available; call translate() first".to_string())?;

        let context = SleighContext::new(self.context_db.total_bits());
        let ctx = ParserContext::new(self.base_addr, Vec::new(), context);

        Ok(ParserWalker::new(ctx, tree))
    }

    /// Save the current context state for speculative disassembly.
    pub fn save_context(&mut self) {
        self.context_db.save_state();
    }

    /// Restore the context state after speculative disassembly.
    pub fn restore_context(&mut self) -> Result<(), String> {
        self.context_db.restore_state()
    }

    /// Commit the context state after successful disassembly.
    pub fn commit_context(&mut self) -> Result<(), String> {
        self.context_db.commit_state()
    }

    /// Get a reference to the context database.
    pub fn context_db(&self) -> &ContextDatabase {
        &self.context_db
    }

    /// Get a mutable reference to the context database.
    pub fn context_db_mut(&mut self) -> &mut ContextDatabase {
        &mut self.context_db
    }

    /// Returns the last disassembly result, if any.
    pub fn last_result(&self) -> Option<&DisassemblyResult> {
        self.last_result.as_ref()
    }

    /// Returns a reference to the current parse tree, if any.
    pub fn parse_tree(&self) -> Option<&ParseTree> {
        self.parse_tree.as_ref()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::construct::{ConstructTpl, Constructor, OperandSymbol, PatternEquation};
    use super::super::pcode::{OpCode, PcodeOp, Varnode};
    use std::sync::Arc;
    use super::*;

    fn make_test_translator() -> TranslateEngine {
        let mut engine = SleighEngine::new();
        engine.set_processor("test", false, 1);

        // Register a MOV instruction: opcode 0xB8 + 4-byte immediate
        let mov_pattern = PatternEquation::Constraint {
            pattern: vec![0xB8],
            mask: vec![0xFF],
        };
        let mut mov_tpl = ConstructTpl::with_operand_count(2);
        mov_tpl.add_operand(OperandSymbol::Register { name: "EAX".into() });
        mov_tpl.add_operand(OperandSymbol::Immediate { index: 1, size: 4 });
        mov_tpl.add_op(PcodeOp::new(
            OpCode::Copy,
            Some(Varnode::register(0, 4)),
            vec![Varnode::constant(0, 4)],
        ));
        let mut mov = Constructor::new(0, "MOV", mov_pattern, mov_tpl);
        mov.is_root = true;
        engine.register_constructor(mov);

        // Register a RET instruction
        let ret_pattern = PatternEquation::Constraint {
            pattern: vec![0xC3],
            mask: vec![0xFF],
        };
        let mut ret_tpl = ConstructTpl::new();
        ret_tpl.add_op(PcodeOp::new(
            OpCode::Return,
            None,
            vec![Varnode::register(0, 4)],
        ));
        let mut ret = Constructor::new(1, "RET", ret_pattern, ret_tpl);
        ret.is_root = true;
        engine.register_constructor(ret);

        engine.build_indices();
        engine.initialized = true;

        TranslateEngine::new(Arc::new(engine))
    }

    #[test]
    fn test_translate_mov() {
        let mut translator = make_test_translator();
        let result = translator
            .translate(0x1000, &[0xB8, 0x78, 0x56, 0x34, 0x12])
            .unwrap();

        assert_eq!(result.mnemonic, "MOV");
        assert_eq!(result.length, 1); // pattern only constrains 1 byte
        assert_eq!(result.flow_state, FlowState::Normal);
        assert!(!result.pcode_ops.is_empty());
    }

    #[test]
    fn test_translate_ret() {
        let mut translator = make_test_translator();
        let result = translator.translate(0x2000, &[0xC3]).unwrap();

        assert_eq!(result.mnemonic, "RET");
        assert_eq!(result.flow_state, FlowState::Return);
        assert!(result.is_terminator());
    }

    #[test]
    fn test_parse_tree_single_node() {
        let node = ParseNode::new(5, 0x1000, 4);
        let tree = ParseTree::single_node(node);

        assert_eq!(tree.node_count(), 1);
        assert!(tree.root_node().is_some());
        assert_eq!(tree.root_node().unwrap().constructor_id, 5);
        assert_eq!(tree.root_node().unwrap().length(), 4);
    }

    #[test]
    fn test_parse_tree_hierarchy() {
        let mut tree = ParseTree::new();
        let mut root = ParseNode::new(0, 0x1000, 2);
        let child_idx = tree.add_node(ParseNode::new(1, 0x1002, 2));
        root.add_child(child_idx);

        let root_idx = tree.add_node(root);
        tree.root = Some(root_idx);

        assert_eq!(tree.node_count(), 2);
        let root_node = tree.root_node().unwrap();
        assert_eq!(root_node.children, vec![child_idx]);
        assert!(!root_node.is_leaf());
        assert!(tree.get_node(child_idx).unwrap().is_leaf());
    }

    #[test]
    fn test_parse_tree_collect_pcode() {
        let mut tree = ParseTree::new();
        let mut root = ParseNode::new(0, 0x1000, 2);
        root.pcode_ops.push(PcodeOp::new(
            OpCode::Copy,
            Some(Varnode::register(0, 4)),
            vec![Varnode::register(4, 4)],
        ));

        let mut child = ParseNode::new(1, 0x1002, 2);
        child.pcode_ops.push(PcodeOp::new(
            OpCode::IntAdd,
            Some(Varnode::register(0, 4)),
            vec![Varnode::register(0, 4), Varnode::constant(1, 4)],
        ));

        let child_idx = tree.add_node(child);
        root.add_child(child_idx);
        let root_idx = tree.add_node(root);
        tree.root = Some(root_idx);

        let ops = tree.collect_pcode_ops();
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].opcode, OpCode::Copy);
        assert_eq!(ops[1].opcode, OpCode::IntAdd);
    }

    #[test]
    fn test_parser_walker_descend_ascend() {
        let mut tree = ParseTree::new();
        let mut root = ParseNode::new(0, 0x1000, 2);
        let child_idx = tree.add_node(ParseNode::new(1, 0x1002, 2));
        root.add_child(child_idx);
        let root_idx = tree.add_node(root);
        tree.root = Some(root_idx);

        let ctx = ParserContext::new(0x1000, vec![], SleighContext::default());
        let mut walker = ParserWalker::new(ctx, tree);

        // Start at root
        assert_eq!(walker.current_node().unwrap().constructor_id, 0);

        // Descend to child
        assert!(walker.descend_to_child(0));
        assert_eq!(walker.current_node().unwrap().constructor_id, 1);

        // Ascend back to root
        assert!(walker.ascend_to_parent());
        assert_eq!(walker.current_node().unwrap().constructor_id, 0);

        // Cannot ascend past root
        assert!(!walker.ascend_to_parent());
    }

    #[test]
    fn test_parser_context_operands() {
        let mut ctx = ParserContext::new(0x1000, vec![0x90, 0x90], SleighContext::default());
        ctx.set_operand(0, OperandVal::register("EAX", 4));
        ctx.set_operand(1, OperandVal::immediate(0x42, 4));

        assert!(ctx.get_operand(0).unwrap().is_register());
        assert!(ctx.get_operand(1).unwrap().is_immediate());
    }
}
