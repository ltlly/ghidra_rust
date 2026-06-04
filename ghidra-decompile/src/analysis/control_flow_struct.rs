//! Control-flow structuring engine.
//!
//! Converts an unstructured control-flow graph (with gotos) into structured C
//! control-flow constructs: if/else, while, for, do-while, switch.
//!
//! # Architecture
//!
//! The algorithm uses region-based recursive descent, inspired by the
//! Peterson-Kasami-Tokura approach used in Ghidra's C++ decompiler:
//!
//! 1. **Loop detection** — natural loops are identified via dominator-tree
//!    back-edge analysis. Innermost loops are structured first.
//!
//! 2. **Acyclic region structuring** — each region is classified by its entry
//!    node's outgoing edges:
//!    - 0 successors     -> leaf block or return
//!    - 1 successor      -> straight-line sequence
//!    - 2 successors     -> if/else (merge point found via post-dominators)
//!    - N (>2) successors -> switch (jump-table or chained-condition detection)
//!
//! 3. **Loop structuring** — the loop type (`while`, `do-while`, `for`) is
//!    determined by the position of the condition test and induction-variable
//!    patterns.
//!
//! 4. **Compound condition handling** — short-circuit `&&` / `||` chains are
//!    collapsed into single compound conditions (configurable).
//!
//! 5. **Goto re-insertion** — irreducible edges that cannot be matched to a
//!    structured construct are emitted as `goto` + `label` pairs.

use std::collections::{HashMap, HashSet};

use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;

use ghidra_core::addr::Address;

use crate::pcode::analysis::{
    find_natural_loops, ControlFlowGraph, DominatorTree, NaturalLoop,
};
use crate::pcode::{OpCode, PcodeOperation, Varnode};

// ============================================================================
// Expression — the decompiler's expression IR
// ============================================================================

/// A decompiler expression representing a C-like computation.
///
/// This is a high-level IR node. It corresponds roughly to a single expression
/// in the output C code.  Lower-level P-code operations are lifted into these
/// expressions by the structurer, and further simplified by later passes.
#[derive(Debug, Clone)]
pub enum Expression {
    /// A named variable (register, local, global).
    Variable {
        /// Human-readable name for the variable.
        name: String,
        /// Size in bytes (for type inference).
        size: u32,
    },
    /// A literal constant value.
    Constant {
        /// The raw bit-pattern value.
        value: u64,
        /// Size in bytes.
        size: u32,
    },
    /// Binary operation: `left op right`.
    BinaryOp {
        op: BinaryOperator,
        left: Box<Expression>,
        right: Box<Expression>,
    },
    /// Unary operation: `op operand`.
    UnaryOp {
        op: UnaryOperator,
        operand: Box<Expression>,
    },
    /// Pointer dereference: `*expr` (load from memory).
    Dereference {
        ptr: Box<Expression>,
        /// Size of the dereferenced value in bytes.
        size: u32,
    },
    /// Address-of: `&operand`.
    AddressOf {
        operand: Box<Expression>,
    },
    /// Function call: `target(args)`.
    Call {
        target: Box<Expression>,
        args: Vec<Expression>,
    },
    /// Type cast: `(target_type)expr`.
    Cast {
        target_type: String,
        expr: Box<Expression>,
    },
    /// Ternary conditional: `cond ? true_expr : false_expr`.
    Ternary {
        cond: Box<Expression>,
        true_expr: Box<Expression>,
        false_expr: Box<Expression>,
    },
    /// Array access: `base[index]`.
    ArrayAccess {
        base: Box<Expression>,
        index: Box<Expression>,
    },
    /// Struct/union field access: `base.field`.
    FieldAccess {
        base: Box<Expression>,
        field: String,
    },
    /// A string literal: `"hello"`.
    StringLiteral {
        /// The string content (without quotes).
        value: String,
    },
    /// A raw P-code operation (fallback for opcodes that cannot be lifted
    /// into a higher-level expression).
    PcodeOp {
        opcode: OpCode,
        inputs: Vec<Varnode>,
        output: Option<Varnode>,
    },
    /// Assignment: `lhs = rhs`.
    Assignment {
        lhs: Box<Expression>,
        rhs: Box<Expression>,
    },
    /// A comma-expression: `left, right` (evaluates both, returns `right`).
    Comma {
        left: Box<Expression>,
        right: Box<Expression>,
    },
    /// No operation / placeholder.
    Nop,
}

impl Expression {
    /// Create a constant expression.
    pub fn constant(value: u64, size: u32) -> Self {
        Expression::Constant { value, size }
    }

    /// Create a variable expression.
    pub fn variable(name: impl Into<String>, size: u32) -> Self {
        Expression::Variable {
            name: name.into(),
            size,
        }
    }

    /// Create a binary operation.
    pub fn binary(op: BinaryOperator, left: Expression, right: Expression) -> Self {
        Expression::BinaryOp {
            op,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// Create a unary operation.
    pub fn unary(op: UnaryOperator, operand: Expression) -> Self {
        Expression::UnaryOp {
            op,
            operand: Box::new(operand),
        }
    }

    /// Create an assignment.
    pub fn assign(lhs: Expression, rhs: Expression) -> Self {
        Expression::Assignment {
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    /// Returns true if this is a Nop.
    pub fn is_nop(&self) -> bool {
        matches!(self, Expression::Nop)
    }

    /// Returns the size hint of this expression (for type inference).
    pub fn size_hint(&self) -> Option<u32> {
        match self {
            Expression::Variable { size, .. } => Some(*size),
            Expression::Constant { size, .. } => Some(*size),
            Expression::BinaryOp { left, .. } => left.size_hint(),
            Expression::UnaryOp { operand, .. } => operand.size_hint(),
            Expression::Dereference { size, .. } => Some(*size),
            Expression::Ternary { true_expr, .. } => true_expr.size_hint(),
            Expression::Cast { .. } => None,
            Expression::Assignment { lhs, .. } => lhs.size_hint(),
            Expression::StringLiteral { .. } => None,
            Expression::PcodeOp { output, .. } => output.as_ref().map(|v| v.size),
            Expression::AddressOf { .. } => {
                // A pointer is typically 8 bytes on 64-bit.
                Some(8)
            }
            Expression::Call { .. } => None,
            Expression::ArrayAccess { .. } => None,
            Expression::FieldAccess { .. } => None,
            Expression::Comma { right, .. } => right.size_hint(),
            Expression::Nop => None,
        }
    }

    /// Returns true if this expression represents a boolean/logical test.
    pub fn is_comparison(&self) -> bool {
        matches!(
            self,
            Expression::BinaryOp {
                op:
                    BinaryOperator::Eq
                    | BinaryOperator::Neq
                    | BinaryOperator::Lt
                    | BinaryOperator::Le
                    | BinaryOperator::Gt
                    | BinaryOperator::Ge
                    | BinaryOperator::LogicalAnd
                    | BinaryOperator::LogicalOr,
                ..
            } | Expression::UnaryOp {
                op: UnaryOperator::Not,
                ..
            }
        )
    }
}

/// Binary operators used in decompiler expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryOperator {
    /// `+`
    Add,
    /// `-`
    Sub,
    /// `*`
    Mul,
    /// `/` (unsigned)
    Div,
    /// `%` (unsigned)
    Mod,
    /// `&`
    And,
    /// `|`
    Or,
    /// `^`
    Xor,
    /// `<<`
    Shl,
    /// `>>`
    Shr,
    /// `==`
    Eq,
    /// `!=`
    Neq,
    /// `<` (unsigned)
    Lt,
    /// `<=` (unsigned)
    Le,
    /// `>` (unsigned)
    Gt,
    /// `>=` (unsigned)
    Ge,
    /// `&&`
    LogicalAnd,
    /// `||`
    LogicalOr,
}

/// Unary operators used in decompiler expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnaryOperator {
    /// `-` (two's-complement negation)
    Neg,
    /// `!` (boolean/logical not)
    Not,
    /// `~` (bitwise not)
    BitNot,
    /// `*` (pointer dereference)
    Deref,
    /// `&` (address-of)
    AddressOf,
}

// ============================================================================
// StructuringOptions
// ============================================================================

/// Options controlling the behaviour of the control-flow structurer.
///
/// These correspond to the tuning knobs available in Ghidra's decompiler
/// analysis options panel.
#[derive(Debug, Clone)]
pub struct StructuringOptions {
    /// Prefer `switch` over chains of if/else when possible.
    pub prefer_switch: bool,

    /// Maximum gap between consecutive case values before the structurer
    /// stops treating a chain of comparisons as a switch candidate.
    pub max_switch_gap: u32,

    /// Prefer `do { ... } while(cond)` over `while(cond) { ... }` when the
    /// loop body is always executed at least once.
    pub prefer_do_while: bool,

    /// Prefer `for(init; cond; step) { ... }` over `while(cond) { ... }`
    /// when a simple induction variable is detected.
    pub prefer_for_loop: bool,

    /// Split compound conditions (`a && b`) into separate if statements
    /// when they map to short-circuit evaluation in the original code.
    pub split_compound_conditions: bool,
}

impl Default for StructuringOptions {
    fn default() -> Self {
        Self {
            prefer_switch: true,
            max_switch_gap: 5,
            prefer_do_while: true,
            prefer_for_loop: true,
            split_compound_conditions: false,
        }
    }
}

// ============================================================================
// StructuredNode — the target structured IR
// ============================================================================

/// A node in the structured control-flow graph.
///
/// This is the output of the control-flow structurer.  Each variant corresponds
/// to a C-level control-flow construct.  The tree can be pretty-printed directly
/// to C source code.
#[derive(Debug, Clone)]
pub enum StructuredNode {
    /// A basic block: a straight-line sequence of expressions.
    Block(BlockData),

    /// `if (condition) { then_branch } else { else_branch }`
    IfElse {
        condition: Expression,
        then_branch: Box<StructuredNode>,
        else_branch: Option<Box<StructuredNode>>,
    },

    /// `while (condition) { body }`
    While {
        condition: Expression,
        body: Box<StructuredNode>,
    },

    /// `do { body } while (condition);`
    DoWhile {
        condition: Expression,
        body: Box<StructuredNode>,
    },

    /// `for (init; condition; step) { body }`
    For {
        init: Option<Box<Expression>>,
        condition: Option<Box<Expression>>,
        step: Option<Box<Expression>>,
        body: Box<StructuredNode>,
    },

    /// `switch (expression) { case ...: ... default: ... }`
    Switch {
        expression: Expression,
        cases: Vec<SwitchCase>,
        default: Option<Box<StructuredNode>>,
    },

    /// An unresolved goto (inserted when structuring fails for an irreducible
    /// edge).
    Goto {
        target: Address,
        label: String,
    },

    /// A label target for a goto.
    Label {
        name: String,
        node: Box<StructuredNode>,
    },

    /// `break;`
    Break,

    /// `continue;`
    Continue,

    /// `return [expr];`
    Return(Option<Box<Expression>>),

    /// `for (;;) { body }` — an infinite loop with no explicit condition test.
    InfiniteLoop {
        body: Box<StructuredNode>,
    },

    /// A sequence of nodes executed in order.
    Sequence(Vec<StructuredNode>),
}

impl StructuredNode {
    /// Create an empty block node with a null address.
    pub fn empty_block() -> Self {
        StructuredNode::Block(BlockData {
            operations: Vec::new(),
            address: Address::NULL,
        })
    }

    /// Create a block node with a single expression.
    pub fn expr(expr: Expression, addr: Address) -> Self {
        StructuredNode::Block(BlockData {
            operations: vec![expr],
            address: addr,
        })
    }

    /// Create a sequence from a list of nodes.  Nested `Sequence` nodes are
    /// flattened so that the resulting tree is always in "left-deep" form.
    pub fn sequence(nodes: Vec<StructuredNode>) -> Self {
        let mut flat = Vec::new();
        for n in nodes {
            match n {
                StructuredNode::Sequence(inner) => flat.extend(inner),
                other => flat.push(other),
            }
        }
        if flat.len() == 1 {
            flat.into_iter().next().unwrap()
        } else {
            StructuredNode::Sequence(flat)
        }
    }

    /// Returns true if this node is semantically empty (a block with zero
    /// operations or an empty sequence).
    pub fn is_empty(&self) -> bool {
        match self {
            StructuredNode::Block(b) => b.operations.is_empty(),
            StructuredNode::Sequence(nodes) => nodes.iter().all(|n| n.is_empty()),
            _ => false,
        }
    }

    /// Walk the structured tree in preorder, calling `f` on each node.
    pub fn walk_preorder(&self, f: &mut impl FnMut(&StructuredNode)) {
        f(self);
        match self {
            StructuredNode::IfElse {
                then_branch,
                else_branch,
                ..
            } => {
                then_branch.walk_preorder(f);
                if let Some(ref eb) = else_branch {
                    eb.walk_preorder(f);
                }
            }
            StructuredNode::While { body, .. }
            | StructuredNode::DoWhile { body, .. }
            | StructuredNode::InfiniteLoop { body } => {
                body.walk_preorder(f);
            }
            StructuredNode::For { body, .. } => {
                body.walk_preorder(f);
            }
            StructuredNode::Switch { cases, default, .. } => {
                for case in cases {
                    case.body.walk_preorder(f);
                }
                if let Some(ref d) = default {
                    d.walk_preorder(f);
                }
            }
            StructuredNode::Label { node, .. } => {
                node.walk_preorder(f);
            }
            StructuredNode::Sequence(nodes) => {
                for n in nodes {
                    n.walk_preorder(f);
                }
            }
            StructuredNode::Block(_)
            | StructuredNode::Goto { .. }
            | StructuredNode::Break
            | StructuredNode::Continue
            | StructuredNode::Return(_) => {}
        }
    }
}

/// Data for a basic block in the structured IR.
#[derive(Debug, Clone)]
pub struct BlockData {
    /// The expressions/operations in this block (in sequential execution order).
    pub operations: Vec<Expression>,
    /// The starting address of this block.
    pub address: Address,
}

/// A single case arm in a switch statement.
#[derive(Debug, Clone)]
pub struct SwitchCase {
    /// The constant values that match this case (multiple values can share a
    /// body when cases are merged).
    pub values: Vec<i64>,
    /// The body of this case.
    pub body: Box<StructuredNode>,
    /// Whether this case falls through to the next case.
    pub is_fallthrough: bool,
}

/// Classification of a natural loop detected in the CFG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopType {
    /// `while (condition) { body }` — condition tested at the top of the loop.
    While,
    /// `do { body } while (condition);` — condition tested at the bottom.
    DoWhile,
    /// `for (init; condition; step) { body }` — initialization, condition, and
    /// increment.
    For,
}

// ============================================================================
// StructuredGraph
// ============================================================================

/// The fully-structured control-flow graph produced by the structurer.
#[derive(Debug, Clone)]
pub struct StructuredGraph {
    /// The root node of the structured graph (the function body).
    pub root: Option<StructuredNode>,
    /// Labels mapping addresses to human-readable label names (for goto
    /// targets).
    pub labels: HashMap<Address, String>,
    /// Set of addresses that are goto targets.
    pub goto_targets: HashSet<Address>,
}

impl Default for StructuredGraph {
    fn default() -> Self {
        Self {
            root: None,
            labels: HashMap::new(),
            goto_targets: HashSet::new(),
        }
    }
}

// ============================================================================
// PostDominatorTree
// ============================================================================

/// A post-dominator tree for the CFG.
///
/// Node `A` **post-dominates** node `B` if every path from `B` to the exit
/// node goes through `A`.  The post-dominator tree is the reverse of the
/// dominator tree on the reversed graph.
#[derive(Debug, Clone)]
struct PostDominatorTree {
    /// Immediate post-dominator for each node (if any).
    ipdom: HashMap<NodeIndex, NodeIndex>,
}

impl PostDominatorTree {
    /// Compute the post-dominator tree for the given CFG.
    ///
    /// We build the reverse graph (swap entry <-> exit, reverse edge
    /// directions) and run the standard dominator algorithm on it.  The
    /// resulting immediate dominators of the reverse graph are the immediate
    /// post-dominators of the original graph.
    fn compute(cfg: &ControlFlowGraph) -> Self {
        let mut rev_graph = petgraph::graph::DiGraph::<usize, ()>::new();
        let mut node_map: HashMap<NodeIndex, NodeIndex> = HashMap::new();

        // Clone nodes.
        for node in cfg.graph.node_indices() {
            let id = cfg.graph[node];
            let rev_node = rev_graph.add_node(id);
            node_map.insert(node, rev_node);
        }

        // Reverse edges.
        for edge in cfg.graph.edge_references() {
            let from = edge.source();
            let to = edge.target();
            if let (Some(&rev_to), Some(&rev_from)) = (node_map.get(&to), node_map.get(&from)) {
                rev_graph.add_edge(rev_to, rev_from, ());
            }
        }

        // The reverse entry is the original exit.
        let rev_entry = node_map[&cfg.exit];

        let dom = petgraph::algo::dominators::simple_fast(&rev_graph, rev_entry);

        // Map reverse dominators back to original node indices.
        let mut ipdom = HashMap::new();
        for (&orig, &rev) in &node_map {
            if let Some(dom_rev) = dom.immediate_dominator(rev) {
                // Find the original node that maps to this reverse node.
                for (&o, &r) in &node_map {
                    if r == dom_rev {
                        ipdom.insert(orig, o);
                        break;
                    }
                }
            }
        }

        PostDominatorTree { ipdom }
    }

    /// Returns the immediate post-dominator of `node`, if any.
    fn ipostdom(&self, node: NodeIndex) -> Option<NodeIndex> {
        self.ipdom.get(&node).copied()
    }

    /// Returns true if `a` post-dominates `b` (every path from `b` to exit
    /// goes through `a`).
    fn postdominates(&self, a: NodeIndex, b: NodeIndex) -> bool {
        if a == b {
            return true;
        }
        let mut current = b;
        // Walk up the post-dominator tree with a visited set to avoid cycles.
        let mut seen = HashSet::new();
        seen.insert(current);
        loop {
            match self.ipostdom(current) {
                Some(ipd) if ipd == a => return true,
                Some(ipd) if !seen.insert(ipd) => return false, // cycle guard
                Some(ipd) => current = ipd,
                None => return false,
            }
        }
    }

    /// Find the nearest common post-dominator of two nodes.
    ///
    /// This is the "merge point" where two branches of an if/else rejoin.
    fn common_postdom(&self, a: NodeIndex, b: NodeIndex) -> Option<NodeIndex> {
        // Collect all post-dominators of `a`.
        let mut postdoms_a = HashSet::new();
        let mut cur = a;
        postdoms_a.insert(cur);
        loop {
            match self.ipostdom(cur) {
                Some(ipd) if postdoms_a.insert(ipd) => cur = ipd,
                _ => break,
            }
        }

        // Walk up from `b` until we find a common ancestor.
        let mut cur = b;
        loop {
            if postdoms_a.contains(&cur) {
                return Some(cur);
            }
            match self.ipostdom(cur) {
                Some(ipd) if ipd != cur => cur = ipd,
                _ => break,
            }
        }
        None
    }
}

// ============================================================================
// ControlFlowStructurer
// ============================================================================

/// The control-flow structurer.
///
/// Converts an unstructured petgraph-based [`ControlFlowGraph`] into a
/// [`StructuredNode`] tree representing C-like control flow.
///
/// # Example
///
/// ```ignore
/// use ghidra_decompile::pcode::analysis::{build_cfg, ControlFlowGraph};
/// use ghidra_decompile::analysis::control_flow_struct::ControlFlowStructurer;
///
/// let cfg: ControlFlowGraph = build_cfg(&sequences);
/// let mut structurer = ControlFlowStructurer::new(cfg);
/// let root = structurer.structure().expect("structuring failed");
/// ```
pub struct ControlFlowStructurer {
    /// The input control-flow graph.
    pub cfg: ControlFlowGraph,
    /// The output structured graph.
    pub structured: StructuredGraph,
    /// Options controlling the structurer's behaviour.
    pub options: StructuringOptions,

    // -- internal state -------------------------------------------------------
    /// Dominator tree for the CFG (entry-based).
    dom: DominatorTree,

    /// Post-dominator tree, computed lazily.
    pdom: Option<PostDominatorTree>,

    /// Natural loops detected in the CFG, sorted by body size (innermost
    /// first).
    loops: Vec<NaturalLoop>,

    /// Map from node to the innermost loop header that contains it (or
    /// `None` if the node is not in any loop).
    node_to_loop: HashMap<NodeIndex, Option<NodeIndex>>,

    /// Label counter for generating unique goto labels.
    label_counter: u64,

    /// Nodes that have already been visited during structuring (prevents
    /// infinite recursion on irreducible regions).
    visited: HashSet<NodeIndex>,
}

impl ControlFlowStructurer {
    /// Create a new control-flow structurer from a CFG using default options.
    pub fn new(cfg: ControlFlowGraph) -> Self {
        let dom = DominatorTree::compute(&cfg);
        let loops = find_natural_loops(&cfg, &dom);
        let node_to_loop = Self::build_node_to_loop_map(&cfg, &loops);

        Self {
            cfg,
            structured: StructuredGraph::default(),
            options: StructuringOptions::default(),
            dom,
            pdom: None,
            loops,
            node_to_loop,
            label_counter: 0,
            visited: HashSet::new(),
        }
    }

    /// Create a structurer with custom options.
    pub fn with_options(cfg: ControlFlowGraph, options: StructuringOptions) -> Self {
        let mut s = Self::new(cfg);
        s.options = options;
        s
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// Run the full structuring pipeline and return the root structured node.
    ///
    /// This is the main entry point.  After this call, the result is also
    /// available via [`root`](Self::root) and
    /// [`structured_graph`](Self::structured_graph).
    pub fn structure(&mut self) -> Result<StructuredNode, String> {
        // Ensure post-dominators are available.
        self.ensure_pdom();

        // Reset mutable state.
        self.visited.clear();
        self.label_counter = 0;
        self.structured = StructuredGraph::default();

        // Structure the function starting from the entry node.
        let root = self.structure_region(self.cfg.entry)?;

        // Final pass: insert labels at goto targets.
        let mut root = self.insert_labels(root);

        // Re-insert any remaining irreducible gotos.
        self.reinsert_gotos(&mut root);

        self.structured.root = Some(root.clone());
        Ok(root)
    }

    /// Returns the structured root after [`structure`] has been called.
    pub fn root(&self) -> Option<&StructuredNode> {
        self.structured.root.as_ref()
    }

    /// Returns a reference to the structured graph (including labels and
    /// goto-target metadata).
    pub fn structured_graph(&self) -> &StructuredGraph {
        &self.structured
    }

    // ------------------------------------------------------------------
    // Public analysis helpers (exposed for testing and incremental use)
    // ------------------------------------------------------------------

    /// Find all loop (header, latch) pairs.
    pub fn find_loops(&self) -> Vec<(NodeIndex, NodeIndex)> {
        self.loops
            .iter()
            .map(|lp| (lp.header, lp.back_edge.0))
            .collect()
    }

    /// Structure a single loop given its header and latch nodes.
    pub fn structure_loop(
        &mut self,
        header: NodeIndex,
        latch: NodeIndex,
    ) -> Result<StructuredNode, String> {
        if let Some(lp) = self
            .loops
            .iter()
            .find(|l| l.header == header && l.back_edge.0 == latch)
            .cloned()
        {
            self.structure_loop_region(header, &lp)
        } else {
            Err(format!(
                "No natural loop found with header {:?} and latch {:?}",
                header, latch
            ))
        }
    }

    /// Find the if/else successors at a node.  Returns `(then_branch,
    /// else_branch_or_none)` if the node has 1 or 2 successors.
    pub fn find_if_else(&self, node: NodeIndex) -> Option<(NodeIndex, Option<NodeIndex>)> {
        let succs = self.cfg.successors(node);
        match succs.len() {
            2 => Some((succs[0], Some(succs[1]))),
            1 => Some((succs[0], None)),
            _ => None,
        }
    }

    /// Try to structure a given node as a switch.  Returns `None` if the
    /// node does not match the switch pattern.
    pub fn structure_switch_node(&mut self, node: NodeIndex) -> Option<StructuredNode> {
        self.structure_switch(node).ok().flatten()
    }

    /// Detect the loop type for a given loop header.
    pub fn detect_loop_type(&self, header: NodeIndex) -> LoopType {
        self.classify_loop_type(header)
    }

    /// Structure compound conditions at a node (short-circuit boolean chains).
    ///
    /// When `split_compound_conditions` is enabled, this returns multiple
    /// if/else nodes instead of a single compound condition.  Returns an empty
    /// vector when no compound conditions are present or splitting is disabled.
    pub fn structure_compound_conditions(
        &self,
        node: NodeIndex,
    ) -> Vec<StructuredNode> {
        if !self.options.split_compound_conditions {
            return Vec::new();
        }

        let block = self.cfg.block_by_node(node);
        let mut result = Vec::new();

        // Look for short-circuit boolean AND/OR chains: if the block computes
        // a boolean and the successors form a pattern where one branch goes to
        // the merge and the other computes the next condition, we have a
        // compound condition.
        for op in &block.operations {
            if matches!(op.opcode, OpCode::BOOL_AND | OpCode::BOOL_OR) {
                // Found a compound condition.  For now, just note it; full
                // splitting is a future enhancement.
                result.push(StructuredNode::Block(BlockData {
                    operations: vec![self.pcode_op_to_expression(op)],
                    address: block.start_address.unwrap_or(Address::NULL),
                }));
            }
        }

        result
    }

    /// Re-insert goto/label pairs for irreducible edges.
    ///
    /// This walks the structured tree and ensures every `Goto` has a
    /// corresponding `Label` at the target.
    pub fn reinsert_gotos(&self, node: &mut StructuredNode) {
        // In the current implementation, labels are tracked in the
        // `StructuredGraph` metadata.  The caller can use this metadata
        // to insert labels during C-output generation.
        //
        // This method exists as a hook for future enhancements (e.g.,
        // wrapping labeled targets directly in the tree).
        let _ = node;
    }

    // ==================================================================
    // Internal: region-based recursive descent
    // ==================================================================

    /// Ensure the post-dominator tree has been computed.
    fn ensure_pdom(&mut self) {
        if self.pdom.is_none() {
            self.pdom = Some(PostDominatorTree::compute(&self.cfg));
        }
    }

    /// Build a map from each node to its innermost loop header (or `None`).
    fn build_node_to_loop_map(
        cfg: &ControlFlowGraph,
        loops: &[NaturalLoop],
    ) -> HashMap<NodeIndex, Option<NodeIndex>> {
        let mut map: HashMap<NodeIndex, Option<NodeIndex>> = HashMap::new();
        for node in cfg.graph.node_indices() {
            map.insert(node, None);
        }

        // Assign innermost loop first (loops are sorted by body size,
        // ascending — innermost loops have the smallest bodies).
        for lp in loops {
            for &node in &lp.body {
                map.insert(node, Some(lp.header));
            }
        }

        map
    }

    /// Find the natural loop whose header is `node`, if any.
    fn find_loop_with_header(&self, node: NodeIndex) -> Option<&NaturalLoop> {
        self.loops.iter().find(|lp| lp.header == node)
    }

    /// Structure a region starting from `entry`.
    ///
    /// A region is a subgraph with a single entry.  This method classifies
    /// the entry node and dispatches to the appropriate structuring routine.
    fn structure_region(
        &mut self,
        entry: NodeIndex,
    ) -> Result<StructuredNode, String> {
        // Guard: already-visited nodes become gotos (irreducible edge).
        if self.visited.contains(&entry) {
            return Ok(self.make_goto(entry));
        }
        self.visited.insert(entry);

        // Exit node: produce an empty block.
        if entry == self.cfg.exit {
            self.visited.remove(&entry);
            return Ok(StructuredNode::empty_block());
        }

        // Loop header: structure the enclosing loop.
        if let Some(lp_header) = self.node_to_loop.get(&entry).copied().flatten() {
            if lp_header == entry {
                let lp = self
                    .find_loop_with_header(entry)
                    .cloned()
                    .ok_or_else(|| format!("Loop header {:?} not found in loop list", entry))?;
                return self.structure_loop_region(entry, &lp);
            }
        }

        // Classify by successor count.
        let succs = self.cfg.successors(entry);

        match succs.len() {
            0 => {
                // Leaf node (should have a return; otherwise dead code).
                self.structure_leaf(entry)
            }
            1 => {
                // Single-successor: straight-line sequence.
                self.structure_sequence_from(entry)
            }
            2 => {
                // Two successors: if/else candidate.
                if let Some(if_else) = self.structure_if_else(entry)? {
                    Ok(if_else)
                } else {
                    // Fallback: structure both branches sequentially.
                    let block = self.node_to_structured(entry);
                    let a = self.structure_region(succs[0])?;
                    let b = self.structure_region(succs[1])?;
                    Ok(StructuredNode::Sequence(vec![block, a, b]))
                }
            }
            _ => {
                // Multi-way: switch candidate.
                if self.options.prefer_switch {
                    if let Some(switch_node) = self.structure_switch(entry)? {
                        return Ok(switch_node);
                    }
                }
                // Fallback: treat each successor as a separate path.
                let block = self.node_to_structured(entry);
                let mut seq = vec![block];
                for succ in &succs {
                    seq.push(self.structure_region(*succ)?);
                }
                Ok(StructuredNode::Sequence(seq))
            }
        }
    }

    /// Structure a leaf node (typically contains a `return`).
    fn structure_leaf(&self, entry: NodeIndex) -> Result<StructuredNode, String> {
        let block = self.cfg.block_by_node(entry);
        for op in &block.operations {
            if op.opcode == OpCode::RETURN {
                let ret_expr = op
                    .inputs
                    .first()
                    .map(|v| Box::new(self.varnode_to_expression(v)));
                return Ok(StructuredNode::Return(ret_expr));
            }
        }
        // No return found: just emit the block.
        Ok(self.node_to_structured(entry))
    }

    /// Structure a straight-line sequence starting from `entry`.
    fn structure_sequence_from(
        &mut self,
        entry: NodeIndex,
    ) -> Result<StructuredNode, String> {
        let block = self.node_to_structured(entry);
        let succs = self.cfg.successors(entry);

        if succs.is_empty() {
            return Ok(block);
        }

        let rest = self.structure_region(succs[0])?;
        if rest.is_empty() {
            Ok(block)
        } else {
            Ok(StructuredNode::Sequence(vec![block, rest]))
        }
    }

    /// Structure a region within loop bounds (stop at `stop` if provided).
    fn structure_region_until(
        &mut self,
        entry: NodeIndex,
        stop: Option<NodeIndex>,
    ) -> Result<StructuredNode, String> {
        if Some(entry) == stop {
            return Ok(StructuredNode::empty_block());
        }

        if entry == self.cfg.exit {
            return self.structure_leaf(entry);
        }

        if self.visited.contains(&entry) {
            return Ok(self.make_goto(entry));
        }
        self.visited.insert(entry);

        // Loop header: structure the loop, then continue.
        if let Some(lp_header) = self.node_to_loop.get(&entry).copied().flatten() {
            if lp_header == entry {
                if let Some(lp) = self.find_loop_with_header(entry).cloned() {
                    let loop_node = self.structure_loop_region(entry, &lp)?;
                    // Find loop exits (successors not in the loop body).
                    let loop_exits: Vec<NodeIndex> = self
                        .cfg
                        .successors(entry)
                        .into_iter()
                        .filter(|s| !lp.body.contains(s))
                        .collect();

                    let mut seq = vec![loop_node];
                    for exit in loop_exits {
                        if Some(exit) != stop && exit != self.cfg.exit {
                            seq.push(self.structure_region_until(exit, stop)?);
                        }
                    }
                    return Ok(StructuredNode::Sequence(seq));
                }
            }
        }

        let succs = self.cfg.successors(entry);

        if succs.is_empty() {
            return self.structure_leaf(entry);
        }

        if succs.len() == 1 {
            let block = self.node_to_structured(entry);
            let rest = self.structure_region_until(succs[0], stop)?;
            if rest.is_empty() {
                return Ok(block);
            }
            return Ok(StructuredNode::Sequence(vec![block, rest]));
        }

        if succs.len() == 2 {
            if let Some(if_else) = self.structure_if_else_until(entry, stop)? {
                return Ok(if_else);
            }
        }

        // Fallback: block + successors.
        let block = self.node_to_structured(entry);
        let mut seq = vec![block];
        for succ in &succs {
            if Some(*succ) != stop {
                seq.push(self.structure_region_until(*succ, stop)?);
            }
        }
        Ok(StructuredNode::Sequence(seq))
    }

    // ==================================================================
    // Loop structuring
    // ==================================================================

    /// Structure a complete loop region given its header and pre-computed
    /// `NaturalLoop`.
    fn structure_loop_region(
        &mut self,
        header: NodeIndex,
        lp: &NaturalLoop,
    ) -> Result<StructuredNode, String> {
        let loop_body_set: HashSet<NodeIndex> = lp.body.iter().cloned().collect();
        let latch = lp.back_edge.0;
        let loop_type = self.classify_loop_type(header);

        // The loop condition comes from the header block (for while/for) or
        // the latch block (for do-while).
        let (condition, condition_block) = match loop_type {
            LoopType::DoWhile => {
                // For do-while, the condition is at the latch.
                let cond = self.extract_cond_from_block(latch);
                (cond, latch)
            }
            _ => {
                // For while/for, the condition is at the header.
                let cond = self.extract_cond_from_block(header);
                (cond, header)
            }
        };

        // Structure the loop body.
        let body_node = self.structure_loop_body_excluding_backedge(
            header, &loop_body_set, latch, condition_block,
        )?;

        match loop_type {
            LoopType::DoWhile => {
                let condition = self.extract_cond_from_block(latch);
                Ok(StructuredNode::DoWhile {
                    condition,
                    body: Box::new(body_node),
                })
            }
            LoopType::For => {
                let (init, step) = self.extract_for_components(header);
                Ok(StructuredNode::For {
                    init: init.map(Box::new),
                    condition: Some(Box::new(condition)),
                    step: step.map(Box::new),
                    body: Box::new(body_node),
                })
            }
            LoopType::While => Ok(StructuredNode::While {
                condition,
                body: Box::new(body_node),
            }),
        }
    }

    /// Structure the body of a loop, excluding the back-edge and the
    /// condition-producing block.
    fn structure_loop_body_excluding_backedge(
        &mut self,
        header: NodeIndex,
        loop_nodes: &HashSet<NodeIndex>,
        latch: NodeIndex,
        condition_block: NodeIndex,
    ) -> Result<StructuredNode, String> {
        let succs = self.cfg.successors(header);

        // The body entry is the first successor of the header that stays
        // inside the loop and is not the header itself.
        let body_entry = succs
            .iter()
            .find(|&&s| loop_nodes.contains(&s) && s != header)
            .copied();

        // Mark the header as visited so the body structurer does not recurse
        // into the loop entry.
        let was_visited = self.visited.contains(&header);
        self.visited.insert(header);

        let result = match body_entry {
            Some(entry) => {
                // Structure from the body entry up to (but not including)
                // the condition block.  For while/for loops, we stop at the
                // latch since the latch feeds back to the header.
                let stop_node = if condition_block == header {
                    // While/for: the condition is in the header; stop before
                    // the latch's back-edge.
                    Some(header)
                } else {
                    // Do-while: the condition is in the latch.  Structure
                    // everything after the header up to the latch, but strip
                    // the condition from the latch.
                    Some(latch)
                };
                self.structure_region_until(entry, stop_node)
            }
            None => {
                // The body is just the header block itself (self-loop).
                let mut block = self.node_to_structured(header);
                // Remove the branch condition since the loop construct
                // already captures it.
                block = self.strip_comparison_from_block(block);
                Ok(block)
            }
        };

        if !was_visited {
            self.visited.remove(&header);
        }

        result
    }

    /// Classify a loop by examining the header and latch block structure.
    fn classify_loop_type(&self, header: NodeIndex) -> LoopType {
        let block = self.cfg.block_by_node(header);

        // Determine if the header has a conditional branch.
        let header_has_cond = block
            .terminator()
            .map_or(false, |t| t.opcode == OpCode::CBRANCH);

        // Do-while: the header does NOT have a conditional branch (the body
        // is always executed at least once, and the condition is at the
        // latch).
        if self.options.prefer_do_while && !header_has_cond {
            return LoopType::DoWhile;
        }

        // For-loop: the header has a conditional branch AND there is an
        // identifiable induction-variable pattern.
        if self.options.prefer_for_loop && header_has_cond {
            if self.detect_for_pattern(header) {
                return LoopType::For;
            }
        }

        LoopType::While
    }

    /// Detect a for-loop pattern: an induction variable that is compared
    /// against a bound in the header.
    ///
    /// The pattern looks like:
    /// ```ignore
    ///   i = <init>;        // before the loop
    ///   if (i < bound) {   // header comparison
    ///       ... body ...
    ///       i = i + step;  // increment
    ///   }
    /// ```
    fn detect_for_pattern(&self, header: NodeIndex) -> bool {
        let block = self.cfg.block_by_node(header);

        // The header must have a conditional branch.
        let has_cbranch = block
            .terminator()
            .map_or(false, |t| t.opcode == OpCode::CBRANCH);
        if !has_cbranch {
            return false;
        }

        // Look for a comparison operation in the header that feeds the
        // conditional branch.
        if let Some(term) = block.terminator() {
            if term.inputs.len() >= 2 {
                let cond_vn = &term.inputs[1];
                for op in &block.operations {
                    if op.output.as_ref() == Some(cond_vn) && op.opcode.is_comparison() {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Extract the loop condition expression from a block.
    fn extract_cond_from_block(&self, block_idx: NodeIndex) -> Expression {
        let block = self.cfg.block_by_node(block_idx);

        // If the terminator is CBRANCH, return the condition input.
        if let Some(term) = block.terminator() {
            if term.opcode == OpCode::CBRANCH && term.inputs.len() >= 2 {
                return self.varnode_to_expression(&term.inputs[1]);
            }
        }

        // Otherwise, look for the last comparison in the block.
        for op in block.operations.iter().rev() {
            if op.opcode.is_comparison()
                || op.opcode == OpCode::BOOL_NEGATE
                || op.opcode == OpCode::BOOL_AND
                || op.opcode == OpCode::BOOL_OR
            {
                return self.pcode_op_to_expression(op);
            }
        }

        Expression::constant(1, 1) // always-true
    }

    /// Extract for-loop initialization and step expressions from the header
    /// block.
    fn extract_for_components(
        &self,
        header: NodeIndex,
    ) -> (Option<Expression>, Option<Expression>) {
        let block = self.cfg.block_by_node(header);
        let mut init: Option<Expression> = None;
        let mut step: Option<Expression> = None;

        let mut found_compare = false;
        for op in &block.operations {
            if op.opcode.is_comparison() {
                found_compare = true;
                continue;
            }

            if found_compare {
                // Operations after the comparison may be the step (increment).
                if op.opcode == OpCode::INT_ADD || op.opcode == OpCode::INT_SUB {
                    if op.inputs.len() >= 2 {
                        let rhs = &op.inputs[1];
                        if rhs.is_constant() && rhs.constant_value() == Some(1) {
                            if let Some(ref out) = op.output {
                                step = Some(Expression::Assignment {
                                    lhs: Box::new(self.varnode_to_expression(out)),
                                    rhs: Box::new(self.pcode_op_to_expression(op)),
                                });
                            }
                        }
                    }
                }
            } else {
                // Operations before the comparison may be initialization.
                if op.opcode == OpCode::COPY {
                    if let Some(ref out) = op.output {
                        if let Some(inp) = op.inputs.first() {
                            init = Some(Expression::Assignment {
                                lhs: Box::new(self.varnode_to_expression(out)),
                                rhs: Box::new(self.varnode_to_expression(inp)),
                            });
                        }
                    }
                }
            }
        }

        (init, step)
    }

    /// Extract the branch condition from a 2-way branch node.
    fn extract_branch_condition(&self, node: NodeIndex) -> Expression {
        let block = self.cfg.block_by_node(node);

        if let Some(term) = block.terminator() {
            if term.opcode == OpCode::CBRANCH && term.inputs.len() >= 2 {
                return self.varnode_to_expression(&term.inputs[1]);
            }
        }

        // Fallback: search for the last comparison/boolean operation.
        for op in block.operations.iter().rev() {
            if op.opcode.is_comparison()
                || matches!(
                    op.opcode,
                    OpCode::BOOL_NEGATE | OpCode::BOOL_AND | OpCode::BOOL_OR
                )
            {
                return self.pcode_op_to_expression(op);
            }
        }

        Expression::constant(1, 1)
    }

    // ==================================================================
    // If/Else structuring
    // ==================================================================

    /// Structure a 2-way branch as an if/else.
    ///
    /// Returns `None` if the node does not match the if/else pattern (e.g.,
    /// the two branches do not share a common post-dominator).
    fn structure_if_else(
        &mut self,
        node: NodeIndex,
    ) -> Result<Option<StructuredNode>, String> {
        let succs = self.cfg.successors(node);
        if succs.len() != 2 {
            return Ok(None);
        }

        let then_succ = succs[0];
        let else_succ = succs[1];

        // Find the merge point (nearest common post-dominator).
        let pdom = self.pdom.as_ref().unwrap();
        let merge = pdom.common_postdom(then_succ, else_succ);

        let condition = self.extract_branch_condition(node);
        let block_prelude = self.node_to_structured_stripped(node);

        let then_body = self.structure_branch_path(then_succ, merge)?;
        let else_body =
            self.structure_branch_path(else_succ, merge)?;

        let then_node = if block_prelude.is_empty() {
            then_body
        } else {
            StructuredNode::Sequence(vec![block_prelude, then_body])
        };

        Ok(Some(StructuredNode::IfElse {
            condition,
            then_branch: Box::new(then_node),
            else_branch: if else_body.is_empty() {
                None
            } else {
                Some(Box::new(else_body))
            },
        }))
    }

    /// Variant of `structure_if_else` that respects a stop node.
    fn structure_if_else_until(
        &mut self,
        node: NodeIndex,
        stop: Option<NodeIndex>,
    ) -> Result<Option<StructuredNode>, String> {
        let succs = self.cfg.successors(node);
        if succs.len() != 2 {
            return Ok(None);
        }

        let condition = self.extract_branch_condition(node);
        let block_prelude = self.node_to_structured_stripped(node);

        let then_body = self.structure_branch_path(succs[0], stop)?;
        let else_body =
            self.structure_branch_path(succs[1], stop)?;

        let then_node = if block_prelude.is_empty() {
            then_body
        } else {
            StructuredNode::Sequence(vec![block_prelude, then_body])
        };

        Ok(Some(StructuredNode::IfElse {
            condition,
            then_branch: Box::new(then_node),
            else_branch: if else_body.is_empty() {
                None
            } else {
                Some(Box::new(else_body))
            },
        }))
    }

    /// Structure the path from `start` to `end` (exclusive).
    fn structure_branch_path(
        &mut self,
        start: NodeIndex,
        end: Option<NodeIndex>,
    ) -> Result<StructuredNode, String> {
        if Some(start) == end {
            return Ok(StructuredNode::empty_block());
        }
        self.structure_region_until(start, end)
    }

    // ==================================================================
    // Switch structuring
    // ==================================================================

    /// Detect and structure a switch statement at a given node.
    ///
    /// Handles two patterns:
    /// 1. **Indirect branch** (jump table): `BRANCHIND` with multiple
    ///    successors mapping to case values.
    /// 2. **Chained conditionals**: a chain of if/else-if comparisons
    ///    against sequential values.
    fn structure_switch(
        &mut self,
        node: NodeIndex,
    ) -> Result<Option<StructuredNode>, String> {
        let succs = self.cfg.successors(node);
        if succs.len() < 3 {
            return Ok(None);
        }

        let block = self.cfg.block_by_node(node);

        // Check for indirect branch (jump table).
        let has_indirect = block
            .terminator()
            .map_or(false, |t| t.opcode == OpCode::BRANCHIND);

        if has_indirect {
            return self.structure_indirect_switch(node);
        }

        // Check for chained-conditional switch pattern.
        self.structure_conditional_chain_switch(node)
    }

    /// Structure an indirect branch as a switch (jump-table pattern).
    fn structure_indirect_switch(
        &mut self,
        node: NodeIndex,
    ) -> Result<Option<StructuredNode>, String> {
        let block = self.cfg.block_by_node(node);

        // The switch expression is the target of the indirect branch.
        let switch_expr = if let Some(term) = block.terminator() {
            if term.inputs.is_empty() {
                return Ok(None);
            }
            self.varnode_to_expression(&term.inputs[0])
        } else {
            return Ok(None);
        };

        let succs = self.cfg.successors(node);
        let mut cases: Vec<SwitchCase> = Vec::new();

        for &succ in &succs {
            if succ == self.cfg.exit {
                continue;
            }
            let target_addr = self.cfg.block_by_node(succ).start_address;
            if let Some(addr) = target_addr {
                let case_body = self.structure_region(succ)?;
                cases.push(SwitchCase {
                    values: vec![addr.offset as i64],
                    body: Box::new(case_body),
                    is_fallthrough: false,
                });
            }
        }

        // Sort cases by value for deterministic output.
        cases.sort_by_key(|c| c.values.first().copied().unwrap_or(0));

        Ok(Some(StructuredNode::Switch {
            expression: switch_expr,
            cases,
            default: None,
        }))
    }

    /// Structure a chain of conditional branches as a switch.
    ///
    /// This handles the pattern where a compiler lowers a switch into a
    /// chain of `if (x == 0) ... else if (x == 1) ... else if (x == 2) ...`.
    fn structure_conditional_chain_switch(
        &mut self,
        node: NodeIndex,
    ) -> Result<Option<StructuredNode>, String> {
        let succs = self.cfg.successors(node);
        if succs.len() < 3 {
            return Ok(None);
        }

        // Collect target addresses for each successor.
        let mut targets: Vec<(i64, Address)> = Vec::new();
        for &succ in &succs {
            if let Some(addr) = self.cfg.block_by_node(succ).start_address {
                targets.push((addr.offset as i64, addr));
            } else {
                return Ok(None);
            }
        }

        if targets.len() < 3 {
            return Ok(None);
        }

        // Check for sequential values (within the configured gap).
        targets.sort_by_key(|t| t.0);
        let gaps: Vec<i64> = targets.windows(2).map(|w| w[1].0 - w[0].0).collect();
        let max_gap = gaps.iter().copied().max().unwrap_or(0);

        if max_gap > self.options.max_switch_gap as i64 {
            return Ok(None);
        }

        // Looks like a switch.  Extract the expression and structure each
        // case.
        let switch_expr = self.extract_switch_expression(node);
        let mut cases = Vec::new();

        for (val, _addr) in &targets {
            let succ_idx = succs.iter().position(|&s| {
                self.cfg
                    .block_by_node(s)
                    .start_address
                    .map_or(false, |a| a.offset as i64 == *val)
            });

            if let Some(idx) = succ_idx {
                let case_body = self.structure_region(succs[idx])?;
                cases.push(SwitchCase {
                    values: vec![*val],
                    body: Box::new(case_body),
                    is_fallthrough: false,
                });
            }
        }

        Ok(Some(StructuredNode::Switch {
            expression: switch_expr,
            cases,
            default: None,
        }))
    }

    /// Extract the expression being switched on from a switch-header node.
    fn extract_switch_expression(&self, node: NodeIndex) -> Expression {
        let block = self.cfg.block_by_node(node);

        // Search for the comparison variable (the first input of an INT_EQUAL
        // or INT_SUB operation that feeds into the branch).
        for op in &block.operations {
            if matches!(
                op.opcode,
                OpCode::INT_EQUAL
                    | OpCode::INT_SUB
                    | OpCode::INT_NOTEQUAL
            ) {
                if !op.inputs.is_empty() {
                    return self.varnode_to_expression(&op.inputs[0]);
                }
            }
        }

        // Fallback: the indirect branch target.
        if let Some(term) = block.terminator() {
            if !term.inputs.is_empty() {
                return self.varnode_to_expression(&term.inputs[0]);
            }
        }

        Expression::variable("switch_expr", 4)
    }

    // ==================================================================
    // Block-structuring helpers
    // ==================================================================

    /// Convert a CFG basic block into a `StructuredNode::Block`.
    fn node_to_structured(&self, node: NodeIndex) -> StructuredNode {
        if node == self.cfg.exit {
            return StructuredNode::empty_block();
        }

        let block = self.cfg.block_by_node(node);
        let mut operations = Vec::new();

        for op in &block.operations {
            if op.is_terminator() {
                // Handle `return` specially: it becomes a `StructuredNode::Return`.
                if op.opcode == OpCode::RETURN {
                    let ret_expr = op
                        .inputs
                        .first()
                        .map(|v| Box::new(self.varnode_to_expression(v)));
                    return StructuredNode::Return(ret_expr);
                }
                // Other terminators (branch, cbranch) are handled by the
                // control-flow constructs; skip them here.
                continue;
            }
            operations.push(self.pcode_op_to_expression(op));
        }

        let address = block.start_address.unwrap_or(Address::NULL);

        StructuredNode::Block(BlockData {
            operations,
            address,
        })
    }

    /// Convert a CFG node to a block but strip the comparison/boolean
    /// expression that serves as the control-flow condition.
    fn node_to_structured_stripped(&self, node: NodeIndex) -> StructuredNode {
        let mut sn = self.node_to_structured(node);
        sn = self.strip_comparison_from_block(sn);
        sn
    }

    /// Remove the last expression from a block if it is a comparison/boolean
    /// operation (which is already captured by the enclosing control-flow
    /// construct).
    fn strip_comparison_from_block(&self, mut node: StructuredNode) -> StructuredNode {
        if let StructuredNode::Block(ref mut block) = node {
            if let Some(last) = block.operations.last() {
                if last.is_comparison() {
                    block.operations.pop();
                }
            }
        }
        node
    }

    // ==================================================================
    // Expression conversion
    // ==================================================================

    /// Convert a varnode to a decompiler expression.
    fn varnode_to_expression(&self, vn: &Varnode) -> Expression {
        if vn.is_constant() {
            Expression::Constant {
                value: vn.offset,
                size: vn.size,
            }
        } else if vn.is_register() {
            Expression::Variable {
                name: format!("{}_{:x}", vn.space.name, vn.offset),
                size: vn.size,
            }
        } else if vn.is_unique() {
            Expression::Variable {
                name: format!("u_{:x}", vn.offset),
                size: vn.size,
            }
        } else if vn.space.name == "ram" {
            Expression::Variable {
                name: format!("mem_{:x}", vn.offset),
                size: vn.size,
            }
        } else {
            Expression::Variable {
                name: format!("{}_{:x}", vn.space.name, vn.offset),
                size: vn.size,
            }
        }
    }

    /// Convert a P-code operation to a decompiler expression.
    fn pcode_op_to_expression(&self, op: &PcodeOperation) -> Expression {
        match op.opcode {
            // --- data movement ---
            OpCode::COPY => {
                if let (Some(ref out), Some(inp)) = (&op.output, op.inputs.first()) {
                    Expression::assign(
                        self.varnode_to_expression(out),
                        self.varnode_to_expression(inp),
                    )
                } else {
                    Expression::Nop
                }
            }

            OpCode::LOAD => {
                if op.inputs.len() >= 2 {
                    let ptr = self.varnode_to_expression(&op.inputs[1]);
                    let size = op.output.as_ref().map(|o| o.size).unwrap_or(4);
                    let deref = Expression::Dereference {
                        ptr: Box::new(ptr),
                        size,
                    };
                    if let Some(ref out) = op.output {
                        Expression::assign(self.varnode_to_expression(out), deref)
                    } else {
                        deref
                    }
                } else {
                    Expression::Nop
                }
            }

            OpCode::STORE => {
                if op.inputs.len() >= 3 {
                    let ptr = self.varnode_to_expression(&op.inputs[1]);
                    let val = self.varnode_to_expression(&op.inputs[2]);
                    let deref = Expression::Dereference {
                        ptr: Box::new(ptr),
                        size: op.inputs[2].size,
                    };
                    Expression::assign(deref, val)
                } else {
                    Expression::Nop
                }
            }

            // --- integer arithmetic ---
            OpCode::INT_ADD => self.binary_op_expr(BinaryOperator::Add, op),
            OpCode::INT_SUB => self.binary_op_expr(BinaryOperator::Sub, op),
            OpCode::INT_MUL => self.binary_op_expr(BinaryOperator::Mul, op),
            OpCode::INT_DIV => self.binary_op_expr(BinaryOperator::Div, op),
            OpCode::INT_SDIV => self.binary_op_expr(BinaryOperator::Div, op),
            OpCode::INT_REM => self.binary_op_expr(BinaryOperator::Mod, op),
            OpCode::INT_SREM => self.binary_op_expr(BinaryOperator::Mod, op),
            OpCode::INT_NEGATE => self.unary_op_expr(UnaryOperator::Neg, op),

            // --- bitwise ---
            OpCode::INT_AND => self.binary_op_expr(BinaryOperator::And, op),
            OpCode::INT_OR => self.binary_op_expr(BinaryOperator::Or, op),
            OpCode::INT_XOR => self.binary_op_expr(BinaryOperator::Xor, op),
            OpCode::INT_LEFT => self.binary_op_expr(BinaryOperator::Shl, op),
            OpCode::INT_RIGHT => self.binary_op_expr(BinaryOperator::Shr, op),
            OpCode::INT_SRIGHT => self.binary_op_expr(BinaryOperator::Shr, op),

            // --- comparisons ---
            OpCode::INT_EQUAL => self.binary_op_expr(BinaryOperator::Eq, op),
            OpCode::INT_NOTEQUAL => self.binary_op_expr(BinaryOperator::Neq, op),
            OpCode::INT_LESS => self.binary_op_expr(BinaryOperator::Lt, op),
            OpCode::INT_SLESS => self.binary_op_expr(BinaryOperator::Lt, op),
            OpCode::INT_LESSEQUAL => self.binary_op_expr(BinaryOperator::Le, op),
            OpCode::INT_SLESSEQUAL => self.binary_op_expr(BinaryOperator::Le, op),

            // --- boolean ---
            OpCode::BOOL_NEGATE => self.unary_op_expr(UnaryOperator::Not, op),
            OpCode::BOOL_AND => self.binary_op_expr(BinaryOperator::LogicalAnd, op),
            OpCode::BOOL_OR => self.binary_op_expr(BinaryOperator::LogicalOr, op),

            // --- extension ---
            OpCode::INT_ZEXT | OpCode::INT_SEXT => {
                if let (Some(ref out), Some(inp)) = (&op.output, op.inputs.first()) {
                    Expression::assign(
                        self.varnode_to_expression(out),
                        self.varnode_to_expression(inp),
                    )
                } else {
                    Expression::Nop
                }
            }

            // --- function calls ---
            OpCode::CALL | OpCode::CALLIND => {
                let target = if op.inputs.is_empty() {
                    Box::new(Expression::variable("unknown_fn", 8))
                } else {
                    Box::new(self.varnode_to_expression(&op.inputs[0]))
                };
                let args: Vec<Expression> = op.inputs[1..]
                    .iter()
                    .map(|v| self.varnode_to_expression(v))
                    .collect();

                let call_expr = Expression::Call { target, args };

                if let Some(ref out) = op.output {
                    Expression::assign(self.varnode_to_expression(out), call_expr)
                } else {
                    call_expr
                }
            }

            // --- casts / composition ---
            OpCode::CAST => {
                if let Some(inp) = op.inputs.first() {
                    let inner = self.varnode_to_expression(inp);
                    let size_name = op.output.as_ref().map(|o| o.size * 8).unwrap_or(32);
                    let cast = Expression::Cast {
                        target_type: format!("int{}_t", size_name),
                        expr: Box::new(inner),
                    };
                    if let Some(ref out) = op.output {
                        Expression::assign(self.varnode_to_expression(out), cast)
                    } else {
                        cast
                    }
                } else {
                    Expression::Nop
                }
            }

            OpCode::SUBPIECE => {
                if op.inputs.len() >= 2 {
                    let inner = self.varnode_to_expression(&op.inputs[0]);
                    let size_name = op.output.as_ref().map(|o| o.size * 8).unwrap_or(32);
                    let cast = Expression::Cast {
                        target_type: format!("int{}_t", size_name),
                        expr: Box::new(inner),
                    };
                    if let Some(ref out) = op.output {
                        Expression::assign(self.varnode_to_expression(out), cast)
                    } else {
                        cast
                    }
                } else {
                    Expression::Nop
                }
            }

            OpCode::PIECE => {
                if op.inputs.len() >= 2 {
                    let hi = self.varnode_to_expression(&op.inputs[0]);
                    let lo = self.varnode_to_expression(&op.inputs[1]);
                    let shift = Expression::BinaryOp {
                        op: BinaryOperator::Shl,
                        left: Box::new(hi),
                        right: Box::new(Expression::constant(
                            op.inputs[1].size as u64 * 8,
                            1,
                        )),
                    };
                    let or_expr = Expression::BinaryOp {
                        op: BinaryOperator::Or,
                        left: Box::new(shift),
                        right: Box::new(lo),
                    };
                    if let Some(ref out) = op.output {
                        Expression::assign(self.varnode_to_expression(out), or_expr)
                    } else {
                        or_expr
                    }
                } else {
                    Expression::Nop
                }
            }

            // --- pointer arithmetic ---
            OpCode::PTRADD => {
                if op.inputs.len() >= 2 {
                    let base = self.varnode_to_expression(&op.inputs[0]);
                    let index = self.varnode_to_expression(&op.inputs[1]);
                    let scale = if op.inputs.len() >= 3 {
                        self.varnode_to_expression(&op.inputs[2])
                    } else {
                        Expression::constant(1, 4)
                    };
                    let mul = Expression::BinaryOp {
                        op: BinaryOperator::Mul,
                        left: Box::new(index),
                        right: Box::new(scale),
                    };
                    let add = Expression::BinaryOp {
                        op: BinaryOperator::Add,
                        left: Box::new(base),
                        right: Box::new(mul),
                    };
                    if let Some(ref out) = op.output {
                        Expression::assign(self.varnode_to_expression(out), add)
                    } else {
                        add
                    }
                } else {
                    Expression::Nop
                }
            }

            OpCode::PTRSUB => self.binary_op_expr(BinaryOperator::Sub, op),

            // --- allocation ---
            OpCode::NEW => {
                if let (Some(ref out), Some(size_vn)) = (&op.output, op.inputs.first()) {
                    let call = Expression::Call {
                        target: Box::new(Expression::variable("malloc", 8)),
                        args: vec![self.varnode_to_expression(size_vn)],
                    };
                    Expression::assign(self.varnode_to_expression(out), call)
                } else {
                    Expression::Nop
                }
            }

            // --- control flow (should be filtered out earlier) ---
            OpCode::BRANCH
            | OpCode::CBRANCH
            | OpCode::BRANCHIND
            | OpCode::RETURN
            | OpCode::MULTIEQUAL
            | OpCode::INDIRECT => Expression::Nop,

            // --- fallback for unhandled opcodes ---
            _ => Expression::PcodeOp {
                opcode: op.opcode,
                inputs: op.inputs.clone(),
                output: op.output.clone(),
            },
        }
    }

    /// Convert a 2-input P-code operation to a binary expression.
    fn binary_op_expr(&self, op_type: BinaryOperator, op: &PcodeOperation) -> Expression {
        if op.inputs.len() >= 2 {
            let left = self.varnode_to_expression(&op.inputs[0]);
            let right = self.varnode_to_expression(&op.inputs[1]);
            let expr = Expression::BinaryOp {
                op: op_type,
                left: Box::new(left),
                right: Box::new(right),
            };
            if let Some(ref out) = op.output {
                Expression::assign(self.varnode_to_expression(out), expr)
            } else {
                expr
            }
        } else {
            Expression::Nop
        }
    }

    /// Convert a 1-input P-code operation to a unary expression.
    fn unary_op_expr(&self, op_type: UnaryOperator, op: &PcodeOperation) -> Expression {
        if let Some(inp) = op.inputs.first() {
            let operand = self.varnode_to_expression(inp);
            let expr = Expression::UnaryOp {
                op: op_type,
                operand: Box::new(operand),
            };
            if let Some(ref out) = op.output {
                Expression::assign(self.varnode_to_expression(out), expr)
            } else {
                expr
            }
        } else {
            Expression::Nop
        }
    }

    // ==================================================================
    // Goto handling
    // ==================================================================

    /// Create a `Goto` structured node for a given target node.
    fn make_goto(&mut self, target: NodeIndex) -> StructuredNode {
        let target_addr = self
            .cfg
            .block_by_node(target)
            .start_address
            .unwrap_or(Address::NULL);

        let label = if let Some(existing) = self.structured.labels.get(&target_addr) {
            existing.clone()
        } else {
            let lbl = format!("label_{}", self.label_counter);
            self.label_counter += 1;
            self.structured
                .labels
                .insert(target_addr, lbl.clone());
            self.structured.goto_targets.insert(target_addr);
            lbl
        };

        StructuredNode::Goto {
            target: target_addr,
            label,
        }
    }

    /// Generate a unique label name.
    fn fresh_label(&mut self) -> String {
        let lbl = format!("L{}", self.label_counter);
        self.label_counter += 1;
        lbl
    }

    /// Walk the structured tree and insert `Label` nodes at goto-target
    /// addresses.
    fn insert_labels(&mut self, node: StructuredNode) -> StructuredNode {
        let goto_targets = self.structured.goto_targets.clone();
        let labels = self.structured.labels.clone();

        if goto_targets.is_empty() {
            return node;
        }

        self.insert_labels_rec(node, &goto_targets, &labels)
    }

    /// Recursive helper for `insert_labels`.
    fn insert_labels_rec(
        &self,
        node: StructuredNode,
        targets: &HashSet<Address>,
        labels: &HashMap<Address, String>,
    ) -> StructuredNode {
        match node {
            StructuredNode::Block(ref block) => {
                // If this block starts at a goto target, wrap it in a Label.
                if targets.contains(&block.address) {
                    if let Some(name) = labels.get(&block.address) {
                        return StructuredNode::Label {
                            name: name.clone(),
                            node: Box::new(node),
                        };
                    }
                }
                node
            }
            StructuredNode::IfElse {
                condition,
                then_branch,
                else_branch,
            } => {
                let new_then = self.insert_labels_rec(*then_branch, targets, labels);
                let new_else = else_branch
                    .map(|eb| Box::new(self.insert_labels_rec(*eb, targets, labels)));
                StructuredNode::IfElse {
                    condition,
                    then_branch: Box::new(new_then),
                    else_branch: new_else,
                }
            }
            StructuredNode::While { condition, body } => StructuredNode::While {
                condition,
                body: Box::new(self.insert_labels_rec(*body, targets, labels)),
            },
            StructuredNode::DoWhile { condition, body } => StructuredNode::DoWhile {
                condition,
                body: Box::new(self.insert_labels_rec(*body, targets, labels)),
            },
            StructuredNode::For {
                init,
                condition,
                step,
                body,
            } => StructuredNode::For {
                init,
                condition,
                step,
                body: Box::new(self.insert_labels_rec(*body, targets, labels)),
            },
            StructuredNode::Switch {
                expression,
                cases,
                default,
            } => {
                let new_cases: Vec<SwitchCase> = cases
                    .into_iter()
                    .map(|c| SwitchCase {
                        values: c.values,
                        body: Box::new(self.insert_labels_rec(*c.body, targets, labels)),
                        is_fallthrough: c.is_fallthrough,
                    })
                    .collect();
                let new_default = default
                    .map(|d| Box::new(self.insert_labels_rec(*d, targets, labels)));
                StructuredNode::Switch {
                    expression,
                    cases: new_cases,
                    default: new_default,
                }
            }
            StructuredNode::Label { name, node } => StructuredNode::Label {
                name,
                node: Box::new(self.insert_labels_rec(*node, targets, labels)),
            },
            StructuredNode::InfiniteLoop { body } => StructuredNode::InfiniteLoop {
                body: Box::new(self.insert_labels_rec(*body, targets, labels)),
            },
            StructuredNode::Sequence(nodes) => {
                let new_nodes: Vec<StructuredNode> = nodes
                    .into_iter()
                    .map(|n| self.insert_labels_rec(n, targets, labels))
                    .collect();
                StructuredNode::Sequence(new_nodes)
            }
            // Leaf nodes: no children to recurse into.
            n => n,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::analysis::{BasicBlock, CfgEdge};
    use petgraph::graph::DiGraph;

    fn test_addr(offset: u64) -> Address {
        Address::new(offset)
    }

    fn make_vn_const(val: u64, size: u32) -> Varnode {
        Varnode::constant(val, size)
    }

    fn make_vn_unique(id: u64, size: u32) -> Varnode {
        Varnode::unique(id, size)
    }

    // ------------------------------------------------------------------
    // CFG construction helpers
    // ------------------------------------------------------------------

    /// Build a linear CFG: entry -> A -> exit.
    fn build_linear_cfg() -> ControlFlowGraph {
        let mut graph = DiGraph::new();
        let entry = graph.add_node(0);
        let a = graph.add_node(1);
        let exit = graph.add_node(2);

        graph.add_edge(entry, a, CfgEdge::Fallthrough);
        graph.add_edge(a, exit, CfgEdge::Fallthrough);

        let mut blocks = vec![
            BasicBlock::new(0),
            BasicBlock::new(1),
            BasicBlock::new(2),
        ];
        blocks[0].node = Some(entry);
        blocks[0].start_address = Some(test_addr(0x1000));
        blocks[1].node = Some(a);
        blocks[1].start_address = Some(test_addr(0x1004));
        blocks[2].node = Some(exit);

        ControlFlowGraph {
            graph,
            blocks,
            entry,
            exit,
        }
    }

    /// Build a diamond (if/else) CFG:
    ///   entry -> A -> B -> D -> exit
    ///             \-> C -/
    fn build_diamond_cfg() -> ControlFlowGraph {
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

        let mut blocks: Vec<BasicBlock> = (0..6)
            .map(|i| {
                let mut bb = BasicBlock::new(i);
                bb.node = Some(NodeIndex::new(i));
                bb.start_address = Some(test_addr(0x1000 + i as u64 * 4));
                bb
            })
            .collect();

        // Add a conditional branch terminator to block A (index 1).
        blocks[1].operations.push(PcodeOperation::new_unannotated(
            OpCode::CBRANCH,
            None,
            vec![
                make_vn_const(test_addr(0x1008).offset, 8),
                make_vn_const(1, 1),
            ],
        ));

        ControlFlowGraph {
            graph,
            blocks,
            entry,
            exit,
        }
    }

    /// Build a simple while-loop CFG:
    ///   entry -> header -> body -> header (back edge)
    ///                 \-> exit
    fn build_while_loop_cfg() -> ControlFlowGraph {
        let mut graph = DiGraph::new();
        let entry = graph.add_node(0);
        let header = graph.add_node(1);
        let body = graph.add_node(2);
        let exit = graph.add_node(3);

        graph.add_edge(entry, header, CfgEdge::Fallthrough);
        graph.add_edge(header, body, CfgEdge::TrueBranch);
        graph.add_edge(header, exit, CfgEdge::FalseBranch);
        graph.add_edge(body, header, CfgEdge::Branch);

        let mut blocks: Vec<BasicBlock> = (0..4)
            .map(|i| {
                let mut bb = BasicBlock::new(i);
                bb.node = Some(NodeIndex::new(i));
                bb.start_address = Some(test_addr(0x1000 + i as u64 * 4));
                bb
            })
            .collect();

        // Header: conditional branch.
        blocks[1].operations.push(PcodeOperation::new_unannotated(
            OpCode::CBRANCH,
            None,
            vec![
                make_vn_const(test_addr(0x1008).offset, 8),
                make_vn_const(1, 1),
            ],
        ));

        ControlFlowGraph {
            graph,
            blocks,
            entry,
            exit,
        }
    }

    /// Build a multi-way branch (indirect jump) CFG for switch testing.
    fn build_switch_cfg() -> ControlFlowGraph {
        let mut graph = DiGraph::new();
        let entry = graph.add_node(0);
        let sw = graph.add_node(1);
        let case1 = graph.add_node(2);
        let case2 = graph.add_node(3);
        let case3 = graph.add_node(4);
        let exit = graph.add_node(5);

        graph.add_edge(entry, sw, CfgEdge::Fallthrough);
        graph.add_edge(sw, case1, CfgEdge::Branch);
        graph.add_edge(sw, case2, CfgEdge::Branch);
        graph.add_edge(sw, case3, CfgEdge::Branch);
        graph.add_edge(case1, exit, CfgEdge::Fallthrough);
        graph.add_edge(case2, exit, CfgEdge::Fallthrough);
        graph.add_edge(case3, exit, CfgEdge::Fallthrough);

        let mut blocks: Vec<BasicBlock> = (0..6)
            .map(|i| {
                let mut bb = BasicBlock::new(i);
                bb.node = Some(NodeIndex::new(i));
                bb.start_address = Some(test_addr(0x1000 + i as u64 * 4));
                bb
            })
            .collect();

        // Add an indirect branch terminator.
        blocks[1].operations.push(PcodeOperation::new_unannotated(
            OpCode::BRANCHIND,
            None,
            vec![make_vn_unique(0, 8)],
        ));

        ControlFlowGraph {
            graph,
            blocks,
            entry,
            exit,
        }
    }

    // ------------------------------------------------------------------
    // Tests
    // ------------------------------------------------------------------

    #[test]
    fn test_structurer_creation() {
        let cfg = build_linear_cfg();
        let structurer = ControlFlowStructurer::new(cfg);
        assert!(structurer.options.prefer_switch);
        assert_eq!(structurer.options.max_switch_gap, 5);
    }

    #[test]
    fn test_structure_linear() {
        let cfg = build_linear_cfg();
        let mut structurer = ControlFlowStructurer::new(cfg);
        let result = structurer.structure();
        assert!(
            result.is_ok(),
            "structuring should succeed: {:?}",
            result.err()
        );
        let node = result.unwrap();
        // Linear CFG should produce a Sequence or Block.
        match &node {
            StructuredNode::Sequence(..) | StructuredNode::Block(..) => {}
            other => panic!(
                "Expected Sequence or Block, got {:?}",
                std::mem::discriminant(other)
            ),
        }
    }

    #[test]
    fn test_structure_diamond() {
        let cfg = build_diamond_cfg();
        let mut structurer = ControlFlowStructurer::new(cfg);
        let result = structurer.structure();
        assert!(
            result.is_ok(),
            "structuring should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_structure_while_loop() {
        let cfg = build_while_loop_cfg();
        let mut structurer = ControlFlowStructurer::new(cfg);
        let result = structurer.structure();
        assert!(
            result.is_ok(),
            "structuring should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_find_loops() {
        let cfg = build_while_loop_cfg();
        let structurer = ControlFlowStructurer::new(cfg);
        let loops = structurer.find_loops();
        assert!(!loops.is_empty(), "should find at least one loop");
    }

    #[test]
    fn test_detect_loop_type() {
        let cfg = build_while_loop_cfg();
        let structurer = ControlFlowStructurer::new(cfg);
        let loops = structurer.find_loops();
        assert!(!loops.is_empty());
        let (header, _latch) = loops[0];
        let lt = structurer.detect_loop_type(header);
        // The header has a CBRANCH, so it should be While.
        assert_eq!(lt, LoopType::While);
    }

    #[test]
    fn test_find_if_else() {
        let cfg = build_diamond_cfg();
        let structurer = ControlFlowStructurer::new(cfg);
        let a_node = NodeIndex::new(1);
        let result = structurer.find_if_else(a_node);
        assert!(result.is_some());
        let (_then_node, else_node) = result.unwrap();
        assert!(else_node.is_some());
    }

    #[test]
    fn test_switch_detection() {
        let cfg = build_switch_cfg();
        let mut structurer = ControlFlowStructurer::new(cfg);
        let result = structurer.structure();
        assert!(
            result.is_ok(),
            "switch structuring should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_expression_creation() {
        let expr = Expression::binary(
            BinaryOperator::Add,
            Expression::variable("x", 4),
            Expression::constant(1, 4),
        );
        match &expr {
            Expression::BinaryOp { op, .. } => assert_eq!(*op, BinaryOperator::Add),
            _ => panic!("Expected BinaryOp"),
        }
    }

    #[test]
    fn test_varnode_to_expression_constant() {
        let cfg = build_linear_cfg();
        let structurer = ControlFlowStructurer::new(cfg);

        let const_vn = Varnode::constant(42, 4);
        let expr = structurer.varnode_to_expression(&const_vn);
        match expr {
            Expression::Constant { value, size } => {
                assert_eq!(value, 42);
                assert_eq!(size, 4);
            }
            other => panic!("Expected Constant expression, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn test_varnode_to_expression_register() {
        let cfg = build_linear_cfg();
        let structurer = ControlFlowStructurer::new(cfg);

        let reg_vn = Varnode::register("rax", 0, 8);
        let expr = structurer.varnode_to_expression(&reg_vn);
        match expr {
            Expression::Variable { name, size } => {
                assert!(name.contains("rax"));
                assert_eq!(size, 8);
            }
            other => panic!("Expected Variable expression, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn test_structured_node_sequence_flattening() {
        let n1 = StructuredNode::Block(BlockData {
            operations: vec![],
            address: test_addr(0x1000),
        });
        let n2 = StructuredNode::Block(BlockData {
            operations: vec![],
            address: test_addr(0x1004),
        });

        // Nested Sequence should be flattened.
        let seq = StructuredNode::sequence(vec![
            StructuredNode::Sequence(vec![n1]),
            n2,
        ]);
        match seq {
            StructuredNode::Sequence(nodes) => assert_eq!(nodes.len(), 2),
            _ => {}
        }
    }

    #[test]
    fn test_structured_node_is_empty() {
        let empty_block = StructuredNode::empty_block();
        assert!(empty_block.is_empty());

        let non_empty = StructuredNode::Block(BlockData {
            operations: vec![Expression::constant(0, 4)],
            address: test_addr(0x1000),
        });
        assert!(!non_empty.is_empty());
    }

    #[test]
    fn test_expression_size_hint() {
        let var = Expression::variable("x", 8);
        assert_eq!(var.size_hint(), Some(8));

        let cnst = Expression::constant(42, 4);
        assert_eq!(cnst.size_hint(), Some(4));

        let nop = Expression::Nop;
        assert_eq!(nop.size_hint(), None);
    }

    #[test]
    fn test_expression_is_comparison() {
        let cmp = Expression::binary(
            BinaryOperator::Eq,
            Expression::variable("x", 4),
            Expression::constant(0, 4),
        );
        assert!(cmp.is_comparison());

        let not_cmp = Expression::binary(
            BinaryOperator::Add,
            Expression::variable("x", 4),
            Expression::constant(1, 4),
        );
        assert!(!not_cmp.is_comparison());

        let not_expr = Expression::unary(
            UnaryOperator::Not,
            Expression::variable("flag", 1),
        );
        assert!(not_expr.is_comparison());
    }

    #[test]
    fn test_structuring_options_default() {
        let opts = StructuringOptions::default();
        assert!(opts.prefer_switch);
        assert_eq!(opts.max_switch_gap, 5);
        assert!(opts.prefer_do_while);
        assert!(opts.prefer_for_loop);
        assert!(!opts.split_compound_conditions);
    }

    #[test]
    fn test_structurer_with_options() {
        let cfg = build_linear_cfg();
        let opts = StructuringOptions {
            prefer_switch: false,
            max_switch_gap: 10,
            prefer_do_while: false,
            prefer_for_loop: false,
            split_compound_conditions: true,
        };
        let structurer = ControlFlowStructurer::with_options(cfg, opts);
        assert!(!structurer.options.prefer_switch);
        assert_eq!(structurer.options.max_switch_gap, 10);
    }

    #[test]
    fn test_pcode_op_to_expression_int_add() {
        let cfg = build_linear_cfg();
        let structurer = ControlFlowStructurer::new(cfg);

        let op = PcodeOperation::new_unannotated(
            OpCode::INT_ADD,
            Some(make_vn_unique(0, 4)),
            vec![make_vn_const(3, 4), make_vn_const(4, 4)],
        );

        let expr = structurer.pcode_op_to_expression(&op);
        match expr {
            Expression::Assignment { rhs, .. } => match *rhs {
                Expression::BinaryOp { op: BinaryOperator::Add, .. } => {}
                other => panic!("Expected Add BinaryOp, got {:?}", std::mem::discriminant(&other)),
            },
            other => panic!("Expected Assignment, got {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn test_structurer_leaf_return() {
        // entry -> block_with_return -> exit
        let mut graph = DiGraph::new();
        let entry = graph.add_node(0);
        let ret_blk = graph.add_node(1);
        let exit = graph.add_node(2);

        graph.add_edge(entry, ret_blk, CfgEdge::Fallthrough);
        graph.add_edge(ret_blk, exit, CfgEdge::Return);

        let mut blocks = vec![
            BasicBlock::new(0),
            BasicBlock::new(1),
            BasicBlock::new(2),
        ];
        blocks[0].node = Some(entry);
        blocks[0].start_address = Some(test_addr(0x1000));
        blocks[1].node = Some(ret_blk);
        blocks[1].start_address = Some(test_addr(0x1004));
        blocks[1].operations.push(PcodeOperation::new_unannotated(
            OpCode::RETURN,
            None,
            vec![make_vn_const(42, 4)],
        ));
        blocks[2].node = Some(exit);

        let cfg = ControlFlowGraph {
            graph,
            blocks,
            entry,
            exit,
        };

        let mut structurer = ControlFlowStructurer::new(cfg);
        let result = structurer.structure();
        assert!(result.is_ok());

        let node = result.unwrap();
        // Should contain a Return node somewhere.
        let mut found_return = false;
        node.walk_preorder(&mut |n| {
            if matches!(n, StructuredNode::Return(..)) {
                found_return = true;
            }
        });
        assert!(found_return, "Expected a Return node in the structured output");
    }

    #[test]
    fn test_structured_graph_default() {
        let sg = StructuredGraph::default();
        assert!(sg.root.is_none());
        assert!(sg.labels.is_empty());
        assert!(sg.goto_targets.is_empty());
    }
}
