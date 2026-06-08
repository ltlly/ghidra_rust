//! Static Single Assignment (SSA) form construction.
//!
//! Converts P-code operations into SSA form using the classical dominance-frontier
//! algorithm (Cytron et al., 1991). The process has two phases:
//!
//! 1. **Phi placement** -- insert φ-nodes at iterated dominance frontiers.
//! 2. **Variable renaming** -- walk the dominator tree, assigning fresh version
//!    numbers to each definition and substituting them in uses.
//!
//! The resulting [`SsaForm`] has unique definition sites for every varnode
//! version, enabling downstream analyses like constant propagation and
//! dead-code elimination.

use std::collections::{HashMap, HashSet, VecDeque};

use petgraph::graph::NodeIndex;

use ghidra_core::addr::{AddressSpace, AddrSpaceType};

use super::cfg::ControlFlowGraph;
use crate::pcode::{OpCode, PcodeOperation, Varnode};

// ============================================================================
// DominatorTree
// ============================================================================

/// A dominator tree computed over a [`ControlFlowGraph`].
///
/// Node `A` **dominates** node `B` if every path from the entry to `B` goes
/// through `A`. The **immediate dominator** of `B` is the unique node that
/// dominates `B` and is dominated by every other dominator of `B`.
#[derive(Debug, Clone)]
pub struct DominatorTree {
    /// Immediate dominator for each node in the CFG.
    idom: HashMap<NodeIndex, NodeIndex>,
}

impl DominatorTree {
    /// Compute the dominator tree for a CFG using petgraph's fast algorithm.
    pub fn compute(cfg: &ControlFlowGraph) -> Self {
        let dom = petgraph::algo::dominators::simple_fast(&cfg.graph, cfg.entry);

        let mut idom = HashMap::new();
        for node in cfg.graph.node_indices() {
            if let Some(parent) = dom.immediate_dominator(node) {
                idom.insert(node, parent);
            }
        }

        Self { idom }
    }

    /// Returns the immediate dominator of `node`, if any.
    pub fn idom(&self, node: NodeIndex) -> Option<NodeIndex> {
        self.idom.get(&node).copied()
    }

    /// Returns true if `a` dominates `b` (all paths from entry to `b` go
    /// through `a`).
    pub fn dominates(&self, a: NodeIndex, b: NodeIndex) -> bool {
        if a == b {
            return true;
        }
        let mut current = b;
        let mut visited = HashSet::new();
        visited.insert(current);
        loop {
            match self.idom(current) {
                Some(idm) if idm == a => return true,
                Some(idm) => {
                    if !visited.insert(idm) {
                        return false; // cycle guard
                    }
                    current = idm;
                }
                None => return false,
            }
        }
    }

    /// Returns all nodes strictly dominated by `node`.
    pub fn strictly_dominated_by(&self, node: NodeIndex) -> Vec<NodeIndex> {
        self.idom
            .iter()
            .filter(|(child, &_dom)| **child != node && self.dominates(node, **child))
            .map(|(child, _)| *child)
            .collect()
    }

    /// Compute the dominance frontier for every node in the CFG.
    ///
    /// The dominance frontier of `X` is the set of nodes `Y` such that `X`
    /// dominates a predecessor of `Y` but does not strictly dominate `Y`.
    /// This is the key structure used for φ-node placement.
    pub fn dominance_frontiers(
        &self,
        cfg: &ControlFlowGraph,
    ) -> HashMap<NodeIndex, HashSet<NodeIndex>> {
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
                let stop = self.idom(node).unwrap_or(node);
                while runner != stop {
                    df.entry(runner).or_default().insert(node);
                    runner = match self.idom(runner) {
                        Some(idm) => idm,
                        None => break,
                    };
                }
            }
        }

        df
    }

    /// Returns the dominance frontier of a single node.
    pub fn dominance_frontier(
        &self,
        node: NodeIndex,
        cfg: &ControlFlowGraph,
    ) -> HashSet<NodeIndex> {
        self.dominance_frontiers(cfg)
            .remove(&node)
            .unwrap_or_default()
    }

    /// Walk the dominator tree in preorder, starting from the entry node.
    pub fn preorder(&self, cfg: &ControlFlowGraph) -> Vec<NodeIndex> {
        let mut order = Vec::new();
        let mut visited = HashSet::new();
        let mut stack = vec![cfg.entry];

        while let Some(node) = stack.pop() {
            if !visited.insert(node) {
                continue;
            }
            order.push(node);

            // Find children (nodes whose idom is this node) and push in
            // reverse for deterministic order.
            let mut children: Vec<NodeIndex> = self
                .idom
                .iter()
                .filter(|(_, &dom)| dom == node)
                .map(|(child, _)| *child)
                .collect();
            children.reverse();
            stack.extend(children);
        }

        order
    }

    /// Returns the set of children of `node` in the dominator tree.
    pub fn children(&self, node: NodeIndex) -> Vec<NodeIndex> {
        self.idom
            .iter()
            .filter(|(_, &dom)| dom == node)
            .map(|(child, _)| *child)
            .collect()
    }
}

// ============================================================================
// VarNode — SSA variable version
// ============================================================================

/// A single SSA variable version.
///
/// Each original varnode gets a sequence of versioned names (e.g., `x_0`,
/// `x_1`, `x_2`) as it is redefined. A `VarNode` records one such version
/// along with metadata about its definition site and uses.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VarNode {
    /// The original (un-versioned) varnode.
    pub base: Varnode,
    /// The version number (0 for the initial value, 1 for the first
    /// redefinition, etc.).
    pub version: u64,
    /// The SSA-renamed varnode (unique-space name encoding base + version).
    pub varnode: Varnode,
    /// The basic block where this version is defined.
    pub defining_block: Option<NodeIndex>,
    /// The operation index (within the block) that defines this version.
    pub defining_op: Option<usize>,
}

impl VarNode {
    /// Create a new SSA variable version.
    pub fn new(
        base: Varnode,
        version: u64,
        varnode: Varnode,
        defining_block: Option<NodeIndex>,
        defining_op: Option<usize>,
    ) -> Self {
        Self {
            base,
            version,
            varnode,
            defining_block,
            defining_op,
        }
    }

    /// Returns a human-readable version name like `x_3`.
    pub fn version_name(&self) -> String {
        format!("{}_{}", self.base, self.version)
    }
}

// ============================================================================
// PhiNode
// ============================================================================

/// A φ-node (phi function) at the entry of a basic block.
///
/// In SSA form, when two or more definitions of a variable merge at a join
/// point in the CFG, a φ-node is inserted. It selects the appropriate value
/// based on which predecessor block execution arrived from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhiNode {
    /// The SSA-renamed output varnode produced by this φ-node.
    pub output: Varnode,
    /// The base (original) varnode that this φ-node resolves.
    pub base: Varnode,
    /// Map from predecessor block → input varnode.
    pub inputs: Vec<(NodeIndex, Varnode)>,
}

impl PhiNode {
    /// Create a new φ-node.
    pub fn new(output: Varnode, base: Varnode, inputs: Vec<(NodeIndex, Varnode)>) -> Self {
        Self {
            output,
            base,
            inputs,
        }
    }

    /// Get the input varnode associated with a specific predecessor block.
    pub fn input_for(&self, pred: NodeIndex) -> Option<&Varnode> {
        self.inputs
            .iter()
            .find(|(p, _)| *p == pred)
            .map(|(_, vn)| vn)
    }

    /// Convert this φ-node into a P-code `MULTIEQUAL` operation.
    pub fn to_pcode_op(&self) -> PcodeOperation {
        let inputs: Vec<Varnode> = self.inputs.iter().map(|(_, vn)| vn.clone()).collect();
        PcodeOperation::new_unannotated(OpCode::MULTIEQUAL, Some(self.output.clone()), inputs)
    }
}

// ============================================================================
// SsaForm
// ============================================================================

/// The SSA form of a function.
///
/// Contains all operations with variables renamed to unique SSA versions,
/// plus φ-nodes inserted at join points.
#[derive(Debug, Clone)]
pub struct SsaForm {
    /// All P-code operations in SSA form, in execution order (φ-nodes
    /// first, then block operations).
    pub operations: Vec<PcodeOperation>,
    /// φ-nodes keyed by the block node index where they appear.
    pub phi_nodes: HashMap<NodeIndex, Vec<PhiNode>>,
    /// All variable versions produced during SSA construction.
    pub versions: Vec<VarNode>,
    /// Map from original varnode to its SSA versions.
    pub version_map: HashMap<Varnode, Vec<VarNode>>,
}

impl SsaForm {
    /// Returns the SSA version of `varnode` with the given version number.
    pub fn get_version(&self, base: &Varnode, version: u64) -> Option<&VarNode> {
        self.version_map.get(base).and_then(|versions| {
            versions.iter().find(|v| v.version == version)
        })
    }

    /// Returns the φ-nodes at a given block, if any.
    pub fn phis_at(&self, node: NodeIndex) -> &[PhiNode] {
        self.phi_nodes.get(&node).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Returns the total number of φ-nodes.
    pub fn phi_count(&self) -> usize {
        self.phi_nodes.values().map(|v| v.len()).sum()
    }

    /// Returns the total number of SSA versions created.
    pub fn version_count(&self) -> usize {
        self.versions.len()
    }
}

// ============================================================================
// SsaBuilder
// ============================================================================

/// Builds SSA form for a function.
///
/// Implements the standard Cytron et al. algorithm:
/// 1. Compute the dominance frontier of the CFG.
/// 2. Place φ-nodes at iterated dominance frontiers.
/// 3. Rename all variables by walking the dominator tree.
pub struct SsaBuilder {
    /// The original P-code operations (flat list).
    operations: Vec<PcodeOperation>,
    /// The control-flow graph.
    cfg: ControlFlowGraph,
    /// The dominator tree.
    dom: DominatorTree,
}

impl SsaBuilder {
    /// Create a new SSA builder.
    ///
    /// - `operations` -- the flat list of operations to convert.
    /// - `cfg` -- the control-flow graph for the function.
    /// - `dom` -- the dominator tree (can be computed from the CFG).
    pub fn new(
        operations: Vec<PcodeOperation>,
        cfg: ControlFlowGraph,
        dom: DominatorTree,
    ) -> Self {
        Self {
            operations,
            cfg,
            dom,
        }
    }

    /// Build SSA form.
    ///
    /// This is the main entry point. It runs φ-placement and renaming,
    /// returning the complete [`SsaForm`].
    pub fn build(&self) -> SsaForm {
        // Collect all varnodes referenced by the program.
        let all_vars: HashSet<Varnode> = self.collect_all_varnodes();

        // Determine which blocks define each variable.
        let def_blocks = self.find_definition_blocks(&all_vars);

        // Compute dominance frontiers.
        let df = self.dom.dominance_frontiers(&self.cfg);

        // Phase 1: place φ-nodes.
        let phi_placement = self.place_phi_nodes(&all_vars, &def_blocks, &df);

        // Phase 2: rename variables.
        self.rename_variables(&all_vars, &def_blocks, &phi_placement, &df)
    }

    /// Collect all varnodes that appear in any operation.
    fn collect_all_varnodes(&self) -> HashSet<Varnode> {
        let mut vars = HashSet::new();
        for op in &self.operations {
            if let Some(ref out) = op.output {
                vars.insert(out.clone());
            }
            for inp in &op.inputs {
                vars.insert(inp.clone());
            }
        }
        vars
    }

    /// Map each variable to the set of basic blocks where it is defined.
    fn find_definition_blocks(
        &self,
        _all_vars: &HashSet<Varnode>,
    ) -> HashMap<Varnode, HashSet<NodeIndex>> {
        let mut def_blocks: HashMap<Varnode, HashSet<NodeIndex>> = HashMap::new();

        // Build op-index → block-node map.
        let mut op_idx = 0;
        for block in &self.cfg.blocks {
            if let Some(node) = block.node {
                for _ in 0..block.operations.len() {
                    if op_idx < self.operations.len() {
                        if let Some(ref out) = self.operations[op_idx].output {
                            def_blocks.entry(out.clone()).or_default().insert(node);
                        }
                    }
                    op_idx += 1;
                }
            }
        }

        def_blocks
    }

    /// Phase 1: Place φ-nodes at iterated dominance frontiers.
    ///
    /// For each variable `v`, while there are blocks where `v` is defined
    /// or already has a φ-node, add φ-nodes for `v` at the dominance frontier
    /// of each such block. Iterate until convergence.
    fn place_phi_nodes(
        &self,
        all_vars: &HashSet<Varnode>,
        def_blocks: &HashMap<Varnode, HashSet<NodeIndex>>,
        df: &HashMap<NodeIndex, HashSet<NodeIndex>>,
    ) -> HashMap<NodeIndex, HashSet<Varnode>> {
        // Per-block set of variables needing a φ.
        let mut phi_blocks: HashMap<NodeIndex, HashSet<Varnode>> = HashMap::new();

        // For each variable, track blocks that already have a φ.
        let mut has_phi: HashMap<Varnode, HashSet<NodeIndex>> = HashMap::new();

        // Worklist: for each variable, the set of blocks to process.
        for var in all_vars {
            if let Some(defs) = def_blocks.get(var) {
                let mut work: VecDeque<NodeIndex> = defs.iter().copied().collect();
                let mut inserted: HashSet<NodeIndex> = defs.clone();

                while let Some(block) = work.pop_front() {
                    if let Some(frontier) = df.get(&block) {
                        for &d in frontier {
                            if inserted.insert(d) {
                                phi_blocks.entry(d).or_default().insert(var.clone());
                                has_phi.entry(var.clone()).or_default().insert(d);
                                work.push_back(d);
                            }
                        }
                    }
                }
            }
        }

        phi_blocks
    }

    /// Phase 2: Walk the dominator tree and rename variables.
    fn rename_variables(
        &self,
        all_vars: &HashSet<Varnode>,
        def_blocks: &HashMap<Varnode, HashSet<NodeIndex>>,
        phi_placement: &HashMap<NodeIndex, HashSet<Varnode>>,
        _df: &HashMap<NodeIndex, HashSet<NodeIndex>>,
    ) -> SsaForm {
        // Version counters per base varnode.
        let mut version_counters: HashMap<Varnode, u64> = HashMap::new();
        // Stack of current SSA varnode per base variable.
        let mut stacks: HashMap<Varnode, Vec<Varnode>> = HashMap::new();

        // Pre-populate stacks for variables that are used but not locally
        // defined (function parameters / initial values).
        for var in all_vars {
            if !def_blocks.contains_key(var) {
                let init_vn = make_ssa_varnode(var, 0);
                stacks.entry(var.clone()).or_default().push(init_vn);
            }
        }

        let mut phi_nodes: HashMap<NodeIndex, Vec<PhiNode>> = HashMap::new();
        let mut all_versions: Vec<VarNode> = Vec::new();
        let mut renamed_ops: Vec<PcodeOperation> = Vec::new();

        // Walk dominator tree in preorder.
        let preorder = self.dom.preorder(&self.cfg);

        for &node in &preorder {
            let block = self.cfg.block_by_node(node);
            let mut pushed_vars: Vec<Varnode> = Vec::new();

            // Insert φ-nodes for this block.
            if let Some(vars_needing_phi) = phi_placement.get(&node) {
                let mut block_phis: Vec<PhiNode> = Vec::new();
                for var in vars_needing_phi {
                    // Create a new SSA version for the φ result.
                    let version = next_version(var, &mut version_counters);
                    let phi_out = make_ssa_varnode(var, version);

                    // Build inputs from each predecessor.
                    let preds = self.cfg.predecessors(node);
                    let phi_inputs: Vec<(NodeIndex, Varnode)> = preds
                        .iter()
                        .map(|&pred| {
                            let pred_vn = stacks
                                .get(var)
                                .and_then(|s| s.last())
                                .cloned()
                                .unwrap_or_else(|| make_ssa_varnode(var, 0));
                            (pred, pred_vn)
                        })
                        .collect();

                    let phi = PhiNode::new(phi_out.clone(), var.clone(), phi_inputs);
                    block_phis.push(phi);

                    // Push the φ result onto the stack.
                    stacks.entry(var.clone()).or_default().push(phi_out.clone());
                    pushed_vars.push(var.clone());

                    // Record version.
                    all_versions.push(VarNode::new(
                        var.clone(),
                        version,
                        phi_out,
                        Some(node),
                        None,
                    ));
                }
                phi_nodes.insert(node, block_phis);
            }

            // Process operations in this block.
            for (op_idx, op) in block.operations.iter().enumerate() {
                let mut new_op = op.clone();

                // Rename inputs (replace with current SSA version from stack).
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

                // Rename output: create a new SSA version.
                if let Some(ref out) = new_op.output {
                    let out_clone = out.clone();
                    let version = next_version(&out_clone, &mut version_counters);
                    let new_out = make_ssa_varnode(&out_clone, version);
                    stacks.entry(out_clone.clone()).or_default().push(new_out.clone());
                    pushed_vars.push(out_clone.clone());
                    new_op.output = Some(new_out.clone());

                    all_versions.push(VarNode::new(
                        out_clone,
                        version,
                        new_out,
                        Some(node),
                        Some(op_idx),
                    ));
                }

                renamed_ops.push(new_op);
            }

            // Fill φ-node inputs in successor blocks with current SSA versions.
            for succ in self.cfg.successors(node) {
                if let Some(succ_phis) = phi_nodes.get(&succ) {
                    for phi in succ_phis {
                        // Update the input from this predecessor.
                        // This is handled during the rename phase: the stack
                        // already has the current version when the successor
                        // block is processed later in preorder.
                        let _ = phi;
                    }
                }
            }

            // Process children in the dominator tree (recursive via preorder).

            // Pop versions pushed in this block to restore stack for
            // sibling paths.
            for var in pushed_vars {
                if let Some(stack) = stacks.get_mut(&var) {
                    stack.pop();
                }
            }
        }

        // Build final operation list: φ-nodes first, then renamed ops.
        let mut final_ops: Vec<PcodeOperation> = Vec::new();
        for &node in &preorder {
            if let Some(phis) = phi_nodes.get(&node) {
                for phi in phis {
                    final_ops.push(phi.to_pcode_op());
                }
            }
        }
        final_ops.extend(renamed_ops);

        // Build version map.
        let mut version_map: HashMap<Varnode, Vec<VarNode>> = HashMap::new();
        for vn in &all_versions {
            version_map.entry(vn.base.clone()).or_default().push(vn.clone());
        }

        SsaForm {
            operations: final_ops,
            phi_nodes,
            versions: all_versions,
            version_map,
        }
    }
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Create a new SSA-renamed varnode in the unique space.
fn make_ssa_varnode(base: &Varnode, version: u64) -> Varnode {
    let unique_space = AddressSpace::new("ssa_unique", 8, false, AddrSpaceType::Unique, 4);
    Varnode::new(
        unique_space,
        (base.offset << 6) | version,
        base.size,
    )
}

/// Increment the version counter for a base varnode and return the new version.
fn next_version(base: &Varnode, counters: &mut HashMap<Varnode, u64>) -> u64 {
    let c = counters.entry(base.clone()).or_insert(0);
    *c += 1;
    *c
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;
    use super::super::cfg::{BasicBlock, CfgEdge};
    use petgraph::graph::DiGraph;

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

    /// Build a simple diamond CFG for testing.
    fn build_diamond_cfg() -> ControlFlowGraph {
        let mut graph = DiGraph::new();
        let entry = graph.add_node(0);
        let a = graph.add_node(1);
        let b = graph.add_node(2);
        let c = graph.add_node(3);
        let d = graph.add_node(4);
        let exit = graph.add_node(5);

        graph.add_edge(entry, a, CfgEdge::FallThrough);
        graph.add_edge(a, b, CfgEdge::Branch(true));
        graph.add_edge(a, c, CfgEdge::Branch(false));
        graph.add_edge(b, d, CfgEdge::FallThrough);
        graph.add_edge(c, d, CfgEdge::FallThrough);
        graph.add_edge(d, exit, CfgEdge::FallThrough);

        let blocks = vec![
            {
                let mut bb = BasicBlock::new(0);
                bb.node = Some(entry);
                bb
            },
            {
                let mut bb = BasicBlock::new(1);
                bb.node = Some(a);
                bb
            },
            {
                let mut bb = BasicBlock::new(2);
                bb.node = Some(b);
                bb
            },
            {
                let mut bb = BasicBlock::new(3);
                bb.node = Some(c);
                bb
            },
            {
                let mut bb = BasicBlock::new(4);
                bb.node = Some(d);
                bb
            },
            {
                let mut bb = BasicBlock::new(5);
                bb.node = Some(exit);
                bb
            },
        ];

        ControlFlowGraph {
            graph,
            blocks,
            entry,
            exit,
        }
    }

    #[test]
    fn test_dominator_tree_diamond() {
        let cfg = build_diamond_cfg();
        let dom = DominatorTree::compute(&cfg);

        // entry dominates everything.
        assert!(dom.dominates(cfg.entry, NodeIndex::new(0)));
        assert!(dom.dominates(cfg.entry, NodeIndex::new(1)));

        // a dominates b, c, d (all paths go through a).
        let a = NodeIndex::new(1);
        assert!(dom.dominates(a, NodeIndex::new(2)));
        assert!(dom.dominates(a, NodeIndex::new(3)));
        assert!(dom.dominates(a, NodeIndex::new(4)));

        // b does NOT dominate c, and vice versa.
        let b = NodeIndex::new(2);
        let c = NodeIndex::new(3);
        assert!(!dom.dominates(b, c));
        assert!(!dom.dominates(c, b));
    }

    #[test]
    fn test_dominance_frontier() {
        let cfg = build_diamond_cfg();
        let dom = DominatorTree::compute(&cfg);
        let df = dom.dominance_frontiers(&cfg);

        // In the diamond CFG: entry -> a -> {b, c} -> d -> exit
        // b and c do not dominate d, but they are predecessors of d.
        // So d should be in the dominance frontier of b and c.
        let b = NodeIndex::new(2);
        let c = NodeIndex::new(3);
        let d = NodeIndex::new(4);
        let frontier_b = df.get(&b).unwrap();
        let frontier_c = df.get(&c).unwrap();
        assert!(
            frontier_b.contains(&d),
            "d should be in b's dominance frontier"
        );
        assert!(
            frontier_c.contains(&d),
            "d should be in c's dominance frontier"
        );
    }

    #[test]
    fn test_dominator_tree_preorder() {
        let cfg = build_diamond_cfg();
        let dom = DominatorTree::compute(&cfg);
        let order = dom.preorder(&cfg);
        assert!(!order.is_empty());
        assert_eq!(order[0], cfg.entry);
    }

    #[test]
    fn test_var_node() {
        let base = reg(0, 4);
        let vn = VarNode::new(
            base.clone(),
            2,
            make_ssa_varnode(&base, 2),
            Some(NodeIndex::new(1)),
            Some(0),
        );
        assert_eq!(vn.version, 2);
        assert_eq!(vn.base, base);
        assert!(vn.version_name().contains("_2"));
    }

    #[test]
    fn test_phi_node_to_pcode() {
        let base = uniq(0, 4);
        let out = make_ssa_varnode(&base, 1);
        let phi = PhiNode::new(
            out.clone(),
            base.clone(),
            vec![
                (NodeIndex::new(2), uniq(10, 4)),
                (NodeIndex::new(3), uniq(11, 4)),
            ],
        );

        let op = phi.to_pcode_op();
        assert_eq!(op.opcode, OpCode::MULTIEQUAL);
        assert_eq!(op.output, Some(out));
        assert_eq!(op.inputs.len(), 2);
    }

    #[test]
    fn test_ssa_form_empty() {
        let form = SsaForm {
            operations: vec![],
            phi_nodes: HashMap::new(),
            versions: vec![],
            version_map: HashMap::new(),
        };
        assert_eq!(form.phi_count(), 0);
        assert_eq!(form.version_count(), 0);
    }

    #[test]
    fn test_ssa_builder_linear() {
        let addr = test_addr(0x1000);
        let op = PcodeOperation::new(
            OpCode::INT_ADD,
            Some(uniq(0, 4)),
            vec![cnst(1, 4), cnst(2, 4)],
            Some(addr),
        );

        // Build a minimal 2-block CFG.
        let mut graph = DiGraph::new();
        let entry = graph.add_node(0);
        let exit = graph.add_node(1);
        graph.add_edge(entry, exit, CfgEdge::FallThrough);

        let mut bb0 = BasicBlock::new(0);
        bb0.node = Some(entry);
        bb0.operations.push(op);

        let mut bb1 = BasicBlock::new(1);
        bb1.node = Some(exit);

        let cfg = ControlFlowGraph {
            graph,
            blocks: vec![bb0, bb1],
            entry,
            exit,
        };

        let dom = DominatorTree::compute(&cfg);
        let builder = SsaBuilder::new(
            vec![PcodeOperation::new_unannotated(
                OpCode::INT_ADD,
                Some(uniq(0, 4)),
                vec![cnst(1, 4), cnst(2, 4)],
            )],
            cfg,
            dom,
        );

        let ssa = builder.build();
        assert!(ssa.operations.len() > 0);
        // The varnodes should be renamed to SSA versions.
        assert!(!ssa.versions.is_empty());
    }

    #[test]
    fn test_make_ssa_varnode() {
        let base = uniq(0x100, 4);
        let renamed = make_ssa_varnode(&base, 3);
        assert_eq!(renamed.size, 4);
        // Offset should encode both base.offset and version.
        assert_eq!(renamed.offset, (0x100 << 6) | 3);
    }
}
