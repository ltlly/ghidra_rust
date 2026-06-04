//! Pcode code member visitor.
//!
//! Ported from `PcodeCodeMemberVisitor.java` in the Lisa extension.
//!
//! Visits the p-code representation of a function and constructs a
//! control flow graph (CFG) suitable for LISA abstract interpretation.
//! The visitor traverses p-code operations, building statements, edges,
//! and variable references that represent the function's dataflow.

use std::collections::{HashMap, HashSet, VecDeque};

use super::pcode_branch::{BranchKind, PcodeBranch};
use super::pcode_frontend::PcodeOp;
use super::work_item::WorkItem;

/// A pcode address identifying a specific p-code operation within an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PcodeLocation {
    /// Address of the instruction containing this p-code op.
    pub instruction_address: u64,
    /// Index of the p-code op within the instruction.
    pub sequence_number: u32,
}

impl PcodeLocation {
    /// Create a new p-code location.
    pub fn new(instruction_address: u64, sequence_number: u32) -> Self {
        Self {
            instruction_address,
            sequence_number,
        }
    }
}

/// A statement in the p-code CFG.
#[derive(Debug, Clone)]
pub struct PcodeStatement {
    /// The p-code location of this statement.
    pub location: PcodeLocation,
    /// The p-code operation.
    pub op: PcodeOp,
    /// Variable references (inputs/outputs).
    pub varnodes: Vec<VarnodeRef>,
    /// The label for display purposes.
    pub label: String,
}

impl PcodeStatement {
    /// Create a new statement.
    pub fn new(
        location: PcodeLocation,
        opcode: impl Into<String>,
        address: u64,
        varnodes: Vec<VarnodeRef>,
        label: impl Into<String>,
    ) -> Self {
        Self {
            location,
            op: PcodeOp::new(opcode, address, location.sequence_number, Vec::new(), None, 0),
            varnodes,
            label: label.into(),
        }
    }
}

/// A reference to a varnode (p-code variable).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VarnodeRef {
    /// Address space name.
    pub space: String,
    /// Offset within the address space.
    pub offset: u64,
    /// Size in bytes.
    pub size: u32,
    /// Optional variable name (from debug info).
    pub name: Option<String>,
}

impl VarnodeRef {
    /// Create a new varnode reference.
    pub fn new(space: impl Into<String>, offset: u64, size: u32) -> Self {
        Self {
            space: space.into(),
            offset,
            size,
            name: None,
        }
    }

    /// Create a named varnode reference.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Check if this is a register varnode.
    pub fn is_register(&self) -> bool {
        self.space == "register"
    }

    /// Check if this is a memory varnode.
    pub fn is_memory(&self) -> bool {
        self.space == "ram"
    }

    /// Check if this is a unique (temporary) varnode.
    pub fn is_unique(&self) -> bool {
        self.space == "unique"
    }
}

/// An edge in the p-code CFG.
#[derive(Debug, Clone)]
pub struct PcodeEdge {
    /// Source p-code location.
    pub from: PcodeLocation,
    /// Target p-code location.
    pub to: PcodeLocation,
    /// The kind of edge (sequential, conditional branch, etc.).
    pub kind: EdgeKind,
}

/// Kind of CFG edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    /// Sequential fall-through.
    Sequential,
    /// Unconditional jump.
    Unconditional,
    /// Conditional branch (true path).
    BranchTrue,
    /// Conditional branch (false path).
    BranchFalse,
    /// Call edge.
    Call,
    /// Return edge.
    Return,
}

/// A p-code CFG visitor that builds a control flow graph from p-code operations.
///
/// Ported from `PcodeCodeMemberVisitor.java`. Visits p-code operations
/// for a function and constructs a CFG with statements, edges, and
/// variable definitions.
///
/// # Example
///
/// ```ignore
/// use ghidra_features::lisa::pcode_code_member_visitor::*;
///
/// let mut visitor = PcodeCodeMemberVisitor::new(0x1000);
///
/// visitor.add_statement(PcodeStatement::new(
///     PcodeLocation::new(0x1000, 0),
///     "COPY", 0x1000,
///     vec![
///         VarnodeRef::new("register", 0, 8),     // output: RAX
///         VarnodeRef::new("const", 42, 8),       // input: constant
///     ],
///     "RAX = 42",
/// ));
///
/// visitor.add_statement(PcodeStatement::new(
///     PcodeLocation::new(0x1004, 0),
///     "STORE", 0x1004,
///     vec![
///         VarnodeRef::new("ram", 0x2000, 4),
///         VarnodeRef::new("register", 0, 4),
///     ],
///     "STORE [0x2000], EAX",
/// ));
///
/// visitor.add_edge(PcodeEdge {
///     from: PcodeLocation::new(0x1000, 0),
///     to: PcodeLocation::new(0x1004, 0),
///     kind: EdgeKind::Sequential,
/// });
///
/// assert_eq!(visitor.statements().len(), 2);
/// assert_eq!(visitor.edges().len(), 1);
/// assert_eq!(visitor.entry_point().unwrap().instruction_address, 0x1000);
/// ```
#[derive(Debug)]
pub struct PcodeCodeMemberVisitor {
    /// The function entry address.
    entry_address: u64,
    /// All statements in the CFG.
    statements: Vec<PcodeStatement>,
    /// All edges in the CFG.
    edges: Vec<PcodeEdge>,
    /// Map from p-code location to statement index.
    location_map: HashMap<PcodeLocation, usize>,
    /// Variable definitions: varnode -> list of defining locations.
    definitions: HashMap<VarnodeRef, Vec<PcodeLocation>>,
    /// Visited locations (for cycle detection).
    visited: HashSet<PcodeLocation>,
    /// Work list for fixpoint iteration.
    work_list: VecDeque<WorkItem>,
}

impl PcodeCodeMemberVisitor {
    /// Create a new visitor for the function at the given entry address.
    pub fn new(entry_address: u64) -> Self {
        Self {
            entry_address,
            statements: Vec::new(),
            edges: Vec::new(),
            location_map: HashMap::new(),
            definitions: HashMap::new(),
            visited: HashSet::new(),
            work_list: VecDeque::new(),
        }
    }

    /// Add a statement to the CFG.
    pub fn add_statement(&mut self, stmt: PcodeStatement) {
        let idx = self.statements.len();
        self.location_map.insert(stmt.location, idx);

        // Record definitions (first varnode is output in most p-code ops)
        if let Some(first) = stmt.varnodes.first() {
            self.definitions
                .entry(first.clone())
                .or_default()
                .push(stmt.location);
        }

        self.statements.push(stmt);
    }

    /// Add an edge to the CFG.
    pub fn add_edge(&mut self, edge: PcodeEdge) {
        self.edges.push(edge);
    }

    /// Get all statements.
    pub fn statements(&self) -> &[PcodeStatement] {
        &self.statements
    }

    /// Get all edges.
    pub fn edges(&self) -> &[PcodeEdge] {
        &self.edges
    }

    /// Get the entry point statement.
    pub fn entry_point(&self) -> Option<&PcodeStatement> {
        self.location_map
            .get(&PcodeLocation::new(self.entry_address, 0))
            .and_then(|&idx| self.statements.get(idx))
    }

    /// Get a statement by its p-code location.
    pub fn statement_at(&self, location: &PcodeLocation) -> Option<&PcodeStatement> {
        self.location_map
            .get(location)
            .and_then(|&idx| self.statements.get(idx))
    }

    /// Get the definitions of a varnode.
    pub fn definitions_of(&self, varnode: &VarnodeRef) -> &[PcodeLocation] {
        self.definitions
            .get(varnode)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get the successors of a given location.
    pub fn successors(&self, location: &PcodeLocation) -> Vec<&PcodeStatement> {
        self.edges
            .iter()
            .filter(|e| &e.from == location)
            .filter_map(|e| self.statement_at(&e.to))
            .collect()
    }

    /// Get the predecessors of a given location.
    pub fn predecessors(&self, location: &PcodeLocation) -> Vec<&PcodeStatement> {
        self.edges
            .iter()
            .filter(|e| &e.to == location)
            .filter_map(|e| self.statement_at(&e.from))
            .collect()
    }

    /// Mark a location as visited.
    pub fn mark_visited(&mut self, location: PcodeLocation) {
        self.visited.insert(location);
    }

    /// Check if a location has been visited.
    pub fn is_visited(&self, location: &PcodeLocation) -> bool {
        self.visited.contains(location)
    }

    /// Get the number of statements.
    pub fn num_statements(&self) -> usize {
        self.statements.len()
    }

    /// Get the number of edges.
    pub fn num_edges(&self) -> usize {
        self.edges.len()
    }

    /// Perform a simple BFS traversal from the entry point.
    pub fn bfs_from_entry(&self) -> Vec<&PcodeStatement> {
        let entry = match self.entry_point() {
            Some(e) => e.location,
            None => return Vec::new(),
        };

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut result = Vec::new();

        visited.insert(entry);
        queue.push_back(entry);

        while let Some(loc) = queue.pop_front() {
            if let Some(stmt) = self.statement_at(&loc) {
                result.push(stmt);
            }
            for successor in self.successors(&loc) {
                if visited.insert(successor.location) {
                    queue.push_back(successor.location);
                }
            }
        }

        result
    }

    /// Collect all unique varnodes referenced in the CFG.
    pub fn all_varnodes(&self) -> HashSet<&VarnodeRef> {
        let mut set = HashSet::new();
        for stmt in &self.statements {
            for vn in &stmt.varnodes {
                set.insert(vn);
            }
        }
        set
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_visitor() -> PcodeCodeMemberVisitor {
        let mut visitor = PcodeCodeMemberVisitor::new(0x1000);

        visitor.add_statement(PcodeStatement::new(
            PcodeLocation::new(0x1000, 0),
            "COPY", 0x1000,
            vec![
                VarnodeRef::new("register", 0, 8),
                VarnodeRef::new("const", 42, 8),
            ],
            "RAX = 42",
        ));

        visitor.add_statement(PcodeStatement::new(
            PcodeLocation::new(0x1004, 0),
            "INT_ADD", 0x1004,
            vec![
                VarnodeRef::new("register", 0, 8),
                VarnodeRef::new("register", 0, 8),
                VarnodeRef::new("register", 8, 8),
            ],
            "RAX = RAX + RBX",
        ));

        visitor.add_statement(PcodeStatement::new(
            PcodeLocation::new(0x1008, 0),
            "RETURN", 0x1008,
            vec![VarnodeRef::new("register", 8, 8)],
            "RETURN",
        ));

        visitor.add_edge(PcodeEdge {
            from: PcodeLocation::new(0x1000, 0),
            to: PcodeLocation::new(0x1004, 0),
            kind: EdgeKind::Sequential,
        });

        visitor.add_edge(PcodeEdge {
            from: PcodeLocation::new(0x1004, 0),
            to: PcodeLocation::new(0x1008, 0),
            kind: EdgeKind::Sequential,
        });

        visitor
    }

    #[test]
    fn test_visitor_statements() {
        let visitor = make_visitor();
        assert_eq!(visitor.num_statements(), 3);
    }

    #[test]
    fn test_visitor_edges() {
        let visitor = make_visitor();
        assert_eq!(visitor.num_edges(), 2);
    }

    #[test]
    fn test_entry_point() {
        let visitor = make_visitor();
        let entry = visitor.entry_point().unwrap();
        assert_eq!(entry.location.instruction_address, 0x1000);
        assert_eq!(entry.op.opcode, "COPY");
    }

    #[test]
    fn test_statement_at() {
        let visitor = make_visitor();
        let stmt = visitor
            .statement_at(&PcodeLocation::new(0x1004, 0))
            .unwrap();
        assert_eq!(stmt.op.opcode, "INT_ADD");
    }

    #[test]
    fn test_statement_at_missing() {
        let visitor = make_visitor();
        assert!(visitor
            .statement_at(&PcodeLocation::new(0x9999, 0))
            .is_none());
    }

    #[test]
    fn test_successors() {
        let visitor = make_visitor();
        let succs = visitor.successors(&PcodeLocation::new(0x1000, 0));
        assert_eq!(succs.len(), 1);
        assert_eq!(succs[0].location.instruction_address, 0x1004);
    }

    #[test]
    fn test_predecessors() {
        let visitor = make_visitor();
        let preds = visitor.predecessors(&PcodeLocation::new(0x1004, 0));
        assert_eq!(preds.len(), 1);
        assert_eq!(preds[0].location.instruction_address, 0x1000);
    }

    #[test]
    fn test_bfs_from_entry() {
        let visitor = make_visitor();
        let order = visitor.bfs_from_entry();
        assert_eq!(order.len(), 3);
        assert_eq!(order[0].location.instruction_address, 0x1000);
        assert_eq!(order[1].location.instruction_address, 0x1004);
        assert_eq!(order[2].location.instruction_address, 0x1008);
    }

    #[test]
    fn test_definitions() {
        let visitor = make_visitor();
        let rax = VarnodeRef::new("register", 0, 8);
        let defs = visitor.definitions_of(&rax);
        assert!(!defs.is_empty());
    }

    #[test]
    fn test_all_varnodes() {
        let visitor = make_visitor();
        let varnodes = visitor.all_varnodes();
        assert!(!varnodes.is_empty());
    }

    #[test]
    fn test_visited() {
        let mut visitor = make_visitor();
        let loc = PcodeLocation::new(0x1000, 0);
        assert!(!visitor.is_visited(&loc));
        visitor.mark_visited(loc);
        assert!(visitor.is_visited(&loc));
    }

    #[test]
    fn test_varnode_ref_properties() {
        let reg = VarnodeRef::new("register", 0, 8);
        assert!(reg.is_register());
        assert!(!reg.is_memory());

        let mem = VarnodeRef::new("ram", 0x1000, 4);
        assert!(mem.is_memory());

        let tmp = VarnodeRef::new("unique", 0, 8);
        assert!(tmp.is_unique());
    }

    #[test]
    fn test_varnode_with_name() {
        let vn = VarnodeRef::new("register", 0, 8).with_name("RAX");
        assert_eq!(vn.name.as_deref(), Some("RAX"));
    }

    #[test]
    fn test_pcode_location() {
        let loc = PcodeLocation::new(0x1000, 3);
        assert_eq!(loc.instruction_address, 0x1000);
        assert_eq!(loc.sequence_number, 3);
    }

    #[test]
    fn test_empty_visitor_bfs() {
        let visitor = PcodeCodeMemberVisitor::new(0);
        let order = visitor.bfs_from_entry();
        assert!(order.is_empty());
    }

    #[test]
    fn test_conditional_branch_edges() {
        let mut visitor = PcodeCodeMemberVisitor::new(0x1000);

        visitor.add_statement(PcodeStatement::new(
            PcodeLocation::new(0x1000, 0),
            "CBRANCH", 0x1000,
            vec![VarnodeRef::new("unique", 0, 1)],
            "CBRANCH",
        ));

        visitor.add_statement(PcodeStatement::new(
            PcodeLocation::new(0x1004, 0),
            "COPY", 0x1004,
            vec![],
            "then",
        ));

        visitor.add_statement(PcodeStatement::new(
            PcodeLocation::new(0x1008, 0),
            "COPY", 0x1008,
            vec![],
            "else",
        ));

        visitor.add_edge(PcodeEdge {
            from: PcodeLocation::new(0x1000, 0),
            to: PcodeLocation::new(0x1004, 0),
            kind: EdgeKind::BranchTrue,
        });

        visitor.add_edge(PcodeEdge {
            from: PcodeLocation::new(0x1000, 0),
            to: PcodeLocation::new(0x1008, 0),
            kind: EdgeKind::BranchFalse,
        });

        let succs = visitor.successors(&PcodeLocation::new(0x1000, 0));
        assert_eq!(succs.len(), 2);
    }
}
