//! Flow-based code selection actions.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.select` package.
//!
//! Provides types for selecting code by following control flow, references,
//! and other program relationships:
//!
//! - [`SelectionType`] -- The kind of flow-based selection.
//! - [`FlowSelector`] -- Core algorithm for selecting code by following flows.
//! - [`SelectionResult`] -- The resulting address set from a selection.
//!
//! # Selection types
//!
//! - **All Flows From**: Select all reachable code from the current location.
//! - **Limited Flows From**: Follow only non-call flows from the location.
//! - **All Flows To**: Select all code that can reach the current location.
//! - **Limited Flows To**: Follow only non-call flows to the location.
//! - **Function**: Select the containing function.
//! - **Subroutine**: Select all code reachable via calls.
//! - **Dead Subroutines**: Select subroutines with no callers.
//!
//! # Usage
//!
//! ```rust
//! use ghidra_features::base::select::*;
//!
//! let flow_graph = FlowGraph::from_edges(&[
//!     (0x400000, 0x400010, FlowEdgeType::FallThrough),
//!     (0x400000, 0x400020, FlowEdgeType::Branch),
//!     (0x400010, 0x400030, FlowEdgeType::FallThrough),
//! ]);
//! let selector = FlowSelector::new(&flow_graph);
//! let result = selector.select_from(0x400000, SelectionType::AllFlowsFrom);
//! assert!(result.addresses.contains(&0x400000));
//! assert!(result.addresses.contains(&0x400010));
//! assert!(result.addresses.contains(&0x400020));
//! ```

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

/// The type of control flow edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowEdgeType {
    /// Fall-through to the next instruction.
    FallThrough,
    /// Unconditional branch.
    Branch,
    /// Conditional branch.
    ConditionalBranch,
    /// Function call.
    Call,
    /// Return from function.
    Return,
    /// Indirect jump (computed target).
    Indirect,
}

impl FlowEdgeType {
    /// Whether this edge type represents a call.
    pub fn is_call(&self) -> bool {
        matches!(self, Self::Call)
    }

    /// Whether this edge type should be followed in "limited" mode.
    ///
    /// Limited mode follows everything except calls.
    pub fn follow_in_limited_mode(&self) -> bool {
        !self.is_call()
    }
}

/// The type of selection to perform.
///
/// Ported from the selection type constants in `SelectByFlowPlugin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SelectionType {
    /// Select all code reachable from the current location (all edge types).
    AllFlowsFrom,
    /// Select code reachable via non-call flows from the current location.
    LimitedFlowsFrom,
    /// Select all code that can reach the current location (all edge types).
    AllFlowsTo,
    /// Select code that can reach via non-call flows to the current location.
    LimitedFlowsTo,
    /// Select the containing function.
    Function,
    /// Select all subroutines (call-reachable code).
    Subroutines,
    /// Select dead subroutines (subroutines with no callers).
    DeadSubroutines,
}

impl SelectionType {
    /// Human-readable name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::AllFlowsFrom => "All Flows From",
            Self::LimitedFlowsFrom => "Limited Flows From",
            Self::AllFlowsTo => "All Flows To",
            Self::LimitedFlowsTo => "Limited Flows To",
            Self::Function => "Function",
            Self::Subroutines => "Subroutines",
            Self::DeadSubroutines => "Dead Subroutines",
        }
    }
}

// ---------------------------------------------------------------------------
// Flow graph
// ---------------------------------------------------------------------------

/// An edge in the control flow graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowEdge {
    /// Source address.
    pub from: u64,
    /// Destination address.
    pub to: u64,
    /// Type of flow edge.
    pub edge_type: FlowEdgeType,
}

/// A control flow graph for selection operations.
///
/// Stores edges as an adjacency list for efficient forward and backward
/// traversal.
#[derive(Debug, Clone)]
pub struct FlowGraph {
    /// Forward adjacency list: address -> list of outgoing edges.
    forward: HashMap<u64, Vec<FlowEdge>>,
    /// Backward adjacency list: address -> list of incoming edges.
    backward: HashMap<u64, Vec<FlowEdge>>,
    /// All known addresses.
    addresses: BTreeSet<u64>,
}

impl FlowGraph {
    /// Create an empty flow graph.
    pub fn new() -> Self {
        Self {
            forward: HashMap::new(),
            backward: HashMap::new(),
            addresses: BTreeSet::new(),
        }
    }

    /// Create a flow graph from a list of (from, to, type) triples.
    pub fn from_edges(edges: &[(u64, u64, FlowEdgeType)]) -> Self {
        let mut graph = Self::new();
        for &(from, to, edge_type) in edges {
            graph.add_edge(from, to, edge_type);
        }
        graph
    }

    /// Add an edge to the flow graph.
    pub fn add_edge(&mut self, from: u64, to: u64, edge_type: FlowEdgeType) {
        let edge = FlowEdge {
            from,
            to,
            edge_type,
        };
        self.forward
            .entry(from)
            .or_default()
            .push(edge.clone());
        self.backward
            .entry(to)
            .or_default()
            .push(edge);
        self.addresses.insert(from);
        self.addresses.insert(to);
    }

    /// Get outgoing edges from an address.
    pub fn outgoing(&self, addr: u64) -> &[FlowEdge] {
        self.forward.get(&addr).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Get incoming edges to an address.
    pub fn incoming(&self, addr: u64) -> &[FlowEdge] {
        self.backward.get(&addr).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Get all addresses in the graph.
    pub fn addresses(&self) -> &BTreeSet<u64> {
        &self.addresses
    }

    /// Whether the graph contains the given address.
    pub fn contains(&self, addr: u64) -> bool {
        self.addresses.contains(&addr)
    }

    /// Get the number of edges in the graph.
    pub fn edge_count(&self) -> usize {
        self.forward.values().map(|v| v.len()).sum()
    }

    /// Get the number of vertices in the graph.
    pub fn vertex_count(&self) -> usize {
        self.addresses.len()
    }
}

impl Default for FlowGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Selection result
// ---------------------------------------------------------------------------

/// The result of a flow-based selection operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionResult {
    /// The set of selected addresses.
    pub addresses: BTreeSet<u64>,
    /// The selection type that was performed.
    pub selection_type: SelectionType,
}

impl SelectionResult {
    /// Create a new empty selection result.
    pub fn new(selection_type: SelectionType) -> Self {
        Self {
            addresses: BTreeSet::new(),
            selection_type,
        }
    }

    /// Whether the selection is empty.
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// Number of addresses selected.
    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    /// Get the minimum selected address.
    pub fn min_address(&self) -> Option<u64> {
        self.addresses.iter().next().copied()
    }

    /// Get the maximum selected address.
    pub fn max_address(&self) -> Option<u64> {
        self.addresses.iter().next_back().copied()
    }
}

// ---------------------------------------------------------------------------
// Flow selector
// /// Performs flow-based code selection on a flow graph.
///
/// Ported from the selection logic in `SelectByFlowPlugin`.
pub struct FlowSelector<'a> {
    graph: &'a FlowGraph,
}

impl<'a> FlowSelector<'a> {
    /// Create a new flow selector operating on the given graph.
    pub fn new(graph: &'a FlowGraph) -> Self {
        Self { graph }
    }

    /// Perform a selection starting from the given address.
    pub fn select_from(&self, start: u64, selection_type: SelectionType) -> SelectionResult {
        match selection_type {
            SelectionType::AllFlowsFrom => self.follow_flows_forward(start, true),
            SelectionType::LimitedFlowsFrom => self.follow_flows_forward(start, false),
            SelectionType::AllFlowsTo => self.follow_flows_backward(start, true),
            SelectionType::LimitedFlowsTo => self.follow_flows_backward(start, false),
            SelectionType::Function => self.select_function(start),
            SelectionType::Subroutines => self.select_subroutines(start),
            SelectionType::DeadSubroutines => self.select_dead_subroutines(),
        }
    }

    /// Follow all outgoing flows from the start address (BFS).
    fn follow_flows_forward(&self, start: u64, all_flows: bool) -> SelectionResult {
        let mut result = SelectionResult::new(if all_flows {
            SelectionType::AllFlowsFrom
        } else {
            SelectionType::LimitedFlowsFrom
        });

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start);
        visited.insert(start);

        while let Some(addr) = queue.pop_front() {
            result.addresses.insert(addr);

            for edge in self.graph.outgoing(addr) {
                if !all_flows && !edge.edge_type.follow_in_limited_mode() {
                    continue;
                }
                if visited.insert(edge.to) {
                    queue.push_back(edge.to);
                }
            }
        }

        result
    }

    /// Follow all incoming flows to the start address (BFS on reverse graph).
    fn follow_flows_backward(&self, start: u64, all_flows: bool) -> SelectionResult {
        let mut result = SelectionResult::new(if all_flows {
            SelectionType::AllFlowsTo
        } else {
            SelectionType::LimitedFlowsTo
        });

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start);
        visited.insert(start);

        while let Some(addr) = queue.pop_front() {
            result.addresses.insert(addr);

            for edge in self.graph.incoming(addr) {
                if !all_flows && !edge.edge_type.follow_in_limited_mode() {
                    continue;
                }
                if visited.insert(edge.from) {
                    queue.push_back(edge.from);
                }
            }
        }

        result
    }

    /// Select the function containing the start address.
    ///
    /// This is a simplified version that returns all addresses reachable
    /// from the function entry via non-call edges (the function body).
    fn select_function(&self, start: u64) -> SelectionResult {
        let mut result = SelectionResult::new(SelectionType::Function);

        // Walk backward to find the function entry (no incoming call edges).
        let entry = self.find_function_entry(start);

        // Walk forward from entry, stopping at call edges and returns.
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(entry);
        visited.insert(entry);

        while let Some(addr) = queue.pop_front() {
            result.addresses.insert(addr);

            for edge in self.graph.outgoing(addr) {
                if edge.edge_type.is_call() || edge.edge_type == FlowEdgeType::Return {
                    continue; // Don't follow calls or returns.
                }
                if visited.insert(edge.to) {
                    queue.push_back(edge.to);
                }
            }
        }

        result
    }

    /// Find the function entry by walking backward to the first address
    /// with no non-call incoming edges.
    fn find_function_entry(&self, start: u64) -> u64 {
        let mut current = start;
        loop {
            let incoming: Vec<_> = self
                .graph
                .incoming(current)
                .iter()
                .filter(|e| !e.edge_type.is_call())
                .collect();

            if incoming.len() != 1 {
                return current; // Entry point (0 or multiple non-call predecessors).
            }

            let prev = incoming[0].from;
            if prev == current {
                return current; // Self-loop.
            }
            current = prev;
        }
    }

    /// Select all subroutines reachable from the start via call edges.
    fn select_subroutines(&self, start: u64) -> SelectionResult {
        let mut result = SelectionResult::new(SelectionType::Subroutines);

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start);
        visited.insert(start);

        while let Some(addr) = queue.pop_front() {
            result.addresses.insert(addr);

            for edge in self.graph.outgoing(addr) {
                if edge.edge_type.is_call() && visited.insert(edge.to) {
                    queue.push_back(edge.to);
                }
            }
        }

        result
    }

    /// Select all addresses with no incoming call edges (dead subroutines).
    fn select_dead_subroutines(&self) -> SelectionResult {
        let mut result = SelectionResult::new(SelectionType::DeadSubroutines);

        for &addr in self.graph.addresses() {
            let has_caller = self
                .graph
                .incoming(addr)
                .iter()
                .any(|e| e.edge_type.is_call());

            if !has_caller {
                result.addresses.insert(addr);
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_graph() -> FlowGraph {
        //     400000
        //     /     \
        // 400010   400020
        //    |        |
        // 400030   400040
        //    \       /
        //    400050
        FlowGraph::from_edges(&[
            (0x400000, 0x400010, FlowEdgeType::FallThrough),
            (0x400000, 0x400020, FlowEdgeType::Branch),
            (0x400010, 0x400030, FlowEdgeType::FallThrough),
            (0x400020, 0x400040, FlowEdgeType::FallThrough),
            (0x400030, 0x400050, FlowEdgeType::Branch),
            (0x400040, 0x400050, FlowEdgeType::Branch),
        ])
    }

    #[test]
    fn test_flow_edge_type() {
        assert!(FlowEdgeType::Call.is_call());
        assert!(!FlowEdgeType::Branch.is_call());
        assert!(FlowEdgeType::Branch.follow_in_limited_mode());
        assert!(!FlowEdgeType::Call.follow_in_limited_mode());
    }

    #[test]
    fn test_selection_type_display() {
        assert_eq!(SelectionType::AllFlowsFrom.display_name(), "All Flows From");
        assert_eq!(
            SelectionType::DeadSubroutines.display_name(),
            "Dead Subroutines"
        );
    }

    #[test]
    fn test_flow_graph_construction() {
        let graph = sample_graph();
        assert_eq!(graph.vertex_count(), 6);
        assert_eq!(graph.edge_count(), 6);
        assert!(graph.contains(0x400000));
        assert!(graph.contains(0x400050));
        assert!(!graph.contains(0x500000));
    }

    #[test]
    fn test_flow_graph_outgoing() {
        let graph = sample_graph();
        let outgoing = graph.outgoing(0x400000);
        assert_eq!(outgoing.len(), 2);
    }

    #[test]
    fn test_flow_graph_incoming() {
        let graph = sample_graph();
        let incoming = graph.incoming(0x400050);
        assert_eq!(incoming.len(), 2);
    }

    #[test]
    fn test_flow_graph_no_edges() {
        let graph = FlowGraph::new();
        assert_eq!(graph.vertex_count(), 0);
        assert_eq!(graph.edge_count(), 0);
    }

    #[test]
    fn test_select_all_flows_from() {
        let graph = sample_graph();
        let selector = FlowSelector::new(&graph);
        let result = selector.select_from(0x400000, SelectionType::AllFlowsFrom);

        // All 6 addresses should be reachable.
        assert_eq!(result.len(), 6);
        assert!(result.addresses.contains(&0x400000));
        assert!(result.addresses.contains(&0x400010));
        assert!(result.addresses.contains(&0x400020));
        assert!(result.addresses.contains(&0x400030));
        assert!(result.addresses.contains(&0x400040));
        assert!(result.addresses.contains(&0x400050));
    }

    #[test]
    fn test_select_all_flows_from_branch_only() {
        let graph = FlowGraph::from_edges(&[
            (0x400000, 0x400010, FlowEdgeType::FallThrough),
            (0x400000, 0x400020, FlowEdgeType::Branch),
        ]);
        let selector = FlowSelector::new(&graph);
        let result = selector.select_from(0x400000, SelectionType::AllFlowsFrom);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_select_limited_flows_from() {
        let graph = FlowGraph::from_edges(&[
            (0x400000, 0x400010, FlowEdgeType::FallThrough),
            (0x400000, 0x400020, FlowEdgeType::Call), // Should be skipped in limited mode.
            (0x400010, 0x400030, FlowEdgeType::FallThrough),
        ]);
        let selector = FlowSelector::new(&graph);
        let result = selector.select_from(0x400000, SelectionType::LimitedFlowsFrom);

        assert_eq!(result.len(), 3); // 400000, 400010, 400030
        assert!(!result.addresses.contains(&0x400020));
    }

    #[test]
    fn test_select_all_flows_to() {
        let graph = sample_graph();
        let selector = FlowSelector::new(&graph);
        let result = selector.select_from(0x400050, SelectionType::AllFlowsTo);

        // All addresses can reach 400050.
        assert_eq!(result.len(), 6);
    }

    #[test]
    fn test_select_limited_flows_to() {
        let graph = FlowGraph::from_edges(&[
            (0x400000, 0x400010, FlowEdgeType::FallThrough),
            (0x400020, 0x400000, FlowEdgeType::Call), // Call edge should be skipped.
        ]);
        let selector = FlowSelector::new(&graph);
        let result = selector.select_from(0x400000, SelectionType::LimitedFlowsTo);

        assert_eq!(result.len(), 1); // Only 400000 itself (400020 via call is skipped).
    }

    #[test]
    fn test_select_function() {
        let graph = FlowGraph::from_edges(&[
            (0x400000, 0x400010, FlowEdgeType::FallThrough),
            (0x400010, 0x400020, FlowEdgeType::FallThrough),
            (0x400020, 0x400030, FlowEdgeType::Return), // Return stops the walk.
        ]);
        let selector = FlowSelector::new(&graph);
        let result = selector.select_from(0x400000, SelectionType::Function);

        assert!(result.addresses.contains(&0x400000));
        assert!(result.addresses.contains(&0x400010));
        assert!(result.addresses.contains(&0x400020));
        assert!(!result.addresses.contains(&0x400030)); // Return edge not followed.
    }

    #[test]
    fn test_select_subroutines() {
        let graph = FlowGraph::from_edges(&[
            (0x400000, 0x400100, FlowEdgeType::Call),
            (0x400000, 0x400010, FlowEdgeType::FallThrough),
            (0x400100, 0x400200, FlowEdgeType::Call),
        ]);
        let selector = FlowSelector::new(&graph);
        let result = selector.select_from(0x400000, SelectionType::Subroutines);

        assert!(result.addresses.contains(&0x400000));
        assert!(result.addresses.contains(&0x400100));
        assert!(result.addresses.contains(&0x400200));
        assert!(!result.addresses.contains(&0x400010)); // Not a call target.
    }

    #[test]
    fn test_select_dead_subroutines() {
        let graph = FlowGraph::from_edges(&[
            (0x400000, 0x400100, FlowEdgeType::Call),
            (0x400000, 0x400010, FlowEdgeType::FallThrough),
            (0x400300, 0x400300, FlowEdgeType::FallThrough), // Dead (no callers).
        ]);
        let selector = FlowSelector::new(&graph);
        let result = selector.select_from(0x400000, SelectionType::DeadSubroutines);

        // 400000 has no callers, 400300 has no callers, 400010 has no callers.
        // 400100 has a caller (400000 via Call).
        assert!(!result.addresses.contains(&0x400100));
        assert!(result.addresses.contains(&0x400000));
        assert!(result.addresses.contains(&0x400300));
    }

    #[test]
    fn test_selection_result_empty() {
        let result = SelectionResult::new(SelectionType::AllFlowsFrom);
        assert!(result.is_empty());
        assert_eq!(result.len(), 0);
        assert_eq!(result.min_address(), None);
        assert_eq!(result.max_address(), None);
    }

    #[test]
    fn test_selection_result_min_max() {
        let graph = FlowGraph::from_edges(&[
            (0x400000, 0x400010, FlowEdgeType::FallThrough),
        ]);
        let selector = FlowSelector::new(&graph);
        let result = selector.select_from(0x400000, SelectionType::AllFlowsFrom);
        assert_eq!(result.min_address(), Some(0x400000));
        assert_eq!(result.max_address(), Some(0x400010));
    }

    #[test]
    fn test_select_from_single_node() {
        let graph = FlowGraph::from_edges(&[]);
        // Manually add a node without edges.
        let mut graph = graph;
        graph.addresses.insert(0x400000);
        let selector = FlowSelector::new(&graph);
        let result = selector.select_from(0x400000, SelectionType::AllFlowsFrom);
        assert_eq!(result.len(), 1);
        assert!(result.addresses.contains(&0x400000));
    }

    #[test]
    fn test_flow_graph_default() {
        let graph = FlowGraph::default();
        assert_eq!(graph.vertex_count(), 0);
    }

    #[test]
    fn test_flow_graph_add_edge() {
        let mut graph = FlowGraph::new();
        graph.add_edge(100, 200, FlowEdgeType::Branch);
        assert_eq!(graph.vertex_count(), 2);
        assert_eq!(graph.edge_count(), 1);
    }
}
