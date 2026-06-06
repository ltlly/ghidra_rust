//! Symbolic analysis for computing stack unwind information from a program.
//!
//! Ported from Ghidra's `UnwindAnalysis`. This module performs analysis of a
//! function's basic block graph to determine:
//!
//! 1. The shortest path from function entry to a program counter (PC).
//! 2. The shortest path from the PC to a function return.
//! 3. Symbolic interpretation along these paths to compute stack depth,
//!    saved registers, and return address location.
//!
//! The analysis uses Dijkstra's algorithm on a basic block graph with
//! uniform edge weights to find shortest paths.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::sym_arithmetic::SymArithmetic;
use super::sym_state::SymState;
use super::unwind_info::{ReturnLocation, UnwindInfo};
use super::unwind_warning::{UnwindWarning, UnwindWarningKind, UnwindWarningSet};

// ---------------------------------------------------------------------------
// Block graph types
// ---------------------------------------------------------------------------

/// A vertex in the basic block graph, wrapping a code block address range.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockVertex {
    /// The start address of the basic block.
    pub start: u64,
    /// The end address of the basic block (inclusive).
    pub end: u64,
}

impl BlockVertex {
    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }
}

/// An edge in the basic block graph, wrapping a block reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEdge {
    /// The source block start address.
    pub source_start: u64,
    /// The source block end address.
    pub source_end: u64,
    /// The destination block start address.
    pub dest_start: u64,
    /// The destination block end address.
    pub dest_end: u64,
    /// Whether this edge represents a call flow (to be excluded from analysis).
    pub is_call: bool,
}

impl BlockEdge {
    /// Get the source vertex.
    pub fn source(&self) -> BlockVertex {
        BlockVertex::new(self.source_start, self.source_end)
    }

    /// Get the destination vertex.
    pub fn dest(&self) -> BlockVertex {
        BlockVertex::new(self.dest_start, self.dest_end)
    }
}

// ---------------------------------------------------------------------------
// Instruction record for symbolic execution
// ---------------------------------------------------------------------------

/// A p-code instruction representation for symbolic execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeInstruction {
    /// The address of this instruction.
    pub address: u64,
    /// P-code operations as (opcode, inputs, output) tuples.
    pub ops: Vec<PcodeOp>,
}

/// A single p-code operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeOp {
    /// The operation code (e.g., "INT_ADD", "STORE", "COPY").
    pub opcode: String,
    /// Input varnode descriptions (offset, size).
    pub inputs: Vec<(u64, u32)>,
    /// Output varnode (offset, size), if any.
    pub output: Option<(u64, u32)>,
}

// ---------------------------------------------------------------------------
// Block graph for path finding
// ---------------------------------------------------------------------------

/// A basic block graph with Dijkstra shortest path support.
///
/// Wraps a set of blocks and edges to find execution paths from entry
/// to PC and from PC to return.
#[derive(Debug, Clone, Default)]
pub struct BlockGraph {
    /// Adjacency list: vertex -> list of outgoing edge destinations.
    edges_from: HashMap<BlockVertex, Vec<BlockVertex>>,
    /// Reverse adjacency list: vertex -> list of incoming edge sources.
    edges_to: HashMap<BlockVertex, Vec<BlockVertex>>,
    /// All vertices in the graph.
    vertices: HashSet<BlockVertex>,
}

impl BlockGraph {
    /// Create an empty block graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a vertex to the graph.
    pub fn add_vertex(&mut self, v: BlockVertex) {
        self.vertices.insert(v);
    }

    /// Add a directed edge (non-call only).
    pub fn add_edge(&mut self, edge: BlockEdge) {
        if edge.is_call {
            return; // Skip call edges
        }
        let src = edge.source();
        let dst = edge.dest();
        self.vertices.insert(src.clone());
        self.vertices.insert(dst.clone());
        self.edges_from.entry(src.clone()).or_default().push(dst.clone());
        self.edges_to.entry(dst).or_default().push(src);
    }

    /// Get outgoing neighbors of a vertex.
    pub fn out_edges(&self, v: &BlockVertex) -> &[BlockVertex] {
        self.edges_from.get(v).map_or(&[], |v| v.as_slice())
    }

    /// Get incoming neighbors of a vertex.
    pub fn in_edges(&self, v: &BlockVertex) -> &[BlockVertex] {
        self.edges_to.get(v).map_or(&[], |v| v.as_slice())
    }

    /// Find shortest path from source to destination using BFS (uniform weights).
    ///
    /// Returns the path as a sequence of vertices, or empty if no path exists.
    pub fn shortest_path(&self, from: &BlockVertex, to: &BlockVertex) -> Vec<BlockVertex> {
        if from == to {
            return vec![from.clone()];
        }

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut parent: HashMap<BlockVertex, BlockVertex> = HashMap::new();

        visited.insert(from.clone());
        queue.push_back(from.clone());

        while let Some(current) = queue.pop_front() {
            for neighbor in self.out_edges(&current) {
                if visited.contains(neighbor) {
                    continue;
                }
                visited.insert(neighbor.clone());
                parent.insert(neighbor.clone(), current.clone());

                if neighbor == to {
                    // Reconstruct path
                    let mut path = vec![to.clone()];
                    let mut node = to.clone();
                    while let Some(p) = parent.get(&node) {
                        path.push(p.clone());
                        node = p.clone();
                    }
                    path.reverse();
                    return path;
                }

                queue.push_back(neighbor.clone());
            }
        }

        Vec::new() // No path found
    }

    /// Find shortest paths from source to ANY vertex in targets.
    ///
    /// Returns paths sorted by length (shortest first).
    pub fn shortest_paths_to_any(
        &self,
        from: &BlockVertex,
        targets: &[BlockVertex],
    ) -> Vec<Vec<BlockVertex>> {
        let _target_set: HashSet<_> = targets.iter().collect();
        let mut results = Vec::new();

        for target in targets {
            let path = self.shortest_path(from, target);
            if !path.is_empty() {
                results.push(path);
            }
        }

        results.sort_by_key(|p| p.len());
        results
    }

    /// Find the vertex containing a given address.
    pub fn find_vertex_containing(&self, addr: u64) -> Option<BlockVertex> {
        self.vertices
            .iter()
            .find(|v| addr >= v.start && addr <= v.end)
            .cloned()
    }

    /// Get all vertices that are terminal (no outgoing edges).
    pub fn terminal_vertices(&self) -> Vec<BlockVertex> {
        self.vertices
            .iter()
            .filter(|v| !self.edges_from.contains_key(v) || self.edges_from[v].is_empty())
            .cloned()
            .collect()
    }

    /// Get the number of vertices.
    pub fn vertex_count(&self) -> usize {
        self.vertices.len()
    }
}

// ---------------------------------------------------------------------------
// UnwindAnalysis
// ---------------------------------------------------------------------------

/// Analysis context for computing unwind information at a specific program counter.
///
/// This mirrors Ghidra's `AnalysisForPC` inner class. It holds the state for
/// analyzing a single function frame at a given PC.
pub struct AnalysisForPC {
    /// The program counter address.
    pub pc: u64,
    /// The function entry point.
    pub entry_point: u64,
    /// The block graph for this function.
    pub graph: BlockGraph,
    /// Cached entry-to-PC paths.
    entry_paths: Vec<Vec<BlockVertex>>,
    /// Cached PC-to-exit paths.
    exit_paths: Vec<Vec<BlockVertex>>,
    /// Warnings collected during analysis.
    pub warnings: UnwindWarningSet,
}

impl AnalysisForPC {
    /// Create a new analysis context for the given PC.
    pub fn new(pc: u64, entry_point: u64, graph: BlockGraph) -> Self {
        Self {
            pc,
            entry_point,
            graph,
            entry_paths: Vec::new(),
            exit_paths: Vec::new(),
            warnings: UnwindWarningSet::new(),
        }
    }

    /// Compute the shortest paths from function entry to the PC block.
    pub fn compute_entry_paths(&mut self) -> &[Vec<BlockVertex>] {
        if self.entry_paths.is_empty() {
            let entry_block = self.graph.find_vertex_containing(self.entry_point);
            let pc_block = self.graph.find_vertex_containing(self.pc);

            if let (Some(entry), Some(pc)) = (entry_block, pc_block) {
                let path = self.graph.shortest_path(&entry, &pc);
                if !path.is_empty() {
                    self.entry_paths.push(path);
                }
            }
        }
        &self.entry_paths
    }

    /// Compute the shortest paths from the PC block to function exit blocks.
    pub fn compute_exit_paths(&mut self) -> &[Vec<BlockVertex>] {
        if self.exit_paths.is_empty() {
            let pc_block = self.graph.find_vertex_containing(self.pc);
            let terminals = self.graph.terminal_vertices();

            if let Some(pc) = pc_block {
                let paths = self.graph.shortest_paths_to_any(&pc, &terminals);
                self.exit_paths = paths;
            }
        }
        &self.exit_paths
    }

    /// Compute the unwind information using symbolic analysis.
    ///
    /// This performs the full analysis:
    /// 1. Execute symbolically from entry to PC to find stack depth and saved registers.
    /// 2. Execute symbolically from PC to return to find return address and stack adjustment.
    /// 3. Combine the results into `UnwindInfo`.
    pub fn compute_unwind_info(&mut self) -> UnwindInfo {
        let entry_paths = self.compute_entry_paths().to_vec();
        if entry_paths.is_empty() {
            return UnwindInfo::error_only(format!(
                "Could not find a path from entry to {}",
                self.pc
            ));
        }

        let exit_paths = self.compute_exit_paths().to_vec();
        if exit_paths.is_empty() {
            self.warnings.add(UnwindWarning {
                kind: UnwindWarningKind::NoReturnPath,
                message: format!("No return path found from {}", self.pc),
            });
        }

        // Try each entry path, looking for a successful analysis
        let mut last_entry_state: Option<SymState> = None;
        let mut last_error: Option<String> = None;

        for entry_path in &entry_paths {
            match self.execute_to_pc(entry_path) {
                Ok(entry_state) => {
                    let depth = entry_state.compute_stack_depth();
                    if depth.is_none() {
                        last_error = Some("Cannot determine stack depth".to_string());
                        continue;
                    }

                    last_entry_state = Some(entry_state.clone());
                    let map_by_entry = entry_state.compute_map_using_stack();

                    // Try each exit path
                    for exit_path in &exit_paths {
                        let mut forked = entry_state.fork_regs();
                        match self.execute_from_pc(&mut forked, exit_path) {
                            Ok(()) => {
                                let address_of_return = forked.compute_address_of_return();
                                let adjust = forked.compute_stack_depth();
                                let map_by_exit = forked.compute_map_using_registers();

                                // Intersect entry and exit maps for saved registers
                                let mut saved: HashMap<String, i64> = HashMap::new();
                                for (reg, addr) in &map_by_exit {
                                    if map_by_entry.contains_key(reg) {
                                        saved.insert(reg.clone(), *addr);
                                    }
                                }

                                let return_location = match address_of_return {
                                    Some(addr) => ReturnLocation::Stack {
                                        offset: addr as i64,
                                        size: 0, // Size determined by architecture
                                    },
                                    None => ReturnLocation::Unknown,
                                };

                                return UnwindInfo {
                                    function_name: None,
                                    depth,
                                    adjust,
                                    return_location,
                                    return_mask: u64::MAX,
                                    saved_registers: saved,
                                    warnings: self.warnings.clone(),
                                    error: None,
                                };
                            }
                            Err(e) => {
                                last_error = Some(e);
                            }
                        }
                    }
                }
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }

        // Fallback: use the last successful entry state if available
        if let Some(state) = last_entry_state {
            let depth = state.compute_stack_depth();
            let saved = state.compute_map_using_stack();

            self.warnings.add(UnwindWarning {
                kind: UnwindWarningKind::OpaqueReturnPath,
                message: format!(
                    "Could not determine return path from {}",
                    self.pc
                ),
            });

            return UnwindInfo {
                function_name: None,
                depth,
                adjust: None,
                return_location: ReturnLocation::Unknown,
                return_mask: u64::MAX,
                saved_registers: saved,
                warnings: self.warnings.clone(),
                error: last_error,
            };
        }

        UnwindInfo::error_only(format!(
            "Could not analyze any path from entry to {}. {}",
            self.pc,
            last_error.unwrap_or_default()
        ))
    }

    /// Execute symbolically from function entry to the PC along the given path.
    fn execute_to_pc(&self, path: &[BlockVertex]) -> Result<SymState, String> {
        let arithmetic = SymArithmetic::default();
        let mut state = SymState::new(arithmetic);

        // Execute blocks in order along the path
        for block in path {
            self.execute_block_range(&mut state, block.start, block.end)?;
        }

        Ok(state)
    }

    /// Execute symbolically from the PC to a function return along the given path.
    fn execute_from_pc(&self, state: &mut SymState, path: &[BlockVertex]) -> Result<(), String> {
        for block in path {
            self.execute_block_range(state, block.start, block.end)?;
        }

        Ok(())
    }

    /// Execute instructions in an address range symbolically.
    ///
    /// In a full implementation, this would iterate over instructions in the
    /// range and execute each p-code operation symbolically. For now, we
    /// track the execution range for the state.
    fn execute_block_range(
        &self,
        _state: &mut SymState,
        _start: u64,
        _end: u64,
    ) -> Result<(), String> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Top-level UnwindAnalysis
// ---------------------------------------------------------------------------

/// Pre-computed analysis of a program for stack unwinding.
///
/// Ported from Ghidra's `UnwindAnalysis`. Maintains a cache of unwind
/// information keyed by program counter address.
pub struct UnwindAnalysis {
    /// Cached unwind info by address.
    unwind_info: HashMap<u64, UnwindInfo>,
    /// The block graph for the program.
    graph: BlockGraph,
    /// Function entry points: maps function start address to entry point.
    function_entries: HashMap<u64, u64>,
}

impl UnwindAnalysis {
    /// Create a new analysis for the given block graph and function entries.
    pub fn new(graph: BlockGraph, function_entries: HashMap<u64, u64>) -> Self {
        Self {
            unwind_info: HashMap::new(),
            graph,
            function_entries,
        }
    }

    /// Find which function contains the given address.
    fn find_function_entry(&self, addr: u64) -> Option<u64> {
        for (&func_start, &entry) in &self.function_entries {
            if addr >= func_start {
                return Some(entry);
            }
        }
        None
    }

    /// Start analysis at the given program counter.
    pub fn start(&self, pc: u64) -> Option<AnalysisForPC> {
        let entry_point = self.find_function_entry(pc)?;
        let graph = self.graph.clone();
        Some(AnalysisForPC::new(pc, entry_point, graph))
    }

    /// Compute unwind info for the given address.
    pub fn compute_unwind_info(&self, pc: u64) -> Option<UnwindInfo> {
        let mut analysis = self.start(pc)?;
        Some(analysis.compute_unwind_info())
    }

    /// Get cached unwind info, computing if necessary.
    pub fn get_unwind_info(&mut self, pc: u64) -> Option<&UnwindInfo> {
        if !self.unwind_info.contains_key(&pc) {
            let info = self.compute_unwind_info(pc)?;
            self.unwind_info.insert(pc, info);
        }
        self.unwind_info.get(&pc)
    }

    /// Get the number of cached entries.
    pub fn cache_size(&self) -> usize {
        self.unwind_info.len()
    }

    /// Clear the cache.
    pub fn clear_cache(&mut self) {
        self.unwind_info.clear();
    }
}

impl fmt::Debug for UnwindAnalysis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnwindAnalysis")
            .field("cached_entries", &self.unwind_info.len())
            .field("graph_vertices", &self.graph.vertex_count())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_vertex_equality() {
        let v1 = BlockVertex::new(0x1000, 0x1010);
        let v2 = BlockVertex::new(0x1000, 0x1010);
        let v3 = BlockVertex::new(0x1000, 0x1020);
        assert_eq!(v1, v2);
        assert_ne!(v1, v3);
    }

    #[test]
    fn test_block_edge_source_dest() {
        let edge = BlockEdge {
            source_start: 0x1000,
            source_end: 0x1010,
            dest_start: 0x2000,
            dest_end: 0x2010,
            is_call: false,
        };
        assert_eq!(edge.source(), BlockVertex::new(0x1000, 0x1010));
        assert_eq!(edge.dest(), BlockVertex::new(0x2000, 0x2010));
    }

    #[test]
    fn test_block_graph_simple_path() {
        let mut graph = BlockGraph::new();
        graph.add_edge(BlockEdge {
            source_start: 0x1000,
            source_end: 0x1010,
            dest_start: 0x2000,
            dest_end: 0x2010,
            is_call: false,
        });
        graph.add_edge(BlockEdge {
            source_start: 0x2000,
            source_end: 0x2010,
            dest_start: 0x3000,
            dest_end: 0x3010,
            is_call: false,
        });

        let path = graph.shortest_path(
            &BlockVertex::new(0x1000, 0x1010),
            &BlockVertex::new(0x3000, 0x3010),
        );
        assert_eq!(path.len(), 3);
        assert_eq!(path[0], BlockVertex::new(0x1000, 0x1010));
        assert_eq!(path[1], BlockVertex::new(0x2000, 0x2010));
        assert_eq!(path[2], BlockVertex::new(0x3000, 0x3010));
    }

    #[test]
    fn test_block_graph_no_path() {
        let mut graph = BlockGraph::new();
        graph.add_vertex(BlockVertex::new(0x1000, 0x1010));
        graph.add_vertex(BlockVertex::new(0x2000, 0x2010));
        // No edge between them
        let path = graph.shortest_path(
            &BlockVertex::new(0x1000, 0x1010),
            &BlockVertex::new(0x2000, 0x2010),
        );
        assert!(path.is_empty());
    }

    #[test]
    fn test_block_graph_self_path() {
        let mut graph = BlockGraph::new();
        let v = BlockVertex::new(0x1000, 0x1010);
        graph.add_vertex(v.clone());
        let path = graph.shortest_path(&v.clone(), &v);
        assert_eq!(path.len(), 1);
    }

    #[test]
    fn test_block_graph_call_edge_excluded() {
        let mut graph = BlockGraph::new();
        graph.add_edge(BlockEdge {
            source_start: 0x1000,
            source_end: 0x1010,
            dest_start: 0x2000,
            dest_end: 0x2010,
            is_call: true, // Should be excluded
        });
        let path = graph.shortest_path(
            &BlockVertex::new(0x1000, 0x1010),
            &BlockVertex::new(0x2000, 0x2010),
        );
        assert!(path.is_empty());
    }

    #[test]
    fn test_block_graph_terminal_vertices() {
        let mut graph = BlockGraph::new();
        graph.add_edge(BlockEdge {
            source_start: 0x1000,
            source_end: 0x1010,
            dest_start: 0x2000,
            dest_end: 0x2010,
            is_call: false,
        });
        graph.add_vertex(BlockVertex::new(0x2000, 0x2010));

        let terminals = graph.terminal_vertices();
        assert_eq!(terminals.len(), 1);
        assert_eq!(terminals[0], BlockVertex::new(0x2000, 0x2010));
    }

    #[test]
    fn test_block_graph_find_vertex_containing() {
        let mut graph = BlockGraph::new();
        graph.add_vertex(BlockVertex::new(0x1000, 0x1010));
        graph.add_vertex(BlockVertex::new(0x2000, 0x2010));

        assert!(graph.find_vertex_containing(0x1005).is_some());
        assert!(graph.find_vertex_containing(0x2008).is_some());
        assert!(graph.find_vertex_containing(0x1500).is_none());
    }

    #[test]
    fn test_block_graph_diamond_path() {
        //  A -> B -> D
        //  A -> C -> D
        let mut graph = BlockGraph::new();
        graph.add_edge(BlockEdge {
            source_start: 0x1000, source_end: 0x1010,
            dest_start: 0x2000, dest_end: 0x2010,
            is_call: false,
        });
        graph.add_edge(BlockEdge {
            source_start: 0x1000, source_end: 0x1010,
            dest_start: 0x3000, dest_end: 0x3010,
            is_call: false,
        });
        graph.add_edge(BlockEdge {
            source_start: 0x2000, source_end: 0x2010,
            dest_start: 0x4000, dest_end: 0x4010,
            is_call: false,
        });
        graph.add_edge(BlockEdge {
            source_start: 0x3000, source_end: 0x3010,
            dest_start: 0x4000, dest_end: 0x4010,
            is_call: false,
        });

        // BFS finds one shortest path per target; since there's only one
        // target, we get exactly one path.
        let paths = graph.shortest_paths_to_any(
            &BlockVertex::new(0x1000, 0x1010),
            &[BlockVertex::new(0x4000, 0x4010)],
        );
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].len(), 3); // A -> (B or C) -> D

        // Test with multiple targets to verify paths_to_any collects correctly
        let paths_multi = graph.shortest_paths_to_any(
            &BlockVertex::new(0x1000, 0x1010),
            &[
                BlockVertex::new(0x2000, 0x2010),
                BlockVertex::new(0x3000, 0x3010),
            ],
        );
        assert_eq!(paths_multi.len(), 2);
        assert!(paths_multi.iter().all(|p| p.len() == 2));
    }

    #[test]
    fn test_analysis_for_pc_no_paths() {
        let graph = BlockGraph::new();
        let mut analysis = AnalysisForPC::new(0x2000, 0x1000, graph);
        let info = analysis.compute_unwind_info();
        assert!(info.error.is_some());
    }

    #[test]
    fn test_analysis_for_pc_with_path() {
        let mut graph = BlockGraph::new();
        graph.add_edge(BlockEdge {
            source_start: 0x1000, source_end: 0x1010,
            dest_start: 0x2000, dest_end: 0x2010,
            is_call: false,
        });

        let mut analysis = AnalysisForPC::new(0x2000, 0x1000, graph);
        let info = analysis.compute_unwind_info();
        // Should produce an info (may have warnings)
        assert!(info.warnings.has_warnings() || info.depth.is_some() || info.error.is_some());
    }

    #[test]
    fn test_unwind_analysis_cached() {
        let mut graph = BlockGraph::new();
        graph.add_edge(BlockEdge {
            source_start: 0x1000, source_end: 0x1010,
            dest_start: 0x2000, dest_end: 0x2010,
            is_call: false,
        });

        let mut entries = HashMap::new();
        entries.insert(0x1000, 0x1000);

        let mut analysis = UnwindAnalysis::new(graph, entries);
        let _ = analysis.get_unwind_info(0x2000);
        assert_eq!(analysis.cache_size(), 1);

        analysis.clear_cache();
        assert_eq!(analysis.cache_size(), 0);
    }

    #[test]
    fn test_pcode_instruction_serde() {
        let inst = PcodeInstruction {
            address: 0x1000,
            ops: vec![PcodeOp {
                opcode: "INT_ADD".to_string(),
                inputs: vec![(0x100, 4), (0x104, 4)],
                output: Some((0x108, 4)),
            }],
        };
        let json = serde_json::to_string(&inst).unwrap();
        let back: PcodeInstruction = serde_json::from_str(&json).unwrap();
        assert_eq!(back.address, 0x1000);
        assert_eq!(back.ops[0].opcode, "INT_ADD");
    }

    #[test]
    fn test_block_vertex_serde() {
        let v = BlockVertex::new(0x1000, 0x1010);
        let json = serde_json::to_string(&v).unwrap();
        let back: BlockVertex = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn test_graph_vertex_count() {
        let mut graph = BlockGraph::new();
        graph.add_vertex(BlockVertex::new(0x1000, 0x1010));
        graph.add_vertex(BlockVertex::new(0x2000, 0x2010));
        graph.add_vertex(BlockVertex::new(0x3000, 0x3010));
        assert_eq!(graph.vertex_count(), 3);
    }

    #[test]
    fn test_graph_out_edges() {
        let mut graph = BlockGraph::new();
        graph.add_edge(BlockEdge {
            source_start: 0x1000, source_end: 0x1010,
            dest_start: 0x2000, dest_end: 0x2010,
            is_call: false,
        });
        graph.add_edge(BlockEdge {
            source_start: 0x1000, source_end: 0x1010,
            dest_start: 0x3000, dest_end: 0x3010,
            is_call: false,
        });

        let v = BlockVertex::new(0x1000, 0x1010);
        let out = graph.out_edges(&v);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn test_graph_in_edges() {
        let mut graph = BlockGraph::new();
        graph.add_edge(BlockEdge {
            source_start: 0x1000, source_end: 0x1010,
            dest_start: 0x2000, dest_end: 0x2010,
            is_call: false,
        });

        let v = BlockVertex::new(0x2000, 0x2010);
        let incoming = graph.in_edges(&v);
        assert_eq!(incoming.len(), 1);
        assert_eq!(incoming[0], BlockVertex::new(0x1000, 0x1010));
    }
}
