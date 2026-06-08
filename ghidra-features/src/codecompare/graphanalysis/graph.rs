//! Control-flow and data-flow graph construction for the Pinning algorithm.
//!
//! Ported from Ghidra's `CtrlGraph` and `DataGraph` Java classes in
//! `ghidra.features.codecompare.graphanalysis`.
//!
//! These graphs mirror the decompiler's `HighFunction` structures but
//! unify PcodeOps and Varnodes into single node types that can carry
//! n-gram hashes for cross-function matching.
//!
//! # Key types
//!
//! - [`CtrlGraph`] -- control-flow graph built from basic blocks
//! - [`DataGraph`] -- data-flow graph built from PcodeOps and Varnodes
//! - [`GraphVertex`] -- a unified vertex in a graph
//! - [`GraphEdge`] -- a directed edge between vertices
//! - [`BasicBlockInfo`] -- metadata for a basic block

use std::collections::{HashMap, HashSet};

use super::{Side, TokenKind};

/// Metadata for a basic block in the control-flow graph.
#[derive(Debug, Clone)]
pub struct BasicBlockInfo {
    /// The start address of the basic block.
    pub start_address: u64,
    /// The end address of the basic block (inclusive).
    pub end_address: u64,
    /// Whether this block is the entry block.
    pub is_entry: bool,
    /// Whether this block is a return block.
    pub is_return: bool,
}

impl BasicBlockInfo {
    /// Create new basic block info.
    pub fn new(start_address: u64, end_address: u64) -> Self {
        Self {
            start_address,
            end_address,
            is_entry: false,
            is_return: false,
        }
    }

    /// Create entry block info.
    pub fn entry(start_address: u64, end_address: u64) -> Self {
        Self {
            start_address,
            end_address,
            is_entry: true,
            is_return: false,
        }
    }

    /// Create return block info.
    pub fn return_block(start_address: u64, end_address: u64) -> Self {
        Self {
            start_address,
            end_address,
            is_entry: false,
            is_return: true,
        }
    }

    /// The size of the block in bytes.
    pub fn size(&self) -> u64 {
        self.end_address - self.start_address + 1
    }
}

/// A directed edge in a graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphEdge {
    /// The source vertex UID.
    pub source: u32,
    /// The destination vertex UID.
    pub target: u32,
}

impl GraphEdge {
    /// Create a new graph edge.
    pub fn new(source: u32, target: u32) -> Self {
        Self { source, target }
    }
}

/// A unified vertex in either the control-flow or data-flow graph.
///
/// Combines the roles of `CtrlVertex` (basic block) and `DataVertex`
/// (PcodeOp or Varnode) into a single representation that can carry
/// n-gram hashes.
#[derive(Debug, Clone)]
pub struct GraphVertex {
    /// Unique identifier.
    pub uid: u32,
    /// Which side of the comparison this vertex belongs to.
    pub side: Side,
    /// The label or operation name.
    pub label: String,
    /// Source (incoming) vertex UIDs.
    pub sources: Vec<u32>,
    /// Sink (outgoing) vertex UIDs.
    pub sinks: Vec<u32>,
    /// The n-gram hash values for this vertex.
    pub ngram_hashes: Vec<u64>,
    /// Whether this vertex has been collapsed (removed from the graph).
    pub collapsed: bool,
    /// Whether this vertex represents an operation (vs. a variable).
    pub is_op: bool,
    /// Optional address associated with this vertex.
    pub address: Option<u64>,
}

impl GraphVertex {
    /// Create a new graph vertex.
    pub fn new(uid: u32, side: Side, label: impl Into<String>, is_op: bool) -> Self {
        Self {
            uid,
            side,
            label: label.into(),
            sources: Vec::new(),
            sinks: Vec::new(),
            ngram_hashes: Vec::new(),
            collapsed: false,
            is_op,
            address: None,
        }
    }

    /// Create a collapsed (removed) vertex.
    pub fn collapsed(uid: u32, side: Side) -> Self {
        Self {
            uid,
            side,
            label: String::new(),
            sources: Vec::new(),
            sinks: Vec::new(),
            ngram_hashes: Vec::new(),
            collapsed: true,
            is_op: false,
            address: None,
        }
    }

    /// Whether this vertex is collapsed.
    pub fn is_collapsed(&self) -> bool {
        self.collapsed
    }

    /// Collapse this vertex, removing it from the graph logically.
    pub fn collapse(&mut self) {
        self.collapsed = true;
        self.sources.clear();
        self.sinks.clear();
    }

    /// Clear computed n-gram hashes.
    pub fn clear_ngrams(&mut self) {
        self.ngram_hashes.clear();
    }

    /// Add the vertex's own label as a base n-gram (0-gram).
    ///
    /// The base hash incorporates the label identity so that vertices
    /// with different operations produce different n-gram roots.
    pub fn init_base_ngram(&mut self) {
        let mut hash: u64 = 0xcbf29ce484222325; // FNV offset basis
        for byte in self.label.bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        // Mix in the is_op flag
        hash ^= if self.is_op { 1 } else { 0 };
        hash = hash.wrapping_mul(0x100000001b3);
        self.ngram_hashes.push(hash);
    }

    /// Compute the next n-gram by walking backward through source vertices.
    ///
    /// Takes the current n-gram hash at `level` and mixes it with the
    /// source vertices' n-gram hashes at the same level to produce a
    /// new hash at `level + 1`.
    pub fn next_ngram_source(&mut self, level: usize, all_vertices: &[GraphVertex]) {
        if self.collapsed || level >= self.ngram_hashes.len() {
            return;
        }
        let base = self.ngram_hashes[level];
        let mut hash = base;
        for &src_uid in &self.sources {
            if let Some(src) = all_vertices.iter().find(|v| v.uid == src_uid && !v.collapsed) {
                if level < src.ngram_hashes.len() {
                    hash ^= src.ngram_hashes[level];
                    hash = hash.wrapping_mul(0x100000001b3);
                }
            }
        }
        self.ngram_hashes.push(hash);
    }

    /// Compute the next n-gram by walking forward through sink vertices.
    ///
    /// Similar to `next_ngram_source` but walks forward.
    pub fn next_ngram_sink(&mut self, level: usize, all_vertices: &[GraphVertex]) {
        if self.collapsed || level >= self.ngram_hashes.len() {
            return;
        }
        let base = self.ngram_hashes[level];
        let mut hash = base;
        for &sink_uid in &self.sinks {
            if let Some(sink) = all_vertices.iter().find(|v| v.uid == sink_uid && !v.collapsed) {
                if level < sink.ngram_hashes.len() {
                    hash ^= sink.ngram_hashes[level];
                    hash = hash.wrapping_mul(0x100000001b3);
                }
            }
        }
        self.ngram_hashes.push(hash);
    }
}

/// A control-flow graph for computing n-grams that can be matched
/// between two functions.
///
/// Mirrors the decompiler's basic-block graph. Vertices represent
/// basic blocks and edges represent control-flow transitions. Each
/// vertex can accumulate n-gram hashes used by the Pinning algorithm
/// to match structurally similar blocks.
///
/// Ported from Ghidra's `CtrlGraph` Java class.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::graphanalysis::graph::*;
/// use ghidra_features::codecompare::graphanalysis::Side;
///
/// let blocks = vec![
///     BasicBlockInfo::entry(0x1000, 0x1010),
///     BasicBlockInfo::new(0x1014, 0x1020),
///     BasicBlockInfo::return_block(0x1024, 0x1030),
/// ];
/// let edges = vec![
///     GraphEdge::new(0, 1),
///     GraphEdge::new(1, 2),
///     GraphEdge::new(0, 2),
/// ];
///
/// let mut graph = CtrlGraph::new(Side::Left, &blocks, &edges);
/// assert_eq!(graph.vertex_count(), 3);
/// assert_eq!(graph.edge_count(), 3);
///
/// graph.make_ngrams(8);
/// assert!(graph.get_vertex(0).unwrap().ngram_hashes.len() > 1);
/// ```
pub struct CtrlGraph {
    /// Which side of the comparison this graph belongs to.
    side: Side,
    /// The vertices (basic blocks) in the graph.
    vertices: Vec<GraphVertex>,
    /// Map from vertex UID to index in the vertices vector.
    uid_to_index: HashMap<u32, usize>,
}

impl CtrlGraph {
    /// Create a new control-flow graph from basic blocks and edges.
    ///
    /// `blocks` provides the metadata for each basic block; their index
    /// in the vector becomes the vertex UID. `edges` specifies the
    /// control-flow transitions between blocks.
    pub fn new(side: Side, blocks: &[BasicBlockInfo], edges: &[GraphEdge]) -> Self {
        let mut vertices = Vec::with_capacity(blocks.len());
        let mut uid_to_index = HashMap::new();

        for (i, block) in blocks.iter().enumerate() {
            let uid = i as u32;
            let mut vertex = GraphVertex::new(
                uid,
                side,
                format!("BB_{:04x}", block.start_address),
                true,
            );
            vertex.address = Some(block.start_address);
            uid_to_index.insert(uid, i);
            vertices.push(vertex);
        }

        // Add edges
        for edge in edges {
            if let Some(&src_idx) = uid_to_index.get(&edge.source) {
                if let Some(&tgt_idx) = uid_to_index.get(&edge.target) {
                    vertices[src_idx].sinks.push(edge.target);
                    vertices[tgt_idx].sources.push(edge.source);
                }
            }
        }

        Self {
            side,
            vertices,
            uid_to_index,
        }
    }

    /// Get the side this graph belongs to.
    pub fn side(&self) -> Side {
        self.side
    }

    /// Get the number of vertices in the graph.
    pub fn vertex_count(&self) -> usize {
        self.vertices.len()
    }

    /// Get the number of edges in the graph.
    pub fn edge_count(&self) -> usize {
        self.vertices.iter().map(|v| v.sinks.len()).sum()
    }

    /// Get a vertex by UID.
    pub fn get_vertex(&self, uid: u32) -> Option<&GraphVertex> {
        self.uid_to_index.get(&uid).map(|&idx| &self.vertices[idx])
    }

    /// Get a mutable vertex by UID.
    pub fn get_vertex_mut(&mut self, uid: u32) -> Option<&mut GraphVertex> {
        self.uid_to_index.get(&uid).map(|&idx| &mut self.vertices[idx])
    }

    /// Get all vertices.
    pub fn vertices(&self) -> &[GraphVertex] {
        &self.vertices
    }

    /// Get all non-collapsed vertices.
    pub fn active_vertices(&self) -> Vec<&GraphVertex> {
        self.vertices.iter().filter(|v| !v.collapsed).collect()
    }

    /// Clear all n-gram hashes for every vertex.
    pub fn clear_ngrams(&mut self) {
        for vertex in &mut self.vertices {
            vertex.clear_ngrams();
        }
    }

    /// Initialize the base n-gram (0-gram) for every vertex.
    fn init_base_ngrams(&mut self) {
        for vertex in &mut self.vertices {
            if !vertex.collapsed {
                vertex.init_base_ngram();
            }
        }
    }

    /// Populate n-gram lists for every vertex.
    ///
    /// Generates two types of n-grams: one walking backward through
    /// source vertices, and one walking forward through sink vertices.
    /// This produces `num_ngrams` total n-gram levels per vertex.
    ///
    /// Ported from Ghidra's `CtrlGraph.makeNGrams` Java method.
    pub fn make_ngrams(&mut self, num_ngrams: usize) {
        if num_ngrams == 0 {
            return;
        }

        self.init_base_ngrams();

        if num_ngrams == 1 {
            return;
        }

        // Phase 1: walk backward from root through sources
        let source_size = (num_ngrams - 1) / 2 + 1;
        for i in 0..source_size {
            if i >= self.vertices.len() {
                break;
            }
            // Clone to satisfy borrow checker
            let vertices_clone = self.vertices.clone();
            for vertex in &mut self.vertices {
                if !vertex.collapsed {
                    vertex.next_ngram_source(i, &vertices_clone);
                }
            }
        }

        // Phase 2: walk forward from root through sinks
        {
            let vertices_clone = self.vertices.clone();
            for vertex in &mut self.vertices {
                if !vertex.collapsed {
                    vertex.next_ngram_sink(0, &vertices_clone);
                }
            }
        }

        for i in (source_size + 1)..(num_ngrams - 1) {
            let vertices_clone = self.vertices.clone();
            for vertex in &mut self.vertices {
                if !vertex.collapsed {
                    vertex.next_ngram_sink(i, &vertices_clone);
                }
            }
        }
    }

    /// Get the entry vertex (the one with no sources).
    pub fn entry_vertex(&self) -> Option<&GraphVertex> {
        self.vertices.iter().find(|v| !v.collapsed && v.sources.is_empty())
    }

    /// Get return vertices (those with no sinks).
    pub fn return_vertices(&self) -> Vec<&GraphVertex> {
        self.vertices
            .iter()
            .filter(|v| !v.collapsed && v.sinks.is_empty())
            .collect()
    }
}

/// Configuration for constructing a data-flow graph.
#[derive(Debug, Clone)]
pub struct DataGraphConfig {
    /// Whether constant values should be factored into n-gram hashes.
    pub const_caring: bool,
    /// Whether local/global distinction should be factored into n-gram hashes.
    pub ram_caring: bool,
    /// Whether CAST operations should be collapsed from n-gram calculations.
    pub cast_collapse: bool,
    /// Whether variable sizes larger than 4 bytes should be treated as 4.
    pub size_collapse: bool,
    /// The default pointer size in bytes.
    pub pointer_size: u32,
}

impl DataGraphConfig {
    /// Create a new config with default settings.
    pub fn new() -> Self {
        Self {
            const_caring: false,
            ram_caring: true,
            cast_collapse: true,
            size_collapse: false,
            pointer_size: 4,
        }
    }

    /// Create a config for cross-architecture comparison.
    ///
    /// This enables `size_collapse` since the two architectures may
    /// have different pointer sizes.
    pub fn cross_arch(pointer_size_src: u32, pointer_size_dst: u32) -> Self {
        Self {
            const_caring: false,
            ram_caring: true,
            cast_collapse: true,
            size_collapse: pointer_size_src != pointer_size_dst,
            pointer_size: pointer_size_src.max(pointer_size_dst),
        }
    }
}

impl Default for DataGraphConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// A data-flow graph for computing n-grams that can be matched
/// between two functions.
///
/// Mirrors the decompiler's data-flow graph by unifying PcodeOps
/// and Varnodes into a single vertex type. The graph can be
/// modified (e.g., eliminating PTRSUB and CAST operations) to
/// facilitate matching across architectures.
///
/// Ported from Ghidra's `DataGraph` Java class.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::graphanalysis::graph::*;
/// use ghidra_features::codecompare::graphanalysis::Side;
///
/// let config = DataGraphConfig::new();
/// let mut graph = DataGraph::new(Side::Left, config);
///
/// // Add operation vertices
/// graph.add_op_vertex("COPY", 0x1000);
/// graph.add_op_vertex("ADD", 0x1004);
///
/// // Add variable vertices
/// graph.add_var_vertex("x", 0x1000);
/// graph.add_var_vertex("y", 0x1004);
///
/// // Add edges: COPY reads x, writes tmp; ADD reads tmp and const, writes y
/// graph.add_edge(0, 2); // COPY -> x (reads)
/// graph.add_edge(0, 3); // COPY -> y (writes)
/// graph.add_edge(1, 3); // ADD -> y (reads)
/// graph.add_edge(1, 2); // ADD -> x (writes)
///
/// assert_eq!(graph.vertex_count(), 4);
///
/// graph.make_ngrams(8);
/// assert!(graph.get_vertex(0).unwrap().ngram_hashes.len() > 1);
/// ```
pub struct DataGraph {
    /// Which side of the comparison this graph belongs to.
    side: Side,
    /// The vertices in the graph.
    vertices: Vec<GraphVertex>,
    /// Map from vertex UID to index in the vertices vector.
    uid_to_index: HashMap<u32, usize>,
    /// Configuration for n-gram generation.
    config: DataGraphConfig,
    /// Next available UID.
    next_uid: u32,
    /// Associates: map from (vertex_uid, slot) -> list of associated vertex UIDs.
    associates: HashMap<(u32, i32), Vec<u32>>,
}

impl DataGraph {
    /// Create a new empty data-flow graph.
    pub fn new(side: Side, config: DataGraphConfig) -> Self {
        Self {
            side,
            vertices: Vec::new(),
            uid_to_index: HashMap::new(),
            config,
            next_uid: 0,
            associates: HashMap::new(),
        }
    }

    /// Get the side this graph belongs to.
    pub fn side(&self) -> Side {
        self.side
    }

    /// Get the graph configuration.
    pub fn config(&self) -> &DataGraphConfig {
        &self.config
    }

    /// Get the number of vertices in the graph.
    pub fn vertex_count(&self) -> usize {
        self.vertices.len()
    }

    /// Get the number of edges in the graph.
    pub fn edge_count(&self) -> usize {
        self.vertices.iter().map(|v| v.sinks.len()).sum()
    }

    /// Add an operation vertex to the graph.
    ///
    /// Returns the UID of the new vertex.
    pub fn add_op_vertex(&mut self, label: impl Into<String>, address: u64) -> u32 {
        let uid = self.next_uid;
        self.next_uid += 1;
        let mut vertex = GraphVertex::new(uid, self.side, label, true);
        vertex.address = Some(address);
        self.uid_to_index.insert(uid, self.vertices.len());
        self.vertices.push(vertex);
        uid
    }

    /// Add a variable vertex to the graph.
    ///
    /// Returns the UID of the new vertex.
    pub fn add_var_vertex(&mut self, label: impl Into<String>, address: u64) -> u32 {
        let uid = self.next_uid;
        self.next_uid += 1;
        let mut vertex = GraphVertex::new(uid, self.side, label, false);
        vertex.address = Some(address);
        self.uid_to_index.insert(uid, self.vertices.len());
        self.vertices.push(vertex);
        uid
    }

    /// Add a directed edge from `source` to `target`.
    ///
    /// Returns `true` if the edge was added, `false` if either vertex
    /// doesn't exist.
    pub fn add_edge(&mut self, source: u32, target: u32) -> bool {
        let src_idx = match self.uid_to_index.get(&source) {
            Some(&idx) => idx,
            None => return false,
        };
        let tgt_idx = match self.uid_to_index.get(&target) {
            Some(&idx) => idx,
            None => return false,
        };

        if !self.vertices[src_idx].sinks.contains(&target) {
            self.vertices[src_idx].sinks.push(target);
        }
        if !self.vertices[tgt_idx].sources.contains(&source) {
            self.vertices[tgt_idx].sources.push(source);
        }
        true
    }

    /// Get a vertex by UID.
    pub fn get_vertex(&self, uid: u32) -> Option<&GraphVertex> {
        self.uid_to_index.get(&uid).map(|&idx| &self.vertices[idx])
    }

    /// Get a mutable vertex by UID.
    pub fn get_vertex_mut(&mut self, uid: u32) -> Option<&mut GraphVertex> {
        self.uid_to_index.get(&uid).map(|&idx| &mut self.vertices[idx])
    }

    /// Get all vertices.
    pub fn vertices(&self) -> &[GraphVertex] {
        &self.vertices
    }

    /// Get all non-collapsed vertices.
    pub fn active_vertices(&self) -> Vec<&GraphVertex> {
        self.vertices.iter().filter(|v| !v.collapsed).collect()
    }

    /// Get the associates for a given vertex and slot.
    pub fn get_associates(&self, vertex_uid: u32, slot: i32) -> Option<&Vec<u32>> {
        self.associates.get(&(vertex_uid, slot))
    }

    /// Add an association between a collapsed vertex and a remaining vertex.
    ///
    /// This is used when PTRSUB or CAST operations are eliminated: the
    /// removed vertex is associated with the vertex that replaces it,
    /// so the Pinning algorithm can still match it.
    pub fn make_association(&mut self, op_uid: u32, var_uid: u32, assoc_uid: u32, slot: i32) {
        let key = (assoc_uid, slot);
        let list = self.associates.entry(key).or_insert_with(Vec::new);
        list.push(op_uid);
        list.push(var_uid);
    }

    /// Eliminate PTRSUB operations from the graph.
    ///
    /// When a PTRSUB has input[0] == constant 0, the constant from
    /// input[1] is propagated forward to everything reading the PTRSUB,
    /// and the PTRSUB node is collapsed.
    ///
    /// Ported from Ghidra's `DataGraph.eliminatePtrsubs` Java method.
    pub fn eliminate_ptrsubs(&mut self) {
        let ptrsub_uids: Vec<u32> = self
            .vertices
            .iter()
            .filter(|v| !v.collapsed && v.is_op && v.label == "PTRSUB")
            .map(|v| v.uid)
            .collect();

        for subop_uid in ptrsub_uids {
            // Check if input[0] is a constant zero
            let sources = match self.get_vertex(subop_uid) {
                Some(v) => v.sources.clone(),
                None => continue,
            };

            if sources.len() < 2 {
                continue;
            }

            let in0_uid = sources[0];
            let in1_uid = sources[1];

            let is_const_zero = self
                .get_vertex(in0_uid)
                .map(|v| v.label == "0" || v.label == "CONST_0")
                .unwrap_or(false);

            if !is_const_zero {
                continue;
            }

            let out_uids = self
                .get_vertex(subop_uid)
                .map(|v| v.sinks.clone())
                .unwrap_or_default();

            // Disconnect in0 from its sinks
            if let Some(in0) = self.get_vertex_mut(in0_uid) {
                in0.sinks.clear();
            }

            // Replace subop's out edges with in1
            for out_uid in &out_uids {
                self.replace_source_in_vertex(*out_uid, subop_uid, in1_uid);
                if let Some(in1) = self.get_vertex_mut(in1_uid) {
                    if !in1.sinks.contains(out_uid) {
                        in1.sinks.push(*out_uid);
                    }
                }
            }

            // Collapse the removed nodes
            if let Some(in0) = self.get_vertex_mut(in0_uid) {
                in0.collapse();
            }
            if let Some(subop) = self.get_vertex_mut(subop_uid) {
                subop.collapse();
            }
            for out_uid in &out_uids {
                if let Some(out) = self.get_vertex_mut(*out_uid) {
                    out.collapse();
                }
            }

            // Record associations
            if let Some(&out_first) = out_uids.first() {
                self.make_association(subop_uid, out_first, in1_uid, 0);
            }
        }
    }

    /// Eliminate CAST operations from the graph.
    ///
    /// CAST operations are isolated and either:
    /// - The input replaces reads of the output (output eliminated), OR
    /// - The output is redefined by the input's defining op (input eliminated).
    ///
    /// Ported from Ghidra's `DataGraph.eliminateCasts` Java method.
    pub fn eliminate_casts(&mut self) {
        let cast_uids: Vec<u32> = self
            .vertices
            .iter()
            .filter(|v| !v.collapsed && v.is_op && v.label == "CAST")
            .map(|v| v.uid)
            .collect();

        for cast_uid in cast_uids {
            let sources = match self.get_vertex(cast_uid) {
                Some(v) => v.sources.clone(),
                None => continue,
            };
            let sinks = match self.get_vertex(cast_uid) {
                Some(v) => v.sinks.clone(),
                None => continue,
            };

            if sources.is_empty() || sinks.is_empty() {
                continue;
            }

            let in_uid = sources[0];
            let out_uid = sinks[0];

            // Determine association slot
            let (assoc_uid, assoc_slot) = {
                let out_sinks = self
                    .get_vertex(out_uid)
                    .map(|v| v.sinks.clone())
                    .unwrap_or_default();
                if out_sinks.len() == 1 {
                    let reader = out_sinks[0];
                    let slot = self
                        .get_vertex(reader)
                        .and_then(|v| {
                            v.sources.iter().position(|&s| s == out_uid).map(|p| p as i32)
                        })
                        .unwrap_or(0);
                    (reader, slot)
                } else {
                    (out_uid, 0i32)
                }
            };

            let in_sources = self
                .get_vertex(in_uid)
                .map(|v| v.sources.clone())
                .unwrap_or_default();
            let in_sinks = self
                .get_vertex(in_uid)
                .map(|v| v.sinks.clone())
                .unwrap_or_default();

            if in_sources.len() == 1 && in_sinks.len() == 1 {
                // Input is defined by a single op and read by a single op
                // The defining op now defines the output instead
                let top_uid = in_sources[0];

                // Disconnect top -> in
                if let Some(top) = self.get_vertex_mut(top_uid) {
                    top.sinks.clear();
                }
                if let Some(in_v) = self.get_vertex_mut(in_uid) {
                    in_v.sources.clear();
                }

                // Connect top -> out
                if let Some(top) = self.get_vertex_mut(top_uid) {
                    top.sinks.push(out_uid);
                }
                if let Some(out) = self.get_vertex_mut(out_uid) {
                    out.sources.clear();
                    out.sources.push(top_uid);
                }

                self.get_vertex_mut(in_uid).map(|v| v.collapse());
                self.make_association(cast_uid, in_uid, assoc_uid, assoc_slot);
            } else {
                // Replace out's reads with in
                self.replace_in_edges(out_uid, in_uid);
                self.get_vertex_mut(out_uid).map(|v| v.collapse());
                self.make_association(cast_uid, out_uid, assoc_uid, assoc_slot);
            }

            self.get_vertex_mut(cast_uid).map(|v| v.collapse());
        }
    }

    /// Replace all references to `old_uid` as a source in other vertices
    /// with `new_uid`.
    fn replace_source_in_vertex(&mut self, vertex_uid: u32, old_uid: u32, new_uid: u32) {
        if let Some(vertex) = self.get_vertex_mut(vertex_uid) {
            for src in &mut vertex.sources {
                if *src == old_uid {
                    *src = new_uid;
                }
            }
        }
    }

    /// Replace all references to `old_uid` in the source lists of its
    /// sinks with `new_uid`, and add the sinks to new_uid's sink list.
    fn replace_in_edges(&mut self, old_uid: u32, new_uid: u32) {
        let out_sinks = self
            .get_vertex(old_uid)
            .map(|v| v.sinks.clone())
            .unwrap_or_default();

        for sink_uid in out_sinks {
            self.replace_source_in_vertex(sink_uid, old_uid, new_uid);
            if let Some(new_v) = self.get_vertex_mut(new_uid) {
                if !new_v.sinks.contains(&sink_uid) {
                    new_v.sinks.push(sink_uid);
                }
            }
        }

        if let Some(old_v) = self.get_vertex_mut(old_uid) {
            old_v.sinks.clear();
        }
    }

    /// Remove an input edge from a vertex.
    fn remove_in_edge(&mut self, vertex_uid: u32, edge_index: usize) {
        let in_uid = match self.get_vertex(vertex_uid) {
            Some(v) => v.sources.get(edge_index).copied(),
            None => return,
        };
        let in_uid = match in_uid {
            Some(uid) => uid,
            None => return,
        };

        // Remove from source list
        if let Some(vertex) = self.get_vertex_mut(vertex_uid) {
            vertex.sources.remove(edge_index);
        }

        // Remove from sink list of the input
        if let Some(in_vertex) = self.get_vertex_mut(in_uid) {
            if let Some(pos) = in_vertex.sinks.iter().position(|&s| s == vertex_uid) {
                in_vertex.sinks.remove(pos);
            }
        }
    }

    /// Initialize the base n-gram for every non-collapsed vertex.
    fn init_base_ngrams(&mut self) {
        for vertex in &mut self.vertices {
            if !vertex.collapsed {
                vertex.init_base_ngram();
            }
        }
    }

    /// Populate n-gram lists for every non-collapsed vertex.
    ///
    /// Generates n-grams by walking backward through source vertices.
    ///
    /// Ported from Ghidra's `DataGraph.makeNGrams` Java method.
    pub fn make_ngrams(&mut self, num_ngrams: usize) {
        if num_ngrams == 0 {
            return;
        }

        self.init_base_ngrams();

        for i in 0..(num_ngrams - 1) {
            let vertices_clone = self.vertices.clone();
            for vertex in &mut self.vertices {
                if !vertex.collapsed {
                    vertex.next_ngram_source(i, &vertices_clone);
                }
            }
        }
    }

    /// Get all vertices as a HashMap keyed by UID.
    pub fn vertex_map(&self) -> HashMap<u32, &GraphVertex> {
        self.vertices.iter().map(|v| (v.uid, v)).collect()
    }
}

/// Compute a CRC32 hash for structural fingerprinting.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Compute an FNV-1a hash of a string.
pub fn fnv_hash(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in s.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- BasicBlockInfo tests ---

    #[test]
    fn test_basic_block_info() {
        let block = BasicBlockInfo::new(0x1000, 0x1010);
        assert_eq!(block.start_address, 0x1000);
        assert_eq!(block.end_address, 0x1010);
        assert_eq!(block.size(), 0x11);
        assert!(!block.is_entry);
        assert!(!block.is_return);
    }

    #[test]
    fn test_basic_block_entry() {
        let block = BasicBlockInfo::entry(0x1000, 0x1010);
        assert!(block.is_entry);
    }

    #[test]
    fn test_basic_block_return() {
        let block = BasicBlockInfo::return_block(0x1020, 0x1030);
        assert!(block.is_return);
    }

    // --- GraphVertex tests ---

    #[test]
    fn test_graph_vertex_new() {
        let v = GraphVertex::new(0, Side::Left, "ADD", true);
        assert_eq!(v.uid, 0);
        assert_eq!(v.side, Side::Left);
        assert_eq!(v.label, "ADD");
        assert!(v.is_op);
        assert!(!v.collapsed);
        assert!(v.sources.is_empty());
        assert!(v.sinks.is_empty());
    }

    #[test]
    fn test_graph_vertex_collapse() {
        let mut v = GraphVertex::new(0, Side::Left, "COPY", true);
        v.sources.push(1);
        v.sinks.push(2);
        v.collapse();
        assert!(v.is_collapsed());
        assert!(v.sources.is_empty());
        assert!(v.sinks.is_empty());
    }

    #[test]
    fn test_graph_vertex_base_ngram() {
        let mut v = GraphVertex::new(0, Side::Left, "ADD", true);
        v.init_base_ngram();
        assert_eq!(v.ngram_hashes.len(), 1);
        assert_ne!(v.ngram_hashes[0], 0);
    }

    #[test]
    fn test_graph_vertex_ngram_deterministic() {
        let mut v1 = GraphVertex::new(0, Side::Left, "ADD", true);
        let mut v2 = GraphVertex::new(0, Side::Left, "ADD", true);
        v1.init_base_ngram();
        v2.init_base_ngram();
        assert_eq!(v1.ngram_hashes[0], v2.ngram_hashes[0]);
    }

    #[test]
    fn test_graph_vertex_ngram_different_labels() {
        let mut v1 = GraphVertex::new(0, Side::Left, "ADD", true);
        let mut v2 = GraphVertex::new(0, Side::Left, "SUB", true);
        v1.init_base_ngram();
        v2.init_base_ngram();
        assert_ne!(v1.ngram_hashes[0], v2.ngram_hashes[0]);
    }

    // --- CtrlGraph tests ---

    #[test]
    fn test_ctrl_graph_basic() {
        let blocks = vec![
            BasicBlockInfo::entry(0x1000, 0x1010),
            BasicBlockInfo::new(0x1014, 0x1020),
            BasicBlockInfo::return_block(0x1024, 0x1030),
        ];
        let edges = vec![GraphEdge::new(0, 1), GraphEdge::new(1, 2)];

        let graph = CtrlGraph::new(Side::Left, &blocks, &edges);
        assert_eq!(graph.vertex_count(), 3);
        assert_eq!(graph.edge_count(), 2);
    }

    #[test]
    fn test_ctrl_graph_entry_vertex() {
        let blocks = vec![
            BasicBlockInfo::entry(0x1000, 0x1010),
            BasicBlockInfo::new(0x1014, 0x1020),
        ];
        let edges = vec![GraphEdge::new(0, 1)];

        let graph = CtrlGraph::new(Side::Right, &blocks, &edges);
        let entry = graph.entry_vertex().unwrap();
        assert_eq!(entry.uid, 0);
        assert!(entry.sources.is_empty());
    }

    #[test]
    fn test_ctrl_graph_return_vertices() {
        let blocks = vec![
            BasicBlockInfo::entry(0x1000, 0x1010),
            BasicBlockInfo::new(0x1014, 0x1020),
            BasicBlockInfo::return_block(0x1024, 0x1030),
        ];
        let edges = vec![GraphEdge::new(0, 1), GraphEdge::new(1, 2)];

        let graph = CtrlGraph::new(Side::Left, &blocks, &edges);
        let returns = graph.return_vertices();
        assert_eq!(returns.len(), 1);
        assert_eq!(returns[0].uid, 2);
    }

    #[test]
    fn test_ctrl_graph_diamond() {
        let blocks = vec![
            BasicBlockInfo::entry(0x1000, 0x1010),
            BasicBlockInfo::new(0x1014, 0x1020),
            BasicBlockInfo::new(0x1024, 0x1030),
            BasicBlockInfo::return_block(0x1034, 0x1040),
        ];
        let edges = vec![
            GraphEdge::new(0, 1),
            GraphEdge::new(0, 2),
            GraphEdge::new(1, 3),
            GraphEdge::new(2, 3),
        ];

        let graph = CtrlGraph::new(Side::Left, &blocks, &edges);
        assert_eq!(graph.vertex_count(), 4);
        assert_eq!(graph.edge_count(), 4);

        let v0 = graph.get_vertex(0).unwrap();
        assert_eq!(v0.sinks.len(), 2);
        assert_eq!(v0.sources.len(), 0);

        let v3 = graph.get_vertex(3).unwrap();
        assert_eq!(v3.sources.len(), 2);
        assert_eq!(v3.sinks.len(), 0);
    }

    #[test]
    fn test_ctrl_graph_make_ngrams() {
        let blocks = vec![
            BasicBlockInfo::entry(0x1000, 0x1010),
            BasicBlockInfo::new(0x1014, 0x1020),
            BasicBlockInfo::return_block(0x1024, 0x1030),
        ];
        let edges = vec![GraphEdge::new(0, 1), GraphEdge::new(1, 2)];

        let mut graph = CtrlGraph::new(Side::Left, &blocks, &edges);
        graph.make_ngrams(8);

        for vertex in graph.vertices() {
            assert!(
                vertex.ngram_hashes.len() > 1,
                "Vertex {} should have multiple n-grams",
                vertex.uid
            );
        }
    }

    #[test]
    fn test_ctrl_graph_empty() {
        let graph = CtrlGraph::new(Side::Left, &[], &[]);
        assert_eq!(graph.vertex_count(), 0);
        assert_eq!(graph.edge_count(), 0);
        assert!(graph.entry_vertex().is_none());
    }

    // --- DataGraph tests ---

    #[test]
    fn test_data_graph_basic() {
        let config = DataGraphConfig::new();
        let mut graph = DataGraph::new(Side::Left, config);

        let op1 = graph.add_op_vertex("COPY", 0x1000);
        let var1 = graph.add_var_vertex("x", 0x1000);

        assert_eq!(graph.vertex_count(), 2);
        graph.add_edge(op1, var1);
        assert_eq!(graph.edge_count(), 1);
    }

    #[test]
    fn test_data_graph_add_edge_invalid() {
        let config = DataGraphConfig::new();
        let mut graph = DataGraph::new(Side::Left, config);
        assert!(!graph.add_edge(99, 100));
    }

    #[test]
    fn test_data_graph_association() {
        let config = DataGraphConfig::new();
        let mut graph = DataGraph::new(Side::Left, config);

        graph.add_op_vertex("PTRSUB", 0x1000);
        graph.add_var_vertex("out", 0x1000);
        graph.add_var_vertex("data", 0x1000);

        graph.make_association(0, 1, 2, 0);
        let assoc = graph.get_associates(2, 0).unwrap();
        assert_eq!(assoc.len(), 2);
        assert_eq!(assoc[0], 0);
        assert_eq!(assoc[1], 1);
    }

    #[test]
    fn test_data_graph_make_ngrams() {
        let config = DataGraphConfig::new();
        let mut graph = DataGraph::new(Side::Left, config);

        graph.add_op_vertex("COPY", 0x1000);
        graph.add_op_vertex("ADD", 0x1004);
        graph.add_var_vertex("x", 0x1000);
        graph.add_var_vertex("y", 0x1004);

        graph.add_edge(0, 2);
        graph.add_edge(0, 3);
        graph.add_edge(1, 2);
        graph.add_edge(1, 3);

        graph.make_ngrams(8);

        for vertex in graph.vertices() {
            assert!(vertex.ngram_hashes.len() > 1);
        }
    }

    #[test]
    fn test_data_graph_ptrsub_elimination() {
        let config = DataGraphConfig::new();
        let mut graph = DataGraph::new(Side::Left, config);

        // PTRSUB(const_0, data_ptr) -> out
        let const0 = graph.add_var_vertex("0", 0x1000);
        let data_ptr = graph.add_var_vertex("DAT_1234", 0x1000);
        let ptrsub = graph.add_op_vertex("PTRSUB", 0x1000);
        let out = graph.add_var_vertex("out", 0x1000);

        graph.add_edge(const0, ptrsub);
        graph.add_edge(data_ptr, ptrsub);
        graph.add_edge(ptrsub, out);

        graph.eliminate_ptrsubs();

        // After elimination: const0 and ptrsub should be collapsed
        assert!(graph.get_vertex(const0).unwrap().is_collapsed());
        assert!(graph.get_vertex(ptrsub).unwrap().is_collapsed());
        assert!(graph.get_vertex(out).unwrap().is_collapsed());
        // data_ptr should still be active
        assert!(!graph.get_vertex(data_ptr).unwrap().is_collapsed());
    }

    #[test]
    fn test_data_graph_cast_elimination() {
        let config = DataGraphConfig::new();
        let mut graph = DataGraph::new(Side::Left, config);

        // in_var -> CAST -> out_var -> reader
        let in_var = graph.add_var_vertex("in", 0x1000);
        let cast = graph.add_op_vertex("CAST", 0x1000);
        let out_var = graph.add_var_vertex("out", 0x1000);
        let reader = graph.add_op_vertex("READ", 0x1004);

        graph.add_edge(in_var, cast);
        graph.add_edge(cast, out_var);
        graph.add_edge(out_var, reader);

        graph.eliminate_casts();

        // CAST should be collapsed
        assert!(graph.get_vertex(cast).unwrap().is_collapsed());
    }

    #[test]
    fn test_data_graph_active_vertices() {
        let config = DataGraphConfig::new();
        let mut graph = DataGraph::new(Side::Left, config);

        let op1 = graph.add_op_vertex("ADD", 0x1000);
        let var1 = graph.add_var_vertex("x", 0x1000);
        let var2 = graph.add_var_vertex("y", 0x1004);

        graph.add_edge(op1, var1);
        graph.add_edge(op1, var2);

        assert_eq!(graph.active_vertices().len(), 3);

        if let Some(v) = graph.get_vertex_mut(op1) {
            v.collapse();
        }

        assert_eq!(graph.active_vertices().len(), 2);
    }

    #[test]
    fn test_data_graph_config_cross_arch() {
        let config = DataGraphConfig::cross_arch(4, 8);
        assert!(config.size_collapse);
        assert_eq!(config.pointer_size, 8);
    }

    #[test]
    fn test_data_graph_config_same_arch() {
        let config = DataGraphConfig::cross_arch(4, 4);
        assert!(!config.size_collapse);
    }

    // --- Utility function tests ---

    #[test]
    fn test_crc32() {
        let hash = crc32(b"hello");
        assert_ne!(hash, 0);
        assert_eq!(hash, crc32(b"hello"));
        assert_ne!(hash, crc32(b"world"));
    }

    #[test]
    fn test_fnv_hash() {
        let h1 = fnv_hash("ADD");
        let h2 = fnv_hash("ADD");
        let h3 = fnv_hash("SUB");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }
}
