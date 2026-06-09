//! Function Reachability -- graph-based reachability analysis.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.reachability` Java package.
//!
//! Computes whether one function can reach another through its call graph.
//! Provides shortest-path computation and reachable-function enumeration.
//!
//! # Architecture
//!
//! - [`ReachabilityGraph`] -- a directed graph of function call relationships.
//! - [`ReachabilityResult`] -- a single path between two functions.
//! - [`ReachabilityAnalyzer`] -- computes reachability between functions.

/// Reachability table model and result types.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.reachability` table classes.
pub mod table;

/// Function reachability graph model: vertices, edges, path finding.
///
/// Ported from `ghidra.app.plugin.core.reachability.FRVertex`,
/// `FREdge`, `FRPathsModel`, and `FunctionReachabilityResult`.
pub mod graph;

/// Function reachability plugin -- top-level plugin coordinating providers.
///
/// Ported from `ghidra.app.plugin.core.reachability.FunctionReachabilityPlugin`.
pub mod reachability_plugin;

/// Function reachability provider -- manages analysis UI state.
///
/// Ported from `ghidra.app.plugin.core.reachability.FunctionReachabilityProvider`.
pub mod reachability_provider;

use ghidra_core::Address;
use std::collections::{HashMap, HashSet, VecDeque};

// ============================================================================
// ReachabilityResult -- a path between two functions
// ============================================================================

/// A single reachable path between a source and target function.
#[derive(Debug, Clone)]
pub struct ReachabilityResult {
    /// The ordered list of function addresses forming the path.
    pub path: Vec<Address>,
    /// The path length (number of edges).
    pub path_length: usize,
}

impl ReachabilityResult {
    /// Create a new reachability result.
    pub fn new(path: Vec<Address>) -> Self {
        let path_length = if path.is_empty() { 0 } else { path.len() - 1 };
        Self {
            path,
            path_length,
        }
    }
}

// ============================================================================
// FRVertex / FREdge -- graph elements (ported from Java)
// ============================================================================

/// A vertex in the reachability graph (a function).
#[derive(Debug, Clone)]
pub struct FRVertex {
    /// The function name.
    pub name: String,
    /// The function address.
    pub address: Address,
}

impl FRVertex {
    /// Create a new FR vertex.
    pub fn new(name: impl Into<String>, address: Address) -> Self {
        Self {
            name: name.into(),
            address,
        }
    }
}

/// An edge in the reachability graph (a call relationship).
#[derive(Debug, Clone)]
pub struct FREdge {
    /// The caller address.
    pub from: Address,
    /// The callee address.
    pub to: Address,
    /// Edge weight (default 1).
    pub weight: f64,
}

impl FREdge {
    /// Create a new edge.
    pub fn new(from: Address, to: Address) -> Self {
        Self {
            from,
            to,
            weight: 1.0,
        }
    }
}

// ============================================================================
// ReachabilityGraph -- directed graph of function call relationships
// ============================================================================

/// A directed graph representing function call relationships.
///
/// Supports BFS shortest-path queries and reachability enumeration.
#[derive(Debug, Default)]
pub struct ReachabilityGraph {
    /// Adjacency list: address -> list of callee addresses.
    edges: HashMap<u64, Vec<u64>>,
    /// Function metadata: address -> (name, address).
    vertices: HashMap<u64, FRVertex>,
}

impl ReachabilityGraph {
    /// Create a new empty reachability graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a function vertex to the graph.
    pub fn add_vertex(&mut self, vertex: FRVertex) {
        self.vertices.insert(vertex.address.offset, vertex);
    }

    /// Add a directed edge (caller -> callee).
    pub fn add_edge(&mut self, from: Address, to: Address) {
        self.edges
            .entry(from.offset)
            .or_default()
            .push(to.offset);
        // Ensure target vertex exists
        self.vertices.entry(to.offset).or_insert_with(|| {
            FRVertex::new(format!("FUN_{:x}", to.offset), to)
        });
    }

    /// Return the number of vertices.
    pub fn vertex_count(&self) -> usize {
        self.vertices.len()
    }

    /// Return the number of edges.
    pub fn edge_count(&self) -> usize {
        self.edges.values().map(|v| v.len()).sum()
    }

    /// Return the callees of a function.
    pub fn callees(&self, addr: Address) -> Vec<Address> {
        self.edges
            .get(&addr.offset)
            .map(|addrs| addrs.iter().map(|&a| Address::new(a)).collect())
            .unwrap_or_default()
    }

    /// Find the shortest path between two functions using BFS.
    ///
    /// Returns `None` if there is no path.
    pub fn shortest_path(&self, from: Address, to: Address) -> Option<ReachabilityResult> {
        if from == to {
            return Some(ReachabilityResult::new(vec![from]));
        }

        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        let mut parent: HashMap<u64, u64> = HashMap::new();

        let from_off = from.offset;
        let to_off = to.offset;

        queue.push_back(from_off);
        visited.insert(from_off);

        while let Some(current) = queue.pop_front() {
            if let Some(neighbors) = self.edges.get(&current) {
                for &next in neighbors {
                    if visited.contains(&next) {
                        continue;
                    }
                    visited.insert(next);
                    parent.insert(next, current);

                    if next == to_off {
                        // Reconstruct path
                        let mut path = Vec::new();
                        let mut node = to_off;
                        path.push(Address::new(node));
                        while let Some(&p) = parent.get(&node) {
                            path.push(Address::new(p));
                            node = p;
                        }
                        path.reverse();
                        return Some(ReachabilityResult::new(path));
                    }

                    queue.push_back(next);
                }
            }
        }

        None
    }

    /// Compute all functions reachable from the given source.
    pub fn reachable_from(&self, source: Address) -> Vec<Address> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut result = Vec::new();

        queue.push_back(source.offset);
        visited.insert(source.offset);

        while let Some(current) = queue.pop_front() {
            if let Some(neighbors) = self.edges.get(&current) {
                for &next in neighbors {
                    if visited.insert(next) {
                        result.push(Address::new(next));
                        queue.push_back(next);
                    }
                }
            }
        }

        result
    }

    /// Check whether `target` is reachable from `source`.
    pub fn is_reachable(&self, source: Address, target: Address) -> bool {
        self.shortest_path(source, target).is_some()
    }
}

// ============================================================================
// ReachabilityAnalyzer -- high-level analysis helper
// ============================================================================

/// High-level analyzer for function reachability.
pub struct ReachabilityAnalyzer;

impl ReachabilityAnalyzer {
    /// Find all paths (up to `max_paths`) between two functions.
    ///
    /// Uses DFS with backtracking. Paths are limited in length to avoid
    /// combinatorial explosion.
    pub fn find_all_paths(
        graph: &ReachabilityGraph,
        from: Address,
        to: Address,
        max_paths: usize,
        max_depth: usize,
    ) -> Vec<ReachabilityResult> {
        let mut results = Vec::new();
        let mut path = vec![from.offset];
        let mut visited = HashSet::new();
        visited.insert(from.offset);

        Self::dfs_all_paths(
            graph,
            from.offset,
            to.offset,
            &mut path,
            &mut visited,
            &mut results,
            max_paths,
            max_depth,
        );

        results
    }

    fn dfs_all_paths(
        graph: &ReachabilityGraph,
        current: u64,
        target: u64,
        path: &mut Vec<u64>,
        visited: &mut HashSet<u64>,
        results: &mut Vec<ReachabilityResult>,
        max_paths: usize,
        max_depth: usize,
    ) {
        if results.len() >= max_paths || path.len() > max_depth {
            return;
        }

        if current == target && path.len() > 1 {
            let addrs: Vec<Address> = path.iter().map(|&a| Address::new(a)).collect();
            results.push(ReachabilityResult::new(addrs));
            return;
        }

        if let Some(neighbors) = graph.edges.get(&current) {
            for &next in neighbors {
                if !visited.contains(&next) {
                    visited.insert(next);
                    path.push(next);
                    Self::dfs_all_paths(
                        graph,
                        next,
                        target,
                        path,
                        visited,
                        results,
                        max_paths,
                        max_depth,
                    );
                    path.pop();
                    visited.remove(&next);
                }
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_graph() -> ReachabilityGraph {
        let mut g = ReachabilityGraph::new();
        g.add_vertex(FRVertex::new("main", Address::new(0x1000)));
        g.add_vertex(FRVertex::new("foo", Address::new(0x2000)));
        g.add_vertex(FRVertex::new("bar", Address::new(0x3000)));
        g.add_vertex(FRVertex::new("baz", Address::new(0x4000)));
        g.add_edge(Address::new(0x1000), Address::new(0x2000)); // main -> foo
        g.add_edge(Address::new(0x2000), Address::new(0x3000)); // foo -> bar
        g.add_edge(Address::new(0x2000), Address::new(0x4000)); // foo -> baz
        g.add_edge(Address::new(0x1000), Address::new(0x3000)); // main -> bar (direct)
        g
    }

    #[test]
    fn test_shortest_path_direct() {
        let g = build_test_graph();
        let result = g.shortest_path(Address::new(0x1000), Address::new(0x2000)).unwrap();
        assert_eq!(result.path, vec![Address::new(0x1000), Address::new(0x2000)]);
        assert_eq!(result.path_length, 1);
    }

    #[test]
    fn test_shortest_path_two_hops() {
        let g = build_test_graph();
        let result = g.shortest_path(Address::new(0x1000), Address::new(0x4000)).unwrap();
        assert_eq!(result.path_length, 2);
        assert_eq!(result.path[0], Address::new(0x1000));
        assert_eq!(result.path[2], Address::new(0x4000));
    }

    #[test]
    fn test_shortest_path_same_node() {
        let g = build_test_graph();
        let result = g.shortest_path(Address::new(0x1000), Address::new(0x1000)).unwrap();
        assert_eq!(result.path_length, 0);
    }

    #[test]
    fn test_shortest_path_unreachable() {
        let g = build_test_graph();
        let result = g.shortest_path(Address::new(0x3000), Address::new(0x1000));
        assert!(result.is_none());
    }

    #[test]
    fn test_reachable_from() {
        let g = build_test_graph();
        let reachable = g.reachable_from(Address::new(0x1000));
        assert_eq!(reachable.len(), 3); // foo, bar, baz
    }

    #[test]
    fn test_is_reachable() {
        let g = build_test_graph();
        assert!(g.is_reachable(Address::new(0x1000), Address::new(0x4000)));
        assert!(!g.is_reachable(Address::new(0x4000), Address::new(0x1000)));
    }

    #[test]
    fn test_find_all_paths() {
        let g = build_test_graph();
        let paths =
            ReachabilityAnalyzer::find_all_paths(&g, Address::new(0x1000), Address::new(0x3000), 10, 10);
        // Two paths: main->bar (direct) and main->foo->bar
        assert_eq!(paths.len(), 2);
        let lengths: Vec<usize> = paths.iter().map(|p| p.path_length).collect();
        assert!(lengths.contains(&1));
        assert!(lengths.contains(&2));
    }

    #[test]
    fn test_max_paths_limit() {
        let g = build_test_graph();
        let paths =
            ReachabilityAnalyzer::find_all_paths(&g, Address::new(0x1000), Address::new(0x3000), 1, 10);
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn test_vertex_and_edge_count() {
        let g = build_test_graph();
        assert_eq!(g.vertex_count(), 4);
        assert_eq!(g.edge_count(), 4);
    }

    #[test]
    fn test_callees() {
        let g = build_test_graph();
        let callees = g.callees(Address::new(0x2000));
        assert_eq!(callees.len(), 2);
    }
}

// ============================================================================
// FunctionReachabilityTableModel -- table model for reachability results
//
// Ported from Ghidra's `FunctionReachabilityTableModel.java`,
// `FunctionReachabilityProvider.java`, `FunctionReachabilityPlugin.java`,
// and `FRPathsModel.java`.
// ============================================================================

/// A single row in the function reachability results table.
///
/// Ported from `ghidra.app.plugin.core.reachability.FunctionReachabilityResult`.
#[derive(Debug, Clone)]
pub struct FunctionReachabilityRow {
    /// The source function name.
    pub from_function: String,
    /// The source function address.
    pub from_address: Address,
    /// The target function name.
    pub to_function: String,
    /// The target function address.
    pub to_address: Address,
    /// The shortest path length.
    pub path_length: usize,
    /// The number of intermediate functions in the path.
    pub hop_count: usize,
    /// The full path (list of function names).
    pub path: Vec<String>,
    /// Whether this result is selected in the UI.
    pub selected: bool,
}

impl FunctionReachabilityRow {
    /// Create a new row from a reachability result.
    pub fn new(
        from_name: impl Into<String>,
        from_address: Address,
        to_name: impl Into<String>,
        to_address: Address,
        path: Vec<String>,
    ) -> Self {
        let path_length = if path.is_empty() { 0 } else { path.len() - 1 };
        Self {
            from_function: from_name.into(),
            from_address,
            to_function: to_name.into(),
            to_address,
            path_length,
            hop_count: path_length.saturating_sub(1),
            path,
            selected: false,
        }
    }

    /// Format the path as a readable string.
    pub fn format_path(&self) -> String {
        self.path.join(" -> ")
    }
}

/// Table model for displaying function reachability results.
///
/// Ported from `ghidra.app.plugin.core.reachability.FunctionReachabilityTableModel`.
#[derive(Debug, Default)]
pub struct FunctionReachabilityTableModel {
    /// The result rows.
    rows: Vec<FunctionReachabilityRow>,
    /// Sort column index.
    sort_column: usize,
    /// Sort ascending.
    sort_ascending: bool,
}

/// Column definitions for the reachability table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachabilityColumn {
    /// Source function name.
    FromFunction,
    /// Target function name.
    ToFunction,
    /// Path length.
    PathLength,
    /// Hop count.
    HopCount,
    /// Path text.
    Path,
}

impl ReachabilityColumn {
    /// Get the column name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::FromFunction => "From",
            Self::ToFunction => "To",
            Self::PathLength => "Path Length",
            Self::HopCount => "Hops",
            Self::Path => "Path",
        }
    }

    /// Get all columns.
    pub fn all() -> &'static [ReachabilityColumn] {
        &[
            Self::FromFunction,
            Self::ToFunction,
            Self::PathLength,
            Self::HopCount,
            Self::Path,
        ]
    }
}

impl FunctionReachabilityTableModel {
    /// Create a new model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a result row.
    pub fn add_row(&mut self, row: FunctionReachabilityRow) {
        self.rows.push(row);
    }

    /// Get all rows.
    pub fn rows(&self) -> &[FunctionReachabilityRow] {
        &self.rows
    }

    /// Get a mutable reference to a row.
    pub fn row_mut(&mut self, index: usize) -> Option<&mut FunctionReachabilityRow> {
        self.rows.get_mut(index)
    }

    /// Get the number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Clear all rows.
    pub fn clear(&mut self) {
        self.rows.clear();
    }

    /// Sort rows by the given column.
    pub fn sort_by_column(&mut self, column: ReachabilityColumn, ascending: bool) {
        self.sort_column = column as usize;
        self.sort_ascending = ascending;
        match column {
            ReachabilityColumn::FromFunction => {
                self.rows
                    .sort_by(|a, b| a.from_function.cmp(&b.from_function));
            }
            ReachabilityColumn::ToFunction => {
                self.rows
                    .sort_by(|a, b| a.to_function.cmp(&b.to_function));
            }
            ReachabilityColumn::PathLength => {
                self.rows
                    .sort_by(|a, b| a.path_length.cmp(&b.path_length));
            }
            ReachabilityColumn::HopCount => {
                self.rows.sort_by(|a, b| a.hop_count.cmp(&b.hop_count));
            }
            ReachabilityColumn::Path => {
                self.rows
                    .sort_by(|a, b| a.format_path().cmp(&b.format_path()));
            }
        }
        if !ascending {
            self.rows.reverse();
        }
    }

    /// Get the selected rows.
    pub fn selected_rows(&self) -> Vec<&FunctionReachabilityRow> {
        self.rows.iter().filter(|r| r.selected).collect()
    }

    /// Filter rows by a function name substring.
    pub fn filter_by_name(&self, query: &str) -> Vec<&FunctionReachabilityRow> {
        let query_lower = query.to_lowercase();
        self.rows
            .iter()
            .filter(|r| {
                r.from_function.to_lowercase().contains(&query_lower)
                    || r.to_function.to_lowercase().contains(&query_lower)
            })
            .collect()
    }

    /// Populate the model from a reachability graph query.
    pub fn populate_from_graph(
        &mut self,
        graph: &ReachabilityGraph,
        from: Address,
        targets: &[Address],
        max_paths: usize,
        max_depth: usize,
    ) {
        self.clear();
        for &target in targets {
            let paths =
                ReachabilityAnalyzer::find_all_paths(graph, from, target, max_paths, max_depth);
            for path_result in paths {
                let path_names: Vec<String> = path_result
                    .path
                    .iter()
                    .map(|addr| {
                        graph
                            .vertices
                            .get(&addr.offset)
                            .map(|v| v.name.clone())
                            .unwrap_or_else(|| format!("FUN_{:x}", addr.offset))
                    })
                    .collect();

                let from_name = path_names.first().cloned().unwrap_or_default();
                let to_name = path_names.last().cloned().unwrap_or_default();
                let from_addr = path_result.path.first().copied().unwrap_or(from);
                let to_addr = path_result.path.last().copied().unwrap_or(target);

                self.add_row(FunctionReachabilityRow::new(
                    from_name, from_addr, to_name, to_addr, path_names,
                ));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FunctionReachabilityPlugin model
// ---------------------------------------------------------------------------

/// Plugin model for function reachability analysis.
///
/// Ported from `ghidra.app.plugin.core.reachability.FunctionReachabilityPlugin`.
#[derive(Debug)]
pub struct FunctionReachabilityPlugin {
    /// The reachability graph.
    pub graph: ReachabilityGraph,
    /// The table model for results.
    pub table_model: FunctionReachabilityTableModel,
    /// The source function address.
    pub source: Option<Address>,
    /// The target function address.
    pub target: Option<Address>,
    /// Maximum search depth.
    pub max_depth: usize,
    /// Maximum number of paths to find.
    pub max_paths: usize,
}

impl FunctionReachabilityPlugin {
    /// Create a new plugin model.
    pub fn new() -> Self {
        Self {
            graph: ReachabilityGraph::new(),
            table_model: FunctionReachabilityTableModel::new(),
            source: None,
            target: None,
            max_depth: 10,
            max_paths: 100,
        }
    }

    /// Set the source function.
    pub fn set_source(&mut self, address: Address) {
        self.source = Some(address);
    }

    /// Set the target function.
    pub fn set_target(&mut self, address: Address) {
        self.target = Some(address);
    }

    /// Run the reachability analysis.
    pub fn analyze(&mut self) {
        if let (Some(from), Some(to)) = (self.source, self.target) {
            self.table_model.populate_from_graph(
                &self.graph,
                from,
                &[to],
                self.max_paths,
                self.max_depth,
            );
        }
    }

    /// Get all functions reachable from the source.
    pub fn reachable_from_source(&self) -> Vec<Address> {
        self.source
            .map(|s| self.graph.reachable_from(s))
            .unwrap_or_default()
    }
}

impl Default for FunctionReachabilityPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod reachability_extended_tests {
    use super::*;

    fn build_test_graph() -> ReachabilityGraph {
        let mut g = ReachabilityGraph::new();
        g.add_vertex(FRVertex::new("main", Address::new(0x1000)));
        g.add_vertex(FRVertex::new("foo", Address::new(0x2000)));
        g.add_vertex(FRVertex::new("bar", Address::new(0x3000)));
        g.add_edge(Address::new(0x1000), Address::new(0x2000));
        g.add_edge(Address::new(0x2000), Address::new(0x3000));
        g.add_edge(Address::new(0x1000), Address::new(0x3000));
        g
    }

    #[test]
    fn test_reachability_table_model() {
        let mut model = FunctionReachabilityTableModel::new();
        assert_eq!(model.row_count(), 0);

        model.add_row(FunctionReachabilityRow::new(
            "main",
            Address::new(0x1000),
            "foo",
            Address::new(0x2000),
            vec!["main".into(), "foo".into()],
        ));
        assert_eq!(model.row_count(), 1);
    }

    #[test]
    fn test_reachability_row_format_path() {
        let row = FunctionReachabilityRow::new(
            "a",
            Address::new(0x1000),
            "c",
            Address::new(0x3000),
            vec!["a".into(), "b".into(), "c".into()],
        );
        assert_eq!(row.format_path(), "a -> b -> c");
        assert_eq!(row.path_length, 2);
        assert_eq!(row.hop_count, 1);
    }

    #[test]
    fn test_reachability_table_sort() {
        let mut model = FunctionReachabilityTableModel::new();
        model.add_row(FunctionReachabilityRow::new(
            "main",
            Address::new(0x1000),
            "foo",
            Address::new(0x2000),
            vec!["main".into(), "foo".into()],
        ));
        model.add_row(FunctionReachabilityRow::new(
            "main",
            Address::new(0x1000),
            "bar",
            Address::new(0x3000),
            vec!["main".into(), "bar".into()],
        ));
        model.sort_by_column(ReachabilityColumn::ToFunction, true);
        assert_eq!(model.rows()[0].to_function, "bar");
        assert_eq!(model.rows()[1].to_function, "foo");

        model.sort_by_column(ReachabilityColumn::ToFunction, false);
        assert_eq!(model.rows()[0].to_function, "foo");
    }

    #[test]
    fn test_reachability_table_filter() {
        let mut model = FunctionReachabilityTableModel::new();
        model.add_row(FunctionReachabilityRow::new(
            "main",
            Address::new(0x1000),
            "foo",
            Address::new(0x2000),
            vec![],
        ));
        model.add_row(FunctionReachabilityRow::new(
            "main",
            Address::new(0x1000),
            "printf",
            Address::new(0x3000),
            vec![],
        ));
        let filtered = model.filter_by_name("prin");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].to_function, "printf");
    }

    #[test]
    fn test_reachability_column_names() {
        assert_eq!(ReachabilityColumn::FromFunction.name(), "From");
        assert_eq!(ReachabilityColumn::PathLength.name(), "Path Length");
        assert_eq!(ReachabilityColumn::all().len(), 5);
    }

    #[test]
    fn test_reachability_plugin() {
        let g = build_test_graph();
        let mut plugin = FunctionReachabilityPlugin::new();
        plugin.graph = g;
        plugin.set_source(Address::new(0x1000));
        plugin.set_target(Address::new(0x3000));
        plugin.analyze();
        assert!(plugin.table_model.row_count() > 0);
    }

    #[test]
    fn test_reachability_plugin_reachable_from() {
        let g = build_test_graph();
        let mut plugin = FunctionReachabilityPlugin::new();
        plugin.graph = g;
        plugin.set_source(Address::new(0x1000));
        let reachable = plugin.reachable_from_source();
        assert_eq!(reachable.len(), 2); // foo and bar
    }

    #[test]
    fn test_reachability_plugin_no_source() {
        let plugin = FunctionReachabilityPlugin::new();
        assert!(plugin.reachable_from_source().is_empty());
    }

    #[test]
    fn test_populate_from_graph() {
        let g = build_test_graph();
        let mut model = FunctionReachabilityTableModel::new();
        model.populate_from_graph(
            &g,
            Address::new(0x1000),
            &[Address::new(0x3000)],
            10,
            10,
        );
        // Two paths: main->bar (direct) and main->foo->bar
        assert!(model.row_count() >= 1);
    }
}
