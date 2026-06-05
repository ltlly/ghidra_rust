//! R*-tree diagnostics for trace object storage.
//!
//! Ported from Ghidra's `RStarDiagnosticsPlugin` and related classes.
//!
//! Provides diagnostic information about the R*-tree used for spatial
//! indexing of trace objects.

use serde::{Deserialize, Serialize};

/// Statistics about an R*-tree's structure and performance.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RStarTreeStats {
    /// Total number of entries in the tree.
    pub total_entries: usize,
    /// Number of leaf nodes.
    pub leaf_count: usize,
    /// Number of internal nodes.
    pub internal_count: usize,
    /// Maximum depth of the tree.
    pub max_depth: usize,
    /// Average number of entries per leaf.
    pub avg_entries_per_leaf: f64,
    /// The fill factor (entries / (nodes * max_entries)).
    pub fill_factor: f64,
    /// Total number of overlap queries performed.
    pub overlap_queries: u64,
    /// Total number of point queries performed.
    pub point_queries: u64,
    /// Average query time in microseconds.
    pub avg_query_time_us: f64,
}

impl RStarTreeStats {
    /// Create a new empty stats structure.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an overlap query.
    pub fn record_overlap_query(&mut self, time_us: f64) {
        self.overlap_queries += 1;
        let total = self.overlap_queries as f64;
        self.avg_query_time_us = (self.avg_query_time_us * (total - 1.0) + time_us) / total;
    }

    /// Record a point query.
    pub fn record_point_query(&mut self, time_us: f64) {
        self.point_queries += 1;
        let total_queries = (self.overlap_queries + self.point_queries) as f64;
        self.avg_query_time_us = (self.avg_query_time_us * (total_queries - 1.0) + time_us) / total_queries;
    }

    /// Get the total number of queries.
    pub fn total_queries(&self) -> u64 {
        self.overlap_queries + self.point_queries
    }

    /// Get the total number of nodes.
    pub fn total_nodes(&self) -> usize {
        self.leaf_count + self.internal_count
    }

    /// Check if the tree appears healthy (reasonable fill factor, depth).
    pub fn is_healthy(&self) -> bool {
        self.fill_factor > 0.3 && self.max_depth < 20 && self.avg_entries_per_leaf > 2.0
    }
}

/// A diagnostic snapshot of a trace database's R*-tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RStarTreeDiagnostics {
    /// The address space name.
    pub space_name: String,
    /// Tree statistics.
    pub stats: RStarTreeStats,
    /// The max entries per node configured.
    pub max_entries_per_node: usize,
    /// The min entries per node configured.
    pub min_entries_per_node: usize,
    /// Diagnostic warnings, if any.
    pub warnings: Vec<String>,
}

impl RStarTreeDiagnostics {
    /// Create diagnostics for the given space.
    pub fn new(space_name: impl Into<String>, max_entries: usize, min_entries: usize) -> Self {
        Self {
            space_name: space_name.into(),
            stats: RStarTreeStats::new(),
            max_entries_per_node: max_entries,
            min_entries_per_node: min_entries,
            warnings: Vec::new(),
        }
    }

    /// Run diagnostics and populate warnings.
    pub fn run_diagnostics(&mut self) {
        self.warnings.clear();

        if self.stats.fill_factor < 0.2 {
            self.warnings.push(format!(
                "Low fill factor ({:.2}) in space '{}'",
                self.stats.fill_factor, self.space_name
            ));
        }

        if self.stats.max_depth > 15 {
            self.warnings.push(format!(
                "Excessive depth ({}) in space '{}'",
                self.stats.max_depth, self.space_name
            ));
        }

        if self.stats.avg_entries_per_leaf < 1.0 {
            self.warnings.push(format!(
                "Sparse leaves ({:.1} avg entries) in space '{}'",
                self.stats.avg_entries_per_leaf, self.space_name
            ));
        }
    }

    /// Check if there are any warnings.
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rstar_tree_stats_default() {
        let stats = RStarTreeStats::new();
        assert_eq!(stats.total_entries, 0);
        assert_eq!(stats.total_queries(), 0);
        assert_eq!(stats.total_nodes(), 0);
    }

    #[test]
    fn test_rstar_tree_stats_queries() {
        let mut stats = RStarTreeStats::new();
        stats.record_overlap_query(10.0);
        stats.record_overlap_query(20.0);
        stats.record_point_query(5.0);

        assert_eq!(stats.total_queries(), 3);
        assert_eq!(stats.overlap_queries, 2);
        assert_eq!(stats.point_queries, 1);
        assert!(stats.avg_query_time_us > 0.0);
    }

    #[test]
    fn test_rstar_tree_stats_health() {
        let mut stats = RStarTreeStats::new();
        stats.fill_factor = 0.5;
        stats.max_depth = 10;
        stats.avg_entries_per_leaf = 5.0;
        assert!(stats.is_healthy());

        stats.fill_factor = 0.1;
        assert!(!stats.is_healthy());
    }

    #[test]
    fn test_rstar_diagnostics_no_warnings() {
        let mut diag = RStarTreeDiagnostics::new("ram", 25, 8);
        diag.stats.fill_factor = 0.5;
        diag.stats.max_depth = 5;
        diag.stats.avg_entries_per_leaf = 10.0;
        diag.run_diagnostics();

        assert!(!diag.has_warnings());
        assert!(diag.warnings.is_empty());
    }

    #[test]
    fn test_rstar_diagnostics_low_fill() {
        let mut diag = RStarTreeDiagnostics::new("ram", 25, 8);
        diag.stats.fill_factor = 0.1;
        diag.stats.max_depth = 5;
        diag.stats.avg_entries_per_leaf = 5.0;
        diag.run_diagnostics();

        assert!(diag.has_warnings());
        assert!(diag.warnings.iter().any(|w| w.contains("fill factor")));
    }

    #[test]
    fn test_rstar_diagnostics_excessive_depth() {
        let mut diag = RStarTreeDiagnostics::new("ram", 25, 8);
        diag.stats.fill_factor = 0.5;
        diag.stats.max_depth = 20;
        diag.stats.avg_entries_per_leaf = 5.0;
        diag.run_diagnostics();

        assert!(diag.has_warnings());
        assert!(diag.warnings.iter().any(|w| w.contains("depth")));
    }

    #[test]
    fn test_rstar_diagnostics_sparse_leaves() {
        let mut diag = RStarTreeDiagnostics::new("register", 25, 8);
        diag.stats.fill_factor = 0.5;
        diag.stats.max_depth = 5;
        diag.stats.avg_entries_per_leaf = 0.5;
        diag.run_diagnostics();

        assert!(diag.has_warnings());
        assert!(diag.warnings.iter().any(|w| w.contains("Sparse")));
    }

    #[test]
    fn test_rstar_diagnostics_serialization() {
        let diag = RStarTreeDiagnostics::new("ram", 25, 8);
        let json = serde_json::to_string(&diag).unwrap();
        let deserialized: RStarTreeDiagnostics = serde_json::from_str(&json).unwrap();
        assert_eq!(diag.space_name, deserialized.space_name);
        assert_eq!(diag.max_entries_per_node, deserialized.max_entries_per_node);
    }

    #[test]
    fn test_rstar_stats_serialization() {
        let mut stats = RStarTreeStats::new();
        stats.total_entries = 100;
        stats.leaf_count = 10;
        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: RStarTreeStats = serde_json::from_str(&json).unwrap();
        assert_eq!(stats.total_entries, deserialized.total_entries);
        assert_eq!(stats.leaf_count, deserialized.leaf_count);
    }
}
