//! Experiment and diagnostics types for the debug framework.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.experiments` and
//! `ghidra.app.plugin.core.debug.gui.internal` packages.
//!
//! Provides types for:
//! - R*-tree diagnostics and visualization support.
//! - Experiment tracking for debug features.
//! - Performance metrics for trace operations.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A tracked experiment in the debug framework.
///
/// Ported from Ghidra's experiment tracking system. Experiments allow
/// toggling debug features on/off for testing purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugExperiment {
    /// The name of the experiment.
    pub name: String,
    /// A description of what this experiment controls.
    pub description: String,
    /// Whether this experiment is currently enabled.
    pub enabled: bool,
    /// The version of the experiment.
    pub version: u32,
}

impl DebugExperiment {
    /// Create a new experiment.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            enabled: false,
            version: 1,
        }
    }

    /// Enable this experiment.
    pub fn enable(mut self) -> Self {
        self.enabled = true;
        self
    }

    /// Toggle the experiment.
    pub fn toggle(&mut self) {
        self.enabled = !self.enabled;
    }
}

/// Performance metrics for trace operations.
///
/// Ported from Ghidra's diagnostics system for tracking R*-tree
/// and database performance.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TracePerformanceMetrics {
    /// Total number of database queries performed.
    pub query_count: u64,
    /// Total number of inserts performed.
    pub insert_count: u64,
    /// Total number of deletes performed.
    pub delete_count: u64,
    /// Total time spent in database operations (microseconds).
    pub db_time_us: u64,
    /// Total time spent in address translation (microseconds).
    pub translation_time_us: u64,
    /// Cache hit count.
    pub cache_hits: u64,
    /// Cache miss count.
    pub cache_misses: u64,
    /// R*-tree split count.
    pub rstar_splits: u64,
    /// R*-tree reinsert count.
    pub rstar_reinserts: u64,
    /// Custom metrics.
    pub custom: BTreeMap<String, u64>,
}

impl TracePerformanceMetrics {
    /// Create new empty metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a query.
    pub fn record_query(&mut self) {
        self.query_count += 1;
    }

    /// Record an insert.
    pub fn record_insert(&mut self) {
        self.insert_count += 1;
    }

    /// Record a delete.
    pub fn record_delete(&mut self) {
        self.delete_count += 1;
    }

    /// Record database time.
    pub fn record_db_time(&mut self, us: u64) {
        self.db_time_us += us;
    }

    /// Record a cache hit.
    pub fn record_cache_hit(&mut self) {
        self.cache_hits += 1;
    }

    /// Record a cache miss.
    pub fn record_cache_miss(&mut self) {
        self.cache_misses += 1;
    }

    /// The cache hit rate (0.0 to 1.0).
    pub fn cache_hit_rate(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            return 0.0;
        }
        self.cache_hits as f64 / total as f64
    }

    /// Record a custom metric.
    pub fn record_custom(&mut self, key: impl Into<String>, value: u64) {
        *self.custom.entry(key.into()).or_insert(0) += value;
    }

    /// Get a custom metric value.
    pub fn get_custom(&self, key: &str) -> Option<u64> {
        self.custom.get(key).copied()
    }

    /// Total operations (queries + inserts + deletes).
    pub fn total_operations(&self) -> u64 {
        self.query_count + self.insert_count + self.delete_count
    }

    /// Merge another metrics set into this one.
    pub fn merge(&mut self, other: &TracePerformanceMetrics) {
        self.query_count += other.query_count;
        self.insert_count += other.insert_count;
        self.delete_count += other.delete_count;
        self.db_time_us += other.db_time_us;
        self.translation_time_us += other.translation_time_us;
        self.cache_hits += other.cache_hits;
        self.cache_misses += other.cache_misses;
        self.rstar_splits += other.rstar_splits;
        self.rstar_reinserts += other.rstar_reinserts;
        for (k, v) in &other.custom {
            *self.custom.entry(k.clone()).or_insert(0) += v;
        }
    }
}

/// R*-tree diagnostics information.
///
/// Ported from Ghidra's `RStarDiagnosticsPlugin` and related types.
/// Provides information about the R*-tree used for spatial indexing
/// of trace data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RStarTreeDiagnostics {
    /// The total number of entries in the tree.
    pub entry_count: usize,
    /// The number of leaf nodes.
    pub leaf_count: usize,
    /// The number of internal nodes.
    pub internal_count: usize,
    /// The depth of the tree.
    pub depth: usize,
    /// The fill factor (entries per node / max entries per node).
    pub fill_factor: f64,
    /// The number of splits that have occurred.
    pub split_count: u64,
    /// The number of forced reinserts.
    pub reinsert_count: u64,
    /// The bounding box of the entire tree.
    pub bounding_box: Option<DiagnosticBoundingBox>,
}

/// A bounding box for R*-tree diagnostics.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DiagnosticBoundingBox {
    /// Minimum x (e.g., address offset).
    pub min_x: f64,
    /// Maximum x.
    pub max_x: f64,
    /// Minimum y (e.g., snap).
    pub min_y: f64,
    /// Maximum y.
    pub max_y: f64,
}

impl DiagnosticBoundingBox {
    /// Create a new bounding box.
    pub fn new(min_x: f64, max_x: f64, min_y: f64, max_y: f64) -> Self {
        Self {
            min_x,
            max_x,
            min_y,
            max_y,
        }
    }

    /// The width of the bounding box.
    pub fn width(&self) -> f64 {
        self.max_x - self.min_x
    }

    /// The height of the bounding box.
    pub fn height(&self) -> f64 {
        self.max_y - self.min_y
    }

    /// The area of the bounding box.
    pub fn area(&self) -> f64 {
        self.width() * self.height()
    }
}

impl RStarTreeDiagnostics {
    /// Create empty diagnostics.
    pub fn new() -> Self {
        Self {
            entry_count: 0,
            leaf_count: 0,
            internal_count: 0,
            depth: 0,
            fill_factor: 0.0,
            split_count: 0,
            reinsert_count: 0,
            bounding_box: None,
        }
    }

    /// The total number of nodes in the tree.
    pub fn total_nodes(&self) -> usize {
        self.leaf_count + self.internal_count
    }

    /// Whether the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.entry_count == 0
    }
}

impl Default for RStarTreeDiagnostics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_experiment() {
        let exp = DebugExperiment::new("new-ui", "Enable the new debugger UI");
        assert_eq!(exp.name, "new-ui");
        assert!(!exp.enabled);

        let exp = exp.enable();
        assert!(exp.enabled);
    }

    #[test]
    fn test_experiment_toggle() {
        let mut exp = DebugExperiment::new("test", "desc");
        assert!(!exp.enabled);
        exp.toggle();
        assert!(exp.enabled);
        exp.toggle();
        assert!(!exp.enabled);
    }

    #[test]
    fn test_performance_metrics() {
        let mut metrics = TracePerformanceMetrics::new();
        metrics.record_query();
        metrics.record_query();
        metrics.record_insert();
        metrics.record_cache_hit();
        metrics.record_cache_hit();
        metrics.record_cache_miss();

        assert_eq!(metrics.query_count, 2);
        assert_eq!(metrics.insert_count, 1);
        assert_eq!(metrics.total_operations(), 3);
        assert!((metrics.cache_hit_rate() - 2.0 / 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_performance_metrics_empty() {
        let metrics = TracePerformanceMetrics::new();
        assert_eq!(metrics.cache_hit_rate(), 0.0);
        assert_eq!(metrics.total_operations(), 0);
    }

    #[test]
    fn test_performance_metrics_custom() {
        let mut metrics = TracePerformanceMetrics::new();
        metrics.record_custom("my_metric", 42);
        metrics.record_custom("my_metric", 8);
        assert_eq!(metrics.get_custom("my_metric"), Some(50));
        assert_eq!(metrics.get_custom("missing"), None);
    }

    #[test]
    fn test_performance_metrics_merge() {
        let mut a = TracePerformanceMetrics::new();
        a.record_query();
        a.record_cache_hit();

        let mut b = TracePerformanceMetrics::new();
        b.record_insert();
        b.record_cache_miss();

        a.merge(&b);
        assert_eq!(a.query_count, 1);
        assert_eq!(a.insert_count, 1);
        assert_eq!(a.cache_hits, 1);
        assert_eq!(a.cache_misses, 1);
    }

    #[test]
    fn test_rstar_diagnostics() {
        let diag = RStarTreeDiagnostics::new();
        assert!(diag.is_empty());
        assert_eq!(diag.total_nodes(), 0);
    }

    #[test]
    fn test_rstar_diagnostics_populated() {
        let diag = RStarTreeDiagnostics {
            entry_count: 100,
            leaf_count: 20,
            internal_count: 5,
            depth: 3,
            fill_factor: 0.7,
            split_count: 10,
            reinsert_count: 3,
            bounding_box: Some(DiagnosticBoundingBox::new(0.0, 1000.0, 0.0, 100.0)),
        };
        assert!(!diag.is_empty());
        assert_eq!(diag.total_nodes(), 25);
        let bbox = diag.bounding_box.unwrap();
        assert_eq!(bbox.width(), 1000.0);
        assert_eq!(bbox.area(), 100000.0);
    }

    #[test]
    fn test_bounding_box() {
        let bbox = DiagnosticBoundingBox::new(10.0, 20.0, 30.0, 50.0);
        assert_eq!(bbox.width(), 10.0);
        assert_eq!(bbox.height(), 20.0);
        assert_eq!(bbox.area(), 200.0);
    }

    #[test]
    fn test_metrics_serde() {
        let mut metrics = TracePerformanceMetrics::new();
        metrics.record_query();
        let json = serde_json::to_string(&metrics).unwrap();
        let back: TracePerformanceMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(back.query_count, 1);
    }

    #[test]
    fn test_experiment_serde() {
        let exp = DebugExperiment::new("test", "desc").enable();
        let json = serde_json::to_string(&exp).unwrap();
        let back: DebugExperiment = serde_json::from_str(&json).unwrap();
        assert!(back.enabled);
    }

    #[test]
    fn test_diagnostics_serde() {
        let diag = RStarTreeDiagnostics {
            entry_count: 10,
            ..Default::default()
        };
        let json = serde_json::to_string(&diag).unwrap();
        let back: RStarTreeDiagnostics = serde_json::from_str(&json).unwrap();
        assert_eq!(back.entry_count, 10);
    }

    #[test]
    fn test_metrics_record_db_time() {
        let mut metrics = TracePerformanceMetrics::new();
        metrics.record_db_time(100);
        metrics.record_db_time(200);
        assert_eq!(metrics.db_time_us, 300);
    }

    #[test]
    fn test_experiment_version() {
        let exp = DebugExperiment::new("test", "desc");
        assert_eq!(exp.version, 1);
    }
}
