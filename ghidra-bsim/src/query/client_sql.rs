//! BSim client-side SQL infrastructure.
//!
//! Ports `ghidra.features.bsim.query.client` from Ghidra's Java source.
//!
//! Contains:
//! - **Scoring**: `ExecutableScorer`, `ExecutableComparison`, `IdHistogram`
//! - **Caching**: `ScoreCaching`, `FileScoreCaching`, `TableScoreCaching`, `TemporaryScoreCaching`
//! - **Effects**: `SqlEffects` -- tracks SQL side effects during query execution
//! - **Resolution**: `IdSqlResolution` -- resolves IDs to SQL row keys
//! - **Configuration**: `Configuration` -- BSim client configuration
//! - **Exceptions**: `NoDatabaseException`, `CancelledSqlException`
//! - **Row keys**: `RowKeySql` -- SQL-specific row key type

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ============================================================================
// Exceptions
// ============================================================================

/// Exception indicating no database connection is available.
///
/// Ports `ghidra.features.bsim.query.client.NoDatabaseException`.
#[derive(Debug, Clone)]
pub struct NoDatabaseException {
    message: String,
}

impl NoDatabaseException {
    /// Create a new exception.
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

impl fmt::Display for NoDatabaseException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "No database: {}", self.message)
    }
}

impl std::error::Error for NoDatabaseException {}

/// Exception indicating a SQL operation was cancelled.
///
/// Ports `ghidra.features.bsim.query.client.CancelledSQLException`.
#[derive(Debug, Clone)]
pub struct CancelledSqlException {
    message: String,
}

impl CancelledSqlException {
    /// Create a new exception.
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

impl fmt::Display for CancelledSqlException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cancelled SQL: {}", self.message)
    }
}

impl std::error::Error for CancelledSqlException {}

// ============================================================================
// RowKeySql
// ============================================================================

/// A row key that references a specific row in a SQL database.
///
/// Ports `ghidra.features.bsim.query.client.RowKeySQL`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RowKeySql {
    /// The table name.
    pub table: String,
    /// The primary key value.
    pub key: i64,
}

impl RowKeySql {
    /// Create a new SQL row key.
    pub fn new(table: impl Into<String>, key: i64) -> Self {
        Self { table: table.into(), key }
    }
}

impl fmt::Display for RowKeySql {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.table, self.key)
    }
}

// ============================================================================
// IdSqlResolution
// ============================================================================

/// Resolves string IDs to SQL row keys.
///
/// Ports `ghidra.features.bsim.query.client.IDSQLResolution`.
#[derive(Debug)]
pub struct IdSqlResolution {
    /// Map from string ID to SQL row key.
    pub resolution: HashMap<String, RowKeySql>,
}

impl IdSqlResolution {
    /// Create a new empty resolution map.
    pub fn new() -> Self {
        Self { resolution: HashMap::new() }
    }

    /// Add a resolution entry.
    pub fn add(&mut self, id: impl Into<String>, key: RowKeySql) {
        self.resolution.insert(id.into(), key);
    }

    /// Resolve a string ID to a row key.
    pub fn resolve(&self, id: &str) -> Option<&RowKeySql> {
        self.resolution.get(id)
    }

    /// Number of resolved entries.
    pub fn len(&self) -> usize {
        self.resolution.len()
    }

    /// Whether the resolution map is empty.
    pub fn is_empty(&self) -> bool {
        self.resolution.is_empty()
    }
}

impl Default for IdSqlResolution {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SqlEffects
// ============================================================================

/// Tracks the side effects of SQL operations during a query.
///
/// Ports `ghidra.features.bsim.query.client.SQLEffects`.
#[derive(Debug, Clone, Default)]
pub struct SqlEffects {
    /// Number of rows inserted.
    pub inserts: usize,
    /// Number of rows updated.
    pub updates: usize,
    /// Number of rows deleted.
    pub deletes: usize,
    /// Number of queries executed.
    pub queries: usize,
    /// Error messages encountered.
    pub errors: Vec<String>,
    /// Warning messages.
    pub warnings: Vec<String>,
}

impl SqlEffects {
    /// Create a new empty effects tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an insert.
    pub fn record_insert(&mut self, count: usize) {
        self.inserts += count;
    }

    /// Record an update.
    pub fn record_update(&mut self, count: usize) {
        self.updates += count;
    }

    /// Record a delete.
    pub fn record_delete(&mut self, count: usize) {
        self.deletes += count;
    }

    /// Record a query.
    pub fn record_query(&mut self) {
        self.queries += 1;
    }

    /// Record an error.
    pub fn record_error(&mut self, msg: impl Into<String>) {
        self.errors.push(msg.into());
    }

    /// Record a warning.
    pub fn record_warning(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
    }

    /// Total number of rows affected.
    pub fn total_affected(&self) -> usize {
        self.inserts + self.updates + self.deletes
    }

    /// Whether any errors were recorded.
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Merge effects from another tracker.
    pub fn merge(&mut self, other: &SqlEffects) {
        self.inserts += other.inserts;
        self.updates += other.updates;
        self.deletes += other.deletes;
        self.queries += other.queries;
        self.errors.extend(other.errors.iter().cloned());
        self.warnings.extend(other.warnings.iter().cloned());
    }
}

// ============================================================================
// IdHistogram
// ============================================================================

/// A histogram of function ID frequencies for scoring purposes.
///
/// Ports `ghidra.features.bsim.query.client.IdHistogram`.
#[derive(Debug, Clone, Default)]
pub struct IdHistogram {
    /// Map from function ID to frequency count.
    pub counts: HashMap<i64, u32>,
    /// Total count across all IDs.
    pub total: u64,
}

impl IdHistogram {
    /// Create a new empty histogram.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one occurrence of a function ID.
    pub fn record(&mut self, id: i64) {
        *self.counts.entry(id).or_insert(0) += 1;
        self.total += 1;
    }

    /// Get the count for a specific ID.
    pub fn get(&self, id: i64) -> u32 {
        self.counts.get(&id).copied().unwrap_or(0)
    }

    /// Get the frequency (count / total) for a specific ID.
    pub fn frequency(&self, id: i64) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        self.get(id) as f64 / self.total as f64
    }

    /// Number of unique IDs.
    pub fn unique_count(&self) -> usize {
        self.counts.len()
    }

    /// Merge another histogram into this one.
    pub fn merge(&mut self, other: &IdHistogram) {
        for (&id, &count) in &other.counts {
            *self.counts.entry(id).or_insert(0) += count;
        }
        self.total += other.total;
    }
}

// ============================================================================
// ExecutableComparison
// ============================================================================

/// The result of comparing two executables for similarity.
///
/// Ports `ghidra.features.bsim.query.client.ExecutableComparison`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutableComparison {
    /// ID of the source executable.
    pub source_exe_id: i64,
    /// ID of the target executable.
    pub target_exe_id: i64,
    /// Similarity score (0.0 = no match, 1.0 = identical).
    pub similarity: f64,
    /// Number of matching functions.
    pub match_count: usize,
    /// Total functions in source.
    pub source_function_count: usize,
    /// Total functions in target.
    pub target_function_count: usize,
    /// Match details (source_func_id -> (target_func_id, score)).
    pub matches: HashMap<i64, (i64, f64)>,
}

impl ExecutableComparison {
    /// Create a new comparison result.
    pub fn new(source_exe_id: i64, target_exe_id: i64) -> Self {
        Self {
            source_exe_id,
            target_exe_id,
            similarity: 0.0,
            match_count: 0,
            source_function_count: 0,
            target_function_count: 0,
            matches: HashMap::new(),
        }
    }

    /// Add a function match.
    pub fn add_match(&mut self, source_func_id: i64, target_func_id: i64, score: f64) {
        self.matches.insert(source_func_id, (target_func_id, score));
        self.match_count = self.matches.len();
    }

    /// Compute the overall similarity score from individual matches.
    pub fn compute_similarity(&mut self) {
        if self.source_function_count == 0 {
            self.similarity = 0.0;
            return;
        }
        let match_ratio = self.match_count as f64 / self.source_function_count as f64;
        let avg_score: f64 = if self.matches.is_empty() {
            0.0
        } else {
            self.matches.values().map(|(_, s)| s).sum::<f64>() / self.matches.len() as f64
        };
        self.similarity = match_ratio * avg_score;
    }
}

// ============================================================================
// ExecutableScorer
// ============================================================================

/// Scores functions against an executable to find matches.
///
/// Ports `ghidra.features.bsim.query.client.ExecutableScorer`.
pub trait ExecutableScorer: Send + Sync + fmt::Debug {
    /// Score a function signature against the target executable.
    ///
    /// Returns a score from 0.0 (no match) to 1.0 (identical).
    fn score_function(&self, source_signature: &[f64], target_signature: &[f64]) -> f64;

    /// Score multiple functions against the target executable.
    fn score_batch(&self, pairs: &[(Vec<f64>, Vec<f64>)]) -> Vec<f64> {
        pairs.iter().map(|(s, t)| self.score_function(s, t)).collect()
    }

    /// Get the name of this scorer.
    fn name(&self) -> &str;
}

/// Simple Euclidean-distance based scorer.
///
/// Ports `ghidra.features.bsim.query.client.ExecutableScorerSingle`.
#[derive(Debug, Clone)]
pub struct EuclideanScorer {
    /// Similarity threshold.
    pub threshold: f64,
}

impl EuclideanScorer {
    /// Create a new Euclidean scorer with the given threshold.
    pub fn new(threshold: f64) -> Self {
        Self { threshold }
    }
}

impl Default for EuclideanScorer {
    fn default() -> Self {
        Self::new(0.7)
    }
}

impl ExecutableScorer for EuclideanScorer {
    fn score_function(&self, source: &[f64], target: &[f64]) -> f64 {
        if source.len() != target.len() || source.is_empty() {
            return 0.0;
        }
        let dist_sq: f64 = source.iter().zip(target.iter()).map(|(a, b)| (a - b).powi(2)).sum();
        let dist = dist_sq.sqrt();
        let max_dist = (source.len() as f64).sqrt();
        let similarity = 1.0 - (dist / max_dist).min(1.0);
        similarity.max(0.0)
    }

    fn name(&self) -> &str {
        "EuclideanScorer"
    }
}

/// Cosine similarity based scorer.
#[derive(Debug, Clone, Default)]
pub struct CosineScorer;

impl CosineScorer {
    /// Create a new cosine scorer.
    pub fn new() -> Self {
        Self
    }
}

impl ExecutableScorer for CosineScorer {
    fn score_function(&self, source: &[f64], target: &[f64]) -> f64 {
        if source.len() != target.len() || source.is_empty() {
            return 0.0;
        }
        let dot: f64 = source.iter().zip(target.iter()).map(|(a, b)| a * b).sum();
        let mag_a: f64 = source.iter().map(|a| a * a).sum::<f64>().sqrt();
        let mag_b: f64 = target.iter().map(|b| b * b).sum::<f64>().sqrt();
        if mag_a == 0.0 || mag_b == 0.0 {
            return 0.0;
        }
        (dot / (mag_a * mag_b)).clamp(0.0, 1.0)
    }

    fn name(&self) -> &str {
        "CosineScorer"
    }
}

// ============================================================================
// ScoreCaching
// ============================================================================

/// Trait for caching function similarity scores.
///
/// Ports `ghidra.features.bsim.query.client.ScoreCaching`.
pub trait ScoreCache: Send + Sync + fmt::Debug {
    /// Look up a cached score.
    fn get(&self, source_id: i64, target_id: i64) -> Option<f64>;

    /// Store a score in the cache.
    fn put(&mut self, source_id: i64, target_id: i64, score: f64);

    /// Clear the cache.
    fn clear(&mut self);

    /// Number of cached entries.
    fn len(&self) -> usize;

    /// Whether the cache is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// In-memory score cache backed by a HashMap.
///
/// Ports `ghidra.features.bsim.query.client.TemporaryScoreCaching`.
#[derive(Debug, Default)]
pub struct TemporaryScoreCache {
    cache: HashMap<(i64, i64), f64>,
}

impl TemporaryScoreCache {
    /// Create a new temporary score cache.
    pub fn new() -> Self {
        Self { cache: HashMap::new() }
    }
}

impl ScoreCache for TemporaryScoreCache {
    fn get(&self, source_id: i64, target_id: i64) -> Option<f64> {
        self.cache.get(&(source_id, target_id)).copied()
    }

    fn put(&mut self, source_id: i64, target_id: i64, score: f64) {
        self.cache.insert((source_id, target_id), score);
    }

    fn clear(&mut self) {
        self.cache.clear();
    }

    fn len(&self) -> usize {
        self.cache.len()
    }
}

/// File-backed score cache using a path-based key.
///
/// Ports `ghidra.features.bsim.query.client.FileScoreCaching`.
#[derive(Debug, Clone)]
pub struct FileScoreCache {
    /// Path prefix for cache files.
    pub path_prefix: String,
    /// In-memory cache before flushing.
    pending: HashMap<(i64, i64), f64>,
    /// Whether changes need to be flushed.
    dirty: bool,
}

impl FileScoreCache {
    /// Create a new file-backed score cache.
    pub fn new(path_prefix: impl Into<String>) -> Self {
        Self {
            path_prefix: path_prefix.into(),
            pending: HashMap::new(),
            dirty: false,
        }
    }

    /// Whether the cache has unflushed changes.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Get the number of pending (in-memory) entries.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Mark the cache as flushed (clear dirty flag).
    pub fn mark_flushed(&mut self) {
        self.dirty = false;
    }
}

impl ScoreCache for FileScoreCache {
    fn get(&self, source_id: i64, target_id: i64) -> Option<f64> {
        self.pending.get(&(source_id, target_id)).copied()
    }

    fn put(&mut self, source_id: i64, target_id: i64, score: f64) {
        self.pending.insert((source_id, target_id), score);
        self.dirty = true;
    }

    fn clear(&mut self) {
        self.pending.clear();
        self.dirty = true;
    }

    fn len(&self) -> usize {
        self.pending.len()
    }
}

/// Table-backed score cache.
///
/// Ports `ghidra.features.bsim.query.client.TableScoreCaching`.
#[derive(Debug, Clone)]
pub struct TableScoreCache {
    /// Table name for the cache.
    pub table_name: String,
    /// In-memory cache.
    cache: HashMap<(i64, i64), f64>,
}

impl TableScoreCache {
    /// Create a new table-backed score cache.
    pub fn new(table_name: impl Into<String>) -> Self {
        Self {
            table_name: table_name.into(),
            cache: HashMap::new(),
        }
    }

    /// Generate the CREATE TABLE SQL for this cache.
    pub fn create_table_sql(&self) -> String {
        format!(
            "CREATE TABLE IF NOT EXISTS {} (
                source_id BIGINT NOT NULL,
                target_id BIGINT NOT NULL,
                score DOUBLE PRECISION NOT NULL,
                PRIMARY KEY (source_id, target_id)
            )",
            self.table_name
        )
    }

    /// Generate the INSERT SQL for storing a score.
    pub fn insert_sql(&self) -> String {
        format!(
            "INSERT INTO {} (source_id, target_id, score) VALUES (?, ?, ?) ON CONFLICT (source_id, target_id) DO UPDATE SET score = ?",
            self.table_name
        )
    }

    /// Generate the SELECT SQL for looking up a score.
    pub fn select_sql(&self) -> String {
        format!(
            "SELECT score FROM {} WHERE source_id = ? AND target_id = ?",
            self.table_name
        )
    }
}

impl ScoreCache for TableScoreCache {
    fn get(&self, source_id: i64, target_id: i64) -> Option<f64> {
        self.cache.get(&(source_id, target_id)).copied()
    }

    fn put(&mut self, source_id: i64, target_id: i64, score: f64) {
        self.cache.insert((source_id, target_id), score);
    }

    fn clear(&mut self) {
        self.cache.clear();
    }

    fn len(&self) -> usize {
        self.cache.len()
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// BSim client configuration.
///
/// Ports `ghidra.features.bsim.query.client.Configuration`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Configuration {
    /// Maximum number of results per query.
    pub max_results: usize,
    /// Default similarity threshold.
    pub similarity_threshold: f64,
    /// Default significance threshold.
    pub significance_threshold: f64,
    /// Connection timeout in seconds.
    pub connection_timeout_secs: u32,
    /// Query timeout in seconds.
    pub query_timeout_secs: u32,
    /// Maximum vector dimensions.
    pub max_vector_dimensions: usize,
    /// Whether to enable score caching.
    pub enable_caching: bool,
    /// Cache table name (if table-backed caching is used).
    pub cache_table_name: String,
    /// Whether to fill in category info for returned executables.
    pub fill_categories: bool,
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            max_results: 100,
            similarity_threshold: 0.7,
            significance_threshold: 0.0,
            connection_timeout_secs: 30,
            query_timeout_secs: 120,
            max_vector_dimensions: 256,
            enable_caching: true,
            cache_table_name: "scorecache".to_string(),
            fill_categories: true,
        }
    }
}

impl Configuration {
    /// Create a configuration with just a similarity threshold.
    pub fn with_threshold(threshold: f64) -> Self {
        Self {
            similarity_threshold: threshold,
            ..Default::default()
        }
    }

    /// Create a configuration with custom max results.
    pub fn with_max_results(max: usize) -> Self {
        Self {
            max_results: max,
            ..Default::default()
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_database_exception() {
        let e = NoDatabaseException::new("test error");
        assert_eq!(e.to_string(), "No database: test error");
    }

    #[test]
    fn test_cancelled_sql_exception() {
        let e = CancelledSqlException::new("user cancelled");
        assert!(e.to_string().contains("user cancelled"));
    }

    #[test]
    fn test_row_key_sql() {
        let key = RowKeySql::new("functions", 42);
        assert_eq!(key.table, "functions");
        assert_eq!(key.key, 42);
        assert_eq!(key.to_string(), "functions:42");
    }

    #[test]
    fn test_id_sql_resolution() {
        let mut res = IdSqlResolution::new();
        assert!(res.is_empty());
        res.add("func1", RowKeySql::new("functions", 1));
        res.add("func2", RowKeySql::new("functions", 2));
        assert_eq!(res.len(), 2);
        assert!(res.resolve("func1").is_some());
        assert_eq!(res.resolve("func1").unwrap().key, 1);
        assert!(res.resolve("nonexistent").is_none());
    }

    #[test]
    fn test_sql_effects() {
        let mut effects = SqlEffects::new();
        effects.record_insert(5);
        effects.record_update(3);
        effects.record_delete(1);
        effects.record_query();
        effects.record_error("test error");
        assert_eq!(effects.total_affected(), 9);
        assert_eq!(effects.queries, 1);
        assert!(effects.has_errors());
    }

    #[test]
    fn test_sql_effects_merge() {
        let mut a = SqlEffects::new();
        a.record_insert(5);
        let mut b = SqlEffects::new();
        b.record_update(3);
        a.merge(&b);
        assert_eq!(a.total_affected(), 8);
    }

    #[test]
    fn test_id_histogram() {
        let mut hist = IdHistogram::new();
        hist.record(1);
        hist.record(1);
        hist.record(2);
        assert_eq!(hist.get(1), 2);
        assert_eq!(hist.get(2), 1);
        assert_eq!(hist.get(3), 0);
        assert_eq!(hist.unique_count(), 2);
        assert_eq!(hist.total, 3);
        assert!((hist.frequency(1) - 2.0 / 3.0).abs() < 1e-6);
    }

    #[test]
    fn test_id_histogram_merge() {
        let mut a = IdHistogram::new();
        a.record(1);
        let mut b = IdHistogram::new();
        b.record(1);
        b.record(2);
        a.merge(&b);
        assert_eq!(a.get(1), 2);
        assert_eq!(a.get(2), 1);
        assert_eq!(a.total, 3);
    }

    #[test]
    fn test_executable_comparison() {
        let mut comp = ExecutableComparison::new(1, 2);
        comp.source_function_count = 10;
        comp.add_match(100, 200, 0.95);
        comp.add_match(101, 201, 0.80);
        comp.compute_similarity();
        assert!(comp.similarity > 0.0);
        assert_eq!(comp.match_count, 2);
    }

    #[test]
    fn test_executable_comparison_empty() {
        let mut comp = ExecutableComparison::new(1, 2);
        comp.source_function_count = 0;
        comp.compute_similarity();
        assert_eq!(comp.similarity, 0.0);
    }

    #[test]
    fn test_euclidean_scorer() {
        let scorer = EuclideanScorer::new(0.7);
        assert_eq!(scorer.name(), "EuclideanScorer");
        // Identical vectors should score 1.0
        let score = scorer.score_function(&[1.0, 0.0, 0.0], &[1.0, 0.0, 0.0]);
        assert!((score - 1.0).abs() < 1e-6);
        // Different lengths should score 0.0
        let score = scorer.score_function(&[1.0], &[1.0, 0.0]);
        assert_eq!(score, 0.0);
    }

    #[test]
    fn test_euclidean_scorer_batch() {
        let scorer = EuclideanScorer::default();
        let pairs = vec![
            (vec![1.0, 0.0], vec![1.0, 0.0]),
            (vec![0.0, 1.0], vec![0.0, 1.0]),
        ];
        let scores = scorer.score_batch(&pairs);
        assert_eq!(scores.len(), 2);
        for s in &scores {
            assert!((s - 1.0).abs() < 1e-6);
        }
    }

    #[test]
    fn test_cosine_scorer() {
        let scorer = CosineScorer::new();
        assert_eq!(scorer.name(), "CosineScorer");
        // Same direction: score = 1.0
        let score = scorer.score_function(&[1.0, 0.0], &[2.0, 0.0]);
        assert!((score - 1.0).abs() < 1e-6);
        // Orthogonal: score = 0.0
        let score = scorer.score_function(&[1.0, 0.0], &[0.0, 1.0]);
        assert!(score.abs() < 1e-6);
        // Empty: score = 0.0
        let score = scorer.score_function(&[], &[]);
        assert_eq!(score, 0.0);
    }

    #[test]
    fn test_temporary_score_cache() {
        let mut cache = TemporaryScoreCache::new();
        assert!(cache.is_empty());
        cache.put(1, 2, 0.95);
        cache.put(3, 4, 0.80);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get(1, 2), Some(0.95));
        assert_eq!(cache.get(1, 3), None);
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_file_score_cache() {
        let mut cache = FileScoreCache::new("/tmp/scores");
        assert!(!cache.is_dirty());
        cache.put(1, 2, 0.9);
        assert!(cache.is_dirty());
        assert_eq!(cache.pending_count(), 1);
        cache.mark_flushed();
        assert!(!cache.is_dirty());
    }

    #[test]
    fn test_table_score_cache() {
        let cache = TableScoreCache::new("mycache");
        assert_eq!(cache.table_name, "mycache");
        assert!(cache.create_table_sql().contains("CREATE TABLE"));
        assert!(cache.insert_sql().contains("ON CONFLICT"));
        assert!(cache.select_sql().contains("source_id = ?"));
    }

    #[test]
    fn test_configuration_default() {
        let config = Configuration::default();
        assert_eq!(config.max_results, 100);
        assert!((config.similarity_threshold - 0.7).abs() < 1e-6);
        assert!(config.enable_caching);
        assert!(config.fill_categories);
    }

    #[test]
    fn test_configuration_builder() {
        let config = Configuration::with_threshold(0.9);
        assert!((config.similarity_threshold - 0.9).abs() < 1e-6);
        assert_eq!(config.max_results, 100); // default

        let config = Configuration::with_max_results(500);
        assert_eq!(config.max_results, 500);
    }
}
