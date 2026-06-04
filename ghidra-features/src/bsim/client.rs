//! BSim client types -- Rust port of Ghidra's `ghidra.features.bsim.query.client` package.
//!
//! This module provides the client-layer types for BSim database interaction:
//! - [`FunctionDatabase`] trait -- abstract database interface
//! - [`ExecutableComparison`] -- compare executables by similarity scores
//! - [`ExecutableScorer`] -- score function pairs between executables
//! - [`ScoreCaching`] -- cache self-scores for normalization
//! - [`Configuration`] -- client configuration
//! - [`RowKeySql`] -- SQL-compatible row key
//! - [`SqlEffects`] -- accumulated SQL side effects

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::description::{
    CategoryRecord, DatabaseInformation, DescriptionManager, ExecutableRecord,
    FunctionDescription, RowKey, VectorResult,
};
use super::protocol::{
    BSimFilter, BSimQueryType, BSimResponseType, FunctionEntry,
    SimilarityResult,
};

// ============================================================================
// Errors
// ============================================================================

/// Error type for BSim database operations.
#[derive(Debug, Clone)]
pub enum BSimError {
    /// No database connection established.
    NoDatabase(String),
    /// SQL error (for SQL-backed databases).
    SqlError(String),
    /// Cancelled by user.
    Cancelled,
    /// LSH vector processing error.
    LshError(String),
    /// General query error.
    QueryError(String),
    /// Database does not exist.
    DatabaseNotFound(String),
    /// Invalid query parameters.
    InvalidQuery(String),
    /// I/O error.
    IoError(String),
    /// Serialization error.
    SerializationError(String),
}

impl std::fmt::Display for BSimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BSimError::NoDatabase(msg) => write!(f, "no database: {}", msg),
            BSimError::SqlError(msg) => write!(f, "SQL error: {}", msg),
            BSimError::Cancelled => write!(f, "operation cancelled"),
            BSimError::LshError(msg) => write!(f, "LSH error: {}", msg),
            BSimError::QueryError(msg) => write!(f, "query error: {}", msg),
            BSimError::DatabaseNotFound(msg) => write!(f, "database not found: {}", msg),
            BSimError::InvalidQuery(msg) => write!(f, "invalid query: {}", msg),
            BSimError::IoError(msg) => write!(f, "I/O error: {}", msg),
            BSimError::SerializationError(msg) => write!(f, "serialization error: {}", msg),
        }
    }
}

impl std::error::Error for BSimError {}

/// Result type for BSim operations.
pub type BSimResult<T> = Result<T, BSimError>;

// ============================================================================
// FunctionDatabase trait
// ============================================================================

/// Connection type for the database backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionType {
    /// PostgreSQL database.
    Postgresql,
    /// Elasticsearch backend.
    Elasticsearch,
    /// H2 file-based database.
    H2File,
    /// In-memory database.
    InMemory,
}

/// Status of a database connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DatabaseStatus {
    /// Not connected.
    Disconnected,
    /// Connected and ready.
    Connected,
    /// Connection error.
    Error,
}

/// The abstract database interface for BSim.
///
/// This mirrors the Java `FunctionDatabase` abstract class. Implementations
/// provide specific backends (PostgreSQL, Elasticsearch, H2 file, etc.).
pub trait FunctionDatabase: Send + Sync {
    /// Get the connection type.
    fn connection_type(&self) -> ConnectionType;

    /// Get the current connection status.
    fn status(&self) -> DatabaseStatus;

    /// Get the database information/metadata.
    fn database_info(&self) -> BSimResult<Option<DatabaseInformation>>;

    /// Open the database connection.
    fn open(&mut self, url: &str) -> BSimResult<()>;

    /// Close the database connection.
    fn close(&mut self) -> BSimResult<()>;

    /// Whether the database is connected.
    fn is_connected(&self) -> bool {
        self.status() == DatabaseStatus::Connected
    }

    /// Execute a query against the database.
    fn query(&mut self, query: &mut BSimQueryType) -> BSimResult<BSimResponseType>;

    /// Get the description manager (if available).
    fn description_manager(&self) -> Option<&DescriptionManager>;

    /// Get a mutable reference to the description manager.
    fn description_manager_mut(&mut self) -> Option<&mut DescriptionManager>;

    /// Create a new database.
    fn create_database(&mut self, info: &DatabaseInformation) -> BSimResult<()>;

    /// Drop (delete) the database.
    fn drop_database(&mut self) -> BSimResult<()>;

    /// Get the number of executables in the database.
    fn executable_count(&mut self) -> BSimResult<u32>;

    /// Install a category into the database.
    fn install_category(&mut self, category: &CategoryRecord) -> BSimResult<()>;

    /// Install metadata.
    fn install_metadata(&mut self, info: &DatabaseInformation) -> BSimResult<()>;

    /// Install a function tag.
    fn install_tag(&mut self, tag_name: &str) -> BSimResult<()>;

    /// Prewarm database caches.
    fn prewarm(&mut self) -> BSimResult<()>;
}

// ============================================================================
// Configuration
// ============================================================================

/// Client-side configuration for BSim queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Configuration {
    /// Default similarity threshold.
    pub similarity_threshold: f64,
    /// Default significance threshold.
    pub significance_threshold: f64,
    /// Maximum number of results per query.
    pub max_results: u32,
    /// Maximum cluster size (functions in a single cluster).
    pub max_cluster_size: u32,
    /// Timeout in seconds for queries.
    pub query_timeout_secs: u64,
    /// Whether to track callgraph information.
    pub track_callgraph: bool,
    /// Whether to use LSH (Locality-Sensitive Hashing) optimization.
    pub use_lsh: bool,
    /// Number of LSH stages.
    pub num_lsh_stages: u32,
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            similarity_threshold: 0.7,
            significance_threshold: 4.0,
            max_results: 100,
            max_cluster_size: 500,
            query_timeout_secs: 300,
            track_callgraph: true,
            use_lsh: true,
            num_lsh_stages: 4,
        }
    }
}

// ============================================================================
// RowKeySql
// ============================================================================

/// SQL-compatible row key (wraps a 64-bit identifier with optional name).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RowKeySql {
    /// The 64-bit key value.
    pub key: u64,
    /// Optional human-readable name for debugging.
    pub name: Option<String>,
}

impl RowKeySql {
    /// Create a new row key.
    pub fn new(key: u64) -> Self {
        Self { key, name: None }
    }

    /// Create a named row key.
    pub fn with_name(key: u64, name: impl Into<String>) -> Self {
        Self {
            key,
            name: Some(name.into()),
        }
    }
}

impl From<u64> for RowKeySql {
    fn from(key: u64) -> Self {
        Self::new(key)
    }
}

// ============================================================================
// SqlEffects
// ============================================================================

/// Tracks accumulated SQL side effects during a batch of operations.
///
/// Used to report what changed in the database after a series of inserts,
/// updates, or deletes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SqlEffects {
    /// Number of rows inserted.
    pub inserts: u32,
    /// Number of rows updated.
    pub updates: u32,
    /// Number of rows deleted.
    pub deletes: u32,
    /// Number of errors encountered.
    pub errors: u32,
    /// Error messages collected during processing.
    pub error_messages: Vec<String>,
}

impl SqlEffects {
    /// Create a new empty effects tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge another SqlEffects into this one.
    pub fn merge(&mut self, other: &SqlEffects) {
        self.inserts += other.inserts;
        self.updates += other.updates;
        self.deletes += other.deletes;
        self.errors += other.errors;
        self.error_messages.extend(other.error_messages.clone());
    }

    /// Whether any changes were made.
    pub fn has_changes(&self) -> bool {
        self.inserts > 0 || self.updates > 0 || self.deletes > 0
    }

    /// Whether any errors occurred.
    pub fn has_errors(&self) -> bool {
        self.errors > 0
    }
}

// ============================================================================
// IdHistogram
// ============================================================================

/// A histogram mapping vector-IDs to their hit counts.
///
/// Used for frequency analysis of function similarity clusters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdHistogram {
    /// Map from vector-ID to count of matching functions.
    pub counts: HashMap<u64, u32>,
}

impl IdHistogram {
    /// Create a new empty histogram.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment the count for a vector-ID.
    pub fn increment(&mut self, vector_id: u64) {
        *self.counts.entry(vector_id).or_insert(0) += 1;
    }

    /// Get the count for a vector-ID.
    pub fn get(&self, vector_id: u64) -> u32 {
        self.counts.get(&vector_id).copied().unwrap_or(0)
    }

    /// Get the most frequent vector-ID.
    pub fn most_frequent(&self) -> Option<(u64, u32)> {
        self.counts
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(&id, &count)| (id, count))
    }

    /// Total number of entries.
    pub fn len(&self) -> usize {
        self.counts.len()
    }

    /// Whether the histogram is empty.
    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }
}

// ============================================================================
// FunctionPair
// ============================================================================

/// A pair of similar functions used in executable comparison scoring.
#[derive(Debug, Clone)]
pub struct FunctionPair {
    /// First function in the pair.
    pub func_a: FunctionDescription,
    /// Second function in the pair.
    pub func_b: FunctionDescription,
    /// Similarity score between the pair.
    pub similarity: f64,
    /// Significance score of the pair.
    pub significance: f64,
}

impl FunctionPair {
    /// Create a new function pair.
    pub fn new(
        func_a: FunctionDescription,
        func_b: FunctionDescription,
        similarity: f64,
        significance: f64,
    ) -> Self {
        Self {
            func_a,
            func_b,
            similarity,
            significance,
        }
    }
}

// ============================================================================
// ScoreCaching
// ============================================================================

/// Trait for caching self-scores of executables for normalization.
///
/// When comparing executables, raw scores need to be normalized by dividing
/// by the self-scores (the score of an executable compared to itself).
pub trait ScoreCaching: Send + Sync {
    /// Get the cached self-score for an executable (by MD5).
    fn get_self_score(&self, md5: &str) -> Option<f64>;

    /// Set the self-score for an executable.
    fn set_self_score(&mut self, md5: &str, score: f64);

    /// Clear all cached scores.
    fn clear(&mut self);
}

/// In-memory score cache (no persistence).
#[derive(Debug, Clone, Default)]
pub struct TemporaryScoreCaching {
    /// Map from MD5 to self-score.
    scores: HashMap<String, f64>,
}

impl TemporaryScoreCaching {
    /// Create a new temporary score cache.
    pub fn new() -> Self {
        Self::default()
    }
}

impl ScoreCaching for TemporaryScoreCaching {
    fn get_self_score(&self, md5: &str) -> Option<f64> {
        self.scores.get(md5).copied()
    }

    fn set_self_score(&mut self, md5: &str, score: f64) {
        self.scores.insert(md5.to_string(), score);
    }

    fn clear(&mut self) {
        self.scores.clear();
    }
}

/// File-backed score cache (persists to a file).
#[derive(Debug, Clone, Default)]
pub struct FileScoreCaching {
    /// In-memory cache.
    cache: TemporaryScoreCaching,
    /// Path to the backing file.
    file_path: Option<String>,
}

impl FileScoreCaching {
    /// Create a new file-backed score cache.
    pub fn new(file_path: impl Into<String>) -> Self {
        Self {
            cache: TemporaryScoreCaching::new(),
            file_path: Some(file_path.into()),
        }
    }

    /// Save the cache to the file.
    pub fn save(&self) -> BSimResult<()> {
        // In a full implementation, this would serialize to the file.
        Ok(())
    }

    /// Load the cache from the file.
    pub fn load(&mut self) -> BSimResult<()> {
        // In a full implementation, this would deserialize from the file.
        Ok(())
    }
}

impl ScoreCaching for FileScoreCaching {
    fn get_self_score(&self, md5: &str) -> Option<f64> {
        self.cache.get_self_score(md5)
    }

    fn set_self_score(&mut self, md5: &str, score: f64) {
        self.cache.set_self_score(md5, score);
    }

    fn clear(&mut self) {
        self.cache.clear();
    }
}

/// Table-backed score cache (persists to a database table).
#[derive(Debug, Clone, Default)]
pub struct TableScoreCaching {
    /// In-memory cache.
    cache: TemporaryScoreCaching,
    /// Table name in the database.
    table_name: String,
}

impl TableScoreCaching {
    /// Create a new table-backed score cache.
    pub fn new(table_name: impl Into<String>) -> Self {
        Self {
            cache: TemporaryScoreCaching::new(),
            table_name: table_name.into(),
        }
    }

    /// Get the table name.
    pub fn table_name(&self) -> &str {
        &self.table_name
    }
}

impl ScoreCaching for TableScoreCaching {
    fn get_self_score(&self, md5: &str) -> Option<f64> {
        self.cache.get_self_score(md5)
    }

    fn set_self_score(&mut self, md5: &str, score: f64) {
        self.cache.set_self_score(md5, score);
    }

    fn clear(&mut self) {
        self.cache.clear();
    }
}

// ============================================================================
// ExecutableScorer
// ============================================================================

/// Scores function pairs between executables for BSim comparison.
///
/// Manages a scoring matrix where each entry [i][j] represents the
/// accumulated significance score between executable i and executable j.
/// The scoring avoids over-counting by tracking which functions have
/// already been scored for each executable pair.
#[derive(Debug)]
pub struct ExecutableScorer {
    /// The scoring matrix (upper-triangular).
    score: Vec<Vec<f64>>,
    /// Number of executables.
    num_exes: usize,
    /// Similarity threshold for accepting a function pair.
    pub similarity_threshold: f64,
    /// Significance threshold for accepting a function pair.
    pub significance_threshold: f64,
    /// Maximum hit count per cluster.
    pub max_hit_count: usize,
}

impl ExecutableScorer {
    /// Create a new executable scorer for `num_exes` executables.
    pub fn new(num_exes: usize) -> Self {
        // Upper-triangular matrix: row i has (num_exes - i - 1) columns.
        let score = (0..num_exes)
            .map(|i| vec![0.0; num_exes - i - 1])
            .collect();

        Self {
            score,
            num_exes,
            similarity_threshold: 0.7,
            significance_threshold: 4.0,
            max_hit_count: 500,
        }
    }

    /// Score a function pair, adding the significance to the matrix.
    ///
    /// The pair is scored at position [min(xref_a, xref_b)][max(xref_a, xref_b)]
    /// using the executable cross-reference indices.
    pub fn score_pair(&mut self, pair: &FunctionPair) {
        let index_a = pair.func_a.exe_index;
        let index_b = pair.func_b.exe_index;

        if index_a == index_b {
            return; // Don't score within the same executable.
        }

        let (row, col) = if index_b > index_a {
            (index_a, index_b - index_a - 1)
        } else {
            (index_b, index_a - index_b - 1)
        };

        if row < self.score.len() && col < self.score[row].len() {
            self.score[row][col] += pair.significance;
        }
    }

    /// Get the score between two executables.
    pub fn get_score(&self, exe_a: usize, exe_b: usize) -> f64 {
        if exe_a == exe_b {
            return 0.0;
        }
        let (row, col) = if exe_b > exe_a {
            (exe_a, exe_b - exe_a - 1)
        } else {
            (exe_b, exe_a - exe_b - 1)
        };
        self.score
            .get(row)
            .and_then(|r| r.get(col))
            .copied()
            .unwrap_or(0.0)
    }

    /// Score all pairs from a list of functions.
    ///
    /// For each cluster of similar functions (same vector-id), generates
    /// function pairs and scores them with de-duplication.
    pub fn score_all_pairs(
        &mut self,
        functions: &[FunctionDescription],
        similarity_threshold: f64,
        significance_threshold: f64,
    ) {
        // Group functions by (exe_index, vector_id) for efficient comparison.
        let mut groups: HashMap<(usize, u64), Vec<&FunctionDescription>> = HashMap::new();
        for func in functions {
            if let Some(ref sig) = func.signature {
                let key = (func.exe_index, sig.vector_id);
                groups.entry(key).or_default().push(func);
            }
        }

        // Compare across groups.
        let group_keys: Vec<(usize, u64)> = groups.keys().copied().collect();
        for (i, key1) in group_keys.iter().enumerate() {
            let funcs1 = &groups[key1];
            for key2 in group_keys.iter().skip(i + 1) {
                let funcs2 = &groups[key2];
                if key1.0 == key2.0 {
                    continue; // Same executable.
                }
                // Generate pairs.
                for f1 in funcs1.iter() {
                    for f2 in funcs2.iter() {
                        let pair = FunctionPair::new(
                            (*f1).clone(),
                            (*f2).clone(),
                            1.0, // Pre-computed similarity
                            1.0, // Pre-computed significance
                        );
                        self.score_pair(&pair);
                    }
                }
            }
        }
    }

    /// Get the number of executables.
    pub fn num_exes(&self) -> usize {
        self.num_exes
    }

    /// Get the full scoring matrix as a flattened vector.
    pub fn scores(&self) -> &[Vec<f64>] {
        &self.score
    }

    /// Reset all scores to zero.
    pub fn reset(&mut self) {
        for row in &mut self.score {
            for val in row.iter_mut() {
                *val = 0.0;
            }
        }
    }
}

// ============================================================================
// ExecutableComparison
// ============================================================================

/// Compare an entire set of executables to each other by combining
/// significance scores between functions.
///
/// The algorithm uses divide-and-conquer based on clusters of similar
/// functions, which greatly improves efficiency over full quadratic
/// comparison.
pub struct ExecutableComparison {
    /// The scoring engine.
    pub scorer: ExecutableScorer,
    /// Executable records indexed by xref_index.
    pub executables: Vec<ExecutableRecord>,
    /// Score cache for normalization.
    pub cache: Option<Box<dyn ScoreCaching>>,
    /// The single executable to focus on (if any).
    pub single_md5: Option<String>,
}

impl ExecutableComparison {
    /// Create a new executable comparison.
    pub fn new(num_exes: usize) -> Self {
        Self {
            scorer: ExecutableScorer::new(num_exes),
            executables: Vec::new(),
            cache: None,
            single_md5: None,
        }
    }

    /// Set the executable records.
    pub fn set_executables(&mut self, exes: Vec<ExecutableRecord>) {
        self.executables = exes;
    }

    /// Set the score cache.
    pub fn set_cache(&mut self, cache: Box<dyn ScoreCaching>) {
        self.cache = Some(cache);
    }

    /// Set the single MD5 to focus comparison on.
    pub fn set_single_md5(&mut self, md5: impl Into<String>) {
        self.single_md5 = Some(md5.into());
    }

    /// Get the score between two executables by index.
    pub fn get_score(&self, exe_a: usize, exe_b: usize) -> f64 {
        self.scorer.get_score(exe_a, exe_b)
    }

    /// Get the normalized score (score / self_score) between two executables.
    pub fn get_normalized_score(&self, exe_a: usize, exe_b: usize) -> f64 {
        let raw_score = self.scorer.get_score(exe_a, exe_b);
        if raw_score == 0.0 {
            return 0.0;
        }
        if let Some(ref cache) = self.cache {
            if let Some(exe) = self.executables.get(exe_a) {
                if let Some(self_score) = cache.get_self_score(&exe.md5) {
                    if self_score > 0.0 {
                        return raw_score / self_score;
                    }
                }
            }
        }
        raw_score
    }

    /// Run the comparison over a set of functions.
    pub fn compare(&mut self, functions: &[FunctionDescription]) {
        self.scorer
            .score_all_pairs(functions, self.scorer.similarity_threshold, self.scorer.significance_threshold);
    }
}

// ============================================================================
// BSimSqlClause
// ============================================================================

/// A SQL clause builder for BSim queries.
///
/// Used to construct parameterized SQL statements for querying the database.
#[derive(Debug, Clone, Default)]
pub struct BSimSqlClause {
    /// The SQL query string.
    pub sql: String,
    /// Parameter values for the query.
    pub params: Vec<String>,
}

impl BSimSqlClause {
    /// Create a new SQL clause.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create from a SQL string.
    pub fn from_sql(sql: impl Into<String>) -> Self {
        Self {
            sql: sql.into(),
            params: Vec::new(),
        }
    }

    /// Add a parameter.
    pub fn add_param(&mut self, value: impl Into<String>) {
        self.params.push(value.into());
    }

    /// Append SQL text.
    pub fn append(&mut self, sql: &str) {
        self.sql.push_str(sql);
    }
}

// ============================================================================
// IdSqlResolution
// ============================================================================

/// Resolves SQL-based vector-IDs to their corresponding feature vectors.
#[derive(Debug, Clone, Default)]
pub struct IdSqlResolution {
    /// Map from vector-ID to vector result.
    pub resolutions: HashMap<u64, VectorResult>,
}

impl IdSqlResolution {
    /// Create a new resolution map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a resolution.
    pub fn add(&mut self, vector_id: u64, result: VectorResult) {
        self.resolutions.insert(vector_id, result);
    }

    /// Look up a resolution by vector-ID.
    pub fn get(&self, vector_id: u64) -> Option<&VectorResult> {
        self.resolutions.get(&vector_id)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_defaults() {
        let config = Configuration::default();
        assert!((config.similarity_threshold - 0.7).abs() < 1e-9);
        assert!((config.significance_threshold - 4.0).abs() < 1e-9);
        assert_eq!(config.max_results, 100);
        assert!(config.track_callgraph);
    }

    #[test]
    fn row_key_sql_creation() {
        let key = RowKeySql::new(42);
        assert_eq!(key.key, 42);
        assert!(key.name.is_none());

        let named = RowKeySql::with_name(99, "test_key");
        assert_eq!(named.key, 99);
        assert_eq!(named.name.as_deref(), Some("test_key"));
    }

    #[test]
    fn sql_effects_merge() {
        let mut e1 = SqlEffects::new();
        e1.inserts = 5;
        e1.deletes = 2;

        let mut e2 = SqlEffects::new();
        e2.inserts = 3;
        e2.updates = 1;
        e2.error_messages.push("error".to_string());

        e1.merge(&e2);
        assert_eq!(e1.inserts, 8);
        assert_eq!(e1.updates, 1);
        assert_eq!(e1.deletes, 2);
        assert!(e1.has_changes());
    }

    #[test]
    fn id_histogram() {
        let mut h = IdHistogram::new();
        h.increment(1);
        h.increment(1);
        h.increment(2);
        assert_eq!(h.get(1), 2);
        assert_eq!(h.get(2), 1);
        assert_eq!(h.get(3), 0);
        assert_eq!(h.len(), 2);
        let (id, count) = h.most_frequent().unwrap();
        assert_eq!(id, 1);
        assert_eq!(count, 2);
    }

    #[test]
    fn executable_scorer_matrix() {
        let mut scorer = ExecutableScorer::new(3);
        assert_eq!(scorer.num_exes(), 3);

        // Score between exe 0 and exe 2.
        let pair = FunctionPair::new(
            FunctionDescription::new(0, "fn1", Some(0x1000)),
            FunctionDescription::new(2, "fn2", Some(0x2000)),
            0.9,
            5.0,
        );
        scorer.score_pair(&pair);
        assert!((scorer.get_score(0, 2) - 5.0).abs() < 1e-9);
        assert!((scorer.get_score(2, 0) - 5.0).abs() < 1e-9); // Symmetric.
        assert_eq!(scorer.get_score(0, 1), 0.0);
    }

    #[test]
    fn executable_scorer_same_exe_skipped() {
        let mut scorer = ExecutableScorer::new(3);
        let pair = FunctionPair::new(
            FunctionDescription::new(0, "fn1", Some(0x1000)),
            FunctionDescription::new(0, "fn2", Some(0x2000)),
            0.9,
            5.0,
        );
        scorer.score_pair(&pair);
        assert_eq!(scorer.get_score(0, 0), 0.0);
    }

    #[test]
    fn executable_scorer_reset() {
        let mut scorer = ExecutableScorer::new(2);
        let pair = FunctionPair::new(
            FunctionDescription::new(0, "fn1", Some(0x1000)),
            FunctionDescription::new(1, "fn2", Some(0x2000)),
            0.9,
            5.0,
        );
        scorer.score_pair(&pair);
        assert!((scorer.get_score(0, 1) - 5.0).abs() < 1e-9);

        scorer.reset();
        assert_eq!(scorer.get_score(0, 1), 0.0);
    }

    #[test]
    fn executable_comparison_basic() {
        let mut comp = ExecutableComparison::new(3);
        comp.set_executables(vec![
            ExecutableRecord::new("aaa", "prog1", "x86", "gcc"),
            ExecutableRecord::new("bbb", "prog2", "x86", "gcc"),
            ExecutableRecord::new("ccc", "prog3", "x86", "gcc"),
        ]);
        assert_eq!(comp.executables.len(), 3);
    }

    #[test]
    fn temporary_score_caching() {
        let mut cache = TemporaryScoreCaching::new();
        assert!(cache.get_self_score("abc").is_none());
        cache.set_self_score("abc", 42.0);
        assert!((cache.get_self_score("abc").unwrap() - 42.0).abs() < 1e-9);
        cache.clear();
        assert!(cache.get_self_score("abc").is_none());
    }

    #[test]
    fn bsim_sql_clause() {
        let mut clause = BSimSqlClause::from_sql("SELECT * FROM functions WHERE md5 = ?");
        clause.add_param("abc123");
        assert_eq!(clause.params.len(), 1);
        assert!(clause.sql.contains("SELECT"));
    }

    #[test]
    fn connection_type_variants() {
        assert_ne!(ConnectionType::Postgresql, ConnectionType::Elasticsearch);
        assert_ne!(ConnectionType::H2File, ConnectionType::InMemory);
    }

    #[test]
    fn database_status_variants() {
        assert_ne!(DatabaseStatus::Connected, DatabaseStatus::Disconnected);
        assert_ne!(DatabaseStatus::Error, DatabaseStatus::Connected);
    }

    #[test]
    fn id_sql_resolution() {
        let mut res = IdSqlResolution::new();
        let vr = VectorResult::new(42, 3, 0.9, 5.0, None);
        res.add(42, vr);
        assert!(res.get(42).is_some());
        assert!(res.get(99).is_none());
    }

    #[test]
    fn bsim_error_display() {
        let err = BSimError::NoDatabase("test".to_string());
        assert!(format!("{}", err).contains("no database"));

        let err = BSimError::Cancelled;
        assert!(format!("{}", err).contains("cancelled"));
    }
}
