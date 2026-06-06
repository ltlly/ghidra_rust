//! Abstract SQL-based function database.
//!
//! Port of Ghidra's `ghidra.features.bsim.query.client.AbstractSQLFunctionDatabase`.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// SQL clause builder for BSim queries.
///
/// Port of `ghidra.features.bsim.query.client.BSimSqlClause`.
#[derive(Debug, Clone, Default)]
pub struct BSimSqlClause {
    /// The clause fragments.
    pub fragments: Vec<String>,
    /// Named parameters.
    pub parameters: HashMap<String, String>,
}

impl BSimSqlClause {
    /// Create a new empty SQL clause.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a fragment.
    pub fn append(&mut self, fragment: impl Into<String>) {
        self.fragments.push(fragment.into());
    }

    /// Add a named parameter.
    pub fn add_parameter(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.parameters.insert(name.into(), value.into());
    }

    /// Build the final SQL string.
    pub fn build(&self) -> String {
        self.fragments.join(" ")
    }
}

/// Configuration for SQL-based function databases.
///
/// Port of `ghidra.features.bsim.query.client.Configuration`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Configuration {
    /// Maximum number of functions per bulk query.
    pub max_function_bulk: usize,
    /// Maximum number of vector deletes per window.
    pub max_vector_delete_window: usize,
    /// Similarity threshold.
    pub similarity_threshold: f64,
    /// Signature threshold.
    pub signature_threshold: f64,
    /// Default queries per stage.
    pub default_queries_per_stage: usize,
    /// Table name for architecture data.
    pub arch_table_name: String,
    /// Layout version.
    pub layout_version: u32,
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            max_function_bulk: 1000,
            max_vector_delete_window: 100,
            similarity_threshold: 0.8,
            signature_threshold: 0.6,
            default_queries_per_stage: 50,
            arch_table_name: "architecture".into(),
            layout_version: 1,
        }
    }
}

impl Configuration {
    /// Create a new configuration with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the similarity threshold.
    pub fn with_similarity_threshold(mut self, threshold: f64) -> Self {
        self.similarity_threshold = threshold;
        self
    }

    /// Set the signature threshold.
    pub fn with_signature_threshold(mut self, threshold: f64) -> Self {
        self.signature_threshold = threshold;
        self
    }
}

/// SQL effects tracker -- tracks what SQL operations have been performed.
///
/// Port of `ghidra.features.bsim.query.client.SQLEffects`.
#[derive(Debug, Clone, Default)]
pub struct SqlEffects {
    /// Number of inserts performed.
    pub inserts: u64,
    /// Number of selects performed.
    pub selects: u64,
    /// Number of updates performed.
    pub updates: u64,
    /// Number of deletes performed.
    pub deletes: u64,
    /// Whether any effects have been recorded.
    pub has_effects: bool,
}

impl SqlEffects {
    /// Create a new SQL effects tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an insert.
    pub fn record_insert(&mut self, count: u64) {
        self.inserts += count;
        self.has_effects = true;
    }

    /// Record a select.
    pub fn record_select(&mut self, count: u64) {
        self.selects += count;
        self.has_effects = true;
    }

    /// Record an update.
    pub fn record_update(&mut self, count: u64) {
        self.updates += count;
        self.has_effects = true;
    }

    /// Record a delete.
    pub fn record_delete(&mut self, count: u64) {
        self.deletes += count;
        self.has_effects = true;
    }

    /// Total operations.
    pub fn total(&self) -> u64 {
        self.inserts + self.selects + self.updates + self.deletes
    }
}

/// Cancelled SQL exception.
///
/// Port of `ghidra.features.bsim.query.client.CancelledSQLException`.
#[derive(Debug, Clone, thiserror::Error)]
#[error("SQL operation cancelled: {message}")]
pub struct CancelledSqlException {
    /// Error message.
    pub message: String,
}

impl CancelledSqlException {
    /// Create a new cancelled SQL exception.
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

/// A single-row SQL score result.
///
/// Port of `ghidra.features.bsim.query.client.ExecutableScorerSingle`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutableScorerSingle {
    /// Executable id.
    pub exe_id: i64,
    /// Similarity score.
    pub score: f64,
    /// Number of matched functions.
    pub match_count: u32,
    /// Self-score (reference baseline).
    pub self_score: f64,
}

impl ExecutableScorerSingle {
    /// Create a new executable scorer result.
    pub fn new(exe_id: i64, score: f64, match_count: u32, self_score: f64) -> Self {
        Self { exe_id, score, match_count, self_score }
    }

    /// Normalized score (0.0..=1.0).
    pub fn normalized_score(&self) -> f64 {
        if self.self_score == 0.0 {
            0.0
        } else {
            (self.score / self.self_score).min(1.0)
        }
    }
}

/// Temporary score caching.
///
/// Port of `ghidra.features.bsim.query.client.TemporaryScoreCaching`.
#[derive(Debug, Clone, Default)]
pub struct TemporaryScoreCache {
    /// Scores keyed by (source_id, target_id).
    scores: HashMap<(i64, i64), f64>,
}

impl TemporaryScoreCache {
    /// Create a new temporary score cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a score.
    pub fn put(&mut self, source_id: i64, target_id: i64, score: f64) {
        self.scores.insert((source_id, target_id), score);
    }

    /// Get a cached score.
    pub fn get(&self, source_id: i64, target_id: i64) -> Option<f64> {
        self.scores.get(&(source_id, target_id)).copied()
    }

    /// Whether the cache contains a score for the given pair.
    pub fn contains(&self, source_id: i64, target_id: i64) -> bool {
        self.scores.contains_key(&(source_id, target_id))
    }

    /// Clear the cache.
    pub fn clear(&mut self) {
        self.scores.clear();
    }

    /// Number of cached entries.
    pub fn len(&self) -> usize {
        self.scores.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.scores.is_empty()
    }
}

/// Abstract base for SQL-backed function databases.
///
/// Port of `ghidra.features.bsim.query.client.AbstractSQLFunctionDatabase`.
#[derive(Debug)]
pub struct AbstractSqlFunctionDatabase {
    /// Connection URL / description.
    pub connection_url: String,
    /// Configuration.
    pub config: Configuration,
    /// SQL effects tracker.
    pub effects: SqlEffects,
    /// Whether connected.
    pub connected: bool,
}

impl AbstractSqlFunctionDatabase {
    /// Create a new abstract SQL function database.
    pub fn new(connection_url: impl Into<String>) -> Self {
        Self {
            connection_url: connection_url.into(),
            config: Configuration::default(),
            effects: SqlEffects::new(),
            connected: false,
        }
    }

    /// Set configuration.
    pub fn with_config(mut self, config: Configuration) -> Self {
        self.config = config;
        self
    }

    /// Connect (placeholder).
    pub fn connect(&mut self) -> Result<(), String> {
        self.connected = true;
        Ok(())
    }

    /// Disconnect (placeholder).
    pub fn disconnect(&mut self) {
        self.connected = false;
    }

    /// Whether the database is connected.
    pub fn is_connected(&self) -> bool {
        self.connected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bsim_sql_clause() {
        let mut clause = BSimSqlClause::new();
        clause.append("SELECT * FROM functions");
        clause.append("WHERE name = :name");
        clause.add_parameter("name", "main");
        assert_eq!(clause.build(), "SELECT * FROM functions WHERE name = :name");
    }

    #[test]
    fn test_configuration_defaults() {
        let cfg = Configuration::new();
        assert_eq!(cfg.max_function_bulk, 1000);
        assert!((cfg.similarity_threshold - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn test_configuration_builder() {
        let cfg = Configuration::new()
            .with_similarity_threshold(0.9)
            .with_signature_threshold(0.5);
        assert!((cfg.similarity_threshold - 0.9).abs() < f64::EPSILON);
        assert!((cfg.signature_threshold - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_sql_effects() {
        let mut fx = SqlEffects::new();
        assert_eq!(fx.total(), 0);
        fx.record_insert(5);
        fx.record_select(10);
        assert_eq!(fx.total(), 15);
        assert!(fx.has_effects);
    }

    #[test]
    fn test_executable_scorer_single() {
        let scorer = ExecutableScorerSingle::new(1, 0.8, 10, 1.0);
        assert!((scorer.normalized_score() - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn test_executable_scorer_single_zero_self_score() {
        let scorer = ExecutableScorerSingle::new(1, 0.5, 5, 0.0);
        assert!((scorer.normalized_score()).abs() < f64::EPSILON);
    }

    #[test]
    fn test_temporary_score_cache() {
        let mut cache = TemporaryScoreCache::new();
        assert!(cache.is_empty());
        cache.put(1, 2, 0.95);
        assert_eq!(cache.get(1, 2), Some(0.95));
        assert!(cache.contains(1, 2));
        assert!(!cache.contains(2, 3));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_cancelled_sql_exception() {
        let e = CancelledSqlException::new("user cancelled");
        assert_eq!(e.message, "user cancelled");
    }

    #[test]
    fn test_abstract_sql_db() {
        let mut db = AbstractSqlFunctionDatabase::new("jdbc:postgresql://localhost/bsim");
        assert!(!db.is_connected());
        db.connect().unwrap();
        assert!(db.is_connected());
        db.disconnect();
        assert!(!db.is_connected());
    }
}
