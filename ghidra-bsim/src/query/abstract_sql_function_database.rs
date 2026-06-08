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
///
/// This struct manages the lifecycle of SQL-backed BSim databases including
/// connection management, table creation/deletion, transaction handling,
/// and the CRUD operations for executables, functions, signatures, and
/// callgraph data.
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
    /// Whether the database is initialized.
    initialized: bool,
    /// Whether a transaction is currently active.
    in_transaction: bool,
    /// Whether callgraph tracking is enabled.
    track_callgraph: bool,
    /// String table for architecture names.
    arch_table: HashMap<String, i64>,
    /// String table for compiler names.
    compiler_table: HashMap<String, i64>,
    /// String table for repository names.
    repository_table: HashMap<String, i64>,
    /// String table for path names.
    path_table: HashMap<String, i64>,
    /// String table for category names.
    category_table: HashMap<String, i64>,
    /// Key-value storage for database metadata.
    key_value_table: HashMap<String, String>,
}

impl AbstractSqlFunctionDatabase {
    /// SQL time format used in BSim databases.
    pub const SQL_TIME_FORMAT: &'static str = "YYYY-MM-DD HH24:MI:SS.MSz";
    /// Java time format used in BSim databases.
    pub const JAVA_TIME_FORMAT: &'static str = "yyyy-MM-dd HH:mm:ss.SSSZ";

    /// Architecture string table name.
    const _ARCH_TABLE_NAME: &'static str = "archtable";
    /// Compiler string table name.
    const _COMPILER_TABLE_NAME: &'static str = "comptable";
    /// Repository string table name.
    const _REPOSITORY_TABLE_NAME: &'static str = "repotable";
    /// Path string table name.
    const _PATH_TABLE_NAME: &'static str = "pathtable";
    /// Category string table name.
    const _CAT_STRING_TABLE_NAME: &'static str = "catstringtable";

    /// Create a new abstract SQL function database.
    pub fn new(connection_url: impl Into<String>) -> Self {
        Self {
            connection_url: connection_url.into(),
            config: Configuration::default(),
            effects: SqlEffects::new(),
            connected: false,
            initialized: false,
            in_transaction: false,
            track_callgraph: true,
            arch_table: HashMap::new(),
            compiler_table: HashMap::new(),
            repository_table: HashMap::new(),
            path_table: HashMap::new(),
            category_table: HashMap::new(),
            key_value_table: HashMap::new(),
        }
    }

    /// Set configuration.
    pub fn with_config(mut self, config: Configuration) -> Self {
        self.config = config;
        self
    }

    /// Enable or disable callgraph tracking.
    pub fn set_track_callgraph(&mut self, track: bool) {
        self.track_callgraph = track;
    }

    /// Whether callgraph tracking is enabled.
    pub fn is_tracking_callgraph(&self) -> bool {
        self.track_callgraph
    }

    /// Connect (placeholder -- in production, establishes pooled connection).
    pub fn connect(&mut self) -> Result<(), String> {
        self.connected = true;
        Ok(())
    }

    /// Disconnect (placeholder -- closes all connections).
    pub fn disconnect(&mut self) {
        self.arch_table.clear();
        self.compiler_table.clear();
        self.repository_table.clear();
        self.path_table.clear();
        self.category_table.clear();
        self.key_value_table.clear();
        self.connected = false;
        self.initialized = false;
    }

    /// Whether the database is connected.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Whether the database has been initialized (tables created).
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Begin a database transaction.
    ///
    /// In a real SQL implementation, this disables auto-commit and optionally
    /// acquires table locks for write operations.
    pub fn begin_transaction(&mut self, lock_for_write: bool) -> Result<(), String> {
        if !self.connected {
            return Err("Not connected".to_string());
        }
        if self.in_transaction {
            return Err("Transaction already in progress".to_string());
        }
        self.in_transaction = true;
        let _ = lock_for_write; // In a real implementation, acquire write locks
        Ok(())
    }

    /// End a transaction, committing or rolling back as specified.
    pub fn end_transaction(&mut self, commit: bool) -> Result<(), String> {
        if !self.in_transaction {
            return Err("No transaction in progress".to_string());
        }
        if commit {
            self.effects.record_insert(0); // Record transaction commit
        }
        self.in_transaction = false;
        Ok(())
    }

    /// Whether a transaction is currently active.
    pub fn is_in_transaction(&self) -> bool {
        self.in_transaction
    }

    // ---- String table operations ----

    /// Look up or insert an architecture string and return its ID.
    pub fn get_or_insert_arch(&mut self, value: &str) -> i64 {
        if let Some(&id) = self.arch_table.get(value) {
            return id;
        }
        let id = self.arch_table.len() as i64 + 1;
        self.arch_table.insert(value.to_string(), id);
        self.effects.record_insert(1);
        id
    }

    /// Look up or insert a compiler string and return its ID.
    pub fn get_or_insert_compiler(&mut self, value: &str) -> i64 {
        if let Some(&id) = self.compiler_table.get(value) {
            return id;
        }
        let id = self.compiler_table.len() as i64 + 1;
        self.compiler_table.insert(value.to_string(), id);
        self.effects.record_insert(1);
        id
    }

    /// Look up or insert a repository string and return its ID.
    pub fn get_or_insert_repository(&mut self, value: &str) -> i64 {
        if let Some(&id) = self.repository_table.get(value) {
            return id;
        }
        let id = self.repository_table.len() as i64 + 1;
        self.repository_table.insert(value.to_string(), id);
        self.effects.record_insert(1);
        id
    }

    /// Look up or insert a path string and return its ID.
    pub fn get_or_insert_path(&mut self, value: &str) -> i64 {
        if let Some(&id) = self.path_table.get(value) {
            return id;
        }
        let id = self.path_table.len() as i64 + 1;
        self.path_table.insert(value.to_string(), id);
        self.effects.record_insert(1);
        id
    }

    /// Look up or insert a category string and return its ID.
    pub fn get_or_insert_category(&mut self, value: &str) -> i64 {
        if let Some(&id) = self.category_table.get(value) {
            return id;
        }
        let id = self.category_table.len() as i64 + 1;
        self.category_table.insert(value.to_string(), id);
        self.effects.record_insert(1);
        id
    }

    /// Get an architecture string by ID.
    pub fn get_arch_string(&self, id: i64) -> Option<&str> {
        self.arch_table.iter()
            .find(|(_, &v)| v == id)
            .map(|(k, _)| k.as_str())
    }

    /// Get a compiler string by ID.
    pub fn get_compiler_string(&self, id: i64) -> Option<&str> {
        self.compiler_table.iter()
            .find(|(_, &v)| v == id)
            .map(|(k, _)| k.as_str())
    }

    // ---- Key-value operations ----

    /// Store a key-value pair in the database metadata.
    pub fn store_key_value(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.key_value_table.insert(key.into(), value.into());
    }

    /// Get a value by key from the database metadata.
    pub fn get_key_value(&self, key: &str) -> Option<&str> {
        self.key_value_table.get(key).map(|s| s.as_str())
    }

    /// Write basic database information to the key-value store.
    pub fn write_basic_info(&mut self, db_name: &str, owner: &str, description: &str) {
        self.store_key_value("name", db_name);
        self.store_key_value("owner", owner);
        self.store_key_value("description", description);
        self.store_key_value("k", self.config.similarity_threshold.to_string());
        self.store_key_value("L", self.config.signature_threshold.to_string());
    }

    /// Read database information from the key-value store.
    pub fn read_database_info(&self) -> DatabaseInfo {
        DatabaseInfo {
            name: self.get_key_value("name").unwrap_or("").to_string(),
            owner: self.get_key_value("owner").unwrap_or("").to_string(),
            description: self.get_key_value("description").unwrap_or("").to_string(),
            major: self.get_key_value("major")
                .and_then(|v| v.parse::<i16>().ok())
                .unwrap_or(0),
            minor: self.get_key_value("minor")
                .and_then(|v| v.parse::<i16>().ok())
                .unwrap_or(0),
            readonly: self.get_key_value("readonly")
                .map(|v| v.starts_with('t'))
                .unwrap_or(false),
            track_callgraph: self.get_key_value("trackcallgraph")
                .map(|v| v.starts_with('t'))
                .unwrap_or(false),
            layout_version: self.get_key_value("layout")
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0),
        }
    }

    /// Escape a string literal for use in SQL.
    ///
    /// Port of `AbstractSQLFunctionDatabase.appendEscapedLiteral`.
    pub fn escape_sql_literal(input: &str) -> Result<String, String> {
        let mut output = String::with_capacity(input.len() + 16);
        for ch in input.chars() {
            if ch == '\0' {
                return Err("Zero byte in SQL string".to_string());
            }
            if ch == '\\' || ch == '\'' {
                output.push(ch);
            }
            output.push(ch);
        }
        Ok(output)
    }

    /// Initialize the database tables (placeholder).
    pub fn initialize_database(&mut self) -> Result<(), String> {
        if !self.connected {
            return Err("Not connected".to_string());
        }
        self.initialized = true;
        Ok(())
    }

    /// Create a new database (placeholder).
    pub fn create_database(&mut self) -> Result<(), String> {
        if !self.connected {
            return Err("Not connected".to_string());
        }
        self.begin_transaction(false)?;
        // In a real implementation, create all SQL tables here.
        self.end_transaction(true)?;
        self.initialized = true;
        Ok(())
    }
}

/// Database information parsed from the key-value store.
///
/// Port of `ghidra.features.bsim.query.description.DatabaseInformation` (partial).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DatabaseInfo {
    /// Database name.
    pub name: String,
    /// Owner of the database.
    pub owner: String,
    /// Description.
    pub description: String,
    /// Major version.
    pub major: i16,
    /// Minor version.
    pub minor: i16,
    /// Whether the database is read-only.
    pub readonly: bool,
    /// Whether callgraph tracking is enabled.
    pub track_callgraph: bool,
    /// Layout version.
    pub layout_version: u32,
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

    #[test]
    fn test_string_table_arch() {
        let mut db = AbstractSqlFunctionDatabase::new("test");
        let id1 = db.get_or_insert_arch("x86");
        let id2 = db.get_or_insert_arch("x86");
        assert_eq!(id1, id2);
        let id3 = db.get_or_insert_arch("arm");
        assert_ne!(id1, id3);
        assert_eq!(db.get_arch_string(id1), Some("x86"));
    }

    #[test]
    fn test_string_table_compiler() {
        let mut db = AbstractSqlFunctionDatabase::new("test");
        let id1 = db.get_or_insert_compiler("gcc");
        let id2 = db.get_or_insert_compiler("clang");
        assert_ne!(id1, id2);
        assert_eq!(db.get_compiler_string(id1), Some("gcc"));
    }

    #[test]
    fn test_key_value_operations() {
        let mut db = AbstractSqlFunctionDatabase::new("test");
        db.store_key_value("name", "test_db");
        db.store_key_value("owner", "admin");
        assert_eq!(db.get_key_value("name"), Some("test_db"));
        assert_eq!(db.get_key_value("owner"), Some("admin"));
        assert_eq!(db.get_key_value("missing"), None);
    }

    #[test]
    fn test_write_read_basic_info() {
        let mut db = AbstractSqlFunctionDatabase::new("test");
        db.write_basic_info("bsim_db", "user1", "BSim test database");
        let info = db.read_database_info();
        assert_eq!(info.name, "bsim_db");
        assert_eq!(info.owner, "user1");
        assert_eq!(info.description, "BSim test database");
    }

    #[test]
    fn test_escape_sql_literal() {
        let result = AbstractSqlFunctionDatabase::escape_sql_literal("hello world").unwrap();
        assert_eq!(result, "hello world");

        let result = AbstractSqlFunctionDatabase::escape_sql_literal("it's").unwrap();
        assert_eq!(result, "it''s");

        let result = AbstractSqlFunctionDatabase::escape_sql_literal("back\\slash").unwrap();
        assert_eq!(result, "back\\\\slash");

        let result = AbstractSqlFunctionDatabase::escape_sql_literal("null\x00byte");
        assert!(result.is_err());
    }

    #[test]
    fn test_transaction_lifecycle() {
        let mut db = AbstractSqlFunctionDatabase::new("test");
        db.connect().unwrap();

        assert!(!db.is_in_transaction());
        db.begin_transaction(false).unwrap();
        assert!(db.is_in_transaction());
        db.end_transaction(true).unwrap();
        assert!(!db.is_in_transaction());
    }

    #[test]
    fn test_transaction_fails_when_not_connected() {
        let mut db = AbstractSqlFunctionDatabase::new("test");
        assert!(db.begin_transaction(false).is_err());
    }

    #[test]
    fn test_transaction_no_nested() {
        let mut db = AbstractSqlFunctionDatabase::new("test");
        db.connect().unwrap();
        db.begin_transaction(false).unwrap();
        assert!(db.begin_transaction(false).is_err());
    }

    #[test]
    fn test_create_database() {
        let mut db = AbstractSqlFunctionDatabase::new("test");
        db.connect().unwrap();
        db.create_database().unwrap();
        assert!(db.is_initialized());
    }

    #[test]
    fn test_callgraph_tracking() {
        let mut db = AbstractSqlFunctionDatabase::new("test");
        assert!(db.is_tracking_callgraph());
        db.set_track_callgraph(false);
        assert!(!db.is_tracking_callgraph());
    }

    #[test]
    fn test_database_info_defaults() {
        let info = DatabaseInfo::default();
        assert!(info.name.is_empty());
        assert_eq!(info.major, 0);
        assert!(!info.readonly);
    }
}
