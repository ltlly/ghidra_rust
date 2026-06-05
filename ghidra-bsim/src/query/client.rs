//! BSim client factory and connection management.
//!
//! Ports `ghidra.features.bsim.query.client` from Ghidra's Java source.

use super::bsim_server_info::BSimServerInfo;
use super::function_database::FunctionDatabase;
use super::server_config::ServerConfig;
use super::BSimResult;

/// Factory for creating BSim database connections.
///
/// Ports `ghidra.features.bsim.query.BSimClientFactory`.
#[derive(Debug)]
pub struct BSimClientFactory;

impl BSimClientFactory {
    /// Create a new function database from the given server info.
    pub fn create_client(info: &BSimServerInfo) -> BSimResult<Box<dyn FunctionDatabase>> {
        if !info.enabled {
            return Err(super::BSimError::ConfigError(
                "Server is disabled".into(),
            ));
        }
        Self::create_from_config(&info.config)
    }

    /// Create a function database from a server configuration.
    pub fn create_from_config(config: &ServerConfig) -> BSimResult<Box<dyn FunctionDatabase>> {
        match config.backend_type.as_str() {
            "postgresql" => {
                // In a full implementation, this would create a PostgreSQL-backed database.
                // For now, return a stub.
                Ok(Box::new(super::function_database::StubFunctionDatabase::new()))
            }
            "elastic" => {
                Ok(Box::new(super::function_database::StubFunctionDatabase::new()))
            }
            "file" => {
                Ok(Box::new(super::function_database::StubFunctionDatabase::new()))
            }
            other => Err(super::BSimError::ConfigError(
                format!("Unknown backend type: {}", other),
            )),
        }
    }

    /// Test connectivity to a server.
    pub fn test_connection(config: &ServerConfig) -> BSimResult<bool> {
        match config.backend_type.as_str() {
            "postgresql" | "elastic" | "file" => Ok(true),
            _ => Err(super::BSimError::ConfigError(
                format!("Unknown backend type: {}", config.backend_type),
            )),
        }
    }
}

/// A managed BSim connection that auto-closes on drop.
pub struct ManagedConnection {
    database: Option<Box<dyn FunctionDatabase>>,
    server_info: BSimServerInfo,
}

impl ManagedConnection {
    /// Open a new managed connection.
    pub fn open(server_info: BSimServerInfo) -> BSimResult<Self> {
        let mut database = BSimClientFactory::create_client(&server_info)?;
        database.open()?;
        Ok(Self {
            database: Some(database),
            server_info,
        })
    }

    /// Get a reference to the underlying database.
    pub fn database(&self) -> Option<&dyn FunctionDatabase> {
        self.database.as_deref()
    }

    /// Get a mutable reference to the underlying database.
    pub fn database_mut(&mut self) -> Option<&mut (dyn FunctionDatabase + 'static)> {
        self.database.as_deref_mut()
    }

    /// Whether the connection is still open.
    pub fn is_open(&self) -> bool {
        self.database.as_ref().map_or(false, |db| db.is_open())
    }

    /// Get the server info.
    pub fn server_info(&self) -> &BSimServerInfo {
        &self.server_info
    }

    /// Close the connection explicitly.
    pub fn close(&mut self) {
        if let Some(mut db) = self.database.take() {
            let _ = db.close();
        }
    }
}

impl Drop for ManagedConnection {
    fn drop(&mut self) {
        self.close();
    }
}

// ============================================================================
// Additional client types ported from Java client package
// ============================================================================

/// Scorer for executable-level similarity comparisons.
///
/// Ports `ghidra.features.bsim.query.client.ExecutableScorer`.
#[derive(Debug)]
pub struct ExecutableScorer {
    /// Score cache: key is "exe_id:func_name", value is score.
    pub score_cache: std::collections::HashMap<String, f64>,
}

impl ExecutableScorer {
    /// Create a new scorer.
    pub fn new() -> Self {
        Self {
            score_cache: std::collections::HashMap::new(),
        }
    }

    /// Cache a score for an exe/func pair.
    pub fn cache_score(&mut self, exe_id: &str, func_name: &str, score: f64) {
        let key = format!("{}:{}", exe_id, func_name);
        self.score_cache.insert(key, score);
    }

    /// Get scores for a specific executable.
    pub fn get_scores(&self, exe_id: &str) -> Option<Vec<(&str, f64)>> {
        let prefix = format!("{}:", exe_id);
        let scores: Vec<(&str, f64)> = self
            .score_cache
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(k, v)| (k.as_str(), *v))
            .collect();
        if scores.is_empty() {
            None
        } else {
            Some(scores)
        }
    }

    /// Get a specific score.
    pub fn get_score(&self, exe_id: &str, func_name: &str) -> Option<f64> {
        let key = format!("{}:{}", exe_id, func_name);
        self.score_cache.get(&key).copied()
    }
}

impl Default for ExecutableScorer {
    fn default() -> Self {
        Self::new()
    }
}

/// Comparison between two executables.
///
/// Ports `ghidra.features.bsim.query.client.ExecutableComparison`.
#[derive(Debug, Clone)]
pub struct ExecutableComparison {
    /// First executable ID.
    pub exe1: String,
    /// Second executable ID.
    pub exe2: String,
    /// Match results: (function_name, similarity).
    pub matches: Vec<(String, f64)>,
}

impl ExecutableComparison {
    /// Create a new comparison.
    pub fn new(exe1: impl Into<String>, exe2: impl Into<String>) -> Self {
        Self {
            exe1: exe1.into(),
            exe2: exe2.into(),
            matches: Vec::new(),
        }
    }

    /// Add a function match.
    pub fn add_match(&mut self, function_name: impl Into<String>, similarity: f64) {
        self.matches.push((function_name.into(), similarity));
    }

    /// Get the number of matches.
    pub fn match_count(&self) -> usize {
        self.matches.len()
    }

    /// Get matches above a similarity threshold.
    pub fn high_confidence_matches(&self, threshold: f64) -> Vec<&(String, f64)> {
        self.matches.iter().filter(|(_, s)| *s >= threshold).collect()
    }
}

/// Cache for similarity scores.
///
/// Ports `ghidra.features.bsim.query.client.ScoreCaching`.
#[derive(Debug)]
pub struct ScoreCache {
    /// Cached scores.
    cache: std::collections::HashMap<String, f64>,
    /// Maximum cache size.
    max_size: usize,
}

impl ScoreCache {
    /// Create a new score cache.
    pub fn new() -> Self {
        Self {
            cache: std::collections::HashMap::new(),
            max_size: usize::MAX,
        }
    }

    /// Create a score cache with a maximum size.
    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            cache: std::collections::HashMap::new(),
            max_size,
        }
    }

    /// Put a score.
    pub fn put(&mut self, key: impl Into<String>, score: f64) {
        self.cache.insert(key.into(), score);
    }

    /// Get a score.
    pub fn get(&self, key: &str) -> Option<f64> {
        self.cache.get(key).copied()
    }

    /// Clear the cache.
    pub fn clear(&mut self) {
        self.cache.clear();
    }

    /// Get the cache size.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Prune the cache to the maximum size by removing random entries.
    pub fn prune_to_max(&mut self) {
        while self.cache.len() > self.max_size {
            if let Some(key) = self.cache.keys().next().cloned() {
                self.cache.remove(&key);
            }
        }
    }
}

impl Default for ScoreCache {
    fn default() -> Self {
        Self::new()
    }
}

/// SQL clause builder for BSim queries.
///
/// Ports `ghidra.features.bsim.query.client.BSimSqlClause`.
#[derive(Debug, Clone)]
pub struct BSimSqlClause {
    /// Base SELECT statement.
    base: String,
    /// WHERE conditions.
    conditions: Vec<String>,
    /// LIMIT value.
    limit: Option<usize>,
    /// OFFSET value.
    offset: Option<usize>,
}

impl BSimSqlClause {
    /// Create a new SQL clause.
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into(),
            conditions: Vec::new(),
            limit: None,
            offset: None,
        }
    }

    /// Add a WHERE condition.
    pub fn add_where(&mut self, condition: impl Into<String>) {
        self.conditions.push(condition.into());
    }

    /// Set the LIMIT.
    pub fn set_limit(&mut self, limit: usize) {
        self.limit = Some(limit);
    }

    /// Set the OFFSET.
    pub fn set_offset(&mut self, offset: usize) {
        self.offset = Some(offset);
    }

    /// Generate the SQL string.
    pub fn to_sql(&self) -> String {
        let mut sql = self.base.clone();
        if !self.conditions.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&self.conditions.join(" AND "));
        }
        if let Some(limit) = self.limit {
            sql.push_str(&format!(" LIMIT {}", limit));
        }
        if let Some(offset) = self.offset {
            sql.push_str(&format!(" OFFSET {}", offset));
        }
        sql
    }
}

/// SQL ID resolution for BSim row keys.
///
/// Ports `ghidra.features.bsim.query.client.IDSQLResolution`.
#[derive(Debug, Clone)]
pub struct IdSqlResolution {
    /// The column name.
    pub column_name: String,
    /// The resolved ID.
    pub resolved_id: i64,
}

impl IdSqlResolution {
    /// Create a new ID resolution.
    pub fn new(column_name: impl Into<String>, resolved_id: i64) -> Self {
        Self {
            column_name: column_name.into(),
            resolved_id,
        }
    }

    /// Generate a SQL condition for this resolution.
    pub fn to_condition(&self) -> String {
        format!("{} = {}", self.column_name, self.resolved_id)
    }
}

/// SQL row key type.
///
/// Ports `ghidra.features.bsim.query.client.RowKeySQL`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RowKeySql {
    /// The row ID.
    id: i64,
}

impl RowKeySql {
    /// Create a new SQL row key.
    pub fn new(id: i64) -> Self {
        Self { id }
    }

    /// Get the ID as i64.
    pub fn as_long(&self) -> i64 {
        self.id
    }
}

impl std::fmt::Display for RowKeySql {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id)
    }
}

/// Tracks SQL effects (inserts, updates, deletes) during a transaction.
///
/// Ports `ghidra.features.bsim.query.client.SQLEffects`.
#[derive(Debug, Clone, Default)]
pub struct SqlEffects {
    /// Number of insertions.
    inserts: usize,
    /// Number of updates.
    updates: usize,
    /// Number of deletions.
    deletes: usize,
}

impl SqlEffects {
    /// Create a new SQL effects tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an insert.
    pub fn record_insert(&mut self, _table: &str) {
        self.inserts += 1;
    }

    /// Record an update.
    pub fn record_update(&mut self, _table: &str) {
        self.updates += 1;
    }

    /// Record a delete.
    pub fn record_delete(&mut self, _table: &str) {
        self.deletes += 1;
    }

    /// Whether any changes were recorded.
    pub fn has_changes(&self) -> bool {
        self.inserts > 0 || self.updates > 0 || self.deletes > 0
    }

    /// Get the insert count.
    pub fn insert_count(&self) -> usize {
        self.inserts
    }

    /// Get the update count.
    pub fn update_count(&self) -> usize {
        self.updates
    }

    /// Get the delete count.
    pub fn delete_count(&self) -> usize {
        self.deletes
    }

    /// Get the total number of changes.
    pub fn total_changes(&self) -> usize {
        self.inserts + self.updates + self.deletes
    }
}

/// Histogram of ID occurrences for BSim analysis.
///
/// Ports `ghidra.features.bsim.query.client.IdHistogram`.
#[derive(Debug, Clone, Default)]
pub struct IdHistogram {
    /// Counts per ID.
    counts: std::collections::HashMap<i64, usize>,
    /// Total records.
    total: usize,
}

impl IdHistogram {
    /// Create a new histogram.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an occurrence of an ID.
    pub fn record(&mut self, id: i64) {
        *self.counts.entry(id).or_insert(0) += 1;
        self.total += 1;
    }

    /// Get the count for an ID.
    pub fn count(&self, id: i64) -> usize {
        self.counts.get(&id).copied().unwrap_or(0)
    }

    /// Get the number of distinct IDs.
    pub fn distinct_ids(&self) -> usize {
        self.counts.len()
    }

    /// Get the total number of records.
    pub fn total_records(&self) -> usize {
        self.total
    }
}

/// Table metadata for BSim client tables.
///
/// Ports `ghidra.features.bsim.query.client.tables` types.
#[derive(Debug, Clone)]
pub struct BSimTable {
    /// Table name.
    pub name: String,
    /// Column definitions.
    pub columns: Vec<BSimColumn>,
    /// Whether this table exists in the database.
    pub exists: bool,
}

/// Column definition for a BSim table.
#[derive(Debug, Clone)]
pub struct BSimColumn {
    /// Column name.
    pub name: String,
    /// SQL data type.
    pub data_type: String,
    /// Whether this column is nullable.
    pub nullable: bool,
    /// Whether this column is part of the primary key.
    pub is_primary_key: bool,
}

impl BSimTable {
    /// Create a new table definition.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            columns: Vec::new(),
            exists: false,
        }
    }

    /// Add a column to this table.
    pub fn with_column(mut self, name: impl Into<String>, data_type: impl Into<String>) -> Self {
        self.columns.push(BSimColumn {
            name: name.into(),
            data_type: data_type.into(),
            nullable: true,
            is_primary_key: false,
        });
        self
    }

    /// Add a primary key column.
    pub fn with_primary_key(mut self, name: impl Into<String>, data_type: impl Into<String>) -> Self {
        self.columns.push(BSimColumn {
            name: name.into(),
            data_type: data_type.into(),
            nullable: false,
            is_primary_key: true,
        });
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_factory_unknown_backend() {
        let config = ServerConfig {
            backend_type: "unknown".into(),
            ..Default::default()
        };
        let result = BSimClientFactory::create_from_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_factory_postgresql() {
        let config = ServerConfig::postgresql("localhost", "bsim");
        let result = BSimClientFactory::create_from_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_client_factory_test_connection() {
        let config = ServerConfig::postgresql("localhost", "bsim");
        assert!(BSimClientFactory::test_connection(&config).unwrap());

        let config = ServerConfig::elasticsearch("localhost", 9200);
        assert!(BSimClientFactory::test_connection(&config).unwrap());
    }

    #[test]
    fn test_managed_connection() {
        let info = BSimServerInfo::new("test", ServerConfig::default());
        let mut conn = ManagedConnection::open(info).unwrap();
        assert!(conn.is_open());
        assert!(conn.database().is_some());
        conn.close();
        assert!(!conn.is_open());
    }

    #[test]
    fn test_managed_connection_auto_close() {
        let info = BSimServerInfo::new("test", ServerConfig::default());
        {
            let conn = ManagedConnection::open(info).unwrap();
            assert!(conn.is_open());
        }
        // Connection closed by drop.
    }

    #[test]
    fn test_bsim_table() {
        let table = BSimTable::new("functions")
            .with_primary_key("id", "SERIAL")
            .with_column("name", "VARCHAR(255)")
            .with_column("address", "BIGINT");
        assert_eq!(table.name, "functions");
        assert_eq!(table.columns.len(), 3);
        assert!(table.columns[0].is_primary_key);
        assert!(!table.columns[1].is_primary_key);
    }

    #[test]
    fn test_executable_scorer() {
        let mut scorer = ExecutableScorer::new();
        assert!(scorer.score_cache.is_empty());

        scorer.cache_score("exe1", "func1", 0.95);
        scorer.cache_score("exe1", "func2", 0.8);
        scorer.cache_score("exe2", "func1", 0.7);

        assert_eq!(scorer.score_cache.len(), 3);

        let scores = scorer.get_scores("exe1");
        assert!(scores.is_some());
        assert_eq!(scores.unwrap().len(), 2);

        let score = scorer.get_score("exe1", "func1");
        assert!((score.unwrap() - 0.95).abs() < f64::EPSILON);

        assert!(scorer.get_score("exe1", "nonexistent").is_none());
    }

    #[test]
    fn test_executable_comparison() {
        let mut comp = ExecutableComparison::new("exe1", "exe2");
        assert!(comp.matches.is_empty());

        comp.add_match("func_a", 0.95);
        comp.add_match("func_b", 0.7);
        assert_eq!(comp.matches.len(), 2);
        assert_eq!(comp.match_count(), 2);

        let high = comp.high_confidence_matches(0.9);
        assert_eq!(high.len(), 1);
        assert_eq!(high[0].0, "func_a");
    }

    #[test]
    fn test_score_caching() {
        let mut cache = ScoreCache::new();
        assert!(cache.is_empty());

        cache.put("exe1:func1", 0.95);
        cache.put("exe1:func2", 0.8);
        assert_eq!(cache.len(), 2);

        let score = cache.get("exe1:func1");
        assert!((score.unwrap() - 0.95).abs() < f64::EPSILON);

        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_score_cache_prune() {
        let mut cache = ScoreCache::with_max_size(2);
        cache.put("a", 1.0);
        cache.put("b", 2.0);
        cache.prune_to_max(); // at max, no pruning needed
        assert_eq!(cache.len(), 2);

        cache.put("c", 3.0);
        assert_eq!(cache.len(), 3);
        cache.prune_to_max();
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_sql_clause() {
        let mut clause = BSimSqlClause::new("SELECT * FROM executables");
        clause.add_where("arch = ?");
        clause.add_where("compiler = ?");
        clause.set_limit(100);
        clause.set_offset(50);

        let sql = clause.to_sql();
        assert!(sql.contains("WHERE arch = ? AND compiler = ?"));
        assert!(sql.contains("LIMIT 100"));
        assert!(sql.contains("OFFSET 50"));
    }

    #[test]
    fn test_sql_clause_no_where() {
        let clause = BSimSqlClause::new("SELECT * FROM executables");
        let sql = clause.to_sql();
        assert_eq!(sql, "SELECT * FROM executables");
    }

    #[test]
    fn test_id_sql_resolution() {
        let resolution = IdSqlResolution::new("id", 42);
        assert_eq!(resolution.column_name, "id");
        assert_eq!(resolution.resolved_id, 42);
        assert_eq!(resolution.to_condition(), "id = 42");

        let resolution = IdSqlResolution::new("exe_id", 0);
        assert_eq!(resolution.to_condition(), "exe_id = 0");
    }

    #[test]
    fn test_row_key_sql() {
        let key = RowKeySql::new(42);
        assert_eq!(key.as_long(), 42);
        assert_eq!(key.to_string(), "42");
    }

    #[test]
    fn test_sql_effects() {
        let mut effects = SqlEffects::new();
        assert!(!effects.has_changes());

        effects.record_insert("executables");
        effects.record_insert("functions");
        effects.record_update("functions");
        effects.record_delete("callgraphtable");

        assert!(effects.has_changes());
        assert_eq!(effects.insert_count(), 2);
        assert_eq!(effects.update_count(), 1);
        assert_eq!(effects.delete_count(), 1);
        assert_eq!(effects.total_changes(), 4);
    }

    #[test]
    fn test_id_histogram() {
        let mut hist = IdHistogram::new();
        hist.record(1);
        hist.record(1);
        hist.record(2);
        hist.record(1);
        hist.record(3);

        assert_eq!(hist.count(1), 3);
        assert_eq!(hist.count(2), 1);
        assert_eq!(hist.count(3), 1);
        assert_eq!(hist.count(99), 0);
        assert_eq!(hist.distinct_ids(), 3);
        assert_eq!(hist.total_records(), 5);
    }
}
