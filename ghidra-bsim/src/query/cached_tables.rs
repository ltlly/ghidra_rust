//! Cached and complex table types for BSim SQL backends.
//!
//! Port of Ghidra's `ghidra.features.bsim.query.client.tables` package:
//! - `CachedStatement`: cached SQL statement wrapper
//! - `ExeToCategoryTable`: mapping from exe to category
//! - `StatementSupplier`: trait for providing SQL statements

use std::collections::HashMap;

/// A supplier of SQL statements (prepared or raw).
///
/// Port of `ghidra.features.bsim.query.client.tables.StatementSupplier`.
pub trait StatementSupplier: std::fmt::Debug {
    /// Get a prepared statement by name.
    fn get_statement(&self, name: &str) -> Option<&str>;

    /// Whether a named statement exists.
    fn has_statement(&self, name: &str) -> bool;

    /// Register a new statement.
    fn register_statement(&mut self, name: String, sql: String);
}

/// A cached SQL statement.
///
/// Port of `ghidra.features.bsim.query.client.tables.CachedStatement`.
#[derive(Debug, Clone)]
pub struct CachedStatement {
    /// The SQL text.
    pub sql: String,
    /// The statement name/key.
    pub name: String,
    /// Whether the statement is currently in use.
    pub in_use: bool,
    /// Hit count.
    pub hit_count: u64,
}

impl CachedStatement {
    /// Create a new cached statement.
    pub fn new(name: impl Into<String>, sql: impl Into<String>) -> Self {
        Self {
            sql: sql.into(),
            name: name.into(),
            in_use: false,
            hit_count: 0,
        }
    }

    /// Mark the statement as in use.
    pub fn acquire(&mut self) -> bool {
        if self.in_use {
            return false;
        }
        self.in_use = true;
        self.hit_count += 1;
        true
    }

    /// Release the statement.
    pub fn release(&mut self) {
        self.in_use = false;
    }
}

/// Exe-to-category mapping table.
///
/// Port of `ghidra.features.bsim.query.client.tables.ExeToCategoryTable`.
#[derive(Debug, Clone)]
pub struct ExeToCategoryTable {
    /// Table name in the database.
    pub table_name: String,
    /// Mappings from exe_id to category_id.
    pub mappings: HashMap<i64, Vec<i64>>,
    /// Layout version.
    pub layout_version: u32,
}

impl ExeToCategoryTable {
    /// Create a new exe-to-category table.
    pub fn new(table_name: impl Into<String>) -> Self {
        Self {
            table_name: table_name.into(),
            mappings: HashMap::new(),
            layout_version: 1,
        }
    }

    /// Add a mapping (exe_id -> category_id).
    pub fn add_mapping(&mut self, exe_id: i64, category_id: i64) {
        self.mappings.entry(exe_id).or_default().push(category_id);
    }

    /// Get categories for an exe.
    pub fn get_categories(&self, exe_id: i64) -> Option<&Vec<i64>> {
        self.mappings.get(&exe_id)
    }

    /// Get the SQL for creating this table.
    pub fn create_table_sql(&self) -> String {
        format!(
            "CREATE TABLE IF NOT EXISTS {} (exe_id BIGINT, category_id BIGINT, PRIMARY KEY(exe_id, category_id))",
            self.table_name
        )
    }

    /// Get the SQL for inserting a mapping.
    pub fn insert_sql(&self) -> String {
        format!(
            "INSERT INTO {} (exe_id, category_id) VALUES (?, ?)",
            self.table_name
        )
    }
}

/// A statement registry that caches named SQL statements.
#[derive(Debug, Default)]
pub struct StatementCache {
    statements: HashMap<String, CachedStatement>,
}

impl StatementCache {
    /// Create a new statement cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a statement.
    pub fn register(&mut self, name: impl Into<String>, sql: impl Into<String>) {
        let name = name.into();
        self.statements.insert(name.clone(), CachedStatement::new(name, sql));
    }

    /// Acquire a statement (returns None if already in use).
    pub fn acquire(&mut self, name: &str) -> Option<&mut CachedStatement> {
        if let Some(stmt) = self.statements.get_mut(name) {
            if stmt.acquire() {
                Some(stmt)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Release a statement.
    pub fn release(&mut self, name: &str) {
        if let Some(stmt) = self.statements.get_mut(name) {
            stmt.release();
        }
    }

    /// Number of cached statements.
    pub fn len(&self) -> usize {
        self.statements.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.statements.is_empty()
    }
}

impl StatementSupplier for StatementCache {
    fn get_statement(&self, name: &str) -> Option<&str> {
        self.statements.get(name).map(|s| s.sql.as_str())
    }

    fn has_statement(&self, name: &str) -> bool {
        self.statements.contains_key(name)
    }

    fn register_statement(&mut self, name: String, sql: String) {
        self.register(name, sql);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cached_statement() {
        let mut stmt = CachedStatement::new("select_all", "SELECT * FROM functions");
        assert!(!stmt.in_use);
        assert_eq!(stmt.hit_count, 0);

        assert!(stmt.acquire());
        assert!(stmt.in_use);
        assert_eq!(stmt.hit_count, 1);

        // Cannot acquire twice.
        assert!(!stmt.acquire());

        stmt.release();
        assert!(!stmt.in_use);
    }

    #[test]
    fn test_exe_to_category_table() {
        let mut table = ExeToCategoryTable::new("exe_category");
        table.add_mapping(1, 10);
        table.add_mapping(1, 20);
        table.add_mapping(2, 10);

        let cats = table.get_categories(1).unwrap();
        assert_eq!(cats.len(), 2);
        assert!(cats.contains(&10));
        assert!(cats.contains(&20));

        assert!(table.get_categories(99).is_none());
    }

    #[test]
    fn test_exe_to_category_table_sql() {
        let table = ExeToCategoryTable::new("exe_cat");
        let sql = table.create_table_sql();
        assert!(sql.contains("exe_cat"));
        assert!(sql.contains("exe_id"));
    }

    #[test]
    fn test_statement_cache() {
        let mut cache = StatementCache::new();
        assert!(cache.is_empty());

        cache.register("sel", "SELECT 1");
        assert_eq!(cache.len(), 1);
        assert!(cache.has_statement("sel"));

        let stmt = cache.acquire("sel").unwrap();
        assert!(stmt.in_use);

        cache.release("sel");
        assert!(!cache.statements.get("sel").unwrap().in_use);
    }

    #[test]
    fn test_statement_cache_double_acquire() {
        let mut cache = StatementCache::new();
        cache.register("q", "SELECT 1");
        let _ = cache.acquire("q").unwrap();
        // Second acquire should fail (statement in use).
        assert!(cache.acquire("q").is_none());
    }
}
