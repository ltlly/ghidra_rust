//! Port of `SQLComplexTable` from `ghidra.features.bsim.query.client.tables`.
//!
//! Abstract base class for SQL tables in the BSim database that have
//! an auto-generated primary key (SERIAL/BIGSERIAL). Provides common
//! infrastructure for table creation, dropping, insertion, and row counting.

use std::collections::HashMap;
use std::sync::Mutex;

/// Represents a database column definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnDefinition {
    /// Column name.
    pub name: String,
    /// SQL type (e.g., "BIGINT", "TEXT", "INTEGER").
    pub sql_type: String,
    /// Whether this column is part of the primary key.
    pub is_primary_key: bool,
    /// Whether this column has a NOT NULL constraint.
    pub not_null: bool,
    /// Default value expression, if any.
    pub default_value: Option<String>,
}

impl ColumnDefinition {
    /// Create a new column definition.
    pub fn new(name: &str, sql_type: &str) -> Self {
        Self {
            name: name.to_string(),
            sql_type: sql_type.to_string(),
            is_primary_key: false,
            not_null: false,
            default_value: None,
        }
    }

    /// Mark this column as part of the primary key.
    pub fn primary_key(mut self) -> Self {
        self.is_primary_key = true;
        self
    }

    /// Mark this column as NOT NULL.
    pub fn not_null(mut self) -> Self {
        self.not_null = true;
        self
    }

    /// Set a default value for this column.
    pub fn default_value(mut self, val: &str) -> Self {
        self.default_value = Some(val.to_string());
        self
    }

    /// Generate the SQL column definition fragment.
    pub fn to_sql(&self) -> String {
        let mut sql = format!("{} {}", self.name, self.sql_type);
        if self.not_null {
            sql.push_str(" NOT NULL");
        }
        if let Some(ref default) = self.default_value {
            sql.push_str(&format!(" DEFAULT {}", default));
        }
        sql
    }
}

/// Represents an index definition for a table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexDefinition {
    /// Index name.
    pub name: String,
    /// Columns covered by this index.
    pub columns: Vec<String>,
    /// Whether the index enforces uniqueness.
    pub unique: bool,
}

impl IndexDefinition {
    /// Create a new index definition.
    pub fn new(name: &str, columns: &[&str]) -> Self {
        Self {
            name: name.to_string(),
            columns: columns.iter().map(|s| s.to_string()).collect(),
            unique: false,
        }
    }

    /// Mark this index as unique.
    pub fn unique(mut self) -> Self {
        self.unique = true;
        self
    }

    /// Generate the CREATE INDEX SQL statement.
    pub fn to_create_sql(&self, table_name: &str) -> String {
        let unique_str = if self.unique { "UNIQUE " } else { "" };
        format!(
            "CREATE {}INDEX {} ON {} ({})",
            unique_str,
            self.name,
            table_name,
            self.columns.join(", ")
        )
    }
}

/// Represents a single row returned from a database query.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TableRow {
    /// Column values stored as strings (for simplicity).
    pub values: HashMap<String, String>,
    /// The auto-generated row ID, if available.
    pub row_id: Option<i64>,
}

impl TableRow {
    /// Create a new empty table row.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a string value by column name.
    pub fn get_str(&self, column: &str) -> Option<&str> {
        self.values.get(column).map(|s| s.as_str())
    }

    /// Get an integer value by column name.
    pub fn get_i64(&self, column: &str) -> Option<i64> {
        self.values.get(column)?.parse().ok()
    }

    /// Set a string value for a column.
    pub fn set(&mut self, column: &str, value: String) {
        self.values.insert(column.to_string(), value);
    }
}

/// Abstract base for BSim SQL tables with auto-generated keys.
///
/// Ports `ghidra.features.bsim.query.client.tables.SQLComplexTable`.
/// In the original Java this is an abstract class; in Rust we use a trait-like
/// struct with overridable behavior.
#[derive(Debug, Clone)]
pub struct SQLComplexTable {
    /// The SQL table name.
    pub table_name: String,
    /// The name of the ID column (typically "id").
    pub id_column_name: String,
    /// Column definitions for this table.
    pub columns: Vec<ColumnDefinition>,
    /// Index definitions for this table.
    pub indexes: Vec<IndexDefinition>,
    /// SQL connection descriptor (for display purposes).
    pub db: String,
    /// Cached row count (lazily computed).
    row_count: Mutex<Option<i64>>,
}

impl SQLComplexTable {
    /// Create a new instance with default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new table with the given name and ID column.
    pub fn with_name(table_name: &str, id_column: &str) -> Self {
        Self {
            table_name: table_name.to_string(),
            id_column_name: id_column.to_string(),
            columns: Vec::new(),
            indexes: Vec::new(),
            db: String::new(),
            row_count: Mutex::new(None),
        }
    }

    /// Add a column definition to this table.
    pub fn add_column(&mut self, column: ColumnDefinition) {
        self.columns.push(column);
    }

    /// Add an index definition to this table.
    pub fn add_index(&mut self, index: IndexDefinition) {
        self.indexes.push(index);
    }

    /// Generate the CREATE TABLE SQL statement.
    pub fn create_table_sql(&self) -> String {
        let column_defs: Vec<String> = self.columns.iter().map(|c| c.to_sql()).collect();
        format!(
            "CREATE TABLE {} ({})",
            self.table_name,
            column_defs.join(", ")
        )
    }

    /// Generate the DROP TABLE SQL statement.
    pub fn drop_table_sql(&self) -> String {
        format!("DROP TABLE IF EXISTS {}", self.table_name)
    }

    /// Generate all CREATE INDEX SQL statements.
    pub fn create_indexes_sql(&self) -> Vec<String> {
        self.indexes
            .iter()
            .map(|idx| idx.to_create_sql(&self.table_name))
            .collect()
    }

    /// Get the table name.
    pub fn get_table_name(&self) -> &str {
        &self.table_name
    }

    /// Get the ID column name.
    pub fn get_id_column_name(&self) -> &str {
        &self.id_column_name
    }

    /// Invalidate the cached row count.
    pub fn invalidate_row_count(&self) {
        if let Ok(mut guard) = self.row_count.lock() {
            *guard = None;
        }
    }

    /// Set the cached row count.
    pub fn set_row_count(&self, count: i64) {
        if let Ok(mut guard) = self.row_count.lock() {
            *guard = Some(count);
        }
    }

    /// Get the cached row count, if available.
    pub fn cached_row_count(&self) -> Option<i64> {
        self.row_count.lock().ok()?.clone()
    }

    /// Generate an INSERT statement for the given column count.
    pub fn insert_sql(&self, num_columns: usize) -> String {
        let placeholders: Vec<String> = (1..=num_columns).map(|i| format!("${}", i)).collect();
        let col_names: Vec<&str> = self
            .columns
            .iter()
            .filter(|c| c.default_value.is_none() || c.name != self.id_column_name)
            .map(|c| c.name.as_str())
            .collect();
        format!(
            "INSERT INTO {} ({}) VALUES({}) RETURNING {}",
            self.table_name,
            col_names.join(", "),
            placeholders.join(", "),
            self.id_column_name
        )
    }

    /// Execute a DDL statement (mock for testing).
    pub fn execute_ddl(&self, sql: &str) -> Result<(), String> {
        if sql.trim().is_empty() {
            return Err("Empty SQL statement".to_string());
        }
        if !sql.trim().to_uppercase().starts_with("CREATE")
            && !sql.trim().to_uppercase().starts_with("DROP")
            && !sql.trim().to_uppercase().starts_with("ALTER")
        {
            return Err(format!("Not a DDL statement: {}", sql));
        }
        Ok(())
    }
}

impl Default for SQLComplexTable {
    fn default() -> Self {
        Self {
            table_name: String::new(),
            id_column_name: "id".to_string(),
            columns: Vec::new(),
            indexes: Vec::new(),
            db: String::new(),
            row_count: Mutex::new(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_column_definition_basic() {
        let col = ColumnDefinition::new("name", "TEXT");
        assert_eq!(col.name, "name");
        assert_eq!(col.sql_type, "TEXT");
        assert!(!col.is_primary_key);
        assert!(!col.not_null);
        assert_eq!(col.to_sql(), "name TEXT");
    }

    #[test]
    fn test_column_definition_with_constraints() {
        let col = ColumnDefinition::new("id", "BIGSERIAL")
            .primary_key()
            .not_null();
        assert!(col.is_primary_key);
        assert!(col.not_null);
        assert_eq!(col.to_sql(), "id BIGSERIAL NOT NULL");
    }

    #[test]
    fn test_column_definition_with_default() {
        let col = ColumnDefinition::new("status", "INTEGER").default_value("0");
        assert_eq!(col.to_sql(), "status INTEGER DEFAULT 0");
    }

    #[test]
    fn test_index_definition() {
        let idx = IndexDefinition::new("idx_name", &["name", "addr"]);
        assert_eq!(idx.to_create_sql("desctable"), "CREATE INDEX idx_name ON desctable (name, addr)");
    }

    #[test]
    fn test_index_definition_unique() {
        let idx = IndexDefinition::new("idx_md5", &["md5"]).unique();
        assert_eq!(
            idx.to_create_sql("exetable"),
            "CREATE UNIQUE INDEX idx_md5 ON exetable (md5)"
        );
    }

    #[test]
    fn test_table_row_basic() {
        let mut row = TableRow::new();
        row.set("name", "main".to_string());
        row.set("addr", "0x1000".to_string());
        assert_eq!(row.get_str("name"), Some("main"));
        assert_eq!(row.get_str("addr"), Some("0x1000"));
        assert_eq!(row.get_str("missing"), None);
    }

    #[test]
    fn test_table_row_i64() {
        let mut row = TableRow::new();
        row.set("count", "42".to_string());
        assert_eq!(row.get_i64("count"), Some(42));
        assert_eq!(row.get_i64("missing"), None);
    }

    #[test]
    fn test_sql_complex_table_default() {
        let table = SQLComplexTable::new();
        assert!(table.table_name.is_empty());
        assert_eq!(table.id_column_name, "id");
        assert!(table.columns.is_empty());
    }

    #[test]
    fn test_sql_complex_table_with_name() {
        let table = SQLComplexTable::with_name("desctable", "id");
        assert_eq!(table.get_table_name(), "desctable");
        assert_eq!(table.get_id_column_name(), "id");
    }

    #[test]
    fn test_sql_complex_table_create_sql() {
        let mut table = SQLComplexTable::with_name("exetable", "id");
        table.add_column(ColumnDefinition::new("id", "SERIAL").primary_key());
        table.add_column(ColumnDefinition::new("md5", "TEXT").not_null());
        table.add_column(ColumnDefinition::new("name_exec", "TEXT"));

        let sql = table.create_table_sql();
        assert!(sql.contains("CREATE TABLE exetable"));
        assert!(sql.contains("id SERIAL"));
        assert!(sql.contains("md5 TEXT NOT NULL"));
        assert!(sql.contains("name_exec TEXT"));
    }

    #[test]
    fn test_sql_complex_table_drop_sql() {
        let table = SQLComplexTable::with_name("test_table", "id");
        assert_eq!(table.drop_table_sql(), "DROP TABLE IF EXISTS test_table");
    }

    #[test]
    fn test_sql_complex_table_indexes() {
        let mut table = SQLComplexTable::with_name("desctable", "id");
        table.add_index(IndexDefinition::new("sigindex", &["id_signature"]));
        table.add_index(IndexDefinition::new("exefuncindex", &["id_exe", "name_func"]));

        let sqls = table.create_indexes_sql();
        assert_eq!(sqls.len(), 2);
        assert!(sqls[0].contains("sigindex"));
        assert!(sqls[1].contains("exefuncindex"));
    }

    #[test]
    fn test_sql_complex_table_row_count() {
        let table = SQLComplexTable::new();
        assert!(table.cached_row_count().is_none());
        table.set_row_count(100);
        assert_eq!(table.cached_row_count(), Some(100));
        table.invalidate_row_count();
        assert!(table.cached_row_count().is_none());
    }

    #[test]
    fn test_sql_complex_table_execute_ddl() {
        let table = SQLComplexTable::new();
        assert!(table.execute_ddl("CREATE TABLE test").is_ok());
        assert!(table.execute_ddl("DROP TABLE test").is_ok());
        assert!(table.execute_ddl("ALTER TABLE test ADD col INT").is_ok());
        assert!(table.execute_ddl("SELECT * FROM test").is_err());
        assert!(table.execute_ddl("").is_err());
    }
}
