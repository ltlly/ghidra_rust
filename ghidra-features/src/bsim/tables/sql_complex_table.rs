//! SQL complex table base for BSim.
//!
//! Ports Ghidra's `ghidra.features.bsim.query.client.tables.SQLComplexTable`.
//!
//! A SQL complex table has an auto-incrementing integer primary key and
//! provides common CRUD operations.

use std::collections::HashMap;

/// A cached SQL prepared statement.
///
/// Ports Ghidra's `CachedStatement`.
#[derive(Debug)]
pub struct CachedStatement {
    /// The SQL template.
    pub sql: String,
    /// Bound parameters (positional).
    pub params: Vec<String>,
    /// Whether this statement is currently in use.
    pub in_use: bool,
}

impl CachedStatement {
    /// Create a new cached statement.
    pub fn new(sql: impl Into<String>) -> Self {
        Self {
            sql: sql.into(),
            params: Vec::new(),
            in_use: false,
        }
    }

    /// Bind a parameter at the given index.
    pub fn bind(&mut self, index: usize, value: impl Into<String>) {
        while self.params.len() <= index {
            self.params.push(String::new());
        }
        self.params[index] = value.into();
    }

    /// Clear all bound parameters.
    pub fn clear_params(&mut self) {
        self.params.clear();
        self.in_use = false;
    }
}

/// A supplier of SQL statement text.
///
/// Ports Ghidra's `StatementSupplier`.
#[derive(Debug)]
pub struct StatementSupplier {
    /// Cached SQL templates.
    templates: HashMap<String, String>,
}

impl StatementSupplier {
    /// Create a new statement supplier.
    pub fn new() -> Self {
        Self { templates: HashMap::new() }
    }

    /// Register a SQL template.
    pub fn register(&mut self, name: impl Into<String>, sql: impl Into<String>) {
        self.templates.insert(name.into(), sql.into());
    }

    /// Get a SQL template by name.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.templates.get(name).map(|s| s.as_str())
    }

    /// Get all registered template names.
    pub fn names(&self) -> Vec<&str> {
        self.templates.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for StatementSupplier {
    fn default() -> Self { Self::new() }
}

/// Base class for BSim SQL tables with an integer primary key.
///
/// Ports Ghidra's `SQLComplexTable`. Provides common table operations
/// including row management, primary key tracking, and SQL generation.
#[derive(Debug)]
pub struct SQLComplexTable {
    /// The table name.
    pub table_name: String,
    /// The primary key column name.
    pub pk_column: String,
    /// Rows stored as column-name to value maps.
    rows: Vec<HashMap<String, SqlValue>>,
    /// Next auto-increment id.
    next_id: i64,
    /// Cached prepared statements.
    statements: HashMap<String, CachedStatement>,
}

/// A SQL column value.
#[derive(Debug, Clone, PartialEq)]
pub enum SqlValue {
    /// NULL value.
    Null,
    /// Integer value.
    Integer(i64),
    /// Text value.
    Text(String),
    /// Real (float) value.
    Real(f64),
    /// Blob (binary) value.
    Blob(Vec<u8>),
    /// Boolean value.
    Boolean(bool),
}

impl SqlValue {
    /// Convert to a string representation for SQL.
    pub fn to_sql_literal(&self) -> String {
        match self {
            SqlValue::Null => "NULL".to_string(),
            SqlValue::Integer(v) => v.to_string(),
            SqlValue::Text(s) => format!("'{}'", s.replace('\'', "''")),
            SqlValue::Real(v) => v.to_string(),
            SqlValue::Blob(b) => {
                let hex: String = b.iter().map(|byte| format!("{:02x}", byte)).collect();
                format!("X'{}'", hex)
            }
            SqlValue::Boolean(b) => if *b { "1".to_string() } else { "0".to_string() },
        }
    }
}

impl SQLComplexTable {
    /// Create a new SQL complex table.
    pub fn new(table_name: impl Into<String>, pk_column: impl Into<String>) -> Self {
        Self {
            table_name: table_name.into(),
            pk_column: pk_column.into(),
            rows: Vec::new(),
            next_id: 1,
            statements: HashMap::new(),
        }
    }

    /// Insert a row. Returns the auto-generated primary key.
    pub fn insert_row(&mut self, mut values: HashMap<String, SqlValue>) -> i64 {
        let id = self.next_id;
        self.next_id += 1;
        values.insert(self.pk_column.clone(), SqlValue::Integer(id));
        self.rows.push(values);
        id
    }

    /// Look up a row by primary key.
    pub fn select_by_pk(&self, pk: i64) -> Option<&HashMap<String, SqlValue>> {
        self.rows.iter().find(|r| {
            r.get(&self.pk_column) == Some(&SqlValue::Integer(pk))
        })
    }

    /// Get all rows.
    pub fn all_rows(&self) -> &[HashMap<String, SqlValue>] {
        &self.rows
    }

    /// Number of rows.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Delete a row by primary key. Returns `true` if a row was removed.
    pub fn delete(&mut self, pk: i64) -> bool {
        let len_before = self.rows.len();
        self.rows.retain(|r| r.get(&self.pk_column) != Some(&SqlValue::Integer(pk)));
        self.rows.len() < len_before
    }

    /// Update a row's column value.
    pub fn update(&mut self, pk: i64, column: &str, value: SqlValue) -> bool {
        if let Some(row) = self.rows.iter_mut().find(|r| {
            r.get(&self.pk_column) == Some(&SqlValue::Integer(pk))
        }) {
            row.insert(column.to_string(), value);
            true
        } else {
            false
        }
    }

    /// Register a cached prepared statement.
    pub fn register_statement(&mut self, name: impl Into<String>, sql: impl Into<String>) {
        self.statements.insert(name.into(), CachedStatement::new(sql));
    }

    /// Get a cached statement by name.
    pub fn get_statement(&self, name: &str) -> Option<&CachedStatement> {
        self.statements.get(name)
    }

    /// Get a mutable cached statement by name.
    pub fn get_statement_mut(&mut self, name: &str) -> Option<&mut CachedStatement> {
        self.statements.get_mut(name)
    }

    /// Generate a CREATE TABLE SQL statement.
    pub fn create_table_sql(&self, columns: &[(&str, &str)]) -> String {
        let col_defs: Vec<String> = columns
            .iter()
            .map(|(name, typ)| {
                if *name == self.pk_column {
                    format!("{} {} PRIMARY KEY", name, typ)
                } else {
                    format!("{} {}", name, typ)
                }
            })
            .collect();
        format!(
            "CREATE TABLE IF NOT EXISTS {} ({})",
            self.table_name,
            col_defs.join(", ")
        )
    }
}

impl Default for SQLComplexTable {
    fn default() -> Self { Self::new("default_table", "id") }
}

/// Helper to create `SqlValue::Text`.
pub fn sql_text(s: impl Into<String>) -> SqlValue {
    SqlValue::Text(s.into())
}

/// Helper to create `SqlValue::Integer`.
pub fn sql_int(v: i64) -> SqlValue {
    SqlValue::Integer(v)
}

/// Helper to create `SqlValue::Boolean`.
pub fn sql_bool(v: bool) -> SqlValue {
    SqlValue::Boolean(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_complex_table_insert_and_lookup() {
        let mut table = SQLComplexTable::new("test", "id");
        let mut values = HashMap::new();
        values.insert("name".to_string(), sql_text("hello"));
        let pk = table.insert_row(values);
        assert_eq!(pk, 1);
        let row = table.select_by_pk(1).unwrap();
        assert_eq!(row.get("name"), Some(&sql_text("hello")));
    }

    #[test]
    fn sql_complex_table_delete() {
        let mut table = SQLComplexTable::new("test", "id");
        let mut values = HashMap::new();
        values.insert("x".to_string(), sql_int(42));
        table.insert_row(values);
        assert_eq!(table.len(), 1);
        assert!(table.delete(1));
        assert!(table.is_empty());
        assert!(!table.delete(1));
    }

    #[test]
    fn sql_complex_table_update() {
        let mut table = SQLComplexTable::new("test", "id");
        let mut values = HashMap::new();
        values.insert("val".to_string(), sql_int(10));
        table.insert_row(values);
        assert!(table.update(1, "val", sql_int(20)));
        let row = table.select_by_pk(1).unwrap();
        assert_eq!(row.get("val"), Some(&sql_int(20)));
    }

    #[test]
    fn sql_complex_table_update_nonexistent() {
        let mut table = SQLComplexTable::new("test", "id");
        assert!(!table.update(999, "x", sql_int(1)));
    }

    #[test]
    fn sql_complex_table_create_sql() {
        let table = SQLComplexTable::new("my_table", "id");
        let sql = table.create_table_sql(&[("id", "INTEGER"), ("name", "TEXT")]);
        assert!(sql.contains("CREATE TABLE"));
        assert!(sql.contains("id INTEGER PRIMARY KEY"));
        assert!(sql.contains("name TEXT"));
    }

    #[test]
    fn cached_statement_bind() {
        let mut stmt = CachedStatement::new("SELECT * FROM t WHERE id = ?");
        stmt.bind(0, "42");
        assert_eq!(stmt.params[0], "42");
        stmt.clear_params();
        assert!(stmt.params.is_empty());
    }

    #[test]
    fn statement_supplier_register_and_get() {
        let mut supplier = StatementSupplier::new();
        supplier.register("find", "SELECT * FROM t");
        assert_eq!(supplier.get("find"), Some("SELECT * FROM t"));
        assert!(supplier.get("missing").is_none());
        assert_eq!(supplier.names().len(), 1);
    }

    #[test]
    fn sql_value_to_literal() {
        assert_eq!(SqlValue::Null.to_sql_literal(), "NULL");
        assert_eq!(SqlValue::Integer(42).to_sql_literal(), "42");
        assert_eq!(SqlValue::Text("hello".into()).to_sql_literal(), "'hello'");
        assert_eq!(SqlValue::Text("it's".into()).to_sql_literal(), "'it''s'");
        assert_eq!(SqlValue::Boolean(true).to_sql_literal(), "1");
        assert_eq!(SqlValue::Boolean(false).to_sql_literal(), "0");
    }
}
