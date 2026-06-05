//! Complex SQL table abstraction for BSim.
//!
//! Ports `ghidra.features.bsim.query.client.tables.SQLComplexTable`.

use std::collections::HashMap;

/// A complex SQL table with multiple columns and typed rows.
///
/// Represents a database table in BSim's PostgreSQL schema with
/// support for row CRUD operations and SQL generation.
#[derive(Debug, Clone)]
pub struct SQLComplexTable {
    /// Table name.
    pub name: String,
    /// Column definitions: (name, sql_type).
    pub columns: Vec<(String, String)>,
    /// Rows: each row is a map from column name to value.
    pub rows: Vec<HashMap<String, SqlValue>>,
    /// Primary key column name.
    pub primary_key: String,
}

/// SQL value types.
#[derive(Debug, Clone, PartialEq)]
pub enum SqlValue {
    /// NULL.
    Null,
    /// Integer value.
    Int(i64),
    /// Text value.
    Text(String),
    /// Float value.
    Float(f64),
    /// Boolean value.
    Bool(bool),
    /// Binary data (hex-encoded).
    Bytes(Vec<u8>),
}

impl SqlValue {
    /// Get as SQL literal string.
    pub fn to_sql_literal(&self) -> String {
        match self {
            SqlValue::Null => "NULL".to_string(),
            SqlValue::Int(v) => v.to_string(),
            SqlValue::Text(v) => format!("'{}'", v.replace('\'', "''")),
            SqlValue::Float(v) => v.to_string(),
            SqlValue::Bool(v) => if *v { "TRUE" } else { "FALSE" }.to_string(),
            SqlValue::Bytes(v) => format!("'\\x{}'", hex::encode(v)),
        }
    }
}

impl SQLComplexTable {
    /// Create a new table definition.
    pub fn new(name: impl Into<String>, primary_key: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            columns: Vec::new(),
            rows: Vec::new(),
            primary_key: primary_key.into(),
        }
    }

    /// Add a column definition.
    pub fn add_column(&mut self, name: impl Into<String>, sql_type: impl Into<String>) {
        self.columns.push((name.into(), sql_type.into()));
    }

    /// Insert a row.
    pub fn insert_row(&mut self, row: HashMap<String, SqlValue>) {
        self.rows.push(row);
    }

    /// Get the CREATE TABLE SQL statement.
    pub fn create_table_sql(&self) -> String {
        let cols: Vec<String> = self.columns.iter()
            .map(|(name, typ)| {
                if name == &self.primary_key {
                    format!("{} {} PRIMARY KEY", name, typ)
                } else {
                    format!("{} {}", name, typ)
                }
            })
            .collect();
        format!("CREATE TABLE {} ({})", self.name, cols.join(", "))
    }

    /// Get the number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }
}

/// A cached prepared statement for repeated SQL queries.
#[derive(Debug, Clone)]
pub struct CachedStatement {
    /// The SQL template.
    pub sql_template: String,
    /// Parameter placeholder count.
    pub param_count: usize,
}

impl CachedStatement {
    /// Create a new cached statement.
    pub fn new(sql: impl Into<String>) -> Self {
        let sql = sql.into();
        let count = sql.matches('?').count();
        Self {
            sql_template: sql,
            param_count: count,
        }
    }

    /// Bind parameters and produce the final SQL.
    pub fn bind(&self, params: &[&str]) -> String {
        let mut result = self.sql_template.clone();
        for param in params {
            result = result.replacen('?', param, 1);
        }
        result
    }
}

/// A statement supplier function.
pub type StatementSupplier = Box<dyn Fn() -> CachedStatement + Send + Sync>;

/// Exe-to-category mapping table.
#[derive(Debug, Clone, Default)]
pub struct ExeToCategoryTable {
    /// Mappings: (exe_id, category_name).
    pub mappings: Vec<(i64, String)>,
}

impl ExeToCategoryTable {
    pub fn new() -> Self { Self::default() }
    pub fn add(&mut self, exe_id: i64, category: impl Into<String>) {
        self.mappings.push((exe_id, category.into()));
    }
    pub fn get_categories(&self, exe_id: i64) -> Vec<&str> {
        self.mappings.iter()
            .filter(|(id, _)| *id == exe_id)
            .map(|(_, cat)| cat.as_str())
            .collect()
    }
}

// Simple hex encoder (avoids adding hex crate dependency)
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sql_value_literal() {
        assert_eq!(SqlValue::Null.to_sql_literal(), "NULL");
        assert_eq!(SqlValue::Int(42).to_sql_literal(), "42");
        assert_eq!(SqlValue::Text("hello".into()).to_sql_literal(), "'hello'");
        assert_eq!(SqlValue::Bool(true).to_sql_literal(), "TRUE");
    }

    #[test]
    fn test_complex_table() {
        let mut table = SQLComplexTable::new("test", "id");
        table.add_column("id", "INTEGER");
        table.add_column("name", "TEXT");
        let create_sql = table.create_table_sql();
        assert!(create_sql.contains("PRIMARY KEY"));
    }

    #[test]
    fn test_cached_statement() {
        let stmt = CachedStatement::new("SELECT * FROM t WHERE id = ? AND name = ?");
        assert_eq!(stmt.param_count, 2);
        let bound = stmt.bind(&["42", "'test'"]);
        assert!(bound.contains("42"));
    }

    #[test]
    fn test_exe_to_category() {
        let mut table = ExeToCategoryTable::new();
        table.add(1, "malware");
        table.add(1, "packed");
        table.add(2, "benign");
        assert_eq!(table.get_categories(1).len(), 2);
        assert_eq!(table.get_categories(2).len(), 1);
    }
}
