//! Row key for SQL-based BSim queries.
//!
//! Ports `ghidra.features.bsim.query.client.RowKeySQL`.

/// A row key used in SQL-based BSim database queries.
///
/// Encapsulates the primary key information for rows in
/// BSim's PostgreSQL-backed database.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RowKeySQL {
    /// The database table name.
    pub table: String,
    /// The row ID (primary key).
    pub row_id: i64,
}

impl RowKeySQL {
    /// Create a new row key.
    pub fn new(table: impl Into<String>, row_id: i64) -> Self {
        Self {
            table: table.into(),
            row_id,
        }
    }

    /// Get the SQL WHERE clause for this key.
    pub fn to_sql_clause(&self) -> String {
        format!("{}.id = {}", self.table, self.row_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_row_key() {
        let key = RowKeySQL::new("exe_table", 42);
        assert_eq!(key.to_sql_clause(), "exe_table.id = 42");
    }
}
