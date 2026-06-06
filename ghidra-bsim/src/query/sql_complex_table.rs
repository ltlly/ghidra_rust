//! Port of `SQLComplexTable`.
use std::collections::HashMap;
/// Struct porting `SQLComplexTable`.
#[derive(Debug, Clone)]
pub struct SQLComplexTable {
    /// table_name.
    pub table_name: String,
    /// id_column_name.
    pub id_column_name: String,
    /// db.
    pub db: String,
}

impl SQLComplexTable {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for SQLComplexTable {
    fn default() -> Self {
        Self {
            table_name: String::new(),
            id_column_name: String::new(),
            db: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_sql_complex_table_new() { let _ = SQLComplexTable::new(); }
}
