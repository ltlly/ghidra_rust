//! Executable table for BSim SQL databases.
//!
//! Ports `ghidra.features.bsim.query.client.tables.ExeTable`.

use std::collections::HashMap;

/// A row in the executable table.
#[derive(Debug, Clone)]
pub struct ExecutableRow {
    /// Auto-incremented primary key.
    pub id: i64,
    /// Executable name.
    pub name: String,
    /// Executable MD5 hash.
    pub md5: String,
    /// Architecture string.
    pub architecture: String,
    /// Compiler string.
    pub compiler: String,
    /// Repository path.
    pub repository: String,
    /// Executable path.
    pub path: String,
    /// Date loaded.
    pub date_loaded: String,
    /// Description.
    pub description: Option<String>,
    /// Number of functions.
    pub function_count: i32,
    /// Executable category.
    pub category: Option<String>,
}

/// Column for ordering executable table queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExeTableOrderColumn {
    /// Order by name.
    Name,
    /// Order by date loaded.
    DateLoaded,
    /// Order by architecture.
    Architecture,
    /// Order by compiler.
    Compiler,
    /// Order by function count.
    FunctionCount,
}

/// The executable table structure.
#[derive(Debug, Default)]
pub struct ExeTable {
    rows: Vec<ExecutableRow>,
    name_index: HashMap<String, Vec<usize>>,
    md5_index: HashMap<String, Vec<usize>>,
}

impl ExeTable {
    /// Create an empty exe table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a row.
    pub fn insert(&mut self, row: ExecutableRow) -> i64 {
        let id = row.id;
        let name = row.name.clone();
        let md5 = row.md5.clone();
        let idx = self.rows.len();
        self.name_index.entry(name).or_default().push(idx);
        self.md5_index.entry(md5).or_default().push(idx);
        self.rows.push(row);
        id
    }

    /// Look up by name.
    pub fn find_by_name(&self, name: &str) -> Vec<&ExecutableRow> {
        self.name_index
            .get(name)
            .map(|indices| indices.iter().filter_map(|&i| self.rows.get(i)).collect())
            .unwrap_or_default()
    }

    /// Look up by MD5.
    pub fn find_by_md5(&self, md5: &str) -> Vec<&ExecutableRow> {
        self.md5_index
            .get(md5)
            .map(|indices| indices.iter().filter_map(|&i| self.rows.get(i)).collect())
            .unwrap_or_default()
    }

    /// Get all rows.
    pub fn all_rows(&self) -> &[ExecutableRow] {
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

    /// Generate CREATE TABLE SQL.
    pub fn create_table_sql() -> &'static str {
        "CREATE TABLE IF NOT EXISTS exetable (id BIGSERIAL PRIMARY KEY, name VARCHAR(512), md5 VARCHAR(32), architecture VARCHAR(100), compiler VARCHAR(100), repository VARCHAR(1024), path VARCHAR(1024), date_loaded TIMESTAMP, description TEXT, function_count INTEGER, category VARCHAR(256))"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_row(id: i64, name: &str, md5: &str) -> ExecutableRow {
        ExecutableRow {
            id,
            name: name.to_string(),
            md5: md5.to_string(),
            architecture: "x86:LE:64:default".to_string(),
            compiler: "gcc".to_string(),
            repository: String::new(),
            path: "/test".to_string(),
            date_loaded: "2024-01-01".to_string(),
            description: None,
            function_count: 100,
            category: None,
        }
    }

    #[test]
    fn test_insert_and_lookup() {
        let mut table = ExeTable::new();
        table.insert(make_test_row(1, "test.exe", "abc123"));
        table.insert(make_test_row(2, "other.exe", "def456"));
        assert_eq!(table.len(), 2);

        let found = table.find_by_name("test.exe");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, 1);
    }

    #[test]
    fn test_find_by_md5() {
        let mut table = ExeTable::new();
        table.insert(make_test_row(1, "a.exe", "md5hash"));
        let found = table.find_by_md5("md5hash");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "a.exe");
    }

    #[test]
    fn test_create_table_sql() {
        let sql = ExeTable::create_table_sql();
        assert!(sql.contains("exetable"));
        assert!(sql.contains("BIGSERIAL"));
    }
}
