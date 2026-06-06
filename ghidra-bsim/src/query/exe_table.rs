//! Port of `ExeTable` from `ghidra.features.bsim.query.client.tables`.
//!
//! The `exetable` SQL table stores one row per ingested executable. Each row
//! contains the executable's MD5 hash, name, architecture ID, compiler ID,
//! ingest date, repository path, and file path. Architecture, compiler,
//! repository, and path values are stored as integer foreign keys referencing
//! separate string tables (`SQLStringTable`).

use std::collections::HashMap;

/// Order column for executable table queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExeTableOrderColumn {
    /// Order by MD5 hash.
    Md5,
    /// Order by executable name.
    Name,
}

impl ExeTableOrderColumn {
    /// Return the SQL column name for this order column.
    pub fn sql_column(&self) -> &'static str {
        match self {
            ExeTableOrderColumn::Md5 => "md5",
            ExeTableOrderColumn::Name => "name_exec",
        }
    }
}

/// A single row from the `exetable` SQL table.
///
/// Ports `ExeTable.ExecutableRow` from Ghidra's Java source.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ExecutableRow {
    /// The auto-generated row ID.
    pub rowid: i64,
    /// MD5 hash of the executable binary.
    pub md5: String,
    /// Name of the executable.
    pub exename: String,
    /// Foreign key into the architecture string table.
    pub arch_id: i64,
    /// Foreign key into the compiler string table.
    pub compiler_id: i64,
    /// Ingest date as milliseconds since epoch.
    pub date_milli: i64,
    /// Foreign key into the repository string table.
    pub repo_id: i64,
    /// Foreign key into the path string table.
    pub path_id: i64,
}

impl ExecutableRow {
    /// Create a new empty executable row.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if this row has a valid (non-zero) row ID.
    pub fn has_valid_id(&self) -> bool {
        self.rowid > 0
    }

    /// Check if this row has a valid MD5 hash (non-empty, 32 hex chars).
    pub fn has_valid_md5(&self) -> bool {
        self.md5.len() == 32 && self.md5.chars().all(|c| c.is_ascii_hexdigit())
    }
}

/// The `exetable` SQL table in the BSim database.
///
/// Ports `ghidra.features.bsim.query.client.tables.ExeTable`. Manages
/// insert, query, and extraction of executable records in the database.
#[derive(Debug, Clone)]
pub struct ExeTable {
    /// SQL table name (always "exetable").
    pub table_name: String,
    /// Architecture string table name.
    pub arch_table_name: String,
    /// Compiler string table name.
    pub compiler_table_name: String,
    /// Repository string table name.
    pub repo_table_name: String,
    /// Path string table name.
    pub path_table_name: String,
    /// Cached rows by ID.
    rows_by_id: HashMap<i64, ExecutableRow>,
    /// Cached rows by MD5.
    rows_by_md5: HashMap<String, ExecutableRow>,
    /// Cached rows by name.
    rows_by_name: HashMap<String, Vec<ExecutableRow>>,
    /// Number of insert operations performed.
    insert_count: u64,
}

impl ExeTable {
    /// Create a new ExeTable with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create the SQL CREATE TABLE statement for `exetable`.
    pub fn create_table_sql() -> &'static str {
        "CREATE TABLE exetable (id SERIAL PRIMARY KEY, md5 TEXT UNIQUE, \
         name_exec TEXT, architecture INTEGER, name_compiler INTEGER, \
         ingest_date TIMESTAMP WITH TIME ZONE, repository INTEGER, path INTEGER)"
    }

    /// Create the SQL INSERT statement.
    pub fn insert_sql() -> &'static str {
        "INSERT INTO exetable (id, md5, name_exec, architecture, name_compiler, \
         ingest_date, repository, path) VALUES(DEFAULT, $1, $2, $3, $4, $5, $6, $7) \
         RETURNING id"
    }

    /// Create the SQL SELECT by name statement.
    pub fn select_by_name_sql() -> &'static str {
        "SELECT id, md5, name_exec, architecture, name_compiler, \
         extract(epoch from ingest_date), repository, path \
         FROM exetable WHERE name_exec = $1 LIMIT $2"
    }

    /// Create the SQL SELECT by ID statement.
    pub fn select_by_id_sql() -> &'static str {
        "SELECT id, md5, name_exec, architecture, name_compiler, \
         extract(epoch from ingest_date), repository, path \
         FROM exetable WHERE id = $1"
    }

    /// Create the SQL SELECT by MD5 statement.
    pub fn select_by_md5_sql() -> &'static str {
        "SELECT id, md5, name_exec, architecture, name_compiler, \
         extract(epoch from ingest_date), repository, path \
         FROM exetable WHERE md5 = $1"
    }

    /// Cache an executable row for later retrieval.
    pub fn cache_row(&mut self, row: ExecutableRow) {
        if row.has_valid_md5() {
            self.rows_by_md5.insert(row.md5.clone(), row.clone());
        }
        self.rows_by_name
            .entry(row.exename.clone())
            .or_default()
            .push(row.clone());
        self.rows_by_id.insert(row.rowid, row);
    }

    /// Look up an executable row by its row ID.
    pub fn get_by_id(&self, id: i64) -> Option<&ExecutableRow> {
        self.rows_by_id.get(&id)
    }

    /// Look up an executable row by its MD5 hash.
    pub fn get_by_md5(&self, md5: &str) -> Option<&ExecutableRow> {
        self.rows_by_md5.get(md5)
    }

    /// Look up executable rows by name.
    pub fn get_by_name(&self, name: &str) -> Option<&Vec<ExecutableRow>> {
        self.rows_by_name.get(name)
    }

    /// Get the total number of cached rows.
    pub fn row_count(&self) -> usize {
        self.rows_by_id.len()
    }

    /// Get the number of insert operations performed.
    pub fn insert_count(&self) -> u64 {
        self.insert_count
    }

    /// Record an insert operation.
    pub fn record_insert(&mut self) {
        self.insert_count += 1;
    }

    /// Extract an `ExecutableRow` from a set of column values.
    ///
    /// This simulates reading from a JDBC ResultSet.
    pub fn extract_executable_row(values: &HashMap<String, String>) -> Option<ExecutableRow> {
        let mut row = ExecutableRow::new();
        row.rowid = values.get("id")?.parse().ok()?;
        row.md5 = values.get("md5")?.clone();
        row.exename = values.get("name_exec")?.clone();
        row.arch_id = values.get("architecture")?.parse().ok()?;
        row.compiler_id = values.get("name_compiler")?.parse().ok()?;
        row.date_milli = values.get("ingest_date_epoch")?.parse().ok()?;
        row.repo_id = values.get("repository")?.parse().ok()?;
        row.path_id = values.get("path")?.parse().ok()?;
        Some(row)
    }

    /// Clear all cached rows.
    pub fn clear_cache(&mut self) {
        self.rows_by_id.clear();
        self.rows_by_md5.clear();
        self.rows_by_name.clear();
    }
}

impl Default for ExeTable {
    fn default() -> Self {
        Self {
            table_name: "exetable".to_string(),
            arch_table_name: "architecturetable".to_string(),
            compiler_table_name: "compilertable".to_string(),
            repo_table_name: "repositorytable".to_string(),
            path_table_name: "pathtable".to_string(),
            rows_by_id: HashMap::new(),
            rows_by_md5: HashMap::new(),
            rows_by_name: HashMap::new(),
            insert_count: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exe_table_default() {
        let table = ExeTable::new();
        assert_eq!(table.table_name, "exetable");
        assert_eq!(table.row_count(), 0);
    }

    #[test]
    fn test_exe_table_sql_statements() {
        let sql = ExeTable::create_table_sql();
        assert!(sql.contains("exetable"));
        assert!(sql.contains("SERIAL PRIMARY KEY"));
        assert!(sql.contains("md5 TEXT UNIQUE"));

        let insert = ExeTable::insert_sql();
        assert!(insert.contains("INSERT INTO exetable"));

        let select_name = ExeTable::select_by_name_sql();
        assert!(select_name.contains("name_exec = $1"));

        let select_id = ExeTable::select_by_id_sql();
        assert!(select_id.contains("WHERE id = $1"));

        let select_md5 = ExeTable::select_by_md5_sql();
        assert!(select_md5.contains("WHERE md5 = $1"));
    }

    #[test]
    fn test_executable_row_default() {
        let row = ExecutableRow::new();
        assert_eq!(row.rowid, 0);
        assert!(row.md5.is_empty());
        assert!(!row.has_valid_id());
        assert!(!row.has_valid_md5());
    }

    #[test]
    fn test_executable_row_valid_md5() {
        let mut row = ExecutableRow::new();
        row.md5 = "d41d8cd98f00b204e9800998ecf8427e".to_string();
        assert!(row.has_valid_md5());

        row.md5 = "invalid".to_string();
        assert!(!row.has_valid_md5());
    }

    #[test]
    fn test_exe_table_cache_and_lookup() {
        let mut table = ExeTable::new();

        let mut row = ExecutableRow::new();
        row.rowid = 1;
        row.md5 = "abc123def456abc123def456abc123de".to_string();
        row.exename = "test.exe".to_string();
        row.arch_id = 10;
        row.compiler_id = 20;
        row.date_milli = 1000000;
        row.repo_id = 1;
        row.path_id = 5;

        table.cache_row(row);
        assert_eq!(table.row_count(), 1);

        let found = table.get_by_id(1).unwrap();
        assert_eq!(found.exename, "test.exe");
        assert_eq!(found.arch_id, 10);

        let by_md5 = table.get_by_md5("abc123def456abc123def456abc123de").unwrap();
        assert_eq!(by_md5.rowid, 1);

        let by_name = table.get_by_name("test.exe").unwrap();
        assert_eq!(by_name.len(), 1);
    }

    #[test]
    fn test_exe_table_order_column() {
        assert_eq!(ExeTableOrderColumn::Md5.sql_column(), "md5");
        assert_eq!(ExeTableOrderColumn::Name.sql_column(), "name_exec");
    }

    #[test]
    fn test_exe_table_extract_row() {
        let mut values = HashMap::new();
        values.insert("id".to_string(), "42".to_string());
        values.insert("md5".to_string(), "d41d8cd98f00b204e9800998ecf8427e".to_string());
        values.insert("name_exec".to_string(), "libc.so".to_string());
        values.insert("architecture".to_string(), "3".to_string());
        values.insert("name_compiler".to_string(), "7".to_string());
        values.insert("ingest_date_epoch".to_string(), "1700000000".to_string());
        values.insert("repository".to_string(), "1".to_string());
        values.insert("path".to_string(), "2".to_string());

        let row = ExeTable::extract_executable_row(&values).unwrap();
        assert_eq!(row.rowid, 42);
        assert_eq!(row.exename, "libc.so");
        assert_eq!(row.arch_id, 3);
        assert_eq!(row.compiler_id, 7);
    }

    #[test]
    fn test_exe_table_clear_cache() {
        let mut table = ExeTable::new();
        let row = ExecutableRow {
            rowid: 1,
            ..Default::default()
        };
        table.cache_row(row);
        assert_eq!(table.row_count(), 1);
        table.clear_cache();
        assert_eq!(table.row_count(), 0);
    }
}
