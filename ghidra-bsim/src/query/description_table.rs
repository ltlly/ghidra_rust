//! Port of `DescriptionTable` from `ghidra.features.bsim.query.client.tables`.
//!
//! The `desctable` SQL table stores one row per ingested function. Each row
//! contains the function name, executable foreign key, signature foreign key,
//! flags bit-vector, and starting address.

use std::collections::HashMap;

/// A single row from the `desctable` SQL table.
///
/// Ports `DescriptionTable.DescriptionRow` from Ghidra's Java source.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DescriptionRow {
    /// Row ID of the function within desctable.
    pub rowid: i64,
    /// Name of the function.
    pub func_name: String,
    /// Row ID of the executable (within exetable) containing this function.
    pub id_exe: i64,
    /// Row ID of the feature vector (within vectortable) describing this function.
    pub id_sig: i64,
    /// The starting address of the function.
    pub addr: i64,
    /// Bit vector describing tags active for this function.
    pub flags: i32,
}

impl DescriptionRow {
    /// Create a new empty description row.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if this row has a valid (non-zero) row ID.
    pub fn has_valid_id(&self) -> bool {
        self.rowid > 0
    }

    /// Check if this row has an associated signature.
    pub fn has_signature(&self) -> bool {
        self.id_sig > 0
    }

    /// Check if a specific tag flag bit is set.
    pub fn has_flag(&self, bit: i32) -> bool {
        (self.flags & bit) != 0
    }
}

/// Filter mode for querying description rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptionFilterMode {
    /// Filter by signature ID.
    BySignatureId,
    /// Filter by function name and address range.
    ByFuncNameAddr,
    /// Filter by function name and executable.
    ByFuncAndExe,
    /// Filter by row ID.
    ByRowId,
}

/// The `desctable` SQL table in the BSim database.
///
/// Ports `ghidra.features.bsim.query.client.tables.DescriptionTable`.
#[derive(Debug, Clone)]
pub struct DescriptionTable {
    /// The SQL table name (always "desctable").
    pub table_name: String,
    /// The ID column name.
    pub id_column_name: String,
    /// Cached rows indexed by row ID.
    rows_by_id: HashMap<i64, DescriptionRow>,
    /// Cached rows indexed by (exe_id, func_name).
    rows_by_exe_func: HashMap<(i64, String), Vec<DescriptionRow>>,
    /// Cached rows indexed by signature ID.
    rows_by_sig: HashMap<i64, Vec<DescriptionRow>>,
    /// Number of insert operations.
    insert_count: u64,
}

impl DescriptionTable {
    /// Create a new DescriptionTable.
    pub fn new() -> Self {
        Self::default()
    }

    /// The CREATE TABLE SQL for desctable.
    pub fn create_table_sql() -> &'static str {
        "CREATE TABLE desctable (id BIGSERIAL PRIMARY KEY, name_func TEXT, \
         id_exe INTEGER, id_signature BIGINT, flags INTEGER, addr BIGINT)"
    }

    /// SQL for the sigindex.
    pub fn create_sig_index_sql() -> &'static str {
        "CREATE INDEX sigindex ON desctable (id_signature)"
    }

    /// SQL for the exefuncindex.
    pub fn create_exe_func_index_sql() -> &'static str {
        "CREATE INDEX exefuncindex ON desctable (id_exe, name_func, addr)"
    }

    /// INSERT SQL statement.
    pub fn insert_sql() -> &'static str {
        "INSERT INTO desctable (id, name_func, id_exe, id_signature, flags, addr) \
         VALUES(DEFAULT, $1, $2, $3, $4, $5) RETURNING id"
    }

    /// SELECT by signature ID.
    pub fn select_by_sig_id_sql() -> &'static str {
        "SELECT id, name_func, id_exe, id_signature, flags, addr \
         FROM desctable WHERE id_signature = $1"
    }

    /// SELECT by function name, address, and executable.
    pub fn select_by_func_name_addr_sql() -> &'static str {
        "SELECT id, name_func, id_exe, id_signature, flags, addr \
         FROM desctable WHERE name_func = $1 AND addr = $2 AND id_exe = $3"
    }

    /// SELECT by function name and executable.
    pub fn select_by_func_and_exe_sql() -> &'static str {
        "SELECT id, name_func, id_exe, id_signature, flags, addr \
         FROM desctable WHERE name_func = $1 AND id_exe = $2"
    }

    /// SELECT by row ID.
    pub fn select_by_row_id_sql() -> &'static str {
        "SELECT id, name_func, id_exe, id_signature, flags, addr \
         FROM desctable WHERE id = $1"
    }

    /// Cache a description row.
    pub fn cache_row(&mut self, row: DescriptionRow) {
        if row.has_signature() {
            self.rows_by_sig
                .entry(row.id_sig)
                .or_default()
                .push(row.clone());
        }
        self.rows_by_exe_func
            .entry((row.id_exe, row.func_name.clone()))
            .or_default()
            .push(row.clone());
        self.rows_by_id.insert(row.rowid, row);
    }

    /// Look up a description row by its row ID.
    pub fn get_by_id(&self, id: i64) -> Option<&DescriptionRow> {
        self.rows_by_id.get(&id)
    }

    /// Look up description rows by executable ID and function name.
    pub fn get_by_exe_and_func(
        &self,
        exe_id: i64,
        func_name: &str,
    ) -> Option<&Vec<DescriptionRow>> {
        self.rows_by_exe_func.get(&(exe_id, func_name.to_string()))
    }

    /// Look up description rows by signature ID.
    pub fn get_by_sig_id(&self, sig_id: i64) -> Option<&Vec<DescriptionRow>> {
        self.rows_by_sig.get(&sig_id)
    }

    /// Get total cached row count.
    pub fn row_count(&self) -> usize {
        self.rows_by_id.len()
    }

    /// Record an insert operation.
    pub fn record_insert(&mut self) {
        self.insert_count += 1;
    }

    /// Get the number of inserts performed.
    pub fn insert_count(&self) -> u64 {
        self.insert_count
    }

    /// Extract a `DescriptionRow` from column values.
    pub fn extract_description_row(values: &HashMap<String, String>) -> Option<DescriptionRow> {
        let mut row = DescriptionRow::new();
        row.rowid = values.get("id")?.parse().ok()?;
        row.func_name = values.get("name_func")?.clone();
        row.id_exe = values.get("id_exe")?.parse().ok()?;
        row.id_sig = values.get("id_signature")?.parse().ok()?;
        row.addr = values.get("addr")?.parse().ok()?;
        row.flags = values.get("flags")?.parse().ok()?;
        Some(row)
    }

    /// Clear all cached rows.
    pub fn clear_cache(&mut self) {
        self.rows_by_id.clear();
        self.rows_by_exe_func.clear();
        self.rows_by_sig.clear();
    }
}

impl Default for DescriptionTable {
    fn default() -> Self {
        Self {
            table_name: "desctable".to_string(),
            id_column_name: "id".to_string(),
            rows_by_id: HashMap::new(),
            rows_by_exe_func: HashMap::new(),
            rows_by_sig: HashMap::new(),
            insert_count: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_description_row_default() {
        let row = DescriptionRow::new();
        assert_eq!(row.rowid, 0);
        assert!(row.func_name.is_empty());
        assert!(!row.has_valid_id());
        assert!(!row.has_signature());
    }

    #[test]
    fn test_description_row_flags() {
        let row = DescriptionRow {
            flags: 0b1010,
            ..Default::default()
        };
        assert!(!row.has_flag(0b0001));
        assert!(row.has_flag(0b0010));
        assert!(!row.has_flag(0b0100));
        assert!(row.has_flag(0b1000));
    }

    #[test]
    fn test_description_table_sql() {
        let sql = DescriptionTable::create_table_sql();
        assert!(sql.contains("desctable"));
        assert!(sql.contains("BIGSERIAL PRIMARY KEY"));

        let insert = DescriptionTable::insert_sql();
        assert!(insert.contains("INSERT INTO desctable"));
    }

    #[test]
    fn test_description_table_cache() {
        let mut table = DescriptionTable::new();

        let row = DescriptionRow {
            rowid: 1,
            func_name: "main".to_string(),
            id_exe: 10,
            id_sig: 20,
            addr: 0x1000,
            flags: 0,
        };
        table.cache_row(row);
        assert_eq!(table.row_count(), 1);

        let found = table.get_by_id(1).unwrap();
        assert_eq!(found.func_name, "main");
        assert_eq!(found.addr, 0x1000);

        let by_exe = table.get_by_exe_and_func(10, "main").unwrap();
        assert_eq!(by_exe.len(), 1);

        let by_sig = table.get_by_sig_id(20).unwrap();
        assert_eq!(by_sig.len(), 1);
    }

    #[test]
    fn test_description_table_extract() {
        let mut values = HashMap::new();
        values.insert("id".to_string(), "100".to_string());
        values.insert("name_func".to_string(), "printf".to_string());
        values.insert("id_exe".to_string(), "5".to_string());
        values.insert("id_signature".to_string(), "50".to_string());
        values.insert("addr".to_string(), "4096".to_string());
        values.insert("flags".to_string(), "3".to_string());

        let row = DescriptionTable::extract_description_row(&values).unwrap();
        assert_eq!(row.rowid, 100);
        assert_eq!(row.func_name, "printf");
        assert_eq!(row.id_exe, 5);
        assert_eq!(row.id_sig, 50);
        assert_eq!(row.addr, 4096);
        assert_eq!(row.flags, 3);
    }

    #[test]
    fn test_description_table_clear() {
        let mut table = DescriptionTable::new();
        let row = DescriptionRow {
            rowid: 1,
            ..Default::default()
        };
        table.cache_row(row);
        assert_eq!(table.row_count(), 1);
        table.clear_cache();
        assert_eq!(table.row_count(), 0);
    }
}
