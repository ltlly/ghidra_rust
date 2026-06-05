//! BSim client table definitions.
//!
//! Ports `ghidra.features.bsim.query.client.tables` from Ghidra's Java source.

/// Column definition for a BSim table.
#[derive(Debug, Clone)]
pub struct TableColumn {
    /// Column name.
    pub name: String,
    /// SQL data type.
    pub data_type: String,
    /// Whether this column is nullable.
    pub nullable: bool,
    /// Default value.
    pub default_value: Option<String>,
    /// Column comment/description.
    pub comment: String,
}

impl TableColumn {
    /// Create a new column.
    pub fn new(name: impl Into<String>, data_type: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            data_type: data_type.into(),
            nullable: true,
            default_value: None,
            comment: String::new(),
        }
    }

    /// Make this column non-nullable.
    pub fn not_null(mut self) -> Self {
        self.nullable = false;
        self
    }

    /// Set a default value.
    pub fn with_default(mut self, default: impl Into<String>) -> Self {
        self.default_value = Some(default.into());
        self
    }

    /// Add a comment.
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = comment.into();
        self
    }
}

/// Generate the CREATE TABLE SQL for the executables table.
pub fn create_executables_table_sql() -> String {
    "CREATE TABLE IF NOT EXISTS executables (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        md5 VARCHAR(32),
        arch VARCHAR(64),
        compiler VARCHAR(64),
        path TEXT,
        ingest_date TIMESTAMP,
        is_executable BOOLEAN DEFAULT TRUE,
        function_count INTEGER DEFAULT 0,
        version VARCHAR(64),
        trusted BOOLEAN DEFAULT FALSE,
        parent_id INTEGER,
        categories TEXT
    )".to_string()
}

/// Generate the CREATE TABLE SQL for the functions table.
pub fn create_functions_table_sql() -> String {
    "CREATE TABLE IF NOT EXISTS functions (
        id SERIAL PRIMARY KEY,
        executable_id INTEGER NOT NULL,
        name VARCHAR(255) NOT NULL,
        entry_point BIGINT NOT NULL,
        hash VARCHAR(64),
        size INTEGER DEFAULT 0,
        bb_count INTEGER DEFAULT 0,
        call_count INTEGER DEFAULT 0,
        instr_count INTEGER DEFAULT 0,
        signature BYTEA,
        is_library BOOLEAN DEFAULT FALSE,
        calling_convention VARCHAR(64),
        return_type VARCHAR(255),
        parameter_count INTEGER DEFAULT 0,
        namespace VARCHAR(255),
        UNIQUE(executable_id, entry_point)
    )".to_string()
}

/// Generate the CREATE TABLE SQL for the signatures table.
pub fn create_signatures_table_sql() -> String {
    "CREATE TABLE IF NOT EXISTS function_signatures (
        function_id INTEGER NOT NULL,
        mnemonic_seq TEXT,
        pcode_flow BYTEA,
        constant_count INTEGER DEFAULT 0,
        constants BYTEA,
        call_targets BYTEA,
        byte_histogram BYTEA,
        cfg_hash VARCHAR(64),
        dataflow_signature BYTEA,
        string_refs TEXT,
        register_usage BIGINT DEFAULT 0,
        PRIMARY KEY(function_id)
    )".to_string()
}

/// Generate the CREATE TABLE SQL for the callgraph table.
pub fn create_callgraph_table_sql() -> String {
    "CREATE TABLE IF NOT EXISTS callgraphtable (
        src BIGINT NOT NULL,
        dest BIGINT NOT NULL,
        PRIMARY KEY (src, dest)
    )".to_string()
}

/// Row in the callgraph table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallgraphRow {
    /// Source function id.
    pub src: i64,
    /// Destination function id.
    pub dest: i64,
}

/// Generate the CREATE TABLE SQL for the weight table.
pub fn create_weight_table_sql() -> String {
    "CREATE TABLE IF NOT EXISTS weighttable (
        funcid BIGINT NOT NULL,
        score_function VARCHAR(64),
        weight DOUBLE PRECISION DEFAULT 1.0,
        PRIMARY KEY (funcid, score_function)
    )".to_string()
}

/// Generate the CREATE TABLE SQL for the key-value table.
pub fn create_key_value_table_sql() -> String {
    "CREATE TABLE IF NOT EXISTS keyvaluetable (
        key VARCHAR(255) PRIMARY KEY,
        value TEXT NOT NULL
    )".to_string()
}

/// Generate the CREATE TABLE SQL for the category table.
pub fn create_category_table_sql() -> String {
    "CREATE TABLE IF NOT EXISTS categorytable (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL UNIQUE,
        description TEXT
    )".to_string()
}

/// Generate the CREATE TABLE SQL for the exe-to-category mapping table.
pub fn create_exe_to_category_table_sql() -> String {
    "CREATE TABLE IF NOT EXISTS exetocategory (
        exeid INTEGER NOT NULL,
        categoryid INTEGER NOT NULL,
        PRIMARY KEY (exeid, categoryid)
    )".to_string()
}

/// Generate the CREATE TABLE SQL for the optional (extra) fields table.
pub fn create_optional_table_sql() -> String {
    "CREATE TABLE IF NOT EXISTS optionaltable (
        funcid BIGINT NOT NULL,
        fieldname VARCHAR(255) NOT NULL,
        fieldvalue TEXT,
        PRIMARY KEY (funcid, fieldname)
    )".to_string()
}

/// Generate the CREATE TABLE SQL for the IDF lookup table.
pub fn create_idf_lookup_table_sql() -> String {
    "CREATE TABLE IF NOT EXISTS idflookuptable (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL UNIQUE
    )".to_string()
}

/// Get all table creation SQL statements.
pub fn all_create_table_sql() -> Vec<String> {
    vec![
        create_executables_table_sql(),
        create_functions_table_sql(),
        create_signatures_table_sql(),
        create_callgraph_table_sql(),
        create_weight_table_sql(),
        create_key_value_table_sql(),
        create_category_table_sql(),
        create_exe_to_category_table_sql(),
        create_optional_table_sql(),
        create_idf_lookup_table_sql(),
    ]
}

// ============================================================================
// SQL table abstractions ported from Java client/tables package
// ============================================================================

/// Cached prepared statement to avoid re-preparation overhead.
///
/// Ports `ghidra.features.bsim.query.client.tables.CachedStatement`.
#[derive(Debug)]
pub struct CachedStatement<T> {
    /// The cached statement, if prepared.
    statement: Option<T>,
    /// The SQL string used to prepare the statement.
    sql: String,
}

impl<T> CachedStatement<T> {
    /// Create a new empty cached statement.
    pub fn new() -> Self {
        Self {
            statement: None,
            sql: String::new(),
        }
    }

    /// Create with a pre-set SQL string.
    pub fn with_sql(sql: impl Into<String>) -> Self {
        Self {
            statement: None,
            sql: sql.into(),
        }
    }

    /// Get the SQL string.
    pub fn sql(&self) -> &str {
        &self.sql
    }

    /// Whether the statement has been prepared.
    pub fn is_prepared(&self) -> bool {
        self.statement.is_some()
    }

    /// Set the SQL and mark as needing preparation.
    pub fn set_sql(&mut self, sql: impl Into<String>) {
        self.sql = sql.into();
        self.statement = None;
    }

    /// Clear the cached statement.
    pub fn invalidate(&mut self) {
        self.statement = None;
    }
}

impl<T> Default for CachedStatement<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Abstract base for SQL table implementations.
///
/// Ports `ghidra.features.bsim.query.client.tables.SQLComplexTable`.
#[derive(Debug)]
pub struct SqlComplexTable {
    /// Table name.
    pub table_name: String,
    /// ID column name (null if table has no single-row ID column).
    pub id_column: Option<String>,
    /// Column definitions.
    pub columns: Vec<TableColumn>,
    /// Whether the table has been created.
    pub created: bool,
}

impl SqlComplexTable {
    /// Create a new complex table definition.
    pub fn new(table_name: impl Into<String>, id_column: Option<String>) -> Self {
        Self {
            table_name: table_name.into(),
            id_column,
            columns: Vec::new(),
            created: false,
        }
    }

    /// Add a column to this table.
    pub fn add_column(&mut self, column: TableColumn) {
        self.columns.push(column);
    }

    /// Generate the CREATE TABLE SQL for this table.
    pub fn create_sql(&self) -> String {
        let mut sql = format!("CREATE TABLE IF NOT EXISTS {} (\n", self.table_name);
        let col_strs: Vec<String> = self
            .columns
            .iter()
            .map(|c| {
                let mut col = format!("    {} {}", c.name, c.data_type);
                if !c.nullable {
                    col.push_str(" NOT NULL");
                }
                if let Some(ref default) = c.default_value {
                    col.push_str(&format!(" DEFAULT {}", default));
                }
                col
            })
            .collect();
        sql.push_str(&col_strs.join(",\n"));
        sql.push_str("\n)");
        sql
    }

    /// Generate a DELETE statement for a row with the given ID.
    pub fn delete_sql(&self) -> Option<String> {
        self.id_column
            .as_ref()
            .map(|id| format!("DELETE FROM {} WHERE {} = ?", self.table_name, id))
    }

    /// Generate a DROP TABLE statement.
    pub fn drop_sql(&self) -> String {
        format!("DROP TABLE IF EXISTS {}", self.table_name)
    }

    /// Generate a SELECT COUNT(*) statement.
    pub fn count_sql(&self) -> String {
        format!("SELECT COUNT(*) FROM {}", self.table_name)
    }

    /// Generate a TRUNCATE statement.
    pub fn truncate_sql(&self) -> String {
        format!("TRUNCATE TABLE {}", self.table_name)
    }

    /// Mark the table as created.
    pub fn mark_created(&mut self) {
        self.created = true;
    }

    /// Get column names as a comma-separated string.
    pub fn column_names(&self) -> String {
        self.columns
            .iter()
            .map(|c| c.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Statement supplier trait for lazy statement creation.
///
/// Ports `ghidra.features.bsim.query.client.tables.StatementSupplier`.
pub trait StatementSupplier: Send + Sync {
    /// Create a new statement with the given SQL.
    fn prepare(&self, sql: &str) -> Result<String, String>;
}

/// Simple in-memory statement supplier for testing.
#[derive(Debug)]
pub struct MemoryStatementSupplier {
    /// Prepared statements by SQL.
    statements: std::collections::HashMap<String, String>,
}

impl MemoryStatementSupplier {
    /// Create a new memory statement supplier.
    pub fn new() -> Self {
        Self {
            statements: std::collections::HashMap::new(),
        }
    }

    /// Get the number of prepared statements.
    pub fn statement_count(&self) -> usize {
        self.statements.len()
    }
}

impl Default for MemoryStatementSupplier {
    fn default() -> Self {
        Self::new()
    }
}

impl StatementSupplier for MemoryStatementSupplier {
    fn prepare(&self, sql: &str) -> Result<String, String> {
        Ok(sql.to_string())
    }
}

/// Executable table implementation.
///
/// Ports `ghidra.features.bsim.query.client.tables.ExeTable`.
#[derive(Debug)]
pub struct ExeTable {
    base: SqlComplexTable,
}

impl ExeTable {
    /// Create a new executable table.
    pub fn new() -> Self {
        let mut base = SqlComplexTable::new("executables", Some("id".to_string()));
        base.add_column(TableColumn::new("id", "SERIAL").not_null());
        base.add_column(TableColumn::new("name", "VARCHAR(255)").not_null());
        base.add_column(TableColumn::new("md5", "VARCHAR(32)"));
        base.add_column(TableColumn::new("arch", "VARCHAR(64)"));
        base.add_column(TableColumn::new("compiler", "VARCHAR(64)"));
        base.add_column(TableColumn::new("path", "TEXT"));
        base.add_column(TableColumn::new("ingest_date", "TIMESTAMP"));
        base.add_column(TableColumn::new("is_executable", "BOOLEAN").with_default("TRUE"));
        base.add_column(TableColumn::new("function_count", "INTEGER").with_default("0"));
        base.add_column(TableColumn::new("version", "VARCHAR(64)"));
        base.add_column(TableColumn::new("trusted", "BOOLEAN").with_default("FALSE"));
        base.add_column(TableColumn::new("parent_id", "INTEGER"));
        base.add_column(TableColumn::new("categories", "TEXT"));
        Self { base }
    }

    /// Get the SQL to insert an executable record.
    pub fn insert_sql(&self) -> String {
        "INSERT INTO executables (name, md5, arch, compiler, path, ingest_date, is_executable, function_count, version, trusted, parent_id, categories) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id".to_string()
    }

    /// Get the SQL to find an executable by MD5.
    pub fn find_by_md5_sql(&self) -> String {
        "SELECT * FROM executables WHERE md5 = ?".to_string()
    }

    /// Get the SQL to find an executable by name.
    pub fn find_by_name_sql(&self) -> String {
        "SELECT * FROM executables WHERE name = ?".to_string()
    }

    /// Get the underlying table definition.
    pub fn table(&self) -> &SqlComplexTable {
        &self.base
    }
}

impl Default for ExeTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Callgraph table implementation.
///
/// Ports `ghidra.features.bsim.query.client.tables.CallgraphTable`.
#[derive(Debug)]
pub struct CallgraphTable {
    base: SqlComplexTable,
}

impl CallgraphTable {
    /// Create a new callgraph table.
    pub fn new() -> Self {
        let mut base = SqlComplexTable::new("callgraphtable", None);
        base.add_column(TableColumn::new("src", "BIGINT").not_null());
        base.add_column(TableColumn::new("dest", "BIGINT").not_null());
        Self { base }
    }

    /// Get the SQL to insert a callgraph edge.
    pub fn insert_sql(&self) -> String {
        "INSERT INTO callgraphtable (src, dest) VALUES (?, ?)".to_string()
    }

    /// Get the SQL to find callers of a function.
    pub fn find_callers_sql(&self) -> String {
        "SELECT src FROM callgraphtable WHERE dest = ?".to_string()
    }

    /// Get the SQL to find callees of a function.
    pub fn find_callees_sql(&self) -> String {
        "SELECT dest FROM callgraphtable WHERE src = ?".to_string()
    }

    /// Get the underlying table definition.
    pub fn table(&self) -> &SqlComplexTable {
        &self.base
    }
}

impl Default for CallgraphTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Description table implementation for function signatures.
///
/// Ports `ghidra.features.bsim.query.client.tables.DescriptionTable`.
#[derive(Debug)]
pub struct DescriptionTable {
    base: SqlComplexTable,
}

impl DescriptionTable {
    /// Create a new description table.
    pub fn new() -> Self {
        let mut base = SqlComplexTable::new("function_signatures", Some("function_id".to_string()));
        base.add_column(TableColumn::new("function_id", "INTEGER").not_null());
        base.add_column(TableColumn::new("mnemonic_seq", "TEXT"));
        base.add_column(TableColumn::new("pcode_flow", "BYTEA"));
        base.add_column(TableColumn::new("constant_count", "INTEGER").with_default("0"));
        base.add_column(TableColumn::new("constants", "BYTEA"));
        base.add_column(TableColumn::new("call_targets", "BYTEA"));
        base.add_column(TableColumn::new("byte_histogram", "BYTEA"));
        base.add_column(TableColumn::new("cfg_hash", "VARCHAR(64)"));
        base.add_column(TableColumn::new("dataflow_signature", "BYTEA"));
        base.add_column(TableColumn::new("string_refs", "TEXT"));
        base.add_column(TableColumn::new("register_usage", "BIGINT").with_default("0"));
        Self { base }
    }

    /// Get the SQL to insert a description record.
    pub fn insert_sql(&self) -> String {
        "INSERT INTO function_signatures (function_id, mnemonic_seq, pcode_flow, constant_count, constants, call_targets, byte_histogram, cfg_hash, dataflow_signature, string_refs, register_usage) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)".to_string()
    }

    /// Get the underlying table definition.
    pub fn table(&self) -> &SqlComplexTable {
        &self.base
    }
}

impl Default for DescriptionTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Weight table for function similarity weights.
///
/// Ports `ghidra.features.bsim.query.client.tables.WeightTable`.
#[derive(Debug)]
pub struct WeightTable {
    base: SqlComplexTable,
}

impl WeightTable {
    /// Create a new weight table.
    pub fn new() -> Self {
        let mut base = SqlComplexTable::new("weighttable", None);
        base.add_column(TableColumn::new("funcid", "BIGINT").not_null());
        base.add_column(TableColumn::new("score_function", "VARCHAR(64)").not_null());
        base.add_column(TableColumn::new("weight", "DOUBLE PRECISION").with_default("1.0"));
        Self { base }
    }

    /// Get the SQL to look up a weight.
    pub fn lookup_sql(&self) -> String {
        "SELECT weight FROM weighttable WHERE funcid = ? AND score_function = ?".to_string()
    }

    /// Get the SQL to upsert a weight.
    pub fn upsert_sql(&self) -> String {
        "INSERT INTO weighttable (funcid, score_function, weight) VALUES (?, ?, ?) ON CONFLICT (funcid, score_function) DO UPDATE SET weight = ?".to_string()
    }

    /// Get the underlying table definition.
    pub fn table(&self) -> &SqlComplexTable {
        &self.base
    }
}

impl Default for WeightTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Key-value table for storing metadata.
///
/// Ports `ghidra.features.bsim.query.client.tables.KeyValueTable`.
#[derive(Debug)]
pub struct KeyValueTable {
    base: SqlComplexTable,
}

impl KeyValueTable {
    /// Create a new key-value table.
    pub fn new() -> Self {
        let mut base = SqlComplexTable::new("keyvaluetable", None);
        base.add_column(TableColumn::new("key", "VARCHAR(255)").not_null());
        base.add_column(TableColumn::new("value", "TEXT").not_null());
        Self { base }
    }

    /// Get the SQL to look up a value by key.
    pub fn get_sql(&self) -> String {
        "SELECT value FROM keyvaluetable WHERE key = ?".to_string()
    }

    /// Get the SQL to insert or update a key-value pair.
    pub fn upsert_sql(&self) -> String {
        "INSERT INTO keyvaluetable (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = ?".to_string()
    }

    /// Get the underlying table definition.
    pub fn table(&self) -> &SqlComplexTable {
        &self.base
    }
}

impl Default for KeyValueTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Optional fields table for storing additional function metadata.
///
/// Ports `ghidra.features.bsim.query.client.tables.OptionalTable`.
#[derive(Debug)]
pub struct OptionalTable {
    base: SqlComplexTable,
}

impl OptionalTable {
    /// Create a new optional table.
    pub fn new() -> Self {
        let mut base = SqlComplexTable::new("optionaltable", None);
        base.add_column(TableColumn::new("funcid", "BIGINT").not_null());
        base.add_column(TableColumn::new("fieldname", "VARCHAR(255)").not_null());
        base.add_column(TableColumn::new("fieldvalue", "TEXT"));
        Self { base }
    }

    /// Get the SQL to look up optional fields for a function.
    pub fn lookup_sql(&self) -> String {
        "SELECT fieldname, fieldvalue FROM optionaltable WHERE funcid = ?".to_string()
    }

    /// Get the SQL to insert an optional field.
    pub fn insert_sql(&self) -> String {
        "INSERT INTO optionaltable (funcid, fieldname, fieldvalue) VALUES (?, ?, ?)".to_string()
    }

    /// Get the underlying table definition.
    pub fn table(&self) -> &SqlComplexTable {
        &self.base
    }
}

impl Default for OptionalTable {
    fn default() -> Self {
        Self::new()
    }
}

/// IDF (Inverse Document Frequency) lookup table.
///
/// Ports `ghidra.features.bsim.query.client.tables.IdfLookupTable`.
#[derive(Debug)]
pub struct IdfLookupTable {
    base: SqlComplexTable,
}

impl IdfLookupTable {
    /// Create a new IDF lookup table.
    pub fn new() -> Self {
        let mut base = SqlComplexTable::new("idflookuptable", Some("id".to_string()));
        base.add_column(TableColumn::new("id", "SERIAL").not_null());
        base.add_column(TableColumn::new("name", "VARCHAR(255)").not_null());
        Self { base }
    }

    /// Get the SQL to look up an IDF value by name.
    pub fn lookup_by_name_sql(&self) -> String {
        "SELECT id FROM idflookuptable WHERE name = ?".to_string()
    }

    /// Get the SQL to insert a new IDF name.
    pub fn insert_sql(&self) -> String {
        "INSERT INTO idflookuptable (name) VALUES (?) RETURNING id".to_string()
    }

    /// Get the underlying table definition.
    pub fn table(&self) -> &SqlComplexTable {
        &self.base
    }
}

impl Default for IdfLookupTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Exe-to-category mapping table.
///
/// Ports `ghidra.features.bsim.query.client.tables.ExeToCategoryTable`.
#[derive(Debug)]
pub struct ExeToCategoryTable {
    base: SqlComplexTable,
}

impl ExeToCategoryTable {
    /// Create a new exe-to-category table.
    pub fn new() -> Self {
        let mut base = SqlComplexTable::new("exetocategory", None);
        base.add_column(TableColumn::new("exeid", "INTEGER").not_null());
        base.add_column(TableColumn::new("categoryid", "INTEGER").not_null());
        Self { base }
    }

    /// Get the SQL to find categories for an executable.
    pub fn categories_for_exe_sql(&self) -> String {
        "SELECT c.name FROM categorytable c JOIN exetocategory e ON c.id = e.categoryid WHERE e.exeid = ?".to_string()
    }

    /// Get the SQL to insert a mapping.
    pub fn insert_sql(&self) -> String {
        "INSERT INTO exetocategory (exeid, categoryid) VALUES (?, ?)".to_string()
    }

    /// Get the underlying table definition.
    pub fn table(&self) -> &SqlComplexTable {
        &self.base
    }
}

impl Default for ExeToCategoryTable {
    fn default() -> Self {
        Self::new()
    }
}

/// String-based SQL table (for simple key/value-like tables).
///
/// Ports `ghidra.features.bsim.query.client.tables.SQLStringTable`.
#[derive(Debug)]
pub struct SqlStringTable {
    /// Table name.
    pub table_name: String,
    /// Column definitions.
    pub columns: Vec<TableColumn>,
    /// Column used as primary lookup key.
    pub key_column: String,
}

impl SqlStringTable {
    /// Create a new string table.
    pub fn new(table_name: impl Into<String>, key_column: impl Into<String>) -> Self {
        Self {
            table_name: table_name.into(),
            columns: Vec::new(),
            key_column: key_column.into(),
        }
    }

    /// Add a column.
    pub fn with_column(mut self, column: TableColumn) -> Self {
        self.columns.push(column);
        self
    }

    /// Generate SELECT by key SQL.
    pub fn select_by_key_sql(&self) -> String {
        format!(
            "SELECT {} FROM {} WHERE {} = ?",
            self.column_names(),
            self.table_name,
            self.key_column
        )
    }

    /// Get column names.
    pub fn column_names(&self) -> String {
        self.columns
            .iter()
            .map(|c| c.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Get all table object instances.
pub fn all_tables() -> Vec<Box<dyn std::fmt::Debug>> {
    vec![
        Box::new(ExeTable::new()),
        Box::new(CallgraphTable::new()),
        Box::new(DescriptionTable::new()),
        Box::new(WeightTable::new()),
        Box::new(KeyValueTable::new()),
        Box::new(OptionalTable::new()),
        Box::new(IdfLookupTable::new()),
        Box::new(ExeToCategoryTable::new()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table_column_new() {
        let col = TableColumn::new("name", "VARCHAR(255)");
        assert_eq!(col.name, "name");
        assert_eq!(col.data_type, "VARCHAR(255)");
        assert!(col.nullable);
    }

    #[test]
    fn test_table_column_builder() {
        let col = TableColumn::new("id", "SERIAL")
            .not_null()
            .with_default("0")
            .with_comment("Primary key");
        assert!(!col.nullable);
        assert_eq!(col.default_value.as_deref(), Some("0"));
        assert_eq!(col.comment, "Primary key");
    }

    #[test]
    fn test_create_table_sql() {
        let sql = create_executables_table_sql();
        assert!(sql.contains("executables"));
        assert!(sql.contains("SERIAL PRIMARY KEY"));
        assert!(sql.contains("name VARCHAR(255)"));

        let sql = create_functions_table_sql();
        assert!(sql.contains("functions"));
        assert!(sql.contains("entry_point BIGINT"));

        let sql = create_signatures_table_sql();
        assert!(sql.contains("function_signatures"));
        assert!(sql.contains("mnemonic_seq TEXT"));
    }

    #[test]
    fn test_all_create_table_sql() {
        let stmts = all_create_table_sql();
        assert_eq!(stmts.len(), 10);
    }

    #[test]
    fn test_callgraph_table_sql() {
        let sql = create_callgraph_table_sql();
        assert!(sql.contains("callgraphtable"));
        assert!(sql.contains("src BIGINT"));
        assert!(sql.contains("dest BIGINT"));
        assert!(sql.contains("PRIMARY KEY (src, dest)"));
    }

    #[test]
    fn test_callgraph_row() {
        let row = CallgraphRow { src: 1, dest: 2 };
        assert_eq!(row.src, 1);
        assert_eq!(row.dest, 2);
    }

    #[test]
    fn test_weight_table_sql() {
        let sql = create_weight_table_sql();
        assert!(sql.contains("weighttable"));
        assert!(sql.contains("weight DOUBLE PRECISION"));
    }

    #[test]
    fn test_key_value_table_sql() {
        let sql = create_key_value_table_sql();
        assert!(sql.contains("keyvaluetable"));
        assert!(sql.contains("key VARCHAR"));
        assert!(sql.contains("value TEXT"));
    }

    #[test]
    fn test_category_table_sql() {
        let sql = create_category_table_sql();
        assert!(sql.contains("categorytable"));
        assert!(sql.contains("name VARCHAR"));
    }

    #[test]
    fn test_exe_to_category_table_sql() {
        let sql = create_exe_to_category_table_sql();
        assert!(sql.contains("exetocategory"));
        assert!(sql.contains("exeid INTEGER"));
        assert!(sql.contains("categoryid INTEGER"));
    }

    #[test]
    fn test_optional_table_sql() {
        let sql = create_optional_table_sql();
        assert!(sql.contains("optionaltable"));
        assert!(sql.contains("fieldname VARCHAR"));
        assert!(sql.contains("fieldvalue TEXT"));
    }

    #[test]
    fn test_idf_lookup_table_sql() {
        let sql = create_idf_lookup_table_sql();
        assert!(sql.contains("idflookuptable"));
        assert!(sql.contains("name VARCHAR"));
    }

    #[test]
    fn test_cached_statement() {
        let mut stmt = CachedStatement::<String>::new();
        assert!(!stmt.is_prepared());
        assert!(stmt.sql().is_empty());

        stmt.set_sql("SELECT 1");
        assert_eq!(stmt.sql(), "SELECT 1");
        assert!(!stmt.is_prepared());

        stmt.invalidate();
        assert!(!stmt.is_prepared());
    }

    #[test]
    fn test_cached_statement_with_sql() {
        let stmt = CachedStatement::<String>::with_sql("SELECT * FROM test");
        assert_eq!(stmt.sql(), "SELECT * FROM test");
    }

    #[test]
    fn test_sql_complex_table() {
        let mut table = SqlComplexTable::new("test_table", Some("id".to_string()));
        table.add_column(TableColumn::new("id", "SERIAL").not_null());
        table.add_column(TableColumn::new("name", "VARCHAR(255)"));

        assert_eq!(table.table_name, "test_table");
        assert_eq!(table.columns.len(), 2);
        assert!(table.id_column.is_some());

        let create = table.create_sql();
        assert!(create.contains("CREATE TABLE IF NOT EXISTS test_table"));
        assert!(create.contains("id SERIAL NOT NULL"));
        assert!(create.contains("name VARCHAR(255)"));

        let delete = table.delete_sql();
        assert!(delete.is_some());
        assert!(delete.unwrap().contains("DELETE FROM test_table WHERE id = ?"));

        let drop = table.drop_sql();
        assert!(drop.contains("DROP TABLE IF EXISTS test_table"));

        let count = table.count_sql();
        assert!(count.contains("SELECT COUNT(*) FROM test_table"));

        assert!(!table.created);
        table.mark_created();
        assert!(table.created);
    }

    #[test]
    fn test_sql_complex_table_no_id() {
        let table = SqlComplexTable::new("junction_table", None);
        assert!(table.delete_sql().is_none());
    }

    #[test]
    fn test_exe_table() {
        let table = ExeTable::new();
        assert_eq!(table.table().table_name, "executables");
        assert_eq!(table.table().columns.len(), 13);
        assert!(table.insert_sql().contains("INSERT INTO executables"));
        assert!(table.find_by_md5_sql().contains("WHERE md5 = ?"));
        assert!(table.find_by_name_sql().contains("WHERE name = ?"));
    }

    #[test]
    fn test_callgraph_table() {
        let table = CallgraphTable::new();
        assert_eq!(table.table().table_name, "callgraphtable");
        assert_eq!(table.table().columns.len(), 2);
        assert!(table.insert_sql().contains("INSERT INTO callgraphtable"));
        assert!(table.find_callers_sql().contains("WHERE dest = ?"));
        assert!(table.find_callees_sql().contains("WHERE src = ?"));
    }

    #[test]
    fn test_description_table() {
        let table = DescriptionTable::new();
        assert_eq!(table.table().table_name, "function_signatures");
        assert!(table.insert_sql().contains("INSERT INTO function_signatures"));
    }

    #[test]
    fn test_weight_table() {
        let table = WeightTable::new();
        assert_eq!(table.table().table_name, "weighttable");
        assert!(table.lookup_sql().contains("WHERE funcid = ?"));
        assert!(table.upsert_sql().contains("ON CONFLICT"));
    }

    #[test]
    fn test_key_value_table() {
        let table = KeyValueTable::new();
        assert_eq!(table.table().table_name, "keyvaluetable");
        assert!(table.get_sql().contains("WHERE key = ?"));
        assert!(table.upsert_sql().contains("ON CONFLICT"));
    }

    #[test]
    fn test_optional_table() {
        let table = OptionalTable::new();
        assert_eq!(table.table().table_name, "optionaltable");
        assert!(table.lookup_sql().contains("WHERE funcid = ?"));
    }

    #[test]
    fn test_idf_lookup_table() {
        let table = IdfLookupTable::new();
        assert_eq!(table.table().table_name, "idflookuptable");
        assert!(table.lookup_by_name_sql().contains("WHERE name = ?"));
        assert!(table.insert_sql().contains("RETURNING id"));
    }

    #[test]
    fn test_exe_to_category_table() {
        let table = ExeToCategoryTable::new();
        assert_eq!(table.table().table_name, "exetocategory");
        assert!(table.categories_for_exe_sql().contains("JOIN"));
    }

    #[test]
    fn test_sql_string_table() {
        let table = SqlStringTable::new("my_table", "key")
            .with_column(TableColumn::new("key", "VARCHAR(255)").not_null())
            .with_column(TableColumn::new("value", "TEXT"));

        assert_eq!(table.table_name, "my_table");
        assert_eq!(table.key_column, "key");
        assert_eq!(table.columns.len(), 2);
        assert!(table.select_by_key_sql().contains("WHERE key = ?"));
    }

    #[test]
    fn test_memory_statement_supplier() {
        let supplier = MemoryStatementSupplier::new();
        assert_eq!(supplier.statement_count(), 0);
        let result = supplier.prepare("SELECT 1");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "SELECT 1");
    }

    #[test]
    fn test_all_tables() {
        let tables = all_tables();
        assert_eq!(tables.len(), 8);
    }
}
