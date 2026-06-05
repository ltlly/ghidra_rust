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
}
