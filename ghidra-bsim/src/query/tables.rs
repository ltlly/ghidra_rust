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

/// Get all table creation SQL statements.
pub fn all_create_table_sql() -> Vec<String> {
    vec![
        create_executables_table_sql(),
        create_functions_table_sql(),
        create_signatures_table_sql(),
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
        assert_eq!(stmts.len(), 3);
    }
}
