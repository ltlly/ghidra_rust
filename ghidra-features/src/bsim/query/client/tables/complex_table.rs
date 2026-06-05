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

// ============================================================================
// Additional table types ported from Ghidra's BSim client tables package
// ============================================================================

/// SQL string table for storing simple key-value string data.
///
/// Used for architecture names, compiler names, repository names,
/// path names, and category string tables.
#[derive(Debug, Clone, Default)]
pub struct SQLStringTable {
    /// Table name.
    pub name: String,
    /// Entries: (id, string_value).
    entries: Vec<(i64, String)>,
    /// Maximum cache size.
    pub max_cache_size: usize,
}

impl SQLStringTable {
    /// Create a new SQL string table.
    pub fn new(name: impl Into<String>, max_cache_size: usize) -> Self {
        Self {
            name: name.into(),
            entries: Vec::new(),
            max_cache_size,
        }
    }

    /// Add a string entry.
    pub fn add(&mut self, id: i64, value: impl Into<String>) {
        self.entries.push((id, value.into()));
    }

    /// Look up a string by ID.
    pub fn get(&self, id: i64) -> Option<&str> {
        self.entries
            .iter()
            .find(|(i, _)| *i == id)
            .map(|(_, v)| v.as_str())
    }

    /// Look up an ID by string value.
    pub fn get_id(&self, value: &str) -> Option<i64> {
        self.entries
            .iter()
            .find(|(_, v)| v == value)
            .map(|(id, _)| *id)
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Key-value table for storing database metadata.
///
/// Stores configuration and metadata as key-value pairs.
#[derive(Debug, Clone, Default)]
pub struct KeyValueTable {
    /// Table name.
    pub name: String,
    /// Entries: (key, value).
    entries: HashMap<String, String>,
}

impl KeyValueTable {
    /// Create a new key-value table.
    pub fn new() -> Self {
        Self {
            name: "keyvaluetable".to_string(),
            entries: HashMap::new(),
        }
    }

    /// Set a key-value pair.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.entries.insert(key.into(), value.into());
    }

    /// Get a value by key.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(|s| s.as_str())
    }

    /// Remove a key.
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.entries.remove(key)
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Optional table for storing optional function metadata.
///
/// Used for storing optional values associated with functions
/// (e.g., confidence scores, feature flags).
#[derive(Debug, Clone, Default)]
pub struct OptionalTable {
    /// Table name.
    pub name: String,
    /// Entries: (function_key, optional_name, optional_value).
    entries: Vec<(i64, String, String)>,
}

impl OptionalTable {
    /// Create a new optional table.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            entries: Vec::new(),
        }
    }

    /// Add an optional value.
    pub fn add(&mut self, function_key: i64, name: impl Into<String>, value: impl Into<String>) {
        self.entries.push((function_key, name.into(), value.into()));
    }

    /// Get optional values for a function key.
    pub fn get_by_function(&self, function_key: i64) -> Vec<(&str, &str)> {
        self.entries
            .iter()
            .filter(|(k, _, _)| *k == function_key)
            .map(|(_, name, value)| (name.as_str(), value.as_str()))
            .collect()
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// IDF (Inverse Document Frequency) lookup table.
///
/// Stores IDF weights for feature vectors used in similarity scoring.
#[derive(Debug, Clone, Default)]
pub struct IdfLookupTable {
    /// Table name.
    pub name: String,
    /// IDF weights: (feature_id, weight).
    weights: HashMap<u64, f64>,
}

impl IdfLookupTable {
    /// Create a new IDF lookup table.
    pub fn new() -> Self {
        Self {
            name: "idflookup".to_string(),
            weights: HashMap::new(),
        }
    }

    /// Set an IDF weight.
    pub fn set_weight(&mut self, feature_id: u64, weight: f64) {
        self.weights.insert(feature_id, weight);
    }

    /// Get an IDF weight.
    pub fn get_weight(&self, feature_id: u64) -> Option<f64> {
        self.weights.get(&feature_id).copied()
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.weights.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.weights.is_empty()
    }
}

/// Weight table for storing vector feature weights.
///
/// Stores the weight configuration for LSH vector features.
#[derive(Debug, Clone, Default)]
pub struct WeightTable {
    /// Table name.
    pub name: String,
    /// Weights: (stage_index, bin_index, weight).
    weights: Vec<(i32, i32, f64)>,
}

impl WeightTable {
    /// Create a new weight table.
    pub fn new() -> Self {
        Self {
            name: "weighttable".to_string(),
            weights: Vec::new(),
        }
    }

    /// Add a weight entry.
    pub fn add_weight(&mut self, stage: i32, bin: i32, weight: f64) {
        self.weights.push((stage, bin, weight));
    }

    /// Get weights for a specific stage.
    pub fn get_stage_weights(&self, stage: i32) -> Vec<(i32, f64)> {
        self.weights
            .iter()
            .filter(|(s, _, _)| *s == stage)
            .map(|(_, bin, w)| (*bin, *w))
            .collect()
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.weights.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.weights.is_empty()
    }
}

/// Callgraph table for storing function call relationships.
///
/// Stores edges in the function callgraph: (caller_key, callee_key, call_address).
#[derive(Debug, Clone, Default)]
pub struct CallgraphTable {
    /// Table name.
    pub name: String,
    /// Edges: (caller_function_key, callee_function_key, call_site_address).
    edges: Vec<(i64, i64, u64)>,
}

impl CallgraphTable {
    /// Create a new callgraph table.
    pub fn new() -> Self {
        Self {
            name: "callgraphtable".to_string(),
            edges: Vec::new(),
        }
    }

    /// Add a callgraph edge.
    pub fn add_edge(&mut self, caller_key: i64, callee_key: i64, call_address: u64) {
        self.edges.push((caller_key, callee_key, call_address));
    }

    /// Get callees of a function.
    pub fn get_callees(&self, caller_key: i64) -> Vec<(i64, u64)> {
        self.edges
            .iter()
            .filter(|(c, _, _)| *c == caller_key)
            .map(|(_, callee, addr)| (*callee, *addr))
            .collect()
    }

    /// Get callers of a function.
    pub fn get_callers(&self, callee_key: i64) -> Vec<(i64, u64)> {
        self.edges
            .iter()
            .filter(|(_, c, _)| *c == callee_key)
            .map(|(caller, _, addr)| (*caller, *addr))
            .collect()
    }

    /// Get the number of edges.
    pub fn len(&self) -> usize {
        self.edges.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }
}

/// Description table for storing function description metadata.
///
/// Stores function names, addresses, and executable references.
#[derive(Debug, Clone, Default)]
pub struct DescriptionTable {
    /// Table name.
    pub name: String,
    /// Rows: (function_key, name, address, exe_key).
    rows: Vec<(i64, String, u64, i64)>,
}

impl DescriptionTable {
    /// Create a new description table.
    pub fn new() -> Self {
        Self {
            name: "descriptiontable".to_string(),
            rows: Vec::new(),
        }
    }

    /// Add a function description row.
    pub fn add(&mut self, function_key: i64, name: impl Into<String>, address: u64, exe_key: i64) {
        self.rows.push((function_key, name.into(), address, exe_key));
    }

    /// Look up by function key.
    pub fn get(&self, function_key: i64) -> Option<(i64, &str, u64, i64)> {
        self.rows
            .iter()
            .find(|(k, _, _, _)| *k == function_key)
            .map(|(_, name, addr, exe)| (*exe, name.as_str(), *addr, *exe))
    }

    /// Get all rows for an executable.
    pub fn get_by_exe(&self, exe_key: i64) -> Vec<(i64, &str, u64)> {
        self.rows
            .iter()
            .filter(|(_, _, _, e)| *e == exe_key)
            .map(|(k, name, addr, _)| (*k, name.as_str(), *addr))
            .collect()
    }

    /// Get the number of rows.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// Executable table for storing executable metadata.
///
/// Stores MD5 hashes, names, architectures, compilers, and other
/// executable-level information.
#[derive(Debug, Clone, Default)]
pub struct ExeTable {
    /// Table name.
    pub name: String,
    /// Rows: (exe_key, md5, name, architecture, compiler).
    rows: Vec<(i64, String, String, String, String)>,
}

impl ExeTable {
    /// Create a new executable table.
    pub fn new() -> Self {
        Self {
            name: "exetable".to_string(),
            rows: Vec::new(),
        }
    }

    /// Add an executable row.
    pub fn add(
        &mut self,
        exe_key: i64,
        md5: impl Into<String>,
        name: impl Into<String>,
        arch: impl Into<String>,
        compiler: impl Into<String>,
    ) {
        self.rows
            .push((exe_key, md5.into(), name.into(), arch.into(), compiler.into()));
    }

    /// Look up by exe key.
    pub fn get(&self, exe_key: i64) -> Option<(&str, &str, &str, &str)> {
        self.rows
            .iter()
            .find(|(k, _, _, _, _)| *k == exe_key)
            .map(|(_, md5, name, arch, compiler)| {
                (md5.as_str(), name.as_str(), arch.as_str(), compiler.as_str())
            })
    }

    /// Look up by MD5 hash.
    pub fn get_by_md5(&self, md5: &str) -> Option<(i64, &str, &str, &str)> {
        self.rows
            .iter()
            .find(|(_, m, _, _, _)| m == md5)
            .map(|(k, _, name, arch, compiler)| {
                (*k, name.as_str(), arch.as_str(), compiler.as_str())
            })
    }

    /// Get the number of rows.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
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

    #[test]
    fn sql_string_table() {
        let mut table = SQLStringTable::new("archtable", 100);
        assert!(table.is_empty());

        table.add(1, "x86");
        table.add(2, "ARM");
        table.add(3, "MIPS");

        assert_eq!(table.len(), 3);
        assert_eq!(table.get(1), Some("x86"));
        assert_eq!(table.get(2), Some("ARM"));
        assert_eq!(table.get_id("MIPS"), Some(3));
        assert_eq!(table.get(99), None);
        assert_eq!(table.get_id("unknown"), None);
    }

    #[test]
    fn key_value_table() {
        let mut table = KeyValueTable::new();
        assert!(table.is_empty());

        table.set("version", "1.0");
        table.set("owner", "admin");
        assert_eq!(table.len(), 2);

        assert_eq!(table.get("version"), Some("1.0"));
        assert_eq!(table.get("owner"), Some("admin"));
        assert_eq!(table.get("missing"), None);

        table.remove("version");
        assert_eq!(table.len(), 1);
        assert!(table.get("version").is_none());
    }

    #[test]
    fn optional_table() {
        let mut table = OptionalTable::new("test_opts");
        assert!(table.is_empty());

        table.add(1, "confidence", "0.95");
        table.add(1, "source", "decompiler");
        table.add(2, "confidence", "0.80");

        let opts = table.get_by_function(1);
        assert_eq!(opts.len(), 2);

        let opts2 = table.get_by_function(2);
        assert_eq!(opts2.len(), 1);
        assert_eq!(opts2[0].1, "0.80");
    }

    #[test]
    fn idf_lookup_table() {
        let mut table = IdfLookupTable::new();
        assert!(table.is_empty());

        table.set_weight(1, 0.5);
        table.set_weight(2, 0.8);
        assert_eq!(table.len(), 2);

        assert!((table.get_weight(1).unwrap() - 0.5).abs() < 1e-9);
        assert!((table.get_weight(2).unwrap() - 0.8).abs() < 1e-9);
        assert!(table.get_weight(3).is_none());
    }

    #[test]
    fn weight_table() {
        let mut table = WeightTable::new();
        table.add_weight(0, 0, 1.0);
        table.add_weight(0, 1, 0.5);
        table.add_weight(1, 0, 0.8);

        assert_eq!(table.len(), 3);

        let stage0 = table.get_stage_weights(0);
        assert_eq!(stage0.len(), 2);
        assert!((stage0[0].1 - 1.0).abs() < 1e-9);

        let stage1 = table.get_stage_weights(1);
        assert_eq!(stage1.len(), 1);

        let stage2 = table.get_stage_weights(2);
        assert!(stage2.is_empty());
    }

    #[test]
    fn callgraph_table() {
        let mut table = CallgraphTable::new();
        assert!(table.is_empty());

        table.add_edge(1, 2, 0x1000);
        table.add_edge(1, 3, 0x1010);
        table.add_edge(2, 3, 0x2000);

        assert_eq!(table.len(), 3);

        let callees = table.get_callees(1);
        assert_eq!(callees.len(), 2);

        let callers = table.get_callers(3);
        assert_eq!(callers.len(), 2);

        let callers2 = table.get_callers(2);
        assert_eq!(callers2.len(), 1);
        assert_eq!(callers2[0].0, 1);
    }

    #[test]
    fn description_table() {
        let mut table = DescriptionTable::new();
        assert!(table.is_empty());

        table.add(1, "main", 0x1000, 1);
        table.add(2, "foo", 0x2000, 1);
        table.add(3, "bar", 0x3000, 2);

        assert_eq!(table.len(), 3);

        let by_exe = table.get_by_exe(1);
        assert_eq!(by_exe.len(), 2);

        let by_exe2 = table.get_by_exe(2);
        assert_eq!(by_exe2.len(), 1);
        assert_eq!(by_exe2[0].1, "bar");
    }

    #[test]
    fn exe_table() {
        let mut table = ExeTable::new();
        assert!(table.is_empty());

        table.add(1, "abc123", "program1", "x86", "gcc");
        table.add(2, "def456", "program2", "ARM", "clang");

        assert_eq!(table.len(), 2);

        let entry = table.get(1).unwrap();
        assert_eq!(entry.0, "abc123");
        assert_eq!(entry.1, "program1");
        assert_eq!(entry.2, "x86");
        assert_eq!(entry.3, "gcc");

        let by_md5 = table.get_by_md5("def456").unwrap();
        assert_eq!(by_md5.0, 2);
        assert_eq!(by_md5.1, "program2");

        assert!(table.get(99).is_none());
        assert!(table.get_by_md5("unknown").is_none());
    }
}
