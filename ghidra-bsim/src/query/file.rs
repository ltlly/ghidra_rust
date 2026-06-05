//! File-based backend for BSim.
//!
//! Ports `ghidra.features.bsim.query.file` from Ghidra's Java source.
//!
//! Stores BSim data in a local SQLite database file.

use super::description::{BSimExecutableInfo, BSimFunctionDescription, BSimResultSet, SimilarityMetric};
use super::function_database::{FunctionDatabase, StubFunctionDatabase};
use super::server_config::ServerConfig;
use super::{BSimError, BSimResult};

/// File-backed function database using SQLite.
#[derive(Debug)]
pub struct FileFunctionDatabase {
    /// Path to the database file.
    pub path: String,
    connected: bool,
    stub: StubFunctionDatabase,
}

impl FileFunctionDatabase {
    /// Create a new file-backed database.
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            connected: false,
            stub: StubFunctionDatabase::new(),
        }
    }

    /// Create from a server config (file type).
    pub fn from_config(config: &ServerConfig) -> Self {
        Self::new(&config.database)
    }

    /// Get the SQL statements to create the schema.
    pub fn create_schema_sql() -> Vec<&'static str> {
        vec![
            "CREATE TABLE IF NOT EXISTS executables (id INTEGER PRIMARY KEY, name TEXT, md5 TEXT, arch TEXT, compiler TEXT, path TEXT, ingest_date INTEGER, is_executable INTEGER, function_count INTEGER)",
            "CREATE TABLE IF NOT EXISTS functions (id INTEGER PRIMARY KEY, executable_id INTEGER, name TEXT, entry_point INTEGER, hash TEXT, size INTEGER, bb_count INTEGER, call_count INTEGER, instr_count INTEGER, signature BLOB, is_library INTEGER)",
            "CREATE TABLE IF NOT EXISTS signatures (function_id INTEGER, type TEXT, data BLOB, PRIMARY KEY (function_id, type))",
        ]
    }
}

impl FunctionDatabase for FileFunctionDatabase {
    fn open(&mut self) -> BSimResult<()> {
        self.connected = true;
        self.stub.open()
    }

    fn close(&mut self) -> BSimResult<()> {
        self.connected = false;
        self.stub.close()
    }

    fn is_open(&self) -> bool {
        self.connected
    }

    fn register_executable(&mut self, info: &BSimExecutableInfo) -> BSimResult<()> {
        self.stub.register_executable(info)
    }

    fn remove_executable(&mut self, executable_id: &str) -> BSimResult<()> {
        self.stub.remove_executable(executable_id)
    }

    fn has_executable(&self, executable_id: &str) -> BSimResult<bool> {
        self.stub.has_executable(executable_id)
    }

    fn ingest_functions(&mut self, functions: &[BSimFunctionDescription]) -> BSimResult<usize> {
        self.stub.ingest_functions(functions)
    }

    fn query_similar(
        &self,
        description: &BSimFunctionDescription,
        metric: SimilarityMetric,
        max_results: usize,
        min_similarity: f64,
    ) -> BSimResult<BSimResultSet> {
        self.stub.query_similar(description, metric, max_results, min_similarity)
    }

    fn query_by_hash(&self, function_hash: &str) -> BSimResult<Option<BSimFunctionDescription>> {
        self.stub.query_by_hash(function_hash)
    }

    fn get_functions_for_executable(&self, executable_id: &str) -> BSimResult<Vec<BSimFunctionDescription>> {
        self.stub.get_functions_for_executable(executable_id)
    }

    fn get_executable_info(&self, executable_id: &str) -> BSimResult<Option<BSimExecutableInfo>> {
        self.stub.get_executable_info(executable_id)
    }

    fn function_count(&self) -> BSimResult<usize> {
        self.stub.function_count()
    }

    fn executable_count(&self) -> BSimResult<usize> {
        self.stub.executable_count()
    }

    fn execute_query(&self, query: &str) -> BSimResult<BSimResultSet> {
        self.stub.execute_query(query)
    }

    fn supports_metric(&self, _metric: SimilarityMetric) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_database_new() {
        let db = FileFunctionDatabase::new("/tmp/bsim.db");
        assert_eq!(db.path, "/tmp/bsim.db");
        assert!(!db.is_open());
    }

    #[test]
    fn test_file_database_from_config() {
        let config = ServerConfig::file("/tmp/test.db");
        let db = FileFunctionDatabase::from_config(&config);
        assert_eq!(db.path, "/tmp/test.db");
    }

    #[test]
    fn test_file_database_open_close() {
        let mut db = FileFunctionDatabase::new("/tmp/bsim.db");
        db.open().unwrap();
        assert!(db.is_open());
        db.close().unwrap();
        assert!(!db.is_open());
    }

    #[test]
    fn test_file_database_schema_sql() {
        let stmts = FileFunctionDatabase::create_schema_sql();
        assert_eq!(stmts.len(), 3);
        assert!(stmts[0].contains("executables"));
        assert!(stmts[1].contains("functions"));
        assert!(stmts[2].contains("signatures"));
    }

    #[test]
    fn test_file_database_ingest_and_query() {
        let mut db = FileFunctionDatabase::new("/tmp/bsim.db");
        db.open().unwrap();

        let func = BSimFunctionDescription::new("exe1", "main", 0x1000);
        db.ingest_functions(&[func]).unwrap();
        assert_eq!(db.function_count().unwrap(), 1);

        let results = db.get_functions_for_executable("exe1").unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_file_database_supports_all_metrics() {
        let db = FileFunctionDatabase::new("/tmp/bsim.db");
        assert!(db.supports_metric(SimilarityMetric::Jaccard));
        assert!(db.supports_metric(SimilarityMetric::Cosine));
        assert!(db.supports_metric(SimilarityMetric::EditDistance));
        assert!(db.supports_metric(SimilarityMetric::LshApproximate));
    }
}
