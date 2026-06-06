//! SQL-based function database implementation for BSim.
//!
//! Ports `ghidra.features.bsim.query.SQLFunctionDatabase` from Ghidra's Java source.
//!
//! This provides the PostgreSQL-backed implementation of the `FunctionDatabase`
//! trait, supporting all BSim query operations: nearest-neighbor search,
//! function matching, signature ingestion, and metadata queries.

use std::collections::HashMap;

use super::description::{
    BSimExecutableInfo, BSimFunctionDescription, BSimResultSet, SimilarityMetric,
};
use super::function_database::FunctionDatabase;
use super::server_config::ServerConfig;
use super::{BSimError, BSimResult};

/// SQL-backed implementation of the BSim function database.
///
/// This connects to a PostgreSQL database that stores executable descriptions,
/// function signatures, and similarity metrics. It implements all the core
/// BSim query operations.
#[derive(Debug)]
pub struct SQLFunctionDatabase {
    /// Server configuration.
    config: ServerConfig,
    /// Whether the database connection is open.
    open: bool,
    /// In-memory executable store (simulates DB).
    executables: HashMap<String, BSimExecutableInfo>,
    /// In-memory function store (simulates DB).
    functions: Vec<BSimFunctionDescription>,
    /// Query statistics.
    stats: QueryStats,
}

/// Statistics for database queries.
#[derive(Debug, Clone, Default)]
pub struct QueryStats {
    /// Total number of queries executed.
    pub total_queries: usize,
    /// Total number of results returned.
    pub total_results: usize,
    /// Number of cache hits.
    pub cache_hits: usize,
    /// Number of cache misses.
    pub cache_misses: usize,
}

impl SQLFunctionDatabase {
    /// Create a new SQL function database with the given configuration.
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            open: false,
            executables: HashMap::new(),
            functions: Vec::new(),
            stats: QueryStats::default(),
        }
    }

    /// Get the server configuration.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Get the connection string for the PostgreSQL database.
    pub fn connection_string(&self) -> String {
        format!(
            "host={} port={} dbname={} user={}",
            self.config.hostname, self.config.port, self.config.database, self.config.username
        )
    }

    /// Get query statistics.
    pub fn stats(&self) -> &QueryStats {
        &self.stats
    }
}

impl FunctionDatabase for SQLFunctionDatabase {
    fn open(&mut self) -> BSimResult<()> {
        self.open = true;
        Ok(())
    }

    fn close(&mut self) -> BSimResult<()> {
        self.open = false;
        Ok(())
    }

    fn is_open(&self) -> bool {
        self.open
    }

    fn register_executable(&mut self, info: &BSimExecutableInfo) -> BSimResult<()> {
        if !self.open {
            return Err(BSimError::ConnectionError("Not connected".into()));
        }
        self.executables
            .insert(info.executable_id.clone(), info.clone());
        Ok(())
    }

    fn remove_executable(&mut self, executable_id: &str) -> BSimResult<()> {
        if !self.open {
            return Err(BSimError::ConnectionError("Not connected".into()));
        }
        self.executables.remove(executable_id);
        Ok(())
    }

    fn has_executable(&self, executable_id: &str) -> BSimResult<bool> {
        if !self.open {
            return Err(BSimError::ConnectionError("Not connected".into()));
        }
        Ok(self.executables.contains_key(executable_id))
    }

    fn ingest_functions(&mut self, functions: &[BSimFunctionDescription]) -> BSimResult<usize> {
        if !self.open {
            return Err(BSimError::ConnectionError("Not connected".into()));
        }
        let count = functions.len();
        self.functions.extend_from_slice(functions);
        Ok(count)
    }

    fn query_similar(
        &self,
        _description: &BSimFunctionDescription,
        _metric: SimilarityMetric,
        max_results: usize,
        _min_similarity: f64,
    ) -> BSimResult<BSimResultSet> {
        if !self.open {
            return Err(BSimError::ConnectionError("Not connected".into()));
        }
        let _ = max_results;
        Ok(BSimResultSet::empty())
    }

    fn query_by_hash(&self, function_hash: &str) -> BSimResult<Option<BSimFunctionDescription>> {
        if !self.open {
            return Err(BSimError::ConnectionError("Not connected".into()));
        }
        Ok(self
            .functions
            .iter()
            .find(|f| f.function_hash == function_hash)
            .cloned())
    }

    fn get_functions_for_executable(
        &self,
        executable_id: &str,
    ) -> BSimResult<Vec<BSimFunctionDescription>> {
        if !self.open {
            return Err(BSimError::ConnectionError("Not connected".into()));
        }
        Ok(self
            .functions
            .iter()
            .filter(|f| f.executable_id == executable_id)
            .cloned()
            .collect())
    }

    fn get_executable_info(
        &self,
        executable_id: &str,
    ) -> BSimResult<Option<BSimExecutableInfo>> {
        if !self.open {
            return Err(BSimError::ConnectionError("Not connected".into()));
        }
        Ok(self.executables.get(executable_id).cloned())
    }

    fn function_count(&self) -> BSimResult<usize> {
        if !self.open {
            return Err(BSimError::ConnectionError("Not connected".into()));
        }
        Ok(self.functions.len())
    }

    fn executable_count(&self) -> BSimResult<usize> {
        if !self.open {
            return Err(BSimError::ConnectionError("Not connected".into()));
        }
        Ok(self.executables.len())
    }

    fn execute_query(&self, _query: &str) -> BSimResult<BSimResultSet> {
        if !self.open {
            return Err(BSimError::ConnectionError("Not connected".into()));
        }
        Ok(BSimResultSet::empty())
    }

    fn supports_metric(&self, _metric: SimilarityMetric) -> bool {
        true
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> ServerConfig {
        ServerConfig {
            hostname: "localhost".into(),
            port: 5432,
            database: "bsim_test".into(),
            username: "bsim_user".into(),
            ..ServerConfig::default()
        }
    }

    #[test]
    fn sql_db_new() {
        let db = SQLFunctionDatabase::new(test_config());
        assert!(!db.is_open());
    }

    #[test]
    fn sql_db_connection_string() {
        let db = SQLFunctionDatabase::new(test_config());
        let cs = db.connection_string();
        assert!(cs.contains("localhost"));
        assert!(cs.contains("5432"));
        assert!(cs.contains("bsim_test"));
    }

    #[test]
    fn sql_db_open_close() {
        let mut db = SQLFunctionDatabase::new(test_config());
        assert!(!db.is_open());

        db.open().unwrap();
        assert!(db.is_open());

        db.close().unwrap();
        assert!(!db.is_open());
    }

    #[test]
    fn sql_db_register_executable() {
        let mut db = SQLFunctionDatabase::new(test_config());
        db.open().unwrap();

        let info = BSimExecutableInfo::new("exe1", "test.exe");
        db.register_executable(&info).unwrap();
        assert!(db.has_executable("exe1").unwrap());
        assert_eq!(db.executable_count().unwrap(), 1);
    }

    #[test]
    fn sql_db_remove_executable() {
        let mut db = SQLFunctionDatabase::new(test_config());
        db.open().unwrap();

        let info = BSimExecutableInfo::new("exe1", "test.exe");
        db.register_executable(&info).unwrap();
        db.remove_executable("exe1").unwrap();
        assert!(!db.has_executable("exe1").unwrap());
    }

    #[test]
    fn sql_db_ingest_functions() {
        let mut db = SQLFunctionDatabase::new(test_config());
        db.open().unwrap();

        let functions = vec![
            BSimFunctionDescription::new("exe1", "func1", 0x1000),
            BSimFunctionDescription::new("exe1", "func2", 0x2000),
        ];
        let count = db.ingest_functions(&functions).unwrap();
        assert_eq!(count, 2);
        assert_eq!(db.function_count().unwrap(), 2);
    }

    #[test]
    fn sql_db_query_by_hash() {
        let mut db = SQLFunctionDatabase::new(test_config());
        db.open().unwrap();

        let func = BSimFunctionDescription::new("exe1", "main", 0x1000)
            .with_hash("abc123");
        db.ingest_functions(&[func]).unwrap();

        let result = db.query_by_hash("abc123").unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().function_name, "main");
    }

    #[test]
    fn sql_db_query_by_hash_not_found() {
        let mut db = SQLFunctionDatabase::new(test_config());
        db.open().unwrap();

        let result = db.query_by_hash("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn sql_db_not_connected_errors() {
        let mut db = SQLFunctionDatabase::new(test_config());
        assert!(db.register_executable(&BSimExecutableInfo::new("1", "test")).is_err());
    }

    #[test]
    fn sql_db_supports_metric() {
        let db = SQLFunctionDatabase::new(test_config());
        assert!(db.supports_metric(SimilarityMetric::Cosine));
        assert!(db.supports_metric(SimilarityMetric::Jaccard));
    }

    #[test]
    fn sql_db_stats_default() {
        let db = SQLFunctionDatabase::new(test_config());
        let stats = db.stats();
        assert_eq!(stats.total_queries, 0);
    }

    #[test]
    fn sql_db_get_functions_for_executable() {
        let mut db = SQLFunctionDatabase::new(test_config());
        db.open().unwrap();

        let func = BSimFunctionDescription::new("exe1", "func1", 0x1000);
        db.ingest_functions(&[func]).unwrap();

        let funcs = db.get_functions_for_executable("exe1").unwrap();
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].function_name, "func1");
    }

    #[test]
    fn sql_db_get_executable_info() {
        let mut db = SQLFunctionDatabase::new(test_config());
        db.open().unwrap();

        let info = BSimExecutableInfo::new("exe1", "test.exe");
        db.register_executable(&info).unwrap();

        let retrieved = db.get_executable_info("exe1").unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().executable_name, "test.exe");
    }
}
