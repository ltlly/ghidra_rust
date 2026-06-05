//! PostgreSQL backend for BSim.
//!
//! Ports `ghidra.features.bsim.query.postgresql` and
//! `ghidra.features.bsim.query.SQLFunctionDatabase`.

use super::description::{BSimExecutableInfo, BSimFunctionDescription, BSimResultSet, SimilarityMetric};
use super::function_database::{FunctionDatabase, StubFunctionDatabase};
use super::server_config::ServerConfig;
use super::{BSimError, BSimResult};

/// PostgreSQL connection manager for BSim.
///
/// Ports `ghidra.features.bsim.query.BSimPostgresDBConnectionManager`.
#[derive(Debug)]
pub struct BSimPostgresConnectionManager {
    config: ServerConfig,
    connected: bool,
}

impl BSimPostgresConnectionManager {
    /// Create a new connection manager.
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            connected: false,
        }
    }

    /// Get the configuration.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Whether the connection manager is connected.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Connect to the PostgreSQL server.
    pub fn connect(&mut self) -> BSimResult<()> {
        // In a full implementation, this would establish a real connection.
        self.connected = true;
        Ok(())
    }

    /// Disconnect from the PostgreSQL server.
    pub fn disconnect(&mut self) {
        self.connected = false;
    }

    /// Get the SQL schema creation statements.
    pub fn schema_statements() -> Vec<&'static str> {
        vec![
            "CREATE TABLE IF NOT EXISTS executables (id SERIAL PRIMARY KEY, name VARCHAR(255), md5 VARCHAR(32), arch VARCHAR(64), compiler VARCHAR(64), path TEXT, ingest_date TIMESTAMP, is_executable BOOLEAN, function_count INTEGER)",
            "CREATE TABLE IF NOT EXISTS functions (id SERIAL PRIMARY KEY, executable_id INTEGER REFERENCES executables(id), name VARCHAR(255), entry_point BIGINT, hash VARCHAR(64), size INTEGER, bb_count INTEGER, call_count INTEGER, instr_count INTEGER, signature BYTEA, is_library BOOLEAN)",
            "CREATE TABLE IF NOT EXISTS function_signatures (function_id INTEGER REFERENCES functions(id), mnemonic_seq TEXT, pcode_flow BYTEA, constants BYTEA, cfg_hash VARCHAR(64))",
        ]
    }
}

/// The PostgreSQL-backed function database.
///
/// Ports `ghidra.features.bsim.query.SQLFunctionDatabase`.
pub struct PostgresFunctionDatabase {
    config: ServerConfig,
    connection_manager: BSimPostgresConnectionManager,
    // In a real implementation, this would hold the actual DB connection.
    stub: StubFunctionDatabase,
}

impl PostgresFunctionDatabase {
    /// Create a new PostgreSQL-backed database.
    pub fn new(config: ServerConfig) -> Self {
        let connection_manager = BSimPostgresConnectionManager::new(config.clone());
        Self {
            config,
            connection_manager,
            stub: StubFunctionDatabase::new(),
        }
    }

    /// Get the connection manager.
    pub fn connection_manager(&self) -> &BSimPostgresConnectionManager {
        &self.connection_manager
    }
}

impl std::fmt::Debug for PostgresFunctionDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresFunctionDatabase")
            .field("config", &self.config)
            .finish()
    }
}

impl FunctionDatabase for PostgresFunctionDatabase {
    fn open(&mut self) -> BSimResult<()> {
        self.connection_manager.connect()?;
        self.stub.open()
    }

    fn close(&mut self) -> BSimResult<()> {
        self.connection_manager.disconnect();
        self.stub.close()
    }

    fn is_open(&self) -> bool {
        self.connection_manager.is_connected()
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

    fn supports_metric(&self, metric: SimilarityMetric) -> bool {
        self.stub.supports_metric(metric)
    }
}

/// BSim database connection task manager.
///
/// Manages asynchronous connection attempts to BSim servers.
/// Ports `ghidra.features.bsim.query.BSimDBConnectTaskManager`.
#[derive(Debug)]
pub struct BSimDBConnectTaskManager {
    /// Whether a connection attempt is in progress.
    pub connecting: bool,
    /// Last error message from a failed connection attempt.
    pub last_error: Option<String>,
}

impl BSimDBConnectTaskManager {
    /// Create a new task manager.
    pub fn new() -> Self {
        Self {
            connecting: false,
            last_error: None,
        }
    }

    /// Start a connection attempt.
    pub fn start_connection(&mut self) {
        self.connecting = true;
        self.last_error = None;
    }

    /// Record a connection failure.
    pub fn record_failure(&mut self, error: impl Into<String>) {
        self.connecting = false;
        self.last_error = Some(error.into());
    }

    /// Record a connection success.
    pub fn record_success(&mut self) {
        self.connecting = false;
        self.last_error = None;
    }
}

impl Default for BSimDBConnectTaskManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_postgres_connection_manager() {
        let config = ServerConfig::postgresql("localhost", "bsim");
        let mut mgr = BSimPostgresConnectionManager::new(config);
        assert!(!mgr.is_connected());
        mgr.connect().unwrap();
        assert!(mgr.is_connected());
        mgr.disconnect();
        assert!(!mgr.is_connected());
    }

    #[test]
    fn test_postgres_schema_statements() {
        let stmts = BSimPostgresConnectionManager::schema_statements();
        assert_eq!(stmts.len(), 3);
        assert!(stmts[0].contains("executables"));
        assert!(stmts[1].contains("functions"));
    }

    #[test]
    fn test_postgres_function_database() {
        let config = ServerConfig::postgresql("localhost", "bsim");
        let mut db = PostgresFunctionDatabase::new(config);
        assert!(!db.is_open());
        db.open().unwrap();
        assert!(db.is_open());

        let info = BSimExecutableInfo::new("exe1", "test.exe");
        db.register_executable(&info).unwrap();
        assert!(db.has_executable("exe1").unwrap());

        db.close().unwrap();
        assert!(!db.is_open());
    }

    #[test]
    fn test_connect_task_manager() {
        let mut mgr = BSimDBConnectTaskManager::new();
        assert!(!mgr.connecting);
        assert!(mgr.last_error.is_none());

        mgr.start_connection();
        assert!(mgr.connecting);

        mgr.record_failure("timeout");
        assert!(!mgr.connecting);
        assert_eq!(mgr.last_error.as_deref(), Some("timeout"));

        mgr.start_connection();
        mgr.record_success();
        assert!(!mgr.connecting);
        assert!(mgr.last_error.is_none());
    }
}
