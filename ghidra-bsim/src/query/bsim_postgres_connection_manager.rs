//! BSim PostgreSQL connection manager.
//!
//! Ports `ghidra.features.bsim.query.BSimPostgresDBConnectionManager`.

use std::sync::{Arc, Mutex};
use std::collections::HashMap;

use crate::query::bsim_data_source::BSimDataSource;
use crate::query::server_config::ServerConfig;

/// Pool statistics for a connection pool.
#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    /// Number of active connections.
    pub active_connections: usize,
    /// Number of idle connections.
    pub idle_connections: usize,
    /// Total connections created.
    pub total_created: u64,
    /// Total connections closed.
    pub total_closed: u64,
    /// Total queries executed.
    pub total_queries: u64,
    /// Number of failed connection attempts.
    pub failed_connections: u64,
}

/// A PostgreSQL connection pool manager for BSim.
///
/// Manages a pool of PostgreSQL connections for BSim database operations.
/// This class handles connection creation, validation, and lifecycle management.
///
/// Ports `ghidra.features.bsim.query.BSimPostgresDBConnectionManager`.
pub struct BSimPostgresConnectionManager {
    /// Data source configuration.
    data_source: BSimDataSource,
    /// Pool configuration.
    min_pool_size: usize,
    max_pool_size: usize,
    /// Idle timeout in seconds.
    idle_timeout_secs: u64,
    /// Whether the pool is initialized.
    initialized: Arc<Mutex<bool>>,
    /// Pool statistics.
    stats: Arc<Mutex<PoolStats>>,
    /// Cached prepared statement names.
    prepared_statements: Arc<Mutex<HashMap<String, String>>>,
}

impl BSimPostgresConnectionManager {
    /// Create a new PostgreSQL connection manager.
    pub fn new(data_source: BSimDataSource) -> Self {
        let max = data_source.max_pool_size;
        Self {
            data_source,
            min_pool_size: 1,
            max_pool_size: max,
            idle_timeout_secs: 300,
            initialized: Arc::new(Mutex::new(false)),
            stats: Arc::new(Mutex::new(PoolStats::default())),
            prepared_statements: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Set the minimum pool size.
    pub fn with_min_pool_size(mut self, size: usize) -> Self {
        self.min_pool_size = size.max(0);
        self
    }

    /// Set the maximum pool size.
    pub fn with_max_pool_size(mut self, size: usize) -> Self {
        self.max_pool_size = size.max(1);
        self
    }

    /// Set the idle timeout.
    pub fn with_idle_timeout(mut self, secs: u64) -> Self {
        self.idle_timeout_secs = secs;
        self
    }

    /// Initialize the connection pool.
    pub fn initialize(&self) -> Result<(), String> {
        self.data_source.validate()?;

        let mut initialized = self.initialized.lock().unwrap();
        if *initialized {
            return Ok(());
        }

        // In a real implementation, this would create the initial connections.
        let mut stats = self.stats.lock().unwrap();
        stats.active_connections = self.min_pool_size;
        stats.total_created = self.min_pool_size as u64;

        *initialized = true;
        Ok(())
    }

    /// Shut down the connection pool.
    pub fn shutdown(&self) {
        let mut initialized = self.initialized.lock().unwrap();
        if !*initialized {
            return;
        }

        let mut stats = self.stats.lock().unwrap();
        let total = stats.active_connections + stats.idle_connections;
        stats.total_closed += total as u64;
        stats.active_connections = 0;
        stats.idle_connections = 0;
        *initialized = false;
    }

    /// Check if the pool is initialized.
    pub fn is_initialized(&self) -> bool {
        *self.initialized.lock().unwrap()
    }

    /// Get pool statistics.
    pub fn stats(&self) -> PoolStats {
        self.stats.lock().unwrap().clone()
    }

    /// Register a prepared statement for reuse.
    pub fn register_prepared_statement(&self, name: &str, sql: &str) {
        let mut stmts = self.prepared_statements.lock().unwrap();
        stmts.insert(name.to_string(), sql.to_string());
    }

    /// Get a registered prepared statement's SQL.
    pub fn get_prepared_statement(&self, name: &str) -> Option<String> {
        self.prepared_statements.lock().unwrap().get(name).cloned()
    }

    /// Execute a SQL statement (simulated).
    pub fn execute(&self, sql: &str) -> Result<usize, String> {
        if !self.is_initialized() {
            return Err("Pool not initialized".to_string());
        }

        let mut stats = self.stats.lock().unwrap();
        stats.total_queries += 1;

        // Simulate execution: return row count
        if sql.trim_start().to_uppercase().starts_with("SELECT") {
            Ok(0) // SELECT returns result set
        } else {
            Ok(1) // INSERT/UPDATE/DELETE returns affected rows
        }
    }

    /// Get a reference to the data source.
    pub fn data_source(&self) -> &BSimDataSource {
        &self.data_source
    }

    /// Build a server config from this manager.
    pub fn to_server_config(&self) -> ServerConfig {
        ServerConfig::postgresql(
            &self.data_source.url,
            &self.data_source.database_name,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager() -> BSimPostgresConnectionManager {
        let ds = BSimDataSource::postgresql("localhost", 5432, "bsim_db")
            .with_username("bsim_user")
            .with_password("bsim_pass");
        BSimPostgresConnectionManager::new(ds)
            .with_min_pool_size(2)
            .with_max_pool_size(10)
    }

    #[test]
    fn test_manager_creation() {
        let mgr = make_manager();
        assert!(!mgr.is_initialized());
        assert_eq!(mgr.min_pool_size, 2);
        assert_eq!(mgr.max_pool_size, 10);
    }

    #[test]
    fn test_initialize() {
        let mgr = make_manager();
        let result = mgr.initialize();
        assert!(result.is_ok());
        assert!(mgr.is_initialized());

        let stats = mgr.stats();
        assert_eq!(stats.active_connections, 2);
        assert_eq!(stats.total_created, 2);
    }

    #[test]
    fn test_initialize_idempotent() {
        let mgr = make_manager();
        mgr.initialize().unwrap();
        mgr.initialize().unwrap(); // Should not error
        assert!(mgr.is_initialized());
    }

    #[test]
    fn test_initialize_invalid_source() {
        let ds = BSimDataSource::default();
        let mgr = BSimPostgresConnectionManager::new(ds);
        let result = mgr.initialize();
        assert!(result.is_err());
    }

    #[test]
    fn test_shutdown() {
        let mgr = make_manager();
        mgr.initialize().unwrap();
        assert!(mgr.is_initialized());

        mgr.shutdown();
        assert!(!mgr.is_initialized());

        let stats = mgr.stats();
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.idle_connections, 0);
    }

    #[test]
    fn test_shutdown_when_not_initialized() {
        let mgr = make_manager();
        mgr.shutdown(); // Should not panic
    }

    #[test]
    fn test_execute() {
        let mgr = make_manager();
        assert!(mgr.execute("SELECT 1").is_err()); // Not initialized

        mgr.initialize().unwrap();
        assert!(mgr.execute("SELECT 1").is_ok());
        assert!(mgr.execute("INSERT INTO foo VALUES (1)").is_ok());

        let stats = mgr.stats();
        assert_eq!(stats.total_queries, 2);
    }

    #[test]
    fn test_prepared_statements() {
        let mgr = make_manager();
        mgr.register_prepared_statement(
            "find_function",
            "SELECT * FROM functions WHERE name = $1",
        );
        let sql = mgr.get_prepared_statement("find_function");
        assert!(sql.is_some());
        assert!(sql.unwrap().contains("SELECT"));

        assert!(mgr.get_prepared_statement("nonexistent").is_none());
    }

    #[test]
    fn test_to_server_config() {
        let mgr = make_manager();
        let config = mgr.to_server_config();
        assert_eq!(config.database, "bsim_db");
        assert_eq!(config.backend_type, "postgresql");
    }

    #[test]
    fn test_builder_chain() {
        let ds = BSimDataSource::file("test.db");
        let mgr = BSimPostgresConnectionManager::new(ds)
            .with_min_pool_size(0)
            .with_max_pool_size(1)
            .with_idle_timeout(60);
        assert_eq!(mgr.min_pool_size, 0);
        assert_eq!(mgr.max_pool_size, 1);
        assert_eq!(mgr.idle_timeout_secs, 60);
    }
}
