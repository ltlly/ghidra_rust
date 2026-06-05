//! BSim client-side query types.
//!
//! Port of `ghidra.features.bsim.query.client`:
//! - [`AbstractSQLFunctionDatabase`]: abstract base for SQL-backed databases
//! - [`BSimJDBCDataSource`]: JDBC data source wrapper
//! - [`BSimPostgresDBConnectionManager`]: PostgreSQL connection pool

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::super::description::{ExecutableRecord, FunctionDescription};

// Re-export core client types from the parent bsim module.
pub use super::super::client::{BSimError, BSimResult, ConnectionType, FunctionDatabase};

/// Abstract base for SQL-backed BSim function databases.
///
/// Provides common operations that all SQL backends share:
/// querying functions by name, inserting signatures, and managing
/// executable metadata.
pub trait AbstractSQLFunctionDatabase {
    /// Query a function by its name and executable index.
    fn query_by_name(&self, exe_index: usize, name: &str) -> Option<FunctionDescription>;

    /// Query all functions for a given executable index.
    fn query_by_executable(&self, exe_index: usize) -> Vec<FunctionDescription>;

    /// Insert a function signature.
    fn insert_function(&mut self, func: &FunctionDescription) -> Result<(), String>;

    /// Insert an executable record.
    fn insert_executable(&mut self, exe: &ExecutableRecord) -> Result<(), String>;

    /// Delete a function by name and executable index.
    fn delete_function(&mut self, exe_index: usize, name: &str) -> Result<(), String>;

    /// Get the count of functions in the database.
    fn function_count(&self) -> usize;

    /// Get the count of executables in the database.
    fn executable_count(&self) -> usize;
}

/// JDBC data source wrapper for BSim connections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimJDBCDataSource {
    /// JDBC URL.
    pub url: String,
    /// Username.
    pub username: String,
    /// Connection properties.
    pub properties: HashMap<String, String>,
}

impl BSimJDBCDataSource {
    /// Create a new JDBC data source.
    pub fn new(url: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            username: username.into(),
            properties: HashMap::new(),
        }
    }

    /// Add a connection property.
    pub fn with_property(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.properties.insert(key.into(), value.into());
        self
    }
}

/// PostgreSQL connection pool manager for BSim.
#[derive(Debug)]
pub struct BSimPostgresDBConnectionManager {
    /// Connection URL.
    pub url: String,
    /// Maximum pool size.
    pub max_pool_size: usize,
    /// Current active connections.
    active_connections: usize,
}

impl BSimPostgresDBConnectionManager {
    /// Create a new connection manager.
    pub fn new(url: impl Into<String>, max_pool_size: usize) -> Self {
        Self {
            url: url.into(),
            max_pool_size,
            active_connections: 0,
        }
    }

    /// Get the number of active connections.
    pub fn active_connections(&self) -> usize {
        self.active_connections
    }

    /// Simulate acquiring a connection.
    pub fn acquire(&mut self) -> bool {
        if self.active_connections < self.max_pool_size {
            self.active_connections += 1;
            true
        } else {
            false
        }
    }

    /// Simulate releasing a connection.
    pub fn release(&mut self) {
        if self.active_connections > 0 {
            self.active_connections -= 1;
        }
    }
}

/// Task manager for BSim database connection lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimDBConnectTaskManager {
    /// Whether the manager is currently connected.
    pub connected: bool,
    /// Connection retry count.
    pub retry_count: u32,
    /// Maximum retries before failure.
    pub max_retries: u32,
}

impl BSimDBConnectTaskManager {
    /// Create a new task manager.
    pub fn new(max_retries: u32) -> Self {
        Self {
            connected: false,
            retry_count: 0,
            max_retries,
        }
    }

    /// Attempt to connect.
    pub fn connect(&mut self) -> bool {
        self.connected = true;
        self.connected
    }

    /// Disconnect.
    pub fn disconnect(&mut self) {
        self.connected = false;
        self.retry_count = 0;
    }
}

/// Plugin package identifier for BSim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BsimPluginPackage {
    /// Package name.
    pub name: String,
    /// Package version.
    pub version: String,
}

impl BsimPluginPackage {
    /// Create a new plugin package identifier.
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jdbc_data_source() {
        let ds = BSimJDBCDataSource::new("jdbc:postgresql://localhost/bsim", "admin")
            .with_property("ssl", "true");
        assert_eq!(ds.url, "jdbc:postgresql://localhost/bsim");
        assert_eq!(ds.properties.get("ssl"), Some(&"true".to_string()));
    }

    #[test]
    fn test_connection_manager() {
        let mut mgr = BSimPostgresDBConnectionManager::new("localhost:5432", 5);
        assert!(mgr.acquire());
        assert_eq!(mgr.active_connections(), 1);
        mgr.release();
        assert_eq!(mgr.active_connections(), 0);
    }

    #[test]
    fn test_connection_manager_pool_limit() {
        let mut mgr = BSimPostgresDBConnectionManager::new("localhost", 2);
        assert!(mgr.acquire());
        assert!(mgr.acquire());
        assert!(!mgr.acquire());
    }

    #[test]
    fn test_task_manager() {
        let mut tm = BSimDBConnectTaskManager::new(3);
        assert!(!tm.connected);
        tm.connect();
        assert!(tm.connected);
        tm.disconnect();
        assert!(!tm.connected);
    }

    #[test]
    fn test_plugin_package() {
        let pkg = BsimPluginPackage::new("bsim", "1.0.0");
        assert_eq!(pkg.name, "bsim");
    }
}
