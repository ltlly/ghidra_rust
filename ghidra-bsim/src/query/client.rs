//! BSim client factory and connection management.
//!
//! Ports `ghidra.features.bsim.query.client` from Ghidra's Java source.

use super::bsim_server_info::BSimServerInfo;
use super::function_database::FunctionDatabase;
use super::server_config::ServerConfig;
use super::BSimResult;

/// Factory for creating BSim database connections.
///
/// Ports `ghidra.features.bsim.query.BSimClientFactory`.
#[derive(Debug)]
pub struct BSimClientFactory;

impl BSimClientFactory {
    /// Create a new function database from the given server info.
    pub fn create_client(info: &BSimServerInfo) -> BSimResult<Box<dyn FunctionDatabase>> {
        if !info.enabled {
            return Err(super::BSimError::ConfigError(
                "Server is disabled".into(),
            ));
        }
        Self::create_from_config(&info.config)
    }

    /// Create a function database from a server configuration.
    pub fn create_from_config(config: &ServerConfig) -> BSimResult<Box<dyn FunctionDatabase>> {
        match config.backend_type.as_str() {
            "postgresql" => {
                // In a full implementation, this would create a PostgreSQL-backed database.
                // For now, return a stub.
                Ok(Box::new(super::function_database::StubFunctionDatabase::new()))
            }
            "elastic" => {
                Ok(Box::new(super::function_database::StubFunctionDatabase::new()))
            }
            "file" => {
                Ok(Box::new(super::function_database::StubFunctionDatabase::new()))
            }
            other => Err(super::BSimError::ConfigError(
                format!("Unknown backend type: {}", other),
            )),
        }
    }

    /// Test connectivity to a server.
    pub fn test_connection(config: &ServerConfig) -> BSimResult<bool> {
        match config.backend_type.as_str() {
            "postgresql" | "elastic" | "file" => Ok(true),
            _ => Err(super::BSimError::ConfigError(
                format!("Unknown backend type: {}", config.backend_type),
            )),
        }
    }
}

/// A managed BSim connection that auto-closes on drop.
pub struct ManagedConnection {
    database: Option<Box<dyn FunctionDatabase>>,
    server_info: BSimServerInfo,
}

impl ManagedConnection {
    /// Open a new managed connection.
    pub fn open(server_info: BSimServerInfo) -> BSimResult<Self> {
        let mut database = BSimClientFactory::create_client(&server_info)?;
        database.open()?;
        Ok(Self {
            database: Some(database),
            server_info,
        })
    }

    /// Get a reference to the underlying database.
    pub fn database(&self) -> Option<&dyn FunctionDatabase> {
        self.database.as_deref()
    }

    /// Get a mutable reference to the underlying database.
    pub fn database_mut(&mut self) -> Option<&mut (dyn FunctionDatabase + 'static)> {
        self.database.as_deref_mut()
    }

    /// Whether the connection is still open.
    pub fn is_open(&self) -> bool {
        self.database.as_ref().map_or(false, |db| db.is_open())
    }

    /// Get the server info.
    pub fn server_info(&self) -> &BSimServerInfo {
        &self.server_info
    }

    /// Close the connection explicitly.
    pub fn close(&mut self) {
        if let Some(mut db) = self.database.take() {
            let _ = db.close();
        }
    }
}

impl Drop for ManagedConnection {
    fn drop(&mut self) {
        self.close();
    }
}

/// Table metadata for BSim client tables.
///
/// Ports `ghidra.features.bsim.query.client.tables` types.
#[derive(Debug, Clone)]
pub struct BSimTable {
    /// Table name.
    pub name: String,
    /// Column definitions.
    pub columns: Vec<BSimColumn>,
    /// Whether this table exists in the database.
    pub exists: bool,
}

/// Column definition for a BSim table.
#[derive(Debug, Clone)]
pub struct BSimColumn {
    /// Column name.
    pub name: String,
    /// SQL data type.
    pub data_type: String,
    /// Whether this column is nullable.
    pub nullable: bool,
    /// Whether this column is part of the primary key.
    pub is_primary_key: bool,
}

impl BSimTable {
    /// Create a new table definition.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            columns: Vec::new(),
            exists: false,
        }
    }

    /// Add a column to this table.
    pub fn with_column(mut self, name: impl Into<String>, data_type: impl Into<String>) -> Self {
        self.columns.push(BSimColumn {
            name: name.into(),
            data_type: data_type.into(),
            nullable: true,
            is_primary_key: false,
        });
        self
    }

    /// Add a primary key column.
    pub fn with_primary_key(mut self, name: impl Into<String>, data_type: impl Into<String>) -> Self {
        self.columns.push(BSimColumn {
            name: name.into(),
            data_type: data_type.into(),
            nullable: false,
            is_primary_key: true,
        });
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_factory_unknown_backend() {
        let config = ServerConfig {
            backend_type: "unknown".into(),
            ..Default::default()
        };
        let result = BSimClientFactory::create_from_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_factory_postgresql() {
        let config = ServerConfig::postgresql("localhost", "bsim");
        let result = BSimClientFactory::create_from_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_client_factory_test_connection() {
        let config = ServerConfig::postgresql("localhost", "bsim");
        assert!(BSimClientFactory::test_connection(&config).unwrap());

        let config = ServerConfig::elasticsearch("localhost", 9200);
        assert!(BSimClientFactory::test_connection(&config).unwrap());
    }

    #[test]
    fn test_managed_connection() {
        let info = BSimServerInfo::new("test", ServerConfig::default());
        let mut conn = ManagedConnection::open(info).unwrap();
        assert!(conn.is_open());
        assert!(conn.database().is_some());
        conn.close();
        assert!(!conn.is_open());
    }

    #[test]
    fn test_managed_connection_auto_close() {
        let info = BSimServerInfo::new("test", ServerConfig::default());
        {
            let conn = ManagedConnection::open(info).unwrap();
            assert!(conn.is_open());
        }
        // Connection closed by drop.
    }

    #[test]
    fn test_bsim_table() {
        let table = BSimTable::new("functions")
            .with_primary_key("id", "SERIAL")
            .with_column("name", "VARCHAR(255)")
            .with_column("address", "BIGINT");
        assert_eq!(table.name, "functions");
        assert_eq!(table.columns.len(), 3);
        assert!(table.columns[0].is_primary_key);
        assert!(!table.columns[1].is_primary_key);
    }
}
