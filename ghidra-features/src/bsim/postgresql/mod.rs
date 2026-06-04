//! PostgreSQL backend for BSim.
//!
//! Ports `ghidra.features.bsim.query.postgresql` package.
//!
//! Provides a PostgreSQL-backed implementation of the BSim function
//! database, supporting remote multi-user deployments.

use serde::{Deserialize, Serialize};

/// PostgreSQL connection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresConfig {
    /// Database host.
    pub host: String,
    /// Database port.
    pub port: u16,
    /// Database name.
    pub database: String,
    /// Username.
    pub username: String,
    /// Password (should be stored securely in production).
    pub password: String,
    /// SSL mode (disable, allow, prefer, require).
    pub ssl_mode: String,
    /// Connection pool size.
    pub pool_size: u32,
    /// Connection timeout in seconds.
    pub connect_timeout_secs: u32,
}

impl Default for PostgresConfig {
    fn default() -> Self {
        Self {
            host: "localhost".to_string(),
            port: 5432,
            database: "bsim".to_string(),
            username: "bsim".to_string(),
            password: String::new(),
            ssl_mode: "prefer".to_string(),
            pool_size: 5,
            connect_timeout_secs: 30,
        }
    }
}

impl PostgresConfig {
    /// Build a JDBC-style connection URL.
    pub fn connection_url(&self) -> String {
        format!(
            "postgresql://{}:{}@{}:{}/{}?sslmode={}",
            self.username, self.password, self.host, self.port, self.database, self.ssl_mode
        )
    }
}

/// PostgreSQL database connection manager.
///
/// Manages a pool of connections to a PostgreSQL BSim database.
#[derive(Debug)]
pub struct PostgresConnectionManager {
    /// Connection configuration.
    pub config: PostgresConfig,
    /// Whether the connection is active.
    connected: bool,
}

impl PostgresConnectionManager {
    /// Create a new connection manager.
    pub fn new(config: PostgresConfig) -> Self {
        Self {
            config,
            connected: false,
        }
    }

    /// Connect to the PostgreSQL server.
    ///
    /// Returns Ok(()) on success. In a full implementation, this would
    /// establish actual database connections using a connection pool.
    pub fn connect(&mut self) -> Result<(), String> {
        // Validate configuration
        if self.config.database.is_empty() {
            return Err("Database name cannot be empty".to_string());
        }
        if self.config.host.is_empty() {
            return Err("Host cannot be empty".to_string());
        }

        // In a real implementation, establish connection pool here
        self.connected = true;
        Ok(())
    }

    /// Disconnect from the PostgreSQL server.
    pub fn disconnect(&mut self) {
        self.connected = false;
    }

    /// Check if connected.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Execute a simple query (stub).
    pub fn execute_query(&self, query: &str) -> Result<Vec<String>, String> {
        if !self.connected {
            return Err("Not connected to database".to_string());
        }
        // Stub: in production, execute against actual PostgreSQL
        Ok(vec![format!("Executed: {}", query)])
    }
}

/// The SQL table schema for BSim in PostgreSQL.
#[derive(Debug, Clone)]
pub struct BSimSchema;

impl BSimSchema {
    /// SQL to create the executable table.
    pub fn create_executable_table() -> &'static str {
        "CREATE TABLE IF NOT EXISTS executable (
            idexehash SERIAL PRIMARY KEY,
            exehash BYTEA NOT NULL UNIQUE,
            exename TEXT NOT NULL,
            architecture TEXT,
            compiler TEXT,
            category TEXT,
            md5 BYTEA,
            description TEXT,
            datesubmit TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"
    }

    /// SQL to create the function table.
    pub fn create_function_table() -> &'static str {
        "CREATE TABLE IF NOT EXISTS function (
            idfunc SERIAL PRIMARY KEY,
            idexehash INTEGER REFERENCES executable(idexehash),
            address BIGINT NOT NULL,
            funcname TEXT,
            signature BYTEA,
            numinstructions INTEGER,
            numbasicblocks INTEGER,
            numcalls INTEGER,
            md5hash BYTEA,
            mangledsig TEXT
        )"
    }

    /// SQL to create the signature vector table.
    pub fn create_signature_table() -> &'static str {
        "CREATE TABLE IF NOT EXISTS signature (
            idsig SERIAL PRIMARY KEY,
            idfunc INTEGER REFERENCES function(idfunc),
            sigtype TEXT NOT NULL,
            vector BYTEA NOT NULL,
            norm DOUBLE PRECISION
        )"
    }

    /// SQL to create the LSH (Locality-Sensitive Hashing) table.
    pub fn create_lsh_table() -> &'static str {
        "CREATE TABLE IF NOT EXISTS lsh (
            idlsh SERIAL PRIMARY KEY,
            idsig INTEGER REFERENCES signature(idsig),
            bucket INTEGER NOT NULL,
            band INTEGER NOT NULL
        )"
    }

    /// Get all table creation statements.
    pub fn all_statements() -> Vec<&'static str> {
        vec![
            Self::create_executable_table(),
            Self::create_function_table(),
            Self::create_signature_table(),
            Self::create_lsh_table(),
        ]
    }
}

/// Result of a PostgreSQL BSim query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresQueryResult {
    /// Number of matching functions found.
    pub match_count: usize,
    /// Total functions queried.
    pub total_queried: usize,
    /// Execution time in milliseconds.
    pub elapsed_ms: u64,
    /// Any warnings from the query.
    pub warnings: Vec<String>,
}

impl PostgresQueryResult {
    /// Create a new empty result.
    pub fn new() -> Self {
        Self {
            match_count: 0,
            total_queried: 0,
            elapsed_ms: 0,
            warnings: Vec::new(),
        }
    }
}

impl Default for PostgresQueryResult {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postgres_config_default() {
        let config = PostgresConfig::default();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 5432);
        assert_eq!(config.database, "bsim");
    }

    #[test]
    fn postgres_config_connection_url() {
        let config = PostgresConfig {
            host: "db.example.com".to_string(),
            port: 5433,
            database: "mydb".to_string(),
            username: "user".to_string(),
            password: "pass".to_string(),
            ssl_mode: "require".to_string(),
            ..Default::default()
        };
        let url = config.connection_url();
        assert!(url.contains("db.example.com"));
        assert!(url.contains("5433"));
        assert!(url.contains("sslmode=require"));
    }

    #[test]
    fn connection_manager_lifecycle() {
        let config = PostgresConfig::default();
        let mut manager = PostgresConnectionManager::new(config);
        assert!(!manager.is_connected());
        manager.connect().unwrap();
        assert!(manager.is_connected());
        manager.disconnect();
        assert!(!manager.is_connected());
    }

    #[test]
    fn connection_manager_empty_db_fails() {
        let config = PostgresConfig {
            database: String::new(),
            ..Default::default()
        };
        let mut manager = PostgresConnectionManager::new(config);
        assert!(manager.connect().is_err());
    }

    #[test]
    fn connection_manager_query_when_disconnected() {
        let config = PostgresConfig::default();
        let manager = PostgresConnectionManager::new(config);
        assert!(manager.execute_query("SELECT 1").is_err());
    }

    #[test]
    fn schema_statements_count() {
        let stmts = BSimSchema::all_statements();
        assert_eq!(stmts.len(), 4);
    }

    #[test]
    fn schema_statements_contain_tables() {
        let stmts = BSimSchema::all_statements();
        let all = stmts.join(" ");
        assert!(all.contains("executable"));
        assert!(all.contains("function"));
        assert!(all.contains("signature"));
        assert!(all.contains("lsh"));
    }

    #[test]
    fn query_result_default() {
        let result = PostgresQueryResult::default();
        assert_eq!(result.match_count, 0);
        assert!(result.warnings.is_empty());
    }
}
