//! BSim server configuration.
//!
//! Ports `ghidra.features.bsim.query.ServerConfig`.

use serde::{Deserialize, Serialize};

/// Configuration for connecting to a BSim server.
///
/// Holds connection parameters for PostgreSQL or Elasticsearch backends.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// The type of backend (e.g., "postgresql", "elastic", "file").
    pub backend_type: String,
    /// Server hostname.
    pub hostname: String,
    /// Server port.
    pub port: u16,
    /// Database name.
    pub database: String,
    /// Username for authentication.
    pub username: String,
    /// Password for authentication.
    pub password: String,
    /// Whether to use SSL/TLS.
    pub use_ssl: bool,
    /// Connection timeout in seconds.
    pub timeout_secs: u32,
    /// Maximum number of connections in the pool.
    pub max_connections: u32,
}

impl ServerConfig {
    /// Create a PostgreSQL server configuration.
    pub fn postgresql(hostname: impl Into<String>, database: impl Into<String>) -> Self {
        Self {
            backend_type: "postgresql".into(),
            hostname: hostname.into(),
            port: 5432,
            database: database.into(),
            username: String::new(),
            password: String::new(),
            use_ssl: false,
            timeout_secs: 30,
            max_connections: 10,
        }
    }

    /// Create an Elasticsearch server configuration.
    pub fn elasticsearch(hostname: impl Into<String>, port: u16) -> Self {
        Self {
            backend_type: "elastic".into(),
            hostname: hostname.into(),
            port,
            database: String::new(),
            username: String::new(),
            password: String::new(),
            use_ssl: false,
            timeout_secs: 30,
            max_connections: 10,
        }
    }

    /// Create a file-based server configuration.
    pub fn file(path: impl Into<String>) -> Self {
        Self {
            backend_type: "file".into(),
            hostname: String::new(),
            port: 0,
            database: path.into(),
            username: String::new(),
            password: String::new(),
            use_ssl: false,
            timeout_secs: 30,
            max_connections: 1,
        }
    }

    /// Set the username.
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = username.into();
        self
    }

    /// Set the password.
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = password.into();
        self
    }

    /// Enable SSL.
    pub fn with_ssl(mut self, use_ssl: bool) -> Self {
        self.use_ssl = use_ssl;
        self
    }

    /// Set the timeout.
    pub fn with_timeout(mut self, timeout_secs: u32) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    /// Get the JDBC connection URL (for PostgreSQL backend).
    pub fn jdbc_url(&self) -> String {
        let protocol = if self.use_ssl { "postgresql" } else { "postgresql" };
        format!("jdbc:{}://{}:{}/{}", protocol, self.hostname, self.port, self.database)
    }

    /// Get the REST API URL (for Elasticsearch backend).
    pub fn rest_url(&self) -> String {
        let scheme = if self.use_ssl { "https" } else { "http" };
        format!("{}://{}:{}", scheme, self.hostname, self.port)
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            backend_type: "postgresql".into(),
            hostname: "localhost".into(),
            port: 5432,
            database: "bsim".into(),
            username: "bsim".into(),
            password: String::new(),
            use_ssl: false,
            timeout_secs: 30,
            max_connections: 10,
        }
    }
}

impl std::fmt::Display for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ServerConfig {{ type={}, host={}:{}, db={} }}",
            self.backend_type, self.hostname, self.port, self.database
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_postgresql_config() {
        let config = ServerConfig::postgresql("localhost", "bsim_db");
        assert_eq!(config.backend_type, "postgresql");
        assert_eq!(config.hostname, "localhost");
        assert_eq!(config.port, 5432);
        assert_eq!(config.database, "bsim_db");
    }

    #[test]
    fn test_elasticsearch_config() {
        let config = ServerConfig::elasticsearch("es-host", 9200);
        assert_eq!(config.backend_type, "elastic");
        assert_eq!(config.port, 9200);
    }

    #[test]
    fn test_file_config() {
        let config = ServerConfig::file("/path/to/bsim.db");
        assert_eq!(config.backend_type, "file");
        assert_eq!(config.database, "/path/to/bsim.db");
    }

    #[test]
    fn test_config_builder() {
        let config = ServerConfig::postgresql("host", "db")
            .with_username("user")
            .with_password("pass")
            .with_ssl(true)
            .with_timeout(60);
        assert_eq!(config.username, "user");
        assert_eq!(config.password, "pass");
        assert!(config.use_ssl);
        assert_eq!(config.timeout_secs, 60);
    }

    #[test]
    fn test_jdbc_url() {
        let config = ServerConfig::postgresql("myhost", "mydb");
        assert!(config.jdbc_url().contains("myhost:5432/mydb"));
    }

    #[test]
    fn test_rest_url() {
        let config = ServerConfig::elasticsearch("es-host", 9200);
        assert!(config.rest_url().contains("http://es-host:9200"));
    }

    #[test]
    fn test_display() {
        let config = ServerConfig::default();
        let s = format!("{}", config);
        assert!(s.contains("postgresql"));
        assert!(s.contains("localhost"));
    }
}
