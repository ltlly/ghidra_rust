//! Port of `BSimClientFactory`.
//!
//! Factory for creating BSim database client instances based on server configuration.

use super::server_config::ServerConfig;
use super::query_database_exception::QueryDatabaseException;

/// The type of BSim database backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BSimDatabaseType {
    /// PostgreSQL backend.
    PostgreSQL,
    /// Elasticsearch backend.
    Elasticsearch,
    /// H2 file-based database.
    H2File,
}

impl Default for BSimDatabaseType {
    fn default() -> Self {
        BSimDatabaseType::PostgreSQL
    }
}

impl std::fmt::Display for BSimDatabaseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BSimDatabaseType::PostgreSQL => write!(f, "PostgreSQL"),
            BSimDatabaseType::Elasticsearch => write!(f, "Elasticsearch"),
            BSimDatabaseType::H2File => write!(f, "H2 File"),
        }
    }
}

/// Configuration for a BSim client connection.
#[derive(Debug, Clone)]
pub struct BSimClientConfig {
    /// The type of database backend.
    pub db_type: BSimDatabaseType,
    /// The server URL or host.
    pub server_url: String,
    /// The database name.
    pub database_name: String,
    /// The port number.
    pub port: u16,
    /// Optional username.
    pub username: Option<String>,
    /// Optional password.
    pub password: Option<String>,
}

impl BSimClientConfig {
    /// Create a new client config.
    pub fn new(db_type: BSimDatabaseType, server_url: impl Into<String>, database: impl Into<String>) -> Self {
        Self {
            db_type,
            server_url: server_url.into(),
            database_name: database.into(),
            port: match db_type {
                BSimDatabaseType::PostgreSQL => 5432,
                BSimDatabaseType::Elasticsearch => 9200,
                BSimDatabaseType::H2File => 0,
            },
            username: None,
            password: None,
        }
    }

    /// Set the port number.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set the username.
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Set the password.
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }
}

/// Factory for creating BSim database client instances.
///
/// Ports `BSimClientFactory`.
#[derive(Debug, Clone)]
pub struct BSimClientFactory {
    /// Default database type when none is specified.
    default_db_type: BSimDatabaseType,
}

impl BSimClientFactory {
    /// Create a new factory with default settings.
    pub fn new() -> Self {
        Self {
            default_db_type: BSimDatabaseType::PostgreSQL,
        }
    }

    /// Create a factory with a specific default database type.
    pub fn with_default_type(db_type: BSimDatabaseType) -> Self {
        Self {
            default_db_type: db_type,
        }
    }

    /// Get the default database type.
    pub fn default_db_type(&self) -> BSimDatabaseType {
        self.default_db_type
    }

    /// Create a client config from a server configuration.
    pub fn create_config(&self, server_config: &ServerConfig) -> Result<BSimClientConfig, QueryDatabaseException> {
        let db_type = self.default_db_type;
        let url = &server_config.hostname;
        let db_name = &server_config.database;

        if url.is_empty() {
            return Err(QueryDatabaseException::new("Server URL is empty"));
        }

        let config = BSimClientConfig::new(db_type, url, db_name)
            .with_port(server_config.port);

        if !server_config.username.is_empty() {
            Ok(config.with_username(&server_config.username))
        } else {
            Ok(config)
        }
    }

    /// Validate that a client config is usable.
    pub fn validate_config(config: &BSimClientConfig) -> Result<(), QueryDatabaseException> {
        if config.server_url.is_empty() {
            return Err(QueryDatabaseException::new("Server URL is empty"));
        }
        if config.database_name.is_empty() {
            return Err(QueryDatabaseException::new("Database name is empty"));
        }
        if config.db_type == BSimDatabaseType::PostgreSQL && config.port == 0 {
            return Err(QueryDatabaseException::new("Invalid port number for PostgreSQL"));
        }
        Ok(())
    }
}

impl Default for BSimClientFactory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_b_sim_client_factory_new() {
        let factory = BSimClientFactory::new();
        assert_eq!(factory.default_db_type(), BSimDatabaseType::PostgreSQL);
    }

    #[test]
    fn test_b_sim_client_factory_with_type() {
        let factory = BSimClientFactory::with_default_type(BSimDatabaseType::Elasticsearch);
        assert_eq!(factory.default_db_type(), BSimDatabaseType::Elasticsearch);
    }

    #[test]
    fn test_bsim_client_config_creation() {
        let config = BSimClientConfig::new(BSimDatabaseType::PostgreSQL, "localhost", "bsimdb");
        assert_eq!(config.db_type, BSimDatabaseType::PostgreSQL);
        assert_eq!(config.server_url, "localhost");
        assert_eq!(config.database_name, "bsimdb");
        assert_eq!(config.port, 5432);
        assert!(config.username.is_none());
    }

    #[test]
    fn test_bsim_client_config_builder() {
        let config = BSimClientConfig::new(BSimDatabaseType::PostgreSQL, "host", "db")
            .with_port(5433)
            .with_username("admin")
            .with_password("secret");
        assert_eq!(config.port, 5433);
        assert_eq!(config.username.as_deref(), Some("admin"));
        assert_eq!(config.password.as_deref(), Some("secret"));
    }

    #[test]
    fn test_validate_config_valid() {
        let config = BSimClientConfig::new(BSimDatabaseType::PostgreSQL, "localhost", "bsim");
        assert!(BSimClientFactory::validate_config(&config).is_ok());
    }

    #[test]
    fn test_validate_config_empty_url() {
        let config = BSimClientConfig::new(BSimDatabaseType::PostgreSQL, "", "bsim");
        assert!(BSimClientFactory::validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_config_empty_db() {
        let config = BSimClientConfig::new(BSimDatabaseType::PostgreSQL, "localhost", "");
        assert!(BSimClientFactory::validate_config(&config).is_err());
    }

    #[test]
    fn test_database_type_display() {
        assert_eq!(BSimDatabaseType::PostgreSQL.to_string(), "PostgreSQL");
        assert_eq!(BSimDatabaseType::Elasticsearch.to_string(), "Elasticsearch");
        assert_eq!(BSimDatabaseType::H2File.to_string(), "H2 File");
    }

    #[test]
    fn test_database_type_default() {
        assert_eq!(BSimDatabaseType::default(), BSimDatabaseType::PostgreSQL);
    }

    #[test]
    fn test_default_ports() {
        let pg = BSimClientConfig::new(BSimDatabaseType::PostgreSQL, "h", "d");
        assert_eq!(pg.port, 5432);

        let es = BSimClientConfig::new(BSimDatabaseType::Elasticsearch, "h", "d");
        assert_eq!(es.port, 9200);

        let h2 = BSimClientConfig::new(BSimDatabaseType::H2File, "h", "d");
        assert_eq!(h2.port, 0);
    }
}
