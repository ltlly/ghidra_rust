//! BSim JDBC-like data source abstraction.
//!
//! Ports `ghidra.features.bsim.query.BSimJDBCDataSource`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A data source configuration for connecting to a BSim database.
///
/// In the Java code, `BSimJDBCDataSource` wraps JDBC connection parameters.
/// In Rust we abstract this into a configuration struct that can be used
/// by PostgreSQL, Elasticsearch, or file-based backends.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimDataSource {
    /// The URL or connection string for the database.
    pub url: String,
    /// The database driver type (e.g., "postgresql", "elasticsearch", "sqlite").
    pub driver: String,
    /// The database name.
    pub database_name: String,
    /// Username for authentication.
    pub username: String,
    /// Password for authentication (stored securely in practice).
    #[serde(skip_serializing)]
    pub password: Option<String>,
    /// Additional connection properties.
    pub properties: HashMap<String, String>,
    /// Connection timeout in seconds.
    pub connect_timeout_secs: u64,
    /// Query timeout in seconds.
    pub query_timeout_secs: u64,
    /// Maximum number of connections in the pool.
    pub max_pool_size: usize,
}

impl BSimDataSource {
    /// Create a new data source for PostgreSQL.
    pub fn postgresql(host: &str, port: u16, database: &str) -> Self {
        Self {
            url: format!("postgresql://{}:{}/{}", host, port, database),
            driver: "postgresql".to_string(),
            database_name: database.to_string(),
            username: String::new(),
            password: None,
            properties: HashMap::new(),
            connect_timeout_secs: 30,
            query_timeout_secs: 120,
            max_pool_size: 5,
        }
    }

    /// Create a new data source for Elasticsearch.
    pub fn elasticsearch(host: &str, port: u16, index: &str) -> Self {
        Self {
            url: format!("http://{}:{}/{}", host, port, index),
            driver: "elasticsearch".to_string(),
            database_name: index.to_string(),
            username: String::new(),
            password: None,
            properties: HashMap::new(),
            connect_timeout_secs: 30,
            query_timeout_secs: 60,
            max_pool_size: 10,
        }
    }

    /// Create a new data source for a local file database.
    pub fn file(path: &str) -> Self {
        Self {
            url: path.to_string(),
            driver: "sqlite".to_string(),
            database_name: path.to_string(),
            username: String::new(),
            password: None,
            properties: HashMap::new(),
            connect_timeout_secs: 5,
            query_timeout_secs: 30,
            max_pool_size: 1,
        }
    }

    /// Set the username.
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = username.into();
        self
    }

    /// Set the password.
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Set a connection property.
    pub fn with_property(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.properties.insert(key.into(), value.into());
        self
    }

    /// Set the connection timeout.
    pub fn with_connect_timeout(mut self, secs: u64) -> Self {
        self.connect_timeout_secs = secs;
        self
    }

    /// Set the query timeout.
    pub fn with_query_timeout(mut self, secs: u64) -> Self {
        self.query_timeout_secs = secs;
        self
    }

    /// Set the maximum pool size.
    pub fn with_max_pool_size(mut self, size: usize) -> Self {
        self.max_pool_size = size.max(1);
        self
    }

    /// Validate the data source configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.url.is_empty() {
            return Err("URL cannot be empty".to_string());
        }
        if self.driver.is_empty() {
            return Err("Driver cannot be empty".to_string());
        }
        if self.database_name.is_empty() {
            return Err("Database name cannot be empty".to_string());
        }
        Ok(())
    }

    /// Get the connection string (URL with credentials if set).
    pub fn connection_string(&self) -> String {
        if self.username.is_empty() {
            self.url.clone()
        } else if let Some(ref password) = self.password {
            format!("{}://{}:{}@{}", self.driver, self.username, password, &self.url[self.driver.len() + 3..])
        } else {
            format!("{}://{}@{}", self.driver, self.username, &self.url[self.driver.len() + 3..])
        }
    }
}

impl Default for BSimDataSource {
    fn default() -> Self {
        Self {
            url: String::new(),
            driver: String::new(),
            database_name: String::new(),
            username: String::new(),
            password: None,
            properties: HashMap::new(),
            connect_timeout_secs: 30,
            query_timeout_secs: 120,
            max_pool_size: 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_postgresql_datasource() {
        let ds = BSimDataSource::postgresql("localhost", 5432, "bsim_db");
        assert_eq!(ds.driver, "postgresql");
        assert_eq!(ds.database_name, "bsim_db");
        assert_eq!(ds.url, "postgresql://localhost:5432/bsim_db");
    }

    #[test]
    fn test_elasticsearch_datasource() {
        let ds = BSimDataSource::elasticsearch("localhost", 9200, "bsim_index");
        assert_eq!(ds.driver, "elasticsearch");
        assert_eq!(ds.database_name, "bsim_index");
    }

    #[test]
    fn test_file_datasource() {
        let ds = BSimDataSource::file("/tmp/bsim.db");
        assert_eq!(ds.driver, "sqlite");
        assert_eq!(ds.max_pool_size, 1);
    }

    #[test]
    fn test_builder_chaining() {
        let ds = BSimDataSource::postgresql("host", 5432, "db")
            .with_username("user")
            .with_password("pass")
            .with_connect_timeout(10)
            .with_query_timeout(60)
            .with_max_pool_size(3);
        assert_eq!(ds.username, "user");
        assert_eq!(ds.password, Some("pass".to_string()));
        assert_eq!(ds.connect_timeout_secs, 10);
        assert_eq!(ds.query_timeout_secs, 60);
        assert_eq!(ds.max_pool_size, 3);
    }

    #[test]
    fn test_validate_valid() {
        let ds = BSimDataSource::postgresql("localhost", 5432, "db");
        assert!(ds.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_url() {
        let ds = BSimDataSource::default();
        assert!(ds.validate().is_err());
    }

    #[test]
    fn test_validate_empty_driver() {
        let mut ds = BSimDataSource::default();
        ds.url = "some_url".to_string();
        assert!(ds.validate().is_err());
    }

    #[test]
    fn test_property_builder() {
        let ds = BSimDataSource::file("test.db")
            .with_property("sslmode", "require")
            .with_property("connect_timeout", "10");
        assert_eq!(ds.properties.len(), 2);
        assert_eq!(ds.properties.get("sslmode").unwrap(), "require");
    }

    #[test]
    fn test_serialization_roundtrip() {
        let ds = BSimDataSource::postgresql("localhost", 5432, "bsim");
        let json = serde_json::to_string(&ds).unwrap();
        let deserialized: BSimDataSource = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.url, ds.url);
        assert_eq!(deserialized.driver, ds.driver);
        assert_eq!(deserialized.database_name, ds.database_name);
        // Password should not be serialized
        assert!(deserialized.password.is_none());
    }
}
