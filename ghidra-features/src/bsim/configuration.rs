//! BSim configuration and connection settings.
//!
//! Ports Ghidra's `ghidra.features.bsim.query.Configuration` and
//! `ghidra.features.bsim.query.BSimServerConfig`.

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

// ============================================================================
// BSimDatabaseType
// ============================================================================

/// The type of database backend for BSim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BSimDatabaseType {
    /// PostgreSQL backend.
    PostgreSQL,
    /// Elasticsearch backend.
    ElasticSearch,
    /// H2 embedded file database.
    H2File,
    /// In-memory (testing only).
    InMemory,
}

impl BSimDatabaseType {
    /// Parse a database type from a string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "postgresql" | "postgres" | "pg" => Some(Self::PostgreSQL),
            "elasticsearch" | "elastic" | "es" => Some(Self::ElasticSearch),
            "h2" | "h2file" | "file" => Some(Self::H2File),
            "memory" | "inmemory" => Some(Self::InMemory),
            _ => None,
        }
    }

    /// The default port for this database type.
    pub fn default_port(&self) -> u16 {
        match self {
            BSimDatabaseType::PostgreSQL => 5432,
            BSimDatabaseType::ElasticSearch => 9200,
            BSimDatabaseType::H2File => 0,
            BSimDatabaseType::InMemory => 0,
        }
    }
}

impl fmt::Display for BSimDatabaseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BSimDatabaseType::PostgreSQL => write!(f, "PostgreSQL"),
            BSimDatabaseType::ElasticSearch => write!(f, "ElasticSearch"),
            BSimDatabaseType::H2File => write!(f, "H2File"),
            BSimDatabaseType::InMemory => write!(f, "InMemory"),
        }
    }
}

// ============================================================================
// BSimServerConfig
// ============================================================================

/// Connection information for a BSim database server.
///
/// Ported from `ghidra.features.bsim.query.BSimServerConfig`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimServerConfig {
    /// The database type.
    pub db_type: BSimDatabaseType,
    /// Host name or IP address.
    pub host: String,
    /// Port number.
    pub port: u16,
    /// Database or repository name.
    pub database: String,
    /// Whether to use TLS/SSL.
    pub use_ssl: bool,
    /// Path to a local H2 database file (only for H2File type).
    pub file_path: Option<PathBuf>,
}

impl BSimServerConfig {
    /// Create a new server info.
    pub fn new(
        db_type: BSimDatabaseType,
        host: impl Into<String>,
        port: u16,
        database: impl Into<String>,
    ) -> Self {
        Self {
            db_type,
            host: host.into(),
            port,
            database: database.into(),
            use_ssl: false,
            file_path: None,
        }
    }

    /// Create a PostgreSQL server info.
    pub fn postgresql(host: impl Into<String>, database: impl Into<String>) -> Self {
        Self::new(BSimDatabaseType::PostgreSQL, host, 5432, database)
    }

    /// Create an Elasticsearch server info.
    pub fn elasticsearch(host: impl Into<String>, repository: impl Into<String>) -> Self {
        Self::new(BSimDatabaseType::ElasticSearch, host, 9200, repository)
    }

    /// Create an H2 file database info.
    pub fn h2_file(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let name = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        Self {
            db_type: BSimDatabaseType::H2File,
            host: String::new(),
            port: 0,
            database: name,
            use_ssl: false,
            file_path: Some(path),
        }
    }

    /// Create an in-memory database info (for testing).
    pub fn in_memory(database: impl Into<String>) -> Self {
        Self::new(BSimDatabaseType::InMemory, "", 0, database)
    }

    /// The connection URL string.
    pub fn url(&self) -> String {
        match self.db_type {
            BSimDatabaseType::PostgreSQL => {
                let proto = if self.use_ssl { "postgresqls" } else { "postgresql" };
                format!("{}://{}:{}/{}", proto, self.host, self.port, self.database)
            }
            BSimDatabaseType::ElasticSearch => {
                let proto = if self.use_ssl { "https" } else { "http" };
                format!("{}://{}:{}", proto, self.host, self.port)
            }
            BSimDatabaseType::H2File => {
                match &self.file_path {
                    Some(p) => format!("jdbc:h2:{}", p.display()),
                    None => format!("jdbc:h2:mem:{}", self.database),
                }
            }
            BSimDatabaseType::InMemory => format!("jdbc:h2:mem:{}", self.database),
        }
    }

    /// Enable SSL.
    pub fn with_ssl(mut self) -> Self {
        self.use_ssl = true;
        self
    }
}

impl fmt::Display for BSimServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}]", self.database, self.db_type)
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Global BSim configuration.
///
/// Ported from `ghidra.features.bsim.query.Configuration`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimConfiguration {
    /// The active server info.
    pub server_info: Option<BSimServerConfig>,
    /// Maximum number of results per query.
    pub max_results: usize,
    /// Default similarity threshold.
    pub default_threshold: f64,
    /// Whether to verify TLS certificates.
    pub verify_ssl: bool,
    /// Connection timeout in seconds.
    pub connection_timeout_secs: u64,
    /// Query timeout in seconds.
    pub query_timeout_secs: u64,
    /// Maximum number of parallel decompilation threads.
    pub max_parallel_decompiles: usize,
    /// Custom properties.
    pub properties: HashMap<String, String>,
}

impl BSimConfiguration {
    /// Create a new default configuration.
    pub fn new() -> Self {
        Self {
            server_info: None,
            max_results: 100,
            default_threshold: 0.7,
            verify_ssl: true,
            connection_timeout_secs: 30,
            query_timeout_secs: 120,
            max_parallel_decompiles: 4,
            properties: HashMap::new(),
        }
    }

    /// Set the server info.
    pub fn with_server(mut self, info: BSimServerConfig) -> Self {
        self.server_info = Some(info);
        self
    }

    /// Set the maximum results.
    pub fn with_max_results(mut self, max: usize) -> Self {
        self.max_results = max;
        self
    }

    /// Set the default threshold.
    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.default_threshold = threshold;
        self
    }

    /// Get a custom property.
    pub fn get_property(&self, key: &str) -> Option<&str> {
        self.properties.get(key).map(|s| s.as_str())
    }

    /// Set a custom property.
    pub fn set_property(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.properties.insert(key.into(), value.into());
    }
}

impl Default for BSimConfiguration {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_type_from_str() {
        assert_eq!(BSimDatabaseType::from_str("postgres"), Some(BSimDatabaseType::PostgreSQL));
        assert_eq!(BSimDatabaseType::from_str("ES"), Some(BSimDatabaseType::ElasticSearch));
        assert_eq!(BSimDatabaseType::from_str("h2"), Some(BSimDatabaseType::H2File));
        assert_eq!(BSimDatabaseType::from_str("memory"), Some(BSimDatabaseType::InMemory));
        assert_eq!(BSimDatabaseType::from_str("unknown"), None);
    }

    #[test]
    fn server_info_url() {
        let info = BSimServerConfig::postgresql("localhost", "bsim_db");
        assert!(info.url().contains("localhost"));
        assert!(info.url().contains("5432"));
        assert!(info.url().contains("bsim_db"));

        let info = BSimServerConfig::elasticsearch("es-host", "repo");
        assert!(info.url().contains("http://es-host:9200"));

        let info = BSimServerConfig::h2_file("/tmp/test.db");
        assert!(info.url().contains("jdbc:h2:/tmp/test.db"));
    }

    #[test]
    fn server_info_ssl() {
        let info = BSimServerConfig::postgresql("host", "db").with_ssl();
        assert!(info.use_ssl);
        assert!(info.url().contains("postgresqls"));
    }

    #[test]
    fn configuration_defaults() {
        let config = BSimConfiguration::new();
        assert_eq!(config.max_results, 100);
        assert_eq!(config.default_threshold, 0.7);
        assert!(config.server_info.is_none());
    }

    #[test]
    fn configuration_builder() {
        let config = BSimConfiguration::new()
            .with_server(BSimServerConfig::in_memory("test"))
            .with_max_results(50)
            .with_threshold(0.9);
        assert_eq!(config.max_results, 50);
        assert!(config.server_info.is_some());
    }

    #[test]
    fn configuration_properties() {
        let mut config = BSimConfiguration::new();
        config.set_property("key1", "value1");
        assert_eq!(config.get_property("key1"), Some("value1"));
        assert_eq!(config.get_property("key2"), None);
    }
}
