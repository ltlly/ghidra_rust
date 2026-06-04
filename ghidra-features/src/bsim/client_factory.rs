//! BSim client factory -- Rust port of Ghidra's `BSimClientFactory`.
//!
//! Provides a unified factory for creating BSim database client connections
//! across PostgreSQL, Elasticsearch, and H2 file backends.

use serde::{Deserialize, Serialize};

use super::client::{BSimError, BSimResult, ConnectionType, DatabaseStatus, FunctionDatabase};
use super::query::{BSimServerInfo, ServerConfig};

/// The type of BSim database server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DatabaseType {
    /// PostgreSQL backend.
    Postgres,
    /// Elasticsearch backend.
    Elastic,
    /// H2 file-based database.
    H2File,
}

impl std::fmt::Display for DatabaseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Postgres => write!(f, "postgresql"),
            Self::Elastic => write!(f, "elasticsearch"),
            Self::H2File => write!(f, "h2"),
        }
    }
}

/// URL protocol prefixes accepted by BSim.
const PROTOCOL_POSTGRES: &str = "postgresql://";
const PROTOCOL_HTTPS: &str = "https://";
const PROTOCOL_HTTP: &str = "http://";
const PROTOCOL_FILE: &str = "file:/";

/// Default ports for each backend type.
pub const DEFAULT_POSTGRES_PORT: u16 = 5432;
pub const DEFAULT_ELASTIC_PORT: u16 = 9200;

/// File extension imposed for H2 file databases.
pub const H2_FILE_EXTENSION: &str = ".mv.db";

/// Factory for building and validating BSim server URLs and creating
/// database client connections.
///
/// This is the Rust equivalent of Ghidra's `BSimClientFactory`.
pub struct BSimClientFactory;

impl BSimClientFactory {
    /// Parse and validate a BSim database URL.
    ///
    /// Acceptable protocols:
    /// - `postgresql://host/repo`
    /// - `https://host/repo`
    /// - `http://host/repo`
    /// - `file:/path/to/db`
    ///
    /// # Errors
    /// Returns `BSimError::InvalidQuery` if the URL is malformed or uses
    /// an unsupported protocol.
    pub fn build_url(url_string: &str) -> BSimResult<BSimUrl> {
        let url = BSimUrl::parse(url_string)?;
        Self::check_bsim_server_url(&url)?;
        Ok(url)
    }

    /// Validate a parsed BSim server URL.
    pub fn check_bsim_server_url(url: &BSimUrl) -> BSimResult<()> {
        match url.protocol {
            BSimProtocol::Postgresql => {
                if url.path_segments.is_empty() {
                    return Err(BSimError::InvalidQuery(
                        "postgresql URL must have a path (database name)".into(),
                    ));
                }
            }
            BSimProtocol::Http | BSimProtocol::Https => {
                if url.path_segments.is_empty() {
                    return Err(BSimError::InvalidQuery(
                        "HTTP(S) URL must have a path (repository name)".into(),
                    ));
                }
            }
            BSimProtocol::File => {
                // File URLs are always valid as long as they have a path.
                if url.path.is_empty() {
                    return Err(BSimError::InvalidQuery(
                        "file URL must have a path".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Infer the database type from a URL.
    pub fn database_type_from_url(url: &BSimUrl) -> DatabaseType {
        match url.protocol {
            BSimProtocol::Postgresql => DatabaseType::Postgres,
            BSimProtocol::Http | BSimProtocol::Https => DatabaseType::Elastic,
            BSimProtocol::File => DatabaseType::H2File,
        }
    }

    /// Build a `ServerConfig` from a URL and optional credentials.
    pub fn server_config_from_url(
        url: &BSimUrl,
        username: Option<String>,
        password: Option<String>,
    ) -> ServerConfig {
        let db_type = Self::database_type_from_url(url);
        let connection_type = match db_type {
            DatabaseType::Postgres => ConnectionType::Postgresql,
            DatabaseType::Elastic => ConnectionType::Elasticsearch,
            DatabaseType::H2File => ConnectionType::H2File,
        };

        let port = url.port.unwrap_or(match db_type {
            DatabaseType::Postgres => DEFAULT_POSTGRES_PORT,
            DatabaseType::Elastic => DEFAULT_ELASTIC_PORT,
            DatabaseType::H2File => 0,
        });

        let mut config = ServerConfig::new(
            url.host.clone().unwrap_or_default(),
            port,
            connection_type,
        );

        if let Some(db) = url.database_name() {
            config = config.with_database(db);
        }
        if let Some(u) = username {
            config = config.with_username(u);
        }
        if let Some(p) = password {
            config = config.with_password(p);
        }

        config
    }

    /// Create a `BSimServerInfo` from a URL.
    pub fn server_info_from_url(url: &BSimUrl) -> BSimServerInfo {
        let config = Self::server_config_from_url(url, None, None);
        BSimServerInfo::new(config)
    }
}

// ============================================================================
// BSimProtocol
// ============================================================================

/// The URL protocol/scheme for a BSim connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BSimProtocol {
    /// `postgresql://`
    Postgresql,
    /// `https://`
    Https,
    /// `http://`
    Http,
    /// `file:/`
    File,
}

impl std::fmt::Display for BSimProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Postgresql => write!(f, "postgresql"),
            Self::Https => write!(f, "https"),
            Self::Http => write!(f, "http"),
            Self::File => write!(f, "file"),
        }
    }
}

// ============================================================================
// BSimUrl
// ============================================================================

/// A parsed BSim database URL.
///
/// Equivalent to Java's `java.net.URL` with BSim-specific validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BSimUrl {
    /// The protocol (scheme).
    pub protocol: BSimProtocol,
    /// The host (for network protocols).
    pub host: Option<String>,
    /// The port (for network protocols).
    pub port: Option<u16>,
    /// Path segments (database name, repository, etc.).
    pub path_segments: Vec<String>,
    /// The raw path string (for file:// URLs).
    pub path: String,
    /// The original URL string.
    pub raw: String,
}

impl BSimUrl {
    /// Parse a URL string into a `BSimUrl`.
    pub fn parse(url_string: &str) -> BSimResult<Self> {
        let raw = url_string.to_string();

        let (protocol, remainder) = if url_string.starts_with(PROTOCOL_POSTGRES) {
            (BSimProtocol::Postgresql, &url_string[PROTOCOL_POSTGRES.len()..])
        } else if url_string.starts_with(PROTOCOL_HTTPS) {
            (BSimProtocol::Https, &url_string[PROTOCOL_HTTPS.len()..])
        } else if url_string.starts_with(PROTOCOL_HTTP) {
            (BSimProtocol::Http, &url_string[PROTOCOL_HTTP.len()..])
        } else if url_string.starts_with(PROTOCOL_FILE) {
            (BSimProtocol::File, &url_string[PROTOCOL_FILE.len()..])
        } else {
            return Err(BSimError::InvalidQuery(format!(
                "unsupported BSim URL protocol: {}",
                url_string
            )));
        };

        match protocol {
            BSimProtocol::File => Ok(Self {
                protocol,
                host: None,
                port: None,
                path_segments: Vec::new(),
                path: remainder.to_string(),
                raw,
            }),
            _ => {
                // Parse host:port/path
                let (authority, path_str) = match remainder.find('/') {
                    Some(pos) => (&remainder[..pos], &remainder[pos + 1..]),
                    None => (remainder, ""),
                };

                let (host, port) = if let Some(colon_pos) = authority.rfind(':') {
                    let h = &authority[..colon_pos];
                    let p = authority[colon_pos + 1..].parse::<u16>().ok();
                    (Some(h.to_string()), p)
                } else {
                    (Some(authority.to_string()), None)
                };

                let path_segments: Vec<String> = path_str
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect();

                Ok(Self {
                    protocol,
                    host,
                    port,
                    path_segments,
                    path: path_str.to_string(),
                    raw,
                })
            }
        }
    }

    /// Get the database/repository name (first path segment).
    pub fn database_name(&self) -> Option<String> {
        self.path_segments.first().cloned()
    }

    /// Convert back to a URL string.
    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

impl std::fmt::Display for BSimUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.raw)
    }
}

// ============================================================================
// BSimControlLaunchable
// ============================================================================

/// Controls a BSim server instance (create, drop, manage databases).
///
/// This is the Rust equivalent of Ghidra's `BSimControlLaunchable`.
#[derive(Debug, Clone)]
pub struct BSimControlLaunchable {
    /// The server info.
    pub server_info: BSimServerInfo,
    /// Whether the control session is active.
    pub active: bool,
}

impl BSimControlLaunchable {
    /// Create a new control launchable.
    pub fn new(server_info: BSimServerInfo) -> Self {
        Self {
            server_info,
            active: false,
        }
    }

    /// Get the database type for this server.
    pub fn database_type(&self) -> DatabaseType {
        match self.server_info.config.connection_type {
            ConnectionType::Postgresql => DatabaseType::Postgres,
            ConnectionType::Elasticsearch => DatabaseType::Elastic,
            ConnectionType::H2File => DatabaseType::H2File,
            ConnectionType::InMemory => DatabaseType::H2File,
        }
    }

    /// Activate the control session.
    pub fn activate(&mut self) {
        self.active = true;
    }

    /// Deactivate the control session.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Whether the session is active.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

// ============================================================================
// BSimJdbcDataSource
// ============================================================================

/// A JDBC-compatible data source for BSim database connections.
///
/// This is the Rust equivalent of Ghidra's `BSimJDBCDataSource`.
#[derive(Debug, Clone)]
pub struct BSimJdbcDataSource {
    /// Current status.
    pub status: DatabaseStatus,
    /// The connection type.
    pub connection_type: ConnectionType,
    /// The server info.
    pub server_info: BSimServerInfo,
    /// Number of active connections in the pool.
    pub active_connections: usize,
    /// Maximum pool size.
    pub max_pool_size: usize,
}

impl BSimJdbcDataSource {
    /// Create a new JDBC data source.
    pub fn new(server_info: BSimServerInfo) -> Self {
        Self {
            status: DatabaseStatus::Disconnected,
            connection_type: server_info.config.connection_type,
            server_info,
            active_connections: 0,
            max_pool_size: 10,
        }
    }

    /// Get the current status.
    pub fn get_status(&self) -> DatabaseStatus {
        self.status
    }

    /// Get the connection type.
    pub fn get_connection_type(&self) -> ConnectionType {
        self.connection_type
    }

    /// Get the server info.
    pub fn get_server_info(&self) -> &BSimServerInfo {
        &self.server_info
    }

    /// Get the number of active connections.
    pub fn get_active_connections(&self) -> usize {
        self.active_connections
    }

    /// Set the connection status.
    pub fn set_status(&mut self, status: DatabaseStatus) {
        self.status = status;
    }

    /// Set the maximum connection pool size.
    pub fn set_max_pool_size(&mut self, size: usize) {
        self.max_pool_size = size;
    }
}

// ============================================================================
// BSimPostgresConnectionManager
// ============================================================================

/// Manages PostgreSQL connection pools for BSim.
///
/// This is the Rust equivalent of Ghidra's `BSimPostgresDBConnectionManager`.
#[derive(Debug)]
pub struct BSimPostgresConnectionManager {
    /// Active data sources keyed by server info.
    sources: std::collections::HashMap<String, BSimJdbcDataSource>,
    /// Default connection pool size.
    pool_size: usize,
}

impl BSimPostgresConnectionManager {
    /// Create a new connection manager.
    pub fn new() -> Self {
        Self {
            sources: std::collections::HashMap::new(),
            pool_size: 2,
        }
    }

    /// Get or create a data source for the given server info.
    pub fn get_or_create(&mut self, server_info: &BSimServerInfo) -> &BSimJdbcDataSource {
        let key = server_info.config.url();
        if !self.sources.contains_key(&key) {
            let mut ds = BSimJdbcDataSource::new(server_info.clone());
            ds.max_pool_size = self.pool_size;
            self.sources.insert(key.clone(), ds);
        }
        &self.sources[&key]
    }

    /// Get a mutable reference to a data source.
    pub fn get_mut(&mut self, server_info: &BSimServerInfo) -> Option<&mut BSimJdbcDataSource> {
        let key = server_info.config.url();
        self.sources.get_mut(&key)
    }

    /// Remove a data source.
    pub fn remove(&mut self, server_info: &BSimServerInfo) -> bool {
        let key = server_info.config.url();
        self.sources.remove(&key).is_some()
    }

    /// Set the default pool size for new connections.
    pub fn set_pool_size(&mut self, size: usize) {
        self.pool_size = size;
    }

    /// Number of active data sources.
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }
}

impl Default for BSimPostgresConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SQLFunctionDatabase
// ============================================================================

/// SQL-specific extensions for BSim function databases.
///
/// This is the Rust equivalent of Ghidra's `SQLFunctionDatabase` interface.
pub trait SqlFunctionDatabase: FunctionDatabase {
    /// Generate SQL bitwise-AND syntax for use in a database query WHERE clause.
    ///
    /// # Arguments
    /// * `v1` - First value expression
    /// * `v2` - Second value expression
    ///
    /// # Returns
    /// SQL expression string for bitwise AND.
    fn format_bit_and_sql(&self, v1: &str, v2: &str) -> String {
        format!("({} & {})", v1, v2)
    }
}

// ============================================================================
// BsimPluginPackage
// ============================================================================

/// Plugin package metadata for the BSim feature.
///
/// This is the Rust equivalent of Ghidra's `BsimPluginPackage`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BsimPluginPackage {
    /// Package name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Priority level.
    pub priority: u32,
}

impl BsimPluginPackage {
    /// The standard BSim plugin package name.
    pub const NAME: &'static str = "BSim";

    /// Create the default BSim plugin package.
    pub fn new() -> Self {
        Self {
            name: Self::NAME.to_string(),
            description:
                "An API and set of plugins for creating, managing and accessing \
                 function by similarity"
                    .to_string(),
            priority: 0,
        }
    }
}

impl Default for BsimPluginPackage {
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
    fn test_parse_postgresql_url() {
        let url = BSimUrl::parse("postgresql://myhost/bsimdb").unwrap();
        assert_eq!(url.protocol, BSimProtocol::Postgresql);
        assert_eq!(url.host.as_deref(), Some("myhost"));
        assert_eq!(url.port, None);
        assert_eq!(url.database_name().as_deref(), Some("bsimdb"));
    }

    #[test]
    fn test_parse_postgresql_url_with_port() {
        let url = BSimUrl::parse("postgresql://myhost:5433/bsimdb").unwrap();
        assert_eq!(url.port, Some(5433));
        assert_eq!(url.database_name().as_deref(), Some("bsimdb"));
    }

    #[test]
    fn test_parse_https_url() {
        let url = BSimUrl::parse("https://elastic.host:9200/myrepo").unwrap();
        assert_eq!(url.protocol, BSimProtocol::Https);
        assert_eq!(url.host.as_deref(), Some("elastic.host"));
        assert_eq!(url.port, Some(9200));
        assert_eq!(url.database_name().as_deref(), Some("myrepo"));
    }

    #[test]
    fn test_parse_http_url() {
        let url = BSimUrl::parse("http://localhost/repo").unwrap();
        assert_eq!(url.protocol, BSimProtocol::Http);
        assert_eq!(url.host.as_deref(), Some("localhost"));
    }

    #[test]
    fn test_parse_file_url() {
        let url = BSimUrl::parse("file:/path/to/database").unwrap();
        assert_eq!(url.protocol, BSimProtocol::File);
        assert_eq!(url.path, "/path/to/database");
    }

    #[test]
    fn test_parse_unsupported_protocol() {
        let result = BSimUrl::parse("ftp://host/path");
        assert!(result.is_err());
    }

    #[test]
    fn test_build_url_valid() {
        let url = BSimClientFactory::build_url("postgresql://host/db").unwrap();
        assert_eq!(url.protocol, BSimProtocol::Postgresql);
    }

    #[test]
    fn test_check_bsim_url_no_path() {
        let url = BSimUrl::parse("postgresql://host/").unwrap();
        let result = BSimClientFactory::check_bsim_server_url(&url);
        assert!(result.is_err());
    }

    #[test]
    fn test_database_type_from_url() {
        let url = BSimUrl::parse("postgresql://host/db").unwrap();
        assert_eq!(
            BSimClientFactory::database_type_from_url(&url),
            DatabaseType::Postgres
        );

        let url = BSimUrl::parse("https://host/repo").unwrap();
        assert_eq!(
            BSimClientFactory::database_type_from_url(&url),
            DatabaseType::Elastic
        );

        let url = BSimUrl::parse("file:/path/to/db").unwrap();
        assert_eq!(
            BSimClientFactory::database_type_from_url(&url),
            DatabaseType::H2File
        );
    }

    #[test]
    fn test_server_config_from_url() {
        let url = BSimUrl::parse("postgresql://myhost:5433/bsimdb").unwrap();
        let config = BSimClientFactory::server_config_from_url(
            &url,
            Some("user".to_string()),
            Some("pass".to_string()),
        );
        assert_eq!(config.hostname, "myhost");
        assert_eq!(config.port, 5433);
        assert_eq!(config.database_name, "bsimdb");
        assert_eq!(config.username, Some("user".to_string()));
    }

    #[test]
    fn test_bsim_control_launchable() {
        let config = ServerConfig::new("localhost", 5432, ConnectionType::Postgresql);
        let info = BSimServerInfo::new(config);
        let mut ctrl = BSimControlLaunchable::new(info);
        assert!(!ctrl.is_active());
        assert_eq!(ctrl.database_type(), DatabaseType::Postgres);
        ctrl.activate();
        assert!(ctrl.is_active());
    }

    #[test]
    fn test_bsim_jdbc_data_source() {
        let config = ServerConfig::new("localhost", 5432, ConnectionType::Postgresql);
        let info = BSimServerInfo::new(config);
        let mut ds = BSimJdbcDataSource::new(info);
        assert_eq!(ds.get_status(), DatabaseStatus::Disconnected);
        ds.set_status(DatabaseStatus::Connected);
        assert_eq!(ds.get_status(), DatabaseStatus::Connected);
    }

    #[test]
    fn test_postgres_connection_manager() {
        let mut mgr = BSimPostgresConnectionManager::new();
        assert_eq!(mgr.source_count(), 0);

        let config = ServerConfig::new("localhost", 5432, ConnectionType::Postgresql);
        let info = BSimServerInfo::new(config);
        let _ds = mgr.get_or_create(&info);
        assert_eq!(mgr.source_count(), 1);

        assert!(mgr.remove(&info));
        assert_eq!(mgr.source_count(), 0);
    }

    #[test]
    fn test_sql_function_database_default_impl() {
        struct MockDb;
        impl FunctionDatabase for MockDb {
            fn status(&self) -> DatabaseStatus { DatabaseStatus::Connected }
        }
        impl SqlFunctionDatabase for MockDb {}

        let db = MockDb;
        assert_eq!(db.format_bit_and_sql("a", "b"), "(a & b)");
    }

    #[test]
    fn test_bsim_plugin_package() {
        let pkg = BsimPluginPackage::new();
        assert_eq!(pkg.name, "BSim");
        assert!(pkg.description.contains("similarity"));
    }

    #[test]
    fn test_database_type_display() {
        assert_eq!(DatabaseType::Postgres.to_string(), "postgresql");
        assert_eq!(DatabaseType::Elastic.to_string(), "elasticsearch");
        assert_eq!(DatabaseType::H2File.to_string(), "h2");
    }

    #[test]
    fn test_bsim_url_display() {
        let url = BSimUrl::parse("postgresql://host/db").unwrap();
        assert_eq!(url.to_string(), "postgresql://host/db");
    }
}
