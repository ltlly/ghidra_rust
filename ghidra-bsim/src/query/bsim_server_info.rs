//! BSim server information and connection metadata.
//!
//! Ports `ghidra.features.bsim.query.BSimServerInfo`.

use serde::{Deserialize, Serialize};

use super::server_config::ServerConfig;

/// Information about a BSim server, including its display name and configuration.
///
/// Used to persistently store server connection details in the BSim
/// server manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimServerInfo {
    /// A user-friendly name for this server.
    pub name: String,
    /// The connection configuration.
    pub config: ServerConfig,
    /// Whether this server is currently enabled.
    pub enabled: bool,
    /// Optional description.
    pub description: String,
    /// Last successful connection timestamp (Unix epoch seconds).
    pub last_connected: Option<i64>,
}

impl BSimServerInfo {
    /// Create a new server info entry.
    pub fn new(name: impl Into<String>, config: ServerConfig) -> Self {
        Self {
            name: name.into(),
            config,
            enabled: true,
            description: String::new(),
            last_connected: None,
        }
    }

    /// Set the description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Enable or disable this server.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Record a successful connection.
    pub fn record_connection(&mut self) {
        self.last_connected = Some(chrono::Utc::now().timestamp());
    }

    /// Get the connection URL string.
    pub fn connection_url(&self) -> String {
        match self.config.backend_type.as_str() {
            "postgresql" => self.config.jdbc_url(),
            "elastic" => self.config.rest_url(),
            "file" => self.config.database.clone(),
            _ => format!("{}://{}:{}", self.config.backend_type, self.config.hostname, self.config.port),
        }
    }
}

impl std::fmt::Display for BSimServerInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BSimServerInfo {{ name='{}', config={}, enabled={} }}",
            self.name, self.config, self.enabled
        )
    }
}

impl PartialEq for BSimServerInfo {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for BSimServerInfo {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_info_new() {
        let config = ServerConfig::postgresql("host", "db");
        let info = BSimServerInfo::new("My Server", config);
        assert_eq!(info.name, "My Server");
        assert!(info.enabled);
        assert!(info.description.is_empty());
        assert!(info.last_connected.is_none());
    }

    #[test]
    fn test_server_info_builder() {
        let config = ServerConfig::default();
        let info = BSimServerInfo::new("test", config)
            .with_description("A test server");
        assert_eq!(info.description, "A test server");
    }

    #[test]
    fn test_server_info_enable_disable() {
        let config = ServerConfig::default();
        let mut info = BSimServerInfo::new("test", config);
        assert!(info.enabled);
        info.set_enabled(false);
        assert!(!info.enabled);
    }

    #[test]
    fn test_server_info_record_connection() {
        let config = ServerConfig::default();
        let mut info = BSimServerInfo::new("test", config);
        assert!(info.last_connected.is_none());
        info.record_connection();
        assert!(info.last_connected.is_some());
        assert!(info.last_connected.unwrap() > 0);
    }

    #[test]
    fn test_server_info_connection_url() {
        let config = ServerConfig::postgresql("myhost", "mydb");
        let info = BSimServerInfo::new("test", config);
        let url = info.connection_url();
        assert!(url.contains("myhost:5432/mydb"));

        let config = ServerConfig::elasticsearch("es", 9200);
        let info = BSimServerInfo::new("test2", config);
        let url = info.connection_url();
        assert!(url.contains("http://es:9200"));

        let config = ServerConfig::file("/tmp/bsim.db");
        let info = BSimServerInfo::new("test3", config);
        assert_eq!(info.connection_url(), "/tmp/bsim.db");
    }

    #[test]
    fn test_server_info_display() {
        let config = ServerConfig::default();
        let info = BSimServerInfo::new("MyServer", config);
        let s = format!("{}", info);
        assert!(s.contains("MyServer"));
        assert!(s.contains("postgresql"));
    }

    #[test]
    fn test_server_info_equality() {
        let config = ServerConfig::default();
        let info1 = BSimServerInfo::new("server1", config.clone());
        let info2 = BSimServerInfo::new("server1", config.clone());
        let info3 = BSimServerInfo::new("server2", config);
        assert_eq!(info1, info2);
        assert_ne!(info1, info3);
    }
}
