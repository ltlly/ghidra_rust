//! Port of `ghidra.features.bsim.gui.BSimServerManager`.
//!
//! Manages BSim server connections, caches, and server discovery.

use std::collections::HashMap;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use crate::query::bsim_server_info::BSimServerInfo;
use crate::query::server_config::ServerConfig;

/// Connection status of a BSim server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerConnectionStatus {
    /// Not yet tested.
    Unknown,
    /// Server is reachable and responsive.
    Connected,
    /// Server is unreachable or returned an error.
    Disconnected,
    /// Connection is being established.
    Connecting,
}

/// Cached information about a BSim server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCacheEntry {
    /// Server connection info.
    pub server_info: BSimServerInfo,
    /// Current connection status.
    pub status: ServerConnectionStatus,
    /// List of available databases on this server.
    pub databases: Vec<String>,
    /// Timestamp of last successful connection (Unix millis).
    pub last_connected_ms: Option<i64>,
}

/// Generates a key from the server config for indexing.
fn server_key(config: &ServerConfig) -> String {
    format!("{}:{}", config.hostname, config.port)
}

/// Manages BSim server connections and caching.
///
/// Ported from Ghidra's `BSimServerManager`.
#[derive(Debug, Default)]
pub struct BSimServerManager {
    /// Known servers indexed by hostname:port.
    servers: RwLock<HashMap<String, ServerCacheEntry>>,
}

impl BSimServerManager {
    /// Create a new server manager.
    pub fn new() -> Self {
        Self { servers: RwLock::new(HashMap::new()) }
    }

    /// Register a server.
    pub fn add_server(&self, info: BSimServerInfo) {
        let key = server_key(&info.config);
        let entry = ServerCacheEntry {
            server_info: info,
            status: ServerConnectionStatus::Unknown,
            databases: Vec::new(),
            last_connected_ms: None,
        };
        self.servers.write().unwrap().insert(key, entry);
    }

    /// Remove a server by config.
    pub fn remove_server(&self, config: &ServerConfig) -> bool {
        let key = server_key(config);
        self.servers.write().unwrap().remove(&key).is_some()
    }

    /// Get a server entry by config.
    pub fn get_server(&self, config: &ServerConfig) -> Option<ServerCacheEntry> {
        let key = server_key(config);
        self.servers.read().unwrap().get(&key).cloned()
    }

    /// Get all registered servers.
    pub fn all_servers(&self) -> Vec<ServerCacheEntry> {
        self.servers.read().unwrap().values().cloned().collect()
    }

    /// Update the connection status of a server.
    pub fn set_status(&self, config: &ServerConfig, status: ServerConnectionStatus) {
        let key = server_key(config);
        let mut servers = self.servers.write().unwrap();
        if let Some(entry) = servers.get_mut(&key) {
            entry.status = status;
            if status == ServerConnectionStatus::Connected {
                entry.last_connected_ms = Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as i64,
                );
            }
        }
    }

    /// Update the database list for a server.
    pub fn set_databases(&self, config: &ServerConfig, databases: Vec<String>) {
        let key = server_key(config);
        let mut servers = self.servers.write().unwrap();
        if let Some(entry) = servers.get_mut(&key) {
            entry.databases = databases;
        }
    }

    /// Number of registered servers.
    pub fn server_count(&self) -> usize {
        self.servers.read().unwrap().len()
    }

    /// Get connected servers only.
    pub fn connected_servers(&self) -> Vec<ServerCacheEntry> {
        self.servers.read().unwrap().values()
            .filter(|e| e.status == ServerConnectionStatus::Connected)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_server(hostname: &str, port: u16) -> BSimServerInfo {
        BSimServerInfo::new(
            hostname,
            ServerConfig {
                backend_type: "postgresql".into(),
                hostname: hostname.into(),
                port,
                database: "testdb".into(),
                username: "user".into(),
                ..Default::default()
            },
        )
    }

    #[test]
    fn test_add_and_get() {
        let mgr = BSimServerManager::new();
        mgr.add_server(sample_server("localhost", 8080));
        assert_eq!(mgr.server_count(), 1);
    }

    #[test]
    fn test_remove() {
        let mgr = BSimServerManager::new();
        let cfg = ServerConfig {
            backend_type: "postgresql".into(),
            hostname: "a".into(), port: 1,
            database: "db".into(), username: "u".into(),
            ..Default::default()
        };
        let info = BSimServerInfo::new("a", cfg.clone());
        mgr.add_server(info);
        assert!(mgr.remove_server(&cfg));
        assert_eq!(mgr.server_count(), 0);
    }

    #[test]
    fn test_set_status() {
        let mgr = BSimServerManager::new();
        let cfg = ServerConfig {
            backend_type: "postgresql".into(),
            hostname: "a".into(), port: 1,
            database: "db".into(), username: "u".into(),
            ..Default::default()
        };
        mgr.add_server(BSimServerInfo::new("a", cfg.clone()));
        mgr.set_status(&cfg, ServerConnectionStatus::Connected);
        let entry = mgr.get_server(&cfg).unwrap();
        assert_eq!(entry.status, ServerConnectionStatus::Connected);
        assert!(entry.last_connected_ms.is_some());
    }

    #[test]
    fn test_connected_servers() {
        let mgr = BSimServerManager::new();
        let cfg1 = ServerConfig { hostname: "a".into(), port: 1, ..Default::default() };
        let cfg2 = ServerConfig { hostname: "b".into(), port: 2, ..Default::default() };
        mgr.add_server(BSimServerInfo::new("a", cfg1.clone()));
        mgr.add_server(BSimServerInfo::new("b", cfg2.clone()));
        mgr.set_status(&cfg1, ServerConnectionStatus::Connected);
        assert_eq!(mgr.connected_servers().len(), 1);
    }
}
