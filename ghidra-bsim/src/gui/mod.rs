//! BSim GUI components.
//!
//! Ports `ghidra.features.bsim.gui` from Ghidra's Java source.

pub mod filters;
pub mod overview;
pub mod search;

/// BSim search configuration.
#[derive(Debug, Clone)]
pub struct BSimSearchConfig {
    /// Server name to connect to.
    pub server_name: String,
    /// Database name to search.
    pub database_name: String,
    /// Maximum number of results.
    pub max_results: usize,
    /// Minimum similarity threshold.
    pub min_similarity: f64,
    /// Active filters.
    pub filters: Vec<String>,
}

impl Default for BSimSearchConfig {
    fn default() -> Self {
        Self {
            server_name: String::new(),
            database_name: String::new(),
            max_results: 100,
            min_similarity: 0.5,
            filters: Vec::new(),
        }
    }
}

impl BSimSearchConfig {
    /// Create a new search config.
    pub fn new(server_name: impl Into<String>, database_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            database_name: database_name.into(),
            ..Default::default()
        }
    }
}

/// BSim server manager for the GUI.
///
/// Manages the list of known BSim servers and their connection state.
#[derive(Debug, Clone)]
pub struct BSimServerManager {
    /// Known servers.
    pub servers: Vec<super::query::bsim_server_info::BSimServerInfo>,
    /// Currently active server index.
    pub active_index: Option<usize>,
}

impl BSimServerManager {
    /// Create a new server manager.
    pub fn new() -> Self {
        Self {
            servers: Vec::new(),
            active_index: None,
        }
    }

    /// Add a server.
    pub fn add_server(&mut self, server: super::query::bsim_server_info::BSimServerInfo) {
        self.servers.push(server);
    }

    /// Remove a server by name.
    pub fn remove_server(&mut self, name: &str) {
        self.servers.retain(|s| s.name != name);
        self.active_index = None;
    }

    /// Get the active server.
    pub fn active_server(&self) -> Option<&super::query::bsim_server_info::BSimServerInfo> {
        self.active_index.and_then(|i| self.servers.get(i))
    }

    /// Set the active server by name.
    pub fn set_active(&mut self, name: &str) {
        self.active_index = self.servers.iter().position(|s| s.name == name);
    }

    /// Get the number of servers.
    pub fn server_count(&self) -> usize {
        self.servers.len()
    }
}

impl Default for BSimServerManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_config_default() {
        let config = BSimSearchConfig::default();
        assert_eq!(config.max_results, 100);
        assert!((config.min_similarity - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_search_config_new() {
        let config = BSimSearchConfig::new("MyServer", "MyDB");
        assert_eq!(config.server_name, "MyServer");
        assert_eq!(config.database_name, "MyDB");
    }

    #[test]
    fn test_server_manager() {
        let mut mgr = BSimServerManager::new();
        assert_eq!(mgr.server_count(), 0);
        assert!(mgr.active_server().is_none());

        let server = super::super::query::bsim_server_info::BSimServerInfo::new(
            "server1",
            super::super::query::server_config::ServerConfig::default(),
        );
        mgr.add_server(server);
        assert_eq!(mgr.server_count(), 1);

        mgr.set_active("server1");
        assert!(mgr.active_server().is_some());
        assert_eq!(mgr.active_server().unwrap().name, "server1");

        mgr.remove_server("server1");
        assert_eq!(mgr.server_count(), 0);
    }
}
