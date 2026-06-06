//! Platform plugin implementation ported from
//! ghidra.app.plugin.core.debug.platform.
//!
//! Provides platform-specific connector management.

use std::collections::HashMap;

/// A platform connector offering debug connection capabilities.
#[derive(Debug, Clone)]
pub struct PlatformConnector {
    /// Connector name (e.g., "gdb", "lldb", "dbgeng").
    pub name: String,
    /// Description.
    pub description: String,
    /// Supported architectures.
    pub architectures: Vec<String>,
    /// Whether this connector is available.
    pub available: bool,
}

impl PlatformConnector {
    /// Create a new connector.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            architectures: Vec::new(),
            available: true,
        }
    }
}

/// Registry of available platform connectors.
#[derive(Debug, Default)]
pub struct PlatformConnectorRegistry {
    connectors: HashMap<String, PlatformConnector>,
}

impl PlatformConnectorRegistry {
    /// Create a new registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a connector.
    pub fn register(&mut self, connector: PlatformConnector) {
        self.connectors.insert(connector.name.clone(), connector);
    }

    /// Get a connector by name.
    pub fn get(&self, name: &str) -> Option<&PlatformConnector> {
        self.connectors.get(name)
    }

    /// Get all available connectors.
    pub fn available_connectors(&self) -> Vec<&PlatformConnector> {
        self.connectors.values().filter(|c| c.available).collect()
    }

    /// Get all connector names.
    pub fn connector_names(&self) -> Vec<&str> {
        self.connectors.keys().map(|s| s.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connector_registry() {
        let mut registry = PlatformConnectorRegistry::new();
        registry.register(PlatformConnector::new("gdb", "GDB Remote"));
        registry.register(PlatformConnector::new("lldb", "LLDB Remote"));

        assert!(registry.get("gdb").is_some());
        assert_eq!(registry.connector_names().len(), 2);
        assert_eq!(registry.available_connectors().len(), 2);
    }

    #[test]
    fn test_unavailable_connector() {
        let mut registry = PlatformConnectorRegistry::new();
        let mut conn = PlatformConnector::new("old", "Old connector");
        conn.available = false;
        registry.register(conn);
        assert_eq!(registry.available_connectors().len(), 0);
    }
}
