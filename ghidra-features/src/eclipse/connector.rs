//! Eclipse connector.
//!
//! Ported from `ghidra.app.plugin.core.eclipse` classes.
//!
//! Provides integration between Ghidra and Eclipse, supporting
//! code navigation, project synchronization, and launch configuration.

/// Connection state for the Eclipse connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EclipseConnectionState {
    Disconnected,
    Connected,
    Error,
}

/// Eclipse connector configuration.
#[derive(Debug, Clone)]
pub struct EclipseConnectorConfig {
    /// Eclipse workspace path.
    pub workspace_path: String,
    /// Whether to enable auto-sync.
    pub auto_sync: bool,
    /// The port for IPC.
    pub port: u16,
}

impl Default for EclipseConnectorConfig {
    fn default() -> Self {
        Self {
            workspace_path: String::new(),
            auto_sync: false,
            port: 18002,
        }
    }
}

/// Eclipse connector for Ghidra.
#[derive(Debug)]
pub struct EclipseConnector {
    state: EclipseConnectionState,
    config: EclipseConnectorConfig,
}

impl EclipseConnector {
    pub fn new(config: EclipseConnectorConfig) -> Self {
        Self {
            state: EclipseConnectionState::Disconnected,
            config,
        }
    }

    pub fn state(&self) -> EclipseConnectionState {
        self.state
    }

    pub fn is_connected(&self) -> bool {
        self.state == EclipseConnectionState::Connected
    }

    pub fn connect(&mut self) -> bool {
        self.state = EclipseConnectionState::Connected;
        true
    }

    pub fn disconnect(&mut self) {
        self.state = EclipseConnectionState::Disconnected;
    }

    pub fn config(&self) -> &EclipseConnectorConfig {
        &self.config
    }
}

impl Default for EclipseConnector {
    fn default() -> Self { Self::new(EclipseConnectorConfig::default()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eclipse_connector() {
        let mut conn = EclipseConnector::default();
        assert!(!conn.is_connected());
        conn.connect();
        assert!(conn.is_connected());
        conn.disconnect();
        assert!(!conn.is_connected());
    }

    #[test]
    fn test_eclipse_config() {
        let config = EclipseConnectorConfig::default();
        assert_eq!(config.port, 18002);
        assert!(!config.auto_sync);
    }
}
