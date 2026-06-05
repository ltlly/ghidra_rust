//! VS Code connector.
//!
//! Ported from `ghidra.app.plugin.core.vscode` classes.
//!
//! Provides integration between Ghidra and VS Code, allowing
//! code navigation and editing to be synchronized between the two tools.

/// Connection state for the VS Code connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected.
    Disconnected,
    /// Connection in progress.
    Connecting,
    /// Connected to VS Code.
    Connected,
    /// Connection failed.
    Failed,
}

impl ConnectionState {
    /// Whether the state represents an active connection.
    pub fn is_active(&self) -> bool {
        *self == Self::Connected
    }

    /// Get the display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Disconnected => "Disconnected",
            Self::Connecting => "Connecting...",
            Self::Connected => "Connected",
            Self::Failed => "Connection Failed",
        }
    }
}

/// Configuration for the VS Code connector.
#[derive(Debug, Clone)]
pub struct VsCodeConnectorConfig {
    /// The port to listen on.
    pub port: u16,
    /// Whether to auto-reconnect on disconnect.
    pub auto_reconnect: bool,
    /// Maximum reconnect attempts.
    pub max_reconnect_attempts: usize,
    /// Reconnect delay in milliseconds.
    pub reconnect_delay_ms: u64,
    /// Whether to enable verbose logging.
    pub verbose: bool,
}

impl Default for VsCodeConnectorConfig {
    fn default() -> Self {
        Self {
            port: 18001,
            auto_reconnect: true,
            max_reconnect_attempts: 5,
            reconnect_delay_ms: 1000,
            verbose: false,
        }
    }
}

/// VS Code connector for Ghidra.
#[derive(Debug)]
pub struct VsCodeConnector {
    /// Current connection state.
    state: ConnectionState,
    /// Configuration.
    config: VsCodeConnectorConfig,
    /// Number of reconnect attempts made.
    reconnect_attempts: usize,
}

impl VsCodeConnector {
    pub fn new(config: VsCodeConnectorConfig) -> Self {
        Self {
            state: ConnectionState::Disconnected,
            config,
            reconnect_attempts: 0,
        }
    }

    pub fn state(&self) -> ConnectionState {
        self.state
    }

    pub fn config(&self) -> &VsCodeConnectorConfig {
        &self.config
    }

    pub fn is_connected(&self) -> bool {
        self.state.is_active()
    }

    pub fn connect(&mut self) -> bool {
        self.state = ConnectionState::Connecting;
        // Simulate connection (in a real implementation, this would
        // start a WebSocket or TCP server)
        self.state = ConnectionState::Connected;
        self.reconnect_attempts = 0;
        true
    }

    pub fn disconnect(&mut self) {
        self.state = ConnectionState::Disconnected;
    }

    pub fn reconnect(&mut self) -> bool {
        if self.reconnect_attempts >= self.config.max_reconnect_attempts {
            self.state = ConnectionState::Failed;
            return false;
        }
        self.reconnect_attempts += 1;
        self.connect()
    }
}

impl Default for VsCodeConnector {
    fn default() -> Self {
        Self::new(VsCodeConnectorConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_state() {
        assert!(!ConnectionState::Disconnected.is_active());
        assert!(ConnectionState::Connected.is_active());
        assert_eq!(ConnectionState::Failed.display_name(), "Connection Failed");
    }

    #[test]
    fn test_connector_connect() {
        let mut connector = VsCodeConnector::default();
        assert!(!connector.is_connected());
        connector.connect();
        assert!(connector.is_connected());
    }

    #[test]
    fn test_connector_disconnect() {
        let mut connector = VsCodeConnector::default();
        connector.connect();
        connector.disconnect();
        assert!(!connector.is_connected());
        assert_eq!(connector.state(), ConnectionState::Disconnected);
    }

    #[test]
    fn test_default_config() {
        let config = VsCodeConnectorConfig::default();
        assert_eq!(config.port, 18001);
        assert!(config.auto_reconnect);
        assert_eq!(config.max_reconnect_attempts, 5);
    }

    #[test]
    fn test_reconnect() {
        let mut connector = VsCodeConnector::default();
        connector.disconnect();
        assert!(connector.reconnect());
        assert!(connector.is_connected());
    }
}
