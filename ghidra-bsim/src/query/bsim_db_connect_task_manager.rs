//! BSim database connection task manager.
//!
//! Ports `ghidra.features.bsim.query.BSimDBConnectTaskManager`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::query::bsim_data_source::BSimDataSource;
use crate::query::server_config::ServerConfig;

/// Connection state for a BSim database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected.
    Disconnected,
    /// Connection in progress.
    Connecting,
    /// Connected and ready.
    Connected,
    /// Connection failed.
    Failed,
}

impl Default for ConnectionState {
    fn default() -> Self {
        ConnectionState::Disconnected
    }
}

impl ConnectionState {
    /// Whether the connection is active.
    pub fn is_connected(&self) -> bool {
        matches!(self, ConnectionState::Connected)
    }

    /// Whether a connection attempt is in progress.
    pub fn is_connecting(&self) -> bool {
        matches!(self, ConnectionState::Connecting)
    }

    /// Whether the connection failed.
    pub fn is_failed(&self) -> bool {
        matches!(self, ConnectionState::Failed)
    }
}

/// A task manager for BSim database connections.
///
/// Manages the lifecycle of database connections including connection
/// pooling, reconnection, and task coordination.
///
/// Ports `ghidra.features.bsim.query.BSimDBConnectTaskManager`.
pub struct BSimDBConnectTaskManager {
    /// The data source configuration.
    data_source: BSimDataSource,
    /// Current connection state.
    state: Arc<Mutex<ConnectionState>>,
    /// Last error message.
    last_error: Arc<Mutex<Option<String>>>,
    /// Whether auto-reconnect is enabled.
    auto_reconnect: bool,
    /// Reconnect delay in milliseconds.
    reconnect_delay_ms: u64,
    /// Maximum number of reconnect attempts.
    max_reconnect_attempts: usize,
}

impl BSimDBConnectTaskManager {
    /// Create a new connection task manager.
    pub fn new(data_source: BSimDataSource) -> Self {
        Self {
            data_source,
            state: Arc::new(Mutex::new(ConnectionState::Disconnected)),
            last_error: Arc::new(Mutex::new(None)),
            auto_reconnect: true,
            reconnect_delay_ms: 5000,
            max_reconnect_attempts: 3,
        }
    }

    /// Get the current connection state.
    pub fn connection_state(&self) -> ConnectionState {
        *self.state.lock().unwrap()
    }

    /// Get the last error message.
    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().unwrap().clone()
    }

    /// Set auto-reconnect behavior.
    pub fn set_auto_reconnect(&mut self, enabled: bool) {
        self.auto_reconnect = enabled;
    }

    /// Set the reconnect delay.
    pub fn set_reconnect_delay(&mut self, delay: Duration) {
        self.reconnect_delay_ms = delay.as_millis() as u64;
    }

    /// Set the maximum reconnect attempts.
    pub fn set_max_reconnect_attempts(&mut self, max: usize) {
        self.max_reconnect_attempts = max;
    }

    /// Initiate a connection to the database.
    pub fn connect(&self) -> Result<(), String> {
        self.data_source.validate()?;

        {
            let mut state = self.state.lock().unwrap();
            *state = ConnectionState::Connecting;
        }

        // In a real implementation, this would connect to the actual database.
        // For now, we simulate a successful connection.
        {
            let mut state = self.state.lock().unwrap();
            *state = ConnectionState::Connected;
        }

        Ok(())
    }

    /// Disconnect from the database.
    pub fn disconnect(&self) {
        let mut state = self.state.lock().unwrap();
        *state = ConnectionState::Disconnected;
        let mut error = self.last_error.lock().unwrap();
        *error = None;
    }

    /// Attempt to reconnect with retry logic.
    pub fn reconnect(&self) -> Result<(), String> {
        if !self.auto_reconnect {
            return Err("Auto-reconnect is disabled".to_string());
        }

        for attempt in 0..self.max_reconnect_attempts {
            let mut state = self.state.lock().unwrap();
            *state = ConnectionState::Connecting;
            drop(state);

            match self.connect() {
                Ok(()) => return Ok(()),
                Err(e) => {
                    let mut error = self.last_error.lock().unwrap();
                    *error = Some(format!("Attempt {}/{}: {}", attempt + 1, self.max_reconnect_attempts, e));
                }
            }
        }

        let mut state = self.state.lock().unwrap();
        *state = ConnectionState::Failed;
        Err(format!(
            "Failed to reconnect after {} attempts",
            self.max_reconnect_attempts
        ))
    }

    /// Get a reference to the data source configuration.
    pub fn data_source(&self) -> &BSimDataSource {
        &self.data_source
    }

    /// Update the server config from the current data source.
    pub fn to_server_config(&self) -> ServerConfig {
        ServerConfig::postgresql(
            &self.data_source.url,
            &self.data_source.database_name,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager() -> BSimDBConnectTaskManager {
        let ds = BSimDataSource::postgresql("localhost", 5432, "testdb");
        BSimDBConnectTaskManager::new(ds)
    }

    #[test]
    fn test_initial_state() {
        let mgr = make_manager();
        assert_eq!(mgr.connection_state(), ConnectionState::Disconnected);
        assert!(mgr.last_error().is_none());
    }

    #[test]
    fn test_connection_state_transitions() {
        let state = ConnectionState::Disconnected;
        assert!(!state.is_connected());
        assert!(!state.is_connecting());
        assert!(!state.is_failed());

        let state = ConnectionState::Connecting;
        assert!(!state.is_connected());
        assert!(state.is_connecting());

        let state = ConnectionState::Connected;
        assert!(state.is_connected());

        let state = ConnectionState::Failed;
        assert!(state.is_failed());
    }

    #[test]
    fn test_connect_success() {
        let mgr = make_manager();
        let result = mgr.connect();
        assert!(result.is_ok());
        assert!(mgr.connection_state().is_connected());
    }

    #[test]
    fn test_connect_invalid_source() {
        let ds = BSimDataSource::default();
        let mgr = BSimDBConnectTaskManager::new(ds);
        let result = mgr.connect();
        assert!(result.is_err());
    }

    #[test]
    fn test_disconnect() {
        let mgr = make_manager();
        mgr.connect().unwrap();
        assert!(mgr.connection_state().is_connected());

        mgr.disconnect();
        assert_eq!(mgr.connection_state(), ConnectionState::Disconnected);
    }

    #[test]
    fn test_reconnect_disabled() {
        let mut mgr = make_manager();
        mgr.set_auto_reconnect(false);
        let result = mgr.reconnect();
        assert!(result.is_err());
    }

    #[test]
    fn test_reconnect_enabled() {
        let mgr = make_manager();
        // Should succeed since connect() simulates success
        let result = mgr.reconnect();
        assert!(result.is_ok());
        assert!(mgr.connection_state().is_connected());
    }

    #[test]
    fn test_to_server_config() {
        let mgr = make_manager();
        let config = mgr.to_server_config();
        assert_eq!(config.database, "testdb");
        assert_eq!(config.backend_type, "postgresql");
    }

    #[test]
    fn test_configuration() {
        let mut mgr = make_manager();
        mgr.set_reconnect_delay(Duration::from_secs(10));
        mgr.set_max_reconnect_attempts(5);
        assert_eq!(mgr.reconnect_delay_ms, 10000);
        assert_eq!(mgr.max_reconnect_attempts, 5);
    }
}
