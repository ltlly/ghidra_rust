//! Eclipse integration plugin, connection, and options.
//!
//! Ported from `ghidra.app.plugin.core.eclipse.EclipseIntegrationPlugin`,
//! `EclipseConnection`, `EclipseConnectorTask`,
//! `EclipseIntegrationOptionsPlugin`.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// EclipseIntegrationOptionsPlugin
// ---------------------------------------------------------------------------

/// Plugin for managing Eclipse integration options.
///
/// Ported from `ghidra.app.plugin.core.eclipse.EclipseIntegrationOptionsPlugin`.
#[derive(Debug, Clone)]
pub struct EclipseIntegrationOptionsPlugin {
    /// Whether Eclipse integration is enabled.
    enabled: bool,
    /// The path to the Eclipse installation.
    eclipse_path: Option<String>,
    /// The Eclipse workspace path.
    workspace_path: Option<String>,
    /// Whether to launch Eclipse on Ghidra startup.
    launch_on_startup: bool,
    /// The port for communicating with Eclipse.
    port: u16,
}

impl EclipseIntegrationOptionsPlugin {
    /// Create a new options plugin.
    pub fn new() -> Self {
        Self {
            enabled: false,
            eclipse_path: None,
            workspace_path: None,
            launch_on_startup: false,
            port: 23456,
        }
    }

    /// Whether Eclipse integration is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable Eclipse integration.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get the Eclipse path.
    pub fn eclipse_path(&self) -> Option<&str> {
        self.eclipse_path.as_deref()
    }

    /// Set the Eclipse path.
    pub fn set_eclipse_path(&mut self, path: impl Into<String>) {
        self.eclipse_path = Some(path.into());
    }

    /// Get the workspace path.
    pub fn workspace_path(&self) -> Option<&str> {
        self.workspace_path.as_deref()
    }

    /// Set the workspace path.
    pub fn set_workspace_path(&mut self, path: impl Into<String>) {
        self.workspace_path = Some(path.into());
    }

    /// Whether to launch on startup.
    pub fn launch_on_startup(&self) -> bool {
        self.launch_on_startup
    }

    /// Set launch on startup.
    pub fn set_launch_on_startup(&mut self, launch: bool) {
        self.launch_on_startup = launch;
    }

    /// Get the communication port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Set the communication port.
    pub fn set_port(&mut self, port: u16) {
        self.port = port;
    }

    /// Save the options to a state map.
    pub fn save_state(&self) -> HashMap<String, String> {
        let mut state = HashMap::new();
        state.insert("enabled".to_string(), self.enabled.to_string());
        state.insert("port".to_string(), self.port.to_string());
        state.insert(
            "launch_on_startup".to_string(),
            self.launch_on_startup.to_string(),
        );
        if let Some(ref path) = self.eclipse_path {
            state.insert("eclipse_path".to_string(), path.clone());
        }
        if let Some(ref ws) = self.workspace_path {
            state.insert("workspace_path".to_string(), ws.clone());
        }
        state
    }

    /// Load options from a state map.
    pub fn load_state(&mut self, state: &HashMap<String, String>) {
        if let Some(v) = state.get("enabled") {
            self.enabled = v == "true";
        }
        if let Some(v) = state.get("port") {
            if let Ok(p) = v.parse() {
                self.port = p;
            }
        }
        if let Some(v) = state.get("launch_on_startup") {
            self.launch_on_startup = v == "true";
        }
        if let Some(v) = state.get("eclipse_path") {
            self.eclipse_path = Some(v.clone());
        }
        if let Some(v) = state.get("workspace_path") {
            self.workspace_path = Some(v.clone());
        }
    }
}

impl Default for EclipseIntegrationOptionsPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// EclipseConnection
// ---------------------------------------------------------------------------

/// Represents a connection to an Eclipse instance.
///
/// Ported from `ghidra.app.plugin.core.eclipse.EclipseConnection`.
#[derive(Debug)]
pub struct EclipseConnection {
    /// The host address.
    host: String,
    /// The port number.
    port: u16,
    /// Whether the connection is active.
    connected: bool,
    /// The connection ID.
    id: u64,
}

impl EclipseConnection {
    /// Create a new Eclipse connection.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            connected: false,
            id: 0,
        }
    }

    /// Get the host.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Get the port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether the connection is active.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Connect (simulated).
    pub fn connect(&mut self) -> bool {
        self.connected = true;
        self.id += 1;
        true
    }

    /// Disconnect.
    pub fn disconnect(&mut self) {
        self.connected = false;
    }

    /// Get the connection ID.
    pub fn connection_id(&self) -> u64 {
        self.id
    }
}

// ---------------------------------------------------------------------------
// EclipseConnectorTask
// ---------------------------------------------------------------------------

/// Background task for connecting to Eclipse.
///
/// Ported from `ghidra.app.plugin.core.eclipse.EclipseConnectorTask`.
#[derive(Debug)]
pub struct EclipseConnectorTask {
    /// The target host.
    host: String,
    /// The target port.
    port: u16,
    /// Whether the task completed successfully.
    success: bool,
    /// Whether the task is complete.
    complete: bool,
    /// Error message.
    error: Option<String>,
}

impl EclipseConnectorTask {
    /// Create a new connector task.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            success: false,
            complete: false,
            error: None,
        }
    }

    /// Execute the task (simulated).
    pub fn execute(&mut self) {
        // In a real implementation, this would attempt a TCP connection
        self.success = true;
        self.complete = true;
    }

    /// Whether the task completed successfully.
    pub fn is_success(&self) -> bool {
        self.success
    }

    /// Whether the task is complete.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Get the error message.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eclipse_options_default() {
        let opts = EclipseIntegrationOptionsPlugin::new();
        assert!(!opts.is_enabled());
        assert_eq!(opts.port(), 23456);
        assert!(!opts.launch_on_startup());
        assert!(opts.eclipse_path().is_none());
    }

    #[test]
    fn test_eclipse_options_setters() {
        let mut opts = EclipseIntegrationOptionsPlugin::new();
        opts.set_enabled(true);
        opts.set_eclipse_path("/opt/eclipse");
        opts.set_workspace_path("/home/user/workspace");
        opts.set_launch_on_startup(true);
        opts.set_port(12345);

        assert!(opts.is_enabled());
        assert_eq!(opts.eclipse_path(), Some("/opt/eclipse"));
        assert_eq!(opts.workspace_path(), Some("/home/user/workspace"));
        assert!(opts.launch_on_startup());
        assert_eq!(opts.port(), 12345);
    }

    #[test]
    fn test_eclipse_options_save_load() {
        let mut opts = EclipseIntegrationOptionsPlugin::new();
        opts.set_enabled(true);
        opts.set_port(9999);
        opts.set_eclipse_path("/eclipse");

        let state = opts.save_state();
        assert_eq!(state.get("enabled"), Some(&"true".to_string()));
        assert_eq!(state.get("port"), Some(&"9999".to_string()));

        let mut opts2 = EclipseIntegrationOptionsPlugin::new();
        opts2.load_state(&state);
        assert!(opts2.is_enabled());
        assert_eq!(opts2.port(), 9999);
        assert_eq!(opts2.eclipse_path(), Some("/eclipse"));
    }

    #[test]
    fn test_eclipse_connection() {
        let mut conn = EclipseConnection::new("localhost", 23456);
        assert!(!conn.is_connected());
        assert_eq!(conn.host(), "localhost");
        assert_eq!(conn.port(), 23456);

        assert!(conn.connect());
        assert!(conn.is_connected());
        assert_eq!(conn.connection_id(), 1);

        conn.disconnect();
        assert!(!conn.is_connected());
    }

    #[test]
    fn test_eclipse_connector_task() {
        let mut task = EclipseConnectorTask::new("localhost", 23456);
        assert!(!task.is_complete());

        task.execute();
        assert!(task.is_complete());
        assert!(task.is_success());
        assert!(task.error().is_none());
    }
}
