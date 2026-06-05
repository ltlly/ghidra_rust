//! Eclipse IDE integration plugin.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.eclipse` package.
//!
//! Provides integration between Ghidra and Eclipse, allowing users to
//! edit scripts in Eclipse, look up symbols, and manage the Eclipse
//! connection.
//!
//! # Key Types
//!
//! - [`EclipseIntegrationPlugin`] -- Plugin providing Eclipse integration
//! - [`EclipseConnection`] -- Represents a connection to a running Eclipse instance
//! - [`EclipseConnectorTask`] -- Background task to connect to Eclipse
//! - [`EclipseIntegrationOptions`] -- Configuration for Eclipse integration
//! - [`EclipseIntegrationService`] -- Service trait for Eclipse operations

/// Eclipse connector for Ghidra integration.
///
/// Ported from `ghidra.app.plugin.core.eclipse` connector classes.
pub mod connector;

use std::path::PathBuf;

/// Plugin options name for Eclipse integration.
pub const PLUGIN_OPTIONS_NAME: &str = "Eclipse Integration";

/// Default port for the script editor connection.
pub const SCRIPT_EDITOR_PORT_DEFAULT: i32 = 28_282;

/// Default port for the symbol lookup connection.
pub const SYMBOL_LOOKUP_PORT_DEFAULT: i32 = 28_283;

// ---------------------------------------------------------------------------
// Eclipse integration options
// ---------------------------------------------------------------------------

/// Configuration for Eclipse integration.
///
/// Ported from `ghidra.app.plugin.core.eclipse.EclipseIntegrationOptionsPlugin`.
#[derive(Debug, Clone)]
pub struct EclipseIntegrationOptions {
    /// Path to the Eclipse installation directory.
    pub eclipse_install_dir: Option<PathBuf>,
    /// Path to the Eclipse workspace directory.
    pub eclipse_workspace_dir: Option<PathBuf>,
    /// Port for the script editor connection.
    pub script_editor_port: i32,
    /// Port for the symbol lookup connection.
    pub symbol_lookup_port: i32,
    /// Whether to auto-install GhidraDev plugin.
    pub auto_ghidra_dev_install: bool,
}

impl Default for EclipseIntegrationOptions {
    fn default() -> Self {
        Self {
            eclipse_install_dir: None,
            eclipse_workspace_dir: None,
            script_editor_port: SCRIPT_EDITOR_PORT_DEFAULT,
            symbol_lookup_port: SYMBOL_LOOKUP_PORT_DEFAULT,
            auto_ghidra_dev_install: true,
        }
    }
}

impl EclipseIntegrationOptions {
    /// Whether the Eclipse installation directory is configured.
    pub fn has_install_dir(&self) -> bool {
        self.eclipse_install_dir.is_some()
    }

    /// Get the Eclipse executable path based on the platform.
    pub fn eclipse_executable(&self) -> Option<PathBuf> {
        let dir = self.eclipse_install_dir.as_ref()?;
        let exe_name = if cfg!(target_os = "windows") {
            "eclipse.exe"
        } else if cfg!(target_os = "macos") {
            "Eclipse.app/Contents/MacOS/eclipse"
        } else {
            "eclipse"
        };
        let path = dir.join(exe_name);
        if path.exists() {
            Some(path)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Eclipse connection
// ---------------------------------------------------------------------------

/// Represents a connection to a running Eclipse instance.
///
/// Ported from `ghidra.app.plugin.core.eclipse.EclipseConnection`.
#[derive(Debug)]
pub struct EclipseConnection {
    /// The port that was connected to.
    pub port: i32,
    /// Whether the connection was successful.
    pub connected: bool,
    /// Error message if the connection failed.
    pub error: Option<String>,
}

impl EclipseConnection {
    /// Create a successful connection.
    pub fn success(port: i32) -> Self {
        Self {
            port,
            connected: true,
            error: None,
        }
    }

    /// Create a failed connection.
    pub fn failure(port: i32, error: impl Into<String>) -> Self {
        Self {
            port,
            connected: false,
            error: Some(error.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Eclipse connector task
// ---------------------------------------------------------------------------

/// Background task to establish a connection to Eclipse.
///
/// Ported from `ghidra.app.plugin.core.eclipse.EclipseConnectorTask`.
#[derive(Debug)]
pub struct EclipseConnectorTask {
    /// The target port.
    pub port: i32,
    /// Whether the connection was successful.
    pub result: Option<EclipseConnection>,
    /// Timeout in milliseconds.
    pub timeout_ms: u64,
}

impl EclipseConnectorTask {
    /// Create a new connector task.
    pub fn new(port: i32) -> Self {
        Self {
            port,
            result: None,
            timeout_ms: 5000,
        }
    }

    /// Execute the connection attempt.
    pub fn execute(&mut self) -> &EclipseConnection {
        // In a full implementation, this would try to connect to
        // localhost:port to reach Eclipse's listening socket.
        let connection = EclipseConnection::failure(
            self.port,
            format!("Eclipse not listening on port {}", self.port),
        );
        self.result = Some(connection);
        self.result.as_ref().unwrap()
    }
}

// ---------------------------------------------------------------------------
// Eclipse integration service
// ---------------------------------------------------------------------------

/// Service trait for Eclipse integration operations.
///
/// Ported from `ghidra.app.services.EclipseIntegrationService`.
pub trait EclipseIntegrationService: Send + Sync {
    /// Get the Eclipse integration options.
    fn get_options(&self) -> &EclipseIntegrationOptions;

    /// Connect to Eclipse at the given port.
    fn connect(&self, port: i32) -> EclipseConnection;

    /// Open a file in Eclipse.
    fn open_file_in_eclipse(&self, file: &std::path::Path) -> Result<(), String>;

    /// Handle an Eclipse error.
    fn handle_error(&self, message: &str, fatal: bool);
}

// ---------------------------------------------------------------------------
// Eclipse integration plugin
// ---------------------------------------------------------------------------

/// Plugin providing Eclipse-related services.
///
/// Ported from `ghidra.app.plugin.core.eclipse.EclipseIntegrationPlugin`.
#[derive(Debug)]
pub struct EclipseIntegrationPlugin {
    /// Integration options.
    options: EclipseIntegrationOptions,
    /// Whether Eclipse is available on this system.
    eclipse_available: bool,
}

impl EclipseIntegrationPlugin {
    /// Create a new Eclipse integration plugin.
    pub fn new() -> Self {
        Self {
            options: EclipseIntegrationOptions::default(),
            eclipse_available: false,
        }
    }

    /// Initialize and detect Eclipse availability.
    pub fn init(&mut self) {
        self.eclipse_available = self.options.has_install_dir();
    }

    /// Get the options.
    pub fn options(&self) -> &EclipseIntegrationOptions {
        &self.options
    }

    /// Get a mutable reference to the options.
    pub fn options_mut(&mut self) -> &mut EclipseIntegrationOptions {
        &mut self.options
    }

    /// Whether Eclipse is available.
    pub fn is_eclipse_available(&self) -> bool {
        self.eclipse_available
    }

    /// Try to open a file in Eclipse.
    ///
    /// Returns `Ok(true)` if the file was sent to Eclipse, `Ok(false)` if
    /// Eclipse is not available.
    pub fn try_edit_file(&self, _file: &std::path::Path) -> Result<bool, String> {
        if !self.eclipse_available {
            return Ok(false);
        }
        let connection = EclipseConnection::new(self.options.script_editor_port);
        if !connection.connected {
            return Err(connection.error.unwrap_or_default());
        }
        Ok(true)
    }
}

impl Default for EclipseIntegrationPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl EclipseConnection {
    /// Attempt a connection to the given port.
    pub fn new(port: i32) -> Self {
        EclipseConnectorTask::new(port).execute().clone()
    }
}

impl Clone for EclipseConnection {
    fn clone(&self) -> Self {
        Self {
            port: self.port,
            connected: self.connected,
            error: self.error.clone(),
        }
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
        let opts = EclipseIntegrationOptions::default();
        assert!(!opts.has_install_dir());
        assert_eq!(opts.script_editor_port, SCRIPT_EDITOR_PORT_DEFAULT);
        assert_eq!(opts.symbol_lookup_port, SYMBOL_LOOKUP_PORT_DEFAULT);
        assert!(opts.auto_ghidra_dev_install);
    }

    #[test]
    fn test_eclipse_options_executable_no_dir() {
        let opts = EclipseIntegrationOptions::default();
        assert!(opts.eclipse_executable().is_none());
    }

    #[test]
    fn test_eclipse_connection_success() {
        let conn = EclipseConnection::success(28282);
        assert!(conn.connected);
        assert!(conn.error.is_none());
    }

    #[test]
    fn test_eclipse_connection_failure() {
        let conn = EclipseConnection::failure(28282, "refused");
        assert!(!conn.connected);
        assert_eq!(conn.error.as_deref(), Some("refused"));
    }

    #[test]
    fn test_connector_task() {
        let mut task = EclipseConnectorTask::new(28282);
        assert!(task.result.is_none());
        task.execute();
        assert!(task.result.is_some());
    }

    #[test]
    fn test_plugin_lifecycle() {
        let mut plugin = EclipseIntegrationPlugin::new();
        assert!(!plugin.is_eclipse_available());

        plugin.init();
        assert!(!plugin.is_eclipse_available()); // No install dir configured

        plugin.options_mut().eclipse_install_dir = Some(PathBuf::from("/opt/eclipse"));
        plugin.init();
        assert!(plugin.is_eclipse_available());
    }

    #[test]
    fn test_plugin_try_edit_no_eclipse() {
        let plugin = EclipseIntegrationPlugin::new();
        let result = plugin.try_edit_file(std::path::Path::new("/test/file.rs"));
        assert_eq!(result, Ok(false));
    }
}
