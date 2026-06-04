//! PyDev debugging utilities.
//!
//! Ported from `PyDevUtils.java` in the Jython extension.
//!
//! Provides utility functions for PyDev remote debugger integration.

use std::path::{Path, PathBuf};

/// The default PyDev remote debugger port.
pub const PYDEV_REMOTE_DEBUGGER_PORT: u16 = 5678;

/// Environment variable / system property for PyDev source directory.
const PYDEV_SRC_DIR_PROPERTY: &str = "eclipse.pysrc.dir";

/// Utility functions for PyDev integration.
///
/// PyDev is the Python IDE plugin for Eclipse that provides debugging
/// capabilities for Jython scripts running within Ghidra.
pub struct PyDevUtils;

impl PyDevUtils {
    /// Get the PyDev source directory.
    ///
    /// Returns the path configured by the `eclipse.pysrc.dir` system
    /// property, or `None` if not set or blank.
    ///
    /// # Example
    ///
    /// ```
    /// use ghidra_features::jython::PyDevUtils;
    ///
    /// // May be None if not configured
    /// let dir = PyDevUtils::get_pydev_src_dir();
    /// ```
    pub fn get_pydev_src_dir() -> Option<PathBuf> {
        std::env::var(PYDEV_SRC_DIR_PROPERTY)
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from)
    }

    /// Get the PyDev remote debugger port.
    ///
    /// Returns the default port (5678) unless overridden by the
    /// `pydev.remote.debugger.port` system property.
    pub fn get_debugger_port() -> u16 {
        std::env::var("pydev.remote.debugger.port")
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(PYDEV_REMOTE_DEBUGGER_PORT)
    }

    /// Check if the PyDev source directory is configured and exists.
    pub fn is_pydev_available() -> bool {
        Self::get_pydev_src_dir()
            .map(|p| p.exists())
            .unwrap_or(false)
    }

    /// Get the PyDev debugger connection URL.
    ///
    /// Returns `host:port` format for connecting to the debugger.
    pub fn get_debugger_url(host: &str, port: Option<u16>) -> String {
        let p = port.unwrap_or(Self::get_debugger_port());
        format!("{host}:{p}")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_port() {
        assert_eq!(PYDEV_REMOTE_DEBUGGER_PORT, 5678);
    }

    #[test]
    fn test_get_debugger_port_default() {
        // Without env var set, should return default
        let port = PyDevUtils::get_debugger_port();
        assert_eq!(port, 5678);
    }

    #[test]
    fn test_get_debugger_url() {
        let url = PyDevUtils::get_debugger_url("localhost", None);
        assert_eq!(url, "localhost:5678");
    }

    #[test]
    fn test_get_debugger_url_custom_port() {
        let url = PyDevUtils::get_debugger_url("192.168.1.1", Some(9999));
        assert_eq!(url, "192.168.1.1:9999");
    }

    #[test]
    fn test_get_pydev_src_dir_no_env() {
        // Without the env var set, should return None
        // (unless user has it set in their environment)
        let _dir = PyDevUtils::get_pydev_src_dir();
        // Just verify it doesn't panic
    }

    #[test]
    fn test_is_pydev_available() {
        // Without PyDev configured, should return false
        // (unless user has it in their environment)
        let _available = PyDevUtils::is_pydev_available();
        // Just verify it doesn't panic
    }
}
