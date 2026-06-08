//! Server port configuration for the Ghidra Server.
//!
//! Ported from `ghidra.server.remote.ServerPortFactory`.
//!
//! Manages the set of network ports used by the Ghidra Server:
//! the RMI registry port, the SSL-protected RMI port, and the
//! block-stream port.  All ports are derived from a single base port.

use std::sync::atomic::{AtomicU16, Ordering};

/// Default base port matching Java's `GhidraServerHandle.DEFAULT_PORT`.
const DEFAULT_BASE_PORT: u16 = 13100;

/// Offset from base port to the RMI registry port (0 in the Java implementation).
const RMI_REGISTRY_OFFSET: u16 = 0;

/// Offset from base port to the SSL RMI port.
const RMI_SSL_OFFSET: u16 = 1;

/// Offset from base port to the stream (block-stream) port.
const STREAM_OFFSET: u16 = 2;

/// Global base port value.
static BASE_PORT: AtomicU16 = AtomicU16::new(DEFAULT_BASE_PORT);

/// Set the base port used by the server.
///
/// All derived ports (RMI registry, SSL RMI, stream) are recalculated
/// from this base.  Matches Java's `ServerPortFactory.setBasePort(int)`.
pub fn set_base_port(port: u16) {
    BASE_PORT.store(port, Ordering::Relaxed);
}

/// Get the current base port.
pub fn get_base_port() -> u16 {
    BASE_PORT.load(Ordering::Relaxed)
}

/// Returns the RMI registry port.
///
/// Matches Java's `ServerPortFactory.getRMIRegistryPort()`.
pub fn get_rmi_registry_port() -> u16 {
    BASE_PORT.load(Ordering::Relaxed) + RMI_REGISTRY_OFFSET
}

/// Returns the SSL-protected RMI port.
///
/// Matches Java's `ServerPortFactory.getRMISSLPort()`.
pub fn get_rmi_ssl_port() -> u16 {
    BASE_PORT.load(Ordering::Relaxed) + RMI_SSL_OFFSET
}

/// Returns the SSL stream (block-stream) port.
///
/// Matches Java's `ServerPortFactory.getStreamPort()`.
pub fn get_stream_port() -> u16 {
    BASE_PORT.load(Ordering::Relaxed) + STREAM_OFFSET
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_ports() {
        set_base_port(DEFAULT_BASE_PORT);
        assert_eq!(get_base_port(), 13100);
        assert_eq!(get_rmi_registry_port(), 13100);
        assert_eq!(get_rmi_ssl_port(), 13101);
        assert_eq!(get_stream_port(), 13102);
    }

    #[test]
    fn test_custom_base_port() {
        set_base_port(14000);
        assert_eq!(get_rmi_registry_port(), 14000);
        assert_eq!(get_rmi_ssl_port(), 14001);
        assert_eq!(get_stream_port(), 14002);
        // Reset to default for other tests.
        set_base_port(DEFAULT_BASE_PORT);
    }

    #[test]
    fn test_set_base_port_persists() {
        set_base_port(15000);
        assert_eq!(get_base_port(), 15000);
        set_base_port(DEFAULT_BASE_PORT);
    }

    #[test]
    fn test_port_offsets() {
        set_base_port(0);
        assert_eq!(get_rmi_registry_port(), 0);
        assert_eq!(get_rmi_ssl_port(), 1);
        assert_eq!(get_stream_port(), 2);
        set_base_port(DEFAULT_BASE_PORT);
    }
}
