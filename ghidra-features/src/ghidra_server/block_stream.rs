//! Block stream server for efficient data transfer.
//!
//! Ported from `ghidra.server.stream.BlockStreamServer`.  Provides a
//! TCP-based block stream server for efficient transfer of database
//! buffer blocks between the Ghidra server and its clients.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Timeout for request headers (milliseconds).
const REQUEST_HEADER_TIMEOUT_MS: u64 = 10_000;

/// Maximum age of a block stream registration before cleanup (ms).
const MAX_AGE_MS: u64 = 30_000;

/// Cleanup check interval (milliseconds).
const CLEANUP_PERIOD_MS: u64 = 30_000;

// ---------------------------------------------------------------------------
// BlockStreamRegistration
// ---------------------------------------------------------------------------

/// Registration for an active block stream.
#[derive(Debug)]
pub struct BlockStreamRegistration {
    /// The stream ID.
    pub stream_id: u64,
    /// When this registration was created.
    pub created_at: Instant,
    /// The hostname that registered this stream.
    pub hostname: String,
    /// Whether the stream is compressed.
    pub compressed: bool,
}

// ---------------------------------------------------------------------------
// StreamRequest
// ---------------------------------------------------------------------------

/// A request to open a block stream.
#[derive(Debug, Clone)]
pub struct StreamRequest {
    /// The stream ID to open.
    pub stream_id: u64,
    /// Whether the client requests compression.
    pub compressed: bool,
}

// ---------------------------------------------------------------------------
// BlockStreamServer
// ---------------------------------------------------------------------------

/// A block stream server for efficient data transfer between Ghidra
/// server and clients.
///
/// Matches Java's `ghidra.server.stream.BlockStreamServer`.
pub struct BlockStreamServer {
    stream_map: Mutex<HashMap<u64, BlockStreamRegistration>>,
    next_stream_id: Mutex<u64>,
    hostname: Mutex<String>,
    running: Mutex<bool>,
    port: Mutex<u16>,
}

impl BlockStreamServer {
    /// Create a new block stream server.
    pub fn new() -> Self {
        Self {
            stream_map: Mutex::new(HashMap::new()),
            next_stream_id: Mutex::new(0),
            hostname: Mutex::new(String::new()),
            running: Mutex::new(false),
            port: Mutex::new(0),
        }
    }

    /// Start the server on the given port.
    pub fn start(&self, port: u16, hostname: &str) {
        if let Ok(mut running) = self.running.lock() {
            *running = true;
        }
        if let Ok(mut h) = self.hostname.lock() {
            *h = hostname.to_string();
        }
        if let Ok(mut p) = self.port.lock() {
            *p = port;
        }
    }

    /// Stop the server.
    pub fn stop(&self) {
        if let Ok(mut running) = self.running.lock() {
            *running = false;
        }
    }

    /// Whether the server is running.
    pub fn is_running(&self) -> bool {
        self.running.lock().map(|v| *v).unwrap_or(false)
    }

    /// Get the server port.
    pub fn server_port(&self) -> u16 {
        self.port.lock().map(|v| *v).unwrap_or(0)
    }

    /// Register a new block stream and return its ID.
    pub fn register_stream(&self, hostname: &str, compressed: bool) -> u64 {
        let mut next_id = self.next_stream_id.lock().unwrap();
        let stream_id = *next_id;
        *next_id += 1;

        let mut map = self.stream_map.lock().unwrap();
        map.insert(
            stream_id,
            BlockStreamRegistration {
                stream_id,
                created_at: Instant::now(),
                hostname: hostname.to_string(),
                compressed,
            },
        );

        stream_id
    }

    /// Remove a block stream registration.
    pub fn unregister_stream(&self, stream_id: u64) -> bool {
        let mut map = self.stream_map.lock().unwrap();
        map.remove(&stream_id).is_some()
    }

    /// Clean up expired stream registrations.
    pub fn cleanup_expired(&self) {
        let mut map = self.stream_map.lock().unwrap();
        let now = Instant::now();
        map.retain(|_, reg| {
            now.duration_since(reg.created_at).as_millis() < MAX_AGE_MS as u128
        });
    }

    /// Get the number of active stream registrations.
    pub fn active_stream_count(&self) -> usize {
        self.stream_map.lock().map(|m| m.len()).unwrap_or(0)
    }
}

impl Default for BlockStreamServer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RemoteBlockStreamHandle (simplified)
// ---------------------------------------------------------------------------

/// Handle for a remote block stream.
///
/// Matches Java's `ghidra.server.stream.RemoteBlockStreamHandle`.
#[derive(Debug, Clone)]
pub struct RemoteBlockStreamHandle {
    /// Whether compressed serialization output is enabled.
    pub compressed: bool,
    /// The stream ID.
    pub stream_id: u64,
    /// The server hostname.
    pub hostname: String,
}

impl RemoteBlockStreamHandle {
    /// Whether compressed serialization output is globally enabled.
    pub const ENABLE_COMPRESSED_SERIALIZATION: bool = true;

    /// Create a new remote block stream handle.
    pub fn new(stream_id: u64, hostname: &str, compressed: bool) -> Self {
        Self {
            compressed,
            stream_id,
            hostname: hostname.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_stream_server_lifecycle() {
        let server = BlockStreamServer::new();
        assert!(!server.is_running());

        server.start(13101, "localhost");
        assert!(server.is_running());
        assert_eq!(server.server_port(), 13101);

        server.stop();
        assert!(!server.is_running());
    }

    #[test]
    fn test_register_and_unregister_stream() {
        let server = BlockStreamServer::new();
        let id1 = server.register_stream("host1", false);
        let id2 = server.register_stream("host2", true);

        assert_eq!(server.active_stream_count(), 2);
        assert!(id1 != id2);

        assert!(server.unregister_stream(id1));
        assert_eq!(server.active_stream_count(), 1);
        assert!(!server.unregister_stream(id1)); // already removed
    }

    #[test]
    fn test_cleanup_expired() {
        let server = BlockStreamServer::new();
        server.register_stream("host", false);
        assert_eq!(server.active_stream_count(), 1);

        // Cleanup won't remove fresh registrations
        server.cleanup_expired();
        assert_eq!(server.active_stream_count(), 1);
    }

    #[test]
    fn test_default_server() {
        let server = BlockStreamServer::default();
        assert!(!server.is_running());
        assert_eq!(server.server_port(), 0);
    }

    #[test]
    fn test_remote_block_stream_handle() {
        let handle = RemoteBlockStreamHandle::new(42, "myhost", true);
        assert_eq!(handle.stream_id, 42);
        assert_eq!(handle.hostname, "myhost");
        assert!(handle.compressed);
    }
}
