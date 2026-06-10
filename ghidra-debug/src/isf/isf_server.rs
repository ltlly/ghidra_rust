//! ISF server: TCP listener with connection management and graceful shutdown.
//!
//! Ported from Ghidra's `IsfServer` in the `ghidra.dbg.isf` package.
//!
//! The server binds to a TCP port, accepts incoming connections, and hands
//! each connection off to an [`IsfClientHandler`] for protocol processing.
//! It supports:
//! - Configurable bind address and port
//! - Maximum concurrent connection limiting
//! - Graceful shutdown via a shared atomic flag
//! - Per-connection statistics tracking

use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::isf_client_handler::{ClientHandlerError, HandlerState, IsfClientHandler};
use super::server::IsfTypeDef;

// ---------------------------------------------------------------------------
// ServerConfig
// ---------------------------------------------------------------------------

/// Configuration for the ISF server.
#[derive(Debug, Clone)]
pub struct IsfServerConfig {
    /// The address to bind to (e.g., `"127.0.0.1:54321"`).
    pub bind_addr: String,
    /// Maximum number of concurrent client connections.
    pub max_connections: usize,
    /// Read timeout for accepted connections (None = blocking).
    pub read_timeout: Option<Duration>,
    /// Write timeout for accepted connections (None = blocking).
    pub write_timeout: Option<Duration>,
    /// Whether to set `SO_REUSEADDR` on the listener.
    pub reuse_addr: bool,
}

impl Default for IsfServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:54321".into(),
            max_connections: 10,
            read_timeout: Some(Duration::from_secs(30)),
            write_timeout: Some(Duration::from_secs(10)),
            reuse_addr: true,
        }
    }
}

// ---------------------------------------------------------------------------
// ServerStats
// ---------------------------------------------------------------------------

/// Cumulative statistics for the ISF server.
#[derive(Debug, Clone, Default)]
pub struct ServerStats {
    /// Total connections accepted since the server started.
    pub connections_accepted: u64,
    /// Total connections currently active.
    pub connections_active: u64,
    /// Total requests processed across all connections.
    pub total_requests: u64,
    /// Total handler errors (non-fatal, per-connection).
    pub handler_errors: u64,
}

// ---------------------------------------------------------------------------
// ConnectionRecord
// ---------------------------------------------------------------------------

/// A record of a client connection managed by the server.
#[derive(Debug, Clone)]
pub struct ConnectionRecord {
    /// Handler-assigned ID.
    pub handler_id: u64,
    /// Remote peer address.
    pub remote_addr: String,
    /// Current state of this connection.
    pub state: HandlerState,
    /// Requests processed by this connection.
    pub requests_processed: u64,
}

// ---------------------------------------------------------------------------
// IsfServer
// ---------------------------------------------------------------------------

/// The ISF server.
///
/// Listens for TCP connections and delegates each to an
/// [`IsfClientHandler`]. The server owns a shared type store that is
/// pre-populated before the server starts accepting connections.
///
/// # Lifecycle
///
/// 1. Create with [`IsfServer::new`].
/// 2. Pre-populate the type store via [`IsfServer::add_type`] and friends.
/// 3. Call [`IsfServer::start`] to bind and begin accepting.
/// 4. Call [`IsfServer::shutdown`] to stop accepting and close all connections.
pub struct IsfServer {
    /// Server configuration.
    pub config: IsfServerConfig,
    /// The TCP listener (Some while running).
    listener: Option<TcpListener>,
    /// Shared type store.
    types: std::collections::BTreeMap<String, Vec<IsfTypeDef>>,
    /// Next type ID to allocate.
    next_type_id: u64,
    /// Next handler ID to assign.
    next_handler_id: u64,
    /// Shutdown flag shared across threads.
    shutdown_flag: Arc<AtomicBool>,
    /// Cumulative server stats.
    pub stats: ServerStats,
    /// Records of closed/active connections.
    pub connection_records: Vec<ConnectionRecord>,
}

impl std::fmt::Debug for IsfServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IsfServer")
            .field("config", &self.config)
            .field("listening", &self.listener.is_some())
            .field("stats", &self.stats)
            .finish()
    }
}

impl IsfServer {
    /// Create a new ISF server with the given configuration.
    pub fn new(config: IsfServerConfig) -> Self {
        Self {
            config,
            listener: None,
            types: std::collections::BTreeMap::new(),
            next_type_id: 0,
            next_handler_id: 0,
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            stats: ServerStats::default(),
            connection_records: Vec::new(),
        }
    }

    // -- Type store -----------------------------------------------------------

    /// Add a type definition to the shared type store.
    pub fn add_type(&mut self, namespace: impl Into<String>, type_def: IsfTypeDef) {
        self.types.entry(namespace.into()).or_default().push(type_def);
    }

    /// Allocate a new type ID.
    pub fn alloc_type_id(&mut self) -> u64 {
        let id = self.next_type_id;
        self.next_type_id += 1;
        id
    }

    /// Get a snapshot of the current type store for injecting into a handler.
    fn clone_types(&self) -> std::collections::BTreeMap<String, Vec<IsfTypeDef>> {
        self.types.clone()
    }

    // -- Lifecycle ------------------------------------------------------------

    /// Bind the TCP listener and begin accepting connections.
    ///
    /// This method blocks the calling thread and runs the accept loop.
    /// It returns when [`IsfServer::shutdown`] is called (or an unrecoverable
    /// I/O error occurs on the listener).
    pub fn start(&mut self) -> io::Result<()> {
        let addr = self.config.bind_addr.clone();
        let listener = TcpListener::bind(&addr)?;

        if self.config.reuse_addr {
            // SO_REUSEADDR is set by default on most platforms for bind(),
            // but we document the intent here.
        }

        self.listener = Some(listener);
        self.shutdown_flag.store(false, Ordering::SeqCst);

        Ok(())
    }

    /// Run the accept loop. Call this after [`start`].
    ///
    /// This blocks until shutdown is signalled.
    pub fn run_accept_loop(&mut self) -> io::Result<()> {
        {
            let listener = self
                .listener
                .as_ref()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Server not started"))?;

            // Set a short accept timeout so we can poll the shutdown flag.
            listener.set_nonblocking(true)?;
        }

        loop {
            if self.shutdown_flag.load(Ordering::SeqCst) {
                break;
            }

            // Accept without holding a borrow on self.
            let accept_result = {
                let listener = self
                    .listener
                    .as_ref()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Server not started"))?;
                listener.accept()
            };

            match accept_result {
                Ok((stream, _addr)) => {
                    // Check connection limit
                    let active = self
                        .connection_records
                        .iter()
                        .filter(|r| r.state == HandlerState::Active)
                        .count();

                    if active >= self.config.max_connections {
                        // Drop the stream to refuse the connection.
                        drop(stream);
                        continue;
                    }

                    self.handle_connection(stream)?;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // No connection pending; sleep briefly and retry.
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    /// Handle a single accepted connection.
    fn handle_connection(&mut self, stream: TcpStream) -> io::Result<()> {
        if let Some(timeout) = self.config.read_timeout {
            stream.set_read_timeout(Some(timeout))?;
        }
        if let Some(timeout) = self.config.write_timeout {
            stream.set_write_timeout(Some(timeout))?;
        }

        let handler_id = self.next_handler_id;
        self.next_handler_id += 1;

        let mut handler = IsfClientHandler::new(handler_id, stream)?;

        // Inject the shared type store into the handler.
        *handler.types_mut() = self.clone_types();

        let record = ConnectionRecord {
            handler_id,
            remote_addr: handler.remote_addr.clone(),
            state: HandlerState::Active,
            requests_processed: 0,
        };
        self.connection_records.push(record);

        self.stats.connections_accepted += 1;
        self.stats.connections_active += 1;

        // Run the handler synchronously (single-threaded model).
        match handler.run() {
            Ok(requests) => {
                self.stats.total_requests += requests;
            }
            Err(ClientHandlerError::ConnectionClosed) => {
                // Client disconnected; not an error.
            }
            Err(_) => {
                self.stats.handler_errors += 1;
            }
        }

        handler.close();
        self.stats.connections_active = self.stats.connections_active.saturating_sub(1);

        // Update the connection record.
        if let Some(rec) = self.connection_records.last_mut() {
            rec.state = HandlerState::Closed;
            rec.requests_processed = handler.requests_processed;
        }

        Ok(())
    }

    /// Signal the server to shut down gracefully.
    pub fn shutdown(&mut self) {
        self.shutdown_flag.store(true, Ordering::SeqCst);
        // Drop the listener to unblock the accept loop.
        self.listener = None;
    }

    /// Get a clone of the shutdown flag for use in other threads.
    pub fn shutdown_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown_flag)
    }

    /// Whether the server is currently running (listener is bound).
    pub fn is_running(&self) -> bool {
        self.listener.is_some()
    }

    /// The local address the server is bound to, if running.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.listener
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Server not started"))?
            .local_addr()
    }

    /// Get the list of connection records.
    pub fn connections(&self) -> &[ConnectionRecord] {
        &self.connection_records
    }

    /// Number of currently active connections.
    pub fn active_connections(&self) -> usize {
        self.connection_records
            .iter()
            .filter(|r| r.state == HandlerState::Active)
            .count()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isf::server::{IsfComponent, IsfRequest, IsfResponse, IsfTypeKind};

    #[test]
    fn test_server_config_default() {
        let cfg = IsfServerConfig::default();
        assert_eq!(cfg.bind_addr, "127.0.0.1:54321");
        assert_eq!(cfg.max_connections, 10);
        assert!(cfg.reuse_addr);
    }

    #[test]
    fn test_server_creation() {
        let server = IsfServer::new(IsfServerConfig::default());
        assert!(!server.is_running());
        assert_eq!(server.stats.connections_accepted, 0);
        assert_eq!(server.stats.connections_active, 0);
    }

    #[test]
    fn test_server_add_type() {
        let mut server = IsfServer::new(IsfServerConfig::default());
        server.add_type("ns", IsfTypeDef {
            type_id: 1,
            name: "int".into(),
            kind: IsfTypeKind::BuiltIn,
            size: 4,
            alignment: 4,
            components: vec![],
            properties: std::collections::BTreeMap::new(),
        });
        let types = server.clone_types();
        assert!(types.contains_key("ns"));
        assert_eq!(types["ns"].len(), 1);
    }

    #[test]
    fn test_server_alloc_type_id() {
        let mut server = IsfServer::new(IsfServerConfig::default());
        assert_eq!(server.alloc_type_id(), 0);
        assert_eq!(server.alloc_type_id(), 1);
        assert_eq!(server.alloc_type_id(), 2);
    }

    #[test]
    fn test_server_start_and_shutdown() {
        let config = IsfServerConfig {
            bind_addr: "127.0.0.1:0".into(),
            ..Default::default()
        };
        let mut server = IsfServer::new(config);
        server.start().unwrap();
        assert!(server.is_running());

        // Get the assigned port.
        let addr = server.local_addr().unwrap();
        assert_ne!(addr.port(), 0);

        server.shutdown();
        assert!(!server.is_running());
    }

    #[test]
    fn test_server_accept_single_connection() {
        let config = IsfServerConfig {
            bind_addr: "127.0.0.1:0".into(),
            max_connections: 5,
            ..Default::default()
        };
        let mut server = IsfServer::new(config);
        server.add_type("test", IsfTypeDef {
            type_id: 1,
            name: "my_type".into(),
            kind: IsfTypeKind::BuiltIn,
            size: 4,
            alignment: 4,
            components: vec![],
            properties: std::collections::BTreeMap::new(),
        });

        server.start().unwrap();
        let addr = server.local_addr().unwrap();
        let flag = server.shutdown_flag();

        // Spawn the accept loop in a background thread.
        let handle = std::thread::spawn(move || {
            // We need a mutable reference, so we move the server.
            // In practice, this would use Arc<Mutex<IsfServer>> or similar.
            // For the test, we just use the server directly.
            server.run_accept_loop().ok();
            server
        });

        // Give the server a moment to start listening.
        std::thread::sleep(Duration::from_millis(50));

        // Connect as a client and do the handshake.
        let mut client = TcpStream::connect(addr).unwrap();

        // Send magic + version.
        client.write_all(b"ISF\x00").unwrap();
        client.write_all(&1u32.to_be_bytes()).unwrap();

        // Read ack (4 bytes version + 1 byte status).
        let mut ack = [0u8; 5];
        client.read_exact(&mut ack).unwrap();
        assert_eq!(ack[4], 0); // status OK

        // Send a Ping request.
        let req = serde_json::to_vec(&IsfRequest::Ping).unwrap();
        client.write_all(&(req.len() as u32).to_be_bytes()).unwrap();
        client.write_all(&req).unwrap();

        // Read response.
        let mut resp_len = [0u8; 4];
        client.read_exact(&mut resp_len).unwrap();
        let len = u32::from_be_bytes(resp_len) as usize;
        let mut resp_buf = vec![0u8; len];
        client.read_exact(&mut resp_buf).unwrap();

        let response: IsfResponse = serde_json::from_slice(&resp_buf).unwrap();
        assert!(matches!(response, IsfResponse::Pong));

        // Drop the client to close the connection.
        drop(client);

        // Give the server time to notice the close.
        std::thread::sleep(Duration::from_millis(100));

        // Signal shutdown.
        flag.store(true, Ordering::SeqCst);

        let server = handle.join().unwrap();
        assert!(server.stats.connections_accepted >= 1);
        assert_eq!(server.stats.connections_active, 0);
    }

    #[test]
    fn test_server_refuses_beyond_max_connections() {
        let config = IsfServerConfig {
            bind_addr: "127.0.0.1:0".into(),
            max_connections: 0, // Refuse all connections.
            ..Default::default()
        };
        let mut server = IsfServer::new(config);
        server.start().unwrap();
        let addr = server.local_addr().unwrap();
        let flag = server.shutdown_flag();

        let handle = std::thread::spawn(move || {
            server.run_accept_loop().ok();
            server
        });

        std::thread::sleep(Duration::from_millis(50));

        // Try to connect -- should be accepted at TCP level but immediately closed.
        let result = TcpStream::connect(addr);
        // The connection may succeed at TCP level; the handler just drops it.
        if let Ok(mut client) = result {
            // The server should close us; read should fail or return 0.
            client.set_read_timeout(Some(Duration::from_millis(200))).ok();
            let mut buf = [0u8; 1];
            // It's OK if this errors or returns 0.
            let _ = client.read(&mut buf);
        }

        flag.store(true, Ordering::SeqCst);
        let server = handle.join().unwrap();
        assert_eq!(server.stats.connections_accepted, 0);
    }

    #[test]
    fn test_server_stats() {
        let stats = ServerStats::default();
        assert_eq!(stats.connections_accepted, 0);
        assert_eq!(stats.connections_active, 0);
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.handler_errors, 0);
    }

    #[test]
    fn test_connection_record() {
        let rec = ConnectionRecord {
            handler_id: 42,
            remote_addr: "10.0.0.1:1234".into(),
            state: HandlerState::Active,
            requests_processed: 10,
        };
        assert_eq!(rec.handler_id, 42);
        assert_eq!(rec.state, HandlerState::Active);
    }

    #[test]
    fn test_server_debug_format() {
        let server = IsfServer::new(IsfServerConfig::default());
        let debug = format!("{:?}", server);
        assert!(debug.contains("IsfServer"));
        assert!(debug.contains("config"));
    }

    #[test]
    fn test_server_config_clone() {
        let cfg = IsfServerConfig::default();
        let cfg2 = cfg.clone();
        assert_eq!(cfg.bind_addr, cfg2.bind_addr);
        assert_eq!(cfg.max_connections, cfg2.max_connections);
    }
}

// Re-export std::io::Read and std::io::Write for use in test code.
#[cfg(test)]
use std::io::{Read, Write};
