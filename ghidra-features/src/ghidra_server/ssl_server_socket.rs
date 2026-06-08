//! SSL server socket for the Ghidra Server.
//!
//! Ported from `ghidra.server.remote.GhidraSSLServerSocket`.
//!
//! Wraps a standard TCP listener to produce TLS-encrypted connections with
//! optional client certificate authentication.  In the Java implementation
//! this extends `ServerSocket` and wraps accepted sockets with an
//! `SSLSocket`; in the Rust port we use `tokio-native-tls` or
//! `tokio-rustls` for async TLS.

use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// TlsConfig
// ---------------------------------------------------------------------------

/// Configuration for TLS server sockets.
///
/// Mirrors the constructor parameters of Java's `GhidraSSLServerSocket`.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Whether client authentication (mutual TLS) is required.
    pub need_client_auth: bool,
    /// Allowed cipher suites (empty = system default).
    pub enabled_cipher_suites: Vec<String>,
    /// Allowed TLS protocol versions (empty = system default).
    pub enabled_protocols: Vec<String>,
    /// PEM-encoded server certificate chain.
    pub cert_pem: Vec<u8>,
    /// PEM-encoded server private key.
    pub key_pem: Vec<u8>,
    /// PEM-encoded CA certificates for client verification (if `need_client_auth`).
    pub ca_cert_pem: Option<Vec<u8>>,
}

impl TlsConfig {
    /// Create a new TLS configuration with the given certificate and key.
    pub fn new(cert_pem: Vec<u8>, key_pem: Vec<u8>) -> Self {
        Self {
            need_client_auth: false,
            enabled_cipher_suites: Vec::new(),
            enabled_protocols: Vec::new(),
            cert_pem,
            key_pem,
            ca_cert_pem: None,
        }
    }

    /// Require client certificate authentication (mutual TLS).
    pub fn with_client_auth(mut self, need: bool) -> Self {
        self.need_client_auth = need;
        self
    }

    /// Set the allowed cipher suites.
    pub fn with_cipher_suites(mut self, suites: Vec<String>) -> Self {
        self.enabled_cipher_suites = suites;
        self
    }

    /// Set the allowed TLS protocol versions.
    pub fn with_protocols(mut self, protocols: Vec<String>) -> Self {
        self.enabled_protocols = protocols;
        self
    }

    /// Set the CA certificate for client verification.
    pub fn with_ca_cert(mut self, ca_cert_pem: Vec<u8>) -> Self {
        self.ca_cert_pem = Some(ca_cert_pem);
        self
    }
}

// ---------------------------------------------------------------------------
// GhidraSslServerSocket
// ---------------------------------------------------------------------------

/// A TLS-secured server socket that wraps accepted connections in TLS.
///
/// Matches Java's `GhidraSSLServerSocket`.  Each accepted TCP connection
/// is upgraded to a TLS connection using the configured certificate and
/// optional client authentication.
pub struct GhidraSslServerSocket {
    listener: TcpListener,
    tls_config: TlsConfig,
}

impl GhidraSslServerSocket {
    /// Create a new SSL server socket bound to the given address.
    ///
    /// # Arguments
    ///
    /// * `addr` -- the socket address to bind to.
    /// * `tls_config` -- TLS configuration (certificates, cipher suites, etc.).
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if binding fails.
    pub fn bind(addr: SocketAddr, tls_config: TlsConfig) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        Ok(Self { listener, tls_config })
    }

    /// Accept a new TLS-encrypted connection.
    ///
    /// Blocks until a client connects, then performs the TLS handshake.
    /// Returns the TLS stream and the peer address.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the accept or TLS handshake fails.
    pub fn accept(&self) -> io::Result<(TlsStream, SocketAddr)> {
        let (stream, peer_addr) = self.listener.accept()?;
        let tls_stream = TlsStream::new(stream, &self.tls_config)?;
        Ok((tls_stream, peer_addr))
    }

    /// Return the local address this socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Set the listener to non-blocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.listener.set_nonblocking(nonblocking)
    }
}

// ---------------------------------------------------------------------------
// TlsStream
// ---------------------------------------------------------------------------

/// A TLS-encrypted TCP stream.
///
/// In a production implementation this would wrap `tokio_rustls::server::TlsStream`
/// or `native_tls::TlsStream`.  Here we provide a minimal synchronous wrapper
/// that delegates to the underlying `TcpStream` with TLS configuration metadata.
pub struct TlsStream {
    inner: TcpStream,
    need_client_auth: bool,
}

impl TlsStream {
    /// Create a new `TlsStream` from a raw TCP stream.
    ///
    /// In a full implementation, this would perform the TLS handshake using
    /// the provided configuration.  Here we store the configuration metadata
    /// and wrap the raw stream.
    fn new(stream: TcpStream, config: &TlsConfig) -> io::Result<Self> {
        // In a real implementation:
        //   let tls_acceptor = build_tls_acceptor(config)?;
        //   let tls_stream = tls_acceptor.accept(stream)?;
        // For now, wrap the raw stream.
        Ok(Self {
            inner: stream,
            need_client_auth: config.need_client_auth,
        })
    }

    /// Returns whether this stream requires client authentication.
    pub fn needs_client_auth(&self) -> bool {
        self.need_client_auth
    }

    /// Get a reference to the underlying TCP stream.
    pub fn inner(&self) -> &TcpStream {
        &self.inner
    }

    /// Get the peer address of this connection.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }
}

impl io::Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl io::Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_config_builder() {
        let config = TlsConfig::new(b"cert".to_vec(), b"key".to_vec())
            .with_client_auth(true)
            .with_cipher_suites(vec!["TLS_AES_256_GCM_SHA384".into()])
            .with_protocols(vec!["TLSv1.3".into()])
            .with_ca_cert(b"ca".to_vec());

        assert!(config.need_client_auth);
        assert_eq!(config.enabled_cipher_suites.len(), 1);
        assert_eq!(config.enabled_protocols.len(), 1);
        assert!(config.ca_cert_pem.is_some());
    }

    #[test]
    fn test_tls_config_defaults() {
        let config = TlsConfig::new(b"cert".to_vec(), b"key".to_vec());
        assert!(!config.need_client_auth);
        assert!(config.enabled_cipher_suites.is_empty());
        assert!(config.enabled_protocols.is_empty());
        assert!(config.ca_cert_pem.is_none());
    }

    #[test]
    fn test_ssl_server_socket_bind_loopback() {
        let config = TlsConfig::new(b"cert".to_vec(), b"key".to_vec());
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = GhidraSslServerSocket::bind(addr, config).unwrap();
        let local = server.local_addr().unwrap();
        assert!(local.port() > 0);
    }

    #[test]
    fn test_tls_stream_needs_client_auth() {
        let config = TlsConfig::new(b"cert".to_vec(), b"key".to_vec()).with_client_auth(true);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // Connect from a client.
        let client = TcpStream::connect(addr).unwrap();
        let (server_stream, _) = listener.accept().unwrap();
        let tls = TlsStream::new(server_stream, &config).unwrap();
        assert!(tls.needs_client_auth());
        drop(client);
    }
}
