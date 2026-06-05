//! Trace RMI acceptor for receiving connections from debug backends.
//!
//! Ported from Ghidra's `TraceRmiAcceptor` interface.
//!
//! Provides an acceptor that listens for and receives a single Trace RMI
//! connection from a back-end debugger. After a connection is accepted or
//! the acceptor fails, it is no longer valid.

use std::net::SocketAddr;
use std::time::Duration;

use thiserror::Error;

/// Errors that can occur during RMI connection acceptance.
#[derive(Debug, Error)]
pub enum AcceptorError {
    /// An I/O error occurred while accepting the connection.
    #[error("I/O error accepting connection: {0}")]
    Io(#[from] std::io::Error),

    /// The accept operation was cancelled.
    #[error("Accept operation was cancelled")]
    Cancelled,

    /// The accept operation timed out.
    #[error("Accept operation timed out after {0:?}")]
    Timeout(Duration),

    /// The acceptor has already been closed.
    #[error("Acceptor is closed")]
    Closed,
}

/// Result type for acceptor operations.
pub type AcceptorResult<T> = Result<T, AcceptorError>;

/// An acceptor that can receive a single Trace RMI connection.
///
/// This mirrors Ghidra's `TraceRmiAcceptor` interface. The acceptor
/// listens on a socket and accepts exactly one connection from a
/// debug backend. After acceptance, the acceptor is no longer valid.
pub trait TraceRmiAcceptor: Send + Sync {
    /// Accept a single connection.
    ///
    /// This method blocks until a connection is received, the timeout
    /// expires, or the acceptor is cancelled.
    ///
    /// Returns a boxed `TraceRmiConnection` on success.
    fn accept(&self) -> AcceptorResult<Box<dyn TraceRmiConnectionTrait>>;

    /// Check if the acceptor is still accepting.
    fn is_closed(&self) -> bool;

    /// Get the address where the acceptor is listening.
    fn get_address(&self) -> SocketAddr;

    /// Set the timeout for acceptance.
    fn set_timeout(&mut self, duration: Duration) -> AcceptorResult<()>;

    /// Cancel the connection acceptance.
    ///
    /// If a different thread has called `accept()`, it will fail
    /// with `AcceptorError::Cancelled`.
    fn cancel(&self);
}

/// Trait representing an RMI connection to a debug backend.
pub trait TraceRmiConnectionTrait: Send + Sync {
    /// Get the remote address of the connection.
    fn remote_address(&self) -> Option<SocketAddr>;

    /// Check if the connection is still open.
    fn is_open(&self) -> bool;

    /// Close the connection.
    fn close(&self) -> AcceptorResult<()>;
}

/// A listener for RMI service events.
///
/// Ported from Ghidra's `TraceRmiServiceListener`.
pub trait TraceRmiServiceListener: Send + Sync {
    /// Called when an acceptor successfully receives a connection.
    fn connection_accepted(&self, connection: &dyn TraceRmiConnectionTrait);

    /// Called when the accept operation is cancelled.
    fn accept_cancelled(&self);

    /// Called when the accept operation fails.
    fn accept_failed(&self, error: &AcceptorError);
}

/// A launch offer for Trace RMI connections.
///
/// Ported from Ghidra's `TraceRmiLaunchOffer`.
#[derive(Debug, Clone)]
pub struct TraceRmiLaunchOffer {
    /// The name of the offer (e.g., "gdb", "lldb").
    pub name: String,
    /// A description of the offer.
    pub description: String,
    /// The command to launch the backend.
    pub command: Vec<String>,
    /// Environment variables for the launch.
    pub env: Vec<(String, String)>,
    /// Whether the offer is currently available.
    pub available: bool,
}

impl TraceRmiLaunchOffer {
    /// Create a new launch offer.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            command: Vec::new(),
            env: Vec::new(),
            available: true,
        }
    }

    /// Set the command to launch.
    pub fn with_command(mut self, command: Vec<String>) -> Self {
        self.command = command;
        self
    }

    /// Set environment variables.
    pub fn with_env(mut self, env: Vec<(String, String)>) -> Self {
        self.env = env;
        self
    }

    /// Set availability.
    pub fn with_available(mut self, available: bool) -> Self {
        self.available = available;
        self
    }
}

/// Errors that can occur during RMI operations.
#[derive(Debug, Error)]
pub enum TraceRmiError {
    /// An I/O error occurred.
    #[error("RMI I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A protocol error occurred.
    #[error("RMI protocol error: {0}")]
    Protocol(String),

    /// The connection was lost.
    #[error("RMI connection lost")]
    ConnectionLost,

    /// The operation timed out.
    #[error("RMI operation timed out")]
    Timeout,

    /// The operation was cancelled.
    #[error("RMI operation cancelled")]
    Cancelled,

    /// An invalid argument was provided.
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    /// A general RMI error.
    #[error("RMI error: {0}")]
    General(String),
}

/// Result type for RMI operations.
pub type TraceRmiResult<T> = Result<T, TraceRmiError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_launch_offer_creation() {
        let offer = TraceRmiLaunchOffer::new("gdb", "GNU Debugger")
            .with_command(vec!["gdb".into(), "--interpreter=mi2".into()])
            .with_env(vec![("PATH".into(), "/usr/bin".into())]);
        assert_eq!(offer.name, "gdb");
        assert_eq!(offer.description, "GNU Debugger");
        assert_eq!(offer.command.len(), 2);
        assert_eq!(offer.env.len(), 1);
        assert!(offer.available);
    }

    #[test]
    fn test_launch_offer_unavailable() {
        let offer = TraceRmiLaunchOffer::new("gdb", "GNU Debugger")
            .with_available(false);
        assert!(!offer.available);
    }

    #[test]
    fn test_acceptor_error_display() {
        let err = AcceptorError::Cancelled;
        assert_eq!(format!("{}", err), "Accept operation was cancelled");

        let err = AcceptorError::Timeout(Duration::from_secs(10));
        assert!(format!("{}", err).contains("10s"));
    }

    #[test]
    fn test_trace_rmi_error_display() {
        let err = TraceRmiError::Protocol("bad message".into());
        assert!(format!("{}", err).contains("bad message"));

        let err = TraceRmiError::ConnectionLost;
        assert_eq!(format!("{}", err), "RMI connection lost");
    }

    #[test]
    fn test_trace_rmi_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let rmi_err: TraceRmiError = io_err.into();
        assert!(matches!(rmi_err, TraceRmiError::Io(_)));
    }

    #[test]
    fn test_acceptor_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout");
        let acc_err: AcceptorError = io_err.into();
        assert!(matches!(acc_err, AcceptorError::Io(_)));
    }
}
