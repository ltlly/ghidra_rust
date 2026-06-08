//! Remote exception sanitization and dispatch utilities.
//!
//! Ported from `ghidra.server.remote.RemoteExceptionUtil`.
//!
//! Provides functions to sanitize, log, and dispatch exceptions that occur
//! during remote server operations.  Ensures that exceptions sent to clients
//! comply with serialization requirements: IOExceptions with causes are
//! simplified to causeless IOExceptions, and unexpected exceptions are
//! wrapped as generic server errors.

use std::collections::HashSet;
use std::fmt;
use std::io;
use std::sync::OnceLock;

use crate::ghidra_server::remote_logging_util;

// ---------------------------------------------------------------------------
// Allowed IOException kinds
// ---------------------------------------------------------------------------

/// Set of `io::ErrorKind` values that are allowed to be returned to clients
/// without wrapping.  Corresponds to Java's `allowedIOExceptionClassSet`.
fn allowed_io_error_kinds() -> &'static HashSet<io::ErrorKind> {
    static ALLOWED: OnceLock<HashSet<io::ErrorKind>> = OnceLock::new();
    ALLOWED.get_or_init(|| {
        let mut set = HashSet::new();
        set.insert(io::ErrorKind::NotFound);
        set.insert(io::ErrorKind::PermissionDenied);
        set.insert(io::ErrorKind::AlreadyExists);
        set.insert(io::ErrorKind::InvalidInput);
        set.insert(io::ErrorKind::InvalidData);
        set.insert(io::ErrorKind::BrokenPipe);
        set.insert(io::ErrorKind::ConnectionRefused);
        set.insert(io::ErrorKind::ConnectionReset);
        set.insert(io::ErrorKind::ConnectionAborted);
        set.insert(io::ErrorKind::NotConnected);
        set.insert(io::ErrorKind::AddrInUse);
        set.insert(io::ErrorKind::AddrNotAvailable);
        set.insert(io::ErrorKind::UnexpectedEof);
        set
    })
}

// ---------------------------------------------------------------------------
// ServerRemoteError
// ---------------------------------------------------------------------------

/// Error type returned to remote clients for unexpected server failures.
///
/// Analogous to Java's `RemoteException` wrapper used by
/// `RemoteExceptionUtil.dispatchIOException`.
#[derive(Debug, Clone)]
pub struct ServerRemoteError {
    message: String,
}

impl ServerRemoteError {
    /// Create a new `ServerRemoteError` with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Return the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ServerRemoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unexpected Server Error: {}", self.message)
    }
}

impl std::error::Error for ServerRemoteError {}

// ---------------------------------------------------------------------------
// Dispatch functions
// ---------------------------------------------------------------------------

/// Sanitize, log, and dispatch an exception for return to the client.
///
/// This is the simple two-argument form matching Java's
/// `dispatchIOException(Throwable, String, String)`.
///
/// # Arguments
///
/// * `err` -- the original error.
/// * `log_detail` -- a description of the operation that failed (required).
/// * `user` -- the user name, if known; `None` otherwise.
///
/// # Returns
///
/// An `io::Error` suitable for sending to the client.
pub fn dispatch_io_error(err: &(dyn std::error::Error + 'static), log_detail: &str, user: Option<&str>) -> io::Error {
    dispatch_io_error_with_context(err, None, None, log_detail, user)
}

/// Sanitize, log, and dispatch an exception for return to the client, with
/// optional repository and path context.
///
/// This is the full five-argument form matching Java's
/// `dispatchIOException(Throwable, String, String, String, String)`.
///
/// # Arguments
///
/// * `err` -- the original error.
/// * `repository_name` -- the repository name, or `None`.
/// * `path` -- the repository file/folder path, or `None`.
/// * `log_detail` -- a description of the operation that failed (required).
/// * `user` -- the user name, if known; `None` otherwise.
///
/// # Returns
///
/// An `io::Error` suitable for sending to the client.
pub fn dispatch_io_error_with_context(
    err: &(dyn std::error::Error + 'static),
    repository_name: Option<&str>,
    path: Option<&str>,
    log_detail: &str,
    user: Option<&str>,
) -> io::Error {
    let err_string = err.to_string();

    // If this is already an io::Error with an allowed kind, return it as-is.
    if let Some(io_err) = err.downcast_ref::<io::Error>() {
        let kind = io_err.kind();
        if allowed_io_error_kinds().contains(&kind) {
            return io::Error::new(kind, io_err.to_string());
        }
    }

    // Log the full error with context.
    log::error!("Error: {}", err_string);

    // Log the server-side operation detail.
    remote_logging_util::log_with_context(
        repository_name,
        path,
        &format!("ERROR: {log_detail}"),
        user,
        true,
    );

    // Return a simplified io::Error without cause chain.
    io::Error::new(io::ErrorKind::Other, err_string)
}

/// Dispatch a non-IO exception as a generic server error.
///
/// For exceptions that are not `io::Error` (e.g., runtime errors, panics),
/// this function logs the error and returns an `io::Error` wrapping a
/// `ServerRemoteError`.
pub fn dispatch_unexpected_error(
    err: &dyn std::error::Error,
    repository_name: Option<&str>,
    path: Option<&str>,
    log_detail: &str,
    user: Option<&str>,
) -> io::Error {
    let err_string = err.to_string();
    let exc_kind = "Error";

    remote_logging_util::log_with_context(
        repository_name,
        path,
        &format!("ERROR: {log_detail}"),
        user,
        true,
    );
    log::error!("{}: {}", exc_kind, err_string);

    io::Error::new(
        io::ErrorKind::Other,
        ServerRemoteError::new(format!("Unexpected Server {exc_kind}")),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dispatch_io_error_not_found() {
        let err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let dispatched = dispatch_io_error(&err, "read file", Some("admin"));
        // Allowed kind, no cause -- should pass through.
        assert_eq!(dispatched.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn test_dispatch_io_error_other() {
        let err = io::Error::new(io::ErrorKind::Other, "something broke");
        let dispatched = dispatch_io_error(&err, "write data", None);
        assert_eq!(dispatched.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn test_server_remote_error_display() {
        let err = ServerRemoteError::new("internal failure");
        assert!(err.to_string().contains("Unexpected Server Error"));
        assert_eq!(err.message(), "internal failure");
    }

    #[test]
    fn test_dispatch_unexpected_error() {
        let inner = io::Error::new(io::ErrorKind::Other, "unexpected");
        let dispatched =
            dispatch_unexpected_error(&inner, Some("repo"), Some("/path"), "operation", None);
        assert_eq!(dispatched.kind(), io::ErrorKind::Other);
    }
}
