//! Ghidra Server: repository management, user authentication, and remote access.
//!
//! Ported from Ghidra's `ghidra.server` and `ghidra.server.remote` Java packages.
//! Provides a Rust-native implementation of the Ghidra Server core:
//!
//! - [`GhidraServer`] -- top-level server entry-point (command-line parsing, TLS setup).
//! - [`RepositoryManager`] -- manages a set of [`Repository`] instances under a root directory.
//! - [`Repository`] -- versioned filesystem with per-user access control.
//! - [`UserManager`] -- user list, password hashing (SHA-256 salted), SSH public-key management.
//! - [`AuthenticationModule`] trait -- pluggable authentication backends.
//! - [`BlockStreamServer`] -- TCP server for efficient block-stream transfers.
//! - [`ServerAdmin`] -- CLI admin tool (`svrAdmin` equivalent).
//!
//! # Design Notes
//!
//! The original Java implementation relies heavily on Java RMI for remote
//! method invocation.  This Rust port replaces RMI with a simple
//! request/response protocol over TLS/TCP, keeping the same logical
//! structure but using `tokio`-based async I/O under the hood (the
//! public API stays synchronous for callers that do not need async).

pub mod authentication;
pub mod block_stream;
pub mod command_processor;
pub mod repository;
pub mod repository_manager;
pub mod server_admin;
pub mod user_manager;

// Re-export the most commonly used types at the crate level.
pub use authentication::{AuthMode, AuthenticationModule, PasswordFileAuthentication};
pub use block_stream::BlockStreamServer;
pub use repository::{Repository, RepositoryChangeEvent};
pub use user_manager::{Permission, User};
pub use repository_manager::RepositoryManager;
pub use user_manager::UserManager;

use std::fmt;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

/// Default RMI registry port (matching Java's GhidraServer.DEFAULT_PORT).
pub const DEFAULT_PORT: u16 = 13100;

/// The bind name used to register the server handle (analogous to Java's `BIND_NAME`).
pub const BIND_NAME: &str = "GhidraServer";

/// The alternate bind name for backward compatibility with older clients.
pub const ALT_BIND_NAME: &str = "GhidraServer-alt";

/// Server interface version, bumped on breaking changes.
pub const SERVER_INTERFACE_VERSION: u32 = 2;

/// Minimum client interface version the server will accept.
pub const SERVER_MIN_CLIENT_INTERFACE_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors produced by server operations.
#[derive(Debug, Clone)]
pub enum ServerError {
    /// An I/O error occurred.
    Io(String),
    /// The user does not have the required privilege.
    UserAccess(String),
    /// A duplicate name was provided.
    DuplicateName(String),
    /// Authentication failed.
    AuthFailed(String),
    /// The requested resource was not found.
    NotFound(String),
    /// Generic server error.
    Other(String),
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
            Self::UserAccess(msg) => write!(f, "access denied: {msg}"),
            Self::DuplicateName(msg) => write!(f, "duplicate: {msg}"),
            Self::AuthFailed(msg) => write!(f, "authentication failed: {msg}"),
            Self::NotFound(msg) => write!(f, "not found: {msg}"),
            Self::Other(msg) => write!(f, "server error: {msg}"),
        }
    }
}

impl std::error::Error for ServerError {}

impl From<std::io::Error> for ServerError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// GhidraServer (top-level)
// ---------------------------------------------------------------------------

/// The main Ghidra Server application.
///
/// Owns the [`RepositoryManager`] and the configured [`AuthenticationModule`].
/// In the original Java code this class extends `UnicastRemoteObject` and
/// implements `GhidraServerHandle`; in the Rust port it acts as the
/// application entry-point.
pub struct GhidraServer {
    /// The root directory for all repositories.
    root_dir: PathBuf,
    /// Authentication mode in use.
    auth_mode: AuthMode,
    /// The repository manager (owns all `Repository` instances).
    pub repository_manager: RepositoryManager,
    /// Whether auto-provisioning of authenticated users is enabled.
    auto_provision: bool,
    /// Optional SSH authentication module.
    ssh_auth: Option<authentication::SshAuthentication>,
    /// Optional anonymous access module.
    anonymous_auth: Option<authentication::AnonymousAuthentication>,
    /// The block-stream server (for efficient data transfer).
    pub block_stream_server: Option<BlockStreamServer>,
}

impl GhidraServer {
    /// Create a new Ghidra Server.
    ///
    /// # Arguments
    ///
    /// * `root_dir` -- root repositories directory.
    /// * `auth_mode` -- the authentication mode to use.
    /// * `allow_anonymous` -- whether anonymous access is allowed.
    /// * `auto_provision` -- auto-add authenticated users to the user list.
    /// * `support_local_passwords` -- whether the auth module uses local password files.
    /// * `default_password_expiration_days` -- days before default password expires (0 = never).
    pub fn new(
        root_dir: PathBuf,
        auth_mode: AuthMode,
        allow_anonymous: bool,
        auto_provision: bool,
        support_local_passwords: bool,
        default_password_expiration_days: i32,
    ) -> Result<Self, ServerError> {
        let repo_mgr = RepositoryManager::new(
            root_dir.clone(),
            support_local_passwords,
            default_password_expiration_days,
            allow_anonymous,
        )?;

        let anonymous_auth = if allow_anonymous {
            Some(authentication::AnonymousAuthentication)
        } else {
            None
        };

        Ok(Self {
            root_dir,
            auth_mode,
            repository_manager: repo_mgr,
            auto_provision,
            ssh_auth: None,
            anonymous_auth,
            block_stream_server: None,
        })
    }

    /// Return the root directory.
    pub fn root_dir(&self) -> &PathBuf {
        &self.root_dir
    }

    /// Return the authentication mode.
    pub fn auth_mode(&self) -> AuthMode {
        self.auth_mode
    }

    /// Check client interface compatibility.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError`] if the client version is incompatible.
    pub fn check_compatibility(&self, client_version: u32) -> Result<(), ServerError> {
        if client_version > SERVER_INTERFACE_VERSION {
            Err(ServerError::Other(
                "Incompatible server interface; a newer Ghidra Server version is required."
                    .into(),
            ))
        } else if client_version < SERVER_MIN_CLIENT_INTERFACE_VERSION {
            Err(ServerError::Other(format!(
                "Incompatible server interface; minimum supported version is {SERVER_MIN_CLIENT_INTERFACE_VERSION}"
            )))
        } else {
            Ok(())
        }
    }

    /// Authenticate a user and return their username.
    ///
    /// This corresponds to the Java `getRepositoryServer()` authentication flow.
    pub fn authenticate(
        &self,
        username: &str,
        password: Option<&str>,
    ) -> Result<String, ServerError> {
        if let Some(ref anon) = self.anonymous_auth {
            if anon.is_anonymous_request(username) {
                return Ok(UserManager::ANONYMOUS_USERNAME.to_string());
            }
        }

        let user_mgr = self.repository_manager.user_manager();
        user_mgr.authenticate_user(username, password.unwrap_or(""))?;

        if !user_mgr.is_valid_user(username) {
            if self.auto_provision {
                user_mgr.add_user(username)?;
                return Ok(username.to_string());
            }
            return Err(ServerError::AuthFailed(format!(
                "Unknown user: {username}"
            )));
        }

        Ok(username.to_string())
    }

    /// Dispose the server, shutting down the repository manager and block-stream server.
    pub fn dispose(&mut self) {
        self.repository_manager.dispose();
        if let Some(ref mut bs) = self.block_stream_server {
            bs.stop();
        }
        self.block_stream_server = None;
    }
}

impl Drop for GhidraServer {
    fn drop(&mut self) {
        self.dispose();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_error_display() {
        let e = ServerError::AuthFailed("bad password".into());
        assert!(e.to_string().contains("authentication failed"));
    }

    #[test]
    fn test_check_compatibility_ok() {
        let server = GhidraServer::new(
            std::env::temp_dir().join("ghidra_test_server"),
            AuthMode::NoAuth,
            false,
            false,
            false,
            -1,
        )
        .unwrap();
        assert!(server.check_compatibility(SERVER_INTERFACE_VERSION).is_ok());
    }

    #[test]
    fn test_check_compatibility_too_new() {
        let server = GhidraServer::new(
            std::env::temp_dir().join("ghidra_test_server2"),
            AuthMode::NoAuth,
            false,
            false,
            false,
            -1,
        )
        .unwrap();
        assert!(server
            .check_compatibility(SERVER_INTERFACE_VERSION + 1)
            .is_err());
    }

    #[test]
    fn test_auth_mode_variants() {
        assert_eq!(AuthMode::from_index(0), Some(AuthMode::PasswordFile));
        assert_eq!(AuthMode::from_index(1), Some(AuthMode::Krb5ActiveDirectory));
        assert_eq!(AuthMode::from_index(2), Some(AuthMode::Pki));
        assert_eq!(AuthMode::from_index(4), Some(AuthMode::Jaas));
        assert_eq!(AuthMode::from_index(99), None);
    }

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_PORT, 13100);
        assert_eq!(BIND_NAME, "GhidraServer");
    }
}
