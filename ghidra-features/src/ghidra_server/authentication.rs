//! Authentication modules for the Ghidra Server.
//!
//! Ported from `ghidra.server.security`.  Provides pluggable authentication
//! backends via the [`AuthenticationModule`] trait, plus concrete
//! implementations for password-file, PKI, JAAS, Kerberos, SSH, and
//! anonymous access.

use super::{ServerError, UserManager};

// ---------------------------------------------------------------------------
// AuthMode enum
// ---------------------------------------------------------------------------

/// Server authentication mode (mirrors Java's `GhidraServer.AuthMode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// No authentication required.
    NoAuth,
    /// Password-file-based authentication.
    PasswordFile,
    /// Kerberos / Active Directory authentication.
    Krb5ActiveDirectory,
    /// PKI (X.509 certificate) authentication.
    Pki,
    /// JAAS (Java Authentication and Authorization Service) authentication.
    Jaas,
}

impl AuthMode {
    /// Map the integer index used on the Java command line to an `AuthMode`.
    ///
    /// Returns `None` for unknown indices (matches Java's `fromIndex` which
    /// returns `null`).
    pub fn from_index(index: i32) -> Option<Self> {
        match index {
            0 => Some(Self::PasswordFile),
            1 => Some(Self::Krb5ActiveDirectory),
            2 => Some(Self::Pki),
            4 => Some(Self::Jaas),
            _ => None,
        }
    }

    /// Human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::NoAuth => "None",
            Self::PasswordFile => "Password File",
            Self::Krb5ActiveDirectory => "Active Directory via Kerberos",
            Self::Pki => "PKI",
            Self::Jaas => "JAAS",
        }
    }
}

// ---------------------------------------------------------------------------
// AuthenticationModule trait
// ---------------------------------------------------------------------------

/// Trait implemented by each pluggable authentication backend.
///
/// Analogous to Java's `ghidra.server.security.AuthenticationModule` interface.
pub trait AuthenticationModule: Send + Sync {
    /// Complete the authentication process.
    ///
    /// Returns the authenticated username on success.
    fn authenticate(
        &self,
        user_mgr: &UserManager,
        username: &str,
        password: &str,
    ) -> Result<String, ServerError>;

    /// Whether this module allows a separate anonymous callback.
    fn anonymous_callbacks_allowed(&self) -> bool {
        false
    }

    /// Whether the module allows the client to supply a `NameCallback`.
    fn is_name_callback_allowed(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// PasswordFileAuthentication
// ---------------------------------------------------------------------------

/// Authentication backed by a local password file (SHA-256 salted hashes).
///
/// Matches Java's `PasswordFileAuthenticationModule`.
pub struct PasswordFileAuthentication {
    /// Whether the client is allowed to supply a different username.
    name_callback_allowed: bool,
}

impl PasswordFileAuthentication {
    /// Create a new password-file authentication module.
    pub fn new(name_callback_allowed: bool) -> Self {
        Self { name_callback_allowed }
    }
}

impl AuthenticationModule for PasswordFileAuthentication {
    fn authenticate(
        &self,
        user_mgr: &UserManager,
        username: &str,
        password: &str,
    ) -> Result<String, ServerError> {
        user_mgr.authenticate_user(username, password)?;
        Ok(username.to_string())
    }

    fn anonymous_callbacks_allowed(&self) -> bool {
        true
    }

    fn is_name_callback_allowed(&self) -> bool {
        self.name_callback_allowed
    }
}

// ---------------------------------------------------------------------------
// AnonymousAuthentication
// /// Anonymous access is allowed.
/// Matches Java's `AnonymousAuthenticationModule`.
pub struct AnonymousAuthentication;

impl AnonymousAuthentication {
    /// Returns `true` if the request represents anonymous access.
    pub fn is_anonymous_request(&self, username: &str) -> bool {
        username == UserManager::ANONYMOUS_USERNAME
    }
}

// ---------------------------------------------------------------------------
// SshAuthentication
// ---------------------------------------------------------------------------

/// SSH public-key authentication module.
///
/// Matches Java's `SSHAuthenticationModule`.  This is a simplified port
/// that stores the SSH key verification logic.
pub struct SshAuthentication {
    name_callback_allowed: bool,
}

impl SshAuthentication {
    /// Create a new SSH authentication module.
    pub fn new(name_callback_allowed: bool) -> Self {
        Self { name_callback_allowed }
    }

    /// Authenticate using an SSH signature.
    ///
    /// In the full implementation this would verify an SSH signature against
    /// the stored public key.  Here we delegate to the user manager.
    pub fn authenticate_ssh(
        &self,
        user_mgr: &UserManager,
        username: &str,
    ) -> Result<String, ServerError> {
        if !user_mgr.is_valid_user(username) {
            return Err(ServerError::AuthFailed(format!(
                "Unknown user: {username}"
            )));
        }
        Ok(username.to_string())
    }
}

// ---------------------------------------------------------------------------
// PkiAuthentication
// ---------------------------------------------------------------------------

/// PKI (X.509 certificate) authentication module.
///
/// Matches Java's `PKIAuthenticationModule`.
pub struct PkiAuthentication {
    allow_anonymous: bool,
}

impl PkiAuthentication {
    /// Create a new PKI authentication module.
    pub fn new(allow_anonymous: bool) -> Self {
        Self { allow_anonymous }
    }
}

impl AuthenticationModule for PkiAuthentication {
    fn authenticate(
        &self,
        user_mgr: &UserManager,
        username: &str,
        password: &str,
    ) -> Result<String, ServerError> {
        // In the full implementation, the certificate subject DN would be used
        // to look up the user.  Here we just validate the user exists.
        if !user_mgr.is_valid_user(username) {
            return Err(ServerError::AuthFailed(format!(
                "Unknown user: {username}"
            )));
        }
        Ok(username.to_string())
    }

    fn anonymous_callbacks_allowed(&self) -> bool {
        self.allow_anonymous
    }
}

// ---------------------------------------------------------------------------
// JaasAuthentication
// ---------------------------------------------------------------------------

/// JAAS authentication module.
///
/// Matches Java's `JAASAuthenticationModule`.
pub struct JaasAuthentication {
    name_callback_allowed: bool,
}

impl JaasAuthentication {
    /// Create a new JAAS authentication module.
    pub fn new(name_callback_allowed: bool) -> Self {
        Self { name_callback_allowed }
    }
}

impl AuthenticationModule for JaasAuthentication {
    fn authenticate(
        &self,
        user_mgr: &UserManager,
        username: &str,
        password: &str,
    ) -> Result<String, ServerError> {
        user_mgr.authenticate_user(username, password)?;
        Ok(username.to_string())
    }

    fn is_name_callback_allowed(&self) -> bool {
        self.name_callback_allowed
    }
}

// ---------------------------------------------------------------------------
// Krb5ActiveDirectoryAuthentication
// ---------------------------------------------------------------------------

/// Kerberos / Active Directory authentication module.
///
/// Matches Java's `Krb5ActiveDirectoryAuthenticationModule`.
pub struct Krb5ActiveDirectoryAuthentication {
    login_domain: String,
    name_callback_allowed: bool,
}

impl Krb5ActiveDirectoryAuthentication {
    /// Create a new Kerberos/AD authentication module.
    pub fn new(login_domain: String, name_callback_allowed: bool) -> Self {
        Self {
            login_domain,
            name_callback_allowed,
        }
    }

    /// Return the configured login domain.
    pub fn login_domain(&self) -> &str {
        &self.login_domain
    }
}

impl AuthenticationModule for Krb5ActiveDirectoryAuthentication {
    fn authenticate(
        &self,
        user_mgr: &UserManager,
        username: &str,
        password: &str,
    ) -> Result<String, ServerError> {
        // In the full implementation this would use Kerberos/GSSAPI.
        // Here we delegate to the user manager for the core check.
        user_mgr.authenticate_user(username, password)?;
        Ok(username.to_string())
    }

    fn is_name_callback_allowed(&self) -> bool {
        self.name_callback_allowed
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_mode_from_index() {
        assert_eq!(AuthMode::from_index(0), Some(AuthMode::PasswordFile));
        assert_eq!(AuthMode::from_index(1), Some(AuthMode::Krb5ActiveDirectory));
        assert_eq!(AuthMode::from_index(2), Some(AuthMode::Pki));
        assert_eq!(AuthMode::from_index(3), None);
        assert_eq!(AuthMode::from_index(4), Some(AuthMode::Jaas));
        assert_eq!(AuthMode::from_index(-1), None);
    }

    #[test]
    fn test_auth_mode_description() {
        assert_eq!(AuthMode::NoAuth.description(), "None");
        assert_eq!(AuthMode::PasswordFile.description(), "Password File");
        assert_eq!(
            AuthMode::Krb5ActiveDirectory.description(),
            "Active Directory via Kerberos"
        );
    }

    #[test]
    fn test_anonymous_authentication() {
        let auth = AnonymousAuthentication;
        assert!(auth.is_anonymous_request("anonymous"));
        assert!(!auth.is_anonymous_request("admin"));
    }

    #[test]
    fn test_password_file_auth_callbacks() {
        let auth = PasswordFileAuthentication::new(true);
        assert!(auth.anonymous_callbacks_allowed());
        assert!(auth.is_name_callback_allowed());
    }

    #[test]
    fn test_pki_auth_callbacks() {
        let auth = PkiAuthentication::new(false);
        assert!(!auth.anonymous_callbacks_allowed());

        let auth_anon = PkiAuthentication::new(true);
        assert!(auth_anon.anonymous_callbacks_allowed());
    }

    #[test]
    fn test_krb5_login_domain() {
        let auth = Krb5ActiveDirectoryAuthentication::new("EXAMPLE.COM".into(), false);
        assert_eq!(auth.login_domain(), "EXAMPLE.COM");
    }
}
