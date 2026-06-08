//! Remote logging utilities for the Ghidra Server.
//!
//! Ported from `ghidra.server.remote.RemoteLoggingUtil`.
//!
//! Provides structured log message formatting that includes repository name,
//! path, message, user, and client host information -- matching the Java
//! server's logging conventions.

use std::sync::Mutex;

// ---------------------------------------------------------------------------
// Thread-local client context
// ---------------------------------------------------------------------------

/// The RMI client hostname for the current thread/operation.
///
/// In the Java implementation this is set via `RepositoryManager.setRMIClient()`.
/// In the Rust port we use a simple global mutex; a production implementation
/// would use a request-scoped context.
static RMI_CLIENT: Mutex<Option<String>> = Mutex::new(None);

/// Set the RMI client hostname for the current context.
///
/// Matches Java's `RepositoryManager.setRMIClient(String)`.
pub fn set_rmi_client(client: Option<&str>) {
    let mut guard = RMI_CLIENT.lock().unwrap();
    *guard = client.map(|s| s.to_string());
}

/// Get the RMI client hostname for the current context.
///
/// Matches Java's `RepositoryManager.getRMIClient()`.
pub fn get_rmi_client() -> Option<String> {
    RMI_CLIENT.lock().unwrap().clone()
}

// ---------------------------------------------------------------------------
// Logging functions
// ---------------------------------------------------------------------------

/// Log an informational message (no repository context).
///
/// Format: `msg (host)`
///
/// Matches Java's `RemoteLoggingUtil.log(String)`.
pub fn log(msg: &str) {
    log_with_context(None, None, msg, None, false);
}

/// Log an informational message with user details.
///
/// Format: `msg (user@host)`
///
/// Matches Java's `RemoteLoggingUtil.log(String, String)`.
pub fn log_with_user(msg: &str, user: &str) {
    log_with_context(None, None, msg, Some(user), false);
}

/// Log a message with full repository, path, user, and error context.
///
/// Format: `[repositoryName]path: msg (user@host)`
///
/// Any of `repository_name`, `path`, or `user` may be `None` and will be
/// omitted from the formatted output.
///
/// Matches Java's `RemoteLoggingUtil.log(String, String, String, String, boolean)`.
pub fn log_with_context(
    repository_name: Option<&str>,
    path: Option<&str>,
    msg: &str,
    user: Option<&str>,
    error: bool,
) {
    let mut buf = String::new();

    if let Some(repo) = repository_name {
        buf.push('[');
        buf.push_str(repo);
        buf.push(']');
    }

    let host = get_rmi_client();

    let user_str = match (user, &host) {
        (Some(u), Some(h)) => Some(format!("{u}@{h}")),
        (Some(u), None) => Some(u.to_string()),
        (None, Some(h)) => Some(h.clone()),
        (None, None) => None,
    };

    if let Some(p) = path {
        buf.push_str(p);
    }

    if repository_name.is_some() || path.is_some() {
        buf.push_str(": ");
    }

    buf.push_str(msg);

    if let Some(ref u) = user_str {
        buf.push_str(" (");
        buf.push_str(u);
        buf.push(')');
    }

    if error {
        log::error!("{}", buf);
    } else {
        log::info!("{}", buf);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_get_rmi_client() {
        set_rmi_client(Some("testhost"));
        assert_eq!(get_rmi_client(), Some("testhost".to_string()));
        set_rmi_client(None);
        assert_eq!(get_rmi_client(), None);
    }

    #[test]
    fn test_log_with_context_full() {
        // Should not panic -- exercises the formatting path.
        set_rmi_client(Some("client.example.com"));
        log_with_context(
            Some("MyRepo"),
            Some("/path/to/file"),
            "operation completed",
            Some("admin"),
            false,
        );
        set_rmi_client(None);
    }

    #[test]
    fn test_log_with_context_minimal() {
        log_with_context(None, None, "bare message", None, true);
    }

    #[test]
    fn test_log_with_user() {
        set_rmi_client(Some("host1"));
        log_with_user("user login", "alice");
        set_rmi_client(None);
    }
}
