//! ClearExternalPathCmd -- command for clearing an external program path.
//!
//! Ported from `ghidra.app.cmd.refs.ClearExternalPathCmd`.
//!
//! This command clears the external program path associated with an
//! external Library.  The library must already exist; the command does
//! not create libraries.  If the library is not found, the command
//! fails with an appropriate status message.

use std::fmt;

use super::external_manager_db::ExternalManagerDB;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors that can occur when clearing an external program path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClearExternalPathError {
    /// The specified library was not found.
    LibraryNotFound(String),
    /// Invalid input provided.
    InvalidInput(String),
    /// General error.
    Other(String),
}

impl fmt::Display for ClearExternalPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClearExternalPathError::LibraryNotFound(name) => {
                write!(f, "Library not found: {}", name)
            }
            ClearExternalPathError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            ClearExternalPathError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ClearExternalPathError {}

// ---------------------------------------------------------------------------
// ClearExternalPathCmd
// ---------------------------------------------------------------------------

/// Command for clearing the external program path associated with an
/// external Library.
///
/// This is the Rust port of Ghidra's `ClearExternalPathCmd`.  It
/// clears (removes) the associated external program path from an
/// existing library.  The library must already exist; this command
/// does not create new libraries.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::{ClearExternalPathCmd, ExternalManagerDB};
/// use ghidra_core::symbol::SourceType;
///
/// let mut mgr = ExternalManagerDB::new();
/// mgr.set_external_path("libc", "/usr/lib/libc.so", true).unwrap();
///
/// let mut cmd = ClearExternalPathCmd::new("libc");
/// assert!(cmd.apply_to(&mut mgr));
/// assert!(mgr.get_external_library_path("libc").is_none());
/// ```
#[derive(Debug, Clone)]
pub struct ClearExternalPathCmd {
    /// The external library name whose path should be cleared.
    external_name: String,
    /// Whether this is a user-defined path (always `true` in the
    /// original Java implementation).
    user_defined: bool,
    /// Error message from the last execution, if any.
    status: Option<String>,
}

impl ClearExternalPathCmd {
    /// Create a new command for clearing the external program path
    /// associated with the specified external Library.
    ///
    /// # Arguments
    ///
    /// * `external_name` -- the external Library name.
    pub fn new(external_name: impl Into<String>) -> Self {
        Self {
            external_name: external_name.into(),
            user_defined: true,
            status: None,
        }
    }

    /// Create a new command with explicit user-defined flag.
    ///
    /// # Arguments
    ///
    /// * `external_name` -- the external Library name.
    /// * `user_defined` -- whether the path is user-defined.
    pub fn with_user_defined(
        external_name: impl Into<String>,
        user_defined: bool,
    ) -> Self {
        Self {
            external_name: external_name.into(),
            user_defined,
            status: None,
        }
    }

    /// Execute the command against the given external manager.
    ///
    /// Returns `true` if the path was successfully cleared, `false`
    /// otherwise.  On failure, [`status_msg`](Self::status_msg)
    /// contains a description of the error.
    pub fn apply_to(&mut self, ext_mgr: &mut ExternalManagerDB) -> bool {
        self.status = None;

        // Avoid creating the Library if it does not already exist
        if !ext_mgr.contains_library(&self.external_name) {
            self.status = Some(format!("Library not found: {}", self.external_name));
            return false;
        }

        // Clear the path by setting it to an empty string, then removing
        // the path entry.  The external_manager_db stores path as
        // Option<String>, so we clear it via set_external_path and then
        // remove it manually since set_external_path sets a value.
        if let Some(info) = ext_mgr.get_library_info_mut(&self.external_name) {
            info.path = None;
            return true;
        }

        self.status = Some(format!("Library not found: {}", self.external_name));
        false
    }

    /// Returns the command name.
    pub fn name(&self) -> &str {
        "Clear External Library Path"
    }

    /// Returns the status message from the last execution, if any.
    pub fn status_msg(&self) -> Option<&str> {
        self.status.as_deref()
    }

    /// Returns the external library name this command targets.
    pub fn external_name(&self) -> &str {
        &self.external_name
    }

    /// Returns whether the path is user-defined.
    pub fn user_defined(&self) -> bool {
        self.user_defined
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::symbol::SourceType;

    #[test]
    fn test_clear_external_path() {
        let mut mgr = ExternalManagerDB::new();
        mgr.set_external_path("libc", "/usr/lib/libc.so", true)
            .unwrap();
        assert_eq!(
            mgr.get_external_library_path("libc"),
            Some("/usr/lib/libc.so")
        );

        let mut cmd = ClearExternalPathCmd::new("libc");
        assert!(cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_none());
        assert!(mgr.get_external_library_path("libc").is_none());
    }

    #[test]
    fn test_clear_path_of_nonexistent_library() {
        let mut mgr = ExternalManagerDB::new();
        let mut cmd = ClearExternalPathCmd::new("nonexistent");

        assert!(!cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_some());
        assert!(cmd.status_msg().unwrap().contains("Library not found"));
    }

    #[test]
    fn test_clear_path_library_without_path() {
        let mut mgr = ExternalManagerDB::new();
        mgr.add_library("libc", SourceType::Imported).unwrap();

        let mut cmd = ClearExternalPathCmd::new("libc");
        assert!(cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_none());
        assert!(mgr.get_external_library_path("libc").is_none());
    }

    #[test]
    fn test_command_name() {
        let cmd = ClearExternalPathCmd::new("libc");
        assert_eq!(cmd.name(), "Clear External Library Path");
    }

    #[test]
    fn test_external_name_accessor() {
        let cmd = ClearExternalPathCmd::new("kernel32.dll");
        assert_eq!(cmd.external_name(), "kernel32.dll");
    }

    #[test]
    fn test_user_defined_default() {
        let cmd = ClearExternalPathCmd::new("libc");
        assert!(cmd.user_defined());
    }

    #[test]
    fn test_with_user_defined_false() {
        let cmd = ClearExternalPathCmd::with_user_defined("libc", false);
        assert!(!cmd.user_defined());
    }

    #[test]
    fn test_initial_status_is_none() {
        let cmd = ClearExternalPathCmd::new("libc");
        assert!(cmd.status_msg().is_none());
    }

    #[test]
    fn test_clone() {
        let cmd = ClearExternalPathCmd::new("libc");
        let cloned = cmd.clone();
        assert_eq!(cloned.external_name(), "libc");
    }

    #[test]
    fn test_status_resets_on_reapply() {
        let mut mgr = ExternalManagerDB::new();
        let mut cmd = ClearExternalPathCmd::new("nonexistent");

        // First attempt fails
        assert!(!cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_some());

        // Add the library and try again
        mgr.add_library("nonexistent", SourceType::Imported).unwrap();
        assert!(cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_none());
    }

    #[test]
    fn test_clear_path_preserves_library() {
        let mut mgr = ExternalManagerDB::new();
        mgr.set_external_path("libc", "/usr/lib/libc.so", true)
            .unwrap();

        let mut cmd = ClearExternalPathCmd::new("libc");
        assert!(cmd.apply_to(&mut mgr));

        // Library should still exist, just without a path
        assert!(mgr.contains_library("libc"));
        assert!(mgr.get_external_library_path("libc").is_none());
    }

    #[test]
    fn test_clear_path_multiple_libraries() {
        let mut mgr = ExternalManagerDB::new();
        mgr.set_external_path("libc", "/usr/lib/libc.so", true)
            .unwrap();
        mgr.set_external_path("libm", "/usr/lib/libm.so", true)
            .unwrap();

        let mut cmd = ClearExternalPathCmd::new("libc");
        assert!(cmd.apply_to(&mut mgr));

        // libc path cleared, libm path preserved
        assert!(mgr.get_external_library_path("libc").is_none());
        assert_eq!(
            mgr.get_external_library_path("libm"),
            Some("/usr/lib/libm.so")
        );
    }

    #[test]
    fn test_clear_path_twice() {
        let mut mgr = ExternalManagerDB::new();
        mgr.set_external_path("libc", "/usr/lib/libc.so", true)
            .unwrap();

        let mut cmd = ClearExternalPathCmd::new("libc");
        assert!(cmd.apply_to(&mut mgr));

        // Second call should still succeed (path already cleared)
        assert!(cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_none());
    }
}
