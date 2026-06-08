//! RemoveExternalNameCmd -- command for removing an external program name.
//!
//! Ported from `ghidra.app.cmd.refs.RemoveExternalNameCmd`.
//!
//! This command removes an external library name from the program's
//! external manager.  The library must not have any associated external
//! locations for the removal to succeed.  The special `<UNKNOWN>`
//! library cannot be removed.

use std::fmt;

use super::external_manager_db::ExternalManagerDB;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors that can occur when removing an external program name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoveExternalNameError {
    /// The library could not be removed (e.g., it still has locations,
    /// or it is the special UNKNOWN library).
    CannotRemove(String),
    /// General error.
    Other(String),
}

impl fmt::Display for RemoveExternalNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RemoveExternalNameError::CannotRemove(name) => {
                write!(f, "{} can not be removed", name)
            }
            RemoveExternalNameError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for RemoveExternalNameError {}

// ---------------------------------------------------------------------------
// RemoveExternalNameCmd
// ---------------------------------------------------------------------------

/// Command for removing an external program (library) name.
///
/// This is the Rust port of Ghidra's `RemoveExternalNameCmd`.  It
/// removes a library entry from the external manager.  The removal
/// fails if the library still has associated external locations or if
/// the library is the special `<UNKNOWN>` library.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::{RemoveExternalNameCmd, ExternalManagerDB};
/// use ghidra_core::symbol::SourceType;
///
/// let mut mgr = ExternalManagerDB::new();
/// mgr.add_library("libc", SourceType::Imported).unwrap();
///
/// let mut cmd = RemoveExternalNameCmd::new("libc");
/// assert!(cmd.apply_to(&mut mgr));
/// assert!(!mgr.contains_library("libc"));
/// ```
#[derive(Debug, Clone)]
pub struct RemoveExternalNameCmd {
    /// The library name to remove.
    external_name: String,
    /// Error message from the last execution, if any.
    status: Option<String>,
}

impl RemoveExternalNameCmd {
    /// Create a new command to remove an external library name.
    ///
    /// # Arguments
    ///
    /// * `external_name` -- the name of the external program to remove.
    pub fn new(external_name: impl Into<String>) -> Self {
        Self {
            external_name: external_name.into(),
            status: None,
        }
    }

    /// Execute the command against the given external manager.
    ///
    /// Returns `true` if the library was successfully removed, `false`
    /// otherwise.  On failure, [`status_msg`](Self::status_msg) contains
    /// a description of the error.
    pub fn apply_to(&mut self, ext_mgr: &mut ExternalManagerDB) -> bool {
        self.status = None;

        if !ext_mgr.remove_library(&self.external_name) {
            self.status = Some(format!("{} can not be removed", self.external_name));
            return false;
        }
        true
    }

    /// Returns the command name.
    pub fn name(&self) -> &str {
        "Remove External Program Name"
    }

    /// Returns the status message from the last execution, if any.
    pub fn status_msg(&self) -> Option<&str> {
        self.status.as_deref()
    }

    /// Returns the library name this command targets.
    pub fn external_name(&self) -> &str {
        &self.external_name
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;
    use ghidra_core::symbol::SourceType;

    #[test]
    fn test_remove_external_name() {
        let mut mgr = ExternalManagerDB::new();
        mgr.add_library("libc", SourceType::Imported).unwrap();
        assert!(mgr.contains_library("libc"));

        let mut cmd = RemoveExternalNameCmd::new("libc");
        assert!(cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_none());
        assert!(!mgr.contains_library("libc"));
    }

    #[test]
    fn test_remove_nonexistent_library() {
        let mut mgr = ExternalManagerDB::new();
        let mut cmd = RemoveExternalNameCmd::new("nonexistent");

        assert!(!cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_some());
        assert!(cmd.status_msg().unwrap().contains("can not be removed"));
    }

    #[test]
    fn test_remove_library_with_locations_fails() {
        let mut mgr = ExternalManagerDB::new();
        mgr.add_ext_function("libc", "printf", None, SourceType::Imported)
            .unwrap();

        let mut cmd = RemoveExternalNameCmd::new("libc");
        assert!(!cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_some());
        assert!(mgr.contains_library("libc"));
    }

    #[test]
    fn test_command_name() {
        let cmd = RemoveExternalNameCmd::new("libc");
        assert_eq!(cmd.name(), "Remove External Program Name");
    }

    #[test]
    fn test_external_name_accessor() {
        let cmd = RemoveExternalNameCmd::new("kernel32.dll");
        assert_eq!(cmd.external_name(), "kernel32.dll");
    }

    #[test]
    fn test_initial_status_is_none() {
        let cmd = RemoveExternalNameCmd::new("libc");
        assert!(cmd.status_msg().is_none());
    }

    #[test]
    fn test_remove_after_removing_locations() {
        let mut mgr = ExternalManagerDB::new();
        mgr.add_ext_function("libc", "printf", None, SourceType::Imported)
            .unwrap();

        // Cannot remove while locations exist
        let mut cmd = RemoveExternalNameCmd::new("libc");
        assert!(!cmd.apply_to(&mut mgr));

        // Remove the location first
        mgr.remove_external_location_by_name("libc", "printf");

        // Now removal should succeed
        assert!(cmd.apply_to(&mut mgr));
        assert!(!mgr.contains_library("libc"));
    }

    #[test]
    fn test_clone() {
        let cmd = RemoveExternalNameCmd::new("libc");
        let cloned = cmd.clone();
        assert_eq!(cloned.external_name(), "libc");
    }

    #[test]
    fn test_remove_multiple_libraries() {
        let mut mgr = ExternalManagerDB::new();
        mgr.add_library("libc", SourceType::Imported).unwrap();
        mgr.add_library("libm", SourceType::Imported).unwrap();
        mgr.add_library("libpthread", SourceType::Imported).unwrap();
        assert_eq!(mgr.library_count(), 3);

        let mut cmd = RemoveExternalNameCmd::new("libm");
        assert!(cmd.apply_to(&mut mgr));
        assert_eq!(mgr.library_count(), 2);
        assert!(!mgr.contains_library("libm"));
        assert!(mgr.contains_library("libc"));
        assert!(mgr.contains_library("libpthread"));
    }

    #[test]
    fn test_status_resets_on_reapply() {
        let mut mgr = ExternalManagerDB::new();
        let mut cmd = RemoveExternalNameCmd::new("nonexistent");

        // First attempt fails
        assert!(!cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_some());

        // Add the library and try again
        mgr.add_library("nonexistent", SourceType::Imported).unwrap();
        assert!(cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_none());
    }
}
