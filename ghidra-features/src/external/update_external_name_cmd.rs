//! UpdateExternalNameCmd -- command for updating an external program name.
//!
//! Ported from `ghidra.app.cmd.refs.UpdateExternalNameCmd`.
//!
//! This command renames an existing external library in the program's
//! external manager.  The new name must be non-empty and not already
//! in use by another library.

use std::fmt;

use ghidra_core::symbol::SourceType;

use super::external_location_db::ExternalLocationError;
use super::external_manager_db::ExternalManagerDB;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors that can occur when updating an external program name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateExternalNameError {
    /// A library with the new name already exists.
    DuplicateName(String),
    /// The supplied new name is invalid.
    InvalidInput(String),
    /// The old library was not found.
    NotFound(String),
    /// General error.
    Other(String),
}

impl fmt::Display for UpdateExternalNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpdateExternalNameError::DuplicateName(name) => {
                write!(f, "{} already exists", name)
            }
            UpdateExternalNameError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            UpdateExternalNameError::NotFound(name) => {
                write!(f, "Library '{}' not found", name)
            }
            UpdateExternalNameError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for UpdateExternalNameError {}

impl From<ExternalLocationError> for UpdateExternalNameError {
    fn from(e: ExternalLocationError) -> Self {
        match e {
            ExternalLocationError::DuplicateName(name) => {
                UpdateExternalNameError::DuplicateName(name)
            }
            ExternalLocationError::InvalidInput(msg) => {
                UpdateExternalNameError::InvalidInput(msg)
            }
            ExternalLocationError::Other(msg) if msg.contains("not found") => {
                UpdateExternalNameError::NotFound(msg)
            }
            _ => UpdateExternalNameError::Other(e.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// UpdateExternalNameCmd
// ---------------------------------------------------------------------------

/// Command for updating (renaming) an external program (library) name.
///
/// This is the Rust port of Ghidra's `UpdateExternalNameCmd`.  It
/// renames an existing library entry in the external manager.  The new
/// name must be non-empty and must not already be in use.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::{UpdateExternalNameCmd, ExternalManagerDB};
/// use ghidra_core::symbol::SourceType;
///
/// let mut mgr = ExternalManagerDB::new();
/// mgr.add_library("old_lib", SourceType::Imported).unwrap();
///
/// let mut cmd = UpdateExternalNameCmd::new("old_lib", "new_lib", SourceType::UserDefined);
/// assert!(cmd.apply_to(&mut mgr));
/// assert!(!mgr.contains_library("old_lib"));
/// assert!(mgr.contains_library("new_lib"));
/// ```
#[derive(Debug, Clone)]
pub struct UpdateExternalNameCmd {
    /// The current library name.
    old_name: String,
    /// The new library name.
    new_name: String,
    /// The source type to apply when renaming.
    source: SourceType,
    /// Error message from the last execution, if any.
    status: Option<String>,
}

impl UpdateExternalNameCmd {
    /// Create a new command to update an external library name.
    ///
    /// # Arguments
    ///
    /// * `old_name` -- the current name of the external program.
    /// * `new_name` -- the new name for the external program (required,
    ///   must be non-empty).
    /// * `source` -- the source of this external name.
    ///
    /// # Panics
    ///
    /// Panics if `new_name` is empty.
    pub fn new(
        old_name: impl Into<String>,
        new_name: impl Into<String>,
        source: SourceType,
    ) -> Self {
        let n = new_name.into();
        assert!(!n.is_empty(), "newName is invalid");
        Self {
            old_name: old_name.into(),
            new_name: n,
            source,
            status: None,
        }
    }

    /// Execute the command against the given external manager.
    ///
    /// Returns `true` if the library was successfully renamed, `false`
    /// otherwise.  On failure, [`status_msg`](Self::status_msg) contains
    /// a description of the error.
    pub fn apply_to(&mut self, ext_mgr: &mut ExternalManagerDB) -> bool {
        self.status = None;

        match ext_mgr.update_library_name(&self.old_name, &self.new_name, self.source) {
            Ok(()) => true,
            Err(e) => {
                self.status = Some(e.to_string());
                false
            }
        }
    }

    /// Returns the command name.
    pub fn name(&self) -> &str {
        "Update External Program Name"
    }

    /// Returns the status message from the last execution, if any.
    pub fn status_msg(&self) -> Option<&str> {
        self.status.as_deref()
    }

    /// Returns the old library name.
    pub fn old_name(&self) -> &str {
        &self.old_name
    }

    /// Returns the new library name.
    pub fn new_name(&self) -> &str {
        &self.new_name
    }

    /// Returns the source type.
    pub fn source(&self) -> SourceType {
        self.source
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_external_name() {
        let mut mgr = ExternalManagerDB::new();
        mgr.add_library("old_lib", SourceType::Imported).unwrap();

        let mut cmd =
            UpdateExternalNameCmd::new("old_lib", "new_lib", SourceType::UserDefined);
        assert!(cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_none());
        assert!(!mgr.contains_library("old_lib"));
        assert!(mgr.contains_library("new_lib"));
    }

    #[test]
    fn test_update_to_duplicate_name() {
        let mut mgr = ExternalManagerDB::new();
        mgr.add_library("old_lib", SourceType::Imported).unwrap();
        mgr.add_library("existing_lib", SourceType::Imported).unwrap();

        let mut cmd =
            UpdateExternalNameCmd::new("old_lib", "existing_lib", SourceType::UserDefined);
        assert!(!cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_some());
        assert!(cmd.status_msg().unwrap().contains("Duplicate name"));
        // old_lib should still exist
        assert!(mgr.contains_library("old_lib"));
    }

    #[test]
    fn test_update_nonexistent_library() {
        let mut mgr = ExternalManagerDB::new();

        let mut cmd =
            UpdateExternalNameCmd::new("nonexistent", "new_name", SourceType::UserDefined);
        assert!(!cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_some());
    }

    #[test]
    fn test_command_name() {
        let cmd = UpdateExternalNameCmd::new("old", "new", SourceType::Imported);
        assert_eq!(cmd.name(), "Update External Program Name");
    }

    #[test]
    fn test_accessors() {
        let cmd = UpdateExternalNameCmd::new("old_name", "new_name", SourceType::Analysis);
        assert_eq!(cmd.old_name(), "old_name");
        assert_eq!(cmd.new_name(), "new_name");
        assert_eq!(cmd.source(), SourceType::Analysis);
    }

    #[test]
    fn test_initial_status_is_none() {
        let cmd = UpdateExternalNameCmd::new("old", "new", SourceType::Imported);
        assert!(cmd.status_msg().is_none());
    }

    #[test]
    fn test_update_preserves_source() {
        let mut mgr = ExternalManagerDB::new();
        mgr.add_library("libc", SourceType::Imported).unwrap();

        let mut cmd = UpdateExternalNameCmd::new("libc", "libc_v2", SourceType::UserDefined);
        assert!(cmd.apply_to(&mut mgr));

        let info = mgr.get_library_info("libc_v2").unwrap();
        assert_eq!(info.source, SourceType::UserDefined);
    }

    #[test]
    #[should_panic(expected = "newName is invalid")]
    fn test_panic_on_empty_new_name() {
        UpdateExternalNameCmd::new("old", "", SourceType::Default);
    }

    #[test]
    fn test_clone() {
        let cmd = UpdateExternalNameCmd::new("old", "new", SourceType::Imported);
        let cloned = cmd.clone();
        assert_eq!(cloned.old_name(), "old");
        assert_eq!(cloned.new_name(), "new");
        assert_eq!(cloned.source(), SourceType::Imported);
    }

    #[test]
    fn test_status_resets_on_reapply() {
        let mut mgr = ExternalManagerDB::new();

        let mut cmd =
            UpdateExternalNameCmd::new("nonexistent", "new", SourceType::Imported);

        // First attempt fails
        assert!(!cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_some());

        // Create the library and try again
        mgr.add_library("nonexistent", SourceType::Imported).unwrap();
        assert!(cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_none());
    }

    #[test]
    fn test_rename_chain() {
        let mut mgr = ExternalManagerDB::new();
        mgr.add_library("libA", SourceType::Imported).unwrap();

        // Rename libA -> libB
        let mut cmd1 = UpdateExternalNameCmd::new("libA", "libB", SourceType::UserDefined);
        assert!(cmd1.apply_to(&mut mgr));
        assert!(mgr.contains_library("libB"));

        // Rename libB -> libC
        let mut cmd2 = UpdateExternalNameCmd::new("libB", "libC", SourceType::UserDefined);
        assert!(cmd2.apply_to(&mut mgr));
        assert!(mgr.contains_library("libC"));
        assert!(!mgr.contains_library("libB"));
    }
}
