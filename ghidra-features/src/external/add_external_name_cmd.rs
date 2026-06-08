//! AddExternalNameCmd -- command for adding an external program name.
//!
//! Ported from `ghidra.app.cmd.refs.AddExternalNameCmd`.
//!
//! This command adds a new external library name to the program's
//! external manager.  If the name already exists, the command fails
//! with a duplicate-name error.  If the name is null or empty, the
//! constructor panics (matching the Java behaviour).

use std::fmt;

use ghidra_core::symbol::SourceType;

use super::external_location_db::ExternalLocationError;
use super::external_manager_db::ExternalManagerDB;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors that can occur when adding an external program name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddExternalNameError {
    /// A library with this name already exists.
    DuplicateName(String),
    /// The supplied name is invalid.
    InvalidInput(String),
    /// General error.
    Other(String),
}

impl fmt::Display for AddExternalNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddExternalNameError::DuplicateName(name) => {
                write!(f, "{} already exists", name)
            }
            AddExternalNameError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            AddExternalNameError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for AddExternalNameError {}

impl From<ExternalLocationError> for AddExternalNameError {
    fn from(e: ExternalLocationError) -> Self {
        match e {
            ExternalLocationError::DuplicateName(name) => {
                AddExternalNameError::DuplicateName(name)
            }
            ExternalLocationError::InvalidInput(msg) => {
                AddExternalNameError::InvalidInput(msg)
            }
            _ => AddExternalNameError::Other(e.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// AddExternalNameCmd
// ---------------------------------------------------------------------------

/// Command for adding an external program (library) name.
///
/// This is the Rust port of Ghidra's `AddExternalNameCmd`.  It adds a
/// new library entry to the external manager.  The name must be
/// non-empty and not already present.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::{AddExternalNameCmd, ExternalManagerDB};
/// use ghidra_core::symbol::SourceType;
///
/// let mut cmd = AddExternalNameCmd::new("libc", SourceType::Imported);
/// let mut mgr = ExternalManagerDB::new();
///
/// assert!(cmd.apply_to(&mut mgr));
/// assert_eq!(cmd.name(), "Add External Program Name");
/// assert!(mgr.contains_library("libc"));
/// ```
#[derive(Debug, Clone)]
pub struct AddExternalNameCmd {
    /// The library name to add.
    name: String,
    /// The source type for the new library.
    source: SourceType,
    /// Error message from the last execution, if any.
    status: Option<String>,
}

impl AddExternalNameCmd {
    /// Create a new command to add an external library name.
    ///
    /// # Arguments
    ///
    /// * `name` -- the external library name (required, must be non-empty).
    /// * `source` -- the source type for this external name.
    ///
    /// # Panics
    ///
    /// Panics if `name` is empty.
    pub fn new(name: impl Into<String>, source: SourceType) -> Self {
        let n = name.into();
        assert!(!n.is_empty(), "name is invalid: {}", n);
        Self {
            name: n,
            source,
            status: None,
        }
    }

    /// Execute the command against the given external manager.
    ///
    /// Returns `true` if the library was successfully added, `false`
    /// otherwise.  On failure, [`status_msg`](Self::status_msg) contains
    /// a description of the error.
    pub fn apply_to(&mut self, ext_mgr: &mut ExternalManagerDB) -> bool {
        self.status = None;

        match ext_mgr.add_library(&self.name, self.source) {
            Ok(true) => true,
            Ok(false) => {
                self.status = Some(format!("{} already exists", self.name));
                false
            }
            Err(e) => {
                self.status = Some(e.to_string());
                false
            }
        }
    }

    /// Returns the command name.
    pub fn name(&self) -> &str {
        "Add External Program Name"
    }

    /// Returns the status message from the last execution, if any.
    pub fn status_msg(&self) -> Option<&str> {
        self.status.as_deref()
    }

    /// Returns the library name that this command will add.
    pub fn library_name(&self) -> &str {
        &self.name
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
    fn test_add_external_name() {
        let mut cmd = AddExternalNameCmd::new("libc", SourceType::Imported);
        let mut mgr = ExternalManagerDB::new();

        assert!(cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_none());
        assert!(mgr.contains_library("libc"));
    }

    #[test]
    fn test_add_duplicate_name() {
        let mut mgr = ExternalManagerDB::new();
        mgr.add_library("libc", SourceType::Imported).unwrap();

        let mut cmd = AddExternalNameCmd::new("libc", SourceType::Imported);
        assert!(!cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_some());
        assert!(cmd.status_msg().unwrap().contains("already exists"));
    }

    #[test]
    fn test_command_name() {
        let cmd = AddExternalNameCmd::new("libc", SourceType::Imported);
        assert_eq!(cmd.name(), "Add External Program Name");
    }

    #[test]
    fn test_accessors() {
        let cmd = AddExternalNameCmd::new("kernel32.dll", SourceType::UserDefined);
        assert_eq!(cmd.library_name(), "kernel32.dll");
        assert_eq!(cmd.source(), SourceType::UserDefined);
    }

    #[test]
    fn test_initial_status_is_none() {
        let cmd = AddExternalNameCmd::new("libc", SourceType::Imported);
        assert!(cmd.status_msg().is_none());
    }

    #[test]
    fn test_add_multiple_libraries() {
        let mut mgr = ExternalManagerDB::new();

        let mut cmd1 = AddExternalNameCmd::new("libc", SourceType::Imported);
        assert!(cmd1.apply_to(&mut mgr));

        let mut cmd2 = AddExternalNameCmd::new("libm", SourceType::Imported);
        assert!(cmd2.apply_to(&mut mgr));

        let mut cmd3 = AddExternalNameCmd::new("kernel32.dll", SourceType::UserDefined);
        assert!(cmd3.apply_to(&mut mgr));

        assert_eq!(mgr.library_count(), 3);
    }

    #[test]
    fn test_add_with_analysis_source() {
        let mut cmd = AddExternalNameCmd::new("libpthread", SourceType::Analysis);
        let mut mgr = ExternalManagerDB::new();

        assert!(cmd.apply_to(&mut mgr));
        let info = mgr.get_library_info("libpthread").unwrap();
        assert_eq!(info.source, SourceType::Analysis);
    }

    #[test]
    #[should_panic(expected = "name is invalid")]
    fn test_panic_on_empty_name() {
        AddExternalNameCmd::new("", SourceType::Default);
    }

    #[test]
    fn test_clone() {
        let cmd = AddExternalNameCmd::new("libc", SourceType::Imported);
        let cloned = cmd.clone();
        assert_eq!(cloned.library_name(), "libc");
        assert_eq!(cloned.source(), SourceType::Imported);
    }

    #[test]
    fn test_apply_twice_fails_second_time() {
        let mut mgr = ExternalManagerDB::new();
        let mut cmd = AddExternalNameCmd::new("libc", SourceType::Imported);

        assert!(cmd.apply_to(&mut mgr));
        // Reset and try again -- should fail because library already exists
        assert!(!cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().unwrap().contains("already exists"));
    }
}
