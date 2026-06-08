//! SetExternalNameCmd -- command for setting the external program name and path.
//!
//! Ported from `ghidra.app.cmd.refs.SetExternalNameCmd`.
//!
//! This command creates a Library entry (if it does not already exist)
//! in the external manager and then sets the associated external program
//! path on that library.  If the library already exists only the path
//! is updated.  When a new library is created it will have
//! [`SourceType::UserDefined`] as its source unless a different source
//! is explicitly provided.

use std::fmt;

use ghidra_core::symbol::SourceType;

use super::external_location_db::ExternalLocationError;
use super::external_manager_db::ExternalManagerDB;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors that can occur when setting an external library name and path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetExternalNameError {
    /// A duplicate name was encountered.
    DuplicateName(String),
    /// The supplied name or path is invalid.
    InvalidInput(String),
    /// General error.
    Other(String),
}

impl fmt::Display for SetExternalNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SetExternalNameError::DuplicateName(name) => {
                write!(f, "{} already exists", name)
            }
            SetExternalNameError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            SetExternalNameError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for SetExternalNameError {}

impl From<ExternalLocationError> for SetExternalNameError {
    fn from(e: ExternalLocationError) -> Self {
        match e {
            ExternalLocationError::DuplicateName(name) => {
                SetExternalNameError::DuplicateName(name)
            }
            ExternalLocationError::InvalidInput(msg) => {
                SetExternalNameError::InvalidInput(msg)
            }
            _ => SetExternalNameError::Other(e.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// SetExternalNameCmd
// ---------------------------------------------------------------------------

/// Command for setting the external program name and path.
///
/// This is the Rust port of Ghidra's `SetExternalNameCmd`.  It creates
/// a new Library entry in the external manager (if one does not already
/// exist) and associates the given file path with it.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::{SetExternalNameCmd, ExternalManagerDB};
/// use ghidra_core::symbol::SourceType;
///
/// let mut mgr = ExternalManagerDB::new();
/// let mut cmd = SetExternalNameCmd::new("libc", "/usr/lib/libc.so");
///
/// assert!(cmd.apply_to(&mut mgr));
/// assert!(mgr.contains_library("libc"));
/// assert_eq!(
///     mgr.get_external_library_path("libc"),
///     Some("/usr/lib/libc.so"),
/// );
/// ```
#[derive(Debug, Clone)]
pub struct SetExternalNameCmd {
    /// The library name to create or look up.
    external_name: String,
    /// The project file path to associate with the library.
    external_path: String,
    /// The source type for a newly created library.
    source: SourceType,
    /// Error message from the last execution, if any.
    status: Option<String>,
}

impl SetExternalNameCmd {
    /// Create a new command using [`SourceType::UserDefined`].
    ///
    /// # Arguments
    ///
    /// * `external_name` -- the Library name (required, non-empty).
    /// * `external_path` -- the project file path of the program file
    ///   to associate with the Library.
    pub fn new(external_name: impl Into<String>, external_path: impl Into<String>) -> Self {
        Self::with_source(external_name, external_path, SourceType::UserDefined)
    }

    /// Create a new command with an explicit source type.
    ///
    /// # Arguments
    ///
    /// * `external_name` -- the Library name (required, non-empty).
    /// * `external_path` -- the project file path of the program file
    ///   to associate with the Library.
    /// * `source` -- the symbol source type to be applied if the library
    ///   must be created.
    pub fn with_source(
        external_name: impl Into<String>,
        external_path: impl Into<String>,
        source: SourceType,
    ) -> Self {
        Self {
            external_name: external_name.into(),
            external_path: external_path.into(),
            source,
            status: None,
        }
    }

    /// Execute the command against the given external manager.
    ///
    /// If the library does not yet exist it will be created.  Then the
    /// associated program path is set on the library.
    ///
    /// Returns `true` on success, `false` otherwise.  On failure,
    /// [`status_msg`](Self::status_msg) contains a description of the
    /// error.
    pub fn apply_to(&mut self, ext_mgr: &mut ExternalManagerDB) -> bool {
        self.status = None;

        // Create the library if it does not already exist.
        if !ext_mgr.contains_library(&self.external_name) {
            if let Err(e) = ext_mgr.add_library(&self.external_name, self.source) {
                self.status = Some(e.to_string());
                return false;
            }
        }

        // Set the associated program path.
        match ext_mgr.set_external_path(
            &self.external_name,
            &self.external_path,
            self.source == SourceType::UserDefined,
        ) {
            Ok(()) => true,
            Err(e) => {
                self.status = Some(e.to_string());
                false
            }
        }
    }

    /// Returns the command name.
    pub fn name(&self) -> &str {
        "Set External Library Name and Path"
    }

    /// Returns the status message from the last execution, if any.
    pub fn status_msg(&self) -> Option<&str> {
        self.status.as_deref()
    }

    /// Returns the external library name.
    pub fn external_name(&self) -> &str {
        &self.external_name
    }

    /// Returns the external program path.
    pub fn external_path(&self) -> &str {
        &self.external_path
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
    fn test_set_external_name_creates_library() {
        let mut mgr = ExternalManagerDB::new();
        let mut cmd = SetExternalNameCmd::new("libc", "/usr/lib/libc.so");

        assert!(cmd.apply_to(&mut mgr));
        assert!(cmd.status_msg().is_none());
        assert!(mgr.contains_library("libc"));
        assert_eq!(
            mgr.get_external_library_path("libc"),
            Some("/usr/lib/libc.so"),
        );
    }

    #[test]
    fn test_set_external_name_updates_path() {
        let mut mgr = ExternalManagerDB::new();
        mgr.add_library("libc", SourceType::Imported).unwrap();

        let mut cmd = SetExternalNameCmd::new("libc", "/new/path/libc.so");
        assert!(cmd.apply_to(&mut mgr));
        assert_eq!(
            mgr.get_external_library_path("libc"),
            Some("/new/path/libc.so"),
        );
    }

    #[test]
    fn test_set_external_name_existing_library_preserves_source() {
        let mut mgr = ExternalManagerDB::new();
        mgr.add_library("libc", SourceType::Imported).unwrap();

        let mut cmd = SetExternalNameCmd::new("libc", "/usr/lib/libc.so");
        assert!(cmd.apply_to(&mut mgr));

        // Source should remain Imported (the library was already present).
        let info = mgr.get_library_info("libc").unwrap();
        assert_eq!(info.source, SourceType::Imported);
    }

    #[test]
    fn test_set_external_name_new_library_default_source() {
        let mut mgr = ExternalManagerDB::new();
        let mut cmd = SetExternalNameCmd::new("libm", "/usr/lib/libm.so");

        assert!(cmd.apply_to(&mut mgr));

        let info = mgr.get_library_info("libm").unwrap();
        assert_eq!(info.source, SourceType::UserDefined);
    }

    #[test]
    fn test_set_external_name_with_custom_source() {
        let mut mgr = ExternalManagerDB::new();
        let mut cmd =
            SetExternalNameCmd::with_source("libpthread", "/usr/lib/libpthread.so", SourceType::Analysis);

        assert!(cmd.apply_to(&mut mgr));

        let info = mgr.get_library_info("libpthread").unwrap();
        assert_eq!(info.source, SourceType::Analysis);
    }

    #[test]
    fn test_command_name() {
        let cmd = SetExternalNameCmd::new("libc", "/usr/lib/libc.so");
        assert_eq!(cmd.name(), "Set External Library Name and Path");
    }

    #[test]
    fn test_accessors() {
        let cmd = SetExternalNameCmd::with_source("libc", "/usr/lib/libc.so", SourceType::Imported);
        assert_eq!(cmd.external_name(), "libc");
        assert_eq!(cmd.external_path(), "/usr/lib/libc.so");
        assert_eq!(cmd.source(), SourceType::Imported);
    }

    #[test]
    fn test_initial_status_is_none() {
        let cmd = SetExternalNameCmd::new("libc", "/usr/lib/libc.so");
        assert!(cmd.status_msg().is_none());
    }

    #[test]
    fn test_clone() {
        let cmd = SetExternalNameCmd::new("libc", "/usr/lib/libc.so");
        let cloned = cmd.clone();
        assert_eq!(cloned.external_name(), "libc");
        assert_eq!(cloned.external_path(), "/usr/lib/libc.so");
    }

    #[test]
    fn test_set_path_on_multiple_libraries() {
        let mut mgr = ExternalManagerDB::new();

        let mut cmd1 = SetExternalNameCmd::new("libc", "/usr/lib/libc.so");
        assert!(cmd1.apply_to(&mut mgr));

        let mut cmd2 = SetExternalNameCmd::new("libm", "/usr/lib/libm.so");
        assert!(cmd2.apply_to(&mut mgr));

        assert_eq!(mgr.library_count(), 2);
        assert_eq!(
            mgr.get_external_library_path("libc"),
            Some("/usr/lib/libc.so"),
        );
        assert_eq!(
            mgr.get_external_library_path("libm"),
            Some("/usr/lib/libm.so"),
        );
    }

    #[test]
    fn test_apply_twice_updates_path() {
        let mut mgr = ExternalManagerDB::new();

        let mut cmd = SetExternalNameCmd::new("libc", "/first/path/libc.so");
        assert!(cmd.apply_to(&mut mgr));

        let mut cmd2 = SetExternalNameCmd::new("libc", "/second/path/libc.so");
        assert!(cmd2.apply_to(&mut mgr));

        assert_eq!(
            mgr.get_external_library_path("libc"),
            Some("/second/path/libc.so"),
        );
    }
}
