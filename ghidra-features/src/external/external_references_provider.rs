//! ExternalReferencesProvider -- component provider for external programs.
//!
//! Ported from `ghidra.app.plugin.core.references.ExternalReferencesProvider`.
//!
//! This module provides the data model and logic for displaying a table
//! of external programs (libraries) with their associated file paths.
//! In Ghidra's Java implementation this is a Swing-based
//! `ComponentProviderAdapter`; here we provide the underlying data model
//! and operations, leaving the GUI layer to the caller.
//!
//! The provider supports:
//!
//! - Listing all external libraries (excluding `UNKNOWN_LIBRARY`)
//! - Adding new external program names
//! - Deleting external programs (only if they have no external locations)
//! - Reordering library ordinals (move up / move down)
//! - Setting and clearing the file-path association for a library
//! - Renaming an external program via inline editing
//!
//! # Examples
//!
//! ```rust
//! use ghidra_features::external::{
//!     ExternalReferencesProvider, ExternalManagerDB,
//! };
//! use ghidra_core::symbol::SourceType;
//!
//! let mut mgr = ExternalManagerDB::new();
//! mgr.add_external_library_name("libc", SourceType::Imported).unwrap();
//! mgr.set_external_path("libc", "/usr/lib/libc.so", false).unwrap();
//!
//! let provider = ExternalReferencesProvider::from_manager(&mgr);
//! assert_eq!(provider.row_count(), 1);
//! assert_eq!(provider.row(0).unwrap().name(), "libc");
//! assert_eq!(provider.row(0).unwrap().path(), Some("/usr/lib/libc.so"));
//! ```

use std::fmt;

use ghidra_core::symbol::SourceType;

use super::add_external_name_cmd::{AddExternalNameCmd, AddExternalNameError};
use super::clear_external_path_cmd::{ClearExternalPathCmd, ClearExternalPathError};
use super::external_manager_db::ExternalManagerDB;
use super::remove_external_name_cmd::{RemoveExternalNameCmd, RemoveExternalNameError};
use super::set_external_name_cmd::{SetExternalNameCmd, SetExternalNameError};
use super::update_external_name_cmd::{UpdateExternalNameCmd, UpdateExternalNameError};
use super::UNKNOWN_LIBRARY;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors that can occur in the external references provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalReferencesError {
    /// The library still has external locations and cannot be deleted.
    HasExternalLocations(String),
    /// The name is a duplicate.
    DuplicateName(String),
    /// The input is invalid.
    InvalidInput(String),
    /// The library ordinal could not be changed.
    OrdinalError(String),
    /// General error.
    Other(String),
}

impl fmt::Display for ExternalReferencesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExternalReferencesError::HasExternalLocations(name) => {
                write!(
                    f,
                    "Cannot delete external program '{}': it still has external locations",
                    name
                )
            }
            ExternalReferencesError::DuplicateName(name) => {
                write!(f, "Duplicate name: {}", name)
            }
            ExternalReferencesError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            ExternalReferencesError::OrdinalError(msg) => {
                write!(f, "Library ordinal error: {}", msg)
            }
            ExternalReferencesError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ExternalReferencesError {}

impl From<AddExternalNameError> for ExternalReferencesError {
    fn from(e: AddExternalNameError) -> Self {
        match e {
            AddExternalNameError::DuplicateName(n) => ExternalReferencesError::DuplicateName(n),
            AddExternalNameError::InvalidInput(m) => ExternalReferencesError::InvalidInput(m),
            AddExternalNameError::Other(m) => ExternalReferencesError::Other(m),
        }
    }
}

impl From<RemoveExternalNameError> for ExternalReferencesError {
    fn from(e: RemoveExternalNameError) -> Self {
        match e {
            RemoveExternalNameError::CannotRemove(n) => {
                ExternalReferencesError::HasExternalLocations(n)
            }
            RemoveExternalNameError::Other(m) => ExternalReferencesError::Other(m),
        }
    }
}

impl From<SetExternalNameError> for ExternalReferencesError {
    fn from(e: SetExternalNameError) -> Self {
        match e {
            SetExternalNameError::DuplicateName(n) => ExternalReferencesError::DuplicateName(n),
            SetExternalNameError::InvalidInput(m) => ExternalReferencesError::InvalidInput(m),
            SetExternalNameError::Other(m) => ExternalReferencesError::Other(m),
        }
    }
}

impl From<UpdateExternalNameError> for ExternalReferencesError {
    fn from(e: UpdateExternalNameError) -> Self {
        match e {
            UpdateExternalNameError::DuplicateName(n) => ExternalReferencesError::DuplicateName(n),
            UpdateExternalNameError::InvalidInput(m) => ExternalReferencesError::InvalidInput(m),
            UpdateExternalNameError::NotFound(m) => ExternalReferencesError::Other(m),
            UpdateExternalNameError::Other(m) => ExternalReferencesError::Other(m),
        }
    }
}

impl From<ClearExternalPathError> for ExternalReferencesError {
    fn from(e: ClearExternalPathError) -> Self {
        match e {
            ClearExternalPathError::LibraryNotFound(m) => ExternalReferencesError::Other(m),
            ClearExternalPathError::InvalidInput(m) => ExternalReferencesError::InvalidInput(m),
            ClearExternalPathError::Other(m) => ExternalReferencesError::Other(m),
        }
    }
}

// ---------------------------------------------------------------------------
// ExternalNamesRow
// ---------------------------------------------------------------------------

/// A single row in the external programs table.
///
/// Each row pairs a library name with its optional associated file path.
/// This corresponds to the inner `ExternalNamesRow` class in the Java
/// implementation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExternalNamesRow {
    /// The external library name.
    name: String,
    /// The associated Ghidra project file path, if any.
    path: Option<String>,
}

impl ExternalNamesRow {
    /// Create a new row.
    pub fn new(name: impl Into<String>, path: Option<String>) -> Self {
        Self {
            name: name.into(),
            path,
        }
    }

    /// The library name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The associated file path, or `None`.
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }
}

// ---------------------------------------------------------------------------
// ExternalReferencesProvider
// ---------------------------------------------------------------------------

/// Data model for the "External Programs" component.
///
/// This is the Rust port of Ghidra's `ExternalReferencesProvider`.  It
/// manages a table of external library names and their associated file
/// paths, backed by an [`ExternalManagerDB`].
///
/// All mutating operations return a result indicating success or the
/// specific error encountered.
#[derive(Debug, Clone)]
pub struct ExternalReferencesProvider {
    /// Cached table rows, in ordinal order.
    rows: Vec<ExternalNamesRow>,
}

impl ExternalReferencesProvider {
    /// Build the table model from the current state of an external manager.
    ///
    /// Libraries are listed in ordinal order.  The `UNKNOWN_LIBRARY`
    /// entry is excluded from the table (matching the Java behaviour).
    pub fn from_manager(mgr: &ExternalManagerDB) -> Self {
        let names = mgr.get_external_library_names();
        let rows: Vec<ExternalNamesRow> = names
            .iter()
            .filter(|n| *n != UNKNOWN_LIBRARY)
            .map(|name| {
                let path = mgr.get_external_library_path(name);
                ExternalNamesRow::new(name.to_string(), path.map(String::from))
            })
            .collect();
        Self { rows }
    }

    // -- queries -------------------------------------------------------------

    /// The number of rows in the table.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Get a row by index.
    pub fn row(&self, index: usize) -> Option<&ExternalNamesRow> {
        self.rows.get(index)
    }

    /// All rows.
    pub fn rows(&self) -> &[ExternalNamesRow] {
        &self.rows
    }

    /// Find the index of a row by library name, or `-1` if not found.
    pub fn index_of(&self, name: &str) -> Option<usize> {
        self.rows.iter().position(|r| r.name() == name)
    }

    /// Return the selected external names for the given row indices.
    pub fn selected_external_names(&self, indices: &[usize]) -> Vec<String> {
        indices
            .iter()
            .filter_map(|&i| self.rows.get(i).map(|r| r.name().to_string()))
            .collect()
    }

    /// Whether a library ordinal can be decremented for the given
    /// single selected row index.
    ///
    /// Returns `true` if exactly one row is selected, it is not the
    /// first row, and the row above it is not the UNKNOWN library.
    pub fn can_decrement_library_ordinal(&self, selected: &[usize]) -> bool {
        if selected.len() != 1 {
            return false;
        }
        let idx = selected[0];
        if idx == 0 || idx >= self.rows.len() {
            return false;
        }
        // The row above must not be the UNKNOWN library
        self.rows[idx - 1].name() != UNKNOWN_LIBRARY
    }

    /// Whether a library ordinal can be incremented for the given
    /// single selected row index.
    ///
    /// Returns `true` if exactly one row is selected, it is not the
    /// last row, and the selected row is not the UNKNOWN library.
    pub fn can_increment_library_ordinal(&self, selected: &[usize]) -> bool {
        if selected.len() != 1 {
            return false;
        }
        let idx = selected[0];
        if idx >= self.rows.len().saturating_sub(1) {
            return false;
        }
        self.rows[idx].name() != UNKNOWN_LIBRARY
    }

    // -- mutations (delegated to ExternalManagerDB) --------------------------

    /// Add a new external program name.
    ///
    /// Returns the name of the newly added library on success.
    pub fn add_external_program(
        &self,
        mgr: &mut ExternalManagerDB,
        new_name: &str,
        source: SourceType,
    ) -> Result<String, ExternalReferencesError> {
        let trimmed = new_name.trim();
        if trimmed.is_empty() {
            return Err(ExternalReferencesError::InvalidInput(
                "External program name cannot be empty".to_string(),
            ));
        }
        let mut cmd = AddExternalNameCmd::new(trimmed, source);
        if !cmd.apply_to(mgr) {
            return Err(ExternalReferencesError::Other(
                cmd.status_msg().unwrap_or("Failed to add external name").to_string(),
            ));
        }
        Ok(trimmed.to_string())
    }

    /// Delete external programs for the given row indices.
    ///
    /// Libraries that still contain external locations are skipped and
    /// their names are collected into the error list.  Successfully
    /// deleted names are returned.
    pub fn delete_external_programs(
        &self,
        mgr: &mut ExternalManagerDB,
        selected: &[usize],
    ) -> DeleteResult {
        let names = self.selected_external_names(selected);
        let mut deleted = Vec::new();
        let mut failed = Vec::new();

        for name in &names {
            // Check whether the library has locations
            if mgr.has_external_locations(name) {
                failed.push(name.clone());
                continue;
            }
            let mut cmd = RemoveExternalNameCmd::new(name);
            if cmd.apply_to(mgr) {
                deleted.push(name.clone());
            } else {
                failed.push(name.clone());
            }
        }

        DeleteResult { deleted, failed }
    }

    /// Adjust the library ordinal for the single selected row.
    ///
    /// Pass `move_up = true` to decrement the ordinal (move the library
    /// earlier in the list), or `move_up = false` to increment it.
    pub fn adjust_library_ordinal(
        &self,
        mgr: &mut ExternalManagerDB,
        selected: &[usize],
        move_up: bool,
    ) -> Result<(), ExternalReferencesError> {
        if (move_up && !self.can_decrement_library_ordinal(selected))
            || (!move_up && !self.can_increment_library_ordinal(selected))
        {
            return Err(ExternalReferencesError::OrdinalError(
                "Cannot adjust library ordinal for the current selection".to_string(),
            ));
        }

        let idx = selected[0];
        let name = &self.rows[idx].name;
        let adjustment: i32 = if move_up { -1 } else { 1 };

        let current_ordinal = mgr.get_library_ordinal(name);
        if current_ordinal < 0 {
            return Err(ExternalReferencesError::OrdinalError(format!(
                "Failed to get library ordinal for: {}",
                name
            )));
        }

        mgr.set_library_ordinal(name, current_ordinal + adjustment);
        Ok(())
    }

    /// Set the external program file path for the library at the given
    /// row index.
    pub fn set_external_program_association(
        &self,
        mgr: &mut ExternalManagerDB,
        selected: &[usize],
        new_path: &str,
    ) -> Result<(), ExternalReferencesError> {
        if selected.len() != 1 {
            return Err(ExternalReferencesError::InvalidInput(
                "Exactly one row must be selected".to_string(),
            ));
        }
        let idx = selected[0];
        let name = &self.rows[idx].name;

        let current_path = mgr.get_external_library_path(name);
        if current_path.as_deref() == Some(new_path) {
            return Ok(()); // no change
        }

        let mut cmd = SetExternalNameCmd::new(name, new_path);
        if !cmd.apply_to(mgr) {
            return Err(ExternalReferencesError::Other(
                cmd.status_msg().unwrap_or("Failed to set external name").to_string(),
            ));
        }
        Ok(())
    }

    /// Clear the file-path association for the libraries at the given
    /// row indices.
    pub fn clear_external_associations(
        &self,
        mgr: &mut ExternalManagerDB,
        selected: &[usize],
    ) -> Result<(), ExternalReferencesError> {
        let names = self.selected_external_names(selected);
        for name in &names {
            let mut cmd = ClearExternalPathCmd::new(name);
            if !cmd.apply_to(mgr) {
                return Err(ExternalReferencesError::Other(
                    cmd.status_msg().unwrap_or("Failed to clear external path").to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Rename an external program by row index.
    ///
    /// This corresponds to inline editing of the "Name" column in the
    /// Java table model.
    pub fn rename_external_program(
        &self,
        mgr: &mut ExternalManagerDB,
        row_index: usize,
        new_name: &str,
        source: SourceType,
    ) -> Result<String, ExternalReferencesError> {
        let trimmed = new_name.trim();
        if trimmed.is_empty() || row_index >= self.rows.len() {
            return Err(ExternalReferencesError::InvalidInput(
                "Invalid rename input".to_string(),
            ));
        }
        let old_name = &self.rows[row_index].name;
        if old_name == trimmed {
            return Ok(old_name.clone()); // no change
        }
        // Check for duplicate
        if self.index_of(trimmed).is_some() {
            return Err(ExternalReferencesError::DuplicateName(trimmed.to_string()));
        }

        let mut cmd = UpdateExternalNameCmd::new(old_name, trimmed, source);
        if !cmd.apply_to(mgr) {
            return Err(ExternalReferencesError::Other(
                cmd.status_msg().unwrap_or("Failed to update external name").to_string(),
            ));
        }
        Ok(trimmed.to_string())
    }
}

// ---------------------------------------------------------------------------
// DeleteResult
// ---------------------------------------------------------------------------

/// Result of a batch delete operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteResult {
    /// Names that were successfully deleted.
    pub deleted: Vec<String>,
    /// Names that could not be deleted (still have external locations).
    pub failed: Vec<String>,
}

impl DeleteResult {
    /// Whether any libraries could not be deleted.
    pub fn has_failures(&self) -> bool {
        !self.failed.is_empty()
    }

    /// Whether any libraries were successfully deleted.
    pub fn has_deletions(&self) -> bool {
        !self.deleted.is_empty()
    }

    /// Build the error message for libraries that could not be deleted.
    pub fn failure_message(&self) -> Option<String> {
        if self.failed.is_empty() {
            return None;
        }
        let mut buf = String::from(
            "The following external reference names could not be deleted\n\
             because they contain external locations:\n",
        );
        for name in &self.failed {
            buf.push_str("\n     ");
            buf.push_str(name);
        }
        Some(buf)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_mgr_with_libs() -> ExternalManagerDB {
        let mut mgr = ExternalManagerDB::new();
        mgr.add_library("libc", SourceType::Imported).unwrap();
        mgr.set_external_path("libc", "/usr/lib/libc.so", true).unwrap();
        mgr.add_library("libm", SourceType::Imported).unwrap();
        mgr.set_external_path("libm", "/usr/lib/libm.so", true).unwrap();
        mgr.add_library("libpthread", SourceType::Imported).unwrap();
        mgr
    }

    #[test]
    fn test_from_manager_excludes_unknown() {
        let mgr = setup_mgr_with_libs();
        let provider = ExternalReferencesProvider::from_manager(&mgr);
        // UNKNOWN_LIBRARY should not appear
        assert!(provider.rows().iter().all(|r| r.name() != UNKNOWN_LIBRARY));
        assert_eq!(provider.row_count(), 3);
    }

    #[test]
    fn test_row_data() {
        let mgr = setup_mgr_with_libs();
        let provider = ExternalReferencesProvider::from_manager(&mgr);
        let row = provider.row(0).unwrap();
        assert_eq!(row.name(), "libc");
        assert_eq!(row.path(), Some("/usr/lib/libc.so"));
    }

    #[test]
    fn test_index_of() {
        let mgr = setup_mgr_with_libs();
        let provider = ExternalReferencesProvider::from_manager(&mgr);
        assert_eq!(provider.index_of("libc"), Some(0));
        assert_eq!(provider.index_of("libm"), Some(1));
        assert_eq!(provider.index_of("nonexistent"), None);
    }

    #[test]
    fn test_selected_external_names() {
        let mgr = setup_mgr_with_libs();
        let provider = ExternalReferencesProvider::from_manager(&mgr);
        let names = provider.selected_external_names(&[0, 2]);
        assert_eq!(names, vec!["libc", "libpthread"]);
    }

    #[test]
    fn test_add_external_program() {
        let mut mgr = setup_mgr_with_libs();
        let provider = ExternalReferencesProvider::from_manager(&mgr);
        let result = provider.add_external_program(&mut mgr, "libz", SourceType::Imported);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "libz");
    }

    #[test]
    fn test_add_external_program_empty_name() {
        let mut mgr = setup_mgr_with_libs();
        let provider = ExternalReferencesProvider::from_manager(&mgr);
        let result = provider.add_external_program(&mut mgr, "   ", SourceType::Imported);
        assert!(matches!(
            result,
            Err(ExternalReferencesError::InvalidInput(_))
        ));
    }

    #[test]
    fn test_can_decrement_library_ordinal() {
        let mgr = setup_mgr_with_libs();
        let provider = ExternalReferencesProvider::from_manager(&mgr);
        // First row cannot be decremented
        assert!(!provider.can_decrement_library_ordinal(&[0]));
        // Second row can be decremented
        assert!(provider.can_decrement_library_ordinal(&[1]));
        // Multiple selection cannot
        assert!(!provider.can_decrement_library_ordinal(&[0, 1]));
    }

    #[test]
    fn test_can_increment_library_ordinal() {
        let mgr = setup_mgr_with_libs();
        let provider = ExternalReferencesProvider::from_manager(&mgr);
        // Last row cannot be incremented
        assert!(!provider.can_increment_library_ordinal(&[2]));
        // First row can be incremented
        assert!(provider.can_increment_library_ordinal(&[0]));
    }

    #[test]
    fn test_rename_external_program() {
        let mut mgr = setup_mgr_with_libs();
        let provider = ExternalReferencesProvider::from_manager(&mgr);
        let result =
            provider.rename_external_program(&mut mgr, 0, "libc_renamed", SourceType::UserDefined);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "libc_renamed");
    }

    #[test]
    fn test_rename_to_duplicate() {
        let mut mgr = setup_mgr_with_libs();
        let provider = ExternalReferencesProvider::from_manager(&mgr);
        let result =
            provider.rename_external_program(&mut mgr, 0, "libm", SourceType::UserDefined);
        assert!(matches!(
            result,
            Err(ExternalReferencesError::DuplicateName(_))
        ));
    }

    #[test]
    fn test_rename_no_change() {
        let mut mgr = setup_mgr_with_libs();
        let provider = ExternalReferencesProvider::from_manager(&mgr);
        let result =
            provider.rename_external_program(&mut mgr, 0, "libc", SourceType::UserDefined);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "libc");
    }

    #[test]
    fn test_delete_result_messages() {
        let dr = DeleteResult {
            deleted: vec!["libc".to_string()],
            failed: vec!["libm".to_string()],
        };
        assert!(dr.has_failures());
        assert!(dr.has_deletions());
        let msg = dr.failure_message().unwrap();
        assert!(msg.contains("libm"));
    }

    #[test]
    fn test_clear_external_associations() {
        let mut mgr = setup_mgr_with_libs();
        let provider = ExternalReferencesProvider::from_manager(&mgr);
        assert!(provider
            .clear_external_associations(&mut mgr, &[0])
            .is_ok());
        // Verify path is cleared
        let refreshed = ExternalReferencesProvider::from_manager(&mgr);
        assert_eq!(refreshed.row(0).unwrap().path(), None);
    }

    #[test]
    fn test_set_external_program_association() {
        let mut mgr = ExternalManagerDB::new();
        mgr.add_library("libc", SourceType::Imported).unwrap();
        let provider = ExternalReferencesProvider::from_manager(&mgr);
        assert!(provider
            .set_external_program_association(&mut mgr, &[0], "/new/path/libc.so")
            .is_ok());
        let refreshed = ExternalReferencesProvider::from_manager(&mgr);
        assert_eq!(
            refreshed.row(0).unwrap().path(),
            Some("/new/path/libc.so")
        );
    }
}
