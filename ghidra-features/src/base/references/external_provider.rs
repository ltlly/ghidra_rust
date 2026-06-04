//! External references provider -- manages external program names and their
//! file-path associations.
//!
//! Ported from `ExternalReferencesProvider`. Provides a table model for
//! listing, adding, removing, and reordering external library names.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A row in the external programs table, representing an external library
/// name and its associated file path.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExternalNameRow {
    /// The external library name (e.g., "libc.so.6").
    name: String,
    /// The Ghidra program file path, or None if not associated.
    path: Option<String>,
}

impl ExternalNameRow {
    /// Create a new external name row.
    pub fn new(name: impl Into<String>, path: Option<String>) -> Self {
        Self {
            name: name.into(),
            path,
        }
    }

    /// Returns the library name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the associated file path, if any.
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// Sets the file path.
    pub fn set_path(&mut self, path: Option<String>) {
        self.path = path;
    }

    /// Renames the library.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }
}

impl fmt::Display for ExternalNameRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)?;
        if let Some(p) = &self.path {
            write!(f, " ({})", p)?;
        }
        Ok(())
    }
}

/// The special "UNKNOWN" library name constant.
pub const UNKNOWN_LIBRARY: &str = "UNKNOWN";

/// Table model for managing external program names.
///
/// Corresponds to the `ExternalNamesTableModel` inner class of
/// `ExternalReferencesProvider`.
#[derive(Debug, Clone, Default)]
pub struct ExternalReferencesProvider {
    /// The rows in the table.
    rows: Vec<ExternalNameRow>,
}

impl ExternalReferencesProvider {
    /// Create a new empty provider.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reload the table data from external library names.
    ///
    /// In the Java version this reads from `ExternalManager`. Here we
    /// accept the names directly.
    pub fn set_external_names(&mut self, names: Vec<ExternalNameRow>) {
        self.rows = names;
        // Ensure UNKNOWN is always first if present
        self.rows
            .sort_by(|a, b| match (a.name() == UNKNOWN_LIBRARY, b.name() == UNKNOWN_LIBRARY) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => std::cmp::Ordering::Equal,
            });
    }

    /// Returns the number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Returns a reference to the row at the given index.
    pub fn get_row(&self, index: usize) -> Option<&ExternalNameRow> {
        self.rows.get(index)
    }

    /// Returns a mutable reference to the row at the given index.
    pub fn get_row_mut(&mut self, index: usize) -> Option<&mut ExternalNameRow> {
        self.rows.get_mut(index)
    }

    /// Returns all rows.
    pub fn rows(&self) -> &[ExternalNameRow] {
        &self.rows
    }

    /// Returns all library names (excluding UNKNOWN).
    pub fn library_names(&self) -> Vec<&str> {
        self.rows
            .iter()
            .filter(|r| r.name() != UNKNOWN_LIBRARY)
            .map(|r| r.name())
            .collect()
    }

    /// Find the index of a row by name.
    pub fn find_by_name(&self, name: &str) -> Option<usize> {
        self.rows.iter().position(|r| r.name() == name)
    }

    /// Add a new external library name.
    ///
    /// Returns `Err` if the name already exists.
    pub fn add_library(
        &mut self,
        name: impl Into<String>,
    ) -> Result<usize, String> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err("External program name cannot be empty".to_string());
        }
        if self.find_by_name(&name).is_some() {
            return Err(format!("Name already exists: {}", name));
        }
        let row = ExternalNameRow::new(name, None);
        let idx = self.rows.len();
        // Insert before the end but after UNKNOWN
        if self.rows.first().map_or(false, |r| r.name() == UNKNOWN_LIBRARY) {
            if self.rows.len() > 1 {
                self.rows.insert(self.rows.len(), row);
            } else {
                self.rows.push(row);
            }
        } else {
            self.rows.push(row);
        }
        Ok(idx)
    }

    /// Remove a library by index.
    ///
    /// Returns the removed row, or None if the index is invalid.
    /// Returns Err if the library is UNKNOWN.
    pub fn remove_library(&mut self, index: usize) -> Result<ExternalNameRow, String> {
        if index >= self.rows.len() {
            return Err("Invalid index".to_string());
        }
        if self.rows[index].name() == UNKNOWN_LIBRARY {
            return Err("Cannot remove the UNKNOWN library".to_string());
        }
        Ok(self.rows.remove(index))
    }

    /// Rename a library.
    ///
    /// Returns `Err` if the new name already exists or the index is invalid.
    pub fn rename_library(
        &mut self,
        index: usize,
        new_name: impl Into<String>,
    ) -> Result<(), String> {
        let new_name = new_name.into();
        if index >= self.rows.len() {
            return Err("Invalid index".to_string());
        }
        if self.rows[index].name() == new_name {
            return Ok(());
        }
        if new_name.trim().is_empty() {
            return Err("Name cannot be empty".to_string());
        }
        if self.find_by_name(&new_name).is_some() {
            return Err(format!("Name already exists: {}", new_name));
        }
        self.rows[index].set_name(new_name);
        Ok(())
    }

    /// Move a library up in the ordinal order.
    ///
    /// Returns `Err` if the move is not possible (e.g., would displace
    /// UNKNOWN).
    pub fn move_up(&mut self, index: usize) -> Result<(), String> {
        if index == 0 || index >= self.rows.len() {
            return Err("Cannot move up".to_string());
        }
        if self.rows[index].name() == UNKNOWN_LIBRARY {
            return Err("Cannot move UNKNOWN library".to_string());
        }
        if self.rows[index - 1].name() == UNKNOWN_LIBRARY {
            return Err("Cannot displace UNKNOWN library".to_string());
        }
        self.rows.swap(index, index - 1);
        Ok(())
    }

    /// Move a library down in the ordinal order.
    ///
    /// Returns `Err` if the move is not possible.
    pub fn move_down(&mut self, index: usize) -> Result<(), String> {
        if index >= self.rows.len() - 1 {
            return Err("Cannot move down".to_string());
        }
        if self.rows[index].name() == UNKNOWN_LIBRARY {
            return Err("Cannot move UNKNOWN library".to_string());
        }
        self.rows.swap(index, index + 1);
        Ok(())
    }

    /// Set the file path for a library.
    pub fn set_library_path(
        &mut self,
        index: usize,
        path: Option<String>,
    ) -> Result<(), String> {
        if index >= self.rows.len() {
            return Err("Invalid index".to_string());
        }
        self.rows[index].set_path(path);
        Ok(())
    }

    /// Get the library names that have external locations (i.e., are referenced).
    ///
    /// In a full implementation this would query the external manager.
    /// Here we accept the list of names that have locations.
    pub fn libraries_with_locations(&self, names_with_locations: &[&str]) -> Vec<String> {
        self.rows
            .iter()
            .filter(|r| names_with_locations.contains(&r.name()))
            .map(|r| r.name().to_string())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_add_library() {
        let mut provider = ExternalReferencesProvider::new();
        provider.add_library("libc.so").unwrap();
        assert_eq!(provider.row_count(), 1);
        assert_eq!(provider.get_row(0).unwrap().name(), "libc.so");
    }

    #[test]
    fn test_provider_add_duplicate() {
        let mut provider = ExternalReferencesProvider::new();
        provider.add_library("libc.so").unwrap();
        assert!(provider.add_library("libc.so").is_err());
    }

    #[test]
    fn test_provider_add_empty() {
        let mut provider = ExternalReferencesProvider::new();
        assert!(provider.add_library("").is_err());
        assert!(provider.add_library("   ").is_err());
    }

    #[test]
    fn test_provider_remove_library() {
        let mut provider = ExternalReferencesProvider::new();
        provider.add_library("libc.so").unwrap();
        let removed = provider.remove_library(0).unwrap();
        assert_eq!(removed.name(), "libc.so");
        assert_eq!(provider.row_count(), 0);
    }

    #[test]
    fn test_provider_rename_library() {
        let mut provider = ExternalReferencesProvider::new();
        provider.add_library("libc.so").unwrap();
        provider.rename_library(0, "libc.so.6").unwrap();
        assert_eq!(provider.get_row(0).unwrap().name(), "libc.so.6");
    }

    #[test]
    fn test_provider_rename_to_existing() {
        let mut provider = ExternalReferencesProvider::new();
        provider.add_library("libc.so").unwrap();
        provider.add_library("libm.so").unwrap();
        assert!(provider.rename_library(0, "libm.so").is_err());
    }

    #[test]
    fn test_provider_move_up() {
        let mut provider = ExternalReferencesProvider::new();
        provider.add_library("aaa").unwrap();
        provider.add_library("bbb").unwrap();
        provider.add_library("ccc").unwrap();
        provider.move_up(2).unwrap();
        assert_eq!(provider.get_row(1).unwrap().name(), "ccc");
        assert_eq!(provider.get_row(2).unwrap().name(), "bbb");
    }

    #[test]
    fn test_provider_move_down() {
        let mut provider = ExternalReferencesProvider::new();
        provider.add_library("aaa").unwrap();
        provider.add_library("bbb").unwrap();
        provider.move_down(0).unwrap();
        assert_eq!(provider.get_row(0).unwrap().name(), "bbb");
        assert_eq!(provider.get_row(1).unwrap().name(), "aaa");
    }

    #[test]
    fn test_provider_move_first_up_fails() {
        let mut provider = ExternalReferencesProvider::new();
        provider.add_library("aaa").unwrap();
        assert!(provider.move_up(0).is_err());
    }

    #[test]
    fn test_provider_library_names() {
        let mut provider = ExternalReferencesProvider::new();
        provider.set_external_names(vec![
            ExternalNameRow::new(UNKNOWN_LIBRARY, None),
            ExternalNameRow::new("libc.so", Some("/usr/lib/libc.so".to_string())),
        ]);
        let names = provider.library_names();
        assert_eq!(names, vec!["libc.so"]);
    }

    #[test]
    fn test_provider_set_path() {
        let mut provider = ExternalReferencesProvider::new();
        provider.add_library("libc.so").unwrap();
        provider
            .set_library_path(0, Some("/usr/lib/libc.so".to_string()))
            .unwrap();
        assert_eq!(
            provider.get_row(0).unwrap().path(),
            Some("/usr/lib/libc.so")
        );
    }

    #[test]
    fn test_provider_find_by_name() {
        let mut provider = ExternalReferencesProvider::new();
        provider.add_library("aaa").unwrap();
        provider.add_library("bbb").unwrap();
        assert_eq!(provider.find_by_name("bbb"), Some(1));
        assert_eq!(provider.find_by_name("zzz"), None);
    }

    #[test]
    fn test_external_name_row_display() {
        let row = ExternalNameRow::new("libc.so", Some("/usr/lib/libc.so".to_string()));
        let display = format!("{}", row);
        assert!(display.contains("libc.so"));
        assert!(display.contains("/usr/lib/libc.so"));
    }

    #[test]
    fn test_external_name_row_display_no_path() {
        let row = ExternalNameRow::new("libm.so", None);
        let display = format!("{}", row);
        assert_eq!(display, "libm.so");
    }

    #[test]
    fn test_provider_libraries_with_locations() {
        let mut provider = ExternalReferencesProvider::new();
        provider.add_library("libc.so").unwrap();
        provider.add_library("libm.so").unwrap();
        provider.add_library("libz.so").unwrap();
        let with_loc = provider.libraries_with_locations(&["libc.so", "libz.so"]);
        assert_eq!(with_loc.len(), 2);
        assert!(with_loc.contains(&"libc.so".to_string()));
        assert!(with_loc.contains(&"libz.so".to_string()));
    }
}
