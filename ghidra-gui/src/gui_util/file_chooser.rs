//! File chooser model and filters.
//!
//! Ports Ghidra's `ghidra.util.filechooser` package:
//! - `GhidraFileChooserModel` -- abstract file chooser model
//! - `GhidraFileFilter` -- file filter trait
//! - `ExtensionFileFilter` -- filter by file extension

use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

/// Trait for filtering files in a file chooser.
///
/// Port of Ghidra's `ghidra.util.filechooser.GhidraFileFilter`.
pub trait GhidraFileFilter: std::fmt::Debug {
    /// Human-readable description of this filter.
    fn description(&self) -> &str;

    /// Whether the given path passes this filter.
    fn accept(&self, path: &Path) -> bool;
}

/// Filters files by extension.
///
/// Port of Ghidra's `ghidra.util.filechooser.ExtensionFileFilter`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionFileFilter {
    /// The file extension (without the dot).
    pub extension: String,
    /// Human-readable description.
    pub description: String,
}

impl ExtensionFileFilter {
    /// Create a new extension file filter.
    pub fn new(extension: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            extension: extension.into(),
            description: description.into(),
        }
    }

    /// Create a filter that accepts multiple extensions.
    pub fn multiple(extensions: Vec<String>, description: impl Into<String>) -> MultiExtensionFileFilter {
        MultiExtensionFileFilter {
            extensions,
            description: description.into(),
        }
    }
}

impl GhidraFileFilter for ExtensionFileFilter {
    fn description(&self) -> &str {
        &self.description
    }

    fn accept(&self, path: &Path) -> bool {
        match path.extension() {
            Some(ext) => ext.to_string_lossy().to_lowercase() == self.extension.to_lowercase(),
            None => false,
        }
    }
}

/// Filters files by multiple extensions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiExtensionFileFilter {
    /// Accepted extensions (without dots).
    pub extensions: Vec<String>,
    /// Human-readable description.
    pub description: String,
}

impl GhidraFileFilter for MultiExtensionFileFilter {
    fn description(&self) -> &str {
        &self.description
    }

    fn accept(&self, path: &Path) -> bool {
        match path.extension() {
            Some(ext) => {
                let ext_lower = ext.to_string_lossy().to_lowercase();
                self.extensions.iter().any(|e| e.to_lowercase() == ext_lower)
            }
            None => false,
        }
    }
}

/// File chooser directory entry.
#[derive(Debug, Clone)]
pub struct FileChooserEntry {
    /// The full path.
    pub path: PathBuf,
    /// Whether this is a directory.
    pub is_directory: bool,
    /// File size in bytes (0 for directories).
    pub size: u64,
    /// Display name.
    pub name: String,
}

impl FileChooserEntry {
    /// Create a new file chooser entry.
    pub fn new(path: PathBuf) -> Self {
        let is_directory = path.is_dir();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let size = if is_directory {
            0
        } else {
            path.metadata().map(|m| m.len()).unwrap_or(0)
        };
        Self {
            path,
            is_directory,
            size,
            name,
        }
    }
}

/// Abstract model for a file chooser.
///
/// Port of Ghidra's `ghidra.util.filechooser.GhidraFileChooserModel`.
#[derive(Debug)]
pub struct GhidraFileChooserModel {
    /// The current directory.
    current_dir: Option<PathBuf>,
    /// Available filters.
    filters: Vec<Box<dyn GhidraFileFilter>>,
    /// Currently selected filter index.
    selected_filter: Option<usize>,
}

impl Default for GhidraFileChooserModel {
    fn default() -> Self {
        Self {
            current_dir: None,
            filters: Vec::new(),
            selected_filter: None,
        }
    }
}

impl GhidraFileChooserModel {
    /// Create a new file chooser model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the current directory.
    pub fn set_current_directory(&mut self, dir: PathBuf) {
        self.current_dir = Some(dir);
    }

    /// Get the current directory.
    pub fn current_directory(&self) -> Option<&Path> {
        self.current_dir.as_deref()
    }

    /// List entries in the current directory.
    pub fn list_entries(&self) -> Vec<FileChooserEntry> {
        let dir = match &self.current_dir {
            Some(d) => d,
            None => return Vec::new(),
        };

        let mut entries = Vec::new();
        if let Ok(read_dir) = std::fs::read_dir(dir) {
            for entry in read_dir.flatten() {
                entries.push(FileChooserEntry::new(entry.path()));
            }
        }
        entries.sort_by(|a, b| {
            // Directories first, then alphabetical.
            b.is_directory
                .cmp(&a.is_directory)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        entries
    }

    /// List entries filtered by the current filter.
    pub fn list_filtered_entries(&self) -> Vec<FileChooserEntry> {
        let entries = self.list_entries();
        match self.selected_filter.and_then(|i| self.filters.get(i)) {
            Some(filter) => entries
                .into_iter()
                .filter(|e| e.is_directory || filter.accept(&e.path))
                .collect(),
            None => entries,
        }
    }

    /// Add a file filter.
    pub fn add_filter(&mut self, filter: Box<dyn GhidraFileFilter>) {
        self.filters.push(filter);
    }

    /// Get the list of available filters.
    pub fn filter_count(&self) -> usize {
        self.filters.len()
    }

    /// Get a filter description by index.
    pub fn filter_description(&self, index: usize) -> Option<&str> {
        self.filters.get(index).map(|f| f.description())
    }

    /// Set the selected filter.
    pub fn set_selected_filter(&mut self, index: usize) {
        if index < self.filters.len() {
            self.selected_filter = Some(index);
        }
    }

    /// Get the selected filter index.
    pub fn selected_filter(&self) -> Option<usize> {
        self.selected_filter
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn extension_filter_matches() {
        let filter = ExtensionFileFilter::new("rs", "Rust files");
        assert!(filter.accept(&PathBuf::new().join("main.rs")));
        assert!(filter.accept(&PathBuf::new().join("lib.RS")));
        assert!(!filter.accept(&PathBuf::new().join("main.py")));
        assert_eq!(filter.description(), "Rust files");
    }

    #[test]
    fn multi_extension_filter() {
        let filter = ExtensionFileFilter::multiple(
            vec!["c".to_string(), "h".to_string(), "cpp".to_string()],
            "C/C++ files",
        );
        assert!(filter.accept(&PathBuf::new().join("foo.c")));
        assert!(filter.accept(&PathBuf::new().join("bar.H")));
        assert!(filter.accept(&PathBuf::new().join("baz.cpp")));
        assert!(!filter.accept(&PathBuf::new().join("main.rs")));
    }

    #[test]
    fn file_chooser_entry_directory() {
        let entry = FileChooserEntry {
            path: PathBuf::from("/tmp/test"),
            is_directory: true,
            size: 0,
            name: "test".to_string(),
        };
        assert!(entry.is_directory);
        assert_eq!(entry.size, 0);
    }

    #[test]
    fn file_chooser_model_filter_operations() {
        let mut model = GhidraFileChooserModel::new();
        assert_eq!(model.filter_count(), 0);

        model.add_filter(Box::new(ExtensionFileFilter::new("rs", "Rust")));
        model.add_filter(Box::new(ExtensionFileFilter::new("py", "Python")));
        assert_eq!(model.filter_count(), 2);
        assert_eq!(model.filter_description(0), Some("Rust"));
        assert_eq!(model.filter_description(1), Some("Python"));

        model.set_selected_filter(1);
        assert_eq!(model.selected_filter(), Some(1));
    }

    #[test]
    fn file_chooser_model_directory() {
        let mut model = GhidraFileChooserModel::new();
        assert!(model.current_directory().is_none());

        model.set_current_directory(PathBuf::from("/tmp"));
        assert_eq!(model.current_directory(), Some(Path::new("/tmp")));
    }

    #[test]
    fn extension_filter_no_extension() {
        let filter = ExtensionFileFilter::new("txt", "Text");
        assert!(!filter.accept(&PathBuf::new().join("Makefile")));
    }
}
