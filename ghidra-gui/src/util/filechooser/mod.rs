//! File chooser abstractions.
//!
//! Ports `ghidra.util.filechooser` package.

use std::path::{Path, PathBuf};

/// A file filter for the file chooser.
#[derive(Debug, Clone)]
pub struct GhidraFileFilter {
    /// Filter description (e.g., "XML Files (*.xml)").
    pub description: String,
    /// File extensions accepted by this filter.
    pub extensions: Vec<String>,
}

impl GhidraFileFilter {
    /// Create a new file filter.
    pub fn new(description: impl Into<String>, extensions: Vec<String>) -> Self {
        Self {
            description: description.into(),
            extensions,
        }
    }

    /// Test if a filename matches this filter.
    pub fn accept(&self, path: &Path) -> bool {
        if self.extensions.is_empty() {
            return true;
        }
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            self.extensions.iter().any(|e| e.eq_ignore_ascii_case(ext))
        } else {
            false
        }
    }
}

/// Extension-based file filter.
///
/// Ports `ghidra.util.filechooser.ExtensionFileFilter`.
#[derive(Debug, Clone)]
pub struct ExtensionFileFilter {
    /// The file filter.
    pub filter: GhidraFileFilter,
}

impl ExtensionFileFilter {
    /// Create a new extension file filter.
    pub fn new(description: impl Into<String>, extensions: Vec<String>) -> Self {
        Self {
            filter: GhidraFileFilter::new(description, extensions),
        }
    }

    /// Test if a path matches.
    pub fn accept(&self, path: &Path) -> bool {
        self.filter.accept(path)
    }
}

/// File chooser model for populating the file list.
///
/// Ports `ghidra.util.filechooser.GhidraFileChooserModel`.
#[derive(Debug, Clone, Default)]
pub struct GhidraFileChooserModel {
    /// Current directory.
    pub current_dir: PathBuf,
    /// Available file filters.
    pub filters: Vec<GhidraFileFilter>,
    /// Currently selected filter index.
    pub active_filter: Option<usize>,
    /// Whether to show hidden files.
    pub show_hidden: bool,
}

impl GhidraFileChooserModel {
    /// Create a new file chooser model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the current directory.
    pub fn set_current_dir(&mut self, dir: PathBuf) {
        self.current_dir = dir;
    }

    /// Add a file filter.
    pub fn add_filter(&mut self, filter: GhidraFileFilter) {
        self.filters.push(filter);
    }

    /// Set the active filter by index.
    pub fn set_active_filter(&mut self, index: usize) {
        if index < self.filters.len() {
            self.active_filter = Some(index);
        }
    }

    /// Get the active filter, if any.
    pub fn active_filter(&self) -> Option<&GhidraFileFilter> {
        self.active_filter.and_then(|i| self.filters.get(i))
    }

    /// Filter a list of paths by the active filter.
    pub fn apply_filter(&self, paths: &[PathBuf]) -> Vec<PathBuf> {
        if let Some(filter) = self.active_filter() {
            paths
                .iter()
                .filter(|p| filter.accept(p))
                .cloned()
                .collect()
        } else {
            paths.to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_filter_matches_extension() {
        let filter = GhidraFileFilter::new("XML Files", vec!["xml".to_string()]);
        assert!(filter.accept(Path::new("test.xml")));
        assert!(filter.accept(Path::new("test.XML")));
        assert!(!filter.accept(Path::new("test.txt")));
    }

    #[test]
    fn file_filter_no_extensions_accepts_all() {
        let filter = GhidraFileFilter::new("All Files", vec![]);
        assert!(filter.accept(Path::new("anything.xyz")));
    }

    #[test]
    fn file_filter_multiple_extensions() {
        let filter = GhidraFileFilter::new("Images", vec!["png".to_string(), "jpg".to_string()]);
        assert!(filter.accept(Path::new("photo.png")));
        assert!(filter.accept(Path::new("photo.jpg")));
        assert!(!filter.accept(Path::new("photo.gif")));
    }

    #[test]
    fn chooser_model_filter() {
        let mut model = GhidraFileChooserModel::new();
        model.add_filter(GhidraFileFilter::new("Rust", vec!["rs".to_string()]));
        model.set_active_filter(0);

        let paths = vec![
            PathBuf::from("main.rs"),
            PathBuf::from("readme.md"),
            PathBuf::from("lib.rs"),
        ];
        let filtered = model.apply_filter(&paths);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn chooser_model_no_filter() {
        let model = GhidraFileChooserModel::new();
        let paths = vec![PathBuf::from("a.txt"), PathBuf::from("b.rs")];
        let filtered = model.apply_filter(&paths);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn extension_file_filter() {
        let filter = ExtensionFileFilter::new("Java", vec!["java".to_string()]);
        assert!(filter.accept(Path::new("Foo.java")));
    }
}
