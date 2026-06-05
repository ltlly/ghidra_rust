//! ProjectPathChooserEditor -- project path chooser for options.
//!
//! Ported from `ghidra.app.plugin.core.analysis.ProjectPathChooserEditor`.
//!
//! Provides a property editor that allows users to select a path within
//! a Ghidra project for use in analysis options (e.g., specifying a
//! data archive location).

use std::path::PathBuf;

/// Property editor for choosing a project path.
///
/// Ported from Ghidra's `ProjectPathChooserEditor`. This editor allows
/// users to select a file or folder path within the Ghidra project for
/// configuration options that require a path (e.g., specifying where to
/// find data archives).
///
/// In the Rust port, this is a data model without GUI components.
#[derive(Debug, Clone)]
pub struct ProjectPathChooserEditor {
    /// The current selected path.
    path: PathBuf,
    /// The root path for browsing.
    root_path: PathBuf,
    /// Whether to select files (true) or directories (false).
    select_files: bool,
    /// File filter description (e.g., "XML Files (*.xml)").
    filter_description: Option<String>,
    /// Allowed file extensions.
    allowed_extensions: Vec<String>,
}

impl ProjectPathChooserEditor {
    /// Create a new project path chooser editor.
    pub fn new() -> Self {
        Self {
            path: PathBuf::new(),
            root_path: PathBuf::new(),
            select_files: true,
            filter_description: None,
            allowed_extensions: Vec::new(),
        }
    }

    /// Create with a root path.
    pub fn with_root(root: PathBuf) -> Self {
        Self {
            root_path: root,
            ..Self::new()
        }
    }

    /// Get the current selected path.
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Set the selected path.
    pub fn set_path(&mut self, path: PathBuf) {
        self.path = path;
    }

    /// Get the root path.
    pub fn root_path(&self) -> &PathBuf {
        &self.root_path
    }

    /// Set the root path.
    pub fn set_root_path(&mut self, root: PathBuf) {
        self.root_path = root;
    }

    /// Whether the editor selects files (vs directories).
    pub fn select_files(&self) -> bool {
        self.select_files
    }

    /// Set whether to select files or directories.
    pub fn set_select_files(&mut self, select_files: bool) {
        self.select_files = select_files;
    }

    /// Get the filter description.
    pub fn filter_description(&self) -> Option<&str> {
        self.filter_description.as_deref()
    }

    /// Set the filter description.
    pub fn set_filter_description(&mut self, desc: Option<String>) {
        self.filter_description = desc;
    }

    /// Get the allowed file extensions.
    pub fn allowed_extensions(&self) -> &[String] {
        &self.allowed_extensions
    }

    /// Add an allowed file extension.
    pub fn add_extension(&mut self, ext: String) {
        self.allowed_extensions.push(ext);
    }

    /// Check if a path matches the filter.
    pub fn matches_filter(&self, path: &PathBuf) -> bool {
        if self.allowed_extensions.is_empty() {
            return true;
        }
        path.extension().map_or(false, |ext| {
            let ext_str = ext.to_string_lossy().to_lowercase();
            self.allowed_extensions
                .iter()
                .any(|allowed| allowed.to_lowercase() == ext_str)
        })
    }
}

impl Default for ProjectPathChooserEditor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_editor_creation() {
        let editor = ProjectPathChooserEditor::new();
        assert!(editor.path().as_os_str().is_empty());
        assert!(editor.select_files());
        assert!(editor.filter_description().is_none());
        assert!(editor.allowed_extensions().is_empty());
    }

    #[test]
    fn test_editor_with_root() {
        let editor = ProjectPathChooserEditor::with_root(PathBuf::from("/project"));
        assert_eq!(editor.root_path(), &PathBuf::from("/project"));
    }

    #[test]
    fn test_editor_set_path() {
        let mut editor = ProjectPathChooserEditor::new();
        editor.set_path(PathBuf::from("/some/path/file.xml"));
        assert_eq!(editor.path(), &PathBuf::from("/some/path/file.xml"));
    }

    #[test]
    fn test_editor_filter() {
        let mut editor = ProjectPathChooserEditor::new();
        editor.add_extension("xml".to_string());
        editor.add_extension("json".to_string());
        assert!(editor.matches_filter(&PathBuf::from("test.xml")));
        assert!(editor.matches_filter(&PathBuf::from("test.json")));
        assert!(!editor.matches_filter(&PathBuf::from("test.txt")));
    }

    #[test]
    fn test_editor_filter_empty() {
        let editor = ProjectPathChooserEditor::new();
        // No extensions means everything matches
        assert!(editor.matches_filter(&PathBuf::from("anything.xyz")));
    }

    #[test]
    fn test_editor_select_directories() {
        let mut editor = ProjectPathChooserEditor::new();
        editor.set_select_files(false);
        assert!(!editor.select_files());
    }
}
