//! File chooser types.
//!
//! Ports Ghidra's `ghidra.util.filechooser` types for selecting files.

use std::path::{Path, PathBuf};

/// File filter for the file chooser.
#[derive(Debug, Clone)]
pub struct FileFilter {
    /// Human-readable description of the filter.
    pub description: String,
    /// File extensions to include (e.g., ["exe", "elf", "bin"]).
    pub extensions: Vec<String>,
}

impl FileFilter {
    /// Create a new file filter.
    pub fn new(description: impl Into<String>, extensions: Vec<String>) -> Self {
        Self {
            description: description.into(),
            extensions,
        }
    }

    /// Check if a file path matches this filter.
    pub fn matches(&self, path: &Path) -> bool {
        if self.extensions.is_empty() {
            return true; // no filter = accept all
        }
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            self.extensions.iter().any(|e| e.eq_ignore_ascii_case(ext))
        } else {
            false
        }
    }
}

/// Result of a file chooser operation.
#[derive(Debug, Clone)]
pub enum FileChooserResult {
    /// User selected one or more files.
    Files(Vec<PathBuf>),
    /// User selected a directory.
    Directory(PathBuf),
    /// User cancelled.
    Cancelled,
    /// Error during file selection.
    Error(String),
}

/// File chooser mode (what can be selected).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileChooserMode {
    /// Select files only.
    Files,
    /// Select directories only.
    Directories,
    /// Select files and directories.
    FilesAndDirectories,
}

impl Default for FileChooserMode {
    fn default() -> Self {
        Self::Files
    }
}

/// A file chooser dialog configuration.
///
/// Mirrors Ghidra's `ghidra.util.filechooser.GhidraFileChooser`.
#[derive(Debug, Clone)]
pub struct GhidraFileChooser {
    title: String,
    mode: FileChooserMode,
    filters: Vec<FileFilter>,
    current_directory: Option<PathBuf>,
    selected_file: Option<PathBuf>,
    multi_select: bool,
}

impl GhidraFileChooser {
    /// Create a new file chooser.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            mode: FileChooserMode::default(),
            filters: Vec::new(),
            current_directory: None,
            selected_file: None,
            multi_select: false,
        }
    }

    /// Set the chooser mode.
    pub fn set_mode(&mut self, mode: FileChooserMode) {
        self.mode = mode;
    }

    /// Get the chooser mode.
    pub fn mode(&self) -> FileChooserMode {
        self.mode
    }

    /// Add a file filter.
    pub fn add_filter(&mut self, filter: FileFilter) {
        self.filters.push(filter);
    }

    /// Get the filters.
    pub fn filters(&self) -> &[FileFilter] {
        &self.filters
    }

    /// Set the current directory.
    pub fn set_current_directory(&mut self, dir: PathBuf) {
        self.current_directory = Some(dir);
    }

    /// Get the current directory.
    pub fn current_directory(&self) -> Option<&Path> {
        self.current_directory.as_deref()
    }

    /// Set the selected file.
    pub fn set_selected_file(&mut self, file: PathBuf) {
        self.selected_file = Some(file);
    }

    /// Get the selected file.
    pub fn selected_file(&self) -> Option<&Path> {
        self.selected_file.as_deref()
    }

    /// Enable multi-select.
    pub fn set_multi_select(&mut self, multi: bool) {
        self.multi_select = multi;
    }

    /// Get the title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Check if a file matches any active filter.
    pub fn matches_any_filter(&self, path: &Path) -> bool {
        if self.filters.is_empty() {
            return true;
        }
        self.filters.iter().any(|f| f.matches(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_filter_matches() {
        let filter = FileFilter::new("Executables", vec!["exe".into(), "elf".into(), "bin".into()]);
        assert!(filter.matches(Path::new("test.exe")));
        assert!(filter.matches(Path::new("test.ELF"))); // case insensitive
        assert!(filter.matches(Path::new("test.bin")));
        assert!(!filter.matches(Path::new("test.txt")));
    }

    #[test]
    fn test_file_filter_empty_accepts_all() {
        let filter = FileFilter::new("All Files", vec![]);
        assert!(filter.matches(Path::new("anything.xyz")));
    }

    #[test]
    fn test_file_chooser_basic() {
        let chooser = GhidraFileChooser::new("Open File");
        assert_eq!(chooser.title(), "Open File");
        assert_eq!(chooser.mode(), FileChooserMode::Files);
        assert!(chooser.filters().is_empty());
    }

    #[test]
    fn test_file_chooser_mode() {
        let mut chooser = GhidraFileChooser::new("Test");
        chooser.set_mode(FileChooserMode::Directories);
        assert_eq!(chooser.mode(), FileChooserMode::Directories);
    }

    #[test]
    fn test_file_chooser_filters() {
        let mut chooser = GhidraFileChooser::new("Test");
        chooser.add_filter(FileFilter::new("Executables", vec!["exe".into()]));
        chooser.add_filter(FileFilter::new("All", vec![]));

        assert!(chooser.matches_any_filter(Path::new("test.exe")));
        assert!(chooser.matches_any_filter(Path::new("test.txt"))); // "All" filter matches
    }

    #[test]
    fn test_file_chooser_directory() {
        let mut chooser = GhidraFileChooser::new("Test");
        chooser.set_current_directory(PathBuf::from("/home/user"));
        assert_eq!(chooser.current_directory(), Some(Path::new("/home/user")));
    }

    #[test]
    fn test_file_chooser_selected() {
        let mut chooser = GhidraFileChooser::new("Test");
        assert!(chooser.selected_file().is_none());
        chooser.set_selected_file(PathBuf::from("/tmp/test.bin"));
        assert_eq!(chooser.selected_file(), Some(Path::new("/tmp/test.bin")));
    }

    #[test]
    fn test_file_chooser_multi_select() {
        let mut chooser = GhidraFileChooser::new("Test");
        chooser.set_multi_select(true);
        assert!(chooser.multi_select);
    }
}
