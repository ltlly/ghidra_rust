//! Script provider for PyGhidra Python scripts.
//!
//! Ported from `ghidra.pyghidra.PyGhidraScriptProvider`.
//! Manages the discovery and loading of `.py` scripts.

use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// PyGhidraScriptProvider
// ---------------------------------------------------------------------------

/// Provides discovery and management of PyGhidra Python scripts.
///
/// Matches Java's `ghidra.pyghidra.PyGhidraScriptProvider`.
pub struct PyGhidraScriptProvider {
    /// Directories to search for scripts.
    search_dirs: Vec<PathBuf>,
    /// The file extension for Python scripts.
    extension: String,
}

impl PyGhidraScriptProvider {
    /// Create a new script provider.
    pub fn new() -> Self {
        Self {
            search_dirs: Vec::new(),
            extension: ".py".to_string(),
        }
    }

    /// Add a directory to the script search path.
    pub fn add_search_dir(&mut self, dir: PathBuf) {
        self.search_dirs.push(dir);
    }

    /// Get the file extension for Python scripts.
    pub fn extension(&self) -> &str {
        &self.extension
    }

    /// Check if a file is a Python script.
    pub fn is_python_script(&self, path: &Path) -> bool {
        path.extension()
            .map(|ext| ext == "py")
            .unwrap_or(false)
    }

    /// Get all search directories.
    pub fn search_dirs(&self) -> &[PathBuf] {
        &self.search_dirs
    }

    /// Find all Python scripts in the search directories.
    pub fn find_scripts(&self) -> Vec<PathBuf> {
        let mut scripts = Vec::new();
        for dir in &self.search_dirs {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if self.is_python_script(&path) {
                        scripts.push(path);
                    }
                }
            }
        }
        scripts.sort();
        scripts
    }
}

impl Default for PyGhidraScriptProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_provider() {
        let provider = PyGhidraScriptProvider::new();
        assert_eq!(provider.extension(), ".py");
        assert!(provider.search_dirs().is_empty());
    }

    #[test]
    fn test_is_python_script() {
        let provider = PyGhidraScriptProvider::new();
        assert!(provider.is_python_script(Path::new("test.py")));
        assert!(!provider.is_python_script(Path::new("test.java")));
        assert!(!provider.is_python_script(Path::new("test")));
    }

    #[test]
    fn test_find_scripts_in_dir() {
        let dir = tempfile::tempdir().unwrap();
        // Create some test files
        std::fs::write(dir.path().join("script1.py"), "print('hello')").unwrap();
        std::fs::write(dir.path().join("script2.py"), "print('world')").unwrap();
        std::fs::write(dir.path().join("readme.txt"), "not a script").unwrap();

        let mut provider = PyGhidraScriptProvider::new();
        provider.add_search_dir(dir.path().to_path_buf());

        let scripts = provider.find_scripts();
        assert_eq!(scripts.len(), 2);
    }
}
