//! Script file list management.
//!
//! Ported from `ghidra.app.plugin.core.script.ScriptList`.
//!
//! Loads and manages the list of available script files from configured
//! script directories. Supports change notification and lazy loading.

use std::path::{Path, PathBuf};

/// A discovered script file on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptFile {
    /// Full path to the script file.
    pub path: PathBuf,
    /// The script name (filename without extension).
    pub name: String,
    /// The file extension (e.g., "py", "java", "groovy").
    pub extension: String,
    /// The directory this script was found in.
    pub directory: PathBuf,
    /// Whether this script is inside a bundle (OSGi).
    pub in_bundle: bool,
}

impl ScriptFile {
    /// Create a new script file.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let name = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let extension = path
            .extension()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let directory = path.parent().map(|p| p.to_path_buf()).unwrap_or_default();
        Self {
            path,
            name,
            extension,
            directory,
            in_bundle: false,
        }
    }

    /// The full filename (name + extension).
    pub fn filename(&self) -> String {
        if self.extension.is_empty() {
            self.name.clone()
        } else {
            format!("{}.{}", self.name, self.extension)
        }
    }

    /// Check if this is a known script extension.
    pub fn is_script(&self) -> bool {
        matches!(
            self.extension.as_str(),
            "py" | "java" | "groovy" | "class" | "sh" | "bash"
        )
    }
}

/// Trait for receiving script list change notifications.
pub trait ScriptListListener: Send + Sync {
    /// Called when the script list has changed.
    fn on_scripts_changed(&self, count: usize);
}

/// Manages the list of available script files.
///
/// Ported from `ghidra.app.plugin.core.script.ScriptList`.
#[derive(Debug)]
pub struct ScriptList {
    /// Known script files.
    scripts: Vec<ScriptFile>,
    /// Script directories to search.
    search_dirs: Vec<PathBuf>,
    /// Whether the list has been loaded.
    loaded: bool,
    /// Maximum scripts to track.
    max_scripts: usize,
}

impl ScriptList {
    /// Create a new script list.
    pub fn new() -> Self {
        Self {
            scripts: Vec::new(),
            search_dirs: Vec::new(),
            loaded: false,
            max_scripts: 10000,
        }
    }

    /// Add a search directory.
    pub fn add_search_dir(&mut self, dir: PathBuf) {
        if !self.search_dirs.contains(&dir) {
            self.search_dirs.push(dir);
        }
    }

    /// Remove a search directory.
    pub fn remove_search_dir(&mut self, dir: &Path) {
        self.search_dirs.retain(|d| d != dir);
    }

    /// Get the search directories.
    pub fn search_dirs(&self) -> &[PathBuf] {
        &self.search_dirs
    }

    /// Load the script list by scanning directories.
    pub fn load(&mut self) {
        if self.loaded {
            return;
        }
        self.do_refresh();
    }

    /// Force a refresh of the script list.
    pub fn refresh(&mut self) {
        self.loaded = false;
        self.do_refresh();
    }

    fn do_refresh(&mut self) {
        self.scripts.clear();
        for dir in &self.search_dirs.clone() {
            self.scan_directory(dir);
        }
        self.loaded = true;
    }

    fn scan_directory(&mut self, dir: &Path) {
        if !dir.exists() || !dir.is_dir() {
            return;
        }
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let mut script = ScriptFile::new(&path);
                    script.directory = dir.to_path_buf();
                    if script.is_script() && self.scripts.len() < self.max_scripts {
                        self.scripts.push(script);
                    }
                } else if path.is_dir() {
                    // Recurse into subdirectories
                    self.scan_directory(&path);
                }
            }
        }
    }

    /// Register a script file manually.
    pub fn register(&mut self, script: ScriptFile) {
        if !self.scripts.iter().any(|s| s.path == script.path) {
            self.scripts.push(script);
        }
    }

    /// Remove a script file.
    pub fn unregister(&mut self, path: &Path) -> Option<ScriptFile> {
        if let Some(pos) = self.scripts.iter().position(|s| s.path == path) {
            Some(self.scripts.remove(pos))
        } else {
            None
        }
    }

    /// Get all scripts.
    pub fn scripts(&self) -> &[ScriptFile] {
        &self.scripts
    }

    /// Get script count.
    pub fn len(&self) -> usize {
        self.scripts.len()
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.scripts.is_empty()
    }

    /// Find a script by name.
    pub fn find_by_name(&self, name: &str) -> Option<&ScriptFile> {
        self.scripts.iter().find(|s| s.name == name)
    }

    /// Find a script by path.
    pub fn find_by_path(&self, path: &Path) -> Option<&ScriptFile> {
        self.scripts.iter().find(|s| s.path == path)
    }

    /// Get scripts grouped by directory.
    pub fn group_by_directory(&self) -> std::collections::BTreeMap<PathBuf, Vec<&ScriptFile>> {
        let mut map = std::collections::BTreeMap::new();
        for script in &self.scripts {
            map.entry(script.directory.clone())
                .or_insert_with(Vec::new)
                .push(script);
        }
        map
    }

    /// Get scripts filtered by extension.
    pub fn scripts_with_extension(&self, ext: &str) -> Vec<&ScriptFile> {
        self.scripts
            .iter()
            .filter(|s| s.extension.eq_ignore_ascii_case(ext))
            .collect()
    }

    /// Whether the list has been loaded.
    pub fn is_loaded(&self) -> bool {
        self.loaded
    }
}

impl Default for ScriptList {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_file_new() {
        let f = ScriptFile::new("/scripts/MyScript.py");
        assert_eq!(f.name, "MyScript");
        assert_eq!(f.extension, "py");
        assert_eq!(f.filename(), "MyScript.py");
        assert!(f.is_script());
    }

    #[test]
    fn test_script_file_non_script() {
        let f = ScriptFile::new("/scripts/data.txt");
        assert!(!f.is_script());
    }

    #[test]
    fn test_script_file_known_extensions() {
        assert!(ScriptFile::new("/a.py").is_script());
        assert!(ScriptFile::new("/a.java").is_script());
        assert!(ScriptFile::new("/a.groovy").is_script());
        assert!(ScriptFile::new("/a.sh").is_script());
        assert!(!ScriptFile::new("/a.rs").is_script());
    }

    #[test]
    fn test_script_list_lifecycle() {
        let mut list = ScriptList::new();
        assert!(list.is_empty());
        assert!(!list.is_loaded());

        list.register(ScriptFile::new("/scripts/a.py"));
        list.register(ScriptFile::new("/scripts/b.java"));
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_script_list_register_dedup() {
        let mut list = ScriptList::new();
        list.register(ScriptFile::new("/scripts/a.py"));
        list.register(ScriptFile::new("/scripts/a.py"));
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn test_script_list_find_by_name() {
        let mut list = ScriptList::new();
        list.register(ScriptFile::new("/scripts/MyScript.py"));
        assert!(list.find_by_name("MyScript").is_some());
        assert!(list.find_by_name("Missing").is_none());
    }

    #[test]
    fn test_script_list_find_by_path() {
        let mut list = ScriptList::new();
        list.register(ScriptFile::new("/scripts/a.py"));
        assert!(list.find_by_path(Path::new("/scripts/a.py")).is_some());
        assert!(list.find_by_path(Path::new("/scripts/b.py")).is_none());
    }

    #[test]
    fn test_script_list_unregister() {
        let mut list = ScriptList::new();
        list.register(ScriptFile::new("/scripts/a.py"));
        let removed = list.unregister(Path::new("/scripts/a.py"));
        assert!(removed.is_some());
        assert!(list.is_empty());
    }

    #[test]
    fn test_script_list_filter_by_extension() {
        let mut list = ScriptList::new();
        list.register(ScriptFile::new("/scripts/a.py"));
        list.register(ScriptFile::new("/scripts/b.java"));
        list.register(ScriptFile::new("/scripts/c.py"));
        assert_eq!(list.scripts_with_extension("py").len(), 2);
        assert_eq!(list.scripts_with_extension("java").len(), 1);
    }

    #[test]
    fn test_script_list_group_by_directory() {
        let mut list = ScriptList::new();
        list.register(ScriptFile::new("/dir1/a.py"));
        list.register(ScriptFile::new("/dir1/b.py"));
        list.register(ScriptFile::new("/dir2/c.py"));
        let groups = list.group_by_directory();
        assert_eq!(groups.len(), 2);
    }

    #[test]
    fn test_script_list_search_dirs() {
        let mut list = ScriptList::new();
        list.add_search_dir(PathBuf::from("/scripts"));
        list.add_search_dir(PathBuf::from("/user/scripts"));
        assert_eq!(list.search_dirs().len(), 2);

        // Adding the same dir again should not duplicate
        list.add_search_dir(PathBuf::from("/scripts"));
        assert_eq!(list.search_dirs().len(), 2);

        list.remove_search_dir(Path::new("/scripts"));
        assert_eq!(list.search_dirs().len(), 1);
    }
}
