//! Jython script and script provider.
//!
//! Ported from `JythonScript.java` and `JythonScriptProvider.java`
//! in the Jython extension.

use std::path::PathBuf;

/// A Jython script that can be executed within Ghidra.
#[derive(Debug, Clone)]
pub struct JythonScript {
    /// The script name.
    pub name: String,
    /// The script source code.
    pub source: String,
    /// The file path, if loaded from disk.
    pub path: Option<PathBuf>,
    /// Whether the script requires a program to be open.
    pub requires_program: bool,
}

impl JythonScript {
    /// Create a new script from source code.
    pub fn new(name: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            source: source.into(),
            path: None,
            requires_program: true,
        }
    }

    /// Load a script from a file path.
    pub fn from_file(path: PathBuf) -> std::io::Result<Self> {
        let source = std::fs::read_to_string(&path)?;
        let name = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        Ok(Self {
            name,
            source,
            path: Some(path),
            requires_program: true,
        })
    }

    /// Get the number of lines in the script.
    pub fn num_lines(&self) -> usize {
        self.source.lines().count()
    }

    /// Whether the script is empty.
    pub fn is_empty(&self) -> bool {
        self.source.trim().is_empty()
    }
}

/// Provides script discovery and loading for Jython scripts.
///
/// Scans script directories for `.py` files and makes them available
/// for execution.
#[derive(Debug)]
pub struct JythonScriptProvider {
    /// Directories to search for scripts.
    search_paths: Vec<PathBuf>,
    /// Discovered scripts.
    scripts: Vec<JythonScript>,
}

impl JythonScriptProvider {
    /// Create a new script provider.
    pub fn new() -> Self {
        Self {
            search_paths: Vec::new(),
            scripts: Vec::new(),
        }
    }

    /// Add a search path for script discovery.
    pub fn add_search_path(&mut self, path: PathBuf) {
        self.search_paths.push(path);
    }

    /// Register a script directly.
    pub fn add_script(&mut self, script: JythonScript) {
        self.scripts.push(script);
    }

    /// Get all discovered scripts.
    pub fn scripts(&self) -> &[JythonScript] {
        &self.scripts
    }

    /// Find a script by name.
    pub fn find_by_name(&self, name: &str) -> Option<&JythonScript> {
        self.scripts.iter().find(|s| s.name == name)
    }

    /// Number of discovered scripts.
    pub fn num_scripts(&self) -> usize {
        self.scripts.len()
    }
}

impl Default for JythonScriptProvider {
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
    fn test_jython_script() {
        let script = JythonScript::new("test", "print('hello')");
        assert_eq!(script.name, "test");
        assert_eq!(script.num_lines(), 1);
        assert!(!script.is_empty());
    }

    #[test]
    fn test_empty_script() {
        let script = JythonScript::new("empty", "");
        assert!(script.is_empty());
    }

    #[test]
    fn test_multiline_script() {
        let script = JythonScript::new(
            "multi",
            "x = 1\ny = 2\nprint(x + y)",
        );
        assert_eq!(script.num_lines(), 3);
    }

    #[test]
    fn test_script_provider() {
        let mut provider = JythonScriptProvider::new();
        provider.add_script(JythonScript::new("hello", "print('hello')"));
        provider.add_script(JythonScript::new("world", "print('world')"));
        assert_eq!(provider.num_scripts(), 2);
        assert!(provider.find_by_name("hello").is_some());
        assert!(provider.find_by_name("missing").is_none());
    }

    #[test]
    fn test_script_from_file() {
        let dir = std::env::temp_dir().join("ghidra_test_jython");
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("test_script.py");
        let _ = std::fs::write(&file, "print('test')");

        let script = JythonScript::from_file(file).unwrap();
        assert_eq!(script.name, "test_script");
        assert_eq!(script.source, "print('test')");
        assert!(script.path.is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
