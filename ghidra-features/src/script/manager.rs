//! Script manager.
//!
//! Ported from `ghidra.app.plugin.core.script` classes.
//!
//! Manages Ghidra scripts, providing script discovery, execution,
//! and lifecycle management.

use std::path::PathBuf;

/// Script language types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScriptLanguage {
    Python,
    Java,
    Rust,
    Bash,
    Unknown,
}

impl ScriptLanguage {
    /// Get the file extension.
    pub fn extension(&self) -> &'static str {
        match self {
            Self::Python => "py",
            Self::Java => "java",
            Self::Rust => "rs",
            Self::Bash => "sh",
            Self::Unknown => "",
        }
    }

    /// Detect the language from a file extension.
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            "py" | "python" => Self::Python,
            "java" => Self::Java,
            "rs" | "rust" => Self::Rust,
            "sh" | "bash" => Self::Bash,
            _ => Self::Unknown,
        }
    }
}

/// State of a script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptState {
    /// Script is available for execution.
    Idle,
    /// Script is currently running.
    Running,
    /// Script completed successfully.
    Completed,
    /// Script failed with an error.
    Failed,
    /// Script was cancelled.
    Cancelled,
}

/// A managed script entry.
#[derive(Debug, Clone)]
pub struct ScriptInfo {
    /// Script name (filename without extension).
    pub name: String,
    /// Full path to the script file.
    pub path: PathBuf,
    /// The script language.
    pub language: ScriptLanguage,
    /// Whether the script supports headless execution.
    pub headless_supported: bool,
    /// Current state.
    pub state: ScriptState,
    /// Script description (from metadata).
    pub description: String,
}

/// Script manager for discovering and running scripts.
#[derive(Debug)]
pub struct ScriptManager {
    /// Available scripts.
    scripts: Vec<ScriptInfo>,
    /// Script directories to search.
    search_dirs: Vec<PathBuf>,
}

impl ScriptManager {
    pub fn new() -> Self {
        Self {
            scripts: Vec::new(),
            search_dirs: Vec::new(),
        }
    }

    /// Add a search directory.
    pub fn add_search_dir(&mut self, dir: PathBuf) {
        self.search_dirs.push(dir);
    }

    /// Get search directories.
    pub fn search_dirs(&self) -> &[PathBuf] {
        &self.search_dirs
    }

    /// Register a script.
    pub fn register(&mut self, script: ScriptInfo) {
        self.scripts.push(script);
    }

    /// Get all scripts.
    pub fn scripts(&self) -> &[ScriptInfo] {
        &self.scripts
    }

    /// Find a script by name.
    pub fn find_by_name(&self, name: &str) -> Option<&ScriptInfo> {
        self.scripts.iter().find(|s| s.name == name)
    }

    /// Get scripts by language.
    pub fn scripts_by_language(&self, lang: ScriptLanguage) -> Vec<&ScriptInfo> {
        self.scripts.iter().filter(|s| s.language == lang).collect()
    }

    /// Get headless-capable scripts.
    pub fn headless_scripts(&self) -> Vec<&ScriptInfo> {
        self.scripts.iter().filter(|s| s.headless_supported).collect()
    }

    /// Get script count.
    pub fn script_count(&self) -> usize {
        self.scripts.len()
    }
}

impl Default for ScriptManager {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_script(name: &str, lang: ScriptLanguage) -> ScriptInfo {
        ScriptInfo {
            name: name.to_string(),
            path: PathBuf::from(format!("/scripts/{}.{}", name, lang.extension())),
            language: lang,
            headless_supported: lang == ScriptLanguage::Python,
            state: ScriptState::Idle,
            description: format!("Test script: {}", name),
        }
    }

    #[test]
    fn test_script_manager() {
        let mut mgr = ScriptManager::new();
        mgr.register(sample_script("analyze", ScriptLanguage::Python));
        mgr.register(sample_script("export", ScriptLanguage::Java));
        assert_eq!(mgr.script_count(), 2);
    }

    #[test]
    fn test_find_by_name() {
        let mut mgr = ScriptManager::new();
        mgr.register(sample_script("test", ScriptLanguage::Python));
        assert!(mgr.find_by_name("test").is_some());
        assert!(mgr.find_by_name("missing").is_none());
    }

    #[test]
    fn test_scripts_by_language() {
        let mut mgr = ScriptManager::new();
        mgr.register(sample_script("a", ScriptLanguage::Python));
        mgr.register(sample_script("b", ScriptLanguage::Python));
        mgr.register(sample_script("c", ScriptLanguage::Java));
        assert_eq!(mgr.scripts_by_language(ScriptLanguage::Python).len(), 2);
    }

    #[test]
    fn test_headless_scripts() {
        let mut mgr = ScriptManager::new();
        mgr.register(sample_script("a", ScriptLanguage::Python));
        assert_eq!(mgr.headless_scripts().len(), 1);
    }

    #[test]
    fn test_script_language() {
        assert_eq!(ScriptLanguage::from_extension("py"), ScriptLanguage::Python);
        assert_eq!(ScriptLanguage::from_extension("java"), ScriptLanguage::Java);
        assert_eq!(ScriptLanguage::from_extension("xyz"), ScriptLanguage::Unknown);
        assert_eq!(ScriptLanguage::Python.extension(), "py");
    }

    #[test]
    fn test_search_dirs() {
        let mut mgr = ScriptManager::new();
        mgr.add_search_dir(PathBuf::from("/user/scripts"));
        assert_eq!(mgr.search_dirs().len(), 1);
    }
}
