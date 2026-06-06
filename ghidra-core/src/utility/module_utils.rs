//! Module management utilities.
//!
//! Port of `utility.module`: ModuleUtilities, ModuleManifestFile,
//! and ClasspathFilter.

use std::collections::HashMap;
use std::path::Path;

/// Utilities for discovering and managing application modules.
///
/// Port of `utility.module.ModuleUtilities`.
pub struct ModuleUtilities;

impl ModuleUtilities {
    /// Discover modules in the given root directories by looking for
    /// manifest files.
    pub fn find_modules(root_dirs: &[&Path]) -> Vec<ModuleManifestFile> {
        let mut modules = Vec::new();
        for root in root_dirs {
            if !root.is_dir() {
                continue;
            }
            if let Ok(entries) = std::fs::read_dir(root) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        let manifest_path = path.join("Module.manifest");
                        if manifest_path.exists() {
                            if let Ok(manifest) = ModuleManifestFile::load(&manifest_path) {
                                modules.push(manifest);
                            }
                        }
                    }
                }
            }
        }
        modules
    }

    /// Get the module name from a module directory path.
    pub fn module_name_from_path(path: &Path) -> Option<String> {
        path.file_name().map(|n| n.to_string_lossy().to_string())
    }
}

/// A module manifest file (Module.manifest).
///
/// Port of `utility.module.ModuleManifestFile`.
#[derive(Debug, Clone)]
pub struct ModuleManifestFile {
    /// Path to the manifest file.
    pub path: std::path::PathBuf,
    /// Module name.
    pub name: String,
    /// Module properties.
    pub properties: HashMap<String, String>,
}

impl ModuleManifestFile {
    /// Load a manifest from a file.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let name = path
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        let mut properties = HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                properties.insert(key.trim().to_string(), value.trim().to_string());
            }
        }

        Ok(Self {
            path: path.to_path_buf(),
            name,
            properties,
        })
    }

    /// Get a property value.
    pub fn property(&self, key: &str) -> Option<&str> {
        self.properties.get(key).map(|s| s.as_str())
    }

    /// Get the module name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Filter for classpath entries.
///
/// Port of `utility.module.ClasspathFilter`.
pub struct ClasspathFilter {
    /// Allowed extensions.
    allowed_extensions: Vec<String>,
    /// Excluded patterns.
    excluded_patterns: Vec<String>,
}

impl ClasspathFilter {
    /// Create a new classpath filter.
    pub fn new() -> Self {
        Self {
            allowed_extensions: Vec::new(),
            excluded_patterns: Vec::new(),
        }
    }

    /// Create a filter that accepts jar and class files.
    pub fn java_filter() -> Self {
        Self {
            allowed_extensions: vec!["jar".to_string(), "class".to_string()],
            excluded_patterns: vec!["*test*".to_string(), "*Test*".to_string()],
        }
    }

    /// Add an allowed extension.
    pub fn allow_extension(&mut self, ext: impl Into<String>) {
        self.allowed_extensions.push(ext.into());
    }

    /// Add an excluded pattern.
    pub fn exclude_pattern(&mut self, pattern: impl Into<String>) {
        self.excluded_patterns.push(pattern.into());
    }

    /// Check if a path is accepted by this filter.
    pub fn accepts(&self, path: &str) -> bool {
        // Check exclusions
        for pattern in &self.excluded_patterns {
            if Self::simple_glob_match(pattern, path) {
                return false;
            }
        }

        // If no extensions are specified, accept everything
        if self.allowed_extensions.is_empty() {
            return true;
        }

        // Check extension
        if let Some(ext) = Path::new(path).extension() {
            let ext_str = ext.to_string_lossy();
            return self
                .allowed_extensions
                .iter()
                .any(|e| e.eq_ignore_ascii_case(&ext_str));
        }

        false
    }

    fn simple_glob_match(pattern: &str, text: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        if let Some(inner) = pattern.strip_prefix('*').and_then(|p| p.strip_suffix('*')) {
            return text.contains(inner);
        }
        if let Some(suffix) = pattern.strip_prefix('*') {
            return text.ends_with(suffix);
        }
        if let Some(prefix) = pattern.strip_suffix('*') {
            return text.starts_with(prefix);
        }
        text == pattern
    }
}

impl Default for ClasspathFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classpath_filter() {
        let filter = ClasspathFilter::java_filter();
        assert!(filter.accepts("lib/core.jar"));
        assert!(!filter.accepts("lib/test-data.jar"));
        assert!(!filter.accepts("readme.txt"));
    }

    #[test]
    fn test_classpath_filter_custom() {
        let mut filter = ClasspathFilter::new();
        filter.allow_extension("rs");
        filter.exclude_pattern("*target*");
        assert!(filter.accepts("src/main.rs"));
        assert!(!filter.accepts("target/debug/main.rs"));
    }

    #[test]
    fn test_module_name_from_path() {
        let name = ModuleUtilities::module_name_from_path(Path::new("/opt/ghidra/Ghidra/Core"));
        assert_eq!(name, Some("Core".to_string()));
    }
}
