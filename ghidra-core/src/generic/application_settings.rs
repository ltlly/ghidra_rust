//! Application settings for the Ghidra framework.
//!
//! Ports Ghidra's `generic.application.ApplicationSettings`. Provides a
//! persistent key-value store for application-wide configuration settings,
//! with support for loading from and saving to a settings file.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::PathBuf;

// ============================================================================
// ApplicationSettings
// ============================================================================

/// Application-wide settings store.
///
/// Stores key-value pairs that persist across sessions. Settings are
/// organized into named categories and can be loaded from / saved to
/// a file on disk.
///
/// # Examples
///
/// ```
/// use ghidra_core::generic::application_settings::ApplicationSettings;
///
/// let mut settings = ApplicationSettings::new("/home/user/.ghidra");
/// settings.set("General", "theme", "Dark");
/// settings.set("General", "fontSize", "14");
///
/// assert_eq!(settings.get("General", "theme"), Some("Dark".to_string()));
/// ```
#[derive(Debug, Clone)]
pub struct ApplicationSettings {
    /// Path to the settings directory.
    pub settings_dir: PathBuf,
    /// Category -> (key -> value) storage.
    settings: HashMap<String, HashMap<String, String>>,
}

impl ApplicationSettings {
    /// Create new empty settings with the given directory.
    pub fn new(settings_dir: impl Into<PathBuf>) -> Self {
        Self {
            settings_dir: settings_dir.into(),
            settings: HashMap::new(),
        }
    }

    /// Get a setting value by category and key.
    pub fn get(&self, category: &str, key: &str) -> Option<String> {
        self.settings
            .get(category)
            .and_then(|m| m.get(key))
            .cloned()
    }

    /// Get a setting value, returning the default if not found.
    pub fn get_or(&self, category: &str, key: &str, default: &str) -> String {
        self.get(category, key)
            .unwrap_or_else(|| default.to_string())
    }

    /// Set a setting value in the given category.
    pub fn set(&mut self, category: &str, key: &str, value: &str) {
        self.settings
            .entry(category.to_string())
            .or_insert_with(HashMap::new)
            .insert(key.to_string(), value.to_string());
    }

    /// Remove a setting by category and key.
    pub fn remove(&mut self, category: &str, key: &str) -> bool {
        self.settings
            .get_mut(category)
            .map(|m| m.remove(key).is_some())
            .unwrap_or(false)
    }

    /// Remove an entire category.
    pub fn remove_category(&mut self, category: &str) -> bool {
        self.settings.remove(category).is_some()
    }

    /// Returns `true` if the given category and key exist.
    pub fn has(&self, category: &str, key: &str) -> bool {
        self.settings
            .get(category)
            .map(|m| m.contains_key(key))
            .unwrap_or(false)
    }

    /// Returns `true` if the given category exists.
    pub fn has_category(&self, category: &str) -> bool {
        self.settings.contains_key(category)
    }

    /// List all category names.
    pub fn categories(&self) -> Vec<String> {
        self.settings.keys().cloned().collect()
    }

    /// List all keys in a category.
    pub fn keys(&self, category: &str) -> Vec<String> {
        self.settings
            .get(category)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Returns the total number of settings across all categories.
    pub fn count(&self) -> usize {
        self.settings.values().map(|m| m.len()).sum()
    }

    /// Returns the number of categories.
    pub fn category_count(&self) -> usize {
        self.settings.len()
    }

    /// Clear all settings.
    pub fn clear(&mut self) {
        self.settings.clear();
    }

    /// Clear all settings in a category.
    pub fn clear_category(&mut self, category: &str) {
        if let Some(m) = self.settings.get_mut(category) {
            m.clear();
        }
    }

    /// Save settings to a file in the settings directory.
    ///
    /// The file is written as a simple key=value format with `[category]`
    /// section headers (INI-style).
    pub fn save_to_file(&self, filename: &str) -> Result<(), ApplicationSettingsError> {
        let path = self.settings_dir.join(filename);
        let mut content = String::new();

        let mut categories: Vec<&String> = self.settings.keys().collect();
        categories.sort();

        for category in categories {
            content.push_str(&format!("[{}]\n", category));
            if let Some(m) = self.settings.get(category) {
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort();
                for key in keys {
                    if let Some(value) = m.get(key) {
                        content.push_str(&format!("{}={}\n", key, value));
                    }
                }
            }
            content.push('\n');
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                ApplicationSettingsError::IoError(format!(
                    "Failed to create directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        fs::write(&path, content).map_err(|e| {
            ApplicationSettingsError::IoError(format!("Failed to write {}: {}", path.display(), e))
        })?;

        Ok(())
    }

    /// Load settings from a file in the settings directory.
    pub fn load_from_file(&mut self, filename: &str) -> Result<(), ApplicationSettingsError> {
        let path = self.settings_dir.join(filename);
        if !path.exists() {
            return Ok(());
        }

        let content = fs::read_to_string(&path).map_err(|e| {
            ApplicationSettingsError::IoError(format!("Failed to read {}: {}", path.display(), e))
        })?;

        let mut current_category = String::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            if line.starts_with('[') && line.ends_with(']') {
                current_category = line[1..line.len() - 1].to_string();
            } else if let Some(eq_pos) = line.find('=') {
                let key = line[..eq_pos].trim().to_string();
                let value = line[eq_pos + 1..].trim().to_string();
                if !current_category.is_empty() {
                    self.set(&current_category, &key, &value);
                }
            }
        }

        Ok(())
    }
}

// ============================================================================
// ApplicationSettingsError
// ============================================================================

/// Errors that can occur when working with application settings.
#[derive(Debug, Clone)]
pub enum ApplicationSettingsError {
    /// An I/O error occurred.
    IoError(String),
    /// A parse error occurred.
    ParseError(String),
    /// A generic error.
    Other(String),
}

impl fmt::Display for ApplicationSettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApplicationSettingsError::IoError(msg) => write!(f, "I/O error: {}", msg),
            ApplicationSettingsError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            ApplicationSettingsError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ApplicationSettingsError {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_settings_basic() {
        let mut s = ApplicationSettings::new("/tmp/test_settings");
        s.set("General", "theme", "Dark");
        s.set("General", "fontSize", "14");
        s.set("Editor", "tabSize", "4");

        assert_eq!(s.get("General", "theme"), Some("Dark".to_string()));
        assert_eq!(s.get("General", "fontSize"), Some("14".to_string()));
        assert_eq!(s.get("Editor", "tabSize"), Some("4".to_string()));
        assert_eq!(s.get("General", "missing"), None);
    }

    #[test]
    fn test_settings_get_or() {
        let mut s = ApplicationSettings::new("/tmp/test");
        s.set("General", "theme", "Dark");

        assert_eq!(s.get_or("General", "theme", "Light"), "Dark");
        assert_eq!(s.get_or("General", "missing", "default"), "default");
    }

    #[test]
    fn test_settings_remove() {
        let mut s = ApplicationSettings::new("/tmp/test");
        s.set("General", "theme", "Dark");
        assert!(s.has("General", "theme"));

        assert!(s.remove("General", "theme"));
        assert!(!s.has("General", "theme"));
        assert!(!s.remove("General", "missing"));
    }

    #[test]
    fn test_settings_remove_category() {
        let mut s = ApplicationSettings::new("/tmp/test");
        s.set("General", "theme", "Dark");
        s.set("Editor", "tabSize", "4");

        assert!(s.remove_category("General"));
        assert!(!s.has_category("General"));
        assert!(s.has_category("Editor"));
    }

    #[test]
    fn test_settings_categories_and_keys() {
        let mut s = ApplicationSettings::new("/tmp/test");
        s.set("General", "theme", "Dark");
        s.set("General", "fontSize", "14");
        s.set("Editor", "tabSize", "4");

        let mut cats = s.categories();
        cats.sort();
        assert_eq!(cats, vec!["Editor", "General"]);

        let mut keys = s.keys("General");
        keys.sort();
        assert_eq!(keys, vec!["fontSize", "theme"]);

        assert!(s.keys("Missing").is_empty());
    }

    #[test]
    fn test_settings_count() {
        let mut s = ApplicationSettings::new("/tmp/test");
        s.set("General", "theme", "Dark");
        s.set("General", "fontSize", "14");
        s.set("Editor", "tabSize", "4");

        assert_eq!(s.count(), 3);
        assert_eq!(s.category_count(), 2);
    }

    #[test]
    fn test_settings_clear() {
        let mut s = ApplicationSettings::new("/tmp/test");
        s.set("General", "theme", "Dark");
        s.set("Editor", "tabSize", "4");

        s.clear_category("General");
        assert_eq!(s.count(), 1);

        s.clear();
        assert_eq!(s.count(), 0);
        assert_eq!(s.category_count(), 0);
    }

    #[test]
    fn test_settings_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let settings_file = "test_settings.ini";

        {
            let mut s = ApplicationSettings::new(dir.path());
            s.set("General", "theme", "Dark");
            s.set("General", "fontSize", "14");
            s.set("Editor", "tabSize", "4");
            s.save_to_file(settings_file).unwrap();
        }

        {
            let mut s = ApplicationSettings::new(dir.path());
            s.load_from_file(settings_file).unwrap();
            assert_eq!(s.get("General", "theme"), Some("Dark".to_string()));
            assert_eq!(s.get("General", "fontSize"), Some("14".to_string()));
            assert_eq!(s.get("Editor", "tabSize"), Some("4".to_string()));
        }
    }

    #[test]
    fn test_settings_load_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = ApplicationSettings::new(dir.path());
        // Loading a non-existent file should succeed silently.
        s.load_from_file("nonexistent.ini").unwrap();
        assert_eq!(s.count(), 0);
    }

    #[test]
    fn test_settings_error_display() {
        let err = ApplicationSettingsError::IoError("disk full".to_string());
        assert!(err.to_string().contains("I/O error"));
        assert!(err.to_string().contains("disk full"));
    }
}
