//! Application layout, properties, and platform configuration.
//!
//! Port of `utility.application` and `ghidra.framework`: ApplicationLayout,
//! ApplicationProperties, ApplicationSettings, ApplicationUtilities,
//! AppCleaner, XdgUtils, DummyApplicationLayout, ApplicationIdentifier,
//! ApplicationVersion, GModule.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use super::operating_system::OperatingSystem;

// ============================================================================
// ApplicationProperties
// ============================================================================

/// Application-level properties for identifying and versioning the application.
///
/// Port of `ghidra.framework.ApplicationProperties`.
#[derive(Debug, Clone)]
pub struct ApplicationProperties {
    /// Application name.
    pub application_name: String,
    /// Application version string.
    pub application_version: String,
    /// Layout version number.
    pub layout_version: u32,
    /// Installation directory.
    pub installation_dir: Option<PathBuf>,
    /// Additional properties.
    pub properties: HashMap<String, String>,
}

impl ApplicationProperties {
    /// Create new application properties.
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            application_name: name.into(),
            application_version: version.into(),
            layout_version: 1,
            installation_dir: None,
            properties: HashMap::new(),
        }
    }

    /// Get a custom property.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.properties.get(key).map(|s| s.as_str())
    }

    /// Set a custom property.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.properties.insert(key.into(), value.into());
    }

    /// The layout version property key.
    pub const APPLICATION_LAYOUT_VERSION_PROPERTY: &'static str = "application.layout.version";
}

impl Default for ApplicationProperties {
    fn default() -> Self {
        Self::new("Ghidra", "1.0.0")
    }
}

// ============================================================================
// ApplicationVersion
// ============================================================================

/// Version information for the application.
///
/// Port of `ghidra.framework.ApplicationVersion`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ApplicationVersion {
    /// Major version.
    pub major: u32,
    /// Minor version.
    pub minor: u32,
    /// Patch version.
    pub patch: u32,
    /// Build identifier (optional).
    pub build: Option<String>,
}

impl ApplicationVersion {
    /// Create a new version.
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
            build: None,
        }
    }

    /// Create with a build identifier.
    pub fn with_build(major: u32, minor: u32, patch: u32, build: impl Into<String>) -> Self {
        Self {
            major,
            minor,
            patch,
            build: Some(build.into()),
        }
    }
}

impl fmt::Display for ApplicationVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(ref b) = self.build {
            write!(f, "+{}", b)?;
        }
        Ok(())
    }
}

impl Default for ApplicationVersion {
    fn default() -> Self {
        Self::new(1, 0, 0)
    }
}

// ============================================================================
// ApplicationIdentifier
// ============================================================================

/// Unique identifier for an application installation.
///
/// Port of `ghidra.framework.ApplicationIdentifier`.
#[derive(Debug, Clone)]
pub struct ApplicationIdentifier {
    /// The application name.
    pub name: String,
    /// A unique installation ID.
    pub installation_id: String,
}

impl ApplicationIdentifier {
    /// Create a new identifier.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            installation_id: uuid::Uuid::new_v4().to_string(),
        }
    }
}

impl Default for ApplicationIdentifier {
    fn default() -> Self {
        Self::new("Ghidra")
    }
}

// ============================================================================
// GModule
// ============================================================================

/// An application module (a logical grouping of related functionality).
///
/// Port of `ghidra.framework.GModule`.
#[derive(Debug, Clone)]
pub struct GModule {
    /// Module name.
    pub name: String,
    /// Module root directory.
    pub root_dir: PathBuf,
    /// Module properties.
    pub properties: HashMap<String, String>,
}

impl GModule {
    /// Create a new module.
    pub fn new(name: impl Into<String>, root_dir: impl Into<PathBuf>) -> Self {
        Self {
            name: name.into(),
            root_dir: root_dir.into(),
            properties: HashMap::new(),
        }
    }

    /// Get a property value.
    pub fn property(&self, key: &str) -> Option<&str> {
        self.properties.get(key).map(|s| s.as_str())
    }
}

// ============================================================================
// ApplicationLayout
// ============================================================================

/// Defines the directory structure of the application.
///
/// Port of `utility.application.ApplicationLayout`.
#[derive(Debug, Clone)]
pub struct ApplicationLayout {
    /// Application properties.
    pub application_properties: ApplicationProperties,
    /// Application root directories.
    pub application_root_dirs: Vec<PathBuf>,
    /// Installation directory.
    pub application_installation_dir: Option<PathBuf>,
    /// Modules by name.
    pub modules: HashMap<String, GModule>,
    /// User temp directory.
    pub user_temp_dir: PathBuf,
    /// User cache directory.
    pub user_cache_dir: PathBuf,
    /// User settings directory.
    pub user_settings_dir: PathBuf,
    /// Patch directory.
    pub patch_dir: Option<PathBuf>,
    /// Extension archive directory.
    pub extension_archive_dir: Option<PathBuf>,
    /// Extension installation directories.
    pub extension_installation_dirs: Vec<PathBuf>,
}

impl ApplicationLayout {
    /// Create a new application layout with defaults.
    pub fn new(application_properties: ApplicationProperties) -> Self {
        Self {
            application_properties,
            application_root_dirs: Vec::new(),
            application_installation_dir: None,
            modules: HashMap::new(),
            user_temp_dir: std::env::temp_dir(),
            user_cache_dir: Self::default_cache_dir(),
            user_settings_dir: Self::default_settings_dir(),
            patch_dir: None,
            extension_archive_dir: None,
            extension_installation_dirs: Vec::new(),
        }
    }

    /// Get modules.
    pub fn modules(&self) -> &HashMap<String, GModule> {
        &self.modules
    }

    /// Get the application name.
    pub fn application_name(&self) -> &str {
        &self.application_properties.application_name
    }

    fn default_cache_dir() -> PathBuf {
        if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".cache").join("ghidra")
        } else if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
            PathBuf::from(appdata).join("ghidra")
        } else {
            std::env::temp_dir().join("ghidra")
        }
    }

    fn default_settings_dir() -> PathBuf {
        if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".config").join("ghidra")
        } else if let Ok(appdata) = std::env::var("APPDATA") {
            PathBuf::from(appdata).join("ghidra")
        } else {
            std::env::temp_dir().join("ghidra")
        }
    }
}

// ============================================================================
// DummyApplicationLayout
// ============================================================================

/// A minimal layout for testing.
///
/// Port of `utility.application.DummyApplicationLayout`.
#[derive(Debug, Clone)]
pub struct DummyApplicationLayout;

impl DummyApplicationLayout {
    /// Create a dummy layout.
    pub fn create() -> ApplicationLayout {
        ApplicationLayout::new(ApplicationProperties::new("GhidraTest", "0.0.1"))
    }
}

// ============================================================================
// ApplicationSettings
// ============================================================================

/// Application-wide settings.
///
/// Port of `utility.application.ApplicationSettings`.
#[derive(Debug, Clone)]
pub struct ApplicationSettings {
    /// Path to the settings file.
    pub settings_dir: PathBuf,
    /// Settings key-value store.
    settings: HashMap<String, String>,
}

impl ApplicationSettings {
    /// Create with the given settings directory.
    pub fn new(settings_dir: impl Into<PathBuf>) -> Self {
        Self {
            settings_dir: settings_dir.into(),
            settings: HashMap::new(),
        }
    }

    /// Get a setting.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.settings.get(key).map(|s| s.as_str())
    }

    /// Set a setting.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.settings.insert(key.into(), value.into());
    }
}

// ============================================================================
// ApplicationUtilities
// ============================================================================

/// Utility functions for application management.
///
/// Port of `utility.application.ApplicationUtilities`.
pub struct ApplicationUtilities;

impl ApplicationUtilities {
    /// Get the current OS.
    pub fn operating_system() -> OperatingSystem {
        OperatingSystem::current()
    }

    /// Get the user home directory.
    pub fn user_home_dir() -> Option<PathBuf> {
        std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .ok()
            .map(PathBuf::from)
    }

    /// Get the user temp directory.
    pub fn temp_dir() -> PathBuf {
        std::env::temp_dir()
    }
}

// ============================================================================
// AppCleaner
// ============================================================================

/// Utility for cleaning up application temp/cache files.
///
/// Port of `utility.application.AppCleaner`.
pub struct AppCleaner;

impl AppCleaner {
    /// Remove files from the given directory that match the pattern.
    pub fn clean_directory(dir: &Path, pattern: &str) -> std::io::Result<usize> {
        if !dir.is_dir() {
            return Ok(0);
        }
        let mut removed = 0;
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.contains(pattern) {
                if std::fs::remove_file(entry.path()).is_ok() {
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }
}

// ============================================================================
// XdgUtils
// ============================================================================

/// XDG Base Directory utilities for Linux/Unix.
///
/// Port of `utility.application.XdgUtils`.
pub struct XdgUtils;

impl XdgUtils {
    /// Get the XDG data home directory.
    pub fn data_home() -> PathBuf {
        std::env::var("XDG_DATA_HOME")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
                PathBuf::from(home).join(".local").join("share")
            })
    }

    /// Get the XDG config home directory.
    pub fn config_home() -> PathBuf {
        std::env::var("XDG_CONFIG_HOME")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
                PathBuf::from(home).join(".config")
            })
    }

    /// Get the XDG cache home directory.
    pub fn cache_home() -> PathBuf {
        std::env::var("XDG_CACHE_HOME")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
                PathBuf::from(home).join(".cache")
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_application_properties() {
        let mut props = ApplicationProperties::new("Ghidra", "11.0");
        assert_eq!(props.application_name, "Ghidra");
        props.set("custom.key", "value");
        assert_eq!(props.get("custom.key"), Some("value"));
    }

    #[test]
    fn test_application_version() {
        let v = ApplicationVersion::new(11, 0, 1);
        assert_eq!(format!("{}", v), "11.0.1");

        let v = ApplicationVersion::with_build(11, 0, 1, "abc123");
        assert_eq!(format!("{}", v), "11.0.1+abc123");
    }

    #[test]
    fn test_g_module() {
        let m = GModule::new("Core", "/opt/ghidra/Ghidra");
        assert_eq!(m.name, "Core");
    }

    #[test]
    fn test_application_layout() {
        let layout = DummyApplicationLayout::create();
        assert_eq!(layout.application_name(), "GhidraTest");
    }

    #[test]
    fn test_application_settings() {
        let mut settings = ApplicationSettings::new("/tmp/settings");
        settings.set("theme", "dark");
        assert_eq!(settings.get("theme"), Some("dark"));
    }

    #[test]
    fn test_xdg_utils() {
        let data = XdgUtils::data_home();
        assert!(!data.as_os_str().is_empty());
    }

    #[test]
    fn test_application_utilities() {
        let home = ApplicationUtilities::user_home_dir();
        // May or may not be set depending on environment
        let _ = home;
    }
}
