//! Application information and environment.
//!
//! Ports `ghidra.framework.main.AppInfo` from Java, providing information about
//! the running Ghidra application: mode (GUI, headless, batch), installation
//! location, version, and current project state.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use super::ProjectLocator;

// ============================================================================
// ApplicationMode
// ============================================================================

/// The mode in which the Ghidra application is running.
///
/// In Java: determined by the launch entry point (Ghidra, GhidraHeadless, etc.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApplicationMode {
    /// Full GUI mode with all UI components available.
    GUI,
    /// Headless analysis mode (no GUI, batch scripts only).
    Headless,
    /// Batch / command-line processing mode.
    Batch,
    /// Testing / unit-test harness mode.
    Testing,
}

impl ApplicationMode {
    /// Returns `true` when a graphical display is available.
    pub fn has_gui(&self) -> bool {
        matches!(self, Self::GUI)
    }

    /// Returns `true` when running in a non-interactive mode.
    pub fn is_non_interactive(&self) -> bool {
        matches!(self, Self::Headless | Self::Batch)
    }
}

impl Default for ApplicationMode {
    fn default() -> Self {
        Self::GUI
    }
}

impl std::fmt::Display for ApplicationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GUI => write!(f, "GUI"),
            Self::Headless => write!(f, "Headless"),
            Self::Batch => write!(f, "Batch"),
            Self::Testing => write!(f, "Testing"),
        }
    }
}

// ============================================================================
// AppInfo
// ============================================================================

/// Global application information singleton.
///
/// In Java: `ghidra.framework.main.AppInfo` holds static state about the
/// running Ghidra instance.  The Rust equivalent uses an `Arc<RwLock<_>>`
/// interior for thread-safe access.
///
/// ```rust,ignore
/// AppInfo::initialize("Ghidra", "/opt/ghidra", ApplicationMode::GUI);
/// let info = AppInfo::get();
/// assert_eq!(info.application_name(), "Ghidra");
/// ```
#[derive(Debug)]
pub struct AppInfo {
    /// Application name (e.g., "Ghidra").
    application_name: String,
    /// Installation directory of the Ghidra application.
    install_dir: Option<PathBuf>,
    /// The running mode of this application.
    mode: ApplicationMode,
    /// Build version string (e.g., "11.0").
    version: String,
    /// The current project locator, if any.
    current_project_locator: Option<ProjectLocator>,
    /// Whether the application is fully initialized.
    initialized: bool,
}

impl AppInfo {
    /// Create a new `AppInfo` with defaults.
    pub fn new() -> Self {
        Self {
            application_name: String::new(),
            install_dir: None,
            mode: ApplicationMode::default(),
            version: String::new(),
            current_project_locator: None,
            initialized: false,
        }
    }

    /// Initialize the application info.
    pub fn initialize(
        application_name: impl Into<String>,
        install_dir: impl Into<PathBuf>,
        mode: ApplicationMode,
    ) {
        let mut info = GLOBAL_APP_INFO.write().unwrap();
        info.application_name = application_name.into();
        info.install_dir = Some(install_dir.into());
        info.mode = mode;
        info.initialized = true;
    }

    /// Get a reference to the global `AppInfo`.
    pub fn get() -> std::sync::RwLockReadGuard<'static, AppInfo> {
        GLOBAL_APP_INFO.read().unwrap()
    }

    /// Get a mutable reference to the global `AppInfo`.
    pub fn get_mut() -> std::sync::RwLockWriteGuard<'static, AppInfo> {
        GLOBAL_APP_INFO.write().unwrap()
    }

    /// The application name.
    pub fn application_name(&self) -> &str {
        &self.application_name
    }

    /// The application installation directory.
    pub fn install_dir(&self) -> Option<&Path> {
        self.install_dir.as_deref()
    }

    /// The application running mode.
    pub fn mode(&self) -> ApplicationMode {
        self.mode
    }

    /// The application version string.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Set the application version string.
    pub fn set_version(&mut self, version: impl Into<String>) {
        self.version = version.into();
    }

    /// Whether the application is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Set the current project locator.
    pub fn set_current_project(&mut self, locator: Option<ProjectLocator>) {
        self.current_project_locator = locator;
    }

    /// The current project locator, if any.
    pub fn current_project(&self) -> Option<&ProjectLocator> {
        self.current_project_locator.as_ref()
    }

    /// Reset all application info to defaults.
    pub fn reset(&mut self) {
        self.application_name.clear();
        self.install_dir = None;
        self.mode = ApplicationMode::default();
        self.version.clear();
        self.current_project_locator = None;
        self.initialized = false;
    }

    /// Returns the user's home directory, if detectable.
    pub fn user_home_dir() -> Option<PathBuf> {
        std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .ok()
            .map(PathBuf::from)
    }

    /// Returns the default Ghidra user directory (e.g., `~/.ghidra`).
    pub fn user_settings_dir() -> Option<PathBuf> {
        Self::user_home_dir().map(|home| home.join(".ghidra"))
    }

    /// Returns the application name for display (including mode).
    pub fn display_name(&self) -> String {
        if self.mode == ApplicationMode::GUI {
            self.application_name.clone()
        } else {
            format!("{} [{}]", self.application_name, self.mode)
        }
    }
}

impl Default for AppInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Global static instance of `AppInfo`.
static GLOBAL_APP_INFO: std::sync::LazyLock<Arc<RwLock<AppInfo>>> =
    std::sync::LazyLock::new(|| Arc::new(RwLock::new(AppInfo::new())));

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_application_mode() {
        assert!(ApplicationMode::GUI.has_gui());
        assert!(!ApplicationMode::Headless.has_gui());
        assert!(ApplicationMode::Headless.is_non_interactive());
        assert!(!ApplicationMode::GUI.is_non_interactive());
        assert!(ApplicationMode::Batch.is_non_interactive());
        assert!(!ApplicationMode::Testing.is_non_interactive());
    }

    #[test]
    fn test_application_mode_display() {
        assert_eq!(format!("{}", ApplicationMode::GUI), "GUI");
        assert_eq!(format!("{}", ApplicationMode::Headless), "Headless");
        assert_eq!(format!("{}", ApplicationMode::Batch), "Batch");
        assert_eq!(format!("{}", ApplicationMode::Testing), "Testing");
    }

    #[test]
    fn test_app_info_default() {
        let info = AppInfo::new();
        assert!(info.application_name().is_empty());
        assert!(info.install_dir().is_none());
        assert_eq!(info.mode(), ApplicationMode::GUI);
        assert!(info.version().is_empty());
        assert!(!info.is_initialized());
        assert!(info.current_project().is_none());
    }

    #[test]
    fn test_app_info_initialize() {
        AppInfo::initialize("TestGhidra", "/opt/ghidra", ApplicationMode::Headless);
        {
            let info = AppInfo::get();
            assert_eq!(info.application_name(), "TestGhidra");
            assert_eq!(info.install_dir(), Some(Path::new("/opt/ghidra")));
            assert_eq!(info.mode(), ApplicationMode::Headless);
            assert!(info.is_initialized());
        }
        // Reset for other tests
        AppInfo::get_mut().reset();
    }

    #[test]
    fn test_app_info_version() {
        let mut info = AppInfo::new();
        info.set_version("11.0.1");
        assert_eq!(info.version(), "11.0.1");
    }

    #[test]
    fn test_app_info_display_name() {
        let mut info = AppInfo::new();
        info.application_name = "Ghidra".to_string();
        assert_eq!(info.display_name(), "Ghidra");

        info.mode = ApplicationMode::Headless;
        assert_eq!(info.display_name(), "Ghidra [Headless]");
    }

    #[test]
    fn test_app_info_project() {
        let mut info = AppInfo::new();
        assert!(info.current_project().is_none());

        let loc = ProjectLocator::new("/tmp/projects", "test");
        info.set_current_project(Some(loc.clone()));
        assert_eq!(info.current_project().unwrap().project_name, "test");

        info.set_current_project(None);
        assert!(info.current_project().is_none());
    }

    #[test]
    fn test_user_dirs() {
        let home = AppInfo::user_home_dir();
        // Should return Some on most unix systems
        if std::env::var("HOME").is_ok() {
            assert!(home.is_some());
        }

        let settings = AppInfo::user_settings_dir();
        if std::env::var("HOME").is_ok() {
            assert!(settings.is_some());
            assert!(settings.unwrap().to_string_lossy().contains(".ghidra"));
        }
    }
}
