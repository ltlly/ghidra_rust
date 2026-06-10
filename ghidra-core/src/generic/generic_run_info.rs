//! OS-specific application settings directory management.
//!
//! Ports Ghidra's `generic.run.GenericRunInfo`, providing OS-aware paths for
//! application settings storage (XDG on Linux, `%APPDATA%` on Windows,
//! `~/Library` on macOS). Also manages the "user settings directory" override
//! and tracks whether the application was previously running (crash detection).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

// ============================================================================
// Constants
// ============================================================================

/// The name of the Ghidra user settings directory.
pub const SETTINGS_DIR_NAME: &str = ".ghidra";

/// The name of the application properties subdirectory.
pub const PROPERTIES_DIR_NAME: &str = "ghidra";

/// Default settings file name.
pub const SETTINGS_FILE_NAME: &str = "preferences";

/// Lock file name used to detect a running instance.
pub const LOCK_FILE_NAME: &str = "application.lock";

// ============================================================================
// GenericRunInfo
// ============================================================================

/// OS-specific application settings directory management.
///
/// Provides the canonical user settings directory for Ghidra-like applications,
/// following OS conventions:
///
/// - **Linux**: `$XDG_CONFIG_HOME/ghidra` (defaults to `~/.config/ghidra`)
/// - **Windows**: `%APPDATA%/ghidra`
/// - **macOS**: `~/Library/Application Support/ghidra`
///
/// The directory can be overridden via the `GHIDRA_USER_SETTINGS_DIR` environment
/// variable or the `GHIDRA_USER_HOME_DIR` environment variable.
#[derive(Debug)]
pub struct GenericRunInfo {
    user_home_dir: PathBuf,
    user_settings_dir: PathBuf,
}

impl GenericRunInfo {
    /// Get the global singleton instance.
    pub fn instance() -> &'static GenericRunInfo {
        static INSTANCE: OnceLock<GenericRunInfo> = OnceLock::new();
        INSTANCE.get_or_init(|| Self::new())
    }

    fn new() -> Self {
        let user_home_dir = Self::detect_user_home_dir();
        let user_settings_dir = Self::detect_user_settings_dir(&user_home_dir);
        Self {
            user_home_dir,
            user_settings_dir,
        }
    }

    /// Return the user's home directory.
    ///
    /// Checks `GHIDRA_USER_HOME_DIR` first, then falls back to OS detection.
    pub fn get_user_home_dir(&self) -> &Path {
        &self.user_home_dir
    }

    /// Return the user settings directory.
    ///
    /// Checks `GHIDRA_USER_SETTINGS_DIR` first, then falls back to OS
    /// conventions.
    pub fn get_user_settings_dir(&self) -> &Path {
        &self.user_settings_dir
    }

    /// Return the application properties directory.
    ///
    /// This is `<user_settings_dir>/ghidra/`.
    pub fn get_application_properties_dir(&self) -> PathBuf {
        self.user_settings_dir.join(PROPERTIES_DIR_NAME)
    }

    /// Return the path to the user settings file (preferences).
    pub fn get_settings_file_path(&self) -> PathBuf {
        self.user_settings_dir.join(SETTINGS_FILE_NAME)
    }

    /// Return the path to the application lock file.
    ///
    /// Used for detecting whether another instance is running.
    pub fn get_lock_file_path(&self) -> PathBuf {
        self.user_settings_dir.join(LOCK_FILE_NAME)
    }

    /// Return the OS-specific application settings directory.
    ///
    /// This returns the standard platform directory for application data:
    /// - Linux: `$XDG_CONFIG_HOME` or `~/.config`
    /// - Windows: `%APPDATA%`
    /// - macOS: `~/Library/Application Support`
    pub fn get_os_application_settings_dir() -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            if let Ok(xdg) = env::var("XDG_CONFIG_HOME") {
                return PathBuf::from(xdg);
            }
            if let Ok(home) = env::var("HOME") {
                return PathBuf::from(home).join(".config");
            }
        }

        #[cfg(target_os = "windows")]
        {
            if let Ok(appdata) = env::var("APPDATA") {
                return PathBuf::from(appdata);
            }
        }

        #[cfg(target_os = "macos")]
        {
            if let Ok(home) = env::var("HOME") {
                return PathBuf::from(home)
                    .join("Library")
                    .join("Application Support");
            }
        }

        // Fallback for unsupported platforms
        if let Ok(home) = env::var("HOME") {
            return PathBuf::from(home).join(".config");
        }

        env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    }

    /// Return the OS-specific application properties directory.
    ///
    /// This is `<os_application_settings_dir>/ghidra/`.
    pub fn get_os_application_properties_dir() -> PathBuf {
        Self::get_os_application_settings_dir().join(PROPERTIES_DIR_NAME)
    }

    /// Create the user settings directory if it does not exist.
    ///
    /// Returns `Ok(true)` if the directory was created, `Ok(false)` if it
    /// already existed, or an error if creation failed.
    pub fn ensure_user_settings_dir(&self) -> std::io::Result<bool> {
        if self.user_settings_dir.exists() {
            return Ok(false);
        }
        fs::create_dir_all(&self.user_settings_dir)?;
        Ok(true)
    }

    /// Create the application properties directory if it does not exist.
    pub fn ensure_application_properties_dir(&self) -> std::io::Result<bool> {
        let dir = self.get_application_properties_dir();
        if dir.exists() {
            return Ok(false);
        }
        fs::create_dir_all(&dir)?;
        Ok(true)
    }

    /// Try to acquire the application lock.
    ///
    /// Returns `Ok(true)` if the lock was acquired (no other instance running),
    /// `Ok(false)` if another instance holds the lock, or an error if the lock
    /// file could not be written.
    ///
    /// The lock file contains the current process ID.
    pub fn try_lock(&self) -> std::io::Result<bool> {
        let lock_path = self.get_lock_file_path();
        if lock_path.exists() {
            // Check if the PID in the lock file is still running
            if let Ok(contents) = fs::read_to_string(&lock_path) {
                if let Ok(pid) = contents.trim().parse::<u32>() {
                    if is_process_running(pid) {
                        return Ok(false);
                    }
                }
            }
            // Stale lock file; remove it
            let _ = fs::remove_file(&lock_path);
        }
        self.ensure_user_settings_dir()?;
        fs::write(&lock_path, std::process::id().to_string())?;
        Ok(true)
    }

    /// Release the application lock by removing the lock file.
    pub fn release_lock(&self) -> std::io::Result<()> {
        let lock_path = self.get_lock_file_path();
        if lock_path.exists() {
            // Only remove if we own it
            if let Ok(contents) = fs::read_to_string(&lock_path) {
                if let Ok(pid) = contents.trim().parse::<u32>() {
                    if pid == std::process::id() {
                        fs::remove_file(&lock_path)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Check whether the settings directory already exists.
    pub fn has_settings_dir(&self) -> bool {
        self.user_settings_dir.is_dir()
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    fn detect_user_home_dir() -> PathBuf {
        // 1. Check environment override
        if let Ok(dir) = env::var("GHIDRA_USER_HOME_DIR") {
            return PathBuf::from(dir);
        }

        // 2. Standard OS detection
        #[cfg(unix)]
        {
            if let Ok(home) = env::var("HOME") {
                return PathBuf::from(home);
            }
        }

        #[cfg(target_os = "windows")]
        {
            if let Ok(profile) = env::var("USERPROFILE") {
                return PathBuf::from(profile);
            }
            if let Ok(drive) = env::var("HOMEDRIVE") {
                if let Ok(path) = env::var("HOMEPATH") {
                    return PathBuf::from(format!("{}{}", drive, path));
                }
            }
        }

        // Fallback
        env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    }

    fn detect_user_settings_dir(user_home: &Path) -> PathBuf {
        // 1. Check environment override
        if let Ok(dir) = env::var("GHIDRA_USER_SETTINGS_DIR") {
            return PathBuf::from(dir);
        }

        // 2. Check for `~/.ghidra` (Ghidra convention on all platforms)
        let dot_ghidra = user_home.join(SETTINGS_DIR_NAME);
        if dot_ghidra.is_dir() {
            return dot_ghidra;
        }

        // 3. OS-specific default
        Self::get_os_application_settings_dir().join(PROPERTIES_DIR_NAME)
    }
}

impl Drop for GenericRunInfo {
    fn drop(&mut self) {
        // Best-effort release of the lock file
        let _ = self.release_lock();
    }
}

// ============================================================================
// Helper: process liveness check
// ============================================================================

/// Check whether a process with the given PID is still running.
///
/// On Unix, this sends signal 0 to the process. On Windows, it uses
/// a simple best-effort check.
fn is_process_running(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // signal 0 checks existence without sending a signal
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }

    #[cfg(not(unix))]
    {
        // Best effort: assume running if we can't check
        true
    }
}

// ============================================================================
// LockFileGuard
// ============================================================================

/// RAII guard that releases the application lock on drop.
///
/// # Examples
///
/// ```
/// use ghidra_core::generic::generic_run_info::{GenericRunInfo, LockFileGuard};
///
/// let info = GenericRunInfo::instance();
/// if let Ok(acquired) = info.try_lock() {
///     if acquired {
///         let _guard = LockFileGuard::new();
///         // Application runs here; lock is released when _guard is dropped.
///     }
/// }
/// ```
pub struct LockFileGuard {
    _private: (),
}

impl LockFileGuard {
    /// Create a new lock guard. Call this only after successfully acquiring
    /// the lock via [`GenericRunInfo::try_lock`].
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for LockFileGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for LockFileGuard {
    fn drop(&mut self) {
        let info = GenericRunInfo::instance();
        let _ = info.release_lock();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instance_singleton() {
        let info1 = GenericRunInfo::instance();
        let info2 = GenericRunInfo::instance();
        // Both point to the same singleton
        assert!(std::ptr::eq(info1, info2));
    }

    #[test]
    fn test_user_home_dir_not_empty() {
        let info = GenericRunInfo::instance();
        let home = info.get_user_home_dir();
        assert!(!home.as_os_str().is_empty());
    }

    #[test]
    fn test_user_settings_dir_not_empty() {
        let info = GenericRunInfo::instance();
        let settings = info.get_user_settings_dir();
        assert!(!settings.as_os_str().is_empty());
    }

    #[test]
    fn test_os_application_settings_dir_not_empty() {
        let dir = GenericRunInfo::get_os_application_settings_dir();
        assert!(!dir.as_os_str().is_empty());
    }

    #[test]
    fn test_os_application_properties_dir_contains_ghidra() {
        let dir = GenericRunInfo::get_os_application_properties_dir();
        assert!(dir
            .to_string_lossy()
            .contains(PROPERTIES_DIR_NAME));
    }

    #[test]
    fn test_application_properties_dir_is_subdir() {
        let info = GenericRunInfo::instance();
        let props = info.get_application_properties_dir();
        assert!(props.starts_with(info.get_user_settings_dir()));
    }

    #[test]
    fn test_settings_file_path() {
        let info = GenericRunInfo::instance();
        let path = info.get_settings_file_path();
        assert!(path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains(SETTINGS_FILE_NAME));
    }

    #[test]
    fn test_lock_file_path() {
        let info = GenericRunInfo::instance();
        let path = info.get_lock_file_path();
        assert!(path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains(LOCK_FILE_NAME));
    }

    #[test]
    fn test_has_settings_dir() {
        let info = GenericRunInfo::instance();
        // Just test it doesn't panic; the result depends on the environment
        let _ = info.has_settings_dir();
    }

    #[test]
    fn test_ensure_user_settings_dir() {
        // Use a temp directory to avoid polluting the real settings
        let tmp = tempfile::tempdir().unwrap();
        let settings_dir = tmp.path().join("test_settings");
        let home_dir = tmp.path().join("home");

        let info = GenericRunInfo {
            user_home_dir: home_dir,
            user_settings_dir: settings_dir.clone(),
        };

        assert!(!settings_dir.exists());
        let created = info.ensure_user_settings_dir().unwrap();
        assert!(created);
        assert!(settings_dir.exists());

        // Second call should return false (already exists)
        let created2 = info.ensure_user_settings_dir().unwrap();
        assert!(!created2);
    }

    #[test]
    fn test_try_lock_and_release() {
        let tmp = tempfile::tempdir().unwrap();
        let settings_dir = tmp.path().join("lock_test");

        let info = GenericRunInfo {
            user_home_dir: tmp.path().to_path_buf(),
            user_settings_dir: settings_dir.clone(),
        };

        // First lock should succeed
        let result = info.try_lock().unwrap();
        assert!(result);
        assert!(info.get_lock_file_path().exists());

        // Second lock from same process should return false (same PID)
        // Actually the lock file has our PID and we ARE running, so it
        // returns false.
        let result2 = info.try_lock().unwrap();
        assert!(!result2);

        // Release should work
        info.release_lock().unwrap();
        assert!(!info.get_lock_file_path().exists());
    }

    #[test]
    fn test_lock_guard_drop() {
        let tmp = tempfile::tempdir().unwrap();
        let settings_dir = tmp.path().join("guard_test");

        let info = GenericRunInfo {
            user_home_dir: tmp.path().to_path_buf(),
            user_settings_dir: settings_dir.clone(),
        };

        let result = info.try_lock().unwrap();
        assert!(result);

        {
            let _guard = LockFileGuard::new();
            // Lock file should exist while guard is alive
            assert!(info.get_lock_file_path().exists());
        }
        // After guard drops, lock file should be released
        // Note: LockFileGuard::drop calls release_lock on the singleton,
        // not on our custom `info`, so this test verifies the guard
        // doesn't panic rather than testing file removal.
    }

    #[test]
    fn test_env_override_user_home() {
        // Temporarily set env var to verify override path
        let tmp = tempfile::tempdir().unwrap();
        let override_path = tmp.path().join("override_home");

        unsafe {
            env::set_var("GHIDRA_USER_HOME_DIR", &override_path);
        }
        let home = GenericRunInfo::detect_user_home_dir();
        assert_eq!(home, override_path);
        unsafe {
            env::remove_var("GHIDRA_USER_HOME_DIR");
        }
    }

    #[test]
    fn test_env_override_user_settings_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let override_path = tmp.path().join("override_settings");

        unsafe {
            env::set_var("GHIDRA_USER_SETTINGS_DIR", &override_path);
        }
        let home = PathBuf::from("/tmp/unused");
        let settings = GenericRunInfo::detect_user_settings_dir(&home);
        assert_eq!(settings, override_path);
        unsafe {
            env::remove_var("GHIDRA_USER_SETTINGS_DIR");
        }
    }

    #[test]
    fn test_is_process_running_current() {
        let pid = std::process::id();
        assert!(is_process_running(pid));
    }

    #[test]
    fn test_is_process_running_invalid() {
        // PID 0 is not a valid process on Linux
        assert!(!is_process_running(0));
    }

    #[test]
    fn test_constants() {
        assert_eq!(SETTINGS_DIR_NAME, ".ghidra");
        assert_eq!(PROPERTIES_DIR_NAME, "ghidra");
        assert_eq!(LOCK_FILE_NAME, "application.lock");
    }
}
