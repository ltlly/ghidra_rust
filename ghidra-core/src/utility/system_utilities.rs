//! System and file utilities.
//!
//! Port of `ghidra.util.SystemUtilities`, `utilities.util.FileUtilities`,
//! and `utilities.util.ReflectionUtilities`.

use std::path::Path;
use std::fmt;

/// System-level utility methods.
///
/// Port of `ghidra.util.SystemUtilities`.
pub struct SystemUtilities;

impl SystemUtilities {
    /// Check if running in a test environment.
    pub fn is_in_testing_mode() -> bool {
        cfg!(test)
    }

    /// Get the Java "user.home" equivalent.
    pub fn user_home() -> Option<String> {
        std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .ok()
    }

    /// Get the OS name.
    pub fn os_name() -> &'static str {
        std::env::consts::OS
    }

    /// Get the OS architecture.
    pub fn os_arch() -> &'static str {
        std::env::consts::ARCH
    }

    /// Check if running on Windows.
    pub fn is_windows() -> bool {
        cfg!(target_os = "windows")
    }

    /// Check if running on macOS.
    pub fn is_mac() -> bool {
        cfg!(target_os = "macos")
    }

    /// Check if running on Linux.
    pub fn is_linux() -> bool {
        cfg!(target_os = "linux")
    }

    /// Get the number of available processors.
    pub fn available_processors() -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    }

    /// Return the string representation of an address.
    pub fn format_address(addr: u64) -> String {
        format!("0x{:x}", addr)
    }
}

impl fmt::Debug for SystemUtilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SystemUtilities").finish()
    }
}

/// File utility methods.
///
/// Port of `utilities.util.FileUtilities`.
pub struct FileUtilities;

impl FileUtilities {
    /// Delete a file or directory (recursively for directories).
    pub fn delete_dir(dir: &Path) -> std::io::Result<()> {
        if dir.is_dir() {
            std::fs::remove_dir_all(dir)
        } else if dir.exists() {
            std::fs::remove_file(dir)
        } else {
            Ok(())
        }
    }

    /// Create a directory and all parent directories.
    pub fn mkdirs(dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)
    }

    /// Copy a file from src to dst.
    pub fn copy_file(src: &Path, dst: &Path) -> std::io::Result<u64> {
        std::fs::copy(src, dst)
    }

    /// Get the file extension (without the dot).
    pub fn get_extension(path: &Path) -> Option<String> {
        path.extension().map(|e| e.to_string_lossy().to_string())
    }

    /// Get the file name without extension.
    pub fn name_without_extension(path: &Path) -> Option<String> {
        path.file_stem().map(|s| s.to_string_lossy().to_string())
    }

    /// Check if a path has the given extension.
    pub fn has_extension(path: &Path, ext: &str) -> bool {
        path.extension()
            .map(|e| e.eq_ignore_ascii_case(ext))
            .unwrap_or(false)
    }

    /// Read a file to a string.
    pub fn read_file_to_string(path: &Path) -> std::io::Result<String> {
        std::fs::read_to_string(path)
    }

    /// Write a string to a file.
    pub fn write_string_to_file(path: &Path, content: &str) -> std::io::Result<()> {
        std::fs::write(path, content)
    }
}

/// Result of resolving a file path.
///
/// Port of `utilities.util.FileResolutionResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileResolutionResult {
    /// File was found at the given path.
    Found(String),
    /// File was not found.
    NotFound,
    /// File was found at an alternative path.
    FoundAtAlternative(String),
}

impl fmt::Display for FileResolutionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileResolutionResult::Found(p) => write!(f, "Found: {}", p),
            FileResolutionResult::NotFound => write!(f, "Not Found"),
            FileResolutionResult::FoundAtAlternative(p) => {
                write!(f, "Found at alternative: {}", p)
            }
        }
    }
}

/// Simple reflection-like utilities for Rust.
///
/// Port of `utilities.util.ReflectionUtilities`.
pub struct ReflectionUtilities;

impl ReflectionUtilities {
    /// Get the type name of a value (using std::any::type_name).
    pub fn type_name_of<T: ?Sized>(_val: &T) -> &'static str {
        std::any::type_name::<T>()
    }

    /// Get the short type name (without module path).
    pub fn short_type_name<T: ?Sized>(_val: &T) -> &'static str {
        let full = std::any::type_name::<T>();
        full.rsplit("::").next().unwrap_or(full)
    }

    /// Create a filtered stack trace (best effort in Rust).
    ///
    /// In Java, this returns a filtered stack trace. In Rust, we return
    /// a backtrace if available.
    pub fn create_filtered_stack_trace() -> String {
        format!("{}", std::backtrace::Backtrace::capture())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_utilities() {
        assert!(!SystemUtilities::os_name().is_empty());
        assert!(!SystemUtilities::os_arch().is_empty());
        assert!(SystemUtilities::available_processors() >= 1);
    }

    #[test]
    fn test_format_address() {
        assert_eq!(SystemUtilities::format_address(0x1234), "0x1234");
        assert_eq!(SystemUtilities::format_address(0), "0x0");
    }

    #[test]
    fn test_file_utilities() {
        let tmp = std::env::temp_dir().join("ghidra_test_file_util");
        FileUtilities::mkdirs(&tmp).unwrap();
        assert!(tmp.exists());
        FileUtilities::delete_dir(&tmp).unwrap();
        assert!(!tmp.exists());
    }

    #[test]
    fn test_file_extension() {
        let path = Path::new("test.class");
        assert_eq!(FileUtilities::get_extension(path), Some("class".to_string()));
        assert_eq!(
            FileUtilities::name_without_extension(path),
            Some("test".to_string())
        );
        assert!(FileUtilities::has_extension(path, "class"));
        assert!(!FileUtilities::has_extension(path, "txt"));
    }

    #[test]
    fn test_file_resolution_result() {
        let r = FileResolutionResult::Found("/tmp/test".to_string());
        assert!(format!("{}", r).contains("Found"));
    }

    #[test]
    fn test_reflection_utilities() {
        let x = 42u32;
        assert_eq!(ReflectionUtilities::type_name_of(&x), "u32");
    }
}
