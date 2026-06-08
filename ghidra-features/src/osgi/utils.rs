//! OSGi utility functions.
//!
//! Ported from `ghidra.app.plugin.core.osgi.OSGiUtils`.
//!
//! Provides helper functions for bundle management, class loading,
//! and the Ghidra plugin framework's OSGi-like operations.

use std::path::{Path, PathBuf};

use super::GhidraBundle;

/// The Ghidra extension directory name.
pub const EXTENSION_DIR_NAME: &str = "Extensions";

/// The Ghidra plugins directory name.
pub const PLUGINS_DIR_NAME: &str = "Plugins";

/// Default bundle symbolic name prefix.
pub const BUNDLE_NAME_PREFIX: &str = "ghidra.";

/// Check if a file path looks like a Ghidra plugin JAR.
///
/// A file is considered a plugin JAR if it:
/// - Has a `.jar` extension
/// - Is located in a Plugins or Extensions directory
pub fn is_plugin_jar(path: &Path) -> bool {
    if path.extension().map_or(true, |e| e != "jar") {
        return false;
    }

    // Check if parent directory contains "plugin" or "extension" path segments
    let path_str = path.to_string_lossy().to_lowercase();
    path_str.contains("plugin") || path_str.contains("extension")
}

/// Extract the bundle symbolic name from a JAR file path.
///
/// The symbolic name is derived from the file name without extension.
pub fn symbolic_name_from_path(path: &Path) -> String {
    path.file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// Build a classpath string from a list of JAR paths.
pub fn build_classpath(jars: &[PathBuf]) -> String {
    jars.iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join(":")
}

/// Parse a version string into (major, minor, patch) components.
///
/// Returns `None` if the string cannot be parsed.
pub fn parse_version(version: &str) -> Option<(u32, u32, u32)> {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() >= 3 {
        let major = parts[0].parse().ok()?;
        let minor = parts[1].parse().ok()?;
        let patch = parts[2].parse().ok()?;
        Some((major, minor, patch))
    } else if parts.len() == 2 {
        let major = parts[0].parse().ok()?;
        let minor = parts[1].parse().ok()?;
        Some((major, minor, 0))
    } else if parts.len() == 1 {
        let major = parts[0].parse().ok()?;
        Some((major, 0, 0))
    } else {
        None
    }
}

/// Format a version tuple back to a string.
pub fn format_version(major: u32, minor: u32, patch: u32) -> String {
    format!("{}.{}.{}", major, minor, patch)
}

/// Check if a version satisfies a minimum version requirement.
pub fn version_satisfies(
    actual: &(u32, u32, u32),
    required: &(u32, u32, u32),
) -> bool {
    actual.0 > required.0
        || (actual.0 == required.0 && actual.1 > required.1)
        || (actual.0 == required.0 && actual.1 == required.1 && actual.2 >= required.2)
}

/// Build a bundle from a JAR path, inferring metadata.
pub fn bundle_from_jar(path: &Path) -> GhidraBundle {
    let name = symbolic_name_from_path(path);
    GhidraBundle::new(
        &name,
        &name,
        "0.0.0",
        path,
    )
}

/// Generate the Ghidra extension installation path.
pub fn extension_install_path(base_dir: &Path, extension_name: &str) -> PathBuf {
    base_dir.join(EXTENSION_DIR_NAME).join(extension_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::osgi::BundleStatus;

    #[test]
    fn test_is_plugin_jar() {
        assert!(is_plugin_jar(Path::new("/ghidra/Plugins/MyPlugin.jar")));
        assert!(is_plugin_jar(Path::new("/ext/Extensions/Foo.jar")));
        assert!(!is_plugin_jar(Path::new("/tmp/data.bin")));
        assert!(!is_plugin_jar(Path::new("/tmp/readme.txt")));
    }

    #[test]
    fn test_symbolic_name_from_path() {
        assert_eq!(
            symbolic_name_from_path(Path::new("/tmp/MyPlugin.jar")),
            "MyPlugin"
        );
        assert_eq!(
            symbolic_name_from_path(Path::new("/tmp/test")),
            "test"
        );
    }

    #[test]
    fn test_build_classpath() {
        let jars = vec![
            PathBuf::from("/lib/a.jar"),
            PathBuf::from("/lib/b.jar"),
        ];
        assert_eq!(build_classpath(&jars), "/lib/a.jar:/lib/b.jar");
    }

    #[test]
    fn test_parse_version() {
        assert_eq!(parse_version("1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("10.0"), Some((10, 0, 0)));
        assert_eq!(parse_version("5"), Some((5, 0, 0)));
        assert_eq!(parse_version("abc"), None);
    }

    #[test]
    fn test_format_version() {
        assert_eq!(format_version(1, 2, 3), "1.2.3");
    }

    #[test]
    fn test_version_satisfies() {
        assert!(version_satisfies(&(1, 2, 3), &(1, 2, 3)));
        assert!(version_satisfies(&(1, 2, 4), &(1, 2, 3)));
        assert!(version_satisfies(&(2, 0, 0), &(1, 9, 9)));
        assert!(!version_satisfies(&(1, 2, 2), &(1, 2, 3)));
        assert!(!version_satisfies(&(0, 9, 0), &(1, 0, 0)));
    }

    #[test]
    fn test_bundle_from_jar() {
        let bundle = bundle_from_jar(Path::new("/tmp/MyPlugin.jar"));
        assert_eq!(bundle.display_name, "MyPlugin");
        assert_eq!(bundle.status, BundleStatus::Installed);
    }

    #[test]
    fn test_extension_install_path() {
        let path = extension_install_path(Path::new("/home/user"), "MyExt");
        assert_eq!(path, Path::new("/home/user/Extensions/MyExt"));
    }
}
