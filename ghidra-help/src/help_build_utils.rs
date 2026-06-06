//! `HelpBuildUtils` -- utilities for building and validating help content.
//!
//! Ported from `help.HelpBuildUtils`. Provides helpers for resolving
//! help module locations, scanning help directories, and validating help
//! HTML files.

use std::path::{Path, PathBuf};

use crate::path_key::{PathKey, HELP_TOPICS_ROOT_PATH};

/// Utilities for working with help content.
pub struct HelpBuildUtils;

impl HelpBuildUtils {
    /// Root path for help topics within a Ghidra installation.
    pub const HELP_TOPICS_ROOT_PATH: &'static str = HELP_TOPICS_ROOT_PATH;

    /// Returns the shared help directory relative to the application root.
    ///
    /// In the Java version this resolves from `Application.getApplicationRootDirectory()`.
    /// Here we accept the app root as a parameter for testability.
    pub fn get_shared_help_directory(app_root: &Path) -> PathBuf {
        app_root.join("Framework/Help/src/main/resources/help/shared/")
    }

    /// Returns the help topics directory for a given application root.
    pub fn get_help_topics_directory(app_root: &Path) -> PathBuf {
        app_root.join(Self::HELP_TOPICS_ROOT_PATH)
    }

    /// Scan a directory tree for help topic HTML files and return their
    /// [`PathKey`]s.
    pub fn scan_help_topics(help_dir: &Path) -> Vec<PathKey> {
        let mut keys = Vec::new();
        if !help_dir.is_dir() {
            return keys;
        }
        Self::scan_recursive(help_dir, help_dir, &mut keys);
        keys.sort();
        keys
    }

    fn scan_recursive(base: &Path, dir: &Path, keys: &mut Vec<PathKey>) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                Self::scan_recursive(base, &path, keys);
            } else if path.extension().map_or(false, |e| e == "html" || e == "htm") {
                if let Ok(relative) = path.strip_prefix(base) {
                    keys.push(PathKey::new(relative));
                }
            }
        }
    }

    /// Validate that a help HTML file exists at the given path.
    pub fn validate_help_file(path: &Path) -> bool {
        path.is_file()
            && path
                .extension()
                .map_or(false, |e| e == "html" || e == "htm")
    }

    /// Extract the `href` targets from an HTML string (simple regex-based).
    pub fn extract_hrefs(html: &str) -> Vec<String> {
        let mut hrefs = Vec::new();
        for line in html.lines() {
            let mut remaining = line;
            while let Some(start) = remaining.find("href=\"") {
                let after = &remaining[start + 6..];
                if let Some(end) = after.find('"') {
                    hrefs.push(after[..end].to_string());
                    remaining = &after[end + 1..];
                } else {
                    break;
                }
            }
        }
        hrefs
    }

    /// Extract CSS class names from HTML content (simple regex-based).
    pub fn extract_style_classes(html: &str) -> Vec<String> {
        let mut classes = Vec::new();
        for line in html.lines() {
            let mut remaining = line;
            while let Some(start) = remaining.find("class=\"") {
                let after = &remaining[start + 7..];
                if let Some(end) = after.find('"') {
                    for cls in after[..end].split_whitespace() {
                        classes.push(cls.to_string());
                    }
                    remaining = &after[end + 1..];
                } else {
                    break;
                }
            }
        }
        classes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_help_topics_root() {
        assert_eq!(HelpBuildUtils::HELP_TOPICS_ROOT_PATH, "help/topics");
    }

    #[test]
    fn test_extract_hrefs() {
        let html = r#"<a href="../Core/Options.html#General">Options</a> <a href="local.html">"#;
        let hrefs = HelpBuildUtils::extract_hrefs(html);
        assert_eq!(hrefs.len(), 2);
        assert_eq!(hrefs[0], "../Core/Options.html#General");
        assert_eq!(hrefs[1], "local.html");
    }

    #[test]
    fn test_extract_hrefs_empty() {
        assert!(HelpBuildUtils::extract_hrefs("<p>no links</p>").is_empty());
    }

    #[test]
    fn test_extract_style_classes() {
        let html = r#"<div class="note warning">"#;
        let classes = HelpBuildUtils::extract_style_classes(html);
        assert!(classes.contains(&"note".to_string()));
        assert!(classes.contains(&"warning".to_string()));
    }

    #[test]
    fn test_extract_style_classes_empty() {
        assert!(HelpBuildUtils::extract_style_classes("<p>plain</p>").is_empty());
    }

    #[test]
    fn test_validate_help_file() {
        // Non-existent file
        assert!(!HelpBuildUtils::validate_help_file(Path::new("/no/such/file.html")));
    }

    #[test]
    fn test_scan_help_topics_empty() {
        let keys = HelpBuildUtils::scan_help_topics(Path::new("/nonexistent"));
        assert!(keys.is_empty());
    }

    #[test]
    fn test_get_shared_help_directory() {
        let dir = HelpBuildUtils::get_shared_help_directory(Path::new("/app"));
        assert!(dir.to_string_lossy().contains("shared"));
    }
}
