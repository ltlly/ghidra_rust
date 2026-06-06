//! `PathKey` -- table-of-contents path key for help topics.
//!
//! Ported from `help.PathKey`. Represents a path in the help TOC hierarchy.

use std::fmt;
use std::path::{Path, PathBuf};

/// A key representing the path to a help topic in the table of contents.
///
/// PathKeys are used to identify and sort entries in the help TOC.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PathKey {
    /// The help file path relative to the help topics root.
    pub path: PathBuf,
    /// The anchor within the help file, if any.
    pub anchor: Option<String>,
}

impl PathKey {
    /// Create a new path key.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            anchor: None,
        }
    }

    /// Create a path key with an anchor.
    pub fn with_anchor(path: impl Into<PathBuf>, anchor: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            anchor: Some(anchor.into()),
        }
    }

    /// Returns the help topics root-relative path as a string.
    pub fn relative_path(&self) -> String {
        self.path.to_string_lossy().to_string()
    }

    /// Returns the file name portion of the path.
    pub fn file_name(&self) -> Option<&str> {
        self.path.file_name().and_then(|n| n.to_str())
    }

    /// Returns the full URL path including anchor.
    pub fn url_string(&self) -> String {
        let base = self.relative_path();
        match &self.anchor {
            Some(a) => format!("{}#{}", base, a),
            None => base,
        }
    }
}

impl fmt::Display for PathKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.url_string())
    }
}

impl PartialOrd for PathKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PathKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.path
            .cmp(&other.path)
            .then_with(|| self.anchor.cmp(&other.anchor))
    }
}

/// Root path constant for help topics.
pub const HELP_TOPICS_ROOT_PATH: &str = "help/topics";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_key_new() {
        let pk = PathKey::new("FunctionID/FunctionIDPlugin.html");
        assert_eq!(pk.file_name(), Some("FunctionIDPlugin.html"));
        assert!(pk.anchor.is_none());
    }

    #[test]
    fn test_path_key_with_anchor() {
        let pk = PathKey::with_anchor("Core/Options.html", "General");
        assert_eq!(pk.url_string(), "Core/Options.html#General");
    }

    #[test]
    fn test_path_key_display() {
        let pk = PathKey::new("a/b.html");
        assert_eq!(format!("{}", pk), "a/b.html");
    }

    #[test]
    fn test_path_key_ordering() {
        let a = PathKey::new("a.html");
        let b = PathKey::new("b.html");
        assert!(a < b);
    }

    #[test]
    fn test_path_key_ordering_same_path_different_anchor() {
        let a = PathKey::with_anchor("t.html", "a");
        let b = PathKey::with_anchor("t.html", "b");
        assert!(a < b);
    }

    #[test]
    fn test_help_topics_root() {
        assert_eq!(HELP_TOPICS_ROOT_PATH, "help/topics");
    }
}
