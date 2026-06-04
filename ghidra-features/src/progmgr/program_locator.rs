//! ProgramLocator -- identifies the location of a program.
//!
//! Ported from `ghidra.app.plugin.core.progmgr.ProgramLocator`.
//!
//! A program can be identified by either a file path (DomainFile) or a
//! Ghidra URL.  This struct unifies both forms into a single key type
//! suitable for use in maps and caches.

use std::fmt;
use std::hash::{Hash, Hasher};

/// Identifies the location of a program.
///
/// A ProgramLocator specifies either a file path or a Ghidra URL, but
/// not both.  It normalizes the location so that it can be used as a
/// unique key for a program instance.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::progmgr::ProgramLocator;
///
/// let loc = ProgramLocator::from_path("/path/to/program.gzf");
/// assert!(loc.is_file_path());
/// assert!(!loc.is_url());
/// assert_eq!(loc.file_path(), Some("/path/to/program.gzf"));
/// ```
#[derive(Debug, Clone)]
pub struct ProgramLocator {
    /// The file path, if this is a file-based locator.
    file_path: Option<String>,
    /// The Ghidra URL, if this is a URL-based locator.
    url: Option<String>,
    /// The version of the program (DEFAULT_VERSION means latest).
    version: i32,
    /// Whether the content is known to be invalid.
    invalid_content: bool,
}

/// The default version constant meaning "latest version".
pub const DEFAULT_VERSION: i32 = -1;

impl ProgramLocator {
    /// Create a file-path-based ProgramLocator for the latest version.
    pub fn from_path(path: impl Into<String>) -> Self {
        Self {
            file_path: Some(path.into()),
            url: None,
            version: DEFAULT_VERSION,
            invalid_content: false,
        }
    }

    /// Create a file-path-based ProgramLocator for a specific version.
    pub fn from_path_version(path: impl Into<String>, version: i32) -> Self {
        Self {
            file_path: Some(path.into()),
            url: None,
            version,
            invalid_content: false,
        }
    }

    /// Create a URL-based ProgramLocator.
    pub fn from_url(url: impl Into<String>) -> Self {
        Self {
            file_path: None,
            url: Some(url.into()),
            version: DEFAULT_VERSION,
            invalid_content: false,
        }
    }

    /// Returns the file path, if this is a file-based locator.
    pub fn file_path(&self) -> Option<&str> {
        self.file_path.as_deref()
    }

    /// Returns the URL, if this is a URL-based locator.
    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    /// Returns the version.
    pub fn version(&self) -> i32 {
        self.version
    }

    /// Returns `true` if this is a file-path-based locator.
    pub fn is_file_path(&self) -> bool {
        self.file_path.is_some()
    }

    /// Returns `true` if this is a URL-based locator.
    pub fn is_url(&self) -> bool {
        self.url.is_some()
    }

    /// Returns `true` if the content is valid.
    pub fn is_valid(&self) -> bool {
        !self.invalid_content
    }

    /// Mark this locator as having invalid content.
    pub fn set_invalid(&mut self) {
        self.invalid_content = true;
    }

    /// Returns `true` if this locator can be used to reopen the program.
    pub fn can_reopen(&self) -> bool {
        !self.invalid_content && (self.file_path.is_some() || self.url.is_some())
    }

    /// Returns the display name for this locator.
    pub fn display_name(&self) -> String {
        if let Some(path) = &self.file_path {
            // Extract filename from path
            path.rsplit('/').next().unwrap_or(path).to_string()
        } else if let Some(url) = &self.url {
            url.clone()
        } else {
            "<unknown>".to_string()
        }
    }
}

impl fmt::Display for ProgramLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(path) = &self.file_path {
            if self.version != DEFAULT_VERSION {
                write!(f, "{} (v{})", path, self.version)
            } else {
                write!(f, "{}", path)
            }
        } else if let Some(url) = &self.url {
            write!(f, "{}", url)
        } else {
            write!(f, "<unknown>")
        }
    }
}

impl PartialEq for ProgramLocator {
    fn eq(&self, other: &Self) -> bool {
        self.file_path == other.file_path && self.url == other.url && self.version == other.version
    }
}
impl Eq for ProgramLocator {}

impl Hash for ProgramLocator {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.file_path.hash(state);
        self.url.hash(state);
        self.version.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_path_locator() {
        let loc = ProgramLocator::from_path("/path/to/program.gzf");
        assert!(loc.is_file_path());
        assert!(!loc.is_url());
        assert_eq!(loc.file_path(), Some("/path/to/program.gzf"));
        assert_eq!(loc.version(), DEFAULT_VERSION);
        assert!(loc.is_valid());
        assert!(loc.can_reopen());
    }

    #[test]
    fn test_url_locator() {
        let loc = ProgramLocator::from_url("ghidra://server/project/program");
        assert!(!loc.is_file_path());
        assert!(loc.is_url());
        assert_eq!(loc.url(), Some("ghidra://server/project/program"));
    }

    #[test]
    fn test_version_locator() {
        let loc = ProgramLocator::from_path_version("/path/to/prog", 5);
        assert_eq!(loc.version(), 5);
    }

    #[test]
    fn test_display() {
        let loc = ProgramLocator::from_path("/home/user/program.gzf");
        assert_eq!(loc.display_name(), "program.gzf");

        let loc2 = ProgramLocator::from_url("ghidra://server/prog");
        assert_eq!(loc2.to_string(), "ghidra://server/prog");
    }

    #[test]
    fn test_equality() {
        let a = ProgramLocator::from_path("/a");
        let b = ProgramLocator::from_path("/a");
        let c = ProgramLocator::from_path("/b");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_invalid_locator() {
        let mut loc = ProgramLocator::from_path("/path");
        assert!(loc.can_reopen());
        loc.set_invalid();
        assert!(!loc.can_reopen());
        assert!(!loc.is_valid());
    }
}
