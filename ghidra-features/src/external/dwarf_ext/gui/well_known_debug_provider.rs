//! WellKnownDebugProvider -- pre-configured debug file search locations.
//!
//! Ported from `ghidra.app.util.bin.format.dwarf.external.gui.WellKnownDebugProvider`.
//!
//! Represents a debug file search location that has been pre-provided by a
//! Ghidra configuration file.  These are typically well-known debuginfod
//! servers that ship with Ghidra or are configured by the user.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// A well-known debug file provider entry.
///
/// In the Java version this is a `record`. Here it is a plain struct with
/// the same fields.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WellKnownDebugProvider {
    /// The URL or path string for this provider.
    location: String,
    /// Grouping criteria (e.g. "Internet", "Local").
    location_category: String,
    /// Optional warning string displayed to the user.
    warning: Option<String>,
    /// The file name that contained this information.
    file_origin: String,
}

impl WellKnownDebugProvider {
    /// Creates a new well-known debug provider entry.
    pub fn new(
        location: String,
        location_category: String,
        warning: Option<String>,
        file_origin: String,
    ) -> Self {
        Self {
            location,
            location_category,
            warning,
            file_origin,
        }
    }

    /// Returns the location URL or path.
    pub fn location(&self) -> &str {
        &self.location
    }

    /// Returns the location category.
    pub fn location_category(&self) -> &str {
        &self.location_category
    }

    /// Returns the optional warning string.
    pub fn warning(&self) -> Option<&str> {
        self.warning.as_deref()
    }

    /// Returns the file name that contained this information.
    pub fn file_origin(&self) -> &str {
        &self.file_origin
    }

    /// Loads well-known debug providers from all matching files found in the
    /// given search directories.
    ///
    /// Each file is expected to contain lines in the format:
    /// ```text
    /// location_category|location_string|warning_string
    /// ```
    ///
    /// For example:
    /// ```text
    /// Internet|https://msdl.microsoft.com/download/symbols|Warning: be careful!
    /// ```
    ///
    /// # Arguments
    ///
    /// * `search_dirs` -- directories to search for configuration files.
    /// * `file_ext` -- extension of the configuration files to find.
    pub fn load_all_from_dirs(search_dirs: &[&Path], file_ext: &str) -> Vec<Self> {
        let mut seen = HashSet::new();
        let mut results = Vec::new();

        for dir in search_dirs {
            if !dir.is_dir() {
                continue;
            }

            let entries = match fs::read_dir(dir) {
                Ok(entries) => entries,
                Err(_) => continue,
            };

            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }

                let matches_ext = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e == file_ext.trim_start_matches('.'))
                    .unwrap_or(false);

                if !matches_ext {
                    continue;
                }

                let file_name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();

                let content = match fs::read_to_string(&path) {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }

                    let fields: Vec<&str> = line.split('|').collect();
                    if fields.len() < 2 {
                        continue;
                    }

                    let category = fields[0].trim().to_string();
                    let location = fields[1].trim().to_string();
                    let warning = if fields.len() > 2 {
                        let w = fields[2].trim();
                        if w.is_empty() {
                            None
                        } else {
                            Some(w.to_string())
                        }
                    } else {
                        None
                    };

                    let provider = WellKnownDebugProvider::new(
                        location,
                        category,
                        warning,
                        file_name.clone(),
                    );

                    if seen.insert(provider.clone()) {
                        results.push(provider);
                    }
                }
            }
        }

        results
    }

    /// Parses well-known providers from a single file content string.
    ///
    /// This is a convenience method for testing or when the file content
    /// is already available.
    pub fn parse_from_content(content: &str, file_name: &str) -> Vec<Self> {
        let mut seen = HashSet::new();
        let mut results = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let fields: Vec<&str> = line.split('|').collect();
            if fields.len() < 2 {
                continue;
            }

            let category = fields[0].trim().to_string();
            let location = fields[1].trim().to_string();
            let warning = if fields.len() > 2 {
                let w = fields[2].trim();
                if w.is_empty() {
                    None
                } else {
                    Some(w.to_string())
                }
            } else {
                None
            };

            let provider = WellKnownDebugProvider::new(
                location,
                category,
                warning,
                file_name.to_string(),
            );

            if seen.insert(provider.clone()) {
                results.push(provider);
            }
        }

        results
    }
}

impl std::fmt::Display for WellKnownDebugProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.location)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_from_content() {
        let content = "\
Internet|https://msdl.microsoft.com/download/symbols|Warning: be careful!
Internet|https://debuginfod.elfutils.org/
Local|file:///usr/lib/debug|
# comment line
";

        let providers = WellKnownDebugProvider::parse_from_content(content, "test.debuginfod_urls");
        assert_eq!(providers.len(), 3);

        assert_eq!(providers[0].location(), "https://msdl.microsoft.com/download/symbols");
        assert_eq!(providers[0].location_category(), "Internet");
        assert_eq!(providers[0].warning(), Some("Warning: be careful!"));
        assert_eq!(providers[0].file_origin(), "test.debuginfod_urls");

        assert_eq!(providers[1].location(), "https://debuginfod.elfutils.org/");
        assert_eq!(providers[1].location_category(), "Internet");
        assert_eq!(providers[1].warning(), None);

        assert_eq!(providers[2].location(), "file:///usr/lib/debug");
        assert_eq!(providers[2].location_category(), "Local");
        assert_eq!(providers[2].warning(), None);
    }

    #[test]
    fn test_parse_empty_content() {
        let providers = WellKnownDebugProvider::parse_from_content("", "empty.txt");
        assert!(providers.is_empty());
    }

    #[test]
    fn test_parse_comments_only() {
        let content = "# comment1\n# comment2\n";
        let providers = WellKnownDebugProvider::parse_from_content(content, "comments.txt");
        assert!(providers.is_empty());
    }

    #[test]
    fn test_parse_insufficient_fields() {
        let content = "only_one_field\n";
        let providers = WellKnownDebugProvider::parse_from_content(content, "bad.txt");
        assert!(providers.is_empty());
    }

    #[test]
    fn test_deduplication() {
        let content = "\
Internet|https://example.com/debug
Internet|https://example.com/debug
";
        let providers = WellKnownDebugProvider::parse_from_content(content, "dup.txt");
        assert_eq!(providers.len(), 1);
    }

    #[test]
    fn test_display() {
        let provider = WellKnownDebugProvider::new(
            "https://example.com".to_string(),
            "Internet".to_string(),
            None,
            "test.txt".to_string(),
        );
        assert_eq!(format!("{}", provider), "https://example.com");
    }

    #[test]
    fn test_new_with_warning() {
        let provider = WellKnownDebugProvider::new(
            "https://example.com".to_string(),
            "Internet".to_string(),
            Some("Use at own risk".to_string()),
            "config.txt".to_string(),
        );
        assert_eq!(provider.location(), "https://example.com");
        assert_eq!(provider.location_category(), "Internet");
        assert_eq!(provider.warning(), Some("Use at own risk"));
        assert_eq!(provider.file_origin(), "config.txt");
    }

    #[test]
    fn test_load_all_from_dirs_nonexistent() {
        let providers =
            WellKnownDebugProvider::load_all_from_dirs(&[Path::new("/nonexistent/dir")], "txt");
        assert!(providers.is_empty());
    }

    #[test]
    fn test_empty_warning_field() {
        let content = "Internet|https://example.com|\n";
        let providers = WellKnownDebugProvider::parse_from_content(content, "test.txt");
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].warning(), None);
    }
}
