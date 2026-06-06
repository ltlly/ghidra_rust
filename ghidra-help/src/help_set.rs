//! `HelpSet` -- help set description, equivalent to a Java `.hs` file.
//!
//! Ported from `help.GHelpSet`. Describes a named collection of help topics.

use std::path::PathBuf;

/// Describes a help set (a named collection of help topics).
///
/// In Ghidra's Java help system this maps to a `.hs` (HelpSet) XML file.
/// The Rust equivalent stores the essential metadata.
#[derive(Debug, Clone)]
pub struct HelpSet {
    /// The name of this help set (e.g., `"GhidraHelp"`).
    pub name: String,
    /// Path to the help set definition file.
    pub file_path: PathBuf,
    /// The title displayed in the help viewer.
    pub title: String,
    /// The base URL for resolving help topics.
    pub base_url: String,
    /// Names of any imported help sets.
    pub imports: Vec<String>,
    /// The table-of-contents file name.
    pub toc_file: Option<String>,
    /// The index file name.
    pub index_file: Option<String>,
    /// The map (ID-to-URL) file name.
    pub map_file: Option<String>,
}

impl HelpSet {
    /// Create a new help set.
    pub fn new(name: impl Into<String>, file_path: impl Into<PathBuf>) -> Self {
        Self {
            name: name.into(),
            file_path: file_path.into(),
            title: String::new(),
            base_url: String::new(),
            imports: Vec::new(),
            toc_file: None,
            index_file: None,
            map_file: None,
        }
    }

    /// Set the title.
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    /// Set the base URL.
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Add an imported help set name.
    pub fn add_import(&mut self, name: impl Into<String>) {
        self.imports.push(name.into());
    }

    /// Set the TOC file.
    pub fn with_toc_file(mut self, file: impl Into<String>) -> Self {
        self.toc_file = Some(file.into());
        self
    }

    /// Set the index file.
    pub fn with_index_file(mut self, file: impl Into<String>) -> Self {
        self.index_file = Some(file.into());
        self
    }

    /// Set the map file.
    pub fn with_map_file(mut self, file: impl Into<String>) -> Self {
        self.map_file = Some(file.into());
        self
    }

    /// Returns `true` if this help set has a table of contents.
    pub fn has_toc(&self) -> bool {
        self.toc_file.is_some()
    }

    /// Returns the number of imported help sets.
    pub fn import_count(&self) -> usize {
        self.imports.len()
    }
}

impl std::fmt::Display for HelpSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HelpSet({}, {})", self.name, self.file_path.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_help_set_new() {
        let hs = HelpSet::new("GhidraHelp", "help/GhidraHelp.hs");
        assert_eq!(hs.name, "GhidraHelp");
        assert!(!hs.has_toc());
    }

    #[test]
    fn test_help_set_builder() {
        let hs = HelpSet::new("Core", "core.hs")
            .with_title("Core Help")
            .with_base_url("help/topics")
            .with_toc_file("toc.xml")
            .with_index_file("index.xml");
        assert_eq!(hs.title, "Core Help");
        assert!(hs.has_toc());
        assert!(hs.index_file.is_some());
    }

    #[test]
    fn test_help_set_imports() {
        let mut hs = HelpSet::new("Main", "main.hs");
        hs.add_import("Core");
        hs.add_import("Features");
        assert_eq!(hs.import_count(), 2);
    }

    #[test]
    fn test_help_set_display() {
        let hs = HelpSet::new("X", "/path/x.hs");
        assert!(format!("{}", hs).contains("X"));
    }
}
