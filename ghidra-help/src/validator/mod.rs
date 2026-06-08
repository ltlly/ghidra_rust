//! Help content validator: link checking, anchor management, and TOC validation.
//!
//! Ported from `help.validator.*`.

pub mod links;
pub mod location;
pub mod model;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use model::{AnchorDefinition, HelpFile, InvalidLink, TOCItemDefinition};

/// Main help validator.
///
/// Scans help HTML files for broken links, missing anchors, and TOC issues.
/// Ported from `help.validator.JavaHelpValidator`.
#[derive(Debug)]
pub struct JavaHelpValidator {
    /// The root directory of help content.
    help_root: PathBuf,
    /// All discovered help files, keyed by relative path.
    files: HashMap<PathBuf, HelpFile>,
    /// All anchor definitions across all files.
    anchors: HashMap<String, Vec<AnchorDefinition>>,
    /// All discovered invalid links.
    invalid_links: Vec<InvalidLink>,
    /// TOC item definitions.
    toc_items: Vec<TOCItemDefinition>,
}

impl JavaHelpValidator {
    /// Create a new validator for the given help root directory.
    pub fn new(help_root: impl Into<PathBuf>) -> Self {
        Self {
            help_root: help_root.into(),
            files: HashMap::new(),
            anchors: HashMap::new(),
            invalid_links: Vec::new(),
            toc_items: Vec::new(),
        }
    }

    /// Returns the help root directory.
    pub fn help_root(&self) -> &Path {
        &self.help_root
    }

    /// Register a help file.
    pub fn add_help_file(&mut self, file: HelpFile) {
        self.files.insert(file.relative_path.clone(), file);
    }

    /// Register an anchor definition.
    pub fn add_anchor(&mut self, anchor: AnchorDefinition) {
        self.anchors
            .entry(anchor.name.clone())
            .or_default()
            .push(anchor);
    }

    /// Register an invalid link.
    pub fn add_invalid_link(&mut self, link: InvalidLink) {
        self.invalid_links.push(link);
    }

    /// Register a TOC item definition.
    pub fn add_toc_item(&mut self, item: TOCItemDefinition) {
        self.toc_items.push(item);
    }

    /// Returns the number of registered help files.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Returns the number of invalid links found.
    pub fn invalid_link_count(&self) -> usize {
        self.invalid_links.len()
    }

    /// Returns all registered anchor names.
    pub fn anchor_names(&self) -> Vec<&str> {
        self.anchors.keys().map(|s| s.as_str()).collect()
    }

    /// Returns `true` if a given anchor is defined in any help file.
    pub fn has_anchor(&self, name: &str) -> bool {
        self.anchors.contains_key(name)
    }

    /// Returns all anchor definitions for a given name.
    pub fn get_anchor(&self, name: &str) -> Option<&Vec<AnchorDefinition>> {
        self.anchors.get(name)
    }

    /// Returns all invalid links.
    pub fn invalid_links(&self) -> &[InvalidLink] {
        &self.invalid_links
    }

    /// Returns all TOC items.
    pub fn toc_items(&self) -> &[TOCItemDefinition] {
        &self.toc_items
    }

    /// Returns a summary report.
    pub fn summary(&self) -> String {
        format!(
            "Help Validator Summary:\n  Files: {}\n  Anchors: {}\n  Invalid links: {}\n  TOC items: {}",
            self.file_count(),
            self.anchors.len(),
            self.invalid_link_count(),
            self.toc_items.len(),
        )
    }

    /// Returns `true` if no issues were found.
    pub fn is_valid(&self) -> bool {
        self.invalid_links.is_empty()
    }
}

impl Default for JavaHelpValidator {
    fn default() -> Self {
        Self::new(PathBuf::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_new() {
        let v = JavaHelpValidator::new("/help/root");
        assert_eq!(v.help_root(), Path::new("/help/root"));
        assert!(v.is_valid());
    }

    #[test]
    fn test_add_help_file() {
        let mut v = JavaHelpValidator::new("/h");
        v.add_help_file(HelpFile::new("topics/index.html"));
        assert_eq!(v.file_count(), 1);
    }

    #[test]
    fn test_add_anchor() {
        let mut v = JavaHelpValidator::new("/h");
        v.add_anchor(AnchorDefinition::new("Options", "Core/Settings.html"));
        assert!(v.has_anchor("Options"));
    }

    #[test]
    fn test_invalid_link_count() {
        let mut v = JavaHelpValidator::new("/h");
        v.add_invalid_link(InvalidLink::missing_file("broken.html"));
        v.add_invalid_link(InvalidLink::missing_anchor("t.html#no"));
        assert_eq!(v.invalid_link_count(), 2);
        assert!(!v.is_valid());
    }

    #[test]
    fn test_summary() {
        let mut v = JavaHelpValidator::new("/h");
        v.add_help_file(HelpFile::new("a.html"));
        v.add_anchor(AnchorDefinition::new("A", "a.html"));
        let summary = v.summary();
        assert!(summary.contains("Files: 1"));
        assert!(summary.contains("Anchors: 1"));
    }

    #[test]
    fn test_toc_items() {
        let mut v = JavaHelpValidator::new("/h");
        v.add_toc_item(TOCItemDefinition::new("Getting Started", "intro.html"));
        assert_eq!(v.toc_items().len(), 1);
    }
}
