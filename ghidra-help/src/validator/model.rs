//! Validation model types: `HelpFile`, `AnchorDefinition`, `InvalidLink`, etc.
//!
//! Ported from `help.validator.model.*` and `help.validator.links.*`.

use std::path::PathBuf;

/// A help HTML file discovered during scanning.
#[derive(Debug, Clone)]
pub struct HelpFile {
    /// Path relative to the help topics root.
    pub relative_path: PathBuf,
    /// Extracted anchor names (`<a name="...">`).
    pub anchors: Vec<String>,
    /// Extracted href targets.
    pub hrefs: Vec<String>,
}

impl HelpFile {
    /// Create a new help file entry.
    pub fn new(relative_path: impl Into<PathBuf>) -> Self {
        Self {
            relative_path: relative_path.into(),
            anchors: Vec::new(),
            hrefs: Vec::new(),
        }
    }

    /// Add an anchor definition.
    pub fn add_anchor(&mut self, name: impl Into<String>) {
        self.anchors.push(name.into());
    }

    /// Add an href target.
    pub fn add_href(&mut self, href: impl Into<String>) {
        self.hrefs.push(href.into());
    }
}

/// An anchor definition found in a help file.
#[derive(Debug, Clone)]
pub struct AnchorDefinition {
    /// The anchor name.
    pub name: String,
    /// The file in which this anchor is defined.
    pub file: String,
}

impl AnchorDefinition {
    /// Create a new anchor definition.
    pub fn new(name: impl Into<String>, file: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            file: file.into(),
        }
    }
}

/// A TOC item definition.
#[derive(Debug, Clone)]
pub struct TOCItemDefinition {
    /// The display text in the TOC.
    pub text: String,
    /// The target help file.
    pub target: String,
    /// Optional target anchor.
    pub anchor: Option<String>,
    /// The nesting level (0 = root).
    pub level: usize,
}

impl TOCItemDefinition {
    /// Create a new TOC item.
    pub fn new(text: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            target: target.into(),
            anchor: None,
            level: 0,
        }
    }

    /// Set the anchor.
    pub fn with_anchor(mut self, anchor: impl Into<String>) -> Self {
        self.anchor = Some(anchor.into());
        self
    }

    /// Set the nesting level.
    pub fn at_level(mut self, level: usize) -> Self {
        self.level = level;
        self
    }
}

/// An invalid link discovered during validation.
#[derive(Debug, Clone)]
pub struct InvalidLink {
    /// The file containing the invalid link.
    pub source_file: String,
    /// The href that is invalid.
    pub href: String,
    /// Description of the issue.
    pub reason: InvalidLinkReason,
}

/// Reason a link is considered invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidLinkReason {
    /// The target file does not exist.
    MissingFile,
    /// The target anchor does not exist.
    MissingAnchor,
    /// The href has an illegal module association.
    IllegalModuleAssociation,
    /// The image file is missing.
    MissingImage,
    /// The image file name has incorrect case.
    IncorrectImageFilenameCase,
    /// The TOC definition is missing.
    MissingTOCDefinition,
    /// The TOC target ID is missing.
    MissingTOCTargetId,
    /// Duplicate anchor found in another file.
    DuplicateAnchor(String),
    /// The runtime image file does not exist.
    InvalidRuntimeImage,
}

impl InvalidLink {
    /// Create a missing-file link.
    pub fn missing_file(href: impl Into<String>) -> Self {
        Self {
            source_file: String::new(),
            href: href.into(),
            reason: InvalidLinkReason::MissingFile,
        }
    }

    /// Create a missing-anchor link.
    pub fn missing_anchor(href: impl Into<String>) -> Self {
        Self {
            source_file: String::new(),
            href: href.into(),
            reason: InvalidLinkReason::MissingAnchor,
        }
    }

    /// Create with a source file.
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source_file = source.into();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_help_file() {
        let mut hf = HelpFile::new("Core/index.html");
        hf.add_anchor("top");
        hf.add_href("../Other/page.html");
        assert_eq!(hf.anchors.len(), 1);
        assert_eq!(hf.hrefs.len(), 1);
    }

    #[test]
    fn test_anchor_definition() {
        let ad = AnchorDefinition::new("Options", "Settings.html");
        assert_eq!(ad.name, "Options");
        assert_eq!(ad.file, "Settings.html");
    }

    #[test]
    fn test_toc_item() {
        let item = TOCItemDefinition::new("Overview", "intro.html")
            .with_anchor("overview")
            .at_level(1);
        assert_eq!(item.level, 1);
        assert_eq!(item.anchor.as_deref(), Some("overview"));
    }

    #[test]
    fn test_invalid_link_missing_file() {
        let link = InvalidLink::missing_file("broken.html").with_source("index.html");
        assert_eq!(link.reason, InvalidLinkReason::MissingFile);
        assert_eq!(link.source_file, "index.html");
    }

    #[test]
    fn test_invalid_link_missing_anchor() {
        let link = InvalidLink::missing_anchor("page.html#x");
        assert_eq!(link.reason, InvalidLinkReason::MissingAnchor);
    }

    #[test]
    fn test_invalid_link_reasons() {
        assert_ne!(
            InvalidLinkReason::MissingFile,
            InvalidLinkReason::MissingAnchor
        );
    }
}
