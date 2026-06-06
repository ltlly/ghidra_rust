//! Link validation types.
//!
//! Ported from `help.validator.links.*`. Provides concrete types for
//! different categories of invalid links.

use super::model::{InvalidLink, InvalidLinkReason};

/// An invalid HREF link.
#[derive(Debug, Clone)]
pub struct InvalidHREFLink {
    /// The source file containing the link.
    pub source: String,
    /// The invalid href.
    pub href: String,
}

impl InvalidHREFLink {
    /// Convert to a generic `InvalidLink`.
    pub fn to_invalid_link(&self) -> InvalidLink {
        InvalidLink {
            source_file: self.source.clone(),
            href: self.href.clone(),
            reason: InvalidLinkReason::MissingFile,
        }
    }
}

/// An invalid IMG link.
#[derive(Debug, Clone)]
pub struct InvalidIMGLink {
    /// The source file containing the image reference.
    pub source: String,
    /// The invalid image src.
    pub img_src: String,
}

impl InvalidIMGLink {
    /// Convert to a generic `InvalidLink`.
    pub fn to_invalid_link(&self) -> InvalidLink {
        InvalidLink {
            source_file: self.source.clone(),
            href: self.img_src.clone(),
            reason: InvalidLinkReason::MissingImage,
        }
    }
}

/// A link where the file exists but the anchor is missing.
#[derive(Debug, Clone)]
pub struct MissingAnchorInvalidLink {
    /// The source file.
    pub source: String,
    /// The href (including the `#anchor` portion).
    pub href: String,
}

/// A link where the target file does not exist.
#[derive(Debug, Clone)]
pub struct MissingFileInvalidLink {
    /// The source file.
    pub source: String,
    /// The href to the missing file.
    pub href: String,
}

/// A link to a missing image file.
#[derive(Debug, Clone)]
pub struct MissingIMGFileInvalidLink {
    /// The source file.
    pub source: String,
    /// The image src.
    pub img_src: String,
}

/// An image link with incorrect filename case.
#[derive(Debug, Clone)]
pub struct IncorrectIMGFilenameCaseInvalidLink {
    /// The source file.
    pub source: String,
    /// The requested image src.
    pub img_src: String,
    /// The correct image src (with proper case).
    pub correct_src: String,
}

/// An illegal module association in an HREF.
#[derive(Debug, Clone)]
pub struct IllegalHModuleAssociationHREF {
    /// The source file.
    pub source: String,
    /// The href.
    pub href: String,
    /// The module that is incorrectly referenced.
    pub module: String,
}

/// An illegal module association in an IMG.
#[derive(Debug, Clone)]
pub struct IllegalHModuleAssociationIMG {
    /// The source file.
    pub source: String,
    /// The img src.
    pub img_src: String,
    /// The module that is incorrectly referenced.
    pub module: String,
}

/// A link to a non-existent runtime image file.
#[derive(Debug, Clone)]
pub struct InvalidRuntimeIMGFile {
    /// The source file.
    pub source: String,
    /// The runtime image path.
    pub img_src: String,
}

/// A link to a missing TOC definition.
#[derive(Debug, Clone)]
pub struct MissingTOCDefinitionInvalidLink {
    /// The source file.
    pub source: String,
    /// The TOC target.
    pub toc_target: String,
}

/// A link to a missing TOC target ID.
#[derive(Debug, Clone)]
pub struct MissingTOCTargetIDInvalidLink {
    /// The source file.
    pub source: String,
    /// The TOC target ID.
    pub toc_target_id: String,
}

/// Duplicate anchor found across multiple files.
#[derive(Debug, Clone)]
pub struct DuplicateAnchorCollection {
    /// The anchor name.
    pub anchor_name: String,
    /// Files that define this anchor.
    pub files: Vec<String>,
}

impl DuplicateAnchorCollection {
    /// Create a new duplicate anchor collection.
    pub fn new(anchor_name: impl Into<String>) -> Self {
        Self {
            anchor_name: anchor_name.into(),
            files: Vec::new(),
        }
    }

    /// Add a file that defines this anchor.
    pub fn add_file(&mut self, file: impl Into<String>) {
        self.files.push(file.into());
    }

    /// Returns the number of files with this anchor.
    pub fn count(&self) -> usize {
        self.files.len()
    }

    /// Returns `true` if this anchor appears in more than one file.
    pub fn is_duplicate(&self) -> bool {
        self.files.len() > 1
    }
}

/// Duplicate anchor grouped by help file.
#[derive(Debug, Clone)]
pub struct DuplicateAnchorByHelpFile {
    /// The file containing the duplicates.
    pub file: String,
    /// The anchor name.
    pub anchor_name: String,
}

/// Duplicate anchor grouped by help topic.
#[derive(Debug, Clone)]
pub struct DuplicateAnchorByHelpTopic {
    /// The topic containing the duplicates.
    pub topic: String,
    /// The anchor name.
    pub anchor_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_href_link() {
        let link = InvalidHREFLink {
            source: "index.html".into(),
            href: "missing.html".into(),
        };
        let il = link.to_invalid_link();
        assert_eq!(il.reason, InvalidLinkReason::MissingFile);
    }

    #[test]
    fn test_invalid_img_link() {
        let link = InvalidIMGLink {
            source: "page.html".into(),
            img_src: "img/missing.png".into(),
        };
        let il = link.to_invalid_link();
        assert_eq!(il.reason, InvalidLinkReason::MissingImage);
    }

    #[test]
    fn test_duplicate_anchor_collection() {
        let mut d = DuplicateAnchorCollection::new("top");
        d.add_file("a.html");
        d.add_file("b.html");
        assert!(d.is_duplicate());
        assert_eq!(d.count(), 2);
    }

    #[test]
    fn test_duplicate_anchor_single() {
        let d = DuplicateAnchorCollection::new("only");
        assert!(!d.is_duplicate());
    }
}
