// Help framework: invalid link types (ported from help.validator.links Java package)

use std::path::{Path, PathBuf};

use crate::help::model::{Href, Img};

/// All possible types of invalid links found during help validation.
#[derive(Debug, Clone)]
pub enum InvalidLink {
    /// Unable to locate the referenced help file.
    MissingFile(MissingFileInvalidLink),
    /// Unable to locate an anchor within a referenced file.
    MissingAnchor(MissingAnchorInvalidLink),
    /// Unable to locate the image file.
    NonExistentImage(NonExistentImgFileInvalidLink),
    /// Image filename has incorrect case.
    IncorrectImageCase(IncorrectImgFilenameCaseInvalidLink),
    /// Runtime image reference not found.
    InvalidRuntimeImage(InvalidRuntimeImgFileInvalidLink),
    /// Image file not in help module.
    MissingImageFile(MissingImgFileInvalidLink),
    /// Illegal module association for HREF.
    IllegalHrefModule(IllegalHModuleAssociationHrefInvalidLink),
    /// Illegal module association for IMG.
    IllegalImgModule(IllegalHModuleAssociationImgInvalidLink),
    /// Missing TOC definition for a tocref.
    MissingTocDefinition(MissingTocDefinitionInvalidLink),
    /// Missing TOC target ID for a tocdef.
    MissingTocTargetId(MissingTocTargetIdInvalidLink),
}

impl InvalidLink {
    pub fn source_file(&self) -> &Path {
        match self {
            InvalidLink::MissingFile(l) => &l.href.source_file,
            InvalidLink::MissingAnchor(l) => &l.href.source_file,
            InvalidLink::NonExistentImage(l) => &l.img.source_file,
            InvalidLink::IncorrectImageCase(l) => &l.img.source_file,
            InvalidLink::InvalidRuntimeImage(l) => &l.img.source_file,
            InvalidLink::MissingImageFile(l) => &l.img.source_file,
            InvalidLink::IllegalHrefModule(l) => &l.href.source_file,
            InvalidLink::IllegalImgModule(l) => &l.img.source_file,
            InvalidLink::MissingTocDefinition(l) => &l.source_file,
            InvalidLink::MissingTocTargetId(l) => &l.source_file,
        }
    }

    pub fn line_number(&self) -> usize {
        match self {
            InvalidLink::MissingFile(l) => l.href.line_number,
            InvalidLink::MissingAnchor(l) => l.href.line_number,
            InvalidLink::NonExistentImage(l) => l.img.line_number,
            InvalidLink::IncorrectImageCase(l) => l.img.line_number,
            InvalidLink::InvalidRuntimeImage(l) => l.img.line_number,
            InvalidLink::MissingImageFile(l) => l.img.line_number,
            InvalidLink::IllegalHrefModule(l) => l.href.line_number,
            InvalidLink::IllegalImgModule(l) => l.img.line_number,
            InvalidLink::MissingTocDefinition(l) => l.line_number,
            InvalidLink::MissingTocTargetId(l) => l.line_number,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            InvalidLink::MissingFile(l) => &l.message,
            InvalidLink::MissingAnchor(l) => &l.message,
            InvalidLink::NonExistentImage(l) => &l.message,
            InvalidLink::IncorrectImageCase(l) => &l.message,
            InvalidLink::InvalidRuntimeImage(l) => &l.message,
            InvalidLink::MissingImageFile(l) => &l.message,
            InvalidLink::IllegalHrefModule(l) => &l.message,
            InvalidLink::IllegalImgModule(l) => &l.message,
            InvalidLink::MissingTocDefinition(l) => &l.message,
            InvalidLink::MissingTocTargetId(l) => &l.message,
        }
    }
}

impl std::fmt::Display for InvalidLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidLink::MissingFile(l) => write!(f, "{}", l),
            InvalidLink::MissingAnchor(l) => write!(f, "{}", l),
            InvalidLink::NonExistentImage(l) => write!(f, "{}", l),
            InvalidLink::IncorrectImageCase(l) => write!(f, "{}", l),
            InvalidLink::InvalidRuntimeImage(l) => write!(f, "{}", l),
            InvalidLink::MissingImageFile(l) => write!(f, "{}", l),
            InvalidLink::IllegalHrefModule(l) => write!(f, "{}", l),
            InvalidLink::IllegalImgModule(l) => write!(f, "{}", l),
            InvalidLink::MissingTocDefinition(l) => write!(f, "{}", l),
            InvalidLink::MissingTocTargetId(l) => write!(f, "{}", l),
        }
    }
}

impl PartialEq for InvalidLink {
    fn eq(&self, other: &Self) -> bool {
        self.source_file() == other.source_file()
            && self.line_number() == other.line_number()
            && self.message() == other.message()
    }
}

impl Eq for InvalidLink {}

impl PartialOrd for InvalidLink {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for InvalidLink {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Sort by type name first, then by source file, then by line number
        let type_name = std::mem::discriminant(self);
        let other_type_name = std::mem::discriminant(other);
        let self_name = format!("{:?}", type_name);
        let other_name = format!("{:?}", other_type_name);

        self_name
            .cmp(&other_name)
            .then_with(|| self.source_file().cmp(other.source_file()))
            .then_with(|| self.line_number().cmp(&other.line_number()))
    }
}

// ---------------------------------------------------------------------------
// InvalidHREFLink variants
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct MissingFileInvalidLink {
    pub href: Href,
    pub message: String,
}

impl MissingFileInvalidLink {
    pub fn new(href: Href) -> Self {
        MissingFileInvalidLink {
            href,
            message: "Unable to locate reference file".to_string(),
        }
    }
}

impl std::fmt::Display for MissingFileInvalidLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}\n\tlink: {}", self.message, self.href)
    }
}

#[derive(Debug, Clone)]
pub struct MissingAnchorInvalidLink {
    pub href: Href,
    pub message: String,
}

impl MissingAnchorInvalidLink {
    pub fn new(href: Href) -> Self {
        MissingAnchorInvalidLink {
            href,
            message: "Unable to locate anchor in reference file".to_string(),
        }
    }
}

impl std::fmt::Display for MissingAnchorInvalidLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}\n\tlink: {}", self.message, self.href)
    }
}

#[derive(Debug, Clone)]
pub struct IllegalHModuleAssociationHrefInvalidLink {
    pub href: Href,
    pub message: String,
    pub source_module: String,
    pub destination_module: String,
}

impl std::fmt::Display for IllegalHModuleAssociationHrefInvalidLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} - link: {} from file: {} (line:{}) \"{}\"->\"{}\"",
            self.message,
            self.href,
            self.href.source_file.display(),
            self.href.line_number,
            self.source_module,
            self.destination_module,
        )
    }
}

// ---------------------------------------------------------------------------
// InvalidIMGLink variants
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct NonExistentImgFileInvalidLink {
    pub img: Img,
    pub message: String,
}

impl NonExistentImgFileInvalidLink {
    pub fn new(img: Img) -> Self {
        NonExistentImgFileInvalidLink {
            img,
            message: "Unable to locate image file".to_string(),
        }
    }
}

impl std::fmt::Display for NonExistentImgFileInvalidLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -\n\tlink: {}", self.message, self.img)
    }
}

#[derive(Debug, Clone)]
pub struct IncorrectImgFilenameCaseInvalidLink {
    pub img: Img,
    pub message: String,
}

impl IncorrectImgFilenameCaseInvalidLink {
    pub fn new(img: Img) -> Self {
        IncorrectImgFilenameCaseInvalidLink {
            img,
            message: "Image filename has incorrect case".to_string(),
        }
    }
}

impl std::fmt::Display for IncorrectImgFilenameCaseInvalidLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -\n\tlink: {}", self.message, self.img)
    }
}

#[derive(Debug, Clone)]
pub struct InvalidRuntimeImgFileInvalidLink {
    pub img: Img,
    pub message: String,
}

impl InvalidRuntimeImgFileInvalidLink {
    pub fn new(img: Img) -> Self {
        InvalidRuntimeImgFileInvalidLink {
            img,
            message: "Runtime image not found (e.g., Icons.XYZ_ICON not found)".to_string(),
        }
    }
}

impl std::fmt::Display for InvalidRuntimeImgFileInvalidLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -\n\tlink: {}", self.message, self.img)
    }
}

#[derive(Debug, Clone)]
pub struct MissingImgFileInvalidLink {
    pub img: Img,
    pub message: String,
}

impl MissingImgFileInvalidLink {
    pub fn new(img: Img) -> Self {
        MissingImgFileInvalidLink {
            img,
            message: "Image file not in help module".to_string(),
        }
    }
}

impl std::fmt::Display for MissingImgFileInvalidLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -\n\tlink: {}", self.message, self.img)
    }
}

#[derive(Debug, Clone)]
pub struct IllegalHModuleAssociationImgInvalidLink {
    pub img: Img,
    pub message: String,
    pub source_module: String,
    pub destination_module: String,
}

impl std::fmt::Display for IllegalHModuleAssociationImgInvalidLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} - link: {} from file: {} (line:{}) \"{}\"->\"{}\"",
            self.message,
            self.img,
            self.img.source_file.display(),
            self.img.line_number,
            self.source_module,
            self.destination_module,
        )
    }
}

// ---------------------------------------------------------------------------
// TOC-related invalid links
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct MissingTocDefinitionInvalidLink {
    pub source_file: PathBuf,
    pub line_number: usize,
    pub message: String,
    pub reference_id: String,
}

impl MissingTocDefinitionInvalidLink {
    pub fn new(source_file: PathBuf, line_number: usize, reference_id: String) -> Self {
        MissingTocDefinitionInvalidLink {
            source_file,
            line_number,
            message: "Missing TOC definition for reference".to_string(),
            reference_id,
        }
    }
}

impl std::fmt::Display for MissingTocDefinitionInvalidLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Missing TOC definition (<tocdef>) for reference (<tocref>):\n\t<tocref id=\"{}\"/>\n\t[source file=\"{}\" (line:{})]",
            self.reference_id,
            self.source_file.display(),
            self.line_number,
        )
    }
}

#[derive(Debug, Clone)]
pub struct MissingTocTargetIdInvalidLink {
    pub source_file: PathBuf,
    pub line_number: usize,
    pub message: String,
    pub item_id: String,
}

impl MissingTocTargetIdInvalidLink {
    pub fn new(source_file: PathBuf, line_number: usize, item_id: String) -> Self {
        MissingTocTargetIdInvalidLink {
            source_file,
            line_number,
            message: "Missing TOC target ID for definition".to_string(),
            item_id,
        }
    }
}

impl std::fmt::Display for MissingTocTargetIdInvalidLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Missing TOC target ID for definition (<tocdef>):\n\t<tocdef id=\"{}\"/>\n\t[source file=\"{}\" (line:{})]",
            self.item_id,
            self.source_file.display(),
            self.line_number,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::help::model::{Href, Img};

    fn make_test_href() -> Href {
        Href::new(
            PathBuf::from("/src/help/topics/MyTopic/page.html"),
            "other.html".to_string(),
            10,
        )
    }

    fn make_test_img() -> Img {
        Img::new(
            PathBuf::from("/src/help/topics/MyTopic/page.html"),
            "images/icon.png".to_string(),
            20,
        )
    }

    #[test]
    fn test_missing_file_invalid_link() {
        let link = InvalidLink::MissingFile(MissingFileInvalidLink::new(make_test_href()));
        assert_eq!(link.line_number(), 10);
        assert!(link.message().contains("Unable to locate"));
    }

    #[test]
    fn test_missing_anchor_invalid_link() {
        let link = InvalidLink::MissingAnchor(MissingAnchorInvalidLink::new(make_test_href()));
        assert!(link.message().contains("anchor"));
    }

    #[test]
    fn test_nonexistent_img_invalid_link() {
        let link = InvalidLink::NonExistentImage(NonExistentImgFileInvalidLink::new(make_test_img()));
        assert_eq!(link.line_number(), 20);
        assert!(link.message().contains("image"));
    }

    #[test]
    fn test_invalid_runtime_img_link() {
        let img = Img::new(
            PathBuf::from("/src/help/topics/MyTopic/page.html"),
            "Icons.ERROR_ICON".to_string(),
            15,
        );
        let link = InvalidLink::InvalidRuntimeImage(InvalidRuntimeImgFileInvalidLink::new(img));
        assert!(link.message().contains("Runtime"));
    }

    #[test]
    fn test_missing_toc_definition_link() {
        let link = InvalidLink::MissingTocDefinition(MissingTocDefinitionInvalidLink::new(
            PathBuf::from("/src/TOC_Source.xml"),
            5,
            "missing_ref".to_string(),
        ));
        assert!(link.message().contains("TOC definition"));
        let display = format!("{}", link);
        assert!(display.contains("missing_ref"));
    }

    #[test]
    fn test_missing_toc_target_id_link() {
        let link = InvalidLink::MissingTocTargetId(MissingTocTargetIdInvalidLink::new(
            PathBuf::from("/src/TOC_Source.xml"),
            10,
            "bad_id".to_string(),
        ));
        assert!(link.message().contains("TOC target ID"));
    }

    #[test]
    fn test_invalid_link_display() {
        let link = InvalidLink::MissingFile(MissingFileInvalidLink::new(make_test_href()));
        let display = format!("{}", link);
        assert!(!display.is_empty());
    }

    #[test]
    fn test_invalid_link_ordering() {
        let l1 = InvalidLink::MissingFile(MissingFileInvalidLink::new(make_test_href()));
        let l2 = InvalidLink::MissingAnchor(MissingAnchorInvalidLink::new(make_test_href()));
        // They should be orderable
        let _ = l1.cmp(&l2);
    }
}
