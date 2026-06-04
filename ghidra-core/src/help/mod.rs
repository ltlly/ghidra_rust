// Ghidra Help Framework
//
// Ported from Java's Ghidra/Framework/Help module. Provides:
// - Help service registration and lookup (HelpService, Help singleton)
// - Help location and descriptor types (HelpLocation, PathKey, ImageLocation)
// - Help content model (HelpFile, HelpTopic, TOC items, anchors, links)
// - Help module location management (HelpModuleLocation, HelpModuleCollection)
// - Help link validation (LinkDatabase, AnchorManager, JavaHelpValidator)
// - Help build system (GHelpBuilder, JavaHelpSetBuilder, HelpBuildUtils)

pub mod model;
pub mod location;
pub mod links;
pub mod validator;
pub mod builder;
pub mod path_key;
pub mod image_location;
pub mod service;

// Re-exports for convenience
pub use path_key::PathKey;
pub use image_location::ImageLocation;
pub use service::{
    DefaultHelpService, DynamicHelpLocation, Help, HelpLocation, HelpService,
};

pub use model::{
    AnchorDefinition, GhidraTocFile, HelpFile, HelpTopic, Href, Img,
    TocItem, TocItemDefinition, TocItemExternal, TocItemReference,
    get_help_topic_dir, is_remote_uri, relativize_with_help_topics,
};

pub use location::{HelpModuleCollection, HelpModuleLocation};

pub use links::{
    IncorrectImgFilenameCaseInvalidLink, InvalidLink,
    InvalidRuntimeImgFileInvalidLink,
    IllegalHModuleAssociationHrefInvalidLink,
    IllegalHModuleAssociationImgInvalidLink,
    MissingAnchorInvalidLink, MissingFileInvalidLink,
    MissingImgFileInvalidLink, MissingTocDefinitionInvalidLink,
    MissingTocTargetIdInvalidLink, NonExistentImgFileInvalidLink,
};

pub use validator::{AnchorManager, JavaHelpValidator, LinkDatabase};

pub use builder::{BuildResult, GHelpBuilder, HelpBuilderConfig};
