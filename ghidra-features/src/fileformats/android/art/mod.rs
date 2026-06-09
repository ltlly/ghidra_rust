//! Android ART image file format modules.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.art` package.
//!
//! Covers: ART image headers (versions 005-106), image blocks,
//! ART methods, ART fields, image sections, and the analyzer.

pub mod art_analyzer;
pub mod art_block;
pub mod art_field;
pub mod art_header;
pub mod art_image_section;
pub mod art_method;

// Re-exports
pub use art_analyzer::ArtAnalyzer;
pub use art_block::{ArtBlock, ArtStorageMode};
pub use art_field::{ArtField, ArtFieldGroup};
pub use art_header::{
    is_art, is_supported_version, parse_art_header, ArtHeaderVersion, ImageSectionsLayout,
    ART_MAGIC, ART_VERSION_005, ART_VERSION_009, ART_VERSION_012, ART_VERSION_017,
    ART_VERSION_029, ART_VERSION_030, ART_VERSION_043, ART_VERSION_044, ART_VERSION_046,
    ART_VERSION_056, ART_VERSION_074, ART_VERSION_085, ART_VERSION_099, ART_VERSION_106,
};
pub use art_image_section::{section_name, ArtImageSection, ArtImageSections};
pub use art_method::{ArtMethod, ArtMethodGroup};
