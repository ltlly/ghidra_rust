//! Android ART image header parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.art.ArtHeader`,
//! `ArtHeaderFactory`, and per-version `headers/ArtHeader_*.java`.
//!
//! The ART image header is the on-disk header for `.art` files produced
//! by the Android Runtime (ART).  Each Android release version changes
//! the header layout; this module covers versions 005 through 106.
//!
//! References:
//! - <https://android.googlesource.com/platform/art/+/refs/heads/master/runtime/image.h>

use super::art_block::ArtBlock;
use super::art_image_section::ArtImageSection;

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// ART image magic: `"art\n"`.
pub const ART_MAGIC: &[u8; 4] = b"art\n";

/// Length of the version string (4 bytes, ASCII).
pub const VERSION_LENGTH: usize = 4;

// Supported version strings.
pub const ART_VERSION_005: &str = "005"; // KitKat
pub const ART_VERSION_009: &str = "009"; // Lollipop
pub const ART_VERSION_012: &str = "012"; // Lollipop MR1 WFC
pub const ART_VERSION_017: &str = "017"; // Marshmallow
pub const ART_VERSION_029: &str = "029"; // Nougat
pub const ART_VERSION_030: &str = "030"; // Nougat MR2 Pixel
pub const ART_VERSION_043: &str = "043"; // Oreo
pub const ART_VERSION_044: &str = "044"; // Oreo MR1
pub const ART_VERSION_046: &str = "046"; // Oreo MR1
pub const ART_VERSION_056: &str = "056"; // Pie
pub const ART_VERSION_074: &str = "074"; // Q
pub const ART_VERSION_085: &str = "085"; // R
pub const ART_VERSION_099: &str = "099"; // S
pub const ART_VERSION_106: &str = "106"; // S v2, 13

/// All supported ART version strings.
pub const SUPPORTED_VERSIONS: &[&str] = &[
    ART_VERSION_005,
    ART_VERSION_009,
    ART_VERSION_012,
    ART_VERSION_017,
    ART_VERSION_029,
    ART_VERSION_030,
    ART_VERSION_043,
    ART_VERSION_044,
    ART_VERSION_046,
    ART_VERSION_056,
    ART_VERSION_074,
    ART_VERSION_085,
    ART_VERSION_099,
    ART_VERSION_106,
];

// Image method counts per version.
/// Marshmallow (017) image method count.
pub const IMAGE_METHODS_COUNT_MARSHMALLOW: usize = 5;
/// Nougat/Pie-era image method count.
pub const IMAGE_METHODS_COUNT_NOUGAT: usize = 8;
/// Q+ image method count.
pub const IMAGE_METHODS_COUNT_Q: usize = 9;

// ═══════════════════════════════════════════════════════════════════════════════════
// Image Method enum (Q+)
// ═══════════════════════════════════════════════════════════════════════════════════

/// Image method indices for Android Q and later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum ImageMethodQ {
    ResolutionMethod = 0,
    ImtConflictMethod = 1,
    ImtUnimplementedMethod = 2,
    SaveAllCalleeSavesMethod = 3,
    SaveRefsOnlyMethod = 4,
    SaveRefsAndArgsMethod = 5,
    SaveEverythingMethod = 6,
    SaveEverythingMethodForClinit = 7,
    SaveEverythingMethodForSuspendCheck = 8,
}

impl ImageMethodQ {
    /// Number of image methods for Q+.
    pub const COUNT: usize = 9;
}

// ═══════════════════════════════════════════════════════════════════════════════════
// ArtImageSectionCount enum
// ═══════════════════════════════════════════════════════════════════════════════════

/// Section layout descriptor -- maps ART version to section count and ordinal names.
///
/// In the Java source, each Android version has its own `ImageSections_*` class
/// with a `kSection*` enum.  In Rust we encode this as a simple struct that
/// stores the section count and per-ordinal option indices.
#[derive(Debug, Clone)]
pub struct ImageSectionsLayout {
    pub section_count: usize,
    pub objects: usize,
    pub art_fields: Option<usize>,
    pub art_methods: Option<usize>,
    pub runtime_methods: Option<usize>,
    pub im_tables: Option<usize>,
    pub imt_conflict_tables: Option<usize>,
    pub dex_cache_arrays: Option<usize>,
    pub interned_strings: Option<usize>,
    pub class_table: Option<usize>,
    pub string_reference_offsets: Option<usize>,
    pub metadata: Option<usize>,
    pub image_bitmap: Option<usize>,
}

impl ImageSectionsLayout {
    /// Marshmallow (version 017).
    pub fn marshmallow() -> Self {
        Self {
            section_count: 5,
            objects: 0,
            art_fields: Some(1),
            art_methods: Some(2),
            runtime_methods: None,
            im_tables: None,
            imt_conflict_tables: None,
            dex_cache_arrays: None,
            interned_strings: Some(3),
            class_table: None,
            string_reference_offsets: None,
            metadata: None,
            image_bitmap: Some(4),
        }
    }

    /// Nougat (version 029).
    pub fn nougat() -> Self {
        Self {
            section_count: 7,
            objects: 0,
            art_fields: Some(1),
            art_methods: Some(2),
            runtime_methods: Some(3),
            im_tables: Some(4),
            imt_conflict_tables: Some(5),
            dex_cache_arrays: None,
            interned_strings: Some(6),
            class_table: None,
            string_reference_offsets: None,
            metadata: None,
            image_bitmap: None, // removed in Nougat
        }
    }

    /// Nougat MR2 Pixel (version 030).
    pub fn nougat_mr2_pixel() -> Self {
        Self {
            section_count: 8,
            objects: 0,
            art_fields: Some(1),
            art_methods: Some(2),
            runtime_methods: Some(3),
            im_tables: Some(4),
            imt_conflict_tables: Some(5),
            dex_cache_arrays: Some(6),
            interned_strings: Some(7),
            class_table: None,
            string_reference_offsets: None,
            metadata: None,
            image_bitmap: None,
        }
    }

    /// Oreo (versions 043, 044).
    pub fn oreo() -> Self {
        Self {
            section_count: 10,
            objects: 0,
            art_fields: Some(1),
            art_methods: Some(2),
            runtime_methods: Some(3),
            im_tables: Some(4),
            imt_conflict_tables: Some(5),
            dex_cache_arrays: Some(6),
            interned_strings: Some(7),
            class_table: Some(8),
            string_reference_offsets: Some(9),
            metadata: None,
            image_bitmap: None,
        }
    }

    /// Oreo MR1 (version 046).
    pub fn oreo_mr1() -> Self {
        Self {
            section_count: 11,
            objects: 0,
            art_fields: Some(1),
            art_methods: Some(2),
            runtime_methods: Some(3),
            im_tables: Some(4),
            imt_conflict_tables: Some(5),
            dex_cache_arrays: Some(6),
            interned_strings: Some(7),
            class_table: Some(8),
            string_reference_offsets: Some(9),
            metadata: Some(10),
            image_bitmap: None,
        }
    }

    /// Pie (version 056).
    pub fn pie() -> Self {
        Self {
            section_count: 12,
            objects: 0,
            art_fields: Some(1),
            art_methods: Some(2),
            runtime_methods: Some(3),
            im_tables: Some(4),
            imt_conflict_tables: Some(5),
            dex_cache_arrays: Some(6),
            interned_strings: Some(7),
            class_table: Some(8),
            string_reference_offsets: Some(9),
            metadata: Some(10),
            image_bitmap: Some(11),
        }
    }

    /// Q / R (versions 074, 085).
    pub fn q_r() -> Self {
        Self {
            section_count: 12,
            objects: 0,
            art_fields: Some(1),
            art_methods: Some(2),
            runtime_methods: Some(3),
            im_tables: Some(4),
            imt_conflict_tables: Some(5),
            dex_cache_arrays: Some(6),
            interned_strings: Some(7),
            class_table: Some(8),
            string_reference_offsets: Some(9),
            metadata: Some(10),
            image_bitmap: Some(11),
        }
    }

    /// S / T (versions 099, 106).
    pub fn s_t() -> Self {
        Self {
            section_count: 11,
            objects: 0,
            art_fields: Some(1),
            art_methods: Some(2),
            runtime_methods: Some(3),
            im_tables: Some(4),
            imt_conflict_tables: Some(5),
            dex_cache_arrays: None, // removed in S
            interned_strings: Some(6),
            class_table: Some(7),
            string_reference_offsets: Some(8),
            metadata: Some(9),
            image_bitmap: Some(10),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// ArtHeaderVersion enum
// ═══════════════════════════════════════════════════════════════════════════════════

/// Discriminated ART header, covering all supported versions.
///
/// The Java source uses an abstract `ArtHeader` base class with per-version
/// subclasses (`ArtHeader_005`, `ArtHeader_017`, ...).  In Rust we use an enum
/// whose variants carry the version-specific fields.
#[derive(Debug, Clone)]
pub enum ArtHeaderVersion {
    /// KitKat (version 005).
    V005(ArtHeaderV005),
    /// Lollipop (version 009).
    V009(ArtHeaderV009),
    /// Lollipop MR1 WFC (version 012).
    V012(ArtHeaderV012),
    /// Marshmallow (version 017).
    V017(ArtHeaderV017),
    /// Nougat (version 029).
    V029(ArtHeaderV029),
    /// Nougat MR2 Pixel (version 030).
    V030(ArtHeaderV030),
    /// Oreo (version 043).
    V043(ArtHeaderV043),
    /// Oreo MR1 (version 044).
    V044(ArtHeaderV044),
    /// Oreo MR1 (version 046).
    V046(ArtHeaderV046),
    /// Pie (version 056).
    V056(ArtHeaderV056),
    /// Q (version 074).
    V074(ArtHeaderV074),
    /// R (version 085).
    V085(ArtHeaderV085),
    /// S (version 099).
    V099(ArtHeaderV099),
    /// S v2 / 13 (version 106).
    V106(ArtHeaderV106),
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Per-version header structs
// ═══════════════════════════════════════════════════════════════════════════════════

/// KitKat header (version 005).
#[derive(Debug, Clone)]
pub struct ArtHeaderV005 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub image_begin: u32,
    pub image_size: u32,
    pub image_bitmap_offset: u32,
    pub image_bitmap_size: u32,
    pub oat_checksum: u32,
    pub oat_file_begin: u32,
    pub oat_data_begin: u32,
    pub oat_data_end: u32,
    pub oat_file_end: u32,
    pub image_roots: u32,
}

/// Lollipop header (version 009).
#[derive(Debug, Clone)]
pub struct ArtHeaderV009 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub image_begin: u32,
    pub image_size: u32,
    pub image_bitmap_offset: u32,
    pub image_bitmap_size: u32,
    pub oat_checksum: u32,
    pub oat_file_begin: u32,
    pub oat_data_begin: u32,
    pub oat_data_end: u32,
    pub oat_file_end: u32,
    pub image_roots: u32,
}

/// Lollipop MR1 WFC header (version 012).
#[derive(Debug, Clone)]
pub struct ArtHeaderV012 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub image_begin: u32,
    pub image_size: u32,
    pub image_bitmap_offset: u32,
    pub image_bitmap_size: u32,
    pub oat_checksum: u32,
    pub oat_file_begin: u32,
    pub oat_data_begin: u32,
    pub oat_data_end: u32,
    pub oat_file_end: u32,
    pub image_roots: u32,
}

/// Marshmallow header (version 017).
#[derive(Debug, Clone)]
pub struct ArtHeaderV017 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub image_begin: u32,
    pub image_size: u32,
    pub oat_checksum: u32,
    pub oat_file_begin: u32,
    pub oat_data_begin: u32,
    pub oat_data_end: u32,
    pub oat_file_end: u32,
    pub patch_delta: u32,
    pub image_roots: u32,
    pub pointer_size: u32,
    pub compile_pic: u32,
    pub sections: Vec<ArtImageSection>,
    pub image_methods: Vec<u64>,
}

/// Nougat header (version 029).
#[derive(Debug, Clone)]
pub struct ArtHeaderV029 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub image_begin: u32,
    pub image_size: u32,
    pub oat_checksum: u32,
    pub oat_file_begin: u32,
    pub oat_data_begin: u32,
    pub oat_data_end: u32,
    pub oat_file_end: u32,
    pub patch_delta: u32,
    pub image_roots: u32,
    pub pointer_size: u32,
    pub compile_pic: u32,
    pub sections: Vec<ArtImageSection>,
    pub image_methods: Vec<u64>,
}

/// Nougat MR2 Pixel header (version 030).
#[derive(Debug, Clone)]
pub struct ArtHeaderV030 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub image_begin: u32,
    pub image_size: u32,
    pub oat_checksum: u32,
    pub oat_file_begin: u32,
    pub oat_data_begin: u32,
    pub oat_data_end: u32,
    pub oat_file_end: u32,
    pub patch_delta: u32,
    pub image_roots: u32,
    pub pointer_size: u32,
    pub compile_pic: u32,
    pub sections: Vec<ArtImageSection>,
    pub image_methods: Vec<u64>,
}

/// Oreo header (version 043).
#[derive(Debug, Clone)]
pub struct ArtHeaderV043 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub image_reservation_size: u32,
    pub component_count: u32,
    pub image_begin: u32,
    pub image_size: u32,
    pub image_checksum: u32,
    pub oat_checksum: u32,
    pub oat_file_begin: u32,
    pub oat_data_begin: u32,
    pub oat_data_end: u32,
    pub oat_file_end: u32,
    pub boot_image_begin: u32,
    pub boot_image_size: u32,
    pub image_roots: u32,
    pub pointer_size: u32,
    pub sections: Vec<ArtImageSection>,
    pub image_methods: Vec<u64>,
    pub data_size: u32,
    pub blocks_offset: u32,
    pub blocks_count: u32,
    pub blocks: Vec<ArtBlock>,
}

/// Oreo MR1 header (version 044).
#[derive(Debug, Clone)]
pub struct ArtHeaderV044 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub image_reservation_size: u32,
    pub component_count: u32,
    pub image_begin: u32,
    pub image_size: u32,
    pub image_checksum: u32,
    pub oat_checksum: u32,
    pub oat_file_begin: u32,
    pub oat_data_begin: u32,
    pub oat_data_end: u32,
    pub oat_file_end: u32,
    pub boot_image_begin: u32,
    pub boot_image_size: u32,
    pub image_roots: u32,
    pub pointer_size: u32,
    pub sections: Vec<ArtImageSection>,
    pub image_methods: Vec<u64>,
    pub data_size: u32,
    pub blocks_offset: u32,
    pub blocks_count: u32,
    pub blocks: Vec<ArtBlock>,
}

/// Oreo MR1 header (version 046).
#[derive(Debug, Clone)]
pub struct ArtHeaderV046 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub image_reservation_size: u32,
    pub component_count: u32,
    pub image_begin: u32,
    pub image_size: u32,
    pub image_checksum: u32,
    pub oat_checksum: u32,
    pub oat_file_begin: u32,
    pub oat_data_begin: u32,
    pub oat_data_end: u32,
    pub oat_file_end: u32,
    pub boot_image_begin: u32,
    pub boot_image_size: u32,
    pub image_roots: u32,
    pub pointer_size: u32,
    pub sections: Vec<ArtImageSection>,
    pub image_methods: Vec<u64>,
    pub data_size: u32,
    pub blocks_offset: u32,
    pub blocks_count: u32,
    pub blocks: Vec<ArtBlock>,
}

/// Pie header (version 056).
#[derive(Debug, Clone)]
pub struct ArtHeaderV056 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub image_reservation_size: u32,
    pub component_count: u32,
    pub image_begin: u32,
    pub image_size: u32,
    pub image_checksum: u32,
    pub oat_checksum: u32,
    pub oat_file_begin: u32,
    pub oat_data_begin: u32,
    pub oat_data_end: u32,
    pub oat_file_end: u32,
    pub boot_image_begin: u32,
    pub boot_image_size: u32,
    pub image_roots: u32,
    pub pointer_size: u32,
    pub sections: Vec<ArtImageSection>,
    pub image_methods: Vec<u64>,
    pub data_size: u32,
    pub blocks_offset: u32,
    pub blocks_count: u32,
    pub blocks: Vec<ArtBlock>,
}

/// Q header (version 074).
#[derive(Debug, Clone)]
pub struct ArtHeaderV074 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub image_reservation_size: u32,
    pub component_count: u32,
    pub image_begin: u32,
    pub image_size: u32,
    pub image_checksum: u32,
    pub oat_checksum: u32,
    pub oat_file_begin: u32,
    pub oat_data_begin: u32,
    pub oat_data_end: u32,
    pub oat_file_end: u32,
    pub boot_image_begin: u32,
    pub boot_image_size: u32,
    pub image_roots: u32,
    pub pointer_size: u32,
    pub sections: Vec<ArtImageSection>,
    pub image_methods: Vec<u64>,
    pub data_size: u32,
    pub blocks_offset: u32,
    pub blocks_count: u32,
    pub blocks: Vec<ArtBlock>,
}

/// R header (version 085).
#[derive(Debug, Clone)]
pub struct ArtHeaderV085 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub image_reservation_size: u32,
    pub component_count: u32,
    pub image_begin: u32,
    pub image_size: u32,
    pub image_checksum: u32,
    pub oat_checksum: u32,
    pub oat_file_begin: u32,
    pub oat_data_begin: u32,
    pub oat_data_end: u32,
    pub oat_file_end: u32,
    pub boot_image_begin: u32,
    pub boot_image_size: u32,
    pub boot_image_component_count: u32,
    pub boot_image_checksum: u32,
    pub image_roots: u32,
    pub pointer_size: u32,
    pub sections: Vec<ArtImageSection>,
    pub image_methods: Vec<u64>,
    pub data_size: u32,
    pub blocks_offset: u32,
    pub blocks_count: u32,
    pub blocks: Vec<ArtBlock>,
}

/// S header (version 099).
#[derive(Debug, Clone)]
pub struct ArtHeaderV099 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub image_reservation_size: u32,
    pub component_count: u32,
    pub image_begin: u32,
    pub image_size: u32,
    pub image_checksum: u32,
    pub oat_checksum: u32,
    pub oat_file_begin: u32,
    pub oat_data_begin: u32,
    pub oat_data_end: u32,
    pub oat_file_end: u32,
    pub boot_image_begin: u32,
    pub boot_image_size: u32,
    pub boot_image_component_count: u32,
    pub boot_image_checksum: u32,
    pub image_roots: u32,
    pub pointer_size: u32,
    pub sections: Vec<ArtImageSection>,
    pub image_methods: Vec<u64>,
    pub data_size: u32,
    pub blocks_offset: u32,
    pub blocks_count: u32,
    pub blocks: Vec<ArtBlock>,
}

/// S v2 / 13 header (version 106).
#[derive(Debug, Clone)]
pub struct ArtHeaderV106 {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub image_reservation_size: u32,
    pub component_count: u32,
    pub image_begin: u32,
    pub image_size: u32,
    pub image_checksum: u32,
    pub oat_checksum: u32,
    pub oat_file_begin: u32,
    pub oat_data_begin: u32,
    pub oat_data_end: u32,
    pub oat_file_end: u32,
    pub boot_image_begin: u32,
    pub boot_image_size: u32,
    pub boot_image_component_count: u32,
    pub boot_image_checksum: u32,
    pub image_roots: u32,
    pub pointer_size: u32,
    pub sections: Vec<ArtImageSection>,
    pub image_methods: Vec<u64>,
    pub data_size: u32,
    pub blocks_offset: u32,
    pub blocks_count: u32,
    pub blocks: Vec<ArtBlock>,
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Parsing helpers
// ═══════════════════════════════════════════════════════════════════════════════════

/// Read a little-endian u32 from `data` at `offset`.
fn read_u32(data: &[u8], offset: usize) -> Result<u32, String> {
    if offset + 4 > data.len() {
        return Err(format!("ART header: read_u32 at {} beyond data length {}", offset, data.len()));
    }
    Ok(u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()))
}

/// Read a little-endian u64 from `data` at `offset`.
fn read_u64(data: &[u8], offset: usize) -> Result<u64, String> {
    if offset + 8 > data.len() {
        return Err(format!("ART header: read_u64 at {} beyond data length {}", offset, data.len()));
    }
    Ok(u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap()))
}

/// Read `count` image methods (u64 each) starting at `offset`.
fn read_image_methods(data: &[u8], offset: usize, count: usize) -> Result<Vec<u64>, String> {
    let mut methods = Vec::with_capacity(count);
    let mut pos = offset;
    for _ in 0..count {
        methods.push(read_u64(data, pos)?);
        pos += 8;
    }
    Ok(methods)
}

/// Read `count` `ArtImageSection` entries starting at `offset`.
fn read_sections(data: &[u8], offset: usize, count: usize) -> Result<Vec<ArtImageSection>, String> {
    let mut sections = Vec::with_capacity(count);
    let mut pos = offset;
    for _ in 0..count {
        sections.push(ArtImageSection::parse_at(data, pos)?);
        pos += ArtImageSection::SIZE;
    }
    Ok(sections)
}

/// Read `count` `ArtBlock` entries starting at `offset`.
fn read_blocks(data: &[u8], offset: usize, count: usize) -> Result<Vec<ArtBlock>, String> {
    let mut blocks = Vec::with_capacity(count);
    let mut pos = offset;
    for _ in 0..count {
        blocks.push(ArtBlock::parse_at(data, pos)?);
        pos += ArtBlock::SIZE;
    }
    Ok(blocks)
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════════════════════

/// Check if data starts with ART magic.
pub fn is_art(data: &[u8]) -> bool {
    data.len() >= 4 && &data[..4] == ART_MAGIC
}

/// Check if a version string is supported.
pub fn is_supported_version(version: &str) -> bool {
    SUPPORTED_VERSIONS.contains(&version)
}

/// Get the sections layout for a given ART version string.
pub fn sections_layout_for_version(version: &str) -> Option<ImageSectionsLayout> {
    match version {
        ART_VERSION_017 => Some(ImageSectionsLayout::marshmallow()),
        ART_VERSION_029 => Some(ImageSectionsLayout::nougat()),
        ART_VERSION_030 => Some(ImageSectionsLayout::nougat_mr2_pixel()),
        ART_VERSION_043 | ART_VERSION_044 => Some(ImageSectionsLayout::oreo()),
        ART_VERSION_046 => Some(ImageSectionsLayout::oreo_mr1()),
        ART_VERSION_056 => Some(ImageSectionsLayout::pie()),
        ART_VERSION_074 | ART_VERSION_085 => Some(ImageSectionsLayout::q_r()),
        ART_VERSION_099 | ART_VERSION_106 => Some(ImageSectionsLayout::s_t()),
        _ => None,
    }
}

/// Get the image method count for a given ART version string.
pub fn image_method_count_for_version(version: &str) -> Option<usize> {
    match version {
        ART_VERSION_017 => Some(IMAGE_METHODS_COUNT_MARSHMALLOW),
        ART_VERSION_029 | ART_VERSION_030 => Some(IMAGE_METHODS_COUNT_NOUGAT),
        ART_VERSION_043 | ART_VERSION_044 | ART_VERSION_046 => Some(IMAGE_METHODS_COUNT_NOUGAT),
        ART_VERSION_056 => Some(IMAGE_METHODS_COUNT_NOUGAT),
        ART_VERSION_074 | ART_VERSION_085 => Some(IMAGE_METHODS_COUNT_Q),
        ART_VERSION_099 | ART_VERSION_106 => Some(IMAGE_METHODS_COUNT_Q),
        _ => None,
    }
}

/// Parse an ART header from raw bytes.
///
/// Returns the version-specific header variant.  The parser reads the
/// magic and version, then dispatches to the correct layout.
pub fn parse_art_header(data: &[u8]) -> Result<ArtHeaderVersion, String> {
    if data.len() < 8 {
        return Err("Data too short for ART header (need at least 8 bytes)".to_string());
    }

    let magic: [u8; 4] = data[0..4].try_into().unwrap();
    if magic != *ART_MAGIC {
        return Err(format!("Invalid ART magic: {:?}", magic));
    }

    let version: [u8; 4] = data[4..8].try_into().unwrap();
    let version_str = std::str::from_utf8(&version)
        .map_err(|_| "ART version is not valid UTF-8")?
        .trim_matches('\0');

    match version_str {
        ART_VERSION_005 => parse_v005(data, magic, version).map(ArtHeaderVersion::V005),
        ART_VERSION_009 => parse_v009(data, magic, version).map(ArtHeaderVersion::V009),
        ART_VERSION_012 => parse_v012(data, magic, version).map(ArtHeaderVersion::V012),
        ART_VERSION_017 => parse_v017(data, magic, version).map(ArtHeaderVersion::V017),
        ART_VERSION_029 => parse_v029(data, magic, version).map(ArtHeaderVersion::V029),
        ART_VERSION_030 => parse_v030(data, magic, version).map(ArtHeaderVersion::V030),
        ART_VERSION_043 => parse_v043(data, magic, version).map(ArtHeaderVersion::V043),
        ART_VERSION_044 => parse_v044(data, magic, version).map(ArtHeaderVersion::V044),
        ART_VERSION_046 => parse_v046(data, magic, version).map(ArtHeaderVersion::V046),
        ART_VERSION_056 => parse_v056(data, magic, version).map(ArtHeaderVersion::V056),
        ART_VERSION_074 => parse_v074(data, magic, version).map(ArtHeaderVersion::V074),
        ART_VERSION_085 => parse_v085(data, magic, version).map(ArtHeaderVersion::V085),
        ART_VERSION_099 => parse_v099(data, magic, version).map(ArtHeaderVersion::V099),
        ART_VERSION_106 => parse_v106(data, magic, version).map(ArtHeaderVersion::V106),
        _ => Err(format!("Unsupported ART version: {:?}", version_str)),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Per-version parsers
// ═══════════════════════════════════════════════════════════════════════════════════

/// Header layout: magic(4) + version(4) + 10 x u32 = 48 bytes
const HEADER_V005_SIZE: usize = 48;

fn parse_v005(data: &[u8], magic: [u8; 4], version: [u8; 4]) -> Result<ArtHeaderV005, String> {
    if data.len() < HEADER_V005_SIZE {
        return Err("Data too short for ART v005 header".to_string());
    }
    Ok(ArtHeaderV005 {
        magic,
        version,
        image_begin: read_u32(data, 8)?,
        image_size: read_u32(data, 12)?,
        image_bitmap_offset: read_u32(data, 16)?,
        image_bitmap_size: read_u32(data, 20)?,
        oat_checksum: read_u32(data, 24)?,
        oat_file_begin: read_u32(data, 28)?,
        oat_data_begin: read_u32(data, 32)?,
        oat_data_end: read_u32(data, 36)?,
        oat_file_end: read_u32(data, 40)?,
        image_roots: read_u32(data, 44)?,
    })
}

fn parse_v009(data: &[u8], magic: [u8; 4], version: [u8; 4]) -> Result<ArtHeaderV009, String> {
    // Same layout as v005
    if data.len() < HEADER_V005_SIZE {
        return Err("Data too short for ART v009 header".to_string());
    }
    Ok(ArtHeaderV009 {
        magic,
        version,
        image_begin: read_u32(data, 8)?,
        image_size: read_u32(data, 12)?,
        image_bitmap_offset: read_u32(data, 16)?,
        image_bitmap_size: read_u32(data, 20)?,
        oat_checksum: read_u32(data, 24)?,
        oat_file_begin: read_u32(data, 28)?,
        oat_data_begin: read_u32(data, 32)?,
        oat_data_end: read_u32(data, 36)?,
        oat_file_end: read_u32(data, 40)?,
        image_roots: read_u32(data, 44)?,
    })
}

fn parse_v012(data: &[u8], magic: [u8; 4], version: [u8; 4]) -> Result<ArtHeaderV012, String> {
    // Same layout as v005
    if data.len() < HEADER_V005_SIZE {
        return Err("Data too short for ART v012 header".to_string());
    }
    Ok(ArtHeaderV012 {
        magic,
        version,
        image_begin: read_u32(data, 8)?,
        image_size: read_u32(data, 12)?,
        image_bitmap_offset: read_u32(data, 16)?,
        image_bitmap_size: read_u32(data, 20)?,
        oat_checksum: read_u32(data, 24)?,
        oat_file_begin: read_u32(data, 28)?,
        oat_data_begin: read_u32(data, 32)?,
        oat_data_end: read_u32(data, 36)?,
        oat_file_end: read_u32(data, 40)?,
        image_roots: read_u32(data, 44)?,
    })
}

fn parse_v017(data: &[u8], magic: [u8; 4], version: [u8; 4]) -> Result<ArtHeaderV017, String> {
    // Layout: magic(4) + version(4) + 11 x u32 + sections + image_methods
    // After the fixed header (8 + 44 = 52 bytes), sections and methods follow.
    let fixed_end = 8 + 11 * 4; // 52
    if data.len() < fixed_end {
        return Err("Data too short for ART v017 header".to_string());
    }

    let image_begin = read_u32(data, 8)?;
    let image_size = read_u32(data, 12)?;
    let oat_checksum = read_u32(data, 16)?;
    let oat_file_begin = read_u32(data, 20)?;
    let oat_data_begin = read_u32(data, 24)?;
    let oat_data_end = read_u32(data, 28)?;
    let oat_file_end = read_u32(data, 32)?;
    let patch_delta = read_u32(data, 36)?;
    let image_roots = read_u32(data, 40)?;
    let pointer_size = read_u32(data, 44)?;
    let compile_pic = read_u32(data, 48)?;

    let layout = ImageSectionsLayout::marshmallow();
    let sections = read_sections(data, fixed_end, layout.section_count)?;
    let methods_offset = fixed_end + layout.section_count * ArtImageSection::SIZE;
    let image_methods = read_image_methods(data, methods_offset, IMAGE_METHODS_COUNT_MARSHMALLOW)?;

    Ok(ArtHeaderV017 {
        magic,
        version,
        image_begin,
        image_size,
        oat_checksum,
        oat_file_begin,
        oat_data_begin,
        oat_data_end,
        oat_file_end,
        patch_delta,
        image_roots,
        pointer_size,
        compile_pic,
        sections,
        image_methods,
    })
}

fn parse_v029(data: &[u8], magic: [u8; 4], version: [u8; 4]) -> Result<ArtHeaderV029, String> {
    // Same fixed layout as v017 (11 x u32 after header), but different section layout
    let fixed_end = 8 + 11 * 4;
    if data.len() < fixed_end {
        return Err("Data too short for ART v029 header".to_string());
    }

    let image_begin = read_u32(data, 8)?;
    let image_size = read_u32(data, 12)?;
    let oat_checksum = read_u32(data, 16)?;
    let oat_file_begin = read_u32(data, 20)?;
    let oat_data_begin = read_u32(data, 24)?;
    let oat_data_end = read_u32(data, 28)?;
    let oat_file_end = read_u32(data, 32)?;
    let patch_delta = read_u32(data, 36)?;
    let image_roots = read_u32(data, 40)?;
    let pointer_size = read_u32(data, 44)?;
    let compile_pic = read_u32(data, 48)?;

    let layout = ImageSectionsLayout::nougat();
    let sections = read_sections(data, fixed_end, layout.section_count)?;
    let methods_offset = fixed_end + layout.section_count * ArtImageSection::SIZE;
    let image_methods = read_image_methods(data, methods_offset, IMAGE_METHODS_COUNT_NOUGAT)?;

    Ok(ArtHeaderV029 {
        magic,
        version,
        image_begin,
        image_size,
        oat_checksum,
        oat_file_begin,
        oat_data_begin,
        oat_data_end,
        oat_file_end,
        patch_delta,
        image_roots,
        pointer_size,
        compile_pic,
        sections,
        image_methods,
    })
}

fn parse_v030(data: &[u8], magic: [u8; 4], version: [u8; 4]) -> Result<ArtHeaderV030, String> {
    // Same fixed layout as v017, different section layout
    let fixed_end = 8 + 11 * 4;
    if data.len() < fixed_end {
        return Err("Data too short for ART v030 header".to_string());
    }

    let image_begin = read_u32(data, 8)?;
    let image_size = read_u32(data, 12)?;
    let oat_checksum = read_u32(data, 16)?;
    let oat_file_begin = read_u32(data, 20)?;
    let oat_data_begin = read_u32(data, 24)?;
    let oat_data_end = read_u32(data, 28)?;
    let oat_file_end = read_u32(data, 32)?;
    let patch_delta = read_u32(data, 36)?;
    let image_roots = read_u32(data, 40)?;
    let pointer_size = read_u32(data, 44)?;
    let compile_pic = read_u32(data, 48)?;

    let layout = ImageSectionsLayout::nougat_mr2_pixel();
    let sections = read_sections(data, fixed_end, layout.section_count)?;
    let methods_offset = fixed_end + layout.section_count * ArtImageSection::SIZE;
    let image_methods = read_image_methods(data, methods_offset, IMAGE_METHODS_COUNT_NOUGAT)?;

    Ok(ArtHeaderV030 {
        magic,
        version,
        image_begin,
        image_size,
        oat_checksum,
        oat_file_begin,
        oat_data_begin,
        oat_data_end,
        oat_file_end,
        patch_delta,
        image_roots,
        pointer_size,
        compile_pic,
        sections,
        image_methods,
    })
}

/// Common parsing for Oreo-era (043/044/046) headers.
///
/// Layout: magic(4) + version(4) + 15 x u32 fixed fields,
/// then sections, image_methods, data_size, blocks_offset, blocks_count,
/// then block array.
fn parse_oreo_common(
    data: &[u8],
    magic: [u8; 4],
    version: [u8; 4],
    layout: ImageSectionsLayout,
) -> Result<(ArtHeaderV043, Vec<ArtBlock>), String> {
    // 8 (magic+version) + 15 * 4 = 68
    let fixed_end = 8 + 15 * 4;
    if data.len() < fixed_end {
        return Err("Data too short for ART Oreo header".to_string());
    }

    let image_reservation_size = read_u32(data, 8)?;
    let component_count = read_u32(data, 12)?;
    let image_begin = read_u32(data, 16)?;
    let image_size = read_u32(data, 20)?;
    let image_checksum = read_u32(data, 24)?;
    let oat_checksum = read_u32(data, 28)?;
    let oat_file_begin = read_u32(data, 32)?;
    let oat_data_begin = read_u32(data, 36)?;
    let oat_data_end = read_u32(data, 40)?;
    let oat_file_end = read_u32(data, 44)?;
    let boot_image_begin = read_u32(data, 48)?;
    let boot_image_size = read_u32(data, 52)?;
    let image_roots = read_u32(data, 56)?;
    let pointer_size = read_u32(data, 60)?;

    // After fixed header: sections, image_methods, then 3 u32 fields
    let sections_offset = fixed_end;
    let sections = read_sections(data, sections_offset, layout.section_count)?;

    let methods_offset = sections_offset + layout.section_count * ArtImageSection::SIZE;
    let image_methods = read_image_methods(data, methods_offset, IMAGE_METHODS_COUNT_NOUGAT)?;

    let trailing_offset = methods_offset + IMAGE_METHODS_COUNT_NOUGAT * 8;
    let data_size = read_u32(data, trailing_offset)?;
    let blocks_offset_val = read_u32(data, trailing_offset + 4)?;
    let blocks_count = read_u32(data, trailing_offset + 8)?;

    let blocks = if blocks_offset_val > 0 && blocks_count > 0 {
        read_blocks(data, blocks_offset_val as usize, blocks_count as usize)?
    } else {
        Vec::new()
    };

    Ok((
        ArtHeaderV043 {
            magic,
            version,
            image_reservation_size,
            component_count,
            image_begin,
            image_size,
            image_checksum,
            oat_checksum,
            oat_file_begin,
            oat_data_begin,
            oat_data_end,
            oat_file_end,
            boot_image_begin,
            boot_image_size,
            image_roots,
            pointer_size,
            sections,
            image_methods,
            data_size,
            blocks_offset: blocks_offset_val,
            blocks_count,
            blocks,
        },
        Vec::new(), // unused second element
    ))
}

fn parse_v043(data: &[u8], magic: [u8; 4], version: [u8; 4]) -> Result<ArtHeaderV043, String> {
    let (h, _) = parse_oreo_common(data, magic, version, ImageSectionsLayout::oreo())?;
    Ok(h)
}

fn parse_v044(data: &[u8], magic: [u8; 4], version: [u8; 4]) -> Result<ArtHeaderV044, String> {
    let (h, _) = parse_oreo_common(data, magic, version, ImageSectionsLayout::oreo())?;
    Ok(ArtHeaderV044 {
        magic: h.magic,
        version: h.version,
        image_reservation_size: h.image_reservation_size,
        component_count: h.component_count,
        image_begin: h.image_begin,
        image_size: h.image_size,
        image_checksum: h.image_checksum,
        oat_checksum: h.oat_checksum,
        oat_file_begin: h.oat_file_begin,
        oat_data_begin: h.oat_data_begin,
        oat_data_end: h.oat_data_end,
        oat_file_end: h.oat_file_end,
        boot_image_begin: h.boot_image_begin,
        boot_image_size: h.boot_image_size,
        image_roots: h.image_roots,
        pointer_size: h.pointer_size,
        sections: h.sections,
        image_methods: h.image_methods,
        data_size: h.data_size,
        blocks_offset: h.blocks_offset,
        blocks_count: h.blocks_count,
        blocks: h.blocks,
    })
}

fn parse_v046(data: &[u8], magic: [u8; 4], version: [u8; 4]) -> Result<ArtHeaderV046, String> {
    let (h, _) = parse_oreo_common(data, magic, version, ImageSectionsLayout::oreo_mr1())?;
    Ok(ArtHeaderV046 {
        magic: h.magic,
        version: h.version,
        image_reservation_size: h.image_reservation_size,
        component_count: h.component_count,
        image_begin: h.image_begin,
        image_size: h.image_size,
        image_checksum: h.image_checksum,
        oat_checksum: h.oat_checksum,
        oat_file_begin: h.oat_file_begin,
        oat_data_begin: h.oat_data_begin,
        oat_data_end: h.oat_data_end,
        oat_file_end: h.oat_file_end,
        boot_image_begin: h.boot_image_begin,
        boot_image_size: h.boot_image_size,
        image_roots: h.image_roots,
        pointer_size: h.pointer_size,
        sections: h.sections,
        image_methods: h.image_methods,
        data_size: h.data_size,
        blocks_offset: h.blocks_offset,
        blocks_count: h.blocks_count,
        blocks: h.blocks,
    })
}

fn parse_v056(data: &[u8], magic: [u8; 4], version: [u8; 4]) -> Result<ArtHeaderV056, String> {
    let (h, _) = parse_oreo_common(data, magic, version, ImageSectionsLayout::pie())?;
    Ok(ArtHeaderV056 {
        magic: h.magic,
        version: h.version,
        image_reservation_size: h.image_reservation_size,
        component_count: h.component_count,
        image_begin: h.image_begin,
        image_size: h.image_size,
        image_checksum: h.image_checksum,
        oat_checksum: h.oat_checksum,
        oat_file_begin: h.oat_file_begin,
        oat_data_begin: h.oat_data_begin,
        oat_data_end: h.oat_data_end,
        oat_file_end: h.oat_file_end,
        boot_image_begin: h.boot_image_begin,
        boot_image_size: h.boot_image_size,
        image_roots: h.image_roots,
        pointer_size: h.pointer_size,
        sections: h.sections,
        image_methods: h.image_methods,
        data_size: h.data_size,
        blocks_offset: h.blocks_offset,
        blocks_count: h.blocks_count,
        blocks: h.blocks,
    })
}

fn parse_v074(data: &[u8], magic: [u8; 4], version: [u8; 4]) -> Result<ArtHeaderV074, String> {
    let (h, _) = parse_oreo_common(data, magic, version, ImageSectionsLayout::q_r())?;
    Ok(ArtHeaderV074 {
        magic: h.magic,
        version: h.version,
        image_reservation_size: h.image_reservation_size,
        component_count: h.component_count,
        image_begin: h.image_begin,
        image_size: h.image_size,
        image_checksum: h.image_checksum,
        oat_checksum: h.oat_checksum,
        oat_file_begin: h.oat_file_begin,
        oat_data_begin: h.oat_data_begin,
        oat_data_end: h.oat_data_end,
        oat_file_end: h.oat_file_end,
        boot_image_begin: h.boot_image_begin,
        boot_image_size: h.boot_image_size,
        image_roots: h.image_roots,
        pointer_size: h.pointer_size,
        sections: h.sections,
        image_methods: h.image_methods,
        data_size: h.data_size,
        blocks_offset: h.blocks_offset,
        blocks_count: h.blocks_count,
        blocks: h.blocks,
    })
}

/// R header (version 085) has 2 extra u32 fields compared to Q: boot_image_component_count, boot_image_checksum.
fn parse_v085(data: &[u8], magic: [u8; 4], version: [u8; 4]) -> Result<ArtHeaderV085, String> {
    // 8 + 17 * 4 = 76
    let fixed_end = 8 + 17 * 4;
    if data.len() < fixed_end {
        return Err("Data too short for ART v085 header".to_string());
    }

    let image_reservation_size = read_u32(data, 8)?;
    let component_count = read_u32(data, 12)?;
    let image_begin = read_u32(data, 16)?;
    let image_size = read_u32(data, 20)?;
    let image_checksum = read_u32(data, 24)?;
    let oat_checksum = read_u32(data, 28)?;
    let oat_file_begin = read_u32(data, 32)?;
    let oat_data_begin = read_u32(data, 36)?;
    let oat_data_end = read_u32(data, 40)?;
    let oat_file_end = read_u32(data, 44)?;
    let boot_image_begin = read_u32(data, 48)?;
    let boot_image_size = read_u32(data, 52)?;
    let boot_image_component_count = read_u32(data, 56)?;
    let boot_image_checksum = read_u32(data, 60)?;
    let image_roots = read_u32(data, 64)?;
    let pointer_size = read_u32(data, 68)?;

    let layout = ImageSectionsLayout::q_r();
    let sections = read_sections(data, fixed_end, layout.section_count)?;

    let methods_offset = fixed_end + layout.section_count * ArtImageSection::SIZE;
    let image_methods = read_image_methods(data, methods_offset, IMAGE_METHODS_COUNT_Q)?;

    let trailing_offset = methods_offset + IMAGE_METHODS_COUNT_Q * 8;
    let data_size = read_u32(data, trailing_offset)?;
    let blocks_offset_val = read_u32(data, trailing_offset + 4)?;
    let blocks_count = read_u32(data, trailing_offset + 8)?;

    let blocks = if blocks_offset_val > 0 && blocks_count > 0 {
        read_blocks(data, blocks_offset_val as usize, blocks_count as usize)?
    } else {
        Vec::new()
    };

    Ok(ArtHeaderV085 {
        magic,
        version,
        image_reservation_size,
        component_count,
        image_begin,
        image_size,
        image_checksum,
        oat_checksum,
        oat_file_begin,
        oat_data_begin,
        oat_data_end,
        oat_file_end,
        boot_image_begin,
        boot_image_size,
        boot_image_component_count,
        boot_image_checksum,
        image_roots,
        pointer_size,
        sections,
        image_methods,
        data_size,
        blocks_offset: blocks_offset_val,
        blocks_count,
        blocks,
    })
}

/// Common parsing for S/T-era (099/106) headers.
///
/// Same layout as v085 but with the S/T section layout.
fn parse_s_t_common(
    data: &[u8],
    magic: [u8; 4],
    version: [u8; 4],
) -> Result<ArtHeaderV099, String> {
    let fixed_end = 8 + 17 * 4;
    if data.len() < fixed_end {
        return Err("Data too short for ART S/T header".to_string());
    }

    let image_reservation_size = read_u32(data, 8)?;
    let component_count = read_u32(data, 12)?;
    let image_begin = read_u32(data, 16)?;
    let image_size = read_u32(data, 20)?;
    let image_checksum = read_u32(data, 24)?;
    let oat_checksum = read_u32(data, 28)?;
    let oat_file_begin = read_u32(data, 32)?;
    let oat_data_begin = read_u32(data, 36)?;
    let oat_data_end = read_u32(data, 40)?;
    let oat_file_end = read_u32(data, 44)?;
    let boot_image_begin = read_u32(data, 48)?;
    let boot_image_size = read_u32(data, 52)?;
    let boot_image_component_count = read_u32(data, 56)?;
    let boot_image_checksum = read_u32(data, 60)?;
    let image_roots = read_u32(data, 64)?;
    let pointer_size = read_u32(data, 68)?;

    let layout = ImageSectionsLayout::s_t();
    let sections = read_sections(data, fixed_end, layout.section_count)?;

    let methods_offset = fixed_end + layout.section_count * ArtImageSection::SIZE;
    let image_methods = read_image_methods(data, methods_offset, IMAGE_METHODS_COUNT_Q)?;

    let trailing_offset = methods_offset + IMAGE_METHODS_COUNT_Q * 8;
    let data_size = read_u32(data, trailing_offset)?;
    let blocks_offset_val = read_u32(data, trailing_offset + 4)?;
    let blocks_count = read_u32(data, trailing_offset + 8)?;

    let blocks = if blocks_offset_val > 0 && blocks_count > 0 {
        read_blocks(data, blocks_offset_val as usize, blocks_count as usize)?
    } else {
        Vec::new()
    };

    Ok(ArtHeaderV099 {
        magic,
        version,
        image_reservation_size,
        component_count,
        image_begin,
        image_size,
        image_checksum,
        oat_checksum,
        oat_file_begin,
        oat_data_begin,
        oat_data_end,
        oat_file_end,
        boot_image_begin,
        boot_image_size,
        boot_image_component_count,
        boot_image_checksum,
        image_roots,
        pointer_size,
        sections,
        image_methods,
        data_size,
        blocks_offset: blocks_offset_val,
        blocks_count,
        blocks,
    })
}

fn parse_v099(data: &[u8], magic: [u8; 4], version: [u8; 4]) -> Result<ArtHeaderV099, String> {
    parse_s_t_common(data, magic, version)
}

fn parse_v106(data: &[u8], magic: [u8; 4], version: [u8; 4]) -> Result<ArtHeaderV106, String> {
    let h = parse_s_t_common(data, magic, version)?;
    Ok(ArtHeaderV106 {
        magic: h.magic,
        version: h.version,
        image_reservation_size: h.image_reservation_size,
        component_count: h.component_count,
        image_begin: h.image_begin,
        image_size: h.image_size,
        image_checksum: h.image_checksum,
        oat_checksum: h.oat_checksum,
        oat_file_begin: h.oat_file_begin,
        oat_data_begin: h.oat_data_begin,
        oat_data_end: h.oat_data_end,
        oat_file_end: h.oat_file_end,
        boot_image_begin: h.boot_image_begin,
        boot_image_size: h.boot_image_size,
        boot_image_component_count: h.boot_image_component_count,
        boot_image_checksum: h.boot_image_checksum,
        image_roots: h.image_roots,
        pointer_size: h.pointer_size,
        sections: h.sections,
        image_methods: h.image_methods,
        data_size: h.data_size,
        blocks_offset: h.blocks_offset,
        blocks_count: h.blocks_count,
        blocks: h.blocks,
    })
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Accessor helpers on ArtHeaderVersion
// ═══════════════════════════════════════════════════════════════════════════════════

impl ArtHeaderVersion {
    /// Returns the version string (e.g. "074").
    pub fn version_string(&self) -> String {
        let v = match self {
            Self::V005(h) => &h.version,
            Self::V009(h) => &h.version,
            Self::V012(h) => &h.version,
            Self::V017(h) => &h.version,
            Self::V029(h) => &h.version,
            Self::V030(h) => &h.version,
            Self::V043(h) => &h.version,
            Self::V044(h) => &h.version,
            Self::V046(h) => &h.version,
            Self::V056(h) => &h.version,
            Self::V074(h) => &h.version,
            Self::V085(h) => &h.version,
            Self::V099(h) => &h.version,
            Self::V106(h) => &h.version,
        };
        String::from_utf8_lossy(v).trim_matches('\0').to_string()
    }

    /// Returns `image_begin` (the base address of the image).
    pub fn image_begin(&self) -> u32 {
        match self {
            Self::V005(h) => h.image_begin,
            Self::V009(h) => h.image_begin,
            Self::V012(h) => h.image_begin,
            Self::V017(h) => h.image_begin,
            Self::V029(h) => h.image_begin,
            Self::V030(h) => h.image_begin,
            Self::V043(h) => h.image_begin,
            Self::V044(h) => h.image_begin,
            Self::V046(h) => h.image_begin,
            Self::V056(h) => h.image_begin,
            Self::V074(h) => h.image_begin,
            Self::V085(h) => h.image_begin,
            Self::V099(h) => h.image_begin,
            Self::V106(h) => h.image_begin,
        }
    }

    /// Returns `image_size`.
    pub fn image_size(&self) -> u32 {
        match self {
            Self::V005(h) => h.image_size,
            Self::V009(h) => h.image_size,
            Self::V012(h) => h.image_size,
            Self::V017(h) => h.image_size,
            Self::V029(h) => h.image_size,
            Self::V030(h) => h.image_size,
            Self::V043(h) => h.image_size,
            Self::V044(h) => h.image_size,
            Self::V046(h) => h.image_size,
            Self::V056(h) => h.image_size,
            Self::V074(h) => h.image_size,
            Self::V085(h) => h.image_size,
            Self::V099(h) => h.image_size,
            Self::V106(h) => h.image_size,
        }
    }

    /// Returns `oat_checksum`.  Returns -1 (u32::MAX) if unsupported.
    pub fn oat_checksum(&self) -> u32 {
        match self {
            Self::V005(h) => h.oat_checksum,
            Self::V009(h) => h.oat_checksum,
            Self::V012(h) => h.oat_checksum,
            Self::V017(h) => h.oat_checksum,
            Self::V029(h) => h.oat_checksum,
            Self::V030(h) => h.oat_checksum,
            Self::V043(h) => h.oat_checksum,
            Self::V044(h) => h.oat_checksum,
            Self::V046(h) => h.oat_checksum,
            Self::V056(h) => h.oat_checksum,
            Self::V074(h) => h.oat_checksum,
            Self::V085(h) => h.oat_checksum,
            Self::V099(h) => h.oat_checksum,
            Self::V106(h) => h.oat_checksum,
        }
    }

    /// Returns `oat_data_begin`.
    pub fn oat_data_begin(&self) -> u32 {
        match self {
            Self::V005(h) => h.oat_data_begin,
            Self::V009(h) => h.oat_data_begin,
            Self::V012(h) => h.oat_data_begin,
            Self::V017(h) => h.oat_data_begin,
            Self::V029(h) => h.oat_data_begin,
            Self::V030(h) => h.oat_data_begin,
            Self::V043(h) => h.oat_data_begin,
            Self::V044(h) => h.oat_data_begin,
            Self::V046(h) => h.oat_data_begin,
            Self::V056(h) => h.oat_data_begin,
            Self::V074(h) => h.oat_data_begin,
            Self::V085(h) => h.oat_data_begin,
            Self::V099(h) => h.oat_data_begin,
            Self::V106(h) => h.oat_data_begin,
        }
    }

    /// Returns `pointer_size`.  Returns 0 for versions that don't have it.
    pub fn pointer_size(&self) -> u32 {
        match self {
            Self::V005(_) | Self::V009(_) | Self::V012(_) => 0,
            Self::V017(h) => h.pointer_size,
            Self::V029(h) => h.pointer_size,
            Self::V030(h) => h.pointer_size,
            Self::V043(h) => h.pointer_size,
            Self::V044(h) => h.pointer_size,
            Self::V046(h) => h.pointer_size,
            Self::V056(h) => h.pointer_size,
            Self::V074(h) => h.pointer_size,
            Self::V085(h) => h.pointer_size,
            Self::V099(h) => h.pointer_size,
            Self::V106(h) => h.pointer_size,
        }
    }

    /// Returns the sections list (empty for versions 005/009/012).
    pub fn sections(&self) -> &[ArtImageSection] {
        match self {
            Self::V005(_) | Self::V009(_) | Self::V012(_) => &[],
            Self::V017(h) => &h.sections,
            Self::V029(h) => &h.sections,
            Self::V030(h) => &h.sections,
            Self::V043(h) => &h.sections,
            Self::V044(h) => &h.sections,
            Self::V046(h) => &h.sections,
            Self::V056(h) => &h.sections,
            Self::V074(h) => &h.sections,
            Self::V085(h) => &h.sections,
            Self::V099(h) => &h.sections,
            Self::V106(h) => &h.sections,
        }
    }

    /// Returns the blocks list (empty for pre-Oreo versions).
    pub fn blocks(&self) -> &[ArtBlock] {
        match self {
            Self::V043(h) => &h.blocks,
            Self::V044(h) => &h.blocks,
            Self::V046(h) => &h.blocks,
            Self::V056(h) => &h.blocks,
            Self::V074(h) => &h.blocks,
            Self::V085(h) => &h.blocks,
            Self::V099(h) => &h.blocks,
            Self::V106(h) => &h.blocks,
            _ => &[],
        }
    }

    /// Returns true if this represents an app image (boot_image_size != 0).
    pub fn is_app_image(&self) -> bool {
        match self {
            Self::V043(h) => h.boot_image_size != 0,
            Self::V044(h) => h.boot_image_size != 0,
            Self::V046(h) => h.boot_image_size != 0,
            Self::V056(h) => h.boot_image_size != 0,
            Self::V074(h) => h.boot_image_size != 0,
            Self::V085(h) => h.boot_image_size != 0,
            Self::V099(h) => h.boot_image_size != 0,
            Self::V106(h) => h.boot_image_size != 0,
            _ => false,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_art() {
        assert!(is_art(b"art\n"));
        assert!(!is_art(b"nope"));
    }

    #[test]
    fn test_is_supported_version() {
        assert!(is_supported_version("005"));
        assert!(is_supported_version("106"));
        assert!(!is_supported_version("999"));
    }

    #[test]
    fn test_sections_layout_marshmallow() {
        let layout = ImageSectionsLayout::marshmallow();
        assert_eq!(layout.section_count, 5);
        assert_eq!(layout.objects, 0);
        assert_eq!(layout.art_fields, Some(1));
        assert_eq!(layout.art_methods, Some(2));
        assert_eq!(layout.interned_strings, Some(3));
        assert_eq!(layout.image_bitmap, Some(4));
        assert_eq!(layout.runtime_methods, None);
    }

    #[test]
    fn test_sections_layout_s_t() {
        let layout = ImageSectionsLayout::s_t();
        assert_eq!(layout.section_count, 11);
        assert_eq!(layout.dex_cache_arrays, None); // removed in S
        assert_eq!(layout.art_fields, Some(1));
        assert_eq!(layout.image_bitmap, Some(10));
    }

    #[test]
    fn test_parse_v005() {
        // Build a minimal v005 header: 8 bytes magic+version + 10 * 4 = 48 bytes
        let mut data = vec![0u8; HEADER_V005_SIZE];
        data[0..4].copy_from_slice(b"art\n");
        data[4..8].copy_from_slice(b"005\0");
        data[8..12].copy_from_slice(&0x1000u32.to_le_bytes()); // image_begin
        data[12..16].copy_from_slice(&0x2000u32.to_le_bytes()); // image_size

        let header = parse_art_header(&data).unwrap();
        assert_eq!(header.version_string(), "005");
        assert_eq!(header.image_begin(), 0x1000);
        assert_eq!(header.image_size(), 0x2000);
    }

    #[test]
    fn test_parse_v017() {
        let layout = ImageSectionsLayout::marshmallow();
        let sections_size = layout.section_count * ArtImageSection::SIZE;
        let methods_size = IMAGE_METHODS_COUNT_MARSHMALLOW * 8;
        let total = 8 + 11 * 4 + sections_size + methods_size;
        let mut data = vec![0u8; total];
        data[0..4].copy_from_slice(b"art\n");
        data[4..8].copy_from_slice(b"017\0");
        // image_begin at offset 8
        data[8..12].copy_from_slice(&0x4000u32.to_le_bytes());
        // pointer_size at offset 44
        data[44..48].copy_from_slice(&4u32.to_le_bytes());

        let header = parse_art_header(&data).unwrap();
        assert_eq!(header.version_string(), "017");
        assert_eq!(header.image_begin(), 0x4000);
        assert_eq!(header.pointer_size(), 4);
        assert_eq!(header.sections().len(), layout.section_count);
    }

    #[test]
    fn test_parse_invalid_magic() {
        let mut data = vec![0u8; 48];
        data[0..4].copy_from_slice(b"bad\n");
        assert!(parse_art_header(&data).is_err());
    }

    #[test]
    fn test_parse_unsupported_version() {
        let mut data = vec![0u8; 48];
        data[0..4].copy_from_slice(b"art\n");
        data[4..8].copy_from_slice(b"999\0");
        assert!(parse_art_header(&data).is_err());
    }

    #[test]
    fn test_parse_too_short() {
        assert!(parse_art_header(&[0u8; 4]).is_err());
    }

    #[test]
    fn test_image_method_counts() {
        assert_eq!(image_method_count_for_version("017"), Some(IMAGE_METHODS_COUNT_MARSHMALLOW));
        assert_eq!(image_method_count_for_version("074"), Some(IMAGE_METHODS_COUNT_Q));
        assert_eq!(image_method_count_for_version("106"), Some(IMAGE_METHODS_COUNT_Q));
        assert_eq!(image_method_count_for_version("999"), None);
    }

    #[test]
    fn test_image_method_q_count() {
        assert_eq!(ImageMethodQ::COUNT, 9);
    }
}
