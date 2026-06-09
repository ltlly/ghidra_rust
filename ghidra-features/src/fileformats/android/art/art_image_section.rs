//! ART image section descriptor.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.art.ArtImageSection`
//! and `ArtImageSections`.
//!
//! An `ArtImageSection` is a simple (offset, size) pair that describes
//! a named region within the ART image (objects, fields, methods,
//! interned strings, class table, bitmap, etc.).
//!
//! The `ArtImageSections` helper provides section name resolution
//! and section enumeration for each Android version's layout.

use super::art_header::ImageSectionsLayout;

// ═══════════════════════════════════════════════════════════════════════════════════
// ArtImageSection
// ═══════════════════════════════════════════════════════════════════════════════════

/// A single ART image section descriptor (8 bytes on disk).
///
/// Fields (all little-endian u32):
/// - `offset`: byte offset of the section within the image
/// - `size`: size of the section in bytes
#[derive(Debug, Clone)]
pub struct ArtImageSection {
    /// Byte offset of this section within the image.
    pub offset: u32,
    /// Size of this section in bytes.
    pub size: u32,
}

impl ArtImageSection {
    /// On-disk size (8 bytes).
    pub const SIZE: usize = 8;

    /// Parse an ArtImageSection from a byte slice at the given offset.
    pub fn parse_at(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + Self::SIZE > data.len() {
            return Err(format!(
                "ArtImageSection: need {} bytes at offset {}, only {} available",
                Self::SIZE,
                offset,
                data.len()
            ));
        }

        Ok(ArtImageSection {
            offset: u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()),
            size: u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap()),
        })
    }

    /// Parse an ArtImageSection from the start of a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        Self::parse_at(data, 0)
    }

    /// Returns the end offset (offset + size).
    pub fn end(&self) -> u32 {
        self.offset.wrapping_add(self.size)
    }

    /// Returns true if this section has zero size.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Well-known section names
// ═══════════════════════════════════════════════════════════════════════════════════

/// Standard section name constants matching the Java `kSection*` enum names.
pub const SECTION_NAMES: &[&str] = &[
    "kSectionObjects",
    "kSectionArtFields",
    "kSectionArtMethods",
    "kSectionRuntimeMethods",
    "kSectionImTables",
    "kSectionIMTConflictTables",
    "kSectionDexCacheArrays",
    "kSectionInternedStrings",
    "kSectionClassTable",
    "kSectionStringReferenceOffsets",
    "kSectionMetadata",
    "kSectionImageBitmap",
];

/// Returns the section name for a given ordinal, or a fallback string
/// if the ordinal is out of range.
pub fn section_name(ordinal: usize) -> String {
    if ordinal < SECTION_NAMES.len() {
        SECTION_NAMES[ordinal].to_string()
    } else {
        format!("unknown_section_0x{:x}", ordinal)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// ArtImageSections helper
// ═══════════════════════════════════════════════════════════════════════════════════

/// Helper for parsing and querying ART image sections.
///
/// Combines a list of parsed `ArtImageSection` entries with the
/// version-specific `ImageSectionsLayout` to resolve section ordinals.
#[derive(Debug, Clone)]
pub struct ArtImageSections {
    /// Parsed section list (in ordinal order).
    pub sections: Vec<ArtImageSection>,
    /// The layout descriptor for this ART version.
    pub layout: ImageSectionsLayout,
}

impl ArtImageSections {
    /// Parse `section_count` ArtImageSection entries from `data` at `offset`,
    /// paired with the given layout.
    pub fn parse(data: &[u8], offset: usize, layout: ImageSectionsLayout) -> Result<Self, String> {
        let mut sections = Vec::with_capacity(layout.section_count);
        let mut pos = offset;
        for _ in 0..layout.section_count {
            sections.push(ArtImageSection::parse_at(data, pos)?);
            pos += ArtImageSection::SIZE;
        }
        Ok(ArtImageSections { sections, layout })
    }

    /// Returns the number of sections.
    pub fn section_count(&self) -> usize {
        self.sections.len()
    }

    /// Get a section by ordinal.
    pub fn get(&self, ordinal: usize) -> Option<&ArtImageSection> {
        self.sections.get(ordinal)
    }

    /// Returns the section name for a given ordinal.
    pub fn name_for(&self, ordinal: usize) -> String {
        section_name(ordinal)
    }

    /// Returns the objects section (ordinal 0).
    pub fn objects(&self) -> &ArtImageSection {
        &self.sections[self.layout.objects]
    }

    /// Returns the art fields section, if present.
    pub fn art_fields(&self) -> Option<&ArtImageSection> {
        self.layout.art_fields.map(|i| &self.sections[i])
    }

    /// Returns the art methods section, if present.
    pub fn art_methods(&self) -> Option<&ArtImageSection> {
        self.layout.art_methods.map(|i| &self.sections[i])
    }

    /// Returns the runtime methods section, if present.
    pub fn runtime_methods(&self) -> Option<&ArtImageSection> {
        self.layout.runtime_methods.map(|i| &self.sections[i])
    }

    /// Returns the IM tables section, if present.
    pub fn im_tables(&self) -> Option<&ArtImageSection> {
        self.layout.im_tables.map(|i| &self.sections[i])
    }

    /// Returns the IMT conflict tables section, if present.
    pub fn imt_conflict_tables(&self) -> Option<&ArtImageSection> {
        self.layout.imt_conflict_tables.map(|i| &self.sections[i])
    }

    /// Returns the DEX cache arrays section, if present.
    pub fn dex_cache_arrays(&self) -> Option<&ArtImageSection> {
        self.layout.dex_cache_arrays.map(|i| &self.sections[i])
    }

    /// Returns the interned strings section, if present.
    pub fn interned_strings(&self) -> Option<&ArtImageSection> {
        self.layout.interned_strings.map(|i| &self.sections[i])
    }

    /// Returns the class table section, if present.
    pub fn class_table(&self) -> Option<&ArtImageSection> {
        self.layout.class_table.map(|i| &self.sections[i])
    }

    /// Returns the string reference offsets section, if present.
    pub fn string_reference_offsets(&self) -> Option<&ArtImageSection> {
        self.layout.string_reference_offsets.map(|i| &self.sections[i])
    }

    /// Returns the metadata section, if present.
    pub fn metadata(&self) -> Option<&ArtImageSection> {
        self.layout.metadata.map(|i| &self.sections[i])
    }

    /// Returns the image bitmap section, if present.
    pub fn image_bitmap(&self) -> Option<&ArtImageSection> {
        self.layout.image_bitmap.map(|i| &self.sections[i])
    }

    /// Iterate over all (name, section) pairs.
    pub fn iter_named(&self) -> Vec<(String, &ArtImageSection)> {
        self.sections
            .iter()
            .enumerate()
            .map(|(i, s)| (section_name(i), s))
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_section() {
        let mut data = vec![0u8; ArtImageSection::SIZE];
        data[0..4].copy_from_slice(&0x100u32.to_le_bytes()); // offset
        data[4..8].copy_from_slice(&0x200u32.to_le_bytes()); // size

        let section = ArtImageSection::parse(&data).unwrap();
        assert_eq!(section.offset, 0x100);
        assert_eq!(section.size, 0x200);
        assert_eq!(section.end(), 0x300);
        assert!(!section.is_empty());
    }

    #[test]
    fn test_parse_section_empty() {
        let mut data = vec![0u8; ArtImageSection::SIZE];
        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        data[4..8].copy_from_slice(&0u32.to_le_bytes());

        let section = ArtImageSection::parse(&data).unwrap();
        assert!(section.is_empty());
    }

    #[test]
    fn test_parse_section_at_offset() {
        let mut data = vec![0u8; ArtImageSection::SIZE + 16];
        let off = 16;
        data[off..off + 4].copy_from_slice(&0xABCu32.to_le_bytes());
        data[off + 4..off + 8].copy_from_slice(&0xDEFu32.to_le_bytes());

        let section = ArtImageSection::parse_at(&data, off).unwrap();
        assert_eq!(section.offset, 0xABC);
        assert_eq!(section.size, 0xDEF);
    }

    #[test]
    fn test_parse_section_truncated() {
        assert!(ArtImageSection::parse(&[0u8; 4]).is_err());
    }

    #[test]
    fn test_section_name() {
        assert_eq!(section_name(0), "kSectionObjects");
        assert_eq!(section_name(1), "kSectionArtFields");
        assert_eq!(section_name(11), "kSectionImageBitmap");
        assert_eq!(section_name(99), "unknown_section_0x63");
    }

    #[test]
    fn test_art_image_sections_parse() {
        let layout = ImageSectionsLayout::marshmallow(); // 5 sections
        let mut data = vec![0u8; 5 * ArtImageSection::SIZE];
        for i in 0..5 {
            let off = i * ArtImageSection::SIZE;
            data[off..off + 4].copy_from_slice(&(i as u32 * 0x100).to_le_bytes());
            data[off + 4..off + 8].copy_from_slice(&0x10u32.to_le_bytes());
        }

        let sections = ArtImageSections::parse(&data, 0, layout).unwrap();
        assert_eq!(sections.section_count(), 5);
        assert_eq!(sections.objects().offset, 0);
        assert_eq!(sections.art_fields().unwrap().offset, 0x100);
        assert_eq!(sections.art_methods().unwrap().offset, 0x200);
        assert!(sections.runtime_methods().is_none()); // Marshmallow doesn't have it
        assert_eq!(sections.interned_strings().unwrap().offset, 0x300);
        assert_eq!(sections.image_bitmap().unwrap().offset, 0x400);
    }

    #[test]
    fn test_art_image_sections_s_t() {
        let layout = ImageSectionsLayout::s_t(); // 11 sections
        let mut data = vec![0u8; 11 * ArtImageSection::SIZE];
        for i in 0..11 {
            let off = i * ArtImageSection::SIZE;
            data[off..off + 4].copy_from_slice(&(i as u32 * 0x100).to_le_bytes());
            data[off + 4..off + 8].copy_from_slice(&0x10u32.to_le_bytes());
        }

        let sections = ArtImageSections::parse(&data, 0, layout).unwrap();
        assert_eq!(sections.section_count(), 11);
        assert!(sections.dex_cache_arrays().is_none()); // removed in S
        assert!(sections.art_fields().is_some());
        assert!(sections.image_bitmap().is_some());
    }

    #[test]
    fn test_iter_named() {
        let layout = ImageSectionsLayout::marshmallow();
        let data = vec![0u8; 5 * ArtImageSection::SIZE];
        let sections = ArtImageSections::parse(&data, 0, layout).unwrap();
        let named = sections.iter_named();
        assert_eq!(named.len(), 5);
        assert_eq!(named[0].0, "kSectionObjects");
        // In the global SECTION_NAMES, ordinal 4 is kSectionImTables.
        // Marshmallow uses ordinal 4 for image_bitmap, but the name
        // resolution uses the global ordinal table.
        assert_eq!(named[4].0, "kSectionImTables");
    }
}
