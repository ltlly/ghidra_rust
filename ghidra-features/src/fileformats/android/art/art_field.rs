//! ART field and field group structures.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.art.ArtField`
//! and `ArtFieldGroup`.
//!
//! An `ArtField` represents a single field (instance or static) in the
//! ART image.  An `ArtFieldGroup` wraps a count-prefixed array of fields
//! (used in versions after Marshmallow).

// ═══════════════════════════════════════════════════════════════════════════════════
// ArtField
// ═══════════════════════════════════════════════════════════════════════════════════

/// A single ART field entry (16 bytes on disk).
///
/// Fields (all little-endian):
/// - `declaring_class`: u32 -- pointer to the declaring class
/// - `access_flags`: u32 -- access flags (ACC_PUBLIC, ACC_STATIC, etc.)
/// - `field_dex_idx`: u32 -- index into the DEX field IDs table
/// - `offset`: u32 -- byte offset of the field within its object
#[derive(Debug, Clone)]
pub struct ArtField {
    /// Pointer to the declaring class.
    pub declaring_class: u32,
    /// Access flags.
    pub access_flags: u32,
    /// Index into the DEX field IDs table.
    pub field_dex_idx: u32,
    /// Byte offset of this field within its object.
    pub offset: u32,
}

impl ArtField {
    /// On-disk size (16 bytes).
    pub const SIZE: usize = 16;

    /// Parse an ArtField from a byte slice at the given offset.
    pub fn parse_at(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + Self::SIZE > data.len() {
            return Err(format!(
                "ArtField: need {} bytes at offset {}, only {} available",
                Self::SIZE,
                offset,
                data.len()
            ));
        }

        Ok(ArtField {
            declaring_class: u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()),
            access_flags: u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap()),
            field_dex_idx: u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap()),
            offset: u32::from_le_bytes(data[offset + 12..offset + 16].try_into().unwrap()),
        })
    }

    /// Parse an ArtField from the start of a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        Self::parse_at(data, 0)
    }

    /// Returns true if the field is public.
    pub fn is_public(&self) -> bool {
        self.access_flags & 0x0001 != 0
    }

    /// Returns true if the field is private.
    pub fn is_private(&self) -> bool {
        self.access_flags & 0x0002 != 0
    }

    /// Returns true if the field is protected.
    pub fn is_protected(&self) -> bool {
        self.access_flags & 0x0004 != 0
    }

    /// Returns true if the field is static.
    pub fn is_static(&self) -> bool {
        self.access_flags & 0x0008 != 0
    }

    /// Returns true if the field is final.
    pub fn is_final(&self) -> bool {
        self.access_flags & 0x0010 != 0
    }

    /// Returns true if the field is volatile.
    pub fn is_volatile(&self) -> bool {
        self.access_flags & 0x0040 != 0
    }

    /// Returns true if the field is transient.
    pub fn is_transient(&self) -> bool {
        self.access_flags & 0x0080 != 0
    }

    /// Returns true if the field is synthetic.
    pub fn is_synthetic(&self) -> bool {
        self.access_flags & 0x1000 != 0
    }

    /// Returns true if the field is an enum constant.
    pub fn is_enum(&self) -> bool {
        self.access_flags & 0x4000 != 0
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// ArtFieldGroup
// ═══════════════════════════════════════════════════════════════════════════════════

/// A group of ART fields, prefixed by a count.
///
/// The count is a u32, followed by `count` ArtField entries.
///
/// Ported from Ghidra's `ArtFieldGroup`.
#[derive(Debug, Clone)]
pub struct ArtFieldGroup {
    /// Number of fields in the group.
    pub field_count: u32,
    /// The fields.
    pub fields: Vec<ArtField>,
}

impl ArtFieldGroup {
    /// Sanity limit on field count.
    const MAX_FIELD_COUNT: u32 = 0xFFFF;

    /// Parse an ArtFieldGroup from a byte slice at the given offset.
    pub fn parse_at(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + 4 > data.len() {
            return Err("Data too short for ArtFieldGroup count".to_string());
        }

        let field_count = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        if field_count > Self::MAX_FIELD_COUNT {
            return Err(format!("Too many ART fields: {}", field_count));
        }

        let mut fields = Vec::with_capacity(field_count as usize);
        let mut pos = offset + 4;

        for _ in 0..field_count {
            let field = ArtField::parse_at(data, pos)?;
            fields.push(field);
            pos += ArtField::SIZE;
        }

        Ok(ArtFieldGroup { field_count, fields })
    }

    /// Parse an ArtFieldGroup from the start of a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        Self::parse_at(data, 0)
    }

    /// Returns the total number of fields in this group.
    pub fn field_count(&self) -> u32 {
        self.field_count
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_field() {
        let mut data = vec![0u8; ArtField::SIZE];
        data[0..4].copy_from_slice(&0x1000u32.to_le_bytes()); // declaring_class
        data[4..8].copy_from_slice(&0x0009u32.to_le_bytes()); // access_flags = PUBLIC | STATIC
        data[8..12].copy_from_slice(&42u32.to_le_bytes()); // field_dex_idx
        data[12..16].copy_from_slice(&8u32.to_le_bytes()); // offset

        let field = ArtField::parse(&data).unwrap();
        assert_eq!(field.declaring_class, 0x1000);
        assert!(field.is_public());
        assert!(field.is_static());
        assert!(!field.is_final());
        assert_eq!(field.field_dex_idx, 42);
        assert_eq!(field.offset, 8);
    }

    #[test]
    fn test_parse_field_at_offset() {
        let mut data = vec![0u8; ArtField::SIZE + 64];
        let offset = 64;
        data[offset..offset + 4].copy_from_slice(&0x2000u32.to_le_bytes());
        data[offset + 4..offset + 8].copy_from_slice(&0x0040u32.to_le_bytes()); // VOLATILE

        let field = ArtField::parse_at(&data, offset).unwrap();
        assert_eq!(field.declaring_class, 0x2000);
        assert!(field.is_volatile());
    }

    #[test]
    fn test_parse_field_truncated() {
        assert!(ArtField::parse(&[0u8; 8]).is_err());
    }

    #[test]
    fn test_parse_field_access_flags() {
        let field = ArtField {
            declaring_class: 0,
            access_flags: 0x0002 | 0x0010 | 0x4000, // PRIVATE | FINAL | ENUM
            field_dex_idx: 0,
            offset: 0,
        };
        assert!(field.is_private());
        assert!(field.is_final());
        assert!(field.is_enum());
        assert!(!field.is_public());
        assert!(!field.is_static());
    }

    #[test]
    fn test_parse_field_group() {
        // Group: count(u32=2) + 2 x ArtField(16 bytes each)
        let mut data = vec![0u8; 4 + 2 * ArtField::SIZE];
        data[0..4].copy_from_slice(&2u32.to_le_bytes()); // count

        // Field 0
        data[4..8].copy_from_slice(&0x100u32.to_le_bytes()); // declaring_class
        data[8..12].copy_from_slice(&0x0001u32.to_le_bytes()); // PUBLIC
        data[12..16].copy_from_slice(&0u32.to_le_bytes()); // field_dex_idx
        data[16..20].copy_from_slice(&0u32.to_le_bytes()); // offset

        // Field 1
        data[20..24].copy_from_slice(&0x200u32.to_le_bytes()); // declaring_class
        data[24..28].copy_from_slice(&0x0008u32.to_le_bytes()); // STATIC
        data[28..32].copy_from_slice(&1u32.to_le_bytes()); // field_dex_idx
        data[32..36].copy_from_slice(&4u32.to_le_bytes()); // offset

        let group = ArtFieldGroup::parse(&data).unwrap();
        assert_eq!(group.field_count(), 2);
        assert_eq!(group.fields[0].declaring_class, 0x100);
        assert!(group.fields[0].is_public());
        assert_eq!(group.fields[1].declaring_class, 0x200);
        assert!(group.fields[1].is_static());
        assert_eq!(group.fields[1].offset, 4);
    }

    #[test]
    fn test_parse_field_group_too_many() {
        // count = 0x10000 (too large)
        let mut data = vec![0u8; 4];
        data[0..4].copy_from_slice(&0x10000u32.to_le_bytes());
        assert!(ArtFieldGroup::parse(&data).is_err());
    }

    #[test]
    fn test_parse_field_group_empty() {
        let mut data = vec![0u8; 4];
        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        let group = ArtFieldGroup::parse(&data).unwrap();
        assert_eq!(group.field_count(), 0);
        assert!(group.fields.is_empty());
    }
}
