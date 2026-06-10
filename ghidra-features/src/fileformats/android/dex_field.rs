//! Android DEX field structures.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.dex.format`
//! `FieldIDItem` and `EncodedField` packages.
//!
//! Covers the `field_id_item` (8 bytes) and `encoded_field`
//! (variable-length, ULEB128-encoded) on-disk structures.

// ═══════════════════════════════════════════════════════════════════════════════════
// FieldIDItem
// ═══════════════════════════════════════════════════════════════════════════════════

/// Represents a `field_id_item` structure (8 bytes).
///
/// Each field referenced in the DEX file has an entry in the `field_ids`
/// table. The entry identifies the declaring class, the field type, and
/// the field name.
#[derive(Debug, Clone)]
pub struct FieldIDItem {
    /// File offset of this item (set during parsing).
    pub file_offset: u64,
    /// Index into `type_ids` for the declaring class.
    pub class_index: u16,
    /// Index into `type_ids` for the field type.
    pub type_index: u16,
    /// Index into `string_ids` for the field name.
    pub name_index: u32,
}

impl FieldIDItem {
    /// Size of the on-disk structure (8 bytes).
    pub const SIZE: usize = 8;

    /// Parse a `field_id_item` from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        Self::parse_at(data, 0)
    }

    /// Parse a `field_id_item` from a byte slice, recording the file offset.
    pub fn parse_at(data: &[u8], file_offset: usize) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err("Data too short for FieldIDItem".to_string());
        }

        let class_index = u16::from_le_bytes(data[0..2].try_into().unwrap());
        let type_index = u16::from_le_bytes(data[2..4].try_into().unwrap());
        let name_index = u32::from_le_bytes(data[4..8].try_into().unwrap());

        Ok(FieldIDItem {
            file_offset: file_offset as u64,
            class_index,
            type_index,
            name_index,
        })
    }

    /// Parse all `field_id_item` entries from a DEX file.
    ///
    /// `count` is the number of entries (from the DEX header).
    /// `offset` is the byte offset of the `field_ids` table.
    pub fn parse_all(data: &[u8], offset: u32, count: u32) -> Result<Vec<Self>, String> {
        let start = offset as usize;
        let table_size = count as usize * Self::SIZE;
        if start + table_size > data.len() {
            return Err("FieldIDItem table extends beyond data".to_string());
        }

        let mut result = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let entry_start = start + i * Self::SIZE;
            let item = Self::parse_at(&data[entry_start..], entry_start)?;
            result.push(item);
        }
        Ok(result)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// EncodedField
// ═══════════════════════════════════════════════════════════════════════════════════

/// Represents an `encoded_field` structure.
///
/// Fields within a `class_data_item` are stored as ULEB128-encoded
/// pairs of (field_idx_diff, access_flags). The `field_idx_diff` is a
/// delta from the previous field index.
#[derive(Debug, Clone)]
pub struct EncodedField {
    /// File offset where this encoded field starts.
    pub file_offset: u64,
    /// Delta-encoded index into `field_ids` (add to previous index).
    pub field_index_diff: u32,
    /// Absolute field index (resolved during parsing).
    pub field_index: u32,
    /// Access flags (ACC_PUBLIC, ACC_STATIC, etc.).
    pub access_flags: u32,
    /// Length of the `field_idx_diff` ULEB128 encoding (bytes).
    pub field_index_diff_length: u32,
    /// Length of the `access_flags` ULEB128 encoding (bytes).
    pub access_flags_length: u32,
}

impl EncodedField {
    /// Parse a single `encoded_field` from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        Self::parse_at(data, 0)
    }

    /// Parse a single `encoded_field`, recording the file offset.
    pub fn parse_at(data: &[u8], file_offset: usize) -> Result<Self, String> {
        let mut pos = 0;

        let (field_index_diff, new_pos, diff_len) = read_uleb128_with_len(data, pos)?;
        pos = new_pos;

        let (access_flags, new_pos, flags_len) = read_uleb128_with_len(data, pos)?;
        pos = new_pos;

        let _ = pos;

        Ok(EncodedField {
            file_offset: file_offset as u64,
            field_index_diff,
            field_index: 0, // resolved later
            access_flags,
            field_index_diff_length: diff_len,
            access_flags_length: flags_len,
        })
    }

    /// Parse all `encoded_field` entries from a list.
    ///
    /// `count` is the number of entries.
    /// `data` is the raw bytes starting at the first entry.
    ///
    /// Returns the parsed fields and the number of bytes consumed.
    pub fn parse_all(data: &[u8], count: u32) -> Result<(Vec<Self>, usize), String> {
        let mut result = Vec::with_capacity(count as usize);
        let mut pos = 0;
        let mut last_field_index: u32 = 0;

        for _ in 0..count {
            let mut field = Self::parse_at(&data[pos..], pos)?;
            last_field_index = last_field_index.wrapping_add(field.field_index_diff);
            field.field_index = last_field_index;
            // Advance past the two ULEB128 values we consumed
            pos += field.field_index_diff_length as usize
                + field.access_flags_length as usize;
            result.push(field);
        }

        Ok((result, pos))
    }

    /// Returns true if this field is public.
    pub fn is_public(&self) -> bool {
        self.access_flags & 0x0001 != 0
    }

    /// Returns true if this field is private.
    pub fn is_private(&self) -> bool {
        self.access_flags & 0x0002 != 0
    }

    /// Returns true if this field is protected.
    pub fn is_protected(&self) -> bool {
        self.access_flags & 0x0004 != 0
    }

    /// Returns true if this field is static.
    pub fn is_static(&self) -> bool {
        self.access_flags & 0x0008 != 0
    }

    /// Returns true if this field is final.
    pub fn is_final(&self) -> bool {
        self.access_flags & 0x0010 != 0
    }

    /// Returns true if this field is volatile.
    pub fn is_volatile(&self) -> bool {
        self.access_flags & 0x0040 != 0
    }

    /// Returns true if this field is transient.
    pub fn is_transient(&self) -> bool {
        self.access_flags & 0x0080 != 0
    }

    /// Returns true if this field is synthetic.
    pub fn is_synthetic(&self) -> bool {
        self.access_flags & 0x1000 != 0
    }

    /// Returns true if this field is an enum constant.
    pub fn is_enum(&self) -> bool {
        self.access_flags & 0x4000 != 0
    }

    /// Returns a human-readable list of modifier names for this field.
    pub fn modifier_names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.is_public() { names.push("public"); }
        if self.is_private() { names.push("private"); }
        if self.is_protected() { names.push("protected"); }
        if self.is_static() { names.push("static"); }
        if self.is_final() { names.push("final"); }
        if self.is_volatile() { names.push("volatile"); }
        if self.is_transient() { names.push("transient"); }
        if self.is_synthetic() { names.push("synthetic"); }
        if self.is_enum() { names.push("enum"); }
        names
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// ULEB128 reader with length tracking
// ═══════════════════════════════════════════════════════════════════════════════════

/// Read an unsigned LEB128 value from `data` starting at `pos`.
///
/// Returns `(value, new_position, byte_length)`.
fn read_uleb128_with_len(data: &[u8], mut pos: usize) -> Result<(u32, usize, u32), String> {
    let mut result: u32 = 0;
    let mut shift = 0;
    let start_pos = pos;

    loop {
        if pos >= data.len() {
            return Err("ULEB128: unexpected end of data".to_string());
        }
        let byte = data[pos];
        pos += 1;
        result |= ((byte & 0x7F) as u32) << shift;
        if byte & 0x80 == 0 {
            return Ok((result, pos, (pos - start_pos) as u32));
        }
        shift += 7;
        if shift >= 32 {
            return Err("ULEB128: too many bytes for u32".to_string());
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
    fn test_field_id_item_parse() {
        let mut data = vec![0u8; FieldIDItem::SIZE];
        data[0..2].copy_from_slice(&3u16.to_le_bytes()); // class_index
        data[2..4].copy_from_slice(&5u16.to_le_bytes()); // type_index
        data[4..8].copy_from_slice(&42u32.to_le_bytes()); // name_index

        let item = FieldIDItem::parse(&data).unwrap();
        assert_eq!(item.class_index, 3);
        assert_eq!(item.type_index, 5);
        assert_eq!(item.name_index, 42);
    }

    #[test]
    fn test_field_id_item_parse_all() {
        let mut data = vec![0u8; FieldIDItem::SIZE * 2];
        // First
        data[0..2].copy_from_slice(&0u16.to_le_bytes());
        data[2..4].copy_from_slice(&0u16.to_le_bytes());
        data[4..8].copy_from_slice(&0u32.to_le_bytes());
        // Second
        data[8..10].copy_from_slice(&1u16.to_le_bytes());
        data[10..12].copy_from_slice(&2u16.to_le_bytes());
        data[12..16].copy_from_slice(&5u32.to_le_bytes());

        let items = FieldIDItem::parse_all(&data, 0, 2).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].class_index, 0);
        assert_eq!(items[1].class_index, 1);
        assert_eq!(items[1].type_index, 2);
        assert_eq!(items[1].name_index, 5);
    }

    #[test]
    fn test_encoded_field_parse() {
        // field_idx_diff = 0 (1 byte ULEB128)
        // access_flags = ACC_PUBLIC | ACC_STATIC = 0x09 (1 byte)
        let data = vec![0x00, 0x09];
        let field = EncodedField::parse_at(&data, 0x100).unwrap();
        assert_eq!(field.file_offset, 0x100);
        assert_eq!(field.field_index_diff, 0);
        assert_eq!(field.access_flags, 0x09);
        assert!(field.is_public());
        assert!(field.is_static());
        assert!(!field.is_volatile());
    }

    #[test]
    fn test_encoded_field_parse_all() {
        // Two fields with delta encoding:
        //   Field 0: idx_diff=0, flags=ACC_PUBLIC (0x01)
        //   Field 1: idx_diff=3, flags=ACC_PRIVATE | ACC_FINAL (0x12)
        let data = vec![
            0x00, 0x01, // field 0: diff=0, flags=ACC_PUBLIC
            0x03, 0x12, // field 1: diff=3, flags=ACC_PRIVATE|ACC_FINAL
        ];
        let (fields, consumed) = EncodedField::parse_all(&data, 2).unwrap();
        assert_eq!(fields.len(), 2);
        assert_eq!(consumed, 4);
        assert_eq!(fields[0].field_index, 0);
        assert_eq!(fields[1].field_index, 3);
        assert!(fields[1].is_private());
        assert!(fields[1].is_final());
    }

    #[test]
    fn test_encoded_field_modifiers() {
        let field = EncodedField {
            file_offset: 0,
            field_index_diff: 0,
            field_index: 0,
            access_flags: 0x0001 | 0x0008 | 0x0040, // PUBLIC | STATIC | VOLATILE
            field_index_diff_length: 1,
            access_flags_length: 1,
        };
        let mods = field.modifier_names();
        assert!(mods.contains(&"public"));
        assert!(mods.contains(&"static"));
        assert!(mods.contains(&"volatile"));
        assert!(!mods.contains(&"private"));
    }

    #[test]
    fn test_field_id_truncated() {
        let data = vec![0u8; 4];
        assert!(FieldIDItem::parse(&data).is_err());
    }

    #[test]
    fn test_read_uleb128_with_len() {
        // 0x00 -> 0, length 1
        assert_eq!(read_uleb128_with_len(&[0x00], 0).unwrap(), (0, 1, 1));
        // 0x7F -> 127, length 1
        assert_eq!(read_uleb128_with_len(&[0x7F], 0).unwrap(), (127, 1, 1));
        // 0x80 0x01 -> 128, length 2
        assert_eq!(read_uleb128_with_len(&[0x80, 0x01], 0).unwrap(), (128, 2, 2));
    }

    #[test]
    fn test_read_uleb128_with_len_truncated() {
        assert!(read_uleb128_with_len(&[0x80], 0).is_err());
    }
}
