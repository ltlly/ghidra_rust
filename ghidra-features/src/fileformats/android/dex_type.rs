//! Android DEX type structures.
//!
//! Ported from Ghidra's `ghidra.file.formats.android.dex.format`
//! `TypeIDItem`, `PrototypesIDItem`, `TypeList`, and `TypeItem` packages.
//!
//! Covers the `type_id_item` (4 bytes), `proto_id_item` (12 bytes),
//! `type_list` (variable-length), and `type_item` (2 bytes) on-disk
//! structures.

// ═══════════════════════════════════════════════════════════════════════════════════
// TypeIDItem
// ═══════════════════════════════════════════════════════════════════════════════════

/// Represents a `type_id_item` structure (4 bytes).
///
/// Each type referenced in the DEX file has an entry in the `type_ids`
/// table. The entry contains an index into the `string_ids` table for
/// the type descriptor string.
#[derive(Debug, Clone)]
pub struct TypeIDItem {
    /// File offset of this item (set during parsing).
    pub file_offset: u64,
    /// Index into `string_ids` for the type descriptor string.
    pub descriptor_index: u32,
}

impl TypeIDItem {
    /// Size of the on-disk structure (4 bytes).
    pub const SIZE: usize = 4;

    /// Parse a `type_id_item` from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        Self::parse_at(data, 0)
    }

    /// Parse a `type_id_item` from a byte slice, recording the file offset.
    pub fn parse_at(data: &[u8], file_offset: usize) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err("Data too short for TypeIDItem".to_string());
        }

        let descriptor_index = u32::from_le_bytes(data[0..4].try_into().unwrap());

        Ok(TypeIDItem {
            file_offset: file_offset as u64,
            descriptor_index,
        })
    }

    /// Parse all `type_id_item` entries from a DEX file.
    ///
    /// `count` is the number of entries (from the DEX header).
    /// `offset` is the byte offset of the `type_ids` table.
    pub fn parse_all(data: &[u8], offset: u32, count: u32) -> Result<Vec<Self>, String> {
        let start = offset as usize;
        let table_size = count as usize * Self::SIZE;
        if start + table_size > data.len() {
            return Err("TypeIDItem table extends beyond data".to_string());
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
// ProtoIDItem (PrototypesIDItem)
// ═══════════════════════════════════════════════════════════════════════════════════

/// Represents a `proto_id_item` structure (12 bytes).
///
/// Each method prototype in the DEX file has an entry in the `proto_ids`
/// table. The entry identifies the shorty descriptor, return type, and
/// parameter types.
#[derive(Debug, Clone)]
pub struct ProtoIDItem {
    /// File offset of this item (set during parsing).
    pub file_offset: u64,
    /// Index into `string_ids` for the shorty descriptor.
    pub shorty_index: u32,
    /// Index into `type_ids` for the return type.
    pub return_type_index: u32,
    /// Offset to the `type_list` for parameters, or 0 if no parameters.
    /// NOTE: For CDEX files, this value is relative to `data_off` in `DexHeader`.
    pub parameters_offset: u32,
}

impl ProtoIDItem {
    /// Size of the on-disk structure (12 bytes).
    pub const SIZE: usize = 12;

    /// Parse a `proto_id_item` from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        Self::parse_at(data, 0)
    }

    /// Parse a `proto_id_item` from a byte slice, recording the file offset.
    pub fn parse_at(data: &[u8], file_offset: usize) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err("Data too short for ProtoIDItem".to_string());
        }

        let shorty_index = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let return_type_index = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let parameters_offset = u32::from_le_bytes(data[8..12].try_into().unwrap());

        Ok(ProtoIDItem {
            file_offset: file_offset as u64,
            shorty_index,
            return_type_index,
            parameters_offset,
        })
    }

    /// Parse all `proto_id_item` entries from a DEX file.
    ///
    /// `count` is the number of entries (from the DEX header).
    /// `offset` is the byte offset of the `proto_ids` table.
    pub fn parse_all(data: &[u8], offset: u32, count: u32) -> Result<Vec<Self>, String> {
        let start = offset as usize;
        let table_size = count as usize * Self::SIZE;
        if start + table_size > data.len() {
            return Err("ProtoIDItem table extends beyond data".to_string());
        }

        let mut result = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let entry_start = start + i * Self::SIZE;
            let item = Self::parse_at(&data[entry_start..], entry_start)?;
            result.push(item);
        }
        Ok(result)
    }

    /// Returns true if this prototype has parameters.
    pub fn has_parameters(&self) -> bool {
        self.parameters_offset != 0
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// TypeItem
// ═══════════════════════════════════════════════════════════════════════════════════

/// Represents a `type_item` structure (2 bytes).
///
/// Each entry in a `type_list` is a `type_item` that contains an index
/// into the `type_ids` table.
#[derive(Debug, Clone, Copy)]
pub struct TypeItem {
    /// Index into `type_ids` for this type.
    pub type_index: u16,
}

impl TypeItem {
    /// Size of the on-disk structure (2 bytes).
    pub const SIZE: usize = 2;

    /// Parse a `type_item` from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err("Data too short for TypeItem".to_string());
        }

        let type_index = u16::from_le_bytes(data[0..2].try_into().unwrap());

        Ok(TypeItem { type_index })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// TypeList
// ═══════════════════════════════════════════════════════════════════════════════════

/// Represents a `type_list` structure (variable-length).
///
/// A `type_list` is a counted array of `type_item` entries. It is used
/// to specify the parameter types for a method prototype.
#[derive(Debug, Clone)]
pub struct TypeList {
    /// Number of entries in the list.
    pub size: u32,
    /// The type items.
    pub items: Vec<TypeItem>,
}

impl TypeList {
    /// Parse a `type_list` from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 4 {
            return Err("Data too short for TypeList size".to_string());
        }

        let size = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let items_start = 4;
        let items_end = items_start + size as usize * TypeItem::SIZE;

        if data.len() < items_end {
            return Err("Data too short for TypeList items".to_string());
        }

        let mut items = Vec::with_capacity(size as usize);
        for i in 0..size as usize {
            let item_start = items_start + i * TypeItem::SIZE;
            let item = TypeItem::parse(&data[item_start..])?;
            items.push(item);
        }

        Ok(TypeList { size, items })
    }

    /// Returns the number of items in the list.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns true if the list is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_id_item_parse() {
        let mut data = vec![0u8; TypeIDItem::SIZE];
        data[0..4].copy_from_slice(&42u32.to_le_bytes()); // descriptor_index

        let item = TypeIDItem::parse(&data).unwrap();
        assert_eq!(item.descriptor_index, 42);
    }

    #[test]
    fn test_type_id_item_parse_all() {
        let mut data = vec![0u8; TypeIDItem::SIZE * 3];
        data[0..4].copy_from_slice(&10u32.to_le_bytes());
        data[4..8].copy_from_slice(&20u32.to_le_bytes());
        data[8..12].copy_from_slice(&30u32.to_le_bytes());

        let items = TypeIDItem::parse_all(&data, 0, 3).unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].descriptor_index, 10);
        assert_eq!(items[1].descriptor_index, 20);
        assert_eq!(items[2].descriptor_index, 30);
    }

    #[test]
    fn test_proto_id_item_parse() {
        let mut data = vec![0u8; ProtoIDItem::SIZE];
        data[0..4].copy_from_slice(&1u32.to_le_bytes()); // shorty_index
        data[4..8].copy_from_slice(&5u32.to_le_bytes()); // return_type_index
        data[8..12].copy_from_slice(&0x200u32.to_le_bytes()); // parameters_offset

        let item = ProtoIDItem::parse(&data).unwrap();
        assert_eq!(item.shorty_index, 1);
        assert_eq!(item.return_type_index, 5);
        assert_eq!(item.parameters_offset, 0x200);
        assert!(item.has_parameters());
    }

    #[test]
    fn test_proto_id_item_no_params() {
        let mut data = vec![0u8; ProtoIDItem::SIZE];
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        data[4..8].copy_from_slice(&5u32.to_le_bytes());
        data[8..12].copy_from_slice(&0u32.to_le_bytes()); // no parameters

        let item = ProtoIDItem::parse(&data).unwrap();
        assert!(!item.has_parameters());
    }

    #[test]
    fn test_proto_id_item_parse_all() {
        let mut data = vec![0u8; ProtoIDItem::SIZE * 2];
        // First
        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        data[4..8].copy_from_slice(&0u32.to_le_bytes());
        data[8..12].copy_from_slice(&0u32.to_le_bytes());
        // Second
        data[12..16].copy_from_slice(&1u32.to_le_bytes());
        data[16..20].copy_from_slice(&2u32.to_le_bytes());
        data[20..24].copy_from_slice(&0x100u32.to_le_bytes());

        let items = ProtoIDItem::parse_all(&data, 0, 2).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].shorty_index, 0);
        assert_eq!(items[1].shorty_index, 1);
        assert_eq!(items[1].return_type_index, 2);
    }

    #[test]
    fn test_type_item_parse() {
        let mut data = vec![0u8; TypeItem::SIZE];
        data[0..2].copy_from_slice(&7u16.to_le_bytes());

        let item = TypeItem::parse(&data).unwrap();
        assert_eq!(item.type_index, 7);
    }

    #[test]
    fn test_type_list_parse() {
        let mut data = Vec::new();
        // size = 3
        data.extend_from_slice(&3u32.to_le_bytes());
        // 3 type items
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&5u16.to_le_bytes());
        data.extend_from_slice(&10u16.to_le_bytes());

        let list = TypeList::parse(&data).unwrap();
        assert_eq!(list.size, 3);
        assert_eq!(list.len(), 3);
        assert!(!list.is_empty());
        assert_eq!(list.items[0].type_index, 1);
        assert_eq!(list.items[1].type_index, 5);
        assert_eq!(list.items[2].type_index, 10);
    }

    #[test]
    fn test_type_list_empty() {
        let mut data = vec![0u8; 4];
        data[0..4].copy_from_slice(&0u32.to_le_bytes()); // size = 0

        let list = TypeList::parse(&data).unwrap();
        assert_eq!(list.size, 0);
        assert_eq!(list.len(), 0);
        assert!(list.is_empty());
    }

    #[test]
    fn test_type_list_truncated() {
        let mut data = vec![0u8; 4];
        data[0..4].copy_from_slice(&2u32.to_le_bytes()); // size = 2, but no items
        assert!(TypeList::parse(&data).is_err());
    }

    #[test]
    fn test_type_id_item_truncated() {
        let data = vec![0u8; 2];
        assert!(TypeIDItem::parse(&data).is_err());
    }

    #[test]
    fn test_proto_id_item_truncated() {
        let data = vec![0u8; 8];
        assert!(ProtoIDItem::parse(&data).is_err());
    }

    #[test]
    fn test_type_item_truncated() {
        let data = vec![0u8; 1];
        assert!(TypeItem::parse(&data).is_err());
    }
}
