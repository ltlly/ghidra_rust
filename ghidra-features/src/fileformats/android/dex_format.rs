//! Android DEX format header (extended version for Android package).
//!
//! Ported from Ghidra's `ghidra.file.formats.android.dex.format` package.
//! This provides the Android-specific DEX structures that complement
//! the existing dex.rs module.

use nom::{bytes::complete::take, number::complete::{le_u16, le_u32, le_u8}, IResult};

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// DEX magic: `"dex\n"`.
pub const DEX_MAGIC: &[u8; 4] = b"dex\n";

/// DEX file header size (112 bytes).
pub const DEX_HEADER_SIZE: usize = 112;

/// DEX endian constant (little endian).
pub const DEX_ENDIAN_LITTLE: u8 = 0x12;

/// DEX endian constant (big endian).
pub const DEX_ENDIAN_BIG: u8 = 0x21;

// Item type codes.
pub const TYPE_HEADER_ITEM: u16 = 0x0000;
pub const TYPE_STRING_ID_ITEM: u16 = 0x0001;
pub const TYPE_TYPE_ID_ITEM: u16 = 0x0002;
pub const TYPE_PROTO_ID_ITEM: u16 = 0x0003;
pub const TYPE_FIELD_ID_ITEM: u16 = 0x0004;
pub const TYPE_METHOD_ID_ITEM: u16 = 0x0005;
pub const TYPE_CLASS_DEF_ITEM: u16 = 0x0006;
pub const TYPE_MAP_LIST: u16 = 0x1000;
pub const TYPE_TYPE_LIST: u16 = 0x1001;
pub const TYPE_ANNOTATION_SET_REF_LIST: u16 = 0x1002;
pub const TYPE_ANNOTATION_SET_ITEM: u16 = 0x1003;
pub const TYPE_CODE_ITEM: u16 = 0x2001;
pub const TYPE_STRING_DATA_ITEM: u16 = 0x2002;
pub const TYPE_DEBUG_INFO_ITEM: u16 = 0x2003;
pub const TYPE_ANNOTATION_ITEM: u16 = 0x2004;
pub const TYPE_ENCODED_ARRAY_ITEM: u16 = 0x2005;
pub const TYPE_CLASS_DATA_ITEM: u16 = 0x2006;
pub const TYPE_MAP_ITEM: u16 = 0x2007;
pub const TYPE_CALL_SITE_ID_ITEM: u16 = 0x2008;
pub const TYPE_METHOD_HANDLE_ITEM: u16 = 0x2009;

// Access flags.
pub const ACC_PUBLIC: u32 = 0x0001;
pub const ACC_PRIVATE: u32 = 0x0002;
pub const ACC_PROTECTED: u32 = 0x0004;
pub const ACC_STATIC: u32 = 0x0008;
pub const ACC_FINAL: u32 = 0x0010;
pub const ACC_SYNCHRONIZED: u32 = 0x0020;
pub const ACC_VOLATILE: u32 = 0x0040;
pub const ACC_BRIDGE: u32 = 0x0040;
pub const ACC_VARARGS: u32 = 0x0080;
pub const ACC_NATIVE: u32 = 0x0100;
pub const ACC_INTERFACE: u32 = 0x0200;
pub const ACC_ABSTRACT: u32 = 0x0400;
pub const ACC_STRICT: u32 = 0x0800;
pub const ACC_SYNTHETIC: u32 = 0x1000;
pub const ACC_ANNOTATION: u32 = 0x2000;
pub const ACC_ENUM: u32 = 0x4000;
pub const ACC_CONSTRUCTOR: u32 = 0x10000;
pub const ACC_DECLARED_SYNCHRONIZED: u32 = 0x20000;

// ═══════════════════════════════════════════════════════════════════════════════════
// DEX Header
// ═══════════════════════════════════════════════════════════════════════════════════

/// Full DEX file header.
#[derive(Debug, Clone)]
pub struct DexHeader {
    /// Magic bytes: `"dex\n"`.
    pub magic: [u8; 4],
    /// DEX version string (e.g. `"035\0"`).
    pub version: [u8; 4],
    /// Adler-32 checksum of the rest of the file.
    pub checksum: u32,
    /// SHA-1 signature of the rest of the file.
    pub signature: [u8; 20],
    /// Size of the entire file in bytes.
    pub file_size: u32,
    /// Header size (112 bytes).
    pub header_size: u32,
    /// Endian tag.
    pub endian_tag: u32,
    /// Size of the link section.
    pub link_size: u32,
    /// Offset from start of file to the link section.
    pub link_off: u32,
    /// Offset from start of file to the map section.
    pub map_off: u32,
    /// Count of strings in the string identifiers section.
    pub string_ids_size: u32,
    /// Offset from start of file to the string identifiers section.
    pub string_ids_off: u32,
    /// Count of elements in the type identifiers section.
    pub type_ids_size: u32,
    /// Offset from start of file to the type identifiers section.
    pub type_ids_off: u32,
    /// Count of elements in the prototype identifiers section.
    pub proto_ids_size: u32,
    /// Offset from start of file to the prototype identifiers section.
    pub proto_ids_off: u32,
    /// Count of elements in the field identifiers section.
    pub field_ids_size: u32,
    /// Offset from start of file to the field identifiers section.
    pub field_ids_off: u32,
    /// Count of elements in the method identifiers section.
    pub method_ids_size: u32,
    /// Offset from start of file to the method identifiers section.
    pub method_ids_off: u32,
    /// Count of elements in the class definitions section.
    pub class_defs_size: u32,
    /// Offset from start of file to the class definitions section.
    pub class_defs_off: u32,
    /// Size of the data section in bytes.
    pub data_size: u32,
    /// Offset from start of file to the data section.
    pub data_off: u32,
}

impl DexHeader {
    /// Parse a DEX header from little-endian bytes.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < DEX_HEADER_SIZE {
            return Err("Data too short for DEX header".to_string());
        }

        let magic: [u8; 4] = data[0..4].try_into().unwrap();
        if magic != *DEX_MAGIC {
            return Err(format!("Invalid DEX magic: {:?}", magic));
        }

        let version: [u8; 4] = data[4..8].try_into().unwrap();
        let checksum = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let signature: [u8; 20] = data[12..32].try_into().unwrap();
        let file_size = u32::from_le_bytes(data[32..36].try_into().unwrap());
        let header_size = u32::from_le_bytes(data[36..40].try_into().unwrap());
        let endian_tag = u32::from_le_bytes(data[40..44].try_into().unwrap());

        let link_size = u32::from_le_bytes(data[44..48].try_into().unwrap());
        let link_off = u32::from_le_bytes(data[48..52].try_into().unwrap());
        let map_off = u32::from_le_bytes(data[52..56].try_into().unwrap());

        let string_ids_size = u32::from_le_bytes(data[56..60].try_into().unwrap());
        let string_ids_off = u32::from_le_bytes(data[60..64].try_into().unwrap());
        let type_ids_size = u32::from_le_bytes(data[64..68].try_into().unwrap());
        let type_ids_off = u32::from_le_bytes(data[68..72].try_into().unwrap());
        let proto_ids_size = u32::from_le_bytes(data[72..76].try_into().unwrap());
        let proto_ids_off = u32::from_le_bytes(data[76..80].try_into().unwrap());
        let field_ids_size = u32::from_le_bytes(data[80..84].try_into().unwrap());
        let field_ids_off = u32::from_le_bytes(data[84..88].try_into().unwrap());
        let method_ids_size = u32::from_le_bytes(data[88..92].try_into().unwrap());
        let method_ids_off = u32::from_le_bytes(data[92..96].try_into().unwrap());
        let class_defs_size = u32::from_le_bytes(data[96..100].try_into().unwrap());
        let class_defs_off = u32::from_le_bytes(data[100..104].try_into().unwrap());
        let data_size = u32::from_le_bytes(data[104..108].try_into().unwrap());
        let data_off = u32::from_le_bytes(data[108..112].try_into().unwrap());

        Ok(DexHeader {
            magic,
            version,
            checksum,
            signature,
            file_size,
            header_size,
            endian_tag,
            link_size,
            link_off,
            map_off,
            string_ids_size,
            string_ids_off,
            type_ids_size,
            type_ids_off,
            proto_ids_size,
            proto_ids_off,
            field_ids_size,
            field_ids_off,
            method_ids_size,
            method_ids_off,
            class_defs_size,
            class_defs_off,
            data_size,
            data_off,
        })
    }

    /// Whether the magic is valid.
    pub fn is_valid(&self) -> bool {
        self.magic == *DEX_MAGIC
    }

    /// Version string (e.g., "035").
    pub fn version_string(&self) -> String {
        String::from_utf8_lossy(&self.version)
            .trim_matches('\0')
            .to_string()
    }
}

/// DEX map item.
#[derive(Debug, Clone, Copy)]
pub struct DexMapItem {
    /// Type of the item.
    pub type_: u16,
    /// Unused.
    pub unused: u16,
    /// Count of the items.
    pub size: u32,
    /// Offset from start of file.
    pub offset: u32,
}

impl DexMapItem {
    pub fn parse(data: &[u8]) -> IResult<&[u8], Self> {
        let (i, type_) = le_u16(data)?;
        let (i, unused) = le_u16(i)?;
        let (i, size) = le_u32(i)?;
        let (i, offset) = le_u32(i)?;
        Ok((i, DexMapItem { type_, unused, size, offset }))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(DEX_MAGIC, b"dex\n");
        assert_eq!(DEX_HEADER_SIZE, 112);
        assert_eq!(ACC_PUBLIC, 0x0001);
        assert_eq!(ACC_STATIC, 0x0008);
        assert_eq!(ACC_FINAL, 0x0010);
    }

    #[test]
    fn test_parse_header() {
        let mut data = vec![0u8; DEX_HEADER_SIZE];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..8].copy_from_slice(b"035\0");
        data[8..12].copy_from_slice(&0x12345678u32.to_le_bytes()); // checksum
        data[32..36].copy_from_slice(&112u32.to_le_bytes()); // file_size
        data[36..40].copy_from_slice(&112u32.to_le_bytes()); // header_size
        data[40..44].copy_from_slice(&0x12345678u32.to_le_bytes()); // endian_tag

        let hdr = DexHeader::parse(&data).unwrap();
        assert!(hdr.is_valid());
        assert_eq!(hdr.version_string(), "035");
        assert_eq!(hdr.file_size, 112);
        assert_eq!(hdr.header_size, 112);
    }

    #[test]
    fn test_parse_header_invalid() {
        let mut data = vec![0u8; DEX_HEADER_SIZE];
        data[0..4].copy_from_slice(b"bad\n");
        assert!(DexHeader::parse(&data).is_err());
    }

    #[test]
    fn test_type_constants() {
        assert_eq!(TYPE_CODE_ITEM, 0x2001);
        assert_eq!(TYPE_CLASS_DATA_ITEM, 0x2006);
    }

    #[test]
    fn test_map_item_parse() {
        let mut data = vec![0u8; 12];
        data[0..2].copy_from_slice(&TYPE_CODE_ITEM.to_le_bytes());
        data[4..8].copy_from_slice(&5u32.to_le_bytes()); // size
        data[8..12].copy_from_slice(&0x200u32.to_le_bytes()); // offset

        let (_, item) = DexMapItem::parse(&data).unwrap();
        assert_eq!(item.type_, TYPE_CODE_ITEM);
        assert_eq!(item.size, 5);
        assert_eq!(item.offset, 0x200);
    }
}
