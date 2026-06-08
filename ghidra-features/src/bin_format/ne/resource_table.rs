//! NE Resource Table ported from Ghidra's
//! `ghidra.app.util.bin.format.ne.ResourceTable` and related classes.
//!
//! Provides types for NE resource definitions:
//! - [`ResourceTable`] -- collection of resource types and names
//! - [`ResourceType`] -- a group of resources sharing the same type
//! - [`Resource`] -- a single resource entry (TNAMEINFO)
//! - [`ResourceName`] -- a resource name entry
//! - [`ResourceStringTable`] -- a string table resource

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;

use super::LengthStringSet;

// ---------------------------------------------------------------------------
// Resource type IDs
// ---------------------------------------------------------------------------

/// Cursor resource type.
pub const RT_CURSOR: u16 = 0x01;
/// Bitmap resource type.
pub const RT_BITMAP: u16 = 0x02;
/// Icon resource type.
pub const RT_ICON: u16 = 0x03;
/// Menu resource type.
pub const RT_MENU: u16 = 0x04;
/// Dialog resource type.
pub const RT_DIALOG: u16 = 0x05;
/// String resource type.
pub const RT_STRING: u16 = 0x06;
/// Font directory resource type.
pub const RT_FONTDIR: u16 = 0x07;
/// Font resource type.
pub const RT_FONT: u16 = 0x08;
/// Accelerator resource type.
pub const RT_ACCELERATOR: u16 = 0x09;
/// RC data resource type.
pub const RT_RCDATA: u16 = 0x0A;
/// Message table resource type.
pub const RT_MESSAGETABLE: u16 = 0x0B;
/// Cursor group resource type.
pub const RT_GROUP_CURSOR: u16 = 0x0C;
/// Icon group resource type.
pub const RT_GROUP_ICON: u16 = 0x0E;
/// Version resource type.
pub const RT_VERSION: u16 = 0x10;

// ---------------------------------------------------------------------------
// Resource
// ---------------------------------------------------------------------------

/// Resource flag: the resource is moveable.
pub const FLAG_MOVEABLE: u16 = 0x0010;
/// Resource flag: the resource can be shared.
pub const FLAG_PURE: u16 = 0x0020;
/// Resource flag: the resource is preloaded.
pub const FLAG_PRELOAD: u16 = 0x0040;

/// A single resource entry (TNAMEINFO structure).
///
/// Ported from `ghidra.app.util.bin.format.ne.Resource`.
/// Each resource has a file offset, length, flags, and an ID that
/// either refers to a numeric ID or a name in the resource name table.
#[derive(Debug, Clone)]
pub struct Resource {
    /// Alignment shift count from the resource table.
    alignment_shift_count: u16,
    /// Byte offset to content (must be shifted by alignment).
    file_offset: u16,
    /// Length of resource in file (must be shifted by alignment).
    file_length: u16,
    /// Resource flags.
    flagword: u16,
    /// Resource ID (if MSB set, it's a numeric ID; otherwise offset to name).
    resource_id: u16,
    /// Handle (reserved).
    handle: u16,
    /// Usage (reserved).
    usage: u16,
}

impl Resource {
    /// Parse a resource entry from the reader.
    pub fn parse(reader: &mut BinaryReader, alignment_shift_count: u16) -> io::Result<Self> {
        let file_offset = reader.read_next_u16()?;
        let file_length = reader.read_next_u16()?;
        let flagword = reader.read_next_u16()?;
        let resource_id = reader.read_next_u16()?;
        let handle = reader.read_next_u16()?;
        let usage = reader.read_next_u16()?;

        Ok(Self {
            alignment_shift_count,
            file_offset,
            file_length,
            flagword,
            resource_id,
            handle,
            usage,
        })
    }

    /// Returns the raw file offset (before shifting).
    pub fn file_offset(&self) -> u16 {
        self.file_offset
    }

    /// Returns the raw file length (before shifting).
    pub fn file_length(&self) -> u16 {
        self.file_length
    }

    /// Returns the flag word.
    pub fn flagword(&self) -> u16 {
        self.flagword
    }

    /// Returns the resource ID.
    pub fn resource_id(&self) -> u16 {
        self.resource_id
    }

    /// Returns the handle (reserved).
    pub fn handle(&self) -> u16 {
        self.handle
    }

    /// Returns the usage (reserved).
    pub fn usage(&self) -> u16 {
        self.usage
    }

    /// Returns true if this resource is moveable.
    pub fn is_moveable(&self) -> bool {
        self.flagword & FLAG_MOVEABLE != 0
    }

    /// Returns true if this resource is pure (shareable).
    pub fn is_pure(&self) -> bool {
        self.flagword & FLAG_PURE != 0
    }

    /// Returns true if this resource is preloaded.
    pub fn is_preload(&self) -> bool {
        self.flagword & FLAG_PRELOAD != 0
    }

    /// Returns the shifted file offset.
    ///
    /// `file_offset << alignment_shift_count`
    pub fn file_offset_shifted(&self) -> u32 {
        (self.file_offset as u32) << (self.alignment_shift_count as u32)
    }

    /// Returns the shifted file length.
    ///
    /// `file_length << alignment_shift_count`
    pub fn file_length_shifted(&self) -> u32 {
        (self.file_length as u32) << (self.alignment_shift_count as u32)
    }

    /// Returns a display name for this resource.
    ///
    /// If MSB is set, returns the numeric ID. Otherwise returns
    /// a placeholder (actual name resolution requires the resource table).
    pub fn display_name(&self) -> String {
        if self.resource_id & 0x8000 != 0 {
            format!("{}", self.resource_id & 0x7FFF)
        } else {
            format!("name_offset_{}", self.resource_id)
        }
    }
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Resource {{ id={}, offset=0x{:08X}, length={}, flags=0x{:04X} }}",
            self.display_name(),
            self.file_offset_shifted(),
            self.file_length_shifted(),
            self.flagword
        )
    }
}

// ---------------------------------------------------------------------------
// ResourceStringTable
// ---------------------------------------------------------------------------

/// A string table resource in a New Executable.
///
/// Ported from `ghidra.app.util.bin.format.ne.ResourceStringTable`.
/// Strings are grouped into a string table resource rather than stored
/// as individual resources.
#[derive(Debug, Clone)]
pub struct ResourceStringTable {
    /// The base resource.
    base: Resource,
    /// Parsed strings from this table.
    strings: Vec<LengthStringSet>,
}

impl ResourceStringTable {
    /// Parse a resource string table from the reader.
    pub fn parse(
        reader: &mut BinaryReader,
        alignment_shift_count: u16,
    ) -> io::Result<Self> {
        let base = Resource::parse(reader, alignment_shift_count)?;

        // Read the bytes of this resource to parse strings
        let offset = base.file_offset_shifted() as u64;
        let length = base.file_length_shifted() as usize;

        let mut strings = Vec::new();
        if length > 0 {
            let old_index = reader.cursor();
            reader.set_cursor(offset);

            let mut pos = 0u64;
            while pos < length as u64 {
                let byte = reader.read_next_u8()?;
                pos += 1;
                if byte != 0 {
                    // Read a length-prefixed string
                    // We already consumed the length byte (byte), so read the string data
                    let str_data = reader.read_next_bytes(byte as usize)?;
                    pos += byte as u64;
                    let name = String::from_utf8_lossy(&str_data).into_owned();
                    strings.push(LengthStringSet {
                        index: offset + pos - byte as u64 - 1,
                        length: byte,
                        name,
                    });
                }
            }

            reader.set_cursor(old_index);
        }

        Ok(Self { base, strings })
    }

    /// Returns the strings defined in this resource string table.
    pub fn strings(&self) -> &[LengthStringSet] {
        &self.strings
    }

    /// Returns a reference to the base resource.
    pub fn resource(&self) -> &Resource {
        &self.base
    }
}

// ---------------------------------------------------------------------------
// ResourceName
// ---------------------------------------------------------------------------

/// A resource name entry in the resource table.
///
/// Ported from `ghidra.app.util.bin.format.ne.ResourceName`.
/// Stores a length-prefixed name string and its file index.
#[derive(Debug, Clone)]
pub struct ResourceName {
    lns: LengthStringSet,
}

impl ResourceName {
    /// Parse a resource name from the reader.
    pub fn parse(reader: &mut BinaryReader) -> io::Result<Self> {
        let lns = LengthStringSet::parse(reader)?;
        Ok(Self { lns })
    }

    /// Returns the length of the resource name.
    pub fn length(&self) -> u8 {
        self.lns.length()
    }

    /// Returns the name string.
    pub fn name(&self) -> &str {
        self.lns.string()
    }

    /// Returns the byte index of this resource name, relative to the file start.
    pub fn index(&self) -> u64 {
        self.lns.index()
    }
}

// ---------------------------------------------------------------------------
// ResourceType
// ---------------------------------------------------------------------------

/// A group of resources sharing the same type (TTYPEINFO structure).
///
/// Ported from `ghidra.app.util.bin.format.ne.ResourceType`.
/// Each type has an ID, a count, and an array of resource entries.
#[derive(Debug)]
pub struct ResourceType {
    /// The type ID (if >= 0x8000, it's a standard type).
    type_id: u16,
    /// Number of resources of this type.
    count: u16,
    /// Reserved value.
    reserved: u32,
    /// The resources of this type.
    resources: Vec<ResourceOrStringTable>,
}

/// Either a regular Resource or a ResourceStringTable.
#[derive(Debug)]
pub enum ResourceOrStringTable {
    /// A regular resource.
    Resource(Resource),
    /// A string table resource.
    StringTable(ResourceStringTable),
}

impl ResourceType {
    /// Parse a resource type from the reader.
    pub fn parse(reader: &mut BinaryReader, alignment_shift_count: u16) -> io::Result<Self> {
        let type_id = reader.read_next_u16()?;
        if type_id == 0 {
            return Ok(Self {
                type_id: 0,
                count: 0,
                reserved: 0,
                resources: Vec::new(),
            });
        }

        let count = reader.read_next_u16()?;
        let reserved = reader.read_next_u32()?;

        let count_usize = count as usize;
        let is_string_table = (type_id & 0x7FFF) == RT_STRING;

        let mut resources = Vec::with_capacity(count_usize);
        for _ in 0..count_usize {
            if is_string_table {
                let rst = ResourceStringTable::parse(reader, alignment_shift_count)?;
                resources.push(ResourceOrStringTable::StringTable(rst));
            } else {
                let r = Resource::parse(reader, alignment_shift_count)?;
                resources.push(ResourceOrStringTable::Resource(r));
            }
        }

        Ok(Self {
            type_id,
            count,
            reserved,
            resources,
        })
    }

    /// Returns the type ID.
    pub fn type_id(&self) -> u16 {
        self.type_id
    }

    /// Returns the count of resources of this type.
    pub fn count(&self) -> u16 {
        self.count
    }

    /// Returns the reserved value.
    pub fn reserved(&self) -> u32 {
        self.reserved
    }

    /// Returns the resources of this type.
    pub fn resources(&self) -> &[ResourceOrStringTable] {
        &self.resources
    }

    /// Returns a human-readable name for this resource type.
    pub fn type_name(&self) -> String {
        if self.type_id & 0x8000 == 0 {
            return format!("UnknownResourceType_{}", self.type_id);
        }
        let idx = self.type_id & 0x7FFF;
        match idx {
            RT_CURSOR => "Cursor".to_string(),
            RT_BITMAP => "Bitmap".to_string(),
            RT_ICON => "Icon".to_string(),
            RT_MENU => "Menu".to_string(),
            RT_DIALOG => "Dialog Box".to_string(),
            RT_STRING => "String Table".to_string(),
            RT_FONTDIR => "Font Directory".to_string(),
            RT_FONT => "Font".to_string(),
            RT_ACCELERATOR => "Accelerator Table".to_string(),
            RT_RCDATA => "Resource Data".to_string(),
            RT_MESSAGETABLE => "Message Table".to_string(),
            RT_GROUP_CURSOR => "Cursor Directory".to_string(),
            RT_GROUP_ICON => "Icon Directory".to_string(),
            RT_VERSION => "Version Information".to_string(),
            _ => format!("Unknown_{}", idx),
        }
    }
}

impl fmt::Display for ResourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ResourceType {{ id=0x{:04X} ({}), count={} }}",
            self.type_id,
            self.type_name(),
            self.count
        )
    }
}

// ---------------------------------------------------------------------------
// ResourceTable
// ---------------------------------------------------------------------------

/// The resource table in a New Executable.
///
/// Ported from `ghidra.app.util.bin.format.ne.ResourceTable`.
/// Contains all resource types and resource names.
#[derive(Debug)]
pub struct ResourceTable {
    /// Byte index where the resource table begins in the file.
    index: u64,
    /// Alignment shift count for resource offsets and lengths.
    alignment_shift_count: u16,
    /// Resource types.
    types: Vec<ResourceType>,
    /// Resource names.
    names: Vec<ResourceName>,
}

impl ResourceTable {
    /// Parse a resource table from the reader.
    pub fn parse(reader: &mut BinaryReader, index: u64) -> io::Result<Self> {
        let old_index = reader.cursor();
        reader.set_cursor(index);

        let alignment_shift_count = reader.read_next_u16()?;

        let mut types = Vec::new();
        loop {
            let rt = ResourceType::parse(reader, alignment_shift_count)?;
            if rt.type_id() == 0 {
                break;
            }
            types.push(rt);
        }

        let mut names = Vec::new();
        loop {
            let rn = ResourceName::parse(reader)?;
            if rn.length() == 0 {
                break;
            }
            names.push(rn);
        }

        reader.set_cursor(old_index);

        Ok(Self {
            index,
            alignment_shift_count,
            types,
            names,
        })
    }

    /// Returns the alignment shift count.
    pub fn alignment_shift_count(&self) -> u16 {
        self.alignment_shift_count
    }

    /// Returns the resource types.
    pub fn resource_types(&self) -> &[ResourceType] {
        &self.types
    }

    /// Returns the resource names.
    pub fn resource_names(&self) -> &[ResourceName] {
        &self.names
    }

    /// Returns the byte index where the resource table begins.
    pub fn index(&self) -> u64 {
        self.index
    }

    /// Resolve a resource ID to a name string.
    ///
    /// If MSB is set, returns the numeric ID as a string.
    /// Otherwise, looks up the name in the resource name table.
    pub fn resolve_resource_name(&self, resource: &Resource) -> String {
        let rid = resource.resource_id();
        if rid & 0x8000 != 0 {
            return format!("{}", rid & 0x7FFF);
        }
        // Look up name by offset relative to resource table
        for name in &self.names {
            if rid == (name.index() as u16).wrapping_sub(self.index as u16) {
                return name.name().to_string();
            }
        }
        format!("NE - Resource - unknown id - 0x{:04X}", rid)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_flags() {
        // Little-endian byte order
        let data = vec![
            0x01, 0x00, // file_offset = 1
            0x02, 0x00, // file_length = 2
            0x30, 0x00, // flagword = 0x0030: MOVEABLE | PURE
            0x05, 0x80, // resource_id = 0x8005
            0x00, 0x00, // handle
            0x00, 0x00, // usage
        ];
        let mut reader = BinaryReader::from_bytes(&data, true);
        let r = Resource::parse(&mut reader, 4).unwrap();

        assert!(r.is_moveable());
        assert!(r.is_pure());
        assert!(!r.is_preload());
        assert_eq!(r.resource_id(), 0x8005);
        assert_eq!(r.file_offset_shifted(), 0x10); // 1 << 4
        assert_eq!(r.file_length_shifted(), 0x20); // 2 << 4
        assert_eq!(r.display_name(), "5");
    }

    #[test]
    fn test_resource_display() {
        // Little-endian byte order
        let data = vec![
            0x01, 0x00, // file_offset = 1
            0x04, 0x00, // file_length = 4
            0x00, 0x00, // flags
            0x03, 0x80, // id = 0x8003
            0x00, 0x00, // handle
            0x00, 0x00, // usage
        ];
        let mut reader = BinaryReader::from_bytes(&data, true);
        let r = Resource::parse(&mut reader, 0).unwrap();

        let s = format!("{}", r);
        assert!(s.contains("id=3"));
        assert!(s.contains("offset=0x00000001"));
    }

    #[test]
    fn test_resource_name() {
        let data = vec![5, b'H', b'e', b'l', b'l', b'o'];
        let mut reader = BinaryReader::from_bytes(&data, true);
        let rn = ResourceName::parse(&mut reader).unwrap();

        assert_eq!(rn.length(), 5);
        assert_eq!(rn.name(), "Hello");
    }

    #[test]
    fn test_resource_type_name_standard() {
        // Build a minimal resource type with 0 resources
        let mut data = Vec::new();
        // type_id = 0x8003 (RT_ICON with MSB set)
        data.extend_from_slice(&0x8003u16.to_le_bytes());
        // count = 0
        data.extend_from_slice(&0u16.to_le_bytes());
        // reserved = 0
        data.extend_from_slice(&0u32.to_le_bytes());

        let mut reader = BinaryReader::from_bytes(&data, true);
        let rt = ResourceType::parse(&mut reader, 4).unwrap();

        assert_eq!(rt.type_id(), 0x8003);
        assert_eq!(rt.type_name(), "Icon");
        assert_eq!(rt.count(), 0);
    }

    #[test]
    fn test_resource_type_unknown() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x80FFu16.to_le_bytes()); // unknown type
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());

        let mut reader = BinaryReader::from_bytes(&data, true);
        let rt = ResourceType::parse(&mut reader, 4).unwrap();

        assert_eq!(rt.type_name(), "Unknown_255");
    }

    #[test]
    fn test_resource_type_display() {
        let mut data = Vec::new();
        data.extend_from_slice(&(RT_DIALOG | 0x8000).to_le_bytes());
        data.extend_from_slice(&2u16.to_le_bytes()); // count
        data.extend_from_slice(&0u32.to_le_bytes());
        // 2 minimal resources
        for _ in 0..2 {
            data.extend_from_slice(&[0u8; 12]);
        }

        let mut reader = BinaryReader::from_bytes(&data, true);
        let rt = ResourceType::parse(&mut reader, 0).unwrap();

        let s = format!("{}", rt);
        assert!(s.contains("Dialog Box"));
        assert!(s.contains("count=2"));
    }

    #[test]
    fn test_resource_table_parse() {
        let mut data = Vec::new();
        // alignment_shift_count = 4
        data.extend_from_slice(&4u16.to_le_bytes());

        // Resource type 1: RT_ICON with 1 resource
        data.extend_from_slice(&(RT_ICON | 0x8000).to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        // 1 resource entry
        data.extend_from_slice(&[0u8; 12]);

        // End of types marker
        data.extend_from_slice(&0u16.to_le_bytes());

        // Resource names: one name
        data.push(4); // length
        data.extend_from_slice(b"Test"); // name
        // End of names marker
        data.push(0);

        let mut reader = BinaryReader::from_bytes(&data, true);
        let table = ResourceTable::parse(&mut reader, 0).unwrap();

        assert_eq!(table.alignment_shift_count(), 4);
        assert_eq!(table.resource_types().len(), 1);
        assert_eq!(table.resource_types()[0].type_name(), "Icon");
        assert_eq!(table.resource_names().len(), 1);
        assert_eq!(table.resource_names()[0].name(), "Test");
    }

    #[test]
    fn test_resource_table_empty() {
        let mut data = Vec::new();
        data.extend_from_slice(&4u16.to_le_bytes()); // alignment
        data.extend_from_slice(&0u16.to_le_bytes()); // end of types
        data.push(0); // end of names

        let mut reader = BinaryReader::from_bytes(&data, true);
        let table = ResourceTable::parse(&mut reader, 0).unwrap();

        assert!(table.resource_types().is_empty());
        assert!(table.resource_names().is_empty());
    }
}
