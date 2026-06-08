//! SOM shlib_list_entry structure ported from Ghidra's `SomShlibListEntry.java`.

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::binary_writer::{BinaryWritable, BinaryWriter};
use crate::bin_format::types::{DataTypeDescription, StructConverter};

use super::som_exception::SomException;

/// The size in bytes of a `SomShlibListEntry`.
pub const SOM_SHLIB_LIST_ENTRY_SIZE: usize = 0x08;

/// Represents a SOM `shlib_list_entry` structure.
///
/// Ported from `ghidra.app.util.bin.format.som.SomShlibListEntry`.
#[derive(Debug, Clone)]
pub struct SomShlibListEntry {
    /// The name of the shared library (from string table).
    pub shlib_name: String,
    /// Whether the shared library entry is an internal name.
    pub internal_name: bool,
    /// Whether the shared library was specified with the `-l` option.
    pub dash_l_reference: bool,
    /// Binding-time preference.
    pub bind: u8,
    /// Highwater mark of the library.
    pub highwater_mark: i16,
}

impl SomShlibListEntry {
    /// Parse a `SomShlibListEntry` from a binary reader.
    pub fn parse(
        reader: &mut BinaryReader,
        string_table_loc: u64,
    ) -> Result<Self, SomException> {
        let name_offset = reader.read_next_i32().map_err(SomException::from)? as u64;
        let shlib_name = reader.read_cstring_at(string_table_loc + name_offset)?;

        let bitfield = reader.read_next_u8().map_err(SomException::from)?;
        let dash_l_reference = (bitfield & 0x1) != 0;
        let internal_name = ((bitfield >> 1) & 0x1) != 0;

        let bind = reader.read_next_u8().map_err(SomException::from)?;
        let highwater_mark = reader.read_next_i16().map_err(SomException::from)?;

        Ok(Self {
            shlib_name,
            internal_name,
            dash_l_reference,
            bind,
            highwater_mark,
        })
    }
}

impl StructConverter for SomShlibListEntry {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Struct {
            name: "shlib_list_entry".to_string(),
            size: SOM_SHLIB_LIST_ENTRY_SIZE as u32,
            fields: vec![
                ("shlib_name".into(), DataTypeDescription::DWord),
                ("bitfield".into(), DataTypeDescription::Byte),
                ("bind".into(), DataTypeDescription::Byte),
                ("highwater_mark".into(), DataTypeDescription::Word),
            ],
        }
    }
}

impl BinaryWritable for SomShlibListEntry {
    fn write_to(&self, writer: &mut BinaryWriter) -> io::Result<()> {
        writer.write_u32(0); // name offset (caller resolves)
        let mut bitfield: u8 = 0;
        if self.dash_l_reference {
            bitfield |= 0x1;
        }
        if self.internal_name {
            bitfield |= 0x2;
        }
        writer.write_u8(bitfield);
        writer.write_u8(self.bind);
        writer.write_i16(self.highwater_mark);
        Ok(())
    }
}

impl fmt::Display for SomShlibListEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SomShlibListEntry {{ name=\"{}\", bind={}, highwater={} }}",
            self.shlib_name, self.bind, self.highwater_mark
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_shlib_data(
        name_offset: u32,
        bitfield: u8,
        bind: u8,
        highwater_mark: i16,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&name_offset.to_le_bytes());
        data.push(bitfield);
        data.push(bind);
        data.extend_from_slice(&highwater_mark.to_le_bytes());
        data
    }

    #[test]
    fn test_parse_shlib() {
        let mut buf = vec![0u8; 0x200];
        let name = b"libc.so\0";
        buf[0x100..0x100 + name.len()].copy_from_slice(name);

        let shlib_data = make_shlib_data(0x100, 0x3, 1, 5);
        buf[0..shlib_data.len()].copy_from_slice(&shlib_data);

        let mut reader = BinaryReader::from_bytes(&buf, true);
        let shlib = SomShlibListEntry::parse(&mut reader, 0).unwrap();

        assert_eq!(shlib.shlib_name, "libc.so");
        assert!(shlib.dash_l_reference);
        assert!(shlib.internal_name);
        assert_eq!(shlib.bind, 1);
        assert_eq!(shlib.highwater_mark, 5);
    }

    #[test]
    fn test_shlib_struct_converter() {
        let mut buf = vec![0u8; 0x200];
        buf[0x100] = b'\0';
        let shlib_data = make_shlib_data(0x100, 0, 0, 0);
        buf[0..shlib_data.len()].copy_from_slice(&shlib_data);

        let mut reader = BinaryReader::from_bytes(&buf, true);
        let shlib = SomShlibListEntry::parse(&mut reader, 0).unwrap();

        let dt = shlib.to_data_type();
        match &dt {
            DataTypeDescription::Struct { name, fields, .. } => {
                assert_eq!(name, "shlib_list_entry");
                assert_eq!(fields.len(), 4);
            }
            _ => panic!("Expected Struct"),
        }
    }

    #[test]
    fn test_shlib_display() {
        let mut buf = vec![0u8; 0x200];
        let name = b"lib\0";
        buf[0x100..0x100 + name.len()].copy_from_slice(name);
        let shlib_data = make_shlib_data(0x100, 0, 2, 10);
        buf[0..shlib_data.len()].copy_from_slice(&shlib_data);

        let mut reader = BinaryReader::from_bytes(&buf, true);
        let shlib = SomShlibListEntry::parse(&mut reader, 0).unwrap();

        let s = format!("{}", shlib);
        assert!(s.contains("lib"));
        assert!(s.contains("bind=2"));
    }

    #[test]
    fn test_shlib_size() {
        assert_eq!(SOM_SHLIB_LIST_ENTRY_SIZE, 0x08);
    }
}
