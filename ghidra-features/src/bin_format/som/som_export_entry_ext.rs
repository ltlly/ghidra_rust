//! SOM export_entry_ext structure ported from Ghidra's `SomExportEntryExt.java`.

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::binary_writer::{BinaryWritable, BinaryWriter};
use crate::bin_format::types::{DataTypeDescription, StructConverter};

use super::som_exception::SomException;

/// The size in bytes of a `SomExportEntryExt`.
pub const SOM_EXPORT_ENTRY_EXT_SIZE: usize = 0x14;

/// Represents a SOM `export_entry_ext` structure.
///
/// Ported from `ghidra.app.util.bin.format.som.SomExportEntryExt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SomExportEntryExt {
    /// Size of the export symbol (only valid for exports of type ST_DATA).
    pub size: i32,
    /// Start of the dreloc records for the exported symbol.
    pub dreloc: i32,
    /// Circular list of exports that have the same value (physical location) in the library.
    pub same_list: i32,
    /// Reserved.
    pub reserved2: i32,
    /// Reserved.
    pub reserved3: i32,
}

impl SomExportEntryExt {
    /// Parse a `SomExportEntryExt` from a binary reader.
    pub fn parse(reader: &mut BinaryReader) -> Result<Self, SomException> {
        let size = reader.read_next_i32().map_err(SomException::from)?;
        let dreloc = reader.read_next_i32().map_err(SomException::from)?;
        let same_list = reader.read_next_i32().map_err(SomException::from)?;
        let reserved2 = reader.read_next_i32().map_err(SomException::from)?;
        let reserved3 = reader.read_next_i32().map_err(SomException::from)?;
        Ok(Self {
            size,
            dreloc,
            same_list,
            reserved2,
            reserved3,
        })
    }
}

impl StructConverter for SomExportEntryExt {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Struct {
            name: "export_entry_ext".to_string(),
            size: SOM_EXPORT_ENTRY_EXT_SIZE as u32,
            fields: vec![
                ("size".into(), DataTypeDescription::DWord),
                ("dreloc".into(), DataTypeDescription::DWord),
                ("same_list".into(), DataTypeDescription::DWord),
                ("reserved2".into(), DataTypeDescription::DWord),
                ("reserved3".into(), DataTypeDescription::DWord),
            ],
        }
    }
}

impl BinaryWritable for SomExportEntryExt {
    fn write_to(&self, writer: &mut BinaryWriter) -> io::Result<()> {
        writer.write_i32(self.size);
        writer.write_i32(self.dreloc);
        writer.write_i32(self.same_list);
        writer.write_i32(self.reserved2);
        writer.write_i32(self.reserved3);
        Ok(())
    }
}

impl fmt::Display for SomExportEntryExt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SomExportEntryExt {{ size={}, dreloc=0x{:x}, same_list=0x{:x} }}",
            self.size, self.dreloc as u32, self.same_list as u32
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_export_entry_ext() {
        let mut data = Vec::new();
        data.extend_from_slice(&100i32.to_le_bytes());
        data.extend_from_slice(&0x1000i32.to_le_bytes());
        data.extend_from_slice(&0x2000i32.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());

        let mut reader = BinaryReader::from_bytes(&data, true);
        let ext = SomExportEntryExt::parse(&mut reader).unwrap();

        assert_eq!(ext.size, 100);
        assert_eq!(ext.dreloc, 0x1000);
        assert_eq!(ext.same_list, 0x2000);
    }

    #[test]
    fn test_export_entry_ext_struct_converter() {
        let data = vec![0u8; 0x14];
        let mut reader = BinaryReader::from_bytes(&data, true);
        let ext = SomExportEntryExt::parse(&mut reader).unwrap();

        let dt = ext.to_data_type();
        match &dt {
            DataTypeDescription::Struct { name, fields, .. } => {
                assert_eq!(name, "export_entry_ext");
                assert_eq!(fields.len(), 5);
            }
            _ => panic!("Expected Struct"),
        }
    }

    #[test]
    fn test_export_entry_ext_display() {
        let data = vec![0u8; 0x14];
        let mut reader = BinaryReader::from_bytes(&data, true);
        let ext = SomExportEntryExt::parse(&mut reader).unwrap();

        let s = format!("{}", ext);
        assert!(s.contains("SomExportEntryExt"));
    }

    #[test]
    fn test_export_entry_ext_size() {
        assert_eq!(SOM_EXPORT_ENTRY_EXT_SIZE, 0x14);
    }
}
