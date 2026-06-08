//! SOM module_entry structure ported from Ghidra's `SomModuleEntry.java`.

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::binary_writer::{BinaryWritable, BinaryWriter};
use crate::bin_format::types::{DataTypeDescription, StructConverter};

use super::som_exception::SomException;

/// The size in bytes of a `SomModuleEntry`.
pub const SOM_MODULE_ENTRY_SIZE: usize = 0x14;

/// Represents a SOM `module_entry` structure.
///
/// Ported from `ghidra.app.util.bin.format.som.SomModuleEntry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SomModuleEntry {
    /// Text offset into the module dynamic relocation array.
    pub drelocs: i32,
    /// Text offset into the module import array.
    pub imports: i32,
    /// Number of entries in the module import array.
    pub import_count: i32,
    /// Flags (currently: ELAB_REF).
    pub flags: u8,
    /// Number of modules the current module needs to have bound before all of its own
    /// import symbols can be found.
    pub module_dependencies: u16,
}

impl SomModuleEntry {
    /// Parse a `SomModuleEntry` from a binary reader.
    pub fn parse(reader: &mut BinaryReader) -> Result<Self, SomException> {
        let drelocs = reader.read_next_i32().map_err(SomException::from)?;
        let imports = reader.read_next_i32().map_err(SomException::from)?;
        let import_count = reader.read_next_i32().map_err(SomException::from)?;
        let flags = reader.read_next_u8().map_err(SomException::from)?;
        let _reserved1 = reader.read_next_u8().map_err(SomException::from)?;
        let module_dependencies = reader.read_next_u16().map_err(SomException::from)?;
        let _reserved2 = reader.read_next_i32().map_err(SomException::from)?;

        Ok(Self {
            drelocs,
            imports,
            import_count,
            flags,
            module_dependencies,
        })
    }
}

impl StructConverter for SomModuleEntry {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Struct {
            name: "module_entry".to_string(),
            size: SOM_MODULE_ENTRY_SIZE as u32,
            fields: vec![
                ("drelocs".into(), DataTypeDescription::DWord),
                ("imports".into(), DataTypeDescription::DWord),
                ("imports_count".into(), DataTypeDescription::DWord),
                ("flags".into(), DataTypeDescription::Byte),
                ("reserved1".into(), DataTypeDescription::Byte),
                ("module_dependencies".into(), DataTypeDescription::Word),
                ("reserved2".into(), DataTypeDescription::DWord),
            ],
        }
    }
}

impl BinaryWritable for SomModuleEntry {
    fn write_to(&self, writer: &mut BinaryWriter) -> io::Result<()> {
        writer.write_i32(self.drelocs);
        writer.write_i32(self.imports);
        writer.write_i32(self.import_count);
        writer.write_u8(self.flags);
        writer.write_u8(0); // reserved1
        writer.write_u16(self.module_dependencies);
        writer.write_i32(0); // reserved2
        Ok(())
    }
}

impl fmt::Display for SomModuleEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SomModuleEntry {{ drelocs=0x{:x}, imports=0x{:x}, import_count={}, deps={} }}",
            self.drelocs as u32,
            self.imports as u32,
            self.import_count,
            self.module_dependencies
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_module_entry() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000i32.to_le_bytes()); // drelocs
        data.extend_from_slice(&0x2000i32.to_le_bytes()); // imports
        data.extend_from_slice(&5i32.to_le_bytes());      // import_count
        data.push(1u8);                                    // flags
        data.push(0u8);                                    // reserved1
        data.extend_from_slice(&3u16.to_le_bytes());       // module_dependencies
        data.extend_from_slice(&0i32.to_le_bytes());       // reserved2

        let mut reader = BinaryReader::from_bytes(&data, true);
        let entry = SomModuleEntry::parse(&mut reader).unwrap();

        assert_eq!(entry.drelocs, 0x1000);
        assert_eq!(entry.imports, 0x2000);
        assert_eq!(entry.import_count, 5);
        assert_eq!(entry.flags, 1);
        assert_eq!(entry.module_dependencies, 3);
    }

    #[test]
    fn test_module_entry_write_roundtrip() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000i32.to_le_bytes());
        data.extend_from_slice(&0x2000i32.to_le_bytes());
        data.extend_from_slice(&5i32.to_le_bytes());
        data.push(1u8);
        data.push(0u8);
        data.extend_from_slice(&3u16.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());

        let mut reader = BinaryReader::from_bytes(&data, true);
        let entry = SomModuleEntry::parse(&mut reader).unwrap();

        let mut writer = BinaryWriter::new(true);
        entry.write_to(&mut writer).unwrap();
        assert_eq!(writer.into_vec(), data);
    }

    #[test]
    fn test_module_entry_struct_converter() {
        let data = vec![0u8; 0x14];
        let mut reader = BinaryReader::from_bytes(&data, true);
        let entry = SomModuleEntry::parse(&mut reader).unwrap();

        let dt = entry.to_data_type();
        match &dt {
            DataTypeDescription::Struct { name, fields, .. } => {
                assert_eq!(name, "module_entry");
                assert_eq!(fields.len(), 7);
            }
            _ => panic!("Expected Struct"),
        }
    }

    #[test]
    fn test_module_entry_display() {
        let data = vec![0u8; 0x14];
        let mut reader = BinaryReader::from_bytes(&data, true);
        let entry = SomModuleEntry::parse(&mut reader).unwrap();

        let s = format!("{}", entry);
        assert!(s.contains("SomModuleEntry"));
    }

    #[test]
    fn test_module_entry_size() {
        assert_eq!(SOM_MODULE_ENTRY_SIZE, 0x14);
    }
}
