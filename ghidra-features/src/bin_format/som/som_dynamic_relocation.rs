//! SOM dreloc_record structure ported from Ghidra's `SomDynamicRelocation.java`.
//!
//! Represents a SOM `dreloc_record` structure.
//!
//! Reference: [The 32-bit PA-RISC Run-time Architecture Document](https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf)

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::binary_writer::{BinaryWritable, BinaryWriter};
use crate::bin_format::types::{DataTypeDescription, StructConverter};

use super::som_constants::dr_type_name;
use super::som_exception::SomException;

/// The size in bytes of a `SomDynamicRelocation`.
pub const SOM_DYNAMIC_RELOCATION_SIZE: usize = 0x14;

/// Represents a SOM `dreloc_record` structure.
///
/// Ported from `ghidra.app.util.bin.format.som.SomDynamicRelocation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SomDynamicRelocation {
    /// Shared library name (currently reserved).
    pub shlib: i32,
    /// Index into import table if the relocation is an external type.
    pub symbol: i32,
    /// Data-relative offset of the data item the dreloc record refers to.
    pub location: i32,
    /// Text or data-relative offset to use for a patch if internal fixup type.
    pub value: i32,
    /// Type of dynamic relocation (see `SomConstants::DR_*`).
    pub reloc_type: u8,
    /// Reserved byte.
    pub reserved: u8,
    /// Module index (currently reserved).
    pub module_index: i16,
}

impl SomDynamicRelocation {
    /// Parse a `SomDynamicRelocation` from a binary reader.
    pub fn parse(reader: &mut BinaryReader) -> Result<Self, SomException> {
        let shlib = reader.read_next_i32().map_err(SomException::from)?;
        let symbol = reader.read_next_i32().map_err(SomException::from)?;
        let location = reader.read_next_i32().map_err(SomException::from)?;
        let value = reader.read_next_i32().map_err(SomException::from)?;
        let reloc_type = reader.read_next_u8().map_err(SomException::from)?;
        let reserved = reader.read_next_i8().map_err(SomException::from)? as u8;
        let module_index = reader.read_next_i16().map_err(SomException::from)?;

        Ok(Self {
            shlib,
            symbol,
            location,
            value,
            reloc_type,
            reserved,
            module_index,
        })
    }

    /// Returns the type name of this relocation.
    pub fn type_name(&self) -> &'static str {
        dr_type_name(self.reloc_type)
    }
}

impl StructConverter for SomDynamicRelocation {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Struct {
            name: "dreloc_record".to_string(),
            size: SOM_DYNAMIC_RELOCATION_SIZE as u32,
            fields: vec![
                ("shlib".into(), DataTypeDescription::DWord),
                ("symbol".into(), DataTypeDescription::DWord),
                ("location".into(), DataTypeDescription::DWord),
                ("value".into(), DataTypeDescription::DWord),
                ("type".into(), DataTypeDescription::Byte),
                ("reserved".into(), DataTypeDescription::Byte),
                ("module_index".into(), DataTypeDescription::Word),
            ],
        }
    }
}

impl BinaryWritable for SomDynamicRelocation {
    fn write_to(&self, writer: &mut BinaryWriter) -> io::Result<()> {
        writer.write_i32(self.shlib);
        writer.write_i32(self.symbol);
        writer.write_i32(self.location);
        writer.write_i32(self.value);
        writer.write_u8(self.reloc_type);
        writer.write_u8(self.reserved);
        writer.write_i16(self.module_index);
        Ok(())
    }
}

impl fmt::Display for SomDynamicRelocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SomDynamicRelocation {{ type={}, symbol={}, location=0x{:x}, value=0x{:x} }}",
            self.type_name(),
            self.symbol,
            self.location as u32,
            self.value as u32
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dreloc_bytes(
        shlib: i32,
        symbol: i32,
        location: i32,
        value: i32,
        reloc_type: u8,
        reserved: u8,
        module_index: i16,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&shlib.to_le_bytes());
        data.extend_from_slice(&symbol.to_le_bytes());
        data.extend_from_slice(&location.to_le_bytes());
        data.extend_from_slice(&value.to_le_bytes());
        data.push(reloc_type);
        data.push(reserved);
        data.extend_from_slice(&module_index.to_le_bytes());
        data
    }

    #[test]
    fn test_parse_dreloc() {
        let data = make_dreloc_bytes(0, 5, 0x100, 0x200, 1, 0, 0);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let dreloc = SomDynamicRelocation::parse(&mut reader).unwrap();

        assert_eq!(dreloc.symbol, 5);
        assert_eq!(dreloc.location, 0x100);
        assert_eq!(dreloc.value, 0x200);
        assert_eq!(dreloc.reloc_type, 1);
        assert_eq!(dreloc.type_name(), "PLABEL_EXT");
    }

    #[test]
    fn test_dreloc_struct_converter() {
        let data = make_dreloc_bytes(0, 0, 0, 0, 3, 0, 0);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let dreloc = SomDynamicRelocation::parse(&mut reader).unwrap();

        let dt = dreloc.to_data_type();
        match &dt {
            DataTypeDescription::Struct { name, fields, .. } => {
                assert_eq!(name, "dreloc_record");
                assert_eq!(fields.len(), 7);
            }
            _ => panic!("Expected Struct"),
        }
    }

    #[test]
    fn test_dreloc_write_roundtrip() {
        let data = make_dreloc_bytes(1, 2, 3, 4, 5, 6, 7);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let dreloc = SomDynamicRelocation::parse(&mut reader).unwrap();

        let mut writer = BinaryWriter::new(true);
        dreloc.write_to(&mut writer).unwrap();
        let written = writer.into_vec();
        assert_eq!(written, data);
    }

    #[test]
    fn test_dreloc_display() {
        let data = make_dreloc_bytes(0, 5, 0x100, 0x200, 1, 0, 0);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let dreloc = SomDynamicRelocation::parse(&mut reader).unwrap();

        let s = format!("{}", dreloc);
        assert!(s.contains("PLABEL_EXT"));
        assert!(s.contains("symbol=5"));
    }

    #[test]
    fn test_dreloc_size() {
        assert_eq!(SOM_DYNAMIC_RELOCATION_SIZE, 0x14);
    }
}
