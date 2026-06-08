//! SOM PLT_entry structure ported from Ghidra's `SomPltEntry.java`.

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::binary_writer::{BinaryWritable, BinaryWriter};
use crate::bin_format::types::{DataTypeDescription, StructConverter};

use super::som_exception::SomException;

/// The size in bytes of a `SomPltEntry`.
pub const SOM_PLT_ENTRY_SIZE: usize = 0x08;

/// Represents a SOM `PLT_entry` structure.
///
/// Ported from `ghidra.app.util.bin.format.som.SomPltEntry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SomPltEntry {
    /// Address of the procedure to be branched to.
    pub proc_addr: i32,
    /// Import index of the code symbol (if proc_addr points to BOR routine).
    pub ltptr_value: i32,
}

impl SomPltEntry {
    /// Parse a `SomPltEntry` from a binary reader.
    pub fn parse(reader: &mut BinaryReader) -> Result<Self, SomException> {
        let proc_addr = reader.read_next_i32().map_err(SomException::from)?;
        let ltptr_value = reader.read_next_i32().map_err(SomException::from)?;
        Ok(Self {
            proc_addr,
            ltptr_value,
        })
    }
}

impl StructConverter for SomPltEntry {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Struct {
            name: "PLT_entry".to_string(),
            size: SOM_PLT_ENTRY_SIZE as u32,
            fields: vec![
                ("proc_addr".into(), DataTypeDescription::DWord),
                ("ltptr_value".into(), DataTypeDescription::DWord),
            ],
        }
    }
}

impl BinaryWritable for SomPltEntry {
    fn write_to(&self, writer: &mut BinaryWriter) -> io::Result<()> {
        writer.write_i32(self.proc_addr);
        writer.write_i32(self.ltptr_value);
        Ok(())
    }
}

impl fmt::Display for SomPltEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SomPltEntry {{ proc_addr=0x{:x}, ltptr_value={} }}",
            self.proc_addr as u32, self.ltptr_value
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_plt_entry() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x4000i32.to_le_bytes());
        data.extend_from_slice(&5i32.to_le_bytes());

        let mut reader = BinaryReader::from_bytes(&data, true);
        let entry = SomPltEntry::parse(&mut reader).unwrap();

        assert_eq!(entry.proc_addr, 0x4000);
        assert_eq!(entry.ltptr_value, 5);
    }

    #[test]
    fn test_plt_entry_write_roundtrip() {
        let mut data = Vec::new();
        data.extend_from_slice(&0xDEADBEEFu32.to_le_bytes());
        data.extend_from_slice(&42i32.to_le_bytes());

        let mut reader = BinaryReader::from_bytes(&data, true);
        let entry = SomPltEntry::parse(&mut reader).unwrap();

        let mut writer = BinaryWriter::new(true);
        entry.write_to(&mut writer).unwrap();
        assert_eq!(writer.into_vec(), data);
    }

    #[test]
    fn test_plt_entry_display() {
        let data = vec![0u8; 8];
        let mut reader = BinaryReader::from_bytes(&data, true);
        let entry = SomPltEntry::parse(&mut reader).unwrap();

        let s = format!("{}", entry);
        assert!(s.contains("SomPltEntry"));
    }

    #[test]
    fn test_plt_entry_size() {
        assert_eq!(SOM_PLT_ENTRY_SIZE, 0x08);
    }
}
