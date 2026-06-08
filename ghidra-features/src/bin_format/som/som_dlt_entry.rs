//! SOM DLT value structure ported from Ghidra's `SomDltEntry.java`.

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::binary_writer::{BinaryWritable, BinaryWriter};
use crate::bin_format::types::{DataTypeDescription, StructConverter};

use super::som_exception::SomException;

/// The size in bytes of a `SomDltEntry`.
pub const SOM_DLT_ENTRY_SIZE: usize = 0x04;

/// Represents a SOM `DLT` value.
///
/// Ported from `ghidra.app.util.bin.format.som.SomDltEntry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SomDltEntry {
    /// The value of the DLT entry.
    pub value: i32,
}

impl SomDltEntry {
    /// Parse a `SomDltEntry` from a binary reader.
    pub fn parse(reader: &mut BinaryReader) -> Result<Self, SomException> {
        let value = reader.read_next_i32().map_err(SomException::from)?;
        Ok(Self { value })
    }
}

impl StructConverter for SomDltEntry {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Pointer
    }
}

impl BinaryWritable for SomDltEntry {
    fn write_to(&self, writer: &mut BinaryWriter) -> io::Result<()> {
        writer.write_i32(self.value);
        Ok(())
    }
}

impl fmt::Display for SomDltEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SomDltEntry {{ value=0x{:x} }}", self.value as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dlt_entry() {
        let data = 0x12345678i32.to_le_bytes();
        let mut reader = BinaryReader::from_bytes(&data, true);
        let entry = SomDltEntry::parse(&mut reader).unwrap();
        assert_eq!(entry.value, 0x12345678u32 as i32);
    }

    #[test]
    fn test_dlt_entry_write_roundtrip() {
        let data = 0xCAFEBABEu32.to_le_bytes();
        let mut reader = BinaryReader::from_bytes(&data, true);
        let entry = SomDltEntry::parse(&mut reader).unwrap();

        let mut writer = BinaryWriter::new(true);
        entry.write_to(&mut writer).unwrap();
        assert_eq!(writer.into_vec(), data);
    }

    #[test]
    fn test_dlt_entry_display() {
        let data = 42i32.to_le_bytes();
        let mut reader = BinaryReader::from_bytes(&data, true);
        let entry = SomDltEntry::parse(&mut reader).unwrap();

        let s = format!("{}", entry);
        assert!(s.contains("0x2a"));
    }

    #[test]
    fn test_dlt_entry_size() {
        assert_eq!(SOM_DLT_ENTRY_SIZE, 0x04);
    }
}
