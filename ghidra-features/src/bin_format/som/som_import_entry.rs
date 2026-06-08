//! SOM import_entry structure ported from Ghidra's `SomImportEntry.java`.

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::binary_writer::{BinaryWritable, BinaryWriter};
use crate::bin_format::types::{DataTypeDescription, StructConverter};

use super::som_exception::SomException;

/// The size in bytes of a `SomImportEntry`.
pub const SOM_IMPORT_ENTRY_SIZE: usize = 0x08;

/// Represents a SOM `import_entry` structure.
///
/// Ported from `ghidra.app.util.bin.format.som.SomImportEntry`.
#[derive(Debug, Clone)]
pub struct SomImportEntry {
    /// The name of the import, or `None` if it doesn't have one.
    pub name: Option<String>,
    /// Whether code imports do not have their address taken in that shared library.
    pub bypassable: bool,
    /// The symbol type (text, data, or bss).
    pub reloc_type: u8,
}

impl SomImportEntry {
    /// Parse a `SomImportEntry` from a binary reader.
    pub fn parse(
        reader: &mut BinaryReader,
        string_table_loc: u64,
    ) -> Result<Self, SomException> {
        let name_index = reader.read_next_i32().map_err(SomException::from)?;
        let name = if name_index != -1 {
            Some(reader.read_cstring_at(string_table_loc + name_index as u64)?)
        } else {
            None
        };

        let bitfield = reader.read_next_i32().map_err(SomException::from)?;
        let bypassable = ((bitfield >> 7) & 0x1) != 0;
        let reloc_type = ((bitfield >> 8) & 0xff) as u8;

        Ok(Self {
            name,
            bypassable,
            reloc_type,
        })
    }

    /// Returns the name of the import, or an empty string if none.
    pub fn name_str(&self) -> &str {
        self.name.as_deref().unwrap_or("")
    }
}

impl StructConverter for SomImportEntry {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Struct {
            name: "import_entry".to_string(),
            size: SOM_IMPORT_ENTRY_SIZE as u32,
            fields: vec![
                ("name".into(), DataTypeDescription::DWord),
                ("bitfield".into(), DataTypeDescription::DWord),
            ],
        }
    }
}

impl BinaryWritable for SomImportEntry {
    fn write_to(&self, writer: &mut BinaryWriter) -> io::Result<()> {
        writer.write_i32(-1); // name offset (caller resolves)
        let mut bitfield: u32 = 0;
        if self.bypassable {
            bitfield |= 1 << 7;
        }
        bitfield |= (self.reloc_type as u32 & 0xff) << 8;
        writer.write_u32(bitfield);
        Ok(())
    }
}

impl fmt::Display for SomImportEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.name {
            Some(n) => write!(f, "SomImportEntry {{ name=\"{}\", type={} }}", n, self.reloc_type),
            None => write!(f, "SomImportEntry {{ name=None, type={} }}", self.reloc_type),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_import_with_name() {
        let mut buf = vec![0u8; 0x200];
        let name = b"printf\0";
        buf[0x100..0x100 + name.len()].copy_from_slice(name);
        buf[0..4].copy_from_slice(&0x100u32.to_le_bytes());
        buf[4..8].copy_from_slice(&(1u32 << 7).to_le_bytes()); // bypassable

        let mut reader = BinaryReader::from_bytes(&buf, true);
        let entry = SomImportEntry::parse(&mut reader, 0).unwrap();

        assert_eq!(entry.name.as_deref(), Some("printf"));
        assert!(entry.bypassable);
    }

    #[test]
    fn test_parse_import_null_name() {
        let mut buf = vec![0u8; 8];
        buf[0..4].copy_from_slice(&(-1i32).to_le_bytes());

        let mut reader = BinaryReader::from_bytes(&buf, true);
        let entry = SomImportEntry::parse(&mut reader, 0).unwrap();

        assert!(entry.name.is_none());
        assert_eq!(entry.name_str(), "");
    }

    #[test]
    fn test_import_display() {
        let mut buf = vec![0u8; 0x200];
        let name = b"func\0";
        buf[0x100..0x100 + name.len()].copy_from_slice(name);
        buf[0..4].copy_from_slice(&0x100u32.to_le_bytes());
        buf[4..8].copy_from_slice(&0u32.to_le_bytes());

        let mut reader = BinaryReader::from_bytes(&buf, true);
        let entry = SomImportEntry::parse(&mut reader, 0).unwrap();

        let s = format!("{}", entry);
        assert!(s.contains("func"));
    }

    #[test]
    fn test_import_size() {
        assert_eq!(SOM_IMPORT_ENTRY_SIZE, 0x08);
    }
}
