//! SOM export_entry structure ported from Ghidra's `SomExportEntry.java`.

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::binary_writer::{BinaryWritable, BinaryWriter};
use crate::bin_format::types::{DataTypeDescription, StructConverter};

use super::som_exception::SomException;

/// The size in bytes of a `SomExportEntry`.
pub const SOM_EXPORT_ENTRY_SIZE: usize = 0x14;

/// Represents a SOM `export_entry` structure.
///
/// Ported from `ghidra.app.util.bin.format.som.SomExportEntry`.
#[derive(Debug, Clone)]
pub struct SomExportEntry {
    /// Next export record in the hash chain.
    pub next: i32,
    /// The symbol name (from string table).
    pub name: Option<String>,
    /// Symbol address (subject to relocation).
    pub value: i32,
    /// Size of storage request (STORAGE type) or version + arg relocation info.
    pub info: i32,
    /// Symbol type (see `SomConstants::SYMBOL_*`).
    pub symbol_type: u8,
    /// Whether this is a TLS export.
    pub is_tp_relative: bool,
    /// Index into the module table of the module defining this symbol.
    pub module_index: i16,
}

impl SomExportEntry {
    /// Parse a `SomExportEntry` from a binary reader.
    pub fn parse(
        reader: &mut BinaryReader,
        string_table_loc: u64,
    ) -> Result<Self, SomException> {
        let next = reader.read_next_i32().map_err(SomException::from)?;
        let name_index = reader.read_next_i32().map_err(SomException::from)?;
        let name = if name_index != -1 {
            Some(reader.read_cstring_at(string_table_loc + name_index as u64)?)
        } else {
            None
        };
        let value = reader.read_next_i32().map_err(SomException::from)?;
        let info = reader.read_next_i32().map_err(SomException::from)?;
        let symbol_type = reader.read_next_u8().map_err(SomException::from)?;
        let bitfield = reader.read_next_u8().map_err(SomException::from)?;
        let is_tp_relative = ((bitfield >> 7) & 0x1) != 0;
        let module_index = reader.read_next_i16().map_err(SomException::from)?;

        Ok(Self {
            next,
            name,
            value,
            info,
            symbol_type,
            is_tp_relative,
            module_index,
        })
    }

    /// Returns the name of the export, or an empty string if none.
    pub fn name_str(&self) -> &str {
        self.name.as_deref().unwrap_or("")
    }
}

impl StructConverter for SomExportEntry {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Struct {
            name: "export_entry".to_string(),
            size: SOM_EXPORT_ENTRY_SIZE as u32,
            fields: vec![
                ("next".into(), DataTypeDescription::DWord),
                ("name".into(), DataTypeDescription::DWord),
                ("value".into(), DataTypeDescription::DWord),
                ("info".into(), DataTypeDescription::DWord),
                ("type".into(), DataTypeDescription::Byte),
                ("flags".into(), DataTypeDescription::Byte),
                ("module_index".into(), DataTypeDescription::Word),
            ],
        }
    }
}

impl BinaryWritable for SomExportEntry {
    fn write_to(&self, writer: &mut BinaryWriter) -> io::Result<()> {
        writer.write_i32(self.next);
        writer.write_i32(-1); // name offset (caller resolves)
        writer.write_i32(self.value);
        writer.write_i32(self.info);
        writer.write_u8(self.symbol_type);
        let mut flags: u8 = 0;
        if self.is_tp_relative {
            flags |= 1 << 7;
        }
        writer.write_u8(flags);
        writer.write_i16(self.module_index);
        Ok(())
    }
}

impl fmt::Display for SomExportEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SomExportEntry {{ name=\"{}\", type={}, value=0x{:x} }}",
            self.name_str(),
            self.symbol_type,
            self.value as u32
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_export() {
        let mut buf = vec![0u8; 0x200];
        let name = b"main\0";
        buf[0x100..0x100 + name.len()].copy_from_slice(name);

        // next=0, name_offset=0x100, value=0x4000, info=0, type=3, flags=0, module_index=0
        let mut data = Vec::new();
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&0x100i32.to_le_bytes());
        data.extend_from_slice(&0x4000i32.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());
        data.push(3u8); // CODE
        data.push(0u8); // flags
        data.extend_from_slice(&0i16.to_le_bytes());
        buf[0..data.len()].copy_from_slice(&data);

        let mut reader = BinaryReader::from_bytes(&buf, true);
        let entry = SomExportEntry::parse(&mut reader, 0).unwrap();

        assert_eq!(entry.name.as_deref(), Some("main"));
        assert_eq!(entry.symbol_type, 3);
        assert_eq!(entry.value, 0x4000);
    }

    #[test]
    fn test_export_display() {
        let mut buf = vec![0u8; 0x200];
        let name = b"func\0";
        buf[0x100..0x100 + name.len()].copy_from_slice(name);

        let mut data = Vec::new();
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&0x100i32.to_le_bytes());
        data.extend_from_slice(&0x4000i32.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());
        data.push(2u8);
        data.push(0u8);
        data.extend_from_slice(&0i16.to_le_bytes());
        buf[0..data.len()].copy_from_slice(&data);

        let mut reader = BinaryReader::from_bytes(&buf, true);
        let entry = SomExportEntry::parse(&mut reader, 0).unwrap();

        let s = format!("{}", entry);
        assert!(s.contains("func"));
        assert!(s.contains("type=2"));
    }

    #[test]
    fn test_export_size() {
        assert_eq!(SOM_EXPORT_ENTRY_SIZE, 0x14);
    }
}
