//! SOM aux_id structure ported from Ghidra's `SomAuxId.java`.
//!
//! Represents a SOM `aux_id` structure -- the identifier at the front of
//! every SOM auxiliary header.
//!
//! Reference: [The 32-bit PA-RISC Run-time Architecture Document](https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf)

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::binary_writer::{BinaryWritable, BinaryWriter};
use crate::bin_format::types::{DataTypeDescription, StructConverter};

use super::som_exception::SomException;

/// The size in bytes of a `SomAuxId`.
pub const SOM_AUX_ID_SIZE: usize = 0x08;

/// Represents a SOM `aux_id` structure.
///
/// Every SOM auxiliary header begins with this identifier, which describes
/// the type and length of the auxiliary header data that follows.
///
/// Ported from `ghidra.app.util.bin.format.som.SomAuxId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SomAuxId {
    /// Whether this auxiliary header contains information that the linker must understand.
    pub mandatory: bool,
    /// Whether this auxiliary header is to be copied without modification to any new SOM
    /// created from this SOM.
    pub copy: bool,
    /// Whether this auxiliary header is to be merged (concatenation of data) when multiple
    /// entries with the same type exist.
    pub append: bool,
    /// Whether this auxiliary header should be ignored if its type field is unknown.
    pub ignore: bool,
    /// Reserved for future expansion.
    pub reserved: u16,
    /// The type of auxiliary header.
    pub aux_type: u16,
    /// The length of the auxiliary header in bytes (does NOT include the two word identifiers
    /// at the front of the header).
    pub length: u32,
}

impl SomAuxId {
    /// Parse a `SomAuxId` from a binary reader at the current position.
    ///
    /// # Errors
    ///
    /// Returns `SomException` if an I/O error occurs.
    pub fn parse(reader: &mut BinaryReader) -> Result<Self, SomException> {
        let bitfield = reader.read_next_i32().map_err(SomException::from)?;
        let aux_type = (bitfield & 0xFFFF) as u16;
        let reserved = ((bitfield >> 16) & 0xFFF) as u16;
        let ignore = ((bitfield >> 28) & 0x1) != 0;
        let append = ((bitfield >> 29) & 0x1) != 0;
        let copy = ((bitfield >> 30) & 0x1) != 0;
        let mandatory = ((bitfield >> 31) & 0x1) != 0;
        let length = reader.read_next_u32().map_err(SomException::from)?;

        Ok(Self {
            mandatory,
            copy,
            append,
            ignore,
            reserved,
            aux_type,
            length,
        })
    }

    /// Returns the total length of the auxiliary header including the aux_id.
    pub fn total_length(&self) -> u64 {
        self.length as u64 + SOM_AUX_ID_SIZE as u64
    }
}

impl StructConverter for SomAuxId {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Struct {
            name: "aux_id".to_string(),
            size: SOM_AUX_ID_SIZE as u32,
            fields: vec![
                // First DWORD is a bitfield, represented as a single DWORD for simplicity
                ("bitfield".into(), DataTypeDescription::DWord),
                ("length".into(), DataTypeDescription::DWord),
            ],
        }
    }
}

impl BinaryWritable for SomAuxId {
    fn write_to(&self, writer: &mut BinaryWriter) -> io::Result<()> {
        let mut bitfield: u32 = self.aux_type as u32 & 0xFFFF;
        bitfield |= (self.reserved as u32 & 0xFFF) << 16;
        if self.ignore {
            bitfield |= 1 << 28;
        }
        if self.append {
            bitfield |= 1 << 29;
        }
        if self.copy {
            bitfield |= 1 << 30;
        }
        if self.mandatory {
            bitfield |= 1 << 31;
        }
        writer.write_u32(bitfield);
        writer.write_u32(self.length);
        Ok(())
    }
}

impl fmt::Display for SomAuxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SomAuxId {{ type={}, length={}, mandatory={}, copy={}, append={}, ignore={} }}",
            self.aux_type, self.length, self.mandatory, self.copy, self.append, self.ignore
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_aux_id_bytes(
        mandatory: bool,
        copy: bool,
        append: bool,
        ignore: bool,
        aux_type: u16,
        length: u32,
    ) -> Vec<u8> {
        let mut bitfield: u32 = aux_type as u32 & 0xFFFF;
        if ignore {
            bitfield |= 1 << 28;
        }
        if append {
            bitfield |= 1 << 29;
        }
        if copy {
            bitfield |= 1 << 30;
        }
        if mandatory {
            bitfield |= 1 << 31;
        }
        let mut data = Vec::new();
        data.extend_from_slice(&bitfield.to_le_bytes());
        data.extend_from_slice(&length.to_le_bytes());
        data
    }

    #[test]
    fn test_parse_aux_id_basic() {
        let data = make_aux_id_bytes(false, false, false, false, 4, 0x28);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let aux_id = SomAuxId::parse(&mut reader).unwrap();

        assert!(!aux_id.mandatory);
        assert!(!aux_id.copy);
        assert!(!aux_id.append);
        assert!(!aux_id.ignore);
        assert_eq!(aux_id.aux_type, 4);
        assert_eq!(aux_id.length, 0x28);
    }

    #[test]
    fn test_parse_aux_id_with_flags() {
        let data = make_aux_id_bytes(true, true, true, true, 1, 100);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let aux_id = SomAuxId::parse(&mut reader).unwrap();

        assert!(aux_id.mandatory);
        assert!(aux_id.copy);
        assert!(aux_id.append);
        assert!(aux_id.ignore);
        assert_eq!(aux_id.aux_type, 1);
        assert_eq!(aux_id.length, 100);
    }

    #[test]
    fn test_aux_id_total_length() {
        let data = make_aux_id_bytes(false, false, false, false, 4, 0x28);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let aux_id = SomAuxId::parse(&mut reader).unwrap();

        assert_eq!(aux_id.total_length(), 0x28 + 8);
    }

    #[test]
    fn test_aux_id_write_roundtrip() {
        let data = make_aux_id_bytes(true, false, true, false, 4, 0x28);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let aux_id = SomAuxId::parse(&mut reader).unwrap();

        let mut writer = BinaryWriter::new(true);
        aux_id.write_to(&mut writer).unwrap();
        let written = writer.into_vec();
        assert_eq!(written, data);
    }

    #[test]
    fn test_aux_id_truncated() {
        let data = vec![0x01, 0x02, 0x03]; // too short
        let mut reader = BinaryReader::from_bytes(&data, true);
        let result = SomAuxId::parse(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn test_aux_id_struct_converter() {
        let data = make_aux_id_bytes(false, false, false, false, 4, 0x28);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let aux_id = SomAuxId::parse(&mut reader).unwrap();

        let dt = aux_id.to_data_type();
        match &dt {
            DataTypeDescription::Struct { name, fields, .. } => {
                assert_eq!(name, "aux_id");
                assert_eq!(fields.len(), 2);
                assert_eq!(fields[0].0, "bitfield");
                assert_eq!(fields[1].0, "length");
            }
            _ => panic!("Expected Struct"),
        }
    }

    #[test]
    fn test_aux_id_display() {
        let data = make_aux_id_bytes(true, false, false, false, 4, 0x28);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let aux_id = SomAuxId::parse(&mut reader).unwrap();

        let s = format!("{}", aux_id);
        assert!(s.contains("type=4"));
        assert!(s.contains("length=40"));
        assert!(s.contains("mandatory=true"));
    }

    #[test]
    fn test_aux_id_equality() {
        let data = make_aux_id_bytes(false, false, false, false, 4, 0x28);
        let mut reader1 = BinaryReader::from_bytes(&data, true);
        let mut reader2 = BinaryReader::from_bytes(&data, true);
        let a = SomAuxId::parse(&mut reader1).unwrap();
        let b = SomAuxId::parse(&mut reader2).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_aux_id_size() {
        assert_eq!(SOM_AUX_ID_SIZE, 8);
    }
}
