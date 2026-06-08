//! SOM subspace_dictionary_record structure ported from Ghidra's `SomSubspace.java`.
//!
//! Represents a SOM `subspace_dictionary_record` structure.
//!
//! Reference: [The 32-bit PA-RISC Run-time Architecture Document](https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf)

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::binary_writer::{BinaryWritable, BinaryWriter};
use crate::bin_format::types::{DataTypeDescription, StructConverter};

use super::som_exception::SomException;

/// The size in bytes of a `SomSubspace`.
pub const SOM_SUBSPACE_SIZE: usize = 0x28;

/// Represents a SOM `subspace_dictionary_record` structure.
///
/// Ported from `ghidra.app.util.bin.format.som.SomSubspace`.
#[derive(Debug, Clone)]
pub struct SomSubspace {
    /// The space index this subspace belongs to.
    pub space_index: i32,
    /// Access control bits for PDIR entries (7 bits).
    pub access_control_bits: u8,
    /// Whether to lock in memory during execution.
    pub memory_resident: bool,
    /// Whether data name clashes are allowed.
    pub dup_common: bool,
    /// Whether the subspace is a common.
    pub is_common: bool,
    /// Whether the subspace is loadable.
    pub is_loadable: bool,
    /// Quadrant request (2 bits).
    pub quadrant: u8,
    /// Whether the subspace must be locked into memory when the OS is booted.
    pub initially_frozen: bool,
    /// Whether this must be the first subspace.
    pub is_first: bool,
    /// Whether the subspace must contain only code.
    pub code_only: bool,
    /// Sort key for the subspace.
    pub sort_key: u8,
    /// Whether init values are replicated to fill `subspace_length`.
    pub replicate_init: bool,
    /// Whether this subspace is a continuation.
    pub continuation: bool,
    /// Whether the subspace is thread specific.
    pub is_thread_specific: bool,
    /// Whether this is for COMDAT subspaces.
    pub is_comdat: bool,
    /// First reserved value (4 bits).
    pub reserved: u8,
    /// File location or initialization value.
    pub file_loc_init_value: i32,
    /// Initialization length.
    pub initialization_length: u32,
    /// Starting offset.
    pub subspace_start: u32,
    /// Number of bytes defined by this subspace.
    pub subspace_length: u32,
    /// Alignment required for the subspace (27 bits).
    pub alignment: u32,
    /// The subspace name (read from the space strings area).
    pub name: String,
    /// Index into fixup array.
    pub fixup_request_index: i32,
    /// Number of fixup requests.
    pub fixup_request_quantity: u32,
}

impl SomSubspace {
    /// Parse a `SomSubspace` from a binary reader at the current position.
    ///
    /// # Arguments
    /// * `reader` - A binary reader positioned at the start of the record.
    /// * `space_strings_location` - The starting index of the space strings in the file.
    ///
    /// # Errors
    ///
    /// Returns `SomException` if an I/O error occurs.
    pub fn parse(
        reader: &mut BinaryReader,
        space_strings_location: u64,
    ) -> Result<Self, SomException> {
        let space_index = reader.read_next_i32().map_err(SomException::from)?;

        let bitfield = reader.read_next_i32().map_err(SomException::from)?;
        let reserved = (bitfield & 0x0f) as u8;
        let is_comdat = ((bitfield >> 4) & 0x1) != 0;
        let is_thread_specific = ((bitfield >> 5) & 0x1) != 0;
        let continuation = ((bitfield >> 6) & 0x1) != 0;
        let replicate_init = ((bitfield >> 7) & 0x1) != 0;
        let sort_key = ((bitfield >> 8) & 0xff) as u8;
        let code_only = ((bitfield >> 16) & 0x1) != 0;
        let is_first = ((bitfield >> 17) & 0x1) != 0;
        let initially_frozen = ((bitfield >> 18) & 0x1) != 0;
        let quadrant = ((bitfield >> 19) & 0x3) as u8;
        let is_loadable = ((bitfield >> 21) & 0x1) != 0;
        let is_common = ((bitfield >> 22) & 0x1) != 0;
        let dup_common = ((bitfield >> 23) & 0x1) != 0;
        let memory_resident = ((bitfield >> 24) & 0x1) != 0;
        let access_control_bits = ((bitfield >> 25) & 0x7f) as u8;

        let file_loc_init_value = reader.read_next_i32().map_err(SomException::from)?;
        let initialization_length = reader.read_next_u32().map_err(SomException::from)?;
        let subspace_start = reader.read_next_u32().map_err(SomException::from)?;
        let subspace_length = reader.read_next_u32().map_err(SomException::from)?;

        let bitfield2 = reader.read_next_i32().map_err(SomException::from)?;
        let alignment = (bitfield2 & 0x7ffffff) as u32;
        // reserved2 = (bitfield2 >> 27) & 0x1f  -- not stored

        let name_offset = reader.read_next_u32().map_err(SomException::from)? as u64;
        let name = reader.read_cstring_at(space_strings_location + name_offset)?;

        let fixup_request_index = reader.read_next_i32().map_err(SomException::from)?;
        let fixup_request_quantity = reader.read_next_u32().map_err(SomException::from)?;

        Ok(Self {
            space_index,
            access_control_bits,
            memory_resident,
            dup_common,
            is_common,
            is_loadable,
            quadrant,
            initially_frozen,
            is_first,
            code_only,
            sort_key,
            replicate_init,
            continuation,
            is_thread_specific,
            is_comdat,
            reserved,
            file_loc_init_value,
            initialization_length,
            subspace_start,
            subspace_length,
            alignment,
            name,
            fixup_request_index,
            fixup_request_quantity,
        })
    }

    /// Returns whether this subspace is readable.
    pub fn is_readable(&self) -> bool {
        self.get_access_control_type() < 4
    }

    /// Returns whether this subspace is writeable.
    pub fn is_writable(&self) -> bool {
        let act = self.get_access_control_type();
        act == 1 || act == 3
    }

    /// Returns whether this subspace is executable.
    pub fn is_executable(&self) -> bool {
        self.get_access_control_type() >= 2
    }

    /// Returns the "type" part of the access control bits.
    fn get_access_control_type(&self) -> u8 {
        (self.access_control_bits >> 4) & 0x3
    }
}

impl StructConverter for SomSubspace {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Struct {
            name: "subspace_dictionary_record".to_string(),
            size: SOM_SUBSPACE_SIZE as u32,
            fields: vec![
                ("space_index".into(), DataTypeDescription::DWord),
                ("bitfield".into(), DataTypeDescription::DWord),
                ("file_loc_init_value".into(), DataTypeDescription::DWord),
                ("initialization_length".into(), DataTypeDescription::DWord),
                ("subspace_start".into(), DataTypeDescription::DWord),
                ("subspace_length".into(), DataTypeDescription::DWord),
                ("alignment_bitfield".into(), DataTypeDescription::DWord),
                ("name".into(), DataTypeDescription::DWord),
                ("fixup_request_index".into(), DataTypeDescription::DWord),
                ("fixup_request_quantity".into(), DataTypeDescription::DWord),
            ],
        }
    }
}

impl BinaryWritable for SomSubspace {
    fn write_to(&self, writer: &mut BinaryWriter) -> io::Result<()> {
        writer.write_i32(self.space_index);

        let mut bitfield: u32 = self.reserved as u32 & 0x0f;
        if self.is_comdat {
            bitfield |= 1 << 4;
        }
        if self.is_thread_specific {
            bitfield |= 1 << 5;
        }
        if self.continuation {
            bitfield |= 1 << 6;
        }
        if self.replicate_init {
            bitfield |= 1 << 7;
        }
        bitfield |= (self.sort_key as u32 & 0xff) << 8;
        if self.code_only {
            bitfield |= 1 << 16;
        }
        if self.is_first {
            bitfield |= 1 << 17;
        }
        if self.initially_frozen {
            bitfield |= 1 << 18;
        }
        bitfield |= (self.quadrant as u32 & 0x3) << 19;
        if self.is_loadable {
            bitfield |= 1 << 21;
        }
        if self.is_common {
            bitfield |= 1 << 22;
        }
        if self.dup_common {
            bitfield |= 1 << 23;
        }
        if self.memory_resident {
            bitfield |= 1 << 24;
        }
        bitfield |= (self.access_control_bits as u32 & 0x7f) << 25;
        writer.write_u32(bitfield);

        writer.write_i32(self.file_loc_init_value);
        writer.write_u32(self.initialization_length);
        writer.write_u32(self.subspace_start);
        writer.write_u32(self.subspace_length);

        // Alignment bitfield: 27 bits alignment, 5 bits reserved
        let bitfield2 = self.alignment & 0x7ffffff;
        writer.write_u32(bitfield2);

        // Write name offset as 0 (caller must resolve string table offset)
        writer.write_u32(0);
        writer.write_i32(self.fixup_request_index);
        writer.write_u32(self.fixup_request_quantity);
        Ok(())
    }
}

impl fmt::Display for SomSubspace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SomSubspace {{ name=\"{}\", space_index={}, start=0x{:x}, length={}, loadable={}, executable={} }}",
            self.name, self.space_index, self.subspace_start, self.subspace_length,
            self.is_loadable, self.is_executable()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_subspace_data(name_offset: u32, name: &[u8]) -> Vec<u8> {
        let mut data = vec![0u8; 0x300];
        // Write name at offset
        data[name_offset as usize..name_offset as usize + name.len()].copy_from_slice(name);
        data
    }

    #[test]
    fn test_parse_subspace_basic() {
        let mut data = make_subspace_data(0x200, b"sub1\0");
        // Write space_index = 1
        data[0..4].copy_from_slice(&1i32.to_le_bytes());
        // Write bitfield: is_loadable = 1 (bit 21)
        let bitfield: u32 = 1 << 21;
        data[4..8].copy_from_slice(&bitfield.to_le_bytes());
        // file_loc_init_value, initialization_length, subspace_start, subspace_length
        data[8..12].copy_from_slice(&0i32.to_le_bytes());  // file_loc_init_value
        data[12..16].copy_from_slice(&0x100u32.to_le_bytes()); // initialization_length
        data[16..20].copy_from_slice(&0x1000u32.to_le_bytes()); // subspace_start
        data[20..24].copy_from_slice(&0x2000u32.to_le_bytes()); // subspace_length
        // alignment bitfield
        data[24..28].copy_from_slice(&0x0Du32.to_le_bytes()); // alignment = 13 (2^13 = 8K)
        // name offset
        data[28..32].copy_from_slice(&0x200u32.to_le_bytes());
        // fixup_request_index, fixup_request_quantity
        data[32..36].copy_from_slice(&0i32.to_le_bytes());
        data[36..40].copy_from_slice(&0u32.to_le_bytes());

        let mut reader = BinaryReader::from_bytes(&data, true);
        let subspace = SomSubspace::parse(&mut reader, 0).unwrap();

        assert_eq!(subspace.space_index, 1);
        assert_eq!(subspace.name, "sub1");
        assert!(subspace.is_loadable);
        assert_eq!(subspace.subspace_start, 0x1000);
        assert_eq!(subspace.subspace_length, 0x2000);
        assert_eq!(subspace.alignment, 13);
    }

    #[test]
    fn test_parse_subspace_permissions() {
        let mut data = make_subspace_data(0x200, b"code\0");
        data[0..4].copy_from_slice(&0i32.to_le_bytes());

        // Set access_control_bits to 0b1010000 (type=2 => read+execute)
        // access_control_bits at bits 25-31 of bitfield
        let bitfield: u32 = (0b1010000u32) << 25;
        data[4..8].copy_from_slice(&bitfield.to_le_bytes());

        data[8..12].copy_from_slice(&0i32.to_le_bytes());
        data[12..16].copy_from_slice(&0u32.to_le_bytes());
        data[16..20].copy_from_slice(&0u32.to_le_bytes());
        data[20..24].copy_from_slice(&0u32.to_le_bytes());
        data[24..28].copy_from_slice(&0u32.to_le_bytes());
        data[28..32].copy_from_slice(&0x200u32.to_le_bytes());
        data[32..36].copy_from_slice(&0i32.to_le_bytes());
        data[36..40].copy_from_slice(&0u32.to_le_bytes());

        let mut reader = BinaryReader::from_bytes(&data, true);
        let subspace = SomSubspace::parse(&mut reader, 0).unwrap();

        // access_control_bits = 0b1010000 = 0x50
        // type = (0x50 >> 4) & 0x3 = 5 & 0x3 = 1
        // readable: type < 4 => true
        // writable: type == 1 => true
        // executable: type >= 2 => false
        assert!(subspace.is_readable());
        assert!(subspace.is_writable());
        assert!(!subspace.is_executable());
    }

    #[test]
    fn test_parse_subspace_comdat_and_flags() {
        let mut data = make_subspace_data(0x200, b"cd\0");
        data[0..4].copy_from_slice(&0i32.to_le_bytes());

        // Set is_comdat (bit 4), is_thread_specific (bit 5), code_only (bit 16)
        let bitfield: u32 = (1 << 4) | (1 << 5) | (1 << 16);
        data[4..8].copy_from_slice(&bitfield.to_le_bytes());

        data[8..12].copy_from_slice(&0i32.to_le_bytes());
        data[12..16].copy_from_slice(&0u32.to_le_bytes());
        data[16..20].copy_from_slice(&0u32.to_le_bytes());
        data[20..24].copy_from_slice(&0u32.to_le_bytes());
        data[24..28].copy_from_slice(&0u32.to_le_bytes());
        data[28..32].copy_from_slice(&0x200u32.to_le_bytes());
        data[32..36].copy_from_slice(&0i32.to_le_bytes());
        data[36..40].copy_from_slice(&0u32.to_le_bytes());

        let mut reader = BinaryReader::from_bytes(&data, true);
        let subspace = SomSubspace::parse(&mut reader, 0).unwrap();

        assert!(subspace.is_comdat);
        assert!(subspace.is_thread_specific);
        assert!(subspace.code_only);
    }

    #[test]
    fn test_subspace_struct_converter() {
        let mut data = make_subspace_data(0x200, b"sub\0");
        data[0..4].copy_from_slice(&0i32.to_le_bytes());
        data[4..8].copy_from_slice(&0u32.to_le_bytes());
        data[8..12].copy_from_slice(&0i32.to_le_bytes());
        data[12..16].copy_from_slice(&0u32.to_le_bytes());
        data[16..20].copy_from_slice(&0u32.to_le_bytes());
        data[20..24].copy_from_slice(&0u32.to_le_bytes());
        data[24..28].copy_from_slice(&0u32.to_le_bytes());
        data[28..32].copy_from_slice(&0x200u32.to_le_bytes());
        data[32..36].copy_from_slice(&0i32.to_le_bytes());
        data[36..40].copy_from_slice(&0u32.to_le_bytes());

        let mut reader = BinaryReader::from_bytes(&data, true);
        let subspace = SomSubspace::parse(&mut reader, 0).unwrap();

        let dt = subspace.to_data_type();
        match &dt {
            DataTypeDescription::Struct { name, fields, .. } => {
                assert_eq!(name, "subspace_dictionary_record");
                assert_eq!(fields.len(), 10);
            }
            _ => panic!("Expected Struct"),
        }
    }

    #[test]
    fn test_subspace_display() {
        let mut data = make_subspace_data(0x200, b"disp\0");
        data[0..4].copy_from_slice(&1i32.to_le_bytes());
        data[4..8].copy_from_slice(&0u32.to_le_bytes());
        data[8..12].copy_from_slice(&0i32.to_le_bytes());
        data[12..16].copy_from_slice(&0u32.to_le_bytes());
        data[16..20].copy_from_slice(&0x1000u32.to_le_bytes());
        data[20..24].copy_from_slice(&0x2000u32.to_le_bytes());
        data[24..28].copy_from_slice(&0u32.to_le_bytes());
        data[28..32].copy_from_slice(&0x200u32.to_le_bytes());
        data[32..36].copy_from_slice(&0i32.to_le_bytes());
        data[36..40].copy_from_slice(&0u32.to_le_bytes());

        let mut reader = BinaryReader::from_bytes(&data, true);
        let subspace = SomSubspace::parse(&mut reader, 0).unwrap();

        let s = format!("{}", subspace);
        assert!(s.contains("disp"));
        assert!(s.contains("space_index=1"));
        assert!(s.contains("start=0x1000"));
        assert!(s.contains("length=8192"));
    }

    #[test]
    fn test_subspace_truncated() {
        let data = vec![0u8; 10]; // too short
        let mut reader = BinaryReader::from_bytes(&data, true);
        let result = SomSubspace::parse(&mut reader, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_subspace_size() {
        assert_eq!(SOM_SUBSPACE_SIZE, 0x28);
    }
}
