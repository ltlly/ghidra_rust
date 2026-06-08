//! SOM space_dictionary_record structure ported from Ghidra's `SomSpace.java`.
//!
//! Represents a SOM `space_dictionary_record` structure.
//!
//! Reference: [The 32-bit PA-RISC Run-time Architecture Document](https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf)

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::binary_writer::{BinaryWritable, BinaryWriter};
use crate::bin_format::types::{DataTypeDescription, StructConverter};

use super::som_exception::SomException;

/// The size in bytes of a `SomSpace`.
pub const SOM_SPACE_SIZE: usize = 0x24;

/// Represents a SOM `space_dictionary_record` structure.
///
/// Ported from `ghidra.app.util.bin.format.som.SomSpace`.
#[derive(Debug, Clone)]
pub struct SomSpace {
    /// The space name (read from the space strings area).
    pub name: String,
    /// Whether the space is loadable.
    pub is_loadable: bool,
    /// Whether the space is defined within the file.
    pub is_defined: bool,
    /// Whether the space is not sharable.
    pub is_private: bool,
    /// Whether the space contains intermediate code.
    pub has_intermediate_code: bool,
    /// Whether the space is thread specific.
    pub is_thread_specific: bool,
    /// First reserved value (from bitfield).
    pub reserved: u16,
    /// Sort key for the space.
    pub sort_key: u8,
    /// Second reserved value (from bitfield).
    pub reserved2: u8,
    /// Space index.
    pub space_number: i32,
    /// Index into the subspace dictionary.
    pub subspace_index: i32,
    /// Number of subspaces in the space.
    pub subspace_quantity: u32,
    /// Loader fix index.
    pub loader_fix_index: i32,
    /// Loader fix quantity.
    pub loader_fix_quantity: u32,
    /// Index into data (init) pointer array.
    pub init_pointer_index: i32,
    /// Number of data (init) pointers.
    pub init_pointer_quantity: u32,
}

impl SomSpace {
    /// Parse a `SomSpace` from a binary reader at the current position.
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
        let name_offset = reader.read_next_u32().map_err(SomException::from)? as u64;
        let name = reader.read_cstring_at(space_strings_location + name_offset)?;

        let bitfield = reader.read_next_i32().map_err(SomException::from)?;
        let reserved2 = (bitfield & 0xff) as u8;
        let sort_key = ((bitfield >> 8) & 0xff) as u8;
        let reserved = ((bitfield >> 16) & 0x7ff) as u16;
        let is_thread_specific = ((bitfield >> 27) & 0x1) != 0;
        let has_intermediate_code = ((bitfield >> 28) & 0x1) != 0;
        let is_private = ((bitfield >> 29) & 0x1) != 0;
        let is_defined = ((bitfield >> 30) & 0x1) != 0;
        let is_loadable = ((bitfield >> 31) & 0x1) != 0;

        let space_number = reader.read_next_i32().map_err(SomException::from)?;
        let subspace_index = reader.read_next_i32().map_err(SomException::from)?;
        let subspace_quantity = reader.read_next_u32().map_err(SomException::from)?;
        let loader_fix_index = reader.read_next_i32().map_err(SomException::from)?;
        let loader_fix_quantity = reader.read_next_u32().map_err(SomException::from)?;
        let init_pointer_index = reader.read_next_i32().map_err(SomException::from)?;
        let init_pointer_quantity = reader.read_next_u32().map_err(SomException::from)?;

        Ok(Self {
            name,
            is_loadable,
            is_defined,
            is_private,
            has_intermediate_code,
            is_thread_specific,
            reserved,
            sort_key,
            reserved2,
            space_number,
            subspace_index,
            subspace_quantity,
            loader_fix_index,
            loader_fix_quantity,
            init_pointer_index,
            init_pointer_quantity,
        })
    }
}

impl StructConverter for SomSpace {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Struct {
            name: "space_dictionary_record".to_string(),
            size: SOM_SPACE_SIZE as u32,
            fields: vec![
                ("name".into(), DataTypeDescription::DWord),
                ("bitfield".into(), DataTypeDescription::DWord),
                ("space_number".into(), DataTypeDescription::DWord),
                ("subspace_index".into(), DataTypeDescription::DWord),
                ("subspace_quantity".into(), DataTypeDescription::DWord),
                ("loader_fix_index".into(), DataTypeDescription::DWord),
                ("loader_fix_quantity".into(), DataTypeDescription::DWord),
                ("init_pointer_index".into(), DataTypeDescription::DWord),
                ("init_pointer_quantity".into(), DataTypeDescription::DWord),
            ],
        }
    }
}

impl BinaryWritable for SomSpace {
    fn write_to(&self, writer: &mut BinaryWriter) -> io::Result<()> {
        // Write name offset as 0 (caller must resolve string table offset)
        writer.write_u32(0);

        let mut bitfield: u32 = self.reserved2 as u32 & 0xff;
        bitfield |= (self.sort_key as u32 & 0xff) << 8;
        bitfield |= (self.reserved as u32 & 0x7ff) << 16;
        if self.is_thread_specific {
            bitfield |= 1 << 27;
        }
        if self.has_intermediate_code {
            bitfield |= 1 << 28;
        }
        if self.is_private {
            bitfield |= 1 << 29;
        }
        if self.is_defined {
            bitfield |= 1 << 30;
        }
        if self.is_loadable {
            bitfield |= 1 << 31;
        }
        writer.write_u32(bitfield);

        writer.write_i32(self.space_number);
        writer.write_i32(self.subspace_index);
        writer.write_u32(self.subspace_quantity);
        writer.write_i32(self.loader_fix_index);
        writer.write_u32(self.loader_fix_quantity);
        writer.write_i32(self.init_pointer_index);
        writer.write_u32(self.init_pointer_quantity);
        Ok(())
    }
}

impl fmt::Display for SomSpace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SomSpace {{ name=\"{}\", space_number={}, subspace_quantity={}, loadable={} }}",
            self.name, self.space_number, self.subspace_quantity, self.is_loadable
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_space_bytes(
        name_offset: u32,
        bitfield: u32,
        space_number: i32,
        subspace_index: i32,
        subspace_quantity: u32,
        loader_fix_index: i32,
        loader_fix_quantity: u32,
        init_pointer_index: i32,
        init_pointer_quantity: u32,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&name_offset.to_le_bytes());
        data.extend_from_slice(&bitfield.to_le_bytes());
        data.extend_from_slice(&space_number.to_le_bytes());
        data.extend_from_slice(&subspace_index.to_le_bytes());
        data.extend_from_slice(&subspace_quantity.to_le_bytes());
        data.extend_from_slice(&loader_fix_index.to_le_bytes());
        data.extend_from_slice(&loader_fix_quantity.to_le_bytes());
        data.extend_from_slice(&init_pointer_index.to_le_bytes());
        data.extend_from_slice(&init_pointer_quantity.to_le_bytes());
        data
    }

    #[test]
    fn test_parse_space_basic() {
        // Build a minimal data buffer with space name at offset 0x100
        let mut data = vec![0u8; 0x200];
        // Write "test_space" at offset 0x100 in the data
        let name = b"test_space\0";
        data[0x100..0x100 + name.len()].copy_from_slice(name);

        // Write space record at offset 0
        let space_data = make_space_bytes(
            0x100,     // name offset (relative to space_strings_location which we'll set to 0)
            0x80000000, // is_loadable bit set
            1,         // space_number
            0,         // subspace_index
            2,         // subspace_quantity
            0,         // loader_fix_index
            0,         // loader_fix_quantity
            0,         // init_pointer_index
            0,         // init_pointer_quantity
        );
        data[0..space_data.len()].copy_from_slice(&space_data);

        let mut reader = BinaryReader::from_bytes(&data, true);
        let space = SomSpace::parse(&mut reader, 0).unwrap();

        assert_eq!(space.name, "test_space");
        assert!(space.is_loadable);
        assert!(!space.is_defined);
        assert_eq!(space.space_number, 1);
        assert_eq!(space.subspace_quantity, 2);
    }

    #[test]
    fn test_parse_space_with_flags() {
        let mut data = vec![0u8; 0x200];
        let name = b"my_space\0";
        data[0x100..0x100 + name.len()].copy_from_slice(name);

        // Set is_loadable, is_defined, is_private, has_intermediate_code, is_thread_specific
        let bitfield: u32 = (1 << 31) | (1 << 30) | (1 << 29) | (1 << 28) | (1 << 27);
        let space_data = make_space_bytes(0x100, bitfield, 5, 10, 3, 0, 0, 0, 0);
        data[0..space_data.len()].copy_from_slice(&space_data);

        let mut reader = BinaryReader::from_bytes(&data, true);
        let space = SomSpace::parse(&mut reader, 0).unwrap();

        assert!(space.is_loadable);
        assert!(space.is_defined);
        assert!(space.is_private);
        assert!(space.has_intermediate_code);
        assert!(space.is_thread_specific);
    }

    #[test]
    fn test_parse_space_with_sort_key() {
        let mut data = vec![0u8; 0x200];
        let name = b"s\0";
        data[0x50..0x50 + name.len()].copy_from_slice(name);

        // Set sort_key = 42 (bits 8-15)
        let bitfield: u32 = 42 << 8;
        let space_data = make_space_bytes(0x50, bitfield, 0, 0, 0, 0, 0, 0, 0);
        data[0..space_data.len()].copy_from_slice(&space_data);

        let mut reader = BinaryReader::from_bytes(&data, true);
        let space = SomSpace::parse(&mut reader, 0).unwrap();

        assert_eq!(space.sort_key, 42);
    }

    #[test]
    fn test_space_struct_converter() {
        let mut data = vec![0u8; 0x200];
        let name = b"space\0";
        data[0x100..0x100 + name.len()].copy_from_slice(name);
        let space_data = make_space_bytes(0x100, 0, 0, 0, 0, 0, 0, 0, 0);
        data[0..space_data.len()].copy_from_slice(&space_data);

        let mut reader = BinaryReader::from_bytes(&data, true);
        let space = SomSpace::parse(&mut reader, 0).unwrap();

        let dt = space.to_data_type();
        match &dt {
            DataTypeDescription::Struct { name, fields, .. } => {
                assert_eq!(name, "space_dictionary_record");
                assert_eq!(fields.len(), 9);
            }
            _ => panic!("Expected Struct"),
        }
    }

    #[test]
    fn test_space_display() {
        let mut data = vec![0u8; 0x200];
        let name = b"test\0";
        data[0x100..0x100 + name.len()].copy_from_slice(name);
        let space_data = make_space_bytes(0x100, 0, 1, 0, 2, 0, 0, 0, 0);
        data[0..space_data.len()].copy_from_slice(&space_data);

        let mut reader = BinaryReader::from_bytes(&data, true);
        let space = SomSpace::parse(&mut reader, 0).unwrap();

        let s = format!("{}", space);
        assert!(s.contains("test"));
        assert!(s.contains("space_number=1"));
        assert!(s.contains("subspace_quantity=2"));
    }

    #[test]
    fn test_space_truncated() {
        let data = vec![0u8; 10]; // too short
        let mut reader = BinaryReader::from_bytes(&data, true);
        let result = SomSpace::parse(&mut reader, 0);
        assert!(result.is_err());
    }
}
