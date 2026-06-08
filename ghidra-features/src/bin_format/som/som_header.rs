//! SOM header structure ported from Ghidra's `SomHeader.java`.
//!
//! Represents a SOM `header` structure -- the main file header for
//! HP PA-RISC System Object Module binaries.
//!
//! Reference: [The 32-bit PA-RISC Run-time Architecture Document](https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf)

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::binary_writer::{BinaryWritable, BinaryWriter};
use crate::bin_format::types::{DataTypeDescription, StructConverter};

use super::som_compilation_unit::SomCompilationUnit;
use super::som_constants::{is_valid_som_magic, is_valid_version_id, magic_name};
use super::som_exception::SomException;
use super::som_space::SomSpace;
use super::som_subspace::SomSubspace;
use super::som_symbol::SomSymbol;
use super::som_sys_clock::SomSysClock;

/// The size in bytes of a `SomHeader`.
pub const SOM_HEADER_SIZE: usize = 0x80;

/// Represents a SOM `header` structure.
///
/// The main file header for HP PA-RISC SOM binaries. Contains pointers to
/// all the various tables within the file (spaces, subspaces, symbols, etc.)
/// and optionally parses those tables.
///
/// Ported from `ghidra.app.util.bin.format.som.SomHeader`.
#[derive(Debug, Clone)]
pub struct SomHeader {
    /// System ID (e.g., PA-RISC 1.0, 1.1, 2.0).
    pub system_id: u16,
    /// Magic number identifying the file type.
    pub magic: u16,
    /// Version ID (format YYMMDDHH).
    pub version_id: u32,
    /// File time (sys_clock).
    pub file_time: SomSysClock,
    /// Index of space containing entry point.
    pub entry_space: u32,
    /// Index of subspace for entry point.
    pub entry_subspace: u32,
    /// Offset of entry point.
    pub entry_offset: u32,
    /// Auxiliary header location in file.
    pub aux_header_location: u32,
    /// Auxiliary header size in bytes.
    pub aux_header_size: u32,
    /// Length in bytes of entire SOM.
    pub som_length: u32,
    /// DP value assumed during compilation.
    pub presumed_dp: u32,
    /// Location in file of space dictionary.
    pub space_location: u32,
    /// Number of space entries.
    pub space_total: u32,
    /// Location of subspace entries.
    pub subspace_location: u32,
    /// Number of subspace entries.
    pub subspace_total: u32,
    /// MPE/iX loader fixup location.
    pub loader_fixup_location: u32,
    /// Number of loader fixup records.
    pub loader_fixup_total: u32,
    /// File location of string area for space and subspace names.
    pub space_strings_location: u32,
    /// Size of string area for space and subspace names.
    pub space_strings_size: u32,
    /// Init array location.
    pub init_array_location: u32,
    /// Init array total.
    pub init_array_total: u32,
    /// Location in file of module dictionary.
    pub compiler_location: u32,
    /// Number of modules.
    pub compiler_total: u32,
    /// Location in file of symbol dictionary.
    pub symbol_location: u32,
    /// Number of symbol records.
    pub symbol_total: u32,
    /// Location in file of fixup requests.
    pub fixup_request_location: u32,
    /// Number of fixup requests.
    pub fixup_request_total: u32,
    /// File location of string area for module and symbol names.
    pub symbol_strings_location: u32,
    /// Size of string area for module and symbol names.
    pub symbol_strings_size: u32,
    /// Byte offset of first byte of data for unloadable spaces.
    pub unloadable_sp_location: u32,
    /// Byte length of data for unloadable spaces.
    pub unloadable_sp_size: u32,
    /// Checksum.
    pub checksum: u32,

    /// Parsed space dictionary entries.
    pub spaces: Vec<SomSpace>,
    /// Parsed subspace dictionary entries.
    pub subspaces: Vec<SomSubspace>,
    /// Parsed compilation unit entries.
    pub compilation_units: Vec<SomCompilationUnit>,
    /// Parsed symbol dictionary entries.
    pub symbols: Vec<SomSymbol>,
}

impl SomHeader {
    /// Parse a `SomHeader` from a binary reader at the current position.
    ///
    /// This also parses the space, subspace, compilation unit, and symbol
    /// tables if their locations are non-zero.
    ///
    /// # Errors
    ///
    /// Returns `SomException` if an I/O error occurs.
    pub fn parse(reader: &mut BinaryReader) -> Result<Self, SomException> {
        let system_id = reader.read_next_u16().map_err(SomException::from)?;
        let magic = reader.read_next_u16().map_err(SomException::from)?;
        let version_id = reader.read_next_u32().map_err(SomException::from)?;
        let file_time = SomSysClock::parse(reader)?;
        let entry_space = reader.read_next_u32().map_err(SomException::from)?;
        let entry_subspace = reader.read_next_u32().map_err(SomException::from)?;
        let entry_offset = reader.read_next_u32().map_err(SomException::from)?;
        let aux_header_location = reader.read_next_u32().map_err(SomException::from)?;
        let aux_header_size = reader.read_next_u32().map_err(SomException::from)?;
        let som_length = reader.read_next_u32().map_err(SomException::from)?;
        let presumed_dp = reader.read_next_u32().map_err(SomException::from)?;
        let space_location = reader.read_next_u32().map_err(SomException::from)?;
        let space_total = reader.read_next_u32().map_err(SomException::from)?;
        let subspace_location = reader.read_next_u32().map_err(SomException::from)?;
        let subspace_total = reader.read_next_u32().map_err(SomException::from)?;
        let loader_fixup_location = reader.read_next_u32().map_err(SomException::from)?;
        let loader_fixup_total = reader.read_next_u32().map_err(SomException::from)?;
        let space_strings_location = reader.read_next_u32().map_err(SomException::from)?;
        let space_strings_size = reader.read_next_u32().map_err(SomException::from)?;
        let init_array_location = reader.read_next_u32().map_err(SomException::from)?;
        let init_array_total = reader.read_next_u32().map_err(SomException::from)?;
        let compiler_location = reader.read_next_u32().map_err(SomException::from)?;
        let compiler_total = reader.read_next_u32().map_err(SomException::from)?;
        let symbol_location = reader.read_next_u32().map_err(SomException::from)?;
        let symbol_total = reader.read_next_u32().map_err(SomException::from)?;
        let fixup_request_location = reader.read_next_u32().map_err(SomException::from)?;
        let fixup_request_total = reader.read_next_u32().map_err(SomException::from)?;
        let symbol_strings_location = reader.read_next_u32().map_err(SomException::from)?;
        let symbol_strings_size = reader.read_next_u32().map_err(SomException::from)?;
        let unloadable_sp_location = reader.read_next_u32().map_err(SomException::from)?;
        let unloadable_sp_size = reader.read_next_u32().map_err(SomException::from)?;
        let checksum = reader.read_next_u32().map_err(SomException::from)?;

        // Parse spaces
        let mut spaces = Vec::new();
        if space_location > 0 {
            reader.set_cursor(space_location as u64);
            for _ in 0..space_total {
                let space = SomSpace::parse(reader, space_strings_location as u64)?;
                spaces.push(space);
            }
        }

        // Parse subspaces
        let mut subspaces = Vec::new();
        if subspace_location > 0 {
            reader.set_cursor(subspace_location as u64);
            for _ in 0..subspace_total {
                let subspace = SomSubspace::parse(reader, space_strings_location as u64)?;
                subspaces.push(subspace);
            }
        }

        // Parse compilation units
        let mut compilation_units = Vec::new();
        if compiler_location > 0 {
            reader.set_cursor(compiler_location as u64);
            for _ in 0..compiler_total {
                let cu = SomCompilationUnit::parse(reader, symbol_strings_location as u64)?;
                compilation_units.push(cu);
            }
        }

        // Parse symbols
        let mut symbols = Vec::new();
        if symbol_location > 0 {
            reader.set_cursor(symbol_location as u64);
            for _ in 0..symbol_total {
                let symbol = SomSymbol::parse(reader, symbol_strings_location as u64)?;
                symbols.push(symbol);
            }
        }

        Ok(Self {
            system_id,
            magic,
            version_id,
            file_time,
            entry_space,
            entry_subspace,
            entry_offset,
            aux_header_location,
            aux_header_size,
            som_length,
            presumed_dp,
            space_location,
            space_total,
            subspace_location,
            subspace_total,
            loader_fixup_location,
            loader_fixup_total,
            space_strings_location,
            space_strings_size,
            init_array_location,
            init_array_total,
            compiler_location,
            compiler_total,
            symbol_location,
            symbol_total,
            fixup_request_location,
            fixup_request_total,
            symbol_strings_location,
            symbol_strings_size,
            unloadable_sp_location,
            unloadable_sp_size,
            checksum,
            spaces,
            subspaces,
            compilation_units,
            symbols,
        })
    }

    /// Returns true if this header has a valid magic number.
    pub fn has_valid_magic(&self) -> bool {
        is_valid_som_magic(self.magic)
    }

    /// Returns true if this header has a valid version ID.
    pub fn has_valid_version_id(&self) -> bool {
        is_valid_version_id(self.version_id)
    }

    /// Returns the magic name.
    pub fn magic_name(&self) -> &'static str {
        magic_name(self.magic)
    }

    /// Returns the starting address of the "text" space.
    ///
    /// Assumes that the text space is the first space.
    pub fn text_address(&self) -> Option<u64> {
        if self.spaces.is_empty() || self.subspaces.is_empty() {
            return None;
        }
        let subspace_idx = self.spaces[0].subspace_index as usize;
        if subspace_idx < self.subspaces.len() {
            Some(self.subspaces[subspace_idx].subspace_start as u64)
        } else {
            None
        }
    }

    /// Returns the starting address of the "data" space.
    ///
    /// Assumes that the data space is the second space.
    pub fn data_address(&self) -> Option<u64> {
        if self.spaces.len() < 2 || self.subspaces.is_empty() {
            return None;
        }
        let subspace_idx = self.spaces[1].subspace_index as usize;
        if subspace_idx < self.subspaces.len() {
            Some(self.subspaces[subspace_idx].subspace_start as u64)
        } else {
            None
        }
    }
}

impl StructConverter for SomHeader {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Struct {
            name: "header".to_string(),
                        size: 0,
            fields: vec![
                ("system_id".into(), DataTypeDescription::Word),
                ("a_magic".into(), DataTypeDescription::Word),
                ("version_id".into(), DataTypeDescription::DWord),
                ("file_time".into(), self.file_time.to_data_type()),
                ("entry_space".into(), DataTypeDescription::DWord),
                ("entry_subspace".into(), DataTypeDescription::DWord),
                ("entry_offset".into(), DataTypeDescription::DWord),
                ("aux_header_location".into(), DataTypeDescription::DWord),
                ("aux_header_size".into(), DataTypeDescription::DWord),
                ("som_length".into(), DataTypeDescription::DWord),
                ("presumed_dp".into(), DataTypeDescription::DWord),
                ("space_location".into(), DataTypeDescription::DWord),
                ("space_total".into(), DataTypeDescription::DWord),
                ("subspace_location".into(), DataTypeDescription::DWord),
                ("subspace_total".into(), DataTypeDescription::DWord),
                ("loader_fixup_location".into(), DataTypeDescription::DWord),
                ("loader_fixup_total".into(), DataTypeDescription::DWord),
                ("space_strings_location".into(), DataTypeDescription::DWord),
                ("space_strings_size".into(), DataTypeDescription::DWord),
                ("init_array_location".into(), DataTypeDescription::DWord),
                ("init_array_total".into(), DataTypeDescription::DWord),
                ("compiler_location".into(), DataTypeDescription::DWord),
                ("compiler_total".into(), DataTypeDescription::DWord),
                ("symbol_location".into(), DataTypeDescription::DWord),
                ("symbol_total".into(), DataTypeDescription::DWord),
                ("fixup_request_location".into(), DataTypeDescription::DWord),
                ("fixup_request_total".into(), DataTypeDescription::DWord),
                ("symbol_strings_location".into(), DataTypeDescription::DWord),
                ("symbol_strings_size".into(), DataTypeDescription::DWord),
                ("unloadable_sp_location".into(), DataTypeDescription::DWord),
                ("unloadable_sp_size".into(), DataTypeDescription::DWord),
                ("checksum".into(), DataTypeDescription::DWord),
            ],
        }
    }
}

impl BinaryWritable for SomHeader {
    fn write_to(&self, writer: &mut BinaryWriter) -> io::Result<()> {
        writer.write_u16(self.system_id);
        writer.write_u16(self.magic);
        writer.write_u32(self.version_id);
        self.file_time.write_to(writer)?;
        writer.write_u32(self.entry_space);
        writer.write_u32(self.entry_subspace);
        writer.write_u32(self.entry_offset);
        writer.write_u32(self.aux_header_location);
        writer.write_u32(self.aux_header_size);
        writer.write_u32(self.som_length);
        writer.write_u32(self.presumed_dp);
        writer.write_u32(self.space_location);
        writer.write_u32(self.space_total);
        writer.write_u32(self.subspace_location);
        writer.write_u32(self.subspace_total);
        writer.write_u32(self.loader_fixup_location);
        writer.write_u32(self.loader_fixup_total);
        writer.write_u32(self.space_strings_location);
        writer.write_u32(self.space_strings_size);
        writer.write_u32(self.init_array_location);
        writer.write_u32(self.init_array_total);
        writer.write_u32(self.compiler_location);
        writer.write_u32(self.compiler_total);
        writer.write_u32(self.symbol_location);
        writer.write_u32(self.symbol_total);
        writer.write_u32(self.fixup_request_location);
        writer.write_u32(self.fixup_request_total);
        writer.write_u32(self.symbol_strings_location);
        writer.write_u32(self.symbol_strings_size);
        writer.write_u32(self.unloadable_sp_location);
        writer.write_u32(self.unloadable_sp_size);
        writer.write_u32(self.checksum);
        Ok(())
    }
}

impl fmt::Display for SomHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SomHeader {{ magic=0x{:04x} ({}), system_id=0x{:04x}, version=0x{:08x}, \
             spaces={}, subspaces={}, symbols={}, length={} }}",
            self.magic,
            self.magic_name(),
            self.system_id,
            self.version_id,
            self.spaces.len(),
            self.subspaces.len(),
            self.symbols.len(),
            self.som_length
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal SOM header with all table pointers set to 0.
    fn make_header_bytes(magic: u16, system_id: u16, version_id: u32) -> Vec<u8> {
        let mut data = vec![0u8; SOM_HEADER_SIZE];
        data[0..2].copy_from_slice(&system_id.to_le_bytes());
        data[2..4].copy_from_slice(&magic.to_le_bytes());
        data[4..8].copy_from_slice(&version_id.to_le_bytes());
        // file_time at offset 8 (8 bytes of zeros)
        // All remaining fields are zeros
        data
    }

    #[test]
    fn test_parse_header_minimal() {
        let data = make_header_bytes(0x108, 0x210, 0x87102412);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = SomHeader::parse(&mut reader).unwrap();

        assert_eq!(header.magic, 0x108);
        assert_eq!(header.system_id, 0x210);
        assert_eq!(header.version_id, 0x87102412);
        assert!(header.has_valid_magic());
        assert!(header.has_valid_version_id());
        assert_eq!(header.magic_name(), "Shareable Executable");
        assert!(header.spaces.is_empty());
        assert!(header.subspaces.is_empty());
        assert!(header.symbols.is_empty());
    }

    #[test]
    fn test_parse_header_invalid_magic() {
        let data = make_header_bytes(0xFFFF, 0x210, 0x87102412);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = SomHeader::parse(&mut reader).unwrap();

        assert!(!header.has_valid_magic());
        assert_eq!(header.magic_name(), "Unknown");
    }

    #[test]
    fn test_parse_header_invalid_version() {
        let data = make_header_bytes(0x108, 0x210, 0x12345678);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = SomHeader::parse(&mut reader).unwrap();

        assert!(!header.has_valid_version_id());
    }

    #[test]
    fn test_parse_header_shared_library() {
        let data = make_header_bytes(0x10e, 0x214, 0x85082112);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = SomHeader::parse(&mut reader).unwrap();

        assert_eq!(header.magic, 0x10e);
        assert!(header.has_valid_magic());
        assert_eq!(header.magic_name(), "Shared Library");
        assert_eq!(header.system_id, 0x214); // PA-RISC 2.0
    }

    #[test]
    fn test_parse_header_library() {
        let data = make_header_bytes(0x104, 0x20b, 0x87102412);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = SomHeader::parse(&mut reader).unwrap();

        assert_eq!(header.magic_name(), "Library");
        assert_eq!(header.system_id, 0x20b); // PA-RISC 1.0
    }

    #[test]
    fn test_header_struct_converter() {
        let data = make_header_bytes(0x108, 0x210, 0x87102412);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = SomHeader::parse(&mut reader).unwrap();

        let dt = header.to_data_type();
        match &dt {
            DataTypeDescription::Struct { name, fields, .. } => {
                assert_eq!(name, "header");
                assert_eq!(fields.len(), 32);
                assert_eq!(fields[0].0, "system_id");
                assert_eq!(fields[1].0, "a_magic");
                assert_eq!(fields[2].0, "version_id");
                assert_eq!(fields[3].0, "file_time");
            }
            _ => panic!("Expected Struct"),
        }
    }

    #[test]
    fn test_header_display() {
        let data = make_header_bytes(0x108, 0x210, 0x87102412);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = SomHeader::parse(&mut reader).unwrap();

        let s = format!("{}", header);
        assert!(s.contains("magic=0x0108"));
        assert!(s.contains("Shareable Executable"));
        assert!(s.contains("system_id=0x0210"));
    }

    #[test]
    fn test_header_text_data_address_empty() {
        let data = make_header_bytes(0x108, 0x210, 0x87102412);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = SomHeader::parse(&mut reader).unwrap();

        assert!(header.text_address().is_none());
        assert!(header.data_address().is_none());
    }

    #[test]
    fn test_header_truncated() {
        let data = vec![0u8; 10]; // too short
        let mut reader = BinaryReader::from_bytes(&data, true);
        let result = SomHeader::parse(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn test_header_write_roundtrip() {
        let data = make_header_bytes(0x108, 0x210, 0x87102412);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = SomHeader::parse(&mut reader).unwrap();

        let mut writer = BinaryWriter::new(true);
        header.write_to(&mut writer).unwrap();
        let written = writer.into_vec();
        assert_eq!(written, data);
    }

    #[test]
    fn test_header_size() {
        assert_eq!(SOM_HEADER_SIZE, 0x80);
    }
}
