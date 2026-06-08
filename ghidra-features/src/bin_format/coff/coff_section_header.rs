//! COFF section header ported from Ghidra's
//! `ghidra.app.util.bin.format.coff.CoffSectionHeader`.
//!
//! Each section header describes a section in the COFF object file,
//! including its name, size, file offsets to raw data and relocations,
//! and its flags.

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::byte_provider::ByteProvider;
use crate::bin_format::types::{DataTypeDescription, StructConverter};

use super::coff_constants;
use super::coff_exception::CoffException;
use super::coff_file_header::CoffFileHeader;
use super::coff_line_number::CoffLineNumber;
use super::coff_relocation::CoffRelocation;
use super::coff_section_header_flags as flags;
use super::coff_section_header_reserved as reserved;

/// COFF section header (0x28 bytes).
///
/// Ported from `ghidra.app.util.bin.format.coff.CoffSectionHeader`.
/// Describes a single section in a COFF object file.
#[derive(Debug, Clone)]
pub struct CoffSectionHeader {
    /// Section name (up to 8 characters).
    s_name: String,
    /// Physical address (aliased s_nlib).
    s_paddr: i32,
    /// Virtual address.
    s_vaddr: i32,
    /// Section size in addressable units.
    s_size: i32,
    /// File pointer to raw data for this section.
    s_scnptr: i32,
    /// File pointer to relocations.
    s_relptr: i32,
    /// File pointer to line numbers.
    s_lnnoptr: i32,
    /// Number of relocation entries.
    s_nreloc: u16,
    /// Number of line number entries.
    s_nlnno: u16,
    /// Flags.
    s_flags: u32,
    /// Reserved field.
    s_reserved: i16,
    /// Section page number (load).
    s_page: i16,

    /// Parsed relocations for this section.
    relocations: Vec<CoffRelocation>,
    /// Parsed line numbers for this section.
    line_numbers: Vec<CoffLineNumber>,
}

impl CoffSectionHeader {
    /// Byte size of a section header entry.
    pub const SIZEOF: usize = 40; // 0x28

    /// Parse a section header from the reader.
    ///
    /// This reads the fixed fields only; call [`parse_details`] to populate
    /// relocations and line numbers.
    pub fn read(reader: &mut BinaryReader, header: &CoffFileHeader) -> Result<Self, CoffException> {
        let s_name = Self::read_name(reader, header)?;
        let s_paddr = reader.read_next_i32().map_err(CoffException::from)?;
        let s_vaddr = reader.read_next_i32().map_err(CoffException::from)?;
        let s_size = reader.read_next_i32().map_err(CoffException::from)?;
        let s_scnptr = reader.read_next_i32().map_err(CoffException::from)?;
        let s_relptr = reader.read_next_i32().map_err(CoffException::from)?;
        let s_lnnoptr = reader.read_next_i32().map_err(CoffException::from)?;
        let s_nreloc = reader.read_next_u16().map_err(CoffException::from)?;
        let s_nlnno = reader.read_next_u16().map_err(CoffException::from)?;
        let s_flags = reader.read_next_u32().map_err(CoffException::from)?;

        Ok(Self {
            s_name,
            s_paddr,
            s_vaddr,
            s_size,
            s_scnptr,
            s_relptr,
            s_lnnoptr,
            s_nreloc,
            s_nlnno,
            s_flags,
            s_reserved: 0,
            s_page: 0,
            relocations: Vec::new(),
            line_numbers: Vec::new(),
        })
    }

    /// Read the section name from the 8-byte name field.
    ///
    /// If the first 4 bytes are zero, the name is looked up in the string table
    /// using the index in the next 4 bytes. Otherwise, the 8 bytes are read as
    /// an ASCII string.
    fn read_name(
        reader: &mut BinaryReader,
        header: &CoffFileHeader,
    ) -> Result<String, CoffException> {
        let peek = reader.peek_i32();
        if peek == 0 {
            // First 4 bytes are zero -- read string table index
            reader.advance(4); // skip the zero
            let name_index = reader.read_next_i32().map_err(CoffException::from)? as u64;
            let string_table_offset =
                header.f_symptr as u64 + (header.f_nsyms as u64 * coff_constants::SYMBOL_SIZEOF as u64);
            let abs_offset = string_table_offset + name_index;
            reader
                .read_cstring_at(abs_offset)
                .map_err(CoffException::from)
        } else {
            // Read 8 bytes as ASCII
            let bytes = reader
                .read_bytes_at(reader.cursor(), coff_constants::SECTION_NAME_LENGTH)
                .map_err(CoffException::from)?;
            reader.advance(coff_constants::SECTION_NAME_LENGTH as u64);
            Ok(trim_ascii(&bytes))
        }
    }

    /// Parse relocations and line numbers for this section.
    ///
    /// The reader is rewound to its original position after parsing.
    pub fn parse_details(
        &mut self,
        reader: &mut BinaryReader,
        header: &CoffFileHeader,
    ) -> Result<(), CoffException> {
        let orig = reader.cursor();
        let result = (|| -> Result<(), CoffException> {
            self.parse_relocations(reader, header)?;
            self.parse_line_numbers(reader)?;
            Ok(())
        })();
        reader.set_cursor(orig);
        result
    }

    fn parse_relocations(
        &mut self,
        reader: &mut BinaryReader,
        header: &CoffFileHeader,
    ) -> Result<(), CoffException> {
        reader.set_cursor(self.s_relptr as u64);
        self.relocations.clear();
        for _ in 0..self.s_nreloc {
            let reloc = CoffRelocation::read(reader, header.f_magic).map_err(CoffException::from)?;
            self.relocations.push(reloc);
        }
        Ok(())
    }

    fn parse_line_numbers(&mut self, reader: &mut BinaryReader) -> Result<(), CoffException> {
        reader.set_cursor(self.s_lnnoptr as u64);
        self.line_numbers.clear();
        for _ in 0..self.s_nlnno {
            let ln = CoffLineNumber::read(reader).map_err(CoffException::from)?;
            self.line_numbers.push(ln);
        }
        Ok(())
    }

    // --- Accessors ---

    /// Returns the section name.
    pub fn name(&self) -> &str {
        &self.s_name
    }

    /// Returns the physical address offset.
    ///
    /// For linked executables, this is the absolute address within the program space.
    /// For unlinked objects, this address is relative to the object's address space
    /// (i.e. the first section is always at offset zero).
    pub fn physical_address(&self) -> i32 {
        self.s_paddr
    }

    /// Adds an offset to the physical address.
    ///
    /// This must be performed before relocations in order to achieve the proper result.
    pub fn move_by(&mut self, offset: i32) {
        self.s_paddr += offset;
    }

    /// Returns the virtual address (always the same as `physical_address`).
    pub fn virtual_address(&self) -> i32 {
        self.s_vaddr
    }

    /// Returns true if this section is byte oriented and aligned.
    pub fn is_explicitly_byte_aligned(&self) -> bool {
        (self.s_reserved & reserved::EXPLICITLY_BYTE_ALIGNED) != 0
    }

    /// Returns the section size in addressable units.
    ///
    /// For byte-aligned sections, this is the size in bytes.
    /// For word-oriented machines, the raw value represents size in words.
    pub fn size_raw(&self) -> i32 {
        self.s_size
    }

    /// Returns the file offset to the section data.
    pub fn pointer_to_raw_data(&self) -> i32 {
        self.s_scnptr
    }

    /// Returns the file offset to the relocations for this section.
    pub fn pointer_to_relocations(&self) -> i32 {
        self.s_relptr
    }

    /// Returns the file offset to the line numbers for this section.
    pub fn pointer_to_line_numbers(&self) -> i32 {
        self.s_lnnoptr
    }

    /// Returns the number of relocations for this section.
    pub fn relocation_count(&self) -> u16 {
        self.s_nreloc
    }

    /// Returns the number of line number entries for this section.
    pub fn line_number_count(&self) -> u16 {
        self.s_nlnno
    }

    /// Returns the flags for this section.
    pub fn flags(&self) -> u32 {
        self.s_flags
    }

    /// Returns the reserved field value.
    pub fn reserved(&self) -> i16 {
        self.s_reserved
    }

    /// Returns the page number.
    pub fn page(&self) -> i16 {
        self.s_page
    }

    /// Returns a reference to the parsed relocations.
    pub fn relocations(&self) -> &[CoffRelocation] {
        &self.relocations
    }

    /// Returns a reference to the parsed line numbers.
    pub fn line_numbers(&self) -> &[CoffLineNumber] {
        &self.line_numbers
    }

    /// Returns true if this section contains uninitialized data.
    pub fn is_uninitialized_data(&self) -> bool {
        (self.s_flags & flags::STYP_BSS) != 0 || self.s_scnptr == 0
    }

    /// Returns true if this section contains initialized data (and not text).
    pub fn is_initialized_data(&self) -> bool {
        (self.s_flags & flags::STYP_DATA) != 0 && (self.s_flags & flags::STYP_TEXT) == 0
    }

    /// Returns true if this section is a data section (initialized or uninitialized).
    pub fn is_data(&self) -> bool {
        self.is_initialized_data() || self.is_uninitialized_data()
    }

    /// Returns true if this section is readable (always true for COFF).
    pub fn is_readable(&self) -> bool {
        true
    }

    /// Returns true if this section is a group section.
    pub fn is_group(&self) -> bool {
        (self.s_flags & flags::STYP_GROUP) != 0
    }

    /// Returns true if this section is writable.
    pub fn is_writable(&self) -> bool {
        (self.s_flags & flags::STYP_TEXT) == 0
    }

    /// Returns true if this section is executable.
    pub fn is_executable(&self) -> bool {
        (self.s_flags & flags::STYP_TEXT) != 0
    }

    /// Returns true if this section is allocated in memory.
    pub fn is_allocated(&self) -> bool {
        (self.s_flags & flags::STYP_COPY) == 0
            && (self.s_flags & flags::STYP_PAD) == 0
            && (self.s_flags & flags::STYP_DSECT) == 0
    }

    /// Sets the reserved field. Used by `CoffSectionHeaderFactory` for variant headers.
    pub fn set_reserved(&mut self, val: i16) {
        self.s_reserved = val;
    }

    /// Sets the page field. Used by `CoffSectionHeaderFactory` for variant headers.
    pub fn set_page(&mut self, val: i16) {
        self.s_page = val;
    }
}

impl StructConverter for CoffSectionHeader {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Struct {
            name: "CoffSectionHeader".into(),
            size: Self::SIZEOF as u32,
            fields: vec![
                (
                    "s_name".into(),
                    DataTypeDescription::Array {
                        element: Box::new(DataTypeDescription::Ascii),
                        count: coff_constants::SECTION_NAME_LENGTH,
                    },
                ),
                ("s_paddr".into(), DataTypeDescription::DWord),
                ("s_vaddr".into(), DataTypeDescription::DWord),
                ("s_size".into(), DataTypeDescription::DWord),
                ("s_scnptr".into(), DataTypeDescription::DWord),
                ("s_relptr".into(), DataTypeDescription::DWord),
                ("s_lnnoptr".into(), DataTypeDescription::DWord),
                ("s_nreloc".into(), DataTypeDescription::Word),
                ("s_nlnno".into(), DataTypeDescription::Word),
                ("s_flags".into(), DataTypeDescription::DWord),
            ],
        }
    }
}

impl fmt::Display for CoffSectionHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} PhysAddr:0x{:08x} Size:0x{:08x} Flags:0x{:08x}",
            self.s_name,
            self.s_paddr as u32,
            self.s_size as u32,
            self.s_flags
        )
    }
}

/// Trim trailing ASCII whitespace/NUL bytes from a byte slice.
fn trim_ascii(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .rposition(|&b| b != 0 && !b.is_ascii_whitespace())
        .map(|p| p + 1)
        .unwrap_or(0);
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_section_header_bytes(name: &[u8; 8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(name);
        data.extend_from_slice(&[0u8; 4]); // s_paddr
        data.extend_from_slice(&[0u8; 4]); // s_vaddr
        // s_size = 0x100
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        // s_scnptr = 0x200
        data.extend_from_slice(&[0x00, 0x02, 0x00, 0x00]);
        // s_relptr = 0x300
        data.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]);
        // s_lnnoptr = 0x400
        data.extend_from_slice(&[0x00, 0x04, 0x00, 0x00]);
        // s_nreloc = 2
        data.extend_from_slice(&[0x02, 0x00]);
        // s_nlnno = 3
        data.extend_from_slice(&[0x03, 0x00]);
        // s_flags = STYP_TEXT | STYP_DATA
        data.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        data
    }

    #[test]
    fn test_read_section_header() {
        let name: [u8; 8] = *b".text\0\0\0";
        let data = make_section_header_bytes(&name);
        let mut reader = BinaryReader::from_bytes(&data, true);

        // Create a minimal header (non-TI, no symbols)
        let header = CoffFileHeader {
            f_magic: 0x014c,
            f_nscns: 1,
            f_timdat: 0,
            f_symptr: 0,
            f_nsyms: 0,
            f_opthdr: 0,
            f_flags: 0,
            f_target_id: None,
        };

        let section = CoffSectionHeader::read(&mut reader, &header).unwrap();
        assert_eq!(section.name(), ".text");
        assert_eq!(section.size_raw(), 0x100);
        assert_eq!(section.pointer_to_raw_data(), 0x200);
        assert_eq!(section.pointer_to_relocations(), 0x300);
        assert_eq!(section.relocation_count(), 2);
        assert_eq!(section.line_number_count(), 3);
        assert!(section.is_executable());
        assert!(!section.is_writable());
        assert!(!section.is_data());
    }

    #[test]
    fn test_section_flags() {
        let name: [u8; 8] = *b".data\0\0\0";
        let data = make_section_header_bytes(&name);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = CoffFileHeader {
            f_magic: 0x014c,
            f_nscns: 1,
            f_timdat: 0,
            f_symptr: 0,
            f_nsyms: 0,
            f_opthdr: 0,
            f_flags: 0,
            f_target_id: None,
        };

        let mut section = CoffSectionHeader::read(&mut reader, &header).unwrap();

        // Override flags to STYP_DATA only
        section.s_flags = flags::STYP_DATA;
        assert!(section.is_initialized_data());
        assert!(!section.is_uninitialized_data());
        assert!(section.is_data());
        assert!(!section.is_executable());
        assert!(section.is_writable());
        assert!(section.is_allocated());

        // BSS section
        section.s_flags = flags::STYP_BSS;
        assert!(section.is_uninitialized_data());
        assert!(section.is_data());
    }

    #[test]
    fn test_to_data_type() {
        let name: [u8; 8] = *b".text\0\0\0";
        let data = make_section_header_bytes(&name);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = CoffFileHeader {
            f_magic: 0x014c,
            f_nscns: 1,
            f_timdat: 0,
            f_symptr: 0,
            f_nsyms: 0,
            f_opthdr: 0,
            f_flags: 0,
            f_target_id: None,
        };

        let section = CoffSectionHeader::read(&mut reader, &header).unwrap();
        let dt = section.to_data_type();
        match &dt {
            DataTypeDescription::Struct { name, size, fields } => {
                assert_eq!(name, "CoffSectionHeader");
                assert_eq!(*size, 40);
                assert_eq!(fields.len(), 10);
            }
            _ => panic!("Expected Struct"),
        }
    }

    #[test]
    fn test_display() {
        let name: [u8; 8] = *b".text\0\0\0";
        let data = make_section_header_bytes(&name);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let header = CoffFileHeader {
            f_magic: 0x014c,
            f_nscns: 1,
            f_timdat: 0,
            f_symptr: 0,
            f_nsyms: 0,
            f_opthdr: 0,
            f_flags: 0,
            f_target_id: None,
        };

        let section = CoffSectionHeader::read(&mut reader, &header).unwrap();
        let s = format!("{}", section);
        assert!(s.contains(".text"));
        assert!(s.contains("Flags:"));
    }
}
