//! XCOFF file header ported from Ghidra's
//! `ghidra.app.util.bin.format.xcoff.XCoffFileHeader`.
//!
//! Handles both 32-bit and 64-bit XCOFF cases.

use std::fmt;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::types::{DataTypeDescription, StructConverter};

use super::xcoff_exception::XCoffException;
use super::xcoff_file_header_magic;
use super::xcoff_optional_header::XCoffOptionalHeader;

/// Minimum size of an XCOFF file header in bytes.
pub const SIZEOF: usize = 20;

/// XCOFF File Header.
///
/// Ported from `ghidra.app.util.bin.format.xcoff.XCoffFileHeader`.
/// Handles both 32-bit and 64-bit cases.
#[derive(Debug, Clone)]
pub struct XCoffFileHeader {
    /// Magic number.
    pub f_magic: u16,
    /// Number of sections.
    pub f_nscns: u16,
    /// Time and date stamp.
    pub f_timdat: u32,
    /// File pointer to symbol table.
    pub f_symptr: u64,
    /// Number of symbol table entries.
    pub f_nsyms: u32,
    /// Size of optional header.
    pub f_opthdr: u16,
    /// Flags.
    pub f_flags: u16,
    /// Optional header (present when `f_opthdr > 0`).
    pub optional_header: Option<XCoffOptionalHeader>,
}

impl XCoffFileHeader {
    /// Parse an XCOFF file header from a byte provider.
    ///
    /// # Errors
    ///
    /// Returns [`XCoffException`] if the provider is null, too small, or has an
    /// invalid magic value.
    pub fn from_reader(reader: &mut BinaryReader) -> Result<Self, XCoffException> {
        let peek_magic = reader.peek_next_short().map_err(XCoffException::from)?;
        if !xcoff_file_header_magic::is_match(peek_magic as u16) {
            return Err(XCoffException::new("Invalid XCOFF: incorrect magic value."));
        }

        let f_magic = reader.read_next_short().map_err(XCoffException::from)? as u16;
        let f_nscns = reader.read_next_short().map_err(XCoffException::from)? as u16;
        let f_timdat = reader.read_next_int().map_err(XCoffException::from)? as u32;

        let f_symptr = if f_magic == xcoff_file_header_magic::MAGIC_XCOFF32 {
            reader.read_next_int().map_err(XCoffException::from)? as u64 & 0xFFFF_FFFF
        } else if f_magic == xcoff_file_header_magic::MAGIC_XCOFF64_OLD
            || f_magic == xcoff_file_header_magic::MAGIC_XCOFF64
        {
            reader.read_next_long().map_err(XCoffException::from)? as u64
        } else {
            return Err(XCoffException::new("Invalid XCOFF: unrecognized bit size."));
        };

        let f_nsyms = reader.read_next_int().map_err(XCoffException::from)? as u32;
        let f_opthdr = reader.read_next_short().map_err(XCoffException::from)? as u16;
        let f_flags = reader.read_next_short().map_err(XCoffException::from)? as u16;

        let optional_header = if f_opthdr > 0 {
            Some(XCoffOptionalHeader::from_reader(reader, f_magic)?)
        } else {
            None
        };

        Ok(Self {
            f_magic,
            f_nscns,
            f_timdat,
            f_symptr,
            f_nsyms,
            f_opthdr,
            f_flags,
            optional_header,
        })
    }

    /// Returns the magic number.
    pub fn magic(&self) -> u16 {
        self.f_magic
    }

    /// Returns the number of sections.
    pub fn section_count(&self) -> u16 {
        self.f_nscns
    }

    /// Returns the time and date stamp.
    pub fn timestamp(&self) -> u32 {
        self.f_timdat
    }

    /// Returns the file pointer to the symbol table.
    pub fn symbol_table_pointer(&self) -> u64 {
        self.f_symptr
    }

    /// Returns the number of symbol table entries.
    pub fn symbol_table_entries(&self) -> u32 {
        self.f_nsyms
    }

    /// Returns the size of the optional header.
    pub fn optional_header_size(&self) -> u16 {
        self.f_opthdr
    }

    /// Returns the flags.
    pub fn flags(&self) -> u16 {
        self.f_flags
    }
}

impl fmt::Display for XCoffFileHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "FILE HEADER VALUES")?;
        writeln!(f, "f_magic  = {}", self.f_magic)?;
        writeln!(f, "f_nscns  = {}", self.f_nscns)?;
        writeln!(f, "f_timdat = {}", self.f_timdat)?;
        writeln!(f, "f_symptr = {}", self.f_symptr)?;
        writeln!(f, "f_nsyms  = {}", self.f_nsyms)?;
        writeln!(f, "f_opthdr = {}", self.f_opthdr)?;
        writeln!(f, "f_flags  = {}", self.f_flags)
    }
}

impl StructConverter for XCoffFileHeader {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Struct {
            name: "XCoffFileHeader".to_string(),
            size: SIZEOF as u32,
            fields: vec![
                ("f_magic".into(), DataTypeDescription::Word),
                ("f_nscns".into(), DataTypeDescription::Word),
                ("f_timdat".into(), DataTypeDescription::DWord),
                ("f_symptr".into(), if self.f_magic == xcoff_file_header_magic::MAGIC_XCOFF32 {
                    DataTypeDescription::DWord
                } else {
                    DataTypeDescription::QWord
                }),
                ("f_nsyms".into(), DataTypeDescription::DWord),
                ("f_opthdr".into(), DataTypeDescription::Word),
                ("f_flags".into(), DataTypeDescription::Word),
            ],
        }
    }
}
