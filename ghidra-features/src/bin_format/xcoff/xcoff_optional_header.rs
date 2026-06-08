//! XCOFF optional header ported from Ghidra's
//! `ghidra.app.util.bin.format.xcoff.XCoffOptionalHeader`.

use std::fmt;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::types::{DataTypeDescription, StructConverter};

use super::xcoff_exception::XCoffException;
use super::xcoff_file_header_magic;

/// Size of the XCOFF optional header (AOUTHDRSZ).
pub const AOUTHDRSZ: usize = 72;

/// XCOFF Optional Header.
///
/// Ported from `ghidra.app.util.bin.format.xcoff.XCoffOptionalHeader`.
/// Handles both 32-bit and 64-bit XCOFF cases.
#[derive(Debug, Clone)]
pub struct XCoffOptionalHeader {
    /// Type of file (0x010B).
    pub o_magic: u16,
    /// Version stamp (1).
    pub o_vstamp: u16,
    /// Text size in bytes, padded to FW boundary.
    pub o_tsize: u64,
    /// Initialized data size.
    pub o_dsize: u64,
    /// Uninitialized data size.
    pub o_bsize: u64,
    /// Entry point.
    pub o_entry: u64,
    /// Base of text used for this file.
    pub o_text_start: u64,
    /// Base of data used for this file.
    pub o_data_start: u64,
    /// Address of TOC anchor.
    pub o_toc: u64,
    /// Section number for entry point.
    pub o_snentry: u16,
    /// Section number for .text.
    pub o_sntext: u16,
    /// Section number for .data.
    pub o_sndata: u16,
    /// Section number for TOC.
    pub o_sntoc: u16,
    /// Section number for loader data.
    pub o_snloader: u16,
    /// Section number for .bss.
    pub o_snbss: u16,
    /// Maximum alignment for .text.
    pub o_algntext: u16,
    /// Maximum alignment for .data.
    pub o_algndata: u16,
    /// Module Type Field.
    pub o_modtype: [u8; 2],
    /// Bit flags -- cpu types of objects.
    pub o_cpuflag: u8,
    /// Reserved for cpu type.
    pub o_cputype: u8,
    /// Maximum stack size allowed (bytes).
    pub o_maxstack: u64,
    /// Maximum data size allowed (bytes).
    pub o_maxdata: u64,
    /// Reserved for debuggers.
    pub o_debugger: u64,
    /// Flags and thread-local storage alignment.
    pub o_flags: u8,
    /// Section number for .tdata.
    pub o_sntdata: u16,
    /// Section number for .tbss.
    pub o_sntbss: u16,
}

impl XCoffOptionalHeader {
    /// Parse an XCOFF optional header from a reader.
    pub fn from_reader(
        reader: &mut BinaryReader,
        magic: u16,
    ) -> Result<Self, XCoffException> {
        let is32 = magic == xcoff_file_header_magic::MAGIC_XCOFF32;

        let o_magic = reader.read_next_short().map_err(XCoffException::from)? as u16;
        let o_vstamp = reader.read_next_short().map_err(XCoffException::from)? as u16;

        let (o_tsize, o_dsize, o_bsize, o_entry, o_text_start, o_data_start, o_toc) = if is32 {
            (
                reader.read_next_int().map_err(XCoffException::from)? as u64 & 0xFFFF_FFFF,
                reader.read_next_int().map_err(XCoffException::from)? as u64 & 0xFFFF_FFFF,
                reader.read_next_int().map_err(XCoffException::from)? as u64 & 0xFFFF_FFFF,
                reader.read_next_int().map_err(XCoffException::from)? as u64 & 0xFFFF_FFFF,
                reader.read_next_int().map_err(XCoffException::from)? as u64 & 0xFFFF_FFFF,
                reader.read_next_int().map_err(XCoffException::from)? as u64 & 0xFFFF_FFFF,
                reader.read_next_int().map_err(XCoffException::from)? as u64 & 0xFFFF_FFFF,
            )
        } else {
            (
                reader.read_next_long().map_err(XCoffException::from)? as u64,
                reader.read_next_long().map_err(XCoffException::from)? as u64,
                reader.read_next_long().map_err(XCoffException::from)? as u64,
                reader.read_next_long().map_err(XCoffException::from)? as u64,
                reader.read_next_long().map_err(XCoffException::from)? as u64,
                reader.read_next_long().map_err(XCoffException::from)? as u64,
                reader.read_next_long().map_err(XCoffException::from)? as u64,
            )
        };

        let o_snentry = reader.read_next_short().map_err(XCoffException::from)? as u16;
        let o_sntext = reader.read_next_short().map_err(XCoffException::from)? as u16;
        let o_sndata = reader.read_next_short().map_err(XCoffException::from)? as u16;
        let o_sntoc = reader.read_next_short().map_err(XCoffException::from)? as u16;
        let o_snloader = reader.read_next_short().map_err(XCoffException::from)? as u16;
        let o_snbss = reader.read_next_short().map_err(XCoffException::from)? as u16;
        let o_algntext = reader.read_next_short().map_err(XCoffException::from)? as u16;
        let o_algndata = reader.read_next_short().map_err(XCoffException::from)? as u16;

        let mut o_modtype = [0u8; 2];
        o_modtype[0] = reader.read_next_byte().map_err(XCoffException::from)? as u8;
        o_modtype[1] = reader.read_next_byte().map_err(XCoffException::from)? as u8;

        let o_cpuflag = reader.read_next_byte().map_err(XCoffException::from)? as u8;
        let o_cputype = reader.read_next_byte().map_err(XCoffException::from)? as u8;

        let (o_maxstack, o_maxdata, o_debugger) = if is32 {
            (
                reader.read_next_int().map_err(XCoffException::from)? as u64 & 0xFFFF_FFFF,
                reader.read_next_int().map_err(XCoffException::from)? as u64 & 0xFFFF_FFFF,
                reader.read_next_int().map_err(XCoffException::from)? as u64 & 0xFFFF_FFFF,
            )
        } else {
            (
                reader.read_next_long().map_err(XCoffException::from)? as u64,
                reader.read_next_long().map_err(XCoffException::from)? as u64,
                reader.read_next_long().map_err(XCoffException::from)? as u64,
            )
        };

        let o_flags = reader.read_next_byte().map_err(XCoffException::from)? as u8;
        let o_sntdata = reader.read_next_short().map_err(XCoffException::from)? as u16;
        let o_sntbss = reader.read_next_short().map_err(XCoffException::from)? as u16;

        Ok(Self {
            o_magic,
            o_vstamp,
            o_tsize,
            o_dsize,
            o_bsize,
            o_entry,
            o_text_start,
            o_data_start,
            o_toc,
            o_snentry,
            o_sntext,
            o_sndata,
            o_sntoc,
            o_snloader,
            o_snbss,
            o_algntext,
            o_algndata,
            o_modtype,
            o_cpuflag,
            o_cputype,
            o_maxstack,
            o_maxdata,
            o_debugger,
            o_flags,
            o_sntdata,
            o_sntbss,
        })
    }

    /// Returns the magic value.
    pub fn magic(&self) -> u16 {
        self.o_magic
    }

    /// Returns the format version for this auxiliary header.
    pub fn version_stamp(&self) -> u16 {
        self.o_vstamp
    }

    /// Returns the size (in bytes) of the raw data for the .text section.
    pub fn text_size(&self) -> u64 {
        self.o_tsize
    }

    /// Returns the size (in bytes) of the raw data for the .data section.
    pub fn initialized_data_size(&self) -> u64 {
        self.o_dsize
    }

    /// Returns the size (in bytes) of the .bss section.
    pub fn uninitialized_data_size(&self) -> u64 {
        self.o_bsize
    }

    /// Returns the virtual address of the entry point.
    pub fn entry(&self) -> u64 {
        self.o_entry
    }

    /// Returns the virtual address of the .text section.
    pub fn text_start(&self) -> u64 {
        self.o_text_start
    }

    /// Returns the virtual address of the .data section.
    pub fn data_start(&self) -> u64 {
        self.o_data_start
    }

    /// Returns the virtual address of the TOC anchor.
    pub fn toc(&self) -> u64 {
        self.o_toc
    }

    /// Returns the number of the section that contains the entry point.
    pub fn section_number_for_entry(&self) -> u16 {
        self.o_snentry
    }

    /// Returns the number of the .text section.
    pub fn section_number_for_text(&self) -> u16 {
        self.o_sntext
    }

    /// Returns the number of the .data section.
    pub fn section_number_for_data(&self) -> u16 {
        self.o_sndata
    }

    /// Returns the number of the section that contains the TOC.
    pub fn section_number_for_toc(&self) -> u16 {
        self.o_sntoc
    }

    /// Returns the number of the section that contains the system loader information.
    pub fn section_number_for_loader(&self) -> u16 {
        self.o_snloader
    }

    /// Returns the number of the .bss section.
    pub fn section_number_for_bss(&self) -> u16 {
        self.o_snbss
    }

    /// Returns log (base-2) of the maximum alignment needed for
    /// any csect in the .text section.
    pub fn max_alignment_for_text(&self) -> u16 {
        self.o_algntext
    }

    /// Returns log (base-2) of the maximum alignment needed for
    /// any csect in the .data or .bss section.
    pub fn max_alignment_for_data(&self) -> u16 {
        self.o_algndata
    }

    /// Returns the module type.
    pub fn module_type(&self) -> &str {
        // Safe: module type is always ASCII (e.g. "RO")
        core::str::from_utf8(&self.o_modtype).unwrap_or("")
    }

    /// Returns the CPU bit flags.
    pub fn cpu_flag(&self) -> u8 {
        self.o_cpuflag
    }

    /// Returns the CPU type (reserved, always 0).
    pub fn cpu_type(&self) -> u8 {
        self.o_cputype
    }

    /// Returns the maximum stack size allowed for this executable.
    pub fn max_stack_size(&self) -> u64 {
        self.o_maxstack
    }

    /// Returns the maximum data size allowed for this executable.
    pub fn max_data_size(&self) -> u64 {
        self.o_maxdata
    }

    /// Returns the debugger field (should be 0).
    pub fn debugger(&self) -> u64 {
        self.o_debugger
    }

    /// Returns the flags field.
    pub fn flags(&self) -> u8 {
        self.o_flags
    }

    /// Returns the section number for .tdata.
    pub fn section_number_for_tdata(&self) -> u16 {
        self.o_sntdata
    }

    /// Returns the section number for .tbss.
    pub fn section_number_for_tbss(&self) -> u16 {
        self.o_sntbss
    }
}

impl fmt::Display for XCoffOptionalHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "OPTIONAL HEADER VALUES")?;
        writeln!(f, "magic      = {}", self.o_magic)?;
        writeln!(f, "vstamp     = {}", self.o_vstamp)?;
        writeln!(f, "tsize      = {}", self.o_tsize)?;
        writeln!(f, "dsize      = {}", self.o_dsize)?;
        writeln!(f, "bsize      = {}", self.o_bsize)?;
        writeln!(f, "entry      = {}", self.o_entry)?;
        writeln!(f, "text_start = {}", self.o_text_start)?;
        writeln!(f, "data_start = {}", self.o_data_start)?;
        writeln!(f, "o_toc      = {}", self.o_toc)?;
        writeln!(f, "o_snentry  = {}", self.o_snentry)?;
        writeln!(f, "o_sntext   = {}", self.o_sntext)?;
        writeln!(f, "o_sndata   = {}", self.o_sndata)?;
        writeln!(f, "o_sntoc    = {}", self.o_sntoc)?;
        writeln!(f, "o_snloader = {}", self.o_snloader)?;
        writeln!(f, "o_snbss    = {}", self.o_snbss)?;
        writeln!(f, "o_algntext = {}", self.o_algntext)?;
        writeln!(f, "o_algndata = {}", self.o_algndata)?;
        writeln!(f, "o_modtype  = {:?}", self.o_modtype)?;
        writeln!(f, "o_cpuflag  = {}", self.o_cpuflag)?;
        writeln!(f, "o_cputype  = {}", self.o_cputype)?;
        writeln!(f, "o_maxstack = {}", self.o_maxstack)?;
        writeln!(f, "o_maxdata  = {}", self.o_maxdata)?;
        writeln!(f, "o_flags    = {}", self.o_flags)?;
        writeln!(f, "o_debugger = {}", self.o_debugger)?;
        writeln!(f, "o_sntdata  = {}", self.o_sntdata)?;
        writeln!(f, "o_sntbss   = {}", self.o_sntbss)
    }
}

impl StructConverter for XCoffOptionalHeader {
    fn to_data_type(&self) -> DataTypeDescription {
        let is32 = self.o_magic == xcoff_file_header_magic::MAGIC_XCOFF32;
        let ptr_dt = if is32 { DataTypeDescription::DWord } else { DataTypeDescription::QWord };
        DataTypeDescription::Struct {
            name: "XCoffOptionalHeader".to_string(),
            size: AOUTHDRSZ as u32,
            fields: vec![
                ("o_magic".into(), DataTypeDescription::Word),
                ("o_vstamp".into(), DataTypeDescription::Word),
                ("o_tsize".into(), ptr_dt.clone()),
                ("o_dsize".into(), ptr_dt.clone()),
                ("o_bsize".into(), ptr_dt.clone()),
                ("o_entry".into(), ptr_dt.clone()),
                ("o_text_start".into(), ptr_dt.clone()),
                ("o_data_start".into(), ptr_dt.clone()),
                ("o_toc".into(), ptr_dt.clone()),
                ("o_snentry".into(), DataTypeDescription::Word),
                ("o_sntext".into(), DataTypeDescription::Word),
                ("o_sndata".into(), DataTypeDescription::Word),
                ("o_sntoc".into(), DataTypeDescription::Word),
                ("o_snloader".into(), DataTypeDescription::Word),
                ("o_snbss".into(), DataTypeDescription::Word),
                ("o_algntext".into(), DataTypeDescription::Word),
                ("o_algndata".into(), DataTypeDescription::Word),
                ("o_modtype".into(), DataTypeDescription::Array {
                    element: Box::new(DataTypeDescription::Byte),
                    count: 2,
                }),
                ("o_cpuflag".into(), DataTypeDescription::Byte),
                ("o_cputype".into(), DataTypeDescription::Byte),
                ("o_maxstack".into(), ptr_dt.clone()),
                ("o_maxdata".into(), ptr_dt.clone()),
                ("o_debugger".into(), ptr_dt),
                ("o_flags".into(), DataTypeDescription::Byte),
                ("o_sntdata".into(), DataTypeDescription::Word),
                ("o_sntbss".into(), DataTypeDescription::Word),
            ],
        }
    }
}
