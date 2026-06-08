//! XCOFF section header ported from Ghidra's
//! `ghidra.app.util.bin.format.xcoff.XCoffSectionHeader`.

use std::fmt;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::types::{DataTypeDescription, StructConverter};

use super::xcoff_exception::XCoffException;
use super::xcoff_file_header_magic;

/// XCOFF Section Header.
///
/// Ported from `ghidra.app.util.bin.format.xcoff.XCoffSectionHeader`.
/// Handles both 32-bit and 64-bit cases.
#[derive(Debug, Clone)]
pub struct XCoffSectionHeader {
    /// Section name (8 bytes).
    pub s_name: [u8; 8],
    /// Physical address, aliased s_nlib.
    pub s_paddr: u64,
    /// Virtual address.
    pub s_vaddr: u64,
    /// Section size.
    pub s_size: u64,
    /// File pointer to raw data for section.
    pub s_scnptr: u64,
    /// File pointer to relocation.
    pub s_relptr: u64,
    /// File pointer to line numbers.
    pub s_lnnoptr: u64,
    /// Number of relocation entries.
    pub s_nreloc: u32,
    /// Number of line number entries.
    pub s_nlnno: u32,
    /// Flags.
    pub s_flags: u32,
    /// Size of this section header in bytes (40 for 32-bit, 72 for 64-bit).
    pub sizeof: usize,
}

impl XCoffSectionHeader {
    /// Parse an XCOFF section header from a reader.
    pub fn from_reader(
        reader: &mut BinaryReader,
        magic: u16,
    ) -> Result<Self, XCoffException> {
        let mut s_name = [0u8; 8];
        for i in 0..8 {
            s_name[i] = reader.read_next_byte().map_err(XCoffException::from)? as u8;
        }

        let is32 = magic == xcoff_file_header_magic::MAGIC_XCOFF32;

        let (s_paddr, s_vaddr, s_size, s_scnptr, s_relptr, s_lnnoptr, s_nreloc, s_nlnno, s_flags, sizeof) =
            if is32 {
                (
                    reader.read_next_int().map_err(XCoffException::from)? as u64 & 0xFFFF_FFFF,
                    reader.read_next_int().map_err(XCoffException::from)? as u64 & 0xFFFF_FFFF,
                    reader.read_next_int().map_err(XCoffException::from)? as u64 & 0xFFFF_FFFF,
                    reader.read_next_int().map_err(XCoffException::from)? as u64 & 0xFFFF_FFFF,
                    reader.read_next_int().map_err(XCoffException::from)? as u64 & 0xFFFF_FFFF,
                    reader.read_next_int().map_err(XCoffException::from)? as u64 & 0xFFFF_FFFF,
                    reader.read_next_short().map_err(XCoffException::from)? as u32 & 0xFFFF,
                    reader.read_next_short().map_err(XCoffException::from)? as u32 & 0xFFFF,
                    reader.read_next_short().map_err(XCoffException::from)? as u32 & 0xFFFF,
                    40usize,
                )
            } else {
                (
                    reader.read_next_long().map_err(XCoffException::from)? as u64,
                    reader.read_next_long().map_err(XCoffException::from)? as u64,
                    reader.read_next_long().map_err(XCoffException::from)? as u64,
                    reader.read_next_long().map_err(XCoffException::from)? as u64,
                    reader.read_next_long().map_err(XCoffException::from)? as u64,
                    reader.read_next_long().map_err(XCoffException::from)? as u64,
                    reader.read_next_int().map_err(XCoffException::from)? as u32,
                    reader.read_next_int().map_err(XCoffException::from)? as u32,
                    reader.read_next_int().map_err(XCoffException::from)? as u32,
                    72usize,
                )
            };

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
            sizeof,
        })
    }

    /// Returns the section name as a string.
    pub fn name(&self) -> &str {
        // Find the first null byte or use the full 8 bytes
        let len = self.s_name.iter().position(|&b| b == 0).unwrap_or(8);
        core::str::from_utf8(&self.s_name[..len]).unwrap_or("")
    }
}

impl fmt::Display for XCoffSectionHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "SECTION HEADER VALUES")?;
        writeln!(f, "{}", self.name())?;
        writeln!(f, "s_paddr = {}", self.s_paddr)?;
        writeln!(f, "s_vaddr = {}", self.s_vaddr)?;
        writeln!(f, "s_size = {}", self.s_size)?;
        writeln!(f, "s_scnptr = {}", self.s_scnptr)?;
        writeln!(f, "s_relptr = {}", self.s_relptr)?;
        writeln!(f, "s_lnnoptr = {}", self.s_lnnoptr)?;
        writeln!(f, "s_nreloc = {}", self.s_nreloc)?;
        writeln!(f, "s_nlnno = {}", self.s_nlnno)?;
        writeln!(f, "s_flags = {}", self.s_flags)
    }
}

impl StructConverter for XCoffSectionHeader {
    fn to_data_type(&self) -> DataTypeDescription {
        let is32 = self.sizeof == 40;
        let ptr_dt = if is32 { DataTypeDescription::DWord } else { DataTypeDescription::QWord };
        DataTypeDescription::Struct {
            name: "XCoffSectionHeader".to_string(),
            size: self.sizeof as u32,
            fields: vec![
                ("s_name".into(), DataTypeDescription::Array {
                    element: Box::new(DataTypeDescription::Byte),
                    count: 8,
                }),
                ("s_paddr".into(), ptr_dt.clone()),
                ("s_vaddr".into(), ptr_dt.clone()),
                ("s_size".into(), ptr_dt.clone()),
                ("s_scnptr".into(), ptr_dt.clone()),
                ("s_relptr".into(), ptr_dt.clone()),
                ("s_lnnoptr".into(), ptr_dt),
                ("s_nreloc".into(), if is32 { DataTypeDescription::Word } else { DataTypeDescription::DWord }),
                ("s_nlnno".into(), if is32 { DataTypeDescription::Word } else { DataTypeDescription::DWord }),
                ("s_flags".into(), DataTypeDescription::DWord),
            ],
        }
    }
}
