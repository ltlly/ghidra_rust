//! XCOFF archive header ported from Ghidra's
//! `ghidra.app.util.bin.format.xcoff.XCoffArchiveHeader`.

use std::fmt;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::byte_provider::{ByteProvider, ByteArrayProvider};

use super::xcoff_archive_constants;
use super::xcoff_exception::XCoffException;

/// Field length for offset fields in the archive header.
const FIELD_LEN: usize = 20;

/// XCOFF Big Archive Header.
///
/// Ported from `ghidra.app.util.bin.format.xcoff.XCoffArchiveHeader`.
#[derive(Debug, Clone)]
pub struct XCoffArchiveHeader {
    /// Archive magic string.
    fl_magic: Vec<u8>,
    /// Offset to member table.
    fl_memoff: Vec<u8>,
    /// Offset to global symbol table.
    fl_gstoff: Vec<u8>,
    /// Offset to global symbol table for 64-bit objects.
    fl_gst64off: Vec<u8>,
    /// Offset to first archive member.
    fl_fstmoff: Vec<u8>,
    /// Offset to last archive member.
    fl_lstmoff: Vec<u8>,
    /// Offset to first member on free list.
    fl_freeoff: Vec<u8>,
}

impl XCoffArchiveHeader {
    /// Parse an XCOFF archive header from a byte provider.
    pub fn from_provider(provider: &dyn ByteProvider) -> Result<Self, XCoffException> {
        let data = provider.read_slice(0, provider.length() as usize)
            .map_err(XCoffException::from)?;
        let mut reader = BinaryReader::from_bytes(&data, false);
        Self::from_reader(&mut reader)
    }

    /// Parse an XCOFF archive header from a reader.
    pub fn from_reader(reader: &mut BinaryReader) -> Result<Self, XCoffException> {
        let fl_magic = Self::read_bytes(reader, xcoff_archive_constants::MAGIC_LENGTH)?;
        let fl_memoff = Self::read_bytes(reader, FIELD_LEN)?;
        let fl_gstoff = Self::read_bytes(reader, FIELD_LEN)?;
        let fl_gst64off = Self::read_bytes(reader, FIELD_LEN)?;
        let fl_fstmoff = Self::read_bytes(reader, FIELD_LEN)?;
        let fl_lstmoff = Self::read_bytes(reader, FIELD_LEN)?;
        let fl_freeoff = Self::read_bytes(reader, FIELD_LEN)?;

        Ok(Self {
            fl_magic,
            fl_memoff,
            fl_gstoff,
            fl_gst64off,
            fl_fstmoff,
            fl_lstmoff,
            fl_freeoff,
        })
    }

    fn read_bytes(reader: &mut BinaryReader, len: usize) -> Result<Vec<u8>, XCoffException> {
        let mut buf = vec![0u8; len];
        for b in &mut buf {
            *b = reader.read_next_byte().map_err(XCoffException::from)? as u8;
        }
        Ok(buf)
    }

    fn parse_long(field: &[u8]) -> Result<i64, XCoffException> {
        let s = core::str::from_utf8(field)
            .map_err(|_| XCoffException::new("Non-UTF-8 archive field"))?
            .trim();
        s.parse::<i64>()
            .map_err(|_| XCoffException::new(format!("Cannot parse archive field: '{}'", s)))
    }

    /// Returns the archive magic string.
    pub fn magic(&self) -> &str {
        core::str::from_utf8(&self.fl_magic)
            .unwrap_or("")
            .trim()
    }

    /// Returns the offset to the member table.
    pub fn member_offset(&self) -> Result<i64, XCoffException> {
        Self::parse_long(&self.fl_memoff)
    }

    /// Returns the offset to the global symbol table.
    pub fn global_symbol_table_offset(&self) -> Result<i64, XCoffException> {
        Self::parse_long(&self.fl_gstoff)
    }

    /// Returns the offset to the 64-bit global symbol table.
    pub fn global_symbol_table_64_offset(&self) -> Result<i64, XCoffException> {
        Self::parse_long(&self.fl_gst64off)
    }

    /// Returns the offset to the first archive member.
    pub fn first_member_offset(&self) -> Result<i64, XCoffException> {
        Self::parse_long(&self.fl_fstmoff)
    }

    /// Returns the offset to the last archive member.
    pub fn last_member_offset(&self) -> Result<i64, XCoffException> {
        Self::parse_long(&self.fl_lstmoff)
    }

    /// Returns the offset to the first member on the free list.
    pub fn free_offset(&self) -> Result<i64, XCoffException> {
        Self::parse_long(&self.fl_freeoff)
    }
}

impl fmt::Display for XCoffArchiveHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ARCHIVE HEADER VALUES")?;
        writeln!(f, "magic    = {}", self.magic())?;
        writeln!(f, "memoff   = {:?}", self.member_offset())?;
        writeln!(f, "gstoff   = {:?}", self.global_symbol_table_offset())?;
        writeln!(f, "gst64off = {:?}", self.global_symbol_table_64_offset())?;
        writeln!(f, "fstmoff  = {:?}", self.first_member_offset())?;
        writeln!(f, "lstmoff  = {:?}", self.last_member_offset())?;
        writeln!(f, "freeoff  = {:?}", self.free_offset())
    }
}
