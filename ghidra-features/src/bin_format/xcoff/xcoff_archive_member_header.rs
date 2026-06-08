//! XCOFF archive member header ported from Ghidra's
//! `ghidra.app.util.bin.format.xcoff.XCoffArchiveMemberHeader`.
//!
//! The archive member header stores per-object-file metadata in an XCOFF
//! big archive.

use std::fmt;

use crate::bin_format::binary_reader::BinaryReader;

use super::xcoff_exception::XCoffException;

/// Field length constants matching the Java source.
const FIELD_20: usize = 20;
const FIELD_12: usize = 12;
const FIELD_4: usize = 4;
const FIELD_2: usize = 2;

/// XCOFF Archive Member Header.
///
/// Ported from `ghidra.app.util.bin.format.xcoff.XCoffArchiveMemberHeader`.
#[derive(Debug, Clone)]
pub struct XCoffArchiveMemberHeader {
    /// File member size -- decimal.
    ar_size: Vec<u8>,
    /// Next member offset -- decimal.
    ar_nxtmem: Vec<u8>,
    /// Previous member offset -- decimal.
    ar_prvmem: Vec<u8>,
    /// File member date -- decimal.
    ar_date: Vec<u8>,
    /// File member userid -- decimal.
    ar_uid: Vec<u8>,
    /// File member group id -- decimal.
    ar_gid: Vec<u8>,
    /// File member mode -- octal.
    ar_mode: Vec<u8>,
    /// File member name length -- decimal.
    ar_namlen: Vec<u8>,
    /// Start of member name.
    ar_name: Vec<u8>,
    /// AIAFMAG -- string to end "`\n".
    ar_fmag: Vec<u8>,
    /// File offset to the object data (after the header).
    file_offset: u64,
}

impl XCoffArchiveMemberHeader {
    /// Parse an archive member header from a reader.
    pub fn from_reader(reader: &mut BinaryReader) -> Result<Self, XCoffException> {
        let ar_size = Self::read_bytes(reader, FIELD_20)?;
        let ar_nxtmem = Self::read_bytes(reader, FIELD_20)?;
        let ar_prvmem = Self::read_bytes(reader, FIELD_20)?;
        let ar_date = Self::read_bytes(reader, FIELD_12)?;
        let ar_uid = Self::read_bytes(reader, FIELD_12)?;
        let ar_gid = Self::read_bytes(reader, FIELD_12)?;
        let ar_mode = Self::read_bytes(reader, FIELD_12)?;
        let ar_namlen = Self::read_bytes(reader, FIELD_4)?;

        let name_len = Self::parse_int(&ar_namlen)?;
        let ar_name = Self::read_bytes(reader, name_len as usize)?;
        let ar_fmag = Self::read_bytes(reader, FIELD_2)?;

        let mut file_offset = reader.get_pointer_index() as u64;
        if file_offset % 2 == 1 {
            file_offset += 1;
        }

        Ok(Self {
            ar_size,
            ar_nxtmem,
            ar_prvmem,
            ar_date,
            ar_uid,
            ar_gid,
            ar_mode,
            ar_namlen,
            ar_name,
            ar_fmag,
            file_offset,
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
            .map_err(|_| XCoffException::new("Non-UTF-8 field"))?
            .trim();
        s.parse::<i64>()
            .map_err(|_| XCoffException::new(format!("Cannot parse field: '{}'", s)))
    }

    fn parse_int(field: &[u8]) -> Result<i32, XCoffException> {
        let s = core::str::from_utf8(field)
            .map_err(|_| XCoffException::new("Non-UTF-8 field"))?
            .trim();
        s.parse::<i32>()
            .map_err(|_| XCoffException::new(format!("Cannot parse field: '{}'", s)))
    }

    fn parse_str(field: &[u8]) -> &str {
        core::str::from_utf8(field).unwrap_or("").trim()
    }

    /// Returns the file member size.
    pub fn size(&self) -> Result<i64, XCoffException> {
        Self::parse_long(&self.ar_size)
    }

    /// Returns the next member offset.
    pub fn next_member_offset(&self) -> Result<i64, XCoffException> {
        Self::parse_long(&self.ar_nxtmem)
    }

    /// Returns the previous member offset.
    pub fn previous_member_offset(&self) -> Result<i64, XCoffException> {
        Self::parse_long(&self.ar_prvmem)
    }

    /// Returns the file member date.
    pub fn date(&self) -> Result<i64, XCoffException> {
        Self::parse_long(&self.ar_date)
    }

    /// Returns the file member user ID.
    pub fn user_id(&self) -> Result<i64, XCoffException> {
        Self::parse_long(&self.ar_uid)
    }

    /// Returns the file member group ID.
    pub fn group_id(&self) -> Result<i64, XCoffException> {
        Self::parse_long(&self.ar_gid)
    }

    /// Returns the file member mode (octal).
    pub fn mode(&self) -> Result<i64, XCoffException> {
        Self::parse_long(&self.ar_mode)
    }

    /// Returns the name length.
    pub fn name_length(&self) -> Result<i32, XCoffException> {
        Self::parse_int(&self.ar_namlen)
    }

    /// Returns the member name.
    pub fn name(&self) -> &str {
        Self::parse_str(&self.ar_name)
    }

    /// Returns the terminator string.
    pub fn terminator(&self) -> &str {
        Self::parse_str(&self.ar_fmag)
    }

    /// Returns the file offset to the object data.
    pub fn object_data_offset(&self) -> u64 {
        self.file_offset
    }
}

impl fmt::Display for XCoffArchiveMemberHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ARCHIVE MEMBER HEADER VALUES")?;
        writeln!(f, "name   = {}", self.name())?;
        writeln!(f, "size   = {:?}", self.size())?;
        writeln!(f, "date   = {:?}", self.date())?;
        writeln!(f, "offset = {}", self.file_offset)
    }
}
