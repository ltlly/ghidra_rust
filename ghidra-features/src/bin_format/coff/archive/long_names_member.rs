//! Long names member ported from Ghidra's
//! `ghidra.app.util.bin.format.coff.archive.LongNamesMember`.
//!
//! A string table that contains the full filenames of COFF archive members whose actual
//! filenames cannot fit in the fixed-length name field.
//!
//! This string table is held in a special archive member named "//" and is usually one of
//! the first members of the archive. With MS libs, this will typically be the 3rd member
//! in the archive, right after the first and second "/" special members.

use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::byte_provider::ByteProvider;

/// Characters that terminate a long name entry (null for MS libs, newline for Linux ar).
const LONGNAME_STR_TERM_CHARS: &[u8] = b"\0\n";

/// A long names member of a COFF archive.
///
/// Ported from `ghidra.app.util.bin.format.coff.archive.LongNamesMember`.
#[derive(Debug, Clone)]
pub struct LongNamesMember {
    /// File offset where this member starts.
    file_offset: u64,
    /// Number of strings in the table.
    n_strings: usize,
    /// Lengths of each string entry (including terminator).
    lengths: Vec<usize>,
}

impl LongNamesMember {
    /// Parse a long names member from the reader.
    ///
    /// The reader should be positioned at the start of the member's payload.
    /// `size` is the payload size from the archive member header.
    pub fn parse(reader: &mut BinaryReader, size: u64) -> io::Result<Self> {
        let file_offset = reader.cursor();
        let mut n_strings = 0usize;
        let mut lengths = Vec::new();

        let end_of_strings = file_offset + size;
        let mut tmp_offset = file_offset;

        while tmp_offset < end_of_strings {
            let s = Self::read_terminated_string(reader.provider(), tmp_offset)?;
            tmp_offset += s.len() as u64 + 1;
            n_strings += 1;
            lengths.push(s.len() + 1);
        }

        Ok(Self {
            file_offset,
            n_strings,
            lengths,
        })
    }

    /// Returns the file offset of this member.
    pub fn file_offset(&self) -> u64 {
        self.file_offset
    }

    /// Returns the number of strings in the table.
    pub fn n_strings(&self) -> usize {
        self.n_strings
    }

    /// Look up the full name for an archive member header.
    ///
    /// If the header's name starts with "/" followed by digits, looks up the name
    /// at that offset in this long names table. Otherwise returns the header name
    /// as-is (with trailing "/" stripped if present).
    pub fn find_name(
        &self,
        provider: &dyn ByteProvider,
        header_name: &str,
    ) -> io::Result<String> {
        if header_name.starts_with('/') && header_name.len() > 1 {
            // Try to parse the offset after '/'
            if let Ok(offset) = header_name[1..].parse::<u64>() {
                let name = self.get_string_at_offset(provider, offset)?;
                return Ok(name);
            }
        }
        // Strip trailing slash if present
        if header_name.ends_with('/') {
            return Ok(header_name[..header_name.len() - 1].to_string());
        }
        Ok(header_name.to_string())
    }

    /// Read a null-terminated string at the given absolute offset in the provider.
    pub fn get_string_at_offset(
        &self,
        provider: &dyn ByteProvider,
        offset: u64,
    ) -> io::Result<String> {
        Self::read_terminated_string(provider, self.file_offset + offset)
    }

    /// Read a terminated string from the provider at the given index.
    fn read_terminated_string(provider: &dyn ByteProvider, mut index: u64) -> io::Result<String> {
        let len = provider.length();
        let mut bytes = Vec::new();
        while index < len {
            let b = provider.read_u8(index)?;
            if LONGNAME_STR_TERM_CHARS.contains(&b) {
                break;
            }
            bytes.push(b);
            index += 1;
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bin_format::byte_provider::ByteArrayProvider;

    #[test]
    fn test_long_names_member_parse() {
        // Build a long names table: "file1.c\0long_file_name.c\0"
        let data = b"file1.c\0long_file_name.c\0";
        let provider = ByteArrayProvider::new(None, data.to_vec());
        let mut reader = BinaryReader::from_bytes(data, true);
        let lnm = LongNamesMember::parse(&mut reader, data.len() as u64).unwrap();
        assert_eq!(lnm.n_strings, 2);
        assert_eq!(lnm.file_offset, 0);

        // Look up name at offset 0
        let name = lnm.get_string_at_offset(&provider, 0).unwrap();
        assert_eq!(name, "file1.c");

        // Look up name at offset 8 (after "file1.c\0")
        let name = lnm.get_string_at_offset(&provider, 8).unwrap();
        assert_eq!(name, "long_file_name.c");
    }

    #[test]
    fn test_find_name_with_slash() {
        let data = b"file1.c\0";
        let provider = ByteArrayProvider::new(None, data.to_vec());
        let mut reader = BinaryReader::from_bytes(data, true);
        let lnm = LongNamesMember::parse(&mut reader, data.len() as u64).unwrap();

        let name = lnm.find_name(&provider, "/0").unwrap();
        assert_eq!(name, "file1.c");
    }

    #[test]
    fn test_find_name_strips_trailing_slash() {
        let data = b"x\0";
        let provider = ByteArrayProvider::new(None, data.to_vec());
        let mut reader = BinaryReader::from_bytes(data, true);
        let lnm = LongNamesMember::parse(&mut reader, data.len() as u64).unwrap();

        let name = lnm.find_name(&provider, "myfile/").unwrap();
        assert_eq!(name, "myfile");
    }
}
