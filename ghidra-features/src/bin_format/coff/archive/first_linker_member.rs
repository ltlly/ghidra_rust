//! First linker member ported from Ghidra's
//! `ghidra.app.util.bin.format.coff.archive.FirstLinkerMember`.

use std::io;

use crate::bin_format::binary_reader::BinaryReader;

/// The first linker member of a COFF archive (Microsoft format).
///
/// Ported from `ghidra.app.util.bin.format.coff.archive.FirstLinkerMember`.
/// This member contains an array of offsets and a string table of symbol names.
/// The entire structure is stored in big-endian format.
#[derive(Debug, Clone)]
pub struct FirstLinkerMember {
    /// File offset where this member starts.
    file_offset: u64,
    /// Number of symbols.
    number_of_symbols: u32,
    /// Offsets to archive members (one per symbol). Only populated if `skip` was false.
    offsets: Option<Vec<u32>>,
    /// Symbol name strings. Only populated if `skip` was false.
    string_table: Option<Vec<String>>,
    /// Lengths of each string entry (always populated, for layout calculations).
    string_lengths: Vec<usize>,
}

impl FirstLinkerMember {
    /// Parse the first linker member from the reader.
    ///
    /// The reader should be positioned at the start of the member's payload.
    /// The header's size is used to advance the reader past this member.
    ///
    /// If `skip` is true, the offsets and string table are not stored (only counted).
    pub fn parse(
        reader: &mut BinaryReader,
        member_size: u64,
        skip: bool,
    ) -> io::Result<Self> {
        let file_offset = reader.cursor();
        let is_le = reader.is_little_endian();

        // This structure is always big-endian
        let number_of_symbols = if is_le {
            let bytes = reader.read_next_bytes(4)?;
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        } else {
            reader.read_next_u32()?
        };

        let mut offsets = None;
        if skip {
            // Skip past the offsets array
            reader.advance(number_of_symbols as u64 * 4);
        } else {
            let mut off = Vec::with_capacity(number_of_symbols as usize);
            for _ in 0..number_of_symbols {
                let val = if is_le {
                    let bytes = reader.read_next_bytes(4)?;
                    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
                } else {
                    reader.read_next_u32()?
                };
                off.push(val);
            }
            offsets = Some(off);
        }

        let mut string_table = if skip { None } else { Some(Vec::new()) };
        let mut string_lengths = Vec::new();

        for _ in 0..number_of_symbols {
            let s = reader.read_next_cstring()?;
            if !skip {
                if let Some(ref mut st) = string_table {
                    st.push(s.clone());
                }
            }
            string_lengths.push(s.len() + 1); // +1 for null terminator
        }

        // Advance past this member
        reader.set_cursor(file_offset + member_size);

        Ok(Self {
            file_offset,
            number_of_symbols,
            offsets,
            string_table,
            string_lengths,
        })
    }

    /// Returns the file offset of this member.
    pub fn file_offset(&self) -> u64 {
        self.file_offset
    }

    /// Returns the number of symbols.
    pub fn number_of_symbols(&self) -> u32 {
        self.number_of_symbols
    }

    /// Returns the offsets array. Panics if parsing was skipped.
    pub fn offsets(&self) -> &[u32] {
        self.offsets
            .as_ref()
            .expect("FirstLinkerMember: offsets were skipped")
    }

    /// Returns the string table. Panics if parsing was skipped.
    pub fn string_table(&self) -> &[String] {
        self.string_table
            .as_ref()
            .expect("FirstLinkerMember: string table was skipped")
    }

    /// Returns the string lengths (always available).
    pub fn string_lengths(&self) -> &[usize] {
        &self.string_lengths
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bin_format::byte_provider::ByteArrayProvider;

    #[test]
    fn test_first_linker_member_parse() {
        // Build a first linker member with 2 symbols
        let mut data = Vec::new();
        // numberOfSymbols = 2 (big-endian)
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]);
        // offsets[0] = 0x10, offsets[1] = 0x20 (big-endian)
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x10]);
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x20]);
        // symbol names (null-terminated)
        data.extend_from_slice(b"_foo\0");
        data.extend_from_slice(b"_bar\0");

        let provider = ByteArrayProvider::new(None, data.clone());
        let mut reader = BinaryReader::new(Box::new(provider), true);

        let flm = FirstLinkerMember::parse(&mut reader, data.len() as u64, false).unwrap();
        assert_eq!(flm.number_of_symbols(), 2);
        assert_eq!(flm.offsets(), &[0x10, 0x20]);
        assert_eq!(flm.string_table(), &["_foo", "_bar"]);
        assert_eq!(flm.string_lengths(), &[5, 5]);
    }

    #[test]
    fn test_first_linker_member_skip() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x30]);
        data.extend_from_slice(b"_sym\0");

        let provider = ByteArrayProvider::new(None, data.clone());
        let mut reader = BinaryReader::new(Box::new(provider), true);

        let flm = FirstLinkerMember::parse(&mut reader, data.len() as u64, true).unwrap();
        assert_eq!(flm.number_of_symbols(), 1);
        assert!(flm.offsets.is_none());
        assert!(flm.string_table.is_none());
        assert_eq!(flm.string_lengths, vec![5]);
    }
}
