//! Second linker member ported from Ghidra's
//! `ghidra.app.util.bin.format.coff.archive.SecondLinkerMember`.

use std::io;

use crate::bin_format::binary_reader::BinaryReader;

/// The second linker member of a COFF archive (Microsoft format).
///
/// Ported from `ghidra.app.util.bin.format.coff.archive.SecondLinkerMember`.
/// This member contains member offsets, symbol indices, and a string table.
#[derive(Debug, Clone)]
pub struct SecondLinkerMember {
    /// File offset where this member starts.
    file_offset: u64,
    /// Number of archive members.
    number_of_members: u32,
    /// Offsets to each archive member. Only populated if `skip` was false.
    offsets: Option<Vec<u32>>,
    /// Number of symbols.
    number_of_symbols: u32,
    /// Indices into the offsets array (1-based). Only populated if `skip` was false.
    indices: Option<Vec<u16>>,
    /// Symbol name strings. Only populated if `skip` was false.
    string_table: Option<Vec<String>>,
    /// Lengths of each string entry (always populated).
    string_lengths: Vec<usize>,
}

impl SecondLinkerMember {
    /// Parse the second linker member from the reader.
    ///
    /// The reader should be positioned at the start of the member's payload.
    /// The header's size is used to advance the reader past this member.
    ///
    /// If `skip` is true, the data arrays are not stored (only counted).
    pub fn parse(
        reader: &mut BinaryReader,
        member_size: u64,
        skip: bool,
    ) -> io::Result<Self> {
        let file_offset = reader.cursor();
        let original_le = reader.is_little_endian();

        // Peek at the first 4 bytes to detect endianness
        let peek = reader.read_bytes_at(file_offset, 4)?;
        let peek_val = u32::from_ne_bytes([peek[0], peek[1], peek[2], peek[3]]);

        // If high byte is set and low byte is also set, we can't determine endianness
        if (peek_val & 0xff000000) != 0 && (peek_val & 0x000000ff) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid COFF: unable to determine big-endian or little-endian; too many members detected.",
            ));
        }

        // If the high byte is non-zero, the stored endianness is opposite of our reader
        let needs_swap = (peek_val & 0xff000000) != 0;

        // Read number_of_members
        let number_of_members = if needs_swap {
            let bytes = reader.read_next_bytes(4)?;
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        } else {
            reader.read_next_u32()?
        };

        let mut offsets = None;
        if skip {
            reader.advance(number_of_members as u64 * 4);
        } else {
            let mut off = Vec::with_capacity(number_of_members as usize);
            for _ in 0..number_of_members {
                let val = if needs_swap {
                    let bytes = reader.read_next_bytes(4)?;
                    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
                } else {
                    reader.read_next_u32()?
                };
                off.push(val);
            }
            offsets = Some(off);
        }

        // Read number_of_symbols
        let number_of_symbols = if needs_swap {
            let bytes = reader.read_next_bytes(4)?;
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        } else {
            reader.read_next_u32()?
        };

        let mut indices = None;
        if skip {
            reader.advance(number_of_symbols as u64 * 2);
        } else {
            let mut idx = Vec::with_capacity(number_of_symbols as usize);
            for _ in 0..number_of_symbols {
                let val = if needs_swap {
                    let bytes = reader.read_next_bytes(2)?;
                    u16::from_be_bytes([bytes[0], bytes[1]])
                } else {
                    reader.read_next_u16()?
                };
                idx.push(val);
            }
            indices = Some(idx);
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
            string_lengths.push(s.len() + 1);
        }

        // Advance past this member
        reader.set_cursor(file_offset + member_size);

        Ok(Self {
            file_offset,
            number_of_members,
            offsets,
            number_of_symbols,
            indices,
            string_table,
            string_lengths,
        })
    }

    /// Returns the file offset of this member.
    pub fn file_offset(&self) -> u64 {
        self.file_offset
    }

    /// Returns the number of archive members referenced.
    pub fn number_of_members(&self) -> u32 {
        self.number_of_members
    }

    /// Returns the member offsets. Panics if parsing was skipped.
    pub fn offsets(&self) -> &[u32] {
        self.offsets
            .as_ref()
            .expect("SecondLinkerMember: offsets were skipped")
    }

    /// Returns the number of symbols.
    pub fn number_of_symbols(&self) -> u32 {
        self.number_of_symbols
    }

    /// Returns the symbol indices (1-based into offsets). Panics if parsing was skipped.
    pub fn indices(&self) -> &[u16] {
        self.indices
            .as_ref()
            .expect("SecondLinkerMember: indices were skipped")
    }

    /// Returns the symbol string table. Panics if parsing was skipped.
    pub fn string_table(&self) -> &[String] {
        self.string_table
            .as_ref()
            .expect("SecondLinkerMember: string table was skipped")
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
    fn test_second_linker_member_parse() {
        let mut data = Vec::new();
        // numberOfMembers = 1 (little-endian)
        data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        // offsets[0] = 0x40
        data.extend_from_slice(&[0x40, 0x00, 0x00, 0x00]);
        // numberOfSymbols = 2
        data.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
        // indices[0] = 1, indices[1] = 1
        data.extend_from_slice(&[0x01, 0x00]);
        data.extend_from_slice(&[0x01, 0x00]);
        // symbol names
        data.extend_from_slice(b"_alpha\0");
        data.extend_from_slice(b"_beta\0");

        let provider = ByteArrayProvider::new(None, data.clone());
        let mut reader = BinaryReader::new(Box::new(provider), true);

        let slm = SecondLinkerMember::parse(&mut reader, data.len() as u64, false).unwrap();
        assert_eq!(slm.number_of_members(), 1);
        assert_eq!(slm.offsets(), &[0x40]);
        assert_eq!(slm.number_of_symbols(), 2);
        assert_eq!(slm.indices(), &[1, 1]);
        assert_eq!(slm.string_table(), &["_alpha", "_beta"]);
    }

    #[test]
    fn test_second_linker_member_skip() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&[0x40, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&[0x01, 0x00]);
        data.extend_from_slice(b"_sym\0");

        let provider = ByteArrayProvider::new(None, data.clone());
        let mut reader = BinaryReader::new(Box::new(provider), true);

        let slm = SecondLinkerMember::parse(&mut reader, data.len() as u64, true).unwrap();
        assert_eq!(slm.number_of_members(), 1);
        assert!(slm.offsets.is_none());
        assert!(slm.indices.is_none());
        assert!(slm.string_table.is_none());
    }
}
