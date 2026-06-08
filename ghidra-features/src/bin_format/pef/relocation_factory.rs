//! PEF relocation factory ported from Ghidra's `RelocationFactory.java`.
//!
//! Decodes PEF relocation instructions from 16-bit chunks.

use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use super::relocation::Relocation;

/// Factory for parsing PEF relocation instructions.
///
/// Ported from `ghidra.app.util.bin.format.pef.RelocationFactory`.
/// Reads 16-bit relocation chunks from a `BinaryReader` and returns
/// parsed [`Relocation`] instances.
pub struct RelocationFactory;

impl RelocationFactory {
    /// Parse a single relocation instruction from the reader.
    ///
    /// Reads a 16-bit big-endian chunk and decodes it into a [`Relocation`].
    /// Returns an error if the chunk cannot be read.
    pub fn get_relocation(reader: &mut BinaryReader) -> io::Result<Relocation> {
        let chunk = reader.read_next_u16()?;
        Ok(Relocation::parse(chunk))
    }

    /// Parse multiple relocation instructions from the reader.
    ///
    /// Reads `count` 16-bit relocation chunks and returns the parsed
    /// relocations. Note that some opcodes consume additional chunks,
    /// so the reader may advance past `count * 2` bytes.
    pub fn get_relocations(
        reader: &mut BinaryReader,
        count: u32,
    ) -> io::Result<Vec<Relocation>> {
        let mut relocations = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let reloc = Self::get_relocation(reader)?;
            // For multi-chunk relocations, advance past additional chunks
            if reloc.repeat_chunks() > 0 {
                let extra_bytes = reloc.repeat_chunks() as usize * 2;
                reader.advance(extra_bytes as u64);
            }
            relocations.push(reloc);
        }
        Ok(relocations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_relocation_basic() {
        // A single BySectDWithSkip chunk: 0x0065
        let data = [0x00u8, 0x65];
        let mut reader = BinaryReader::from_bytes(&data, false);
        let reloc = RelocationFactory::get_relocation(&mut reader).unwrap();
        assert_eq!(reloc.opcode(), super::super::relocation::RelocOpcode::BySectDWithSkip);
        assert_eq!(reloc.skip_count(), 3);
        assert_eq!(reloc.reloc_count(), 5);
    }

    #[test]
    fn test_get_relocation_multiple() {
        // Two chunks: 0x0001 and 0xC000
        let data = [0x00, 0x01, 0xC0, 0x00];
        let mut reader = BinaryReader::from_bytes(&data, false);
        let relocs = RelocationFactory::get_relocations(&mut reader, 2).unwrap();
        assert_eq!(relocs.len(), 2);
        assert_eq!(relocs[0].opcode(), super::super::relocation::RelocOpcode::BySectDWithSkip);
        assert_eq!(relocs[1].opcode(), super::super::relocation::RelocOpcode::SetPosition);
    }

    #[test]
    fn test_get_relocation_eof() {
        // Empty data should return an error
        let data: [u8; 0] = [];
        let mut reader = BinaryReader::from_bytes(&data, false);
        assert!(RelocationFactory::get_relocation(&mut reader).is_err());
    }
}
