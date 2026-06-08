//! PEF loader relocation header ported from Ghidra's `LoaderRelocationHeader.java`.
//!
//! Represents the relocation header within a PEF loader section.

use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use super::relocation::Relocation;
use super::relocation_factory::RelocationFactory;

/// PEF loader relocation header.
///
/// See Apple's PEFBinaryFormat.h:
/// ```c
/// struct PEFLoaderRelocationHeader {
///     UInt16   sectionIndex;
///     UInt16   reservedA;
///     UInt32   relocCount;
///     UInt32   firstRelocOffset;
/// };
/// ```
#[derive(Debug, Clone)]
pub struct LoaderRelocationHeader {
    /// Index of the section to be fixed up.
    section_index: u16,
    /// Reserved, must be zero.
    reserved_a: u16,
    /// Number of 16-bit relocation chunks.
    reloc_count: u32,
    /// Offset of first relocation instruction (from start of relocation area).
    first_reloc_offset: u32,
    /// The parsed relocation instructions.
    relocations: Vec<Relocation>,
}

impl LoaderRelocationHeader {
    /// Size of a loader relocation header in bytes.
    pub const SIZE: usize = 12;

    /// Parse a loader relocation header from a big-endian binary reader.
    ///
    /// `container_offset` is the PEF section container offset.
    /// `reloc_instr_offset` is the loader section's relocInstrOffset.
    pub fn parse(
        reader: &mut BinaryReader,
        container_offset: u32,
        reloc_instr_offset: u32,
    ) -> io::Result<Self> {
        let section_index = reader.read_next_u16()?;
        let reserved_a = reader.read_next_u16()?;
        let reloc_count = reader.read_next_u32()?;
        let first_reloc_offset = reader.read_next_u32()?;

        // Save the reader position and seek to relocations
        let saved_pos = reader.cursor();
        let reloc_start = container_offset as u64
            + reloc_instr_offset as u64
            + first_reloc_offset as u64;
        reader.set_cursor(reloc_start);

        let relocations =
            RelocationFactory::get_relocations(reader, reloc_count)?;

        // Restore the reader position
        reader.set_cursor(saved_pos);

        Ok(Self {
            section_index,
            reserved_a,
            reloc_count,
            first_reloc_offset,
            relocations,
        })
    }

    /// Returns the section number to which this relocation header refers.
    pub fn section_index(&self) -> u16 {
        self.section_index
    }

    /// Returns the reserved field (should be zero).
    pub fn reserved_a(&self) -> u16 {
        self.reserved_a
    }

    /// Returns the number of 16-bit relocation blocks for this section.
    pub fn reloc_count(&self) -> u32 {
        self.reloc_count
    }

    /// Returns the offset from the start of the relocations area to the
    /// first relocation instruction for this section.
    pub fn first_reloc_offset(&self) -> u32 {
        self.first_reloc_offset
    }

    /// Returns the parsed relocation instructions.
    pub fn relocations(&self) -> &[Relocation] {
        &self.relocations
    }
}

impl std::fmt::Display for LoaderRelocationHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "LoaderRelocationHeader(section={}, relocs={})",
            self.section_index, self.reloc_count
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_relocation_header_bytes(
        section_index: u16,
        reloc_count: u32,
        first_reloc_offset: u32,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&section_index.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes()); // reservedA
        data.extend_from_slice(&reloc_count.to_be_bytes());
        data.extend_from_slice(&first_reloc_offset.to_be_bytes());
        data
    }

    #[test]
    fn test_parse_loader_relocation_header() {
        let mut bytes = make_relocation_header_bytes(2, 3, 0);

        // Append 3 relocation chunks (6 bytes) starting at offset 0
        // Chunk 1: BySectDWithSkip with skip=1, reloc=2 -> 0x0022
        bytes.extend_from_slice(&0x0022u16.to_be_bytes());
        // Chunk 2: SetPosition -> 0xC000 | 5
        bytes.extend_from_slice(&0xC005u16.to_be_bytes());
        // Chunk 3: BySectDWithSkip -> 0x0001
        bytes.extend_from_slice(&0x0001u16.to_be_bytes());

        let mut reader = BinaryReader::from_bytes(&bytes, false);
        let header = LoaderRelocationHeader::parse(&mut reader, 0, 0).unwrap();

        assert_eq!(header.section_index(), 2);
        assert_eq!(header.reloc_count(), 3);
        assert_eq!(header.first_reloc_offset(), 0);
        assert_eq!(header.relocations().len(), 3);
    }

    #[test]
    fn test_parse_no_relocations() {
        let bytes = make_relocation_header_bytes(0, 0, 0);
        let mut reader = BinaryReader::from_bytes(&bytes, false);
        let header = LoaderRelocationHeader::parse(&mut reader, 0, 0).unwrap();

        assert_eq!(header.section_index(), 0);
        assert_eq!(header.reloc_count(), 0);
        assert!(header.relocations().is_empty());
    }

    #[test]
    fn test_loader_relocation_header_display() {
        let bytes = make_relocation_header_bytes(1, 5, 10);
        let mut reader = BinaryReader::from_bytes(&bytes, false);
        let header = LoaderRelocationHeader::parse(&mut reader, 0, 0).unwrap();

        let s = format!("{}", header);
        assert!(s.contains("section=1"));
        assert!(s.contains("relocs=5"));
    }
}
