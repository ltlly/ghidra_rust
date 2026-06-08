//! Unix a.out relocation table ported from Ghidra's `UnixAoutRelocationTable.java`.

use std::io;

use crate::bin_format::binary_reader::BinaryReader;

use super::relocation::UnixAoutRelocation;
use super::symbol_table::UnixAoutSymbolTable;

/// A parsed UNIX a.out relocation table.
///
/// Ported from `ghidra.app.util.bin.format.unixaout.UnixAoutRelocationTable`.
/// Contains a list of [`UnixAoutRelocation`] entries parsed from the binary.
#[derive(Debug)]
pub struct UnixAoutRelocationTable {
    relocations: Vec<UnixAoutRelocation>,
}

impl UnixAoutRelocationTable {
    /// Size of a single relocation entry in bytes (two 32-bit words).
    const ENTRY_SIZE: u64 = 8;

    /// Parse a relocation table from the reader.
    ///
    /// - `reader`: the binary reader (positioned anywhere; will be reset)
    /// - `file_offset`: file offset of the relocation table
    /// - `size`: size of the relocation table in bytes
    /// - `big_endian`: whether the flags word is big-endian
    pub fn parse(
        reader: &mut BinaryReader,
        file_offset: u64,
        size: u64,
        big_endian: bool,
    ) -> io::Result<Self> {
        let mut relocations = Vec::new();
        reader.set_cursor(file_offset);

        while reader.cursor() < file_offset + size {
            let address = reader.read_next_u32()?;
            let flags = reader.read_next_u32()?;

            relocations.push(UnixAoutRelocation::new(address, flags, big_endian));
        }

        Ok(Self { relocations })
    }

    /// Returns the number of relocations.
    pub fn len(&self) -> usize {
        self.relocations.len()
    }

    /// Returns true if the relocation table is empty.
    pub fn is_empty(&self) -> bool {
        self.relocations.is_empty()
    }

    /// Get a relocation by index.
    pub fn get(&self, index: usize) -> Option<&UnixAoutRelocation> {
        self.relocations.get(index)
    }

    /// Returns an iterator over all relocations.
    pub fn iter(&self) -> impl Iterator<Item = &UnixAoutRelocation> {
        self.relocations.iter()
    }

    /// Returns the number of entries that could fit in the given size.
    pub fn entry_count(size: u64) -> usize {
        (size / Self::ENTRY_SIZE) as usize
    }
}

impl<'a> IntoIterator for &'a UnixAoutRelocationTable {
    type Item = &'a UnixAoutRelocation;
    type IntoIter = std::slice::Iter<'a, UnixAoutRelocation>;

    fn into_iter(self) -> Self::IntoIter {
        self.relocations.iter()
    }
}

/// An annotated relocation entry with symbol name resolved.
#[derive(Debug, Clone)]
pub struct AnnotatedRelocation {
    pub relocation: UnixAoutRelocation,
    pub symbol_name: Option<String>,
}

impl UnixAoutRelocationTable {
    /// Annotate relocations with symbol names from the symbol table.
    pub fn annotated(
        &self,
        symtab: &UnixAoutSymbolTable,
    ) -> Vec<AnnotatedRelocation> {
        self.relocations
            .iter()
            .map(|reloc| {
                let symbol_name = if reloc.is_extern {
                    let idx = reloc.symbol_num as usize;
                    symtab.symbol_name(idx).map(|s| s.to_string())
                } else {
                    reloc.symbol_name(&[]).map(|s| s.to_string())
                };
                AnnotatedRelocation {
                    relocation: reloc.clone(),
                    symbol_name,
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bin_format::binary_reader::BinaryReader;

    fn make_reloc_entry_be(address: u32, symbol_num: u32, flags_byte: u8) -> Vec<u8> {
        let mut data = Vec::with_capacity(8);
        data.extend_from_slice(&address.to_le_bytes());
        let flags = (symbol_num << 8) | (flags_byte as u32);
        data.extend_from_slice(&flags.to_le_bytes());
        data
    }

    #[test]
    fn test_parse_single_relocation_be() {
        // BE: address=0x1000, sym=1, flags=0x10 (extern)
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        data.extend_from_slice(&0x00000110u32.to_le_bytes());

        let mut reader = BinaryReader::from_bytes(&data, true);
        let table = UnixAoutRelocationTable::parse(&mut reader, 0, 8, true).unwrap();

        assert_eq!(table.len(), 1);
        let reloc = table.get(0).unwrap();
        assert_eq!(reloc.address, 0x1000);
        assert_eq!(reloc.symbol_num, 1);
        assert!(reloc.is_extern);
    }

    #[test]
    fn test_parse_multiple_relocations() {
        let mut data = Vec::new();
        // Reloc 0: address=0x1000, sym=0, flags=0x83 (pcrel, rel, copy)
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        data.extend_from_slice(&0x00000083u32.to_le_bytes());
        // Reloc 1: address=0x2000, sym=2, flags=0x10 (extern)
        data.extend_from_slice(&0x2000u32.to_le_bytes());
        data.extend_from_slice(&0x00000210u32.to_le_bytes());

        let mut reader = BinaryReader::from_bytes(&data, true);
        let table = UnixAoutRelocationTable::parse(&mut reader, 0, 16, true).unwrap();

        assert_eq!(table.len(), 2);
        assert_eq!(table.get(0).unwrap().address, 0x1000);
        assert!(table.get(0).unwrap().pc_relative);
        assert_eq!(table.get(1).unwrap().address, 0x2000);
        assert!(table.get(1).unwrap().is_extern);
    }

    #[test]
    fn test_empty_table() {
        let mut reader = BinaryReader::from_bytes(&[], true);
        let table = UnixAoutRelocationTable::parse(&mut reader, 0, 0, true).unwrap();
        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
    }

    #[test]
    fn test_entry_count() {
        assert_eq!(UnixAoutRelocationTable::entry_count(0), 0);
        assert_eq!(UnixAoutRelocationTable::entry_count(7), 0);
        assert_eq!(UnixAoutRelocationTable::entry_count(8), 1);
        assert_eq!(UnixAoutRelocationTable::entry_count(16), 2);
        assert_eq!(UnixAoutRelocationTable::entry_count(24), 3);
    }

    #[test]
    fn test_iterator() {
        let mut data = Vec::new();
        for i in 0..3u32 {
            data.extend_from_slice(&(i * 0x1000).to_le_bytes());
            data.extend_from_slice(&((i << 8) | 0x10u32).to_le_bytes()); // extern
        }

        let mut reader = BinaryReader::from_bytes(&data, true);
        let table = UnixAoutRelocationTable::parse(&mut reader, 0, 24, true).unwrap();

        let addrs: Vec<u32> = table.iter().map(|r| r.address).collect();
        assert_eq!(addrs, vec![0, 0x1000, 0x2000]);
    }

    #[test]
    fn test_little_endian_parse() {
        // LE: address=0x3000, sym=3, flags_byte=0x08 (extern)
        let mut data = Vec::new();
        data.extend_from_slice(&0x3000u32.to_le_bytes());
        data.extend_from_slice(&0x08000003u32.to_le_bytes());

        let mut reader = BinaryReader::from_bytes(&data, true);
        let table = UnixAoutRelocationTable::parse(&mut reader, 0, 8, false).unwrap();

        assert_eq!(table.len(), 1);
        let reloc = table.get(0).unwrap();
        assert_eq!(reloc.address, 0x3000);
        assert_eq!(reloc.symbol_num, 3);
        assert!(reloc.is_extern);
    }
}
