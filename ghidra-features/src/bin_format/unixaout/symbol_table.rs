//! Unix a.out symbol table ported from Ghidra's `UnixAoutSymbolTable.java`.

use std::io;

use crate::bin_format::binary_reader::BinaryReader;

use super::symbol::UnixAoutSymbol;

/// A parsed UNIX a.out symbol table.
///
/// Ported from `ghidra.app.util.bin.format.unixaout.UnixAoutSymbolTable`.
/// Contains a list of [`UnixAoutSymbol`] entries parsed from the binary, with
/// names resolved from the associated string table.
#[derive(Debug)]
pub struct UnixAoutSymbolTable {
    symbols: Vec<UnixAoutSymbol>,
}

impl UnixAoutSymbolTable {
    /// Parse a symbol table from the reader.
    ///
    /// - `reader`: the binary reader (positioned anywhere; will be reset)
    /// - `file_offset`: file offset of the symbol table
    /// - `size`: size of the symbol table in bytes
    /// - `strtab`: the string table bytes (for resolving symbol names)
    /// - `strtab_offset`: file offset of the string table
    ///
    /// Returns the parsed symbol table and a list of warning messages for
    /// symbols with unknown types.
    pub fn parse(
        reader: &mut BinaryReader,
        file_offset: u64,
        size: u64,
        strtab: &[u8],
        strtab_offset: u64,
    ) -> io::Result<(Self, Vec<String>)> {
        let mut symbols = Vec::new();
        let mut warnings = Vec::new();
        let mut idx = 0usize;

        reader.set_cursor(file_offset);

        while reader.cursor() < file_offset + size {
            let str_offset = reader.read_next_u32()?;
            let type_byte = reader.read_next_u8()?;
            let other_byte = reader.read_next_u8()?;
            let desc = reader.read_next_i16()?;
            let value = reader.read_next_u32()?;

            let mut symbol = UnixAoutSymbol::new(str_offset, type_byte, other_byte, desc, value);

            if symbol.symbol_type == super::symbol::SymbolType::UNKNOWN {
                warnings.push(format!(
                    "Unknown symbol type 0x{:02x} at symbol index {}",
                    type_byte, idx
                ));
            }

            // Resolve name from string table
            // str_offset is an offset within the string table bytes
            let str_idx = str_offset as usize;
            if str_idx < strtab.len() {
                let start = str_idx;
                let end = strtab[start..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|p| start + p)
                    .unwrap_or(strtab.len());
                if start < end {
                    symbol.name = Some(String::from_utf8_lossy(&strtab[start..end]).into_owned());
                }
            }

            symbols.push(symbol);
            idx += 1;
        }

        Ok((Self { symbols }, warnings))
    }

    /// Returns the number of symbols.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Returns true if the symbol table is empty.
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Get a symbol by index.
    pub fn get(&self, index: usize) -> Option<&UnixAoutSymbol> {
        self.symbols.get(index)
    }

    /// Returns an iterator over all symbols.
    pub fn iter(&self) -> impl Iterator<Item = &UnixAoutSymbol> {
        self.symbols.iter()
    }

    /// Returns the name of the symbol at the given index, or `None`.
    pub fn symbol_name(&self, index: usize) -> Option<&str> {
        self.symbols
            .get(index)
            .and_then(|s| s.name.as_deref())
    }

    /// Find a symbol by name.
    pub fn find_by_name(&self, name: &str) -> Option<&UnixAoutSymbol> {
        self.symbols.iter().find(|s| s.name_str() == name)
    }
}

impl<'a> IntoIterator for &'a UnixAoutSymbolTable {
    type Item = &'a UnixAoutSymbol;
    type IntoIter = std::slice::Iter<'a, UnixAoutSymbol>;

    fn into_iter(self) -> Self::IntoIter {
        self.symbols.iter()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_symbol_entry(str_offset: u32, type_byte: u8, other: u8, desc: i16, value: u32) -> Vec<u8> {
        let mut entry = Vec::with_capacity(12);
        entry.extend_from_slice(&str_offset.to_le_bytes());
        entry.push(type_byte);
        entry.push(other);
        entry.extend_from_slice(&desc.to_le_bytes());
        entry.extend_from_slice(&value.to_le_bytes());
        entry
    }

    fn make_string_table(strings: &[&str]) -> Vec<u8> {
        let mut strtab = Vec::new();
        strtab.push(0); // first byte is null (empty string at offset 0)
        for s in strings {
            let offset = strtab.len() as u32;
            // Write the offset into the first 4 bytes isn't needed here,
            // we just append the string
            strtab.extend_from_slice(s.as_bytes());
            strtab.push(0);
        }
        strtab
    }

    #[test]
    fn test_parse_single_symbol() {
        let symtab_offset = 0u64;
        let strtab_offset = 0x1000u64;
        let strtab = make_string_table(&["main"]);

        // Symbol: str_offset=1 (points to "main" in strtab), type=N_TEXT(0x04|0x01=ext)
        let entry = make_symbol_entry(1, 0x05, 0x02, 0, 0x08048000);
        let mut reader = BinaryReader::from_bytes(&entry, true);
        let (table, warnings) =
            UnixAoutSymbolTable::parse(&mut reader, 0, 12, &strtab, strtab_offset).unwrap();

        assert_eq!(table.len(), 1);
        assert!(warnings.is_empty());

        let sym = table.get(0).unwrap();
        assert_eq!(sym.symbol_type, super::super::symbol::SymbolType::N_TEXT);
        assert!(sym.is_ext);
        assert_eq!(sym.name.as_deref(), Some("main"));
        assert_eq!(sym.value, 0x08048000);
    }

    #[test]
    fn test_parse_multiple_symbols() {
        let strtab = make_string_table(&["start", "loop", "end"]);
        // strtab layout: [0] = null, [1..6] = "start\0", [6..10] = "loop\0", [10..13] = "end\0"

        let mut data = Vec::new();
        // Symbol 0: str_offset=1, type=N_TEXT
        data.extend_from_slice(&make_symbol_entry(1, 0x04, 0, 0, 0x1000));
        // Symbol 1: str_offset=7, type=N_DATA
        data.extend_from_slice(&make_symbol_entry(7, 0x06, 0, 0, 0x2000));
        // Symbol 2: str_offset=12, type=N_BSS
        data.extend_from_slice(&make_symbol_entry(12, 0x08, 0, 0, 0x3000));

        let mut reader = BinaryReader::from_bytes(&data, true);
        let (table, warnings) =
            UnixAoutSymbolTable::parse(&mut reader, 0, 36, &strtab, 0).unwrap();

        assert_eq!(table.len(), 3);
        assert!(warnings.is_empty());
        assert_eq!(table.get(0).unwrap().name.as_deref(), Some("start"));
        assert_eq!(table.get(1).unwrap().name.as_deref(), Some("loop"));
        assert_eq!(table.get(2).unwrap().name.as_deref(), Some("end"));
    }

    #[test]
    fn test_unknown_type_produces_warning() {
        let strtab = make_string_table(&["weird"]);
        // type=0x0C (unknown)
        let entry = make_symbol_entry(1, 0x0C, 0, 0, 0);
        let mut reader = BinaryReader::from_bytes(&entry, true);
        let (table, warnings) =
            UnixAoutSymbolTable::parse(&mut reader, 0, 12, &strtab, 0).unwrap();

        assert_eq!(table.len(), 1);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Unknown symbol type"));
    }

    #[test]
    fn test_empty_symbol_table() {
        let strtab = vec![0u8];
        let mut reader = BinaryReader::from_bytes(&[], true);
        let (table, warnings) =
            UnixAoutSymbolTable::parse(&mut reader, 0, 0, &strtab, 0).unwrap();

        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_symbol_name_lookup() {
        let strtab = make_string_table(&["alpha", "beta"]);
        let mut data = Vec::new();
        data.extend_from_slice(&make_symbol_entry(1, 0x04, 0, 0, 0x1000));
        data.extend_from_slice(&make_symbol_entry(7, 0x04, 0, 0, 0x2000));

        let mut reader = BinaryReader::from_bytes(&data, true);
        let (table, _) =
            UnixAoutSymbolTable::parse(&mut reader, 0, 24, &strtab, 0).unwrap();

        assert_eq!(table.symbol_name(0), Some("alpha"));
        assert_eq!(table.symbol_name(1), Some("beta"));
        assert_eq!(table.symbol_name(2), None);
    }

    #[test]
    fn test_find_by_name() {
        let strtab = make_string_table(&["main", "init"]);
        let mut data = Vec::new();
        data.extend_from_slice(&make_symbol_entry(1, 0x05, 0x02, 0, 0x08048000));
        data.extend_from_slice(&make_symbol_entry(6, 0x04, 0, 0, 0x08049000));

        let mut reader = BinaryReader::from_bytes(&data, true);
        let (table, _) =
            UnixAoutSymbolTable::parse(&mut reader, 0, 24, &strtab, 0).unwrap();

        let sym = table.find_by_name("main");
        assert!(sym.is_some());
        assert_eq!(sym.unwrap().value, 0x08048000);

        assert!(table.find_by_name("nonexistent").is_none());
    }

    #[test]
    fn test_iterator() {
        let strtab = make_string_table(&["a", "b"]);
        let mut data = Vec::new();
        data.extend_from_slice(&make_symbol_entry(1, 0x04, 0, 0, 0x1000));
        data.extend_from_slice(&make_symbol_entry(3, 0x04, 0, 0, 0x2000));

        let mut reader = BinaryReader::from_bytes(&data, true);
        let (table, _) =
            UnixAoutSymbolTable::parse(&mut reader, 0, 24, &strtab, 0).unwrap();

        let names: Vec<&str> = table.iter().map(|s| s.name_str()).collect();
        assert_eq!(names, vec!["a", "b"]);
    }
}
