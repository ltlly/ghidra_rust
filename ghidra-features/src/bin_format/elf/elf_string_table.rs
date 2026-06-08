//! ELF string table implementation ported from Ghidra's `ElfStringTable.java`.
//!
//! Provides:
//! - [`ElfStringTable`] -- a string table backed by a byte slice or file region
//! - String reading at specified offsets within the table
//! - Bounds checking and error handling for invalid offsets

use std::fmt;

use super::elf_exception::ElfException;

// ---------------------------------------------------------------------------
// ElfFileSection Trait
// ---------------------------------------------------------------------------

/// Trait for ELF file sections that can be loaded into memory.
///
/// Ported from `ghidra.app.util.bin.format.elf.ElfFileSection`. Provides
/// access to the section's file offset, memory address offset, length,
/// and entry size.
pub trait ElfFileSection {
    /// Preferred memory address offset where data should be loaded.
    ///
    /// The returned offset should already have the prelink adjustment applied,
    /// although will not reflect any change in the image base.
    fn address_offset(&self) -> u64;

    /// Offset within the file where section bytes are located.
    fn file_offset(&self) -> u64;

    /// Length of the file section in bytes.
    fn length(&self) -> u64;

    /// Size of each structured entry in bytes, or -1 if variable.
    fn entry_size(&self) -> i32;
}

// ---------------------------------------------------------------------------
// ElfStringTable
// ---------------------------------------------------------------------------

/// An ELF string table.
///
/// String tables are used to store null-terminated strings referenced by
/// other ELF structures (section names, symbol names, etc.). The table
/// is typically backed by a section (e.g., `.strtab` or `.dynstr`) or
/// by a dynamic table entry.
///
/// Ported from `ghidra.app.util.bin.format.elf.ElfStringTable`.
pub struct ElfStringTable {
    /// The section header for this string table, if associated with a section.
    section_index: Option<u32>,
    /// The file offset where the string table begins.
    file_offset: u64,
    /// The memory address offset where the string table should be loaded.
    addr_offset: u64,
    /// The length of the string table in bytes.
    length: u64,
    /// The raw bytes of the string table (if loaded in memory).
    data: Vec<u8>,
}

impl ElfStringTable {
    /// Create a new string table from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `section_index` - Optional section header index for this string table.
    /// * `file_offset` - The file offset where the string table begins.
    /// * `addr_offset` - The memory address offset for loading.
    /// * `data` - The raw bytes of the string table.
    pub fn new(
        section_index: Option<u32>,
        file_offset: u64,
        addr_offset: u64,
        data: Vec<u8>,
    ) -> Self {
        let length = data.len() as u64;
        Self {
            section_index,
            file_offset,
            addr_offset,
            length,
            data,
        }
    }

    /// Create a new string table from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `section_index` - Optional section header index for this string table.
    /// * `file_offset` - The file offset where the string table begins.
    /// * `addr_offset` - The memory address offset for loading.
    /// * `data` - The raw bytes of the string table.
    pub fn from_slice(
        section_index: Option<u32>,
        file_offset: u64,
        addr_offset: u64,
        data: &[u8],
    ) -> Self {
        Self::new(section_index, file_offset, addr_offset, data.to_vec())
    }

    /// Read a null-terminated string from the table at the specified offset.
    ///
    /// # Arguments
    ///
    /// * `string_offset` - The offset within the string table where the string begins.
    ///
    /// # Returns
    ///
    /// The string at the given offset, or `None` if the offset is out of bounds
    /// or the string cannot be decoded.
    pub fn read_string(&self, string_offset: u64) -> Option<&str> {
        if string_offset >= self.length {
            return None;
        }

        let start = string_offset as usize;
        let end = self.data.len();

        // Find the null terminator
        let null_pos = self.data[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| start + p)
            .unwrap_or(end);

        // Attempt to decode as UTF-8
        std::str::from_utf8(&self.data[start..null_pos]).ok()
    }

    /// Read a null-terminated string from the table at the specified offset,
    /// returning an error if the offset is out of bounds.
    ///
    /// # Arguments
    ///
    /// * `string_offset` - The offset within the string table where the string begins.
    ///
    /// # Returns
    ///
    /// The string at the given offset, or an [`ElfException`] if the offset
    /// is out of bounds.
    pub fn read_string_or_err(&self, string_offset: u64) -> Result<&str, ElfException> {
        if string_offset >= self.length {
            return Err(ElfException::new(format!(
                "String read beyond table bounds: offset 0x{:x}, table length 0x{:x}",
                string_offset, self.length
            )));
        }

        self.read_string(string_offset)
            .ok_or_else(|| ElfException::new("Failed to decode string as UTF-8"))
    }

    /// Read a string at the given offset, trimming whitespace.
    ///
    /// # Arguments
    ///
    /// * `string_offset` - The offset within the string table where the string begins.
    ///
    /// # Returns
    ///
    /// The trimmed string, or `None` if the offset is out of bounds.
    pub fn read_string_trimmed(&self, string_offset: u64) -> Option<&str> {
        self.read_string(string_offset).map(|s| s.trim())
    }

    /// Get the section index associated with this string table, if any.
    pub fn section_index(&self) -> Option<u32> {
        self.section_index
    }

    /// Get the raw bytes of the string table.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the length of the string table in bytes.
    pub fn len(&self) -> u64 {
        self.length
    }

    /// Returns `true` if the string table is empty.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Returns an iterator over all strings in the table.
    ///
    /// The iterator yields `(offset, &str)` pairs for each null-terminated
    /// string found in the table. Empty strings (at offset 0) are included.
    pub fn iter_strings(&self) -> StringTableIterator<'_> {
        StringTableIterator {
            table: self,
            offset: 0,
        }
    }

    /// Count the number of strings in the table.
    pub fn string_count(&self) -> usize {
        self.iter_strings().count()
    }
}

impl ElfFileSection for ElfStringTable {
    fn address_offset(&self) -> u64 {
        self.addr_offset
    }

    fn file_offset(&self) -> u64 {
        self.file_offset
    }

    fn length(&self) -> u64 {
        self.length
    }

    fn entry_size(&self) -> i32 {
        -1 // Variable-length strings
    }
}

impl fmt::Debug for ElfStringTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ElfStringTable")
            .field("section_index", &self.section_index)
            .field("file_offset", &format_args!("0x{:x}", self.file_offset))
            .field("addr_offset", &format_args!("0x{:x}", self.addr_offset))
            .field("length", &format_args!("0x{:x}", self.length))
            .finish()
    }
}

// ---------------------------------------------------------------------------
// StringTableIterator
// ---------------------------------------------------------------------------

/// An iterator over the strings in an [`ElfStringTable`].
///
/// Yields `(offset, &str)` pairs for each null-terminated string in the table.
pub struct StringTableIterator<'a> {
    table: &'a ElfStringTable,
    offset: u64,
}

impl<'a> Iterator for StringTableIterator<'a> {
    type Item = (u64, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.table.length {
            return None;
        }

        let start = self.offset as usize;
        let data = &self.table.data;
        let end = data.len();

        // Find the null terminator
        let null_pos = data[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| start + p)
            .unwrap_or(end);

        let current_offset = self.offset;
        let s = std::str::from_utf8(&data[start..null_pos]).unwrap_or("");

        // Move past the null terminator (if found) or to end
        self.offset = if null_pos < end {
            (null_pos + 1) as u64
        } else {
            end as u64
        };

        Some((current_offset, s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_table_basic() {
        // "\0hello\0world\0"
        let data = b"\0hello\0world\0";
        let table = ElfStringTable::new(None, 0, 0, data.to_vec());

        assert_eq!(table.len(), 13);
        assert!(!table.is_empty());
        assert_eq!(table.read_string(0), Some(""));
        assert_eq!(table.read_string(1), Some("hello"));
        assert_eq!(table.read_string(7), Some("world"));
    }

    #[test]
    fn test_string_table_out_of_bounds() {
        let data = b"\0hello\0";
        let table = ElfStringTable::new(None, 0, 0, data.to_vec());

        assert_eq!(table.read_string(100), None);
        assert!(table.read_string_or_err(100).is_err());
    }

    #[test]
    fn test_string_table_read_string_trimmed() {
        let data = b"\0  hello  \0world\0";
        let table = ElfStringTable::new(None, 0, 0, data.to_vec());

        assert_eq!(table.read_string_trimmed(1), Some("hello"));
        assert_eq!(table.read_string_trimmed(11), Some("world"));
    }

    #[test]
    fn test_string_table_iter() {
        let data = b"\0hello\0world\0";
        let table = ElfStringTable::new(None, 0, 0, data.to_vec());

        let strings: Vec<(u64, &str)> = table.iter_strings().collect();
        assert_eq!(strings.len(), 3);
        assert_eq!(strings[0], (0, ""));
        assert_eq!(strings[1], (1, "hello"));
        assert_eq!(strings[2], (7, "world"));
    }

    #[test]
    fn test_string_table_string_count() {
        let data = b"\0hello\0world\0";
        let table = ElfStringTable::new(None, 0, 0, data.to_vec());
        assert_eq!(table.string_count(), 3);
    }

    #[test]
    fn test_string_table_empty() {
        let data = b"";
        let table = ElfStringTable::new(None, 0, 0, data.to_vec());
        assert!(table.is_empty());
        assert_eq!(table.string_count(), 0);
    }

    #[test]
    fn test_string_table_section_index() {
        let data = b"\0test\0";
        let table = ElfStringTable::new(Some(5), 0x100, 0x200, data.to_vec());
        assert_eq!(table.section_index(), Some(5));
        assert_eq!(table.file_offset(), 0x100);
        assert_eq!(table.address_offset(), 0x200);
    }

    #[test]
    fn test_string_table_entry_size() {
        let data = b"\0test\0";
        let table = ElfStringTable::new(None, 0, 0, data.to_vec());
        assert_eq!(table.entry_size(), -1);
    }

    #[test]
    fn test_string_table_from_slice() {
        let data = b"\0hello\0";
        let table = ElfStringTable::from_slice(None, 0, 0, data);
        assert_eq!(table.read_string(1), Some("hello"));
    }

    #[test]
    fn test_string_table_debug() {
        let data = b"\0test\0";
        let table = ElfStringTable::new(Some(3), 0x100, 0x200, data.to_vec());
        let debug = format!("{:?}", table);
        assert!(debug.contains("ElfStringTable"));
        assert!(debug.contains("section_index: Some(3)"));
    }

    #[test]
    fn test_string_table_multiple_strings() {
        // Simulate a real .strtab with section names
        // Layout: \0 . t e x t \0 . d a t a \0 . b s s \0 . s y m t a b \0 . s t r t a b \0
        //         0  1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33
        let data = b"\0.text\0.data\0.bss\0.symtab\0.strtab\0";
        let table = ElfStringTable::new(Some(1), 0, 0, data.to_vec());

        assert_eq!(table.read_string(1), Some(".text"));
        assert_eq!(table.read_string(7), Some(".data"));
        assert_eq!(table.read_string(13), Some(".bss"));
        assert_eq!(table.read_string(18), Some(".symtab"));
        assert_eq!(table.read_string(26), Some(".strtab"));
    }
}
