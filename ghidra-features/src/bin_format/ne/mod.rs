//! Windows New Executable (NE) format ported from Ghidra's
//! `ghidra.app.util.bin.format.ne` package.
//!
//! Provides types for parsing 16-bit Windows New Executables:
//! - [`NewExecutable`] -- top-level NE parser
//! - [`WindowsHeader`] -- NE header orchestrator
//! - [`InformationBlock`] -- IMAGE_OS2_HEADER structure
//! - [`Segment`] / [`SegmentTable`] -- segment descriptors
//! - [`SegmentRelocation`] -- segment relocation entries
//! - [`EntryTable`] / [`EntryTableBundle`] / [`EntryPoint`] -- entry point data
//! - [`ResourceTable`] / [`ResourceType`] / [`Resource`] -- resource definitions
//! - [`ResidentNameTable`] / [`NonResidentNameTable`] -- name tables
//! - [`ModuleReferenceTable`] / [`ImportedNameTable`] -- import tables
//! - [`LengthStringSet`] / [`LengthStringOrdinalSet`] -- string primitives

pub mod entry_table;
pub mod information_block;
pub mod resource_table;
pub mod segment;
pub mod windows_header;

pub use entry_table::{EntryPoint, EntryTable, EntryTableBundle};
pub use information_block::InformationBlock;
pub use resource_table::{Resource, ResourceName, ResourceStringTable, ResourceTable, ResourceType};
pub use segment::{Segment, SegmentRelocation, SegmentTable};
pub use windows_header::WindowsHeader;

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::mz::DOSHeader;

// ---------------------------------------------------------------------------
// Exceptions
// ---------------------------------------------------------------------------

/// Error for invalid Windows NE headers.
#[derive(Debug)]
pub struct InvalidWindowsHeaderError;

impl fmt::Display for InvalidWindowsHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid Windows NE header")
    }
}

impl std::error::Error for InvalidWindowsHeaderError {}

// ---------------------------------------------------------------------------
// LengthStringSet
// ---------------------------------------------------------------------------

/// A length-prefixed, non-null-terminated string.
///
/// Ported from `ghidra.app.util.bin.format.ne.LengthStringSet`.
/// The first byte is the length, followed by that many ASCII bytes.
#[derive(Debug, Clone)]
pub struct LengthStringSet {
    /// Byte index where this string was located in the file.
    pub(crate) index: u64,
    /// Length of the string.
    pub(crate) length: u8,
    /// The string content.
    pub(crate) name: String,
}

impl LengthStringSet {
    /// Parse a length-prefixed string from the reader at its current position.
    pub fn parse(reader: &mut BinaryReader) -> io::Result<Self> {
        let index = reader.cursor();
        let length = reader.read_next_u8()?;

        if length == 0 {
            return Ok(Self {
                index,
                length: 0,
                name: String::new(),
            });
        }

        let name = reader.read_next_fixed_string(length as usize)?;

        Ok(Self { index, length, name })
    }

    /// Returns the byte index of this string, relative to the beginning of the file.
    pub fn index(&self) -> u64 {
        self.index
    }

    /// Returns the length of the string.
    pub fn length(&self) -> u8 {
        self.length
    }

    /// Returns the string content.
    pub fn string(&self) -> &str {
        &self.name
    }
}

// ---------------------------------------------------------------------------
// LengthStringOrdinalSet
// ---------------------------------------------------------------------------

/// A length-prefixed string followed by an ordinal value.
///
/// Ported from `ghidra.app.util.bin.format.ne.LengthStringOrdinalSet`.
/// Extends [`LengthStringSet`] with a 16-bit ordinal that follows the string.
#[derive(Debug, Clone)]
pub struct LengthStringOrdinalSet {
    /// The base length/string set.
    base: LengthStringSet,
    /// The ordinal value.
    ordinal: i16,
}

impl LengthStringOrdinalSet {
    /// Parse a length/string/ordinal set from the reader.
    pub fn parse(reader: &mut BinaryReader) -> io::Result<Self> {
        let base = LengthStringSet::parse(reader)?;

        if base.length() == 0 {
            return Ok(Self { base, ordinal: 0 });
        }

        let ordinal = reader.read_next_i16()?;

        Ok(Self { base, ordinal })
    }

    /// Returns the length of the string.
    pub fn length(&self) -> u8 {
        self.base.length()
    }

    /// Returns the string content.
    pub fn string(&self) -> &str {
        self.base.string()
    }

    /// Returns the byte index of this string.
    pub fn index(&self) -> u64 {
        self.base.index()
    }

    /// Returns the ordinal value.
    pub fn ordinal(&self) -> i16 {
        self.ordinal
    }
}

// ---------------------------------------------------------------------------
// ImportedNameTable
// ---------------------------------------------------------------------------

/// The imported name table in a New Executable.
///
/// Ported from `ghidra.app.util.bin.format.ne.ImportedNameTable`.
/// Stores references to imported module names by offset.
#[derive(Debug)]
pub struct ImportedNameTable {
    /// Byte index where the table begins in the file.
    index: u64,
}

impl ImportedNameTable {
    /// Create a new imported name table reference.
    pub fn new(index: u64) -> Self {
        Self { index }
    }

    /// Returns the length/string set at the given offset within this table.
    pub fn get_name_at(
        &self,
        reader: &mut BinaryReader,
        offset: u16,
    ) -> io::Result<LengthStringSet> {
        let old_index = reader.cursor();
        let new_index = self.index + offset as u64;
        reader.set_cursor(new_index);
        let lss = LengthStringSet::parse(reader)?;
        reader.set_cursor(old_index);
        Ok(lss)
    }

    /// Returns the byte index where this table begins.
    pub fn index(&self) -> u64 {
        self.index
    }
}

// ---------------------------------------------------------------------------
// ModuleReferenceTable
// ---------------------------------------------------------------------------

/// The module reference table in a New Executable.
///
/// Ported from `ghidra.app.util.bin.format.ne.ModuleReferenceTable`.
/// Lists the modules (DLLs) referenced by this executable.
#[derive(Debug)]
pub struct ModuleReferenceTable {
    /// Offsets into the imported name table.
    offsets: Vec<u16>,
    /// Resolved module names.
    names: Vec<String>,
}

impl ModuleReferenceTable {
    /// Parse a module reference table from the reader.
    pub fn parse(
        reader: &mut BinaryReader,
        index: u64,
        count: u16,
        imp_table: &ImportedNameTable,
    ) -> io::Result<Self> {
        let old_index = reader.cursor();
        reader.set_cursor(index);

        let count_usize = count as usize;
        let mut offsets = Vec::with_capacity(count_usize);
        for _ in 0..count_usize {
            offsets.push(reader.read_next_u16()?);
        }

        let mut names = Vec::new();
        for &off in &offsets {
            let lss = imp_table.get_name_at(reader, off)?;
            if lss.length() == 0 {
                break;
            }
            names.push(lss.string().to_string());
        }

        reader.set_cursor(old_index);

        Ok(Self { offsets, names })
    }

    /// Returns the offsets into the imported name table.
    pub fn offsets(&self) -> &[u16] {
        &self.offsets
    }

    /// Returns the resolved module names.
    pub fn names(&self) -> &[String] {
        &self.names
    }
}

// ---------------------------------------------------------------------------
// ResidentNameTable
// ---------------------------------------------------------------------------

/// The resident name table in a New Executable.
///
/// Ported from `ghidra.app.util.bin.format.ne.ResidentNameTable`.
/// Contains exported function names that are kept in memory.
#[derive(Debug)]
pub struct ResidentNameTable {
    names: Vec<LengthStringOrdinalSet>,
}

impl ResidentNameTable {
    /// Parse a resident name table from the reader.
    pub fn parse(reader: &mut BinaryReader, index: u64) -> io::Result<Self> {
        let old_index = reader.cursor();
        reader.set_cursor(index);

        let mut names = Vec::new();
        loop {
            let lsos = LengthStringOrdinalSet::parse(reader)?;
            if lsos.length() == 0 {
                break;
            }
            names.push(lsos);
        }

        reader.set_cursor(old_index);
        Ok(Self { names })
    }

    /// Returns the array of names defined in the resident name table.
    pub fn names(&self) -> &[LengthStringOrdinalSet] {
        &self.names
    }
}

// ---------------------------------------------------------------------------
// NonResidentNameTable
// ---------------------------------------------------------------------------

/// The non-resident name table in a New Executable.
///
/// Ported from `ghidra.app.util.bin.format.ne.NonResidentNameTable`.
/// Contains exported names and the module description that are not
/// kept in memory.
#[derive(Debug)]
pub struct NonResidentNameTable {
    /// The module title (first entry with ordinal 0).
    title: String,
    names: Vec<LengthStringOrdinalSet>,
}

impl NonResidentNameTable {
    /// Parse a non-resident name table from the reader.
    pub fn parse(reader: &mut BinaryReader, index: u64, _byte_count: u16) -> io::Result<Self> {
        let old_index = reader.cursor();
        reader.set_cursor(index);

        let mut title = String::from("<not set>");
        let mut names = Vec::new();

        loop {
            let lsos = LengthStringOrdinalSet::parse(reader)?;
            if lsos.length() == 0 {
                break;
            }
            if lsos.ordinal() == 0 {
                title = lsos.string().to_string();
            }
            names.push(lsos);
        }

        reader.set_cursor(old_index);
        Ok(Self { title, names })
    }

    /// Returns the module title (description string).
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the array of names defined in the non-resident name table.
    pub fn names(&self) -> &[LengthStringOrdinalSet] {
        &self.names
    }
}

// ---------------------------------------------------------------------------
// NewExecutable
// ---------------------------------------------------------------------------

/// Top-level parser for Windows New Executable (NE) format files.
///
/// Ported from `ghidra.app.util.bin.format.ne.NewExecutable`.
/// Parses the DOS header and Windows NE header from a byte provider.
pub struct NewExecutable {
    reader: BinaryReader,
    dos_header: DOSHeader,
    win_header: Option<WindowsHeader>,
}

impl NewExecutable {
    /// Parse a New Executable from the given byte data.
    pub fn parse(data: &[u8]) -> io::Result<Self> {
        let mut reader = BinaryReader::from_bytes(data, true);
        let dos_header = DOSHeader::parse(&mut reader)?;

        let win_header = if dos_header.base.is_dos_signature() {
            match WindowsHeader::parse(&mut reader, dos_header.e_lfanew as u64) {
                Ok(wh) => Some(wh),
                Err(_) => None,
            }
        } else {
            None
        };

        Ok(Self {
            reader,
            dos_header,
            win_header,
        })
    }

    /// Returns a reference to the binary reader.
    pub fn reader(&self) -> &BinaryReader {
        &self.reader
    }

    /// Returns a mutable reference to the binary reader.
    pub fn reader_mut(&mut self) -> &mut BinaryReader {
        &mut self.reader
    }

    /// Returns a reference to the DOS header.
    pub fn dos_header(&self) -> &DOSHeader {
        &self.dos_header
    }

    /// Returns a reference to the Windows NE header, if present.
    pub fn windows_header(&self) -> Option<&WindowsHeader> {
        self.win_header.as_ref()
    }

    /// Returns true if the file has a valid DOS signature.
    pub fn is_dos_signature(&self) -> bool {
        self.dos_header.base.is_dos_signature()
    }

    /// Returns true if a valid NE Windows header was found.
    pub fn has_windows_header(&self) -> bool {
        self.win_header.is_some()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_length_string_set_parse() {
        // Length=5, followed by "Hello"
        let data = vec![5, b'H', b'e', b'l', b'l', b'o'];
        let mut reader = BinaryReader::from_bytes(&data, true);
        let lss = LengthStringSet::parse(&mut reader).unwrap();

        assert_eq!(lss.length(), 5);
        assert_eq!(lss.string(), "Hello");
        assert_eq!(lss.index(), 0);
    }

    #[test]
    fn test_length_string_set_empty() {
        let data = vec![0u8];
        let mut reader = BinaryReader::from_bytes(&data, true);
        let lss = LengthStringSet::parse(&mut reader).unwrap();

        assert_eq!(lss.length(), 0);
        assert_eq!(lss.string(), "");
    }

    #[test]
    fn test_length_string_ordinal_set() {
        // Length=3, "ABC", ordinal=42
        let data = vec![3, b'A', b'B', b'C', 42, 0];
        let mut reader = BinaryReader::from_bytes(&data, true);
        let lsos = LengthStringOrdinalSet::parse(&mut reader).unwrap();

        assert_eq!(lsos.length(), 3);
        assert_eq!(lsos.string(), "ABC");
        assert_eq!(lsos.ordinal(), 42);
    }

    #[test]
    fn test_resident_name_table() {
        // First entry: length=4, "Test", ordinal=1
        // Second entry: length=0 (terminator)
        let data = vec![4, b'T', b'e', b's', b't', 1, 0, 0];
        let mut reader = BinaryReader::from_bytes(&data, true);
        let table = ResidentNameTable::parse(&mut reader, 0).unwrap();

        assert_eq!(table.names().len(), 1);
        assert_eq!(table.names()[0].string(), "Test");
        assert_eq!(table.names()[0].ordinal(), 1);
    }

    #[test]
    fn test_non_resident_name_table() {
        // Entry with ordinal=0 (title): length=7, "MyTitle", ordinal=0
        // Terminator: length=0
        let data = vec![7, b'M', b'y', b'T', b'i', b't', b'l', b'e', 0, 0, 0];
        let mut reader = BinaryReader::from_bytes(&data, true);
        let table = NonResidentNameTable::parse(&mut reader, 0, 11).unwrap();

        assert_eq!(table.title(), "MyTitle");
        assert_eq!(table.names().len(), 1);
    }

    #[test]
    fn test_invalid_windows_header_error() {
        let err = InvalidWindowsHeaderError;
        assert_eq!(format!("{}", err), "Invalid Windows NE header");
    }
}
