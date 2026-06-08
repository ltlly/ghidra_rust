//! PE File Header ported from Ghidra's `ghidra.app.util.bin.format.pe.FileHeader`.
//!
//! Represents the `IMAGE_FILE_HEADER` structure as defined in `winnt.h`.
//!
//! ```text
//! typedef struct _IMAGE_FILE_HEADER {
//!     WORD    Machine;
//!     WORD    NumberOfSections;
//!     DWORD   TimeDateStamp;
//!     DWORD   PointerToSymbolTable;
//!     DWORD   NumberOfSymbols;
//!     WORD    SizeOfOptionalHeader;
//!     WORD    Characteristics;
//! } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
//! ```

use std::fmt;
use std::io;

use super::pe_constants::{
    self, IMAGE_FILE_HEADER_SIZE, IMAGE_SIZEOF_SECTION_HEADER, IMAGE_SIZEOF_SHORT_NAME,
    IMAGE_SIZEOF_NT_OPTIONAL32_HEADER, IMAGE_SIZEOF_NT_OPTIONAL64_HEADER,
};
use super::pe_section_header::SectionHeader;

// ---------------------------------------------------------------------------
// IMAGE_FILE_HEADER characteristics flags
// ---------------------------------------------------------------------------

/// Relocation info stripped from file.
pub const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
/// File is executable (no unresolved external references).
pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
/// Line numbers stripped from file.
pub const IMAGE_FILE_LINE_NUMS_STRIPPED: u16 = 0x0004;
/// Local symbols stripped from file.
pub const IMAGE_FILE_LOCAL_SYMS_STRIPPED: u16 = 0x0008;
/// Aggressively trim working set.
pub const IMAGE_FILE_AGGRESIVE_WS_TRIM: u16 = 0x0010;
/// App can handle >2gb addresses.
pub const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
/// Bytes of machine word are reversed.
pub const IMAGE_FILE_BYTES_REVERSED_LO: u16 = 0x0080;
/// 32 bit word machine.
pub const IMAGE_FILE_32BIT_MACHINE: u16 = 0x0100;
/// Debugging info stripped from file in .DBG file.
pub const IMAGE_FILE_DEBUG_STRIPPED: u16 = 0x0200;
/// If Image is on removable media, copy and run from the swap file.
pub const IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP: u16 = 0x0400;
/// If Image is on Net, copy and run from the swap file.
pub const IMAGE_FILE_NET_RUN_FROM_SWAP: u16 = 0x0800;
/// System File.
pub const IMAGE_FILE_SYSTEM: u16 = 0x1000;
/// File is a DLL.
pub const IMAGE_FILE_DLL: u16 = 0x2000;
/// File should only be run on a UP machine.
pub const IMAGE_FILE_UP_SYSTEM_ONLY: u16 = 0x4000;
/// Bytes of machine word are reversed.
pub const IMAGE_FILE_BYTES_REVERSED_HI: u16 = 0x8000;

// LordPE magic values
const LORDPE_SYMBOL_TABLE: u32 = 0x726F_4C5B;
const LORDPE_NUMBER_OF_SYMBOLS: u32 = 0x5D45_5064;

/// Human-readable description strings for file header characteristic bits.
pub const CHARACTERISTICS_DESCRIPTIONS: [&str; 15] = [
    "Relocation info stripped from file",
    "File is executable (no unresolved external references)",
    "Line numbers stripped from file",
    "Local symbols stripped from file",
    "Aggressively trim working set",
    "App can handle >2gb addresses",
    "Bytes of machine word are reversed",
    "32 bit word machine",
    "Debugging info stripped from file in .DBG file",
    "If Image is on removable media, copy and run from the swap file",
    "If Image is on Net, copy and run from the swap file",
    "System file",
    "File is a DLL",
    "File should only be run on a UP machine",
    "Bytes of machine word are reversed",
];

// ---------------------------------------------------------------------------
// FileHeader
// ---------------------------------------------------------------------------

/// Represents the `IMAGE_FILE_HEADER` struct in a PE file.
///
/// This is the COFF file header that appears after the PE signature in the
/// NT headers. It contains the machine type, number of sections, timestamp,
/// symbol table pointer, optional header size, and file characteristic flags.
#[derive(Debug, Clone)]
pub struct FileHeader {
    /// The target machine architecture.
    machine: u16,
    /// The number of sections.
    number_of_sections: u16,
    /// The low 32 bits of the time stamp of the image.
    time_date_stamp: u32,
    /// The file offset of the COFF symbol table.
    pointer_to_symbol_table: u32,
    /// The number of entries in the symbol table.
    number_of_symbols: u32,
    /// The size of the optional header.
    size_of_optional_header: u16,
    /// The characteristics flags.
    characteristics: u16,
    /// Parsed section headers.
    section_headers: Vec<SectionHeader>,
}

impl FileHeader {
    /// The name used when converting to a Ghidra structure data type.
    pub const NAME: &'static str = "IMAGE_FILE_HEADER";

    /// The size of the `IMAGE_FILE_HEADER` in bytes.
    pub const SIZE: usize = IMAGE_FILE_HEADER_SIZE;

    /// Parses a `FileHeader` from the given byte slice at the specified offset.
    ///
    /// The reader should be positioned at the start of the file header.
    pub fn parse(data: &[u8], offset: usize) -> io::Result<Self> {
        if data.len() < offset + Self::SIZE {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Not enough data for IMAGE_FILE_HEADER",
            ));
        }

        let machine = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let number_of_sections = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);
        let time_date_stamp = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        let pointer_to_symbol_table = u32::from_le_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
        ]);
        let number_of_symbols = u32::from_le_bytes([
            data[offset + 12],
            data[offset + 13],
            data[offset + 14],
            data[offset + 15],
        ]);
        let size_of_optional_header = u16::from_le_bytes([data[offset + 16], data[offset + 17]]);
        let characteristics = u16::from_le_bytes([data[offset + 18], data[offset + 19]]);

        Ok(FileHeader {
            machine,
            number_of_sections,
            time_date_stamp,
            pointer_to_symbol_table,
            number_of_symbols,
            size_of_optional_header,
            characteristics,
            section_headers: Vec::new(),
        })
    }

    /// Returns the target machine type.
    pub fn machine(&self) -> u16 {
        self.machine
    }

    /// Returns a string representation of the machine type.
    pub fn machine_name(&self) -> &'static str {
        pe_constants::machine_type_name(self.machine)
    }

    /// Returns `true` if the machine is an x86 variant (I386 or AMD64).
    pub fn is_x86(&self) -> bool {
        matches!(
            self.machine & 0xFFFF,
            pe_constants::IMAGE_FILE_MACHINE_I386 | pe_constants::IMAGE_FILE_MACHINE_AMD64
        )
    }

    /// Returns `true` if the machine is an ARM variant.
    pub fn is_arm(&self) -> bool {
        matches!(
            self.machine & 0xFFFF,
            pe_constants::IMAGE_FILE_MACHINE_ARM
                | pe_constants::IMAGE_FILE_MACHINE_ARM64
                | pe_constants::IMAGE_FILE_MACHINE_ARMNT
        )
    }

    /// Returns the number of sections.
    pub fn number_of_sections(&self) -> u16 {
        self.number_of_sections
    }

    /// Returns a reference to the parsed section headers.
    pub fn section_headers(&self) -> &[SectionHeader] {
        &self.section_headers
    }

    /// Returns the time stamp of the image.
    pub fn time_date_stamp(&self) -> u32 {
        self.time_date_stamp
    }

    /// Returns the file offset of the COFF symbol table.
    pub fn pointer_to_symbol_table(&self) -> u32 {
        self.pointer_to_symbol_table
    }

    /// Returns the number of symbols in the COFF symbol table.
    pub fn number_of_symbols(&self) -> u32 {
        self.number_of_symbols
    }

    /// Returns the size of the optional header, in bytes.
    pub fn size_of_optional_header(&self) -> u16 {
        self.size_of_optional_header
    }

    /// Returns the characteristics flags.
    pub fn characteristics(&self) -> u16 {
        self.characteristics
    }

    /// Returns `true` if the given characteristic flag is set.
    pub fn has_characteristic(&self, flag: u16) -> bool {
        self.characteristics & flag != 0
    }

    /// Returns the file pointer to the section headers.
    ///
    /// `nt_header_offset` is the file offset of the NT header (start of "PE\0\0").
    /// `is_64bit` indicates whether the optional header is 64-bit.
    pub fn pointer_to_sections(&self, nt_header_offset: usize, is_64bit: bool) -> usize {
        let expected_size = if is_64bit {
            IMAGE_SIZEOF_NT_OPTIONAL64_HEADER
        } else {
            IMAGE_SIZEOF_NT_OPTIONAL32_HEADER
        };
        if self.size_of_optional_header as usize != expected_size {
            // Non-standard optional header size -- still compute, but caller should be aware
        }
        // NT header = PE signature (4 bytes) + file header (20 bytes) + optional header
        nt_header_offset + 4 + IMAGE_FILE_HEADER_SIZE + self.size_of_optional_header as usize
    }

    /// Returns the section header that contains the specified virtual address.
    pub fn section_header_containing(&self, virtual_addr: u32) -> Option<&SectionHeader> {
        self.section_headers.iter().find(|sh| {
            let start = sh.virtual_address();
            let end = start.saturating_add(sh.virtual_size());
            virtual_addr >= start && virtual_addr <= end.saturating_sub(1)
        })
    }

    /// Returns the section header at the specified index, or `None` if out of bounds.
    pub fn section_header_at(&self, index: usize) -> Option<&SectionHeader> {
        self.section_headers.get(index)
    }

    /// Returns the first section header with the given name, or `None`.
    pub fn section_header_by_name(&self, name: &str) -> Option<&SectionHeader> {
        self.section_headers
            .iter()
            .find(|sh| sh.name() == name)
    }

    /// Returns `true` if the symbol table pointer appears to be a LordPE marker.
    pub fn is_lord_pe(&self) -> bool {
        self.pointer_to_symbol_table == LORDPE_SYMBOL_TABLE
            && self.number_of_symbols == LORDPE_NUMBER_OF_SYMBOLS
    }

    /// Computes the offset of the COFF string table.
    ///
    /// Returns `None` if the string table is not valid or not present.
    pub fn string_table_offset(&self, file_length: u64) -> Option<u64> {
        if self.pointer_to_symbol_table == 0 || (self.number_of_symbols as i32) < 0 {
            return None;
        }
        let symbol_size: u64 = 18; // IMAGE_SIZEOF_SYMBOL = 18
        let end = self.pointer_to_symbol_table as u64
            + symbol_size * self.number_of_symbols as u64;
        if end > file_length {
            return None;
        }
        Some(end)
    }

    /// Processes section headers from the raw data.
    ///
    /// `data` is the full file data. `nt_header_offset` is where "PE\0\0" starts.
    /// `is_64bit` indicates the optional header bitness. `file_alignment` is the
    /// PE file alignment from the optional header. `section_alignment` is the PE
    /// section alignment. `file_length` is the total file length.
    pub fn process_sections(
        &mut self,
        data: &[u8],
        nt_header_offset: usize,
        is_64bit: bool,
        file_alignment: u32,
        section_alignment: u32,
        file_length: u64,
    ) -> io::Result<()> {
        if file_alignment == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "File alignment == 0: section processing skipped",
            ));
        }
        if (self.number_of_sections as i32) < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Number of sections = {}", self.number_of_sections),
            ));
        }

        let sections_offset = self.pointer_to_sections(nt_header_offset, is_64bit);
        let string_table_offset = self.string_table_offset(file_length);

        self.section_headers.clear();
        for i in 0..self.number_of_sections as usize {
            let hdr_offset = sections_offset + i * IMAGE_SIZEOF_SECTION_HEADER;
            let mut section = SectionHeader::parse(data, hdr_offset, string_table_offset)?;

            let mut pointer_to_raw_data = section.pointer_to_raw_data();
            let mut size_of_raw_data = section.size_of_raw_data();

            // Ensure PointerToRawData + SizeOfRawData doesn't exceed the file length
            if pointer_to_raw_data as u64 >= file_length {
                size_of_raw_data = 0;
            } else if pointer_to_raw_data as u64 + size_of_raw_data as u64 > file_length {
                size_of_raw_data = (file_length - pointer_to_raw_data as u64) as u32;
            }
            section.set_size_of_raw_data(size_of_raw_data);

            // Ensure VirtualSize is large enough to accommodate SizeOfRawData
            let virtual_address = section.virtual_address();
            let mut virtual_size = section.virtual_size();
            let aligned_virtual_address = compute_alignment(virtual_address, section_alignment);
            let aligned_virtual_size = compute_alignment(virtual_size, section_alignment);
            if virtual_address == aligned_virtual_address {
                if size_of_raw_data > virtual_size {
                    section.set_virtual_size(size_of_raw_data.min(aligned_virtual_size));
                }
            }
            self.section_headers.push(section);
        }

        Ok(())
    }

    /// Serializes this file header to bytes (little-endian).
    pub fn to_bytes(&self) -> [u8; IMAGE_FILE_HEADER_SIZE] {
        let mut buf = [0u8; IMAGE_FILE_HEADER_SIZE];
        buf[0..2].copy_from_slice(&self.machine.to_le_bytes());
        buf[2..4].copy_from_slice(&self.number_of_sections.to_le_bytes());
        buf[4..8].copy_from_slice(&self.time_date_stamp.to_le_bytes());
        buf[8..12].copy_from_slice(&self.pointer_to_symbol_table.to_le_bytes());
        buf[12..16].copy_from_slice(&self.number_of_symbols.to_le_bytes());
        buf[16..18].copy_from_slice(&self.size_of_optional_header.to_le_bytes());
        buf[18..20].copy_from_slice(&self.characteristics.to_le_bytes());
        buf
    }

    /// Returns the names of all set characteristic flags.
    pub fn characteristic_names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        let flags = [
            (IMAGE_FILE_RELOCS_STRIPPED, "RELOCS_STRIPPED"),
            (IMAGE_FILE_EXECUTABLE_IMAGE, "EXECUTABLE_IMAGE"),
            (IMAGE_FILE_LINE_NUMS_STRIPPED, "LINE_NUMS_STRIPPED"),
            (IMAGE_FILE_LOCAL_SYMS_STRIPPED, "LOCAL_SYMS_STRIPPED"),
            (IMAGE_FILE_AGGRESIVE_WS_TRIM, "AGGRESIVE_WS_TRIM"),
            (IMAGE_FILE_LARGE_ADDRESS_AWARE, "LARGE_ADDRESS_AWARE"),
            (IMAGE_FILE_BYTES_REVERSED_LO, "BYTES_REVERSED_LO"),
            (IMAGE_FILE_32BIT_MACHINE, "32BIT_MACHINE"),
            (IMAGE_FILE_DEBUG_STRIPPED, "DEBUG_STRIPPED"),
            (IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "REMOVABLE_RUN_FROM_SWAP"),
            (IMAGE_FILE_NET_RUN_FROM_SWAP, "NET_RUN_FROM_SWAP"),
            (IMAGE_FILE_SYSTEM, "SYSTEM"),
            (IMAGE_FILE_DLL, "DLL"),
            (IMAGE_FILE_UP_SYSTEM_ONLY, "UP_SYSTEM_ONLY"),
            (IMAGE_FILE_BYTES_REVERSED_HI, "BYTES_REVERSED_HI"),
        ];
        for (flag, name) in &flags {
            if self.characteristics & flag != 0 {
                names.push(*name);
            }
        }
        names
    }
}

/// Computes alignment: rounds `value` up to the next multiple of `alignment`.
///
/// If `alignment` is 0 or `value` is already aligned, returns `value` unchanged.
/// Ported from `PortableExecutable.computeAlignment()`.
pub fn compute_alignment(value: u32, alignment: u32) -> u32 {
    if alignment == 0 || value % alignment == 0 {
        return value;
    }
    ((value + alignment) / alignment) * alignment
}

impl fmt::Display for FileHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "FileHeader:")?;
        writeln!(f, "  Machine:            0x{:04X} ({})", self.machine, self.machine_name())?;
        writeln!(f, "  NumberOfSections:   {}", self.number_of_sections)?;
        writeln!(f, "  TimeDateStamp:      0x{:08X}", self.time_date_stamp)?;
        writeln!(f, "  PointerToSymbolTable: 0x{:08X}", self.pointer_to_symbol_table)?;
        writeln!(f, "  NumberOfSymbols:    {}", self.number_of_symbols)?;
        writeln!(f, "  SizeOfOptionalHeader: {}", self.size_of_optional_header)?;
        writeln!(
            f,
            "  Characteristics:    0x{:04X} [{}]",
            self.characteristics,
            self.characteristic_names().join(", ")
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::pe_constants::{
        IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64,
    };

    fn make_file_header_bytes(
        machine: u16,
        num_sections: u16,
        timestamp: u32,
        sym_table_ptr: u32,
        num_symbols: u32,
        opt_hdr_size: u16,
        chars: u16,
    ) -> [u8; IMAGE_FILE_HEADER_SIZE] {
        let mut buf = [0u8; IMAGE_FILE_HEADER_SIZE];
        buf[0..2].copy_from_slice(&machine.to_le_bytes());
        buf[2..4].copy_from_slice(&num_sections.to_le_bytes());
        buf[4..8].copy_from_slice(&timestamp.to_le_bytes());
        buf[8..12].copy_from_slice(&sym_table_ptr.to_le_bytes());
        buf[12..16].copy_from_slice(&num_symbols.to_le_bytes());
        buf[16..18].copy_from_slice(&opt_hdr_size.to_le_bytes());
        buf[18..20].copy_from_slice(&chars.to_le_bytes());
        buf
    }

    #[test]
    fn test_parse_basic() {
        let data = make_file_header_bytes(
            IMAGE_FILE_MACHINE_I386,
            3,
            0x1234_5678,
            0,
            0,
            0xE0,
            IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE,
        );
        let fh = FileHeader::parse(&data, 0).unwrap();
        assert_eq!(fh.machine(), IMAGE_FILE_MACHINE_I386);
        assert_eq!(fh.machine_name(), "I386");
        assert_eq!(fh.number_of_sections(), 3);
        assert_eq!(fh.time_date_stamp(), 0x1234_5678);
        assert_eq!(fh.size_of_optional_header(), 0xE0);
        assert!(fh.has_characteristic(IMAGE_FILE_EXECUTABLE_IMAGE));
        assert!(fh.has_characteristic(IMAGE_FILE_32BIT_MACHINE));
        assert!(!fh.has_characteristic(IMAGE_FILE_DLL));
    }

    #[test]
    fn test_parse_amd64() {
        let data = make_file_header_bytes(
            IMAGE_FILE_MACHINE_AMD64,
            5,
            0,
            0,
            0,
            0xF0,
            IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE,
        );
        let fh = FileHeader::parse(&data, 0).unwrap();
        assert_eq!(fh.machine(), IMAGE_FILE_MACHINE_AMD64);
        assert_eq!(fh.machine_name(), "AMD64");
        assert!(fh.is_x86());
        assert!(!fh.is_arm());
    }

    #[test]
    fn test_parse_arm64() {
        let data = make_file_header_bytes(
            IMAGE_FILE_MACHINE_ARM64,
            1,
            0,
            0,
            0,
            0xF0,
            IMAGE_FILE_EXECUTABLE_IMAGE,
        );
        let fh = FileHeader::parse(&data, 0).unwrap();
        assert!(fh.is_arm());
        assert!(!fh.is_x86());
    }

    #[test]
    fn test_insufficient_data() {
        let data = [0u8; 10];
        assert!(FileHeader::parse(&data, 0).is_err());
    }

    #[test]
    fn test_to_bytes_roundtrip() {
        let data = make_file_header_bytes(
            IMAGE_FILE_MACHINE_AMD64,
            4,
            0xABCD_1234,
            0x100,
            50,
            0xF0,
            IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL,
        );
        let fh = FileHeader::parse(&data, 0).unwrap();
        let bytes = fh.to_bytes();
        assert_eq!(bytes, data);
    }

    #[test]
    fn test_lord_pe() {
        let data = make_file_header_bytes(
            IMAGE_FILE_MACHINE_I386,
            1,
            0,
            LORDPE_SYMBOL_TABLE,
            LORDPE_NUMBER_OF_SYMBOLS,
            0xE0,
            0,
        );
        let fh = FileHeader::parse(&data, 0).unwrap();
        assert!(fh.is_lord_pe());
    }

    #[test]
    fn test_not_lord_pe() {
        let data = make_file_header_bytes(IMAGE_FILE_MACHINE_I386, 1, 0, 0, 0, 0xE0, 0);
        let fh = FileHeader::parse(&data, 0).unwrap();
        assert!(!fh.is_lord_pe());
    }

    #[test]
    fn test_characteristic_names() {
        let data = make_file_header_bytes(
            IMAGE_FILE_MACHINE_I386,
            1,
            0,
            0,
            0,
            0xE0,
            IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL,
        );
        let fh = FileHeader::parse(&data, 0).unwrap();
        let names = fh.characteristic_names();
        assert!(names.contains(&"EXECUTABLE_IMAGE"));
        assert!(names.contains(&"DLL"));
        assert!(!names.contains(&"SYSTEM"));
    }

    #[test]
    fn test_pointer_to_sections() {
        let data = make_file_header_bytes(IMAGE_FILE_MACHINE_I386, 1, 0, 0, 0, 0xE0, 0);
        let fh = FileHeader::parse(&data, 0).unwrap();
        // NT header offset = 0, PE sig is 4 bytes, file header is 20 bytes, opt hdr is 0xE0 bytes
        assert_eq!(fh.pointer_to_sections(0, false), 4 + 20 + 0xE0);
    }

    #[test]
    fn test_string_table_offset() {
        let data = make_file_header_bytes(
            IMAGE_FILE_MACHINE_I386,
            1,
            0,
            0x200, // pointer to symbol table
            10,    // number of symbols
            0xE0,
            0,
        );
        let fh = FileHeader::parse(&data, 0).unwrap();
        // string table = sym_ptr + 18 * num_symbols = 0x200 + 180 = 0x2B4
        assert_eq!(fh.string_table_offset(0x1000), Some(0x200 + 18 * 10));
        assert_eq!(fh.string_table_offset(0x100), None); // file too short
    }

    #[test]
    fn test_compute_alignment() {
        assert_eq!(compute_alignment(0, 0x200), 0);
        assert_eq!(compute_alignment(1, 0x200), 0x200);
        assert_eq!(compute_alignment(0x200, 0x200), 0x200);
        assert_eq!(compute_alignment(0x201, 0x200), 0x400);
        assert_eq!(compute_alignment(100, 0), 100);
    }

    #[test]
    fn test_display() {
        let data = make_file_header_bytes(
            IMAGE_FILE_MACHINE_AMD64,
            3,
            0x1234_5678,
            0,
            0,
            0xF0,
            IMAGE_FILE_EXECUTABLE_IMAGE,
        );
        let fh = FileHeader::parse(&data, 0).unwrap();
        let display = format!("{}", fh);
        assert!(display.contains("AMD64"));
        assert!(display.contains("NumberOfSections:   3"));
        assert!(display.contains("EXECUTABLE_IMAGE"));
    }

    #[test]
    fn test_section_headers_empty_by_default() {
        let data = make_file_header_bytes(IMAGE_FILE_MACHINE_I386, 0, 0, 0, 0, 0xE0, 0);
        let fh = FileHeader::parse(&data, 0).unwrap();
        assert!(fh.section_headers().is_empty());
        assert!(fh.section_header_at(0).is_none());
        assert!(fh.section_header_by_name(".text").is_none());
        assert!(fh.section_header_containing(0).is_none());
    }
}
