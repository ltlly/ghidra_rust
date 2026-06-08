//! PE NT Header ported from Ghidra's `ghidra.app.util.bin.format.pe.NTHeader`,
//! `ghidra.app.util.bin.format.pe.PortableExecutable`,
//! `ghidra.app.util.bin.format.pe.OffsetValidator`, and
//! `ghidra.app.util.bin.format.pe.InvalidNTHeaderException`.
//!
//! Represents the `IMAGE_NT_HEADERS32` / `IMAGE_NT_HEADERS64` structures:
//!
//! ```text
//! typedef struct _IMAGE_NT_HEADERS {
//!     DWORD Signature;                // "PE\0\0"
//!     IMAGE_FILE_HEADER FileHeader;
//!     IMAGE_OPTIONAL_HEADER32 OptionalHeader;
//! };
//! ```

use std::fmt;
use std::io;

use super::pe_constants::{IMAGE_NT_SIGNATURE, IMAGE_FILE_HEADER_SIZE, IMAGE_SIZEOF_SECTION_HEADER};
use super::pe_file_header::FileHeader;
use super::pe_section_header::SectionHeader;

// ---------------------------------------------------------------------------
// InvalidNTHeaderException
// ---------------------------------------------------------------------------

/// Error indicating the bytes at the specified offset do not form a valid NT header.
#[derive(Debug)]
pub struct InvalidNtHeaderError;

impl fmt::Display for InvalidNtHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid NT header")
    }
}

impl std::error::Error for InvalidNtHeaderError {}

// ---------------------------------------------------------------------------
// SectionLayout
// ---------------------------------------------------------------------------

/// Indicates how sections of a PE are laid out in the underlying byte provider.
///
/// Use `File` when loading from a file, and `Memory` when loading from a
/// memory model (like an already-loaded program).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionLayout {
    /// The sections are laid out as stored in a file.
    File,
    /// The sections are laid out as loaded into memory.
    Memory,
}

// ---------------------------------------------------------------------------
// OffsetValidator
// ---------------------------------------------------------------------------

/// Trait for validating pointers and RVAs against a PE section map.
pub trait OffsetValidator {
    /// Returns `true` if the given file pointer falls within a section.
    fn check_pointer(&self, ptr: u64) -> bool;

    /// Returns `true` if the given RVA is within the image bounds.
    fn check_rva(&self, rva: u64) -> bool;
}

// ---------------------------------------------------------------------------
// NtHeader
// ---------------------------------------------------------------------------

/// Represents `IMAGE_NT_HEADERS32` or `IMAGE_NT_HEADERS64`.
///
/// Contains the PE signature, file header, and optional header (not fully
/// parsed in this module -- see the optional header module for that).
///
/// The `NtHeader` also provides RVA-to-pointer conversion and offset
/// validation against the section table.
#[derive(Debug, Clone)]
pub struct NtHeader {
    /// The PE signature ("PE\0\0" = 0x00004550).
    signature: u32,
    /// The file (COFF) header.
    file_header: FileHeader,
    /// The layout mode (file vs memory).
    layout: SectionLayout,
    /// The file offset where the NT header starts.
    index: usize,
    /// Whether to parse CLI headers.
    parse_cli_headers: bool,
    /// Size of the image (from optional header), used for RVA validation.
    size_of_image: u32,
    /// Image base address (from optional header), for VA conversion.
    image_base: u64,
    /// File alignment (from optional header).
    file_alignment: u32,
    /// Section alignment (from optional header).
    section_alignment: u32,
    /// Whether the optional header is 64-bit.
    is_64bit: bool,
}

impl NtHeader {
    /// The size of the PE signature field.
    pub const SIZEOF_SIGNATURE: usize = 4;

    /// Maximum sane section/entry count.
    pub const MAX_SANE_COUNT: u32 = 0x10000;

    /// Parses an `NtHeader` from the given data.
    ///
    /// `data` is the full file contents. `index` is the file offset where the
    /// "PE\0\0" signature resides. `layout` controls RVA resolution.
    /// `parse_cli_headers` indicates whether CLI (.NET) headers should be parsed.
    ///
    /// The `opt_hdr_values` parameter provides values typically obtained from
    /// the optional header: `(image_base, size_of_image, file_alignment,
    /// section_alignment, is_64bit)`.
    pub fn parse(
        data: &[u8],
        index: usize,
        layout: SectionLayout,
        parse_cli_headers: bool,
        opt_hdr_values: (u64, u32, u32, u32, bool),
    ) -> Result<Self, InvalidNtHeaderError> {
        if index > data.len() || index + 4 > data.len() {
            return Err(InvalidNtHeaderError);
        }

        let signature = u32::from_le_bytes([
            data[index],
            data[index + 1],
            data[index + 2],
            data[index + 3],
        ]);

        if signature != IMAGE_NT_SIGNATURE {
            return Err(InvalidNtHeaderError);
        }

        let file_header_offset = index + Self::SIZEOF_SIGNATURE;
        let file_header = FileHeader::parse(data, file_header_offset)
            .map_err(|_| InvalidNtHeaderError)?;

        let (image_base, size_of_image, file_alignment, section_alignment, is_64bit) =
            opt_hdr_values;

        Ok(NtHeader {
            signature,
            file_header,
            layout,
            index,
            parse_cli_headers,
            size_of_image,
            image_base,
            file_alignment,
            section_alignment,
            is_64bit,
        })
    }

    /// Returns the PE signature.
    pub fn signature(&self) -> u32 {
        self.signature
    }

    /// Returns the name of this NT header (IMAGE_NT_HEADERS32 or IMAGE_NT_HEADERS64).
    pub fn name(&self) -> &'static str {
        if self.is_64bit {
            "IMAGE_NT_HEADERS64"
        } else {
            "IMAGE_NT_HEADERS32"
        }
    }

    /// Returns `true` if RVA resolution is section-aligned (memory layout).
    pub fn is_rva_resolution_section_aligned(&self) -> bool {
        self.layout == SectionLayout::Memory
    }

    /// Returns the file header.
    pub fn file_header(&self) -> &FileHeader {
        &self.file_header
    }

    /// Returns the layout mode.
    pub fn layout(&self) -> SectionLayout {
        self.layout
    }

    /// Returns whether CLI headers should be parsed.
    pub fn should_parse_cli_headers(&self) -> bool {
        self.parse_cli_headers
    }

    /// Returns the image base address.
    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Returns the size of the image.
    pub fn size_of_image(&self) -> u32 {
        self.size_of_image
    }

    /// Returns the file alignment.
    pub fn file_alignment(&self) -> u32 {
        self.file_alignment
    }

    /// Returns the section alignment.
    pub fn section_alignment(&self) -> u32 {
        self.section_alignment
    }

    /// Returns `true` if the optional header is 64-bit.
    pub fn is_64bit(&self) -> bool {
        self.is_64bit
    }

    /// Returns the file offset where the NT header starts.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Converts a relative virtual address (RVA) to a file pointer.
    ///
    /// Returns `None` if the RVA does not map to any section.
    pub fn rva_to_pointer(&self, rva: u64) -> Option<u64> {
        match self.layout {
            SectionLayout::Memory => Some(rva),
            SectionLayout::File => {
                for section in self.file_header.section_headers() {
                    let section_va = section.virtual_address() as u64;
                    let v_size = section.virtual_size() as u64;
                    let raw_ptr = section.raw_pointer_to_raw_data() as u64;
                    let raw_size = section.size_of_raw_data() as u64;

                    if rva >= section_va && rva < section_va + v_size {
                        let ptr = rva + raw_ptr - section_va;
                        // Make sure the pointer points to actual section bytes, not padding
                        if ptr >= raw_ptr + raw_size {
                            return None;
                        }
                        return Some(ptr);
                    }
                }
                // Low alignment mode
                if self.file_alignment == self.section_alignment
                    && self.section_alignment < 800
                    && self.file_alignment > 1
                {
                    return Some(rva);
                }
                None
            }
        }
    }

    /// Converts a virtual address (VA) to a file pointer.
    pub fn va_to_pointer(&self, va: u64) -> Option<u64> {
        self.rva_to_pointer(va.wrapping_sub(self.image_base))
    }

    /// Processes section headers from the raw data.
    ///
    /// This is a convenience method that delegates to `FileHeader::process_sections`.
    pub fn process_sections(&mut self, data: &[u8], file_length: u64) -> io::Result<()> {
        self.file_header.process_sections(
            data,
            self.index,
            self.is_64bit,
            self.file_alignment,
            self.section_alignment,
            file_length,
        )
    }

    /// Serializes the NT header signature and file header to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::SIZEOF_SIGNATURE + IMAGE_FILE_HEADER_SIZE);
        buf.extend_from_slice(&self.signature.to_le_bytes());
        buf.extend_from_slice(&self.file_header.to_bytes());
        buf
    }
}

impl OffsetValidator for NtHeader {
    fn check_pointer(&self, ptr: u64) -> bool {
        for section in self.file_header.section_headers() {
            let virt_ptr = section.virtual_address() as u64;
            let virt_size = section.virtual_size() as u64;
            let raw_size = section.size_of_raw_data() as u64;
            let raw_ptr = section.raw_pointer_to_raw_data() as u64;

            let (section_base_ptr, section_size) = match self.layout {
                SectionLayout::Memory => (virt_ptr, virt_size),
                SectionLayout::File => (raw_ptr, raw_size),
            };

            // <= allows data after the last section
            if ptr >= section_base_ptr && ptr <= section_base_ptr + section_size {
                return true;
            }
        }
        if self.file_alignment == self.section_alignment {
            return self.check_rva(ptr);
        }
        false
    }

    fn check_rva(&self, rva: u64) -> bool {
        rva <= self.size_of_image as u64
    }
}

impl fmt::Display for NtHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "NtHeader ({})", self.name())?;
        writeln!(f, "  Signature: 0x{:08X}", self.signature)?;
        writeln!(f, "  Layout: {:?}", self.layout)?;
        writeln!(f, "  ImageBase: 0x{:016X}", self.image_base)?;
        writeln!(f, "  SizeOfImage: 0x{:08X}", self.size_of_image)?;
        writeln!(f, "  FileAlignment: 0x{:X}", self.file_alignment)?;
        writeln!(f, "  SectionAlignment: 0x{:X}", self.section_alignment)?;
        write!(f, "{}", self.file_header)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::pe_constants::*;
    use super::super::pe_file_header::compute_alignment;
    use super::super::pe_section_header::{
        IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA,
        IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
    };

    /// Build a minimal PE file with NT header + file header + 2 sections.
    fn make_pe_with_sections(
        machine: u16,
        is_64bit: bool,
        image_base: u64,
    ) -> (Vec<u8>, usize) {
        let mut data = Vec::new();

        // DOS stub (simplified): just put e_lfanew at offset 0x3C pointing to 0x80
        data.resize(0x80, 0);
        data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

        // NT header at offset 0x80
        let nt_offset = 0x80;
        data.extend_from_slice(&IMAGE_NT_SIGNATURE.to_le_bytes()); // "PE\0\0"

        // File header
        let num_sections: u16 = 2;
        let opt_hdr_size: u16 = if is_64bit { 0xF0 } else { 0xE0 };
        data.extend_from_slice(&machine.to_le_bytes());
        data.extend_from_slice(&num_sections.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes()); // timestamp
        data.extend_from_slice(&0u32.to_le_bytes()); // sym table ptr
        data.extend_from_slice(&0u32.to_le_bytes()); // num symbols
        data.extend_from_slice(&opt_hdr_size.to_le_bytes());
        data.extend_from_slice(&IMAGE_FILE_EXECUTABLE_IMAGE.to_le_bytes());

        // Optional header placeholder (zeroed)
        data.resize(data.len() + opt_hdr_size as usize, 0);

        // Section 1: .text
        let mut name1 = [0u8; 8];
        name1[..5].copy_from_slice(b".text");
        data.extend_from_slice(&name1);
        data.extend_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
        data.extend_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        data.extend_from_slice(&0x600u32.to_le_bytes()); // SizeOfRawData
        data.extend_from_slice(&0x400u32.to_le_bytes()); // PointerToRawData
        data.extend_from_slice(&0u32.to_le_bytes()); // PointerToRelocations
        data.extend_from_slice(&0u32.to_le_bytes()); // PointerToLinenumbers
        data.extend_from_slice(&0u16.to_le_bytes()); // NumberOfRelocations
        data.extend_from_slice(&0u16.to_le_bytes()); // NumberOfLinenumbers
        data.extend_from_slice(&(IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ).to_le_bytes());

        // Section 2: .data
        let mut name2 = [0u8; 8];
        name2[..5].copy_from_slice(b".data");
        data.extend_from_slice(&name2);
        data.extend_from_slice(&0x800u32.to_le_bytes()); // VirtualSize
        data.extend_from_slice(&0x2000u32.to_le_bytes()); // VirtualAddress
        data.extend_from_slice(&0x400u32.to_le_bytes()); // SizeOfRawData
        data.extend_from_slice(&0xA00u32.to_le_bytes()); // PointerToRawData
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&(IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE).to_le_bytes());

        // Pad file to cover all sections
        let file_end = (0xA00 + 0x400).max(0x400 + 0x600);
        data.resize(file_end.max(data.len()), 0);

        (data, nt_offset)
    }

    #[test]
    fn test_parse_valid_nt_header() {
        let (data, nt_offset) = make_pe_with_sections(IMAGE_FILE_MACHINE_I386, false, 0x0040_0000);
        let hdr = NtHeader::parse(
            &data,
            nt_offset,
            SectionLayout::File,
            false,
            (0x0040_0000, 0x5000, 0x200, 0x1000, false),
        )
        .unwrap();
        assert_eq!(hdr.signature(), IMAGE_NT_SIGNATURE);
        assert_eq!(hdr.name(), "IMAGE_NT_HEADERS32");
        assert_eq!(hdr.image_base(), 0x0040_0000);
        assert!(!hdr.is_64bit());
    }

    #[test]
    fn test_parse_64bit() {
        let (data, nt_offset) = make_pe_with_sections(IMAGE_FILE_MACHINE_AMD64, true, 0x0001_4000_0000);
        let hdr = NtHeader::parse(
            &data,
            nt_offset,
            SectionLayout::File,
            false,
            (0x0001_4000_0000, 0x5000, 0x200, 0x1000, true),
        )
        .unwrap();
        assert_eq!(hdr.name(), "IMAGE_NT_HEADERS64");
        assert!(hdr.is_64bit());
    }

    #[test]
    fn test_invalid_signature() {
        let mut data = vec![0u8; 0x100];
        // Write a bad signature
        data[0x80..0x84].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        let result = NtHeader::parse(&data, 0x80, SectionLayout::File, false, (0, 0, 0, 0, false));
        assert!(result.is_err());
    }

    #[test]
    fn test_offset_out_of_bounds() {
        let data = vec![0u8; 10];
        let result = NtHeader::parse(&data, 100, SectionLayout::File, false, (0, 0, 0, 0, false));
        assert!(result.is_err());
    }

    #[test]
    fn test_rva_to_pointer_file_layout() {
        let (data, nt_offset) = make_pe_with_sections(IMAGE_FILE_MACHINE_I386, false, 0x0040_0000);
        let mut hdr = NtHeader::parse(
            &data,
            nt_offset,
            SectionLayout::File,
            false,
            (0x0040_0000, 0x5000, 0x200, 0x1000, false),
        )
        .unwrap();
        hdr.process_sections(&data, data.len() as u64).unwrap();

        // .text section: VA=0x1000, RawPtr=0x400, VSize=0x1000
        // RVA 0x1000 should map to pointer 0x400
        assert_eq!(hdr.rva_to_pointer(0x1000), Some(0x400));
        // RVA 0x1100 should map to pointer 0x500
        assert_eq!(hdr.rva_to_pointer(0x1100), Some(0x500));
        // RVA 0x2000 (.data VA) should map to pointer 0xA00
        assert_eq!(hdr.rva_to_pointer(0x2000), Some(0xA00));
        // RVA in gap between sections
        assert_eq!(hdr.rva_to_pointer(0x0500), None);
    }

    #[test]
    fn test_rva_to_pointer_memory_layout() {
        let (data, nt_offset) = make_pe_with_sections(IMAGE_FILE_MACHINE_I386, false, 0x0040_0000);
        let mut hdr = NtHeader::parse(
            &data,
            nt_offset,
            SectionLayout::Memory,
            false,
            (0x0040_0000, 0x5000, 0x200, 0x1000, false),
        )
        .unwrap();
        hdr.process_sections(&data, data.len() as u64).unwrap();

        // In memory layout, RVA == pointer
        assert_eq!(hdr.rva_to_pointer(0x1000), Some(0x1000));
        assert_eq!(hdr.rva_to_pointer(0x2000), Some(0x2000));
    }

    #[test]
    fn test_va_to_pointer() {
        let (data, nt_offset) = make_pe_with_sections(IMAGE_FILE_MACHINE_I386, false, 0x0040_0000);
        let mut hdr = NtHeader::parse(
            &data,
            nt_offset,
            SectionLayout::File,
            false,
            (0x0040_0000, 0x5000, 0x200, 0x1000, false),
        )
        .unwrap();
        hdr.process_sections(&data, data.len() as u64).unwrap();

        // VA = image_base + RVA
        // VA 0x0040_1000 -> RVA 0x1000 -> pointer 0x400
        assert_eq!(hdr.va_to_pointer(0x0040_1000), Some(0x400));
    }

    #[test]
    fn test_check_pointer() {
        let (data, nt_offset) = make_pe_with_sections(IMAGE_FILE_MACHINE_I386, false, 0x0040_0000);
        let mut hdr = NtHeader::parse(
            &data,
            nt_offset,
            SectionLayout::File,
            false,
            (0x0040_0000, 0x5000, 0x200, 0x1000, false),
        )
        .unwrap();
        hdr.process_sections(&data, data.len() as u64).unwrap();

        assert!(hdr.check_pointer(0x400)); // start of .text raw
        assert!(hdr.check_pointer(0x900)); // within .text raw + size
        assert!(hdr.check_pointer(0xA00)); // start of .data raw
    }

    #[test]
    fn test_check_rva() {
        let (data, nt_offset) = make_pe_with_sections(IMAGE_FILE_MACHINE_I386, false, 0x0040_0000);
        let hdr = NtHeader::parse(
            &data,
            nt_offset,
            SectionLayout::File,
            false,
            (0x0040_0000, 0x5000, 0x200, 0x1000, false),
        )
        .unwrap();

        assert!(hdr.check_rva(0x0));
        assert!(hdr.check_rva(0x5000));
        assert!(!hdr.check_rva(0x5001));
    }

    #[test]
    fn test_to_bytes() {
        let (data, nt_offset) = make_pe_with_sections(IMAGE_FILE_MACHINE_AMD64, true, 0x1_4000_0000);
        let hdr = NtHeader::parse(
            &data,
            nt_offset,
            SectionLayout::File,
            false,
            (0x1_4000_0000, 0x5000, 0x200, 0x1000, true),
        )
        .unwrap();

        let bytes = hdr.to_bytes();
        assert_eq!(bytes.len(), 4 + IMAGE_FILE_HEADER_SIZE);
        assert_eq!(&bytes[..4], &IMAGE_NT_SIGNATURE.to_le_bytes());
    }

    #[test]
    fn test_display() {
        let (data, nt_offset) = make_pe_with_sections(IMAGE_FILE_MACHINE_I386, false, 0x0040_0000);
        let hdr = NtHeader::parse(
            &data,
            nt_offset,
            SectionLayout::File,
            false,
            (0x0040_0000, 0x5000, 0x200, 0x1000, false),
        )
        .unwrap();
        let display = format!("{}", hdr);
        assert!(display.contains("IMAGE_NT_HEADERS32"));
        assert!(display.contains("I386"));
    }

    #[test]
    fn test_section_layout_equality() {
        assert_eq!(SectionLayout::File, SectionLayout::File);
        assert_ne!(SectionLayout::File, SectionLayout::Memory);
    }
}
