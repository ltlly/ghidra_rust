//! PE Section Header ported from Ghidra's `ghidra.app.util.bin.format.pe.SectionHeader`.
//!
//! Represents the `IMAGE_SECTION_HEADER` structure as defined in `winnt.h`.
//!
//! ```text
//! typedef struct _IMAGE_SECTION_HEADER {
//!     BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
//!     union {
//!         DWORD   PhysicalAddress;
//!         DWORD   VirtualSize;
//!     } Misc;
//!     DWORD   VirtualAddress;
//!     DWORD   SizeOfRawData;
//!     DWORD   PointerToRawData;
//!     DWORD   PointerToRelocations;
//!     DWORD   PointerToLinenumbers;
//!     WORD    NumberOfRelocations;
//!     WORD    NumberOfLinenumbers;
//!     DWORD   Characteristics;
//! } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
//! ```
//!
//! `IMAGE_SIZEOF_SECTION_HEADER = 40`

use std::fmt;
use std::io;

use super::pe_constants::{IMAGE_SIZEOF_SECTION_HEADER, IMAGE_SIZEOF_SHORT_NAME};
use super::pe_section_flags::SectionFlag;

// ---------------------------------------------------------------------------
// Content count flags (subset used directly by SectionHeader)
// ---------------------------------------------------------------------------

/// Section contains code.
pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
/// Section contains initialized data.
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
/// Section contains uninitialized data.
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
/// Section contains information for use by the linker (OBJ only).
pub const IMAGE_SCN_LNK_INFO: u32 = 0x0000_0200;
/// Section will not become part of the image (OBJ only).
pub const IMAGE_SCN_LNK_REMOVE: u32 = 0x0000_0800;
/// Section contents is communal data (comdat, OBJ only).
pub const IMAGE_SCN_LNK_COMDAT: u32 = 0x0000_1000;
/// Reset speculative exceptions handling bits in TLB entries.
pub const IMAGE_SCN_NO_DEFER_SPEC_EXC: u32 = 0x0000_4000;
/// Section content can be accessed relative to GP.
pub const IMAGE_SCN_GPREL: u32 = 0x0000_8000;
/// Align on 1-byte boundary.
pub const IMAGE_SCN_ALIGN_1BYTES: u32 = 0x0010_0000;
/// Align on 2-byte boundary.
pub const IMAGE_SCN_ALIGN_2BYTES: u32 = 0x0020_0000;
/// Align on 4-byte boundary.
pub const IMAGE_SCN_ALIGN_4BYTES: u32 = 0x0030_0000;
/// Align on 8-byte boundary.
pub const IMAGE_SCN_ALIGN_8BYTES: u32 = 0x0040_0000;
/// Align on 16-byte boundary.
pub const IMAGE_SCN_ALIGN_16BYTES: u32 = 0x0050_0000;
/// Align on 32-byte boundary.
pub const IMAGE_SCN_ALIGN_32BYTES: u32 = 0x0060_0000;
/// Align on 64-byte boundary.
pub const IMAGE_SCN_ALIGN_64BYTES: u32 = 0x0070_0000;
/// Align on 128-byte boundary.
pub const IMAGE_SCN_ALIGN_128BYTES: u32 = 0x0080_0000;
/// Align on 256-byte boundary.
pub const IMAGE_SCN_ALIGN_256BYTES: u32 = 0x0090_0000;
/// Align on 512-byte boundary.
pub const IMAGE_SCN_ALIGN_512BYTES: u32 = 0x00A0_0000;
/// Align on 1024-byte boundary.
pub const IMAGE_SCN_ALIGN_1024BYTES: u32 = 0x00B0_0000;
/// Align on 2048-byte boundary.
pub const IMAGE_SCN_ALIGN_2048BYTES: u32 = 0x00C0_0000;
/// Align on 4096-byte boundary.
pub const IMAGE_SCN_ALIGN_4096BYTES: u32 = 0x00D0_0000;
/// Align on 8192-byte boundary.
pub const IMAGE_SCN_ALIGN_8192BYTES: u32 = 0x00E0_0000;
/// Mask for alignment flags.
pub const IMAGE_SCN_ALIGN_MASK: u32 = 0x00F0_0000;
/// Section contains extended relocations.
pub const IMAGE_SCN_LNK_NRELOC_OVFL: u32 = 0x0100_0000;
/// The section can be discarded from the final executable.
pub const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
/// Section is not cacheable.
pub const IMAGE_SCN_MEM_NOT_CACHED: u32 = 0x0400_0000;
/// The section is not pageable.
pub const IMAGE_SCN_MEM_NOT_PAGED: u32 = 0x0800_0000;
/// Section is shareable.
pub const IMAGE_SCN_MEM_SHARED: u32 = 0x1000_0000;
/// Section is executable.
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// Section is readable.
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
/// Section is writeable.
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

// ---------------------------------------------------------------------------
// SectionHeader
// ---------------------------------------------------------------------------

/// Represents an `IMAGE_SECTION_HEADER` in a PE file.
///
/// Each section in a PE image has a header that describes its name, virtual
/// address, raw data location, and characteristic flags.
#[derive(Debug, Clone)]
pub struct SectionHeader {
    /// The section name (up to 8 characters, null-padded).
    name: String,
    /// The physical (file) address. Alias for virtual_size in executables.
    physical_address: u32,
    /// The actual, used size of the section.
    virtual_size: u32,
    /// The RVA where the section begins in memory.
    virtual_address: u32,
    /// The size of the section data in the file.
    size_of_raw_data: u32,
    /// The file pointer to the section data.
    pointer_to_raw_data: u32,
    /// The file pointer to relocations for this section.
    pointer_to_relocations: u32,
    /// The file pointer to COFF-style line numbers.
    pointer_to_linenumbers: u32,
    /// The number of relocations.
    number_of_relocations: u16,
    /// The number of line numbers.
    number_of_linenumbers: u16,
    /// The section characteristic flags.
    characteristics: u32,
}

impl SectionHeader {
    /// The name used when converting to a Ghidra structure data type.
    pub const NAME: &'static str = "IMAGE_SECTION_HEADER";

    /// The size of the section header short name.
    pub const IMAGE_SIZEOF_SHORT_NAME: usize = IMAGE_SIZEOF_SHORT_NAME;

    /// The size of the section header (40 bytes).
    pub const SIZE: usize = IMAGE_SIZEOF_SECTION_HEADER;

    /// Sentinel indicating a field is not set.
    pub const NOT_SET: i32 = -1;

    /// Parses a `SectionHeader` from raw data.
    ///
    /// `data` is the full file data. `offset` is where the section header begins.
    /// `string_table_offset` is the file offset of the COFF string table, or `None`
    /// if not available.
    pub fn parse(
        data: &[u8],
        offset: usize,
        string_table_offset: Option<u64>,
    ) -> io::Result<Self> {
        if data.len() < offset + Self::SIZE {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Not enough data for IMAGE_SECTION_HEADER",
            ));
        }

        // Read the 8-byte name (null-padded, may not be null-terminated)
        let name_bytes = &data[offset..offset + IMAGE_SIZEOF_SHORT_NAME];
        let name_raw = std::str::from_utf8(name_bytes)
            .unwrap_or("")
            .trim_end_matches('\0')
            .trim();

        // Handle "/nnn" style string table references
        let name = if name_raw.starts_with('/') {
            if let Some(st_off) = string_table_offset {
                if let Ok(name_offset) = name_raw[1..].parse::<u64>() {
                    let abs_offset = (st_off + name_offset) as usize;
                    read_null_terminated_ascii(data, abs_offset)
                        .unwrap_or_else(|| name_raw.to_string())
                } else {
                    name_raw.to_string()
                }
            } else {
                name_raw.to_string()
            }
        } else {
            name_raw.to_string()
        };

        // Fields start after the 8-byte name
        let mut pos = offset + IMAGE_SIZEOF_SHORT_NAME;
        let physical_address = u32::from_le_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
        ]);
        let virtual_size = physical_address; // union: PhysicalAddress == VirtualSize
        pos += 4;
        let virtual_address = u32::from_le_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
        ]);
        pos += 4;
        let size_of_raw_data = u32::from_le_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
        ]);
        pos += 4;
        let pointer_to_raw_data = u32::from_le_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
        ]);
        pos += 4;
        let pointer_to_relocations = u32::from_le_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
        ]);
        pos += 4;
        let pointer_to_linenumbers = u32::from_le_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
        ]);
        pos += 4;
        let number_of_relocations = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        let number_of_linenumbers = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        let characteristics = u32::from_le_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
        ]);

        Ok(SectionHeader {
            name,
            physical_address,
            virtual_size,
            virtual_address,
            size_of_raw_data,
            pointer_to_raw_data,
            pointer_to_relocations,
            pointer_to_linenumbers,
            number_of_relocations,
            number_of_linenumbers,
            characteristics,
        })
    }

    /// Returns the section name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns a readable ASCII version of the name.
    ///
    /// All non-printable characters are replaced with underscores.
    pub fn readable_name(&self) -> String {
        self.name
            .chars()
            .map(|c| if (0x20..=0x7E).contains(&(c as u32)) { c } else { '_' })
            .collect()
    }

    /// Returns the physical (file) address.
    pub fn physical_address(&self) -> u32 {
        self.physical_address
    }

    /// Returns the virtual size.
    ///
    /// If the stored virtual size is 0, falls back to the raw data size.
    pub fn virtual_size(&self) -> u32 {
        if self.virtual_size == 0 {
            self.size_of_raw_data
        } else {
            self.virtual_size
        }
    }

    /// Returns the RVA where the section begins in memory.
    pub fn virtual_address(&self) -> u32 {
        self.virtual_address
    }

    /// Returns the size of the section data in the file.
    pub fn size_of_raw_data(&self) -> u32 {
        self.size_of_raw_data
    }

    /// Returns the file offset where section data begins.
    ///
    /// Returns 0 if the pointer is less than 0x200 (PE header area).
    pub fn pointer_to_raw_data(&self) -> u32 {
        if self.pointer_to_raw_data < 0x200 {
            0
        } else {
            self.pointer_to_raw_data
        }
    }

    /// Returns the raw pointer value without the < 0x200 clamp.
    pub fn raw_pointer_to_raw_data(&self) -> u32 {
        self.pointer_to_raw_data
    }

    /// Returns the file offset of relocations for this section.
    pub fn pointer_to_relocations(&self) -> u32 {
        self.pointer_to_relocations
    }

    /// Returns the file offset for COFF-style line numbers.
    pub fn pointer_to_linenumbers(&self) -> u32 {
        self.pointer_to_linenumbers
    }

    /// Returns the number of relocations.
    pub fn number_of_relocations(&self) -> u16 {
        self.number_of_relocations
    }

    /// Returns the number of line numbers.
    pub fn number_of_linenumbers(&self) -> u16 {
        self.number_of_linenumbers
    }

    /// Returns the characteristics flags.
    pub fn characteristics(&self) -> u32 {
        self.characteristics
    }

    /// Returns `true` if the given characteristic flag is set.
    pub fn has_characteristic(&self, flag: u32) -> bool {
        self.characteristics & flag != 0
    }

    /// Returns `true` if this section contains code.
    pub fn is_code(&self) -> bool {
        self.characteristics & IMAGE_SCN_CNT_CODE != 0
    }

    /// Returns `true` if this section contains initialized data.
    pub fn is_initialized_data(&self) -> bool {
        self.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0
    }

    /// Returns `true` if this section contains uninitialized data.
    pub fn is_uninitialized_data(&self) -> bool {
        self.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0
    }

    /// Returns `true` if this section is executable.
    pub fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }

    /// Returns `true` if this section is readable.
    pub fn is_readable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_READ != 0
    }

    /// Returns `true` if this section is writable.
    pub fn is_writable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_WRITE != 0
    }

    /// Returns the alignment in bytes implied by the alignment flags, or 0 if
    /// no alignment is specified.
    pub fn alignment_bytes(&self) -> u32 {
        let align_bits = (self.characteristics & IMAGE_SCN_ALIGN_MASK) >> 20;
        if align_bits == 0 {
            0
        } else {
            1u32 << (align_bits - 1)
        }
    }

    /// Returns the names of all set characteristic flags.
    pub fn characteristic_names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        let flags: &[(u32, &str)] = &[
            (IMAGE_SCN_CNT_CODE, "CNT_CODE"),
            (IMAGE_SCN_CNT_INITIALIZED_DATA, "CNT_INITIALIZED_DATA"),
            (IMAGE_SCN_CNT_UNINITIALIZED_DATA, "CNT_UNINITIALIZED_DATA"),
            (IMAGE_SCN_LNK_INFO, "LNK_INFO"),
            (IMAGE_SCN_LNK_REMOVE, "LNK_REMOVE"),
            (IMAGE_SCN_LNK_COMDAT, "LNK_COMDAT"),
            (IMAGE_SCN_NO_DEFER_SPEC_EXC, "NO_DEFER_SPEC_EXC"),
            (IMAGE_SCN_GPREL, "GPREL"),
            (IMAGE_SCN_LNK_NRELOC_OVFL, "LNK_NRELOC_OVFL"),
            (IMAGE_SCN_MEM_DISCARDABLE, "MEM_DISCARDABLE"),
            (IMAGE_SCN_MEM_NOT_CACHED, "MEM_NOT_CACHED"),
            (IMAGE_SCN_MEM_NOT_PAGED, "MEM_NOT_PAGED"),
            (IMAGE_SCN_MEM_SHARED, "MEM_SHARED"),
            (IMAGE_SCN_MEM_EXECUTE, "MEM_EXECUTE"),
            (IMAGE_SCN_MEM_READ, "MEM_READ"),
            (IMAGE_SCN_MEM_WRITE, "MEM_WRITE"),
        ];
        for (flag, name) in flags {
            if self.characteristics & flag != 0 {
                names.push(*name);
            }
        }
        names
    }

    /// Serializes this section header to a 40-byte array (little-endian).
    pub fn to_bytes(&self) -> [u8; IMAGE_SIZEOF_SECTION_HEADER] {
        let mut buf = [0u8; IMAGE_SIZEOF_SECTION_HEADER];
        // Name (8 bytes, null-padded)
        let name_bytes = self.name.as_bytes();
        let copy_len = name_bytes.len().min(IMAGE_SIZEOF_SHORT_NAME);
        buf[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        let mut pos = IMAGE_SIZEOF_SHORT_NAME;
        buf[pos..pos + 4].copy_from_slice(&self.virtual_size.to_le_bytes());
        pos += 4;
        buf[pos..pos + 4].copy_from_slice(&self.virtual_address.to_le_bytes());
        pos += 4;
        buf[pos..pos + 4].copy_from_slice(&self.size_of_raw_data.to_le_bytes());
        pos += 4;
        buf[pos..pos + 4].copy_from_slice(&self.pointer_to_raw_data.to_le_bytes());
        pos += 4;
        buf[pos..pos + 4].copy_from_slice(&self.pointer_to_relocations.to_le_bytes());
        pos += 4;
        buf[pos..pos + 4].copy_from_slice(&self.pointer_to_linenumbers.to_le_bytes());
        pos += 4;
        buf[pos..pos + 2].copy_from_slice(&self.number_of_relocations.to_le_bytes());
        pos += 2;
        buf[pos..pos + 2].copy_from_slice(&self.number_of_linenumbers.to_le_bytes());
        pos += 2;
        buf[pos..pos + 4].copy_from_slice(&self.characteristics.to_le_bytes());
        buf
    }

    // -- Mutators for section processing --

    /// Sets the virtual size.
    pub fn set_virtual_size(&mut self, size: u32) {
        self.virtual_size = size;
    }

    /// Sets the size of raw data.
    pub fn set_size_of_raw_data(&mut self, size: u32) {
        self.size_of_raw_data = size;
    }

    /// Offsets the pointers by the given amount (used when adding sections).
    pub fn update_pointers(&mut self, offset: u32) {
        if self.pointer_to_raw_data > 0 {
            self.pointer_to_raw_data += offset;
        }
        if self.pointer_to_relocations > 0 {
            self.pointer_to_relocations += offset;
        }
        if self.pointer_to_linenumbers > 0 {
            self.pointer_to_linenumbers += offset;
        }
    }
}

impl fmt::Display for SectionHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "SectionHeader:")?;
        writeln!(f, "  Name:                 {}", self.name)?;
        writeln!(f, "  PhysicalAddress:      0x{:08X}", self.physical_address)?;
        writeln!(f, "  VirtualSize:          0x{:08X}", self.virtual_size)?;
        writeln!(f, "  VirtualAddress:       0x{:08X}", self.virtual_address)?;
        writeln!(f, "  SizeOfRawData:        0x{:08X}", self.size_of_raw_data)?;
        writeln!(f, "  PointerToRawData:     0x{:08X}", self.pointer_to_raw_data)?;
        writeln!(f, "  PointerToRelocations: 0x{:08X}", self.pointer_to_relocations)?;
        writeln!(f, "  PointerToLinenumbers: 0x{:08X}", self.pointer_to_linenumbers)?;
        writeln!(f, "  NumberOfRelocations:  0x{:04X}", self.number_of_relocations)?;
        writeln!(f, "  NumberOfLinenumbers:  0x{:04X}", self.number_of_linenumbers)?;
        write!(
            f,
            "  Characteristics:      0x{:08X} [{}]",
            self.characteristics,
            self.characteristic_names().join(", ")
        )
    }
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

/// Reads a null-terminated ASCII string from `data` starting at `offset`.
fn read_null_terminated_ascii(data: &[u8], offset: usize) -> Option<String> {
    if offset >= data.len() {
        return None;
    }
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| offset + p)
        .unwrap_or(data.len());
    let slice = &data[offset..end];
    std::str::from_utf8(slice)
        .ok()
        .map(|s| s.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_section_header_bytes(
        name: &[u8; 8],
        virtual_size: u32,
        virtual_address: u32,
        size_of_raw_data: u32,
        pointer_to_raw_data: u32,
        pointer_to_relocations: u32,
        pointer_to_linenumbers: u32,
        number_of_relocations: u16,
        number_of_linenumbers: u16,
        characteristics: u32,
    ) -> [u8; IMAGE_SIZEOF_SECTION_HEADER] {
        let mut buf = [0u8; IMAGE_SIZEOF_SECTION_HEADER];
        buf[..8].copy_from_slice(name);
        let mut pos = 8;
        buf[pos..pos + 4].copy_from_slice(&virtual_size.to_le_bytes());
        pos += 4;
        buf[pos..pos + 4].copy_from_slice(&virtual_address.to_le_bytes());
        pos += 4;
        buf[pos..pos + 4].copy_from_slice(&size_of_raw_data.to_le_bytes());
        pos += 4;
        buf[pos..pos + 4].copy_from_slice(&pointer_to_raw_data.to_le_bytes());
        pos += 4;
        buf[pos..pos + 4].copy_from_slice(&pointer_to_relocations.to_le_bytes());
        pos += 4;
        buf[pos..pos + 4].copy_from_slice(&pointer_to_linenumbers.to_le_bytes());
        pos += 4;
        buf[pos..pos + 2].copy_from_slice(&number_of_relocations.to_le_bytes());
        pos += 2;
        buf[pos..pos + 2].copy_from_slice(&number_of_linenumbers.to_le_bytes());
        pos += 2;
        buf[pos..pos + 4].copy_from_slice(&characteristics.to_le_bytes());
        buf
    }

    #[test]
    fn test_parse_text_section() {
        let mut name = [0u8; 8];
        name[..5].copy_from_slice(b".text");
        let data = make_section_header_bytes(
            &name,
            0x1000, // virtual_size
            0x1000, // virtual_address
            0x600,  // size_of_raw_data
            0x400,  // pointer_to_raw_data
            0,
            0,
            0,
            0,
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        );
        let sh = SectionHeader::parse(&data, 0, None).unwrap();
        assert_eq!(sh.name(), ".text");
        assert_eq!(sh.virtual_size(), 0x1000);
        assert_eq!(sh.virtual_address(), 0x1000);
        assert_eq!(sh.size_of_raw_data(), 0x600);
        assert_eq!(sh.pointer_to_raw_data(), 0x400);
        assert!(sh.is_code());
        assert!(sh.is_executable());
        assert!(sh.is_readable());
        assert!(!sh.is_writable());
    }

    #[test]
    fn test_parse_data_section() {
        let mut name = [0u8; 8];
        name[..5].copy_from_slice(b".data");
        let data = make_section_header_bytes(
            &name,
            0x800,
            0x2000,
            0x400,
            0xA00,
            0,
            0,
            0,
            0,
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        );
        let sh = SectionHeader::parse(&data, 0, None).unwrap();
        assert_eq!(sh.name(), ".data");
        assert!(!sh.is_code());
        assert!(sh.is_initialized_data());
        assert!(sh.is_writable());
    }

    #[test]
    fn test_virtual_size_fallback() {
        let mut name = [0u8; 8];
        name[..4].copy_from_slice(b".bss");
        let data = make_section_header_bytes(
            &name,
            0,    // virtual_size = 0
            0x3000,
            0x200, // size_of_raw_data (used as fallback)
            0,
            0,
            0,
            0,
            0,
            IMAGE_SCN_CNT_UNINITIALIZED_DATA,
        );
        let sh = SectionHeader::parse(&data, 0, None).unwrap();
        assert_eq!(sh.virtual_size(), 0x200); // falls back to size_of_raw_data
        assert!(sh.is_uninitialized_data());
    }

    #[test]
    fn test_pointer_to_raw_data_clamp() {
        let mut name = [0u8; 8];
        name[..4].copy_from_slice(b".hdr");
        let data = make_section_header_bytes(
            &name,
            0x100,
            0,
            0x100,
            0x100, // < 0x200, should clamp to 0
            0,
            0,
            0,
            0,
            0,
        );
        let sh = SectionHeader::parse(&data, 0, None).unwrap();
        assert_eq!(sh.pointer_to_raw_data(), 0);
        assert_eq!(sh.raw_pointer_to_raw_data(), 0x100);
    }

    #[test]
    fn test_to_bytes_roundtrip() {
        let mut name = [0u8; 8];
        name[..5].copy_from_slice(b".text");
        let data = make_section_header_bytes(
            &name,
            0x1000,
            0x1000,
            0x600,
            0x400,
            0,
            0,
            0,
            0,
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        );
        let sh = SectionHeader::parse(&data, 0, None).unwrap();
        let bytes = sh.to_bytes();
        assert_eq!(&bytes[..8], b".text\0\0\0");
        // Verify key fields round-trip
        assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 0x1000);
        assert_eq!(u32::from_le_bytes(bytes[12..16].try_into().unwrap()), 0x1000);
    }

    #[test]
    fn test_update_pointers() {
        let mut name = [0u8; 8];
        name[..5].copy_from_slice(b".data");
        let data = make_section_header_bytes(&name, 0x100, 0x2000, 0x100, 0x400, 0, 0, 0, 0, 0);
        let mut sh = SectionHeader::parse(&data, 0, None).unwrap();
        sh.update_pointers(0x1000);
        assert_eq!(sh.pointer_to_raw_data(), 0x400 + 0x1000);
    }

    #[test]
    fn test_alignment_bytes() {
        let mut name = [0u8; 8];
        name[..5].copy_from_slice(b".text");
        let data = make_section_header_bytes(
            &name,
            0x100,
            0x1000,
            0x100,
            0x400,
            0,
            0,
            0,
            0,
            IMAGE_SCN_ALIGN_16BYTES,
        );
        let sh = SectionHeader::parse(&data, 0, None).unwrap();
        assert_eq!(sh.alignment_bytes(), 16);
    }

    #[test]
    fn test_insufficient_data() {
        let data = [0u8; 10];
        assert!(SectionHeader::parse(&data, 0, None).is_err());
    }

    #[test]
    fn test_readable_name() {
        let mut name = [0x01u8; 8]; // non-printable
        name[0] = b'.';
        name[1] = b't';
        let data = make_section_header_bytes(&name, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        let sh = SectionHeader::parse(&data, 0, None).unwrap();
        let readable = sh.readable_name();
        assert!(readable.starts_with(".t"));
        assert!(readable.chars().skip(2).all(|c| c == '_'));
    }

    #[test]
    fn test_display() {
        let mut name = [0u8; 8];
        name[..5].copy_from_slice(b".text");
        let data = make_section_header_bytes(
            &name,
            0x1000,
            0x1000,
            0x600,
            0x400,
            0,
            0,
            0,
            0,
            IMAGE_SCN_CNT_CODE,
        );
        let sh = SectionHeader::parse(&data, 0, None).unwrap();
        let display = format!("{}", sh);
        assert!(display.contains(".text"));
        assert!(display.contains("CNT_CODE"));
    }
}
