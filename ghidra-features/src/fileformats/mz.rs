//! DOS MZ (MZ) executable format parser.
//!
//! Ported from Ghidra's `ghidra.app.util.bin.format.mz` package.
//!
//! The MZ format is the executable format used by MS-DOS. The name comes
//! from the magic number "MZ" (0x5A4D) at the start of the file header.
//!
//! References:
//! - <https://wiki.osdev.org/MZ>
//! - <https://www.tavi.co.uk/phobos/exeformat.html>

use std::fmt;

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// DOS MZ magic number: 0x5A4D ("MZ" in ASCII).
pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;

/// Size of the DOS header in bytes (28 bytes for the minimal header).
pub const DOS_HEADER_SIZE: usize = 28;

/// Size of a relocation entry in bytes (4 bytes: offset + segment).
pub const MZ_RELOCATION_SIZE: usize = 4;

// ═══════════════════════════════════════════════════════════════════════════════════
// Error Types
// ═══════════════════════════════════════════════════════════════════════════════════

/// Errors encountered while parsing MZ files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MzError {
    /// The file is too small to contain a valid MZ header.
    TooShort,
    /// The magic number is not "MZ" (0x5A4D).
    InvalidMagic(u16),
    /// Error reading relocation entries.
    TruncatedRelocation,
}

impl fmt::Display for MzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(f, "file too small for MZ header"),
            Self::InvalidMagic(m) => {
                write!(f, "invalid MZ magic: 0x{m:04X} (expected 0x5A4D)")
            }
            Self::TruncatedRelocation => write!(f, "truncated relocation entry"),
        }
    }
}

impl std::error::Error for MzError {}

// ═══════════════════════════════════════════════════════════════════════════════════
// OldDOSHeader
// ═══════════════════════════════════════════════════════════════════════════════════

/// DOS MZ executable header.
///
/// The header is 28 bytes (14 little-endian 16-bit words).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OldDOSHeader {
    /// Magic number (0x5A4D = "MZ").
    pub e_magic: u16,
    /// Bytes on the last page of the file (0..511).
    pub e_cblp: u16,
    /// Total number of 512-byte pages in the file.
    pub e_cp: u16,
    /// Number of relocation entries.
    pub e_crlc: u16,
    /// Size of the header in paragraphs (1 paragraph = 16 bytes).
    pub e_cparhdr: u16,
    /// Minimum extra paragraphs needed.
    pub e_minalloc: u16,
    /// Maximum extra paragraphs needed.
    pub e_maxalloc: u16,
    /// Initial (relative) SS value.
    pub e_ss: u16,
    /// Initial SP value.
    pub e_sp: u16,
    /// Checksum (usually 0).
    pub e_csum: u16,
    /// Initial IP value.
    pub e_ip: u16,
    /// Initial (relative) CS value.
    pub e_cs: u16,
    /// File address of the relocation table (byte offset from start of file).
    pub e_lfarlc: u16,
    /// Overlay number (0 = main program).
    pub e_ovno: u16,
}

impl OldDOSHeader {
    /// Parse the DOS header from a byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, MzError> {
        if data.len() < DOS_HEADER_SIZE {
            return Err(MzError::TooShort);
        }

        let e_magic = u16::from_le_bytes([data[0], data[1]]);
        if e_magic != IMAGE_DOS_SIGNATURE {
            return Err(MzError::InvalidMagic(e_magic));
        }

        Ok(Self {
            e_magic,
            e_cblp: u16::from_le_bytes([data[2], data[3]]),
            e_cp: u16::from_le_bytes([data[4], data[5]]),
            e_crlc: u16::from_le_bytes([data[6], data[7]]),
            e_cparhdr: u16::from_le_bytes([data[8], data[9]]),
            e_minalloc: u16::from_le_bytes([data[10], data[11]]),
            e_maxalloc: u16::from_le_bytes([data[12], data[13]]),
            e_ss: u16::from_le_bytes([data[14], data[15]]),
            e_sp: u16::from_le_bytes([data[16], data[17]]),
            e_csum: u16::from_le_bytes([data[18], data[19]]),
            e_ip: u16::from_le_bytes([data[20], data[21]]),
            e_cs: u16::from_le_bytes([data[22], data[23]]),
            e_lfarlc: u16::from_le_bytes([data[24], data[25]]),
            e_ovno: u16::from_le_bytes([data[26], data[27]]),
        })
    }

    /// Whether the magic number is the valid DOS signature.
    pub fn is_dos_signature(&self) -> bool {
        self.e_magic == IMAGE_DOS_SIGNATURE
    }

    /// The size of the header in bytes (e_cparhdr * 16).
    pub fn header_size_bytes(&self) -> usize {
        self.e_cparhdr as usize * 16
    }

    /// The total file size as computed from e_cp and e_cblp.
    pub fn computed_file_size(&self) -> usize {
        let full_pages = self.e_cp as usize;
        let last_page_bytes = self.e_cblp as usize;
        if last_page_bytes == 0 {
            full_pages * 512
        } else {
            (full_pages.saturating_sub(1)) * 512 + last_page_bytes
        }
    }

    /// The initial CS:IP entry point.
    pub fn entry_point_cs_ip(&self) -> (u16, u16) {
        (self.e_cs, self.e_ip)
    }

    /// The initial SS:SP stack pointer.
    pub fn stack_pointer_ss_sp(&self) -> (u16, u16) {
        (self.e_ss, self.e_sp)
    }

    /// Whether this file has a new EXE header (NE/LE/LX/PE).
    ///
    /// This is determined by checking if the e_lfarlc field is 0x40,
    /// which is the standard offset for the new EXE header signature.
    pub fn has_new_exe_header(&self, data: &[u8]) -> bool {
        // The new EXE header offset is at file offset 0x3C in the full DOS header
        if data.len() >= 0x40 {
            let ne_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]);
            if ne_offset > 0 && (ne_offset as usize) + 2 <= data.len() {
                let sig = u16::from_le_bytes([data[ne_offset as usize], data[ne_offset as usize + 1]]);
                // NE = 0x454E, LE = 0x454C, LX = 0x584C, PE = 0x4550
                return sig == 0x454E || sig == 0x454C || sig == 0x584C || sig == 0x4550;
            }
        }
        false
    }

    /// Whether this file has a PE header.
    pub fn has_pe_header(&self, data: &[u8]) -> bool {
        if data.len() >= 0x40 {
            let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]);
            if pe_offset > 0 && (pe_offset as usize) + 2 <= data.len() {
                let sig = u16::from_le_bytes([data[pe_offset as usize], data[pe_offset as usize + 1]]);
                return sig == 0x4550; // "PE"
            }
        }
        false
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// MzRelocation
// ═══════════════════════════════════════════════════════════════════════════════════

/// An MZ relocation entry.
///
/// Each relocation entry is 4 bytes: a 16-bit offset and a 16-bit segment.
/// The relocation tells the loader which addresses need to be patched when
/// the executable is loaded at a different base address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MzRelocation {
    /// Offset within the segment.
    pub offset: u16,
    /// Segment value.
    pub segment: u16,
}

impl MzRelocation {
    /// Parse a relocation entry from a byte slice.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, MzError> {
        if offset + MZ_RELOCATION_SIZE > data.len() {
            return Err(MzError::TruncatedRelocation);
        }
        Ok(Self {
            offset: u16::from_le_bytes([data[offset], data[offset + 1]]),
            segment: u16::from_le_bytes([data[offset + 2], data[offset + 3]]),
        })
    }

    /// Return the full address as a 32-bit value (segment:offset).
    pub fn address(&self) -> u32 {
        ((self.segment as u32) << 16) | (self.offset as u32)
    }
}

impl fmt::Display for MzRelocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04X}:{:04X}", self.segment, self.offset)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// MzExecutable
// ═══════════════════════════════════════════════════════════════════════════════════

/// A parsed DOS MZ executable.
#[derive(Debug, Clone)]
pub struct MzExecutable {
    /// The DOS header.
    pub header: OldDOSHeader,
    /// Relocation entries.
    pub relocations: Vec<MzRelocation>,
    /// Whether this file wraps a new-style executable (NE/LE/LX/PE).
    pub has_new_exe: bool,
    /// Whether this file wraps a PE executable.
    pub has_pe: bool,
}

impl MzExecutable {
    /// Parse an MZ executable from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, MzError> {
        let header = OldDOSHeader::parse(data)?;

        // Parse relocations
        let reloc_count = header.e_crlc as usize;
        let reloc_offset = header.e_lfarlc as usize;
        let mut relocations = Vec::with_capacity(reloc_count);

        for i in 0..reloc_count {
            let off = reloc_offset + i * MZ_RELOCATION_SIZE;
            relocations.push(MzRelocation::parse(data, off)?);
        }

        let has_new_exe = header.has_new_exe_header(data);
        let has_pe = header.has_pe_header(data);

        Ok(Self {
            header,
            relocations,
            has_new_exe,
            has_pe,
        })
    }

    /// Whether this is a plain DOS executable (not wrapping NE/PE/etc.).
    pub fn is_dos_only(&self) -> bool {
        !self.has_new_exe && !self.has_pe
    }
}

/// Check if a byte slice starts with the MZ magic number.
pub fn is_mz_file(data: &[u8]) -> bool {
    data.len() >= 2 && u16::from_le_bytes([data[0], data[1]]) == IMAGE_DOS_SIGNATURE
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_mz(reloc_count: u16, reloc_offset: u16) -> Vec<u8> {
        let mut data = vec![0u8; DOS_HEADER_SIZE + reloc_count as usize * MZ_RELOCATION_SIZE + 64];
        data[0..2].copy_from_slice(&IMAGE_DOS_SIGNATURE.to_le_bytes()); // magic
        data[2..4].copy_from_slice(&0u16.to_le_bytes()); // e_cblp
        data[4..6].copy_from_slice(&1u16.to_le_bytes()); // e_cp (1 page)
        data[6..8].copy_from_slice(&reloc_count.to_le_bytes()); // e_crlc
        data[8..10].copy_from_slice(&2u16.to_le_bytes()); // e_cparhdr (2 paragraphs = 32 bytes)
        data[10..12].copy_from_slice(&0u16.to_le_bytes()); // e_minalloc
        data[12..14].copy_from_slice(&0xFFFFu16.to_le_bytes()); // e_maxalloc
        data[14..16].copy_from_slice(&0u16.to_le_bytes()); // e_ss
        data[16..18].copy_from_slice(&0xFFFEu16.to_le_bytes()); // e_sp
        data[18..20].copy_from_slice(&0u16.to_le_bytes()); // e_csum
        data[20..22].copy_from_slice(&0u16.to_le_bytes()); // e_ip
        data[22..24].copy_from_slice(&0u16.to_le_bytes()); // e_cs
        data[24..26].copy_from_slice(&reloc_offset.to_le_bytes()); // e_lfarlc
        data[26..28].copy_from_slice(&0u16.to_le_bytes()); // e_ovno
        data
    }

    #[test]
    fn test_parse_header() {
        let data = make_minimal_mz(0, DOS_HEADER_SIZE as u16);
        let header = OldDOSHeader::parse(&data).unwrap();
        assert_eq!(header.e_magic, IMAGE_DOS_SIGNATURE);
        assert!(header.is_dos_signature());
        assert_eq!(header.e_cparhdr, 2);
        assert_eq!(header.header_size_bytes(), 32);
    }

    #[test]
    fn test_invalid_magic() {
        let mut data = make_minimal_mz(0, 0);
        data[0] = 0x00;
        data[1] = 0x00;
        assert_eq!(
            OldDOSHeader::parse(&data),
            Err(MzError::InvalidMagic(0))
        );
    }

    #[test]
    fn test_too_short() {
        assert_eq!(OldDOSHeader::parse(&[0x4D, 0x5A]), Err(MzError::TooShort));
    }

    #[test]
    fn test_is_mz_file() {
        let data = make_minimal_mz(0, 0);
        assert!(is_mz_file(&data));
        assert!(!is_mz_file(&[0x00, 0x00]));
        assert!(!is_mz_file(&[0x4D]));
    }

    #[test]
    fn test_parse_with_relocations() {
        let reloc_offset = DOS_HEADER_SIZE as u16;
        let mut data = make_minimal_mz(2, reloc_offset);
        // Relocation 0: 0x0010:0x0100
        let off = DOS_HEADER_SIZE;
        data[off..off + 2].copy_from_slice(&0x0100u16.to_le_bytes());
        data[off + 2..off + 4].copy_from_slice(&0x0010u16.to_le_bytes());
        // Relocation 1: 0x0020:0x0200
        data[off + 4..off + 6].copy_from_slice(&0x0200u16.to_le_bytes());
        data[off + 6..off + 8].copy_from_slice(&0x0020u16.to_le_bytes());

        let mz = MzExecutable::parse(&data).unwrap();
        assert_eq!(mz.relocations.len(), 2);
        assert_eq!(mz.relocations[0].offset, 0x0100);
        assert_eq!(mz.relocations[0].segment, 0x0010);
        assert_eq!(mz.relocations[1].offset, 0x0200);
        assert_eq!(mz.relocations[1].segment, 0x0020);
    }

    #[test]
    fn test_relocation_display() {
        let reloc = MzRelocation {
            offset: 0x0100,
            segment: 0x0010,
        };
        assert_eq!(reloc.to_string(), "0010:0100");
    }

    #[test]
    fn test_relocation_address() {
        let reloc = MzRelocation {
            offset: 0x0100,
            segment: 0x0010,
        };
        assert_eq!(reloc.address(), 0x0010_0100);
    }

    #[test]
    fn test_entry_point() {
        let mut data = make_minimal_mz(0, DOS_HEADER_SIZE as u16);
        data[20..22].copy_from_slice(&0x0100u16.to_le_bytes()); // e_ip
        data[22..24].copy_from_slice(&0x0040u16.to_le_bytes()); // e_cs
        let header = OldDOSHeader::parse(&data).unwrap();
        assert_eq!(header.entry_point_cs_ip(), (0x0040, 0x0100));
    }

    #[test]
    fn test_stack_pointer() {
        let data = make_minimal_mz(0, DOS_HEADER_SIZE as u16);
        let header = OldDOSHeader::parse(&data).unwrap();
        assert_eq!(header.stack_pointer_ss_sp(), (0, 0xFFFE));
    }

    #[test]
    fn test_computed_file_size() {
        let data = make_minimal_mz(0, DOS_HEADER_SIZE as u16);
        let header = OldDOSHeader::parse(&data).unwrap();
        // e_cp=1, e_cblp=0 -> 1 * 512 = 512
        assert_eq!(header.computed_file_size(), 512);
    }

    #[test]
    fn test_computed_file_size_with_partial_page() {
        let mut data = make_minimal_mz(0, DOS_HEADER_SIZE as u16);
        data[2..4].copy_from_slice(&100u16.to_le_bytes()); // e_cblp = 100
        data[4..6].copy_from_slice(&3u16.to_le_bytes()); // e_cp = 3 pages
        let header = OldDOSHeader::parse(&data).unwrap();
        // (3-1) * 512 + 100 = 1124
        assert_eq!(header.computed_file_size(), 1124);
    }

    #[test]
    fn test_mz_executable_is_dos_only() {
        let data = make_minimal_mz(0, DOS_HEADER_SIZE as u16);
        let mz = MzExecutable::parse(&data).unwrap();
        assert!(mz.is_dos_only());
        assert!(!mz.has_new_exe);
        assert!(!mz.has_pe);
    }

    #[test]
    fn test_mz_with_pe_header() {
        let mut data = make_minimal_mz(0, DOS_HEADER_SIZE as u16);
        // Set the PE header pointer at offset 0x3C
        data.resize(0x44, 0);
        let pe_offset: u32 = 0x40;
        data[0x3C..0x40].copy_from_slice(&pe_offset.to_le_bytes());
        // Write "PE" signature at the pointed offset
        data[0x40..0x42].copy_from_slice(&0x4550u16.to_le_bytes());

        let mz = MzExecutable::parse(&data).unwrap();
        assert!(!mz.is_dos_only());
        assert!(mz.has_pe);
    }

    #[test]
    fn test_header_full_fields() {
        let mut data = make_minimal_mz(0, DOS_HEADER_SIZE as u16);
        // Set unique values for each field
        data[0..2].copy_from_slice(&0x5A4Du16.to_le_bytes());
        data[2..4].copy_from_slice(&512u16.to_le_bytes()); // e_cblp
        data[4..6].copy_from_slice(&10u16.to_le_bytes()); // e_cp
        data[6..8].copy_from_slice(&5u16.to_le_bytes()); // e_crlc
        data[8..10].copy_from_slice(&4u16.to_le_bytes()); // e_cparhdr
        data[10..12].copy_from_slice(&16u16.to_le_bytes()); // e_minalloc
        data[12..14].copy_from_slice(&0xFFFFu16.to_le_bytes()); // e_maxalloc
        data[14..16].copy_from_slice(&0x1234u16.to_le_bytes()); // e_ss
        data[16..18].copy_from_slice(&0xFFFEu16.to_le_bytes()); // e_sp
        data[18..20].copy_from_slice(&0x1234u16.to_le_bytes()); // e_csum
        data[20..22].copy_from_slice(&0x0100u16.to_le_bytes()); // e_ip
        data[22..24].copy_from_slice(&0x0040u16.to_le_bytes()); // e_cs
        data[24..26].copy_from_slice(&0x0040u16.to_le_bytes()); // e_lfarlc
        data[26..28].copy_from_slice(&3u16.to_le_bytes()); // e_ovno

        let header = OldDOSHeader::parse(&data).unwrap();
        assert_eq!(header.e_cblp, 512);
        assert_eq!(header.e_cp, 10);
        assert_eq!(header.e_crlc, 5);
        assert_eq!(header.e_cparhdr, 4);
        assert_eq!(header.e_minalloc, 16);
        assert_eq!(header.e_maxalloc, 0xFFFF);
        assert_eq!(header.e_ss, 0x1234);
        assert_eq!(header.e_sp, 0xFFFE);
        assert_eq!(header.e_csum, 0x1234);
        assert_eq!(header.e_ip, 0x0100);
        assert_eq!(header.e_cs, 0x0040);
        assert_eq!(header.e_lfarlc, 0x0040);
        assert_eq!(header.e_ovno, 3);
        assert_eq!(header.header_size_bytes(), 64); // 4 * 16
    }

    #[test]
    fn test_no_relocations() {
        let data = make_minimal_mz(0, DOS_HEADER_SIZE as u16);
        let mz = MzExecutable::parse(&data).unwrap();
        assert!(mz.relocations.is_empty());
    }

    #[test]
    fn test_error_display() {
        assert_eq!(
            MzError::TooShort.to_string(),
            "file too small for MZ header"
        );
        assert!(MzError::InvalidMagic(0x1234)
            .to_string()
            .contains("0x1234"));
        assert_eq!(
            MzError::TruncatedRelocation.to_string(),
            "truncated relocation entry"
        );
    }
}
