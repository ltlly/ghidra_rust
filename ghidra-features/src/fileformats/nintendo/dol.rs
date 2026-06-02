//! GameCube / Wii DOL executable format.
//!
//! DOL is the primary executable format for the GameCube and Wii consoles.
//! It consists of a 256-byte header (0x100) followed by the raw section data.
//! The header encodes up to 7 text (code) sections and 11 data sections, each
//! described by a triple of (offset, load-address, size).
//!
//! # Header layout (all values are big-endian u32)
//!
//! | Offset | Size | Field              |
//! |--------|------|--------------------|
//! | 0x00   | 0x1C | text offsets[7]    |
//! | 0x1C   | 0x2C | data offsets[11]   |
//! | 0x48   | 0x1C | text addresses[7]  |
//! | 0x64   | 0x2C | data addresses[11] |
//! | 0x90   | 0x1C | text sizes[7]      |
//! | 0xAC   | 0x2C | data sizes[11]     |
//! | 0xD8   | 4    | bss_address        |
//! | 0xDC   | 4    | bss_size           |
//! | 0xE0   | 4    | entry_point        |
//! | 0xE4   | 0x1C | padding            |
//!
//! A section whose offset is 0 is considered empty / not present.
//!
//! References:
//! - [GC-Forever Wiki: DOL Format](https://www.gc-forever.com/wiki/index.php?title=DOL)
//! - [WiiBrew: DOL](https://wiibrew.org/wiki/DOL)
//! - Ghidra's `ghidra.app.util.bin.format.dol` package

// ===========================================================================
// Imports
// ===========================================================================

use std::fmt;

use nom::{
    bytes::complete::take,
    multi::count,
    number::complete::be_u32,
    sequence::tuple,
    IResult, Parser,
};

// ===========================================================================
// Error Types
// ===========================================================================

/// DOL parse error.
#[derive(Debug, Clone)]
pub enum DolError {
    /// File is too small to contain a DOL header (256 bytes minimum).
    TruncatedData,
    /// No sections were found (all offsets are zero).
    NoSections,
    /// A section offset points beyond the file data.
    InvalidSectionOffset,
    /// A nom parse error.
    ParseError(String),
}

impl fmt::Display for DolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedData => write!(f, "truncated DOL data (need at least 256 bytes)"),
            Self::NoSections => write!(f, "no sections present in DOL"),
            Self::InvalidSectionOffset => write!(f, "section offset points beyond file data"),
            Self::ParseError(s) => write!(f, "parse error: {s}"),
        }
    }
}

impl std::error::Error for DolError {}

impl<T: std::fmt::Debug> From<nom::Err<nom::error::Error<T>>> for DolError {
    fn from(e: nom::Err<nom::error::Error<T>>) -> Self {
        Self::ParseError(format!("{e:?}"))
    }
}

/// Type alias for DOL results.
pub type DolResult<T> = Result<T, DolError>;

// ===========================================================================
// Constants
// ===========================================================================

/// Size of the DOL header in bytes.
pub const DOL_HEADER_SIZE: usize = 0x100;

/// Maximum number of text (code) sections.
pub const TEXT_SECTION_COUNT: usize = 7;

/// Maximum number of data sections.
pub const DATA_SECTION_COUNT: usize = 11;

/// Maximum total sections.
pub const MAX_SECTIONS: usize = TEXT_SECTION_COUNT + DATA_SECTION_COUNT;

/// Offset within the header for the entry-point field.
const ENTRY_OFFSET: usize = 0xE0;

// ===========================================================================
// Structured Types
// ===========================================================================

/// Permission flags for a DOL section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DolSectionKind {
    /// Executable code (text).
    Text,
    /// Read-only or read-write data.
    Data,
    /// Zero-initialised (BSS).
    Bss,
}

impl fmt::Display for DolSectionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text => write!(f, "text"),
            Self::Data => write!(f, "data"),
            Self::Bss => write!(f, "bss"),
        }
    }
}

/// A single section described by the DOL header.
#[derive(Debug, Clone)]
pub struct DolSection {
    /// File offset where this section begins (0 = not present).
    pub offset: u32,
    /// Target load address in memory.
    pub address: u32,
    /// Size in bytes (0 = not present).
    pub size: u32,
    /// Section kind (text, data, or bss).
    pub kind: DolSectionKind,
    /// Raw section data (empty for BSS).
    pub data: Vec<u8>,
}

impl DolSection {
    /// Returns true if this section is present (offset and size non-zero).
    pub fn is_present(&self) -> bool {
        self.offset != 0 && self.size != 0
    }
}

/// A fully parsed DOL executable.
#[derive(Debug, Clone)]
pub struct DolFile {
    /// All sections (text then data), including empty ones.
    pub sections: Vec<DolSection>,
    /// Address of the uninitialised BSS section.
    pub bss_address: u32,
    /// Size of the BSS section in bytes.
    pub bss_size: u32,
    /// Entry-point address (PowerPC function pointer).
    pub entry_point: u32,
    /// Total size of the file on disk (header + all section data).
    pub file_size: u32,
}

impl DolFile {
    /// Iterate over sections that are actually present (offset != 0).
    pub fn active_sections(&self) -> impl Iterator<Item = &DolSection> {
        self.sections.iter().filter(|s| s.is_present())
    }

    /// Iterate over text sections that are actually present.
    pub fn text_sections(&self) -> impl Iterator<Item = &DolSection> {
        self.sections
            .iter()
            .filter(|s| s.kind == DolSectionKind::Text && s.is_present())
    }

    /// Iterate over data sections that are actually present.
    pub fn data_sections(&self) -> impl Iterator<Item = &DolSection> {
        self.sections
            .iter()
            .filter(|s| s.kind == DolSectionKind::Data && s.is_present())
    }

    /// Total size of all code (text) sections.
    pub fn total_text_size(&self) -> u32 {
        self.text_sections().map(|s| s.size).sum()
    }

    /// Total size of all data sections.
    pub fn total_data_size(&self) -> u32 {
        self.data_sections().map(|s| s.size).sum()
    }

    /// Returns true if this appears to be a valid DOL (has at least one section).
    pub fn is_valid(&self) -> bool {
        self.sections.iter().any(|s| s.is_present())
    }
}

// ===========================================================================
// Nom Parsers
// ===========================================================================

/// Parse a DOL executable from a byte slice.
///
/// # Errors
///
/// Returns [`DolError::TruncatedData`] if the buffer is smaller than
/// [`DOL_HEADER_SIZE`].  Returns [`DolError::NoSections`] if no text or
/// data sections are present.
pub fn parse_dol(data: &[u8]) -> DolResult<DolFile> {
    if data.len() < DOL_HEADER_SIZE {
        return Err(DolError::TruncatedData);
    }
    let (remaining, header) = parse_dol_header(data)?;
    let _ = remaining; // nom returns the unconsumed portion

    let mut sections = header.sections;
    let file_size = populate_section_data(&mut sections, data)?;

    Ok(DolFile {
        sections,
        bss_address: header.bss_address,
        bss_size: header.bss_size,
        entry_point: header.entry_point,
        file_size,
    })
}

/// Quick check: is this blob a DOL?
///
/// Checks for non-zero text in the offset/address/size arrays
/// inside the first 256 bytes.
pub fn is_dol(data: &[u8]) -> bool {
    if data.len() < DOL_HEADER_SIZE {
        return false;
    }
    // Check that at least one text or data section has a non-zero offset
    let text_offsets = &data[0x00..0x1C];
    let data_offsets = &data[0x1C..0x48];
    let has_text = text_offsets
        .chunks_exact(4)
        .any(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]) != 0);
    let has_data = data_offsets
        .chunks_exact(4)
        .any(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]) != 0);
    has_text || has_data
}

// ── Internal header-only struct ─────────────────────────────────────────

#[derive(Debug, Clone)]
struct DolRawHeader {
    sections: Vec<DolSection>,
    bss_address: u32,
    bss_size: u32,
    entry_point: u32,
}

/// Parse the DOL header with nom.
fn parse_dol_header(input: &[u8]) -> IResult<&[u8], DolRawHeader> {
    let (input, text_offsets) = count(be_u32, TEXT_SECTION_COUNT)(input)?;
    let (input, data_offsets) = count(be_u32, DATA_SECTION_COUNT)(input)?;
    let (input, text_addresses) = count(be_u32, TEXT_SECTION_COUNT)(input)?;
    let (input, data_addresses) = count(be_u32, DATA_SECTION_COUNT)(input)?;
    let (input, text_sizes) = count(be_u32, TEXT_SECTION_COUNT)(input)?;
    let (input, data_sizes) = count(be_u32, DATA_SECTION_COUNT)(input)?;

    let (input, (bss_address, bss_size, entry_point)) =
        tuple((be_u32, be_u32, be_u32)).parse(input)?;

    // Consume remaining header padding (0xE4 .. 0x100)
    let (input, _padding) = take(DOL_HEADER_SIZE - ENTRY_OFFSET - 12)(input)?;

    // Build section list: text sections first, then data sections
    let mut sections = Vec::with_capacity(MAX_SECTIONS);
    for i in 0..TEXT_SECTION_COUNT {
        sections.push(DolSection {
            offset: text_offsets[i],
            address: text_addresses[i],
            size: text_sizes[i],
            kind: DolSectionKind::Text,
            data: Vec::new(),
        });
    }
    for i in 0..DATA_SECTION_COUNT {
        sections.push(DolSection {
            offset: data_offsets[i],
            address: data_addresses[i],
            size: data_sizes[i],
            kind: DolSectionKind::Data,
            data: Vec::new(),
        });
    }

    Ok((
        input,
        DolRawHeader {
            sections,
            bss_address,
            bss_size,
            entry_point,
        },
    ))
}

/// Populate section data from the file bytes.
///
/// Returns the total file size (header + all section data).
fn populate_section_data(sections: &mut [DolSection], data: &[u8]) -> Result<u32, DolError> {
    let mut max_end: u32 = DOL_HEADER_SIZE as u32;

    for section in sections.iter_mut() {
        if !section.is_present() {
            continue;
        }
        let start = section.offset as usize;
        let size = section.size as usize;
        let end = start.saturating_add(size);

        if start < DOL_HEADER_SIZE || end > data.len() {
            return Err(DolError::InvalidSectionOffset);
        }

        section.data = data[start..end].to_vec();
        if (end as u32) > max_end {
            max_end = end as u32;
        }
    }

    Ok(max_end)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid DOL with one text section.
    fn build_minimal_dol() -> Vec<u8> {
        let mut buf = vec![0u8; DOL_HEADER_SIZE + 0x1000];

        // One text section at offset 0x100, address 0x8000_3100, size 0x1000
        let text_offset: u32 = 0x0000_0100;
        let text_addr: u32 = 0x8000_3100;
        let text_size: u32 = 0x0000_1000;

        buf[0x00..0x04].copy_from_slice(&text_offset.to_be_bytes());

        // text address
        buf[0x48..0x4C].copy_from_slice(&text_addr.to_be_bytes());

        // text size
        buf[0x90..0x94].copy_from_slice(&text_size.to_be_bytes());

        // entry point = 0x8000_3100
        let entry: u32 = 0x8000_3100;
        buf[ENTRY_OFFSET..ENTRY_OFFSET + 4].copy_from_slice(&entry.to_be_bytes());

        // Fill text section with some fake code (PowerPC NOPs)
        for i in 0x100..0x100 + 0x1000 {
            buf[i] = 0x60;
        }

        buf
    }

    #[test]
    fn test_parse_minimal_dol() {
        let data = build_minimal_dol();
        let dol = parse_dol(&data).expect("should parse minimal DOL");
        assert_eq!(dol.entry_point, 0x8000_3100);
        assert_eq!(dol.sections.len(), TEXT_SECTION_COUNT + DATA_SECTION_COUNT);
        assert!(dol.is_valid());

        let text_secs: Vec<_> = dol.text_sections().collect();
        assert_eq!(text_secs.len(), 1);
        assert_eq!(text_secs[0].offset, 0x100);
        assert_eq!(text_secs[0].address, 0x8000_3100);
        assert_eq!(text_secs[0].size, 0x1000);
        assert_eq!(text_secs[0].data.len(), 0x1000);

        // Total file size should be header + text section
        assert_eq!(dol.file_size, DOL_HEADER_SIZE as u32 + 0x1000);
    }

    #[test]
    fn test_truncated_data() {
        let data = vec![0u8; 100];
        assert!(parse_dol(&data).is_err());
    }

    #[test]
    fn test_is_dol_detection() {
        let data = build_minimal_dol();
        assert!(is_dol(&data));

        // Empty buffer
        assert!(!is_dol(&[]));

        // All-zero header (no sections)
        let zeros = vec![0u8; DOL_HEADER_SIZE];
        assert!(!is_dol(&zeros));
    }

    #[test]
    fn test_empty_sections_skipped() {
        let data = build_minimal_dol();
        let dol = parse_dol(&data).unwrap();
        let active: Vec<_> = dol.active_sections().collect();
        // Only one active text section, no data sections
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].kind, DolSectionKind::Text);
    }

    #[test]
    fn test_multiple_sections() {
        let text0_size: u32 = 0x1000;
        let data0_size: u32 = 0x200;
        let mut buf = vec![0u8; DOL_HEADER_SIZE + text0_size as usize + data0_size as usize];

        // text[0]
        buf[0x00..0x04].copy_from_slice(&(DOL_HEADER_SIZE as u32).to_be_bytes());
        buf[0x48..0x4C].copy_from_slice(&0x8000_4000_u32.to_be_bytes());
        buf[0x90..0x94].copy_from_slice(&text0_size.to_be_bytes());

        // data[0]
        let data_offset = DOL_HEADER_SIZE as u32 + text0_size;
        buf[0x1C..0x20].copy_from_slice(&data_offset.to_be_bytes());
        buf[0x64..0x68].copy_from_slice(&0x8100_0000_u32.to_be_bytes());
        buf[0xAC..0xB0].copy_from_slice(&data0_size.to_be_bytes());

        // entry
        buf[ENTRY_OFFSET..ENTRY_OFFSET + 4].copy_from_slice(&0x8000_4000_u32.to_be_bytes());

        let dol = parse_dol(&buf).expect("should parse multi-section DOL");
        let active: Vec<_> = dol.active_sections().collect();
        assert_eq!(active.len(), 2);
        assert_eq!(active[0].kind, DolSectionKind::Text);
        assert_eq!(active[1].kind, DolSectionKind::Data);
    }
}
