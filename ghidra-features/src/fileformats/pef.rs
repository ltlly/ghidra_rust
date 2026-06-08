//! PEF (Preferred Executable Format) parser for classic Mac OS.
//!
//! Ported from Ghidra's `ghidra.app.util.bin.format.pef` package.
//!
//! PEF was the native executable format for classic Mac OS (System 7 through 9)
//! on PowerPC and 68k architectures. It was replaced by Mach-O on Mac OS X.
//!
//! References:
//! - Apple's PEFBinaryFormat.h
//! - <https://developer.apple.com/library/archive/documentation/mac/pdf/MoreMacToolbox/PEF.pdf>

use std::fmt;

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// PEF container tag 1: "Joy!".
pub const PEF_TAG1: &[u8; 4] = b"Joy!";
/// PEF container tag 2: "peff".
pub const PEF_TAG2: &[u8; 4] = b"peff";

/// Architecture: PowerPC.
pub const ARCH_PPC: &[u8; 4] = b"pwpc";
/// Architecture: Motorola 68k.
pub const ARCH_68K: &[u8; 4] = b"m68k";

/// Container header size in bytes.
pub const CONTAINER_HEADER_SIZE: usize = 40;

/// Section header size in bytes.
pub const SECTION_HEADER_SIZE: usize = 28;

/// Loader info header minimum size in bytes.
pub const LOADER_INFO_HEADER_SIZE: usize = 56;

/// No name offset sentinel value.
pub const NO_NAME_OFFSET: i32 = -1;

// ═══════════════════════════════════════════════════════════════════════════════════
// Error Types
// ═══════════════════════════════════════════════════════════════════════════════════

/// Errors encountered while parsing PEF files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PefError {
    /// File is too small.
    TooShort,
    /// Invalid PEF tags.
    InvalidTags,
    /// Invalid architecture.
    InvalidArchitecture(String),
    /// Multiple loader sections found.
    MultipleLoaderSections,
    /// Truncated section header.
    TruncatedSectionHeader,
    /// Truncated loader info header.
    TruncatedLoaderInfo,
    /// Invalid packed data opcode.
    InvalidPackedOpcode(u8),
    /// Error reading packed data.
    PackedDataError(String),
}

impl fmt::Display for PefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(f, "file too small for PEF header"),
            Self::InvalidTags => write!(f, "invalid PEF tags (expected 'Joy!' + 'peff')"),
            Self::InvalidArchitecture(a) => {
                write!(f, "invalid PEF architecture: {a}")
            }
            Self::MultipleLoaderSections => {
                write!(f, "multiple loader sections found")
            }
            Self::TruncatedSectionHeader => write!(f, "truncated section header"),
            Self::TruncatedLoaderInfo => write!(f, "truncated loader info header"),
            Self::InvalidPackedOpcode(op) => write!(f, "invalid packed data opcode: {op}"),
            Self::PackedDataError(s) => write!(f, "packed data error: {s}"),
        }
    }
}

impl std::error::Error for PefError {}

// ═══════════════════════════════════════════════════════════════════════════════════
// SectionKind
// ═══════════════════════════════════════════════════════════════════════════════════

/// PEF section kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionKind {
    /// Code section.
    Code,
    /// Unpacked data.
    UnpackedData,
    /// Packed data.
    PackedData,
    /// Constant data.
    Constant,
    /// Loader section.
    Loader,
    /// Executable data (read/write/execute).
    ExecutableData,
    /// Unknown.
    Unknown(u8),
}

impl SectionKind {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::Code,
            1 => Self::UnpackedData,
            2 => Self::PackedData,
            3 => Self::Constant,
            4 => Self::Loader,
            6 => Self::ExecutableData,
            other => Self::Unknown(other),
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            Self::Code => 0,
            Self::UnpackedData => 1,
            Self::PackedData => 2,
            Self::Constant => 3,
            Self::Loader => 4,
            Self::ExecutableData => 6,
            Self::Unknown(v) => *v,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Code => "code",
            Self::UnpackedData => "unpacked-data",
            Self::PackedData => "packed-data",
            Self::Constant => "constant",
            Self::Loader => "loader",
            Self::ExecutableData => "executable-data",
            Self::Unknown(_) => "unknown",
        }
    }
}

impl fmt::Display for SectionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// SectionShareKind
// ═══════════════════════════════════════════════════════════════════════════════════

/// PEF section sharing kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionShareKind {
    /// Process sharing.
    ProcessShare,
    /// Global sharing.
    GlobalShare,
    /// Protected sharing.
    ProtectedShare,
    /// Unknown.
    Unknown(u8),
}

impl SectionShareKind {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::ProcessShare,
            1 => Self::GlobalShare,
            4 => Self::ProtectedShare,
            other => Self::Unknown(other),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// ContainerHeader
// ═══════════════════════════════════════════════════════════════════════════════════

/// PEF container header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PefContainerHeader {
    /// Architecture (e.g., "pwpc" for PowerPC, "m68k" for 68k).
    pub architecture: [u8; 4],
    /// Format version (currently 1).
    pub format_version: u32,
    /// Date/time stamp (Mac time: seconds since Jan 1, 1904).
    pub date_time_stamp: u32,
    /// Old definition version.
    pub old_def_version: u32,
    /// Old implementation version.
    pub old_imp_version: u32,
    /// Current version.
    pub current_version: u32,
    /// Total number of section headers.
    pub section_count: u16,
    /// Number of instantiated sections.
    pub inst_section_count: u16,
    /// Section headers.
    pub sections: Vec<PefSectionHeader>,
    /// Loader info (if present).
    pub loader_info: Option<PefLoaderInfo>,
}

impl PefContainerHeader {
    /// Parse a PEF container header from raw bytes (big-endian).
    pub fn parse(data: &[u8]) -> Result<Self, PefError> {
        if data.len() < CONTAINER_HEADER_SIZE {
            return Err(PefError::TooShort);
        }

        // Check tags
        if &data[0..4] != PEF_TAG1 || &data[4..8] != PEF_TAG2 {
            return Err(PefError::InvalidTags);
        }

        let architecture = [data[8], data[9], data[10], data[11]];
        if &architecture != ARCH_PPC && &architecture != ARCH_68K {
            return Err(PefError::InvalidArchitecture(
                String::from_utf8_lossy(&architecture).to_string(),
            ));
        }

        let format_version = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let date_time_stamp = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let old_def_version = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        let old_imp_version = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);
        let current_version = u32::from_be_bytes([data[28], data[29], data[30], data[31]]);
        let section_count = u16::from_be_bytes([data[32], data[33]]);
        let inst_section_count = u16::from_be_bytes([data[34], data[35]]);

        // Parse section headers
        let mut sections = Vec::with_capacity(section_count as usize);
        let mut offset = CONTAINER_HEADER_SIZE;
        let mut loader_info: Option<PefLoaderInfo> = None;

        for i in 0..section_count as usize {
            if offset + SECTION_HEADER_SIZE > data.len() {
                return Err(PefError::TruncatedSectionHeader);
            }
            let section = PefSectionHeader::parse_be(&data[offset..offset + SECTION_HEADER_SIZE]);
            offset += SECTION_HEADER_SIZE;

            if section.section_kind == SectionKind::Loader {
                if loader_info.is_some() {
                    return Err(PefError::MultipleLoaderSections);
                }
                // Parse loader info from the section data
                let loader_offset = section.container_offset as usize;
                if loader_offset + LOADER_INFO_HEADER_SIZE <= data.len() {
                    loader_info = Some(PefLoaderInfo::parse_be(
                        &data[loader_offset..],
                        section.container_length as usize,
                    )?);
                }
            }

            sections.push(section);
        }

        Ok(Self {
            architecture,
            format_version,
            date_time_stamp,
            old_def_version,
            old_imp_version,
            current_version,
            section_count,
            inst_section_count,
            sections,
            loader_info,
        })
    }

    /// Whether the architecture is PowerPC.
    pub fn is_ppc(&self) -> bool {
        &self.architecture == ARCH_PPC
    }

    /// Whether the architecture is 68k.
    pub fn is_68k(&self) -> bool {
        &self.architecture == ARCH_68K
    }

    /// Return the architecture as a string.
    pub fn architecture_str(&self) -> &str {
        match &self.architecture {
            b"pwpc" => "PowerPC",
            b"m68k" => "Motorola 68k",
            _ => "Unknown",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// PefSectionHeader
// ═══════════════════════════════════════════════════════════════════════════════════

/// PEF section header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PefSectionHeader {
    /// Offset of name within the section name table (-1 = unnamed).
    pub name_offset: i32,
    /// Default address (affects relocations).
    pub default_address: u32,
    /// Fully expanded size in bytes of the section contents.
    pub total_length: u32,
    /// Size in bytes of the "initialized" part.
    pub unpacked_length: u32,
    /// Size in bytes of the raw data in the container.
    pub container_length: u32,
    /// Offset of the section's raw data.
    pub container_offset: u32,
    /// Kind of section contents/usage.
    pub section_kind: SectionKind,
    /// Sharing level.
    pub share_kind: SectionShareKind,
    /// Preferred alignment, expressed as log2.
    pub alignment: u8,
}

impl PefSectionHeader {
    /// Parse from big-endian bytes.
    pub fn parse_be(data: &[u8]) -> Self {
        Self {
            name_offset: i32::from_be_bytes([data[0], data[1], data[2], data[3]]),
            default_address: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            total_length: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            unpacked_length: u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
            container_length: u32::from_be_bytes([data[16], data[17], data[18], data[19]]),
            container_offset: u32::from_be_bytes([data[20], data[21], data[22], data[23]]),
            section_kind: SectionKind::from_u8(data[24]),
            share_kind: SectionShareKind::from_u8(data[25]),
            alignment: data[26],
        }
    }

    /// Whether this section is named.
    pub fn is_named(&self) -> bool {
        self.name_offset != NO_NAME_OFFSET
    }

    /// Whether this section has read permissions (always true).
    pub fn is_readable(&self) -> bool {
        true
    }

    /// Whether this section has write permissions.
    pub fn is_writable(&self) -> bool {
        matches!(
            self.section_kind,
            SectionKind::UnpackedData | SectionKind::PackedData | SectionKind::ExecutableData
        )
    }

    /// Whether this section has execute permissions.
    pub fn is_executable(&self) -> bool {
        matches!(
            self.section_kind,
            SectionKind::Code | SectionKind::ExecutableData
        )
    }

    /// Alignment in bytes (2^alignment).
    pub fn alignment_bytes(&self) -> u32 {
        1u32 << self.alignment
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// PefLoaderInfo
// ═══════════════════════════════════════════════════════════════════════════════════

/// PEF loader info header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PefLoaderInfo {
    /// Main section index.
    pub main_section: i32,
    /// Main offset within the section.
    pub main_offset: u32,
    /// Init section index.
    pub init_section: i32,
    /// Init offset within the section.
    pub init_offset: u32,
    /// Term section index.
    pub term_section: i32,
    /// Term offset within the section.
    pub term_offset: u32,
    /// Number of imported libraries.
    pub import_library_count: u32,
    /// Total imported symbols.
    pub total_imported_symbol_count: u32,
    /// Relocation section count.
    pub reloc_section_count: u32,
    /// Reloc instructions offset.
    pub reloc_instructions_offset: u32,
    /// Loader strings offset.
    pub loader_strings_offset: u32,
    /// Export hash offset.
    pub export_hash_offset: u32,
    /// Export hash table power (log2 of hash table size).
    pub export_hash_table_power: u32,
    /// Exported symbol count.
    pub exported_symbol_count: u32,
}

impl PefLoaderInfo {
    /// Parse from big-endian bytes.
    pub fn parse_be(data: &[u8], _length: usize) -> Result<Self, PefError> {
        if data.len() < LOADER_INFO_HEADER_SIZE {
            return Err(PefError::TruncatedLoaderInfo);
        }

        Ok(Self {
            main_section: i32::from_be_bytes([data[0], data[1], data[2], data[3]]),
            main_offset: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            init_section: i32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            init_offset: u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
            term_section: i32::from_be_bytes([data[16], data[17], data[18], data[19]]),
            term_offset: u32::from_be_bytes([data[20], data[21], data[22], data[23]]),
            import_library_count: u32::from_be_bytes([data[24], data[25], data[26], data[27]]),
            total_imported_symbol_count: u32::from_be_bytes([
                data[28], data[29], data[30], data[31],
            ]),
            reloc_section_count: u32::from_be_bytes([data[32], data[33], data[34], data[35]]),
            reloc_instructions_offset: u32::from_be_bytes([
                data[36], data[37], data[38], data[39],
            ]),
            loader_strings_offset: u32::from_be_bytes([data[40], data[41], data[42], data[43]]),
            export_hash_offset: u32::from_be_bytes([data[44], data[45], data[46], data[47]]),
            export_hash_table_power: u32::from_be_bytes([data[48], data[49], data[50], data[51]]),
            exported_symbol_count: u32::from_be_bytes([data[52], data[53], data[54], data[55]]),
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Packed Data Opcodes
// ═══════════════════════════════════════════════════════════════════════════════════

/// PEF packed data opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackedDataOpcode {
    /// Zero fill.
    Zero,
    /// Copy block.
    Block,
    /// Repeat block.
    Repeat,
    /// Repeat with common + custom blocks.
    RepeatBlock,
    /// Repeat with zero common + custom blocks.
    RepeatZero,
    /// Unknown opcode.
    Unknown(u8),
}

impl PackedDataOpcode {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::Zero,
            1 => Self::Block,
            2 => Self::Repeat,
            3 => Self::RepeatBlock,
            4 => Self::RepeatZero,
            other => Self::Unknown(other),
        }
    }
}

/// Unpack PEF packed data.
///
/// The packed data format uses a variable-length encoding for counts
/// and opcodes in the high 3 bits of the first byte.
pub fn unpack_pef_data(
    packed: &[u8],
    unpacked_length: usize,
) -> Result<Vec<u8>, PefError> {
    let mut output = vec![0u8; unpacked_length];
    let mut out_idx = 0;
    let mut in_idx = 0;

    while out_idx < unpacked_length && in_idx < packed.len() {
        let first_byte = packed[in_idx];
        in_idx += 1;

        let count_raw = (first_byte & 0x1F) as usize;
        let opcode = PackedDataOpcode::from_u8(first_byte >> 5);

        let count = if count_raw == 0 {
            let (val, new_idx) = unpack_next_value(packed, in_idx)?;
            in_idx = new_idx;
            val
        } else {
            count_raw
        };

        match opcode {
            PackedDataOpcode::Zero => {
                // Fill with zeros
                let fill = std::cmp::min(count, unpacked_length - out_idx);
                out_idx += fill;
            }
            PackedDataOpcode::Block => {
                // Copy raw bytes
                let copy_count = std::cmp::min(count, packed.len() - in_idx);
                let copy_count = std::cmp::min(copy_count, unpacked_length - out_idx);
                output[out_idx..out_idx + copy_count]
                    .copy_from_slice(&packed[in_idx..in_idx + copy_count]);
                in_idx += copy_count;
                out_idx += copy_count;
            }
            PackedDataOpcode::Repeat => {
                let (repeat_count, new_idx) = unpack_next_value(packed, in_idx)?;
                in_idx = new_idx;
                let copy_count = std::cmp::min(count, packed.len() - in_idx);
                let copy_count = std::cmp::min(copy_count, unpacked_length - out_idx);
                let pattern = &packed[in_idx..in_idx + copy_count];
                in_idx += copy_count;
                for _ in 0..=repeat_count {
                    let fill = std::cmp::min(pattern.len(), unpacked_length - out_idx);
                    output[out_idx..out_idx + fill].copy_from_slice(&pattern[..fill]);
                    out_idx += fill;
                }
            }
            PackedDataOpcode::RepeatBlock => {
                let common_size = count;
                let (custom_size, new_idx) = unpack_next_value(packed, in_idx)?;
                in_idx = new_idx;
                let (repeat_count, new_idx) = unpack_next_value(packed, in_idx)?;
                in_idx = new_idx;

                let common_copy = std::cmp::min(common_size, packed.len() - in_idx);
                let common_data = &packed[in_idx..in_idx + common_copy].to_vec();
                in_idx += common_copy;

                for _ in 0..repeat_count {
                    let fill = std::cmp::min(common_data.len(), unpacked_length - out_idx);
                    output[out_idx..out_idx + fill].copy_from_slice(&common_data[..fill]);
                    out_idx += fill;

                    let custom_copy = std::cmp::min(custom_size, packed.len() - in_idx);
                    let custom_copy = std::cmp::min(custom_copy, unpacked_length - out_idx);
                    output[out_idx..out_idx + custom_copy]
                        .copy_from_slice(&packed[in_idx..in_idx + custom_copy]);
                    in_idx += custom_copy;
                    out_idx += custom_copy;
                }
                // Final common data
                let fill = std::cmp::min(common_data.len(), unpacked_length - out_idx);
                if out_idx + fill <= unpacked_length {
                    output[out_idx..out_idx + fill].copy_from_slice(&common_data[..fill]);
                    out_idx += fill;
                }
            }
            PackedDataOpcode::RepeatZero => {
                let common_size = count;
                let (custom_size, new_idx) = unpack_next_value(packed, in_idx)?;
                in_idx = new_idx;
                let (repeat_count, new_idx) = unpack_next_value(packed, in_idx)?;
                in_idx = new_idx;

                for _ in 0..repeat_count {
                    out_idx += std::cmp::min(common_size, unpacked_length - out_idx);

                    let custom_copy = std::cmp::min(custom_size, packed.len() - in_idx);
                    let custom_copy = std::cmp::min(custom_copy, unpacked_length - out_idx);
                    output[out_idx..out_idx + custom_copy]
                        .copy_from_slice(&packed[in_idx..in_idx + custom_copy]);
                    in_idx += custom_copy;
                    out_idx += custom_copy;
                }
                out_idx += std::cmp::min(common_size, unpacked_length - out_idx);
            }
            PackedDataOpcode::Unknown(op) => {
                return Err(PefError::InvalidPackedOpcode(op));
            }
        }
    }

    Ok(output)
}

/// Unpack a variable-length value (7 bits per byte, high bit = continuation).
fn unpack_next_value(data: &[u8], mut pos: usize) -> Result<(usize, usize), PefError> {
    let mut value: usize = 0;
    loop {
        if pos >= data.len() {
            return Err(PefError::PackedDataError("unexpected end of data".to_string()));
        }
        value <<= 7;
        let byte = data[pos];
        value += (byte & 0x7F) as usize;
        pos += 1;
        if byte & 0x80 == 0 {
            break;
        }
    }
    Ok((value, pos))
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Utility
// ═══════════════════════════════════════════════════════════════════════════════════

/// Check if a byte slice starts with the PEF magic tags.
pub fn is_pef_file(data: &[u8]) -> bool {
    data.len() >= 8 && &data[0..4] == PEF_TAG1 && &data[4..8] == PEF_TAG2
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_pef(section_count: u16) -> Vec<u8> {
        let mut data = vec![0u8; CONTAINER_HEADER_SIZE + section_count as usize * SECTION_HEADER_SIZE];
        data[0..4].copy_from_slice(PEF_TAG1);
        data[4..8].copy_from_slice(PEF_TAG2);
        data[8..12].copy_from_slice(ARCH_PPC);
        data[12..16].copy_from_slice(&1u32.to_be_bytes()); // format version
        data[16..20].copy_from_slice(&0u32.to_be_bytes()); // timestamp
        data[20..24].copy_from_slice(&0u32.to_be_bytes()); // old def version
        data[24..28].copy_from_slice(&0u32.to_be_bytes()); // old imp version
        data[28..32].copy_from_slice(&0u32.to_be_bytes()); // current version
        data[32..34].copy_from_slice(&section_count.to_be_bytes());
        data[34..36].copy_from_slice(&section_count.to_be_bytes()); // inst section count
        data
    }

    #[test]
    fn test_parse_container_header() {
        let data = make_minimal_pef(0);
        let header = PefContainerHeader::parse(&data).unwrap();
        assert!(header.is_ppc());
        assert!(!header.is_68k());
        assert_eq!(header.format_version, 1);
        assert_eq!(header.section_count, 0);
        assert_eq!(header.architecture_str(), "PowerPC");
    }

    #[test]
    fn test_invalid_tags() {
        let mut data = make_minimal_pef(0);
        data[0] = b'X';
        assert_eq!(PefContainerHeader::parse(&data), Err(PefError::InvalidTags));
    }

    #[test]
    fn test_invalid_architecture() {
        let mut data = make_minimal_pef(0);
        data[8..12].copy_from_slice(b"xxxx");
        assert!(matches!(
            PefContainerHeader::parse(&data),
            Err(PefError::InvalidArchitecture(_))
        ));
    }

    #[test]
    fn test_too_short() {
        assert_eq!(
            PefContainerHeader::parse(&[0u8; 10]),
            Err(PefError::TooShort)
        );
    }

    #[test]
    fn test_is_pef_file() {
        let data = make_minimal_pef(0);
        assert!(is_pef_file(&data));
        assert!(!is_pef_file(b"not a pef"));
        assert!(!is_pef_file(&[0u8; 4]));
    }

    #[test]
    fn test_parse_section_header() {
        let mut sec_data = vec![0u8; SECTION_HEADER_SIZE];
        // name_offset = -1 (unnamed)
        sec_data[0..4].copy_from_slice(&(-1i32).to_be_bytes());
        // default_address
        sec_data[4..8].copy_from_slice(&0x1000u32.to_be_bytes());
        // total_length
        sec_data[8..12].copy_from_slice(&0x2000u32.to_be_bytes());
        // unpacked_length
        sec_data[12..16].copy_from_slice(&0x1000u32.to_be_bytes());
        // container_length
        sec_data[16..20].copy_from_slice(&0x800u32.to_be_bytes());
        // container_offset
        sec_data[20..24].copy_from_slice(&0x100u32.to_be_bytes());
        // section kind = Code
        sec_data[24] = 0;
        // share kind = ProcessShare
        sec_data[25] = 0;
        // alignment = 4 (16-byte aligned)
        sec_data[26] = 4;

        let section = PefSectionHeader::parse_be(&sec_data);
        assert!(!section.is_named());
        assert_eq!(section.default_address, 0x1000);
        assert_eq!(section.total_length, 0x2000);
        assert_eq!(section.section_kind, SectionKind::Code);
        assert!(section.is_executable());
        assert!(!section.is_writable());
        assert_eq!(section.alignment_bytes(), 16);
    }

    #[test]
    fn test_section_kind_from_u8() {
        assert_eq!(SectionKind::from_u8(0), SectionKind::Code);
        assert_eq!(SectionKind::from_u8(1), SectionKind::UnpackedData);
        assert_eq!(SectionKind::from_u8(2), SectionKind::PackedData);
        assert_eq!(SectionKind::from_u8(3), SectionKind::Constant);
        assert_eq!(SectionKind::from_u8(4), SectionKind::Loader);
        assert_eq!(SectionKind::from_u8(6), SectionKind::ExecutableData);
        assert_eq!(SectionKind::from_u8(255), SectionKind::Unknown(255));
    }

    #[test]
    fn test_section_kind_display() {
        assert_eq!(SectionKind::Code.to_string(), "code");
        assert_eq!(SectionKind::Loader.to_string(), "loader");
    }

    #[test]
    fn test_section_permissions() {
        // Code section
        let code = PefSectionHeader {
            name_offset: -1,
            default_address: 0,
            total_length: 0,
            unpacked_length: 0,
            container_length: 0,
            container_offset: 0,
            section_kind: SectionKind::Code,
            share_kind: SectionShareKind::ProcessShare,
            alignment: 0,
        };
        assert!(code.is_executable());
        assert!(!code.is_writable());
        assert!(code.is_readable());

        // Data section
        let data = PefSectionHeader {
            section_kind: SectionKind::UnpackedData,
            ..code.clone()
        };
        assert!(!data.is_executable());
        assert!(data.is_writable());
    }

    #[test]
    fn test_parse_with_sections() {
        let mut data = make_minimal_pef(2);

        // Section 0: Code
        let off = CONTAINER_HEADER_SIZE;
        data[off + 0..off + 4].copy_from_slice(&(-1i32).to_be_bytes()); // unnamed
        data[off + 4..off + 8].copy_from_slice(&0x1000u32.to_be_bytes()); // default addr
        data[off + 8..off + 12].copy_from_slice(&0x1000u32.to_be_bytes()); // total length
        data[off + 12..off + 16].copy_from_slice(&0x1000u32.to_be_bytes()); // unpacked
        data[off + 16..off + 20].copy_from_slice(&0x800u32.to_be_bytes()); // container length
        data[off + 20..off + 24].copy_from_slice(&0x100u32.to_be_bytes()); // container offset
        data[off + 24] = 0; // Code

        // Section 1: Constant
        let off = CONTAINER_HEADER_SIZE + SECTION_HEADER_SIZE;
        data[off + 0..off + 4].copy_from_slice(&(-1i32).to_be_bytes());
        data[off + 4..off + 8].copy_from_slice(&0x2000u32.to_be_bytes());
        data[off + 8..off + 12].copy_from_slice(&0x500u32.to_be_bytes());
        data[off + 12..off + 16].copy_from_slice(&0x500u32.to_be_bytes());
        data[off + 16..off + 20].copy_from_slice(&0x400u32.to_be_bytes());
        data[off + 20..off + 24].copy_from_slice(&0x900u32.to_be_bytes());
        data[off + 24] = 3; // Constant

        let header = PefContainerHeader::parse(&data).unwrap();
        assert_eq!(header.sections.len(), 2);
        assert_eq!(header.sections[0].section_kind, SectionKind::Code);
        assert_eq!(header.sections[1].section_kind, SectionKind::Constant);
    }

    #[test]
    fn test_68k_architecture() {
        let mut data = make_minimal_pef(0);
        data[8..12].copy_from_slice(ARCH_68K);
        let header = PefContainerHeader::parse(&data).unwrap();
        assert!(header.is_68k());
        assert!(!header.is_ppc());
        assert_eq!(header.architecture_str(), "Motorola 68k");
    }

    #[test]
    fn test_unpack_pef_zero() {
        // Opcode 0 (Zero), count 5
        let packed = vec![0x05]; // 000_00101 = Zero, count 5
        let result = unpack_pef_data(&packed, 5).unwrap();
        assert_eq!(result, vec![0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_unpack_pef_block() {
        // Opcode 1 (Block), count 3, followed by 3 data bytes
        let packed = vec![0x23, 0xAA, 0xBB, 0xCC]; // 001_00011 = Block, count 3
        let result = unpack_pef_data(&packed, 3).unwrap();
        assert_eq!(result, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_unpack_pef_repeat() {
        // Opcode 2 (Repeat), count 2, data=AB, repeat_count=1 (total 2 repetitions)
        let packed = vec![0x42, 0x01, 0x41, 0x42]; // Repeat, count 2, repeat=1, data "AB"
        let result = unpack_pef_data(&packed, 4).unwrap();
        assert_eq!(result, vec![0x41, 0x42, 0x41, 0x42]);
    }

    #[test]
    fn test_unpack_next_value() {
        // Single byte: 0x42 = 66
        let (val, pos) = unpack_next_value(&[0x42], 0).unwrap();
        assert_eq!(val, 66);
        assert_eq!(pos, 1);

        // Two bytes: 0x81 0x02 = (1 << 7) + 2 = 130
        let (val, pos) = unpack_next_value(&[0x81, 0x02], 0).unwrap();
        assert_eq!(val, 130);
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_pef_loader_info_parse() {
        let mut data = vec![0u8; LOADER_INFO_HEADER_SIZE];
        // main_section = 0
        data[0..4].copy_from_slice(&0i32.to_be_bytes());
        // main_offset = 0x100
        data[4..8].copy_from_slice(&0x100u32.to_be_bytes());
        // init_section = -1 (none)
        data[8..12].copy_from_slice(&(-1i32).to_be_bytes());
        // init_offset = 0
        data[12..16].copy_from_slice(&0u32.to_be_bytes());
        // term_section = -1 (none)
        data[16..20].copy_from_slice(&(-1i32).to_be_bytes());
        // term_offset = 0
        data[20..24].copy_from_slice(&0u32.to_be_bytes());
        // import_library_count = 1
        data[24..28].copy_from_slice(&1u32.to_be_bytes());
        // total_imported_symbol_count = 5
        data[28..32].copy_from_slice(&5u32.to_be_bytes());
        // reloc_section_count = 1
        data[32..36].copy_from_slice(&1u32.to_be_bytes());
        // reloc_instructions_offset = 0x200
        data[36..40].copy_from_slice(&0x200u32.to_be_bytes());
        // loader_strings_offset = 0x300
        data[40..44].copy_from_slice(&0x300u32.to_be_bytes());
        // export_hash_offset = 0x400
        data[44..48].copy_from_slice(&0x400u32.to_be_bytes());
        // export_hash_table_power = 4
        data[48..52].copy_from_slice(&4u32.to_be_bytes());
        // exported_symbol_count = 10
        data[52..56].copy_from_slice(&10u32.to_be_bytes());

        let info = PefLoaderInfo::parse_be(&data, LOADER_INFO_HEADER_SIZE).unwrap();
        assert_eq!(info.main_section, 0);
        assert_eq!(info.main_offset, 0x100);
        assert_eq!(info.init_section, -1);
        assert_eq!(info.import_library_count, 1);
        assert_eq!(info.total_imported_symbol_count, 5);
        assert_eq!(info.exported_symbol_count, 10);
    }

    #[test]
    fn test_share_kind() {
        assert_eq!(SectionShareKind::from_u8(0), SectionShareKind::ProcessShare);
        assert_eq!(SectionShareKind::from_u8(1), SectionShareKind::GlobalShare);
        assert_eq!(SectionShareKind::from_u8(4), SectionShareKind::ProtectedShare);
        assert!(matches!(
            SectionShareKind::from_u8(255),
            SectionShareKind::Unknown(255)
        ));
    }

    #[test]
    fn test_section_count_zero() {
        let data = make_minimal_pef(0);
        let header = PefContainerHeader::parse(&data).unwrap();
        assert!(header.sections.is_empty());
        assert!(header.loader_info.is_none());
    }
}
