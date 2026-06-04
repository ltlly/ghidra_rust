//! Debug information: C13 line numbers, file checksums, section headers,
//! image function entries, and debug data streams.
//! Ported from Ghidra's C13FileChecksum, C13FileRecord, C13LineRecord,
//! C13ColumnRecord, C13ChecksumType, C13Type, ImageSectionHeader,
//! ImageFunctionEntry, and DebugData Java classes.

use super::le_u32_at;

// =============================================================================
// C13 Checksum Types
// =============================================================================

/// C13 file checksum types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum C13ChecksumType {
    None = 0x00,
    Md5 = 0x01,
    Sha1 = 0x02,
    Sha256 = 0x03,
    Unknown(u8),
}

impl C13ChecksumType {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0x00 => Self::None,
            0x01 => Self::Md5,
            0x02 => Self::Sha1,
            0x03 => Self::Sha256,
            v => Self::Unknown(v),
        }
    }
}

// =============================================================================
// C13 File Checksum
// =============================================================================

/// A single C13 file checksum record.
/// Ported from C13FileChecksum.java.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct C13FileChecksum {
    /// Offset of the filename within the filename list.
    pub offset_filename: u32,
    /// Number of bytes of the checksum.
    pub length: u8,
    /// Checksum type.
    pub checksum_type: C13ChecksumType,
    /// The raw checksum bytes.
    pub bytes: Vec<u8>,
}

impl C13FileChecksum {
    /// Base record size before checksum bytes.
    pub const BASE_SIZE: usize = 6;

    /// Parse a C13FileChecksum from a byte slice.
    /// Returns (parsed, bytes_consumed).
    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 6 { return None; }
        let offset_filename = le_u32_at(data, 0);
        let length = data[4];
        let checksum_type = C13ChecksumType::from_u8(data[5]);
        let end = 6 + length as usize;
        if data.len() < end { return None; }
        let bytes = data[6..end].to_vec();
        // Align to 4 bytes
        let consumed = (end + 3) & !3;
        Some((Self { offset_filename, length, checksum_type, bytes }, consumed))
    }
}

// =============================================================================
// C13 Column Record
// =============================================================================

/// C13 column record, optionally present in line records.
/// Ported from C13ColumnRecord.java.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct C13ColumnRecord {
    pub start_column: u16,
    pub end_column: u16,
}

impl C13ColumnRecord {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 { return None; }
        Some(Self {
            start_column: u16::from_le_bytes([data[0], data[1]]),
            end_column: u16::from_le_bytes([data[2], data[3]]),
        })
    }
}

// =============================================================================
// C13 Line Record
// =============================================================================

/// A C13 line record within a file record.
/// Ported from C13LineRecord.java.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct C13LineRecord {
    /// Offset within the segment for this line.
    pub offset: u32,
    /// Raw bit values containing line number info.
    pub bit_vals: u32,
    /// Optional column record.
    pub column: Option<C13ColumnRecord>,
}

impl C13LineRecord {
    /// Line number start (lower 24 bits).
    pub fn line_num_start(&self) -> u32 {
        self.bit_vals & 0x00FF_FFFF
    }

    /// Delta between line number start and end (bits 24..30).
    pub fn delta_line_end(&self) -> u32 {
        (self.bit_vals >> 24) & 0x7F
    }

    /// Line number end.
    pub fn line_num_end(&self) -> u32 {
        self.line_num_start() + self.delta_line_end()
    }

    /// True if this record represents a statement (vs. expression).
    pub fn is_statement(&self) -> bool {
        (self.bit_vals & 0x8000_0000) != 0
    }

    /// True if this is a special line (0xFEFEFE or 0xF00F00).
    pub fn is_special_line(&self) -> bool {
        let start = self.line_num_start();
        start == 0xFEFEFE || start == 0xF00F00
    }

    /// Parse a C13LineRecord.
    /// data: 8 bytes for offset + bitVals, optional 4 bytes for column.
    pub fn parse(data: &[u8], has_column: bool) -> Option<Self> {
        if data.len() < 8 { return None; }
        let offset = le_u32_at(data, 0);
        let bit_vals = le_u32_at(data, 4);
        let column = if has_column && data.len() >= 12 {
            C13ColumnRecord::parse(&data[8..])
        } else {
            None
        };
        Some(Self { offset, bit_vals, column })
    }
}

// =============================================================================
// C13 File Record
// =============================================================================

/// A C13 file record containing line records for one source file.
/// Ported from C13FileRecord.java.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct C13FileRecord {
    /// File ID (offset into file name table).
    pub file_id: u32,
    /// Number of line records.
    pub n_lines: u32,
    /// Length of this file block in bytes (including header).
    pub len_file_block: u32,
    /// The line records.
    pub line_records: Vec<C13LineRecord>,
}

impl C13FileRecord {
    /// Parse a C13FileRecord from a byte slice.
    /// Returns (parsed, bytes_consumed).
    pub fn parse(data: &[u8], has_column: bool) -> Option<(Self, usize)> {
        if data.len() < 12 { return None; }
        let file_id = le_u32_at(data, 0);
        let n_lines = le_u32_at(data, 4);
        let len_file_block = le_u32_at(data, 8);
        let n_lines_usize = n_lines as usize;
        let size_lines = n_lines_usize * 8;
        let size_columns = if has_column { n_lines_usize * 4 } else { 0 };
        let total_size = 12 + size_lines + size_columns;
        if data.len() < total_size { return None; }
        let mut line_records = Vec::with_capacity(n_lines_usize);
        let line_base = 12;
        for i in 0..n_lines_usize {
            let off = line_base + i * 8;
            let col_off = line_base + size_lines + i * 4;
            let lr_data = if has_column && col_off + 4 <= data.len() {
                &data[off..col_off + 4]
            } else {
                &data[off..off + 8]
            };
            if let Some(lr) = C13LineRecord::parse(lr_data, has_column) {
                line_records.push(lr);
            }
        }
        let consumed = len_file_block as usize;
        Some((Self { file_id, n_lines, len_file_block, line_records }, consumed))
    }
}

// =============================================================================
// C13 Section Types (debug subsection types)
// =============================================================================

/// C13 subsection type IDs.
/// Ported from C13Type.java.
pub mod c13_type {
    pub const SYMBOLS: u32 = 0xF1;
    pub const LINES: u32 = 0xF2;
    pub const STRING_TABLE: u32 = 0xF3;
    pub const FILE_CHKSMS: u32 = 0xF4;
    pub const FRAMEDATA: u32 = 0xF5;
    pub const INLINEE_LINES: u32 = 0xF6;
    pub const CROSS_SCOPE_IMPORTS: u32 = 0xF7;
    pub const CROSS_SCOPE_EXPORTS: u32 = 0xF8;
    pub const IL_LINES: u32 = 0xF9;
    pub const FUNC_MDTOKEN_MAP: u32 = 0xFA;
    pub const TYPE_MDTOKEN_MAP: u32 = 0xFB;
    pub const MERGED_ASSEMBLY_INPUT: u32 = 0xFC;
    pub const COFF_SYMBOL_RVA: u32 = 0xFD;
    pub const IGNORE: u32 = 0x8000_0000;
}

// =============================================================================
// C13 Line Subsection
// =============================================================================

/// A C13 lines subsection, containing file records with line information.
/// This corresponds to the LINES (0xF2) subsection type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct C13LinesSubsection {
    /// The section contribution index.
    pub contribution_index: u32,
    /// File checksums offset into the file checksums buffer.
    pub file_checksums_offset: u16,
    /// Number of file checksums.
    pub num_file_checksums: u16,
    /// Block size of line information.
    pub block_size: u32,
    /// Whether column information is present.
    pub has_column: bool,
    /// The file records.
    pub file_records: Vec<C13FileRecord>,
}

impl C13LinesSubsection {
    /// Parse a C13 lines subsection from the payload (after type ID and size).
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 12 { return None; }
        let contribution_index = le_u32_at(data, 0);
        let file_checksums_offset = u16::from_le_bytes([data[4], data[5]]);
        let num_file_checksums = u16::from_le_bytes([data[6], data[7]]);
        let block_size = le_u32_at(data, 8);
        // has_column flag is embedded in the block_size or contribution flags
        // For simplicity, detect from signature
        let has_column = false; // typically set by caller
        let mut pos = 12usize;
        let mut file_records = Vec::new();
        while pos + 12 <= data.len() {
            match C13FileRecord::parse(&data[pos..], has_column) {
                Some((fr, consumed)) => {
                    if consumed == 0 { break; }
                    pos += consumed;
                    file_records.push(fr);
                }
                None => break,
            }
        }
        Some(Self { contribution_index, file_checksums_offset, num_file_checksums, block_size, has_column, file_records })
    }
}

// =============================================================================
// Image Section Header
// =============================================================================

/// COFF Image Section Header, parsed from the section header debug stream.
/// Ported from ImageSectionHeader.java.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageSectionHeader {
    /// Section name (8 bytes, null-padded).
    pub name: String,
    /// Physical address / virtual size (union field).
    pub physical_address_virtual_size: u32,
    /// Virtual address of the section.
    pub virtual_address: u32,
    /// Size of raw data.
    pub raw_data_size: u32,
    /// Pointer to raw data.
    pub raw_data_pointer: u32,
    /// Pointer to relocations.
    pub relocations_pointer: u32,
    /// Pointer to line numbers.
    pub line_numbers_pointer: u32,
    /// Number of relocations.
    pub num_relocations: u16,
    /// Number of line numbers.
    pub num_line_numbers: u16,
    /// Section characteristics flags.
    pub characteristics: u32,
}

impl ImageSectionHeader {
    /// Size of a single IMAGE_SECTION_HEADER in bytes.
    pub const SIZE: usize = 40;

    /// Parse a single IMAGE_SECTION_HEADER.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE { return None; }
        let name_end = data[..8].iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&data[..name_end]).to_string();
        Some(Self {
            name,
            physical_address_virtual_size: le_u32_at(data, 8),
            virtual_address: le_u32_at(data, 12),
            raw_data_size: le_u32_at(data, 16),
            raw_data_pointer: le_u32_at(data, 20),
            relocations_pointer: le_u32_at(data, 24),
            line_numbers_pointer: le_u32_at(data, 28),
            num_relocations: u16::from_le_bytes([data[32], data[33]]),
            num_line_numbers: u16::from_le_bytes([data[34], data[35]]),
            characteristics: le_u32_at(data, 36),
        })
    }

    /// Parse all IMAGE_SECTION_HEADERs from a stream.
    pub fn parse_all(data: &[u8]) -> Vec<Self> {
        let mut headers = Vec::new();
        let mut pos = 0usize;
        while pos + Self::SIZE <= data.len() {
            if let Some(h) = Self::parse(&data[pos..]) {
                headers.push(h);
            }
            pos += Self::SIZE;
        }
        headers
    }
}

// =============================================================================
// Image Function Entry (PData)
// =============================================================================

/// Image function entry (from PData debug stream).
/// Ported from ImageFunctionEntry.java.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageFunctionEntry {
    pub starting_address: u32,
    pub ending_address: u32,
    pub end_of_prologue_address: u32,
}

impl ImageFunctionEntry {
    pub const SIZE: usize = 12;

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE { return None; }
        Some(Self {
            starting_address: le_u32_at(data, 0),
            ending_address: le_u32_at(data, 4),
            end_of_prologue_address: le_u32_at(data, 8),
        })
    }

    /// Parse all function entries from a stream.
    pub fn parse_all(data: &[u8]) -> Vec<Self> {
        let mut entries = Vec::new();
        let mut pos = 0usize;
        while pos + Self::SIZE <= data.len() {
            if let Some(e) = Self::parse(&data[pos..]) {
                entries.push(e);
            }
            pos += Self::SIZE;
        }
        entries
    }
}

// =============================================================================
// Debug Data Stream Types
// =============================================================================

/// Debug stream types, as referenced by the DBI debug header.
/// Ported from DebugData.DebugType enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DebugType {
    FramePointerOmission = 0,
    Exception = 1,
    Fixup = 2,
    OmapToSrc = 3,
    OmapFromSrc = 4,
    SectionHeader = 5,
    TokenRidMap = 6,
    XData = 7,
    PData = 8,
    NewFramePointerOmission = 9,
    SectionHeaderOrig = 10,
    Unknown(u8),
}

impl DebugType {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::FramePointerOmission,
            1 => Self::Exception,
            2 => Self::Fixup,
            3 => Self::OmapToSrc,
            4 => Self::OmapFromSrc,
            5 => Self::SectionHeader,
            6 => Self::TokenRidMap,
            7 => Self::XData,
            8 => Self::PData,
            9 => Self::NewFramePointerOmission,
            10 => Self::SectionHeaderOrig,
            v => Self::Unknown(v),
        }
    }

    /// Return the integer value for indexing into the debug_streams vector.
    pub fn value(&self) -> usize {
        match self {
            Self::FramePointerOmission => 0,
            Self::Exception => 1,
            Self::Fixup => 2,
            Self::OmapToSrc => 3,
            Self::OmapFromSrc => 4,
            Self::SectionHeader => 5,
            Self::TokenRidMap => 6,
            Self::XData => 7,
            Self::PData => 8,
            Self::NewFramePointerOmission => 9,
            Self::SectionHeaderOrig => 10,
            Self::Unknown(v) => *v as usize,
        }
    }
}

/// Parsed debug data from the optional debug header stream.
#[derive(Debug, Clone)]
pub struct DebugData {
    /// Stream numbers for each debug type.
    pub debug_streams: Vec<u32>,
}

impl DebugData {
    /// Parse the debug data header from raw bytes.
    /// Each entry is a 2-byte stream number. The order matches DebugType indices.
    pub fn parse_header(data: &[u8]) -> Self {
        let mut streams = Vec::new();
        let mut pos = 0usize;
        while pos + 2 <= data.len() {
            let sn = u16::from_le_bytes([data[pos], data[pos + 1]]) as u32;
            streams.push(sn);
            pos += 2;
        }
        DebugData { debug_streams: streams }
    }

    /// Get the stream number for a specific debug type.
    pub fn get_stream(&self, dt: DebugType) -> Option<u32> {
        let idx = dt.value();
        self.debug_streams.get(idx).copied().filter(|&s| s != 0xFFFF)
    }
}

// =============================================================================
// Frame Pointer Omission Record
// =============================================================================

/// Frame pointer omission record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FramePointerOmissionRecord {
    pub frame_pointer_offset: u32,
    pub frame_pointer_register: u16,
}

impl FramePointerOmissionRecord {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 6 { return None; }
        Some(Self {
            frame_pointer_offset: le_u32_at(data, 0),
            frame_pointer_register: u16::from_le_bytes([data[4], data[5]]),
        })
    }
}

// =============================================================================
// OMAP Record
// =============================================================================

/// OMAP mapping record (RVA to RVA remapping).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OmapEntry {
    pub source_rva: u32,
    pub target_rva: u32,
}

impl OmapEntry {
    pub const SIZE: usize = 8;

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE { return None; }
        Some(Self {
            source_rva: le_u32_at(data, 0),
            target_rva: le_u32_at(data, 4),
        })
    }

    /// Parse all OMAP entries from a stream.
    pub fn parse_all(data: &[u8]) -> Vec<Self> {
        let mut entries = Vec::new();
        let mut pos = 0usize;
        while pos + Self::SIZE <= data.len() {
            if let Some(e) = Self::parse(&data[pos..]) {
                entries.push(e);
            }
            pos += Self::SIZE;
        }
        entries
    }
}
