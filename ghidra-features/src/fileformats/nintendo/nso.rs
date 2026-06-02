//! Nintendo Switch NSO / NRO executable format.
//!
//! The Nintendo Switch uses two executable container formats:
//!
//! - **NSO** (Nintendo Switch Object) -- the "main" static executable.  NSO
//!   files are typically embedded inside an NPDM meta NCAs and loaded directly
//!   by the kernel.
//!
//! - **NRO** (Nintendo Relocatable Object) -- a dynamically loadable module
//!   used for sysmodules, homebrew, and user-process overlays.  NRO files are
//!   loaded by `ro` (the Loader service) at runtime and support a richer set of
//!   metadata sections (asset header, module name, API info, etc.).
//!
//! # NSO header layout (0x100 bytes)
//!
//! | Offset | Size | Field              |
//! |--------|------|--------------------|
//! | 0x00   | 4    | magic ("NSO0")     |
//! | 0x04   | 4    | version            |
//! | 0x08   | 4    | reserved           |
//! | 0x0C   | 4    | flags              |
//! | 0x10   | 4    | text_offset        |
//! | 0x14   | 4    | text_size          |
//! | 0x18   | 4    | text_file_size     |
//! | 0x1C   | 4    | text_memory_size   |
//! | 0x20   | 4    | rodata_offset      |
//! | 0x24   | 4    | rodata_size        |
//! | 0x28   | 4    | rodata_file_size   |
//! | 0x2C   | 4    | rodata_memory_size |
//! | 0x30   | 4    | data_offset        |
//! | 0x34   | 4    | data_size          |
//! | 0x38   | 4    | data_file_size     |
//! | 0x3C   | 4    | bss_size           |
//! | 0x40   | 32   | module_id          |
//! | 0x60   | 32   | text_hash          |
//! | 0x80   | 32   | rodata_hash        |
//! | 0xA0   | 32   | data_hash          |
//!
//! # NRO header layout (0x100 bytes)
//!
//! | Offset | Size | Field              |
//! |--------|------|--------------------|
//! | 0x00   | 4    | magic ("NRO0")     |
//! | 0x04   | 4    | version            |
//! | 0x08   | 4    | nro_size           |
//! | 0x0C   | 4    | flags              |
//! | 0x10   | 4    | text_offset        |
//! | 0x14   | 4    | text_size          |
//! | 0x18   | 4    | rodata_offset      |
//! | 0x1C   | 4    | rodata_size        |
//! | 0x20   | 4    | data_offset        |
//! | 0x24   | 4    | data_size          |
//! | 0x28   | 4    | bss_size           |
//! | 0x2C   | 4    | reserved           |
//! | 0x30   | 32   | build_id           |
//! | 0x50   | 32   | text_hash          |
//! | 0x70   | 32   | rodata_hash        |
//! | 0x90   | 32   | data_hash          |
//! | 0xC0   | 32   | module_name (NRO-specific extension) |
//!
//! References:
//! - [Switchbrew: NSO](https://switchbrew.org/wiki/NSO)
//! - [Switchbrew: NRO](https://switchbrew.org/wiki/NRO)
//! - [Atmosphere-libs: ldr_nso.hpp](https://github.com/Atmosphere-NX/Atmosphere)
//! - Ghidra's `ghidra.app.util.bin.format.nso` package

// ===========================================================================
// Imports
// ===========================================================================

use std::fmt;

use nom::{
    bytes::complete::take,
    combinator::{map, verify},
    multi::count,
    number::complete::{le_u32, le_u64, le_u8},
    sequence::tuple,
    IResult, Parser,
};

// ===========================================================================
// Error Types
// ===========================================================================

/// NSO / NRO parse error.
#[derive(Debug, Clone)]
pub enum NsoError {
    /// Magic bytes did not match "NSO0" or "NRO0".
    InvalidMagic,
    /// Buffer is too small for the header (at least 0x100 bytes required).
    TruncatedData,
    /// An or-ed flag combination is not valid for this format.
    InvalidFlags,
    /// A segment offset points beyond the file bounds.
    SegmentOffsetOutOfBounds,
    /// A nom parse error.
    ParseError(String),
}

impl fmt::Display for NsoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "invalid NSO/NRO magic (expected NSO0 or NRO0)"),
            Self::TruncatedData => write!(f, "truncated NSO/NRO data"),
            Self::InvalidFlags => write!(f, "invalid NSO/NRO flags"),
            Self::SegmentOffsetOutOfBounds => write!(f, "segment offset out of bounds"),
            Self::ParseError(s) => write!(f, "parse error: {s}"),
        }
    }
}

impl std::error::Error for NsoError {}

impl<T> From<nom::Err<nom::error::Error<T>>> for NsoError {
    fn from(e: nom::Err<nom::error::Error<T>>) -> Self {
        Self::ParseError(format!("{e:?}"))
    }
}

/// Type alias for NSO/NRO results.
pub type NsoResult<T> = Result<T, NsoError>;

// ===========================================================================
// Constants
// ===========================================================================

/// Magic bytes for NSO files.
pub const NSO_MAGIC: [u8; 4] = *b"NSO0";

/// Magic bytes for NRO files.
pub const NRO_MAGIC: [u8; 4] = *b"NRO0";

/// Size of the NSO/NRO header in bytes.
pub const NSO_HEADER_SIZE: usize = 0x100;

/// Size of module_id / build_id fields.
pub const MODULE_ID_SIZE: usize = 32;

/// Size of hash fields (SHA-256).
pub const HASH_SIZE: usize = 32;

/// Maximum permissible size for a segment (256 MiB) -- sanity check.
const MAX_SEGMENT_SIZE: u32 = 256 * 1024 * 1024;

// ── NSO flags ──────────────────────────────────────────────────────────

/// Text section is compressed (LZ4).
pub const NSO_FLAG_TEXT_COMPRESS: u32 = 1 << 0;
/// Rodata section is compressed (LZ4).
pub const NSO_FLAG_RODATA_COMPRESS: u32 = 1 << 1;
/// Data section is compressed (LZ4).
pub const NSO_FLAG_DATA_COMPRESS: u32 = 1 << 2;
/// Check text section hash against the embedded hash.
pub const NSO_FLAG_TEXT_HASH: u32 = 1 << 3;
/// Check rodata section hash.
pub const NSO_FLAG_RODATA_HASH: u32 = 1 << 4;
/// Check data section hash.
pub const NSO_FLAG_DATA_HASH: u32 = 1 << 5;
/// All known flag bits for NSO.
pub const NSO_FLAG_KNOWN_MASK: u32 = 0x3F;

// ── NRO flags ──────────────────────────────────────────────────────────

/// NRO has an embedded asset header.
pub const NRO_FLAG_HAS_ASSET_HEADER: u32 = 1 << 0;
/// NRO has embedded module name.
pub const NRO_FLAG_HAS_MODULE_NAME: u32 = 1 << 1;
/// All known flag bits for NRO.
pub const NRO_FLAG_KNOWN_MASK: u32 = 0x03;

/// Human-readable flag descriptions for NSO.
pub fn nso_flag_names(flags: u32) -> Vec<&'static str> {
    let mut v = Vec::new();
    if flags & NSO_FLAG_TEXT_COMPRESS != 0 {
        v.push("TEXT_COMPRESS");
    }
    if flags & NSO_FLAG_RODATA_COMPRESS != 0 {
        v.push("RODATA_COMPRESS");
    }
    if flags & NSO_FLAG_DATA_COMPRESS != 0 {
        v.push("DATA_COMPRESS");
    }
    if flags & NSO_FLAG_TEXT_HASH != 0 {
        v.push("TEXT_HASH");
    }
    if flags & NSO_FLAG_RODATA_HASH != 0 {
        v.push("RODATA_HASH");
    }
    if flags & NSO_FLAG_DATA_HASH != 0 {
        v.push("DATA_HASH");
    }
    v
}

/// Human-readable flag descriptions for NRO.
pub fn nro_flag_names(flags: u32) -> Vec<&'static str> {
    let mut v = Vec::new();
    if flags & NRO_FLAG_HAS_ASSET_HEADER != 0 {
        v.push("HAS_ASSET_HEADER");
    }
    if flags & NRO_FLAG_HAS_MODULE_NAME != 0 {
        v.push("HAS_MODULE_NAME");
    }
    v
}

// ===========================================================================
// Structured Types
// ===========================================================================

/// NSO segment kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NsoSegmentKind {
    /// .text (executable code).
    Text,
    /// .rodata (read-only data).
    Rodata,
    /// .data (read-write data).
    Data,
    /// .bss (zero-initialised, no file content).
    Bss,
}

impl fmt::Display for NsoSegmentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text => write!(f, "text"),
            Self::Rodata => write!(f, "rodata"),
            Self::Data => write!(f, "data"),
            Self::Bss => write!(f, "bss"),
        }
    }
}

/// Whether the file is an NSO or an NRO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NsoFileKind {
    /// Static linked executable (NSO).
    Nso,
    /// Relocatable module (NRO).
    Nro,
}

/// A segment described by the NSO/NRO header.
#[derive(Debug, Clone)]
pub struct NsoSegment {
    /// File offset of the segment.
    pub offset: u32,
    /// Size of the segment in memory.
    pub memory_size: u32,
    /// Size of the segment on disk (may differ for BSS and compressed).
    pub file_size: u32,
    /// Segment kind.
    pub kind: NsoSegmentKind,
    /// SHA-256 hash of the segment (when available).
    pub hash: [u8; HASH_SIZE],
    /// Raw segment data (empty for BSS).
    pub data: Vec<u8>,
    /// Whether this segment is compressed (LZ4 for NSO).
    pub compressed: bool,
}

impl NsoSegment {
    /// Returns true if this segment has file content.
    pub fn has_file_content(&self) -> bool {
        self.offset != 0 && self.file_size != 0
    }

    /// Data size on disk (accounting for compression).
    pub fn on_disk_size(&self) -> u32 {
        if self.compressed {
            self.file_size
        } else {
            self.memory_size
        }
    }
}

/// NSO/NRO module_name asset header (NRO only).
///
/// Describes embedded assets (icons, NACP data, etc.).
#[derive(Debug, Clone)]
pub struct NroAssetHeader {
    /// Magic "ASET".
    pub magic: [u8; 4],
    /// Version.
    pub version: u32,
    /// Offset of the embedded icon (JPEG).
    pub icon_offset: u32,
    /// Size of the icon.
    pub icon_size: u32,
    /// Offset of the embedded NACP XML.
    pub nacp_offset: u32,
    /// Size of the NACP XML.
    pub nacp_size: u32,
}

/// A fully parsed NSO or NRO file.
#[derive(Debug, Clone)]
pub struct NsoFile {
    /// NSO or NRO.
    pub kind: NsoFileKind,
    /// Raw magic bytes.
    pub magic: [u8; 4],
    /// Format version.
    pub version: u32,
    /// Flags (compression, hashing, extras).
    pub flags: u32,
    /// Module / build ID.
    pub module_id: [u8; MODULE_ID_SIZE],
    /// Segments: text, rodata, data, and optionally bss.
    pub segments: Vec<NsoSegment>,
    /// Total size of the NRO on disk (NRO only).
    pub nro_size: u32,
    /// Module name string (NRO only).
    pub module_name: String,
    /// Asset header (NRO only, when HAS_ASSET_HEADER flag is set).
    pub asset_header: Option<NroAssetHeader>,
}

impl NsoFile {
    /// Iterate over segments that actually contain file data.
    pub fn active_segments(&self) -> impl Iterator<Item = &NsoSegment> {
        self.segments.iter().filter(|s| s.has_file_content())
    }

    /// Find a segment by kind.
    pub fn segment_by_kind(&self, kind: NsoSegmentKind) -> Option<&NsoSegment> {
        self.segments.iter().find(|s| s.kind == kind)
    }

    /// Text segment (if present).
    pub fn text(&self) -> Option<&NsoSegment> {
        self.segment_by_kind(NsoSegmentKind::Text)
    }

    /// Rodata segment (if present).
    pub fn rodata(&self) -> Option<&NsoSegment> {
        self.segment_by_kind(NsoSegmentKind::Rodata)
    }

    /// Data segment (if present).
    pub fn data_seg(&self) -> Option<&NsoSegment> {
        self.segment_by_kind(NsoSegmentKind::Data)
    }

    /// BSS segment size (always 0 for NRO parsed from header).
    pub fn bss_size(&self) -> u32 {
        self.segment_by_kind(NsoSegmentKind::Bss)
            .map(|s| s.memory_size)
            .unwrap_or(0)
    }

    /// Total code + data size (useful for memory allocation).
    pub fn total_image_size(&self) -> u32 {
        self.segments
            .iter()
            .map(|s| s.memory_size)
            .sum()
    }

    /// Returns true if this is an NSO (static executable).
    pub fn is_nso(&self) -> bool {
        self.kind == NsoFileKind::Nso
    }

    /// Returns true if this is an NRO (relocatable module).
    pub fn is_nro(&self) -> bool {
        self.kind == NsoFileKind::Nro
    }

    /// Return the module_id as a hex string.
    pub fn module_id_hex(&self) -> String {
        self.module_id.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Return the build_id as a hex string (synonym for module_id_hex).
    pub fn build_id_hex(&self) -> String {
        self.module_id_hex()
    }
}

// ===========================================================================
// Nom Parsers
// ===========================================================================

/// Parse an NSO file from a byte slice.
pub fn parse_nso(data: &[u8]) -> NsoResult<NsoFile> {
    if data.len() < NSO_HEADER_SIZE {
        return Err(NsoError::TruncatedData);
    }

    let magic = &data[0..4];
    let kind = match magic {
        b"NSO0" => NsoFileKind::Nso,
        b"NRO0" => NsoFileKind::Nro,
        _ => return Err(NsoError::InvalidMagic),
    };

    match kind {
        NsoFileKind::Nso => parse_nso_inner(data),
        NsoFileKind::Nro => parse_nro_inner(data),
    }
}

/// Quick check: is this blob an NSO?
pub fn is_nso(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..4] == b"NSO0"
}

/// Quick check: is this blob an NRO?
pub fn is_nro(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..4] == b"NRO0"
}

/// Quick check: is this blob either NSO or NRO?
pub fn is_nso_or_nro(data: &[u8]) -> bool {
    data.len() >= 4 && (&data[0..4] == b"NSO0" || &data[0..4] == b"NRO0")
}

// ── NSO parser ─────────────────────────────────────────────────────────

fn parse_nso_inner(data: &[u8]) -> NsoResult<NsoFile> {
    let (remaining, header) = parse_nso_header(data)?;
    let _ = remaining;

    let mut segments = Vec::new();

    // Text segment
    if header.text_offset != 0 && header.text_size != 0 {
        let compressed = (header.flags & NSO_FLAG_TEXT_COMPRESS) != 0;
        let file_size = header.text_file_size;
        let seg_data = extract_segment_data(data, header.text_offset, file_size);
        segments.push(NsoSegment {
            offset: header.text_offset,
            memory_size: header.text_size,
            file_size: if compressed { file_size } else { header.text_size },
            kind: NsoSegmentKind::Text,
            hash: header.text_hash,
            data: seg_data,
            compressed,
        });
    }

    // Rodata segment
    if header.rodata_offset != 0 && header.rodata_size != 0 {
        let compressed = (header.flags & NSO_FLAG_RODATA_COMPRESS) != 0;
        let file_size = header.rodata_file_size;
        let seg_data = extract_segment_data(data, header.rodata_offset, file_size);
        segments.push(NsoSegment {
            offset: header.rodata_offset,
            memory_size: header.rodata_size,
            file_size: if compressed { file_size } else { header.rodata_size },
            kind: NsoSegmentKind::Rodata,
            hash: header.rodata_hash,
            data: seg_data,
            compressed,
        });
    }

    // Data segment
    if header.data_offset != 0 && header.data_size != 0 {
        let compressed = (header.flags & NSO_FLAG_DATA_COMPRESS) != 0;
        let file_size = header.data_file_size;
        let seg_data = extract_segment_data(data, header.data_offset, file_size);
        segments.push(NsoSegment {
            offset: header.data_offset,
            memory_size: header.data_size,
            file_size: if compressed { file_size } else { header.data_size },
            kind: NsoSegmentKind::Data,
            hash: header.data_hash,
            data: seg_data,
            compressed,
        });
    }

    // BSS (zero-filled, no file data)
    if header.bss_size != 0 {
        segments.push(NsoSegment {
            offset: 0,
            memory_size: header.bss_size,
            file_size: 0,
            kind: NsoSegmentKind::Bss,
            hash: [0u8; HASH_SIZE],
            data: Vec::new(),
            compressed: false,
        });
    }

    let mut flags = header.flags;
    if flags & !NSO_FLAG_KNOWN_MASK != 0 {
        // Mask off unknown bits but keep going
        flags &= NSO_FLAG_KNOWN_MASK;
    }

    Ok(NsoFile {
        kind: NsoFileKind::Nso,
        magic: NSO_MAGIC,
        version: header.version,
        flags,
        module_id: header.module_id,
        segments,
        nro_size: 0,
        module_name: String::new(),
        asset_header: None,
    })
}

// ── NRO parser ─────────────────────────────────────────────────────────

fn parse_nro_inner(data: &[u8]) -> NsoResult<NsoFile> {
    let (remaining, header) = parse_nro_header(data)?;
    let _ = remaining;

    let mut segments = Vec::new();

    // Text segment
    if header.text_offset != 0 && header.text_size != 0 {
        let seg_data = extract_segment_data(data, header.text_offset, header.text_size);
        segments.push(NsoSegment {
            offset: header.text_offset,
            memory_size: header.text_size,
            file_size: header.text_size,
            kind: NsoSegmentKind::Text,
            hash: header.text_hash,
            data: seg_data,
            compressed: false,
        });
    }

    // Rodata segment
    if header.rodata_offset != 0 && header.rodata_size != 0 {
        let seg_data = extract_segment_data(data, header.rodata_offset, header.rodata_size);
        segments.push(NsoSegment {
            offset: header.rodata_offset,
            memory_size: header.rodata_size,
            file_size: header.rodata_size,
            kind: NsoSegmentKind::Rodata,
            hash: header.rodata_hash,
            data: seg_data,
            compressed: false,
        });
    }

    // Data segment
    if header.data_offset != 0 && header.data_size != 0 {
        let seg_data = extract_segment_data(data, header.data_offset, header.data_size);
        segments.push(NsoSegment {
            offset: header.data_offset,
            memory_size: header.data_size,
            file_size: header.data_size,
            kind: NsoSegmentKind::Data,
            hash: header.data_hash,
            data: seg_data,
            compressed: false,
        });
    }

    // BSS (zero-filled)
    if header.bss_size != 0 {
        segments.push(NsoSegment {
            offset: 0,
            memory_size: header.bss_size,
            file_size: 0,
            kind: NsoSegmentKind::Bss,
            hash: [0u8; HASH_SIZE],
            data: Vec::new(),
            compressed: false,
        });
    }

    // Parse NRO-specific extensions
    let mut flags = header.flags & NRO_FLAG_KNOWN_MASK;
    let module_name = parse_nro_module_name(data, header.nro_size, flags);
    let asset_header = if flags & NRO_FLAG_HAS_ASSET_HEADER != 0 {
        parse_nro_asset_header(data, header.nro_size)
    } else {
        None
    };

    Ok(NsoFile {
        kind: NsoFileKind::Nro,
        magic: NRO_MAGIC,
        version: header.version,
        flags,
        module_id: header.build_id,
        segments,
        nro_size: header.nro_size,
        module_name,
        asset_header,
    })
}

// ── Raw header structs for nom ─────────────────────────────────────────

#[derive(Debug, Clone)]
struct NsoRawHeader {
    version: u32,
    flags: u32,
    text_offset: u32,
    text_size: u32,
    text_file_size: u32,
    text_memory_size: u32,
    rodata_offset: u32,
    rodata_size: u32,
    rodata_file_size: u32,
    rodata_memory_size: u32,
    data_offset: u32,
    data_size: u32,
    data_file_size: u32,
    bss_size: u32,
    module_id: [u8; MODULE_ID_SIZE],
    text_hash: [u8; HASH_SIZE],
    rodata_hash: [u8; HASH_SIZE],
    data_hash: [u8; HASH_SIZE],
}

#[derive(Debug, Clone)]
struct NroRawHeader {
    version: u32,
    nro_size: u32,
    flags: u32,
    text_offset: u32,
    text_size: u32,
    rodata_offset: u32,
    rodata_size: u32,
    data_offset: u32,
    data_size: u32,
    bss_size: u32,
    build_id: [u8; MODULE_ID_SIZE],
    text_hash: [u8; HASH_SIZE],
    rodata_hash: [u8; HASH_SIZE],
    data_hash: [u8; HASH_SIZE],
}

fn parse_nso_header(input: &[u8]) -> IResult<&[u8], NsoRawHeader> {
    let (input, _magic) = take(4usize)(input)?; // skip "NSO0"
    let (input, version) = le_u32(input)?;
    let (input, _reserved) = le_u32(input)?; // skip reserved
    let (input, flags) = le_u32(input)?;
    let (input, text_offset) = le_u32(input)?;
    let (input, text_size) = le_u32(input)?;
    let (input, text_file_size) = le_u32(input)?;
    let (input, text_memory_size) = le_u32(input)?;
    let (input, rodata_offset) = le_u32(input)?;
    let (input, rodata_size) = le_u32(input)?;
    let (input, rodata_file_size) = le_u32(input)?;
    let (input, rodata_memory_size) = le_u32(input)?;
    let (input, data_offset) = le_u32(input)?;
    let (input, data_size) = le_u32(input)?;
    let (input, data_file_size) = le_u32(input)?;
    let (input, bss_size) = le_u32(input)?;
    let (input, module_id_bytes) = take(MODULE_ID_SIZE)(input)?;
    let (input, text_hash_bytes) = take(HASH_SIZE)(input)?;
    let (input, rodata_hash_bytes) = take(HASH_SIZE)(input)?;
    let (input, data_hash_bytes) = take(HASH_SIZE)(input)?;

    let mut module_id = [0u8; MODULE_ID_SIZE];
    module_id.copy_from_slice(module_id_bytes);

    let mut text_hash = [0u8; HASH_SIZE];
    text_hash.copy_from_slice(text_hash_bytes);

    let mut rodata_hash = [0u8; HASH_SIZE];
    rodata_hash.copy_from_slice(rodata_hash_bytes);

    let mut data_hash = [0u8; HASH_SIZE];
    data_hash.copy_from_slice(data_hash_bytes);

    Ok((
        input,
        NsoRawHeader {
            version,
            flags,
            text_offset,
            text_size,
            text_file_size,
            text_memory_size,
            rodata_offset,
            rodata_size,
            rodata_file_size,
            rodata_memory_size,
            data_offset,
            data_size,
            data_file_size,
            bss_size,
            module_id,
            text_hash,
            rodata_hash,
            data_hash,
        },
    ))
}

fn parse_nro_header(input: &[u8]) -> IResult<&[u8], NroRawHeader> {
    let (input, _magic) = take(4usize)(input)?; // skip "NRO0"
    let (input, version) = le_u32(input)?;
    let (input, nro_size) = le_u32(input)?;
    let (input, flags) = le_u32(input)?;
    let (input, text_offset) = le_u32(input)?;
    let (input, text_size) = le_u32(input)?;
    let (input, rodata_offset) = le_u32(input)?;
    let (input, rodata_size) = le_u32(input)?;
    let (input, data_offset) = le_u32(input)?;
    let (input, data_size) = le_u32(input)?;
    let (input, bss_size) = le_u32(input)?;
    let (input, _reserved) = le_u32(input)?; // skip reserved
    let (input, build_id_bytes) = take(MODULE_ID_SIZE)(input)?;
    let (input, text_hash_bytes) = take(HASH_SIZE)(input)?;
    let (input, rodata_hash_bytes) = take(HASH_SIZE)(input)?;
    let (input, data_hash_bytes) = take(HASH_SIZE)(input)?;

    let mut build_id = [0u8; MODULE_ID_SIZE];
    build_id.copy_from_slice(build_id_bytes);

    let mut text_hash = [0u8; HASH_SIZE];
    text_hash.copy_from_slice(text_hash_bytes);

    let mut rodata_hash = [0u8; HASH_SIZE];
    rodata_hash.copy_from_slice(rodata_hash_bytes);

    let mut data_hash = [0u8; HASH_SIZE];
    data_hash.copy_from_slice(data_hash_bytes);

    Ok((
        input,
        NroRawHeader {
            version,
            nro_size,
            flags,
            text_offset,
            text_size,
            rodata_offset,
            rodata_size,
            data_offset,
            data_size,
            bss_size,
            build_id,
            text_hash,
            rodata_hash,
            data_hash,
        },
    ))
}

// ── Helpers ────────────────────────────────────────────────────────────

/// Extract segment data from the file, bounded by the data buffer length.
fn extract_segment_data(data: &[u8], offset: u32, size: u32) -> Vec<u8> {
    let start = offset as usize;
    let size = size as usize;
    if size == 0 || start + size > data.len() {
        let end = data.len().min(start + size);
        if start < data.len() && end > start {
            return data[start..end].to_vec();
        }
        return Vec::new();
    }
    data[start..start + size].to_vec()
}

/// Read the embedded module name from the NRO file.
fn parse_nro_module_name(data: &[u8], nro_size: u32, flags: u32) -> String {
    if flags & NRO_FLAG_HAS_MODULE_NAME == 0 {
        return String::new();
    }
    // Module name is stored at the end of the NRO, typically 0x10 bytes
    // before the end, followed by the name string
    let module_name_offset = nro_size.saturating_sub(0x20) as usize;
    if module_name_offset + 8 > data.len() || module_name_offset == 0 {
        return String::new();
    }

    // Module name header at module_name_offset:
    // u32: offset to name string from module_name header
    // u32: size of name string
    let name_hdr = &data[module_name_offset..];
    if name_hdr.len() < 8 {
        return String::new();
    }

    let name_rel_off =
        u32::from_le_bytes([name_hdr[0], name_hdr[1], name_hdr[2], name_hdr[3]]);
    let name_size =
        u32::from_le_bytes([name_hdr[4], name_hdr[5], name_hdr[6], name_hdr[7]]);

    let name_abs_off = module_name_offset + name_rel_off as usize;
    if name_abs_off + name_size as usize > data.len() {
        return String::new();
    }

    let name_bytes = &data[name_abs_off..name_abs_off + name_size as usize];
    String::from_utf8_lossy(name_bytes).trim_end_matches('\0').to_string()
}

/// Parse an NRO embedded asset header ("ASET").
fn parse_nro_asset_header(data: &[u8], nro_size: u32) -> Option<NroAssetHeader> {
    // Asset header is stored at nro_size - sizeof(asset_header)
    let aset_offset = nro_size.saturating_sub(0x40) as usize;
    if aset_offset + 0x20 > data.len() || aset_offset == 0 {
        return None;
    }

    let aset = &data[aset_offset..];
    if aset.len() < 0x20 || &aset[0..4] != b"ASET" {
        return None;
    }

    let version = u32::from_le_bytes([aset[4], aset[5], aset[6], aset[7]]);
    let icon_offset = u32::from_le_bytes([aset[8], aset[9], aset[10], aset[11]]);
    let icon_size = u32::from_le_bytes([aset[12], aset[13], aset[14], aset[15]]);
    let nacp_offset = u32::from_le_bytes([aset[16], aset[17], aset[18], aset[19]]);
    let nacp_size = u32::from_le_bytes([aset[20], aset[21], aset[22], aset[23]]);

    Some(NroAssetHeader {
        magic: *b"ASET",
        version,
        icon_offset,
        icon_size,
        nacp_offset,
        nacp_size,
    })
}

/// Return a human-readable name for the NSO/NRO version field.
pub fn version_name(version: u32) -> &'static str {
    match version {
        0 => "v0 (1.0.0)",
        _ => "UNKNOWN",
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn build_minimal_nso() -> Vec<u8> {
        let mut buf = vec![0u8; NSO_HEADER_SIZE + 0x1000];
        // Magic
        buf[0..4].copy_from_slice(b"NSO0");
        // text_offset = 0x100
        buf[0x10..0x14].copy_from_slice(&0x100_u32.to_le_bytes());
        // text_size = 0x1000
        buf[0x14..0x18].copy_from_slice(&0x1000_u32.to_le_bytes());
        // text_file_size = 0x1000
        buf[0x18..0x1C].copy_from_slice(&0x1000_u32.to_le_bytes());
        // text_memory_size = 0x2000
        buf[0x1C..0x20].copy_from_slice(&0x2000_u32.to_le_bytes());

        // Fill text with some AArch64 NOPs
        for i in 0x100..0x100 + 0x1000 {
            buf[i] = 0xD5;
            buf[i + 1] = 0x03;
            buf[i + 2] = 0x20;
            buf[i + 3] = 0x1F;
        }
        buf
    }

    fn build_minimal_nro() -> Vec<u8> {
        let nro_size: u32 = NSO_HEADER_SIZE as u32 + 0x1000;
        let mut buf = vec![0u8; nro_size as usize];
        // Magic
        buf[0..4].copy_from_slice(b"NRO0");
        // version = 0
        buf[0x04..0x08].copy_from_slice(&0u32.to_le_bytes());
        // nro_size
        buf[0x08..0x0C].copy_from_slice(&nro_size.to_le_bytes());
        // text_offset = 0x100
        buf[0x10..0x14].copy_from_slice(&0x100_u32.to_le_bytes());
        // text_size = 0x1000
        buf[0x14..0x18].copy_from_slice(&0x1000_u32.to_le_bytes());

        // Fill text with AArch64 NOPs
        for i in 0x100..0x100 + 0x1000 {
            buf[i] = 0xD5;
            buf[i + 1] = 0x03;
            buf[i + 2] = 0x20;
            buf[i + 3] = 0x1F;
        }
        buf
    }

    #[test]
    fn test_parse_minimal_nso() {
        let data = build_minimal_nso();
        let nso = parse_nso(&data).expect("should parse minimal NSO");
        assert!(nso.is_nso());
        assert!(!nso.is_nro());
        assert_eq!(nso.magic, NSO_MAGIC);

        let text = nso.text().expect("should have text segment");
        assert_eq!(text.offset, 0x100);
        assert_eq!(text.memory_size, 0x2000);
        assert_eq!(text.file_size, 0x1000);
        assert!(!text.compressed);
        assert_eq!(text.data.len(), 0x1000);
    }

    #[test]
    fn test_parse_minimal_nro() {
        let data = build_minimal_nro();
        let nro = parse_nso(&data).expect("should parse minimal NRO");
        assert!(nro.is_nro());
        assert!(!nro.is_nso());
        assert_eq!(nro.magic, NRO_MAGIC);
        assert_eq!(nro.nro_size, NSO_HEADER_SIZE as u32 + 0x1000);

        let text = nro.text().expect("should have text segment");
        assert_eq!(text.offset, 0x100);
        assert_eq!(text.data.len(), 0x1000);
    }

    #[test]
    fn test_is_nso_nro_detection() {
        let nso = build_minimal_nso();
        let nro = build_minimal_nro();
        assert!(is_nso(&nso));
        assert!(!is_nso(&nro));
        assert!(is_nro(&nro));
        assert!(!is_nro(&nso));
        assert!(is_nso_or_nro(&nso));
        assert!(is_nso_or_nro(&nro));
        assert!(!is_nso_or_nro(&[]));
    }

    #[test]
    fn test_invalid_magic_rejected() {
        let mut data = build_minimal_nso();
        data[3] = b'X'; // corrupt magic
        assert!(parse_nso(&data).is_err());
    }

    #[test]
    fn test_truncated_data() {
        let data = vec![0u8; 10];
        assert!(parse_nso(&data).is_err());
    }

    #[test]
    fn test_nso_flags() {
        let flags = NSO_FLAG_TEXT_COMPRESS | NSO_FLAG_RODATA_HASH;
        let names = nso_flag_names(flags);
        assert!(names.contains(&"TEXT_COMPRESS"));
        assert!(names.contains(&"RODATA_HASH"));
        assert!(!names.contains(&"DATA_COMPRESS"));
    }

    #[test]
    fn test_module_id_hex() {
        let nso = build_minimal_nso();
        let parsed = parse_nso(&nso).unwrap();
        // All zeros in our fake NSO
        assert_eq!(parsed.module_id_hex(), "00".repeat(32));
    }

    #[test]
    fn test_bss_segment() {
        let mut buf = vec![0u8; NSO_HEADER_SIZE];
        buf[0..4].copy_from_slice(b"NSO0");
        // Set BSS size to 0x1000
        buf[0x3C..0x40].copy_from_slice(&0x1000_u32.to_le_bytes());

        let nso = parse_nso(&buf).expect("should parse NSO with BSS");
        assert_eq!(nso.bss_size(), 0x1000);
        let bss = nso.segment_by_kind(NsoSegmentKind::Bss).unwrap();
        assert_eq!(bss.memory_size, 0x1000);
        assert!(!bss.has_file_content());
    }

    #[test]
    fn test_total_image_size() {
        let data = build_minimal_nso();
        let nso = parse_nso(&data).unwrap();
        // text memory_size = 0x2000
        assert_eq!(nso.total_image_size(), 0x2000);
    }
}
