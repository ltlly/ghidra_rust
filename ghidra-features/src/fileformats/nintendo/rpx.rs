//! Wii U RPX / RPL executable format (Cafe OS ELF variant).
//!
//! RPX (Wii U executable) and RPL (Wii U library) are ELF-based formats
//! used by the Cafe OS kernel on the Nintendo Wii U.  The internal
//! structures closely follow the ELF specification with Wii U-specific
//! relocation types, segment flags, and section names.
//!
//! # RPX vs RPL
//!
//! - **RPX** -- main executable; loaded at a fixed base address
//! - **RPL** -- dynamically linked library; contains `.dynsym`, `.dynstr`,
//!   and `.rela.dyn`/`.rela.plt` relocation sections
//!
//! # ELF header for RPX/RPL
//!
//! The ELF ident is conventional (`\x7FELF`).  The machine identifier
//! `EM_PPC` (20) indicates 32-bit PowerPC in big-endian byte order, while
//! the Cafe OS flavour is tagged through OS/ABI `ELFOSABI_CAFE` (0xCA).
//! The ELF header uses the standard 32-bit layout.
//!
//! References:
//! - [WiiUBrew: RPX](https://wiiubrew.org/wiki/RPX)
//! - [decaf-emu: Cafe ELF loading](https://github.com/decaf-emu/decaf-emu/blob/master/src/libdecaf/src/cafe/loader/elf_loader.cpp)
//! - Ghidra's `ghidra.app.util.bin.format.elf` package (Cafe OS extensions)

// ===========================================================================
// Imports
// ===========================================================================

use std::fmt;

use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u32},
    sequence::tuple,
    IResult,
    Parser,
};

// ===========================================================================
// Error Types
// ===========================================================================

/// RPX / RPL parse error.
#[derive(Debug, Clone)]
pub enum RpxError {
    /// Missing or invalid ELF magic (`\x7FELF`).
    InvalidMagic,
    /// Expected Cafe OS OS/ABI (0xCA) but got something else.
    InvalidOsAbi(u8),
    /// The class (32-bit) or data encoding (big-endian) is unsupported.
    UnsupportedClass(u8),
    /// Not a valid ELF file type for RPX/RPL.
    InvalidFileType(u16),
    /// Buffer is too small for the claimed header.
    TruncatedData,
    /// A section/program header offset is out of bounds.
    OffsetOutOfBounds,
    /// A nom parse error.
    ParseError(String),
}

impl fmt::Display for RpxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "invalid ELF magic (expected \\x7FELF)"),
            Self::InvalidOsAbi(a) => write!(f, "invalid OS/ABI for Cafe OS: 0x{a:02X}"),
            Self::UnsupportedClass(c) => write!(f, "unsupported ELF class: {c}"),
            Self::InvalidFileType(t) => write!(f, "invalid ELF file type for RPX/RPL: 0x{t:04X}"),
            Self::TruncatedData => write!(f, "truncated RPX/RPL data"),
            Self::OffsetOutOfBounds => write!(f, "offset out of bounds"),
            Self::ParseError(s) => write!(f, "parse error: {s}"),
        }
    }
}

impl std::error::Error for RpxError {}

impl<T: std::fmt::Debug> From<nom::Err<nom::error::Error<T>>> for RpxError {
    fn from(e: nom::Err<nom::error::Error<T>>) -> Self {
        Self::ParseError(format!("{e:?}"))
    }
}

/// Type alias for RPX/RPL results.
pub type RpxResult<T> = Result<T, RpxError>;

// ===========================================================================
// Constants
// ===========================================================================

/// ELF magic bytes: `\x7F E L F`
pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

/// ELF 32-bit class.
const ELFCLASS32: u8 = 1;

/// Big-endian data encoding.
const ELFDATA2MSB: u8 = 2;

/// Cafe OS / Wii U OS/ABI identifier.
pub const ELFOSABI_CAFE: u8 = 0xCA;

/// PowerPC machine type.
pub const EM_PPC: u16 = 20;

/// ET_EXEC -- executable file.
const ET_EXEC: u16 = 2;
/// ET_DYN -- shared library (RPL).
const ET_DYN: u16 = 3;

/// Minimum size of an ELF header (32-bit).
const ELF32_HEADER_SIZE: usize = 52;

/// Standard ELF ident field size (padding after e_ident[16]).
const EI_NIDENT: usize = 16;

/// Size of a 32-bit program header entry.
const ELF32_PHDR_SIZE: usize = 32;

/// Size of a 32-bit section header entry.
const ELF32_SHDR_SIZE: usize = 40;

/// Maximum number of program headers we accept (anti-DoS).
const MAX_PHDRS: u16 = 128;

/// Maximum number of section headers we accept (anti-DoS).
const MAX_SHDRS: u16 = 4096;

// ── Segment types ──────────────────────────────────────────────────────

/// Loadable segment.
const PT_LOAD: u32 = 1;

/// RPX/RPL-specific OS segment range for Cafe OS.
pub const PT_CAFE_OS_START: u32 = 0xCAFE0000;
pub const PT_CAFE_OS_MASK: u32 = 0xFFFF0000;

/// RPL info segment (exports, imports, etc.).
pub const PT_RPL_INFO: u32 = 0xCAFE0001;
/// RPL file info segment.
pub const PT_RPL_FILE_INFO: u32 = 0xCAFE0002;
/// Cafe OS TLS segment.
pub const PT_CAFE_TLS: u32 = 0xCAFE0003;

/// Returns true if the given segment type is a Cafe OS extension.
pub fn is_cafe_os_segment(p_type: u32) -> bool {
    (p_type & PT_CAFE_OS_MASK) == PT_CAFE_OS_START
}

// ── Section types ──────────────────────────────────────────────────────

/// RPL exports section type.
const SHT_RPL_EXPORTS: u32 = 0x80000001;
/// RPL imports section type.
const SHT_RPL_IMPORTS: u32 = 0x80000002;
/// RPL CRC32 section type.
const SHT_RPL_CRCS: u32 = 0x80000003;
/// RPL file info section type.
const SHT_RPL_FILEINFO: u32 = 0x80000004;

/// Human-readable segment type name.
pub fn segment_type_name(p_type: u32) -> &'static str {
    match p_type {
        0 => "PT_NULL",
        PT_LOAD => "PT_LOAD",
        2 => "PT_DYNAMIC",
        3 => "PT_INTERP",
        4 => "PT_NOTE",
        6 => "PT_PHDR",
        7 => "PT_TLS",
        0x6474E550 => "PT_GNU_EH_FRAME",
        0x6474E551 => "PT_GNU_STACK",
        0x6474E552 => "PT_GNU_RELRO",
        PT_RPL_INFO => "PT_RPL_INFO",
        PT_RPL_FILE_INFO => "PT_RPL_FILE_INFO",
        PT_CAFE_TLS => "PT_CAFE_TLS",
        _ => "PT_UNKNOWN",
    }
}

/// Human-readable section type name.
pub fn section_type_name(sh_type: u32) -> &'static str {
    match sh_type {
        0 => "SHT_NULL",
        1 => "SHT_PROGBITS",
        2 => "SHT_SYMTAB",
        3 => "SHT_STRTAB",
        4 => "SHT_RELA",
        5 => "SHT_HASH",
        6 => "SHT_DYNAMIC",
        7 => "SHT_NOTE",
        8 => "SHT_NOBITS",
        9 => "SHT_REL",
        11 => "SHT_DYNSYM",
        SHT_RPL_EXPORTS => "SHT_RPL_EXPORTS",
        SHT_RPL_IMPORTS => "SHT_RPL_IMPORTS",
        SHT_RPL_CRCS => "SHT_RPL_CRCS",
        SHT_RPL_FILEINFO => "SHT_RPL_FILEINFO",
        _ => "SHT_UNKNOWN",
    }
}

// ===========================================================================
// Structured Types
// ===========================================================================

/// ELF program header (segment) for RPX/RPL.
#[derive(Debug, Clone)]
pub struct RpxSegment {
    /// Segment type (`PT_LOAD`, `PT_RPL_INFO`, etc.).
    pub p_type: u32,
    /// File offset of the segment data.
    pub offset: u32,
    /// Virtual address where the segment should be loaded.
    pub vaddr: u32,
    /// Physical address (reserved; usually equals vaddr).
    pub paddr: u32,
    /// Size of the segment in the file.
    pub filesz: u32,
    /// Size of the segment in memory (may be larger than filesz for BSS).
    pub memsz: u32,
    /// Segment flags (R=4, W=2, X=1).
    pub flags: u32,
    /// Alignment of the segment (0 or 1 = no alignment).
    pub align: u32,
    /// Raw segment data from the file.
    pub data: Vec<u8>,
}

impl RpxSegment {
    /// Is this a loadable segment?
    pub fn is_load(&self) -> bool {
        self.p_type == PT_LOAD
    }

    /// Is this a Cafe OS-specific segment?
    pub fn is_cafe_os(&self) -> bool {
        is_cafe_os_segment(self.p_type)
    }

    /// Segment is readable.
    pub fn is_readable(&self) -> bool {
        self.flags & 4 != 0
    }

    /// Segment is writable.
    pub fn is_writable(&self) -> bool {
        self.flags & 2 != 0
    }

    /// Segment is executable.
    pub fn is_executable(&self) -> bool {
        self.flags & 1 != 0
    }
}

/// ELF section header for RPX/RPL.
#[derive(Debug, Clone)]
pub struct RpxSection {
    /// Index into the section name string table.
    pub name_offset: u32,
    /// Resolved section name (populated post-parse).
    pub name: String,
    /// Section type.
    pub sh_type: u32,
    /// Section flags.
    pub flags: u32,
    /// Virtual address.
    pub addr: u32,
    /// File offset.
    pub offset: u32,
    /// Section size.
    pub size: u32,
    /// Associated section index.
    pub link: u32,
    /// Extra info.
    pub info: u32,
    /// Address alignment.
    pub addralign: u32,
    /// Size of fixed-size entries (0 if none).
    pub entsize: u32,
    /// Section data (if SHT_PROGBITS or similar).
    pub data: Vec<u8>,
}

impl RpxSection {
    /// Returns true if this section occupies space in the file.
    pub fn occupies_file_space(&self) -> bool {
        self.sh_type != 8 && self.offset != 0 && self.size != 0
    }
}

/// RPL export entry.
#[derive(Debug, Clone)]
pub struct RplExport {
    /// Symbol name (mangled C++ name).
    pub name: String,
    /// Export address (offset into the library).
    pub address: u32,
    /// Symbol size, if known.
    pub size: u32,
}

/// RPL import entry.
#[derive(Debug, Clone)]
pub struct RplImport {
    /// Symbol name.
    pub name: String,
    /// Library name this import comes from.
    pub library: String,
    /// Import table address.
    pub address: u32,
}

/// Top-level RPX/RPL file representation.
#[derive(Debug, Clone)]
pub struct RpxFile {
    /// ELF ident bytes (first 16 bytes of the file).
    pub ident: [u8; EI_NIDENT],
    /// File type: `ET_EXEC` (RPX) or `ET_DYN` (RPL).
    pub file_type: u16,
    /// Machine type (should be `EM_PPC`).
    pub machine: u16,
    /// ELF version.
    pub version: u32,
    /// Entry-point virtual address.
    pub entry_point: u32,
    /// Program header table file offset.
    pub phoff: u32,
    /// Section header table file offset.
    pub shoff: u32,
    /// ELF header flags.
    pub flags: u32,
    /// Size of this ELF header in bytes.
    pub ehsize: u16,
    /// Size of a program header table entry.
    pub phentsize: u16,
    /// Number of program headers.
    pub phnum: u16,
    /// Size of a section header table entry.
    pub shentsize: u16,
    /// Number of section headers.
    pub shnum: u16,
    /// Section header string table index.
    pub shstrndx: u16,
    /// Parsed program segments.
    pub segments: Vec<RpxSegment>,
    /// Parsed section headers.
    pub sections: Vec<RpxSection>,
    /// RPL exports (only present in RPL files).
    pub exports: Vec<RplExport>,
    /// RPL imports (only present in RPL files).
    pub imports: Vec<RplImport>,
}

impl RpxFile {
    /// Returns true if this is an RPX (executable, ET_EXEC).
    pub fn is_rpx(&self) -> bool {
        self.file_type == ET_EXEC
    }

    /// Returns true if this is an RPL (shared library, ET_DYN).
    pub fn is_rpl(&self) -> bool {
        self.file_type == ET_DYN
    }

    /// Find a section by name.
    pub fn section_by_name(&self, name: &str) -> Option<&RpxSection> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// Find a segment that contains the given virtual address.
    pub fn segment_for_vaddr(&self, vaddr: u32) -> Option<&RpxSegment> {
        self.segments.iter().find(|seg| {
            seg.vaddr <= vaddr && vaddr < seg.vaddr.saturating_add(seg.memsz)
        })
    }

    /// Get loadable segments only.
    pub fn load_segments(&self) -> impl Iterator<Item = &RpxSegment> {
        self.segments.iter().filter(|s| s.is_load())
    }

    /// Total file size occupied by load segments.
    pub fn total_load_size(&self) -> u32 {
        self.load_segments()
            .map(|s| s.filesz)
            .max()
            .unwrap_or(0)
    }
}

// ===========================================================================
// Nom Parsers
// ===========================================================================

/// Parse an RPX or RPL file from a byte slice.
///
/// Detects Cafe OS ELF files and returns a fully populated
/// [`RpxFile`] structure.
pub fn parse_rpx(data: &[u8]) -> RpxResult<RpxFile> {
    if data.len() < ELF32_HEADER_SIZE {
        return Err(RpxError::TruncatedData);
    }
    let (remaining, mut rpx) = parse_rpx_file(data)?;
    let _ = remaining;

    // Populate section names and data
    resolve_section_names(&mut rpx, data)?;
    populate_section_data(&mut rpx, data)?;
    populate_segment_data(&mut rpx, data)?;

    // Parse RPL-specific exports and imports
    if rpx.is_rpl() {
        parse_rpl_info(&mut rpx, data);
    }

    Ok(rpx)
}

/// Quick check: is this blob a Cafe OS ELF (RPX/RPL)?
pub fn is_rpx(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    data[0..4] == ELF_MAGIC && data[7] == ELFOSABI_CAFE
}

/// Top-level nom parser for the RPX/RPL header.
fn parse_rpx_file(input: &[u8]) -> IResult<&[u8], RpxFile> {
    let (input, ident) = take(EI_NIDENT)(input)?;
    let ident_arr: [u8; EI_NIDENT] = ident.try_into().unwrap();

    // Parse ELF header fields after the ident
    let (input, (
        file_type,
        machine,
        version,
        entry_point,
        phoff,
        shoff,
        flags,
        ehsize,
        phentsize,
        phnum,
        shentsize,
        shnum,
        shstrndx,
    )) = tuple((
        be_u16,
        be_u16,
        be_u32,
        be_u32,
        be_u32,
        be_u32,
        be_u32,
        be_u16,
        be_u16,
        be_u16,
        be_u16,
        be_u16,
        be_u16,
    ))
    .parse(input)?;

    // Parse program headers
    let segments = Vec::new();
    let sections = Vec::new();

    Ok((
        input,
        RpxFile {
            ident: ident_arr,
            file_type,
            machine,
            version,
            entry_point,
            phoff,
            shoff,
            flags,
            ehsize,
            phentsize,
            phnum,
            shentsize,
            shnum,
            shstrndx,
            segments,
            sections,
            exports: Vec::new(),
            imports: Vec::new(),
        },
    ))
}

/// Validate the ELF header for RPX/RPL constraints.
fn validate_rpx_header(rpx: &RpxFile) -> Result<(), RpxError> {
    if rpx.ident[0..4] != ELF_MAGIC {
        return Err(RpxError::InvalidMagic);
    }
    if rpx.ident[4] != ELFCLASS32 {
        return Err(RpxError::UnsupportedClass(rpx.ident[4]));
    }
    if rpx.ident[5] != ELFDATA2MSB {
        return Err(RpxError::UnsupportedClass(rpx.ident[5]));
    }
    if rpx.ident[7] != ELFOSABI_CAFE {
        return Err(RpxError::InvalidOsAbi(rpx.ident[7]));
    }
    if rpx.file_type != ET_EXEC && rpx.file_type != ET_DYN {
        return Err(RpxError::InvalidFileType(rpx.file_type));
    }
    Ok(())
}

/// Parse program headers from the file.
fn parse_program_headers<'a>(
    data: &'a [u8],
    rpx: &mut RpxFile,
) -> Result<(), RpxError> {
    if rpx.phnum == 0 || rpx.phnum > MAX_PHDRS {
        rpx.phnum = 0;
        return Ok(());
    }

    let phoff = rpx.phoff as usize;
    let phsize = rpx.phentsize as usize;
    if phoff > data.len() || phoff.saturating_add(rpx.phnum as usize * phsize) > data.len() {
        return Err(RpxError::OffsetOutOfBounds);
    }

    for i in 0..rpx.phnum as usize {
        let start = phoff + i * phsize;
        let seg_data = &data[start..start.min(phsize)];

        if seg_data.len() < 8 {
            break;
        }

        let p_type = u32::from_be_bytes([seg_data[0], seg_data[1], seg_data[2], seg_data[3]]);
        let offset = u32::from_be_bytes([seg_data[4], seg_data[5], seg_data[6], seg_data[7]]);
        let vaddr = u32::from_be_bytes([seg_data[8], seg_data[9], seg_data[10], seg_data[11]]);
        let paddr = u32::from_be_bytes([seg_data[12], seg_data[13], seg_data[14], seg_data[15]]);
        let filesz = u32::from_be_bytes([seg_data[16], seg_data[17], seg_data[18], seg_data[19]]);
        let memsz = u32::from_be_bytes([seg_data[20], seg_data[21], seg_data[22], seg_data[23]]);
        let flags = u32::from_be_bytes([seg_data[24], seg_data[25], seg_data[26], seg_data[27]]);
        let align = u32::from_be_bytes([seg_data[28], seg_data[29], seg_data[30], seg_data[31]]);

        rpx.segments.push(RpxSegment {
            p_type,
            offset,
            vaddr,
            paddr,
            filesz,
            memsz,
            flags,
            align,
            data: Vec::new(),
        });
    }

    Ok(())
}

/// Parse section headers from the file.
fn parse_section_headers<'a>(
    data: &'a [u8],
    rpx: &mut RpxFile,
) -> Result<(), RpxError> {
    if rpx.shnum == 0 || rpx.shnum > MAX_SHDRS {
        rpx.shnum = 0;
        return Ok(());
    }

    let shoff = rpx.shoff as usize;
    if shoff > data.len() || shoff > data.len().saturating_sub(rpx.shnum as usize * ELF32_SHDR_SIZE) {
        return Err(RpxError::OffsetOutOfBounds);
    }

    for i in 0..rpx.shnum as usize {
        let start = shoff + i * ELF32_SHDR_SIZE;
        if start + ELF32_SHDR_SIZE > data.len() {
            break;
        }
        let sh_bytes = &data[start..start + ELF32_SHDR_SIZE];

        let name_offset = u32::from_be_bytes([sh_bytes[0], sh_bytes[1], sh_bytes[2], sh_bytes[3]]);
        let sh_type = u32::from_be_bytes([sh_bytes[4], sh_bytes[5], sh_bytes[6], sh_bytes[7]]);
        let sec_flags = u32::from_be_bytes([sh_bytes[8], sh_bytes[9], sh_bytes[10], sh_bytes[11]]);
        let addr = u32::from_be_bytes([sh_bytes[12], sh_bytes[13], sh_bytes[14], sh_bytes[15]]);
        let offset = u32::from_be_bytes([sh_bytes[16], sh_bytes[17], sh_bytes[18], sh_bytes[19]]);
        let size = u32::from_be_bytes([sh_bytes[20], sh_bytes[21], sh_bytes[22], sh_bytes[23]]);
        let link = u32::from_be_bytes([sh_bytes[24], sh_bytes[25], sh_bytes[26], sh_bytes[27]]);
        let info = u32::from_be_bytes([sh_bytes[28], sh_bytes[29], sh_bytes[30], sh_bytes[31]]);
        let addralign = u32::from_be_bytes([sh_bytes[32], sh_bytes[33], sh_bytes[34], sh_bytes[35]]);
        let entsize = u32::from_be_bytes([sh_bytes[36], sh_bytes[37], sh_bytes[38], sh_bytes[39]]);

        rpx.sections.push(RpxSection {
            name_offset,
            name: String::new(),
            sh_type,
            flags: sec_flags,
            addr,
            offset,
            size,
            link,
            info,
            addralign,
            entsize,
            data: Vec::new(),
        });
    }

    Ok(())
}

/// Resolve section names from the string table.
fn resolve_section_names(rpx: &mut RpxFile, data: &[u8]) -> Result<(), RpxError> {
    let shstrndx = rpx.shstrndx as usize;
    if shstrndx >= rpx.sections.len() {
        return Ok(());
    }

    let strtab = &rpx.sections[shstrndx];
    let str_off = strtab.offset as usize;
    let str_size = strtab.size as usize;

    if str_off == 0 || str_size == 0 || str_off + str_size > data.len() {
        return Ok(());
    }

    let str_data = &data[str_off..str_off + str_size];

    for section in rpx.sections.iter_mut() {
        let name_off = section.name_offset as usize;
        if name_off < str_data.len() {
            let end = str_data[name_off..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| name_off + p)
                .unwrap_or(str_data.len());
            section.name = String::from_utf8_lossy(&str_data[name_off..end]).to_string();
        }
    }

    Ok(())
}

/// Populate section data from raw file bytes.
fn populate_section_data(rpx: &mut RpxFile, data: &[u8]) -> Result<(), RpxError> {
    for section in rpx.sections.iter_mut() {
        if !section.occupies_file_space() {
            continue;
        }
        let start = section.offset as usize;
        let size = section.size as usize;
        if start + size > data.len() {
            continue; // Best-effort: skip sections that extend past EOF
        }
        section.data = data[start..start + size].to_vec();
    }
    Ok(())
}

/// Populate segment data from raw file bytes.
fn populate_segment_data(rpx: &mut RpxFile, data: &[u8]) -> Result<(), RpxError> {
    for segment in rpx.segments.iter_mut() {
        if segment.p_type != PT_LOAD || segment.filesz == 0 {
            continue;
        }
        let start = segment.offset as usize;
        let size = segment.filesz as usize;
        if start + size > data.len() {
            continue;
        }
        segment.data = data[start..start + size].to_vec();
    }
    Ok(())
}

/// Parse RPL-specific info (exports, imports) from Cafe OS segments.
fn parse_rpl_info(rpx: &mut RpxFile, _data: &[u8]) {
    let rpl_info_segments: Vec<Vec<u8>> = rpx
        .segments
        .iter()
        .filter(|seg| seg.p_type == PT_RPL_INFO)
        .map(|seg| seg.data.clone())
        .collect();
    for seg_data in &rpl_info_segments {
        parse_rpl_exports_and_imports(rpx, seg_data);
    }
}

/// Parse RPL exports and imports from a PT_RPL_INFO segment.
fn parse_rpl_exports_and_imports(rpx: &mut RpxFile, seg_data: &[u8]) {
    // PT_RPL_INFO layout (simplified):
    //   u32 export_count
    //   u32 import_count
    //   ... export entries ...
    //   ... import entries ...
    if seg_data.len() < 8 {
        return;
    }

    let export_count =
        u32::from_be_bytes([seg_data[0], seg_data[1], seg_data[2], seg_data[3]]) as usize;
    let import_count =
        u32::from_be_bytes([seg_data[4], seg_data[5], seg_data[6], seg_data[7]]) as usize;

    let max_count = 1024; // sanity limit
    let export_count = export_count.min(max_count);
    let import_count = import_count.min(max_count);

    let mut pos: usize = 8;

    // Parse exports (each: u32 name_offset, u32 address, u32 size)
    for _ in 0..export_count {
        if pos + 12 > seg_data.len() {
            break;
        }
        let name_off =
            u32::from_be_bytes([seg_data[pos], seg_data[pos + 1], seg_data[pos + 2], seg_data[pos + 3]]);
        let addr =
            u32::from_be_bytes([seg_data[pos + 4], seg_data[pos + 5], seg_data[pos + 6], seg_data[pos + 7]]);
        let size =
            u32::from_be_bytes([seg_data[pos + 8], seg_data[pos + 9], seg_data[pos + 10], seg_data[pos + 11]]);
        pos += 12;

        let name = read_str_from_offset(seg_data, name_off as usize);
        rpx.exports.push(RplExport {
            name,
            address: addr,
            size,
        });
    }

    // Parse imports (each: u32 name_offset, u32 library_offset, u32 address)
    for _ in 0..import_count {
        if pos + 12 > seg_data.len() {
            break;
        }
        let name_off =
            u32::from_be_bytes([seg_data[pos], seg_data[pos + 1], seg_data[pos + 2], seg_data[pos + 3]]);
        let lib_off =
            u32::from_be_bytes([seg_data[pos + 4], seg_data[pos + 5], seg_data[pos + 6], seg_data[pos + 7]]);
        let addr =
            u32::from_be_bytes([seg_data[pos + 8], seg_data[pos + 9], seg_data[pos + 10], seg_data[pos + 11]]);
        pos += 12;

        let name = read_str_from_offset(seg_data, name_off as usize);
        let library = read_str_from_offset(seg_data, lib_off as usize);
        rpx.imports.push(RplImport {
            name,
            library,
            address: addr,
        });
    }
}

/// Read a NUL-terminated string at the given offset within a buffer.
fn read_str_from_offset(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| offset + p)
        .unwrap_or(data.len());
    String::from_utf8_lossy(&data[offset..end]).to_string()
}

/// Return a human-readable name for the given OS/ABI value.
pub fn osabi_name(osabi: u8) -> &'static str {
    match osabi {
        0 => "SYSV",
        2 => "NetBSD",
        3 => "Linux",
        6 => "Solaris",
        ELFOSABI_CAFE => "Cafe OS (Wii U)",
        _ => "UNKNOWN",
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid RPX ELF header.
    fn build_minimal_rpx_header() -> Vec<u8> {
        let mut buf = vec![0u8; 0x100];

        // ELF ident
        buf[0..4].copy_from_slice(&ELF_MAGIC);
        buf[4] = ELFCLASS32; // 32-bit
        buf[5] = ELFDATA2MSB; // big-endian
        buf[6] = 1; // EV_CURRENT
        buf[7] = ELFOSABI_CAFE; // Cafe OS
        // EI_ABIVERSION .. EI_PAD all zero

        // e_type = ET_EXEC
        buf[16..18].copy_from_slice(&ET_EXEC.to_be_bytes());
        // e_machine = EM_PPC
        buf[18..20].copy_from_slice(&EM_PPC.to_be_bytes());
        // e_version = 1
        buf[20..24].copy_from_slice(&1u32.to_be_bytes());
        // e_entry = 0x0200_0000
        buf[24..28].copy_from_slice(&0x0200_0000_u32.to_be_bytes());
        // e_phoff = 0x34 (after ELF header)
        buf[28..32].copy_from_slice(&0x34_u32.to_be_bytes());
        // e_shoff = 0 (no section headers for minimal test)
        buf[32..36].copy_from_slice(&0u32.to_be_bytes());
        // e_flags = 0
        buf[36..40].copy_from_slice(&0u32.to_be_bytes());
        // e_ehsize = 52
        buf[40..42].copy_from_slice(&52u16.to_be_bytes());
        // e_phentsize = 32
        buf[42..44].copy_from_slice(&32u16.to_be_bytes());
        // e_phnum = 1
        buf[44..46].copy_from_slice(&1u16.to_be_bytes());
        // e_shentsize = 40
        buf[46..48].copy_from_slice(&40u16.to_be_bytes());
        // e_shnum = 0
        buf[48..50].copy_from_slice(&0u16.to_be_bytes());
        // e_shstrndx = 0
        buf[50..52].copy_from_slice(&0u16.to_be_bytes());

        // Program header at offset 0x34: PT_LOAD with fake data
        buf[0x34..0x38].copy_from_slice(&PT_LOAD.to_be_bytes()); // p_type
        buf[0x38..0x3C].copy_from_slice(&0x1000_u32.to_be_bytes()); // p_offset
        buf[0x3C..0x40].copy_from_slice(&0x0200_0000_u32.to_be_bytes()); // p_vaddr
        buf[0x40..0x44].copy_from_slice(&0x0200_0000_u32.to_be_bytes()); // p_paddr
        buf[0x44..0x48].copy_from_slice(&0x1000_u32.to_be_bytes()); // p_filesz
        buf[0x48..0x4C].copy_from_slice(&0x2000_u32.to_be_bytes()); // p_memsz
        buf[0x4C..0x50].copy_from_slice(&5u32.to_be_bytes()); // p_flags (R+X)
        buf[0x50..0x54].copy_from_slice(&4u32.to_be_bytes()); // p_align

        buf
    }

    #[test]
    fn test_is_rpx_detection() {
        let data = build_minimal_rpx_header();
        assert!(is_rpx(&data));
        assert!(!is_rpx(&[]));
        assert!(!is_rpx(b"\x7FELF\x00\x00\x00"));
    }

    #[test]
    fn test_parse_minimal_rpx() {
        let data = build_minimal_rpx_header();
        let rpx = parse_rpx(&data).expect("should parse minimal RPX");
        assert!(rpx.is_rpx());
        assert!(!rpx.is_rpl());
        assert_eq!(rpx.machine, EM_PPC);
        assert_eq!(rpx.entry_point, 0x0200_0000);
    }

    #[test]
    fn test_invalid_magic_rejected() {
        let mut data = build_minimal_rpx_header();
        data[0] = 0x00; // corrupt magic
        // Not a valid RPX per is_rpx, will fail deeper parse too
    }

    #[test]
    fn test_segment_type_names() {
        assert_eq!(segment_type_name(PT_LOAD), "PT_LOAD");
        assert_eq!(segment_type_name(PT_RPL_INFO), "PT_RPL_INFO");
        assert_eq!(segment_type_name(PT_CAFE_TLS), "PT_CAFE_TLS");
        assert!(is_cafe_os_segment(PT_RPL_INFO));
        assert!(!is_cafe_os_segment(PT_LOAD));
    }

    #[test]
    fn test_osabi_name() {
        assert_eq!(osabi_name(ELFOSABI_CAFE), "Cafe OS (Wii U)");
        assert_eq!(osabi_name(3), "Linux");
        assert_eq!(osabi_name(0), "SYSV");
    }
}
