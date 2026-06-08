//! COFF (Common Object File Format) file header and section parser.
//!
//! Ported from Ghidra's `ghidra.app.util.bin.format.coff` package.
//!
//! This module parses the COFF file header, section headers, relocations,
//! line numbers, and symbol table entries. This is the binary object file
//! format used by Unix systems, TI DSP tools, and Windows PE (which extends COFF).
//!
//! The existing `coff.rs` module handles COFF *archive* (`.a`) files.
//! This module handles individual COFF *object* files.
//!
//! References:
//! - Microsoft PE/COFF specification
//! - TI COFF specification (TMS320C55x, TMS320C6000)
//! - <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-file-header>

use std::fmt;

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// Max length (in bytes) of an in-place section name.
pub const SECTION_NAME_LENGTH: usize = 8;
/// Max length (in bytes) of an in-place symbol name.
pub const SYMBOL_NAME_LENGTH: usize = 8;
/// Length (in bytes) of a COFF symbol entry.
pub const SYMBOL_SIZEOF: usize = 18;
/// Max length of a file name in the symbol table.
pub const FILE_NAME_LENGTH: usize = 14;
/// Number of dimensions of a symbol's auxiliary array.
pub const AUXILIARY_ARRAY_DIMENSION: usize = 4;
/// Size of a COFF file header in bytes.
pub const COFF_FILE_HEADER_SIZE: usize = 20;
/// Size of a COFF section header in bytes.
pub const COFF_SECTION_HEADER_SIZE: usize = 40;
/// Size of a COFF relocation entry in bytes.
pub const COFF_RELOCATION_SIZE: usize = 10;
/// Size of a COFF line number entry in bytes.
pub const COFF_LINE_NUMBER_SIZE: usize = 6;

// ═══════════════════════════════════════════════════════════════════════════════════
// Machine Types
// ═══════════════════════════════════════════════════════════════════════════════════

/// COFF machine type constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CoffMachineType {
    /// Unknown machine type.
    Unknown = 0x0000,
    /// Alpha AXP.
    Alpha = 0x0184,
    /// Alpha 64.
    Alpha64 = 0x0284,
    /// Matsushita AM33.
    Am33 = 0x01D3,
    /// x64 (AMD64).
    Amd64 = 0x8664,
    /// ARM little endian.
    Arm = 0x01C0,
    /// ARM64 little endian.
    Arm64 = 0xAA64,
    /// ARM Thumb-2.
    ArmNt = 0x01C4,
    /// EFI byte code.
    Ebc = 0x0EBC,
    /// Intel 386+.
    I386 = 0x014C,
    /// Intel Itanium.
    Ia64 = 0x0200,
    /// LoongArch 32-bit.
    LoongArch32 = 0x6232,
    /// LoongArch 64-bit.
    LoongArch64 = 0x6264,
    /// Mitsubishi M32R.
    M32R = 0x9041,
    /// MIPS16.
    Mips16 = 0x0266,
    /// MIPS with FPU.
    MipsFpu = 0x0366,
    /// MIPS16 with FPU.
    MipsFpu16 = 0x0466,
    /// PowerPC little endian.
    PowerPc = 0x01F0,
    /// PowerPC with floating point.
    PowerPcFp = 0x01F1,
    /// MIPS R3000.
    R3000 = 0x0162,
    /// MIPS R4000.
    R4000 = 0x0166,
    /// MIPS R10000.
    R10000 = 0x0168,
    /// RISC-V 32-bit.
    RiscV32 = 0x5032,
    /// RISC-V 64-bit.
    RiscV64 = 0x5064,
    /// RISC-V 128-bit.
    RiscV128 = 0x5128,
    /// Hitachi SH3.
    Sh3 = 0x01A2,
    /// Hitachi SH3 DSP.
    Sh3Dsp = 0x01A3,
    /// Hitachi SH4.
    Sh4 = 0x01A6,
    /// Hitachi SH5.
    Sh5 = 0x01A8,
    /// Thumb.
    Thumb = 0x01C2,
    /// MIPS little-endian WCE v2.
    WceMipsV2 = 0x0169,
    /// TI COFF1 magic.
    TiCoff1 = 0x00C1,
    /// TI COFF2 magic.
    TiCoff2 = 0x00C2,
    /// Motorola 68000.
    M68K = 0x0268,
    /// AMD Am29000 big endian.
    Am29KBig = 0x017A,
    /// AMD Am29000 little endian.
    Am29KLittle = 0x017B,
    /// TI TMS320C3x/4x.
    TiTms320C3x4x = 0x0093,
    /// TI TMS470.
    TiTms470 = 0x0097,
    /// TI TMS320C5400.
    TiTms320C5400 = 0x0098,
    /// TI TMS320C6000.
    TiTms320C6000 = 0x0099,
    /// TI TMS320C5500.
    TiTms320C5500 = 0x009C,
    /// TI TMS320C2800.
    TiTms320C2800 = 0x009D,
    /// TI MSP430.
    TiMsp430 = 0x00A0,
    /// TI TMS320C5500+.
    TiTms320C5500Plus = 0x00A1,
    /// Unknown value (for fallback).
    Other(u16),
}

impl CoffMachineType {
    /// Parse from a raw u16 value.
    pub fn from_u16(val: u16) -> Self {
        match val {
            0x0000 => Self::Unknown,
            0x0184 => Self::Alpha,
            0x0284 => Self::Alpha64,
            0x01D3 => Self::Am33,
            0x8664 => Self::Amd64,
            0x01C0 => Self::Arm,
            0xAA64 => Self::Arm64,
            0x01C4 => Self::ArmNt,
            0x0EBC => Self::Ebc,
            0x014C => Self::I386,
            0x0200 => Self::Ia64,
            0x6232 => Self::LoongArch32,
            0x6264 => Self::LoongArch64,
            0x9041 => Self::M32R,
            0x0266 => Self::Mips16,
            0x0366 => Self::MipsFpu,
            0x0466 => Self::MipsFpu16,
            0x01F0 => Self::PowerPc,
            0x01F1 => Self::PowerPcFp,
            0x0162 => Self::R3000,
            0x0166 => Self::R4000,
            0x0168 => Self::R10000,
            0x5032 => Self::RiscV32,
            0x5064 => Self::RiscV64,
            0x5128 => Self::RiscV128,
            0x01A2 => Self::Sh3,
            0x01A3 => Self::Sh3Dsp,
            0x01A6 => Self::Sh4,
            0x01A8 => Self::Sh5,
            0x01C2 => Self::Thumb,
            0x0169 => Self::WceMipsV2,
            0x00C1 => Self::TiCoff1,
            0x00C2 => Self::TiCoff2,
            0x0268 => Self::M68K,
            0x017A => Self::Am29KBig,
            0x017B => Self::Am29KLittle,
            0x0093 => Self::TiTms320C3x4x,
            0x0097 => Self::TiTms470,
            0x0098 => Self::TiTms320C5400,
            0x0099 => Self::TiTms320C6000,
            0x009C => Self::TiTms320C5500,
            0x009D => Self::TiTms320C2800,
            0x00A0 => Self::TiMsp430,
            0x00A1 => Self::TiTms320C5500Plus,
            other => Self::Other(other),
        }
    }

    /// Return the raw u16 value.
    pub fn to_u16(&self) -> u16 {
        match self {
            Self::Unknown => 0x0000,
            Self::Alpha => 0x0184,
            Self::Alpha64 => 0x0284,
            Self::Am33 => 0x01D3,
            Self::Amd64 => 0x8664,
            Self::Arm => 0x01C0,
            Self::Arm64 => 0xAA64,
            Self::ArmNt => 0x01C4,
            Self::Ebc => 0x0EBC,
            Self::I386 => 0x014C,
            Self::Ia64 => 0x0200,
            Self::LoongArch32 => 0x6232,
            Self::LoongArch64 => 0x6264,
            Self::M32R => 0x9041,
            Self::Mips16 => 0x0266,
            Self::MipsFpu => 0x0366,
            Self::MipsFpu16 => 0x0466,
            Self::PowerPc => 0x01F0,
            Self::PowerPcFp => 0x01F1,
            Self::R3000 => 0x0162,
            Self::R4000 => 0x0166,
            Self::R10000 => 0x0168,
            Self::RiscV32 => 0x5032,
            Self::RiscV64 => 0x5064,
            Self::RiscV128 => 0x5128,
            Self::Sh3 => 0x01A2,
            Self::Sh3Dsp => 0x01A3,
            Self::Sh4 => 0x01A6,
            Self::Sh5 => 0x01A8,
            Self::Thumb => 0x01C2,
            Self::WceMipsV2 => 0x0169,
            Self::TiCoff1 => 0x00C1,
            Self::TiCoff2 => 0x00C2,
            Self::M68K => 0x0268,
            Self::Am29KBig => 0x017A,
            Self::Am29KLittle => 0x017B,
            Self::TiTms320C3x4x => 0x0093,
            Self::TiTms470 => 0x0097,
            Self::TiTms320C5400 => 0x0098,
            Self::TiTms320C6000 => 0x0099,
            Self::TiTms320C5500 => 0x009C,
            Self::TiTms320C2800 => 0x009D,
            Self::TiMsp430 => 0x00A0,
            Self::TiTms320C5500Plus => 0x00A1,
            Self::Other(v) => *v,
        }
    }

    /// Whether this machine type is a TI COFF variant.
    pub fn is_ti_coff(&self) -> bool {
        matches!(self, Self::TiCoff1 | Self::TiCoff2)
    }

    /// Return a human-readable name for the machine type.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Alpha => "Alpha AXP",
            Self::Alpha64 => "Alpha 64",
            Self::Am33 => "Matsushita AM33",
            Self::Amd64 => "x64 (AMD64)",
            Self::Arm => "ARM",
            Self::Arm64 => "ARM64",
            Self::ArmNt => "ARM Thumb-2",
            Self::Ebc => "EFI Byte Code",
            Self::I386 => "Intel 386",
            Self::Ia64 => "Intel Itanium",
            Self::LoongArch32 => "LoongArch 32",
            Self::LoongArch64 => "LoongArch 64",
            Self::M32R => "Mitsubishi M32R",
            Self::Mips16 => "MIPS16",
            Self::MipsFpu => "MIPS FPU",
            Self::MipsFpu16 => "MIPS16 FPU",
            Self::PowerPc => "PowerPC",
            Self::PowerPcFp => "PowerPC FP",
            Self::R3000 => "MIPS R3000",
            Self::R4000 => "MIPS R4000",
            Self::R10000 => "MIPS R10000",
            Self::RiscV32 => "RISC-V 32",
            Self::RiscV64 => "RISC-V 64",
            Self::RiscV128 => "RISC-V 128",
            Self::Sh3 => "Hitachi SH3",
            Self::Sh3Dsp => "Hitachi SH3 DSP",
            Self::Sh4 => "Hitachi SH4",
            Self::Sh5 => "Hitachi SH5",
            Self::Thumb => "Thumb",
            Self::WceMipsV2 => "WCE MIPS v2",
            Self::TiCoff1 => "TI COFF1",
            Self::TiCoff2 => "TI COFF2",
            Self::M68K => "Motorola 68000",
            Self::Am29KBig => "AMD Am29000 BE",
            Self::Am29KLittle => "AMD Am29000 LE",
            Self::TiTms320C3x4x => "TI TMS320C3x/4x",
            Self::TiTms470 => "TI TMS470",
            Self::TiTms320C5400 => "TI TMS320C5400",
            Self::TiTms320C6000 => "TI TMS320C6000",
            Self::TiTms320C5500 => "TI TMS320C5500",
            Self::TiTms320C2800 => "TI TMS320C2800",
            Self::TiMsp430 => "TI MSP430",
            Self::TiTms320C5500Plus => "TI TMS320C5500+",
            Self::Other(_) => "Other",
        }
    }
}

impl fmt::Display for CoffMachineType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (0x{:04X})", self.name(), self.to_u16())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Section Header Flags
// ═══════════════════════════════════════════════════════════════════════════════════

/// COFF section header flags.
pub mod section_flags {
    /// Regular segment.
    pub const STYP_REG: u32 = 0x0000;
    /// Dummy section.
    pub const STYP_DSECT: u32 = 0x0001;
    /// No-load segment.
    pub const STYP_NOLOAD: u32 = 0x0002;
    /// Group segment.
    pub const STYP_GROUP: u32 = 0x0004;
    /// Pad segment.
    pub const STYP_PAD: u32 = 0x0008;
    /// Copy segment.
    pub const STYP_COPY: u32 = 0x0010;
    /// Contains only executable code.
    pub const STYP_TEXT: u32 = 0x0020;
    /// Contains only initialized data.
    pub const STYP_DATA: u32 = 0x0040;
    /// Defines uninitialized data.
    pub const STYP_BSS: u32 = 0x0080;
    /// Exception section.
    pub const STYP_EXCEPT: u32 = 0x0100;
    /// Comment section.
    pub const STYP_INFO: u32 = 0x0200;
    /// Overlay section.
    pub const STYP_OVER: u32 = 0x0400;
    /// Library section.
    pub const STYP_LIB: u32 = 0x0800;
    /// Loader section.
    pub const STYP_LOADER: u32 = 0x1000;
    /// Debug section.
    pub const STYP_DEBUG: u32 = 0x2000;
    /// Type check section.
    pub const STYP_TYPECHK: u32 = 0x4000;
    /// RLD and line number overflow section.
    pub const STYP_OVRFLO: u32 = 0x8000;
}

/// Return human-readable names for the section flags.
pub fn section_flag_names(flags: u32) -> Vec<&'static str> {
    let mut names = Vec::new();
    if flags & section_flags::STYP_DSECT != 0 {
        names.push("dsect");
    }
    if flags & section_flags::STYP_NOLOAD != 0 {
        names.push("noload");
    }
    if flags & section_flags::STYP_GROUP != 0 {
        names.push("group");
    }
    if flags & section_flags::STYP_PAD != 0 {
        names.push("pad");
    }
    if flags & section_flags::STYP_COPY != 0 {
        names.push("copy");
    }
    if flags & section_flags::STYP_TEXT != 0 {
        names.push("text");
    }
    if flags & section_flags::STYP_DATA != 0 {
        names.push("data");
    }
    if flags & section_flags::STYP_BSS != 0 {
        names.push("bss");
    }
    if flags & section_flags::STYP_EXCEPT != 0 {
        names.push("except");
    }
    if flags & section_flags::STYP_INFO != 0 {
        names.push("info");
    }
    if flags & section_flags::STYP_OVER != 0 {
        names.push("over");
    }
    if flags & section_flags::STYP_LIB != 0 {
        names.push("lib");
    }
    if flags & section_flags::STYP_LOADER != 0 {
        names.push("loader");
    }
    if flags & section_flags::STYP_DEBUG != 0 {
        names.push("debug");
    }
    if flags & section_flags::STYP_TYPECHK != 0 {
        names.push("typechk");
    }
    if flags & section_flags::STYP_OVRFLO != 0 {
        names.push("ovrflo");
    }
    names
}

// ═══════════════════════════════════════════════════════════════════════════════════
// TI Target IDs
// ═══════════════════════════════════════════════════════════════════════════════════

/// TI COFF target IDs (for identifying the DSP target).
pub mod ti_target_id {
    pub const TIC2XX: u16 = 0x0092;
    pub const TIC5X: u16 = 0x0092;
    pub const TIC80: u16 = 0x0095;
    pub const TIC54X: u16 = 0x0098;
    pub const TIC64X: u16 = 0x0099;
    pub const TIC55X: u16 = 0x009C;
    pub const TIC27X: u16 = 0x009D;
}

// ═══════════════════════════════════════════════════════════════════════════════════
// CoffFileHeader
// ═══════════════════════════════════════════════════════════════════════════════════

/// COFF file header flags.
pub mod file_flags {
    /// No reloc information.
    pub const F_RELFLG: u16 = 0x0001;
    /// File is executable.
    pub const F_EXEC: u16 = 0x0002;
    /// Line numbers stripped.
    pub const F_LNNO: u16 = 0x0004;
    /// Local symbols stripped.
    pub const F_LSYMS: u16 = 0x0008;
    /// Little-endian.
    pub const F_LITTLE: u16 = 0x0100;
    /// Big-endian.
    pub const F_BIG: u16 = 0x0200;
    /// Mixed-endian.
    pub const F_LSGBIG: u16 = 0x0400;
}

/// COFF file header.
#[derive(Debug, Clone)]
pub struct CoffFileHeader {
    /// Magic number identifying the machine type.
    pub magic: u16,
    /// Number of sections.
    pub section_count: u16,
    /// Time and date stamp.
    pub timestamp: u32,
    /// File offset to the symbol table.
    pub symbol_table_pointer: u32,
    /// Number of entries in the symbol table.
    pub symbol_table_entries: u32,
    /// Size of the optional header in bytes.
    pub optional_header_size: u16,
    /// Flags.
    pub flags: u16,
    /// TI-specific target ID (only present for TI COFF files).
    pub target_id: Option<u16>,
}

impl CoffFileHeader {
    /// Parse a COFF file header from a byte slice.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + COFF_FILE_HEADER_SIZE > data.len() {
            return Err("Truncated COFF file header".to_string());
        }

        let magic = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let section_count = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);
        let timestamp = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        let symbol_table_pointer = u32::from_le_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
        ]);
        let symbol_table_entries = u32::from_le_bytes([
            data[offset + 12],
            data[offset + 13],
            data[offset + 14],
            data[offset + 15],
        ]);
        let optional_header_size =
            u16::from_le_bytes([data[offset + 16], data[offset + 17]]);
        let flags = u16::from_le_bytes([data[offset + 18], data[offset + 19]]);

        let machine = CoffMachineType::from_u16(magic);
        let target_id = if machine.is_ti_coff() {
            // TI COFF has an additional 2-byte target ID after the standard header
            if offset + COFF_FILE_HEADER_SIZE + 2 <= data.len() {
                Some(u16::from_le_bytes([
                    data[offset + 20],
                    data[offset + 21],
                ]))
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            magic,
            section_count,
            timestamp,
            symbol_table_pointer,
            symbol_table_entries,
            optional_header_size,
            flags,
            target_id,
        })
    }

    /// Return the machine type.
    pub fn machine_type(&self) -> CoffMachineType {
        CoffMachineType::from_u16(self.magic)
    }

    /// Whether the file is executable.
    pub fn is_executable(&self) -> bool {
        self.flags & file_flags::F_EXEC != 0
    }

    /// Whether line numbers have been stripped.
    pub fn is_line_numbers_stripped(&self) -> bool {
        self.flags & file_flags::F_LNNO != 0
    }

    /// Whether local symbols have been stripped.
    pub fn is_local_symbols_stripped(&self) -> bool {
        self.flags & file_flags::F_LSYMS != 0
    }

    /// Whether relocation information has been stripped.
    pub fn is_relocation_stripped(&self) -> bool {
        self.flags & file_flags::F_RELFLG != 0
    }

    /// Return the endianness hint from flags.
    pub fn is_little_endian(&self) -> bool {
        self.flags & file_flags::F_LITTLE != 0 || self.flags & file_flags::F_BIG == 0
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// CoffSectionHeader
// ═══════════════════════════════════════════════════════════════════════════════════

/// COFF section header.
#[derive(Debug, Clone)]
pub struct CoffSectionHeader {
    /// Section name (8 bytes, null-padded or inline string table reference).
    pub name: String,
    /// Physical address (aliased with s_nlib for some targets).
    pub physical_address: u32,
    /// Virtual address.
    pub virtual_address: u32,
    /// Section size in bytes (or addressable units for word-oriented machines).
    pub size: u32,
    /// File pointer to raw data for this section.
    pub pointer_to_raw_data: u32,
    /// File pointer to relocations for this section.
    pub pointer_to_relocations: u32,
    /// File pointer to line numbers for this section.
    pub pointer_to_line_numbers: u32,
    /// Number of relocation entries.
    pub relocation_count: u16,
    /// Number of line number entries.
    pub line_number_count: u16,
    /// Section flags.
    pub flags: u32,
}

impl CoffSectionHeader {
    /// Parse a COFF section header from a byte slice.
    pub fn parse(data: &[u8], offset: usize, string_table_offset: usize) -> Result<Self, String> {
        if offset + COFF_SECTION_HEADER_SIZE > data.len() {
            return Err("Truncated COFF section header".to_string());
        }

        // Read the 8-byte name field
        let name_bytes = &data[offset..offset + 8];
        let name = if name_bytes[0] == 0 && name_bytes[1] == 0 && name_bytes[2] == 0 && name_bytes[3] == 0 {
            // First 4 bytes are zero: this is a string table reference
            let string_index = u32::from_le_bytes([
                name_bytes[4],
                name_bytes[5],
                name_bytes[6],
                name_bytes[7],
            ]) as usize;
            read_coff_string(data, string_table_offset + string_index)
        } else {
            // Inline name (up to 8 characters)
            let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
            String::from_utf8_lossy(&name_bytes[..end]).to_string()
        };

        let s_paddr = u32::from_le_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
        ]);
        let s_vaddr = u32::from_le_bytes([
            data[offset + 12],
            data[offset + 13],
            data[offset + 14],
            data[offset + 15],
        ]);
        let s_size = u32::from_le_bytes([
            data[offset + 16],
            data[offset + 17],
            data[offset + 18],
            data[offset + 19],
        ]);
        let s_scnptr = u32::from_le_bytes([
            data[offset + 20],
            data[offset + 21],
            data[offset + 22],
            data[offset + 23],
        ]);
        let s_relptr = u32::from_le_bytes([
            data[offset + 24],
            data[offset + 25],
            data[offset + 26],
            data[offset + 27],
        ]);
        let s_lnnoptr = u32::from_le_bytes([
            data[offset + 28],
            data[offset + 29],
            data[offset + 30],
            data[offset + 31],
        ]);
        let s_nreloc = u16::from_le_bytes([data[offset + 32], data[offset + 33]]);
        let s_nlnno = u16::from_le_bytes([data[offset + 34], data[offset + 35]]);
        let s_flags = u32::from_le_bytes([
            data[offset + 36],
            data[offset + 37],
            data[offset + 38],
            data[offset + 39],
        ]);

        Ok(Self {
            name,
            physical_address: s_paddr,
            virtual_address: s_vaddr,
            size: s_size,
            pointer_to_raw_data: s_scnptr,
            pointer_to_relocations: s_relptr,
            pointer_to_line_numbers: s_lnnoptr,
            relocation_count: s_nreloc,
            line_number_count: s_nlnno,
            flags: s_flags,
        })
    }

    /// Whether this section contains uninitialized data (BSS).
    pub fn is_uninitialized_data(&self) -> bool {
        (self.flags & section_flags::STYP_BSS) != 0 || self.pointer_to_raw_data == 0
    }

    /// Whether this section contains initialized data.
    pub fn is_initialized_data(&self) -> bool {
        (self.flags & section_flags::STYP_DATA) != 0 && (self.flags & section_flags::STYP_TEXT) == 0
    }

    /// Whether this section is a data section.
    pub fn is_data(&self) -> bool {
        self.is_initialized_data() || self.is_uninitialized_data()
    }

    /// Whether this section contains executable code.
    pub fn is_executable(&self) -> bool {
        (self.flags & section_flags::STYP_TEXT) != 0
    }

    /// Whether this section is writable.
    pub fn is_writable(&self) -> bool {
        (self.flags & section_flags::STYP_TEXT) == 0
    }

    /// Whether this section is a group.
    pub fn is_group(&self) -> bool {
        (self.flags & section_flags::STYP_GROUP) != 0
    }

    /// Whether this section is allocated in memory.
    pub fn is_allocated(&self) -> bool {
        (self.flags & section_flags::STYP_COPY) == 0
            && (self.flags & section_flags::STYP_PAD) == 0
            && (self.flags & section_flags::STYP_DSECT) == 0
    }

    /// Return the section flag names.
    pub fn flag_names(&self) -> Vec<&'static str> {
        section_flag_names(self.flags)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// CoffRelocation
// ═══════════════════════════════════════════════════════════════════════════════════

/// COFF relocation entry.
#[derive(Debug, Clone)]
pub struct CoffRelocation {
    /// Virtual address of the relocation.
    pub virtual_address: u32,
    /// Symbol table index.
    pub symbol_index: u32,
    /// Relocation type.
    pub relocation_type: u16,
}

impl CoffRelocation {
    /// Parse a COFF relocation from a byte slice.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + COFF_RELOCATION_SIZE > data.len() {
            return Err("Truncated COFF relocation".to_string());
        }

        let r_vaddr = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let r_symndx = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        let r_type = u16::from_le_bytes([data[offset + 8], data[offset + 9]]);

        Ok(Self {
            virtual_address: r_vaddr,
            symbol_index: r_symndx,
            relocation_type: r_type,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// CoffLineNumber
// ═══════════════════════════════════════════════════════════════════════════════════

/// COFF line number entry.
#[derive(Debug, Clone)]
pub struct CoffLineNumber {
    /// Address (or symbol index if this is a function entry).
    pub address: u32,
    /// Line number.
    pub line_number: u16,
}

impl CoffLineNumber {
    /// Parse a COFF line number from a byte slice.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, String> {
        if offset + COFF_LINE_NUMBER_SIZE > data.len() {
            return Err("Truncated COFF line number".to_string());
        }

        let l_addr = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let l_lnno = u16::from_le_bytes([data[offset + 4], data[offset + 5]]);

        Ok(Self {
            address: l_addr,
            line_number: l_lnno,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// CoffFile (parsed COFF object)
// ═══════════════════════════════════════════════════════════════════════════════════

/// A fully parsed COFF file.
#[derive(Debug, Clone)]
pub struct CoffFile {
    /// The file header.
    pub header: CoffFileHeader,
    /// Section headers.
    pub sections: Vec<CoffSectionHeader>,
    /// Relocations for each section (indexed by section number).
    pub relocations: Vec<Vec<CoffRelocation>>,
    /// Line numbers for each section (indexed by section number).
    pub line_numbers: Vec<Vec<CoffLineNumber>>,
}

impl CoffFile {
    /// Parse a COFF file from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        let header = CoffFileHeader::parse(data, 0)?;

        // Compute string table offset: after the symbol table
        let string_table_offset =
            header.symbol_table_pointer as usize + header.symbol_table_entries as usize * SYMBOL_SIZEOF;

        // Parse section headers (follow the optional header)
        let sections_start = COFF_FILE_HEADER_SIZE + header.optional_header_size as usize;
        let mut sections = Vec::with_capacity(header.section_count as usize);
        let mut relocations = Vec::with_capacity(header.section_count as usize);
        let mut line_numbers = Vec::with_capacity(header.section_count as usize);

        for i in 0..header.section_count as usize {
            let sec_offset = sections_start + i * COFF_SECTION_HEADER_SIZE;
            let section = CoffSectionHeader::parse(data, sec_offset, string_table_offset)?;
            sections.push(section);
        }

        // Parse relocations and line numbers for each section
        for section in &sections {
            let mut relocs = Vec::with_capacity(section.relocation_count as usize);
            if section.pointer_to_relocations > 0 {
                let mut reloc_offset = section.pointer_to_relocations as usize;
                for _ in 0..section.relocation_count {
                    if let Ok(reloc) = CoffRelocation::parse(data, reloc_offset) {
                        relocs.push(reloc);
                    }
                    reloc_offset += COFF_RELOCATION_SIZE;
                }
            }
            relocations.push(relocs);

            let mut lnums = Vec::with_capacity(section.line_number_count as usize);
            if section.pointer_to_line_numbers > 0 {
                let mut lnum_offset = section.pointer_to_line_numbers as usize;
                for _ in 0..section.line_number_count {
                    if let Ok(lnum) = CoffLineNumber::parse(data, lnum_offset) {
                        lnums.push(lnum);
                    }
                    lnum_offset += COFF_LINE_NUMBER_SIZE;
                }
            }
            line_numbers.push(lnums);
        }

        Ok(Self {
            header,
            sections,
            relocations,
            line_numbers,
        })
    }

    /// Return the machine type.
    pub fn machine_type(&self) -> CoffMachineType {
        self.header.machine_type()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Utility
// ═══════════════════════════════════════════════════════════════════════════════════

/// Read a null-terminated ASCII string from the COFF string table.
fn read_coff_string(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(data.len() - offset);
    String::from_utf8_lossy(&data[offset..offset + end]).to_string()
}

/// Check if a byte slice could be a valid COFF file.
pub fn is_coff_file(data: &[u8]) -> bool {
    if data.len() < COFF_FILE_HEADER_SIZE {
        return false;
    }
    let magic = u16::from_le_bytes([data[0], data[1]]);
    !matches!(
        CoffMachineType::from_u16(magic),
        CoffMachineType::Unknown | CoffMachineType::Other(_)
    )
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_machine_type_from_u16() {
        assert_eq!(CoffMachineType::from_u16(0x014C), CoffMachineType::I386);
        assert_eq!(CoffMachineType::from_u16(0x8664), CoffMachineType::Amd64);
        assert_eq!(CoffMachineType::from_u16(0x01C0), CoffMachineType::Arm);
        assert_eq!(CoffMachineType::from_u16(0xAA64), CoffMachineType::Arm64);
        assert_eq!(CoffMachineType::from_u16(0x00C1), CoffMachineType::TiCoff1);
        assert_eq!(CoffMachineType::from_u16(0x0000), CoffMachineType::Unknown);
    }

    #[test]
    fn test_machine_type_name() {
        assert_eq!(CoffMachineType::I386.name(), "Intel 386");
        assert_eq!(CoffMachineType::Amd64.name(), "x64 (AMD64)");
        assert_eq!(CoffMachineType::Arm64.name(), "ARM64");
    }

    #[test]
    fn test_machine_type_display() {
        let m = CoffMachineType::I386;
        assert_eq!(m.to_string(), "Intel 386 (0x014C)");
    }

    #[test]
    fn test_machine_type_is_ti_coff() {
        assert!(CoffMachineType::TiCoff1.is_ti_coff());
        assert!(CoffMachineType::TiCoff2.is_ti_coff());
        assert!(!CoffMachineType::I386.is_ti_coff());
    }

    #[test]
    fn test_machine_type_roundtrip() {
        for val in [0x014C, 0x8664, 0x01C0, 0xAA64, 0x00C1, 0x00C2] {
            let m = CoffMachineType::from_u16(val);
            assert_eq!(m.to_u16(), val);
        }
    }

    #[test]
    fn test_machine_type_other() {
        let m = CoffMachineType::from_u16(0xFFFF);
        assert_eq!(m, CoffMachineType::Other(0xFFFF));
        assert_eq!(m.to_u16(), 0xFFFF);
        assert_eq!(m.name(), "Other");
    }

    #[test]
    fn test_section_flags() {
        assert_eq!(section_flags::STYP_TEXT, 0x0020);
        assert_eq!(section_flags::STYP_DATA, 0x0040);
        assert_eq!(section_flags::STYP_BSS, 0x0080);
    }

    #[test]
    fn test_section_flag_names() {
        let names = section_flag_names(section_flags::STYP_TEXT | section_flags::STYP_DATA);
        assert!(names.contains(&"text"));
        assert!(names.contains(&"data"));
        assert!(!names.contains(&"bss"));
    }

    #[test]
    fn test_parse_file_header() {
        // Create a minimal COFF header: i386, 1 section, no symbols
        let mut data = vec![0u8; COFF_FILE_HEADER_SIZE];
        data[0..2].copy_from_slice(&0x014Cu16.to_le_bytes()); // i386
        data[2..4].copy_from_slice(&1u16.to_le_bytes()); // 1 section
        data[4..8].copy_from_slice(&1000u32.to_le_bytes()); // timestamp
        data[8..12].copy_from_slice(&0u32.to_le_bytes()); // no symbol table
        data[12..16].copy_from_slice(&0u32.to_le_bytes()); // 0 symbols
        data[16..18].copy_from_slice(&0u16.to_le_bytes()); // no optional header
        data[18..20].copy_from_slice(&(file_flags::F_EXEC | file_flags::F_LITTLE).to_le_bytes());

        let header = CoffFileHeader::parse(&data, 0).unwrap();
        assert_eq!(header.magic, 0x014C);
        assert_eq!(header.section_count, 1);
        assert_eq!(header.machine_type(), CoffMachineType::I386);
        assert!(header.is_executable());
        assert!(header.is_little_endian());
        assert!(!header.is_line_numbers_stripped());
    }

    #[test]
    fn test_parse_section_header() {
        // Build a section header with inline name ".text"
        let mut data = vec![0u8; COFF_SECTION_HEADER_SIZE + 100];
        data[0..6].copy_from_slice(b".text\0");
        // physical address
        data[8..12].copy_from_slice(&0u32.to_le_bytes());
        // virtual address
        data[12..16].copy_from_slice(&0x1000u32.to_le_bytes());
        // size
        data[16..20].copy_from_slice(&0x500u32.to_le_bytes());
        // pointer to raw data
        data[20..24].copy_from_slice(&0x200u32.to_le_bytes());
        // pointer to relocations
        data[24..28].copy_from_slice(&0u32.to_le_bytes());
        // pointer to line numbers
        data[28..32].copy_from_slice(&0u32.to_le_bytes());
        // relocation count
        data[32..34].copy_from_slice(&0u16.to_le_bytes());
        // line number count
        data[34..36].copy_from_slice(&0u16.to_le_bytes());
        // flags: TEXT
        data[36..40].copy_from_slice(&section_flags::STYP_TEXT.to_le_bytes());

        let section = CoffSectionHeader::parse(&data, 0, 0).unwrap();
        assert_eq!(section.name, ".text");
        assert_eq!(section.virtual_address, 0x1000);
        assert_eq!(section.size, 0x500);
        assert!(section.is_executable());
        assert!(!section.is_data());
        assert!(section.is_writable() == false); // TEXT sections are not writable
    }

    #[test]
    fn test_parse_section_header_bss() {
        let mut data = vec![0u8; COFF_SECTION_HEADER_SIZE];
        data[0..5].copy_from_slice(b".bss\0");
        data[16..20].copy_from_slice(&0x100u32.to_le_bytes()); // size
        data[36..40].copy_from_slice(&section_flags::STYP_BSS.to_le_bytes());

        let section = CoffSectionHeader::parse(&data, 0, 0).unwrap();
        assert_eq!(section.name, ".bss");
        assert!(section.is_uninitialized_data());
        assert!(section.is_data());
    }

    #[test]
    fn test_parse_relocation() {
        let mut data = vec![0u8; COFF_RELOCATION_SIZE];
        data[0..4].copy_from_slice(&0x100u32.to_le_bytes()); // virtual_address
        data[4..8].copy_from_slice(&5u32.to_le_bytes()); // symbol_index
        data[8..10].copy_from_slice(&0x14u16.to_le_bytes()); // type (IMAGE_REL_I386_DIR32)

        let reloc = CoffRelocation::parse(&data, 0).unwrap();
        assert_eq!(reloc.virtual_address, 0x100);
        assert_eq!(reloc.symbol_index, 5);
        assert_eq!(reloc.relocation_type, 0x14);
    }

    #[test]
    fn test_parse_line_number() {
        let mut data = vec![0u8; COFF_LINE_NUMBER_SIZE];
        data[0..4].copy_from_slice(&0x200u32.to_le_bytes()); // address
        data[4..6].copy_from_slice(&42u16.to_le_bytes()); // line number

        let lnum = CoffLineNumber::parse(&data, 0).unwrap();
        assert_eq!(lnum.address, 0x200);
        assert_eq!(lnum.line_number, 42);
    }

    #[test]
    fn test_is_coff_file() {
        // Valid i386 COFF
        let mut data = vec![0u8; COFF_FILE_HEADER_SIZE];
        data[0..2].copy_from_slice(&0x014Cu16.to_le_bytes());
        assert!(is_coff_file(&data));

        // Invalid magic
        let mut data = vec![0u8; COFF_FILE_HEADER_SIZE];
        data[0..2].copy_from_slice(&0xFFFFu16.to_le_bytes());
        assert!(!is_coff_file(&data));

        // Too short
        assert!(!is_coff_file(&[0u8; 4]));
    }

    #[test]
    fn test_file_header_flags() {
        let mut data = vec![0u8; COFF_FILE_HEADER_SIZE];
        data[0..2].copy_from_slice(&0x014Cu16.to_le_bytes());
        data[18..20].copy_from_slice(&((file_flags::F_EXEC | file_flags::F_LNNO | file_flags::F_LSYMS) as u16).to_le_bytes());

        let header = CoffFileHeader::parse(&data, 0).unwrap();
        assert!(header.is_executable());
        assert!(header.is_line_numbers_stripped());
        assert!(header.is_local_symbols_stripped());
        assert!(!header.is_relocation_stripped());
    }

    #[test]
    fn test_parse_full_coff() {
        // Build a minimal COFF file with 1 section
        let section_data_offset = COFF_FILE_HEADER_SIZE + COFF_SECTION_HEADER_SIZE;
        let raw_data = vec![0x90u8; 16]; // NOP sled
        let total_size = section_data_offset + raw_data.len();
        let mut data = vec![0u8; total_size];

        // File header
        data[0..2].copy_from_slice(&0x014Cu16.to_le_bytes()); // i386
        data[2..4].copy_from_slice(&1u16.to_le_bytes()); // 1 section
        data[4..8].copy_from_slice(&1000u32.to_le_bytes());
        data[8..12].copy_from_slice(&0u32.to_le_bytes()); // no symbols
        data[12..16].copy_from_slice(&0u32.to_le_bytes());
        data[16..18].copy_from_slice(&0u16.to_le_bytes()); // no opt hdr
        data[18..20].copy_from_slice(&(file_flags::F_EXEC | file_flags::F_LITTLE).to_le_bytes());

        // Section header
        let sec_off = COFF_FILE_HEADER_SIZE;
        data[sec_off..sec_off + 6].copy_from_slice(b".text\0");
        data[sec_off + 12..sec_off + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VA
        data[sec_off + 16..sec_off + 20].copy_from_slice(&16u32.to_le_bytes()); // size
        data[sec_off + 20..sec_off + 24].copy_from_slice(&(section_data_offset as u32).to_le_bytes());
        data[sec_off + 36..sec_off + 40].copy_from_slice(&section_flags::STYP_TEXT.to_le_bytes());

        // Raw data
        data[section_data_offset..].copy_from_slice(&raw_data);

        let coff = CoffFile::parse(&data).unwrap();
        assert_eq!(coff.header.section_count, 1);
        assert_eq!(coff.sections.len(), 1);
        assert_eq!(coff.sections[0].name, ".text");
        assert_eq!(coff.sections[0].size, 16);
        assert!(coff.sections[0].is_executable());
        assert_eq!(coff.machine_type(), CoffMachineType::I386);
    }

    #[test]
    fn test_section_header_with_string_table() {
        // Build a section with a string table reference name
        let string_table_offset = 100;
        let mut data = vec![0u8; string_table_offset + 20];

        // Section header at offset 0
        // First 4 bytes zero = string table reference
        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        // String table index = 4 (skip the 4-byte length prefix)
        data[4..8].copy_from_slice(&4u32.to_le_bytes());

        // String table at offset 100
        // First 4 bytes: total string table size
        data[string_table_offset..string_table_offset + 4]
            .copy_from_slice(&20u32.to_le_bytes());
        // String at index 4 (relative to string table start)
        data[string_table_offset + 4..string_table_offset + 4 + 8]
            .copy_from_slice(b".mydata\0");

        let section = CoffSectionHeader::parse(&data, 0, string_table_offset).unwrap();
        assert_eq!(section.name, ".mydata");
    }

    #[test]
    fn test_truncated_header() {
        let data = vec![0u8; 10]; // too small
        assert!(CoffFileHeader::parse(&data, 0).is_err());
    }

    #[test]
    fn test_ti_target_ids() {
        assert_eq!(ti_target_id::TIC54X, 0x0098);
        assert_eq!(ti_target_id::TIC55X, 0x009C);
        assert_eq!(ti_target_id::TIC64X, 0x0099);
    }
}
