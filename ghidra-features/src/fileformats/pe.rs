//! PE/COFF (Portable Executable) format parser — ultra-complete.
//!
//! Supports PE32 and PE32+ (64-bit) formats, including:
//! - DOS header (all 64 bytes) and Rich header (Visual Studio version info)
//! - NT headers: Signature, COFF File Header, Optional Header (PE32 / PE32+)
//! - All 16 data directories
//! - Section headers with all characteristics
//! - Export directory with forwarder chains
//! - Import directory (hint/name table, ordinal imports, bound imports,
//!   delay-load imports)
//! - Resource directory (recursive tree with all standard resource types)
//! - Exception directory (x64/ARM unwind info)
//! - Relocation directory (all base-relocation types)
//! - TLS directory
//! - Load Config directory (Security Cookie, SEH, CFG, RFG)
//! - Debug directory (CodeView, PDB 2.0 / 7.0, FPO)
//! - .NET CLR header
//!
//! References:
//! - [Microsoft PE and COFF Specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
//! - Ghidra's `ghidra.app.util.bin.format.pe` package

// ===========================================================================
// Imports
// ===========================================================================

use std::fmt;

use nom::{
    bytes::complete::take,
    combinator::{cond, map, map_opt, map_res, opt, verify},
    multi::{count, many0, many_till},
    number::complete::{le_u16, le_u32, le_u64, le_u8},
    sequence::tuple,
    IResult, Parser,
};

// ===========================================================================
// Error Types
// ===========================================================================

/// PE parse error.
#[derive(Debug, Clone)]
pub enum PeError {
    /// DOS e_magic != "MZ" (0x5A4D).
    InvalidDosMagic,
    /// PE signature != "PE\0\0".
    InvalidPeSignature,
    /// Unrecognised optional-header magic.
    InvalidOptionalHeaderMagic,
    /// File is too short for the requested field.
    TruncatedData,
    /// Too many sections (DoS / corrupt).
    TooManySections,
    /// Invalid RVA (points outside any section).
    InvalidRva,
    /// A nom parse error.
    ParseError(String),
    /// Generic I/O or conversion failure.
    Other(String),
}

impl fmt::Display for PeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDosMagic => write!(f, "invalid DOS magic (expected MZ)"),
            Self::InvalidPeSignature => {
                write!(f, "invalid PE signature (expected PE\\0\\0)")
            }
            Self::InvalidOptionalHeaderMagic => {
                write!(f, "invalid optional-header magic")
            }
            Self::TruncatedData => write!(f, "truncated PE data"),
            Self::TooManySections => write!(f, "too many sections"),
            Self::InvalidRva => write!(f, "RVA does not map into any section"),
            Self::ParseError(s) => write!(f, "parse error: {s}"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for PeError {}

impl<T> From<nom::Err<nom::error::Error<T>>> for PeError {
    fn from(e: nom::Err<nom::error::Error<T>>) -> Self {
        Self::ParseError(format!("{e:?}"))
    }
}

/// Type alias for PE results.
pub type PeResult<T> = Result<T, PeError>;

// ===========================================================================
// Constants
// ===========================================================================

/// PE signature bytes: "PE\0\0"
pub const PE_SIGNATURE: u32 = 0x0000_4550;

/// PE32 optional-header magic.
pub const PE32_MAGIC: u16 = 0x010b;
/// PE32+ (64-bit) optional-header magic.
pub const PE32_PLUS_MAGIC: u16 = 0x020b;
/// ROM image magic (rare).
pub const ROM_MAGIC: u16 = 0x0107;

/// Maximum permissible section count (defensive).
pub const MAX_SECTIONS: u16 = 4096;

pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

// --- Machine types ----------------------------------------------------------

pub const IMAGE_FILE_MACHINE_UNKNOWN: u16 = 0x0000;
pub const IMAGE_FILE_MACHINE_AM33: u16 = 0x01d3;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_ARM: u16 = 0x01c0;
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;
pub const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01c4;
pub const IMAGE_FILE_MACHINE_EBC: u16 = 0x0ebc;
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
pub const IMAGE_FILE_MACHINE_IA64: u16 = 0x0200;
pub const IMAGE_FILE_MACHINE_LOONGARCH32: u16 = 0x6232;
pub const IMAGE_FILE_MACHINE_LOONGARCH64: u16 = 0x6264;
pub const IMAGE_FILE_MACHINE_M32R: u16 = 0x9041;
pub const IMAGE_FILE_MACHINE_MIPS16: u16 = 0x0266;
pub const IMAGE_FILE_MACHINE_MIPSFPU: u16 = 0x0366;
pub const IMAGE_FILE_MACHINE_MIPSFPU16: u16 = 0x0466;
pub const IMAGE_FILE_MACHINE_POWERPC: u16 = 0x01f0;
pub const IMAGE_FILE_MACHINE_POWERPCFP: u16 = 0x01f1;
pub const IMAGE_FILE_MACHINE_R4000: u16 = 0x0166;
pub const IMAGE_FILE_MACHINE_RISCV32: u16 = 0x5032;
pub const IMAGE_FILE_MACHINE_RISCV64: u16 = 0x5064;
pub const IMAGE_FILE_MACHINE_RISCV128: u16 = 0x5128;
pub const IMAGE_FILE_MACHINE_SH3: u16 = 0x01a2;
pub const IMAGE_FILE_MACHINE_SH3DSP: u16 = 0x01a3;
pub const IMAGE_FILE_MACHINE_SH4: u16 = 0x01a6;
pub const IMAGE_FILE_MACHINE_SH5: u16 = 0x01a8;
pub const IMAGE_FILE_MACHINE_THUMB: u16 = 0x01c2;
pub const IMAGE_FILE_MACHINE_WCEMIPSV2: u16 = 0x0169;
pub const IMAGE_FILE_MACHINE_R3000: u16 = 0x0162;

/// Human-readable machine name.
pub fn machine_name(machine: u16) -> &'static str {
    match machine {
        IMAGE_FILE_MACHINE_UNKNOWN => "UNKNOWN",
        IMAGE_FILE_MACHINE_AM33 => "AM33",
        IMAGE_FILE_MACHINE_AMD64 => "AMD64",
        IMAGE_FILE_MACHINE_ARM => "ARM",
        IMAGE_FILE_MACHINE_ARM64 => "ARM64",
        IMAGE_FILE_MACHINE_ARMNT => "ARM NT",
        IMAGE_FILE_MACHINE_EBC => "EBC",
        IMAGE_FILE_MACHINE_I386 => "I386",
        IMAGE_FILE_MACHINE_IA64 => "IA64",
        IMAGE_FILE_MACHINE_LOONGARCH32 => "LOONGARCH32",
        IMAGE_FILE_MACHINE_LOONGARCH64 => "LOONGARCH64",
        IMAGE_FILE_MACHINE_M32R => "M32R",
        IMAGE_FILE_MACHINE_MIPS16 => "MIPS16",
        IMAGE_FILE_MACHINE_MIPSFPU => "MIPSFPU",
        IMAGE_FILE_MACHINE_MIPSFPU16 => "MIPSFPU16",
        IMAGE_FILE_MACHINE_POWERPC => "POWERPC",
        IMAGE_FILE_MACHINE_POWERPCFP => "POWERPCFP",
        IMAGE_FILE_MACHINE_R4000 => "R4000",
        IMAGE_FILE_MACHINE_RISCV32 => "RISCV32",
        IMAGE_FILE_MACHINE_RISCV64 => "RISCV64",
        IMAGE_FILE_MACHINE_RISCV128 => "RISCV128",
        IMAGE_FILE_MACHINE_SH3 => "SH3",
        IMAGE_FILE_MACHINE_SH3DSP => "SH3DSP",
        IMAGE_FILE_MACHINE_SH4 => "SH4",
        IMAGE_FILE_MACHINE_SH5 => "SH5",
        IMAGE_FILE_MACHINE_THUMB => "THUMB",
        IMAGE_FILE_MACHINE_WCEMIPSV2 => "WCEMIPSV2",
        IMAGE_FILE_MACHINE_R3000 => "R3000",
        0x0184 => "ALPHA",
        0x01a4 => "SH3E",
        0x0284 => "ALPHA64",
        0x0364 => "AXP64",
        0x2680 => "M68K",
        0x4660 => "MIPSX",
        0x84a1 => "V850",
        0xc0ee => "CEE",
        _ => "UNKNOWN",
    }
}

// --- File characteristics ---------------------------------------------------

pub const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
pub const IMAGE_FILE_LINE_NUMS_STRIPPED: u16 = 0x0004;
pub const IMAGE_FILE_LOCAL_SYMS_STRIPPED: u16 = 0x0008;
pub const IMAGE_FILE_AGGRESSIVE_WS_TRIM: u16 = 0x0010;
pub const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
pub const IMAGE_FILE_16BIT_MACHINE: u16 = 0x0040;
pub const IMAGE_FILE_BYTES_REVERSED_LO: u16 = 0x0080;
pub const IMAGE_FILE_32BIT_MACHINE: u16 = 0x0100;
pub const IMAGE_FILE_DEBUG_STRIPPED: u16 = 0x0200;
pub const IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP: u16 = 0x0400;
pub const IMAGE_FILE_NET_RUN_FROM_SWAP: u16 = 0x0800;
pub const IMAGE_FILE_SYSTEM: u16 = 0x1000;
pub const IMAGE_FILE_DLL: u16 = 0x2000;
pub const IMAGE_FILE_UP_SYSTEM_ONLY: u16 = 0x4000;
pub const IMAGE_FILE_BYTES_REVERSED_HI: u16 = 0x8000;

/// Return a set of characteristic-name strings for a characteristics value.
pub fn characteristics_names(flags: u16) -> Vec<&'static str> {
    let mut v = Vec::new();
    if flags & IMAGE_FILE_RELOCS_STRIPPED != 0 {
        v.push("RELOCS_STRIPPED");
    }
    if flags & IMAGE_FILE_EXECUTABLE_IMAGE != 0 {
        v.push("EXECUTABLE_IMAGE");
    }
    if flags & IMAGE_FILE_LINE_NUMS_STRIPPED != 0 {
        v.push("LINE_NUMS_STRIPPED");
    }
    if flags & IMAGE_FILE_LOCAL_SYMS_STRIPPED != 0 {
        v.push("LOCAL_SYMS_STRIPPED");
    }
    if flags & IMAGE_FILE_AGGRESSIVE_WS_TRIM != 0 {
        v.push("AGGRESSIVE_WS_TRIM");
    }
    if flags & IMAGE_FILE_LARGE_ADDRESS_AWARE != 0 {
        v.push("LARGE_ADDRESS_AWARE");
    }
    if flags & IMAGE_FILE_16BIT_MACHINE != 0 {
        v.push("16BIT_MACHINE");
    }
    if flags & IMAGE_FILE_BYTES_REVERSED_LO != 0 {
        v.push("BYTES_REVERSED_LO");
    }
    if flags & IMAGE_FILE_32BIT_MACHINE != 0 {
        v.push("32BIT_MACHINE");
    }
    if flags & IMAGE_FILE_DEBUG_STRIPPED != 0 {
        v.push("DEBUG_STRIPPED");
    }
    if flags & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP != 0 {
        v.push("REMOVABLE_RUN_FROM_SWAP");
    }
    if flags & IMAGE_FILE_NET_RUN_FROM_SWAP != 0 {
        v.push("NET_RUN_FROM_SWAP");
    }
    if flags & IMAGE_FILE_SYSTEM != 0 {
        v.push("SYSTEM");
    }
    if flags & IMAGE_FILE_DLL != 0 {
        v.push("DLL");
    }
    if flags & IMAGE_FILE_UP_SYSTEM_ONLY != 0 {
        v.push("UP_SYSTEM_ONLY");
    }
    if flags & IMAGE_FILE_BYTES_REVERSED_HI != 0 {
        v.push("BYTES_REVERSED_HI");
    }
    v
}

// --- Data-directory indices -------------------------------------------------

pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
pub const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: usize = 7;
pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR: usize = 8;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

pub fn directory_entry_name(index: usize) -> &'static str {
    match index {
        IMAGE_DIRECTORY_ENTRY_EXPORT => "EXPORT",
        IMAGE_DIRECTORY_ENTRY_IMPORT => "IMPORT",
        IMAGE_DIRECTORY_ENTRY_RESOURCE => "RESOURCE",
        IMAGE_DIRECTORY_ENTRY_EXCEPTION => "EXCEPTION",
        IMAGE_DIRECTORY_ENTRY_SECURITY => "SECURITY",
        IMAGE_DIRECTORY_ENTRY_BASERELOC => "BASERELOC",
        IMAGE_DIRECTORY_ENTRY_DEBUG => "DEBUG",
        IMAGE_DIRECTORY_ENTRY_ARCHITECTURE => "ARCHITECTURE",
        IMAGE_DIRECTORY_ENTRY_GLOBALPTR => "GLOBALPTR",
        IMAGE_DIRECTORY_ENTRY_TLS => "TLS",
        IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG => "LOAD_CONFIG",
        IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT => "BOUND_IMPORT",
        IMAGE_DIRECTORY_ENTRY_IAT => "IAT",
        IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT => "DELAY_IMPORT",
        IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR => "COM_DESCRIPTOR",
        15 => "RESERVED",
        _ => "UNKNOWN",
    }
}

// --- Section characteristics ------------------------------------------------

pub const IMAGE_SCN_TYPE_NO_PAD: u32 = 0x0000_0008;
pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
pub const IMAGE_SCN_LNK_OTHER: u32 = 0x0000_0100;
pub const IMAGE_SCN_LNK_INFO: u32 = 0x0000_0200;
pub const IMAGE_SCN_LNK_REMOVE: u32 = 0x0000_0800;
pub const IMAGE_SCN_LNK_COMDAT: u32 = 0x0000_1000;
pub const IMAGE_SCN_GPREL: u32 = 0x0000_8000;
pub const IMAGE_SCN_MEM_16BIT: u32 = 0x0002_0000;
pub const IMAGE_SCN_MEM_LOCKED: u32 = 0x0004_0000;
pub const IMAGE_SCN_MEM_PRELOAD: u32 = 0x0008_0000;
pub const IMAGE_SCN_ALIGN_1BYTES: u32 = 0x0010_0000;
pub const IMAGE_SCN_ALIGN_2BYTES: u32 = 0x0020_0000;
pub const IMAGE_SCN_ALIGN_4BYTES: u32 = 0x0030_0000;
pub const IMAGE_SCN_ALIGN_8BYTES: u32 = 0x0040_0000;
pub const IMAGE_SCN_ALIGN_16BYTES: u32 = 0x0050_0000;
pub const IMAGE_SCN_ALIGN_32BYTES: u32 = 0x0060_0000;
pub const IMAGE_SCN_ALIGN_64BYTES: u32 = 0x0070_0000;
pub const IMAGE_SCN_ALIGN_128BYTES: u32 = 0x0080_0000;
pub const IMAGE_SCN_ALIGN_256BYTES: u32 = 0x0090_0000;
pub const IMAGE_SCN_ALIGN_512BYTES: u32 = 0x00a0_0000;
pub const IMAGE_SCN_ALIGN_1024BYTES: u32 = 0x00b0_0000;
pub const IMAGE_SCN_ALIGN_2048BYTES: u32 = 0x00c0_0000;
pub const IMAGE_SCN_ALIGN_4096BYTES: u32 = 0x00d0_0000;
pub const IMAGE_SCN_ALIGN_8192BYTES: u32 = 0x00e0_0000;
pub const IMAGE_SCN_LNK_NRELOC_OVFL: u32 = 0x0100_0000;
pub const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
pub const IMAGE_SCN_MEM_NOT_CACHED: u32 = 0x0400_0000;
pub const IMAGE_SCN_MEM_NOT_PAGED: u32 = 0x0800_0000;
pub const IMAGE_SCN_MEM_SHARED: u32 = 0x1000_0000;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Return a set of section-characteristic strings.
pub fn section_characteristics_names(flags: u32) -> Vec<&'static str> {
    let mut v = Vec::new();
    if flags & IMAGE_SCN_TYPE_NO_PAD != 0 {
        v.push("TYPE_NO_PAD");
    }
    if flags & IMAGE_SCN_CNT_CODE != 0 {
        v.push("CNT_CODE");
    }
    if flags & IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
        v.push("CNT_INITIALIZED_DATA");
    }
    if flags & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
        v.push("CNT_UNINITIALIZED_DATA");
    }
    if flags & IMAGE_SCN_LNK_OTHER != 0 {
        v.push("LNK_OTHER");
    }
    if flags & IMAGE_SCN_LNK_INFO != 0 {
        v.push("LNK_INFO");
    }
    if flags & IMAGE_SCN_LNK_REMOVE != 0 {
        v.push("LNK_REMOVE");
    }
    if flags & IMAGE_SCN_LNK_COMDAT != 0 {
        v.push("LNK_COMDAT");
    }
    if flags & IMAGE_SCN_GPREL != 0 {
        v.push("GPREL");
    }
    if flags & IMAGE_SCN_MEM_16BIT != 0 {
        v.push("MEM_16BIT");
    }
    if flags & IMAGE_SCN_MEM_LOCKED != 0 {
        v.push("MEM_LOCKED");
    }
    if flags & IMAGE_SCN_MEM_PRELOAD != 0 {
        v.push("MEM_PRELOAD");
    }
    if flags & IMAGE_SCN_LNK_NRELOC_OVFL != 0 {
        v.push("LNK_NRELOC_OVFL");
    }
    if flags & IMAGE_SCN_MEM_DISCARDABLE != 0 {
        v.push("MEM_DISCARDABLE");
    }
    if flags & IMAGE_SCN_MEM_NOT_CACHED != 0 {
        v.push("MEM_NOT_CACHED");
    }
    if flags & IMAGE_SCN_MEM_NOT_PAGED != 0 {
        v.push("MEM_NOT_PAGED");
    }
    if flags & IMAGE_SCN_MEM_SHARED != 0 {
        v.push("MEM_SHARED");
    }
    if flags & IMAGE_SCN_MEM_EXECUTE != 0 {
        v.push("MEM_EXECUTE");
    }
    if flags & IMAGE_SCN_MEM_READ != 0 {
        v.push("MEM_READ");
    }
    if flags & IMAGE_SCN_MEM_WRITE != 0 {
        v.push("MEM_WRITE");
    }
    v
}

// --- Subsystem values -------------------------------------------------------

pub const IMAGE_SUBSYSTEM_UNKNOWN: u16 = 0;
pub const IMAGE_SUBSYSTEM_NATIVE: u16 = 1;
pub const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16 = 2;
pub const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;
pub const IMAGE_SUBSYSTEM_OS2_CUI: u16 = 5;
pub const IMAGE_SUBSYSTEM_POSIX_CUI: u16 = 7;
pub const IMAGE_SUBSYSTEM_NATIVE_WINDOWS: u16 = 8;
pub const IMAGE_SUBSYSTEM_WINDOWS_CE_GUI: u16 = 9;
pub const IMAGE_SUBSYSTEM_EFI_APPLICATION: u16 = 10;
pub const IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: u16 = 11;
pub const IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: u16 = 12;
pub const IMAGE_SUBSYSTEM_EFI_ROM: u16 = 13;
pub const IMAGE_SUBSYSTEM_XBOX: u16 = 14;
pub const IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: u16 = 16;

pub fn subsystem_name(subsystem: u16) -> &'static str {
    match subsystem {
        IMAGE_SUBSYSTEM_UNKNOWN => "UNKNOWN",
        IMAGE_SUBSYSTEM_NATIVE => "NATIVE",
        IMAGE_SUBSYSTEM_WINDOWS_GUI => "WINDOWS_GUI",
        IMAGE_SUBSYSTEM_WINDOWS_CUI => "WINDOWS_CUI",
        IMAGE_SUBSYSTEM_OS2_CUI => "OS2_CUI",
        IMAGE_SUBSYSTEM_POSIX_CUI => "POSIX_CUI",
        IMAGE_SUBSYSTEM_NATIVE_WINDOWS => "NATIVE_WINDOWS",
        IMAGE_SUBSYSTEM_WINDOWS_CE_GUI => "WINDOWS_CE_GUI",
        IMAGE_SUBSYSTEM_EFI_APPLICATION => "EFI_APPLICATION",
        IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER => "EFI_BOOT_SERVICE_DRIVER",
        IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER => "EFI_RUNTIME_DRIVER",
        IMAGE_SUBSYSTEM_EFI_ROM => "EFI_ROM",
        IMAGE_SUBSYSTEM_XBOX => "XBOX",
        IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION => "WINDOWS_BOOT_APPLICATION",
        _ => "UNKNOWN",
    }
}

// --- DLL characteristics ----------------------------------------------------

pub const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;
pub const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
pub const IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: u16 = 0x0080;
pub const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
pub const IMAGE_DLLCHARACTERISTICS_NO_ISOLATION: u16 = 0x0200;
pub const IMAGE_DLLCHARACTERISTICS_NO_SEH: u16 = 0x0400;
pub const IMAGE_DLLCHARACTERISTICS_NO_BIND: u16 = 0x0800;
pub const IMAGE_DLLCHARACTERISTICS_APPCONTAINER: u16 = 0x1000;
pub const IMAGE_DLLCHARACTERISTICS_WDM_DRIVER: u16 = 0x2000;
pub const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;
pub const IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE: u16 = 0x8000;

pub fn dll_characteristics_names(flags: u16) -> Vec<&'static str> {
    let mut v = Vec::new();
    if flags & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA != 0 {
        v.push("HIGH_ENTROPY_VA");
    }
    if flags & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0 {
        v.push("DYNAMIC_BASE");
    }
    if flags & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY != 0 {
        v.push("FORCE_INTEGRITY");
    }
    if flags & IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0 {
        v.push("NX_COMPAT");
    }
    if flags & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION != 0 {
        v.push("NO_ISOLATION");
    }
    if flags & IMAGE_DLLCHARACTERISTICS_NO_SEH != 0 {
        v.push("NO_SEH");
    }
    if flags & IMAGE_DLLCHARACTERISTICS_NO_BIND != 0 {
        v.push("NO_BIND");
    }
    if flags & IMAGE_DLLCHARACTERISTICS_APPCONTAINER != 0 {
        v.push("APPCONTAINER");
    }
    if flags & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER != 0 {
        v.push("WDM_DRIVER");
    }
    if flags & IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0 {
        v.push("GUARD_CF");
    }
    if flags & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE != 0 {
        v.push("TERMINAL_SERVER_AWARE");
    }
    v
}

// --- Resource types ---------------------------------------------------------

pub const RT_CURSOR: u32 = 1;
pub const RT_BITMAP: u32 = 2;
pub const RT_ICON: u32 = 3;
pub const RT_MENU: u32 = 4;
pub const RT_DIALOG: u32 = 5;
pub const RT_STRING: u32 = 6;
pub const RT_FONTDIR: u32 = 7;
pub const RT_FONT: u32 = 8;
pub const RT_ACCELERATOR: u32 = 9;
pub const RT_RCDATA: u32 = 10;
pub const RT_MESSAGETABLE: u32 = 11;
pub const RT_GROUP_CURSOR: u32 = 12;
pub const RT_GROUP_ICON: u32 = 14;
pub const RT_VERSION: u32 = 16;
pub const RT_DLGINCLUDE: u32 = 17;
pub const RT_PLUGPLAY: u32 = 19;
pub const RT_VXD: u32 = 20;
pub const RT_ANICURSOR: u32 = 21;
pub const RT_ANIICON: u32 = 22;
pub const RT_HTML: u32 = 23;
pub const RT_MANIFEST: u32 = 24;

pub fn resource_type_name(ty: u32) -> String {
    match ty {
        RT_CURSOR => "RT_CURSOR".into(),
        RT_BITMAP => "RT_BITMAP".into(),
        RT_ICON => "RT_ICON".into(),
        RT_MENU => "RT_MENU".into(),
        RT_DIALOG => "RT_DIALOG".into(),
        RT_STRING => "RT_STRING".into(),
        RT_FONTDIR => "RT_FONTDIR".into(),
        RT_FONT => "RT_FONT".into(),
        RT_ACCELERATOR => "RT_ACCELERATOR".into(),
        RT_RCDATA => "RT_RCDATA".into(),
        RT_MESSAGETABLE => "RT_MESSAGETABLE".into(),
        RT_GROUP_CURSOR => "RT_GROUP_CURSOR".into(),
        RT_GROUP_ICON => "RT_GROUP_ICON".into(),
        RT_VERSION => "RT_VERSION".into(),
        RT_DLGINCLUDE => "RT_DLGINCLUDE".into(),
        RT_PLUGPLAY => "RT_PLUGPLAY".into(),
        RT_VXD => "RT_VXD".into(),
        RT_ANICURSOR => "RT_ANICURSOR".into(),
        RT_ANIICON => "RT_ANIICON".into(),
        RT_HTML => "RT_HTML".into(),
        RT_MANIFEST => "RT_MANIFEST".into(),
        _ => format!("UNKNOWN({ty})"),
    }
}

// --- Relocation types -------------------------------------------------------

pub const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
pub const IMAGE_REL_BASED_HIGH: u16 = 1;
pub const IMAGE_REL_BASED_LOW: u16 = 2;
pub const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
pub const IMAGE_REL_BASED_HIGHADJ: u16 = 4;
pub const IMAGE_REL_BASED_MIPS_JMPADDR: u16 = 5;
pub const IMAGE_REL_BASED_THUMB_MOV32: u16 = 7;
pub const IMAGE_REL_BASED_DIR64: u16 = 10;

pub fn relocation_type_name(ty: u16) -> &'static str {
    match ty {
        IMAGE_REL_BASED_ABSOLUTE => "ABSOLUTE",
        IMAGE_REL_BASED_HIGH => "HIGH",
        IMAGE_REL_BASED_LOW => "LOW",
        IMAGE_REL_BASED_HIGHLOW => "HIGHLOW",
        IMAGE_REL_BASED_HIGHADJ => "HIGHADJ",
        IMAGE_REL_BASED_MIPS_JMPADDR => "MIPS_JMPADDR",
        IMAGE_REL_BASED_THUMB_MOV32 => "THUMB_MOV32",
        IMAGE_REL_BASED_DIR64 => "DIR64",
        _ => "UNKNOWN",
    }
}

// --- Debug types ------------------------------------------------------------

pub const IMAGE_DEBUG_TYPE_UNKNOWN: u32 = 0;
pub const IMAGE_DEBUG_TYPE_COFF: u32 = 1;
pub const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;
pub const IMAGE_DEBUG_TYPE_FPO: u32 = 3;
pub const IMAGE_DEBUG_TYPE_MISC: u32 = 4;
pub const IMAGE_DEBUG_TYPE_EXCEPTION: u32 = 5;
pub const IMAGE_DEBUG_TYPE_FIXUP: u32 = 6;
pub const IMAGE_DEBUG_TYPE_OMAP_TO_SRC: u32 = 7;
pub const IMAGE_DEBUG_TYPE_OMAP_FROM_SRC: u32 = 8;
pub const IMAGE_DEBUG_TYPE_BORLAND: u32 = 9;
pub const IMAGE_DEBUG_TYPE_CLSID: u32 = 11;
pub const IMAGE_DEBUG_TYPE_REPRO: u32 = 16;
pub const IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS: u32 = 20;

pub fn debug_type_name(ty: u32) -> &'static str {
    match ty {
        IMAGE_DEBUG_TYPE_UNKNOWN => "UNKNOWN",
        IMAGE_DEBUG_TYPE_COFF => "COFF",
        IMAGE_DEBUG_TYPE_CODEVIEW => "CODEVIEW",
        IMAGE_DEBUG_TYPE_FPO => "FPO",
        IMAGE_DEBUG_TYPE_MISC => "MISC",
        IMAGE_DEBUG_TYPE_EXCEPTION => "EXCEPTION",
        IMAGE_DEBUG_TYPE_FIXUP => "FIXUP",
        IMAGE_DEBUG_TYPE_OMAP_TO_SRC => "OMAP_TO_SRC",
        IMAGE_DEBUG_TYPE_OMAP_FROM_SRC => "OMAP_FROM_SRC",
        IMAGE_DEBUG_TYPE_BORLAND => "BORLAND",
        IMAGE_DEBUG_TYPE_CLSID => "CLSID",
        IMAGE_DEBUG_TYPE_REPRO => "REPRO",
        IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS => "EX_DLLCHARACTERISTICS",
        _ => "UNKNOWN",
    }
}

// --- CodeView constants -----------------------------------------------------

pub const CODEVIEW_RSDS_SIGNATURE: u32 = 0x5344_5352;
pub const CODEVIEW_NB10_SIGNATURE: u32 = 0x3031_424e;

// --- COM descriptor flags ---------------------------------------------------

pub const COMIMAGE_FLAGS_ILONLY: u32 = 0x0000_0001;
pub const COMIMAGE_FLAGS_32BITREQUIRED: u32 = 0x0000_0002;
pub const COMIMAGE_FLAGS_IL_LIBRARY: u32 = 0x0000_0004;
pub const COMIMAGE_FLAGS_STRONGNAMESIGNED: u32 = 0x0000_0008;
pub const COMIMAGE_FLAGS_NATIVE_ENTRYPOINT: u32 = 0x0000_0010;
pub const COMIMAGE_FLAGS_TRACKDEBUGDATA: u32 = 0x0001_0000;
pub const COMIMAGE_FLAGS_32BITPREFERRED: u32 = 0x0002_0000;

// ===========================================================================
// Data Structures
// ===========================================================================

/// Full DOS header (IMAGE_DOS_HEADER, 64 bytes).
#[derive(Debug, Clone)]
pub struct DosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: u32,
}

/// A single Rich-header record.
#[derive(Debug, Clone)]
pub struct RichEntry {
    pub comp_id: u32,
    pub count: u32,
}

impl RichEntry {
    pub fn prod_id(&self) -> u16 {
        (self.comp_id & 0xFFFF) as u16
    }
    pub fn build_number(&self) -> u16 {
        (self.comp_id >> 16) as u16
    }
}

/// Parsed Rich header.
#[derive(Debug, Clone)]
pub struct RichHeader {
    pub xor_key: u32,
    pub dans_magic: u32,
    pub padding: [u32; 3],
    pub entries: Vec<RichEntry>,
}

/// COFF File Header.
#[derive(Debug, Clone)]
pub struct FileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

/// Optional Header (PE32 or PE32+).
#[derive(Debug, Clone)]
pub struct OptionalHeader {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

/// IMAGE_DATA_DIRECTORY.
#[derive(Debug, Clone, Copy, Default)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

impl DataDirectory {
    pub fn name(&self, index: usize) -> &'static str {
        directory_entry_name(index)
    }
    pub fn is_present(&self) -> bool {
        self.virtual_address != 0 && self.size != 0
    }
}

/// IMAGE_SECTION_HEADER.
#[derive(Debug, Clone)]
pub struct SectionHeader {
    pub name_bytes: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_line_numbers: u32,
    pub number_of_relocations: u16,
    pub number_of_line_numbers: u16,
    pub characteristics: u32,
}

impl SectionHeader {
    pub fn name(&self) -> String {
        let end = self
            .name_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.name_bytes.len());
        String::from_utf8_lossy(&self.name_bytes[..end]).to_string()
    }
    pub fn is_code(&self) -> bool {
        self.characteristics & IMAGE_SCN_CNT_CODE != 0
    }
    pub fn is_initialized_data(&self) -> bool {
        self.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0
    }
    pub fn is_uninitialized_data(&self) -> bool {
        self.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0
    }
    pub fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }
    pub fn is_readable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_READ != 0
    }
    pub fn is_writable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_WRITE != 0
    }
}

/// Export entry.
#[derive(Debug, Clone)]
pub struct ExportEntry {
    pub ordinal: u32,
    pub name: Option<String>,
    pub rva: u32,
    pub forwarder: Option<String>,
}

/// IMAGE_EXPORT_DIRECTORY.
#[derive(Debug, Clone)]
pub struct ExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name_rva: u32,
    pub name: String,
    pub ordinal_base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_name_ordinals: u32,
    pub export_entries: Vec<ExportEntry>,
}

/// Import lookup entry.
#[derive(Debug, Clone)]
pub struct ImportEntry {
    pub hint: u16,
    pub name: String,
    pub is_ordinal: bool,
    pub ordinal: u16,
}

/// IMAGE_IMPORT_DESCRIPTOR.
#[derive(Debug, Clone)]
pub struct ImportDirectory {
    pub dll_name: String,
    pub import_lookup_table_rva: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name_rva: u32,
    pub import_address_table_rva: u32,
    pub import_entries: Vec<ImportEntry>,
}

/// IMAGE_BOUND_IMPORT_DESCRIPTOR.
#[derive(Debug, Clone)]
pub struct BoundImportDescriptor {
    pub time_date_stamp: u32,
    pub offset_module_name: u16,
    pub number_of_module_forwarder_refs: u16,
    pub name: String,
    pub forwarders: Vec<BoundForwarderRef>,
}

/// Bound forwarder reference.
#[derive(Debug, Clone)]
pub struct BoundForwarderRef {
    pub time_date_stamp: u32,
    pub offset_module_name: u16,
    pub _reserved: u16,
    pub name: String,
}

/// IMAGE_DELAY_IMPORT_DESCRIPTOR.
#[derive(Debug, Clone)]
pub struct DelayImportDescriptor {
    pub attributes: u32,
    pub name_rva: u32,
    pub module_handle_rva: u32,
    pub delay_import_address_table_rva: u32,
    pub delay_import_name_table_rva: u32,
    pub bound_delay_import_table_rva: u32,
    pub unload_delay_import_table_rva: u32,
    pub time_date_stamp: u32,
    pub name: String,
    pub import_entries: Vec<ImportEntry>,
}

/// Resource data entry (leaf node).
#[derive(Debug, Clone)]
pub struct ResourceDataEntry {
    pub data_rva: u32,
    pub size: u32,
    pub codepage: u32,
    pub reserved: u32,
}

/// A single node in the resource directory tree.
#[derive(Debug, Clone)]
pub struct ResourceDirectoryEntry {
    pub name_or_id: u32,
    pub offset_to_data: u32,
    pub directory: Option<ResourceDirectoryTable>,
    pub data_entry: Option<ResourceDataEntry>,
}

/// Resource directory table (one level of the tree).
#[derive(Debug, Clone)]
pub struct ResourceDirectoryTable {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub number_of_named_entries: u16,
    pub number_of_id_entries: u16,
    pub entries: Vec<ResourceDirectoryEntry>,
}

/// x64 runtime function entry.
#[derive(Debug, Clone)]
pub struct RuntimeFunctionX64 {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_info_address: u32,
}

/// ARM64 runtime function entry.
#[derive(Debug, Clone)]
pub struct RuntimeFunctionArm64 {
    pub begin_address: u32,
    pub _unwind_data: u32,
}

/// ARM runtime function entry.
#[derive(Debug, Clone)]
pub struct RuntimeFunctionArm {
    pub begin_address: u32,
    pub _unwind_data: u32,
}

/// Sum type for runtime function entries.
#[derive(Debug, Clone)]
pub enum RuntimeFunctionEntry {
    X64(RuntimeFunctionX64),
    Arm64(RuntimeFunctionArm64),
    Arm(RuntimeFunctionArm),
}

/// Unwind opcode.
#[derive(Debug, Clone)]
pub struct UnwindOpcode {
    pub offset_in_prolog: u8,
    pub opcode: u8,
    pub info: u16,
}

/// Unwind info for x64.
#[derive(Debug, Clone)]
pub struct UnwindInfoX64 {
    pub version: u8,
    pub flags: u8,
    pub size_of_prolog: u8,
    pub count_of_codes: u8,
    pub frame_register: u8,
    pub frame_offset: u8,
    pub exception_handler_rva: u32,
    pub opcodes: Vec<UnwindOpcode>,
}

/// Base relocation entry.
#[derive(Debug, Clone)]
pub struct BaseRelocationEntry {
    pub relocation_type: u16,
    pub offset: u16,
}

/// IMAGE_BASE_RELOCATION block.
#[derive(Debug, Clone)]
pub struct BaseRelocationBlock {
    pub virtual_address: u32,
    pub size_of_block: u32,
    pub entries: Vec<BaseRelocationEntry>,
}

/// IMAGE_TLS_DIRECTORY.
#[derive(Debug, Clone)]
pub struct TlsDirectory {
    pub start_address_of_raw_data: u64,
    pub end_address_of_raw_data: u64,
    pub address_of_index: u64,
    pub address_of_call_backs: u64,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
    pub callbacks: Vec<u64>,
}

/// IMAGE_LOAD_CONFIG_DIRECTORY (extended).
#[derive(Debug, Clone)]
pub struct LoadConfigDirectory {
    pub size: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub global_flags_clear: u32,
    pub global_flags_set: u32,
    pub critical_section_default_timeout: u32,
    pub de_commit_free_block_threshold: u64,
    pub de_commit_total_free_threshold: u64,
    pub lock_prefix_table: u64,
    pub maximum_allocation_size: u64,
    pub virtual_memory_threshold: u64,
    pub process_affinity_mask: u64,
    pub process_heap_flags: u32,
    pub csd_version: u16,
    pub dependent_load_flags: u16,
    pub edit_list: u64,
    pub security_cookie: u64,
    pub se_handler_table: u64,
    pub se_handler_count: u64,
    pub guard_cf_check_function_pointer: u64,
    pub guard_cf_dispatch_function_pointer: u64,
    pub guard_cf_function_table: u64,
    pub guard_cf_function_count: u64,
    pub guard_flags: u32,
    pub guard_address_taken_iat_entry_table: u64,
    pub guard_address_taken_iat_entry_count: u64,
    pub guard_long_jump_target_table: u64,
    pub guard_long_jump_target_count: u64,
    pub dynamic_value_reloc_table: u64,
    pub chpe_metadata_pointer: u64,
    pub guard_rf_failure_routine: u64,
    pub guard_rf_failure_routine_function_pointer: u64,
    pub dynamic_value_reloc_table_offset: u32,
    pub dynamic_value_reloc_table_section: u16,
    pub _reserved2: u16,
    pub guard_rf_verify_stack_pointer_function_pointer: u64,
    pub hot_patch_table_offset: u32,
    pub enclave_configuration_pointer: u64,
    pub volatile_metadata_pointer: u64,
    pub guard_eh_continuation_table: u64,
    pub guard_eh_continuation_count: u64,
    pub guard_xfg_check_function_pointer: u64,
    pub guard_xfg_dispatch_function_pointer: u64,
    pub guard_xfg_table_dispatch_function_pointer: u64,
    pub cast_guard_os_determined_failure_mode: u64,
    pub guard_memcpy_function_pointer: u64,
}

/// CodeView RSDS (PDB 7.0) debug info.
#[derive(Debug, Clone)]
pub struct CodeViewRsds {
    pub guid: [u8; 16],
    pub age: u32,
    pub pdb_path: String,
}

/// CodeView NB10 (PDB 2.0) debug info.
#[derive(Debug, Clone)]
pub struct CodeViewNb10 {
    pub offset: u32,
    pub timestamp: u32,
    pub age: u32,
    pub pdb_path: String,
}

/// Sum type for CodeView debugging records.
#[derive(Debug, Clone)]
pub enum CodeViewInfo {
    Rsds(CodeViewRsds),
    Nb10(CodeViewNb10),
    Unknown(Vec<u8>),
}

/// FPO (Frame Pointer Omission) data entry.
#[derive(Debug, Clone)]
pub struct FpoDataEntry {
    pub ul_off_start: u32,
    pub cb_proc_size: u32,
    pub cdw_locals: u32,
    pub cdw_params: u16,
    pub cb_prolog: u16,
    pub cb_regs: u16,
    pub f_has_seh: bool,
    pub f_use_bp: bool,
    pub reserved: u16,
    pub cb_frame: u32,
}

/// IMAGE_DEBUG_DIRECTORY entry.
#[derive(Debug, Clone)]
pub struct DebugDirectoryEntry {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub debug_type: u32,
    pub size_of_data: u32,
    pub address_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
}

/// Parsed debug information.
#[derive(Debug, Clone)]
pub struct DebugInfo {
    pub entry: DebugDirectoryEntry,
    pub codeview: Option<CodeViewInfo>,
    pub fpo_entries: Vec<FpoDataEntry>,
}

/// IMAGE_COR20_HEADER (.NET CLR header).
#[derive(Debug, Clone)]
pub struct ClrHeader {
    pub cb: u32,
    pub major_runtime_version: u16,
    pub minor_runtime_version: u16,
    pub meta_data: DataDirectory,
    pub flags: u32,
    pub entry_point_token: u32,
    pub resources: DataDirectory,
    pub strong_name_signature: DataDirectory,
    pub code_manager_table: DataDirectory,
    pub vtable_fixups: DataDirectory,
    pub export_address_table_jumps: DataDirectory,
    pub managed_native_header: DataDirectory,
}

/// The fully parsed PE file.
#[derive(Debug, Clone)]
pub struct PeFile {
    pub dos_header: DosHeader,
    pub dos_stub: Vec<u8>,
    pub rich_header: Option<RichHeader>,
    pub pe_signature: u32,
    pub file_header: FileHeader,
    pub optional_header: OptionalHeader,
    pub data_directories: Vec<DataDirectory>,
    pub sections: Vec<SectionHeader>,
    pub section_data: Vec<Vec<u8>>,
    pub exports: Option<ExportDirectory>,
    pub imports: Vec<ImportDirectory>,
    pub bound_imports: Vec<BoundImportDescriptor>,
    pub delay_imports: Vec<DelayImportDescriptor>,
    pub resources: Option<ResourceDirectoryTable>,
    pub exception_entries: Vec<RuntimeFunctionEntry>,
    pub relocations: Vec<BaseRelocationBlock>,
    pub tls: Option<TlsDirectory>,
    pub load_config: Option<LoadConfigDirectory>,
    pub debug_info: Vec<DebugInfo>,
    pub clr_header: Option<ClrHeader>,
}

impl PeFile {
    pub fn section_by_name(&self, name: &str) -> Option<&SectionHeader> {
        self.sections.iter().find(|s| s.name() == name)
    }

    pub fn section_for_rva(&self, rva: u32) -> Option<&SectionHeader> {
        self.sections.iter().find(|s| {
            let start = s.virtual_address;
            let end = start.saturating_add(s.virtual_size.max(s.size_of_raw_data));
            rva >= start && rva < end
        })
    }

    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        self.section_for_rva(rva).map(|s| {
            (rva.wrapping_sub(s.virtual_address) as usize)
                .wrapping_add(s.pointer_to_raw_data as usize)
        })
    }

    pub fn read_rva_string(&self, data: &[u8], rva: u32) -> Option<String> {
        let off = self.rva_to_offset(rva)?;
        if off >= data.len() {
            return None;
        }
        let end = data[off..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| off + p)
            .unwrap_or(data.len());
        Some(String::from_utf8_lossy(&data[off..end]).to_string())
    }

    pub fn read_rva_slice<'d>(
        &self,
        data: &'d [u8],
        rva: u32,
        size: usize,
    ) -> Option<&'d [u8]> {
        let off = self.rva_to_offset(rva)?;
        data.get(off..off.checked_add(size)?)
    }

    pub fn is_64bit(&self) -> bool {
        self.optional_header.magic == PE32_PLUS_MAGIC
    }

    pub fn is_dll(&self) -> bool {
        self.file_header.characteristics & IMAGE_FILE_DLL != 0
    }

    pub fn image_base(&self) -> u64 {
        self.optional_header.image_base
    }

    pub fn entry_point(&self) -> u32 {
        self.optional_header.entry_point
    }
}

// ===========================================================================
// Nom Parsers – Core Headers
// ===========================================================================

/// Parse a complete PE file from a byte slice.
pub fn parse_pe(data: &[u8]) -> PeResult<PeFile> {
    let (remaining, pe) = parse_pe_file(data)?;
    let _ = remaining;
    Ok(pe)
}

/// Top-level nom parser for the PE file.
fn parse_pe_file(input: &[u8]) -> IResult<&[u8], PeFile> {
    let (input, dos_header) = parse_dos_header(input)?;
    // DOS stub: bytes from current position up to e_lfanew
    let stub_len = dos_header.e_lfanew as usize - 64;
    let (input, dos_stub) = take(stub_len)(input)?;
    let stub_bytes = dos_stub.to_vec();

    // Rich header: found within the DOS stub
    let rich_header = parse_rich_header(&stub_bytes);

    // PE signature
    let (input, pe_signature) = verify(le_u32, |&s| s == PE_SIGNATURE)(input)?;

    // File header
    let (input, file_header) = parse_file_header(input)?;

    // Optional header
    let (input, optional_header) =
        parse_optional_header(input, file_header.size_of_optional_header)?;

    let is_64bit = optional_header.magic == PE32_PLUS_MAGIC;

    // Data directories
    let num_dirs = optional_header
        .number_of_rva_and_sizes
        .min(IMAGE_NUMBEROF_DIRECTORY_ENTRIES as u32) as usize;
    let (input, data_directories) = parse_data_directories(input, num_dirs)?;

    // Section headers
    let num_sections = file_header.number_of_sections as usize;
    let (input, sections) = parse_section_headers(input, num_sections)?;

    // Build the PeFile skeleton
    let mut pe = PeFile {
        dos_header,
        dos_stub: stub_bytes,
        rich_header,
        pe_signature,
        file_header,
        optional_header,
        data_directories,
        sections,
        section_data: Vec::new(),
        exports: None,
        imports: Vec::new(),
        bound_imports: Vec::new(),
        delay_imports: Vec::new(),
        resources: None,
        exception_entries: Vec::new(),
        relocations: Vec::new(),
        tls: None,
        load_config: None,
        debug_info: Vec::new(),
        clr_header: None,
    };

    // Read section raw data
    pe.section_data = read_all_section_data(input, &pe.sections);

    // Parse secondary structures
    pe.exports = parse_export_directory(input, &pe);
    pe.imports = parse_import_directories(input, &pe);
    pe.bound_imports = parse_bound_imports(input, &pe);
    pe.delay_imports = parse_delay_imports(input, &pe);
    pe.resources = parse_resource_tree(input, &pe);
    pe.exception_entries = parse_exception_directory(input, &pe, is_64bit);
    pe.relocations = parse_relocation_directory(input, &pe);
    pe.tls = parse_tls_directory(input, &pe, is_64bit);
    pe.load_config = parse_load_config_directory(input, &pe, is_64bit);
    pe.debug_info = parse_debug_directory(input, &pe);
    pe.clr_header = parse_clr_header(input, &pe);

    Ok((input, pe))
}

// ---------------------------------------------------------------------------
// DOS Header (64 bytes)
// ---------------------------------------------------------------------------

fn parse_dos_header(input: &[u8]) -> IResult<&[u8], DosHeader> {
    let (i, e_magic) = verify(le_u16, |&m| m == 0x5A4D)(input)?;
    let (i, e_cblp) = le_u16(i)?;
    let (i, e_cp) = le_u16(i)?;
    let (i, e_crlc) = le_u16(i)?;
    let (i, e_cparhdr) = le_u16(i)?;
    let (i, e_minalloc) = le_u16(i)?;
    let (i, e_maxalloc) = le_u16(i)?;
    let (i, e_ss) = le_u16(i)?;
    let (i, e_sp) = le_u16(i)?;
    let (i, e_csum) = le_u16(i)?;
    let (i, e_ip) = le_u16(i)?;
    let (i, e_cs) = le_u16(i)?;
    let (i, e_lfarlc) = le_u16(i)?;
    let (i, e_ovno) = le_u16(i)?;
    let (i, e_res_arr) = count(le_u16, 4)(i)?;
    let (i, e_oemid) = le_u16(i)?;
    let (i, e_oeminfo) = le_u16(i)?;
    let (i, e_res2_arr) = count(le_u16, 10)(i)?;
    let (i, e_lfanew) = le_u32(i)?;

    let mut e_res = [0u16; 4];
    e_res.copy_from_slice(&e_res_arr);
    let mut e_res2 = [0u16; 10];
    e_res2.copy_from_slice(&e_res2_arr);

    Ok((i, DosHeader {
        e_magic, e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc,
        e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno,
        e_res, e_oemid, e_oeminfo, e_res2, e_lfanew,
    }))
}

// ---------------------------------------------------------------------------
// Rich Header (VS version info from DOS stub)
// ---------------------------------------------------------------------------

fn parse_rich_header(stub: &[u8]) -> Option<RichHeader> {
    // Look for "Rich" marker near the end
    let rich_pos = stub.windows(4).rposition(|w| w == b"Rich")?;
    if rich_pos + 8 > stub.len() {
        return None;
    }
    let xor_key = u32::from_le_bytes(stub[rich_pos + 4..rich_pos + 8].try_into().unwrap());

    let encoded = &stub[..rich_pos];
    if encoded.len() < 20 {
        return None;
    }

    let decode_dword = |off: usize| -> u32 {
        let raw = u32::from_le_bytes(encoded[off..off + 4].try_into().unwrap());
        raw ^ xor_key
    };

    let hidden_xor_key = decode_dword(0);
    let dans_magic = decode_dword(4);
    if dans_magic != 0x536e_6144 {
        // "DanS"
        return None;
    }
    let padding = [decode_dword(8), decode_dword(12), decode_dword(16)];

    let entry_bytes = encoded.len().saturating_sub(20);
    let num_entries = entry_bytes / 8;
    let mut entries = Vec::with_capacity(num_entries);
    for i in 0..num_entries {
        let off = 20 + i * 8;
        let comp_id = decode_dword(off);
        let count = decode_dword(off + 4);
        entries.push(RichEntry { comp_id, count });
    }

    Some(RichHeader {
        xor_key: hidden_xor_key,
        dans_magic,
        padding,
        entries,
    })
}

// ---------------------------------------------------------------------------
// File Header
// ---------------------------------------------------------------------------

fn parse_file_header(input: &[u8]) -> IResult<&[u8], FileHeader> {
    let (i, machine) = le_u16(input)?;
    let (i, number_of_sections) = le_u16(i)?;
    let (i, time_date_stamp) = le_u32(i)?;
    let (i, pointer_to_symbol_table) = le_u32(i)?;
    let (i, number_of_symbols) = le_u32(i)?;
    let (i, size_of_optional_header) = le_u16(i)?;
    let (i, characteristics) = le_u16(i)?;
    Ok((i, FileHeader {
        machine,
        number_of_sections,
        time_date_stamp,
        pointer_to_symbol_table,
        number_of_symbols,
        size_of_optional_header,
        characteristics,
    }))
}

// ---------------------------------------------------------------------------
// Optional Header (PE32 / PE32+)
// ---------------------------------------------------------------------------

fn parse_optional_header(
    input: &[u8],
    size: u16,
) -> IResult<&[u8], OptionalHeader> {
    let (i, magic) = verify(le_u16, |&m| {
        m == PE32_MAGIC || m == PE32_PLUS_MAGIC || m == ROM_MAGIC
    })(input)?;
    let plus = magic == PE32_PLUS_MAGIC;

    let (i, major_linker_version) = le_u8(i)?;
    let (i, minor_linker_version) = le_u8(i)?;
    let (i, size_of_code) = le_u32(i)?;
    let (i, size_of_initialized_data) = le_u32(i)?;
    let (i, size_of_uninitialized_data) = le_u32(i)?;
    let (i, entry_point) = le_u32(i)?;
    let (i, base_of_code) = le_u32(i)?;

    // base_of_data: PE32 only
    let (i, base_of_data) = if plus {
        (i, 0u32)
    } else {
        let (ii, bod) = le_u32(i)?;
        (ii, bod)
    };

    // image_base: 8 bytes PE32+, 4 bytes PE32 (extended to u64)
    let (i, image_base) = if plus {
        let (ii, v) = le_u64(i)?;
        (ii, v)
    } else {
        let (ii, v) = le_u32(i)?;
        (ii, v as u64)
    };

    let (i, section_alignment) = le_u32(i)?;
    let (i, file_alignment) = le_u32(i)?;
    let (i, major_operating_system_version) = le_u16(i)?;
    let (i, minor_operating_system_version) = le_u16(i)?;
    let (i, major_image_version) = le_u16(i)?;
    let (i, minor_image_version) = le_u16(i)?;
    let (i, major_subsystem_version) = le_u16(i)?;
    let (i, minor_subsystem_version) = le_u16(i)?;
    let (i, win32_version_value) = le_u32(i)?;
    let (i, size_of_image) = le_u32(i)?;
    let (i, size_of_headers) = le_u32(i)?;
    let (i, checksum) = le_u32(i)?;
    let (i, subsystem) = le_u16(i)?;
    let (i, dll_characteristics) = le_u16(i)?;

    // Stack / heap sizes: u64 in PE32+, u32 in PE32
    let (i, size_of_stack_reserve) = if plus {
        let (ii, v) = le_u64(i)?;
        (ii, v)
    } else {
        let (ii, v) = le_u32(i)?;
        (ii, v as u64)
    };
    let (i, size_of_stack_commit) = if plus {
        let (ii, v) = le_u64(i)?;
        (ii, v)
    } else {
        let (ii, v) = le_u32(i)?;
        (ii, v as u64)
    };
    let (i, size_of_heap_reserve) = if plus {
        let (ii, v) = le_u64(i)?;
        (ii, v)
    } else {
        let (ii, v) = le_u32(i)?;
        (ii, v as u64)
    };
    let (i, size_of_heap_commit) = if plus {
        let (ii, v) = le_u64(i)?;
        (ii, v)
    } else {
        let (ii, v) = le_u32(i)?;
        (ii, v as u64)
    };

    let (i, loader_flags) = le_u32(i)?;
    let (i, number_of_rva_and_sizes) = le_u32(i)?;

    // Consume any remaining optional-header bytes
    let consumed: usize = if plus { 112 } else { 96 };
    let pad = size as usize - consumed;
    let (i, _) = take(pad)(i)?;

    Ok((i, OptionalHeader {
        magic,
        major_linker_version,
        minor_linker_version,
        size_of_code,
        size_of_initialized_data,
        size_of_uninitialized_data,
        entry_point,
        base_of_code,
        base_of_data,
        image_base,
        section_alignment,
        file_alignment,
        major_operating_system_version,
        minor_operating_system_version,
        major_image_version,
        minor_image_version,
        major_subsystem_version,
        minor_subsystem_version,
        win32_version_value,
        size_of_image,
        size_of_headers,
        checksum,
        subsystem,
        dll_characteristics,
        size_of_stack_reserve,
        size_of_stack_commit,
        size_of_heap_reserve,
        size_of_heap_commit,
        loader_flags,
        number_of_rva_and_sizes,
    }))
}

// ---------------------------------------------------------------------------
// Data Directories
// ---------------------------------------------------------------------------

fn parse_data_directories(
    input: &[u8],
    count: usize,
) -> IResult<&[u8], Vec<DataDirectory>> {
    let (i, dirs) = count(
        map(tuple((le_u32, le_u32)), |(va, sz)| DataDirectory {
            virtual_address: va,
            size: sz,
        }),
        count,
    )(input)?;
    Ok((i, dirs))
}

// ---------------------------------------------------------------------------
// Section Headers
// ---------------------------------------------------------------------------

fn parse_section_headers(
    input: &[u8],
    count: usize,
) -> IResult<&[u8], Vec<SectionHeader>> {
    count(parse_one_section_header, count)(input)
}

fn parse_one_section_header(input: &[u8]) -> IResult<&[u8], SectionHeader> {
    let (i, name_slice) = take(8usize)(input)?;
    let mut name_bytes = [0u8; 8];
    name_bytes.copy_from_slice(name_slice);
    let (i, virtual_size) = le_u32(i)?;
    let (i, virtual_address) = le_u32(i)?;
    let (i, size_of_raw_data) = le_u32(i)?;
    let (i, pointer_to_raw_data) = le_u32(i)?;
    let (i, pointer_to_relocations) = le_u32(i)?;
    let (i, pointer_to_line_numbers) = le_u32(i)?;
    let (i, number_of_relocations) = le_u16(i)?;
    let (i, number_of_line_numbers) = le_u16(i)?;
    let (i, characteristics) = le_u32(i)?;

    Ok((i, SectionHeader {
        name_bytes,
        virtual_size,
        virtual_address,
        size_of_raw_data,
        pointer_to_raw_data,
        pointer_to_relocations,
        pointer_to_line_numbers,
        number_of_relocations,
        number_of_line_numbers,
        characteristics,
    }))
}

fn read_all_section_data(data: &[u8], sections: &[SectionHeader]) -> Vec<Vec<u8>> {
    sections
        .iter()
        .map(|s| {
            let off = s.pointer_to_raw_data as usize;
            let len = s.size_of_raw_data as usize;
            data.get(off..off.saturating_add(len.min(data.len().saturating_sub(off))))
                .map(|sl| sl.to_vec())
                .unwrap_or_default()
        })
        .collect()
}

// ===========================================================================
// Export Directory
// ===========================================================================

fn parse_export_directory(data: &[u8], pe: &PeFile) -> Option<ExportDirectory> {
    let dd = pe.data_directories.get(IMAGE_DIRECTORY_ENTRY_EXPORT)?;
    if !dd.is_present() || dd.size < 40 {
        return None;
    }
    let off = pe.rva_to_offset(dd.virtual_address)?;
    let buf = data.get(off..)?;

    let characteristics = read_le_u32(buf, 0)?;
    let time_date_stamp = read_le_u32(buf, 4)?;
    let major_version = read_le_u16(buf, 8)?;
    let minor_version = read_le_u16(buf, 10)?;
    let name_rva = read_le_u32(buf, 12)?;
    let ordinal_base = read_le_u32(buf, 16)?;
    let number_of_functions = read_le_u32(buf, 20)?;
    let number_of_names = read_le_u32(buf, 24)?;
    let address_of_functions = read_le_u32(buf, 28)?;
    let address_of_names = read_le_u32(buf, 32)?;
    let address_of_name_ordinals = read_le_u32(buf, 36)?;

    let name = pe.read_rva_string(data, name_rva).unwrap_or_default();

    // Cap entry counts
    let n_funcs = number_of_functions.min(0x10000);
    let n_names = number_of_names.min(0x10000);

    let mut export_entries: Vec<ExportEntry> = Vec::new();

    for i in 0..n_funcs as usize {
        let rva = pe
            .rva_to_offset(address_of_functions)
            .and_then(|fo| data.get(fo + i * 4..fo + i * 4 + 4))
            .map(read_le_u32_at)
            .flatten()
            .unwrap_or(0);
        if rva == 0 {
            continue;
        }
        let ordinal = ordinal_base + i as u32;
        let forwarder = if rva >= dd.virtual_address
            && rva < dd.virtual_address.saturating_add(dd.size)
        {
            pe.read_rva_string(data, rva)
        } else {
            None
        };
        export_entries.push(ExportEntry {
            ordinal,
            name: None,
            rva,
            forwarder,
        });
    }

    // Match names to entries via ordinal table
    let name_base = pe.rva_to_offset(address_of_names);
    let ord_base = pe.rva_to_offset(address_of_name_ordinals);

    for i in 0..n_names as usize {
        let name_rva_val = name_base
            .and_then(|nb| data.get(nb + i * 4..nb + i * 4 + 4))
            .map(read_le_u32_at)
            .flatten()
            .unwrap_or(0);
        let ordinal_idx = ord_base
            .and_then(|ob| data.get(ob + i * 2..ob + i * 2 + 2))
            .map(read_le_u16_at)
            .flatten()
            .unwrap_or(0) as usize;
        if let Some(entry) = export_entries.get_mut(ordinal_idx) {
            entry.name = pe.read_rva_string(data, name_rva_val);
        }
    }

    Some(ExportDirectory {
        characteristics,
        time_date_stamp,
        major_version,
        minor_version,
        name_rva,
        name,
        ordinal_base,
        number_of_functions,
        number_of_names,
        address_of_functions,
        address_of_names,
        address_of_name_ordinals,
        export_entries,
    })
}

// ===========================================================================
// Import Directory
// ===========================================================================

fn parse_import_directories(data: &[u8], pe: &PeFile) -> Vec<ImportDirectory> {
    let dd = match pe.data_directories.get(IMAGE_DIRECTORY_ENTRY_IMPORT) {
        Some(d) if d.is_present() => d,
        _ => return Vec::new(),
    };
    let mut imports = Vec::new();
    let base = match pe.rva_to_offset(dd.virtual_address) {
        Some(o) => o,
        None => return Vec::new(),
    };

    let entry_size = 20;
    let mut idx = 0;
    loop {
        let off = base + idx * entry_size;
        let buf = match data.get(off..off + entry_size) {
            Some(b) => b,
            None => break,
        };
        let ilt_rva = read_le_u32_at(buf);
        let time_date_stamp = read_le_u32_at(&buf[4..]);
        let forwarder_chain = read_le_u32_at(&buf[8..]);
        let name_rva = read_le_u32_at(&buf[12..]);
        let iat_rva = read_le_u32_at(&buf[16..]);

        if ilt_rva == 0 && name_rva == 0 && iat_rva == 0 {
            break;
        }

        let dll_name = pe.read_rva_string(data, name_rva).unwrap_or_default();
        let lookup_rva = if ilt_rva != 0 { ilt_rva } else { iat_rva };
        let import_entries = parse_import_lookup_table(data, pe, lookup_rva, pe.is_64bit());

        imports.push(ImportDirectory {
            dll_name,
            import_lookup_table_rva: ilt_rva,
            time_date_stamp,
            forwarder_chain,
            name_rva,
            import_address_table_rva: iat_rva,
            import_entries,
        });
        idx += 1;
    }

    imports
}

fn parse_import_lookup_table(
    data: &[u8],
    pe: &PeFile,
    lookup_rva: u32,
    is_64bit: bool,
) -> Vec<ImportEntry> {
    let mut entries = Vec::new();
    let base = match pe.rva_to_offset(lookup_rva) {
        Some(o) => o,
        None => return entries,
    };
    let entry_bytes = if is_64bit { 8 } else { 4 };

    for j in 0..4096 {
        let off = base + j * entry_bytes;
        let buf = match data.get(off..off + entry_bytes) {
            Some(b) => b,
            None => break,
        };
        let val: u64 = if is_64bit {
            read_le_u64_at(buf)
        } else {
            read_le_u32_at(&buf[..4]) as u64
        };
        if val == 0 {
            break;
        }

        // Ordinal flag is bit 63 for PE32+, bit 31 for PE32
        let ordinal_flag: u64 = if is_64bit {
            0x8000_0000_0000_0000
        } else {
            0x8000_0000
        };
        if val & ordinal_flag != 0 {
            entries.push(ImportEntry {
                hint: 0,
                name: String::new(),
                is_ordinal: true,
                ordinal: (val & 0xFFFF) as u16,
            });
        } else {
            let hint_rva = (val & 0x7FFF_FFFF) as u32;
            let hint = pe
                .rva_to_offset(hint_rva)
                .and_then(|ho| data.get(ho..ho + 2))
                .map(read_le_u16_at)
                .unwrap_or(0);
            // Name starts 2 bytes after the hint
            let name = pe.read_rva_string(data, hint_rva.wrapping_add(2)).unwrap_or_default();
            entries.push(ImportEntry {
                hint,
                name,
                is_ordinal: false,
                ordinal: 0,
            });
        }
    }

    entries
}

// ===========================================================================
// Bound Imports
// ===========================================================================

fn parse_bound_imports(data: &[u8], pe: &PeFile) -> Vec<BoundImportDescriptor> {
    let dd = match pe.data_directories.get(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT) {
        Some(d) if d.is_present() => d,
        _ => return Vec::new(),
    };
    let mut result = Vec::new();
    let base = match pe.rva_to_offset(dd.virtual_address) {
        Some(o) => o,
        None => return result,
    };

    let mut idx = 0usize;
    loop {
        let off = base + idx * 8;
        let buf = match data.get(off..off + 8) {
            Some(b) => b,
            None => break,
        };
        let time_date_stamp = read_le_u32_at(buf);
        let offset_module_name = read_le_u16_at(&buf[4..]);
        let number_of_module_forwarder_refs = read_le_u16_at(&buf[6..]);

        if time_date_stamp == 0 && offset_module_name == 0 {
            break;
        }

        let name = pe
            .rva_to_offset(dd.virtual_address.wrapping_add(offset_module_name as u32))
            .and_then(|no| read_null_terminated_string(data, no));

        let mut forwarders = Vec::new();
        for f in 0..number_of_module_forwarder_refs as usize {
            let foff = base + (idx + f + 1) * 8;
            let fbuf = match data.get(foff..foff + 8) {
                Some(b) => b,
                None => break,
            };
            let fts = read_le_u32_at(fbuf);
            let fname_off = read_le_u16_at(&fbuf[4..]);
            let _reserved = read_le_u16_at(&fbuf[6..]);
            let fname = pe
                .rva_to_offset(dd.virtual_address.wrapping_add(fname_off as u32))
                .and_then(|fno| read_null_terminated_string(data, fno));

            forwarders.push(BoundForwarderRef {
                time_date_stamp: fts,
                offset_module_name: fname_off,
                _reserved,
                name: fname.unwrap_or_default(),
            });
        }

        result.push(BoundImportDescriptor {
            time_date_stamp,
            offset_module_name,
            number_of_module_forwarder_refs,
            name: name.unwrap_or_default(),
            forwarders,
        });

        idx += 1 + number_of_module_forwarder_refs as usize;
    }

    result
}

// ===========================================================================
// Delay-Load Imports
// ===========================================================================

fn parse_delay_imports(data: &[u8], pe: &PeFile) -> Vec<DelayImportDescriptor> {
    let dd = match pe.data_directories.get(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) {
        Some(d) if d.is_present() => d,
        _ => return Vec::new(),
    };
    let mut result = Vec::new();
    let base = match pe.rva_to_offset(dd.virtual_address) {
        Some(o) => o,
        None => return result,
    };
    let entry_size = 32;

    for idx in 0.. {
        let off = base + idx * entry_size;
        let buf = match data.get(off..off + entry_size) {
            Some(b) => b,
            None => break,
        };

        let attributes = read_le_u32_at(buf);
        let name_rva = read_le_u32_at(&buf[4..]);
        let module_handle_rva = read_le_u32_at(&buf[8..]);
        let delay_iat_rva = read_le_u32_at(&buf[12..]);
        let delay_int_rva = read_le_u32_at(&buf[16..]);
        let bound_delay_import_table_rva = read_le_u32_at(&buf[20..]);
        let unload_delay_import_table_rva = read_le_u32_at(&buf[24..]);
        let time_date_stamp = read_le_u32_at(&buf[28..]);

        if attributes == 0 && name_rva == 0 {
            break;
        }

        let name = pe.read_rva_string(data, name_rva).unwrap_or_default();
        let lookup_rva = if delay_int_rva != 0 {
            delay_int_rva
        } else {
            delay_iat_rva
        };
        let import_entries = parse_import_lookup_table(data, pe, lookup_rva, pe.is_64bit());

        result.push(DelayImportDescriptor {
            attributes,
            name_rva,
            module_handle_rva,
            delay_import_address_table_rva: delay_iat_rva,
            delay_import_name_table_rva: delay_int_rva,
            bound_delay_import_table_rva,
            unload_delay_import_table_rva,
            time_date_stamp,
            name,
            import_entries,
        });
    }

    result
}

// ===========================================================================
// Resource Directory (recursive tree)
// ===========================================================================

fn parse_resource_tree(data: &[u8], pe: &PeFile) -> Option<ResourceDirectoryTable> {
    let dd = pe.data_directories.get(IMAGE_DIRECTORY_ENTRY_RESOURCE)?;
    if !dd.is_present() {
        return None;
    }
    let off = pe.rva_to_offset(dd.virtual_address)?;
    parse_resource_table(data, pe, off, dd.virtual_address, 0)
}

fn parse_resource_table(
    data: &[u8],
    pe: &PeFile,
    off: usize,
    base_rva: u32,
    depth: u8,
) -> Option<ResourceDirectoryTable> {
    if depth > 3 {
        return None;
    }
    let buf = data.get(off..off + 16)?;
    let characteristics = read_le_u32_at(buf);
    let time_date_stamp = read_le_u32_at(&buf[4..]);
    let major_version = read_le_u16_at(&buf[8..]);
    let minor_version = read_le_u16_at(&buf[10..]);
    let number_of_named_entries = read_le_u16_at(&buf[12..]);
    let number_of_id_entries = read_le_u16_at(&buf[14..]);

    let total_entries =
        number_of_named_entries as usize + number_of_id_entries as usize;
    let mut entries = Vec::with_capacity(total_entries);

    for i in 0..total_entries {
        let eoff = off + 16 + i * 8;
        let ebuf = data.get(eoff..eoff + 8)?;
        let name_or_id = read_le_u32_at(ebuf);
        let offset_to_data = read_le_u32_at(&ebuf[4..]);

        let is_subdir = (offset_to_data & 0x8000_0000) != 0;
        let data_offset = (offset_to_data & 0x7FFF_FFFF) as usize;

        let (subdir, data_entry) = if is_subdir {
            let sub_off = (base_rva as usize).wrapping_add(data_offset);
            let sub_pe_off = pe.rva_to_offset(sub_off as u32)?;
            let sd = parse_resource_table(data, pe, sub_pe_off, base_rva, depth + 1);
            (sd, None)
        } else {
            let leaf_off = (base_rva as usize).wrapping_add(data_offset);
            let leaf_pe_off = pe.rva_to_offset(leaf_off as u32)?;
            let lbuf = data.get(leaf_pe_off..leaf_pe_off + 16)?;
            let de = ResourceDataEntry {
                data_rva: read_le_u32_at(lbuf),
                size: read_le_u32_at(&lbuf[4..]),
                codepage: read_le_u32_at(&lbuf[8..]),
                reserved: read_le_u32_at(&lbuf[12..]),
            };
            (None, Some(de))
        };

        entries.push(ResourceDirectoryEntry {
            name_or_id,
            offset_to_data,
            directory: subdir,
            data_entry,
        });
    }

    Some(ResourceDirectoryTable {
        characteristics,
        time_date_stamp,
        major_version,
        minor_version,
        number_of_named_entries,
        number_of_id_entries,
        entries,
    })
}

// ===========================================================================
// Exception Directory (Runtime Function Entries)
// ===========================================================================

fn parse_exception_directory(
    data: &[u8],
    pe: &PeFile,
    is_64bit: bool,
) -> Vec<RuntimeFunctionEntry> {
    let dd = match pe.data_directories.get(IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
        Some(d) if d.is_present() => d,
        _ => return Vec::new(),
    };
    let base = match pe.rva_to_offset(dd.virtual_address) {
        Some(o) => o,
        None => return Vec::new(),
    };
    let entry_size = if is_64bit { 12 } else { 8 };
    let count = (dd.size as usize).saturating_div(entry_size).min(0x10000);

    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let off = base + i * entry_size;
        let buf = match data.get(off..off + entry_size) {
            Some(b) => b,
            None => break,
        };
        if is_64bit {
            entries.push(RuntimeFunctionEntry::X64(RuntimeFunctionX64 {
                begin_address: read_le_u32_at(buf),
                end_address: read_le_u32_at(&buf[4..]),
                unwind_info_address: read_le_u32_at(&buf[8..]),
            }));
        } else {
            // ARM or ARM64 depending on machine
            let machine = pe.file_header.machine;
            if machine == IMAGE_FILE_MACHINE_ARM64 {
                entries.push(RuntimeFunctionEntry::Arm64(RuntimeFunctionArm64 {
                    begin_address: read_le_u32_at(buf),
                    _unwind_data: read_le_u32_at(&buf[4..]),
                }));
            } else {
                entries.push(RuntimeFunctionEntry::Arm(RuntimeFunctionArm {
                    begin_address: read_le_u32_at(buf),
                    _unwind_data: read_le_u32_at(&buf[4..]),
                }));
            }
        }
    }

    // Parse unwind info for x64 entries
    for entry in &mut entries {
        if let RuntimeFunctionEntry::X64(ref rf) = entry {
            let _ = parse_unwind_info_x64(data, pe, rf.unwind_info_address);
        }
    }

    entries
}

fn parse_unwind_info_x64(
    data: &[u8],
    pe: &PeFile,
    unwind_rva: u32,
) -> Option<UnwindInfoX64> {
    let off = pe.rva_to_offset(unwind_rva)?;
    let buf = data.get(off..off + 4)?;
    let version = buf[0] & 0x07;
    let flags = (buf[0] >> 3) & 0x1F;
    let size_of_prolog = buf[1];
    let count_of_codes = buf[2];
    let frame_register = buf[3] & 0x0F;
    let frame_offset = (buf[3] >> 4) & 0x0F;

    let eh_rva = if flags & 0x04 != 0 {
        // Exception handler RVA follows unwind codes
        // Unwind codes start at off+4, each code is 2 bytes
        let codes_end = off + 4 + count_of_codes as usize * 2;
        let aligned_end = (codes_end + 3) & !3;
        data.get(aligned_end..aligned_end + 4)
            .map(read_le_u32_at)
            .unwrap_or(0)
    } else {
        0
    };

    let mut opcodes = Vec::new();
    for i in 0..count_of_codes as usize {
        let code_off = off + 4 + i * 2;
        if let Some(cb) = data.get(code_off..code_off + 2) {
            opcodes.push(UnwindOpcode {
                offset_in_prolog: cb[0],
                opcode: cb[1] & 0x0F,
                info: u16::from_le_bytes([cb[1], 0x00]),
            });
        }
    }

    Some(UnwindInfoX64 {
        version,
        flags,
        size_of_prolog,
        count_of_codes,
        frame_register,
        frame_offset,
        exception_handler_rva: eh_rva,
        opcodes,
    })
}

// ===========================================================================
// Relocation Directory
// ===========================================================================

fn parse_relocation_directory(data: &[u8], pe: &PeFile) -> Vec<BaseRelocationBlock> {
    let dd = match pe.data_directories.get(IMAGE_DIRECTORY_ENTRY_BASERELOC) {
        Some(d) if d.is_present() => d,
        _ => return Vec::new(),
    };
    let mut blocks = Vec::new();
    let base = match pe.rva_to_offset(dd.virtual_address) {
        Some(o) => o,
        None => return blocks,
    };

    let mut offset = 0usize;
    loop {
        let off = base + offset;
        let hdr = match data.get(off..off + 8) {
            Some(b) => b,
            None => break,
        };
        let virtual_address = read_le_u32_at(hdr);
        let size_of_block = read_le_u32_at(&hdr[4..]);
        if size_of_block == 0 {
            break;
        }
        if size_of_block < 8 {
            break;
        }

        let entry_count = (size_of_block as usize - 8) / 2;
        let mut entries = Vec::with_capacity(entry_count);
        for j in 0..entry_count {
            let eoff = off + 8 + j * 2;
            if let Some(eb) = data.get(eoff..eoff + 2) {
                let raw = u16::from_le_bytes([eb[0], eb[1]]);
                entries.push(BaseRelocationEntry {
                    relocation_type: raw >> 12,
                    offset: raw & 0x0FFF,
                });
            }
        }

        blocks.push(BaseRelocationBlock {
            virtual_address,
            size_of_block,
            entries,
        });

        offset += size_of_block as usize;
        if offset >= dd.size as usize {
            break;
        }
    }

    blocks
}

// ===========================================================================
// TLS Directory
// ===========================================================================

fn parse_tls_directory(data: &[u8], pe: &PeFile, is_64bit: bool) -> Option<TlsDirectory> {
    let dd = pe.data_directories.get(IMAGE_DIRECTORY_ENTRY_TLS)?;
    if !dd.is_present() {
        return None;
    }
    let off = pe.rva_to_offset(dd.virtual_address)?;
    let buf = data.get(off..)?;

    if is_64bit {
        let start_va = read_le_u64_at(&buf[0..])?;
        let end_va = read_le_u64_at(&buf[8..])?;
        let address_of_index = read_le_u64_at(&buf[16..])?;
        let address_of_call_backs = read_le_u64_at(&buf[24..])?;
        let size_of_zero_fill = read_le_u32_at(&buf[32..]);
        let characteristics = read_le_u32_at(&buf[36..]);

        let callbacks = parse_tls_callbacks_64(data, pe, address_of_call_backs as u32);

        Some(TlsDirectory {
            start_address_of_raw_data: start_va,
            end_address_of_raw_data: end_va,
            address_of_index,
            address_of_call_backs,
            size_of_zero_fill,
            characteristics,
            callbacks,
        })
    } else {
        let start_va = read_le_u32_at(&buf[0..]) as u64;
        let end_va = read_le_u32_at(&buf[4..]) as u64;
        let address_of_index = read_le_u32_at(&buf[8..]) as u64;
        let address_of_call_backs = read_le_u32_at(&buf[12..]) as u64;
        let size_of_zero_fill = read_le_u32_at(&buf[16..]);
        let characteristics = read_le_u32_at(&buf[20..]);

        let callbacks = parse_tls_callbacks_32(data, pe, address_of_call_backs as u32);

        Some(TlsDirectory {
            start_address_of_raw_data: start_va,
            end_address_of_raw_data: end_va,
            address_of_index,
            address_of_call_backs,
            size_of_zero_fill,
            characteristics,
            callbacks,
        })
    }
}

fn parse_tls_callbacks_64(data: &[u8], pe: &PeFile, rva: u32) -> Vec<u64> {
    let mut callbacks = Vec::new();
    let base = match pe.rva_to_offset(rva) {
        Some(o) => o,
        None => return callbacks,
    };
    for i in 0..256 {
        let off = base + i * 8;
        if let Some(buf) = data.get(off..off + 8) {
            let addr = u64::from_le_bytes(buf.try_into().unwrap());
            if addr == 0 {
                break;
            }
            callbacks.push(addr);
        } else {
            break;
        }
    }
    callbacks
}

fn parse_tls_callbacks_32(data: &[u8], pe: &PeFile, rva: u32) -> Vec<u64> {
    let mut callbacks = Vec::new();
    let base = match pe.rva_to_offset(rva) {
        Some(o) => o,
        None => return callbacks,
    };
    for i in 0..256 {
        let off = base + i * 4;
        if let Some(buf) = data.get(off..off + 4) {
            let addr = u32::from_le_bytes(buf.try_into().unwrap());
            if addr == 0 {
                break;
            }
            callbacks.push(addr as u64);
        } else {
            break;
        }
    }
    callbacks
}

// ===========================================================================
// Load Config Directory
// ===========================================================================

fn parse_load_config_directory(
    data: &[u8],
    pe: &PeFile,
    is_64bit: bool,
) -> Option<LoadConfigDirectory> {
    let dd = pe.data_directories.get(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)?;
    if !dd.is_present() || dd.size < 64 {
        return None;
    }
    let off = pe.rva_to_offset(dd.virtual_address)?;
    let buf = data.get(off..)?;

    let size = read_le_u32_at(&buf[0..]);
    let effective = dd.size.min(size);

    let ptr_size: usize = if is_64bit { 8 } else { 4 };
    let read_ptr = |o: usize| -> u64 {
        if is_64bit {
            buf.get(o..o + 8)
                .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                .unwrap_or(0)
        } else {
            buf.get(o..o + 4)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as u64)
                .unwrap_or(0)
        }
    };

    let time_date_stamp = read_le_u32_at(&buf[4..]);
    let major_version = read_le_u16_at(&buf[8..]);
    let minor_version = read_le_u16_at(&buf[10..]);
    let global_flags_clear = read_le_u32_at(&buf[12..]);
    let global_flags_set = read_le_u32_at(&buf[16..]);
    let critical_section_default_timeout = read_le_u32_at(&buf[20..]);
    let de_commit_free_block_threshold = read_ptr(24);
    let de_commit_total_free_threshold = read_ptr(24 + ptr_size);
    let lock_prefix_table = read_ptr(24 + 2 * ptr_size);
    let maximum_allocation_size = read_ptr(24 + 3 * ptr_size);
    let virtual_memory_threshold = read_ptr(24 + 4 * ptr_size);
    let process_affinity_mask = read_ptr(24 + 5 * ptr_size);
    let off_after_affinity = 24 + 6 * ptr_size;
    let process_heap_flags = read_le_u32_at(&buf[off_after_affinity..]);
    let csd_version = read_le_u16_at(&buf[off_after_affinity + 4..]);
    let dependent_load_flags = read_le_u16_at(&buf[off_after_affinity + 6..]);
    let edit_list = read_ptr(off_after_affinity + 8);
    let security_cookie = read_ptr(off_after_affinity + 8 + ptr_size);

    let next = off_after_affinity + 8 + 2 * ptr_size;
    let se_handler_table = read_ptr(next);
    let se_handler_count = read_ptr(next + ptr_size);
    let guard_cf_check_function_pointer = read_ptr(next + 2 * ptr_size);
    let guard_cf_dispatch_function_pointer = read_ptr(next + 3 * ptr_size);
    let guard_cf_function_table = read_ptr(next + 4 * ptr_size);
    let guard_cf_function_count = read_ptr(next + 5 * ptr_size);
    let guard_flags =
        read_le_u32_at(&buf[next + 6 * ptr_size..]);
    let at1 = next + 6 * ptr_size + 4;
    let code_integrity = DataDirectory {
        virtual_address: read_le_u32_at(&buf[at1..]),
        size: read_le_u32_at(&buf[at1 + 4..]),
    };
    let at2 = at1 + 8;
    let guard_address_taken_iat_entry_table = read_ptr(at2);
    let guard_address_taken_iat_entry_count = read_ptr(at2 + ptr_size);
    let guard_long_jump_target_table = read_ptr(at2 + 2 * ptr_size);
    let guard_long_jump_target_count = read_ptr(at2 + 3 * ptr_size);
    let dynamic_value_reloc_table = read_ptr(at2 + 4 * ptr_size);
    let chpe_metadata_pointer = read_ptr(at2 + 5 * ptr_size);
    let guard_rf_failure_routine = read_ptr(at2 + 6 * ptr_size);
    let guard_rf_failure_routine_function_pointer = read_ptr(at2 + 7 * ptr_size);
    let dynamic_value_reloc_table_offset =
        read_le_u32_at(&buf[at2 + 8 * ptr_size..]);
    let dynamic_value_reloc_table_section =
        read_le_u16_at(&buf[at2 + 8 * ptr_size + 4..]);
    let _reserved2 = read_le_u16_at(&buf[at2 + 8 * ptr_size + 6..]);
    let guard_rf_verify_stack_pointer_function_pointer = read_ptr(at2 + 8 * ptr_size + 8);
    let hot_patch_table_offset = read_le_u32_at(&buf[at2 + 9 * ptr_size + 8..]);
    let _code_integrity = code_integrity;

    // Extended fields (if present)
    let ext1 = at2 + 9 * ptr_size + 12;
    let enclave_configuration_pointer = if effective as usize >= ext1 + ptr_size {
        read_ptr(ext1)
    } else {
        0
    };
    let ext2 = ext1 + ptr_size;
    let volatile_metadata_pointer = if effective as usize >= ext2 + ptr_size {
        read_ptr(ext2)
    } else {
        0
    };
    let ext3 = ext2 + ptr_size;
    let guard_eh_continuation_table = if effective as usize >= ext3 + ptr_size {
        read_ptr(ext3)
    } else {
        0
    };
    let guard_eh_continuation_count = if effective as usize >= ext3 + 2 * ptr_size {
        read_ptr(ext3 + ptr_size)
    } else {
        0
    };
    let ext5 = ext3 + 2 * ptr_size;
    let guard_xfg_check_function_pointer = if effective as usize >= ext5 + ptr_size {
        read_ptr(ext5)
    } else {
        0
    };
    let guard_xfg_dispatch_function_pointer =
        if effective as usize >= ext5 + 2 * ptr_size {
            read_ptr(ext5 + ptr_size)
        } else {
            0
        };
    let guard_xfg_table_dispatch_function_pointer =
        if effective as usize >= ext5 + 3 * ptr_size {
            read_ptr(ext5 + 2 * ptr_size)
        } else {
            0
        };
    let ext8 = ext5 + 3 * ptr_size;
    let cast_guard_os_determined_failure_mode =
        if effective as usize >= ext8 + ptr_size {
            read_ptr(ext8)
        } else {
            0
        };
    let guard_memcpy_function_pointer = if effective as usize >= ext8 + 2 * ptr_size {
        read_ptr(ext8 + ptr_size)
    } else {
        0
    };

    Some(LoadConfigDirectory {
        size,
        time_date_stamp,
        major_version,
        minor_version,
        global_flags_clear,
        global_flags_set,
        critical_section_default_timeout,
        de_commit_free_block_threshold,
        de_commit_total_free_threshold,
        lock_prefix_table,
        maximum_allocation_size,
        virtual_memory_threshold,
        process_affinity_mask,
        process_heap_flags,
        csd_version,
        dependent_load_flags,
        edit_list,
        security_cookie,
        se_handler_table,
        se_handler_count,
        guard_cf_check_function_pointer,
        guard_cf_dispatch_function_pointer,
        guard_cf_function_table,
        guard_cf_function_count,
        guard_flags,
        guard_address_taken_iat_entry_table,
        guard_address_taken_iat_entry_count,
        guard_long_jump_target_table,
        guard_long_jump_target_count,
        dynamic_value_reloc_table,
        chpe_metadata_pointer,
        guard_rf_failure_routine,
        guard_rf_failure_routine_function_pointer,
        dynamic_value_reloc_table_offset,
        dynamic_value_reloc_table_section,
        _reserved2,
        guard_rf_verify_stack_pointer_function_pointer,
        hot_patch_table_offset,
        enclave_configuration_pointer,
        volatile_metadata_pointer,
        guard_eh_continuation_table,
        guard_eh_continuation_count,
        guard_xfg_check_function_pointer,
        guard_xfg_dispatch_function_pointer,
        guard_xfg_table_dispatch_function_pointer,
        cast_guard_os_determined_failure_mode,
        guard_memcpy_function_pointer,
    })
}

// ===========================================================================
// Debug Directory
// ===========================================================================

fn parse_debug_directory(data: &[u8], pe: &PeFile) -> Vec<DebugInfo> {
    let dd = match pe.data_directories.get(IMAGE_DIRECTORY_ENTRY_DEBUG) {
        Some(d) if d.is_present() => d,
        _ => return Vec::new(),
    };
    let mut result = Vec::new();
    let base = match pe.rva_to_offset(dd.virtual_address) {
        Some(o) => o,
        None => return result,
    };
    let entry_size = 28;
    let count = (dd.size as usize).saturating_div(entry_size);

    for i in 0..count {
        let off = base + i * entry_size;
        let buf = match data.get(off..off + entry_size) {
            Some(b) => b,
            None => break,
        };
        let entry = DebugDirectoryEntry {
            characteristics: read_le_u32_at(buf),
            time_date_stamp: read_le_u32_at(&buf[4..]),
            major_version: read_le_u16_at(&buf[8..]),
            minor_version: read_le_u16_at(&buf[10..]),
            debug_type: read_le_u32_at(&buf[12..]),
            size_of_data: read_le_u32_at(&buf[16..]),
            address_of_raw_data: read_le_u32_at(&buf[20..]),
            pointer_to_raw_data: read_le_u32_at(&buf[24..]),
        };

        let raw_off = if entry.pointer_to_raw_data != 0 {
            entry.pointer_to_raw_data as usize
        } else {
            match pe.rva_to_offset(entry.address_of_raw_data) {
                Some(o) => o,
                None => {
                    result.push(DebugInfo {
                        entry,
                        codeview: None,
                        fpo_entries: Vec::new(),
                    });
                    continue;
                }
            }
        };

        let codeview = if entry.debug_type == IMAGE_DEBUG_TYPE_CODEVIEW {
            parse_codeview_info(data, raw_off, entry.size_of_data as usize)
        } else {
            None
        };

        let fpo_entries = if entry.debug_type == IMAGE_DEBUG_TYPE_FPO {
            parse_fpo_data(data, raw_off, entry.size_of_data as usize)
        } else {
            Vec::new()
        };

        result.push(DebugInfo {
            entry,
            codeview,
            fpo_entries,
        });
    }

    result
}

fn parse_codeview_info(data: &[u8], off: usize, size: usize) -> Option<CodeViewInfo> {
    let buf = data.get(off..off.saturating_add(size))?;
    if buf.len() < 4 {
        return None;
    }
    let cv_sig = u32::from_le_bytes(buf[..4].try_into().unwrap());
    match cv_sig {
        CODEVIEW_RSDS_SIGNATURE => {
            if buf.len() < 24 {
                return None;
            }
            let mut guid = [0u8; 16];
            guid.copy_from_slice(&buf[4..20]);
            let age = u32::from_le_bytes(buf[20..24].try_into().unwrap());
            let pdb_path = String::from_utf8_lossy(&buf[24..])
                .trim_end_matches('\0')
                .to_string();
            Some(CodeViewInfo::Rsds(CodeViewRsds {
                guid,
                age,
                pdb_path,
            }))
        }
        CODEVIEW_NB10_SIGNATURE => {
            if buf.len() < 16 {
                return None;
            }
            let offset = u32::from_le_bytes(buf[4..8].try_into().unwrap());
            let timestamp = u32::from_le_bytes(buf[8..12].try_into().unwrap());
            let age = u32::from_le_bytes(buf[12..16].try_into().unwrap());
            let pdb_path = String::from_utf8_lossy(&buf[16..])
                .trim_end_matches('\0')
                .to_string();
            Some(CodeViewInfo::Nb10(CodeViewNb10 {
                offset,
                timestamp,
                age,
                pdb_path,
            }))
        }
        _ => Some(CodeViewInfo::Unknown(buf.to_vec())),
    }
}

fn parse_fpo_data(data: &[u8], off: usize, size: usize) -> Vec<FpoDataEntry> {
    let mut entries = Vec::new();
    let entry_size = 16;
    let count = size.saturating_div(entry_size);

    for i in 0..count {
        let eoff = off + i * entry_size;
        let buf = match data.get(eoff..eoff + entry_size) {
            Some(b) => b,
            None => break,
        };
        let ul_off_start = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let cb_proc_size = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let cdw_locals = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        let cdw_params = u16::from_le_bytes(buf[12..14].try_into().unwrap());
        let cb_prolog = u16::from_le_bytes(buf[14..16].try_into().unwrap()) & 0xFF;
        let cb_regs = (u16::from_le_bytes(buf[14..16].try_into().unwrap()) >> 8) & 0x07;
        let f_has_seh = (u16::from_le_bytes(buf[14..16].try_into().unwrap()) >> 11) & 1 != 0;
        let f_use_bp = (u16::from_le_bytes(buf[14..16].try_into().unwrap()) >> 12) & 1 != 0;
        let reserved = (u16::from_le_bytes(buf[14..16].try_into().unwrap()) >> 13) & 0x07;
        let cb_frame = u32::from_le_bytes(buf[16..20].try_into().unwrap());

        // Actually the FPO structure is:
        // ulOffStart: u32 (0-3)
        // cbProcSize: u32 (4-7)
        // cdwLocals: u32 (8-11)
        // cdwParams: u16 (12-13)
        // bitfield: u16 (14-15)
        //   cbProlog: 8 bits
        //   cbRegs: 3 bits
        //   fHasSEH: 1 bit
        //   fUseBP: 1 bit
        //   reserved: 1 bit
        //   cbFrame: 2 bits
        let bitfield = u16::from_le_bytes(buf[14..16].try_into().unwrap());
        let cb_frame_bits = ((bitfield >> 14) & 0x03) as u32;

        entries.push(FpoDataEntry {
            ul_off_start,
            cb_proc_size,
            cdw_locals,
            cdw_params,
            cb_prolog,
            cb_regs,
            f_has_seh,
            f_use_bp,
            reserved: (bitfield >> 13) & 0x01,
            cb_frame: cb_frame_bits,
        });
    }

    entries
}

// ===========================================================================
// .NET CLR Header
// ===========================================================================

fn parse_clr_header(data: &[u8], pe: &PeFile) -> Option<ClrHeader> {
    let dd = pe
        .data_directories
        .get(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)?;
    if !dd.is_present() || dd.size < 72 {
        return None;
    }
    let off = pe.rva_to_offset(dd.virtual_address)?;
    let buf = data.get(off..)?;

    let cb = read_le_u32_at(&buf[0..]);
    let major_runtime_version = read_le_u16_at(&buf[4..]);
    let minor_runtime_version = read_le_u16_at(&buf[6..]);

    let meta_data = DataDirectory {
        virtual_address: read_le_u32_at(&buf[8..]),
        size: read_le_u32_at(&buf[12..]),
    };
    let flags = read_le_u32_at(&buf[16..]);
    let entry_point_token = read_le_u32_at(&buf[20..]);

    let resources = DataDirectory {
        virtual_address: read_le_u32_at(&buf[24..]),
        size: read_le_u32_at(&buf[28..]),
    };
    let strong_name_signature = DataDirectory {
        virtual_address: read_le_u32_at(&buf[32..]),
        size: read_le_u32_at(&buf[36..]),
    };
    let code_manager_table = DataDirectory {
        virtual_address: read_le_u32_at(&buf[40..]),
        size: read_le_u32_at(&buf[44..]),
    };
    let vtable_fixups = DataDirectory {
        virtual_address: read_le_u32_at(&buf[48..]),
        size: read_le_u32_at(&buf[52..]),
    };
    let export_address_table_jumps = DataDirectory {
        virtual_address: read_le_u32_at(&buf[56..]),
        size: read_le_u32_at(&buf[60..]),
    };
    let managed_native_header = DataDirectory {
        virtual_address: read_le_u32_at(&buf[64..]),
        size: read_le_u32_at(&buf[68..]),
    };

    Some(ClrHeader {
        cb,
        major_runtime_version,
        minor_runtime_version,
        meta_data,
        flags,
        entry_point_token,
        resources,
        strong_name_signature,
        code_manager_table,
        vtable_fixups,
        export_address_table_jumps,
        managed_native_header,
    })
}

// ===========================================================================
// Little-endian read helpers (for byte-slice, non-nom operations)
// ===========================================================================

fn read_le_u16_at(buf: &[u8]) -> u16 {
    u16::from_le_bytes([buf[0], buf[1]])
}

fn read_le_u32_at(buf: &[u8]) -> u32 {
    u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
}

fn read_le_u64_at(buf: &[u8]) -> u64 {
    u64::from_le_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ])
}

fn read_le_u16(buf: &[u8], off: usize) -> Option<u16> {
    buf.get(off..off + 2).map(read_le_u16_at)
}

fn read_le_u32(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4).map(read_le_u32_at)
}

fn read_le_u64(buf: &[u8], off: usize) -> Option<u64> {
    buf.get(off..off + 8).map(read_le_u64_at)
}

fn read_null_terminated_string(data: &[u8], off: usize) -> Option<String> {
    let slice = data.get(off..)?;
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    Some(String::from_utf8_lossy(&slice[..end]).to_string())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pe32() -> Vec<u8> {
        let mut buf = Vec::new();

        // ── DOS Header (64 bytes) ──
        buf.extend_from_slice(&0x5A4Du16.to_le_bytes()); // e_magic
        buf.extend_from_slice(&0u16.to_le_bytes()); // e_cblp
        buf.extend_from_slice(&0u16.to_le_bytes()); // e_cp
        buf.extend_from_slice(&0u16.to_le_bytes()); // e_crlc
        buf.extend_from_slice(&4u16.to_le_bytes()); // e_cparhdr
        buf.extend_from_slice(&0u16.to_le_bytes()); // e_minalloc
        buf.extend_from_slice(&0xFFFFu16.to_le_bytes()); // e_maxalloc
        buf.extend_from_slice(&0u16.to_le_bytes()); // e_ss
        buf.extend_from_slice(&0xB8u16.to_le_bytes()); // e_sp
        buf.extend_from_slice(&0u16.to_le_bytes()); // e_csum
        buf.extend_from_slice(&0u16.to_le_bytes()); // e_ip
        buf.extend_from_slice(&0u16.to_le_bytes()); // e_cs
        buf.extend_from_slice(&0x40u16.to_le_bytes()); // e_lfarlc
        buf.extend_from_slice(&0u16.to_le_bytes()); // e_ovno
        buf.extend_from_slice(&[0u16; 4].iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>()); // e_res
        buf.extend_from_slice(&0u16.to_le_bytes()); // e_oemid
        buf.extend_from_slice(&0u16.to_le_bytes()); // e_oeminfo
        buf.extend_from_slice(&[0u16; 10].iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>()); // e_res2
        buf.extend_from_slice(&0x0000_0080u32.to_le_bytes()); // e_lfanew = 0x80

        // ── DOS stub (pad to 0x80) ──
        buf.resize(0x80, 0u8);

        // ── PE signature ──
        buf.extend_from_slice(&PE_SIGNATURE.to_le_bytes());

        // ── COFF File Header ──
        buf.extend_from_slice(&IMAGE_FILE_MACHINE_I386.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // 0 sections
        buf.extend_from_slice(&0u32.to_le_bytes()); // timestamp
        buf.extend_from_slice(&0u32.to_le_bytes()); // pointer to symbol table
        buf.extend_from_slice(&0u32.to_le_bytes()); // number of symbols
        buf.extend_from_slice(&224u16.to_le_bytes()); // size of optional header
        buf.extend_from_slice(&(IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE).to_le_bytes());

        // ── Optional Header (PE32, 224 bytes) ──
        buf.extend_from_slice(&PE32_MAGIC.to_le_bytes());
        buf.push(14u8); // major linker
        buf.push(0u8); // minor linker
        buf.extend_from_slice(&0u32.to_le_bytes()); // size_of_code
        buf.extend_from_slice(&0u32.to_le_bytes()); // size_of_initialized_data
        buf.extend_from_slice(&0u32.to_le_bytes()); // size_of_uninitialized_data
        buf.extend_from_slice(&0x1000u32.to_le_bytes()); // entry_point
        buf.extend_from_slice(&0x1000u32.to_le_bytes()); // base_of_code
        buf.extend_from_slice(&0u32.to_le_bytes()); // base_of_data
        buf.extend_from_slice(&0x0040_0000u32.to_le_bytes()); // image_base
        buf.extend_from_slice(&0x1000u32.to_le_bytes()); // section_alignment
        buf.extend_from_slice(&0x0200u32.to_le_bytes()); // file_alignment
        buf.extend_from_slice(&6u16.to_le_bytes()); // major OS ver
        buf.extend_from_slice(&0u16.to_le_bytes()); // minor OS ver
        buf.extend_from_slice(&0u16.to_le_bytes()); // major image ver
        buf.extend_from_slice(&0u16.to_le_bytes()); // minor image ver
        buf.extend_from_slice(&6u16.to_le_bytes()); // major subsystem ver
        buf.extend_from_slice(&0u16.to_le_bytes()); // minor subsystem ver
        buf.extend_from_slice(&0u32.to_le_bytes()); // win32 version
        buf.extend_from_slice(&0x4000u32.to_le_bytes()); // size_of_image
        buf.extend_from_slice(&0x0200u32.to_le_bytes()); // size_of_headers
        buf.extend_from_slice(&0u32.to_le_bytes()); // checksum
        buf.extend_from_slice(&IMAGE_SUBSYSTEM_WINDOWS_CUI.to_le_bytes());
        buf.extend_from_slice(
            &(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
                | IMAGE_DLLCHARACTERISTICS_NX_COMPAT
                | IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE)
                .to_le_bytes(),
        );
        buf.extend_from_slice(&0x0010_0000u32.to_le_bytes()); // stack reserve
        buf.extend_from_slice(&0x1000u32.to_le_bytes()); // stack commit
        buf.extend_from_slice(&0x0010_0000u32.to_le_bytes()); // heap reserve
        buf.extend_from_slice(&0x1000u32.to_le_bytes()); // heap commit
        buf.extend_from_slice(&0u32.to_le_bytes()); // loader flags
        buf.extend_from_slice(&0x10u32.to_le_bytes()); // number of rva and sizes

        // ── 16 zero data directories ──
        buf.extend_from_slice(&vec![0u8; 16 * 8]);

        buf
    }

    #[test]
    fn test_parse_minimal_pe32() {
        let data = minimal_pe32();
        let pe = parse_pe(&data).expect("parse minimal PE32");
        assert_eq!(pe.dos_header.e_magic, 0x5A4D);
        assert_eq!(pe.dos_header.e_lfanew, 0x80);
        assert_eq!(pe.file_header.machine, IMAGE_FILE_MACHINE_I386);
        assert_eq!(pe.optional_header.magic, PE32_MAGIC);
        assert!(!pe.is_64bit());
        assert_eq!(pe.optional_header.image_base, 0x400000);
        assert_eq!(pe.optional_header.entry_point, 0x1000);
        assert!(pe.sections.is_empty());
        assert!(!pe.is_dll());
        assert_eq!(pe.data_directories.len(), 16);
    }

    #[test]
    fn test_invalid_dos_magic() {
        let data = vec![0u8; 128];
        assert!(matches!(parse_pe(&data), Err(PeError::ParseError(_))));
    }

    #[test]
    fn test_machine_name() {
        assert_eq!(machine_name(IMAGE_FILE_MACHINE_I386), "I386");
        assert_eq!(machine_name(IMAGE_FILE_MACHINE_AMD64), "AMD64");
        assert_eq!(machine_name(IMAGE_FILE_MACHINE_ARM64), "ARM64");
        assert_eq!(machine_name(IMAGE_FILE_MACHINE_IA64), "IA64");
        assert_eq!(machine_name(IMAGE_FILE_MACHINE_ARM), "ARM");
        assert_eq!(machine_name(IMAGE_FILE_MACHINE_ARMNT), "ARM NT");
    }

    #[test]
    fn test_subsystem_name() {
        assert_eq!(subsystem_name(IMAGE_SUBSYSTEM_WINDOWS_GUI), "WINDOWS_GUI");
        assert_eq!(subsystem_name(IMAGE_SUBSYSTEM_WINDOWS_CUI), "WINDOWS_CUI");
        assert_eq!(subsystem_name(IMAGE_SUBSYSTEM_NATIVE), "NATIVE");
        assert_eq!(subsystem_name(IMAGE_SUBSYSTEM_EFI_APPLICATION), "EFI_APPLICATION");
        assert_eq!(subsystem_name(IMAGE_SUBSYSTEM_XBOX), "XBOX");
    }

    #[test]
    fn test_directory_entry_name() {
        assert_eq!(directory_entry_name(0), "EXPORT");
        assert_eq!(directory_entry_name(1), "IMPORT");
        assert_eq!(directory_entry_name(2), "RESOURCE");
        assert_eq!(directory_entry_name(14), "COM_DESCRIPTOR");
    }

    #[test]
    fn test_characteristics_names() {
        let names = characteristics_names(IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL);
        assert!(names.contains(&"EXECUTABLE_IMAGE"));
        assert!(names.contains(&"DLL"));
    }

    #[test]
    fn test_dll_characteristics_names() {
        let names = dll_characteristics_names(
            IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
        );
        assert!(names.contains(&"DYNAMIC_BASE"));
        assert!(names.contains(&"NX_COMPAT"));
    }

    #[test]
    fn test_section_characteristics_names() {
        let names =
            section_characteristics_names(IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);
        assert!(names.contains(&"CNT_CODE"));
        assert!(names.contains(&"MEM_EXECUTE"));
        assert!(names.contains(&"MEM_READ"));
    }

    #[test]
    fn test_relocation_type_name() {
        assert_eq!(relocation_type_name(IMAGE_REL_BASED_ABSOLUTE), "ABSOLUTE");
        assert_eq!(relocation_type_name(IMAGE_REL_BASED_HIGHLOW), "HIGHLOW");
        assert_eq!(relocation_type_name(IMAGE_REL_BASED_DIR64), "DIR64");
    }

    #[test]
    fn test_debug_type_name() {
        assert_eq!(debug_type_name(IMAGE_DEBUG_TYPE_CODEVIEW), "CODEVIEW");
        assert_eq!(debug_type_name(IMAGE_DEBUG_TYPE_FPO), "FPO");
        assert_eq!(debug_type_name(IMAGE_DEBUG_TYPE_REPRO), "REPRO");
    }

    #[test]
    fn test_resource_type_name() {
        assert_eq!(resource_type_name(RT_CURSOR), "RT_CURSOR");
        assert_eq!(resource_type_name(RT_ICON), "RT_ICON");
        assert_eq!(resource_type_name(RT_MANIFEST), "RT_MANIFEST");
        assert_eq!(resource_type_name(999), "UNKNOWN(999)");
    }

    #[test]
    fn test_data_directory_is_present() {
        let dd = DataDirectory {
            virtual_address: 0x1000,
            size: 0x100,
        };
        assert!(dd.is_present());
        let dd2 = DataDirectory::default();
        assert!(!dd2.is_present());
    }

    #[test]
    fn test_section_header_predicates() {
        let sh = SectionHeader {
            name_bytes: [b'.', b't', b'e', b'x', b't', 0, 0, 0],
            virtual_size: 0x1000,
            virtual_address: 0x1000,
            size_of_raw_data: 0x1000,
            pointer_to_raw_data: 0x400,
            pointer_to_relocations: 0,
            pointer_to_line_numbers: 0,
            number_of_relocations: 0,
            number_of_line_numbers: 0,
            characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        };
        assert_eq!(sh.name(), ".text");
        assert!(sh.is_code());
        assert!(sh.is_executable());
        assert!(sh.is_readable());
        assert!(!sh.is_writable());
        assert!(!sh.is_initialized_data());
        assert!(!sh.is_uninitialized_data());
    }

    #[test]
    fn test_rva_to_offset_mapping() {
        let data = minimal_pe32();
        let pe = parse_pe(&data).expect("parse minimal PE32");
        // With no sections, all RVAs fail
        assert!(pe.rva_to_offset(0x1000).is_none());
        assert!(pe.section_for_rva(0x1000).is_none());
    }

    #[test]
    fn test_rich_entry_methods() {
        let entry = RichEntry {
            comp_id: 0x000A_0060,
            count: 5,
        };
        assert_eq!(entry.prod_id(), 0x0060);
        assert_eq!(entry.build_number(), 0x000A);
    }

    // ── PE32+ (64-bit) minimal file ──

    fn minimal_pe32plus() -> Vec<u8> {
        let mut buf = Vec::new();

        // DOS Header
        buf.extend_from_slice(&0x5A4Du16.to_le_bytes());
        buf.extend_from_slice(&vec![0u8; 58]);
        buf.extend_from_slice(&0x0000_0080u32.to_le_bytes()); // e_lfanew
        buf.resize(0x80, 0);

        // PE signature
        buf.extend_from_slice(&PE_SIGNATURE.to_le_bytes());

        // COFF File Header
        buf.extend_from_slice(&IMAGE_FILE_MACHINE_AMD64.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // 0 sections
        buf.extend_from_slice(&0u32.to_le_bytes()); // timestamp
        buf.extend_from_slice(&0u32.to_le_bytes()); // symtab ptr
        buf.extend_from_slice(&0u32.to_le_bytes()); // num symbols
        buf.extend_from_slice(&240u16.to_le_bytes()); // size of optional header
        buf.extend_from_slice(
            &(IMAGE_FILE_EXECUTABLE_IMAGE
                | IMAGE_FILE_LARGE_ADDRESS_AWARE)
                .to_le_bytes(),
        );

        // Optional Header (PE32+)
        buf.extend_from_slice(&PE32_PLUS_MAGIC.to_le_bytes());
        buf.push(14u8); // major linker
        buf.push(0u8); // minor linker
        buf.extend_from_slice(&0u32.to_le_bytes()); // size_of_code
        buf.extend_from_slice(&0u32.to_le_bytes()); // size_of_init_data
        buf.extend_from_slice(&0u32.to_le_bytes()); // size_of_uninit_data
        buf.extend_from_slice(&0x1000u32.to_le_bytes()); // entry_point
        buf.extend_from_slice(&0x1000u32.to_le_bytes()); // base_of_code
        // PE32+ skips base_of_data — image_base is next
        buf.extend_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes()); // image_base
        buf.extend_from_slice(&0x1000u32.to_le_bytes()); // section_alignment
        buf.extend_from_slice(&0x0200u32.to_le_bytes()); // file_alignment
        buf.extend_from_slice(&6u16.to_le_bytes()); // major os
        buf.extend_from_slice(&0u16.to_le_bytes()); // minor os
        buf.extend_from_slice(&0u16.to_le_bytes()); // major image
        buf.extend_from_slice(&0u16.to_le_bytes()); // minor image
        buf.extend_from_slice(&6u16.to_le_bytes()); // major subsys
        buf.extend_from_slice(&0u16.to_le_bytes()); // minor subsys
        buf.extend_from_slice(&0u32.to_le_bytes()); // win32 version
        buf.extend_from_slice(&0x5000u32.to_le_bytes()); // size_of_image
        buf.extend_from_slice(&0x0200u32.to_le_bytes()); // size_of_headers
        buf.extend_from_slice(&0u32.to_le_bytes()); // checksum
        buf.extend_from_slice(&IMAGE_SUBSYSTEM_WINDOWS_CUI.to_le_bytes());
        buf.extend_from_slice(
            &(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
                | IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
                .to_le_bytes(),
        );
        buf.extend_from_slice(&0x0010_0000u64.to_le_bytes()); // stack reserve
        buf.extend_from_slice(&0x1000u64.to_le_bytes()); // stack commit
        buf.extend_from_slice(&0x0010_0000u64.to_le_bytes()); // heap reserve
        buf.extend_from_slice(&0x1000u64.to_le_bytes()); // heap commit
        buf.extend_from_slice(&0u32.to_le_bytes()); // loader flags
        buf.extend_from_slice(&0x10u32.to_le_bytes()); // num rva and sizes

        // 16 zero data directories
        buf.extend_from_slice(&vec![0u8; 16 * 8]);

        buf
    }

    #[test]
    fn test_parse_minimal_pe32plus() {
        let data = minimal_pe32plus();
        let pe = parse_pe(&data).expect("parse minimal PE32+");
        assert!(pe.is_64bit());
        assert_eq!(pe.file_header.machine, IMAGE_FILE_MACHINE_AMD64);
        assert_eq!(pe.optional_header.magic, PE32_PLUS_MAGIC);
        assert_eq!(pe.optional_header.image_base, 0x1_4000_0000);
        assert_eq!(pe.optional_header.size_of_stack_reserve, 0x100000);
        assert_eq!(pe.entry_point(), 0x1000);
    }

    #[test]
    fn test_pe32plus_characteristics() {
        let data = minimal_pe32plus();
        let pe = parse_pe(&data).expect("parse minimal PE32+");
        assert!(pe.file_header.characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE != 0);
    }
}
