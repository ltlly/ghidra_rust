//! Deep PE/COFF (Portable Executable) format parser — complete with all data directories.
//!
//! Supports PE32 and PE32+ (64-bit) formats, including:
//! - DOS header with Rich header
//! - NT headers (Signature, COFF File Header, Optional Header)
//! - All 16 data directories
//! - Section headers with raw section data
//! - Export directory (names, ordinals, forwarders)
//! - Import directory (hint/name table, ordinal imports)
//! - Resource directory (recursive tree flattened into entries with data)
//! - Exception directory (x64/ARM runtime function entries)
//! - Security directory (Authenticode certificates)
//! - Relocation directory (all base-relocation types)
//! - TLS directory with callback addresses
//! - Load Config directory (Security Cookie, SEH, CFG, XFG)
//! - Debug directory (CodeView PDB paths, RSDS / NB10)
//! - Bound import directory
//! - Delay-load import directory
//! - .NET CLR COM descriptor header
//!
//! References:
//! - [Microsoft PE and COFF Specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)

// ===========================================================================
// Imports
// ===========================================================================

use std::fmt;

use nom::{
    bytes::complete::take,
    combinator::{map, verify},
    multi::count,
    number::complete::{le_u16, le_u32, le_u64, le_u8},
    sequence::tuple,
    IResult,
};

// ===========================================================================
// Error Types
// ===========================================================================

/// Errors that can occur during PE/COFF parsing.
#[derive(Debug, Clone)]
pub enum PeFullError {
    /// The DOS magic number is not "MZ" (0x5A4D).
    InvalidDosMagic,
    /// The PE signature is not "PE\0\0".
    InvalidPeSignature,
    /// The optional-header magic is unrecognised.
    InvalidOptionalHeaderMagic,
    /// The file data is truncated / too short.
    TruncatedData,
    /// The section count exceeds the safety limit.
    TooManySections,
    /// An RVA cannot be mapped to any section.
    InvalidRva(u32),
    /// A nom-level parse error.
    ParseError(String),
    /// A general I/O or logic error.
    Other(String),
}

impl fmt::Display for PeFullError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDosMagic => write!(f, "invalid DOS magic (expected MZ)"),
            Self::InvalidPeSignature => write!(f, "invalid PE signature (expected PE\\0\\0)"),
            Self::InvalidOptionalHeaderMagic => write!(f, "invalid optional-header magic"),
            Self::TruncatedData => write!(f, "truncated PE data"),
            Self::TooManySections => write!(f, "too many sections"),
            Self::InvalidRva(rva) => write!(f, "RVA 0x{rva:08X} does not map into any section"),
            Self::ParseError(s) => write!(f, "parse error: {s}"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for PeFullError {}

impl<T: std::fmt::Debug> From<nom::Err<nom::error::Error<T>>> for PeFullError {
    fn from(e: nom::Err<nom::error::Error<T>>) -> Self {
        Self::ParseError(format!("{e:?}"))
    }
}

/// Type alias for PE parse results.
pub type PeFullResult<T> = Result<T, PeFullError>;

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

/// Maximum permissible section count (defensive bound).
pub const MAX_SECTIONS: u16 = 4096;

/// Standard number of data-directory entries.
pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

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

// --- Relocation types -------------------------------------------------------

pub const IMAGE_REL_BASED_ABSOLUTE: u8 = 0;
pub const IMAGE_REL_BASED_HIGH: u8 = 1;
pub const IMAGE_REL_BASED_LOW: u8 = 2;
pub const IMAGE_REL_BASED_HIGHLOW: u8 = 3;
pub const IMAGE_REL_BASED_HIGHADJ: u8 = 4;
pub const IMAGE_REL_BASED_MIPS_JMPADDR: u8 = 5;
pub const IMAGE_REL_BASED_THUMB_MOV32: u8 = 7;
pub const IMAGE_REL_BASED_DIR64: u8 = 10;

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

// --- CodeView signature constants -------------------------------------------

/// RSDS signature (PDB 7.0): "SDSR" in little-endian.
pub const CODEVIEW_RSDS_SIGNATURE: [u8; 4] = *b"RSDS";
/// NB10 signature (PDB 2.0): "01BN" in little-endian.
pub const CODEVIEW_NB10_SIGNATURE: [u8; 4] = *b"NB10";

// --- Resource type constants ------------------------------------------------

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

// --- COM descriptor (CLR) flags ---------------------------------------------

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

/// IMAGE_DOS_HEADER (64 bytes).
#[derive(Debug, Clone)]
pub struct DosHeader {
    /// Magic number: must be "MZ" (0x5A4D).
    pub e_magic: u16,
    /// Bytes on last page of file.
    pub e_cblp: u16,
    /// Pages in file.
    pub e_cp: u16,
    /// Relocations.
    pub e_crlc: u16,
    /// Size of header in paragraphs.
    pub e_cparhdr: u16,
    /// Minimum extra paragraphs needed.
    pub e_minalloc: u16,
    /// Maximum extra paragraphs needed.
    pub e_maxalloc: u16,
    /// Initial (relative) SS value.
    pub e_ss: u16,
    /// Initial SP value.
    pub e_sp: u16,
    /// Checksum.
    pub e_csum: u16,
    /// Initial IP value.
    pub e_ip: u16,
    /// Initial (relative) CS value.
    pub e_cs: u16,
    /// File address of relocation table.
    pub e_lfarlc: u16,
    /// Overlay number.
    pub e_ovno: u16,
    /// Reserved words.
    pub e_res: [u16; 4],
    /// OEM identifier.
    pub e_oemid: u16,
    /// OEM information.
    pub e_oeminfo: u16,
    /// Reserved words.
    pub e_res2: [u16; 10],
    /// File address of the new exe header (PE signature).
    pub e_lfanew: i32,
}

/// A single Rich-header record (Visual Studio version info).
#[derive(Debug, Clone)]
pub struct RichEntry {
    /// Encoded compiler ID (build number in high 16 bits, product ID in low 16).
    pub comp_id: u32,
    /// Usage count for this compiler.
    pub count: u32,
}

impl RichEntry {
    /// Extract the product ID (low 16 bits of comp_id).
    pub fn prod_id(&self) -> u16 {
        (self.comp_id & 0xFFFF) as u16
    }

    /// Extract the build number (high 16 bits of comp_id).
    pub fn build_number(&self) -> u16 {
        (self.comp_id >> 16) as u16
    }
}

/// Parsed Rich header (Visual Studio build metadata from DOS stub).
#[derive(Debug, Clone)]
pub struct RichHeader {
    /// XOR key used to decode entries.
    pub xor_key: u32,
    /// Magic value "DanS" = 0x536E6144.
    pub dans_magic: u32,
    /// Three padding dwords.
    pub padding: [u32; 3],
    /// Decoded compiler entries.
    pub entries: Vec<RichEntry>,
}

/// COFF File Header (IMAGE_FILE_HEADER).
#[derive(Debug, Clone)]
pub struct FileHeader {
    /// Target machine architecture.
    pub machine: u16,
    /// Number of sections.
    pub number_of_sections: u16,
    /// Timestamp (seconds since 1970-01-01).
    pub time_date_stamp: u32,
    /// File offset of the COFF symbol table (deprecated).
    pub pointer_to_symbol_table: u32,
    /// Number of COFF symbol table entries (deprecated).
    pub number_of_symbols: u32,
    /// Size of the optional header that follows.
    pub size_of_optional_header: u16,
    /// File characteristics flags.
    pub characteristics: u16,
}

/// IMAGE_DATA_DIRECTORY.
#[derive(Debug, Clone, Copy, Default)]
pub struct DataDirectory {
    /// RVA of the directory data.
    pub virtual_address: u32,
    /// Size of the directory data in bytes.
    pub size: u32,
}

impl DataDirectory {
    /// Returns true if the directory entry is present (non-zero RVA and size).
    pub fn is_present(&self) -> bool {
        self.virtual_address != 0 && self.size != 0
    }
}

/// Optional Header (PE32 / PE32+).  All pointer-width fields are stored as
/// `u64` regardless of bitness.
#[derive(Debug, Clone)]
pub struct OptionalHeader {
    /// Magic number: PE32_MAGIC (0x10b), PE32_PLUS_MAGIC (0x20b), or ROM_MAGIC.
    pub magic: u16,
    /// Entry-point RVA (promoted to u64 for uniformity).
    pub entry: u64,
    /// Preferred load address.
    pub image_base: u64,
    /// Section alignment in memory (must be >= file_alignment).
    pub section_alignment: u32,
    /// File alignment of raw section data.
    pub file_alignment: u32,
    /// Total size of the image in memory.
    pub size_of_image: u32,
    /// Combined size of all headers (DOS, PE, section headers) rounded up.
    pub size_of_headers: u32,
    /// Required subsystem (GUI, CUI, EFI, etc.).
    pub subsystem: u16,
    /// DLL characteristics.
    pub dll_characteristics: u16,
    /// Size of stack to reserve.
    pub stack_reserve_size: u64,
    /// Size of stack to commit initially.
    pub stack_commit_size: u64,
    /// Size of heap to reserve.
    pub heap_reserve_size: u64,
    /// Size of heap to commit initially.
    pub heap_commit_size: u64,
    /// Data-directory entries (always 16 slots).
    pub data_directories: [DataDirectory; 16],
}

/// NT Headers: PE signature + COFF File Header + Optional Header.
#[derive(Debug, Clone)]
pub struct NtHeaders {
    /// PE signature (must be PE_SIGNATURE = "PE\0\0").
    pub signature: u32,
    /// COFF file header.
    pub file_header: FileHeader,
    /// Optional header (PE32 or PE32+).
    pub optional_header: OptionalHeader,
}

/// IMAGE_SECTION_HEADER.
#[derive(Debug, Clone)]
pub struct SectionHeader {
    /// Raw section name (8-byte UTF-8, NUL-padded).
    pub name_bytes: [u8; 8],
    /// Virtual size of the section (size in memory).
    pub virtual_size: u32,
    /// RVA of the section.
    pub virtual_address: u32,
    /// Size of raw data on disk.
    pub size_of_raw_data: u32,
    /// File pointer to raw data.
    pub pointer_to_raw_data: u32,
    /// File pointer to relocations (OBJ files).
    pub pointer_to_relocations: u32,
    /// File pointer to line numbers (OBJ files).
    pub pointer_to_line_numbers: u32,
    /// Number of relocations (OBJ files).
    pub number_of_relocations: u16,
    /// Number of line numbers (OBJ files).
    pub number_of_line_numbers: u16,
    /// Section characteristics flags.
    pub characteristics: u32,
}

impl SectionHeader {
    /// Return the decoded section name (up to first NUL byte).
    pub fn name(&self) -> String {
        let end = self
            .name_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.name_bytes.len());
        String::from_utf8_lossy(&self.name_bytes[..end]).to_string()
    }

    /// True if the section contains executable code.
    pub fn is_code(&self) -> bool {
        self.characteristics & IMAGE_SCN_CNT_CODE != 0
    }

    /// True if the section is executable.
    pub fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }

    /// True if the section is readable.
    pub fn is_readable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_READ != 0
    }

    /// True if the section is writable.
    pub fn is_writable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_WRITE != 0
    }
}

/// A single exported function entry.
#[derive(Debug, Clone)]
pub struct ExportFunction {
    /// Export ordinal (relative to the export directory's ordinal base).
    pub ordinal: u16,
    /// Exported name (None for ordinal-only exports).
    pub name: Option<String>,
    /// RVA of the exported symbol (or forwarder string).
    pub rva: u32,
    /// Forwarder string (e.g. "NTDLL.RtlAllocateHeap"), if this is a forwarder.
    pub forwarder: Option<String>,
}

/// Parsed Export Directory.
#[derive(Debug, Clone)]
pub struct ExportDirectory {
    /// DLL / executable name (from the name RVA).
    pub name: String,
    /// Ordinal base (added to the index to obtain the actual ordinal).
    pub base: u32,
    /// All exported functions.
    pub functions: Vec<ExportFunction>,
}

/// A single imported function entry (by name or ordinal).
#[derive(Debug, Clone)]
pub struct ImportFunction {
    /// Hint for the import lookup (index into the export name pointer table).
    pub hint: u16,
    /// Imported function name (None for ordinal-only imports).
    pub name: Option<String>,
    /// Imported ordinal (None for name imports).
    pub ordinal: Option<u16>,
}

/// A parsed import descriptor (one DLL).
#[derive(Debug, Clone)]
pub struct ImportDescriptor {
    /// DLL name (e.g. "KERNEL32.dll").
    pub name: String,
    /// Functions imported from this DLL.
    pub functions: Vec<ImportFunction>,
}

/// A single resource entry (leaf node with extracted data).
#[derive(Debug, Clone)]
pub struct ResourceEntry {
    /// Resource name string (if named, e.g. "MYRESOURCE").
    pub name: Option<String>,
    /// Resource integer ID (if identified, e.g. RT_ICON = 3).
    pub id: Option<u32>,
    /// Raw resource data.
    pub data: Vec<u8>,
    /// Code page of the resource data.
    pub code_page: u32,
}

/// Flattened resource directory (all leaf resources collected).
#[derive(Debug, Clone)]
pub struct ResourceDirectory {
    /// All resource entries extracted from the tree.
    pub entries: Vec<ResourceEntry>,
}

/// A single exception (runtime function) entry.  For x64 this is
/// IMAGE_RUNTIME_FUNCTION_ENTRY; for ARM/ARM64 this is the corresponding
/// packed entry.
#[derive(Debug, Clone)]
pub struct ExceptionEntry {
    /// Begin address RVA of the function.
    pub begin_address: u32,
    /// End address RVA of the function.
    pub end_address: u32,
    /// RVA of the UNWIND_INFO structure.
    pub unwind_info_address: u32,
}

/// A security directory entry (Authenticode certificate).
#[derive(Debug, Clone)]
pub struct SecurityEntry {
    /// Total length of the certificate entry.
    pub length: u32,
    /// Certificate revision (usually 0x0200 for WIN_CERT_REVISION_2_0).
    pub revision: u16,
    /// Certificate type (e.g. WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002).
    pub certificate_type: u16,
    /// Raw certificate data.
    pub certificate_data: Vec<u8>,
}

/// A single base-relocation fixup entry.
#[derive(Debug, Clone)]
pub struct RelocationEntry {
    /// Offset within the page (low 12 bits of the entry word).
    pub offset: u16,
    /// Relocation type (high 4 bits of the entry word).
    pub reloc_type: u8,
}

/// A base-relocation block covering one 4 KB page.
#[derive(Debug, Clone)]
pub struct RelocationBlock {
    /// RVA of the page being fixed up.
    pub page_rva: u32,
    /// Individual relocation fixups within this page.
    pub entries: Vec<RelocationEntry>,
}

/// IMAGE_TLS_DIRECTORY (simplified).
#[derive(Debug, Clone)]
pub struct TlsDirectory {
    /// Start VA of the TLS template data.
    pub start_address: u64,
    /// End VA of the TLS template data.
    pub end_address: u64,
    /// VA of the TLS index variable.
    pub index: u64,
    /// VA of the TLS callback array.
    pub callbacks_address: u64,
    /// Resolved TLS callback addresses (VA).
    pub callbacks: Vec<u64>,
}

/// IMAGE_LOAD_CONFIG_DIRECTORY (simplified — Security Cookie, SEH, CFG, XFG).
#[derive(Debug, Clone)]
pub struct LoadConfigDirectory {
    /// Security cookie VA (used by /GS stack checks).
    pub security_cookie: u64,
    /// VA of the SEH handler table.
    pub se_handler_table: u64,
    /// Number of SEH handlers.
    pub se_handler_count: u64,
    /// VA of the CFG check-function pointer.
    pub guard_cf_check_function: u64,
    /// VA of the CFG dispatch-function pointer.
    pub guard_cf_dispatch_function: u64,
    /// VA of the CFG function table.
    pub guard_cf_function_table: u64,
    /// Number of entries in the CFG function table.
    pub guard_cf_function_count: u64,
    /// CFG guard flags.
    pub guard_flags: u32,
    /// VA of the XFG check-function pointer.
    pub guard_xfg_check_function: u64,
    /// VA of the XFG dispatch-function pointer.
    pub guard_xfg_dispatch_function: u64,
}

/// CodeView debug information (RSDS / NB10 / unknown).
#[derive(Debug, Clone)]
pub struct CodeViewInfo {
    /// CV signature bytes: "RSDS" for PDB 7.0 or "NB10" for PDB 2.0.
    pub signature: [u8; 4],
    /// GUID (meaningful only for RSDS).
    pub guid: [u8; 16],
    /// Age value (RSDS: incrementing build number; NB10: same meaning).
    pub age: u32,
    /// PDB file path (NUL-terminated string from the debug entry).
    pub pdb_name: String,
}

/// IMAGE_DEBUG_DIRECTORY entry.
#[derive(Debug, Clone)]
pub struct DebugEntry {
    /// Debug type (e.g. IMAGE_DEBUG_TYPE_CODEVIEW = 2).
    pub debug_type: u32,
    /// Size of the debug data.
    pub size: u32,
    /// RVA of the debug data.
    pub rva: u32,
    /// File offset (pointer to raw data).
    pub file_offset: u32,
    /// Parsed CodeView information (if debug_type == IMAGE_DEBUG_TYPE_CODEVIEW).
    pub codeview: Option<CodeViewInfo>,
}

/// A bound forwarder reference within a bound import descriptor.
#[derive(Debug, Clone)]
pub struct BoundForwarderRef {
    /// Timestamp of the forwarded DLL.
    pub time_date_stamp: u32,
    /// Module name string.
    pub name: String,
}

/// IMAGE_BOUND_IMPORT_DESCRIPTOR.
#[derive(Debug, Clone)]
pub struct BoundImportDescriptor {
    /// DLL name.
    pub name: String,
    /// Timestamp of the bound DLL.
    pub time_date_stamp: u32,
    /// Forwarder references for this bound import.
    pub forwarders: Vec<BoundForwarderRef>,
}

/// IMAGE_DELAY_IMPORT_DESCRIPTOR.
#[derive(Debug, Clone)]
pub struct DelayImportDescriptor {
    /// DLL name.
    pub name: String,
    /// Delay-loaded functions.
    pub functions: Vec<ImportFunction>,
}

/// IMAGE_COR20_HEADER (.NET CLR COM descriptor, simplified).
#[derive(Debug, Clone)]
pub struct ComDescriptorDirectory {
    /// Major runtime version.
    pub major_runtime_version: u16,
    /// Minor runtime version.
    pub minor_runtime_version: u16,
    /// Flags (ILONLY, 32BITREQUIRED, STRONGNAMESIGNED, etc.).
    pub flags: u32,
    /// RVA of the metadata.
    pub metadata_rva: u32,
    /// Size of the metadata.
    pub metadata_size: u32,
    /// Entry-point token (managed entry point).
    pub entry_point_token: u32,
}

/// A fully parsed PE file.
#[derive(Debug, Clone)]
pub struct PeFile {
    /// DOS header (always present).
    pub dos_header: DosHeader,
    /// NT headers (signature + file header + optional header).
    pub nt_headers: NtHeaders,
    /// Section headers.
    pub section_headers: Vec<SectionHeader>,
    /// Raw section data (one Vec<u8> per section).
    pub sections: Vec<Vec<u8>>,
    /// Export directory (if present).
    pub export_directory: Option<ExportDirectory>,
    /// Import directory (one descriptor per imported DLL).
    pub import_directory: Option<Vec<ImportDescriptor>>,
    /// Resource directory (flattened leaf entries).
    pub resource_directory: Option<ResourceDirectory>,
    /// Exception directory (runtime function entries).
    pub exception_directory: Option<Vec<ExceptionEntry>>,
    /// Security directory (Authenticode certificates).
    pub security_directory: Option<Vec<SecurityEntry>>,
    /// Relocation directory.
    pub relocation_directory: Option<Vec<RelocationBlock>>,
    /// Debug directory.
    pub debug_directory: Option<Vec<DebugEntry>>,
    /// TLS directory.
    pub tls_directory: Option<TlsDirectory>,
    /// Load Config directory.
    pub load_config: Option<LoadConfigDirectory>,
    /// Bound import directory.
    pub bound_import: Option<Vec<BoundImportDescriptor>>,
    /// Delay-load import directory.
    pub delay_import: Option<Vec<DelayImportDescriptor>>,
    /// .NET CLR COM descriptor directory.
    pub com_descriptor: Option<ComDescriptorDirectory>,
}

impl PeFile {
    /// Returns true if this is a 64-bit (PE32+) image.
    pub fn is_64bit(&self) -> bool {
        self.nt_headers.optional_header.magic == PE32_PLUS_MAGIC
    }

    /// Returns true if this is a DLL (IMAGE_FILE_DLL characteristic set).
    pub fn is_dll(&self) -> bool {
        self.nt_headers.file_header.characteristics & IMAGE_FILE_DLL != 0
    }

    /// Find a section header by name.
    pub fn section_by_name(&self, name: &str) -> Option<&SectionHeader> {
        self.section_headers.iter().find(|s| s.name() == name)
    }

    /// Find the section that contains the given RVA.
    pub fn section_for_rva(&self, rva: u32) -> Option<&SectionHeader> {
        self.section_headers.iter().find(|s| {
            let start = s.virtual_address;
            let end = start.saturating_add(s.virtual_size.max(s.size_of_raw_data));
            rva >= start && rva < end
        })
    }

    /// Convert an RVA to a file offset using the section table.
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        self.section_for_rva(rva).map(|s| {
            (rva.wrapping_sub(s.virtual_address) as usize)
                .wrapping_add(s.pointer_to_raw_data as usize)
        })
    }

    /// Read a NUL-terminated string at the given RVA.
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

    /// Read a fixed-size slice at the given RVA.
    pub fn read_rva_slice<'d>(&self, data: &'d [u8], rva: u32, size: usize) -> Option<&'d [u8]> {
        let off = self.rva_to_offset(rva)?;
        data.get(off..off.checked_add(size)?)
    }

    /// Convenience: get the image base.
    pub fn image_base(&self) -> u64 {
        self.nt_headers.optional_header.image_base
    }

    /// Convenience: get the entry-point RVA.
    pub fn entry_point(&self) -> u64 {
        self.nt_headers.optional_header.entry
    }
}

// ===========================================================================
// Nom Parsers — Core Headers
// ===========================================================================

/// Parse the IMAGE_DOS_HEADER (64 bytes).
fn nom_dos_header(input: &[u8]) -> IResult<&[u8], DosHeader> {
    let (i, (e_magic, e_cblp, e_cp, e_crlc)) =
        tuple((verify(le_u16, |&m| m == 0x5A4D), le_u16, le_u16, le_u16))(input)?;
    let (i, (e_cparhdr, e_minalloc, e_maxalloc, e_ss)) =
        tuple((le_u16, le_u16, le_u16, le_u16))(i)?;
    let (i, (e_sp, e_csum, e_ip, e_cs)) = tuple((le_u16, le_u16, le_u16, le_u16))(i)?;
    let (i, (e_lfarlc, e_ovno)) = tuple((le_u16, le_u16))(i)?;
    let (i, e_res_arr) = count(le_u16, 4)(i)?;
    let (i, (e_oemid, e_oeminfo)) = tuple((le_u16, le_u16))(i)?;
    let (i, e_res2_arr) = count(le_u16, 10)(i)?;
    let (i, e_lfanew) = le_u32(i)?;

    let mut e_res = [0u16; 4];
    e_res.copy_from_slice(&e_res_arr);
    let mut e_res2 = [0u16; 10];
    e_res2.copy_from_slice(&e_res2_arr);

    Ok((
        i,
        DosHeader {
            e_magic,
            e_cblp,
            e_cp,
            e_crlc,
            e_cparhdr,
            e_minalloc,
            e_maxalloc,
            e_ss,
            e_sp,
            e_csum,
            e_ip,
            e_cs,
            e_lfarlc,
            e_ovno,
            e_res,
            e_oemid,
            e_oeminfo,
            e_res2,
            e_lfanew: e_lfanew as i32,
        },
    ))
}

/// Parse the Rich header from the DOS stub bytes.
fn parse_rich_header_inner(stub: &[u8]) -> Option<RichHeader> {
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
        // "DanS" in LE
        return None;
    }
    let padding = [decode_dword(8), decode_dword(12), decode_dword(16)];

    let entry_bytes = encoded.len().saturating_sub(20);
    let num_entries = entry_bytes / 8;
    let mut entries = Vec::with_capacity(num_entries);
    for idx in 0..num_entries {
        let off = 20 + idx * 8;
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

/// Parse the COFF File Header (20 bytes).
fn nom_file_header(input: &[u8]) -> IResult<&[u8], FileHeader> {
    let (i, machine) = le_u16(input)?;
    let (i, number_of_sections) = le_u16(i)?;
    let (i, time_date_stamp) = le_u32(i)?;
    let (i, pointer_to_symbol_table) = le_u32(i)?;
    let (i, number_of_symbols) = le_u32(i)?;
    let (i, size_of_optional_header) = le_u16(i)?;
    let (i, characteristics) = le_u16(i)?;
    Ok((
        i,
        FileHeader {
            machine,
            number_of_sections,
            time_date_stamp,
            pointer_to_symbol_table,
            number_of_symbols,
            size_of_optional_header,
            characteristics,
        },
    ))
}

/// Parse a single IMAGE_DATA_DIRECTORY (8 bytes).
fn nom_data_directory(input: &[u8]) -> IResult<&[u8], DataDirectory> {
    let (i, (virtual_address, size)) = tuple((le_u32, le_u32))(input)?;
    Ok((
        i,
        DataDirectory {
            virtual_address,
            size,
        },
    ))
}

/// Parse 16 data directories.
fn nom_data_directories(input: &[u8]) -> IResult<&[u8], [DataDirectory; 16]> {
    let (i, dirs) = count(nom_data_directory, 16)(input)?;
    let mut arr = [DataDirectory::default(); 16];
    for (idx, d) in dirs.into_iter().enumerate() {
        arr[idx] = d;
    }
    Ok((i, arr))
}

/// Read a size field that is u64 in PE32+ or u32 (promoted to u64) in PE32.
fn read_size(input: &[u8], is_plus: bool) -> IResult<&[u8], u64> {
    if is_plus {
        le_u64(input)
    } else {
        map(le_u32, |v| v as u64)(input)
    }
}

/// Parse the Optional Header (PE32 or PE32+).
fn nom_optional_header(
    input: &[u8],
    _size_of_optional_header: u16,
) -> IResult<&[u8], OptionalHeader> {
    let (i, magic) = verify(le_u16, |&m| {
        m == PE32_MAGIC || m == PE32_PLUS_MAGIC || m == ROM_MAGIC
    })(input)?;
    let is_plus = magic == PE32_PLUS_MAGIC;

    // Standard fields (same in both)
    let (i, _major_linker) = le_u8(i)?;
    let (i, _minor_linker) = le_u8(i)?;
    let (i, _size_of_code) = le_u32(i)?;
    let (i, _size_of_init_data) = le_u32(i)?;
    let (i, _size_of_uninit_data) = le_u32(i)?;
    let (i, entry_raw) = le_u32(i)?;
    let (i, _base_of_code) = le_u32(i)?;

    // base_of_data: present only in PE32
    let (i, _base_of_data) = if is_plus { (i, 0u32) } else { le_u32(i)? };

    // image_base: u64 for PE32+, u32 for PE32 (promoted)
    let (i, image_base) = if is_plus {
        let (ii, v) = le_u64(i)?;
        (ii, v)
    } else {
        let (ii, v) = le_u32(i)?;
        (ii, v as u64)
    };

    let (i, section_alignment) = le_u32(i)?;
    let (i, file_alignment) = le_u32(i)?;
    // Skip OS / image / subsystem versions
    let (i, _) = take(16usize)(i)?;
    // win32_version_value
    let (i, _) = le_u32(i)?;
    let (i, size_of_image) = le_u32(i)?;
    let (i, size_of_headers) = le_u32(i)?;
    // checksum
    let (i, _checksum) = le_u32(i)?;
    let (i, subsystem) = le_u16(i)?;
    let (i, dll_characteristics) = le_u16(i)?;

    // Stack / heap sizes: u64 in PE32+, u32 in PE32 (promoted)
    let (i, stack_reserve_size) = read_size(i, is_plus)?;
    let (i, stack_commit_size) = read_size(i, is_plus)?;
    let (i, heap_reserve_size) = read_size(i, is_plus)?;
    let (i, heap_commit_size) = read_size(i, is_plus)?;

    // loader_flags
    let (i, _loader_flags) = le_u32(i)?;
    // number_of_rva_and_sizes
    let (i, _num_rva_sizes) = le_u32(i)?;

    // Note: data directories follow directly after the fixed optional header
    // fields and are parsed below. No padding consumption needed.

    // Data directories
    let (i, data_directories) = nom_data_directories(i)?;

    Ok((
        i,
        OptionalHeader {
            magic,
            entry: entry_raw as u64,
            image_base,
            section_alignment,
            file_alignment,
            size_of_image,
            size_of_headers,
            subsystem,
            dll_characteristics,
            stack_reserve_size,
            stack_commit_size,
            heap_reserve_size,
            heap_commit_size,
            data_directories,
        },
    ))
}

/// Parse the NT headers (signature + file header + optional header).
fn nom_nt_headers(input: &[u8]) -> IResult<&[u8], NtHeaders> {
    let (i, signature) = verify(le_u32, |&s| s == PE_SIGNATURE)(input)?;
    let (i, file_header) = nom_file_header(i)?;
    let (i, optional_header) = nom_optional_header(i, file_header.size_of_optional_header)?;
    Ok((
        i,
        NtHeaders {
            signature,
            file_header,
            optional_header,
        },
    ))
}

/// Parse a single IMAGE_SECTION_HEADER (40 bytes).
fn nom_section_header(input: &[u8]) -> IResult<&[u8], SectionHeader> {
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
    Ok((
        i,
        SectionHeader {
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
        },
    ))
}

/// Parse all section headers.
fn nom_section_headers(input: &[u8], num_sections: usize) -> IResult<&[u8], Vec<SectionHeader>> {
    count(nom_section_header, num_sections)(input)
}

// ===========================================================================
// RVA Resolution for Standalone Parsers
// ===========================================================================

/// Parsed skeleton of a PE file, just enough to resolve RVAs to file offsets.
#[derive(Debug, Clone)]
struct PeSkeleton {
    section_headers: Vec<SectionHeader>,
    is_64bit: bool,
}

impl PeSkeleton {
    fn section_for_rva(&self, rva: u32) -> Option<&SectionHeader> {
        self.section_headers.iter().find(|s| {
            let start = s.virtual_address;
            let end = start.saturating_add(s.virtual_size.max(s.size_of_raw_data));
            rva >= start && rva < end
        })
    }

    fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        self.section_for_rva(rva).map(|s| {
            (rva.wrapping_sub(s.virtual_address) as usize)
                .wrapping_add(s.pointer_to_raw_data as usize)
        })
    }
}

/// Parse just enough of the PE to resolve RVAs.
fn parse_pe_skeleton(data: &[u8]) -> PeFullResult<PeSkeleton> {
    let (_rest, dos_header) = nom_dos_header(data).map_err(PeFullError::from)?;
    let pe_offset = dos_header.e_lfanew as usize;
    if pe_offset > data.len() {
        return Err(PeFullError::TruncatedData);
    }
    let pe_data = &data[pe_offset..];
    let (_pe_rest, nt_headers) = nom_nt_headers(pe_data).map_err(PeFullError::from)?;
    let num_sections = nt_headers.file_header.number_of_sections as usize;
    if num_sections > MAX_SECTIONS as usize {
        return Err(PeFullError::TooManySections);
    }
    // After NT headers, there are data directories (which we already consumed
    // in nom_nt_headers -> nom_optional_header), then section headers.
    // We need to find where section headers start.  We already consumed the
    // optional header + data directories.  The remaining input in _pe_rest
    // starts at the section headers.
    let (_rem, section_headers) =
        nom_section_headers(_pe_rest, num_sections).map_err(PeFullError::from)?;
    let is_64bit = nt_headers.optional_header.magic == PE32_PLUS_MAGIC;
    Ok(PeSkeleton {
        section_headers,
        is_64bit,
    })
}

// ===========================================================================
// Standalone Directory Parsers
// ===========================================================================

/// Parse the export directory from raw PE data at the given RVA.
///
/// `data` is the full PE file bytes; `rva` is the RVA of the export directory;
/// `size` is the size from the data directory entry.
pub fn parse_export(data: &[u8], rva: u32, size: u32) -> PeFullResult<ExportDirectory> {
    if rva == 0 || size < 40 {
        return Err(PeFullError::InvalidRva(rva));
    }
    let skel = parse_pe_skeleton(data)?;
    let off = skel
        .rva_to_offset(rva)
        .ok_or(PeFullError::InvalidRva(rva))?;
    let buf = data.get(off..).ok_or(PeFullError::TruncatedData)?;

    let read_u32_at = |o: usize| -> Option<u32> {
        buf.get(o..o + 4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    };
    let read_u16_at = |o: usize| -> Option<u16> {
        buf.get(o..o + 2)
            .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
    };

    let _characteristics = read_u32_at(0).unwrap_or(0);
    let _time_date_stamp = read_u32_at(4).unwrap_or(0);
    let _major_version = read_u16_at(8).unwrap_or(0);
    let _minor_version = read_u16_at(10).unwrap_or(0);
    let name_rva = read_u32_at(12).unwrap_or(0);
    let ordinal_base = read_u32_at(16).unwrap_or(0);
    let number_of_functions = read_u32_at(20).unwrap_or(0);
    let number_of_names = read_u32_at(24).unwrap_or(0);
    let address_of_functions = read_u32_at(28).unwrap_or(0);
    let address_of_names = read_u32_at(32).unwrap_or(0);
    let address_of_name_ordinals = read_u32_at(36).unwrap_or(0);

    let name = read_rva_string_raw(data, &skel, name_rva).unwrap_or_default();

    let n_funcs = number_of_functions.min(0x10000);
    let n_names = number_of_names.min(0x10000);

    let mut functions: Vec<ExportFunction> = Vec::new();

    // Read function RVAs
    for i in 0..n_funcs as usize {
        let func_rva = skel
            .rva_to_offset(address_of_functions)
            .and_then(|fo| data.get(fo + i * 4..fo + i * 4 + 4))
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .unwrap_or(0);
        if func_rva == 0 {
            continue;
        }
        let ordinal = (ordinal_base + i as u32) as u16;
        let is_within_export = func_rva >= rva && func_rva < rva.saturating_add(size);
        let forwarder = if is_within_export {
            read_rva_string_raw(data, &skel, func_rva)
        } else {
            None
        };
        functions.push(ExportFunction {
            ordinal,
            name: None,
            rva: func_rva,
            forwarder,
        });
    }

    // Read names and match to functions by ordinal table
    let name_base = skel.rva_to_offset(address_of_names);
    let ord_base = skel.rva_to_offset(address_of_name_ordinals);

    for i in 0..n_names as usize {
        let name_rva_val = name_base
            .and_then(|nb| data.get(nb + i * 4..nb + i * 4 + 4))
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .unwrap_or(0);
        let ordinal_idx = ord_base
            .and_then(|ob| data.get(ob + i * 2..ob + i * 2 + 2))
            .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
            .unwrap_or(0) as usize;
        if let Some(entry) = functions.get_mut(ordinal_idx) {
            entry.name = read_rva_string_raw(data, &skel, name_rva_val);
        }
    }

    Ok(ExportDirectory {
        name,
        base: ordinal_base,
        functions,
    })
}

/// Parse the import directory from raw PE data at the given RVA.
///
/// `data` is the full PE file bytes; `rva` is the RVA of the import directory;
/// `size` is the size from the data directory entry.
pub fn parse_import(data: &[u8], rva: u32, _size: u32) -> PeFullResult<Vec<ImportDescriptor>> {
    if rva == 0 {
        return Ok(Vec::new());
    }
    let skel = parse_pe_skeleton(data)?;
    let base = skel
        .rva_to_offset(rva)
        .ok_or(PeFullError::InvalidRva(rva))?;
    let mut imports = Vec::new();
    let entry_size = 20;
    let mut idx = 0;

    loop {
        let off = base + idx * entry_size;
        let buf = match data.get(off..off + entry_size) {
            Some(b) => b,
            None => break,
        };
        let ilt_rva = read_le_u32_at(buf);
        let _time_date_stamp = read_le_u32_at(&buf[4..]);
        let _forwarder_chain = read_le_u32_at(&buf[8..]);
        let name_rva = read_le_u32_at(&buf[12..]);
        let iat_rva = read_le_u32_at(&buf[16..]);

        if ilt_rva == 0 && name_rva == 0 && iat_rva == 0 {
            break;
        }

        let dll_name = read_rva_string_raw(data, &skel, name_rva).unwrap_or_default();
        let lookup_rva = if ilt_rva != 0 { ilt_rva } else { iat_rva };
        let functions = parse_import_lookup(data, &skel, lookup_rva);

        imports.push(ImportDescriptor {
            name: dll_name,
            functions,
        });
        idx += 1;
    }

    Ok(imports)
}

/// Walk the import lookup table and resolve function names/ordinals.
fn parse_import_lookup(data: &[u8], skel: &PeSkeleton, lookup_rva: u32) -> Vec<ImportFunction> {
    let mut entries = Vec::new();
    let base = match skel.rva_to_offset(lookup_rva) {
        Some(o) => o,
        None => return entries,
    };
    let entry_bytes: usize = if skel.is_64bit { 8 } else { 4 };
    let ordinal_flag: u64 = if skel.is_64bit {
        0x8000_0000_0000_0000
    } else {
        0x8000_0000
    };

    for j in 0..4096 {
        let off = base + j * entry_bytes;
        let buf = match data.get(off..off + entry_bytes) {
            Some(b) => b,
            None => break,
        };
        let val: u64 = if skel.is_64bit {
            buf.get(..8)
                .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                .unwrap_or(0)
        } else {
            buf.get(..4)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as u64)
                .unwrap_or(0)
        };
        if val == 0 {
            break;
        }

        if val & ordinal_flag != 0 {
            entries.push(ImportFunction {
                hint: 0,
                name: None,
                ordinal: Some((val & 0xFFFF) as u16),
            });
        } else {
            let hint_rva = (val & 0x7FFF_FFFF) as u32;
            let hint = skel
                .rva_to_offset(hint_rva)
                .and_then(|ho| data.get(ho..ho + 2))
                .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
                .unwrap_or(0);
            let name = read_rva_string_raw(data, skel, hint_rva.wrapping_add(2));
            entries.push(ImportFunction {
                hint,
                name,
                ordinal: None,
            });
        }
    }

    entries
}

/// Parse the resource directory from raw PE data at the given RVA.
///
/// The resource directory is a recursive tree; this function flattens it,
/// extracting the raw data for each leaf resource entry.
pub fn parse_resource(data: &[u8], rva: u32) -> PeFullResult<ResourceDirectory> {
    if rva == 0 {
        return Ok(ResourceDirectory {
            entries: Vec::new(),
        });
    }
    let skel = parse_pe_skeleton(data)?;
    let off = skel
        .rva_to_offset(rva)
        .ok_or(PeFullError::InvalidRva(rva))?;
    let mut entries = Vec::new();
    // Walk the resource tree starting at the root level (depth 0: type level)
    walk_resource_tree(data, &skel, off, rva, 0, None, None, &mut entries);
    Ok(ResourceDirectory { entries })
}

/// Recursively walk the resource tree, collecting leaf data entries.
fn walk_resource_tree(
    data: &[u8],
    skel: &PeSkeleton,
    off: usize,
    base_rva: u32,
    depth: u8,
    _type_id: Option<u32>,
    _name_str: Option<String>,
    entries: &mut Vec<ResourceEntry>,
) {
    if depth > 3 {
        return;
    }
    let buf = match data.get(off..off + 16) {
        Some(b) => b,
        None => return,
    };
    let _characteristics = read_le_u32_at(buf);
    let _time_date_stamp = read_le_u32_at(&buf[4..]);
    let _major_version = read_le_u16_at(&buf[8..]);
    let _minor_version = read_le_u16_at(&buf[10..]);
    let number_of_named_entries = read_le_u16_at(&buf[12..]);
    let number_of_id_entries = read_le_u16_at(&buf[14..]);

    let total = number_of_named_entries as usize + number_of_id_entries as usize;

    for i in 0..total {
        let eoff = off + 16 + i * 8;
        let ebuf = match data.get(eoff..eoff + 8) {
            Some(b) => b,
            None => return,
        };
        let name_or_id = read_le_u32_at(ebuf);
        let offset_to_data = read_le_u32_at(&ebuf[4..]);

        let is_subdir = (offset_to_data & 0x8000_0000) != 0;
        let data_offset = (offset_to_data & 0x7FFF_FFFF) as usize;

        if is_subdir {
            let sub_off = (base_rva as usize).wrapping_add(data_offset);
            let sub_pe_off = match skel.rva_to_offset(sub_off as u32) {
                Some(o) => o,
                None => continue,
            };

            // Determine type/name/id context based on depth
            let (type_id, name_str) = match depth {
                0 => {
                    // Type level: name_or_id is the resource type
                    if (name_or_id & 0x8000_0000) != 0 {
                        // Named type: name is at offset in name_or_id
                        let name_off = (name_or_id & 0x7FFF_FFFF) as usize;
                        let name_str_val = read_rva_string_raw(
                            data,
                            skel,
                            (base_rva as usize).wrapping_add(name_off) as u32,
                        );
                        (None, name_str_val)
                    } else {
                        (Some(name_or_id), None)
                    }
                }
                1 => {
                    // Name level: name_or_id is the resource name/ID
                    let name_val = if (name_or_id & 0x8000_0000) != 0 {
                        let name_field_off = (name_or_id & 0x7FFF_FFFF) as usize;
                        read_rva_string_raw(
                            data,
                            skel,
                            (base_rva as usize).wrapping_add(name_field_off) as u32,
                        )
                    } else {
                        Some(format!("{}", name_or_id))
                    };
                    (_type_id, name_val)
                }
                _ => (_type_id, _name_str.clone()),
            };

            walk_resource_tree(
                data,
                skel,
                sub_pe_off,
                base_rva,
                depth + 1,
                type_id,
                name_str,
                entries,
            );
        } else {
            // Leaf data entry
            let leaf_off = (base_rva as usize).wrapping_add(data_offset);
            let leaf_pe_off = match skel.rva_to_offset(leaf_off as u32) {
                Some(o) => o,
                None => continue,
            };
            let lbuf = match data.get(leaf_pe_off..leaf_pe_off + 16) {
                Some(b) => b,
                None => continue,
            };
            let data_rva = read_le_u32_at(lbuf);
            let size = read_le_u32_at(&lbuf[4..]);
            let code_page = read_le_u32_at(&lbuf[8..]);
            let _reserved = read_le_u32_at(&lbuf[12..]);

            // Extract raw resource data
            let res_data = skel
                .rva_to_offset(data_rva)
                .and_then(|ro| data.get(ro..ro + size as usize))
                .map(|s| s.to_vec())
                .unwrap_or_default();

            let (res_name, res_id) = match depth {
                1 => {
                    // depth 1 means this is a name entry at the name level, leaf at language level
                    // The name_or_id from the parent (depth 0) contains the type
                    // The name_or_id here contains the name
                    let n = if (name_or_id & 0x8000_0000) != 0 {
                        let name_field_off = (name_or_id & 0x7FFF_FFFF) as usize;
                        read_rva_string_raw(
                            data,
                            skel,
                            (base_rva as usize).wrapping_add(name_field_off) as u32,
                        )
                    } else {
                        None
                    };
                    let i = if (name_or_id & 0x8000_0000) == 0 {
                        Some(name_or_id)
                    } else {
                        None
                    };
                    (n, i)
                }
                _ => (_name_str.clone(), _type_id),
            };

            entries.push(ResourceEntry {
                name: res_name,
                id: res_id,
                data: res_data,
                code_page,
            });
        }
    }
}

// ===========================================================================
// Convenience: Extract PDB Path
// ===========================================================================

/// Extract the CodeView (PDB) debug information from a parsed PE file.
///
/// Returns the first CodeView entry found in the debug directory.
pub fn parse_pdb_path(pe: &PeFile) -> Option<CodeViewInfo> {
    pe.debug_directory
        .as_ref()
        .and_then(|entries| entries.iter().find_map(|e| e.codeview.clone()))
}

// ===========================================================================
// Main PE Parser
// ===========================================================================

/// Parse a complete PE/COFF file from a byte slice.
///
/// This is the primary entry point.  It parses all headers, section data, and
/// all data directories into the `PeFile` structure.
pub fn parse_pe(data: &[u8]) -> PeFullResult<PeFile> {
    let (remaining, pe) = nom_parse_pe_file(data)?;
    let _ = remaining;
    Ok(pe)
}

/// Top-level nom parser that produces a fully populated PeFile.
fn nom_parse_pe_file(input: &[u8]) -> IResult<&[u8], PeFile> {
    let _data = input;
    // --- DOS Header ---
    let (input, dos_header) = nom_dos_header(input)?;
    let stub_len = dos_header.e_lfanew as usize - 64;
    let (input, dos_stub) = take(stub_len)(input)?;
    let stub_bytes = dos_stub.to_vec();

    // Rich header is parsed from the stub but not stored in PeFile
    let _rich_header = parse_rich_header_inner(&stub_bytes);

    // --- NT Headers ---
    let (input, nt_headers) = nom_nt_headers(input)?;

    let num_sections = nt_headers.file_header.number_of_sections as usize;
    if num_sections > MAX_SECTIONS as usize {
        // We can't return an error from a nom parser easily, so just cap it
    }
    let max_sec = num_sections.min(MAX_SECTIONS as usize);

    // --- Section Headers ---
    let (input, section_headers) = nom_section_headers(input, max_sec)?;

    // --- Build the PeFile skeleton ---
    // We need the section headers to resolve RVAs.  We build a temporary PeFile
    // for RVA resolution, then populate the directories.

    let is_64bit = nt_headers.optional_header.magic == PE32_PLUS_MAGIC;

    let mut pe = PeFile {
        dos_header,
        nt_headers,
        section_headers,
        sections: Vec::new(),
        export_directory: None,
        import_directory: None,
        resource_directory: None,
        exception_directory: None,
        security_directory: None,
        relocation_directory: None,
        debug_directory: None,
        tls_directory: None,
        load_config: None,
        bound_import: None,
        delay_import: None,
        com_descriptor: None,
    };

    // Read section raw data
    pe.sections = read_section_data_all(input, &pe.section_headers);

    // --- Parse data directories ---
    let dd = &pe.nt_headers.optional_header.data_directories;

    // Export
    if let Some(d) = dd.get(IMAGE_DIRECTORY_ENTRY_EXPORT) {
        if d.is_present() {
            pe.export_directory = parse_export(input, d.virtual_address, d.size).ok();
        }
    }

    // Import
    if let Some(d) = dd.get(IMAGE_DIRECTORY_ENTRY_IMPORT) {
        if d.is_present() {
            let imports = parse_import(input, d.virtual_address, d.size).ok();
            pe.import_directory = imports.filter(|v| !v.is_empty());
        }
    }

    // Resource
    if let Some(d) = dd.get(IMAGE_DIRECTORY_ENTRY_RESOURCE) {
        if d.is_present() {
            let res = parse_resource(input, d.virtual_address).ok();
            pe.resource_directory = res.filter(|r| !r.entries.is_empty());
        }
    }

    // Exception
    if let Some(d) = dd.get(IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
        if d.is_present() {
            pe.exception_directory = parse_exception_directory(input, &pe, d, is_64bit);
        }
    }

    // Security
    if let Some(d) = dd.get(IMAGE_DIRECTORY_ENTRY_SECURITY) {
        if d.is_present() {
            pe.security_directory = parse_security_directory(input, d);
        }
    }

    // Relocation
    if let Some(d) = dd.get(IMAGE_DIRECTORY_ENTRY_BASERELOC) {
        if d.is_present() {
            pe.relocation_directory = parse_relocation_directory(input, &pe, d);
        }
    }

    // Debug
    if let Some(d) = dd.get(IMAGE_DIRECTORY_ENTRY_DEBUG) {
        if d.is_present() {
            pe.debug_directory = parse_debug_directory(input, &pe, d);
        }
    }

    // TLS
    if let Some(d) = dd.get(IMAGE_DIRECTORY_ENTRY_TLS) {
        if d.is_present() {
            pe.tls_directory = parse_tls_directory(input, &pe, d, is_64bit);
        }
    }

    // Load Config
    if let Some(d) = dd.get(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) {
        if d.is_present() {
            pe.load_config = parse_load_config_directory(input, &pe, d, is_64bit);
        }
    }

    // Bound Import
    if let Some(d) = dd.get(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT) {
        if d.is_present() {
            pe.bound_import = parse_bound_import_directory(input, &pe, d);
        }
    }

    // Delay Import
    if let Some(d) = dd.get(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) {
        if d.is_present() {
            pe.delay_import = parse_delay_import_directory(input, &pe, d);
        }
    }

    // COM Descriptor
    if let Some(d) = dd.get(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) {
        if d.is_present() {
            pe.com_descriptor = parse_com_descriptor(input, &pe, d);
        }
    }

    Ok((input, pe))
}

// ===========================================================================
// Internal Parsers for Data Directories
// ===========================================================================

/// Read a NUL-terminated string from raw data using a skeleton for RVA resolution.
fn read_rva_string_raw(data: &[u8], skel: &PeSkeleton, rva: u32) -> Option<String> {
    let off = skel.rva_to_offset(rva)?;
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

/// Little-endian read helpers.
fn read_le_u16_at(buf: &[u8]) -> u16 {
    if buf.len() < 2 {
        return 0;
    }
    u16::from_le_bytes([buf[0], buf[1]])
}

fn read_le_u32_at(buf: &[u8]) -> u32 {
    if buf.len() < 4 {
        return 0;
    }
    u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
}

fn read_le_u64_at(buf: &[u8]) -> u64 {
    if buf.len() < 8 {
        return 0;
    }
    u64::from_le_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ])
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

/// Read all section raw data (duplicate of read_all_section_data, used internally).
fn read_section_data_all(data: &[u8], sections: &[SectionHeader]) -> Vec<Vec<u8>> {
    read_all_section_data(data, sections)
}

/// Parse the exception directory.
fn parse_exception_directory(
    data: &[u8],
    pe: &PeFile,
    dd: &DataDirectory,
    is_64bit: bool,
) -> Option<Vec<ExceptionEntry>> {
    let base = pe.rva_to_offset(dd.virtual_address)?;
    let entry_size = if is_64bit { 12 } else { 8 };
    let count = (dd.size as usize).saturating_div(entry_size).min(0x10000);
    let mut entries = Vec::with_capacity(count);

    for i in 0..count {
        let off = base + i * entry_size;
        let buf = data.get(off..off + entry_size)?;
        if is_64bit {
            entries.push(ExceptionEntry {
                begin_address: read_le_u32_at(buf),
                end_address: read_le_u32_at(&buf[4..]),
                unwind_info_address: read_le_u32_at(&buf[8..]),
            });
        } else {
            // ARM / ARM64: only two u32 fields
            entries.push(ExceptionEntry {
                begin_address: read_le_u32_at(buf),
                end_address: 0,
                unwind_info_address: read_le_u32_at(&buf[4..]),
            });
        }
    }
    if entries.is_empty() {
        None
    } else {
        Some(entries)
    }
}

/// Parse the security (Authenticode) directory.
fn parse_security_directory(data: &[u8], dd: &DataDirectory) -> Option<Vec<SecurityEntry>> {
    // The security directory uses raw file offsets, not RVAs.
    let mut entries = Vec::new();
    let mut offset = dd.virtual_address as usize;

    while offset + 8 <= data.len() {
        let buf = &data[offset..];
        let length = read_le_u32_at(buf);
        let revision = read_le_u16_at(&buf[4..]);
        let cert_type = read_le_u16_at(&buf[6..]);

        if length < 8 || length > 0x100_0000 {
            // Safety bound: 16 MB max per certificate
            break;
        }
        let len = length as usize;
        if offset + len > data.len() {
            break;
        }

        let cert_data = data[offset + 8..offset + len].to_vec();
        entries.push(SecurityEntry {
            length,
            revision,
            certificate_type: cert_type,
            certificate_data: cert_data,
        });

        // Entries are 8-byte aligned
        offset += (len + 7) & !7;
    }

    if entries.is_empty() {
        None
    } else {
        Some(entries)
    }
}

/// Parse the relocation directory.
fn parse_relocation_directory(
    data: &[u8],
    pe: &PeFile,
    dd: &DataDirectory,
) -> Option<Vec<RelocationBlock>> {
    let base = pe.rva_to_offset(dd.virtual_address)?;
    let mut blocks = Vec::new();
    let mut offset = 0usize;

    loop {
        let off = base + offset;
        let hdr = data.get(off..off + 8)?;
        let page_rva = read_le_u32_at(hdr);
        let size_of_block = read_le_u32_at(&hdr[4..]);
        if size_of_block == 0 || size_of_block < 8 {
            break;
        }

        let entry_count = (size_of_block as usize - 8) / 2;
        let mut entries = Vec::with_capacity(entry_count);
        for j in 0..entry_count {
            let eoff = off + 8 + j * 2;
            if let Some(eb) = data.get(eoff..eoff + 2) {
                let raw = u16::from_le_bytes([eb[0], eb[1]]);
                entries.push(RelocationEntry {
                    offset: raw & 0x0FFF,
                    reloc_type: (raw >> 12) as u8,
                });
            }
        }

        blocks.push(RelocationBlock { page_rva, entries });

        offset += size_of_block as usize;
        if offset >= dd.size as usize {
            break;
        }
    }

    if blocks.is_empty() {
        None
    } else {
        Some(blocks)
    }
}

/// Parse the debug directory.
fn parse_debug_directory(data: &[u8], pe: &PeFile, dd: &DataDirectory) -> Option<Vec<DebugEntry>> {
    let base = pe.rva_to_offset(dd.virtual_address)?;
    let entry_size = 28;
    let count = (dd.size as usize).saturating_div(entry_size);
    let mut entries = Vec::with_capacity(count);

    for i in 0..count {
        let off = base + i * entry_size;
        let buf = data.get(off..off + entry_size)?;
        let _characteristics = read_le_u32_at(buf);
        let _time_date_stamp = read_le_u32_at(&buf[4..]);
        let _major_version = read_le_u16_at(&buf[8..]);
        let _minor_version = read_le_u16_at(&buf[10..]);
        let debug_type = read_le_u32_at(&buf[12..]);
        let size_of_data = read_le_u32_at(&buf[16..]);
        let address_of_raw_data = read_le_u32_at(&buf[20..]);
        let pointer_to_raw_data = read_le_u32_at(&buf[24..]);

        let raw_off = if pointer_to_raw_data != 0 {
            pointer_to_raw_data as usize
        } else {
            match pe.rva_to_offset(address_of_raw_data) {
                Some(o) => o,
                None => {
                    entries.push(DebugEntry {
                        debug_type,
                        size: size_of_data,
                        rva: address_of_raw_data,
                        file_offset: pointer_to_raw_data,
                        codeview: None,
                    });
                    continue;
                }
            }
        };

        let codeview = if debug_type == IMAGE_DEBUG_TYPE_CODEVIEW {
            parse_codeview_info(data, raw_off, size_of_data as usize)
        } else {
            None
        };

        entries.push(DebugEntry {
            debug_type,
            size: size_of_data,
            rva: address_of_raw_data,
            file_offset: pointer_to_raw_data,
            codeview,
        });
    }

    if entries.is_empty() {
        None
    } else {
        Some(entries)
    }
}

/// Parse CodeView (RSDS / NB10) debug info at a file offset.
fn parse_codeview_info(data: &[u8], off: usize, size: usize) -> Option<CodeViewInfo> {
    let buf = data.get(off..off.saturating_add(size))?;
    if buf.len() < 4 {
        return None;
    }
    let mut sig = [0u8; 4];
    sig.copy_from_slice(&buf[..4]);

    match sig {
        CODEVIEW_RSDS_SIGNATURE => {
            if buf.len() < 24 {
                return None;
            }
            let mut guid = [0u8; 16];
            guid.copy_from_slice(&buf[4..20]);
            let age = u32::from_le_bytes(buf[20..24].try_into().unwrap());
            let pdb_name = String::from_utf8_lossy(&buf[24..])
                .trim_end_matches('\0')
                .to_string();
            Some(CodeViewInfo {
                signature: sig,
                guid,
                age,
                pdb_name,
            })
        }
        CODEVIEW_NB10_SIGNATURE => {
            if buf.len() < 16 {
                return None;
            }
            let guid = [0u8; 16];
            // NB10 has a 4-byte offset and 4-byte timestamp before age.
            // We zero the GUID since NB10 doesn't have one.
            let age = u32::from_le_bytes(buf[12..16].try_into().unwrap());
            let pdb_name = String::from_utf8_lossy(&buf[16..])
                .trim_end_matches('\0')
                .to_string();
            Some(CodeViewInfo {
                signature: sig,
                guid,
                age,
                pdb_name,
            })
        }
        _ => {
            // Unknown CodeView signature: still provide the raw signature
            let guid = [0u8; 16];
            let age = 0u32;
            let pdb_name = String::new();
            Some(CodeViewInfo {
                signature: sig,
                guid,
                age,
                pdb_name,
            })
        }
    }
}

/// Parse the TLS directory.
fn parse_tls_directory(
    data: &[u8],
    pe: &PeFile,
    dd: &DataDirectory,
    is_64bit: bool,
) -> Option<TlsDirectory> {
    let off = pe.rva_to_offset(dd.virtual_address)?;
    let buf = data.get(off..)?;

    let (start_address, end_address, index, callbacks_address) = if is_64bit {
        (
            read_le_u64_at(&buf[0..]),
            read_le_u64_at(&buf[8..]),
            read_le_u64_at(&buf[16..]),
            read_le_u64_at(&buf[24..]),
        )
    } else {
        (
            read_le_u32_at(&buf[0..]) as u64,
            read_le_u32_at(&buf[4..]) as u64,
            read_le_u32_at(&buf[8..]) as u64,
            read_le_u32_at(&buf[12..]) as u64,
        )
    };

    // Parse callback addresses
    let callbacks = parse_tls_callbacks(data, pe, callbacks_address, is_64bit);

    Some(TlsDirectory {
        start_address,
        end_address,
        index,
        callbacks_address,
        callbacks,
    })
}

/// Read TLS callback array (NULL-terminated array of VA pointers).
fn parse_tls_callbacks(data: &[u8], pe: &PeFile, callbacks_rva: u64, is_64bit: bool) -> Vec<u64> {
    let mut callbacks = Vec::new();
    let rva = callbacks_rva as u32;
    let base = match pe.rva_to_offset(rva) {
        Some(o) => o,
        None => return callbacks,
    };
    let ptr_size = if is_64bit { 8 } else { 4 };

    for i in 0..256 {
        let off = base + i * ptr_size;
        let cb = match data.get(off..off + ptr_size) {
            Some(b) => b,
            None => break,
        };
        let addr: u64 = if is_64bit {
            read_le_u64_at(cb)
        } else {
            read_le_u32_at(cb) as u64
        };
        if addr == 0 {
            break;
        }
        callbacks.push(addr);
    }

    callbacks
}

/// Parse the Load Config directory.
fn parse_load_config_directory(
    data: &[u8],
    pe: &PeFile,
    dd: &DataDirectory,
    is_64bit: bool,
) -> Option<LoadConfigDirectory> {
    if dd.size < 64 {
        return None;
    }
    let off = pe.rva_to_offset(dd.virtual_address)?;
    let buf = data.get(off..)?;
    let size = read_le_u32_at(&buf[0..]);
    let _effective = dd.size.min(size);

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

    // Field offsets in the load config structure
    // After 'size' (4), 'time_date_stamp' (4), 'major_version' (2), 'minor_version' (2),
    // 'global_flags_clear' (4), 'global_flags_set' (4),
    // 'critical_section_default_timeout' (4),
    // then pointer-width fields start at offset 24
    let _de_commit_free_block_threshold = read_ptr(24);
    let _de_commit_total_free_threshold = read_ptr(24 + ptr_size);
    let _lock_prefix_table = read_ptr(24 + 2 * ptr_size);
    let _maximum_allocation_size = read_ptr(24 + 3 * ptr_size);
    let _virtual_memory_threshold = read_ptr(24 + 4 * ptr_size);
    let _process_affinity_mask = read_ptr(24 + 5 * ptr_size);
    let off_after_affinity = 24 + 6 * ptr_size;

    // process_heap_flags (4), csd_version (2), dependent_load_flags (2), edit_list (ptr)
    let _edit_list = read_ptr(off_after_affinity + 8);
    let security_cookie = read_ptr(off_after_affinity + 8 + ptr_size);
    let next = off_after_affinity + 8 + 2 * ptr_size;

    let se_handler_table = read_ptr(next);
    let se_handler_count = read_ptr(next + ptr_size);
    let guard_cf_check_function = read_ptr(next + 2 * ptr_size);
    let guard_cf_dispatch_function = read_ptr(next + 3 * ptr_size);
    let guard_cf_function_table = read_ptr(next + 4 * ptr_size);
    let guard_cf_function_count = read_ptr(next + 5 * ptr_size);
    let guard_flags = buf
        .get(next + 6 * ptr_size..next + 6 * ptr_size + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .unwrap_or(0);

    // Extended fields (XFG)
    let _xfg_base = next + 6 * ptr_size + 4 // skip guard_flags + code_integrity (8 bytes)
        + 8  // skip code_integrity DataDirectory
        + 5 * ptr_size // skip GuardAddressTakenIatEntry*, GuardLongJumpTarget*
        + 2 * ptr_size // skip DynamicValueRelocTable*, CHPEMetadataPointer
        + 2 * ptr_size // skip GuardRFFailureRoutine*
        + ptr_size // skip GuardRFVerifyStackPointerFunctionPointer
        + 8 // skip DynamicValueRelocTableOffset (4) + Section (2) + Reserved (2)
        + ptr_size; // skip HotPatchTableOffset (4) + padding to pointer alignment

    // Actually, let me simplify: the extended XFG fields are at known positions
    // relative to the end of the base structure.
    // After guard_flags (at next + 6*ptr_size), we have:
    //   code_integrity (8) at next+6*ptr_size+4
    //   guard_address_taken_iat* (2*ptr_size) at next+6*ptr_size+12
    //   guard_long_jump_target* (2*ptr_size)
    //   dynamic_value_reloc_table* (ptr)
    //   chpe_metadata_pointer (ptr)
    //   guard_rf_failure_routine* (2*ptr_size)
    //   dynamic_value_reloc_table_offset (4) + section (2) + reserved (2)
    //   guard_rf_verify_stack_pointer_function_pointer (ptr)
    //   hot_patch_table_offset (4) -> padding to 8 -> (ptr)
    //   enclave_configuration_pointer (ptr)
    //   volatile_metadata_pointer (ptr)
    //   guard_eh_continuation* (2*ptr_size)
    //   guard_xfg_check_function_pointer (ptr)
    //   guard_xfg_dispatch_function_pointer (ptr)
    //   guard_xfg_table_dispatch_function_pointer (ptr)
    //   cast_guard_os_determined_failure_mode (ptr)
    //   guard_memcpy_function_pointer (ptr)

    let c1 = next + 6 * ptr_size + 12 + 2 * ptr_size; // after address_taken_iat
    let c2 = c1 + 2 * ptr_size; // after long_jump_target
    let c3 = c2 + ptr_size; // after dynamic_value_reloc_table
    let c4 = c3 + ptr_size; // after chpe_metadata
    let c5 = c4 + 2 * ptr_size; // after rf_failure_routine
    let c6 = c5 + 8; // after dyn_val_reloc_offset+section+reserved
    let c7 = c6 + ptr_size; // after rf_verify_sp
                            // hot_patch_table_offset (4), padded to align next pointer at +4 relative
    let c8 = c7 + ptr_size; // after hot_patch_table (aligned)
    let c9 = c8 + ptr_size; // after enclave_configuration
    let c10 = c9 + ptr_size; // after volatile_metadata
    let c11 = c10 + 2 * ptr_size; // after eh_continuation

    let guard_xfg_check_function = read_ptr(c11);
    let guard_xfg_dispatch_function = read_ptr(c11 + ptr_size);

    Some(LoadConfigDirectory {
        security_cookie,
        se_handler_table,
        se_handler_count,
        guard_cf_check_function,
        guard_cf_dispatch_function,
        guard_cf_function_table,
        guard_cf_function_count,
        guard_flags,
        guard_xfg_check_function,
        guard_xfg_dispatch_function,
    })
}

/// Parse the bound import directory.
fn parse_bound_import_directory(
    data: &[u8],
    pe: &PeFile,
    dd: &DataDirectory,
) -> Option<Vec<BoundImportDescriptor>> {
    let base = pe.rva_to_offset(dd.virtual_address)?;
    let mut result = Vec::new();
    let mut idx = 0usize;

    loop {
        let off = base + idx * 8;
        let buf = data.get(off..off + 8)?;
        let time_date_stamp = read_le_u32_at(buf);
        let offset_module_name = read_le_u16_at(&buf[4..]);
        let number_of_module_forwarder_refs = read_le_u16_at(&buf[6..]);

        if time_date_stamp == 0 && offset_module_name == 0 {
            break;
        }

        let name = pe
            .rva_to_offset(dd.virtual_address.wrapping_add(offset_module_name as u32))
            .and_then(|no| {
                data.get(no..).and_then(|sl| {
                    let end = sl.iter().position(|&b| b == 0).unwrap_or(sl.len());
                    Some(String::from_utf8_lossy(&sl[..end]).to_string())
                })
            })
            .unwrap_or_default();

        let mut forwarders = Vec::new();
        for f in 0..number_of_module_forwarder_refs as usize {
            let foff = base + (idx + f + 1) * 8;
            let fbuf = data.get(foff..foff + 8)?;
            let fts = read_le_u32_at(fbuf);
            let fname_off = read_le_u16_at(&fbuf[4..]);
            let fname = pe
                .rva_to_offset(dd.virtual_address.wrapping_add(fname_off as u32))
                .and_then(|fno| {
                    data.get(fno..).and_then(|sl| {
                        let end = sl.iter().position(|&b| b == 0).unwrap_or(sl.len());
                        Some(String::from_utf8_lossy(&sl[..end]).to_string())
                    })
                })
                .unwrap_or_default();

            forwarders.push(BoundForwarderRef {
                time_date_stamp: fts,
                name: fname,
            });
        }

        result.push(BoundImportDescriptor {
            name,
            time_date_stamp,
            forwarders,
        });

        idx += 1 + number_of_module_forwarder_refs as usize;
    }

    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Parse the delay-load import directory.
fn parse_delay_import_directory(
    data: &[u8],
    pe: &PeFile,
    dd: &DataDirectory,
) -> Option<Vec<DelayImportDescriptor>> {
    let base = pe.rva_to_offset(dd.virtual_address)?;
    let entry_size = 32;
    let mut result = Vec::new();
    let skel = PeSkeleton {
        section_headers: pe.section_headers.clone(),
        is_64bit: pe.is_64bit(),
    };

    for idx in 0.. {
        let off = base + idx * entry_size;
        let buf = data.get(off..off + entry_size)?;
        let attributes = read_le_u32_at(buf);
        let name_rva = read_le_u32_at(&buf[4..]);
        let _module_handle_rva = read_le_u32_at(&buf[8..]);
        let delay_iat_rva = read_le_u32_at(&buf[12..]);
        let delay_int_rva = read_le_u32_at(&buf[16..]);
        let _bound_delay_import_table_rva = read_le_u32_at(&buf[20..]);
        let _unload_delay_import_table_rva = read_le_u32_at(&buf[24..]);
        let _time_date_stamp = read_le_u32_at(&buf[28..]);

        if attributes == 0 && name_rva == 0 {
            break;
        }

        let name = read_rva_string_raw(data, &skel, name_rva).unwrap_or_default();
        let lookup_rva = if delay_int_rva != 0 {
            delay_int_rva
        } else {
            delay_iat_rva
        };
        let functions = parse_import_lookup(data, &skel, lookup_rva);

        result.push(DelayImportDescriptor { name, functions });
    }

    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Parse the .NET CLR COM descriptor directory.
fn parse_com_descriptor(
    data: &[u8],
    pe: &PeFile,
    dd: &DataDirectory,
) -> Option<ComDescriptorDirectory> {
    if dd.size < 72 {
        return None;
    }
    let off = pe.rva_to_offset(dd.virtual_address)?;
    let buf = data.get(off..)?;

    let _cb = read_le_u32_at(&buf[0..]);
    let major_runtime_version = read_le_u16_at(&buf[4..]);
    let minor_runtime_version = read_le_u16_at(&buf[6..]);
    let metadata_rva = read_le_u32_at(&buf[8..]);
    let metadata_size = read_le_u32_at(&buf[12..]);
    let flags = read_le_u32_at(&buf[16..]);
    let entry_point_token = read_le_u32_at(&buf[20..]);

    Some(ComDescriptorDirectory {
        major_runtime_version,
        minor_runtime_version,
        flags,
        metadata_rva,
        metadata_size,
        entry_point_token,
    })
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal PE32 file with no sections and zeroed data directories.
    fn minimal_pe32() -> Vec<u8> {
        let mut buf = Vec::new();

        // DOS Header (64 bytes)
        buf.extend_from_slice(&0x5A4Du16.to_le_bytes()); // e_magic
        buf.extend_from_slice(&vec![0u8; 58]); // rest of DOS header (zeros)
        buf.extend_from_slice(&0x0000_0080u32.to_le_bytes()); // e_lfanew = 0x80
        buf.resize(0x80, 0u8); // DOS stub padding

        // PE signature
        buf.extend_from_slice(&PE_SIGNATURE.to_le_bytes());

        // COFF File Header
        buf.extend_from_slice(&IMAGE_FILE_MACHINE_I386.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // 0 sections
        buf.extend_from_slice(&0u32.to_le_bytes()); // timestamp
        buf.extend_from_slice(&0u32.to_le_bytes()); // ptr to symbol table
        buf.extend_from_slice(&0u32.to_le_bytes()); // num symbols
        buf.extend_from_slice(&224u16.to_le_bytes()); // size of optional header
        buf.extend_from_slice(
            &(IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE).to_le_bytes(),
        );

        // Optional Header (PE32)
        buf.extend_from_slice(&PE32_MAGIC.to_le_bytes());
        buf.push(14u8); // major linker
        buf.push(0u8); // minor linker
        buf.extend_from_slice(&0u32.to_le_bytes()); // size_of_code
        buf.extend_from_slice(&0u32.to_le_bytes()); // size_of_initialized_data
        buf.extend_from_slice(&0u32.to_le_bytes()); // size_of_uninitialized_data
        buf.extend_from_slice(&0x1000u32.to_le_bytes()); // entry_point
        buf.extend_from_slice(&0x1000u32.to_le_bytes()); // base_of_code
        buf.extend_from_slice(&0u32.to_le_bytes()); // base_of_data (PE32 only)
        buf.extend_from_slice(&0x0040_0000u32.to_le_bytes()); // image_base
        buf.extend_from_slice(&0x1000u32.to_le_bytes()); // section_alignment
        buf.extend_from_slice(&0x0200u32.to_le_bytes()); // file_alignment
                                                         // OS version, image version, subsystem version (16 bytes of zeros)
        buf.extend_from_slice(&vec![0u8; 16]);
        buf.extend_from_slice(&0u32.to_le_bytes()); // win32_version_value
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

        // 16 zero data directories
        buf.extend_from_slice(&vec![0u8; 16 * 8]);

        buf
    }

    /// Build a minimal PE32+ (64-bit) file.
    fn minimal_pe32plus() -> Vec<u8> {
        let mut buf = Vec::new();

        // DOS Header
        buf.extend_from_slice(&0x5A4Du16.to_le_bytes());
        buf.extend_from_slice(&vec![0u8; 58]);
        buf.extend_from_slice(&0x0000_0080u32.to_le_bytes());
        buf.resize(0x80, 0u8);

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
            &(IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE).to_le_bytes(),
        );

        // Optional Header (PE32+)
        buf.extend_from_slice(&PE32_PLUS_MAGIC.to_le_bytes());
        buf.push(14u8);
        buf.push(0u8);
        buf.extend_from_slice(&0u32.to_le_bytes()); // size_of_code
        buf.extend_from_slice(&0u32.to_le_bytes()); // size_of_init_data
        buf.extend_from_slice(&0u32.to_le_bytes()); // size_of_uninit_data
        buf.extend_from_slice(&0x1000u32.to_le_bytes()); // entry_point
        buf.extend_from_slice(&0x1000u32.to_le_bytes()); // base_of_code
                                                         // PE32+ skips base_of_data — image_base (u64) comes next
        buf.extend_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes());
        buf.extend_from_slice(&0x1000u32.to_le_bytes()); // section_alignment
        buf.extend_from_slice(&0x0200u32.to_le_bytes()); // file_alignment
        buf.extend_from_slice(&vec![0u8; 16]); // version fields
        buf.extend_from_slice(&0u32.to_le_bytes()); // win32_version_value
        buf.extend_from_slice(&0x5000u32.to_le_bytes()); // size_of_image
        buf.extend_from_slice(&0x0200u32.to_le_bytes()); // size_of_headers
        buf.extend_from_slice(&0u32.to_le_bytes()); // checksum
        buf.extend_from_slice(&IMAGE_SUBSYSTEM_WINDOWS_CUI.to_le_bytes());
        buf.extend_from_slice(
            &(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
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

    // ── Basic parsing tests ────────────────────────────────────────────────

    #[test]
    fn test_parse_minimal_pe32() {
        let data = minimal_pe32();
        let pe = parse_pe(&data).expect("parse minimal PE32");
        assert_eq!(pe.dos_header.e_magic, 0x5A4D);
        assert_eq!(pe.dos_header.e_lfanew, 0x80);
        assert_eq!(pe.nt_headers.file_header.machine, IMAGE_FILE_MACHINE_I386);
        assert_eq!(pe.nt_headers.optional_header.magic, PE32_MAGIC);
        assert!(!pe.is_64bit());
        assert_eq!(pe.nt_headers.optional_header.image_base, 0x400000);
        assert_eq!(pe.nt_headers.optional_header.entry, 0x1000);
        assert!(pe.section_headers.is_empty());
        assert!(pe.sections.is_empty());
        assert!(!pe.is_dll());
        assert_eq!(pe.nt_headers.optional_header.data_directories.len(), 16);
    }

    #[test]
    fn test_parse_minimal_pe32plus() {
        let data = minimal_pe32plus();
        let pe = parse_pe(&data).expect("parse minimal PE32+");
        assert!(pe.is_64bit());
        assert_eq!(pe.nt_headers.file_header.machine, IMAGE_FILE_MACHINE_AMD64);
        assert_eq!(pe.nt_headers.optional_header.magic, PE32_PLUS_MAGIC);
        assert_eq!(pe.nt_headers.optional_header.image_base, 0x1_4000_0000);
        assert_eq!(pe.nt_headers.optional_header.stack_reserve_size, 0x100000);
        assert_eq!(pe.entry_point(), 0x1000);
        assert_eq!(pe.image_base(), 0x1_4000_0000);
    }

    #[test]
    fn test_invalid_dos_magic() {
        let data = vec![0u8; 128];
        assert!(parse_pe(&data).is_err());
    }

    // ── DataDirectory tests ────────────────────────────────────────────────

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

    // ── SectionHeader tests ────────────────────────────────────────────────

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
    }

    // ── RVA resolution tests ───────────────────────────────────────────────

    #[test]
    fn test_rva_to_offset_empty() {
        let data = minimal_pe32();
        let pe = parse_pe(&data).expect("parse minimal PE32");
        // With no sections, RVA resolution should fail
        assert!(pe.section_for_rva(0x1000).is_none());
        assert!(pe.rva_to_offset(0x1000).is_none());
    }

    #[test]
    fn test_pe32plus_characteristics() {
        let data = minimal_pe32plus();
        let pe = parse_pe(&data).expect("parse minimal PE32+");
        assert!(pe.nt_headers.file_header.characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE != 0);
    }

    // ── RichEntry tests ────────────────────────────────────────────────────

    #[test]
    fn test_rich_entry_methods() {
        let entry = RichEntry {
            comp_id: 0x000A_0060,
            count: 5,
        };
        assert_eq!(entry.prod_id(), 0x0060);
        assert_eq!(entry.build_number(), 0x000A);
    }

    // ── NtHeaders round-trip ───────────────────────────────────────────────

    #[test]
    fn test_nt_headers_fields() {
        let data = minimal_pe32();
        let pe = parse_pe(&data).expect("parse minimal PE32");
        assert_eq!(pe.nt_headers.signature, PE_SIGNATURE);
        assert_eq!(
            pe.nt_headers.optional_header.subsystem,
            IMAGE_SUBSYSTEM_WINDOWS_CUI
        );
    }

    // ── Data directory array ───────────────────────────────────────────────

    #[test]
    fn test_data_directories_all_present() {
        let data = minimal_pe32();
        let pe = parse_pe(&data).expect("parse minimal PE32");
        // All 16 directories should be present (though all zero)
        for i in 0..16 {
            let dd = &pe.nt_headers.optional_header.data_directories[i];
            assert_eq!(dd.virtual_address, 0);
            assert_eq!(dd.size, 0);
            assert!(!dd.is_present());
        }
    }

    // ── Standalone parse_export ────────────────────────────────────────────

    #[test]
    fn test_parse_export_empty() {
        let data = minimal_pe32();
        let result = parse_export(&data, 0, 0);
        assert!(result.is_err());
    }

    // ── Standalone parse_import ────────────────────────────────────────────

    #[test]
    fn test_parse_import_empty() {
        let data = minimal_pe32();
        let result = parse_import(&data, 0, 0).expect("parse_import with zero RVA");
        assert!(result.is_empty());
    }

    // ── Standalone parse_resource ──────────────────────────────────────────

    #[test]
    fn test_parse_resource_empty() {
        let data = minimal_pe32();
        let result = parse_resource(&data, 0).expect("parse_resource with zero RVA");
        assert!(result.entries.is_empty());
    }

    // ── parse_pdb_path ─────────────────────────────────────────────────────

    #[test]
    fn test_parse_pdb_path_empty() {
        let data = minimal_pe32();
        let pe = parse_pe(&data).expect("parse minimal PE32");
        let cv = parse_pdb_path(&pe);
        assert!(cv.is_none());
    }

    // ── is_dll test ────────────────────────────────────────────────────────

    #[test]
    fn test_is_dll_false_for_exe() {
        let data = minimal_pe32();
        let pe = parse_pe(&data).expect("parse minimal PE32");
        assert!(!pe.is_dll());
    }

    // ── Copy / Clone test ──────────────────────────────────────────────────

    #[test]
    fn test_pefile_clone() {
        let data = minimal_pe32();
        let pe = parse_pe(&data).expect("parse minimal PE32");
        let pe2 = pe.clone();
        assert_eq!(pe2.dos_header.e_magic, 0x5A4D);
        assert_eq!(
            pe2.nt_headers.optional_header.magic,
            pe.nt_headers.optional_header.magic
        );
    }

    // ── Debug trait test ───────────────────────────────────────────────────

    #[test]
    fn test_pefile_debug() {
        let data = minimal_pe32();
        let pe = parse_pe(&data).expect("parse minimal PE32");
        let debug_str = format!("{pe:?}");
        assert!(debug_str.contains("PeFile"));
        assert!(debug_str.contains("DosHeader"));
        assert!(debug_str.contains("NtHeaders"));
    }
}
